/**
 * Azure provider (Phase 2 skeleton — EXPERIMENTAL, not yet validated against a
 * live account). China (21Vianet) is the default cloud; Global is also supported.
 *
 * Resource model (plan §3.3): account = Entra ID tenant; scan unit = subscription.
 * `listRegions` returns one scope per visible subscription
 * (`RegionScope { region: subscriptionId, domainId: tenantId }`), so the generic
 * regional-provider runner path iterates subscriptions; `globalModules` (tenant-level)
 * run once. A single service principal sees many subscriptions, so no cross-account
 * assume is needed — `listAccounts` / `assumeCrossAccount` throw.
 *
 * T0 wires the provider into the registry / runner. T1 adds credentials (§3.2), the
 * ARM / Graph client factory (§3.4), error classification + redaction (§3.5) and URNs
 * (§3.6). Scanners land in T2–T7. `@azure/*` SDKs must be loaded lazily
 * (`await import()`) so the default AWS path never loads them — this file imports none.
 */
import type { Scanner } from "../../scanners/base.js";
import type { AccountRef, AssumeCrossAccountOptions, CloudCredentials, CloudProvider, RegionScope } from "../types.js";
import type { AzureCloud, AzureCredentials, ScanContext } from "../../types.js";
import { isAzureCredentials } from "../../types.js";
import { listAzureSubscriptions, type AzureSubscriptionRef } from "./subscriptions.js";

export * from "./subscriptions.js";

export const AZURE_PARTITION = "azure";
export const DEFAULT_AZURE_CLOUD: AzureCloud = "china";

/**
 * Placeholder scope used when no subscription could be determined (Azure has no
 * meaningful default "region"). `contextFor` leaves `subscriptionId` unset for it, so
 * subscription-scoped scanners must treat a missing `ScanContext.subscriptionId` as
 * "nothing to scan" and report it.
 */
export const AZURE_NO_SUBSCRIPTION = "no-subscription";

/** Tenant-level modules (Entra directory roles): run once per scan, not once per subscription. */
export const AZURE_GLOBAL_MODULES: ReadonlySet<string> = new Set(["iam_privilege_escalation"]);

export const AZURE_MULTI_ACCOUNT_WARNING =
  "org_mode is not applicable to azure: every subscription visible to the service principal is scanned by default (cross-tenant scanning is not supported). Scanning the current tenant only.";

const AZURE_NO_SUBSCRIPTION_HINT = "set AZURE_SUBSCRIPTION_ID or pass a subscription ID as region";

/** Subscription states that cannot be scanned. */
const INACTIVE_SUBSCRIPTION_STATES = new Set(["disabled", "deleted"]);

/** `AZURE_CLOUD` → national cloud; anything other than a Global alias means China (the default). */
export function resolveAzureCloud(value: string | undefined = process.env.AZURE_CLOUD): AzureCloud {
  const v = value?.trim().toLowerCase();
  return v === "global" || v === "public" || v === "azurecloud" || v === "azurepubliccloud" ? "global" : DEFAULT_AZURE_CLOUD;
}

function envValue(name: string): string | undefined {
  const v = process.env[name]?.trim();
  return v ? v : undefined;
}

/**
 * Credentials for provider-level calls: explicit Azure credentials when given, else the
 * service principal from env (`AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`,
 * `AZURE_CLOUD`). Returns undefined when neither yields credentials (no network).
 *
 * TODO(T1): replace with `loadAzureCredentials` from ./credentials.ts (§3.2), which also
 * registers the secret with the redactor.
 */
function tryResolveCredentials(creds?: CloudCredentials): AzureCredentials | undefined {
  if (isAzureCredentials(creds)) return creds;
  const tenantId = envValue("AZURE_TENANT_ID");
  const clientId = envValue("AZURE_CLIENT_ID");
  const clientSecret = envValue("AZURE_CLIENT_SECRET");
  if (!tenantId || !clientId || !clientSecret) return undefined;
  return { kind: "azure", tenantId, clientId, clientSecret, cloud: resolveAzureCloud(), source: "env" };
}

export const azureProvider: CloudProvider = {
  id: "azure",
  displayName: "Azure",
  partitionFor: () => AZURE_PARTITION,
  defaultRegion: AZURE_NO_SUBSCRIPTION,
  globalModules: AZURE_GLOBAL_MODULES,
  // TODO(T1): wire to redactAzureDiagnostic (Bearer / JWT / client_secret / SAS / storage key).
  redactDiagnostic: (text: string) => text,
  supportsMultiAccount: false,
  regionalMessages: {
    noRegions: () =>
      `Azure subscription enumeration returned no subscriptions visible to the service principal; ${AZURE_NO_SUBSCRIPTION_HINT}.`,
    unknownRegion: (requested, known) =>
      `Azure subscription "${requested}" is not among the subscriptions visible to the service principal (known: ${known}); scanning it anyway.`,
    discoveryFailed: (reason, fallback) =>
      fallback === AZURE_NO_SUBSCRIPTION
        ? `Azure subscription enumeration failed: ${reason}. No subscription to scan; ${AZURE_NO_SUBSCRIPTION_HINT}.`
        : `Azure subscription enumeration failed: ${reason}. Scanning subscription ${fallback} only.`,
    multiAccountUnsupported: AZURE_MULTI_ACCOUNT_WARNING,
  },

  // Subscription scope → subscriptionId / tenantId / cloud on the ScanContext.
  contextFor(scope: RegionScope, accountId: string): Partial<ScanContext> {
    const extra: Partial<ScanContext> = { cloud: tryResolveCredentials()?.cloud ?? resolveAzureCloud() };
    if (scope.region && scope.region !== AZURE_NO_SUBSCRIPTION) extra.subscriptionId = scope.region;
    const tenantId = scope.domainId ?? (accountId && accountId !== "unknown" ? accountId : undefined);
    if (tenantId) extra.tenantId = tenantId;
    return extra;
  },

  // Account identifier = tenant ID (scope's subscription tenant, else the credentials' tenant).
  async getAccountId(scope: RegionScope, creds?: CloudCredentials): Promise<string> {
    return scope.domainId ?? tryResolveCredentials(creds)?.tenantId ?? "unknown";
  },

  // One scope per visible, active subscription. `requested` (an explicit subscription ID)
  // is matched by the runner against the returned list; without one, AZURE_SUBSCRIPTION_ID
  // pins the scan to a single subscription. When enumeration fails, the requested / pinned
  // subscription is scanned alone; with neither, the failure propagates (the runner reports
  // it, redacted, as a warning).
  async listRegions(creds?: CloudCredentials, requested?: string): Promise<RegionScope[]> {
    const pinned = envValue("AZURE_SUBSCRIPTION_ID");
    const fallback = requested ?? pinned;
    const resolved = tryResolveCredentials(creds);
    if (!resolved) return fallback ? [{ region: fallback }] : [];

    let subs: AzureSubscriptionRef[];
    try {
      subs = await listAzureSubscriptions(resolved);
    } catch (err) {
      // TODO(T1): rethrow authentication failures (isAzureAuthFailure) so the scan reports them.
      if (fallback) return [{ region: fallback, domainId: resolved.tenantId }];
      throw err;
    }

    const seen = new Set<string>();
    const scopes: RegionScope[] = [];
    for (const sub of subs) {
      const id = sub.subscriptionId?.trim();
      if (!id || seen.has(id.toLowerCase())) continue;
      if (sub.state && INACTIVE_SUBSCRIPTION_STATES.has(sub.state.toLowerCase())) continue;
      seen.add(id.toLowerCase());
      scopes.push({ region: id, domainId: sub.tenantId || resolved.tenantId });
    }

    if (!requested && pinned) {
      const match = scopes.find((s) => s.region.toLowerCase() === pinned.toLowerCase());
      return [match ?? { region: pinned, domainId: resolved.tenantId }];
    }
    return scopes;
  },

  async listAccounts(_scope: RegionScope, _creds?: CloudCredentials): Promise<AccountRef[]> {
    throw new Error("Azure listAccounts is not implemented (Azure uses multi-subscription enumeration, not cross-account assume)");
  },

  async assumeCrossAccount(
    _target: AccountRef,
    _scope: RegionScope,
    _opts?: AssumeCrossAccountOptions,
  ): Promise<CloudCredentials> {
    throw new Error(
      "Azure assumeCrossAccount is not implemented (Azure uses multi-subscription enumeration, not cross-account assume)",
    );
  },

  // T2–T7 add the scanners (plan §4.1).
  scanners(): Scanner[] {
    return [];
  },

  // ARM resource IDs are already globally unique: pass them through.
  // TODO(T1): replace the fallback with toAzureUrn (plan §3.6).
  toResourceUrn(resourceType: string, resourceId: string, scope: RegionScope, _accountId: string): string {
    if (resourceId.startsWith("/")) return resourceId;
    return `azure:${scope.region}:${resourceType}:${resourceId}`;
  },
};
