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
 * Credentials (§3.2) live in ./credentials.ts, the ARM / Graph client factory (§3.4) in
 * ./client.ts, error classification + redaction (§3.5) in ./errors.ts and URNs (§3.6) in
 * ./urn.ts. Scanners live in ./scanners/ (T2–T7). `@azure/*` SDKs are loaded lazily (`await import()`)
 * so the default AWS path never loads them — no module here imports one at runtime.
 */
import type { Scanner } from "../../scanners/base.js";
import type { AccountRef, AssumeCrossAccountOptions, CloudCredentials, CloudProvider, RegionScope } from "../types.js";
import type { AzureCredentials, ScanContext } from "../../types.js";
import { isAzureCredentials } from "../../types.js";
import { loadAzureCredentials, pinnedAzureSubscriptionId, resolveAzureCloud } from "./credentials.js";
import { isAzureAuthFailure, redactAzureDiagnostic } from "./errors.js";
import { AZURE_NO_SUBSCRIPTION, listAzureSubscriptions, type AzureSubscriptionRef } from "./subscriptions.js";
import { toAzureUrn } from "./urn.js";
import { AzureDefenderAssessmentsScanner } from "./scanners/defender-assessments.js";
import { AzurePolicyComplianceScanner } from "./scanners/policy-compliance.js";
import { AzurePublicAccessScanner } from "./scanners/public-access.js";
import { AzureServiceDetectionScanner } from "./scanners/service-detection.js";

export * from "./subscriptions.js";
export { DEFAULT_AZURE_CLOUD, resolveAzureCloud } from "./credentials.js";

export const AZURE_PARTITION = "azure";

/** Tenant-level modules (Entra directory roles): run once per scan, not once per subscription. */
export const AZURE_GLOBAL_MODULES: ReadonlySet<string> = new Set(["iam_privilege_escalation"]);

export const AZURE_MULTI_ACCOUNT_WARNING =
  "org_mode is not applicable to azure: every subscription visible to the service principal is scanned by default (cross-tenant scanning is not supported). Scanning the current tenant only.";

const AZURE_NO_SUBSCRIPTION_HINT = "set AZURE_SUBSCRIPTION_ID or pass a subscription ID as region";

/** Subscription states that cannot be scanned. */
const INACTIVE_SUBSCRIPTION_STATES = new Set(["disabled", "deleted"]);

/**
 * Credentials for provider-level calls: explicit Azure credentials when given, else the
 * env service principal (`loadAzureCredentials`, which also registers the secret with the
 * redactor). Returns undefined when nothing yields credentials (no network, never throws).
 */
function tryResolveCredentials(creds?: CloudCredentials): AzureCredentials | undefined {
  try {
    return loadAzureCredentials({ explicit: isAzureCredentials(creds) ? creds : undefined });
  } catch {
    return undefined;
  }
}

export const azureProvider: CloudProvider = {
  id: "azure",
  displayName: "Azure",
  partitionFor: () => AZURE_PARTITION,
  defaultRegion: AZURE_NO_SUBSCRIPTION,
  globalModules: AZURE_GLOBAL_MODULES,
  redactDiagnostic: redactAzureDiagnostic,
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
  // it, redacted, as a warning). Authentication failures with a requested subscription also
  // propagate, so the runner's warning names the auth failure (it still scans the requested
  // subscription, whose modules then report `Azure authentication failed`).
  async listRegions(creds?: CloudCredentials, requested?: string): Promise<RegionScope[]> {
    const pinned = pinnedAzureSubscriptionId();
    const fallback = requested ?? pinned;
    const resolved = tryResolveCredentials(creds);
    if (!resolved) return fallback ? [{ region: fallback }] : [];

    let subs: AzureSubscriptionRef[];
    try {
      subs = await listAzureSubscriptions(resolved);
    } catch (err) {
      if (requested && isAzureAuthFailure(err)) throw err;
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

  // Subscription-scoped scanners (plan §4.1); T3–T7 add the rest.
  scanners(): Scanner[] {
    return [
      new AzurePolicyComplianceScanner(),
      new AzureServiceDetectionScanner(),
      new AzureDefenderAssessmentsScanner(),
      new AzurePublicAccessScanner(),
    ];
  },

  // ARM resource IDs are already globally unique: pass them through; otherwise build
  // `/subscriptions/<sub>/providers/<resourceType>/<name>` (tenant-level: `/tenants/<tenant>/…`).
  toResourceUrn(resourceType: string, resourceId: string, scope: RegionScope, accountId: string): string {
    const subscriptionId = scope.region && scope.region !== AZURE_NO_SUBSCRIPTION ? scope.region : undefined;
    const tenantId = scope.domainId ?? (accountId && accountId !== "unknown" ? accountId : undefined);
    return toAzureUrn({ id: resourceId, subscriptionId, tenantId, resourceType, name: resourceId });
  },
};
