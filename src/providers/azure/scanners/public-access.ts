/**
 * Azure public-access verification (moduleName `public_access_verify`, plan §4.1 P0 / T3).
 * EXPERIMENTAL — not yet validated against a live account; field names follow the
 * `@azure/arm-storage` 21.x / `@azure/arm-keyvault` 6.x d.ts.
 *
 * Azure analog of `src/scanners/public-access-verify.ts` and the Alibaba / Huawei scanners.
 * Two independent sub-services (a failure in one never hides the other's results):
 *
 * Storage (`StorageManagementClient.storageAccounts.list()`, paged, capped at
 * {@link AZURE_STORAGE_MAX_ACCOUNTS}; the TypeSpec client flattens `properties`, a nested
 * `properties` object is also accepted):
 *  - `allowBlobPublicAccess === true` → HIGH (8.0): containers may be made anonymously readable.
 *  - open network: `publicNetworkAccess` not `Disabled` / `SecuredByPerimeter` (absent =
 *    Enabled, the Azure default) and `networkRuleSet.defaultAction` not `Deny` (absent =
 *    Allow) → HIGH (7.0) while shared key (account key / SAS) authorization is allowed
 *    (`allowSharedKeyAccess !== false`), MEDIUM (5.5) when only Entra ID auth is accepted.
 *
 * Key Vault (`KeyVaultManagementClient.vaults.listBySubscription()`, capped at
 * {@link AZURE_KEY_VAULT_MAX_VAULTS}): `properties.publicNetworkAccess` not `Disabled`
 * (absent = Enabled) and `properties.networkAcls.defaultAction` not `Deny` (absent = Allow)
 * → MEDIUM (5.5).
 *
 * resourceArn = the native ARM resource ID; region = the resource `location`.
 *
 * Errors (per sub-service): access denied / RP not registered / throttled / network /
 * other → warning and skip that sub-service; **auth_failed or api_misuse in either →
 * module `status: "error"`**. Raw SDK errors (holding the Bearer token) never reach the result.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { armClient, azurePaginate } from "../client.js";
import { redactAzureDiagnostic } from "../errors.js";
import { parseAzureResourceId, toAzureUrn } from "../urn.js";
import {
  azField,
  azString,
  aztUntrusted,
  aztUntrustedOpt,
  azureEmptyResult,
  azureErrorResult,
  azureNoSubscriptionWarning,
  azureSafeFinding,
  azureScanEnv,
  azureSoftWarning,
  azureTruncationWarning,
  isAzureFatal,
  type AzureScanEnv,
} from "./shared.js";

export const AZURE_STORAGE_MAX_ACCOUNTS = 5000;
export const AZURE_KEY_VAULT_MAX_VAULTS = 5000;

export const AZURE_STORAGE_BLOB_PUBLIC_RISK = 8.0;
export const AZURE_STORAGE_OPEN_NETWORK_SHARED_KEY_RISK = 7.0;
export const AZURE_STORAGE_OPEN_NETWORK_ENTRA_ONLY_RISK = 5.5;
export const AZURE_KEY_VAULT_OPEN_NETWORK_RISK = 5.5;

const STORAGE_TYPE = "Microsoft.Storage/storageAccounts";
const KEY_VAULT_TYPE = "Microsoft.KeyVault/vaults";
const STORAGE_SERVICE = "Storage storageAccounts.list";
const KEY_VAULT_SERVICE = "Key Vault vaults.listBySubscription";

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

function lower(v: unknown): string | undefined {
  return azString(v)?.toLowerCase();
}

/** `publicNetworkAccess` allows public endpoints (absent → Enabled, the Azure default). */
export function isAzurePublicNetworkEnabled(value: unknown): boolean {
  const v = lower(value);
  return v !== "disabled" && v !== "securedbyperimeter";
}

/** Firewall default action lets every network in (absent → Allow, the Azure default). */
export function isAzureDefaultActionAllow(value: unknown): boolean {
  return lower(value) !== "deny";
}

/** Storage account property: flattened (TypeSpec SDK) or nested under `properties` (raw ARM). */
function saProp(account: unknown, key: string): unknown {
  const direct = azField(account, key);
  return direct !== undefined ? direct : azField(azField(account, "properties"), key);
}

/** Shared identity fields of a listed resource; every emitted string is redacted. */
interface ResourceRef {
  name: string;
  arn: string;
  region: string;
  resourceGroup?: string;
}

function resourceRef(resource: unknown, resourceType: string, env: AzureScanEnv): ResourceRef {
  const rawId = azString(azField(resource, "id"));
  const parsed = rawId ? parseAzureResourceId(rawId) : undefined;
  const rawName = azString(azField(resource, "name")) ?? parsed?.name ?? "unknown";
  return {
    name: aztUntrusted(rawName),
    arn: toAzureUrn({ id: rawId, subscriptionId: env.subscriptionId, resourceGroup: parsed?.resourceGroup, resourceType, name: rawName }),
    region: aztUntrustedOpt(azField(resource, "location")) ?? "global",
    resourceGroup: aztUntrustedOpt(parsed?.resourceGroup),
  };
}

function where(ref: ResourceRef, env: AzureScanEnv): string {
  return `${ref.resourceGroup ? `resource group ${ref.resourceGroup}, ` : ""}subscription ${aztUntrusted(env.subscriptionId)}`;
}

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return azureSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "azure" });
}

/** Findings for one storage account. Exported for unit tests. */
export function storageAccountFindings(account: unknown, env: AzureScanEnv, module: string): Finding[] {
  const ref = resourceRef(account, STORAGE_TYPE, env);
  const findings: Finding[] = [];
  const networkOpen =
    isAzurePublicNetworkEnabled(saProp(account, "publicNetworkAccess")) &&
    isAzureDefaultActionAllow(azField(saProp(account, "networkRuleSet"), "defaultAction"));
  const sharedKey = saProp(account, "allowSharedKeyAccess") !== false;

  if (saProp(account, "allowBlobPublicAccess") === true) {
    findings.push(
      makeFinding({
        riskScore: AZURE_STORAGE_BLOB_PUBLIC_RISK,
        title: `Storage account ${ref.name} allows anonymous (public) blob access`,
        resourceType: STORAGE_TYPE,
        resourceId: ref.name,
        resourceArn: ref.arn,
        region: ref.region,
        description: `Storage account ${ref.name} (${where(ref, env)}) has allowBlobPublicAccess=true: any container can be set to anonymous Blob / Container access level and its data read without authentication${networkOpen ? "; the account is also reachable from all networks" : ""}.`,
        impact: "Blob data in containers with a public access level can be read (and listed) by anyone on the internet without credentials.",
        remediationSteps: [
          `Storage account ${ref.name} → Settings → Configuration → set "Allow Blob anonymous access" to Disabled (allowBlobPublicAccess=false).`,
          "Before disabling, review containers whose public access level is Blob / Container and move intended public content to a CDN / SAS-based delivery.",
          "Assign the Azure Policy \"Storage account public access should be disallowed\" to prevent regressions.",
        ],
        accountId: env.tenantId,
        module,
      }),
    );
  }

  if (networkOpen) {
    findings.push(
      makeFinding({
        riskScore: sharedKey ? AZURE_STORAGE_OPEN_NETWORK_SHARED_KEY_RISK : AZURE_STORAGE_OPEN_NETWORK_ENTRA_ONLY_RISK,
        title: `Storage account ${ref.name} is reachable from all networks`,
        resourceType: STORAGE_TYPE,
        resourceId: ref.name,
        resourceArn: ref.arn,
        region: ref.region,
        description: `Storage account ${ref.name} (${where(ref, env)}) has public network access enabled and its firewall default action is Allow, so the data-plane endpoints accept requests from any IP address. ${sharedKey ? "Shared key authorization is enabled: a leaked account key or SAS token grants access from anywhere." : "Shared key authorization is disabled (Entra ID only), which limits the exposure."}`,
        impact: "Data-plane endpoints are exposed to the internet; any leaked credential (account key, SAS, Entra token) can be used from any network.",
        remediationSteps: [
          `Storage account ${ref.name} → Security + networking → Networking → "Enabled from selected virtual networks and IP addresses" (networkRuleSet.defaultAction=Deny), or disable public network access and use private endpoints.`,
          "Add only the required virtual network / IP rules; keep the AzureServices bypass only if needed.",
          ...(sharedKey ? ["Consider disallowing shared key authorization (allowSharedKeyAccess=false) and using Entra ID (RBAC) access."] : []),
        ],
        accountId: env.tenantId,
        module,
      }),
    );
  }
  return findings;
}

/** Finding for one key vault (or none). Exported for unit tests. */
export function keyVaultFinding(vault: unknown, env: AzureScanEnv, module: string): Finding | undefined {
  const props = azField(vault, "properties");
  const open =
    isAzurePublicNetworkEnabled(azField(props, "publicNetworkAccess")) &&
    isAzureDefaultActionAllow(azField(azField(props, "networkAcls"), "defaultAction"));
  if (!open) return undefined;
  const ref = resourceRef(vault, KEY_VAULT_TYPE, env);
  return makeFinding({
    riskScore: AZURE_KEY_VAULT_OPEN_NETWORK_RISK,
    title: `Key vault ${ref.name} is reachable from all networks`,
    resourceType: KEY_VAULT_TYPE,
    resourceId: ref.name,
    resourceArn: ref.arn,
    region: ref.region,
    description: `Key vault ${ref.name} (${where(ref, env)}) has public network access enabled and its network ACL default action is Allow (or no network ACLs), so the vault endpoint accepts requests from any IP address.`,
    impact: "Secrets, keys and certificates are protected only by authentication; a leaked Entra token or misconfigured access policy can be exploited from any network.",
    remediationSteps: [
      `Key vault ${ref.name} → Settings → Networking → "Allow public access from specific virtual networks and IP addresses" (networkAcls.defaultAction=Deny), or disable public access and use a private endpoint.`,
      "Allow trusted Microsoft services to bypass the firewall only if required.",
      "Assign the Azure Policy \"Azure Key Vault should have firewall enabled\" to prevent regressions.",
    ],
    accountId: env.tenantId,
    module,
  });
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

interface SubResult {
  findings: Finding[];
  scanned: number;
  warnings: string[];
  /** auth_failed / api_misuse: the whole module fails. */
  fatal?: unknown;
}

export class AzurePublicAccessScanner implements Scanner {
  readonly moduleName = "public_access_verify";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    let env: AzureScanEnv | undefined;
    try {
      env = azureScanEnv(ctx);
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, "Azure public access scan failed", err);
    }
    if (!env) return azureEmptyResult(this.moduleName, startMs, { warnings: [azureNoSubscriptionWarning(this.moduleName)] });

    const parts = await Promise.all([this.scanStorage(env), this.scanKeyVaults(env)]);
    const warnings = parts.flatMap((p) => p.warnings);
    const fatal = parts.find((p) => p.fatal !== undefined);
    if (fatal) return azureErrorResult(this.moduleName, startMs, "Azure public access scan failed", fatal.fatal, warnings);

    const findings = parts.flatMap((p) => p.findings);
    return {
      module: this.moduleName,
      status: "success",
      warnings: warnings.length > 0 ? warnings.map(redactAzureDiagnostic) : undefined,
      resourcesScanned: parts.reduce((n, p) => n + p.scanned, 0),
      findingsCount: findings.length,
      scanTimeMs: Date.now() - startMs,
      findings,
    };
  }

  private async scanStorage(env: AzureScanEnv): Promise<SubResult> {
    const out: SubResult = { findings: [], scanned: 0, warnings: [] };
    try {
      const { StorageManagementClient } = await import("@azure/arm-storage");
      const client = await armClient(StorageManagementClient, env.credentials, env.subscriptionId);
      const page = await azurePaginate(client.storageAccounts.list(), {
        max: AZURE_STORAGE_MAX_ACCOUNTS,
        collect: false,
        onItem: (a) => {
          out.findings.push(...storageAccountFindings(a, env, this.moduleName));
        },
      });
      out.scanned = page.count;
      if (page.truncated) out.warnings.push(azureTruncationWarning(STORAGE_SERVICE, AZURE_STORAGE_MAX_ACCOUNTS));
    } catch (err) {
      if (isAzureFatal(err)) return { ...out, fatal: err };
      out.warnings.push(`${azureSoftWarning(STORAGE_SERVICE, err)} — storage account public access not verified.`);
    }
    return out;
  }

  private async scanKeyVaults(env: AzureScanEnv): Promise<SubResult> {
    const out: SubResult = { findings: [], scanned: 0, warnings: [] };
    try {
      const { KeyVaultManagementClient } = await import("@azure/arm-keyvault");
      const client = await armClient(KeyVaultManagementClient, env.credentials, env.subscriptionId);
      const page = await azurePaginate(client.vaults.listBySubscription(), {
        max: AZURE_KEY_VAULT_MAX_VAULTS,
        collect: false,
        onItem: (v) => {
          const f = keyVaultFinding(v, env, this.moduleName);
          if (f) out.findings.push(f);
        },
      });
      out.scanned = page.count;
      if (page.truncated) out.warnings.push(azureTruncationWarning(KEY_VAULT_SERVICE, AZURE_KEY_VAULT_MAX_VAULTS));
    } catch (err) {
      if (isAzureFatal(err)) return { ...out, fatal: err };
      out.warnings.push(`${azureSoftWarning(KEY_VAULT_SERVICE, err)} — key vault public access not verified.`);
    }
    return out;
  }
}
