/**
 * Azure tag compliance scanner (moduleName `tag_compliance`, plan §2 #8 / §4.1 P2 / T7).
 * EXPERIMENTAL — not yet validated against a live account; field names follow the
 * `@azure/arm-resources` 8.x d.ts (`GenericResourceExpanded.tags: Record<string, string>`).
 *
 * Mirrors `src/scanners/tag-compliance.ts`: every resource missing one of the AWS
 * {@link DEFAULT_REQUIRED_TAGS} → MEDIUM 4.0.
 *  - `ResourceManagementClient.resources.list()` (every resource of the subscription with
 *    its inline `tags`; paged, capped at {@link AZURE_TAG_MAX_ITEMS}).
 *  - `resourceGroups.list()` (resource groups carry tags too; same cap).
 * Azure tag names are case-insensitive (ARM treats `owner` and `Owner` as the same tag),
 * so — unlike the AWS scanner — required keys are matched case-insensitively.
 *
 * Errors: access denied / RP not registered / throttled / network on a category → warning and
 * skip that category; **auth_failed or api_misuse in any → module `status: "error"`**. Every
 * server-sourced string (IDs, names, tag keys, locations) passes through aztUntrusted.
 */
import type { ResourceManagementClient } from "@azure/arm-resources";
import type { Scanner } from "../../../scanners/base.js";
import { DEFAULT_REQUIRED_TAGS } from "../../../scanners/tag-compliance.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { armClient, azurePaginate } from "../client.js";
import { parseAzureResourceId, toAzureUrn } from "../urn.js";
import {
  azField,
  azString,
  aztUntrusted,
  aztUntrustedOpt,
  azureErrorResult,
  azureNoSubscriptionResult,
  azureSafeFinding,
  azureSafeWarnings,
  azureScanEnv,
  azureSoftWarning,
  azureTruncationWarning,
  isAzureFatal,
  type AzureScanEnv,
} from "./shared.js";

export { DEFAULT_REQUIRED_TAGS };

export const AZURE_TAG_RISK = 4.0;
export const AZURE_TAG_MAX_ITEMS = 5000;

const RG_TYPE = "Microsoft.Resources/resourceGroups";
const RESOURCES_SERVICE = "Resources resources.list";
const RG_SERVICE = "Resources resourceGroups.list";

/** Tag keys of an ARM resource (`tags` object; non-object → none). Raw. */
export function azureTagKeys(resource: unknown): string[] {
  const tags = azField(resource, "tags");
  if (!tags || typeof tags !== "object" || Array.isArray(tags)) return [];
  try {
    return Object.keys(tags as Record<string, unknown>).filter((k) => k.trim().length > 0);
  } catch {
    return [];
  }
}

/** Required tags absent from `keys` (case-insensitive: Azure tag names are case-insensitive). */
export function azureMissingRequiredTags(keys: readonly string[], required: readonly string[] = DEFAULT_REQUIRED_TAGS): string[] {
  const have = new Set(keys.map((k) => k.trim().toLowerCase()));
  return required.filter((t) => !have.has(t.toLowerCase()));
}

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return azureSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "azure" });
}

/** One finding for a resource / resource group missing required tags; undefined when compliant. */
export function azureTagFinding(resource: unknown, env: AzureScanEnv, module: string, isResourceGroup = false): Finding | undefined {
  const keys = azureTagKeys(resource);
  const missing = azureMissingRequiredTags(keys);
  if (missing.length === 0) return undefined;

  const rawId = azString(azField(resource, "id"));
  const parsed = rawId ? parseAzureResourceId(rawId) : undefined;
  const rawName = azString(azField(resource, "name")) ?? parsed?.name ?? "unknown";
  const rawType = isResourceGroup ? RG_TYPE : azString(azField(resource, "type")) ?? parsed?.resourceType ?? "resource";
  const name = aztUntrusted(rawName);
  const resourceType = aztUntrusted(rawType);
  const rg = isResourceGroup ? undefined : aztUntrustedOpt(parsed?.resourceGroup);
  const label = isResourceGroup ? "Resource group" : `${resourceType} resource`;
  const where = `${rg ? `resource group ${rg}, ` : ""}subscription ${aztUntrusted(env.subscriptionId)}`;
  const list = missing.join(", ");

  return makeFinding({
    riskScore: AZURE_TAG_RISK,
    title: `${label} ${name} missing required tags: ${list}`,
    resourceType,
    resourceId: name,
    resourceArn: toAzureUrn({ id: rawId, subscriptionId: env.subscriptionId, resourceGroup: parsed?.resourceGroup, resourceType: rawType, name: rawName }),
    region: aztUntrustedOpt(azField(resource, "location")) ?? "global",
    description:
      keys.length === 0
        ? `${label} "${name}" (${where}) has no tags configured. Missing all required tags: ${list}.`
        : `${label} "${name}" (${where}) is missing the following required tags: ${list}. Present tags: ${keys.map(aztUntrusted).join(", ")}.`,
    impact: "Resources without proper tags cannot be tracked for cost allocation, ownership, or compliance purposes.",
    remediationSteps: [
      `Add the missing tags (${list}) to ${isResourceGroup ? "resource group" : "resource"} ${name}.`,
      'Enforce tagging with Azure Policy (e.g. the built-in "Require a tag on resources" / "Inherit a tag from the resource group" definitions).',
      "Use the Azure portal Tags blade or `az tag update` for bulk tagging operations.",
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

export class AzureTagComplianceScanner implements Scanner {
  readonly moduleName = "tag_compliance";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    let env: AzureScanEnv | undefined;
    let client: ResourceManagementClient;
    try {
      env = azureScanEnv(ctx);
      if (!env) return azureNoSubscriptionResult(this.moduleName, startMs, ctx);
      const { ResourceManagementClient } = await import("@azure/arm-resources");
      client = await armClient(ResourceManagementClient, env.credentials, env.subscriptionId);
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, "Azure tag compliance scan failed", err);
    }

    const scanEnv = env;
    const parts = await Promise.all([
      this.category(() => client.resources.list(), RESOURCES_SERVICE, "resource tags not checked", scanEnv, false),
      this.category(() => client.resourceGroups.list(), RG_SERVICE, "resource group tags not checked", scanEnv, true),
    ]);
    const warnings = parts.flatMap((p) => p.warnings);
    const fatal = parts.find((p) => p.fatal !== undefined);
    if (fatal) return azureErrorResult(this.moduleName, startMs, "Azure tag compliance scan failed", fatal.fatal, warnings);

    const findings = parts.flatMap((p) => p.findings);
    return {
      module: this.moduleName,
      status: "success",
      ...(warnings.length > 0 ? { warnings: azureSafeWarnings(warnings) } : {}),
      resourcesScanned: parts.reduce((n, p) => n + p.scanned, 0),
      findingsCount: findings.length,
      scanTimeMs: Date.now() - startMs,
      findings,
    };
  }

  private async category(iter: () => AsyncIterable<unknown>, service: string, consequence: string, env: AzureScanEnv, isResourceGroup: boolean): Promise<SubResult> {
    const out: SubResult = { findings: [], scanned: 0, warnings: [] };
    try {
      const page = await azurePaginate(iter(), {
        max: AZURE_TAG_MAX_ITEMS,
        collect: false,
        onItem: (item) => {
          const f = azureTagFinding(item, env, this.moduleName, isResourceGroup);
          if (f) out.findings.push(f);
        },
      });
      out.scanned = page.count;
      if (page.truncated) out.warnings.push(azureTruncationWarning(service, AZURE_TAG_MAX_ITEMS));
    } catch (err) {
      if (isAzureFatal(err)) return { ...out, fatal: err };
      out.warnings.push(`${azureSoftWarning(service, err)} — ${consequence}.`);
    }
    return out;
  }
}
