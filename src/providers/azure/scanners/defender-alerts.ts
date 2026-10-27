/**
 * Microsoft Defender for Cloud security alert scanner (moduleName `guardduty_findings`,
 * plan §2 #12 / §4.1 P2 / T7). EXPERIMENTAL — not yet validated against a live account;
 * field names follow the `@azure/arm-security` 5.x d.ts (`Alert`; AutoRest client, so
 * properties are flattened — a nested `properties` object is also accepted).
 *
 * GuardDuty counterpart: Defender threat-detection alerts (brute force, suspicious
 * processes, anomalous sign-ins, crypto mining, …).
 *
 *  1. `SecurityCenter.alerts.list()` (subscription scope, paged, capped at
 *     {@link AZURE_ALERT_MAX_ITEMS} with a truncation warning).
 *  2. Only alerts in status `Active` (absent status = Active, per the d.ts) are reported;
 *     `Resolved` / `Dismissed` are counted as scanned but skipped.
 *  3. Severity: High → HIGH 8.0, Medium → MEDIUM 6.0, Low → LOW 3.0, Informational → LOW 1.0
 *     (unknown → 6.0). One Finding per alert, most severe / most recent first, capped at
 *     {@link AZURE_ALERT_MAX_FINDINGS} with an overflow warning carrying the per-severity
 *     counts (same approach as the Alibaba SAS alert scanner).
 *  Resource: the first `resourceIdentifiers[]` `AzureResource.azureResourceId`, else the
 *  alert ID; `compromisedEntity` is the display name. Region = `/locations/<ascLocation>/`
 *  segment of the alert ID.
 *
 * Errors: auth_failed / api_misuse → `status: "error"`; Microsoft.Security not registered /
 * Defender not available (common in Azure China) → not_enabled warning + success; access
 * denied / throttled / network → warning + success. Every server-sourced string passes
 * through aztUntrusted.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { armClient, azurePaginate } from "../client.js";
import { classifyAzureError, describeAzureError } from "../errors.js";
import { parseAzureResourceId, toAzureUrn } from "../urn.js";
import {
  azArray,
  azField,
  azString,
  aztUntrusted,
  aztUntrustedOpt,
  azureEmptyResult,
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

export const AZURE_ALERT_SOURCE = "Defender for Cloud";
export const AZURE_ALERTS_NOT_ENABLED_WARNING =
  "Microsoft Defender for Cloud (Microsoft.Security) is not registered / not available for this subscription; no security alert (threat detection) data available.";

/** Alerts listed per subscription. */
export const AZURE_ALERT_MAX_ITEMS = 5000;
/** Alerts reported as individual findings. */
export const AZURE_ALERT_MAX_FINDINGS = 100;
/** Remediation steps copied from one alert. */
const MAX_ALERT_REMEDIATION_STEPS = 10;
/** Longest alert description kept (characters). */
const MAX_DESCRIPTION_CHARS = 1000;

export type AzureAlertSeverity = "high" | "medium" | "low" | "informational" | "unknown";

export const AZURE_ALERT_RISK: Readonly<Record<AzureAlertSeverity, number>> = { high: 8.0, medium: 6.0, low: 3.0, informational: 1.0, unknown: 6.0 };
const SEVERITY_RANK: Readonly<Record<AzureAlertSeverity, number>> = { high: 0, medium: 1, low: 2, informational: 3, unknown: 4 };

const ALERT_SERVICE = "Defender for Cloud alerts.list";

/** Alert property: flattened (SDK) or nested under `properties` (raw ARM). */
function prop(alert: unknown, key: string): unknown {
  const direct = azField(alert, key);
  return direct !== undefined ? direct : azField(azField(alert, "properties"), key);
}

/** Normalised alert severity (case-insensitive). */
export function azureAlertSeverity(alert: unknown): AzureAlertSeverity {
  const s = azString(prop(alert, "severity"))?.toLowerCase();
  return s === "high" || s === "medium" || s === "low" || s === "informational" ? s : "unknown";
}

/** Active (or status not reported — Active is the service default). */
export function isAzureAlertActive(alert: unknown): boolean {
  const s = azString(prop(alert, "status"))?.toLowerCase();
  return s === undefined || s === "active";
}

function timeMs(v: unknown): number {
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? 0 : v.getTime();
  if (typeof v === "string") {
    const t = Date.parse(v);
    return Number.isNaN(t) ? 0 : t;
  }
  return 0;
}

function lastSeenMs(alert: unknown): number {
  return timeMs(prop(alert, "endTimeUtc")) || timeMs(prop(alert, "timeGeneratedUtc")) || timeMs(prop(alert, "startTimeUtc"));
}

function isoTime(v: unknown): string | undefined {
  const t = timeMs(v);
  return t > 0 ? new Date(t).toISOString() : undefined;
}

/** Most severe first, then most recent, then by ID for stability. */
export function sortAzureAlerts<T>(alerts: T[]): T[] {
  return [...alerts].sort((a, b) => {
    const ra = SEVERITY_RANK[azureAlertSeverity(a)];
    const rb = SEVERITY_RANK[azureAlertSeverity(b)];
    if (ra !== rb) return ra - rb;
    const ta = lastSeenMs(a);
    const tb = lastSeenMs(b);
    if (ta !== tb) return tb - ta;
    const ia = azString(azField(a, "id")) ?? "";
    const ib = azString(azField(b, "id")) ?? "";
    return ia < ib ? -1 : ia > ib ? 1 : 0;
  });
}

/** ARM ID of the alerted resource (first `AzureResource` identifier). Raw. */
export function azureAlertResourceId(alert: unknown): string | undefined {
  for (const ri of azArray(prop(alert, "resourceIdentifiers"))) {
    const id = azString(azField(ri, "azureResourceId"));
    if (id) return id;
  }
  return undefined;
}

function clip(s: string | undefined): string | undefined {
  return s && s.length > MAX_DESCRIPTION_CHARS ? `${s.slice(0, MAX_DESCRIPTION_CHARS)}…` : s;
}

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return azureSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "azure" });
}

/** Map one Active alert to a Finding. Exported for unit tests. */
export function azureAlertFinding(alert: unknown, env: AzureScanEnv, module: string): Finding {
  const level = azureAlertSeverity(alert);
  const rawId = azString(azField(alert, "id"));
  const rawName = azString(azField(alert, "name")) ?? azString(prop(alert, "systemAlertId"));
  const alertName = aztUntrustedOpt(rawName) ?? "unknown";
  const displayName = aztUntrustedOpt(prop(alert, "alertDisplayName")) ?? aztUntrustedOpt(prop(alert, "alertType")) ?? "Defender for Cloud alert";
  const alertType = aztUntrustedOpt(prop(alert, "alertType"));
  const intent = aztUntrustedOpt(prop(alert, "intent"));
  const product = aztUntrustedOpt(prop(alert, "productName"));
  const incident = prop(alert, "isIncident") === true;

  const rawResource = azureAlertResourceId(alert);
  const parsed = rawResource ? parseAzureResourceId(rawResource) : undefined;
  const entity = aztUntrustedOpt(prop(alert, "compromisedEntity"));
  const resourceName = aztUntrustedOpt(parsed?.name) ?? entity ?? alertName;
  const asset = entity && entity !== resourceName ? `${resourceName} (${entity})` : resourceName;
  const resourceType = aztUntrustedOpt(parsed?.resourceType) ?? "Microsoft.Security/alerts";
  const resourceArn = rawResource
    ? toAzureUrn({ id: rawResource, resourceType: "resource", name: "" })
    : toAzureUrn({ id: rawId, subscriptionId: env.subscriptionId, resourceType: "Microsoft.Security/alerts", name: rawName ?? "unknown" });
  const location = rawId ? /\/locations\/([^/]+)\//i.exec(rawId)?.[1] : undefined;

  const first = isoTime(prop(alert, "startTimeUtc"));
  const last = isoTime(prop(alert, "endTimeUtc"));
  const desc = clip(aztUntrustedOpt(prop(alert, "description")));
  const uri = aztUntrustedOpt(prop(alert, "alertUri"));
  const kind = incident ? "security incident" : "security alert";
  const levelLabel = level === "unknown" ? "unrated" : level;

  const descParts = [
    `Defender for Cloud ${levelLabel}-severity ${kind} "${displayName}"${alertType && alertType !== displayName ? ` (type: ${alertType})` : ""} is active on ${asset} (subscription ${aztUntrusted(env.subscriptionId)})`,
    intent ? `Intent: ${intent}` : undefined,
    first ? `First seen: ${first}` : undefined,
    last ? `Last seen: ${last}` : undefined,
    desc ? `Details: ${desc}` : undefined,
    product ? `Product: ${product}` : undefined,
    `Alert: ${alertName}`,
  ].filter((p): p is string => Boolean(p));

  const serverSteps = azArray(prop(alert, "remediationSteps"))
    .slice(0, MAX_ALERT_REMEDIATION_STEPS)
    .map((s) => aztUntrustedOpt(s))
    .filter((s): s is string => Boolean(s));

  return makeFinding({
    riskScore: AZURE_ALERT_RISK[level],
    title: `Defender for Cloud ${levelLabel} ${incident ? "incident" : "alert"}: ${displayName} on ${asset}`,
    resourceType,
    resourceId: resourceName,
    resourceArn,
    region: aztUntrustedOpt(location) ?? "global",
    description: descParts.join(". ") + ".",
    impact:
      level === "high"
        ? "High-severity Defender alerts indicate a high likelihood of compromise (intrusion, malware, credential abuse or data exfiltration) that needs immediate response."
        : level === "low" || level === "informational"
          ? "Low-severity / informational alerts indicate benign-looking anomalies or blocked attacks that may precede an attack if left uninvestigated."
          : "Suspicious activity was detected on the resource; if malicious, it may lead to compromise or data exfiltration.",
    remediationSteps: [
      ...serverSteps,
      `Open Microsoft Defender for Cloud → Security alerts and locate the alert "${displayName}"${uri ? ` (${uri})` : ""}.`,
      "Investigate the alert details (entities, processes, source IPs, sign-in records) and the attack timeline.",
      "Contain the threat (isolate the VM, revoke credentials, block the source IP) and remediate the root cause.",
      "Resolve or dismiss the alert once handled (or create a suppression rule if confirmed benign).",
    ],
    accountId: env.tenantId,
    module,
    source: AZURE_ALERT_SOURCE,
  });
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

interface SecurityCenterAlertsApi {
  alerts: { list(): AsyncIterable<unknown> };
}

export class AzureDefenderAlertsScanner implements Scanner {
  readonly moduleName = "guardduty_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];

    let env: AzureScanEnv | undefined;
    const active: unknown[] = [];
    let scanned = 0;
    try {
      env = azureScanEnv(ctx);
      if (!env) return azureNoSubscriptionResult(this.moduleName, startMs, ctx);
      const { SecurityCenter } = await import("@azure/arm-security");
      const client = (await armClient(SecurityCenter, env.credentials, env.subscriptionId)) as unknown as SecurityCenterAlertsApi;
      const page = await azurePaginate(client.alerts.list(), {
        max: AZURE_ALERT_MAX_ITEMS,
        collect: false,
        onItem: (a) => {
          if (isAzureAlertActive(a)) active.push(a);
        },
      });
      scanned = page.count;
      if (page.truncated) warnings.push(azureTruncationWarning(ALERT_SERVICE, AZURE_ALERT_MAX_ITEMS));
    } catch (err) {
      const { kind } = classifyAzureError(err);
      if (kind === "not_enabled" || kind === "not_found") {
        warnings.push(`${AZURE_ALERTS_NOT_ENABLED_WARNING} (${describeAzureError(err)})`);
        return azureEmptyResult(this.moduleName, startMs, { warnings });
      }
      if (!isAzureFatal(err) && kind !== "other") {
        warnings.push(`${azureSoftWarning(ALERT_SERVICE, err)} — security alerts not checked.`);
        return azureEmptyResult(this.moduleName, startMs, { warnings });
      }
      return azureErrorResult(this.moduleName, startMs, "Defender for Cloud alert scan failed", err, warnings);
    }

    const scanEnv = env;
    try {
      const counts: Record<AzureAlertSeverity, number> = { high: 0, medium: 0, low: 0, informational: 0, unknown: 0 };
      for (const a of active) counts[azureAlertSeverity(a)]++;
      const sorted = sortAzureAlerts(active);
      const findings = sorted.slice(0, AZURE_ALERT_MAX_FINDINGS).map((a) => azureAlertFinding(a, scanEnv, this.moduleName));
      if (sorted.length > AZURE_ALERT_MAX_FINDINGS) {
        warnings.push(
          `Defender for Cloud: ${sorted.length} active alerts (high ${counts.high}, medium ${counts.medium}, low ${counts.low}, informational ${counts.informational}${counts.unknown ? `, unrated ${counts.unknown}` : ""}); only the top ${AZURE_ALERT_MAX_FINDINGS} (by severity and recency) are reported as findings. Review the rest in Defender for Cloud → Security alerts.`,
        );
      }
      return {
        module: this.moduleName,
        status: "success",
        ...(warnings.length > 0 ? { warnings: azureSafeWarnings(warnings) } : {}),
        resourcesScanned: scanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, "Defender for Cloud alert scan failed", err, warnings);
    }
  }
}
