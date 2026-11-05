/**
 * Microsoft Defender for Cloud vulnerability scanner (moduleName `inspector_findings`,
 * plan §2 #13 / §4.1 P2 / T7). EXPERIMENTAL — not yet validated against a live account;
 * field names follow the `@azure/arm-security` 5.x d.ts (`SecuritySubAssessment`;
 * AutoRest client, properties flattened — a nested `properties` object is also accepted).
 *
 * Amazon Inspector counterpart: Defender vulnerability-assessment sub-assessments (server
 * VA, container registry image VA, SQL VA) — one record per vulnerability × resource.
 *
 *  1. `SecurityCenter.subAssessments.listAll("/subscriptions/<sub>")` (paged, capped at
 *     {@link AZURE_SUBASSESSMENT_MAX_ITEMS} with a truncation warning). Only status
 *     `Unhealthy` records are kept.
 *  2. Records are aggregated per vulnerability (`idPropertiesId`, else `displayName`, within
 *     its `additionalData.assessedResourceType`) with the affected resources, CVE IDs
 *     (`additionalData.cve[].title`), highest CVSS base score (`additionalData.cvss{}.base`),
 *     patchability and the highest `status.severity`.
 *  3. riskScore = highest CVSS base when reported, else severity High 8.0 / Medium 5.5 /
 *     Low 3.0 (unknown → 5.5). One Finding per vulnerability, sorted by risk, affected
 *     resources and name, capped at {@link AZURE_SUBASSESSMENT_MAX_FINDINGS} (same approach
 *     as the Alibaba SAS / Huawei HSS scanners) with an overflow warning carrying the
 *     per-severity counts.
 *
 * Errors: auth_failed / api_misuse → `status: "error"`; Microsoft.Security not registered /
 * Defender vulnerability assessment not available (common in Azure China) → not_enabled
 * warning + success; access denied / throttled / network → warning + success. Every
 * server-sourced string passes through aztUntrusted.
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
  azLastSegment,
  azNumber,
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

export const AZURE_SUBASSESSMENT_SOURCE = "Defender for Cloud vulnerability assessment";
export const AZURE_SUBASSESSMENTS_NOT_ENABLED_WARNING =
  "Microsoft Defender for Cloud (Microsoft.Security) is not registered / vulnerability assessment is not available for this subscription; no vulnerability (Inspector-equivalent) data available.";

/** Sub-assessments listed per subscription. */
export const AZURE_SUBASSESSMENT_MAX_ITEMS = 5000;
/** Vulnerabilities reported as individual findings. */
export const AZURE_SUBASSESSMENT_MAX_FINDINGS = 50;
/** Affected resources / CVE IDs named in one finding's description. */
const MAX_LISTED_RESOURCES = 10;
const MAX_LISTED_CVES = 20;

export type AzureVulnSeverity = "high" | "medium" | "low" | "unknown";

export const AZURE_VULN_RISK: Readonly<Record<AzureVulnSeverity, number>> = { high: 8.0, medium: 5.5, low: 3.0, unknown: 5.5 };
const SEVERITY_RANK: Readonly<Record<AzureVulnSeverity, number>> = { high: 0, medium: 1, low: 2, unknown: 3 };

const SUB_SERVICE = "Defender for Cloud subAssessments.listAll";
const SUBASSESSMENT_TAIL_RE = /\/providers\/Microsoft\.Security\/assessments\/[^/]+\/subAssessments\/[^/]+\/?$/i;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

/** Sub-assessment property: flattened (SDK) or nested under `properties` (raw ARM). */
function prop(sa: unknown, key: string): unknown {
  const direct = azField(sa, key);
  return direct !== undefined ? direct : azField(azField(sa, "properties"), key);
}

export function isAzureSubAssessmentUnhealthy(sa: unknown): boolean {
  return azString(azField(prop(sa, "status"), "code"))?.toLowerCase() === "unhealthy";
}

export function azureVulnSeverity(sa: unknown): AzureVulnSeverity {
  const s = azString(azField(prop(sa, "status"), "severity"))?.toLowerCase();
  return s === "high" || s === "medium" || s === "low" ? s : "unknown";
}

/** Assessed resource ID (raw): `resourceDetails.id`, else the sub-assessment ID minus its tail. */
export function azureSubAssessedResourceId(sa: unknown): string | undefined {
  const direct = azString(azField(prop(sa, "resourceDetails"), "id"));
  if (direct) return direct;
  const id = azString(azField(sa, "id"));
  if (!id) return undefined;
  const stripped = id.replace(SUBASSESSMENT_TAIL_RE, "");
  return stripped && stripped !== id ? stripped : undefined;
}

/** On-premises machine label (raw) when the resource is not in Azure. */
function onPremiseLabel(sa: unknown): string | undefined {
  const details = prop(sa, "resourceDetails");
  return azString(azField(details, "machineName")) ?? azString(azField(details, "serverName")) ?? azString(azField(details, "vmuuid"));
}

/** CVE IDs of a record (`additionalData.cve[].title`; titles that are not CVE IDs are ignored). Raw. */
export function azureSubAssessmentCves(sa: unknown): string[] {
  return azArray(azField(prop(sa, "additionalData"), "cve"))
    .map((c) => azString(azField(c, "title")))
    .filter((t): t is string => !!t && CVE_RE.test(t))
    .map((t) => t.toUpperCase());
}

/** Highest CVSS base score of a record (`additionalData.cvss{<version>: {base}}`). */
export function azureSubAssessmentCvss(sa: unknown): number | undefined {
  const cvss = azField(prop(sa, "additionalData"), "cvss");
  if (!cvss || typeof cvss !== "object") return undefined;
  let max: number | undefined;
  try {
    for (const v of Object.values(cvss as Record<string, unknown>)) {
      const base = azNumber(azField(v, "base"));
      if (base !== undefined && base >= 0 && base <= 10 && (max === undefined || base > max)) max = base;
    }
  } catch {
    return max;
  }
  return max;
}

export interface AzureVulnSummary {
  /** Vulnerability ID (`idPropertiesId`, else display name), redacted. */
  vulnId: string;
  /** Display name, redacted. */
  name: string;
  /** `additionalData.assessedResourceType`, redacted. */
  kind?: string;
  severity: AzureVulnSeverity;
  cvss?: number;
  patchable: boolean;
  category?: string;
  remediation?: string;
  impact?: string;
  /** Distinct affected resource labels, redacted. */
  resources: string[];
  /** Raw ARM ID of the first affected Azure resource (for the URN when only one is affected). */
  firstResourceId?: string;
  cves: string[];
}

export function azureVulnRiskScore(v: Pick<AzureVulnSummary, "severity" | "cvss">): number {
  return v.cvss !== undefined ? Math.round(v.cvss * 10) / 10 : AZURE_VULN_RISK[v.severity];
}

/** Aggregate Unhealthy sub-assessments into one summary per vulnerability — pure. */
export function aggregateAzureSubAssessments(records: unknown[]): AzureVulnSummary[] {
  const byKey = new Map<string, { s: AzureVulnSummary; resources: Set<string>; cves: Set<string> }>();
  for (const sa of records) {
    const rawVuln = azString(prop(sa, "idPropertiesId")) ?? azString(prop(sa, "displayName"));
    if (!rawVuln) continue;
    const rawKind = azString(azField(prop(sa, "additionalData"), "assessedResourceType"));
    const key = `${rawKind?.toLowerCase() ?? ""}|${rawVuln.toLowerCase()}`;
    const severity = azureVulnSeverity(sa);
    const cvss = azureSubAssessmentCvss(sa);
    const patchable = azField(prop(sa, "additionalData"), "patchable") === true;

    let entry = byKey.get(key);
    if (!entry) {
      const vulnId = aztUntrusted(rawVuln);
      entry = {
        s: {
          vulnId,
          name: aztUntrustedOpt(prop(sa, "displayName")) ?? vulnId,
          kind: aztUntrustedOpt(rawKind),
          severity,
          cvss,
          patchable,
          category: aztUntrustedOpt(prop(sa, "category")),
          remediation: aztUntrustedOpt(prop(sa, "remediation")),
          impact: aztUntrustedOpt(prop(sa, "impact")),
          resources: [],
          cves: [],
        },
        resources: new Set(),
        cves: new Set(),
      };
      byKey.set(key, entry);
    } else {
      if (SEVERITY_RANK[severity] < SEVERITY_RANK[entry.s.severity]) entry.s.severity = severity;
      if (cvss !== undefined && (entry.s.cvss === undefined || cvss > entry.s.cvss)) entry.s.cvss = cvss;
      entry.s.patchable ||= patchable;
    }

    const rawResource = azureSubAssessedResourceId(sa);
    const label = rawResource
      ? aztUntrustedOpt(parseAzureResourceId(rawResource)?.name) ?? aztUntrustedOpt(azLastSegment(rawResource))
      : aztUntrustedOpt(onPremiseLabel(sa));
    if (label && !entry.resources.has(label)) {
      entry.resources.add(label);
      if (rawResource && entry.s.firstResourceId === undefined) entry.s.firstResourceId = rawResource;
    }
    for (const c of azureSubAssessmentCves(sa)) entry.cves.add(aztUntrusted(c));
  }
  return [...byKey.values()].map(({ s, resources, cves }) => ({ ...s, resources: [...resources], cves: [...cves] }));
}

/** Highest risk first, then most affected resources, then kind / ID for stability. */
export function sortAzureVulnSummaries(list: AzureVulnSummary[]): AzureVulnSummary[] {
  return [...list].sort((a, b) => {
    const ra = azureVulnRiskScore(a);
    const rb = azureVulnRiskScore(b);
    if (ra !== rb) return rb - ra;
    if (a.resources.length !== b.resources.length) return b.resources.length - a.resources.length;
    const ka = `${a.kind ?? ""}|${a.vulnId}`;
    const kb = `${b.kind ?? ""}|${b.vulnId}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return azureSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "azure" });
}

const KIND_LABELS: Readonly<Record<string, string>> = {
  servervulnerabilityassessment: "server",
  containerregistryvulnerability: "container image",
  sqlservervulnerability: "SQL",
};

/** One Finding per aggregated vulnerability. Exported for unit tests. */
export function azureVulnFinding(v: AzureVulnSummary, env: AzureScanEnv, module: string): Finding {
  const riskScore = azureVulnRiskScore(v);
  const kindLabel = v.kind ? KIND_LABELS[v.kind.toLowerCase()] ?? v.kind : undefined;
  const count = v.resources.length;
  const single = count === 1 && v.firstResourceId !== undefined;
  const parsed = single ? parseAzureResourceId(v.firstResourceId as string) : undefined;
  const shown = v.resources.slice(0, MAX_LISTED_RESOURCES);
  const more = count > shown.length ? ` and ${count - shown.length} more` : "";
  const cves = v.cves.slice(0, MAX_LISTED_CVES);
  const moreCves = v.cves.length > cves.length ? ` (+${v.cves.length - cves.length} more)` : "";
  const subject = v.name !== v.vulnId ? `${v.name} (${v.vulnId})` : v.name;

  const descParts = [
    `Defender for Cloud ${kindLabel ? `${kindLabel} ` : ""}vulnerability assessment reports "${subject}" on ${count} resource(s) in subscription ${aztUntrusted(env.subscriptionId)}${count > 0 ? `: ${shown.join(", ")}${more}` : ""}`,
    `Severity: ${v.severity === "unknown" ? "unrated" : v.severity}${v.cvss !== undefined ? `, CVSS ${v.cvss}` : ""}`,
    cves.length > 0 ? `CVEs: ${cves.join(", ")}${moreCves}` : undefined,
    v.category ? `Category: ${v.category}` : undefined,
    v.patchable ? "A patch is available" : undefined,
  ].filter((p): p is string => Boolean(p));

  return makeFinding({
    riskScore,
    title: `Vulnerability ${v.name}${cves.length > 0 && !v.name.includes(cves[0]) ? ` (${cves[0]}${v.cves.length > 1 ? ", …" : ""})` : ""} on ${count} resource(s)`,
    resourceType: single ? aztUntrustedOpt(parsed?.resourceType) ?? "resource" : "Microsoft.Security/subAssessments",
    resourceId: single ? shown[0] : v.vulnId,
    resourceArn: single
      ? toAzureUrn({ id: v.firstResourceId, resourceType: "resource", name: "" })
      : toAzureUrn({ subscriptionId: env.subscriptionId, resourceType: "Microsoft.Security/subAssessments", name: v.vulnId }),
    region: "global",
    description: descParts.join(". ") + ".",
    impact: v.impact ?? "Unpatched vulnerabilities can be exploited for remote code execution, privilege escalation or data exposure.",
    remediationSteps: [
      ...(v.remediation ? [v.remediation] : []),
      `Open Microsoft Defender for Cloud → Recommendations → vulnerability findings and locate "${v.name}".`,
      v.patchable ? "Apply the available vendor patch / update the affected package or image, then redeploy." : "Apply the vendor fix or a compensating control (configuration change, isolation) on the affected resources.",
      "Re-scan (or wait for the next vulnerability assessment cycle) and confirm the finding is Healthy.",
    ],
    accountId: env.tenantId,
    module,
    source: AZURE_SUBASSESSMENT_SOURCE,
  });
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

interface SecurityCenterSubAssessmentsApi {
  subAssessments: { listAll(scope: string): AsyncIterable<unknown> };
}

export class AzureDefenderSubAssessmentsScanner implements Scanner {
  readonly moduleName = "inspector_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];

    let env: AzureScanEnv | undefined;
    const unhealthy: unknown[] = [];
    let scanned = 0;
    try {
      env = azureScanEnv(ctx);
      if (!env) return azureNoSubscriptionResult(this.moduleName, startMs, ctx);
      const { SecurityCenter } = await import("@azure/arm-security");
      const client = (await armClient(SecurityCenter, env.credentials, env.subscriptionId)) as unknown as SecurityCenterSubAssessmentsApi;
      const page = await azurePaginate(client.subAssessments.listAll(`/subscriptions/${env.subscriptionId}`), {
        max: AZURE_SUBASSESSMENT_MAX_ITEMS,
        collect: false,
        onItem: (sa) => {
          if (isAzureSubAssessmentUnhealthy(sa)) unhealthy.push(sa);
        },
      });
      scanned = page.count;
      if (page.truncated) warnings.push(azureTruncationWarning(SUB_SERVICE, AZURE_SUBASSESSMENT_MAX_ITEMS));
    } catch (err) {
      const { kind } = classifyAzureError(err);
      if (kind === "not_enabled" || kind === "not_found") {
        warnings.push(`${AZURE_SUBASSESSMENTS_NOT_ENABLED_WARNING} (${describeAzureError(err)})`);
        return azureEmptyResult(this.moduleName, startMs, { warnings });
      }
      if (!isAzureFatal(err) && kind !== "other") {
        warnings.push(`${azureSoftWarning(SUB_SERVICE, err)} — vulnerability findings not checked.`);
        return azureEmptyResult(this.moduleName, startMs, { warnings });
      }
      return azureErrorResult(this.moduleName, startMs, "Defender for Cloud vulnerability scan failed", err, warnings);
    }

    const scanEnv = env;
    try {
      const vulns = sortAzureVulnSummaries(aggregateAzureSubAssessments(unhealthy));
      const counts: Record<AzureVulnSeverity, number> = { high: 0, medium: 0, low: 0, unknown: 0 };
      for (const v of vulns) counts[v.severity]++;
      const findings = vulns.slice(0, AZURE_SUBASSESSMENT_MAX_FINDINGS).map((v) => azureVulnFinding(v, scanEnv, this.moduleName));
      if (vulns.length > AZURE_SUBASSESSMENT_MAX_FINDINGS) {
        warnings.push(
          `Defender for Cloud: ${vulns.length} distinct vulnerabilities (high ${counts.high}, medium ${counts.medium}, low ${counts.low}${counts.unknown ? `, unrated ${counts.unknown}` : ""}); only the top ${AZURE_SUBASSESSMENT_MAX_FINDINGS} (by risk and affected resources) are reported as findings. Review the rest in Defender for Cloud.`,
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
      return azureErrorResult(this.moduleName, startMs, "Defender for Cloud vulnerability scan failed", err, warnings);
    }
  }
}
