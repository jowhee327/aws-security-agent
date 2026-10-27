/**
 * Microsoft Defender for Cloud assessment scanner (moduleName `defender_assessment_findings`,
 * aliased from `security_hub_findings`; plan §4.1 / T2). EXPERIMENTAL — not yet validated
 * against a live account; field names follow the `@azure/arm-security` 5.x d.ts.
 *
 * Azure analog of `src/scanners/security-hub-findings.ts`: every Defender recommendation
 * (assessment) in status `Unhealthy` becomes one Finding for the assessed resource.
 *
 * APIs (`SecurityCenter`, subscription scope):
 *  1. `assessments.list("/subscriptions/<sub>")` (paged, capped at
 *     {@link AZURE_DEFENDER_MAX_ASSESSMENTS}) → `status.code` Unhealthy → finding;
 *     Healthy / NotApplicable are skipped. Resource = `resourceDetails.id` (Azure source),
 *     else the assessment ID minus its `/providers/Microsoft.Security/assessments/<key>` tail.
 *  2. Severity from `metadata.severity` (High 7.5 / Medium 5.0 / Low 3.0; absent → Medium).
 *     The list API usually omits `metadata`, so when any Unhealthy assessment lacks it,
 *     `assessmentsMetadata.list()` (best effort, capped) supplies severity / display name /
 *     description / remediation by assessment key (the assessment `name`).
 *  3. Best effort, MLPS (等保) annotation (plan §4.4): `regulatoryComplianceStandards.list()`;
 *     for each standard that looks like MLPS and has data (state ≠ Unsupported), its failed
 *     controls' `regulatoryComplianceAssessments.list(standard, control)` give the assessment
 *     keys (last segment of `assessmentDetailsLink`, else the name) whose findings get
 *     `source = "Defender:<standard>"`. // unverified, needs live account: whether
 *     `assessmentDetailsLink` / name carry the assessment key in Azure China.
 *
 * Errors: auth_failed / api_misuse → `status: "error"`; Microsoft.Security not registered /
 * Defender not available (common in Azure China) → not_enabled warning + success; access
 * denied / throttled / network → warning + success. Metadata / compliance enrichment
 * failures are warnings only.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { armClient, azurePaginate } from "../client.js";
import { classifyAzureError, describeAzureError, redactAzureDiagnostic } from "../errors.js";
import { parseAzureResourceId, toAzureUrn } from "../urn.js";
import { isAzureMlps } from "./policy-compliance.js";
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
  azureScanEnv,
  azureSoftWarning,
  azureTruncationWarning,
  isAzureFatal,
  type AzureScanEnv,
} from "./shared.js";

export const AZURE_DEFENDER_SOURCE = "Defender for Cloud";
/** Source prefix for findings covered by an enabled MLPS regulatory compliance standard. */
export const AZURE_DEFENDER_STANDARD_SOURCE_PREFIX = "Defender";
export const AZURE_DEFENDER_NOT_ENABLED_WARNING =
  "Microsoft Defender for Cloud (Microsoft.Security) is not registered / not available for this subscription; no assessment findings available.";

export const AZURE_DEFENDER_MAX_ASSESSMENTS = 5000;
export const AZURE_DEFENDER_MAX_METADATA = 5000;
export const AZURE_DEFENDER_MAX_FINDINGS = 5000;
/** MLPS standards / failed controls examined for the source annotation (N+1 caps). */
export const AZURE_DEFENDER_MAX_MLPS_STANDARDS = 3;
export const AZURE_DEFENDER_MAX_MLPS_CONTROLS = 200;
export const AZURE_DEFENDER_MAX_CONTROL_ASSESSMENTS = 200;
export const AZURE_DEFENDER_CONTROL_CONCURRENCY = 5;

export const AZURE_DEFENDER_SEVERITY_SCORES: Readonly<Record<string, number>> = { high: 7.5, medium: 5.0, low: 3.0 };
export const AZURE_DEFENDER_DEFAULT_RISK_SCORE = 5.0;

const ASSESSMENT_TAIL_RE = /\/providers\/Microsoft\.Security\/assessments\/[^/]+\/?$/i;

/** Defender severity (High / Medium / Low, case-insensitive) → risk score; anything else → Medium. */
export function azureDefenderRiskScore(severity: unknown): number {
  const s = typeof severity === "string" ? severity.trim().toLowerCase() : "";
  return AZURE_DEFENDER_SEVERITY_SCORES[s] ?? AZURE_DEFENDER_DEFAULT_RISK_SCORE;
}

export function isAzureUnhealthy(code: unknown): boolean {
  return typeof code === "string" && code.trim().toLowerCase() === "unhealthy";
}

/** Assessed resource ID (raw): `resourceDetails.id`, else the assessment ID without its assessment tail. */
export function assessedResourceId(assessment: unknown): string | undefined {
  const details = azField(assessment, "resourceDetails");
  const direct = azString(azField(details, "id")) ?? azString(azField(details, "resourceId"));
  if (direct) return direct;
  const id = azString(azField(assessment, "id"));
  if (!id) return undefined;
  const stripped = id.replace(ASSESSMENT_TAIL_RE, "");
  return stripped && stripped !== id ? stripped : undefined;
}

/** Display metadata for an assessment key (from the assessment itself or assessmentsMetadata). */
export interface AzureAssessmentMeta {
  displayName?: string;
  severity?: string;
  description?: string;
  remediationDescription?: string;
  categories?: string[];
}

function metaFrom(obj: unknown): AzureAssessmentMeta {
  return {
    displayName: azString(azField(obj, "displayName")),
    severity: azString(azField(obj, "severity")),
    description: azString(azField(obj, "description")),
    remediationDescription: azString(azField(obj, "remediationDescription")),
    categories: azArray(azField(obj, "categories")).filter((c): c is string => typeof c === "string"),
  };
}

/** Map one Unhealthy assessment to a Finding. Exported for unit tests. */
export function assessmentToFinding(
  assessment: unknown,
  ctx: { env: AzureScanEnv; module: string; meta?: AzureAssessmentMeta; standard?: string },
): Finding {
  const own = metaFrom(azField(assessment, "metadata"));
  const fallback = ctx.meta ?? {};
  const status = azField(assessment, "status");
  // Every server-sourced string is redacted here, before it is used anywhere below.
  const key = aztUntrustedOpt(azField(assessment, "name")) ?? "unknown";
  const displayName = aztUntrustedOpt(azField(assessment, "displayName")) ?? aztUntrustedOpt(own.displayName) ?? aztUntrustedOpt(fallback.displayName) ?? key;
  const severityRaw = own.severity ?? fallback.severity;
  const riskScore = azureDefenderRiskScore(severityRaw);
  const severity = severityFromScore(riskScore);
  const rawResource = assessedResourceId(assessment);
  const parsed = rawResource ? parseAzureResourceId(rawResource) : undefined;
  const resourceArn = rawResource
    ? toAzureUrn({ id: rawResource, resourceType: "resource", name: "" })
    : toAzureUrn({ subscriptionId: ctx.env.subscriptionId, resourceType: "Microsoft.Security/assessments", name: key });
  const resourceName = aztUntrustedOpt(parsed?.name) ?? aztUntrustedOpt(azLastSegment(rawResource)) ?? key;
  const resourceType =
    aztUntrustedOpt(parsed?.resourceType) ??
    (parsed?.resourceGroup ? "Microsoft.Resources/resourceGroups" : parsed?.subscriptionId ? "Microsoft.Resources/subscriptions" : "Microsoft.Security/assessments");
  const description = aztUntrustedOpt(own.description) ?? aztUntrustedOpt(fallback.description);
  const remediation = aztUntrustedOpt(own.remediationDescription) ?? aztUntrustedOpt(fallback.remediationDescription);
  const cause = aztUntrustedOpt(azField(status, "cause"));
  const statusDescription = aztUntrustedOpt(azField(status, "description"));
  const categories = (own.categories && own.categories.length > 0 ? own.categories : fallback.categories ?? []).map(aztUntrusted).filter((c) => c);
  const standard = aztUntrustedOpt(ctx.standard);
  const source = standard ? `${AZURE_DEFENDER_STANDARD_SOURCE_PREFIX}:${standard}` : AZURE_DEFENDER_SOURCE;

  const desc: string[] = [
    `Defender for Cloud recommendation "${displayName}" is Unhealthy for ${resourceType} ${resourceName} (subscription ${aztUntrusted(ctx.env.subscriptionId)}).`,
  ];
  if (description) desc.push(description);
  if (statusDescription) desc.push(`Status: ${statusDescription}.`);
  if (cause) desc.push(`Cause: ${cause}.`);
  if (categories.length > 0) desc.push(`Categories: ${categories.join(", ")}.`);
  if (standard) desc.push(`Regulatory compliance standard: ${standard}.`);

  const remediationSteps: string[] = [];
  if (remediation) remediationSteps.push(remediation);
  remediationSteps.push(
    `Open Microsoft Defender for Cloud → Recommendations → "${displayName}" and remediate the affected resource ${resourceName}.`,
  );
  remediationSteps.push("After the fix, wait for the next assessment cycle (or trigger a re-scan) and confirm the status is Healthy.");

  return azureSafeFinding({
    severity,
    title: `Defender for Cloud: ${displayName}`,
    resourceType,
    resourceId: resourceName,
    resourceArn,
    region: "global",
    description: desc.join(" "),
    impact: `Source: ${source} (${key})`,
    riskScore,
    remediationSteps,
    priority: priorityFromSeverity(severity),
    module: ctx.module,
    accountId: ctx.env.tenantId,
    source,
    provider: "azure",
  });
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

interface SecurityCenterApi {
  assessments: { list(scope: string): AsyncIterable<unknown> };
  assessmentsMetadata: { list(): AsyncIterable<unknown> };
  regulatoryComplianceStandards: { list(): AsyncIterable<unknown> };
  regulatoryComplianceControls: { list(standard: string): AsyncIterable<unknown> };
  regulatoryComplianceAssessments: { list(standard: string, control: string): AsyncIterable<unknown> };
}

export class AzureDefenderAssessmentsScanner implements Scanner {
  readonly moduleName = "defender_assessment_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];

    let env: AzureScanEnv | undefined;
    let client: SecurityCenterApi;
    let unhealthy: unknown[];
    let scanned = 0;
    try {
      env = azureScanEnv(ctx);
      if (!env) return azureNoSubscriptionResult(this.moduleName, startMs, ctx);
      const { SecurityCenter } = await import("@azure/arm-security");
      client = (await armClient(SecurityCenter, env.credentials, env.subscriptionId)) as unknown as SecurityCenterApi;
      unhealthy = [];
      const page = await azurePaginate(client.assessments.list(`/subscriptions/${env.subscriptionId}`), {
        max: AZURE_DEFENDER_MAX_ASSESSMENTS,
        collect: false,
        onItem: (a) => {
          if (isAzureUnhealthy(azField(azField(a, "status"), "code"))) unhealthy.push(a);
        },
      });
      scanned = page.count;
      if (page.truncated) warnings.push(azureTruncationWarning("Defender for Cloud assessments.list", AZURE_DEFENDER_MAX_ASSESSMENTS));
    } catch (err) {
      const { kind } = classifyAzureError(err);
      if (kind === "not_enabled" || kind === "not_found") {
        warnings.push(`${AZURE_DEFENDER_NOT_ENABLED_WARNING} (${describeAzureError(err)})`);
        return azureEmptyResult(this.moduleName, startMs, { warnings });
      }
      if (!isAzureFatal(err) && kind !== "other") {
        warnings.push(azureSoftWarning("Defender for Cloud assessments.list", err));
        return azureEmptyResult(this.moduleName, startMs, { warnings });
      }
      return azureErrorResult(this.moduleName, startMs, "Defender for Cloud assessment scan failed", err, warnings);
    }

    try {
      const needsMeta = unhealthy.some((a) => !azString(azField(azField(a, "metadata"), "severity")));
      const meta = needsMeta ? await this.loadMetadata(client, warnings) : new Map<string, AzureAssessmentMeta>();
      const mlps = unhealthy.length > 0 ? await this.loadMlpsKeys(client, warnings) : new Map<string, string>();

      const findings: Finding[] = [];
      const seen = new Set<string>();
      let truncated = false;
      for (const a of unhealthy) {
        const keyRaw = azString(azField(a, "name"))?.toLowerCase() ?? "";
        const dedupe = `${azString(azField(a, "id"))?.toLowerCase() ?? ""}|${keyRaw}|${assessedResourceId(a)?.toLowerCase() ?? ""}`;
        if (seen.has(dedupe)) continue;
        seen.add(dedupe);
        if (findings.length >= AZURE_DEFENDER_MAX_FINDINGS) {
          truncated = true;
          continue;
        }
        findings.push(assessmentToFinding(a, { env, module: this.moduleName, meta: meta.get(keyRaw), standard: mlps.get(keyRaw) }));
      }
      if (truncated) warnings.push(`Defender for Cloud: more than ${AZURE_DEFENDER_MAX_FINDINGS} unhealthy assessments; findings were truncated.`);

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings.map(redactAzureDiagnostic) : undefined,
        resourcesScanned: scanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, "Defender for Cloud assessment scan failed", err, warnings);
    }
  }

  /** assessmentsMetadata.list() (best effort) → lower-cased assessment key → metadata. */
  private async loadMetadata(client: SecurityCenterApi, warnings: string[]): Promise<Map<string, AzureAssessmentMeta>> {
    const map = new Map<string, AzureAssessmentMeta>();
    try {
      const page = await azurePaginate(client.assessmentsMetadata.list(), {
        max: AZURE_DEFENDER_MAX_METADATA,
        collect: false,
        onItem: (m) => {
          const name = azString(azField(m, "name"));
          if (name) map.set(name.toLowerCase(), metaFrom(m));
        },
      });
      if (page.truncated) warnings.push(azureTruncationWarning("Defender for Cloud assessmentsMetadata.list", AZURE_DEFENDER_MAX_METADATA));
    } catch (err) {
      if (isAzureFatal(err)) throw err;
      warnings.push(`${azureSoftWarning("Defender for Cloud assessmentsMetadata.list", err)} — severities default to Medium where the assessment carries none.`);
    }
    return map;
  }

  /**
   * Assessment keys (lower-cased) covered by an MLPS regulatory compliance standard →
   * standard name (raw; redacted at emission). Best effort; never fails the module unless fatal.
   */
  private async loadMlpsKeys(client: SecurityCenterApi, warnings: string[]): Promise<Map<string, string>> {
    const keys = new Map<string, string>();
    let standards: string[];
    try {
      const page = await azurePaginate(client.regulatoryComplianceStandards.list(), { max: 500 });
      standards = page.items
        .filter((s) => (azString(azField(s, "state"))?.toLowerCase() ?? "") !== "unsupported")
        .map((s) => azString(azField(s, "name")))
        .filter((n): n is string => !!n && isAzureMlps(n));
    } catch (err) {
      if (isAzureFatal(err)) throw err;
      // Regulatory compliance needs a paid Defender plan; its absence is not worth a warning
      // unless it is a permission problem.
      if (classifyAzureError(err).kind === "access_denied") {
        warnings.push(`${azureSoftWarning("Defender for Cloud regulatoryComplianceStandards.list", err)} — findings are not annotated with MLPS standards.`);
      }
      return keys;
    }
    if (standards.length > AZURE_DEFENDER_MAX_MLPS_STANDARDS) standards = standards.slice(0, AZURE_DEFENDER_MAX_MLPS_STANDARDS);

    for (const standard of standards) {
      const shown = redactAzureDiagnostic(standard);
      try {
        const controlsPage = await azurePaginate(client.regulatoryComplianceControls.list(standard), { max: AZURE_DEFENDER_MAX_MLPS_CONTROLS });
        if (controlsPage.truncated) {
          warnings.push(azureTruncationWarning(`Defender for Cloud regulatoryComplianceControls.list (${shown})`, AZURE_DEFENDER_MAX_MLPS_CONTROLS));
        }
        const failed = controlsPage.items
          .filter((c) => (azNumber(azField(c, "failedAssessments")) ?? 0) > 0 || azString(azField(c, "state"))?.toLowerCase() === "failed")
          .map((c) => azString(azField(c, "name")))
          .filter((n): n is string => !!n);
        const settled = await runWithConcurrency(
          failed.map((control) => async () => {
            const page = await azurePaginate(client.regulatoryComplianceAssessments.list(standard, control), {
              max: AZURE_DEFENDER_MAX_CONTROL_ASSESSMENTS,
            });
            return page.items;
          }),
          AZURE_DEFENDER_CONTROL_CONCURRENCY,
        );
        let failures = 0;
        for (const s of settled) {
          if (s.status === "rejected") {
            if (isAzureFatal(s.reason)) throw s.reason;
            failures += 1;
            continue;
          }
          for (const ra of s.value) {
            const key = azLastSegment(azString(azField(ra, "assessmentDetailsLink"))?.split("?")[0]) ?? azString(azField(ra, "name"));
            if (key && !keys.has(key.toLowerCase())) keys.set(key.toLowerCase(), standard);
          }
        }
        if (failures > 0) warnings.push(`Defender for Cloud: ${failures} control(s) of standard ${shown} could not be listed; MLPS annotation is partial.`);
      } catch (err) {
        if (isAzureFatal(err)) throw err;
        warnings.push(`${azureSoftWarning(`Defender for Cloud regulatory compliance (${shown})`, err)} — MLPS annotation skipped.`);
      }
    }
    return keys;
  }
}
