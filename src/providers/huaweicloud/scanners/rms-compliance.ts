/**
 * Huawei Cloud RMS (Config) compliance aggregation scanner
 * (moduleName `rms_compliance_findings`, plan T6).
 *
 * Huawei analog of `src/scanners/security-hub-findings.ts`: every
 * `NonCompliant` policy state reported by RMS becomes one Finding, so the
 * report layer gets a security_hub-like aggregation of built-in / custom
 * compliance rules (including the 等保 conformance-pack rules when assigned).
 *
 * API (global endpoint `rms.myhuaweicloud.com`, GlobalCredentials + domainId):
 *  - `listPolicyStatesByDomainId({ compliance_state: "NonCompliant", limit, marker })`
 *    paginated via `page_info.next_marker`. Compliance is ALSO filtered
 *    client-side in case the server ignores the query parameter.
 *  - `listPolicyAssignments({ limit, marker })` (best effort) to resolve
 *    `policy_assignment_id` → assignment name / built-in policy id / description.
 *    A 403 or any failure here only produces a warning.
 *
 * Region handling: RMS is account-wide (an account- or organization-level
 * tracker aggregates every region), so a single call already returns states
 * from all regions plus "global" resources (IAM, ...). Default behaviour is
 * `regionScope: "all"`: keep every state and set `Finding.region` from the
 * state's `region_id` ("global" for global resources), exactly like the AWS
 * Security Hub scanner honours `f.Region` under cross-region aggregation.
 * A warning summarises how many findings came from other regions. Callers
 * that loop over regions (runner, Phase 2) can pass `regionScope: "context"`
 * to keep only `ctx.region` + "global" states and avoid duplicates.
 *
 * Severity: MEDIUM (5.0) by default; HIGH (7.5) when the policy name / built-in
 * policy id matches {@link RMS_HIGH_SEVERITY_KEYWORDS} (small, explicit list).
 *
 * Graceful degradation: 403 → warning + status success; RMS not enabled /
 * 404 → warning + status success; any other failure → status "error".
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { severityFromScore, priorityFromSeverity } from "../../../utils/risk-scoring.js";
import { hwClient } from "../client.js";
import { classifyHwError, describeHwError } from "../errors.js";
import { HWS_GLOBAL_REGION, toResourceUrn } from "../urn.js";
import { hwCredentialsFromContext, hwDomainIdFromContext, MarkerGuard, repeatedMarkerWarning } from "./shared.js";

export const RMS_POLICY_STATES_PAGE_SIZE = 200;
export const RMS_MAX_POLICY_STATES = 5000;
export const RMS_POLICY_ASSIGNMENTS_PAGE_SIZE = 200;
const MAX_PAGES = 100;

export const RMS_COMPLIANCE_SOURCE = "RMS";
export const RMS_NOT_ENABLED_WARNING =
  "Huawei Cloud RMS (Config) is not enabled for this account; no compliance findings available.";

/** Default risk score for a NonCompliant policy state (MEDIUM). */
export const RMS_DEFAULT_RISK_SCORE = 5.0;
/** Risk score for policies matching {@link RMS_HIGH_SEVERITY_KEYWORDS} (HIGH). */
export const RMS_HIGH_RISK_SCORE = 7.5;

/**
 * Keywords (matched case-insensitively against the policy assignment name and
 * the built-in policy definition id) that upgrade a finding to HIGH. Examples
 * of built-in policies hit: `iam-user-mfa-enabled`, `iam-root-access-key-check`,
 * `obs-bucket-public-read-policy-check`, `volumes-encrypted-check`,
 * `vpc-sg-ports-check`, `access-keys-rotated`.
 */
export const RMS_HIGH_SEVERITY_KEYWORDS: readonly string[] = [
  "mfa",
  "public",
  "encrypt",
  "sg-ports",
  "security-group",
  "root",
  "access-key",
];

/* ------------------------------------------------------------------------ */
/* Loose SDK response shapes (wire keys; camelCase accepted for fakes)       */
/* ------------------------------------------------------------------------ */

export interface LoosePolicyState {
  domain_id?: string;
  domainId?: string;
  region_id?: string;
  regionId?: string;
  resource_id?: string;
  resourceId?: string;
  resource_name?: string;
  resourceName?: string;
  resource_provider?: string;
  resourceProvider?: string;
  resource_type?: string;
  resourceType?: string;
  trigger_type?: string;
  triggerType?: string;
  compliance_state?: string;
  complianceState?: string;
  policy_assignment_id?: string;
  policyAssignmentId?: string;
  policy_assignment_name?: string;
  policyAssignmentName?: string;
  policy_definition_id?: string;
  policyDefinitionId?: string;
  evaluation_time?: string;
  evaluationTime?: string;
  enterprise_project_id?: string;
  enterpriseProjectId?: string;
}

interface LoosePageInfo {
  next_marker?: string;
  nextMarker?: string;
  current_count?: number;
  currentCount?: number;
}

interface LooseListPolicyStatesResponse {
  value?: LoosePolicyState[];
  page_info?: LoosePageInfo;
  pageInfo?: LoosePageInfo;
}

export interface LoosePolicyAssignment {
  id?: string;
  name?: string;
  description?: string;
  policy_assignment_type?: string;
  policyAssignmentType?: string;
  policy_definition_id?: string;
  policyDefinitionId?: string;
  state?: string;
}

interface LooseListPolicyAssignmentsResponse {
  value?: LoosePolicyAssignment[];
  page_info?: LoosePageInfo;
  pageInfo?: LoosePageInfo;
}

/** Minimal ConfigClient surface used here (tests inject fakes). */
export interface RmsComplianceClient {
  listPolicyStatesByDomainId(req?: unknown): Promise<unknown>;
  listPolicyAssignments?(req?: unknown): Promise<unknown>;
}

export interface RmsAssignmentInfo {
  id: string;
  name?: string;
  description?: string;
  policyDefinitionId?: string;
  type?: string;
}

export interface HuaweiRmsComplianceOptions {
  /**
   * "all" (default): keep states from every region, `Finding.region` = state's region_id.
   * "context": keep only states whose region_id is `ctx.region` or "global".
   */
  regionScope?: "all" | "context";
  /** Skip the best-effort `listPolicyAssignments` enrichment call. */
  skipAssignmentLookup?: boolean;
}

/* ------------------------------------------------------------------------ */
/* Pure helpers                                                             */
/* ------------------------------------------------------------------------ */

function nextMarkerOf(resp: { page_info?: LoosePageInfo; pageInfo?: LoosePageInfo } | undefined): string | undefined {
  const pi = resp?.page_info ?? resp?.pageInfo;
  const m = pi?.next_marker ?? pi?.nextMarker;
  return typeof m === "string" && m.length > 0 ? m : undefined;
}

export function isNonCompliant(state: LoosePolicyState): boolean {
  const s = state.compliance_state ?? state.complianceState ?? "";
  return s.replace(/[^a-z]/gi, "").toLowerCase() === "noncompliant";
}

/** Risk score for a policy: HIGH when the name / built-in id matches a high-severity keyword. */
export function rmsPolicyRiskScore(policyName: string | undefined, policyDefinitionId: string | undefined): number {
  const hay = `${policyName ?? ""} ${policyDefinitionId ?? ""}`.toLowerCase();
  return RMS_HIGH_SEVERITY_KEYWORDS.some((kw) => hay.includes(kw)) ? RMS_HIGH_RISK_SCORE : RMS_DEFAULT_RISK_SCORE;
}

/** Normalise an RMS `region_id` ("global" / empty → HWS_GLOBAL_REGION). */
export function normalizeRmsRegion(regionId: string | undefined): string {
  const r = regionId?.trim();
  if (!r || r.toLowerCase() === HWS_GLOBAL_REGION) return HWS_GLOBAL_REGION;
  return r;
}

/**
 * Map one NonCompliant policy state to a Finding. Exported for unit tests.
 * `assignment` (optional) enriches title / description / severity.
 */
export function policyStateToFinding(
  state: LoosePolicyState,
  ctx: { domainId: string; module: string },
  assignment?: RmsAssignmentInfo,
): Finding {
  const provider = state.resource_provider ?? state.resourceProvider ?? "unknown";
  const type = state.resource_type ?? state.resourceType ?? "resource";
  const resourceId = state.resource_id ?? state.resourceId ?? "unknown";
  const resourceName = state.resource_name ?? state.resourceName;
  const region = normalizeRmsRegion(state.region_id ?? state.regionId);
  const assignmentId = state.policy_assignment_id ?? state.policyAssignmentId ?? assignment?.id;
  const assignmentName = state.policy_assignment_name ?? state.policyAssignmentName ?? assignment?.name;
  const definitionId = state.policy_definition_id ?? state.policyDefinitionId ?? assignment?.policyDefinitionId;
  const policyLabel = assignmentName ?? definitionId ?? assignmentId ?? "unknown policy";
  const evaluationTime = state.evaluation_time ?? state.evaluationTime;
  const eps = state.enterprise_project_id ?? state.enterpriseProjectId;

  const riskScore = rmsPolicyRiskScore(assignmentName, definitionId);
  const severity = severityFromScore(riskScore);
  const display = resourceName && resourceName !== resourceId ? `${resourceId} (${resourceName})` : resourceId;

  const descParts: string[] = [
    `${provider}:${type} ${display} in ${region} is NonCompliant with RMS policy assignment "${policyLabel}".`,
  ];
  if (assignment?.description) descParts.push(assignment.description);
  if (evaluationTime) descParts.push(`Last evaluated: ${evaluationTime}.`);

  const remediationSteps: string[] = [
    `Open the Huawei Cloud Config (RMS) console → Resource Compliance → policy assignment "${policyLabel}" and review the non-compliant resource ${resourceId}.`,
  ];
  if (assignment?.description) remediationSteps.push(assignment.description);
  if (definitionId) {
    remediationSteps.push(`Built-in policy reference: ${definitionId} (see Huawei Cloud Config built-in policy documentation).`);
  }
  remediationSteps.push("Fix the resource configuration, then re-run the policy evaluation to confirm compliance.");

  const finding: Finding = {
    severity,
    title: `RMS policy non-compliance: ${policyLabel}`,
    resourceType: `${provider}:${type}`,
    resourceId,
    resourceArn: toResourceUrn(provider, type, resourceId, region, ctx.domainId),
    region,
    description: descParts.join(" "),
    // Same "Source: <product> (<generator>)" convention as the Security Hub scanner.
    impact: `Source: ${RMS_COMPLIANCE_SOURCE} (${definitionId ?? assignmentId ?? "custom"})`,
    riskScore,
    remediationSteps,
    priority: priorityFromSeverity(severity),
    module: ctx.module,
    accountId: state.domain_id ?? state.domainId ?? ctx.domainId,
    source: RMS_COMPLIANCE_SOURCE,
    provider: "huaweicloud",
  };
  if (eps) finding.enterpriseProjectId = eps;
  return finding;
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class HuaweiRmsComplianceScanner implements Scanner {
  readonly moduleName = "rms_compliance_findings";
  private readonly regionScope: "all" | "context";
  private readonly skipAssignmentLookup: boolean;

  constructor(opts: HuaweiRmsComplianceOptions = {}) {
    this.regionScope = opts.regionScope ?? "all";
    this.skipAssignmentLookup = opts.skipAssignmentLookup ?? false;
  }

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      const creds = hwCredentialsFromContext(ctx, "global");
      const domainId = await hwDomainIdFromContext(ctx, creds);
      const { ConfigClient } = await import("@huaweicloud/huaweicloud-sdk-config");
      const rms = (await hwClient(ConfigClient, "rms", creds, {
        region: ctx.region,
        domainId,
      })) as unknown as RmsComplianceClient;

      // Best-effort enrichment: assignment id → name / built-in policy id / description.
      const assignments = this.skipAssignmentLookup ? new Map<string, RmsAssignmentInfo>() : await this.loadAssignments(rms, warnings);

      let marker: string | undefined;
      let truncated = false;
      let otherRegionCount = 0;
      let droppedCount = 0;
      let duplicateCount = 0;
      const markers = new MarkerGuard();
      // Dedupe by (policy_assignment_id, resource_id): a repeated / overlapping page
      // must not produce the same finding twice.
      const seenStates = new Set<string>();

      pages: for (let page = 0; page < MAX_PAGES; page++) {
        const req: Record<string, unknown> = {
          domainId,
          compliance_state: "NonCompliant",
          limit: RMS_POLICY_STATES_PAGE_SIZE,
        };
        if (marker !== undefined) req.marker = marker;
        const resp = (await rms.listPolicyStatesByDomainId(req)) as LooseListPolicyStatesResponse | undefined;
        const batch = Array.isArray(resp?.value) ? resp!.value! : [];

        for (const state of batch) {
          if (resourcesScanned >= RMS_MAX_POLICY_STATES) {
            truncated = true;
            break pages;
          }
          resourcesScanned += 1;
          if (!isNonCompliant(state)) continue; // server may ignore the filter

          const region = normalizeRmsRegion(state.region_id ?? state.regionId);
          if (region !== ctx.region && region !== HWS_GLOBAL_REGION) {
            if (this.regionScope === "context") {
              droppedCount += 1;
              continue;
            }
            otherRegionCount += 1;
          }

          const assignmentId = state.policy_assignment_id ?? state.policyAssignmentId;
          const resourceId = state.resource_id ?? state.resourceId;
          if (assignmentId || resourceId) {
            const key = `${assignmentId ?? ""}|${resourceId ?? ""}`;
            if (seenStates.has(key)) {
              duplicateCount += 1;
              continue;
            }
            seenStates.add(key);
          }
          const assignment = assignmentId ? assignments.get(assignmentId) : undefined;
          findings.push(policyStateToFinding(state, { domainId, module: this.moduleName }, assignment));
        }

        marker = nextMarkerOf(resp);
        if (!marker || batch.length === 0) break;
        if (!markers.accept(marker)) {
          warnings.push(repeatedMarkerWarning("RMS", "policy states"));
          break;
        }
      }
      if (duplicateCount > 0) {
        warnings.push(`RMS returned ${duplicateCount} duplicate policy state(s) (same policy assignment + resource); duplicates were dropped.`);
      }

      if (truncated) {
        warnings.push(
          `RMS returned more than ${RMS_MAX_POLICY_STATES} non-compliant policy states; results were truncated.`,
        );
      }
      if (otherRegionCount > 0) {
        warnings.push(
          `${otherRegionCount} RMS compliance finding(s) belong to regions other than ${ctx.region} (RMS aggregates account-wide); Finding.region reflects the resource's region.`,
        );
      }
      if (droppedCount > 0) {
        warnings.push(
          `${droppedCount} RMS compliance finding(s) from other regions were skipped (regionScope=context).`,
        );
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      const { kind } = classifyHwError(err);

      if (kind === "access_denied") {
        warnings.push(`RMS: insufficient permissions (${describeHwError(err)}); skipped`);
        return this.degraded(startMs, warnings);
      }
      if (kind === "not_enabled" || kind === "not_found") {
        warnings.push(`${RMS_NOT_ENABLED_WARNING} (${describeHwError(err)})`);
        return this.degraded(startMs, warnings);
      }

      return {
        module: this.moduleName,
        status: "error",
        error: `RMS compliance findings scan failed: ${describeHwError(err)}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }

  private degraded(startMs: number, warnings: string[]): ScanResult {
    return {
      module: this.moduleName,
      status: "success",
      warnings,
      resourcesScanned: 0,
      findingsCount: 0,
      scanTimeMs: Date.now() - startMs,
      findings: [],
    };
  }

  /** Paginate `listPolicyAssignments`; any failure (403 included) → warning, empty map. */
  private async loadAssignments(rms: RmsComplianceClient, warnings: string[]): Promise<Map<string, RmsAssignmentInfo>> {
    const map = new Map<string, RmsAssignmentInfo>();
    if (typeof rms.listPolicyAssignments !== "function") return map;
    try {
      let marker: string | undefined;
      const markers = new MarkerGuard();
      for (let page = 0; page < MAX_PAGES; page++) {
        const req: Record<string, unknown> = { limit: RMS_POLICY_ASSIGNMENTS_PAGE_SIZE };
        if (marker !== undefined) req.marker = marker;
        const resp = (await rms.listPolicyAssignments(req)) as LooseListPolicyAssignmentsResponse | undefined;
        const batch = Array.isArray(resp?.value) ? resp!.value! : [];
        for (const a of batch) {
          if (!a?.id) continue;
          map.set(a.id, {
            id: a.id,
            name: a.name,
            description: a.description,
            policyDefinitionId: a.policy_definition_id ?? a.policyDefinitionId,
            type: a.policy_assignment_type ?? a.policyAssignmentType,
          });
        }
        marker = nextMarkerOf(resp);
        if (!marker || batch.length === 0) break;
        if (!markers.accept(marker)) {
          warnings.push(repeatedMarkerWarning("RMS", "policy assignments"));
          break;
        }
      }
    } catch (err) {
      warnings.push(
        `RMS: could not list policy assignments (${describeHwError(err)}); findings use policy ids from the compliance states only.`,
      );
    }
    return map;
  }
}
