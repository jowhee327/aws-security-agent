/**
 * Azure Policy compliance scanner (moduleName `config_rules_findings`; plan §4.1 / T2).
 * EXPERIMENTAL — not yet validated against a live account; response field names follow the
 * `@azure/arm-policyinsights` 6.x d.ts (`SummarizeResults` / `PolicyState`).
 *
 * Azure analog of the AWS Config rules scanner: every policy definition (of every policy
 * assignment on the subscription) with NonCompliant resources becomes one Finding carrying
 * the non-compliant resource COUNT.
 *
 * APIs (`PolicyInsightsClient`, subscription scope):
 *  1. `policyStates.summarizeForSubscription("latest", sub)` (single response, not paged) →
 *     `value[0].policyAssignments[].{policyAssignmentId, policySetDefinitionId, results,
 *     policyDefinitions[].{policyDefinitionId, policyDefinitionReferenceId, effect, results}}`;
 *     `results.nonCompliantResources > 0` → finding. No assignment at all → warning (Azure
 *     Policy is effectively unused on the subscription; service_detection reports it).
 *  2. Best effort: `policyStates.listQueryResultsForSubscription("latest", sub,
 *     { $filter: ComplianceState eq 'NonCompliant' })` (paged, capped at
 *     {@link AZURE_POLICY_MAX_STATES}) → up to {@link AZURE_POLICY_SAMPLE_RESOURCES} sample
 *     resource IDs + the definition / assignment names per finding. A failure here
 *     (other than auth_failed / api_misuse) is a warning; the summary findings stand.
 *
 * Severity: Azure Policy has no severity — every non-compliant definition is MEDIUM (5.0).
 * An assignment whose name / initiative looks like an MLPS (等保) initiative marks its
 * findings with `source = "Policy:<assignment>"` (the mlps report prefers those).
 *
 * Errors: auth_failed / api_misuse → `status: "error"`; Microsoft.PolicyInsights not
 * registered / not available (common in Azure China) → not_enabled warning + success;
 * access denied / throttled / network → warning + success.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { armClient, azurePaginate } from "../client.js";
import { classifyAzureError, describeAzureError, redactAzureDiagnostic } from "../errors.js";
import { toAzureUrn } from "../urn.js";
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

export const AZURE_POLICY_SOURCE = "Policy";
export const AZURE_POLICY_RESOURCE = "latest";
export const AZURE_POLICY_NON_COMPLIANT_FILTER = "ComplianceState eq 'NonCompliant'";
export const AZURE_POLICY_STATE_SELECT =
  "ResourceId,ResourceType,ResourceLocation,PolicyAssignmentId,PolicyAssignmentName,PolicyDefinitionId,PolicyDefinitionName,PolicyDefinitionReferenceId,PolicySetDefinitionName";
export const AZURE_POLICY_NOT_ENABLED_WARNING =
  "Azure Policy Insights (Microsoft.PolicyInsights) is not registered / not available for this subscription; no policy compliance findings available.";
export const AZURE_POLICY_NO_ASSIGNMENTS_WARNING =
  "Azure Policy: no policy assignments found on this subscription; nothing is evaluated (assign e.g. the Microsoft cloud security benchmark initiative).";

/** Non-compliant policy states fetched for the per-finding resource samples. */
export const AZURE_POLICY_MAX_STATES = 5000;
/** Sample resource IDs listed per finding. */
export const AZURE_POLICY_SAMPLE_RESOURCES = 5;
/** Findings reported by the module. */
export const AZURE_POLICY_MAX_FINDINGS = 2000;
export const AZURE_POLICY_RISK_SCORE = 5.0;

/** Matches MLPS (等保 / classified protection) initiatives / assignments. */
export const AZURE_MLPS_PATTERN = /等保|等级保护|mlps|classified[\s_-]?protection|multi[\s_-]?level[\s_-]?protection|dengbao/i;

export function isAzureMlps(...texts: Array<string | undefined>): boolean {
  return texts.some((t) => typeof t === "string" && AZURE_MLPS_PATTERN.test(t));
}

/* ------------------------------------------------------------------------ */
/* Loose response shapes (arm-policyinsights d.ts)                           */
/* ------------------------------------------------------------------------ */

interface SummaryResults {
  nonCompliantResources?: number;
  nonCompliantPolicies?: number;
}

export interface AzurePolicyDefinitionSummary {
  policyDefinitionId?: string;
  policyDefinitionReferenceId?: string;
  policyDefinitionGroupNames?: string[];
  effect?: string;
  results?: SummaryResults;
}

export interface AzurePolicyAssignmentSummary {
  policyAssignmentId?: string;
  policySetDefinitionId?: string;
  results?: SummaryResults;
  policyDefinitions?: AzurePolicyDefinitionSummary[];
}

/** Sample details gathered from the policy-state query for one (assignment, definition). */
export interface AzurePolicySamples {
  resourceIds: string[];
  /** Total non-compliant states seen for the key (may exceed the samples). */
  seen: number;
  assignmentName?: string;
  definitionName?: string;
  setDefinitionName?: string;
}

/** Map key for (assignment, definition, reference) — case-insensitive ARM IDs. */
export function azurePolicyKey(assignmentId: unknown, definitionId: unknown, referenceId?: unknown): string {
  const norm = (v: unknown) => (typeof v === "string" ? v.trim().toLowerCase() : "");
  return `${norm(assignmentId)}|${norm(definitionId)}|${norm(referenceId)}`;
}

/** Map one non-compliant (assignment, definition) summary to a Finding. Exported for unit tests. */
export function policySummaryToFinding(
  assignment: AzurePolicyAssignmentSummary,
  definition: AzurePolicyDefinitionSummary | undefined,
  ctx: { env: AzureScanEnv; module: string; samples?: AzurePolicySamples },
): Finding {
  const nonCompliant = azNumber((definition ?? assignment).results?.nonCompliantResources) ?? 0;
  // Every server-sourced string is redacted here, before it is used anywhere below.
  const assignmentId = aztUntrustedOpt(assignment.policyAssignmentId) ?? "unknown";
  const assignmentName =
    aztUntrustedOpt(ctx.samples?.assignmentName) ?? aztUntrustedOpt(azLastSegment(azString(assignment.policyAssignmentId))) ?? assignmentId;
  const setDefinitionId = aztUntrustedOpt(assignment.policySetDefinitionId);
  const setName = aztUntrustedOpt(ctx.samples?.setDefinitionName) ?? aztUntrustedOpt(azLastSegment(azString(assignment.policySetDefinitionId)));
  const definitionId = aztUntrustedOpt(definition?.policyDefinitionId);
  const referenceId = aztUntrustedOpt(definition?.policyDefinitionReferenceId);
  const definitionName =
    aztUntrustedOpt(ctx.samples?.definitionName) ?? aztUntrustedOpt(azLastSegment(azString(definition?.policyDefinitionId))) ?? referenceId;
  const effect = aztUntrustedOpt(definition?.effect);
  const groups = azArray(definition?.policyDefinitionGroupNames).map(aztUntrusted).filter((g) => g.length > 0);
  const subscription = aztUntrusted(ctx.env.subscriptionId);

  const mlps = isAzureMlps(assignmentName, setName, setDefinitionId);
  const source = mlps ? `${AZURE_POLICY_SOURCE}:${assignmentName}` : AZURE_POLICY_SOURCE;
  const severity = severityFromScore(AZURE_POLICY_RISK_SCORE);
  const subject = definitionName ? `policy "${definitionName}"` : `policy assignment "${assignmentName}"`;

  const desc: string[] = [
    `${nonCompliant} resource(s) in subscription ${subscription} are NonCompliant with ${subject}${definitionName ? ` (assignment "${assignmentName}")` : ""}.`,
  ];
  if (setName) desc.push(`Initiative: ${setName}.`);
  if (effect) desc.push(`Effect: ${effect}.`);
  if (groups.length > 0) desc.push(`Groups: ${groups.join(", ")}.`);
  const samples = (ctx.samples?.resourceIds ?? []).map(aztUntrusted).filter((s) => s.length > 0);
  if (samples.length > 0) {
    desc.push(`Non-compliant resources (sample): ${samples.join(", ")}${nonCompliant > samples.length ? ", …" : ""}.`);
  }

  const remediationSteps: string[] = [
    `Open Azure Policy → Compliance → assignment "${assignmentName}" and review the non-compliant resources${definitionName ? ` of ${subject}` : ""}.`,
    "Fix the resource configuration (or create a remediation task for deployIfNotExists / modify policies), then trigger a compliance re-evaluation.",
  ];
  if (definitionId) remediationSteps.push(`Policy definition: ${definitionId}`);
  remediationSteps.push("If the resources are intentionally out of scope, add a policy exemption with a documented justification.");

  // Every part is already redacted above; azureSafeFinding is the shared defence-in-depth pass.
  return azureSafeFinding({
    severity,
    title: `Azure Policy non-compliance: ${definitionName ?? assignmentName}`,
    resourceType: definitionId ? "Microsoft.Authorization/policyDefinitions" : "Microsoft.Authorization/policyAssignments",
    resourceId: definitionName ?? assignmentName,
    resourceArn: toAzureUrn({
      id: definitionId ? `${assignmentId}${referenceId ? `#${referenceId}` : `#${definitionName ?? ""}`}` : assignmentId,
      subscriptionId: ctx.env.subscriptionId,
      resourceType: "Microsoft.Authorization/policyAssignments",
      name: assignmentName,
    }),
    region: "global",
    description: desc.join(" "),
    // Same "Source: <product> (<generator>)" convention as the Security Hub / Config scanners.
    impact: `Source: ${source} (${definitionId ?? assignmentId})`,
    riskScore: AZURE_POLICY_RISK_SCORE,
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

interface PolicyStatesApi {
  summarizeForSubscription(resource: string, subscriptionId: string, options?: unknown): Promise<unknown>;
  listQueryResultsForSubscription(resource: string, subscriptionId: string, options?: unknown): AsyncIterable<unknown>;
}

export class AzurePolicyComplianceScanner implements Scanner {
  readonly moduleName = "config_rules_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];

    let env: AzureScanEnv | undefined;
    let states: PolicyStatesApi;
    let summary: unknown;
    try {
      env = azureScanEnv(ctx);
      if (!env) return azureNoSubscriptionResult(this.moduleName, startMs, ctx);
      const { PolicyInsightsClient } = await import("@azure/arm-policyinsights");
      const client = await armClient(PolicyInsightsClient, env.credentials, env.subscriptionId);
      states = client.policyStates as unknown as PolicyStatesApi;
      summary = await states.summarizeForSubscription(AZURE_POLICY_RESOURCE, env.subscriptionId);
    } catch (err) {
      const { kind } = classifyAzureError(err);
      if (kind === "not_enabled" || kind === "not_found") {
        warnings.push(`${AZURE_POLICY_NOT_ENABLED_WARNING} (${describeAzureError(err)})`);
        return azureEmptyResult(this.moduleName, startMs, { warnings });
      }
      if (!isAzureFatal(err) && kind !== "other") {
        warnings.push(azureSoftWarning("Azure Policy summarizeForSubscription", err));
        return azureEmptyResult(this.moduleName, startMs, { warnings });
      }
      return azureErrorResult(this.moduleName, startMs, "Azure Policy compliance scan failed", err, warnings);
    }

    try {
      const assignments: AzurePolicyAssignmentSummary[] = [];
      for (const s of azArray(azField(summary, "value"))) {
        assignments.push(...azArray<AzurePolicyAssignmentSummary>(azField(s, "policyAssignments")).filter((a) => a && typeof a === "object"));
      }
      if (assignments.length === 0) {
        warnings.push(AZURE_POLICY_NO_ASSIGNMENTS_WARNING);
        return azureEmptyResult(this.moduleName, startMs, { warnings });
      }

      // (assignment, definition) pairs with NonCompliant resources; assignments without
      // per-definition detail fall back to one assignment-level finding.
      const targets: Array<{ assignment: AzurePolicyAssignmentSummary; definition?: AzurePolicyDefinitionSummary }> = [];
      for (const a of assignments) {
        const defs = azArray<AzurePolicyDefinitionSummary>(a.policyDefinitions).filter(
          (d) => d && typeof d === "object" && (azNumber(d.results?.nonCompliantResources) ?? 0) > 0,
        );
        if (defs.length > 0) for (const d of defs) targets.push({ assignment: a, definition: d });
        else if ((azNumber(a.results?.nonCompliantResources) ?? 0) > 0) targets.push({ assignment: a });
      }

      const samples = targets.length > 0 ? await this.loadSamples(states, env, warnings) : new Map<string, AzurePolicySamples>();

      const findings: Finding[] = [];
      const seen = new Set<string>();
      let truncated = false;
      for (const t of targets) {
        const key = azurePolicyKey(t.assignment.policyAssignmentId, t.definition?.policyDefinitionId, t.definition?.policyDefinitionReferenceId);
        if (seen.has(key)) continue;
        seen.add(key);
        if (findings.length >= AZURE_POLICY_MAX_FINDINGS) {
          truncated = true;
          continue;
        }
        const sample =
          samples.get(key) ??
          (t.definition ? samples.get(azurePolicyKey(t.assignment.policyAssignmentId, t.definition.policyDefinitionId)) : undefined) ??
          (t.definition ? undefined : samples.get(azurePolicyKey(t.assignment.policyAssignmentId, "")));
        findings.push(policySummaryToFinding(t.assignment, t.definition, { env, module: this.moduleName, samples: sample }));
      }
      if (truncated) warnings.push(`Azure Policy: more than ${AZURE_POLICY_MAX_FINDINGS} non-compliant policies; findings were truncated.`);

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings.map(redactAzureDiagnostic) : undefined,
        resourcesScanned: assignments.length,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return azureErrorResult(this.moduleName, startMs, "Azure Policy compliance scan failed", err, warnings);
    }
  }

  /**
   * NonCompliant policy states (paged, capped) grouped by (assignment, definition, reference)
   * and by (assignment, definition) for the per-finding resource samples. Best effort:
   * non-fatal failures → warning + whatever was collected.
   */
  private async loadSamples(states: PolicyStatesApi, env: AzureScanEnv, warnings: string[]): Promise<Map<string, AzurePolicySamples>> {
    const map = new Map<string, AzurePolicySamples>();
    const add = (key: string, state: unknown) => {
      let entry = map.get(key);
      if (!entry) {
        entry = {
          resourceIds: [],
          seen: 0,
          assignmentName: azString(azField(state, "policyAssignmentName")),
          definitionName: azString(azField(state, "policyDefinitionName")),
          setDefinitionName: azString(azField(state, "policySetDefinitionName")),
        };
        map.set(key, entry);
      }
      entry.seen += 1;
      const rid = azString(azField(state, "resourceId"));
      if (rid && entry.resourceIds.length < AZURE_POLICY_SAMPLE_RESOURCES && !entry.resourceIds.some((r) => r.toLowerCase() === rid.toLowerCase())) {
        entry.resourceIds.push(rid);
      }
    };
    try {
      const page = await azurePaginate(
        states.listQueryResultsForSubscription(AZURE_POLICY_RESOURCE, env.subscriptionId, {
          queryOptions: { filter: AZURE_POLICY_NON_COMPLIANT_FILTER, select: AZURE_POLICY_STATE_SELECT },
        }),
        {
          max: AZURE_POLICY_MAX_STATES,
          collect: false,
          onItem: (state) => {
            const compliance = azString(azField(state, "complianceState"));
            if (compliance !== undefined && compliance.toLowerCase() !== "noncompliant") return;
            const assignmentId = azField(state, "policyAssignmentId");
            const definitionId = azField(state, "policyDefinitionId");
            add(azurePolicyKey(assignmentId, definitionId, azField(state, "policyDefinitionReferenceId")), state);
            add(azurePolicyKey(assignmentId, definitionId), state);
            add(azurePolicyKey(assignmentId, ""), state);
          },
        },
      );
      if (page.truncated) warnings.push(azureTruncationWarning("Azure Policy listQueryResultsForSubscription (resource samples)", AZURE_POLICY_MAX_STATES));
    } catch (err) {
      if (isAzureFatal(err)) throw err;
      warnings.push(
        `${azureSoftWarning("Azure Policy listQueryResultsForSubscription", err)} — findings carry counts only (no resource samples).`,
      );
    }
    return map;
  }
}
