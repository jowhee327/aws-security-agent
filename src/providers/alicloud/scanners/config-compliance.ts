/**
 * Alibaba Cloud Config compliance aggregation scanner (moduleName
 * `config_compliance_findings`, aliased from `security_hub_findings`; plan §4.1 / T2).
 * EXPERIMENTAL — not yet validated against a live account.
 *
 * Alibaba analog of `src/scanners/security-hub-findings.ts` / the Huawei RMS compliance
 * scanner: every NON_COMPLIANT resource evaluation of a Config rule becomes one Finding.
 *
 * APIs (Config 2020-09-07, centralised site-dependent endpoint):
 *  1. `ListCompliancePacks` (PageNumber / PageSize; best effort) → pack id → name. A pack
 *     whose name / template / description looks like an MLPS (等保) pack marks its rules'
 *     findings with `source = "Config:<packName>"` (the mlps report prefers those).
 *  2. `ListConfigRules` (PageNumber / PageSize, `ComplianceType=NON_COMPLIANT`; compliance
 *     is ALSO filtered client-side on `Compliance.ComplianceType`).
 *  3. Per non-compliant rule: `ListConfigRuleEvaluationResults` (NextToken / MaxResults,
 *     `ConfigRuleId`, `ComplianceType=NON_COMPLIANT`) → one Finding per resource from
 *     `EvaluationResultIdentifier.EvaluationResultQualifier.{ResourceType,ResourceId,RegionId}`.
 *     Bounded by {@link ALI_CONFIG_RULE_CONCURRENCY}, {@link ALI_CONFIG_MAX_RULES},
 *     {@link ALI_CONFIG_MAX_RESULTS_PER_RULE} and {@link ALI_CONFIG_MAX_FINDINGS} (each
 *     truncation produces a warning).
 *
 * Severity: rule `RiskLevel` 1 → HIGH (7.5), 2 → MEDIUM (5.0), 3 → LOW (3.0); absent → MEDIUM.
 * `resourceArn`: `acs:<svc>:<region>:<uid>:<type>/<id>` with `ResourceType` mapped through
 * {@link ALI_CONFIG_RESOURCE_TYPE_MAP} (fallback `ACS::Svc::Type` → `svc:type`).
 *
 * Untrusted text: every Config-sourced string (resource / rule IDs and names, descriptions,
 * annotations, pack names, …) is server-controlled and may echo credential material
 * (e.g. a `server string to sign is: …AccessKeyId%3DLTAI…` annotation). It passes through
 * {@link aliUntrusted} (→ `redactAliDiagnostic`) before it reaches any Finding / warning field.
 *
 * Errors: auth_failed / api_misuse anywhere → `status: "error"`; Config not enabled /
 * access denied on the rule listing → warning + success; a per-rule evaluation failure
 * (access denied, throttled, …) → warning, the other rules are still reported.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { ALI_API } from "../api-catalog.js";
import { aliCall, aliPaginate } from "../client.js";
import { classifyAliError, degradeAliError, describeAliError, redactAliDiagnostic } from "../errors.js";
import { ALI_GLOBAL_URN_SERVICES, toAliUrn } from "../urn.js";
import {
  aliCallCtx,
  aliErrorResult,
  aliField,
  aliNumber,
  aliScanEnv,
  aliString,
  emptyScanResult,
  isAliFatal,
  type AliScanEnv,
} from "./shared.js";

export const ALI_CONFIG_COMPLIANCE_SOURCE = "Config";
export const ALI_CONFIG_NOT_ENABLED_WARNING =
  "Alibaba Cloud Config is not enabled for this account; no compliance findings available.";

export const ALI_CONFIG_RULES_PAGE_SIZE = 100;
export const ALI_CONFIG_PACKS_PAGE_SIZE = 100;
export const ALI_CONFIG_EVALUATIONS_PAGE_SIZE = 100;
/** Non-compliant rules whose evaluation results are fetched (N+1 cap). */
export const ALI_CONFIG_MAX_RULES = 200;
/** Non-compliant resources reported per rule. */
export const ALI_CONFIG_MAX_RESULTS_PER_RULE = 500;
/** Total findings reported by the module. */
export const ALI_CONFIG_MAX_FINDINGS = 5000;
/** Concurrent ListConfigRuleEvaluationResults calls. */
export const ALI_CONFIG_RULE_CONCURRENCY = 5;

export const ALI_CONFIG_NON_COMPLIANT = "NON_COMPLIANT";

/** RiskLevel → risk score (1 = high, 2 = medium, 3 = low). */
export const ALI_CONFIG_RISK_SCORES: Readonly<Record<number, number>> = { 1: 7.5, 2: 5.0, 3: 3.0 };
export const ALI_CONFIG_DEFAULT_RISK_SCORE = 5.0;

/** Matches MLPS (等保 / classified protection) compliance packs by name / template / description. */
export const ALI_MLPS_PACK_PATTERN = /等保|等级保护|mlps|classified[\s_-]?protection|multi[\s_-]?level[\s_-]?protection|dengbao/i;

/**
 * Config `ResourceType` → `<svc>:<type>` used for URNs (plan §3.4 types). Unknown types fall
 * back to {@link aliConfigResourceType}'s generic `ACS::<Svc>::<Type>` → `svc:type` rule.
 */
export const ALI_CONFIG_RESOURCE_TYPE_MAP: Readonly<Record<string, string>> = {
  "ACS::ECS::Instance": "ecs:instance",
  "ACS::ECS::Disk": "ecs:disk",
  "ACS::ECS::SecurityGroup": "ecs:securitygroup",
  "ACS::ECS::NetworkInterface": "ecs:networkinterface",
  "ACS::ECS::Snapshot": "ecs:snapshot",
  "ACS::ECS::Image": "ecs:image",
  "ACS::ECS::KeyPair": "ecs:keypair",
  "ACS::EIP::EipAddress": "vpc:eip",
  "ACS::VPC::EIP": "vpc:eip",
  "ACS::VPC::EipAddress": "vpc:eip",
  "ACS::VPC::VPC": "vpc:vpc",
  "ACS::VPC::VSwitch": "vpc:vswitch",
  "ACS::VPC::NatGateway": "vpc:natgateway",
  "ACS::SLB::LoadBalancer": "slb:loadbalancer",
  "ACS::ALB::LoadBalancer": "alb:loadbalancer",
  "ACS::RDS::DBInstance": "rds:dbinstance",
  "ACS::OSS::Bucket": "oss:bucket",
  "ACS::RAM::User": "ram:user",
  "ACS::RAM::Role": "ram:role",
  "ACS::RAM::Group": "ram:group",
  "ACS::RAM::Policy": "ram:policy",
  "ACS::KMS::Key": "kms:key",
  "ACS::KMS::Secret": "kms:secret",
  "ACS::CAS::Certificate": "cas:certificate",
  "ACS::FC::Function": "fc:function",
  "ACS::ActionTrail::Trail": "actiontrail:trail",
  "ACS::WAF::Instance": "waf:instance",
  "ACS::ACK::Cluster": "cs:cluster",
  "ACS::CS::Cluster": "cs:cluster",
  "ACS::Redis::DBInstance": "kvstore:instance",
  "ACS::MongoDB::DBInstance": "dds:dbinstance",
  "ACS::PolarDB::DBCluster": "polardb:dbcluster",
};

/* ------------------------------------------------------------------------ */
/* Loose response shapes (SDK `dist/models/*.d.ts`, wire keys)               */
/* ------------------------------------------------------------------------ */

export interface AliConfigRule {
  ConfigRuleId?: string;
  ConfigRuleName?: string;
  ConfigRuleArn?: string;
  ConfigRuleState?: string;
  Description?: string;
  RiskLevel?: number;
  SourceIdentifier?: string;
  SourceOwner?: string;
  Compliance?: { ComplianceType?: string; Count?: number };
  CreateBy?: { CompliancePackId?: string; CompliancePackName?: string };
}

export interface AliEvaluationQualifier {
  CompliancePackId?: string;
  ConfigRuleArn?: string;
  ConfigRuleId?: string;
  ConfigRuleName?: string;
  RegionId?: string;
  ResourceGroupId?: string;
  ResourceId?: string;
  ResourceName?: string;
  ResourceOwnerId?: number | string;
  ResourceType?: string;
}

export interface AliEvaluationResult {
  Annotation?: string;
  ComplianceType?: string;
  RiskLevel?: number;
  ResultRecordedTimestamp?: number;
  EvaluationResultIdentifier?: { EvaluationResultQualifier?: AliEvaluationQualifier; OrderingTimestamp?: number };
}

export interface AliCompliancePackInfo {
  id: string;
  name?: string;
  templateId?: string;
  status?: string;
  /** True when the pack looks like an MLPS (等保) pack. */
  mlps: boolean;
}

/* ------------------------------------------------------------------------ */
/* Pure helpers                                                             */
/* ------------------------------------------------------------------------ */

export function isAliNonCompliant(complianceType: unknown): boolean {
  return typeof complianceType === "string" && complianceType.replace(/[^a-z]/gi, "").toUpperCase() === "NONCOMPLIANT";
}

/**
 * Server-sourced (untrusted) Config value → trimmed, credential-redacted string; undefined
 * when absent. Ordinary IDs / names pass through unchanged (only credential-looking
 * patterns are rewritten). Use for EVERY Config value emitted in a Finding or warning.
 */
export function aliUntrusted(v: unknown): string | undefined {
  const s = aliString(v);
  return s === undefined ? undefined : redactAliDiagnostic(s);
}

/** RiskLevel 1/2/3 → 7.5 / 5.0 / 3.0 (HIGH / MEDIUM / LOW); anything else → MEDIUM. */
export function aliConfigRiskScore(riskLevel: unknown): number {
  const n = aliNumber(riskLevel);
  return n !== undefined && ALI_CONFIG_RISK_SCORES[n] !== undefined ? ALI_CONFIG_RISK_SCORES[n] : ALI_CONFIG_DEFAULT_RISK_SCORE;
}

/** `ACS::ECS::Instance` → `ecs:instance` (table first, then the generic rule). */
export function aliConfigResourceType(resourceType: string | undefined): string {
  const raw = resourceType?.trim();
  if (!raw) return "config:resource";
  const mapped = ALI_CONFIG_RESOURCE_TYPE_MAP[raw];
  if (mapped) return mapped;
  const lower = Object.keys(ALI_CONFIG_RESOURCE_TYPE_MAP).find((k) => k.toLowerCase() === raw.toLowerCase());
  if (lower) return ALI_CONFIG_RESOURCE_TYPE_MAP[lower];
  const parts = raw.split("::").filter((p) => p.length > 0);
  const body = parts[0]?.toUpperCase() === "ACS" ? parts.slice(1) : parts;
  const svc = (body[0] ?? "").replace(/[^A-Za-z0-9]/g, "").toLowerCase();
  const type = body.slice(1).join("").replace(/[^A-Za-z0-9]/g, "").toLowerCase();
  if (!svc) return `config:${type || "resource"}`;
  return `${svc}:${type || "resource"}`;
}

/** Normalised RegionId: empty / "global" → "" (URN global segment). */
function urnRegion(regionId: string | undefined): string {
  const r = regionId?.trim();
  return !r || r.toLowerCase() === "global" ? "" : r;
}

/** `acs:` URN of an evaluated resource. */
export function aliConfigResourceUrn(resourceType: string | undefined, resourceId: string, regionId: string | undefined, uid: string): string {
  const [svc, ...rest] = aliConfigResourceType(resourceType).split(":");
  const type = rest.join(":") || "resource";
  const region = ALI_GLOBAL_URN_SERVICES.has(svc) ? "" : urnRegion(regionId);
  return toAliUrn(svc, type, resourceId, region, uid);
}

export function isAliMlpsPack(...texts: Array<string | undefined>): boolean {
  return texts.some((t) => typeof t === "string" && ALI_MLPS_PACK_PATTERN.test(t));
}

/** Map one NON_COMPLIANT evaluation result to a Finding. Exported for unit tests. */
export function evaluationToFinding(
  rule: AliConfigRule,
  result: AliEvaluationResult,
  ctx: { accountId: string; module: string; packs: ReadonlyMap<string, AliCompliancePackInfo> },
): Finding {
  const q = result.EvaluationResultIdentifier?.EvaluationResultQualifier ?? {};
  // Every server-sourced string is redacted here, before it is used anywhere below.
  const ruleId = aliUntrusted(q.ConfigRuleId) ?? aliUntrusted(rule.ConfigRuleId) ?? "unknown";
  const ruleName = aliUntrusted(rule.ConfigRuleName) ?? aliUntrusted(q.ConfigRuleName) ?? ruleId;
  const resourceId = aliUntrusted(q.ResourceId) ?? "unknown";
  const resourceName = aliUntrusted(q.ResourceName);
  const resourceType = aliUntrusted(q.ResourceType) ?? "ACS::Config::Resource";
  const regionRaw = aliUntrusted(q.RegionId);
  const region = urnRegion(regionRaw) || "global";
  const uid = aliUntrusted(q.ResourceOwnerId) ?? ctx.accountId;
  const identifier = aliUntrusted(rule.SourceIdentifier);

  // Pack lookup uses the raw id (map key); the emitted name is redacted (loadPacks redacts too).
  const packId = aliString(rule.CreateBy?.CompliancePackId) ?? aliString(q.CompliancePackId);
  const pack = packId ? ctx.packs.get(packId) : undefined;
  const packName = pack?.name ?? aliUntrusted(rule.CreateBy?.CompliancePackName);
  const mlps = pack ? pack.mlps : isAliMlpsPack(packName);
  const source = mlps && packName ? `${ALI_CONFIG_COMPLIANCE_SOURCE}:${packName}` : ALI_CONFIG_COMPLIANCE_SOURCE;

  const riskScore = aliConfigRiskScore(rule.RiskLevel ?? result.RiskLevel);
  const severity = severityFromScore(riskScore);
  const display = resourceName && resourceName !== resourceId ? `${resourceId} (${resourceName})` : resourceId;

  const desc: string[] = [`${resourceType} ${display} in ${region} is NON_COMPLIANT with Config rule "${ruleName}".`];
  if (packName) desc.push(`Compliance pack: ${packName}.`);
  const description = aliUntrusted(rule.Description);
  if (description) desc.push(description);
  const annotation = aliUntrusted(result.Annotation);
  if (annotation) desc.push(`Evaluation detail: ${annotation}`);

  const remediationSteps: string[] = [
    `Open the Alibaba Cloud Config console → Rules → "${ruleName}" and review the non-compliant resource ${resourceId}.`,
  ];
  if (description) remediationSteps.push(description);
  if (identifier) remediationSteps.push(`Managed rule reference: ${identifier} (see the Alibaba Cloud Config managed rule documentation).`);
  remediationSteps.push("Fix the resource configuration, then re-evaluate the rule to confirm compliance.");

  return {
    severity,
    title: `Config rule non-compliance: ${ruleName}`,
    resourceType,
    resourceId,
    resourceArn: aliConfigResourceUrn(resourceType, resourceId, regionRaw, uid),
    region,
    description: desc.join(" "),
    // Same "Source: <product> (<generator>)" convention as the Security Hub / RMS scanners.
    impact: `Source: ${source} (${identifier ?? ruleId})`,
    riskScore,
    remediationSteps,
    priority: priorityFromSeverity(severity),
    module: ctx.module,
    accountId: uid,
    source,
    provider: "alicloud",
  };
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

interface RuleEvaluations {
  rule: AliConfigRule;
  results: AliEvaluationResult[];
  warnings: string[];
}

export class AliConfigComplianceScanner implements Scanner {
  readonly moduleName = "config_compliance_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];

    let env: AliScanEnv;
    let rules: AliConfigRule[];
    try {
      env = aliScanEnv(ctx);
      const page = await aliPaginate<unknown, AliConfigRule>({
        style: "page",
        label: "Config ListConfigRules",
        pageSize: ALI_CONFIG_RULES_PAGE_SIZE,
        fetch: (q) => aliCall(ALI_API.config.ListConfigRules, aliCallCtx(env), { ...q, ComplianceType: ALI_CONFIG_NON_COMPLIANT }),
        items: (p) => asArray<AliConfigRule>(aliField(aliField(p, "ConfigRules"), "ConfigRuleList")),
        totalCount: (p) => aliNumber(aliField(aliField(p, "ConfigRules"), "TotalCount")),
      });
      warnings.push(...page.warnings);
      rules = page.items;
    } catch (err) {
      const { kind } = classifyAliError(err);
      if (kind === "not_enabled" || kind === "not_found") {
        warnings.push(`${ALI_CONFIG_NOT_ENABLED_WARNING} (${describeAliError(err)})`);
        return emptyScanResult(this.moduleName, startMs, { warnings });
      }
      const degraded = degradeAliError("Config", err);
      if (degraded) {
        warnings.push(degraded);
        return emptyScanResult(this.moduleName, startMs, { warnings });
      }
      return aliErrorResult(this.moduleName, startMs, "Config compliance findings scan failed", err, warnings);
    }

    try {
      const packs = await this.loadPacks(env, warnings);

      // Client-side filter too, in case the server ignores ComplianceType.
      const seenRules = new Set<string>();
      let nonCompliant = rules.filter((r) => {
        if (!isAliNonCompliant(r.Compliance?.ComplianceType)) return false;
        const id = aliString(r.ConfigRuleId);
        if (!id || seenRules.has(id)) return false;
        seenRules.add(id);
        return true;
      });
      if (nonCompliant.length > ALI_CONFIG_MAX_RULES) {
        warnings.push(
          `Config: ${nonCompliant.length} non-compliant rules found; evaluation results were fetched for the first ${ALI_CONFIG_MAX_RULES} only.`,
        );
        nonCompliant = nonCompliant.slice(0, ALI_CONFIG_MAX_RULES);
      }

      const settled = await runWithConcurrency(
        nonCompliant.map((rule) => () => this.loadEvaluations(env, rule)),
        ALI_CONFIG_RULE_CONCURRENCY,
      );

      const findings: Finding[] = [];
      const seen = new Set<string>();
      let resourcesScanned = 0;
      let truncated = false;
      for (const s of settled) {
        if (s.status === "rejected") throw s.reason; // fatal (auth_failed / api_misuse) only
        warnings.push(...s.value.warnings);
        for (const result of s.value.results) {
          // The request already filters on NON_COMPLIANT; drop results that explicitly say otherwise.
          if (result.ComplianceType !== undefined && !isAliNonCompliant(result.ComplianceType)) continue;
          resourcesScanned += 1;
          const q = result.EvaluationResultIdentifier?.EvaluationResultQualifier;
          const key = `${s.value.rule.ConfigRuleId ?? ""}|${q?.ResourceId ?? ""}|${q?.RegionId ?? ""}`;
          if (seen.has(key)) continue;
          seen.add(key);
          if (findings.length >= ALI_CONFIG_MAX_FINDINGS) {
            truncated = true;
            continue;
          }
          findings.push(evaluationToFinding(s.value.rule, result, { accountId: env.accountId, module: this.moduleName, packs }));
        }
      }
      if (truncated) {
        warnings.push(`Config: more than ${ALI_CONFIG_MAX_FINDINGS} non-compliant resources; findings were truncated.`);
      }

      return {
        module: this.moduleName,
        status: "success",
        // Defence in depth: every warning is already built from redacted parts (idempotent).
        warnings: warnings.length > 0 ? warnings.map(redactAliDiagnostic) : undefined,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return aliErrorResult(this.moduleName, startMs, "Config compliance findings scan failed", err, warnings);
    }
  }

  /** Non-compliant evaluation results of one rule; non-fatal failures become warnings. */
  private async loadEvaluations(env: AliScanEnv, rule: AliConfigRule): Promise<RuleEvaluations> {
    const ruleId = aliString(rule.ConfigRuleId) as string;
    // Raw id for the request; redacted id for every label / warning.
    const shownId = redactAliDiagnostic(ruleId);
    const label = `Config ListConfigRuleEvaluationResults (rule ${shownId})`;
    try {
      const page = await aliPaginate<unknown, AliEvaluationResult>({
        style: "token",
        label,
        pageSize: ALI_CONFIG_EVALUATIONS_PAGE_SIZE,
        maxItems: ALI_CONFIG_MAX_RESULTS_PER_RULE,
        fetch: (q) =>
          aliCall(ALI_API.config.ListConfigRuleEvaluationResults, aliCallCtx(env), {
            ...q,
            ConfigRuleId: ruleId,
            ComplianceType: ALI_CONFIG_NON_COMPLIANT,
          }),
        items: (p) => asArray<AliEvaluationResult>(aliField(aliField(p, "EvaluationResults"), "EvaluationResultList")),
        nextToken: (p) => aliString(aliField(aliField(p, "EvaluationResults"), "NextToken")),
      });
      return { rule, results: page.items, warnings: page.warnings };
    } catch (err) {
      if (isAliFatal(err)) throw err;
      const degraded =
        degradeAliError(`Config rule ${shownId}`, err) ?? `Config rule ${shownId}: could not list evaluation results (${describeAliError(err)}); skipped`;
      return { rule, results: [], warnings: [degraded] };
    }
  }

  /** ListCompliancePacks (best effort): failures other than auth / api misuse → warning, empty map. */
  private async loadPacks(env: AliScanEnv, warnings: string[]): Promise<Map<string, AliCompliancePackInfo>> {
    const map = new Map<string, AliCompliancePackInfo>();
    try {
      const page = await aliPaginate<unknown, Record<string, unknown>>({
        style: "page",
        label: "Config ListCompliancePacks",
        pageSize: ALI_CONFIG_PACKS_PAGE_SIZE,
        fetch: (q) => aliCall(ALI_API.config.ListCompliancePacks, aliCallCtx(env), q),
        items: (p) => asArray<Record<string, unknown>>(aliField(aliField(p, "CompliancePacksResult"), "CompliancePacks")),
        totalCount: (p) => aliNumber(aliField(aliField(p, "CompliancePacksResult"), "TotalCount")),
      });
      warnings.push(...page.warnings);
      for (const p of page.items) {
        const id = aliString(p.CompliancePackId);
        if (!id) continue;
        const name = aliUntrusted(p.CompliancePackName);
        const templateId = aliUntrusted(p.CompliancePackTemplateId);
        const status = aliString(p.Status);
        // Only ACTIVE (or status-less) packs count as "enabled" for the MLPS annotation.
        const active = status === undefined || status.toUpperCase() === "ACTIVE";
        map.set(id, { id, name, templateId, status, mlps: active && isAliMlpsPack(name, templateId, aliString(p.Description)) });
      }
    } catch (err) {
      if (isAliFatal(err)) throw err;
      warnings.push(`Config: could not list compliance packs (${describeAliError(err)}); findings are not annotated with compliance pack names.`);
    }
    return map;
  }
}

function asArray<T>(v: unknown): T[] {
  return Array.isArray(v) ? (v as T[]) : [];
}
