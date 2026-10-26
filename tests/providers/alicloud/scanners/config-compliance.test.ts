/**
 * Phase 2 T2 — AliConfigComplianceScanner (config_compliance_findings): NON_COMPLIANT rule
 * evaluations → findings, COMPLIANT skipped, RiskLevel mapping, MLPS (等保) pack source
 * annotation, URNs, pagination, caps (rules / per rule / total / concurrency) and errors.
 * aliCall is mocked by spec.action; fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall };
});

import {
  AliConfigComplianceScanner,
  ALI_CONFIG_MAX_FINDINGS,
  ALI_CONFIG_MAX_RESULTS_PER_RULE,
  ALI_CONFIG_MAX_RULES,
  ALI_CONFIG_NOT_ENABLED_WARNING,
  ALI_CONFIG_RULE_CONCURRENCY,
  aliConfigResourceType,
  aliConfigResourceUrn,
  aliConfigRiskScore,
  isAliMlpsPack,
  isAliNonCompliant,
} from "../../../../src/providers/alicloud/scanners/config-compliance.js";
import {
  aliCtx,
  authError,
  callsFor,
  deniedError,
  FAKE_SK,
  isolateAliEnv,
  misuseError,
  notEnabledError,
  restoreAliEnv,
  routeAliCall,
  UID,
  type AliHandler,
} from "./helpers.js";

const RULES = "ListConfigRules";
const EVALS = "ListConfigRuleEvaluationResults";
const PACKS = "ListCompliancePacks";

beforeEach(() => {
  isolateAliEnv();
  mocks.aliCall.mockReset();
});
afterEach(() => restoreAliEnv());

interface RuleOpts {
  risk?: number;
  compliance?: string;
  packId?: string;
  packName?: string;
  name?: string;
}
const rule = (id: string, o: RuleOpts = {}) => ({
  ConfigRuleId: id,
  ConfigRuleName: o.name ?? `rule-${id}`,
  ConfigRuleState: "ACTIVE",
  Description: `Description of ${id}`,
  ...(o.risk !== undefined ? { RiskLevel: o.risk } : {}),
  SourceIdentifier: `managed-${id}`,
  SourceOwner: "ALIYUN",
  Compliance: { ComplianceType: o.compliance ?? "NON_COMPLIANT", Count: 1 },
  ...(o.packId || o.packName ? { CreateBy: { CompliancePackId: o.packId, CompliancePackName: o.packName } } : {}),
});

interface EvalOpts {
  type?: string;
  region?: string;
  owner?: string | number;
  compliance?: string | null;
  annotation?: string;
}
const evaluation = (ruleId: string, resourceId: string, o: EvalOpts = {}) => ({
  ...(o.compliance === null ? {} : { ComplianceType: o.compliance ?? "NON_COMPLIANT" }),
  ...(o.annotation ? { Annotation: o.annotation } : {}),
  EvaluationResultIdentifier: {
    EvaluationResultQualifier: {
      ConfigRuleId: ruleId,
      ResourceId: resourceId,
      ResourceName: `name-${resourceId}`,
      ResourceType: o.type ?? "ACS::ECS::Instance",
      RegionId: o.region ?? "cn-hangzhou",
      ...(o.owner !== undefined ? { ResourceOwnerId: o.owner } : {}),
    },
  },
});

const rulesPage = (list: unknown[], total = list.length) => ({ ConfigRules: { ConfigRuleList: list, PageNumber: 1, PageSize: 100, TotalCount: total } });
const evalPage = (list: unknown[], next?: string) => ({ EvaluationResults: { EvaluationResultList: list, ...(next ? { NextToken: next } : {}), MaxResults: 100 } });
const packsPage = (list: unknown[]) => ({ CompliancePacksResult: { CompliancePacks: list, PageNumber: 1, PageSize: 100, TotalCount: list.length } });

/** Route with sensible defaults: no packs; evaluations by rule id. */
function route(opts: { rules: AliHandler | object; evals?: Record<string, unknown[]> | AliHandler; packs?: AliHandler | object }) {
  const evals = opts.evals ?? {};
  routeAliCall(mocks.aliCall, {
    [RULES]: opts.rules,
    [PACKS]: opts.packs ?? packsPage([]),
    [EVALS]:
      typeof evals === "function"
        ? evals
        : (q: Record<string, unknown>) => evalPage((evals as Record<string, unknown[]>)[q.ConfigRuleId as string] ?? []),
  });
}

describe("pure helpers", () => {
  it("isAliNonCompliant tolerates case / separators", () => {
    expect(isAliNonCompliant("NON_COMPLIANT")).toBe(true);
    expect(isAliNonCompliant("non_compliant")).toBe(true);
    expect(isAliNonCompliant("NonCompliant")).toBe(true);
    expect(isAliNonCompliant("COMPLIANT")).toBe(false);
    expect(isAliNonCompliant(undefined)).toBe(false);
  });

  it("maps RiskLevel 1/2/3 → 7.5/5.0/3.0, default 5.0", () => {
    expect(aliConfigRiskScore(1)).toBe(7.5);
    expect(aliConfigRiskScore("2")).toBe(5.0);
    expect(aliConfigRiskScore(3)).toBe(3.0);
    expect(aliConfigRiskScore(undefined)).toBe(5.0);
    expect(aliConfigRiskScore(9)).toBe(5.0);
  });

  it("maps resource types via the table and the generic fallback", () => {
    expect(aliConfigResourceType("ACS::ECS::Instance")).toBe("ecs:instance");
    expect(aliConfigResourceType("acs::oss::bucket")).toBe("oss:bucket");
    expect(aliConfigResourceType("ACS::RDS::DBInstance")).toBe("rds:dbinstance");
    expect(aliConfigResourceType("ACS::Foo::BarBaz")).toBe("foo:barbaz");
    expect(aliConfigResourceType("ACS::Foo")).toBe("foo:resource");
    expect(aliConfigResourceType(undefined)).toBe("config:resource");
    expect(aliConfigResourceType("")).toBe("config:resource");
  });

  it("builds URNs (global services drop the region)", () => {
    expect(aliConfigResourceUrn("ACS::ECS::Instance", "i-1", "cn-hangzhou", UID)).toBe(`acs:ecs:cn-hangzhou:${UID}:instance/i-1`);
    expect(aliConfigResourceUrn("ACS::RAM::User", "u-1", "cn-hangzhou", UID)).toBe(`acs:ram::${UID}:user/u-1`);
    expect(aliConfigResourceUrn("ACS::OSS::Bucket", "b-1", "global", UID)).toBe(`acs:oss::${UID}:bucket/b-1`);
    expect(aliConfigResourceUrn("ACS::Foo::Bar", "x", "cn-beijing", UID)).toBe(`acs:foo:cn-beijing:${UID}:bar/x`);
  });

  it("recognises MLPS (等保) packs", () => {
    expect(isAliMlpsPack("等保三级预检合规包")).toBe(true);
    expect(isAliMlpsPack(undefined, "MLPS-Level3-template")).toBe(true);
    expect(isAliMlpsPack("Classified Protection 2.0")).toBe(true);
    expect(isAliMlpsPack("CIS Benchmark", undefined)).toBe(false);
  });
});

describe("AliConfigComplianceScanner", () => {
  const scanner = new AliConfigComplianceScanner();

  it("has the alicloud aggregation moduleName", () => {
    expect(scanner.moduleName).toBe("config_compliance_findings");
  });

  it("emits one finding per NON_COMPLIANT resource (normal hit)", async () => {
    route({
      rules: rulesPage([rule("cr-1", { risk: 1, name: "ecs-instance-no-public-ip" })]),
      evals: { "cr-1": [evaluation("cr-1", "i-1", { annotation: "has public IP" }), evaluation("cr-1", "i-2", { region: "cn-beijing" })] },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(2);
    expect(r.resourcesScanned).toBe(2);
    const [f1, f2] = r.findings;
    expect(f1).toMatchObject({
      severity: "HIGH",
      riskScore: 7.5,
      title: "Config rule non-compliance: ecs-instance-no-public-ip",
      resourceType: "ACS::ECS::Instance",
      resourceId: "i-1",
      resourceArn: `acs:ecs:cn-hangzhou:${UID}:instance/i-1`,
      region: "cn-hangzhou",
      accountId: UID,
      module: "config_compliance_findings",
      source: "Config",
      provider: "alicloud",
      impact: "Source: Config (managed-cr-1)",
    });
    expect(f1.description).toContain("has public IP");
    expect(f2.region).toBe("cn-beijing");
    expect(f2.resourceArn).toBe(`acs:ecs:cn-beijing:${UID}:instance/i-2`);

    // Request filters + site pass-through.
    const [, ctx, q] = callsFor(mocks.aliCall, RULES)[0];
    expect(q).toMatchObject({ ComplianceType: "NON_COMPLIANT", PageNumber: 1, PageSize: 100 });
    expect(ctx).toMatchObject({ site: "cn" });
    expect(callsFor(mocks.aliCall, EVALS)[0][2]).toMatchObject({ ConfigRuleId: "cr-1", ComplianceType: "NON_COMPLIANT", MaxResults: 100 });
  });

  it("no non-compliant rules → success, 0 findings, no warnings (no hit)", async () => {
    route({ rules: rulesPage([]) });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toBeUndefined();
    expect(callsFor(mocks.aliCall, EVALS)).toHaveLength(0);
  });

  it("skips COMPLIANT rules and explicitly COMPLIANT results", async () => {
    route({
      rules: rulesPage([rule("cr-ok", { compliance: "COMPLIANT" }), rule("cr-bad")]),
      evals: {
        "cr-ok": [evaluation("cr-ok", "i-9")],
        "cr-bad": [evaluation("cr-bad", "i-1"), evaluation("cr-bad", "i-2", { compliance: "COMPLIANT" }), evaluation("cr-bad", "i-3", { compliance: null })],
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(callsFor(mocks.aliCall, EVALS).map((c) => c[2].ConfigRuleId)).toEqual(["cr-bad"]);
    expect(r.findings.map((f) => f.resourceId)).toEqual(["i-1", "i-3"]);
  });

  it("maps RiskLevel 1/2/3/absent → HIGH/MEDIUM/LOW/MEDIUM", async () => {
    route({
      rules: rulesPage([rule("r1", { risk: 1 }), rule("r2", { risk: 2 }), rule("r3", { risk: 3 }), rule("rx")]),
      evals: { r1: [evaluation("r1", "a")], r2: [evaluation("r2", "b")], r3: [evaluation("r3", "c")], rx: [evaluation("rx", "d")] },
    });
    const r = await scanner.scan(aliCtx());
    const sev = Object.fromEntries(r.findings.map((f) => [f.resourceId, f.severity]));
    expect(sev).toEqual({ a: "HIGH", b: "MEDIUM", c: "LOW", d: "MEDIUM" });
  });

  it('annotates MLPS (等保) pack rules with source "Config:<packName>"', async () => {
    route({
      packs: packsPage([
        { CompliancePackId: "cp-mlps", CompliancePackName: "等保三级预检合规包", CompliancePackTemplateId: "ct-mlps3", Status: "ACTIVE" },
        { CompliancePackId: "cp-cis", CompliancePackName: "CIS Benchmark", Status: "ACTIVE" },
        { CompliancePackId: "cp-old", CompliancePackName: "等保二级预检", Status: "INACTIVE" },
      ]),
      rules: rulesPage([
        rule("r-mlps", { packId: "cp-mlps" }),
        rule("r-cis", { packId: "cp-cis", packName: "CIS Benchmark" }),
        rule("r-old", { packId: "cp-old" }),
        rule("r-none"),
      ]),
      evals: {
        "r-mlps": [evaluation("r-mlps", "i-1")],
        "r-cis": [evaluation("r-cis", "i-2")],
        "r-old": [evaluation("r-old", "i-3")],
        "r-none": [evaluation("r-none", "i-4")],
      },
    });
    const r = await scanner.scan(aliCtx());
    const src = Object.fromEntries(r.findings.map((f) => [f.resourceId, f.source]));
    expect(src).toEqual({ "i-1": "Config:等保三级预检合规包", "i-2": "Config", "i-3": "Config", "i-4": "Config" });
    const mlps = r.findings.find((f) => f.resourceId === "i-1")!;
    expect(mlps.impact).toBe("Source: Config:等保三级预检合规包 (managed-r-mlps)");
    expect(mlps.description).toContain("Compliance pack: 等保三级预检合规包.");
  });

  it("uses ResourceOwnerId and global-service URNs", async () => {
    route({
      rules: rulesPage([rule("r1")]),
      evals: { r1: [evaluation("r1", "alice", { type: "ACS::RAM::User", region: "global", owner: 1111222233334444 })] },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings[0]).toMatchObject({
      region: "global",
      accountId: "1111222233334444",
      resourceArn: "acs:ram::1111222233334444:user/alice",
    });
  });

  it("dedupes the same rule / resource / region", async () => {
    route({ rules: rulesPage([rule("r1")]), evals: { r1: [evaluation("r1", "i-1"), evaluation("r1", "i-1")] } });
    const r = await scanner.scan(aliCtx());
    expect(r.findingsCount).toBe(1);
  });

  it("paginates ListConfigRules (PageNumber) and evaluation results (NextToken)", async () => {
    const all = [rule("r1"), rule("r2"), rule("r3")];
    route({
      rules: (q) => (q.PageNumber === 1 ? rulesPage(all.slice(0, 2), 3) : rulesPage(all.slice(2), 3)),
      evals: (q) => {
        if (q.ConfigRuleId !== "r1") return evalPage([]);
        return q.NextToken === "tok-2" ? evalPage([evaluation("r1", "i-2")]) : evalPage([evaluation("r1", "i-1")], "tok-2");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(callsFor(mocks.aliCall, RULES).map((c) => c[2].PageNumber)).toEqual([1, 2]);
    const r1Calls = callsFor(mocks.aliCall, EVALS).filter((c) => c[2].ConfigRuleId === "r1");
    expect(r1Calls).toHaveLength(2);
    expect(r1Calls[1][2].NextToken).toBe("tok-2");
    expect(r.findings.map((f) => f.resourceId)).toEqual(["i-1", "i-2"]);
    expect(callsFor(mocks.aliCall, EVALS).map((c) => c[2].ConfigRuleId).sort()).toEqual(["r1", "r1", "r2", "r3"]);
  });

  it(`caps the number of rules (${ALI_CONFIG_MAX_RULES}) with a warning`, async () => {
    const all = Array.from({ length: ALI_CONFIG_MAX_RULES + 5 }, (_, i) => rule(`r${i}`));
    route({
      rules: (q) => {
        const n = q.PageNumber as number;
        const size = q.PageSize as number;
        return rulesPage(all.slice((n - 1) * size, n * size), all.length);
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(callsFor(mocks.aliCall, EVALS)).toHaveLength(ALI_CONFIG_MAX_RULES);
    expect(r.warnings?.some((w) => w.includes(`first ${ALI_CONFIG_MAX_RULES} only`))).toBe(true);
  });

  it(`caps results per rule (${ALI_CONFIG_MAX_RESULTS_PER_RULE}) with a warning`, async () => {
    let n = 0;
    route({
      rules: rulesPage([rule("r1")]),
      evals: () => {
        n += 1;
        return evalPage(Array.from({ length: 100 }, (_, i) => evaluation("r1", `i-${n}-${i}`)), `tok-${n}`);
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findingsCount).toBe(ALI_CONFIG_MAX_RESULTS_PER_RULE);
    expect(r.warnings?.some((w) => w.includes("item cap reached"))).toBe(true);
  });

  it(`caps total findings (${ALI_CONFIG_MAX_FINDINGS}) with a truncation warning`, async () => {
    const ruleCount = Math.ceil(ALI_CONFIG_MAX_FINDINGS / ALI_CONFIG_MAX_RESULTS_PER_RULE) + 1;
    const rules = Array.from({ length: ruleCount }, (_, i) => rule(`r${i}`));
    const pageNo = new Map<string, number>();
    route({
      rules: rulesPage(rules),
      evals: (q) => {
        const id = q.ConfigRuleId as string;
        const p = (pageNo.get(id) ?? 0) + 1;
        pageNo.set(id, p);
        return evalPage(Array.from({ length: 100 }, (_, i) => evaluation(id, `${id}-${p}-${i}`)), `${id}-tok-${p}`);
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(ALI_CONFIG_MAX_FINDINGS);
    expect(r.resourcesScanned).toBe(ruleCount * ALI_CONFIG_MAX_RESULTS_PER_RULE);
    expect(r.warnings?.some((w) => w.includes("findings were truncated"))).toBe(true);
  });

  it(`runs at most ${ALI_CONFIG_RULE_CONCURRENCY} evaluation listings concurrently`, async () => {
    let inFlight = 0;
    let peak = 0;
    route({
      rules: rulesPage(Array.from({ length: 12 }, (_, i) => rule(`r${i}`))),
      evals: async (q) => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await new Promise((res) => setTimeout(res, 2));
        inFlight -= 1;
        return evalPage([evaluation(q.ConfigRuleId as string, "i-1")]);
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findingsCount).toBe(12);
    expect(peak).toBeGreaterThan(1);
    expect(peak).toBeLessThanOrEqual(ALI_CONFIG_RULE_CONCURRENCY);
  });

  it("Config not enabled → warning, success", async () => {
    route({ rules: () => { throw notEnabledError("config:ListConfigRules"); } });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings?.[0]).toContain(ALI_CONFIG_NOT_ENABLED_WARNING);
  });

  it("access_denied on ListConfigRules → degraded warning, success", async () => {
    route({ rules: () => { throw deniedError("config:ListConfigRules"); } });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings?.[0]).toMatch(/^Config: insufficient permissions/);
  });

  it("access_denied on one rule's evaluations → warning, other rules still reported", async () => {
    route({
      rules: rulesPage([rule("r1"), rule("r2")]),
      evals: (q) => {
        if (q.ConfigRuleId === "r1") throw deniedError("config:ListConfigRuleEvaluationResults");
        return evalPage([evaluation("r2", "i-2")]);
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceId)).toEqual(["i-2"]);
    expect(r.warnings?.some((w) => w.startsWith("Config rule r1: insufficient permissions"))).toBe(true);
  });

  it("access_denied on ListCompliancePacks → warning, findings unannotated", async () => {
    route({
      packs: () => { throw deniedError("config:ListCompliancePacks"); },
      rules: rulesPage([rule("r1", { packId: "cp-mlps" })]),
      evals: { r1: [evaluation("r1", "i-1")] },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings[0].source).toBe("Config");
    expect(r.warnings?.some((w) => w.includes("could not list compliance packs"))).toBe(true);
  });

  it("auth_failed (404 InvalidAccessKeyId.NotFound) on ListConfigRules → status error", async () => {
    route({ rules: () => { throw authError("config:ListConfigRules"); } });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
    expect(JSON.stringify(r)).not.toContain(FAKE_SK);
  });

  it("auth_failed in a per-rule evaluation listing → status error (not swallowed)", async () => {
    route({
      rules: rulesPage([rule("r1"), rule("r2")]),
      evals: (q) => {
        if (q.ConfigRuleId === "r2") throw authError("config:ListConfigRuleEvaluationResults");
        return evalPage([evaluation("r1", "i-1")]);
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
    expect(r.findings).toEqual([]);
  });

  it("auth_failed on ListCompliancePacks → status error", async () => {
    route({ packs: () => { throw authError("config:ListCompliancePacks"); }, rules: rulesPage([rule("r1")]) });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
  });

  it("api_misuse → status error", async () => {
    route({ rules: () => { throw misuseError("config:ListConfigRules"); } });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toContain("Config compliance findings scan failed");
    expect(r.error).toContain("MissingParameter");
  });

  it("api_misuse in a per-rule evaluation listing → status error", async () => {
    route({
      rules: rulesPage([rule("r1")]),
      evals: () => { throw misuseError("config:ListConfigRuleEvaluationResults"); },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toContain("MissingParameter");
  });

  it("redacts credential echoes in every Config-sourced field (resourceId / URN / description / remediation / warnings)", async () => {
    const leakAk = "LTAI5tFAKE000000000000";
    const echo = `server string to sign is:POST&%2F&AccessKeyId%3D${leakAk}`;
    const leakyAnnotation = `evaluation failed accessKeySecret=${FAKE_SK} ${echo}`;
    const leakyRuleId = `cr-${leakAk}`;
    route({
      rules: rulesPage([
        { ...rule("cr-leak", { risk: 1 }), Description: `Check failed: accessKeySecret=${FAKE_SK}` },
        rule(leakyRuleId),
      ]),
      evals: (q) => {
        if (q.ConfigRuleId === leakyRuleId) throw deniedError("config:ListConfigRuleEvaluationResults");
        const e = evaluation("cr-leak", leakAk, { annotation: leakyAnnotation });
        e.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceName = `AccessKeyId=${leakAk}`;
        return evalPage([e]);
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toHaveLength(1);
    const [f] = r.findings;
    // The raw request still used the real rule id (redaction is output-only).
    expect(callsFor(mocks.aliCall, EVALS).map(([, , q]) => q.ConfigRuleId)).toContain(leakyRuleId);

    const forbidden = [leakAk, "LTAI5tFAKE", FAKE_SK, "AccessKeyId%3DLTAI", "POST&%2F&AccessKeyId", "%3DLTAI"];
    const emitted: Array<[string, string]> = [
      ["resourceId", f.resourceId],
      ["resourceArn", f.resourceArn],
      ["title", f.title],
      ["description", f.description],
      ["impact", f.impact],
      ...f.remediationSteps.map((s, i): [string, string] => [`remediationSteps[${i}]`, s]),
      ...(r.warnings ?? []).map((w, i): [string, string] => [`warnings[${i}]`, w]),
      ["json", JSON.stringify(r)],
    ];
    for (const [field, text] of emitted) {
      for (const bad of forbidden) expect(text, `${field} leaks ${bad}`).not.toContain(bad);
    }
    expect(f.resourceId).toContain("[REDACTED]");
    expect(f.resourceArn).toBe(`acs:ecs:cn-hangzhou:${UID}:instance/[REDACTED]`);
    expect(f.description).toContain("server string to sign is: [REDACTED]");
    expect(r.warnings?.some((w) => w.startsWith("Config rule cr-[REDACTED]: insufficient permissions"))).toBe(true);
  });

  it("leaves ordinary Config IDs / names untouched by the redaction", async () => {
    route({
      rules: rulesPage([rule("cr-0a1b2c3d4e5f", { name: "oss-bucket-public-read-prohibited" })]),
      evals: { "cr-0a1b2c3d4e5f": [evaluation("cr-0a1b2c3d4e5f", "i-bp1abcdefghijklmnop", { annotation: "ACL is public-read" })] },
    });
    const r = await scanner.scan(aliCtx());
    const [f] = r.findings;
    expect(f.resourceId).toBe("i-bp1abcdefghijklmnop");
    expect(f.resourceArn).toBe(`acs:ecs:cn-hangzhou:${UID}:instance/i-bp1abcdefghijklmnop`);
    expect(f.title).toBe("Config rule non-compliance: oss-bucket-public-read-prohibited");
    expect(f.description).toContain("Evaluation detail: ACL is public-read");
    expect(f.description).not.toContain("[REDACTED]");
  });
});
