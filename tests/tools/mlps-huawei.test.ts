/** T8 — MLPS / HW Defense report layer with provider=huaweicloud (rms_compliance_findings substitutes Security Hub). */
import { describe, it, expect } from "vitest";
import {
  MLPS3_CHECK_MAPPING,
  MLPS3_FULL_CHECKLIST,
  cloudProviderNote,
} from "../../src/data/mlps3-check-mapping.js";
import { evaluateFullCheck, evaluateAllFullChecks, generateMlps3Report, getMappingById } from "../../src/tools/mlps-report.js";
import { generateMlps3HtmlReport } from "../../src/tools/html-report.js";
import { generateHwDefenseHtmlReport } from "../../src/tools/hw-report.js";
import { generateMarkdownReport } from "../../src/tools/report-tool.js";
import { buildAiSummaryPrompt } from "../../src/tools/ai-summary-prompt.js";
import { resolveModuleAlias } from "../../src/providers/module-aliases.js";
import type { Finding, FullScanResult } from "../../src/types.js";

function rmsFinding(policy: string, id = "res-1"): Finding {
  return {
    severity: "HIGH",
    title: `RMS policy non-compliance: ${policy}`,
    resourceType: "vpc:securityGroups",
    resourceId: id,
    resourceArn: `hws:cn-north-4:d0m41n:vpc:securityGroups:${id}`,
    region: "cn-north-4",
    description: `vpc:securityGroups ${id} in cn-north-4 is NonCompliant with RMS policy assignment "${policy}".`,
    impact: `Source: RMS (${policy})`,
    riskScore: 7.5,
    remediationSteps: ["Open the Huawei Cloud Config (RMS) console"],
    priority: "P1",
    module: "rms_compliance_findings",
    source: "RMS",
    provider: "huaweicloud",
  };
}

const item = (id: string) => MLPS3_FULL_CHECKLIST.find((i) => i.id === id)!;

describe("mlps3-check-mapping — provider-aware fields", () => {
  it("cloud_provider notes: AWS wording by default, Huawei wording when requested", () => {
    const pes = getMappingById("L3-PES1-01")!;
    expect(cloudProviderNote(pes)).toBe("AWS 负责机房物理安全");
    expect(cloudProviderNote(pes, "aws")).toBe("AWS 负责机房物理安全");
    expect(cloudProviderNote(pes, "huaweicloud")).toBe("华为云负责机房物理安全");
    expect(cloudProviderNote(getMappingById("L3-PES2-01")!, "huaweicloud")).toBe("华为云中国区基础设施位于中国境内");
    // Notes that never mentioned AWS fall back unchanged.
    expect(cloudProviderNote(getMappingById("L3-CNS2-02")!, "huaweicloud")).toBe("VPC 实现虚拟网络隔离");
    for (const m of MLPS3_CHECK_MAPPING.filter((m) => m.type === "cloud_provider")) {
      expect(m.note, m.id).toBeTruthy();
      if (m.note!.includes("AWS")) {
        expect(m.noteHuawei, m.id).toBeTruthy();
        expect(m.noteHuawei, m.id).not.toContain("AWS");
      }
    }
  });

  it("rmsPolicyAssignmentNames only accompany securityHubControlIds (which stay untouched)", () => {
    const withRms = MLPS3_CHECK_MAPPING.filter((m) => m.rmsPolicyAssignmentNames?.length);
    expect(withRms.length).toBeGreaterThanOrEqual(15);
    for (const m of withRms) {
      expect(m.type).toBe("auto");
      expect(m.securityHubControlIds?.length, m.id).toBeGreaterThan(0);
      expect(m.modules, m.id).toContain("security_hub_findings");
    }
    expect(getMappingById("L3-CES1-04")!.securityHubControlIds).toEqual(["IAM.5", "IAM.6"]);
    expect(getMappingById("L3-CES1-04")!.rmsPolicyAssignmentNames).toEqual(["iam-user-mfa-enabled"]);
    expect(getMappingById("L3-CES1-17")!.rmsPolicyAssignmentNames).toEqual(["vpc-sg-ports-check"]);
  });

  it("resolveModuleAlias only rewrites for huaweicloud", () => {
    expect(resolveModuleAlias("security_hub_findings", undefined)).toBe("security_hub_findings");
    expect(resolveModuleAlias("security_hub_findings", "aws")).toBe("security_hub_findings");
    expect(resolveModuleAlias("security_hub_findings", "huaweicloud")).toBe("rms_compliance_findings");
    expect(resolveModuleAlias("ssl_certificate", "huaweicloud")).toBe("ssl_certificate");
  });
});

describe("evaluateFullCheck with provider=huaweicloud", () => {
  const rmsOk = [{ module: "rms_compliance_findings", status: "success" }];

  it("matches RMS policy names against rms_compliance_findings (Security Hub substitute)", () => {
    const mapping = getMappingById("L3-CES1-04")!; // modules: [security_hub_findings], IAM.5/IAM.6 → iam-user-mfa-enabled
    const issues = evaluateFullCheck(item("L3-CES1-04"), mapping, [rmsFinding("iam-user-mfa-enabled")], rmsOk, "huaweicloud");
    expect(issues.status).toBe("issues");
    expect(issues.relatedFindings).toHaveLength(1);

    const clean = evaluateFullCheck(item("L3-CES1-04"), mapping, [rmsFinding("volumes-encrypted-check")], rmsOk, "huaweicloud");
    expect(clean.status).toBe("clean");

    // Same inputs evaluated as AWS: security_hub_findings did not run → unknown (unchanged semantics).
    expect(evaluateFullCheck(item("L3-CES1-04"), mapping, [rmsFinding("iam-user-mfa-enabled")], rmsOk).status).toBe("unknown");
    expect(evaluateFullCheck(item("L3-CES1-04"), mapping, [], [{ module: "security_hub_findings", status: "success" }], "aws").status).toBe("clean");
  });

  it("checks defined only by Security Hub control IDs without an RMS mapping stay unknown on Huawei Cloud", () => {
    const mapping = getMappingById("L3-CES1-14")!; // CloudTrail.4-7, security_hub_findings only
    expect(mapping.rmsPolicyAssignmentNames).toBeUndefined();
    const r = evaluateFullCheck(item("L3-CES1-14"), mapping, [rmsFinding("cts-tracker-exists")], rmsOk, "huaweicloud");
    expect(r.status).toBe("unknown");
  });

  it("hybrid checks still count non-aggregation module findings on Huawei Cloud", () => {
    const mapping = getMappingById("L3-CES1-03")!; // ssl_certificate + security_hub_findings (ELB.1)
    const sslFinding: Finding = { ...rmsFinding("x"), module: "ssl_certificate", title: "SCM certificate expired" };
    const mods = [{ module: "ssl_certificate", status: "success" }, ...rmsOk];
    const r = evaluateFullCheck(item("L3-CES1-03"), mapping, [sslFinding, rmsFinding("unrelated-policy")], mods, "huaweicloud");
    expect(r.status).toBe("issues");
    expect(r.relatedFindings.map((f) => f.module)).toEqual(["ssl_certificate"]);
  });
});

describe("report generators accept Huawei Cloud results", () => {
  const hwResult: FullScanResult = {
    scanStart: "2026-09-13T01:00:00.000Z",
    scanEnd: "2026-09-13T01:00:05.000Z",
    region: "all",
    accountId: "d0m41n",
    provider: "huaweicloud",
    modules: [
      {
        module: "rms_compliance_findings",
        status: "success",
        resourcesScanned: 10,
        findingsCount: 2,
        scanTimeMs: 50,
        findings: [rmsFinding("vpc-sg-ports-check", "sg-public"), rmsFinding("iam-user-mfa-enabled", "user-1")],
      },
      { module: "service_detection", status: "success", resourcesScanned: 4, findingsCount: 0, scanTimeMs: 10, findings: [] },
      { module: "config_rules_findings", status: "success", resourcesScanned: 0, findingsCount: 0, scanTimeMs: 5, findings: [], warnings: ["Huawei Cloud RMS (Config) resource recorder is not enabled for this account."] },
      { module: "ssl_certificate", status: "success", resourcesScanned: 1, findingsCount: 0, scanTimeMs: 5, findings: [] },
    ],
    summary: { totalFindings: 2, critical: 0, high: 2, medium: 0, low: 0, modulesSuccess: 4, modulesError: 0 },
  };

  it("evaluateAllFullChecks uses RMS findings where Security Hub is expected", () => {
    const results = evaluateAllFullChecks(hwResult);
    expect(results).toHaveLength(184);
    const mfa = results.find((r) => r.item.id === "L3-CES1-04")!;
    expect(mfa.status).toBe("issues");
    expect(mfa.relatedFindings[0].title).toContain("iam-user-mfa-enabled");
    const sgOnly = results.find((r) => r.item.id === "L3-ABS1-02")!; // network_reachability + SH → hw lacks network_reachability
    expect(["unknown", "issues", "clean"]).toContain(sgOnly.status);
  });

  it("Markdown / MLPS / MLPS-HTML / HW-Defense / AI prompt do not throw and use Huawei wording", () => {
    const md = generateMarkdownReport(hwResult, "zh");
    expect(md).toContain("# 华为云安全扫描报告");
    expect(md).toContain("hws:cn-north-4:d0m41n:vpc:securityGroups:sg-public");

    const mlps = generateMlps3Report(hwResult, "zh");
    expect(mlps).toContain("L3-CES1-04");

    const mlpsHtml = generateMlps3HtmlReport(hwResult, undefined, "zh");
    expect(mlpsHtml).toContain("华为云负责机房物理安全");
    expect(mlpsHtml).not.toContain("AWS 负责机房物理安全");
    expect(mlpsHtml).toContain("由华为云平台负责");
    expect(mlpsHtml).toContain("华为云 Config (RMS)"); // service reminder for the RMS recorder

    const hw = generateHwDefenseHtmlReport(hwResult, "en");
    expect(hw).toContain("RMS policy non-compliance: vpc-sg-ports-check");

    const prompt = buildAiSummaryPrompt("html", hwResult, "en");
    expect(prompt).toContain("Huawei Cloud security scan report");
    expect(prompt).not.toContain("AWS security scan report");
    expect(buildAiSummaryPrompt("html", { ...hwResult, provider: undefined }, "en")).toContain("AWS security scan report");
  });

  it("AWS MLPS output is unchanged (notes keep AWS wording)", () => {
    const awsResult: FullScanResult = { ...hwResult, provider: undefined, accountId: "123456789012", region: "cn-north-1", modules: [] };
    const html = generateMlps3HtmlReport(awsResult, undefined, "zh");
    expect(html).toContain("AWS 负责机房物理安全");
    expect(html).toContain("由 AWS 云平台负责");
  });
});
