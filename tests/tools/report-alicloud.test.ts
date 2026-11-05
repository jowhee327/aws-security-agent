/**
 * Phase 2 T8 — report layer / i18n / MLPS mapping with provider=alicloud (EXPERIMENTAL).
 * config_compliance_findings substitutes Security Hub; `acs:` ARNs collapse like AWS ARNs.
 * Pure in-memory fixtures: no credentials, no network.
 */
import { describe, it, expect } from "vitest";
import { getI18n, providerName, providerDisplayName } from "../../src/i18n/index.js";
import { zhI18n } from "../../src/i18n/zh.js";
import { enI18n } from "../../src/i18n/en.js";
import { MLPS3_CHECK_MAPPING, MLPS3_FULL_CHECKLIST, cloudProviderNote } from "../../src/data/mlps3-check-mapping.js";
import { evaluateFullCheck, evaluateAllFullChecks, generateMlps3Report, getMappingById } from "../../src/tools/mlps-report.js";
import { generateHtmlReport, generateMlps3HtmlReport, getRecommendationTemplate } from "../../src/tools/html-report.js";
import { generateMarkdownReport } from "../../src/tools/report-tool.js";
import { buildAiSummaryPrompt } from "../../src/tools/ai-summary-prompt.js";
import { resolveModuleAlias } from "../../src/providers/module-aliases.js";
import { alibabaCloudProvider } from "../../src/providers/alicloud/index.js";
import type { Finding, FullScanResult } from "../../src/types.js";

const UID = "1234567890123456";

function configFinding(identifier: string, id = "sg-bp1fake"): Finding {
  return {
    severity: "HIGH",
    title: `Config rule non-compliance: rule-${identifier}`,
    resourceType: "ACS::ECS::SecurityGroup",
    resourceId: id,
    resourceArn: `acs:ecs:cn-hangzhou:${UID}:securitygroup/${id}`,
    region: "cn-hangzhou",
    description: `ACS::ECS::SecurityGroup ${id} in cn-hangzhou is NON_COMPLIANT with Config rule "rule-${identifier}".`,
    impact: `Source: Config (${identifier})`,
    riskScore: 7.5,
    remediationSteps: [`Open the Alibaba Cloud Config console and review acs:ecs:cn-hangzhou:${UID}:securitygroup/${id}`],
    priority: "P1",
    module: "config_compliance_findings",
    source: "Config",
    provider: "alicloud",
  };
}

const item = (id: string) => MLPS3_FULL_CHECKLIST.find((i) => i.id === id)!;

/** Managed-rule identifiers listed in plan §3.7 (the only ones the mapping may use). */
const KNOWN_IDENTIFIERS = new Set([
  "ram-user-mfa-check",
  "ram-password-policy-check",
  "root-ak-check",
  "actiontrail-enabled",
  "oss-bucket-public-read-prohibited",
  "oss-bucket-public-write-prohibited",
  "ecs-disk-encrypted",
  "sg-public-access-check",
  "rds-public-access-check",
  "rds-instance-enabled-ssl",
  "slb-listener-https-enabled",
  "kms-key-rotation-enabled",
]);

describe("i18n — alicloud", () => {
  it("providerName / providerDisplayName", () => {
    expect(providerName("alicloud", "zh")).toBe("阿里云");
    expect(providerName("alicloud", "en")).toBe("Alibaba Cloud");
    expect(providerName("alicloud")).toBe("阿里云");
    expect(providerDisplayName("alicloud", "en")).toBe("Alibaba Cloud");
    expect(providerDisplayName(undefined, "en")).toBe("AWS");
    expect(providerDisplayName("huaweicloud", "en")).toBe("Huawei Cloud");
  });

  it("derives Alibaba Cloud labels without touching the AWS / Huawei tables", () => {
    const zh = getI18n("zh", "alicloud");
    const en = getI18n("en", "alicloud");
    expect(zh).not.toBe(zhI18n);
    expect(zh).not.toBe(getI18n("zh", "huaweicloud"));
    expect(zh.securityReportTitle).toBe("阿里云安全扫描报告");
    expect(en.securityReportTitle).toBe("Alibaba Cloud Security Scan Report");
    expect(zh.cloudItemsNote(2)).toContain("阿里云");
    expect(zh.cloudItemsNote(2)).not.toContain("AWS");
    expect(en.cloudItemsNote(2)).toContain("Alibaba Cloud platform");
    expect(zh.serviceRecommendations.config_rules_findings.service).toContain("配置审计");
    expect(en.serviceRecommendations.config_rules_findings.service).toBe("Alibaba Cloud Config");
    expect(zh.serviceRecommendations.config_compliance_findings.service).toContain("合规包");
    expect(en.serviceRecommendations.config_compliance_findings.action).toContain("compliance pack");
    for (const mod of ["guardduty_findings", "inspector_findings", "patch_compliance_findings"]) {
      expect(zh.serviceRecommendations[mod].service, mod).toContain("SAS");
      expect(en.serviceRecommendations[mod].service, mod).toContain("Security Center");
    }
    // Shared / product-name entries untouched; cached identity.
    expect(zh.moduleNames).toBe(zhI18n.moduleNames);
    expect(zh.serviceRecommendations.security_hub_findings).toBe(zhI18n.serviceRecommendations.security_hub_findings);
    expect(zh.generatedBy).toBe(zhI18n.generatedBy);
    expect(getI18n("zh", "alicloud")).toBe(zh);
    expect(getI18n("en", "alicloud")).toBe(en);
    // AWS / Huawei tables not affected
    expect(getI18n("zh")).toBe(zhI18n);
    expect(getI18n("en", "aws")).toBe(enI18n);
    expect(zhI18n.serviceRecommendations.config_compliance_findings).toBeUndefined();
    expect(getI18n("zh", "huaweicloud").serviceRecommendations.config_compliance_findings).toBeUndefined();
    expect(getI18n("zh", "huaweicloud").securityReportTitle).toBe("华为云安全扫描报告");
    expect(getI18n("zh", "huaweicloud").serviceRecommendations.guardduty_findings).toBe(zhI18n.serviceRecommendations.guardduty_findings);
  });

  it("every alicloud scanner module has en/zh display names", () => {
    const modules = alibabaCloudProvider.scanners().map((s) => s.moduleName);
    expect(modules).toHaveLength(14);
    for (const mod of modules) {
      expect(zhI18n.moduleNames[mod], mod).toBeTruthy();
      expect(enI18n.moduleNames[mod], mod).toBeTruthy();
    }
    expect(zhI18n.moduleNames.config_compliance_findings).toBe("Config 合规检查");
    expect(enI18n.moduleNames.config_compliance_findings).toBe("Config Compliance");
  });
});

describe("mlps3-check-mapping — alicloud fields", () => {
  it("cloud_provider notes use Alibaba Cloud wording, falling back to note", () => {
    const pes = getMappingById("L3-PES1-01")!;
    expect(cloudProviderNote(pes, "alicloud")).toBe("阿里云负责机房物理安全");
    expect(cloudProviderNote(pes, "huaweicloud")).toBe("华为云负责机房物理安全");
    expect(cloudProviderNote(pes)).toBe("AWS 负责机房物理安全");
    expect(cloudProviderNote(getMappingById("L3-CNS2-05")!, "alicloud")).toBe("阿里云云市场 支持第三方产品");
    expect(cloudProviderNote(getMappingById("L3-CNS2-02")!, "alicloud")).toBe("VPC 实现虚拟网络隔离");
    for (const m of MLPS3_CHECK_MAPPING.filter((m) => m.noteHuawei)) {
      expect(m.noteAlicloud, m.id).toBeTruthy();
      expect(m.noteAlicloud, m.id).toContain("阿里云");
      expect(m.noteAlicloud, m.id).not.toMatch(/AWS|华为/);
    }
    expect(MLPS3_CHECK_MAPPING.filter((m) => m.noteAlicloud).every((m) => m.type === "cloud_provider")).toBe(true);
  });

  it("alicloudConfigRuleIdentifiers accompany Security Hub control IDs and use known managed-rule identifiers", () => {
    const withAli = MLPS3_CHECK_MAPPING.filter((m) => m.alicloudConfigRuleIdentifiers?.length);
    expect(withAli.length).toBeGreaterThanOrEqual(20);
    const used = new Set<string>();
    for (const m of withAli) {
      expect(m.type, m.id).toBe("auto");
      expect(m.securityHubControlIds?.length, m.id).toBeGreaterThan(0);
      expect(m.modules, m.id).toContain("security_hub_findings");
      for (const id of m.alicloudConfigRuleIdentifiers!) {
        expect(KNOWN_IDENTIFIERS.has(id), `${m.id}: ${id}`).toBe(true);
        used.add(id);
      }
    }
    expect([...used].sort()).toEqual([...KNOWN_IDENTIFIERS].sort());
    // Existing AWS / Huawei values untouched.
    expect(getMappingById("L3-CES1-04")!.securityHubControlIds).toEqual(["IAM.5", "IAM.6"]);
    expect(getMappingById("L3-CES1-04")!.rmsPolicyAssignmentNames).toEqual(["iam-user-mfa-enabled"]);
    expect(getMappingById("L3-CES1-04")!.alicloudConfigRuleIdentifiers).toEqual(["ram-user-mfa-check"]);
  });

  it("resolveModuleAlias maps security_hub_findings to config_compliance_findings for alicloud", () => {
    expect(resolveModuleAlias("security_hub_findings", "alicloud")).toBe("config_compliance_findings");
    expect(resolveModuleAlias("ssl_certificate", "alicloud")).toBe("ssl_certificate");
  });
});

describe("evaluateFullCheck with provider=alicloud", () => {
  const cfgOk = [{ module: "config_compliance_findings", status: "success" }];

  it("matches Config managed-rule identifiers against config_compliance_findings", () => {
    const mapping = getMappingById("L3-CES1-04")!;
    const issues = evaluateFullCheck(item("L3-CES1-04"), mapping, [configFinding("ram-user-mfa-check")], cfgOk, "alicloud");
    expect(issues.status).toBe("issues");
    expect(issues.relatedFindings).toHaveLength(1);

    const clean = evaluateFullCheck(item("L3-CES1-04"), mapping, [configFinding("ecs-disk-encrypted")], cfgOk, "alicloud");
    expect(clean.status).toBe("clean");

    // Huawei RMS findings / module do not satisfy an Alibaba check and vice versa.
    expect(evaluateFullCheck(item("L3-CES1-04"), mapping, [configFinding("ram-user-mfa-check")], cfgOk, "huaweicloud").status).toBe("unknown");
    expect(evaluateFullCheck(item("L3-CES1-04"), mapping, [], [{ module: "rms_compliance_findings", status: "success" }], "alicloud").status).toBe("unknown");
  });

  it("checks defined only by Security Hub control IDs without an Alibaba mapping stay unknown", () => {
    const mapping = getMappingById("L3-CES1-14")!; // CloudTrail.4-7, security_hub_findings only
    expect(mapping.alicloudConfigRuleIdentifiers).toBeUndefined();
    expect(evaluateFullCheck(item("L3-CES1-14"), mapping, [configFinding("actiontrail-enabled")], cfgOk, "alicloud").status).toBe("unknown");
  });

  it("hybrid checks count non-aggregation module findings and filter Config findings by identifier", () => {
    const mapping = getMappingById("L3-CES1-17")!; // network_reachability + security_hub_findings
    const netFinding: Finding = { ...configFinding("x"), module: "network_reachability", title: "ECS instance reachable from 0.0.0.0/0 on port 22" };
    const mods = [{ module: "network_reachability", status: "success" }, ...cfgOk];
    const r = evaluateFullCheck(
      item("L3-CES1-17"),
      mapping,
      [netFinding, configFinding("sg-public-access-check"), configFinding("kms-key-rotation-enabled")],
      mods,
      "alicloud",
    );
    expect(r.status).toBe("issues");
    expect(r.relatedFindings.map((f) => f.impact)).toEqual([netFinding.impact, "Source: Config (sg-public-access-check)"]);
  });
});

describe("report generators accept Alibaba Cloud results", () => {
  const aliResult: FullScanResult = {
    scanStart: "2026-10-26T01:00:00.000Z",
    scanEnd: "2026-10-26T01:00:05.000Z",
    region: "all",
    accountId: UID,
    provider: "alicloud",
    modules: [
      {
        module: "config_compliance_findings",
        status: "success",
        resourcesScanned: 10,
        findingsCount: 2,
        scanTimeMs: 50,
        findings: [configFinding("sg-public-access-check", "sg-public"), configFinding("ram-user-mfa-check", "user-1")],
      },
      { module: "service_detection", status: "success", resourcesScanned: 5, findingsCount: 0, scanTimeMs: 10, findings: [] },
      {
        module: "config_rules_findings",
        status: "success",
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: 5,
        findings: [],
        warnings: ["Alibaba Cloud Config resource recorder is not enabled for this account."],
      },
      { module: "ssl_certificate", status: "success", resourcesScanned: 1, findingsCount: 0, scanTimeMs: 5, findings: [] },
    ],
    summary: { totalFindings: 2, critical: 0, high: 2, medium: 0, low: 0, modulesSuccess: 4, modulesError: 0 },
  };

  it("evaluateAllFullChecks uses Config findings where Security Hub is expected", () => {
    const results = evaluateAllFullChecks(aliResult);
    expect(results).toHaveLength(184);
    const mfa = results.find((r) => r.item.id === "L3-CES1-04")!;
    expect(mfa.status).toBe("issues");
    expect(mfa.relatedFindings[0].impact).toContain("ram-user-mfa-check");
  });

  it("Markdown / MLPS / MLPS-HTML / HTML / AI prompt use Alibaba Cloud wording", () => {
    const md = generateMarkdownReport(aliResult, "zh");
    expect(md).toContain("# 阿里云安全扫描报告");
    expect(md).toContain(`acs:ecs:cn-hangzhou:${UID}:securitygroup/sg-public`);

    const mlps = generateMlps3Report(aliResult, "zh");
    expect(mlps).toContain("L3-CES1-04");
    expect(mlps).toContain("阿里云负责机房物理安全");
    expect(mlps).not.toContain("AWS 负责机房物理安全");

    const mlpsHtml = generateMlps3HtmlReport(aliResult, undefined, "zh");
    expect(mlpsHtml).toContain("阿里云负责机房物理安全");
    expect(mlpsHtml).not.toContain("AWS 负责机房物理安全");
    expect(mlpsHtml).toContain("由阿里云平台负责");
    expect(mlpsHtml).toContain("阿里云配置审计（Config）"); // service reminder for the Config recorder

    const html = generateHtmlReport(aliResult, undefined, "en");
    expect(html).toContain("Alibaba Cloud Security Scan Report");
    expect(html).not.toContain("AWS Security Scan Report");

    const prompt = buildAiSummaryPrompt("html", aliResult, "en");
    expect(prompt).toContain("Alibaba Cloud Security Scan Report");
    expect(prompt).not.toContain("AWS security scan report");
    expect(buildAiSummaryPrompt("html", aliResult, "zh")).toContain("阿里云 安全扫描报告");
  });

  it("AWS MLPS Markdown output keeps AWS wording", () => {
    const awsResult: FullScanResult = { ...aliResult, provider: undefined, accountId: "123456789012", region: "cn-north-1", modules: [] };
    const md = generateMlps3Report(awsResult, "zh");
    expect(md).toContain("AWS 负责机房物理安全");
    expect(md).not.toContain("阿里云");
  });
});

describe("getRecommendationTemplate — acs: ARNs", () => {
  it("collapses regional and global Alibaba Cloud ARNs to {arn}", () => {
    expect(getRecommendationTemplate(`Remove the public ACL of acs:oss:cn-hangzhou:${UID}:bucket/my-bucket now`))
      .toBe("Remove the public ACL of {arn} now");
    expect(getRecommendationTemplate(`Enable MFA for acs:ram::${UID}:user/alice`)).toBe("Enable MFA for {arn}");
    expect(getRecommendationTemplate(`Restrict acs:ecs:cn-shanghai:${UID}:securitygroup/sg-bp1abc ingress`))
      .toBe("Restrict {arn} ingress");
    const out = getRecommendationTemplate(`Review acs:rds:cn-beijing:${UID}:dbinstance/rm-2zefake and acs:kms::${UID}:key/key-fake`);
    expect(out).toBe("Review {arn} and {arn}");
    expect(out).not.toContain("acs:");
  });

  it("does not touch words merely ending in 'acs'", () => {
    expect(getRecommendationTemplate("Update macs:list and lilacs:garden")).toBe("Update macs:list and lilacs:garden");
  });
});
