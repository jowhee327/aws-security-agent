/**
 * Phase 2 (Azure) T8 — report layer / i18n / MLPS mapping with provider=azure (EXPERIMENTAL).
 * defender_assessment_findings substitutes Security Hub; Azure resource IDs collapse like ARNs.
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
import { azureProvider } from "../../src/providers/azure/index.js";
import type { Finding, FullScanResult } from "../../src/types.js";

const TENANT = "00000000-0000-0000-0000-00000000fake";
const SUB = "22222222-2222-2222-2222-222222222222";

function defenderFinding(displayName: string, name = "vm-1"): Finding {
  const id = `/subscriptions/${SUB}/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/${name}`;
  return {
    severity: "HIGH",
    title: `Defender for Cloud: ${displayName}`,
    resourceType: "Microsoft.Compute/virtualMachines",
    resourceId: name,
    resourceArn: id,
    region: "global",
    description: `Defender for Cloud recommendation "${displayName}" is Unhealthy for Microsoft.Compute/virtualMachines ${name} (subscription ${SUB}).`,
    impact: "Source: Defender for Cloud (00000000-1111-2222-3333-444444444444)",
    riskScore: 7.0,
    remediationSteps: [`Open Microsoft Defender for Cloud → Recommendations and remediate ${id}`],
    priority: "P1",
    module: "defender_assessment_findings",
    accountId: TENANT,
    source: "Defender for Cloud",
    provider: "azure",
  };
}

const item = (id: string) => MLPS3_FULL_CHECKLIST.find((i) => i.id === id)!;

describe("i18n — azure", () => {
  it("providerName / providerDisplayName", () => {
    expect(providerName("azure", "en")).toBe("Azure");
    expect(providerName("azure", "zh")).toBe("Azure");
    expect(providerDisplayName("azure", "en")).toBe("Azure");
    expect(providerDisplayName("alicloud", "en")).toBe("Alibaba Cloud");
    expect(providerDisplayName(undefined, "en")).toBe("AWS");
  });

  it("derives Azure labels without touching the AWS / Huawei / Alibaba tables", () => {
    const zh = getI18n("zh", "azure");
    const en = getI18n("en", "azure");
    expect(zh).not.toBe(zhI18n);
    expect(zh).not.toBe(getI18n("zh", "alicloud"));
    expect(zh.securityReportTitle).toBe("Azure 安全扫描报告");
    expect(en.securityReportTitle).toBe("Azure Security Scan Report");
    expect(zh.cloudItemsNote(2)).toContain("Azure 平台");
    expect(zh.cloudItemsNote(2)).not.toContain("AWS");
    expect(en.cloudItemsNote(2)).toContain("Azure platform");
    expect(en.serviceRecommendations.config_rules_findings.service).toBe("Azure Policy");
    expect(zh.serviceRecommendations.defender_assessment_findings.service).toContain("Defender for Cloud");
    expect(en.serviceRecommendations.defender_assessment_findings.action).toContain("Microsoft.Security");
    expect(en.serviceRecommendations.disk_encryption_findings.service).toContain("disk encryption");
    for (const mod of ["guardduty_findings", "inspector_findings"]) {
      expect(zh.serviceRecommendations[mod].service, mod).toContain("Defender for Cloud");
      expect(en.serviceRecommendations[mod].service, mod).toContain("Defender for Cloud");
    }
    // Shared / product-name entries untouched; cached identity.
    expect(zh.moduleNames).toBe(zhI18n.moduleNames);
    expect(zh.serviceRecommendations.security_hub_findings).toBe(zhI18n.serviceRecommendations.security_hub_findings);
    expect(getI18n("zh", "azure")).toBe(zh);
    expect(getI18n("en", "azure")).toBe(en);
    // Other providers' tables not affected
    expect(getI18n("zh")).toBe(zhI18n);
    expect(getI18n("en", "aws")).toBe(enI18n);
    expect(zhI18n.serviceRecommendations.defender_assessment_findings).toBeUndefined();
    expect(getI18n("zh", "alicloud").serviceRecommendations.defender_assessment_findings).toBeUndefined();
    expect(getI18n("zh", "alicloud").securityReportTitle).toBe("阿里云安全扫描报告");
    expect(getI18n("zh", "huaweicloud").securityReportTitle).toBe("华为云安全扫描报告");
  });

  it("every azure scanner module has en/zh display names", () => {
    const modules = azureProvider.scanners().map((s) => s.moduleName);
    expect(modules).toHaveLength(12);
    for (const mod of modules) {
      expect(zhI18n.moduleNames[mod], mod).toBeTruthy();
      expect(enI18n.moduleNames[mod], mod).toBeTruthy();
    }
    expect(enI18n.moduleNames.defender_assessment_findings).toBe("Defender for Cloud Assessments");
    expect(zhI18n.moduleNames.disk_encryption_findings).toBe("磁盘加密");
  });
});

describe("mlps3-check-mapping — azure fields", () => {
  it("cloud_provider notes use Azure wording, falling back to note", () => {
    const pes = getMappingById("L3-PES1-01")!;
    expect(cloudProviderNote(pes, "azure")).toBe("Azure（世纪互联）负责机房物理安全");
    expect(cloudProviderNote(pes, "alicloud")).toBe("阿里云负责机房物理安全");
    expect(cloudProviderNote(pes)).toBe("AWS 负责机房物理安全");
    expect(cloudProviderNote(getMappingById("L3-CNS2-02")!, "azure")).toBe("Azure 虚拟网络（VNet）实现虚拟网络隔离");
    expect(cloudProviderNote(getMappingById("L3-CNS2-02")!, "alicloud")).toBe("VPC 实现虚拟网络隔离");
    for (const m of MLPS3_CHECK_MAPPING.filter((m) => m.noteAlicloud)) {
      expect(m.noteAzure, m.id).toContain("Azure");
      expect(m.noteAzure, m.id).not.toMatch(/AWS|华为|阿里/);
    }
    expect(MLPS3_CHECK_MAPPING.filter((m) => m.noteAzure).every((m) => m.type === "cloud_provider")).toBe(true);
  });

  it("azurePolicyDefinitionNames accompany Security Hub control IDs on auto rows", () => {
    const withAzure = MLPS3_CHECK_MAPPING.filter((m) => m.azurePolicyDefinitionNames?.length);
    expect(withAzure.length).toBeGreaterThanOrEqual(20);
    const used = new Set<string>();
    for (const m of withAzure) {
      expect(m.type, m.id).toBe("auto");
      expect(m.securityHubControlIds?.length, m.id).toBeGreaterThan(0);
      expect(m.modules, m.id).toContain("security_hub_findings");
      for (const n of m.azurePolicyDefinitionNames!) used.add(n);
    }
    for (const n of [
      "Storage account public access should be disallowed",
      "MFA should be enabled on accounts with owner permissions",
      "Disk encryption should be applied on virtual machines",
      "Key vaults should have purge protection enabled",
    ]) {
      expect(used.has(n), n).toBe(true);
    }
    // Existing AWS / Huawei / Alibaba values untouched.
    expect(getMappingById("L3-CES1-04")!.securityHubControlIds).toEqual(["IAM.5", "IAM.6"]);
    expect(getMappingById("L3-CES1-04")!.rmsPolicyAssignmentNames).toEqual(["iam-user-mfa-enabled"]);
    expect(getMappingById("L3-CES1-04")!.alicloudConfigRuleIdentifiers).toEqual(["ram-user-mfa-check"]);
  });

  it("resolveModuleAlias maps security_hub_findings to defender_assessment_findings for azure", () => {
    expect(resolveModuleAlias("security_hub_findings", "azure")).toBe("defender_assessment_findings");
    expect(resolveModuleAlias("network_reachability", "azure")).toBe("network_reachability");
  });
});

describe("evaluateFullCheck with provider=azure", () => {
  const defOk = [{ module: "defender_assessment_findings", status: "success" }];

  it("matches Azure Policy / Defender recommendation names against defender_assessment_findings", () => {
    const mapping = getMappingById("L3-CES1-04")!;
    const mfa = defenderFinding("MFA should be enabled on accounts with owner permissions on your subscription");
    const issues = evaluateFullCheck(item("L3-CES1-04"), mapping, [mfa], defOk, "azure");
    expect(issues.status).toBe("issues");
    expect(issues.relatedFindings).toHaveLength(1);

    const clean = evaluateFullCheck(item("L3-CES1-04"), mapping, [defenderFinding("Key vaults should have purge protection enabled")], defOk, "azure");
    expect(clean.status).toBe("clean");

    // Alibaba Config module does not satisfy an Azure check and vice versa.
    expect(evaluateFullCheck(item("L3-CES1-04"), mapping, [mfa], defOk, "alicloud").status).toBe("unknown");
    expect(evaluateFullCheck(item("L3-CES1-04"), mapping, [], [{ module: "config_compliance_findings", status: "success" }], "azure").status).toBe("unknown");
  });

  it("checks defined only by Security Hub control IDs without an Azure mapping stay unknown", () => {
    const mapping = getMappingById("L3-CES1-14")!;
    expect(mapping.azurePolicyDefinitionNames).toBeUndefined();
    expect(evaluateFullCheck(item("L3-CES1-14"), mapping, [defenderFinding("Activity log should be retained for at least one year")], defOk, "azure").status).toBe("unknown");
  });

  it("hybrid checks count non-aggregation module findings and filter Defender findings by name", () => {
    const mapping = getMappingById("L3-CES1-17")!; // network_reachability + security_hub_findings
    const netFinding: Finding = { ...defenderFinding("x"), module: "network_reachability", title: "NSG allows 0.0.0.0/0 on port 22", impact: "net" };
    const mods = [{ module: "network_reachability", status: "success" }, ...defOk];
    const ports = defenderFinding("Management ports should be closed on your virtual machines");
    const r = evaluateFullCheck(
      item("L3-CES1-17"),
      mapping,
      [netFinding, ports, defenderFinding("Key vaults should have purge protection enabled")],
      mods,
      "azure",
    );
    expect(r.status).toBe("issues");
    expect(r.relatedFindings.map((f) => f.title)).toEqual([netFinding.title, ports.title]);
  });
});

describe("report generators accept Azure results", () => {
  const azResult: FullScanResult = {
    scanStart: "2026-10-27T01:00:00.000Z",
    scanEnd: "2026-10-27T01:00:05.000Z",
    region: "all",
    accountId: TENANT,
    provider: "azure",
    modules: [
      {
        module: "defender_assessment_findings",
        status: "success",
        resourcesScanned: 10,
        findingsCount: 2,
        scanTimeMs: 50,
        findings: [
          defenderFinding("Management ports should be closed on your virtual machines", "vm-public"),
          defenderFinding("MFA should be enabled on accounts with owner permissions on your subscription", "sub"),
        ],
      },
      { module: "service_detection", status: "success", resourcesScanned: 4, findingsCount: 0, scanTimeMs: 10, findings: [] },
      {
        module: "config_rules_findings",
        status: "success",
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: 5,
        findings: [],
        warnings: [`Azure Policy Insights is not enabled for subscription ${SUB} (Microsoft.PolicyInsights not registered).`],
      },
      { module: "disk_encryption_findings", status: "success", resourcesScanned: 3, findingsCount: 0, scanTimeMs: 5, findings: [] },
    ],
    summary: { totalFindings: 2, critical: 0, high: 2, medium: 0, low: 0, modulesSuccess: 4, modulesError: 0 },
  };

  it("evaluateAllFullChecks uses Defender findings where Security Hub is expected", () => {
    const results = evaluateAllFullChecks(azResult);
    expect(results).toHaveLength(184);
    const mfa = results.find((r) => r.item.id === "L3-CES1-04")!;
    expect(mfa.status).toBe("issues");
    expect(mfa.relatedFindings[0].title).toContain("MFA should be enabled");
  });

  it("Markdown / MLPS / MLPS-HTML / HTML / AI prompt use Azure wording", () => {
    const md = generateMarkdownReport(azResult, "zh");
    expect(md).toContain("# Azure 安全扫描报告");
    expect(md).toContain(`/subscriptions/${SUB}/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-public`);
    expect(md).toContain("Defender for Cloud 安全建议");

    const mlps = generateMlps3Report(azResult, "zh");
    expect(mlps).toContain("L3-CES1-04");
    expect(mlps).toContain("Azure（世纪互联）负责机房物理安全");
    expect(mlps).not.toContain("AWS 负责机房物理安全");

    const mlpsHtml = generateMlps3HtmlReport(azResult, undefined, "zh");
    expect(mlpsHtml).toContain("Azure（世纪互联）负责机房物理安全");
    expect(mlpsHtml).not.toContain("AWS 负责机房物理安全");
    expect(mlpsHtml).toContain("由 Azure 平台负责");
    expect(mlpsHtml).toContain("Azure Policy"); // service reminder for Policy Insights

    const html = generateHtmlReport(azResult, undefined, "en");
    expect(html).toContain("Azure Security Scan Report");
    expect(html).not.toContain("AWS Security Scan Report");
    expect(html).toContain("Defender for Cloud Assessments");

    const prompt = buildAiSummaryPrompt("html", azResult, "en");
    expect(prompt).toContain("Azure Security Scan Report");
    expect(prompt).not.toContain("AWS security scan report");
    expect(buildAiSummaryPrompt("html", azResult, "zh")).toContain("Azure 安全扫描报告");
  });

  it("AWS / Alibaba Cloud MLPS output keeps its own wording", () => {
    const awsResult: FullScanResult = { ...azResult, provider: undefined, accountId: "123456789012", region: "cn-north-1", modules: [] };
    const md = generateMlps3Report(awsResult, "zh");
    expect(md).toContain("AWS 负责机房物理安全");
    expect(md).not.toContain("Azure");
    const ali = generateMlps3Report({ ...awsResult, provider: "alicloud" }, "zh");
    expect(ali).toContain("阿里云负责机房物理安全");
    expect(ali).not.toContain("世纪互联");
  });
});

describe("getRecommendationTemplate — Azure resource IDs", () => {
  it("collapses subscription / provider / tenant scoped IDs to {arn}", () => {
    expect(getRecommendationTemplate(`Restrict /subscriptions/${SUB}/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-1 now`))
      .toBe("Restrict {arn} now");
    expect(getRecommendationTemplate("Policy definition: /providers/Microsoft.Authorization/policyDefinitions/0000-fake"))
      .toBe("Policy definition: {arn}");
    expect(getRecommendationTemplate(`Review /tenants/${TENANT}/providers/Microsoft.Authorization/roleAssignments/x`)).toBe("Review {arn}");
  });

  it("leaves URLs and AWS / Alibaba strings unchanged", () => {
    expect(getRecommendationTemplate("See https://learn.microsoft.com/azure/providers/overview"))
      .toBe("See https://learn.microsoft.com/azure/providers/overview");
    expect(getRecommendationTemplate("Restrict arn:aws:s3:::my-bucket and acs:ram::123:user/a")).toBe("Restrict {arn} and {arn}");
  });
});
