/** T8 — provider-aware i18n: AWS tables untouched, Huawei Cloud overrides only where "AWS" would be wrong. */
import { describe, it, expect } from "vitest";
import { getI18n, providerName } from "../src/i18n/index.js";
import { zhI18n } from "../src/i18n/zh.js";
import { enI18n } from "../src/i18n/en.js";

describe("getI18n(lang, provider)", () => {
  it("returns the very same AWS table when provider is omitted or aws", () => {
    expect(getI18n("zh")).toBe(zhI18n);
    expect(getI18n("zh", "aws")).toBe(zhI18n);
    expect(getI18n("zh", undefined)).toBe(zhI18n);
    expect(getI18n("en")).toBe(enI18n);
    expect(getI18n("en", "aws")).toBe(enI18n);
    expect(zhI18n.securityReportTitle).toBe("AWS 安全扫描报告");
    expect(enI18n.securityReportTitle).toBe("AWS Security Scan Report");
  });

  it("derives Huawei Cloud labels without mutating the AWS table", () => {
    const zh = getI18n("zh", "huaweicloud");
    const en = getI18n("en", "huaweicloud");
    expect(zh).not.toBe(zhI18n);
    expect(zh.securityReportTitle).toBe("华为云安全扫描报告");
    expect(en.securityReportTitle).toBe("Huawei Cloud Security Scan Report");
    expect(zh.cloudItemsNote(3)).toContain("华为云");
    expect(zh.cloudItemsNote(3)).not.toContain("AWS");
    expect(en.cloudItemsNote(3)).toContain("Huawei Cloud platform");
    expect(zh.serviceRecommendations.config_rules_findings.service).toContain("RMS");
    expect(en.serviceRecommendations.config_rules_findings.action).toContain("RMS");
    // T9: HSS replaces Inspector / SSM Patch Manager in the "service not enabled" recommendations.
    expect(zh.serviceRecommendations.inspector_findings.service).toContain("HSS");
    expect(en.serviceRecommendations.inspector_findings.service).toContain("HSS");
    expect(zh.serviceRecommendations.patch_compliance_findings.service).toContain("HSS");
    expect(en.serviceRecommendations.patch_compliance_findings.action).toContain("HSS");
    expect(zhI18n.serviceRecommendations.inspector_findings.service).toBe("Inspector");
    expect(enI18n.serviceRecommendations.patch_compliance_findings.service).toBe("SSM Patch Manager");
    // Untouched entries are shared with the AWS table.
    expect(zh.moduleNames).toBe(zhI18n.moduleNames);
    expect(zh.serviceRecommendations.guardduty_findings).toBe(zhI18n.serviceRecommendations.guardduty_findings);
    expect(zh.generatedBy).toBe(zhI18n.generatedBy); // product name is kept
    // AWS table not mutated
    expect(zhI18n.securityReportTitle).toBe("AWS 安全扫描报告");
    expect(zhI18n.serviceRecommendations.config_rules_findings.service).toBe("AWS Config");
    // Cached
    expect(getI18n("zh", "huaweicloud")).toBe(zh);
  });

  it("providerName", () => {
    expect(providerName(undefined)).toBe("AWS");
    expect(providerName("aws", "en")).toBe("AWS");
    expect(providerName("huaweicloud", "zh")).toBe("华为云");
    expect(providerName("huaweicloud", "en")).toBe("Huawei Cloud");
  });
});
