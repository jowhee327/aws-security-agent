import { describe, it, expect } from "vitest";
import { applyFindingsFilter } from "../../src/tools/scan-groups.js";
import type { Finding } from "../../src/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "MEDIUM",
    title: "Test Finding",
    resourceType: "AWS::Test",
    resourceId: "r-1",
    resourceArn: "arn:aws:test::r-1",
    region: "us-east-1",
    description: "Test description",
    impact: "Test impact",
    riskScore: 5.5,
    remediationSteps: ["fix it"],
    priority: "P2",
    ...overrides,
  };
}

describe("applyFindingsFilter", () => {
  describe("securityHubCategories", () => {
    it("filters Security Hub findings by keyword in title", () => {
      const findings = [
        makeFinding({ title: "S3 Encryption not enabled", module: "security_hub_findings" }),
        makeFinding({ title: "IAM user without MFA", module: "security_hub_findings" }),
        makeFinding({ title: "VPC flow logs", module: "security_hub_findings" }),
      ];

      const result = applyFindingsFilter("security_hub_findings", findings, {
        securityHubCategories: ["encryption"],
      });

      expect(result).toHaveLength(1);
      expect(result[0].title).toContain("Encryption");
    });

    it("matches keywords case-insensitively", () => {
      const findings = [
        makeFinding({ title: "S3 ENCRYPTION check", module: "security_hub_findings" }),
      ];

      const result = applyFindingsFilter("security_hub_findings", findings, {
        securityHubCategories: ["encryption"],
      });

      expect(result).toHaveLength(1);
    });

    it("matches in description and impact fields too", () => {
      const findings = [
        makeFinding({ description: "Check IAM access controls", module: "security_hub_findings" }),
        makeFinding({ impact: "Source: IAM Analyzer (generator)", module: "security_hub_findings" }),
      ];

      const result = applyFindingsFilter("security_hub_findings", findings, {
        securityHubCategories: ["IAM"],
      });

      expect(result).toHaveLength(2);
    });

    it("does not filter non-Security Hub modules", () => {
      const findings = [
        makeFinding({ title: "Unrelated finding", module: "ssl_certificate" }),
      ];

      const result = applyFindingsFilter("ssl_certificate", findings, {
        securityHubCategories: ["encryption"],
      });

      // Should not be filtered — wrong module
      expect(result).toHaveLength(1);
    });
  });

  describe("guardDutyTypes", () => {
    it("filters GuardDuty findings by type prefix in impact", () => {
      const findings = [
        makeFinding({ impact: "GuardDuty threat type: Backdoor:EC2/DenialOfService.Dns (severity 8)" }),
        makeFinding({ impact: "GuardDuty threat type: Recon:EC2/PortScan (severity 5)" }),
        makeFinding({ impact: "GuardDuty threat type: CryptoCurrency:EC2/BitcoinTool (severity 3)" }),
      ];

      const result = applyFindingsFilter("guardduty_findings", findings, {
        guardDutyTypes: ["Backdoor", "CryptoCurrency"],
      });

      expect(result).toHaveLength(2);
    });
  });

  describe("minSeverity", () => {
    it("filters findings below minimum severity", () => {
      const findings = [
        makeFinding({ severity: "CRITICAL" }),
        makeFinding({ severity: "HIGH" }),
        makeFinding({ severity: "MEDIUM" }),
        makeFinding({ severity: "LOW" }),
      ];

      const result = applyFindingsFilter("security_hub_findings", findings, {
        minSeverity: "MEDIUM",
      });

      expect(result).toHaveLength(3); // CRITICAL, HIGH, MEDIUM
      expect(result.every((f) => f.severity !== "LOW")).toBe(true);
    });

    it("returns all findings when minSeverity is LOW", () => {
      const findings = [
        makeFinding({ severity: "LOW" }),
        makeFinding({ severity: "MEDIUM" }),
      ];

      const result = applyFindingsFilter("any_module", findings, {
        minSeverity: "LOW",
      });

      expect(result).toHaveLength(2);
    });
  });

  describe("combined filters", () => {
    it("applies both category and severity filters", () => {
      const findings = [
        makeFinding({ severity: "HIGH", title: "IAM admin access", module: "security_hub_findings" }),
        makeFinding({ severity: "LOW", title: "IAM unused key", module: "security_hub_findings" }),
        makeFinding({ severity: "HIGH", title: "S3 public bucket", module: "security_hub_findings" }),
      ];

      const result = applyFindingsFilter("security_hub_findings", findings, {
        securityHubCategories: ["IAM"],
        minSeverity: "MEDIUM",
      });

      expect(result).toHaveLength(1);
      expect(result[0].title).toContain("IAM admin");
    });
  });

  describe("empty filter", () => {
    it("returns all findings when no filter criteria specified", () => {
      const findings = [makeFinding(), makeFinding()];

      const result = applyFindingsFilter("any_module", findings, {});

      expect(result).toHaveLength(2);
    });
  });
});
