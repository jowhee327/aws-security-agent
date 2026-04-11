import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { ConfigRulesFindingsScanner } from "../../src/scanners/config-rules-findings.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("ConfigRulesFindingsScanner", () => {
  const scanner = new ConfigRulesFindingsScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns findings for non-compliant Config Rules", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeComplianceByConfigRuleCommand":
          return {
            ComplianceByConfigRules: [
              {
                ConfigRuleName: "s3-bucket-encryption-enabled",
                Compliance: { ComplianceType: "NON_COMPLIANT" },
              },
              {
                ConfigRuleName: "required-tags",
                Compliance: { ComplianceType: "COMPLIANT" },
              },
            ],
          };
        case "GetComplianceDetailsByConfigRuleCommand":
          return {
            EvaluationResults: [
              {
                EvaluationResultIdentifier: {
                  EvaluationResultQualifier: {
                    ConfigRuleName: "s3-bucket-encryption-enabled",
                    ResourceType: "AWS::S3::Bucket",
                    ResourceId: "my-bucket",
                  },
                },
                ComplianceType: "NON_COMPLIANT",
                Annotation: "Encryption not enabled",
              },
            ],
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.module).toBe("config_rules_findings");
    expect(result.resourcesScanned).toBe(2);
    expect(result.findingsCount).toBe(1);

    const finding = result.findings[0];
    expect(finding.title).toBe("Config Rule: s3-bucket-encryption-enabled - AWS::S3::Bucket/my-bucket Non-Compliant");
    expect(finding.severity).toBe("HIGH"); // encryption is security-related
    expect(finding.riskScore).toBe(7.5);
    expect(finding.resourceId).toBe("my-bucket");
    expect(finding.resourceArn).toBe("my-bucket");
    expect(finding.description).toContain("Encryption not enabled");
  });

  it("returns success with warning when Config is not enabled", async () => {
    mockSend.mockRejectedValue(
      Object.assign(new Error("No Configuration Recorder was found"), {
        name: "NoSuchConfigurationRecorderException",
      }),
    );

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("Config is not enabled"))).toBe(true);
  });

  it("returns no findings when all rules are compliant", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      if (cmd.constructor.name === "DescribeComplianceByConfigRuleCommand") {
        return {
          ComplianceByConfigRules: [
            {
              ConfigRuleName: "s3-bucket-encryption-enabled",
              Compliance: { ComplianceType: "COMPLIANT" },
            },
            {
              ConfigRuleName: "ec2-instance-no-public-ip",
              Compliance: { ComplianceType: "COMPLIANT" },
            },
          ],
        };
      }
      return {};
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.resourcesScanned).toBe(2);
  });

  it("maps non-security rules to MEDIUM severity", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeComplianceByConfigRuleCommand":
          return {
            ComplianceByConfigRules: [
              {
                ConfigRuleName: "required-tags",
                Compliance: { ComplianceType: "NON_COMPLIANT" },
              },
            ],
          };
        case "GetComplianceDetailsByConfigRuleCommand":
          return {
            EvaluationResults: [
              {
                EvaluationResultIdentifier: {
                  EvaluationResultQualifier: {
                    ConfigRuleName: "required-tags",
                    ResourceType: "AWS::EC2::Instance",
                    ResourceId: "i-1234567890abcdef0",
                  },
                },
                ComplianceType: "NON_COMPLIANT",
              },
            ],
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].severity).toBe("MEDIUM");
    expect(result.findings[0].riskScore).toBe(5.5);
  });
});
