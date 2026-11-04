import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { SecurityHubFindingsScanner } from "../../src/scanners/security-hub-findings.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("SecurityHubFindingsScanner", () => {
  const scanner = new SecurityHubFindingsScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns findings mapped from Security Hub with correct severity", async () => {
    mockSend.mockResolvedValueOnce({
      Findings: [
        {
          Id: "finding-1",
          Title: "S3.1 S3 Block Public Access setting should be enabled",
          Description: "S3 Block Public Access is not enabled",
          Severity: { Label: "CRITICAL" },
          Resources: [{ Id: "arn:aws:s3:::my-bucket", Type: "AwsS3Bucket" }],
          Remediation: {
            Recommendation: {
              Text: "Enable S3 Block Public Access",
              Url: "https://docs.aws.example",
            },
          },
          Region: "us-east-1",
          ProductName: "Security Hub",
          GeneratorId: "aws-foundational-security-best-practices/v/1.0.0/S3.1",
        },
        {
          Id: "finding-2",
          Title: "IAM.3 IAM users access keys should be rotated every 90 days",
          Description: "Access key has not been rotated",
          Severity: { Label: "MEDIUM" },
          Resources: [{ Id: "AKIA1234567890", Type: "AwsIamAccessKey" }],
          Region: "us-east-1",
          ProductName: "Security Hub",
          GeneratorId: "aws-foundational-security-best-practices/v/1.0.0/IAM.3",
        },
        {
          Id: "finding-3",
          Title: "Informational finding",
          Severity: { Label: "INFORMATIONAL" },
          Resources: [{ Id: "some-resource", Type: "AwsAccount" }],
        },
      ],
      NextToken: undefined,
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.module).toBe("security_hub_findings");
    // INFORMATIONAL should be skipped
    expect(result.findingsCount).toBe(2);
    expect(result.findings).toHaveLength(2);

    const critical = result.findings.find((f) => f.title.includes("S3.1"));
    expect(critical).toBeDefined();
    expect(critical!.severity).toBe("CRITICAL");
    expect(critical!.riskScore).toBe(9.5);
    expect(critical!.resourceArn).toBe("arn:aws:s3:::my-bucket");
    expect(critical!.remediationSteps).toContain("S3.1 S3 Block Public Access setting should be enabled");
    expect(critical!.remediationSteps).toContain("Documentation: https://docs.aws.example");

    const medium = result.findings.find((f) => f.title.includes("IAM.3"));
    expect(medium).toBeDefined();
    expect(medium!.severity).toBe("MEDIUM");
    expect(medium!.riskScore).toBe(5.5);
  });

  it("returns empty findings with warning when Security Hub is not enabled", async () => {
    const err = new Error("Security Hub is not enabled");
    err.name = "InvalidAccessException";
    mockSend.mockRejectedValue(err);

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("Security Hub is not enabled"))).toBe(true);
  });

  it("paginates through multiple pages of findings", async () => {
    mockSend
      .mockResolvedValueOnce({
        Findings: [
          {
            Id: "f1",
            Title: "Finding page 1",
            Severity: { Label: "HIGH" },
            Resources: [{ Id: "res-1", Type: "AwsEc2Instance" }],
            Region: "us-east-1",
          },
        ],
        NextToken: "page2",
      })
      .mockResolvedValueOnce({
        Findings: [
          {
            Id: "f2",
            Title: "Finding page 2",
            Severity: { Label: "LOW" },
            Resources: [{ Id: "res-2", Type: "AwsEc2Instance" }],
            Region: "us-east-1",
          },
        ],
        NextToken: undefined,
      });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(2);
    expect(mockSend).toHaveBeenCalledTimes(2);
  });
});

describe("SecurityHubFindingsScanner exploitability (Inspector CVEs)", () => {
  const scanner = new SecurityHubFindingsScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  function inspectorFinding(over: Record<string, unknown> = {}) {
    return {
      Id: "arn:aws:inspector2:us-east-1:123456789012:finding/abc",
      Title: "CVE-2026-31431 - kernel",
      Description: "kernel vuln",
      Severity: { Label: "HIGH" },
      Resources: [{ Id: "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc", Type: "AwsEc2Instance" }],
      Region: "us-east-1",
      ProductName: "Inspector",
      GeneratorId: "AWSInspector",
      Vulnerabilities: [{ Id: "CVE-2026-31431", ExploitAvailable: "YES", EpssScore: 0.02, FixAvailable: "YES" }],
      ...over,
    };
  }

  it("stores sourceFindingId = SH finding Id on every finding", async () => {
    mockSend.mockResolvedValueOnce({
      Findings: [
        { Id: "fsbp-1", Title: "S3.1", Severity: { Label: "HIGH" }, Resources: [{ Id: "arn:aws:s3:::b", Type: "AwsS3Bucket" }], ProductName: "Security Hub" },
        inspectorFinding(),
      ],
    });
    const result = await scanner.scan(ctx);
    expect(result.findings.map((f) => f.sourceFindingId)).toEqual([
      "fsbp-1",
      "arn:aws:inspector2:us-east-1:123456789012:finding/abc",
    ]);
  });

  it("computes exploitability from ASFF signals + KEV and bands riskScore", async () => {
    mockSend.mockResolvedValueOnce({ Findings: [inspectorFinding()] });
    const result = await scanner.scan(ctx);
    const f = result.findings[0];
    expect(f.source).toBe("Inspector");
    expect(f.severity).toBe("HIGH");
    expect(f.priority).toBe("P1"); // severity-derived, unchanged
    expect(f.exploitability).toMatchObject({
      cveId: "CVE-2026-31431",
      exploitAvailable: true,
      epss: 0.02,
      epssLevel: "medium",
      kev: true,
      fixAvailable: "YES",
      reachability: "unknown",
      priority: "P0",
      rationaleCode: "KEV",
      originalRiskScore: 8.0,
      dataSource: "securityhub",
    });
    expect(f.riskScore).toBe(9.8); // 9.0 + 8.0/10
  });

  it("maps missing ASFF signals to null/none and non-KEV to baseline", async () => {
    mockSend.mockResolvedValueOnce({
      Findings: [inspectorFinding({
        Title: "CVE-2026-43284 - libfoo",
        Severity: { Label: "CRITICAL" },
        Vulnerabilities: [{ Id: "CVE-2026-43284" }],
      })],
    });
    const result = await scanner.scan(ctx);
    const f = result.findings[0];
    expect(f.severity).toBe("CRITICAL");
    expect(f.exploitability).toMatchObject({ exploitAvailable: null, epss: null, epssLevel: "none", kev: false, priority: "P3" });
    expect(f.exploitability!.fixAvailable).toBeUndefined();
    expect(f.riskScore).toBe(3.7); // 0.1 + 9.5/10*3.8
  });

  it("leaves non-Inspector and non-CVE findings without exploitability and riskScore unchanged", async () => {
    mockSend.mockResolvedValueOnce({
      Findings: [
        // Non-Inspector product carrying a CVE vulnerability → untouched.
        inspectorFinding({ Id: "gd-1", ProductName: "GuardDuty" }),
        // Inspector but non-CVE vulnerability ID → untouched.
        inspectorFinding({ Id: "ins-ghsa", Vulnerabilities: [{ Id: "GHSA-xxxx-yyyy", ExploitAvailable: "YES" }] }),
        // Inspector without Vulnerabilities → untouched.
        inspectorFinding({ Id: "ins-none", Vulnerabilities: undefined }),
      ],
    });
    const result = await scanner.scan(ctx);
    expect(result.findings).toHaveLength(3);
    for (const f of result.findings) {
      expect(f.exploitability).toBeUndefined();
      expect(f.riskScore).toBe(8.0);
    }
  });
});
