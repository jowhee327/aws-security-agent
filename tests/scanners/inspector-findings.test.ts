import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { InspectorFindingsScanner } from "../../src/scanners/inspector-findings.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("InspectorFindingsScanner", () => {
  const scanner = new InspectorFindingsScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns findings with CVE IDs in titles", async () => {
    mockSend.mockResolvedValueOnce({
      findings: [
        {
          findingArn: "arn:aws:inspector2:us-east-1:123456789012:finding/f1",
          title: "Kernel vulnerability in amazon linux 2",
          description: "A critical vulnerability exists in the Linux kernel",
          severity: "CRITICAL",
          type: "PACKAGE_VULNERABILITY",
          resources: [
            {
              id: "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
              type: "AWS_EC2_INSTANCE",
            },
          ],
          packageVulnerabilityDetails: {
            vulnerabilityId: "CVE-2024-1234",
            cvss: [{ baseScore: 9.8 }],
            referenceUrls: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
          },
          remediation: {
            recommendation: {
              text: "Update the kernel to the latest version",
            },
          },
        },
        {
          findingArn: "arn:aws:inspector2:us-east-1:123456789012:finding/f2",
          title: "OpenSSL vulnerability",
          description: "Medium-severity OpenSSL issue",
          severity: "MEDIUM",
          type: "PACKAGE_VULNERABILITY",
          resources: [
            {
              id: "arn:aws:lambda:us-east-1:123456789012:function:my-func",
              type: "AWS_LAMBDA_FUNCTION",
            },
          ],
          packageVulnerabilityDetails: {
            vulnerabilityId: "CVE-2024-5678",
            referenceUrls: [],
          },
        },
        {
          findingArn: "arn:aws:inspector2:us-east-1:123456789012:finding/f3",
          title: "Info finding",
          severity: "INFORMATIONAL",
          type: "PACKAGE_VULNERABILITY",
          resources: [{ id: "some-resource", type: "AWS_EC2_INSTANCE" }],
        },
      ],
      nextToken: undefined,
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.module).toBe("inspector_findings");
    // INFORMATIONAL should be skipped
    expect(result.findingsCount).toBe(2);

    const critical = result.findings.find((f) => f.title.includes("CVE-2024-1234"));
    expect(critical).toBeDefined();
    expect(critical!.severity).toBe("CRITICAL");
    expect(critical!.riskScore).toBe(9.5);
    expect(critical!.title).toContain("[CVE-2024-1234]");
    expect(critical!.remediationSteps).toContain("Update the kernel to the latest version");

    const medium = result.findings.find((f) => f.title.includes("CVE-2024-5678"));
    expect(medium).toBeDefined();
    expect(medium!.severity).toBe("MEDIUM");
  });

  it("returns empty findings with warning when Inspector is not enabled", async () => {
    const err = new Error("Inspector is not enabled in this account");
    err.name = "ValidationException";
    mockSend.mockRejectedValue(err);

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("Inspector is not enabled"))).toBe(true);
  });

  it("returns warning for AccessDeniedException (insufficient permissions)", async () => {
    const err = new Error("User is not authorized to perform inspector2:ListFindings");
    err.name = "AccessDeniedException";
    mockSend.mockRejectedValue(err);

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("Insufficient permissions"))).toBe(true);
  });

  it("paginates through findings", async () => {
    mockSend
      .mockResolvedValueOnce({
        findings: [
          {
            findingArn: "f1",
            title: "Finding 1",
            severity: "HIGH",
            type: "PACKAGE_VULNERABILITY",
            resources: [{ id: "r1", type: "AWS_EC2_INSTANCE" }],
          },
        ],
        nextToken: "page2",
      })
      .mockResolvedValueOnce({
        findings: [
          {
            findingArn: "f2",
            title: "Finding 2",
            severity: "LOW",
            type: "PACKAGE_VULNERABILITY",
            resources: [{ id: "r2", type: "AWS_EC2_INSTANCE" }],
          },
        ],
        nextToken: undefined,
      });

    const result = await scanner.scan(ctx);

    expect(result.findingsCount).toBe(2);
    expect(mockSend).toHaveBeenCalledTimes(2);
  });
});
