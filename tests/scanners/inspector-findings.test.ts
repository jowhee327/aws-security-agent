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

  it("returns 0 findings when no active Inspector findings exist", async () => {
    mockSend.mockResolvedValueOnce({ findings: [] });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.module).toBe("inspector_findings");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("returns findings for active Inspector vulnerabilities", async () => {
    mockSend.mockResolvedValueOnce({
      findings: [{
        severity: "HIGH",
        title: "CVE-2024-1234 test vulnerability",
        findingArn: "arn:aws:inspector2:us-east-1:123456789012:finding/f-1",
        resources: [{ id: "i-abc123", type: "AWS::EC2::Instance" }],
        packageVulnerabilityDetails: {
          vulnerabilityId: "CVE-2024-1234",
          vulnerablePackages: [{ name: "openssl", version: "1.1.1", fixedInVersion: "1.1.2" }],
        },
        awsAccountId: "123456789012",
      }],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].title).toContain("CVE-2024-1234");
    expect(result.findings[0].remediationSteps[0]).toContain("openssl");
  });

  it("returns empty findings with warning when Inspector is not enabled (error path)", async () => {
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

  it("returns error on unexpected failure", async () => {
    mockSend.mockRejectedValue(new Error("Service unavailable"));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("error");
    expect(result.error).toContain("Service unavailable");
    expect(result.findingsCount).toBe(0);
  });
});
