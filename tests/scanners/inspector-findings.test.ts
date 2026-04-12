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

describe("InspectorFindingsScanner (detection-only)", () => {
  const scanner = new InspectorFindingsScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns 0 findings when Inspector is fully enabled", async () => {
    mockSend.mockResolvedValueOnce({
      accounts: [{
        accountId: "123456789012",
        state: { status: "ENABLED" },
        resourceState: {
          ec2: { status: "ENABLED" },
          ecr: { status: "ENABLED" },
          lambda: { status: "ENABLED" },
          lambdaCode: { status: "ENABLED" },
          codeRepository: { status: "ENABLED" },
        },
      }],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.module).toBe("inspector_findings");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings).toBeUndefined();
  });

  it("warns when Inspector is not enabled", async () => {
    mockSend.mockResolvedValueOnce({
      accounts: [{
        accountId: "123456789012",
        state: { status: "DISABLED" },
      }],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("Inspector is not enabled"))).toBe(true);
  });

  it("warns about disabled scan types (ecr, lambdaCode)", async () => {
    mockSend.mockResolvedValueOnce({
      accounts: [{
        accountId: "123456789012",
        state: { status: "ENABLED" },
        resourceState: {
          ec2: { status: "ENABLED" },
          ecr: { status: "DISABLED" },
          lambda: { status: "ENABLED" },
          lambdaCode: { status: "DISABLED" },
          codeRepository: { status: "ENABLED" },
        },
      }],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings![0]).toContain("ECR");
    expect(result.warnings![0]).toContain("Lambda Code");
  });

  it("returns success with warning on AccessDeniedException", async () => {
    const err = new Error("User is not authorized to perform inspector2:BatchGetAccountStatus");
    err.name = "AccessDeniedException";
    mockSend.mockRejectedValue(err);

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("Insufficient permissions"))).toBe(true);
  });

  it("returns success with warning when Inspector is not enabled (error path)", async () => {
    mockSend.mockRejectedValue(new Error("Inspector is not enabled in this account"));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings!.some((w) => w.includes("Inspector is not enabled"))).toBe(true);
  });
});
