import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { AccessAnalyzerFindingsScanner } from "../../src/scanners/access-analyzer-findings.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("AccessAnalyzerFindingsScanner", () => {
  const scanner = new AccessAnalyzerFindingsScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns 0 findings when analyzer is active but no findings", async () => {
    // ListAnalyzers
    mockSend.mockResolvedValueOnce({
      analyzers: [
        {
          arn: "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/my-analyzer",
          name: "my-analyzer",
          type: "ACCOUNT",
          status: "ACTIVE",
        },
      ],
    });
    // ListFindingsV2
    mockSend.mockResolvedValueOnce({ findings: [] });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.module).toBe("access_analyzer_findings");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("reports no analyzer when none exist", async () => {
    mockSend.mockResolvedValueOnce({ analyzers: [] });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("No IAM Access Analyzer found"))).toBe(true);
  });

  it("skips inactive analyzers", async () => {
    mockSend.mockResolvedValueOnce({
      analyzers: [
        {
          arn: "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/old-analyzer",
          name: "old-analyzer",
          type: "ACCOUNT",
          status: "CREATING",
        },
      ],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings!.some((w) => w.includes("No IAM Access Analyzer found"))).toBe(true);
  });

  it("returns error status on exception", async () => {
    mockSend.mockRejectedValue(new Error("Access Denied"));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("error");
    expect(result.error).toContain("Access Denied");
    expect(result.findingsCount).toBe(0);
  });
});
