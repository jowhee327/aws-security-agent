import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: vi.fn() })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));

import { runAllScanners } from "../src/scanners/runner.js";
import type { Scanner } from "../src/scanners/base.js";
import type { ScanResult, ScanContext } from "../src/types.js";

function createMockScanner(name: string, result: ScanResult): Scanner {
  return {
    moduleName: name,
    scan: vi.fn().mockResolvedValue(result),
  };
}

describe("runAllScanners", () => {
  it("aggregates summary counts correctly", async () => {
    const scanners: Scanner[] = [
      createMockScanner("mod_a", {
        module: "mod_a",
        status: "success",
        resourcesScanned: 5,
        findingsCount: 2,
        scanTimeMs: 100,
        findings: [
          {
            severity: "CRITICAL",
            title: "Critical Issue",
            resourceType: "AWS::Test",
            resourceId: "r-1",
            resourceArn: "arn:aws:test::r-1",
            region: "us-east-1",
            description: "test",
            impact: "test",
            riskScore: 9.5,
            remediationSteps: ["fix it"],
            priority: "P0",
          },
          {
            severity: "LOW",
            title: "Low Issue",
            resourceType: "AWS::Test",
            resourceId: "r-2",
            resourceArn: "arn:aws:test::r-2",
            region: "us-east-1",
            description: "test",
            impact: "test",
            riskScore: 2.0,
            remediationSteps: ["note it"],
            priority: "P3",
          },
        ],
      }),
      createMockScanner("mod_b", {
        module: "mod_b",
        status: "success",
        resourcesScanned: 3,
        findingsCount: 1,
        scanTimeMs: 50,
        findings: [
          {
            severity: "HIGH",
            title: "High Issue",
            resourceType: "AWS::Test",
            resourceId: "r-3",
            resourceArn: "arn:aws:test::r-3",
            region: "us-east-1",
            description: "test",
            impact: "test",
            riskScore: 7.5,
            remediationSteps: ["remediate"],
            priority: "P1",
          },
        ],
      }),
    ];

    const result = await runAllScanners(scanners, "us-east-1");

    expect(result.accountId).toBe("123456789012");
    expect(result.region).toBe("us-east-1");
    expect(result.modules).toHaveLength(2);
    expect(result.summary.totalFindings).toBe(3);
    expect(result.summary.critical).toBe(1);
    expect(result.summary.high).toBe(1);
    expect(result.summary.low).toBe(1);
    expect(result.summary.modulesSuccess).toBe(2);
    expect(result.summary.modulesError).toBe(0);

    // Verify scanners received ScanContext
    const mockScan = scanners[0].scan as ReturnType<typeof vi.fn>;
    expect(mockScan).toHaveBeenCalledWith({
      region: "us-east-1",
      partition: "aws",
      accountId: "123456789012",
    });
  });

  it("handles scanner that throws with error status", async () => {
    const scanners: Scanner[] = [
      {
        moduleName: "failing_mod",
        scan: vi.fn().mockRejectedValue(new Error("AWS timeout")),
      },
    ];

    const result = await runAllScanners(scanners, "us-east-1");

    expect(result.modules).toHaveLength(1);
    expect(result.modules[0].status).toBe("error");
    expect(result.modules[0].error).toBe("AWS timeout");
    expect(result.summary.modulesError).toBe(1);
    expect(result.summary.modulesSuccess).toBe(0);
  });

  it("falls back to 'unknown' accountId when STS fails", async () => {
    const { getAccountId } = await import("../src/utils/aws-client.js");
    (getAccountId as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error("STS error"));

    const scanners: Scanner[] = [
      createMockScanner("mod_a", {
        module: "mod_a",
        status: "success",
        resourcesScanned: 1,
        findingsCount: 0,
        scanTimeMs: 10,
        findings: [],
      }),
    ];

    const result = await runAllScanners(scanners, "us-east-1");
    expect(result.accountId).toBe("unknown");
    expect(result.modules[0].status).toBe("success");
  });
});
