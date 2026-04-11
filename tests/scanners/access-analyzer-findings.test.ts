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

  it("returns findings from active Access Analyzer", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListAnalyzersCommand":
          return {
            analyzers: [
              {
                arn: "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/my-analyzer",
                name: "my-analyzer",
                type: "ACCOUNT",
                status: "ACTIVE",
              },
            ],
          };
        case "ListFindingsV2Command":
          return {
            findings: [
              {
                resource: "arn:aws:s3:::my-public-bucket",
                resourceType: "AWS::S3::Bucket",
                resourceOwnerAccount: "123456789012",
                findingType: "HIGH",
                status: "ACTIVE",
              },
              {
                resource: "arn:aws:iam::123456789012:role/cross-account-role",
                resourceType: "AWS::IAM::Role",
                resourceOwnerAccount: "123456789012",
                findingType: "LOW",
                status: "ACTIVE",
              },
            ],
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.module).toBe("access_analyzer_findings");
    expect(result.resourcesScanned).toBe(2);
    expect(result.findingsCount).toBe(2);

    // HIGH finding
    const highFinding = result.findings.find((f) => f.resourceArn.includes("my-public-bucket"));
    expect(highFinding).toBeDefined();
    expect(highFinding!.severity).toBe("HIGH");
    expect(highFinding!.riskScore).toBe(8.0);
    expect(highFinding!.title).toContain("Access Analyzer");
    expect(highFinding!.title).toContain("my-public-bucket");

    // LOW finding
    const lowFinding = result.findings.find((f) => f.resourceArn.includes("cross-account-role"));
    expect(lowFinding).toBeDefined();
    expect(lowFinding!.severity).toBe("LOW");
    expect(lowFinding!.riskScore).toBe(3.0);
  });

  it("returns success with warning when no analyzers exist", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      if (cmd.constructor.name === "ListAnalyzersCommand") {
        return { analyzers: [] };
      }
      return {};
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("No IAM Access Analyzer found"))).toBe(true);
  });

  it("returns no findings when analyzer has no active findings", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListAnalyzersCommand":
          return {
            analyzers: [
              {
                arn: "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/my-analyzer",
                name: "my-analyzer",
                type: "ACCOUNT",
                status: "ACTIVE",
              },
            ],
          };
        case "ListFindingsV2Command":
          return { findings: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("returns error status on exception", async () => {
    mockSend.mockRejectedValue(new Error("Access Denied"));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("error");
    expect(result.error).toContain("Access Denied");
  });
});
