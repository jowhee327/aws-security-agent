import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { PatchComplianceFindingsScanner } from "../../src/scanners/patch-compliance-findings.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("PatchComplianceFindingsScanner", () => {
  const scanner = new PatchComplianceFindingsScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns findings for instances with missing patches", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeInstanceInformationCommand":
          return {
            InstanceInformationList: [
              {
                InstanceId: "i-1234567890abcdef0",
                PlatformName: "Amazon Linux 2",
                PlatformType: "Linux",
              },
              {
                InstanceId: "i-abcdef1234567890",
                PlatformName: "Windows Server 2022",
                PlatformType: "Windows",
              },
            ],
          };
        case "DescribeInstancePatchStatesCommand":
          return {
            InstancePatchStates: [
              {
                InstanceId: "i-1234567890abcdef0",
                MissingCount: 3,
                FailedCount: 0,
                SecurityNonCompliantCount: 2,
                OperationEndTime: new Date("2026-04-10T12:00:00Z"),
              },
              {
                InstanceId: "i-abcdef1234567890",
                MissingCount: 1,
                FailedCount: 1,
                SecurityNonCompliantCount: 0,
                OperationEndTime: new Date("2026-04-10T14:00:00Z"),
              },
            ],
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.module).toBe("patch_compliance_findings");
    expect(result.resourcesScanned).toBe(2);
    expect(result.findingsCount).toBe(2);

    // Instance with security non-compliant patches → HIGH
    const linux = result.findings.find((f) => f.resourceId === "i-1234567890abcdef0");
    expect(linux).toBeDefined();
    expect(linux!.severity).toBe("HIGH");
    expect(linux!.riskScore).toBe(7.5);
    expect(linux!.title).toContain("3 missing");
    expect(linux!.description).toContain("Amazon Linux 2");

    // Instance with failed patches → HIGH
    const windows = result.findings.find((f) => f.resourceId === "i-abcdef1234567890");
    expect(windows).toBeDefined();
    expect(windows!.severity).toBe("HIGH");
    expect(windows!.title).toContain("1 missing");
    expect(windows!.title).toContain("1 failed");
  });

  it("returns success with warning when no managed instances found", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      if (cmd.constructor.name === "DescribeInstanceInformationCommand") {
        return { InstanceInformationList: [] };
      }
      return {};
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("No SSM-managed instances"))).toBe(true);
  });

  it("returns no findings when all instances are fully patched", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeInstanceInformationCommand":
          return {
            InstanceInformationList: [
              { InstanceId: "i-1234567890abcdef0", PlatformType: "Linux" },
            ],
          };
        case "DescribeInstancePatchStatesCommand":
          return {
            InstancePatchStates: [
              {
                InstanceId: "i-1234567890abcdef0",
                MissingCount: 0,
                FailedCount: 0,
                SecurityNonCompliantCount: 0,
                OperationEndTime: new Date("2026-04-10T12:00:00Z"),
              },
            ],
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("flags instances without patch data as LOW", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeInstanceInformationCommand":
          return {
            InstanceInformationList: [
              { InstanceId: "i-nopatch", PlatformName: "Ubuntu", PlatformType: "Linux" },
            ],
          };
        case "DescribeInstancePatchStatesCommand":
          return { InstancePatchStates: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].severity).toBe("LOW");
    expect(result.findings[0].title).toContain("no patch compliance data");
  });
});
