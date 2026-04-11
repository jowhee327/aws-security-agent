import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { GuardDutyFindingsScanner } from "../../src/scanners/guardduty-findings.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("GuardDutyFindingsScanner", () => {
  const scanner = new GuardDutyFindingsScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns findings from GuardDuty with correct severity mapping", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListDetectorsCommand":
          return { DetectorIds: ["detector-1"] };
        case "ListFindingsCommand":
          return { FindingIds: ["gd-finding-1", "gd-finding-2"] };
        case "GetFindingsCommand":
          return {
            Findings: [
              {
                Id: "gd-finding-1",
                Title: "Unusual API call from known malicious IP",
                Description: "EC2 instance contacted a known malicious IP",
                Type: "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
                Severity: 8.0,
                Region: "us-east-1",
                Arn: "arn:aws:guardduty:us-east-1:123456789012:detector/detector-1/finding/gd-finding-1",
                Resource: {
                  ResourceType: "Instance",
                  InstanceDetails: { InstanceId: "i-1234567890abcdef0" },
                },
              },
              {
                Id: "gd-finding-2",
                Title: "DNS query to Bitcoin mining pool",
                Description: "EC2 instance queried a bitcoin mining domain",
                Type: "CryptoCurrency:EC2/BitcoinTool.B!DNS",
                Severity: 2.0,
                Region: "us-east-1",
                Arn: "arn:aws:guardduty:us-east-1:123456789012:detector/detector-1/finding/gd-finding-2",
                Resource: {
                  ResourceType: "Instance",
                  InstanceDetails: { InstanceId: "i-abcdef1234567890" },
                },
              },
            ],
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.module).toBe("guardduty_findings");
    expect(result.findingsCount).toBe(2);

    // High severity (8.0 >= 7.0)
    const high = result.findings.find((f) => f.title.includes("Unusual API call"));
    expect(high).toBeDefined();
    expect(high!.severity).toBe("HIGH");
    expect(high!.riskScore).toBe(8.0);
    expect(high!.resourceId).toBe("i-1234567890abcdef0");

    // Low severity (2.0 < 4.0)
    const low = result.findings.find((f) => f.title.includes("Bitcoin"));
    expect(low).toBeDefined();
    expect(low!.severity).toBe("LOW");
    expect(low!.riskScore).toBe(3.0);
  });

  it("returns empty findings with warning when no detectors exist", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      if (cmd.constructor.name === "ListDetectorsCommand") {
        return { DetectorIds: [] };
      }
      return {};
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("GuardDuty is not enabled"))).toBe(true);
  });

  it("returns empty findings when no active findings", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListDetectorsCommand":
          return { DetectorIds: ["detector-1"] };
        case "ListFindingsCommand":
          return { FindingIds: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
  });
});
