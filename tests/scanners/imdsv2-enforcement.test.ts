import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { Imdsv2EnforcementScanner } from "../../src/scanners/imdsv2-enforcement.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("Imdsv2EnforcementScanner", () => {
  const scanner = new Imdsv2EnforcementScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns HIGH finding for instance not enforcing IMDSv2", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeInstancesCommand":
          return {
            Reservations: [
              {
                Instances: [
                  {
                    InstanceId: "i-abc123",
                    InstanceType: "t3.micro",
                    State: { Name: "running" },
                    MetadataOptions: {
                      HttpTokens: "optional",
                      HttpPutResponseHopLimit: 1,
                    },
                  },
                ],
              },
            ],
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(1);
    expect(result.findingsCount).toBe(1);
    const finding = result.findings[0];
    expect(finding.severity).toBe("HIGH");
    expect(finding.riskScore).toBe(7.5);
    expect(finding.title).toContain("i-abc123");
    expect(finding.title).toContain("does not enforce IMDSv2");
    expect(finding.impact).toContain("SSRF");
  });

  it("returns no findings when all instances enforce IMDSv2", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeInstancesCommand":
          return {
            Reservations: [
              {
                Instances: [
                  {
                    InstanceId: "i-good1",
                    InstanceType: "t3.large",
                    State: { Name: "running" },
                    MetadataOptions: {
                      HttpTokens: "required",
                      HttpPutResponseHopLimit: 1,
                    },
                  },
                  {
                    InstanceId: "i-good2",
                    InstanceType: "m5.xlarge",
                    State: { Name: "running" },
                    MetadataOptions: {
                      HttpTokens: "required",
                      HttpPutResponseHopLimit: 1,
                    },
                  },
                ],
              },
            ],
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(2);
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toEqual([]);
  });

  it("returns error status on service error", async () => {
    mockSend.mockRejectedValue(new Error("EC2 DescribeInstances access denied"));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("error");
    expect(result.error).toContain("access denied");
    expect(result.findingsCount).toBe(0);
  });

  it("includes hop limit warning in description when > 1", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeInstancesCommand":
          return {
            Reservations: [
              {
                Instances: [
                  {
                    InstanceId: "i-container1",
                    InstanceType: "t3.medium",
                    State: { Name: "running" },
                    MetadataOptions: {
                      HttpTokens: "optional",
                      HttpPutResponseHopLimit: 2,
                    },
                  },
                ],
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
    expect(result.findings[0].description).toContain("HttpPutResponseHopLimit is 2");
  });
});
