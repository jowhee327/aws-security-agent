import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { TagComplianceScanner } from "../../src/scanners/tag-compliance.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("TagComplianceScanner", () => {
  const scanner = new TagComplianceScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("detects EC2 instance missing required tags", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeInstancesCommand":
          return {
            Reservations: [
              {
                Instances: [
                  {
                    InstanceId: "i-12345",
                    Tags: [{ Key: "Environment", Value: "prod" }],
                  },
                ],
              },
            ],
          };
        case "DescribeDBInstancesCommand":
          return { DBInstances: [] };
        case "ListBucketsCommand":
          return { Buckets: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const finding = result.findings.find((f) => f.title.includes("i-12345"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("MEDIUM");
    expect(finding!.title).toContain("Project");
    expect(finding!.title).toContain("Owner");
  });

  it("returns no findings when all tags are present", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeInstancesCommand":
          return {
            Reservations: [
              {
                Instances: [
                  {
                    InstanceId: "i-ok",
                    Tags: [
                      { Key: "Environment", Value: "prod" },
                      { Key: "Project", Value: "main" },
                      { Key: "Owner", Value: "team" },
                    ],
                  },
                ],
              },
            ],
          };
        case "DescribeDBInstancesCommand":
          return { DBInstances: [] };
        case "ListBucketsCommand":
          return { Buckets: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
  });

  it("detects S3 bucket with no tags at all", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeInstancesCommand":
          return { Reservations: [] };
        case "DescribeDBInstancesCommand":
          return { DBInstances: [] };
        case "ListBucketsCommand":
          return { Buckets: [{ Name: "untagged-bucket" }] };
        case "GetBucketTaggingCommand": {
          const err = new Error("NoSuchTagSet");
          (err as Error & { name: string }).name = "NoSuchTagSet";
          throw err;
        }
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const finding = result.findings.find((f) => f.title.includes("untagged-bucket"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("MEDIUM");
    expect(finding!.title).toContain("Environment");
    expect(finding!.title).toContain("Project");
    expect(finding!.title).toContain("Owner");
  });
});
