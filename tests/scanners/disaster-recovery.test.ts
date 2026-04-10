import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { DisasterRecoveryScanner } from "../../src/scanners/disaster-recovery.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("DisasterRecoveryScanner", () => {
  const scanner = new DisasterRecoveryScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("detects RDS without Multi-AZ and low backup retention", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeDBInstancesCommand":
          return {
            DBInstances: [
              {
                DBInstanceIdentifier: "mydb",
                DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db/mydb",
                Engine: "mysql",
                MultiAZ: false,
                BackupRetentionPeriod: 3,
              },
            ],
          };
        case "DescribeVolumesCommand":
          return { Volumes: [] };
        case "DescribeSnapshotsCommand":
          return { Snapshots: [] };
        case "ListBucketsCommand":
          return { Buckets: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const titles = result.findings.map((f) => f.title);
    expect(titles).toContain("RDS instance mydb is not Multi-AZ");
    expect(titles.some((t) => t.includes("mydb") && t.includes("backup retention"))).toBe(true);
  });

  it("detects EBS volumes without snapshots", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeDBInstancesCommand":
          return { DBInstances: [] };
        case "DescribeVolumesCommand":
          return {
            Volumes: [
              { VolumeId: "vol-nosnap", State: "in-use", Size: 100, VolumeType: "gp3" },
            ],
          };
        case "DescribeSnapshotsCommand":
          return { Snapshots: [] };
        case "ListBucketsCommand":
          return { Buckets: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const finding = result.findings.find((f) => f.title.includes("vol-nosnap"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
    expect(finding!.title).toContain("no snapshots");
  });

  it("detects S3 bucket without versioning and replication", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeDBInstancesCommand":
          return { DBInstances: [] };
        case "DescribeVolumesCommand":
          return { Volumes: [] };
        case "DescribeSnapshotsCommand":
          return { Snapshots: [] };
        case "ListBucketsCommand":
          return { Buckets: [{ Name: "my-bucket" }] };
        case "GetBucketVersioningCommand":
          return { Status: "Suspended" };
        case "GetBucketReplicationCommand": {
          const err = new Error("ReplicationConfigurationNotFoundError");
          err.name = "ReplicationConfigurationNotFoundError";
          throw err;
        }
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const titles = result.findings.map((f) => f.title);
    expect(titles).toContain("S3 bucket my-bucket does not have versioning enabled");
    expect(titles).toContain("S3 bucket my-bucket has no cross-region replication");
  });
});
