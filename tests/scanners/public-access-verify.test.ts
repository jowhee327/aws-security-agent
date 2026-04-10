import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// Mock dns
vi.mock("node:dns", () => ({
  default: {
    promises: {
      resolve4: vi.fn(),
    },
  },
}));
import dns from "node:dns";
const mockResolve4 = vi.mocked(dns.promises.resolve4);

import { PublicAccessVerifyScanner } from "../../src/scanners/public-access-verify.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("PublicAccessVerifyScanner", () => {
  const scanner = new PublicAccessVerifyScanner();

  beforeEach(() => {
    mockSend.mockReset();
    mockFetch.mockReset();
    mockResolve4.mockReset();
  });

  it("detects S3 bucket that is actually publicly readable", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string }; input?: { Bucket?: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListBucketsCommand":
          return { Buckets: [{ Name: "public-bucket" }] };
        case "GetBucketLocationCommand":
          return { LocationConstraint: "us-east-1" };
        case "GetPublicAccessBlockCommand": {
          const err = new Error("NoSuchPublicAccessBlockConfiguration");
          (err as Error & { name: string }).name = "NoSuchPublicAccessBlockConfiguration";
          throw err;
        }
        case "GetBucketAclCommand":
          return {
            Grants: [
              { Grantee: { URI: "http://acs.amazonaws.com/groups/global/AllUsers" }, Permission: "READ" },
            ],
          };
        case "DescribeDBInstancesCommand":
          return { DBInstances: [] };
        default:
          return {};
      }
    });

    mockFetch.mockResolvedValueOnce({ ok: true, status: 200 });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const s3Finding = result.findings.find((f) => f.title.includes("publicly readable"));
    expect(s3Finding).toBeDefined();
    expect(s3Finding!.severity).toBe("CRITICAL");
    expect(s3Finding!.riskScore).toBe(9.5);
  });

  it("returns LOW finding for S3 bucket marked public but returning 403", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListBucketsCommand":
          return { Buckets: [{ Name: "blocked-bucket" }] };
        case "GetBucketLocationCommand":
          return { LocationConstraint: "us-east-1" };
        case "GetPublicAccessBlockCommand": {
          const err = new Error("NoSuchPublicAccessBlockConfiguration");
          (err as Error & { name: string }).name = "NoSuchPublicAccessBlockConfiguration";
          throw err;
        }
        case "GetBucketAclCommand":
          return {
            Grants: [
              { Grantee: { URI: "http://acs.amazonaws.com/groups/global/AllUsers" }, Permission: "READ" },
            ],
          };
        case "DescribeDBInstancesCommand":
          return { DBInstances: [] };
        default:
          return {};
      }
    });

    mockFetch.mockResolvedValueOnce({ ok: false, status: 403 });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const finding = result.findings.find((f) => f.title.includes("403"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("LOW");
    expect(finding!.riskScore).toBe(2.0);
  });

  it("detects RDS endpoint resolving to public IP", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListBucketsCommand":
          return { Buckets: [] };
        case "DescribeDBInstancesCommand":
          return {
            DBInstances: [
              {
                DBInstanceIdentifier: "my-db",
                DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db/my-db",
                PubliclyAccessible: true,
                Endpoint: { Address: "my-db.abc123.us-east-1.rds.amazonaws.com" },
              },
            ],
          };
        default:
          return {};
      }
    });

    mockResolve4.mockResolvedValueOnce(["54.123.45.67"]);

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const rdsFind = result.findings.find((f) => f.title.includes("public IP"));
    expect(rdsFind).toBeDefined();
    expect(rdsFind!.severity).toBe("HIGH");
    expect(rdsFind!.riskScore).toBe(8.0);
  });
});
