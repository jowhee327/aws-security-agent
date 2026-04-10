import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { S3Scanner } from "../../src/scanners/s3.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("S3Scanner", () => {
  const scanner = new S3Scanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns findings for a public bucket", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "GetPublicAccessBlockCommand":
          return {
            PublicAccessBlockConfiguration: {
              BlockPublicAcls: false,
              IgnorePublicAcls: false,
              BlockPublicPolicy: false,
              RestrictPublicBuckets: false,
            },
          };
        case "GetAccountPublicAccessBlockCommand":
          return {
            PublicAccessBlockConfiguration: {
              BlockPublicAcls: true,
              IgnorePublicAcls: true,
              BlockPublicPolicy: true,
              RestrictPublicBuckets: true,
            },
          };
        case "ListBucketsCommand":
          return { Buckets: [{ Name: "my-bucket" }] };
        case "GetBucketLocationCommand":
          return { LocationConstraint: "us-east-1" };
        case "GetBucketAclCommand":
          return {
            Grants: [
              {
                Grantee: {
                  URI: "http://acs.amazonaws.com/groups/global/AllUsers",
                },
                Permission: "READ",
              },
            ],
          };
        case "GetBucketPolicyStatusCommand":
          return { PolicyStatus: { IsPublic: true } };
        case "GetBucketEncryptionCommand":
          return {};
        case "GetBucketVersioningCommand":
          return { Status: "Enabled" };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBeGreaterThanOrEqual(3);
    const severities = result.findings.map((f) => f.severity);
    expect(severities).toContain("CRITICAL");
    expect(severities).toContain("HIGH");
    // All ARNs should use correct partition
    for (const f of result.findings) {
      if (f.resourceArn.startsWith("arn:")) {
        expect(f.resourceArn).toContain("arn:aws:");
      }
    }
  });

  it("returns 0 findings for fully compliant bucket", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "GetAccountPublicAccessBlockCommand":
          return {
            PublicAccessBlockConfiguration: {
              BlockPublicAcls: true,
              IgnorePublicAcls: true,
              BlockPublicPolicy: true,
              RestrictPublicBuckets: true,
            },
          };
        case "ListBucketsCommand":
          return { Buckets: [{ Name: "secure-bucket" }] };
        case "GetBucketLocationCommand":
          return { LocationConstraint: "us-east-1" };
        case "GetPublicAccessBlockCommand":
          return {
            PublicAccessBlockConfiguration: {
              BlockPublicAcls: true,
              IgnorePublicAcls: true,
              BlockPublicPolicy: true,
              RestrictPublicBuckets: true,
            },
          };
        case "GetBucketAclCommand":
          return { Grants: [] };
        case "GetBucketPolicyStatusCommand":
          return { PolicyStatus: { IsPublic: false } };
        case "GetBucketEncryptionCommand":
          return {};
        case "GetBucketVersioningCommand":
          return { Status: "Enabled" };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("reports account-level BPA finding when not configured", async () => {
    const err = new Error("NoSuchPublicAccessBlockConfiguration");
    err.name = "NoSuchPublicAccessBlockConfiguration";

    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "GetAccountPublicAccessBlockCommand":
          throw err;
        case "ListBucketsCommand":
          return { Buckets: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findings.some((f) => f.title.includes("Account-level"))).toBe(true);
  });
});
