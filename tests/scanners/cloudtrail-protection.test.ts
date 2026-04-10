import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { CloudTrailProtectionScanner } from "../../src/scanners/cloudtrail-protection.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("CloudTrailProtectionScanner", () => {
  const scanner = new CloudTrailProtectionScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns findings for unprotected CloudTrail S3 bucket", async () => {
    const noEncryptionErr = new Error("ServerSideEncryptionConfigurationNotFoundError");
    noEncryptionErr.name = "ServerSideEncryptionConfigurationNotFoundError";

    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrailsCommand":
          return {
            trailList: [
              {
                Name: "main-trail",
                TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/main-trail",
                S3BucketName: "cloudtrail-logs-bucket",
              },
            ],
          };
        case "GetBucketEncryptionCommand":
          throw noEncryptionErr;
        case "GetBucketVersioningCommand":
          return { Status: "Suspended" };
        case "GetPublicAccessBlockCommand":
          return {
            PublicAccessBlockConfiguration: {
              BlockPublicAcls: false,
              IgnorePublicAcls: false,
              BlockPublicPolicy: false,
              RestrictPublicBuckets: false,
            },
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    // Should have: not encrypted, no versioning, incomplete BPA
    expect(result.findingsCount).toBe(3);
    const titles = result.findings.map((f) => f.title);
    expect(titles.some((t) => t.includes("not encrypted"))).toBe(true);
    expect(titles.some((t) => t.includes("versioning"))).toBe(true);
    expect(titles.some((t) => t.includes("Block Public Access"))).toBe(true);
  });

  it("returns CRITICAL when BPA configuration is missing entirely", async () => {
    const noBpaErr = new Error("NoSuchPublicAccessBlockConfiguration");
    noBpaErr.name = "NoSuchPublicAccessBlockConfiguration";

    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrailsCommand":
          return {
            trailList: [
              {
                Name: "audit-trail",
                TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit-trail",
                S3BucketName: "audit-logs",
              },
            ],
          };
        case "GetBucketEncryptionCommand":
          return { ServerSideEncryptionConfiguration: {} };
        case "GetBucketVersioningCommand":
          return { Status: "Enabled" };
        case "GetPublicAccessBlockCommand":
          throw noBpaErr;
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    const finding = result.findings[0];
    expect(finding.severity).toBe("CRITICAL");
    expect(finding.riskScore).toBe(9.0);
    expect(finding.title).toContain("no Block Public Access configuration");
  });

  it("returns no findings for fully protected bucket", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrailsCommand":
          return {
            trailList: [
              {
                Name: "secure-trail",
                S3BucketName: "secure-ct-bucket",
              },
            ],
          };
        case "GetBucketEncryptionCommand":
          return { ServerSideEncryptionConfiguration: { Rules: [] } };
        case "GetBucketVersioningCommand":
          return { Status: "Enabled" };
        case "GetPublicAccessBlockCommand":
          return {
            PublicAccessBlockConfiguration: {
              BlockPublicAcls: true,
              IgnorePublicAcls: true,
              BlockPublicPolicy: true,
              RestrictPublicBuckets: true,
            },
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
  });
});
