import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

vi.mock("dns", () => ({
  promises: {
    resolve: vi.fn(),
  },
}));

import { promises as dns } from "dns";
import { DnsDanglingScanner } from "../../src/scanners/dns-dangling.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("DnsDanglingScanner", () => {
  const scanner = new DnsDanglingScanner();

  beforeEach(() => {
    mockSend.mockReset();
    vi.mocked(dns.resolve).mockReset();
  });

  it("returns CRITICAL finding for CNAME to non-existent S3 bucket", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListHostedZonesCommand":
          return {
            HostedZones: [
              { Id: "/hostedzone/Z123", Name: "example.com." },
            ],
            IsTruncated: false,
          };
        case "ListResourceRecordSetsCommand":
          return {
            ResourceRecordSets: [
              {
                Name: "static.example.com.",
                Type: "CNAME",
                ResourceRecords: [{ Value: "my-deleted-bucket.s3.amazonaws.com." }],
              },
            ],
            IsTruncated: false,
          };
        case "HeadBucketCommand":
          throw { name: "NotFound" };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    const finding = result.findings[0];
    expect(finding.severity).toBe("CRITICAL");
    expect(finding.riskScore).toBe(9.5);
    expect(finding.title).toContain("non-existent S3 bucket");
    expect(finding.description).toContain("subdomain takeover");
  });

  it("returns HIGH finding for CNAME to non-resolving ELB", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListHostedZonesCommand":
          return {
            HostedZones: [
              { Id: "/hostedzone/Z456", Name: "example.com." },
            ],
            IsTruncated: false,
          };
        case "ListResourceRecordSetsCommand":
          return {
            ResourceRecordSets: [
              {
                Name: "api.example.com.",
                Type: "CNAME",
                ResourceRecords: [{ Value: "old-lb-123456.us-east-1.elb.amazonaws.com." }],
              },
            ],
            IsTruncated: false,
          };
        default:
          return {};
      }
    });

    // DNS resolution fails
    vi.mocked(dns.resolve).mockRejectedValue(new Error("ENOTFOUND"));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    const finding = result.findings[0];
    expect(finding.severity).toBe("HIGH");
    expect(finding.riskScore).toBe(8.0);
    expect(finding.title).toContain("non-resolving ELB");
  });

  it("returns no findings when all CNAMEs resolve", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListHostedZonesCommand":
          return {
            HostedZones: [
              { Id: "/hostedzone/Z789", Name: "example.com." },
            ],
            IsTruncated: false,
          };
        case "ListResourceRecordSetsCommand":
          return {
            ResourceRecordSets: [
              {
                Name: "app.example.com.",
                Type: "CNAME",
                ResourceRecords: [{ Value: "active-lb-789.us-east-1.elb.amazonaws.com." }],
              },
            ],
            IsTruncated: false,
          };
        default:
          return {};
      }
    });

    // DNS resolution succeeds
    vi.mocked(dns.resolve).mockResolvedValue(["1.2.3.4"]);

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
  });
});
