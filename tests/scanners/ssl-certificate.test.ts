import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { SslCertificateScanner } from "../../src/scanners/ssl-certificate.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("SslCertificateScanner", () => {
  const scanner = new SslCertificateScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns HIGH finding for expired certificate", async () => {
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 10);

    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListCertificatesCommand":
          return {
            CertificateSummaryList: [
              {
                CertificateArn: "arn:aws:acm:us-east-1:123456789012:certificate/abc-123",
                DomainName: "example.com",
              },
            ],
          };
        case "DescribeCertificateCommand":
          return {
            Certificate: {
              Status: "ISSUED",
              NotAfter: pastDate,
              InUseBy: ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/123"],
            },
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    const finding = result.findings[0];
    expect(finding.severity).toBe("HIGH");
    expect(finding.riskScore).toBe(8.0);
    expect(finding.title).toContain("expired");
  });

  it("returns MEDIUM finding for certificate expiring within 30 days", async () => {
    const soonDate = new Date();
    soonDate.setDate(soonDate.getDate() + 15);

    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListCertificatesCommand":
          return {
            CertificateSummaryList: [
              {
                CertificateArn: "arn:aws:acm:us-east-1:123456789012:certificate/def-456",
                DomainName: "api.example.com",
              },
            ],
          };
        case "DescribeCertificateCommand":
          return {
            Certificate: {
              Status: "ISSUED",
              NotAfter: soonDate,
              InUseBy: [],
            },
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    const finding = result.findings[0];
    expect(finding.severity).toBe("MEDIUM");
    expect(finding.riskScore).toBe(6.0);
    expect(finding.title).toContain("expires in");
  });

  it("returns HIGH finding for FAILED certificate", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListCertificatesCommand":
          return {
            CertificateSummaryList: [
              {
                CertificateArn: "arn:aws:acm:us-east-1:123456789012:certificate/fail-789",
                DomainName: "broken.example.com",
              },
            ],
          };
        case "DescribeCertificateCommand":
          return {
            Certificate: {
              Status: "FAILED",
              InUseBy: [],
            },
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    const finding = result.findings[0];
    expect(finding.severity).toBe("HIGH");
    expect(finding.riskScore).toBe(7.5);
    expect(finding.title).toContain("FAILED");
  });
});
