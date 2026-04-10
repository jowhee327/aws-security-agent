import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { ElbHttpsScanner } from "../../src/scanners/elb-https.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("ElbHttpsScanner", () => {
  const scanner = new ElbHttpsScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns HIGH finding for ALB HTTP listener without HTTPS redirect", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeLoadBalancersCommand":
          return {
            LoadBalancers: [
              {
                LoadBalancerName: "my-alb",
                LoadBalancerArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/123",
                Type: "application",
              },
            ],
          };
        case "DescribeListenersCommand":
          return {
            Listeners: [
              {
                ListenerArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/my-alb/123/456",
                Protocol: "HTTP",
                Port: 80,
                DefaultActions: [
                  { Type: "forward" },
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
    const finding = result.findings[0];
    expect(finding.severity).toBe("HIGH");
    expect(finding.riskScore).toBe(7.5);
    expect(finding.title).toContain("HTTP listener");
    expect(finding.title).toContain("without HTTPS redirect");
  });

  it("returns no finding for ALB HTTP listener with HTTPS redirect", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeLoadBalancersCommand":
          return {
            LoadBalancers: [
              {
                LoadBalancerName: "secure-alb",
                LoadBalancerArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/secure-alb/789",
                Type: "application",
              },
            ],
          };
        case "DescribeListenersCommand":
          return {
            Listeners: [
              {
                Protocol: "HTTP",
                Port: 80,
                DefaultActions: [
                  {
                    Type: "redirect",
                    RedirectConfig: { Protocol: "HTTPS", StatusCode: "HTTP_301" },
                  },
                ],
              },
              {
                Protocol: "HTTPS",
                Port: 443,
                DefaultActions: [{ Type: "forward" }],
                Certificates: [{ CertificateArn: "arn:aws:acm:us-east-1:123456789012:certificate/abc" }],
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
  });

  it("returns MEDIUM finding for NLB TCP listener without TLS", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeLoadBalancersCommand":
          return {
            LoadBalancers: [
              {
                LoadBalancerName: "my-nlb",
                LoadBalancerArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/456",
                Type: "network",
              },
            ],
          };
        case "DescribeListenersCommand":
          return {
            Listeners: [
              {
                Protocol: "TCP",
                Port: 443,
                DefaultActions: [{ Type: "forward" }],
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
    const finding = result.findings[0];
    expect(finding.severity).toBe("MEDIUM");
    expect(finding.riskScore).toBe(6.0);
    expect(finding.title).toContain("NLB");
    expect(finding.title).toContain("without TLS");
  });
});
