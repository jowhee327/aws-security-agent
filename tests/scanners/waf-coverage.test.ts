import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { WafCoverageScanner } from "../../src/scanners/waf-coverage.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("WafCoverageScanner", () => {
  const scanner = new WafCoverageScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns HIGH finding for internet-facing ALB without WAF", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeLoadBalancersCommand":
          return {
            LoadBalancers: [
              {
                LoadBalancerName: "my-public-alb",
                LoadBalancerArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-public-alb/abc123",
                Scheme: "internet-facing",
                Type: "application",
              },
            ],
          };
        case "GetWebACLForResourceCommand":
          return { WebACL: null };
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
    expect(finding.title).toContain("my-public-alb");
    expect(finding.title).toContain("no WAF protection");
  });

  it("returns no findings when all ALBs have WAF", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeLoadBalancersCommand":
          return {
            LoadBalancers: [
              {
                LoadBalancerName: "protected-alb",
                LoadBalancerArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/protected-alb/def456",
                Scheme: "internet-facing",
                Type: "application",
              },
            ],
          };
        case "GetWebACLForResourceCommand":
          return {
            WebACL: {
              Name: "my-web-acl",
              Id: "acl-123",
              ARN: "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-web-acl/acl-123",
            },
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(1);
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toEqual([]);
  });

  it("skips internal load balancers and NLBs", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeLoadBalancersCommand":
          return {
            LoadBalancers: [
              {
                LoadBalancerName: "internal-alb",
                LoadBalancerArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/internal-alb/111",
                Scheme: "internal",
                Type: "application",
              },
              {
                LoadBalancerName: "public-nlb",
                LoadBalancerArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/public-nlb/222",
                Scheme: "internet-facing",
                Type: "network",
              },
            ],
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    // Only the NLB is internet-facing, but it's skipped for WAF check
    expect(result.resourcesScanned).toBe(1);
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings![0]).toContain("public-nlb");
  });

  it("returns error status on service error", async () => {
    mockSend.mockRejectedValue(new Error("ELBv2 service unavailable"));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("error");
    expect(result.error).toContain("service unavailable");
    expect(result.findingsCount).toBe(0);
  });

  it("returns success with warning on AccessDeniedException", async () => {
    const accessDenied = new Error("Access Denied");
    (accessDenied as any).name = "AccessDeniedException";
    mockSend.mockRejectedValue(accessDenied);

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings![0]).toContain("skipped");
  });
});
