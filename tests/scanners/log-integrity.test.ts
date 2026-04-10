import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { LogIntegrityScanner } from "../../src/scanners/log-integrity.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("LogIntegrityScanner", () => {
  const scanner = new LogIntegrityScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("detects no multi-region CloudTrail", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrailsCommand":
          return {
            trailList: [
              {
                Name: "local-trail",
                TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/local-trail",
                HomeRegion: "us-east-1",
                IsMultiRegionTrail: false,
                LogFileValidationEnabled: true,
                CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:ct-logs",
              },
            ],
          };
        case "GetTrailStatusCommand":
          return { IsLogging: true };
        case "DescribeVpcsCommand":
          return { Vpcs: [] };
        case "DescribeFlowLogsCommand":
          return { FlowLogs: [] };
        case "ListBucketsCommand":
          return { Buckets: [] };
        case "DescribeLoadBalancersCommand":
          return { LoadBalancers: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const finding = result.findings.find((f) => f.title.includes("multi-region"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
    expect(finding!.riskScore).toBe(7.5);
  });

  it("detects VPC without Flow Logs", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrailsCommand":
          return {
            trailList: [
              {
                Name: "main-trail",
                HomeRegion: "us-east-1",
                IsMultiRegionTrail: true,
                LogFileValidationEnabled: true,
                CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123456789012:log-group:ct",
              },
            ],
          };
        case "GetTrailStatusCommand":
          return { IsLogging: true };
        case "DescribeVpcsCommand":
          return {
            Vpcs: [
              { VpcId: "vpc-111" },
              { VpcId: "vpc-222" },
            ],
          };
        case "DescribeFlowLogsCommand":
          return {
            FlowLogs: [{ ResourceId: "vpc-111" }],
          };
        case "ListBucketsCommand":
          return { Buckets: [] };
        case "DescribeLoadBalancersCommand":
          return { LoadBalancers: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const finding = result.findings.find((f) => f.title.includes("vpc-222"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("HIGH");
    expect(finding!.riskScore).toBe(7.0);
  });

  it("detects ELB without access logging", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrailsCommand":
          return {
            trailList: [
              {
                Name: "trail",
                HomeRegion: "us-east-1",
                IsMultiRegionTrail: true,
                LogFileValidationEnabled: true,
                CloudWatchLogsLogGroupArn: "arn:aws:logs:us-east-1:123:log-group:ct",
              },
            ],
          };
        case "GetTrailStatusCommand":
          return { IsLogging: true };
        case "DescribeVpcsCommand":
          return { Vpcs: [] };
        case "DescribeFlowLogsCommand":
          return { FlowLogs: [] };
        case "ListBucketsCommand":
          return { Buckets: [] };
        case "DescribeLoadBalancersCommand":
          return {
            LoadBalancers: [
              {
                LoadBalancerName: "my-alb",
                LoadBalancerArn: "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/123",
              },
            ],
          };
        case "DescribeLoadBalancerAttributesCommand":
          return {
            Attributes: [
              { Key: "access_logs.s3.enabled", Value: "false" },
            ],
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const finding = result.findings.find((f) => f.title.includes("ELB") && f.title.includes("access logging"));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe("MEDIUM");
    expect(finding!.riskScore).toBe(5.5);
  });
});
