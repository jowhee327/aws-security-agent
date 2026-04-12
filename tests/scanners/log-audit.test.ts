import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { LogAuditScanner } from "../../src/scanners/log-audit.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("LogAuditScanner", () => {
  const scanner = new LogAuditScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns success with 0 findings when no resources exist", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeVpcsCommand":
          return { Vpcs: [] };
        case "ListBucketsCommand":
          return { Buckets: [] };
        case "DescribeLoadBalancersCommand":
          return { LoadBalancers: [] };
        case "DescribeTrailsCommand":
          return { trailList: [] };
        case "DescribeDBInstancesCommand":
          return { DBInstances: [] };
        case "DescribeLogGroupsCommand":
          return { logGroups: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);
    expect(result.status).toBe("success");
    // With no trails, expect a HIGH finding for missing CloudTrail
    const ctFinding = result.findings.find(f => f.title.includes("CloudTrail"));
    expect(ctFinding).toBeDefined();
    expect(result.module).toBe("log_audit");
  });

  it("generates finding for VPC without flow logs", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeVpcsCommand":
          return {
            Vpcs: [{ VpcId: "vpc-123", Tags: [{ Key: "Name", Value: "my-vpc" }] }],
          };
        case "DescribeFlowLogsCommand":
          return { FlowLogs: [] };
        case "ListBucketsCommand":
          return { Buckets: [] };
        case "DescribeLoadBalancersCommand":
          return { LoadBalancers: [] };
        case "DescribeTrailsCommand":
          return { trailList: [] };
        case "DescribeDBInstancesCommand":
          return { DBInstances: [] };
        case "DescribeLogGroupsCommand":
          return { logGroups: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);
    expect(result.status).toBe("success");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    const vpcFinding = result.findings.find(f => f.resourceId === "vpc-123");
    expect(vpcFinding).toBeDefined();
    expect(vpcFinding!.severity).toBe("MEDIUM");
    expect(vpcFinding!.title).toContain("Flow Logs");
  });

  it("generates finding for CloudTrail not logging", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeVpcsCommand":
          return { Vpcs: [] };
        case "ListBucketsCommand":
          return { Buckets: [] };
        case "DescribeLoadBalancersCommand":
          return { LoadBalancers: [] };
        case "DescribeTrailsCommand":
          return {
            trailList: [
              {
                Name: "my-trail",
                TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail",
                IsMultiRegionTrail: true,
              },
            ],
          };
        case "GetTrailStatusCommand":
          return { IsLogging: false };
        case "DescribeDBInstancesCommand":
          return { DBInstances: [] };
        case "DescribeLogGroupsCommand":
          return { logGroups: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);
    expect(result.status).toBe("success");
    const ctFinding = result.findings.find(f => f.title.includes("CloudTrail"));
    expect(ctFinding).toBeDefined();
    expect(ctFinding!.severity).toBe("HIGH");
  });

  it("handles permission errors gracefully", async () => {
    mockSend.mockRejectedValue(
      Object.assign(new Error("User is not authorized"), { name: "AccessDeniedException" })
    );

    const result = await scanner.scan(ctx);
    expect(result.status).toBe("success");
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.length).toBeGreaterThan(0);
  });

  it("generates finding for ELB without access logging", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeVpcsCommand":
          return { Vpcs: [] };
        case "ListBucketsCommand":
          return { Buckets: [] };
        case "DescribeLoadBalancersCommand":
          return {
            LoadBalancers: [
              {
                LoadBalancerName: "my-alb",
                LoadBalancerArn: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc",
                Type: "application",
              },
            ],
          };
        case "DescribeLoadBalancerAttributesCommand":
          return {
            Attributes: [
              { Key: "access_logs.s3.enabled", Value: "false" },
            ],
          };
        case "DescribeTrailsCommand":
          return { trailList: [] };
        case "DescribeDBInstancesCommand":
          return { DBInstances: [] };
        case "DescribeLogGroupsCommand":
          return { logGroups: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);
    expect(result.status).toBe("success");
    const elbFinding = result.findings.find(f => f.resourceId === "my-alb");
    expect(elbFinding).toBeDefined();
    expect(elbFinding!.severity).toBe("MEDIUM");
  });
});
