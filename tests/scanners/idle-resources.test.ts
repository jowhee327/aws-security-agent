import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { IdleResourcesScanner } from "../../src/scanners/idle-resources.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("IdleResourcesScanner", () => {
  const scanner = new IdleResourcesScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("detects unattached EBS volumes and unused EIPs", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeVolumesCommand":
          return {
            Volumes: [
              { VolumeId: "vol-idle", State: "available", Size: 100, VolumeType: "gp3" },
              { VolumeId: "vol-used", State: "in-use", Size: 50, VolumeType: "gp2" },
            ],
          };
        case "DescribeAddressesCommand":
          return {
            Addresses: [
              { AllocationId: "eipalloc-1", PublicIp: "1.2.3.4" },
              { AllocationId: "eipalloc-2", PublicIp: "5.6.7.8", AssociationId: "eipassoc-1" },
            ],
          };
        case "DescribeInstancesCommand":
          return { Reservations: [] };
        case "DescribeSecurityGroupsCommand":
          return { SecurityGroups: [] };
        case "DescribeNetworkInterfacesCommand":
          return { NetworkInterfaces: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const titles = result.findings.map((f) => f.title);
    expect(titles).toContain("EBS volume vol-idle is unattached");
    expect(titles).toContain("Elastic IP 1.2.3.4 is not associated");
    // vol-used should NOT produce a finding
    expect(titles.some((t) => t.includes("vol-used"))).toBe(false);
    // Associated EIP should NOT produce a finding
    expect(titles.some((t) => t.includes("5.6.7.8"))).toBe(false);
  });

  it("detects stopped instances and unused security groups", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeVolumesCommand":
          return { Volumes: [] };
        case "DescribeAddressesCommand":
          return { Addresses: [] };
        case "DescribeInstancesCommand":
          return {
            Reservations: [
              {
                Instances: [
                  {
                    InstanceId: "i-stopped",
                    InstanceType: "t3.micro",
                    State: { Name: "stopped" },
                    StateTransitionReason: "User initiated (2024-01-01 00:00:00 GMT)",
                  },
                  {
                    InstanceId: "i-running",
                    InstanceType: "t3.large",
                    State: { Name: "running" },
                  },
                ],
              },
            ],
          };
        case "DescribeSecurityGroupsCommand":
          return {
            SecurityGroups: [
              { GroupId: "sg-unused", GroupName: "unused-sg", OwnerId: "123456789012" },
              { GroupId: "sg-default", GroupName: "default", OwnerId: "123456789012" },
            ],
          };
        case "DescribeNetworkInterfacesCommand":
          return { NetworkInterfaces: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const titles = result.findings.map((f) => f.title);
    // Stopped instance
    expect(titles.some((t) => t.includes("i-stopped") && t.includes("stopped"))).toBe(true);
    // Running instance should NOT produce a finding
    expect(titles.some((t) => t.includes("i-running"))).toBe(false);
    // Unused SG (not default)
    expect(titles.some((t) => t.includes("sg-unused"))).toBe(true);
    // Default SG should be skipped even if unused
    expect(titles.some((t) => t.includes("sg-default"))).toBe(false);
  });

  it("returns 0 findings when all resources are in use", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeVolumesCommand":
          return {
            Volumes: [
              { VolumeId: "vol-1", State: "in-use", Size: 50 },
            ],
          };
        case "DescribeAddressesCommand":
          return {
            Addresses: [
              { AllocationId: "eipalloc-1", PublicIp: "1.2.3.4", AssociationId: "eipassoc-1" },
            ],
          };
        case "DescribeInstancesCommand":
          return {
            Reservations: [
              {
                Instances: [
                  { InstanceId: "i-1", State: { Name: "running" } },
                ],
              },
            ],
          };
        case "DescribeSecurityGroupsCommand":
          return {
            SecurityGroups: [
              { GroupId: "sg-1", GroupName: "web-sg", OwnerId: "123456789012" },
            ],
          };
        case "DescribeNetworkInterfacesCommand":
          return {
            NetworkInterfaces: [
              { Groups: [{ GroupId: "sg-1" }] },
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
});
