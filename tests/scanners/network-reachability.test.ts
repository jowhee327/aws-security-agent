import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { NetworkReachabilityScanner } from "../../src/scanners/network-reachability.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("NetworkReachabilityScanner", () => {
  const scanner = new NetworkReachabilityScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns CRITICAL finding when SG+NACL both allow SSH to public instance", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeAddressesCommand":
          return { Addresses: [] };
        case "DescribeInstancesCommand":
          return {
            Reservations: [
              {
                Instances: [
                  {
                    InstanceId: "i-abc123",
                    PublicIpAddress: "54.1.2.3",
                    SubnetId: "subnet-aaa",
                    SecurityGroups: [{ GroupId: "sg-111" }],
                  },
                ],
              },
            ],
          };
        case "DescribeSecurityGroupsCommand":
          return {
            SecurityGroups: [
              {
                GroupId: "sg-111",
                IpPermissions: [
                  {
                    FromPort: 22,
                    ToPort: 22,
                    IpRanges: [{ CidrIp: "0.0.0.0/0" }],
                    Ipv6Ranges: [],
                  },
                ],
              },
            ],
          };
        case "DescribeNetworkAclsCommand":
          return {
            NetworkAcls: [
              {
                Associations: [{ SubnetId: "subnet-aaa" }],
                Entries: [
                  {
                    RuleNumber: 100,
                    Protocol: "6", // TCP
                    RuleAction: "allow",
                    Egress: false,
                    CidrBlock: "0.0.0.0/0",
                    PortRange: { From: 0, To: 65535 },
                  },
                  {
                    RuleNumber: 32767,
                    Protocol: "-1",
                    RuleAction: "deny",
                    Egress: false,
                    CidrBlock: "0.0.0.0/0",
                  },
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
    expect(result.findingsCount).toBeGreaterThanOrEqual(1);
    const sshFinding = result.findings.find((f) => f.title.includes("SSH"));
    expect(sshFinding).toBeDefined();
    expect(sshFinding!.severity).toBe("CRITICAL");
    expect(sshFinding!.riskScore).toBe(9.5);
    expect(sshFinding!.title).toContain("54.1.2.3");
  });

  it("returns LOW finding when SG allows but NACL blocks", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeAddressesCommand":
          return { Addresses: [] };
        case "DescribeInstancesCommand":
          return {
            Reservations: [
              {
                Instances: [
                  {
                    InstanceId: "i-def456",
                    PublicIpAddress: "54.4.5.6",
                    SubnetId: "subnet-bbb",
                    SecurityGroups: [{ GroupId: "sg-222" }],
                  },
                ],
              },
            ],
          };
        case "DescribeSecurityGroupsCommand":
          return {
            SecurityGroups: [
              {
                GroupId: "sg-222",
                IpPermissions: [
                  {
                    FromPort: 22,
                    ToPort: 22,
                    IpRanges: [{ CidrIp: "0.0.0.0/0" }],
                    Ipv6Ranges: [],
                  },
                ],
              },
            ],
          };
        case "DescribeNetworkAclsCommand":
          return {
            NetworkAcls: [
              {
                Associations: [{ SubnetId: "subnet-bbb" }],
                Entries: [
                  {
                    RuleNumber: 50,
                    Protocol: "6", // TCP
                    RuleAction: "deny",
                    Egress: false,
                    CidrBlock: "0.0.0.0/0",
                    PortRange: { From: 22, To: 22 },
                  },
                  {
                    RuleNumber: 100,
                    Protocol: "6",
                    RuleAction: "allow",
                    Egress: false,
                    CidrBlock: "0.0.0.0/0",
                    PortRange: { From: 0, To: 65535 },
                  },
                  {
                    RuleNumber: 32767,
                    Protocol: "-1",
                    RuleAction: "deny",
                    Egress: false,
                    CidrBlock: "0.0.0.0/0",
                  },
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
    const sshFinding = result.findings.find((f) => f.title.includes("SSH"));
    expect(sshFinding).toBeDefined();
    expect(sshFinding!.severity).toBe("LOW");
    expect(sshFinding!.riskScore).toBe(2.0);
    expect(sshFinding!.title).toContain("blocked by NACL");
  });

  it("returns no findings for instances without public IPs", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeAddressesCommand":
          return { Addresses: [] };
        case "DescribeInstancesCommand":
          return {
            Reservations: [
              {
                Instances: [
                  {
                    InstanceId: "i-private",
                    SubnetId: "subnet-ccc",
                    SecurityGroups: [{ GroupId: "sg-333" }],
                    // No PublicIpAddress
                  },
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
    expect(result.findingsCount).toBe(0);
    expect(result.resourcesScanned).toBe(0);
  });
});
