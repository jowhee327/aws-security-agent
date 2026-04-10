import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { SgScanner } from "../../src/scanners/sg.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("SgScanner", () => {
  const scanner = new SgScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns CRITICAL finding for SSH open to 0.0.0.0/0", async () => {
    // DescribeSecurityGroups
    mockSend.mockResolvedValueOnce({
      SecurityGroups: [
        {
          GroupId: "sg-123",
          GroupName: "test-sg",
          OwnerId: "123456789012",
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
      NextToken: undefined,
    });
    // DescribeInstances
    mockSend.mockResolvedValueOnce({
      Reservations: [],
      NextToken: undefined,
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].severity).toBe("CRITICAL");
    expect(result.findings[0].title).toContain("SSH");
    expect(result.findings[0].title).toContain("sg-123");
    expect(result.findings[0].resourceArn).toContain("arn:aws:");
  });

  it("returns 0 findings for empty security groups", async () => {
    mockSend.mockResolvedValueOnce({
      SecurityGroups: [],
      NextToken: undefined,
    });
    mockSend.mockResolvedValueOnce({
      Reservations: [],
      NextToken: undefined,
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("uses correct partition in ARNs for China region", async () => {
    const cnCtx: ScanContext = {
      region: "cn-north-1",
      partition: "aws-cn",
      accountId: "123456789012",
    };

    mockSend.mockResolvedValueOnce({
      SecurityGroups: [
        {
          GroupId: "sg-456",
          GroupName: "test-sg-cn",
          OwnerId: "123456789012",
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
      NextToken: undefined,
    });
    mockSend.mockResolvedValueOnce({
      Reservations: [],
      NextToken: undefined,
    });

    const result = await scanner.scan(cnCtx);

    expect(result.findings[0].resourceArn).toContain("arn:aws-cn:");
  });
});
