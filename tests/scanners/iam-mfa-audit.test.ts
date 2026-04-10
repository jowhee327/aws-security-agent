import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { IamMfaAuditScanner } from "../../src/scanners/iam-mfa-audit.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("IamMfaAuditScanner", () => {
  const scanner = new IamMfaAuditScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns HIGH finding for console user without MFA", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string }; input?: Record<string, unknown> }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListUsersCommand":
          return {
            Users: [
              {
                UserName: "alice",
                Arn: "arn:aws:iam::123456789012:user/alice",
              },
            ],
            IsTruncated: false,
          };
        case "GetLoginProfileCommand":
          // User has console access
          return { LoginProfile: { UserName: "alice" } };
        case "ListMFADevicesCommand":
          // No MFA devices
          return { MFADevices: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBeGreaterThanOrEqual(1);
    const noMfa = result.findings.find((f) =>
      f.title.includes("alice") && f.title.includes("without MFA"),
    );
    expect(noMfa).toBeDefined();
    expect(noMfa!.severity).toBe("HIGH");
    expect(noMfa!.riskScore).toBe(7.5);
  });

  it("returns no per-user finding when all console users have MFA", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListUsersCommand":
          return {
            Users: [
              {
                UserName: "bob",
                Arn: "arn:aws:iam::123456789012:user/bob",
              },
            ],
            IsTruncated: false,
          };
        case "GetLoginProfileCommand":
          return { LoginProfile: { UserName: "bob" } };
        case "ListMFADevicesCommand":
          return {
            MFADevices: [{ SerialNumber: "arn:aws:iam::123456789012:mfa/bob" }],
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    // No per-user findings, and no adoption finding (100%)
    expect(result.findings).toHaveLength(0);
  });

  it("skips users without console access", async () => {
    const err = new Error("NoSuchEntityException");
    err.name = "NoSuchEntityException";

    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListUsersCommand":
          return {
            Users: [
              {
                UserName: "api-only-user",
                Arn: "arn:aws:iam::123456789012:user/api-only-user",
              },
            ],
            IsTruncated: false,
          };
        case "GetLoginProfileCommand":
          // No console access
          throw err;
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findings).toHaveLength(0);
  });
});
