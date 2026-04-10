import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { IamScanner } from "../../src/scanners/iam.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("IamScanner", () => {
  const scanner = new IamScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns CRITICAL finding when root MFA is disabled", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "GetAccountSummaryCommand":
          return { SummaryMap: { AccountMFAEnabled: 0 } };
        case "GenerateCredentialReportCommand":
          return {};
        case "GetCredentialReportCommand":
          return { Content: Buffer.from("user,access_key_1_active,access_key_2_active\n<root_account>,false,false") };
        case "ListUsersCommand":
          return { Users: [], IsTruncated: false };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    const rootMfaFinding = result.findings.find(
      (f) => f.title === "Root account does not have MFA enabled",
    );
    expect(rootMfaFinding).toBeDefined();
    expect(rootMfaFinding!.severity).toBe("CRITICAL");
    expect(rootMfaFinding!.riskScore).toBe(10.0);
    expect(rootMfaFinding!.resourceArn).toBe("arn:aws:iam::123456789012:root");
  });

  it("returns no root MFA finding when MFA is enabled", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "GetAccountSummaryCommand":
          return { SummaryMap: { AccountMFAEnabled: 1 } };
        case "GenerateCredentialReportCommand":
          return {};
        case "GetCredentialReportCommand":
          return { Content: Buffer.from("user,access_key_1_active,access_key_2_active\n<root_account>,false,false") };
        case "ListUsersCommand":
          return { Users: [], IsTruncated: false };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const rootMfaFinding = result.findings.find(
      (f) => f.title === "Root account does not have MFA enabled",
    );
    expect(rootMfaFinding).toBeUndefined();
  });

  it("skips root user checks in AWS China regions", async () => {
    const cnCtx: ScanContext = {
      region: "cn-north-1",
      partition: "aws-cn",
      accountId: "123456789012",
    };

    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "GetAccountSummaryCommand":
          return { SummaryMap: { AccountMFAEnabled: 0 } };
        case "ListUsersCommand":
          return { Users: [], IsTruncated: false };
        default:
          return {};
      }
    });

    const result = await scanner.scan(cnCtx);

    expect(result.status).toBe("success");
    // Should NOT produce root MFA finding
    const rootMfaFinding = result.findings.find(
      (f) => f.title === "Root account does not have MFA enabled",
    );
    expect(rootMfaFinding).toBeUndefined();
    // Should NOT produce root access key finding
    const rootKeyFinding = result.findings.find(
      (f) => f.title === "Root account has active access keys",
    );
    expect(rootKeyFinding).toBeUndefined();
    // Should have China warning
    expect(result.warnings).toContain(
      "Root user checks skipped: AWS China regions use partner-managed accounts without root user.",
    );
  });

  it("checks access key last used for inactive user detection", async () => {
    const longAgo = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000);
    const recently = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000);

    mockSend.mockImplementation((cmd: { constructor: { name: string; }; input?: Record<string, unknown> }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "GetAccountSummaryCommand":
          return { SummaryMap: { AccountMFAEnabled: 1 } };
        case "GenerateCredentialReportCommand":
          return {};
        case "GetCredentialReportCommand":
          return { Content: Buffer.from("user,access_key_1_active,access_key_2_active\n<root_account>,false,false") };
        case "ListUsersCommand":
          return {
            Users: [
              {
                UserName: "active-via-key",
                Arn: "arn:aws:iam::123456789012:user/active-via-key",
                PasswordLastUsed: longAgo,
                CreateDate: longAgo,
              },
            ],
            IsTruncated: false,
          };
        case "ListAccessKeysCommand":
          return {
            AccessKeyMetadata: [
              {
                AccessKeyId: "AKIA12345",
                Status: "Active",
                CreateDate: longAgo,
              },
            ],
          };
        case "GetAccessKeyLastUsedCommand":
          // Key was used recently, so user is NOT inactive
          return {
            AccessKeyLastUsed: {
              LastUsedDate: recently,
            },
          };
        case "ListAttachedUserPoliciesCommand":
          return { AttachedPolicies: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    // User should NOT be marked inactive because API key was used recently
    const inactiveFinding = result.findings.find(
      (f) => f.title.includes("inactive"),
    );
    expect(inactiveFinding).toBeUndefined();

    // But should have old key finding
    const oldKeyFinding = result.findings.find(
      (f) => f.title.includes("access key older than 90 days"),
    );
    expect(oldKeyFinding).toBeDefined();
  });
});
