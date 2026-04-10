import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { IamPasswordPolicyScanner } from "../../src/scanners/iam-password-policy.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("IamPasswordPolicyScanner", () => {
  const scanner = new IamPasswordPolicyScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns HIGH finding when no password policy is configured", async () => {
    const err = new Error("NoSuchEntityException");
    err.name = "NoSuchEntityException";

    mockSend.mockImplementation(() => {
      throw err;
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    const finding = result.findings[0];
    expect(finding.title).toBe("No IAM password policy configured");
    expect(finding.severity).toBe("HIGH");
    expect(finding.riskScore).toBe(7.5);
  });

  it("returns no findings for a fully compliant policy", async () => {
    mockSend.mockImplementation(() => ({
      PasswordPolicy: {
        MinimumPasswordLength: 14,
        RequireUppercaseCharacters: true,
        RequireLowercaseCharacters: true,
        RequireNumbers: true,
        RequireSymbols: true,
        MaxPasswordAge: 90,
        PasswordReusePrevention: 5,
      },
    }));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("returns multiple findings for a weak policy", async () => {
    mockSend.mockImplementation(() => ({
      PasswordPolicy: {
        MinimumPasswordLength: 6,
        RequireUppercaseCharacters: false,
        RequireLowercaseCharacters: true,
        RequireNumbers: false,
        RequireSymbols: false,
        MaxPasswordAge: 0,
        PasswordReusePrevention: 0,
      },
    }));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    // Should have: short password, missing complexity, no expiry, no reuse prevention
    expect(result.findingsCount).toBe(4);
    const titles = result.findings.map((f) => f.title);
    expect(titles).toContain("IAM password policy minimum length is too short");
    expect(titles).toContain("IAM password policy missing complexity requirements");
    expect(titles).toContain("IAM password policy has no password expiry");
    expect(titles).toContain("IAM password policy has no reuse prevention");
  });
});
