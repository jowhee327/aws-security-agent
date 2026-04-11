import { describe, it, expect, vi, beforeEach } from "vitest";

const mockSend = vi.fn();

vi.mock("@aws-sdk/client-sts", () => ({
  STSClient: vi.fn().mockImplementation(() => ({ send: mockSend })),
  AssumeRoleCommand: vi.fn().mockImplementation((input: unknown) => ({
    ...input,
    constructor: { name: "AssumeRoleCommand" },
  })),
  GetCallerIdentityCommand: vi.fn().mockImplementation((input: unknown) => ({
    ...input,
    constructor: { name: "GetCallerIdentityCommand" },
  })),
}));

import { getCurrentAccountId, assumeRole, buildRoleArn } from "../../src/utils/assume-role.js";

describe("assume-role utilities", () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  describe("getCurrentAccountId", () => {
    it("returns account ID from STS", async () => {
      mockSend.mockResolvedValueOnce({ Account: "111122223333" });
      const result = await getCurrentAccountId("us-east-1");
      expect(result).toBe("111122223333");
    });
  });

  describe("assumeRole", () => {
    it("returns temporary credentials", async () => {
      mockSend.mockResolvedValueOnce({
        Credentials: {
          AccessKeyId: "ASIA_TEST_KEY",
          SecretAccessKey: "secret_test_key",
          SessionToken: "session_test_token",
        },
      });

      const result = await assumeRole("arn:aws:iam::111122223333:role/TestRole", "us-east-1");
      expect(result.accessKeyId).toBe("ASIA_TEST_KEY");
      expect(result.secretAccessKey).toBe("secret_test_key");
      expect(result.sessionToken).toBe("session_test_token");
    });

    it("uses custom session name when provided", async () => {
      mockSend.mockResolvedValueOnce({
        Credentials: {
          AccessKeyId: "ASIA_KEY",
          SecretAccessKey: "secret",
          SessionToken: "token",
        },
      });

      const result = await assumeRole(
        "arn:aws:iam::111122223333:role/TestRole",
        "us-east-1",
        "custom-session",
      );
      expect(result.accessKeyId).toBe("ASIA_KEY");
    });

    it("throws when STS returns error", async () => {
      mockSend.mockRejectedValueOnce(new Error("AccessDenied"));
      await expect(
        assumeRole("arn:aws:iam::111122223333:role/TestRole", "us-east-1"),
      ).rejects.toThrow("AccessDenied");
    });
  });

  describe("buildRoleArn", () => {
    it("builds standard partition ARN", () => {
      expect(buildRoleArn("111122223333", "AWSSecurityMCPAudit")).toBe(
        "arn:aws:iam::111122223333:role/AWSSecurityMCPAudit",
      );
    });

    it("builds China partition ARN", () => {
      expect(buildRoleArn("111122223333", "AWSSecurityMCPAudit", "aws-cn")).toBe(
        "arn:aws-cn:iam::111122223333:role/AWSSecurityMCPAudit",
      );
    });

    it("builds GovCloud partition ARN", () => {
      expect(buildRoleArn("111122223333", "AWSSecurityMCPAudit", "aws-us-gov")).toBe(
        "arn:aws-us-gov:iam::111122223333:role/AWSSecurityMCPAudit",
      );
    });
  });
});
