import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { IamPrivilegeEscalationScanner } from "../../src/scanners/iam-privilege-escalation.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("IamPrivilegeEscalationScanner", () => {
  const scanner = new IamPrivilegeEscalationScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("detects user with iam:* wildcard permissions", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListUsersCommand":
          return {
            Users: [{ UserName: "admin-user", Arn: "arn:aws:iam::123456789012:user/admin-user" }],
            IsTruncated: false,
          };
        case "ListAttachedUserPoliciesCommand":
          return {
            AttachedPolicies: [{ PolicyArn: "arn:aws:iam::123456789012:policy/AdminPolicy", PolicyName: "AdminPolicy" }],
          };
        case "GetPolicyCommand":
          return { Policy: { DefaultVersionId: "v1" } };
        case "GetPolicyVersionCommand":
          return {
            PolicyVersion: {
              Document: encodeURIComponent(JSON.stringify({
                Version: "2012-10-17",
                Statement: [{ Effect: "Allow", Action: "iam:*", Resource: "*" }],
              })),
            },
          };
        case "ListUserPoliciesCommand":
          return { PolicyNames: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].severity).toBe("CRITICAL");
    expect(result.findings[0].riskScore).toBe(9.0);
    expect(result.findings[0].title).toContain("iam:*");
    // Should always include users-only limitation warning
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("IAM users only"))).toBe(true);
  });

  it("detects self-grant escalation via iam:AttachUserPolicy", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListUsersCommand":
          return {
            Users: [{ UserName: "dev-user", Arn: "arn:aws:iam::123456789012:user/dev-user" }],
            IsTruncated: false,
          };
        case "ListAttachedUserPoliciesCommand":
          return { AttachedPolicies: [] };
        case "ListUserPoliciesCommand":
          return { PolicyNames: ["inline-policy"] };
        case "GetUserPolicyCommand":
          return {
            PolicyDocument: encodeURIComponent(JSON.stringify({
              Version: "2012-10-17",
              Statement: [
                { Effect: "Allow", Action: ["iam:AttachUserPolicy", "s3:GetObject"], Resource: "*" },
              ],
            })),
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].severity).toBe("CRITICAL");
    expect(result.findings[0].riskScore).toBe(9.5);
    expect(result.findings[0].title).toContain("self-grant");
  });

  it("detects PassRole + Lambda escalation path", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "ListUsersCommand":
          return {
            Users: [{ UserName: "lambda-dev", Arn: "arn:aws:iam::123456789012:user/lambda-dev" }],
            IsTruncated: false,
          };
        case "ListAttachedUserPoliciesCommand":
          return {
            AttachedPolicies: [{ PolicyArn: "arn:aws:iam::123456789012:policy/LambdaDev", PolicyName: "LambdaDev" }],
          };
        case "GetPolicyCommand":
          return { Policy: { DefaultVersionId: "v1" } };
        case "GetPolicyVersionCommand":
          return {
            PolicyVersion: {
              Document: encodeURIComponent(JSON.stringify({
                Version: "2012-10-17",
                Statement: [
                  { Effect: "Allow", Action: ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], Resource: "*" },
                ],
              })),
            },
          };
        case "ListUserPoliciesCommand":
          return { PolicyNames: [] };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findings.some((f) => f.title.includes("Lambda role passing"))).toBe(true);
    expect(result.findings.find((f) => f.title.includes("Lambda"))!.riskScore).toBe(7.5);
  });
});
