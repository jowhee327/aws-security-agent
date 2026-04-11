import { describe, it, expect, vi, beforeEach } from "vitest";

// Trusted Advisor creates its own SupportClient directly (not via createClient),
// so we mock the entire AWS SDK module
const mockSend = vi.fn();

vi.mock("@aws-sdk/client-support", () => {
  return {
    SupportClient: vi.fn().mockImplementation(() => ({ send: mockSend })),
    DescribeTrustedAdvisorChecksCommand: vi.fn().mockImplementation((input: unknown) => ({
      ...input,
      constructor: { name: "DescribeTrustedAdvisorChecksCommand" },
    })),
    DescribeTrustedAdvisorCheckResultCommand: vi.fn().mockImplementation((input: unknown) => ({
      ...input,
      constructor: { name: "DescribeTrustedAdvisorCheckResultCommand" },
    })),
  };
});

import { TrustedAdvisorFindingsScanner } from "../../src/scanners/trusted-advisor-findings.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

const ctxChina: ScanContext = {
  region: "cn-north-1",
  partition: "aws-cn",
  accountId: "123456789012",
};

describe("TrustedAdvisorFindingsScanner", () => {
  const scanner = new TrustedAdvisorFindingsScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns findings for flagged security checks", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrustedAdvisorChecksCommand":
          return {
            checks: [
              {
                id: "check-1",
                name: "Security Groups - Specific Ports Unrestricted",
                category: "security",
                metadata: ["Region", "Resource ID"],
              },
              {
                id: "check-2",
                name: "IAM Access Key Rotation",
                category: "security",
                metadata: ["Resource ID"],
              },
              {
                id: "check-perf",
                name: "Performance Check",
                category: "performance",
                metadata: [],
              },
            ],
          };
        case "DescribeTrustedAdvisorCheckResultCommand":
          if ((cmd as unknown as { checkId: string }).checkId === "check-1") {
            return {
              result: {
                status: "error",
                flaggedResources: [
                  {
                    resourceId: "sg-12345",
                    isSuppressed: false,
                    metadata: ["us-east-1", "sg-12345"],
                  },
                ],
              },
            };
          }
          return {
            result: {
              status: "ok",
              flaggedResources: [],
            },
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.module).toBe("trusted_advisor_findings");
    // Only check-1 has error status, check-2 is ok
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].title).toContain("Security Groups");
    expect(result.findings[0].severity).toBe("HIGH"); // error status → 8.0 → HIGH
    expect(result.findings[0].riskScore).toBe(8.0);
  });

  it("works in China regions using cn-north-1 endpoint", async () => {
    mockSend.mockImplementation((cmd: { constructor: { name: string } }) => {
      const name = cmd.constructor.name;
      switch (name) {
        case "DescribeTrustedAdvisorChecksCommand":
          return {
            checks: [
              {
                id: "check-cn",
                name: "S3 Bucket Permissions",
                category: "security",
                metadata: [],
              },
            ],
          };
        case "DescribeTrustedAdvisorCheckResultCommand":
          return {
            result: {
              status: "ok",
              flaggedResources: [],
            },
          };
        default:
          return {};
      }
    });

    const result = await scanner.scan(ctxChina);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    // Should have called the API (not skipped)
    expect(mockSend).toHaveBeenCalled();
  });

  it("handles subscription required error gracefully", async () => {
    const err = new Error("AWS Premium Support Subscription is required");
    err.name = "SubscriptionRequiredException";
    mockSend.mockRejectedValue(err);

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("Business or Enterprise Support"))).toBe(true);
  });
});
