import { describe, it, expect, vi, beforeEach } from "vitest";
import { getPartition, getIamRegion } from "../src/utils/aws-client.js";

describe("getPartition", () => {
  it("returns 'aws' for standard regions", () => {
    expect(getPartition("us-east-1")).toBe("aws");
    expect(getPartition("eu-west-1")).toBe("aws");
    expect(getPartition("ap-northeast-1")).toBe("aws");
  });

  it("returns 'aws-cn' for China regions", () => {
    expect(getPartition("cn-north-1")).toBe("aws-cn");
    expect(getPartition("cn-northwest-1")).toBe("aws-cn");
  });

  it("returns 'aws-us-gov' for GovCloud regions", () => {
    expect(getPartition("us-gov-west-1")).toBe("aws-us-gov");
    expect(getPartition("us-gov-east-1")).toBe("aws-us-gov");
  });
});

describe("getIamRegion", () => {
  it("returns 'us-east-1' for standard regions", () => {
    expect(getIamRegion("us-east-1")).toBe("us-east-1");
    expect(getIamRegion("eu-west-1")).toBe("us-east-1");
    expect(getIamRegion("ap-northeast-1")).toBe("us-east-1");
  });

  it("returns the region itself for China regions", () => {
    expect(getIamRegion("cn-north-1")).toBe("cn-north-1");
    expect(getIamRegion("cn-northwest-1")).toBe("cn-northwest-1");
  });
});

// Warnings propagation: test that a scanner with a graceful degradation path
// includes warnings in the result
vi.mock("../src/utils/aws-client.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/utils/aws-client.js")>();
  return {
    ...actual,
    createClient: vi.fn(() => ({ send: mockSend })),
  };
});
const mockSend = vi.fn();

import { SecurityHubFindingsScanner } from "../src/scanners/security-hub-findings.js";
import type { ScanContext } from "../src/types.js";

describe("warnings propagation", () => {
  const ctx: ScanContext = {
    region: "us-east-1",
    partition: "aws",
    accountId: "123456789012",
  };

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("SecurityHubFindingsScanner includes warnings when Security Hub is not enabled", async () => {
    const scanner = new SecurityHubFindingsScanner();

    const notEnabledErr = new Error("Security Hub is not enabled");
    notEnabledErr.name = "InvalidAccessException";
    mockSend.mockRejectedValue(notEnabledErr);

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.length).toBeGreaterThanOrEqual(1);
    expect(result.warnings!.some((w) => w.includes("Security Hub is not enabled"))).toBe(true);
    expect(result.findingsCount).toBe(0);
  });
});
