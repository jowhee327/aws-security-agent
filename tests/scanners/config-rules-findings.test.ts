import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { ConfigRulesFindingsScanner } from "../../src/scanners/config-rules-findings.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("ConfigRulesFindingsScanner (detection-only)", () => {
  const scanner = new ConfigRulesFindingsScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns 0 findings when Config is enabled", async () => {
    mockSend.mockResolvedValueOnce({
      ConfigurationRecorders: [{ name: "default" }],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.module).toBe("config_rules_findings");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings).toBeUndefined();
  });

  it("reports Config not enabled when no recorders exist", async () => {
    mockSend.mockResolvedValueOnce({
      ConfigurationRecorders: [],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("Config is not enabled"))).toBe(true);
  });

  it("returns success with warning when Config is not enabled (error path)", async () => {
    mockSend.mockRejectedValue(
      Object.assign(new Error("No Configuration Recorder was found"), {
        name: "NoSuchConfigurationRecorderException",
      }),
    );

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("Config is not enabled"))).toBe(true);
  });

  it("returns error on unexpected failure", async () => {
    mockSend.mockRejectedValue(new Error("Service unavailable"));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("error");
    expect(result.error).toContain("Service unavailable");
    expect(result.findingsCount).toBe(0);
  });
});
