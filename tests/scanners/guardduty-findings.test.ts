import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: mockSend })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
const mockSend = vi.fn();

import { GuardDutyFindingsScanner } from "../../src/scanners/guardduty-findings.js";
import type { ScanContext } from "../../src/types.js";

const ctx: ScanContext = {
  region: "us-east-1",
  partition: "aws",
  accountId: "123456789012",
};

describe("GuardDutyFindingsScanner", () => {
  const scanner = new GuardDutyFindingsScanner();

  beforeEach(() => {
    mockSend.mockReset();
  });

  it("returns 0 findings when GuardDuty is enabled but no active findings", async () => {
    mockSend.mockResolvedValueOnce({ DetectorIds: ["detector-1"] }); // ListDetectors
    mockSend.mockResolvedValueOnce({ FindingIds: [] }); // ListFindings

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.module).toBe("guardduty_findings");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("reports GuardDuty not enabled when no detectors exist", async () => {
    mockSend.mockResolvedValueOnce({ DetectorIds: [] });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings).toBeDefined();
    expect(result.warnings!.some((w) => w.includes("GuardDuty is not enabled"))).toBe(true);
  });

  it("returns error on API failure", async () => {
    mockSend.mockRejectedValue(new Error("Service unavailable"));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("error");
    expect(result.error).toContain("Service unavailable");
    expect(result.findingsCount).toBe(0);
  });
});
