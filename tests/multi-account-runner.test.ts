import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: vi.fn() })),
  getAccountId: vi.fn().mockResolvedValue("000000000000"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));

vi.mock("../src/utils/org-accounts.js", () => ({
  listOrgAccounts: vi.fn(),
}));

vi.mock("../src/utils/assume-role.js", () => ({
  assumeRole: vi.fn(),
  buildRoleArn: vi.fn((accountId: string, roleName: string, partition: string) =>
    `arn:${partition}:iam::${accountId}:role/${roleName}`,
  ),
}));

import { runMultiAccountScanners } from "../src/scanners/runner.js";
import { listOrgAccounts } from "../src/utils/org-accounts.js";
import { assumeRole } from "../src/utils/assume-role.js";
import type { Scanner } from "../src/scanners/base.js";
import type { ScanResult, ScanContext } from "../src/types.js";
import { acceptanceModules } from "./exploitability/fixtures.js";

function createMockScanner(name: string, findings: ScanResult["findings"] = []): Scanner {
  return {
    moduleName: name,
    scan: vi.fn().mockImplementation(async (ctx: ScanContext) => ({
      module: name,
      status: "success" as const,
      resourcesScanned: 1,
      findingsCount: findings.length,
      scanTimeMs: 10,
      findings: findings.map((f) => ({ ...f })),
    })),
  };
}

describe("runMultiAccountScanners", () => {
  beforeEach(() => {
    vi.mocked(listOrgAccounts).mockReset();
    vi.mocked(assumeRole).mockReset();
  });

  it("runs aggregation scanners once and per-account scanners for each account", async () => {
    vi.mocked(listOrgAccounts).mockResolvedValue([
      { id: "000000000000", name: "Admin", email: "admin@test.com", status: "ACTIVE" },
      { id: "111111111111", name: "Child1", email: "child1@test.com", status: "ACTIVE" },
    ]);
    vi.mocked(assumeRole).mockResolvedValue({
      accessKeyId: "ASIA_KEY",
      secretAccessKey: "secret",
      sessionToken: "token",
    });

    const aggScanner = createMockScanner("security_hub_findings");
    const perAcctScanner = createMockScanner("ssl_certificate");

    const result = await runMultiAccountScanners(
      [aggScanner, perAcctScanner],
      "us-east-1",
      { orgMode: true, roleName: "AWSSecurityMCPAudit" },
    );

    // Aggregation scanner runs once (admin account)
    expect(aggScanner.scan).toHaveBeenCalledTimes(1);
    // Per-account scanner runs for each account (admin + child1)
    expect(perAcctScanner.scan).toHaveBeenCalledTimes(2);

    // Should have 3 total module results: 1 agg + 2 per-account
    expect(result.modules).toHaveLength(3);
    expect(result.accountId).toBe("000000000000");
  });

  it("skips assume role for admin account", async () => {
    vi.mocked(listOrgAccounts).mockResolvedValue([
      { id: "000000000000", name: "Admin", email: "admin@test.com", status: "ACTIVE" },
    ]);

    const scanner = createMockScanner("ssl_certificate");

    await runMultiAccountScanners(
      [scanner],
      "us-east-1",
      { orgMode: true, roleName: "AWSSecurityMCPAudit" },
    );

    // Should NOT have called assumeRole for admin's own account
    expect(assumeRole).not.toHaveBeenCalled();
  });

  it("records error when assume role fails for a child account", async () => {
    vi.mocked(listOrgAccounts).mockResolvedValue([
      { id: "000000000000", name: "Admin", email: "admin@test.com", status: "ACTIVE" },
      { id: "999999999999", name: "FailChild", email: "fail@test.com", status: "ACTIVE" },
    ]);
    vi.mocked(assumeRole).mockRejectedValue(new Error("AccessDenied"));

    const scanner = createMockScanner("ssl_certificate");

    const result = await runMultiAccountScanners(
      [scanner],
      "us-east-1",
      { orgMode: true, roleName: "AWSSecurityMCPAudit" },
    );

    // Admin account scanner runs, child account fails on assume role
    expect(scanner.scan).toHaveBeenCalledTimes(1); // only admin
    const errorModule = result.modules.find((m) => m.module.startsWith("assume_role_"));
    expect(errorModule).toBeDefined();
    expect(errorModule!.status).toBe("error");
    expect(errorModule!.error).toContain("999999999999");
  });

  it("filters to specific account IDs when provided", async () => {
    vi.mocked(listOrgAccounts).mockResolvedValue([
      { id: "000000000000", name: "Admin", email: "admin@test.com", status: "ACTIVE" },
      { id: "111111111111", name: "Target", email: "target@test.com", status: "ACTIVE" },
      { id: "222222222222", name: "Excluded", email: "excluded@test.com", status: "ACTIVE" },
    ]);
    vi.mocked(assumeRole).mockResolvedValue({
      accessKeyId: "ASIA_KEY",
      secretAccessKey: "secret",
      sessionToken: "token",
    });

    const scanner = createMockScanner("ssl_certificate");

    const result = await runMultiAccountScanners(
      [scanner],
      "us-east-1",
      { orgMode: true, roleName: "AWSSecurityMCPAudit", accountIds: ["111111111111"] },
    );

    // Only the specified account should be scanned
    expect(scanner.scan).toHaveBeenCalledTimes(1);
    expect(result.modules).toHaveLength(1);
  });

  it("stamps accountId and accountAlias on findings", async () => {
    vi.mocked(listOrgAccounts).mockResolvedValue([
      { id: "000000000000", name: "Admin", email: "admin@test.com", status: "ACTIVE" },
    ]);

    const scanner: Scanner = {
      moduleName: "test_scanner",
      scan: vi.fn().mockResolvedValue({
        module: "test_scanner",
        status: "success",
        resourcesScanned: 1,
        findingsCount: 1,
        scanTimeMs: 10,
        findings: [{
          severity: "HIGH",
          title: "Test",
          resourceType: "AWS::Test",
          resourceId: "r1",
          resourceArn: "arn:aws:test::r1",
          region: "us-east-1",
          description: "test",
          impact: "test",
          riskScore: 8.0,
          remediationSteps: ["fix"],
          priority: "P1",
        }],
      }),
    };

    const result = await runMultiAccountScanners(
      [scanner],
      "us-east-1",
      { orgMode: true, roleName: "AWSSecurityMCPAudit" },
    );

    expect(result.modules[0].findings[0].accountId).toBe("000000000000");
    expect(result.modules[0].findings[0].accountAlias).toBe("Admin");
  });
});

describe("runMultiAccountScanners — exploitability post-process (T4)", () => {
  beforeEach(() => {
    vi.mocked(listOrgAccounts).mockReset();
    vi.mocked(assumeRole).mockReset();
  });

  it("org mode: dedupes aggregation results (security_hub vs inspector) before the summary", async () => {
    vi.mocked(listOrgAccounts).mockResolvedValue([
      { id: "000000000000", name: "Admin", email: "admin@test.com", status: "ACTIVE" },
    ]);
    const [inspector, sh] = acceptanceModules();
    const result = await runMultiAccountScanners(
      [
        { moduleName: inspector.module, scan: vi.fn().mockResolvedValue(inspector) },
        { moduleName: sh.module, scan: vi.fn().mockResolvedValue(sh) },
        createMockScanner("ssl_certificate"),
      ],
      "cn-north-1",
      { orgMode: true, roleName: "AWSSecurityMCPAudit" },
    );

    const shOut = result.modules.find((m) => m.module === "security_hub_findings")!;
    expect(shOut.findings.filter((f) => f.source === "Inspector")).toHaveLength(1);
    expect(shOut.findingsCount).toBe(2);
    expect(shOut.warnings?.some((w) => w.includes("Deduplicated 3"))).toBe(true);
    expect(result.summary.totalFindings).toBe(5);
  });

  it("org mode: detection-only Inspector leaves Security Hub findings untouched", async () => {
    vi.mocked(listOrgAccounts).mockResolvedValue([
      { id: "000000000000", name: "Admin", email: "admin@test.com", status: "ACTIVE" },
    ]);
    const [inspector, sh] = acceptanceModules("detection-only");
    const result = await runMultiAccountScanners(
      [
        { moduleName: inspector.module, scan: vi.fn().mockResolvedValue(inspector) },
        { moduleName: sh.module, scan: vi.fn().mockResolvedValue(sh) },
      ],
      "cn-north-1",
      { orgMode: true, roleName: "AWSSecurityMCPAudit" },
    );

    const shOut = result.modules.find((m) => m.module === "security_hub_findings")!;
    expect(shOut.findings).toHaveLength(5);
    expect(result.summary.totalFindings).toBe(5);
  });

  it("org mode with account_ids filter: dedupes after the aggregation filter", async () => {
    vi.mocked(listOrgAccounts).mockResolvedValue([
      { id: "123456789012", name: "Member", email: "m@test.com", status: "ACTIVE" },
    ]);
    vi.mocked(assumeRole).mockResolvedValue({
      accessKeyId: "ASIA_FAKE",
      secretAccessKey: "fake",
      sessionToken: "fake",
    });
    const [inspector, sh] = acceptanceModules();
    const result = await runMultiAccountScanners(
      [
        { moduleName: inspector.module, scan: vi.fn().mockResolvedValue(inspector) },
        { moduleName: sh.module, scan: vi.fn().mockResolvedValue(sh) },
      ],
      "cn-north-1",
      { orgMode: true, roleName: "AWSSecurityMCPAudit", accountIds: ["123456789012"] },
    );

    const shOut = result.modules.find((m) => m.module === "security_hub_findings")!;
    expect(shOut.findings).toHaveLength(2);
    expect(shOut.findingsCount).toBe(2);
    expect(result.summary.totalFindings).toBe(5);
  });
});
