/**
 * T8 — provider-aware orchestration.
 *  - AWS: `provider` omitted vs `provider: "aws"` must be deep-equal (byte-identical JSON).
 *  - Huawei Cloud: single-account orchestration through a mocked provider (no network).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => {
  const hwProvider = {
    id: "huaweicloud" as const,
    getAccountId: vi.fn(),
    listRegions: vi.fn(),
    scanners: vi.fn(() => []),
    toResourceUrn: vi.fn(() => "hws:x"),
  };
  const awsProvider = { id: "aws" as const, scanners: vi.fn(() => []) };
  return { hwProvider, awsProvider };
});

vi.mock("../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: vi.fn() })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));

vi.mock("../src/utils/org-accounts.js", () => ({
  listOrgAccounts: vi.fn().mockResolvedValue([{ id: "123456789012", name: "Admin", email: "a@t", status: "ACTIVE" }]),
}));

vi.mock("../src/utils/assume-role.js", () => ({
  assumeRole: vi.fn(),
  buildRoleArn: vi.fn(() => "arn:aws:iam::0:role/x"),
}));

// Keep the Huawei provider module (and its SDK/log4js plumbing) out of this test entirely.
vi.mock("../src/providers/huaweicloud/index.js", () => ({
  HUAWEI_PARTITION: "huaweicloud",
  DEFAULT_HUAWEI_REGION: "cn-north-4",
}));

vi.mock("../src/providers/registry.js", () => ({
  DEFAULT_PROVIDER_ID: "aws",
  isProviderId: (id: string) => id === "aws" || id === "huaweicloud",
  listProviderIds: () => ["aws", "huaweicloud"],
  getProvider: vi.fn((id: string = "aws") => (id === "huaweicloud" ? mocks.hwProvider : mocks.awsProvider)),
}));

import {
  runAllScanners,
  runMultiAccountScanners,
  buildScanContext,
  HUAWEI_MULTI_ACCOUNT_WARNING,
  HUAWEI_GLOBAL_MODULES,
} from "../src/scanners/runner.js";
import type { Scanner } from "../src/scanners/base.js";
import type { ScanContext, ScanResult, Finding } from "../src/types.js";

function finding(id: string): Finding {
  return {
    severity: "HIGH",
    title: `Issue ${id}`,
    resourceType: "hws:obs:bucket",
    resourceId: id,
    resourceArn: `hws:cn-north-4:d0m41n:obs:bucket:${id}`,
    region: "cn-north-4",
    description: "d",
    impact: "i",
    riskScore: 7.5,
    remediationSteps: ["fix"],
    priority: "P1",
  };
}

function mockScanner(name: string, findings: Finding[] = []): Scanner {
  return {
    moduleName: name,
    scan: vi.fn(async (ctx: ScanContext): Promise<ScanResult> => ({
      module: name,
      status: "success",
      resourcesScanned: 1,
      findingsCount: findings.length,
      scanTimeMs: 1,
      findings: findings.map((f) => ({ ...f, region: ctx.region })),
    })),
  };
}

const SCOPES = [
  { region: "cn-north-4", projectId: "p-north-4", domainId: "d0m41n" },
  { region: "cn-east-3", projectId: "p-east-3", domainId: "d0m41n" },
];

describe("runner — AWS path is unchanged when provider is omitted or 'aws'", () => {
  beforeEach(() => {
    vi.useFakeTimers({ now: new Date("2026-09-13T00:00:00.000Z") });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("runAllScanners: omitted vs provider:'aws' produce deep-equal results and identical ScanContext", async () => {
    const a = mockScanner("mod_a", [finding("r1")]);
    const b = mockScanner("mod_a", [finding("r1")]);

    const withoutProvider = await runAllScanners([a], "us-east-1");
    const withAws = await runAllScanners([b], "us-east-1", { provider: "aws" });

    expect(withAws).toEqual(withoutProvider);
    expect(JSON.stringify(withAws)).toBe(JSON.stringify(withoutProvider));
    // No provider field leaks into the legacy serialization.
    expect("provider" in withoutProvider).toBe(false);
    expect("provider" in withAws).toBe(false);
    // ScanContext is exactly the historical shape (no provider / projectId / domainId keys).
    expect(a.scan).toHaveBeenCalledWith({ region: "us-east-1", partition: "aws", accountId: "123456789012" });
    expect(b.scan).toHaveBeenCalledWith({ region: "us-east-1", partition: "aws", accountId: "123456789012" });
  });

  it("runMultiAccountScanners: omitted vs provider:'aws' produce deep-equal results", async () => {
    const a = mockScanner("ssl_certificate", [finding("c1")]);
    const b = mockScanner("ssl_certificate", [finding("c1")]);
    const opts = { orgMode: true, roleName: "AWSSecurityMCPAudit" };

    const withoutProvider = await runMultiAccountScanners([a], "us-east-1", opts);
    const withAws = await runMultiAccountScanners([b], "us-east-1", { ...opts, provider: "aws" });

    expect(withAws).toEqual(withoutProvider);
    expect(JSON.stringify(withAws)).toBe(JSON.stringify(withoutProvider));
    expect(mocks.hwProvider.listRegions).not.toHaveBeenCalled();
  });

  it("buildScanContext defaults to the AWS shape", async () => {
    await expect(buildScanContext("us-east-1")).resolves.toEqual({ region: "us-east-1", partition: "aws", accountId: "123456789012" });
    await expect(buildScanContext("us-east-1", "aws")).resolves.toEqual({ region: "us-east-1", partition: "aws", accountId: "123456789012" });
  });
});

describe("runner — Huawei Cloud single-account orchestration", () => {
  beforeEach(() => {
    mocks.hwProvider.listRegions.mockReset().mockResolvedValue(SCOPES);
    mocks.hwProvider.getAccountId.mockReset().mockResolvedValue("d0m41n");
  });

  it("single region: resolves projectId/domainId, stamps provider on context and result", async () => {
    const s = mockScanner("public_access_verify", [finding("bucket-1")]);
    const result = await runAllScanners([s], "cn-north-4", { provider: "huaweicloud" });

    expect(mocks.hwProvider.listRegions).toHaveBeenCalledWith(undefined, "cn-north-4");
    expect(s.scan).toHaveBeenCalledTimes(1);
    expect(s.scan).toHaveBeenCalledWith({
      region: "cn-north-4",
      partition: "huaweicloud",
      accountId: "d0m41n",
      provider: "huaweicloud",
      projectId: "p-north-4",
      domainId: "d0m41n",
    });
    expect(result.provider).toBe("huaweicloud");
    expect(result.accountId).toBe("d0m41n");
    expect(result.region).toBe("cn-north-4");
    expect(result.modules).toHaveLength(1);
    expect(result.modules[0].warnings).toBeUndefined();
    expect(result.modules[0].findings[0].accountId).toBe("d0m41n");
    expect(result.summary.high).toBe(1);
  });

  it("region 'all' (or omitted): global modules run once, regional modules once per region", async () => {
    const global = mockScanner("rms_compliance_findings");
    const tracker = mockScanner("config_rules_findings");
    const regional = mockScanner("idle_resources");
    expect(HUAWEI_GLOBAL_MODULES.has("rms_compliance_findings")).toBe(true);
    expect(HUAWEI_GLOBAL_MODULES.has("config_rules_findings")).toBe(true);

    const result = await runAllScanners([global, tracker, regional], "all", { provider: "huaweicloud" });

    expect(mocks.hwProvider.listRegions).toHaveBeenCalledWith(undefined, undefined);
    expect(global.scan).toHaveBeenCalledTimes(1);
    expect(tracker.scan).toHaveBeenCalledTimes(1);
    expect(regional.scan).toHaveBeenCalledTimes(2);
    const regions = (regional.scan as ReturnType<typeof vi.fn>).mock.calls.map((c) => (c[0] as ScanContext).region);
    expect(regions).toEqual(["cn-north-4", "cn-east-3"]);
    const projects = (regional.scan as ReturnType<typeof vi.fn>).mock.calls.map((c) => (c[0] as ScanContext).projectId);
    expect(projects).toEqual(["p-north-4", "p-east-3"]);
    expect(result.region).toBe("all");
    expect(result.modules.map((m) => m.module)).toEqual([
      "rms_compliance_findings",
      "config_rules_findings",
      "idle_resources",
      "idle_resources",
    ]);

    const omitted = await runAllScanners([mockScanner("idle_resources")], "", { provider: "huaweicloud" });
    expect(omitted.region).toBe("all");
    expect(omitted.modules).toHaveLength(2);
  });

  it("unknown region: scans it anyway with a warning and no projectId", async () => {
    const s = mockScanner("ssl_certificate");
    const result = await runAllScanners([s], "ap-nowhere-9", { provider: "huaweicloud" });

    const ctx = (s.scan as ReturnType<typeof vi.fn>).mock.calls[0][0] as ScanContext;
    expect(ctx.region).toBe("ap-nowhere-9");
    expect(ctx.projectId).toBeUndefined();
    expect(ctx.domainId).toBe("d0m41n");
    expect(result.modules[0].warnings?.[0]).toMatch(/"ap-nowhere-9" is not among this account's IAM region projects \(known: cn-north-4, cn-east-3\)/);
  });

  it("region discovery failure degrades gracefully (warning, accountId unknown, scan still runs)", async () => {
    mocks.hwProvider.listRegions.mockRejectedValue(new Error("Huawei Cloud credentials not found"));
    mocks.hwProvider.getAccountId.mockRejectedValue(new Error("no creds"));
    const s = mockScanner("secret_exposure");

    const result = await runAllScanners([s], "all", { provider: "huaweicloud" });

    expect(result.accountId).toBe("unknown");
    expect(result.modules[0].status).toBe("success");
    expect(result.modules[0].warnings?.[0]).toMatch(/region discovery failed: Huawei Cloud credentials not found\. Scanning cn-north-4 only/);
    expect(s.scan).toHaveBeenCalledWith({
      region: "cn-north-4",
      partition: "huaweicloud",
      accountId: "unknown",
      provider: "huaweicloud",
    });
  });

  it("scanner exceptions become error modules (same as AWS)", async () => {
    const boom: Scanner = { moduleName: "tag_compliance", scan: vi.fn().mockRejectedValue(new Error("RMS 500")) };
    const result = await runAllScanners([boom], "cn-north-4", { provider: "huaweicloud" });
    expect(result.modules[0]).toMatchObject({ module: "tag_compliance", status: "error", error: "RMS 500" });
    expect(result.summary.modulesError).toBe(1);
  });

  it("org_mode: Phase 1 falls back to single account with an explicit warning", async () => {
    const s = mockScanner("ssl_certificate");
    const result = await runMultiAccountScanners([s], "cn-north-4", {
      orgMode: true,
      roleName: "SecurityAuditAgency",
      provider: "huaweicloud",
    });

    expect(s.scan).toHaveBeenCalledTimes(1);
    expect(result.provider).toBe("huaweicloud");
    expect(result.modules[0].warnings?.[0]).toBe(HUAWEI_MULTI_ACCOUNT_WARNING);
    expect(HUAWEI_MULTI_ACCOUNT_WARNING).toMatch(/Organizations listAccounts \+ STS assumeAgency/);
  });

  it("buildScanContext('…', 'huaweicloud') builds the Huawei context", async () => {
    await expect(buildScanContext("cn-east-3", "huaweicloud")).resolves.toEqual({
      region: "cn-east-3",
      partition: "huaweicloud",
      accountId: "d0m41n",
      provider: "huaweicloud",
      projectId: "p-east-3",
      domainId: "d0m41n",
    });
  });
});
