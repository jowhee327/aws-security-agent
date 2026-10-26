/**
 * Phase 2 T0 — generic regional-provider orchestration (runner.ts), exercised with a
 * fake regional provider that declares every optional hook (no SDKs, no network).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const mocks = vi.hoisted(() => {
  const FAKE_AK = "LTAI5tFAKEFAKEFAKE0000001";
  const fakeProvider = {
    id: "alicloud" as const,
    displayName: "Fake Regional Cloud",
    defaultRegion: "fk-default-1",
    globalModules: new Set(["global_mod"]),
    supportsMultiAccount: false,
    partitionFor: vi.fn((_region: string) => "fakepart"),
    contextFor: vi.fn((scope: { region: string }, accountId: string) => ({ projectId: `proj-${scope.region}-${accountId}` })),
    redactDiagnostic: vi.fn((text: string) => text.split(FAKE_AK).join("***AK***")),
    getAccountId: vi.fn(),
    listRegions: vi.fn(),
    scanners: vi.fn(() => []),
    toResourceUrn: vi.fn(() => "fake:x"),
    regionalMessages: undefined as undefined | { multiAccountUnsupported?: string },
  };
  const awsProvider = { id: "aws" as const, scanners: vi.fn(() => []) };
  return { FAKE_AK, fakeProvider, awsProvider };
});

vi.mock("../src/utils/aws-client.js", () => ({
  createClient: vi.fn(() => ({ send: vi.fn() })),
  getAccountId: vi.fn().mockResolvedValue("123456789012"),
  getPartition: vi.fn().mockReturnValue("aws"),
  getIamRegion: vi.fn().mockReturnValue("us-east-1"),
}));
vi.mock("../src/utils/org-accounts.js", () => ({ listOrgAccounts: vi.fn() }));
vi.mock("../src/utils/assume-role.js", () => ({ assumeRole: vi.fn(), buildRoleArn: vi.fn() }));

vi.mock("../src/providers/registry.js", () => ({
  DEFAULT_PROVIDER_ID: "aws",
  isProviderId: (id: string) => id === "aws" || id === "alicloud",
  listProviderIds: () => ["aws", "alicloud"],
  getProvider: vi.fn((id: string = "aws") => (id === "alicloud" ? mocks.fakeProvider : mocks.awsProvider)),
}));

import { runAllScanners, runMultiAccountScanners, buildScanContext } from "../src/scanners/runner.js";
import type { Scanner } from "../src/scanners/base.js";
import type { ScanContext, ScanResult } from "../src/types.js";

const SCOPES = [{ region: "fk-east-1" }, { region: "fk-west-1" }, { region: "fk-north-1" }];

function mockScanner(name: string): Scanner & { scan: ReturnType<typeof vi.fn> } {
  return {
    moduleName: name,
    scan: vi.fn(async (ctx: ScanContext): Promise<ScanResult> => ({
      module: name,
      status: "success",
      resourcesScanned: 1,
      findingsCount: 0,
      scanTimeMs: 1,
      findings: [],
      warnings: [`scanned ${ctx.region}`],
    })),
  };
}

const ctxOf = (s: { scan: ReturnType<typeof vi.fn> }, call = 0) => s.scan.mock.calls[call][0] as ScanContext;

beforeEach(() => {
  vi.clearAllMocks();
  mocks.fakeProvider.regionalMessages = undefined;
  mocks.fakeProvider.listRegions.mockResolvedValue(SCOPES);
  mocks.fakeProvider.getAccountId.mockResolvedValue("1234567890123456");
});

describe("regional provider — single region", () => {
  it("scans only the requested region with a context built from the hooks", async () => {
    const regional = mockScanner("regional_mod");
    const global = mockScanner("global_mod");

    const result = await runAllScanners([regional, global], "fk-west-1", { provider: "alicloud" });

    expect(result.provider).toBe("alicloud");
    expect(result.region).toBe("fk-west-1");
    expect(result.accountId).toBe("1234567890123456");
    expect(regional.scan).toHaveBeenCalledTimes(1);
    expect(global.scan).toHaveBeenCalledTimes(1);
    expect(ctxOf(regional)).toEqual({
      region: "fk-west-1",
      partition: "fakepart",
      accountId: "1234567890123456",
      provider: "alicloud",
      projectId: "proj-fk-west-1-1234567890123456",
    });
    expect(mocks.fakeProvider.partitionFor).toHaveBeenCalledWith("fk-west-1");
    expect(mocks.fakeProvider.listRegions).toHaveBeenCalledWith(undefined, "fk-west-1");
  });

  it("buildScanContext uses the same regional context", async () => {
    const ctx = await buildScanContext("fk-east-1", "alicloud");
    expect(ctx).toEqual({
      region: "fk-east-1",
      partition: "fakepart",
      accountId: "1234567890123456",
      provider: "alicloud",
      projectId: "proj-fk-east-1-1234567890123456",
    });
  });

  it("warns (generic wording) but still scans a region missing from discovery", async () => {
    const regional = mockScanner("regional_mod");
    const result = await runAllScanners([regional], "fk-south-9", { provider: "alicloud" });

    expect(ctxOf(regional).region).toBe("fk-south-9");
    expect(result.modules[0].warnings).toContain(
      'Fake Regional Cloud region "fk-south-9" is not among this account\'s regions (known: fk-east-1, fk-west-1, fk-north-1); scanning it anyway.',
    );
  });

  it("degrades accountId to \"unknown\" when account resolution fails", async () => {
    mocks.fakeProvider.getAccountId.mockRejectedValue(new Error("sts down"));
    const result = await runAllScanners([mockScanner("regional_mod")], "fk-east-1", { provider: "alicloud" });
    expect(result.accountId).toBe("unknown");
  });
});

describe("regional provider — all regions", () => {
  it.each([undefined, "all", " ALL "])("region=%j: globalModules run once, regional modules once per region", async (region) => {
    const regional = mockScanner("regional_mod");
    const global = mockScanner("global_mod");

    const result = await runAllScanners([regional, global], region as string, { provider: "alicloud" });

    expect(result.region).toBe("all");
    expect(global.scan).toHaveBeenCalledTimes(1);
    expect(ctxOf(global).region).toBe("fk-east-1");
    expect(regional.scan).toHaveBeenCalledTimes(3);
    expect(regional.scan.mock.calls.map((c) => (c[0] as ScanContext).region)).toEqual([
      "fk-east-1",
      "fk-west-1",
      "fk-north-1",
    ]);
    expect(result.modules.map((m) => m.module)).toEqual(["global_mod", "regional_mod", "regional_mod", "regional_mod"]);
    expect(mocks.fakeProvider.listRegions).toHaveBeenCalledWith(undefined, undefined);
  });

  it("falls back to defaultRegion when discovery returns nothing", async () => {
    mocks.fakeProvider.listRegions.mockResolvedValue([]);
    const regional = mockScanner("regional_mod");

    const result = await runAllScanners([regional], "all", { provider: "alicloud" });

    expect(ctxOf(regional).region).toBe("fk-default-1");
    expect(result.modules[0].warnings).toContain(
      "Fake Regional Cloud region discovery returned no regions; scanning fk-default-1 only.",
    );
  });
});

describe("regional provider — org_mode", () => {
  it("falls back to the current account with the generic multi-account warning", async () => {
    const regional = mockScanner("regional_mod");
    const result = await runMultiAccountScanners([regional], "fk-east-1", {
      provider: "alicloud",
      orgMode: true,
      roleName: "SomeRole",
    });

    expect(regional.scan).toHaveBeenCalledTimes(1);
    expect(result.accountId).toBe("1234567890123456");
    expect(result.modules[0].warnings?.[0]).toBe(
      "org_mode requested but multi-account scanning is not yet supported for alicloud. Scanning the current account only.",
    );
  });

  it("uses the provider's own multi-account warning when declared", async () => {
    mocks.fakeProvider.regionalMessages = { multiAccountUnsupported: "custom org_mode fallback warning" };
    const result = await runMultiAccountScanners([mockScanner("regional_mod")], "fk-east-1", {
      provider: "alicloud",
      orgMode: true,
      roleName: "SomeRole",
    });
    expect(result.modules[0].warnings?.[0]).toBe("custom org_mode fallback warning");
  });
});

describe("regional provider — diagnostics go through redactDiagnostic", () => {
  it("redacts scanner error text", async () => {
    const failing: Scanner = {
      moduleName: "regional_mod",
      scan: vi.fn(async () => {
        throw new Error(`InvalidAccessKeyId.NotFound: ${mocks.FAKE_AK} is invalid`);
      }),
    };

    const result = await runAllScanners([failing], "fk-east-1", { provider: "alicloud" });

    expect(result.modules[0].status).toBe("error");
    expect(result.modules[0].error).toBe("InvalidAccessKeyId.NotFound: ***AK*** is invalid");
    expect(JSON.stringify(result)).not.toContain(mocks.FAKE_AK);
    expect(mocks.fakeProvider.redactDiagnostic).toHaveBeenCalled();
  });

  it("redacts region discovery failures and falls back to the requested region", async () => {
    mocks.fakeProvider.listRegions.mockRejectedValue(new Error(`AccessKeyId=${mocks.FAKE_AK} rejected`));
    const regional = mockScanner("regional_mod");

    const result = await runAllScanners([regional], "fk-west-1", { provider: "alicloud" });

    expect(ctxOf(regional).region).toBe("fk-west-1");
    expect(result.modules[0].warnings).toContain(
      "Fake Regional Cloud region discovery failed: AccessKeyId=***AK*** rejected. Scanning fk-west-1 only.",
    );
    expect(JSON.stringify(result)).not.toContain(mocks.FAKE_AK);
  });
});
