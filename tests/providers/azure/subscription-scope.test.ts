/**
 * Phase 2 (Azure) T0 — multi-subscription scopes (plan §3.3).
 * The subscription enumeration seam (`providers/azure/subscriptions.ts`, real
 * SubscriptionClient lands in T1) is mocked; fake service principal only, no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ listAzureSubscriptions: vi.fn() }));

vi.mock("../../../src/providers/azure/subscriptions.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../src/providers/azure/subscriptions.js")>();
  return { ...actual, listAzureSubscriptions: mocks.listAzureSubscriptions };
});

import { getProvider } from "../../../src/providers/registry.js";
import { AZURE_NO_SUBSCRIPTION } from "../../../src/providers/azure/index.js";
import { runAllScanners, buildScanContext } from "../../../src/scanners/runner.js";
import type { Scanner } from "../../../src/scanners/base.js";
import type { AzureCredentials, ScanContext, ScanResult } from "../../../src/types.js";

const FAKE_TENANT = "00000000-0000-0000-0000-00000000fake";
const FAKE_CLIENT = "11111111-1111-1111-1111-11111111fake";
const FAKE_SECRET = "FakeAzureClientSecretValue~DoNotUse-0000000000";
const SUB_A = "aaaaaaaa-0000-0000-0000-00000000fake";
const SUB_B = "bbbbbbbb-0000-0000-0000-00000000fake";
const SUB_C = "cccccccc-0000-0000-0000-00000000fake";
const OTHER_TENANT = "99999999-0000-0000-0000-00000000fake";

const FAKE_AZ: AzureCredentials = {
  kind: "azure",
  tenantId: FAKE_TENANT,
  clientId: FAKE_CLIENT,
  clientSecret: FAKE_SECRET,
  cloud: "china",
};

const AZURE_ENV = [
  "AZURE_TENANT_ID",
  "AZURE_CLIENT_ID",
  "AZURE_CLIENT_SECRET",
  "AZURE_CLOUD",
  "AZURE_SUBSCRIPTION_ID",
] as const;

function stubServicePrincipalEnv(): void {
  vi.stubEnv("AZURE_TENANT_ID", FAKE_TENANT);
  vi.stubEnv("AZURE_CLIENT_ID", FAKE_CLIENT);
  vi.stubEnv("AZURE_CLIENT_SECRET", FAKE_SECRET);
}

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
      warnings: [`scanned ${ctx.subscriptionId ?? "-"}`],
    })),
  };
}

const ctxOf = (s: { scan: ReturnType<typeof vi.fn> }, call = 0) => s.scan.mock.calls[call][0] as ScanContext;

beforeEach(() => {
  vi.clearAllMocks();
  // Never let a real environment leak into these tests: blank every Azure variable.
  for (const name of AZURE_ENV) vi.stubEnv(name, "");
  mocks.listAzureSubscriptions.mockResolvedValue([
    { subscriptionId: SUB_A, tenantId: FAKE_TENANT, displayName: "prod", state: "Enabled" },
    { subscriptionId: SUB_B, displayName: "dev", state: "Warned" },
  ]);
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("azure listRegions — subscription scopes", () => {
  it("returns one scope per visible subscription (region = subscriptionId, domainId = tenantId)", async () => {
    const p = getProvider("azure");
    await expect(p.listRegions(FAKE_AZ)).resolves.toEqual([
      { region: SUB_A, domainId: FAKE_TENANT },
      { region: SUB_B, domainId: FAKE_TENANT },
    ]);
    expect(mocks.listAzureSubscriptions).toHaveBeenCalledTimes(1);
    expect(mocks.listAzureSubscriptions).toHaveBeenCalledWith(FAKE_AZ);
  });

  it("skips disabled / deleted / blank / duplicate subscriptions and keeps a subscription's own tenant", async () => {
    mocks.listAzureSubscriptions.mockResolvedValue([
      { subscriptionId: SUB_A, state: "Enabled" },
      { subscriptionId: SUB_B, state: "Disabled" },
      { subscriptionId: SUB_C, tenantId: OTHER_TENANT, state: "PastDue" },
      { subscriptionId: "dddddddd-0000-0000-0000-00000000fake", state: "Deleted" },
      { subscriptionId: SUB_A.toUpperCase(), state: "Enabled" },
      { subscriptionId: "  " },
    ]);
    await expect(getProvider("azure").listRegions(FAKE_AZ)).resolves.toEqual([
      { region: SUB_A, domainId: FAKE_TENANT },
      { region: SUB_C, domainId: OTHER_TENANT },
    ]);
  });

  it("uses the env service principal when no explicit credentials are given", async () => {
    stubServicePrincipalEnv();
    vi.stubEnv("AZURE_CLOUD", "global");
    const scopes = await getProvider("azure").listRegions();
    expect(scopes.map((s) => s.region)).toEqual([SUB_A, SUB_B]);
    expect(mocks.listAzureSubscriptions).toHaveBeenCalledWith({
      kind: "azure",
      tenantId: FAKE_TENANT,
      clientId: FAKE_CLIENT,
      clientSecret: FAKE_SECRET,
      cloud: "global",
      source: "env",
    });
  });

  it("AZURE_SUBSCRIPTION_ID pins the scan to a single subscription", async () => {
    vi.stubEnv("AZURE_SUBSCRIPTION_ID", SUB_B);
    await expect(getProvider("azure").listRegions(FAKE_AZ)).resolves.toEqual([{ region: SUB_B, domainId: FAKE_TENANT }]);
  });

  it("falls back to AZURE_SUBSCRIPTION_ID when enumeration fails", async () => {
    mocks.listAzureSubscriptions.mockRejectedValue(new Error("enumeration unavailable"));
    vi.stubEnv("AZURE_SUBSCRIPTION_ID", SUB_C);
    await expect(getProvider("azure").listRegions(FAKE_AZ)).resolves.toEqual([{ region: SUB_C, domainId: FAKE_TENANT }]);
  });

  it("falls back to the requested subscription when enumeration fails", async () => {
    mocks.listAzureSubscriptions.mockRejectedValue(new Error("enumeration unavailable"));
    await expect(getProvider("azure").listRegions(FAKE_AZ, SUB_C)).resolves.toEqual([
      { region: SUB_C, domainId: FAKE_TENANT },
    ]);
  });

  it("propagates the enumeration failure when there is no subscription to fall back to", async () => {
    mocks.listAzureSubscriptions.mockRejectedValue(new Error("enumeration unavailable"));
    await expect(getProvider("azure").listRegions(FAKE_AZ)).rejects.toThrow("enumeration unavailable");
  });

  it("without credentials returns only the requested / pinned subscription (no enumeration)", async () => {
    const p = getProvider("azure");
    await expect(p.listRegions()).resolves.toEqual([]);
    await expect(p.listRegions(undefined, SUB_A)).resolves.toEqual([{ region: SUB_A }]);
    vi.stubEnv("AZURE_SUBSCRIPTION_ID", SUB_B);
    await expect(p.listRegions()).resolves.toEqual([{ region: SUB_B }]);
    expect(mocks.listAzureSubscriptions).not.toHaveBeenCalled();
  });

  it("the T0 seam stub throws a clear not-implemented error", async () => {
    const actual = await vi.importActual<typeof import("../../../src/providers/azure/subscriptions.js")>(
      "../../../src/providers/azure/subscriptions.js",
    );
    await expect(actual.listAzureSubscriptions(FAKE_AZ)).rejects.toBeInstanceOf(
      actual.AzureSubscriptionEnumerationUnavailableError,
    );
    await expect(actual.listAzureSubscriptions(FAKE_AZ)).rejects.toThrow(/AZURE_SUBSCRIPTION_ID/);
  });
});

describe("azure runner — multi-subscription scan", () => {
  beforeEach(() => {
    stubServicePrincipalEnv();
  });

  it.each([undefined, "all"])(
    "region=%j: every subscription is scanned; tenant-level modules run once",
    async (region) => {
      const regional = mockScanner("public_access_verify");
      const global = mockScanner("iam_privilege_escalation");

      const result = await runAllScanners([regional, global], region as string, { provider: "azure" });

      expect(result.provider).toBe("azure");
      expect(result.region).toBe("all");
      expect(result.accountId).toBe(FAKE_TENANT);

      expect(global.scan).toHaveBeenCalledTimes(1);
      expect(ctxOf(global).subscriptionId).toBe(SUB_A);

      expect(regional.scan).toHaveBeenCalledTimes(2);
      expect(ctxOf(regional, 0)).toEqual({
        region: SUB_A,
        partition: "azure",
        accountId: FAKE_TENANT,
        provider: "azure",
        subscriptionId: SUB_A,
        tenantId: FAKE_TENANT,
        cloud: "china",
      });
      expect(ctxOf(regional, 1)).toMatchObject({
        region: SUB_B,
        subscriptionId: SUB_B,
        tenantId: FAKE_TENANT,
        cloud: "china",
        primaryRegionScope: false,
      });
      expect(result.modules.map((m) => m.module)).toEqual([
        "iam_privilege_escalation",
        "public_access_verify",
        "public_access_verify",
      ]);
      expect(JSON.stringify(result)).not.toContain(FAKE_SECRET);
    },
  );

  it("a given subscription ID scans that subscription only", async () => {
    const regional = mockScanner("public_access_verify");
    const global = mockScanner("iam_privilege_escalation");

    const result = await runAllScanners([regional, global], SUB_B, { provider: "azure" });

    expect(result.region).toBe(SUB_B);
    expect(regional.scan).toHaveBeenCalledTimes(1);
    expect(global.scan).toHaveBeenCalledTimes(1);
    expect(ctxOf(regional)).toMatchObject({ region: SUB_B, subscriptionId: SUB_B, tenantId: FAKE_TENANT });
    expect(result.modules[0].warnings).toEqual(["scanned " + SUB_B]);
  });

  it("an unknown subscription ID is scanned anyway with an Azure-worded warning", async () => {
    const regional = mockScanner("public_access_verify");
    const result = await runAllScanners([regional], SUB_C, { provider: "azure" });

    expect(ctxOf(regional)).toMatchObject({ subscriptionId: SUB_C, tenantId: FAKE_TENANT });
    expect(result.modules[0].warnings?.[0]).toBe(
      `Azure subscription "${SUB_C}" is not among the subscriptions visible to the service principal (known: ${SUB_A}, ${SUB_B}); scanning it anyway.`,
    );
  });

  it("enumeration failure + AZURE_SUBSCRIPTION_ID: scans the pinned subscription", async () => {
    mocks.listAzureSubscriptions.mockRejectedValue(new Error("enumeration unavailable"));
    vi.stubEnv("AZURE_SUBSCRIPTION_ID", SUB_C);
    const regional = mockScanner("public_access_verify");

    const result = await runAllScanners([regional], "all", { provider: "azure" });

    expect(regional.scan).toHaveBeenCalledTimes(1);
    expect(ctxOf(regional)).toMatchObject({ region: SUB_C, subscriptionId: SUB_C, tenantId: FAKE_TENANT });
    expect(result.modules[0].warnings).toEqual(["scanned " + SUB_C]);
  });

  it("enumeration failure without a fallback: warns and runs once with no subscriptionId", async () => {
    mocks.listAzureSubscriptions.mockRejectedValue(new Error("enumeration unavailable"));
    const regional = mockScanner("public_access_verify");

    const result = await runAllScanners([regional], "all", { provider: "azure" });

    expect(regional.scan).toHaveBeenCalledTimes(1);
    const ctx = ctxOf(regional);
    expect(ctx.region).toBe(AZURE_NO_SUBSCRIPTION);
    expect(ctx.subscriptionId).toBeUndefined();
    expect(ctx.tenantId).toBe(FAKE_TENANT);
    expect(result.modules[0].warnings?.[0]).toBe(
      "Azure subscription enumeration failed: enumeration unavailable. No subscription to scan; set AZURE_SUBSCRIPTION_ID or pass a subscription ID as region.",
    );
  });

  it("no visible subscriptions: warns with the Azure wording", async () => {
    mocks.listAzureSubscriptions.mockResolvedValue([]);
    const regional = mockScanner("public_access_verify");

    const result = await runAllScanners([regional], "all", { provider: "azure" });

    expect(ctxOf(regional).subscriptionId).toBeUndefined();
    expect(result.modules[0].warnings?.[0]).toBe(
      "Azure subscription enumeration returned no subscriptions visible to the service principal; set AZURE_SUBSCRIPTION_ID or pass a subscription ID as region.",
    );
  });

  it("AZURE_CLOUD=global flows into the ScanContext", async () => {
    vi.stubEnv("AZURE_CLOUD", "global");
    const regional = mockScanner("public_access_verify");
    await runAllScanners([regional], SUB_A, { provider: "azure" });
    expect(ctxOf(regional).cloud).toBe("global");
  });

  it("buildScanContext resolves the single-module context for a subscription", async () => {
    await expect(buildScanContext(SUB_B, "azure")).resolves.toEqual({
      region: SUB_B,
      partition: "azure",
      accountId: FAKE_TENANT,
      provider: "azure",
      subscriptionId: SUB_B,
      tenantId: FAKE_TENANT,
      cloud: "china",
    });
  });
});
