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
    // No requested / pinned subscription: the credentials-not-found error propagates (FIX-FINAL-R1b).
    await expect(p.listRegions()).rejects.toThrow(/^Azure credentials not found\./);
    await expect(p.listRegions(undefined, SUB_A)).resolves.toEqual([{ region: SUB_A }]);
    vi.stubEnv("AZURE_SUBSCRIPTION_ID", SUB_B);
    await expect(p.listRegions()).resolves.toEqual([{ region: SUB_B }]);
    expect(mocks.listAzureSubscriptions).not.toHaveBeenCalled();
  });

  it("the seam re-exports the SubscriptionClient implementation from client.ts (T1)", async () => {
    const actual = await vi.importActual<typeof import("../../../src/providers/azure/subscriptions.js")>(
      "../../../src/providers/azure/subscriptions.js",
    );
    const client = await vi.importActual<typeof import("../../../src/providers/azure/client.js")>(
      "../../../src/providers/azure/client.js",
    );
    expect(actual.listAzureSubscriptions).toBe(client.listAzureSubscriptions);
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

describe("azure runner — enumeration failure with no subscription fallback (real subscription-scoped scanners)", () => {
  // The 11 subscription-scoped modules; with no subscription in scope they return before
  // touching any SDK (iam_privilege_escalation enumerates subscriptions itself — excluded).
  const subscriptionScanners = () =>
    getProvider("azure")
      .scanners()
      .filter((s) => s.moduleName !== "iam_privilege_escalation");

  beforeEach(() => {
    stubServicePrincipalEnv();
  });

  it("covers all 11 subscription-scoped modules", () => {
    expect(subscriptionScanners()).toHaveLength(11);
  });

  it.each([undefined, "all"])(
    "region=%j: auth_failed enumeration → every subscription-scoped module status error with the auth text",
    async (region) => {
      const { toAzureError, AZURE_AUTH_FAILED_PREFIX } = await import("../../../src/providers/azure/errors.js");
      const { authError } = await import("./scanners/helpers.js");
      mocks.listAzureSubscriptions.mockRejectedValue(toAzureError(authError(), "subscriptions.list"));

      const result = await runAllScanners(subscriptionScanners(), region as string, { provider: "azure" });

      expect(result.modules).toHaveLength(11);
      for (const m of result.modules) {
        expect(m.status, m.module).toBe("error");
        expect(m.error!.startsWith(AZURE_AUTH_FAILED_PREFIX), m.module).toBe(true);
        expect(m.error).toContain("AADSTS900023");
        expect(m.findings).toEqual([]);
      }
      expect(result.summary.modulesError).toBe(11);
      expect(result.summary.modulesSuccess).toBe(0);
      // The runner's enumeration-failure warning is kept.
      expect(result.modules[0].warnings?.[0]).toMatch(/^Azure subscription enumeration failed: Azure authentication failed \(AADSTS900023/);
      expect(JSON.stringify(result)).not.toContain(FAKE_SECRET);
    },
  );

  it("api_misuse enumeration → status error (not a clean skip)", async () => {
    const { toAzureError } = await import("../../../src/providers/azure/errors.js");
    const { misuseError } = await import("./scanners/helpers.js");
    mocks.listAzureSubscriptions.mockRejectedValue(toAzureError(misuseError(), "subscriptions.list"));

    const result = await runAllScanners(subscriptionScanners(), "all", { provider: "azure" });

    for (const m of result.modules) {
      expect(m.status, m.module).toBe("error");
      expect(m.error).toContain("Azure subscription enumeration failed");
      expect(m.error).toContain("InvalidApiVersionParameter");
    }
  });

  it("access_denied enumeration → success + skip warning (unchanged)", async () => {
    const { toAzureError } = await import("../../../src/providers/azure/errors.js");
    const { deniedError } = await import("./scanners/helpers.js");
    mocks.listAzureSubscriptions.mockRejectedValue(toAzureError(deniedError(), "subscriptions.list"));

    const result = await runAllScanners(subscriptionScanners(), "all", { provider: "azure" });

    expect(result.modules).toHaveLength(11);
    for (const m of result.modules) {
      expect(m.status, m.module).toBe("success");
      expect(m.error).toBeUndefined();
      expect(m.warnings!.some((w) => w.includes("no Azure subscription in scope")), m.module).toBe(true);
    }
    expect(result.modules[0].warnings?.[0]).toMatch(/^Azure subscription enumeration failed: /);
  });

  it("empty subscription list → success + skip warning (unchanged), also right after an auth failure", async () => {
    const { toAzureError } = await import("../../../src/providers/azure/errors.js");
    const { authError } = await import("./scanners/helpers.js");
    mocks.listAzureSubscriptions.mockRejectedValueOnce(toAzureError(authError(), "subscriptions.list"));
    const failed = await runAllScanners(subscriptionScanners(), "all", { provider: "azure" });
    expect(failed.modules.every((m) => m.status === "error")).toBe(true);

    mocks.listAzureSubscriptions.mockResolvedValue([]);
    const result = await runAllScanners(subscriptionScanners(), "all", { provider: "azure" });

    for (const m of result.modules) {
      expect(m.status, m.module).toBe("success");
      expect(m.warnings!.some((w) => w.includes("no Azure subscription in scope")), m.module).toBe(true);
    }
    expect(result.modules[0].warnings?.[0]).toBe(
      "Azure subscription enumeration returned no subscriptions visible to the service principal; set AZURE_SUBSCRIPTION_ID or pass a subscription ID as region.",
    );
  });

  it("auth_failed enumeration + AZURE_SUBSCRIPTION_ID fallback: the placeholder error is not attached", async () => {
    const { toAzureError } = await import("../../../src/providers/azure/errors.js");
    const { authError } = await import("./scanners/helpers.js");
    mocks.listAzureSubscriptions.mockRejectedValue(toAzureError(authError(), "subscriptions.list"));
    vi.stubEnv("AZURE_SUBSCRIPTION_ID", SUB_C);
    const regional = mockScanner("public_access_verify");

    await runAllScanners([regional], "all", { provider: "azure" });

    expect(ctxOf(regional)).toMatchObject({ subscriptionId: SUB_C });
    expect(ctxOf(regional).azureScopeError).toBeUndefined();
  });
});

describe("azure runner — no credentials (real subscription-scoped scanners)", () => {
  const subscriptionScanners = () =>
    getProvider("azure")
      .scanners()
      .filter((s) => s.moduleName !== "iam_privilege_escalation");
  // beforeEach above blanks every AZURE_* variable: no service principal is resolvable.

  it.each([undefined, "all"])(
    "region=%j: every subscription-scoped module status error with the credentials-not-found text",
    async (region) => {
      const result = await runAllScanners(subscriptionScanners(), region as string, { provider: "azure" });

      expect(mocks.listAzureSubscriptions).not.toHaveBeenCalled();
      expect(result.modules).toHaveLength(11);
      for (const m of result.modules) {
        expect(m.status, m.module).toBe("error");
        expect(m.error, m.module).toMatch(/^Azure credentials not found\. /);
        expect(m.error).toContain("Missing: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET.");
        expect(m.findings).toEqual([]);
      }
      expect(result.summary.modulesError).toBe(11);
      expect(result.summary.modulesSuccess).toBe(0);
      const warning = result.modules[0].warnings?.[0];
      expect(warning).toMatch(/^Azure subscription enumeration failed: Azure credentials not found\./);
      expect(JSON.stringify(result)).not.toContain("no subscriptions visible to the service principal");
    },
  );

  it("explicit subscription as region → every subscription-scoped module status error", async () => {
    const result = await runAllScanners(subscriptionScanners(), SUB_A, { provider: "azure" });

    expect(mocks.listAzureSubscriptions).not.toHaveBeenCalled();
    expect(result.modules).toHaveLength(11);
    for (const m of result.modules) {
      expect(m.status, m.module).toBe("error");
      expect(m.error, m.module).toContain("Azure credentials not found.");
      expect(m.findings).toEqual([]);
    }
    expect(result.summary.modulesSuccess).toBe(0);
    expect(JSON.stringify(result)).not.toContain("no subscriptions visible to the service principal");
  });

  it("valid credentials + empty subscription list right after a no-credentials run → success + warning (unchanged)", async () => {
    const failed = await runAllScanners(subscriptionScanners(), "all", { provider: "azure" });
    expect(failed.modules.every((m) => m.status === "error")).toBe(true);

    stubServicePrincipalEnv();
    mocks.listAzureSubscriptions.mockResolvedValue([]);
    const result = await runAllScanners(subscriptionScanners(), "all", { provider: "azure" });

    for (const m of result.modules) {
      expect(m.status, m.module).toBe("success");
      expect(m.error).toBeUndefined();
      expect(m.warnings!.some((w) => w.includes("no Azure subscription in scope")), m.module).toBe(true);
    }
    expect(result.modules[0].warnings?.[0]).toBe(
      "Azure subscription enumeration returned no subscriptions visible to the service principal; set AZURE_SUBSCRIPTION_ID or pass a subscription ID as region.",
    );
    expect(JSON.stringify(result)).not.toContain(FAKE_SECRET);
  });
});
