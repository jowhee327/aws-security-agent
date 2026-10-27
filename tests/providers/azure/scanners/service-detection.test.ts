/**
 * Phase 2 (Azure) T2 — AzureServiceDetectionScanner (service_detection): 4-probe matrix
 * (Defender pricings / Policy summarize / Activity Log diagnostic settings / Key Vault),
 * shared ServiceDetectionResult + maturity, findings for Defender / Policy, degrade / error
 * matrix, pagination and hostile-field redaction. Every `@azure/*` package is mocked; fake
 * service principal only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@azure/identity", async () => ({ ClientSecretCredential: (await import("./helpers.js")).FakeClientSecretCredential }));
vi.mock("@azure/logger", () => ({ setLogLevel: () => {}, AzureLogger: { log: () => {} } }));
vi.mock("@azure/arm-security", async () => ({ SecurityCenter: (await import("./helpers.js")).fakeArmClientClass("SecurityCenter") }));
vi.mock("@azure/arm-policyinsights", async () => ({
  PolicyInsightsClient: (await import("./helpers.js")).fakeArmClientClass("PolicyInsightsClient"),
}));
vi.mock("@azure/arm-monitor", async () => ({ MonitorClient: (await import("./helpers.js")).fakeArmClientClass("MonitorClient") }));
vi.mock("@azure/arm-keyvault", async () => ({
  KeyVaultManagementClient: (await import("./helpers.js")).fakeArmClientClass("KeyVaultManagementClient"),
}));

import type { ServiceDetectionResult } from "../../../../src/scanners/service-detection.js";
import { clearAzureCredentialCache } from "../../../../src/providers/azure/client.js";
import { AZURE_AUTH_FAILED_PREFIX } from "../../../../src/providers/azure/errors.js";
import {
  AZURE_SERVICE_ORDER,
  AzureServiceDetectionScanner,
} from "../../../../src/providers/azure/scanners/service-detection.js";
import type { ScanResult } from "../../../../src/types.js";
import {
  authError,
  azCtx,
  azureSdk,
  deniedError,
  expectNoLeak,
  failingPages,
  FAKE_JWT,
  hostile,
  isolateAzureEnv,
  misuseError,
  notRegisteredError,
  pages,
  restoreAzureEnv,
  SUB,
  throttledError,
} from "./helpers.js";

const PRICINGS = "SecurityCenter.pricings.list";
const SUMMARIZE = "PolicyInsightsClient.policyStates.summarizeForSubscription";
const DIAG = "MonitorClient.diagnosticSettings.list";
const VAULTS = "KeyVaultManagementClient.vaults.listBySubscription";

const WORKSPACE = `/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law`;
const vault = (n: number) => ({ id: `/subscriptions/${SUB}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-${n}`, name: `kv-${n}` });

/** Everything enabled by default; override per probe. */
function route(overrides: Record<string, unknown> = {}) {
  azureSdk.on(PRICINGS, async () => ({ value: [{ name: "VirtualMachines", pricingTier: "Standard" }, { name: "StorageAccounts", pricingTier: "Free" }] }));
  azureSdk.on(SUMMARIZE, async () => ({ value: [{ results: { nonCompliantResources: 3 }, policyAssignments: [{ policyAssignmentId: "a1" }, { policyAssignmentId: "a2" }] }] }));
  azureSdk.on(DIAG, () => pages([[{ name: "to-law", workspaceId: WORKSPACE, logs: [{ category: "Administrative", enabled: true }] }]]));
  azureSdk.on(VAULTS, () => pages([[vault(1), vault(2)]]));
  for (const [k, v] of Object.entries(overrides)) azureSdk.on(k, v);
}

const detection = (r: ScanResult) => (r as ScanResult & { serviceDetection: ServiceDetectionResult }).serviceDetection;
const svc = (r: ScanResult, name: string) => detection(r).services.find((s) => s.name === name)!;

const scanner = new AzureServiceDetectionScanner();
let stdoutWrites: string[];

beforeEach(() => {
  isolateAzureEnv();
  clearAzureCredentialCache();
  azureSdk.reset();
  stdoutWrites = [];
  vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
    stdoutWrites.push(String(chunk));
    return true;
  }) as typeof process.stdout.write);
});
afterEach(() => {
  expect(stdoutWrites).toEqual([]);
  vi.restoreAllMocks();
  restoreAzureEnv();
});

describe("AzureServiceDetectionScanner", () => {
  it("module name is service_detection", () => {
    expect(scanner.moduleName).toBe("service_detection");
  });

  it("all four enabled → 100% coverage, maturity advanced, no findings", async () => {
    route();
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toBeUndefined();
    expect(r.findings).toEqual([]);
    expect(r.resourcesScanned).toBe(4);
    const d = detection(r);
    expect(d.services.map((s) => s.name)).toEqual([...AZURE_SERVICE_ORDER]);
    expect(d.services.every((s) => s.enabled === true)).toBe(true);
    expect(d.coveragePercent).toBe(100);
    expect(d.maturityLevel).toBe("advanced");
    expect(svc(r, "Defender for Cloud").details).toBe("1 of 2 Defender plan(s) on Standard (VirtualMachines)");
    expect(svc(r, "Azure Policy").details).toBe("2 policy assignment(s), 3 non-compliant resource(s)");
    expect(svc(r, "Key Vault").details).toBe("2 key vault(s)");
    // Diagnostic settings at subscription scope (`/{+resourceUri}` → no leading slash).
    expect(azureSdk.callsFor(DIAG)[0]).toEqual([`subscriptions/${SUB}`]);
    expect(azureSdk.callsFor(SUMMARIZE)[0]).toEqual(["latest", SUB]);
    // TypeSpec clients (Monitor / Key Vault) get the China scope via credentials.scopes.
    for (const client of ["MonitorClient", "KeyVaultManagementClient"]) {
      const ctor = azureSdk.ctorArgs.find((c) => c.client === client);
      expect(ctor?.args[1]).toBe(SUB);
      expect(ctor?.args[2]).toMatchObject({
        endpoint: "https://management.chinacloudapi.cn",
        credentials: { scopes: ["https://management.chinacloudapi.cn/.default"] },
      });
    }
  });

  it("nothing enabled → basic maturity, recommendations, Defender + Policy findings", async () => {
    route({
      [PRICINGS]: async () => ({ value: [{ name: "VirtualMachines", pricingTier: "Free" }] }),
      [SUMMARIZE]: async () => ({ value: [{ results: {}, policyAssignments: [] }] }),
      [DIAG]: () => pages([[{ name: "no-dest", logs: [{ category: "Administrative", enabled: true }] }]]),
      [VAULTS]: () => pages([[]]),
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    const d = detection(r);
    expect(d.services.every((s) => s.enabled === false)).toBe(true);
    expect(d.services.every((s) => typeof s.recommendation === "string" && s.recommendation.length > 0)).toBe(true);
    expect(d.coveragePercent).toBe(0);
    expect(d.maturityLevel).toBe("basic");
    expect(r.findings.map((f) => f.title)).toEqual([
      "Microsoft Defender for Cloud plans are not enabled",
      "Azure Policy has no assignments on the subscription",
    ]);
    expect(r.findings[0].severity).toBe("HIGH");
    expect(r.findings[1].severity).toBe("MEDIUM");
    expect(r.findings[0].resourceArn).toBe(`/subscriptions/${SUB}/providers/Microsoft.Security/pricings`);
    expect(r.findings.every((f) => f.provider === "azure" && f.module === "service_detection")).toBe(true);
    expect(svc(r, "Activity Log").details).toMatch(/none exports/);
  });

  it("Activity Log: settings across ≥2 pages; any exporting one enables it", async () => {
    const fetched = { pages: 0 };
    route({
      [DIAG]: () =>
        pages(
          [
            [{ name: "disabled-logs", workspaceId: WORKSPACE, logs: [{ category: "Administrative", enabled: false }] }],
            [{ name: "to-storage", storageAccountId: "/subscriptions/x/storageAccounts/sa", logs: [{ categoryGroup: "allLogs", enabled: true }] }],
          ],
          fetched,
        ),
      [VAULTS]: () => pages([[vault(1)], [vault(2)], [vault(3)]]),
    });
    const r = await scanner.scan(azCtx());
    expect(fetched.pages).toBe(2);
    expect(svc(r, "Activity Log").enabled).toBe(true);
    expect(svc(r, "Activity Log").details).toBe("1 diagnostic setting(s) exporting the Activity Log");
    expect(svc(r, "Key Vault").details).toBe("3 key vault(s)");
  });

  it("RP not registered (Azure China) → enabled=false + not_enabled warning, never error", async () => {
    route({
      [PRICINGS]: () => Promise.reject(notRegisteredError("Microsoft.Security")),
      [SUMMARIZE]: () => Promise.reject(notRegisteredError("Microsoft.PolicyInsights")),
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(svc(r, "Defender for Cloud").enabled).toBe(false);
    expect(svc(r, "Azure Policy").enabled).toBe(false);
    expect(r.warnings).toHaveLength(2);
    expect(r.warnings![0]).toMatch(/^Defender for Cloud: not enabled \/ resource provider not registered.*MissingSubscriptionRegistration/);
    expect(r.warnings![1]).toMatch(/^Azure Policy: not enabled/);
    expect(r.findingsCount).toBe(2);
  });

  it("access_denied on one probe → enabled=null + warning; others unaffected", async () => {
    route({ [VAULTS]: () => failingPages(deniedError()) });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(svc(r, "Key Vault")).toEqual({ name: "Key Vault", enabled: null, details: "Access denied" });
    expect(svc(r, "Defender for Cloud").enabled).toBe(true);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toMatch(/^Key Vault: insufficient permissions to check status/);
    expect(detection(r).coveragePercent).toBe(100); // unknown excluded from the denominator
    expect(JSON.stringify(r)).not.toContain(FAKE_JWT);
  });

  it("throttled → enabled=null + detection-error warning", async () => {
    route({ [DIAG]: () => failingPages(throttledError()) });
    const r = await scanner.scan(azCtx());
    expect(svc(r, "Activity Log").enabled).toBeNull();
    expect(r.warnings![0]).toMatch(/^Activity Log detection failed: HTTP 429/);
  });

  it("auth_failed in any probe → status error (never 'not enabled')", async () => {
    route({ [SUMMARIZE]: () => Promise.reject(authError()) });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
    expect(r.findings).toEqual([]);
  });

  it("api_misuse in any probe → status error", async () => {
    route({ [VAULTS]: () => failingPages(misuseError()) });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Azure service detection failed: .*InvalidApiVersionParameter/);
  });

  it("missing subscription in scope → clear warning, no SDK call", async () => {
    const r = await scanner.scan(azCtx({ subscriptionId: undefined }));
    expect(r.status).toBe("success");
    expect(r.warnings?.[0]).toMatch(/no Azure subscription in scope/);
    expect(azureSdk.calls).toHaveLength(0);
  });

  it("no credentials anywhere → status error listing env var names only", async () => {
    const r = await scanner.scan(azCtx({ credentials: undefined }));
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/AZURE_CLIENT_SECRET/);
  });

  it("hostile server strings (fake secret / JWT) never reach details, findings or warnings", async () => {
    route({
      [PRICINGS]: async () => ({ value: [{ name: hostile("plan"), pricingTier: "Standard" }] }),
      [VAULTS]: () => failingPages(Object.assign(deniedError(), { message: hostile("denied") })),
      [DIAG]: () => failingPages(Object.assign(throttledError(), { message: hostile("throttled") })),
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expectNoLeak(r);
    expect(svc(r, "Defender for Cloud").details).toContain("[REDACTED]");
  });
});
