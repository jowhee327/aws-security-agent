/**
 * Phase 2 (Azure) T3 — AzurePublicAccessScanner (public_access_verify): storage account
 * anonymous blob access / open network (HIGH / MEDIUM by shared key), key vault open network
 * (MEDIUM), native resource IDs, pagination, per-sub-service degrade, error matrix and the
 * hostile-field / storage key / SAS redaction regression. Every `@azure/*` package is
 * mocked; fake service principal only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@azure/identity", async () => ({ ClientSecretCredential: (await import("./helpers.js")).FakeClientSecretCredential }));
vi.mock("@azure/logger", () => ({ setLogLevel: () => {}, AzureLogger: { log: () => {} } }));
vi.mock("@azure/arm-storage", async () => ({ StorageManagementClient: (await import("./helpers.js")).fakeArmClientClass("Storage") }));
vi.mock("@azure/arm-keyvault", async () => ({ KeyVaultManagementClient: (await import("./helpers.js")).fakeArmClientClass("KeyVault") }));

import { clearAzureCredentialCache } from "../../../../src/providers/azure/client.js";
import { AZURE_AUTH_FAILED_PREFIX } from "../../../../src/providers/azure/errors.js";
import {
  AZURE_KEY_VAULT_MAX_VAULTS,
  AZURE_STORAGE_MAX_ACCOUNTS,
  AzurePublicAccessScanner,
  isAzureDefaultActionAllow,
  isAzurePublicNetworkEnabled,
} from "../../../../src/providers/azure/scanners/public-access.js";
import {
  authError,
  azCtx,
  azureSdk,
  deniedError,
  expectNoLeak,
  failingPages,
  FAKE_JWT,
  FAKE_TENANT,
  hostile,
  isolateAzureEnv,
  misuseError,
  notRegisteredError,
  pages,
  restoreAzureEnv,
  SUB,
  throttledError,
} from "./helpers.js";

const STORAGE = "Storage.storageAccounts.list";
const VAULTS = "KeyVault.vaults.listBySubscription";

/** 44-char base64 shared access / storage account key (fake). */
const FAKE_STORAGE_KEY = "RmFrZVN0b3JhZ2VBY2NvdW50S2V5RG9Ob3RVc2UwMDA=";
const FAKE_SAS_SIG = "FakeSasSignatureDoNotUse%2Babc%3D";
const FAKE_SAS = `sv=2022-11-02&ss=bfqt&srt=sco&sp=rwdlacup&se=2026-12-31T00:00:00Z&sig=${FAKE_SAS_SIG}`;

const saId = (n: string) => `/subscriptions/${SUB}/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/${n}`;
const kvId = (n: string) => `/subscriptions/${SUB}/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/${n}`;

/** Storage account in the flattened TypeSpec SDK shape; default = fully locked down. */
const account = (name: string, extra: Record<string, unknown> = {}) => ({
  id: saId(name),
  name,
  type: "Microsoft.Storage/storageAccounts",
  location: "chinanorth3",
  allowBlobPublicAccess: false,
  publicNetworkAccess: "Disabled",
  networkRuleSet: { defaultAction: "Deny", bypass: "AzureServices" },
  ...extra,
});

/** Key vault (`properties` stays nested in arm-keyvault 6); default = locked down. */
const vault = (name: string, props: Record<string, unknown> = {}) => ({
  id: kvId(name),
  name,
  type: "Microsoft.KeyVault/vaults",
  location: "chinaeast2",
  properties: { tenantId: FAKE_TENANT, publicNetworkAccess: "Disabled", networkAcls: { defaultAction: "Deny" }, ...props },
});

function route(storage: unknown, vaults: unknown) {
  azureSdk.on(STORAGE, typeof storage === "function" ? storage : () => storage);
  azureSdk.on(VAULTS, typeof vaults === "function" ? vaults : () => vaults);
}

const scanner = new AzurePublicAccessScanner();
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

describe("pure helpers", () => {
  it("publicNetworkAccess / defaultAction semantics (absent → Azure default open)", () => {
    expect(isAzurePublicNetworkEnabled("Enabled")).toBe(true);
    expect(isAzurePublicNetworkEnabled(undefined)).toBe(true);
    expect(isAzurePublicNetworkEnabled("disabled")).toBe(false);
    expect(isAzurePublicNetworkEnabled("SecuredByPerimeter")).toBe(false);
    expect(isAzureDefaultActionAllow("Allow")).toBe(true);
    expect(isAzureDefaultActionAllow(undefined)).toBe(true);
    expect(isAzureDefaultActionAllow("Deny")).toBe(false);
  });
});

describe("AzurePublicAccessScanner", () => {
  it("module name is public_access_verify", () => {
    expect(scanner.moduleName).toBe("public_access_verify");
  });

  it("storage: allowBlobPublicAccess=true → HIGH with native resource ID; China endpoint", async () => {
    route(pages([[account("blobpub", { allowBlobPublicAccess: true })]]), pages([[]]));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(1);
    expect(r.findingsCount).toBe(1);
    const f = r.findings[0];
    expect(f.title).toBe("Storage account blobpub allows anonymous (public) blob access");
    expect(f.severity).toBe("HIGH");
    expect(f.riskScore).toBe(8.0);
    expect(f.resourceArn).toBe(saId("blobpub"));
    expect(f.resourceId).toBe("blobpub");
    expect(f.resourceType).toBe("Microsoft.Storage/storageAccounts");
    expect(f.region).toBe("chinanorth3");
    expect(f.accountId).toBe(FAKE_TENANT);
    expect(f.provider).toBe("azure");
    expect(f.module).toBe("public_access_verify");
    expect(f.description).toContain(`resource group rg-data, subscription ${SUB}`);
    expect(f.description).not.toContain("reachable from all networks");
    for (const c of ["Storage", "KeyVault"]) {
      const ctor = azureSdk.ctorArgs.find((a) => a.client === c);
      expect(ctor?.args[1]).toBe(SUB);
      expect(ctor?.args[2]).toMatchObject({ endpoint: "https://management.chinacloudapi.cn" });
    }
  });

  it("storage: open network + shared key → HIGH; open network + Entra-only → MEDIUM; restricted → none", async () => {
    route(
      pages([
        [
          account("openkey", { publicNetworkAccess: "Enabled", networkRuleSet: { defaultAction: "Allow" } }),
          account("openentra", { publicNetworkAccess: "Enabled", networkRuleSet: { defaultAction: "Allow" }, allowSharedKeyAccess: false }),
          // Defaults: publicNetworkAccess / networkRuleSet absent → open.
          account("defaults", { publicNetworkAccess: undefined, networkRuleSet: undefined }),
          // Public endpoint but firewall Deny → not open.
          account("firewalled", { publicNetworkAccess: "Enabled", networkRuleSet: { defaultAction: "Deny", ipRules: [{ value: "1.2.3.4" }] } }),
          // Public access disabled → firewall default ignored.
          account("private", { publicNetworkAccess: "Disabled", networkRuleSet: { defaultAction: "Allow" } }),
          account("perimeter", { publicNetworkAccess: "SecuredByPerimeter", networkRuleSet: { defaultAction: "Allow" } }),
        ],
      ]),
      pages([[]]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.resourcesScanned).toBe(6);
    expect(r.findings.map((f) => [f.resourceId, f.severity])).toEqual([
      ["openkey", "HIGH"],
      ["openentra", "MEDIUM"],
      ["defaults", "HIGH"],
    ]);
    expect(r.findings[0].title).toBe("Storage account openkey is reachable from all networks");
    expect(r.findings[0].riskScore).toBe(7.0);
    expect(r.findings[0].description).toContain("Shared key authorization is enabled");
    expect(r.findings[1].riskScore).toBe(5.5);
    expect(r.findings[1].description).toContain("Entra ID only");
  });

  it("storage: blob public + open network → two findings; nested `properties` shape also accepted", async () => {
    route(
      pages([
        [
          account("both", { allowBlobPublicAccess: true, publicNetworkAccess: "Enabled", networkRuleSet: { defaultAction: "Allow" } }),
          {
            id: saId("rawshape"),
            name: "rawshape",
            location: "chinanorth2",
            properties: { allowBlobPublicAccess: true, publicNetworkAccess: "Disabled", networkRuleSet: { defaultAction: "Deny" } },
          },
        ],
      ]),
      pages([[]]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.findings.map((f) => f.title)).toEqual([
      "Storage account both allows anonymous (public) blob access",
      "Storage account both is reachable from all networks",
      "Storage account rawshape allows anonymous (public) blob access",
    ]);
    expect(r.findings[0].description).toContain("also reachable from all networks");
  });

  it("key vault: public + defaultAction Allow / no networkAcls → MEDIUM; Deny or Disabled → none", async () => {
    route(
      pages([[]]),
      pages([
        [
          vault("kvopen", { publicNetworkAccess: "Enabled", networkAcls: { defaultAction: "Allow" } }),
          vault("kvnoacl", { publicNetworkAccess: undefined, networkAcls: undefined }),
          vault("kvfw", { publicNetworkAccess: "Enabled", networkAcls: { defaultAction: "Deny" } }),
          vault("kvprivate", { publicNetworkAccess: "Disabled", networkAcls: { defaultAction: "Allow" } }),
        ],
      ]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.resourcesScanned).toBe(4);
    expect(r.findings.map((f) => f.resourceId)).toEqual(["kvopen", "kvnoacl"]);
    const f = r.findings[0];
    expect(f.title).toBe("Key vault kvopen is reachable from all networks");
    expect(f.severity).toBe("MEDIUM");
    expect(f.riskScore).toBe(5.5);
    expect(f.resourceArn).toBe(kvId("kvopen"));
    expect(f.resourceType).toBe("Microsoft.KeyVault/vaults");
    expect(f.region).toBe("chinaeast2");
  });

  it("no hit: locked-down accounts and vaults → no findings, no warnings", async () => {
    route(pages([[account("a"), account("b")]]), pages([[vault("v")]]));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(3);
  });

  it("resource without id → templated ARM ID", async () => {
    route(pages([[{ name: "noid", allowBlobPublicAccess: true, publicNetworkAccess: "Disabled" }]]), pages([[]]));
    const r = await scanner.scan(azCtx());
    expect(r.findings[0].resourceArn).toBe(`/subscriptions/${SUB}/providers/Microsoft.Storage/storageAccounts/noid`);
    expect(r.findings[0].region).toBe("global");
  });

  it("pagination: storage accounts and key vaults across ≥2 pages", async () => {
    const sp = { pages: 0 };
    const vp = { pages: 0 };
    route(
      pages([[account("s1", { allowBlobPublicAccess: true })], [account("s2")], [account("s3", { allowBlobPublicAccess: true })]], sp),
      pages([[vault("v1", { publicNetworkAccess: "Enabled", networkAcls: { defaultAction: "Allow" } })], [vault("v2", { networkAcls: undefined, publicNetworkAccess: undefined })]], vp),
    );
    const r = await scanner.scan(azCtx());
    expect(sp.pages).toBe(3);
    expect(vp.pages).toBe(2);
    expect(r.resourcesScanned).toBe(5);
    expect(r.findings.map((f) => f.resourceId)).toEqual(["s1", "s3", "v1", "v2"]);
  });

  it("listing caps → truncation warnings", async () => {
    route(
      pages([Array.from({ length: AZURE_STORAGE_MAX_ACCOUNTS + 1 }, (_, i) => account(`s${i}`))]),
      pages([Array.from({ length: AZURE_KEY_VAULT_MAX_VAULTS + 1 }, (_, i) => vault(`v${i}`))]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.resourcesScanned).toBe(AZURE_STORAGE_MAX_ACCOUNTS + AZURE_KEY_VAULT_MAX_VAULTS);
    expect(r.warnings).toHaveLength(2);
    expect(r.warnings![0]).toMatch(/storageAccounts.list: more than .* truncated/);
    expect(r.warnings![1]).toMatch(/vaults.listBySubscription: more than .* truncated/);
  });

  it("storage access_denied → warning, key vault findings still reported (token redacted)", async () => {
    route(() => failingPages(deniedError()), pages([[vault("kvopen", { publicNetworkAccess: "Enabled", networkAcls: { defaultAction: "Allow" } })]]));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceId)).toEqual(["kvopen"]);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toMatch(/^Storage storageAccounts.list: insufficient permissions .*storage account public access not verified/);
    expect(JSON.stringify(r)).not.toContain(FAKE_JWT);
  });

  it("key vault access_denied / not registered → warning, storage findings still reported", async () => {
    route(pages([[account("blobpub", { allowBlobPublicAccess: true })]]), () => failingPages(deniedError()));
    const denied = await scanner.scan(azCtx());
    expect(denied.status).toBe("success");
    expect(denied.findings.map((f) => f.resourceId)).toEqual(["blobpub"]);
    expect(denied.warnings![0]).toMatch(/^Key Vault vaults.listBySubscription: insufficient permissions/);

    route(pages([[account("blobpub", { allowBlobPublicAccess: true })]]), () => failingPages(notRegisteredError("Microsoft.KeyVault")));
    const nr = await scanner.scan(azCtx());
    expect(nr.status).toBe("success");
    expect(nr.findingsCount).toBe(1);
    expect(nr.warnings![0]).toMatch(/not enabled \/ resource provider not registered/);
  });

  it("both sub-services throttled → success with two warnings", async () => {
    route(() => failingPages(throttledError()), () => failingPages(throttledError()));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toHaveLength(2);
    for (const w of r.warnings!) expect(w).toMatch(/throttled/);
  });

  it("auth_failed in either sub-service → status error (Azure authentication failed …)", async () => {
    route(() => failingPages(authError()), pages([[vault("kvopen", { publicNetworkAccess: "Enabled" })]]));
    const a = await scanner.scan(azCtx());
    expect(a.status).toBe("error");
    expect(a.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
    expect(a.findings).toEqual([]);

    route(pages([[account("a")]]), () => failingPages(authError()));
    const b = await scanner.scan(azCtx());
    expect(b.status).toBe("error");
    expect(b.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
  });

  it("api_misuse → status error (keeps the other sub-service's warnings)", async () => {
    route(() => failingPages(deniedError()), () => failingPages(misuseError()));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Azure public access scan failed: .*InvalidApiVersionParameter/);
    expect(r.warnings![0]).toMatch(/insufficient permissions/);
    expectNoLeak(r);
  });

  it("missing subscription in scope → clear warning, no SDK call", async () => {
    const r = await scanner.scan(azCtx({ subscriptionId: "no-subscription" }));
    expect(r.status).toBe("success");
    expect(r.warnings?.[0]).toMatch(/no Azure subscription in scope/);
    expect(azureSdk.calls).toHaveLength(0);
  });

  it("hostile server strings (fake secret / JWT) never reach findings or warnings", async () => {
    route(
      pages([[account(hostile("acct"), { id: saId(hostile("id")), location: hostile("loc"), allowBlobPublicAccess: true, publicNetworkAccess: "Enabled", networkRuleSet: { defaultAction: "Allow" } })]]),
      pages([[{ ...vault(hostile("kv"), { publicNetworkAccess: "Enabled", networkAcls: { defaultAction: "Allow" } }), id: kvId(hostile("kvid")), location: hostile("kvloc") }]]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(3);
    expectNoLeak(r);
    expect(r.findings[0].title).toContain("[REDACTED]");

    route(() => failingPages(Object.assign(deniedError(), { message: hostile("denied") })), () => failingPages(Object.assign(throttledError(), { message: hostile("throttled") })));
    const w = await scanner.scan(azCtx());
    expect(w.warnings).toHaveLength(2);
    expectNoLeak(w);
  });

  it("regression: storage account key and SAS token in server strings never reach the output", async () => {
    const forbidden = [FAKE_STORAGE_KEY, FAKE_SAS_SIG, "FakeSasSignatureDoNotUse"];
    const leaky = `AccountKey=${FAKE_STORAGE_KEY} key ${FAKE_STORAGE_KEY} sas ?${FAKE_SAS}`;
    route(
      pages([
        [
          account(`acct ${leaky}`, {
            id: `${saId(FAKE_STORAGE_KEY)}`,
            location: `loc ${leaky}`,
            allowBlobPublicAccess: true,
            publicNetworkAccess: "Enabled",
            networkRuleSet: { defaultAction: "Allow" },
          }),
        ],
      ]),
      pages([[{ ...vault(`kv ${leaky}`, { publicNetworkAccess: "Enabled", networkAcls: { defaultAction: "Allow" } }), id: `${kvId("kv")}?${FAKE_SAS}` }]]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.findingsCount).toBe(3);
    const blob = JSON.stringify(r);
    for (const bad of forbidden) expect(blob).not.toContain(bad);
    expect(r.findings[0].resourceArn).toBe(saId("[REDACTED]"));

    route(
      () => failingPages(Object.assign(deniedError(), { message: `denied ${leaky}` })),
      () => failingPages(Object.assign(notRegisteredError("Microsoft.KeyVault"), { message: `not registered ${leaky}` })),
    );
    const w = await scanner.scan(azCtx());
    expect(w.warnings).toHaveLength(2);
    const wblob = JSON.stringify(w);
    for (const bad of forbidden) expect(wblob).not.toContain(bad);

    route(() => failingPages(Object.assign(misuseError(), { message: `bad api ${leaky}` })), pages([[]]));
    const e = await scanner.scan(azCtx());
    expect(e.status).toBe("error");
    for (const bad of forbidden) expect(JSON.stringify(e)).not.toContain(bad);
  });
});
