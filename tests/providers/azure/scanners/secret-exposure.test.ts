/**
 * Phase 2 (Azure) T4 — AzureSecretExposureScanner (secret_exposure): App Service app settings
 * (name + value detectors) / connection strings (value detectors, Key Vault references
 * skipped), VM custom data + Custom Script extension public settings (protectedSettings never
 * read), N+1 caps + concurrency, pagination, per-sub-service and per-resource degrade, error
 * matrix, hostile-field redaction and "matched secret value never echoed". Every `@azure/*`
 * package is mocked; fake service principal only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@azure/identity", async () => ({ ClientSecretCredential: (await import("./helpers.js")).FakeClientSecretCredential }));
vi.mock("@azure/logger", () => ({ setLogLevel: () => {}, AzureLogger: { log: () => {} } }));
vi.mock("@azure/arm-appservice", async () => ({ WebSiteManagementClient: (await import("./helpers.js")).fakeArmClientClass("Web") }));
vi.mock("@azure/arm-compute", async () => ({ ComputeManagementClient: (await import("./helpers.js")).fakeArmClientClass("Compute") }));

import { clearAzureCredentialCache } from "../../../../src/providers/azure/client.js";
import { AZURE_AUTH_FAILED_PREFIX } from "../../../../src/providers/azure/errors.js";
import {
  AZURE_SECRET_CONCURRENCY,
  AZURE_SECRET_MAX_APPS,
  AZURE_SECRET_MAX_VMS,
  AzureSecretExposureScanner,
  azureConnectionStringEntries,
  decodeAzureBase64Text,
  isAzureCustomScriptExtension,
  isAzureSecretReference,
  matchAzureNamePatterns,
  matchAzureValuePatterns,
} from "../../../../src/providers/azure/scanners/secret-exposure.js";
import {
  authError,
  azCtx,
  azureSdk,
  deniedError,
  expectNoLeak,
  failingPages,
  FAKE_JWT,
  FAKE_SECRET,
  FAKE_TENANT,
  hostile,
  isolateAzureEnv,
  misuseError,
  notRegisteredError,
  pages,
  restError,
  restoreAzureEnv,
  SUB,
  throttledError,
} from "./helpers.js";

const APPS = "Web.webApps.list";
const SETTINGS = "Web.webApps.listApplicationSettings";
const CONNSTR = "Web.webApps.listConnectionStrings";
const VMS = "Compute.virtualMachines.listAll";
const EXTS = "Compute.virtualMachineExtensions.list";

/* Fake secret values — none may ever appear in the scan output. */
const FAKE_AWS_KEY = "AKIAFAKEFAKEFAKE1234";
const FAKE_STORAGE_KEY = `${"RmFrZVN0b3JhZ2VLZXk".repeat(4)}RmFrZVN0b3JhZ2VLZXk012==`.slice(0, 86) + "==";
const FAKE_DB_PASSWORD = "FakeDbP4ssw0rdDoNotUse";
const FAKE_PLAIN_TOKEN = "fake-plain-token-value-do-not-use";
const FAKE_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIFakePrivateKeyBodyDoNotUse\n-----END RSA PRIVATE KEY-----";
const SECRET_VALUES = [FAKE_AWS_KEY, FAKE_STORAGE_KEY, FAKE_DB_PASSWORD, FAKE_PLAIN_TOKEN, "MIIFakePrivateKeyBodyDoNotUse"];

const b64 = (s: string) => Buffer.from(s, "utf-8").toString("base64");
const appId = (n: string, rg = "rg-web") => `/subscriptions/${SUB}/resourceGroups/${rg}/providers/Microsoft.Web/sites/${n}`;
const vmId = (n: string, rg = "rg-vm") => `/subscriptions/${SUB}/resourceGroups/${rg}/providers/Microsoft.Compute/virtualMachines/${n}`;

const app = (name: string, extra: Record<string, unknown> = {}) => ({ id: appId(name), name, kind: "app", location: "chinanorth3", ...extra });
const vm = (name: string, extra: Record<string, unknown> = {}) => ({ id: vmId(name), name, location: "chinaeast2", osProfile: { computerName: name }, ...extra });
const settings = (props: Record<string, string>) => ({ id: `${appId("x")}/config/appsettings`, name: "appsettings", properties: props });
const connStrings = (props: Record<string, { value: string; type: string }>) => ({ name: "connectionstrings", properties: props });
const ext = (name: string, type: string, extra: Record<string, unknown> = {}) => ({
  id: `${vmId("x")}/extensions/${name}`,
  name,
  type: "Microsoft.Compute/virtualMachines/extensions",
  publisher: "Microsoft.Azure.Extensions",
  typePropertiesType: type,
  ...extra,
});

interface Routes {
  apps?: unknown;
  settings?: unknown;
  connStrings?: unknown;
  vms?: unknown;
  exts?: unknown;
}

/** Defaults: no apps, no VMs. `settings` / `connStrings` / `exts` may be (rg, name) => value. */
function route(r: Routes) {
  const wrap = (v: unknown) => (typeof v === "function" ? v : () => v);
  azureSdk.on(APPS, wrap(r.apps ?? pages([[]])));
  azureSdk.on(SETTINGS, wrap(r.settings ?? (async () => settings({}))));
  azureSdk.on(CONNSTR, wrap(r.connStrings ?? (async () => connStrings({}))));
  azureSdk.on(VMS, wrap(r.vms ?? pages([[]])));
  azureSdk.on(EXTS, wrap(r.exts ?? (async () => ({ value: [] }))));
}

const scanner = new AzureSecretExposureScanner();
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

function expectNoSecretValues(r: unknown) {
  const blob = JSON.stringify(r);
  for (const v of SECRET_VALUES) expect(blob).not.toContain(v);
}

describe("pure helpers", () => {
  it("value / name detectors (AWS patterns + Azure extras)", () => {
    expect(matchAzureValuePatterns(`key ${FAKE_AWS_KEY}`).map((p) => p.name)).toEqual(["AWS Access Key"]);
    expect(matchAzureValuePatterns(FAKE_PRIVATE_KEY).map((p) => p.name)).toEqual(["Private Key"]);
    expect(matchAzureValuePatterns(`DefaultEndpointsProtocol=https;AccountName=sa;AccountKey=${FAKE_STORAGE_KEY};EndpointSuffix=core.chinacloudapi.cn`).map((p) => p.name)).toEqual([
      "Azure Storage account key",
    ]);
    expect(matchAzureValuePatterns(`Endpoint=sb://ns.servicebus.chinacloudapi.cn/;SharedAccessKeyName=root;SharedAccessKey=${FAKE_STORAGE_KEY}`).map((p) => p.name)).toEqual([
      "Azure shared access key",
    ]);
    expect(matchAzureValuePatterns("https://sa.blob.core.chinacloudapi.cn/c?sv=2022-11-02&sp=r&sig=FakeSasSignatureDoNotUse%2Babc%3D").map((p) => p.name)).toEqual([
      "Azure SAS token",
    ]);
    expect(matchAzureValuePatterns(`Server=tcp:db;Database=d;User ID=u;Password=${FAKE_DB_PASSWORD};`).map((p) => p.name)).toEqual([
      "Password in connection string",
    ]);
    expect(matchAzureValuePatterns("Server=tcp:db;Authentication=Active Directory Managed Identity;")).toEqual([]);
    expect(matchAzureValuePatterns("plain value")).toEqual([]);
    expect(matchAzureNamePatterns("db_password").map((p) => p.name)).toEqual(["Password in env var"]);
    expect(matchAzureNamePatterns("AZURE_CLIENT_SECRET").map((p) => p.name)).toEqual(["Azure credential in app setting"]);
    expect(matchAzureNamePatterns("WEBSITE_RUN_FROM_PACKAGE")).toEqual([]);
  });

  it("Key Vault / App Configuration references, base64 decode, extension type, connection string shape", () => {
    expect(isAzureSecretReference("@Microsoft.KeyVault(SecretUri=https://kv.vault.azure.cn/secrets/x/)")).toBe(true);
    expect(isAzureSecretReference(" @Microsoft.AppConfiguration(Endpoint=https://x;Key=y)")).toBe(true);
    expect(isAzureSecretReference("hunter2")).toBe(false);
    expect(decodeAzureBase64Text(b64("#!/bin/bash\necho hi"))).toBe("#!/bin/bash\necho hi");
    expect(decodeAzureBase64Text("not base64 at all!")).toBe("not base64 at all!");
    expect(decodeAzureBase64Text("")).toBeUndefined();
    expect(decodeAzureBase64Text(42)).toBeUndefined();
    expect(isAzureCustomScriptExtension(ext("cse", "CustomScript"))).toBe(true);
    expect(isAzureCustomScriptExtension(ext("cse", "CustomScriptExtension"))).toBe(true);
    expect(isAzureCustomScriptExtension({ name: "raw", properties: { type: "CustomScriptForLinux" } })).toBe(true);
    expect(isAzureCustomScriptExtension(ext("mma", "MicrosoftMonitoringAgent"))).toBe(false);
    expect(azureConnectionStringEntries(connStrings({ Db: { value: "v", type: "SQLAzure" } }))).toEqual([["Db", "v"]]);
    expect(azureConnectionStringEntries({ properties: null })).toEqual([]);
  });
});

describe("AzureSecretExposureScanner", () => {
  it("module name is secret_exposure", () => {
    expect(scanner.moduleName).toBe("secret_exposure");
  });

  it("App Service: app setting name / value hits and connection string hits; values never echoed", async () => {
    route({
      apps: pages([[app("web1")]]),
      settings: async () =>
        settings({
          DB_PASSWORD: FAKE_DB_PASSWORD,
          AWS_KEY_ID: FAKE_AWS_KEY,
          AzureWebJobsStorage: `DefaultEndpointsProtocol=https;AccountName=sa;AccountKey=${FAKE_STORAGE_KEY};EndpointSuffix=core.chinacloudapi.cn`,
          API_KEY: "@Microsoft.KeyVault(SecretUri=https://kv.vault.azure.cn/secrets/api/)",
          TOKEN: "",
          WEBSITE_NODE_DEFAULT_VERSION: "~18",
        }),
      connStrings: async () =>
        connStrings({
          Db: { value: `Server=tcp:db.database.chinacloudapi.cn;Database=d;User ID=u;Password=${FAKE_DB_PASSWORD};`, type: "SQLAzure" },
          Kv: { value: "@Microsoft.KeyVault(SecretUri=https://kv.vault.azure.cn/secrets/db/)", type: "SQLAzure" },
          Mi: { value: "Server=tcp:db;Authentication=Active Directory Default;", type: "SQLAzure" },
        }),
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(1);
    expect(r.findings.map((f) => [f.title, f.riskScore, f.severity])).toEqual([
      ['App Service web1 has suspicious app setting "DB_PASSWORD"', 7.5, "HIGH"],
      ["App Service web1 app setting contains AWS Access Key", 9.5, "CRITICAL"],
      ["App Service web1 app setting contains Azure Storage account key", 9.5, "CRITICAL"],
      ["App Service web1 connection string contains Password in connection string", 9.0, "CRITICAL"],
    ]);
    const f = r.findings[1];
    expect(f.resourceType).toBe("Microsoft.Web/sites");
    expect(f.resourceId).toBe("web1");
    expect(f.resourceArn).toBe(appId("web1"));
    expect(f.region).toBe("chinanorth3");
    expect(f.accountId).toBe(FAKE_TENANT);
    expect(f.provider).toBe("azure");
    expect(f.module).toBe("secret_exposure");
    expect(f.description).toContain('app setting "AWS_KEY_ID"');
    expect(f.description).toContain("resource group rg-web, subscription");
    expect(f.description).toContain("not included in this report");
    expect(r.findings[3].description).toContain('connection string "Db"');
    expectNoSecretValues(r);
    expect(azureSdk.callsFor(SETTINGS)).toEqual([["rg-web", "web1"]]);
    expect(azureSdk.callsFor(CONNSTR)).toEqual([["rg-web", "web1"]]);
    const ctor = azureSdk.ctorArgs.find((a) => a.client === "Web");
    expect(ctor?.args[1]).toBe(SUB);
    expect(ctor?.args[2]).toMatchObject({ endpoint: "https://management.chinacloudapi.cn" });
  });

  it("VMs: Custom Script public settings + base64 script + custom data; other extensions and protectedSettings ignored", async () => {
    route({
      vms: pages([[vm("vm1"), vm("vm2", { osProfile: { computerName: "vm2", customData: b64(`#cloud-config\n${FAKE_PRIVATE_KEY}`) } }), vm("vm3")]]),
      exts: async (_rg: unknown, name: unknown) => {
        if (name === "vm1")
          return {
            value: [
              ext("cse", "CustomScript", { settings: { commandToExecute: `export AWS_ACCESS_KEY_ID=${FAKE_AWS_KEY} && ./run.sh` } }),
              ext("mma", "MicrosoftMonitoringAgent", { settings: { workspaceKey: FAKE_AWS_KEY } }),
            ],
          };
        if (name === "vm3")
          return {
            value: [
              ext("cse-script", "CustomScript", { settings: { script: b64(`#!/bin/sh\ncat > id_rsa <<EOF\n${FAKE_PRIVATE_KEY}\nEOF`) } }),
              // Secrets only in protectedSettings → not read, no finding.
              ext("cse-protected", "CustomScriptExtension", { publisher: "Microsoft.Compute", settings: { fileUris: [] }, protectedSettings: { commandToExecute: FAKE_AWS_KEY } }),
            ],
          };
        return { value: [] };
      },
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(3);
    expect(r.findings.map((f) => [f.title, f.riskScore])).toEqual([
      ["VM vm2 custom data contains Private Key", 8.0],
      ["VM vm1 Custom Script extension settings contain AWS Access Key", 9.5],
      ["VM vm3 Custom Script extension settings contain Private Key", 8.0],
    ]);
    expect(r.findings[1].description).toContain('Custom Script extension "cse"');
    expect(r.findings[1].resourceArn).toBe(vmId("vm1"));
    expect(r.findings[1].resourceType).toBe("Microsoft.Compute/virtualMachines");
    expect(r.findings[1].region).toBe("chinaeast2");
    expectNoSecretValues(r);
    expect(azureSdk.callsFor(EXTS)).toEqual([
      ["rg-vm", "vm1"],
      ["rg-vm", "vm2"],
      ["rg-vm", "vm3"],
    ]);
  });

  it("no hit: clean apps and VMs → no findings, no warnings", async () => {
    route({
      apps: pages([[app("a"), app("b")]]),
      settings: async () => settings({ WEBSITE_RUN_FROM_PACKAGE: "1", FEATURE_FLAG: "on" }),
      vms: pages([[vm("v")]]),
      exts: async () => ({ value: [ext("cse", "CustomScript", { settings: { commandToExecute: "./setup.sh" } })] }),
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(3);
  });

  it("pagination: apps and VMs across ≥2 pages", async () => {
    const ap = { pages: 0 };
    const vp = { pages: 0 };
    route({
      apps: pages([[app("a1")], [app("a2")], [app("a3")]], ap),
      settings: async (_rg: unknown, name: unknown) => settings(name === "a3" ? { SECRET: FAKE_PLAIN_TOKEN } : {}),
      vms: pages([[vm("v1")], [vm("v2")]], vp),
      exts: async (_rg: unknown, name: unknown) =>
        name === "v2" ? { value: [ext("cse", "CustomScript", { settings: { commandToExecute: FAKE_AWS_KEY } })] } : { value: [] },
    });
    const r = await scanner.scan(azCtx());
    expect(ap.pages).toBe(3);
    expect(vp.pages).toBe(2);
    expect(r.resourcesScanned).toBe(5);
    expect(r.findings.map((f) => f.resourceId)).toEqual(["a3", "v2"]);
    expectNoSecretValues(r);
  });

  it("N+1 caps → warnings; per-resource calls never exceed the concurrency limit", async () => {
    let inFlight = 0;
    let peak = 0;
    const slow = (value: unknown) => async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((res) => setTimeout(res, 1));
      inFlight--;
      return value;
    };
    route({
      apps: pages([Array.from({ length: AZURE_SECRET_MAX_APPS + 3 }, (_, i) => app(`a${i}`))]),
      settings: slow(settings({})),
      connStrings: slow(connStrings({})),
      vms: pages([Array.from({ length: AZURE_SECRET_MAX_VMS + 2 }, (_, i) => vm(`v${i}`))]),
      exts: slow({ value: [] }),
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(azureSdk.callsFor(SETTINGS)).toHaveLength(AZURE_SECRET_MAX_APPS);
    expect(azureSdk.callsFor(EXTS)).toHaveLength(AZURE_SECRET_MAX_VMS);
    expect(peak).toBeLessThanOrEqual(AZURE_SECRET_CONCURRENCY);
    expect(r.warnings).toHaveLength(2);
    expect(r.warnings![0]).toMatch(new RegExp(`${AZURE_SECRET_MAX_APPS + 3} apps .*first ${AZURE_SECRET_MAX_APPS} only`));
    expect(r.warnings![1]).toMatch(new RegExp(`${AZURE_SECRET_MAX_VMS + 2} VMs .*first ${AZURE_SECRET_MAX_VMS} only`));
    expect(r.resourcesScanned).toBe(AZURE_SECRET_MAX_APPS + AZURE_SECRET_MAX_VMS + 2);
  });

  it("per-app access_denied (Reader role) → one aggregated warning with the RBAC hint; VM findings still reported", async () => {
    route({
      apps: pages([[app("a1"), app("a2")]]),
      settings: async () => {
        throw deniedError();
      },
      connStrings: async () => {
        throw deniedError();
      },
      vms: pages([[vm("v1")]]),
      exts: async () => ({ value: [ext("cse", "CustomScript", { settings: { commandToExecute: FAKE_AWS_KEY } })] }),
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceId)).toEqual(["v1"]);
    expect(r.resourcesScanned).toBe(1);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toMatch(/^App Service listApplicationSettings \/ listConnectionStrings failed for 4 resource\(s\); first: App Service a1 listApplicationSettings: insufficient permissions/);
    expect(r.warnings![0]).toContain("Microsoft.Web/sites/config/list/action");
    expectNoLeak(r);
  });

  it("webApps.list access_denied → warning; VM listAll not registered → warning (success, no error)", async () => {
    route({ apps: () => failingPages(deniedError()), vms: pages([[vm("v1")]]), exts: async () => ({ value: [ext("cse", "CustomScript", { settings: { commandToExecute: FAKE_AWS_KEY } })] }) });
    const a = await scanner.scan(azCtx());
    expect(a.status).toBe("success");
    expect(a.findingsCount).toBe(1);
    expect(a.warnings![0]).toMatch(/^App Service webApps.list: insufficient permissions .*not checked for secrets/);

    route({ apps: pages([[app("a1")]]), settings: async () => settings({ SECRET: FAKE_PLAIN_TOKEN }), vms: () => failingPages(notRegisteredError("Microsoft.Compute")) });
    const b = await scanner.scan(azCtx());
    expect(b.status).toBe("success");
    expect(b.findings.map((f) => f.resourceId)).toEqual(["a1"]);
    expect(b.warnings![0]).toMatch(/^Compute virtualMachines.listAll: not enabled \/ resource provider not registered/);
    expectNoLeak(b);
  });

  it("per-VM extension failures (throttled) aggregated; not_found (deleted meanwhile) skipped silently", async () => {
    route({
      apps: pages([[app("gone")]]),
      settings: async () => {
        throw restError(404, "ResourceNotFound", "The Resource 'Microsoft.Web/sites/gone' was not found.");
      },
      connStrings: async () => {
        throw restError(404, "ResourceNotFound", "The Resource 'Microsoft.Web/sites/gone' was not found.");
      },
      vms: pages([[vm("v1"), vm("v2"), vm("v3")]]),
      exts: async (_rg: unknown, name: unknown) => {
        if (name === "v3") return { value: [] };
        throw throttledError();
      },
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toMatch(/^Compute virtualMachineExtensions.list failed for 2 resource\(s\); first: Compute VM v1 virtualMachineExtensions.list: throttled/);
    expect(r.resourcesScanned).toBe(3); // deleted app not counted; VMs listed
  });

  it("auth_failed anywhere → status error (Azure authentication failed …)", async () => {
    route({ apps: () => failingPages(authError()) });
    const a = await scanner.scan(azCtx());
    expect(a.status).toBe("error");
    expect(a.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
    expect(a.findings).toEqual([]);

    route({
      apps: pages([[app("a1")]]),
      settings: async () => {
        throw authError();
      },
    });
    const b = await scanner.scan(azCtx());
    expect(b.status).toBe("error");
    expect(b.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);

    route({
      vms: pages([[vm("v1")]]),
      exts: async () => {
        throw authError();
      },
    });
    const c = await scanner.scan(azCtx());
    expect(c.status).toBe("error");
    expect(c.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
    expectNoLeak(c);
  });

  it("api_misuse → status error (keeps earlier sub-service warnings)", async () => {
    route({ apps: () => failingPages(deniedError()), vms: () => failingPages(misuseError()) });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^VM secret scan failed: .*InvalidApiVersionParameter/);
    expect(r.warnings![0]).toMatch(/insufficient permissions/);
    expectNoLeak(r);

    route({
      apps: pages([[app("a1")]]),
      connStrings: async () => {
        throw misuseError();
      },
    });
    const b = await scanner.scan(azCtx());
    expect(b.status).toBe("error");
    expect(b.error).toMatch(/^App Service secret scan failed: /);
  });

  it("missing subscription in scope → clear warning, no SDK call", async () => {
    const r = await scanner.scan(azCtx({ subscriptionId: "no-subscription" }));
    expect(r.status).toBe("success");
    expect(r.warnings?.[0]).toMatch(/no Azure subscription in scope/);
    expect(azureSdk.calls).toHaveLength(0);
  });

  it("hostile server strings (fake secret / JWT) in names, setting keys and errors never reach the output", async () => {
    route({
      apps: pages([[{ ...app(hostile("app")), id: appId(hostile("appid"), hostile("rg")), location: hostile("loc") }]]),
      settings: async () => settings({ [hostile("SECRET")]: `${FAKE_AWS_KEY} ${FAKE_JWT}`, SECRET: hostile("value") }),
      connStrings: async () => connStrings({ [hostile("cs")]: { value: `Password=${FAKE_SECRET};`, type: "Custom" } }),
      vms: pages([[{ ...vm(hostile("vm")), id: vmId(hostile("vmid")), location: hostile("vmloc") }]]),
      exts: async () => ({ value: [ext(hostile("ext"), "CustomScript", { settings: { commandToExecute: `${FAKE_AWS_KEY} ${hostile("cmd")}` } })] }),
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBeGreaterThanOrEqual(4);
    expectNoLeak(r);
    expectNoSecretValues(r);
    expect(r.findings[0].title).toContain("[REDACTED]");

    route({
      apps: pages([[app("a1")]]),
      settings: async () => {
        throw Object.assign(deniedError(), { message: hostile("denied") });
      },
      vms: () => failingPages(Object.assign(throttledError(), { message: hostile("throttled") })),
    });
    const w = await scanner.scan(azCtx());
    expect(w.warnings).toHaveLength(2);
    expectNoLeak(w);

    route({ apps: () => failingPages(Object.assign(misuseError(), { message: hostile("misuse") })) });
    const e = await scanner.scan(azCtx());
    expect(e.status).toBe("error");
    expectNoLeak(e);
  });
});
