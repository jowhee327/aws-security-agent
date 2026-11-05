/**
 * Phase 2 (Azure) T7 — AzureTagComplianceScanner (tag_compliance): resources / resource
 * groups missing DEFAULT_REQUIRED_TAGS (case-insensitive), pagination, cap, per-category
 * degrade, error matrix and hostile-field redaction. Every `@azure/*` package is mocked;
 * fake service principal only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@azure/identity", async () => ({ ClientSecretCredential: (await import("./helpers.js")).FakeClientSecretCredential }));
vi.mock("@azure/logger", () => ({ setLogLevel: () => {}, AzureLogger: { log: () => {} } }));
vi.mock("@azure/arm-resources", async () => ({ ResourceManagementClient: (await import("./helpers.js")).fakeArmClientClass("ResourceManagementClient") }));

import { clearAzureCredentialCache } from "../../../../src/providers/azure/client.js";
import { AZURE_AUTH_FAILED_PREFIX } from "../../../../src/providers/azure/errors.js";
import {
  AZURE_TAG_MAX_ITEMS,
  AZURE_TAG_RISK,
  AzureTagComplianceScanner,
  DEFAULT_REQUIRED_TAGS,
  azureMissingRequiredTags,
  azureTagKeys,
} from "../../../../src/providers/azure/scanners/tag-compliance.js";
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

const RES = "ResourceManagementClient.resources.list";
const RGS = "ResourceManagementClient.resourceGroups.list";

const vmId = (n: string, rg = "rg") => `/subscriptions/${SUB}/resourceGroups/${rg}/providers/Microsoft.Compute/virtualMachines/${n}`;
const rgId = (n: string) => `/subscriptions/${SUB}/resourceGroups/${n}`;
const ALL_TAGS = { Environment: "prod", Project: "x", Owner: "team" };

const vm = (n: string, tags?: Record<string, string>, extra: Record<string, unknown> = {}) => ({
  id: vmId(n),
  name: n,
  type: "Microsoft.Compute/virtualMachines",
  location: "chinanorth3",
  ...(tags ? { tags } : {}),
  ...extra,
});
const rg = (n: string, tags?: Record<string, string>) => ({ id: rgId(n), name: n, location: "chinaeast2", ...(tags ? { tags } : {}) });

function route(resources: unknown, groups: unknown = () => pages([[]])) {
  azureSdk.on(RES, typeof resources === "function" ? resources : () => resources);
  azureSdk.on(RGS, typeof groups === "function" ? groups : () => groups);
}

const scanner = new AzureTagComplianceScanner();
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
  it("tag keys and case-insensitive missing-tag detection", () => {
    expect(DEFAULT_REQUIRED_TAGS).toEqual(["Environment", "Project", "Owner"]);
    expect(azureTagKeys({ tags: { a: "1", " ": "x", b: "" } })).toEqual(["a", "b"]);
    expect(azureTagKeys({ tags: null })).toEqual([]);
    expect(azureTagKeys({ tags: ["Owner"] })).toEqual([]);
    expect(azureTagKeys({})).toEqual([]);
    expect(azureMissingRequiredTags(["environment", "PROJECT"])).toEqual(["Owner"]);
    expect(azureMissingRequiredTags([])).toEqual(["Environment", "Project", "Owner"]);
    expect(azureMissingRequiredTags(["Environment", "Project", "Owner"])).toEqual([]);
  });
});

describe("AzureTagComplianceScanner", () => {
  it("module name is tag_compliance", () => {
    expect(scanner.moduleName).toBe("tag_compliance");
  });

  it("hit: resources / resource groups missing required tags → MEDIUM findings; compliant skipped", async () => {
    route(pages([[vm("untagged"), vm("partial", { environment: "prod", Team: "a" }), vm("ok", ALL_TAGS)]]), pages([[rg("rg-bare"), rg("rg-ok", { ENVIRONMENT: "p", project: "x", owner: "y" })]]));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(5);
    expect(r.findingsCount).toBe(3);

    const bare = r.findings.find((f) => f.resourceId === "untagged")!;
    expect(bare.title).toBe("Microsoft.Compute/virtualMachines resource untagged missing required tags: Environment, Project, Owner");
    expect(bare.severity).toBe("MEDIUM");
    expect(bare.riskScore).toBe(AZURE_TAG_RISK);
    expect(bare.resourceArn).toBe(vmId("untagged"));
    expect(bare.resourceType).toBe("Microsoft.Compute/virtualMachines");
    expect(bare.region).toBe("chinanorth3");
    expect(bare.description).toContain("has no tags configured");
    expect(bare.description).toContain("resource group rg");
    expect(bare.provider).toBe("azure");
    expect(bare.accountId).toBe(FAKE_TENANT);
    expect(bare.module).toBe("tag_compliance");

    const partial = r.findings.find((f) => f.resourceId === "partial")!;
    expect(partial.title).toMatch(/missing required tags: Project, Owner$/);
    expect(partial.description).toContain("Present tags: environment, Team.");

    const group = r.findings.find((f) => f.resourceId === "rg-bare")!;
    expect(group.title).toBe("Resource group rg-bare missing required tags: Environment, Project, Owner");
    expect(group.resourceType).toBe("Microsoft.Resources/resourceGroups");
    expect(group.resourceArn).toBe(rgId("rg-bare"));
    expect(group.region).toBe("chinaeast2");

    const ctor = azureSdk.ctorArgs.find((c) => c.client === "ResourceManagementClient");
    expect(ctor?.args[1]).toBe(SUB);
    expect(ctor?.args[2]).toMatchObject({ endpoint: "https://management.chinacloudapi.cn" });
  });

  it("no hit: every resource fully tagged → no findings", async () => {
    route(pages([[vm("a", ALL_TAGS), vm("b", { ...ALL_TAGS, extra: "1" })]]), pages([[rg("g", ALL_TAGS)]]));
    const r = await scanner.scan(azCtx());
    expect(r.findings).toEqual([]);
    expect(r.resourcesScanned).toBe(3);
    expect(r.warnings).toBeUndefined();
  });

  it("pagination: resources across ≥2 pages", async () => {
    const fetched = { pages: 0 };
    route(pages([[vm("p1")], [vm("p2", ALL_TAGS)], [vm("p3")]], fetched));
    const r = await scanner.scan(azCtx());
    expect(fetched.pages).toBe(3);
    expect(r.resourcesScanned).toBe(3);
    expect(r.findings.map((f) => f.resourceId)).toEqual(["p1", "p3"]);
  });

  it("listing cap → truncation warning", async () => {
    route(pages([Array.from({ length: AZURE_TAG_MAX_ITEMS + 1 }, (_, i) => vm(`v${i}`, ALL_TAGS))]));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.resourcesScanned).toBe(AZURE_TAG_MAX_ITEMS);
    expect(r.warnings).toEqual([`Resources resources.list: more than ${AZURE_TAG_MAX_ITEMS} items; results were truncated to the first ${AZURE_TAG_MAX_ITEMS}.`]);
  });

  it("access_denied on resources → warning, resource groups still evaluated (token redacted)", async () => {
    route(() => failingPages(deniedError()), pages([[rg("rg-bare")]]));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(1);
    expect(r.warnings![0]).toMatch(/^Resources resources.list: insufficient permissions.*resource tags not checked\.$/);
    expect(JSON.stringify(r)).not.toContain(FAKE_JWT);
  });

  it("RP not registered / throttled on resource groups → warning, resources still evaluated", async () => {
    route(pages([[vm("bare")]]), () => failingPages(notRegisteredError("Microsoft.Resources")));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(1);
    expect(r.warnings![0]).toMatch(/resourceGroups.list: not enabled/);

    route(pages([[vm("bare")]]), () => failingPages(throttledError()));
    const t = await scanner.scan(azCtx());
    expect(t.status).toBe("success");
    expect(t.warnings![0]).toMatch(/throttled/);
  });

  it("auth_failed → status error (Azure authentication failed …); api_misuse → status error", async () => {
    route(() => failingPages(authError()));
    const auth = await scanner.scan(azCtx());
    expect(auth.status).toBe("error");
    expect(auth.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);

    route(pages([[vm("a")]]), () => failingPages(misuseError()));
    const misuse = await scanner.scan(azCtx());
    expect(misuse.status).toBe("error");
    expect(misuse.error).toMatch(/^Azure tag compliance scan failed: .*InvalidApiVersionParameter/);
    expect(misuse.findings).toEqual([]);
  });

  it("missing subscription in scope → clear warning, no SDK call", async () => {
    const r = await scanner.scan(azCtx({ subscriptionId: "no-subscription" }));
    expect(r.status).toBe("success");
    expect(r.warnings?.[0]).toMatch(/no Azure subscription in scope/);
    expect(azureSdk.calls).toHaveLength(0);
  });

  it("hostile server strings (fake secret / JWT) never reach findings or warnings", async () => {
    const evil = hostile("vm");
    route(
      pages([[{ id: vmId(evil, hostile("rg")), name: evil, type: hostile("Microsoft.Evil/type"), location: hostile("loc"), tags: { [hostile("tagkey")]: hostile("tagval") } }]]),
      () => failingPages(Object.assign(deniedError(), { message: hostile("denied") })),
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(1);
    expectNoLeak(r);
    expect(r.findings[0].title).toContain("[REDACTED]");
    expect(r.findings[0].description).toContain("[REDACTED]");
  });
});
