/**
 * Phase 2 (Azure) T5 — AzureIdleResourcesScanner (idle_resources): unattached managed disks,
 * unassociated public IPs, stopped / deallocated VMs (instance view power state), NSGs
 * associated with nothing; pagination, truncation, per-category degrade, error matrix and
 * hostile-field redaction. Every `@azure/*` package is mocked; fake service principal only;
 * no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@azure/identity", async () => ({ ClientSecretCredential: (await import("./helpers.js")).FakeClientSecretCredential }));
vi.mock("@azure/logger", () => ({ setLogLevel: () => {}, AzureLogger: { log: () => {} } }));
vi.mock("@azure/arm-compute", async () => ({ ComputeManagementClient: (await import("./helpers.js")).fakeArmClientClass("Compute") }));
vi.mock("@azure/arm-network", async () => ({ NetworkManagementClient: (await import("./helpers.js")).fakeArmClientClass("Network") }));

import { clearAzureCredentialCache } from "../../../../src/providers/azure/client.js";
import { AZURE_AUTH_FAILED_PREFIX } from "../../../../src/providers/azure/errors.js";
import {
  AZURE_IDLE_MAX_ITEMS,
  AzureIdleResourcesScanner,
  azureDiskIsUnattached,
  azureNsgIsUnassociated,
  azurePublicIpIsUnassociated,
  azureVmPowerState,
} from "../../../../src/providers/azure/scanners/idle-resources.js";
import {
  authError,
  azCtx,
  azureSdk,
  deniedError,
  expectNoLeak,
  failingPages,
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

const DISKS = "Compute.disks.list";
const VMS = "Compute.virtualMachines.listAll";
const PIPS = "Network.publicIPAddresses.listAll";
const NSGS = "Network.networkSecurityGroups.listAll";

const id = (type: string, n: string) => `/subscriptions/${SUB}/resourceGroups/rg-idle/providers/${type}/${n}`;
const diskId = (n: string) => id("Microsoft.Compute/disks", n);
const vmId = (n: string) => id("Microsoft.Compute/virtualMachines", n);
const pipId = (n: string) => id("Microsoft.Network/publicIPAddresses", n);
const nsgId = (n: string) => id("Microsoft.Network/networkSecurityGroups", n);

const disk = (name: string, state: string, extra: Record<string, unknown> = {}) => ({
  id: diskId(name),
  name,
  location: "chinanorth3",
  diskState: state,
  diskSizeGB: 128,
  sku: { name: "Premium_LRS" },
  ...(state === "Attached" || state === "Reserved" ? { managedBy: vmId("vm-a") } : {}),
  ...extra,
});

const vm = (name: string, power: string | undefined, extra: Record<string, unknown> = {}) => ({
  id: vmId(name),
  name,
  location: "chinaeast2",
  hardwareProfile: { vmSize: "Standard_D2s_v5" },
  instanceView: {
    statuses: [
      { code: "ProvisioningState/succeeded", displayStatus: "Provisioning succeeded" },
      ...(power ? [{ code: `PowerState/${power}`, displayStatus: `VM ${power}` }] : []),
    ],
  },
  ...extra,
});

const pip = (name: string, extra: Record<string, unknown> = {}) => ({
  id: pipId(name),
  name,
  location: "chinanorth3",
  ipAddress: "52.130.9.9",
  sku: { name: "Standard" },
  publicIPAllocationMethod: "Static",
  ...extra,
});

const nsg = (name: string, assoc: { nics?: number; subnets?: number } = {}) => ({
  id: nsgId(name),
  name,
  location: "chinanorth3",
  securityRules: [{ name: "r1" }, { name: "r2" }],
  networkInterfaces: Array.from({ length: assoc.nics ?? 0 }, (_, i) => ({ id: `/nic/${i}` })),
  subnets: Array.from({ length: assoc.subnets ?? 0 }, (_, i) => ({ id: `/subnet/${i}` })),
});

function route(r: { disks?: unknown; vms?: unknown; pips?: unknown; nsgs?: unknown }) {
  for (const [op, v] of [
    [DISKS, r.disks ?? []],
    [VMS, r.vms ?? []],
    [PIPS, r.pips ?? []],
    [NSGS, r.nsgs ?? []],
  ] as const) {
    azureSdk.on(op, typeof v === "function" ? v : () => pages([v as unknown[]]));
  }
}

const scanner = new AzureIdleResourcesScanner();
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
  it.each([
    ["Unattached", undefined, true],
    ["unattached", undefined, true],
    ["Unattached", vmId("x"), false],
    ["Attached", vmId("x"), false],
    ["Reserved", vmId("x"), false],
    ["ActiveSAS", undefined, false],
    [undefined, undefined, false],
  ])("disk state %s managedBy=%s → unattached=%s", (state, managedBy, expected) => {
    expect(azureDiskIsUnattached({ diskState: state, managedBy })).toBe(expected);
  });

  it("public IP / NSG association; raw `properties` shape accepted", () => {
    expect(azurePublicIpIsUnassociated(pip("a"))).toBe(true);
    expect(azurePublicIpIsUnassociated(pip("b", { ipConfiguration: { id: "/x/ipConfigurations/c" } }))).toBe(false);
    expect(azurePublicIpIsUnassociated(pip("c", { natGateway: { id: "/natGateways/n" } }))).toBe(false);
    expect(azurePublicIpIsUnassociated({ properties: { ipConfiguration: { id: "/y" } } })).toBe(false);
    expect(azureNsgIsUnassociated(nsg("a"))).toBe(true);
    expect(azureNsgIsUnassociated(nsg("b", { nics: 1 }))).toBe(false);
    expect(azureNsgIsUnassociated(nsg("c", { subnets: 1 }))).toBe(false);
    expect(azureNsgIsUnassociated({ properties: { subnets: [{ id: "/s" }] } })).toBe(false);
  });

  it("VM power state from the instance view", () => {
    expect(azureVmPowerState(vm("a", "deallocated"))?.state).toBe("deallocated");
    expect(azureVmPowerState(vm("b", "running"))?.state).toBe("running");
    expect(azureVmPowerState(vm("c", undefined))).toBeUndefined();
    expect(azureVmPowerState({})).toBeUndefined();
    const t = azureVmPowerState({ instanceView: { statuses: [{ code: "PowerState/stopped", time: "2026-09-01T00:00:00Z" }] } });
    expect(t?.state).toBe("stopped");
    expect(t?.time?.toISOString()).toBe("2026-09-01T00:00:00.000Z");
    expect(azureVmPowerState({ instanceView: { statuses: [{ code: "PowerState/stopped", time: "garbage" }] } })?.time).toBeUndefined();
  });
});

describe("AzureIdleResourcesScanner", () => {
  it("module name is idle_resources", () => {
    expect(scanner.moduleName).toBe("idle_resources");
  });

  it("every idle category → findings with the AWS-aligned riskScores", async () => {
    route({
      disks: [disk("d-free", "Unattached"), disk("d-used", "Attached"), disk("d-res", "Reserved")],
      pips: [pip("ip-free"), pip("ip-nic", { ipConfiguration: { id: "/x" } }), pip("ip-nat", { natGateway: { id: "/n" } })],
      vms: [vm("vm-run", "running"), vm("vm-dealloc", "deallocated"), vm("vm-stopped", "stopped"), vm("vm-unknown", undefined)],
      nsgs: [nsg("nsg-orphan"), nsg("nsg-nic", { nics: 2 }), nsg("nsg-subnet", { subnets: 1 })],
    });
    const r = await scanner.scan(azCtx({ subscriptionId: SUB }));
    expect(r.status).toBe("success");
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(13);
    expect(r.findings.map((f) => [f.resourceId, f.riskScore, f.severity])).toEqual([
      ["d-free", 3.0, "LOW"],
      ["ip-free", 2.0, "LOW"],
      ["vm-dealloc", 2.0, "LOW"],
      ["vm-stopped", 3.0, "LOW"],
      ["nsg-orphan", 2.0, "LOW"],
    ]);
    const [d, ip, dealloc, stopped, n] = r.findings;
    expect(d.title).toBe("Managed disk d-free is unattached");
    expect(d.description).toContain("128 GiB, Premium_LRS");
    expect(d.resourceArn).toBe(diskId("d-free"));
    expect(d.resourceType).toBe("Microsoft.Compute/disks");
    expect(d.accountId).toBe(FAKE_TENANT);
    expect(d.provider).toBe("azure");
    expect(d.module).toBe("idle_resources");
    expect(ip.title).toBe("Public IP 52.130.9.9 is not associated");
    expect(ip.resourceType).toBe("Microsoft.Network/publicIPAddresses");
    expect(dealloc.title).toBe("VM vm-dealloc is deallocated");
    expect(dealloc.region).toBe("chinaeast2");
    expect(stopped.title).toBe("VM vm-stopped is stopped but not deallocated (still billed)");
    expect(stopped.remediationSteps.join(" ")).toContain("az vm deallocate");
    expect(n.title).toBe("Network security group nsg-orphan is not attached to any resource");
    expect(n.description).toContain("2 custom rule(s)");
    expect(azureSdk.callsFor(VMS)[0]).toEqual([{ statusOnly: "true" }]);
    for (const c of azureSdk.ctorArgs) expect(c.args[2]).toMatchObject({ endpoint: "https://management.chinacloudapi.cn" });
    expect(azureSdk.ctorArgs.map((c) => c.client).sort()).toEqual(["Compute", "Network"]);
  });

  it("no hit: everything in use → no findings", async () => {
    route({ disks: [disk("d", "Attached")], pips: [pip("p", { ipConfiguration: { id: "/x" } })], vms: [vm("v", "running")], nsgs: [nsg("n", { nics: 1 })] });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.resourcesScanned).toBe(4);
  });

  it("pagination: every category across ≥2 pages", async () => {
    const counters = { d: { pages: 0 }, v: { pages: 0 }, p: { pages: 0 }, n: { pages: 0 } };
    route({
      disks: () => pages([[disk("d1", "Unattached")], [disk("d2", "Unattached")]], counters.d),
      vms: () => pages([[vm("v1", "running")], [vm("v2", "deallocated")]], counters.v),
      pips: () => pages([[pip("p1")], [pip("p2", { ipConfiguration: { id: "/x" } })], [pip("p3")]], counters.p),
      nsgs: () => pages([[nsg("n1", { nics: 1 })], [nsg("n2")]], counters.n),
    });
    const r = await scanner.scan(azCtx());
    expect([counters.d.pages, counters.v.pages, counters.p.pages, counters.n.pages]).toEqual([2, 2, 3, 2]);
    expect(r.resourcesScanned).toBe(9);
    expect(r.findings.map((f) => f.resourceId)).toEqual(["d1", "d2", "p1", "p3", "v2", "n2"]);
  });

  it("listing cap → truncation warning", async () => {
    route({ disks: Array.from({ length: AZURE_IDLE_MAX_ITEMS + 1 }, (_, i) => disk(`d${i}`, "Attached")) });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.resourcesScanned).toBe(AZURE_IDLE_MAX_ITEMS);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toMatch(/^Compute disks.list: more than .* truncated/);
  });

  it("per-category degrade: denied / not registered / throttled → warnings, other categories still reported", async () => {
    route({
      disks: () => failingPages(deniedError()),
      pips: [pip("p")],
      vms: () => failingPages(notRegisteredError("Microsoft.Compute")),
      nsgs: () => failingPages(throttledError()),
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceId)).toEqual(["p"]);
    expect(r.warnings).toHaveLength(3);
    expect(r.warnings![0]).toMatch(/^Compute disks.list: insufficient permissions .*unattached disks not checked/);
    expect(r.warnings![1]).toMatch(/^Compute virtualMachines.listAll: not enabled \/ resource provider not registered.*stopped \/ deallocated VMs not checked/);
    expect(r.warnings![2]).toMatch(/throttled.*unassociated NSGs not checked/);
    expectNoLeak(r);
  });

  it("auth_failed in any category → status error (Azure authentication failed …)", async () => {
    for (const which of ["disks", "vms", "pips", "nsgs"] as const) {
      route({ [which]: () => failingPages(authError()) });
      const r = await scanner.scan(azCtx());
      expect(r.status).toBe("error");
      expect(r.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
      expect(r.findings).toEqual([]);
      expectNoLeak(r);
    }
  });

  it("api_misuse → status error (keeps the other categories' warnings)", async () => {
    route({ disks: () => failingPages(deniedError()), pips: () => failingPages(misuseError()) });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Azure idle resources scan failed: .*InvalidApiVersionParameter/);
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
    route({
      disks: [disk(hostile("disk"), "Unattached", { id: diskId(hostile("diskid")), location: hostile("loc"), sku: { name: hostile("sku") } })],
      pips: [pip(hostile("pip"), { ipAddress: hostile("ip"), sku: { name: hostile("pipsku") }, publicIPAllocationMethod: hostile("alloc") })],
      vms: [vm(hostile("vm"), "stopped", { id: vmId(hostile("vmid")), hardwareProfile: { vmSize: hostile("size") } })],
      nsgs: [nsg(hostile("nsg"))],
    });
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(4);
    expectNoLeak(r);
    expect(r.findings[0].title).toContain("[REDACTED]");

    route({
      disks: () => failingPages(Object.assign(deniedError(), { message: hostile("denied") })),
      nsgs: () => failingPages(Object.assign(throttledError(), { message: hostile("throttled") })),
    });
    const w = await scanner.scan(azCtx());
    expect(w.warnings).toHaveLength(2);
    expectNoLeak(w);

    route({ vms: () => failingPages(Object.assign(misuseError(), { message: hostile("misuse") })) });
    const e = await scanner.scan(azCtx());
    expect(e.status).toBe("error");
    expectNoLeak(e);
  });
});
