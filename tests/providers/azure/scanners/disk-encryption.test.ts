/**
 * Phase 2 (Azure) T4 — AzureDiskEncryptionScanner (disk_encryption_findings): managed disks
 * without encryption (HIGH), platform-managed-only / CMK / double encryption (no finding),
 * unmanaged VHD disks without ADE (HIGH), VMs without encryption at host (LOW, capped),
 * pagination, per-sub-service degrade, error matrix and hostile-field redaction. Every
 * `@azure/*` package is mocked; fake service principal only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@azure/identity", async () => ({ ClientSecretCredential: (await import("./helpers.js")).FakeClientSecretCredential }));
vi.mock("@azure/logger", () => ({ setLogLevel: () => {}, AzureLogger: { log: () => {} } }));
vi.mock("@azure/arm-compute", async () => ({ ComputeManagementClient: (await import("./helpers.js")).fakeArmClientClass("Compute") }));

import { clearAzureCredentialCache } from "../../../../src/providers/azure/client.js";
import { AZURE_AUTH_FAILED_PREFIX } from "../../../../src/providers/azure/errors.js";
import {
  AZURE_DISK_HOST_MAX_FINDINGS,
  AZURE_DISK_MAX_DISKS,
  AzureDiskEncryptionScanner,
  azureDiskEncryptionState,
  azureUnmanagedVmDisks,
  azureVmEncryptionAtHost,
} from "../../../../src/providers/azure/scanners/disk-encryption.js";
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

const diskId = (n: string) => `/subscriptions/${SUB}/resourceGroups/rg-disk/providers/Microsoft.Compute/disks/${n}`;
const vmId = (n: string) => `/subscriptions/${SUB}/resourceGroups/rg-vm/providers/Microsoft.Compute/virtualMachines/${n}`;

/** Managed disk (flattened TypeSpec shape); default = platform-managed key. */
const disk = (name: string, extra: Record<string, unknown> = {}) => ({
  id: diskId(name),
  name,
  location: "chinanorth3",
  diskState: "Attached",
  managedBy: vmId("vm-a"),
  encryption: { type: "EncryptionAtRestWithPlatformKey" },
  ...extra,
});

/** VM with managed disks; default = encryption at host on. */
const vm = (name: string, extra: Record<string, unknown> = {}) => ({
  id: vmId(name),
  name,
  location: "chinaeast2",
  securityProfile: { encryptionAtHost: true },
  storageProfile: {
    osDisk: { name: `${name}-os`, createOption: "FromImage", managedDisk: { id: diskId(`${name}-os`) } },
    dataDisks: [],
  },
  ...extra,
});

const unmanagedStorage = (name: string, ade = false) => ({
  osDisk: {
    name: `${name}-osvhd`,
    createOption: "FromImage",
    vhd: { uri: `https://savhd.blob.core.chinacloudapi.cn/vhds/${name}-os.vhd` },
    ...(ade ? { encryptionSettings: { enabled: true } } : {}),
  },
  dataDisks: [
    { lun: 0, name: `${name}-data0`, createOption: "Empty", vhd: { uri: `https://savhd.blob.core.chinacloudapi.cn/vhds/${name}-d0.vhd` } },
    { lun: 1, name: `${name}-data1`, createOption: "Empty", managedDisk: { id: diskId(`${name}-data1`) } },
  ],
});

function route(disks: unknown, vms: unknown) {
  azureSdk.on(DISKS, typeof disks === "function" ? disks : () => disks);
  azureSdk.on(VMS, typeof vms === "function" ? vms : () => vms);
}

const scanner = new AzureDiskEncryptionScanner();
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
  it("disk encryption state", () => {
    expect(azureDiskEncryptionState(disk("p"))).toBe("platform");
    expect(azureDiskEncryptionState(disk("c", { encryption: { type: "EncryptionAtRestWithCustomerKey", diskEncryptionSetId: "/x" } }))).toBe("customer");
    expect(azureDiskEncryptionState(disk("d", { encryption: { type: "EncryptionAtRestWithPlatformAndCustomerKeys" } }))).toBe("double");
    expect(azureDiskEncryptionState(disk("n", { encryption: undefined }))).toBe("unencrypted");
    expect(azureDiskEncryptionState(disk("u", { encryption: { type: "Unencrypted" } }))).toBe("unencrypted");
    expect(azureDiskEncryptionState(disk("a", { encryption: undefined, encryptionSettingsCollection: { enabled: true } }))).toBe("ade");
    expect(azureDiskEncryptionState(disk("o", { encryption: { type: "EncryptionAtRestWithSomethingNew" } }))).toBe("other");
    expect(azureDiskEncryptionState({ name: "raw", properties: { encryption: { type: "EncryptionAtRestWithCustomerKey" } } })).toBe("customer");
  });

  it("unmanaged disks / encryption at host", () => {
    expect(azureUnmanagedVmDisks(vm("m"))).toEqual([]);
    expect(azureUnmanagedVmDisks(vm("u", { storageProfile: unmanagedStorage("u") }))).toEqual(["u-osvhd", "u-data0"]);
    expect(azureVmEncryptionAtHost(vm("h"))).toBe(true);
    expect(azureVmEncryptionAtHost(vm("h", { securityProfile: undefined }))).toBe(false);
    expect(azureVmEncryptionAtHost({ properties: { securityProfile: { encryptionAtHost: true } } })).toBe(true);
  });
});

describe("AzureDiskEncryptionScanner", () => {
  it("module name is disk_encryption_findings", () => {
    expect(scanner.moduleName).toBe("disk_encryption_findings");
  });

  it("managed disks: missing / unencrypted → HIGH; platform-only, CMK, double, ADE, unknown type → none", async () => {
    route(
      pages([
        [
          disk("platform"),
          disk("cmk", { encryption: { type: "EncryptionAtRestWithCustomerKey", diskEncryptionSetId: "/des" } }),
          disk("double", { encryption: { type: "EncryptionAtRestWithPlatformAndCustomerKeys" } }),
          disk("noenc", { encryption: undefined }),
          disk("explicit", { encryption: { type: "Unencrypted" }, managedBy: undefined, diskState: "Unattached" }),
          disk("ade", { encryption: undefined, encryptionSettingsCollection: { enabled: true } }),
          disk("future", { encryption: { type: "EncryptionAtRestWithSomethingNew" } }),
        ],
      ]),
      pages([[]]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(7);
    expect(r.findings.map((f) => f.resourceId)).toEqual(["noenc", "explicit"]);
    const f = r.findings[0];
    expect(f.title).toBe("Managed disk noenc is not encrypted at rest");
    expect(f.severity).toBe("HIGH");
    expect(f.riskScore).toBe(7.0);
    expect(f.resourceType).toBe("Microsoft.Compute/disks");
    expect(f.resourceArn).toBe(diskId("noenc"));
    expect(f.region).toBe("chinanorth3");
    expect(f.accountId).toBe(FAKE_TENANT);
    expect(f.provider).toBe("azure");
    expect(f.module).toBe("disk_encryption_findings");
    expect(f.description).toContain("attached to VM vm-a");
    expect(r.findings[1].description).toContain("state Unattached");
    const ctor = azureSdk.ctorArgs.find((a) => a.client === "Compute");
    expect(ctor?.args[1]).toBe(SUB);
    expect(ctor?.args[2]).toMatchObject({ endpoint: "https://management.chinacloudapi.cn" });
  });

  it("VMs: unmanaged VHD without ADE → HIGH; with ADE → none; no encryption at host → LOW", async () => {
    route(
      pages([[]]),
      pages([
        [
          vm("ok"),
          vm("nohost", { securityProfile: { encryptionAtHost: false } }),
          vm("vhd", { storageProfile: unmanagedStorage("vhd") }),
          vm("vhdade", { storageProfile: unmanagedStorage("vhdade", true), securityProfile: {} }),
        ],
      ]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.resourcesScanned).toBe(4);
    expect(r.findings.map((f) => [f.resourceId, f.severity, f.riskScore])).toEqual([
      ["nohost", "LOW", 2.0],
      ["vhd", "HIGH", 7.0],
      ["vhdade", "LOW", 2.0],
    ]);
    expect(r.findings[0].title).toBe("VM nohost does not use encryption at host");
    const vhd = r.findings[1];
    expect(vhd.title).toBe("VM vhd has unmanaged (VHD) disks without Azure Disk Encryption");
    expect(vhd.description).toContain("2 unmanaged");
    expect(vhd.description).toContain("vhd-osvhd, vhd-data0");
    expect(vhd.description).not.toContain("blob.core");
    expect(vhd.resourceArn).toBe(vmId("vhd"));
    expect(vhd.resourceType).toBe("Microsoft.Compute/virtualMachines");
  });

  it("no hit: platform-encrypted disks and fully configured VMs → no findings", async () => {
    route(pages([[disk("a"), disk("b")]]), pages([[vm("v")]]));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(3);
  });

  it("pagination: disks and VMs across ≥2 pages", async () => {
    const dp = { pages: 0 };
    const vp = { pages: 0 };
    route(
      pages([[disk("d1", { encryption: undefined })], [disk("d2")], [disk("d3", { encryption: undefined })]], dp),
      pages([[vm("v1")], [vm("v2", { securityProfile: { encryptionAtHost: false } })]], vp),
    );
    const r = await scanner.scan(azCtx());
    expect(dp.pages).toBe(3);
    expect(vp.pages).toBe(2);
    expect(r.resourcesScanned).toBe(5);
    expect(r.findings.map((f) => f.resourceId)).toEqual(["d1", "d3", "v2"]);
  });

  it("encryption-at-host findings capped with a summary warning; disk listing cap → truncation warning", async () => {
    route(
      pages([Array.from({ length: AZURE_DISK_MAX_DISKS + 1 }, (_, i) => disk(`d${i}`))]),
      pages([Array.from({ length: AZURE_DISK_HOST_MAX_FINDINGS + 7 }, (_, i) => vm(`v${i}`, { securityProfile: undefined }))]),
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(AZURE_DISK_HOST_MAX_FINDINGS);
    expect(r.resourcesScanned).toBe(AZURE_DISK_MAX_DISKS + AZURE_DISK_HOST_MAX_FINDINGS + 7);
    expect(r.warnings).toHaveLength(2);
    expect(r.warnings![0]).toMatch(/disks.list: more than .* truncated/);
    expect(r.warnings![1]).toMatch(/7 more VM\(s\) without encryption at host were not reported individually/);
  });

  it("disks access_denied → warning, VM findings still reported", async () => {
    route(() => failingPages(deniedError()), pages([[vm("nohost", { securityProfile: { encryptionAtHost: false } })]]));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceId)).toEqual(["nohost"]);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toMatch(/^Compute disks.list: insufficient permissions .*managed disk encryption not verified/);
    expectNoLeak(r);
  });

  it("VMs not registered / throttled → warning, disk findings still reported", async () => {
    route(pages([[disk("noenc", { encryption: undefined })]]), () => failingPages(notRegisteredError("Microsoft.Compute")));
    const a = await scanner.scan(azCtx());
    expect(a.status).toBe("success");
    expect(a.findings.map((f) => f.resourceId)).toEqual(["noenc"]);
    expect(a.warnings![0]).toMatch(/^Compute virtualMachines.listAll: not enabled \/ resource provider not registered/);

    route(() => failingPages(throttledError()), () => failingPages(throttledError()));
    const b = await scanner.scan(azCtx());
    expect(b.status).toBe("success");
    expect(b.warnings).toHaveLength(2);
    for (const w of b.warnings!) expect(w).toMatch(/throttled/);
  });

  it("auth_failed in either sub-service → status error (Azure authentication failed …)", async () => {
    route(() => failingPages(authError()), pages([[vm("v")]]));
    const a = await scanner.scan(azCtx());
    expect(a.status).toBe("error");
    expect(a.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
    expect(a.findings).toEqual([]);

    route(pages([[disk("d")]]), () => failingPages(authError()));
    const b = await scanner.scan(azCtx());
    expect(b.status).toBe("error");
    expect(b.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
    expectNoLeak(b);
  });

  it("api_misuse → status error (keeps the other sub-service's warnings)", async () => {
    route(() => failingPages(deniedError()), () => failingPages(misuseError()));
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Azure disk encryption scan failed: .*InvalidApiVersionParameter/);
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
      pages([[disk(hostile("disk"), { id: diskId(hostile("diskid")), location: hostile("loc"), encryption: undefined, managedBy: vmId(hostile("owner")), diskState: hostile("state") })]]),
      pages([
        [
          {
            ...vm(hostile("vm"), { securityProfile: { encryptionAtHost: false } }),
            id: vmId(hostile("vmid")),
            location: hostile("vmloc"),
            storageProfile: { osDisk: { name: hostile("osdisk"), createOption: "FromImage", vhd: { uri: `https://x/${hostile("uri")}` } }, dataDisks: [] },
          },
        ],
      ]),
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

    route(() => failingPages(Object.assign(misuseError(), { message: hostile("misuse") })), pages([[]]));
    const e = await scanner.scan(azCtx());
    expect(e.status).toBe("error");
    expectNoLeak(e);
  });
});
