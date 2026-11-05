/**
 * Phase 2 (Azure) T5 — AzureNetworkReachabilityScanner (network_reachability): table-driven
 * NSG port / rule parsing, priority evaluation (higher-priority world Deny suppresses, partial
 * Deny does not), subnet + NIC NSG layering, public-IP association (severity), no-NSG Basic vs
 * Standard SKU, pagination, per-sub-service degrade, error matrix and hostile-field redaction.
 * Every `@azure/*` package is mocked; fake service principal only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@azure/identity", async () => ({ ClientSecretCredential: (await import("./helpers.js")).FakeClientSecretCredential }));
vi.mock("@azure/logger", () => ({ setLogLevel: () => {}, AzureLogger: { log: () => {} } }));
vi.mock("@azure/arm-network", async () => ({ NetworkManagementClient: (await import("./helpers.js")).fakeArmClientClass("Network") }));

import { clearAzureCredentialCache } from "../../../../src/providers/azure/client.js";
import { AZURE_AUTH_FAILED_PREFIX } from "../../../../src/providers/azure/errors.js";
import {
  AZURE_NET_MAX_NSGS,
  AzureNetworkReachabilityScanner,
  HIGH_RISK_PORTS,
  azureDecidingRule,
  azureNicIdFromIpConfigId,
  azureNsgRules,
  azureRulePortSpans,
  parseAzureNsgRule,
  parseAzurePortRange,
} from "../../../../src/providers/azure/scanners/nsg-reachability.js";
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

const NSGS = "Network.networkSecurityGroups.listAll";
const NICS = "Network.networkInterfaces.listAll";
const PIPS = "Network.publicIPAddresses.listAll";

const RG = `/subscriptions/${SUB}/resourceGroups/rg-net/providers`;
const nsgId = (n: string) => `${RG}/Microsoft.Network/networkSecurityGroups/${n}`;
const nicId = (n: string) => `${RG}/Microsoft.Network/networkInterfaces/${n}`;
const pipId = (n: string) => `${RG}/Microsoft.Network/publicIPAddresses/${n}`;
const subnetId = (n: string) => `${RG}/Microsoft.Network/virtualNetworks/vnet1/subnets/${n}`;
const vmId = (n: string) => `/subscriptions/${SUB}/resourceGroups/rg-vm/providers/Microsoft.Compute/virtualMachines/${n}`;

const AZURE_DEFAULT_RULES = [
  { name: "AllowVnetInBound", priority: 65000, direction: "Inbound", access: "Allow", protocol: "*", sourceAddressPrefix: "VirtualNetwork", destinationPortRange: "*" },
  { name: "AllowAzureLoadBalancerInBound", priority: 65001, direction: "Inbound", access: "Allow", protocol: "*", sourceAddressPrefix: "AzureLoadBalancer", destinationPortRange: "*" },
  { name: "DenyAllInBound", priority: 65500, direction: "Inbound", access: "Deny", protocol: "*", sourceAddressPrefix: "*", destinationPortRange: "*" },
];

const rule = (name: string, priority: number, extra: Record<string, unknown> = {}) => ({
  name,
  priority,
  direction: "Inbound",
  access: "Allow",
  protocol: "Tcp",
  sourceAddressPrefix: "*",
  destinationPortRange: "22",
  ...extra,
});

const nsg = (name: string, rules: unknown[], assoc: { nics?: string[]; subnets?: string[] } = {}) => ({
  id: nsgId(name),
  name,
  location: "chinanorth3",
  securityRules: rules,
  defaultSecurityRules: AZURE_DEFAULT_RULES,
  networkInterfaces: (assoc.nics ?? []).map((n) => ({ id: nicId(n) })),
  subnets: (assoc.subnets ?? []).map((s) => ({ id: subnetId(s) })),
});

const nic = (name: string, opts: { nsg?: string; subnet?: string; pip?: string; vm?: string } = {}) => ({
  id: nicId(name),
  name,
  location: "chinanorth3",
  ...(opts.nsg ? { networkSecurityGroup: { id: nsgId(opts.nsg) } } : {}),
  ...(opts.vm ? { virtualMachine: { id: vmId(opts.vm) } } : {}),
  ipConfigurations: [
    {
      id: `${nicId(name)}/ipConfigurations/ipconfig1`,
      name: "ipconfig1",
      subnet: { id: subnetId(opts.subnet ?? "default") },
      ...(opts.pip ? { publicIPAddress: { id: pipId(opts.pip) } } : {}),
    },
  ],
});

const pip = (name: string, ip: string, opts: { nic?: string; sku?: string } = {}) => ({
  id: pipId(name),
  name,
  location: "chinanorth3",
  ipAddress: ip,
  sku: { name: opts.sku ?? "Standard" },
  ...(opts.nic ? { ipConfiguration: { id: `${nicId(opts.nic)}/ipConfigurations/ipconfig1` } } : {}),
});

function route(nsgs: unknown, nics: unknown, pips: unknown) {
  for (const [op, v] of [
    [NSGS, nsgs],
    [NICS, nics],
    [PIPS, pips],
  ] as const) {
    azureSdk.on(op, typeof v === "function" ? v : () => pages([v as unknown[]]));
  }
}

const scanner = new AzureNetworkReachabilityScanner();
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

describe("port / rule parsing (table-driven)", () => {
  it.each([
    ["22", { from: 22, to: 22 }],
    [" 3389 ", { from: 3389, to: 3389 }],
    ["1000-2000", { from: 1000, to: 2000 }],
    ["20 - 25", { from: 20, to: 25 }],
    ["*", { from: 0, to: 65535 }],
    ["0-65535", { from: 0, to: 65535 }],
    ["65535", { from: 65535, to: 65535 }],
    ["65536", undefined],
    ["2000-1000", undefined],
    ["-1", undefined],
    ["22,23", undefined],
    ["ssh", undefined],
    ["", undefined],
    [undefined, undefined],
    [22, undefined],
  ])("parseAzurePortRange(%j) → %j", (input, expected) => {
    expect(parseAzurePortRange(input)).toEqual(expected);
  });

  it("destinationPortRange and destinationPortRanges[] are both used", () => {
    expect(azureRulePortSpans({ destinationPortRange: "22", destinationPortRanges: ["3389", "5000-5100", "bad"] })).toEqual([
      { from: 22, to: 22 },
      { from: 3389, to: 3389 },
      { from: 5000, to: 5100 },
    ]);
    expect(azureRulePortSpans({ destinationPortRanges: ["*"] })).toEqual([{ from: 0, to: 65535 }]);
    expect(azureRulePortSpans({ properties: { destinationPortRange: "443" } })).toEqual([{ from: 443, to: 443 }]);
  });

  it.each([
    ["*", true, true],
    ["Internet", true, true],
    ["internet", true, true],
    ["0.0.0.0/0", true, false],
    ["::/0", false, true],
    ["10.0.0.0/8", false, false],
    ["VirtualNetwork", false, false],
    ["AzureLoadBalancer", false, false],
    ["203.0.113.4", false, false],
  ])("source %s → ipv4World=%s ipv6World=%s", (src, v4, v6) => {
    const r = parseAzureNsgRule(rule("r", 100, { sourceAddressPrefix: src }));
    expect(r).toMatchObject({ ipv4World: v4, ipv6World: v6 });
  });

  it("sourceAddressPrefixes[] counts; direction / protocol / access filters", () => {
    expect(parseAzureNsgRule(rule("r", 100, { sourceAddressPrefix: undefined, sourceAddressPrefixes: ["10.0.0.0/8", "0.0.0.0/0"] }))?.ipv4World).toBe(true);
    expect(parseAzureNsgRule(rule("r", 100, { sourceAddressPrefix: undefined, sourceAddressPrefixes: ["10.0.0.0/8"] }))?.ipv4World).toBe(false);
    expect(parseAzureNsgRule(rule("r", 100, { direction: "Outbound" }))).toBeUndefined();
    expect(parseAzureNsgRule(rule("r", 100, { protocol: "Icmp" }))).toBeUndefined();
    expect(parseAzureNsgRule(rule("r", 100, { protocol: "Udp" }))).toBeDefined();
    expect(parseAzureNsgRule(rule("r", 100, { protocol: "*" }))).toBeDefined();
    expect(parseAzureNsgRule(rule("r", 100, { access: "Maybe" }))).toBeUndefined();
    expect(parseAzureNsgRule(rule("r", 100, { destinationPortRange: "nope" }))).toBeUndefined();
    expect(parseAzureNsgRule({ name: "raw", properties: rule("x", 120) })).toMatchObject({ access: "allow", priority: 120 });
  });

  it("priority: lower number wins; partial-source rules never decide; implicit deny", () => {
    const rules = azureNsgRules(
      nsg("n", [
        rule("allow-ssh-world", 300),
        rule("deny-ssh-world", 200, { access: "Deny" }),
        rule("deny-rdp-partial", 100, { access: "Deny", destinationPortRange: "3389", sourceAddressPrefix: "198.51.100.0/24" }),
        rule("allow-rdp-world", 110, { destinationPortRange: "3389" }),
        rule("allow-mysql-partial", 100, { destinationPortRange: "3306", sourceAddressPrefix: "10.0.0.0/8" }),
      ]),
    );
    expect(azureDecidingRule(rules, 22, "v4")?.name).toBe("deny-ssh-world");
    expect(azureDecidingRule(rules, 3389, "v4")?.name).toBe("allow-rdp-world");
    expect(azureDecidingRule(rules, 3306, "v4")?.name).toBe("DenyAllInBound");
    expect(azureDecidingRule(azureNsgRules({ securityRules: [] }), 22, "v4")).toBeUndefined();
  });

  it("NIC id from an IP configuration id", () => {
    expect(azureNicIdFromIpConfigId(`${nicId("NIC-A")}/ipConfigurations/ipconfig1`)).toBe(nicId("NIC-A").toLowerCase());
    expect(azureNicIdFromIpConfigId(`${RG}/Microsoft.Network/loadBalancers/lb/frontendIPConfigurations/fe`)).toBeUndefined();
    expect(azureNicIdFromIpConfigId(undefined)).toBeUndefined();
  });

  it("reuses the AWS high-risk port table", () => {
    expect(HIGH_RISK_PORTS[22]).toBe("SSH");
    expect(HIGH_RISK_PORTS[3389]).toBe("RDP");
    expect(Object.keys(HIGH_RISK_PORTS)).toHaveLength(9);
  });
});

describe("AzureNetworkReachabilityScanner", () => {
  it("module name is network_reachability", () => {
    expect(scanner.moduleName).toBe("network_reachability");
  });

  it("public VM NIC with world SSH / RDP Allow → CRITICAL per port; Deny at higher priority suppresses", async () => {
    route(
      [
        nsg(
          "nsg-web",
          [
            rule("ssh", 100),
            rule("rdp", 110, { destinationPortRange: undefined, destinationPortRanges: ["3389", "8080"], sourceAddressPrefix: "Internet" }),
            rule("deny-mysql", 120, { access: "Deny", destinationPortRange: "3306" }),
            rule("mysql", 130, { destinationPortRange: "3306" }),
            rule("pg-partial", 140, { destinationPortRange: "5432", sourceAddressPrefix: "203.0.113.0/24" }),
          ],
          { nics: ["nic-web"] },
        ),
      ],
      [nic("nic-web", { nsg: "nsg-web", pip: "pip-web", vm: "vm-web" })],
      [pip("pip-web", "52.130.1.10", { nic: "nic-web" })],
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(2);
    expect(r.findings.map((f) => f.title)).toEqual([
      "VM vm-web (NIC nic-web, 52.130.1.10): SSH (22) reachable from internet",
      "VM vm-web (NIC nic-web, 52.130.1.10): RDP (3389) reachable from internet",
    ]);
    const f = r.findings[0];
    expect(f.severity).toBe("CRITICAL");
    expect(f.riskScore).toBe(9.5);
    expect(f.resourceType).toBe("Microsoft.Compute/virtualMachines");
    expect(f.resourceArn).toBe(vmId("vm-web"));
    expect(f.region).toBe("chinanorth3");
    expect(f.accountId).toBe(FAKE_TENANT);
    expect(f.provider).toBe("azure");
    expect(f.module).toBe("network_reachability");
    expect(f.description).toContain("NSG nsg-web rule ssh (priority 100)");
    const ctor = azureSdk.ctorArgs.find((a) => a.client === "Network");
    expect(ctor?.args[1]).toBe(SUB);
    expect(ctor?.args[2]).toMatchObject({ endpoint: "https://management.chinacloudapi.cn" });
  });

  it("all ports open (`*`) → per-port findings + an all-ports finding", async () => {
    route(
      [nsg("nsg-any", [rule("any", 100, { destinationPortRange: "*", protocol: "*" })], { nics: ["nic-a"] })],
      [nic("nic-a", { nsg: "nsg-any", pip: "pip-a" })],
      [pip("pip-a", "52.130.1.11")],
    );
    const r = await scanner.scan(azCtx());
    expect(r.findingsCount).toBe(Object.keys(HIGH_RISK_PORTS).length + 1);
    const all = r.findings.at(-1)!;
    expect(all.title).toBe("NIC nic-a (52.130.1.11): all ports reachable from internet");
    expect(all.riskScore).toBe(8.0);
    expect(all.resourceType).toBe("Microsoft.Network/networkInterfaces");
    expect(all.resourceArn).toBe(nicId("nic-a"));
  });

  it("subnet + NIC NSG layering: both must allow; subnet Deny blocks NIC Allow", async () => {
    route(
      [
        nsg("nsg-subnet", [rule("deny-ssh", 100, { access: "Deny" }), rule("rdp", 110, { destinationPortRange: "3389" })], { subnets: ["web"] }),
        nsg("nsg-nic", [rule("ssh", 100), rule("rdp", 110, { destinationPortRange: "3389" })], { nics: ["nic-b"] }),
      ],
      [nic("nic-b", { nsg: "nsg-nic", subnet: "web", pip: "pip-b" })],
      [pip("pip-b", "52.130.1.12")],
    );
    const r = await scanner.scan(azCtx());
    expect(r.findings.map((f) => f.title)).toEqual(["NIC nic-b (52.130.1.12): RDP (3389) reachable from internet"]);
    expect(r.findings[0].description).toContain("NSG nsg-subnet rule rdp (priority 110) and NSG nsg-nic rule rdp (priority 110)");
  });

  it("subnet-only NSG governs a NIC without its own NSG", async () => {
    route([nsg("nsg-subnet", [rule("ssh", 100)], { subnets: ["web"] })], [nic("nic-c", { subnet: "web", pip: "pip-c" })], [pip("pip-c", "52.130.1.13")]);
    const r = await scanner.scan(azCtx());
    expect(r.findings.map((f) => f.title)).toEqual(["NIC nic-c (52.130.1.13): SSH (22) reachable from internet"]);
  });

  it("no NSG anywhere: Basic SKU public IP → all ports; Standard SKU → none", async () => {
    route(
      [],
      [nic("nic-basic", { pip: "pip-basic" }), nic("nic-std", { pip: "pip-std" })],
      [pip("pip-basic", "52.130.1.14", { sku: "Basic" }), pip("pip-std", "52.130.1.15", { sku: "Standard" })],
    );
    const r = await scanner.scan(azCtx());
    expect(r.findings.map((f) => [f.title, f.riskScore])).toEqual([["NIC nic-basic (52.130.1.14): all ports reachable from internet (no NSG)", 8.0]]);
  });

  it("NSG in use but no public IP → MEDIUM per NSG; unassociated NSG → none; IPv6 ::/0 counts", async () => {
    route(
      [
        nsg("nsg-private", [rule("ssh", 100), rule("redis6", 110, { destinationPortRange: "6379", sourceAddressPrefix: "::/0" })], { nics: ["nic-priv"] }),
        nsg("nsg-orphan", [rule("ssh", 100)]),
        nsg("nsg-closed", [rule("https", 100, { destinationPortRange: "443" })], { subnets: ["app"] }),
      ],
      [nic("nic-priv", { nsg: "nsg-private" })],
      [],
    );
    const r = await scanner.scan(azCtx());
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f.title).toBe("NSG nsg-private allows high-risk ports from the internet (no public IP association found)");
    expect(f.severity).toBe("MEDIUM");
    expect(f.riskScore).toBe(5.0);
    expect(f.resourceArn).toBe(nsgId("nsg-private"));
    expect(f.description).toContain("SSH (22) via rule ssh, Redis (6379) via rule redis6");
  });

  it("no hit: restricted sources / non-risky ports → no findings", async () => {
    route(
      [nsg("nsg-ok", [rule("https", 100, { destinationPortRange: "443" }), rule("ssh-office", 110, { sourceAddressPrefix: "203.0.113.0/24" })], { nics: ["nic-ok"] })],
      [nic("nic-ok", { nsg: "nsg-ok", pip: "pip-ok" })],
      [pip("pip-ok", "52.130.1.16")],
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toBeUndefined();
  });

  it("pagination: NSGs / NICs / public IPs across ≥2 pages", async () => {
    const np = { pages: 0 };
    const ip = { pages: 0 };
    const pp = { pages: 0 };
    route(
      () => pages([[nsg("n1", [rule("ssh", 100)], { nics: ["c1"] })], [nsg("n2", [rule("rdp", 100, { destinationPortRange: "3389" })], { nics: ["c2"] })]], np),
      () => pages([[nic("c1", { nsg: "n1", pip: "p1" })], [nic("c2", { nsg: "n2", pip: "p2" })]], ip),
      () => pages([[pip("p1", "52.130.2.1")], [pip("p2", "52.130.2.2")]], pp),
    );
    const r = await scanner.scan(azCtx());
    expect([np.pages, ip.pages, pp.pages]).toEqual([2, 2, 2]);
    expect(r.resourcesScanned).toBe(4);
    expect(r.findings.map((f) => f.title)).toEqual([
      "NIC c1 (52.130.2.1): SSH (22) reachable from internet",
      "NIC c2 (52.130.2.2): RDP (3389) reachable from internet",
    ]);
  });

  it("NSG listing truncated → warning; NIC whose NSG is missing is skipped with a warning", async () => {
    route(
      Array.from({ length: AZURE_NET_MAX_NSGS + 1 }, (_, i) => nsg(`n${i}`, [])),
      [nic("late", { nsg: `n${AZURE_NET_MAX_NSGS}`, pip: "p" })],
      [pip("p", "52.130.3.1")],
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toHaveLength(2);
    expect(r.warnings![0]).toMatch(/networkSecurityGroups.listAll: more than .* truncated/);
    expect(r.warnings![1]).toMatch(/NSG of NIC late was not in the NSG listing/);
  });

  it("NIC listing access_denied → warning; NICs found via public IP still evaluated (NIC-level NSG)", async () => {
    route(
      [nsg("nsg-nic", [rule("ssh", 100)], { nics: ["nic-d"] })],
      () => failingPages(deniedError()),
      [pip("pip-d", "52.130.4.1", { nic: "nic-d" }), pip("pip-orphan", "52.130.4.2", { sku: "Basic", nic: "nic-nonsg" })],
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    // nic-nonsg: no NSG known, but the subnet layer is unknown → the no-NSG check is skipped.
    expect(r.findings.map((f) => f.title)).toEqual(["NIC nic-d (52.130.4.1): SSH (22) reachable from internet"]);
    expect(r.warnings).toHaveLength(2);
    expect(r.warnings![0]).toMatch(/^Network networkInterfaces.listAll: insufficient permissions .*associations incomplete/);
    expect(r.warnings![1]).toMatch(/subnet NSGs of internet-exposed NICs could not be resolved/);
    expectNoLeak(r);
  });

  it("NSG listing not registered → warning, no evaluation; public IP listing throttled → warning, findings still raised", async () => {
    route(() => failingPages(notRegisteredError("Microsoft.Network")), [nic("x", { pip: "p" })], [pip("p", "1.1.1.1", { sku: "Basic" })]);
    const a = await scanner.scan(azCtx());
    expect(a.status).toBe("success");
    expect(a.findings).toEqual([]);
    expect(a.warnings![0]).toMatch(/^Network networkSecurityGroups.listAll: not enabled \/ resource provider not registered.*NSG rules not evaluated/);

    route([nsg("n", [rule("ssh", 100)], { nics: ["x"] })], [nic("x", { nsg: "n", pip: "p" })], () => failingPages(throttledError()));
    const b = await scanner.scan(azCtx());
    expect(b.status).toBe("success");
    expect(b.findings.map((f) => f.title)).toEqual(["NIC x (public IP): SSH (22) reachable from internet"]);
    expect(b.warnings![0]).toMatch(/throttled/);
  });

  it("auth_failed in any sub-service → status error (Azure authentication failed …)", async () => {
    for (const which of [0, 1, 2]) {
      const fail = () => failingPages(authError());
      route(which === 0 ? fail : [], which === 1 ? fail : [], which === 2 ? fail : []);
      const r = await scanner.scan(azCtx());
      expect(r.status).toBe("error");
      expect(r.error!.startsWith(AZURE_AUTH_FAILED_PREFIX)).toBe(true);
      expect(r.findings).toEqual([]);
      expectNoLeak(r);
    }
  });

  it("api_misuse → status error (keeps the other sub-services' warnings)", async () => {
    route(() => failingPages(misuseError()), () => failingPages(deniedError()), []);
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Azure network reachability scan failed: .*InvalidApiVersionParameter/);
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
    const h = hostile("x");
    route(
      [
        { ...nsg(hostile("nsg"), [rule(hostile("rule"), 100), rule("any", 110, { destinationPortRange: "*" })], { nics: [h] }), location: hostile("loc") },
        nsg(hostile("private"), [rule(hostile("rule2"), 100)], { subnets: ["s"] }),
      ],
      [{ ...nic(h, { pip: "p", vm: hostile("vm") }), networkSecurityGroup: { id: nsgId(hostile("nsg")) }, location: hostile("nicloc") }],
      [pip("p", hostile("ip")), pip("p2", "2.2.2.2", { nic: hostile("ghost") })],
    );
    const r = await scanner.scan(azCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBeGreaterThan(2);
    expectNoLeak(r);
    expect(r.findings[0].title).toContain("[REDACTED]");

    route(
      () => failingPages(Object.assign(deniedError(), { message: hostile("denied") })),
      () => failingPages(Object.assign(throttledError(), { message: hostile("throttled") })),
      [],
    );
    const w = await scanner.scan(azCtx());
    expect(w.warnings).toHaveLength(2);
    expectNoLeak(w);

    route(() => failingPages(Object.assign(misuseError(), { message: hostile("misuse") })), [], []);
    const e = await scanner.scan(azCtx());
    expect(e.status).toBe("error");
    expectNoLeak(e);
  });
});
