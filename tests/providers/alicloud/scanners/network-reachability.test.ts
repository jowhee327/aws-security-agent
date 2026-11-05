/**
 * Phase 2 T5 — AliNetworkReachabilityScanner (network_reachability): PortRange / IpProtocol
 * parsing (table-driven), simplified priority / Drop handling, internet-exposed vs private
 * instances, per-SG lookup dedupe + cap, pagination, degrade, auth_failed / api_misuse → error,
 * redaction. aliCall is mocked by spec.action; fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall };
});

import {
  AliNetworkReachabilityScanner,
  aliInstancePublicIp,
  HIGH_RISK_PORTS,
  isAllPortSpan,
  NET_MAX_SECURITY_GROUPS,
  parseAliPortRange,
  parseAliSgRule,
  worldOpenAllPortRules,
  worldOpenRulesForPort,
  type AliSgRule,
} from "../../../../src/providers/alicloud/scanners/network-reachability.js";
import { alibabaCloudProvider } from "../../../../src/providers/alicloud/index.js";
import {
  aliCtx,
  authError,
  callsFor,
  deniedError,
  FAKE_AK,
  isolateAliEnv,
  misuseError,
  restoreAliEnv,
  routeAliCall,
  UID,
  type AliHandler,
} from "./helpers.js";

const scanner = new AliNetworkReachabilityScanner();

interface Perm {
  IpProtocol?: string;
  PortRange?: string;
  SourceCidrIp?: string;
  Ipv6SourceCidrIp?: string;
  Policy?: string;
  Priority?: number | string;
  Direction?: string;
}

const accept = (proto: string, range: string, extra: Perm = {}): Perm => ({
  Direction: "ingress",
  Policy: "Accept",
  Priority: 1,
  IpProtocol: proto,
  PortRange: range,
  SourceCidrIp: "0.0.0.0/0",
  ...extra,
});
const drop = (proto: string, range: string, extra: Perm = {}): Perm => accept(proto, range, { Policy: "Drop", ...extra });

const instance = (id: string, opts: { publicIp?: string; eip?: string; sgs: string[]; name?: string }) => ({
  InstanceId: id,
  InstanceName: opts.name ?? id,
  Status: "Running",
  PublicIpAddress: { IpAddress: opts.publicIp ? [opts.publicIp] : [] },
  EipAddress: { IpAddress: opts.eip ?? "", AllocationId: opts.eip ? "eip-1" : "" },
  SecurityGroupIds: { SecurityGroupId: opts.sgs },
});
const instancesBody = (insts: object[], total = insts.length) => ({ Instances: { Instance: insts }, TotalCount: total });
const sgBody = (perms: Perm[], nextToken?: string) => ({ Permissions: { Permission: perms }, ...(nextToken ? { NextToken: nextToken } : {}) });

/** Rules per security group id. */
const rulesBySg =
  (map: Record<string, Perm[]>): AliHandler =>
  (q) =>
    sgBody(map[q.SecurityGroupId as string] ?? []);

const rules = (groupId: string, perms: Perm[]): AliSgRule[] => perms.map((p) => parseAliSgRule(groupId, p)!).filter(Boolean);

beforeEach(() => {
  isolateAliEnv();
  mocks.aliCall.mockReset();
});
afterEach(() => restoreAliEnv());

/* ------------------------------------------------------------------------ */
/* Parsing                                                                  */
/* ------------------------------------------------------------------------ */

describe("network_reachability — PortRange / IpProtocol parsing", () => {
  const cases: Array<[string, unknown, unknown, { from: number; to: number } | undefined]> = [
    ["TCP a/b", "TCP", "22/22", { from: 22, to: 22 }],
    ["TCP range", "tcp", "3000/3400", { from: 3000, to: 3400 }],
    ["UDP a/b", "UDP", "53/53", { from: 53, to: 53 }],
    ["TCP -1/-1 = all", "TCP", "-1/-1", { from: 1, to: 65535 }],
    ["TCP 1/65535 = all", "TCP", "1/65535", { from: 1, to: 65535 }],
    ["single port", "TCP", "8080", { from: 8080, to: 8080 }],
    ["ALL protocol ignores range", "ALL", "-1/-1", { from: 1, to: 65535 }],
    ["ALL protocol lower-case, no range", "all", undefined, { from: 1, to: 65535 }],
    ["ICMP not a port rule", "ICMP", "-1/-1", undefined],
    ["GRE not a port rule", "GRE", "-1/-1", undefined],
    ["ICMPv6 not a port rule", "ICMPv6", "-1/-1", undefined],
    ["reversed range invalid", "TCP", "80/22", undefined],
    ["out of range invalid", "TCP", "1/70000", undefined],
    ["garbage invalid", "TCP", "ssh", undefined],
    ["missing range invalid", "TCP", undefined, undefined],
    ["missing protocol", undefined, "22/22", undefined],
  ];
  it.each(cases)("%s", (_label, proto, range, expected) => {
    expect(parseAliPortRange(proto, range)).toEqual(expected);
  });

  it("isAllPortSpan", () => {
    expect(isAllPortSpan({ from: 1, to: 65535 })).toBe(true);
    expect(isAllPortSpan({ from: 0, to: 65535 })).toBe(true);
    expect(isAllPortSpan({ from: 22, to: 65535 })).toBe(false);
    expect(isAllPortSpan(undefined)).toBe(false);
  });

  it("parseAliSgRule: ingress only, Accept default, Priority default 1, ipv4 / ipv6 world", () => {
    expect(parseAliSgRule("sg-1", { ...accept("TCP", "22/22"), Direction: "egress" })).toBeUndefined();
    expect(parseAliSgRule("sg-1", accept("ICMP", "-1/-1"))).toBeUndefined();
    const r = parseAliSgRule("sg-1", { IpProtocol: "TCP", PortRange: "22/22", SourceCidrIp: "0.0.0.0/0" })!;
    expect(r).toEqual({ groupId: "sg-1", policy: "accept", priority: 1, span: { from: 22, to: 22 }, ipv4World: true, ipv6World: false });
    const v6 = parseAliSgRule("sg-1", { IpProtocol: "TCP", PortRange: "22/22", SourceCidrIp: "", Ipv6SourceCidrIp: "::/0", Priority: "5" })!;
    expect(v6.ipv6World).toBe(true);
    expect(v6.ipv4World).toBe(false);
    expect(v6.priority).toBe(5);
    expect(parseAliSgRule("sg-1", accept("TCP", "22/22", { SourceCidrIp: "10.0.0.0/8" }))!.ipv4World).toBe(false);
  });

  it("aliInstancePublicIp: PublicIpAddress first, then EIP, else undefined", () => {
    expect(aliInstancePublicIp(instance("i", { publicIp: "1.2.3.4", sgs: [] }))).toBe("1.2.3.4");
    expect(aliInstancePublicIp(instance("i", { eip: "5.6.7.8", sgs: [] }))).toBe("5.6.7.8");
    expect(aliInstancePublicIp(instance("i", { sgs: [] }))).toBeUndefined();
  });
});

describe("network_reachability — priority / Drop (simplified)", () => {
  it("world Accept covering the port is open; non-world / non-covering are not", () => {
    expect(worldOpenRulesForPort(rules("sg", [accept("TCP", "22/22")]), 22)).toHaveLength(1);
    expect(worldOpenRulesForPort(rules("sg", [accept("TCP", "20/30")]), 22)).toHaveLength(1);
    expect(worldOpenRulesForPort(rules("sg", [accept("TCP", "80/80")]), 22)).toHaveLength(0);
    expect(worldOpenRulesForPort(rules("sg", [accept("TCP", "22/22", { SourceCidrIp: "203.0.113.0/24" })]), 22)).toHaveLength(0);
    expect(worldOpenRulesForPort(rules("sg", [accept("TCP", "22/22", { SourceCidrIp: undefined, Ipv6SourceCidrIp: "::/0" })]), 22)).toHaveLength(1);
  });

  it("same-priority world Drop wins; higher-priority (smaller number) Drop wins; lower-priority Drop does not", () => {
    expect(worldOpenRulesForPort(rules("sg", [accept("TCP", "22/22", { Priority: 5 }), drop("TCP", "22/22", { Priority: 5 })]), 22)).toHaveLength(0);
    expect(worldOpenRulesForPort(rules("sg", [accept("TCP", "22/22", { Priority: 5 }), drop("TCP", "1/65535", { Priority: 1 })]), 22)).toHaveLength(0);
    expect(worldOpenRulesForPort(rules("sg", [accept("TCP", "22/22", { Priority: 1 }), drop("TCP", "22/22", { Priority: 10 })]), 22)).toHaveLength(1);
  });

  it("Drop must match the address family and be world-wide (partial-CIDR Drops are not evaluated)", () => {
    expect(
      worldOpenRulesForPort(rules("sg", [accept("TCP", "22/22"), drop("TCP", "22/22", { SourceCidrIp: undefined, Ipv6SourceCidrIp: "::/0" })]), 22),
    ).toHaveLength(1);
    expect(worldOpenRulesForPort(rules("sg", [accept("TCP", "22/22"), drop("TCP", "22/22", { SourceCidrIp: "1.2.3.0/24" })]), 22)).toHaveLength(1);
  });

  it("all-ports Accept is reported unless a world Drop covers a sampled port", () => {
    expect(worldOpenAllPortRules(rules("sg", [accept("ALL", "-1/-1")]))).toHaveLength(1);
    expect(worldOpenAllPortRules(rules("sg", [accept("TCP", "1/65535")]))).toHaveLength(1);
    expect(worldOpenAllPortRules(rules("sg", [accept("TCP", "1/1024")]))).toHaveLength(0);
    expect(worldOpenAllPortRules(rules("sg", [accept("ALL", "-1/-1", { Priority: 10 }), drop("TCP", "22/22", { Priority: 1 })]))).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

describe("network_reachability — scan", () => {
  it("exposed vs not: public SSH instance flagged 9.5; private instance with the same SG ignored", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: instancesBody([
        instance("i-pub", { publicIp: "47.1.1.1", sgs: ["sg-ssh"], name: "bastion" }),
        instance("i-priv", { sgs: ["sg-ssh"] }),
      ]),
      DescribeSecurityGroupAttribute: rulesBySg({ "sg-ssh": [accept("TCP", "22/22"), accept("TCP", "443/443")] }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.module).toBe("network_reachability");
    expect(r.resourcesScanned).toBe(1);
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f.title).toBe("ECS i-pub (47.1.1.1): SSH (22) reachable from internet");
    expect(f.riskScore).toBe(9.5);
    expect(f.severity).toBe("CRITICAL");
    expect(f.resourceType).toBe("ACS::ECS::Instance");
    expect(f.resourceId).toBe("i-pub");
    expect(f.resourceArn).toBe(`acs:ecs:cn-hangzhou:${UID}:instance/i-pub`);
    expect(f.description).toContain("sg-ssh");
    expect(f.provider).toBe("alicloud");
    const sgCalls = callsFor(mocks.aliCall, "DescribeSecurityGroupAttribute");
    expect(sgCalls).toHaveLength(1);
    expect(sgCalls[0][2]).toMatchObject({ RegionId: "cn-hangzhou", SecurityGroupId: "sg-ssh", Direction: "ingress" });
  });

  it("EIP-only instance with ALL / -1/-1 → one finding per high-risk port + all-ports 8.0", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: instancesBody([instance("i-eip", { eip: "8.8.4.4", sgs: ["sg-open"] })]),
      DescribeSecurityGroupAttribute: rulesBySg({ "sg-open": [accept("ALL", "-1/-1")] }),
    });
    const r = await scanner.scan(aliCtx());
    const portCount = Object.keys(HIGH_RISK_PORTS).length;
    expect(r.findings).toHaveLength(portCount + 1);
    expect(r.findings.filter((f) => f.riskScore === 9.5)).toHaveLength(portCount);
    const all = r.findings.find((f) => f.riskScore === 8.0)!;
    expect(all.title).toBe("ECS i-eip (8.8.4.4): all ports reachable from internet");
    expect(all.severity).toBe("HIGH");
  });

  it("IPv6 ::/0 rule on MySQL → flagged", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: instancesBody([instance("i-v6", { publicIp: "1.1.1.1", sgs: ["sg-v6"] })]),
      DescribeSecurityGroupAttribute: rulesBySg({ "sg-v6": [accept("TCP", "3306/3306", { SourceCidrIp: "", Ipv6SourceCidrIp: "::/0" })] }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings.map((f) => f.title)).toEqual(["ECS i-v6 (1.1.1.1): MySQL (3306) reachable from internet"]);
  });

  it("no hit: restricted CIDRs, Drop of same priority, non-risky ports → 0 findings", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: instancesBody([instance("i-1", { publicIp: "1.1.1.1", sgs: ["sg-a", "sg-b"] })]),
      DescribeSecurityGroupAttribute: rulesBySg({
        "sg-a": [accept("TCP", "22/22", { SourceCidrIp: "203.0.113.10/32" }), accept("TCP", "80/80"), accept("TCP", "443/443")],
        // Drop in another group of the same instance blocks the open RDP Accept (rules are pooled).
        "sg-b": [accept("TCP", "3389/3389", { Priority: 3 }), drop("TCP", "3389/3389", { Priority: 3 })],
      }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.resourcesScanned).toBe(1);
  });

  it("dedupes SG lookups across instances and paginates instances (2 pages) and SG rules (NextToken)", async () => {
    const page1 = Array.from({ length: 100 }, (_, i) => instance(`i-${i}`, { publicIp: `10.0.0.${i % 250}`, sgs: ["sg-shared"] }));
    routeAliCall(mocks.aliCall, {
      DescribeInstances: (q) => (q.PageNumber === 1 ? instancesBody(page1, 101) : instancesBody([instance("i-last", { publicIp: "9.9.9.9", sgs: ["sg-shared"] })], 101)),
      DescribeSecurityGroupAttribute: (q) => (q.NextToken === "tok-2" ? sgBody([accept("TCP", "6379/6379")]) : sgBody([accept("TCP", "80/80")], "tok-2")),
    });
    const r = await scanner.scan(aliCtx());
    expect(callsFor(mocks.aliCall, "DescribeInstances").map((c) => c[2].PageNumber)).toEqual([1, 2]);
    const sgCalls = callsFor(mocks.aliCall, "DescribeSecurityGroupAttribute");
    expect(sgCalls).toHaveLength(2);
    expect(sgCalls[1][2].NextToken).toBe("tok-2");
    expect(r.resourcesScanned).toBe(101);
    expect(r.findings).toHaveLength(101);
    expect(r.findings.every((f) => f.title.includes("Redis (6379)"))).toBe(true);
  });

  it(`caps distinct SG lookups at NET_MAX_SECURITY_GROUPS (${NET_MAX_SECURITY_GROUPS}) with a warning`, async () => {
    const insts = Array.from({ length: NET_MAX_SECURITY_GROUPS + 2 }, (_, i) => instance(`i-${i}`, { publicIp: "1.1.1.1", sgs: [`sg-${i}`] }));
    routeAliCall(mocks.aliCall, {
      DescribeInstances: (q) => {
        const start = ((q.PageNumber as number) - 1) * 100;
        return instancesBody(insts.slice(start, start + 100), insts.length);
      },
      DescribeSecurityGroupAttribute: sgBody([]),
    });
    const r = await scanner.scan(aliCtx());
    expect(callsFor(mocks.aliCall, "DescribeSecurityGroupAttribute")).toHaveLength(NET_MAX_SECURITY_GROUPS);
    expect(r.warnings?.some((w) => w.includes(`only the first ${NET_MAX_SECURITY_GROUPS}`))).toBe(true);
  });
});

describe("network_reachability — errors", () => {
  it("access_denied on one SG → warning (incomplete), other SGs still evaluated", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: instancesBody([instance("i-1", { publicIp: "1.1.1.1", sgs: ["sg-denied", "sg-ok"] })]),
      DescribeSecurityGroupAttribute: (q) => {
        if (q.SecurityGroupId === "sg-denied") throw deniedError("ecs:DescribeSecurityGroupAttribute");
        return sgBody([accept("TCP", "22/22")]);
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.title)).toEqual(["ECS i-1 (1.1.1.1): SSH (22) reachable from internet"]);
    expect(r.warnings?.some((w) => w.startsWith("ECS DescribeSecurityGroupAttribute (sg-denied): insufficient permissions"))).toBe(true);
    expect(r.warnings?.some((w) => w.includes("could not be evaluated"))).toBe(true);
  });

  it("access_denied on DescribeInstances → success with warning, 0 findings", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: () => {
        throw deniedError("ecs:DescribeInstances");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings?.some((w) => w.startsWith("ECS DescribeInstances: insufficient permissions"))).toBe(true);
  });

  it("auth_failed on DescribeInstances → status error with canonical prefix", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: () => {
        throw authError("ecs:DescribeInstances");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error?.startsWith("Alibaba Cloud authentication failed")).toBe(true);
  });

  it("auth_failed in the SG fan-out → status error", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: instancesBody([instance("i-1", { publicIp: "1.1.1.1", sgs: ["sg-1"] })]),
      DescribeSecurityGroupAttribute: () => {
        throw authError("ecs:DescribeSecurityGroupAttribute");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error?.startsWith("Alibaba Cloud authentication failed")).toBe(true);
    expect(r.findings).toEqual([]);
  });

  it("api_misuse (MissingParameter) → status error, not swallowed", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: instancesBody([instance("i-1", { publicIp: "1.1.1.1", sgs: ["sg-1"] })]),
      DescribeSecurityGroupAttribute: () => {
        throw misuseError("ecs:DescribeSecurityGroupAttribute");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toContain("Security group rule lookup failed");
    expect(r.error).toContain("MissingParameter");
  });

  it("redaction: AK-looking instance id / name / SG id never reach the result", async () => {
    const sgId = `sg-${FAKE_AK}`;
    routeAliCall(mocks.aliCall, {
      DescribeInstances: instancesBody([instance(`i-${FAKE_AK}`, { publicIp: "1.1.1.1", sgs: [sgId], name: FAKE_AK })]),
      DescribeSecurityGroupAttribute: rulesBySg({ [sgId]: [accept("TCP", "22/22")] }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings).toHaveLength(1);
    // The raw id is still used for the API call …
    expect(callsFor(mocks.aliCall, "DescribeSecurityGroupAttribute")[0][2].SecurityGroupId).toBe(sgId);
    // … but never echoed in the result.
    const text = JSON.stringify(r);
    expect(text).not.toContain(FAKE_AK);
    expect(text).toContain("[REDACTED]");
  });
});

describe("network_reachability — registration", () => {
  it("is registered on the alicloud provider", () => {
    expect(alibabaCloudProvider.scanners().some((s) => s.moduleName === "network_reachability")).toBe(true);
  });
});
