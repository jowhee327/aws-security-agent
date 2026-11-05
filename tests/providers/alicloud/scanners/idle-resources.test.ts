/**
 * Phase 2 T5 — AliIdleResourcesScanner (idle_resources): unattached disks, unbound EIPs,
 * stopped instances (KeepCharging flagged higher), security groups with 0 ENIs; pagination,
 * SG cap, degrade, auth_failed / api_misuse → error, redaction of AK-looking ids / names.
 * aliCall is mocked by spec.action; fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall };
});

import {
  AliIdleResourcesScanner,
  IDLE_MAX_SG_CHECKS,
  isKeepCharging,
} from "../../../../src/providers/alicloud/scanners/idle-resources.js";
import { alibabaCloudProvider } from "../../../../src/providers/alicloud/index.js";
import {
  aliCtx,
  authError,
  callsFor,
  deniedError,
  FAKE_AK,
  FAKE_SK,
  isolateAliEnv,
  misuseError,
  restoreAliEnv,
  routeAliCall,
  UID,
  type AliHandler,
} from "./helpers.js";

const scanner = new AliIdleResourcesScanner();

const disksBody = (disks: object[], total = disks.length) => ({ Disks: { Disk: disks }, TotalCount: total });
const eipsBody = (eips: object[], total = eips.length) => ({ EipAddresses: { EipAddress: eips }, TotalCount: total });
const instancesBody = (insts: object[], total = insts.length) => ({ Instances: { Instance: insts }, TotalCount: total });
const sgsBody = (sgs: object[], total = sgs.length) => ({ SecurityGroups: { SecurityGroup: sgs }, TotalCount: total });
const eniBody = (n: number) => ({
  NetworkInterfaceSets: { NetworkInterfaceSet: Array.from({ length: Math.min(n, 10) }, (_, i) => ({ NetworkInterfaceId: `eni-${i}` })) },
  TotalCount: n,
});

/** Empty responses for every category. */
const EMPTY: Record<string, AliHandler | object> = {
  DescribeDisks: disksBody([]),
  DescribeEipAddresses: eipsBody([]),
  DescribeInstances: instancesBody([]),
  DescribeSecurityGroups: sgsBody([]),
  DescribeNetworkInterfaces: eniBody(0),
};

/** ENI count per security group id. */
const eniBySg =
  (counts: Record<string, number>): AliHandler =>
  (q) =>
    eniBody(counts[q.SecurityGroupId as string] ?? 0);

beforeEach(() => {
  isolateAliEnv();
  mocks.aliCall.mockReset();
});
afterEach(() => restoreAliEnv());

describe("idle_resources — categories", () => {
  it("normal hit: one finding per idle category, AWS-aligned scores, URNs and filters", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeDisks: disksBody([{ DiskId: "d-idle", DiskName: "old-data", Size: 40, Category: "cloud_essd", Status: "Available" }]),
      DescribeEipAddresses: eipsBody([{ AllocationId: "eip-free", IpAddress: "47.1.2.3", Status: "Available" }]),
      DescribeInstances: instancesBody([
        { InstanceId: "i-keep", InstanceName: "web", InstanceType: "ecs.g7.large", Status: "Stopped", StoppedMode: "KeepCharging" },
        { InstanceId: "i-stop", InstanceType: "ecs.g7.large", Status: "Stopped", StoppedMode: "StopCharging" },
      ]),
      DescribeSecurityGroups: sgsBody([
        { SecurityGroupId: "sg-empty", SecurityGroupName: "legacy", VpcId: "vpc-1" },
        { SecurityGroupId: "sg-used", SecurityGroupName: "app", VpcId: "vpc-1" },
      ]),
      DescribeNetworkInterfaces: eniBySg({ "sg-used": 3 }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.module).toBe("idle_resources");
    expect(r.resourcesScanned).toBe(1 + 1 + 2 + 2);
    const byId = new Map(r.findings.map((f) => [f.resourceId, f]));
    expect([...byId.keys()].sort()).toEqual(["d-idle", "eip-free", "i-keep", "i-stop", "sg-empty"]);

    const disk = byId.get("d-idle")!;
    expect(disk.title).toBe("ECS disk d-idle is unattached");
    expect(disk.riskScore).toBe(3.0);
    expect(disk.severity).toBe("LOW");
    expect(disk.resourceType).toBe("ACS::ECS::Disk");
    expect(disk.resourceArn).toBe(`acs:ecs:cn-hangzhou:${UID}:disk/d-idle`);
    expect(disk.description).toContain("40GiB, cloud_essd");
    expect(disk.provider).toBe("alicloud");

    const eip = byId.get("eip-free")!;
    expect(eip.title).toBe("Elastic IP 47.1.2.3 is not associated");
    expect(eip.riskScore).toBe(2.0);
    expect(eip.resourceArn).toBe(`acs:vpc:cn-hangzhou:${UID}:eip/eip-free`);

    const keep = byId.get("i-keep")!;
    const stop = byId.get("i-stop")!;
    expect(keep.title).toBe("ECS instance i-keep is stopped but still billed (StoppedMode=KeepCharging)");
    expect(keep.riskScore).toBe(3.0);
    expect(stop.title).toBe("ECS instance i-stop is stopped");
    expect(stop.riskScore).toBe(2.0);
    expect(keep.riskScore).toBeGreaterThan(stop.riskScore);
    expect(keep.resourceArn).toBe(`acs:ecs:cn-hangzhou:${UID}:instance/i-keep`);

    const sg = byId.get("sg-empty")!;
    expect(sg.title).toBe("Security group sg-empty is not attached to any resource");
    expect(sg.riskScore).toBe(2.0);
    expect(sg.resourceType).toBe("ACS::ECS::SecurityGroup");
    expect(sg.resourceArn).toBe(`acs:ecs:cn-hangzhou:${UID}:securitygroup/sg-empty`);

    // Request filters / per-SG lookups
    expect(callsFor(mocks.aliCall, "DescribeDisks")[0][2]).toMatchObject({ RegionId: "cn-hangzhou", Status: "Available" });
    expect(callsFor(mocks.aliCall, "DescribeEipAddresses")[0][2]).toMatchObject({ RegionId: "cn-hangzhou", Status: "Available" });
    expect(callsFor(mocks.aliCall, "DescribeInstances")[0][2]).toMatchObject({ RegionId: "cn-hangzhou", Status: "Stopped" });
    expect(callsFor(mocks.aliCall, "DescribeEipAddresses")[0][0].service).toBe("vpc");
    expect(callsFor(mocks.aliCall, "DescribeNetworkInterfaces").map((c) => c[2].SecurityGroupId).sort()).toEqual(["sg-empty", "sg-used"]);
  });

  it("no hit: every list empty / every SG in use → 0 findings, no warnings", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeSecurityGroups: sgsBody([{ SecurityGroupId: "sg-a", SecurityGroupName: "a" }]),
      DescribeNetworkInterfaces: eniBySg({ "sg-a": 1 }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(1);
  });

  it("defensive filters: attached disk / bound EIP / running instance returned anyway are not flagged", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeDisks: disksBody([{ DiskId: "d-1", Status: "In_use" }]),
      DescribeEipAddresses: eipsBody([{ AllocationId: "eip-1", Status: "InUse", InstanceId: "i-1" }, { AllocationId: "eip-2", Status: "Available", InstanceId: "i-2" }]),
      DescribeInstances: instancesBody([{ InstanceId: "i-run", Status: "Running" }]),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings).toEqual([]);
  });

  it("skips service-managed and `default` security groups (no ENI lookup)", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeSecurityGroups: sgsBody([
        { SecurityGroupId: "sg-managed", SecurityGroupName: "ack", ServiceManaged: true },
        { SecurityGroupId: "sg-default", SecurityGroupName: "default" },
      ]),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings).toEqual([]);
    expect(callsFor(mocks.aliCall, "DescribeNetworkInterfaces")).toHaveLength(0);
  });

  it("isKeepCharging is case-insensitive", () => {
    expect(isKeepCharging("KeepCharging")).toBe(true);
    expect(isKeepCharging("keepcharging")).toBe(true);
    expect(isKeepCharging("StopCharging")).toBe(false);
    expect(isKeepCharging("Not-applicable")).toBe(false);
    expect(isKeepCharging(undefined)).toBe(false);
  });
});

describe("idle_resources — pagination and caps", () => {
  it("paginates disks (PageNumber 1..2 by TotalCount) and EIPs", async () => {
    const page1 = Array.from({ length: 100 }, (_, i) => ({ DiskId: `d-${i}`, Status: "Available" }));
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeDisks: (q) => (q.PageNumber === 1 ? disksBody(page1, 101) : disksBody([{ DiskId: "d-last", Status: "Available" }], 101)),
      DescribeEipAddresses: (q) =>
        q.PageNumber === 1
          ? eipsBody(Array.from({ length: 100 }, (_, i) => ({ AllocationId: `eip-${i}`, Status: "Available" })), 102)
          : eipsBody([{ AllocationId: "eip-a", Status: "Available" }, { AllocationId: "eip-b", Status: "Available" }], 102),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(callsFor(mocks.aliCall, "DescribeDisks").map((c) => c[2].PageNumber)).toEqual([1, 2]);
    expect(callsFor(mocks.aliCall, "DescribeEipAddresses").map((c) => c[2].PageNumber)).toEqual([1, 2]);
    expect(r.findings.filter((f) => f.resourceType === "ACS::ECS::Disk")).toHaveLength(101);
    expect(r.findings.filter((f) => f.resourceType === "ACS::VPC::EIP")).toHaveLength(102);
  });

  it("paginates security groups (PageSize 50) and stopped instances", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeSecurityGroups: (q) =>
        q.PageNumber === 1
          ? sgsBody(Array.from({ length: 50 }, (_, i) => ({ SecurityGroupId: `sg-${i}` })), 51)
          : sgsBody([{ SecurityGroupId: "sg-50" }], 51),
      DescribeNetworkInterfaces: eniBody(1),
      DescribeInstances: (q) =>
        q.PageNumber === 1
          ? instancesBody(Array.from({ length: 100 }, (_, i) => ({ InstanceId: `i-${i}`, Status: "Running" })), 101)
          : instancesBody([{ InstanceId: "i-stopped", Status: "Stopped", StoppedMode: "KeepCharging" }], 101),
    });
    const r = await scanner.scan(aliCtx());
    const sgCalls = callsFor(mocks.aliCall, "DescribeSecurityGroups");
    expect(sgCalls.map((c) => c[2].PageNumber)).toEqual([1, 2]);
    expect(sgCalls[0][2].PageSize).toBe(50);
    expect(callsFor(mocks.aliCall, "DescribeNetworkInterfaces")).toHaveLength(51);
    expect(callsFor(mocks.aliCall, "DescribeInstances").map((c) => c[2].PageNumber)).toEqual([1, 2]);
    expect(r.findings.map((f) => f.resourceId)).toEqual(["i-stopped"]);
  });

  it(`caps per-SG ENI lookups at IDLE_MAX_SG_CHECKS (${IDLE_MAX_SG_CHECKS}) with a warning`, async () => {
    const total = IDLE_MAX_SG_CHECKS + 5;
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeSecurityGroups: (q) => {
        const start = ((q.PageNumber as number) - 1) * 50;
        const n = Math.max(0, Math.min(50, total - start));
        return sgsBody(Array.from({ length: n }, (_, i) => ({ SecurityGroupId: `sg-${start + i}` })), total);
      },
      DescribeNetworkInterfaces: eniBody(2),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(callsFor(mocks.aliCall, "DescribeNetworkInterfaces")).toHaveLength(IDLE_MAX_SG_CHECKS);
    expect(r.warnings?.some((w) => w.includes(`only the first ${IDLE_MAX_SG_CHECKS}`))).toBe(true);
  });
});

describe("idle_resources — errors", () => {
  it("access_denied on EIP listing → warning, other categories still scanned", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeDisks: disksBody([{ DiskId: "d-1", Status: "Available" }]),
      DescribeEipAddresses: () => {
        throw deniedError("vpc:DescribeEipAddresses");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceId)).toEqual(["d-1"]);
    expect(r.warnings?.some((w) => w.startsWith("VPC DescribeEipAddresses: insufficient permissions"))).toBe(true);
  });

  it("access_denied on one ENI lookup → warning, group not flagged", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeSecurityGroups: sgsBody([{ SecurityGroupId: "sg-x" }, { SecurityGroupId: "sg-y" }]),
      DescribeNetworkInterfaces: (q) => {
        if (q.SecurityGroupId === "sg-x") throw deniedError("ecs:DescribeNetworkInterfaces");
        return eniBody(0);
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceId)).toEqual(["sg-y"]);
    expect(r.warnings?.some((w) => w.includes("security group sg-x") && w.includes("insufficient permissions"))).toBe(true);
  });

  it("auth_failed (404 InvalidAccessKeyId.NotFound) → status error with the canonical prefix", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeDisks: () => {
        throw authError("ecs:DescribeDisks");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error?.startsWith("Alibaba Cloud authentication failed")).toBe(true);
    expect(r.findings).toEqual([]);
    expect(callsFor(mocks.aliCall, "DescribeEipAddresses")).toHaveLength(0);
  });

  it("auth_failed inside the per-SG fan-out → status error", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeSecurityGroups: sgsBody([{ SecurityGroupId: "sg-x" }]),
      DescribeNetworkInterfaces: () => {
        throw authError("ecs:DescribeNetworkInterfaces");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error?.startsWith("Alibaba Cloud authentication failed")).toBe(true);
  });

  it("api_misuse (MissingParameter) → status error, not swallowed", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeInstances: () => {
        throw misuseError("ecs:DescribeInstances");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toContain("Stopped instance check failed");
    expect(r.error).toContain("MissingParameter");
  });

  it("redaction: AK-looking disk id / name and EIP address never reach the result", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeDisks: disksBody([{ DiskId: `d-${FAKE_AK}`, DiskName: `secret ${FAKE_SK}`, Status: "Available" }]),
      DescribeInstances: instancesBody([{ InstanceId: "i-1", InstanceName: FAKE_AK, Status: "Stopped", StoppedMode: FAKE_AK }]),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings).toHaveLength(2);
    const text = JSON.stringify(r);
    expect(text).not.toContain(FAKE_AK);
    expect(text).not.toContain(FAKE_SK);
    expect(text).toContain("[REDACTED]");
  });
});

describe("idle_resources — registration", () => {
  it("is registered on the alicloud provider", () => {
    expect(alibabaCloudProvider.scanners().some((s) => s.moduleName === "idle_resources")).toBe(true);
  });
});
