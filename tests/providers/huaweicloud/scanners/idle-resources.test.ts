/**
 * HuaweiIdleResourcesScanner (Huawei Cloud idle_resources) — SDK client
 * factory + SDK packages are mocked; no network, no credential file access.
 */
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll, afterEach } from "vitest";
import { inspect } from "util";

const { listVolumes, listPublicips, listServersDetails, listSecurityGroups, listPorts, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock } = vi.hoisted(() => ({
  listVolumes: vi.fn(),
  listPublicips: vi.fn(),
  listServersDetails: vi.fn(),
  listSecurityGroups: vi.fn(),
  listPorts: vi.fn(),
  hwClientMock: vi.fn(),
  loadHuaweiCredentialsMock: vi.fn(),
  resolveRegionScopeMock: vi.fn(),
}));

vi.mock("../../../../src/providers/huaweicloud/client.js", () => ({
  hwClient: hwClientMock,
  hwObsClient: vi.fn(),
  silenceSdkLogging: vi.fn(),
}));
// SDK packages must never be loaded in unit tests (heavy + configure log4js).
const boom = () => ({ newBuilder: vi.fn(() => { throw new Error("real SDK builder must not be used in tests"); }) });
vi.mock("@huaweicloud/huaweicloud-sdk-evs", () => ({ EvsClient: boom() }));
vi.mock("@huaweicloud/huaweicloud-sdk-eip/v2/EipClient.js", () => ({ EipClient: boom() }));
vi.mock("@huaweicloud/huaweicloud-sdk-ecs", () => ({ EcsClient: boom() }));
vi.mock("@huaweicloud/huaweicloud-sdk-vpc", () => ({ VpcClient: boom() }));
vi.mock("../../../../src/providers/huaweicloud/credentials.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../../src/providers/huaweicloud/credentials.js")>();
  return { ...actual, loadHuaweiCredentials: loadHuaweiCredentialsMock, resolveRegionScope: resolveRegionScopeMock };
});

import {
  HuaweiIdleResourcesScanner,
  stoppedDays,
  EVS_PAGE_SIZE,
  EIP_PAGE_SIZE,
  ECS_PAGE_SIZE,
  SG_PAGE_SIZE,
  PORT_PAGE_SIZE,
} from "../../../../src/providers/huaweicloud/scanners/idle-resources.js";
import { createHuaweiCredentials } from "../../../../src/providers/huaweicloud/credentials.js";
import { huaweiCloudProvider } from "../../../../src/providers/huaweicloud/index.js";
import type { ScanContext } from "../../../../src/types.js";

const FAKE_AK = "FAKEAK0123456789ABCD";
const FAKE_SK = "FAKESK0123456789abcdefghijklmnopqrstuvwx";
const DOMAIN = "0123456789abcdef0123456789abcdef";
const PROJECT = "p-north4";
const FAKE_AUTH_HEADER = `SDK-HMAC-SHA256 Access=${FAKE_AK}, SignedHeaders=host;x-sdk-date, Signature=deadbeef`;

const creds = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK, domainId: DOMAIN });

const ctx: ScanContext = {
  region: "cn-north-4",
  partition: "huaweicloud",
  accountId: DOMAIN,
  provider: "huaweicloud",
  projectId: PROJECT,
  domainId: DOMAIN,
  credentials: creds,
};

const DAY = 24 * 60 * 60 * 1000;
const daysAgo = (d: number) => new Date(Date.now() - d * DAY).toISOString();
const urn = (svc: string, type: string, id: string) => `hws:cn-north-4:${DOMAIN}:${svc}:${type}:${id}`;

const captured: string[] = [];
const spies: Array<ReturnType<typeof vi.spyOn>> = [];
beforeAll(() => {
  spies.push(vi.spyOn(process.stdout, "write").mockImplementation(((c: unknown) => { captured.push(String(c)); return true; }) as never));
  spies.push(vi.spyOn(process.stderr, "write").mockImplementation(((c: unknown) => { captured.push(String(c)); return true; }) as never));
  for (const m of ["log", "error", "warn", "info", "debug"] as const) {
    spies.push(vi.spyOn(console, m).mockImplementation((...args: unknown[]) => { captured.push(args.map((a) => (typeof a === "string" ? a : inspect(a))).join(" ")); }));
  }
});
afterAll(() => { for (const s of spies) s.mockRestore(); });
afterEach(() => {
  const all = captured.join("\n");
  expect(all, "no output may contain the Authorization header or key material").not.toContain("Authorization");
  expect(all).not.toContain(FAKE_AK);
  expect(all).not.toContain(FAKE_SK);
  captured.length = 0;
});

function installClients() {
  hwClientMock.mockImplementation(async (_cls: unknown, svc: string) => {
    if (svc === "evs") return { listVolumes };
    if (svc === "eip") return { listPublicips };
    if (svc === "ecs") return { listServersDetails };
    if (svc === "vpc") return { listSecurityGroups, listPorts };
    throw new Error(`unexpected service ${svc}`);
  });
}

describe("HuaweiIdleResourcesScanner (idle_resources)", () => {
  const scanner = new HuaweiIdleResourcesScanner();

  beforeEach(() => {
    for (const m of [listVolumes, listPublicips, listServersDetails, listSecurityGroups, listPorts, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock]) m.mockReset();
    installClients();
    // defaults: nothing deployed
    listVolumes.mockResolvedValue({ volumes: [], count: 0 });
    listPublicips.mockResolvedValue({ publicips: [] });
    listServersDetails.mockResolvedValue({ servers: [], count: 0 });
    listSecurityGroups.mockResolvedValue({ security_groups: [] });
    listPorts.mockResolvedValue({ ports: [] });
  });

  it("is registered on the huaweicloud provider under the AWS module name", () => {
    expect(scanner.moduleName).toBe("idle_resources");
    expect(huaweiCloudProvider.scanners().map((s) => s.moduleName)).toContain("idle_resources");
  });

  it("flags unattached EVS volumes (3.0), unbound EIPs (2.0), long-stopped ECS (3.0) and unused SGs (2.0) — attached / bound / active / used (ECS or VPC port) are ignored", async () => {
    listVolumes.mockResolvedValueOnce({
      count: 3,
      volumes: [
        { id: "vol-free", name: "scratch", status: "available", size: 100, volume_type: "SAS", attachments: [] },
        { id: "vol-used", status: "in-use", size: 40, volume_type: "SSD", attachments: [{ server_id: "srv-run" }] },
        { id: "vol-err", status: "error", size: 10 },
      ],
    });
    listPublicips.mockResolvedValueOnce({
      publicips: [
        { id: "eip-free", status: "DOWN", public_ip_address: "1.2.3.4", alias: "spare" },
        { id: "eip-bound", status: "ACTIVE", public_ip_address: "5.6.7.8", port_id: "port-1" },
      ],
    });
    listServersDetails.mockResolvedValueOnce({
      count: 4,
      servers: [
        { id: "srv-run", name: "web", status: "ACTIVE", updated: daysAgo(100), security_groups: [{ id: "sg-used", name: "web-sg" }] },
        { id: "srv-old", name: "batch", status: "SHUTOFF", updated: daysAgo(45), flavor: { id: "s6.large.2" }, security_groups: [{ id: "sg-used" }] },
        { id: "srv-recent", status: "SHUTOFF", updated: daysAgo(5), security_groups: [] },
        { id: "srv-nodate", status: "SHUTOFF", security_groups: [{ id: "sg-default", name: "default" }] },
      ],
    });
    listSecurityGroups.mockResolvedValueOnce({
      security_groups: [
        { id: "sg-used", name: "web-sg", vpc_id: "vpc-1" },
        { id: "sg-idle", name: "old-sg", vpc_id: "vpc-1" },
        { id: "sg-default", name: "default", vpc_id: "vpc-1" },
        { id: "sg-default-2", name: "default", vpc_id: "vpc-2" }, // default groups never reported
        { id: "sg-elb", name: "elb-sg", vpc_id: "vpc-1" }, // attached only through a VPC port (ELB), not through ECS
        { id: "sg-rds", name: "rds-sg", vpc_id: "vpc-1" }, // attached only through a VPC port (RDS)
      ],
    });
    listPorts.mockResolvedValueOnce({
      ports: [
        { id: "port-ecs", device_owner: "compute:cn-north-4a", security_groups: ["sg-used"] },
        { id: "port-elb", device_owner: "neutron:LOADBALANCERV3", security_groups: ["sg-elb"] },
        { id: "port-rds", device_owner: "network:rds", security_groups: ["sg-rds", "sg-elb"] },
        { id: "port-none", device_owner: "network:dhcp", security_groups: [] },
      ],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.error).toBeUndefined();
    expect(result.resourcesScanned).toBe(3 + 2 + 4 + 6);
    expect(result.findingsCount).toBe(4);
    expect(result.warnings).toEqual(['Could not determine stop date for ECS server srv-nodate (no parseable "updated" timestamp).']);

    const byArn = new Map(result.findings.map((f) => [f.resourceArn, f]));
    expect(byArn.get(urn("evs", "volume", "vol-free"))).toMatchObject({
      riskScore: 3.0, severity: "LOW", resourceType: "HuaweiCloud::EVS::Volume", resourceId: "vol-free", region: "cn-north-4", provider: "huaweicloud",
    });
    expect(byArn.get(urn("evs", "volume", "vol-free"))!.description).toContain("(100GB, SAS)");
    expect(byArn.get(urn("eip", "publicip", "eip-free"))).toMatchObject({ riskScore: 2.0, severity: "LOW", resourceType: "HuaweiCloud::EIP::PublicIp", resourceId: "eip-free" });
    expect(byArn.get(urn("eip", "publicip", "eip-free"))!.title).toBe("Elastic IP 1.2.3.4 is not bound");
    expect(byArn.get(urn("ecs", "server", "srv-old"))).toMatchObject({ riskScore: 3.0, resourceType: "HuaweiCloud::ECS::CloudServer", resourceId: "srv-old" });
    expect(byArn.get(urn("ecs", "server", "srv-old"))!.title).toBe("ECS server srv-old has been stopped for 45 days");
    expect(byArn.get(urn("vpc", "security-group", "sg-idle"))).toMatchObject({ riskScore: 2.0, resourceType: "HuaweiCloud::VPC::SecurityGroup", resourceId: "sg-idle" });
    expect(byArn.get(urn("vpc", "security-group", "sg-idle"))!.title).toBe("Security group sg-idle is not attached to any ECS server or VPC port");
    // Not flagged: attached volume, error volume, bound EIP, active server, recently stopped server, used SG, port-attached SGs, default SGs.
    expect(byArn.has(urn("vpc", "security-group", "sg-elb"))).toBe(false);
    expect(byArn.has(urn("vpc", "security-group", "sg-rds"))).toBe(false);
    expect(byArn.has(urn("evs", "volume", "vol-used"))).toBe(false);
    expect(byArn.has(urn("evs", "volume", "vol-err"))).toBe(false);
    expect(byArn.has(urn("eip", "publicip", "eip-bound"))).toBe(false);
    expect(byArn.has(urn("ecs", "server", "srv-run"))).toBe(false);
    expect(byArn.has(urn("ecs", "server", "srv-recent"))).toBe(false);
    expect(byArn.has(urn("vpc", "security-group", "sg-used"))).toBe(false);
    expect(byArn.has(urn("vpc", "security-group", "sg-default"))).toBe(false);
    expect(byArn.has(urn("vpc", "security-group", "sg-default-2"))).toBe(false);

    // Ports are listed before security groups (a single VPC client serves both).
    expect(listPorts).toHaveBeenCalledTimes(1);
    expect(listPorts.mock.calls[0][0]).toEqual({ limit: PORT_PAGE_SIZE });
    expect(listPorts.mock.invocationCallOrder[0]).toBeLessThan(listSecurityGroups.mock.invocationCallOrder[0]);
    // Regional (basic) clients built with the region scope; credential chain not consulted.
    expect(hwClientMock.mock.calls.map((c) => c[1])).toEqual(["evs", "eip", "ecs", "vpc"]);
    for (const c of hwClientMock.mock.calls) {
      expect(c[2]).toBe(creds);
      expect(c[3]).toEqual({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });
    }
    expect(loadHuaweiCredentialsMock).not.toHaveBeenCalled();
  });

  it("paginates: EVS offset/limit + count, EIP marker (= last id), ECS offset pages + count, VPC ports / SGs marker (= last id) — 2 pages each", async () => {
    const evs1 = Array.from({ length: EVS_PAGE_SIZE }, (_, i) => ({ id: `vol-${i}`, status: "in-use" }));
    const evs2 = [{ id: "vol-last", status: "available", size: 1, volume_type: "SAS" }];
    listVolumes
      .mockResolvedValueOnce({ volumes: evs1, count: EVS_PAGE_SIZE + 1 })
      .mockResolvedValueOnce({ volumes: evs2, count: EVS_PAGE_SIZE + 1 });

    const eip1 = Array.from({ length: EIP_PAGE_SIZE }, (_, i) => ({ id: `eip-${i}`, status: "ACTIVE" }));
    const eip2 = [{ id: "eip-last", status: "DOWN", public_ip_address: "9.9.9.9" }];
    listPublicips.mockResolvedValueOnce({ publicips: eip1 }).mockResolvedValueOnce({ publicips: eip2 });

    const ecs1 = Array.from({ length: ECS_PAGE_SIZE }, (_, i) => ({ id: `srv-${i}`, status: "ACTIVE", security_groups: [{ id: `sg-${i}` }] }));
    const ecs2 = [{ id: "srv-last", status: "SHUTOFF", updated: daysAgo(31), security_groups: [{ id: "sg-last" }] }];
    listServersDetails
      .mockResolvedValueOnce({ servers: ecs1, count: ECS_PAGE_SIZE + 1 })
      .mockResolvedValueOnce({ servers: ecs2, count: ECS_PAGE_SIZE + 1 });

    const sg1 = Array.from({ length: SG_PAGE_SIZE }, (_, i) => ({ id: `sg-${i}`, name: `sg-${i}` }));
    const sg2 = [{ id: "sg-last", name: "sg-last" }, { id: "sg-orphan", name: "orphan" }, { id: "sg-port-only", name: "port-only" }];
    listSecurityGroups.mockResolvedValueOnce({ security_groups: sg1 }).mockResolvedValueOnce({ security_groups: sg2 });

    const ports1 = Array.from({ length: PORT_PAGE_SIZE }, (_, i) => ({ id: `port-${i}`, security_groups: [] }));
    const ports2 = [{ id: "port-last", device_owner: "neutron:LOADBALANCERV3", security_groups: ["sg-port-only"] }];
    listPorts.mockResolvedValueOnce({ ports: ports1 }).mockResolvedValueOnce({ ports: ports2 });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(listVolumes).toHaveBeenCalledTimes(2);
    expect(listVolumes.mock.calls[0][0]).toEqual({ limit: EVS_PAGE_SIZE, offset: 0 });
    expect(listVolumes.mock.calls[1][0]).toEqual({ limit: EVS_PAGE_SIZE, offset: EVS_PAGE_SIZE });
    expect(listPublicips).toHaveBeenCalledTimes(2);
    expect(listPublicips.mock.calls[0][0]).toEqual({ limit: EIP_PAGE_SIZE });
    expect(listPublicips.mock.calls[1][0]).toEqual({ limit: EIP_PAGE_SIZE, marker: `eip-${EIP_PAGE_SIZE - 1}` });
    expect(listServersDetails).toHaveBeenCalledTimes(2);
    expect(listServersDetails.mock.calls[0][0]).toEqual({ offset: 1, limit: ECS_PAGE_SIZE });
    expect(listServersDetails.mock.calls[1][0]).toEqual({ offset: 2, limit: ECS_PAGE_SIZE });
    expect(listSecurityGroups).toHaveBeenCalledTimes(2);
    expect(listSecurityGroups.mock.calls[0][0]).toEqual({ limit: SG_PAGE_SIZE });
    expect(listSecurityGroups.mock.calls[1][0]).toEqual({ limit: SG_PAGE_SIZE, marker: `sg-${SG_PAGE_SIZE - 1}` });
    expect(listPorts).toHaveBeenCalledTimes(2);
    expect(listPorts.mock.calls[0][0]).toEqual({ limit: PORT_PAGE_SIZE });
    expect(listPorts.mock.calls[1][0]).toEqual({ limit: PORT_PAGE_SIZE, marker: `port-${PORT_PAGE_SIZE - 1}` });

    expect(result.resourcesScanned).toBe(EVS_PAGE_SIZE + 1 + EIP_PAGE_SIZE + 1 + ECS_PAGE_SIZE + 1 + SG_PAGE_SIZE + 3);
    expect(result.findings.map((f) => f.resourceId).sort()).toEqual(["eip-last", "sg-orphan", "srv-last", "vol-last"]);
    expect(result.warnings).toBeUndefined();
  });

  it("degrades per service on 403: EVS denied, others still scanned; ECS denied skips the SG usage check", async () => {
    listVolumes.mockRejectedValueOnce({ httpStatusCode: 403, errorCode: "EVS.1002", errorMsg: "Forbidden", requestId: "r-evs" });
    listPublicips.mockResolvedValueOnce({ publicips: [{ id: "eip-1", status: "DOWN", public_ip_address: "1.1.1.1" }] });

    const partial = await scanner.scan(ctx);
    expect(partial.status).toBe("success");
    expect(partial.findingsCount).toBe(1);
    expect(partial.findings[0].resourceId).toBe("eip-1");
    expect(partial.warnings).toEqual(["EVS: insufficient permissions (HTTP 403 | EVS.1002 | Forbidden | requestId=r-evs); skipped"]);
    expect(listSecurityGroups).toHaveBeenCalledTimes(1);

    listServersDetails.mockRejectedValueOnce({
      status: 401,
      data: { error_code: "APIGW.0301", error_msg: "Incorrect IAM authentication information" },
      message: "Request failed with status code 401",
      config: { headers: { Authorization: FAKE_AUTH_HEADER } },
    });
    listSecurityGroups.mockClear();
    listSecurityGroups.mockResolvedValueOnce({ security_groups: [{ id: "sg-x", name: "would-be-false-positive" }] });

    const noEcs = await scanner.scan(ctx);
    expect(noEcs.status).toBe("success");
    expect(noEcs.findingsCount).toBe(0);
    expect(listSecurityGroups).not.toHaveBeenCalled();
    expect(noEcs.warnings).toHaveLength(2);
    expect(noEcs.warnings![0]).toContain("ECS: insufficient permissions");
    expect(noEcs.warnings![1]).toContain("security group usage check skipped");
    const serialized = JSON.stringify(noEcs);
    expect(serialized).not.toContain("Authorization");
    expect(serialized).not.toContain(FAKE_AK);
  });

  it("skips the SG usage check (no SG findings, warning) when listPorts is denied, not available, truncated or repeats a marker", async () => {
    const idleOnly = { security_groups: [{ id: "sg-x", name: "would-be-false-positive" }] };

    // 403 on ports → warning, SG listing not even attempted, EVS/EIP/ECS results intact
    listVolumes.mockResolvedValueOnce({ volumes: [{ id: "vol-free", status: "available", size: 1, volume_type: "SAS" }], count: 1 });
    listPorts.mockRejectedValueOnce({ httpStatusCode: 403, errorCode: "VPC.0003", errorMsg: "Forbidden", requestId: "r-ports" });
    listSecurityGroups.mockResolvedValueOnce(idleOnly);
    const denied = await scanner.scan(ctx);
    expect(denied.status).toBe("success");
    expect(denied.findings.map((f) => f.resourceId)).toEqual(["vol-free"]);
    expect(listSecurityGroups).not.toHaveBeenCalled();
    expect(denied.warnings).toEqual([
      "VPC ports: insufficient permissions (HTTP 403 | VPC.0003 | Forbidden | requestId=r-ports); skipped",
      "VPC: security group usage check skipped because the port listing was unavailable.",
    ]);

    // 404 / not enabled on ports → same skip
    listPorts.mockRejectedValueOnce({ httpStatusCode: 404, errorCode: "APIGW.0101", errorMsg: "API not found" });
    listSecurityGroups.mockResolvedValueOnce(idleOnly);
    const notEnabled = await scanner.scan(ctx);
    expect(notEnabled.status).toBe("success");
    expect(notEnabled.findingsCount).toBe(0);
    expect(notEnabled.warnings![0]).toContain("VPC ports: service not enabled or not available");
    expect(notEnabled.warnings![1]).toContain("security group usage check skipped");

    // repeated marker: the API keeps returning the same full page → stop, skip the check
    const samePage = Array.from({ length: PORT_PAGE_SIZE }, (_, i) => ({ id: `port-${i}`, security_groups: [] }));
    listPorts.mockReset();
    listPorts.mockResolvedValue({ ports: samePage });
    listSecurityGroups.mockClear();
    listSecurityGroups.mockResolvedValueOnce(idleOnly);
    const repeated = await scanner.scan(ctx);
    expect(repeated.status).toBe("success");
    expect(repeated.findingsCount).toBe(0);
    expect(listPorts).toHaveBeenCalledTimes(2);
    expect(listSecurityGroups).not.toHaveBeenCalled();
    expect(repeated.warnings).toEqual([
      "VPC: pagination of ports stopped early because the API repeated a page marker; results may be incomplete.",
      "VPC: security group usage check skipped because the port listing was incomplete.",
    ]);

    // unexpected failure on ports → status error, as for any other unexpected VPC failure
    listPorts.mockReset();
    listPorts.mockRejectedValueOnce({ httpStatusCode: 500, errorCode: "VPC.9999", errorMsg: "internal error" });
    const failed = await scanner.scan(ctx);
    expect(failed.status).toBe("error");
    expect(failed.error).toBe("Huawei Cloud idle resources scan failed: HTTP 500 | VPC.9999 | internal error");
  });

  it("treats 404 / not-enabled as a warning and returns status error on unexpected failures", async () => {
    listPublicips.mockRejectedValueOnce({ httpStatusCode: 404, errorCode: "APIGW.0101", errorMsg: "API not found" });
    const notEnabled = await scanner.scan(ctx);
    expect(notEnabled.status).toBe("success");
    expect(notEnabled.warnings).toHaveLength(1);
    expect(notEnabled.warnings![0]).toContain("EIP: service not enabled or not available");

    listSecurityGroups.mockRejectedValueOnce({ httpStatusCode: 500, errorCode: "VPC.9999", errorMsg: "internal error" });
    const failed = await scanner.scan(ctx);
    expect(failed.status).toBe("error");
    expect(failed.error).toBe("Huawei Cloud idle resources scan failed: HTTP 500 | VPC.9999 | internal error");
    expect(failed.findingsCount).toBe(0);
    expect(JSON.stringify(failed)).not.toContain(FAKE_AK);
  });

  it("resolves projectId via IAM when the context lacks it, and errors without credentials", async () => {
    const noProject = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK, domainId: DOMAIN });
    resolveRegionScopeMock.mockResolvedValueOnce({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });
    const ok = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: DOMAIN, provider: "huaweicloud", credentials: noProject });
    expect(ok.status).toBe("success");
    expect(resolveRegionScopeMock).toHaveBeenCalledWith(noProject, "cn-north-4");
    expect(hwClientMock.mock.calls[0][3]).toEqual({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });

    loadHuaweiCredentialsMock.mockImplementationOnce(() => { throw new Error("Huawei Cloud credentials not found."); });
    const noCreds = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: DOMAIN, provider: "huaweicloud" });
    expect(noCreds.status).toBe("error");
    expect(noCreds.error).toContain("Huawei Cloud credentials not found");
  });

  it("stoppedDays uses the server's updated timestamp and tolerates missing / garbage values", () => {
    const now = Date.parse("2026-09-13T00:00:00Z");
    expect(stoppedDays({ updated: "2026-08-01T00:00:00Z" }, now)).toBe(43);
    expect(stoppedDays({ updated: "2026-09-12 12:00:00" }, now)).toBe(1);
    expect(stoppedDays({}, now)).toBeUndefined();
    expect(stoppedDays({ updated: "yesterday" }, now)).toBeUndefined();
  });
});
