/**
 * HuaweiHssPatchComplianceScanner (Huawei Cloud patch_compliance_findings → HSS) —
 * SDK client factory + SDK package are mocked; no network, no credential file access.
 * Covers: not enabled (0 hosts) / per-host findings / 403 / 404 / 500, host + vulnerability
 * pagination, host cap, N+1 bounded concurrency, aggregated per-host failures, no-leak assertion.
 */
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll, afterEach } from "vitest";
import { inspect } from "util";

const { listHostStatus, listHostVuls, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock } = vi.hoisted(() => ({
  listHostStatus: vi.fn(),
  listHostVuls: vi.fn(),
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
const boom = () => { throw new Error("real SDK builder must not be used in tests"); };
vi.mock("@huaweicloud/huaweicloud-sdk-hss", () => ({ HssClient: { newBuilder: vi.fn(boom) } }));
vi.mock("../../../../src/providers/huaweicloud/credentials.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../../src/providers/huaweicloud/credentials.js")>();
  return { ...actual, loadHuaweiCredentials: loadHuaweiCredentialsMock, resolveRegionScope: resolveRegionScopeMock };
});

import {
  HuaweiHssPatchComplianceScanner,
  HSS_PATCH_NOT_ENABLED_WARNING,
  HSS_HOST_PAGE_SIZE,
  HSS_PATCH_MAX_HOSTS,
  HSS_PATCH_CONCURRENCY,
  HSS_HOST_VUL_PAGE_SIZE,
  hssOsVulType,
  summarizeHostVuls,
  patchRiskScore,
} from "../../../../src/providers/huaweicloud/scanners/hss-patch-compliance.js";
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

const urn = (svc: string, type: string, id: string) => `hws:cn-north-4:${DOMAIN}:${svc}:${type}:${id}`;

const ERR_403 = { httpStatusCode: 403, errorCode: "IAM.0002", errorMsg: "You have no permission to perform this action.", requestId: "req-403" };
const ERR_404 = { httpStatusCode: 404, errorCode: "APIGW.0101", errorMsg: "The API does not exist or has not been published in the environment", requestId: "req-404" };
const ERR_500 = { httpStatusCode: 500, errorCode: "HSS.9999", errorMsg: "internal error", requestId: "req-500" };
const ERR_401_RAW = {
  status: 401,
  data: { error_code: "APIGW.0301", error_msg: "Incorrect IAM authentication information: verify aksk signature fail" },
  message: "Request failed with status code 401",
  config: { url: "https://hss.cn-north-4.myhuaweicloud.com/v5/p/vulnerability/host/vulnerabilities", headers: { Authorization: FAKE_AUTH_HEADER } },
};

const host = (over: Record<string, unknown>) => ({ host_id: "h", host_name: "srv", os_type: "Linux", agent_status: "online", protect_status: "opened", vulnerability: 1, ...over });
const hostVul = (over: Record<string, unknown>) => ({ vul_id: "V", vul_name: "v", type: "linux_vul", severity_level: "Medium", status: "vul_status_unfix", ...over });

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
    if (svc === "hss") return { listHostStatus, listHostVuls };
    throw new Error(`unexpected service ${svc}`);
  });
}

describe("HuaweiHssPatchComplianceScanner (patch_compliance_findings)", () => {
  const scanner = new HuaweiHssPatchComplianceScanner();

  beforeEach(() => {
    for (const m of [listHostStatus, listHostVuls, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock]) m.mockReset();
    installClients();
    listHostStatus.mockResolvedValue({ total_num: 0, data_list: [] });
    listHostVuls.mockResolvedValue({ total_num: 0, data_list: [] });
  });

  it("is registered on the huaweicloud provider under the AWS module name", () => {
    expect(scanner.moduleName).toBe("patch_compliance_findings");
    expect(huaweiCloudProvider.scanners().map((s) => s.moduleName)).toContain("patch_compliance_findings");
  });

  it("no protected hosts → single 'cannot be assessed' finding (3.0 LOW, distinct from inspector_findings) + 'is not enabled' warning; no per-host calls", async () => {
    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(0);
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0]).toMatchObject({
      riskScore: 3.0,
      severity: "LOW",
      priority: "P3",
      resourceType: "HuaweiCloud::HSS::Host",
      resourceId: "hss-patch-compliance",
      resourceArn: urn("hss", "patch-compliance", "none"),
      region: "cn-north-4",
      accountId: DOMAIN,
      module: "patch_compliance_findings",
      provider: "huaweicloud",
    });
    expect(result.findings[0].title).toBe("OS patch compliance cannot be assessed: no hosts are protected by HSS");
    expect(result.warnings).toEqual([HSS_PATCH_NOT_ENABLED_WARNING]);
    expect(HSS_PATCH_NOT_ENABLED_WARNING).toContain("is not enabled"); // HTML report N/A pattern
    expect(listHostStatus).toHaveBeenCalledTimes(1);
    expect(listHostStatus.mock.calls[0][0]).toEqual({ region: "cn-north-4", protect_status: "opened", limit: HSS_HOST_PAGE_SIZE, offset: 0 });
    expect(listHostVuls).not.toHaveBeenCalled();
    expect(hwClientMock.mock.calls[0].slice(1)).toEqual(["hss", creds, { region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN }]);
    expect(loadHuaweiCredentialsMock).not.toHaveBeenCalled();
  });

  it("per-host findings: Critical/High → 7.5 HIGH, Medium/Low only → 5.5 MEDIUM; OS type picks linux_vul / windows_vul; vulnerability=0 hosts skipped; hosts without ID warned", async () => {
    listHostStatus.mockResolvedValueOnce({
      total_num: 5,
      data_list: [
        host({ host_id: "h-linux", host_name: "web-01", os_type: "Linux", os_name: "CentOS", os_version: "7.9", vulnerability: 5, private_ip: "10.0.0.5", public_ip: "1.2.3.4" }),
        host({ host_id: "h-win", host_name: "ad-01", os_type: "Windows", vulnerability: 2 }),
        host({ host_id: "h-clean", host_name: "clean", vulnerability: 0 }),
        host({ host_id: "h-nocount", host_name: "nocount", vulnerability: undefined }),
        host({ host_id: undefined, host_name: "ghost" }),
      ],
    });
    listHostVuls.mockImplementation(async (req: { host_id: string }) => {
      switch (req.host_id) {
        case "h-linux":
          return { total_num: 2, data_list: [hostVul({ vul_id: "CESA-1", vul_name: "kernel RCE", severity_level: "Critical" }), hostVul({ vul_id: "CESA-2", vul_name: "curl leak", severity_level: "Medium" })] };
        case "h-win":
          return { total_num: 2, data_list: [hostVul({ vul_id: "KB-1", vul_name: "KB1", type: "windows_vul", severity_level: "Low" }), hostVul({ vul_id: "KB-2", vul_name: "KB2", type: "windows_vul", severity_level: "medium" })] };
        case "h-nocount":
          return { total_num: 0, data_list: [] };
        default:
          throw new Error(`unexpected host ${req.host_id}`);
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.error).toBeUndefined();
    expect(result.resourcesScanned).toBe(5);
    expect(listHostVuls).toHaveBeenCalledTimes(3);
    const byHost = new Map(listHostVuls.mock.calls.map((c) => [c[0].host_id, c[0]]));
    expect(byHost.get("h-linux")).toEqual({ host_id: "h-linux", type: "linux_vul", handle_status: "unhandled", limit: HSS_HOST_VUL_PAGE_SIZE, offset: 0 });
    expect(byHost.get("h-win")).toEqual({ host_id: "h-win", type: "windows_vul", handle_status: "unhandled", limit: HSS_HOST_VUL_PAGE_SIZE, offset: 0 });
    expect(byHost.has("h-clean")).toBe(false);

    expect(result.findingsCount).toBe(2);
    const linux = result.findings.find((f) => f.resourceId === "h-linux")!;
    expect(linux).toMatchObject({
      riskScore: 7.5,
      severity: "HIGH",
      priority: "P1",
      resourceType: "HuaweiCloud::ECS::CloudServer",
      resourceArn: urn("ecs", "server", "h-linux"),
      region: "cn-north-4",
      accountId: DOMAIN,
      module: "patch_compliance_findings",
      provider: "huaweicloud",
    });
    expect(linux.title).toBe("Host h-linux (web-01) has 2 unpatched OS vulnerabilities (1 critical, 1 medium)");
    expect(linux.description).toContain("OS: Linux CentOS 7.9");
    expect(linux.description).toContain("Public IP: 1.2.3.4");
    expect(linux.description).toContain("Examples: kernel RCE, curl leak");
    const win = result.findings.find((f) => f.resourceId === "h-win")!;
    expect(win).toMatchObject({ riskScore: 5.5, severity: "MEDIUM", resourceArn: urn("ecs", "server", "h-win") });
    expect(win.title).toBe("Host h-win (ad-01) has 2 unpatched OS vulnerabilities (1 medium, 1 low)");
    expect(result.warnings).toEqual(["HSS: 1 protected host(s) had no host ID and were not evaluated."]);
  });

  it("paginates hosts (offset/limit + total_num) and per-host vulnerabilities; fully patched hosts produce no finding", async () => {
    const page1 = Array.from({ length: HSS_HOST_PAGE_SIZE }, (_, i) => host({ host_id: `h-${i}`, vulnerability: 0 }));
    const page2 = [host({ host_id: "h-last", vulnerability: 203 })];
    listHostStatus
      .mockResolvedValueOnce({ total_num: HSS_HOST_PAGE_SIZE + 1, data_list: page1 })
      .mockResolvedValueOnce({ total_num: HSS_HOST_PAGE_SIZE + 1, data_list: page2 });
    const vulPage1 = Array.from({ length: HSS_HOST_VUL_PAGE_SIZE }, (_, i) => hostVul({ vul_id: `V-${i}`, severity_level: "Low" }));
    const vulPage2 = [hostVul({ vul_id: "V-a", severity_level: "High" }), hostVul({ vul_id: "V-b" }), hostVul({ vul_id: "V-c" })];
    listHostVuls
      .mockResolvedValueOnce({ total_num: HSS_HOST_VUL_PAGE_SIZE + 3, data_list: vulPage1 })
      .mockResolvedValueOnce({ total_num: HSS_HOST_VUL_PAGE_SIZE + 3, data_list: vulPage2 });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(listHostStatus).toHaveBeenCalledTimes(2);
    expect(listHostStatus.mock.calls.map((c) => c[0].offset)).toEqual([0, HSS_HOST_PAGE_SIZE]);
    expect(result.resourcesScanned).toBe(HSS_HOST_PAGE_SIZE + 1);
    expect(listHostVuls).toHaveBeenCalledTimes(2);
    expect(listHostVuls.mock.calls.map((c) => c[0])).toEqual([
      { host_id: "h-last", type: "linux_vul", handle_status: "unhandled", limit: HSS_HOST_VUL_PAGE_SIZE, offset: 0 },
      { host_id: "h-last", type: "linux_vul", handle_status: "unhandled", limit: HSS_HOST_VUL_PAGE_SIZE, offset: HSS_HOST_VUL_PAGE_SIZE },
    ]);
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].title).toBe(`Host h-last (srv) has ${HSS_HOST_VUL_PAGE_SIZE + 3} unpatched OS vulnerabilities (1 high, 2 medium, ${HSS_HOST_VUL_PAGE_SIZE} low)`);
    expect(result.findings[0].riskScore).toBe(7.5);
    expect(result.warnings).toBeUndefined();
  });

  it("caps the host listing (truncation warning) and bounds per-host concurrency", async () => {
    const full = Array.from({ length: HSS_HOST_PAGE_SIZE }, (_, i) => host({ host_id: `h-${i}` }));
    listHostStatus.mockResolvedValue({ total_num: 5000, data_list: full });
    let inFlight = 0;
    let maxInFlight = 0;
    listHostVuls.mockImplementation(async () => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 1));
      inFlight--;
      return { total_num: 0, data_list: [] };
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(listHostStatus).toHaveBeenCalledTimes(Math.ceil(HSS_PATCH_MAX_HOSTS / HSS_HOST_PAGE_SIZE));
    expect(result.resourcesScanned).toBe(HSS_PATCH_MAX_HOSTS);
    expect(listHostVuls).toHaveBeenCalledTimes(HSS_PATCH_MAX_HOSTS);
    expect(maxInFlight).toBeLessThanOrEqual(HSS_PATCH_CONCURRENCY);
    expect(maxInFlight).toBeGreaterThan(1);
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toEqual([`HSS: more than ${HSS_PATCH_MAX_HOSTS} protected hosts; only the first ${HSS_PATCH_MAX_HOSTS} were checked.`]);
  });

  it("aggregates per-host failures (403 / raw 401 → denied, 404 → unavailable, 500 → failed) into one warning each and keeps scanning", async () => {
    listHostStatus.mockResolvedValueOnce({
      total_num: 5,
      data_list: [host({ host_id: "h-403" }), host({ host_id: "h-401" }), host({ host_id: "h-404" }), host({ host_id: "h-500" }), host({ host_id: "h-ok" })],
    });
    listHostVuls.mockImplementation(async (req: { host_id: string }) => {
      switch (req.host_id) {
        case "h-403": throw ERR_403;
        case "h-401": throw ERR_401_RAW;
        case "h-404": throw ERR_404;
        case "h-500": throw ERR_500;
        default: return { total_num: 1, data_list: [hostVul({ vul_id: "C-1", vul_name: "crit", severity_level: "Critical" })] };
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(5);
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].resourceId).toBe("h-ok");
    expect(result.warnings).toEqual([
      "HSS: insufficient permissions to list host vulnerabilities for 2 host(s) (HTTP 403 | IAM.0002 | You have no permission to perform this action. | requestId=req-403); those hosts were not evaluated.",
      "HSS: host vulnerability data not available for 1 host(s) (HTTP 404 | APIGW.0101 | The API does not exist or has not been published in the environment | requestId=req-404); those hosts were not evaluated.",
      "HSS: host vulnerability lookup failed for 1 host(s) (HTTP 500 | HSS.9999 | internal error | requestId=req-500); those hosts were not evaluated.",
    ]);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("Authorization");
    expect(serialized).not.toContain(FAKE_AK);
  });

  it("first per-host failure being the raw 401 → the aggregated warning is redacted", async () => {
    listHostStatus.mockResolvedValueOnce({ total_num: 1, data_list: [host({ host_id: "h-401" })] });
    listHostVuls.mockRejectedValueOnce(ERR_401_RAW);
    const result = await scanner.scan(ctx);
    expect(result.status).toBe("success");
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings![0]).toContain("insufficient permissions to list host vulnerabilities for 1 host(s)");
    expect(result.warnings![0]).toContain("APIGW.0301");
    expect(JSON.stringify(result)).not.toContain("Authorization");
    expect(JSON.stringify(result)).not.toContain(FAKE_AK);
  });

  it("403 on listHostStatus → permissions warning, success; 404 → 'not enabled' finding; 500 → status error", async () => {
    listHostStatus.mockRejectedValueOnce(ERR_403);
    const denied = await scanner.scan(ctx);
    expect(denied.status).toBe("success");
    expect(denied.findingsCount).toBe(0);
    expect(denied.warnings).toEqual([
      "HSS: insufficient permissions to list protected hosts (HTTP 403 | IAM.0002 | You have no permission to perform this action. | requestId=req-403). Grant HSS ReadOnlyAccess to assess patch compliance.",
    ]);
    expect(listHostVuls).not.toHaveBeenCalled();

    listHostStatus.mockRejectedValueOnce(ERR_404);
    const notEnabled = await scanner.scan(ctx);
    expect(notEnabled.status).toBe("success");
    expect(notEnabled.findingsCount).toBe(1);
    expect(notEnabled.findings[0].resourceId).toBe("hss-patch-compliance");
    expect(notEnabled.warnings![0]).toBe(`${HSS_PATCH_NOT_ENABLED_WARNING} (HTTP 404 | APIGW.0101 | The API does not exist or has not been published in the environment | requestId=req-404)`);

    listHostStatus.mockRejectedValueOnce(ERR_500);
    const failed = await scanner.scan(ctx);
    expect(failed.status).toBe("error");
    expect(failed.error).toBe("Huawei Cloud HSS patch compliance scan failed: HTTP 500 | HSS.9999 | internal error | requestId=req-500");
    expect(failed.findingsCount).toBe(0);
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

  it("helpers: hssOsVulType, summarizeHostVuls, patchRiskScore", () => {
    expect(hssOsVulType({ os_type: "Windows" })).toBe("windows_vul");
    expect(hssOsVulType({ os_name: "Windows Server 2019" })).toBe("windows_vul");
    expect(hssOsVulType({ os_type: "Linux" })).toBe("linux_vul");
    expect(hssOsVulType({})).toBe("linux_vul");

    const state = summarizeHostVuls([
      hostVul({ vul_name: "low-1", severity_level: "Low" }),
      hostVul({ vul_name: "crit-1", severity_level: "Critical" }),
      hostVul({ vul_name: "med-1", severity_level: "Medium" }),
      hostVul({ vul_name: "high-1", severity_level: "High" }),
      hostVul({ vul_name: undefined, vul_id: "unrated-id", severity_level: "weird" }),
    ]);
    expect(state).toMatchObject({ total: 5, critical: 1, high: 1, medium: 1, low: 1, unknown: 1, truncated: false });
    expect(state.sample).toEqual(["crit-1", "high-1", "med-1", "low-1", "unrated-id"]);
    expect(patchRiskScore(state)).toBe(7.5);
    expect(patchRiskScore({ critical: 0, high: 0 })).toBe(5.5);
    expect(summarizeHostVuls([], true).truncated).toBe(true);
  });
});
