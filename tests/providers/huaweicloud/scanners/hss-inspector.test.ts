/**
 * HuaweiHssInspectorScanner (Huawei Cloud inspector_findings → HSS) — SDK client
 * factory + SDK package are mocked; no network, no credential file access.
 * Covers: not enabled (0 hosts) / enabled with vulnerabilities / 403 / 404 / 500,
 * pagination + per-type cap, top-N finding cap, and the no-Authorization-leak assertion.
 */
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll, afterEach } from "vitest";
import { inspect } from "util";

const { listHostStatus, listVulnerabilities, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock } = vi.hoisted(() => ({
  listHostStatus: vi.fn(),
  listVulnerabilities: vi.fn(),
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
  HuaweiHssInspectorScanner,
  HSS_NOT_ENABLED_WARNING,
  HSS_VUL_TYPES,
  HSS_VUL_PAGE_SIZE,
  HSS_MAX_VULS_PER_TYPE,
  HSS_MAX_VUL_FINDINGS,
  normalizeHssSeverity,
  sortHssVulnerabilities,
} from "../../../../src/providers/huaweicloud/scanners/hss-inspector.js";
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
  config: { url: "https://hss.cn-north-4.myhuaweicloud.com/v5/p/vulnerability/vulnerabilities", headers: { Authorization: FAKE_AUTH_HEADER } },
};

const HOSTS_ENABLED = { total_num: 12, data_list: [{ host_id: "h1", protect_status: "opened" }] };
const HOSTS_NONE = { total_num: 0, data_list: [] };

const vul = (over: Record<string, unknown>) => ({
  vul_id: "VUL-x",
  vul_name: "vuln",
  severity_level: "High",
  unhandle_host_num: 1,
  host_num: 1,
  cve_list: [],
  ...over,
});

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
    if (svc === "hss") return { listHostStatus, listVulnerabilities };
    throw new Error(`unexpected service ${svc}`);
  });
}

describe("HuaweiHssInspectorScanner (inspector_findings)", () => {
  const scanner = new HuaweiHssInspectorScanner();

  beforeEach(() => {
    for (const m of [listHostStatus, listVulnerabilities, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock]) m.mockReset();
    installClients();
    listHostStatus.mockResolvedValue(HOSTS_ENABLED);
    listVulnerabilities.mockResolvedValue({ total_num: 0, data_list: [] });
  });

  it("is registered on the huaweicloud provider under the AWS module name", () => {
    expect(scanner.moduleName).toBe("inspector_findings");
    expect(huaweiCloudProvider.scanners().map((s) => s.moduleName)).toContain("inspector_findings");
  });

  it("no protected hosts → single 'HSS not enabled' finding (6.0 MEDIUM, same level as the AWS Inspector detection finding) + 'is not enabled' warning; vulnerabilities not queried", async () => {
    listHostStatus.mockResolvedValueOnce(HOSTS_NONE);

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(0);
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0]).toMatchObject({
      riskScore: 6.0,
      severity: "MEDIUM",
      priority: "P2",
      resourceType: "HuaweiCloud::HSS::Host",
      resourceId: "hss-vulnerability-scan",
      resourceArn: urn("hss", "vulnerability-scan", "none"),
      region: "cn-north-4",
      accountId: DOMAIN,
      module: "inspector_findings",
      provider: "huaweicloud",
    });
    expect(result.findings[0].title).toContain("HSS vulnerability scanning is not enabled");
    expect(result.warnings).toEqual([HSS_NOT_ENABLED_WARNING]);
    expect(HSS_NOT_ENABLED_WARNING).toContain("is not enabled"); // HTML report N/A pattern
    expect(listHostStatus).toHaveBeenCalledTimes(1);
    expect(listHostStatus.mock.calls[0][0]).toEqual({ region: "cn-north-4", protect_status: "opened", limit: 10, offset: 0 });
    expect(listVulnerabilities).not.toHaveBeenCalled();
    // Regional (basic) client built with the region scope; credential chain not consulted.
    expect(hwClientMock).toHaveBeenCalledTimes(1);
    expect(hwClientMock.mock.calls[0][1]).toBe("hss");
    expect(hwClientMock.mock.calls[0][2]).toBe(creds);
    expect(hwClientMock.mock.calls[0][3]).toEqual({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });
    expect(loadHuaweiCredentialsMock).not.toHaveBeenCalled();
  });

  it("enabled → queries every vulnerability type (unhandled only), reports Critical/High as findings (9.5 / 8.0) sorted by severity then affected hosts, summarises Medium/Low", async () => {
    listVulnerabilities.mockImplementation(async (req: { type: string }) => {
      switch (req.type) {
        case "linux_vul":
          return {
            total_num: 5,
            data_list: [
              vul({ vul_id: "CESA-2026:0001", vul_name: "kernel: use-after-free", severity_level: "Critical", unhandle_host_num: 3, host_id_list: ["h1", "h2", "h3"], cve_list: [{ cve_id: "CVE-2026-0001", cvss: 9.8 }], repair_priority: "Critical", solution_detail: "yum update kernel", patch_url: "https://example.invalid/cesa-0001" }),
              vul({ vul_id: "CESA-2026:0002", vul_name: "openssl: buffer overflow", severity_level: "High", unhandle_host_num: 1 }),
              vul({ vul_id: "CESA-2026:0003", vul_name: "curl: info leak", severity_level: "Medium", unhandle_host_num: 4 }),
              vul({ vul_id: "CESA-2026:0004", vul_name: "vim: minor", severity_level: "Low", unhandle_host_num: 2 }),
              vul({ vul_id: "CESA-2026:0005", vul_name: "already fixed everywhere", severity_level: "Critical", unhandle_host_num: 0 }),
            ],
          };
        case "windows_vul":
          return { total_num: 1, data_list: [vul({ vul_id: "KB5031234", vul_name: "Windows SMB RCE", severity_level: "high", unhandle_host_num: 2, cve_list: [{ cve_id: "CVE-2026-1000" }] })] };
        case "web_cms":
          return { total_num: 0, data_list: [] };
        case "app_vul":
          return { total_num: 1, data_list: [vul({ vul_id: "APP-1", vul_name: "log4j old", severity_level: "Low", unhandle_host_num: 1 })] };
        default:
          throw new Error(`unexpected type ${req.type}`);
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.error).toBeUndefined();
    expect(result.resourcesScanned).toBe(12);
    expect(listVulnerabilities).toHaveBeenCalledTimes(HSS_VUL_TYPES.length);
    expect(listVulnerabilities.mock.calls.map((c) => c[0])).toEqual(
      HSS_VUL_TYPES.map((type) => ({ type, handle_status: "unhandled", limit: HSS_VUL_PAGE_SIZE, offset: 0 })),
    );

    expect(result.findingsCount).toBe(3);
    expect(result.findings.map((f) => f.resourceId)).toEqual(["CESA-2026:0001", "KB5031234", "CESA-2026:0002"]);
    const critical = result.findings[0];
    expect(critical).toMatchObject({
      riskScore: 9.5,
      severity: "CRITICAL",
      priority: "P0",
      resourceType: "HuaweiCloud::HSS::Vulnerability",
      resourceArn: urn("hss", "vulnerability", "CESA-2026:0001"),
      region: "cn-north-4",
      accountId: DOMAIN,
      module: "inspector_findings",
      provider: "huaweicloud",
    });
    expect(critical.title).toBe("HSS Critical vulnerability kernel: use-after-free is unhandled on 3 host(s)");
    expect(critical.description).toContain("CVEs: CVE-2026-0001");
    expect(critical.description).toContain("Affected hosts: h1, h2, h3");
    expect(critical.description).toContain("type linux_vul");
    expect(critical.remediationSteps.join("\n")).toContain("yum update kernel");
    expect(critical.remediationSteps.join("\n")).toContain("https://example.invalid/cesa-0001");
    expect(result.findings[1]).toMatchObject({ riskScore: 8.0, severity: "HIGH", resourceId: "KB5031234" });
    expect(result.findings[1].title).toContain("HSS High vulnerability Windows SMB RCE is unhandled on 2 host(s)");
    expect(result.findings[2]).toMatchObject({ riskScore: 8.0, severity: "HIGH", resourceId: "CESA-2026:0002" });

    expect(result.warnings).toEqual([
      "HSS: 6 unhandled vulnerabilities across 12 protected host(s) — Critical 1, High 2, Medium 1, Low 2. Medium/Low are summarised here only; review them in the HSS console.",
    ]);
  });

  it("enabled with no unhandled vulnerabilities → 0 findings and an informational warning", async () => {
    const result = await scanner.scan(ctx);
    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.resourcesScanned).toBe(12);
    expect(result.warnings).toEqual(["HSS: 12 protected host(s), no unhandled vulnerabilities reported."]);
  });

  it("paginates vulnerabilities with offset/limit + total_num and caps findings at the top 50 Critical/High with a count warning", async () => {
    const page1 = Array.from({ length: HSS_VUL_PAGE_SIZE }, (_, i) => vul({ vul_id: `V-${i}`, vul_name: `v${i}`, severity_level: i % 2 ? "High" : "Critical", unhandle_host_num: (i % 7) + 1 }));
    const page2 = [vul({ vul_id: "V-last", vul_name: "last", severity_level: "Critical", unhandle_host_num: 99 })];
    listVulnerabilities.mockImplementation(async (req: { type: string; offset: number }) => {
      if (req.type !== "linux_vul") return { total_num: 0, data_list: [] };
      return req.offset === 0 ? { total_num: HSS_VUL_PAGE_SIZE + 1, data_list: page1 } : { total_num: HSS_VUL_PAGE_SIZE + 1, data_list: page2 };
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const linuxCalls = listVulnerabilities.mock.calls.map((c) => c[0]).filter((r) => r.type === "linux_vul");
    expect(linuxCalls.map((r) => r.offset)).toEqual([0, HSS_VUL_PAGE_SIZE]);
    expect(listVulnerabilities).toHaveBeenCalledTimes(HSS_VUL_TYPES.length + 1);
    expect(result.findingsCount).toBe(HSS_MAX_VUL_FINDINGS);
    // Critical with the most affected hosts first.
    expect(result.findings[0].resourceId).toBe("V-last");
    expect(result.findings.every((f) => f.severity === "CRITICAL" || f.severity === "HIGH")).toBe(true);
    expect(result.findings.filter((f) => f.severity === "CRITICAL")).toHaveLength(HSS_MAX_VUL_FINDINGS); // 101 Critical available
    expect(result.warnings).toEqual([
      `HSS: ${HSS_VUL_PAGE_SIZE + 1} unhandled Critical/High vulnerabilities; only the top ${HSS_MAX_VUL_FINDINGS} (by severity and affected hosts) are reported as findings.`,
      `HSS: ${HSS_VUL_PAGE_SIZE + 1} unhandled vulnerabilities across 12 protected host(s) — Critical 101, High 100, Medium 0, Low 0. Medium/Low are summarised here only; review them in the HSS console.`,
    ]);
  });

  it("stops after the per-type cap when the API keeps returning full pages (truncation warning)", async () => {
    const full = Array.from({ length: HSS_VUL_PAGE_SIZE }, (_, i) => vul({ vul_id: `M-${i}`, severity_level: "Medium" }));
    listVulnerabilities.mockImplementation(async (req: { type: string }) => (req.type === "linux_vul" ? { total_num: 5000, data_list: full } : { total_num: 0, data_list: [] }));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    const linuxCalls = listVulnerabilities.mock.calls.map((c) => c[0]).filter((r) => r.type === "linux_vul");
    expect(linuxCalls).toHaveLength(HSS_MAX_VULS_PER_TYPE / HSS_VUL_PAGE_SIZE);
    expect(result.findingsCount).toBe(0); // Medium only
    expect(result.warnings![0]).toBe(`HSS: more than ${HSS_MAX_VULS_PER_TYPE} unhandled linux_vul vulnerabilities; only the first ${HSS_MAX_VULS_PER_TYPE} were evaluated.`);
    expect(result.warnings![1]).toContain(`HSS: ${HSS_MAX_VULS_PER_TYPE} unhandled vulnerabilities`);
  });

  it("403 on listHostStatus → permissions warning, status success, no findings, vulnerabilities not queried", async () => {
    listHostStatus.mockRejectedValueOnce(ERR_403);
    const result = await scanner.scan(ctx);
    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.resourcesScanned).toBe(0);
    expect(result.warnings).toEqual([
      "HSS: insufficient permissions to check host protection status (HTTP 403 | IAM.0002 | You have no permission to perform this action. | requestId=req-403). Grant HSS ReadOnlyAccess to check enablement.",
    ]);
    expect(listVulnerabilities).not.toHaveBeenCalled();
  });

  it("404 / not enabled on listHostStatus → 'not enabled' finding + warning with the redacted diagnostic", async () => {
    listHostStatus.mockRejectedValueOnce(ERR_404);
    const result = await scanner.scan(ctx);
    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].resourceId).toBe("hss-vulnerability-scan");
    expect(result.warnings).toEqual([`${HSS_NOT_ENABLED_WARNING} (HTTP 404 | APIGW.0101 | The API does not exist or has not been published in the environment | requestId=req-404)`]);
    expect(listVulnerabilities).not.toHaveBeenCalled();
  });

  it("500 on listHostStatus → status error with redacted message", async () => {
    listHostStatus.mockRejectedValueOnce(ERR_500);
    const result = await scanner.scan(ctx);
    expect(result.status).toBe("error");
    expect(result.error).toBe("Huawei Cloud HSS vulnerability scan failed: HTTP 500 | HSS.9999 | internal error | requestId=req-500");
    expect(result.findingsCount).toBe(0);
  });

  it("403 (raw 401 with Authorization header) on listVulnerabilities → one warning, remaining types skipped, status success, nothing leaks", async () => {
    listVulnerabilities.mockRejectedValueOnce(ERR_401_RAW);
    const result = await scanner.scan(ctx);
    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(12);
    expect(result.findingsCount).toBe(0);
    expect(listVulnerabilities).toHaveBeenCalledTimes(1);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings![0]).toContain("HSS vulnerabilities (linux_vul): insufficient permissions");
    expect(result.warnings![0]).toContain("APIGW.0301");
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("Authorization");
    expect(serialized).not.toContain(FAKE_AK);
    expect(serialized).not.toContain("Signature=deadbeef");
  });

  it("404 on one vulnerability type → warning for that type, other types still queried", async () => {
    listVulnerabilities.mockImplementation(async (req: { type: string }) => {
      if (req.type === "web_cms") throw ERR_404;
      if (req.type === "app_vul") return { total_num: 1, data_list: [vul({ vul_id: "APP-9", vul_name: "struts", severity_level: "Critical", unhandle_host_num: 1 })] };
      return { total_num: 0, data_list: [] };
    });
    const result = await scanner.scan(ctx);
    expect(result.status).toBe("success");
    expect(listVulnerabilities).toHaveBeenCalledTimes(HSS_VUL_TYPES.length);
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].resourceId).toBe("APP-9");
    expect(result.warnings![0]).toContain("HSS vulnerabilities (web_cms): service not enabled or not available");
  });

  it("500 on listVulnerabilities → status error", async () => {
    listVulnerabilities.mockRejectedValueOnce(ERR_500);
    const result = await scanner.scan(ctx);
    expect(result.status).toBe("error");
    expect(result.error).toContain("HSS.9999");
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

  it("helpers: normalizeHssSeverity is case-insensitive; sortHssVulnerabilities orders by severity, hosts, name", () => {
    expect(normalizeHssSeverity("critical")).toBe("Critical");
    expect(normalizeHssSeverity(" HIGH ")).toBe("High");
    expect(normalizeHssSeverity("Medium")).toBe("Medium");
    expect(normalizeHssSeverity("low")).toBe("Low");
    expect(normalizeHssSeverity(undefined)).toBe("Unknown");
    expect(normalizeHssSeverity(42)).toBe("Unknown");

    const sorted = sortHssVulnerabilities([
      { vul_name: "b-high-1", severity_level: "High", unhandle_host_num: 1 },
      { vul_name: "a-high-1", severity_level: "High", unhandle_host_num: 1 },
      { vul_name: "crit-2", severity_level: "Critical", unhandle_host_num: 2 },
      { vul_name: "high-9", severity_level: "High", unhandle_host_num: 9 },
      { vul_name: "unrated" },
    ]);
    expect(sorted.map((v) => v.vul_name)).toEqual(["crit-2", "high-9", "a-high-1", "b-high-1", "unrated"]);
  });
});
