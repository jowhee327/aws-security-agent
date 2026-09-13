/**
 * HuaweiSslCertificateScanner (Huawei Cloud ssl_certificate) — SDK client
 * factory + SDK packages are mocked; no network, no credential file access.
 */
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll, afterEach } from "vitest";
import { inspect } from "util";

const { scmListCertificates, elbListCertificates, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock } = vi.hoisted(() => ({
  scmListCertificates: vi.fn(),
  elbListCertificates: vi.fn(),
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
vi.mock("@huaweicloud/huaweicloud-sdk-scm", () => ({
  ScmClient: { newBuilder: vi.fn(() => { throw new Error("real SDK builder must not be used in tests"); }) },
}));
vi.mock("@huaweicloud/huaweicloud-sdk-elb/v3/ElbClient.js", () => ({
  ElbClient: { newBuilder: vi.fn(() => { throw new Error("real SDK builder must not be used in tests"); }) },
}));
vi.mock("../../../../src/providers/huaweicloud/credentials.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../../src/providers/huaweicloud/credentials.js")>();
  return { ...actual, loadHuaweiCredentials: loadHuaweiCredentialsMock, resolveRegionScope: resolveRegionScopeMock };
});

import {
  HuaweiSslCertificateScanner,
  evaluateCertificate,
  SCM_PAGE_SIZE,
  ELB_CERT_PAGE_SIZE,
} from "../../../../src/providers/huaweicloud/scanners/ssl-certificate.js";
import { parseHwTimestamp } from "../../../../src/providers/huaweicloud/scanners/shared.js";
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
/** SCM-style timestamp ("YYYY-MM-DD HH:mm:ss.S", UTC) `days` from now. */
function scmTime(days: number): string {
  const d = new Date(Date.now() + days * DAY);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.0`;
}
/** ELB-style ISO timestamp `days` from now. */
function isoTime(days: number): string {
  return new Date(Date.now() + days * DAY).toISOString();
}

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
    if (svc === "scm") return { listCertificates: scmListCertificates };
    if (svc === "elb") return { listCertificates: elbListCertificates };
    throw new Error(`unexpected service ${svc}`);
  });
}

describe("HuaweiSslCertificateScanner (ssl_certificate)", () => {
  const scanner = new HuaweiSslCertificateScanner();

  beforeEach(() => {
    scmListCertificates.mockReset();
    elbListCertificates.mockReset();
    hwClientMock.mockReset();
    loadHuaweiCredentialsMock.mockReset();
    resolveRegionScopeMock.mockReset();
    installClients();
    scmListCertificates.mockResolvedValue({ certificates: [], total_count: 0 });
    elbListCertificates.mockResolvedValue({ certificates: [], page_info: { current_count: 0 } });
  });

  it("is registered on the huaweicloud provider under the AWS module name", () => {
    expect(scanner.moduleName).toBe("ssl_certificate");
    expect(huaweiCloudProvider.scanners().map((s) => s.moduleName)).toContain("ssl_certificate");
  });

  it("maps SCM certificates to the AWS thresholds: expired 8.0, <30d 6.0, <90d 4.0, healthy none, UNPASSED 7.5, REVOKED 7.5", async () => {
    scmListCertificates.mockResolvedValueOnce({
      total_count: 7,
      certificates: [
        { id: "scm-expired", domain: "expired.example.com", status: "ISSUED", expire_time: scmTime(-10) },
        { id: "scm-status-expired", domain: "old.example.com", status: "EXPIRED", expire_time: scmTime(-400) },
        { id: "scm-soon", domain: "soon.example.com", status: "ISSUED", expire_time: scmTime(10) },
        { id: "scm-later", domain: "later.example.com", status: "ISSUED", expire_time: scmTime(60) },
        { id: "scm-ok", domain: "ok.example.com", status: "ISSUED", expire_time: scmTime(200) },
        { id: "scm-unpassed", domain: "bad.example.com", status: "UNPASSED", expire_time: scmTime(300) },
        { id: "scm-revoked", domain: "revoked.example.com", status: "REVOKED" },
      ],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.error).toBeUndefined();
    expect(result.warnings).toBeUndefined();
    expect(result.resourcesScanned).toBe(7);
    expect(result.findingsCount).toBe(6);

    const byId = new Map(result.findings.map((f) => [f.resourceId, f]));
    expect(byId.get("expired.example.com")).toMatchObject({ riskScore: 8.0, severity: "HIGH", resourceType: "HuaweiCloud::SCM::Certificate", provider: "huaweicloud", region: "cn-north-4" });
    expect(byId.get("expired.example.com")!.title).toBe("Certificate for expired.example.com has expired");
    expect(byId.get("expired.example.com")!.description).toMatch(/expired 1[01] days ago/);
    expect(byId.get("expired.example.com")!.resourceArn).toBe(`hws:cn-north-4:${DOMAIN}:scm:certificate:scm-expired`);
    expect(byId.get("old.example.com")).toMatchObject({ riskScore: 8.0 });
    expect(byId.get("soon.example.com")).toMatchObject({ riskScore: 6.0, severity: "MEDIUM" });
    expect(byId.get("soon.example.com")!.title).toMatch(/expires in (9|10) days/);
    expect(byId.get("later.example.com")).toMatchObject({ riskScore: 4.0, severity: "MEDIUM" });
    expect(byId.has("ok.example.com")).toBe(false);
    expect(byId.get("bad.example.com")).toMatchObject({ riskScore: 7.5, severity: "HIGH" });
    expect(byId.get("bad.example.com")!.title).toBe("Certificate for bad.example.com is in UNPASSED status");
    expect(byId.get("revoked.example.com")).toMatchObject({ riskScore: 7.5 });

    // Same regional (basic) client construction for both services.
    expect(hwClientMock).toHaveBeenCalledTimes(2);
    expect(hwClientMock.mock.calls[0][1]).toBe("scm");
    expect(hwClientMock.mock.calls[0][2]).toBe(creds);
    expect(hwClientMock.mock.calls[0][3]).toEqual({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });
    expect(hwClientMock.mock.calls[1][1]).toBe("elb");
    expect(loadHuaweiCredentialsMock).not.toHaveBeenCalled();
    expect(resolveRegionScopeMock).not.toHaveBeenCalled();
  });

  it("pending SCM statuses (CHECKING / ISSUING) and missing expire_time produce no findings", async () => {
    scmListCertificates.mockResolvedValueOnce({
      total_count: 3,
      certificates: [
        { id: "a", domain: "a.example.com", status: "CHECKING" },
        { id: "b", domain: "b.example.com", status: "ISSUING", expire_time: scmTime(5) },
        { id: "c", domain: "c.example.com", status: "ISSUED" },
      ],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(3);
    expect(result.findingsCount).toBe(0);
  });

  it("paginates SCM by limit/offset (2 pages, total_count) and ELB by page_info.next_marker (2 pages)", async () => {
    const scmPage1 = Array.from({ length: SCM_PAGE_SIZE }, (_, i) => ({ id: `scm-${i}`, domain: `d${i}.example.com`, status: "ISSUED", expire_time: scmTime(365) }));
    const scmPage2 = [{ id: "scm-last", domain: "last.example.com", status: "ISSUED", expire_time: scmTime(3) }];
    scmListCertificates
      .mockResolvedValueOnce({ certificates: scmPage1, total_count: SCM_PAGE_SIZE + 1 })
      .mockResolvedValueOnce({ certificates: scmPage2, total_count: SCM_PAGE_SIZE + 1 });

    const elbPage1 = Array.from({ length: ELB_CERT_PAGE_SIZE }, (_, i) => ({ id: `elb-${i}`, domain: `e${i}.example.com`, type: "server", expire_time: isoTime(400) }));
    const elbPage2 = [{ id: "elb-last", domain: "elb-last.example.com", type: "server", expire_time: isoTime(-2) }];
    elbListCertificates
      .mockResolvedValueOnce({ certificates: elbPage1, page_info: { next_marker: "elb-99", current_count: ELB_CERT_PAGE_SIZE } })
      .mockResolvedValueOnce({ certificates: elbPage2, page_info: { current_count: 1 } });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(scmListCertificates).toHaveBeenCalledTimes(2);
    expect(scmListCertificates.mock.calls[0][0]).toEqual({ limit: SCM_PAGE_SIZE, offset: 0 });
    expect(scmListCertificates.mock.calls[1][0]).toEqual({ limit: SCM_PAGE_SIZE, offset: SCM_PAGE_SIZE });
    expect(elbListCertificates).toHaveBeenCalledTimes(2);
    expect(elbListCertificates.mock.calls[0][0]).toEqual({ limit: ELB_CERT_PAGE_SIZE });
    expect(elbListCertificates.mock.calls[1][0]).toEqual({ limit: ELB_CERT_PAGE_SIZE, marker: "elb-99" });
    expect(result.resourcesScanned).toBe(SCM_PAGE_SIZE + 1 + ELB_CERT_PAGE_SIZE + 1);
    expect(result.findings.map((f) => f.resourceId).sort()).toEqual(["elb-last.example.com", "last.example.com"]);
    const elbFinding = result.findings.find((f) => f.resourceId === "elb-last.example.com")!;
    expect(elbFinding).toMatchObject({ riskScore: 8.0, resourceType: "HuaweiCloud::ELB::Certificate" });
    expect(elbFinding.resourceArn).toBe(`hws:cn-north-4:${DOMAIN}:elb:certificate:elb-last`);
  });

  it("de-duplicates ELB certificates that reference an SCM certificate or share domain + expiry day", async () => {
    const exp = scmTime(5);
    scmListCertificates.mockResolvedValueOnce({
      total_count: 1,
      certificates: [{ id: "scm-1", domain: "shared.example.com", status: "ISSUED", expire_time: exp }],
    });
    elbListCertificates.mockResolvedValueOnce({
      certificates: [
        { id: "elb-ref", domain: "shared.example.com", scm_certificate_id: "scm-1", expire_time: exp },
        { id: "elb-samedomain", domain: "SHARED.example.com", expire_time: new Date(parseHwTimestamp(exp)!).toISOString() },
        { id: "elb-own", domain: "own.example.com", expire_time: isoTime(20) },
      ],
      page_info: { current_count: 3 },
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(2); // 1 SCM + 1 non-duplicate ELB
    expect(result.findings.map((f) => f.resourceArn).sort()).toEqual([
      `hws:cn-north-4:${DOMAIN}:elb:certificate:elb-own`,
      `hws:cn-north-4:${DOMAIN}:scm:certificate:scm-1`,
    ]);
    expect(result.findings.every((f) => f.riskScore === 6.0)).toBe(true);
  });

  it("degrades gracefully on 403 for SCM (ELB still scanned) and for both services (success, 0 findings)", async () => {
    scmListCertificates.mockRejectedValueOnce({ httpStatusCode: 403, errorCode: "SCM.0403", errorMsg: "Forbidden", requestId: "r-scm" });
    elbListCertificates.mockResolvedValueOnce({ certificates: [{ id: "elb-1", domain: "e.example.com", expire_time: isoTime(-1) }], page_info: {} });

    const partial = await scanner.scan(ctx);
    expect(partial.status).toBe("success");
    expect(partial.findingsCount).toBe(1);
    expect(partial.findings[0].resourceId).toBe("e.example.com");
    expect(partial.warnings).toEqual(["SCM: insufficient permissions (HTTP 403 | SCM.0403 | Forbidden | requestId=r-scm); skipped"]);

    scmListCertificates.mockRejectedValueOnce({
      status: 401,
      data: { error_code: "APIGW.0301", error_msg: "Incorrect IAM authentication information" },
      message: "Request failed with status code 401",
      config: { headers: { Authorization: FAKE_AUTH_HEADER } },
    });
    elbListCertificates.mockRejectedValueOnce({ httpStatusCode: 404, errorCode: "APIGW.0101", errorMsg: "The API does not exist or has not been published in the environment" });

    const both = await scanner.scan(ctx);
    expect(both.status).toBe("success");
    expect(both.findingsCount).toBe(0);
    expect(both.warnings).toHaveLength(2);
    expect(both.warnings![0]).toContain("SCM: insufficient permissions");
    expect(both.warnings![1]).toContain("ELB: service not enabled or not available");
    const serialized = JSON.stringify(both);
    expect(serialized).not.toContain("Authorization");
    expect(serialized).not.toContain(FAKE_AK);
  });

  it("returns status error (without credentials) on unexpected failures", async () => {
    scmListCertificates.mockRejectedValueOnce({ httpStatusCode: 500, errorCode: "SCM.9999", errorMsg: "internal error" });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("error");
    expect(result.error).toBe("Huawei Cloud SSL certificate scan failed: HTTP 500 | SCM.9999 | internal error");
    expect(result.findingsCount).toBe(0);
    expect(JSON.stringify(result)).not.toContain(FAKE_AK);
  });

  it("falls back to the credential chain / IAM project resolution when the context lacks them", async () => {
    const chainCreds = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK });
    loadHuaweiCredentialsMock.mockReturnValueOnce({ basic: chainCreds, global: chainCreds, source: "env" });
    resolveRegionScopeMock.mockResolvedValueOnce({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });

    const result = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: "", provider: "huaweicloud" });

    expect(result.status).toBe("success");
    expect(loadHuaweiCredentialsMock).toHaveBeenCalledTimes(1);
    expect(resolveRegionScopeMock).toHaveBeenCalledWith(chainCreds, "cn-north-4");
    expect(hwClientMock.mock.calls[0][3]).toEqual({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });
  });

  it("evaluateCertificate / parseHwTimestamp handle SCM, ISO and epoch formats and edge cases", () => {
    const now = Date.parse("2026-09-13T00:00:00Z");
    expect(parseHwTimestamp("2026-10-01 12:00:00.0")).toBe(Date.parse("2026-10-01T12:00:00.000Z"));
    expect(parseHwTimestamp("2026-10-01 12:00:00")).toBe(Date.parse("2026-10-01T12:00:00Z"));
    expect(parseHwTimestamp("2026-10-01T12:00:00Z")).toBe(Date.parse("2026-10-01T12:00:00Z"));
    expect(parseHwTimestamp(1790000000)).toBe(1790000000 * 1000);
    expect(parseHwTimestamp("1790000000000")).toBe(1790000000000);
    expect(parseHwTimestamp("not a date")).toBeUndefined();
    expect(parseHwTimestamp("")).toBeUndefined();
    expect(parseHwTimestamp(undefined)).toBeUndefined();

    expect(evaluateCertificate("ISSUED", "2026-09-12 00:00:00.0", now)).toEqual({ kind: "expired", daysAgo: 1, expiryIso: "2026-09-12" });
    expect(evaluateCertificate("ISSUED", "2026-10-12 00:00:00.0", now)).toEqual({ kind: "expiring", days: 29, riskScore: 6.0, expiryIso: "2026-10-12" });
    expect(evaluateCertificate("ISSUED", "2026-10-13 00:00:00.0", now)).toEqual({ kind: "expiring", days: 30, riskScore: 4.0, expiryIso: "2026-10-13" });
    expect(evaluateCertificate("ISSUED", "2026-12-12 00:00:00.0", now)).toEqual({ kind: "ok" });
    expect(evaluateCertificate("EXPIRED", undefined, now)).toEqual({ kind: "expired", daysAgo: 0, expiryIso: undefined });
    expect(evaluateCertificate("unpassed", "2027-01-01 00:00:00.0", now)).toEqual({ kind: "failed", status: "UNPASSED" });
    expect(evaluateCertificate("CHECKING", "2026-09-01 00:00:00.0", now)).toEqual({ kind: "ok" });
    expect(evaluateCertificate(undefined, "garbage", now)).toEqual({ kind: "ok" });
  });
});
