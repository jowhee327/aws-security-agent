/**
 * HuaweiServiceDetectionScanner (Huawei Cloud service_detection) — SDK client
 * factory + SDK packages are mocked; no network, no credential file access.
 * Probe matrix per service: enabled / empty / 404 / 403 / other error.
 */
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll, afterEach } from "vitest";
import { inspect } from "util";

const { listTrackers, showTrackerConfig, listHostStatus, listWorkspaces, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock } =
  vi.hoisted(() => ({
    listTrackers: vi.fn(),
    showTrackerConfig: vi.fn(),
    listHostStatus: vi.fn(),
    listWorkspaces: vi.fn(),
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
vi.mock("@huaweicloud/huaweicloud-sdk-cts", () => ({ CtsClient: { newBuilder: vi.fn(boom) } }));
vi.mock("@huaweicloud/huaweicloud-sdk-config", () => ({ ConfigClient: { newBuilder: vi.fn(boom) } }));
vi.mock("@huaweicloud/huaweicloud-sdk-hss", () => ({ HssClient: { newBuilder: vi.fn(boom) } }));
vi.mock("@huaweicloud/huaweicloud-sdk-secmaster/v1/SecMasterClient.js", () => ({ SecMasterClient: { newBuilder: vi.fn(boom) } }));
vi.mock("../../../../src/providers/huaweicloud/credentials.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../../src/providers/huaweicloud/credentials.js")>();
  return { ...actual, loadHuaweiCredentials: loadHuaweiCredentialsMock, resolveRegionScope: resolveRegionScopeMock };
});

import {
  HuaweiServiceDetectionScanner,
  HW_SERVICE_RECOMMENDATIONS,
  probeOutcomeFromError,
} from "../../../../src/providers/huaweicloud/scanners/service-detection.js";
import type { ServiceDetectionResult } from "../../../../src/scanners/service-detection.js";
import { createHuaweiCredentials, HuaweiCredentialsNotFoundError } from "../../../../src/providers/huaweicloud/credentials.js";
import { huaweiCloudProvider } from "../../../../src/providers/huaweicloud/index.js";
import type { ScanContext, ScanResult } from "../../../../src/types.js";

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

type ScanResultWithDetection = ScanResult & { serviceDetection?: ServiceDetectionResult };

const ERR_403 = { httpStatusCode: 403, errorCode: "IAM.0002", errorMsg: "You have no permission to perform this action.", requestId: "req-403" };
const ERR_404 = { httpStatusCode: 404, errorCode: "APIGW.0101", errorMsg: "The API does not exist or has not been published in the environment", requestId: "req-404" };
const ERR_500 = { httpStatusCode: 500, errorCode: "SVC.9999", errorMsg: "internal error", requestId: "req-500" };
const ERR_401_RAW = {
  status: 401,
  data: { error_code: "APIGW.0301", error_msg: "Incorrect IAM authentication information: verify aksk signature fail" },
  message: "Request failed with status code 401",
  config: { url: "https://hss.cn-north-4.myhuaweicloud.com/v5/p/host-management/hosts", headers: { Authorization: FAKE_AUTH_HEADER } },
};

const TRACKER_OK = {
  channel: { obs: { bucket_name: "rms-bucket", region_id: "cn-north-4" } },
  selector: { all_supported: true, resource_types: [] },
  retention_period_in_days: 180,
  agency_name: "rms_tracker_agency",
};

/** All four services enabled. */
function allEnabled() {
  listTrackers.mockResolvedValue({ trackers: [{ id: "t1", tracker_name: "system", tracker_type: "system", status: "enabled" }] });
  showTrackerConfig.mockResolvedValue(TRACKER_OK);
  listHostStatus.mockResolvedValue({ total_num: 12, data_list: [{ host_id: "h1", protect_status: "opened" }] });
  listWorkspaces.mockResolvedValue({ workspaces: [{ id: "ws-1", name: "default" }], count: 1 });
}

/** All four services report "nothing configured". */
function allEmpty() {
  listTrackers.mockResolvedValue({ trackers: [] });
  showTrackerConfig.mockResolvedValue({ httpStatusCode: 200 });
  listHostStatus.mockResolvedValue({ total_num: 0, data_list: [] });
  listWorkspaces.mockResolvedValue({ workspaces: [], count: 0 });
}

function installClients() {
  hwClientMock.mockImplementation(async (_cls: unknown, svc: string) => {
    switch (svc) {
      case "cts": return { listTrackers };
      case "rms": return { showTrackerConfig };
      case "hss": return { listHostStatus };
      case "secmaster": return { listWorkspaces };
      default: throw new Error(`unexpected service ${svc}`);
    }
  });
}

function svc(result: ScanResultWithDetection, name: string) {
  const s = result.serviceDetection!.services.find((x) => x.name === name);
  expect(s, `service ${name} present`).toBeDefined();
  return s!;
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

describe("HuaweiServiceDetectionScanner (service_detection)", () => {
  const scanner = new HuaweiServiceDetectionScanner();

  beforeEach(() => {
    for (const m of [listTrackers, showTrackerConfig, listHostStatus, listWorkspaces, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock]) m.mockReset();
    installClients();
  });

  it("is registered on the huaweicloud provider under the AWS module name", () => {
    expect(scanner.moduleName).toBe("service_detection");
    expect(huaweiCloudProvider.scanners().map((s) => s.moduleName)).toContain("service_detection");
  });

  it("all enabled → 0 findings, 100% coverage, maturity advanced (4 probes), services in fixed order, correct client scopes", async () => {
    allEnabled();

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.status).toBe("success");
    expect(result.error).toBeUndefined();
    expect(result.warnings).toBeUndefined();
    expect(result.findingsCount).toBe(0);
    expect(result.resourcesScanned).toBe(4);
    expect(result.serviceDetection).toBeDefined();
    expect(result.serviceDetection!.coveragePercent).toBe(100);
    expect(result.serviceDetection!.maturityLevel).toBe("advanced");
    expect(result.serviceDetection!.services.map((s) => s.name)).toEqual(["CTS", "RMS (Config)", "HSS", "SecMaster"]);
    for (const s of result.serviceDetection!.services) expect(s.enabled).toBe(true);
    expect(svc(result, "CTS").details).toBe("1 tracker(s) configured");
    expect(svc(result, "RMS (Config)").details).toBe("Resource recorder configured (retention 180 days)");
    expect(svc(result, "HSS").details).toBe("12 protected host(s)");
    expect(svc(result, "SecMaster").details).toBe("1 workspace(s)");

    // Regional probes use the basic scope; RMS uses the global scope with the domain ID.
    const bySvc = new Map(hwClientMock.mock.calls.map((c) => [c[1] as string, c]));
    expect(bySvc.size).toBe(4);
    expect(bySvc.get("cts")![3]).toEqual({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });
    expect(bySvc.get("hss")![3]).toEqual({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });
    expect(bySvc.get("secmaster")![3]).toEqual({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });
    expect(bySvc.get("rms")![3]).toEqual({ region: "cn-north-4", domainId: DOMAIN });
    for (const c of hwClientMock.mock.calls) expect(c[2]).toBe(creds);

    // Request shapes: HSS needs region + protect_status filter; SecMaster v1 requires offset + limit.
    expect(listTrackers).toHaveBeenCalledWith({});
    expect(showTrackerConfig).toHaveBeenCalledWith({ domainId: DOMAIN });
    expect(listHostStatus).toHaveBeenCalledWith({ region: "cn-north-4", protect_status: "opened", limit: 1, offset: 0 });
    expect(listWorkspaces).toHaveBeenCalledWith({ offset: 0, limit: 1 });
    expect(loadHuaweiCredentialsMock).not.toHaveBeenCalled();
    expect(resolveRegionScopeMock).not.toHaveBeenCalled();
  });

  it("all empty → enabled=false with recommendations, 3 findings (RMS/HSS/SecMaster, not CTS), 0% coverage, basic", async () => {
    allEmpty();

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.status).toBe("success");
    expect(result.warnings).toBeUndefined();
    expect(result.serviceDetection!.coveragePercent).toBe(0);
    expect(result.serviceDetection!.maturityLevel).toBe("basic");
    for (const name of ["CTS", "RMS (Config)", "HSS", "SecMaster"]) {
      const s = svc(result, name);
      expect(s.enabled).toBe(false);
      expect(s.recommendation).toBe(HW_SERVICE_RECOMMENDATIONS[name]);
      expect(s.recommendation).toBeTruthy();
    }

    expect(result.findingsCount).toBe(3);
    const byType = new Map(result.findings.map((f) => [f.resourceType, f]));
    expect(byType.get("HuaweiCloud::RMS::Tracker")).toMatchObject({
      riskScore: 6.0,
      severity: "MEDIUM",
      priority: "P2",
      region: "global",
      resourceArn: `hws:global:${DOMAIN}:rms:tracker:default`,
      provider: "huaweicloud",
      accountId: DOMAIN,
      module: "service_detection",
    });
    expect(byType.get("HuaweiCloud::HSS::Host")).toMatchObject({
      riskScore: 6.0,
      severity: "MEDIUM",
      region: "cn-north-4",
      resourceArn: `hws:cn-north-4:${DOMAIN}:hss:protection:none`,
    });
    expect(byType.get("HuaweiCloud::SecMaster::Workspace")).toMatchObject({
      riskScore: 7.5,
      severity: "HIGH",
      priority: "P1",
      region: "cn-north-4",
      resourceArn: `hws:cn-north-4:${DOMAIN}:secmaster:workspace:none`,
    });
    expect(byType.get("HuaweiCloud::SecMaster::Workspace")!.title).toBe("Huawei Cloud SecMaster is not enabled");
    for (const f of result.findings) expect(f.remediationSteps.length).toBeGreaterThan(0);
  });

  it("404 / 'not opened' errors are treated as not enabled (enabled=false + finding), no warnings", async () => {
    listTrackers.mockRejectedValue(ERR_404);
    showTrackerConfig.mockRejectedValue({ httpStatusCode: 404, errorCode: "RMS.0002", errorMsg: "The tracker config does not exist." });
    listHostStatus.mockRejectedValue({ httpStatusCode: 400, errorCode: "HSS.NotOpen", errorMsg: "HSS service has not been enabled" });
    listWorkspaces.mockRejectedValue({ httpStatusCode: 405, errorCode: "APIGW.0106", errorMsg: "method not allowed" });

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.status).toBe("success");
    expect(result.warnings).toBeUndefined();
    for (const name of ["CTS", "RMS (Config)", "HSS", "SecMaster"]) {
      const s = svc(result, name);
      expect(s.enabled).toBe(false);
      expect(s.recommendation).toBe(HW_SERVICE_RECOMMENDATIONS[name]);
      expect(s.details).toBeTruthy(); // carries the error description
    }
    expect(svc(result, "CTS").details).toContain("APIGW.0101");
    expect(result.findingsCount).toBe(3);
    expect(result.serviceDetection!.coveragePercent).toBe(0);
  });

  it("403 → enabled=null + 'insufficient permissions' warning, excluded from the coverage denominator, no finding", async () => {
    allEnabled();
    listHostStatus.mockRejectedValue(ERR_403);
    listWorkspaces.mockRejectedValue(ERR_401_RAW); // 401 raw shape with Authorization header → access denied

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(svc(result, "HSS")).toEqual({ name: "HSS", enabled: null, details: "Access denied" });
    expect(svc(result, "SecMaster")).toEqual({ name: "SecMaster", enabled: null, details: "Access denied" });
    expect(svc(result, "CTS").enabled).toBe(true);
    expect(svc(result, "RMS (Config)").enabled).toBe(true);
    expect(result.warnings).toEqual([
      "HSS: insufficient permissions to check status",
      "SecMaster: insufficient permissions to check status",
    ]);
    // 2 enabled out of 2 known → 100%; maturity from enabled count (2) → intermediate.
    expect(result.serviceDetection!.coveragePercent).toBe(100);
    expect(result.serviceDetection!.maturityLevel).toBe("intermediate");

    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("Authorization");
    expect(serialized).not.toContain(FAKE_AK);
    expect(serialized).not.toContain(FAKE_SK);
  });

  it("other errors → enabled=null + 'detection failed' warning with the safe error description; other probes unaffected", async () => {
    allEmpty();
    listTrackers.mockRejectedValue(ERR_500);
    showTrackerConfig.mockRejectedValue(new Error("connect ETIMEDOUT 1.2.3.4:443"));

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.status).toBe("success");
    expect(svc(result, "CTS")).toEqual({ name: "CTS", enabled: null, details: "Detection error" });
    expect(svc(result, "RMS (Config)")).toEqual({ name: "RMS (Config)", enabled: null, details: "Detection error" });
    expect(svc(result, "HSS").enabled).toBe(false);
    expect(svc(result, "SecMaster").enabled).toBe(false);
    expect(result.warnings).toEqual([
      "CTS detection failed: HTTP 500 | SVC.9999 | internal error | requestId=req-500",
      "RMS (Config) detection failed: connect ETIMEDOUT 1.2.3.4:443",
    ]);
    // Only HSS + SecMaster findings (RMS probe errored → no RMS finding).
    expect(result.findings.map((f) => f.resourceType).sort()).toEqual(["HuaweiCloud::HSS::Host", "HuaweiCloud::SecMaster::Workspace"]);
    expect(result.serviceDetection!.coveragePercent).toBe(0);
    expect(result.serviceDetection!.maturityLevel).toBe("basic");
  });

  it("mixed matrix: CTS enabled, RMS empty, HSS 403, SecMaster error → coverage 50%, maturity basic", async () => {
    listTrackers.mockResolvedValue({ trackers: [{ id: "a" }, { id: "b" }] });
    showTrackerConfig.mockResolvedValue({});
    listHostStatus.mockRejectedValue(ERR_403);
    listWorkspaces.mockRejectedValue(ERR_500);

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(result.status).toBe("success");
    expect(svc(result, "CTS")).toMatchObject({ enabled: true, details: "2 tracker(s) configured" });
    expect(svc(result, "RMS (Config)").enabled).toBe(false);
    expect(svc(result, "HSS").enabled).toBeNull();
    expect(svc(result, "SecMaster").enabled).toBeNull();
    expect(result.serviceDetection!.coveragePercent).toBe(50); // 1 of 2 known
    expect(result.serviceDetection!.maturityLevel).toBe("basic");
    expect(result.findings.map((f) => f.resourceType)).toEqual(["HuaweiCloud::RMS::Tracker"]);
    expect(result.warnings).toHaveLength(2);
  });

  it("HSS falls back to data_list length and SecMaster to workspaces length when counts are missing", async () => {
    allEmpty();
    listHostStatus.mockResolvedValue({ data_list: [{ host_id: "h1" }] });
    listWorkspaces.mockResolvedValue({ workspaces: [{ id: "ws" }] });

    const result = (await scanner.scan(ctx)) as ScanResultWithDetection;

    expect(svc(result, "HSS")).toMatchObject({ enabled: true, details: "1 protected host(s)" });
    expect(svc(result, "SecMaster")).toMatchObject({ enabled: true, details: "1 workspace(s)" });
  });

  it("falls back to the credential chain / IAM scope resolution when the context lacks them", async () => {
    const chainCreds = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK });
    loadHuaweiCredentialsMock.mockReturnValue({ basic: chainCreds, global: chainCreds, source: "env" });
    resolveRegionScopeMock.mockResolvedValue({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });
    allEnabled();

    const result = (await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: "", provider: "huaweicloud" })) as ScanResultWithDetection;

    expect(result.status).toBe("success");
    expect(result.serviceDetection!.coveragePercent).toBe(100);
    expect(resolveRegionScopeMock).toHaveBeenCalledWith(chainCreds, "cn-north-4");
    const bySvc = new Map(hwClientMock.mock.calls.map((c) => [c[1] as string, c]));
    expect(bySvc.get("cts")![3]).toEqual({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });
    expect(bySvc.get("rms")![3]).toEqual({ region: "cn-north-4", domainId: DOMAIN });
    expect(showTrackerConfig).toHaveBeenCalledWith({ domainId: DOMAIN });
  });

  it("returns status error (no probes) when credentials cannot be resolved", async () => {
    loadHuaweiCredentialsMock.mockImplementation(() => { throw new HuaweiCredentialsNotFoundError("/nonexistent/credentials"); });

    const result = (await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: DOMAIN, provider: "huaweicloud" })) as ScanResultWithDetection;

    expect(result.status).toBe("error");
    expect(result.error).toContain("Huawei Cloud credentials not found");
    expect(result.serviceDetection).toBeUndefined();
    expect(hwClientMock).not.toHaveBeenCalled();
  });
});

describe("probeOutcomeFromError", () => {
  it("classifies 403/401 as denied, 404/405/not-open as disabled, others as error", () => {
    expect(probeOutcomeFromError(ERR_403)).toEqual({ kind: "denied" });
    expect(probeOutcomeFromError(ERR_401_RAW)).toEqual({ kind: "denied" });
    expect(probeOutcomeFromError(ERR_404)).toMatchObject({ kind: "disabled" });
    expect(probeOutcomeFromError({ httpStatusCode: 405 })).toMatchObject({ kind: "disabled" });
    expect(probeOutcomeFromError({ httpStatusCode: 400, errorCode: "SecMaster.NotOpen", errorMsg: "x" })).toMatchObject({ kind: "disabled" });
    expect(probeOutcomeFromError(ERR_500)).toEqual({ kind: "error", message: "HTTP 500 | SVC.9999 | internal error | requestId=req-500" });
    const described = JSON.stringify(probeOutcomeFromError(ERR_401_RAW));
    expect(described).not.toContain("Authorization");
    expect(described).not.toContain(FAKE_AK);
  });
});
