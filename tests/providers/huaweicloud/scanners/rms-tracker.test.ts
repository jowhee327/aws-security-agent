/**
 * RmsTrackerScanner (Huawei Cloud config_rules_findings) — client factory and
 * SDK package are mocked; no network, no credential file access.
 */
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll, afterEach } from "vitest";
import { inspect } from "util";

const { showTrackerConfig, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock } = vi.hoisted(() => ({
  showTrackerConfig: vi.fn(),
  hwClientMock: vi.fn(),
  loadHuaweiCredentialsMock: vi.fn(),
  resolveRegionScopeMock: vi.fn(),
}));

vi.mock("../../../../src/providers/huaweicloud/client.js", () => ({
  hwClient: hwClientMock,
  silenceSdkLogging: vi.fn(),
}));
// The SDK package must never be loaded in unit tests (heavy + configures log4js).
vi.mock("@huaweicloud/huaweicloud-sdk-config", () => ({
  ConfigClient: { newBuilder: vi.fn(() => { throw new Error("real SDK builder must not be used in tests"); }) },
}));
vi.mock("../../../../src/providers/huaweicloud/credentials.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../../src/providers/huaweicloud/credentials.js")>();
  return { ...actual, loadHuaweiCredentials: loadHuaweiCredentialsMock, resolveRegionScope: resolveRegionScopeMock };
});

import { RmsTrackerScanner, RMS_TRACKER_NOT_ENABLED_WARNING, rmsTrackerUrn, isTrackerConfigured } from "../../../../src/providers/huaweicloud/scanners/rms-tracker.js";
import { createHuaweiCredentials, HuaweiCredentialsNotFoundError } from "../../../../src/providers/huaweicloud/credentials.js";
import { huaweiCloudProvider } from "../../../../src/providers/huaweicloud/index.js";
import type { ScanContext } from "../../../../src/types.js";

const FAKE_AK = "FAKEAK0123456789ABCD";
const FAKE_SK = "FAKESK0123456789abcdefghijklmnopqrstuvwx";
const DOMAIN = "0123456789abcdef0123456789abcdef";
const FAKE_AUTH_HEADER = `SDK-HMAC-SHA256 Access=${FAKE_AK}, SignedHeaders=host;x-sdk-date, Signature=deadbeef`;

const creds = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK, domainId: DOMAIN });

const ctx: ScanContext = {
  region: "cn-north-4",
  partition: "huaweicloud",
  accountId: DOMAIN,
  provider: "huaweicloud",
  projectId: "p-north4",
  domainId: DOMAIN,
  credentials: creds,
};

const TRACKER_OK = {
  channel: { obs: { bucket_name: "rms-bucket", region_id: "cn-north-4" } },
  selector: { all_supported: true, resource_types: [] },
  retention_period_in_days: 180,
  agency_name: "rms_tracker_agency",
  domain_id: DOMAIN,
  frozen_status: { is_frozen: false, frozen_scene: [] },
};

/** Capture anything that could reach the MCP stdio channel or a terminal. */
const captured: string[] = [];
const spies: Array<ReturnType<typeof vi.spyOn>> = [];
beforeAll(() => {
  spies.push(vi.spyOn(process.stdout, "write").mockImplementation(((c: unknown) => { captured.push(String(c)); return true; }) as never));
  spies.push(vi.spyOn(process.stderr, "write").mockImplementation(((c: unknown) => { captured.push(String(c)); return true; }) as never));
  for (const m of ["log", "error", "warn", "info", "debug"] as const) {
    spies.push(vi.spyOn(console, m).mockImplementation((...args: unknown[]) => {
      captured.push(args.map((a) => (typeof a === "string" ? a : inspect(a))).join(" "));
    }));
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

describe("RmsTrackerScanner (config_rules_findings, detection-only)", () => {
  const scanner = new RmsTrackerScanner();

  beforeEach(() => {
    showTrackerConfig.mockReset();
    hwClientMock.mockReset();
    hwClientMock.mockResolvedValue({ showTrackerConfig });
    loadHuaweiCredentialsMock.mockReset();
    resolveRegionScopeMock.mockReset();
  });

  it("is registered on the huaweicloud provider under the AWS module name", () => {
    expect(scanner.moduleName).toBe("config_rules_findings");
    expect(huaweiCloudProvider.scanners().map((s) => s.moduleName)).toContain("config_rules_findings");
  });

  it("returns 0 findings and no warnings when the tracker is configured", async () => {
    showTrackerConfig.mockResolvedValueOnce(TRACKER_OK);

    const result = await scanner.scan(ctx);

    expect(result).toMatchObject({
      module: "config_rules_findings",
      status: "success",
      resourcesScanned: 0,
      findingsCount: 0,
      findings: [],
    });
    expect(result.warnings).toBeUndefined();
    expect(result.error).toBeUndefined();
    expect(typeof result.scanTimeMs).toBe("number");

    // Global RMS client built with the account domain ID; credential chain not consulted.
    expect(hwClientMock).toHaveBeenCalledTimes(1);
    const [clientClass, svc, passedCreds, scope] = hwClientMock.mock.calls[0];
    expect(clientClass).toBeDefined();
    expect(svc).toBe("rms");
    expect(passedCreds).toBe(creds);
    expect(scope).toEqual({ region: "cn-north-4", domainId: DOMAIN });
    expect(showTrackerConfig).toHaveBeenCalledWith({ domainId: DOMAIN });
    expect(loadHuaweiCredentialsMock).not.toHaveBeenCalled();
    expect(resolveRegionScopeMock).not.toHaveBeenCalled();
  });

  it("warns when the tracker is configured but frozen", async () => {
    showTrackerConfig.mockResolvedValueOnce({ ...TRACKER_OK, frozen_status: { is_frozen: true, frozen_scene: ["ARREAR"] } });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings![0]).toContain("frozen");
    expect(result.warnings![0]).toContain("ARREAR");
    expect(result.warnings![0]).toContain(rmsTrackerUrn(DOMAIN));
    expect(rmsTrackerUrn(DOMAIN)).toBe(`hws:global:${DOMAIN}:rms:tracker:default`);
  });

  it("reports recorder not enabled when the response carries no tracker config", async () => {
    showTrackerConfig.mockResolvedValueOnce({ httpStatusCode: 200 });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings).toEqual([RMS_TRACKER_NOT_ENABLED_WARNING]);
    expect(isTrackerConfigured(undefined)).toBe(false);
    expect(isTrackerConfigured({})).toBe(false);
    expect(isTrackerConfigured({ retentionPeriodInDays: 30 })).toBe(true);
  });

  it("reports recorder not enabled on 404 (RMS.xxxx not found) with status success", async () => {
    showTrackerConfig.mockRejectedValueOnce({
      httpStatusCode: 404,
      errorCode: "RMS.0002",
      errorMsg: "The tracker config does not exist.",
      requestId: "req-404",
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.error).toBeUndefined();
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings![0]).toContain(RMS_TRACKER_NOT_ENABLED_WARNING);
    expect(result.warnings![0]).toContain("RMS.0002");
    expect(result.warnings![0]).toContain("HTTP 404");
  });

  it("degrades gracefully on 403 IAM.0002 (success, access-denied warning, 0 findings)", async () => {
    showTrackerConfig.mockRejectedValueOnce({
      httpStatusCode: 403,
      errorCode: "IAM.0002",
      errorMsg: "You have no permission to perform this action.",
      requestId: "req-403",
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.error).toBeUndefined();
    expect(result.findingsCount).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings).toEqual([
      "RMS: insufficient permissions (HTTP 403 | IAM.0002 | You have no permission to perform this action. | requestId=req-403); skipped",
    ]);
  });

  it("never surfaces the signed Authorization header from a raw SDK error", async () => {
    // Raw ExceptionResponse shape thrown by DefaultHttpClient (carries the signed request config).
    showTrackerConfig.mockRejectedValueOnce({
      status: 401,
      data: { error_code: "APIGW.0301", error_msg: "Incorrect IAM authentication information: verify aksk signature fail" },
      message: "Request failed with status code 401",
      config: { url: `https://rms.myhuaweicloud.com/v1/resource-manager/domains/${DOMAIN}/tracker-config`, headers: { Authorization: FAKE_AUTH_HEADER } },
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success"); // 401 = access denied → graceful
    const serialized = JSON.stringify(result);
    expect(serialized).toContain("APIGW.0301");
    expect(serialized).not.toContain("Authorization");
    expect(serialized).not.toContain(FAKE_AK);
    expect(serialized).not.toContain(FAKE_SK);
  });

  it("returns status error (without credentials) on unexpected failures", async () => {
    showTrackerConfig.mockRejectedValueOnce({ httpStatusCode: 500, errorCode: "RMS.9999", errorMsg: "internal error" });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("error");
    expect(result.error).toBe("RMS tracker detection check failed: HTTP 500 | RMS.9999 | internal error");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeUndefined();
    expect(JSON.stringify(result)).not.toContain(FAKE_AK);

    showTrackerConfig.mockRejectedValueOnce(new Error("connect ETIMEDOUT 1.2.3.4:443"));
    const net = await scanner.scan(ctx);
    expect(net.status).toBe("error");
    expect(net.error).toContain("ETIMEDOUT");
  });

  it("falls back to the credential chain when the context carries no Huawei credentials", async () => {
    const chainCreds = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK, domainId: DOMAIN });
    loadHuaweiCredentialsMock.mockReturnValueOnce({ basic: chainCreds, global: chainCreds, source: "env" });
    showTrackerConfig.mockResolvedValueOnce(TRACKER_OK);

    const result = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: DOMAIN, provider: "huaweicloud" });

    expect(result.status).toBe("success");
    expect(loadHuaweiCredentialsMock).toHaveBeenCalledTimes(1);
    expect(hwClientMock.mock.calls[0][2]).toBe(chainCreds);
    expect(hwClientMock.mock.calls[0][3]).toEqual({ region: "cn-north-4", domainId: DOMAIN });
  });

  it("resolves the domain ID via IAM when neither context nor credentials carry it", async () => {
    const noDomain = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK });
    resolveRegionScopeMock.mockResolvedValueOnce({ region: "cn-north-4", projectId: "p-north4", domainId: DOMAIN });
    showTrackerConfig.mockResolvedValueOnce(TRACKER_OK);

    const result = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: "", credentials: noDomain });

    expect(result.status).toBe("success");
    expect(resolveRegionScopeMock).toHaveBeenCalledWith(noDomain, "cn-north-4");
    expect(hwClientMock.mock.calls[0][3]).toEqual({ region: "cn-north-4", domainId: DOMAIN });
  });

  it("returns status error when no credentials are configured anywhere", async () => {
    loadHuaweiCredentialsMock.mockImplementationOnce(() => { throw new HuaweiCredentialsNotFoundError("/nonexistent/credentials"); });

    const result = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: DOMAIN, provider: "huaweicloud" });

    expect(result.status).toBe("error");
    expect(result.error).toContain("Huawei Cloud credentials not found");
    expect(hwClientMock).not.toHaveBeenCalled();
  });
});
