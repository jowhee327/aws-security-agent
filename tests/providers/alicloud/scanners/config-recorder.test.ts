/**
 * Phase 2 T2 — AliConfigRecorderScanner (config_rules_findings): GetConfigurationRecorder
 * status → warning / no warning, site pass-through, degradation and fatal errors.
 * aliCall is mocked by spec.action; fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall };
});

import {
  AliConfigRecorderScanner,
  ALI_CONFIG_RECORDER_NOT_ENABLED_WARNING,
  aliConfigRecorderUrn,
  configEndpointNote,
  configRecorderStatus,
} from "../../../../src/providers/alicloud/scanners/config-recorder.js";
import {
  aliCtx,
  authError,
  callsFor,
  deniedError,
  FAKE_AK,
  FAKE_SK,
  isolateAliEnv,
  misuseError,
  notEnabledError,
  restoreAliEnv,
  routeAliCall,
  throttledError,
  UID,
} from "./helpers.js";

const ACTION = "GetConfigurationRecorder";

beforeEach(() => {
  isolateAliEnv();
  mocks.aliCall.mockReset();
});
afterEach(() => restoreAliEnv());

const recorder = (status: string | undefined, resourceTypes: string[] = ["ACS::ECS::Instance"]) => ({
  ConfigurationRecorder: { ...(status ? { ConfigurationRecorderStatus: status } : {}), ResourceTypes: resourceTypes },
});

describe("helpers", () => {
  it("reads the recorder status (upper-cased) and builds the recorder URN", () => {
    expect(configRecorderStatus(recorder("registered"))).toBe("REGISTERED");
    expect(configRecorderStatus({})).toBeUndefined();
    expect(aliConfigRecorderUrn(UID)).toBe(`acs:config::${UID}:recorder/default`);
    expect(configEndpointNote("cn")).toContain("config.cn-shanghai.aliyuncs.com");
    expect(configEndpointNote("intl")).toContain("config.ap-southeast-1.aliyuncs.com");
  });
});

describe("AliConfigRecorderScanner", () => {
  const scanner = new AliConfigRecorderScanner();

  it("has the shared moduleName", () => {
    expect(scanner.moduleName).toBe("config_rules_findings");
  });

  it("REGISTERED recorder → success, 0 findings, no warning (normal hit)", async () => {
    routeAliCall(mocks.aliCall, { [ACTION]: recorder("REGISTERED") });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.findingsCount).toBe(0);
    expect(r.warnings).toBeUndefined();
    const [spec, ctx] = callsFor(mocks.aliCall, ACTION)[0];
    expect(spec).toMatchObject({ service: "config", action: ACTION });
    expect(ctx).toMatchObject({ site: "cn", credentials: { accessKeyId: FAKE_AK } });
  });

  it("REGISTERED but no resource types → warning", async () => {
    routeAliCall(mocks.aliCall, { [ACTION]: recorder("REGISTERED", []) });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings?.[0]).toContain("monitors no resource types");
  });

  it.each(["UNREGISTERED", "REGISTRABLE", "BUILDING"])("status %s → not-enabled warning (no hit)", async (status) => {
    routeAliCall(mocks.aliCall, { [ACTION]: recorder(status) });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings?.[0]).toContain(ALI_CONFIG_RECORDER_NOT_ENABLED_WARNING);
    expect(r.warnings?.[0]).toContain(`ConfigurationRecorderStatus=${status}`);
    expect(r.warnings?.[0]).toContain("config.cn-shanghai.aliyuncs.com");
  });

  it("missing recorder object → not-enabled warning (status absent)", async () => {
    routeAliCall(mocks.aliCall, { [ACTION]: {} });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings?.[0]).toContain("ConfigurationRecorderStatus=absent");
  });

  it("passes the intl site through (ALIBABA_CLOUD_SITE=intl)", async () => {
    process.env.ALIBABA_CLOUD_SITE = "intl";
    routeAliCall(mocks.aliCall, { [ACTION]: recorder("UNREGISTERED") });
    const r = await scanner.scan(aliCtx());
    expect(callsFor(mocks.aliCall, ACTION)[0][1]).toMatchObject({ site: "intl" });
    expect(r.warnings?.[0]).toContain("config.ap-southeast-1.aliyuncs.com");
    expect(r.warnings?.[0]).toContain("site intl");
  });

  it("not_enabled error → not-enabled warning, success", async () => {
    routeAliCall(mocks.aliCall, { [ACTION]: () => { throw notEnabledError(); } });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings?.[0]).toContain(ALI_CONFIG_RECORDER_NOT_ENABLED_WARNING);
  });

  it("access_denied → degraded warning, success", async () => {
    routeAliCall(mocks.aliCall, { [ACTION]: () => { throw deniedError(); } });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.error).toBeUndefined();
    expect(r.warnings?.[0]).toMatch(/^Config: insufficient permissions/);
  });

  it("throttled → degraded warning, success", async () => {
    routeAliCall(mocks.aliCall, { [ACTION]: () => { throw throttledError(); } });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings?.[0]).toContain("throttled");
  });

  it("auth_failed (404 InvalidAccessKeyId.NotFound) → status error, never 'not enabled'", async () => {
    routeAliCall(mocks.aliCall, { [ACTION]: () => { throw authError(); } });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
    expect(r.error).toContain("InvalidAccessKeyId.NotFound");
    expect(r.warnings).toBeUndefined();
    expect(JSON.stringify(r)).not.toContain(FAKE_SK);
  });

  it("raw SDK-shaped auth error (code compared case-insensitively) → status error", async () => {
    routeAliCall(mocks.aliCall, {
      [ACTION]: () => {
        throw Object.assign(new Error("Specified access key is not found."), { code: "invalidaccesskeyid.notfound", statusCode: 404 });
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
  });

  it("api_misuse → status error", async () => {
    routeAliCall(mocks.aliCall, { [ACTION]: () => { throw misuseError(); } });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toContain("Config recorder detection check failed");
    expect(r.error).toContain("MissingParameter");
  });

  it("no credentials anywhere → status error (no call)", async () => {
    const r = await scanner.scan(aliCtx({ credentials: undefined }));
    expect(r.status).toBe("error");
    expect(mocks.aliCall).not.toHaveBeenCalled();
  });
});
