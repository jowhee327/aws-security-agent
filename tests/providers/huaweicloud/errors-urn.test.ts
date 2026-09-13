import { describe, it, expect } from "vitest";
import {
  classifyHwError,
  describeHwError,
  degradeHwError,
  extractHwError,
  isHwAccessDenied,
  isHwNotEnabled,
  redactHwDiagnostic,
  registerHwSecret,
  HW_REDACTED,
} from "../../../src/providers/huaweicloud/errors.js";
import { createHuaweiCredentials } from "../../../src/providers/huaweicloud/credentials.js";
import { toResourceUrn, parseResourceUrn } from "../../../src/providers/huaweicloud/urn.js";

const FAKE_AK = "FAKEAK0123456789ABCD";
const FAKE_SK = "FAKESK0123456789abcdefghijklmnopqrstuvwx"; // 40 chars, like a real SK
const FAKE_TOKEN = "gQpjbi1ub3J0aC00FAKE_SECURITY_TOKEN_VALUE_0123456789";
const FAKE_AUTH_HEADER = `SDK-HMAC-SHA256 Access=${FAKE_AK}, SignedHeaders=host, Signature=deadbeef`;

describe("Huawei error classification", () => {
  it("classifies ServiceResponseException-style errors", () => {
    expect(classifyHwError({ httpStatusCode: 403, errorCode: "IAM.0002", errorMsg: "no permission" }).kind).toBe("access_denied");
    expect(classifyHwError({ httpStatusCode: 401, errorCode: "APIGW.0301", errorMsg: "Incorrect IAM authentication information" }).kind).toBe("access_denied");
    expect(classifyHwError({ httpStatusCode: 400, errorCode: "RMS.0403Forbidden", errorMsg: "x" }).kind).toBe("access_denied");
    expect(classifyHwError({ httpStatusCode: 400, errorCode: "HSS.NoPermission", errorMsg: "x" }).kind).toBe("access_denied");
    expect(classifyHwError({ httpStatusCode: 404, errorCode: "RMS.0001", errorMsg: "tracker not found" }).kind).toBe("not_found");
    expect(classifyHwError({ httpStatusCode: 405, errorMsg: "Method Not Allowed" }).kind).toBe("not_enabled");
    expect(classifyHwError({ httpStatusCode: 400, errorCode: "SecMaster.ServiceNotOpen", errorMsg: "x" }).kind).toBe("not_enabled");
    expect(classifyHwError({ httpStatusCode: 400, errorCode: "CTS.0001", errorMsg: "The service has not been enabled" }).kind).toBe("not_enabled");
    expect(classifyHwError({ httpStatusCode: 500, errorCode: "ECS.0001", errorMsg: "boom" }).kind).toBe("other");
  });

  it("classifies raw ExceptionResponse shapes (flat and nested error)", () => {
    const flat = { status: 403, data: { error_code: "APIGW.0303", error_msg: "no permission" }, message: "Request failed with status code 403" };
    expect(classifyHwError(flat)).toMatchObject({ kind: "access_denied", status: 403, code: "APIGW.0303", message: "no permission" });
    const nested = { status: "404", data: { error: { code: "OBS.NoSuchBucket", message: "gone" } }, requestId: "req-1" };
    expect(classifyHwError(nested)).toMatchObject({ kind: "not_found", status: 404, code: "OBS.NoSuchBucket", requestId: "req-1" });
    expect(classifyHwError(new Error("connect ECONNREFUSED 127.0.0.1:1"))).toMatchObject({ kind: "other", message: "connect ECONNREFUSED 127.0.0.1:1" });
    expect(classifyHwError("Forbidden")).toMatchObject({ kind: "access_denied", message: "Forbidden" });
    expect(classifyHwError(undefined)).toMatchObject({ kind: "other", message: "unknown error" });
    expect(classifyHwError(42)).toMatchObject({ kind: "other", message: "42" });
  });

  it("helpers and degradation text", () => {
    expect(isHwAccessDenied({ httpStatusCode: 403 })).toBe(true);
    expect(isHwNotEnabled({ httpStatusCode: 404 })).toBe(true);
    expect(isHwNotEnabled({ httpStatusCode: 405 })).toBe(true);
    expect(isHwNotEnabled({ httpStatusCode: 403 })).toBe(false);
    expect(degradeHwError("RMS", { httpStatusCode: 403, errorCode: "IAM.0002", errorMsg: "no permission", requestId: "r1" }))
      .toBe("RMS: insufficient permissions (HTTP 403 | IAM.0002 | no permission | requestId=r1); skipped");
    expect(degradeHwError("HSS", { httpStatusCode: 404, errorMsg: "not found" })).toMatch(/^HSS: service not enabled or not available/);
    expect(degradeHwError("ECS", { httpStatusCode: 500, errorMsg: "boom" })).toBeUndefined();
  });

  it("describeHwError never includes headers/config (Authorization) from raw SDK errors", () => {
    const raw = {
      status: 401,
      data: { error_code: "APIGW.0301", error_msg: "Incorrect IAM authentication information" },
      message: "Request failed with status code 401",
      headers: { "x-request-id": "abc" },
      config: { url: "https://iam.myhuaweicloud.com/v3/projects", headers: { Authorization: FAKE_AUTH_HEADER, "X-Sdk-Date": "now" } },
    };
    const text = describeHwError(raw);
    expect(text).toBe("HTTP 401 | APIGW.0301 | Incorrect IAM authentication information");
    expect(text).not.toContain("Authorization");
    expect(text).not.toContain("FAKEAK0123456789ABCD");
    expect(JSON.stringify(classifyHwError(raw))).not.toContain("FAKEAK0123456789ABCD");
  });
});

describe("redactHwDiagnostic", () => {
  it("strips Authorization header values in header, JSON and key=value forms", () => {
    expect(redactHwDiagnostic(`request failed; Authorization: ${FAKE_AUTH_HEADER}`)).toBe(`request failed; Authorization=${HW_REDACTED}`);
    expect(redactHwDiagnostic(`{"headers":{"Authorization":"${FAKE_AUTH_HEADER}","X-Sdk-Date":"now"}}`)).toBe(`{"headers":{"Authorization=${HW_REDACTED}`);
    const multi = redactHwDiagnostic(`line1 Authorization=${FAKE_AUTH_HEADER}\nline2 ok`);
    expect(multi).toBe(`line1 Authorization=${HW_REDACTED}\nline2 ok`);
  });

  it("redacts bare signature blobs and their components", () => {
    const out = redactHwDiagnostic(`sig ${FAKE_AUTH_HEADER} end`);
    expect(out).not.toContain(FAKE_AK);
    expect(out).not.toContain("deadbeef");
    expect(out).toBe(`sig SDK-HMAC-SHA256 ${HW_REDACTED}`);
    expect(redactHwDiagnostic(`Access=${FAKE_AK} SignedHeaders=host;x-sdk-date Signature=deadbeef`)).toBe(
      `Access=${HW_REDACTED} SignedHeaders=${HW_REDACTED} Signature=${HW_REDACTED}`,
    );
  });

  it("redacts credential-like key/value pairs (ak / sk / access_key / secret_key / X-Security-Token)", () => {
    expect(redactHwDiagnostic(`bad creds ak=${FAKE_AK} sk=${FAKE_SK}`)).toBe(`bad creds ak=${HW_REDACTED} sk=${HW_REDACTED}`);
    expect(redactHwDiagnostic(`access_key: ${FAKE_AK}, secret_key: "${FAKE_SK}"`)).toBe(`access_key=${HW_REDACTED}, secret_key=${HW_REDACTED}"`);
    expect(redactHwDiagnostic(`X-Security-Token: ${FAKE_TOKEN}; X-Auth-Token=tok123456789`)).toBe(`X-Security-Token=${HW_REDACTED}; X-Auth-Token=${HW_REDACTED}`);
    expect(redactHwDiagnostic(`{"accessKeyId":"${FAKE_AK}","secretAccessKey":"${FAKE_SK}"}`)).not.toContain(FAKE_SK);
    // ordinary words containing "sk"/"ak" are left alone
    expect(redactHwDiagnostic("task: risk=high, mask: on, weak=no")).toBe("task: risk=high, mask: on, weak=no");
  });

  it("redacts a 40-char token that follows sk/secret on the same line, but not elsewhere", () => {
    expect(redactHwDiagnostic(`the sk value ${FAKE_SK} was rejected`)).toBe(`the sk value ${HW_REDACTED} was rejected`);
    expect(redactHwDiagnostic(`secret rotated; old ${FAKE_SK}`)).not.toContain(FAKE_SK);
    // 40-char token without a trigger word on that line is preserved (e.g. an opaque resource id)
    expect(redactHwDiagnostic(`resource ${FAKE_SK} not found`)).toBe(`resource ${FAKE_SK} not found`);
    expect(redactHwDiagnostic(`secret here\nresource ${FAKE_SK} not found`)).toBe(`secret here\nresource ${FAKE_SK} not found`);
  });

  it("literally replaces secrets registered at runtime (credential objects register ak/sk/token)", () => {
    const ak = "REGISTEREDAK0000000001";
    const sk = "registered-sk-value-that-is-not-40-chars!";
    registerHwSecret(ak);
    registerHwSecret(sk);
    registerHwSecret("short"); // ignored: too short to be a secret, would redact ordinary text
    expect(redactHwDiagnostic(`proxy said ${ak} / ${sk} / short`)).toBe(`proxy said ${HW_REDACTED} / ${HW_REDACTED} / short`);

    const token = "TOKEN-from-createHuaweiCredentials-0123456789";
    createHuaweiCredentials({ ak: "CREATEDAK00000000001", sk: "createdsk-0123456789-abcdefghij", securityToken: token });
    const text = redactHwDiagnostic(`echo CREATEDAK00000000001 createdsk-0123456789-abcdefghij ${token}`);
    expect(text).toBe(`echo ${HW_REDACTED} ${HW_REDACTED} ${HW_REDACTED}`);
  });

  it("is idempotent (text may pass through extractHwError, describeHwError and the runner/MCP layer)", () => {
    const samples = [
      `Authorization: ${FAKE_AUTH_HEADER}`,
      `Access=${FAKE_AK} SignedHeaders=host;x-sdk-date Signature=deadbeef`,
      `ak=${FAKE_AK}; sk=${FAKE_SK}; "X-Security-Token": "${FAKE_TOKEN}"`,
      `sk ${FAKE_SK}`,
      "HTTP 403 | IAM.0002 | no permission | requestId=r1",
    ];
    for (const s of samples) {
      const once = redactHwDiagnostic(s);
      expect(redactHwDiagnostic(once)).toBe(once);
      expect(redactHwDiagnostic(redactHwDiagnostic(once))).toBe(once);
    }
  });

  it("is safe on empty / non-string input and leaves ordinary diagnostics untouched", () => {
    expect(redactHwDiagnostic("")).toBe("");
    expect(redactHwDiagnostic(undefined as unknown as string)).toBe("undefined");
    expect(redactHwDiagnostic("HTTP 403 | IAM.0002 | no permission | requestId=r1")).toBe("HTTP 403 | IAM.0002 | no permission | requestId=r1");
    expect(redactHwDiagnostic("connect ECONNREFUSED 127.0.0.1:443")).toBe("connect ECONNREFUSED 127.0.0.1:443");
  });

  it("describeHwError / extractHwError / classifyHwError redact messages that echo the signed request or the keys", () => {
    createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK });
    const echoed = {
      httpStatusCode: 401,
      errorCode: "APIGW.0301",
      errorMsg: `Incorrect IAM authentication information: Authorization: ${FAKE_AUTH_HEADER} (ak=${FAKE_AK}, sk=${FAKE_SK})`,
      requestId: "r-echo",
    };
    const text = describeHwError(echoed);
    expect(text).toBe(`HTTP 401 | APIGW.0301 | Incorrect IAM authentication information: Authorization=${HW_REDACTED} | requestId=r-echo`);
    expect(text).not.toContain(FAKE_AK);
    expect(text).not.toContain(FAKE_SK);
    expect(text).not.toContain("SDK-HMAC");

    const raw = { status: 400, data: { error: { code: "X", message: `proxy rejected ${FAKE_AK}:${FAKE_SK}` } } };
    expect(extractHwError(raw).message).toBe(`proxy rejected ${HW_REDACTED}:${HW_REDACTED}`);
    expect(JSON.stringify(classifyHwError(raw))).not.toContain(FAKE_AK);
    expect(describeHwError(new Error(`ECONNRESET while sending Authorization: ${FAKE_AUTH_HEADER}`))).toBe(`ECONNRESET while sending Authorization=${HW_REDACTED}`);
    expect(describeHwError(`string error with sk=${FAKE_SK}`)).toBe(`string error with sk=${HW_REDACTED}`);
    // classification still works on the redacted message
    expect(classifyHwError({ status: 400, message: `Forbidden for ak=${FAKE_AK}` }).kind).toBe("access_denied");
  });
});

describe("Huawei URN", () => {
  it("formats hws:<region>:<domainId>:<svc>:<type>:<id>", () => {
    expect(toResourceUrn("ecs", "server", "abc-123", "cn-north-4", "d0m41n")).toBe("hws:cn-north-4:d0m41n:ecs:server:abc-123");
    expect(toResourceUrn("obs", "bucket", "my-bucket", "cn-east-3", "d0m41n")).toBe("hws:cn-east-3:d0m41n:obs:bucket:my-bucket");
  });

  it("coerces an empty/undefined region to the logical 'global' region (never hws::...)", () => {
    expect(toResourceUrn("iam", "user", "u1", "", "d0m41n")).toBe("hws:global:d0m41n:iam:user:u1");
    expect(toResourceUrn("iam", "user", "u1", undefined, "d0m41n")).toBe("hws:global:d0m41n:iam:user:u1");
    expect(toResourceUrn("iam", "user", "u1", "   ", "d0m41n")).toBe("hws:global:d0m41n:iam:user:u1");
    expect(toResourceUrn("rms", "tracker", "default", "global", "d0m41n")).toBe("hws:global:d0m41n:rms:tracker:default");
    expect(parseResourceUrn(toResourceUrn("iam", "user", "u1", "", "d0m41n"))?.region).toBe("global");
  });

  it("parses its own output (ids may contain colons)", () => {
    expect(parseResourceUrn("hws:cn-north-4:d0m41n:ecs:server:abc-123")).toEqual({
      region: "cn-north-4", domainId: "d0m41n", svc: "ecs", type: "server", id: "abc-123",
    });
    expect(parseResourceUrn("hws:cn-north-4:d:iam:agency:a:b")?.id).toBe("a:b");
    expect(parseResourceUrn("arn:aws:s3:::bucket")).toBeUndefined();
    expect(parseResourceUrn("hws:short")).toBeUndefined();
  });
});
