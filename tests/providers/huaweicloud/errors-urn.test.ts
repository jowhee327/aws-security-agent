import { describe, it, expect } from "vitest";
import {
  classifyHwError,
  describeHwError,
  degradeHwError,
  isHwAccessDenied,
  isHwNotEnabled,
} from "../../../src/providers/huaweicloud/errors.js";
import { toResourceUrn, parseResourceUrn } from "../../../src/providers/huaweicloud/urn.js";

const FAKE_AUTH_HEADER = "SDK-HMAC-SHA256 Access=FAKEAK0123456789ABCD, SignedHeaders=host, Signature=deadbeef";

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
