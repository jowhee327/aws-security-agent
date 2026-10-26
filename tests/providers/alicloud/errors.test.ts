/**
 * Phase 2 T1 — Alibaba Cloud error classification + diagnostic redaction (plan §3.6).
 * Error objects mimic the openapi-core / ali-oss / Node shapes; fake keys only; no network.
 */
import { describe, it, expect } from "vitest";

import {
  AliCloudError,
  ALI_AUTH_FAILED_PREFIX,
  ALI_REDACTED,
  aliModuleErrorText,
  classifyAliError,
  degradeAliError,
  describeAliAuthFailure,
  describeAliError,
  extractAliError,
  isAliAccessDenied,
  isAliApiMisuse,
  isAliAuthFailure,
  isAliRetryable,
  redactAliDiagnostic,
  registerAliSecret,
  type AliErrorKind,
} from "../../../src/providers/alicloud/errors.js";

const FAKE_AK = "LTAI5tFAKEFAKEFAKE0000001";
const FAKE_SK = "FakeSecretKeyDoNotUseXXXXXXXXXXXX01";
const FAKE_STS_AK = "STS.NUFAKEFAKEFAKEFAKE00002";
const FAKE_TOKEN = "CAISFAKEFAKEFAKEFAKEtokenDoNotUse0003";

/** openapi-core ClientError-like object. */
function clientError(code: string, statusCode: number, message: string, extra: Record<string, unknown> = {}) {
  const err = new Error(`code: ${statusCode}, ${message} request id: REQ-1 Response: {"RequestId":"REQ-1","Code":"${code}"}`) as Error &
    Record<string, unknown>;
  err.name = "ClientError";
  Object.assign(err, {
    code,
    statusCode,
    requestId: "REQ-1",
    description: message,
    data: { Code: code, Message: message, RequestId: "REQ-1", HostId: "ecs.aliyuncs.com" },
    ...extra,
  });
  return err;
}

describe("classifyAliError", () => {
  const table: Array<[string, unknown, AliErrorKind]> = [
    // [P0] fake / revoked AK answers HTTP 404 — must be auth_failed, never not_found.
    ["RPC 404 InvalidAccessKeyId.NotFound", clientError("InvalidAccessKeyId.NotFound", 404, "Specified access key is not found."), "auth_failed"],
    ["FC 403 InvalidAccessKeyID (upper-case ID)", clientError("InvalidAccessKeyID", 403, "invalid access key id: LTAI5t…0001"), "auth_failed"],
    [
      "OSS 403 InvalidAccessKeyId",
      { name: "InvalidAccessKeyIdError", code: "InvalidAccessKeyId", status: 403, requestId: "OSS-REQ", message: "The OSS Access Key Id you provided does not exist in our records." },
      "auth_failed",
    ],
    ["SignatureDoesNotMatch", clientError("SignatureDoesNotMatch", 400, "Specified signature is not matched with our calculation."), "auth_failed"],
    ["InvalidSecurityToken.Expired", clientError("InvalidSecurityToken.Expired", 400, "Specified SecurityToken is expired."), "auth_failed"],
    ["Forbidden.AccessKeyDisabled", clientError("Forbidden.AccessKeyDisabled", 403, "The Access Key is disabled."), "auth_failed"],
    ["InvalidAction.NotFound", clientError("InvalidAction.NotFound", 404, "Specified api is not found, please check your url and method."), "api_misuse"],
    ["InvalidVersion", clientError("InvalidVersion", 400, "Specified parameter Version is not valid."), "api_misuse"],
    ["UnsupportedHTTPMethod", clientError("UnsupportedHTTPMethod", 400, "This http method is not supported."), "api_misuse"],
    ["MissingParameter", clientError("MissingParameter", 400, "The input parameter RegionId that is mandatory is missing."), "api_misuse"],
    ["InvalidParameter", clientError("InvalidParameter", 400, "The specified parameter is not valid."), "api_misuse"],
    ["Throttling.User", clientError("Throttling.User", 400, "Request was denied due to user flow control."), "throttled"],
    ["ServiceUnavailable 503", clientError("ServiceUnavailable", 503, "The request has failed due to a temporary failure of the server."), "throttled"],
    ["bare HTTP 429", { statusCode: 429, message: "Too Many Requests" }, "throttled"],
    ["ENOTFOUND", Object.assign(new Error("getaddrinfo ENOTFOUND ecs.cn-nowhere.aliyuncs.com"), { code: "ENOTFOUND" }), "network"],
    ["tea RequestTimeoutError", Object.assign(new Error("Socket timeout because of exceed 15000ms"), { name: "RequestTimeoutError" }), "network"],
    ["socket hang up (no status)", new Error("socket hang up"), "network"],
    ["Forbidden.KmsServiceNotEnabled", clientError("Forbidden.KmsServiceNotEnabled", 403, "The KMS service is not enabled."), "not_enabled"],
    ["not-enabled message", clientError("Forbidden", 403, "The service has not been opened for this account."), "not_enabled"],
    [
      "Forbidden.RAM with AccessDeniedDetail",
      clientError("Forbidden.RAM", 403, "User not authorized to operate on the specified resource.", {
        accessDeniedDetail: { AuthAction: "ecs:DescribeInstances", PolicyType: "AccountLevelIdentityBasedPolicy", AuthPrincipalOwnerId: "1234567890123456" },
      }),
      "access_denied",
    ],
    ["OSS AccessDenied", { name: "AccessDeniedError", code: "AccessDenied", status: 403, message: "You have no right to access this object." }, "access_denied"],
    ["NoPermission", clientError("NoPermission", 403, "You are not authorized to do this action."), "access_denied"],
    ["bare HTTP 403", { statusCode: 403, code: "SomethingElse", message: "nope" }, "access_denied"],
    ["InvalidInstanceId.NotFound", clientError("InvalidInstanceId.NotFound", 404, "The specified InstanceId does not exist."), "not_found"],
    ["OSS NoSuchBucket", { name: "NoSuchBucketError", code: "NoSuchBucket", status: 404, message: "The specified bucket does not exist." }, "not_found"],
    ["bare HTTP 404", { statusCode: 404, code: "Whatever", message: "gone" }, "not_found"],
    ["InternalError 500", clientError("InternalError", 500, "The request processing has failed due to some unknown error."), "other"],
    ["plain Error", new Error("something odd"), "other"],
    ["string", "weird", "other"],
    ["undefined", undefined, "other"],
  ];

  for (const [name, err, kind] of table) {
    it(`${name} → ${kind}`, () => {
      expect(classifyAliError(err).kind).toBe(kind);
    });
  }

  it("auth / misuse / denied helpers", () => {
    expect(isAliAuthFailure(clientError("InvalidAccessKeyId.NotFound", 404, "x"))).toBe(true);
    expect(isAliApiMisuse(clientError("UnsupportedHTTPMethod", 400, "x"))).toBe(true);
    expect(isAliAccessDenied(clientError("Forbidden.RAM", 403, "x"))).toBe(true);
    expect(isAliAuthFailure(clientError("Forbidden.RAM", 403, "x"))).toBe(false);
  });

  it("isAliRetryable: throttled / network / 5xx only (not 501, not auth)", () => {
    expect(isAliRetryable(classifyAliError(clientError("Throttling.User", 400, "x")))).toBe(true);
    expect(isAliRetryable(classifyAliError(Object.assign(new Error("x"), { code: "ECONNRESET" })))).toBe(true);
    expect(isAliRetryable(classifyAliError(clientError("InternalError", 500, "x")))).toBe(true);
    expect(isAliRetryable(classifyAliError({ statusCode: 501, message: "not implemented" }))).toBe(false);
    expect(isAliRetryable(classifyAliError(clientError("InvalidAccessKeyId.NotFound", 404, "x")))).toBe(false);
    expect(isAliRetryable(classifyAliError(clientError("Forbidden.RAM", 403, "x")))).toBe(false);
  });
});

describe("extractAliError / describeAliError", () => {
  it("prefers data.Code / data.Message and drops the Response dump", () => {
    const info = extractAliError(clientError("Forbidden.RAM", 403, "User not authorized to operate on the specified resource."));
    expect(info).toMatchObject({ status: 403, code: "Forbidden.RAM", message: "User not authorized to operate on the specified resource.", requestId: "REQ-1" });
  });

  it("keeps only AuthAction / PolicyType from AccessDeniedDetail", () => {
    const info = classifyAliError(
      clientError("Forbidden.RAM", 403, "denied", {
        accessDeniedDetail: { AuthAction: "ram:ListUsers", PolicyType: "ResourceGroupLevelIdentityBasedPolicy", EncodedDiagnosticMessage: "AQEAAAAA" },
      }),
    );
    expect(info.authAction).toBe("ram:ListUsers");
    expect(info.policyType).toBe("ResourceGroupLevelIdentityBasedPolicy");
    expect(JSON.stringify(info)).not.toContain("AQEAAAAA");
  });

  it("trims `Response: {…}` and multi-line messages", () => {
    const info = extractAliError(new Error('boom\nsecond line Response: {"AccessKeyId":"LTAI5tFAKEFAKEFAKE0000001"}'));
    expect(info.message).toBe("boom second line");
  });

  it("formats HTTP | code | message | requestId", () => {
    expect(describeAliError(clientError("InvalidAccessKeyId.NotFound", 404, "Specified access key is not found."))).toBe(
      "HTTP 404 | InvalidAccessKeyId.NotFound | Specified access key is not found. | requestId=REQ-1",
    );
  });

  it("ignores generic JS error names as codes", () => {
    expect(extractAliError(new TypeError("bad")).code).toBeUndefined();
  });

  it("never echoes the AK from a SignatureDoesNotMatch message", () => {
    const err = clientError(
      "SignatureDoesNotMatch",
      400,
      `Specified signature is not matched with our calculation. server string to sign is:POST&%2F&AccessKeyId%3D${FAKE_AK}%26Action%3DDescribeRegions`,
    );
    const text = describeAliError(err);
    expect(text).not.toContain(FAKE_AK);
    expect(text).toContain("SignatureDoesNotMatch");
  });
});

describe("AliCloudError / auth-failure text / degradation", () => {
  it("auth_failed message has the canonical prefix and no key material", () => {
    const raw = clientError("InvalidAccessKeyId.NotFound", 404, `Specified access key is not found: ${FAKE_AK}`);
    const err = new AliCloudError(classifyAliError(raw), "ecs:DescribeInstances");
    expect(err.kind).toBe("auth_failed");
    expect(err.message.startsWith(ALI_AUTH_FAILED_PREFIX)).toBe(true);
    expect(err.message).toContain("InvalidAccessKeyId.NotFound");
    expect(err.message).toContain("requestId=REQ-1");
    expect(err.cause).toBeUndefined();
    expect(JSON.stringify(err)).not.toContain(FAKE_AK);
    expect(describeAliAuthFailure(raw).startsWith(ALI_AUTH_FAILED_PREFIX)).toBe(true);
    expect(aliModuleErrorText(raw).startsWith(ALI_AUTH_FAILED_PREFIX)).toBe(true);
    expect(aliModuleErrorText(err).startsWith(ALI_AUTH_FAILED_PREFIX)).toBe(true);
  });

  it("non-auth message names the API; re-classification is stable", () => {
    const err = new AliCloudError(classifyAliError(clientError("Forbidden.RAM", 403, "denied")), "ram:ListUsers");
    expect(err.message).toBe("ram:ListUsers failed: HTTP 403 | Forbidden.RAM | denied | requestId=REQ-1");
    expect(classifyAliError(err).kind).toBe("access_denied");
    expect(extractAliError(err).code).toBe("Forbidden.RAM");
    expect(aliModuleErrorText(err)).toBe(err.message);
  });

  it("degradeAliError warns for access_denied (with missing permission) / not_enabled / not_found / throttled / network", () => {
    const denied = degradeAliError(
      "ECS",
      clientError("Forbidden.RAM", 403, "denied", { accessDeniedDetail: { AuthAction: "ecs:DescribeInstances", PolicyType: "AccountLevelIdentityBasedPolicy" } }),
    );
    expect(denied).toContain("ECS: insufficient permissions");
    expect(denied).toContain("missing permission ecs:DescribeInstances (AccountLevelIdentityBasedPolicy)");
    expect(degradeAliError("ECS", clientError("Forbidden.RAM", 403, "denied"))).not.toContain("missing permission");
    expect(degradeAliError("KMS", clientError("Forbidden.KmsServiceNotEnabled", 403, "x"))).toContain("not enabled");
    expect(degradeAliError("ECS", clientError("InvalidInstanceId.NotFound", 404, "x"))).toContain("not found");
    expect(degradeAliError("ECS", clientError("Throttling.User", 400, "x"))).toContain("throttled");
    expect(degradeAliError("ECS", Object.assign(new Error("x"), { code: "ETIMEDOUT" }))).toContain("network error");
  });

  it("degradeAliError never downgrades auth_failed / api_misuse / other", () => {
    expect(degradeAliError("ECS", clientError("InvalidAccessKeyId.NotFound", 404, "x"))).toBeUndefined();
    expect(degradeAliError("ECS", clientError("InvalidAction.NotFound", 404, "x"))).toBeUndefined();
    expect(degradeAliError("ECS", clientError("InternalError", 500, "x"))).toBeUndefined();
  });
});

describe("redactAliDiagnostic", () => {
  it("(a) registered literal secrets", () => {
    const literal = "RegisteredLiteralSecretValue0007x";
    registerAliSecret(literal);
    registerAliSecret("short"); // too short to register
    expect(redactAliDiagnostic(`value ${literal} here`)).toBe(`value ${ALI_REDACTED} here`);
    expect(redactAliDiagnostic("a short note")).toBe("a short note");
  });

  it("(b) LTAI access keys, including half-masked forms", () => {
    expect(redactAliDiagnostic(`AK ${FAKE_AK} used`)).toBe(`AK ${ALI_REDACTED} used`);
    for (const masked of ["LTAI5t…0001", "LTAI5t...0001", "LTAI****0001"]) {
      expect(redactAliDiagnostic(`key ${masked} invalid`)).toBe(`key ${ALI_REDACTED} invalid`);
    }
  });

  it("(c) STS access keys and CAIS security tokens", () => {
    expect(redactAliDiagnostic(`ak ${FAKE_STS_AK}`)).toBe(`ak ${ALI_REDACTED}`);
    expect(redactAliDiagnostic(`header ${FAKE_TOKEN}`)).toBe(`header ${ALI_REDACTED}`);
  });

  it("(d) RPC string-to-sign echo, signed query components (plain and URL-encoded)", () => {
    const sts = redactAliDiagnostic(
      `Specified signature is not matched with our calculation. server string to sign is:POST&%2F&AccessKeyId%3D${FAKE_AK}%26Action%3DDescribeRegions`,
    );
    expect(sts).toBe(`Specified signature is not matched with our calculation. server string to sign is: ${ALI_REDACTED}`);

    const url = redactAliDiagnostic(
      `https://ecs.aliyuncs.com/?AccessKeyId=${FAKE_AK}&Signature=abcDEF123sig&SignatureNonce=fake-nonce-1&SecurityToken=${FAKE_TOKEN}&Action=DescribeInstances`,
    );
    expect(url).not.toContain(FAKE_AK);
    expect(url).not.toContain("abcDEF123sig");
    expect(url).not.toContain("fake-nonce-1");
    expect(url).not.toContain(FAKE_TOKEN);
    expect(url).toContain("Action=DescribeInstances");

    const encoded = redactAliDiagnostic(`GET&%2F&AccessKeyId%3D${FAKE_AK}%26Action%3DListUsers`);
    expect(encoded).toContain(`AccessKeyId%3D${ALI_REDACTED}`);
    expect(encoded).toContain("Action%3DListUsers");

    const json = redactAliDiagnostic(`{"StringToSign":"POST\\n\\napplication/json\\n${FAKE_AK}"}`);
    expect(json).not.toContain(FAKE_AK);
    expect(json).toContain(`StringToSign=${ALI_REDACTED}`);
  });

  it("(e) OSS XML credential / signature elements", () => {
    const xml =
      `<Error><Code>SignatureDoesNotMatch</Code><OSSAccessKeyId>${FAKE_AK}</OSSAccessKeyId>` +
      "<StringToSign>PUT\n\nimage/png\nfake-date\n/bucket/key</StringToSign>" +
      "<SignatureProvided>fakeSigBase64=</SignatureProvided><StringToSignBytes>50 55 54</StringToSignBytes></Error>";
    const out = redactAliDiagnostic(xml);
    expect(out).toContain("<Code>SignatureDoesNotMatch</Code>");
    expect(out).toContain(`<OSSAccessKeyId>${ALI_REDACTED}</OSSAccessKeyId>`);
    expect(out).toContain(`<StringToSign>${ALI_REDACTED}</StringToSign>`);
    expect(out).toContain(`<SignatureProvided>${ALI_REDACTED}</SignatureProvided>`);
    expect(out).toContain(`<StringToSignBytes>${ALI_REDACTED}</StringToSignBytes>`);
    expect(out).not.toContain("fakeSigBase64");
  });

  it("(f) Authorization headers, V3 / OSS4 blobs and OSS V1 signatures", () => {
    expect(redactAliDiagnostic(`Authorization: ACS3-HMAC-SHA256 Credential=${FAKE_AK},SignedHeaders=host,Signature=abc`)).toBe(
      `Authorization=${ALI_REDACTED}`,
    );
    expect(redactAliDiagnostic(`sig ACS3-HMAC-SHA256 Credential=${FAKE_AK},Signature=abc`)).toBe(`sig ACS3-HMAC-SHA256 ${ALI_REDACTED}`);
    expect(redactAliDiagnostic(`sig OSS4-HMAC-SHA256 Credential=${FAKE_AK}/20261026/cn-hangzhou/oss/aliyun_v4_request`)).toBe(
      `sig OSS4-HMAC-SHA256 ${ALI_REDACTED}`,
    );
    expect(redactAliDiagnostic(`header OSS ${FAKE_AK}:fakeSignature123=`)).toBe(`header OSS ${ALI_REDACTED}`);
  });

  it("(g) generic credential key/value pairs and env-var names", () => {
    expect(redactAliDiagnostic(`accessKeySecret=${FAKE_SK}`)).toBe(`accessKeySecret=${ALI_REDACTED}`);
    expect(redactAliDiagnostic('{"access_key_secret":"abc123secretvalue"}')).not.toContain("abc123secretvalue");
    expect(redactAliDiagnostic("ALIBABA_CLOUD_ACCESS_KEY_SECRET=xyzFakeValue123")).not.toContain("xyzFakeValue123");
    expect(redactAliDiagnostic("ALICLOUD_SECRET_KEY: xyzFakeValue456")).not.toContain("xyzFakeValue456");
    expect(redactAliDiagnostic("securityToken: someOpaqueTokenValue")).not.toContain("someOpaqueTokenValue");
  });

  it("exact 30-char alnum token after 'secret' on the same line", () => {
    expect(redactAliDiagnostic("secret is abcdefghijABCDEFGHIJ0123456789")).toBe(`secret is ${ALI_REDACTED}`);
    // Not on a secret line → kept.
    expect(redactAliDiagnostic("id abcdefghijABCDEFGHIJ0123456789")).toBe("id abcdefghijABCDEFGHIJ0123456789");
  });

  it("is idempotent", () => {
    const text = [
      `AK ${FAKE_AK} / ${FAKE_STS_AK} / ${FAKE_TOKEN}`,
      `server string to sign is:GET&%2F&AccessKeyId%3D${FAKE_AK}`,
      `<OSSAccessKeyId>${FAKE_AK}</OSSAccessKeyId>`,
      `Authorization: OSS ${FAKE_AK}:sig=`,
      `sig ACS3-HMAC-SHA256 Credential=${FAKE_AK}`,
      `header OSS ${FAKE_AK}:fakeSignature123=`,
      `https://x/?AccessKeyId=${FAKE_AK}&Signature=s1`,
      `accessKeySecret=${FAKE_SK}`,
      "secret abcdefghijABCDEFGHIJ0123456789",
    ].join("\n");
    const once = redactAliDiagnostic(text);
    expect(redactAliDiagnostic(once)).toBe(once);
    for (const s of [FAKE_AK, FAKE_SK, FAKE_STS_AK, FAKE_TOKEN]) expect(once).not.toContain(s);
  });

  it("leaves AWS ARNs, acs: URNs, Huawei text and ordinary text untouched", () => {
    const samples = [
      "arn:aws:iam::123456789012:role/Admin",
      "acs:ram::1234567890123456:user/alice",
      "acs:ecs:cn-hangzhou:1234567890123456:instance/i-bp1abcdefghijklmn",
      "Huawei Cloud ECS.0114: The ECS does not exist (request_id=abc123)",
      "Security group sg-bp1abc allows 0.0.0.0/0 on port 22",
      "InvalidAccessKeyId.NotFound | Specified access key is not found.",
      "",
    ];
    for (const s of samples) expect(redactAliDiagnostic(s)).toBe(s);
  });
});

describe("redactAliDiagnostic — hostile server strings (FIX2)", () => {
  const HOSTILE_AK = "LTAI5tFAKE000000000000";

  it("AKs glued to `_` or a URL-encoded byte are redacted; alnum-glued text is left alone", () => {
    expect(redactAliDiagnostic(`APP_${HOSTILE_AK}`)).toBe(`APP_${ALI_REDACTED}`);
    expect(redactAliDiagnostic(`${HOSTILE_AK}_suffix`)).toBe(`${ALI_REDACTED}_suffix`);
    expect(redactAliDiagnostic(`a%2C${HOSTILE_AK}&b`)).toBe(`a%2C${ALI_REDACTED}&b`);
    expect(redactAliDiagnostic("xLTAIword")).toBe("xLTAIword");
  });

  it("prefixed credential env-var names (APP_ACCESS_KEY_SECRET=…) are redacted", () => {
    expect(redactAliDiagnostic("APP_ACCESS_KEY_SECRET=xyzFakeValue789")).toBe(`APP_ACCESS_KEY_SECRET=${ALI_REDACTED}`);
  });

  it("re-redacting a line keeps the context appended after an already-redacted marker", () => {
    const shown = redactAliDiagnostic(`bkt-server string to sign is:POST&%2F&AccessKeyId%3D${HOSTILE_AK}`);
    expect(shown).toBe(`bkt-server string to sign is: ${ALI_REDACTED}`);
    const line = `OSS bucket ${shown} (cn-hangzhou): ACL suppressed`;
    expect(redactAliDiagnostic(line)).toBe(line);
    expect(redactAliDiagnostic(`${redactAliDiagnostic("Authorization: OSS x:y")} tail`)).toBe(`Authorization=${ALI_REDACTED} tail`);
    expect(redactAliDiagnostic(`${redactAliDiagnostic("StringToSign: GET")} tail`)).toBe(`StringToSign=${ALI_REDACTED} tail`);
    // upper-cased marker (scanner upper-cased a redacted status) is still recognised
    expect(redactAliDiagnostic(`${shown.toUpperCase()}; tail`)).toBe(`${shown.toUpperCase()}; tail`);
  });
});
