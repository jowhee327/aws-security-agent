/**
 * Phase 2 (Azure) T1 — error classification + diagnostic redaction (plan §3.5).
 * Fake values only; no network. The RestError is the real `@azure/core-rest-pipeline`
 * class (constructed in memory) so its non-enumerable request / response headers are
 * exercised exactly as the SDK would produce them.
 */
import { describe, it, expect } from "vitest";
import { RestError, createHttpHeaders, createPipelineRequest } from "@azure/core-rest-pipeline";

import {
  AZURE_AUTH_FAILED_PREFIX,
  AZURE_REDACTED,
  AzureCloudError,
  aztUntrusted,
  aztUntrustedOpt,
  azureModuleErrorText,
  classifyAzureError,
  degradeAzureError,
  describeAzureAuthFailure,
  describeAzureError,
  isAzureAccessDenied,
  isAzureApiMisuse,
  isAzureAuthFailure,
  isAzureRetryable,
  redactAzureDiagnostic,
  registerAzureSecret,
  toAzureError,
  type AzureErrorKind,
} from "../../../src/providers/azure/errors.js";

const FAKE_TENANT = "00000000-0000-0000-0000-00000000fake";
const FAKE_CLIENT = "11111111-1111-1111-1111-11111111fake";
const FAKE_SECRET = "FakeAzureClientSecretValue~DoNotUse-0000000000";
const FAKE_SUB = "22222222-2222-2222-2222-22222222fake";
// Fake JWT-shaped bearer token (header.payload.signature) — not a real token.
const FAKE_JWT =
  "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY2hpbmFjbG91ZGFwaS5jbiIsImZha2UiOnRydWV9.RmFrZVNpZ25hdHVyZURvTm90VXNlMDAwMDAwMDAwMA";
const FAKE_STORAGE_KEY = "RmFrZVN0b3JhZ2VLZXlEb05vdFVzZQ" + "A".repeat(56) + "==";
const FAKE_SAS_KEY = "RmFrZVNoYXJlZEFjY2Vzc0tleURvTm90VXNlMDAwMDA=";

function identityError(name: string, aadsts: string, description: string, statusCode = 400): Error {
  const err = new Error(
    `ClientSecretCredential authentication failed: ${aadsts}: ${description} Trace ID: 0000 Correlation ID: 1111 Timestamp: 2026-10-26 00:00:00Z`,
  );
  err.name = name;
  Object.assign(err, {
    statusCode,
    errorResponse: { error: "invalid_client", errorDescription: `${aadsts}: ${description}`, errorCodes: [Number(aadsts.slice(6))] },
  });
  return err;
}

function armError(statusCode: number, code: string, message: string): Error {
  const err = new Error(message);
  err.name = "RestError";
  Object.assign(err, { statusCode, code, details: { error: { code, message } } });
  return err;
}

/** RestError exactly as core-client produces it: Bearer token in the request headers. */
function restErrorWithBearer(statusCode: number, code: string, message: string): RestError {
  const request = createPipelineRequest({
    url: `https://management.chinacloudapi.cn/subscriptions/${FAKE_SUB}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01`,
    method: "GET",
    headers: createHttpHeaders({ Authorization: `Bearer ${FAKE_JWT}`, "x-ms-client-request-id": "client-req-1" }),
  });
  const err = new RestError(message, {
    code,
    statusCode,
    request,
    response: {
      request,
      status: statusCode,
      headers: createHttpHeaders({
        "x-ms-request-id": "req-0001",
        "www-authenticate": `Bearer authorization_uri="https://login.chinacloudapi.cn/${FAKE_TENANT}"`,
      }),
      bodyAsText: JSON.stringify({ error: { code, message }, echoedAuthorization: `Bearer ${FAKE_JWT}` }),
    },
  });
  err.details = { error: { code, message } };
  return err;
}

describe("classifyAzureError — plan §3.5 table", () => {
  const cases: Array<[string, unknown, AzureErrorKind]> = [
    ["AADSTS7000215 (invalid secret)", identityError("AuthenticationError", "AADSTS7000215", "Invalid client secret provided."), "auth_failed"],
    ["AADSTS700016 (app not found)", identityError("AuthenticationError", "AADSTS700016", "Application not found in the directory."), "auth_failed"],
    ["AADSTS900023 (tenant not found)", identityError("AuthenticationError", "AADSTS900023", "Specified tenant identifier is neither a valid DNS name nor a valid external domain."), "auth_failed"],
    ["AADSTS90002 (tenant)", identityError("AuthenticationError", "AADSTS90002", "Tenant not found."), "auth_failed"],
    ["AADSTS70001 (app disabled)", identityError("AuthenticationError", "AADSTS70001", "Application is disabled."), "auth_failed"],
    ["CredentialUnavailableError", Object.assign(new Error("ClientSecretCredential: unavailable"), { name: "CredentialUnavailableError" }), "auth_failed"],
    ["AggregateAuthenticationError", Object.assign(new Error("chain failed"), { name: "AggregateAuthenticationError" }), "auth_failed"],
    ["ARM 401 InvalidAuthenticationToken", armError(401, "InvalidAuthenticationToken", "The access token is invalid."), "auth_failed"],
    ["ARM 401 InvalidAuthenticationTokenAudience", armError(401, "InvalidAuthenticationTokenAudience", "wrong audience"), "auth_failed"],
    ["ARM 403 AuthorizationFailed", armError(403, "AuthorizationFailed", "The client does not have authorization to perform action."), "access_denied"],
    ["ARM 403 LinkedAuthorizationFailed", armError(403, "LinkedAuthorizationFailed", "linked"), "access_denied"],
    ["Graph 403 Authorization_RequestDenied", { statusCode: 403, code: "Authorization_RequestDenied", message: "Insufficient privileges to complete the operation.", requestId: "g-1" }, "access_denied"],
    ["409 MissingSubscriptionRegistration", armError(409, "MissingSubscriptionRegistration", "The subscription is not registered to use namespace 'Microsoft.Security'."), "not_enabled"],
    ["404 SubscriptionNotRegistered", armError(404, "SubscriptionNotRegistered", "Subscription not registered"), "not_enabled"],
    ["RP not registered (message only)", armError(400, "BadRequest", "The resource provider 'Microsoft.PolicyInsights' is not registered for this subscription."), "not_enabled"],
    ["404 ResourceNotFound", armError(404, "ResourceNotFound", "The Resource was not found."), "not_found"],
    ["404 ResourceGroupNotFound", armError(404, "ResourceGroupNotFound", "Resource group could not be found."), "not_found"],
    ["Graph 404 Request_ResourceNotFound", { statusCode: 404, code: "Request_ResourceNotFound", message: "not found" }, "not_found"],
    ["429 TooManyRequests", armError(429, "TooManyRequests", "Too many requests"), "throttled"],
    ["429 SubscriptionRequestsThrottled", armError(429, "SubscriptionRequestsThrottled", "throttled"), "throttled"],
    ["400 InvalidApiVersion", armError(400, "InvalidApiVersionParameter", "The api-version '1999-01-01' is invalid."), "api_misuse"],
    ["400 NoRegisteredProviderFound", armError(400, "NoRegisteredProviderFound", "No registered resource provider found"), "api_misuse"],
    ["400 InvalidResourceType", armError(400, "InvalidResourceType", "bad type"), "api_misuse"],
    ["400 MissingApiVersionParameter", armError(400, "MissingApiVersionParameter", "missing"), "api_misuse"],
    ["ENOTFOUND", Object.assign(new Error("getaddrinfo ENOTFOUND management.chinacloudapi.cn"), { code: "ENOTFOUND" }), "network"],
    ["ECONNRESET", Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }), "network"],
    ["AbortError", Object.assign(new Error("The operation was aborted."), { name: "AbortError" }), "network"],
    ["RestError without status", Object.assign(new Error("request failed"), { name: "RestError", code: "REQUEST_SEND_ERROR" }), "network"],
    ["500 InternalServerError", armError(500, "InternalServerError", "boom"), "other"],
    ["plain string", "something odd", "other"],
    ["undefined", undefined, "other"],
  ];

  it.each(cases)("%s", (_label, err, kind) => {
    expect(classifyAzureError(err).kind).toBe(kind);
  });

  it("extracts the AADSTS code from identity errors", () => {
    const info = classifyAzureError(identityError("AuthenticationError", "AADSTS7000215", "Invalid client secret provided."));
    expect(info.aadsts).toBe("AADSTS7000215");
    expect(info.code).toBe("invalid_client");
    expect(info.message).not.toContain("Trace ID");
  });

  it("uses errorCodes when the message carries no AADSTS text", () => {
    const err = Object.assign(new Error("failed"), { name: "AuthenticationError", errorResponse: { errorCodes: [700016] } });
    expect(classifyAzureError(err).aadsts).toBe("AADSTS700016");
  });

  it("helpers agree with the classification", () => {
    expect(isAzureAuthFailure(identityError("AuthenticationError", "AADSTS900023", "x"))).toBe(true);
    expect(isAzureAuthFailure(armError(403, "AuthorizationFailed", "x"))).toBe(false);
    expect(isAzureAccessDenied(armError(403, "AuthorizationFailed", "x"))).toBe(true);
    expect(isAzureApiMisuse(armError(400, "InvalidApiVersion", "x"))).toBe(true);
    expect(isAzureRetryable(classifyAzureError(armError(429, "TooManyRequests", "x")))).toBe(true);
    expect(isAzureRetryable(classifyAzureError(armError(503, "ServiceUnavailable", "x")))).toBe(true);
    expect(isAzureRetryable(classifyAzureError(armError(403, "AuthorizationFailed", "x")))).toBe(false);
  });

  it("never throws on hostile error objects (throwing getters)", () => {
    const hostile = {
      get name() {
        throw new Error("boom");
      },
      get message() {
        throw new Error("boom");
      },
      statusCode: 403,
    };
    expect(() => classifyAzureError(hostile)).not.toThrow();
    expect(classifyAzureError(hostile).kind).toBe("access_denied");
  });
});

describe("describeAzureError — never leaks the Bearer token held by a RestError", () => {
  it("reads only status | code | details.code | message | x-ms-request-id", () => {
    const err = restErrorWithBearer(403, "AuthorizationFailed", "The client does not have authorization to perform action 'Microsoft.Storage/storageAccounts/read'.");
    // Precondition: the token really is reachable on the error object.
    expect(err.request?.headers.get("authorization")).toContain(FAKE_JWT);

    const out = describeAzureError(err);
    expect(out).toBe(
      "HTTP 403 | AuthorizationFailed | The client does not have authorization to perform action 'Microsoft.Storage/storageAccounts/read'. | requestId=req-0001",
    );
    expect(out).not.toContain(FAKE_JWT);
    expect(out).not.toContain("Bearer");
    expect(out).not.toContain("client-req-1");
  });

  it("redacts a token echoed inside the message, and every derived output stays clean", () => {
    const err = restErrorWithBearer(401, "InvalidAuthenticationToken", `Token rejected. Authorization: Bearer ${FAKE_JWT}`);
    const outputs = [
      describeAzureError(err),
      JSON.stringify(classifyAzureError(err)),
      toAzureError(err, "storageAccounts.list").message,
      JSON.stringify(toAzureError(err, "storageAccounts.list")),
      String(toAzureError(err)),
      azureModuleErrorText(err),
      describeAzureAuthFailure(err),
      degradeAzureError("Storage", restErrorWithBearer(403, "AuthorizationFailed", `denied Bearer ${FAKE_JWT}`)) ?? "",
    ];
    for (const o of outputs) {
      expect(o).not.toContain(FAKE_JWT);
      expect(o).not.toContain(FAKE_JWT.slice(0, 40));
    }
  });

  it("the wrapper keeps no reference to the raw error (no cause / request / response)", () => {
    const wrapped = toAzureError(restErrorWithBearer(403, "AuthorizationFailed", "denied"));
    expect(wrapped).toBeInstanceOf(AzureCloudError);
    expect((wrapped as unknown as { cause?: unknown }).cause).toBeUndefined();
    expect((wrapped as unknown as { request?: unknown }).request).toBeUndefined();
    expect((wrapped as unknown as { response?: unknown }).response).toBeUndefined();
    expect(wrapped.kind).toBe("access_denied");
    expect(toAzureError(wrapped)).toBe(wrapped);
    expect(classifyAzureError(wrapped).kind).toBe("access_denied");
  });

  it("includes details.code when it differs from the top-level code", () => {
    const err = armError(400, "BadRequest", "bad");
    (err as unknown as { details: unknown }).details = { error: { code: "InvalidApiVersionParameter", message: "bad version" } };
    expect(describeAzureError(err)).toBe("HTTP 400 | BadRequest | InvalidApiVersionParameter | bad version");
    expect(classifyAzureError(err).kind).toBe("api_misuse");
  });

  it("auth failures get the canonical prefix with the AADSTS code", () => {
    const err = identityError("AuthenticationError", "AADSTS7000215", "Invalid client secret provided.");
    expect(azureModuleErrorText(err)).toMatch(new RegExp(`^${AZURE_AUTH_FAILED_PREFIX} \\(AADSTS7000215\\)`));
    const wrapped = toAzureError(err, "subscriptions.list");
    expect(wrapped.message.startsWith(`${AZURE_AUTH_FAILED_PREFIX} (AADSTS7000215)`)).toBe(true);
    expect(wrapped.aadsts).toBe("AADSTS7000215");
  });

  it("degradeAzureError: warnings for degradable kinds, undefined for auth / api misuse / other", () => {
    expect(degradeAzureError("Defender", armError(403, "AuthorizationFailed", "denied"))).toBe(
      "Defender: insufficient permissions (HTTP 403 | AuthorizationFailed | denied); skipped",
    );
    expect(degradeAzureError("Defender", armError(409, "MissingSubscriptionRegistration", "not registered"))).toMatch(
      /^Defender: not enabled \/ resource provider not registered/,
    );
    expect(degradeAzureError("x", armError(404, "ResourceNotFound", "gone"))).toMatch(/resource not found/);
    expect(degradeAzureError("x", armError(429, "TooManyRequests", "slow down"))).toMatch(/throttled/);
    expect(degradeAzureError("x", Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }))).toMatch(/network error/);
    expect(degradeAzureError("x", identityError("AuthenticationError", "AADSTS7000215", "bad"))).toBeUndefined();
    expect(degradeAzureError("x", armError(400, "InvalidApiVersion", "bad"))).toBeUndefined();
    expect(degradeAzureError("x", armError(500, "InternalServerError", "boom"))).toBeUndefined();
  });
});

describe("redactAzureDiagnostic — plan §3.5 (a)–(f)", () => {
  it("(a) registered client secret literals (plain and URL-encoded)", () => {
    registerAzureSecret(FAKE_SECRET);
    const out = redactAzureDiagnostic(`secret was ${FAKE_SECRET} / ${encodeURIComponent(FAKE_SECRET)}`);
    expect(out).toBe(`secret was ${AZURE_REDACTED} / ${AZURE_REDACTED}`);
    // Short strings are never registered (would mangle ordinary text).
    registerAzureSecret("abc");
    expect(redactAzureDiagnostic("abc def")).toBe("abc def");
  });

  it("(b) Bearer tokens and bare JWTs", () => {
    expect(redactAzureDiagnostic(`got Bearer ${FAKE_JWT} back`)).toBe(`got Bearer ${AZURE_REDACTED} back`);
    expect(redactAzureDiagnostic(`token ${FAKE_JWT}`)).toBe(`token ${AZURE_REDACTED}`);
    expect(redactAzureDiagnostic(`bearer opaqueTokenValue123`)).toBe(`Bearer ${AZURE_REDACTED}`);
  });

  it("(c) Authorization / Cookie headers (header and JSON form)", () => {
    expect(redactAzureDiagnostic(`Authorization: Bearer ${FAKE_JWT}`)).toBe(`Authorization: ${AZURE_REDACTED}`);
    const json = redactAzureDiagnostic(`{"authorization":"Bearer ${FAKE_JWT}","x":"y"}`);
    expect(json).not.toContain(FAKE_JWT);
    expect(json).toContain(AZURE_REDACTED);
    expect(redactAzureDiagnostic("Cookie: fpc=AbCdEf; x-ms-gateway-slice=estsfd")).toBe(`Cookie: ${AZURE_REDACTED}`);
    expect(redactAzureDiagnostic("line1\nAuthorization=SharedKey acct:sig\nline3")).toBe(`line1\nAuthorization=${AZURE_REDACTED}\nline3`);
  });

  it("(d) credential key=value pairs, case-insensitive", () => {
    const samples: Array<[string, string]> = [
      ["client_secret=s3cr3tValue", `client_secret=${AZURE_REDACTED}`],
      ['"clientSecret":"s3cr3tValue"', `"clientSecret":"${AZURE_REDACTED}"`],
      ["AZURE_CLIENT_SECRET=s3cr3tValue", `AZURE_CLIENT_SECRET=${AZURE_REDACTED}`],
      ["MY_APP_CLIENT_SECRET: s3cr3tValue", `MY_APP_CLIENT_SECRET: ${AZURE_REDACTED}`],
      ["client_assertion=abc.def.ghi", `client_assertion=${AZURE_REDACTED}`],
      ["assertion=abc.def.ghi", `assertion=${AZURE_REDACTED}`],
      ["Password=hunter2hunter2", `Password=${AZURE_REDACTED}`],
      ["refresh_token: 0.ARoAv4j5cvGGr0", `refresh_token: ${AZURE_REDACTED}`],
      ["AccountKey=abcdef;EndpointSuffix=core.chinacloudapi.cn", `AccountKey=${AZURE_REDACTED};EndpointSuffix=core.chinacloudapi.cn`],
    ];
    for (const [input, expected] of samples) expect(redactAzureDiagnostic(input)).toBe(expected);
  });

  it("(e) secret query / form parameters", () => {
    expect(redactAzureDiagnostic("https://app.example/cb?code=0.AXEAv4j5cv&state=xyz")).toBe(
      `https://app.example/cb?code=${AZURE_REDACTED}&state=xyz`,
    );
    expect(redactAzureDiagnostic("grant_type=client_credentials&client_secret=abc~def&scope=x")).toBe(
      `grant_type=client_credentials&client_secret=${AZURE_REDACTED}&scope=x`,
    );
  });

  it("(f) SAS sig / sv and storage / shared access keys", () => {
    const sas = redactAzureDiagnostic(
      "https://sa1.blob.core.chinacloudapi.cn/c/b?sv=2022-11-02&ss=b&sp=r&se=2026-12-01&sig=AbCdEf%2BgHi%3D",
    );
    expect(sas).toBe(
      `https://sa1.blob.core.chinacloudapi.cn/c/b?sv=${AZURE_REDACTED}&ss=b&sp=r&se=2026-12-01&sig=${AZURE_REDACTED}`,
    );
    expect(redactAzureDiagnostic(`key1 ${FAKE_STORAGE_KEY} end`)).toBe(`key1 ${AZURE_REDACTED} end`);
    expect(redactAzureDiagnostic(`sas key ${FAKE_SAS_KEY}`)).toBe(`sas key ${AZURE_REDACTED}`);
    expect(redactAzureDiagnostic(`DefaultEndpointsProtocol=https;AccountName=sa1;AccountKey=${FAKE_STORAGE_KEY}`)).not.toContain(
      FAKE_STORAGE_KEY,
    );
  });

  it("is idempotent", () => {
    const inputs = [
      `Authorization: Bearer ${FAKE_JWT}`,
      `{"authorization":"Bearer ${FAKE_JWT}","x":"y"}`,
      `got Bearer ${FAKE_JWT} back`,
      'client_secret=abc "clientSecret": "def" password: ghi',
      "?code=abc&client_secret=def&sig=xyz&sv=2022-11-02",
      `key ${FAKE_STORAGE_KEY} and ${FAKE_SAS_KEY}`,
      `${FAKE_SECRET} Cookie: a=b`,
      `{"clientSecret":"***REDACTED***"}`,
    ];
    for (const input of inputs) {
      const once = redactAzureDiagnostic(input);
      expect(redactAzureDiagnostic(once)).toBe(once);
    }
  });

  it("keeps GUIDs, ARM resource IDs, ARM error codes and other providers' text intact", () => {
    const keep = [
      `tenant ${FAKE_TENANT} client ${FAKE_CLIENT}`,
      `/subscriptions/${FAKE_SUB}/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-prod`,
      "HTTP 403 | AuthorizationFailed | The client does not have authorization to perform action 'Microsoft.Security/assessments/read' over scope '/subscriptions/x'.",
      '{"error":{"code":"MissingSubscriptionRegistration","message":"not registered"}}',
      "Graph 403 Authorization_RequestDenied: Insufficient privileges",
      "Status code: 429",
      "arn:aws:iam::123456789012:role/Admin",
      "acs:ram::1234567890123456:user/alice",
      "Huawei IAM 401 APIGW.0301 Incorrect IAM authentication information",
      "chinanorth2 Standard_LRS Microsoft.Storage/storageAccounts",
    ];
    for (const s of keep) expect(redactAzureDiagnostic(s)).toBe(s);
  });

  it("never throws and coerces non-strings", () => {
    expect(redactAzureDiagnostic("")).toBe("");
    expect(redactAzureDiagnostic(42 as unknown as string)).toBe("42");
    expect(() => redactAzureDiagnostic({ toString: () => { throw new Error("x"); } } as unknown as string)).not.toThrow();
  });

  it("aztUntrusted / aztUntrustedOpt", () => {
    expect(aztUntrusted(undefined)).toBe("");
    expect(aztUntrusted(null)).toBe("");
    expect(aztUntrusted("kv-prod")).toBe("kv-prod");
    expect(aztUntrusted(`desc Bearer ${FAKE_JWT}`)).toBe(`desc Bearer ${AZURE_REDACTED}`);
    expect(aztUntrusted(7)).toBe("7");
    expect(aztUntrustedOpt("   ")).toBeUndefined();
    expect(aztUntrustedOpt(" sa1 ")).toBe("sa1");
  });
});
