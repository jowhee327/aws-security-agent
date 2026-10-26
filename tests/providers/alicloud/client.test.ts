/**
 * Phase 2 T1 — Alibaba Cloud generic OpenAPI client (plan §3.5). The SDK modules
 * (`@alicloud/openapi-core`, its `dist/utils.js`, `@alicloud/tea-util`, `ali-oss`) are
 * mocked: no network, fake keys only.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const sdk = vi.hoisted(() => {
  const state = {
    configs: [] as Array<Record<string, unknown>>,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    callApi: undefined as any,
    ossOptions: [] as Array<Record<string, unknown>>,
  };
  class Bag {
    constructor(map: Record<string, unknown> = {}) {
      Object.assign(this, map);
    }
  }
  class FakeClient {
    constructor(config: Record<string, unknown>) {
      state.configs.push(config);
    }
    callApi(params: unknown, request: unknown, runtime: unknown) {
      return state.callApi(params, request, runtime);
    }
  }
  class FakeOss {
    constructor(opts: Record<string, unknown>) {
      state.ossOptions.push(opts);
    }
  }
  return { state, Bag, FakeClient, FakeOss };
});

// openapi-core is CJS: ESM import yields { default: module.exports } with module.exports.default = Client.
vi.mock("@alicloud/openapi-core", () => ({ default: { default: sdk.FakeClient } }));
vi.mock("@alicloud/openapi-core/dist/utils.js", () => ({
  Config: class Config extends sdk.Bag {},
  Params: class Params extends sdk.Bag {},
  OpenApiRequest: class OpenApiRequest extends sdk.Bag {},
}));
// Named export only: vitest throws when a test reads an export the mock does not define.
vi.mock("@alicloud/tea-util", () => ({ RuntimeOptions: class RuntimeOptions extends sdk.Bag {} }));
vi.mock("ali-oss", () => ({ default: sdk.FakeOss }));

import {
  aliCall,
  aliEndpoint,
  aliOssClient,
  aliPaginate,
  clearAliClientCache,
  flattenAliQuery,
  listAliRegions,
  resolveAliSite,
  stripAliOssDebug,
  ALI_CONNECT_TIMEOUT_MS,
  ALI_ECS_GLOBAL_ENDPOINT,
  ALI_MAX_RETRIES,
  ALI_READ_TIMEOUT_MS,
} from "../../../src/providers/alicloud/client.js";
import { ALI_API } from "../../../src/providers/alicloud/api-catalog.js";
import { AliCloudError, ALI_AUTH_FAILED_PREFIX } from "../../../src/providers/alicloud/errors.js";
import type { AlibabaCloudCredentials } from "../../../src/types.js";

const FAKE_AK = "LTAI5tFAKEFAKEFAKE0000001";
const FAKE_SK = "FakeSecretKeyDoNotUseXXXXXXXXXXXX01";
const FAKE_TOKEN = "CAISFAKEFAKEFAKEFAKEtokenDoNotUse0003";

// Plain objects (not createAliCredentials) so redaction relies on the patterns, not the registry.
const creds = (): AlibabaCloudCredentials => ({ kind: "alicloud", accessKeyId: FAKE_AK, accessKeySecret: FAKE_SK });
const stsCreds = (): AlibabaCloudCredentials => ({ kind: "alicloud", accessKeyId: FAKE_AK, accessKeySecret: FAKE_SK, securityToken: FAKE_TOKEN });
const noDelay = { baseDelayMs: 0 };

function sdkError(code: string, statusCode: number, message: string): Error {
  const e = new Error(`code: ${statusCode}, ${message} request id: REQ-9`) as Error & Record<string, unknown>;
  e.name = "ClientError";
  Object.assign(e, { code, statusCode, requestId: "REQ-9", data: { Code: code, Message: message, RequestId: "REQ-9" } });
  return e;
}

beforeEach(() => {
  sdk.state.configs.length = 0;
  sdk.state.ossOptions.length = 0;
  sdk.state.callApi = vi.fn(async () => ({ statusCode: 200, headers: {}, body: { RequestId: "OK-1" } }));
  clearAliClientCache();
});

describe("aliEndpoint / resolveAliSite", () => {
  it("resolves the site from ALIBABA_CLOUD_SITE", () => {
    expect(resolveAliSite({})).toBe("cn");
    expect(resolveAliSite({ ALIBABA_CLOUD_SITE: "INTL" })).toBe("intl");
    expect(resolveAliSite({ ALIBABA_CLOUD_SITE: "bogus" })).toBe("cn");
  });

  it("maps services to hostnames for the cn site", () => {
    expect(aliEndpoint("ecs", "cn-beijing", "cn")).toBe("ecs.cn-beijing.aliyuncs.com");
    expect(aliEndpoint("fc", "cn-hangzhou", "cn")).toBe("fcv3.cn-hangzhou.aliyuncs.com");
    expect(aliEndpoint("kms", "cn-shanghai", "cn")).toBe("kms.cn-shanghai.aliyuncs.com");
    expect(aliEndpoint("ram", undefined, "cn")).toBe("ram.aliyuncs.com");
    expect(aliEndpoint("ims", undefined, "cn")).toBe("ims.aliyuncs.com");
    expect(aliEndpoint("sts", undefined, "cn")).toBe("sts.aliyuncs.com");
    expect(aliEndpoint("rds", "cn-beijing", "cn")).toBe("rds.aliyuncs.com");
    expect(aliEndpoint("config", undefined, "cn")).toBe("config.cn-shanghai.aliyuncs.com");
    expect(aliEndpoint("sas", undefined, "cn")).toBe("tds.aliyuncs.com");
    expect(aliEndpoint("cas", undefined, "cn")).toBe("cas.aliyuncs.com");
    expect(aliEndpoint("waf", undefined, "cn")).toBe("wafopenapi.cn-hangzhou.aliyuncs.com");
  });

  it("maps centralised services to the intl site", () => {
    expect(aliEndpoint("config", undefined, "intl")).toBe("config.ap-southeast-1.aliyuncs.com");
    expect(aliEndpoint("sas", undefined, "intl")).toBe("tds.ap-southeast-1.aliyuncs.com");
    expect(aliEndpoint("cas", undefined, "intl")).toBe("cas.ap-southeast-1.aliyuncs.com");
    expect(aliEndpoint("waf", undefined, "intl")).toBe("wafopenapi.ap-southeast-1.aliyuncs.com");
    expect(aliEndpoint("ram", undefined, "intl")).toBe("ram.aliyuncs.com");
    expect(aliEndpoint("ecs", "ap-southeast-1", "intl")).toBe("ecs.ap-southeast-1.aliyuncs.com");
  });

  it("requires a region for regional services", () => {
    expect(() => aliEndpoint("ecs", undefined, "cn")).toThrow(/region is required/);
  });
});

describe("flattenAliQuery", () => {
  it("flattens arrays / objects and stringifies scalars", () => {
    expect(
      flattenAliQuery({
        RegionId: "cn-hangzhou",
        PageSize: 50,
        DryRun: false,
        InstanceIds: ["i-1", "i-2"],
        Tag: [{ Key: "env", Value: "prod" }],
        Filter: { Name: "x" },
        Skip: undefined,
        Nothing: null,
      }),
    ).toEqual({
      RegionId: "cn-hangzhou",
      PageSize: "50",
      DryRun: "false",
      "InstanceIds.1": "i-1",
      "InstanceIds.2": "i-2",
      "Tag.1.Key": "env",
      "Tag.1.Value": "prod",
      "Filter.Name": "x",
    });
    expect(flattenAliQuery(undefined)).toEqual({});
  });
});

describe("aliCall", () => {
  it("builds Config with EXPLICIT credentials, endpoint and timeouts; Params from the catalog", async () => {
    const body = await aliCall(ALI_API.ecs.DescribeInstances, { credentials: creds(), region: "cn-beijing", retry: noDelay }, { RegionId: "cn-beijing", PageSize: 50 });
    expect(body).toEqual({ RequestId: "OK-1" });
    expect(sdk.state.configs).toHaveLength(1);
    expect(sdk.state.configs[0]).toMatchObject({
      type: "access_key",
      accessKeyId: FAKE_AK,
      accessKeySecret: FAKE_SK,
      endpoint: "ecs.cn-beijing.aliyuncs.com",
      protocol: "https",
      regionId: "cn-beijing",
      connectTimeout: ALI_CONNECT_TIMEOUT_MS,
      readTimeout: ALI_READ_TIMEOUT_MS,
    });
    expect(sdk.state.configs[0].securityToken).toBeUndefined();

    const [params, request, runtime] = sdk.state.callApi.mock.calls[0];
    expect(params).toMatchObject({
      action: "DescribeInstances",
      version: "2014-05-26",
      protocol: "HTTPS",
      pathname: "/",
      method: "POST",
      authType: "AK",
      style: "RPC",
      reqBodyType: "formData",
      bodyType: "json",
    });
    expect(request).toMatchObject({ query: { RegionId: "cn-beijing", PageSize: "50" } });
    expect(runtime).toMatchObject({ autoretry: false, maxAttempts: 1, connectTimeout: ALI_CONNECT_TIMEOUT_MS, readTimeout: ALI_READ_TIMEOUT_MS });
  });

  it("uses type sts + securityToken for STS credentials", async () => {
    await aliCall(ALI_API.sts.GetCallerIdentity, { credentials: stsCreds(), retry: noDelay });
    expect(sdk.state.configs[0]).toMatchObject({ type: "sts", securityToken: FAKE_TOKEN, endpoint: "sts.aliyuncs.com" });
  });

  it("sends GET for Config GetCompliancePackReport and ROA params for FC ListFunctions", async () => {
    await aliCall(ALI_API.config.GetCompliancePackReport, { credentials: creds(), retry: noDelay, site: "cn" }, { CompliancePackId: "cp-1" });
    expect(sdk.state.callApi.mock.calls[0][0]).toMatchObject({ action: "GetCompliancePackReport", method: "GET", style: "RPC", version: "2020-09-07" });
    expect(sdk.state.configs[0].endpoint).toBe("config.cn-shanghai.aliyuncs.com");

    await aliCall(ALI_API.fc.ListFunctions, { credentials: creds(), region: "cn-hangzhou", retry: noDelay }, { limit: 100 });
    expect(sdk.state.callApi.mock.calls[1][0]).toMatchObject({
      action: "ListFunctions",
      method: "GET",
      style: "ROA",
      pathname: "/2023-03-30/functions",
      reqBodyType: "json",
      version: "2023-03-30",
    });
    expect(sdk.state.configs[1].endpoint).toBe("fcv3.cn-hangzhou.aliyuncs.com");
  });

  it("reuses the client per credentials object + endpoint", async () => {
    const c = creds();
    await aliCall(ALI_API.ram.ListUsers, { credentials: c, retry: noDelay });
    await aliCall(ALI_API.ram.ListRoles, { credentials: c, retry: noDelay });
    expect(sdk.state.configs).toHaveLength(1);
    await aliCall(ALI_API.ram.ListUsers, { credentials: creds(), retry: noDelay });
    expect(sdk.state.configs).toHaveLength(2);
  });

  it("retries throttling up to ALI_MAX_RETRIES times, then throws a classified AliCloudError", async () => {
    sdk.state.callApi = vi.fn(async () => {
      throw sdkError("Throttling.User", 400, "Request was denied due to user flow control.");
    });
    const err = await aliCall(ALI_API.ecs.DescribeDisks, { credentials: creds(), region: "cn-hangzhou", retry: noDelay }).catch((e) => e);
    expect(err).toBeInstanceOf(AliCloudError);
    expect(err.kind).toBe("throttled");
    expect(err.api).toBe("ecs:DescribeDisks");
    expect(sdk.state.callApi).toHaveBeenCalledTimes(ALI_MAX_RETRIES + 1);
  });

  it("recovers when a retry succeeds (5xx then 200)", async () => {
    let n = 0;
    sdk.state.callApi = vi.fn(async () => {
      if (n++ === 0) throw sdkError("InternalError", 500, "unknown error");
      return { statusCode: 200, body: { ok: true } };
    });
    expect(await aliCall(ALI_API.vpc.DescribeEipAddresses, { credentials: creds(), region: "cn-hangzhou", retry: noDelay })).toEqual({ ok: true });
    expect(sdk.state.callApi).toHaveBeenCalledTimes(2);
  });

  it("honours maxRetries", async () => {
    sdk.state.callApi = vi.fn(async () => {
      throw Object.assign(new Error("socket hang up"), { code: "ECONNRESET" });
    });
    const err = await aliCall(ALI_API.ram.ListUsers, { credentials: creds(), retry: { maxRetries: 1, baseDelayMs: 0 } }).catch((e) => e);
    expect(err.kind).toBe("network");
    expect(sdk.state.callApi).toHaveBeenCalledTimes(2);
  });

  it("does NOT retry auth failures (404 InvalidAccessKeyId.NotFound) and never echoes the AK", async () => {
    sdk.state.callApi = vi.fn(async () => {
      throw sdkError("InvalidAccessKeyId.NotFound", 404, `Specified access key is not found: ${FAKE_AK}`);
    });
    const err = await aliCall(ALI_API.ecs.DescribeRegions, { credentials: creds(), endpoint: ALI_ECS_GLOBAL_ENDPOINT, retry: noDelay }).catch((e) => e);
    expect(sdk.state.callApi).toHaveBeenCalledTimes(1);
    expect(err).toBeInstanceOf(AliCloudError);
    expect(err.kind).toBe("auth_failed");
    expect(err.message.startsWith(ALI_AUTH_FAILED_PREFIX)).toBe(true);
    for (const text of [err.message, JSON.stringify(err), String(err.stack ?? "")]) {
      expect(text).not.toContain(FAKE_AK);
      expect(text).not.toContain(FAKE_SK);
    }
  });

  it("does not retry api_misuse / access_denied; wrapped messages carry no AK", async () => {
    sdk.state.callApi = vi.fn(async () => {
      throw sdkError(
        "SignatureDoesNotMatch",
        400,
        `Specified signature is not matched with our calculation. server string to sign is:POST&%2F&AccessKeyId%3D${FAKE_AK}%26Action%3DListUsers`,
      );
    });
    let err = await aliCall(ALI_API.ram.ListUsers, { credentials: creds(), retry: noDelay }).catch((e) => e);
    expect(sdk.state.callApi).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(err)).not.toContain(FAKE_AK);

    sdk.state.callApi = vi.fn(async () => {
      throw sdkError("UnsupportedHTTPMethod", 400, "This http method is not supported.");
    });
    err = await aliCall(ALI_API.config.GetCompliancePackReport, { credentials: creds(), retry: noDelay }).catch((e) => e);
    expect(err.kind).toBe("api_misuse");
    expect(sdk.state.callApi).toHaveBeenCalledTimes(1);

    sdk.state.callApi = vi.fn(async () => {
      throw sdkError("Forbidden.RAM", 403, "User not authorized to operate on the specified resource.");
    });
    err = await aliCall(ALI_API.ram.ListUsers, { credentials: creds(), retry: noDelay }).catch((e) => e);
    expect(err.kind).toBe("access_denied");
    expect(err.message).toContain("ram:ListUsers failed: HTTP 403 | Forbidden.RAM");
    expect(sdk.state.callApi).toHaveBeenCalledTimes(1);
  });

  it("refuses to call without explicit credentials", async () => {
    const err = await aliCall(ALI_API.ram.ListUsers, { credentials: undefined as unknown as AlibabaCloudCredentials }).catch((e) => e);
    expect(err).toBeInstanceOf(AliCloudError);
    expect(err.kind).toBe("auth_failed");
    expect(err.code).toBe("MissingCredentials");
    expect(sdk.state.callApi).not.toHaveBeenCalled();
    expect(sdk.state.configs).toHaveLength(0);
  });

  it("fails cleanly when a regional service has no region", async () => {
    const err = await aliCall(ALI_API.ecs.DescribeInstances, { credentials: creds(), retry: noDelay }).catch((e) => e);
    expect(err).toBeInstanceOf(AliCloudError);
    expect(err.message).toContain("region is required");
    expect(sdk.state.callApi).not.toHaveBeenCalled();
  });
});

describe("listAliRegions", () => {
  it("calls ECS DescribeRegions on the global endpoint with AcceptLanguage=en-US; returns sorted valid ids", async () => {
    sdk.state.callApi = vi.fn(async () => ({
      statusCode: 200,
      body: { Regions: { Region: [{ RegionId: "cn-shanghai" }, { RegionId: "ap-southeast-1" }, { RegionId: "cn-beijing" }, { RegionId: "bad id" }, {}, { RegionId: "cn-beijing" }] } },
    }));
    expect(await listAliRegions(creds(), { retry: noDelay })).toEqual(["ap-southeast-1", "cn-beijing", "cn-shanghai"]);
    expect(sdk.state.configs[0].endpoint).toBe(ALI_ECS_GLOBAL_ENDPOINT);
    const [params, request] = sdk.state.callApi.mock.calls[0];
    expect(params).toMatchObject({ action: "DescribeRegions", version: "2014-05-26" });
    expect(request).toMatchObject({ query: { AcceptLanguage: "en-US" } });
  });
});

describe("aliPaginate", () => {
  it("page style: PageNumber/PageSize until TotalCount", async () => {
    const queries: Array<Record<string, string | number>> = [];
    const res = await aliPaginate({
      style: "page",
      pageSize: 50,
      fetch: async (q) => {
        queries.push(q);
        const n = q.PageNumber === 3 ? 20 : 50;
        return { TotalCount: 120, Items: Array.from({ length: n }, (_, i) => `${q.PageNumber}-${i}`) };
      },
      items: (p) => p.Items,
    });
    expect(res.items).toHaveLength(120);
    expect(res.pages).toBe(3);
    expect(res.truncated).toBe(false);
    expect(res.warnings).toEqual([]);
    expect(queries).toEqual([
      { PageSize: 50, PageNumber: 1 },
      { PageSize: 50, PageNumber: 2 },
      { PageSize: 50, PageNumber: 3 },
    ]);
  });

  it("page style without TotalCount stops on a short page", async () => {
    const res = await aliPaginate({
      style: "page",
      pageSize: 2,
      fetch: async (q) => ({ Items: q.PageNumber === 1 ? ["a", "b"] : ["c"] }),
      items: (p) => p.Items,
    });
    expect(res.items).toEqual(["a", "b", "c"]);
    expect(res.pages).toBe(2);
  });

  it("token style: NextToken/MaxResults", async () => {
    const queries: Array<Record<string, string | number>> = [];
    const tokens: Record<string, string | undefined> = { "": "t1", t1: "t2", t2: undefined };
    const res = await aliPaginate({
      style: "token",
      pageSize: 10,
      fetch: async (q) => {
        queries.push(q);
        const cur = String(q.NextToken ?? "");
        return { NextToken: tokens[cur], Keys: [cur || "first"] };
      },
      items: (p) => p.Keys,
    });
    expect(res.items).toEqual(["first", "t1", "t2"]);
    expect(queries).toEqual([{ MaxResults: 10 }, { MaxResults: 10, NextToken: "t1" }, { MaxResults: 10, NextToken: "t2" }]);
    expect(res.truncated).toBe(false);
  });

  it("marker style: Marker/MaxItems + IsTruncated", async () => {
    const queries: Array<Record<string, string | number>> = [];
    const res = await aliPaginate({
      style: "marker",
      pageSize: 100,
      fetch: async (q) => {
        queries.push(q);
        return q.Marker ? { IsTruncated: false, Users: ["u2"] } : { IsTruncated: true, Marker: "m1", Users: ["u1"] };
      },
      items: (p) => p.Users,
    });
    expect(res.items).toEqual(["u1", "u2"]);
    expect(queries).toEqual([{ MaxItems: 100 }, { MaxItems: 100, Marker: "m1" }]);
  });

  it("guards against a repeated token", async () => {
    const res = await aliPaginate({
      style: "token",
      label: "KMS ListKeys",
      fetch: async () => ({ NextToken: "same", Keys: ["k"] }),
      items: (p) => p.Keys,
    });
    expect(res.pages).toBe(2);
    expect(res.truncated).toBe(true);
    expect(res.warnings[0]).toMatch(/^KMS ListKeys: pagination token repeated/);
  });

  it("stops at the page cap with a warning", async () => {
    let n = 0;
    const res = await aliPaginate({
      style: "token",
      maxPages: 3,
      fetch: async () => ({ NextToken: `t${++n}`, Keys: [n] }),
      items: (p) => p.Keys,
    });
    expect(res.pages).toBe(3);
    expect(res.items).toEqual([1, 2, 3]);
    expect(res.truncated).toBe(true);
    expect(res.warnings[0]).toMatch(/page cap/);
  });

  it("stops at maxItems", async () => {
    const res = await aliPaginate({
      style: "page",
      pageSize: 5,
      maxItems: 7,
      fetch: async () => ({ Items: [1, 2, 3, 4, 5] }),
      items: (p) => p.Items,
    });
    expect(res.items).toHaveLength(7);
    expect(res.truncated).toBe(true);
    expect(res.warnings[0]).toMatch(/item cap/);
  });
});

describe("OSS client", () => {
  const savedDebug = process.env.DEBUG;
  afterEach(() => {
    if (savedDebug === undefined) delete process.env.DEBUG;
    else process.env.DEBUG = savedDebug;
  });

  it("stripAliOssDebug removes ali-oss namespaces and excludes them from wildcards", () => {
    const cases: Array<[string | undefined, string | undefined]> = [
      [undefined, undefined],
      ["ali-oss", undefined],
      ["ali-oss:*,express:*", "express:*,-ali-oss*"],
      ["foo,ali-oss*", "foo"],
      ["*", "*,-ali-oss*"],
      ["-ali-oss*,*", "-ali-oss*,*"],
    ];
    for (const [input, expected] of cases) {
      const env: NodeJS.ProcessEnv = input === undefined ? {} : { DEBUG: input };
      stripAliOssDebug(env);
      expect(env.DEBUG).toBe(expected);
    }
  });

  it("aliOssClient passes explicit credentials, https, timeout and strips DEBUG first", async () => {
    process.env.DEBUG = "ali-oss";
    await aliOssClient(stsCreds(), "cn-hangzhou", { bucket: "b1" });
    expect(process.env.DEBUG).toBeUndefined();
    expect(sdk.state.ossOptions[0]).toEqual({
      region: "oss-cn-hangzhou",
      accessKeyId: FAKE_AK,
      accessKeySecret: FAKE_SK,
      stsToken: FAKE_TOKEN,
      bucket: "b1",
      secure: true,
      timeout: ALI_READ_TIMEOUT_MS,
    });
    await aliOssClient(creds(), "oss-cn-beijing", { timeoutMs: 1000 });
    expect(sdk.state.ossOptions[1]).toMatchObject({ region: "oss-cn-beijing", timeout: 1000 });
    expect(sdk.state.ossOptions[1].stsToken).toBeUndefined();
  });
});
