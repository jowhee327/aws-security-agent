/**
 * ObsPublicAccessScanner (Huawei Cloud public_access_verify) — the OBS client
 * factory is mocked with callback-style fakes; no network, no credential file.
 */
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll, afterEach } from "vitest";
import { inspect } from "util";

const { hwObsClientMock, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock } = vi.hoisted(() => ({
  hwObsClientMock: vi.fn(),
  hwClientMock: vi.fn(),
  loadHuaweiCredentialsMock: vi.fn(),
  resolveRegionScopeMock: vi.fn(),
}));

vi.mock("../../../../src/providers/huaweicloud/client.js", () => ({
  hwClient: hwClientMock,
  hwObsClient: hwObsClientMock,
  silenceSdkLogging: vi.fn(),
}));
// The OBS SDK must never be loaded in unit tests (configures log4js).
vi.mock("esdk-obs-nodejs", () => ({ default: class { constructor() { throw new Error("real ObsClient must not be used in tests"); } } }));
vi.mock("../../../../src/providers/huaweicloud/credentials.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../../src/providers/huaweicloud/credentials.js")>();
  return { ...actual, loadHuaweiCredentials: loadHuaweiCredentialsMock, resolveRegionScope: resolveRegionScopeMock };
});

import {
  ObsPublicAccessScanner,
  evaluateObsAcl,
  evaluateObsPolicy,
  pabBlocksAll,
  obsCall,
  ObsHttpError,
  OBS_MAX_BUCKETS,
} from "../../../../src/providers/huaweicloud/scanners/obs-public-access.js";
import { createHuaweiCredentials } from "../../../../src/providers/huaweicloud/credentials.js";
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

/* ------------------------------------------------------------------------ */
/* Callback-style fake OBS client                                           */
/* ------------------------------------------------------------------------ */

type ObsResp = { CommonMsg: { Status: number; Code?: string; Message?: string; RequestId?: string }; InterfaceResult: unknown };
type Responder = (params: Record<string, unknown>) => ObsResp | Error;
type BucketMethod = "getBucketAcl" | "getBucketPolicy" | "getBucketPublicAccessBlock" | "getBucketLocation";

const ok = (InterfaceResult: unknown): ObsResp => ({ CommonMsg: { Status: 200, RequestId: "req-ok" }, InterfaceResult });
const http = (Status: number, Code: string, Message: string): ObsResp => ({ CommonMsg: { Status, Code, Message, RequestId: `req-${Status}` }, InterfaceResult: null });

const PRIVATE_ACL = ok({ Owner: { ID: DOMAIN }, Grants: [{ Grantee: { Type: "CanonicalUser", ID: DOMAIN }, Permission: "FULL_CONTROL" }] });
const PUBLIC_READ_ACL = ok({
  Owner: { ID: DOMAIN },
  Grants: [
    { Grantee: { Type: "CanonicalUser", ID: DOMAIN }, Permission: "FULL_CONTROL" },
    { Grantee: { Type: "Group", URI: "Everyone" }, Permission: "READ" },
  ],
});
const NO_POLICY = http(404, "NoSuchBucketPolicy", "The bucket policy does not exist");
const PAB_405 = http(405, "MethodNotAllowed", "The specified method is not allowed against this resource.");
const DENIED = http(403, "AccessDenied", "Access Denied");

/** Per-bucket behaviour table; each fake client records the region it was built for. */
function makeFakeObs(
  region: string,
  table: Record<string, Partial<Record<BucketMethod, Responder>>>,
  buckets: unknown[] | Error | ObsResp,
  calls: string[],
) {
  const respond = (method: string, params: Record<string, unknown>, cb: (err: unknown, r: ObsResp | null) => void) => {
    calls.push(`${region}:${method}:${String(params.Bucket ?? "")}`);
    setImmediate(() => {
      if (method === "listBuckets") {
        if (buckets instanceof Error) return cb(buckets, null);
        if (Array.isArray(buckets)) return cb(null, ok({ Owner: { ID: DOMAIN }, Buckets: buckets }));
        return cb(null, buckets);
      }
      const r = table[String(params.Bucket)]?.[method as BucketMethod];
      if (!r) return cb(null, http(500, "TestNoResponder", `no responder for ${method}`));
      const out = r(params);
      if (out instanceof Error) return cb(out, null);
      cb(null, out);
    });
  };
  const client: Record<string, unknown> = { close: vi.fn() };
  for (const m of ["listBuckets", "getBucketAcl", "getBucketPolicy", "getBucketPublicAccessBlock", "getBucketLocation"]) {
    client[m] = (params: Record<string, unknown>, cb: (err: unknown, r: ObsResp | null) => void) => respond(m, params, cb);
  }
  return client;
}

/* Capture anything that could reach the MCP stdio channel. */
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

describe("ObsPublicAccessScanner (public_access_verify)", () => {
  const scanner = new ObsPublicAccessScanner();
  let calls: string[];

  beforeEach(() => {
    calls = [];
    hwObsClientMock.mockReset();
    hwClientMock.mockReset();
    loadHuaweiCredentialsMock.mockReset();
    resolveRegionScopeMock.mockReset();
  });

  it("is registered on the huaweicloud provider under the AWS module name", () => {
    expect(scanner.moduleName).toBe("public_access_verify");
    expect(huaweiCloudProvider.scanners().map((s) => s.moduleName)).toContain("public_access_verify");
  });

  it("three states: public-read (finding), private (none), PAB 405 is not an error", async () => {
    const table = {
      "pub-bucket": { getBucketPublicAccessBlock: () => PAB_405, getBucketAcl: () => PUBLIC_READ_ACL, getBucketPolicy: () => NO_POLICY },
      "priv-bucket": { getBucketPublicAccessBlock: () => PAB_405, getBucketAcl: () => PRIVATE_ACL, getBucketPolicy: () => NO_POLICY },
      "pab-bucket": {
        getBucketPublicAccessBlock: () => ok({ BlockPublicAcls: "true", IgnorePublicAcls: "true", BlockPublicPolicy: "true", RestrictPublicBuckets: "true" }),
        getBucketAcl: () => PUBLIC_READ_ACL, // must NOT be consulted: PAB blocks everything
        getBucketPolicy: () => NO_POLICY,
      },
    };
    hwObsClientMock.mockImplementation(async (_c: unknown, region: string) =>
      makeFakeObs(region, table, [
        { BucketName: "pub-bucket", Location: "cn-north-4", CreationDate: "2026-01-01T00:00:00Z" },
        { BucketName: "priv-bucket", Location: "cn-north-4" },
        { BucketName: "pab-bucket", Location: "cn-north-4" },
      ], calls),
    );

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.error).toBeUndefined();
    expect(result.warnings).toBeUndefined(); // 405 PAB + 404 policy are not warnings
    expect(result.resourcesScanned).toBe(3);
    expect(result.findingsCount).toBe(1);
    const f = result.findings[0];
    expect(f.title).toBe("OBS bucket pub-bucket is publicly readable");
    expect(f.severity).toBe("HIGH");
    expect(f.riskScore).toBe(8.0);
    expect(f.priority).toBe("P1");
    expect(f.resourceArn).toBe(`hws:cn-north-4:${DOMAIN}:obs:bucket:pub-bucket`);
    expect(f.resourceType).toBe("HuaweiCloud::OBS::Bucket");
    expect(f.region).toBe("cn-north-4");
    expect(f.provider).toBe("huaweicloud");
    expect(f.description).toContain("ACL grants READ to Everyone");

    // Client built once for the scan region with the context credentials, ACL not fetched behind a full PAB.
    expect(hwObsClientMock).toHaveBeenCalledTimes(1);
    expect(hwObsClientMock.mock.calls[0][0]).toBe(creds);
    expect(hwObsClientMock.mock.calls[0][1]).toBe("cn-north-4");
    expect(calls).toContain("cn-north-4:listBuckets:");
    expect(calls).not.toContain("cn-north-4:getBucketAcl:pab-bucket");
    expect(calls).toContain("cn-north-4:getBucketAcl:pub-bucket");
    expect(loadHuaweiCredentialsMock).not.toHaveBeenCalled();
  });

  it("flags public write via ACL and via wildcard-principal policy as CRITICAL, one finding per bucket", async () => {
    const policy = JSON.stringify({
      Statement: [
        { Sid: "AllowAnyoneWrite", Effect: "Allow", Principal: { ID: ["*"] }, Action: ["PutObject", "GetObject"], Resource: ["site/*"] },
      ],
    });
    const table = {
      "acl-write": {
        getBucketPublicAccessBlock: () => PAB_405,
        getBucketAcl: () => ok({ Grants: [{ Grantee: { Type: "Group", URI: "http://acs.amazonaws.com/groups/global/AllUsers" }, Permission: "WRITE" }] }),
        getBucketPolicy: () => NO_POLICY,
      },
      "pol-write": { getBucketPublicAccessBlock: () => PAB_405, getBucketAcl: () => PRIVATE_ACL, getBucketPolicy: () => ok({ Policy: policy }) },
      "pol-read": {
        getBucketPublicAccessBlock: () => PAB_405,
        getBucketAcl: () => PRIVATE_ACL,
        getBucketPolicy: () => ok({ Policy: JSON.stringify({ Statement: { Effect: "Allow", Principal: "*", Action: "obs:object:GetObject", Resource: "x/*" } }) }),
      },
      "pol-cond": {
        getBucketPublicAccessBlock: () => PAB_405,
        getBucketAcl: () => PRIVATE_ACL,
        getBucketPolicy: () => ok({ Policy: JSON.stringify({ Statement: [{ Effect: "Allow", Principal: { ID: "*" }, Action: ["GetObject"], Resource: "x/*", Condition: { IpAddress: { SourceIp: "10.0.0.0/8" } } }] }) }),
      },
      "pol-deny": {
        getBucketPublicAccessBlock: () => PAB_405,
        getBucketAcl: () => PRIVATE_ACL,
        getBucketPolicy: () => ok({ Policy: JSON.stringify({ Statement: [{ Effect: "Deny", Principal: "*", Action: "*", Resource: "*" }] }) }),
      },
    };
    hwObsClientMock.mockImplementation(async (_c: unknown, region: string) =>
      makeFakeObs(region, table, Object.keys(table).map((BucketName) => ({ BucketName, Location: "cn-north-4" })), calls),
    );

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.warnings).toBeUndefined();
    expect(result.resourcesScanned).toBe(5);
    const byId = Object.fromEntries(result.findings.map((f) => [f.resourceId, f]));
    expect(Object.keys(byId).sort()).toEqual(["acl-write", "pol-cond", "pol-read", "pol-write"]);
    expect(byId["acl-write"]).toMatchObject({ severity: "CRITICAL", riskScore: 9.5, priority: "P0", title: "OBS bucket acl-write is publicly writable" });
    expect(byId["pol-write"]).toMatchObject({ severity: "CRITICAL", riskScore: 9.5, title: "OBS bucket pol-write is publicly writable" });
    expect(byId["pol-write"].description).toContain("Sid AllowAnyoneWrite");
    expect(byId["pol-read"]).toMatchObject({ severity: "HIGH", riskScore: 8.0, title: "OBS bucket pol-read is publicly readable" });
    expect(byId["pol-cond"]).toMatchObject({ severity: "MEDIUM", riskScore: 6.0, title: "OBS bucket pol-cond grants conditional access to any principal" });
  });

  it("uses each bucket's Location for the endpoint, URN and Finding.region; falls back to getBucketLocation", async () => {
    const table = {
      "east-bucket": { getBucketPublicAccessBlock: () => PAB_405, getBucketAcl: () => PUBLIC_READ_ACL, getBucketPolicy: () => NO_POLICY },
      "noloc-bucket": { getBucketLocation: () => ok({ Location: "cn-east-3" }), getBucketPublicAccessBlock: () => PAB_405, getBucketAcl: () => PRIVATE_ACL, getBucketPolicy: () => NO_POLICY },
    };
    hwObsClientMock.mockImplementation(async (_c: unknown, region: string) =>
      makeFakeObs(region, table, [{ BucketName: "east-bucket", Location: "cn-east-3" }, { BucketName: "noloc-bucket" }], calls),
    );

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].region).toBe("cn-east-3");
    expect(result.findings[0].resourceArn).toBe(`hws:cn-east-3:${DOMAIN}:obs:bucket:east-bucket`);
    // one client per region: cn-north-4 (listing) + cn-east-3 (both buckets)
    expect(hwObsClientMock.mock.calls.map((c) => c[1]).sort()).toEqual(["cn-east-3", "cn-north-4"]);
    expect(calls).toContain("cn-north-4:getBucketLocation:noloc-bucket");
    expect(calls).toContain("cn-east-3:getBucketAcl:east-bucket");
    expect(calls).toContain("cn-east-3:getBucketAcl:noloc-bucket");
  });

  it("degrades gracefully: 403 on listBuckets → success, warning, 0 findings", async () => {
    hwObsClientMock.mockImplementation(async (_c: unknown, region: string) => makeFakeObs(region, {}, DENIED, calls));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.error).toBeUndefined();
    expect(result.findingsCount).toBe(0);
    expect(result.resourcesScanned).toBe(0);
    expect(result.warnings).toEqual(["OBS: insufficient permissions to list buckets (HTTP 403 | AccessDenied | Access Denied | requestId=req-403); skipped"]);
  });

  it("degrades per bucket: 403 on one bucket's ACL/policy → warnings, other buckets still evaluated", async () => {
    const table = {
      "denied": { getBucketPublicAccessBlock: () => DENIED, getBucketAcl: () => DENIED, getBucketPolicy: () => DENIED },
      "public": { getBucketPublicAccessBlock: () => PAB_405, getBucketAcl: () => PUBLIC_READ_ACL, getBucketPolicy: () => NO_POLICY },
      "neterr": { getBucketPublicAccessBlock: () => PAB_405, getBucketAcl: () => new Error("connect ETIMEDOUT 1.2.3.4:443"), getBucketPolicy: () => NO_POLICY },
    };
    hwObsClientMock.mockImplementation(async (_c: unknown, region: string) =>
      makeFakeObs(region, table, Object.keys(table).map((BucketName) => ({ BucketName, Location: "cn-north-4" })), calls),
    );

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].resourceId).toBe("public");
    expect(result.warnings).toHaveLength(4);
    expect(result.warnings!.filter((w) => w.includes("bucket denied"))).toHaveLength(3);
    expect(result.warnings!.find((w) => w.startsWith("Could not check public access block for bucket denied (insufficient permissions)"))).toBeDefined();
    expect(result.warnings!.find((w) => w.startsWith("Could not check ACL for bucket neterr:"))).toContain("ETIMEDOUT");
    // "denied" was not evaluated at all → not counted; "neterr" had its policy checked → counted.
    expect(result.resourcesScanned).toBe(2);
  });

  it("caps the number of buckets and warns when truncated", async () => {
    const buckets = Array.from({ length: OBS_MAX_BUCKETS + 5 }, (_, i) => ({ BucketName: `b${i}`, Location: "cn-north-4" }));
    const table: Record<string, Partial<Record<BucketMethod, Responder>>> = {};
    for (const b of buckets) table[b.BucketName] = { getBucketPublicAccessBlock: () => PAB_405, getBucketAcl: () => PRIVATE_ACL, getBucketPolicy: () => NO_POLICY };
    hwObsClientMock.mockImplementation(async (_c: unknown, region: string) => makeFakeObs(region, table, buckets, calls));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(OBS_MAX_BUCKETS);
    expect(result.warnings).toEqual([`OBS: ${OBS_MAX_BUCKETS + 5} buckets found; only the first ${OBS_MAX_BUCKETS} were checked.`]);
    expect(calls.filter((c) => c.includes(":getBucketAcl:"))).toHaveLength(OBS_MAX_BUCKETS);
  });

  it("returns status error (without secrets) on unexpected listBuckets failures", async () => {
    const netErr = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:443"), { config: { headers: { Authorization: FAKE_AUTH_HEADER } } });
    hwObsClientMock.mockImplementation(async (_c: unknown, region: string) => makeFakeObs(region, {}, netErr, calls));

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("error");
    expect(result.error).toBe("OBS public access verification failed: connect ECONNREFUSED 127.0.0.1:443");
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("Authorization");
    expect(serialized).not.toContain(FAKE_AK);
  });

  it("falls back to the credential chain ([basic]) when the context carries no Huawei credentials", async () => {
    const chainCreds = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK, domainId: DOMAIN });
    loadHuaweiCredentialsMock.mockReturnValueOnce({ basic: chainCreds, global: chainCreds, source: "env" });
    hwObsClientMock.mockImplementation(async (_c: unknown, region: string) => makeFakeObs(region, {}, [], calls));

    const result = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: DOMAIN, provider: "huaweicloud" });

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(loadHuaweiCredentialsMock).toHaveBeenCalledTimes(1);
    expect(hwObsClientMock.mock.calls[0][0]).toBe(chainCreds);
  });
});

describe("OBS judgement helpers", () => {
  it("evaluateObsAcl recognises Everyone / AllUsers / AuthenticatedUsers in Grants and GrantsV2", () => {
    expect(evaluateObsAcl(undefined)).toEqual([]);
    expect(evaluateObsAcl({ Grants: [{ Grantee: { ID: "owner" }, Permission: "FULL_CONTROL" }] })).toEqual([]);
    expect(evaluateObsAcl({ Grants: [{ Grantee: { Type: "Group", URI: "Everyone" }, Permission: "READ" }] })).toEqual([{ vector: "acl_read", detail: "ACL grants READ to Everyone", riskScore: 8.0 }]);
    expect(evaluateObsAcl({ GrantsV2: [{ Grantee: { Type: "Group", URI: "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" }, Permission: "READ_ACP" }] })).toEqual([{ vector: "acl_read_acp", detail: "ACL grants READ_ACP to AuthenticatedUsers", riskScore: 7.0 }]);
    const write = evaluateObsAcl({ Grants: [{ Grantee: { Type: "Group", URI: "Everyone" }, Permission: "WRITE_ACP" }, { Grantee: { Type: "Group", URI: "Everyone" }, Permission: "WRITE_ACP" }] });
    expect(write).toHaveLength(1); // deduplicated
    expect(write[0].riskScore).toBe(9.5);
  });

  it("evaluateObsPolicy tolerates malformed JSON and ignores Deny / scoped principals", () => {
    expect(evaluateObsPolicy(undefined)).toEqual([]);
    expect(evaluateObsPolicy("not json")).toEqual([]);
    expect(evaluateObsPolicy(JSON.stringify({ Statement: [{ Effect: "Allow", Principal: { ID: [`domain/${DOMAIN}:user/abc`] }, Action: ["*"] }] }))).toEqual([]);
    expect(evaluateObsPolicy(JSON.stringify({ Statement: [{ Effect: "Deny", Principal: "*", Action: ["*"] }] }))).toEqual([]);
    expect(evaluateObsPolicy(JSON.stringify({ Statement: [{ Effect: "Allow", Principal: { AWS: "*" }, Action: "s3:GetObject" }] }))[0].vector).toBe("policy_read");
    expect(evaluateObsPolicy(JSON.stringify({ Statement: [{ Effect: "Allow", Principal: "*", Action: "*" }] }))[0].vector).toBe("policy_write");
    expect(evaluateObsPolicy(JSON.stringify({ Statement: [{ Effect: "Allow", Principal: "*", Action: ["obs:object:DeleteObject"] }] }))[0].vector).toBe("policy_write");
  });

  it("pabBlocksAll requires all four switches (string or boolean)", () => {
    expect(pabBlocksAll(undefined)).toBe(false);
    expect(pabBlocksAll({ BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: false })).toBe(false);
    expect(pabBlocksAll({ BlockPublicAcls: "true", IgnorePublicAcls: "true", BlockPublicPolicy: "true", RestrictPublicBuckets: "true" })).toBe(true);
  });

  it("obsCall wraps callbacks: transport error rejects, HTTP >= 300 rejects with ObsHttpError, success resolves", async () => {
    const client = {
      good: (_p: unknown, cb: (e: unknown, r: unknown) => void) => cb(null, ok({ X: 1 })),
      bad: (_p: unknown, cb: (e: unknown, r: unknown) => void) => cb(null, http(405, "MethodNotAllowed", "nope")),
      boom: (_p: unknown, cb: (e: unknown, r: unknown) => void) => cb(new Error("socket hang up"), null),
      empty: (_p: unknown, cb: (e: unknown, r: unknown) => void) => cb(null, null),
      throws: () => { throw new Error("sync throw"); },
    };
    await expect(obsCall(client, "good")).resolves.toMatchObject({ InterfaceResult: { X: 1 } });
    await expect(obsCall(client, "bad", { Bucket: "b" })).rejects.toBeInstanceOf(ObsHttpError);
    await expect(obsCall(client, "bad", { Bucket: "b" })).rejects.toMatchObject({ status: 405, code: "MethodNotAllowed", requestId: "req-405", message: "nope" });
    await expect(obsCall(client, "boom")).rejects.toThrow("socket hang up");
    await expect(obsCall(client, "empty")).rejects.toThrow(/empty response/);
    await expect(obsCall(client, "throws")).rejects.toThrow("sync throw");
    await expect(obsCall(client, "missing")).rejects.toThrow(/no method "missing"/);
  });
});
