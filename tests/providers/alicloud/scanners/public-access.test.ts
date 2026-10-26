/**
 * Phase 2 T3 — AliPublicAccessScanner (public_access_verify): OSS bucket ACL / Block Public
 * Access / bucket policy (region filtering, primary-scope rule for buckets without region,
 * 403 AccessDenied degrade, 403 InvalidAccessKeyId → error) and RDS public endpoint +
 * whitelist (three states, pagination, per-instance calls, degrade, auth_failed → error).
 * aliCall is mocked by spec.action and the OSS client factory is mocked; fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn(), aliOssClient: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall, aliOssClient: mocks.aliOssClient };
});

import {
  AliPublicAccessScanner,
  evaluateOssPolicy,
  normalizeOssRegion,
  OSS_MAX_BUCKETS,
  ossConditionRestrictsNetwork,
  ossPrincipalIsPublic,
  rdsOpenWhitelistGroups,
  rdsPublicEndpoints,
} from "../../../../src/providers/alicloud/scanners/public-access.js";
import { alibabaCloudProvider } from "../../../../src/providers/alicloud/index.js";
import type { ScanResult } from "../../../../src/types.js";
import {
  aliCtx,
  authError,
  callsFor,
  deniedError,
  FAKE_AK,
  FAKE_SK,
  isolateAliEnv,
  misuseError,
  restoreAliEnv,
  routeAliCall,
  UID,
  type AliHandler,
} from "./helpers.js";

/* ------------------------------------------------------------------------ */
/* Fixtures                                                                 */
/* ------------------------------------------------------------------------ */

interface FakeBucket {
  name: string;
  region?: string;
  acl?: string;
  bpa?: boolean;
  policy?: unknown;
}

/** ali-oss style error (own keys: name, message, status, code, requestId, hostId). */
function ossError(status: number, code: string, message: string): Error {
  const e = new Error(message) as Error & Record<string, unknown>;
  e.name = `${code}Error`;
  e.status = status;
  e.code = code;
  e.requestId = "5F1A2B3C4D5E6F7A8B9C0D1E";
  e.hostId = "bucket.oss-cn-hangzhou.aliyuncs.com";
  return e;
}

/** Simulated OSS error XML echoing the AK (plan §6.1). */
const akEchoXml = (code: string) =>
  `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>denied</Message><OSSAccessKeyId>${FAKE_AK}</OSSAccessKeyId><RequestId>5F1A</RequestId></Error>`;

const noPolicyError = () => ossError(404, "NoSuchBucketPolicy", "The bucket policy does not exist.");

function fakeOss(buckets: FakeBucket[], overrides: Partial<Record<"listBuckets" | "getBucketInfo" | "getBucketPolicy", (...a: unknown[]) => unknown>> = {}) {
  const byName = new Map(buckets.map((b) => [b.name, b]));
  return {
    listBuckets: vi.fn(
      overrides.listBuckets ??
        (async () => ({
          buckets: buckets.map((b) => ({ name: b.name, region: b.region, creationDate: "2026-01-01", storageClass: "Standard" })),
          owner: { id: UID, displayName: UID },
          isTruncated: false,
          nextMarker: null,
        })),
    ),
    getBucketInfo: vi.fn(
      overrides.getBucketInfo ??
        (async (name: unknown) => {
          const b = byName.get(name as string)!;
          return {
            bucket: {
              Name: b.name,
              Location: b.region,
              AccessControlList: { Grant: b.acl ?? "private" },
              ...(b.bpa !== undefined ? { BlockPublicAccess: String(b.bpa) } : {}),
            },
          };
        }),
    ),
    getBucketPolicy: vi.fn(
      overrides.getBucketPolicy ??
        (async (name: unknown) => {
          const b = byName.get(name as string)!;
          if (b.policy === undefined) throw noPolicyError();
          return { policy: b.policy, status: 200 };
        }),
    ),
  };
}

const PUBLIC_POLICY = {
  Version: "1",
  Statement: [{ Sid: "pub", Effect: "Allow", Principal: ["*"], Action: ["oss:GetObject"], Resource: ["acs:oss:*:*:b/*"] }],
};
const IP_RESTRICTED_POLICY = {
  Version: "1",
  Statement: [
    {
      Effect: "Allow",
      Principal: ["*"],
      Action: ["oss:GetObject"],
      Resource: ["acs:oss:*:*:b/*"],
      Condition: { IpAddress: { "acs:SourceIp": ["203.0.113.0/24"] } },
    },
  ],
};

/** RDS: no instances (default for OSS-focused tests). */
const RDS_EMPTY: Record<string, AliHandler | object> = {
  DescribeDBInstances: { Items: { DBInstance: [] }, TotalRecordCount: 0, PageNumber: 1, PageRecordCount: 0 },
};

function netInfo(...entries: Array<{ type: string; cs: string; port?: string }>) {
  return { DBInstanceNetInfos: { DBInstanceNetInfo: entries.map((e) => ({ IPType: e.type, ConnectionString: e.cs, Port: e.port ?? "3306" })) } };
}
function ipArray(...groups: Array<{ name: string; list: string }>) {
  return { Items: { DBInstanceIPArray: groups.map((g) => ({ DBInstanceIPArrayName: g.name, SecurityIPList: g.list, SecurityIPType: "ipv4" })) } };
}

const scanner = new AliPublicAccessScanner();

function noSecrets(r: ScanResult): void {
  const text = JSON.stringify(r);
  expect(text).not.toContain(FAKE_AK);
  expect(text).not.toContain(FAKE_SK);
  expect(text).not.toContain("LTAI5t");
}

beforeEach(() => {
  isolateAliEnv();
  mocks.aliCall.mockReset();
  mocks.aliOssClient.mockReset();
});
afterEach(() => restoreAliEnv());

/* ------------------------------------------------------------------------ */
/* Pure helpers                                                             */
/* ------------------------------------------------------------------------ */

describe("helpers", () => {
  it("normalizeOssRegion strips the oss- prefix", () => {
    expect(normalizeOssRegion("oss-cn-hangzhou")).toBe("cn-hangzhou");
    expect(normalizeOssRegion("cn-beijing")).toBe("cn-beijing");
    expect(normalizeOssRegion("")).toBeUndefined();
    expect(normalizeOssRegion(undefined)).toBeUndefined();
  });

  it("ossPrincipalIsPublic: *, [*], {RAM:[*]}, {RAM:*}", () => {
    expect(ossPrincipalIsPublic("*")).toBe(true);
    expect(ossPrincipalIsPublic(["*"])).toBe(true);
    expect(ossPrincipalIsPublic({ RAM: ["*"] })).toBe(true);
    expect(ossPrincipalIsPublic({ RAM: "*" })).toBe(true);
    expect(ossPrincipalIsPublic(["1234567890123456"])).toBe(false);
    expect(ossPrincipalIsPublic({ RAM: ["acs:ram::1234567890123456:root"] })).toBe(false);
    expect(ossPrincipalIsPublic(undefined)).toBe(false);
  });

  it("ossConditionRestrictsNetwork: SourceIp / SourceVpc positive operators only", () => {
    expect(ossConditionRestrictsNetwork({ IpAddress: { "acs:SourceIp": ["10.0.0.0/8"] } })).toBe(true);
    expect(ossConditionRestrictsNetwork({ StringEquals: { "acs:SourceVpc": "vpc-bp1xxx" } })).toBe(true);
    expect(ossConditionRestrictsNetwork({ NotIpAddress: { "acs:SourceIp": ["10.0.0.0/8"] } })).toBe(false);
    expect(ossConditionRestrictsNetwork({ IpAddress: { "acs:SourceIp": ["0.0.0.0/0"] } })).toBe(false);
    expect(ossConditionRestrictsNetwork({ Bool: { "acs:SecureTransport": "true" } })).toBe(false);
    expect(ossConditionRestrictsNetwork(undefined)).toBe(false);
  });

  it("evaluateOssPolicy: public Allow without network condition; object or JSON string", () => {
    expect(evaluateOssPolicy(PUBLIC_POLICY)).toHaveLength(1);
    expect(evaluateOssPolicy(JSON.stringify(PUBLIC_POLICY))[0].detail).toContain("Sid pub");
    expect(evaluateOssPolicy(IP_RESTRICTED_POLICY)).toEqual([]);
    expect(evaluateOssPolicy({ Statement: [{ Effect: "Deny", Principal: ["*"], Action: ["oss:*"] }] })).toEqual([]);
    expect(evaluateOssPolicy({ Statement: { Effect: "Allow", Principal: { RAM: ["*"] }, Action: "oss:PutObject" } })).toHaveLength(1);
    expect(evaluateOssPolicy("not json")).toEqual([]);
    expect(evaluateOssPolicy(null)).toEqual([]);
  });

  it("rdsPublicEndpoints / rdsOpenWhitelistGroups", () => {
    expect(rdsPublicEndpoints(netInfo({ type: "Private", cs: "rm-1.mysql.rds.aliyuncs.com" }, { type: "Public", cs: "rm-1pub.mysql.rds.aliyuncs.com" }))).toEqual([
      "rm-1pub.mysql.rds.aliyuncs.com:3306",
    ]);
    expect(rdsPublicEndpoints({})).toEqual([]);
    expect(rdsOpenWhitelistGroups(ipArray({ name: "default", list: "127.0.0.1" }, { name: "app", list: "10.0.0.0/8,0.0.0.0/0" }))).toEqual(["app"]);
    expect(rdsOpenWhitelistGroups(ipArray({ name: "legacy", list: "%" }))).toEqual(["legacy"]);
    expect(rdsOpenWhitelistGroups(ipArray({ name: "default", list: "203.0.113.5,10.0.0.0/8" }))).toEqual([]);
  });
});

/* ------------------------------------------------------------------------ */
/* OSS                                                                      */
/* ------------------------------------------------------------------------ */

describe("OSS buckets", () => {
  it("public-read-write → CRITICAL, public-read → HIGH, private → no finding", async () => {
    const oss = fakeOss([
      { name: "rw-bucket", region: "oss-cn-hangzhou", acl: "public-read-write" },
      { name: "r-bucket", region: "oss-cn-hangzhou", acl: "public-read" },
      { name: "priv-bucket", region: "oss-cn-hangzhou", acl: "private" },
    ]);
    mocks.aliOssClient.mockResolvedValue(oss);
    routeAliCall(mocks.aliCall, RDS_EMPTY);

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.module).toBe("public_access_verify");
    expect(r.resourcesScanned).toBe(3);
    expect(r.findingsCount).toBe(2);
    const rw = r.findings.find((f) => f.resourceId === "rw-bucket")!;
    expect(rw.severity).toBe("CRITICAL");
    expect(rw.priority).toBe("P0");
    expect(rw.provider).toBe("alicloud");
    expect(rw.resourceType).toBe("ACS::OSS::Bucket");
    expect(rw.resourceArn).toBe(`acs:oss:cn-hangzhou:${UID}:bucket/rw-bucket`);
    expect(rw.region).toBe("cn-hangzhou");
    const ro = r.findings.find((f) => f.resourceId === "r-bucket")!;
    expect(ro.severity).toBe("HIGH");
    expect(ro.title).toContain("public-read");
    expect(r.findings.some((f) => f.resourceId === "priv-bucket")).toBe(false);
    const [ossCreds, ossRegion] = mocks.aliOssClient.mock.calls[0] as [{ accessKeyId: string }, string];
    expect(ossCreds.accessKeyId).toBe(FAKE_AK); // explicit credentials, never ali-oss lookup
    expect(ossRegion).toBe("cn-hangzhou");
    noSecrets(r);
  });

  it("BlockPublicAccess=true suppresses public ACL and policy findings (informational note only)", async () => {
    mocks.aliOssClient.mockResolvedValue(
      fakeOss([{ name: "blocked", region: "oss-cn-hangzhou", acl: "public-read-write", bpa: true, policy: PUBLIC_POLICY }]),
    );
    routeAliCall(mocks.aliCall, RDS_EMPTY);

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.resourcesScanned).toBe(1);
    const note = r.warnings?.find((w) => w.includes("blocked"));
    expect(note).toContain("Block Public Access is enabled");
    expect(note).toContain("public-read-write");
  });

  it("bucket policy Principal * without SourceIp → HIGH; with SourceIp condition → no finding", async () => {
    mocks.aliOssClient.mockResolvedValue(
      fakeOss([
        { name: "pol-open", region: "oss-cn-hangzhou", policy: PUBLIC_POLICY },
        { name: "pol-ip", region: "oss-cn-hangzhou", policy: IP_RESTRICTED_POLICY },
        { name: "pol-ram", region: "oss-cn-hangzhou", policy: { Statement: [{ Effect: "Allow", Principal: { RAM: ["*"] }, Action: ["oss:*"] }] } },
      ]),
    );
    routeAliCall(mocks.aliCall, RDS_EMPTY);

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceId).sort()).toEqual(["pol-open", "pol-ram"]);
    for (const f of r.findings) {
      expect(f.severity).toBe("HIGH");
      expect(f.title).toContain("policy grants access to any principal");
    }
    expect(r.warnings).toBeUndefined(); // NoSuchBucketPolicy is not an error
  });

  it("public ACL and public policy on one bucket → two findings", async () => {
    mocks.aliOssClient.mockResolvedValue(fakeOss([{ name: "both", region: "oss-cn-hangzhou", acl: "public-read", policy: PUBLIC_POLICY }]));
    routeAliCall(mocks.aliCall, RDS_EMPTY);
    const r = await scanner.scan(aliCtx());
    expect(r.findingsCount).toBe(2);
    expect(r.resourcesScanned).toBe(1);
  });

  it("filters buckets to the scope region; region-less buckets only on the primary scope", async () => {
    const buckets: FakeBucket[] = [
      { name: "hz", region: "oss-cn-hangzhou", acl: "public-read" },
      { name: "bj", region: "oss-cn-beijing", acl: "public-read" },
      { name: "noregion", acl: "public-read" },
    ];
    routeAliCall(mocks.aliCall, RDS_EMPTY);

    mocks.aliOssClient.mockResolvedValue(fakeOss(buckets));
    const primary = await scanner.scan(aliCtx());
    expect(primary.findings.map((f) => f.resourceId).sort()).toEqual(["hz", "noregion"]);
    expect(primary.findings.find((f) => f.resourceId === "noregion")!.resourceArn).toBe(`acs:oss:cn-hangzhou:${UID}:bucket/noregion`);

    const ossBj = fakeOss(buckets);
    mocks.aliOssClient.mockResolvedValue(ossBj);
    const secondary = await scanner.scan(aliCtx({ region: "cn-beijing", primaryRegionScope: false }));
    expect(secondary.findings.map((f) => f.resourceId)).toEqual(["bj"]);
    expect(secondary.findings[0].region).toBe("cn-beijing");
    expect(ossBj.getBucketInfo.mock.calls.map((c) => c[0])).toEqual(["bj"]);
  });

  it("listBuckets marker pagination", async () => {
    const pages: Record<string, unknown> = {
      "": { buckets: [{ name: "a", region: "oss-cn-hangzhou" }], isTruncated: true, nextMarker: "a" },
      a: { buckets: [{ name: "b", region: "oss-cn-hangzhou" }], isTruncated: false, nextMarker: null },
    };
    const oss = fakeOss([{ name: "a", acl: "public-read" }, { name: "b", acl: "public-read" }], {
      listBuckets: async (q: unknown) => pages[((q as { marker?: string }).marker ?? "") as string],
    });
    mocks.aliOssClient.mockResolvedValue(oss);
    routeAliCall(mocks.aliCall, RDS_EMPTY);

    const r = await scanner.scan(aliCtx());
    expect(oss.listBuckets).toHaveBeenCalledTimes(2);
    expect(oss.listBuckets.mock.calls[1][0]).toEqual(expect.objectContaining({ marker: "a" }));
    expect(r.findings.map((f) => f.resourceId).sort()).toEqual(["a", "b"]);
  });

  it(`caps per-region buckets at OSS_MAX_BUCKETS (${OSS_MAX_BUCKETS}) with a warning`, async () => {
    const many: FakeBucket[] = Array.from({ length: OSS_MAX_BUCKETS + 3 }, (_, i) => ({ name: `b${i}`, region: "oss-cn-hangzhou" }));
    const oss = fakeOss(many);
    mocks.aliOssClient.mockResolvedValue(oss);
    routeAliCall(mocks.aliCall, RDS_EMPTY);

    const r = await scanner.scan(aliCtx());
    expect(oss.getBucketInfo).toHaveBeenCalledTimes(OSS_MAX_BUCKETS);
    expect(r.resourcesScanned).toBe(OSS_MAX_BUCKETS);
    expect(r.warnings?.some((w) => w.includes(`only the first ${OSS_MAX_BUCKETS}`))).toBe(true);
  });

  it("OSS 403 AccessDenied on listBuckets → warning, RDS still scanned, no AK echoed", async () => {
    mocks.aliOssClient.mockResolvedValue(
      fakeOss([], {
        listBuckets: async () => {
          throw ossError(403, "AccessDenied", `You have no right to access this object. ${akEchoXml("AccessDenied")}`);
        },
      }),
    );
    routeAliCall(mocks.aliCall, {
      DescribeDBInstances: { Items: { DBInstance: [{ DBInstanceId: "rm-pub", Engine: "MySQL" }] }, TotalRecordCount: 1 },
      DescribeDBInstanceNetInfo: netInfo({ type: "Public", cs: "rm-pub.mysql.rds.aliyuncs.com" }),
      DescribeDBInstanceIPArrayList: ipArray({ name: "default", list: "0.0.0.0/0" }),
    });

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings?.some((w) => /^OSS ListBuckets: insufficient permissions/.test(w))).toBe(true);
    expect(r.findings.map((f) => f.resourceId)).toEqual(["rm-pub"]);
    noSecrets(r);
  });

  it("per-bucket 403 AccessDenied → warning for that bucket, others still checked", async () => {
    const oss = fakeOss(
      [
        { name: "denied", region: "oss-cn-hangzhou" },
        { name: "open", region: "oss-cn-hangzhou", acl: "public-read" },
      ],
      {
        getBucketInfo: async (name: unknown) => {
          if (name === "denied") throw ossError(403, "AccessDenied", akEchoXml("AccessDenied"));
          return { bucket: { Name: name, AccessControlList: { Grant: "public-read" } } };
        },
        getBucketPolicy: async (name: unknown) => {
          if (name === "denied") throw ossError(403, "AccessDenied", akEchoXml("AccessDenied"));
          throw noPolicyError();
        },
      },
    );
    mocks.aliOssClient.mockResolvedValue(oss);
    routeAliCall(mocks.aliCall, RDS_EMPTY);

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceId)).toEqual(["open"]);
    expect(r.resourcesScanned).toBe(1);
    expect(r.warnings?.filter((w) => w.startsWith("OSS bucket denied")).length).toBe(2);
    expect(r.warnings?.every((w) => !w.includes(FAKE_AK))).toBe(true);
    expect(r.warnings?.join("\n")).toContain("<OSSAccessKeyId>[REDACTED]</OSSAccessKeyId>");
    noSecrets(r);
  });

  it("OSS 403 InvalidAccessKeyId → module status error (authentication failed), no AK anywhere", async () => {
    mocks.aliOssClient.mockResolvedValue(
      fakeOss([], {
        listBuckets: async () => {
          throw ossError(403, "InvalidAccessKeyId", `The OSS Access Key Id you provided does not exist in our records. ${akEchoXml("InvalidAccessKeyId")}`);
        },
      }),
    );
    routeAliCall(mocks.aliCall, RDS_EMPTY);

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
    expect(r.error).toContain("InvalidAccessKeyId");
    expect(r.findings).toEqual([]);
    expect(mocks.aliCall).not.toHaveBeenCalled(); // RDS not attempted after an auth failure
    noSecrets(r);
  });

  it("auth failure on a per-bucket call → module status error", async () => {
    mocks.aliOssClient.mockResolvedValue(
      fakeOss([{ name: "b1", region: "oss-cn-hangzhou" }], {
        getBucketInfo: async () => {
          throw ossError(403, "SignatureDoesNotMatch", `<StringToSign>GET\n\n\n${FAKE_AK}</StringToSign>`);
        },
      }),
    );
    routeAliCall(mocks.aliCall, RDS_EMPTY);
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
    noSecrets(r);
  });

  it("a getBucketPolicy failure that is not NoSuchBucketPolicy → warning; ACL finding still emitted", async () => {
    mocks.aliOssClient.mockResolvedValue(
      fakeOss([{ name: "x", region: "oss-cn-hangzhou", acl: "public-read" }], {
        getBucketPolicy: async () => {
          throw ossError(503, "ServiceUnavailable", "Please try again.");
        },
      }),
    );
    routeAliCall(mocks.aliCall, RDS_EMPTY);
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceId)).toEqual(["x"]);
    expect(r.warnings?.some((w) => w.startsWith("OSS bucket x GetBucketPolicy"))).toBe(true);
  });
});

/* ------------------------------------------------------------------------ */
/* RDS                                                                      */
/* ------------------------------------------------------------------------ */

describe("RDS instances", () => {
  beforeEach(() => {
    mocks.aliOssClient.mockResolvedValue(fakeOss([]));
  });

  const INSTANCES = {
    Items: {
      DBInstance: [
        { DBInstanceId: "rm-open", Engine: "MySQL" },
        { DBInstanceId: "rm-pubonly", Engine: "PostgreSQL" },
        { DBInstanceId: "rm-private", Engine: "MySQL" },
      ],
    },
    TotalRecordCount: 3,
  };
  const NET: Record<string, unknown> = {
    "rm-open": netInfo({ type: "Private", cs: "rm-open.mysql.rds.aliyuncs.com" }, { type: "Public", cs: "rm-openo.mysql.rds.aliyuncs.com" }),
    "rm-pubonly": netInfo({ type: "Public", cs: "pgm-pub.pg.rds.aliyuncs.com", port: "5432" }),
    "rm-private": netInfo({ type: "Private", cs: "rm-private.mysql.rds.aliyuncs.com" }),
  };
  const IPS: Record<string, unknown> = {
    "rm-open": ipArray({ name: "default", list: "127.0.0.1" }, { name: "app", list: "10.0.0.0/8,0.0.0.0/0" }),
    "rm-pubonly": ipArray({ name: "default", list: "203.0.113.10" }),
  };

  it("public + open whitelist → HIGH; public only → MEDIUM; private → none", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeDBInstances: INSTANCES,
      DescribeDBInstanceNetInfo: (q) => NET[q.DBInstanceId as string],
      DescribeDBInstanceIPArrayList: (q) => IPS[q.DBInstanceId as string],
    });

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.resourcesScanned).toBe(3);
    expect(r.findingsCount).toBe(2);
    const open = r.findings.find((f) => f.resourceId === "rm-open")!;
    expect(open.severity).toBe("HIGH");
    expect(open.riskScore).toBe(8.0);
    expect(open.resourceType).toBe("ACS::RDS::DBInstance");
    expect(open.resourceArn).toBe(`acs:rds:cn-hangzhou:${UID}:dbinstance/rm-open`);
    expect(open.description).toContain("rm-openo.mysql.rds.aliyuncs.com:3306");
    expect(open.description).toContain("app");
    const pub = r.findings.find((f) => f.resourceId === "rm-pubonly")!;
    expect(pub.severity).toBe("MEDIUM");
    expect(pub.description).toContain("pgm-pub.pg.rds.aliyuncs.com:5432");

    // per-instance N+1: NetInfo for every instance, IP array only for public ones
    expect(callsFor(mocks.aliCall, "DescribeDBInstanceNetInfo").map((c) => c[2].DBInstanceId).sort()).toEqual(["rm-open", "rm-private", "rm-pubonly"]);
    expect(callsFor(mocks.aliCall, "DescribeDBInstanceIPArrayList").map((c) => c[2].DBInstanceId).sort()).toEqual(["rm-open", "rm-pubonly"]);
    // RegionId + region on the call context
    const list = callsFor(mocks.aliCall, "DescribeDBInstances")[0];
    expect(list[0].service).toBe("rds");
    expect(list[2].RegionId).toBe("cn-hangzhou");
    expect(list[1].region).toBe("cn-hangzhou");
  });

  it("DescribeDBInstances PageNumber pagination (TotalRecordCount)", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeDBInstances: (q) =>
        q.PageNumber === 1
          ? { Items: { DBInstance: [{ DBInstanceId: "rm-1" }] }, TotalRecordCount: 2, PageNumber: 1 }
          : { Items: { DBInstance: [{ DBInstanceId: "rm-2" }] }, TotalRecordCount: 2, PageNumber: 2 },
      DescribeDBInstanceNetInfo: netInfo({ type: "Public", cs: "x.mysql.rds.aliyuncs.com" }),
      DescribeDBInstanceIPArrayList: ipArray({ name: "default", list: "%" }),
    });

    const r = await scanner.scan(aliCtx());
    expect(callsFor(mocks.aliCall, "DescribeDBInstances").map((c) => c[2].PageNumber)).toEqual([1, 2]);
    expect(r.findings.map((f) => f.resourceId).sort()).toEqual(["rm-1", "rm-2"]);
    expect(r.findings.every((f) => f.severity === "HIGH")).toBe(true);
  });

  it("access denied on DescribeDBInstances → warning, success", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeDBInstances: () => {
        throw deniedError("rds:DescribeDBInstances");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings?.some((w) => /^RDS DescribeDBInstances: insufficient permissions/.test(w))).toBe(true);
  });

  it("access denied on the IP whitelist → public-only MEDIUM finding + warning", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeDBInstances: { Items: { DBInstance: [{ DBInstanceId: "rm-x" }] }, TotalRecordCount: 1 },
      DescribeDBInstanceNetInfo: netInfo({ type: "Public", cs: "rm-x.mysql.rds.aliyuncs.com" }),
      DescribeDBInstanceIPArrayList: () => {
        throw deniedError("rds:DescribeDBInstanceIPArrayList");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings[0].severity).toBe("MEDIUM");
    expect(r.findings[0].description).toContain("could not be read");
    expect(r.warnings?.some((w) => w.startsWith("RDS rm-x DescribeDBInstanceIPArrayList"))).toBe(true);
  });

  it("auth_failed (404 InvalidAccessKeyId.NotFound) → module status error, never 'not enabled'", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeDBInstances: () => {
        throw authError("rds:DescribeDBInstances");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
    expect(r.error).toContain("InvalidAccessKeyId.NotFound");
    noSecrets(r);
  });

  it("auth_failed on a per-instance call → module status error", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeDBInstances: { Items: { DBInstance: [{ DBInstanceId: "rm-1" }] }, TotalRecordCount: 1 },
      DescribeDBInstanceNetInfo: () => {
        throw authError("rds:DescribeDBInstanceNetInfo");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
  });

  it("api_misuse → module status error (not swallowed)", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeDBInstances: () => {
        throw misuseError("rds:DescribeDBInstances");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toContain("RDS public access check failed");
    expect(r.error).toContain("MissingParameter");
  });
});

describe("registration", () => {
  it("alicloud provider exposes public_access_verify as a regional module", () => {
    const p = alibabaCloudProvider;
    expect(p.scanners().some((s) => s.moduleName === "public_access_verify")).toBe(true);
    expect(p.globalModules?.has("public_access_verify")).toBe(false);
  });
});
