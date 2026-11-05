/**
 * Phase 2 T5 — AliTagComplianceScanner (tag_compliance): required tags (AWS
 * DEFAULT_REQUIRED_TAGS) on ECS instances / disks, SLB, RDS (region-level DescribeTags) and
 * OSS (getBucketTags per bucket); pagination, degrade, auth_failed / api_misuse → error,
 * redaction. aliCall and the OSS client factory are mocked; fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn(), aliOssClient: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall, aliOssClient: mocks.aliOssClient };
});

import {
  AliTagComplianceScanner,
  aliTagKeys,
  missingRequiredTags,
  rdsTagMap,
  TAG_OSS_MAX_BUCKETS,
} from "../../../../src/providers/alicloud/scanners/tag-compliance.js";
import { DEFAULT_REQUIRED_TAGS } from "../../../../src/scanners/tag-compliance.js";
import { alibabaCloudProvider } from "../../../../src/providers/alicloud/index.js";
import {
  aliCtx,
  authError,
  callsFor,
  deniedError,
  FAKE_AK,
  isolateAliEnv,
  misuseError,
  restoreAliEnv,
  routeAliCall,
  UID,
  type AliHandler,
} from "./helpers.js";

const scanner = new AliTagComplianceScanner();

const ecsTags = (tags: Record<string, string>) => ({ Tag: Object.entries(tags).map(([TagKey, TagValue]) => ({ TagKey, TagValue })) });
const FULL = { Environment: "prod", Project: "shop", Owner: "ops" };

const instancesBody = (insts: object[], total = insts.length) => ({ Instances: { Instance: insts }, TotalCount: total });
const disksBody = (disks: object[], total = disks.length) => ({ Disks: { Disk: disks }, TotalCount: total });
const slbBody = (lbs: object[], total = lbs.length) => ({ LoadBalancers: { LoadBalancer: lbs }, TotalCount: total });
const rdsBody = (dbs: object[], total = dbs.length) => ({ Items: { DBInstance: dbs }, TotalRecordCount: total });
const rdsTagsBody = (infos: Array<{ key: string; value?: string; ids: string[] }>) => ({
  Items: { TagInfos: infos.map((i) => ({ TagKey: i.key, TagValue: i.value ?? "v", DBInstanceIds: { DBInstanceIds: i.ids } })) },
});

const EMPTY: Record<string, AliHandler | object> = {
  DescribeInstances: instancesBody([]),
  DescribeDisks: disksBody([]),
  DescribeLoadBalancers: slbBody([]),
  DescribeDBInstances: rdsBody([]),
  DescribeTags: rdsTagsBody([]),
};

/** ali-oss style error (own keys: name, message, status, code, requestId). */
function ossError(status: number, code: string, message: string): Error {
  const e = new Error(message) as Error & Record<string, unknown>;
  e.name = `${code}Error`;
  e.status = status;
  e.code = code;
  e.requestId = "5F1A2B3C4D5E6F7A8B9C0D1E";
  return e;
}

interface FakeBucket {
  name: string;
  region?: string;
  /** undefined → NoSuchTagSet */
  tags?: Record<string, string>;
  error?: Error;
}

function fakeOss(buckets: FakeBucket[]) {
  const byName = new Map(buckets.map((b) => [b.name, b]));
  return {
    listBuckets: vi.fn(async () => ({ buckets: buckets.map((b) => ({ name: b.name, region: b.region })), isTruncated: false, nextMarker: null })),
    getBucketTags: vi.fn(async (name: string) => {
      const b = byName.get(name)!;
      if (b.error) throw b.error;
      if (b.tags === undefined) throw ossError(404, "NoSuchTagSet", "There is no tag set.");
      return { status: 200, tag: { ...b.tags } };
    }),
  };
}

beforeEach(() => {
  isolateAliEnv();
  mocks.aliCall.mockReset();
  mocks.aliOssClient.mockReset();
  mocks.aliOssClient.mockResolvedValue(fakeOss([]));
});
afterEach(() => restoreAliEnv());

describe("tag_compliance — helpers", () => {
  it("reuses the AWS DEFAULT_REQUIRED_TAGS; case-sensitive keys", () => {
    expect(DEFAULT_REQUIRED_TAGS).toEqual(["Environment", "Project", "Owner"]);
    expect(missingRequiredTags(["Environment", "Project", "Owner"])).toEqual([]);
    expect(missingRequiredTags(["environment", "Project"])).toEqual(["Environment", "Owner"]);
    expect(missingRequiredTags([])).toEqual(["Environment", "Project", "Owner"]);
  });

  it("aliTagKeys handles Tags.Tag[] (TagKey / Key), bare arrays, empty and absent containers", () => {
    expect(aliTagKeys({ Tag: [{ TagKey: "A", TagValue: "1" }, { Key: "B", Value: "2" }] })).toEqual(["A", "B"]);
    expect(aliTagKeys([{ TagKey: "C" }])).toEqual(["C"]);
    expect(aliTagKeys({ Tag: { TagKey: "single" } })).toEqual(["single"]);
    expect(aliTagKeys({})).toEqual([]);
    expect(aliTagKeys({ Tag: [] })).toEqual([]);
    expect(aliTagKeys(undefined)).toBeUndefined();
  });

  it("rdsTagMap builds instance → keys from Items.TagInfos[]", () => {
    const m = rdsTagMap(rdsTagsBody([{ key: "Environment", ids: ["rm-1", "rm-2"] }, { key: "Owner", ids: ["rm-1"] }]));
    expect(m.get("rm-1")).toEqual(["Environment", "Owner"]);
    expect(m.get("rm-2")).toEqual(["Environment"]);
    expect(m.get("rm-3")).toBeUndefined();
    expect(rdsTagMap({}).size).toBe(0);
  });
});

describe("tag_compliance — per resource type", () => {
  it("normal hit: missing vs present across ECS / disk / SLB / RDS / OSS", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: instancesBody([
        { InstanceId: "i-ok", InstanceName: "ok", Tags: ecsTags(FULL) },
        { InstanceId: "i-miss", InstanceName: "web", Tags: ecsTags({ Environment: "prod", Project: "shop" }) },
      ]),
      DescribeDisks: disksBody([{ DiskId: "d-none", DiskName: "data" }]),
      DescribeLoadBalancers: slbBody([
        { LoadBalancerId: "lb-ok", LoadBalancerName: "ok", Tags: ecsTags(FULL) },
        { LoadBalancerId: "lb-lower", LoadBalancerName: "lower", Tags: ecsTags({ environment: "prod", Project: "p", Owner: "o" }) },
      ]),
      DescribeDBInstances: rdsBody([{ DBInstanceId: "rm-ok", Engine: "MySQL" }, { DBInstanceId: "rm-miss", Engine: "MySQL" }]),
      DescribeTags: rdsTagsBody([
        { key: "Environment", ids: ["rm-ok", "rm-miss"] },
        { key: "Project", ids: ["rm-ok"] },
        { key: "Owner", ids: ["rm-ok"] },
      ]),
    });
    const oss = fakeOss([
      { name: "bkt-ok", region: "cn-hangzhou", tags: FULL },
      { name: "bkt-partial", region: "cn-hangzhou", tags: { Owner: "x" } },
      { name: "bkt-none", region: "cn-hangzhou" },
      { name: "bkt-other-region", region: "cn-beijing" },
    ]);
    mocks.aliOssClient.mockResolvedValue(oss);

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.module).toBe("tag_compliance");
    expect(r.resourcesScanned).toBe(2 + 1 + 2 + 2 + 3);
    const byId = new Map(r.findings.map((f) => [f.resourceId, f]));
    expect([...byId.keys()].sort()).toEqual(["bkt-none", "bkt-partial", "d-none", "i-miss", "lb-lower", "rm-miss"]);

    for (const f of r.findings) {
      expect(f.riskScore).toBe(4.0);
      expect(f.severity).toBe("MEDIUM");
      expect(f.provider).toBe("alicloud");
      expect(f.region).toBe("cn-hangzhou");
    }

    const inst = byId.get("i-miss")!;
    expect(inst.title).toBe("ECS instance i-miss missing required tags: Owner");
    expect(inst.resourceType).toBe("ACS::ECS::Instance");
    expect(inst.resourceArn).toBe(`acs:ecs:cn-hangzhou:${UID}:instance/i-miss`);

    const disk = byId.get("d-none")!;
    expect(disk.title).toBe("ECS disk d-none missing required tags: Environment, Project, Owner");
    expect(disk.description).toContain("has no tags configured");
    expect(disk.resourceArn).toBe(`acs:ecs:cn-hangzhou:${UID}:disk/d-none`);

    const lb = byId.get("lb-lower")!;
    expect(lb.title).toBe("SLB load balancer lb-lower missing required tags: Environment");
    expect(lb.resourceType).toBe("ACS::SLB::LoadBalancer");
    expect(lb.resourceArn).toBe(`acs:slb:cn-hangzhou:${UID}:loadbalancer/lb-lower`);

    const db = byId.get("rm-miss")!;
    expect(db.title).toBe("RDS instance rm-miss missing required tags: Project, Owner");
    expect(db.resourceType).toBe("ACS::RDS::DBInstance");
    expect(db.resourceArn).toBe(`acs:rds:cn-hangzhou:${UID}:dbinstance/rm-miss`);

    expect(byId.get("bkt-partial")!.title).toBe("OSS bucket bkt-partial missing required tags: Environment, Project");
    expect(byId.get("bkt-none")!.title).toBe("OSS bucket bkt-none missing required tags: Environment, Project, Owner");
    expect(byId.get("bkt-none")!.resourceArn).toBe(`acs:oss:cn-hangzhou:${UID}:bucket/bkt-none`);

    // One region-level DescribeTags (no N+1), OSS tags only for in-region buckets.
    const tagCalls = callsFor(mocks.aliCall, "DescribeTags");
    expect(tagCalls).toHaveLength(1);
    expect(tagCalls[0][2]).toEqual({ RegionId: "cn-hangzhou" });
    expect(tagCalls[0][0].service).toBe("rds");
    expect(callsFor(mocks.aliCall, "DescribeLoadBalancers")[0][0].service).toBe("slb");
    expect(oss.getBucketTags.mock.calls.map((c) => c[0]).sort()).toEqual(["bkt-none", "bkt-ok", "bkt-partial"]);
  });

  it("no hit: every resource fully tagged → 0 findings", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeInstances: instancesBody([{ InstanceId: "i-1", Tags: ecsTags(FULL) }]),
      DescribeDisks: disksBody([{ DiskId: "d-1", Tags: ecsTags(FULL) }]),
      DescribeLoadBalancers: slbBody([{ LoadBalancerId: "lb-1", Tags: ecsTags(FULL) }]),
      DescribeDBInstances: rdsBody([{ DBInstanceId: "rm-1" }]),
      DescribeTags: rdsTagsBody(Object.keys(FULL).map((key) => ({ key, ids: ["rm-1"] }))),
    });
    mocks.aliOssClient.mockResolvedValue(fakeOss([{ name: "b1", region: "cn-hangzhou", tags: FULL }]));
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(5);
  });

  it("RDS inline tags are honoured; DescribeTags skipped when every instance has them; skipped entirely with no instances", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeDBInstances: rdsBody([{ DBInstanceId: "rm-inline", Tags: ecsTags(FULL) }]),
    });
    let r = await scanner.scan(aliCtx());
    expect(r.findings).toEqual([]);
    expect(callsFor(mocks.aliCall, "DescribeTags")).toHaveLength(0);

    mocks.aliCall.mockReset();
    routeAliCall(mocks.aliCall, EMPTY);
    r = await scanner.scan(aliCtx());
    expect(callsFor(mocks.aliCall, "DescribeTags")).toHaveLength(0);
  });

  it("OSS: region-less buckets checked on the primary scope only", async () => {
    routeAliCall(mocks.aliCall, EMPTY);
    const oss = fakeOss([{ name: "b-noregion" }]);
    mocks.aliOssClient.mockResolvedValue(oss);
    let r = await scanner.scan(aliCtx({ primaryRegionScope: false }));
    expect(r.findings).toEqual([]);
    expect(oss.getBucketTags).not.toHaveBeenCalled();
    r = await scanner.scan(aliCtx());
    expect(r.findings.map((f) => f.resourceId)).toEqual(["b-noregion"]);
  });

  it(`OSS: bucket cap TAG_OSS_MAX_BUCKETS (${TAG_OSS_MAX_BUCKETS}) with a warning`, async () => {
    routeAliCall(mocks.aliCall, EMPTY);
    const oss = fakeOss(Array.from({ length: TAG_OSS_MAX_BUCKETS + 3 }, (_, i) => ({ name: `b-${i}`, region: "cn-hangzhou", tags: FULL })));
    mocks.aliOssClient.mockResolvedValue(oss);
    const r = await scanner.scan(aliCtx());
    expect(oss.getBucketTags).toHaveBeenCalledTimes(TAG_OSS_MAX_BUCKETS);
    expect(r.warnings?.some((w) => w.includes(`only the first ${TAG_OSS_MAX_BUCKETS}`))).toBe(true);
  });
});

describe("tag_compliance — pagination", () => {
  it("paginates ECS disks, SLB and RDS (TotalRecordCount) over 2 pages", async () => {
    const many = (prefix: string, idKey: string, n: number) => Array.from({ length: n }, (_, i) => ({ [idKey]: `${prefix}-${i}`, Tags: ecsTags(FULL) }));
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeDisks: (q) => (q.PageNumber === 1 ? disksBody(many("d", "DiskId", 100), 101) : disksBody([{ DiskId: "d-last" }], 101)),
      DescribeLoadBalancers: (q) =>
        q.PageNumber === 1 ? slbBody(many("lb", "LoadBalancerId", 100), 101) : slbBody([{ LoadBalancerId: "lb-last" }], 101),
      DescribeDBInstances: (q) =>
        q.PageNumber === 1 ? rdsBody(many("rm", "DBInstanceId", 100), 101) : rdsBody([{ DBInstanceId: "rm-last" }], 101),
      DescribeTags: rdsTagsBody([]),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    for (const action of ["DescribeDisks", "DescribeLoadBalancers", "DescribeDBInstances"]) {
      expect(callsFor(mocks.aliCall, action).map((c) => c[2].PageNumber)).toEqual([1, 2]);
    }
    expect(r.findings.map((f) => f.resourceId).sort()).toEqual(["d-last", "lb-last", "rm-last"]);
    expect(r.resourcesScanned).toBe(303);
  });
});

describe("tag_compliance — errors", () => {
  it("access_denied on SLB → warning; other types still evaluated", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeInstances: instancesBody([{ InstanceId: "i-1" }]),
      DescribeLoadBalancers: () => {
        throw deniedError("slb:DescribeLoadBalancers");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceId)).toEqual(["i-1"]);
    expect(r.warnings?.some((w) => w.startsWith("SLB DescribeLoadBalancers: insufficient permissions"))).toBe(true);
  });

  it("access_denied on RDS DescribeTags → warning, RDS not reported (no false positives)", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeDBInstances: rdsBody([{ DBInstanceId: "rm-1" }]),
      DescribeTags: () => {
        throw deniedError("rds:DescribeTags");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings?.some((w) => w.startsWith("RDS DescribeTags") && w.includes("insufficient permissions"))).toBe(true);
  });

  it("OSS getBucketTags 403 AccessDenied on one bucket → warning, others evaluated", async () => {
    routeAliCall(mocks.aliCall, EMPTY);
    mocks.aliOssClient.mockResolvedValue(
      fakeOss([
        { name: "b-denied", region: "cn-hangzhou", error: ossError(403, "AccessDenied", "You have no right to access this object.") },
        { name: "b-none", region: "cn-hangzhou" },
      ]),
    );
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceId)).toEqual(["b-none"]);
    expect(r.warnings?.some((w) => w.startsWith("OSS bucket b-denied GetBucketTags: insufficient permissions"))).toBe(true);
  });

  it("auth_failed via OSS (403 InvalidAccessKeyId from ali-oss) → status error", async () => {
    routeAliCall(mocks.aliCall, EMPTY);
    mocks.aliOssClient.mockResolvedValue(
      fakeOss([{ name: "b-1", region: "cn-hangzhou", error: ossError(403, "InvalidAccessKeyId", "The OSS Access Key Id you provided does not exist in our records.") }]),
    );
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error?.startsWith("Alibaba Cloud authentication failed")).toBe(true);
    expect(JSON.stringify(r)).not.toContain(FAKE_AK);
  });

  it("auth_failed on ECS DescribeInstances → status error, later types not called", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeInstances: () => {
        throw authError("ecs:DescribeInstances");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error?.startsWith("Alibaba Cloud authentication failed")).toBe(true);
    expect(callsFor(mocks.aliCall, "DescribeDisks")).toHaveLength(0);
  });

  it("api_misuse on SLB → status error, not swallowed", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeLoadBalancers: () => {
        throw misuseError("slb:DescribeLoadBalancers");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toContain("SLB tag compliance check failed");
    expect(r.error).toContain("MissingParameter");
  });

  it("redaction: AK-looking instance id / name / tag key never reach the result", async () => {
    routeAliCall(mocks.aliCall, {
      ...EMPTY,
      DescribeInstances: instancesBody([{ InstanceId: `i-${FAKE_AK}`, InstanceName: FAKE_AK, Tags: ecsTags({ [FAKE_AK]: "x" }) }]),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings).toHaveLength(1);
    const text = JSON.stringify(r);
    expect(text).not.toContain(FAKE_AK);
    expect(text).toContain("[REDACTED]");
  });
});

describe("tag_compliance — registration", () => {
  it("is registered on the alicloud provider", () => {
    expect(alibabaCloudProvider.scanners().some((s) => s.moduleName === "tag_compliance")).toBe(true);
  });
});
