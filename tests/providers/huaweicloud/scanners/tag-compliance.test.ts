/**
 * HuaweiTagComplianceScanner (Huawei Cloud tag_compliance) — SDK client
 * factory + SDK package are mocked; no network, no credential file access.
 */
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll, afterEach } from "vitest";
import { inspect } from "util";

const { listAllResources, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock } = vi.hoisted(() => ({
  listAllResources: vi.fn(),
  hwClientMock: vi.fn(),
  loadHuaweiCredentialsMock: vi.fn(),
  resolveRegionScopeMock: vi.fn(),
}));

vi.mock("../../../../src/providers/huaweicloud/client.js", () => ({
  hwClient: hwClientMock,
  hwObsClient: vi.fn(),
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

import {
  HuaweiTagComplianceScanner,
  HW_TAG_RESOURCE_TYPES,
  RMS_RESOURCE_PAGE_SIZE,
  RMS_MAX_RESOURCES,
  getMissingRmsTags,
  type LooseRmsResource,
} from "../../../../src/providers/huaweicloud/scanners/tag-compliance.js";
import { DEFAULT_REQUIRED_TAGS } from "../../../../src/scanners/tag-compliance.js";
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

const FULL_TAGS = { Environment: "prod", Project: "sec", Owner: "will" };

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

/** Dispatch fixtures by RMS resource type; unknown types return an empty page. */
function installResources(byType: Record<string, Array<Record<string, unknown>>>) {
  listAllResources.mockImplementation(async (req: { type: string }) => ({
    resources: byType[req.type] ?? [],
    page_info: { current_count: (byType[req.type] ?? []).length },
  }));
}

describe("HuaweiTagComplianceScanner (tag_compliance)", () => {
  const scanner = new HuaweiTagComplianceScanner();

  beforeEach(() => {
    listAllResources.mockReset();
    hwClientMock.mockReset();
    hwClientMock.mockResolvedValue({ listAllResources });
    loadHuaweiCredentialsMock.mockReset();
    resolveRegionScopeMock.mockReset();
    installResources({});
  });

  it("is registered on the huaweicloud provider under the AWS module name and reuses DEFAULT_REQUIRED_TAGS", () => {
    expect(scanner.moduleName).toBe("tag_compliance");
    expect(huaweiCloudProvider.scanners().map((s) => s.moduleName)).toContain("tag_compliance");
    expect(DEFAULT_REQUIRED_TAGS).toEqual(["Environment", "Project", "Owner"]); // AWS default unchanged
    expect(HW_TAG_RESOURCE_TYPES).toEqual(["ecs.cloudservers", "rds.instances", "obs.buckets", "evs.volumes"]);
  });

  it("flags resources missing required tags (4.0) and skips fully tagged ones; queries RMS per resource type with region_id", async () => {
    installResources({
      "ecs.cloudservers": [
        { id: "srv-1", name: "web", provider: "ecs", type: "cloudservers", region_id: "cn-north-4", tags: FULL_TAGS },
        { id: "srv-2", name: "db-proxy", provider: "ecs", type: "cloudservers", region_id: "cn-north-4", tags: { Environment: "prod" } },
        { id: "srv-3", provider: "ecs", type: "cloudservers", region_id: "cn-north-4", tags: {} },
      ],
      "rds.instances": [
        { id: "rds-1", name: "orders", provider: "rds", type: "instances", region_id: "cn-north-4", tags: { ...FULL_TAGS, Extra: "x" } },
        { id: "rds-2", name: "legacy", provider: "rds", type: "instances", region_id: "cn-north-4", tags: null },
      ],
      "obs.buckets": [
        { id: "my-bucket", name: "my-bucket", provider: "obs", type: "buckets", region_id: "cn-north-4", tags: { environment: "prod", Project: "p", Owner: "o" } }, // case-sensitive
      ],
      "evs.volumes": [
        { id: "vol-1", name: "data", provider: "evs", type: "volumes", region_id: "cn-north-4", tags: [{ key: "Environment", value: "prod" }, { key: "Project", value: "p" }, { key: "Owner", value: "o" }] },
      ],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.error).toBeUndefined();
    expect(result.warnings).toBeUndefined();
    expect(result.resourcesScanned).toBe(7);
    expect(result.findingsCount).toBe(4);

    const byId = new Map(result.findings.map((f) => [f.resourceId, f]));
    expect(byId.get("srv-2")).toMatchObject({
      riskScore: 4.0,
      severity: "MEDIUM",
      resourceType: "HuaweiCloud::ECS::CloudServer",
      resourceArn: `hws:cn-north-4:${DOMAIN}:ecs:cloudservers:srv-2`,
      region: "cn-north-4",
      provider: "huaweicloud",
    });
    expect(byId.get("srv-2")!.title).toBe("ECS server srv-2 (db-proxy) missing required tags: Project, Owner");
    expect(byId.get("srv-3")!.title).toBe("ECS server srv-3 missing required tags: Environment, Project, Owner");
    expect(byId.get("srv-3")!.description).toContain("has no tags configured");
    expect(byId.get("rds-2")).toMatchObject({ resourceType: "HuaweiCloud::RDS::Instance", resourceArn: `hws:cn-north-4:${DOMAIN}:rds:instances:rds-2` });
    expect(byId.get("my-bucket")).toMatchObject({ resourceType: "HuaweiCloud::OBS::Bucket" });
    expect(byId.get("my-bucket")!.title).toBe("OBS bucket my-bucket missing required tags: Environment");
    expect(byId.has("srv-1")).toBe(false);
    expect(byId.has("rds-1")).toBe(false);
    expect(byId.has("vol-1")).toBe(false);

    // Global RMS client with domain ID + global credentials; one request per resource type, region-filtered.
    expect(hwClientMock).toHaveBeenCalledTimes(1);
    expect(hwClientMock.mock.calls[0][1]).toBe("rms");
    expect(hwClientMock.mock.calls[0][2]).toBe(creds);
    expect(hwClientMock.mock.calls[0][3]).toEqual({ region: "cn-north-4", domainId: DOMAIN });
    expect(listAllResources).toHaveBeenCalledTimes(4);
    expect(listAllResources.mock.calls.map((c) => c[0])).toEqual(
      HW_TAG_RESOURCE_TYPES.map((type) => ({ region_id: "cn-north-4", type, limit: RMS_RESOURCE_PAGE_SIZE })),
    );
    expect(loadHuaweiCredentialsMock).not.toHaveBeenCalled();
  });

  it("paginates via page_info.next_marker (2 pages) and caps with a truncation warning", async () => {
    const page1 = Array.from({ length: RMS_RESOURCE_PAGE_SIZE }, (_, i) => ({ id: `srv-${i}`, provider: "ecs", type: "cloudservers", tags: FULL_TAGS }));
    const page2 = [{ id: "srv-last", provider: "ecs", type: "cloudservers", tags: { Owner: "x" } }];
    listAllResources.mockImplementation(async (req: { type: string; marker?: string }) => {
      if (req.type !== "ecs.cloudservers") return { resources: [], page_info: { current_count: 0 } };
      if (req.marker === undefined) return { resources: page1, page_info: { next_marker: "m1", current_count: page1.length } };
      return { resources: page2, page_info: { current_count: 1 } };
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(listAllResources).toHaveBeenCalledTimes(2 + 3);
    expect(listAllResources.mock.calls[0][0]).toEqual({ region_id: "cn-north-4", type: "ecs.cloudservers", limit: RMS_RESOURCE_PAGE_SIZE });
    expect(listAllResources.mock.calls[1][0]).toEqual({ region_id: "cn-north-4", type: "ecs.cloudservers", limit: RMS_RESOURCE_PAGE_SIZE, marker: "m1" });
    expect(result.resourcesScanned).toBe(RMS_RESOURCE_PAGE_SIZE + 1);
    expect(result.findings.map((f) => f.resourceId)).toEqual(["srv-last"]);
    expect(result.findings[0].title).toBe("ECS server srv-last missing required tags: Environment, Project");
    expect(result.warnings).toBeUndefined();

    // Cap: an endless stream of pages stops at RMS_MAX_RESOURCES with a warning.
    listAllResources.mockReset();
    listAllResources.mockImplementation(async (req: { type: string; marker?: string }) => {
      const n = Number(req.marker ?? 0);
      return {
        resources: Array.from({ length: RMS_RESOURCE_PAGE_SIZE }, (_, i) => ({ id: `${req.type}-${n + i}`, tags: {} })),
        page_info: { next_marker: String(n + RMS_RESOURCE_PAGE_SIZE), current_count: RMS_RESOURCE_PAGE_SIZE },
      };
    });
    const capped = await scanner.scan(ctx);
    expect(capped.status).toBe("success");
    expect(capped.resourcesScanned).toBe(RMS_MAX_RESOURCES);
    expect(capped.findingsCount).toBe(RMS_MAX_RESOURCES);
    expect(capped.warnings).toEqual([`RMS: more than ${RMS_MAX_RESOURCES} resources in cn-north-4; only the first ${RMS_MAX_RESOURCES} were checked for tag compliance.`]);
  });

  it("honours a custom requiredTags option without touching the AWS default", async () => {
    const custom = new HuaweiTagComplianceScanner({ requiredTags: ["CostCenter"], resourceTypes: ["ecs.cloudservers"] });
    installResources({
      "ecs.cloudservers": [
        { id: "srv-a", provider: "ecs", type: "cloudservers", tags: { CostCenter: "42" } },
        { id: "srv-b", provider: "ecs", type: "cloudservers", tags: FULL_TAGS },
      ],
    });

    const result = await custom.scan(ctx);

    expect(result.status).toBe("success");
    expect(listAllResources).toHaveBeenCalledTimes(1);
    expect(result.findings.map((f) => f.resourceId)).toEqual(["srv-b"]);
    expect(result.findings[0].title).toBe("ECS server srv-b missing required tags: CostCenter");
    expect(DEFAULT_REQUIRED_TAGS).toEqual(["Environment", "Project", "Owner"]);
  });

  it("degrades gracefully on 403 (success, warning, 0 findings) and never surfaces the Authorization header", async () => {
    listAllResources.mockRejectedValueOnce({ httpStatusCode: 403, errorCode: "RMS.0003", errorMsg: "no permission", requestId: "r-rms" });

    const denied = await scanner.scan(ctx);
    expect(denied.status).toBe("success");
    expect(denied.findingsCount).toBe(0);
    expect(denied.warnings).toEqual(["RMS: insufficient permissions (HTTP 403 | RMS.0003 | no permission | requestId=r-rms); skipped"]);

    listAllResources.mockRejectedValueOnce({
      status: 401,
      data: { error_code: "APIGW.0301", error_msg: "Incorrect IAM authentication information" },
      message: "Request failed with status code 401",
      config: { url: `https://rms.myhuaweicloud.com/v1/resource-manager/domains/${DOMAIN}/all-resources`, headers: { Authorization: FAKE_AUTH_HEADER } },
    });
    const raw = await scanner.scan(ctx);
    expect(raw.status).toBe("success");
    const serialized = JSON.stringify(raw);
    expect(serialized).toContain("APIGW.0301");
    expect(serialized).not.toContain("Authorization");
    expect(serialized).not.toContain(FAKE_AK);
  });

  it("treats RMS not enabled (404) as a warning and returns status error on unexpected failures", async () => {
    listAllResources.mockRejectedValueOnce({ httpStatusCode: 404, errorCode: "RMS.0002", errorMsg: "The tracker config does not exist." });
    const notEnabled = await scanner.scan(ctx);
    expect(notEnabled.status).toBe("success");
    expect(notEnabled.warnings).toHaveLength(1);
    expect(notEnabled.warnings![0]).toContain("RMS: service not enabled or not available");

    listAllResources.mockRejectedValueOnce({ httpStatusCode: 500, errorCode: "RMS.9999", errorMsg: "internal error" });
    const failed = await scanner.scan(ctx);
    expect(failed.status).toBe("error");
    expect(failed.error).toBe("Huawei Cloud tag compliance scan failed: HTTP 500 | RMS.9999 | internal error");
    expect(failed.findingsCount).toBe(0);
    expect(JSON.stringify(failed)).not.toContain(FAKE_AK);
  });

  it("resolves the domain ID via IAM when neither context nor credentials carry it, and errors without credentials", async () => {
    const noDomain = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK });
    resolveRegionScopeMock.mockResolvedValueOnce({ region: "cn-north-4", projectId: "p-north4", domainId: DOMAIN });
    const ok = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: "", credentials: noDomain });
    expect(ok.status).toBe("success");
    expect(resolveRegionScopeMock).toHaveBeenCalledWith(noDomain, "cn-north-4");
    expect(hwClientMock.mock.calls[0][3]).toEqual({ region: "cn-north-4", domainId: DOMAIN });

    loadHuaweiCredentialsMock.mockImplementationOnce(() => { throw new Error("Huawei Cloud credentials not found."); });
    const noCreds = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: DOMAIN, provider: "huaweicloud" });
    expect(noCreds.status).toBe("error");
    expect(noCreds.error).toContain("Huawei Cloud credentials not found");
    expect(hwClientMock).toHaveBeenCalledTimes(1);
  });

  it("getMissingRmsTags handles object tags, [{key,value}] tags, null and case-sensitivity", () => {
    const req = DEFAULT_REQUIRED_TAGS;
    expect(getMissingRmsTags(FULL_TAGS, req)).toEqual([]);
    expect(getMissingRmsTags({ Environment: "", Owner: "x" }, req)).toEqual(["Project"]);
    expect(getMissingRmsTags([{ key: "Project", value: "p" }] as LooseRmsResource["tags"], req)).toEqual(["Environment", "Owner"]);
    expect(getMissingRmsTags(null, req)).toEqual(["Environment", "Project", "Owner"]);
    expect(getMissingRmsTags(undefined, req)).toEqual(["Environment", "Project", "Owner"]);
    expect(getMissingRmsTags({ environment: "prod", project: "p", owner: "o" }, req)).toEqual(["Environment", "Project", "Owner"]);
  });
});
