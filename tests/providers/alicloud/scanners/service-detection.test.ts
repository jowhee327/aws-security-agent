/**
 * Phase 2 T2 — AliServiceDetectionScanner (service_detection): ActionTrail / Config /
 * Security Center (SAS) / WAF / KMS matrix — enabled, not enabled, access denied (null +
 * warning), auth_failed / api_misuse (module error) — plus maturity / coverage, findings,
 * site / region pass-through and the GetTrailStatus cap.
 * aliCall is mocked by spec.action; fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall };
});

import {
  AliServiceDetectionScanner,
  ALI_ACTIONTRAIL_MAX_STATUS_CHECKS,
  ALI_SERVICE_ACTIONTRAIL,
  ALI_SERVICE_CONFIG,
  ALI_SERVICE_KMS,
  ALI_SERVICE_ORDER,
  ALI_SERVICE_RECOMMENDATIONS,
  ALI_SERVICE_SAS,
  ALI_SERVICE_WAF,
  aliWafRegionId,
} from "../../../../src/providers/alicloud/scanners/service-detection.js";
import type { ServiceDetectionResult } from "../../../../src/scanners/service-detection.js";
import type { ScanResult } from "../../../../src/types.js";
import {
  aliCtx,
  authError,
  callsFor,
  deniedError,
  FAKE_SK,
  isolateAliEnv,
  misuseError,
  notEnabledError,
  restoreAliEnv,
  routeAliCall,
  type AliHandler,
} from "./helpers.js";

beforeEach(() => {
  isolateAliEnv();
  mocks.aliCall.mockReset();
});
afterEach(() => restoreAliEnv());

/** Every probe "enabled". */
const ENABLED: Record<string, AliHandler | object> = {
  DescribeTrails: { TrailList: [{ Name: "audit", Status: "Enable", HomeRegion: "cn-hangzhou", IsOrganizationTrail: false }] },
  GetTrailStatus: { IsLogging: true },
  GetConfigurationRecorder: { ConfigurationRecorder: { ConfigurationRecorderStatus: "REGISTERED", ResourceTypes: ["ACS::ECS::Instance"] } },
  DescribeVersionConfig: { Version: 5, IsTrialVersion: 0, InstanceId: "sas-1" },
  DescribeInstance: { InstanceId: "waf_v3prepaid_public_cn-1", Edition: "Pro", Status: 1, RegionId: "cn-hangzhou" },
  ListKmsInstances: { KmsInstances: { KmsInstance: [{ KmsInstanceId: "kst-1" }] }, TotalCount: 1 },
  ListKeys: { Keys: { Key: [] }, TotalCount: 0 },
};

/** Every probe "not enabled" (empty / free / unregistered bodies). */
const DISABLED: Record<string, AliHandler | object> = {
  DescribeTrails: { TrailList: [] },
  GetTrailStatus: { IsLogging: false },
  GetConfigurationRecorder: { ConfigurationRecorder: { ConfigurationRecorderStatus: "UNREGISTERED" } },
  DescribeVersionConfig: { Version: 1 },
  DescribeInstance: {},
  ListKmsInstances: { KmsInstances: { KmsInstance: [] }, TotalCount: 0 },
  ListKeys: { Keys: { Key: [] }, TotalCount: 0 },
};

/** Actions probed per service (all of them fail together for the error matrix). */
const SERVICE_ACTIONS: Record<string, string[]> = {
  [ALI_SERVICE_ACTIONTRAIL]: ["DescribeTrails"],
  [ALI_SERVICE_CONFIG]: ["GetConfigurationRecorder"],
  [ALI_SERVICE_SAS]: ["DescribeVersionConfig"],
  [ALI_SERVICE_WAF]: ["DescribeInstance"],
  [ALI_SERVICE_KMS]: ["ListKmsInstances", "ListKeys"],
};

const scanner = new AliServiceDetectionScanner();

async function run(handlers: Record<string, AliHandler | object>, ctxOverrides = {}) {
  routeAliCall(mocks.aliCall, handlers);
  const r = (await scanner.scan(aliCtx(ctxOverrides))) as ScanResult & { serviceDetection?: ServiceDetectionResult };
  return r;
}

const svc = (r: { serviceDetection?: ServiceDetectionResult }, name: string) => r.serviceDetection!.services.find((s) => s.name === name)!;

const failing = (service: string, make: (api: string) => Error) =>
  Object.fromEntries(SERVICE_ACTIONS[service].map((a) => [a, () => { throw make(`svc:${a}`); }]));

describe("AliServiceDetectionScanner", () => {
  it("has the shared moduleName and a fixed service order", () => {
    expect(scanner.moduleName).toBe("service_detection");
    expect(ALI_SERVICE_ORDER).toEqual(["ActionTrail", "Config", "Security Center (SAS)", "WAF", "KMS"]);
    expect(aliWafRegionId("cn")).toBe("cn-hangzhou");
    expect(aliWafRegionId("intl")).toBe("ap-southeast-1");
  });

  it("all services enabled → 100% coverage, comprehensive, no findings (normal hit)", async () => {
    const r = await run(ENABLED);
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(5);
    const d = r.serviceDetection!;
    expect(d.services.map((s) => s.name)).toEqual([...ALI_SERVICE_ORDER]);
    expect(d.services.every((s) => s.enabled === true)).toBe(true);
    expect(d.coveragePercent).toBe(100);
    expect(d.maturityLevel).toBe("comprehensive");
    expect(svc(r, ALI_SERVICE_SAS).details).toBe("Advanced Edition");
    expect(svc(r, ALI_SERVICE_KMS).details).toBe("1 KMS instance(s)");
    // ListKeys is only a fallback.
    expect(callsFor(mocks.aliCall, "ListKeys")).toHaveLength(0);
  });

  it("all services not enabled → 0% coverage, basic, Config + SAS findings (no hit)", async () => {
    const r = await run(DISABLED);
    expect(r.status).toBe("success");
    const d = r.serviceDetection!;
    expect(d.services.every((s) => s.enabled === false)).toBe(true);
    for (const s of d.services) expect(s.recommendation).toBe(ALI_SERVICE_RECOMMENDATIONS[s.name]);
    expect(d.coveragePercent).toBe(0);
    expect(d.maturityLevel).toBe("basic");
    expect(r.findings.map((f) => f.title)).toEqual([
      "Alibaba Cloud Config resource recorder is not enabled",
      "Alibaba Cloud Security Center (SAS) paid edition is not enabled",
    ]);
    expect(r.findings.map((f) => f.severity)).toEqual(["MEDIUM", "HIGH"]);
    expect(r.findings.every((f) => f.provider === "alicloud" && f.module === "service_detection")).toBe(true);
    expect(r.findings[0].resourceArn).toBe("acs:config::1234567890123456:recorder/default");
    expect(svc(r, ALI_SERVICE_SAS).details).toContain("Free Edition");
  });

  it("passes the scan region to regional probes and the site / WAF RegionId to centralised ones", async () => {
    process.env.ALIBABA_CLOUD_SITE = "intl";
    await run(ENABLED, { region: "ap-southeast-1" });
    expect(callsFor(mocks.aliCall, "DescribeTrails")[0][1]).toMatchObject({ region: "ap-southeast-1", site: "intl" });
    expect(callsFor(mocks.aliCall, "ListKmsInstances")[0][1]).toMatchObject({ region: "ap-southeast-1" });
    expect(callsFor(mocks.aliCall, "GetConfigurationRecorder")[0][1]).toMatchObject({ site: "intl" });
    expect(callsFor(mocks.aliCall, "GetConfigurationRecorder")[0][1].region).toBeUndefined();
    const [, wafCtx, wafQuery] = callsFor(mocks.aliCall, "DescribeInstance")[0];
    expect(wafCtx).toMatchObject({ site: "intl" });
    expect(wafQuery).toEqual({ RegionId: "ap-southeast-1" });
  });

  describe("per-service matrix", () => {
    it.each(ALI_SERVICE_ORDER)("%s: not_enabled error → enabled=false + recommendation", async (name) => {
      const r = await run({ ...ENABLED, ...failing(name, notEnabledError) });
      expect(r.status).toBe("success");
      const s = svc(r, name);
      expect(s.enabled).toBe(false);
      expect(s.recommendation).toBe(ALI_SERVICE_RECOMMENDATIONS[name]);
      for (const other of ALI_SERVICE_ORDER.filter((n) => n !== name)) expect(svc(r, other).enabled).toBe(true);
      expect(r.serviceDetection!.maturityLevel).toBe("advanced");
    });

    it.each(ALI_SERVICE_ORDER)("%s: access_denied (403) → enabled=null + permissions warning", async (name) => {
      const r = await run({ ...ENABLED, ...failing(name, deniedError) });
      expect(r.status).toBe("success");
      expect(svc(r, name)).toMatchObject({ enabled: null, details: "Access denied" });
      expect(r.warnings).toHaveLength(1);
      expect(r.warnings![0]).toMatch(new RegExp(`^${name.replace(/[()]/g, "\\$&")}: insufficient permissions to check status`));
      expect(r.findings).toEqual([]);
      // Unknown services are excluded from coverage.
      expect(r.serviceDetection!.coveragePercent).toBe(100);
    });

    it.each(ALI_SERVICE_ORDER)("%s: auth_failed (404 InvalidAccessKeyId.NotFound) → module status error", async (name) => {
      const r = await run({ ...ENABLED, ...failing(name, authError) });
      expect(r.status).toBe("error");
      expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
      expect(r.findings).toEqual([]);
      expect(JSON.stringify(r)).not.toContain(FAKE_SK);
    });

    it.each(ALI_SERVICE_ORDER)("%s: api_misuse → module status error", async (name) => {
      const r = await run({ ...ENABLED, ...failing(name, misuseError) });
      expect(r.status).toBe("error");
      expect(r.error).toContain("Alibaba Cloud service detection failed");
      expect(r.error).toContain("MissingParameter");
    });
  });

  it("other errors (e.g. throttled) → enabled=null + detection warning", async () => {
    const throttled = () => {
      throw Object.assign(new Error("Request was denied due to user flow control."), { code: "Throttling.User", statusCode: 429 });
    };
    const r = await run({ ...ENABLED, DescribeVersionConfig: throttled });
    expect(r.status).toBe("success");
    expect(svc(r, ALI_SERVICE_SAS)).toMatchObject({ enabled: null, details: "Detection error" });
    expect(r.warnings?.[0]).toMatch(/^Security Center \(SAS\) detection failed:/);
  });

  describe("ActionTrail", () => {
    it("trails present but none logging → disabled", async () => {
      const r = await run({ ...ENABLED, GetTrailStatus: { IsLogging: false } });
      expect(svc(r, ALI_SERVICE_ACTIONTRAIL)).toMatchObject({ enabled: false, details: "1 trail(s) configured but none is logging" });
    });

    it("GetTrailStatus denied → falls back to DescribeTrails Status", async () => {
      const r = await run({
        ...ENABLED,
        DescribeTrails: { TrailList: [{ Name: "a", Status: "Enable" }, { Name: "b", Status: "Disable" }] },
        GetTrailStatus: () => { throw deniedError("actiontrail:GetTrailStatus"); },
      });
      expect(svc(r, ALI_SERVICE_ACTIONTRAIL)).toMatchObject({ enabled: true, details: "1 of 2 trail(s) logging" });
      expect(r.warnings).toBeUndefined();
    });

    it("GetTrailStatus auth_failed → module status error", async () => {
      const r = await run({ ...ENABLED, GetTrailStatus: () => { throw authError("actiontrail:GetTrailStatus"); } });
      expect(r.status).toBe("error");
      expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
    });

    it(`checks at most ${ALI_ACTIONTRAIL_MAX_STATUS_CHECKS} trails via GetTrailStatus (rest use Status)`, async () => {
      const trails = Array.from({ length: ALI_ACTIONTRAIL_MAX_STATUS_CHECKS + 3 }, (_, i) => ({ Name: `t${i}`, Status: "Enable" }));
      const r = await run({ ...ENABLED, DescribeTrails: { TrailList: trails }, GetTrailStatus: { IsLogging: false } });
      expect(callsFor(mocks.aliCall, "GetTrailStatus")).toHaveLength(ALI_ACTIONTRAIL_MAX_STATUS_CHECKS);
      expect(svc(r, ALI_SERVICE_ACTIONTRAIL)).toMatchObject({ enabled: true, details: `3 of ${trails.length} trail(s) logging` });
    });

    it("passes the organization-trail flag to GetTrailStatus", async () => {
      await run({ ...ENABLED, DescribeTrails: { TrailList: [{ Name: "org", Status: "Enable", IsOrganizationTrail: true }] } });
      expect(callsFor(mocks.aliCall, "GetTrailStatus")[0][2]).toEqual({ Name: "org", IsOrganizationTrail: true });
    });
  });

  describe("SAS editions", () => {
    it("value-added only (10) → low maturity, disabled", async () => {
      const r = await run({ ...ENABLED, DescribeVersionConfig: { Version: 10 } });
      expect(svc(r, ALI_SERVICE_SAS).enabled).toBe(false);
      expect(r.findings).toHaveLength(1);
    });

    it("missing Version → disabled", async () => {
      const r = await run({ ...ENABLED, DescribeVersionConfig: {} });
      expect(svc(r, ALI_SERVICE_SAS).enabled).toBe(false);
    });

    it("trial of a paid edition → enabled, noted", async () => {
      const r = await run({ ...ENABLED, DescribeVersionConfig: { Version: 3, IsTrialVersion: 1 } });
      expect(svc(r, ALI_SERVICE_SAS)).toMatchObject({ enabled: true, details: "Enterprise Edition (trial)" });
    });
  });

  describe("WAF", () => {
    it.each([
      [2, "expired"],
      [3, "released"],
    ])("Status %s → disabled (%s)", async (status, word) => {
      const r = await run({ ...ENABLED, DescribeInstance: { InstanceId: "waf-1", Status: status } });
      expect(svc(r, ALI_SERVICE_WAF).enabled).toBe(false);
      expect(svc(r, ALI_SERVICE_WAF).details).toContain(word);
    });
  });

  describe("KMS", () => {
    it("no KMS instance but customer keys → enabled via ListKeys", async () => {
      const r = await run({
        ...ENABLED,
        ListKmsInstances: { KmsInstances: { KmsInstance: [] }, TotalCount: 0 },
        ListKeys: { Keys: { Key: [{ KeyId: "key-1" }, { KeyId: "key-2" }] }, TotalCount: 2 },
      });
      expect(svc(r, ALI_SERVICE_KMS)).toMatchObject({ enabled: true, details: "2 KMS key(s)" });
    });

    it("ListKmsInstances denied → still tries ListKeys", async () => {
      const r = await run({
        ...ENABLED,
        ListKmsInstances: () => { throw deniedError("kms:ListKmsInstances"); },
        ListKeys: { Keys: { Key: [{ KeyId: "key-1" }] }, TotalCount: 1 },
      });
      expect(svc(r, ALI_SERVICE_KMS).enabled).toBe(true);
      expect(r.warnings).toBeUndefined();
    });

    it("ListKmsInstances auth_failed → module status error (ListKeys not attempted)", async () => {
      const r = await run({ ...ENABLED, ListKmsInstances: () => { throw authError("kms:ListKmsInstances"); } });
      expect(r.status).toBe("error");
      expect(callsFor(mocks.aliCall, "ListKeys")).toHaveLength(0);
    });
  });

  it("no credentials anywhere → status error (no call)", async () => {
    const r = await scanner.scan(aliCtx({ credentials: undefined }));
    expect(r.status).toBe("error");
    expect(mocks.aliCall).not.toHaveBeenCalled();
  });
});
