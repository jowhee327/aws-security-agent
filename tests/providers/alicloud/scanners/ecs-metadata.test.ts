/**
 * Phase 2 T4 — AliEcsMetadataScanner (imdsv2_enforcement): DescribeInstances MetadataOptions
 * (HttpTokens required / optional / missing, HttpEndpoint disabled, hop limit), pagination,
 * degrade, auth_failed / api_misuse → error. aliCall is mocked by spec.action; fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall };
});

import { AliEcsMetadataScanner, ECS_METADATA_NOT_HARDENED_RISK, evaluateAliMetadataOptions } from "../../../../src/providers/alicloud/scanners/ecs-metadata.js";
import { alibabaCloudProvider } from "../../../../src/providers/alicloud/index.js";
import type { ScanResult } from "../../../../src/types.js";
import { aliCtx, authError, callsFor, deniedError, FAKE_AK, FAKE_SK, isolateAliEnv, misuseError, restoreAliEnv, routeAliCall, UID } from "./helpers.js";
import { expectNoHostileLeak, hostile } from "./helpers.js";

interface Inst {
  id: string;
  tokens?: string;
  endpoint?: string;
  hop?: number | string;
  noMetadata?: boolean;
}

function instancesPage(list: Inst[], total = list.length) {
  return {
    Instances: {
      Instance: list.map((i) => ({
        InstanceId: i.id,
        InstanceType: "ecs.g7.large",
        Status: "Running",
        ...(i.noMetadata
          ? {}
          : {
              MetadataOptions: {
                ...(i.tokens !== undefined ? { HttpTokens: i.tokens } : {}),
                HttpEndpoint: i.endpoint ?? "enabled",
                ...(i.hop !== undefined ? { HttpPutResponseHopLimit: i.hop } : {}),
              },
            }),
      })),
    },
    TotalCount: total,
    PageNumber: 1,
    PageSize: 100,
  };
}

const scanner = new AliEcsMetadataScanner();

function noSecrets(r: ScanResult): void {
  const text = JSON.stringify(r);
  expect(text).not.toContain(FAKE_AK);
  expect(text).not.toContain(FAKE_SK);
}

beforeEach(() => {
  isolateAliEnv();
  mocks.aliCall.mockReset();
});
afterEach(() => restoreAliEnv());

describe("evaluateAliMetadataOptions", () => {
  it("required → hardened; optional → not hardened; missing → optional + missing flag", () => {
    expect(evaluateAliMetadataOptions({ MetadataOptions: { HttpTokens: "required", HttpEndpoint: "enabled" } })).toMatchObject({ notHardened: false, missing: false });
    expect(evaluateAliMetadataOptions({ MetadataOptions: { HttpTokens: "optional", HttpEndpoint: "enabled" } })).toMatchObject({ notHardened: true, httpTokens: "optional" });
    expect(evaluateAliMetadataOptions({})).toMatchObject({ notHardened: true, missing: true, httpTokens: "optional", httpEndpoint: "enabled" });
    expect(evaluateAliMetadataOptions({ MetadataOptions: { HttpEndpoint: "enabled" } })).toMatchObject({ missing: true, notHardened: true });
  });

  it("endpoint disabled → no finding even with optional tokens; case-insensitive; hop limit parsed", () => {
    expect(evaluateAliMetadataOptions({ MetadataOptions: { HttpTokens: "optional", HttpEndpoint: "disabled" } }).notHardened).toBe(false);
    expect(evaluateAliMetadataOptions({ MetadataOptions: { HttpTokens: "Required" } }).notHardened).toBe(false);
    expect(evaluateAliMetadataOptions({ MetadataOptions: { HttpTokens: "optional", HttpPutResponseHopLimit: "3" } }).hopLimit).toBe(3);
  });
});

describe("AliEcsMetadataScanner", () => {
  it("HttpTokens optional → 7.5 HIGH finding; required → none; Status=Running queried", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: instancesPage([
        { id: "i-opt", tokens: "optional" },
        { id: "i-req", tokens: "required" },
      ]),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.resourcesScanned).toBe(2);
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f.resourceId).toBe("i-opt");
    expect(f.riskScore).toBe(ECS_METADATA_NOT_HARDENED_RISK);
    expect(f.riskScore).toBe(7.5);
    expect(f.severity).toBe("HIGH");
    expect(f.resourceType).toBe("ACS::ECS::Instance");
    expect(f.resourceArn).toBe(`acs:ecs:cn-hangzhou:${UID}:instance/i-opt`);
    expect(f.region).toBe("cn-hangzhou");
    expect(f.provider).toBe("alicloud");
    expect(f.description).toContain('HttpTokens set to "optional"');
    expect(f.remediationSteps.join(" ")).toContain("--HttpTokens required");
    expect(r.warnings).toBeUndefined();
    const call = callsFor(mocks.aliCall, "DescribeInstances")[0];
    expect(call[0]).toMatchObject({ service: "ecs", action: "DescribeInstances", version: "2014-05-26" });
    expect(call[2]).toMatchObject({ RegionId: "cn-hangzhou", Status: "Running", PageNumber: 1, PageSize: 100 });
    expect(call[1].region).toBe("cn-hangzhou");
    noSecrets(r);
  });

  it("no hit: all instances hardened or metadata disabled → 0 findings", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: instancesPage([
        { id: "i-1", tokens: "required" },
        { id: "i-2", tokens: "optional", endpoint: "disabled" },
      ]),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.resourcesScanned).toBe(2);
  });

  it("missing MetadataOptions → treated as optional (finding) + one aggregated warning", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: instancesPage([
        { id: "i-miss1", noMetadata: true },
        { id: "i-miss2", noMetadata: true },
        { id: "i-req", tokens: "required" },
      ]),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings.map((x) => x.resourceId)).toEqual(["i-miss1", "i-miss2"]);
    expect(r.findings[0].description).toContain("MetadataOptions not returned");
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toContain("no MetadataOptions for 2 instance(s)");
    expect(r.warnings![0]).toContain('treated as HttpTokens "optional"');
  });

  it("hop limit > 1: noted in the finding (optional) / informational warning (required)", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: instancesPage([
        { id: "i-opt", tokens: "optional", hop: 3 },
        { id: "i-req", tokens: "required", hop: 2 },
      ]),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].description).toContain("HttpPutResponseHopLimit is 3");
    expect(r.warnings).toEqual([expect.stringContaining("Instance i-req enforces security-hardened metadata mode but HttpPutResponseHopLimit is 2")]);
  });

  it("pagination (PageNumber / TotalCount) covers every page", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: (q) =>
        q.PageNumber === 1
          ? instancesPage([{ id: "i-1", tokens: "optional" }, { id: "i-2", tokens: "required" }], 3)
          : instancesPage([{ id: "i-3", tokens: "optional" }], 3),
    });
    const r = await scanner.scan(aliCtx());
    expect(callsFor(mocks.aliCall, "DescribeInstances").map((c) => c[2].PageNumber)).toEqual([1, 2]);
    expect(r.resourcesScanned).toBe(3);
    expect(r.findings.map((f) => f.resourceId)).toEqual(["i-1", "i-3"]);
  });

  it("access denied → warning, success with 0 findings", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: () => {
        throw deniedError("ecs:DescribeInstances");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings?.[0]).toMatch(/^ECS DescribeInstances: insufficient permissions/);
    noSecrets(r);
  });

  it("auth_failed (404 InvalidAccessKeyId.NotFound) → module status error, never degraded", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: () => {
        throw authError("ecs:DescribeInstances");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
    expect(r.error).toContain("InvalidAccessKeyId.NotFound");
    noSecrets(r);
  });

  it("api_misuse → module status error", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: () => {
        throw misuseError("ecs:DescribeInstances");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toContain("ECS metadata check failed");
    expect(r.error).toContain("MissingParameter");
  });

  it("alicloud provider exposes imdsv2_enforcement as a regional module", () => {
    expect(alibabaCloudProvider.scanners().some((s) => s.moduleName === "imdsv2_enforcement")).toBe(true);
    expect(alibabaCloudProvider.globalModules?.has("imdsv2_enforcement")).toBe(false);
  });
});

describe("hostile server strings (FIX2)", () => {
  const hostilePage = (metadata: Record<string, unknown> | undefined) => ({
    Instances: {
      Instance: [
        {
          InstanceId: hostile("i"),
          InstanceType: hostile("ecs.type"),
          Status: "Running",
          ...(metadata ? { MetadataOptions: metadata } : {}),
        },
      ],
    },
    TotalCount: 1,
    PageNumber: 1,
    PageSize: 100,
  });

  it("ECS instance id / type / HttpTokens are redacted in the finding (incl. lower-cased HttpTokens)", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeInstances: hostilePage({ HttpTokens: hostile("Optional"), HttpEndpoint: "enabled", HttpPutResponseHopLimit: 2 }),
    });

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(1);
    const f = r.findings[0];
    expect(f.resourceId.startsWith("i-[REDACTED]")).toBe(true);
    expect(f.resourceArn.startsWith(`acs:ecs:cn-hangzhou:${UID}:instance/i-[REDACTED]`)).toBe(true);
    expect(f.description).toContain("ecs.type-[REDACTED]");
    expectNoHostileLeak(r);
    expect(JSON.stringify(r).toLowerCase()).not.toContain("ltai5tfake0");
    noSecrets(r);
  });

  it("missing-MetadataOptions warning never echoes a hostile instance id", async () => {
    routeAliCall(mocks.aliCall, { DescribeInstances: hostilePage(undefined) });

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings?.some((w) => w.includes("returned no MetadataOptions") && w.includes("i-[REDACTED]"))).toBe(true);
    expectNoHostileLeak(r);
  });
});
