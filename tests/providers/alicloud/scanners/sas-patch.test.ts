/**
 * Phase 2 T7 — AliSasPatchScanner (patch_compliance_findings): SAS DescribeVulList for
 * Type=sys (Windows patches) + cve (Linux), per-host aggregation (Uuid / InstanceId),
 * riskScore 7.5 / 5.5 / 3.0, host cap + overflow warning, edition gate, degrade,
 * auth_failed / api_misuse → error, redaction. aliCall is mocked by spec.action; fake keys
 * only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall };
});

import {
  AliSasPatchScanner,
  SAS_PATCH_MAX_HOST_FINDINGS,
  SAS_PATCH_VUL_TYPES,
  sasPatchRiskScore,
  summarizeSasHostVuls,
} from "../../../../src/providers/alicloud/scanners/sas-patch.js";
import { SAS_NOT_ENABLED_WARNING, SAS_VUL_PAGE_SIZE } from "../../../../src/providers/alicloud/scanners/sas-shared.js";
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
  notEnabledError,
  restoreAliEnv,
  routeAliCall,
  UID,
  type AliHandler,
} from "./helpers.js";

const LEAK_AK = "LTAI5tLEAKLEAKLEAK0000009";

function rec(name: string, host: string, necessity: string | undefined, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    Name: name,
    AliasName: `${name} alias`,
    ...(necessity ? { Necessity: necessity } : {}),
    Uuid: `uuid-${host}`,
    InstanceId: `i-${host}`,
    InstanceName: `srv-${host}`,
    RegionId: "cn-hangzhou",
    OsName: "Windows Server 2019",
    IntranetIp: "10.0.0.5",
    Status: 1,
    ...extra,
  };
}

/** DescribeVulList handler keyed by Type; each list is served in pages of the requested PageSize. */
function vulsByType(map: Record<string, Record<string, unknown>[] | (() => unknown)>): AliHandler {
  return (q) => {
    const h = map[String(q.Type)];
    if (typeof h === "function") return h();
    const all = h ?? [];
    const page = Number(q.CurrentPage ?? 1);
    const size = Number(q.PageSize ?? 10);
    return { VulRecords: all.slice((page - 1) * size, page * size), TotalCount: all.length, CurrentPage: page, PageSize: size };
  };
}

const PAID = { Version: 3 };
const scanner = new AliSasPatchScanner();

function noSecrets(r: ScanResult): void {
  const text = JSON.stringify(r);
  expect(text).not.toContain(FAKE_AK);
  expect(text).not.toContain(FAKE_SK);
  expect(text).not.toContain(LEAK_AK);
}

beforeEach(() => {
  isolateAliEnv();
  mocks.aliCall.mockReset();
});
afterEach(() => restoreAliEnv());

describe("helpers", () => {
  it("summarizeSasHostVuls aggregates per host, de-duplicates items, splits sys / cve", () => {
    const out = summarizeSasHostVuls([
      { type: "sys", rec: rec("KB500001", "1", "asap") },
      { type: "sys", rec: rec("KB500001", "1", "asap") },
      { type: "cve", rec: rec("oval:bash", "1", "later") },
      { type: "cve", rec: rec("oval:bash", "2", "nntf", { Uuid: undefined }) },
      { type: "cve", rec: rec("oval:orphan", "x", "asap", { Uuid: undefined, InstanceId: undefined }) },
    ]);
    expect(out).toHaveLength(2);
    const h1 = out.find((h) => h.key === "uuid-1")!;
    expect(h1).toMatchObject({ instanceId: "i-1", total: 2, asap: 1, later: 1, nntf: 0, sys: 1, cve: 1 });
    expect(h1.sample).toEqual(["KB500001 alias", "oval:bash alias"]);
    const h2 = out.find((h) => h.key === "i-2")!;
    expect(h2).toMatchObject({ total: 1, nntf: 1 });
  });

  it("sasPatchRiskScore: asap → 7.5, later / unrated → 5.5, nntf only → 3.0", () => {
    expect(sasPatchRiskScore({ asap: 1, later: 0, unknown: 0 })).toBe(7.5);
    expect(sasPatchRiskScore({ asap: 0, later: 2, unknown: 0 })).toBe(5.5);
    expect(sasPatchRiskScore({ asap: 0, later: 0, unknown: 1 })).toBe(5.5);
    expect(sasPatchRiskScore({ asap: 0, later: 0, unknown: 0 })).toBe(3.0);
  });
});

describe("AliSasPatchScanner", () => {
  it("is registered in the alicloud provider as a global module", () => {
    expect(alibabaCloudProvider.scanners().some((s) => s instanceof AliSasPatchScanner)).toBe(true);
    expect(alibabaCloudProvider.globalModules?.has("patch_compliance_findings")).toBe(true);
    expect(scanner.moduleName).toBe("patch_compliance_findings");
  });

  it("queries Type=sys then cve (Dealed=n) on the centralised endpoint", async () => {
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: PAID, DescribeVulList: vulsByType({}) });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.resourcesScanned).toBe(0);
    expect(r.warnings).toBeUndefined();
    expect(SAS_PATCH_VUL_TYPES).toEqual(["sys", "cve"]);
    const calls = callsFor(mocks.aliCall, "DescribeVulList");
    expect(calls.map((c) => c[2])).toEqual(
      ["sys", "cve"].map((Type) => ({ Type, Dealed: "n", Lang: "en", CurrentPage: 1, PageSize: SAS_VUL_PAGE_SIZE })),
    );
    expect(calls[0][1].region).toBeUndefined();
  });

  it("one finding per host, sorted by risk; ECS URN when InstanceId + RegionId, SAS host URN otherwise", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: PAID,
      DescribeVulList: vulsByType({
        sys: [rec("KB500001", "1", "asap"), rec("KB500002", "1", "later")],
        cve: [
          rec("oval:bash", "1", "later"),
          rec("oval:bash", "1", "later"), // duplicate → counted once
          rec("oval:curl", "2", "nntf", { InstanceId: undefined, RegionId: undefined, OsName: "CentOS 7" }),
          rec("oval:vim", "3", "later"),
          rec("oval:old", "3", "asap", { Status: 7 }), // fixed → dropped
        ],
      }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.resourcesScanned).toBe(3);
    expect(r.findings.map((f) => [f.resourceId, f.severity, f.riskScore])).toEqual([
      ["i-1", "HIGH", 7.5],
      ["i-3", "MEDIUM", 5.5],
      ["uuid-2", "LOW", 3.0],
    ]);
    const [h1, h3, h2] = r.findings;
    expect(h1.title).toBe("Host i-1 (srv-1) has 3 unpatched OS vulnerabilities (1 high-priority, 2 medium-priority)");
    expect(h1.description).toContain("Windows system patches: 2, Linux software: 1");
    expect(h1.description).toContain("OS: Windows Server 2019");
    expect(h1.resourceType).toBe("ACS::ECS::Instance");
    expect(h1.resourceArn).toBe(`acs:ecs:cn-hangzhou:${UID}:instance/i-1`);
    expect(h1.region).toBe("cn-hangzhou");
    expect(h1.provider).toBe("alicloud");
    expect(h1.module).toBe("patch_compliance_findings");
    expect(h3.title).toContain("has 1 unpatched OS vulnerabilities (1 medium-priority)");
    expect(h2.resourceArn).toBe(`acs:sas::${UID}:host/uuid-2`);
    expect(h2.region).toBe("global");
  });

  it("paginates DescribeVulList with CurrentPage until TotalCount", async () => {
    const many = Array.from({ length: 70 }, (_, i) => rec(`KB${i}`, "1", "later"));
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: PAID, DescribeVulList: vulsByType({ sys: many }) });
    const r = await scanner.scan(aliCtx());
    expect(callsFor(mocks.aliCall, "DescribeVulList").filter((c) => c[2].Type === "sys").map((c) => c[2].CurrentPage)).toEqual([1, 2]);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].title).toContain("has 70 unpatched OS vulnerabilities");
  });

  it("caps host findings at SAS_PATCH_MAX_HOST_FINDINGS with an overflow warning; high-risk hosts first", async () => {
    const cve = [
      ...Array.from({ length: SAS_PATCH_MAX_HOST_FINDINGS + 5 }, (_, i) => rec("oval:minor", `h${String(i).padStart(3, "0")}`, "nntf")),
      rec("oval:critical", "zz", "asap"),
    ];
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: PAID, DescribeVulList: vulsByType({ cve }) });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toHaveLength(SAS_PATCH_MAX_HOST_FINDINGS);
    expect(r.findings[0].resourceId).toBe("i-zz");
    expect(r.resourcesScanned).toBe(SAS_PATCH_MAX_HOST_FINDINGS + 6);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toContain(`${SAS_PATCH_MAX_HOST_FINDINGS + 6} host(s) with unhandled OS vulnerabilities (1 with high-priority items)`);
  });

  it.each([
    ["Free Edition", { Version: 1 }],
    ["value-added only", { Version: 10 }],
  ])("SAS %s → 0 findings + not-enabled warning", async (_label, body) => {
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: body });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0].startsWith(SAS_NOT_ENABLED_WARNING)).toBe(true);
    expect(r.warnings![0]).toContain("OS patch compliance data not available");
    expect(callsFor(mocks.aliCall, "DescribeVulList")).toHaveLength(0);
  });

  it("not-enabled code on DescribeVersionConfig → not-enabled warning, status success", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: () => {
        throw notEnabledError("sas:DescribeVersionConfig");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings![0].startsWith(SAS_NOT_ENABLED_WARNING)).toBe(true);
  });

  it("access denied → permission warning, cve skipped, status success", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: PAID,
      DescribeVulList: () => {
        throw deniedError("sas:DescribeVulList");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toContain("SAS DescribeVulList (Type=sys): insufficient permissions");
    expect(callsFor(mocks.aliCall, "DescribeVulList")).toHaveLength(1);
  });

  it.each([
    ["DescribeVersionConfig", "auth"],
    ["DescribeVulList", "auth"],
    ["DescribeVersionConfig", "misuse"],
    ["DescribeVulList", "misuse"],
  ])("%s %s error → status error", async (action, kind) => {
    const err = kind === "auth" ? authError(`sas:${action}`) : misuseError(`sas:${action}`);
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: PAID,
      DescribeVulList: vulsByType({}),
      [action]: () => {
        throw err;
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.findings).toEqual([]);
    if (kind === "auth") expect(r.error!.startsWith("Alibaba Cloud authentication failed")).toBe(true);
    else expect(r.error).toContain("SAS patch compliance scan failed");
    noSecrets(r);
  });

  it("redacts AK-looking host ids / names / vulnerability names", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: PAID,
      DescribeVulList: vulsByType({
        sys: [rec(`KB-${LEAK_AK}`, "1", "asap", { Uuid: `uuid-${LEAK_AK}`, InstanceId: undefined, InstanceName: `srv-${FAKE_AK}`, AliasName: undefined })],
      }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].title).toContain("[REDACTED]");
    noSecrets(r);
  });
});
