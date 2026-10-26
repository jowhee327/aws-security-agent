/**
 * Phase 2 T7 — AliSasVulnsScanner (inspector_findings): SAS DescribeVulList for Type=cve,
 * app, emg (CurrentPage / PageSize, Dealed=n), per-vulnerability aggregation, Necessity
 * asap / later / nntf → HIGH / MEDIUM / LOW, sort + SAS_MAX_VUL_FINDINGS cap, edition gate,
 * degrade, auth_failed / api_misuse → error, redaction. aliCall is mocked by spec.action;
 * fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall };
});

import {
  AliSasVulnsScanner,
  SAS_MAX_VUL_FINDINGS,
  SAS_VUL_TYPES,
  aggregateSasVuls,
} from "../../../../src/providers/alicloud/scanners/sas-vulns.js";
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
  throttledError,
  UID,
  type AliHandler,
} from "./helpers.js";

const LEAK_AK = "LTAI5tLEAKLEAKLEAK0000009";

function vul(name: string, host: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    Name: name,
    AliasName: `${name} alias`,
    Necessity: "later",
    Uuid: `uuid-${host}`,
    InstanceId: `i-${host}`,
    InstanceName: `srv-${host}`,
    RegionId: "cn-hangzhou",
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

const PAID = { Version: 5 };
const scanner = new AliSasVulnsScanner();

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

describe("aggregateSasVuls", () => {
  it("groups records per Type + Name, counts hosts, keeps the most urgent necessity", () => {
    const out = aggregateSasVuls([
      { type: "cve", rec: vul("CVE-A", "1", { Necessity: "nntf", Related: "CVE-2026-0001,CVE-2026-0002" }) },
      { type: "cve", rec: vul("CVE-A", "2", { Necessity: "asap" }) },
      { type: "cve", rec: vul("CVE-A", "2", { Necessity: "later" }) },
      { type: "app", rec: vul("CVE-A", "3") },
      { type: "emg", rec: vul("EMG-1", "1", { Necessity: undefined }) },
    ]);
    expect(out).toHaveLength(3);
    const a = out.find((v) => v.type === "cve")!;
    expect(a.necessity).toBe("asap");
    expect(a.hosts).toEqual(["i-1 (srv-1)", "i-2 (srv-2)"]);
    expect(a.cves).toEqual(["CVE-2026-0001", "CVE-2026-0002"]);
    expect(out.find((v) => v.type === "emg")!.necessity).toBe("asap"); // unrated emergency → asap
  });
});

describe("AliSasVulnsScanner", () => {
  it("is registered in the alicloud provider as a global module", () => {
    expect(alibabaCloudProvider.scanners().some((s) => s instanceof AliSasVulnsScanner)).toBe(true);
    expect(alibabaCloudProvider.globalModules?.has("inspector_findings")).toBe(true);
    expect(scanner.moduleName).toBe("inspector_findings");
  });

  it("iterates Type=cve, app, emg on the centralised endpoint with Dealed=n", async () => {
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: PAID, DescribeVulList: vulsByType({}) });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toBeUndefined();
    expect(SAS_VUL_TYPES).toEqual(["cve", "app", "emg"]);
    const calls = callsFor(mocks.aliCall, "DescribeVulList");
    expect(calls.map((c) => c[2])).toEqual(
      ["cve", "app", "emg"].map((Type) => ({ Type, Dealed: "n", Lang: "en", CurrentPage: 1, PageSize: SAS_VUL_PAGE_SIZE })),
    );
    expect(calls[0][0]).toMatchObject({ service: "sas", action: "DescribeVulList", version: "2018-12-03", method: "POST", style: "RPC" });
    expect(calls[0][1].region).toBeUndefined();
  });

  it("Necessity asap / later / nntf → HIGH 8.0 / MEDIUM 5.5 / LOW 3.0; sorted; closed records dropped", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: PAID,
      DescribeVulList: vulsByType({
        cve: [
          vul("oval:kernel", "1", { Necessity: "asap", AliasName: "RHSA-2026:0001: kernel update", Related: "CVE-2026-1111" }),
          vul("oval:kernel", "2", { Necessity: "asap" }),
          vul("oval:openssl", "1", { Necessity: "nntf" }),
          vul("oval:fixed", "1", { Necessity: "asap", Status: 7 }),
        ],
        app: [vul("app:struts", "3", { Necessity: "later" }), vul("app:legacy", "3", { Necessity: undefined, Level: "low" })],
        emg: [vul("emg:log4shell", "4", { Necessity: "asap" })],
      }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.resourcesScanned).toBe(5);
    expect(r.findings.map((f) => [f.resourceId, f.severity, f.riskScore])).toEqual([
      ["oval:kernel", "HIGH", 8.0],
      ["emg:log4shell", "HIGH", 8.0],
      ["app:struts", "MEDIUM", 5.5],
      ["app:legacy", "LOW", 3.0],
      ["oval:openssl", "LOW", 3.0],
    ]);
    const k = r.findings[0];
    expect(k.title).toBe("SAS high-priority (asap) Linux software (CVE) vulnerability RHSA-2026:0001: kernel update is unhandled on 2 host(s)");
    expect(k.description).toContain("CVE-2026-1111");
    expect(k.description).toContain("i-1 (srv-1), i-2 (srv-2)");
    expect(k.resourceType).toBe("ACS::SAS::Vulnerability");
    expect(k.resourceArn).toBe(`acs:sas::${UID}:vul/oval:kernel`);
    expect(k.region).toBe("global");
    expect(k.provider).toBe("alicloud");
    expect(k.module).toBe("inspector_findings");
    expect(r.findings.some((f) => f.resourceId === "oval:fixed")).toBe(false);
  });

  it("paginates DescribeVulList with CurrentPage until TotalCount", async () => {
    const many = Array.from({ length: 60 }, (_, i) => vul("oval:same", String(i)));
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: PAID, DescribeVulList: vulsByType({ cve: many }) });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    const cveCalls = callsFor(mocks.aliCall, "DescribeVulList").filter((c) => c[2].Type === "cve");
    expect(cveCalls.map((c) => c[2].CurrentPage)).toEqual([1, 2]);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].title).toContain("unhandled on 60 host(s)");
  });

  it("caps findings at SAS_MAX_VUL_FINDINGS (most urgent first) with an overflow warning", async () => {
    const cve = Array.from({ length: 60 }, (_, i) => vul(`oval:${String(i).padStart(3, "0")}`, "1", { Necessity: "nntf" }));
    const emg = [vul("emg:urgent", "9", { Necessity: "asap" })];
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: PAID, DescribeVulList: vulsByType({ cve, emg }) });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toHaveLength(SAS_MAX_VUL_FINDINGS);
    expect(r.findings[0].resourceId).toBe("emg:urgent");
    expect(r.resourcesScanned).toBe(61);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toContain("61 unhandled vulnerabilities (asap 1, later 0, nntf 60)");
    expect(r.warnings![0]).toContain(`only the top ${SAS_MAX_VUL_FINDINGS}`);
  });

  it.each([
    ["Free Edition", { Version: 1 }],
    ["not purchased", {}],
  ])("SAS %s → 0 findings + not-enabled warning, no DescribeVulList", async (_label, body) => {
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: body });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0].startsWith(SAS_NOT_ENABLED_WARNING)).toBe(true);
    expect(callsFor(mocks.aliCall, "DescribeVulList")).toHaveLength(0);
  });

  it("not-enabled code on DescribeVulList → not-enabled warning, remaining types skipped", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: PAID,
      DescribeVulList: () => {
        throw notEnabledError("sas:DescribeVulList");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0].startsWith(SAS_NOT_ENABLED_WARNING)).toBe(true);
    expect(callsFor(mocks.aliCall, "DescribeVulList")).toHaveLength(1);
  });

  it("access denied → one permission warning, remaining types skipped, status success", async () => {
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
    expect(r.warnings![0]).toContain("SAS DescribeVulList (Type=cve): insufficient permissions");
    expect(callsFor(mocks.aliCall, "DescribeVulList")).toHaveLength(1);
  });

  it("throttled type → warning, other types still evaluated", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: PAID,
      DescribeVulList: vulsByType({
        app: () => {
          throw throttledError("sas:DescribeVulList");
        },
        emg: [vul("emg:x", "1", { Necessity: "asap" })],
      }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toHaveLength(1);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toContain("SAS DescribeVulList (Type=app): throttled");
    expect(callsFor(mocks.aliCall, "DescribeVulList")).toHaveLength(3);
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
    else expect(r.error).toContain("SAS vulnerability scan failed");
    noSecrets(r);
  });

  it("redacts AK-looking vulnerability names / host names", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: PAID,
      DescribeVulList: vulsByType({
        cve: [vul(`oval:${LEAK_AK}`, "1", { AliasName: `leak ${FAKE_AK}`, InstanceName: `srv-${LEAK_AK}`, Related: LEAK_AK })],
      }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].title).toContain("[REDACTED]");
    noSecrets(r);
  });
});
