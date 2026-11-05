/**
 * Phase 2 T7 — AliSasAlertsScanner (guardduty_findings): SAS DescribeVersionConfig edition
 * gate, DescribeSuspEvents (CurrentPage / PageSize) with Level serious / suspicious / remind
 * → HIGH 8.0 / MEDIUM 6.0 / LOW 3.0, finding cap + overflow warning, degrade, auth_failed /
 * api_misuse → error, redaction. aliCall is mocked by spec.action; fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall };
});

import {
  AliSasAlertsScanner,
  SAS_ALERT_PAGE_SIZE,
  SAS_MAX_ALERT_FINDINGS,
  sasAlertLevel,
} from "../../../../src/providers/alicloud/scanners/sas-alerts.js";
import { SAS_NOT_ENABLED_WARNING, checkSasEdition, sasNecessity } from "../../../../src/providers/alicloud/scanners/sas-shared.js";
import { aliScanEnv } from "../../../../src/providers/alicloud/scanners/shared.js";
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

function alert(id: number, level: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    Id: id,
    Uuid: `uuid-${id}`,
    AlarmEventNameDisplay: `Event ${id}`,
    AlarmEventTypeDisplay: "Abnormal login",
    Level: level,
    InstanceId: `i-${id}`,
    InstanceName: `web-${id}`,
    InternetIp: "203.0.113.10",
    OccurrenceTime: "2026-10-25 10:00:00",
    LastTime: "2026-10-26 10:00:00",
    LastTimeStamp: 1761400000000 + id,
    Desc: "Suspicious login from an unusual location",
    ...extra,
  };
}

/** DescribeSuspEvents handler serving `all` in pages of the requested PageSize. */
function pagedAlerts(all: Record<string, unknown>[]): AliHandler {
  return (q) => {
    const page = Number(q.CurrentPage ?? 1);
    const size = Number(q.PageSize ?? 20);
    return { SuspEvents: all.slice((page - 1) * size, page * size), TotalCount: all.length, CurrentPage: page, PageSize: size };
  };
}

const PAID = { Version: 3, RequestId: "req-1" };
const scanner = new AliSasAlertsScanner();

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
  it("sasAlertLevel normalises Level", () => {
    expect(sasAlertLevel({ Level: "serious" })).toBe("serious");
    expect(sasAlertLevel({ Level: "SUSPICIOUS" })).toBe("suspicious");
    expect(sasAlertLevel({ Level: "remind" })).toBe("remind");
    expect(sasAlertLevel({ Level: "other" })).toBe("unknown");
    expect(sasAlertLevel({})).toBe("unknown");
  });

  it("sasNecessity: Necessity first, Level fallback", () => {
    expect(sasNecessity({ Necessity: "asap" })).toBe("asap");
    expect(sasNecessity({ Necessity: "LATER" })).toBe("later");
    expect(sasNecessity({ Necessity: "nntf" })).toBe("nntf");
    expect(sasNecessity({ Level: "high" })).toBe("asap");
    expect(sasNecessity({ Level: "medium" })).toBe("later");
    expect(sasNecessity({ Level: "low" })).toBe("nntf");
    expect(sasNecessity({})).toBe("unknown");
  });

  it("checkSasEdition: paid / free / value-added / absent / pay-as-you-go", async () => {
    const env = aliScanEnv(aliCtx());
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: { Version: 7 } });
    expect(await checkSasEdition(env, "x")).toEqual({ kind: "enabled", edition: "Ultimate Edition" });
    for (const body of [{ Version: 1 }, { Version: 10 }, {}]) {
      routeAliCall(mocks.aliCall, { DescribeVersionConfig: body });
      const r = await checkSasEdition(env, "x");
      expect(r.kind).toBe("stop");
      expect(r.kind === "stop" && r.warning.startsWith(SAS_NOT_ENABLED_WARNING)).toBe(true);
    }
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: { Version: 1, IsPostpay: true } });
    expect(await checkSasEdition(env, "x")).toEqual({ kind: "enabled", edition: "pay-as-you-go" });
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: { PostPayStatus: 1 } });
    expect(await checkSasEdition(env, "x")).toEqual({ kind: "enabled", edition: "pay-as-you-go" });
  });
});

describe("AliSasAlertsScanner", () => {
  it("is registered in the alicloud provider as a global module", () => {
    expect(alibabaCloudProvider.scanners().some((s) => s instanceof AliSasAlertsScanner)).toBe(true);
    expect(alibabaCloudProvider.globalModules?.has("guardduty_findings")).toBe(true);
    expect(scanner.moduleName).toBe("guardduty_findings");
  });

  it("maps Level serious / suspicious / remind → HIGH 8.0 / MEDIUM 6.0 / LOW 3.0, sorted, global URN", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: PAID,
      DescribeSuspEvents: pagedAlerts([alert(3, "remind"), alert(1, "serious"), alert(2, "suspicious")]),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toBeUndefined();
    expect(r.resourcesScanned).toBe(3);
    expect(r.findingsCount).toBe(3);
    expect(r.findings.map((f) => [f.severity, f.riskScore])).toEqual([
      ["HIGH", 8.0],
      ["MEDIUM", 6.0],
      ["LOW", 3.0],
    ]);
    const f = r.findings[0];
    expect(f.title).toBe("SAS urgent alert: Event 1 on i-1 (web-1)");
    expect(f.resourceType).toBe("ACS::SAS::Alert");
    expect(f.resourceId).toBe("i-1");
    expect(f.resourceArn).toBe(`acs:sas::${UID}:alert/1`);
    expect(f.region).toBe("global");
    expect(f.provider).toBe("alicloud");
    expect(f.module).toBe("guardduty_findings");
    expect(f.accountId).toBe(UID);
    expect(f.priority).toBe("P1");
    expect(f.description).toContain("Abnormal login");
    expect(f.description).toContain("203.0.113.10");

    const calls = callsFor(mocks.aliCall, "DescribeSuspEvents");
    expect(calls).toHaveLength(1);
    expect(calls[0][0]).toMatchObject({ service: "sas", action: "DescribeSuspEvents", version: "2018-12-03", method: "POST", style: "RPC" });
    expect(calls[0][1].region).toBeUndefined();
    expect(calls[0][2]).toEqual({
      From: "sas",
      Lang: "en",
      Dealed: "N",
      Levels: "serious,suspicious,remind",
      CurrentPage: 1,
      PageSize: SAS_ALERT_PAGE_SIZE,
    });
    expect(callsFor(mocks.aliCall, "DescribeVersionConfig")).toHaveLength(1);
  });

  it("no alerts → success, 0 findings, no warnings", async () => {
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: PAID, DescribeSuspEvents: { SuspEvents: [], TotalCount: 0 } });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.resourcesScanned).toBe(0);
    expect(r.warnings).toBeUndefined();
  });

  it("paginates with CurrentPage until TotalCount", async () => {
    const all = Array.from({ length: 130 }, (_, i) => alert(i + 1, "remind"));
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: PAID, DescribeSuspEvents: pagedAlerts(all) });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.resourcesScanned).toBe(130);
    expect(callsFor(mocks.aliCall, "DescribeSuspEvents").map((c) => c[2].CurrentPage)).toEqual([1, 2]);
  });

  it("caps findings at SAS_MAX_ALERT_FINDINGS with an overflow warning; serious alerts kept first", async () => {
    const all = [
      ...Array.from({ length: 110 }, (_, i) => alert(i + 1, "remind")),
      ...Array.from({ length: 5 }, (_, i) => alert(1000 + i, "serious")),
    ];
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: PAID, DescribeSuspEvents: pagedAlerts(all) });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toHaveLength(SAS_MAX_ALERT_FINDINGS);
    expect(r.findings.slice(0, 5).every((f) => f.severity === "HIGH")).toBe(true);
    expect(r.resourcesScanned).toBe(115);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toContain("115 unhandled alerts (serious 5, suspicious 0, remind 110)");
    expect(r.warnings![0]).toContain(`only the top ${SAS_MAX_ALERT_FINDINGS}`);
  });

  it.each([
    ["Free Edition", { Version: 1 }],
    ["value-added only", { Version: 10 }],
    ["not purchased", {}],
  ])("SAS %s → 0 findings + not-enabled warning, no DescribeSuspEvents", async (_label, body) => {
    routeAliCall(mocks.aliCall, { DescribeVersionConfig: body });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0].startsWith(SAS_NOT_ENABLED_WARNING)).toBe(true);
    expect(callsFor(mocks.aliCall, "DescribeSuspEvents")).toHaveLength(0);
  });

  it("not-enabled code on DescribeVersionConfig or DescribeSuspEvents → warning, status success", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: () => {
        throw notEnabledError("sas:DescribeVersionConfig");
      },
    });
    let r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings![0].startsWith(SAS_NOT_ENABLED_WARNING)).toBe(true);

    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: PAID,
      DescribeSuspEvents: () => {
        throw notEnabledError("sas:DescribeSuspEvents");
      },
    });
    r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings![0].startsWith(SAS_NOT_ENABLED_WARNING)).toBe(true);
  });

  it("access denied on DescribeSuspEvents → insufficient-permissions warning, status success", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: PAID,
      DescribeSuspEvents: () => {
        throw deniedError("sas:DescribeSuspEvents");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toContain("SAS DescribeSuspEvents: insufficient permissions");
  });

  it("access denied on DescribeVersionConfig → warning, listing skipped", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: () => {
        throw deniedError("sas:DescribeVersionConfig");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings![0]).toContain("SAS DescribeVersionConfig: insufficient permissions");
    expect(callsFor(mocks.aliCall, "DescribeSuspEvents")).toHaveLength(0);
  });

  it("throttled DescribeVersionConfig → warning, listing still runs", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: () => {
        throw throttledError("sas:DescribeVersionConfig");
      },
      DescribeSuspEvents: pagedAlerts([alert(1, "serious")]),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toHaveLength(1);
    expect(r.warnings![0]).toContain("edition check failed");
  });

  it.each([
    ["DescribeVersionConfig", "auth"],
    ["DescribeSuspEvents", "auth"],
    ["DescribeVersionConfig", "misuse"],
    ["DescribeSuspEvents", "misuse"],
  ])("%s %s error → status error", async (action, kind) => {
    const err = kind === "auth" ? authError(`sas:${action}`) : misuseError(`sas:${action}`);
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: PAID,
      DescribeSuspEvents: pagedAlerts([]),
      [action]: () => {
        throw err;
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.findings).toEqual([]);
    if (kind === "auth") expect(r.error!.startsWith("Alibaba Cloud authentication failed")).toBe(true);
    else expect(r.error).toContain("SAS alert scan failed");
    noSecrets(r);
  });

  it("redacts AK-looking event names / instance names", async () => {
    routeAliCall(mocks.aliCall, {
      DescribeVersionConfig: PAID,
      DescribeSuspEvents: pagedAlerts([
        alert(1, "serious", {
          AlarmEventNameDisplay: `Leaked key ${LEAK_AK}`,
          InstanceName: `host-${FAKE_AK}`,
          Desc: `accessKeySecret=${FAKE_SK}`,
        }),
      ]),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].title).toContain("[REDACTED]");
    noSecrets(r);
  });
});
