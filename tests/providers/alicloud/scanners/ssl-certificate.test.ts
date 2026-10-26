/**
 * Phase 2 T4 — AliSslCertificateScanner (ssl_certificate): CAS ListUserCertificateOrder for
 * OrderType=CERT and UPLOAD (default + Status=EXPIRED), CurrentPage / ShowSize pagination,
 * de-duplication, AWS-aligned thresholds (expired 8.0 / <30 6.0 / <90 4.0 / abnormal 7.5),
 * degrade, auth_failed / api_misuse → error. aliCall is mocked by spec.action; fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall };
});

import {
  AliSslCertificateScanner,
  casCertEndMs,
  casDaysUntil,
  evaluateCasCertificate,
} from "../../../../src/providers/alicloud/scanners/ssl-certificate.js";
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
  throttledError,
  UID,
  type AliHandler,
} from "./helpers.js";
import { expectNoHostileLeak, hostile } from "./helpers.js";

const DAY = 24 * 60 * 60 * 1000;
/** Expiry `days` (+ half a day of margin so Math.floor is stable) from now, epoch ms. */
const inDays = (days: number) => Date.now() + days * DAY + DAY / 2;

interface Cert {
  id: number | string;
  domain?: string;
  status?: string;
  end?: number;
  endDate?: string;
  expired?: boolean;
  upload?: boolean;
}

function cert(c: Cert): Record<string, unknown> {
  return {
    CertificateId: c.id,
    Domain: c.domain ?? `site-${c.id}.example.com`,
    Name: `cert-${c.id}`,
    Status: c.status ?? "ISSUED",
    ...(c.end !== undefined ? { CertEndTime: c.end } : {}),
    ...(c.endDate !== undefined ? { EndDate: c.endDate } : {}),
    ...(c.expired !== undefined ? { Expired: c.expired } : {}),
    ...(c.upload !== undefined ? { Upload: c.upload } : {}),
  };
}

function page(certs: Cert[], total = certs.length) {
  return { CertificateOrderList: certs.map(cert), TotalCount: total, CurrentPage: 1, ShowSize: 50 };
}

/** Handler keyed by `OrderType|Status` (Status "" = default query). */
function casHandler(map: Record<string, ReturnType<typeof page> | ((q: Record<string, unknown>) => unknown)>): AliHandler {
  return (q) => {
    const key = `${q.OrderType}|${q.Status ?? ""}`;
    const h = map[key];
    if (h === undefined) return page([]);
    return typeof h === "function" ? h(q) : h;
  };
}

const scanner = new AliSslCertificateScanner();

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

describe("helpers", () => {
  it("casCertEndMs: CertEndTime ms / seconds, EndDate yyyy-MM-dd (UTC), missing", () => {
    expect(casCertEndMs({ CertEndTime: 1700000000000 })).toBe(1700000000000);
    expect(casCertEndMs({ CertEndTime: 1700000000 })).toBe(1700000000000);
    expect(casCertEndMs({ EndDate: "2027-01-15" })).toBe(Date.parse("2027-01-15T00:00:00Z"));
    expect(casCertEndMs({ CertEndTime: 1700000000000, EndDate: "2030-01-01" })).toBe(1700000000000);
    expect(casCertEndMs({ EndDate: "garbage" })).toBeUndefined();
    expect(casCertEndMs({})).toBeUndefined();
  });

  it("casDaysUntil floors like the AWS scanner", () => {
    const now = Date.parse("2026-10-26T00:00:00Z");
    expect(casDaysUntil(now + 29.9 * DAY, now)).toBe(29);
    expect(casDaysUntil(now - 0.1 * DAY, now)).toBe(-1);
  });

  it("evaluateCasCertificate boundaries", () => {
    const now = Date.parse("2026-10-26T00:00:00Z");
    const at = (d: number) => ({ Status: "ISSUED", CertEndTime: now + d * DAY + DAY / 2 });
    expect(evaluateCasCertificate(at(-1), now)).toEqual({ kind: "expired", days: -1 });
    expect(evaluateCasCertificate(at(0), now)).toEqual({ kind: "expires_30", days: 0 });
    expect(evaluateCasCertificate(at(29), now)).toEqual({ kind: "expires_30", days: 29 });
    expect(evaluateCasCertificate(at(30), now)).toEqual({ kind: "expires_90", days: 30 });
    expect(evaluateCasCertificate(at(89), now)).toEqual({ kind: "expires_90", days: 89 });
    expect(evaluateCasCertificate(at(90), now)).toEqual({ kind: "ok" });
    expect(evaluateCasCertificate({ ...at(10), Status: "WILLEXPIRED" }, now)).toEqual({ kind: "expires_30", days: 10 });
    expect(evaluateCasCertificate({ Status: "EXPIRED" }, now)).toEqual({ kind: "expired" });
    expect(evaluateCasCertificate({ ...at(200), Expired: true }, now)).toEqual({ kind: "expired" });
    expect(evaluateCasCertificate({ ...at(200), Status: "REVOKED" }, now)).toEqual({ kind: "abnormal", status: "REVOKED" });
    expect(evaluateCasCertificate({ Status: "checked_fail" }, now)).toEqual({ kind: "abnormal", status: "CHECKED_FAIL" });
    expect(evaluateCasCertificate({ ...at(5), Status: "PAYED" }, now)).toEqual({ kind: "ok" });
    expect(evaluateCasCertificate({ Status: "ISSUED" }, now)).toEqual({ kind: "ok" });
  });
});

describe("AliSslCertificateScanner", () => {
  it("queries OrderType=CERT and UPLOAD (default + Status=EXPIRED) on the centralised endpoint", async () => {
    routeAliCall(mocks.aliCall, { ListUserCertificateOrder: casHandler({}) });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.resourcesScanned).toBe(0);
    const calls = callsFor(mocks.aliCall, "ListUserCertificateOrder");
    expect(calls.map((c) => c[2])).toEqual([
      { OrderType: "CERT", ShowSize: 50, CurrentPage: 1 },
      { OrderType: "CERT", Status: "EXPIRED", ShowSize: 50, CurrentPage: 1 },
      { OrderType: "UPLOAD", ShowSize: 50, CurrentPage: 1 },
      { OrderType: "UPLOAD", Status: "EXPIRED", ShowSize: 50, CurrentPage: 1 },
    ]);
    expect(calls[0][0]).toMatchObject({ service: "cas", action: "ListUserCertificateOrder", version: "2020-04-07", method: "POST", style: "RPC" });
    expect(calls[0][1].region).toBeUndefined();
  });

  it("thresholds: expired 8.0 / <30d 6.0 / <90d 4.0 / healthy none; dedupe across queries; global URN", async () => {
    routeAliCall(mocks.aliCall, {
      ListUserCertificateOrder: casHandler({
        "CERT|": page([
          { id: 101, end: inDays(200) },
          { id: 102, end: inDays(20), status: "WILLEXPIRED" },
          { id: 103, end: inDays(60) },
          { id: 105, end: inDays(10), upload: true },
        ]),
        "CERT|EXPIRED": page([{ id: 104, end: inDays(-3), status: "EXPIRED", expired: true, domain: "old.example.com" }]),
        "UPLOAD|": page([
          { id: 105, end: inDays(10), upload: true },
          { id: 106, endDate: new Date(inDays(45)).toISOString().split("T")[0], upload: true },
        ]),
      }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.resourcesScanned).toBe(6);
    const byId = Object.fromEntries(r.findings.map((f) => [f.resourceArn.split("/").pop(), f]));
    expect(Object.keys(byId).sort()).toEqual(["102", "103", "104", "105", "106"]);
    expect(byId["102"].riskScore).toBe(6.0);
    expect(byId["102"].severity).toBe("MEDIUM");
    expect(byId["102"].title).toBe("Certificate for site-102.example.com expires in 20 days");
    expect(byId["103"].riskScore).toBe(4.0);
    expect(byId["103"].title).toBe("Certificate for site-103.example.com expires in 60 days");
    expect(byId["104"].riskScore).toBe(8.0);
    expect(byId["104"].severity).toBe("HIGH");
    expect(byId["104"].title).toBe("Certificate for old.example.com has expired");
    expect(byId["104"].description).toMatch(/expired 3 days ago/);
    expect(byId["105"].riskScore).toBe(6.0);
    expect(byId["105"].description).toContain("(uploaded)");
    expect(byId["106"].riskScore).toBe(4.0);
    for (const f of r.findings) {
      expect(f.resourceType).toBe("ACS::CAS::Certificate");
      expect(f.resourceArn).toMatch(new RegExp(`^acs:cas::${UID}:certificate/\\d+$`));
      expect(f.region).toBe("global");
      expect(f.provider).toBe("alicloud");
    }
    expect(r.findings.filter((f) => f.resourceArn.endsWith("/105"))).toHaveLength(1);
    noSecrets(r);
  });

  it("abnormal status (REVOKED / CHECKED_FAIL) → 7.5; pending (PAYED) → none", async () => {
    routeAliCall(mocks.aliCall, {
      ListUserCertificateOrder: casHandler({
        "CERT|": page([
          { id: 201, status: "REVOKED", end: inDays(300) },
          { id: 202, status: "CHECKED_FAIL" },
          { id: 203, status: "PAYED", end: inDays(5) },
        ]),
      }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings).toHaveLength(2);
    for (const f of r.findings) {
      expect(f.riskScore).toBe(7.5);
      expect(f.severity).toBe("HIGH");
    }
    expect(r.findings.map((f) => f.title).sort()).toEqual([
      "Certificate for site-201.example.com is in REVOKED status",
      "Certificate for site-202.example.com is in CHECKED_FAIL status",
    ]);
  });

  it("Status=EXPIRED without a date → expired finding", async () => {
    routeAliCall(mocks.aliCall, {
      ListUserCertificateOrder: casHandler({ "UPLOAD|EXPIRED": page([{ id: 301, status: "EXPIRED" }]) }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].riskScore).toBe(8.0);
    expect(r.findings[0].description).toContain("has expired");
  });

  it("pagination (CurrentPage / ShowSize / TotalCount) covers every page", async () => {
    routeAliCall(mocks.aliCall, {
      ListUserCertificateOrder: casHandler({
        "CERT|": (q) => (q.CurrentPage === 1 ? page([{ id: 1, end: inDays(200) }, { id: 2, end: inDays(200) }], 3) : page([{ id: 3, end: inDays(5) }], 3)),
      }),
    });
    const r = await scanner.scan(aliCtx());
    const certCalls = callsFor(mocks.aliCall, "ListUserCertificateOrder").filter((c) => c[2].OrderType === "CERT" && c[2].Status === undefined);
    expect(certCalls.map((c) => c[2].CurrentPage)).toEqual([1, 2]);
    expect(r.resourcesScanned).toBe(3);
    expect(r.findings.map((f) => f.resourceArn)).toEqual([`acs:cas::${UID}:certificate/3`]);
  });

  it("access denied → one warning, remaining queries skipped, success", async () => {
    routeAliCall(mocks.aliCall, {
      ListUserCertificateOrder: () => {
        throw deniedError("cas:ListUserCertificateOrder");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(callsFor(mocks.aliCall, "ListUserCertificateOrder")).toHaveLength(1);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toMatch(/^CAS ListUserCertificateOrder \(OrderType=CERT\): insufficient permissions/);
    noSecrets(r);
  });

  it("throttled on one query → warning, other queries still evaluated", async () => {
    routeAliCall(mocks.aliCall, {
      ListUserCertificateOrder: casHandler({
        "CERT|": () => {
          throw throttledError("cas:ListUserCertificateOrder");
        },
        "UPLOAD|": page([{ id: 9, end: inDays(3), upload: true }]),
      }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(callsFor(mocks.aliCall, "ListUserCertificateOrder")).toHaveLength(4);
    expect(r.warnings?.some((w) => w.includes("throttled"))).toBe(true);
    expect(r.findings).toHaveLength(1);
  });

  it("auth_failed (404 InvalidAccessKeyId.NotFound) → module status error", async () => {
    routeAliCall(mocks.aliCall, {
      ListUserCertificateOrder: () => {
        throw authError("cas:ListUserCertificateOrder");
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
      ListUserCertificateOrder: casHandler({
        "UPLOAD|": () => {
          throw misuseError("cas:ListUserCertificateOrder");
        },
      }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toContain("SSL certificate check failed");
    expect(r.error).toContain("MissingParameter");
  });

  it("alicloud provider exposes ssl_certificate as a global module", () => {
    expect(alibabaCloudProvider.scanners().some((s) => s.moduleName === "ssl_certificate")).toBe(true);
    expect(alibabaCloudProvider.globalModules?.has("ssl_certificate")).toBe(true);
  });
});

describe("hostile server strings (FIX2)", () => {
  it("CAS certificate id / name / domain / SANs are redacted in findings", async () => {
    const hostileCert = {
      CertificateId: hostile("cert"),
      Domain: hostile("dom"),
      Name: hostile("name"),
      Sans: hostile("san"),
      Status: "ISSUED",
      CertEndTime: inDays(-5),
    };
    routeAliCall(mocks.aliCall, {
      ListUserCertificateOrder: casHandler({
        "CERT|": { CertificateOrderList: [hostileCert], TotalCount: 1, CurrentPage: 1, ShowSize: 50 } as ReturnType<typeof page>,
      }),
    });

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(1);
    const f = r.findings[0];
    expect(f.severity).toBe("HIGH");
    expect(f.resourceId.startsWith("dom-[REDACTED]")).toBe(true);
    expect(f.resourceArn.startsWith(`acs:cas::${UID}:certificate/cert-[REDACTED]`)).toBe(true);
    expect(f.description).toContain("name-[REDACTED]");
    expect(f.description).toContain("san-[REDACTED]");
    expectNoHostileLeak(r);
    noSecrets(r);
  });
});
