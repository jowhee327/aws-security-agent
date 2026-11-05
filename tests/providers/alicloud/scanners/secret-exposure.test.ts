/**
 * Phase 2 T4 — AliSecretExposureScanner (secret_exposure): ECS DescribeInstances →
 * DescribeUserData (base64, incl. bad base64), FC3 ListFunctions environmentVariables,
 * pagination, caps, degrade, auth_failed / api_misuse → error, and the guarantee that the
 * matched secret value never appears in the result. aliCall is mocked by spec.action; fake keys only; no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({ aliCall: vi.fn() }));
vi.mock("../../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: mocks.aliCall };
});

import {
  AliSecretExposureScanner,
  ALI_SECRET_PATTERNS,
  decodeAliUserData,
  ECS_MAX_USERDATA,
  fcEnvEntries,
  matchAliNamePatterns,
  matchAliValuePatterns,
} from "../../../../src/providers/alicloud/scanners/secret-exposure.js";
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
import { expectNoHostileLeak, hostile, HOSTILE_AK } from "./helpers.js";

/* ------------------------------------------------------------------------ */
/* Fixtures (fake secrets only)                                             */
/* ------------------------------------------------------------------------ */

/** Planted Alibaba AK (fake) — distinct from the scan credentials. */
const PLANTED_ALI_AK = "LTAI5tFAKEFAKEFAKE0000002";
const PLANTED_AWS_AK = "AKIAIOSFODNN7EXAMPLE";
const PLANTED_PEM_BODY = "MIIFAKEPRIVATEKEYBODYDONOTUSE0000";
const PLANTED_PEM = `-----BEGIN RSA PRIVATE KEY-----\n${PLANTED_PEM_BODY}\n-----END RSA PRIVATE KEY-----`;
const PLANTED_PASSWORD = "FakePassw0rdDoNotUse!";

const b64 = (s: string) => Buffer.from(s, "utf-8").toString("base64");

function instancesPage(ids: string[], total = ids.length) {
  return { Instances: { Instance: ids.map((id) => ({ InstanceId: id, InstanceName: `name-${id}`, Status: "Running" })) }, TotalCount: total, PageNumber: 1, PageSize: 100 };
}

const FC_EMPTY: Record<string, AliHandler | object> = { ListFunctions: { functions: [] } };
const ECS_EMPTY: Record<string, AliHandler | object> = { DescribeInstances: instancesPage([]) };

/** DescribeUserData handler from an InstanceId → raw UserData map. */
function userDataHandler(map: Record<string, string | undefined>): AliHandler {
  return (q) => ({ RegionId: q.RegionId, InstanceId: q.InstanceId, UserData: map[q.InstanceId as string] ?? "" });
}

const scanner = new AliSecretExposureScanner();

function assertNoSecretValues(r: ScanResult): void {
  const text = JSON.stringify(r);
  for (const v of [PLANTED_ALI_AK, PLANTED_AWS_AK, PLANTED_PEM_BODY, PLANTED_PASSWORD, FAKE_AK, FAKE_SK, "LTAI5t"]) {
    expect(text).not.toContain(v);
  }
}

beforeEach(() => {
  isolateAliEnv();
  mocks.aliCall.mockReset();
});
afterEach(() => restoreAliEnv());

/* ------------------------------------------------------------------------ */
/* Pure helpers                                                             */
/* ------------------------------------------------------------------------ */

describe("helpers", () => {
  it("decodeAliUserData decodes valid base64", () => {
    expect(decodeAliUserData(b64("#!/bin/bash\necho hi"))).toBe("#!/bin/bash\necho hi");
    expect(decodeAliUserData(`  ${b64("abc")}\n`)).toBe("abc");
  });

  it("decodeAliUserData never throws on bad base64 / binary and falls back to the raw text", () => {
    expect(() => decodeAliUserData("%%% not base64 !!!")).not.toThrow();
    expect(decodeAliUserData("%%% not base64 !!!")).toBe("%%% not base64 !!!");
    expect(decodeAliUserData("abcde")).toBe("abcde"); // length % 4 === 1 → not base64
    const binary = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe, 0xfd]).toString("base64");
    expect(decodeAliUserData(binary)).toBe(binary);
  });

  it("decodeAliUserData: empty / non-string → undefined", () => {
    expect(decodeAliUserData("")).toBeUndefined();
    expect(decodeAliUserData("   ")).toBeUndefined();
    expect(decodeAliUserData(undefined)).toBeUndefined();
    expect(decodeAliUserData(42)).toBeUndefined();
  });

  it("ALI_SECRET_PATTERNS = AWS patterns + Alibaba AK / env-name detectors", () => {
    const names = ALI_SECRET_PATTERNS.map((p) => p.name);
    expect(names).toEqual(expect.arrayContaining(["AWS Access Key", "Private Key", "Password in env var", "Alibaba Cloud Access Key", "Alibaba Cloud credential in env var"]));
    expect(matchAliValuePatterns(`export AK=${PLANTED_ALI_AK}`).map((p) => p.name)).toEqual(["Alibaba Cloud Access Key"]);
    expect(matchAliValuePatterns(PLANTED_AWS_AK).map((p) => p.name)).toEqual(["AWS Access Key"]);
    expect(matchAliValuePatterns("LTAIshort")).toEqual([]);
    expect(matchAliNamePatterns("ALIBABA_CLOUD_ACCESS_KEY_SECRET").map((p) => p.name)).toEqual(["Alibaba Cloud credential in env var"]);
    expect(matchAliNamePatterns("db_password").map((p) => p.name)).toEqual(["Password in env var"]);
    expect(matchAliNamePatterns("LOG_LEVEL")).toEqual([]);
  });

  it("fcEnvEntries tolerates missing / odd environmentVariables", () => {
    expect(fcEnvEntries({})).toEqual([]);
    expect(fcEnvEntries({ environmentVariables: null })).toEqual([]);
    expect(fcEnvEntries({ environmentVariables: ["x"] })).toEqual([]);
    expect(fcEnvEntries({ environmentVariables: { A: "1", B: 2, C: null } })).toEqual([
      ["A", "1"],
      ["B", "2"],
      ["C", ""],
    ]);
  });
});

/* ------------------------------------------------------------------------ */
/* ECS user data                                                            */
/* ------------------------------------------------------------------------ */

describe("ECS user data", () => {
  it("normal hit: base64 user data with Alibaba + AWS keys → two 9.5 findings, value never echoed", async () => {
    routeAliCall(mocks.aliCall, {
      ...FC_EMPTY,
      DescribeInstances: instancesPage(["i-hit", "i-clean"]),
      DescribeUserData: userDataHandler({
        "i-hit": b64(`#!/bin/bash\nexport ALIBABA_CLOUD_ACCESS_KEY_ID=${PLANTED_ALI_AK}\nexport AWS_ACCESS_KEY_ID=${PLANTED_AWS_AK}\n`),
        "i-clean": b64("#!/bin/bash\nyum -y update\n"),
      }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.resourcesScanned).toBe(2);
    expect(r.findingsCount).toBe(2);
    const titles = r.findings.map((f) => f.title).sort();
    expect(titles).toEqual(["ECS i-hit user data contains AWS Access Key", "ECS i-hit user data contains Alibaba Cloud Access Key"]);
    for (const f of r.findings) {
      expect(f.riskScore).toBe(9.5);
      expect(f.severity).toBe("CRITICAL");
      expect(f.resourceType).toBe("ACS::ECS::Instance");
      expect(f.resourceId).toBe("i-hit");
      expect(f.resourceArn).toBe(`acs:ecs:cn-hangzhou:${UID}:instance/i-hit`);
      expect(f.region).toBe("cn-hangzhou");
      expect(f.provider).toBe("alicloud");
    }
    assertNoSecretValues(r);
    const ud = callsFor(mocks.aliCall, "DescribeUserData");
    expect(ud.map((c) => c[2])).toEqual([
      { RegionId: "cn-hangzhou", InstanceId: "i-hit" },
      { RegionId: "cn-hangzhou", InstanceId: "i-clean" },
    ]);
    expect(ud[0][1].region).toBe("cn-hangzhou");
  });

  it("private key in user data → 8.0 finding", async () => {
    routeAliCall(mocks.aliCall, {
      ...FC_EMPTY,
      DescribeInstances: instancesPage(["i-pem"]),
      DescribeUserData: userDataHandler({ "i-pem": b64(`cat > /root/key.pem <<EOF\n${PLANTED_PEM}\nEOF\n`) }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].title).toBe("ECS i-pem user data contains Private Key");
    expect(r.findings[0].riskScore).toBe(8.0);
    assertNoSecretValues(r);
  });

  it("bad base64 user data is scanned as raw text (no throw)", async () => {
    routeAliCall(mocks.aliCall, {
      ...FC_EMPTY,
      DescribeInstances: instancesPage(["i-raw", "i-empty"]),
      DescribeUserData: userDataHandler({ "i-raw": `not*base64!! key=${PLANTED_ALI_AK}`, "i-empty": undefined }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.title)).toEqual(["ECS i-raw user data contains Alibaba Cloud Access Key"]);
    assertNoSecretValues(r);
  });

  it("no hit: clean user data → 0 findings", async () => {
    routeAliCall(mocks.aliCall, {
      ...FC_EMPTY,
      DescribeInstances: instancesPage(["i-1"]),
      DescribeUserData: userDataHandler({ "i-1": b64("#!/bin/bash\necho hello\n") }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.resourcesScanned).toBe(1);
    expect(r.warnings).toBeUndefined();
  });

  it("DescribeInstances pagination (PageNumber / TotalCount) covers every page", async () => {
    routeAliCall(mocks.aliCall, {
      ...FC_EMPTY,
      DescribeInstances: (q) => (q.PageNumber === 1 ? instancesPage(["i-1", "i-2"], 3) : instancesPage(["i-3"], 3)),
      DescribeUserData: userDataHandler({ "i-3": b64(`AK=${PLANTED_ALI_AK}`) }),
    });
    const r = await scanner.scan(aliCtx());
    const pages = callsFor(mocks.aliCall, "DescribeInstances");
    expect(pages).toHaveLength(2);
    expect(pages.map((c) => c[2].PageNumber)).toEqual([1, 2]);
    expect(pages[0][2]).toMatchObject({ RegionId: "cn-hangzhou", PageSize: 100 });
    expect(callsFor(mocks.aliCall, "DescribeUserData")).toHaveLength(3);
    expect(r.findings.map((f) => f.resourceId)).toEqual(["i-3"]);
  });

  it(`caps DescribeUserData at ECS_MAX_USERDATA (${ECS_MAX_USERDATA}) with a warning`, async () => {
    const ids = Array.from({ length: ECS_MAX_USERDATA + 3 }, (_, i) => `i-${i}`);
    routeAliCall(mocks.aliCall, {
      ...FC_EMPTY,
      DescribeInstances: instancesPage(ids),
      DescribeUserData: userDataHandler({}),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(callsFor(mocks.aliCall, "DescribeUserData")).toHaveLength(ECS_MAX_USERDATA);
    expect(r.warnings?.some((w) => w.includes(`first ${ECS_MAX_USERDATA} only`))).toBe(true);
  });

  it("access denied on DescribeUserData → one aggregated warning, success", async () => {
    routeAliCall(mocks.aliCall, {
      ...FC_EMPTY,
      DescribeInstances: instancesPage(["i-1", "i-2"]),
      DescribeUserData: () => {
        throw deniedError("ecs:DescribeUserData");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toEqual([]);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0]).toMatch(/^ECS DescribeUserData failed for 2 instance\(s\) in cn-hangzhou; first: ECS i-1 DescribeUserData: insufficient permissions/);
    assertNoSecretValues(r);
  });

  it("access denied on DescribeInstances → warning, FC still scanned", async () => {
    routeAliCall(mocks.aliCall, {
      ListFunctions: { functions: [{ functionName: "fn-1", environmentVariables: { DB_PASSWORD: PLANTED_PASSWORD } }] },
      DescribeInstances: () => {
        throw deniedError("ecs:DescribeInstances");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings).toHaveLength(1);
    expect(r.warnings?.some((w) => /^ECS DescribeInstances: insufficient permissions/.test(w))).toBe(true);
  });

  it("auth_failed (404 InvalidAccessKeyId.NotFound) on DescribeInstances → module status error", async () => {
    routeAliCall(mocks.aliCall, {
      ...FC_EMPTY,
      DescribeInstances: () => {
        throw authError("ecs:DescribeInstances");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
    expect(r.error).toContain("InvalidAccessKeyId.NotFound");
    expect(r.findings).toEqual([]);
    assertNoSecretValues(r);
  });

  it("auth_failed on a per-instance DescribeUserData → module status error", async () => {
    routeAliCall(mocks.aliCall, {
      ...FC_EMPTY,
      DescribeInstances: instancesPage(["i-1"]),
      DescribeUserData: () => {
        throw authError("ecs:DescribeUserData");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
  });

  it("api_misuse on DescribeUserData → module status error (not swallowed)", async () => {
    routeAliCall(mocks.aliCall, {
      ...FC_EMPTY,
      DescribeInstances: instancesPage(["i-1"]),
      DescribeUserData: () => {
        throw misuseError("ecs:DescribeUserData");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toContain("ECS user data secret scan failed");
    expect(r.error).toContain("MissingParameter");
  });
});

/* ------------------------------------------------------------------------ */
/* Function Compute                                                         */
/* ------------------------------------------------------------------------ */

describe("Function Compute environment variables", () => {
  it("normal hit: value + name detectors; findings name the env key but never the value", async () => {
    routeAliCall(mocks.aliCall, {
      ...ECS_EMPTY,
      ListFunctions: {
        functions: [
          {
            functionName: "fn-leaky",
            functionArn: `acs:fc:cn-hangzhou:${UID}:functions/fn-leaky`,
            environmentVariables: {
              MY_KEY: PLANTED_ALI_AK,
              TLS_KEY: PLANTED_PEM,
              DB_PASSWORD: PLANTED_PASSWORD,
              ALIBABA_CLOUD_ACCESS_KEY_SECRET: FAKE_SK,
              LOG_LEVEL: "info",
            },
          },
          { functionName: "fn-clean", environmentVariables: { LOG_LEVEL: "debug" } },
          { functionName: "fn-noenv" },
        ],
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.resourcesScanned).toBe(3);
    const byTitle = Object.fromEntries(r.findings.map((f) => [f.title, f]));
    expect(Object.keys(byTitle).sort()).toEqual([
      "Function Compute fn-leaky env var contains Alibaba Cloud Access Key",
      "Function Compute fn-leaky env var contains Private Key",
      'Function Compute fn-leaky has suspicious env var "ALIBABA_CLOUD_ACCESS_KEY_SECRET"',
      'Function Compute fn-leaky has suspicious env var "DB_PASSWORD"',
    ]);
    expect(byTitle["Function Compute fn-leaky env var contains Alibaba Cloud Access Key"].riskScore).toBe(9.5);
    expect(byTitle["Function Compute fn-leaky env var contains Alibaba Cloud Access Key"].description).toContain('"MY_KEY"');
    expect(byTitle["Function Compute fn-leaky env var contains Private Key"].riskScore).toBe(9.0);
    expect(byTitle['Function Compute fn-leaky has suspicious env var "DB_PASSWORD"'].riskScore).toBe(7.5);
    for (const f of r.findings) {
      expect(f.resourceType).toBe("ACS::FC::Function");
      expect(f.resourceId).toBe("fn-leaky");
      expect(f.resourceArn).toBe(`acs:fc:cn-hangzhou:${UID}:function/fn-leaky`);
    }
    assertNoSecretValues(r);
  });

  it("no hit: clean env vars → 0 findings", async () => {
    routeAliCall(mocks.aliCall, {
      ...ECS_EMPTY,
      ListFunctions: { functions: [{ functionName: "fn", environmentVariables: { REGION: "cn-hangzhou", LOG_LEVEL: "info" } }] },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.findings).toEqual([]);
    expect(r.resourcesScanned).toBe(1);
  });

  it("ListFunctions nextToken pagination (ROA limit / nextToken)", async () => {
    routeAliCall(mocks.aliCall, {
      ...ECS_EMPTY,
      ListFunctions: (q) =>
        q.nextToken === undefined
          ? { functions: [{ functionName: "fn-1" }], nextToken: "tok-2" }
          : { functions: [{ functionName: "fn-2", environmentVariables: { K: PLANTED_AWS_AK } }] },
    });
    const r = await scanner.scan(aliCtx());
    const calls = callsFor(mocks.aliCall, "ListFunctions");
    expect(calls).toHaveLength(2);
    expect(calls[0][0]).toMatchObject({ service: "fc", action: "ListFunctions", style: "ROA", method: "GET", pathname: "/2023-03-30/functions" });
    expect(calls[0][2]).toEqual({ limit: 100 });
    expect(calls[1][2]).toEqual({ limit: 100, nextToken: "tok-2" });
    expect(calls[0][1].region).toBe("cn-hangzhou");
    expect(r.resourcesScanned).toBe(2);
    expect(r.findings.map((f) => f.title)).toEqual(["Function Compute fn-2 env var contains AWS Access Key"]);
    assertNoSecretValues(r);
  });

  it("access denied on ListFunctions → warning, ECS still scanned", async () => {
    routeAliCall(mocks.aliCall, {
      ListFunctions: () => {
        throw deniedError("fc:ListFunctions");
      },
      DescribeInstances: instancesPage(["i-1"]),
      DescribeUserData: userDataHandler({ "i-1": b64(`AK=${PLANTED_ALI_AK}`) }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findings.map((f) => f.resourceId)).toEqual(["i-1"]);
    expect(r.warnings?.some((w) => /^Function Compute ListFunctions: insufficient permissions/.test(w))).toBe(true);
  });

  it("auth_failed on ListFunctions → module status error", async () => {
    routeAliCall(mocks.aliCall, {
      ...ECS_EMPTY,
      ListFunctions: () => {
        throw authError("fc:ListFunctions");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toMatch(/^Alibaba Cloud authentication failed/);
    assertNoSecretValues(r);
  });

  it("api_misuse on ListFunctions → module status error", async () => {
    routeAliCall(mocks.aliCall, {
      ...ECS_EMPTY,
      ListFunctions: () => {
        throw misuseError("fc:ListFunctions");
      },
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("error");
    expect(r.error).toContain("Function Compute secret scan failed");
    expect(r.error).toContain("MissingParameter");
  });
});

describe("combined + registration", () => {
  it("hits across ECS user data and FC env in one scan; no secret value anywhere in the result", async () => {
    routeAliCall(mocks.aliCall, {
      ListFunctions: { functions: [{ functionName: "fn-a", environmentVariables: { SECRET: PLANTED_PASSWORD, KEY: PLANTED_ALI_AK } }] },
      DescribeInstances: instancesPage(["i-a"]),
      DescribeUserData: userDataHandler({ "i-a": b64(`${PLANTED_PEM}\n${PLANTED_AWS_AK}`) }),
    });
    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.resourcesScanned).toBe(2);
    expect(r.findings.map((f) => f.resourceType).sort()).toEqual(["ACS::ECS::Instance", "ACS::ECS::Instance", "ACS::FC::Function", "ACS::FC::Function"]);
    expect(r.findingsCount).toBe(4);
    assertNoSecretValues(r);
  });

  it("alicloud provider exposes secret_exposure as a regional module", () => {
    expect(alibabaCloudProvider.scanners().some((s) => s.moduleName === "secret_exposure")).toBe(true);
    expect(alibabaCloudProvider.globalModules?.has("secret_exposure")).toBe(false);
  });
});

describe("hostile server strings (FIX2)", () => {
  it("FC function name + env var names are redacted; values never emitted", async () => {
    const fnName = hostile("fn");
    routeAliCall(mocks.aliCall, {
      ...ECS_EMPTY,
      ListFunctions: {
        functions: [
          {
            functionName: fnName,
            environmentVariables: {
              [`APP_${HOSTILE_AK}`]: PLANTED_ALI_AK,
              [hostile("VAR")]: `export AK=${PLANTED_ALI_AK}`,
            },
          },
        ],
      },
    });

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(2);
    expect(r.findings.every((f) => f.resourceId.startsWith("fn-[REDACTED]"))).toBe(true);
    expect(r.findings.some((f) => f.description.includes('"APP_[REDACTED]"'))).toBe(true);
    expectNoHostileLeak(r);
    assertNoSecretValues(r);
  });

  it("ECS instance id is redacted in findings; the raw id still reaches DescribeUserData", async () => {
    const id = hostile("i");
    routeAliCall(mocks.aliCall, {
      ...FC_EMPTY,
      DescribeInstances: instancesPage([id]),
      DescribeUserData: userDataHandler({ [id]: b64(`#!/bin/bash\nexport ALI_AK=${PLANTED_ALI_AK}\n`) }),
    });

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.findingsCount).toBe(1);
    expect(callsFor(mocks.aliCall, "DescribeUserData")[0][2].InstanceId).toBe(id);
    expect(r.findings[0].resourceId.startsWith("i-[REDACTED]")).toBe(true);
    expect(r.findings[0].resourceArn.startsWith(`acs:ecs:cn-hangzhou:${UID}:instance/i-[REDACTED]`)).toBe(true);
    expectNoHostileLeak(r);
    assertNoSecretValues(r);
  });

  it("DescribeUserData failure warning never echoes a hostile instance id", async () => {
    routeAliCall(mocks.aliCall, {
      ...FC_EMPTY,
      DescribeInstances: instancesPage([hostile("i")]),
      DescribeUserData: () => {
        throw deniedError("ecs:DescribeUserData");
      },
    });

    const r = await scanner.scan(aliCtx());
    expect(r.status).toBe("success");
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings![0].startsWith("ECS i-[REDACTED]")).toBe(true);
    expectNoHostileLeak(r);
  });
});
