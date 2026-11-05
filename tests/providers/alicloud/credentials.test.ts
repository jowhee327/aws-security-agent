/**
 * Phase 2 T1 — Alibaba Cloud credentials (plan §3.2). Fake keys only; no network
 * (aliCall is mocked for the STS GetCallerIdentity account-ID lookup).
 */
import { describe, it, expect, vi, beforeAll, afterAll, afterEach, beforeEach } from "vitest";
import { inspect } from "util";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const { aliCallMock } = vi.hoisted(() => ({ aliCallMock: vi.fn() }));
vi.mock("../../../src/providers/alicloud/client.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../../src/providers/alicloud/client.js")>();
  return { ...orig, aliCall: aliCallMock };
});

import {
  parseAliCredentialsIni,
  listAliCredentialProfiles,
  createAliCredentials,
  redactAliCredentials,
  loadAliCredentials,
  loadAliCredentialsFile,
  defaultAliCredentialsPath,
  aliCredentialsFromContext,
  resolveAliAccountId,
  clearAliAccountIdCache,
  AlibabaCloudCredentialsError,
  AlibabaCloudCredentialsNotFoundError,
  ALI_CREDENTIALS_FILE_ENV,
  REDACTED,
} from "../../../src/providers/alicloud/credentials.js";
import { ALI_API } from "../../../src/providers/alicloud/api-catalog.js";
import { redactAliDiagnostic } from "../../../src/providers/alicloud/errors.js";

// Fake, non-functional key material.
const FAKE_AK = "LTAI5tFAKEFAKEFAKE0000001";
const FAKE_SK = "FakeSecretKeyDoNotUseXXXXXXXXXXXX01";
const FAKE_STS_AK = "STS.NUFAKEFAKEFAKEFAKE00002";
const FAKE_STS_SK = "FakeStsSecretDoNotUseXXXXXXXXXXX02";
const FAKE_TOKEN = "CAISFAKEFAKEFAKEFAKEtokenDoNotUse0003";
const FAKE_ENV_AK = "LTAI5tFAKEENVENVENV0000004";
const FAKE_ENV_SK = "FakeEnvSecretDoNotUseXXXXXXXXXXX04";
const FAKE_LEGACY_AK = "LTAI5tFAKELEGACYLEG0000005";
const FAKE_LEGACY_SK = "FakeLegacySecretDoNotUseXXXXXXXX05";
const ALL_SECRETS = [FAKE_AK, FAKE_SK, FAKE_STS_AK, FAKE_STS_SK, FAKE_TOKEN, FAKE_ENV_AK, FAKE_ENV_SK, FAKE_LEGACY_AK, FAKE_LEGACY_SK];

const INI = `
# Alibaba Cloud credentials (fake)
[default]
type = access_key
access_key_id = ${FAKE_AK}
access_key_secret   =   ${FAKE_SK}   ; trailing comment

[temp]
type = sts
access_key_id = ${FAKE_STS_AK}
access_key_secret = ${FAKE_STS_SK}
security_token = ${FAKE_TOKEN}

[notype]
access_key_id = ${FAKE_AK}
access_key_secret = ${FAKE_SK}

[role]
type = ram_role_arn
access_key_id = ${FAKE_AK}
access_key_secret = ${FAKE_SK}
role_arn = acs:ram::1234567890123456:role/fake

[broken]
type = access_key
access_key_id = ${FAKE_AK}

[broken-sts]
type = sts
access_key_id = ${FAKE_STS_AK}
access_key_secret = ${FAKE_STS_SK}
`;

/** Capture everything that could reach a terminal / the MCP stdio channel. */
const captured: string[] = [];
let stdoutSpy: ReturnType<typeof vi.spyOn>;
let stderrSpy: ReturnType<typeof vi.spyOn>;
const consoleSpies: Array<ReturnType<typeof vi.spyOn>> = [];

beforeAll(() => {
  stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
    captured.push(String(chunk));
    return true;
  }) as never);
  stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(((chunk: unknown) => {
    captured.push(String(chunk));
    return true;
  }) as never);
  for (const m of ["log", "error", "warn", "info", "debug"] as const) {
    consoleSpies.push(
      vi.spyOn(console, m).mockImplementation((...args: unknown[]) => {
        captured.push(args.map((a) => (typeof a === "string" ? a : inspect(a))).join(" "));
      }),
    );
  }
});

afterAll(() => {
  stdoutSpy.mockRestore();
  stderrSpy.mockRestore();
  for (const s of consoleSpies) s.mockRestore();
});

afterEach(() => {
  const all = captured.join("\n");
  for (const secret of ALL_SECRETS) {
    expect(all, "no console/stdout/stderr output may contain secret material").not.toContain(secret);
  }
  captured.length = 0;
});

let tmp: string;
beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), "ali-creds-test-"));
});
afterAll(() => {
  rmSync(tmp, { recursive: true, force: true });
});

/** An env with no Alibaba variables whose credentials file does not exist. */
function emptyEnv(): NodeJS.ProcessEnv {
  return { [ALI_CREDENTIALS_FILE_ENV]: join(tmp, "does-not-exist") };
}

describe("parseAliCredentialsIni", () => {
  it("parses the default access_key profile with tolerant syntax", () => {
    expect(parseAliCredentialsIni(INI)).toEqual({ accessKeyId: FAKE_AK, accessKeySecret: FAKE_SK });
  });

  it("parses an sts profile with security_token", () => {
    expect(parseAliCredentialsIni(INI, "temp")).toEqual({
      accessKeyId: FAKE_STS_AK,
      accessKeySecret: FAKE_STS_SK,
      securityToken: FAKE_TOKEN,
    });
  });

  it("treats a missing type as access_key", () => {
    expect(parseAliCredentialsIni(INI, "notype")).toEqual({ accessKeyId: FAKE_AK, accessKeySecret: FAKE_SK });
  });

  it("matches profile names case-insensitively as a fallback", () => {
    expect(parseAliCredentialsIni(INI, "TEMP")?.securityToken).toBe(FAKE_TOKEN);
  });

  it("returns undefined for an absent profile", () => {
    expect(parseAliCredentialsIni(INI, "nope")).toBeUndefined();
    expect(parseAliCredentialsIni("", "default")).toBeUndefined();
  });

  it("rejects unsupported credential types without echoing values", () => {
    let err: unknown;
    try {
      parseAliCredentialsIni(INI, "role");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(AlibabaCloudCredentialsError);
    const msg = (err as Error).message;
    expect(msg).toContain("unsupported credential type ram_role_arn");
    expect(msg).toContain("Phase 2");
    for (const s of ALL_SECRETS) expect(msg).not.toContain(s);
  });

  it("names missing fields only (access_key and sts)", () => {
    expect(() => parseAliCredentialsIni(INI, "broken")).toThrow(/missing access_key_secret/);
    expect(() => parseAliCredentialsIni(INI, "broken-sts")).toThrow(/missing security_token/);
    try {
      parseAliCredentialsIni(INI, "broken");
    } catch (e) {
      for (const s of ALL_SECRETS) expect((e as Error).message).not.toContain(s);
    }
  });

  it("lists profile names", () => {
    expect(listAliCredentialProfiles(INI)).toEqual(["default", "temp", "notype", "role", "broken", "broken-sts"]);
  });

  it("handles CRLF line endings, a BOM and quoted values", () => {
    const text = `\uFEFF[default]\r\naccess_key_id = "${FAKE_AK}"\r\naccess_key_secret = '${FAKE_SK}'\r\n`;
    expect(parseAliCredentialsIni(text)).toEqual({ accessKeyId: FAKE_AK, accessKeySecret: FAKE_SK });
  });
});

describe("createAliCredentials / redactAliCredentials", () => {
  it("keeps secrets non-enumerable and redacts JSON / inspect / toString / spread", () => {
    const c = createAliCredentials({ accessKeyId: FAKE_STS_AK, accessKeySecret: FAKE_STS_SK, securityToken: FAKE_TOKEN, source: "explicit" });
    expect(c.accessKeyId).toBe(FAKE_STS_AK);
    expect(c.accessKeySecret).toBe(FAKE_STS_SK);
    expect(c.securityToken).toBe(FAKE_TOKEN);
    expect(c.kind).toBe("alicloud");
    expect(Object.keys(c).sort()).toEqual(["kind", "source"]);
    expect(Object.isFrozen(c)).toBe(true);
    const views = [JSON.stringify(c), inspect(c), String(c), JSON.stringify({ ...c }), `${c}`];
    for (const v of views) {
      for (const s of [FAKE_STS_AK, FAKE_STS_SK, FAKE_TOKEN]) expect(v).not.toContain(s);
    }
    expect(JSON.parse(JSON.stringify(c))).toEqual({
      kind: "alicloud",
      accessKeyId: "STS.****0002",
      accessKeySecret: REDACTED,
      securityToken: REDACTED,
      source: "explicit",
    });
  });

  it("redactAliCredentials masks the AK as first 4 + last 4", () => {
    const r = redactAliCredentials({ kind: "alicloud", accessKeyId: FAKE_AK, accessKeySecret: FAKE_SK });
    expect(r).toEqual({ kind: "alicloud", accessKeyId: "LTAI****0001", accessKeySecret: REDACTED });
  });

  it("rejects a half-specified pair", () => {
    expect(() => createAliCredentials({ accessKeyId: FAKE_AK })).toThrow(AlibabaCloudCredentialsError);
    expect(() => createAliCredentials({ accessKeySecret: FAKE_SK })).toThrow(/accessKeyId and accessKeySecret/);
  });

  it("registers values with the diagnostic redactor", () => {
    const sk = "FakeRegisteredSecretValue000000006";
    createAliCredentials({ accessKeyId: FAKE_AK, accessKeySecret: sk });
    expect(redactAliDiagnostic(`oops ${sk} leaked`)).toBe("oops [REDACTED] leaked");
  });
});

describe("loadAliCredentials (chain)", () => {
  it("explicit credentials win over env and file", () => {
    const env = { ALIBABA_CLOUD_ACCESS_KEY_ID: FAKE_ENV_AK, ALIBABA_CLOUD_ACCESS_KEY_SECRET: FAKE_ENV_SK };
    const c = loadAliCredentials({ explicit: { accessKeyId: FAKE_AK, accessKeySecret: FAKE_SK }, env });
    expect(c.accessKeyId).toBe(FAKE_AK);
    expect(c.source).toBe("explicit");
  });

  it("reads ALIBABA_CLOUD_* env (with STS token)", () => {
    const env = {
      ...emptyEnv(),
      ALIBABA_CLOUD_ACCESS_KEY_ID: FAKE_ENV_AK,
      ALIBABA_CLOUD_ACCESS_KEY_SECRET: FAKE_ENV_SK,
      ALIBABA_CLOUD_SECURITY_TOKEN: FAKE_TOKEN,
      ALICLOUD_ACCESS_KEY: FAKE_LEGACY_AK,
      ALICLOUD_SECRET_KEY: FAKE_LEGACY_SK,
    };
    const c = loadAliCredentials({ env });
    expect(c.accessKeyId).toBe(FAKE_ENV_AK);
    expect(c.accessKeySecret).toBe(FAKE_ENV_SK);
    expect(c.securityToken).toBe(FAKE_TOKEN);
    expect(c.source).toBe("env");
  });

  it("uses legacy ALICLOUD_* names only when both new names are absent", () => {
    const legacy = { ALICLOUD_ACCESS_KEY: FAKE_LEGACY_AK, ALICLOUD_SECRET_KEY: FAKE_LEGACY_SK, ALICLOUD_SECURITY_TOKEN: FAKE_TOKEN };
    const c = loadAliCredentials({ env: { ...emptyEnv(), ...legacy } });
    expect(c.accessKeyId).toBe(FAKE_LEGACY_AK);
    expect(c.securityToken).toBe(FAKE_TOKEN);
    expect(c.source).toBe("env");

    // A half-set new pair disables the legacy fallback (and falls through to the file).
    expect(() => loadAliCredentials({ env: { ...emptyEnv(), ...legacy, ALIBABA_CLOUD_ACCESS_KEY_ID: FAKE_ENV_AK } })).toThrow(
      AlibabaCloudCredentialsNotFoundError,
    );
  });

  it("falls back to the INI file (ALIBABA_CLOUD_CREDENTIALS_FILE + ALIBABA_CLOUD_PROFILE)", () => {
    const file = join(tmp, "credentials");
    writeFileSync(file, INI, "utf8");
    const c = loadAliCredentials({ env: { [ALI_CREDENTIALS_FILE_ENV]: file, ALIBABA_CLOUD_PROFILE: "temp" } });
    expect(c.accessKeyId).toBe(FAKE_STS_AK);
    expect(c.securityToken).toBe(FAKE_TOKEN);
    expect(c.source).toBe("file");

    const d = loadAliCredentials({ env: {}, filePath: file });
    expect(d.accessKeyId).toBe(FAKE_AK);
    expect(d.securityToken).toBeUndefined();
  });

  it("explicit filePath / profile options override env", () => {
    const file = join(tmp, "credentials-opts");
    writeFileSync(file, INI, "utf8");
    const c = loadAliCredentials({ env: { ALIBABA_CLOUD_PROFILE: "default" }, filePath: file, profile: "temp" });
    expect(c.accessKeyId).toBe(FAKE_STS_AK);
  });

  it("propagates an invalid profile error with the file path but no values", () => {
    const file = join(tmp, "credentials-bad");
    writeFileSync(file, INI, "utf8");
    let err: unknown;
    try {
      loadAliCredentials({ env: {}, filePath: file, profile: "role" });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(AlibabaCloudCredentialsError);
    expect((err as Error).message).toContain(file);
    for (const s of ALL_SECRETS) expect((err as Error).message).not.toContain(s);
  });

  it("loadAliCredentialsFile returns undefined for a missing file or profile", () => {
    expect(loadAliCredentialsFile(join(tmp, "missing"))).toBeUndefined();
    const file = join(tmp, "credentials-one");
    writeFileSync(file, INI, "utf8");
    expect(loadAliCredentialsFile(file, "nope")).toBeUndefined();
  });

  it("NotFound error lists sources only, never values", () => {
    let err: unknown;
    try {
      loadAliCredentials({ env: { ...emptyEnv(), ALIBABA_CLOUD_ACCESS_KEY_ID: FAKE_ENV_AK } });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(AlibabaCloudCredentialsNotFoundError);
    const msg = (err as Error).message;
    expect(msg).toContain("ALIBABA_CLOUD_ACCESS_KEY_ID");
    expect(msg).toContain("ALICLOUD_ACCESS_KEY");
    expect(msg).toContain("does-not-exist");
    expect(msg).not.toContain(FAKE_ENV_AK);
    expect((err as AlibabaCloudCredentialsNotFoundError).sources.length).toBe(4);
    expect(msg).not.toContain(".aliyun");
  });

  it("defaultAliCredentialsPath honours the env override and defaults to ~/.alibabacloud/credentials", () => {
    expect(defaultAliCredentialsPath({ [ALI_CREDENTIALS_FILE_ENV]: "/x/y" })).toBe("/x/y");
    expect(defaultAliCredentialsPath({})).toMatch(/[\\/]\.alibabacloud[\\/]credentials$/);
  });

  it("aliCredentialsFromContext uses Alibaba context credentials", () => {
    const c = aliCredentialsFromContext({ credentials: { kind: "alicloud", accessKeyId: FAKE_AK, accessKeySecret: FAKE_SK } });
    expect(c.accessKeyId).toBe(FAKE_AK);
    expect(c.source).toBe("explicit");
  });
});

describe("resolveAliAccountId (STS GetCallerIdentity)", () => {
  beforeEach(() => {
    aliCallMock.mockReset();
    clearAliAccountIdCache();
  });

  it("returns AccountId and caches successes per credentials", async () => {
    aliCallMock.mockResolvedValue({ AccountId: "1234567890123456", Arn: "acs:ram::1234567890123456:root" });
    const creds = createAliCredentials({ accessKeyId: FAKE_AK, accessKeySecret: FAKE_SK });
    expect(await resolveAliAccountId(creds)).toBe("1234567890123456");
    expect(await resolveAliAccountId(creds)).toBe("1234567890123456");
    expect(aliCallMock).toHaveBeenCalledTimes(1);
    expect(aliCallMock.mock.calls[0][0]).toBe(ALI_API.sts.GetCallerIdentity);
    expect(aliCallMock.mock.calls[0][1].credentials).toBe(creds);

    await resolveAliAccountId(creds, { force: true });
    expect(aliCallMock).toHaveBeenCalledTimes(2);
  });

  it("does not cache failures", async () => {
    const creds = createAliCredentials({ accessKeyId: FAKE_AK, accessKeySecret: FAKE_SK });
    aliCallMock.mockRejectedValueOnce(new Error("boom"));
    await expect(resolveAliAccountId(creds)).rejects.toThrow("boom");
    aliCallMock.mockResolvedValueOnce({ AccountId: "1234567890123456" });
    expect(await resolveAliAccountId(creds)).toBe("1234567890123456");
    expect(aliCallMock).toHaveBeenCalledTimes(2);
  });

  it("rejects an empty AccountId", async () => {
    aliCallMock.mockResolvedValue({});
    const creds = createAliCredentials({ accessKeyId: FAKE_AK, accessKeySecret: FAKE_SK });
    await expect(resolveAliAccountId(creds)).rejects.toThrow(/no AccountId/);
  });
});
