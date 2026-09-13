import { describe, it, expect, vi, beforeAll, afterAll, afterEach, beforeEach } from "vitest";
import { inspect } from "util";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

import {
  parseHuaweiCredentialsIni,
  createHuaweiCredentials,
  redactHuaweiCredentials,
  loadHuaweiCredentials,
  loadHuaweiCredentialsFile,
  defaultHuaweiCredentialsPath,
  resolveProjects,
  resolveRegionScope,
  clearHuaweiProjectCache,
  isHuaweiRegionId,
  HuaweiCredentialsNotFoundError,
  HUAWEI_CREDENTIALS_FILE_ENV,
  REDACTED,
} from "../../../src/providers/huaweicloud/credentials.js";
import { huaweiCloudProvider } from "../../../src/providers/huaweicloud/index.js";

// Fake, non-functional key material (Huawei AKs are 20 chars, SKs 40 chars).
const FAKE_BASIC_AK = "FAKEBASICAK0123456AB";
const FAKE_BASIC_SK = "FAKEBASICSK0123456789abcdefghijklmnopqrs";
const FAKE_GLOBAL_AK = "FAKEGLOBALAK012345CD";
const FAKE_GLOBAL_SK = "FAKEGLOBALSK123456789abcdefghijklmnopqrs";
const FAKE_ENV_AK = "FAKEENVAK01234567890E";
const FAKE_ENV_SK = "FAKEENVSK0123456789abcdefghijklmnopqrstu";
const FAKE_TOKEN = "FAKESECURITYTOKENxyz";
const ALL_SECRETS = [FAKE_BASIC_AK, FAKE_BASIC_SK, FAKE_GLOBAL_AK, FAKE_GLOBAL_SK, FAKE_ENV_AK, FAKE_ENV_SK, FAKE_TOKEN];

const INI = `
# Huawei Cloud credentials (fake)
[basic]
ak = ${FAKE_BASIC_AK}
sk   =   ${FAKE_BASIC_SK}   ; trailing comment
region = cn-north-4

[Global]
AK: "${FAKE_GLOBAL_AK}"
sk='${FAKE_GLOBAL_SK}'
domain_id = 0123456789abcdef0123456789abcdef

[other]
foo = bar
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

describe("parseHuaweiCredentialsIni", () => {
  it("parses [basic] and [global] with tolerant syntax", () => {
    const parsed = parseHuaweiCredentialsIni(INI);
    expect(parsed.basic?.ak).toHaveLength(20);
    expect(parsed.basic?.sk).toHaveLength(40);
    expect(parsed.global?.ak).toHaveLength(20);
    expect(parsed.global?.sk).toHaveLength(40);
    expect(parsed.basic?.ak).not.toBe(parsed.global?.ak);
    expect(parsed.basic?.ak).toBe(FAKE_BASIC_AK);
    expect(parsed.basic?.sk).toBe(FAKE_BASIC_SK);
    expect(parsed.global?.ak).toBe(FAKE_GLOBAL_AK);
    expect(parsed.global?.sk).toBe(FAKE_GLOBAL_SK);
    expect(parsed.basic?.region).toBe("cn-north-4");
    expect(parsed.global?.domainId).toBe("0123456789abcdef0123456789abcdef");
    expect(Object.keys(parsed.sections).sort()).toEqual(["basic", "global", "other"]);
  });

  it("handles CRLF, BOM, missing sections and garbage lines without throwing", () => {
    const parsed = parseHuaweiCredentialsIni(`﻿[basic]\r\nak=${FAKE_BASIC_AK}\r\nthis is not a kv\r\nsk=${FAKE_BASIC_SK}\r\n`);
    expect(parsed.basic?.ak).toBe(FAKE_BASIC_AK);
    expect(parsed.basic?.sk).toBe(FAKE_BASIC_SK);
    expect(parsed.global).toBeUndefined();
    expect(parseHuaweiCredentialsIni("")).toEqual({ basic: undefined, global: undefined, sections: {} });
    expect(parseHuaweiCredentialsIni("ak=orphan\n").basic).toBeUndefined();
  });

  it("does not treat '#' inside a value as a comment unless preceded by whitespace", () => {
    const parsed = parseHuaweiCredentialsIni(`[basic]\nak=${FAKE_BASIC_AK}\nsk=abc#def\n`);
    expect(parsed.basic?.sk).toBe("abc#def");
  });
});

describe("createHuaweiCredentials", () => {
  it("keeps ak/sk readable but non-enumerable and redacted on serialization", () => {
    const c = createHuaweiCredentials({ ak: FAKE_BASIC_AK, sk: FAKE_BASIC_SK, securityToken: FAKE_TOKEN, projectId: "p1", domainId: "d1" });
    expect(c.ak).toBe(FAKE_BASIC_AK);
    expect(c.sk).toBe(FAKE_BASIC_SK);
    expect(c.securityToken).toBe(FAKE_TOKEN);
    expect(c.projectId).toBe("p1");

    expect(Object.keys(c).sort()).toEqual(["domainId", "projectId"]);
    const spread = { ...c } as Record<string, unknown>;
    expect(spread.ak).toBeUndefined();
    expect(spread.sk).toBeUndefined();

    const json = JSON.stringify(c);
    expect(json).toContain(REDACTED);
    expect(json).toContain('"projectId":"p1"');
    const insp = inspect(c);
    expect(insp).toContain("HuaweiCloudCredentials");
    expect(`${c}`).toBe("[HuaweiCloudCredentials]");
    for (const s of [json, insp, String(c)]) {
      expect(s).not.toContain(FAKE_BASIC_AK);
      expect(s).not.toContain(FAKE_BASIC_SK);
      expect(s).not.toContain(FAKE_TOKEN);
    }
    expect(redactHuaweiCredentials(c)).toEqual({ ak: REDACTED, sk: REDACTED, securityToken: REDACTED, akLength: "20", projectId: "p1", domainId: "d1" });
    expect(Object.isFrozen(c)).toBe(true);
  });

  it("rejects missing ak or sk", () => {
    expect(() => createHuaweiCredentials({ ak: FAKE_BASIC_AK })).toThrow(/ak and sk/);
    expect(() => createHuaweiCredentials({ ak: "  ", sk: FAKE_BASIC_SK })).toThrow(/ak and sk/);
  });
});

describe("loadHuaweiCredentials chain", () => {
  let dir: string;
  let iniPath: string;
  const emptyEnv: NodeJS.ProcessEnv = {};

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "hw-creds-test-"));
    iniPath = join(dir, "credentials");
    writeFileSync(iniPath, INI, { mode: 0o600 });
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("explicit beats env and file", () => {
    const set = loadHuaweiCredentials({
      explicit: { ak: FAKE_BASIC_AK, sk: FAKE_BASIC_SK, domainId: "dExplicit" },
      env: { HUAWEICLOUD_SDK_AK: FAKE_ENV_AK, HUAWEICLOUD_SDK_SK: FAKE_ENV_SK },
      filePath: iniPath,
    });
    expect(set.source).toBe("explicit");
    expect(set.basic.ak).toBe(FAKE_BASIC_AK);
    expect(set.global.ak).toBe(FAKE_BASIC_AK);
    expect(set.global.domainId).toBe("dExplicit");
  });

  it("env beats file and carries project/domain ids", () => {
    const set = loadHuaweiCredentials({
      env: {
        HUAWEICLOUD_SDK_AK: FAKE_ENV_AK,
        HUAWEICLOUD_SDK_SK: FAKE_ENV_SK,
        HUAWEICLOUD_SDK_SECURITY_TOKEN: FAKE_TOKEN,
        HUAWEICLOUD_SDK_PROJECT_ID: "pEnv",
        HUAWEICLOUD_SDK_DOMAIN_ID: "dEnv",
      },
      filePath: iniPath,
    });
    expect(set.source).toBe("env");
    expect(set.basic.ak).toBe(FAKE_ENV_AK);
    expect(set.basic.securityToken).toBe(FAKE_TOKEN);
    expect(set.basic.projectId).toBe("pEnv");
    expect(set.global.domainId).toBe("dEnv");
  });

  it("falls back to the INI file with distinct basic/global sections", () => {
    const set = loadHuaweiCredentials({ env: emptyEnv, filePath: iniPath });
    expect(set.source).toBe("file");
    expect(set.basic.ak).toBe(FAKE_BASIC_AK);
    expect(set.basic.sk).toBe(FAKE_BASIC_SK);
    expect(set.global.ak).toBe(FAKE_GLOBAL_AK);
    expect(set.global.sk).toBe(FAKE_GLOBAL_SK);
    // domainId from [global] propagates to basic for convenience
    expect(set.basic.domainId).toBe("0123456789abcdef0123456789abcdef");
  });

  it("honours HUAWEICLOUD_CREDENTIALS_FILE for the file location", () => {
    const env = { [HUAWEI_CREDENTIALS_FILE_ENV]: iniPath };
    expect(defaultHuaweiCredentialsPath(env)).toBe(iniPath);
    expect(defaultHuaweiCredentialsPath({})).toMatch(/[\\/]\.huaweicloud[\\/]credentials$/);
    const set = loadHuaweiCredentials({ env });
    expect(set.source).toBe("file");
    expect(set.global.ak).toBe(FAKE_GLOBAL_AK);
  });

  it("uses a single section for both scopes when only one is present", () => {
    const p = join(dir, "basic-only");
    writeFileSync(p, `[global]\nak=${FAKE_GLOBAL_AK}\nsk=${FAKE_GLOBAL_SK}\n`);
    const set = loadHuaweiCredentialsFile(p)!;
    expect(set.basic.ak).toBe(FAKE_GLOBAL_AK);
    expect(set.global.ak).toBe(FAKE_GLOBAL_AK);
    expect(loadHuaweiCredentialsFile(join(dir, "does-not-exist"))).toBeUndefined();
    writeFileSync(join(dir, "empty"), "# nothing here\n");
    expect(loadHuaweiCredentialsFile(join(dir, "empty"))).toBeUndefined();
  });

  it("throws a descriptive error (without values) when nothing is configured", () => {
    const missing = join(dir, "missing");
    expect(() => loadHuaweiCredentials({ env: emptyEnv, filePath: missing })).toThrow(HuaweiCredentialsNotFoundError);
    try {
      loadHuaweiCredentials({ env: { HUAWEICLOUD_SDK_AK: FAKE_ENV_AK }, filePath: missing }); // sk missing → env ignored
      expect.unreachable();
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).toContain(missing);
      expect(msg).toContain("HUAWEICLOUD_SDK_AK");
      expect(msg).not.toContain(FAKE_ENV_AK);
    }
  });
});

describe("isHuaweiRegionId", () => {
  it("accepts real Huawei region IDs and rejects non-region project names", () => {
    for (const r of ["cn-north-4", "cn-east-3", "cn-south-1", "cn-south-4b", "ap-southeast-1", "ap-southeast-3", "la-south-2", "la-north-2", "af-south-1", "tr-west-1", "me-east-1", "ru-moscow-1", "sa-brazil-1", "na-mexico-1", "eu-west-101", "cn-southwest-2", "ap-southeast-4", "eu-west-0"]) {
      expect(isHuaweiRegionId(r), r).toBe(true);
    }
    for (const n of ["MOS", "mos", "cn-north-4_sub", "example_domain_project", "", "cn-north", "north-4", "CN-NORTH-4", "cn_north_4", "default", "cn-north-4 "]) {
      expect(isHuaweiRegionId(n), JSON.stringify(n)).toBe(false);
    }
  });
});

describe("resolveProjects / resolveRegionScope", () => {
  const DOMAIN = "0123456789abcdef0123456789abcdef";
  const projects = [
    { id: "p-north4", name: "cn-north-4", domain_id: DOMAIN, enabled: true },
    { id: "p-east3", name: "cn-east-3", domain_id: DOMAIN, enabled: true },
    { id: "p-sub", name: "cn-north-4_sub", domain_id: DOMAIN, enabled: true },
    { id: "p-disabled", name: "ap-southeast-1", domain_id: DOMAIN, enabled: false },
    { id: "MOS", name: "MOS", domain_id: DOMAIN },
    { id: "p-domain", name: "example_domain_project", domain_id: DOMAIN },
    { id: "p-la", name: "la-south-2", domain_id: DOMAIN, enabled: true },
    { id: "p-tr", name: "tr-west-1", domain_id: DOMAIN, enabled: true },
    { id: "p-south4b", name: "cn-south-4b", domain_id: DOMAIN, enabled: true },
  ];
  const fake = { keystoneListProjects: vi.fn(async () => ({ projects })) };
  const creds = createHuaweiCredentials({ ak: FAKE_GLOBAL_AK, sk: FAKE_GLOBAL_SK });

  beforeEach(() => {
    clearHuaweiProjectCache();
    fake.keystoneListProjects.mockClear();
  });

  it("maps region name → projectId/domainId and caches per credential", async () => {
    const map = await resolveProjects(creds, { client: fake });
    expect(map.get("cn-north-4")).toEqual({ projectId: "p-north4", domainId: DOMAIN, region: "cn-north-4" });
    expect(map.get("cn-east-3")?.projectId).toBe("p-east3");
    expect(map.has("ap-southeast-1")).toBe(false); // disabled
    expect(map.has("MOS")).toBe(false); // not a region (bulk migration project)
    expect(map.has("cn-north-4_sub")).toBe(false); // sub-project
    expect(map.has("example_domain_project")).toBe(false); // domain project
    expect(map.get("la-south-2")?.projectId).toBe("p-la");
    expect(map.get("tr-west-1")?.projectId).toBe("p-tr");
    expect(map.get("cn-south-4b")?.projectId).toBe("p-south4b");
    expect(fake.keystoneListProjects).toHaveBeenCalledTimes(1);
    expect(fake.keystoneListProjects.mock.calls[0][0]?.constructor?.name).toBe("KeystoneListProjectsRequest");

    await resolveProjects(creds, { client: fake });
    expect(fake.keystoneListProjects).toHaveBeenCalledTimes(1); // cache hit
    await resolveProjects(creds, { client: fake, force: true });
    expect(fake.keystoneListProjects).toHaveBeenCalledTimes(2);

    const other = createHuaweiCredentials({ ak: FAKE_BASIC_AK, sk: FAKE_BASIC_SK });
    await resolveProjects(other, { client: fake });
    expect(fake.keystoneListProjects).toHaveBeenCalledTimes(3); // separate cache entry
  });

  it("builds a RegionScope, preferring explicit projectId/domainId", async () => {
    const scope = await resolveRegionScope(creds, "cn-north-4", { client: fake });
    expect(scope).toEqual({ region: "cn-north-4", projectId: "p-north4", domainId: DOMAIN });

    const explicit = createHuaweiCredentials({ ak: FAKE_GLOBAL_AK, sk: FAKE_GLOBAL_SK, projectId: "pX", domainId: "dX" });
    await expect(resolveRegionScope(explicit, "cn-north-4", { client: fake })).resolves.toEqual({ region: "cn-north-4", projectId: "pX", domainId: "dX" });
    expect(fake.keystoneListProjects).toHaveBeenCalledTimes(1);
  });

  it("errors clearly for an unknown region (listing known regions, no secrets)", async () => {
    await expect(resolveRegionScope(creds, "eu-west-0", { client: fake })).rejects.toThrow(/eu-west-0.*Known regions: cn-east-3, cn-north-4, cn-south-4b, la-south-2, tr-west-1/);
  });

  it("provider.listRegions and getAccountId use the resolved projects (sub-projects excluded)", async () => {
    await resolveProjects(creds, { client: fake }); // warm cache; provider path never hits the network
    const regions = await huaweiCloudProvider.listRegions(creds, "cn-north-4");
    expect(regions.map((r) => r.region)).toEqual(["cn-north-4", "cn-east-3", "cn-south-4b", "la-south-2", "tr-west-1"]);
    expect(regions[0]).toEqual({ region: "cn-north-4", projectId: "p-north4", domainId: DOMAIN });
    await expect(huaweiCloudProvider.getAccountId({ region: "cn-east-3" }, creds)).resolves.toBe(DOMAIN);
    expect(fake.keystoneListProjects).toHaveBeenCalledTimes(1);
  });
});
