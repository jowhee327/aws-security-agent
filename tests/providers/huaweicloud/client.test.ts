/**
 * Real-SDK tests (no mocks): endpoint table, credential construction and the
 * P0 guarantee that a failing SDK call never writes the signed Authorization
 * header (which embeds the AK) to stdout. Network is limited to a local
 * loopback HTTP server that answers 401 like the Huawei API gateway.
 */
import { describe, it, expect, vi, beforeAll, afterAll, afterEach } from "vitest";
import { createServer, type Server } from "http";
import { createRequire } from "module";
import { inspect } from "util";
import log4js from "log4js";

import {
  hwEndpoint,
  isGlobalService,
  defaultCredentialType,
  buildSdkCredential,
  hwClient,
  hwObsClient,
  loadSdkCore,
  silenceSdkLogging,
} from "../../../src/providers/huaweicloud/client.js";
import { createHuaweiCredentials } from "../../../src/providers/huaweicloud/credentials.js";
import { classifyHwError, describeHwError } from "../../../src/providers/huaweicloud/errors.js";
import { IamClient } from "@huaweicloud/huaweicloud-sdk-iam/v3/IamClient.js";
import { KeystoneListProjectsRequest } from "@huaweicloud/huaweicloud-sdk-iam/v3/model/KeystoneListProjectsRequest.js";

const FAKE_AK = "FAKEAK0123456789ABCD";
const FAKE_SK = "FAKESK0123456789abcdefghijklmnopqrstuvwx";
const creds = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK });

const captured: string[] = [];
let stdoutSpy: ReturnType<typeof vi.spyOn>;
let stderrSpy: ReturnType<typeof vi.spyOn>;
const consoleSpies: Array<ReturnType<typeof vi.spyOn>> = [];

beforeAll(() => {
  stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => { captured.push(String(chunk)); return true; }) as never);
  stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(((chunk: unknown) => { captured.push(String(chunk)); return true; }) as never);
  for (const m of ["log", "error", "warn", "info", "debug"] as const) {
    consoleSpies.push(vi.spyOn(console, m).mockImplementation((...args: unknown[]) => {
      captured.push(args.map((a) => (typeof a === "string" ? a : inspect(a))).join(" "));
    }));
  }
});
afterAll(() => {
  stdoutSpy.mockRestore();
  stderrSpy.mockRestore();
  for (const s of consoleSpies) s.mockRestore();
});
afterEach(() => {
  const all = captured.join("\n");
  expect(all, "stdout/stderr/console must never contain the signed Authorization header").not.toContain("Authorization");
  expect(all).not.toContain(FAKE_AK);
  expect(all).not.toContain(FAKE_SK);
  captured.length = 0;
});

describe("endpoint table (Appendix A)", () => {
  it("builds cn-north-4 endpoints", () => {
    expect(hwEndpoint("ecs", "cn-north-4")).toBe("https://ecs.cn-north-4.myhuaweicloud.com");
    expect(hwEndpoint("evs", "cn-north-4")).toBe("https://evs.cn-north-4.myhuaweicloud.com");
    expect(hwEndpoint("eip", "cn-north-4")).toBe("https://vpc.cn-north-4.myhuaweicloud.com"); // EIP via VPC host
    expect(hwEndpoint("vpc", "cn-north-4")).toBe("https://vpc.cn-north-4.myhuaweicloud.com");
    expect(hwEndpoint("rds", "cn-north-4")).toBe("https://rds.cn-north-4.myhuaweicloud.com");
    expect(hwEndpoint("elb", "cn-north-4")).toBe("https://elb.cn-north-4.myhuaweicloud.com");
    expect(hwEndpoint("scm", "cn-north-4")).toBe("https://scm.cn-north-4.myhuaweicloud.com");
    expect(hwEndpoint("functiongraph", "cn-north-4")).toBe("https://functiongraph.cn-north-4.myhuaweicloud.com");
    expect(hwEndpoint("cts", "cn-north-4")).toBe("https://cts.cn-north-4.myhuaweicloud.com");
    expect(hwEndpoint("obs", "cn-north-4")).toBe("https://obs.cn-north-4.myhuaweicloud.com");
    expect(hwEndpoint("hss", "cn-north-4")).toBe("https://hss.cn-north-4.myhuaweicloud.com");
    expect(hwEndpoint("secmaster", "cn-north-4")).toBe("https://secmaster.cn-north-4.myhuaweicloud.com");
    expect(hwEndpoint("sts", "cn-north-4")).toBe("https://sts.cn-north-4.myhuaweicloud.com"); // STS is regional
  });

  it("global services ignore region", () => {
    expect(hwEndpoint("iam")).toBe("https://iam.myhuaweicloud.com");
    expect(hwEndpoint("iam", "cn-north-4")).toBe("https://iam.myhuaweicloud.com");
    expect(hwEndpoint("rms", "cn-north-4")).toBe("https://rms.myhuaweicloud.com"); // Config service host is rms
    expect(hwEndpoint("organizations")).toBe("https://organizations.myhuaweicloud.com");
    expect(hwEndpoint("eps")).toBe("https://eps.myhuaweicloud.com");
    expect(hwEndpoint("dns")).toBe("https://dns.myhuaweicloud.com");
    for (const s of ["iam", "rms", "organizations", "eps", "dns"] as const) expect(isGlobalService(s)).toBe(true);
    for (const s of ["sts", "ecs", "obs", "eip"] as const) expect(isGlobalService(s)).toBe(false);
  });

  it("regional services require a region", () => {
    expect(() => hwEndpoint("ecs")).toThrow(/regional; region is required/);
  });

  it("chooses credential type per service", () => {
    expect(defaultCredentialType("iam")).toBe("global");
    expect(defaultCredentialType("rms")).toBe("global");
    expect(defaultCredentialType("sts")).toBe("global");
    expect(defaultCredentialType("organizations")).toBe("global");
    expect(defaultCredentialType("ecs")).toBe("basic");
    expect(defaultCredentialType("obs")).toBe("basic");
    expect(defaultCredentialType("dns")).toBe("basic");
  });
});

describe("SDK credential objects", () => {
  it("builds BasicCredentials(projectId) / GlobalCredentials(domainId)", async () => {
    const core = await loadSdkCore();
    const basic = (await buildSdkCredential(creds, { region: "cn-north-4", projectId: "p1" }, "basic")) as InstanceType<typeof core.BasicCredentials>;
    expect(basic).toBeInstanceOf(core.BasicCredentials);
    expect(basic.projectId).toBe("p1");
    expect(basic.getAk()).toBe(FAKE_AK);
    expect(basic.getSk()).toBe(FAKE_SK);

    const global = (await buildSdkCredential(creds, { region: "cn-north-4", domainId: "d1" }, "global")) as InstanceType<typeof core.GlobalCredentials>;
    expect(global).toBeInstanceOf(core.GlobalCredentials);
    expect(global.domainId).toBe("d1");

    const withToken = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK, securityToken: "tok", projectId: "pFromCreds" });
    const b2 = (await buildSdkCredential(withToken, {}, "basic")) as InstanceType<typeof core.BasicCredentials>;
    expect(b2.projectId).toBe("pFromCreds");
    expect(b2.getSecurityToken()).toBe("tok");
  });

  it("the SDK core uses the same log4js instance we silence", async () => {
    await loadSdkCore();
    const req = createRequire(import.meta.url);
    const coreLog4js = createRequire(req.resolve("@huaweicloud/huaweicloud-sdk-core"))("log4js");
    expect(coreLog4js).toBe(log4js);
  });
});

describe("P0: SDK error path never leaks Authorization to stdout", () => {
  let server: Server;
  let endpoint: string;

  beforeAll(async () => {
    server = createServer((req, res) => {
      res.statusCode = 401;
      res.setHeader("content-type", "application/json");
      res.setHeader("x-request-id", "local-test-request");
      res.end(JSON.stringify({ error_code: "APIGW.0301", error_msg: "Incorrect IAM authentication information: verify aksk signature fail" }));
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const addr = server.address();
    endpoint = typeof addr === "object" && addr ? `http://127.0.0.1:${addr.port}` : "";
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  it("a 401 from the API surfaces as access_denied with no secret material anywhere", async () => {
    const iam = await hwClient(IamClient, "iam", creds, { domainId: "d1" }, { endpoint });
    let thrown: unknown;
    try {
      await iam.keystoneListProjects(new KeystoneListProjectsRequest());
    } catch (e) {
      thrown = e;
    }
    await new Promise((r) => setTimeout(r, 20)); // let any async appender flush
    expect(thrown).toBeDefined();
    const info = classifyHwError(thrown);
    expect(info.kind).toBe("access_denied");
    expect(info.status).toBe(401);
    expect(info.code).toBe("APIGW.0301");
    expect(describeHwError(thrown)).toContain("APIGW.0301");
    expect(describeHwError(thrown)).not.toContain(FAKE_AK);
    // afterEach asserts captured output has no "Authorization" / AK / SK
  });

  it("stays silent even if another SDK module revives log4js", async () => {
    // Simulate esdk-obs-nodejs (or anything else) re-enabling debug logging on stdout.
    log4js.configure({ appenders: { out: { type: "stdout" } }, categories: { default: { appenders: ["out"], level: "debug" } } });
    log4js.getLogger().error("probe-before", { Authorization: "revived" });
    expect(captured.join("")).toContain("Authorization");
    captured.length = 0;

    // Building any client re-applies the kill switch...
    const obs = await hwObsClient(creds, "cn-north-4", { server: "127.0.0.1:1" });
    expect(obs).toBeDefined();
    const iam = await hwClient(IamClient, "iam", creds, { domainId: "d1" }, { endpoint });
    expect(iam).toBeDefined();
    // ...so the SDK's own logger no longer reaches stdout.
    log4js.getLogger().error("Some error found:", { config: { headers: { Authorization: "SDK-HMAC-SHA256 Access=" + FAKE_AK } } });
    const { getLogger } = createRequire(createRequire(import.meta.url).resolve("@huaweicloud/huaweicloud-sdk-core"))("./logger");
    getLogger("DefaultHttpClient", "error").error("Some error found:", { config: { headers: { Authorization: "SDK-HMAC-SHA256 Access=" + FAKE_AK } } });
    await new Promise((r) => setTimeout(r, 20));
    expect(captured.join("")).toBe("");
    silenceSdkLogging();
  });
});
