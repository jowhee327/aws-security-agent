/**
 * HuaweiSecretExposureScanner (Huawei Cloud secret_exposure) — SDK client
 * factory + SDK packages are mocked; no network, no credential file access.
 */
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll, afterEach } from "vitest";
import { inspect } from "util";

const { listFunctions, showFunctionConfig, listServersDetails, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock } = vi.hoisted(() => ({
  listFunctions: vi.fn(),
  showFunctionConfig: vi.fn(),
  listServersDetails: vi.fn(),
  hwClientMock: vi.fn(),
  loadHuaweiCredentialsMock: vi.fn(),
  resolveRegionScopeMock: vi.fn(),
}));

vi.mock("../../../../src/providers/huaweicloud/client.js", () => ({
  hwClient: hwClientMock,
  hwObsClient: vi.fn(),
  silenceSdkLogging: vi.fn(),
}));
// SDK packages must never be loaded in unit tests (heavy + configure log4js).
vi.mock("@huaweicloud/huaweicloud-sdk-functiongraph", () => ({
  FunctionGraphClient: { newBuilder: vi.fn(() => { throw new Error("real SDK builder must not be used in tests"); }) },
}));
vi.mock("@huaweicloud/huaweicloud-sdk-ecs", () => ({
  EcsClient: { newBuilder: vi.fn(() => { throw new Error("real SDK builder must not be used in tests"); }) },
}));
vi.mock("../../../../src/providers/huaweicloud/credentials.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../../src/providers/huaweicloud/credentials.js")>();
  return { ...actual, loadHuaweiCredentials: loadHuaweiCredentialsMock, resolveRegionScope: resolveRegionScopeMock };
});

import {
  HuaweiSecretExposureScanner,
  HUAWEI_SECRET_PATTERNS,
  HUAWEI_EXTRA_SECRET_PATTERNS,
  parseFunctionUserData,
  decodeEcsUserData,
  matchValuePatterns,
  FG_PAGE_SIZE,
  ECS_PAGE_SIZE,
} from "../../../../src/providers/huaweicloud/scanners/secret-exposure.js";
import { SECRET_PATTERNS } from "../../../../src/scanners/secret-exposure.js";
import { createHuaweiCredentials } from "../../../../src/providers/huaweicloud/credentials.js";
import { huaweiCloudProvider } from "../../../../src/providers/huaweicloud/index.js";
import type { ScanContext } from "../../../../src/types.js";

const FAKE_AK = "FAKEAK0123456789ABCD";
const FAKE_SK = "FAKESK0123456789abcdefghijklmnopqrstuvwx";
const DOMAIN = "0123456789abcdef0123456789abcdef";
const PROJECT = "p-north4";
const FAKE_AUTH_HEADER = `SDK-HMAC-SHA256 Access=${FAKE_AK}, SignedHeaders=host;x-sdk-date, Signature=deadbeef`;

// Fake secret material that must never appear in scanner output.
const LEAKED_AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const LEAKED_HW_AK = "HWAKEXAMPLE0123456AB";
const LEAKED_PASSWORD = "Sup3rS3cretPassw0rd!";
const LEAKED_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEfakefakefake\n-----END RSA PRIVATE KEY-----";
const ALL_LEAKED = [LEAKED_AWS_KEY, LEAKED_HW_AK, LEAKED_PASSWORD, "MIIEfakefakefake"];

const creds = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK, domainId: DOMAIN });

const ctx: ScanContext = {
  region: "cn-north-4",
  partition: "huaweicloud",
  accountId: DOMAIN,
  provider: "huaweicloud",
  projectId: PROJECT,
  domainId: DOMAIN,
  credentials: creds,
};

const FN_URN = (name: string) => `urn:fss:cn-north-4:${PROJECT}:function:default:${name}:latest`;
const b64 = (s: string) => Buffer.from(s, "utf-8").toString("base64");

const captured: string[] = [];
const spies: Array<ReturnType<typeof vi.spyOn>> = [];
beforeAll(() => {
  spies.push(vi.spyOn(process.stdout, "write").mockImplementation(((c: unknown) => { captured.push(String(c)); return true; }) as never));
  spies.push(vi.spyOn(process.stderr, "write").mockImplementation(((c: unknown) => { captured.push(String(c)); return true; }) as never));
  for (const m of ["log", "error", "warn", "info", "debug"] as const) {
    spies.push(vi.spyOn(console, m).mockImplementation((...args: unknown[]) => { captured.push(args.map((a) => (typeof a === "string" ? a : inspect(a))).join(" ")); }));
  }
});
afterAll(() => { for (const s of spies) s.mockRestore(); });
afterEach(() => {
  const all = captured.join("\n");
  expect(all, "no output may contain the Authorization header or key material").not.toContain("Authorization");
  expect(all).not.toContain(FAKE_AK);
  expect(all).not.toContain(FAKE_SK);
  for (const leaked of ALL_LEAKED) expect(all).not.toContain(leaked);
  captured.length = 0;
});

/** hwClient fake: dispatch on the service name. */
function installClients() {
  hwClientMock.mockImplementation(async (_cls: unknown, svc: string) => {
    if (svc === "functiongraph") return { listFunctions, showFunctionConfig };
    if (svc === "ecs") return { listServersDetails };
    throw new Error(`unexpected service ${svc}`);
  });
}

describe("HuaweiSecretExposureScanner (secret_exposure)", () => {
  const scanner = new HuaweiSecretExposureScanner();

  beforeEach(() => {
    listFunctions.mockReset();
    showFunctionConfig.mockReset();
    listServersDetails.mockReset();
    hwClientMock.mockReset();
    loadHuaweiCredentialsMock.mockReset();
    resolveRegionScopeMock.mockReset();
    installClients();
    // defaults: nothing deployed
    listFunctions.mockResolvedValue({ functions: [], next_marker: 0, count: 0 });
    listServersDetails.mockResolvedValue({ servers: [], count: 0 });
  });

  it("is registered on the huaweicloud provider under the AWS module name and reuses AWS SECRET_PATTERNS", () => {
    expect(scanner.moduleName).toBe("secret_exposure");
    expect(huaweiCloudProvider.scanners().map((s) => s.moduleName)).toContain("secret_exposure");
    for (const sp of SECRET_PATTERNS) expect(HUAWEI_SECRET_PATTERNS).toContain(sp);
    expect(HUAWEI_SECRET_PATTERNS).toHaveLength(SECRET_PATTERNS.length + HUAWEI_EXTRA_SECRET_PATTERNS.length);
    // AWS patterns are untouched (no Huawei detector leaked into the AWS list).
    expect(SECRET_PATTERNS.map((p) => p.name)).toEqual(["AWS Access Key", "Private Key", "Password in env var"]);
  });

  it("flags FunctionGraph env vars: AWS key (CRITICAL 9.5), private key (9.0), suspicious names (HIGH 7.5)", async () => {
    listFunctions.mockResolvedValueOnce({
      functions: [
        { func_urn: FN_URN("leaky"), func_name: "leaky", user_data: "{}" },
        { func_urn: FN_URN("clean"), func_name: "clean", user_data: "{}", encrypted_user_data: "{\"DB_PASSWORD\":\"***\"}" },
      ],
      next_marker: 2,
      count: 2,
    });
    showFunctionConfig.mockImplementation(async (req: { function_urn: string }) => {
      if (req.function_urn === FN_URN("leaky")) {
        return {
          func_urn: FN_URN("leaky"),
          func_name: "leaky",
          user_data: JSON.stringify({
            AWS_KEY: LEAKED_AWS_KEY,
            PASSWORD: LEAKED_PASSWORD,
            PEM: LEAKED_PRIVATE_KEY,
            HUAWEICLOUD_SDK_AK: LEAKED_HW_AK, // name match only: a bare 20-char value is not matched without assignment context
            REGION: "cn-north-4",
          }),
        };
      }
      return { func_urn: req.function_urn, func_name: "clean", user_data: JSON.stringify({ LOG_LEVEL: "info" }), encrypted_user_data: "{\"DB_PASSWORD\":\"***\"}" };
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.warnings).toBeUndefined();
    expect(result.resourcesScanned).toBe(2);
    expect(showFunctionConfig).toHaveBeenCalledTimes(2);
    expect(showFunctionConfig).toHaveBeenCalledWith({ function_urn: FN_URN("leaky") });

    const titles = result.findings.map((f) => f.title).sort();
    expect(titles).toEqual([
      'FunctionGraph leaky has suspicious env var "HUAWEICLOUD_SDK_AK"',
      'FunctionGraph leaky has suspicious env var "PASSWORD"',
      "FunctionGraph leaky env var contains AWS Access Key",
      "FunctionGraph leaky env var contains Private Key",
    ].sort());
    const aws = result.findings.find((f) => f.title.includes("AWS Access Key"))!;
    expect(aws).toMatchObject({ severity: "CRITICAL", riskScore: 9.5, priority: "P0", resourceType: "HuaweiCloud::FunctionGraph::Function", region: "cn-north-4", provider: "huaweicloud" });
    expect(aws.resourceArn).toBe(`hws:cn-north-4:${DOMAIN}:functiongraph:function:${FN_URN("leaky")}`);
    expect(result.findings.find((f) => f.title.includes("Private Key"))).toMatchObject({ severity: "CRITICAL", riskScore: 9.0 });
    expect(result.findings.find((f) => f.title.includes('"PASSWORD"'))).toMatchObject({ severity: "HIGH", riskScore: 7.5, priority: "P1" });
    // every finding belongs to the leaky function; the clean one (encrypted_user_data only) produced nothing
    expect(result.findings.every((f) => f.resourceId === "leaky")).toBe(true);

    // Secret values never appear anywhere in the result.
    const serialized = JSON.stringify(result);
    for (const leaked of ALL_LEAKED) expect(serialized).not.toContain(leaked);
    expect(serialized).not.toContain("***"); // encrypted_user_data is never inspected/echoed

    // Regional clients are built with the context scope (projectId for BasicCredentials).
    expect(hwClientMock).toHaveBeenCalledTimes(2);
    expect(hwClientMock.mock.calls.map((c) => c[1]).sort()).toEqual(["ecs", "functiongraph"]);
    expect(hwClientMock.mock.calls[0][2]).toBe(creds);
    expect(hwClientMock.mock.calls[0][3]).toEqual({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });
    expect(loadHuaweiCredentialsMock).not.toHaveBeenCalled();
  });

  it("flags ECS user data (base64): AWS key 9.5, Huawei AK in assignment context 9.5, private key 8.0; invalid base64 tolerated", async () => {
    listServersDetails.mockResolvedValueOnce({
      count: 5,
      servers: [
        { id: "srv-aws", name: "web-1", "OS-EXT-SRV-ATTR:user_data": b64(`#!/bin/bash\nexport AWS_ACCESS_KEY_ID=${LEAKED_AWS_KEY}\n`) },
        { id: "srv-hw", name: "web-2", "OS-EXT-SRV-ATTR:user_data": b64(`#cloud-config\nruncmd:\n  - export HUAWEICLOUD_SDK_AK=${LEAKED_HW_AK}\n  - export HUAWEICLOUD_SDK_SK=${FAKE_SK}\n`) },
        { id: "srv-pem", "OS-EXT-SRV-ATTR:user_data": b64(`cat > /root/.ssh/id_rsa <<EOF\n${LEAKED_PRIVATE_KEY}\nEOF\n`) },
        { id: "srv-bad", "OS-EXT-SRV-ATTR:user_data": "%%%not-base64-at-all " },
        { id: "srv-none" },
      ],
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.warnings).toBeUndefined();
    expect(result.resourcesScanned).toBe(5);
    const byId = Object.fromEntries(result.findings.map((f) => [f.resourceId, f]));
    expect(Object.keys(byId).sort()).toEqual(["srv-aws", "srv-hw", "srv-pem"]);
    expect(byId["srv-aws"]).toMatchObject({ title: "ECS srv-aws user data contains AWS Access Key", severity: "CRITICAL", riskScore: 9.5, resourceType: "HuaweiCloud::ECS::CloudServer" });
    expect(byId["srv-aws"].resourceArn).toBe(`hws:cn-north-4:${DOMAIN}:ecs:server:srv-aws`);
    expect(byId["srv-hw"]).toMatchObject({ title: "ECS srv-hw user data contains Huawei Cloud Access Key", severity: "CRITICAL", riskScore: 9.5 });
    expect(byId["srv-pem"]).toMatchObject({ title: "ECS srv-pem user data contains Private Key", severity: "HIGH", riskScore: 8.0 });

    const serialized = JSON.stringify(result);
    for (const leaked of ALL_LEAKED) expect(serialized).not.toContain(leaked);
    expect(serialized).not.toContain(FAKE_SK);
  });

  it("consumes FunctionGraph marker pagination and ECS offset pagination", async () => {
    const page1 = Array.from({ length: FG_PAGE_SIZE }, (_, i) => ({ func_urn: FN_URN(`f${i}`), func_name: `f${i}` }));
    const page2 = [{ func_urn: FN_URN("last"), func_name: "last" }];
    listFunctions
      .mockResolvedValueOnce({ functions: page1, next_marker: FG_PAGE_SIZE, count: FG_PAGE_SIZE + 1 })
      .mockResolvedValueOnce({ functions: page2, next_marker: FG_PAGE_SIZE + 1, count: FG_PAGE_SIZE + 1 });
    showFunctionConfig.mockImplementation(async (req: { function_urn: string }) => ({
      func_urn: req.function_urn,
      user_data: req.function_urn === FN_URN("last") ? JSON.stringify({ API_KEY: "x" }) : "{}",
    }));

    const ecsPage1 = Array.from({ length: ECS_PAGE_SIZE }, (_, i) => ({ id: `s${i}` }));
    const ecsPage2 = [{ id: "s-last", "OS-EXT-SRV-ATTR:user_data": b64(`token=${LEAKED_AWS_KEY}`) }];
    listServersDetails
      .mockResolvedValueOnce({ servers: ecsPage1, count: ECS_PAGE_SIZE + 1 })
      .mockResolvedValueOnce({ servers: ecsPage2, count: ECS_PAGE_SIZE + 1 });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(listFunctions).toHaveBeenCalledTimes(2);
    expect(listFunctions.mock.calls[0][0]).toEqual({ maxitems: String(FG_PAGE_SIZE) });
    expect(listFunctions.mock.calls[1][0]).toEqual({ maxitems: String(FG_PAGE_SIZE), marker: String(FG_PAGE_SIZE) });
    expect(showFunctionConfig).toHaveBeenCalledTimes(FG_PAGE_SIZE + 1);
    expect(listServersDetails).toHaveBeenCalledTimes(2);
    expect(listServersDetails.mock.calls[0][0]).toEqual({ offset: 1, limit: ECS_PAGE_SIZE });
    expect(listServersDetails.mock.calls[1][0]).toEqual({ offset: 2, limit: ECS_PAGE_SIZE });
    expect(result.resourcesScanned).toBe(FG_PAGE_SIZE + 1 + ECS_PAGE_SIZE + 1);
    expect(result.findings.map((f) => f.resourceId).sort()).toEqual(["last", "s-last"]);
  });

  it("falls back to list data with a warning when showFunctionConfig fails for one function", async () => {
    listFunctions.mockResolvedValueOnce({
      functions: [{ func_urn: FN_URN("a"), func_name: "a", user_data: JSON.stringify({ TOKEN: "t" }) }],
      next_marker: 1,
      count: 1,
    });
    showFunctionConfig.mockRejectedValueOnce({ httpStatusCode: 404, errorCode: "FSS.1051", errorMsg: "function not found" });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].title).toBe('FunctionGraph a has suspicious env var "TOKEN"');
    expect(result.warnings).toEqual(["FunctionGraph: showFunctionConfig failed for a (HTTP 404 | FSS.1051 | function not found); used list data."]);
  });

  it("degrades per service on 403: FunctionGraph denied, ECS still scanned", async () => {
    listFunctions.mockRejectedValueOnce({ httpStatusCode: 403, errorCode: "FSS.0403", errorMsg: "Forbidden", requestId: "r-fg" });
    listServersDetails.mockResolvedValueOnce({ count: 1, servers: [{ id: "srv-1", "OS-EXT-SRV-ATTR:user_data": b64(`AKID=${LEAKED_AWS_KEY}`) }] });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(1);
    expect(result.findings[0].resourceId).toBe("srv-1");
    expect(result.warnings).toEqual(["FunctionGraph: insufficient permissions (HTTP 403 | FSS.0403 | Forbidden | requestId=r-fg); skipped"]);
  });

  it("both services denied / not enabled → status success with two warnings and 0 findings", async () => {
    listFunctions.mockRejectedValueOnce({
      status: 401,
      data: { error_code: "APIGW.0301", error_msg: "Incorrect IAM authentication information" },
      message: "Request failed with status code 401",
      config: { headers: { Authorization: FAKE_AUTH_HEADER } },
    });
    listServersDetails.mockRejectedValueOnce({ httpStatusCode: 404, errorCode: "APIGW.0101", errorMsg: "The API does not exist or has not been published in the environment" });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.resourcesScanned).toBe(0);
    expect(result.warnings).toHaveLength(2);
    expect(result.warnings![0]).toMatch(/^FunctionGraph: insufficient permissions \(HTTP 401 \| APIGW\.0301/);
    expect(result.warnings![1]).toMatch(/^ECS: service not enabled or not available/);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("Authorization");
    expect(serialized).not.toContain(FAKE_AK);
  });

  it("unexpected (non-403) service errors become warnings, not a failed scan", async () => {
    listFunctions.mockRejectedValueOnce(new Error("connect ETIMEDOUT 1.2.3.4:443"));
    listServersDetails.mockRejectedValueOnce({ httpStatusCode: 500, errorCode: "Ecs.0005", errorMsg: "internal error" });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.warnings).toEqual([
      "FunctionGraph scan error: connect ETIMEDOUT 1.2.3.4:443",
      "ECS user data scan error: HTTP 500 | Ecs.0005 | internal error",
    ]);
  });

  it("resolves projectId via IAM when the context lacks it, and errors without credentials", async () => {
    const noProject = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK });
    resolveRegionScopeMock.mockResolvedValueOnce({ region: "cn-east-3", projectId: "p-east3", domainId: DOMAIN });

    const result = await scanner.scan({ region: "cn-east-3", partition: "huaweicloud", accountId: "", credentials: noProject });

    expect(result.status).toBe("success");
    expect(resolveRegionScopeMock).toHaveBeenCalledWith(noProject, "cn-east-3");
    expect(hwClientMock.mock.calls[0][3]).toEqual({ region: "cn-east-3", projectId: "p-east3", domainId: DOMAIN });

    loadHuaweiCredentialsMock.mockImplementationOnce(() => { throw new Error("Huawei Cloud credentials not found. Provide ak/sk explicitly"); });
    const none = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: DOMAIN, provider: "huaweicloud" });
    expect(none.status).toBe("error");
    expect(none.error).toContain("Huawei Cloud credentials not found");
  });
});

describe("secret_exposure helpers", () => {
  it("parseFunctionUserData handles JSON env maps, non-JSON strings and empties", () => {
    expect(parseFunctionUserData(undefined)).toEqual([]);
    expect(parseFunctionUserData("")).toEqual([]);
    expect(parseFunctionUserData("{}")).toEqual([]);
    expect(parseFunctionUserData(JSON.stringify({ A: "1", B: 2, C: null }))).toEqual([["A", "1"], ["B", "2"], ["C", '""']]);
    expect(parseFunctionUserData("plain text")).toEqual([[undefined, "plain text"]]);
    expect(parseFunctionUserData("[1,2]")).toEqual([[undefined, "[1,2]"]]);
  });

  it("decodeEcsUserData decodes base64, never throws, and falls back to raw text", () => {
    expect(decodeEcsUserData(undefined)).toBeUndefined();
    expect(decodeEcsUserData("")).toBeUndefined();
    expect(decodeEcsUserData(b64("hello"))).toBe("hello");
    expect(decodeEcsUserData(" \n" + b64("hello") + "\n")).toBe("hello");
    expect(decodeEcsUserData("%%%not-base64 ")).toBe("%%%not-base64");
    expect(decodeEcsUserData("#!/bin/bash echo plain")).toBe("#!/bin/bash echo plain");
    expect(decodeEcsUserData(12345 as unknown as string)).toBeUndefined();
  });

  it("Huawei AK detector requires an assignment context and rejects generic 20-char tokens", () => {
    const names = (t: string) => matchValuePatterns(t).map((p) => p.name);
    expect(names(`export HUAWEICLOUD_SDK_AK=${LEAKED_HW_AK}`)).toEqual(["Huawei Cloud Access Key"]);
    expect(names(`ak: "${LEAKED_HW_AK}"`)).toEqual(["Huawei Cloud Access Key"]);
    expect(names(`access_key_id = ${LEAKED_HW_AK}`)).toEqual(["Huawei Cloud Access Key"]);
    expect(names(`ACCESS_KEY=${LEAKED_HW_AK}\n`)).toEqual(["Huawei Cloud Access Key"]);
    // no context → no match (avoid false positives on random constants)
    expect(names(`BUILD_ID=${LEAKED_HW_AK}`)).toEqual([]);
    expect(names(LEAKED_HW_AK)).toEqual([]);
    // wrong length / lowercase → no match
    expect(names("ak=ABCDEFGHIJ0123456789X")).toEqual([]);
    expect(names("ak=abcdefghij0123456789")).toEqual([]);
    expect(names("ak=ABCDEFGHIJ012345678")).toEqual([]);
    // AWS + private key still detected through the shared list
    expect(names(`x=${LEAKED_AWS_KEY}`)).toEqual(["AWS Access Key"]);
    expect(names(LEAKED_PRIVATE_KEY)).toEqual(["Private Key"]);
  });
});
