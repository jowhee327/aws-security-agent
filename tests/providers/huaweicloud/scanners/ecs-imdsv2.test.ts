/**
 * HuaweiEcsImdsv2Scanner (Huawei Cloud imdsv2_enforcement → ECS metadata options) —
 * SDK client factory + SDK package are mocked; no network, no credential file access.
 * Covers: enforced / not enforced / endpoint disabled / empty, 403 / 404 / 500 on the
 * listing, per-server 403/404/500 aggregation, pagination, N+1 cap + concurrency, no-leak assertion.
 */
import { describe, it, expect, vi, beforeEach, beforeAll, afterAll, afterEach } from "vitest";
import { inspect } from "util";

const { listServersDetails, showMetadataOptions, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock } = vi.hoisted(() => ({
  listServersDetails: vi.fn(),
  showMetadataOptions: vi.fn(),
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
const boom = () => { throw new Error("real SDK builder must not be used in tests"); };
vi.mock("@huaweicloud/huaweicloud-sdk-ecs", () => ({ EcsClient: { newBuilder: vi.fn(boom) } }));
vi.mock("../../../../src/providers/huaweicloud/credentials.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../../src/providers/huaweicloud/credentials.js")>();
  return { ...actual, loadHuaweiCredentials: loadHuaweiCredentialsMock, resolveRegionScope: resolveRegionScopeMock };
});

import {
  HuaweiEcsImdsv2Scanner,
  evaluateMetadataOptions,
  IMDS_PAGE_SIZE,
  IMDS_MAX_SERVERS,
  IMDS_CONCURRENCY,
  IMDS_SERVER_STATUS,
} from "../../../../src/providers/huaweicloud/scanners/ecs-imdsv2.js";
import { createHuaweiCredentials } from "../../../../src/providers/huaweicloud/credentials.js";
import { huaweiCloudProvider } from "../../../../src/providers/huaweicloud/index.js";
import type { ScanContext } from "../../../../src/types.js";

const FAKE_AK = "FAKEAK0123456789ABCD";
const FAKE_SK = "FAKESK0123456789abcdefghijklmnopqrstuvwx";
const DOMAIN = "0123456789abcdef0123456789abcdef";
const PROJECT = "p-north4";
const FAKE_AUTH_HEADER = `SDK-HMAC-SHA256 Access=${FAKE_AK}, SignedHeaders=host;x-sdk-date, Signature=deadbeef`;

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

const urn = (svc: string, type: string, id: string) => `hws:cn-north-4:${DOMAIN}:${svc}:${type}:${id}`;

const ERR_403 = { httpStatusCode: 403, errorCode: "Ecs.0003", errorMsg: "Forbidden", requestId: "req-403" };
const ERR_404 = { httpStatusCode: 404, errorCode: "Ecs.0114", errorMsg: "The server does not exist.", requestId: "req-404" };
const ERR_500 = { httpStatusCode: 500, errorCode: "Ecs.9999", errorMsg: "internal error", requestId: "req-500" };
const ERR_401_RAW = {
  status: 401,
  data: { error_code: "APIGW.0301", error_msg: "Incorrect IAM authentication information: verify aksk signature fail" },
  message: "Request failed with status code 401",
  config: { url: "https://ecs.cn-north-4.myhuaweicloud.com/v1/p/cloudservers/s/metadata-options", headers: { Authorization: FAKE_AUTH_HEADER } },
};

const server = (id: string, over: Record<string, unknown> = {}) => ({ id, name: `srv-${id}`, status: "ACTIVE", flavor: { id: "s6.large.2" }, ...over });

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
  captured.length = 0;
});

function installClients() {
  hwClientMock.mockImplementation(async (_cls: unknown, svc: string) => {
    if (svc === "ecs") return { listServersDetails, showMetadataOptions };
    throw new Error(`unexpected service ${svc}`);
  });
}

describe("HuaweiEcsImdsv2Scanner (imdsv2_enforcement)", () => {
  const scanner = new HuaweiEcsImdsv2Scanner();

  beforeEach(() => {
    for (const m of [listServersDetails, showMetadataOptions, hwClientMock, loadHuaweiCredentialsMock, resolveRegionScopeMock]) m.mockReset();
    installClients();
    listServersDetails.mockResolvedValue({ servers: [], count: 0 });
    showMetadataOptions.mockResolvedValue({ http_endpoint: "enabled", http_tokens: "required" });
  });

  it("is registered on the huaweicloud provider under the AWS module name", () => {
    expect(scanner.moduleName).toBe("imdsv2_enforcement");
    expect(huaweiCloudProvider.scanners().map((s) => s.moduleName)).toContain("imdsv2_enforcement");
  });

  it("flags http_tokens != required (7.5 HIGH, AWS parity); required and endpoint-disabled servers pass; missing http_tokens counts as not enforced", async () => {
    listServersDetails.mockResolvedValueOnce({
      count: 4,
      servers: [server("s-opt"), server("s-req"), server("s-off"), server("s-missing", { name: undefined, flavor: undefined, status: undefined })],
    });
    showMetadataOptions.mockImplementation(async (req: { server_id: string }) => {
      switch (req.server_id) {
        case "s-opt": return { http_endpoint: "enabled", http_tokens: "optional" };
        case "s-req": return { http_endpoint: "enabled", http_tokens: "required" };
        case "s-off": return { http_endpoint: "disabled", http_tokens: "optional" };
        case "s-missing": return { httpStatusCode: 200 };
        default: throw new Error(`unexpected server ${req.server_id}`);
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.error).toBeUndefined();
    expect(result.resourcesScanned).toBe(4);
    expect(result.findingsCount).toBe(2);
    expect(result.warnings).toBeUndefined();
    // Running servers only (AWS parity), page 1.
    expect(listServersDetails).toHaveBeenCalledTimes(1);
    expect(listServersDetails.mock.calls[0][0]).toEqual({ status: IMDS_SERVER_STATUS, offset: 1, limit: IMDS_PAGE_SIZE });
    expect(IMDS_SERVER_STATUS).toBe("ACTIVE");
    expect(showMetadataOptions).toHaveBeenCalledTimes(4);
    expect(showMetadataOptions.mock.calls.map((c) => c[0])).toEqual([{ server_id: "s-opt" }, { server_id: "s-req" }, { server_id: "s-off" }, { server_id: "s-missing" }]);

    const opt = result.findings.find((f) => f.resourceId === "s-opt")!;
    expect(opt).toMatchObject({
      riskScore: 7.5,
      severity: "HIGH",
      priority: "P1",
      resourceType: "HuaweiCloud::ECS::CloudServer",
      resourceArn: urn("ecs", "server", "s-opt"),
      region: "cn-north-4",
      accountId: DOMAIN,
      module: "imdsv2_enforcement",
      provider: "huaweicloud",
    });
    expect(opt.title).toBe("ECS server s-opt does not enforce metadata service tokens (IMDSv2)");
    expect(opt.description).toContain('ECS server s-opt (srv-s-opt) (flavor: s6.large.2, state: ACTIVE) has http_tokens set to "optional" (http_endpoint: enabled).');
    expect(opt.remediationSteps.join("\n")).toContain('http_tokens to "required"');
    const missing = result.findings.find((f) => f.resourceId === "s-missing")!;
    expect(missing.description).toContain('has http_tokens set to "unknown"');
    expect(missing.description).toContain("(flavor: unknown, state: unknown)");
    expect(result.findings.some((f) => f.resourceId === "s-req")).toBe(false);
    expect(result.findings.some((f) => f.resourceId === "s-off")).toBe(false);

    // Regional (basic) client built with the region scope; credential chain not consulted.
    expect(hwClientMock).toHaveBeenCalledTimes(1);
    expect(hwClientMock.mock.calls[0].slice(1)).toEqual(["ecs", creds, { region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN }]);
    expect(loadHuaweiCredentialsMock).not.toHaveBeenCalled();
  });

  it("no running servers → 0 findings, no warnings, no per-server calls", async () => {
    const result = await scanner.scan(ctx);
    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(0);
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toBeUndefined();
    expect(showMetadataOptions).not.toHaveBeenCalled();
  });

  it("paginates servers (offset = page number, count) and evaluates every server", async () => {
    const page1 = Array.from({ length: IMDS_PAGE_SIZE }, (_, i) => server(`s-${i}`));
    const page2 = [server("s-last")];
    listServersDetails
      .mockResolvedValueOnce({ servers: page1, count: IMDS_PAGE_SIZE + 1 })
      .mockResolvedValueOnce({ servers: page2, count: IMDS_PAGE_SIZE + 1 });
    showMetadataOptions.mockImplementation(async (req: { server_id: string }) =>
      req.server_id === "s-last" ? { http_endpoint: "enabled", http_tokens: "optional" } : { http_endpoint: "enabled", http_tokens: "required" },
    );

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(listServersDetails).toHaveBeenCalledTimes(2);
    expect(listServersDetails.mock.calls.map((c) => c[0])).toEqual([
      { status: IMDS_SERVER_STATUS, offset: 1, limit: IMDS_PAGE_SIZE },
      { status: IMDS_SERVER_STATUS, offset: 2, limit: IMDS_PAGE_SIZE },
    ]);
    expect(showMetadataOptions).toHaveBeenCalledTimes(IMDS_PAGE_SIZE + 1);
    expect(result.resourcesScanned).toBe(IMDS_PAGE_SIZE + 1);
    expect(result.findings.map((f) => f.resourceId)).toEqual(["s-last"]);
    expect(result.warnings).toBeUndefined();
  });

  it("caps the N+1 at 500 servers with a truncation warning and never exceeds the concurrency limit", async () => {
    const full = Array.from({ length: IMDS_PAGE_SIZE }, (_, i) => server(`s-${i}`));
    listServersDetails.mockResolvedValue({ servers: full, count: 5000 });
    let inFlight = 0;
    let maxInFlight = 0;
    showMetadataOptions.mockImplementation(async () => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 1));
      inFlight--;
      return { http_endpoint: "enabled", http_tokens: "required" };
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(listServersDetails).toHaveBeenCalledTimes(IMDS_MAX_SERVERS / IMDS_PAGE_SIZE);
    expect(showMetadataOptions).toHaveBeenCalledTimes(IMDS_MAX_SERVERS);
    expect(maxInFlight).toBeLessThanOrEqual(IMDS_CONCURRENCY);
    expect(maxInFlight).toBeGreaterThan(1);
    expect(result.resourcesScanned).toBe(IMDS_MAX_SERVERS);
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toEqual([`ECS: more than ${IMDS_MAX_SERVERS} running servers; only the first ${IMDS_MAX_SERVERS} were checked.`]);
  });

  it("per-server 403 / 404 / raw 401 are aggregated into one warning, 500s into another; the scan continues and nothing leaks", async () => {
    listServersDetails.mockResolvedValueOnce({
      count: 6,
      servers: [server("s-403"), server("s-404"), server("s-401"), server("s-500"), server("s-ok"), { name: "no-id" }],
    });
    showMetadataOptions.mockImplementation(async (req: { server_id: string }) => {
      switch (req.server_id) {
        case "s-403": throw ERR_403;
        case "s-404": throw ERR_404;
        case "s-401": throw ERR_401_RAW;
        case "s-500": throw ERR_500;
        default: return { http_endpoint: "enabled", http_tokens: "optional" };
      }
    });

    const result = await scanner.scan(ctx);

    expect(result.status).toBe("success");
    expect(result.resourcesScanned).toBe(6);
    expect(showMetadataOptions).toHaveBeenCalledTimes(5); // the id-less server is not looked up
    expect(result.findings.map((f) => f.resourceId)).toEqual(["s-ok"]);
    expect(result.warnings).toEqual([
      "ECS: metadata options unavailable for 3 server(s) (insufficient permissions or not found — HTTP 403 | Ecs.0003 | Forbidden | requestId=req-403); those servers were not evaluated.",
      "ECS: metadata options lookup failed for 2 server(s) (HTTP 500 | Ecs.9999 | internal error | requestId=req-500); those servers were not evaluated.",
    ]);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("Authorization");
    expect(serialized).not.toContain(FAKE_AK);
  });

  it("first per-server failure being the raw 401 → the aggregated warning is redacted", async () => {
    listServersDetails.mockResolvedValueOnce({ count: 1, servers: [server("s-401")] });
    showMetadataOptions.mockRejectedValueOnce(ERR_401_RAW);
    const result = await scanner.scan(ctx);
    expect(result.status).toBe("success");
    expect(result.findingsCount).toBe(0);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings![0]).toContain("metadata options unavailable for 1 server(s)");
    expect(result.warnings![0]).toContain("APIGW.0301");
    expect(JSON.stringify(result)).not.toContain("Authorization");
    expect(JSON.stringify(result)).not.toContain(FAKE_AK);
    expect(JSON.stringify(result)).not.toContain("Signature=deadbeef");
  });

  it("403 / 404 on listServersDetails → warning + success without per-server calls; 500 → status error", async () => {
    listServersDetails.mockRejectedValueOnce(ERR_403);
    const denied = await scanner.scan(ctx);
    expect(denied.status).toBe("success");
    expect(denied.findingsCount).toBe(0);
    expect(denied.warnings).toEqual(["ECS: insufficient permissions (HTTP 403 | Ecs.0003 | Forbidden | requestId=req-403); skipped"]);
    expect(showMetadataOptions).not.toHaveBeenCalled();

    listServersDetails.mockRejectedValueOnce({ httpStatusCode: 404, errorCode: "APIGW.0101", errorMsg: "API not found" });
    const notEnabled = await scanner.scan(ctx);
    expect(notEnabled.status).toBe("success");
    expect(notEnabled.warnings![0]).toContain("ECS: service not enabled or not available");

    listServersDetails.mockRejectedValueOnce(ERR_500);
    const failed = await scanner.scan(ctx);
    expect(failed.status).toBe("error");
    expect(failed.error).toBe("Huawei Cloud ECS metadata options scan failed: HTTP 500 | Ecs.9999 | internal error | requestId=req-500");
    expect(failed.findingsCount).toBe(0);
    expect(JSON.stringify(failed)).not.toContain(FAKE_AK);
  });

  it("resolves projectId via IAM when the context lacks it, and errors without credentials", async () => {
    const noProject = createHuaweiCredentials({ ak: FAKE_AK, sk: FAKE_SK, domainId: DOMAIN });
    resolveRegionScopeMock.mockResolvedValueOnce({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });
    const ok = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: DOMAIN, provider: "huaweicloud", credentials: noProject });
    expect(ok.status).toBe("success");
    expect(resolveRegionScopeMock).toHaveBeenCalledWith(noProject, "cn-north-4");
    expect(hwClientMock.mock.calls[0][3]).toEqual({ region: "cn-north-4", projectId: PROJECT, domainId: DOMAIN });

    loadHuaweiCredentialsMock.mockImplementationOnce(() => { throw new Error("Huawei Cloud credentials not found."); });
    const noCreds = await scanner.scan({ region: "cn-north-4", partition: "huaweicloud", accountId: DOMAIN, provider: "huaweicloud" });
    expect(noCreds.status).toBe("error");
    expect(noCreds.error).toContain("Huawei Cloud credentials not found");
  });

  it("evaluateMetadataOptions: pure AWS-semantics verdicts (case-insensitive, camelCase accepted)", () => {
    expect(evaluateMetadataOptions({ http_endpoint: "enabled", http_tokens: "required" }).verdict).toBe("enforced");
    expect(evaluateMetadataOptions({ httpEndpoint: "ENABLED", httpTokens: "Required" }).verdict).toBe("enforced");
    expect(evaluateMetadataOptions({ http_endpoint: "enabled", http_tokens: "optional" }).verdict).toBe("not_enforced");
    expect(evaluateMetadataOptions({ http_endpoint: "disabled", http_tokens: "optional" }).verdict).toBe("endpoint_disabled");
    expect(evaluateMetadataOptions({})).toEqual({ verdict: "not_enforced", httpTokens: "unknown", httpEndpoint: "enabled" });
    expect(evaluateMetadataOptions(undefined).verdict).toBe("not_enforced");
  });
});
