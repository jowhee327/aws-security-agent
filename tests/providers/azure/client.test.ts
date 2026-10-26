/**
 * Phase 2 (Azure) T1 — ARM / Graph client factory (plan §3.4). Every SDK package is
 * mocked (identity, SubscriptionClient, Graph client, logger); fake service principal
 * only, no network. The RestError used on the failure path is the real
 * `@azure/core-rest-pipeline` class, built in memory with a fake Bearer header.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { RestError, createHttpHeaders, createPipelineRequest } from "@azure/core-rest-pipeline";

const mocks = vi.hoisted(() => {
  const credentialInstances: Array<{ args: unknown[]; getToken: ReturnType<typeof vi.fn> }> = [];
  const constructAttempts = { count: 0 };
  class FakeClientSecretCredential {
    args: unknown[];
    getToken: ReturnType<typeof vi.fn>;
    constructor(...args: unknown[]) {
      constructAttempts.count++;
      // Mirrors the SDK's tenant-ID validation (thrown synchronously by the constructor).
      if (args[0] === "invalid tenant!") {
        throw new Error(`Invalid tenant id provided. client_secret=${String(args[2])}`);
      }
      this.args = args;
      this.getToken = vi.fn(async (scope: string) => ({ token: `fake-token-for:${scope}`, expiresOnTimestamp: 0 }));
      credentialInstances.push(this);
    }
  }
  const subscriptionClientArgs: unknown[][] = [];
  const subscriptionsList = vi.fn();
  class FakeSubscriptionClient {
    subscriptions = { list: subscriptionsList };
    constructor(...args: unknown[]) {
      subscriptionClientArgs.push(args);
    }
  }
  const graphInit = vi.fn((opts: unknown) => ({ fakeGraphClient: true, opts }));
  const setLogLevel = vi.fn();
  const AzureLogger = { log: vi.fn() };
  return {
    credentialInstances,
    constructAttempts,
    FakeClientSecretCredential,
    subscriptionClientArgs,
    subscriptionsList,
    FakeSubscriptionClient,
    graphInit,
    setLogLevel,
    AzureLogger,
  };
});

vi.mock("@azure/identity", () => ({ ClientSecretCredential: mocks.FakeClientSecretCredential }));
vi.mock("@azure/arm-resources-subscriptions", () => ({ SubscriptionClient: mocks.FakeSubscriptionClient }));
vi.mock("@microsoft/microsoft-graph-client", () => ({ Client: { initWithMiddleware: mocks.graphInit } }));
vi.mock("@azure/logger", () => ({ setLogLevel: mocks.setLogLevel, AzureLogger: mocks.AzureLogger }));

import {
  AZURE_CLOUDS,
  AZURE_GRAPH_VERSION,
  armClient,
  azureArmClientOptions,
  azureCloudConfig,
  azureCredential,
  azurePaginate,
  clearAzureCredentialCache,
  ensureQuietAzureLogging,
  graphClient,
  listAzureSubscriptions,
  resetAzureLoggingMemoForTest,
} from "../../../src/providers/azure/client.js";
import { AZURE_AUTH_FAILED_PREFIX, AzureCloudError, isAzureAuthFailure } from "../../../src/providers/azure/errors.js";
import type { AzureCredentials } from "../../../src/types.js";

const FAKE_TENANT = "00000000-0000-0000-0000-00000000fake";
const FAKE_CLIENT = "11111111-1111-1111-1111-11111111fake";
const FAKE_SECRET = "FakeAzureClientSecretValue~DoNotUse-0000000000";
const SUB_A = "aaaaaaaa-0000-0000-0000-00000000fake";
const SUB_B = "bbbbbbbb-0000-0000-0000-00000000fake";
const SUB_C = "cccccccc-0000-0000-0000-00000000fake";
const FAKE_JWT =
  "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY2hpbmFjbG91ZGFwaS5jbiIsImZha2UiOnRydWV9.RmFrZVNpZ25hdHVyZURvTm90VXNlMDAwMDAwMDAwMA";

const INVALID_TENANT = "invalid tenant!";

const CHINA: AzureCredentials = { kind: "azure", tenantId: FAKE_TENANT, clientId: FAKE_CLIENT, clientSecret: FAKE_SECRET, cloud: "china" };
const GLOBAL: AzureCredentials = { ...CHINA, cloud: "global" };

/** Lazy multi-page async iterator (pages fetched on demand, like PagedAsyncIterableIterator). */
function pagedIterator<T>(pages: T[][], fetched: { pages: number }): AsyncIterable<T> {
  return {
    async *[Symbol.asyncIterator]() {
      for (const page of pages) {
        fetched.pages++;
        for (const item of page) yield item;
      }
    },
  };
}

let stdoutWrites: string[];

beforeEach(() => {
  clearAzureCredentialCache();
  mocks.credentialInstances.length = 0;
  mocks.subscriptionClientArgs.length = 0;
  mocks.subscriptionsList.mockReset();
  mocks.graphInit.mockClear();
  stdoutWrites = [];
  vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
    stdoutWrites.push(String(chunk));
    return true;
  }) as typeof process.stdout.write);
});

afterEach(() => {
  // No module may write to stdout (the MCP stdio transport) — and certainly never a secret.
  expect(stdoutWrites).toEqual([]);
  vi.restoreAllMocks();
});

describe("AZURE_CLOUDS", () => {
  it("China (21Vianet) endpoints are exact", () => {
    expect(AZURE_CLOUDS.china).toEqual({
      authorityHost: "https://login.chinacloudapi.cn",
      armEndpoint: "https://management.chinacloudapi.cn",
      armScope: "https://management.chinacloudapi.cn/.default",
      graphEndpoint: "https://microsoftgraph.chinacloudapi.cn",
      graphScope: "https://microsoftgraph.chinacloudapi.cn/.default",
    });
  });

  it("Global endpoints are exact", () => {
    expect(AZURE_CLOUDS.global).toEqual({
      authorityHost: "https://login.microsoftonline.com",
      armEndpoint: "https://management.azure.com",
      armScope: "https://management.azure.com/.default",
      graphEndpoint: "https://graph.microsoft.com",
      graphScope: "https://graph.microsoft.com/.default",
    });
  });

  it("is frozen; unknown cloud falls back to china", () => {
    expect(Object.isFrozen(AZURE_CLOUDS)).toBe(true);
    expect(Object.isFrozen(AZURE_CLOUDS.china)).toBe(true);
    expect(azureCloudConfig(undefined)).toBe(AZURE_CLOUDS.china);
    expect(azureCloudConfig("global")).toBe(AZURE_CLOUDS.global);
  });

  it("ARM client options carry the explicit endpoint + scope (China never uses SDK Global defaults)", () => {
    expect(azureArmClientOptions("china")).toEqual({
      endpoint: "https://management.chinacloudapi.cn",
      credentialScopes: ["https://management.chinacloudapi.cn/.default"],
      $host: "https://management.chinacloudapi.cn",
    });
  });
});

describe("azureCredential", () => {
  it("builds ClientSecretCredential(tenant, client, secret, { authorityHost }) for the cloud", async () => {
    await azureCredential(CHINA);
    expect(mocks.credentialInstances).toHaveLength(1);
    expect(mocks.credentialInstances[0].args).toEqual([
      FAKE_TENANT,
      FAKE_CLIENT,
      FAKE_SECRET,
      { authorityHost: "https://login.chinacloudapi.cn" },
    ]);
    await azureCredential(GLOBAL);
    expect(mocks.credentialInstances[1].args[3]).toEqual({ authorityHost: "https://login.microsoftonline.com" });
  });

  it("caches per (tenant, client, cloud, secret)", async () => {
    const a = await azureCredential(CHINA);
    const b = await azureCredential({ ...CHINA });
    expect(b).toBe(a);
    expect(mocks.credentialInstances).toHaveLength(1);

    const g = await azureCredential(GLOBAL);
    expect(g).not.toBe(a);
    const rotated = await azureCredential({ ...CHINA, clientSecret: "FakeAzureClientSecretValue~Rotated-0000000000" });
    expect(rotated).not.toBe(a);
    expect(mocks.credentialInstances).toHaveLength(3);

    clearAzureCredentialCache();
    expect(await azureCredential(CHINA)).not.toBe(a);
  });

  it("silences @azure/logger before the SDK is used", async () => {
    // The silencing is memoised per process and earlier tests already triggered it;
    // re-arm the memo and the logger mock so this test observes a fresh run.
    resetAzureLoggingMemoForTest();
    mocks.setLogLevel.mockClear();
    mocks.AzureLogger.log = vi.fn();
    await azureCredential(CHINA);
    await ensureQuietAzureLogging();
    expect(mocks.setLogLevel).toHaveBeenCalled();
    expect(mocks.setLogLevel.mock.calls[0]).toEqual([]);
    // The sink is replaced by a no-op (never console.* / stdout).
    expect(mocks.AzureLogger.log).not.toBe(undefined);
    expect(vi.isMockFunction(mocks.AzureLogger.log)).toBe(false);
  });
});

describe("armClient / graphClient", () => {
  it("armClient: new Ctor(credential, subscriptionId, { endpoint, credentialScopes })", async () => {
    const seen: unknown[][] = [];
    class FakeArmClient {
      constructor(...args: unknown[]) {
        seen.push(args);
      }
    }
    const client = await armClient(FakeArmClient, CHINA, SUB_A);
    expect(client).toBeInstanceOf(FakeArmClient);
    expect(seen).toHaveLength(1);
    expect(seen[0][0]).toBe(await azureCredential(CHINA));
    expect(seen[0][1]).toBe(SUB_A);
    expect(seen[0][2]).toMatchObject({
      endpoint: "https://management.chinacloudapi.cn",
      credentialScopes: ["https://management.chinacloudapi.cn/.default"],
    });
  });

  it("graphClient: China baseUrl + Graph scope token", async () => {
    await graphClient(CHINA);
    expect(mocks.graphInit).toHaveBeenCalledTimes(1);
    const opts = mocks.graphInit.mock.calls[0][0] as {
      baseUrl: string;
      defaultVersion: string;
      customHosts: Set<string>;
      authProvider: { getAccessToken: () => Promise<string> };
    };
    expect(opts.baseUrl).toBe("https://microsoftgraph.chinacloudapi.cn/");
    expect(opts.defaultVersion).toBe(AZURE_GRAPH_VERSION);
    expect([...opts.customHosts]).toEqual(["microsoftgraph.chinacloudapi.cn"]);

    const token = await opts.authProvider.getAccessToken();
    expect(token).toBe("fake-token-for:https://microsoftgraph.chinacloudapi.cn/.default");
    expect(mocks.credentialInstances[0].getToken).toHaveBeenCalledWith("https://microsoftgraph.chinacloudapi.cn/.default");
  });

  it("graphClient: Global baseUrl", async () => {
    await graphClient(GLOBAL);
    const opts = mocks.graphInit.mock.calls[0][0] as { baseUrl: string };
    expect(opts.baseUrl).toBe("https://graph.microsoft.com/");
  });

  it("graphClient: token failures surface as redacted AzureCloudErrors", async () => {
    await graphClient(CHINA);
    const opts = mocks.graphInit.mock.calls[0][0] as { authProvider: { getAccessToken: () => Promise<string> } };
    mocks.credentialInstances[0].getToken.mockRejectedValueOnce(
      Object.assign(new Error(`AADSTS7000215: Invalid client secret provided. secret=${FAKE_SECRET} Bearer ${FAKE_JWT}`), {
        name: "AuthenticationError",
      }),
    );
    const err = await opts.authProvider.getAccessToken().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AzureCloudError);
    expect(isAzureAuthFailure(err)).toBe(true);
    expect(String((err as Error).message)).not.toContain(FAKE_JWT);
    expect(JSON.stringify(err)).not.toContain(FAKE_JWT);

    mocks.credentialInstances[0].getToken.mockResolvedValueOnce(null);
    await expect(opts.authProvider.getAccessToken()).rejects.toBeInstanceOf(AzureCloudError);
  });
});

describe("azurePaginate", () => {
  it("drains all pages when under the cap", async () => {
    const fetched = { pages: 0 };
    const seen: number[] = [];
    const res = await azurePaginate(pagedIterator([[1, 2], [3, 4], [5]], fetched), { onItem: (n) => void seen.push(n) });
    expect(res).toEqual({ items: [1, 2, 3, 4, 5], count: 5, truncated: false });
    expect(seen).toEqual([1, 2, 3, 4, 5]);
    expect(fetched.pages).toBe(3);
  });

  it("stops at max and flags truncation without fetching later pages", async () => {
    const fetched = { pages: 0 };
    const res = await azurePaginate(pagedIterator([[1, 2], [3, 4], [5, 6]], fetched), { max: 3 });
    expect(res).toEqual({ items: [1, 2, 3], count: 3, truncated: true });
    expect(fetched.pages).toBe(2);
  });

  it("exactly max items is not truncated", async () => {
    const res = await azurePaginate(pagedIterator([[1, 2], [3]], { pages: 0 }), { max: 3 });
    expect(res.truncated).toBe(false);
    expect(res.count).toBe(3);
  });

  it("collect=false counts without retaining; sync iterables work", async () => {
    const res = await azurePaginate([1, 2, 3], { collect: false });
    expect(res).toEqual({ items: [], count: 3, truncated: false });
  });
});

describe("listAzureSubscriptions", () => {
  it("paginates (≥2 pages) and maps subscriptionId / tenantId / displayName / state", async () => {
    const fetched = { pages: 0 };
    mocks.subscriptionsList.mockReturnValue(
      pagedIterator(
        [
          [
            { subscriptionId: SUB_A, tenantId: FAKE_TENANT, displayName: "Prod", state: "Enabled", extra: "ignored" },
            { subscriptionId: "  ", displayName: "blank id — skipped" },
          ],
          [{ subscriptionId: SUB_B, displayName: "Dev", state: "Disabled" }],
          [{ subscriptionId: SUB_C, tenantId: "", state: "Warned" }],
        ],
        fetched,
      ),
    );

    const subs = await listAzureSubscriptions(CHINA);
    expect(subs).toEqual([
      { subscriptionId: SUB_A, tenantId: FAKE_TENANT, displayName: "Prod", state: "Enabled" },
      { subscriptionId: SUB_B, displayName: "Dev", state: "Disabled" },
      { subscriptionId: SUB_C, state: "Warned" },
    ]);
    expect(fetched.pages).toBe(3);

    // SubscriptionClient(credential, { endpoint, credentialScopes }) — China ARM.
    expect(mocks.subscriptionClientArgs).toHaveLength(1);
    const [cred, opts] = mocks.subscriptionClientArgs[0];
    expect(cred).toBe(await azureCredential(CHINA));
    expect(opts).toMatchObject({
      endpoint: "https://management.chinacloudapi.cn",
      credentialScopes: ["https://management.chinacloudapi.cn/.default"],
    });
  });

  it("RestError with a Bearer header → redacted AzureCloudError (token never escapes)", async () => {
    const request = createPipelineRequest({
      url: "https://management.chinacloudapi.cn/subscriptions?api-version=2022-12-01",
      method: "GET",
      headers: createHttpHeaders({ Authorization: `Bearer ${FAKE_JWT}` }),
    });
    const rest = new RestError(`The client does not have authorization. Authorization: Bearer ${FAKE_JWT}`, {
      code: "AuthorizationFailed",
      statusCode: 403,
      request,
      response: { request, status: 403, headers: createHttpHeaders({ "x-ms-request-id": "req-sub-1" }) },
    });
    mocks.subscriptionsList.mockReturnValue({
      // eslint-disable-next-line require-yield
      async *[Symbol.asyncIterator]() {
        throw rest;
      },
    });

    const err = await listAzureSubscriptions(CHINA).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AzureCloudError);
    const e = err as AzureCloudError;
    expect(e.kind).toBe("access_denied");
    expect(e.statusCode).toBe(403);
    expect(e.api).toBe("subscriptions.list");
    expect(e.requestId).toBe("req-sub-1");
    expect((e as unknown as { cause?: unknown }).cause).toBeUndefined();
    for (const s of [e.message, String(e), JSON.stringify(e), JSON.stringify(e.info)]) {
      expect(s).not.toContain(FAKE_JWT);
    }
    expect(isAzureAuthFailure(e)).toBe(false);
  });

  it("identity failure → isAzureAuthFailure + canonical 'Azure authentication failed (AADSTS…)' message", async () => {
    const authErr = Object.assign(
      new Error("ClientSecretCredential authentication failed: AADSTS7000215: Invalid client secret provided. Trace ID: 0000"),
      {
        name: "AuthenticationError",
        statusCode: 401,
        errorResponse: { error: "invalid_client", errorDescription: "AADSTS7000215: Invalid client secret provided.", errorCodes: [7000215] },
      },
    );
    mocks.subscriptionsList.mockReturnValue({
      // eslint-disable-next-line require-yield
      async *[Symbol.asyncIterator]() {
        throw authErr;
      },
    });

    const err = await listAzureSubscriptions(CHINA).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AzureCloudError);
    expect(isAzureAuthFailure(err)).toBe(true);
    expect((err as Error).message.startsWith(`${AZURE_AUTH_FAILED_PREFIX} (AADSTS7000215)`)).toBe(true);
    expect((err as Error).message).not.toContain(FAKE_SECRET);
    expect((err as Error).message).not.toContain("Trace ID");
  });

  it("a credential construction failure is a redacted auth failure and is not cached", async () => {
    const bad: AzureCredentials = { ...CHINA, tenantId: INVALID_TENANT };
    const err = await listAzureSubscriptions(bad).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AzureCloudError);
    expect(isAzureAuthFailure(err)).toBe(true);
    expect((err as Error).message).not.toContain(FAKE_SECRET);
    expect(mocks.subscriptionClientArgs).toHaveLength(0);

    // The rejected promise is dropped from the cache: the next call constructs again.
    const constructed = mocks.constructAttempts.count;
    await azureCredential(bad).catch(() => undefined);
    expect(mocks.constructAttempts.count).toBe(constructed + 1);
  });
});
