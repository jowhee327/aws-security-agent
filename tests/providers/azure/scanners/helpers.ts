/**
 * Shared fixtures for the Azure scanner tests (T2+): fake service principal, a generic fake
 * ARM client (every `client.<group>.<method>(...)` call is routed to a handler keyed by
 * `"<Client>.<group>.<method>"`), lazy paged iterators, real `RestError` fixtures carrying a
 * fake Bearer header, and hostile-string assertions. Fake values only; no network — the
 * test files `vi.mock` every `@azure/*` package with {@link fakeArmClientClass} /
 * {@link FakeClientSecretCredential}.
 */
import { RestError, createHttpHeaders, createPipelineRequest, type PipelineResponse } from "@azure/core-rest-pipeline";
import type { AzureCredentials, ScanContext } from "../../../../src/types.js";

export const FAKE_TENANT = "00000000-0000-0000-0000-00000000fake";
export const FAKE_CLIENT = "11111111-1111-1111-1111-111111111111";
export const FAKE_SECRET = "FakeAzureClientSecretValue~DoNotUse";
export const FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJmYWtlIjoidG9rZW4ifQ.fakesignaturefakesignature";
export const SUB = "aaaaaaaa-0000-0000-0000-00000000fake";

export const FAKE_CREDS: AzureCredentials = {
  kind: "azure",
  tenantId: FAKE_TENANT,
  clientId: FAKE_CLIENT,
  clientSecret: FAKE_SECRET,
  cloud: "china",
};

export function azCtx(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    region: SUB,
    partition: "azure",
    accountId: FAKE_TENANT,
    credentials: FAKE_CREDS,
    provider: "azure",
    subscriptionId: SUB,
    tenantId: FAKE_TENANT,
    cloud: "china",
    ...overrides,
  };
}

const ENV_KEYS = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_CLOUD", "AZURE_SUBSCRIPTION_ID"];
const saved: Record<string, string | undefined> = {};

export function isolateAzureEnv(): void {
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
}

export function restoreAzureEnv(): void {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
}

/* ------------------------------------------------------------------------ */
/* Fake SDK                                                                 */
/* ------------------------------------------------------------------------ */

export type SdkHandler = (...args: unknown[]) => unknown;

export const azureSdk = {
  handlers: new Map<string, SdkHandler | unknown>(),
  calls: [] as Array<{ op: string; args: unknown[] }>,
  ctorArgs: [] as Array<{ client: string; args: unknown[] }>,
  reset(): void {
    this.handlers.clear();
    this.calls.length = 0;
    this.ctorArgs.length = 0;
  },
  /** `handlers` value: a function (called with the SDK args; may throw) or a literal result. */
  on(op: string, handler: SdkHandler | unknown): void {
    this.handlers.set(op, handler);
  },
  invoke(op: string, args: unknown[]): unknown {
    this.calls.push({ op, args });
    if (!this.handlers.has(op)) throw new Error(`unexpected Azure SDK call ${op}`);
    const h = this.handlers.get(op);
    return typeof h === "function" ? (h as SdkHandler)(...args) : h;
  },
  callsFor(op: string): unknown[][] {
    return this.calls.filter((c) => c.op === op).map((c) => c.args);
  },
};

/** Fake generated ARM client class: `new X(cred, sub, opts).<group>.<method>(...)` → `azureSdk.invoke("X.group.method")`. */
export function fakeArmClientClass(name: string): new (...args: unknown[]) => unknown {
  return class FakeArmClient {
    constructor(...args: unknown[]) {
      azureSdk.ctorArgs.push({ client: name, args });
      return new Proxy(
        {},
        {
          get: (_t, group) =>
            typeof group !== "string" || group === "then"
              ? undefined
              : new Proxy(
                  {},
                  {
                    get: (_t2, method) =>
                      typeof method !== "string" || method === "then"
                        ? undefined
                        : (...callArgs: unknown[]) => azureSdk.invoke(`${name}.${group}.${method}`, callArgs),
                  },
                ),
        },
      );
    }
  };
}

export class FakeClientSecretCredential {
  constructor(..._args: unknown[]) {}
  async getToken(): Promise<{ token: string; expiresOnTimestamp: number }> {
    return { token: FAKE_JWT, expiresOnTimestamp: 0 };
  }
}

/** Lazy multi-page async iterable (pages fetched on demand, like PagedAsyncIterableIterator). */
export function pages<T>(pageList: T[][], fetched: { pages: number } = { pages: 0 }): AsyncIterable<T> {
  return {
    async *[Symbol.asyncIterator]() {
      for (const page of pageList) {
        fetched.pages++;
        for (const item of page) yield item;
      }
    },
  };
}

/** Async iterable that fails on the first page (SDK paged errors surface on iteration). */
export function failingPages(err: unknown, before: unknown[] = []): AsyncIterable<unknown> {
  return {
    async *[Symbol.asyncIterator]() {
      for (const item of before) yield item;
      throw err;
    },
  };
}

/* ------------------------------------------------------------------------ */
/* Errors                                                                   */
/* ------------------------------------------------------------------------ */

/** Real RestError with a fake Bearer token in the request (and an echo in the response headers). */
export function restError(statusCode: number, code: string, message: string): RestError {
  const request = createPipelineRequest({
    url: `https://management.chinacloudapi.cn/subscriptions/${SUB}/providers/Microsoft.Security/assessments?api-version=2021-06-01`,
    method: "GET",
    headers: createHttpHeaders({ Authorization: `Bearer ${FAKE_JWT}` }),
  });
  const response: PipelineResponse = {
    request,
    status: statusCode,
    headers: createHttpHeaders({ "x-ms-request-id": "req-0000-fake", "www-authenticate": `Bearer token=${FAKE_JWT}` }),
  };
  return new RestError(message, { code, statusCode, request, response });
}

export const deniedError = () =>
  restError(
    403,
    "AuthorizationFailed",
    `The client '${FAKE_CLIENT}' with object id '${FAKE_CLIENT}' does not have authorization to perform action 'Microsoft.Security/assessments/read' over scope '/subscriptions/${SUB}'.`,
  );

export const notRegisteredError = (ns = "Microsoft.Security") =>
  restError(409, "MissingSubscriptionRegistration", `The subscription is not registered to use namespace '${ns}'.`);

export const misuseError = () =>
  restError(400, "InvalidApiVersionParameter", "The api-version '1999-01-01' is invalid. The supported versions are '2021-06-01'.");

export const throttledError = () => restError(429, "TooManyRequests", "Too many requests, retry later.");

/** `@azure/identity` AuthenticationError shape for a fake tenant (plan §6.1: AADSTS900023). */
export function authError(): Error {
  const message = `ClientSecretCredential authentication failed: AADSTS900023: Specified tenant identifier '${FAKE_TENANT}' is neither a valid DNS name, nor a valid external domain. Trace ID: 0000 Correlation ID: 0000 Timestamp: 2026-10-26`;
  return Object.assign(new Error(message), {
    name: "AuthenticationError",
    statusCode: 400,
    errorResponse: { error: "invalid_request", errorDescription: message, errorCodes: [900023] },
  });
}

/* ------------------------------------------------------------------------ */
/* Hostile strings                                                          */
/* ------------------------------------------------------------------------ */

/** A hostile server string carrying the fake secret, a `client_secret=` pair and a fake JWT. */
export const hostile = (prefix: string): string =>
  `${prefix} ${FAKE_SECRET} client_secret=${FAKE_SECRET} Authorization: Bearer ${FAKE_JWT} token ${FAKE_JWT}`;

export const HOSTILE_FORBIDDEN = [FAKE_SECRET, FAKE_JWT, "eyJhbGciOiJIUzI1NiJ9", "fakesignaturefakesignature"];

interface Checkable {
  error?: string;
  warnings?: string[];
  findings: Array<{ title: string; description: string; resourceId: string; resourceArn: string; remediationSteps: string[]; source?: string }>;
}

/** Assert no secret / token in any Finding field, warning, error or the serialised result. */
export function expectNoLeak(r: Checkable): void {
  const texts: string[] = [JSON.stringify(r), r.error ?? "", ...(r.warnings ?? [])];
  for (const f of r.findings) texts.push(f.title, f.description, f.resourceId, f.resourceArn, f.source ?? "", ...f.remediationSteps);
  for (const t of texts) {
    for (const bad of HOSTILE_FORBIDDEN) {
      if (t.includes(bad)) throw new Error(`secret / token ${JSON.stringify(bad)} leaked into: ${t.slice(0, 300)}`);
    }
  }
}
