/**
 * Azure ARM / Microsoft Graph client factory (plan §3.4). EXPERIMENTAL — endpoints follow
 * the Azure national-cloud documentation (plan appendix A); not validated against a live
 * account. China (21Vianet) is the default cloud.
 *
 *  - {@link AZURE_CLOUDS}: authority host / ARM endpoint + scope / Graph endpoint + scope.
 *    China REQUIRES the explicit ARM `endpoint` + `credentialScopes`: the SDK defaults are
 *    Global (`management.azure.com`), which yields a wrong-audience 401 in China.
 *  - {@link azureCredential}: a cached `ClientSecretCredential(tenant, client, secret,
 *    { authorityHost })`. `DefaultAzureCredential` is never used (it probes IMDS / CLI).
 *  - {@link armClient}: `new Ctor(credential, subscriptionId, { endpoint, credentialScopes })`.
 *  - {@link graphClient}: Graph `Client` with a custom auth provider and the cloud's baseUrl.
 *  - {@link azurePaginate}: `PagedAsyncIterableIterator` → capped item list + overflow flag.
 *  - {@link listAzureSubscriptions}: `SubscriptionClient.subscriptions.list()`.
 *
 * Every `@azure/*` / Graph package is loaded lazily (`await import()`), so the AWS /
 * Huawei / Alibaba paths never load them; only TYPE imports appear at the top.
 * `@azure/logger` is silenced before the first SDK import: its info / verbose output goes
 * to `console.info` / `console.debug` — i.e. stdout, which is the MCP stdio transport.
 */
import { createHash } from "crypto";
import type { AccessToken, TokenCredential } from "@azure/identity";
import type { Client as GraphClient } from "@microsoft/microsoft-graph-client";
import type { AzureCloud, AzureCredentials } from "../../types.js";
import { AzureCloudError, toAzureError } from "./errors.js";
import type { AzureSubscriptionRef } from "./subscriptions.js";

export interface AzureCloudConfig {
  /** Entra ID (AAD) authority host for `ClientSecretCredential`. */
  authorityHost: string;
  /** ARM endpoint for every management client. */
  armEndpoint: string;
  /** ARM token scope (`<armEndpoint>/.default`). */
  armScope: string;
  /** Microsoft Graph endpoint (no version segment). */
  graphEndpoint: string;
  /** Graph token scope (`<graphEndpoint>/.default`). */
  graphScope: string;
}

export const AZURE_CLOUDS: Readonly<Record<AzureCloud, Readonly<AzureCloudConfig>>> = Object.freeze({
  china: Object.freeze({
    authorityHost: "https://login.chinacloudapi.cn",
    armEndpoint: "https://management.chinacloudapi.cn",
    armScope: "https://management.chinacloudapi.cn/.default",
    graphEndpoint: "https://microsoftgraph.chinacloudapi.cn",
    graphScope: "https://microsoftgraph.chinacloudapi.cn/.default",
  }),
  global: Object.freeze({
    authorityHost: "https://login.microsoftonline.com",
    armEndpoint: "https://management.azure.com",
    armScope: "https://management.azure.com/.default",
    graphEndpoint: "https://graph.microsoft.com",
    graphScope: "https://graph.microsoft.com/.default",
  }),
});

/** Cloud config for credentials (unknown values fall back to China, the default). */
export function azureCloudConfig(cloud: AzureCloud | undefined): Readonly<AzureCloudConfig> {
  return cloud === "global" ? AZURE_CLOUDS.global : AZURE_CLOUDS.china;
}

/** Graph API version used by {@link graphClient}. */
export const AZURE_GRAPH_VERSION = "v1.0";
/** Default cap for {@link azurePaginate}. */
export const AZURE_DEFAULT_MAX_ITEMS = 5000;
/** Cap for subscription enumeration. */
export const AZURE_MAX_SUBSCRIPTIONS = 1000;

/* ------------------------------------------------------------------------ */
/* SDK logging                                                              */
/* ------------------------------------------------------------------------ */

let quietLogging: Promise<void> | undefined;

/**
 * Disable `@azure/logger` (`setLogLevel()` with no level = off) and drop its sink, once.
 * Never throws. `@azure/logger` is a transitive dependency; it is marked external in
 * tsup.config.ts so the bundle resolves the same instance the SDK uses at runtime (not
 * an inlined private copy). The specifier stays a literal so test mocks apply to it.
 */
export function ensureQuietAzureLogging(): Promise<void> {
  quietLogging ??= (async () => {
    try {
      const logger = (await import("@azure/logger")) as {
        setLogLevel?: (level?: string) => void;
        AzureLogger?: { log: (...args: unknown[]) => void };
      };
      logger.setLogLevel?.();
      if (logger.AzureLogger) logger.AzureLogger.log = () => {};
    } catch {
      // Logger unavailable: nothing to silence (AZURE_LOG_LEVEL is never set by this package).
    }
  })();
  return quietLogging;
}

/** Test-only: forget that logging was silenced so the next call re-runs it. */
export function resetAzureLoggingMemoForTest(): void {
  quietLogging = undefined;
}

/* ------------------------------------------------------------------------ */
/* Credential                                                               */
/* ------------------------------------------------------------------------ */

const credentialCache = new Map<string, Promise<TokenCredential>>();

/** tenant | client | cloud | secret fingerprint — the secret itself is never a key. */
function credentialCacheKey(creds: AzureCredentials): string {
  const secretFp = createHash("sha256").update(creds.clientSecret ?? "").digest("hex").slice(0, 16);
  return `${creds.tenantId}|${creds.clientId}|${azureCloudConfig(creds.cloud).authorityHost}|${secretFp}`;
}

export function clearAzureCredentialCache(): void {
  credentialCache.clear();
}

/**
 * Cached `ClientSecretCredential(tenantId, clientId, clientSecret, { authorityHost })`,
 * keyed by (tenant, client, cloud) plus a secret fingerprint so a rotated secret is not
 * served from the cache. Lazy-imports `@azure/identity`. Construction failures (e.g. an
 * invalid tenant ID) surface as a redacted `auth_failed` {@link AzureCloudError}.
 */
export function azureCredential(creds: AzureCredentials): Promise<TokenCredential> {
  const key = credentialCacheKey(creds);
  const cached = credentialCache.get(key);
  if (cached) return cached;
  const pending = (async (): Promise<TokenCredential> => {
    await ensureQuietAzureLogging();
    const { ClientSecretCredential } = await import("@azure/identity");
    try {
      return new ClientSecretCredential(creds.tenantId, creds.clientId, creds.clientSecret, {
        authorityHost: azureCloudConfig(creds.cloud).authorityHost,
      });
    } catch (err) {
      const info = toAzureError(err).info;
      throw new AzureCloudError({ ...info, kind: "auth_failed" }, "ClientSecretCredential");
    }
  })();
  credentialCache.set(key, pending);
  pending.catch(() => credentialCache.delete(key));
  return pending;
}

/* ------------------------------------------------------------------------ */
/* ARM / Graph clients                                                      */
/* ------------------------------------------------------------------------ */

/** Options passed to every ARM management client. */
export interface AzureArmClientOptions {
  endpoint: string;
  credentialScopes: string[];
  /** Older generated clients build URLs from `$host`; kept equal to `endpoint`. */
  $host: string;
}

export function azureArmClientOptions(cloud: AzureCloud | undefined): AzureArmClientOptions {
  const cfg = azureCloudConfig(cloud);
  return { endpoint: cfg.armEndpoint, credentialScopes: [cfg.armScope], $host: cfg.armEndpoint };
}

/** {@link azureArmClientOptions} plus the token scope in the shape TypeSpec-generated clients read. */
export interface AzureArmClientCtorOptions extends AzureArmClientOptions {
  credentials: { scopes: string[] };
}

/**
 * Options actually passed to ARM client constructors. Two generations of generated clients
 * read the token scope from different places: AutoRest clients (`@azure/arm-security`,
 * `arm-policyinsights`, `arm-authorization`) use `credentialScopes`; TypeSpec clients
 * (`arm-monitor`, `arm-keyvault`, `arm-storage`, `arm-network`, `arm-compute`,
 * `arm-appservice`, `arm-resources`, `arm-resources-subscriptions`) use `credentials.scopes`
 * and otherwise default to the Global `management.azure.com/.default` audience — a
 * wrong-audience token for the China endpoint. Both are set.
 */
export function azureArmClientCtorOptions(cloud: AzureCloud | undefined): AzureArmClientCtorOptions {
  const base = azureArmClientOptions(cloud);
  return { ...base, credentials: { scopes: [...base.credentialScopes] } };
}

/** Any generated `@azure/arm-*` client class (`StorageManagementClient`, `SecurityCenter`, …). */
export type AzureArmClientCtor<T> = new (
  credential: TokenCredential,
  subscriptionId: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  options?: any,
) => T;

/**
 * `new Ctor(credential, subscriptionId, { endpoint: armEndpoint, credentialScopes: [armScope], credentials: { scopes: [armScope] } })`
 * (see {@link azureArmClientCtorOptions}).
 * The caller lazy-imports the client package (`const { StorageManagementClient } = await
 * import("@azure/arm-storage")`); the credential is resolved (and `@azure/identity` loaded) here.
 */
export async function armClient<T>(Ctor: AzureArmClientCtor<T>, creds: AzureCredentials, subscriptionId: string): Promise<T> {
  const credential = await azureCredential(creds);
  return new Ctor(credential, subscriptionId, azureArmClientCtorOptions(creds.cloud));
}

/**
 * Microsoft Graph client for the credentials' cloud (China baseUrl
 * `https://microsoftgraph.chinacloudapi.cn/`). The auth provider asks the cached
 * credential for a `<graphEndpoint>/.default` token per request; token failures surface as
 * redacted {@link AzureCloudError}s.
 */
export async function graphClient(creds: AzureCredentials): Promise<GraphClient> {
  const cfg = azureCloudConfig(creds.cloud);
  const credential = await azureCredential(creds);
  const mod = (await import("@microsoft/microsoft-graph-client")) as unknown as {
    Client?: typeof GraphClient;
    default?: { Client?: typeof GraphClient };
  };
  const Client = mod.Client ?? mod.default?.Client;
  if (!Client) throw new AzureCloudError({ kind: "other", message: "Microsoft Graph client unavailable" }, "graphClient");
  return Client.initWithMiddleware({
    baseUrl: `${cfg.graphEndpoint}/`,
    defaultVersion: AZURE_GRAPH_VERSION,
    customHosts: new Set([new URL(cfg.graphEndpoint).host]),
    authProvider: {
      async getAccessToken(): Promise<string> {
        let token: AccessToken | null;
        try {
          token = await credential.getToken(cfg.graphScope);
        } catch (err) {
          throw toAzureError(err, "graph token");
        }
        if (!token?.token) {
          throw new AzureCloudError({ kind: "auth_failed", message: "no Graph access token returned" }, "graph token");
        }
        return token.token;
      },
    },
  });
}

/* ------------------------------------------------------------------------ */
/* Pagination                                                               */
/* ------------------------------------------------------------------------ */

export interface AzurePaginateOptions<T> {
  /** Maximum number of items to consume (default {@link AZURE_DEFAULT_MAX_ITEMS}). */
  max?: number;
  /** Called for each consumed item (in order). */
  onItem?: (item: T) => void | Promise<void>;
  /** Collect items into the result (default true). */
  collect?: boolean;
}

export interface AzurePaginateResult<T> {
  items: T[];
  /** Number of items consumed (≤ max). */
  count: number;
  /** True when more items were available beyond `max` (iteration stopped early). */
  truncated: boolean;
}

/**
 * Drain an ARM `PagedAsyncIterableIterator` (any async / sync iterable) up to `max` items.
 * Pages are fetched lazily by the SDK, so stopping early saves the remaining requests.
 * SDK errors propagate unchanged — the caller classifies them (classifyAzureError).
 */
export async function azurePaginate<T>(
  iterable: AsyncIterable<T> | Iterable<T>,
  opts: AzurePaginateOptions<T> = {},
): Promise<AzurePaginateResult<T>> {
  const max = opts.max !== undefined && Number.isFinite(opts.max) ? Math.max(0, Math.floor(opts.max)) : AZURE_DEFAULT_MAX_ITEMS;
  const collect = opts.collect ?? true;
  const items: T[] = [];
  let count = 0;
  let truncated = false;
  for await (const item of iterable as AsyncIterable<T>) {
    if (count >= max) {
      truncated = true;
      break;
    }
    count++;
    if (collect) items.push(item);
    if (opts.onItem) await opts.onItem(item);
  }
  return { items, count, truncated };
}

/* ------------------------------------------------------------------------ */
/* Subscriptions                                                            */
/* ------------------------------------------------------------------------ */

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

/**
 * Every subscription visible to the service principal, via
 * `SubscriptionClient(credential, { endpoint, credentialScopes }).subscriptions.list()`
 * (paginated, capped at {@link AZURE_MAX_SUBSCRIPTIONS}). Failures are rethrown as a
 * redacted {@link AzureCloudError} (`isAzureAuthFailure` works on it); the raw RestError
 * — which holds the Bearer token in its request headers — never escapes.
 */
export async function listAzureSubscriptions(creds: AzureCredentials): Promise<AzureSubscriptionRef[]> {
  try {
    const credential = await azureCredential(creds);
    const { SubscriptionClient } = await import("@azure/arm-resources-subscriptions");
    const client = new SubscriptionClient(credential, azureArmClientCtorOptions(creds.cloud));
    const { items } = await azurePaginate(client.subscriptions.list(), { max: AZURE_MAX_SUBSCRIPTIONS });
    const out: AzureSubscriptionRef[] = [];
    for (const s of items as unknown as Array<Record<string, unknown>>) {
      const subscriptionId = str(s?.subscriptionId);
      if (!subscriptionId) continue;
      const ref: AzureSubscriptionRef = { subscriptionId };
      const tenantId = str(s.tenantId);
      const displayName = str(s.displayName);
      const state = str(s.state);
      if (tenantId) ref.tenantId = tenantId;
      if (displayName) ref.displayName = displayName;
      if (state) ref.state = state;
      out.push(ref);
    }
    return out;
  } catch (err) {
    throw toAzureError(err, "subscriptions.list");
  }
}
