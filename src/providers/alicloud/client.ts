/**
 * Alibaba Cloud client factory (plan §3.5): ONE generic OpenAPI client
 * (`@alicloud/openapi-core` `callApi`) for every RPC / ROA API in
 * {@link ALI_API_CATALOG}, plus `ali-oss` for OSS. No per-service SDK packages.
 *
 * - SDK modules are imported lazily (`await import()`) so the default AWS path never loads them.
 * - openapi-core is CJS: under ESM the client class is `module.default.default`
 *   (`import OpenApi from "@alicloud/openapi-core"` → `OpenApi.default`); `Config` / `Params` /
 *   `OpenApiRequest` come from `@alicloud/openapi-core/dist/utils.js`; `RuntimeOptions` from
 *   `@alicloud/tea-util`. {@link loadAliSdk} accepts both the named and the `.default` shapes.
 * - [P0] Every Config is built with EXPLICIT accessKeyId / accessKeySecret (/ securityToken):
 *   otherwise openapi-core falls back to `@alicloud/credentials`' default chain, which reads
 *   `~/.aliyun/config.json` and probes the ECS IMDS (100.100.100.200, ~2 s timeout).
 * - RuntimeOptions: connectTimeout 5000 ms, readTimeout 15000 ms, autoretry=false. Retries are
 *   done here, only for throttling / 5xx / network blips, with exponential backoff (max 3 retries).
 * - Every failure is rethrown as an {@link AliCloudError} carrying only redacted fields
 *   (the raw SDK error is never attached).
 *
 * The SDKs write nothing to stdout (measured, plan §6.1). `ali-oss` uses the `debug`
 * module (stringToSign / headers → stderr when DEBUG matches `ali-oss*`):
 * {@link aliOssClient} strips those namespaces from `process.env.DEBUG` before importing it.
 *
 * EXPERIMENTAL: not yet validated against a live account.
 */
import type OSS from "ali-oss";
import type { AlibabaCloudCredentials } from "../../types.js";
import { ALI_API, type AliApiSpec, type AliService } from "./api-catalog.js";
import { AliCloudError, classifyAliError, isAliRetryable } from "./errors.js";

/* ------------------------------------------------------------------------ */
/* Site / endpoints                                                         */
/* ------------------------------------------------------------------------ */

export type AliSite = "cn" | "intl";
export const ALI_SITE_ENV = "ALIBABA_CLOUD_SITE";
export const ALI_ENDPOINT_DOMAIN = "aliyuncs.com";

/** `ALIBABA_CLOUD_SITE=cn|intl` (case-insensitive; anything else → `cn`). */
export function resolveAliSite(env: NodeJS.ProcessEnv = process.env): AliSite {
  const v = (env[ALI_SITE_ENV] ?? "").trim().toLowerCase();
  return v === "intl" || v === "international" ? "intl" : "cn";
}

/** Regional services: `<host>.<region>.aliyuncs.com`. FC3 uses `fcv3` (NOT `<uid>.<region>.fc`). */
const REGIONAL_HOSTS: Readonly<Partial<Record<AliService, string>>> = {
  ecs: "ecs",
  vpc: "vpc",
  slb: "slb",
  kms: "kms",
  actiontrail: "actiontrail",
  fc: "fcv3",
};

/** Global / centralised services with a single endpoint for both sites. */
const GLOBAL_HOSTS: Readonly<Partial<Record<AliService, string>>> = {
  ram: `ram.${ALI_ENDPOINT_DOMAIN}`,
  ims: `ims.${ALI_ENDPOINT_DOMAIN}`,
  sts: `sts.${ALI_ENDPOINT_DOMAIN}`,
  resourcemanager: `resourcemanager.${ALI_ENDPOINT_DOMAIN}`,
  alidns: `alidns.${ALI_ENDPOINT_DOMAIN}`,
  rds: `rds.${ALI_ENDPOINT_DOMAIN}`, // centralised endpoint; pass RegionId as a parameter
};

/**
 * Centralised services whose endpoint depends on the site (measured: `config.cn-hangzhou`
 * does not resolve; `sas.aliyuncs.com` times out — SAS is served from `tds`).
 */
const SITE_HOSTS: Readonly<Partial<Record<AliService, Readonly<Record<AliSite, string>>>>> = {
  config: { cn: `config.cn-shanghai.${ALI_ENDPOINT_DOMAIN}`, intl: `config.ap-southeast-1.${ALI_ENDPOINT_DOMAIN}` },
  sas: { cn: `tds.${ALI_ENDPOINT_DOMAIN}`, intl: `tds.ap-southeast-1.${ALI_ENDPOINT_DOMAIN}` },
  cas: { cn: `cas.${ALI_ENDPOINT_DOMAIN}`, intl: `cas.ap-southeast-1.${ALI_ENDPOINT_DOMAIN}` }, // intl: to be confirmed on a live account
  waf: { cn: `wafopenapi.cn-hangzhou.${ALI_ENDPOINT_DOMAIN}`, intl: `wafopenapi.ap-southeast-1.${ALI_ENDPOINT_DOMAIN}` },
};

/** ECS DescribeRegions is called on the global ECS endpoint. */
export const ALI_ECS_GLOBAL_ENDPOINT = `ecs.${ALI_ENDPOINT_DOMAIN}`;

export function isAliRegionalService(service: AliService): boolean {
  return service in REGIONAL_HOSTS;
}

/** Endpoint HOSTNAME (no scheme) for a service. Regional services require `region`. */
export function aliEndpoint(service: AliService, region?: string, site: AliSite = resolveAliSite()): string {
  const bySite = SITE_HOSTS[service];
  if (bySite) return bySite[site];
  const global = GLOBAL_HOSTS[service];
  if (global) return global;
  const host = REGIONAL_HOSTS[service];
  if (!host) throw new Error(`Alibaba Cloud service "${service}" has no endpoint rule`);
  const r = region?.trim();
  if (!r) throw new Error(`Alibaba Cloud service "${service}" is regional; region is required`);
  return `${host}.${r}.${ALI_ENDPOINT_DOMAIN}`;
}

/* ------------------------------------------------------------------------ */
/* Lazy SDK loading                                                         */
/* ------------------------------------------------------------------------ */

type AnyCtor<T = unknown> = new (map?: Record<string, unknown>) => T;

/** Structural view of the openapi-core client (only what we call). */
export interface AliOpenApiClient {
  callApi(params: unknown, request: unknown, runtime: unknown): Promise<{ body?: unknown; statusCode?: number } | undefined>;
}

export interface AliSdk {
  Client: new (config: unknown) => AliOpenApiClient;
  Config: AnyCtor;
  Params: AnyCtor;
  OpenApiRequest: AnyCtor;
  RuntimeOptions: AnyCtor;
}

function pickNamed(ns: unknown, name: string): unknown {
  const m = ns as Record<string, unknown> | undefined;
  const direct = m?.[name];
  if (direct !== undefined) return direct;
  const d = m?.default as Record<string, unknown> | undefined;
  return d?.[name];
}

/** CJS interop: ESM `import()` yields `{ default: module.exports }` and module.exports.default is the class. */
function pickDefaultClass(ns: unknown): unknown {
  const d = (ns as { default?: unknown } | undefined)?.default;
  const inner = (d as { default?: unknown } | undefined)?.default;
  return typeof inner === "function" ? inner : d;
}

let sdkPromise: Promise<AliSdk> | undefined;

export function loadAliSdk(): Promise<AliSdk> {
  if (!sdkPromise) {
    const p = (async (): Promise<AliSdk> => {
      const [core, utils, teaUtil] = await Promise.all([
        import("@alicloud/openapi-core"),
        import("@alicloud/openapi-core/dist/utils.js"),
        import("@alicloud/tea-util"),
      ]);
      const sdk = {
        Client: pickDefaultClass(core),
        Config: pickNamed(utils, "Config"),
        Params: pickNamed(utils, "Params"),
        OpenApiRequest: pickNamed(utils, "OpenApiRequest"),
        RuntimeOptions: pickNamed(teaUtil, "RuntimeOptions"),
      };
      for (const [k, v] of Object.entries(sdk)) {
        if (typeof v !== "function") throw new Error(`Alibaba Cloud SDK export "${k}" could not be resolved (@alicloud/openapi-core / @alicloud/tea-util)`);
      }
      return sdk as unknown as AliSdk;
    })();
    sdkPromise = p;
    // A failed load must not be cached forever.
    p.catch(() => {
      if (sdkPromise === p) sdkPromise = undefined;
    });
  }
  return sdkPromise;
}

/* ------------------------------------------------------------------------ */
/* aliCall                                                                  */
/* ------------------------------------------------------------------------ */

export const ALI_CONNECT_TIMEOUT_MS = 5000;
export const ALI_READ_TIMEOUT_MS = 15000;
export const ALI_MAX_RETRIES = 3;
export const ALI_RETRY_BASE_DELAY_MS = 300;
export const ALI_RETRY_MAX_DELAY_MS = 5000;

export interface AliRetryOptions {
  /** Maximum retries after the first attempt (default {@link ALI_MAX_RETRIES}). */
  maxRetries?: number;
  /** Backoff base: delay = base * 2^attempt, capped at {@link ALI_RETRY_MAX_DELAY_MS} (default {@link ALI_RETRY_BASE_DELAY_MS}). */
  baseDelayMs?: number;
}

export interface AliCallContext {
  credentials: AlibabaCloudCredentials;
  /** Region for regional endpoints (also sent as Config.regionId). */
  region?: string;
  /** Site for centralised endpoints; defaults to `ALIBABA_CLOUD_SITE`. */
  site?: AliSite;
  /** Endpoint hostname override (tests / private endpoints / ECS DescribeRegions). */
  endpoint?: string;
  retry?: AliRetryOptions;
}

/**
 * Flatten request parameters the way the per-service SDKs do (`OpenApiUtil.query`):
 * arrays → `Key.1`, `Key.2`…; objects → `Key.Sub`; booleans / numbers → strings;
 * null / undefined dropped.
 */
export function flattenAliQuery(query: Record<string, unknown> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (prefix: string, v: unknown) => {
    if (v === undefined || v === null) return;
    if (Array.isArray(v)) {
      v.forEach((item, i) => walk(`${prefix}.${i + 1}`, item));
    } else if (typeof v === "object") {
      for (const [k, sub] of Object.entries(v as Record<string, unknown>)) walk(prefix ? `${prefix}.${k}` : k, sub);
    } else {
      out[prefix] = String(v);
    }
  };
  for (const [k, v] of Object.entries(query ?? {})) walk(k, v);
  return out;
}

/** Clients cached per credential object and endpoint (credentials never used as a string key). */
let clientCache = new WeakMap<object, Map<string, AliOpenApiClient>>();

export function clearAliClientCache(): void {
  clientCache = new WeakMap();
}

function buildClient(sdk: AliSdk, creds: AlibabaCloudCredentials, endpoint: string, region: string | undefined): AliOpenApiClient {
  let perCreds = clientCache.get(creds);
  const key = `${endpoint}|${region ?? ""}`;
  const cached = perCreds?.get(key);
  if (cached) return cached;
  const config = new sdk.Config({
    // [P0] explicit credentials — never let openapi-core fall back to its default chain (IMDS probe).
    type: creds.securityToken ? "sts" : "access_key",
    accessKeyId: creds.accessKeyId,
    accessKeySecret: creds.accessKeySecret,
    ...(creds.securityToken ? { securityToken: creds.securityToken } : {}),
    endpoint,
    protocol: "https",
    ...(region ? { regionId: region } : {}),
    connectTimeout: ALI_CONNECT_TIMEOUT_MS,
    readTimeout: ALI_READ_TIMEOUT_MS,
  });
  const client = new sdk.Client(config);
  if (!perCreds) {
    perCreds = new Map();
    clientCache.set(creds, perCreds);
  }
  perCreds.set(key, client);
  return client;
}

function sleep(ms: number): Promise<void> {
  return ms > 0 ? new Promise((resolve) => setTimeout(resolve, ms)) : Promise.resolve();
}

function resolveEndpoint(spec: AliApiSpec, ctx: AliCallContext): string {
  return ctx.endpoint ?? aliEndpoint(spec.service, ctx.region, ctx.site ?? resolveAliSite());
}

/**
 * Call one Alibaba Cloud OpenAPI and return the response body.
 *
 * `spec` MUST come from `api-catalog.ts`. `query` is flattened with {@link flattenAliQuery};
 * `body` is sent as-is (form data for RPC, JSON for ROA). Throws {@link AliCloudError}.
 */
export async function aliCall<T = Record<string, unknown>>(
  spec: AliApiSpec,
  ctx: AliCallContext,
  query?: Record<string, unknown>,
  body?: unknown,
): Promise<T> {
  const api = `${spec.service}:${spec.action}`;
  const creds = ctx.credentials;
  if (!creds || typeof creds.accessKeyId !== "string" || !creds.accessKeyId || typeof creds.accessKeySecret !== "string" || !creds.accessKeySecret) {
    // Never call without explicit credentials (openapi-core would use its default chain).
    throw new AliCloudError({ kind: "auth_failed", code: "MissingCredentials", message: "Alibaba Cloud credentials are missing" }, api);
  }

  const maxRetries = Math.max(0, ctx.retry?.maxRetries ?? ALI_MAX_RETRIES);
  const baseDelay = Math.max(0, ctx.retry?.baseDelayMs ?? ALI_RETRY_BASE_DELAY_MS);

  let sdk: AliSdk;
  let endpoint: string;
  try {
    sdk = await loadAliSdk();
    endpoint = resolveEndpoint(spec, ctx);
  } catch (err) {
    throw new AliCloudError({ ...classifyAliError(err), kind: "other" }, api);
  }

  for (let attempt = 0; ; attempt++) {
    try {
      const client = buildClient(sdk, creds, endpoint, ctx.region);
      const params = new sdk.Params({
        action: spec.action,
        version: spec.version,
        protocol: "HTTPS",
        pathname: spec.pathname ?? "/",
        method: spec.method,
        authType: "AK",
        style: spec.style,
        reqBodyType: spec.style === "ROA" ? "json" : "formData",
        bodyType: "json",
      });
      const request = new sdk.OpenApiRequest({
        query: flattenAliQuery(query),
        ...(body !== undefined ? { body } : {}),
      });
      const runtime = new sdk.RuntimeOptions({
        autoretry: false,
        maxAttempts: 1,
        connectTimeout: ALI_CONNECT_TIMEOUT_MS,
        readTimeout: ALI_READ_TIMEOUT_MS,
      });
      const res = await client.callApi(params, request, runtime);
      return ((res && typeof res === "object" && "body" in res ? res.body : res) ?? {}) as T;
    } catch (err) {
      const info = classifyAliError(err);
      if (attempt < maxRetries && isAliRetryable(info)) {
        await sleep(Math.min(baseDelay * 2 ** attempt, ALI_RETRY_MAX_DELAY_MS));
        continue;
      }
      throw new AliCloudError(info, api);
    }
  }
}

/* ------------------------------------------------------------------------ */
/* Pagination                                                               */
/* ------------------------------------------------------------------------ */

/**
 * - `page`:   `PageNumber` / `PageSize`, terminated by `TotalCount` or a short page (ECS/RDS/SLB/VPC/SAS/CAS)
 * - `token`:  `NextToken` / `MaxResults` (Config, KMS, ResourceManager, ECS new-style; FC3 with overrides)
 * - `marker`: `Marker` / `MaxItems` + `IsTruncated` (RAM / IMS)
 */
export type AliPaginationStyle = "page" | "token" | "marker";

export const ALI_DEFAULT_PAGE_SIZE = 50;
export const ALI_DEFAULT_MAX_PAGES = 100;

export interface AliPaginateOptions<P, I> {
  style: AliPaginationStyle;
  /** Fetch one page; `pageQuery` holds the pagination parameters to merge into the request. */
  fetch(pageQuery: Record<string, string | number>): Promise<P>;
  /** Items of one page. */
  items(page: P): readonly I[] | undefined | null;
  pageSize?: number;
  /** Hard cap on requests (default {@link ALI_DEFAULT_MAX_PAGES}). */
  maxPages?: number;
  /** Stop once this many items were collected (result is marked truncated). */
  maxItems?: number;
  /** Label used in warnings, e.g. "ECS DescribeInstances". */
  label?: string;
  /** Request parameter names (defaults per style: PageNumber/PageSize, NextToken/MaxResults, Marker/MaxItems). */
  pageParam?: string;
  sizeParam?: string;
  tokenParam?: string;
  /** Response accessors (defaults: TotalCount, NextToken, Marker, IsTruncated). */
  totalCount?(page: P): number | undefined;
  nextToken?(page: P): string | undefined;
  isTruncated?(page: P): boolean | undefined;
}

export interface AliPageResult<I> {
  items: I[];
  pages: number;
  /** True when pagination stopped early (page cap, item cap or repeated token). */
  truncated: boolean;
  warnings: string[];
}

function field(page: unknown, name: string): unknown {
  return page && typeof page === "object" ? (page as Record<string, unknown>)[name] : undefined;
}

function asCount(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
  return undefined;
}

function asToken(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

function asBool(v: unknown): boolean | undefined {
  if (typeof v === "boolean") return v;
  if (v === "true") return true;
  if (v === "false") return false;
  return undefined;
}

/** Collect every item across pages, with a repeated-token guard and a page cap. */
export async function aliPaginate<P, I>(opts: AliPaginateOptions<P, I>): Promise<AliPageResult<I>> {
  const pageSize = opts.pageSize ?? ALI_DEFAULT_PAGE_SIZE;
  const maxPages = Math.max(1, opts.maxPages ?? ALI_DEFAULT_MAX_PAGES);
  const label = opts.label ?? "Alibaba Cloud pagination";
  const items: I[] = [];
  const warnings: string[] = [];
  const seenTokens = new Set<string>();
  let truncated = false;
  let pages = 0;
  let pageNumber = 1;
  let token: string | undefined;

  const sizeParam = opts.sizeParam ?? (opts.style === "page" ? "PageSize" : opts.style === "token" ? "MaxResults" : "MaxItems");
  const pageParam = opts.pageParam ?? "PageNumber";
  const tokenParam = opts.tokenParam ?? (opts.style === "token" ? "NextToken" : "Marker");

  for (;;) {
    if (pages >= maxPages) {
      truncated = true;
      warnings.push(`${label}: stopped after ${maxPages} pages (page cap reached); results may be incomplete`);
      break;
    }
    const q: Record<string, string | number> = { [sizeParam]: pageSize };
    if (opts.style === "page") q[pageParam] = pageNumber;
    else if (token) q[tokenParam] = token;

    const page = await opts.fetch(q);
    pages++;
    const batch = opts.items(page) ?? [];
    items.push(...batch);

    if (opts.maxItems !== undefined && items.length >= opts.maxItems) {
      if (items.length > opts.maxItems) items.length = opts.maxItems;
      truncated = true;
      warnings.push(`${label}: stopped at ${opts.maxItems} items (item cap reached); results may be incomplete`);
      break;
    }

    if (opts.style === "page") {
      const total = opts.totalCount ? opts.totalCount(page) : asCount(field(page, "TotalCount"));
      if (batch.length === 0) break;
      if (total !== undefined ? items.length >= total : batch.length < pageSize) break;
      pageNumber++;
      continue;
    }

    let next: string | undefined;
    if (opts.style === "token") {
      next = opts.nextToken ? opts.nextToken(page) : asToken(field(page, "NextToken"));
    } else {
      const more = opts.isTruncated ? opts.isTruncated(page) : asBool(field(page, "IsTruncated"));
      next = more ? (opts.nextToken ? opts.nextToken(page) : asToken(field(page, "Marker"))) : undefined;
    }
    if (!next) break;
    if (seenTokens.has(next) || next === token) {
      truncated = true;
      warnings.push(`${label}: pagination token repeated; stopped to avoid an infinite loop`);
      break;
    }
    seenTokens.add(next);
    token = next;
  }
  return { items, pages, truncated, warnings };
}

/* ------------------------------------------------------------------------ */
/* OSS (ali-oss)                                                            */
/* ------------------------------------------------------------------------ */

/**
 * Remove `ali-oss` namespaces from a DEBUG value (`ali-oss`, `ali-oss:*`, …); when a
 * remaining wildcard could still match (`*`, `ali*`), append the exclusion `-ali-oss*`.
 * Mutates `env` (defaults to process.env). The `debug` module reads DEBUG when it is first
 * loaded, so this must run BEFORE ali-oss is imported.
 */
export function stripAliOssDebug(env: NodeJS.ProcessEnv = process.env): void {
  const raw = env.DEBUG;
  if (!raw) return;
  const kept = raw.split(/[\s,]+/).filter((p) => p.length > 0 && !/^ali-oss/i.test(p));
  const wildcard = kept.some((p) => !p.startsWith("-") && p.includes("*"));
  if (wildcard && !kept.some((p) => /^-ali-oss/i.test(p))) kept.push("-ali-oss*");
  if (kept.length === 0) delete env.DEBUG;
  else env.DEBUG = kept.join(",");
}

export interface AliOssClientOptions {
  /** Endpoint override (tests / private endpoints). Defaults to `oss-<region>.aliyuncs.com` via ali-oss `region`. */
  endpoint?: string;
  /** Request timeout in ms (default 15000). */
  timeoutMs?: number;
  /** Bucket to bind the client to (bucket-level APIs). */
  bucket?: string;
}

export type AliOssClient = OSS;

/** Build an ali-oss client with explicit credentials (never ali-oss' own credential lookup). */
export async function aliOssClient(
  creds: AlibabaCloudCredentials,
  region: string,
  opts: AliOssClientOptions = {},
): Promise<AliOssClient> {
  stripAliOssDebug();
  const mod = await import("ali-oss");
  const Ctor = ((mod as { default?: unknown }).default ?? mod) as new (o: OSS.Options) => OSS;
  const options: OSS.Options = {
    region: region.startsWith("oss-") ? region : `oss-${region}`,
    accessKeyId: creds.accessKeyId,
    accessKeySecret: creds.accessKeySecret,
    ...(creds.securityToken ? { stsToken: creds.securityToken } : {}),
    ...(opts.endpoint ? { endpoint: opts.endpoint } : {}),
    ...(opts.bucket ? { bucket: opts.bucket } : {}),
    secure: true,
    timeout: opts.timeoutMs ?? ALI_READ_TIMEOUT_MS,
  };
  try {
    return new Ctor(options);
  } catch (err) {
    throw new AliCloudError({ ...classifyAliError(err), kind: "other" }, "oss:client");
  }
}

/* ------------------------------------------------------------------------ */
/* Regions                                                                  */
/* ------------------------------------------------------------------------ */

interface DescribeRegionsBody {
  Regions?: { Region?: Array<{ RegionId?: string; LocalName?: string; RegionEndpoint?: string }> };
}

/** ECS DescribeRegions on the global ECS endpoint → sorted region IDs. */
export async function listAliRegions(creds: AlibabaCloudCredentials, opts: { retry?: AliRetryOptions } = {}): Promise<string[]> {
  const body = await aliCall<DescribeRegionsBody>(
    ALI_API.ecs.DescribeRegions,
    { credentials: creds, endpoint: ALI_ECS_GLOBAL_ENDPOINT, retry: opts.retry },
    { AcceptLanguage: "en-US" },
  );
  const ids = new Set<string>();
  for (const r of body?.Regions?.Region ?? []) {
    if (typeof r?.RegionId === "string" && /^[a-z]{2}(?:-[a-z0-9]+)+$/.test(r.RegionId)) ids.add(r.RegionId);
  }
  return [...ids].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}
