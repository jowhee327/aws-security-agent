/**
 * Huawei Cloud SDK client factory + endpoint table (plan Appendix A).
 *
 * [P0] The SDK core configures a global log4js logger at load time (level debug,
 * stdout appender) and logs HTTP failures INCLUDING the signed `Authorization`
 * header (which embeds the AK). This MCP server speaks JSON-RPC over stdio, so
 * any such output both corrupts the protocol stream and leaks the access key.
 *
 * Mitigation: {@link silenceSdkLogging} configures log4js with every category
 * at level "off". It is applied (a) when this module loads, (b) immediately
 * after each SDK module is (lazily) imported — the core's own load-time
 * `configure()` would otherwise win — and (c) before every client construction,
 * because `esdk-obs-nodejs` can call `log4js.configure()` again.
 *
 * SDK modules are imported lazily so the default AWS code path never loads them.
 */
import log4js from "log4js";
import type { HuaweiCloudCredentials } from "../../types.js";
import type { RegionScope } from "../types.js";

/* ------------------------------------------------------------------------ */
/* log4js silencing                                                         */
/* ------------------------------------------------------------------------ */

export const SILENT_LOG4JS_CONFIG = {
  appenders: { hwSdkSilent: { type: "stdout" } },
  categories: { default: { appenders: ["hwSdkSilent"], level: "off" } },
} as const;

/** Turn off all log4js output (idempotent; safe to call repeatedly). */
export function silenceSdkLogging(): void {
  try {
    log4js.configure(SILENT_LOG4JS_CONFIG as unknown as Parameters<typeof log4js.configure>[0]);
  } catch {
    // log4js should never throw here; if it does, there is nothing better to do
    // than continue — the caller must not crash because of logging plumbing.
  }
}

// (a) provider entry: silence at load.
silenceSdkLogging();

/* ------------------------------------------------------------------------ */
/* Endpoint table                                                           */
/* ------------------------------------------------------------------------ */

export type HwService =
  | "iam"
  | "sts"
  | "rms"
  | "organizations"
  | "eps"
  | "dns"
  | "cts"
  | "obs"
  | "ecs"
  | "evs"
  | "eip"
  | "vpc"
  | "rds"
  | "elb"
  | "scm"
  | "functiongraph"
  | "cbr"
  | "ces"
  | "waf"
  | "hss"
  | "secmaster";

export const HW_ENDPOINT_DOMAIN = "myhuaweicloud.com";

/** Global services: `https://<host>.myhuaweicloud.com` (no region segment). */
const GLOBAL_SERVICE_HOSTS: Readonly<Partial<Record<HwService, string>>> = {
  iam: "iam",
  rms: "rms",
  organizations: "organizations",
  eps: "eps",
  dns: "dns",
};

/** Regional services whose hostname differs from the service key. */
const REGIONAL_HOST_ALIASES: Readonly<Partial<Record<HwService, string>>> = {
  eip: "vpc", // EIP API is served from the VPC endpoint
};

/** Services authenticated with GlobalCredentials (domainId) rather than BasicCredentials (projectId). */
const GLOBAL_CREDENTIAL_SERVICES: ReadonlySet<HwService> = new Set<HwService>([
  "iam",
  "sts", // regional endpoint, but authenticates with GlobalCredentials(domainId)
  "rms",
  "organizations",
  "eps",
]);

export function isGlobalService(svc: HwService): boolean {
  return svc in GLOBAL_SERVICE_HOSTS;
}

export type HwCredentialType = "basic" | "global";

export function defaultCredentialType(svc: HwService): HwCredentialType {
  return GLOBAL_CREDENTIAL_SERVICES.has(svc) ? "global" : "basic";
}

/**
 * Endpoint URL for a service. Regional services require `region`.
 * NOTE: STS's global endpoint times out; it is always regional (plan §6.1).
 */
export function hwEndpoint(svc: HwService, region?: string): string {
  const globalHost = GLOBAL_SERVICE_HOSTS[svc];
  if (globalHost) return `https://${globalHost}.${HW_ENDPOINT_DOMAIN}`;
  if (!region) throw new Error(`Huawei Cloud service "${svc}" is regional; region is required`);
  const host = REGIONAL_HOST_ALIASES[svc] ?? svc;
  return `https://${host}.${region}.${HW_ENDPOINT_DOMAIN}`;
}

/* ------------------------------------------------------------------------ */
/* Client factory                                                           */
/* ------------------------------------------------------------------------ */

/** Structural type of the SDK's ClientBuilder (avoids importing the core at type level in scanners). */
export interface HwClientBuilder<T> {
  withCredential(credential?: unknown): HwClientBuilder<T>;
  withEndpoint(endpoint: string | string[]): HwClientBuilder<T>;
  build(): T;
}

export interface HwClientClass<T> {
  newBuilder(): HwClientBuilder<T>;
}

export interface HwClientOptions {
  /** Override the credential type implied by the service. */
  credentialType?: HwCredentialType;
  /** Override the endpoint (tests / private endpoints). */
  endpoint?: string;
}

type SdkCore = typeof import("@huaweicloud/huaweicloud-sdk-core");

let corePromise: Promise<SdkCore> | undefined;

/** Lazily import the SDK core and immediately re-silence log4js (core configures it at load). */
export async function loadSdkCore(): Promise<SdkCore> {
  if (!corePromise) {
    corePromise = import("@huaweicloud/huaweicloud-sdk-core").then((mod) => {
      // (b) core's load-time configure() ran during import; override it now.
      silenceSdkLogging();
      return mod;
    });
  }
  return corePromise;
}

/**
 * Build an SDK credential object for `scope`.
 * - basic  → BasicCredentials(ak, sk, projectId)
 * - global → GlobalCredentials(ak, sk, domainId)
 */
export async function buildSdkCredential(
  creds: HuaweiCloudCredentials,
  scope: Pick<RegionScope, "region" | "projectId" | "domainId"> | Record<string, never>,
  type: HwCredentialType,
): Promise<unknown> {
  const core = await loadSdkCore();
  const projectId = (scope as RegionScope).projectId ?? creds.projectId;
  const domainId = (scope as RegionScope).domainId ?? creds.domainId;
  const region = (scope as RegionScope).region;

  if (type === "global") {
    const c = new core.GlobalCredentials().withAk(creds.ak).withSk(creds.sk);
    if (creds.securityToken) c.withSecurityToken(creds.securityToken);
    if (domainId) c.withDomainId(domainId);
    return c;
  }
  const c = new core.BasicCredentials().withAk(creds.ak).withSk(creds.sk);
  if (creds.securityToken) c.withSecurityToken(creds.securityToken);
  if (projectId) c.withProjectId(projectId);
  if (region) c.withRegionId(region);
  return c;
}

/**
 * Generic client factory: `hwClient(EcsClient, "ecs", creds, scope)`.
 *
 * `ClientClass` must be imported by the caller — use deep paths for packages
 * with broken root exports (iam v3, eip v2, eps v1, tms v1; elb v3 for
 * listLoadBalancers; secmaster v1) — see plan §6.1.
 */
export async function hwClient<T>(
  ClientClass: HwClientClass<T>,
  svc: HwService,
  creds: HuaweiCloudCredentials,
  scope: Pick<RegionScope, "region" | "projectId" | "domainId"> | Record<string, never> = {},
  opts: HwClientOptions = {},
): Promise<T> {
  const type = opts.credentialType ?? defaultCredentialType(svc);
  const credential = await buildSdkCredential(creds, scope, type);
  const endpoint = opts.endpoint ?? hwEndpoint(svc, (scope as RegionScope).region);
  // (c) belt-and-braces: another SDK module may have re-configured log4js meanwhile.
  silenceSdkLogging();
  return ClientClass.newBuilder().withCredential(credential).withEndpoint(endpoint).build();
}

/* ------------------------------------------------------------------------ */
/* OBS (esdk-obs-nodejs) — not a ClientBuilder client                        */
/* ------------------------------------------------------------------------ */

export interface HwObsClientOptions {
  /** Override the server (tests / private endpoints). Defaults to `obs.<region>.myhuaweicloud.com`. */
  server?: string;
  timeoutSeconds?: number;
  maxRetryCount?: number;
}

/**
 * Build an OBS client. `esdk-obs-nodejs` takes ak/sk directly and may call
 * `log4js.configure()` (with `replaceConsole: true`) if `initLog` is invoked —
 * we never call `initLog`, and re-silence after construction regardless.
 */
export type ObsClientInstance = import("esdk-obs-nodejs").default;

export async function hwObsClient(
  creds: HuaweiCloudCredentials,
  region: string,
  opts: HwObsClientOptions = {},
): Promise<ObsClientInstance> {
  const mod = await import("esdk-obs-nodejs");
  // CJS module: ESM default import yields the constructor itself.
  const ObsClient = ((mod as { default?: unknown }).default ?? mod) as new (
    p: import("esdk-obs-nodejs").ObsClientParams,
  ) => ObsClientInstance;
  silenceSdkLogging();
  const server = opts.server ?? hwEndpoint("obs", region).replace(/^https:\/\//, "");
  const client = new ObsClient({
    access_key_id: creds.ak,
    secret_access_key: creds.sk,
    security_token: creds.securityToken,
    server,
    is_secure: true,
    timeout: opts.timeoutSeconds ?? 30,
    max_retry_count: opts.maxRetryCount ?? 1,
  });
  silenceSdkLogging();
  return client;
}
