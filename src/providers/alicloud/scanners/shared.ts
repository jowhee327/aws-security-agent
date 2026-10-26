/**
 * Helpers shared by Alibaba Cloud scanners (EXPERIMENTAL — not yet validated against a
 * live account): credentials / call context from a ScanContext, result skeletons and the
 * canonical error result. Nothing here logs or serialises secret material.
 */
import type { AlibabaCloudCredentials, ScanContext, ScanResult } from "../../../types.js";
import { ALI_API } from "../api-catalog.js";
import { aliCall, aliPaginate, resolveAliSite, type AliCallContext, type AliSite } from "../client.js";
import { aliCredentialsFromContext } from "../credentials.js";
import { aliModuleErrorText, classifyAliError } from "../errors.js";

/** Credentials + site + account UID resolved once per scan. */
export interface AliScanEnv {
  credentials: AlibabaCloudCredentials;
  site: AliSite;
  /** Account UID for URNs (`ctx.accountId`; "unknown" when the runner could not resolve it). */
  accountId: string;
}

/**
 * Resolve the scan environment: the context's Alibaba credentials (runner / cross-account)
 * or the credential chain (env → INI file); site from `ALIBABA_CLOUD_SITE`.
 * Throws `AlibabaCloudCredentialsNotFoundError` when no credentials are available.
 */
export function aliScanEnv(ctx: ScanContext): AliScanEnv {
  return {
    credentials: aliCredentialsFromContext(ctx),
    site: resolveAliSite(),
    accountId: ctx.accountId && ctx.accountId.trim() ? ctx.accountId : "unknown",
  };
}

/** aliCall context for a centralised (site-dependent) or regional service. */
export function aliCallCtx(env: AliScanEnv, region?: string): AliCallContext {
  return { credentials: env.credentials, site: env.site, ...(region ? { region } : {}) };
}

/** Empty (detection-style) ScanResult skeleton. */
export function emptyScanResult(
  module: string,
  startMs: number,
  extra: Partial<Pick<ScanResult, "status" | "error" | "warnings">> = {},
): ScanResult {
  return {
    module,
    status: extra.status ?? "success",
    ...(extra.error !== undefined ? { error: extra.error } : {}),
    ...(extra.warnings && extra.warnings.length > 0 ? { warnings: extra.warnings } : {}),
    resourcesScanned: 0,
    findingsCount: 0,
    scanTimeMs: Date.now() - startMs,
    findings: [],
  };
}

/**
 * Module `error` text for a failure that is not degraded. Authentication failures keep the
 * canonical `Alibaba Cloud authentication failed …` prefix (never wrapped / downgraded);
 * everything else is prefixed with `context`. Always redacted (describeAliError path).
 */
export function aliScanErrorText(context: string, err: unknown): string {
  const text = aliModuleErrorText(err);
  return classifyAliError(err).kind === "auth_failed" ? text : `${context}: ${text}`;
}

/** `status: "error"` ScanResult for a failure that must surface (auth_failed / api_misuse / other). */
export function aliErrorResult(module: string, startMs: number, context: string, err: unknown, warnings: string[] = []): ScanResult {
  return emptyScanResult(module, startMs, { status: "error", error: aliScanErrorText(context, err), warnings });
}

/** Errors a sub-call must never swallow: our bug (api_misuse) or bad credentials (auth_failed). */
export function isAliFatal(err: unknown): boolean {
  const kind = classifyAliError(err).kind;
  return kind === "auth_failed" || kind === "api_misuse";
}

/** Read a field from a loosely typed response object. */
export function aliField(obj: unknown, key: string): unknown {
  return obj && typeof obj === "object" ? (obj as Record<string, unknown>)[key] : undefined;
}

/** Number from a number or digit-string field. */
export function aliNumber(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^-?\d+(\.\d+)?$/.test(v.trim())) return Number(v);
  return undefined;
}

/** Non-empty trimmed string, else undefined. */
export function aliString(v: unknown): string | undefined {
  if (typeof v === "string" && v.trim()) return v.trim();
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return undefined;
}

/** Array from an array, a single value, or nothing (RPC lists are `{ Items: { Item: [...] } }`). */
export function aliArray<T = unknown>(v: unknown): T[] {
  if (Array.isArray(v)) return v as T[];
  return v === undefined || v === null ? [] : [v as T];
}

/* ------------------------------------------------------------------------ */
/* ECS DescribeInstances (shared by secret_exposure / imdsv2_enforcement)   */
/* ------------------------------------------------------------------------ */

/** DescribeInstances page size (ECS maximum 100) and listing cap. */
export const ECS_PAGE_SIZE = 100;
export const ECS_MAX_INSTANCES = 1000;

export interface AliEcsInstanceList {
  /** Raw `Instances.Instance[]` entries (loosely typed). */
  instances: Record<string, unknown>[];
  warnings: string[];
}

/**
 * List the ECS instances of `region` (PageNumber / PageSize, `TotalCount`), capped at
 * {@link ECS_MAX_INSTANCES}. `extra` is merged into every request (e.g. `Status`).
 * Throws the (redacted) AliCloudError from aliCall.
 */
export async function listAliEcsInstances(
  env: AliScanEnv,
  region: string,
  extra: Record<string, unknown> = {},
  maxItems: number = ECS_MAX_INSTANCES,
): Promise<AliEcsInstanceList> {
  const page = await aliPaginate<unknown, Record<string, unknown>>({
    style: "page",
    label: "ECS DescribeInstances",
    pageSize: ECS_PAGE_SIZE,
    maxItems,
    fetch: (q) => aliCall(ALI_API.ecs.DescribeInstances, aliCallCtx(env, region), { RegionId: region, ...extra, ...q }),
    items: (body) =>
      aliArray<Record<string, unknown>>(aliField(aliField(body, "Instances"), "Instance")).filter((i) => i && typeof i === "object"),
    totalCount: (body) => aliNumber(aliField(body, "TotalCount")),
  });
  return { instances: page.items, warnings: page.warnings };
}
