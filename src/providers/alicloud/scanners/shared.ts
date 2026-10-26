/**
 * Helpers shared by Alibaba Cloud scanners (EXPERIMENTAL — not yet validated against a
 * live account): credentials / call context from a ScanContext, result skeletons and the
 * canonical error result. Nothing here logs or serialises secret material.
 */
import type { AlibabaCloudCredentials, ScanContext, ScanResult } from "../../../types.js";
import { ALI_API, type AliApiSpec } from "../api-catalog.js";
import { aliCall, aliPaginate, resolveAliSite, type AliCallContext, type AliSite } from "../client.js";
import { aliCredentialsFromContext } from "../credentials.js";
import { AliCloudError, aliModuleErrorText, classifyAliError, degradeAliError, describeAliError, redactAliDiagnostic } from "../errors.js";

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

/**
 * Server-sourced (untrusted) value → trimmed, credential-redacted string; undefined when
 * absent. Ordinary IDs / names pass through unchanged (only credential-looking patterns are
 * rewritten). Use for EVERY cloud-sourced value (id, name, tag, description) emitted in a
 * Finding or warning.
 */
export function aliUntrusted(v: unknown): string | undefined {
  const s = aliString(v);
  return s === undefined ? undefined : redactAliDiagnostic(s);
}

/** Re-wrap any error (ali-oss / SDK / other) as a redacted AliCloudError — never keep the raw object. */
export function toAliError(err: unknown, api: string): AliCloudError {
  return err instanceof AliCloudError ? err : new AliCloudError(classifyAliError(err), api);
}

/** Warning for a non-fatal sub-service failure (degradeAliError, or a generic redacted line). */
export function aliSoftWarning(service: string, err: unknown): string {
  return degradeAliError(service, err) ?? redactAliDiagnostic(`${service}: failed (${describeAliError(err)}); skipped`);
}

/* ------------------------------------------------------------------------ */
/* Generic PageNumber / PageSize listing                                    */
/* ------------------------------------------------------------------------ */

export interface AliPagedListOptions {
  /** Warning label, e.g. "ECS DescribeDisks". */
  label: string;
  /** Response list container + item key: `{ Disks: { Disk: [...] } }` → ["Disks", "Disk"]. */
  listKey: string;
  itemKey: string;
  pageSize: number;
  maxItems: number;
  /** Merged into every request (e.g. `Status`). */
  extra?: Record<string, unknown>;
  /** Total-count field (default `TotalCount`; RDS uses `TotalRecordCount`). */
  totalKey?: string;
}

/**
 * List a regional RPC collection with PageNumber / PageSize pagination (`RegionId` = region).
 * Throws the (redacted) AliCloudError from aliCall.
 */
export async function listAliPaged(
  spec: AliApiSpec,
  env: AliScanEnv,
  region: string,
  opts: AliPagedListOptions,
): Promise<{ items: Record<string, unknown>[]; warnings: string[] }> {
  const page = await aliPaginate<unknown, Record<string, unknown>>({
    style: "page",
    label: opts.label,
    pageSize: opts.pageSize,
    maxItems: opts.maxItems,
    fetch: (q) => aliCall(spec, aliCallCtx(env, region), { RegionId: region, ...(opts.extra ?? {}), ...q }),
    items: (body) =>
      aliArray<Record<string, unknown>>(aliField(aliField(body, opts.listKey), opts.itemKey)).filter((i) => i && typeof i === "object"),
    totalCount: (body) => aliNumber(aliField(body, opts.totalKey ?? "TotalCount")),
  });
  return { items: page.items, warnings: page.warnings };
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
