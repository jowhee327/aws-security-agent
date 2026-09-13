/**
 * Helpers shared by Huawei Cloud scanners: resolve credentials / domain ID
 * from a ScanContext without ever logging secret material.
 */
import type { HuaweiCloudCredentials, ScanContext, ScanResult } from "../../../types.js";
import { isHuaweiCloudCredentials } from "../../../types.js";
import { loadHuaweiCredentials, resolveRegionScope } from "../credentials.js";

/**
 * Credentials for a Huawei scanner call.
 * Uses the credentials carried on the context (runner / cross-account) when
 * they are Huawei credentials; otherwise falls back to the credential chain
 * (explicit → env → ~/.huaweicloud/credentials). `type` picks the INI section.
 */
export function hwCredentialsFromContext(ctx: ScanContext, type: "basic" | "global"): HuaweiCloudCredentials {
  if (isHuaweiCloudCredentials(ctx.credentials)) return ctx.credentials;
  const set = loadHuaweiCredentials();
  return type === "global" ? set.global : set.basic;
}

/**
 * Account domain ID for global-service calls. Order: `ctx.domainId` →
 * credential `domainId` → `ctx.accountId` (Huawei contexts store the domain ID
 * there) → IAM project resolution (cached, one network call per credential).
 */
export async function hwDomainIdFromContext(ctx: ScanContext, creds: HuaweiCloudCredentials): Promise<string> {
  const direct = ctx.domainId ?? creds.domainId ?? (ctx.provider === "huaweicloud" ? ctx.accountId : undefined);
  if (direct) return direct;
  const scope = await resolveRegionScope(creds, ctx.region);
  if (!scope.domainId) {
    throw new Error(`Huawei Cloud domain ID could not be resolved for region "${ctx.region}"`);
  }
  return scope.domainId;
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
 * Region scope (projectId + domainId) for regional-service calls. Order:
 * `ctx.projectId`/`ctx.domainId` → credential fields → IAM project resolution
 * (cached). `domainId` may still be undefined when nothing resolves it; callers
 * that need it for URNs should fall back to `ctx.accountId`.
 */
export async function hwRegionScopeFromContext(
  ctx: ScanContext,
  creds: HuaweiCloudCredentials,
): Promise<{ region: string; projectId: string; domainId: string }> {
  const projectId = ctx.projectId ?? creds.projectId;
  const domainId = ctx.domainId ?? creds.domainId ?? (ctx.provider === "huaweicloud" && ctx.accountId ? ctx.accountId : undefined);
  if (projectId && domainId) return { region: ctx.region, projectId, domainId };
  const scope = await resolveRegionScope(creds, ctx.region);
  const resolvedProject = projectId ?? scope.projectId;
  if (!resolvedProject) {
    throw new Error(`Huawei Cloud project ID could not be resolved for region "${ctx.region}"`);
  }
  return { region: ctx.region, projectId: resolvedProject, domainId: domainId ?? scope.domainId ?? ctx.accountId ?? "" };
}

/**
 * Parse a Huawei Cloud timestamp into epoch milliseconds. Accepts:
 *  - `"YYYY-MM-DD HH:mm:ss"` / `"YYYY-MM-DD HH:mm:ss.S"` (SCM `expire_time`; no zone → UTC)
 *  - ISO-8601 with or without zone (ELB `expire_time`, ECS `updated`)
 *  - epoch seconds / milliseconds (number or digit string)
 * Returns undefined when the value cannot be parsed. Never throws.
 */
export function parseHwTimestamp(value: unknown): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || value <= 0) return undefined;
    return value < 1e12 ? value * 1000 : value;
  }
  if (typeof value !== "string") return undefined;
  const s = value.trim();
  if (!s) return undefined;
  if (/^\d+$/.test(s)) return parseHwTimestamp(Number(s));
  // "2026-10-01 12:00:00.0" / "2026-10-01T12:00:00" → no zone designator: treat as UTC.
  const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,3})\d*)?$/.exec(s);
  if (m) {
    const iso = `${m[1]}T${m[2]}${m[3] ? `.${m[3].padEnd(3, "0")}` : ""}Z`;
    const t = Date.parse(iso);
    return Number.isNaN(t) ? undefined : t;
  }
  const t = Date.parse(s);
  return Number.isNaN(t) ? undefined : t;
}

/** Whole days from `nowMs` until `targetMs` (negative when in the past); mirrors the AWS scanners' Math.floor. */
export function daysUntil(targetMs: number, nowMs: number = Date.now()): number {
  return Math.floor((targetMs - nowMs) / (24 * 60 * 60 * 1000));
}

/**
 * Guard for `marker` / `next_marker` pagination loops: a server that keeps
 * returning the same (or an already seen) marker would otherwise spin until
 * the page cap. `accept(marker)` returns false when the marker was seen
 * before; callers then break with {@link repeatedMarkerWarning}.
 */
export class MarkerGuard {
  private readonly seen = new Set<string>();

  accept(marker: string | number | undefined): boolean {
    if (marker === undefined || marker === null || marker === "") return false;
    const key = String(marker);
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    return true;
  }
}

/** Standard warning when a list API repeats a pagination marker. */
export function repeatedMarkerWarning(service: string, what: string): string {
  return `${service}: pagination of ${what} stopped early because the API repeated a page marker; results may be incomplete.`;
}
