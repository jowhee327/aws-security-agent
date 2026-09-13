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
