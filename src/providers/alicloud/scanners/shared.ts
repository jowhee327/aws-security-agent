/**
 * Helpers shared by Alibaba Cloud scanners (EXPERIMENTAL — not yet validated against a
 * live account): credentials / call context from a ScanContext, result skeletons and the
 * canonical error result. Nothing here logs or serialises secret material.
 */
import type { AlibabaCloudCredentials, ScanContext, ScanResult } from "../../../types.js";
import { resolveAliSite, type AliCallContext, type AliSite } from "../client.js";
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
