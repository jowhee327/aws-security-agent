/**
 * Helpers shared by Azure scanners (EXPERIMENTAL — not yet validated against a live
 * account): credentials + subscription scope from a ScanContext, result skeletons, the
 * canonical error result and the defence-in-depth redaction passes. Nothing here logs or
 * serialises secret material; a raw SDK error (whose `request` / `response` hold the
 * Bearer token) is only ever read through the T1 describe / classify helpers.
 */
import type { AzureCloud, AzureCredentials, Finding, ScanContext, ScanResult } from "../../../types.js";
import { azureCredentialFromContext } from "../credentials.js";
import {
  aztUntrusted,
  aztUntrustedOpt,
  azureModuleErrorText,
  classifyAzureError,
  degradeAzureError,
  describeAzureError,
  redactAzureDiagnostic,
} from "../errors.js";
import { AZURE_NO_SUBSCRIPTION } from "../subscriptions.js";

/** Credentials + subscription scope resolved once per scanner run. */
export interface AzureScanEnv {
  credentials: AzureCredentials;
  /** Subscription of this scope (`ctx.subscriptionId`); the raw value is used for SDK calls only. */
  subscriptionId: string;
  /** Tenant ID (`ctx.tenantId`, else the credentials' tenant) — the Finding `accountId`. */
  tenantId: string;
  cloud: AzureCloud;
}

/** Warning emitted when a subscription-scoped module runs without a subscription in scope. */
export function azureNoSubscriptionWarning(module: string): string {
  return `${module}: no Azure subscription in scope (subscription enumeration failed or returned nothing); set AZURE_SUBSCRIPTION_ID or pass a subscription ID as region. Skipped.`;
}

/** Subscription of the scan context (`undefined` for the no-subscription placeholder scope). */
export function azureSubscriptionFromContext(ctx: ScanContext): string | undefined {
  const sub = ctx.subscriptionId?.trim();
  if (sub && sub !== AZURE_NO_SUBSCRIPTION) return sub;
  return undefined;
}

/**
 * Resolve the scan environment. Returns `undefined` when there is no subscription in scope
 * (callers report {@link azureNoSubscriptionWarning}); throws the credential-chain error
 * (`AzureCredentialsNotFoundError`, which lists env var NAMES only) when no credentials exist.
 */
export function azureScanEnv(ctx: ScanContext): AzureScanEnv | undefined {
  const subscriptionId = azureSubscriptionFromContext(ctx);
  if (!subscriptionId) return undefined;
  const credentials = azureCredentialFromContext(ctx);
  const tenantId = ctx.tenantId?.trim() || credentials.tenantId;
  return { credentials, subscriptionId, tenantId, cloud: ctx.cloud ?? credentials.cloud };
}

/** Empty (detection-style) ScanResult skeleton; error / warnings are redacted. */
export function azureEmptyResult(
  module: string,
  startMs: number,
  extra: Partial<Pick<ScanResult, "status" | "error" | "warnings">> = {},
): ScanResult {
  return {
    module,
    status: extra.status ?? "success",
    ...(extra.error !== undefined ? { error: redactAzureDiagnostic(extra.error) } : {}),
    ...(extra.warnings && extra.warnings.length > 0 ? { warnings: azureSafeWarnings(extra.warnings) } : {}),
    resourcesScanned: 0,
    findingsCount: 0,
    scanTimeMs: Date.now() - startMs,
    findings: [],
  };
}

/**
 * Module `error` text for a failure that is not degraded. Authentication failures keep the
 * canonical `Azure authentication failed …` prefix (never wrapped / downgraded); everything
 * else is prefixed with `context`. Always redacted.
 */
export function azureScanErrorText(context: string, err: unknown): string {
  const text = azureModuleErrorText(err);
  return classifyAzureError(err).kind === "auth_failed" ? text : redactAzureDiagnostic(`${context}: ${text}`);
}

/** `status: "error"` ScanResult for a failure that must surface (auth_failed / api_misuse / other). */
export function azureErrorResult(module: string, startMs: number, context: string, err: unknown, warnings: string[] = []): ScanResult {
  return azureEmptyResult(module, startMs, { status: "error", error: azureScanErrorText(context, err), warnings });
}

/** Errors a sub-call must never swallow: our bug (api_misuse) or bad credentials (auth_failed). */
export function isAzureFatal(err: unknown): boolean {
  const kind = classifyAzureError(err).kind;
  return kind === "auth_failed" || kind === "api_misuse";
}

/** Warning for a non-fatal sub-service failure (degradeAzureError, or a generic redacted line). */
export function azureSoftWarning(service: string, err: unknown): string {
  return degradeAzureError(service, err) ?? redactAzureDiagnostic(`${service}: failed (${describeAzureError(err)}); skipped`);
}

/** Read a field from a loosely typed SDK object (getters must not make a scanner throw). */
export function azField(obj: unknown, key: string): unknown {
  try {
    return obj && typeof obj === "object" ? (obj as Record<string, unknown>)[key] : undefined;
  } catch {
    return undefined;
  }
}

/** Non-empty trimmed RAW string (map keys / SDK parameters / comparisons only — never emitted). */
export function azString(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

/** Finite number from a number or digit-string field. */
export function azNumber(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^-?\d+(\.\d+)?$/.test(v.trim())) return Number(v);
  return undefined;
}

export function azArray<T = unknown>(v: unknown): T[] {
  return Array.isArray(v) ? (v as T[]) : [];
}

/** Last path segment of an ARM ID (`/…/policyDefinitions/<name>` → `<name>`); raw. */
export function azLastSegment(id: string | undefined): string | undefined {
  if (!id) return undefined;
  const parts = id.split("/").filter((p) => p.length > 0);
  return parts.length > 0 ? parts[parts.length - 1] : undefined;
}

/** Re-exported from errors.ts (the single untrusted-string wrappers). */
export { aztUntrusted, aztUntrustedOpt };

/**
 * Defence in depth for every emitted Finding: all free-text / identifier fields pass through
 * {@link redactAzureDiagnostic} (idempotent; ordinary text is unchanged). Scanners still wrap
 * each server-sourced value with {@link aztUntrusted} at the point of extraction.
 */
export function azureSafeFinding(f: Finding): Finding {
  return {
    ...f,
    title: redactAzureDiagnostic(f.title),
    resourceType: redactAzureDiagnostic(f.resourceType),
    resourceId: redactAzureDiagnostic(f.resourceId),
    resourceArn: redactAzureDiagnostic(f.resourceArn),
    region: redactAzureDiagnostic(f.region),
    description: redactAzureDiagnostic(f.description),
    impact: redactAzureDiagnostic(f.impact),
    remediationSteps: f.remediationSteps.map(redactAzureDiagnostic),
    ...(f.source !== undefined ? { source: redactAzureDiagnostic(f.source) } : {}),
  };
}

/** Defence in depth for warnings[]: every line redacted (idempotent). */
export function azureSafeWarnings(warnings: readonly string[]): string[] {
  return warnings.map(redactAzureDiagnostic);
}

/** Truncation warning for a capped listing. */
export function azureTruncationWarning(label: string, max: number): string {
  return `${label}: more than ${max} items; results were truncated to the first ${max}.`;
}
