/**
 * Classification helpers for Huawei Cloud SDK errors.
 *
 * The SDK throws either:
 *  - `ServiceResponseException` subclasses: `{ httpStatusCode, errorCode, errorMsg, requestId }`
 *  - or (from `DefaultHttpClient`) a raw `ExceptionResponse`:
 *    `{ status, data: { error_code, error_msg } | { error: { code, message } }, message, config, headers }`
 *
 * The raw shape carries the signed request config, including the
 * `Authorization` header (contains the AK). NEVER stringify an SDK error
 * wholesale — always go through {@link describeHwError}.
 */

export type HwErrorKind = "access_denied" | "not_enabled" | "not_found" | "other";

export interface HwErrorInfo {
  kind: HwErrorKind;
  status?: number;
  code?: string;
  message: string;
  requestId?: string;
}

const ACCESS_DENIED_CODE_PATTERNS = [
  /forbidden/i,
  /nopermission/i,
  /no_permission/i,
  /permissiondenied/i,
  /accessdenied/i,
  /unauthorized/i,
  /^IAM\.0002$/i,
  /^APIGW\.0301$/i,   // incorrect IAM authentication information (AK/SK rejected)
  /^APIGW\.0303$/i,   // no permission
  /^APIGW\.0308$/i,   // access denied by ACL
];

const ACCESS_DENIED_MSG_PATTERNS = [
  /forbidden/i,
  /no permission/i,
  /not authorized/i,
  /permission denied/i,
  /policy doesn't allow/i,
  /insufficient permission/i,
];

const NOT_ENABLED_CODE_PATTERNS = [
  /notopen/i,
  /not_open/i,
  /notsubscribe/i,
  /notenabled/i,
  /not_enabled/i,
  /serviceunavailable/i,
  /^APIGW\.0101$/i,   // API not found in this region / service not deployed
  /^APIGW\.0106$/i,
];

const NOT_ENABLED_MSG_PATTERNS = [
  /not (been )?(enabled|opened|subscribed|activated)/i,
  /service (is )?not (open|available)/i,
  /has not (opened|subscribed)/i,
  /未开通/,
  /尚未开通/,
];

function toNumber(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
  return undefined;
}

function pickString(...vals: unknown[]): string | undefined {
  for (const v of vals) if (typeof v === "string" && v.length > 0) return v;
  return undefined;
}

/** Extract status / code / message from any SDK error shape without touching headers or config. */
export function extractHwError(err: unknown): { status?: number; code?: string; message: string; requestId?: string } {
  if (err === null || err === undefined) return { message: "unknown error" };
  if (typeof err === "string") return { message: err };
  if (typeof err !== "object") return { message: String(err) };

  const e = err as Record<string, unknown>;
  const data = (e.data && typeof e.data === "object" ? e.data : {}) as Record<string, unknown>;
  const nested = (data.error && typeof data.error === "object" ? data.error : {}) as Record<string, unknown>;

  const status = toNumber(e.httpStatusCode) ?? toNumber(e.status) ?? toNumber(e.statusCode);
  const code = pickString(e.errorCode, e.error_code, nested.code, data.error_code, e.code, e.Code);
  const message =
    pickString(e.errorMsg, e.error_msg, nested.message, data.error_msg, e.message) ??
    (status !== undefined ? `HTTP ${status}` : "unknown error");
  const requestId = pickString(e.requestId, e.request_id);
  return { status, code, message, requestId };
}

export function classifyHwError(err: unknown): HwErrorInfo {
  const base = extractHwError(err);
  const { status, code = "", message } = base;

  let kind: HwErrorKind = "other";
  if (
    status === 401 ||
    status === 403 ||
    ACCESS_DENIED_CODE_PATTERNS.some((re) => re.test(code)) ||
    ACCESS_DENIED_MSG_PATTERNS.some((re) => re.test(message))
  ) {
    kind = "access_denied";
  } else if (
    status === 405 ||
    NOT_ENABLED_CODE_PATTERNS.some((re) => re.test(code)) ||
    NOT_ENABLED_MSG_PATTERNS.some((re) => re.test(message))
  ) {
    kind = "not_enabled";
  } else if (status === 404) {
    // 404 from a list/show endpoint usually means the service is not provisioned
    // in this region/account; scanners treat it as "not enabled" as well.
    kind = "not_found";
  }

  return { kind, ...base };
}

export function isHwAccessDenied(err: unknown): boolean {
  return classifyHwError(err).kind === "access_denied";
}

/** 404 / 405 / explicit "not opened" codes — service is not provisioned for this account/region. */
export function isHwNotEnabled(err: unknown): boolean {
  const k = classifyHwError(err).kind;
  return k === "not_enabled" || k === "not_found";
}

/**
 * Safe, single-line description of an SDK error for `warnings[]` / `error` fields.
 * Only status, error code, message and request ID are included; headers/config
 * (which can carry the signed Authorization header) are never touched.
 */
export function describeHwError(err: unknown): string {
  const { status, code, message, requestId } = extractHwError(err);
  const parts: string[] = [];
  if (status !== undefined) parts.push(`HTTP ${status}`);
  if (code) parts.push(code);
  parts.push(message);
  if (requestId) parts.push(`requestId=${requestId}`);
  return parts.join(" | ");
}

/**
 * Standard graceful-degradation warning text for a service call.
 * Returns undefined when the error is a genuine failure that should propagate.
 */
export function degradeHwError(service: string, err: unknown): string | undefined {
  const info = classifyHwError(err);
  switch (info.kind) {
    case "access_denied":
      return `${service}: insufficient permissions (${describeHwError(err)}); skipped`;
    case "not_enabled":
    case "not_found":
      return `${service}: service not enabled or not available in this region (${describeHwError(err)}); skipped`;
    default:
      return undefined;
  }
}
