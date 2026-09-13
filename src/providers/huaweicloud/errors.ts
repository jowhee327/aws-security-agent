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

/* ------------------------------------------------------------------------ */
/* Diagnostic redaction                                                     */
/* ------------------------------------------------------------------------ */

export const HW_REDACTED = "[REDACTED]";

/**
 * Runtime secret registry. `credentials.ts` registers every AK / SK / security
 * token it materialises so {@link redactHwDiagnostic} can also remove the
 * literal values from any text (e.g. an SDK / proxy error that echoes them).
 * Values live only inside this closure; nothing here is exported or enumerable.
 */
const { registerHwSecret, redactRegisteredSecrets } = (() => {
  const secrets = new Set<string>();
  return {
    registerHwSecret(value: string | undefined): void {
      if (typeof value !== "string") return;
      const v = value.trim();
      // Very short strings would redact ordinary text; real AK/SK/tokens are ≥ 8 chars.
      if (v.length < 8) return;
      secrets.add(v);
    },
    redactRegisteredSecrets(text: string): string {
      if (secrets.size === 0 || text.length === 0) return text;
      // Longest first so a token that embeds another registered value is handled as a whole.
      const ordered = [...secrets].sort((a, b) => b.length - a.length);
      let out = text;
      for (const s of ordered) {
        if (out.includes(s)) out = out.split(s).join(HW_REDACTED);
      }
      return out;
    },
  };
})();

export { registerHwSecret };

/** `Authorization: SDK-HMAC-SHA256 Access=..., SignedHeaders=..., Signature=...` (header or JSON form) → drop the rest of the line. */
const AUTHORIZATION_HEADER_RE = /\bAuthorization\b["']?\s*[:=]\s*[^\r\n]*/gi;
/** A bare signature blob (`SDK-HMAC-SHA256 Access=..., ...`) outside an Authorization header. */
const SDK_HMAC_BLOB_RE = /\bSDK-HMAC-SHA256\b[^\r\n]*/gi;
/** Individual signature components. */
const SIGNATURE_COMPONENT_RE = /\b(Access|SignedHeaders|Signature)=(?!\[REDACTED\])[^\s,"'\]\}]+/g; // SignedHeaders uses ';' as separator
/**
 * `key=value` / `key: value` / `"key":"value"` for credential-like keys
 * (ak, sk, access_key, secret_key, access_key_id, secret_access_key,
 * security_token, X-Security-Token, X-Auth-Token, camelCase variants).
 */
const CREDENTIAL_KV_RE =
  /\b(ak|sk|access[_-]?key(?:[_-]?id)?|secret[_-]?(?:access[_-]?)?key|accesskey(?:id)?|secretkey|secretaccesskey|security[_-]?token|securitytoken|x-security-token|x-auth-token|session[_-]?token)\b["']?\s*[:=]\s*["']?(?!\[REDACTED\])([^\s"',;&\]\}]+)/gi;
/** Lines mentioning sk / secret: any exact 40-char base64/alnum token after that word is treated as a secret key. */
const SK_LINE_TRIGGER_RE = /\b(sk|secret)/i;
const FORTY_CHAR_TOKEN_RE = /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{40}(?![A-Za-z0-9+/=])/g;

/**
 * Central redactor for any Huawei-side diagnostic text (SDK error messages,
 * scanner warnings, MCP error results). Never throws; non-strings pass through
 * as `String(text)`.
 *
 *  (a) `Authorization` header values → `Authorization=[REDACTED]`
 *  (b) `SDK-HMAC-SHA256 …` signature blobs, `Access=…`, `SignedHeaders=…`, `Signature=…`
 *  (c) `ak` / `sk` / `access_key` / `secret_key` / `X-Security-Token`-style key=value pairs
 *  (d) any 40-char base64/alnum token that follows `sk` / `secret` on the same line
 *  (e) literal AK / SK / token values registered at runtime via {@link registerHwSecret}
 *
 * Idempotent: redacting already-redacted text is a no-op (the same text may
 * pass through `extractHwError`, `describeHwError` and the runner / MCP layer).
 */
export function redactHwDiagnostic(text: string): string {
  if (typeof text !== "string") return redactHwDiagnostic(String(text));
  if (text.length === 0) return text;
  let out = redactRegisteredSecrets(text);
  out = out.replace(AUTHORIZATION_HEADER_RE, `Authorization=${HW_REDACTED}`);
  out = out.replace(SDK_HMAC_BLOB_RE, `SDK-HMAC-SHA256 ${HW_REDACTED}`);
  out = out.replace(SIGNATURE_COMPONENT_RE, `$1=${HW_REDACTED}`);
  out = out.replace(CREDENTIAL_KV_RE, (_m, key: string) => `${key}=${HW_REDACTED}`);
  out = out
    .split(/(\r?\n)/)
    .map((segment) => {
      const trigger = SK_LINE_TRIGGER_RE.exec(segment);
      if (!trigger) return segment;
      const head = segment.slice(0, trigger.index);
      const tail = segment.slice(trigger.index).replace(FORTY_CHAR_TOKEN_RE, HW_REDACTED);
      return head + tail;
    })
    .join("");
  return out;
}

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

/**
 * Extract status / code / message from any SDK error shape without touching
 * headers or config. The message (and code) pass through {@link redactHwDiagnostic}
 * because SDK / proxy / service errors may echo the signed request.
 */
export function extractHwError(err: unknown): { status?: number; code?: string; message: string; requestId?: string } {
  if (err === null || err === undefined) return { message: "unknown error" };
  if (typeof err === "string") return { message: redactHwDiagnostic(err) };
  if (typeof err !== "object") return { message: redactHwDiagnostic(String(err)) };

  const e = err as Record<string, unknown>;
  const data = (e.data && typeof e.data === "object" ? e.data : {}) as Record<string, unknown>;
  const nested = (data.error && typeof data.error === "object" ? data.error : {}) as Record<string, unknown>;

  const status = toNumber(e.httpStatusCode) ?? toNumber(e.status) ?? toNumber(e.statusCode);
  const code = pickString(e.errorCode, e.error_code, nested.code, data.error_code, e.code, e.Code);
  const message = redactHwDiagnostic(
    pickString(e.errorMsg, e.error_msg, nested.message, data.error_msg, e.message) ??
      (status !== undefined ? `HTTP ${status}` : "unknown error"),
  );
  const requestId = pickString(e.requestId, e.request_id);
  return { status, code: code === undefined ? undefined : redactHwDiagnostic(code), message, requestId };
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
 * (which can carry the signed Authorization header) are never touched, and the
 * whole line is passed through {@link redactHwDiagnostic}.
 */
export function describeHwError(err: unknown): string {
  const { status, code, message, requestId } = extractHwError(err);
  const parts: string[] = [];
  if (status !== undefined) parts.push(`HTTP ${status}`);
  if (code) parts.push(code);
  parts.push(message);
  if (requestId) parts.push(`requestId=${requestId}`);
  // Redact per part so an Authorization header inside the message does not swallow the request ID.
  return parts.map(redactHwDiagnostic).join(" | ");
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
