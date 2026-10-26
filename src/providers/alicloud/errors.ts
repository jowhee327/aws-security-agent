/**
 * Classification + redaction helpers for Alibaba Cloud SDK errors (plan §3.6).
 *
 * Error shapes handled:
 *  - openapi-core `ClientError` / `ServerError` / `ThrottlingError`:
 *    `{ code, message, statusCode, requestId, description, data: { Code, Message, RequestId, Recommend, HostId },
 *       accessDeniedDetail?: { AuthAction, PolicyType, ... } }`
 *  - ali-oss errors: `{ name, message, status, code, requestId, ecCode, hostId }`
 *  - Node / tea network errors: `{ code: "ENOTFOUND" | "ECONNRESET" | ..., name: "RequestTimeoutError", message }`
 *  - {@link AliCloudError} (what `aliCall` throws after wrapping one of the above)
 *
 * [P0] A fake / revoked AK yields **HTTP 404 `InvalidAccessKeyId.NotFound`** on every RPC
 * gateway (plan §6.1). Classification therefore checks the error CODE first, so an
 * authentication failure is never mistaken for "resource not found / service not enabled".
 * Code comparison is case-insensitive (FC answers `InvalidAccessKeyID`, OSS `InvalidAccessKeyId`).
 *
 * NEVER JSON.stringify an SDK error: it can carry the request / response body, which
 * may echo the access key (OSS `<OSSAccessKeyId>`, RPC `server string to sign is: …`).
 * Always go through {@link describeAliError}.
 */

export type AliErrorKind =
  | "auth_failed"
  | "access_denied"
  | "not_enabled"
  | "not_found"
  | "throttled"
  | "network"
  | "api_misuse"
  | "other";

/* ------------------------------------------------------------------------ */
/* Diagnostic redaction                                                     */
/* ------------------------------------------------------------------------ */

export const ALI_REDACTED = "[REDACTED]";

/**
 * Runtime secret registry. `credentials.ts` registers every AK / SK / security token
 * it materialises so {@link redactAliDiagnostic} can remove the literal values from
 * any text. Values live only inside this closure; nothing here is exported or enumerable.
 */
const { registerAliSecret, redactRegisteredAliSecrets } = (() => {
  const secrets = new Set<string>();
  return {
    registerAliSecret(value: string | undefined): void {
      if (typeof value !== "string") return;
      const v = value.trim();
      // Very short strings would redact ordinary text; real AK/SK/tokens are ≥ 16 chars.
      if (v.length < 8) return;
      secrets.add(v);
    },
    redactRegisteredAliSecrets(text: string): string {
      if (secrets.size === 0 || text.length === 0) return text;
      // Longest first so a token that embeds another registered value is handled as a whole.
      const ordered = [...secrets].sort((a, b) => b.length - a.length);
      let out = text;
      for (const s of ordered) {
        if (out.includes(s)) out = out.split(s).join(ALI_REDACTED);
      }
      return out;
    },
  };
})();

export { registerAliSecret };

/** (b) Permanent AK (`LTAI` + 12–30 alnum). */
const LTAI_AK_RE = /\bLTAI[0-9A-Za-z]{12,30}\b/g;
/** (b) Half-masked AK as echoed by FC / gateways: `LTAI5t…0006`, `LTAI5t...0006`, `LTAI****0001`. */
const LTAI_MASKED_RE = /\bLTAI[0-9A-Za-z]{0,6}(?:…|\.{2,3}|\*{2,})[0-9A-Za-z]{0,8}/g;
/** (c) STS temporary AK. */
const STS_AK_RE = /\bSTS\.[0-9A-Za-z]{16,}/g;
/** (c) STS security token (base64-ish, starts with `CAIS`). */
const CAIS_TOKEN_RE = /\bCAIS[0-9A-Za-z+/=_-]{16,}/g;
/** (d) RPC V1 `SignatureDoesNotMatch` echo — the string to sign embeds the (URL-encoded) AK. */
const SERVER_STRING_TO_SIGN_RE = /server string to sign is\s*:?[^\r\n]*/gi;
/** (e) OSS XML elements that echo credential / signature material. */
const OSS_XML_ELEMENT_RE =
  /<(OSSAccessKeyId|AccessKeyId|SecurityToken|StringToSign|StringToSignBytes|SignatureProvided|CanonicalRequest)>[\s\S]*?<\/\1>/gi;
/** (d) `StringToSign: …` / `"StringToSign":"…"` / `CanonicalRequest=…` outside XML → drop the rest of the line. */
const STRING_TO_SIGN_KV_RE = /\b(StringToSign(?:Bytes)?|CanonicalRequest)\b["']?\s*[:=]\s*[^\r\n]*/gi;
/** (d) Query-string / URL-encoded components (`AccessKeyId=…`, `AccessKeyId%3D…`, `Signature=…`, `SignatureNonce=…`, `SecurityToken=…`). */
const SIGNED_QUERY_COMPONENT_RE =
  /\b(OSSAccessKeyId|AccessKeyId|Signature|SignatureNonce|SecurityToken|x-acs-security-token)(=|%3D|%253D)(?!\[REDACTED\])[^\s&%,"'<\]}]+/gi;
/** (f) `Authorization: …` header (header or JSON form) → drop the rest of the line. */
const AUTHORIZATION_HEADER_RE = /\bAuthorization\b["']?\s*[:=]\s*[^\r\n]*/gi;
/** (f) Bare V3 / OSS V4 signature blobs outside an Authorization header. */
const HMAC_BLOB_RE = /\b(ACS3-HMAC-SHA256|ACS3-HMAC-SM3|ACS3-RSA-SHA256|OSS4-HMAC-SHA256)\b(?! \[REDACTED\])[^\r\n]*/g;
/** (f) OSS V1 / legacy ACS signature: `OSS <ak>:<sig>` / `acs <ak>:<sig>`. */
const OSS_V1_AUTH_RE = /\b(OSS|acs)\s+(?!\[REDACTED\])[0-9A-Za-z.]{8,}:[0-9A-Za-z+/=]+/g;
/**
 * (g) Generic credential `key=value` / `key: value` / `"key":"value"` pairs
 * (accessKeySecret, access_key_secret, accessKeyId, securityToken, stsToken, the
 * Alibaba env var names, …). Case-insensitive.
 */
const CREDENTIAL_KV_RE =
  /\b(access[_-]?key[_-]?(?:id|secret)|secret[_-]?(?:access[_-]?)?key|access[_-]?secret|security[_-]?token|sts[_-]?token|session[_-]?token|alibaba_cloud_access_key_(?:id|secret)|alibaba_cloud_security_token|alicloud_(?:access_key|secret_key|security_token))\b["']?\s*[:=]\s*["']?(?!\[REDACTED\])([^\s"',;&<\]}]+)/gi;
/** Lines mentioning a secret: an exact 30-char alnum token after that word is treated as an AccessKey secret. */
const SECRET_LINE_TRIGGER_RE = /secret/i;
const THIRTY_CHAR_TOKEN_RE = /(?<![A-Za-z0-9+/=])[A-Za-z0-9]{30}(?![A-Za-z0-9+/=])/g;

/**
 * Central redactor for any Alibaba-side diagnostic text (SDK error messages, scanner
 * warnings, MCP error results). Never throws; non-strings pass through as `String(text)`.
 *
 *  (a) literal AK / SK / token values registered at runtime via {@link registerAliSecret}
 *  (b) `LTAI…` access keys, including the half-masked `LTAI5t…0006` form
 *  (c) `STS.…` temporary access keys and `CAIS…` security tokens
 *  (d) RPC signature echoes: `server string to sign is:…`, `StringToSign`, `Signature=`,
 *      `SignatureNonce=`, `AccessKeyId=` / `AccessKeyId%3D…` (URL-encoded)
 *  (e) OSS XML `<OSSAccessKeyId>` / `<StringToSign>` / `<SignatureProvided>` / `<StringToSignBytes>`
 *  (f) `Authorization:` headers, `ACS3-HMAC-SHA256 …` / `OSS4-HMAC-SHA256 …` blobs, `OSS <ak>:<sig>`
 *  (g) generic credential key=value pairs (`accessKeySecret`, `access_key_secret`, `securityToken`, …)
 *
 * Idempotent: redacting already-redacted text is a no-op (the same text may pass through
 * `describeAliError`, the scanner, the runner and the MCP layer). AWS ARNs, `acs:` URNs and
 * Huawei text are left untouched.
 */
export function redactAliDiagnostic(text: string): string {
  if (typeof text !== "string") return redactAliDiagnostic(String(text));
  if (text.length === 0) return text;
  try {
    let out = redactRegisteredAliSecrets(text); // (a)
    out = out.replace(OSS_XML_ELEMENT_RE, (_m, tag: string) => `<${tag}>${ALI_REDACTED}</${tag}>`); // (e)
    out = out.replace(SERVER_STRING_TO_SIGN_RE, `server string to sign is: ${ALI_REDACTED}`); // (d)
    out = out.replace(STRING_TO_SIGN_KV_RE, (_m, key: string) => `${key}=${ALI_REDACTED}`); // (d)
    out = out.replace(AUTHORIZATION_HEADER_RE, `Authorization=${ALI_REDACTED}`); // (f)
    out = out.replace(HMAC_BLOB_RE, (_m, algo: string) => `${algo} ${ALI_REDACTED}`); // (f)
    out = out.replace(OSS_V1_AUTH_RE, (_m, scheme: string) => `${scheme} ${ALI_REDACTED}`); // (f)
    out = out.replace(SIGNED_QUERY_COMPONENT_RE, (_m, key: string, sep: string) => `${key}${sep}${ALI_REDACTED}`); // (d)
    out = out.replace(CREDENTIAL_KV_RE, (_m, key: string) => `${key}=${ALI_REDACTED}`); // (g)
    out = out.replace(STS_AK_RE, ALI_REDACTED); // (c)
    out = out.replace(CAIS_TOKEN_RE, ALI_REDACTED); // (c)
    out = out.replace(LTAI_AK_RE, ALI_REDACTED); // (b)
    out = out.replace(LTAI_MASKED_RE, ALI_REDACTED); // (b)
    out = out
      .split(/(\r?\n)/)
      .map((segment) => {
        const trigger = SECRET_LINE_TRIGGER_RE.exec(segment);
        if (!trigger) return segment;
        const head = segment.slice(0, trigger.index);
        const tail = segment.slice(trigger.index).replace(THIRTY_CHAR_TOKEN_RE, ALI_REDACTED);
        return head + tail;
      })
      .join("");
    return out;
  } catch {
    // Regex failures are not expected; never leak the original text if one happens.
    return ALI_REDACTED;
  }
}

/* ------------------------------------------------------------------------ */
/* Extraction                                                               */
/* ------------------------------------------------------------------------ */

export interface AliErrorInfo {
  kind: AliErrorKind;
  status?: number;
  code?: string;
  /** Redacted, single-line-ish message (never the whole error object). */
  message: string;
  requestId?: string;
  /** RAM denial detail (only these two fields are kept). */
  authAction?: string;
  policyType?: string;
}

/**
 * Wrapped error thrown by `aliCall`. Carries only the redacted classification — the
 * raw SDK error (whose `data` / `stack` may echo credentials) is deliberately NOT kept
 * as `cause`.
 */
export class AliCloudError extends Error {
  readonly kind: AliErrorKind;
  readonly statusCode?: number;
  readonly code?: string;
  readonly requestId?: string;
  readonly authAction?: string;
  readonly policyType?: string;
  /** `<service>:<action>` that failed, when known. */
  readonly api?: string;
  /** @internal redacted extraction, reused by {@link extractAliError}. */
  readonly info: AliErrorInfo;

  constructor(info: AliErrorInfo, api?: string) {
    const described = describeAliInfo(info);
    super(
      info.kind === "auth_failed"
        ? aliAuthFailedText(info)
        : redactAliDiagnostic(api ? `${api} failed: ${described}` : described),
    );
    this.name = "AliCloudError";
    this.kind = info.kind;
    this.statusCode = info.status;
    this.code = info.code;
    this.requestId = info.requestId;
    this.authAction = info.authAction;
    this.policyType = info.policyType;
    this.api = api;
    this.info = { ...info };
  }
}

function toNumber(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
  return undefined;
}

function pickString(...vals: unknown[]): string | undefined {
  for (const v of vals) if (typeof v === "string" && v.trim().length > 0) return v.trim();
  return undefined;
}

/** Built-in JS error names that say nothing about the cloud-side failure. */
const GENERIC_ERROR_NAMES: ReadonlySet<string> = new Set(["Error", "TypeError", "RangeError", "SyntaxError", "ReferenceError", "AggregateError"]);

function asRecord(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" ? (v as Record<string, unknown>) : {};
}

/** Keep messages to one bounded line: SDK messages may append a full `Response: {...}` dump. */
function trimMessage(msg: string): string {
  const cut = msg.split(/\s+Response:\s*\{/)[0];
  const oneLine = cut.replace(/\s*[\r\n]+\s*/g, " ").trim();
  return oneLine.length > 500 ? `${oneLine.slice(0, 500)}…` : oneLine;
}

/**
 * Extract status / code / message / requestId from any SDK error shape without touching
 * request / response bodies or headers. Every string passes through {@link redactAliDiagnostic}.
 */
export function extractAliError(err: unknown): Omit<AliErrorInfo, "kind"> {
  if (err instanceof AliCloudError) {
    const { kind: _kind, ...rest } = err.info;
    return rest;
  }
  if (err === null || err === undefined) return { message: "unknown error" };
  if (typeof err === "string") return { message: redactAliDiagnostic(trimMessage(err)) };
  if (typeof err !== "object") return { message: redactAliDiagnostic(String(err)) };

  const e = err as Record<string, unknown>;
  const data = asRecord(e.data);
  const denied = asRecord(e.accessDeniedDetail ?? data.AccessDeniedDetail);

  const status = toNumber(e.statusCode) ?? toNumber(e.status) ?? toNumber(data.statusCode) ?? toNumber(data.HttpCode);
  // `name` is only a last resort (tea network errors such as `RequestTimeoutError` carry no code).
  const name = typeof e.name === "string" && !GENERIC_ERROR_NAMES.has(e.name) ? e.name : undefined;
  const code = pickString(data.Code, e.code, e.Code, name);
  const rawMessage =
    pickString(data.Message, e.description !== e.code ? e.description : undefined, e.message) ??
    (status !== undefined ? `HTTP ${status}` : "unknown error");
  const requestId = pickString(e.requestId, data.RequestId, e.RequestId);
  const authAction = pickString(denied.AuthAction);
  const policyType = pickString(denied.PolicyType);

  const redact = (v: string | undefined) => (v === undefined ? undefined : redactAliDiagnostic(v));
  return {
    status,
    code: redact(code),
    message: redactAliDiagnostic(trimMessage(rawMessage)),
    requestId: redact(requestId),
    authAction: redact(authAction),
    policyType: redact(policyType),
  };
}

/* ------------------------------------------------------------------------ */
/* Classification                                                           */
/* ------------------------------------------------------------------------ */

/** Matched against the lower-cased code. Order matters: see {@link classifyAliError}. */
const AUTH_FAILED_CODES: readonly RegExp[] = [
  /^invalidaccesskeyid/, // InvalidAccessKeyId, .NotFound (HTTP 404!), .Inactive; FC InvalidAccessKeyID; OSS 403
  /^signaturedoesnotmatch/,
  /^incompletesignature/,
  /^invalidsecuritytoken/, // InvalidSecurityToken.Expired / .Malformed / .MismatchWithAccessKey
  /^securitytokenexpired/,
  /^securitytoken\.expired/,
  /^invalidststoken/,
  /^forbidden\.accesskeydisabled/, // disabled AK (must win over the generic Forbidden → access_denied)
];

const API_MISUSE_CODES: readonly RegExp[] = [
  /^invalidaction/, // InvalidAction.NotFound
  /^invalidapi\.notfound/, // ROA equivalent
  /^invalidversion/,
  /^unsupportedhttpmethod/,
  /^missingparameter/,
  /^invalidparameter/,
];

const THROTTLED_CODES: readonly RegExp[] = [/^throttling/, /^serviceunavailable/, /^flowlimit/, /^request\.throttle/];

const NETWORK_CODES: readonly RegExp[] = [
  /^enotfound$/,
  /^eai_again$/,
  /^econnrefused$/,
  /^econnreset$/,
  /^econnaborted$/,
  /^etimedout$/,
  /^esockettimedout$/,
  /^ehostunreach$/,
  /^enetunreach$/,
  /^epipe$/,
  /^requesttimeouterror$/,
  /^connecttimeout/,
  /^readtimeout/,
];

const NETWORK_MSG_PATTERNS: readonly RegExp[] = [
  /\bENOTFOUND\b/,
  /\bEAI_AGAIN\b/,
  /\bECONNREFUSED\b/,
  /\bECONNRESET\b/,
  /\bETIMEDOUT\b/,
  /\bConnectTimeout\b/i,
  /\bReadTimeout\b/i,
  /socket hang up/i,
];

/** Not-enabled codes (several are "to be confirmed on a live account", plan §3.6). */
const NOT_ENABLED_CODES: readonly RegExp[] = [
  /^forbidden\.kmsservicenotenabled/,
  /^waf\.instance\.notexist/,
  /^instancenotexist$/,
  /^configurationrecordernotexists/,
  /^accountnotexisted/,
  /servicenotopen/,
  /servicenotenabled/,
  /notopen(ed)?$/,
  /notactivated/,
  /notpurchased/,
  /unpurchased/,
];

const NOT_ENABLED_MSG_PATTERNS: readonly RegExp[] = [
  /\bnot (been )?(enabled|opened|activated|purchased|subscribed)\b/i,
  /service (is )?not (open|available)\b/i,
  /未开通/,
  /尚未开通/,
  /未购买/,
];

const ACCESS_DENIED_CODES: readonly RegExp[] = [
  /^forbidden/, // Forbidden, Forbidden.RAM, Forbidden.AccessDenied, Forbidden.NoPermission, Forbidden.Unauthorized
  /^nopermission/,
  /^accessdenied/, // OSS AccessDenied
  /^notauthorized/,
  /^unauthorized/,
];

const NOT_FOUND_CODES: readonly RegExp[] = [/\.notfound$/, /notfound$/, /^nosuch/, /^invalidregionid/, /notexist(s|ed)?$/];

function matchesAny(patterns: readonly RegExp[], value: string): boolean {
  return value.length > 0 && patterns.some((re) => re.test(value));
}

/**
 * Classify an Alibaba Cloud error. Precedence (codes compared lower-cased):
 *   auth_failed → api_misuse → throttled → network → not_enabled → access_denied → not_found → other.
 * HTTP status is only a fallback AFTER the code checks: 404 `InvalidAccessKeyId.NotFound`
 * is `auth_failed`, never `not_found`.
 */
export function classifyAliError(err: unknown): AliErrorInfo {
  if (err instanceof AliCloudError) return { ...err.info };
  const base = extractAliError(err);
  const code = (base.code ?? "").toLowerCase();
  const { status, message } = base;

  let kind: AliErrorKind = "other";
  if (matchesAny(AUTH_FAILED_CODES, code)) {
    kind = "auth_failed";
  } else if (matchesAny(API_MISUSE_CODES, code)) {
    kind = "api_misuse";
  } else if (matchesAny(THROTTLED_CODES, code) || status === 429 || status === 503) {
    kind = "throttled";
  } else if (matchesAny(NETWORK_CODES, code) || (status === undefined && NETWORK_MSG_PATTERNS.some((re) => re.test(message)))) {
    kind = "network";
  } else if (matchesAny(NOT_ENABLED_CODES, code) || NOT_ENABLED_MSG_PATTERNS.some((re) => re.test(message))) {
    kind = "not_enabled";
  } else if (matchesAny(ACCESS_DENIED_CODES, code) || status === 401 || status === 403) {
    kind = "access_denied";
  } else if (matchesAny(NOT_FOUND_CODES, code) || status === 404) {
    kind = "not_found";
  }
  return { kind, ...base };
}

export function isAliAuthFailure(err: unknown): boolean {
  return classifyAliError(err).kind === "auth_failed";
}

export function isAliApiMisuse(err: unknown): boolean {
  return classifyAliError(err).kind === "api_misuse";
}

export function isAliAccessDenied(err: unknown): boolean {
  return classifyAliError(err).kind === "access_denied";
}

/** Transient failures `aliCall` retries: throttling, network blips and 5xx (except 501 Not Implemented). */
export function isAliRetryable(info: AliErrorInfo): boolean {
  if (info.kind === "throttled" || info.kind === "network") return true;
  if (info.kind !== "other") return false;
  return info.status !== undefined && info.status >= 500 && info.status !== 501;
}

/* ------------------------------------------------------------------------ */
/* Description / degradation                                                */
/* ------------------------------------------------------------------------ */

function describeAliInfo(info: Omit<AliErrorInfo, "kind">): string {
  const parts: string[] = [];
  if (info.status !== undefined) parts.push(`HTTP ${info.status}`);
  if (info.code) parts.push(info.code);
  parts.push(info.message);
  if (info.requestId) parts.push(`requestId=${info.requestId}`);
  // Redact per part so an Authorization header inside the message does not swallow the request ID.
  return parts.map(redactAliDiagnostic).join(" | ");
}

/**
 * Safe, single-line description for `warnings[]` / `error` fields:
 * `HTTP <status> | <code> | <message> | requestId=<id>` — nothing else from the error
 * object is read, and every part is redacted.
 */
export function describeAliError(err: unknown): string {
  return describeAliInfo(extractAliError(err));
}

export const ALI_AUTH_FAILED_PREFIX = "Alibaba Cloud authentication failed";

function aliAuthFailedText(info: Omit<AliErrorInfo, "kind">): string {
  const detail = [info.code ?? (info.status !== undefined ? `HTTP ${info.status}` : "unknown"), info.requestId ? `requestId=${info.requestId}` : undefined]
    .filter(Boolean)
    .join(", ");
  return redactAliDiagnostic(`${ALI_AUTH_FAILED_PREFIX} (${detail}): check the AccessKey ID / secret / STS token`);
}

/** `Alibaba Cloud authentication failed (<code>, requestId=…)…` — the module `error` text for auth_failed. */
export function describeAliAuthFailure(err: unknown): string {
  return aliAuthFailedText(extractAliError(err));
}

/**
 * Standard graceful-degradation warning for a sub-service call. Returns undefined when
 * the error must propagate (auth_failed, api_misuse, other) — the scanner then reports
 * `status: "error"`; auth failures must never be downgraded to "not enabled".
 */
export function degradeAliError(service: string, err: unknown): string | undefined {
  const info = classifyAliError(err);
  const desc = describeAliInfo(info);
  switch (info.kind) {
    case "access_denied": {
      const missing = info.authAction ? `; missing permission ${info.authAction}${info.policyType ? ` (${info.policyType})` : ""}` : "";
      return redactAliDiagnostic(`${service}: insufficient permissions (${desc})${missing}; skipped`);
    }
    case "not_enabled":
      return redactAliDiagnostic(`${service}: service not enabled or not purchased for this account (${desc}); skipped`);
    case "not_found":
      return redactAliDiagnostic(`${service}: not available in this region / resource not found (${desc}); skipped`);
    case "throttled":
      return redactAliDiagnostic(`${service}: throttled after retries (${desc}); skipped`);
    case "network":
      return redactAliDiagnostic(`${service}: network error (${desc}); skipped`);
    default:
      return undefined;
  }
}

/**
 * Module-level error text for a failure that was NOT degraded:
 * auth failures get the canonical `Alibaba Cloud authentication failed …` prefix.
 */
export function aliModuleErrorText(err: unknown): string {
  const info = classifyAliError(err);
  if (info.kind === "auth_failed") return aliAuthFailedText(info);
  if (err instanceof AliCloudError) return err.message;
  return describeAliInfo(info);
}
