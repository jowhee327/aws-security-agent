/**
 * Classification + redaction helpers for Azure SDK errors (plan §3.5). EXPERIMENTAL:
 * error codes follow the Azure REST / Entra ID documentation and the 2026-10-26 fake
 * service-principal probe (plan §6.1); not yet validated against a live account.
 *
 * Error shapes handled:
 *  - `@azure/core-rest-pipeline` `RestError` (every ARM client):
 *    `{ name: "RestError", code, statusCode, request, response, details: { code, message } | { error: { code, message } } }`
 *  - `@azure/identity` `AuthenticationError` / `CredentialUnavailableError` /
 *    `AggregateAuthenticationError` / `AuthenticationRequiredError`:
 *    `{ name, statusCode, errorResponse: { error, errorDescription, errorCodes } }`, the message
 *    carrying `AADSTS<digits>: …`
 *  - `@microsoft/microsoft-graph-client` `GraphError`: `{ statusCode, code, message, requestId, body, headers }`
 *  - Node network errors (`ENOTFOUND`, `ECONNRESET`, …) and `AbortError` timeouts
 *  - {@link AzureCloudError} (the redacted wrapper this provider throws)
 *
 * [P0] The leak surface is the Bearer access token (a JWT in the `Authorization` request
 * header), not the client secret. `RestError.request` / `.response` hold the request and
 * response headers, so a RestError must NEVER be JSON.stringify'd, logged or kept as a
 * `cause`. {@link describeAzureError} reads only `statusCode | code | details.code |
 * message | x-ms-request-id` and every string passes through {@link redactAzureDiagnostic}.
 */

export type AzureErrorKind =
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

export const AZURE_REDACTED = "[REDACTED]";

/**
 * Runtime secret registry. `credentials.ts` registers every client secret it materialises
 * so {@link redactAzureDiagnostic} can remove the literal value from any text. Values live
 * only inside this closure. Tenant / client IDs are identifiers and are NOT registered
 * (redacting GUIDs would make diagnostics useless).
 */
const { registerAzureSecret, redactRegisteredAzureSecrets } = (() => {
  const secrets = new Set<string>();
  return {
    registerAzureSecret(value: string | undefined): void {
      if (typeof value !== "string") return;
      const v = value.trim();
      // Very short strings would redact ordinary text; real client secrets are ≥ 30 chars.
      if (v.length < 8) return;
      secrets.add(v);
    },
    redactRegisteredAzureSecrets(text: string): string {
      if (secrets.size === 0 || text.length === 0) return text;
      // Longest first so a value that embeds another registered value is handled as a whole.
      const ordered = [...secrets].sort((a, b) => b.length - a.length);
      let out = text;
      for (const s of ordered) {
        if (out.includes(s)) out = out.split(s).join(AZURE_REDACTED);
        // Secrets often travel URL-encoded (`client_secret=abc%7E…` in a token request body).
        const encoded = encodeURIComponent(s);
        if (encoded !== s && out.includes(encoded)) out = out.split(encoded).join(AZURE_REDACTED);
      }
      return out;
    },
  };
})();

export { registerAzureSecret };

/*
 * Every "rest of value" pattern below skips an already-redacted marker, so re-redacting
 * a line (describeAzureError → scanner → runner → MCP layer) is a no-op.
 */
const ALREADY = String.raw`(?!\[REDACTED\]|\*\*\*REDACTED\*\*\*)`;

/** (c) `Authorization: …` / `"authorization":"…"` / `Cookie:` headers → drop the rest of the line. */
const AUTH_HEADER_RE = new RegExp(
  String.raw`\b(Proxy-Authorization|Authorization|Set-Cookie|Cookie)\b(["']?\s*[:=]\s*)(?!\s*["']?\[REDACTED\])[^\r\n]*`,
  "gi",
);
/** (b) `Bearer <token>` anywhere (header value, WWW-Authenticate echo, message text). */
const BEARER_RE = new RegExp(String.raw`\bBearer\s+${ALREADY}[A-Za-z0-9._~+/=-]+`, "gi");
/** (b) Bare JWT (`eyJ…` header segment; access / id / client-assertion tokens). */
const JWT_RE = /(?<![A-Za-z0-9])eyJ[A-Za-z0-9._-]{20,}/g;
/**
 * (d) Generic credential `key=value` / `key: value` / `"key":"value"` pairs, case-insensitive.
 * Alnum lookbehind (not `\b`) so a prefixed env-var name such as `APP_CLIENT_SECRET=…` is
 * caught too. Bare `code` is deliberately NOT a key here: ARM / Graph error bodies are
 * `"code":"AuthorizationFailed"` and must stay readable; OAuth authorization codes are
 * handled in their query-parameter form by {@link QUERY_SECRET_RE}.
 */
const CREDENTIAL_KV_RE = new RegExp(
  String.raw`(?<![0-9A-Za-z])((?:azure[_-]?)?client[_-]?secret|client[_-]?assertion|assertion|password|passwd|access[_-]?token|refresh[_-]?token|id[_-]?token|auth(?:orization)?[_-]?code|code[_-]?verifier|account[_-]?key|shared[_-]?access[_-]?key|primary[_-]?key|secondary[_-]?key)(["']?\s*[:=]\s*["']?)${ALREADY}[^\s"',;&<\]}]+`,
  "gi",
);
/** (e) Secret-bearing URL query / form parameters (`?code=…`, `&client_secret=…`, `&assertion=…`). */
const QUERY_SECRET_RE = new RegExp(
  String.raw`([?&](?:code|client_secret|client_assertion|assertion|code_verifier|access_token|refresh_token|id_token|password|token)=)${ALREADY}[^&\s"'#<>]+`,
  "gi",
);
/** (f) SAS token components: signature `sig=` and version `sv=` (plan §3.5). */
const SAS_PARAM_RE = new RegExp(String.raw`(?<![0-9A-Za-z_-])((?:sig|sv)=)${ALREADY}[^&\s"'<>,;]+`, "gi");
/**
 * (f) Storage account keys (512-bit → 88 base64 chars ending `==`) and 256-bit shared
 * access keys (44 base64 chars ending `=`, the form named in plan §3.5).
 */
const STORAGE_KEY_RE = /(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{86}==|[A-Za-z0-9+/]{43}=)(?![A-Za-z0-9+/=])/g;

/**
 * Central redactor for any Azure-side diagnostic text (SDK error messages, scanner
 * warnings, MCP error results). Never throws; non-strings pass through as `String(text)`.
 *
 *  (a) client secret literals registered at runtime via {@link registerAzureSecret}
 *  (b) `Bearer <token>` and bare JWTs (`eyJ…`)
 *  (c) `Authorization:` / `Proxy-Authorization:` / `Cookie:` headers (header or JSON form)
 *  (d) credential key=value pairs (`client_secret`, `clientSecret`, `AZURE_CLIENT_SECRET`,
 *      `assertion`, `password`, `access_token`, `AccountKey`, …), case-insensitive
 *  (e) secret URL / form parameters (`?code=`, `&client_secret=`, `&client_assertion=`, …)
 *  (f) SAS `sig=` / `sv=` and base64 storage / shared access keys
 *
 * Idempotent. Tenant / client / subscription GUIDs, ARM resource IDs, AWS ARNs and
 * Huawei / Alibaba text are left untouched.
 */
export function redactAzureDiagnostic(text: string): string {
  if (typeof text !== "string") {
    try {
      return redactAzureDiagnostic(String(text));
    } catch {
      return AZURE_REDACTED;
    }
  }
  if (text.length === 0) return text;
  try {
    let out = redactRegisteredAzureSecrets(text); // (a)
    out = out.replace(AUTH_HEADER_RE, (_m, header: string, sep: string) => `${header}${sep}${AZURE_REDACTED}`); // (c)
    out = out.replace(BEARER_RE, `Bearer ${AZURE_REDACTED}`); // (b)
    out = out.replace(JWT_RE, AZURE_REDACTED); // (b)
    out = out.replace(QUERY_SECRET_RE, (_m, prefix: string) => `${prefix}${AZURE_REDACTED}`); // (e)
    out = out.replace(CREDENTIAL_KV_RE, (_m, key: string, sep: string) => `${key}${sep}${AZURE_REDACTED}`); // (d)
    out = out.replace(SAS_PARAM_RE, (_m, prefix: string) => `${prefix}${AZURE_REDACTED}`); // (f)
    out = out.replace(STORAGE_KEY_RE, AZURE_REDACTED); // (f)
    return out;
  } catch {
    // Regex failures are not expected; never leak the original text if one happens.
    return AZURE_REDACTED;
  }
}

/**
 * Server-sourced (untrusted) value → credential-redacted string ("" when absent). THE
 * wrapper for every Azure-sourced value (resource id / name, tag, description, status,
 * role name, …) emitted in a Finding field, a URN, a warning or a status / error message.
 * Ordinary IDs / names pass through unchanged. Keep raw values only for SDK parameters /
 * map keys.
 */
export function aztUntrusted(v: unknown): string {
  if (typeof v === "string") return redactAzureDiagnostic(v);
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  if (typeof v === "boolean") return String(v);
  return "";
}

/** Like {@link aztUntrusted}, but trimmed and `undefined` when absent / blank. */
export function aztUntrustedOpt(v: unknown): string | undefined {
  const s = aztUntrusted(v).trim();
  return s ? s : undefined;
}

/* ------------------------------------------------------------------------ */
/* Extraction                                                               */
/* ------------------------------------------------------------------------ */

export interface AzureErrorInfo {
  kind: AzureErrorKind;
  status?: number;
  /** Top-level code (`RestError.code` / Graph `code` / OAuth `error`), redacted. */
  code?: string;
  /** `details.code` / `details.error.code` when it differs from {@link code}. */
  detailsCode?: string;
  /** Entra ID error code (`AADSTS7000215`, …) from identity errors. */
  aadsts?: string;
  /** Redacted, single-line message (never the whole error object). */
  message: string;
  /** `x-ms-request-id` (or Graph `requestId`). */
  requestId?: string;
}

/**
 * Wrapped error thrown by this provider (`listAzureSubscriptions`, `azureCredential`, …).
 * Carries only the redacted classification — the raw SDK error (whose `request` /
 * `response` hold the Bearer token) is deliberately NOT kept as `cause`.
 */
export class AzureCloudError extends Error {
  readonly kind: AzureErrorKind;
  readonly statusCode?: number;
  readonly code?: string;
  readonly aadsts?: string;
  readonly requestId?: string;
  /** Operation that failed (e.g. `subscriptions.list`), when known. */
  readonly api?: string;
  /** @internal redacted extraction, reused by {@link extractAzureError}. */
  readonly info: AzureErrorInfo;

  constructor(info: AzureErrorInfo, api?: string) {
    const described = describeAzureInfo(info);
    super(
      info.kind === "auth_failed"
        ? azureAuthFailedText(info)
        : redactAzureDiagnostic(api ? `${api} failed: ${described}` : described),
    );
    this.name = "AzureCloudError";
    this.kind = info.kind;
    this.statusCode = info.status;
    this.code = info.code;
    this.aadsts = info.aadsts;
    this.requestId = info.requestId;
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

function asRecord(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" ? (v as Record<string, unknown>) : {};
}

/** Safe property read: getters on exotic SDK objects must not make extraction throw. */
function prop(obj: unknown, key: string): unknown {
  try {
    return obj && typeof obj === "object" ? (obj as Record<string, unknown>)[key] : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Read ONE named response header (`x-ms-request-id`) from a core-rest-pipeline
 * `HttpHeaders` (`.get()`) or a plain header object. No other header is ever touched.
 */
function readHeader(headers: unknown, name: string): string | undefined {
  if (!headers || typeof headers !== "object") return undefined;
  try {
    const get = (headers as { get?: unknown }).get;
    if (typeof get === "function") {
      const v = (get as (n: string) => unknown).call(headers, name);
      return typeof v === "string" ? v : undefined;
    }
    for (const [k, v] of Object.entries(headers as Record<string, unknown>)) {
      if (k.toLowerCase() === name && typeof v === "string") return v;
    }
  } catch {
    // ignore
  }
  return undefined;
}

/** Built-in JS error names that say nothing about the cloud-side failure. */
const GENERIC_ERROR_NAMES: ReadonlySet<string> = new Set([
  "Error",
  "TypeError",
  "RangeError",
  "SyntaxError",
  "ReferenceError",
  "AggregateError",
  "RestError",
  "GraphError",
]);

/** `@azure/identity` error classes: credential acquisition failed. */
const IDENTITY_ERROR_NAMES: ReadonlySet<string> = new Set([
  "AuthenticationError",
  "AggregateAuthenticationError",
  "CredentialUnavailableError",
  "AuthenticationRequiredError",
]);

const AADSTS_RE = /\bAADSTS(\d{4,})\b/;

/** Keep messages to one bounded line; drop identity's `Trace ID / Correlation ID / Timestamp` tail. */
function trimMessage(msg: string): string {
  const cut = msg.split(/\s+Trace ID:/)[0];
  const oneLine = cut.replace(/\s*[\r\n]+\s*/g, " ").trim();
  return oneLine.length > 500 ? `${oneLine.slice(0, 500)}…` : oneLine;
}

interface ExtractedAzureError extends Omit<AzureErrorInfo, "kind"> {
  /** Non-generic error class name (`AuthenticationError`, `AbortError`, …). */
  errorName?: string;
}

/**
 * Extract status / code / message / request ID from any Azure SDK error shape WITHOUT
 * serialising it and without touching request / response headers other than
 * `x-ms-request-id`. Every string passes through {@link redactAzureDiagnostic}.
 */
function extractInternal(err: unknown): ExtractedAzureError {
  if (err instanceof AzureCloudError) {
    const { kind: _kind, ...rest } = err.info;
    return rest;
  }
  if (err === null || err === undefined) return { message: "unknown error" };
  if (typeof err === "string") return { message: redactAzureDiagnostic(trimMessage(err)) };
  if (typeof err !== "object") return { message: redactAzureDiagnostic(String(err)) };

  const name = pickString(prop(err, "name"));
  const details = asRecord(prop(err, "details"));
  const detailsError = asRecord(details.error);
  const body = asRecord(prop(err, "body"));
  const bodyError = asRecord(body.error);
  const errorResponse = asRecord(prop(err, "errorResponse"));
  const response = prop(err, "response");
  const rawMessage = pickString(prop(err, "message"));

  const status =
    toNumber(prop(err, "statusCode")) ?? toNumber(prop(err, "status")) ?? toNumber(prop(response, "status"));
  const oauthError = pickString(errorResponse.error);
  const code = pickString(prop(err, "code"), detailsError.code, details.code, bodyError.code, oauthError);
  const innerCode = pickString(detailsError.code, details.code, bodyError.code);
  const detailsCode = innerCode && innerCode !== code ? innerCode : undefined;

  const errorCodes = prop(errorResponse, "errorCodes");
  const firstErrorCode = Array.isArray(errorCodes) ? toNumber(errorCodes[0]) : undefined;
  const aadstsMatch =
    AADSTS_RE.exec(rawMessage ?? "") ?? AADSTS_RE.exec(pickString(errorResponse.errorDescription) ?? "");
  const aadsts = aadstsMatch ? `AADSTS${aadstsMatch[1]}` : firstErrorCode !== undefined ? `AADSTS${firstErrorCode}` : undefined;

  const message =
    pickString(detailsError.message, details.message, bodyError.message, rawMessage, errorResponse.errorDescription) ??
    (status !== undefined ? `HTTP ${status}` : "unknown error");
  const requestId =
    readHeader(prop(response, "headers"), "x-ms-request-id") ??
    pickString(prop(err, "requestId"), readHeader(prop(err, "headers"), "request-id"));

  const redact = (v: string | undefined) => (v === undefined ? undefined : redactAzureDiagnostic(v));
  return {
    status,
    code: redact(code),
    detailsCode: redact(detailsCode),
    aadsts,
    message: redactAzureDiagnostic(trimMessage(message)),
    requestId: redact(requestId),
    errorName: name && !GENERIC_ERROR_NAMES.has(name) ? redactAzureDiagnostic(name) : undefined,
  };
}

/** Public extraction (no `kind`). */
export function extractAzureError(err: unknown): Omit<AzureErrorInfo, "kind"> {
  const { errorName: _n, ...rest } = extractInternal(err);
  return rest;
}

/* ------------------------------------------------------------------------ */
/* Classification                                                           */
/* ------------------------------------------------------------------------ */

/** Matched against lower-cased codes. Order matters: see {@link classifyAzureError}. */
const AUTH_FAILED_CODES: readonly RegExp[] = [
  /^invalidauthenticationtoken/, // ARM 401 InvalidAuthenticationToken / …Audience / …Tenant; Graph 401
  /^expiredauthenticationtoken/,
  /^authenticationfailed/,
  /^invalid_client$/, // OAuth: bad secret / unknown app
  /^unauthorized_client$/,
  /^invalid_grant$/,
  /^invalid_request$/, // OAuth token endpoint: malformed tenant / client
];

const API_MISUSE_CODES: readonly RegExp[] = [
  /^invalidapiversion/, // InvalidApiVersion / InvalidApiVersionParameter
  /^missingapiversionparameter$/,
  /^noregisteredproviderfound$/,
  /^invalidresourcetype$/,
  /^invalidresourcenamespace$/,
  /^unsupportedapiversion$/,
];

const THROTTLED_CODES: readonly RegExp[] = [/^toomanyrequests$/, /throttled$/, /^serverbusy$/];

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
  /^request_send_error$/,
  /^und_err_/,
];

const NETWORK_NAMES: ReadonlySet<string> = new Set(["AbortError", "TimeoutError", "FetchError"]);

const NETWORK_MSG_PATTERNS: readonly RegExp[] = [
  /\bENOTFOUND\b/,
  /\bEAI_AGAIN\b/,
  /\bECONNREFUSED\b/,
  /\bECONNRESET\b/,
  /\bETIMEDOUT\b/,
  /socket hang up/i,
  /operation was aborted/i,
];

/** Resource provider / feature not registered on the subscription (Defender, Policy Insights, …). */
const NOT_ENABLED_CODES: readonly RegExp[] = [
  /^missingsubscriptionregistration$/,
  /^subscriptionnotregistered/,
  /notregistered/, // ResourceProviderNotRegistered, FeatureNotRegistered, …
  /^featurenotenabled$/,
  /^subscriptionnotenabled$/,
];

const NOT_ENABLED_MSG_PATTERNS: readonly RegExp[] = [
  /is not registered to use namespace/i,
  /resource provider\b.*\bnot registered/i,
  /subscription is not registered/i,
];

const ACCESS_DENIED_CODES: readonly RegExp[] = [
  /^authorizationfailed$/, // ARM RBAC
  /^linkedauthorizationfailed$/,
  /^authorization_requestdenied$/, // Graph
  /^forbidden/,
  /^accessdenied/,
  /^insufficientaccountpermissions$/,
  /^authorizationpermissionmismatch$/,
];

const NOT_FOUND_CODES: readonly RegExp[] = [/notfound$/, /^request_resourcenotfound$/];

function matchesAny(patterns: readonly RegExp[], values: readonly string[]): boolean {
  return values.some((v) => v.length > 0 && patterns.some((re) => re.test(v)));
}

/**
 * Classify an Azure error. Precedence:
 *   auth_failed → api_misuse → throttled → network → not_enabled → access_denied → not_found → other.
 *
 * auth_failed: any `@azure/identity` error (AADSTS7000215 bad secret, 700016 app not found,
 * 90002 / 900023 tenant not found, 70001 app disabled, …), OAuth `invalid_client`, or HTTP 401
 * (`InvalidAuthenticationToken`). Codes are checked before statuses, so a 404
 * `MissingSubscriptionRegistration` is not_enabled, never not_found.
 */
export function classifyAzureError(err: unknown): AzureErrorInfo {
  if (err instanceof AzureCloudError) return { ...err.info };
  const { errorName, ...base } = extractInternal(err);
  const codes = [base.code, base.detailsCode].filter((c): c is string => !!c).map((c) => c.toLowerCase());
  const { status, message } = base;
  const isIdentity = (errorName !== undefined && IDENTITY_ERROR_NAMES.has(errorName)) || base.aadsts !== undefined;

  let kind: AzureErrorKind = "other";
  if (isIdentity || matchesAny(AUTH_FAILED_CODES, codes) || status === 401) {
    kind = "auth_failed";
  } else if (matchesAny(API_MISUSE_CODES, codes)) {
    kind = "api_misuse";
  } else if (matchesAny(THROTTLED_CODES, codes) || status === 429) {
    kind = "throttled";
  } else if (
    matchesAny(NETWORK_CODES, codes) ||
    (errorName !== undefined && NETWORK_NAMES.has(errorName)) ||
    (status === undefined && NETWORK_MSG_PATTERNS.some((re) => re.test(message))) ||
    (status === undefined && pickString(prop(err, "name")) === "RestError")
  ) {
    kind = "network";
  } else if (matchesAny(NOT_ENABLED_CODES, codes) || NOT_ENABLED_MSG_PATTERNS.some((re) => re.test(message))) {
    kind = "not_enabled";
  } else if (matchesAny(ACCESS_DENIED_CODES, codes) || status === 403) {
    kind = "access_denied";
  } else if (matchesAny(NOT_FOUND_CODES, codes) || status === 404) {
    kind = "not_found";
  }
  return { kind, ...base };
}

export function isAzureAuthFailure(err: unknown): boolean {
  return classifyAzureError(err).kind === "auth_failed";
}

export function isAzureApiMisuse(err: unknown): boolean {
  return classifyAzureError(err).kind === "api_misuse";
}

export function isAzureAccessDenied(err: unknown): boolean {
  return classifyAzureError(err).kind === "access_denied";
}

/** Transient failures worth retrying: throttling, network blips and 5xx (except 501). */
export function isAzureRetryable(info: AzureErrorInfo): boolean {
  if (info.kind === "throttled" || info.kind === "network") return true;
  if (info.kind !== "other") return false;
  return info.status !== undefined && info.status >= 500 && info.status !== 501;
}

/** Wrap any error into a redacted {@link AzureCloudError} (idempotent for wrapped errors). */
export function toAzureError(err: unknown, api?: string): AzureCloudError {
  if (err instanceof AzureCloudError) return err;
  return new AzureCloudError(classifyAzureError(err), api);
}

/* ------------------------------------------------------------------------ */
/* Description / degradation                                                */
/* ------------------------------------------------------------------------ */

function describeAzureInfo(info: Omit<AzureErrorInfo, "kind">): string {
  const parts: string[] = [];
  if (info.status !== undefined) parts.push(`HTTP ${info.status}`);
  if (info.code) parts.push(info.code);
  if (info.detailsCode) parts.push(info.detailsCode);
  if (info.aadsts && info.aadsts !== info.code && !info.message.includes(info.aadsts)) parts.push(info.aadsts);
  parts.push(info.message);
  if (info.requestId) parts.push(`requestId=${info.requestId}`);
  // Redact per part so an Authorization header inside the message does not swallow the request ID.
  return parts.map(redactAzureDiagnostic).join(" | ");
}

/**
 * Safe, single-line description for `warnings[]` / `error` fields:
 * `HTTP <status> | <code> | <details.code> | <message> | requestId=<x-ms-request-id>` —
 * nothing else from the error object is read (never JSON.stringify a RestError), and
 * every part is redacted.
 */
export function describeAzureError(err: unknown): string {
  return describeAzureInfo(extractAzureError(err));
}

export const AZURE_AUTH_FAILED_PREFIX = "Azure authentication failed";

function azureAuthFailedText(info: Omit<AzureErrorInfo, "kind">): string {
  const detail = [
    info.aadsts ?? info.code ?? (info.status !== undefined ? `HTTP ${info.status}` : "unknown"),
    info.requestId ? `requestId=${info.requestId}` : undefined,
  ]
    .filter(Boolean)
    .join(", ");
  return redactAzureDiagnostic(
    `${AZURE_AUTH_FAILED_PREFIX} (${detail}): check AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET and AZURE_CLOUD (china|global)`,
  );
}

/** `Azure authentication failed (<AADSTS code>, requestId=…)…` — the module `error` text for auth_failed. */
export function describeAzureAuthFailure(err: unknown): string {
  return azureAuthFailedText(extractAzureError(err));
}

/**
 * Standard graceful-degradation warning for a sub-service call. Returns undefined when
 * the error must propagate (auth_failed, api_misuse, other) — the scanner then reports
 * `status: "error"`; auth failures must never be downgraded to "not enabled".
 */
export function degradeAzureError(service: string, err: unknown): string | undefined {
  const info = classifyAzureError(err);
  const desc = describeAzureInfo(info);
  const svc = redactAzureDiagnostic(service);
  switch (info.kind) {
    case "access_denied":
      return redactAzureDiagnostic(`${svc}: insufficient permissions (${desc}); skipped`);
    case "not_enabled":
      return redactAzureDiagnostic(
        `${svc}: not enabled / resource provider not registered for this subscription (${desc}); skipped`,
      );
    case "not_found":
      return redactAzureDiagnostic(`${svc}: resource not found (${desc}); skipped`);
    case "throttled":
      return redactAzureDiagnostic(`${svc}: throttled after retries (${desc}); skipped`);
    case "network":
      return redactAzureDiagnostic(`${svc}: network error (${desc}); skipped`);
    default:
      return undefined;
  }
}

/**
 * Module-level error text for a failure that was NOT degraded:
 * auth failures get the canonical `Azure authentication failed …` prefix.
 */
export function azureModuleErrorText(err: unknown): string {
  const info = classifyAzureError(err);
  if (info.kind === "auth_failed") return azureAuthFailedText(info);
  if (err instanceof AzureCloudError) return err.message;
  return describeAzureInfo(info);
}
