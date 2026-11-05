/**
 * Alibaba Cloud credential loading (plan §3.2).
 *
 * SECURITY: AK/SK/token values must never be logged, serialized or embedded in error
 * messages. Credential objects produced here keep `accessKeyId` / `accessKeySecret` /
 * `securityToken` as NON-ENUMERABLE properties and redact them in `toJSON()` and
 * `util.inspect()`, so accidental `console.log(creds)` / `JSON.stringify(creds)` /
 * `{ ...creds }` never reveal secrets. Every value is registered with
 * {@link registerAliSecret} so the diagnostic redactor strips it from any text.
 *
 * Resolution chain:
 *   1. explicit credentials passed by the caller (ScanContext.credentials / tool parameters)
 *   2. environment: ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET
 *      (+ ALIBABA_CLOUD_SECURITY_TOKEN); legacy Terraform names ALICLOUD_ACCESS_KEY /
 *      ALICLOUD_SECRET_KEY (+ ALICLOUD_SECURITY_TOKEN) only when the new names are absent
 *   3. INI file ALIBABA_CLOUD_CREDENTIALS_FILE or `~/.alibabacloud/credentials`,
 *      profile ALIBABA_CLOUD_PROFILE (default "default"); `type = access_key | sts`.
 *
 * `@alicloud/credentials`' default chain is deliberately NOT used: it also reads
 * `~/.aliyun/config.json` and probes the ECS IMDS (100.100.100.200).
 */
import { createHash } from "crypto";
import { existsSync, readFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { inspect } from "util";
import type { AlibabaCloudCredentials, ScanContext } from "../../types.js";
import { isAlibabaCloudCredentials } from "../../types.js";
import { ALI_API } from "./api-catalog.js";
import { aliCall, type AliRetryOptions } from "./client.js";
import { registerAliSecret } from "./errors.js";

export const ALI_ENV_ACCESS_KEY_ID = "ALIBABA_CLOUD_ACCESS_KEY_ID";
export const ALI_ENV_ACCESS_KEY_SECRET = "ALIBABA_CLOUD_ACCESS_KEY_SECRET";
export const ALI_ENV_SECURITY_TOKEN = "ALIBABA_CLOUD_SECURITY_TOKEN";
export const ALI_ENV_LEGACY_ACCESS_KEY = "ALICLOUD_ACCESS_KEY";
export const ALI_ENV_LEGACY_SECRET_KEY = "ALICLOUD_SECRET_KEY";
export const ALI_ENV_LEGACY_SECURITY_TOKEN = "ALICLOUD_SECURITY_TOKEN";
export const ALI_CREDENTIALS_FILE_ENV = "ALIBABA_CLOUD_CREDENTIALS_FILE";
export const ALI_PROFILE_ENV = "ALIBABA_CLOUD_PROFILE";
export const ALI_DEFAULT_PROFILE = "default";

export const REDACTED = "***REDACTED***";

export type AlibabaCloudCredentialSource = "explicit" | "env" | "file";

export interface AlibabaCloudCredentialInput {
  accessKeyId?: string;
  accessKeySecret?: string;
  securityToken?: string;
  source?: AlibabaCloudCredentialSource;
}

/** Credential types accepted in the INI file this phase. */
export const ALI_SUPPORTED_CREDENTIAL_TYPES: ReadonlySet<string> = new Set(["access_key", "sts"]);

/** Generic credential configuration error (never contains secret values). */
export class AlibabaCloudCredentialsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AlibabaCloudCredentialsError";
  }
}

/** No source yielded credentials. Lists only the source NAMES that were checked. */
export class AlibabaCloudCredentialsNotFoundError extends Error {
  readonly sources: readonly string[];
  constructor(sources: readonly string[]) {
    super(
      `Alibaba Cloud credentials not found. Checked: ${sources.join("; ")}. ` +
        `Set ${ALI_ENV_ACCESS_KEY_ID}/${ALI_ENV_ACCESS_KEY_SECRET} or create an INI credentials file ` +
        "(type = access_key | sts).",
    );
    this.name = "AlibabaCloudCredentialsNotFoundError";
    this.sources = [...sources];
  }
}

/* ------------------------------------------------------------------------ */
/* Credential objects                                                       */
/* ------------------------------------------------------------------------ */

/** `LTAI****0001` (first 4 + last 4) — safe for debugging / test assertions only. */
function maskAccessKeyId(ak: string): string {
  if (ak.length <= 8) return "****";
  return `${ak.slice(0, 4)}****${ak.slice(-4)}`;
}

/** Redacted view safe for logs / diagnostics. */
export function redactAliCredentials(c: AlibabaCloudCredentials): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {
    kind: "alicloud",
    accessKeyId: typeof c.accessKeyId === "string" ? maskAccessKeyId(c.accessKeyId) : undefined,
    accessKeySecret: c.accessKeySecret !== undefined ? REDACTED : undefined,
  };
  if (c.securityToken !== undefined) out.securityToken = REDACTED;
  if (c.source) out.source = c.source;
  return out;
}

/**
 * Build a credentials object whose secret fields are non-enumerable and redacted on
 * serialization / inspection. Registers every value with the diagnostic redactor.
 */
export function createAliCredentials(input: AlibabaCloudCredentialInput): AlibabaCloudCredentials {
  const accessKeyId = (input.accessKeyId ?? "").trim();
  const accessKeySecret = (input.accessKeySecret ?? "").trim();
  if (!accessKeyId || !accessKeySecret) {
    throw new AlibabaCloudCredentialsError("Alibaba Cloud credentials require both accessKeyId and accessKeySecret");
  }
  const securityToken = input.securityToken?.trim() || undefined;
  registerAliSecret(accessKeyId);
  registerAliSecret(accessKeySecret);
  registerAliSecret(securityToken);

  const obj: Record<string | symbol, unknown> = { kind: "alicloud" };
  if (input.source) obj.source = input.source;
  const define = (key: string, value: string | undefined) => {
    if (value === undefined) return;
    Object.defineProperty(obj, key, { value, enumerable: false, writable: false, configurable: false });
  };
  define("accessKeyId", accessKeyId);
  define("accessKeySecret", accessKeySecret);
  define("securityToken", securityToken);

  const redacted = () => redactAliCredentials(obj as unknown as AlibabaCloudCredentials);
  Object.defineProperty(obj, "toJSON", { value: redacted, enumerable: false });
  Object.defineProperty(obj, inspect.custom, { value: () => `AlibabaCloudCredentials ${inspect(redacted())}`, enumerable: false });
  Object.defineProperty(obj, "toString", { value: () => "[AlibabaCloudCredentials]", enumerable: false });
  return Object.freeze(obj) as unknown as AlibabaCloudCredentials;
}

/* ------------------------------------------------------------------------ */
/* INI parsing                                                              */
/* ------------------------------------------------------------------------ */

const KEY_ALIASES: Readonly<Record<string, "type" | "accessKeyId" | "accessKeySecret" | "securityToken">> = {
  type: "type",
  access_key_id: "accessKeyId",
  accesskeyid: "accessKeyId",
  access_key_secret: "accessKeySecret",
  accesskeysecret: "accessKeySecret",
  security_token: "securityToken",
  securitytoken: "securityToken",
  sts_token: "securityToken",
};

function stripQuotes(v: string): string {
  const t = v.trim();
  if (t.length >= 2 && ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")))) {
    return t.slice(1, -1);
  }
  return t;
}

/** Raw INI sections keyed by section name (case preserved; values may be secret — never log). */
function parseIniSections(text: string): Map<string, Record<string, string>> {
  const sections = new Map<string, Record<string, string>>();
  let current: Record<string, string> | undefined;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/^\uFEFF/, "").trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sec = /^\[\s*([^\]]+?)\s*\]$/.exec(line);
    if (sec) {
      const name = sec[1];
      current = sections.get(name) ?? {};
      sections.set(name, current);
      continue;
    }
    if (!current) continue;
    const kv = /^([^=:#;]+?)\s*[=:]\s*(.*)$/.exec(line);
    if (!kv) continue;
    const key = kv[1].trim().toLowerCase();
    // Strip trailing inline comments only when preceded by whitespace (secrets may contain '#').
    const value = stripQuotes(kv[2].replace(/\s+[#;].*$/, ""));
    if (key) current[key] = value;
  }
  return sections;
}

/** Names of the profiles present in an INI text (no values). */
export function listAliCredentialProfiles(text: string): string[] {
  return [...parseIniSections(text).keys()];
}

/**
 * Parse one profile of an Alibaba Cloud credentials INI (format compatible with
 * `@alicloud/credentials`):
 *
 *   [default]
 *   type = access_key          ; or sts (+ security_token)
 *   access_key_id = ...
 *   access_key_secret = ...
 *
 * Returns undefined when the profile does not exist. Throws {@link AlibabaCloudCredentialsError}
 * for an unsupported `type` (ram_role_arn / ecs_ram_role / oidc_role_arn / …) or missing fields;
 * error messages name the profile and the missing KEYS only, never values.
 * A missing `type` is treated as `access_key`. Profile names are matched exactly first, then
 * case-insensitively.
 */
export function parseAliCredentialsIni(text: string, profile: string = ALI_DEFAULT_PROFILE): AlibabaCloudCredentialInput | undefined {
  const sections = parseIniSections(text);
  let raw = sections.get(profile);
  if (!raw) {
    const lower = profile.toLowerCase();
    for (const [name, sec] of sections) {
      if (name.toLowerCase() === lower) {
        raw = sec;
        break;
      }
    }
  }
  if (!raw) return undefined;

  const fields: Partial<Record<"type" | "accessKeyId" | "accessKeySecret" | "securityToken", string>> = {};
  for (const [k, v] of Object.entries(raw)) {
    const alias = KEY_ALIASES[k];
    if (alias && v) fields[alias] = v;
  }
  const type = (fields.type ?? "access_key").toLowerCase();
  if (!ALI_SUPPORTED_CREDENTIAL_TYPES.has(type)) {
    throw new AlibabaCloudCredentialsError(
      `Alibaba Cloud credentials profile "${profile}": unsupported credential type ${type} (Phase 2 supports access_key and sts only)`,
    );
  }
  const missing: string[] = [];
  if (!fields.accessKeyId) missing.push("access_key_id");
  if (!fields.accessKeySecret) missing.push("access_key_secret");
  if (type === "sts" && !fields.securityToken) missing.push("security_token");
  if (missing.length > 0) {
    throw new AlibabaCloudCredentialsError(
      `Alibaba Cloud credentials profile "${profile}" (type ${type}) is missing ${missing.join(", ")}`,
    );
  }
  return {
    accessKeyId: fields.accessKeyId,
    accessKeySecret: fields.accessKeySecret,
    ...(type === "sts" ? { securityToken: fields.securityToken } : {}),
  };
}

/* ------------------------------------------------------------------------ */
/* Credential chain                                                         */
/* ------------------------------------------------------------------------ */

export function defaultAliCredentialsPath(env: NodeJS.ProcessEnv = process.env): string {
  return env[ALI_CREDENTIALS_FILE_ENV] || join(homedir(), ".alibabacloud", "credentials");
}

export interface LoadAliCredentialsOptions {
  /** Explicit credentials (highest priority). */
  explicit?: AlibabaCloudCredentialInput | AlibabaCloudCredentials;
  /** Environment to consult (defaults to process.env). */
  env?: NodeJS.ProcessEnv;
  /** INI file path (defaults to ALIBABA_CLOUD_CREDENTIALS_FILE or ~/.alibabacloud/credentials). */
  filePath?: string;
  /** INI profile (defaults to ALIBABA_CLOUD_PROFILE or "default"). */
  profile?: string;
}

/**
 * Load the file portion of the chain. Returns undefined when the file or profile is absent /
 * unreadable; throws {@link AlibabaCloudCredentialsError} when the profile is present but invalid.
 */
export function loadAliCredentialsFile(filePath: string, profile: string = ALI_DEFAULT_PROFILE): AlibabaCloudCredentials | undefined {
  if (!existsSync(filePath)) return undefined;
  let text: string;
  try {
    text = readFileSync(filePath, "utf8");
  } catch {
    return undefined;
  }
  let input: AlibabaCloudCredentialInput | undefined;
  try {
    input = parseAliCredentialsIni(text, profile);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new AlibabaCloudCredentialsError(`${msg} (file ${filePath})`);
  }
  return input ? createAliCredentials({ ...input, source: "file" }) : undefined;
}

/**
 * Resolve Alibaba Cloud credentials via the chain: explicit → env → file.
 * Throws {@link AlibabaCloudCredentialsNotFoundError} when no source yields an AK pair.
 */
export function loadAliCredentials(opts: LoadAliCredentialsOptions = {}): AlibabaCloudCredentials {
  const env = opts.env ?? process.env;

  const ex = opts.explicit;
  if (ex?.accessKeyId && ex?.accessKeySecret) {
    return createAliCredentials({
      accessKeyId: ex.accessKeyId,
      accessKeySecret: ex.accessKeySecret,
      securityToken: ex.securityToken,
      source: "explicit",
    });
  }

  const id = env[ALI_ENV_ACCESS_KEY_ID]?.trim();
  const secret = env[ALI_ENV_ACCESS_KEY_SECRET]?.trim();
  if (id && secret) {
    return createAliCredentials({ accessKeyId: id, accessKeySecret: secret, securityToken: env[ALI_ENV_SECURITY_TOKEN], source: "env" });
  }
  // Legacy (Terraform) names only when the new names are entirely absent.
  if (!id && !secret) {
    const legacyId = env[ALI_ENV_LEGACY_ACCESS_KEY]?.trim();
    const legacySecret = env[ALI_ENV_LEGACY_SECRET_KEY]?.trim();
    if (legacyId && legacySecret) {
      return createAliCredentials({
        accessKeyId: legacyId,
        accessKeySecret: legacySecret,
        securityToken: env[ALI_ENV_LEGACY_SECURITY_TOKEN],
        source: "env",
      });
    }
  }

  const filePath = opts.filePath ?? defaultAliCredentialsPath(env);
  const profile = opts.profile ?? (env[ALI_PROFILE_ENV]?.trim() || ALI_DEFAULT_PROFILE);
  const fromFile = loadAliCredentialsFile(filePath, profile);
  if (fromFile) return fromFile;

  throw new AlibabaCloudCredentialsNotFoundError([
    "explicit credentials",
    `env ${ALI_ENV_ACCESS_KEY_ID}/${ALI_ENV_ACCESS_KEY_SECRET}`,
    `env ${ALI_ENV_LEGACY_ACCESS_KEY}/${ALI_ENV_LEGACY_SECRET_KEY}`,
    `file ${filePath} (profile "${profile}")`,
  ]);
}

/**
 * Credentials for an Alibaba scanner call: the context's credentials when they are Alibaba
 * credentials (runner / cross-account), otherwise the credential chain.
 */
export function aliCredentialsFromContext(ctx: Pick<ScanContext, "credentials">): AlibabaCloudCredentials {
  if (isAlibabaCloudCredentials(ctx.credentials)) return loadAliCredentials({ explicit: ctx.credentials });
  return loadAliCredentials();
}

/* ------------------------------------------------------------------------ */
/* Account UID (STS GetCallerIdentity)                                      */
/* ------------------------------------------------------------------------ */

interface GetCallerIdentityBody {
  AccountId?: string;
  Arn?: string;
  IdentityType?: string;
  PrincipalId?: string;
  UserId?: string;
}

const accountIdCache = new Map<string, string>();

/** Non-reversible cache key (the AK itself is never used as a key). */
function fingerprint(creds: AlibabaCloudCredentials): string {
  return createHash("sha256")
    .update(`${creds.accessKeyId}\u0000${creds.securityToken ?? ""}`)
    .digest("hex")
    .slice(0, 32);
}

export function clearAliAccountIdCache(): void {
  accountIdCache.clear();
}

export interface ResolveAliAccountIdOptions {
  /** Bypass the cache. */
  force?: boolean;
  retry?: AliRetryOptions;
}

/**
 * Account UID (16-digit main-account ID) via STS GetCallerIdentity, cached per credentials.
 * Throws the (redacted) `AliCloudError` on failure; callers wanting best-effort semantics
 * (provider.getAccountId) map failures to "unknown".
 */
export async function resolveAliAccountId(creds: AlibabaCloudCredentials, opts: ResolveAliAccountIdOptions = {}): Promise<string> {
  const key = fingerprint(creds);
  if (!opts.force) {
    const cached = accountIdCache.get(key);
    if (cached) return cached;
  }
  const body = await aliCall<GetCallerIdentityBody>(ALI_API.sts.GetCallerIdentity, { credentials: creds, retry: opts.retry });
  const accountId = typeof body?.AccountId === "string" ? body.AccountId.trim() : "";
  if (!accountId) {
    throw new AlibabaCloudCredentialsError("Alibaba Cloud STS GetCallerIdentity returned no AccountId");
  }
  accountIdCache.set(key, accountId);
  return accountId;
}
