/**
 * Huawei Cloud credential loading.
 *
 * SECURITY: AK/SK values must never be logged, serialized or embedded in error
 * messages. Credential objects produced here keep `ak` / `sk` / `securityToken`
 * as NON-ENUMERABLE properties and redact them in `toJSON()` and
 * `util.inspect()`, so accidental `console.log(creds)` / `JSON.stringify(creds)`
 * / `{ ...creds }` never reveal secrets.
 *
 * Resolution chain (plan §3.2):
 *   1. explicit values passed by the caller
 *   2. environment: HUAWEICLOUD_SDK_AK / HUAWEICLOUD_SDK_SK
 *      (+ HUAWEICLOUD_SDK_SECURITY_TOKEN / HUAWEICLOUD_SDK_PROJECT_ID / HUAWEICLOUD_SDK_DOMAIN_ID)
 *   3. INI file `~/.huaweicloud/credentials` (`[basic]` regional, `[global]` global),
 *      path overridable via HUAWEICLOUD_CREDENTIALS_FILE.
 *
 * The SDK itself does NOT read the credentials file, hence the INI parser.
 */
import { readFileSync, existsSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { inspect } from "util";
import type { HuaweiCloudCredentials } from "../../types.js";
import type { RegionScope } from "../types.js";

export const HUAWEI_CREDENTIALS_FILE_ENV = "HUAWEICLOUD_CREDENTIALS_FILE";
export const HUAWEI_ENV_AK = "HUAWEICLOUD_SDK_AK";
export const HUAWEI_ENV_SK = "HUAWEICLOUD_SDK_SK";
export const HUAWEI_ENV_SECURITY_TOKEN = "HUAWEICLOUD_SDK_SECURITY_TOKEN";
export const HUAWEI_ENV_PROJECT_ID = "HUAWEICLOUD_SDK_PROJECT_ID";
export const HUAWEI_ENV_DOMAIN_ID = "HUAWEICLOUD_SDK_DOMAIN_ID";

export const REDACTED = "***REDACTED***";

export type HuaweiCredentialSource = "explicit" | "env" | "file";

/** A pair of credentials: `basic` for regional services, `global` for global services (IAM/RMS/...). */
export interface HuaweiCredentialSet {
  basic: HuaweiCloudCredentials;
  global: HuaweiCloudCredentials;
  source: HuaweiCredentialSource;
}

export interface HuaweiCredentialInput {
  ak?: string;
  sk?: string;
  securityToken?: string;
  projectId?: string;
  domainId?: string;
}

const SECRET_KEYS = ["ak", "sk", "securityToken"] as const;

/**
 * Build a credentials object whose secret fields are non-enumerable and redacted
 * on serialization / inspection. Typed as the plain interface so scanners can
 * read `creds.ak` normally.
 */
export function createHuaweiCredentials(input: HuaweiCredentialInput): HuaweiCloudCredentials {
  const ak = (input.ak ?? "").trim();
  const sk = (input.sk ?? "").trim();
  if (!ak || !sk) {
    throw new Error("Huawei Cloud credentials require both ak and sk");
  }
  const obj: Record<string, unknown> = {};
  const define = (key: string, value: string | undefined) => {
    if (value === undefined) return;
    Object.defineProperty(obj, key, { value, enumerable: false, writable: false, configurable: false });
  };
  define("ak", ak);
  define("sk", sk);
  define("securityToken", input.securityToken?.trim() || undefined);
  if (input.projectId) obj.projectId = input.projectId.trim();
  if (input.domainId) obj.domainId = input.domainId.trim();

  const redacted = () => redactHuaweiCredentials(obj as unknown as HuaweiCloudCredentials);
  Object.defineProperty(obj, "toJSON", { value: redacted, enumerable: false });
  Object.defineProperty(obj, inspect.custom, { value: () => `HuaweiCloudCredentials ${inspect(redacted())}`, enumerable: false });
  Object.defineProperty(obj, "toString", { value: () => "[HuaweiCloudCredentials]", enumerable: false });
  return Object.freeze(obj) as unknown as HuaweiCloudCredentials;
}

/** Redacted view safe for logs / diagnostics (never contains secret material). */
export function redactHuaweiCredentials(c: HuaweiCloudCredentials): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const k of SECRET_KEYS) {
    if (c[k] !== undefined) out[k] = REDACTED;
  }
  out.akLength = c.ak ? String(c.ak.length) : undefined;
  if (c.projectId) out.projectId = c.projectId;
  if (c.domainId) out.domainId = c.domainId;
  return out;
}

/* ------------------------------------------------------------------------ */
/* INI parsing                                                              */
/* ------------------------------------------------------------------------ */

export interface HuaweiIniSection {
  ak?: string;
  sk?: string;
  securityToken?: string;
  projectId?: string;
  domainId?: string;
  region?: string;
}

export interface ParsedHuaweiIni {
  basic?: HuaweiIniSection;
  global?: HuaweiIniSection;
  /** Any other sections, keyed by lower-cased section name (kept for diagnostics; values may be secret). */
  sections: Record<string, Record<string, string>>;
}

const KEY_ALIASES: Record<string, keyof HuaweiIniSection> = {
  ak: "ak",
  access_key: "ak",
  access_key_id: "ak",
  accesskey: "ak",
  sk: "sk",
  secret_key: "sk",
  secret_access_key: "sk",
  secretkey: "sk",
  security_token: "securityToken",
  securitytoken: "securityToken",
  session_token: "securityToken",
  project_id: "projectId",
  projectid: "projectId",
  domain_id: "domainId",
  domainid: "domainId",
  region: "region",
  region_id: "region",
};

function stripQuotes(v: string): string {
  const t = v.trim();
  if (t.length >= 2 && ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")))) {
    return t.slice(1, -1);
  }
  return t;
}

/**
 * Parse Huawei Cloud credentials INI text (`[basic]` / `[global]` sections).
 * Tolerates blank lines, `#` / `;` comments, `key = value` / `key: value`,
 * surrounding whitespace, quoted values and mixed-case keys/sections.
 * Never throws on malformed lines; they are ignored.
 */
export function parseHuaweiCredentialsIni(text: string): ParsedHuaweiIni {
  const sections: Record<string, Record<string, string>> = {};
  let current: string | undefined;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/^﻿/, "").trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;

    const sec = /^\[\s*([^\]]+?)\s*\]$/.exec(line);
    if (sec) {
      current = sec[1].toLowerCase();
      sections[current] ??= {};
      continue;
    }
    if (!current) continue;

    const kv = /^([^=:#;]+?)\s*[=:]\s*(.*)$/.exec(line);
    if (!kv) continue;
    const key = kv[1].trim().toLowerCase();
    // Strip trailing inline comments only when preceded by whitespace (secrets may contain '#').
    const value = stripQuotes(kv[2].replace(/\s+[#;].*$/, ""));
    if (!key) continue;
    sections[current][key] = value;
  }

  const toSection = (raw: Record<string, string> | undefined): HuaweiIniSection | undefined => {
    if (!raw) return undefined;
    const out: HuaweiIniSection = {};
    for (const [k, v] of Object.entries(raw)) {
      const alias = KEY_ALIASES[k];
      if (alias && v) out[alias] = v;
    }
    return out;
  };

  return {
    basic: toSection(sections.basic),
    global: toSection(sections.global),
    sections,
  };
}

/* ------------------------------------------------------------------------ */
/* Credential chain                                                         */
/* ------------------------------------------------------------------------ */

export function defaultHuaweiCredentialsPath(env: NodeJS.ProcessEnv = process.env): string {
  return env[HUAWEI_CREDENTIALS_FILE_ENV] || join(homedir(), ".huaweicloud", "credentials");
}

export interface LoadHuaweiCredentialsOptions {
  /** Explicit credentials (highest priority). */
  explicit?: HuaweiCredentialInput;
  /** Environment to consult (defaults to process.env). */
  env?: NodeJS.ProcessEnv;
  /** INI file path (defaults to HUAWEICLOUD_CREDENTIALS_FILE or ~/.huaweicloud/credentials). */
  filePath?: string;
}

export class HuaweiCredentialsNotFoundError extends Error {
  constructor(filePath: string) {
    super(
      "Huawei Cloud credentials not found. Provide ak/sk explicitly, set " +
        `${HUAWEI_ENV_AK}/${HUAWEI_ENV_SK}, or create ${filePath} with [basic]/[global] sections.`,
    );
    this.name = "HuaweiCredentialsNotFoundError";
  }
}

function fromSections(basic: HuaweiIniSection | undefined, global: HuaweiIniSection | undefined, source: HuaweiCredentialSource): HuaweiCredentialSet | undefined {
  const b = basic?.ak && basic?.sk ? basic : undefined;
  const g = global?.ak && global?.sk ? global : undefined;
  if (!b && !g) return undefined;
  // Fall back to the other section when only one is present.
  const basicSrc = b ?? g!;
  const globalSrc = g ?? b!;
  return {
    basic: createHuaweiCredentials({
      ak: basicSrc.ak,
      sk: basicSrc.sk,
      securityToken: basicSrc.securityToken,
      projectId: basicSrc.projectId,
      domainId: basicSrc.domainId ?? globalSrc.domainId,
    }),
    global: createHuaweiCredentials({
      ak: globalSrc.ak,
      sk: globalSrc.sk,
      securityToken: globalSrc.securityToken,
      domainId: globalSrc.domainId ?? basicSrc.domainId,
    }),
    source,
  };
}

/** Load the file portion of the chain; returns undefined when absent/unusable. Never throws on unreadable file. */
export function loadHuaweiCredentialsFile(filePath: string): HuaweiCredentialSet | undefined {
  if (!existsSync(filePath)) return undefined;
  let text: string;
  try {
    text = readFileSync(filePath, "utf8");
  } catch {
    return undefined;
  }
  const parsed = parseHuaweiCredentialsIni(text);
  return fromSections(parsed.basic, parsed.global, "file");
}

/**
 * Resolve Huawei Cloud credentials via the chain: explicit → env → file.
 * Throws {@link HuaweiCredentialsNotFoundError} when no source yields an ak/sk pair.
 */
export function loadHuaweiCredentials(opts: LoadHuaweiCredentialsOptions = {}): HuaweiCredentialSet {
  const env = opts.env ?? process.env;

  if (opts.explicit?.ak && opts.explicit?.sk) {
    const s: HuaweiIniSection = { ...opts.explicit };
    return fromSections(s, s, "explicit")!;
  }

  const envAk = env[HUAWEI_ENV_AK];
  const envSk = env[HUAWEI_ENV_SK];
  if (envAk && envSk) {
    const s: HuaweiIniSection = {
      ak: envAk,
      sk: envSk,
      securityToken: env[HUAWEI_ENV_SECURITY_TOKEN],
      projectId: env[HUAWEI_ENV_PROJECT_ID],
      domainId: env[HUAWEI_ENV_DOMAIN_ID],
    };
    return fromSections(s, s, "env")!;
  }

  const filePath = opts.filePath ?? defaultHuaweiCredentialsPath(env);
  const fromFile = loadHuaweiCredentialsFile(filePath);
  if (fromFile) return fromFile;

  throw new HuaweiCredentialsNotFoundError(filePath);
}

/* ------------------------------------------------------------------------ */
/* Project / domain resolution (IAM keystoneListProjects)                   */
/* ------------------------------------------------------------------------ */

export interface HuaweiProjectInfo {
  projectId: string;
  domainId: string;
  region: string;
}

/** Minimal IAM surface needed for project resolution (allows fakes in tests). */
export interface KeystoneProjectsClient {
  keystoneListProjects(req?: unknown): Promise<unknown>;
}

/**
 * Loose shape of a keystone project. The SDK deserializes JSON into plain
 * objects, so the wire key `domain_id` is what exists at runtime; `domainId`
 * is accepted too for model instances / fakes.
 */
interface LooseProject {
  id?: string;
  name?: string;
  domainId?: string;
  domain_id?: string;
  enabled?: boolean;
}

export interface ResolveProjectsOptions {
  /** Inject a client (tests). Defaults to a real IamClient built through `hwClient`. */
  client?: KeystoneProjectsClient;
  /** Bypass the cache. */
  force?: boolean;
}

const projectCache = new Map<string, Map<string, HuaweiProjectInfo>>();

function cacheKey(creds: HuaweiCloudCredentials): string {
  // Cache key derived from a non-reversible fingerprint of the AK; the AK itself is never stored as key.
  let h = 0;
  for (let i = 0; i < creds.ak.length; i++) h = (h * 31 + creds.ak.charCodeAt(i)) | 0;
  return `${creds.ak.length}:${h}`;
}

export function clearHuaweiProjectCache(): void {
  projectCache.clear();
}

/**
 * Resolve region → { projectId, domainId } via IAM `keystoneListProjects`
 * (`project.name === region`). Results are cached per credential.
 * IAM is a global service; uses the `global` credentials.
 */
export async function resolveProjects(
  creds: HuaweiCloudCredentials,
  opts: ResolveProjectsOptions = {},
): Promise<Map<string, HuaweiProjectInfo>> {
  const key = cacheKey(creds);
  if (!opts.force) {
    const cached = projectCache.get(key);
    if (cached) return cached;
  }

  let client: KeystoneProjectsClient;
  if (opts.client) {
    client = opts.client;
  } else {
    const { hwClient } = await import("./client.js");
    const { IamClient } = await import("@huaweicloud/huaweicloud-sdk-iam/v3/IamClient.js");
    client = await hwClient(IamClient, "iam", creds, {}, { credentialType: "global" });
  }

  const { KeystoneListProjectsRequest } = await import("@huaweicloud/huaweicloud-sdk-iam/v3/model/KeystoneListProjectsRequest.js");
  const resp = (await client.keystoneListProjects(new KeystoneListProjectsRequest())) as { projects?: LooseProject[] } | undefined;

  const map = new Map<string, HuaweiProjectInfo>();
  for (const p of resp?.projects ?? []) {
    if (!p.id || !p.name) continue;
    if (p.enabled === false) continue;
    const domainId = p.domainId ?? p.domain_id ?? creds.domainId ?? "";
    // Sub-projects are named "<region>_<name>"; only top-level region projects map 1:1.
    map.set(p.name, { projectId: p.id, domainId, region: p.name });
  }
  projectCache.set(key, map);
  return map;
}

/**
 * Build a RegionScope for `region`, filling projectId/domainId from explicit
 * credential fields first and IAM project resolution otherwise.
 */
export async function resolveRegionScope(
  creds: HuaweiCloudCredentials,
  region: string,
  opts: ResolveProjectsOptions = {},
): Promise<RegionScope> {
  if (creds.projectId && creds.domainId) {
    return { region, projectId: creds.projectId, domainId: creds.domainId };
  }
  const projects = await resolveProjects(creds, opts);
  const info = projects.get(region);
  const domainId = creds.domainId ?? info?.domainId ?? [...projects.values()][0]?.domainId;
  if (!info && !creds.projectId) {
    const known = [...projects.keys()].filter((n) => !n.includes("_")).sort().join(", ");
    throw new Error(`Huawei Cloud region "${region}" has no project for these credentials. Known regions: ${known || "(none)"}`);
  }
  return {
    region,
    projectId: creds.projectId ?? info!.projectId,
    domainId,
  };
}
