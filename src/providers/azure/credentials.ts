/**
 * Azure credential loading (plan §3.2). EXPERIMENTAL — not validated against a live account.
 *
 * Resolution chain (service principal + client secret only):
 *   1. explicit credentials passed by the caller (ScanContext.credentials / tool parameters)
 *   2. environment: AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET;
 *      AZURE_CLOUD = china | global (default china / 21Vianet); optional
 *      AZURE_SUBSCRIPTION_ID (pins the scan to one subscription — read by the provider).
 *
 * `@azure/identity`'s `DefaultAzureCredential` is deliberately NOT used: it probes the
 * IMDS endpoint, the Azure CLI, VS Code, … which is slow and uncontrolled outside Azure.
 * `~/.azure/` is never read.
 *
 * SECURITY: the client secret must never be logged, serialized or embedded in error
 * messages. Objects produced here serialize (`toJSON`) / inspect as the redacted view
 * ({@link redactAzureCredentials}) and the secret is registered with the diagnostic
 * redactor. Tenant / client IDs are identifiers and are kept.
 */
import { inspect } from "util";
import type { AzureCloud, AzureCredentials, ScanContext } from "../../types.js";
import { isAzureCredentials } from "../../types.js";
import { registerAzureSecret } from "./errors.js";

export { registerAzureSecret };

export const AZURE_ENV_TENANT_ID = "AZURE_TENANT_ID";
export const AZURE_ENV_CLIENT_ID = "AZURE_CLIENT_ID";
export const AZURE_ENV_CLIENT_SECRET = "AZURE_CLIENT_SECRET";
export const AZURE_ENV_CLOUD = "AZURE_CLOUD";
export const AZURE_ENV_SUBSCRIPTION_ID = "AZURE_SUBSCRIPTION_ID";

export const DEFAULT_AZURE_CLOUD: AzureCloud = "china";

export const REDACTED = "***REDACTED***";

export type AzureCredentialSource = "explicit" | "env";

export interface AzureCredentialInput {
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
  /** `china` | `global` or an alias accepted by {@link resolveAzureCloud}. */
  cloud?: string;
  source?: AzureCredentialSource;
}

const GLOBAL_CLOUD_ALIASES: ReadonlySet<string> = new Set(["global", "public", "azurecloud", "azurepubliccloud"]);

/**
 * National cloud from an `AZURE_CLOUD` value (or an env object): anything other than a
 * Global alias (`global` / `public` / `AzureCloud` / `AzurePublicCloud`) means China
 * (21Vianet), the default.
 */
export function resolveAzureCloud(value: string | NodeJS.ProcessEnv | undefined = process.env.AZURE_CLOUD): AzureCloud {
  const raw = typeof value === "object" && value !== null ? value[AZURE_ENV_CLOUD] : value;
  const v = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  return GLOBAL_CLOUD_ALIASES.has(v) ? "global" : DEFAULT_AZURE_CLOUD;
}

/** Generic credential configuration error (never contains secret values). */
export class AzureCredentialsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AzureCredentialsError";
  }
}

/** No source yielded credentials. Lists only the source / env-var NAMES that were checked. */
export class AzureCredentialsNotFoundError extends Error {
  readonly sources: readonly string[];
  /** Env variable names that were absent / blank (names only, never values). */
  readonly missing: readonly string[];
  constructor(sources: readonly string[], missing: readonly string[] = []) {
    super(
      `Azure credentials not found. Checked: ${sources.join("; ")}.` +
        (missing.length > 0 ? ` Missing: ${missing.join(", ")}.` : "") +
        ` Set ${AZURE_ENV_TENANT_ID}, ${AZURE_ENV_CLIENT_ID} and ${AZURE_ENV_CLIENT_SECRET} (service principal);` +
        ` optional ${AZURE_ENV_CLOUD}=china|global (default china) and ${AZURE_ENV_SUBSCRIPTION_ID}.`,
    );
    this.name = "AzureCredentialsNotFoundError";
    this.sources = [...sources];
    this.missing = [...missing];
  }
}

/* ------------------------------------------------------------------------ */
/* Credential objects                                                       */
/* ------------------------------------------------------------------------ */

/** Redacted view safe for logs / diagnostics: the secret is masked, the IDs are kept. */
export function redactAzureCredentials(c: AzureCredentials): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {
    kind: "azure",
    tenantId: typeof c.tenantId === "string" ? c.tenantId : undefined,
    clientId: typeof c.clientId === "string" ? c.clientId : undefined,
    clientSecret: c.clientSecret !== undefined ? REDACTED : undefined,
    cloud: c.cloud,
  };
  if (c.source) out.source = c.source;
  return out;
}

/**
 * Build a frozen credentials object. The fields stay enumerable (structural equality with
 * a plain {@link AzureCredentials}), but `JSON.stringify` / `util.inspect` / `String()` only
 * ever show the redacted view. Registers the secret with the diagnostic redactor.
 */
export function createAzureCredentials(input: AzureCredentialInput): AzureCredentials {
  const tenantId = (input.tenantId ?? "").trim();
  const clientId = (input.clientId ?? "").trim();
  const clientSecret = (input.clientSecret ?? "").trim();
  const missing: string[] = [];
  if (!tenantId) missing.push("tenantId");
  if (!clientId) missing.push("clientId");
  if (!clientSecret) missing.push("clientSecret");
  if (missing.length > 0) {
    throw new AzureCredentialsError(`Azure credentials require tenantId, clientId and clientSecret (missing ${missing.join(", ")})`);
  }
  registerAzureSecret(clientSecret);

  const obj: Record<string | symbol, unknown> = {
    kind: "azure",
    tenantId,
    clientId,
    clientSecret,
    cloud: resolveAzureCloud(input.cloud ?? ""),
  };
  if (input.source) obj.source = input.source;

  const redacted = () => redactAzureCredentials(obj as unknown as AzureCredentials);
  Object.defineProperty(obj, "toJSON", { value: redacted, enumerable: false });
  Object.defineProperty(obj, inspect.custom, { value: () => `AzureCredentials ${inspect(redacted())}`, enumerable: false });
  Object.defineProperty(obj, "toString", { value: () => "[AzureCredentials]", enumerable: false });
  return Object.freeze(obj) as unknown as AzureCredentials;
}

/* ------------------------------------------------------------------------ */
/* Credential chain                                                         */
/* ------------------------------------------------------------------------ */

export interface LoadAzureCredentialsOptions {
  /** Explicit credentials (highest priority). */
  explicit?: AzureCredentialInput | AzureCredentials;
  /** Environment to consult (defaults to process.env). */
  env?: NodeJS.ProcessEnv;
}

function envValue(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const v = env[name]?.trim();
  return v ? v : undefined;
}

function isCompleteAzureCredentials(c: unknown): c is AzureCredentials {
  if (!isAzureCredentials(c as AzureCredentials)) return false;
  const a = c as AzureCredentials;
  const ok = (v: unknown) => typeof v === "string" && v.length > 0 && v === v.trim();
  return ok(a.tenantId) && ok(a.clientId) && ok(a.clientSecret) && (a.cloud === "china" || a.cloud === "global");
}

/**
 * Resolve Azure credentials via the chain: explicit → env. A complete, well-formed
 * {@link AzureCredentials} object is returned as-is (its secret is registered with the
 * redactor); partial explicit input is normalised. Throws
 * {@link AzureCredentialsNotFoundError} (env-var NAMES only) when nothing yields a
 * service principal. Never touches the network or `~/.azure/`.
 */
export function loadAzureCredentials(opts: LoadAzureCredentialsOptions = {}): AzureCredentials {
  const env = opts.env ?? process.env;

  const ex = opts.explicit;
  if (ex) {
    if (isCompleteAzureCredentials(ex)) {
      registerAzureSecret(ex.clientSecret);
      return ex;
    }
    if (ex.tenantId?.trim() && ex.clientId?.trim() && ex.clientSecret?.trim()) {
      return createAzureCredentials({
        tenantId: ex.tenantId,
        clientId: ex.clientId,
        clientSecret: ex.clientSecret,
        cloud: ex.cloud ?? env[AZURE_ENV_CLOUD],
        source: "explicit",
      });
    }
  }

  const tenantId = envValue(env, AZURE_ENV_TENANT_ID);
  const clientId = envValue(env, AZURE_ENV_CLIENT_ID);
  const clientSecret = envValue(env, AZURE_ENV_CLIENT_SECRET);
  if (tenantId && clientId && clientSecret) {
    return createAzureCredentials({ tenantId, clientId, clientSecret, cloud: env[AZURE_ENV_CLOUD], source: "env" });
  }

  const missing = [
    !tenantId ? AZURE_ENV_TENANT_ID : undefined,
    !clientId ? AZURE_ENV_CLIENT_ID : undefined,
    !clientSecret ? AZURE_ENV_CLIENT_SECRET : undefined,
  ].filter((n): n is string => !!n);
  throw new AzureCredentialsNotFoundError(
    ["explicit credentials", `env ${AZURE_ENV_TENANT_ID}/${AZURE_ENV_CLIENT_ID}/${AZURE_ENV_CLIENT_SECRET}`],
    missing,
  );
}

/**
 * Credentials for an Azure scanner call: the context's credentials when they are Azure
 * credentials (runner), otherwise the chain (env).
 */
export function azureCredentialFromContext(ctx: Pick<ScanContext, "credentials">): AzureCredentials {
  if (isAzureCredentials(ctx.credentials)) return loadAzureCredentials({ explicit: ctx.credentials });
  return loadAzureCredentials();
}

/** `AZURE_SUBSCRIPTION_ID` (trimmed) when set, else undefined. */
export function pinnedAzureSubscriptionId(env: NodeJS.ProcessEnv = process.env): string | undefined {
  return envValue(env, AZURE_ENV_SUBSCRIPTION_ID);
}
