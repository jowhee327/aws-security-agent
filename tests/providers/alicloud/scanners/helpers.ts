/**
 * Shared fixtures for the Alibaba Cloud scanner tests (T2): fake credentials, env
 * isolation, an aliCall router keyed by `spec.action`, and typed AliCloudError fixtures.
 * Fake keys only; aliCall is always mocked by the test file — no network.
 */
import { tmpdir } from "os";
import { join } from "path";
import type { Mock } from "vitest";
import { AliCloudError } from "../../../../src/providers/alicloud/errors.js";
import type { AlibabaCloudCredentials, ScanContext } from "../../../../src/types.js";

export const FAKE_AK = "LTAI5tFAKEFAKEFAKE0000001";
export const FAKE_SK = "FakeSecretKeyDoNotUseXXXXXXXXXXXX01";
export const FAKE: AlibabaCloudCredentials = { kind: "alicloud", accessKeyId: FAKE_AK, accessKeySecret: FAKE_SK };
export const UID = "1234567890123456";

const ENV_KEYS = [
  "ALIBABA_CLOUD_ACCESS_KEY_ID",
  "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
  "ALIBABA_CLOUD_SECURITY_TOKEN",
  "ALICLOUD_ACCESS_KEY",
  "ALICLOUD_SECRET_KEY",
  "ALICLOUD_SECURITY_TOKEN",
  "ALIBABA_CLOUD_CREDENTIALS_FILE",
  "ALIBABA_CLOUD_PROFILE",
  "ALIBABA_CLOUD_SITE",
];
const saved: Record<string, string | undefined> = {};

/** Clear Alibaba env vars and point the credentials file at a missing temp path. */
export function isolateAliEnv(): void {
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  process.env.ALIBABA_CLOUD_CREDENTIALS_FILE = join(tmpdir(), `ali-scanner-test-missing-${process.pid}`);
}

export function restoreAliEnv(): void {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
}

export function aliCtx(overrides: Partial<ScanContext> = {}): ScanContext {
  return { region: "cn-hangzhou", partition: "alicloud", accountId: UID, credentials: FAKE, provider: "alicloud", ...overrides };
}

export type AliHandler = (query: Record<string, unknown>, ctx: Record<string, unknown>) => unknown;

/**
 * Route mocked aliCall by `spec.action`: a function handler is invoked with (query, ctx)
 * and may throw; any other value is returned as the body. Unknown actions throw.
 */
export function routeAliCall(mock: Mock, handlers: Record<string, AliHandler | object>): void {
  mock.mockImplementation(async (spec: { action: string }, ctx: Record<string, unknown>, query?: Record<string, unknown>) => {
    const h = handlers[spec.action];
    if (h === undefined) throw new Error(`unexpected Alibaba Cloud call ${spec.action}`);
    return typeof h === "function" ? (h as AliHandler)(query ?? {}, ctx) : h;
  });
}

/** Calls made for one action: [spec, ctx, query] tuples. */
export function callsFor(mock: Mock, action: string): Array<[{ service: string; action: string }, Record<string, unknown>, Record<string, unknown>]> {
  return mock.mock.calls.filter((c) => (c[0] as { action: string }).action === action) as never;
}

export const authError = (api = "config:GetConfigurationRecorder") =>
  new AliCloudError({ kind: "auth_failed", status: 404, code: "InvalidAccessKeyId.NotFound", message: "Specified access key is not found." }, api);

export const deniedError = (api = "config:GetConfigurationRecorder") =>
  new AliCloudError({ kind: "access_denied", status: 403, code: "Forbidden.RAM", message: "User not authorized to operate on the specified resource." }, api);

export const misuseError = (api = "config:GetConfigurationRecorder") =>
  new AliCloudError({ kind: "api_misuse", status: 400, code: "MissingParameter", message: "A required parameter is missing." }, api);

export const notEnabledError = (api = "config:GetConfigurationRecorder") =>
  new AliCloudError({ kind: "not_enabled", status: 400, code: "ServiceNotEnabled", message: "The service is not enabled." }, api);

export const throttledError = (api = "config:GetConfigurationRecorder") =>
  new AliCloudError({ kind: "throttled", status: 429, code: "Throttling.User", message: "Request was denied due to user flow control." }, api);

/*
 * FIX2 hostile server strings: a fake AK, an `accessKeySecret=` pair and a
 * SignatureDoesNotMatch string-to-sign echo, as a malicious / misconfigured resource could
 * carry them in a name, Sid, domain, status … Every scanner must redact them before they
 * reach a Finding field, a warning or the error text.
 */
export const HOSTILE_AK = "LTAI5tFAKE000000000000";
export const HOSTILE_SK_VALUE = "FakeHostileSecretValue0000000001";
export const HOSTILE_SECRET_PAIR = `accessKeySecret=${HOSTILE_SK_VALUE}`;
export const HOSTILE_SIGN_ECHO = `server string to sign is:POST&%2F&AccessKeyId%3D${HOSTILE_AK}`;
/** Substrings that must never appear in a scan result. */
export const HOSTILE_FORBIDDEN = [
  HOSTILE_AK,
  HOSTILE_SK_VALUE,
  HOSTILE_SECRET_PAIR,
  HOSTILE_SIGN_ECHO,
  "AccessKeyId%3DLTAI",
  "POST&%2F&AccessKeyId",
  "%3DLTAI",
  "string to sign is:POST",
];

/**
 * A hostile server string carrying all three payloads (non-alnum separated; the sign echo
 * last because its redaction drops the rest of the line).
 */
export const hostile = (prefix: string): string => `${prefix}-${HOSTILE_AK}-x ${HOSTILE_SECRET_PAIR} ${HOSTILE_SIGN_ECHO}`;

interface HostileCheckable {
  error?: string;
  warnings?: string[];
  findings: Array<{
    title: string;
    description: string;
    resourceId: string;
    resourceArn: string;
    remediationSteps: string[];
  }>;
}

/** Assert no hostile payload in title / description / resourceId / resourceArn / remediation / warnings / error (and the whole result). */
export function expectNoHostileLeak(r: HostileCheckable): void {
  const texts: string[] = [JSON.stringify(r), r.error ?? "", ...(r.warnings ?? [])];
  for (const f of r.findings) {
    texts.push(f.title, f.description, f.resourceId, f.resourceArn, ...f.remediationSteps);
  }
  for (const t of texts) {
    for (const bad of HOSTILE_FORBIDDEN) {
      if (t.includes(bad)) throw new Error(`hostile payload ${JSON.stringify(bad)} leaked into: ${t.slice(0, 300)}`);
    }
  }
}
