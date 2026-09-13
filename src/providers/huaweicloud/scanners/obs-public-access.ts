/**
 * Huawei Cloud OBS public-access verification (moduleName `public_access_verify`).
 *
 * Mirrors the S3 half of `src/scanners/public-access-verify.ts`: list buckets,
 * then per bucket inspect the Public Access Block, the bucket ACL and the
 * bucket policy for grants to Everyone / AllUsers / AuthenticatedUsers or a
 * wildcard principal. Uses `esdk-obs-nodejs` (callback style: `(err, result)`
 * with `result.CommonMsg.Status` / `result.InterfaceResult`).
 *
 * Graceful degradation:
 *  - `getBucketPublicAccessBlock` returns 405 on the real service (and 404 when
 *    unset) → "no PAB", not an error.
 *  - `getBucketPolicy` 404 `NoSuchBucketPolicy` → no policy.
 *  - 403 on a bucket → warning, continue; 403 on `listBuckets` → success + warning.
 *
 * Bucket names are account-global, but each bucket lives in one region; the
 * `Location` from `listBuckets({ QueryLocation: true })` picks the regional
 * endpoint and fills `Finding.region`. Bounded concurrency + a bucket cap keep
 * large tenants from amplifying N+1 calls.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { severityFromScore, priorityFromSeverity } from "../../../utils/risk-scoring.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { hwObsClient, type ObsClientInstance } from "../client.js";
import { classifyHwError, describeHwError } from "../errors.js";
import { toResourceUrn } from "../urn.js";
import { hwCredentialsFromContext, hwDomainIdFromContext } from "./shared.js";

export const OBS_MAX_BUCKETS = 200;
export const OBS_BUCKET_CONCURRENCY = 5;

/* ------------------------------------------------------------------------ */
/* OBS callback → promise plumbing                                          */
/* ------------------------------------------------------------------------ */

export interface ObsCommonMsg {
  Status?: number;
  Code?: string;
  Message?: string;
  RequestId?: string;
}

export interface ObsCallResult<T = Record<string, unknown>> {
  CommonMsg?: ObsCommonMsg;
  InterfaceResult?: T | null;
}

/** HTTP-level OBS failure (status >= 300). Shape is understood by `classifyHwError`. */
export class ObsHttpError extends Error {
  readonly status?: number;
  readonly code?: string;
  readonly requestId?: string;
  constructor(method: string, msg: ObsCommonMsg | undefined) {
    const status = msg?.Status;
    super(msg?.Message || `OBS ${method} failed${status !== undefined ? ` with HTTP ${status}` : ""}`);
    this.name = "ObsHttpError";
    this.status = status;
    this.code = msg?.Code;
    this.requestId = msg?.RequestId;
  }
}

type ObsCallbackMethod = (
  params: Record<string, unknown>,
  cb: (err: unknown, result: ObsCallResult | null | undefined) => void,
) => unknown;

/** Minimal client surface (the real ObsClient satisfies it; tests inject fakes). */
export type ObsClientLike = object;

/** Invoke a callback-style OBS method and resolve with the result, rejecting on transport or HTTP (>=300) errors. */
export function obsCall<T = Record<string, unknown>>(
  client: ObsClientLike,
  method: string,
  params: Record<string, unknown> = {},
): Promise<ObsCallResult<T>> {
  return new Promise((resolve, reject) => {
    const fn = (client as Record<string, unknown>)[method];
    if (typeof fn !== "function") {
      reject(new Error(`OBS client has no method "${method}"`));
      return;
    }
    try {
      (fn as ObsCallbackMethod).call(client, params, (err, result) => {
        if (err) {
          reject(err);
          return;
        }
        if (!result) {
          reject(new Error(`OBS ${method}: empty response`));
          return;
        }
        const status = result.CommonMsg?.Status;
        if (typeof status === "number" && status >= 300) {
          reject(new ObsHttpError(method, result.CommonMsg));
          return;
        }
        resolve(result as ObsCallResult<T>);
      });
    } catch (e) {
      reject(e);
    }
  });
}

/* ------------------------------------------------------------------------ */
/* Judgement                                                                */
/* ------------------------------------------------------------------------ */

export type PublicVector =
  | "acl_write"
  | "acl_read"
  | "acl_read_acp"
  | "policy_write"
  | "policy_read"
  | "policy_conditional";

export interface PublicExposure {
  vector: PublicVector;
  /** Human-readable evidence (never contains secrets). */
  detail: string;
  riskScore: number;
}

interface LooseGrant {
  Grantee?: { Type?: string; ID?: string; URI?: string; Canned?: string; Name?: string };
  Permission?: string;
}

interface LooseAcl {
  Grants?: LooseGrant[];
  GrantsV2?: LooseGrant[];
}

const PUBLIC_GROUP_RE = /Everyone|AllUsers|AuthenticatedUsers/i;

function grantGroup(g: LooseGrant): string | undefined {
  const raw = g.Grantee?.URI ?? g.Grantee?.Canned ?? "";
  const m = PUBLIC_GROUP_RE.exec(raw);
  if (m) return m[0];
  // Some responses use Type=Group with an empty URI for Everyone.
  if ((g.Grantee?.Type ?? "").toLowerCase() === "group" && !g.Grantee?.ID) return "Everyone";
  return undefined;
}

/** ACL grants to Everyone/AllUsers/AuthenticatedUsers → exposures (WRITE-class 9.5, READ 8.0, READ_ACP 7.0). */
export function evaluateObsAcl(acl: unknown): PublicExposure[] {
  const out: PublicExposure[] = [];
  if (!acl || typeof acl !== "object") return out;
  const a = acl as LooseAcl;
  const grants = [...(Array.isArray(a.Grants) ? a.Grants : []), ...(Array.isArray(a.GrantsV2) ? a.GrantsV2 : [])];
  const seen = new Set<string>();
  for (const g of grants) {
    const group = grantGroup(g);
    if (!group) continue;
    const perm = (g.Permission ?? "").toUpperCase();
    if (!perm) continue;
    const key = `${group}:${perm}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (perm === "WRITE" || perm === "WRITE_ACP" || perm === "FULL_CONTROL") {
      out.push({ vector: "acl_write", detail: `ACL grants ${perm} to ${group}`, riskScore: 9.5 });
    } else if (perm === "READ") {
      out.push({ vector: "acl_read", detail: `ACL grants READ to ${group}`, riskScore: 8.0 });
    } else if (perm === "READ_ACP") {
      out.push({ vector: "acl_read_acp", detail: `ACL grants READ_ACP to ${group}`, riskScore: 7.0 });
    }
  }
  return out;
}

interface LooseStatement {
  Effect?: string;
  Principal?: unknown;
  Action?: unknown;
  Condition?: unknown;
  Sid?: string;
}

function principalIsWildcard(p: unknown): boolean {
  if (p === "*") return true;
  if (!p || typeof p !== "object") return false;
  for (const v of Object.values(p as Record<string, unknown>)) {
    if (v === "*") return true;
    if (Array.isArray(v) && v.some((x) => x === "*" || (typeof x === "string" && /^(?:\*|arn:aws:iam::\*)$/.test(x)))) return true;
    if (typeof v === "string" && /^arn:aws:iam::\*/.test(v)) return true;
  }
  return false;
}

const WRITE_ACTION_RE = /(?:^|:)(?:\*|Put\w*|Delete\w*|Write\w*|Abort\w*|Restore\w*|Modify\w*|Append\w*|Create\w*|Rename\w*)$/i;

function actionsAllowWrite(action: unknown): boolean {
  const list = Array.isArray(action) ? action : action === undefined ? [] : [action];
  return list.some((a) => typeof a === "string" && (a === "*" || WRITE_ACTION_RE.test(a)));
}

function actionList(action: unknown): string[] {
  const list = Array.isArray(action) ? action : action === undefined ? [] : [action];
  return list.filter((a): a is string => typeof a === "string");
}

/** Bucket policy statements with Effect Allow and a wildcard principal → exposures. */
export function evaluateObsPolicy(policyText: string | undefined | null): PublicExposure[] {
  const out: PublicExposure[] = [];
  if (!policyText || !policyText.trim()) return out;
  let doc: unknown;
  try {
    doc = JSON.parse(policyText);
  } catch {
    return out;
  }
  if (!doc || typeof doc !== "object") return out;
  const raw = (doc as { Statement?: unknown }).Statement;
  const statements = (Array.isArray(raw) ? raw : raw ? [raw] : []) as LooseStatement[];
  for (const st of statements) {
    if (!st || typeof st !== "object") continue;
    if ((st.Effect ?? "").toLowerCase() !== "allow") continue;
    if (!principalIsWildcard(st.Principal)) continue;
    const actions = actionList(st.Action);
    const label = actions.length > 0 ? actions.slice(0, 5).join(", ") + (actions.length > 5 ? ", …" : "") : "(no Action)";
    const sid = st.Sid ? ` (Sid ${st.Sid})` : "";
    if (st.Condition && typeof st.Condition === "object" && Object.keys(st.Condition as object).length > 0) {
      out.push({ vector: "policy_conditional", detail: `Policy allows ${label} to principal * with a Condition${sid}`, riskScore: 6.0 });
    } else if (actionsAllowWrite(st.Action)) {
      out.push({ vector: "policy_write", detail: `Policy allows write actions (${label}) to principal *${sid}`, riskScore: 9.5 });
    } else {
      out.push({ vector: "policy_read", detail: `Policy allows ${label} to principal *${sid}`, riskScore: 8.0 });
    }
  }
  return out;
}

interface LoosePab {
  BlockPublicAcls?: unknown;
  IgnorePublicAcls?: unknown;
  BlockPublicPolicy?: unknown;
  RestrictPublicBuckets?: unknown;
}

function truthy(v: unknown): boolean {
  return v === true || v === "true" || v === "True" || v === 1 || v === "1";
}

/** True only when every PAB switch is on (mirrors the AWS scanner's `bpaBlocks`). */
export function pabBlocksAll(pab: unknown): boolean {
  if (!pab || typeof pab !== "object") return false;
  const p = pab as LoosePab;
  return truthy(p.BlockPublicAcls) && truthy(p.IgnorePublicAcls) && truthy(p.BlockPublicPolicy) && truthy(p.RestrictPublicBuckets);
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

interface LooseBucket {
  BucketName?: string;
  Name?: string;
  Location?: string;
  CreationDate?: string;
  BucketType?: string;
}

function makeFinding(opts: {
  riskScore: number;
  title: string;
  resourceType: string;
  resourceId: string;
  resourceArn: string;
  region: string;
  description: string;
  impact: string;
  remediationSteps: string[];
}): Finding {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity), provider: "huaweicloud" };
}

function isNoSuchPolicy(err: unknown): boolean {
  const info = classifyHwError(err);
  return info.kind === "not_found" || /NoSuchBucketPolicy/i.test(info.code ?? "") || /NoSuchBucketPolicy/i.test(info.message);
}

function isNoPab(err: unknown): boolean {
  const info = classifyHwError(err);
  return (
    info.kind === "not_found" ||
    info.kind === "not_enabled" || // 405 Method Not Allowed on the real service
    /NoSuchPublicAccessBlockConfiguration|MethodNotAllowed|NotImplemented/i.test(info.code ?? "")
  );
}

export class ObsPublicAccessScanner implements Scanner {
  readonly moduleName = "public_access_verify";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;

    try {
      const creds = hwCredentialsFromContext(ctx, "basic");
      const domainId = await hwDomainIdFromContext(ctx, creds);

      // One OBS client per bucket region (bucket names are global, buckets are regional).
      const clients = new Map<string, Promise<ObsClientInstance>>();
      const clientFor = (region: string): Promise<ObsClientInstance> => {
        let p = clients.get(region);
        if (!p) {
          p = hwObsClient(creds, region);
          clients.set(region, p);
        }
        return p;
      };

      // --- list buckets (account-wide) ---
      let buckets: LooseBucket[];
      try {
        const listResp = await obsCall<{ Buckets?: LooseBucket[] }>(await clientFor(ctx.region), "listBuckets", { QueryLocation: true });
        buckets = Array.isArray(listResp.InterfaceResult?.Buckets) ? listResp.InterfaceResult!.Buckets! : [];
      } catch (err) {
        const { kind } = classifyHwError(err);
        if (kind === "access_denied") {
          warnings.push(`OBS: insufficient permissions to list buckets (${describeHwError(err)}); skipped`);
          return this.result(startMs, findings, warnings, resourcesScanned);
        }
        if (kind === "not_enabled" || kind === "not_found") {
          warnings.push(`OBS: service not enabled or not available (${describeHwError(err)}); skipped`);
          return this.result(startMs, findings, warnings, resourcesScanned);
        }
        throw err;
      }

      if (buckets.length > OBS_MAX_BUCKETS) {
        warnings.push(`OBS: ${buckets.length} buckets found; only the first ${OBS_MAX_BUCKETS} were checked.`);
        buckets = buckets.slice(0, OBS_MAX_BUCKETS);
      }

      // --- per-bucket checks (bounded concurrency) ---
      const tasks = buckets.map((b) => async () => {
        const name = b.BucketName ?? b.Name ?? "unknown";
        const bucketWarnings: string[] = [];
        let region = (b.Location ?? "").trim();
        const client0 = await clientFor(ctx.region);

        if (!region) {
          try {
            const loc = await obsCall<{ Location?: string }>(client0, "getBucketLocation", { Bucket: name });
            region = (loc.InterfaceResult?.Location ?? "").trim();
          } catch (err) {
            bucketWarnings.push(`Failed to detect region for bucket ${name}, using ${ctx.region}: ${describeHwError(err)}`);
          }
          if (!region) region = ctx.region;
        }
        const client = region === ctx.region ? client0 : await clientFor(region);

        // Public Access Block (405 on the real service = feature unavailable → no PAB)
        let pabBlocks = false;
        try {
          const pab = await obsCall(client, "getBucketPublicAccessBlock", { Bucket: name });
          pabBlocks = pabBlocksAll(pab.InterfaceResult);
        } catch (err) {
          if (!isNoPab(err)) {
            const { kind } = classifyHwError(err);
            bucketWarnings.push(
              kind === "access_denied"
                ? `Could not check public access block for bucket ${name} (insufficient permissions): ${describeHwError(err)}`
                : `Could not check public access block for bucket ${name}: ${describeHwError(err)}`,
            );
          }
        }

        const exposures: PublicExposure[] = [];
        let aclChecked = false;
        let policyChecked = false;

        if (!pabBlocks) {
          try {
            const acl = await obsCall(client, "getBucketAcl", { Bucket: name });
            aclChecked = true;
            exposures.push(...evaluateObsAcl(acl.InterfaceResult));
          } catch (err) {
            bucketWarnings.push(`Could not check ACL for bucket ${name}: ${describeHwError(err)}`);
          }

          try {
            const pol = await obsCall<{ Policy?: string }>(client, "getBucketPolicy", { Bucket: name });
            policyChecked = true;
            exposures.push(...evaluateObsPolicy(pol.InterfaceResult?.Policy));
          } catch (err) {
            if (isNoSuchPolicy(err)) {
              policyChecked = true; // no policy is the normal case
            } else {
              bucketWarnings.push(`Could not check policy for bucket ${name}: ${describeHwError(err)}`);
            }
          }
        }

        return { name, region, pabBlocks, aclChecked, policyChecked, exposures, bucketWarnings };
      });

      const settled = await runWithConcurrency(tasks, OBS_BUCKET_CONCURRENCY);

      for (let i = 0; i < settled.length; i++) {
        const r = settled[i];
        const name = buckets[i].BucketName ?? buckets[i].Name ?? "unknown";
        if (r.status === "rejected") {
          warnings.push(`OBS bucket ${name}: check failed: ${describeHwError(r.reason)}`);
          continue;
        }
        const v = r.value;
        warnings.push(...v.bucketWarnings);
        if (v.pabBlocks || v.aclChecked || v.policyChecked) resourcesScanned++;
        if (v.exposures.length === 0) continue;

        const top = v.exposures.reduce((a, b) => (b.riskScore > a.riskScore ? b : a));
        const writable = v.exposures.some((e) => e.vector === "acl_write" || e.vector === "policy_write");
        const conditionalOnly = v.exposures.every((e) => e.vector === "policy_conditional");
        const urn = toResourceUrn("obs", "bucket", v.name, v.region, domainId);
        const evidence = v.exposures.map((e) => e.detail).join("; ");

        findings.push(
          makeFinding({
            riskScore: top.riskScore,
            title: writable
              ? `OBS bucket ${v.name} is publicly writable`
              : conditionalOnly
                ? `OBS bucket ${v.name} grants conditional access to any principal`
                : `OBS bucket ${v.name} is publicly readable`,
            resourceType: "HuaweiCloud::OBS::Bucket",
            resourceId: v.name,
            resourceArn: urn,
            region: v.region,
            description: `OBS bucket "${v.name}" (${v.region}) has public access configuration: ${evidence}. Public Access Block is ${v.pabBlocks ? "fully enabled" : "not fully enabled"}.`,
            impact: writable
              ? "Anyone on the internet can upload, overwrite or delete objects in this bucket (malware hosting, data tampering, ransom) and may read its contents."
              : conditionalOnly
                ? "Any principal satisfying the policy condition can access this bucket; a misconfigured or weak condition exposes its contents to the internet."
                : "Anyone on the internet can read objects from this bucket, potentially exposing sensitive data.",
            remediationSteps: [
              "Enable OBS Public Access Block (block public ACLs and policies) on the bucket.",
              "Remove ACL grants to Everyone / all users and bucket-policy statements with Principal \"*\".",
              "If public read is intended (static website / CDN origin), restrict to specific objects and enable access logging.",
              "Audit bucket contents for sensitive data exposure.",
            ],
          }),
        );
      }

      // Release sockets held by the OBS clients (best effort).
      for (const p of clients.values()) {
        try {
          const c = (await p) as unknown as { close?: () => void };
          if (typeof c.close === "function") c.close();
        } catch {
          /* ignore */
        }
      }

      return this.result(startMs, findings, warnings, resourcesScanned);
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: `OBS public access verification failed: ${describeHwError(err)}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }

  private result(startMs: number, findings: Finding[], warnings: string[], resourcesScanned: number): ScanResult {
    return {
      module: this.moduleName,
      status: "success",
      warnings: warnings.length > 0 ? warnings : undefined,
      resourcesScanned,
      findingsCount: findings.length,
      scanTimeMs: Date.now() - startMs,
      findings,
    };
  }
}
