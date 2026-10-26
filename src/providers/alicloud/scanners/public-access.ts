/**
 * Alibaba Cloud public-access verification (moduleName `public_access_verify`, plan §4.1 P0 / T3).
 * EXPERIMENTAL — not yet validated against a live account.
 *
 * Mirrors `src/scanners/public-access-verify.ts` (S3 + RDS) and the Huawei OBS scanner:
 *
 * OSS (`ali-oss` via {@link aliOssClient}):
 *  - `listBuckets` (marker pagination) returns every bucket of the account; buckets are
 *    filtered to the current scope region (`region` "oss-cn-hangzhou" → "cn-hangzhou").
 *    Buckets without region info are checked only on the primary region scope
 *    (`ctx.primaryRegionScope !== false`) so a multi-region scan reports them once.
 *  - per bucket (concurrency {@link OSS_BUCKET_CONCURRENCY}, cap {@link OSS_MAX_BUCKETS}):
 *    `getBucketInfo` (ACL + `BlockPublicAccess`) and `getBucketPolicy` (`NoSuchBucketPolicy` = no policy).
 *  - ACL `public-read-write` → CRITICAL; `public-read` → HIGH; a policy statement
 *    `Effect: Allow` + `Principal: "*"` (or `{"RAM": ["*"]}`) without an `acs:SourceIp` /
 *    `acs:SourceVpc` condition → HIGH. `BlockPublicAccess=true` overrides public ACLs and
 *    policies: no finding, an informational note in `warnings` instead.
 *
 * RDS (aliCall, centralised `rds.aliyuncs.com` + `RegionId`):
 *  - `DescribeDBInstances` (PageNumber / PageSize, `TotalRecordCount`) → per instance
 *    (concurrency {@link RDS_INSTANCE_CONCURRENCY}, cap {@link RDS_MAX_INSTANCES})
 *    `DescribeDBInstanceNetInfo` (`IPType=Public` connection string) and, for public
 *    instances, `DescribeDBInstanceIPArrayList` (`SecurityIPList` containing `0.0.0.0/0` / `%`).
 *  - public endpoint + fully open whitelist → HIGH (8.0, as AWS "endpoint resolves to public
 *    IP"); public endpoint with a restricted whitelist → MEDIUM.
 *
 * Errors: access denied / not found / throttled / network on a sub-service → warning and
 * skip; **auth_failed (404 InvalidAccessKeyId.NotFound, OSS 403 InvalidAccessKeyId) or
 * api_misuse anywhere → module `status: "error"`**. ali-oss errors are classified and
 * described by the same helpers as SDK errors; raw error objects never reach the result.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { ALI_API } from "../api-catalog.js";
import { aliCall, aliOssClient, aliPaginate } from "../client.js";
import { AliCloudError, classifyAliError, degradeAliError, describeAliError, redactAliDiagnostic } from "../errors.js";
import { toAliUrn } from "../urn.js";
import { aliCallCtx, aliErrorResult, aliField, aliNumber, aliScanEnv, aliString, isAliFatal, type AliScanEnv } from "./shared.js";

export const OSS_MAX_BUCKETS = 500;
export const OSS_BUCKET_CONCURRENCY = 5;
/** listBuckets page size (OSS maximum 1000) and page cap. */
export const OSS_LIST_PAGE_SIZE = 1000;
export const OSS_LIST_MAX_PAGES = 50;

export const RDS_MAX_INSTANCES = 500;
export const RDS_INSTANCE_CONCURRENCY = 5;
export const RDS_PAGE_SIZE = 100;

/** RDS riskScores: aligned with the AWS scanner's verified-public RDS endpoint (8.0). */
export const RDS_PUBLIC_OPEN_RISK = 8.0;
export const RDS_PUBLIC_RESTRICTED_RISK = 5.5;

export const OSS_ACL_PUBLIC_READ_WRITE_RISK = 9.5;
export const OSS_ACL_PUBLIC_READ_RISK = 8.0;
export const OSS_POLICY_PUBLIC_RISK = 8.0;

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity), provider: "alicloud" };
}

function asArray<T = unknown>(v: unknown): T[] {
  if (Array.isArray(v)) return v as T[];
  return v === undefined || v === null ? [] : [v as T];
}

function truthy(v: unknown): boolean {
  return v === true || v === 1 || (typeof v === "string" && /^(true|1)$/i.test(v.trim()));
}

/** Re-wrap any error (ali-oss / SDK / other) as a redacted AliCloudError — never keep the raw object. */
function toAliError(err: unknown, api: string): AliCloudError {
  return err instanceof AliCloudError ? err : new AliCloudError(classifyAliError(err), api);
}

/** Warning for a non-fatal sub-service failure (degradeAliError, or a generic redacted line). */
function softWarning(service: string, err: unknown): string {
  return degradeAliError(service, err) ?? redactAliDiagnostic(`${service}: failed (${describeAliError(err)}); skipped`);
}

/** `oss-cn-hangzhou` → `cn-hangzhou`; empty → undefined. */
export function normalizeOssRegion(v: unknown): string | undefined {
  const s = aliString(v);
  if (!s) return undefined;
  return s.toLowerCase().startsWith("oss-") ? s.slice(4) : s;
}

/* ------------------------------------------------------------------------ */
/* OSS judgement                                                            */
/* ------------------------------------------------------------------------ */

/** ACL from `getBucketInfo().bucket.AccessControlList.Grant` (lower-cased). */
export function ossBucketAcl(bucketInfo: unknown): string | undefined {
  const grant = aliField(aliField(bucketInfo, "AccessControlList"), "Grant");
  return aliString(grant)?.toLowerCase();
}

/** `BlockPublicAccess` flag from `getBucketInfo().bucket`. */
export function ossBlockPublicAccess(bucketInfo: unknown): boolean {
  return truthy(aliField(bucketInfo, "BlockPublicAccess"));
}

export interface OssPolicyExposure {
  /** Statement label (`Sid …` or index) + actions; never contains secrets. */
  detail: string;
}

/** `"*"`, `["*"]`, `{"RAM": ["*"]}`, `{"RAM": "*"}` … */
export function ossPrincipalIsPublic(p: unknown): boolean {
  if (p === "*") return true;
  if (Array.isArray(p)) return p.some((x) => x === "*");
  if (p && typeof p === "object") {
    return Object.values(p as Record<string, unknown>).some((v) => v === "*" || (Array.isArray(v) && v.some((x) => x === "*")));
  }
  return false;
}

const NETWORK_CONDITION_KEYS: ReadonlySet<string> = new Set(["acs:sourceip", "acs:sourcevpc", "acs:sourcevpcid"]);
const OPEN_CIDRS: ReadonlySet<string> = new Set(["0.0.0.0/0", "::/0", "*"]);

/**
 * True when the Condition block restricts the caller network: a positive operator
 * (not `Not*`) on `acs:SourceIp` / `acs:SourceVpc` whose values are not all open (`0.0.0.0/0`).
 */
export function ossConditionRestrictsNetwork(cond: unknown): boolean {
  if (!cond || typeof cond !== "object") return false;
  for (const [op, block] of Object.entries(cond as Record<string, unknown>)) {
    if (/^not/i.test(op) || !block || typeof block !== "object") continue;
    for (const [key, value] of Object.entries(block as Record<string, unknown>)) {
      if (!NETWORK_CONDITION_KEYS.has(key.toLowerCase())) continue;
      const values = asArray(value).filter((v): v is string => typeof v === "string" && v.trim().length > 0);
      if (values.length > 0 && values.some((v) => !OPEN_CIDRS.has(v.trim()))) return true;
    }
  }
  return false;
}

/** Policy (object or JSON string) → public Allow statements lacking a network restriction. */
export function evaluateOssPolicy(policy: unknown): OssPolicyExposure[] {
  let doc: unknown = policy;
  if (typeof policy === "string") {
    if (!policy.trim()) return [];
    try {
      doc = JSON.parse(policy);
    } catch {
      return [];
    }
  }
  if (!doc || typeof doc !== "object") return [];
  const out: OssPolicyExposure[] = [];
  asArray<Record<string, unknown>>(aliField(doc, "Statement")).forEach((st, i) => {
    if (!st || typeof st !== "object") return;
    if ((aliString(st.Effect) ?? "").toLowerCase() !== "allow") return;
    if (!ossPrincipalIsPublic(st.Principal)) return;
    if (ossConditionRestrictsNetwork(st.Condition)) return;
    const actions = asArray(st.Action).filter((a): a is string => typeof a === "string");
    const label = actions.length > 0 ? actions.slice(0, 5).join(", ") + (actions.length > 5 ? ", …" : "") : "(no Action)";
    const sid = aliString(st.Sid);
    out.push({ detail: `statement ${sid ? `Sid ${sid}` : `#${i + 1}`} allows ${label} to Principal "*" without an acs:SourceIp / acs:SourceVpc condition` });
  });
  return out;
}

function isNoSuchPolicy(err: unknown): boolean {
  const info = classifyAliError(err);
  return /^NoSuchBucketPolicy$/i.test(info.code ?? "") || (info.kind === "not_found" && info.status === 404);
}

/* ------------------------------------------------------------------------ */
/* OSS                                                                      */
/* ------------------------------------------------------------------------ */

/** The ali-oss methods used here (ali-oss' typings declare `listBuckets` as returning an array). */
interface OssLike {
  listBuckets(query: Record<string, unknown> | null, options?: Record<string, unknown>): Promise<unknown>;
  getBucketInfo(name: string): Promise<unknown>;
  getBucketPolicy(name: string): Promise<unknown>;
}

interface OssBucketRef {
  name: string;
  region?: string;
}

interface SubResult {
  findings: Finding[];
  warnings: string[];
  resourcesScanned: number;
  /** auth_failed / api_misuse → module error. */
  fatal?: AliCloudError;
}

async function listOssBuckets(oss: OssLike, warnings: string[]): Promise<OssBucketRef[]> {
  const buckets: OssBucketRef[] = [];
  const seen = new Set<string>();
  let marker: string | undefined;
  for (let page = 0; ; page++) {
    if (page >= OSS_LIST_MAX_PAGES) {
      warnings.push(`OSS ListBuckets: stopped after ${OSS_LIST_MAX_PAGES} pages (page cap reached); results may be incomplete`);
      break;
    }
    let res: unknown;
    try {
      res = await oss.listBuckets({ "max-keys": OSS_LIST_PAGE_SIZE, ...(marker ? { marker } : {}) });
    } catch (err) {
      throw toAliError(err, "oss:ListBuckets");
    }
    const raw = Array.isArray(res) ? res : asArray(aliField(res, "buckets"));
    for (const b of raw) {
      const name = aliString(aliField(b, "name") ?? aliField(b, "Name"));
      if (!name) continue;
      buckets.push({ name, region: normalizeOssRegion(aliField(b, "region") ?? aliField(b, "Location")) });
    }
    const next = truthy(aliField(res, "isTruncated")) ? aliString(aliField(res, "nextMarker")) : undefined;
    if (!next) break;
    if (seen.has(next) || next === marker) {
      warnings.push("OSS ListBuckets: pagination marker repeated; stopped to avoid an infinite loop");
      break;
    }
    seen.add(next);
    marker = next;
  }
  return buckets;
}

interface BucketOutcome {
  name: string;
  checked: boolean;
  acl?: string;
  blockPublicAccess: boolean;
  policyExposures: OssPolicyExposure[];
  warnings: string[];
}

async function checkBucket(oss: OssLike, name: string): Promise<BucketOutcome> {
  const out: BucketOutcome = { name, checked: false, blockPublicAccess: false, policyExposures: [], warnings: [] };

  try {
    const res = await oss.getBucketInfo(name);
    const info = aliField(res, "bucket") ?? aliField(res, "Bucket");
    out.acl = ossBucketAcl(info);
    out.blockPublicAccess = ossBlockPublicAccess(info);
    out.checked = true;
  } catch (err) {
    if (isAliFatal(err)) throw toAliError(err, "oss:GetBucketInfo");
    if (classifyAliError(err).kind === "not_found") return out; // bucket deleted meanwhile
    out.warnings.push(softWarning(`OSS bucket ${name} GetBucketInfo`, err));
  }

  try {
    const res = await oss.getBucketPolicy(name);
    out.policyExposures = evaluateOssPolicy(aliField(res, "policy"));
    out.checked = true;
  } catch (err) {
    if (isAliFatal(err)) throw toAliError(err, "oss:GetBucketPolicy");
    if (isNoSuchPolicy(err)) {
      out.checked = true; // no policy is the normal case
    } else {
      out.warnings.push(softWarning(`OSS bucket ${name} GetBucketPolicy`, err));
    }
  }
  return out;
}

const OSS_REMEDIATION = [
  "Enable Block Public Access on the bucket (OSS console → Bucket → Permission Control → Block Public Access).",
  "Set the bucket ACL to private.",
  'Remove bucket-policy statements granting Principal "*" or restrict them with acs:SourceIp / acs:SourceVpc conditions.',
  "If public read is intended (static website / CDN origin), serve it through CDN with origin access restrictions and enable access logging.",
  "Audit bucket contents for sensitive data exposure.",
];

async function scanOss(ctx: ScanContext, env: AliScanEnv): Promise<SubResult> {
  const r: SubResult = { findings: [], warnings: [], resourcesScanned: 0 };
  const region = ctx.region;
  const primary = ctx.primaryRegionScope !== false;

  let oss: OssLike;
  let all: OssBucketRef[];
  try {
    oss = (await aliOssClient(env.credentials, region)) as unknown as OssLike;
    all = await listOssBuckets(oss, r.warnings);
  } catch (err) {
    if (isAliFatal(err)) return { ...r, fatal: toAliError(err, "oss:ListBuckets") };
    r.warnings.push(softWarning("OSS ListBuckets", err));
    return r;
  }

  let buckets = all.filter((b) => (b.region ? b.region === region : primary));
  if (buckets.length > OSS_MAX_BUCKETS) {
    r.warnings.push(`OSS: ${buckets.length} buckets in ${region}; only the first ${OSS_MAX_BUCKETS} were checked.`);
    buckets = buckets.slice(0, OSS_MAX_BUCKETS);
  }

  const settled = await runWithConcurrency(
    buckets.map((b) => () => checkBucket(oss, b.name)),
    OSS_BUCKET_CONCURRENCY,
  );

  for (let i = 0; i < settled.length; i++) {
    const s = settled[i];
    const bucket = buckets[i];
    const bucketRegion = bucket.region ?? region;
    if (s.status === "rejected") {
      if (isAliFatal(s.reason)) return { ...r, fatal: toAliError(s.reason, "oss:bucket") };
      r.warnings.push(softWarning(`OSS bucket ${bucket.name}`, s.reason));
      continue;
    }
    const v = s.value;
    r.warnings.push(...v.warnings);
    if (v.checked) r.resourcesScanned++;

    const urn = toAliUrn("oss", "bucket", v.name, bucketRegion, env.accountId);
    const aclPublic = v.acl === "public-read-write" || v.acl === "public-read";

    if (v.blockPublicAccess) {
      const overridden = [
        aclPublic ? `ACL ${v.acl}` : undefined,
        v.policyExposures.length > 0 ? `${v.policyExposures.length} public bucket-policy statement(s)` : undefined,
      ].filter(Boolean);
      if (overridden.length > 0) {
        r.warnings.push(
          `OSS bucket ${v.name} (${bucketRegion}): ${overridden.join(" and ")} suppressed — Block Public Access is enabled, so public access is blocked (informational).`,
        );
      }
      continue;
    }

    if (aclPublic) {
      const writable = v.acl === "public-read-write";
      r.findings.push(
        makeFinding({
          riskScore: writable ? OSS_ACL_PUBLIC_READ_WRITE_RISK : OSS_ACL_PUBLIC_READ_RISK,
          title: writable ? `OSS bucket ${v.name} is publicly writable (ACL public-read-write)` : `OSS bucket ${v.name} is publicly readable (ACL public-read)`,
          resourceType: "ACS::OSS::Bucket",
          resourceId: v.name,
          resourceArn: urn,
          region: bucketRegion,
          description: `OSS bucket "${v.name}" (${bucketRegion}) has bucket ACL "${v.acl}" and Block Public Access is not enabled.`,
          impact: writable
            ? "Anyone on the internet can upload, overwrite or delete objects in this bucket (malware hosting, data tampering, ransom, cost abuse) and can read its contents."
            : "Anyone on the internet can read (and list) objects in this bucket, potentially exposing sensitive data.",
          remediationSteps: OSS_REMEDIATION,
        }),
      );
    }

    if (v.policyExposures.length > 0) {
      r.findings.push(
        makeFinding({
          riskScore: OSS_POLICY_PUBLIC_RISK,
          title: `OSS bucket ${v.name} policy grants access to any principal`,
          resourceType: "ACS::OSS::Bucket",
          resourceId: v.name,
          resourceArn: urn,
          region: bucketRegion,
          description: `OSS bucket "${v.name}" (${bucketRegion}) bucket policy: ${v.policyExposures.map((e) => e.detail).join("; ")}. Block Public Access is not enabled.`,
          impact: "Anonymous users or any Alibaba Cloud account can perform the allowed OSS actions on this bucket from any network.",
          remediationSteps: OSS_REMEDIATION,
        }),
      );
    }
  }
  return r;
}

/* ------------------------------------------------------------------------ */
/* RDS                                                                      */
/* ------------------------------------------------------------------------ */

/** Whitelist entries that open the instance to every address. */
const RDS_OPEN_ENTRIES: ReadonlySet<string> = new Set(["0.0.0.0/0", "%", "::/0"]);

/** Public connection strings from `DescribeDBInstanceNetInfo` (`IPType=Public`). */
export function rdsPublicEndpoints(body: unknown): string[] {
  const infos = asArray(aliField(aliField(body, "DBInstanceNetInfos"), "DBInstanceNetInfo"));
  const out: string[] = [];
  for (const n of infos) {
    if ((aliString(aliField(n, "IPType")) ?? "").toLowerCase() !== "public") continue;
    const cs = aliString(aliField(n, "ConnectionString"));
    if (!cs) continue;
    const port = aliString(aliField(n, "Port"));
    out.push(port ? `${cs}:${port}` : cs);
  }
  return out;
}

/** Whitelist groups (`DBInstanceIPArrayName`) whose `SecurityIPList` contains 0.0.0.0/0 or `%`. */
export function rdsOpenWhitelistGroups(body: unknown): string[] {
  const groups = asArray(aliField(aliField(body, "Items"), "DBInstanceIPArray"));
  const out: string[] = [];
  for (const g of groups) {
    const list = aliString(aliField(g, "SecurityIPList")) ?? "";
    const entries = list.split(/[\s,]+/).map((e) => e.trim()).filter(Boolean);
    if (entries.some((e) => RDS_OPEN_ENTRIES.has(e))) out.push(aliString(aliField(g, "DBInstanceIPArrayName")) ?? "default");
  }
  return out;
}

interface RdsOutcome {
  id: string;
  checked: boolean;
  publicEndpoints: string[];
  openGroups: string[];
  /** Whitelist could not be read (finding is emitted as public-only). */
  whitelistUnknown: boolean;
  warnings: string[];
}

async function checkRdsInstance(env: AliScanEnv, region: string, id: string): Promise<RdsOutcome> {
  const out: RdsOutcome = { id, checked: false, publicEndpoints: [], openGroups: [], whitelistUnknown: false, warnings: [] };
  const callCtx = aliCallCtx(env, region);

  try {
    const net = await aliCall(ALI_API.rds.DescribeDBInstanceNetInfo, callCtx, { DBInstanceId: id });
    out.publicEndpoints = rdsPublicEndpoints(net);
    out.checked = true;
  } catch (err) {
    if (isAliFatal(err)) throw toAliError(err, "rds:DescribeDBInstanceNetInfo");
    if (classifyAliError(err).kind !== "not_found") out.warnings.push(softWarning(`RDS ${id} DescribeDBInstanceNetInfo`, err));
    return out;
  }
  if (out.publicEndpoints.length === 0) return out;

  try {
    const ips = await aliCall(ALI_API.rds.DescribeDBInstanceIPArrayList, callCtx, { DBInstanceId: id });
    out.openGroups = rdsOpenWhitelistGroups(ips);
  } catch (err) {
    if (isAliFatal(err)) throw toAliError(err, "rds:DescribeDBInstanceIPArrayList");
    out.whitelistUnknown = true;
    out.warnings.push(softWarning(`RDS ${id} DescribeDBInstanceIPArrayList`, err));
  }
  return out;
}

const RDS_REMEDIATION = [
  "Release the public (Internet) connection string if it is not required (RDS console → Database Connection → Release Internet Address).",
  "Remove 0.0.0.0/0 and % from every IP whitelist group; allow only specific office / bastion IPs.",
  "Access the database from inside the VPC (ECS, VPN Gateway, Express Connect or a bastion host).",
  "Enforce SSL and strong credentials; monitor login failures with SQL Explorer / audit logs.",
];

async function scanRds(ctx: ScanContext, env: AliScanEnv): Promise<SubResult> {
  const r: SubResult = { findings: [], warnings: [], resourcesScanned: 0 };
  const region = ctx.region;

  let instances: Array<{ id: string; engine?: string }>;
  try {
    const page = await aliPaginate<unknown, unknown>({
      style: "page",
      label: "RDS DescribeDBInstances",
      pageSize: RDS_PAGE_SIZE,
      maxItems: RDS_MAX_INSTANCES,
      fetch: (q) => aliCall(ALI_API.rds.DescribeDBInstances, aliCallCtx(env, region), { RegionId: region, ...q }),
      items: (body) => asArray(aliField(aliField(body, "Items"), "DBInstance")),
      totalCount: (body) => aliNumber(aliField(body, "TotalRecordCount")),
    });
    r.warnings.push(...page.warnings);
    instances = page.items.flatMap((i) => {
      const id = aliString(aliField(i, "DBInstanceId"));
      return id ? [{ id, engine: aliString(aliField(i, "Engine")) }] : [];
    });
  } catch (err) {
    if (isAliFatal(err)) return { ...r, fatal: toAliError(err, "rds:DescribeDBInstances") };
    r.warnings.push(softWarning("RDS DescribeDBInstances", err));
    return r;
  }

  const settled = await runWithConcurrency(
    instances.map((inst) => () => checkRdsInstance(env, region, inst.id)),
    RDS_INSTANCE_CONCURRENCY,
  );

  for (let i = 0; i < settled.length; i++) {
    const s = settled[i];
    const inst = instances[i];
    if (s.status === "rejected") {
      if (isAliFatal(s.reason)) return { ...r, fatal: toAliError(s.reason, "rds:instance") };
      r.warnings.push(softWarning(`RDS ${inst.id}`, s.reason));
      continue;
    }
    const v = s.value;
    r.warnings.push(...v.warnings);
    if (v.checked) r.resourcesScanned++;
    if (v.publicEndpoints.length === 0) continue;

    const open = v.openGroups.length > 0;
    const engine = inst.engine ? ` (${inst.engine})` : "";
    const endpoints = v.publicEndpoints.join(", ");
    const whitelistNote = open
      ? `IP whitelist group(s) ${v.openGroups.join(", ")} allow 0.0.0.0/0 (or %), so any internet address can connect.`
      : v.whitelistUnknown
        ? "The IP whitelist could not be read; verify it does not allow 0.0.0.0/0."
        : "The IP whitelist does not contain 0.0.0.0/0 or %, which limits exposure to the listed addresses.";
    r.findings.push(
      makeFinding({
        riskScore: open ? RDS_PUBLIC_OPEN_RISK : RDS_PUBLIC_RESTRICTED_RISK,
        title: open
          ? `RDS instance ${v.id} is publicly accessible from any IP (public endpoint + 0.0.0.0/0 whitelist)`
          : `RDS instance ${v.id} has a public (Internet) endpoint`,
        resourceType: "ACS::RDS::DBInstance",
        resourceId: v.id,
        resourceArn: toAliUrn("rds", "dbinstance", v.id, region, env.accountId),
        region,
        description: `RDS instance ${v.id}${engine} has public connection string(s) ${endpoints}. ${whitelistNote}`,
        impact: open
          ? "The database can be reached from the public internet, making it vulnerable to brute-force, credential stuffing, and exploitation of database vulnerabilities."
          : "The database has an internet-facing endpoint; a whitelist change or a compromised whitelisted address exposes it to brute-force and exploitation of database vulnerabilities.",
        remediationSteps: RDS_REMEDIATION,
      }),
    );
  }
  return r;
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class AliPublicAccessScanner implements Scanner {
  readonly moduleName = "public_access_verify";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];
    const findings: Finding[] = [];
    let resourcesScanned = 0;

    try {
      const env = aliScanEnv(ctx);

      for (const [label, run] of [
        ["OSS public access check failed", scanOss],
        ["RDS public access check failed", scanRds],
      ] as const) {
        const sub = await run(ctx, env);
        warnings.push(...sub.warnings);
        if (sub.fatal) return aliErrorResult(this.moduleName, startMs, label, sub.fatal, warnings);
        findings.push(...sub.findings);
        resourcesScanned += sub.resourcesScanned;
      }

      return {
        module: this.moduleName,
        status: "success",
        ...(warnings.length > 0 ? { warnings } : {}),
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return aliErrorResult(this.moduleName, startMs, "Public access verification failed", err, warnings);
    }
  }
}
