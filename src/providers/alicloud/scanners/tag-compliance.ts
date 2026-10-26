/**
 * Alibaba Cloud tag compliance scanner (moduleName `tag_compliance`, plan §4.1 P1 / T5).
 * EXPERIMENTAL — not yet validated against a live account.
 *
 * Mirrors `src/scanners/tag-compliance.ts`: every resource missing one of the AWS
 * {@link DEFAULT_REQUIRED_TAGS} (case-sensitive key match, as AWS) → MEDIUM 4.0.
 *  - ECS `DescribeInstances` and `DescribeDisks` (`Tags.Tag[]` {TagKey, TagValue}, inline).
 *  - SLB `DescribeLoadBalancers` (2014-05-15, `Tags.Tag[]` inline).
 *  - RDS `DescribeDBInstances` (PageNumber / PageSize, `TotalRecordCount`); the list does not
 *    return tags, so ONE region-level RDS `DescribeTags` (no `DBInstanceId` → tags of all
 *    instances, `Items.TagInfos[]` with `DBInstanceIds`) builds the instance → keys map
 *    (avoids N+1). If DescribeTags fails the RDS instances are NOT reported (no false
 *    positives), only a warning. Inline `Tags.Tag[]` is honoured when present.
 *  - OSS `listBuckets` → buckets of the scope region (region-less buckets on the primary
 *    scope only, as public_access_verify) → per bucket (concurrency
 *    {@link TAG_OSS_CONCURRENCY}, cap {@link TAG_OSS_MAX_BUCKETS}) `getBucketTags`
 *    (`{ tag: { key: value } }`; `NoSuchTagSet` = no tags).
 *
 * Errors: access denied / not enabled / throttled / network on a resource type → warning and
 * skip that type; **auth_failed or api_misuse anywhere → module `status: "error"`**. Every
 * cloud-sourced string (ids, names, tag keys) in a Finding / warning passes through
 * redactAliDiagnostic.
 */
import type { Scanner } from "../../../scanners/base.js";
import { DEFAULT_REQUIRED_TAGS } from "../../../scanners/tag-compliance.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { ALI_API } from "../api-catalog.js";
import { aliCall, aliOssClient } from "../client.js";
import { classifyAliError, type AliCloudError } from "../errors.js";
import { toAliUrn } from "../urn.js";
import { listOssBuckets, type OssBucketRef } from "./public-access.js";
import {
  aliArray,
  aliCallCtx,
  aliErrorResult,
  aliField,
  aliScanEnv,
  aliSoftWarning,
  aliString,
  aliUntrusted,
  isAliFatal,
  listAliEcsInstances,
  listAliPaged,
  toAliError,
  type AliScanEnv,
} from "./shared.js";

export const TAG_RISK = 4.0;
export const TAG_PAGE_SIZE = 100;
export const TAG_MAX_ITEMS = 1000;
export const TAG_OSS_MAX_BUCKETS = 500;
export const TAG_OSS_CONCURRENCY = 5;

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity), provider: "alicloud" };
}

interface SubResult {
  findings: Finding[];
  warnings: string[];
  resourcesScanned: number;
  fatal?: AliCloudError;
}

const emptySub = (): SubResult => ({ findings: [], warnings: [], resourcesScanned: 0 });

function failSub(r: SubResult, label: string, api: string, err: unknown): SubResult {
  if (isAliFatal(err)) return { ...r, fatal: toAliError(err, api) };
  r.warnings.push(aliSoftWarning(label, err));
  return r;
}

/**
 * Tag keys from an inline `Tags` container (`{ Tag: [{ TagKey, TagValue }] }`; also accepts
 * `Key` and a bare array). Undefined when the container is absent.
 */
export function aliTagKeys(container: unknown): string[] | undefined {
  if (container === undefined || container === null) return undefined;
  const list = Array.isArray(container) ? container : aliField(container, "Tag");
  return aliArray(list).flatMap((t) => {
    const k = aliString(aliField(t, "TagKey") ?? aliField(t, "Key"));
    return k ? [k] : [];
  });
}

/** Required tags absent from `keys` (case-sensitive, as the AWS scanner). */
export function missingRequiredTags(keys: readonly string[], required: readonly string[] = DEFAULT_REQUIRED_TAGS): string[] {
  const have = new Set(keys);
  return required.filter((t) => !have.has(t));
}

interface TagTarget {
  /** Already redacted. */
  id: string;
  /** Already redacted. */
  name?: string;
  region: string;
  keys: string[];
}

interface ResourceKind {
  label: string;
  resourceType: string;
  urnSvc: string;
  urnType: string;
  where: string;
}

function tagFinding(kind: ResourceKind, t: TagTarget, missing: string[], accountId: string): Finding {
  const list = missing.join(", ");
  const named = t.name && t.name !== t.id ? ` (${t.name})` : "";
  return makeFinding({
    riskScore: TAG_RISK,
    title: `${kind.label} ${t.id} missing required tags: ${list}`,
    resourceType: kind.resourceType,
    resourceId: t.id,
    resourceArn: toAliUrn(kind.urnSvc, kind.urnType, t.id, t.region, accountId),
    region: t.region,
    description:
      t.keys.length === 0
        ? `${kind.label} "${t.id}"${named} has no tags configured. Missing all required tags: ${list}.`
        : `${kind.label} "${t.id}"${named} is missing the following required tags: ${list}.`,
    impact: "Resources without proper tags cannot be tracked for cost allocation, ownership, or compliance purposes.",
    remediationSteps: [
      `Add the missing tags (${list}) to ${kind.where} ${t.id}.`,
      "Enforce tagging with Resource Management Tag Policies or Cloud Config rules (e.g. required-tags).",
      "Use the Tag Editor (Resource Management → Tags) for bulk tagging operations.",
    ],
  });
}

function evaluate(kind: ResourceKind, targets: TagTarget[], accountId: string, r: SubResult): void {
  for (const t of targets) {
    r.resourcesScanned++;
    const missing = missingRequiredTags(t.keys);
    if (missing.length > 0) r.findings.push(tagFinding(kind, t, missing, accountId));
  }
}

const redactKeys = (keys: string[] | undefined): string[] => (keys ?? []).map((k) => aliUntrusted(k) ?? k);

/* ------------------------------------------------------------------------ */
/* ECS / SLB (inline tags)                                                  */
/* ------------------------------------------------------------------------ */

const ECS_INSTANCE: ResourceKind = { label: "ECS instance", resourceType: "ACS::ECS::Instance", urnSvc: "ecs", urnType: "instance", where: "instance" };
const ECS_DISK: ResourceKind = { label: "ECS disk", resourceType: "ACS::ECS::Disk", urnSvc: "ecs", urnType: "disk", where: "disk" };
const SLB_LB: ResourceKind = { label: "SLB load balancer", resourceType: "ACS::SLB::LoadBalancer", urnSvc: "slb", urnType: "loadbalancer", where: "load balancer" };
const RDS_DB: ResourceKind = { label: "RDS instance", resourceType: "ACS::RDS::DBInstance", urnSvc: "rds", urnType: "dbinstance", where: "instance" };
const OSS_BUCKET: ResourceKind = { label: "OSS bucket", resourceType: "ACS::OSS::Bucket", urnSvc: "oss", urnType: "bucket", where: "bucket" };

function inlineTargets(items: Record<string, unknown>[], idKey: string, nameKey: string, region: string): TagTarget[] {
  return items.flatMap((i) => {
    const id = aliUntrusted(i[idKey]);
    return id ? [{ id, name: aliUntrusted(i[nameKey]), region, keys: redactKeys(aliTagKeys(i.Tags)) }] : [];
  });
}

async function scanEcsInstances(env: AliScanEnv, region: string): Promise<SubResult> {
  const r = emptySub();
  try {
    const list = await listAliEcsInstances(env, region);
    r.warnings.push(...list.warnings);
    evaluate(ECS_INSTANCE, inlineTargets(list.instances, "InstanceId", "InstanceName", region), env.accountId, r);
    return r;
  } catch (err) {
    return failSub(r, "ECS DescribeInstances", "ecs:DescribeInstances", err);
  }
}

async function scanEcsDisks(env: AliScanEnv, region: string): Promise<SubResult> {
  const r = emptySub();
  try {
    const page = await listAliPaged(ALI_API.ecs.DescribeDisks, env, region, {
      label: "ECS DescribeDisks",
      listKey: "Disks",
      itemKey: "Disk",
      pageSize: TAG_PAGE_SIZE,
      maxItems: TAG_MAX_ITEMS,
    });
    r.warnings.push(...page.warnings);
    evaluate(ECS_DISK, inlineTargets(page.items, "DiskId", "DiskName", region), env.accountId, r);
    return r;
  } catch (err) {
    return failSub(r, "ECS DescribeDisks", "ecs:DescribeDisks", err);
  }
}

async function scanSlb(env: AliScanEnv, region: string): Promise<SubResult> {
  const r = emptySub();
  try {
    const page = await listAliPaged(ALI_API.slb.DescribeLoadBalancers, env, region, {
      label: "SLB DescribeLoadBalancers",
      listKey: "LoadBalancers",
      itemKey: "LoadBalancer",
      pageSize: TAG_PAGE_SIZE,
      maxItems: TAG_MAX_ITEMS,
    });
    r.warnings.push(...page.warnings);
    evaluate(SLB_LB, inlineTargets(page.items, "LoadBalancerId", "LoadBalancerName", region), env.accountId, r);
    return r;
  } catch (err) {
    return failSub(r, "SLB DescribeLoadBalancers", "slb:DescribeLoadBalancers", err);
  }
}

/* ------------------------------------------------------------------------ */
/* RDS (DescribeDBInstances + region-level DescribeTags)                    */
/* ------------------------------------------------------------------------ */

/** RDS DescribeTags body → instanceId → tag keys (`Items.TagInfos[]`, `DBInstanceIds.DBInstanceIds[]`). */
export function rdsTagMap(body: unknown): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const items = aliField(body, "Items");
  const infos = aliArray(aliField(items, "TagInfos") ?? aliField(items, "TagInfo"));
  for (const info of infos) {
    const key = aliString(aliField(info, "TagKey"));
    if (!key) continue;
    const idsField = aliField(info, "DBInstanceIds");
    const ids = Array.isArray(idsField) ? idsField : aliArray(aliField(idsField, "DBInstanceIds"));
    for (const raw of ids) {
      const id = aliString(raw);
      if (!id) continue;
      const keys = out.get(id) ?? [];
      keys.push(key);
      out.set(id, keys);
    }
  }
  return out;
}

async function scanRds(env: AliScanEnv, region: string): Promise<SubResult> {
  const r = emptySub();
  let items: Record<string, unknown>[];
  try {
    const page = await listAliPaged(ALI_API.rds.DescribeDBInstances, env, region, {
      label: "RDS DescribeDBInstances",
      listKey: "Items",
      itemKey: "DBInstance",
      pageSize: TAG_PAGE_SIZE,
      maxItems: TAG_MAX_ITEMS,
      totalKey: "TotalRecordCount",
    });
    r.warnings.push(...page.warnings);
    items = page.items;
  } catch (err) {
    return failSub(r, "RDS DescribeDBInstances", "rds:DescribeDBInstances", err);
  }
  if (items.length === 0) return r;

  let tagMap: Map<string, string[]> | undefined;
  if (items.some((i) => aliTagKeys(i.Tags) === undefined)) {
    try {
      tagMap = rdsTagMap(await aliCall(ALI_API.rds.DescribeTags, aliCallCtx(env, region), { RegionId: region }));
    } catch (err) {
      return failSub(r, "RDS DescribeTags (instance tags not evaluated)", "rds:DescribeTags", err);
    }
  }

  const targets: TagTarget[] = items.flatMap((i) => {
    const rawId = aliString(i.DBInstanceId);
    const id = aliUntrusted(rawId);
    if (!rawId || !id) return [];
    const keys = aliTagKeys(i.Tags) ?? tagMap?.get(rawId) ?? [];
    return [{ id, name: aliUntrusted(i.DBInstanceDescription), region, keys: redactKeys(keys) }];
  });
  evaluate(RDS_DB, targets, env.accountId, r);
  return r;
}

/* ------------------------------------------------------------------------ */
/* OSS (getBucketTags per bucket)                                           */
/* ------------------------------------------------------------------------ */

interface OssTagLike {
  listBuckets(query: Record<string, unknown> | null, options?: Record<string, unknown>): Promise<unknown>;
  getBucketTags(name: string): Promise<unknown>;
}

function isNoTagSet(err: unknown): boolean {
  return /^NoSuchTag(Set|ging)?$/i.test(classifyAliError(err).code ?? "");
}

/** Tag keys of one bucket; `[]` when it has no tags. Throws (raw) on other errors. */
async function bucketTagKeys(oss: OssTagLike, name: string): Promise<string[]> {
  try {
    // ali-oss returns `{ tag: { key: value } }` (formatTag of the TagSet).
    const tag = aliField(await oss.getBucketTags(name), "tag");
    return tag && typeof tag === "object" ? Object.keys(tag as Record<string, unknown>).filter((k) => k.length > 0) : [];
  } catch (err) {
    if (isNoTagSet(err)) return [];
    throw err;
  }
}

async function scanOss(ctx: ScanContext, env: AliScanEnv): Promise<SubResult> {
  const r = emptySub();
  const region = ctx.region;
  const primary = ctx.primaryRegionScope !== false;

  let oss: OssTagLike;
  let all: OssBucketRef[];
  try {
    oss = (await aliOssClient(env.credentials, region)) as unknown as OssTagLike;
    all = await listOssBuckets(oss, r.warnings);
  } catch (err) {
    return failSub(r, "OSS ListBuckets", "oss:ListBuckets", err);
  }

  let buckets = all.filter((b) => (b.region ? b.region === region : primary));
  if (buckets.length > TAG_OSS_MAX_BUCKETS) {
    r.warnings.push(`OSS: ${buckets.length} buckets in ${region}; only the first ${TAG_OSS_MAX_BUCKETS} were checked for tags.`);
    buckets = buckets.slice(0, TAG_OSS_MAX_BUCKETS);
  }

  const settled = await runWithConcurrency(
    buckets.map((b) => () => bucketTagKeys(oss, b.name)),
    TAG_OSS_CONCURRENCY,
  );

  const targets: TagTarget[] = [];
  for (let i = 0; i < settled.length; i++) {
    const s = settled[i];
    const b = buckets[i];
    const name = aliUntrusted(b.name) ?? "unknown";
    if (s.status === "rejected") {
      if (isAliFatal(s.reason)) return { ...r, fatal: toAliError(s.reason, "oss:GetBucketTags") };
      if (classifyAliError(s.reason).kind === "not_found") continue; // bucket deleted meanwhile
      r.warnings.push(aliSoftWarning(`OSS bucket ${name} GetBucketTags`, s.reason));
      continue;
    }
    targets.push({ id: name, region: b.region ?? region, keys: redactKeys(s.value) });
  }
  evaluate(OSS_BUCKET, targets, env.accountId, r);
  return r;
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class AliTagComplianceScanner implements Scanner {
  readonly moduleName = "tag_compliance";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];
    const findings: Finding[] = [];
    let resourcesScanned = 0;

    try {
      const env = aliScanEnv(ctx);
      const region = ctx.region;

      const steps: ReadonlyArray<readonly [string, () => Promise<SubResult>]> = [
        ["ECS instance tag compliance check failed", () => scanEcsInstances(env, region)],
        ["ECS disk tag compliance check failed", () => scanEcsDisks(env, region)],
        ["SLB tag compliance check failed", () => scanSlb(env, region)],
        ["RDS tag compliance check failed", () => scanRds(env, region)],
        ["OSS tag compliance check failed", () => scanOss(ctx, env)],
      ];
      for (const [label, run] of steps) {
        const sub = await run();
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
      return aliErrorResult(this.moduleName, startMs, "Tag compliance check failed", err, warnings);
    }
  }
}
