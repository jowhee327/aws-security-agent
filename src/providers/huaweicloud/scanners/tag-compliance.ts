/**
 * Huawei Cloud tag compliance scanner (moduleName `tag_compliance`).
 *
 * Mirrors `src/scanners/tag-compliance.ts` (EC2 / RDS / S3 required tags).
 * Instead of calling each service, it uses the RMS (Config) resource inventory:
 * `listAllResources` (global endpoint, GlobalCredentials + domain ID) filtered
 * by `region_id` and resource `type`, paginated via `page_info.next_marker`.
 * Resource classes checked (compute / database / storage, mirroring AWS):
 * `ecs.cloudservers`, `rds.instances`, `obs.buckets`, `evs.volumes`.
 *
 * A resource missing any of the required tags (default
 * {@link DEFAULT_REQUIRED_TAGS}, shared with the AWS scanner) → riskScore 4.0.
 * Tag keys are compared case-sensitively, as on AWS.
 *
 * Graceful degradation: 403 / RMS not enabled → warning, status success.
 * Any other failure → status "error". Resources are capped; a warning is
 * emitted when the listing is truncated.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { DEFAULT_REQUIRED_TAGS } from "../../../scanners/tag-compliance.js";
import { severityFromScore, priorityFromSeverity } from "../../../utils/risk-scoring.js";
import { hwClient } from "../client.js";
import { degradeHwError, describeHwError } from "../errors.js";
import { toResourceUrn } from "../urn.js";
import { hwCredentialsFromContext, hwDomainIdFromContext } from "./shared.js";

export { DEFAULT_REQUIRED_TAGS };

export const RMS_RESOURCE_PAGE_SIZE = 200;
export const RMS_MAX_RESOURCES = 2000;
const MAX_PAGES = 100;

/** RMS `provider.type` identifiers checked (same classes as the AWS scanner: compute / db / storage). */
export const HW_TAG_RESOURCE_TYPES: readonly string[] = ["ecs.cloudservers", "rds.instances", "obs.buckets", "evs.volumes"];

/** Human-readable resourceType per RMS type (fallback: `HuaweiCloud::<PROVIDER>::<type>`). */
const RESOURCE_TYPE_LABELS: Readonly<Record<string, { resourceType: string; noun: string }>> = {
  "ecs.cloudservers": { resourceType: "HuaweiCloud::ECS::CloudServer", noun: "ECS server" },
  "rds.instances": { resourceType: "HuaweiCloud::RDS::Instance", noun: "RDS instance" },
  "obs.buckets": { resourceType: "HuaweiCloud::OBS::Bucket", noun: "OBS bucket" },
  "evs.volumes": { resourceType: "HuaweiCloud::EVS::Volume", noun: "EVS volume" },
};

/* ------------------------------------------------------------------------ */
/* Loose SDK response shapes (wire keys; camelCase accepted for fakes)       */
/* ------------------------------------------------------------------------ */

export interface LooseRmsResource {
  id?: string;
  name?: string;
  provider?: string;
  type?: string;
  region_id?: string;
  regionId?: string;
  project_id?: string;
  projectId?: string;
  /** RMS returns tags as a key → value object; arrays of {key,value} are tolerated. */
  tags?: Record<string, unknown> | Array<{ key?: string; Key?: string; value?: unknown }> | null;
}

interface LooseListAllResourcesResponse {
  resources?: LooseRmsResource[];
  page_info?: { next_marker?: string; nextMarker?: string; current_count?: number };
  pageInfo?: { next_marker?: string; nextMarker?: string; currentCount?: number };
}

/** Minimal client surface (tests inject fakes). */
export interface RmsResourcesClient {
  listAllResources(req?: unknown): Promise<unknown>;
}

export interface HuaweiTagComplianceOptions {
  /** Required tag keys (defaults to the AWS scanner's DEFAULT_REQUIRED_TAGS). */
  requiredTags?: string[];
  /** RMS resource types to check (defaults to HW_TAG_RESOURCE_TYPES). */
  resourceTypes?: string[];
}

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

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

/** Tag keys present on an RMS resource (object form or `[{key,value}]` form). */
export function rmsTagKeys(tags: LooseRmsResource["tags"]): Set<string> {
  const keys = new Set<string>();
  if (!tags) return keys;
  if (Array.isArray(tags)) {
    for (const t of tags) {
      const k = t?.key ?? t?.Key;
      if (typeof k === "string" && k) keys.add(k);
    }
    return keys;
  }
  if (typeof tags === "object") {
    for (const k of Object.keys(tags)) if (k) keys.add(k);
  }
  return keys;
}

export function getMissingRmsTags(tags: LooseRmsResource["tags"], requiredTags: readonly string[]): string[] {
  const present = rmsTagKeys(tags);
  return requiredTags.filter((rt) => !present.has(rt));
}

function labelFor(rmsType: string, provider: string, type: string): { resourceType: string; noun: string } {
  return (
    RESOURCE_TYPE_LABELS[rmsType] ?? {
      resourceType: `HuaweiCloud::${provider.toUpperCase()}::${type}`,
      noun: `${provider.toUpperCase()} ${type}`,
    }
  );
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class HuaweiTagComplianceScanner implements Scanner {
  readonly moduleName = "tag_compliance";
  private readonly requiredTags: readonly string[];
  private readonly resourceTypes: readonly string[];

  constructor(opts: HuaweiTagComplianceOptions = {}) {
    this.requiredTags = opts.requiredTags && opts.requiredTags.length > 0 ? [...opts.requiredTags] : DEFAULT_REQUIRED_TAGS;
    this.resourceTypes = opts.resourceTypes && opts.resourceTypes.length > 0 ? [...opts.resourceTypes] : HW_TAG_RESOURCE_TYPES;
  }

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];
    let resourcesScanned = 0;
    const requiredTags = this.requiredTags;

    try {
      const creds = hwCredentialsFromContext(ctx, "global");
      const domainId = await hwDomainIdFromContext(ctx, creds);
      const region = ctx.region;

      try {
        const { ConfigClient } = await import("@huaweicloud/huaweicloud-sdk-config");
        const rms = (await hwClient(ConfigClient, "rms", creds, { region, domainId })) as unknown as RmsResourcesClient;

        let total = 0;
        let truncated = false;

        typeLoop: for (const rmsType of this.resourceTypes) {
          let marker: string | undefined;
          for (let page = 0; page < MAX_PAGES; page++) {
            // Plain-object requests use the wire (snake_case) keys; see ConfigClient.listAllResources.
            const req: Record<string, unknown> = { region_id: region, type: rmsType, limit: RMS_RESOURCE_PAGE_SIZE };
            if (marker !== undefined) req.marker = marker;
            const resp = (await rms.listAllResources(req)) as LooseListAllResourcesResponse | undefined;
            const batch = Array.isArray(resp?.resources) ? resp!.resources! : [];

            for (const res of batch) {
              if (total >= RMS_MAX_RESOURCES) {
                truncated = true;
                break typeLoop;
              }
              total += 1;
              resourcesScanned += 1;

              const provider = res.provider ?? rmsType.split(".")[0] ?? "unknown";
              const type = res.type ?? rmsType.split(".").slice(1).join(".") ?? "resource";
              const id = res.id ?? "unknown";
              const resRegion = res.region_id ?? res.regionId ?? region;
              const { resourceType, noun } = labelFor(`${provider}.${type}`, provider, type);
              const missing = getMissingRmsTags(res.tags, requiredTags);
              if (missing.length === 0) continue;

              const display = res.name && res.name !== id ? `${id} (${res.name})` : id;
              const noTags = rmsTagKeys(res.tags).size === 0;
              findings.push(
                makeFinding({
                  riskScore: 4.0,
                  title: `${noun} ${display} missing required tags: ${missing.join(", ")}`,
                  resourceType,
                  resourceId: id,
                  resourceArn: toResourceUrn(provider, type, id, resRegion, domainId),
                  region: resRegion,
                  description: noTags
                    ? `${noun} "${display}" has no tags configured. Missing all required tags: ${missing.join(", ")}.`
                    : `${noun} "${display}" is missing the following required tags: ${missing.join(", ")}.`,
                  impact:
                    "Resources without proper tags cannot be tracked for cost allocation, ownership, or compliance purposes.",
                  remediationSteps: [
                    `Add the missing tags (${missing.join(", ")}) to ${noun} ${id}.`,
                    "Implement RMS (Config) rules (e.g. required-tag-check) or Organizations tag policies to enforce tagging.",
                    "Use TMS (Tag Management Service) for bulk tagging operations.",
                  ],
                }),
              );
            }

            const pageInfo = resp?.page_info ?? resp?.pageInfo;
            const next = pageInfo?.next_marker ?? pageInfo?.nextMarker;
            if (batch.length === 0 || !next || next === marker) break;
            marker = next;
          }
        }

        if (truncated) {
          warnings.push(`RMS: more than ${RMS_MAX_RESOURCES} resources in ${region}; only the first ${RMS_MAX_RESOURCES} were checked for tag compliance.`);
        }
      } catch (err) {
        const degraded = degradeHwError("RMS", err);
        if (!degraded) throw err;
        warnings.push(degraded);
      }

      return {
        module: this.moduleName,
        status: "success",
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: `Huawei Cloud tag compliance scan failed: ${describeHwError(err)}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }
}
