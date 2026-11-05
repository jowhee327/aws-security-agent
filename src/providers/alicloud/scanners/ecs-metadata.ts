/**
 * Alibaba Cloud ECS metadata hardening scanner (moduleName `imdsv2_enforcement`, plan §4.1 P1 / T4).
 * EXPERIMENTAL — not yet validated against a live account.
 *
 * Mirrors `src/scanners/imdsv2-enforcement.ts`: ECS `DescribeInstances` (Status=Running,
 * PageNumber / PageSize) returns `MetadataOptions` in the list response (no N+1).
 *  - `HttpTokens != "required"` AND `HttpEndpoint != "disabled"` → finding (security-hardened
 *    metadata mode not enforced; normal mode allows unauthenticated metadata requests);
 *    riskScore 7.5 as AWS.
 *  - `HttpEndpoint == "disabled"` → metadata service unreachable, no finding.
 *  - `MetadataOptions` / `HttpTokens` missing → treated as `optional` (the ECS default) and
 *    reported in one aggregated warning.
 *  - `HttpPutResponseHopLimit > 1` is called out in the description, or — for hardened
 *    instances — as an informational warning (as AWS).
 *
 * Errors: auth_failed / api_misuse → module `status: "error"`; access denied / not
 * enabled / throttled / network → warning + success with 0 findings.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { degradeAliError, describeAliError, redactAliDiagnostic } from "../errors.js";
import { toAliUrn } from "../urn.js";
import {
  aliErrorResult,
  aliField,
  aliNumber,
  aliSafeFinding,
  aliSafeWarnings,
  aliScanEnv,
  aliUntrusted,
  isAliFatal,
  listAliEcsInstances,
} from "./shared.js";

/** Aligned with the AWS imdsv2_enforcement finding. */
export const ECS_METADATA_NOT_HARDENED_RISK = 7.5;

export interface AliMetadataVerdict {
  /** Effective HttpTokens (missing → "optional"). */
  httpTokens: string;
  httpEndpoint: string;
  hopLimit: number;
  /** MetadataOptions (or HttpTokens) absent from the response. */
  missing: boolean;
  /** Finding required: hardened mode not enforced while the endpoint is reachable. */
  notHardened: boolean;
}

/** Evaluate one `DescribeInstances` entry's `MetadataOptions`. */
export function evaluateAliMetadataOptions(instance: unknown): AliMetadataVerdict {
  const opts = aliField(instance, "MetadataOptions");
  // Server-sourced: redacted BEFORE lower-casing (httpTokens is echoed in the description).
  const rawTokens = aliUntrusted(aliField(opts, "HttpTokens"));
  const httpTokens = (rawTokens ?? "optional").toLowerCase();
  const httpEndpoint = (aliUntrusted(aliField(opts, "HttpEndpoint")) ?? "enabled").toLowerCase();
  const hopLimit = aliNumber(aliField(opts, "HttpPutResponseHopLimit")) ?? 1;
  return {
    httpTokens,
    httpEndpoint,
    hopLimit,
    missing: rawTokens === undefined,
    notHardened: httpTokens !== "required" && httpEndpoint !== "disabled",
  };
}

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return aliSafeFinding({ ...opts, severity, priority: priorityFromSeverity(severity), provider: "alicloud" });
}

export class AliEcsMetadataScanner implements Scanner {
  readonly moduleName = "imdsv2_enforcement";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];
    const findings: Finding[] = [];
    const region = ctx.region;

    try {
      const env = aliScanEnv(ctx);

      let instances: Record<string, unknown>[];
      try {
        const list = await listAliEcsInstances(env, region, { Status: "Running" });
        warnings.push(...list.warnings);
        instances = list.instances;
      } catch (err) {
        if (isAliFatal(err)) return aliErrorResult(this.moduleName, startMs, "ECS metadata check failed", err, warnings);
        warnings.push(degradeAliError("ECS DescribeInstances", err) ?? redactAliDiagnostic(`ECS DescribeInstances: failed (${describeAliError(err)}); skipped`));
        return {
          module: this.moduleName,
          status: "success",
          warnings: aliSafeWarnings(warnings),
          resourcesScanned: 0,
          findingsCount: 0,
          scanTimeMs: Date.now() - startMs,
          findings,
        };
      }

      const missing: string[] = [];
      let scanned = 0;
      for (const inst of instances) {
        // Every instance field below is server-sourced: only redacted forms are emitted.
        const id = aliUntrusted(inst.InstanceId);
        if (!id) continue;
        scanned++;
        const v = evaluateAliMetadataOptions(inst);
        if (v.missing) missing.push(id);
        const instanceType = aliUntrusted(inst.InstanceType) ?? "unknown";
        const state = aliUntrusted(inst.Status) ?? "unknown";

        if (v.notHardened) {
          const description = [
            `ECS instance ${id} (type: ${instanceType}, state: ${state}) has HttpTokens set to "${v.httpTokens}"${v.missing ? " (MetadataOptions not returned; assumed the default)" : ""}.`,
            "Security-hardened mode is not enforced, so the metadata service (100.100.100.200) accepts unauthenticated requests.",
          ];
          if (v.hopLimit > 1) {
            description.push(`HttpPutResponseHopLimit is ${v.hopLimit} (>1), which may allow containers to reach the metadata service.`);
          }
          findings.push(
            makeFinding({
              riskScore: ECS_METADATA_NOT_HARDENED_RISK,
              title: `ECS instance ${id} does not enforce security-hardened metadata access (IMDSv2 equivalent)`,
              resourceType: "ACS::ECS::Instance",
              resourceId: id,
              resourceArn: toAliUrn("ecs", "instance", id, region, env.accountId),
              region,
              description: description.join(" "),
              impact: "Normal-mode metadata access allows attackers to steal RAM role STS credentials via SSRF attacks",
              remediationSteps: [
                "Enforce security-hardened mode by setting HttpTokens to 'required'.",
                `Run: aliyun ecs ModifyInstanceMetadataOptions --RegionId ${region} --InstanceId ${id} --HttpTokens required --HttpEndpoint enabled`,
                "Set HttpPutResponseHopLimit to 1 unless running containers that need metadata access.",
                "Update launch templates / scaling configurations so new instances use security-hardened mode.",
              ],
            }),
          );
        } else if (v.httpTokens === "required" && v.hopLimit > 1) {
          warnings.push(
            `Instance ${id} enforces security-hardened metadata mode but HttpPutResponseHopLimit is ${v.hopLimit} (>1). Verify this is intentional for containerized workloads.`,
          );
        }
      }

      if (missing.length > 0) {
        const sample = missing.slice(0, 10).join(", ") + (missing.length > 10 ? ", …" : "");
        warnings.push(
          `ECS DescribeInstances returned no MetadataOptions for ${missing.length} instance(s) in ${region} (${sample}); treated as HttpTokens "optional".`,
        );
      }

      return {
        module: this.moduleName,
        status: "success",
        ...(warnings.length > 0 ? { warnings: aliSafeWarnings(warnings) } : {}),
        resourcesScanned: scanned,
        findingsCount: findings.length,
        scanTimeMs: Date.now() - startMs,
        findings,
      };
    } catch (err) {
      return aliErrorResult(this.moduleName, startMs, "ECS metadata check failed", err, warnings);
    }
  }
}
