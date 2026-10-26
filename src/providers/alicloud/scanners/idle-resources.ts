/**
 * Alibaba Cloud idle resources scanner (moduleName `idle_resources`, plan §4.1 P1 / T5).
 * EXPERIMENTAL — not yet validated against a live account.
 *
 * Mirrors `src/scanners/idle-resources.ts` (EBS / EIP / stopped EC2 / unused SG):
 *  - ECS `DescribeDisks Status=Available` (unattached cloud disks) → 3.0 (AWS unattached EBS).
 *  - VPC `DescribeEipAddresses Status=Available` (allocated, unbound EIPs) → 2.0 (AWS unused EIP).
 *  - ECS `DescribeInstances Status=Stopped`. DescribeInstances exposes no stop timestamp (AWS
 *    parses `StateTransitionReason` and only flags > 30 days), so EVERY stopped instance is
 *    reported: `StoppedMode=KeepCharging` (instance still billed) → 3.0 (AWS stopped instance);
 *    `StopCharging` / other (only disks billed) → 2.0.
 *  - ECS `DescribeSecurityGroups` → per group (concurrency {@link IDLE_SG_CONCURRENCY}, cap
 *    {@link IDLE_MAX_SG_CHECKS}) `DescribeNetworkInterfaces SecurityGroupId=<id>`; zero ENIs
 *    (primary + secondary) → 2.0 (AWS unused SG). Service-managed groups and groups named
 *    `default` are skipped (as AWS skips `default`).
 * Every list uses PageNumber / PageSize pagination (`TotalCount`) with an item cap.
 *
 * Errors: access denied / not enabled / throttled / network on a category → warning and skip
 * that category; **auth_failed or api_misuse anywhere → module `status: "error"`**. Every
 * cloud-sourced string in a Finding / warning passes through redactAliDiagnostic.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { ALI_API } from "../api-catalog.js";
import { aliCall } from "../client.js";
import type { AliCloudError } from "../errors.js";
import { toAliUrn } from "../urn.js";
import {
  aliArray,
  aliCallCtx,
  aliErrorResult,
  aliField,
  aliNumber,
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

/** DescribeDisks / DescribeEipAddresses page size (maximum 100) and listing cap. */
export const IDLE_PAGE_SIZE = 100;
export const IDLE_MAX_ITEMS = 1000;
/** DescribeSecurityGroups page size (ECS maximum 50). */
export const IDLE_SG_PAGE_SIZE = 50;
export const IDLE_MAX_SG_CHECKS = 300;
export const IDLE_SG_CONCURRENCY = 5;

/** riskScores aligned with the AWS idle-resources scanner. */
export const IDLE_DISK_RISK = 3.0;
export const IDLE_EIP_RISK = 2.0;
export const IDLE_STOPPED_KEEP_CHARGING_RISK = 3.0;
export const IDLE_STOPPED_RISK = 2.0;
export const IDLE_SG_RISK = 2.0;

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity), provider: "alicloud" };
}

interface SubResult {
  findings: Finding[];
  warnings: string[];
  resourcesScanned: number;
  /** auth_failed / api_misuse → module error. */
  fatal?: AliCloudError;
}

const emptySub = (): SubResult => ({ findings: [], warnings: [], resourcesScanned: 0 });

/** Shared catch for a category listing: fatal → module error, else warning + skip. */
function failSub(r: SubResult, label: string, api: string, err: unknown): SubResult {
  if (isAliFatal(err)) return { ...r, fatal: toAliError(err, api) };
  r.warnings.push(aliSoftWarning(label, err));
  return r;
}

/** True for `StoppedMode=KeepCharging` (stopped but the instance is still billed). */
export function isKeepCharging(stoppedMode: unknown): boolean {
  return (aliString(stoppedMode) ?? "").toLowerCase() === "keepcharging";
}

/* ------------------------------------------------------------------------ */
/* Categories                                                               */
/* ------------------------------------------------------------------------ */

async function scanDisks(env: AliScanEnv, region: string): Promise<SubResult> {
  const r = emptySub();
  let disks: Record<string, unknown>[];
  try {
    const page = await listAliPaged(ALI_API.ecs.DescribeDisks, env, region, {
      label: "ECS DescribeDisks",
      listKey: "Disks",
      itemKey: "Disk",
      pageSize: IDLE_PAGE_SIZE,
      maxItems: IDLE_MAX_ITEMS,
      extra: { Status: "Available" },
    });
    r.warnings.push(...page.warnings);
    disks = page.items;
  } catch (err) {
    return failSub(r, "ECS DescribeDisks", "ecs:DescribeDisks", err);
  }

  for (const d of disks) {
    const id = aliUntrusted(d.DiskId);
    if (!id) continue;
    r.resourcesScanned++;
    // Defensive: the request filters Status=Available, but never flag an attached disk.
    const status = aliString(d.Status);
    if (status && status.toLowerCase() !== "available") continue;
    const name = aliUntrusted(d.DiskName);
    const size = aliNumber(d.Size);
    const category = aliUntrusted(d.Category) ?? "unknown";
    r.findings.push(
      makeFinding({
        riskScore: IDLE_DISK_RISK,
        title: `ECS disk ${id} is unattached`,
        resourceType: "ACS::ECS::Disk",
        resourceId: id,
        resourceArn: toAliUrn("ecs", "disk", id, region, env.accountId),
        region,
        description: `ECS cloud disk "${id}"${name ? ` (${name})` : ""} (${size ?? "?"}GiB, ${category}) is in "Available" state and not attached to any instance.`,
        impact: "Unattached disks incur storage costs and may contain sensitive data that is no longer actively managed.",
        remediationSteps: [
          "Determine if the disk is still needed.",
          "If not needed, create a snapshot for archival and release the disk.",
          "If needed, attach it to the appropriate instance.",
        ],
      }),
    );
  }
  return r;
}

async function scanEips(env: AliScanEnv, region: string): Promise<SubResult> {
  const r = emptySub();
  let eips: Record<string, unknown>[];
  try {
    const page = await listAliPaged(ALI_API.vpc.DescribeEipAddresses, env, region, {
      label: "VPC DescribeEipAddresses",
      listKey: "EipAddresses",
      itemKey: "EipAddress",
      pageSize: IDLE_PAGE_SIZE,
      maxItems: IDLE_MAX_ITEMS,
      extra: { Status: "Available" },
    });
    r.warnings.push(...page.warnings);
    eips = page.items;
  } catch (err) {
    return failSub(r, "VPC DescribeEipAddresses", "vpc:DescribeEipAddresses", err);
  }

  for (const e of eips) {
    const id = aliUntrusted(e.AllocationId);
    if (!id) continue;
    r.resourcesScanned++;
    const status = aliString(e.Status);
    if (status && status.toLowerCase() !== "available") continue;
    if (aliString(e.InstanceId)) continue; // bound despite the filter
    const ip = aliUntrusted(e.IpAddress) ?? "unknown";
    r.findings.push(
      makeFinding({
        riskScore: IDLE_EIP_RISK,
        title: `Elastic IP ${ip} is not associated`,
        resourceType: "ACS::VPC::EIP",
        resourceId: id,
        resourceArn: toAliUrn("vpc", "eip", id, region, env.accountId),
        region,
        description: `Elastic IP ${ip} (${id}) is allocated but not associated with any instance, NAT gateway, SLB or network interface.`,
        impact: "Unused Elastic IPs keep incurring reservation / bandwidth fees and represent unnecessary spend.",
        remediationSteps: [
          "Associate the EIP with an instance or network interface if needed.",
          "Release the EIP if it is no longer required.",
        ],
      }),
    );
  }
  return r;
}

async function scanStoppedInstances(env: AliScanEnv, region: string): Promise<SubResult> {
  const r = emptySub();
  let instances: Record<string, unknown>[];
  try {
    const list = await listAliEcsInstances(env, region, { Status: "Stopped" });
    r.warnings.push(...list.warnings);
    instances = list.instances;
  } catch (err) {
    return failSub(r, "ECS DescribeInstances", "ecs:DescribeInstances", err);
  }

  for (const inst of instances) {
    const id = aliUntrusted(inst.InstanceId);
    if (!id) continue;
    r.resourcesScanned++;
    const status = aliString(inst.Status);
    if (status && status.toLowerCase() !== "stopped") continue;
    const keepCharging = isKeepCharging(inst.StoppedMode);
    const name = aliUntrusted(inst.InstanceName);
    const type = aliUntrusted(inst.InstanceType) ?? "unknown";
    const mode = aliUntrusted(inst.StoppedMode) ?? "unknown";
    r.findings.push(
      makeFinding({
        riskScore: keepCharging ? IDLE_STOPPED_KEEP_CHARGING_RISK : IDLE_STOPPED_RISK,
        title: keepCharging
          ? `ECS instance ${id} is stopped but still billed (StoppedMode=KeepCharging)`
          : `ECS instance ${id} is stopped`,
        resourceType: "ACS::ECS::Instance",
        resourceId: id,
        resourceArn: toAliUrn("ecs", "instance", id, region, env.accountId),
        region,
        description: `ECS instance "${id}"${name ? ` (${name})` : ""} (${type}) is in Stopped state (StoppedMode=${mode}). ${
          keepCharging
            ? "In KeepCharging mode the instance's vCPU / memory and public IP stay reserved and billed, in addition to its disks."
            : "Its system / data disks (and any bound EIP) continue to incur charges."
        } The stop time is not exposed by DescribeInstances; review how long it has been stopped.`,
        impact: keepCharging
          ? "The stopped instance is still billed for compute resources and storage, and may run stale configurations or unpatched images when restarted."
          : "Stopped instances still incur disk storage costs and may contain stale configurations or unpatched images.",
        remediationSteps: [
          "Determine if the instance is still needed.",
          "If not needed, create a custom image / snapshot for archival and release the instance.",
          "If it must be kept, stop it in economical mode (StopCharging) for pay-as-you-go instances.",
          "If needed temporarily, consider a launch template for on-demand recreation.",
        ],
      }),
    );
  }
  return r;
}

interface SgRef {
  id: string;
  name?: string;
  vpcId?: string;
}

/** ENI count for a security group: `TotalCount`, else the number of returned ENIs. */
async function sgEniCount(env: AliScanEnv, region: string, sgId: string): Promise<number> {
  const body = await aliCall(ALI_API.ecs.DescribeNetworkInterfaces, aliCallCtx(env, region), {
    RegionId: region,
    SecurityGroupId: sgId,
    PageNumber: 1,
    PageSize: 10,
  });
  const listed = aliArray(aliField(aliField(body, "NetworkInterfaceSets"), "NetworkInterfaceSet")).length;
  const total = aliNumber(aliField(body, "TotalCount"));
  return Math.max(listed, total ?? 0);
}

async function scanSecurityGroups(env: AliScanEnv, region: string): Promise<SubResult> {
  const r = emptySub();
  let groups: SgRef[];
  try {
    const page = await listAliPaged(ALI_API.ecs.DescribeSecurityGroups, env, region, {
      label: "ECS DescribeSecurityGroups",
      listKey: "SecurityGroups",
      itemKey: "SecurityGroup",
      pageSize: IDLE_SG_PAGE_SIZE,
      maxItems: IDLE_MAX_ITEMS,
    });
    r.warnings.push(...page.warnings);
    groups = page.items.flatMap((g) => {
      const id = aliString(g.SecurityGroupId);
      if (!id) return [];
      const managed = g.ServiceManaged === true || (aliString(g.ServiceManaged) ?? "").toLowerCase() === "true";
      const name = aliString(g.SecurityGroupName);
      if (managed || name === "default") return [];
      return [{ id, name, vpcId: aliString(g.VpcId) }];
    });
  } catch (err) {
    return failSub(r, "ECS DescribeSecurityGroups", "ecs:DescribeSecurityGroups", err);
  }

  if (groups.length > IDLE_MAX_SG_CHECKS) {
    r.warnings.push(
      `ECS security groups: ${groups.length} groups in ${region}; only the first ${IDLE_MAX_SG_CHECKS} were checked for attached network interfaces.`,
    );
    groups = groups.slice(0, IDLE_MAX_SG_CHECKS);
  }

  const settled = await runWithConcurrency(
    groups.map((g) => () => sgEniCount(env, region, g.id)),
    IDLE_SG_CONCURRENCY,
  );

  for (let i = 0; i < settled.length; i++) {
    const s = settled[i];
    const g = groups[i];
    const id = aliUntrusted(g.id) ?? "unknown";
    if (s.status === "rejected") {
      if (isAliFatal(s.reason)) return { ...r, fatal: toAliError(s.reason, "ecs:DescribeNetworkInterfaces") };
      r.warnings.push(aliSoftWarning(`ECS DescribeNetworkInterfaces (security group ${id})`, s.reason));
      continue;
    }
    r.resourcesScanned++;
    if (s.value > 0) continue;
    const name = aliUntrusted(g.name);
    const vpc = aliUntrusted(g.vpcId);
    r.findings.push(
      makeFinding({
        riskScore: IDLE_SG_RISK,
        title: `Security group ${id} is not attached to any resource`,
        resourceType: "ACS::ECS::SecurityGroup",
        resourceId: id,
        resourceArn: toAliUrn("ecs", "securitygroup", id, region, env.accountId),
        region,
        description: `Security group "${name ?? id}" (${id}${vpc ? `, VPC ${vpc}` : ""}) is not associated with any network interface (ECS instances, ENIs).`,
        impact: "Unused security groups add clutter and may cause confusion during security reviews.",
        remediationSteps: [
          "Verify the security group is not referenced by other resources (e.g., launch templates, scaling configurations, other security group rules).",
          "Delete the security group if it is no longer needed.",
        ],
      }),
    );
  }
  return r;
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class AliIdleResourcesScanner implements Scanner {
  readonly moduleName = "idle_resources";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];
    const findings: Finding[] = [];
    let resourcesScanned = 0;

    try {
      const env = aliScanEnv(ctx);
      const region = ctx.region;

      for (const [label, run] of [
        ["Unattached disk check failed", scanDisks],
        ["Unused EIP check failed", scanEips],
        ["Stopped instance check failed", scanStoppedInstances],
        ["Unused security group check failed", scanSecurityGroups],
      ] as const) {
        const sub = await run(env, region);
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
      return aliErrorResult(this.moduleName, startMs, "Idle resources check failed", err, warnings);
    }
  }
}
