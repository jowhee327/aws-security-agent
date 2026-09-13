/**
 * Huawei Cloud HSS OS patch compliance scanner (moduleName `patch_compliance_findings`, plan T9).
 *
 * Mirrors `src/scanners/patch-compliance-findings.ts` (SSM Patch Manager).
 * Huawei Cloud has no Patch Manager; OS patch compliance is derived from
 * HSS's per-host vulnerability management:
 *
 *  1. `listHostStatus({region, protect_status:"opened", limit, offset})`
 *     (paginated, cap {@link HSS_PATCH_MAX_HOSTS}) → protected hosts with
 *     `host_id` (= ECS server ID), `host_name`, `os_type`, `vulnerability`
 *     (total vulnerability count as reported by HSS), IPs and agent status.
 *     Zero protected hosts → ONE "not enabled" Finding (riskScore 3.0 — the
 *     AWS scanner's "no patch compliance data" level; the HSS-not-enabled
 *     condition itself is already reported at 6.0 by `inspector_findings` /
 *     `service_detection`, so this module only states that patch compliance
 *     cannot be assessed) plus an "is not enabled" warning.
 *  2. Per host (bounded concurrency {@link HSS_PATCH_CONCURRENCY}; hosts whose
 *     `vulnerability` counter is exactly 0 are treated as fully patched and
 *     skipped): `listHostVuls({host_id, type, handle_status:"unhandled",
 *     limit, offset})` with `type` = `windows_vul` / `linux_vul` from
 *     `os_type` (OS patch classes only — web_cms / app_vul are application
 *     vulnerabilities, covered by `inspector_findings`). Unhandled OS
 *     vulnerabilities > 0 → one Finding per host; riskScore mirrors the AWS
 *     thresholds: Critical/High present → 7.5 (HIGH, "security patches
 *     missing"), only Medium/Low → 5.5 (MEDIUM).
 *
 * Graceful degradation: 403 / not enabled on the host listing → warning +
 * status success; per-host failures are aggregated into one warning per
 * class (denied / not available / other) and the scan continues; unexpected
 * failures of the host listing → status "error". Diagnostics are redacted via
 * `describeHwError`.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { runWithConcurrency } from "../../../utils/concurrency.js";
import { severityFromScore, priorityFromSeverity } from "../../../utils/risk-scoring.js";
import { hwClient } from "../client.js";
import { classifyHwError, describeHwError } from "../errors.js";
import { toResourceUrn } from "../urn.js";
import { hwCredentialsFromContext, hwRegionScopeFromContext } from "./shared.js";
import { normalizeHssSeverity } from "./hss-inspector.js";

/** HSS `limit` must be 10..200. */
export const HSS_HOST_PAGE_SIZE = 200;
export const HSS_PATCH_MAX_HOSTS = 500;
export const HSS_PATCH_CONCURRENCY = 5;
export const HSS_HOST_VUL_PAGE_SIZE = 200;
/** Per host; 5 pages of 200. */
export const HSS_MAX_VULS_PER_HOST = 1000;
export const HSS_PATCH_NOT_ENABLED_WARNING =
  "HSS host protection is not enabled in this region (no protected hosts); OS patch compliance cannot be assessed.";
const MAX_PAGES = 100;

/* ------------------------------------------------------------------------ */
/* Loose SDK response shapes (wire keys; camelCase accepted for fakes)       */
/* ------------------------------------------------------------------------ */

export interface LooseHssHost {
  host_id?: string;
  hostId?: string;
  host_name?: string;
  hostName?: string;
  os_type?: string;
  osType?: string;
  os_name?: string;
  osName?: string;
  os_version?: string;
  osVersion?: string;
  agent_status?: string;
  agentStatus?: string;
  protect_status?: string;
  protectStatus?: string;
  detect_result?: string;
  detectResult?: string;
  private_ip?: string;
  privateIp?: string;
  public_ip?: string;
  publicIp?: string;
  version?: string;
  /** Total vulnerability count reported by HSS for the host. */
  vulnerability?: number;
}
interface LooseListHostStatusResponse {
  total_num?: number;
  totalNum?: number;
  data_list?: LooseHssHost[];
  dataList?: LooseHssHost[];
}

export interface LooseHostVul {
  vul_id?: string;
  vulId?: string;
  vul_name?: string;
  vulName?: string;
  type?: string;
  severity_level?: string;
  severityLevel?: string;
  repair_priority?: string;
  repairPriority?: string;
  status?: string;
  scan_time?: number;
  scanTime?: number;
  first_scan_time?: number;
  firstScanTime?: number;
}
interface LooseListHostVulsResponse {
  total_num?: number;
  totalNum?: number;
  data_list?: LooseHostVul[];
  dataList?: LooseHostVul[];
}

/** Minimal client surface (tests inject fakes). */
export interface HssPatchClient {
  listHostStatus(req?: unknown): Promise<unknown>;
  listHostVuls(req?: unknown): Promise<unknown>;
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
  accountId: string;
  module: string;
}): Finding {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity), provider: "huaweicloud" };
}

/** HSS vulnerability type for OS patches: Windows hosts → `windows_vul`, everything else → `linux_vul`. */
export function hssOsVulType(host: Pick<LooseHssHost, "os_type" | "osType" | "os_name" | "osName">): "linux_vul" | "windows_vul" {
  const os = `${host.os_type ?? host.osType ?? ""} ${host.os_name ?? host.osName ?? ""}`.toLowerCase();
  return os.includes("windows") ? "windows_vul" : "linux_vul";
}

export interface HostPatchState {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  /** Most severe unhandled vulnerability names (for the description). */
  sample: string[];
  truncated: boolean;
}

/** Aggregate unhandled OS vulnerabilities of one host (pure). */
export function summarizeHostVuls(vuls: LooseHostVul[], truncated = false): HostPatchState {
  const state: HostPatchState = { total: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0, sample: [], truncated };
  const ranked: Array<{ rank: number; name: string }> = [];
  const rank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };
  for (const v of vuls) {
    state.total++;
    const sev = normalizeHssSeverity(v.severity_level ?? v.severityLevel);
    if (sev === "Critical") state.critical++;
    else if (sev === "High") state.high++;
    else if (sev === "Medium") state.medium++;
    else if (sev === "Low") state.low++;
    else state.unknown++;
    const name = v.vul_name ?? v.vulName ?? v.vul_id ?? v.vulId;
    if (name) ranked.push({ rank: rank[sev], name });
  }
  ranked.sort((a, b) => a.rank - b.rank || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  state.sample = ranked.slice(0, 5).map((r) => r.name);
  return state;
}

/** riskScore mirroring the AWS patch scanner: security (Critical/High) patches missing → 7.5, otherwise → 5.5. */
export function patchRiskScore(state: Pick<HostPatchState, "critical" | "high">): number {
  return state.critical > 0 || state.high > 0 ? 7.5 : 5.5;
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

type HostOutcome =
  | { kind: "ok"; host: LooseHssHost; state: HostPatchState }
  | { kind: "skipped"; host: LooseHssHost }
  | { kind: "failed"; host: LooseHssHost; err: unknown };

export class HuaweiHssPatchComplianceScanner implements Scanner {
  readonly moduleName = "patch_compliance_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const findings: Finding[] = [];
    const warnings: string[] = [];

    try {
      const creds = hwCredentialsFromContext(ctx, "basic");
      const scope = await hwRegionScopeFromContext(ctx, creds);
      const { region } = scope;
      const domainId = scope.domainId || ctx.accountId;

      const { HssClient } = await import("@huaweicloud/huaweicloud-sdk-hss");
      const hss = (await hwClient(HssClient, "hss", creds, scope)) as unknown as HssPatchClient;

      // 1. Protected hosts (paginated, capped).
      const hosts: LooseHssHost[] = [];
      try {
        let truncated = false;
        for (let page = 0; page < MAX_PAGES; page++) {
          const resp = (await hss.listHostStatus({
            region,
            protect_status: "opened",
            limit: HSS_HOST_PAGE_SIZE,
            offset: page * HSS_HOST_PAGE_SIZE,
          })) as LooseListHostStatusResponse | undefined;
          const list = resp?.data_list ?? resp?.dataList;
          const batch = Array.isArray(list) ? list : [];
          hosts.push(...batch);
          if (hosts.length >= HSS_PATCH_MAX_HOSTS) {
            truncated = hosts.length > HSS_PATCH_MAX_HOSTS || batch.length === HSS_HOST_PAGE_SIZE;
            hosts.length = Math.min(hosts.length, HSS_PATCH_MAX_HOSTS);
            break;
          }
          const total = resp?.total_num ?? resp?.totalNum;
          if (batch.length === 0 || batch.length < HSS_HOST_PAGE_SIZE || (typeof total === "number" && hosts.length >= total)) break;
        }
        if (truncated) warnings.push(`HSS: more than ${HSS_PATCH_MAX_HOSTS} protected hosts; only the first ${HSS_PATCH_MAX_HOSTS} were checked.`);
      } catch (err) {
        const { kind } = classifyHwError(err);
        if (kind === "access_denied") {
          warnings.push(`HSS: insufficient permissions to list protected hosts (${describeHwError(err)}). Grant HSS ReadOnlyAccess to assess patch compliance.`);
          return this.result(startMs, 0, findings, warnings);
        }
        if (kind === "not_enabled" || kind === "not_found") {
          warnings.push(`${HSS_PATCH_NOT_ENABLED_WARNING} (${describeHwError(err)})`);
          findings.push(this.notEnabledFinding(region, domainId));
          return this.result(startMs, 0, findings, warnings);
        }
        throw err;
      }

      if (hosts.length === 0) {
        warnings.push(HSS_PATCH_NOT_ENABLED_WARNING);
        findings.push(this.notEnabledFinding(region, domainId));
        return this.result(startMs, 0, findings, warnings);
      }

      // 2. Per-host unhandled OS vulnerabilities (N+1, bounded).
      const tasks = hosts.map((host) => async (): Promise<HostOutcome> => {
        const hostId = host.host_id ?? host.hostId;
        if (!hostId) return { kind: "skipped", host };
        if (host.vulnerability === 0) return { kind: "ok", host, state: summarizeHostVuls([]) };
        try {
          const vuls: LooseHostVul[] = [];
          let truncated = false;
          const type = hssOsVulType(host);
          for (let page = 0; page < MAX_PAGES; page++) {
            const resp = (await hss.listHostVuls({
              host_id: hostId,
              type,
              handle_status: "unhandled",
              limit: HSS_HOST_VUL_PAGE_SIZE,
              offset: page * HSS_HOST_VUL_PAGE_SIZE,
            })) as LooseListHostVulsResponse | undefined;
            const list = resp?.data_list ?? resp?.dataList;
            const batch = Array.isArray(list) ? list : [];
            vuls.push(...batch);
            if (vuls.length >= HSS_MAX_VULS_PER_HOST) {
              truncated = vuls.length > HSS_MAX_VULS_PER_HOST || batch.length === HSS_HOST_VUL_PAGE_SIZE;
              vuls.length = Math.min(vuls.length, HSS_MAX_VULS_PER_HOST);
              break;
            }
            const total = resp?.total_num ?? resp?.totalNum;
            if (batch.length === 0 || batch.length < HSS_HOST_VUL_PAGE_SIZE || (typeof total === "number" && vuls.length >= total)) break;
          }
          return { kind: "ok", host, state: summarizeHostVuls(vuls, truncated) };
        } catch (err) {
          return { kind: "failed", host, err };
        }
      });
      const settled = await runWithConcurrency(tasks, HSS_PATCH_CONCURRENCY);

      const failed: Record<"denied" | "unavailable" | "other", { count: number; first?: unknown }> = {
        denied: { count: 0 },
        unavailable: { count: 0 },
        other: { count: 0 },
      };
      let skipped = 0;

      for (const r of settled) {
        if (r.status === "rejected") {
          failed.other.count++;
          failed.other.first ??= r.reason;
          continue;
        }
        const outcome = r.value;
        if (outcome.kind === "skipped") {
          skipped++;
          continue;
        }
        if (outcome.kind === "failed") {
          const { kind } = classifyHwError(outcome.err);
          const bucket = kind === "access_denied" ? failed.denied : kind === "not_enabled" || kind === "not_found" ? failed.unavailable : failed.other;
          bucket.count++;
          bucket.first ??= outcome.err;
          continue;
        }
        const { host, state } = outcome;
        if (state.total === 0) continue; // fully patched
        findings.push(this.hostFinding(host, state, region, domainId));
      }

      if (skipped > 0) warnings.push(`HSS: ${skipped} protected host(s) had no host ID and were not evaluated.`);
      if (failed.denied.count > 0) {
        warnings.push(`HSS: insufficient permissions to list host vulnerabilities for ${failed.denied.count} host(s) (${describeHwError(failed.denied.first)}); those hosts were not evaluated.`);
      }
      if (failed.unavailable.count > 0) {
        warnings.push(`HSS: host vulnerability data not available for ${failed.unavailable.count} host(s) (${describeHwError(failed.unavailable.first)}); those hosts were not evaluated.`);
      }
      if (failed.other.count > 0) {
        warnings.push(`HSS: host vulnerability lookup failed for ${failed.other.count} host(s) (${describeHwError(failed.other.first)}); those hosts were not evaluated.`);
      }

      return this.result(startMs, hosts.length, findings, warnings);
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: `Huawei Cloud HSS patch compliance scan failed: ${describeHwError(err)}`,
        warnings: warnings.length > 0 ? warnings : undefined,
        resourcesScanned: 0,
        findingsCount: 0,
        scanTimeMs: Date.now() - startMs,
        findings: [],
      };
    }
  }

  private result(startMs: number, resourcesScanned: number, findings: Finding[], warnings: string[]): ScanResult {
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

  /** Distinct title / resourceId from `inspector_findings` and `service_detection` (no duplicate reporting). */
  private notEnabledFinding(region: string, domainId: string): Finding {
    return makeFinding({
      riskScore: 3.0,
      title: "OS patch compliance cannot be assessed: no hosts are protected by HSS",
      resourceType: "HuaweiCloud::HSS::Host",
      resourceId: "hss-patch-compliance",
      resourceArn: toResourceUrn("hss", "patch-compliance", "none", region, domainId),
      region,
      description:
        "No ECS host in this region is protected by HSS (Host Security Service). Huawei Cloud has no Patch Manager; OS patch status is derived from HSS host vulnerability management, so patch compliance is unknown for every host.",
      impact: "Patch compliance status is unknown — unpatched operating system vulnerabilities may exist.",
      remediationSteps: [
        "Install the HSS agent on ECS instances and enable a protection edition (Basic or higher).",
        "Enable HSS vulnerability scanning (Linux / Windows vulnerability detection).",
        "Establish a patch cadence: review the HSS vulnerability management page and fix Critical/High items first.",
      ],
      accountId: domainId,
      module: this.moduleName,
    });
  }

  private hostFinding(host: LooseHssHost, state: HostPatchState, region: string, domainId: string): Finding {
    const hostId = host.host_id ?? host.hostId ?? "unknown";
    const name = host.host_name ?? host.hostName;
    const label = name ? `${hostId} (${name})` : hostId;
    const os = [host.os_type ?? host.osType, host.os_name ?? host.osName, host.os_version ?? host.osVersion].filter(Boolean).join(" ") || "unknown";
    const riskScore = patchRiskScore(state);

    const titleParts: string[] = [];
    if (state.critical > 0) titleParts.push(`${state.critical} critical`);
    if (state.high > 0) titleParts.push(`${state.high} high`);
    if (state.medium > 0) titleParts.push(`${state.medium} medium`);
    if (state.low > 0) titleParts.push(`${state.low} low`);
    if (state.unknown > 0) titleParts.push(`${state.unknown} unrated`);

    const descParts = [
      `Host: ${label}`,
      `OS: ${os}`,
      `Unhandled OS vulnerabilities: ${state.total}${state.truncated ? "+" : ""}`,
      `Critical: ${state.critical}`,
      `High: ${state.high}`,
      `Medium: ${state.medium}`,
      `Low: ${state.low}`,
      host.agent_status ?? host.agentStatus ? `Agent: ${host.agent_status ?? host.agentStatus}` : undefined,
      host.private_ip ?? host.privateIp ? `Private IP: ${host.private_ip ?? host.privateIp}` : undefined,
      host.public_ip ?? host.publicIp ? `Public IP: ${host.public_ip ?? host.publicIp}` : undefined,
      state.sample.length > 0 ? `Examples: ${state.sample.join(", ")}` : undefined,
    ].filter((p): p is string => Boolean(p));

    return makeFinding({
      riskScore,
      title: `Host ${label} has ${state.total}${state.truncated ? "+" : ""} unpatched OS vulnerabilities (${titleParts.join(", ")})`,
      resourceType: "HuaweiCloud::ECS::CloudServer",
      resourceId: hostId,
      resourceArn: toResourceUrn("ecs", "server", hostId, region, domainId),
      region,
      description: descParts.join(". ") + ".",
      impact: `Host has ${state.total}${state.truncated ? "+" : ""} unhandled operating system vulnerabilities${state.critical + state.high > 0 ? ` including ${state.critical + state.high} critical/high` : ""} — potential security vulnerabilities.`,
      remediationSteps: [
        `Review the host in the HSS console → Asset Management → Servers → ${label} → Vulnerabilities.`,
        "Fix Critical/High vulnerabilities first (HSS one-click repair or the vendor patch / package upgrade), then reboot if required.",
        "Verify the fix with an HSS re-scan; ignore only vulnerabilities that are confirmed not applicable.",
        "Establish a regular OS patch cadence (e.g. HSS scheduled scans + maintenance windows).",
      ],
      accountId: domainId,
      module: this.moduleName,
    });
  }
}
