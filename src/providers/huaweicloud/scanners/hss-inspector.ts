/**
 * Huawei Cloud HSS vulnerability scanner (moduleName `inspector_findings`, plan T9).
 *
 * Mirrors `src/scanners/inspector-findings.ts` (Amazon Inspector detection):
 *
 *  1. `listHostStatus({region, protect_status:"opened", limit:10, offset:0})`
 *     → `total_num` = hosts protected by HSS. Zero protected hosts means HSS
 *     is not in use in this region → a "not enabled" Finding (same shape /
 *     riskScore 6.0 as the AWS service-detection "Amazon Inspector is not
 *     enabled" finding) plus an "is not enabled" warning so the HTML report
 *     lists the module as N/A with the HSS recommendation.
 *  2. When hosts are protected, HSS's host vulnerability list is summarised:
 *     `listVulnerabilities({type, handle_status:"unhandled", limit, offset})`
 *     per vulnerability type ({@link HSS_VUL_TYPES}: linux_vul, windows_vul,
 *     web_cms, app_vul — the API defaults to linux_vul only). Unhandled
 *     vulnerabilities with `severity_level` Critical / High become Findings
 *     (riskScore 9.5 / 8.0, the Security Hub mapping used for Inspector data on
 *     AWS), capped at {@link HSS_MAX_VUL_FINDINGS} (highest severity, most
 *     affected hosts first) with a count warning; Medium / Low are counted in
 *     a summary warning only.
 *
 * Graceful degradation: 403 → warning + status success (as the AWS scanner);
 * 404 / 405 / "not opened" → "not enabled" finding; unexpected failures →
 * status "error" (as the other Huawei scanners). All diagnostics go through
 * `describeHwError` (redacted).
 *
 * SDK notes: HSS is regional and REQUIRES the `region` request field (sent as
 * a header) on `listHostStatus`; `limit` must be within 10..200.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { severityFromScore, priorityFromSeverity } from "../../../utils/risk-scoring.js";
import { hwClient } from "../client.js";
import { classifyHwError, degradeHwError, describeHwError } from "../errors.js";
import { toResourceUrn } from "../urn.js";
import { hwCredentialsFromContext, hwRegionScopeFromContext } from "./shared.js";

/** HSS `limit` must be 10..200. */
export const HSS_VUL_PAGE_SIZE = 200;
/** Per vulnerability type; 5 pages of 200. */
export const HSS_MAX_VULS_PER_TYPE = 1000;
/** Critical / High vulnerabilities reported as individual findings. */
export const HSS_MAX_VUL_FINDINGS = 50;
/** Vulnerability types queried (the API defaults to linux_vul only). */
export const HSS_VUL_TYPES: readonly string[] = ["linux_vul", "windows_vul", "web_cms", "app_vul"];
/** riskScore per HSS `severity_level` (same mapping as Security Hub severities on AWS). */
export const HSS_SEVERITY_RISK_SCORES: Readonly<Record<string, number>> = {
  Critical: 9.5,
  High: 8.0,
  Medium: 5.5,
  Low: 3.0,
};
export const HSS_NOT_ENABLED_WARNING =
  "HSS host protection is not enabled in this region (no protected hosts). Enable HSS to scan hosts for software vulnerabilities.";
const MAX_PAGES = 100;

/* ------------------------------------------------------------------------ */
/* Loose SDK response shapes (wire keys; camelCase accepted for fakes)       */
/* ------------------------------------------------------------------------ */

interface LooseListHostStatusResponse {
  total_num?: number;
  totalNum?: number;
  data_list?: unknown[];
  dataList?: unknown[];
}

export interface LooseVulInfo {
  vul_id?: string;
  vulId?: string;
  vul_name?: string;
  vulName?: string;
  type?: string;
  severity_level?: string;
  severityLevel?: string;
  repair_priority?: string;
  repairPriority?: string;
  repair_necessity?: string;
  repairNecessity?: string;
  host_num?: number;
  hostNum?: number;
  unhandle_host_num?: number;
  unhandleHostNum?: number;
  host_id_list?: string[];
  hostIdList?: string[];
  cve_list?: Array<{ cve_id?: string; cveId?: string; cvss?: number }>;
  cveList?: Array<{ cve_id?: string; cveId?: string; cvss?: number }>;
  scan_time?: number;
  scanTime?: number;
  solution_detail?: string;
  solutionDetail?: string;
  patch_url?: string;
  patchUrl?: string;
  url?: string;
  description?: string;
  label_list?: string[];
  labelList?: string[];
}
interface LooseListVulnerabilitiesResponse {
  total_num?: number;
  totalNum?: number;
  data_list?: LooseVulInfo[];
  dataList?: LooseVulInfo[];
}

/** Minimal client surface (tests inject fakes). */
export interface HssVulnerabilityClient {
  listHostStatus(req?: unknown): Promise<unknown>;
  listVulnerabilities(req?: unknown): Promise<unknown>;
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

/** Normalise HSS `severity_level` (Critical / High / Medium / Low; case-insensitive) — unknown → "Unknown". */
export function normalizeHssSeverity(level: unknown): "Critical" | "High" | "Medium" | "Low" | "Unknown" {
  if (typeof level !== "string") return "Unknown";
  const l = level.trim().toLowerCase();
  if (l === "critical") return "Critical";
  if (l === "high") return "High";
  if (l === "medium") return "Medium";
  if (l === "low") return "Low";
  return "Unknown";
}

/** Order used to rank vulnerabilities (most severe first). */
const SEVERITY_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };

export function hssUnhandledHosts(v: LooseVulInfo): number {
  const n = v.unhandle_host_num ?? v.unhandleHostNum ?? v.host_num ?? v.hostNum;
  return typeof n === "number" && Number.isFinite(n) && n > 0 ? n : 0;
}

/** Sort Critical → High → …, then by affected host count (desc), then by name for stability. */
export function sortHssVulnerabilities(list: LooseVulInfo[]): LooseVulInfo[] {
  return [...list].sort((a, b) => {
    const sa = SEVERITY_RANK[normalizeHssSeverity(a.severity_level ?? a.severityLevel)];
    const sb = SEVERITY_RANK[normalizeHssSeverity(b.severity_level ?? b.severityLevel)];
    if (sa !== sb) return sa - sb;
    const ha = hssUnhandledHosts(a);
    const hb = hssUnhandledHosts(b);
    if (ha !== hb) return hb - ha;
    const na = a.vul_name ?? a.vulName ?? "";
    const nb = b.vul_name ?? b.vulName ?? "";
    return na < nb ? -1 : na > nb ? 1 : 0;
  });
}

function truncateText(s: string | undefined, max = 300): string | undefined {
  if (!s) return undefined;
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/* ------------------------------------------------------------------------ */
/* Scanner                                                                  */
/* ------------------------------------------------------------------------ */

export class HuaweiHssInspectorScanner implements Scanner {
  readonly moduleName = "inspector_findings";

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
      const hss = (await hwClient(HssClient, "hss", creds, scope)) as unknown as HssVulnerabilityClient;

      // 1. Protected host count (detection, as Inspector BatchGetAccountStatus on AWS).
      let protectedHosts: number | undefined;
      try {
        const resp = (await hss.listHostStatus({
          region,
          protect_status: "opened",
          limit: 10,
          offset: 0,
        })) as LooseListHostStatusResponse | undefined;
        const list = resp?.data_list ?? resp?.dataList;
        const total = resp?.total_num ?? resp?.totalNum;
        protectedHosts = typeof total === "number" && Number.isFinite(total) ? total : Array.isArray(list) ? list.length : 0;
      } catch (err) {
        const { kind } = classifyHwError(err);
        if (kind === "access_denied") {
          warnings.push(
            `HSS: insufficient permissions to check host protection status (${describeHwError(err)}). Grant HSS ReadOnlyAccess to check enablement.`,
          );
          return this.result(startMs, 0, findings, warnings);
        }
        if (kind === "not_enabled" || kind === "not_found") {
          warnings.push(`${HSS_NOT_ENABLED_WARNING} (${describeHwError(err)})`);
          findings.push(this.notEnabledFinding(region, domainId));
          return this.result(startMs, 0, findings, warnings);
        }
        throw err;
      }

      if (protectedHosts === 0) {
        warnings.push(HSS_NOT_ENABLED_WARNING);
        findings.push(this.notEnabledFinding(region, domainId));
        return this.result(startMs, 0, findings, warnings);
      }

      // 2. Unhandled vulnerabilities per type.
      const vulns: LooseVulInfo[] = [];
      let vulListingDenied = false;
      for (const type of HSS_VUL_TYPES) {
        try {
          let truncated = false;
          const collected: LooseVulInfo[] = [];
          for (let page = 0; page < MAX_PAGES; page++) {
            const resp = (await hss.listVulnerabilities({
              type,
              handle_status: "unhandled",
              limit: HSS_VUL_PAGE_SIZE,
              offset: page * HSS_VUL_PAGE_SIZE,
            })) as LooseListVulnerabilitiesResponse | undefined;
            const list = resp?.data_list ?? resp?.dataList;
            const batch = Array.isArray(list) ? list : [];
            collected.push(...batch);
            if (collected.length >= HSS_MAX_VULS_PER_TYPE) {
              truncated = collected.length > HSS_MAX_VULS_PER_TYPE || batch.length === HSS_VUL_PAGE_SIZE;
              collected.length = Math.min(collected.length, HSS_MAX_VULS_PER_TYPE);
              break;
            }
            const total = resp?.total_num ?? resp?.totalNum;
            if (batch.length === 0 || batch.length < HSS_VUL_PAGE_SIZE || (typeof total === "number" && collected.length >= total)) break;
          }
          if (truncated) {
            warnings.push(`HSS: more than ${HSS_MAX_VULS_PER_TYPE} unhandled ${type} vulnerabilities; only the first ${HSS_MAX_VULS_PER_TYPE} were evaluated.`);
          }
          vulns.push(...collected.map((v) => ({ ...v, type: v.type ?? type })));
        } catch (err) {
          const degraded = degradeHwError(`HSS vulnerabilities (${type})`, err);
          if (!degraded) throw err;
          warnings.push(degraded);
          if (classifyHwError(err).kind === "access_denied") {
            // Same permission applies to every type: do not repeat the call.
            vulListingDenied = true;
            break;
          }
        }
      }

      // Only vulnerabilities that still affect at least one host are actionable.
      const active = vulns.filter((v) => hssUnhandledHosts(v) > 0);
      const counts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 };
      for (const v of active) counts[normalizeHssSeverity(v.severity_level ?? v.severityLevel)]++;

      const reportable = sortHssVulnerabilities(
        active.filter((v) => {
          const s = normalizeHssSeverity(v.severity_level ?? v.severityLevel);
          return s === "Critical" || s === "High";
        }),
      );
      const selected = reportable.slice(0, HSS_MAX_VUL_FINDINGS);
      for (const v of selected) findings.push(this.vulnerabilityFinding(v, region, domainId));

      if (reportable.length > HSS_MAX_VUL_FINDINGS) {
        warnings.push(
          `HSS: ${reportable.length} unhandled Critical/High vulnerabilities; only the top ${HSS_MAX_VUL_FINDINGS} (by severity and affected hosts) are reported as findings.`,
        );
      }
      if (active.length > 0) {
        warnings.push(
          `HSS: ${active.length} unhandled vulnerabilities across ${protectedHosts} protected host(s) — Critical ${counts.Critical}, High ${counts.High}, Medium ${counts.Medium}, Low ${counts.Low}${counts.Unknown ? `, Unrated ${counts.Unknown}` : ""}. Medium/Low are summarised here only; review them in the HSS console.`,
        );
      } else if (!vulListingDenied) {
        warnings.push(`HSS: ${protectedHosts} protected host(s), no unhandled vulnerabilities reported.`);
      }

      return this.result(startMs, protectedHosts ?? 0, findings, warnings);
    } catch (err) {
      return {
        module: this.moduleName,
        status: "error",
        error: `Huawei Cloud HSS vulnerability scan failed: ${describeHwError(err)}`,
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

  /** Same shape / riskScore as the AWS service-detection "Amazon Inspector is not enabled" finding. */
  private notEnabledFinding(region: string, domainId: string): Finding {
    return makeFinding({
      riskScore: 6.0,
      title: "Huawei Cloud HSS vulnerability scanning is not enabled (no protected hosts)",
      resourceType: "HuaweiCloud::HSS::Host",
      resourceId: "hss-vulnerability-scan",
      resourceArn: toResourceUrn("hss", "vulnerability-scan", "none", region, domainId),
      region,
      description:
        "No ECS host in this region is protected by HSS (Host Security Service), so no host software vulnerability (CVE) data is available. HSS is the Huawei Cloud counterpart of Amazon Inspector for host vulnerability detection.",
      impact:
        "Known CVEs in operating system packages, web frameworks and applications on hosts go undetected; unpatched hosts are a primary entry point for attackers.",
      remediationSteps: [
        "Open the Huawei Cloud HSS console.",
        "Install the HSS agent on ECS instances (or enable automatic agent installation).",
        "Purchase / enable a protection edition (Basic or higher) and bind it to the hosts.",
        "Enable vulnerability scanning and review the vulnerability management page regularly.",
      ],
      accountId: domainId,
      module: this.moduleName,
    });
  }

  private vulnerabilityFinding(v: LooseVulInfo, region: string, domainId: string): Finding {
    const sev = normalizeHssSeverity(v.severity_level ?? v.severityLevel);
    const riskScore = HSS_SEVERITY_RISK_SCORES[sev] ?? HSS_SEVERITY_RISK_SCORES.High;
    const name = v.vul_name ?? v.vulName ?? "unknown";
    const id = v.vul_id ?? v.vulId ?? name;
    const type = v.type ?? "unknown";
    const hosts = hssUnhandledHosts(v);
    const cves = (v.cve_list ?? v.cveList ?? [])
      .map((c) => c.cve_id ?? c.cveId)
      .filter((c): c is string => typeof c === "string" && c.length > 0);
    const hostIds = (v.host_id_list ?? v.hostIdList ?? []).filter((h): h is string => typeof h === "string" && h.length > 0);
    const priority = v.repair_priority ?? v.repairPriority;
    const solution = truncateText(v.solution_detail ?? v.solutionDetail);
    const patchUrl = v.patch_url ?? v.patchUrl ?? v.url;

    const descParts = [
      `HSS vulnerability "${name}" (${id}, type ${type}, severity ${sev}) is unhandled on ${hosts} host(s)`,
      cves.length > 0 ? `CVEs: ${cves.slice(0, 5).join(", ")}${cves.length > 5 ? ` (+${cves.length - 5} more)` : ""}` : undefined,
      priority ? `Repair priority: ${priority}` : undefined,
      hostIds.length > 0 ? `Affected hosts: ${hostIds.slice(0, 5).join(", ")}${hostIds.length > 5 ? ` (+${hostIds.length - 5} more)` : ""}` : undefined,
      truncateText(v.description, 200) ? `Details: ${truncateText(v.description, 200)}` : undefined,
    ].filter((p): p is string => Boolean(p));

    const remediation = [
      `Open the HSS console → Vulnerability Management and locate "${name}".`,
      solution ? `Apply the vendor fix: ${solution}` : "Apply the vendor patch or upgrade the affected package on each affected host.",
      "Use HSS one-click repair where supported, then verify and (if required) reboot the host.",
    ];
    if (patchUrl) remediation.push(`Reference: ${patchUrl}`);

    return makeFinding({
      riskScore,
      title: `HSS ${sev} vulnerability ${name} is unhandled on ${hosts} host(s)`,
      resourceType: "HuaweiCloud::HSS::Vulnerability",
      resourceId: id,
      resourceArn: toResourceUrn("hss", "vulnerability", id, region, domainId),
      region,
      description: descParts.join(". ") + ".",
      impact: `Unpatched ${sev.toLowerCase()} vulnerabilities allow remote code execution, privilege escalation or data theft on the affected hosts.`,
      remediationSteps: remediation,
      accountId: domainId,
      module: this.moduleName,
    });
  }
}
