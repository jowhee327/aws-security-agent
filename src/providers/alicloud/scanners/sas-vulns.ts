/**
 * Alibaba Cloud Security Center (SAS) vulnerability scanner (moduleName `inspector_findings`,
 * plan §4.1 P2 / T7). EXPERIMENTAL — not yet validated against a live account.
 *
 * Amazon Inspector counterpart (mirrors the Huawei HSS scanner `hss-inspector.ts`):
 *
 *  1. {@link checkSasEdition} (`DescribeVersionConfig`): not purchased / Free Edition /
 *     value-added only → 0 findings + "not enabled / insufficient edition" warning (status
 *     success; `service_detection` already reports the missing edition as a Finding).
 *  2. `DescribeVulList` (centralised tds endpoint, `CurrentPage` / `PageSize`, `Dealed=n`)
 *     for each of {@link SAS_VUL_TYPES} — `cve` (Linux software), `app` (application),
 *     `emg` (emergency). Records are per vulnerability × host; they are aggregated per
 *     vulnerability (`Type` + `Name`) with the affected host count and the most urgent
 *     `Necessity`.
 *  3. One Finding per vulnerability — `Necessity` asap → HIGH 8.0, later → MEDIUM 5.5,
 *     nntf → LOW 3.0 (unrated → 5.5; unrated emergency vulnerabilities count as asap) —
 *     sorted by necessity, affected hosts and name, capped at {@link SAS_MAX_VUL_FINDINGS}
 *     (same approach as Huawei `HSS_MAX_VUL_FINDINGS`) with an overflow warning carrying
 *     the per-necessity counts.
 *
 * Every server-sourced string (vulnerability name / alias, CVE IDs, host IDs / names) passes
 * through redactAliDiagnostic. Errors: auth_failed / api_misuse → module `status: "error"`;
 * access denied / not enabled / throttled / network → warning + degrade.
 */
import type { Scanner } from "../../../scanners/base.js";
import type { Finding, ScanContext, ScanResult } from "../../../types.js";
import { priorityFromSeverity, severityFromScore } from "../../../utils/risk-scoring.js";
import { toAliUrn } from "../urn.js";
import {
  checkSasEdition,
  listSasVulRecords,
  sasMoreUrgent,
  sasNecessity,
  sasTruncate,
  sasVulCves,
  SAS_NECESSITY_LABELS,
  SAS_NECESSITY_RANK,
  SAS_NECESSITY_RISK,
  SAS_VUL_TYPE_LABELS,
  type SasNecessity,
  type SasVulRecord,
} from "./sas-shared.js";
import { aliErrorResult, aliScanEnv, aliUntrusted, emptyScanResult } from "./shared.js";

/** Vulnerability types queried (Windows `sys` patches are covered by `patch_compliance_findings`). */
export const SAS_VUL_TYPES: readonly string[] = ["cve", "app", "emg"];
/** Vulnerabilities reported as individual findings. */
export const SAS_MAX_VUL_FINDINGS = 50;

const WHAT = "vulnerability (Inspector-equivalent) data";

export interface SasVulSummary {
  type: string;
  /** Vulnerability identifier (`Name`), redacted. */
  name: string;
  /** Display name (`AliasName`, else `Name`), redacted. */
  alias: string;
  necessity: SasNecessity;
  /** Distinct affected hosts (Uuid / InstanceId / IP), redacted. */
  hosts: string[];
  cves: string[];
}

function makeFinding(opts: Omit<Finding, "severity" | "priority" | "provider">): Finding {
  const severity = severityFromScore(opts.riskScore);
  return { ...opts, severity, priority: priorityFromSeverity(severity), provider: "alicloud" };
}

/** Host label of a record: `InstanceId (InstanceName)`, else Uuid / IP (redacted). */
export function sasHostLabel(rec: Record<string, unknown>): string | undefined {
  const instanceId = aliUntrusted(rec.InstanceId);
  const name = aliUntrusted(rec.InstanceName);
  if (instanceId) return name && name !== instanceId ? `${instanceId} (${name})` : instanceId;
  return aliUntrusted(rec.Uuid) ?? name ?? aliUntrusted(rec.InternetIp) ?? aliUntrusted(rec.IntranetIp);
}

/** Aggregate per-host records into one summary per vulnerability (`Type` + `Name`) — pure. */
export function aggregateSasVuls(records: SasVulRecord[]): SasVulSummary[] {
  const byKey = new Map<string, { s: SasVulSummary; hosts: Set<string>; cves: Set<string> }>();
  for (const { type, rec } of records) {
    const name = aliUntrusted(rec.Name) ?? aliUntrusted(rec.AliasName);
    if (!name) continue;
    const key = `${type}|${name}`;
    let necessity = sasNecessity(rec);
    if (necessity === "unknown" && type === "emg") necessity = "asap";
    let entry = byKey.get(key);
    if (!entry) {
      entry = {
        s: { type, name, alias: aliUntrusted(rec.AliasName) ?? name, necessity, hosts: [], cves: [] },
        hosts: new Set(),
        cves: new Set(),
      };
      byKey.set(key, entry);
    } else {
      entry.s.necessity = sasMoreUrgent(entry.s.necessity, necessity);
    }
    const host = sasHostLabel(rec);
    if (host) entry.hosts.add(host);
    for (const c of sasVulCves(rec)) entry.cves.add(c);
  }
  return [...byKey.values()].map(({ s, hosts, cves }) => ({ ...s, hosts: [...hosts], cves: [...cves] }));
}

/** Most urgent first, then most affected hosts, then type / name for stability. */
export function sortSasVulSummaries(list: SasVulSummary[]): SasVulSummary[] {
  return [...list].sort((a, b) => {
    const na = SAS_NECESSITY_RANK[a.necessity];
    const nb = SAS_NECESSITY_RANK[b.necessity];
    if (na !== nb) return na - nb;
    if (a.hosts.length !== b.hosts.length) return b.hosts.length - a.hosts.length;
    const ka = `${a.type}|${a.name}`;
    const kb = `${b.type}|${b.name}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

export class AliSasVulnsScanner implements Scanner {
  readonly moduleName = "inspector_findings";

  async scan(ctx: ScanContext): Promise<ScanResult> {
    const startMs = Date.now();
    const warnings: string[] = [];
    const findings: Finding[] = [];

    try {
      const env = aliScanEnv(ctx);

      const edition = await checkSasEdition(env, WHAT);
      if (edition.kind === "stop") return emptyScanResult(this.moduleName, startMs, { warnings: [edition.warning] });
      if (edition.warning) warnings.push(edition.warning);

      const listing = await listSasVulRecords(env, SAS_VUL_TYPES, WHAT);
      warnings.push(...listing.warnings);

      const vulns = sortSasVulSummaries(aggregateSasVuls(listing.records));
      const counts: Record<SasNecessity, number> = { asap: 0, later: 0, nntf: 0, unknown: 0 };
      for (const v of vulns) counts[v.necessity]++;
      for (const v of vulns.slice(0, SAS_MAX_VUL_FINDINGS)) findings.push(this.vulnFinding(v, env.accountId));

      if (vulns.length > SAS_MAX_VUL_FINDINGS) {
        warnings.push(
          `SAS: ${vulns.length} unhandled vulnerabilities (asap ${counts.asap}, later ${counts.later}, nntf ${counts.nntf}${counts.unknown ? `, unrated ${counts.unknown}` : ""}); only the top ${SAS_MAX_VUL_FINDINGS} (by fix priority and affected hosts) are reported as findings. Review the rest in the Security Center console.`,
        );
      }

      return {
        ...emptyScanResult(this.moduleName, startMs, { warnings }),
        resourcesScanned: vulns.length,
        findingsCount: findings.length,
        findings,
      };
    } catch (err) {
      return aliErrorResult(this.moduleName, startMs, "SAS vulnerability scan failed", err, warnings);
    }
  }

  private vulnFinding(v: SasVulSummary, accountId: string): Finding {
    const typeLabel = SAS_VUL_TYPE_LABELS[v.type] ?? v.type;
    const priority = SAS_NECESSITY_LABELS[v.necessity];
    const hosts = v.hosts.length;
    const nameNote = v.alias !== v.name ? ` (${v.name})` : "";
    const descParts = [
      `Security Center ${typeLabel} vulnerability "${v.alias}"${nameNote} with fix priority ${priority} is unhandled on ${hosts} host(s)`,
      v.cves.length > 0 ? `CVEs: ${v.cves.slice(0, 5).join(", ")}${v.cves.length > 5 ? ` (+${v.cves.length - 5} more)` : ""}` : undefined,
      hosts > 0 ? `Affected hosts: ${v.hosts.slice(0, 5).join(", ")}${hosts > 5 ? ` (+${hosts - 5} more)` : ""}` : undefined,
    ].filter((p): p is string => Boolean(p));

    return makeFinding({
      riskScore: SAS_NECESSITY_RISK[v.necessity],
      title: sasTruncate(`SAS ${priority} ${typeLabel} vulnerability ${v.alias} is unhandled on ${hosts} host(s)`, 250) ?? v.name,
      resourceType: "ACS::SAS::Vulnerability",
      resourceId: v.name,
      resourceArn: toAliUrn("sas", "vul", v.name, "", accountId),
      region: "global",
      description: descParts.join(". ") + ".",
      impact:
        v.necessity === "asap"
          ? "High-priority vulnerabilities are likely exploitable (remote code execution, privilege escalation, data theft) and should be fixed immediately."
          : v.necessity === "nntf"
            ? "Low-priority vulnerabilities have limited exploitability but still widen the attack surface."
            : "Unpatched vulnerabilities may allow attackers to compromise the affected hosts or applications.",
      remediationSteps: [
        `Open the Security Center console → Vulnerabilities (${typeLabel}) and locate "${v.alias}".`,
        "Apply the vendor fix (package upgrade / patch / configuration change) on every affected host, using Security Center one-click fix where supported.",
        "Re-scan (Verify) after fixing and reboot hosts if required.",
        "Fix asap (high-priority) vulnerabilities first; ignore only vulnerabilities confirmed not applicable.",
      ],
      accountId,
      module: this.moduleName,
    });
  }
}
