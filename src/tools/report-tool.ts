import type { FullScanResult, Finding, Severity } from "../types.js";
import { getI18n, type Lang } from "../i18n/index.js";
import { computeExploitabilityFunnel, FUNNEL_LAYERS } from "../exploitability/funnel.js";
import {
  PRIORITY_ORDER,
  fmtEpss,
  fmtExploit,
  hasExploitability,
  kevStaleNote,
  localizedRationale,
  selectInspectorFindings,
  summarizeByCve,
  urgentFindings,
} from "./exploitability-report.js";

const SEVERITY_ICON: Record<Severity, string> = {
  CRITICAL: "\ud83d\udd34",
  HIGH: "\ud83d\udfe0",
  MEDIUM: "\ud83d\udfe1",
  LOW: "\ud83d\udfe2",
};

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function formatDuration(start: string, end: string): string {
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (ms < 1000) return `${ms}ms`;
  const secs = Math.round(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  const remainSecs = secs % 60;
  return `${mins}m ${remainSecs}s`;
}

/** P0/P1 rows in the Markdown exploitability section. */
const MD_URGENT_TOP = 10;

/** Make user data safe inside a Markdown table cell. */
function mdCell(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

export function generateMarkdownReport(scanResults: FullScanResult, lang?: Lang): string {
  const t = getI18n(lang ?? "zh", scanResults.provider);
  const { summary, modules, accountId, region, scanStart, scanEnd } =
    scanResults;
  const date = scanStart.split("T")[0];
  const duration = formatDuration(scanStart, scanEnd);

  const sevLabel: Record<Severity, string> = {
    CRITICAL: t.critical,
    HIGH: t.high,
    MEDIUM: t.medium,
    LOW: t.low,
  };

  const tx = t.exploitability;

  function renderFinding(f: Finding): string {
    const steps = f.remediationSteps
      .map((s, i) => `  ${i + 1}. ${s}`)
      .join("\n");

    const x = f.exploitability;
    if (x) {
      return [
        `#### ${f.title}`,
        `- **${t.resource}:** ${f.resourceId} (\`${f.resourceArn}\`)`,
        `- **${tx.exploitPriority}:** ${x.priority} \u2014 ${localizedRationale(tx, f)} (${tx.colReachability}: ${tx.reachability[x.reachability] ?? x.reachability})`,
        `- **${t.description}:** ${f.description}`,
        `- **${t.impact}:** ${f.impact}`,
        `- **${t.riskScore}:** ${f.riskScore}/10`,
        `- **${t.remediation}:**`,
        steps,
        `- **${t.priority}:** ${f.priority}`,
      ].join("\n");
    }

    return [
      `#### ${f.title}`,
      `- **${t.resource}:** ${f.resourceId} (\`${f.resourceArn}\`)`,
      `- **${t.description}:** ${f.description}`,
      `- **${t.impact}:** ${f.impact}`,
      `- **${t.riskScore}:** ${f.riskScore}/10`,
      `- **${t.remediation}:**`,
      steps,
      `- **${t.priority}:** ${f.priority}`,
    ].join("\n");
  }

  const lines: string[] = [];

  lines.push(`# ${t.securityReportTitle} \u2014 ${date}`);
  lines.push("");

  // Executive Summary
  lines.push(`## ${t.executiveSummary}`);
  lines.push(`- **${t.account}:** ${accountId}`);
  lines.push(`- **${t.region}:** ${region}`);
  lines.push(`- **${t.duration}:** ${duration}`);
  lines.push(
    `- **${t.totalFindingsLabel}:** ${summary.totalFindings} (${SEVERITY_ICON.CRITICAL} ${summary.critical} ${t.critical} | ${SEVERITY_ICON.HIGH} ${summary.high} ${t.high} | ${SEVERITY_ICON.MEDIUM} ${summary.medium} ${t.medium} | ${SEVERITY_ICON.LOW} ${summary.low} ${t.low})`,
  );
  lines.push("");

  // Optional AI summary (client AI supplies; rendered only if present)
  if (scanResults.aiSummary && scanResults.aiSummary.trim()) {
    lines.push(`> \u2728 **${t.aiSummaryTitle}**`);
    lines.push(">");
    for (const ln of scanResults.aiSummary.trim().split(/\r?\n/)) {
      lines.push(`> ${ln}`);
    }
    lines.push("");
  }

  // Exploitability: when present, inspector_findings is listed only for P0/P1 + the
  // top entries by priority; the remainder goes to a per-CVE summary table.
  const everyFinding: Finding[] = modules.flatMap((m) => m.findings);
  const hasExploit = hasExploitability(everyFinding);
  const inspectorMod = modules.find((m) => m.module === "inspector_findings");
  const inspectorSel = hasExploit && inspectorMod && hasExploitability(inspectorMod.findings)
    ? selectInspectorFindings(inspectorMod.findings, undefined, true)
    : undefined;
  const omitted = new Set<Finding>(inspectorSel?.rest ?? []);
  const listedFindings = (): Finding[] =>
    omitted.size === 0 ? modules.flatMap((m) => m.findings) : modules.flatMap((m) => m.findings).filter((f) => !omitted.has(f));

  if (hasExploit) {
    const funnel = computeExploitabilityFunnel(everyFinding);
    lines.push(`## ${tx.sectionTitle}`);
    lines.push("");
    lines.push(`| ${tx.funnelTitle} | ${t.findings} | ${tx.funnelCves} |`);
    lines.push("|---|---|---|");
    for (const layer of FUNNEL_LAYERS) {
      lines.push(`| ${tx.funnelLayers[layer]} | ${funnel[layer].findings} | ${funnel[layer].cves} |`);
    }
    lines.push("");
    lines.push(`_${tx.funnelNote}_`);
    lines.push("");
    lines.push(`- **${tx.byPriority}:** ${PRIORITY_ORDER.map((p) => `${p} ${funnel.byPriority[p]}`).join(" | ")}`);
    const stale = kevStaleNote(tx, funnel.kevSnapshotDate, date);
    lines.push(`- ${tx.kevSnapshot(funnel.kevSnapshotDate)}${stale ? ` \u2014 ${stale}` : ""}`);
    lines.push("");

    const urgent = urgentFindings(everyFinding);
    lines.push(`### ${tx.mdTopTitle(MD_URGENT_TOP)}`);
    lines.push("");
    if (urgent.length === 0) {
      lines.push(tx.noUrgent);
    } else {
      lines.push(`| ${tx.colPriority} | ${tx.colCve} | ${tx.colResource} | ${tx.colResourceType} | ${tx.colExploit} | ${tx.colEpss} | ${tx.colKev} | ${tx.colReachability} | ${tx.colRationale} |`);
      lines.push("|---|---|---|---|---|---|---|---|---|");
      for (const f of urgent.slice(0, MD_URGENT_TOP)) {
        const x = f.exploitability!;
        const kev = x.kev ? `${tx.yes}${x.kevDateAdded ? ` (${x.kevDateAdded})` : ""}` : tx.no;
        const reach = tx.reachability[x.reachability] ?? x.reachability;
        lines.push(
          `| ${x.priority} | ${mdCell(x.cveId)} | ${mdCell(f.resourceId)} | ${mdCell(f.resourceType)} | ${fmtExploit(tx, x.exploitAvailable)} | ${fmtEpss(x.epss) || tx.notAvailable} | ${mdCell(kev)} | ${mdCell(reach)} | ${mdCell(localizedRationale(tx, f))} |`,
        );
      }
      if (urgent.length > MD_URGENT_TOP) {
        lines.push("");
        lines.push(tx.moreRows(urgent.length - MD_URGENT_TOP));
      }
    }
    lines.push("");
    lines.push(`> ${tx.disclaimer}`);
    lines.push("");
  }

  // Edge case: no findings
  if (summary.totalFindings === 0) {
    lines.push(`## ${t.findingsBySeverity}`);
    lines.push("");
    lines.push(`\u2705 ${t.noIssuesFound}`);
    lines.push("");
  } else {
    // Collect all findings
    const allFindings: Finding[] = listedFindings();

    // Group by severity
    const grouped = new Map<Severity, Finding[]>();
    for (const sev of SEVERITY_ORDER) {
      grouped.set(sev, []);
    }
    for (const f of allFindings) {
      grouped.get(f.severity)!.push(f);
    }

    lines.push(`## ${t.findingsBySeverity}`);
    lines.push("");

    for (const sev of SEVERITY_ORDER) {
      const findings = grouped.get(sev)!;
      const icon = SEVERITY_ICON[sev];
      lines.push(`### ${icon} ${sevLabel[sev]}`);
      lines.push("");

      if (findings.length === 0) {
        lines.push(t.noFindingsForSeverity(sevLabel[sev]));
        lines.push("");
        continue;
      }

      // Sort by riskScore descending
      findings.sort((a, b) => b.riskScore - a.riskScore);
      for (const f of findings) {
        lines.push(renderFinding(f));
        lines.push("");
      }
    }

    if (inspectorSel && inspectorSel.rest.length > 0) {
      const rows = summarizeByCve(inspectorSel.rest);
      lines.push(`### ${tx.cveSummaryTitle(inspectorSel.rest.length, rows.length)}`);
      lines.push("");
      lines.push(tx.cveSummaryNote(inspectorSel.listed.length));
      lines.push("");
      lines.push(`| ${tx.colCve} | ${tx.colAffectedResources} | ${tx.colFindings} | ${tx.colHighestPriority} |`);
      lines.push("|---|---|---|---|");
      for (const r of rows) {
        lines.push(`| ${mdCell(r.cveId)} | ${r.resources} | ${r.findings} | ${r.highestPriority} |`);
      }
      lines.push("");
    }
  }

  // Scan Statistics
  lines.push(`## ${t.scanStatistics}`);
  lines.push(
    `| ${t.module} | ${t.resources} | ${t.findings} | ${t.status} |`,
  );
  lines.push("|--------|------------------|----------|--------|");
  for (const m of modules) {
    const status = m.status === "success" ? "\u2705" : "\u274c";
    lines.push(
      `| ${t.moduleNames[m.module] ?? m.module} | ${m.resourcesScanned} | ${m.findingsCount} | ${status} |`,
    );
  }
  lines.push("");

  // Recommendations
  if (summary.totalFindings > 0) {
    const allFindings: Finding[] = listedFindings();
    allFindings.sort((a, b) => b.riskScore - a.riskScore);

    lines.push(`## ${t.recommendations}`);
    for (let i = 0; i < allFindings.length; i++) {
      const f = allFindings[i];
      lines.push(`${i + 1}. [${f.priority}] ${f.title}: ${f.remediationSteps[0] ?? "Review and remediate."}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
