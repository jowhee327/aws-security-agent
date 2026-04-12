import type { FullScanResult, Finding, Severity } from "../types.js";
import { getI18n, type Lang } from "../i18n/index.js";

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

export function generateMarkdownReport(scanResults: FullScanResult, lang?: Lang): string {
  const t = getI18n(lang ?? "zh");
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

  function renderFinding(f: Finding): string {
    const steps = f.remediationSteps
      .map((s, i) => `  ${i + 1}. ${s}`)
      .join("\n");

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

  // Edge case: no findings
  if (summary.totalFindings === 0) {
    lines.push(`## ${t.findingsBySeverity}`);
    lines.push("");
    lines.push(`\u2705 ${t.noIssuesFound}`);
    lines.push("");
  } else {
    // Collect all findings
    const allFindings: Finding[] = modules.flatMap((m) => m.findings);

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
      `| ${m.module} | ${m.resourcesScanned} | ${m.findingsCount} | ${status} |`,
    );
  }
  lines.push("");

  // Recommendations
  if (summary.totalFindings > 0) {
    const allFindings: Finding[] = modules.flatMap((m) => m.findings);
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
