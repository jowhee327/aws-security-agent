import type { FullScanResult, Finding, Severity } from "../types.js";

const SEVERITY_ICON: Record<Severity, string> = {
  CRITICAL: "🔴",
  HIGH: "🟠",
  MEDIUM: "🟡",
  LOW: "🟢",
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

function renderFinding(f: Finding): string {
  const steps = f.remediationSteps
    .map((s, i) => `  ${i + 1}. ${s}`)
    .join("\n");

  return [
    `#### ${f.title}`,
    `- **Resource:** ${f.resourceId} (\`${f.resourceArn}\`)`,
    `- **Description:** ${f.description}`,
    `- **Impact:** ${f.impact}`,
    `- **Risk Score:** ${f.riskScore}/10`,
    `- **Remediation:**`,
    steps,
    `- **Priority:** ${f.priority}`,
  ].join("\n");
}

export function generateMarkdownReport(scanResults: FullScanResult): string {
  const { summary, modules, accountId, region, scanStart, scanEnd } =
    scanResults;
  const date = scanStart.split("T")[0];
  const duration = formatDuration(scanStart, scanEnd);

  const lines: string[] = [];

  lines.push(`# AWS Security Scan Report — ${date}`);
  lines.push("");

  // Executive Summary
  lines.push("## Executive Summary");
  lines.push(`- **Account:** ${accountId}`);
  lines.push(`- **Region:** ${region}`);
  lines.push(`- **Scan Duration:** ${duration}`);
  lines.push(
    `- **Total Findings:** ${summary.totalFindings} (🔴 ${summary.critical} Critical | 🟠 ${summary.high} High | 🟡 ${summary.medium} Medium | 🟢 ${summary.low} Low)`,
  );
  lines.push("");

  // Edge case: no findings
  if (summary.totalFindings === 0) {
    lines.push("## Findings by Severity");
    lines.push("");
    lines.push("✅ No security issues found.");
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

    lines.push("## Findings by Severity");
    lines.push("");

    for (const sev of SEVERITY_ORDER) {
      const findings = grouped.get(sev)!;
      const icon = SEVERITY_ICON[sev];
      lines.push(`### ${icon} ${sev.charAt(0)}${sev.slice(1).toLowerCase()}`);
      lines.push("");

      if (findings.length === 0) {
        lines.push(`No ${sev.toLowerCase()} findings.`);
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
  lines.push("## Scan Statistics");
  lines.push(
    "| Module | Resources Scanned | Findings | Status |",
  );
  lines.push("|--------|------------------|----------|--------|");
  for (const m of modules) {
    const status = m.status === "success" ? "✅" : "❌";
    lines.push(
      `| ${m.module} | ${m.resourcesScanned} | ${m.findingsCount} | ${status} |`,
    );
  }
  lines.push("");

  // Recommendations
  if (summary.totalFindings > 0) {
    const allFindings: Finding[] = modules.flatMap((m) => m.findings);
    allFindings.sort((a, b) => b.riskScore - a.riskScore);

    lines.push("## Recommendations (Priority Order)");
    for (let i = 0; i < allFindings.length; i++) {
      const f = allFindings[i];
      lines.push(`${i + 1}. [${f.priority}] ${f.title}: ${f.remediationSteps[0] ?? "Review and remediate."}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
