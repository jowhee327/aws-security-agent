import type { FullScanResult, Finding, Severity } from "../types.js";
import { VERSION } from "../version.js";
import { getI18n, type Lang } from "../i18n/index.js";

// ---------------------------------------------------------------------------
// Helpers (same XSS-safe helpers as html-report.ts)
// ---------------------------------------------------------------------------

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeUrl(url: string): string | null {
  try {
    const u = new URL(url);
    if (u.protocol === "https:" || u.protocol === "http:") return url;
    return null;
  } catch {
    return null;
  }
}

function escWithLinks(s: string): string {
  const parts = s.split(/(https?:\/\/\S+)/);
  return parts
    .map((part, i) => {
      if (i % 2 === 1) {
        const safe = safeUrl(part);
        if (safe) {
          return `<a href="${esc(safe)}" style="color:#60a5fa" target="_blank" rel="noopener">${esc(part)}</a>`;
        }
        return esc(part);
      }
      return esc(part);
    })
    .join("");
}

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
};

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

// ---------------------------------------------------------------------------
// HW Defense SOP section definitions
// ---------------------------------------------------------------------------

interface HwSection {
  id: string;
  autoModules: string[];
  shKeywords: string[];
}

const HW_SECTIONS: HwSection[] = [
  {
    id: "attack_surface",
    autoModules: ["network_reachability", "dns_dangling", "public_access_verify", "waf_coverage"],
    shKeywords: ["network", "public", "exposure", "port", "waf", "firewall", "vpc", "securitygroup"],
  },
  {
    id: "vulnerability_patch",
    autoModules: ["patch_compliance_findings"],
    shKeywords: ["vulnerability", "patch", "cve", "inspector", "software"],
  },
  {
    id: "identity_credential",
    autoModules: ["iam_privilege_escalation", "secret_exposure"],
    shKeywords: ["iam", "access", "privilege", "credential", "password", "mfa", "key rotation"],
  },
  {
    id: "transport_security",
    autoModules: ["ssl_certificate", "imdsv2_enforcement"],
    shKeywords: ["ssl", "tls", "certificate", "imds", "metadata"],
  },
  {
    id: "security_services",
    autoModules: ["service_detection"],
    shKeywords: [],
  },
  {
    id: "emergency_response",
    autoModules: [],
    shKeywords: [],
  },
  {
    id: "environment_control",
    autoModules: [],
    shKeywords: [],
  },
  {
    id: "post_review",
    autoModules: [],
    shKeywords: [],
  },
];

// ---------------------------------------------------------------------------
// CSS (dark theme, same base as html-report.ts with HW-specific additions)
// ---------------------------------------------------------------------------

function hwCss(): string {
  return `
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#0f172a;color:#f8fafc;font-family:Inter,system-ui,-apple-system,sans-serif;line-height:1.6;font-size:14px}
    .container{max-width:900px;margin:0 auto;padding:40px 24px}
    header{text-align:center;margin-bottom:40px;border-bottom:1px solid #334155;padding-bottom:24px}
    header h1{font-size:28px;font-weight:700;margin-bottom:8px;letter-spacing:-0.5px}
    .meta{color:#94a3b8;font-size:13px}
    .disclaimer{color:#94a3b8;font-size:12px;font-style:italic;margin-top:8px;max-width:640px;margin-left:auto;margin-right:auto}
    h2{font-size:20px;font-weight:600;margin:32px 0 16px;padding-bottom:8px;border-bottom:1px solid #334155}
    h3{font-size:16px;font-weight:600;margin:16px 0 8px}
    h4{font-size:14px;font-weight:600;margin:12px 0 4px}
    .summary-cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:32px;justify-content:center}
    .summary-card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px 20px;text-align:center;min-width:100px;flex:1}
    .summary-card .stat-count{font-size:28px;font-weight:700}
    .summary-card .stat-label{font-size:12px;color:#94a3b8;margin-top:2px}
    .badge{display:inline-block;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:0.5px;color:#fff}
    .badge-critical{background:#ef4444}
    .badge-high{background:#f97316}
    .badge-medium{background:#eab308;color:#1e293b}
    .badge-low{background:#22c55e;color:#1e293b}
    .hw-section{background:#1e293b;border:1px solid #334155;border-radius:8px;margin-bottom:16px;overflow:hidden}
    .hw-section>summary{cursor:pointer;padding:16px 20px;display:flex;align-items:center;gap:12px;list-style:none;font-size:16px;font-weight:600;user-select:none;flex-wrap:wrap}
    .hw-section>summary::-webkit-details-marker{display:none}
    .hw-section>summary::marker{content:""}
    .hw-section>summary::after{content:"\\25B6";font-size:12px;color:#64748b;flex-shrink:0;transition:transform 0.2s;margin-left:auto}
    .hw-section[open]>summary::after{transform:rotate(90deg)}
    .hw-section[open]>summary{border-bottom:1px solid #334155}
    .hw-section-body{padding:16px 20px}
    .hw-section-icon{font-size:20px}
    .hw-section-title{flex:1}
    .hw-section-stats{display:inline-flex;gap:8px;font-size:12px;flex-wrap:wrap}
    .hw-section-stats .badge{font-size:10px;padding:1px 8px}
    .hw-auto-section{margin-bottom:16px}
    .hw-auto-section h4{color:#60a5fa;margin-bottom:8px}
    .hw-manual-section h4{color:#fbbf24;margin-bottom:8px}
    .hw-clean{color:#22c55e;font-size:14px;padding:8px 12px;background:rgba(34,197,94,0.1);border-radius:6px}
    .hw-no-auto{color:#94a3b8;font-size:14px;padding:8px 12px;background:rgba(148,163,184,0.08);border-radius:6px}
    .hw-manual-item{display:flex;align-items:flex-start;gap:8px;padding:6px 12px;margin-bottom:4px;font-size:14px;color:#cbd5e1;border-radius:4px;background:rgba(148,163,184,0.06)}
    .hw-manual-checkbox{color:#fbbf24;font-size:16px;flex-shrink:0}
    .finding-card{display:flex;align-items:center;gap:8px;padding:8px 12px;margin-bottom:4px;border-radius:6px;border-left:4px solid #334155;background:rgba(30,41,59,0.5);flex-wrap:wrap}
    .sev-critical{border-left-color:#ef4444}
    .sev-high{border-left-color:#f97316}
    .sev-medium{border-left-color:#eab308}
    .sev-low{border-left-color:#22c55e}
    .finding-title-text{font-weight:600;font-size:13px;flex:1;min-width:200px}
    .finding-resource{color:#94a3b8;font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .finding-card>details{width:100%;margin-top:4px}
    .finding-card>details>summary{cursor:pointer;font-size:12px;color:#60a5fa;user-select:none}
    .finding-card-body{padding:8px 0}
    .finding-card-body p{color:#cbd5e1;font-size:13px;margin-bottom:4px}
    .finding-card-body ol{padding-left:20px}
    .finding-card-body li{color:#cbd5e1;font-size:13px;margin-bottom:2px}
    footer{margin-top:48px;padding-top:24px;border-top:1px solid #334155;text-align:center}
    footer p{color:#64748b;font-size:12px;margin-bottom:4px}
    @media print{
      body{background:#fff;color:#1e293b;-webkit-print-color-adjust:exact;print-color-adjust:exact}
      .container{max-width:100%;padding:20px}
      .hw-section,.summary-card,.finding-card{background:#fff;border:1px solid #e2e8f0}
      .badge{border:1px solid}
      header{border-bottom-color:#e2e8f0}
      h2{border-bottom-color:#e2e8f0}
      footer{border-top-color:#e2e8f0}
      .meta,.disclaimer{color:#64748b}
      .summary-card .stat-label{color:#64748b}
      .finding-title-text{color:#1e293b}
      .finding-resource{color:#64748b}
      .finding-card-body p,.finding-card-body li{color:#475569}
      .hw-section[open]>summary{border-bottom-color:#e2e8f0}
      .hw-manual-item{color:#475569}
      details{display:block}
      details>summary{display:block}
      details>:not(summary){display:block !important}
    }
  `;
}

// ---------------------------------------------------------------------------
// Main report generator
// ---------------------------------------------------------------------------

export function generateHwDefenseHtmlReport(
  scanResults: FullScanResult,
  lang?: Lang,
): string {
  const t = getI18n(lang ?? "zh");
  const htmlLang = (lang ?? "zh") === "zh" ? "zh-CN" : "en";
  const { accountId, region, scanStart } = scanResults;
  const date = scanStart.split("T")[0];
  const scanTime = scanStart.replace("T", " ").replace(/\.\d+Z$/, " UTC");

  // Build module findings map
  const moduleMap = new Map<string, Finding[]>();
  for (const mod of scanResults.modules) {
    const findings = mod.findings.map((f) => ({ ...f, module: f.module ?? mod.module }));
    moduleMap.set(mod.module, findings);
  }

  // Track SH findings already assigned (dedup — first match wins)
  const assignedShFindings = new Set<string>();

  function shFindingKey(f: Finding): string {
    return `${f.title}|${f.resourceId}|${f.resourceArn}`;
  }

  // Process each section
  interface SectionResult {
    id: string;
    findings: Finding[];
    manualItems: string[];
    hasAutoModules: boolean;
    hasAutoResults: boolean;
  }

  const sectionResults: SectionResult[] = [];

  for (const section of HW_SECTIONS) {
    const findings: Finding[] = [];

    // Collect findings from auto modules (non-SH)
    for (const mod of section.autoModules) {
      if (mod === "security_hub_findings") continue;
      const modFindings = moduleMap.get(mod) ?? [];
      findings.push(...modFindings);
    }

    // Collect SH findings by keyword match (dedup across sections)
    if (section.shKeywords.length > 0) {
      const shFindings = moduleMap.get("security_hub_findings") ?? [];
      for (const f of shFindings) {
        const key = shFindingKey(f);
        if (assignedShFindings.has(key)) continue;
        const searchText = `${f.title} ${f.description} ${f.impact}`.toLowerCase();
        if (section.shKeywords.some((kw) => searchText.includes(kw))) {
          findings.push(f);
          assignedShFindings.add(key);
        }
      }
    }

    // Check if this section has any auto modules defined
    const hasAutoModules = section.autoModules.length > 0 || section.shKeywords.length > 0;

    // Check if we actually have scanner results for any of the auto modules
    const hasAutoResults = hasAutoModules && (
      section.autoModules.some((m) => moduleMap.has(m)) ||
      (section.shKeywords.length > 0 && moduleMap.has("security_hub_findings"))
    );

    // Manual items from i18n
    const manualItems = t.hwManualItems[section.id] ?? [];

    sectionResults.push({
      id: section.id,
      findings,
      manualItems,
      hasAutoModules,
      hasAutoResults,
    });
  }

  // Summary stats
  const totalFindings = sectionResults.reduce((sum, s) => sum + s.findings.length, 0);
  const sectionsChecked = sectionResults.filter((s) => s.hasAutoResults || s.manualItems.length > 0).length;
  const autoVerified = sectionResults.filter((s) => s.hasAutoResults).length;
  const totalManualItems = sectionResults.reduce((sum, s) => sum + s.manualItems.length, 0);

  // Render finding card
  const renderCard = (f: Finding): string => {
    const sev = f.severity.toLowerCase();
    return `<div class="finding-card sev-${esc(sev)}">
      <span class="badge badge-${esc(sev)}">${esc(f.severity)}</span>
      <span class="finding-title-text">${esc(f.title)}</span>
      <span class="finding-resource">${esc(f.resourceArn || f.resourceId)}</span>
      <details><summary>${t.details}</summary><div class="finding-card-body">
        <p>${esc(f.description)}</p>
        <p><strong>${t.remediation}:</strong></p>
        <ol>${f.remediationSteps.map((s) => `<li>${escWithLinks(s)}</li>`).join("")}</ol>
      </div></details>
    </div>`;
  };

  // Render sections
  const sectionsHtml = sectionResults
    .map((section) => {
      const meta = t.hwSectionNames[section.id];
      if (!meta) return "";
      const sectionName = meta.name;
      const sectionIcon = meta.icon ?? "";

      // Stats badges for summary line
      const statBadges: string[] = [];
      if (section.findings.length > 0) {
        // Count by severity
        const sevCounts: Record<string, number> = {};
        for (const f of section.findings) {
          sevCounts[f.severity] = (sevCounts[f.severity] ?? 0) + 1;
        }
        for (const sev of SEVERITY_ORDER) {
          if (sevCounts[sev]) {
            statBadges.push(
              `<span class="badge badge-${sev.toLowerCase()}">${sevCounts[sev]} ${sev}</span>`,
            );
          }
        }
      } else if (section.hasAutoResults) {
        statBadges.push(`<span style="color:#22c55e;font-size:12px">&#10003; ${esc(t.hwClean)}</span>`);
      }
      if (section.manualItems.length > 0) {
        statBadges.push(`<span style="color:#fbbf24;font-size:12px">&#9744; ${esc(t.hwManualCount(section.manualItems.length))}</span>`);
      }

      // Auto-check section
      let autoHtml: string;
      if (!section.hasAutoModules) {
        autoHtml = `<div class="hw-no-auto">&#9898; ${esc(t.hwNoAutoCheck)}</div>`;
      } else if (!section.hasAutoResults) {
        autoHtml = `<div class="hw-no-auto">&#9898; ${esc(t.hwNoAutoCheck)}</div>`;
      } else if (section.findings.length === 0) {
        autoHtml = `<div class="hw-clean">&#10004; ${esc(t.hwClean)}</div>`;
      } else {
        // Sort findings: critical first, then by riskScore
        const sorted = [...section.findings].sort((a, b) => {
          const sevDiff = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
          if (sevDiff !== 0) return sevDiff;
          return b.riskScore - a.riskScore;
        });
        autoHtml = sorted.map(renderCard).join("\n");
      }

      // Manual checklist section
      let manualHtml = "";
      if (section.manualItems.length > 0) {
        const items = section.manualItems
          .map((item) => `<div class="hw-manual-item"><span class="hw-manual-checkbox">&#9633;</span>${esc(item)}</div>`)
          .join("\n");
        manualHtml = `
        <div class="hw-manual-section">
          <h4>&#128203; ${esc(t.hwManualCheck)}</h4>
          ${items}
        </div>`;
      }

      // Open by default if there are findings
      const openAttr = section.findings.length > 0 ? " open" : "";

      return `<details class="hw-section"${openAttr}>
  <summary>
    <span class="hw-section-icon">${esc(sectionIcon)}</span>
    <span class="hw-section-title">${esc(sectionName)}</span>
    <span class="hw-section-stats">${statBadges.join(" ")}</span>
  </summary>
  <div class="hw-section-body">
    <div class="hw-auto-section">
      <h4>&#129302; ${esc(t.hwAutoCheck)}</h4>
      ${autoHtml}
    </div>
    ${manualHtml}
  </div>
</details>`;
    })
    .filter(Boolean)
    .join("\n");

  // Determine finding color for summary
  const findingsColor = totalFindings === 0 ? "#22c55e" : totalFindings <= 5 ? "#eab308" : "#ef4444";

  return `<!DOCTYPE html>
<html lang="${htmlLang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(t.hwReportTitle)} &mdash; ${esc(date)}</title>
<style>${hwCss()}</style>
</head>
<body>
<div class="container">

<header>
  <h1>&#128737;&#65039; ${esc(t.hwReportTitle)}</h1>
  <div class="meta">${esc(t.account)}: ${esc(accountId)} | ${esc(t.region)}: ${esc(region)} | ${esc(t.scanTime)}: ${esc(scanTime)}</div>
  <div class="disclaimer">${esc(t.hwReportDisclaimer)}</div>
</header>

<section class="summary-cards">
  <div class="summary-card"><div class="stat-count" style="color:${findingsColor}">${totalFindings}</div><div class="stat-label">${esc(t.hwTotalFindings)}</div></div>
  <div class="summary-card"><div class="stat-count" style="color:#60a5fa">${sectionsChecked}</div><div class="stat-label">${esc(t.hwSectionsChecked)}</div></div>
  <div class="summary-card"><div class="stat-count" style="color:#22c55e">${autoVerified}</div><div class="stat-label">${esc(t.hwAutoVerified)}</div></div>
  <div class="summary-card"><div class="stat-count" style="color:#fbbf24">${totalManualItems}</div><div class="stat-label">${esc(t.hwManualPending)}</div></div>
</section>

${sectionsHtml}

<footer>
  <p>${esc(t.generatedBy)} v${VERSION}</p>
  <p>${esc(t.hwReportDisclaimer)}</p>
</footer>

</div>
</body>
</html>`;
}
