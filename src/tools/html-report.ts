import type { FullScanResult, Finding, Severity, DashboardHistoryEntry } from "../types.js";
import {
  MLPS_CHECKS,
  CATEGORY_ORDER,
  CATEGORY_SECTION,
  evaluateCheck,
} from "./mlps-report.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function calcScore(summary: FullScanResult["summary"]): number {
  const raw =
    100 -
    summary.critical * 15 -
    summary.high * 5 -
    summary.medium * 2 -
    summary.low * 0.5;
  return Math.max(0, Math.min(100, Math.round(raw)));
}

function formatDuration(start: string, end: string): string {
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (ms < 1000) return `${ms}ms`;
  const secs = Math.round(ms / 1000);
  if (secs < 60) return `${secs}s`;
  return `${Math.floor(secs / 60)}m ${secs % 60}s`;
}

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
};

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function scoreColor(score: number): string {
  if (score >= 80) return "#22c55e";
  if (score >= 50) return "#eab308";
  return "#ef4444";
}

// ---------------------------------------------------------------------------
// CSS
// ---------------------------------------------------------------------------

function sharedCss(): string {
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
    .card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:20px;margin-bottom:16px}
    .summary{display:flex;gap:24px;margin-bottom:32px;flex-wrap:wrap}
    .score-card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px 32px;text-align:center;flex:0 0 auto}
    .score-value{font-size:48px;font-weight:700}
    .score-label{color:#94a3b8;font-size:13px;margin-top:4px}
    .severity-stats{display:flex;gap:12px;flex-wrap:wrap;flex:1;align-items:center;justify-content:center}
    .stat-card{border-radius:8px;padding:16px 20px;text-align:center;min-width:100px;border:1px solid #334155;background:#1e293b}
    .stat-count{font-size:28px;font-weight:700}
    .stat-label{font-size:12px;color:#94a3b8;margin-top:2px}
    .stat-critical .stat-count{color:#ef4444}
    .stat-high .stat-count{color:#f97316}
    .stat-medium .stat-count{color:#eab308}
    .stat-low .stat-count{color:#22c55e}
    .charts{display:flex;gap:24px;margin-bottom:32px;flex-wrap:wrap;justify-content:center}
    .chart-box{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:20px;flex:1;min-width:280px}
    .chart-title{font-size:14px;font-weight:600;margin-bottom:12px;text-align:center;color:#cbd5e1}
    .sev-critical{border-left-color:#ef4444}
    .sev-high{border-left-color:#f97316}
    .sev-medium{border-left-color:#eab308}
    .sev-low{border-left-color:#22c55e}
    .badge{display:inline-block;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:0.5px;color:#fff}
    .badge-critical{background:#ef4444}
    .badge-high{background:#f97316}
    .badge-medium{background:#eab308;color:#1e293b}
    .badge-low{background:#22c55e;color:#1e293b}
    .finding-title{font-size:15px;font-weight:600;margin-bottom:8px}
    .finding-detail{color:#cbd5e1;font-size:13px;margin-bottom:4px}
    .finding-detail strong{color:#f8fafc}
    .remediation-steps{margin-top:8px;padding-left:20px}
    .remediation-steps li{color:#cbd5e1;font-size:13px;margin-bottom:4px}
    table{width:100%;border-collapse:collapse;margin-bottom:16px}
    th{background:#334155;color:#f8fafc;padding:10px 12px;text-align:left;font-size:13px;font-weight:600}
    td{padding:8px 12px;border-bottom:1px solid #334155;font-size:13px;color:#cbd5e1}
    tr:hover td{background:rgba(51,65,85,0.3)}
    .recommendations ol{padding-left:24px}
    .recommendations li{margin-bottom:8px;color:#cbd5e1;font-size:13px}
    .priority-p0{color:#ef4444;font-weight:700}
    .priority-p1{color:#f97316;font-weight:700}
    .priority-p2{color:#eab308;font-weight:700}
    .priority-p3{color:#22c55e;font-weight:700}
    footer{margin-top:48px;padding-top:24px;border-top:1px solid #334155;text-align:center}
    footer p{color:#64748b;font-size:12px;margin-bottom:4px}
    .check-item{display:flex;align-items:flex-start;gap:8px;padding:8px 12px;border-radius:6px;margin-bottom:4px;font-size:14px}
    .check-pass{background:rgba(34,197,94,0.1)}
    .check-fail{background:rgba(239,68,68,0.1)}
    .check-unknown{background:rgba(148,163,184,0.1)}
    .check-icon{font-size:16px;flex-shrink:0}
    .check-name{font-weight:500}
    .check-findings{margin-left:28px;margin-top:4px}
    .check-findings li{color:#94a3b8;font-size:12px;margin-bottom:2px;list-style:none}
    .no-findings{text-align:center;padding:40px;color:#22c55e;font-size:18px;font-weight:600}
    .finding-fold{background:#1e293b;border:1px solid #334155;border-radius:8px;margin-bottom:12px;border-left:4px solid;overflow:hidden}
    .finding-fold>summary{cursor:pointer;padding:12px 20px;display:flex;align-items:center;gap:12px;list-style:none;user-select:none}
    .finding-fold>summary::-webkit-details-marker{display:none}
    .finding-fold>summary::marker{content:""}
    .finding-fold>summary .badge{margin-bottom:0}
    .finding-fold>summary::after{content:"\\25B6";font-size:10px;color:#64748b;flex-shrink:0;transition:transform 0.2s}
    .finding-fold[open]>summary::after{transform:rotate(90deg)}
    .finding-fold[open]>summary{border-bottom:1px solid #334155}
    .finding-body{padding:12px 20px 16px}
    .finding-summary-title{font-weight:600;font-size:14px;flex:1}
    .finding-summary-score{color:#94a3b8;font-size:13px;font-weight:600;white-space:nowrap}
    .top5-card{display:flex;gap:16px;background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:16px;border-left:4px solid}
    .top5-card .badge{margin-bottom:0}
    .top5-rank{font-size:28px;font-weight:800;color:#475569;min-width:44px;display:flex;align-items:flex-start;justify-content:center}
    .top5-content{flex:1}
    .top5-title{font-size:17px;font-weight:700;margin:8px 0}
    .top5-detail{color:#cbd5e1;font-size:13px;margin-bottom:4px}
    .top5-detail strong{color:#f8fafc}
    .top5-remediation{margin-top:8px;padding-left:20px}
    .top5-remediation li{color:#cbd5e1;font-size:13px;margin-bottom:4px}
    .trend-section{margin-bottom:32px}
    .trend-chart{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:20px;margin-bottom:16px}
    .trend-title{font-size:14px;font-weight:600;margin-bottom:12px;text-align:center;color:#cbd5e1}
    .category-fold{background:#1e293b;border:1px solid #334155;border-radius:8px;margin-bottom:16px;overflow:hidden}
    .category-fold>summary{cursor:pointer;padding:16px 20px;display:flex;align-items:center;gap:12px;list-style:none;font-size:18px;font-weight:600;user-select:none}
    .category-fold>summary::-webkit-details-marker{display:none}
    .category-fold>summary::marker{content:""}
    .category-fold>summary::after{content:"\\25B6";font-size:12px;color:#64748b;flex-shrink:0;transition:transform 0.2s}
    .category-fold[open]>summary::after{transform:rotate(90deg)}
    .category-fold[open]>summary{border-bottom:1px solid #334155}
    .category-body{padding:12px 20px 16px}
    .category-title{flex:1}
    .category-stats{display:inline-flex;gap:12px;font-size:13px}
    .category-stat-pass{color:#22c55e}
    .category-stat-fail{color:#ef4444}
    .category-stat-unknown{color:#94a3b8}
    .module-fold{background:#1e293b;border:1px solid #334155;border-radius:8px;margin-bottom:16px;overflow:hidden}
    .module-fold>summary{cursor:pointer;padding:16px 20px;display:flex;align-items:center;gap:12px;list-style:none;user-select:none;flex-wrap:wrap}
    .module-fold>summary::-webkit-details-marker{display:none}
    .module-fold>summary::marker{content:""}
    .module-fold>summary h3{margin:0;font-size:16px}
    .module-fold>summary::after{content:"\\25B6";font-size:12px;color:#64748b;flex-shrink:0;transition:transform 0.2s;margin-left:auto}
    .module-fold[open]>summary::after{transform:rotate(90deg)}
    .module-fold[open]>summary{border-bottom:1px solid #334155}
    .module-body{padding:12px 20px 16px}
    .module-badges{display:inline-flex;gap:6px;flex-wrap:wrap}
    .severity-group{margin-bottom:16px}
    .severity-group-fold{margin-bottom:16px}
    .severity-group-fold>summary{cursor:pointer;padding:4px 0;list-style:none;user-select:none}
    .severity-group-fold>summary::-webkit-details-marker{display:none}
    .severity-group-fold>summary::marker{content:""}
    .severity-group-fold>summary h4{margin:0;display:inline}
    .finding-card{display:flex;align-items:center;gap:8px;padding:8px 12px;margin-bottom:4px;border-radius:6px;border-left:4px solid #334155;background:rgba(30,41,59,0.5);flex-wrap:wrap}
    .finding-title-text{font-weight:600;font-size:13px;flex:1;min-width:200px}
    .finding-resource{color:#94a3b8;font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .finding-card>details{width:100%;margin-top:4px}
    .finding-card>details>summary{cursor:pointer;font-size:12px;color:#60a5fa;user-select:none}
    .finding-card-body{padding:8px 0}
    .finding-card-body p{color:#cbd5e1;font-size:13px;margin-bottom:4px}
    .finding-card-body ol{padding-left:20px}
    .finding-card-body li{color:#cbd5e1;font-size:13px;margin-bottom:2px}
    @media print{
      body{background:#fff;color:#1e293b;-webkit-print-color-adjust:exact;print-color-adjust:exact}
      .container{max-width:100%;padding:20px}
      .card,.score-card,.stat-card,.chart-box,.finding-fold,.top5-card,.trend-chart,.category-fold,.module-fold,.finding-card{background:#fff;border:1px solid #e2e8f0}
      .badge{border:1px solid}
      header{border-bottom-color:#e2e8f0}
      h2{border-bottom-color:#e2e8f0}
      th{background:#f1f5f9;color:#1e293b}
      td{border-bottom-color:#e2e8f0;color:#475569}
      footer{border-top-color:#e2e8f0}
      .meta,.disclaimer{color:#64748b}
      .finding-detail,.top5-detail{color:#475569}
      .finding-detail strong,.top5-detail strong{color:#1e293b}
      .stat-label,.score-label{color:#64748b}
      .chart-title,.trend-title{color:#475569}
      .remediation-steps li,.top5-remediation li{color:#475569}
      .recommendations li{color:#475569}
      .finding-card-body p,.finding-card-body li{color:#475569}
      .finding-title-text{color:#1e293b}
      .finding-resource{color:#64748b}
      .check-findings li{color:#64748b}
      .finding-fold,.top5-card,.category-fold,.module-fold,.finding-card{break-inside:avoid}
      .check-item{break-inside:avoid}
      svg text{fill:#1e293b !important}
      .finding-fold[open]>summary,.category-fold[open]>summary,.module-fold[open]>summary{border-bottom-color:#e2e8f0}
      details{display:block}
      details>summary{display:block}
      details>:not(summary){display:block !important}
    }
  `;
}

// ---------------------------------------------------------------------------
// SVG Charts
// ---------------------------------------------------------------------------

function donutChart(summary: FullScanResult["summary"]): string {
  const total = summary.totalFindings;
  const r = 80;
  const circ = 2 * Math.PI * r; // ~502.65

  if (total === 0) {
    return [
      '<svg viewBox="0 0 200 200" width="200" height="200">',
      '  <circle cx="100" cy="100" r="80" fill="none" stroke="#334155" stroke-width="20"/>',
      '  <text x="100" y="105" text-anchor="middle" fill="#22c55e" font-size="24" font-weight="700">0</text>',
      "</svg>",
    ].join("\n");
  }

  const segments: Array<{ count: number; color: string }> = [
    { count: summary.critical, color: SEV_COLOR.CRITICAL },
    { count: summary.high, color: SEV_COLOR.HIGH },
    { count: summary.medium, color: SEV_COLOR.MEDIUM },
    { count: summary.low, color: SEV_COLOR.LOW },
  ].filter((s) => s.count > 0);

  let offset = 0;
  const circles = segments.map((s) => {
    const arc = (s.count / total) * circ;
    const el = `<circle cx="100" cy="100" r="80" fill="none" stroke="${s.color}" stroke-width="20" stroke-dasharray="${arc.toFixed(2)} ${(circ - arc).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}" transform="rotate(-90 100 100)"/>`;
    offset += arc;
    return el;
  });

  return [
    '<svg viewBox="0 0 200 200" width="200" height="200">',
    ...circles.map((c) => `  ${c}`),
    `  <text x="100" y="105" text-anchor="middle" fill="#f8fafc" font-size="28" font-weight="700">${total}</text>`,
    "</svg>",
  ].join("\n");
}

function barChart(modules: FullScanResult["modules"]): string {
  const withFindings = modules
    .filter((m) => m.findingsCount > 0)
    .sort((a, b) => b.findingsCount - a.findingsCount)
    .slice(0, 12);

  if (withFindings.length === 0) {
    return [
      '<svg viewBox="0 0 400 50" width="100%">',
      '  <text x="200" y="30" text-anchor="middle" fill="#22c55e" font-size="14" font-weight="600">All modules clean</text>',
      "</svg>",
    ].join("\n");
  }

  const maxCount = withFindings[0].findingsCount;
  const barH = 22;
  const gap = 6;
  const labelW = 160;
  const maxBarW = 190;
  const height = withFindings.length * (barH + gap);

  const bars = withFindings.map((m, i) => {
    const y = i * (barH + gap);
    const w = Math.max(4, (m.findingsCount / maxCount) * maxBarW);
    const worstSev = m.findings.reduce<Severity>((worst, f) => {
      const idx = SEVERITY_ORDER.indexOf(f.severity);
      return idx < SEVERITY_ORDER.indexOf(worst) ? f.severity : worst;
    }, "LOW");
    const color = SEV_COLOR[worstSev];
    return [
      `<text x="${labelW - 8}" y="${y + barH / 2 + 4}" text-anchor="end" fill="#94a3b8" font-size="11">${esc(m.module)}</text>`,
      `<rect x="${labelW}" y="${y}" width="${w.toFixed(1)}" height="${barH}" rx="3" fill="${color}" opacity="0.85"/>`,
      `<text x="${labelW + w + 6}" y="${y + barH / 2 + 4}" fill="#f8fafc" font-size="11">${m.findingsCount}</text>`,
    ].join("\n");
  });

  return [
    `<svg viewBox="0 0 400 ${height}" width="100%">`,
    ...bars,
    "</svg>",
  ].join("\n");
}

function findingsTrendChart(history: DashboardHistoryEntry[]): string {
  const entries = history.slice(-30);
  if (entries.length < 2) return "";

  const W = 800;
  const H = 260;
  const pad = { top: 30, right: 20, bottom: 50, left: 50 };
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;

  const maxVal = Math.max(
    1,
    ...entries.flatMap((e) => [e.critical, e.high, e.medium, e.low]),
  );

  const xPos = (i: number) =>
    pad.left + (i / Math.max(1, entries.length - 1)) * plotW;
  const yPos = (v: number) => pad.top + plotH - (v / maxVal) * plotH;

  const lines: Array<{
    key: "critical" | "high" | "medium" | "low";
    color: string;
    label: string;
  }> = [
    { key: "critical", color: "#ef4444", label: "Critical" },
    { key: "high", color: "#f97316", label: "High" },
    { key: "medium", color: "#eab308", label: "Medium" },
    { key: "low", color: "#22c55e", label: "Low" },
  ];

  const polylines = lines
    .map((line) => {
      const pts = entries
        .map(
          (e, i) =>
            `${xPos(i).toFixed(1)},${yPos(e[line.key]).toFixed(1)}`,
        )
        .join(" ");
      return `<polyline points="${pts}" fill="none" stroke="${line.color}" stroke-width="2" stroke-linejoin="round"/>`;
    })
    .join("\n  ");

  const xLabels = entries
    .map((e, i) => {
      if (i % 5 !== 0 && i !== entries.length - 1) return "";
      return `<text x="${xPos(i).toFixed(1)}" y="${H - 8}" text-anchor="middle" fill="#94a3b8" font-size="10">${e.date.slice(5)}</text>`;
    })
    .filter(Boolean)
    .join("\n  ");

  const ySteps = 5;
  const yLabels = Array.from({ length: ySteps + 1 }, (_, i) => {
    const val = Math.round((maxVal / ySteps) * i);
    return [
      `<text x="${pad.left - 8}" y="${yPos(val).toFixed(1)}" text-anchor="end" fill="#94a3b8" font-size="10" dominant-baseline="middle">${val}</text>`,
      `<line x1="${pad.left}" y1="${yPos(val).toFixed(1)}" x2="${W - pad.right}" y2="${yPos(val).toFixed(1)}" stroke="#334155" stroke-width="0.5"/>`,
    ].join("\n  ");
  }).join("\n  ");

  const legend = lines
    .map((line, i) => {
      const lx = pad.left + i * 110;
      return `<rect x="${lx}" y="8" width="14" height="3" rx="1" fill="${line.color}"/><text x="${lx + 18}" y="12" fill="#94a3b8" font-size="10">${line.label}</text>`;
    })
    .join("\n  ");

  return [
    `<svg viewBox="0 0 ${W} ${H}" width="100%" preserveAspectRatio="xMidYMid meet">`,
    `  ${legend}`,
    `  ${yLabels}`,
    `  ${polylines}`,
    `  ${xLabels}`,
    "</svg>",
  ].join("\n");
}

function scoreTrendChart(history: DashboardHistoryEntry[]): string {
  const entries = history.slice(-30);
  if (entries.length < 2) return "";

  const W = 800;
  const H = 220;
  const pad = { top: 20, right: 20, bottom: 50, left: 50 };
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;

  const xPos = (i: number) =>
    pad.left + (i / Math.max(1, entries.length - 1)) * plotW;
  const yPos = (v: number) => pad.top + plotH - (v / 100) * plotH;

  const pts = entries
    .map((e, i) => `${xPos(i).toFixed(1)},${yPos(e.score).toFixed(1)}`)
    .join(" ");

  const zones = [
    `<rect x="${pad.left}" y="${yPos(100).toFixed(1)}" width="${plotW}" height="${(yPos(80) - yPos(100)).toFixed(1)}" fill="#22c55e" opacity="0.06"/>`,
    `<rect x="${pad.left}" y="${yPos(80).toFixed(1)}" width="${plotW}" height="${(yPos(50) - yPos(80)).toFixed(1)}" fill="#eab308" opacity="0.06"/>`,
    `<rect x="${pad.left}" y="${yPos(50).toFixed(1)}" width="${plotW}" height="${(yPos(0) - yPos(50)).toFixed(1)}" fill="#ef4444" opacity="0.06"/>`,
  ].join("\n  ");

  const xLabels = entries
    .map((e, i) => {
      if (i % 5 !== 0 && i !== entries.length - 1) return "";
      return `<text x="${xPos(i).toFixed(1)}" y="${H - 8}" text-anchor="middle" fill="#94a3b8" font-size="10">${e.date.slice(5)}</text>`;
    })
    .filter(Boolean)
    .join("\n  ");

  const yVals = [0, 25, 50, 75, 100];
  const yLabels = yVals
    .map(
      (val) =>
        `<text x="${pad.left - 8}" y="${yPos(val).toFixed(1)}" text-anchor="end" fill="#94a3b8" font-size="10" dominant-baseline="middle">${val}</text>\n  <line x1="${pad.left}" y1="${yPos(val).toFixed(1)}" x2="${W - pad.right}" y2="${yPos(val).toFixed(1)}" stroke="#334155" stroke-width="0.5"/>`,
    )
    .join("\n  ");

  return [
    `<svg viewBox="0 0 ${W} ${H}" width="100%" preserveAspectRatio="xMidYMid meet">`,
    `  ${zones}`,
    `  ${yLabels}`,
    `  <polyline points="${pts}" fill="none" stroke="#60a5fa" stroke-width="2.5" stroke-linejoin="round"/>`,
    `  ${xLabels}`,
    "</svg>",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// General HTML Report
// ---------------------------------------------------------------------------

export function generateHtmlReport(
  scanResults: FullScanResult,
  history?: DashboardHistoryEntry[],
): string {
  const { summary, modules, accountId, region, scanStart, scanEnd } =
    scanResults;
  const date = scanStart.split("T")[0];
  const duration = formatDuration(scanStart, scanEnd);
  const score = calcScore(summary);

  const allFindings: Finding[] = modules.flatMap((m) =>
    m.findings.map((f) => ({ ...f, module: f.module ?? m.module })),
  );

  // --- Top 5 Findings ---
  let top5Html = "";
  if (allFindings.length > 0) {
    const top5 = [...allFindings]
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, 5);
    const cards = top5
      .map(
        (f, i) => `
      <div class="top5-card sev-${esc(f.severity.toLowerCase())}">
        <div class="top5-rank">#${i + 1}</div>
        <div class="top5-content">
          <span class="badge badge-${esc(f.severity.toLowerCase())}">${esc(f.severity)}</span>
          <div class="top5-title">${esc(f.title)}</div>
          <div class="top5-detail"><strong>Resource:</strong> ${esc(f.resourceId)}</div>
          <div class="top5-detail"><strong>Impact:</strong> ${esc(f.impact)}</div>
          <div class="top5-detail"><strong>Risk Score:</strong> ${f.riskScore}/10</div>
          <h4>Remediation</h4>
          <ol class="top5-remediation">${f.remediationSteps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
        </div>
      </div>`,
      )
      .join("\n");
    top5Html = `
    <section>
      <h2>Top ${top5.length} Highest Risk Findings</h2>
      ${cards}
    </section>`;
  }

  // --- Findings HTML (grouped by module, then severity) ---
  let findingsHtml: string;
  if (summary.totalFindings === 0) {
    findingsHtml = '<div class="no-findings">No security issues found.</div>';
  } else {
    const FOLD_THRESHOLD = 20;

    const renderCard = (f: Finding): string => {
      const sev = f.severity.toLowerCase();
      return `<div class="finding-card sev-${esc(sev)}">
        <span class="badge badge-${esc(sev)}">${esc(f.severity)}</span>
        <span class="finding-title-text">${esc(f.title)}</span>
        <span class="finding-resource">${esc(f.resourceArn || f.resourceId)}</span>
        <details><summary>Details</summary><div class="finding-card-body">
          <p>${esc(f.description)}</p>
          <p><strong>Remediation:</strong></p>
          <ol>${f.remediationSteps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
        </div></details>
      </div>`;
    };

    const renderCards = (findings: Finding[]): string => {
      if (findings.length <= FOLD_THRESHOLD) {
        return findings.map(renderCard).join("\n");
      }
      const first = findings.slice(0, FOLD_THRESHOLD).map(renderCard).join("\n");
      const rest = findings.slice(FOLD_THRESHOLD).map(renderCard).join("\n");
      return `${first}\n<details><summary>Show remaining ${findings.length - FOLD_THRESHOLD} findings...</summary>\n${rest}\n</details>`;
    };

    const SEV_EMOJI: Record<string, string> = {
      CRITICAL: "&#128308;",
      HIGH: "&#128992;",
      MEDIUM: "&#128993;",
      LOW: "&#128309;",
    };

    // Group findings by module
    const moduleMap = new Map<string, Finding[]>();
    for (const f of allFindings) {
      const mod = f.module ?? "unknown";
      if (!moduleMap.has(mod)) moduleMap.set(mod, []);
      moduleMap.get(mod)!.push(f);
    }

    // Sort modules: those with critical/high first, then by count
    const moduleEntries = [...moduleMap.entries()].sort((a, b) => {
      const aHasCritHigh = a[1].some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
      const bHasCritHigh = b[1].some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
      if (aHasCritHigh !== bHasCritHigh) return aHasCritHigh ? -1 : 1;
      return b[1].length - a[1].length;
    });

    findingsHtml = moduleEntries.map(([modName, modFindings]) => {
      const hasCritHigh = modFindings.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
      const openAttr = hasCritHigh ? " open" : "";

      const sevCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      for (const f of modFindings) sevCounts[f.severity]++;

      const badges = SEVERITY_ORDER
        .filter((sev) => sevCounts[sev] > 0)
        .map((sev) => `<span class="badge badge-${sev.toLowerCase()}">${sevCounts[sev]} ${sev.charAt(0) + sev.slice(1).toLowerCase()}</span>`)
        .join(" ");

      const sevGroups = SEVERITY_ORDER.map((sev) => {
        const findings = modFindings.filter((f) => f.severity === sev);
        if (findings.length === 0) return "";
        findings.sort((a, b) => b.riskScore - a.riskScore);

        const emoji = SEV_EMOJI[sev] ?? "";
        const label = sev.charAt(0) + sev.slice(1).toLowerCase();
        const isCritHigh = sev === "CRITICAL" || sev === "HIGH";

        if (isCritHigh) {
          return `<div class="severity-group">
            <h4>${emoji} ${label} (${findings.length})</h4>
            ${renderCards(findings)}
          </div>`;
        }
        return `<details class="severity-group-fold">
          <summary><h4>${emoji} ${label} (${findings.length}) &mdash; click to expand</h4></summary>
          ${renderCards(findings)}
        </details>`;
      }).filter(Boolean).join("\n");

      return `<details class="module-fold"${openAttr}>
        <summary>
          <h3>&#128274; ${esc(modName)} (${modFindings.length})</h3>
          <span class="module-badges">${badges}</span>
        </summary>
        <div class="module-body">
          ${sevGroups}
        </div>
      </details>`;
    }).join("\n");
  }

  // --- Trend Charts ---
  let trendHtml = "";
  if (history && history.length >= 2) {
    trendHtml = `
    <section class="trend-section">
      <h2>30-Day Trends</h2>
      <div class="trend-chart">
        <div class="trend-title">Findings by Severity</div>
        ${findingsTrendChart(history)}
      </div>
      <div class="trend-chart">
        <div class="trend-title">Security Score</div>
        ${scoreTrendChart(history)}
      </div>
    </section>`;
  }

  // --- Statistics table ---
  const statsRows = modules
    .map(
      (m) =>
        `<tr><td>${esc(m.module)}</td><td>${m.resourcesScanned}</td><td>${m.findingsCount}</td><td>${m.status === "success" ? "&#10003;" : "&#10007;"}</td></tr>`,
    )
    .join("\n");

  // --- Recommendations ---
  let recsHtml = "";
  if (summary.totalFindings > 0) {
    const sorted = [...allFindings].sort((a, b) => b.riskScore - a.riskScore);
    const items = sorted
      .map((f) => {
        const pc = f.priority.toLowerCase();
        const rem = f.remediationSteps[0] ?? "Review and remediate.";
        return `<li><span class="priority-${esc(pc)}">[${esc(f.priority)}]</span> ${esc(f.title)}: ${esc(rem)}</li>`;
      })
      .join("\n");
    recsHtml = `
      <section class="recommendations">
        <h2>Recommendations (Priority Order)</h2>
        <ol>${items}</ol>
      </section>`;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AWS Security Scan Report &mdash; ${esc(date)}</title>
<style>${sharedCss()}</style>
</head>
<body>
<div class="container">

<header>
  <h1>&#128737;&#65039; AWS Security Scan Report</h1>
  <div class="meta">Account: ${esc(accountId)} | Region: ${esc(region)} | ${esc(date)} | Duration: ${esc(duration)}</div>
</header>

<section class="summary">
  <div class="score-card">
    <div class="score-value" style="color:${scoreColor(score)}">${score}</div>
    <div class="score-label">Security Score</div>
  </div>
  <div class="severity-stats">
    <div class="stat-card stat-critical"><div class="stat-count">${summary.critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card stat-high"><div class="stat-count">${summary.high}</div><div class="stat-label">High</div></div>
    <div class="stat-card stat-medium"><div class="stat-count">${summary.medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card stat-low"><div class="stat-count">${summary.low}</div><div class="stat-label">Low</div></div>
  </div>
</section>

<section class="charts">
  <div class="chart-box">
    <div class="chart-title">Severity Distribution</div>
    <div style="text-align:center">${donutChart(summary)}</div>
  </div>
  <div class="chart-box">
    <div class="chart-title">Findings by Module</div>
    ${barChart(modules)}
  </div>
</section>

${trendHtml}

${top5Html}

<section>
  <h2>Scan Statistics</h2>
  <table>
    <thead><tr><th>Module</th><th>Resources</th><th>Findings</th><th>Status</th></tr></thead>
    <tbody>${statsRows}</tbody>
  </table>
</section>

<section>
  <h2>All Findings</h2>
  ${findingsHtml}
</section>

${recsHtml}

<footer>
  <p>Generated by AWS Security MCP Server v0.3.0</p>
  <p>This report is for informational purposes only.</p>
</footer>

</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// MLPS Level 3 HTML Report (等保三级)
// ---------------------------------------------------------------------------

export function generateMlps3HtmlReport(
  scanResults: FullScanResult,
  history?: DashboardHistoryEntry[],
): string {
  const { accountId, region, scanStart } = scanResults;
  const date = scanStart.split("T")[0];
  const scanTime = scanStart.replace("T", " ").replace(/\.\d+Z$/, " UTC");

  const allFindings: Finding[] = scanResults.modules.flatMap((m) =>
    m.findings.map((f) => ({ ...f, module: f.module ?? m.module })),
  );

  const scanModules = scanResults.modules.map((m) => ({
    module: m.module,
    status: m.status,
  }));
  const results = MLPS_CHECKS.map((check) =>
    evaluateCheck(check, allFindings, scanModules),
  );

  const passCount = results.filter((r) => r.status === "pass").length;
  const failCount = results.filter((r) => r.status === "fail").length;
  const unknownCount = results.filter((r) => r.status === "unknown").length;
  const checkedTotal = passCount + failCount;
  const percent =
    checkedTotal > 0 ? Math.round((passCount / checkedTotal) * 100) : 0;

  // --- Trend Charts ---
  let trendHtml = "";
  if (history && history.length >= 2) {
    trendHtml = `
    <section class="trend-section">
      <h2>30日趋势</h2>
      <div class="trend-chart">
        <div class="trend-title">按严重性分类的发现</div>
        ${findingsTrendChart(history)}
      </div>
      <div class="trend-chart">
        <div class="trend-title">安全评分</div>
        ${scoreTrendChart(history)}
      </div>
    </section>`;
  }

  // --- Category sections (folded) ---
  const categorySections = CATEGORY_ORDER.map((category) => {
    const sectionTitle = CATEGORY_SECTION[category];
    const categoryResults = results.filter(
      (r) => r.check.category === category,
    );
    if (categoryResults.length === 0) return "";

    const catPass = categoryResults.filter((r) => r.status === "pass").length;
    const catFail = categoryResults.filter((r) => r.status === "fail").length;
    const catUnknown = categoryResults.filter(
      (r) => r.status === "unknown",
    ).length;
    const hasFailure = catFail > 0;
    const openAttr = hasFailure ? " open" : "";

    const byId = new Map<string, typeof categoryResults>();
    for (const r of categoryResults) {
      const existing = byId.get(r.check.id) ?? [];
      existing.push(r);
      byId.set(r.check.id, existing);
    }

    const groups = [...byId.entries()]
      .map(([checkId, checkResults]) => {
        const items = checkResults
          .map((r) => {
            const icon =
              r.status === "pass"
                ? "&#10004;"
                : r.status === "fail"
                  ? "&#10008;"
                  : "&#9888;";
            const cls = `check-${r.status}`;
            const label = r.status === "unknown" ? " (未检查)" : "";
            let findingsHtml = "";
            if (r.status === "fail" && r.relatedFindings.length > 0) {
              const items = r.relatedFindings
                .slice(0, 3)
                .map(
                  (f) =>
                    `<li>${esc(f.severity)}: ${esc(f.title)}</li>`,
                );
              if (r.relatedFindings.length > 3) {
                items.push(
                  `<li>... 及其他 ${r.relatedFindings.length - 3} 项</li>`,
                );
              }
              findingsHtml = `<ul class="check-findings">${items.join("")}</ul>`;
            }
            return `<div class="check-item ${cls}"><span class="check-icon">${icon}</span><span class="check-name">${esc(r.check.name)}${label}</span></div>${findingsHtml}`;
          })
          .join("\n");
        return `<h3>${esc(checkId)} ${esc(checkResults[0].check.name)}</h3>\n${items}`;
      })
      .join("\n");

    const statsHtml = [
      catPass > 0
        ? `<span class="category-stat-pass">&#10003; ${catPass}</span>`
        : "",
      catFail > 0
        ? `<span class="category-stat-fail">&#10007; ${catFail}</span>`
        : "",
      catUnknown > 0
        ? `<span class="category-stat-unknown">? ${catUnknown}</span>`
        : "",
    ]
      .filter(Boolean)
      .join("");

    return `<details class="category-fold"${openAttr}>
  <summary>
    <span class="category-title">${esc(sectionTitle)}</span>
    <span class="category-stats">${statsHtml}</span>
  </summary>
  <div class="category-body">${groups}</div>
</details>`;
  })
    .filter(Boolean)
    .join("\n");

  // --- Remediation ---
  const failedResults = results.filter((r) => r.status === "fail");
  let remediationHtml = "";
  if (failedResults.length > 0) {
    const allFailedFindings = new Map<string, Finding>();
    for (const r of failedResults) {
      for (const f of r.relatedFindings) {
        const key = `${f.resourceId}:${f.title}`;
        if (!allFailedFindings.has(key)) {
          allFailedFindings.set(key, f);
        }
      }
    }
    const sorted = [...allFailedFindings.values()].sort(
      (a, b) => b.riskScore - a.riskScore,
    );
    const items = sorted
      .map((f) => {
        const p =
          f.riskScore >= 9.0
            ? "P0"
            : f.riskScore >= 7.0
              ? "P1"
              : f.riskScore >= 4.0
                ? "P2"
                : "P3";
        const rem = f.remediationSteps[0] ?? "Review and remediate.";
        return `<li><span class="priority-${p.toLowerCase()}">[${p}]</span> ${esc(f.title)} &mdash; ${esc(rem)}</li>`;
      })
      .join("\n");
    remediationHtml = `
      <section class="recommendations">
        <h2>建议整改项（按优先级）</h2>
        <ol>${items}</ol>
      </section>`;
  }

  const passRateColor =
    percent >= 80 ? "#22c55e" : percent >= 50 ? "#eab308" : "#ef4444";
  const unknownNote =
    unknownCount > 0
      ? `<div style="color:#94a3b8;font-size:12px;margin-top:8px">（未检查项不计入通过率）</div>`
      : "";

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>等保三级预检报告 &mdash; ${esc(date)}</title>
<style>${sharedCss()}</style>
</head>
<body>
<div class="container">

<header>
  <h1>&#128737;&#65039; 等保三级预检报告</h1>
  <div class="disclaimer">本报告为等保预检参考，仅覆盖 AWS 云平台配置检查。完整等保测评需由持证测评机构执行。</div>
  <div class="meta">账户: ${esc(accountId)} | 区域: ${esc(region)} | 扫描时间: ${esc(scanTime)}</div>
</header>

<section class="summary">
  <div class="score-card">
    <div class="score-value" style="color:${passRateColor}">${percent}%</div>
    <div class="score-label">通过率</div>
  </div>
  <div class="severity-stats">
    <div class="stat-card" style="border-color:#22c55e30"><div class="stat-count" style="color:#22c55e">${passCount}</div><div class="stat-label">通过</div></div>
    <div class="stat-card" style="border-color:#ef444430"><div class="stat-count" style="color:#ef4444">${failCount}</div><div class="stat-label">不通过</div></div>
    ${unknownCount > 0 ? `<div class="stat-card" style="border-color:#94a3b830"><div class="stat-count" style="color:#94a3b8">${unknownCount}</div><div class="stat-label">未检查</div></div>` : ""}
  </div>
</section>
${unknownNote}

${trendHtml}

${categorySections}

${remediationHtml}

<footer>
  <p>由 AWS Security MCP Server v0.3.0 生成</p>
  <p>本报告仅供参考。完整等保测评需由持证测评机构执行。</p>
</footer>

</div>
</body>
</html>`;
}
