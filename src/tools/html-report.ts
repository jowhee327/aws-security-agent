import type { FullScanResult, Finding, Severity, DashboardHistoryEntry, ScanResult } from "../types.js";
import {
  evaluateAllFullChecks,
  MLPS3_CATEGORY_ORDER,
  type FullCheckResult,
} from "./mlps-report.js";
import { VERSION } from "../version.js";
import { getI18n, type Lang } from "../i18n/index.js";

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

/** Escape HTML but render URLs as clickable links */
function escWithLinks(s: string): string {
  const parts = s.split(/(https?:\/\/\S+)/);
  return parts.map((part, i) => {
    if (i % 2 === 1) {
      return `<a href="${esc(part)}" style="color:#60a5fa" target="_blank" rel="noopener">${esc(part)}</a>`;
    }
    return esc(part);
  }).join("");
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
// Service Dependency Reminder
// ---------------------------------------------------------------------------

// SERVICE_RECOMMENDATIONS are now in the i18n module (t.serviceRecommendations)

const SERVICE_NOT_ENABLED_PATTERNS = [
  "not enabled",
  "not found",
  "No IAM Access Analyzer",
  "No SSM-managed instances",
  "requires AWS Business or Enterprise Support",
  "not available",
  "is not enabled",
];

function getDisabledServices(modules: ScanResult[], lang?: Lang): Array<{ icon: string; service: string; impact: string; action: string }> {
  const t = getI18n(lang ?? "zh");
  const disabled: Array<{ icon: string; service: string; impact: string; action: string }> = [];
  for (const mod of modules) {
    const rec = t.serviceRecommendations[mod.module];
    if (!rec) continue;
    if (!mod.warnings?.length) continue;
    const hasNotEnabled = mod.warnings.some((w) =>
      SERVICE_NOT_ENABLED_PATTERNS.some((p) => w.includes(p)),
    );
    if (hasNotEnabled) {
      disabled.push(rec);
    }
  }
  return disabled;
}

function buildServiceReminderHtml(modules: ScanResult[], lang?: Lang): string {
  const t = getI18n(lang ?? "zh");
  const disabled = getDisabledServices(modules, lang);
  if (disabled.length === 0) return "";

  const items = disabled.map((svc) => `
    <div style="margin-bottom:12px">
      <div style="font-weight:600;font-size:15px">${esc(svc.icon)} ${esc(svc.service)} ${esc(t.notEnabled)}</div>
      <div style="margin-left:28px;color:#cbd5e1;font-size:13px">${esc(t.serviceImpact)}\uff1a${esc(svc.impact)}</div>
      <div style="margin-left:28px;color:#cbd5e1;font-size:13px">${esc(t.serviceAction)}\uff1a${esc(svc.action)}</div>
    </div>`).join("\n");

  return `
  <section>
    <div style="background:#2d1f00;border:1px solid #b45309;border-radius:8px;padding:20px;margin-bottom:32px">
      <div style="font-size:17px;font-weight:700;margin-bottom:12px">${esc(t.serviceReminderTitle)}</div>
      ${items}
      <div style="margin-top:12px;font-size:13px;color:#fbbf24;font-weight:500">${esc(t.serviceReminderFooter)}</div>
    </div>
  </section>`;
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
    .rec-fold{background:#1e293b;border:1px solid #334155;border-radius:8px;margin-bottom:16px;overflow:hidden}
    .rec-fold>summary{cursor:pointer;padding:16px 20px;display:flex;align-items:center;gap:12px;list-style:none;user-select:none}
    .rec-fold>summary::-webkit-details-marker{display:none}
    .rec-fold>summary::marker{content:""}
    .rec-fold>summary::after{content:"\\25B6";font-size:12px;color:#64748b;flex-shrink:0;transition:transform 0.2s;margin-left:auto}
    .rec-fold[open]>summary::after{transform:rotate(90deg)}
    .rec-fold[open]>summary{border-bottom:1px solid #334155}
    .rec-body{padding:12px 20px 16px}
    .rec-body ol{padding-left:24px}
    .rec-body li{margin-bottom:8px;color:#cbd5e1;font-size:13px}
    .rec-body .badge{margin-right:6px;vertical-align:middle}
    @media print{
      body{background:#fff;color:#1e293b;-webkit-print-color-adjust:exact;print-color-adjust:exact}
      .container{max-width:100%;padding:20px}
      .card,.score-card,.stat-card,.chart-box,.finding-fold,.top5-card,.trend-chart,.category-fold,.module-fold,.finding-card,.rec-fold{background:#fff;border:1px solid #e2e8f0}
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
      .finding-fold,.top5-card,.category-fold,.module-fold,.finding-card,.rec-fold{break-inside:avoid}
      .check-item{break-inside:avoid}
      svg text{fill:#1e293b !important}
      .finding-fold[open]>summary,.category-fold[open]>summary,.module-fold[open]>summary,.rec-fold[open]>summary{border-bottom-color:#e2e8f0}
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

function barChart(modules: FullScanResult["modules"], allCleanLabel = "All modules clean"): string {
  const withFindings = modules
    .filter((m) => m.findingsCount > 0)
    .sort((a, b) => b.findingsCount - a.findingsCount)
    .slice(0, 12);

  if (withFindings.length === 0) {
    return [
      '<svg viewBox="0 0 400 50" width="100%">',
      `  <text x="200" y="30" text-anchor="middle" fill="#22c55e" font-size="14" font-weight="600">${esc(allCleanLabel)}</text>`,
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
  lang?: Lang,
): string {
  const t = getI18n(lang ?? "zh");
  const htmlLang = (lang ?? "zh") === "zh" ? "zh-CN" : "en";
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
          <div class="top5-detail"><strong>${t.resource}:</strong> ${esc(f.resourceId)}</div>
          <div class="top5-detail"><strong>${t.impact}:</strong> ${esc(f.impact)}</div>
          <div class="top5-detail"><strong>${t.riskScore}:</strong> ${f.riskScore}/10</div>
          <h4>${t.remediation}</h4>
          <ol class="top5-remediation">${f.remediationSteps.map((s) => `<li>${escWithLinks(s)}</li>`).join("")}</ol>
        </div>
      </div>`,
      )
      .join("\n");
    top5Html = `
    <section>
      <h2>${esc(t.topHighestRiskFindings(top5.length))}</h2>
      ${cards}
    </section>`;
  }

  // --- Findings HTML (grouped by module, then severity) ---
  let findingsHtml: string;
  if (summary.totalFindings === 0) {
    findingsHtml = `<div class="no-findings">${esc(t.noIssuesFound)}</div>`;
  } else {
    const FOLD_THRESHOLD = 20;

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

    const renderCards = (findings: Finding[]): string => {
      if (findings.length <= FOLD_THRESHOLD) {
        return findings.map(renderCard).join("\n");
      }
      const first = findings.slice(0, FOLD_THRESHOLD).map(renderCard).join("\n");
      const rest = findings.slice(FOLD_THRESHOLD).map(renderCard).join("\n");
      return `${first}\n<details><summary>${t.showRemainingFindings(findings.length - FOLD_THRESHOLD)}</summary>\n${rest}\n</details>`;
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

        return `<details class="severity-group-fold">
          <summary><h4>${emoji} ${label} (${findings.length})</h4></summary>
          ${renderCards(findings)}
        </details>`;
      }).filter(Boolean).join("\n");

      return `<details class="module-fold">
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
      <h2>${esc(t.trendTitle)}</h2>
      <div class="trend-chart">
        <div class="trend-title">${esc(t.findingsBySeverity)}</div>
        ${findingsTrendChart(history)}
      </div>
      <div class="trend-chart">
        <div class="trend-title">${esc(t.securityScore)}</div>
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

  // --- Recommendations (deduplicated) ---
  let recsHtml = "";
  if (summary.totalFindings > 0) {
    const recMap = new Map<string, { text: string; severity: Severity; count: number; url?: string }>();
    const kbPatches: string[] = [];
    let kbSeverity: Severity = "LOW";
    let kbUrl: string | undefined;
    const genericPatterns = ["See References", "None Provided", "Review the finding", "Review and remediate."];

    for (const f of allFindings) {
      const rem = f.remediationSteps[0] ?? "Review and remediate.";
      const url = f.remediationSteps.find((s) => s.startsWith("Documentation:"))?.replace("Documentation: ", "");

      // Skip generic remediation
      if (genericPatterns.some(p => rem.startsWith(p))) continue;

      // Group KB patches together
      const kbMatch = f.title.match(/KB\d+/);
      if (kbMatch && (f.module === "security_hub_findings" || f.module === "inspector_findings")) {
        kbPatches.push(kbMatch[0]);
        if (SEVERITY_ORDER.indexOf(f.severity) < SEVERITY_ORDER.indexOf(kbSeverity)) kbSeverity = f.severity;
        if (!kbUrl && url) kbUrl = url;
        continue;
      }

      // Group Security Hub findings by control ID
      if (f.module === "security_hub_findings") {
        const controlMatch = f.title.match(/^([A-Z][A-Za-z0-9]*\.\d+)\s/);
        if (controlMatch) {
          const controlId = controlMatch[1];
          const key = `ctrl:${controlId}`;
          const existing = recMap.get(key);
          if (existing) {
            existing.count++;
            if (!existing.url && url) existing.url = url;
            if (SEVERITY_ORDER.indexOf(f.severity) < SEVERITY_ORDER.indexOf(existing.severity)) existing.severity = f.severity;
          } else {
            recMap.set(key, { text: `[${controlId}] ${rem}`, severity: f.severity, count: 1, url });
          }
          continue;
        }
      }

      // Default grouping by remediation text
      const existing = recMap.get(rem);
      if (existing) {
        existing.count++;
        if (!existing.url && url) existing.url = url;
        if (SEVERITY_ORDER.indexOf(f.severity) < SEVERITY_ORDER.indexOf(existing.severity)) {
          existing.severity = f.severity;
        }
      } else {
        recMap.set(rem, { text: rem, severity: f.severity, count: 1, url });
      }
    }

    // Add grouped KB patches as a single entry
    if (kbPatches.length > 0) {
      const unique = [...new Set(kbPatches)];
      const kbList = unique.slice(0, 5).join(", ") + (unique.length > 5 ? ", \u2026" : "");
      recMap.set("__kb__", { text: t.installWindowsPatches(unique.length, kbList), severity: kbSeverity, count: 1, url: kbUrl });
    }

    // Post-process: embed resource count for control-ID groups
    for (const [key, rec] of recMap) {
      if (key.startsWith("ctrl:") && rec.count > 1) {
        rec.text += ` \u2014 ${t.affectedResources(rec.count)}`;
        rec.count = 1;
      }
    }

    const uniqueRecs = [...recMap.values()].sort((a, b) => {
      const sevDiff = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
      if (sevDiff !== 0) return sevDiff;
      return b.count - a.count;
    });

    const renderRec = (r: { text: string; severity: Severity; count: number; url?: string }): string => {
      const sev = r.severity.toLowerCase();
      const countLabel = r.count > 1 ? ` (&times; ${r.count})` : "";
      const linkHtml = r.url ? ` <a href="${esc(r.url)}" style="color:#60a5fa" target="_blank" rel="noopener">&#128214;</a>` : "";
      return `<li><span class="badge badge-${esc(sev)}">${esc(r.severity)}</span> ${esc(r.text)}${countLabel}${linkHtml}</li>`;
    };

    const TOP_N = 10;
    const topItems = uniqueRecs.slice(0, TOP_N).map(renderRec).join("\n");
    const remaining = uniqueRecs.slice(TOP_N);
    const moreHtml = remaining.length > 0
      ? `\n<details><summary>${t.showMoreCount(remaining.length)}</summary>\n${remaining.map(renderRec).join("\n")}\n</details>`
      : "";

    recsHtml = `
      <details class="rec-fold">
        <summary><h2 style="margin:0;border:0;display:inline">${esc(t.recommendations)} (${uniqueRecs.length} ${esc(t.unique)})</h2></summary>
        <div class="rec-body">
          <ol>${topItems}${moreHtml}</ol>
        </div>
      </details>`;
  }

  return `<!DOCTYPE html>
<html lang="${htmlLang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(t.securityReportTitle)} &mdash; ${esc(date)}</title>
<style>${sharedCss()}</style>
</head>
<body>
<div class="container">

<header>
  <h1>&#128737;&#65039; ${esc(t.securityReportTitle)}</h1>
  <div class="meta">${esc(t.account)}: ${esc(accountId)} | ${esc(t.region)}: ${esc(region)} | ${esc(date)} | ${esc(t.duration)}: ${esc(duration)}</div>
</header>

<section class="summary">
  <div class="score-card">
    <div class="score-value" style="color:${scoreColor(score)}">${score}</div>
    <div class="score-label">${esc(t.securityScore)}</div>
  </div>
  <div class="severity-stats">
    <div class="stat-card stat-critical"><div class="stat-count">${summary.critical}</div><div class="stat-label">${esc(t.critical)}</div></div>
    <div class="stat-card stat-high"><div class="stat-count">${summary.high}</div><div class="stat-label">${esc(t.high)}</div></div>
    <div class="stat-card stat-medium"><div class="stat-count">${summary.medium}</div><div class="stat-label">${esc(t.medium)}</div></div>
    <div class="stat-card stat-low"><div class="stat-count">${summary.low}</div><div class="stat-label">${esc(t.low)}</div></div>
  </div>
</section>

<section class="charts">
  <div class="chart-box">
    <div class="chart-title">${esc(t.severityDistribution)}</div>
    <div style="text-align:center">${donutChart(summary)}</div>
  </div>
  <div class="chart-box">
    <div class="chart-title">${esc(t.findingsByModule)}</div>
    ${barChart(modules, t.allModulesClean)}
  </div>
</section>

${trendHtml}

${top5Html}

${buildServiceReminderHtml(modules, lang)}

<section>
  <h2>${esc(t.scanStatistics)}</h2>
  <table>
    <thead><tr><th>${esc(t.module)}</th><th>${esc(t.resources)}</th><th>${esc(t.findings)}</th><th>${esc(t.status)}</th></tr></thead>
    <tbody>${statsRows}</tbody>
  </table>
</section>

<section>
  <h2>${esc(t.allFindings)}</h2>
  ${findingsHtml}
</section>

${recsHtml}

<footer>
  <p>${esc(t.generatedBy)} v${VERSION}</p>
  <p>${esc(t.informationalOnly)}</p>
</footer>

</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// MLPS Level 3 HTML Report (等保三级) — Full GB/T 22239-2019 (184 items)
// ---------------------------------------------------------------------------

export function generateMlps3HtmlReport(
  scanResults: FullScanResult,
  history?: DashboardHistoryEntry[],
  lang?: Lang,
): string {
  const t = getI18n(lang ?? "zh");
  const htmlLang = (lang ?? "zh") === "zh" ? "zh-CN" : "en";
  const { accountId, region, scanStart } = scanResults;
  const date = scanStart.split("T")[0];
  const scanTime = scanStart.replace("T", " ").replace(/\.\d+Z$/, " UTC");

  // Evaluate all 184 checks
  const results = evaluateAllFullChecks(scanResults);

  // Summary counts by type
  const autoResults = results.filter((r) => r.mapping.type === "auto");
  const autoClean = autoResults.filter((r) => r.status === "clean").length;
  const autoIssues = autoResults.filter((r) => r.status === "issues").length;
  const autoUnknown = autoResults.filter((r) => r.status === "unknown").length;
  const checkedTotal = autoClean + autoIssues;
  const cloudCount = results.filter((r) => r.status === "cloud_provider").length;
  const manualCount = results.filter((r) => r.status === "manual").length;
  const naCount = results.filter((r) => r.status === "not_applicable").length;

  // --- Trend Charts ---
  let trendHtml = "";
  if (history && history.length >= 2) {
    trendHtml = `
    <section class="trend-section">
      <h2>${esc(t.trendTitle)}</h2>
      <div class="trend-chart">
        <div class="trend-title">${esc(t.findingsBySeverity)}</div>
        ${findingsTrendChart(history)}
      </div>
      <div class="trend-chart">
        <div class="trend-title">${esc(t.securityScore)}</div>
        ${scoreTrendChart(history)}
      </div>
    </section>`;
  }

  // Helper to pick item text by lang
  const isEn = (lang ?? "zh") === "en";
  const itemCat = (r: FullCheckResult) => isEn ? r.item.categoryEn : r.item.categoryCn;
  const itemControl = (r: FullCheckResult) => isEn ? r.item.controlEn : r.item.controlCn;
  const itemReq = (r: FullCheckResult) => isEn ? r.item.requirementEn : r.item.requirementCn;

  // --- Group results by categoryCn (key is always categoryCn for ordering) ---
  const categoryMap = new Map<string, FullCheckResult[]>();
  for (const r of results) {
    if (r.status === "not_applicable") continue; // N/A items excluded from domain sections
    const cat = r.item.categoryCn;
    if (!categoryMap.has(cat)) categoryMap.set(cat, []);
    categoryMap.get(cat)!.push(r);
  }

  // --- Build domain sections ---
  const categorySections = MLPS3_CATEGORY_ORDER
    .map((category) => {
      const sectionTitle = t.mlpsCategorySection[category] ?? category;
      const catResults = categoryMap.get(category);
      if (!catResults || catResults.length === 0) return "";

      // Check if ALL results in this category are cloud_provider
      const allCloud = catResults.every((r) => r.status === "cloud_provider");
      if (allCloud) {
        return `<details class="category-fold mlps-cloud-section">
  <summary>
    <span class="category-title">${esc(sectionTitle)}</span>
    <span class="category-stats"><span class="category-stat-cloud">\ud83c\udfe2 ${catResults.length} ${esc(t.cloudProvider)}</span></span>
  </summary>
  <div class="category-body">
    <div class="mlps-cloud-note">${esc(t.cloudItemsNote(catResults.length))}</div>
    ${catResults.map((r) => `<div class="check-item check-cloud"><span class="check-icon">\ud83c\udfe2</span><span class="check-name">${esc(r.item.id)} ${esc(itemControl(r))}</span><span class="check-note">${esc(r.mapping.note ?? "")}</span></div>`).join("\n")}
  </div>
</details>`;
      }

      // Mixed category — compute stats
      const catClean = catResults.filter((r) => r.status === "clean").length;
      const catIssues = catResults.filter((r) => r.status === "issues").length;
      const catUnknown = catResults.filter((r) => r.status === "unknown").length;
      const catCloud = catResults.filter((r) => r.status === "cloud_provider").length;
      const catManual = catResults.filter((r) => r.status === "manual").length;

      const statsHtml = [
        catClean > 0 ? `<span class="category-stat-clean">\ud83d\udfe2 ${catClean}</span>` : "",
        catIssues > 0 ? `<span class="category-stat-issues">\ud83d\udd34 ${catIssues}</span>` : "",
        catUnknown > 0 ? `<span class="category-stat-unknown">? ${catUnknown}</span>` : "",
        catCloud > 0 ? `<span class="category-stat-cloud">\ud83c\udfe2 ${catCloud}</span>` : "",
        catManual > 0 ? `<span class="category-stat-manual">\ud83d\udccb ${catManual}</span>` : "",
      ].filter(Boolean).join("");

      // Group by control within category (key by controlCn for grouping stability)
      const controlMap = new Map<string, FullCheckResult[]>();
      for (const r of catResults) {
        const key = r.item.controlCn;
        if (!controlMap.has(key)) controlMap.set(key, []);
        controlMap.get(key)!.push(r);
      }

      const controlGroups = [...controlMap.entries()]
        .map(([_controlKey, controlResults]) => {
          const controlName = itemControl(controlResults[0]);
          // Cloud provider items in this control
          const cloudItems = controlResults.filter((r) => r.status === "cloud_provider");
          const nonCloudItems = controlResults.filter((r) => r.status !== "cloud_provider");

          let itemsHtml = "";

          // Render non-cloud items
          for (const r of nonCloudItems) {
            const icon = r.status === "clean" ? "\ud83d\udfe2"
              : r.status === "issues" ? "\ud83d\udd34"
              : r.status === "unknown" ? "\u2b1c"
              : r.status === "manual" ? "\ud83d\udccb"
              : "\ud83c\udfe2";
            const cls = `check-${r.status === "cloud_provider" ? "cloud" : r.status}`;
            const suffix = r.status === "unknown" ? ` \u2014 ${esc(t.notChecked)}`
              : r.status === "manual" ? ` \u2014 ${esc(r.mapping.guidance ?? t.manualReview)}`
              : "";

            let findingsDetail = "";
            if (r.status === "clean") {
              findingsDetail = `<div class="check-detail">${esc(t.noRelatedIssues)}</div>`;
            } else if (r.status === "issues" && r.relatedFindings.length > 0) {
              const fItems = r.relatedFindings
                .slice(0, 5)
                .map((f) => `<li>${esc(f.severity)}: ${esc(f.title)}</li>`);
              if (r.relatedFindings.length > 5) {
                fItems.push(`<li>${esc(t.andMore(r.relatedFindings.length - 5))}</li>`);
              }
              const remediationHint = r.relatedFindings[0]?.remediationSteps?.[0]
                ? `<p style="color:#fbbf24;font-size:12px;margin-top:4px">${esc(t.remediation)}\uff1a${escWithLinks(r.relatedFindings[0].remediationSteps[0])}</p>`
                : "";
              findingsDetail = `<div class="check-findings-wrap"><details><summary>${esc(t.issuesFoundCount(r.relatedFindings.length))}</summary><ul class="check-findings">${fItems.join("")}</ul>${remediationHint}</details></div>`;
            }

            const reqText = itemReq(r);
            itemsHtml += `<div class="check-item ${cls}"><span class="check-icon">${icon}</span><span class="check-name">${esc(r.item.id)} ${esc(reqText.slice(0, 60))}${reqText.length > 60 ? "\u2026" : ""}${suffix}</span></div>\n${findingsDetail}`;
          }

          // Render cloud items compactly
          if (cloudItems.length > 0) {
            for (const r of cloudItems) {
              const reqText = itemReq(r);
              itemsHtml += `<div class="check-item check-cloud"><span class="check-icon">\ud83c\udfe2</span><span class="check-name">${esc(r.item.id)} ${esc(reqText.slice(0, 50))}${reqText.length > 50 ? "\u2026" : ""}</span><span class="check-note">${esc(t.cloudProvider)}</span></div>\n`;
            }
          }

          const grpClean = controlResults.filter((r) => r.status === "clean").length;
          const grpIssues = controlResults.filter((r) => r.status === "issues").length;
          const grpUnknown = controlResults.filter((r) => r.status === "unknown").length;
          const grpCloud = controlResults.filter((r) => r.status === "cloud_provider").length;
          const grpManual = controlResults.filter((r) => r.status === "manual").length;

          const grpStats = [
            grpClean > 0 ? `<span class="category-stat-clean">\ud83d\udfe2 ${grpClean}</span>` : "",
            grpIssues > 0 ? `<span class="category-stat-issues">\ud83d\udd34 ${grpIssues}</span>` : "",
            grpUnknown > 0 ? `<span class="category-stat-unknown">? ${grpUnknown}</span>` : "",
            grpCloud > 0 ? `<span class="category-stat-cloud">\ud83c\udfe2 ${grpCloud}</span>` : "",
            grpManual > 0 ? `<span class="category-stat-manual">\ud83d\udccb ${grpManual}</span>` : "",
          ].filter(Boolean).join(" ");

          // Items with issues expanded by default, others collapsed
          const hasFailures = grpIssues > 0;
          return `<details class="severity-group-fold"${hasFailures ? " open" : ""}><summary><h4>${esc(controlName)} <span class="category-stats">${grpStats}</span></h4></summary>\n${itemsHtml}\n</details>`;
        })
        .join("\n");

      return `<details class="category-fold">
  <summary>
    <span class="category-title">${esc(sectionTitle)}</span>
    <span class="category-stats">${statsHtml}</span>
  </summary>
  <div class="category-body">${controlGroups}</div>
</details>`;
    })
    .filter(Boolean)
    .join("\n");

  // --- Remediation for failed auto checks (deduplicated) ---
  const failedResults = results.filter((r) => r.status === "issues");
  let remediationHtml = "";
  if (failedResults.length > 0) {
    const mlpsRecMap = new Map<string, { text: string; severity: Severity; count: number; url?: string }>();
    const mlpsKbPatches: string[] = [];
    let mlpsKbSeverity: Severity = "LOW";
    let mlpsKbUrl: string | undefined;
    const mlpsGenericPatterns = ["See References", "None Provided", "Review the finding", "Review and remediate."];

    for (const r of failedResults) {
      for (const f of r.relatedFindings) {
        const rem = f.remediationSteps[0] ?? "Review and remediate.";
        const url = f.remediationSteps.find((s) => s.startsWith("Documentation:"))?.replace("Documentation: ", "");

        // Skip generic remediation
        if (mlpsGenericPatterns.some(p => rem.startsWith(p))) continue;

        // Group KB patches
        const kbMatch = f.title.match(/KB\d+/);
        if (kbMatch && (f.module === "security_hub_findings" || f.module === "inspector_findings")) {
          mlpsKbPatches.push(kbMatch[0]);
          if (SEVERITY_ORDER.indexOf(f.severity) < SEVERITY_ORDER.indexOf(mlpsKbSeverity)) mlpsKbSeverity = f.severity;
          if (!mlpsKbUrl && url) mlpsKbUrl = url;
          continue;
        }

        // Group by control ID for Security Hub
        if (f.module === "security_hub_findings") {
          const controlMatch = f.title.match(/^([A-Z][A-Za-z0-9]*\.\d+)\s/);
          if (controlMatch) {
            const controlId = controlMatch[1];
            const key = `ctrl:${controlId}`;
            const existing = mlpsRecMap.get(key);
            if (existing) {
              existing.count++;
              if (!existing.url && url) existing.url = url;
              if (SEVERITY_ORDER.indexOf(f.severity) < SEVERITY_ORDER.indexOf(existing.severity)) existing.severity = f.severity;
            } else {
              mlpsRecMap.set(key, { text: `[${controlId}] ${rem}`, severity: f.severity, count: 1, url });
            }
            continue;
          }
        }

        const existing = mlpsRecMap.get(rem);
        if (existing) {
          existing.count++;
          if (!existing.url && url) existing.url = url;
          if (SEVERITY_ORDER.indexOf(f.severity) < SEVERITY_ORDER.indexOf(existing.severity)) {
            existing.severity = f.severity;
          }
        } else {
          mlpsRecMap.set(rem, { text: rem, severity: f.severity, count: 1, url });
        }
      }
    }

    // Add grouped KB patches
    if (mlpsKbPatches.length > 0) {
      const unique = [...new Set(mlpsKbPatches)];
      const kbList = unique.slice(0, 5).join(", ") + (unique.length > 5 ? ", \u2026" : "");
      mlpsRecMap.set("__kb__", { text: t.installWindowsPatches(unique.length, kbList), severity: mlpsKbSeverity, count: 1, url: mlpsKbUrl });
    }

    // Post-process: embed resource count for control-ID groups
    for (const [key, rec] of mlpsRecMap) {
      if (key.startsWith("ctrl:") && rec.count > 1) {
        rec.text += ` \u2014 ${t.affectedResources(rec.count)}`;
        rec.count = 1;
      }
    }

    const mlpsUniqueRecs = [...mlpsRecMap.values()].sort((a, b) => {
      const sevDiff = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
      if (sevDiff !== 0) return sevDiff;
      return b.count - a.count;
    });

    if (mlpsUniqueRecs.length > 0) {
      const renderMlpsRec = (r: { text: string; severity: Severity; count: number; url?: string }): string => {
        const sev = r.severity.toLowerCase();
        const countLabel = r.count > 1 ? ` (&times; ${r.count})` : "";
        const linkHtml = r.url ? ` <a href="${esc(r.url)}" style="color:#60a5fa" target="_blank" rel="noopener">&#128214;</a>` : "";
        return `<li><span class="badge badge-${esc(sev)}">${esc(r.severity)}</span> ${esc(r.text)}${countLabel}${linkHtml}</li>`;
      };

      const MLPS_TOP_N = 10;
      const mlpsTopItems = mlpsUniqueRecs.slice(0, MLPS_TOP_N).map(renderMlpsRec).join("\n");
      const mlpsRemaining = mlpsUniqueRecs.slice(MLPS_TOP_N);
      const mlpsMoreHtml = mlpsRemaining.length > 0
        ? `\n<details><summary>${esc(t.showRemaining(mlpsRemaining.length))}&hellip;</summary>\n${mlpsRemaining.map(renderMlpsRec).join("\n")}\n</details>`
        : "";

      remediationHtml = `
        <details class="rec-fold" open>
          <summary><h2 style="margin:0;border:0;display:inline">${esc(t.remediationItems(mlpsUniqueRecs.length))}</h2></summary>
          <div class="rec-body">
            <ol>${mlpsTopItems}${mlpsMoreHtml}</ol>
          </div>
        </details>`;
    }
  }

  // --- N/A count at bottom ---
  const naNote = naCount > 0
    ? `<p style="color:#64748b;font-size:13px;margin-top:24px">${esc(t.naNote(naCount))}</p>`
    : "";

  const unknownNote =
    autoUnknown > 0
      ? `<div style="color:#94a3b8;font-size:12px;margin-top:8px">${esc(t.unknownNote(autoUnknown))}</div>`
      : "";

  const mlpsCss = `
    .mlps-cloud-section>summary{color:#94a3b8}
    .mlps-cloud-note{color:#94a3b8;font-size:13px;margin-bottom:12px;font-style:italic}
    .check-cloud{background:rgba(148,163,184,0.08)}
    .check-cloud .check-note{color:#64748b;font-size:12px;margin-left:auto;white-space:nowrap}
    .check-manual{background:rgba(148,163,184,0.06)}
    .check-clean{background:rgba(34,197,94,0.1);border-left:3px solid #22c55e}
    .check-issues{background:rgba(239,68,68,0.1);border-left:3px solid #ef4444}
    .check-unknown{background:rgba(148,163,184,0.1);border-left:3px solid #94a3b8}
    .check-findings-wrap{margin-left:28px;margin-bottom:4px}
    .check-detail{color:#94a3b8;font-size:13px;margin-left:28px;margin-top:2px}
    .category-stat-clean{color:#22c55e}
    .category-stat-issues{color:#ef4444}
    .category-stat-cloud{color:#94a3b8}
    .category-stat-manual{color:#94a3b8}
    .mlps-summary-cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:32px}
    .mlps-summary-card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px 20px;text-align:center;min-width:100px;flex:1}
    .mlps-summary-card .stat-count{font-size:28px;font-weight:700}
    .mlps-summary-card .stat-label{font-size:12px;color:#94a3b8;margin-top:2px}
  `;

  return `<!DOCTYPE html>
<html lang="${htmlLang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(t.mlpsTitle)} &mdash; ${esc(date)}</title>
<style>${sharedCss()}${mlpsCss}</style>
</head>
<body>
<div class="container">

<header>
  <h1>&#128737;&#65039; ${esc(t.mlpsTitle)}</h1>
  <div class="disclaimer">${esc(t.mlpsDisclaimer)}</div>
  <div class="meta">${esc(t.account)}: ${esc(accountId)} | ${esc(t.region)}: ${esc(region)} | ${esc(t.scanTime)}: ${esc(scanTime)}</div>
</header>

<section class="summary" style="display:block;text-align:center">
  <div style="font-size:36px;font-weight:700;margin-bottom:12px">
    <span style="color:#22c55e">${autoClean}</span> <span style="color:#94a3b8;font-size:18px">${esc(t.noIssues)}</span>
    <span style="color:#475569;margin:0 16px">/</span>
    <span style="color:#ef4444">${autoIssues}</span> <span style="color:#94a3b8;font-size:18px">${esc(t.issuesFound)}</span>
  </div>
  <div class="mlps-summary-cards" style="justify-content:center">
    <div class="mlps-summary-card"><div class="stat-count" style="color:#60a5fa">${checkedTotal}</div><div class="stat-label">${esc(t.checkedItems)}</div></div>
    <div class="mlps-summary-card"><div class="stat-count" style="color:#94a3b8">${cloudCount}</div><div class="stat-label">\ud83c\udfe2 ${esc(t.cloudProvider)}</div></div>
    <div class="mlps-summary-card"><div class="stat-count" style="color:#eab308">${manualCount}</div><div class="stat-label">\ud83d\udccb ${esc(t.manualReview)}</div></div>
    ${naCount > 0 ? `<div class="mlps-summary-card"><div class="stat-count" style="color:#64748b">${naCount}</div><div class="stat-label">\u2796 ${esc(t.notApplicable)}</div></div>` : ""}
  </div>
</section>
${unknownNote}

${trendHtml}

${buildServiceReminderHtml(scanResults.modules, lang)}

${categorySections}

${remediationHtml}

${naNote}

<footer>
  <p>${esc(t.mlpsFooterGenerated(VERSION))}</p>
  <p>${esc(t.mlpsFooterDisclaimer)}</p>
</footer>

</div>
</body>
</html>`;
}
