import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts';
import type { Finding } from '../types';

const DETECTION_MODULES = new Set([
  'guardduty_findings',
  'inspector_findings',
  'config_rules_findings',
  'access_analyzer_findings',
]);

interface ModuleBarProps {
  modules: Array<{ module: string; findingsCount: number; status: string }>;
  findings: Finding[];
}

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

const SH_SOURCE_LABELS: Record<string, string> = {
  FSBP: 'SH: FSBP',
  Inspector: 'SH: Inspector',
  GuardDuty: 'SH: GuardDuty',
  Config: 'SH: Config',
  AA: 'SH: Access Analyzer',
};

function getMaxSeverityColor(items: Finding[]): string {
  if (items.length === 0) return '#22c55e';
  let maxRank = 0;
  let maxSev = 'LOW';
  for (const f of items) {
    const rank = SEVERITY_RANK[f.severity] ?? 0;
    if (rank > maxRank) {
      maxRank = rank;
      maxSev = f.severity;
    }
  }
  return SEVERITY_COLORS[maxSev];
}

function formatModuleName(name: string): string {
  return name
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}

export default function ModuleBar({ modules, findings }: ModuleBarProps) {
  const data: Array<{ name: string; count: number; color: string }> = [];

  for (const m of modules) {
    if (DETECTION_MODULES.has(m.module)) continue;

    if (m.module === 'security_hub_findings') {
      const shFindings = findings.filter(f => f.module === 'security_hub_findings');
      const bySource = new Map<string, Finding[]>();
      for (const f of shFindings) {
        const src = f.source ?? 'Other';
        if (!bySource.has(src)) bySource.set(src, []);
        bySource.get(src)!.push(f);
      }
      for (const [src, srcFindings] of bySource) {
        data.push({
          name: SH_SOURCE_LABELS[src] ?? `SH: ${src}`,
          count: srcFindings.length,
          color: getMaxSeverityColor(srcFindings),
        });
      }
      continue;
    }

    const moduleFindings = findings.filter(f => f.module === m.module);
    data.push({
      name: formatModuleName(m.module),
      count: m.findingsCount,
      color: getMaxSeverityColor(moduleFindings),
    });
  }

  // Filter out modules with 0 findings, then sort descending
  const filtered = data.filter(d => d.count > 0);
  filtered.sort((a, b) => b.count - a.count);

  if (filtered.length === 0) {
    return <div className="text-slate-500 text-sm py-4">No findings to display</div>;
  }

  const chartHeight = Math.max(200, filtered.length * 40 + 40);

  return (
    <ResponsiveContainer width="100%" height={chartHeight}>
      <BarChart data={filtered} layout="vertical" margin={{ left: 20, right: 50, top: 10, bottom: 10 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
        <XAxis type="number" stroke="#94a3b8" fontSize={12} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="name"
          stroke="#94a3b8"
          fontSize={12}
          width={160}
          tick={{ fill: '#cbd5e1' }}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: '#1e293b',
            border: '1px solid #334155',
            borderRadius: '8px',
            color: '#f8fafc',
          }}
          formatter={(value) => [String(value), 'Findings']}
        />
        <Bar dataKey="count" radius={[0, 6, 6, 0]} barSize={20} minPointSize={5}
          label={{ position: 'right', fill: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>
          {filtered.map((entry, index) => (
            <Cell key={index} fill={entry.color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
