import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
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

  // Sort by count descending for visual clarity
  data.sort((a, b) => b.count - a.count);

  const chartHeight = Math.max(250, data.length * 36 + 40);

  return (
    <ResponsiveContainer width="100%" height={chartHeight}>
      <BarChart data={data} layout="vertical" margin={{ left: 20, right: 30, top: 10, bottom: 10 }}>
        <XAxis type="number" stroke="#94a3b8" fontSize={12} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="name"
          stroke="#94a3b8"
          fontSize={11}
          width={140}
          tick={{ fill: '#94a3b8' }}
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
        <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={24}>
          {data.map((entry, index) => (
            <Cell key={index} fill={entry.color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
