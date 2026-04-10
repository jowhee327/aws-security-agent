import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import type { Finding } from '../types';

interface ModuleBarProps {
  modules: Array<{ module: string; findingsCount: number }>;
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

function getModuleColor(moduleName: string, findings: Finding[]): string {
  const moduleFindings = findings.filter(f => f.module === moduleName);
  if (moduleFindings.length === 0) return '#22c55e';

  let maxSeverity = 'LOW';
  let maxRank = 0;
  for (const f of moduleFindings) {
    const rank = SEVERITY_RANK[f.severity] ?? 0;
    if (rank > maxRank) {
      maxRank = rank;
      maxSeverity = f.severity;
    }
  }
  return SEVERITY_COLORS[maxSeverity];
}

export default function ModuleBar({ modules, findings }: ModuleBarProps) {
  const data = modules.map(m => ({
    name: m.module,
    count: m.findingsCount,
    color: getModuleColor(m.module, findings),
  }));

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data} layout="vertical" margin={{ left: 20, right: 30, top: 10, bottom: 10 }}>
        <XAxis type="number" stroke="#94a3b8" fontSize={12} />
        <YAxis
          type="category"
          dataKey="name"
          stroke="#94a3b8"
          fontSize={12}
          width={80}
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
