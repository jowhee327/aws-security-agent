import type { Finding, Severity } from '../types';

interface TopFindingsProps {
  findings: Finding[];
}

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-green-500/20 text-green-400 border-green-500/30',
};

export default function TopFindings({ findings }: TopFindingsProps) {
  const top5 = [...findings]
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 5);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
      {top5.map((f, i) => (
        <div
          key={i}
          className="bg-slate-800 border border-slate-700 rounded-lg p-4 flex flex-col gap-2"
        >
          <div className="flex items-center justify-between">
            <span
              className={`text-xs font-semibold px-2 py-0.5 rounded border ${SEVERITY_COLORS[f.severity]}`}
            >
              {f.severity}
            </span>
            <span className="text-sm font-bold text-slate-300">{f.riskScore}</span>
          </div>
          <h3 className="text-sm font-medium text-slate-100 leading-tight line-clamp-2">
            {f.title}
          </h3>
          <p className="text-xs text-slate-500 truncate">{f.resourceId}</p>
          <p className="text-xs text-slate-600">{f.module}{f.source ? ` (${f.source})` : ''}</p>
        </div>
      ))}
    </div>
  );
}
