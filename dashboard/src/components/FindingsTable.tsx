import { useState, useMemo, Fragment } from 'react';
import type { Finding, Severity } from '../types';

interface FindingsTableProps {
  findings: Finding[];
}

const SEVERITY_BADGE: Record<Severity, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-green-500/20 text-green-400 border-green-500/30',
};

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

type SortKey = 'severity' | 'title' | 'module' | 'resourceId' | 'riskScore';
type SortDir = 'asc' | 'desc';

export default function FindingsTable({ findings }: FindingsTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>('riskScore');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set());
  const [moduleFilter, setModuleFilter] = useState<Set<string>>(new Set());
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  const modules = useMemo(
    () => [...new Set(findings.map(f => f.module))].sort(),
    [findings],
  );

  const filtered = useMemo(() => {
    let result = findings;
    if (severityFilter.size > 0) {
      result = result.filter(f => severityFilter.has(f.severity));
    }
    if (moduleFilter.size > 0) {
      result = result.filter(f => moduleFilter.has(f.module));
    }
    return result;
  }, [findings, severityFilter, moduleFilter]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case 'severity':
          cmp = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
          break;
        case 'title':
          cmp = a.title.localeCompare(b.title);
          break;
        case 'module':
          cmp = a.module.localeCompare(b.module);
          break;
        case 'resourceId':
          cmp = a.resourceId.localeCompare(b.resourceId);
          break;
        case 'riskScore':
          cmp = a.riskScore - b.riskScore;
          break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }, [filtered, sortKey, sortDir]);

  function handleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  }

  function toggleSeverity(s: Severity) {
    setSeverityFilter(prev => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  }

  function toggleModule(m: string) {
    setModuleFilter(prev => {
      const next = new Set(prev);
      if (next.has(m)) next.delete(m);
      else next.add(m);
      return next;
    });
  }

  const sortArrow = (key: SortKey) => {
    if (sortKey !== key) return ' ↕';
    return sortDir === 'asc' ? ' ↑' : ' ↓';
  };

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-6">
        <div>
          <span className="text-xs text-slate-400 block mb-2">Severity</span>
          <div className="flex gap-2">
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).map(s => (
              <button
                key={s}
                onClick={() => toggleSeverity(s)}
                className={`text-xs px-3 py-1.5 rounded border transition-colors ${
                  severityFilter.has(s)
                    ? SEVERITY_BADGE[s] + ' border-current'
                    : 'bg-slate-800 text-slate-400 border-slate-700 hover:border-slate-500'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
        <div>
          <span className="text-xs text-slate-400 block mb-2">Module</span>
          <div className="flex gap-2 flex-wrap">
            {modules.map(m => (
              <button
                key={m}
                onClick={() => toggleModule(m)}
                className={`text-xs px-3 py-1.5 rounded border transition-colors ${
                  moduleFilter.has(m)
                    ? 'bg-blue-500/20 text-blue-400 border-blue-500/30'
                    : 'bg-slate-800 text-slate-400 border-slate-700 hover:border-slate-500'
                }`}
              >
                {m}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-slate-700">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-slate-800 text-slate-400 text-left">
              {([
                ['severity', 'Severity'],
                ['title', 'Title'],
                ['module', 'Module'],
                ['resourceId', 'Resource'],
                ['riskScore', 'Risk Score'],
              ] as [SortKey, string][]).map(([key, label]) => (
                <th
                  key={key}
                  onClick={() => handleSort(key)}
                  className="px-4 py-3 font-medium cursor-pointer hover:text-slate-200 select-none whitespace-nowrap"
                >
                  {label}{sortArrow(key)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((f, i) => (
              <Fragment key={`${f.resourceId}-${f.title}`}>
                <tr
                  onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                  className={`border-t border-slate-700 cursor-pointer transition-colors hover:bg-slate-700/50 ${
                    i % 2 === 0 ? 'bg-slate-800/50' : 'bg-slate-800/30'
                  }`}
                >
                  <td className="px-4 py-3">
                    <span
                      className={`text-xs font-semibold px-2 py-0.5 rounded border ${SEVERITY_BADGE[f.severity]}`}
                    >
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-200">{f.title}</td>
                  <td className="px-4 py-3 text-slate-400">{f.module}</td>
                  <td className="px-4 py-3 text-slate-400 font-mono text-xs">{f.resourceId}</td>
                  <td className="px-4 py-3 text-slate-200 font-bold">{f.riskScore}</td>
                </tr>
                {expandedRow === i && (
                  <tr className="bg-slate-800/80">
                    <td colSpan={5} className="px-6 py-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div>
                          <h4 className="text-slate-400 text-xs font-semibold mb-1">Description</h4>
                          <p className="text-slate-300">{f.description}</p>
                        </div>
                        <div>
                          <h4 className="text-slate-400 text-xs font-semibold mb-1">Impact</h4>
                          <p className="text-slate-300">{f.impact}</p>
                        </div>
                        <div className="md:col-span-2">
                          <h4 className="text-slate-400 text-xs font-semibold mb-1">Remediation Steps</h4>
                          <ol className="list-decimal list-inside text-slate-300 space-y-1">
                            {f.remediationSteps.map((step, j) => (
                              <li key={j}>{step}</li>
                            ))}
                          </ol>
                        </div>
                        <div className="md:col-span-2">
                          <span className="text-xs text-slate-500 font-mono">{f.resourceArn}</span>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>

      <div className="text-xs text-slate-500">
        Showing {sorted.length} of {findings.length} findings
      </div>
    </div>
  );
}
