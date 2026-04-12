import { useState, useMemo, Fragment } from 'react';
import { useI18n } from '../i18n';
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

const ALL_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const PAGE_SIZE = 20;

type SortKey = 'severity' | 'title' | 'module' | 'resourceId' | 'riskScore';
type SortDir = 'asc' | 'desc';

export default function FindingsTable({ findings }: FindingsTableProps) {
  const { t } = useI18n();
  const [sortKey, setSortKey] = useState<SortKey>('riskScore');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set());
  const [moduleFilter, setModuleFilter] = useState('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
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
    if (moduleFilter) {
      result = result.filter(f => f.module === moduleFilter);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        f =>
          f.title.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q),
      );
    }
    return result;
  }, [findings, severityFilter, moduleFilter, search]);

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

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const paged = sorted.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

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
    setPage(1);
    setExpandedRow(null);
  }

  function clearSeverityFilter() {
    setSeverityFilter(new Set());
    setPage(1);
    setExpandedRow(null);
  }

  function handleModuleChange(m: string) {
    setModuleFilter(m);
    setPage(1);
    setExpandedRow(null);
  }

  function handleSearch(q: string) {
    setSearch(q);
    setPage(1);
    setExpandedRow(null);
  }

  const sortArrow = (key: SortKey) => {
    if (sortKey !== key) return ' \u2195';
    return sortDir === 'asc' ? ' \u2191' : ' \u2193';
  };

  const columns: [SortKey, string][] = [
    ['severity', t('findings.severity')],
    ['title', t('findings.titleCol')],
    ['module', t('findings.module')],
    ['resourceId', t('findings.resource')],
    ['riskScore', t('findings.riskScore')],
  ];

  return (
    <div className="space-y-4">
      {/* Filter Toolbar */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-4 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          {/* Severity buttons */}
          <button
            onClick={clearSeverityFilter}
            className={`text-xs px-3 py-1.5 rounded border transition-colors font-medium ${
              severityFilter.size === 0
                ? 'bg-blue-500/20 text-blue-400 border-blue-500/30'
                : 'bg-slate-700 text-slate-400 border-slate-600 hover:border-slate-500'
            }`}
          >
            {t('findings.all')}
          </button>
          {ALL_SEVERITIES.map(s => (
            <button
              key={s}
              onClick={() => toggleSeverity(s)}
              className={`text-xs px-3 py-1.5 rounded border transition-colors font-medium ${
                severityFilter.has(s)
                  ? SEVERITY_BADGE[s] + ' border-current'
                  : 'bg-slate-700 text-slate-400 border-slate-600 hover:border-slate-500'
              }`}
            >
              {s}
            </button>
          ))}

          {/* Module dropdown */}
          <select
            value={moduleFilter}
            onChange={e => handleModuleChange(e.target.value)}
            className="text-xs px-3 py-1.5 rounded border border-slate-600 bg-slate-700 text-slate-300 hover:border-slate-500 transition-colors cursor-pointer"
          >
            <option value="">{t('findings.allModules')}</option>
            {modules.map(m => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>

          {/* Search */}
          <div className="flex-1 min-w-[200px]">
            <input
              type="text"
              placeholder={`🔍 ${t('findings.search')}`}
              value={search}
              onChange={e => handleSearch(e.target.value)}
              className="w-full text-sm px-3 py-1.5 rounded border border-slate-600 bg-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-colors"
            />
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-slate-700">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-slate-800 text-slate-400 text-left">
              {columns.map(([key, label]) => (
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
            {paged.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                  {t('findings.noFindings')}
                </td>
              </tr>
            ) : (
              paged.map((f, i) => {
                const globalIndex = (page - 1) * PAGE_SIZE + i;
                return (
                  <Fragment key={`${f.resourceId}-${f.title}-${globalIndex}`}>
                    <tr
                      onClick={() => setExpandedRow(expandedRow === globalIndex ? null : globalIndex)}
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
                    {expandedRow === globalIndex && (
                      <tr className="bg-slate-800/80">
                        <td colSpan={5} className="px-6 py-4">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                            <div>
                              <h4 className="text-slate-400 text-xs font-semibold mb-1">{t('findings.description')}</h4>
                              <p className="text-slate-300">{f.description}</p>
                            </div>
                            <div>
                              <h4 className="text-slate-400 text-xs font-semibold mb-1">{t('findings.impact')}</h4>
                              <p className="text-slate-300">{f.impact}</p>
                            </div>
                            <div className="md:col-span-2">
                              <h4 className="text-slate-400 text-xs font-semibold mb-1">{t('findings.remediation')}</h4>
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
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-xs text-slate-500">
        <span>
          {t('findings.showing')} {sorted.length > 0 ? (page - 1) * PAGE_SIZE + 1 : 0}–{Math.min(page * PAGE_SIZE, sorted.length)} {t('findings.of')} {sorted.length} {t('findings.findingsLabel')}
        </span>
        {totalPages > 1 && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => { setPage(p => Math.max(1, p - 1)); setExpandedRow(null); }}
              disabled={page <= 1}
              className="px-3 py-1 rounded border border-slate-600 text-slate-400 hover:text-slate-200 hover:border-slate-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              {t('findings.prev')}
            </button>
            <span className="text-slate-400">
              {t('findings.page')} {page} / {totalPages}
            </span>
            <button
              onClick={() => { setPage(p => Math.min(totalPages, p + 1)); setExpandedRow(null); }}
              disabled={page >= totalPages}
              className="px-3 py-1 rounded border border-slate-600 text-slate-400 hover:text-slate-200 hover:border-slate-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              {t('findings.next')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
