import { useI18n } from '../i18n';
import type { DashboardData } from '../types';
import ScoreGauge from '../components/ScoreGauge';
import SeverityChart from '../components/SeverityChart';
import TopFindings from '../components/TopFindings';
import ModuleBar from '../components/ModuleBar';

interface OverviewProps {
  data: DashboardData;
}

export default function Overview({ data }: OverviewProps) {
  const { t } = useI18n();
  const { summary, modules, findings, scanStart, scanEnd } = data.lastScan;
  const latestScore = data.history[data.history.length - 1]?.score ?? 0;

  const scanDuration = Math.round(
    (new Date(scanEnd).getTime() - new Date(scanStart).getTime()) / 1000,
  );

  const disabledModules = modules.filter(m => m.status === 'disabled');

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-slate-50">{t('overview.title')}</h2>

      {/* Quick Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-4">
          <div className="text-xs text-slate-400 mb-1">{t('overview.totalFindings')}</div>
          <div className="text-2xl font-bold text-slate-50">{summary.totalFindings}</div>
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-4">
          <div className="text-xs text-slate-400 mb-1">{t('overview.modulesScanned')}</div>
          <div className="text-2xl font-bold text-slate-50">{summary.modulesSuccess}</div>
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-4">
          <div className="text-xs text-slate-400 mb-1">{t('overview.scanTime')}</div>
          <div className="text-2xl font-bold text-slate-50">{scanDuration}{t('seconds')}</div>
        </div>
        {disabledModules.length > 0 && (
          <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-lg p-4">
            <div className="text-xs text-yellow-400/80 mb-1">{t('overview.disabledServices')}</div>
            <div className="text-2xl font-bold text-yellow-400">{disabledModules.length}</div>
            <div className="text-xs text-yellow-500/60 mt-1">
              {disabledModules
                .map(m => m.module.replace(/_findings$/, '').replace(/_/g, ' '))
                .join(', ')}
            </div>
          </div>
        )}
      </div>

      {/* Score + Severity row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 flex items-center justify-center">
          <ScoreGauge score={latestScore} />
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-slate-200 mb-2">{t('overview.severity')}</h3>
          <SeverityChart
            critical={summary.critical}
            high={summary.high}
            medium={summary.medium}
            low={summary.low}
          />
        </div>
      </div>

      {/* Top Findings */}
      <div>
        <h3 className="text-lg font-semibold text-slate-200 mb-4">{t('overview.topFindings')}</h3>
        <TopFindings findings={findings} />
      </div>

      {/* Module Breakdown with SH sub-categories */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-slate-200 mb-2">{t('overview.moduleBreakdown')}</h3>
        <ModuleBar modules={modules} findings={findings} />
      </div>
    </div>
  );
}
