import type { DashboardData } from '../types';
import ScoreGauge from '../components/ScoreGauge';
import SeverityChart from '../components/SeverityChart';
import TopFindings from '../components/TopFindings';
import ModuleBar from '../components/ModuleBar';

interface OverviewProps {
  data: DashboardData;
}

export default function Overview({ data }: OverviewProps) {
  const { summary, modules, findings } = data.lastScan;
  const latestScore = data.history[data.history.length - 1]?.score ?? 0;

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-slate-50">Overview</h2>

      {/* Score + Severity row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 flex items-center justify-center">
          <ScoreGauge score={latestScore} />
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-slate-200 mb-2">Severity Distribution</h3>
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
        <h3 className="text-lg font-semibold text-slate-200 mb-4">Top Findings</h3>
        <TopFindings findings={findings} />
      </div>

      {/* Module Breakdown */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-slate-200 mb-2">Findings by Module</h3>
        <ModuleBar modules={modules} findings={findings} />
      </div>
    </div>
  );
}
