import type { DashboardData } from '../types';
import TrendChart from '../components/TrendChart';

interface TrendsProps {
  data: DashboardData;
}

export default function Trends({ data }: TrendsProps) {
  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-slate-50">Trends</h2>

      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-slate-200 mb-4">Findings Trend (30 days)</h3>
        <TrendChart data={data.history} mode="findings" />
      </div>

      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-slate-200 mb-4">Score Trend (30 days)</h3>
        <TrendChart data={data.history} mode="score" />
      </div>
    </div>
  );
}
