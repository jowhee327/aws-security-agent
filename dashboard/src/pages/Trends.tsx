import { useI18n } from '../i18n';
import type { DashboardData } from '../types';
import TrendChart from '../components/TrendChart';

interface TrendsProps {
  data: DashboardData;
}

export default function Trends({ data }: TrendsProps) {
  const { t } = useI18n();

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-slate-50">{t('trends.title')}</h2>

      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-slate-200 mb-4">{t('trends.findingsTrend')}</h3>
        <TrendChart data={data.history} mode="findings" />
      </div>

      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-slate-200 mb-4">{t('trends.scoreTrend')}</h3>
        <TrendChart data={data.history} mode="score" />
      </div>
    </div>
  );
}
