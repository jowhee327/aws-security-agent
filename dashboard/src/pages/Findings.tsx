import { useI18n } from '../i18n';
import type { DashboardData } from '../types';
import FindingsTable from '../components/FindingsTable';

interface FindingsProps {
  data: DashboardData;
}

export default function Findings({ data }: FindingsProps) {
  const { t } = useI18n();

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-slate-50">{t('findings.title')}</h2>
      <FindingsTable findings={data.lastScan.findings} />
    </div>
  );
}
