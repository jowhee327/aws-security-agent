import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { useI18n } from '../i18n';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

interface SeverityChartProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export default function SeverityChart({ critical, high, medium, low }: SeverityChartProps) {
  const { t } = useI18n();
  const data = [
    { name: t('severity.critical'), key: 'CRITICAL', value: critical },
    { name: t('severity.high'), key: 'HIGH', value: high },
    { name: t('severity.medium'), key: 'MEDIUM', value: medium },
    { name: t('severity.low'), key: 'LOW', value: low },
  ];
  const total = critical + high + medium + low;

  return (
    <div className="w-full h-[300px] relative">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="45%"
            innerRadius={60}
            outerRadius={90}
            dataKey="value"
            strokeWidth={0}
          >
            {data.map((entry) => (
              <Cell key={entry.key} fill={SEVERITY_COLORS[entry.key]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#f8fafc',
            }}
          />
          <Legend
            formatter={(value: string) => (
              <span className="text-slate-300 text-sm">{value}</span>
            )}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none" style={{ paddingBottom: '40px' }}>
        <div className="text-center">
          <div className="text-3xl font-bold text-slate-50">{total}</div>
          <div className="text-xs text-slate-400">{t('findings')}</div>
        </div>
      </div>
    </div>
  );
}
