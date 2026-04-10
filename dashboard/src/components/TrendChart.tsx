import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Legend, ReferenceArea,
} from 'recharts';
import type { DashboardHistoryEntry } from '../types';

interface TrendChartProps {
  data: DashboardHistoryEntry[];
  mode: 'findings' | 'score';
}

export default function TrendChart({ data, mode }: TrendChartProps) {
  const chartData = data.map(d => ({
    ...d,
    date: d.date.slice(5), // MM-DD
  }));

  if (mode === 'score') {
    return (
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={chartData} margin={{ left: 10, right: 30, top: 10, bottom: 10 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis dataKey="date" stroke="#94a3b8" fontSize={11} />
          <YAxis domain={[0, 100]} stroke="#94a3b8" fontSize={12} />
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
              color: '#f8fafc',
            }}
          />
          {/* Colored zone backgrounds */}
          <ReferenceArea y1={90} y2={100} fill="#22c55e" fillOpacity={0.08} />
          <ReferenceArea y1={70} y2={90} fill="#3b82f6" fillOpacity={0.08} />
          <ReferenceArea y1={50} y2={70} fill="#eab308" fillOpacity={0.08} />
          <ReferenceArea y1={0} y2={50} fill="#ef4444" fillOpacity={0.08} />
          <Line
            type="monotone"
            dataKey="score"
            stroke="#3b82f6"
            strokeWidth={2}
            dot={{ fill: '#3b82f6', r: 3 }}
            activeDot={{ r: 5 }}
          />
        </LineChart>
      </ResponsiveContainer>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={chartData} margin={{ left: 10, right: 30, top: 10, bottom: 10 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis dataKey="date" stroke="#94a3b8" fontSize={11} />
        <YAxis stroke="#94a3b8" fontSize={12} />
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
            <span className="text-slate-300 text-sm capitalize">{value}</span>
          )}
        />
        <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={false} />
        <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} dot={false} />
        <Line type="monotone" dataKey="medium" stroke="#eab308" strokeWidth={2} dot={false} />
        <Line type="monotone" dataKey="low" stroke="#22c55e" strokeWidth={2} dot={false} />
      </LineChart>
    </ResponsiveContainer>
  );
}
