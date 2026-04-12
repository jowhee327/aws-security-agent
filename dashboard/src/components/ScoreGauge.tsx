import { useI18n } from '../i18n';

interface ScoreGaugeProps {
  score: number;
}

function getScoreColor(score: number): string {
  if (score >= 90) return '#22c55e';
  if (score >= 70) return '#3b82f6';
  if (score >= 50) return '#eab308';
  if (score >= 30) return '#f97316';
  return '#ef4444';
}

function getGrade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

export default function ScoreGauge({ score }: ScoreGaugeProps) {
  const { t } = useI18n();
  const color = getScoreColor(score);
  const grade = getGrade(score);
  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const dashOffset = circumference - progress;

  return (
    <div className="flex flex-col items-center justify-center">
      <svg width="200" height="200" viewBox="0 0 200 200">
        <circle
          cx="100"
          cy="100"
          r={radius}
          fill="none"
          stroke="#334155"
          strokeWidth="12"
        />
        <circle
          cx="100"
          cy="100"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          transform="rotate(-90 100 100)"
          style={{ transition: 'stroke-dashoffset 0.8s ease' }}
        />
        <text
          x="100"
          y="95"
          textAnchor="middle"
          fill={color}
          fontSize="48"
          fontWeight="bold"
        >
          {score}
        </text>
        <text
          x="100"
          y="125"
          textAnchor="middle"
          fill="#94a3b8"
          fontSize="16"
        >
          / 100
        </text>
      </svg>
      <div className="mt-2 text-center">
        <span
          className="text-2xl font-bold"
          style={{ color }}
        >
          {t('grade')} {grade}
        </span>
      </div>
    </div>
  );
}
