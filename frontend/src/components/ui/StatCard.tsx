import Skeleton from '@/components/ui/Skeleton';

export type Tone = 'red' | 'orange' | 'amber' | 'green' | 'cyan' | 'purple';

export default function StatCard({
  label, value, hint, tone, icon: Icon, loading,
}: {
  label: string;
  value: number | string;
  hint?: string;
  tone?: Tone;
  icon?: React.ElementType;
  loading?: boolean;
}) {
  return (
    <div className="stat-card">
      <div className="kpi-top">
        {Icon && <Icon size={14} />}
        <span>{label}</span>
      </div>
      {loading ? (
        <Skeleton width={64} height={30} />
      ) : (
        <div className={`kpi-value${tone ? ' tone-' + tone : ''}`}>{value}</div>
      )}
      {hint && !loading && <div className="kpi-hint">{hint}</div>}
    </div>
  );
}
