export default function EmptyState({
  title, children, action,
}: { title: string; children?: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="empty-state">
      <strong>{title}</strong>
      {children}
      {action && <div style={{ marginTop: '0.75rem' }}>{action}</div>}
    </div>
  );
}
