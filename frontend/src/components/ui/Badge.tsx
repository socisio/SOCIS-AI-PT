// Severity and status chips. The colors come from the theme tokens (globals.css), so they follow dark/light.

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const STATUSES = new Set(['pending', 'running', 'analyzing', 'completed', 'failed', 'cancelled']);

export function SeverityBadge({ value }: { value?: string | null }) {
  if (!value) return <span className="muted">—</span>;
  const v = value.toLowerCase();
  return <span className={`badge badge-${SEVERITIES.has(v) ? v : 'info'}`}>{v}</span>;
}

export function StatusBadge({ value }: { value: string }) {
  const v = value.toLowerCase();
  return <span className={`badge status-${STATUSES.has(v) ? v : 'pending'}`}>{v.replace(/_/g, ' ')}</span>;
}
