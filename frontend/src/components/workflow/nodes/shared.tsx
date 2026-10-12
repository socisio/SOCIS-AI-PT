// Shared node styles and status helpers used by all custom ReactFlow nodes.
// Styled to match the approved "Flow Lanes" canvas design: a left accent bar, an icon tile, and a status CHIP
// (✓ done / ● running / queued) in the header, so a running workflow reads clearly at a glance.
import type { WFNodeData } from '@/lib/types';

// Per-status visual treatment for the whole node (border + glow). Keyed by execStatus.
export const EXEC_STATUS_STYLE: Record<string, React.CSSProperties> = {
  pending:   { borderColor: 'var(--border)', boxShadow: '0 6px 20px rgba(0,0,0,0.22)' },
  running:   { borderColor: 'var(--cyan)', boxShadow: '0 0 0 1px var(--cyan), 0 0 22px color-mix(in srgb, var(--cyan) 35%, transparent), 0 6px 20px rgba(0,0,0,0.22)' },
  completed: { borderColor: 'color-mix(in srgb, var(--green) 55%, transparent)', boxShadow: '0 6px 20px rgba(0,0,0,0.22)' },
  failed:    { borderColor: 'color-mix(in srgb, var(--red) 55%, transparent)', boxShadow: '0 0 0 1px color-mix(in srgb, var(--red) 40%, transparent), 0 6px 20px rgba(0,0,0,0.22)' },
  skipped:   { borderColor: 'var(--border)', boxShadow: 'none', opacity: 0.55 },
};

export const NODE_BASE: React.CSSProperties = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: 12,
  boxShadow: '0 6px 20px rgba(0,0,0,0.22)',
  minWidth: 248,
  maxWidth: 280,
  fontFamily: 'inherit',
  fontSize: 13,
  color: 'var(--text-primary)',
  userSelect: 'none',
  overflow: 'hidden',
};

export function statusRingStyle(data: WFNodeData): React.CSSProperties {
  const s = EXEC_STATUS_STYLE[data.execStatus ?? 'pending'] ?? {};
  return { ...NODE_BASE, ...s };
}

// The status chip shown top-right in a node header — matches the mock's "✓ done / ● running / queued" pills.
function StatusChip({ execStatus }: { execStatus?: string }) {
  const map: Record<string, { text: string; color: string }> = {
    running:   { text: '● running', color: 'var(--cyan)' },
    completed: { text: '✓ done',    color: 'var(--green)' },
    failed:    { text: '✗ failed',  color: 'var(--red)' },
    skipped:   { text: '⊘ skipped', color: 'var(--text-muted)' },
    pending:   { text: 'queued',    color: 'var(--text-muted)' },
  };
  const s = map[execStatus ?? 'pending'] ?? map.pending;
  return (
    <span
      style={{
        fontSize: 9, fontWeight: 700, padding: '2px 7px', borderRadius: 999, whiteSpace: 'nowrap',
        background: `color-mix(in srgb, ${s.color} 16%, transparent)`,
        color: s.color,
        animation: execStatus === 'running' ? 'pulse 1.1s ease-in-out infinite' : 'none',
      }}
    >
      {s.text}
    </span>
  );
}

export function NodeHeader({
  icon,
  label,
  accent,
  execStatus,
  onDelete,
}: {
  icon: React.ReactNode;
  label: string;
  accent: string;
  execStatus?: string;
  onDelete?: () => void;
}) {
  return (
    <>
      {/* top accent bar — the coloured strip across the top of each node in the mock */}
      <div style={{ height: 3, background: accent }} />
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          padding: '9px 11px',
          borderBottom: '1px solid var(--border)',
        }}
      >
        {/* icon tile */}
        <span
          style={{
            width: 24, height: 24, borderRadius: 7, flexShrink: 0,
            display: 'grid', placeItems: 'center',
            background: `color-mix(in srgb, ${accent} 16%, transparent)`,
            color: accent,
          }}
        >
          {icon}
        </span>
        <span style={{ fontWeight: 700, flex: 1, color: 'var(--text-primary)', fontSize: 12, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {label}
        </span>
        <StatusChip execStatus={execStatus} />
        {onDelete && (
          <button
            onClick={e => { e.stopPropagation(); onDelete(); }}
            title="Delete node"
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'color-mix(in srgb, var(--red) 60%, transparent)', padding: '0 1px', fontSize: '0.9rem',
              lineHeight: 1, display: 'flex', alignItems: 'center', flexShrink: 0,
            }}
          >
            ×
          </button>
        )}
      </div>
    </>
  );
}

export function NodeBody({ children }: { children: React.ReactNode }) {
  return <div style={{ padding: '8px 11px 10px' }}>{children}</div>;
}

export function NodeField({ label, value }: { label: string; value: string | undefined }) {
  if (!value) return null;
  return (
    <div style={{ marginTop: 3, fontSize: '0.6875rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
      <span>{label}: </span>
      <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{value}</span>
    </div>
  );
}
