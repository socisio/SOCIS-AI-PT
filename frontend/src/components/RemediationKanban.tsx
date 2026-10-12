'use client';

/**
 * RemediationKanban — Enterprise vulnerability lifecycle management board.
 * Features: HTML5 drag-and-drop, CVSS/EPSS badges, SLA indicators,
 * severity breakdown per column, search/filter, risk scoring, detail modal.
 */

import { useState, useRef, useCallback } from 'react';
import {
  ShieldAlert, X, ExternalLink, Clock, Zap, BarChart2,
  AlertTriangle, CheckCircle2, Search, Filter,
} from 'lucide-react';
import { vulnsApi } from '@/lib/api';
import { SEV_COLORS } from '@/lib/vulns';

// ─── Constants ────────────────────────────────────────────────

// Severity colors come from the shared source (@/lib/vulns) so this board can't drift from the list/detail views.
const SEV_COLOR = SEV_COLORS;

const SEV_RANK: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
};

export type VulnStatus =
  | 'open' | 'in_progress' | 'resolved' | 'accepted_risk' | 'false_positive';

interface Column {
  id: VulnStatus;
  label: string;
  color: string;
  icon: string;
  description: string;
}

const COLUMNS: Column[] = [
  { id: 'open',           label: 'Open',          color: 'var(--red)', icon: '🔴', description: 'Newly discovered, unactioned' },
  { id: 'in_progress',    label: 'In Progress',   color: 'var(--amber)', icon: '🟡', description: 'Remediation underway' },
  { id: 'resolved',       label: 'Resolved',      color: 'var(--green)', icon: '🟢', description: 'Fix applied and verified' },
  { id: 'accepted_risk',  label: 'Accepted Risk', color: 'var(--blue)', icon: '🔵', description: 'Risk acknowledged, no fix planned' },
  { id: 'false_positive', label: 'False Positive',color: 'var(--text-secondary)', icon: '⚪', description: 'Confirmed non-issue' },
];

// SLA thresholds in days (for critical/high/medium/low)
const SLA_DAYS: Record<string, number> = {
  critical: 7, high: 14, medium: 30, low: 90, info: 180,
};

// ─── Types ────────────────────────────────────────────────────

interface KanbanVuln {
  id: string;
  vuln_name: string;
  severity: string;
  cve_id?: string | null;
  description?: string | null;
  cvss_score?: number | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  status?: string | null;
  created_at?: string;
  // VM management fields
  priority?: string | null;
  assigned_user_name?: string | null;
  due_date?: string | null;
}

interface Props {
  vulnerabilities: KanbanVuln[];
  onUpdate?: () => void;
}

// ─── Helpers ──────────────────────────────────────────────────

function daysOpen(createdAt?: string): number {
  if (!createdAt) return 0;
  return Math.floor((Date.now() - new Date(createdAt).getTime()) / 86_400_000);
}

function slaStatus(vuln: KanbanVuln): 'breach' | 'warning' | 'ok' | 'na' {
  if (!vuln.created_at) return 'na';
  const days = daysOpen(vuln.created_at);
  const sla = SLA_DAYS[vuln.severity] ?? 90;
  if (days > sla) return 'breach';
  if (days > sla * 0.75) return 'warning';
  return 'ok';
}

function riskScore(vuln: KanbanVuln): number | null {
  if (vuln.cvss_score != null && vuln.epss_score != null) {
    return Math.round(vuln.cvss_score * vuln.epss_score * 10) / 10;
  }
  return null;
}

function severityBreakdown(items: KanbanVuln[]) {
  const counts: Record<string, number> = {};
  for (const v of items) counts[v.severity] = (counts[v.severity] ?? 0) + 1;
  return counts;
}

// ─── Sub-components ───────────────────────────────────────────

function SeverityPill({ severity }: { severity: string }) {
  const color = SEV_COLOR[severity] ?? 'var(--text-secondary)';
  return (
    <span style={{
      background: `color-mix(in srgb, ${color} 13%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 33%, transparent)`,
      borderRadius: 'var(--radius-sm)', padding: '1px 6px', fontSize: '0.6875rem',
      fontWeight: 700, color, textTransform: 'uppercase', letterSpacing: '0.04em',
    }}>
      {severity}
    </span>
  );
}

function SlaTag({ vuln }: { vuln: KanbanVuln }) {
  const days = daysOpen(vuln.created_at);
  const status = slaStatus(vuln);
  if (status === 'na') return null;
  const color = status === 'breach' ? 'var(--red)' : status === 'warning' ? 'var(--amber)' : 'var(--text-muted)';
  const sla = SLA_DAYS[vuln.severity] ?? 90;
  return (
    <span title={`SLA: ${sla}d | Open ${days}d`} style={{
      display: 'flex', alignItems: 'center', gap: 2,
      fontSize: '0.6875rem', color, fontWeight: 600,
    }}>
      <Clock size={9} />
      {days}d
      {status === 'breach' && <AlertTriangle size={9} />}
    </span>
  );
}

function CvssEpssRow({ vuln }: { vuln: KanbanVuln }) {
  const rs = riskScore(vuln);
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 4 }}>
      {vuln.cvss_score != null && (
        <span title="CVSS Base Score" style={{
          display: 'flex', alignItems: 'center', gap: 2,
          fontSize: '0.6875rem', color: 'var(--text-secondary)', fontWeight: 600,
        }}>
          <BarChart2 size={9} />CVSS {vuln.cvss_score.toFixed(1)}
        </span>
      )}
      {vuln.epss_score != null && (
        <span title={`EPSS: ${(vuln.epss_score * 100).toFixed(2)}% exploitation probability`} style={{
          display: 'flex', alignItems: 'center', gap: 2,
          fontSize: '0.6875rem', color: 'var(--text-secondary)', fontWeight: 600,
        }}>
          <Zap size={9} />EPSS {(vuln.epss_score * 100).toFixed(1)}%
        </span>
      )}
      {rs != null && (
        <span title="Risk Score = CVSS × EPSS" style={{
          display: 'flex', alignItems: 'center', gap: 2,
          fontSize: '0.6875rem', color: rs > 3 ? 'var(--orange)' : 'var(--text-muted)', fontWeight: 700,
        }}>
          ⚡{rs}
        </span>
      )}
    </div>
  );
}

function ColumnHeader({ col, count, items }: { col: Column; count: number; items: KanbanVuln[] }) {
  const breakdown = severityBreakdown(items);
  return (
    <div style={{ marginBottom: '0.75rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 5 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: col.color, display: 'inline-block', flexShrink: 0 }} />
          <span style={{ fontWeight: 700, fontSize: '0.8125rem', color: 'var(--text-primary)' }}>{col.label}</span>
        </div>
        <span style={{
          background: `color-mix(in srgb, ${col.color} 9%, transparent)`, border: `1px solid color-mix(in srgb, ${col.color} 25%, transparent)`,
          borderRadius: 'var(--radius-lg)', padding: '1px 9px',
          fontSize: '0.6875rem', color: col.color, fontWeight: 700,
        }}>{count}</span>
      </div>
      {/* Severity breakdown mini-bar */}
      {count > 0 && (
        <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
          {(['critical','high','medium','low','info'] as const).map(sev =>
            breakdown[sev] ? (
              <span key={sev} title={`${breakdown[sev]} ${sev}`} style={{
                width: 6, height: 6, borderRadius: '50%',
                background: SEV_COLOR[sev], display: 'inline-block',
                opacity: 0.8,
              }} />
            ) : null
          )}
        </div>
      )}
    </div>
  );
}

// ─── Detail Modal ─────────────────────────────────────────────

function VulnDetailModal({ vuln, currentStatus, onClose, onMove }: {
  vuln: KanbanVuln;
  currentStatus: VulnStatus;
  onClose: () => void;
  onMove: (id: string, status: VulnStatus) => void;
}) {
  const days = daysOpen(vuln.created_at);
  const sla = SLA_DAYS[vuln.severity] ?? 90;
  const slaProgress = Math.min(100, Math.round((days / sla) * 100));
  const slaColor = slaProgress > 100 ? 'var(--red)' : slaProgress > 75 ? 'var(--amber)' : 'var(--green)';

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        zIndex: 1000, backdropFilter: 'blur(2px)',
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: 'var(--bg-secondary)', borderRadius: 'var(--radius-lg)',
          border: `1px solid ${SEV_COLOR[vuln.severity] ?? 'var(--border)'}`,
          padding: '1.5rem', width: '100%', maxWidth: 520,
          maxHeight: '85vh', overflowY: 'auto',
          boxShadow: `0 0 40px color-mix(in srgb, ${SEV_COLOR[vuln.severity] ?? 'var(--border)'} 19%, transparent)`,
        }}
      >
        {/* Modal header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
          <div style={{ flex: 1, marginRight: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <ShieldAlert size={16} color={SEV_COLOR[vuln.severity]} />
              <SeverityPill severity={vuln.severity} />
              {vuln.cve_id && (
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                  target="_blank" rel="noopener noreferrer"
                  style={{ display: 'flex', alignItems: 'center', gap: 3, color: 'var(--cyan)', fontSize: '0.75rem' }}
                >
                  {vuln.cve_id} <ExternalLink size={10} />
                </a>
              )}
            </div>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, lineHeight: 1.35, margin: 0 }}>
              {vuln.vuln_name}
            </h3>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2 }}>
            <X size={18} />
          </button>
        </div>

        {/* Score row */}
        <div style={{ display: 'flex', gap: 12, marginBottom: '1rem', flexWrap: 'wrap' }}>
          {vuln.cvss_score != null && (
            <div style={{ background: 'var(--bg-primary)', borderRadius: 'var(--radius-md)', padding: '0.5rem 0.875rem', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>CVSS</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 800, color: SEV_COLOR[vuln.severity] }}>{vuln.cvss_score.toFixed(1)}</div>
            </div>
          )}
          {vuln.epss_score != null && (
            <div style={{ background: 'var(--bg-primary)', borderRadius: 'var(--radius-md)', padding: '0.5rem 0.875rem', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>EPSS</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--orange)' }}>{(vuln.epss_score * 100).toFixed(2)}%</div>
            </div>
          )}
          {vuln.epss_percentile != null && (
            <div style={{ background: 'var(--bg-primary)', borderRadius: 'var(--radius-md)', padding: '0.5rem 0.875rem', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Percentile</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--blue)' }}>{(vuln.epss_percentile * 100).toFixed(0)}th</div>
            </div>
          )}
          <div style={{ background: 'var(--bg-primary)', borderRadius: 'var(--radius-md)', padding: '0.5rem 0.875rem', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Age</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 800, color: days > sla ? 'var(--red)' : 'var(--text-primary)' }}>{days}d</div>
          </div>
        </div>

        {/* SLA progress bar */}
        <div style={{ marginBottom: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontWeight: 600 }}>SLA Progress</span>
            <span style={{ fontSize: '0.6875rem', color: slaColor, fontWeight: 700 }}>
              {days}/{sla}d {slaProgress >= 100 ? '— BREACHED' : `(${slaProgress}%)`}
            </span>
          </div>
          <div style={{ height: 4, borderRadius: 'var(--radius-sm)', background: 'var(--bg-primary)', overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${Math.min(100, slaProgress)}%`, background: slaColor, borderRadius: 'var(--radius-sm)', transition: 'width 0.4s' }} />
          </div>
        </div>

        {/* Description */}
        {vuln.description && (
          <div style={{ marginBottom: '1rem' }}>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>Description</div>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>{vuln.description}</p>
          </div>
        )}

        {/* Move to */}
        <div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>Move to Status</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {COLUMNS.map(col => {
              const active = col.id === currentStatus;
              return (
                <button
                  key={col.id}
                  onClick={() => { if (!active) { onMove(vuln.id, col.id); onClose(); } }}
                  disabled={active}
                  style={{
                    padding: '0.35rem 0.75rem', borderRadius: 'var(--radius-sm)', fontSize: '0.75rem', fontWeight: 600,
                    cursor: active ? 'default' : 'pointer',
                    background: active ? `color-mix(in srgb, ${col.color} 19%, transparent)` : `color-mix(in srgb, ${col.color} 8%, transparent)`,
                    border: `1px solid ${active ? col.color : `color-mix(in srgb, ${col.color} 31%, transparent)`}`,
                    color: col.color, display: 'flex', alignItems: 'center', gap: 4,
                    opacity: active ? 1 : 0.8,
                  }}
                >
                  {active && <CheckCircle2 size={12} />}
                  {col.label}
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────

export default function RemediationKanban({ vulnerabilities, onUpdate }: Props) {
  const [items, setItems] = useState<KanbanVuln[]>(
    vulnerabilities.map(v => ({ ...v, status: v.status || 'open' }))
  );
  const [moving, setMoving] = useState<string | null>(null);
  const [selected, setSelected] = useState<KanbanVuln | null>(null);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  // Drag-and-drop state
  const dragId = useRef<string | null>(null);
  const [dragOver, setDragOver] = useState<VulnStatus | null>(null);

  const moveToColumn = useCallback(async (vulnId: string, newStatus: VulnStatus) => {
    setMoving(vulnId);
    try {
      await vulnsApi.updateStatus(vulnId, newStatus);
      setItems(prev => prev.map(v => v.id === vulnId ? { ...v, status: newStatus } : v));
      onUpdate?.();
    } catch {
      // silent — keep UI state
    } finally {
      setMoving(null);
    }
  }, [onUpdate]);

  // Filter logic
  const visibleItems = items.filter(v => {
    const matchSearch = !search ||
      v.vuln_name.toLowerCase().includes(search.toLowerCase()) ||
      (v.cve_id ?? '').toLowerCase().includes(search.toLowerCase());
    const matchSev = !severityFilter || v.severity === severityFilter;
    return matchSearch && matchSev;
  });

  // Sort: within each column, sort by severity rank desc, then CVSS desc
  function sortedColItems(status: string) {
    return visibleItems
      .filter(v => (v.status || 'open') === status)
      .sort((a, b) => {
        const rankDiff = (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0);
        if (rankDiff !== 0) return rankDiff;
        return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
      });
  }

  const SEVS = ['critical', 'high', 'medium', 'low', 'info'];

  return (
    <div>
      {/* Toolbar */}
      <div style={{ display: 'flex', gap: 8, marginBottom: '0.875rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: '1 1 200px', minWidth: 160, maxWidth: 320 }}>
          <Search size={12} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            className="input"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search cards…"
            style={{ paddingLeft: 28, height: 32, fontSize: '0.75rem' }}
          />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <Filter size={11} style={{ color: 'var(--text-muted)' }} />
          {SEVS.map(sev => (
            <button key={sev} onClick={() => setSeverityFilter(severityFilter === sev ? '' : sev)}
              style={{
                padding: '2px 8px', borderRadius: 99, fontSize: '0.6875rem', fontWeight: 700,
                textTransform: 'uppercase', cursor: 'pointer',
                background: severityFilter === sev ? `color-mix(in srgb, ${SEV_COLOR[sev]} 19%, transparent)` : 'transparent',
                border: `1px solid ${severityFilter === sev ? SEV_COLOR[sev] : 'var(--border)'}`,
                color: severityFilter === sev ? SEV_COLOR[sev] : 'var(--text-muted)',
                transition: 'all 0.15s',
              }}
            >{sev}</button>
          ))}
        </div>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
          {visibleItems.length} findings
        </span>
      </div>

      {/* Board */}
      <div style={{ overflowX: 'auto', paddingBottom: '0.5rem' }}>
        <div style={{ display: 'flex', gap: '0.75rem', minWidth: `${COLUMNS.length * 245}px` }}>
          {COLUMNS.map(col => {
            const colItems = sortedColItems(col.id);
            const isOver = dragOver === col.id;
            return (
              <div
                key={col.id}
                onDragOver={e => { e.preventDefault(); setDragOver(col.id); }}
                onDragLeave={() => setDragOver(null)}
                onDrop={e => {
                  e.preventDefault();
                  if (dragId.current) moveToColumn(dragId.current, col.id);
                  setDragOver(null);
                  dragId.current = null;
                }}
                style={{
                  flex: '0 0 235px',
                  background: isOver ? `color-mix(in srgb, ${col.color} 6%, transparent)` : 'var(--bg-secondary)',
                  borderRadius: 'var(--radius-lg)',
                  border: `1px solid ${isOver ? col.color : 'var(--border)'}`,
                  padding: '0.875rem',
                  transition: 'border-color 0.15s, background 0.15s',
                }}
              >
                <ColumnHeader col={col} count={colItems.length} items={colItems} />

                {/* Cards */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', minHeight: 80 }}>
                  {colItems.length === 0 && (
                    <div style={{
                      textAlign: 'center', padding: '1.25rem 0.5rem',
                      color: 'var(--text-muted)', fontSize: '0.75rem',
                      border: '1px dashed var(--border)', borderRadius: 'var(--radius-md)',
                    }}>
                      {isOver ? 'Drop here' : 'No findings'}
                    </div>
                  )}
                  {colItems.map(vuln => {
                    const sl = slaStatus(vuln);
                    const borderColor = SEV_COLOR[vuln.severity] ?? 'var(--border)';
                    const isSlaBreached = sl === 'breach';
                    return (
                      <div
                        key={vuln.id}
                        draggable
                        onDragStart={() => { dragId.current = vuln.id; }}
                        onDragEnd={() => setDragOver(null)}
                        onClick={() => setSelected(vuln)}
                        style={{
                          background: 'var(--bg-primary)', borderRadius: 'var(--radius-md)', padding: '0.625rem 0.75rem',
                          border: `1px solid color-mix(in srgb, ${borderColor} 20%, transparent)`,
                          borderLeft: `3px solid ${borderColor}`,
                          outline: isSlaBreached ? `1px solid color-mix(in srgb, var(--red) 33%, transparent)` : 'none',
                          opacity: moving === vuln.id ? 0.5 : 1,
                          cursor: 'grab',
                          transition: 'transform 0.1s, box-shadow 0.1s, opacity 0.2s',
                          userSelect: 'none',
                        }}
                        onMouseEnter={e => {
                          (e.currentTarget as HTMLElement).style.transform = 'translateY(-1px)';
                          (e.currentTarget as HTMLElement).style.boxShadow = `0 4px 16px color-mix(in srgb, ${borderColor} 13%, transparent)`;
                        }}
                        onMouseLeave={e => {
                          (e.currentTarget as HTMLElement).style.transform = '';
                          (e.currentTarget as HTMLElement).style.boxShadow = '';
                        }}
                      >
                        {/* Card top row */}
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 4 }}>
                          <SeverityPill severity={vuln.severity} />
                          <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                            {/* Priority pill */}
                            {vuln.priority && (() => {
                              const PCOL: Record<string, string> = { p1: 'var(--red)', p2: 'var(--orange)', p3: 'var(--amber)', p4: 'var(--text-secondary)' };
                              return (
                                <span style={{ fontSize: '0.6875rem', fontWeight: 700, padding: '1px 6px', borderRadius: 'var(--radius-sm)', background: `color-mix(in srgb, ${PCOL[vuln.priority] ?? 'var(--text-muted)'} 13%, transparent)`, color: PCOL[vuln.priority] ?? 'var(--text-secondary)', border: `1px solid color-mix(in srgb, ${PCOL[vuln.priority] ?? 'var(--border-strong)'} 27%, transparent)` }}>
                                  {vuln.priority.toUpperCase()}
                                </span>
                              );
                            })()}
                            {/* Overdue indicator */}
                            {vuln.due_date && vuln.status !== 'resolved' && vuln.status !== 'false_positive' && new Date(vuln.due_date) < new Date() && (
                              <span title="Overdue" style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--red)', display: 'inline-flex', alignItems: 'center' }}>🔴</span>
                            )}
                            {/* Assignee initials */}
                            {vuln.assigned_user_name && (
                              <span title={vuln.assigned_user_name} style={{ width: 20, height: 20, borderRadius: '50%', background: 'color-mix(in srgb, var(--cyan) 13%, transparent)', border: '1px solid color-mix(in srgb, var(--cyan) 27%, transparent)', color: 'var(--cyan)', fontSize: '0.6875rem', fontWeight: 700, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                                {vuln.assigned_user_name.charAt(0).toUpperCase()}
                              </span>
                            )}
                            <SlaTag vuln={vuln} />
                          </div>
                        </div>

                        {/* Title */}
                        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.3, wordBreak: 'break-word', marginBottom: 4 }}>
                          {vuln.vuln_name}
                        </div>

                        {/* CVE */}
                        {vuln.cve_id && (
                          <div style={{ fontSize: '0.6875rem', color: 'var(--cyan)', fontFamily: 'var(--font-mono)', marginBottom: 2 }}>
                            {vuln.cve_id}
                          </div>
                        )}

                        {/* Scores */}
                        <CvssEpssRow vuln={vuln} />
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detail Modal */}
      {selected && (
        <VulnDetailModal
          vuln={selected}
          currentStatus={((selected.status || 'open') as VulnStatus)}
          onClose={() => setSelected(null)}
          onMove={(id, status) => {
            moveToColumn(id, status);
            setSelected(null);
          }}
        />
      )}
    </div>
  );
}
