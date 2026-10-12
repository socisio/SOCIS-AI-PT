'use client';
import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { Plus, Radar, Clock, CheckCircle, AlertCircle, XCircle, RotateCcw, Trash2, RefreshCw } from 'lucide-react';
import { scansApi } from '@/lib/api';
import type { Scan, ScanStatus } from '@/lib/types';
import { notify } from '@/lib/dialogs';

const STATUS_ICONS: Record<ScanStatus, React.ReactNode> = {
  pending:   <Clock size={13} />,
  running:   <RefreshCw size={13} className="animate-spin" />,
  analyzing: <RefreshCw size={13} className="animate-spin" />,
  completed: <CheckCircle size={13} />,
  failed:    <AlertCircle size={13} />,
  cancelled: <XCircle size={13} />,
};

const RISK_COLORS: Record<string, string> = {
  CRITICAL: 'var(--red)', HIGH: 'var(--orange)', MEDIUM: 'var(--amber)', LOW: 'var(--green)',
};

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [autoRefreshing, setAutoRefreshing] = useState(false);
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage] = useState(1);

  const load = useCallback(async (withSpinner = true) => {
    if (withSpinner) setLoading(true);
    try {
      const res = await scansApi.list({ status: statusFilter || undefined, page });
      setScans(res.data.scans || []);
      setTotal(res.data.total || 0);
    } catch { setScans([]); }
    finally {
      if (withSpinner) setLoading(false);
    }
  }, [statusFilter, page]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    const hasActive = scans.some(s => s.status === 'pending' || s.status === 'running' || s.status === 'analyzing');
    if (!hasActive) {
      setAutoRefreshing(false);
      return;
    }

    setAutoRefreshing(true);
    const interval = setInterval(() => {
      load(false);
    }, 5000);

    return () => {
      clearInterval(interval);
      setAutoRefreshing(false);
    };
  }, [scans, load]);

  const handleCancel = async (id: string) => {
    try {
      await scansApi.cancel(id);
      load();
    } catch (e: any) { notify(e?.message || 'Failed to cancel scan', 'error'); }
  };
  const handleDelete = async (id: string) => {
    try {
      await scansApi.delete(id);
      load();
    } catch (e: any) {
      const errorMsg = e?.response?.data?.detail || e?.message || 'Failed to delete scan';
      notify(errorMsg, 'error');
    }
  };
  const handleRequeue = async (id: string) => {
    try {
      await scansApi.requeue(id);
      load();
    } catch (e: any) { notify(e?.message || 'Failed to requeue scan', 'error'); }
  };

  const STATUSES: Array<{ value: string; label: string }> = [
    { value: '', label: 'All' },
    { value: 'pending', label: 'Pending' },
    { value: 'running', label: 'Running' },
    { value: 'analyzing', label: 'Analyzing' },
    { value: 'completed', label: 'Completed' },
    { value: 'failed', label: 'Failed' },
    { value: 'cancelled', label: 'Cancelled' },
  ];

  return (
    <div className="animate-fadeIn" style={{ padding: '2rem', width: '100%' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.75rem' }}>
        <div>
          <h1>Scans</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: 4 }}>
            {total} total scans
          </p>
        </div>
        <Link href="/scans/new" className="btn btn-primary">
          <Plus size={16} /> New Scan
        </Link>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.25rem' }}>
        {STATUSES.map(({ value, label }) => (
          <button key={value}
            onClick={() => { setStatusFilter(value); setPage(1); }}
            className="btn"
            style={{
              padding: '0.375rem 0.875rem',
              fontSize: '0.8125rem',
              background: statusFilter === value ? 'var(--cyan-glow)' : 'transparent',
              border: `1px solid ${statusFilter === value ? 'var(--cyan)' : 'var(--border)'}`,
              color: statusFilter === value ? 'var(--cyan)' : 'var(--text-secondary)',
            }}
          >
            {label}
          </button>
        ))}
        <button onClick={() => load()} className="btn btn-ghost" style={{ marginLeft: 'auto', padding: '0.375rem 0.75rem' }}>
          <RefreshCw size={14} />
        </button>
        {autoRefreshing && (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: 8 }}>
            Auto-refreshing...
          </span>
        )}
      </div>

      {/* Scans Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Type</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Vulns</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>Loading scans...</td></tr>
              ) : scans.length === 0 ? (
                <tr><td colSpan={8} style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
                  No scans yet. <Link href="/scans/new" style={{ color: 'var(--cyan)' }}>Start your first scan →</Link>
                </td></tr>
              ) : scans.map(scan => {
                const started = scan.started_at ? new Date(scan.started_at) : null;
                const completed = scan.completed_at ? new Date(scan.completed_at) : null;
                const duration = started && completed
                  ? `${Math.round((completed.getTime() - started.getTime()) / 1000)}s`
                  : scan.status === 'running' || scan.status === 'analyzing'
                    ? '...'
                    : '—';

                return (
                  <tr key={scan.id}>
                    <td>
                      <Link href={`/scans/${scan.id}`} style={{
                        color: 'var(--text-primary)', textDecoration: 'none',
                        fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', fontWeight: 500,
                      }}>
                        {scan.target}
                      </Link>
                    </td>
                    <td style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', textTransform: 'capitalize' }}>
                      {scan.scan_type}
                    </td>
                    <td>
                      <span className={`badge status-${scan.status}`} style={{
                        display: 'inline-flex', alignItems: 'center', gap: 5, borderRadius: 'var(--radius-sm)',
                      }}>
                        {STATUS_ICONS[scan.status as ScanStatus]}
                        {scan.status}
                      </span>
                    </td>
                    <td>
                      {scan.risk_level && (
                        <span style={{ color: RISK_COLORS[scan.risk_level] || 'var(--text-secondary)', fontWeight: 700, fontSize: '0.8125rem' }}>
                          {scan.risk_level}
                        </span>
                      )}
                    </td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
                      {scan.vulnerability_count ?? scan.vulnerabilities?.length ?? '—'}
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                      {started ? started.toLocaleDateString() : '—'}
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', fontFamily: 'var(--font-mono)' }}>
                      {duration}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 4 }}>
                        {(scan.status === 'failed' || scan.status === 'cancelled') && (
                          <button onClick={() => handleRequeue(scan.id)}
                            className="btn btn-ghost" style={{ padding: '0.25rem 0.5rem' }}
                            title="Re-queue scan"
                          ><RotateCcw size={13} /></button>
                        )}
                        {(scan.status === 'pending' || scan.status === 'running' || scan.status === 'analyzing') && (
                          <button onClick={() => handleCancel(scan.id)}
                            className="btn btn-ghost" style={{ padding: '0.25rem 0.5rem' }}
                            title="Cancel scan"
                          ><XCircle size={13} /></button>
                        )}
                        <button onClick={() => handleDelete(scan.id)}
                          className="btn btn-danger" style={{ padding: '0.25rem 0.5rem' }}
                          title="Delete scan"
                        ><Trash2 size={13} /></button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {total > 20 && (
          <div style={{
            padding: '1rem 1.5rem', borderTop: '1px solid var(--border)',
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
              Page {page} of {Math.ceil(total / 20)}
            </span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="btn btn-ghost" style={{ padding: '0.3rem 0.75rem' }}>Prev</button>
              <button onClick={() => setPage(p => p + 1)} disabled={page >= Math.ceil(total / 20)} className="btn btn-ghost" style={{ padding: '0.3rem 0.75rem' }}>Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
