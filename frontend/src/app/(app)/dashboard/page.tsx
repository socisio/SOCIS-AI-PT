'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import dynamic from 'next/dynamic';
import { Radar, ShieldAlert, FileText, Zap, Activity, Plus, ArrowRight, FolderKanban, AlertTriangle } from 'lucide-react';
import { dashboardApi, scansApi } from '@/lib/api';
import type { DashboardSummary } from '@/lib/api';
import type { Scan } from '@/lib/types';
import PageHeader from '@/components/ui/PageHeader';
import Card from '@/components/ui/Card';
import StatCard from '@/components/ui/StatCard';
import EmptyState from '@/components/ui/EmptyState';
import Skeleton from '@/components/ui/Skeleton';
import { SeverityBadge, StatusBadge } from '@/components/ui/Badge';

const VulnTrendsChart = dynamic(() => import('@/components/VulnTrendsChart'), { ssr: false });

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? '';

type Svc = 'ok' | 'down' | 'degraded' | 'not_configured' | 'unknown';
type ServiceKey = 'backend' | 'ollama' | 'postgres' | 'redis' | 'metasploit';

const SERVICES: { key: ServiceKey; label: string }[] = [
  { key: 'backend', label: 'Backend API' },
  { key: 'ollama', label: 'Ollama (external)' },
  { key: 'postgres', label: 'PostgreSQL' },
  { key: 'redis', label: 'Redis and workers' },
  { key: 'metasploit', label: 'Metasploit MCP' },
];

const SVC_TEXT: Record<Svc, { text: string; dot: string }> = {
  ok: { text: 'Online', dot: '' },
  down: { text: 'Offline', dot: 'err' },
  degraded: { text: 'Unreachable', dot: 'warn' },
  not_configured: { text: 'Not configured', dot: 'muted' },
  unknown: { text: 'Checking', dot: 'muted' },
};

const SEVERITY_ROWS: { key: keyof DashboardSummary['open_by_severity']; label: string; color: string }[] = [
  { key: 'critical', label: 'Critical', color: 'var(--chart-red)' },
  { key: 'high', label: 'High', color: 'var(--chart-orange)' },
  { key: 'medium', label: 'Medium', color: 'var(--chart-amber)' },
  { key: 'low', label: 'Low', color: 'var(--chart-green)' },
  { key: 'info', label: 'Info', color: 'var(--chart-blue)' },
];

const QUICK_ACTIONS = [
  { href: '/scans/new', label: 'New pentest scan', icon: Radar, color: 'var(--cyan)' },
  { href: '/ai-chat', label: 'Open AI assistant', icon: Zap, color: 'var(--purple)' },
  { href: '/reports', label: 'Generate report', icon: FileText, color: 'var(--green)' },
  { href: '/mcp', label: 'Manage MCP servers', icon: Activity, color: 'var(--amber)' },
];

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(true);
  const [summaryError, setSummaryError] = useState(false);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [scansLoading, setScansLoading] = useState(true);
  const [services, setServices] = useState<Record<ServiceKey, Svc>>({
    backend: 'unknown', ollama: 'unknown', postgres: 'unknown', redis: 'unknown', metasploit: 'unknown',
  });

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const r = await dashboardApi.summary();
        if (alive) setSummary(r.data);
      } catch {
        if (alive) setSummaryError(true);
      } finally {
        if (alive) setSummaryLoading(false);
      }
    })();
    (async () => {
      try {
        const r = await scansApi.list({ page: 1 });
        if (alive) setRecentScans(r.data.scans?.slice(0, 6) || []);
      } catch {
        /* shown as the empty state */
      } finally {
        if (alive) setScansLoading(false);
      }
    })();
    return () => { alive = false; };
  }, []);

  // Service health. /api/services-health returns coarse strings ('ok' | 'degraded' | 'not_configured').
  useEffect(() => {
    const check = async () => {
      try {
        const r = await fetch(`${API_BASE}/api/services-health`);
        if (r.ok) {
          const d = await r.json();
          const ollama: Svc = d.ollama === 'ok' ? 'ok' : d.ollama === 'not_configured' ? 'not_configured' : d.ollama === 'degraded' ? 'degraded' : 'unknown';
          setServices((prev) => ({
            ...prev,
            backend: 'ok',
            postgres: d.database === 'ok' ? 'ok' : 'down',
            redis: d.redis === 'ok' ? 'ok' : 'down',
            ollama,
          }));
        } else {
          setServices((prev) => ({ ...prev, backend: 'down', postgres: 'down', redis: 'down', ollama: 'down' }));
        }
      } catch {
        setServices((prev) => ({ ...prev, backend: 'down', postgres: 'down', redis: 'down', ollama: 'down' }));
      }
      try {
        const r = await fetch(`${API_BASE}/api/v1/mcp/servers`, { credentials: 'include' });
        if (r.ok) {
          const d = await r.json();
          const msf = d.servers?.find((s: { name?: string }) => s.name === 'metasploit_mcp');
          setServices((prev) => ({ ...prev, metasploit: msf ? 'ok' : 'down' }));
        } else {
          setServices((prev) => ({ ...prev, metasploit: 'down' }));
        }
      } catch {
        setServices((prev) => ({ ...prev, metasploit: 'down' }));
      }
    };
    check();
    const interval = setInterval(check, 30000);
    return () => clearInterval(interval);
  }, []);

  const sev = summary?.open_by_severity;
  const openTotal = summary?.vulns_open ?? 0;
  const dash = (n: number | undefined) => (summaryError ? '—' : n ?? 0);

  return (
    <div className="page animate-fadeIn">
      <PageHeader
        title="Dashboard"
        subtitle="Security posture across all projects"
        actions={<Link href="/scans/new" className="btn btn-primary"><Plus size={16} /> New scan</Link>}
      />

      {summaryError && (
        <div className="card" role="alert" style={{ marginBottom: '1rem', display: 'flex', gap: '0.5rem', alignItems: 'center', color: 'var(--amber)' }}>
          <AlertTriangle size={16} />
          <span style={{ color: 'var(--text-secondary)', fontSize: '0.8125rem' }}>
            Couldn&apos;t load the summary numbers. Check that the backend is reachable and that you&apos;re signed in.
          </span>
        </div>
      )}

      <div className="grid-kpi">
        <StatCard label="Open critical" value={dash(sev?.critical)} tone="red" icon={ShieldAlert} loading={summaryLoading}
          hint={summary ? `${openTotal} open in total` : undefined} />
        <StatCard label="Open vulnerabilities" value={dash(summary?.vulns_open)} tone="orange" icon={ShieldAlert} loading={summaryLoading}
          hint={summary ? `${summary.vulns_total} found overall` : undefined} />
        <StatCard label="Active scans" value={dash(summary?.scans_active)} tone="cyan" icon={Radar} loading={summaryLoading}
          hint={summary ? `${summary.scans_total} scans in total` : undefined} />
        <StatCard label="Reports" value={dash(summary?.reports)} tone="green" icon={FileText} loading={summaryLoading} hint="generated" />
        <StatCard label="Projects" value={dash(summary?.projects)} tone="purple" icon={FolderKanban} loading={summaryLoading} />
      </div>

      <div className="grid-main">
        <div className="stack">
          <VulnTrendsChart days={30} />

          <Card title="Recent scans" right={<Link href="/scans" className="link-accent">View all <ArrowRight size={13} /></Link>}>
            {scansLoading ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <Skeleton height={16} /><Skeleton height={16} /><Skeleton height={16} />
              </div>
            ) : recentScans.length === 0 ? (
              <EmptyState
                title="Start your first scan"
                action={<Link href="/scans/new" className="btn btn-primary"><Plus size={16} /> New scan</Link>}
              >
                Scans find vulnerabilities in your targets and show up here.
              </EmptyState>
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr><th>Target</th><th>Type</th><th>Status</th><th>Risk</th><th>Started</th></tr>
                  </thead>
                  <tbody>
                    {recentScans.map((scan) => (
                      <tr key={scan.id}>
                        <td><Link href={`/scans/${scan.id}`} className="mono-link">{scan.target}</Link></td>
                        <td>{String(scan.scan_type).replace(/_/g, ' ')}</td>
                        <td><StatusBadge value={scan.status} /></td>
                        <td><SeverityBadge value={scan.risk_level} /></td>
                        <td className="muted">{new Date(scan.created_at).toLocaleDateString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>

        <div className="stack">
          <Card title="Open vulnerabilities by severity">
            {summaryLoading ? (
              <Skeleton height={8} />
            ) : openTotal === 0 ? (
              <EmptyState title="No open vulnerabilities">New findings appear here after a scan.</EmptyState>
            ) : (
              <>
                <div className="sevbar" role="img" aria-label={`Open vulnerabilities by severity: ${SEVERITY_ROWS.map((r) => `${sev?.[r.key] ?? 0} ${r.label.toLowerCase()}`).join(', ')}`}>
                  {SEVERITY_ROWS.map((r) => {
                    const n = sev?.[r.key] ?? 0;
                    return n > 0 ? <i key={r.key} style={{ width: `${(n / openTotal) * 100}%`, background: r.color }} /> : null;
                  })}
                </div>
                <div className="legend">
                  {SEVERITY_ROWS.map((r) => (
                    <span key={r.key}><i style={{ background: r.color }} />{r.label} <strong style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{sev?.[r.key] ?? 0}</strong></span>
                  ))}
                </div>
              </>
            )}
          </Card>

          <Card title="Platform status">
            {SERVICES.map(({ key, label }) => {
              const st = SVC_TEXT[services[key]];
              return (
                <div key={key} className="list-row">
                  <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
                  <span style={{ marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)' }}>
                    <i className={`dot ${st.dot}`} />
                    {st.text}
                  </span>
                </div>
              );
            })}
          </Card>

          <Card title="Quick actions">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {QUICK_ACTIONS.map(({ href, label, icon: Icon, color }) => (
                <Link key={href} href={href} className="action-link">
                  <Icon size={15} color={color} />
                  {label}
                  <ArrowRight size={12} style={{ marginLeft: 'auto', opacity: 0.5 }} />
                </Link>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
