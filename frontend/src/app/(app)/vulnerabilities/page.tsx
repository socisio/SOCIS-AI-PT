'use client';
import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  ShieldAlert, Search, LayoutGrid, List, TrendingUp, Sparkles, Wrench,
  BarChart2, Filter, Calendar, Tag, User, Download, X, ChevronDown,
  Clock, CheckSquare, Square, ExternalLink, MessageSquare, Send, Trash2,
} from 'lucide-react';
import { vulnsApi, usersApi } from '@/lib/api';
import type { Vulnerability, DirectoryUser, VulnMetrics } from '@/lib/types';
import VulnDetail from '@/components/VulnDetail';
import { SEV_COLORS, PRIORITY_META, STATUS_META, getSlaStatus, isJunkVulnName } from '@/lib/vulns';
import { notify } from '@/lib/dialogs';
import dynamic from 'next/dynamic';
import { useRouter } from 'next/navigation';

const VulnRiskHeatmap = dynamic(() => import('@/components/VulnRiskHeatmap'), { ssr: false });
const RemediationKanban = dynamic(() => import('@/components/RemediationKanban'), { ssr: false });

// SEV_COLORS, PRIORITY_META, STATUS_META, getSlaStatus and the junk-name filter now come from @/lib/vulns — the
// single shared source, so this page, the detail page, and the heatmap/kanban components can't drift apart.

type ViewMode = 'list' | 'heatmap' | 'kanban' | 'metrics';

export default function VulnerabilitiesPage() {
  const router = useRouter();

  // ── Core list state ──────────────────────────────────────────
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [page, setPage] = useState(1);
  const [viewMode, setViewMode] = useState<ViewMode>('list');

  // ── Basic filters ────────────────────────────────────────────
  const [searchInput, setSearchInput] = useState(''); // bound to the input box
  const [search, setSearch] = useState('');            // debounced value actually sent to the server
  const [severity, setSeverity] = useState('');

  // ── Advanced filters ─────────────────────────────────────────
  const [showFilters, setShowFilters] = useState(false);
  const [filterStatus, setFilterStatus] = useState('');
  const [filterPriority, setFilterPriority] = useState('');
  const [filterAssignedTo, setFilterAssignedTo] = useState('');
  const [filterOverdue, setFilterOverdue] = useState(false);
  const [filterDateFrom, setFilterDateFrom] = useState('');
  const [filterDateTo, setFilterDateTo] = useState('');
  const [filterOwasp, setFilterOwasp] = useState('');
  const [filterMitre, setFilterMitre] = useState('');
  const [filterTags, setFilterTags] = useState('');

  // ── Selection + bulk actions ──────────────────────────────────
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkStatus, setBulkStatus] = useState('');
  const [applyingBulk, setApplyingBulk] = useState(false);

  // ── Detail panel ─────────────────────────────────────────────
  // Management fields, comments, and CVE enrichment now live inside the shared <VulnDetail> component — this page
  // only tracks which vuln is selected.
  const [selected, setSelected] = useState<Vulnerability | null>(null);

  // ── Users directory ───────────────────────────────────────────
  const [users, setUsers] = useState<DirectoryUser[]>([]);

  // ── Enrich all ───────────────────────────────────────────────
  const [enriching, setEnriching] = useState(false);
  const [enrichResult, setEnrichResult] = useState<string | null>(null);

  // ── Metrics ───────────────────────────────────────────────────
  const [metricsData, setMetricsData] = useState<VulnMetrics | null>(null);
  const [loadingMetrics, setLoadingMetrics] = useState(false);

  // ── Export ────────────────────────────────────────────────────
  const [exporting, setExporting] = useState(false);

  // ─────────────────────────────────────────────────────────────
  // Load vulnerabilities
  // ─────────────────────────────────────────────────────────────
  const load = useCallback(async () => {
    setLoading(true);
    try {
      const isVisualMode = viewMode === 'heatmap' || viewMode === 'kanban';
      const res = await vulnsApi.list({
        severity: severity || undefined,
        status: filterStatus || undefined,
        priority: filterPriority || undefined,
        assigned_to: filterAssignedTo || undefined,
        overdue: filterOverdue || undefined,
        date_from: filterDateFrom || undefined,
        date_to: filterDateTo || undefined,
        owasp: filterOwasp || undefined,
        mitre: filterMitre || undefined,
        tags: filterTags || undefined,
        search: search.trim() || undefined,
        page: isVisualMode ? 1 : page,
        per_page: isVisualMode ? 500 : 50,
      });
      setVulns(res.data.vulnerabilities || []);
      setTotal(res.data.total || 0);
      setLoadError(false);
    } catch { setVulns([]); setLoadError(true); }
    finally { setLoading(false); }
  }, [severity, filterStatus, filterPriority, filterAssignedTo, filterOverdue,
      filterDateFrom, filterDateTo, filterOwasp, filterMitre, filterTags, search, page, viewMode]);

  useEffect(() => { load(); }, [load]);

  // Debounce the search box into the value load() actually uses — one request after typing settles, not per keystroke.
  useEffect(() => {
    const t = setTimeout(() => { setSearch(searchInput); setPage(1); }, 300);
    return () => clearTimeout(t);
  }, [searchInput]);

  // Load users directory once
  useEffect(() => {
    usersApi.directory().then(r => setUsers(r.data || [])).catch(() => {});
  }, []);

  // Load aggregate metrics eagerly (and refresh with the list) — they drive the TRUE status counts shown in every
  // view, not just the metrics tab, so they must not wait until the metrics tab is opened.
  const loadMetrics = useCallback(() => {
    setLoadingMetrics(true);
    vulnsApi.metrics()
      .then(r => setMetricsData(r.data))
      .catch(() => setMetricsData(null))
      .finally(() => setLoadingMetrics(false));
  }, []);
  useEffect(() => { loadMetrics(); }, [loadMetrics]);

  // ─────────────────────────────────────────────────────────────
  // Actions
  // ─────────────────────────────────────────────────────────────
  const handleEnrichAll = async () => {
    setEnriching(true); setEnrichResult(null);
    try {
      const res = await vulnsApi.enrichAll();
      const d = res.data;
      const newMsg = d.new_from_ai > 0 ? ` +${d.new_from_ai} new from AI` : ' (no new vulns)';
      setEnrichResult(`Enriched ${d.enriched}/${d.total} — ${d.cvss_fetched} CVSS, ${d.epss_fetched} EPSS${newMsg}`);
      await load();
    } catch { setEnrichResult('Enrichment failed. Check backend logs.'); }
    finally { setEnriching(false); }
  };

  // Selecting a vuln just opens the shared detail panel; it loads its own CVE/comments/manage data.
  const handleSelect = (vuln: Vulnerability) => setSelected(vuln);

  const handleBulkApply = async () => {
    if (!bulkStatus || selectedIds.size === 0) return;
    setApplyingBulk(true);
    try {
      // One request, applied in a single transaction server-side with per-row access re-checked — not N parallel
      // PATCHes that could partially fail.
      const res = await vulnsApi.bulkUpdate({ ids: [...selectedIds], status: bulkStatus });
      const updated = res.data?.updated ?? selectedIds.size;
      notify(`Updated ${updated} vulnerabilit${updated === 1 ? 'y' : 'ies'}`, 'success');
      setSelectedIds(new Set()); setBulkStatus('');
      await load();
      loadMetrics();
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.message || 'Unknown error';
      notify(`Bulk update failed: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`, 'error');
    } finally { setApplyingBulk(false); }
  };

  const handleExportCsv = async () => {
    setExporting(true);
    try {
      const res = await vulnsApi.exportCsv({
        severity: severity || undefined,
        status: filterStatus || undefined,
        priority: filterPriority || undefined,
        assigned_to: filterAssignedTo || undefined,
        overdue: filterOverdue || undefined,
      });
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/csv' }));
      const a = document.createElement('a');
      a.href = url; a.download = 'vulnerabilities.csv'; a.click();
      URL.revokeObjectURL(url);
    } catch {} finally { setExporting(false); }
  };

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === filtered.length) setSelectedIds(new Set());
    else setSelectedIds(new Set(filtered.map(v => v.id)));
  };

  // ─────────────────────────────────────────────────────────────
  // Derived
  // ─────────────────────────────────────────────────────────────
  // Junk-name filtering uses the shared helper. Text search is now applied server-side (see load()); the only
  // client-side filter left is the junk-name guard.
  const filtered = vulns.filter(v => !isJunkVulnName(v.vuln_name));

  const SEVS = ['', 'critical', 'high', 'medium', 'low', 'info'];

  // Status counts come from the server-side aggregate metrics (true totals across the whole dataset), not just the
  // current page. metricsData is loaded eagerly below for this purpose, falling back to page-local counts only if
  // the metrics endpoint hasn't responded yet.
  const statusCounts = STATUS_META.map(s => ({
    ...s,
    count: metricsData?.by_status?.[s.id] ?? vulns.filter(v => (v.status || 'open') === s.id).length,
  }));

  // ─────────────────────────────────────────────────────────────
  // Metrics view
  // ─────────────────────────────────────────────────────────────
  const MetricsView = () => {
    if (loadingMetrics) return <div style={{ textAlign: 'center', padding: '4rem', color: 'var(--text-muted)' }}>Loading metrics…</div>;
    if (!metricsData) return (
      <div style={{ textAlign: 'center', padding: '4rem', color: 'var(--text-muted)' }}>
        <BarChart2 size={40} style={{ margin: '0 auto 0.75rem', opacity: 0.3 }} aria-hidden="true" />
        <p>No metrics available.</p>
        <button onClick={() => loadMetrics()} className="btn btn-ghost" style={{ marginTop: '0.75rem' }}>Retry</button>
      </div>
    );

    const m = metricsData;
    const sevCounts = { critical: m.by_severity?.critical ?? 0, high: m.by_severity?.high ?? 0, medium: m.by_severity?.medium ?? 0, low: m.by_severity?.low ?? 0, info: m.by_severity?.info ?? 0 };
    const totalSev = Object.values(sevCounts).reduce((a, b) => a + b, 0) || 1;

    // Composite risk score 0–100: severity-weighted open findings, scaled and capped. A single, honest headline number.
    const weighted = sevCounts.critical * 10 + sevCounts.high * 6 + sevCounts.medium * 3 + sevCounts.low * 1;
    const riskScore = Math.min(100, Math.round((weighted / (totalSev * 10)) * 100));
    const riskLabel = riskScore >= 70 ? 'elevated' : riskScore >= 40 ? 'moderate' : 'low';
    const riskColor = riskScore >= 70 ? 'var(--orange)' : riskScore >= 40 ? 'var(--amber)' : 'var(--green)';

    // Priority queue: the actual open findings, ranked by severity then CVSS. The thing to work from.
    const rank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    const queue = [...vulns]
      .filter(v => !isJunkVulnName(v.vuln_name) && v.status !== 'resolved' && v.status !== 'false_positive')
      .sort((a, b) => (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0) || (b.cvss_score ?? 0) - (a.cvss_score ?? 0))
      .slice(0, 8);

    const trend = m.open_trend_30d || [];
    const trendMax = Math.max(1, ...trend.map(t => t.count));
    const trendPts = trend.length > 1
      ? trend.map((t, i) => `${(i / (trend.length - 1)) * 300},${50 - (t.count / trendMax) * 44}`).join(' ')
      : '';

    const statusRow = (id: string, label: string, color: string) => {
      const n = m.by_status?.[id] ?? 0;
      const pct = Math.round((n / (m.total || 1)) * 100);
      return (
        <div key={id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.8125rem', padding: '3px 0' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, flexShrink: 0 }} />
          <span style={{ flex: 1 }}>{label}</span>
          <span style={{ color: 'var(--text-secondary)' }}>{n}</span>
          <span style={{ color: 'var(--text-muted)', width: 40, textAlign: 'right', fontSize: '0.75rem' }}>{pct}%</span>
        </div>
      );
    };

    return (
      <div style={{ padding: '1.25rem 2rem 2rem' }}>
        {/* Headline band: risk score + key counts */}
        <div style={{ display: 'flex', flexWrap: 'wrap', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', overflow: 'hidden', marginBottom: '1rem' }}>
          <div style={{ flex: '1 1 320px', padding: '1.25rem 1.5rem', borderRight: '1px solid var(--border)' }}>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>Risk score</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
              <span style={{ fontSize: '2.4rem', fontWeight: 600, color: riskColor, lineHeight: 1 }}>{riskScore}</span>
              <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>/ 100 · {riskLabel}</span>
            </div>
            <div style={{ height: 5, background: 'var(--bg-hover)', borderRadius: 3, marginTop: 12, overflow: 'hidden' }}>
              <div style={{ width: `${riskScore}%`, height: '100%', background: riskColor }} />
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', flex: '1 1 300px' }}>
            {([
              ['Open', m.by_status?.open ?? 0, 'var(--text-primary)'],
              ['Critical', sevCounts.critical, 'var(--red)'],
              ['In SLA', `${m.sla_compliance_pct}%`, 'var(--green)'],
              ['Overdue', m.overdue_count, m.overdue_count > 0 ? 'var(--red)' : 'var(--text-primary)'],
            ] as [string, React.ReactNode, string][]).map(([label, val, color], i) => (
              <div key={label} style={{ padding: '0.9rem 1.1rem', borderRight: i % 2 === 0 ? '1px solid var(--border)' : 'none', borderBottom: i < 2 ? '1px solid var(--border)' : 'none' }}>
                <div style={{ fontSize: '1.4rem', fontWeight: 600, color }}>{val}</div>
                <div style={{ fontSize: '0.625rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>{label}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Priority queue — the centerpiece */}
        <div className="card" style={{ padding: '1.1rem 1.25rem', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ fontSize: '0.875rem', fontWeight: 600 }}>Priority queue</span>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>ranked by severity &amp; CVSS</span>
          </div>
          {queue.length === 0 ? (
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', padding: '1rem 0' }}>No open findings — nothing in the queue.</p>
          ) : queue.map((v, i) => {
            const statusMeta = STATUS_META.find(s => s.id === (v.status || 'open'));
            return (
              <div key={v.id} role="button" tabIndex={0}
                onClick={() => { setViewMode('list'); handleSelect(v); }}
                onKeyDown={(e) => { if (e.key === 'Enter') { setViewMode('list'); handleSelect(v); } }}
                style={{ display: 'flex', alignItems: 'center', gap: 11, padding: '0.6rem 0', borderBottom: i < queue.length - 1 ? '1px solid var(--border)' : 'none', cursor: 'pointer' }}>
                <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', width: 14, textAlign: 'center' }}>{i + 1}</span>
                <span style={{ width: 3, height: 28, background: SEV_COLORS[v.severity] || 'var(--border)', borderRadius: 2, flexShrink: 0 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: '0.8125rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.vuln_name}</div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    {v.cve_id || v.owasp_category || '—'}{v.cvss_score != null ? ` · CVSS ${v.cvss_score}` : ''}
                  </div>
                </div>
                {statusMeta && <span style={{ fontSize: '0.6875rem', color: statusMeta.color, display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: statusMeta.color }} />{statusMeta.label}</span>}
                <span className={`badge badge-${v.severity}`}>{v.severity}</span>
              </div>
            );
          })}
          {queue.length > 0 && (
            <button onClick={() => setViewMode('list')} style={{ marginTop: 10, fontSize: '0.75rem', color: 'var(--cyan)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
              View all {m.total} findings →
            </button>
          )}
        </div>

        {/* Supporting footer: severity mix · lifecycle · intake */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
          <div className="card" style={{ padding: '1.1rem 1.25rem' }}>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 10 }}>Severity mix</div>
            <div style={{ display: 'flex', height: 22, borderRadius: 5, overflow: 'hidden', gap: 2 }}>
              {(['critical', 'high', 'medium', 'low'] as const).map(sev => sevCounts[sev] > 0 && (
                <div key={sev} title={`${sevCounts[sev]} ${sev}`} style={{ width: `${(sevCounts[sev] / totalSev) * 100}%`, background: SEV_COLORS[sev], display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.625rem', color: 'var(--on-accent)', fontWeight: 600 }}>{sevCounts[sev]}</div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 12, marginTop: 8, flexWrap: 'wrap', fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
              {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
                <span key={sev} style={{ textTransform: 'capitalize' }}><span style={{ color: SEV_COLORS[sev] }}>●</span> {sev}</span>
              ))}
            </div>
          </div>

          <div className="card" style={{ padding: '1.1rem 1.25rem' }}>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 10 }}>Lifecycle status</div>
            {statusRow('open', 'Open', 'var(--red)')}
            {statusRow('in_progress', 'In progress', 'var(--amber)')}
            {statusRow('resolved', 'Resolved', 'var(--green)')}
            {statusRow('accepted_risk', 'Accepted', 'var(--blue)')}
          </div>

          <div className="card" style={{ padding: '1.1rem 1.25rem' }}>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 10 }}>30-day intake</div>
            {trend.length === 0 ? (
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>No new findings in the last 30 days.</p>
            ) : (
              <svg viewBox="0 0 300 50" style={{ width: '100%', height: 56 }} role="img" aria-label="New findings over the last 30 days">
                <polyline points={trendPts} fill="none" stroke="var(--cyan)" strokeWidth={2} />
                <polygon points={`${trendPts} 300,50 0,50`} fill="var(--cyan-glow)" />
              </svg>
            )}
          </div>
        </div>
      </div>
    );
  };

  // ─────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────
  return (
    <div className="animate-fadeIn" style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>

      {/* ── Page header ───────────────────────────────────────── */}
      <div style={{ padding: '1.5rem 2rem 0', flexShrink: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.875rem' }}>
          <div>
            <h1 style={{ marginBottom: 2 }}>Vulnerabilities</h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>{total} total findings</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {/* Export CSV */}
            <button onClick={handleExportCsv} disabled={exporting}
              style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '0.4rem 0.85rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-secondary)', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer' }}
              title="Export to CSV">
              <Download size={13} />{exporting ? 'Exporting…' : 'Export'}
            </button>
            {/* Advanced filters toggle */}
            <button onClick={() => setShowFilters(f => !f)}
              style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '0.4rem 0.85rem', borderRadius: 'var(--radius-md)', border: `1px solid ${showFilters ? 'var(--cyan)' : 'var(--border)'}`, background: showFilters ? 'color-mix(in srgb, var(--cyan) 8%, transparent)' : 'var(--bg-secondary)', color: showFilters ? 'var(--cyan)' : 'var(--text-secondary)', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer' }}>
              <Filter size={13} /> Filters {showFilters ? '▲' : '▼'}
            </button>
            {/* Enrich All */}
            <button onClick={handleEnrichAll} disabled={enriching}
              style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0.4rem 0.9rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--cyan)', background: enriching ? 'color-mix(in srgb, var(--cyan) 19%, transparent)' : 'color-mix(in srgb, var(--cyan) 8%, transparent)', color: 'var(--cyan)', fontSize: '0.75rem', fontWeight: 600, cursor: enriching ? 'not-allowed' : 'pointer' }}
              title="Backfill from AI analyses and enrich CVSS/EPSS">
              <Sparkles size={13} />{enriching ? 'Enriching…' : 'Enrich All'}
            </button>
            {/* View switcher moved to the left sub-navigation below. */}
          </div>
        </div>

        {/* Enrich result banner */}
        {enrichResult && (
          <div style={{ marginBottom: '0.75rem', padding: '0.5rem 0.875rem', borderRadius: 'var(--radius-md)', background: enrichResult.includes('failed') ? 'color-mix(in srgb, var(--red) 13%, transparent)' : 'color-mix(in srgb, var(--green) 13%, transparent)', border: `1px solid ${enrichResult.includes('failed') ? 'color-mix(in srgb, var(--red) 25%, transparent)' : 'color-mix(in srgb, var(--green) 25%, transparent)'}`, color: enrichResult.includes('failed') ? 'var(--red)' : 'var(--green)', fontSize: '0.8125rem', fontWeight: 500 }}>
            {enrichResult}
          </div>
        )}

        {/* Advanced filter panel */}
        {showFilters && (
          <div className="card animate-fadeIn" style={{ padding: '1rem', marginBottom: '0.875rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '0.75rem' }}>
            <div>
              <label style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Status</label>
              <select className="input" value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{ fontSize: '0.8125rem', padding: '0.3rem 0.5rem' }}>
                <option value="">All</option>
                {STATUS_META.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
              </select>
            </div>
            <div>
              <label style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Priority</label>
              <select className="input" value={filterPriority} onChange={e => setFilterPriority(e.target.value)} style={{ fontSize: '0.8125rem', padding: '0.3rem 0.5rem' }}>
                <option value="">All</option>
                {['p1','p2','p3','p4'].map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
              </select>
            </div>
            <div>
              <label style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Assignee</label>
              <select className="input" value={filterAssignedTo} onChange={e => setFilterAssignedTo(e.target.value)} style={{ fontSize: '0.8125rem', padding: '0.3rem 0.5rem' }}>
                <option value="">Anyone</option>
                {users.map(u => <option key={u.id} value={u.id}>{u.name}</option>)}
              </select>
            </div>
            <div>
              <label style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>From</label>
              <input type="date" className="input" value={filterDateFrom} onChange={e => setFilterDateFrom(e.target.value)} style={{ fontSize: '0.8125rem', padding: '0.3rem 0.5rem' }} />
            </div>
            <div>
              <label style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>To</label>
              <input type="date" className="input" value={filterDateTo} onChange={e => setFilterDateTo(e.target.value)} style={{ fontSize: '0.8125rem', padding: '0.3rem 0.5rem' }} />
            </div>
            <div>
              <label style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>OWASP Category</label>
              <input className="input" value={filterOwasp} onChange={e => setFilterOwasp(e.target.value)} placeholder="e.g. A01" style={{ fontSize: '0.8125rem', padding: '0.3rem 0.5rem' }} />
            </div>
            <div>
              <label style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>MITRE Technique</label>
              <input className="input" value={filterMitre} onChange={e => setFilterMitre(e.target.value)} placeholder="e.g. T1190" style={{ fontSize: '0.8125rem', padding: '0.3rem 0.5rem' }} />
            </div>
            <div>
              <label style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Tags</label>
              <input className="input" value={filterTags} onChange={e => setFilterTags(e.target.value)} placeholder="comma-separated" style={{ fontSize: '0.8125rem', padding: '0.3rem 0.5rem' }} />
            </div>
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: 8 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.8125rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                <input type="checkbox" checked={filterOverdue} onChange={e => setFilterOverdue(e.target.checked)} />
                Overdue only
              </label>
            </div>
            <div style={{ display: 'flex', alignItems: 'flex-end' }}>
              <button onClick={() => { setFilterStatus(''); setFilterPriority(''); setFilterAssignedTo(''); setFilterOverdue(false); setFilterDateFrom(''); setFilterDateTo(''); setFilterOwasp(''); setFilterMitre(''); setFilterTags(''); }}
                style={{ fontSize: '0.75rem', color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline' }}>
                Clear all
              </button>
            </div>
          </div>
        )}

        {/* Status summary strip */}
        {total > 0 && viewMode === 'list' && (
          <div style={{ display: 'flex', gap: 6, marginBottom: '0.875rem', flexWrap: 'wrap' }}>
            {statusCounts.map(s => (
              <div key={s.id} onClick={() => setFilterStatus(s.id === filterStatus ? '' : s.id)}
                title={`${s.count} ${s.label}`}
                style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0.3rem 0.75rem', borderRadius: 99, cursor: 'pointer', background: filterStatus === s.id ? `color-mix(in srgb, ${s.color} 13%, transparent)` : `color-mix(in srgb, ${s.color} 6%, transparent)`, border: `1px solid ${filterStatus === s.id ? s.color : `color-mix(in srgb, ${s.color} 21%, transparent)`}`, transition: 'all 0.15s' }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: s.color, display: 'inline-block' }} />
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: s.color }}>{s.count}</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{s.label}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Body: left sub-navigation + the active view ─────────── */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

        {/* Left sub-navigation */}
        <nav aria-label="Vulnerability views" style={{ width: 200, flexShrink: 0, borderRight: '1px solid var(--border)', padding: '1rem 0.6rem', display: 'flex', flexDirection: 'column', gap: 3, background: 'var(--bg-secondary)', overflow: 'auto' }}>
          <div style={{ fontSize: '0.625rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, padding: '0.25rem 0.7rem 0.5rem' }}>Views</div>
          {([
            ['list', List, 'Vulnerability List'],
            ['heatmap', TrendingUp, 'Heatmap'],
            ['metrics', BarChart2, 'Metrics'],
            ['kanban', LayoutGrid, 'Kanban'],
          ] as [ViewMode, React.ElementType, string][]).map(([mode, Icon, label]) => {
            const active = viewMode === mode;
            return (
              <button
                key={mode}
                onClick={() => setViewMode(mode)}
                aria-current={active ? 'page' : undefined}
                style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '0.55rem 0.75rem', borderRadius: 'var(--radius-md)', border: 'none', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 500, textAlign: 'left', width: '100%', background: active ? 'var(--bg-hover)' : 'transparent', color: active ? 'var(--cyan)' : 'var(--text-secondary)', borderLeft: `2px solid ${active ? 'var(--cyan)' : 'transparent'}`, transition: 'background 0.15s' }}
              >
                <Icon size={16} aria-hidden="true" /> {label}
              </button>
            );
          })}

          {/* Always-visible open-by-severity mini summary */}
          <div style={{ marginTop: 'auto', padding: '0.75rem 0.75rem 0.25rem', borderTop: '1px solid var(--border)' }}>
            <div style={{ fontSize: '0.625rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 7 }}>Open by severity</div>
            {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
              const n = metricsData?.by_severity?.[sev] ?? 0;
              if (n === 0 && sev === 'low') return null;
              return (
                <div key={sev} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem', color: 'var(--text-secondary)', padding: '2px 0' }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 6, textTransform: 'capitalize' }}>
                    <span style={{ width: 7, height: 7, borderRadius: '50%', background: SEV_COLORS[sev] }} />{sev}
                  </span>
                  <span style={{ fontWeight: 600 }}>{n}</span>
                </div>
              );
            })}
          </div>
        </nav>

        {/* Active view */}
        {viewMode === 'heatmap' && (
          <div style={{ flex: 1, overflow: 'auto', padding: '1rem 2rem 2rem' }}>
            <VulnRiskHeatmap vulnerabilities={vulns} />
          </div>
        )}
        {viewMode === 'kanban' && (
          <div style={{ flex: 1, overflow: 'auto', padding: '1rem 2rem 2rem' }}>
            <RemediationKanban vulnerabilities={vulns} onUpdate={load} />
          </div>
        )}
        {viewMode === 'metrics' && (
          <div style={{ flex: 1, overflow: 'auto' }}>
            <MetricsView />
          </div>
        )}

      {/* ── List view ─────────────────────────────────────────── */}
      {viewMode === 'list' && (
        <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

          {/* Left: list */}
          <div style={{ flex: 1, overflow: 'auto', padding: '1rem 1.5rem', borderRight: '1px solid var(--border)', minWidth: 0 }}>
            {/* Search + severity pills */}
            <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
              <div style={{ position: 'relative', flex: 1, minWidth: 180 }}>
                <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input className="input" value={searchInput} onChange={e => setSearchInput(e.target.value)} aria-label="Search vulnerabilities"
                  placeholder="Search vulnerabilities…" style={{ paddingLeft: 30 }} />
              </div>
              {SEVS.map(s => (
                <button key={s || 'all'} onClick={() => { setSeverity(s); setPage(1); }}
                  style={{ padding: '0.4rem 0.875rem', borderRadius: 99, fontSize: '0.75rem', fontWeight: 600, border: `1px solid ${severity === s ? (SEV_COLORS[s] || 'var(--cyan)') : 'var(--border)'}`, background: severity === s ? `color-mix(in srgb, ${SEV_COLORS[s] || 'var(--cyan)'} 13%, transparent)` : 'transparent', color: severity === s ? (SEV_COLORS[s] || 'var(--cyan)') : 'var(--text-muted)', cursor: 'pointer', textTransform: 'capitalize' }}>
                  {s || 'All'}
                </button>
              ))}
            </div>

            {/* Bulk action bar */}
            {selectedIds.size > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: '0.875rem', padding: '0.6rem 1rem', borderRadius: 'var(--radius-md)', background: 'color-mix(in srgb, var(--cyan) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--cyan) 19%, transparent)' }}>
                <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--cyan)' }}>{selectedIds.size} selected</span>
                <select value={bulkStatus} onChange={e => setBulkStatus(e.target.value)}
                  className="input" style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem', width: 'auto' }}>
                  <option value="">Set status…</option>
                  {STATUS_META.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
                </select>
                <button onClick={handleBulkApply} disabled={!bulkStatus || applyingBulk}
                  className="btn btn-primary" style={{ fontSize: '0.75rem', padding: '0.3rem 0.8rem' }}>
                  {applyingBulk ? 'Applying…' : 'Apply'}
                </button>
                <button onClick={() => setSelectedIds(new Set())}
                  style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                  <X size={14} />
                </button>
              </div>
            )}

            {/* Table header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 0.5rem', marginBottom: '0.4rem' }}>
              <input type="checkbox" checked={filtered.length > 0 && selectedIds.size === filtered.length}
                onChange={toggleSelectAll} style={{ cursor: 'pointer' }} />
              <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', flex: 1 }}>NAME</span>
              <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', width: 60, textAlign: 'right' }}>SEVERITY</span>
            </div>

            {loading ? (
              // Skeleton rows while loading — distinct from the empty state below.
              Array.from({ length: 6 }).map((_, i) => (
                <div key={`sk-${i}`} className="card" style={{ marginBottom: '0.45rem', padding: '0.85rem 0.875rem', borderLeft: '3px solid var(--border)' }}>
                  <div style={{ height: 12, width: `${55 + (i % 3) * 12}%`, background: 'var(--bg-hover)', borderRadius: 4, marginBottom: 8 }} />
                  <div style={{ height: 9, width: '35%', background: 'var(--bg-hover)', borderRadius: 4, opacity: 0.6 }} />
                </div>
              ))
            ) : loadError ? (
              <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
                <ShieldAlert size={40} style={{ margin: '0 auto 0.75rem', opacity: 0.3 }} aria-hidden="true" />
                <p>Couldn&apos;t load vulnerabilities.</p>
                <button onClick={() => load()} className="btn btn-ghost" style={{ marginTop: '0.75rem' }}>Retry</button>
              </div>
            ) : filtered.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
                <ShieldAlert size={40} style={{ margin: '0 auto 0.75rem', opacity: 0.3 }} aria-hidden="true" />
                <p>{search || filterStatus || severity ? 'No vulnerabilities match these filters.' : 'No vulnerabilities found.'}</p>
                {(search || filterStatus || severity) && (
                  <button onClick={() => { setSearchInput(''); setSeverity(''); setFilterStatus(''); }} className="btn btn-ghost" style={{ marginTop: '0.75rem' }}>Clear filters</button>
                )}
              </div>
            ) : filtered.map(v => {
              const sla = getSlaStatus(v);
              const statusMeta = STATUS_META.find(s => s.id === (v.status || 'open'));
              const terminal = v.status === 'resolved' || v.status === 'false_positive';
              return (
                <div
                  key={v.id}
                  role="button"
                  tabIndex={0}
                  aria-label={`${v.vuln_name}, ${v.severity} severity`}
                  onClick={() => handleSelect(v)}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleSelect(v); } }}
                  className="card"
                  style={{ marginBottom: '0.45rem', padding: '0.75rem 0.875rem', cursor: 'pointer', transition: 'background 0.15s', borderLeft: `3px solid ${SEV_COLORS[v.severity] || 'var(--border)'}`, background: selected?.id === v.id ? 'var(--bg-hover)' : 'var(--bg-card)', opacity: terminal ? 0.72 : 1 }}
                >
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                    <input type="checkbox" checked={selectedIds.has(v.id)} onChange={() => toggleSelect(v.id)}
                      onClick={e => e.stopPropagation()} aria-label={`Select ${v.vuln_name}`} style={{ marginTop: 2, cursor: 'pointer', flexShrink: 0 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontWeight: 600, fontSize: '0.875rem', marginBottom: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.vuln_name}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
                        {statusMeta && (
                          <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: statusMeta.color }}>
                            <span style={{ width: 6, height: 6, borderRadius: '50%', background: statusMeta.color, flexShrink: 0 }} />{statusMeta.label}
                          </span>
                        )}
                        {v.cve_id && <span style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>{v.cve_id}</span>}
                        {v.owasp_category && <span>{v.owasp_category}</span>}
                        {v.priority && PRIORITY_META[v.priority] && <span style={{ color: PRIORITY_META[v.priority].color, fontWeight: 600 }}>{PRIORITY_META[v.priority].label}</span>}
                        {v.assigned_user_name && <span style={{ color: 'var(--text-secondary)' }}>→ {v.assigned_user_name}</span>}
                        {sla && <span style={{ color: sla.color, display: 'flex', alignItems: 'center', gap: 3 }}><Clock size={10} aria-hidden="true" /> {sla.label}</span>}
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                      <button title="Generate attack payloads" aria-label="Generate attack payloads" onClick={e => {
                          e.stopPropagation();
                          const params = new URLSearchParams();
                          if (v.cve_id) params.set('cve_id', v.cve_id);
                          const name = v.vuln_name?.toLowerCase() || '';
                          const vt = name.includes('sql') ? 'sqli' : name.includes('xss') ? 'xss' : name.includes('lfi') ? 'lfi' : name.includes('rce') ? 'rce' : name.includes('ssrf') ? 'ssrf' : 'sqli';
                          params.set('vuln_type', vt);
                          router.push(`/tools/payload-generator?${params.toString()}`);
                        }}
                        style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: '0.6875rem', fontWeight: 600, padding: '2px 7px', borderRadius: 'var(--radius-sm)', border: '1px solid color-mix(in srgb, var(--cyan) 35%, transparent)', background: 'color-mix(in srgb, var(--cyan) 10%, transparent)', color: 'var(--cyan)', cursor: 'pointer' }}>
                        <Wrench size={10} aria-hidden="true" />
                      </button>
                      <span className={`badge badge-${v.severity}`}>{v.severity}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Right: Detail panel */}
          <div style={{ width: 380, flexShrink: 0, overflow: 'auto', padding: '1.5rem', background: 'var(--bg-secondary)', display: 'flex', flexDirection: 'column' }}>
            {!selected ? (
              <div style={{ textAlign: 'center', padding: '4rem 2rem', color: 'var(--text-muted)' }}>
                <ShieldAlert size={40} style={{ margin: '0 auto 0.75rem', opacity: 0.2 }} />
                <p style={{ fontSize: '0.875rem' }}>Select a vulnerability to see details</p>
              </div>
            ) : (
              <div className="animate-fadeIn">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem', gap: 8 }}>
                  <h3 style={{ fontSize: '0.95rem', fontWeight: 600, lineHeight: 1.4, margin: 0 }}>{selected.vuln_name}</h3>
                  <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                    <button onClick={() => router.push(`/vulnerabilities/${selected.id}`)} className="btn btn-ghost" aria-label="Open full page" style={{ padding: 4 }}>
                      <ExternalLink size={14} />
                    </button>
                    <button onClick={() => setSelected(null)} className="btn btn-ghost" aria-label="Close panel" style={{ padding: 4 }}>
                      <X size={14} />
                    </button>
                  </div>
                </div>
                <VulnDetail vuln={selected} users={users} onSaved={load} compact />
              </div>
            )}
          </div>
        </div>
      )} {/* end list view */}

      </div> {/* end body: sub-nav + active view */}
    </div>
  );
}
