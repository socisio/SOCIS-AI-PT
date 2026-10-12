'use client';
import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, ShieldAlert } from 'lucide-react';
import { vulnsApi, usersApi } from '@/lib/api';
import type { Vulnerability, DirectoryUser } from '@/lib/types';
import { SEV_COLORS, PRIORITY_META } from '@/lib/vulns';
import VulnDetail from '@/components/VulnDetail';

export default function VulnerabilityDetailPage() {
  const router = useRouter();
  const params = useParams();
  const id = params?.id as string;

  const [vuln, setVuln] = useState<Vulnerability | null>(null);
  const [loading, setLoading] = useState(true);
  const [users, setUsers] = useState<DirectoryUser[]>([]);

  const loadVuln = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      const res = await vulnsApi.get(id);
      setVuln(res.data);
    } catch {
      setVuln(null);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { loadVuln(); }, [loadVuln]);

  useEffect(() => {
    usersApi.directory().then((r) => setUsers(r.data || [])).catch(() => {});
  }, []);

  if (loading) {
    return <div style={{ textAlign: 'center', padding: '6rem', color: 'var(--text-muted)' }}>Loading vulnerability…</div>;
  }

  if (!vuln) {
    return (
      <div style={{ textAlign: 'center', padding: '6rem', color: 'var(--text-muted)' }}>
        <ShieldAlert size={40} style={{ margin: '0 auto 1rem', opacity: 0.3 }} aria-hidden="true" />
        <p>Vulnerability not found or access denied.</p>
        <button onClick={() => router.back()} className="btn btn-ghost" style={{ marginTop: '1rem' }}>&larr; Go back</button>
      </div>
    );
  }

  const sevColor = SEV_COLORS[vuln.severity] || 'var(--text-secondary)';

  const metaTiles = [
    vuln.cvss_score != null ? { label: 'CVSS Score', value: String(vuln.cvss_score), color: sevColor } : null,
    vuln.epss_score != null ? { label: 'EPSS', value: `${(vuln.epss_score * 100).toFixed(3)}%`, color: 'var(--text-secondary)' } : null,
    vuln.port ? { label: 'Port', value: String(vuln.port), color: 'var(--text-primary)' } : null,
    vuln.service ? { label: 'Service', value: vuln.service, color: 'var(--text-primary)' } : null,
    { label: 'Found', value: new Date(vuln.created_at).toLocaleDateString(), color: 'var(--text-muted)' },
    vuln.resolved_at ? { label: 'Resolved', value: new Date(vuln.resolved_at).toLocaleDateString(), color: 'var(--green)' } : null,
  ].filter((x): x is { label: string; value: string; color: string } => x !== null);

  return (
    <div className="animate-fadeIn" style={{ minHeight: '100vh', background: 'var(--bg-primary)', padding: '1.5rem 2rem 3rem' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
        <button onClick={() => router.back()} className="btn btn-ghost" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.8125rem', padding: '0.4rem 0.75rem' }}>
          <ArrowLeft size={14} /> Back
        </button>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <span className={`badge badge-${vuln.severity}`}>{vuln.severity}</span>
            {vuln.priority && PRIORITY_META[vuln.priority] && (
              <span style={{
                fontSize: '0.75rem', fontWeight: 600, padding: '2px 8px', borderRadius: 'var(--radius-sm)',
                background: `color-mix(in srgb, ${PRIORITY_META[vuln.priority].color} 13%, transparent)`,
                color: PRIORITY_META[vuln.priority].color,
                border: `1px solid color-mix(in srgb, ${PRIORITY_META[vuln.priority].color} 27%, transparent)`,
              }}>{PRIORITY_META[vuln.priority].label}</span>
            )}
            {vuln.cve_id && <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', color: 'var(--cyan)' }}>{vuln.cve_id}</span>}
          </div>
          <h1 style={{ marginTop: 6, lineHeight: 1.35 }}>{vuln.vuln_name}</h1>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 360px', gap: '1.5rem', alignItems: 'start' }} className="vuln-detail-grid">
        <div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(130px, 1fr))', gap: '0.875rem', marginBottom: '1.5rem' }}>
            {metaTiles.map(({ label, value, color }) => (
              <div key={label} className="card" style={{ padding: '0.875rem', textAlign: 'center' }}>
                <div style={{ fontSize: '1rem', fontWeight: 600, color }}>{value}</div>
                <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: 2 }}>{label}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="card" style={{ padding: '1.25rem' }}>
          <VulnDetail vuln={vuln} users={users} onSaved={loadVuln} />
        </div>
      </div>
    </div>
  );
}
