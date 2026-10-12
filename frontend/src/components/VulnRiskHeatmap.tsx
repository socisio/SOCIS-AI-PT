'use client';

import { useMemo, Fragment, type CSSProperties } from 'react';
import { SEV_COLORS, isJunkVulnName } from '@/lib/vulns';

// Severity-based EPSS fallback (midpoint estimates for display when a finding has no real EPSS score yet).
const SEV_EPSS: Record<string, number> = {
  critical: 72, high: 38, medium: 14, low: 4, info: 1,
};

interface HeatmapVuln {
  id: string;
  vuln_name: string;
  severity: string;
  cvss_score?: number | null;
  epss_score?: number | null;
  cve_id?: string | null;
}

interface Props {
  vulnerabilities: HeatmapVuln[];
}

// Column = CVSS severity band. Row = EPSS exploitation-probability band (highest at the top).
const SEV_COLS = ['info', 'low', 'medium', 'high', 'critical'] as const;
const SEV_LABEL: Record<string, string> = { info: 'Info', low: 'Low', medium: 'Med', high: 'High', critical: 'Crit' };
const EPSS_ROWS = [
  { label: '90%+', min: 90 },
  { label: '50%+', min: 50 },
  { label: '20%+', min: 20 },
  { label: '<20%', min: 0 },
];

/**
 * Risk density grid — a true heat MAP: a CVSS-severity × EPSS-probability matrix where each cell is shaded by how
 * many findings fall in that band. Replaces the previous scatter plot (which wasted ~60% of its space and overlapped
 * its quadrant labels). Scales cleanly from a handful of findings to thousands. Every color is a CSS variable, so it
 * works in both the light and dark themes.
 */
export default function VulnRiskHeatmap({ vulnerabilities }: Props) {
  const { grid, max, total } = useMemo(() => {
    const g: number[][] = EPSS_ROWS.map(() => SEV_COLS.map(() => 0));
    let count = 0;
    for (const v of vulnerabilities) {
      if (isJunkVulnName(v.vuln_name)) continue;
      const sev = (v.severity || 'info').toLowerCase();
      const col = SEV_COLS.indexOf(sev as typeof SEV_COLS[number]);
      if (col < 0) continue;
      const epss = v.epss_score != null ? v.epss_score * 100 : (SEV_EPSS[sev] ?? 1);
      const row = EPSS_ROWS.findIndex(r => epss >= r.min);
      const r = row < 0 ? EPSS_ROWS.length - 1 : row;
      g[r][col] += 1;
      count += 1;
    }
    const mx = Math.max(1, ...g.flat());
    return { grid: g, max: mx, total: count };
  }, [vulnerabilities]);

  // Cell fill: scales opacity with density, tinted toward the column's severity color.
  const cellStyle = (n: number, sev: string): CSSProperties => {
    if (n === 0) return { background: 'var(--bg-secondary)' };
    const intensity = 0.18 + (n / max) * 0.62; // 0.18 → 0.80
    return { background: `color-mix(in srgb, ${SEV_COLORS[sev] || 'var(--text-muted)'} ${Math.round(intensity * 100)}%, transparent)` };
  };

  const labelCount: Record<string, number> = {};
  for (const v of vulnerabilities) {
    if (isJunkVulnName(v.vuln_name)) continue;
    const s = (v.severity || 'info').toLowerCase();
    labelCount[s] = (labelCount[s] ?? 0) + 1;
  }

  return (
    <div className="card" style={{ padding: '1.25rem 1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: 10 }}>
        <div>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600, margin: 0 }}>Risk density</h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: '2px 0 0' }}>How many findings sit in each severity &times; exploitability band</p>
        </div>
        <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap' }}>
          {(['critical', 'high', 'medium'] as const).map(s => (
            <span key={s} style={{ fontSize: '0.6875rem', color: 'var(--text-secondary)', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: '3px 9px', textTransform: 'capitalize' }}>
              <span style={{ color: SEV_COLORS[s] }}>●</span> {s} {labelCount[s] ?? 0}
            </span>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <span style={{ fontSize: '0.625rem', color: 'var(--text-muted)', writingMode: 'vertical-rl', transform: 'rotate(180deg)', letterSpacing: 0.5 }}>Exploitation probability &rarr;</span>
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'grid', gridTemplateColumns: `44px repeat(${SEV_COLS.length}, 1fr)`, gap: 4 }}>
            <div />
            {SEV_COLS.map(s => (
              <div key={s} style={{ textAlign: 'center', fontSize: '0.625rem', color: 'var(--text-muted)', paddingBottom: 4 }}>{SEV_LABEL[s]}</div>
            ))}
            {EPSS_ROWS.map((rowDef, r) => (
              <Fragment key={`row-${r}`}>
                <div style={{ fontSize: '0.625rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', justifyContent: 'flex-end', paddingRight: 6 }}>{rowDef.label}</div>
                {SEV_COLS.map((sev, c) => {
                  const n = grid[r][c];
                  return (
                    <div key={`${r}-${c}`} title={`${n} finding${n === 1 ? '' : 's'} · ${SEV_LABEL[sev]} severity · EPSS ${rowDef.label}`}
                      style={{ aspectRatio: '1.6', borderRadius: 4, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 500, color: n > 0 ? 'var(--text-primary)' : 'transparent', ...cellStyle(n, sev) }}>
                      {n > 0 ? n : ''}
                    </div>
                  );
                })}
              </Fragment>
            ))}
          </div>
          <div style={{ textAlign: 'center', fontSize: '0.625rem', color: 'var(--text-muted)', marginTop: 8 }}>CVSS severity &rarr;</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border)', flexWrap: 'wrap', gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>Fewer</span>
          <div style={{ display: 'flex', gap: 2 }}>
            {[0.15, 0.35, 0.6, 0.85].map((o, i) => (
              <span key={i} style={{ width: 16, height: 10, borderRadius: 2, background: `color-mix(in srgb, var(--orange) ${Math.round(o * 100)}%, transparent)` }} />
            ))}
          </div>
          <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>More findings</span>
        </div>
        <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>{total} plotted · top-right band = act now</span>
      </div>
    </div>
  );
}
