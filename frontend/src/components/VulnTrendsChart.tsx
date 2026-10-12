'use client';

import { useEffect, useState, useMemo } from 'react';
import {
  ComposedChart, Bar, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Cell, ReferenceLine,
} from 'recharts';
import axios from 'axios';

interface TrendPoint {
  date: string;
  count: number;
}

interface Props {
  days?: number;
}

// Colour bar by relative intensity (low → teal, high → red)
function barColor(count: number, max: number): string {
  if (max === 0) return 'var(--chart-cyan)';
  const ratio = count / max;
  if (ratio >= 0.8) return 'var(--chart-red)';
  if (ratio >= 0.55) return 'var(--chart-orange)';
  if (ratio >= 0.3) return 'var(--chart-amber)';
  return 'var(--chart-cyan)';
}

// ── Custom Tooltip ────────────────────────────────────────────
function CustomTooltip({ active, payload, label }: {
  active?: boolean;
  payload?: { value?: number }[];
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  const count = payload[0]?.value ?? 0;
  const color = count >= 8 ? 'var(--red)' : count >= 5 ? 'var(--orange)' : count >= 3 ? 'var(--amber)' : 'var(--cyan)';
  return (
    <div style={{
      background: 'var(--bg-card)', border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
      borderRadius: 'var(--radius-lg)', padding: '0.65rem 0.875rem',
      boxShadow: 'var(--shadow-pop)', minWidth: 150,
    }}>
      <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 4, fontFamily: 'monospace' }}>
        {label}
      </div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
        <span style={{ fontSize: '1.5rem', fontWeight: 800, color, lineHeight: 1 }}>{count}</span>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>vulnerabilities</span>
      </div>
    </div>
  );
}

export default function VulnTrendsChart({ days = 30 }: Props) {
  const [data, setData] = useState<TrendPoint[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios
      .get(`${process.env.NEXT_PUBLIC_API_URL ?? ''}/api/v1/reports/trends?days=${days}`, {
        withCredentials: true,
      })
      .then(r => setData(r.data))
      .catch(() => setData([]))
      .finally(() => setLoading(false));
  }, [days]);

  const { max, total, avg, peakDate } = useMemo(() => {
    if (!data.length) return { max: 0, total: 0, avg: 0, peakDate: '' };
    const max = Math.max(...data.map(d => d.count));
    const total = data.reduce((s, d) => s + d.count, 0);
    const avg = total / data.length;
    const peakDate = data.find(d => d.count === max)?.date ?? '';
    return { max, total, avg, peakDate };
  }, [data]);

  if (loading) {
    return (
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
        padding: '1.5rem', minHeight: 220, display: 'flex',
        alignItems: 'center', justifyContent: 'center',
        color: 'var(--text-muted)', fontSize: '0.875rem',
      }}>
        Loading trends…
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
        padding: '1.5rem', minHeight: 180, display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center', gap: 6,
      }}>
        <div style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>No vulnerability data for this period.</div>
      </div>
    );
  }

  return (
    <div style={{
      background: 'var(--bg-card)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius-lg)', padding: '1.25rem 1.5rem 1rem',
    }}>
      {/* Header row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.1rem', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Vulnerability trends
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
            Daily discoveries — last {days} days
          </div>
        </div>
        {/* KPI pills */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {[
            { label: 'Total', value: total, color: 'var(--cyan)' },
            { label: 'Peak', value: max, color: max >= 5 ? 'var(--orange)' : 'var(--cyan)' },
            { label: 'Daily avg', value: avg.toFixed(1), color: 'var(--text-muted)' },
          ].map(({ label, value, color }) => (
            <div key={label} style={{
              padding: '3px 12px', borderRadius: 99,
              background: `color-mix(in srgb, ${color} 8%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 19%, transparent)`,
              display: 'flex', gap: 6, alignItems: 'baseline',
            }}>
              <span style={{ fontSize: '1rem', fontWeight: 700, color }}>{value}</span>
              <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'none' }}>{label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Chart */}
      <ResponsiveContainer width="100%" height={210}>
        <ComposedChart data={data} margin={{ top: 10, right: 8, bottom: 24, left: 0 }} barCategoryGap="30%">
          <CartesianGrid strokeDasharray="2 4" stroke="var(--border)" vertical={false} />

          <XAxis
            dataKey="date"
            tick={{ fill: 'var(--text-muted)', fontSize: 9.5 }}
            tickLine={false}
            axisLine={{ stroke: 'var(--border)' }}
            tickFormatter={d => d.slice(5)} /* MM-DD */
            angle={-35}
            textAnchor="end"
            interval="preserveStartEnd"
            height={36}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: 'var(--text-muted)', fontSize: 10 }}
            tickLine={false}
            axisLine={false}
            width={24}
          />

          {/* 7-day rolling avg line */}
          {avg > 0 && (
            <ReferenceLine
              y={avg}
              stroke="var(--cyan)"
              strokeOpacity={0.3}
              strokeDasharray="4 3"
              strokeWidth={1}
              label={{ value: 'avg', position: 'insideTopRight', fill: 'var(--cyan)', fontSize: 9 }}
            />
          )}

          {/* Peak marker */}
          {peakDate && (
            <ReferenceLine
              x={peakDate}
              stroke="var(--orange)"
              strokeOpacity={0.3}
              strokeWidth={1}
              strokeDasharray="3 3"
            />
          )}

          <Tooltip
            cursor={{ fill: 'var(--text-primary)', fillOpacity: 0.06, radius: 4 }}
            content={<CustomTooltip />}
          />

          <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={28} isAnimationActive={false}>
            {data.map((entry, idx) => (
              <Cell key={idx} fill={barColor(entry.count, max)} fillOpacity={0.85} />
            ))}
          </Bar>

          {/* Trend line overlay */}
          <Line
            type="monotone"
            dataKey="count"
            stroke="var(--cyan)"
            strokeWidth={1.5}
            dot={false}
            strokeOpacity={0.35}
            isAnimationActive={false}
          />
        </ComposedChart>
      </ResponsiveContainer>

      {/* Footer legend */}
      <div style={{ display: 'flex', gap: 16, marginTop: '0.25rem', flexWrap: 'wrap' }}>
        {[
          { color: 'var(--chart-cyan)', label: 'Low (under 30%)' },
          { color: 'var(--chart-amber)', label: 'Medium' },
          { color: 'var(--chart-orange)', label: 'High' },
          { color: 'var(--chart-red)', label: 'Peak (80% or more)' },
        ].map(({ color, label }) => (
          <span key={label} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
            <span style={{ width: 8, height: 8, borderRadius: 'var(--radius-sm)', background: color, display: 'inline-block', opacity: 0.85 }} />
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}

