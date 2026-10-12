'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import {
  Layers, Search, Target, Terminal, X, ChevronDown, ChevronUp,
  ExternalLink, Clock, Download, RefreshCw, AlertCircle,
  Sparkles, CheckSquare, Square, Radio, AlertTriangle, Info, Check, Plus, Flag,
} from 'lucide-react';
import { findingsApi } from '@/lib/api';
import type { Finding, FindingsStats } from '@/lib/types';
import StructuredFindingOutput from '@/components/findings/StructuredFindingOutput';
import { hasSecuritySignal, needsReview } from '@/lib/findings';
import { notify } from '@/lib/dialogs';
import { useLlmProviders } from '@/hooks/useLlmProviders';
import LlmProviderModelPicker from '@/components/LlmProviderModelPicker';

// ── Category config ────────────────────────────────────────────────────────

// Intelligence (cve/cisa_kev/epss/poc_index) is handled by the Vulnerabilities page.
const CATEGORIES = [
  'All', 'Discovery', 'Vulnerability',
  'Exploitation', 'Web', 'Recon', 'Crypto', 'Code',
] as const;

type Category = typeof CATEGORIES[number];

const CATEGORY_COLORS: Record<string, string> = {
  Discovery:     'var(--cyan)',
  Vulnerability: 'var(--amber)',
  Intelligence:  'var(--purple)',
  Exploitation:  'var(--red)',
  Web:           'var(--orange)',
  Recon:         'var(--green)',
  Crypto:        'var(--blue)',
  Code:          'var(--text-secondary)',
  Other:         'var(--text-muted)',
};

// ── Mini summary ────────────────────────────────────────────────────────────

function miniSummary(finding: Finding): string {
  const p = finding.parsed_output as Record<string, unknown> | null | undefined;
  if (!p) {
    const raw = finding.raw_output;
    if (raw) return raw.slice(0, 120) + (raw.length > 120 ? '…' : '');
    return 'No output recorded';
  }

  // Ports
  const ports = p.open_ports as any[];
  if (Array.isArray(ports) && ports.length > 0) return `${ports.length} open port${ports.length !== 1 ? 's' : ''} found`;

  // Gobuster found paths
  const found = p.found as any[];
  if (Array.isArray(found) && found.length > 0) {
    const paths = found.filter((f) => typeof f === 'object' && f !== null);
    return `${paths.length || found.length} path${found.length !== 1 ? 's' : ''} discovered`;
  }

  // Subdomains
  const subs = p.subdomains as any[];
  if (Array.isArray(subs) && subs.length > 0) return `${subs.length} subdomain${subs.length !== 1 ? 's' : ''} enumerated`;

  // Nuclei / vuln findings
  const vulns = (p.vulnerabilities || p.findings) as any[];
  if (Array.isArray(vulns) && vulns.length > 0) return `${vulns.length} finding${vulns.length !== 1 ? 's' : ''} detected`;

  // WAF
  const waf = p.waf_detected;
  if (waf !== undefined) return waf ? `WAF detected: ${p.waf_name || 'unknown'}` : 'No WAF detected';

  // CISA KEV
  if ('in_kev' in p) return p.in_kev ? `⚠ Actively exploited — ${p.cve_id || p.product || 'KEV entry'}` : `Not in CISA KEV — ${p.cve_id || 'checked'}`;

  // EPSS
  const epss = (p.epss_score ?? p.epss) as number | undefined;
  if (typeof epss === 'number') {
    const pctLabel = (epss * 100).toFixed(2) + '%';
    const label = epss > 0.5 ? '🔴 Critical' : epss > 0.1 ? '🟡 Elevated' : '🟢 Low';
    return `EPSS: ${pctLabel} — ${label} exploitation probability`;
  }

  // Public PoC
  if ('public_poc_exists' in p) {
    const edb = Array.isArray(p.exploits) ? (p.exploits as any[]).length : 0;
    const gh = Array.isArray((p as any).github_poc_repos) ? (p as any).github_poc_repos.length : 0;
    if (p.public_poc_exists) return `⚠ Public PoC — ${edb} ExploitDB, ${gh} GitHub repos`;
    return 'No public PoC found';
  }

  // CVE
  if (p.cve_id && p.severity) return `${p.cve_id} — ${String(p.severity).toUpperCase()} ${p.cvss_v3_score ? `(CVSS ${p.cvss_v3_score})` : ''}`.trim();

  // SQLMap
  if ('vulnerable' in p || 'injectable' in p) {
    const isVuln = p.vulnerable === true || p.injectable === true;
    return isVuln ? `⚠ SQL injection found — ${p.dbms || 'unknown DBMS'}` : 'No SQL injection detected';
  }

  // Metasploit
  if (p.mode || Array.isArray((p as any).sessions_opened)) {
    const sessions = Array.isArray((p as any).sessions_opened) ? (p as any).sessions_opened.length : 0;
    return sessions > 0 ? `⚠ ${sessions} Metasploit session${sessions !== 1 ? 's' : ''} opened` : 'No Metasploit sessions opened';
  }

  // JWT
  if (p.algorithm) return `JWT: ${p.algorithm}${p.cracked ? ' — ⚠ SECRET CRACKED' : ''}`;

  // SSL
  if (p.grade || p.ssl_grade) return `SSL grade: ${p.grade || p.ssl_grade}${p.expires ? ` — expires ${String(p.expires).slice(0, 10)}` : ''}`;

  // Tech fingerprint
  const techs = (p.detected_technologies ?? p.technologies ?? (p as any).tech) as any[] | undefined;
  if (Array.isArray(techs) && techs.length > 0) return `${techs.length} technolog${techs.length !== 1 ? 'ies' : 'y'} detected`;

  // DNS records
  if (p.records && typeof p.records === 'object' && !Array.isArray(p.records)) {
    const count = Object.values(p.records as Record<string, unknown[]>).flat().length;
    return `${count} DNS record${count !== 1 ? 's' : ''} for ${p.domain || 'domain'}`;
  }

  // IP Geolocation
  if (p.ip && (p.country || p.city)) return `${p.ip} — ${[p.city, p.region, p.country].filter(Boolean).join(', ')}`;

  // OSINT / whois fields
  if (p.registrar) return `Registrar: ${p.registrar}${p.expiry ? ` — expires ${String(p.expiry).slice(0, 10)}` : ''}`;
  if (p.domain) return `Domain: ${p.domain}`;

  // Raw text output
  if (typeof p.output === 'string') return p.output.trim().split('\n').filter(Boolean)[0]?.slice(0, 100) || 'Output available';

  // Generic: first key/value
  const keys = Object.keys(p);
  if (keys.length > 0) {
    const val = p[keys[0]];
    const display = typeof val === 'object' ? JSON.stringify(val).slice(0, 60) : String(val).slice(0, 80);
    return `${keys[0]}: ${display}`;
  }
  return 'Result recorded';
}

// ── Structured output renderer — global, all tools ─────────────────────────

const URL_RE = /^https?:\/\//i;


// ── Parsed output detail renderer (legacy — replaced by StructuredFindingOutput) ──────────────────────────

function ParsedOutputDetail({ finding }: { finding: Finding }) {
  return <StructuredFindingOutput finding={finding} />;
}

// ── Detail Drawer ────────────────────────────────────────────────────────────

function FindingDrawer({
  finding,
  onClose,
}: {
  finding: Finding;
  onClose: () => void;
}) {
  const [showRaw, setShowRaw] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const catColor = CATEGORY_COLORS[finding.category] || CATEGORY_COLORS.Other;

  // Which provider/model to analyze THIS finding with — defaults to whatever the admin's configured providers
  // report (same data source AI Chat already uses), but is a local, per-panel choice: picking a different provider
  // here never overwrites the user's saved AI Chat default.
  const llmPicker = useLlmProviders();

  const runAiAnalysis = () => {
    setAiLoading(true);
    setAiError(null);
    findingsApi.analyze(finding.id, {
      provider: llmPicker.provider,
      model: llmPicker.model || undefined,
    })
      .then((res) => setAiAnalysis((res.data as { analysis: string }).analysis))
      .catch(() => setAiError('AI analysis failed. Check that the selected provider is configured in Admin → AI providers.'))
      .finally(() => setAiLoading(false));
  };

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)',
          zIndex: 1000, backdropFilter: 'blur(2px)',
        }}
      />
      {/* Panel */}
      <div style={{
        position: 'fixed', top: 0, right: 0, bottom: 0, width: 520,
        background: 'var(--bg-secondary)', borderLeft: '1px solid var(--border)',
        zIndex: 1001, display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }}>
        {/* Header */}
        <div style={{
          padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'flex-start', gap: 12,
        }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
              <span style={{
                fontFamily: 'monospace', fontWeight: 700, fontSize: '1rem',
                color: catColor,
              }}>
                {finding.tool_name}
              </span>
              <span style={{
                padding: '2px 8px', borderRadius: 99,
                background: `color-mix(in srgb, ${catColor} 13%, transparent)`, border: `1px solid color-mix(in srgb, ${catColor} 25%, transparent)`,
                fontSize: '0.6875rem', fontWeight: 600, color: catColor,
                textTransform: 'uppercase', letterSpacing: '0.05em',
              }}>
                {finding.category}
              </span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Target:{' '}
              <span style={{ color: 'var(--text-primary)', fontFamily: 'monospace' }}>
                {finding.scan.target}
              </span>
              {' · '}
              {new Date(finding.executed_at).toLocaleString()}
            </div>
          </div>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', color: 'var(--text-muted)',
            cursor: 'pointer', padding: 4, borderRadius: 'var(--radius-sm)',
          }}>
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '1.25rem 1.5rem' }}>
          {/* Meta badges */}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 20 }}>
            {finding.duration_ms !== undefined && (
              <span style={{
                padding: '3px 10px', borderRadius: 99,
                background: 'color-mix(in srgb, var(--text-primary) 5%, transparent)', border: '1px solid var(--border)',
                fontSize: '0.75rem', color: 'var(--text-muted)',
                display: 'flex', alignItems: 'center', gap: 5,
              }}>
                <Clock size={11} />
                {finding.duration_ms < 1000
                  ? `${finding.duration_ms}ms`
                  : `${(finding.duration_ms / 1000).toFixed(1)}s`}
              </span>
            )}
            {finding.exit_code !== undefined && (
              <span style={{
                padding: '3px 10px', borderRadius: 99,
                background: finding.exit_code === 0 ? 'rgba(74,222,128,0.1)' : 'rgba(248,113,113,0.1)',
                border: `1px solid ${finding.exit_code === 0 ? 'color-mix(in srgb, var(--green) 25%, transparent)' : 'color-mix(in srgb, var(--red) 25%, transparent)'}`,
                fontSize: '0.75rem',
                color: finding.exit_code === 0 ? 'var(--green)' : 'var(--red)',
              }}>
                Exit {finding.exit_code}
              </span>
            )}
          </div>

          {/* Parsed output */}
          <div style={{ marginBottom: 24 }}>
            <div style={{
              fontSize: '0.6875rem', fontWeight: 600, color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 10,
            }}>
              Parsed Output
            </div>
            <div style={{
              background: 'rgba(0,0,0,0.2)', borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border)', padding: '12px 14px',
            }}>
              <ParsedOutputDetail finding={finding} />
            </div>
          </div>

          {/* Raw output toggle */}
          {finding.raw_output && (
            <div style={{ marginBottom: 20 }}>
              <button
                onClick={() => setShowRaw((v) => !v)}
                style={{
                  background: 'none', border: 'none', cursor: 'pointer',
                  color: 'var(--text-muted)', fontSize: '0.75rem', fontWeight: 600,
                  display: 'flex', alignItems: 'center', gap: 6, padding: 0, marginBottom: 8,
                }}
              >
                {showRaw ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                Raw Output
              </button>
              {showRaw && (
                <pre style={{
                  background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)', padding: '12px 14px', margin: 0,
                  fontSize: '0.75rem', fontFamily: 'monospace', whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all', color: 'var(--text-secondary)',
                  maxHeight: 300, overflowY: 'auto',
                }}>
                  {finding.raw_output}
                </pre>
              )}
            </div>
          )}

          {/* AI Analysis */}
          <div style={{ marginBottom: 20 }}>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10,
            }}>
              <div style={{
                fontSize: '0.6875rem', fontWeight: 600, color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: '0.06em',
              }}>
                AI Analysis
              </div>
              {!aiAnalysis && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <LlmProviderModelPicker
                    providers={llmPicker.providers}
                    provider={llmPicker.provider}
                    model={llmPicker.model}
                    loading={llmPicker.loading}
                    onProviderChange={llmPicker.selectProvider}
                    onModelChange={llmPicker.setModel}
                    onRefresh={llmPicker.refresh}
                    disabled={aiLoading}
                    compact
                  />
                  <button
                    onClick={runAiAnalysis}
                    disabled={aiLoading}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 5,
                      padding: '4px 10px', borderRadius: 'var(--radius-sm)',
                      background: aiLoading ? 'rgba(167,139,250,0.1)' : 'rgba(167,139,250,0.15)',
                      border: '1px solid rgba(167,139,250,0.4)',
                      color: 'var(--purple)', cursor: aiLoading ? 'not-allowed' : 'pointer',
                      fontSize: '0.75rem', fontWeight: 600,
                    }}
                  >
                    <Sparkles size={12} style={{ animation: aiLoading ? 'spin 1s linear infinite' : 'none' }} />
                    {aiLoading ? 'Analyzing…' : 'Analyze with AI'}
                  </button>
                </div>
              )}
              {aiAnalysis && (
                <button
                  onClick={() => { setAiAnalysis(null); setAiError(null); }}
                  style={{
                    background: 'none', border: 'none', color: 'var(--text-muted)',
                    cursor: 'pointer', fontSize: '0.75rem',
                  }}
                >
                  Clear
                </button>
              )}
            </div>

            {aiError && (
              <div style={{
                padding: '8px 12px', borderRadius: 'var(--radius-md)',
                background: 'rgba(248,113,113,0.1)', border: '1px solid rgba(248,113,113,0.3)',
                color: 'var(--red)', fontSize: '0.75rem',
              }}>
                {aiError}
              </div>
            )}

            {aiLoading && (
              <div style={{
                padding: '16px', borderRadius: 'var(--radius-md)', textAlign: 'center',
                background: 'rgba(167,139,250,0.05)', border: '1px solid rgba(167,139,250,0.2)',
                color: 'var(--purple)', fontSize: '0.75rem',
              }}>
                <Sparkles size={16} style={{ marginBottom: 6, display: 'block', margin: '0 auto 8px' }} />
                Asking AI to analyze this finding…
              </div>
            )}

            {aiAnalysis && (
              <div style={{
                padding: '14px 16px', borderRadius: 'var(--radius-md)',
                background: 'rgba(167,139,250,0.07)', border: '1px solid rgba(167,139,250,0.25)',
              }}>
                <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                  <Sparkles size={13} color="var(--purple)" style={{ flexShrink: 0, marginTop: 1 }} />
                  <span style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--purple)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    AI Security Analysis
                  </span>
                </div>
                <p style={{
                  margin: 0, fontSize: '0.8125rem', color: 'var(--text-secondary)',
                  whiteSpace: 'pre-wrap', lineHeight: 1.65,
                }}>
                  {aiAnalysis}
                </p>
              </div>
            )}

            {!aiAnalysis && !aiLoading && !aiError && (
              <div style={{
                padding: '12px 14px', borderRadius: 'var(--radius-md)', textAlign: 'center',
                background: 'color-mix(in srgb, var(--text-primary) 3%, transparent)', border: '1px dashed var(--border)',
                color: 'var(--text-muted)', fontSize: '0.75rem',
              }}>
                Click "Analyze with AI" for a security assessment of this finding
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div style={{ padding: '1rem 1.5rem', borderTop: '1px solid var(--border)' }}>
          <Link
            href={`/scans/${finding.scan.id}`}
            style={{
              display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center',
              padding: '0.6rem 1.25rem', borderRadius: 'var(--radius-md)',
              background: 'var(--cyan)', color: '#000',
              fontWeight: 600, fontSize: '0.875rem', textDecoration: 'none',
            }}
          >
            <ExternalLink size={14} />
            View Full Scan
          </Link>
        </div>
      </div>
    </>
  );
}

// ── Mini bar chart ───────────────────────────────────────────────────────────

function MiniBarChart({ data }: { data: { label: string; count: number; color?: string }[] }) {
  const max = Math.max(...data.map((d) => d.count), 1);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {data.map((d) => (
        <div key={d.label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            width: 90, fontSize: '0.75rem', color: 'var(--text-muted)',
            textAlign: 'right', flexShrink: 0, overflow: 'hidden',
            textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }} title={d.label}>
            {d.label}
          </span>
          <div style={{
            flex: 1, height: 8, borderRadius: 'var(--radius-sm)', background: 'color-mix(in srgb, var(--text-primary) 6%, transparent)',
            overflow: 'hidden',
          }}>
            <div style={{
              height: '100%', width: `${(d.count / max) * 100}%`,
              background: d.color || 'var(--cyan)', borderRadius: 'var(--radius-sm)',
              transition: 'width 0.4s ease',
            }} />
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', width: 28, textAlign: 'right' }}>
            {d.count}
          </span>
        </div>
      ))}
    </div>
  );
}

// ── Activity timeline ────────────────────────────────────────────────────────

function ActivityTimeline({ days }: { days: { date: string; count: number }[] }) {
  if (days.length === 0) {
    return <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: 0 }}>No activity in last 30 days</p>;
  }
  const max = Math.max(...days.map((d) => d.count), 1);
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 48 }}>
      {days.map((d) => (
        <div
          key={d.date}
          title={`${d.date}: ${d.count} finding${d.count !== 1 ? 's' : ''}`}
          style={{
            flex: 1, borderRadius: 'var(--radius-sm)',
            height: `${Math.max(10, (d.count / max) * 100)}%`,
            background: 'var(--cyan)',
            opacity: 0.5 + 0.5 * (d.count / max),
            cursor: 'default',
          }}
        />
      ))}
    </div>
  );
}

// ── Finding card ─────────────────────────────────────────────────────────────

function FindingCard({
  finding, onClick, selected, onSelect, onPromote, promoting,
}: {
  finding: Finding;
  onClick: () => void;
  selected: boolean;
  onSelect: (id: string, v: boolean) => void;
  onPromote: (finding: Finding) => void;
  promoting: boolean;
}) {
  const catColor = CATEGORY_COLORS[finding.category] || CATEGORY_COLORS.Other;
  const summary = miniSummary(finding);
  const signal = hasSecuritySignal(finding);
  const tracked = !!finding.promoted_vuln_id;

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={`${finding.tool_name} finding on ${finding.scan.target}`}
      onClick={onClick}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(); } }}
      style={{
        background: selected ? 'var(--bg-hover)' : 'var(--bg-secondary)',
        border: selected ? `1px solid ${catColor}` : '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)', padding: '14px 16px', cursor: 'pointer',
        transition: 'border-color 0.15s, transform 0.1s',
        borderLeft: `3px solid ${catColor}`,
        opacity: signal ? 1 : 0.72,  // informational findings recede so security signals stand out
      }}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLDivElement).style.borderColor = catColor;
        (e.currentTarget as HTMLDivElement).style.transform = 'translateX(2px)';
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLDivElement).style.borderColor = selected ? catColor : 'var(--border)';
        (e.currentTarget as HTMLDivElement).style.borderLeftColor = catColor;
        (e.currentTarget as HTMLDivElement).style.transform = 'translateX(0)';
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        {/* Checkbox */}
        <span
          onClick={(e) => { e.stopPropagation(); onSelect(finding.id, !selected); }}
          style={{ color: selected ? 'var(--cyan)' : 'var(--text-muted)', cursor: 'pointer', flexShrink: 0 }}
        >
          {selected ? <CheckSquare size={15} /> : <Square size={15} />}
        </span>
        {/* Signal indicator */}
        {signal
          ? <AlertTriangle size={14} style={{ color: catColor, flexShrink: 0 }} aria-label="Has a security result" />
          : <Info size={14} style={{ color: 'var(--text-muted)', flexShrink: 0 }} aria-label="Informational" />}
        <span style={{
          fontFamily: 'monospace', fontWeight: 700, fontSize: '0.875rem', color: catColor,
        }}>
          {finding.tool_name}
        </span>
        <span style={{
          padding: '1px 7px', borderRadius: 99,
          background: `color-mix(in srgb, ${catColor} 9%, transparent)`, border: `1px solid color-mix(in srgb, ${catColor} 21%, transparent)`,
          fontSize: '0.6875rem', fontWeight: 600, color: catColor,
          textTransform: 'uppercase', letterSpacing: '0.04em',
        }}>
          {finding.category}
        </span>
        <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
          {/* Promote / Tracked action — the bridge to /vulnerabilities */}
          {tracked ? (
            <a href={`/vulnerabilities/${finding.promoted_vuln_id}`} onClick={(e) => e.stopPropagation()}
              style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.6875rem', fontWeight: 600, color: 'var(--green)', background: 'color-mix(in srgb, var(--green) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--green) 30%, transparent)', borderRadius: 6, padding: '2px 8px', textDecoration: 'none' }}>
              <Check size={11} aria-hidden="true" /> Tracked
            </a>
          ) : signal ? (
            <button onClick={(e) => { e.stopPropagation(); onPromote(finding); }} disabled={promoting}
              aria-label="Promote to vulnerability"
              style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.6875rem', fontWeight: 600, color: 'var(--cyan)', background: 'transparent', border: '1px solid color-mix(in srgb, var(--cyan) 40%, transparent)', borderRadius: 6, padding: '2px 8px', cursor: promoting ? 'default' : 'pointer' }}>
              <Plus size={11} aria-hidden="true" /> Promote
            </button>
          ) : null}
          <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
            {new Date(finding.executed_at).toLocaleDateString()}
          </span>
        </span>
      </div>

      <div style={{
        fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 6,
        display: 'flex', alignItems: 'center', gap: 6,
      }}>
        <Target size={11} />
        <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
          {finding.scan.target}
        </span>
        {finding.duration_ms !== undefined && (
          <>
            <span>·</span>
            <Clock size={11} />
            <span>
              {finding.duration_ms < 1000
                ? `${finding.duration_ms}ms`
                : `${(finding.duration_ms / 1000).toFixed(1)}s`}
            </span>
          </>
        )}
      </div>

      <p style={{
        fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
      }}>
        {summary}
      </p>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function FindingsPage() {
  const [stats, setStats] = useState<FindingsStats | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [statsLoading, setStatsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedCategory, setSelectedCategory] = useState<Category>('All');
  const [targetSearch, setTargetSearch] = useState('');
  const [toolFilter, setToolFilter] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // ── Bulk selection ─────────────────────────────────────────
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [needsReviewOnly, setNeedsReviewOnly] = useState(false); // "Needs Review" triage filter
  const [promotingId, setPromotingId] = useState<string | null>(null);
  const toggleSelect = (id: string, v: boolean) =>
    setSelectedIds((prev) => { const n = new Set(prev); v ? n.add(id) : n.delete(id); return n; });
  const selectAll = () => setSelectedIds(new Set(findings.map((f) => f.id)));
  const clearSelection = () => setSelectedIds(new Set());

  // ── Live update poll ───────────────────────────────────────
  const [countdown, setCountdown] = useState(30);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [liveToast, setLiveToast] = useState<string | null>(null);
  const prevTotalRef = useRef<number>(0);
  const liveIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const countdownRef = useRef(30);

  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const loadFindingsRef = useRef<(() => void) | null>(null); // lets handlePromote trigger a reload without a dep cycle
  const PER_PAGE = 50;

  // Load stats once on mount
  useEffect(() => {
    setStatsLoading(true);
    findingsApi.stats()
      .then((res) => {
        const s = res.data as FindingsStats;
        setStats(s);
        prevTotalRef.current = s.total_findings;
        setLastUpdated(new Date());
      })
      .catch(() => setStats(null))
      .finally(() => setStatsLoading(false));
  }, []);

  // Live 30-second poll — check for new findings, refresh if total changed
  useEffect(() => {
    countdownRef.current = 30;
    setCountdown(30);
    if (liveIntervalRef.current) clearInterval(liveIntervalRef.current);

    liveIntervalRef.current = setInterval(() => {
      countdownRef.current -= 1;
      setCountdown(countdownRef.current);

      if (countdownRef.current <= 0) {
        countdownRef.current = 30;
        setCountdown(30);
        // Silent stats check
        findingsApi.stats()
          .then((res) => {
            const s = res.data as FindingsStats;
            const newTotal = s.total_findings;
            setStats(s);
            setLastUpdated(new Date());
            if (newTotal > prevTotalRef.current) {
              const diff = newTotal - prevTotalRef.current;
              setLiveToast(`${diff} new finding${diff !== 1 ? 's' : ''} loaded`);
              setTimeout(() => setLiveToast(null), 4000);
              // Reload findings list if on page 1 (so new ones appear at top)
              if (page === 1) {
                loadFindings(1, selectedCategory, targetSearch, toolFilter, dateFrom, dateTo);
              }
            }
            prevTotalRef.current = newTotal;
          })
          .catch(() => {});
      }
    }, 1000);

    return () => { if (liveIntervalRef.current) clearInterval(liveIntervalRef.current); };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Load findings on filter change (debounced for target search)
  // Promote a finding to a tracked vulnerability — the bridge to /vulnerabilities. Reloads so the row flips to
  // "Tracked" and the vulnerability becomes available on that page.
  const handlePromote = useCallback(async (finding: Finding) => {
    setPromotingId(finding.id);
    try {
      const res = await findingsApi.promote(finding.id);
      notify(res.data.already_promoted ? 'Already tracked as a vulnerability' : `Promoted to vulnerability: ${res.data.vuln_name}`, 'success');
      loadFindingsRef.current?.();
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.message || 'Unknown error';
      notify(`Promote failed: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`, 'error');
    } finally {
      setPromotingId(null);
    }
  }, []);

  const loadFindings = useCallback((pageNum: number, category: Category, target: string, tool: string, from: string, to: string) => {
    setLoading(true);
    setError(null);
    findingsApi.list({
      category: category !== 'All' ? category : undefined,
      target: target || undefined,
      tool_name: tool || undefined,
      date_from: from || undefined,
      date_to: to || undefined,
      page: pageNum,
      per_page: PER_PAGE,
    })
      .then((res) => {
        const data = res.data as { findings: Finding[]; total: number };
        setFindings(data.findings);
        setTotal(data.total);
        setLastUpdated(new Date());
        // Reset countdown on manual load
        countdownRef.current = 30;
        setCountdown(30);
      })
      .catch(() => setError('Failed to load findings'))
      .finally(() => setLoading(false));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setPage(1);
      loadFindings(1, selectedCategory, targetSearch, toolFilter, dateFrom, dateTo);
    }, targetSearch ? 400 : 0);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [selectedCategory, targetSearch, toolFilter, dateFrom, dateTo, loadFindings]);

  useEffect(() => {
    loadFindings(page, selectedCategory, targetSearch, toolFilter, dateFrom, dateTo);
  }, [page]); // eslint-disable-line react-hooks/exhaustive-deps

  // Keep the reload ref pointing at a loader bound to the current filters, so handlePromote can refresh after a promote.
  useEffect(() => {
    loadFindingsRef.current = () => loadFindings(page, selectedCategory, targetSearch, toolFilter, dateFrom, dateTo);
  }, [page, selectedCategory, targetSearch, toolFilter, dateFrom, dateTo, loadFindings]);

  // Export CSV — selected items if any, otherwise all loaded
  const exportCsv = (ids?: Set<string>) => {
    const source = ids && ids.size > 0 ? findings.filter((f) => ids.has(f.id)) : findings;
    const header = 'id,tool_name,category,target,executed_at,duration_ms,exit_code,summary';
    const rows = source.map((f) => [
      f.id, f.tool_name, f.category, f.scan.target,
      f.executed_at, f.duration_ms ?? '', f.exit_code ?? '',
      `"${miniSummary(f).replace(/"/g, '""')}"`,
    ].join(','));
    const csv = [header, ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = ids && ids.size > 0 ? `findings-selected-${ids.size}.csv` : 'findings.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  const totalPages = Math.ceil(total / PER_PAGE);
  const catBarData = (stats?.by_category ?? []).map((c) => ({
    label: c.category,
    count: c.count,
    color: CATEGORY_COLORS[c.category],
  }));

  return (
    <div style={{ padding: '2rem', width: '100%' }}>
      {/* ── Live toast ── */}
      {liveToast && (
        <div style={{
          position: 'fixed', top: 20, right: 20, zIndex: 2000,
          padding: '10px 18px', borderRadius: 'var(--radius-lg)',
          background: 'rgba(0,200,220,0.15)', border: '1px solid rgba(0,200,220,0.4)',
          color: 'var(--cyan)', fontWeight: 600, fontSize: '0.8125rem',
          display: 'flex', alignItems: 'center', gap: 8,
          boxShadow: '0 4px 20px rgba(0,0,0,0.4)',
          animation: 'slideIn 0.3s ease',
        }}>
          <Radio size={13} />
          {liveToast}
        </div>
      )}

      {/* ── Header ── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16, marginBottom: 28 }}>
        <div style={{
          width: 44, height: 44, borderRadius: 'var(--radius-lg)', flexShrink: 0,
          background: 'rgba(0,200,220,0.1)', border: '1px solid rgba(0,200,220,0.25)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Layers size={20} color="var(--cyan)" />
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 3 }}>
            <h1 style={{ margin: 0, color: 'var(--text-primary)' }}>
              Findings Intelligence
            </h1>
            {/* Live indicator */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '2px 8px', borderRadius: 99,
              background: 'rgba(74,222,128,0.1)', border: '1px solid rgba(74,222,128,0.3)',
              fontSize: '0.6875rem', fontWeight: 600, color: 'var(--green)',
            }}>
              <span style={{
                width: 6, height: 6, borderRadius: '50%', background: 'var(--chart-green)',
                animation: 'pulse 2s ease-in-out infinite',
              }} />
              LIVE · {countdown}s
            </div>
            {lastUpdated && (
              <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                Updated {lastUpdated.toLocaleTimeString()}
              </span>
            )}
          </div>
          <p style={{ margin: 0, fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
            All tool results across scans — ports, paths, DNS, SSL, OSINT, and more
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => exportCsv()}
            disabled={findings.length === 0}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '0.5rem 1rem', borderRadius: 'var(--radius-md)',
              background: 'color-mix(in srgb, var(--text-primary) 5%, transparent)', border: '1px solid var(--border)',
              color: 'var(--text-secondary)', cursor: findings.length === 0 ? 'not-allowed' : 'pointer',
              fontSize: '0.8125rem', fontWeight: 600, opacity: findings.length === 0 ? 0.5 : 1,
            }}
          >
            <Download size={14} />
            Export CSV
          </button>
          <button
            onClick={() => loadFindings(page, selectedCategory, targetSearch, toolFilter, dateFrom, dateTo)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '0.5rem 1rem', borderRadius: 'var(--radius-md)',
              background: 'color-mix(in srgb, var(--text-primary) 5%, transparent)', border: '1px solid var(--border)',
              color: 'var(--text-secondary)', cursor: 'pointer',
              fontSize: '0.8125rem', fontWeight: 600,
            }}
          >
            <RefreshCw size={14} />
            Refresh
          </button>
        </div>
      </div>

      {/* ── Stats Cards ── */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 28,
      }}>
        {[
          { label: 'Total Findings', value: statsLoading ? '…' : (stats?.total_findings ?? 0).toLocaleString(), icon: Layers, color: 'var(--cyan)' },
          { label: 'Scans Analyzed', value: statsLoading ? '…' : (stats?.unique_scans ?? 0).toLocaleString(), icon: Search, color: 'var(--purple)' },
          { label: 'Unique Targets', value: statsLoading ? '…' : (stats?.unique_targets ?? 0).toLocaleString(), icon: Target, color: 'var(--orange)' },
          { label: 'Tools Executed', value: statsLoading ? '…' : (stats?.unique_tools ?? 0).toLocaleString(), icon: Terminal, color: 'var(--green)' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} style={{
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-lg)', padding: '18px 20px',
            display: 'flex', alignItems: 'center', gap: 14,
          }}>
            <div style={{
              width: 40, height: 40, borderRadius: 'var(--radius-lg)', flexShrink: 0,
              background: `color-mix(in srgb, ${color} 9%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 21%, transparent)`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Icon size={18} color={color} />
            </div>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                {value}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 3 }}>
                {label}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* ── Category Tabs + Needs-Review triage toggle ── */}
      <div style={{
        display: 'flex', gap: 6, overflowX: 'auto', marginBottom: 20,
        paddingBottom: 4, scrollbarWidth: 'none', alignItems: 'center',
      }}>
        <button
          onClick={() => setNeedsReviewOnly(v => !v)}
          aria-pressed={needsReviewOnly}
          style={{
            display: 'flex', alignItems: 'center', gap: 5, padding: '5px 12px', borderRadius: 99,
            fontSize: '0.75rem', fontWeight: 600, whiteSpace: 'nowrap', cursor: 'pointer',
            border: `1px solid ${needsReviewOnly ? 'var(--red)' : 'color-mix(in srgb, var(--red) 30%, transparent)'}`,
            background: needsReviewOnly ? 'color-mix(in srgb, var(--red) 15%, transparent)' : 'transparent',
            color: 'var(--red)',
          }}
          title="Show only findings with a real security result that aren't tracked yet"
        >
          <Flag size={13} aria-hidden="true" /> Needs review
        </button>
        <span style={{ width: 1, height: 20, background: 'var(--border)', flexShrink: 0 }} />
        {CATEGORIES.map((cat) => {
          const active = selectedCategory === cat;
          const color = cat === 'All' ? 'var(--cyan)' : (CATEGORY_COLORS[cat] || 'var(--text-muted)');
          const catCount = cat === 'All'
            ? (stats?.total_findings ?? 0)
            : (stats?.by_category.find((c) => c.category === cat)?.count ?? 0);
          return (
            <button
              key={cat}
              onClick={() => { setSelectedCategory(cat); setPage(1); }}
              style={{
                padding: '7px 14px', borderRadius: 'var(--radius-md)', cursor: 'pointer',
                border: active ? `1px solid ${color}` : '1px solid var(--border)',
                background: active ? `color-mix(in srgb, ${color} 8%, transparent)` : 'var(--bg-secondary)',
                color: active ? color : 'var(--text-muted)',
                fontSize: '0.8125rem', fontWeight: 600, whiteSpace: 'nowrap',
                transition: 'all 0.15s',
                display: 'flex', alignItems: 'center', gap: 6,
              }}
            >
              {cat}
              {catCount > 0 && (
                <span style={{
                  padding: '1px 6px', borderRadius: 99,
                  background: active ? `color-mix(in srgb, ${color} 15%, transparent)` : 'color-mix(in srgb, var(--text-primary) 6%, transparent)',
                  fontSize: '0.6875rem', fontWeight: 700,
                  color: active ? color : 'var(--text-muted)',
                }}>
                  {catCount.toLocaleString()}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* ── Toolbar ── */}
      <div style={{
        display: 'flex', gap: 10, marginBottom: 20, flexWrap: 'wrap',
      }}>
        {/* Target search */}
        <div style={{ position: 'relative', flex: '1 1 220px', minWidth: 180 }}>
          <Search size={13} style={{
            position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)',
            color: 'var(--text-muted)', pointerEvents: 'none',
          }} />
          <input
            type="text"
            placeholder="Search target…"
            value={targetSearch}
            onChange={(e) => setTargetSearch(e.target.value)}
            style={{
              width: '100%', padding: '8px 10px 8px 30px', borderRadius: 'var(--radius-md)',
              background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', fontSize: '0.8125rem', outline: 'none',
              boxSizing: 'border-box',
            }}
          />
        </div>

        {/* Tool dropdown */}
        <select
          value={toolFilter}
          onChange={(e) => { setToolFilter(e.target.value); setPage(1); }}
          style={{
            padding: '8px 12px', borderRadius: 'var(--radius-md)',
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            color: toolFilter ? 'var(--text-primary)' : 'var(--text-muted)',
            fontSize: '0.8125rem', cursor: 'pointer', outline: 'none',
            minWidth: 160,
          }}
        >
          <option value="">All Tools</option>
          {(stats?.by_tool ?? []).map((t) => (
            <option key={t.tool_name} value={t.tool_name}>
              {t.tool_name} ({t.count})
            </option>
          ))}
        </select>

        {/* Date from */}
        <input
          type="date"
          value={dateFrom}
          onChange={(e) => { setDateFrom(e.target.value); setPage(1); }}
          style={{
            padding: '8px 10px', borderRadius: 'var(--radius-md)',
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            color: dateFrom ? 'var(--text-primary)' : 'var(--text-muted)',
            fontSize: '0.8125rem', outline: 'none',
          }}
        />
        <input
          type="date"
          value={dateTo}
          onChange={(e) => { setDateTo(e.target.value); setPage(1); }}
          style={{
            padding: '8px 10px', borderRadius: 'var(--radius-md)',
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            color: dateTo ? 'var(--text-primary)' : 'var(--text-muted)',
            fontSize: '0.8125rem', outline: 'none',
          }}
        />

        {/* Clear filters */}
        {(targetSearch || toolFilter || dateFrom || dateTo || selectedCategory !== 'All') && (
          <button
            onClick={() => {
              setTargetSearch(''); setToolFilter('');
              setDateFrom(''); setDateTo('');
              setSelectedCategory('All'); setPage(1);
            }}
            style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '8px 12px', borderRadius: 'var(--radius-md)',
              background: 'rgba(248,113,113,0.1)', border: '1px solid rgba(248,113,113,0.3)',
              color: 'var(--red)', cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 600,
            }}
          >
            <X size={13} /> Clear
          </button>
        )}
      </div>

      {/* ── Main two-column layout ── */}
      <div style={{ display: 'flex', gap: 20, alignItems: 'flex-start' }}>
        {/* Left — Findings list */}
        <div style={{ flex: '1 1 0', minWidth: 0 }}>
          {/* Count row */}
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            marginBottom: 12,
          }}>
            <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
              {loading ? 'Loading…' : `${total.toLocaleString()} finding${total !== 1 ? 's' : ''}`}
              {total > PER_PAGE && ` · page ${page} of ${totalPages}`}
            </span>
            {findings.length > 0 && (
              <button
                onClick={() => selectedIds.size === findings.length ? clearSelection() : selectAll()}
                style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  padding: '4px 10px', borderRadius: 'var(--radius-md)',
                  background: 'color-mix(in srgb, var(--text-primary) 5%, transparent)', border: '1px solid var(--border)',
                  color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.75rem',
                }}
              >
                {selectedIds.size === findings.length
                  ? <CheckSquare size={12} style={{ color: 'var(--cyan)' }} />
                  : <Square size={12} />}
                {selectedIds.size > 0 ? `${selectedIds.size} selected` : 'Select All'}
              </button>
            )}
          </div>

          {/* Error */}
          {error && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '12px 16px', borderRadius: 'var(--radius-md)',
              background: 'rgba(248,113,113,0.1)', border: '1px solid rgba(248,113,113,0.3)',
              color: 'var(--red)', fontSize: '0.8125rem', marginBottom: 12,
            }}>
              <AlertCircle size={15} />
              {error}
            </div>
          )}

          {/* Cards */}
          {!loading && findings.length === 0 && !error && (
            <div style={{
              padding: '3rem 2rem', textAlign: 'center',
              background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius-lg)', color: 'var(--text-muted)',
            }}>
              <Layers size={36} style={{ marginBottom: 12, opacity: 0.3 }} />
              <p style={{ margin: 0, fontSize: '0.875rem' }}>No findings match the current filters</p>
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {(needsReviewOnly ? findings.filter(needsReview) : findings).map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                onClick={() => setSelectedFinding(f)}
                selected={selectedIds.has(f.id)}
                onSelect={toggleSelect}
                onPromote={handlePromote}
                promoting={promotingId === f.id}
              />
            ))}
            {needsReviewOnly && findings.filter(needsReview).length === 0 && (
              <div style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                Nothing needs review on this page — all security findings are tracked.
              </div>
            )}
          </div>

          {/* Loading skeleton */}
          {loading && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} style={{
                  height: 78, borderRadius: 'var(--radius-lg)',
                  background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                  animation: 'pulse 1.5s ease-in-out infinite',
                }} />
              ))}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              gap: 6, marginTop: 20,
            }}>
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                style={{
                  padding: '6px 14px', borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                  color: page <= 1 ? 'var(--text-muted)' : 'var(--text-primary)',
                  cursor: page <= 1 ? 'not-allowed' : 'pointer', fontSize: '0.8125rem',
                }}
              >
                ← Prev
              </button>
              {Array.from({ length: Math.min(7, totalPages) }).map((_, i) => {
                let pg: number;
                if (totalPages <= 7) {
                  pg = i + 1;
                } else if (page <= 4) {
                  pg = i + 1;
                } else if (page >= totalPages - 3) {
                  pg = totalPages - 6 + i;
                } else {
                  pg = page - 3 + i;
                }
                return (
                  <button
                    key={pg}
                    onClick={() => setPage(pg)}
                    style={{
                      width: 32, height: 32, borderRadius: 'var(--radius-md)',
                      background: pg === page ? 'var(--cyan)' : 'var(--bg-secondary)',
                      border: `1px solid ${pg === page ? 'var(--cyan)' : 'var(--border)'}`,
                      color: pg === page ? '#000' : 'var(--text-secondary)',
                      cursor: 'pointer', fontSize: '0.8125rem', fontWeight: pg === page ? 700 : 400,
                    }}
                  >
                    {pg}
                  </button>
                );
              })}
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                style={{
                  padding: '6px 14px', borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                  color: page >= totalPages ? 'var(--text-muted)' : 'var(--text-primary)',
                  cursor: page >= totalPages ? 'not-allowed' : 'pointer', fontSize: '0.8125rem',
                }}
              >
                Next →
              </button>
            </div>
          )}
        </div>

        {/* Right — Stats sidebar */}
        <div style={{ width: 340, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* By category */}
          <div style={{
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-lg)', padding: '16px 18px',
          }}>
            <div style={{
              fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 14,
            }}>
              By Category
            </div>
            {statsLoading
              ? <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: 0 }}>Loading…</p>
              : <MiniBarChart data={catBarData} />}
          </div>

          {/* By tool */}
          {stats && stats.by_tool.length > 0 && (
            <div style={{
              background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius-lg)', padding: '16px 18px',
            }}>
              <div style={{
                fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 14,
              }}>
                By Tool
              </div>
              <MiniBarChart data={stats.by_tool.slice(0, 10).map((t) => ({
                label: t.tool_name,
                count: t.count,
                color: CATEGORY_COLORS[t.category],
              }))} />
            </div>
          )}

          {/* Top targets */}
          {stats && stats.top_targets.length > 0 && (
            <div style={{
              background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius-lg)', padding: '16px 18px',
            }}>
              <div style={{
                fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 12,
              }}>
                Top Targets
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {stats.top_targets.map((t, i) => (
                  <div key={t.target} style={{
                    display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.75rem',
                  }}>
                    <span style={{
                      width: 18, height: 18, borderRadius: '50%',
                      background: 'color-mix(in srgb, var(--text-primary) 6%, transparent)', border: '1px solid var(--border)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)',
                      flexShrink: 0,
                    }}>
                      {i + 1}
                    </span>
                    <span style={{
                      flex: 1, color: 'var(--text-secondary)', fontFamily: 'monospace',
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }} title={t.target}>
                      {t.target}
                    </span>
                    <span style={{
                      padding: '1px 6px', borderRadius: 99,
                      background: 'rgba(0,200,220,0.1)', border: '1px solid rgba(0,200,220,0.2)',
                      fontSize: '0.6875rem', fontWeight: 600, color: 'var(--cyan)',
                    }}>
                      {t.count}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 30-day activity */}
          <div style={{
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-lg)', padding: '16px 18px',
          }}>
            <div style={{
              fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 12,
            }}>
              Activity — Last 30 Days
            </div>
            {statsLoading
              ? <div style={{ height: 48, borderRadius: 'var(--radius-sm)', background: 'color-mix(in srgb, var(--text-primary) 4%, transparent)' }} />
              : <ActivityTimeline days={stats?.recent_days ?? []} />}
          </div>
        </div>
      </div>

      {/* ── Detail drawer ── */}
      {selectedFinding && (
        <FindingDrawer
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}

      {/* ── Floating bulk action bar ── */}
      {selectedIds.size > 0 && (
        <div style={{
          position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)',
          zIndex: 500, display: 'flex', alignItems: 'center', gap: 12,
          padding: '10px 20px', borderRadius: 'var(--radius-lg)',
          background: 'var(--bg-card)', border: '1px solid color-mix(in srgb, var(--cyan) 35%, transparent)',
          boxShadow: 'var(--shadow-pop)',
          backdropFilter: 'blur(12px)',
        }}>
          <span style={{
            fontFamily: 'monospace', fontWeight: 700, fontSize: '0.8125rem', color: 'var(--cyan)',
          }}>
            {selectedIds.size} finding{selectedIds.size !== 1 ? 's' : ''} selected
          </span>
          <div style={{ width: 1, height: 18, background: 'var(--border)' }} />
          <button
            onClick={() => exportCsv(selectedIds)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '6px 14px', borderRadius: 'var(--radius-md)',
              background: 'rgba(0,200,220,0.15)', border: '1px solid rgba(0,200,220,0.4)',
              color: 'var(--cyan)', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600,
            }}
          >
            <Download size={13} />
            Export Selected CSV
          </button>
          <button
            onClick={clearSelection}
            style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '6px 12px', borderRadius: 'var(--radius-md)',
              background: 'color-mix(in srgb, var(--text-primary) 5%, transparent)', border: '1px solid var(--border)',
              color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.75rem',
            }}
          >
            <X size={12} /> Clear
          </button>
        </div>
      )}
    </div>
  );
}
