'use client';
import { useState, useEffect, useRef, useCallback } from 'react';
import { useParams } from 'next/navigation';
import { 
  ShieldAlert, Brain, AlertTriangle, CheckCircle, 
  Clock, RefreshCw, FileText, Download, Loader2, Zap, Activity,
  Shield, Target, Wifi, Lock, Code, Database, Globe, Server,
  Eye, EyeOff,
} from 'lucide-react';
import { scansApi, reportsApi, llmApi } from '@/lib/api';
import { prettyToolOutput } from '@/lib/prettyToolOutput';
import type { Scan, Vulnerability } from '@/lib/types';
import MetasploitTerminal from '@/components/MetasploitTerminal';
import { notify } from '@/lib/dialogs';

function extractMetasploitSessionId(output?: string): number | null {
  if (!output || typeof output !== 'string') return null;
  try {
    const parsed = JSON.parse(output);
    if (typeof parsed?.session_id === 'number') return parsed.session_id;
    if (parsed?.interactive_handoff && parsed?.session_id) {
      const sid = parseInt(String(parsed.session_id), 10);
      return Number.isFinite(sid) ? sid : null;
    }
  } catch {
    return null;
  }
  return null;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--amber)', low: 'var(--green)', info: 'var(--blue)',
};

// ── Tool metadata ─────────────────────────────────────────────────────────────
const TOOL_META: Record<string, { label: string; description: string; category: string }> = {
  nmap:        { label: 'Nmap',          description: 'TCP/UDP port scan · service & version detection',        category: 'Discovery'    },
  nuclei:      { label: 'Nuclei',        description: 'Template-based CVE scanner (9000+ templates)',           category: 'Vulnerability'},
  cve:         { label: 'CVE Database',  description: 'NVD lookup for known Common Vulnerabilities',            category: 'Intelligence' },
  metasploit:  { label: 'Metasploit',    description: 'Exploit framework — auxiliary & exploit modules',        category: 'Exploitation' },
  sqlmap:      { label: 'SQLMap',        description: 'Automated SQL injection detection & exploitation',       category: 'Web'          },
  ffuf:        { label: 'FFUF',          description: 'Fast web fuzzer — directory & endpoint discovery',       category: 'Web'          },
  waf:         { label: 'WAF Detection', description: 'Web Application Firewall fingerprinting & bypass',      category: 'Discovery'    },
  ssl:         { label: 'SSL/TLS Audit', description: 'Certificate analysis · weak cipher & protocol checks',  category: 'Crypto'       },
  osint:       { label: 'OSINT',         description: 'WHOIS · DNS · geolocation · HTTP header analysis',      category: 'Recon'        },
  cisa_kev:    { label: 'CISA KEV',      description: 'Known Exploited Vulnerabilities catalog lookup',         category: 'Intelligence' },
  epss:        { label: 'EPSS',          description: 'Exploit Prediction Scoring System probability score',   category: 'Intelligence' },
  poc_index:   { label: 'PoC Index',     description: 'Public proof-of-concept & ExploitDB availability',      category: 'Intelligence' },
  whois:       { label: 'WHOIS',         description: 'Domain registration · registrar · ownership data',      category: 'Recon'        },
  whatweb:     { label: 'WhatWeb',       description: 'Web technology fingerprinting & CMS detection',         category: 'Discovery'    },
  curl_headers:{ label: 'HTTP Headers',  description: 'HTTP security header audit & misconfiguration check',   category: 'Web'          },
  dig:         { label: 'DNS Lookup',    description: 'DNS record enumeration — A, MX, NS, TXT, CNAME',        category: 'Recon'        },
  nikto:       { label: 'Nikto',         description: 'Web server scan for dangerous files & outdated software',category: 'Web'          },
  subfinder:   { label: 'Subfinder',     description: 'Passive subdomain enumeration via multiple APIs',        category: 'Recon'        },
  testssl:     { label: 'TestSSL',       description: 'SSL/TLS implementation & ciphersuite analysis',         category: 'Crypto'       },
  cve_lite:    { label: 'CVE Lite',      description: 'OWASP JS/TS dependency vuln scanner — OSV advisory data', category: 'Code'         },
  masscan:     { label: 'Masscan',       description: 'Massively fast TCP port scanner',                        category: 'Discovery'    },
  wpscan:      { label: 'WPScan',        description: 'WordPress vulnerability scanner',                        category: 'Web'          },
  jwt:         { label: 'JWT Analyzer',  description: 'JWT decode, forge & weakness testing',                  category: 'Web'          },
  gobuster:    { label: 'Gobuster',      description: 'Directory, DNS and vhost brute-force',                  category: 'Web'          },
};

const CATEGORY_COLORS: Record<string, string> = {
  Discovery:     'var(--blue)',
  Vulnerability: 'var(--orange)',
  Intelligence:  'var(--purple)',
  Exploitation:  'var(--red)',
  Web:           'var(--green)',
  Recon:         'var(--cyan)',
  Crypto:        'var(--amber)',
  Code:          'var(--pink)',
  Infrastructure:'var(--purple)',
};

const CATEGORY_ICON: Record<string, React.ReactNode> = {
  Discovery:     <Wifi size={11} />,
  Vulnerability: <Target size={11} />,
  Intelligence:  <Database size={11} />,
  Exploitation:  <Zap size={11} />,
  Web:           <Globe size={11} />,
  Recon:         <Activity size={11} />,
  Crypto:        <Lock size={11} />,
  Code:          <Code size={11} />,
  Infrastructure:<Server size={11} />,
};

// ── Internal state types ──────────────────────────────────────────────────────
interface ToolState {
  name: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'skipped';
  startedAt?: number;   // ms timestamp
  durationMs?: number;
  triage?: string;
  exitCode?: number;
  progress?: number;    // 0-100 estimated progress
}

interface WorkflowStepProgress {
  step_id: number | string;
  step_name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  tools: string[];
  reason?: string;
  failed_tools?: string[];
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtDuration(ms: number) {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const m = Math.floor(ms / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  return `${m}m ${s}s`;
}

function fmtElapsed(startMs: number, nowMs: number) {
  const diff = Math.max(0, nowMs - startMs);
  return fmtDuration(diff);
}

/** Extract the TRIAGE severity word from an AI triage string */
function triageSeverity(triage?: string): string | null {
  if (!triage) return null;
  const m = triage.match(/TRIAGE:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO|UNKNOWN)/i);
  return m ? m[1].toUpperCase() : null;
}

function triageColor(sev: string | null) {
  if (!sev) return 'var(--text-secondary)';
  return SEVERITY_COLORS[sev.toLowerCase()] || 'var(--text-secondary)';
}

function normalizeSeverity(input: unknown): string {
  const raw = String(input ?? '').toLowerCase();
  if (raw === 'critical' || raw === 'high' || raw === 'medium' || raw === 'low' || raw === 'info') {
    return raw;
  }
  if (raw === 'informational') return 'info';
  return 'low';
}

// Format a single port object into a readable line
function ToolRow({ tool, now }: { tool: ToolState; now: number }) {
  const meta = TOOL_META[tool.name] || { label: tool.name, description: 'Security testing tool', category: 'Discovery' };
  const catColor = CATEGORY_COLORS[meta.category] || 'var(--text-secondary)';
  const sev = triageSeverity(tool.triage);
  const sevColor = triageColor(sev);

  const statusBg =
    tool.status === 'running'   ? 'rgba(6,182,212,0.06)'  :
    tool.status === 'completed' ? 'rgba(34,197,94,0.06)'  :
    tool.status === 'failed'    ? 'rgba(239,68,68,0.06)'  :
    tool.status === 'skipped'   ? 'rgba(245,158,11,0.06)' :
                                  'rgba(148,163,184,0.04)';
  const statusBorder =
    tool.status === 'running'   ? 'rgba(6,182,212,0.25)'  :
    tool.status === 'completed' ? 'rgba(34,197,94,0.25)'  :
    tool.status === 'failed'    ? 'rgba(239,68,68,0.25)'  :
    tool.status === 'skipped'   ? 'rgba(245,158,11,0.25)' :
                                  'rgba(148,163,184,0.1)';

  const barColor =
    tool.status === 'completed' ? 'var(--green)' :
    tool.status === 'failed'    ? 'var(--red)' :
    tool.status === 'running'   ? 'var(--cyan)' :
    tool.status === 'skipped'   ? 'var(--amber)' : 'transparent';

  // Running with no progress events yet → show 5% so bar is visually "started"
  const pct = tool.status === 'completed' || tool.status === 'failed' ? 100
    : tool.status === 'running' ? (tool.progress ?? 5)
    : 0;
  const barWidth = `${pct}%`;

  const elapsed = tool.startedAt
    ? (tool.durationMs != null ? fmtDuration(tool.durationMs) : fmtElapsed(tool.startedAt, now))
    : tool.durationMs != null ? fmtDuration(tool.durationMs) : null;

  return (
    <div style={{
      background: statusBg,
      border: `1px solid ${statusBorder}`,
      borderRadius: 'var(--radius-lg)',
      padding: '0.75rem 1rem',
      display: 'flex',
      flexDirection: 'column',
      gap: '0.5rem',
    }}>
      {/* Row header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
        {/* Status icon */}
        <div style={{ flexShrink: 0, width: 20 }}>
          {tool.status === 'running'   && <Loader2 size={15} color="var(--cyan)" className="animate-spin" />}
          {tool.status === 'completed' && <CheckCircle size={15} color="var(--green)" />}
          {tool.status === 'failed'    && <AlertTriangle size={15} color="var(--red)" />}
          {tool.status === 'skipped'   && <span style={{ fontSize: '0.8125rem', color: 'var(--amber)' }}>—</span>}
          {tool.status === 'queued'    && <Clock size={14} color="var(--text-muted)" />}
        </div>

        {/* Tool name & description */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.8125rem', color: 'var(--text-primary)' }}>
              {meta.label}
            </span>
            {/* Category badge */}
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 3,
              fontSize: '0.6875rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em',
              color: catColor, background: `color-mix(in srgb, ${catColor} 9%, transparent)`, border: `1px solid color-mix(in srgb, ${catColor} 21%, transparent)`,
              borderRadius: 'var(--radius-sm)', padding: '1px 5px',
            }}>
              {CATEGORY_ICON[meta.category]} {meta.category}
            </span>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 1 }}>
            {meta.description}
          </div>
        </div>

        {/* Right: status + timer */}
        <div style={{ flexShrink: 0, display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 2 }}>
          <span style={{
            fontSize: '0.6875rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em',
            color: tool.status === 'running'   ? 'var(--cyan)' :
                   tool.status === 'completed' ? 'var(--green)' :
                   tool.status === 'failed'    ? 'var(--red)' :
                   tool.status === 'skipped'   ? 'var(--amber)' : 'var(--text-muted)',
            display: 'flex', alignItems: 'center', gap: 4,
          }}>
            {tool.status === 'running' && (
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--cyan)', display: 'inline-block', animation: 'pulse 1.5s ease-in-out infinite' }} />
            )}
            {tool.status}
          </span>
          {tool.status === 'running' && tool.progress != null && (
            <span style={{ fontSize: '0.6875rem', color: 'var(--cyan)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
              {tool.progress}%
            </span>
          )}
          {elapsed && (
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {elapsed}
            </span>
          )}
        </div>
      </div>

      {/* Progress bar */}
      <div style={{
        height: 4, borderRadius: 'var(--radius-sm)', overflow: 'hidden',
        background: 'rgba(148,163,184,0.12)',
        position: 'relative',
      }}>
        <div style={{
          position: 'absolute', top: 0, left: 0, height: '100%',
          width: barWidth,
          borderRadius: 'var(--radius-sm)',
          background: tool.status === 'running'
            ? (tool.progress != null
                ? `linear-gradient(90deg, var(--cyan) 0%, var(--chart-purple) 100%)`
                : 'linear-gradient(90deg, var(--cyan), var(--chart-purple), var(--cyan))')
            : barColor,
          backgroundSize: tool.status === 'running' && tool.progress == null ? '200% 100%' : undefined,
          animation: tool.status === 'running' && tool.progress == null ? 'shimmer 1.8s linear infinite' : undefined,
          transition: 'width 0.4s ease',
        }} />
      </div>

      {/* AI triage */}
      {tool.triage && (
        <div style={{
          fontSize: '0.75rem',
          color: 'var(--text-secondary)',
          display: 'flex', alignItems: 'flex-start', gap: 6,
          borderTop: '1px solid rgba(148,163,184,0.1)', paddingTop: 6,
        }}>
          <Brain size={11} color={sevColor} style={{ marginTop: 1, flexShrink: 0 }} />
          <span>
            {sev && <strong style={{ color: sevColor, marginRight: 4 }}>[{sev}]</strong>}
            {tool.triage.replace(/TRIAGE:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO|UNKNOWN)\s*[-–—]\s*/i, '')}
          </span>
        </div>
      )}
    </div>
  );
}

// ── Enterprise Execution Panel ────────────────────────────────────────────────
function ExecutionPanel({
  scan, tools, workflowSteps, wsConnected, now,
}: {
  scan: Scan;
  tools: ToolState[];
  workflowSteps: WorkflowStepProgress[];
  wsConnected: boolean;
  now: number;
}) {
  const isActive = !['completed', 'failed', 'cancelled'].includes(scan.status);
  const total     = tools.length;
  const done      = tools.filter(t => t.status === 'completed' || t.status === 'failed' || t.status === 'skipped').length;
  const running   = tools.filter(t => t.status === 'running').length;
  const failed    = tools.filter(t => t.status === 'failed').length;
  const pct       = total > 0 ? Math.round((done / total) * 100) : 0;

  const isWorkflow  = scan.scan_type === 'workflow';
  const hasSteps    = isWorkflow && workflowSteps.length > 0;

  // Current running phase (for phase indicator)
  // Prefer a live 'running' step from WS; fall back to last completed; for active scans
  // with only pending steps (WS not yet received), default to step 1 so the badge is
  // always visible while the scan is underway.
  const liveRunningStep = hasSteps ? workflowSteps.find(s => s.status === 'running') : null;
  const liveLastDoneStep = hasSteps ? workflowSteps.filter(s => s.status === 'completed').at(-1) : null;
  const currentStep = liveRunningStep ?? liveLastDoneStep ?? (hasSteps && isActive ? workflowSteps[0] : null);
  const totalSteps  = workflowSteps.length;
  const currentStepIdx = currentStep ? workflowSteps.indexOf(currentStep) + 1 : 0;

  // Elapsed since scan started
  const scanElapsed = scan.started_at
    ? (scan.completed_at
        ? fmtDuration(new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime())
        : fmtElapsed(new Date(scan.started_at).getTime(), now))
    : null;

  if (total === 0) return null;

  return (
    <div className="card" style={{ marginBottom: '1.5rem', padding: 0, overflow: 'hidden' }}>
      {/* ── Header ── */}
      <div style={{
        padding: '1rem 1.25rem',
        background: 'linear-gradient(135deg, rgba(6,182,212,0.06) 0%, rgba(124,58,237,0.06) 100%)',
        borderBottom: '1px solid var(--border)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: '0.75rem' }}>
          <Shield size={16} color="var(--cyan)" />
          <span style={{ fontWeight: 700, fontSize: '0.875rem', color: 'var(--text-primary)' }}>
            Pentest Execution
          </span>
          {wsConnected && isActive && (
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.75rem', color: 'var(--green)', marginLeft: 4 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--chart-green)', display: 'inline-block' }} />
              Live
            </span>
          )}
          {/* Phase indicator */}
          {hasSteps && currentStep && (
            <span style={{
              marginLeft: 8, fontSize: '0.6875rem', fontWeight: 700,
              color: 'var(--cyan)', background: 'rgba(6,182,212,0.1)',
              border: '1px solid rgba(6,182,212,0.3)', borderRadius: 'var(--radius-sm)',
              padding: '2px 8px', display: 'flex', alignItems: 'center', gap: 5,
            }}>
              Phase {currentStepIdx}/{totalSteps}: {currentStep.step_name}
            </span>
          )}
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 16 }}>
            {scanElapsed && (
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 5 }}>
                <Clock size={12} /> {scanElapsed}
              </span>
            )}
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              <span style={{ color: 'var(--green)', fontWeight: 700 }}>{done}</span>
              <span style={{ color: 'var(--text-muted)' }}>/{total} tools</span>
            </span>
            {running > 0 && (
              <span style={{ fontSize: '0.75rem', color: 'var(--cyan)', fontWeight: 600 }}>
                {running} ACTIVE
              </span>
            )}
            {failed > 0 && (
              <span style={{ fontSize: '0.75rem', color: 'var(--red)', fontWeight: 600 }}>
                {failed} FAILED
              </span>
            )}
          </div>
        </div>

        {/* Overall progress bar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ flex: 1, height: 8, borderRadius: 'var(--radius-sm)', background: 'rgba(148,163,184,0.12)', overflow: 'hidden', position: 'relative' }}>
            <div style={{
              position: 'absolute', top: 0, left: 0, height: '100%',
              width: `${pct}%`,
              borderRadius: 'var(--radius-sm)',
              background: scan.status === 'failed' ? 'var(--chart-red)' :
                          scan.status === 'completed' ? 'var(--chart-green)' :
                          'linear-gradient(90deg, var(--cyan) 0%, var(--chart-purple) 100%)',
              transition: 'width 0.5s ease',
            }} />
          </div>
          <span style={{
            fontSize: '0.8125rem', fontWeight: 700, minWidth: 38, textAlign: 'right',
            color: scan.status === 'completed' ? 'var(--green)' : 'var(--cyan)',
          }}>
            {pct}%
          </span>
        </div>
      </div>

      {/* ── Body ── */}
      <div style={{ padding: '1rem 1.25rem', display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
        {hasSteps ? (
          // Workflow: group tools under their step
          workflowSteps.map(step => {
            const stepColor =
              step.status === 'running'   ? 'var(--cyan)' :
              step.status === 'completed' ? 'var(--green)'     :
              step.status === 'failed'    ? 'var(--red)'     :
              step.status === 'skipped'   ? 'var(--amber)'     : 'var(--text-muted)';
            const stepTools = tools.filter(t => step.tools.includes(t.name));
            return (
              <div key={String(step.step_id)}>
                {/* Step header */}
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  marginBottom: '0.5rem',
                  padding: '0.375rem 0.5rem',
                  borderRadius: 'var(--radius-sm)',
                  background: `color-mix(in srgb, ${stepColor} 5%, transparent)`,
                  border: `1px solid color-mix(in srgb, ${stepColor} 15%, transparent)`,
                }}>
                  <div style={{
                    width: 20, height: 20, borderRadius: '50%',
                    background: stepColor, color: 'var(--bg-primary)',
                    fontSize: '0.6875rem', fontWeight: 800,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    {step.status === 'running' ? <Loader2 size={10} className="animate-spin" /> :
                     step.status === 'completed' ? <CheckCircle size={10} /> :
                     step.status === 'failed' ? '✕' : step.status === 'skipped' ? '—' : step.step_id}
                  </div>
                  <span style={{ fontWeight: 700, fontSize: '0.8125rem', color: stepColor }}>{step.step_name}</span>
                  <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    {step.status}
                  </span>
                  {step.reason && (
                    <span style={{ fontSize: '0.6875rem', color: 'var(--amber)', marginLeft: 4 }}>{step.reason}</span>
                  )}
                  {step.failed_tools && step.failed_tools.length > 0 && (
                    <span style={{ fontSize: '0.6875rem', color: 'var(--red)' }}>Failed: {step.failed_tools.join(', ')}</span>
                  )}
                </div>
                {/* Tools under this step */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', paddingLeft: 12, borderLeft: `2px solid color-mix(in srgb, ${stepColor} 19%, transparent)` }}>
                  {stepTools.map(t => <ToolRow key={t.name} tool={t} now={now} />)}
                  {stepTools.length === 0 && step.tools.map(tName => (
                    <ToolRow key={tName} tool={{ name: tName, status: step.status === 'skipped' ? 'skipped' : 'queued' }} now={now} />
                  ))}
                </div>
              </div>
            );
          })
        ) : (
          // Flat list for non-workflow scans
          tools.map(t => <ToolRow key={t.name} tool={t} now={now} />)
        )}
      </div>

      {/* Shimmer keyframe injection */}
      <style>{`
        @keyframes shimmer {
          0% { background-position: -200% 0; }
          100% { background-position: 200% 0; }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </div>
  );
}

// ── Vuln Card ─────────────────────────────────────────────────────────────────
function VulnCard({ vuln }: { vuln: Vulnerability }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div style={{
      border: `1px solid color-mix(in srgb, ${SEVERITY_COLORS[vuln.severity] || 'var(--border)'} 20%, transparent)`,
      borderLeft: `3px solid ${SEVERITY_COLORS[vuln.severity] || 'var(--border)'}`,
      borderRadius: 'var(--radius-md)', background: 'var(--bg-secondary)',
      marginBottom: '0.625rem', overflow: 'hidden',
    }}>
      <div onClick={() => setExpanded(!expanded)} style={{ padding: '0.75rem 1rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <ShieldAlert size={15} color={SEVERITY_COLORS[vuln.severity]} style={{ flexShrink: 0 }} />
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-primary)' }}>{vuln.vuln_name}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
            {vuln.port && `Port ${vuln.port}`}{vuln.service && ` · ${vuln.service}`}
            {vuln.cve_id && ` · ${vuln.cve_id}`}
          </div>
        </div>
        <span className={`badge badge-${vuln.severity}`}>{vuln.severity}</span>
      </div>
      {expanded && (
        <div style={{ padding: '0 1rem 0.875rem', borderTop: '1px solid var(--border)' }}>
          {vuln.description && (
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.625rem', lineHeight: 1.6 }}>
              {vuln.description}
            </p>
          )}
          {vuln.cvss_score && (
            <div style={{ marginTop: 6, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              CVSS Score: <strong style={{ color: SEVERITY_COLORS[vuln.severity] }}>{vuln.cvss_score}</strong>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Tool Results Tab ──────────────────────────────────────────────────────────
function ToolResultsTab({ toolResults }: { toolResults?: import('@/lib/types').ToolResult[] }) {
  const [rawVisible, setRawVisible] = useState<Record<string, boolean>>({});

  if (!toolResults?.length) {
    return (
      <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
        No tool results yet.
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
      {toolResults.map(tr => {
        const showRaw = rawVisible[tr.id] ?? false;

        return (
          <div key={tr.id} className="card" style={{ padding: '1rem' }}>
            {/* Header row */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--cyan)' }}>
                {tr.tool_name}
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                {tr.anomaly_score != null && (
                  <span title={`Anomaly Score: ${tr.anomaly_score.toFixed(3)} (more negative = more anomalous)`} style={{
                    fontSize: '0.6875rem', fontWeight: 700, padding: '2px 7px', borderRadius: 99,
                    background: tr.anomaly_score < -0.1 ? 'rgba(249,115,22,0.15)' : 'rgba(148,163,184,0.1)',
                    border: `1px solid ${tr.anomaly_score < -0.1 ? 'rgba(249,115,22,0.4)' : 'rgba(148,163,184,0.25)'}`,
                    color: tr.anomaly_score < -0.1 ? 'var(--orange)' : 'var(--text-secondary)',
                  }}>
                    {tr.anomaly_score < -0.1 ? '⚠ Anomaly' : '✓ Normal'} {tr.anomaly_score.toFixed(2)}
                  </span>
                )}
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {tr.duration_ms ? `${tr.duration_ms}ms` : ''}{tr.duration_ms && tr.exit_code != null ? ' · ' : ''}{tr.exit_code != null ? `exit ${tr.exit_code}` : ''}
                </span>
                <button
                  onClick={() => setRawVisible(prev => ({ ...prev, [tr.id]: !showRaw }))}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 5,
                    fontSize: '0.75rem', fontWeight: 600,
                    padding: '0.2rem 0.55rem', borderRadius: 'var(--radius-sm)',
                    border: `1px solid ${showRaw ? 'rgba(6,182,212,0.4)' : 'var(--border)'}`,
                    background: showRaw ? 'rgba(6,182,212,0.08)' : 'transparent',
                    color: showRaw ? 'var(--cyan)' : 'var(--text-muted)',
                    cursor: 'pointer', transition: 'all 0.15s',
                  }}
                  title={showRaw ? 'Show summary' : 'Show raw output'}
                >
                  {showRaw ? <EyeOff size={12} /> : <Eye size={12} />}
                  {showRaw ? 'Summary' : 'Raw'}
                </button>
              </div>
            </div>

            {/* Output */}
            <div className="terminal" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
              {showRaw
                ? (tr.raw_output || '[No output]')
                : prettyToolOutput(tr.raw_output, tr.tool_name)}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'tools' | 'ai' | 'vulns' | 'terminal'>('overview');
  const [generating, setGenerating] = useState(false);
  const [aiProvider, setAiProvider] = useState<'ollama_remote'>('ollama_remote');
  const [aiModel, setAiModel] = useState('');
  const [aiModels, setAiModels] = useState<string[]>([]);
  const [aiModelsLoading, setAiModelsLoading] = useState(false);
  const [runningAiAnalysis, setRunningAiAnalysis] = useState(false);
  const [aiAnalysisInProgress, setAiAnalysisInProgress] = useState(false);
  const [remoteConfigured, setRemoteConfigured] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const [llmTokens, setLlmTokens] = useState<string[]>([]);
  const [toolStates, setToolStates] = useState<Record<string, ToolState>>({});
  const [workflowProgress, setWorkflowProgress] = useState<WorkflowStepProgress[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [handoffSessions, setHandoffSessions] = useState<number[]>([]);
  const [terminalSessionId, setTerminalSessionId] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const aiScrollRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    const res = await scansApi.get(id);
    setScan(res.data);
  }, [id]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const tab = new URLSearchParams(window.location.search).get('tab');
    if (tab === 'terminal') setActiveTab('terminal');
  }, []);

  const loadAiModels = useCallback(async () => {
    setAiModelsLoading(true);
    try {
      const res = await llmApi.models({
        provider: aiProvider,
      });
      const data = res.data;
      const byProvider: Record<string, string[]> = data.provider_models || {};
      const list: string[] = Array.isArray(byProvider[aiProvider])
        ? byProvider[aiProvider]
        : (data.ollama_remote_models ?? []).map((m: any) => m.name);
      setAiModels(list);
      if (!aiModel || !list.includes(aiModel)) setAiModel(list[0] || '');
    } catch {
      setAiModels([]);
    } finally {
      setAiModelsLoading(false);
    }
  }, [aiProvider, aiModel]);

  const loadLlmStatus = useCallback(async () => {
    try {
      const res = await llmApi.status();
      const isConfigured = Boolean(res.data?.ollama_remote?.url);
      setRemoteConfigured(isConfigured);
      // Ollama is an external server only. If it isn't configured, the dropdown
      // shows a disabled "configure in Admin" hint.
    } catch {
      setRemoteConfigured(false);
    }
  }, [aiProvider]);

  useEffect(() => {
    if (activeTab === 'ai') {
      loadLlmStatus();
      loadAiModels();
    }
  }, [activeTab, aiProvider, loadAiModels, loadLlmStatus]);

  const handleRunAiAnalysis = async () => {
    if (!scan || !aiModel) return;
    setRunningAiAnalysis(true);
    setAiAnalysisInProgress(true);
    try {
      const existingCount = scan.ai_analyses?.length || 0;
      await scansApi.runAiAnalysis(scan.id, {
        provider: aiProvider,
        model: aiModel,
      });
      setLlmTokens([]);

      // Manual AI job runs in worker queue; poll scan details so new analysis appears
      // even when the page websocket is not connected for already-completed scans.
      for (let i = 0; i < 45; i++) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        const res = await scansApi.get(scan.id);
        setScan(res.data);
        const nextCount = res.data?.ai_analyses?.length || 0;
        if (nextCount > existingCount) {
          setAiAnalysisInProgress(false);
          break;
        }
      }
    } catch (e) {
      console.error('Failed to start AI analysis', e);
      notify('Failed to start AI analysis. Check provider/model settings.', 'error');
      setAiAnalysisInProgress(false);
    } finally {
      setRunningAiAnalysis(false);
      if (!scan?.status || scan.status !== 'analyzing') {
        setTimeout(() => setAiAnalysisInProgress(false), 1000);
      }
    }
  };

  // Tick every second for live elapsed timers, but only while the scan is still active: this state lives in the top-level
  // component of a very large page, so an idle 1-second tick re-rendered the whole page every second for finished scans too.
  const scanIsActive = !scan || !['completed', 'failed', 'cancelled'].includes(scan.status);
  useEffect(() => {
    if (!scanIsActive) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [scanIsActive]);

  // Pre-populate / sync tool states from scan config + any known tool_results
  useEffect(() => {
    if (!scan) return;
    const isFinished = ['completed', 'failed', 'cancelled'].includes(scan.status);

    // Build states from tool_results (available for both running AND finished scans)
    if (scan.tool_results && scan.tool_results.length > 0) {
      const states: Record<string, ToolState> = {};
      const sessionsFromResults: number[] = [];
      for (const tr of scan.tool_results) {
        states[tr.tool_name] = {
          name: tr.tool_name,
          // exit_code may be null/undefined for success — treat null as 0 (success)
          status: (tr.exit_code ?? 0) === 0 ? 'completed' : 'failed',
          durationMs: tr.duration_ms,
        };
        const sid = extractMetasploitSessionId(tr.raw_output);
        if (sid !== null) sessionsFromResults.push(sid);
      }
      if (sessionsFromResults.length > 0) {
        setHandoffSessions(prev => Array.from(new Set([...prev, ...sessionsFromResults])));
        setTerminalSessionId(prev => prev ?? sessionsFromResults[0]);
      }
      setToolStates(prev => {
        // Merge: DB results are source of truth — override queued AND running states
        // so a WS-dropped tool stuck in 'running' is corrected by the DB poll.
        const merged: Record<string, ToolState> = { ...prev };
        for (const [k, v] of Object.entries(states)) {
          if (!merged[k] || merged[k].status === 'queued' || merged[k].status === 'running') {
            merged[k] = { ...v, triage: merged[k]?.triage };
          }
        }
        // Also pre-populate remaining tools from config as queued
        const cfg2 = scan.tool_config || {};
        const allNames: string[] = [...(cfg2.tools ?? []), ...(cfg2.steps ?? []).flatMap((s: any) => s.tools ?? [])];
        for (const t of allNames) { if (!merged[t]) merged[t] = { name: t, status: 'queued' }; }
        return merged;
      });
      if (isFinished) return;
    }

    // For scans with no tool_results yet: pre-populate from tool_config as queued
    const cfg = scan.tool_config || {};

    // Graph workflow: extract tool nodes from the saved graph
    if (cfg.graph?.nodes) {
      const graphNodes: any[] = cfg.graph.nodes;
      const toolNodes = graphNodes.filter(n => n.type === 'tool' && n.data?.tool);
      setToolStates(prev => {
        const next = { ...prev };
        for (const n of toolNodes) { if (!next[n.data.tool]) next[n.data.tool] = { name: n.data.tool, status: 'queued' }; }
        return next;
      });
      // Pre-populate workflowProgress so ExecutionPanel shows graph nodes in order
      setWorkflowProgress(prev => {
        if (prev.length > 0) return prev; // don't overwrite live WS data
        return toolNodes.map((n, i) => ({
          step_id: i + 1,
          step_name: n.data.label || n.data.tool,
          status: isFinished ? ('completed' as const) : ('pending' as const),
          tools: [n.data.tool],
          _node_id: n.id,
        }));
      });
    } else {
      setToolStates(prev => {
        const next = { ...prev };
        const toolNames: string[] = cfg.tools ?? [];
        for (const t of toolNames) { if (!next[t]) next[t] = { name: t, status: 'queued' }; }
        const steps: Array<{ tools: string[] }> = cfg.steps ?? [];
        for (const step of steps) {
          for (const t of step.tools ?? []) { if (!next[t]) next[t] = { name: t, status: 'queued' }; }
        }
        return next;
      });
    }
  }, [scan?.id, scan?.status, scan?.tool_results?.length]);

  // Poll DB every 10s during active scans to pick up tool results from mid-scan page loads
  useEffect(() => {
    if (!scan) return;
    if (['completed', 'failed', 'cancelled'].includes(scan.status)) return;
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, [scan?.status, load]);

  // Auto-scroll AI analysis as tokens stream in
  useEffect(() => {
    if (aiScrollRef.current) {
      aiScrollRef.current.scrollTop = aiScrollRef.current.scrollHeight;
    }
  }, [llmTokens]);

  // WebSocket connection for live scan updates
  useEffect(() => {
    if (!scan) return;
    if (['completed', 'failed', 'cancelled'].includes(scan.status)) return;

    let reconnectTimeout: NodeJS.Timeout;
    let reconnectAttempts = 0;
    const maxReconnects = 10;

    const connect = () => {
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
      const host = process.env.NEXT_PUBLIC_API_URL?.replace(/^https?:\/\//, '') ||
        (typeof window !== 'undefined' ? window.location.host : 'localhost:8000');
      const token = document.cookie.split('; ').find(c => c.startsWith('access_token='))?.split('=')[1] ?? '';
      const socket = new WebSocket(`${proto}://${host}/ws/scan/${id}?token=${token}`);
      wsRef.current = socket;

      socket.onopen = () => {
        setWsConnected(true);
        reconnectAttempts = 0;
      };
      socket.onclose = () => {
        setWsConnected(false);
        if (reconnectAttempts < maxReconnects) {
          reconnectTimeout = setTimeout(() => {
            reconnectAttempts++;
            connect();
          }, 2000 * reconnectAttempts);
        }
      };
      socket.onerror = () => {
        setWsConnected(false);
      };
      socket.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
        switch (msg.type) {
          case 'tool_start':
            setToolStates(prev => ({
              ...prev,
              [msg.tool]: { ...prev[msg.tool], name: msg.tool, status: 'running', startedAt: Date.now() },
            }));
            break;
          case 'tool_complete':
            setToolStates(prev => ({
              ...prev,
              [msg.tool]: {
                ...prev[msg.tool],
                name: msg.tool,
                status: msg.success === false ? 'failed' : 'completed',
                durationMs: msg.duration_ms,
              },
            }));
            break;
          case 'tool_error':
            setToolStates(prev => ({
              ...prev,
              [msg.tool]: { ...prev[msg.tool], name: msg.tool, status: 'failed' },
            }));
            break;
          case 'tool_triage':
            setToolStates(prev => ({
              ...prev,
              [msg.tool]: { ...(prev[msg.tool] ?? { name: msg.tool, status: 'completed' }), triage: msg.triage || msg.summary },
            }));
            break;
          case 'tool_progress':
            setToolStates(prev => {
              const existing = prev[msg.tool];
              if (!existing || existing.status !== 'running') return prev;
              return { ...prev, [msg.tool]: { ...existing, progress: msg.progress } };
            });
            break;
          case 'workflow_plan':
            // Backend emitted dynamic step plan — pre-register pending steps
            if (msg.steps && Array.isArray(msg.steps)) {
              setWorkflowProgress(prev => {
                const existingIds = new Set(prev.map(s => s.step_id));
                const newSteps: WorkflowStepProgress[] = msg.steps
                  .filter((s: any) => !existingIds.has(s.step_id))
                  .map((s: any) => ({
                    step_id: s.step_id,
                    step_name: s.step_name,
                    status: 'pending' as const,
                    tools: s.tools || [],
                  }));
                return [...prev, ...newSteps];
              });
              // Pre-register tools as queued
              setToolStates(prev2 => {
                const next = { ...prev2 };
                for (const s of msg.steps) {
                  for (const t of (s.tools || [])) {
                    if (!next[t]) next[t] = { name: t, status: 'queued' };
                  }
                }
                return next;
              });
            }
            break;
          case 'workflow_step':
            setWorkflowProgress(prev => {
              const existing = prev.findIndex(s => s.step_id === msg.step_id);
              const entry: WorkflowStepProgress = {
                step_id: msg.step_id,
                step_name: msg.step_name,
                status: msg.status,
                tools: msg.tools || [],
                reason: msg.reason,
                failed_tools: msg.failed_tools,
              };
              if (existing >= 0) {
                const updated = [...prev];
                updated[existing] = entry;
                return updated;
              }
              // When step starts running, pre-register all its tools as queued
              if (msg.status === 'running' && msg.tools) {
                setToolStates(prev2 => {
                  const next = { ...prev2 };
                  for (const t of msg.tools) {
                    if (!next[t]) next[t] = { name: t, status: 'queued' };
                  }
                  return next;
                });
              }
              return [...prev, entry];
            });
            break;
          // Graph-based workflow nodes (n8n-style)
          case 'node_start':
            if (msg.tool) {
              setToolStates(prev => ({
                ...prev,
                [msg.tool]: { ...prev[msg.tool], name: msg.tool, status: 'running', startedAt: Date.now() },
              }));
            }
            // Also update workflowProgress for graph nodes
            if (msg.node_id) {
              setWorkflowProgress(prev => prev.map(s =>
                (s as any)._node_id === msg.node_id ? { ...s, status: 'running' as const } : s
              ));
            }
            break;
          case 'node_complete':
            if (msg.tool) {
              const nodeStatus = msg.skipped ? 'skipped' : msg.success === false ? 'failed' : 'completed';
              setToolStates(prev => ({
                ...prev,
                [msg.tool]: {
                  ...prev[msg.tool],
                  name: msg.tool,
                  status: nodeStatus as any,
                  durationMs: msg.duration_ms,
                },
              }));
              // Also update workflowProgress
              if (msg.node_id) {
                setWorkflowProgress(prev => prev.map(s =>
                  (s as any)._node_id === msg.node_id
                    ? { ...s, status: nodeStatus as 'completed' | 'failed' | 'pending' }
                    : s
                ));
              }
              const sid = extractMetasploitSessionId(msg.output);
              if (sid !== null) {
                setHandoffSessions(prev => Array.from(new Set([...prev, sid])));
                setTerminalSessionId(prev => prev ?? sid);
              }
            }
            break;
          case 'node_failed':
            if (msg.tool) {
              setToolStates(prev => ({
                ...prev,
                [msg.tool]: { ...prev[msg.tool], name: msg.tool, status: 'failed' },
              }));
              if (msg.node_id) {
                setWorkflowProgress(prev => prev.map(s =>
                  (s as any)._node_id === msg.node_id ? { ...s, status: 'failed' as const } : s
                ));
              }
            }
            break;
          case 'llm_token':
            setLlmTokens(m => [...m, msg.token]);
            break;
          case 'complete':
          case 'status':
            load();
            break;
          default:
            break;
        }
      } catch {
          // ignore parse errors
        }
      };
    };

    connect();

    return () => {
      clearTimeout(reconnectTimeout);
      wsRef.current?.close();
    };
  }, [id]);

  const handleGenerateReport = async (format: string) => {
    if (!scan) return;
    setGenerating(true);
    try {
      await reportsApi.generate({ scan_id: scan.id, format });
      notify(`${format.toUpperCase()} report generation started!`, 'success');
    } catch {
      notify('Error generating report', 'error');
    } finally {
      setGenerating(false);
    }
  };

  if (!scan) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', color: 'var(--text-muted)' }}>
      <RefreshCw size={20} className="animate-spin" style={{ marginRight: 10 }} /> Loading scan...
    </div>
  );

  const latestAiWithFindings = (scan.ai_analyses || []).find((a: any) =>
    Array.isArray((a?.parsed_data as any)?.vulnerabilities)
  );
  const latestAi = latestAiWithFindings || (scan.ai_analyses || [])[0];

  const aiParsedVulnsRaw: any[] = Array.isArray((latestAi?.parsed_data as any)?.vulnerabilities)
    ? ((latestAi?.parsed_data as any).vulnerabilities as any[])
    : [];

  const aiParsedVulns: Vulnerability[] = aiParsedVulnsRaw.map((v: any, i: number) => ({
    id: String(v.id ?? `${scan.id}-ai-${i}`),
    vuln_name: String(v.vuln_name ?? v.name ?? v.title ?? v.cve_id ?? 'Detected Vulnerability'),
    severity: normalizeSeverity(v.severity),
    port: v.port,
    service: v.service,
    cve_id: v.cve_id,
    description: v.description,
    cvss_score: typeof v.cvss_score === 'number' ? v.cvss_score : (typeof v.cvss === 'number' ? v.cvss : undefined),
    epss_score: typeof v.epss_score === 'number' ? v.epss_score : null,
    created_at: String(v.created_at ?? scan.created_at),
  }));

  const effectiveVulnerabilities: Vulnerability[] =
    (scan.vulnerabilities && scan.vulnerabilities.length > 0) ? scan.vulnerabilities : aiParsedVulns;

  const effectiveRiskLevel = scan.risk_level || latestAi?.risk_level;
  const RISK_COLOR = SEVERITY_COLORS[effectiveRiskLevel?.toLowerCase() || ''] || 'var(--text-secondary)';
  const vulnCounts = {
    critical: effectiveVulnerabilities.filter(v => normalizeSeverity(v.severity) === 'critical').length,
    high: effectiveVulnerabilities.filter(v => normalizeSeverity(v.severity) === 'high').length,
    medium: effectiveVulnerabilities.filter(v => normalizeSeverity(v.severity) === 'medium').length,
    low: effectiveVulnerabilities.filter(v => normalizeSeverity(v.severity) === 'low').length,
  };

  // Build ordered tool list for ExecutionPanel
  // For workflow: use step-ordered tools; for others: tool_config order
  const cfg = scan.tool_config || {};
  let orderedToolNames: string[] = [];
  if (scan.scan_type === 'workflow' && workflowProgress.length > 0) {
    for (const step of workflowProgress) orderedToolNames.push(...step.tools);
  } else if (cfg.steps?.length) {
    for (const step of cfg.steps) orderedToolNames.push(...(step.tools ?? []));
  } else {
    orderedToolNames = cfg.tools ?? Object.keys(toolStates);
  }
  // Deduplicate, then add any extras from toolStates not already listed
  const seen = new Set<string>();
  const dedupedNames: string[] = [];
  for (const t of orderedToolNames) { if (!seen.has(t)) { seen.add(t); dedupedNames.push(t); } }
  for (const t of Object.keys(toolStates)) { if (!seen.has(t)) { seen.add(t); dedupedNames.push(t); } }
  const allTools: ToolState[] = dedupedNames.map(n => toolStates[n] ?? { name: n, status: 'queued' });

  // Build effective workflow steps: prefer live WS data, fall back to config
  const isFinishedScan = ['completed', 'failed', 'cancelled'].includes(scan.status);
  let effectiveWorkflowSteps = workflowProgress;
  if (scan.scan_type === 'workflow' && effectiveWorkflowSteps.length === 0 && cfg.steps?.length && !cfg.graph) {
    effectiveWorkflowSteps = cfg.steps.map((s: any) => ({
      step_id: s.step_id,
      step_name: s.name,
      // For completed scans show all steps as completed; for active scans show as pending
      status: isFinishedScan ? ('completed' as const) : ('pending' as const),
      tools: s.tools ?? [],
    }));
  }

  return (
    <div className="animate-fadeIn" style={{ padding: '2rem', width: '100%' }}>
      {/* Header */}
      <div style={{ marginBottom: '1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: 6 }}>
            <h1 style={{ fontFamily: 'var(--font-mono)',  }}>
              {scan.target}
            </h1>
            <span className={`badge status-${scan.status}`} style={{ borderRadius: 'var(--radius-sm)' }}>{scan.status}</span>
          </div>
          <div style={{ display: 'flex', gap: '1rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
            <span>ID: <span style={{ fontFamily: 'var(--font-mono)' }}>{scan.id.slice(0, 8)}...</span></span>
            <span>Type: {scan.scan_type}</span>
            <span>Created: {new Date(scan.created_at).toLocaleString()}</span>
          </div>
        </div>
        {effectiveRiskLevel && (
          <div style={{ textAlign: 'center', padding: '0.75rem 1.5rem', background: `color-mix(in srgb, ${RISK_COLOR} 8%, transparent)`, border: `2px solid color-mix(in srgb, ${RISK_COLOR} 25%, transparent)`, borderRadius: 'var(--radius-lg)' }}>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 2 }}>Risk Level</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: RISK_COLOR }}>{effectiveRiskLevel}</div>
          </div>
        )}
      </div>

      {/* Vuln Summary Cards */}
      {scan.status === 'completed' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.75rem', marginBottom: '1.5rem' }}>
          {Object.entries(vulnCounts).map(([sev, count]) => (
            <div key={sev} className="stat-card" style={{ padding: '0.875rem' }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: SEVERITY_COLORS[sev] }}>{count}</div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'capitalize' }}>{sev} Severity</div>
            </div>
          ))}
        </div>
      )}

      {/* ── Enterprise Execution Panel ── */}
      <ExecutionPanel
        scan={scan}
        tools={allTools}
        workflowSteps={effectiveWorkflowSteps}
        wsConnected={wsConnected}
        now={now}
      />

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '0.25rem', borderBottom: '1px solid var(--border)', marginBottom: '1.5rem' }}>
        {(['overview', 'vulns', 'tools', 'ai', 'terminal'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            style={{
              padding: '0.625rem 1.125rem', background: 'none', border: 'none', cursor: 'pointer',
              fontSize: '0.875rem', fontWeight: 500, transition: 'all 0.15s', textTransform: 'capitalize',
              borderBottom: `2px solid ${activeTab === tab ? 'var(--cyan)' : 'transparent'}`,
              color: activeTab === tab ? 'var(--cyan)' : 'var(--text-muted)',
              marginBottom: -1,
            }}
          >
            {tab === 'vulns' ? `Vulnerabilities (${effectiveVulnerabilities.length})` :
             tab === 'tools' ? `Tool Results (${scan.tool_results?.length || 0})` :
             tab === 'ai' ? 'AI Analysis' :
             tab === 'terminal' ? `Terminal${handoffSessions.length > 0 ? ` (${handoffSessions.length})` : ''}` :
             'Overview'}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div className="card">
            <h3 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '1rem' }}>Scan Details</h3>
            {[
              { label: 'Target',          value: scan.target },
              { label: 'Scan Type',       value: scan.scan_type },
              { label: 'Risk Level',      value: effectiveRiskLevel || 'Pending' },
              { label: 'Vulnerabilities', value: String(effectiveVulnerabilities.length) },
              { label: 'Started',         value: scan.started_at ? new Date(scan.started_at).toLocaleString() : '—' },
              { label: 'Completed',       value: scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '—' },
            ].map(({ label, value }) => (
              <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0', borderBottom: '1px solid var(--border)', fontSize: '0.875rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>{label}</span>
                <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{value}</span>
              </div>
            ))}
          </div>
          <div className="card">
            <h3 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '1rem' }}>Generate Report</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {(['pdf', 'html', 'json', 'csv', 'docx', 'sarif'] as const).map(fmt => (
                <button key={fmt} onClick={() => handleGenerateReport(fmt)} disabled={generating || scan.status !== 'completed'}
                  className="btn btn-ghost"
                  style={{ justifyContent: 'space-between', padding: '0.625rem 0.875rem' }}
                >
                  <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <FileText size={15} /> {fmt.toUpperCase()} Report
                  </span>
                  <Download size={13} />
                </button>
              ))}
            </div>
            {scan.status !== 'completed' && (
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 10 }}>
                Reports available after scan completes.
              </p>
            )}
          </div>
        </div>
      )}

      {activeTab === 'vulns' && (
        <div>
          {!effectiveVulnerabilities.length ? (
            <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
              {scan.status === 'completed' ? 'No vulnerabilities found.' : 'Analysis in progress...'}
            </div>
          ) : (
            <div>
              {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => {
                const vulns = effectiveVulnerabilities.filter(v => normalizeSeverity(v.severity) === sev);
                if (!vulns.length) return null;
                return (
                  <div key={sev} style={{ marginBottom: '1.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '0.625rem' }}>
                      <span style={{ color: SEVERITY_COLORS[sev], fontWeight: 700, fontSize: '0.875rem', textTransform: 'uppercase' }}>{sev}</span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>({vulns.length})</span>
                    </div>
                    {vulns.map(v => <VulnCard key={v.id} vuln={v} />)}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {activeTab === 'tools' && (
        <ToolResultsTab toolResults={scan.tool_results} />
      )}

      {activeTab === 'ai' && (
        <div>
          <div className="card" style={{ marginBottom: '1rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '160px 1fr auto', gap: 10, alignItems: 'end' }}>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>Provider</div>
                <select
                  value={aiProvider}
                  onChange={e => setAiProvider(e.target.value as 'ollama_remote')}
                  style={{ width: '100%', background: 'var(--bg-primary)', color: 'var(--text-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '8px 10px' }}
                >
                  <option value="ollama_remote" disabled={!remoteConfigured}>Remote Ollama{!remoteConfigured ? ' (configure in Admin)' : ''}</option>
                </select>
              </div>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>Model</div>
                <select
                  value={aiModel}
                  onChange={e => setAiModel(e.target.value)}
                  style={{ width: '100%', background: 'var(--bg-primary)', color: 'var(--text-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '8px 10px' }}
                  disabled={aiModelsLoading}
                >
                  <option value="">{aiModelsLoading ? 'Loading models...' : 'Select model'}</option>
                  {aiModels.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              </div>
              <button
                onClick={handleRunAiAnalysis}
                disabled={runningAiAnalysis || aiAnalysisInProgress || !aiModel || scan.status === 'running' || scan.status === 'pending'}
                style={{
                  background: 'var(--cyan)', color: 'var(--ink)', border: 'none', borderRadius: 'var(--radius-sm)',
                  padding: '8px 12px', fontWeight: 700, cursor: 'pointer', height: 36,
                }}
              >
                {runningAiAnalysis ? 'Starting...' : aiAnalysisInProgress ? 'Running...' : 'Run AI Analysis'}
              </button>
            </div>
            <div style={{ marginTop: 8, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              AI analysis is manual for new scans/workflows. Select provider/model and run when tool execution completes.
              {!remoteConfigured && ' Remote Ollama can be enabled from Admin -> Settings.'}
            </div>
            {aiAnalysisInProgress && (
              <div style={{
                marginTop: 10,
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                padding: '6px 10px',
                borderRadius: 999,
                border: '1px solid color-mix(in srgb, var(--cyan) 33%, transparent)',
                background: 'color-mix(in srgb, var(--cyan) 8%, transparent)',
                color: 'var(--cyan)',
                fontSize: '0.75rem',
                fontWeight: 600,
              }}>
                <RefreshCw size={12} className="animate-spin" />
                AI analysis running... waiting for result
              </div>
            )}
          </div>

          {!scan.ai_analyses?.length ? (
            <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
              {scan.status === 'analyzing' ? (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10 }}>
                  <RefreshCw size={16} className="animate-spin" color="var(--purple)" />
                  <span>AI is analyzing the findings...</span>
                </div>
              ) : 'No AI analysis yet.'}
            </div>
          ) : scan.ai_analyses.map(a => (
            <div key={a.id} className="card" style={{ marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '1rem' }}>
                <Brain size={17} color="var(--purple)" />
                <span style={{ fontWeight: 600, fontSize: '0.875rem' }}>AI Analysis</span>
                {a.risk_level && <span style={{ marginLeft: 'auto', color: SEVERITY_COLORS[a.risk_level.toLowerCase()] || 'var(--text-secondary)', fontWeight: 700 }}>Risk: {a.risk_level}</span>}
              </div>
              <div className="terminal" style={{ color: 'var(--text-primary)', maxHeight: 600 }}>
                {a.response}
              </div>
            </div>
          ))}

          {/* Live token stream during analysis */}
          {llmTokens.length > 0 && (
            <div className="card">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '0.75rem' }}>
                <RefreshCw size={14} color="var(--purple)" className="animate-spin" />
                <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--purple)' }}>Live Analysis Stream</span>
              </div>
              <div ref={aiScrollRef} className="terminal" style={{ maxHeight: 400, overflowY: 'auto' }}>
                {llmTokens.join('')}
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'terminal' && (
        <div>
          <div className="card" style={{ marginBottom: '1rem' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 8 }}>
              Interactive Metasploit xterm session. Add a Metasploit node with action
              {' '}
              <span style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>interactive_handoff</span>
              {' '}
              in your workflow to populate this tab with an active session.
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Session:</label>
              <select
                value={terminalSessionId ?? ''}
                onChange={(e) => setTerminalSessionId(e.target.value ? parseInt(e.target.value, 10) : null)}
                style={{
                  background: 'var(--bg-primary)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.75rem',
                  padding: '0.35rem 0.45rem',
                  minWidth: 180,
                }}
              >
                {handoffSessions.length === 0 && <option value="">No handoff session detected</option>}
                {handoffSessions.map((sid) => (
                  <option key={sid} value={sid}>Session {sid}</option>
                ))}
              </select>
            </div>
            <MetasploitTerminal
              scanId={id}
              sessionId={terminalSessionId}
              height={420}
            />
          </div>
        </div>
      )}
    </div>
  );
}
