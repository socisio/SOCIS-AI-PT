'use client';
import { scopeBlock } from '@/lib/scope';
import { askScopeOverride } from '@/lib/dialogs';
import { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Radar, Settings, ChevronRight, ChevronLeft, Check, Loader2, GitBranch, ChevronUp, ChevronDown, X, Plus, Zap } from 'lucide-react';
import { scansApi, projectsApi } from '@/lib/api';
import type { Project } from '@/lib/types';
import { WORKFLOW_PRESETS, type WorkflowStep } from '@/lib/workflow-presets';

const SCAN_TYPES = [
  { value: 'full',      label: 'Full Scan',          description: 'Recon + Vuln Scan + AI Analysis', recommended: true },
  { value: 'quick',     label: 'Quick Scan',          description: 'Fast port scan + AI summary' },
  { value: 'recon_only',label: 'Recon Only',          description: 'nmap, whois, DNS, headers' },
  { value: 'vuln_scan', label: 'Vulnerability Scan',  description: 'nikto, nuclei, CVE + CVE Lite' },
  { value: 'workflow',  label: 'Workflow',             description: 'Sequential chained tools — nmap feeds into next step' },
  { value: 'custom',    label: 'Custom',               description: 'Choose specific tools' },
];

const ALL_TOOLS = [
  // Recon
  'nmap', 'osint', 'waf', 'ssl',
  // Vulnerability Scanning
  'nuclei', 'cve', 'cve_lite', 'nikto',
  // Threat Intel
  'cisa_kev', 'epss', 'poc_index',
  // Web Attacks
  'ffuf', 'sqlmap',
  // Exploitation
  'metasploit',
];
const DEFAULT_TOOLS = ['nmap', 'osint', 'waf'];
// Mirrors backend/app/core/scan_coverage.py METHODOLOGY. A scan type NOT listed here (workflow, custom) has no fixed tool set:
// the user chooses exactly what runs, so picking it leaves the current tool selection alone instead of overwriting it.
const TOOLS_FOR_SCAN_TYPE: Record<string, string[]> = {
  full: ALL_TOOLS,
  quick: ['nmap'],
  recon_only: ['nmap', 'osint'],
  vuln_scan: ['nikto', 'nuclei', 'cve', 'cve_lite'],
};

// Inner component that uses useSearchParams
function NewScanContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [step, setStep] = useState(1);
  const [projects, setProjects] = useState<Project[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const [form, setForm] = useState({
    target: '',
    project_id: '',
    scan_type: 'full',
    tools: DEFAULT_TOOLS as string[],
    nmap_flags: '-sV -sC -T4 --open',
    workflow_id: 'full_pentest',
    workflow_steps: WORKFLOW_PRESETS['full_pentest'].steps as WorkflowStep[],
    ai_payloads: false,
    enable_anomaly_detection: false,
  });

  useEffect(() => {
    projectsApi.list().then(res => setProjects(res.data.projects || [])).catch(() => {});
  }, []);

  // Read project_id from URL query parameter
  useEffect(() => {
    const projectId = searchParams.get('project_id');
    if (projectId) {
      setForm(f => ({ ...f, project_id: projectId }));
    }
  }, [searchParams]);

  const toggleTool = (tool: string) => {
    setForm(f => ({
      ...f,
      tools: f.tools.includes(tool) ? f.tools.filter(t => t !== tool) : [...f.tools, tool],
    }));
  };

  const submitScan = async (overrideReason?: string): Promise<void> => {
    if (!form.target || !form.project_id) {
      setError('Target and project are required');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      const isWorkflow = form.scan_type === 'workflow';
      const tool_config = isWorkflow
        ? { workflow_id: form.workflow_id, steps: form.workflow_steps, nmap_flags: form.nmap_flags, ai_payloads: form.ai_payloads, enable_anomaly_detection: form.enable_anomaly_detection }
        : { tools: form.tools, nmap_flags: form.nmap_flags, ai_payloads: form.ai_payloads, enable_anomaly_detection: form.enable_anomaly_detection };
      const res = await scansApi.create({
        target: form.target,
        project_id: form.project_id,
        scan_type: form.scan_type,
        tool_config,
        scope_override_reason: overrideReason,
      });
      router.push(`/scans/${res.data.id}`);
    } catch (e: any) {
      // Outside the project's authorized scope: explain, and let an administrator run it anyway with a written reason.
      const block = scopeBlock(e);
      if (block) {
        const reason = await askScopeOverride(block);
        if (reason) return submitScan(reason);
      }
      const detail = e?.response?.data?.detail;
      if (Array.isArray(detail)) {
        setError(detail.map((d: any) => d.msg ?? String(d)).join('; '));
      } else {
        setError(typeof detail === 'string' ? detail : 'Failed to create scan');
      }
    } finally {
      setSubmitting(false);
    }
  };
  const handleSubmit = () => { void submitScan(); };

  const STEPS = ['Target', 'Scan Type', 'Tools', 'Launch'];

  return (
    <div className="animate-fadeIn" style={{ padding: '2rem', width: '100%' }}>
      <div style={{ marginBottom: '2rem' }}>
        <h1>New Penetration Test</h1>
        <p style={{ color: 'var(--text-muted)', marginTop: 4, fontSize: '0.875rem' }}>
          Configure and launch an AI-powered security scan
        </p>
      </div>

      {/* Step Indicator */}
      <div style={{ display: 'flex', gap: 0, marginBottom: '2rem' }}>
        {STEPS.map((s, i) => {
          const n = i + 1;
          const active = step === n;
          const done = step > n;
          return (
            <div key={s} style={{ display: 'flex', alignItems: 'center', flex: 1 }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8, cursor: done ? 'pointer' : 'default',
              }} onClick={() => done && setStep(n)}>
                <div style={{
                  width: 28, height: 28, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: done ? 'var(--cyan)' : active ? 'var(--cyan-glow)' : 'var(--bg-secondary)',
                  border: `2px solid ${done || active ? 'var(--cyan)' : 'var(--border)'}`,
                  color: done ? 'var(--bg-primary)' : active ? 'var(--cyan)' : 'var(--text-muted)',
                  fontSize: '0.75rem', fontWeight: 700, flexShrink: 0,
                }}>
                  {done ? <Check size={13} /> : n}
                </div>
                <span style={{ fontSize: '0.8125rem', color: active ? 'var(--text-primary)' : 'var(--text-muted)', fontWeight: active ? 600 : 400 }}>
                  {s}
                </span>
              </div>
              {i < STEPS.length - 1 && (
                <div style={{ flex: 1, height: 1, background: step > n + 1 ? 'var(--cyan)' : 'var(--border)', margin: '0 0.5rem' }} />
              )}
            </div>
          );
        })}
      </div>

      {/* Step Content */}
      <div className="card" style={{ marginBottom: '1.25rem' }}>
        {/* Step 1: Target */}
        {step === 1 && (
          <div>
            <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '1.25rem' }}>Define Target</h2>
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: 6 }}>
                Target (IP, domain, or CIDR range) *
              </label>
              <input
                className="input"
                value={form.target}
                onChange={e => setForm(f => ({ ...f, target: e.target.value }))}
                placeholder="e.g. 192.168.1.1  or  example.com  or  10.0.0.0/24"
                style={{ fontFamily: 'var(--font-mono)', fontSize: '0.875rem' }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: 6 }}>
                Project *
              </label>
              <select
                className="input"
                value={form.project_id}
                onChange={e => setForm(f => ({ ...f, project_id: e.target.value }))}
                style={{ background: 'var(--bg-secondary)' }}
              >
                <option value="">— Select a project —</option>
                {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
              {projects.length === 0 && (
                <p style={{ fontSize: '0.75rem', color: 'var(--amber)', marginTop: 4 }}>
                  No projects found. <a href="/projects" style={{ color: 'var(--cyan)' }}>Create one first →</a>
                </p>
              )}
            </div>
          </div>
        )}

        {/* Step 2: Scan Type */}
        {step === 2 && (
          <div>
            <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '1.25rem' }}>Select Scan Type</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
              {SCAN_TYPES.map(type => (
                <div key={type.value}
                  onClick={() => setForm(f => ({
                    ...f,
                    scan_type: type.value,
                    // Picking a scan type with a fixed methodology (Full, Quick, Recon Only, Vulnerability Scan) selects the
                    // tools that type is described as running, so the scan actually does what its label promises. Workflow
                    // and Custom have no fixed set, so the current tool selection is left alone.
                    tools: TOOLS_FOR_SCAN_TYPE[type.value] || f.tools,
                  }))}
                  style={{
                    padding: '0.875rem 1rem', borderRadius: 'var(--radius-lg)', cursor: 'pointer', transition: 'all 0.15s',
                    border: `2px solid ${form.scan_type === type.value ? 'var(--cyan)' : 'var(--border)'}`,
                    background: form.scan_type === type.value ? 'var(--cyan-glow)' : 'var(--bg-secondary)',
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.875rem', display: 'flex', alignItems: 'center', gap: 8 }}>
                      {type.value === 'workflow' && <GitBranch size={14} color="var(--cyan)" />}
                      {type.label}
                      {type.recommended && (
                        <span style={{ fontSize: '0.6875rem', background: 'var(--cyan)', color: 'var(--bg-primary)', padding: '1px 6px', borderRadius: 99, fontWeight: 700 }}>
                          RECOMMENDED
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginTop: 2 }}>{type.description}</div>
                  </div>
                  {form.scan_type === type.value && <Check size={16} color="var(--cyan)" />}
                </div>
              ))}
            </div>

            {/* Workflow preset picker — shown inline when Workflow is selected */}
            {form.scan_type === 'workflow' && (
              <div style={{ marginTop: '1.5rem' }}>
                <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: '0.625rem', fontWeight: 600 }}>
                  Select a workflow preset:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {Object.entries(WORKFLOW_PRESETS).map(([id, preset]) => (
                    <div key={id}
                      onClick={() => setForm(f => ({ ...f, workflow_id: id, workflow_steps: preset.steps }))}
                      style={{
                        padding: '0.75rem 1rem', borderRadius: 'var(--radius-md)', cursor: 'pointer', transition: 'all 0.15s',
                        border: `1px solid ${form.workflow_id === id ? (preset.dynamic ? 'var(--purple)' : 'var(--cyan)') : 'var(--border)'}`,
                        background: form.workflow_id === id ? (preset.dynamic ? 'rgba(167,139,250,0.08)' : 'var(--cyan-glow)') : 'var(--bg-secondary)',
                        display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12,
                      }}
                    >
                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: 600, fontSize: '0.875rem', display: 'flex', alignItems: 'center', gap: 6 }}>
                          {preset.dynamic && <Zap size={13} color="var(--purple)" />}
                          {preset.name}
                          {preset.dynamic && (
                            <span style={{ fontSize: '0.6875rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--purple)', background: 'rgba(167,139,250,0.15)', border: '1px solid rgba(167,139,250,0.4)', borderRadius: 'var(--radius-sm)', padding: '1px 5px' }}>
                              AI-Routed
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>{preset.description}</div>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 6 }}>
                          {preset.steps.map((s, i) => (
                            <span key={i} style={{ fontSize: '0.6875rem', background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '1px 6px', fontFamily: 'var(--font-mono)' }}>
                              {s.name}
                            </span>
                          ))}
                          {preset.dynamic && (
                            <span style={{ fontSize: '0.6875rem', background: 'rgba(167,139,250,0.1)', border: '1px solid rgba(167,139,250,0.3)', borderRadius: 'var(--radius-sm)', padding: '1px 6px', fontFamily: 'var(--font-mono)', color: 'var(--purple)' }}>
                              + dynamic steps
                            </span>
                          )}
                        </div>
                        <div style={{ marginTop: 8 }}>
                          <a
                            href={`/workflows/builder?preset=${id}`}
                            onClick={(e) => e.stopPropagation()}
                            style={{
                              fontSize: '0.75rem',
                              color: 'var(--cyan)',
                              textDecoration: 'none',
                              border: '1px solid var(--border)',
                              borderRadius: 'var(--radius-sm)',
                              padding: '3px 8px',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 4,
                            }}
                          >
                            Open In Builder (Editable)
                          </a>
                        </div>
                      </div>
                      {form.workflow_id === id && <Check size={15} color={preset.dynamic ? 'var(--purple)' : 'var(--cyan)'} style={{ flexShrink: 0, marginTop: 2 }} />}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Step 3: Tools / Workflow Steps */}
        {step === 3 && form.scan_type === 'workflow' ? (
          <div>
            <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.5rem' }}>Customize Workflow Steps</h2>
            {WORKFLOW_PRESETS[form.workflow_id]?.dynamic ? (
              <div style={{ padding: '1rem', background: 'rgba(167,139,250,0.07)', border: '1px solid rgba(167,139,250,0.3)', borderRadius: 'var(--radius-lg)', marginBottom: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <Zap size={14} color="var(--purple)" />
                  <span style={{ fontWeight: 700, fontSize: '0.875rem', color: 'var(--purple)' }}>Intelligent Auto-Routing Enabled</span>
                </div>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', margin: 0, lineHeight: 1.5 }}>
                  After port discovery, the backend automatically selects and schedules tools based on what's found
                  (e.g., web tools for HTTP ports, Metasploit modules for FTP/SSH/SMB, CVE lookup for versioned services).
                  No manual step configuration needed.
                </p>
              </div>
            ) : (
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
                Reorder or remove steps. Step 1 (nmap) is required for port-based filtering.
              </p>
            )}
            {!WORKFLOW_PRESETS[form.workflow_id]?.dynamic && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {form.workflow_steps.map((wStep, idx) => (
                <div key={wStep.step_id} style={{
                  border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '0.75rem 1rem',
                  background: 'var(--bg-secondary)', display: 'flex', alignItems: 'flex-start', gap: 10,
                }}>
                  {/* Step number badge */}
                  <div style={{
                    width: 24, height: 24, borderRadius: '50%', background: 'var(--cyan)',
                    color: 'var(--bg-primary)', fontSize: '0.75rem', fontWeight: 700,
                    display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 2,
                  }}>
                    {idx + 1}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>{wStep.name}</div>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 5 }}>
                      {wStep.tools.map(t => (
                        <span key={t} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', background: 'var(--bg-primary)', border: '1px solid color-mix(in srgb, var(--cyan) 25%, transparent)', color: 'var(--cyan)', borderRadius: 'var(--radius-sm)', padding: '1px 6px' }}>
                          {t}
                        </span>
                      ))}
                    </div>
                    {wStep.port_filter && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>
                        Port filter: {wStep.port_filter.join(', ')}
                      </div>
                    )}
                  </div>
                  {/* Controls */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flexShrink: 0 }}>
                    <button
                      onClick={() => {
                        if (idx === 0) return;
                        const s = [...form.workflow_steps];
                        [s[idx - 1], s[idx]] = [s[idx], s[idx - 1]];
                        setForm(f => ({ ...f, workflow_steps: s }));
                      }}
                      disabled={idx === 0}
                      style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '2px 4px', cursor: idx === 0 ? 'not-allowed' : 'pointer', opacity: idx === 0 ? 0.3 : 1 }}
                      title="Move up"
                    >
                      <ChevronUp size={12} />
                    </button>
                    <button
                      onClick={() => {
                        if (idx === form.workflow_steps.length - 1) return;
                        const s = [...form.workflow_steps];
                        [s[idx], s[idx + 1]] = [s[idx + 1], s[idx]];
                        setForm(f => ({ ...f, workflow_steps: s }));
                      }}
                      disabled={idx === form.workflow_steps.length - 1}
                      style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '2px 4px', cursor: idx === form.workflow_steps.length - 1 ? 'not-allowed' : 'pointer', opacity: idx === form.workflow_steps.length - 1 ? 0.3 : 1 }}
                      title="Move down"
                    >
                      <ChevronDown size={12} />
                    </button>
                    <button
                      onClick={() => {
                        if (wStep.tools.includes('nmap')) return; // protect step 1
                        setForm(f => ({ ...f, workflow_steps: f.workflow_steps.filter((_, i) => i !== idx) }));
                      }}
                      disabled={wStep.tools.includes('nmap')}
                      style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '2px 4px', cursor: wStep.tools.includes('nmap') ? 'not-allowed' : 'pointer', opacity: wStep.tools.includes('nmap') ? 0.3 : 1, color: 'var(--red)' }}
                      title={wStep.tools.includes('nmap') ? 'nmap step is required' : 'Remove step'}
                    >
                      <X size={12} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
            )}

            {/* Nmap Flags */}
            <div style={{ marginTop: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: 6 }}>
                Nmap Flags
              </label>
              <input
                className="input"
                value={form.nmap_flags}
                onChange={e => setForm(f => ({ ...f, nmap_flags: e.target.value }))}
                style={{ fontFamily: 'var(--font-mono)' }}
              />
            </div>
          </div>
        ) : step === 3 && (
          <div>
            <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.5rem' }}>Configure Tools</h2>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
              Select which tools to include. Enabled by default for your scan type.
            </p>

            {([
              { label: 'Recon & Fingerprinting', tools: ['nmap', 'osint', 'waf', 'ssl'] },
              { label: 'Vulnerability Scanning', tools: ['nuclei', 'cve', 'cve_lite', 'nikto'] },
              { label: 'Threat Intelligence', tools: ['cisa_kev', 'epss', 'poc_index'] },
              { label: 'Web Attacks', tools: ['ffuf', 'sqlmap'] },
              { label: 'Exploitation', tools: ['metasploit'] },
            ] as { label: string; tools: string[] }[]).map(group => (
              <div key={group.label} style={{ marginBottom: '1rem' }}>
                <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                  {group.label}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                  {group.tools.map(tool => {
                    const on = form.tools.includes(tool);
                    return (
                      <div key={tool}
                        onClick={() => toggleTool(tool)}
                        style={{
                          padding: '0.625rem 0.875rem', borderRadius: 'var(--radius-md)', cursor: 'pointer',
                          border: `1px solid ${on ? 'var(--cyan)' : 'var(--border)'}`,
                          background: on ? 'var(--cyan-glow)' : 'var(--bg-secondary)',
                          display: 'flex', alignItems: 'center', justifyContent: 'space-between', transition: 'all 0.15s',
                        }}
                      >
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', color: on ? 'var(--cyan)' : 'var(--text-secondary)' }}>
                          {tool}
                        </span>
                        {on && <Check size={13} color="var(--cyan)" />}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}

            <div style={{ marginTop: '0.75rem' }}>
              <label style={{ display: 'block', fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: 6 }}>
                Nmap Flags
              </label>
              <input
                className="input"
                value={form.nmap_flags}
                onChange={e => setForm(f => ({ ...f, nmap_flags: e.target.value }))}
                style={{ fontFamily: 'var(--font-mono)' }}
              />
            </div>

            <div style={{ marginTop: '1rem', padding: '0.875rem 1rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 2 }}>Advanced Options</div>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', cursor: 'pointer' }}>
                <input type="checkbox" checked={form.ai_payloads} onChange={e => setForm(f => ({ ...f, ai_payloads: e.target.checked }))} />
                <div>
                  <div style={{ fontSize: '0.875rem', fontWeight: 600 }}>AI-Assisted Payloads</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Pre-generate CVE-aware attack payloads via Ollama before fuzzing</div>
                </div>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', cursor: 'pointer' }}>
                <input type="checkbox" checked={form.enable_anomaly_detection} onChange={e => setForm(f => ({ ...f, enable_anomaly_detection: e.target.checked }))} />
                <div>
                  <div style={{ fontSize: '0.875rem', fontWeight: 600 }}>ML Anomaly Detection</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Score HTTP responses using IsolationForest after scan completes</div>
                </div>
              </label>
            </div>
          </div>
        )}

        {/* Step 4: Review & Launch */}
        {step === 4 && (
          <div>
            <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '1.25rem' }}>Review & Launch</h2>
            {[
              { label: 'Target', value: form.target, mono: true },
              { label: 'Project', value: projects.find(p => p.id === form.project_id)?.name || '—' },
              { label: 'Scan Type', value: SCAN_TYPES.find(t => t.value === form.scan_type)?.label || '' },
              ...(form.scan_type === 'workflow'
                ? [{ label: 'Workflow', value: WORKFLOW_PRESETS[form.workflow_id]?.name || form.workflow_id }]
                : [{ label: 'Tools', value: form.tools.join(', '), mono: true }]
              ),
              { label: 'Nmap Flags', value: form.nmap_flags, mono: true },
            ].map(({ label, value, mono }) => (
              <div key={label} style={{
                display: 'flex', padding: '0.625rem 0',
                borderBottom: '1px solid var(--border)', fontSize: '0.875rem',
              }}>
                <span style={{ width: 120, color: 'var(--text-muted)', flexShrink: 0 }}>{label}</span>
                <span style={{ color: 'var(--text-primary)', fontFamily: (mono as boolean) ? 'var(--font-mono)' : undefined, fontSize: (mono as boolean) ? '0.82rem' : undefined }}>
                  {value}
                </span>
              </div>
            ))}
            {form.scan_type === 'workflow' && (
              <div style={{ marginTop: '0.875rem' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em' }}>Steps</div>
                {WORKFLOW_PRESETS[form.workflow_id]?.dynamic ? (
                  <div style={{ padding: '0.625rem 0.875rem', background: 'rgba(167,139,250,0.07)', border: '1px solid rgba(167,139,250,0.25)', borderRadius: 'var(--radius-md)', fontSize: '0.8125rem', color: 'var(--purple)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Zap size={13} /> Steps will be determined automatically after port discovery
                  </div>
                ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {form.workflow_steps.map((s, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.8125rem' }}>
                      <span style={{ color: 'var(--cyan)', fontWeight: 700, minWidth: 18 }}>{i + 1}.</span>
                      <span style={{ color: 'var(--text-secondary)' }}>{s.name}</span>
                      <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                        [{s.tools.join(', ')}]
                      </span>
                    </div>
                  ))}
                </div>
                )}
              </div>
            )}
            {error && (
              <div style={{ marginTop: '1rem', padding: '0.75rem', background: 'color-mix(in srgb, var(--red) 13%, transparent)', border: '1px solid var(--red)', borderRadius: 'var(--radius-md)', color: 'var(--red)', fontSize: '0.875rem' }}>
                {error}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Navigation */}
      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
        <button onClick={() => setStep(s => Math.max(1, s - 1))} disabled={step === 1}
          className="btn btn-ghost" style={{ opacity: step === 1 ? 0.4 : 1 }}>
          <ChevronLeft size={16} /> Previous
        </button>

        {step < 4 ? (
          <button
            onClick={() => {
              if (step === 1 && !form.target) { setError('Please enter a target'); return; }
              if (step === 1 && !form.project_id) { setError('Please select a project'); return; }
              setError('');
              setStep(s => s + 1);
            }}
            className="btn btn-primary"
          >
            Continue <ChevronRight size={16} />
          </button>
        ) : (
          <button onClick={handleSubmit} disabled={submitting} className="btn btn-primary">
            {submitting ? <><Loader2 size={15} className="animate-spin" /> Launching...</> : <><Radar size={15} /> Launch Scan</>}
          </button>
        )}
      </div>
    </div>
  );
}

// Export the page wrapped in Suspense for useSearchParams
export default function NewScanPage() {
  return (
    <Suspense>
      <NewScanContent />
    </Suspense>
  );
}
