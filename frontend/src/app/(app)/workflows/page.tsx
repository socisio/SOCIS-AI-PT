'use client';
import { scopeBlock } from '@/lib/scope';
import { askScopeOverride } from '@/lib/dialogs';
import { Fragment, useState, useEffect, useCallback, useRef } from 'react';
import UiIcon from '@/components/ui/Icon';
import type { IconName } from '@/components/ui/Icon';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  GitBranch, Plus, Check, ChevronUp, ChevronDown, X, Loader2,
  Clock, RefreshCw, CheckCircle, AlertCircle, XCircle, Play,
  ArrowRight, Network, Trash2, Download, Pencil,
} from 'lucide-react';
import { scansApi, projectsApi, workflowsApi } from '@/lib/api';
import type { Scan, ScanStatus, Project, WorkflowDefinition } from '@/lib/types';
import { WORKFLOW_PRESETS, type WorkflowStep } from '@/lib/workflow-presets';
import { askConfirm } from '@/lib/dialogs';

// ── Status helpers ────────────────────────────────────────────────────────────
const STATUS_ICONS: Record<ScanStatus, React.ReactNode> = {
  pending:   <Clock size={13} />,
  running:   <RefreshCw size={13} className="animate-spin" />,
  analyzing: <RefreshCw size={13} className="animate-spin" />,
  completed: <CheckCircle size={13} />,
  failed:    <AlertCircle size={13} />,
  cancelled: <XCircle size={13} />,
};

const STATUS_COLORS: Record<ScanStatus, string> = {
  pending:   'var(--text-secondary)',
  running:   'var(--cyan)',
  analyzing: 'var(--purple)',
  completed: 'var(--green)',
  failed:    'var(--red)',
  cancelled: 'var(--text-muted)',
};

// ── Step Builder sub-component ────────────────────────────────────────────────
function StepBuilder({
  steps,
  onChange,
}: {
  steps: WorkflowStep[];
  onChange: (steps: WorkflowStep[]) => void;
}) {
  const moveUp = (i: number) => {
    if (i === 0) return;
    const s = [...steps];
    [s[i - 1], s[i]] = [s[i], s[i - 1]];
    onChange(s);
  };
  const moveDown = (i: number) => {
    if (i === steps.length - 1) return;
    const s = [...steps];
    [s[i], s[i + 1]] = [s[i + 1], s[i]];
    onChange(s);
  };
  const remove = (i: number) => {
    if (steps[i].tools.includes('nmap')) return;
    onChange(steps.filter((_, idx) => idx !== i));
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
      {steps.map((step, idx) => (
        <div
          key={step.step_id}
          style={{
            border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '0.75rem 1rem',
            background: 'var(--bg-secondary)', display: 'flex', alignItems: 'flex-start', gap: 10,
          }}
        >
          <div style={{
            width: 24, height: 24, borderRadius: '50%', background: 'var(--cyan)',
            color: 'var(--bg-primary)', fontSize: '0.75rem', fontWeight: 700,
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 2,
          }}>
            {idx + 1}
          </div>

          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>{step.name}</div>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 5 }}>
              {step.tools.map(t => (
                <span key={t} style={{
                  fontFamily: 'var(--font-mono)', fontSize: '0.75rem',
                  background: 'var(--bg-primary)', border: '1px solid color-mix(in srgb, var(--cyan) 25%, transparent)',
                  color: 'var(--cyan)', borderRadius: 'var(--radius-sm)', padding: '1px 6px',
                }}>
                  {t}
                </span>
              ))}
            </div>
            {step.port_filter && (
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>
                Port filter: {step.port_filter.join(', ')}
              </div>
            )}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flexShrink: 0 }}>
            <button
              onClick={() => moveUp(idx)}
              disabled={idx === 0}
              title="Move up"
              style={{
                background: 'none', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
                padding: '2px 4px', cursor: idx === 0 ? 'not-allowed' : 'pointer', opacity: idx === 0 ? 0.3 : 1,
              }}
            >
              <ChevronUp size={12} />
            </button>
            <button
              onClick={() => moveDown(idx)}
              disabled={idx === steps.length - 1}
              title="Move down"
              style={{
                background: 'none', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
                padding: '2px 4px', cursor: idx === steps.length - 1 ? 'not-allowed' : 'pointer',
                opacity: idx === steps.length - 1 ? 0.3 : 1,
              }}
            >
              <ChevronDown size={12} />
            </button>
            <button
              onClick={() => remove(idx)}
              disabled={step.tools.includes('nmap')}
              title={step.tools.includes('nmap') ? 'nmap step is required' : 'Remove step'}
              style={{
                background: 'none', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
                padding: '2px 4px',
                cursor: step.tools.includes('nmap') ? 'not-allowed' : 'pointer',
                opacity: step.tools.includes('nmap') ? 0.3 : 1,
                color: 'var(--red)',
              }}
            >
              <X size={12} />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Workflow Run Card ─────────────────────────────────────────────────────────
function WorkflowRunCard({ scan, onDelete }: { scan: Scan; onDelete: (id: string) => void }) {
  const steps: WorkflowStep[] = scan.tool_config?.steps ?? [];
  const presetId = scan.tool_config?.workflow_id as string | undefined;
  const workflowDefinitionId = scan.tool_config?.workflow_definition_id as string | undefined;
  const presetName = presetId ? (WORKFLOW_PRESETS[presetId]?.name ?? presetId) : 'Custom';
  const statusColor = STATUS_COLORS[scan.status as ScanStatus] ?? 'var(--text-secondary)';
  const isActive = ['running', 'analyzing'].includes(scan.status);
  const detailsHref = workflowDefinitionId
    ? `/workflows/${workflowDefinitionId}/runs/${scan.id}`
    : `/scans/${scan.id}`;
  const terminalHref = workflowDefinitionId
    ? `/workflows/${workflowDefinitionId}/runs/${scan.id}?tab=terminal`
    : `/scans/${scan.id}?tab=terminal`;

  return (
    <div className="card" style={{ marginBottom: '0.875rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
            <GitBranch size={15} color="var(--cyan)" style={{ flexShrink: 0 }} />
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '1rem' }}>
              {scan.target}
            </span>
            <span style={{
              fontSize: '0.75rem', color: 'var(--text-muted)',
              background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm)', padding: '1px 7px', flexShrink: 0,
            }}>
              {presetName}
            </span>
          </div>
          <div style={{ display: 'flex', gap: '0.875rem', fontSize: '0.75rem', color: 'var(--text-muted)', flexWrap: 'wrap' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: statusColor }}>
              {STATUS_ICONS[scan.status as ScanStatus]}
              {scan.status}
            </span>
            <span>{new Date(scan.created_at).toLocaleString()}</span>
            {scan.completed_at && (
              <span>Completed: {new Date(scan.completed_at).toLocaleString()}</span>
            )}
          </div>
        </div>

        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0, marginLeft: 8 }}>
          {isActive && (
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.75rem', color: 'var(--green)' }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--chart-green)', display: 'inline-block', animation: 'pulse 2s infinite' }} />
              Live
            </span>
          )}
          <Link
            href={detailsHref}
            className="btn btn-ghost"
            style={{ padding: '0.3rem 0.75rem', fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: 4 }}
          >
            Details →
          </Link>
          <Link
            href={terminalHref}
            className="btn btn-ghost"
            style={{ padding: '0.3rem 0.75rem', fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: 4, borderColor: 'color-mix(in srgb, var(--green) 33%, transparent)', color: 'var(--green)' }}
          >
            Terminal
          </Link>
          <button
            onClick={async () => { if (!(await askConfirm('Delete this workflow run?'))) return; onDelete(scan.id); }}
            className="btn btn-ghost"
            style={{ padding: '0.3rem 0.5rem', color: 'var(--red)', borderColor: 'color-mix(in srgb, var(--red) 25%, transparent)' }}
            title="Delete run"
          >
            <X size={13} />
          </button>
        </div>
      </div>

      {/* Step progress pills */}
      {steps.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          {steps.map((step, i) => {
            const completed = scan.status === 'completed';
            return (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  padding: '3px 10px', borderRadius: 'var(--radius-lg)', fontSize: '0.75rem', fontWeight: 500,
                  background: completed ? 'color-mix(in srgb, var(--green) 9%, transparent)' : 'var(--bg-secondary)',
                  border: `1px solid ${completed ? 'color-mix(in srgb, var(--green) 25%, transparent)' : 'var(--border)'}`,
                  color: completed ? 'var(--green)' : 'var(--text-muted)',
                }}>
                  {completed && <CheckCircle size={11} style={{ flexShrink: 0 }} />}
                  {step.name}
                </div>
                {i < steps.length - 1 && <ArrowRight size={10} color="var(--text-muted)" style={{ flexShrink: 0 }} />}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── New Workflow Form ─────────────────────────────────────────────────────────
function NewWorkflowForm({
  projects,
  onSuccess,
  onCancel,
  initialPresetId,
}: {
  projects: Project[];
  onSuccess: () => void;
  onCancel: () => void;
  initialPresetId?: string;
}) {
  const startPreset = initialPresetId && WORKFLOW_PRESETS[initialPresetId] ? initialPresetId : 'full_pentest';
  const [formStep, setFormStep] = useState<1 | 2 | 3>(initialPresetId ? 1 : 1);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [form, setForm] = useState({
    target: '',
    project_id: '',
    workflow_id: startPreset,
    workflow_steps: WORKFLOW_PRESETS[startPreset].steps as WorkflowStep[],
    nmap_flags: '-sV -sC -T4 --open',
  });

  const submitRun = async (overrideReason?: string): Promise<void> => {
    if (!form.target || !form.project_id) {
      setError('Target and project are required');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await scansApi.create({
        target: form.target,
        project_id: form.project_id,
        scan_type: 'workflow',
        tool_config: {
          workflow_id: form.workflow_id,
          steps: form.workflow_steps,
          nmap_flags: form.nmap_flags,
        },
        scope_override_reason: overrideReason,
      });
      onSuccess();
    } catch (e: any) {
      // Outside the project's authorized scope: explain, and let an administrator run it anyway with a written reason.
      const block = scopeBlock(e);
      if (block) {
        const reason = await askScopeOverride(block);
        if (reason) return submitRun(reason);
      }
      const detail = e?.response?.data?.detail;
      if (Array.isArray(detail)) {
        setError(detail.map((d: any) => d.msg ?? String(d)).join('; '));
      } else {
        setError(typeof detail === 'string' ? detail : 'Failed to launch workflow');
      }
    } finally {
      setSubmitting(false);
    }
  };
  const handleSubmit = () => { void submitRun(); };

  const FORM_STEPS = ['Target', 'Preset', 'Steps'] as const;

  return (
    <div className="card" style={{ marginBottom: '1.75rem', border: '1px solid color-mix(in srgb, var(--cyan) 31%, transparent)' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <GitBranch size={16} color="var(--cyan)" />
          <span style={{ fontWeight: 700, fontSize: '1rem' }}>New Workflow Run</span>
        </div>
        <button
          onClick={onCancel}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}
        >
          <X size={16} />
        </button>
      </div>

      {/* Step indicators */}
      <div style={{ display: 'flex', gap: 4, marginBottom: '1.5rem' }}>
        {FORM_STEPS.map((label, i) => {
          const n = i + 1;
          const active = formStep === n;
          const done = formStep > n;
          return (
            <div key={label} style={{ display: 'flex', alignItems: 'center', flex: 1 }}>
              <div
                style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: done ? 'pointer' : 'default' }}
                onClick={() => done && setFormStep(n as 1 | 2 | 3)}
              >
                <div style={{
                  width: 22, height: 22, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: done ? 'var(--cyan)' : active ? 'var(--cyan-glow)' : 'var(--bg-secondary)',
                  border: `2px solid ${done || active ? 'var(--cyan)' : 'var(--border)'}`,
                  color: done ? 'var(--bg-primary)' : active ? 'var(--cyan)' : 'var(--text-muted)',
                  fontSize: '0.6875rem', fontWeight: 700, flexShrink: 0,
                }}>
                  {done ? <Check size={11} /> : n}
                </div>
                <span style={{
                  fontSize: '0.75rem',
                  color: active ? 'var(--text-primary)' : 'var(--text-muted)',
                  fontWeight: active ? 600 : 400,
                }}>
                  {label}
                </span>
              </div>
              {i < FORM_STEPS.length - 1 && (
                <div style={{ flex: 1, height: 1, background: formStep > n ? 'var(--cyan)' : 'var(--border)', margin: '0 0.4rem' }} />
              )}
            </div>
          );
        })}
      </div>

      {/* Step 1: Target + Project */}
      {formStep === 1 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: 5 }}>
              Target (IP or domain) *
            </label>
            <input
              className="input"
              value={form.target}
              onChange={e => setForm(f => ({ ...f, target: e.target.value }))}
              placeholder="e.g. 192.168.1.1  or  example.com"
              style={{ fontFamily: 'var(--font-mono)', fontSize: '0.875rem' }}
              onKeyDown={e => {
                if (e.key === 'Enter' && form.target && form.project_id) {
                  setError('');
                  setFormStep(2);
                }
              }}
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: 5 }}>
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
                No projects yet. <a href="/projects" style={{ color: 'var(--cyan)' }}>Create one first →</a>
              </p>
            )}
          </div>
        </div>
      )}

      {/* Step 2: Preset picker */}
      {formStep === 2 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
          {Object.entries(WORKFLOW_PRESETS).map(([id, preset]) => (
            <div
              key={id}
              onClick={() => setForm(f => ({ ...f, workflow_id: id, workflow_steps: preset.steps }))}
              style={{
                padding: '0.875rem 1rem', borderRadius: 'var(--radius-lg)', cursor: 'pointer', transition: 'all 0.15s',
                border: `2px solid ${form.workflow_id === id ? 'var(--cyan)' : 'var(--border)'}`,
                background: form.workflow_id === id ? 'var(--cyan-glow)' : 'var(--bg-secondary)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>{preset.name}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
                    {preset.description}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap', marginTop: 8 }}>
                    {preset.steps.map((s, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <span style={{
                          fontSize: '0.6875rem', background: 'var(--bg-primary)',
                          border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '1px 6px',
                          fontFamily: 'var(--font-mono)',
                        }}>
                          {s.name}
                        </span>
                        {i < preset.steps.length - 1 && <ArrowRight size={9} color="var(--text-muted)" />}
                      </div>
                    ))}
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
                {form.workflow_id === id && <Check size={16} color="var(--cyan)" style={{ flexShrink: 0, marginTop: 2 }} />}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Step 3: Step customization + nmap flags */}
      {formStep === 3 && (
        <div>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: '0.875rem' }}>
            Reorder or remove steps. The nmap step is required.
          </p>
          <StepBuilder
            steps={form.workflow_steps}
            onChange={steps => setForm(f => ({ ...f, workflow_steps: steps }))}
          />
          <div style={{ marginTop: '1rem' }}>
            <label style={{ display: 'block', fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: 5 }}>
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
      )}

      {error && (
        <div style={{
          marginTop: '1rem', padding: '0.625rem 0.875rem',
          background: 'color-mix(in srgb, var(--red) 13%, transparent)', border: '1px solid var(--red)',
          borderRadius: 'var(--radius-md)', color: 'var(--red)', fontSize: '0.8125rem',
        }}>
          {error}
        </div>
      )}

      {/* Form navigation */}
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '1.5rem' }}>
        <button
          onClick={() => formStep > 1 ? setFormStep(s => (s - 1) as 1 | 2 | 3) : onCancel()}
          className="btn btn-ghost"
        >
          {formStep === 1 ? 'Cancel' : '← Back'}
        </button>
        {formStep < 3 ? (
          <button
            onClick={() => {
              if (formStep === 1 && !form.target) { setError('Enter a target'); return; }
              if (formStep === 1 && !form.project_id) { setError('Select a project'); return; }
              setError('');
              setFormStep(s => (s + 1) as 1 | 2 | 3);
            }}
            className="btn btn-primary"
          >
            Next →
          </button>
        ) : (
          <button onClick={handleSubmit} disabled={submitting} className="btn btn-primary">
            {submitting
              ? <><Loader2 size={15} className="animate-spin" /> Launching...</>
              : <><Play size={15} /> Launch Workflow</>
            }
          </button>
        )}
      </div>
    </div>
  );
}

// ── Custom Workflow Card ─────────────────────────────────────────────────────
function CustomWorkflowCard({ wf, onDelete, onRename }: { wf: WorkflowDefinition; onDelete: (id: string) => void; onRename: (id: string, name: string) => void }) {
  const router = useRouter();
  const [editing, setEditing] = useState(false);
  const [nameVal, setNameVal] = useState(wf.name);
  const [saving, setSaving] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const startEdit = () => {
    setNameVal(wf.name);
    setEditing(true);
    setTimeout(() => { inputRef.current?.select(); }, 30);
  };

  const commitRename = async () => {
    const trimmed = nameVal.trim();
    if (!trimmed || trimmed === wf.name) { setEditing(false); return; }
    setSaving(true);
    try {
      await workflowsApi.update(wf.id, { name: trimmed, nodes: wf.nodes as any[], edges: wf.edges as any[] });
      onRename(wf.id, trimmed);
    } catch { /* ignore */ } finally {
      setSaving(false);
      setEditing(false);
    }
  };

  const handleExport = async () => {
    const r = await workflowsApi.exportWorkflow(wf.id);
    const url = URL.createObjectURL(r.data);
    const a = document.createElement('a');
    a.href = url; a.download = `${wf.name}.socis-workflow.json`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="card" style={{ marginBottom: '0.625rem', display: 'flex', alignItems: 'center', gap: 12 }}>
      <Network size={15} color="var(--cyan)" style={{ flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        {editing ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <input
              ref={inputRef}
              value={nameVal}
              onChange={e => setNameVal(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') commitRename(); if (e.key === 'Escape') setEditing(false); }}
              autoFocus
              style={{
                background: 'var(--bg-primary)', border: '1px solid var(--cyan)',
                borderRadius: 'var(--radius-sm)', padding: '3px 8px', color: 'var(--text-primary)',
                fontWeight: 600, fontSize: '0.875rem', flex: 1, outline: 'none',
              }}
            />
            <button onClick={commitRename} disabled={saving}
              className="btn btn-ghost" style={{ padding: '3px 8px', fontSize: '0.75rem', color: 'var(--green)', flexShrink: 0 }}>
              {saving ? <Loader2 size={11} className="animate-spin" /> : <Check size={11} />}
            </button>
            <button onClick={() => setEditing(false)}
              className="btn btn-ghost" style={{ padding: '3px 6px', flexShrink: 0 }}>
              <X size={11} />
            </button>
          </div>
        ) : (
          <div
            onClick={startEdit}
            title="Click to rename"
            style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', cursor: 'text' }}>
            {wf.name}
          </div>
        )}
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
          {wf.nodes?.length ?? 0} nodes · {new Date(wf.created_at).toLocaleDateString()}
        </div>
      </div>
      <div style={{ display: 'flex', gap: 5, flexShrink: 0 }}>
        <button onClick={() => router.push(`/workflows/builder?id=${wf.id}`)}
          className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: 4 }}>
          <Pencil size={11} /> Edit
        </button>
        <button onClick={handleExport} className="btn btn-ghost" style={{ padding: '4px 8px' }} title="Export">
          <Download size={12} />
        </button>
        <button
          onClick={async () => { if (!(await askConfirm(`Delete workflow "${wf.name}"?`))) return; onDelete(wf.id); }}
          className="btn btn-ghost" style={{ padding: '4px 8px', color: 'var(--red)' }} title="Delete">
          <Trash2 size={12} />
        </button>
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function WorkflowsPage() {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [pendingPreset, setPendingPreset] = useState<string>('full_pentest');
  const [presetCat, setPresetCat] = useState('All');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [customWorkflows, setCustomWorkflows] = useState<WorkflowDefinition[]>([]);
  const [loadingCustom, setLoadingCustom] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await scansApi.list({ page: 1 });
      const all: Scan[] = res.data.scans || [];
      setScans(all.filter(s => s.scan_type === 'workflow'));
    } catch {
      setScans([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadCustom = useCallback(() => {
    setLoadingCustom(true);
    workflowsApi.list().then(r => {
      setCustomWorkflows(r.data.workflows ?? r.data ?? []);
    }).catch(() => setCustomWorkflows([])).finally(() => setLoadingCustom(false));
  }, []);

  useEffect(() => {
    load();
    loadCustom();
    projectsApi.list().then(res => setProjects(res.data.projects || [])).catch(() => {});
  }, [load, loadCustom]);

  const handleDelete = async (id: string) => {
    await scansApi.delete(id);
    load();
  };

  const handleDeleteCustom = async (id: string) => {
    await workflowsApi.delete(id);
    loadCustom();
  };

  const handleRenameCustom = (id: string, newName: string) => {
    setCustomWorkflows(prev => prev.map(w => w.id === id ? { ...w, name: newName } : w));
  };

  const filtered = statusFilter
    ? scans.filter(s => s.status === statusFilter)
    : scans;

  const activeCount    = scans.filter(s => ['running', 'analyzing'].includes(s.status)).length;
  const completedCount = scans.filter(s => s.status === 'completed').length;
  const failedCount    = scans.filter(s => s.status === 'failed').length;

  const STATUS_FILTERS = [
    { value: '',          label: 'All' },
    { value: 'running',   label: 'Running' },
    { value: 'analyzing', label: 'Analyzing' },
    { value: 'completed', label: 'Completed' },
    { value: 'failed',    label: 'Failed' },
    { value: 'pending',   label: 'Pending' },
  ];

  return (
    <div className="animate-fadeIn" style={{ padding: '2rem', width: '100%' }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.75rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
            <GitBranch size={22} color="var(--cyan)" />
            <h1>Workflows</h1>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            Sequential chained penetration test workflows — each step feeds into the next
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
          <button
            onClick={() => router.push('/workflows/builder')}
            className="btn btn-ghost"
            style={{ border: '1px solid color-mix(in srgb, var(--cyan) 38%, transparent)', color: 'var(--cyan)', display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <Network size={15} /> Visual Builder
          </button>
          {!showForm && (
            <button onClick={() => setShowForm(true)} className="btn btn-primary">
              <Plus size={16} /> New Workflow
            </button>
          )}
        </div>
      </div>

      {/* ── Stats ── */}
      <div className="statstrip">
        <div><small>Total runs</small><b>{scans.length}</b></div>
        <div><small>Active</small><b style={{ color: 'var(--green)' }}>{activeCount}</b></div>
        <div><small>Completed</small><b>{completedCount}</b></div>
        <div><small>Failed</small><b style={{ color: failedCount > 0 ? 'var(--red)' : undefined }}>{failedCount}</b></div>
      </div>

      {/* ── Templates (shown when the form is closed) ── */}
      {!showForm && (
        <div style={{ marginBottom: '1.75rem' }}>
          <div className="tools-row">
            <h2 style={{ fontSize: '1rem', fontWeight: 600 }}>Templates</h2>
            <span className="muted" style={{ fontSize: '0.8125rem' }}>Start from a proven chain, or customize one in the builder</span>
            <div className="seg" role="radiogroup" aria-label="Filter templates by category" style={{ marginLeft: 'auto' }}>
              {['All', ...Array.from(new Set(Object.values(WORKFLOW_PRESETS).map((x) => x.category).filter((c): c is string => Boolean(c))))].map((c) => (
                <span key={c} role="radio" aria-checked={presetCat === c} tabIndex={0} className={presetCat === c ? 'on' : ''}
                  onClick={() => setPresetCat(c)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setPresetCat(c); } }}
                  style={{ cursor: 'pointer' }}>{c}</span>
              ))}
            </div>
          </div>
          <div className="wfg">
            {Object.entries(WORKFLOW_PRESETS).filter(([, x]) => presetCat === 'All' || x.category === presetCat).map(([id, preset]) => {
              const accent = preset.color ?? 'var(--cyan)';
              const n = preset.steps.length;
              const CAT_ICON: Record<string, IconName> = { Full: 'target', Web: 'globe', Network: 'activity', Quick: 'zap', AI: 'spark', Passive: 'eye', Exploit: 'bug' };
              return (
                <article key={id} className="wf" style={{ '--c': accent } as React.CSSProperties}>
                  <div className="wf-top">
                    <span className="wf-ico"><UiIcon name={CAT_ICON[preset.category ?? ''] ?? 'workflow'} size={18} /></span>
                    <div><h3>{preset.name}</h3><p>{preset.description}</p></div>
                  </div>
                  <ol className="wf-steps">
                    {preset.steps.map((step, i) => (
                      <Fragment key={i}>
                        <li><b>{i + 1}</b>{step.name}</li>
                        {i < n - 1 && <span className="sep"><UiIcon name="chevr" size={12} /></span>}
                      </Fragment>
                    ))}
                  </ol>
                  <div className="wf-foot">
                    <div className="wf-meta">
                      {preset.category && <span className="pill soft">{preset.category}</span>}
                      {preset.duration && <span><UiIcon name="clock" size={13} />{preset.duration}</span>}
                      <span><UiIcon name="workflow" size={13} />{n} {n === 1 ? 'step' : 'steps'}</span>
                    </div>
                    <div className="end">
                      <button className="btn btn-ghost btn-sm" title="Open this template in the Visual Builder" onClick={() => router.push(`/workflows/builder?preset=${id}`)}>
                        <UiIcon name="pencil" size={13} /> Customize
                      </button>
                      <button className="btn btn-primary btn-sm" onClick={() => { setPendingPreset(id); setShowForm(true); }}>
                        <UiIcon name="play" size={12} /> Run
                      </button>
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        </div>
      )}

      {/* ── My Custom Workflows (Visual Builder) ── */}
      <div style={{ marginBottom: '1.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
          <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', fontWeight: 600 }}>
            My Custom Workflows ({customWorkflows.length})
          </div>
          <button onClick={() => router.push('/workflows/builder')}
            className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: 4, color: 'var(--cyan)' }}>
            <Plus size={12} /> Create New
          </button>
        </div>
        {loadingCustom ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-muted)', padding: '1rem 0', fontSize: '0.875rem' }}>
            <Loader2 size={13} className="animate-spin" /> Loading...
          </div>
        ) : customWorkflows.length === 0 ? (
          <div style={{ padding: '1.5rem', border: '1px dashed var(--border)', borderRadius: 'var(--radius-lg)', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            No custom workflows yet.{' '}
            <button onClick={() => router.push('/workflows/builder')}
              style={{ background: 'none', border: 'none', color: 'var(--cyan)', cursor: 'pointer', fontSize: '0.875rem', textDecoration: 'underline' }}>
              Build your first one →
            </button>
          </div>
        ) : (
          customWorkflows.map(wf => <CustomWorkflowCard key={wf.id} wf={wf} onDelete={handleDeleteCustom} onRename={handleRenameCustom} />)
        )}
      </div>

      {/* ── New Workflow Form ── */}
      {showForm && (
        <NewWorkflowForm
          projects={projects}
          initialPresetId={pendingPreset}
          onSuccess={() => { setShowForm(false); load(); }}
          onCancel={() => setShowForm(false)}
        />
      )}

      {/* ── Runs list ── */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
          <div style={{
            fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.08em',
            color: 'var(--text-muted)', fontWeight: 600,
          }}>
            Workflow Runs ({filtered.length})
          </div>
          <div style={{ display: 'flex', gap: '0.375rem', alignItems: 'center' }}>
            {STATUS_FILTERS.map(({ value, label }) => (
              <button
                key={value}
                onClick={() => setStatusFilter(value)}
                className="btn"
                style={{
                  padding: '0.25rem 0.625rem', fontSize: '0.75rem',
                  background: statusFilter === value ? 'var(--cyan-glow)' : 'transparent',
                  border: `1px solid ${statusFilter === value ? 'var(--cyan)' : 'var(--border)'}`,
                  color: statusFilter === value ? 'var(--cyan)' : 'var(--text-muted)',
                }}
              >
                {label}
              </button>
            ))}
            <button onClick={load} className="btn btn-ghost" style={{ padding: '0.25rem 0.5rem' }}>
              <RefreshCw size={13} />
            </button>
          </div>
        </div>

        {loading ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-muted)', padding: '2.5rem 0' }}>
            <Loader2 size={16} className="animate-spin" /> Loading workflow runs...
          </div>
        ) : filtered.length === 0 ? (
          <div style={{
            textAlign: 'center', padding: '3rem',
            border: '1px dashed var(--border)', borderRadius: 'var(--radius-lg)',
            color: 'var(--text-muted)',
          }}>
            <GitBranch size={32} style={{ margin: '0 auto 0.875rem', opacity: 0.4, display: 'block' }} />
            <div style={{ fontWeight: 600, marginBottom: 4 }}>
              {statusFilter ? `No ${statusFilter} workflow runs` : 'No workflow runs yet'}
            </div>
            <div style={{ fontSize: '0.875rem', marginBottom: '1.25rem' }}>
              Launch a sequential penetration test workflow to get started
            </div>
            {!statusFilter && (
              <button onClick={() => setShowForm(true)} className="btn btn-primary" style={{ margin: '0 auto', display: 'inline-flex' }}>
                <Plus size={15} /> New Workflow
              </button>
            )}
          </div>
        ) : (
          filtered.map(scan => (
            <WorkflowRunCard key={scan.id} scan={scan} onDelete={handleDelete} />
          ))
        )}
      </div>
    </div>
  );
}
