'use client';

/**
 * ProjectScopeDialog: the authorized scope of one project.
 * Administrators edit the allowlist and the enforcement switch; everyone with access to the project can read it, test a target
 * against it, and see what was blocked or overridden. The project owner's own "requested scope" appears as suggestions an
 * administrator can approve with one click.
 */

import { useCallback, useEffect, useState } from 'react';
import { projectsApi } from '@/lib/api';
import type { ScopeCheckResult, ScopeInfo } from '@/lib/api';
import Modal from '@/components/ui/Modal';
import Toggle from '@/components/ui/Toggle';
import Icon from '@/components/ui/Icon';
import { Pill } from '@/components/ui/Panel';
import { notify } from '@/lib/dialogs';
import { apiError } from '@/lib/errors';
import { timeAgo } from '@/lib/format';

const EVENT_LABEL: Record<string, string> = { 'scope:blocked': 'Blocked', 'scope:override': 'Override', 'scope:updated': 'Scope changed' };

function eventLine(a: string, d: Record<string, unknown>): string {
  const target = typeof d.target === 'string' ? d.target : '';
  if (a === 'scope:blocked') return `${target || 'a target'}${d.source ? ` (${String(d.source)})` : ''}`;
  if (a === 'scope:override') return `${target}: ${String(d.reason ?? '')}`;
  if (a === 'scope:updated') {
    const add = Array.isArray(d.added) ? d.added.length : 0;
    const rem = Array.isArray(d.removed) ? d.removed.length : 0;
    return `${add} added, ${rem} removed, ${d.enforced_after ? 'enforced' : 'not enforced'}`;
  }
  return '';
}

export default function ProjectScopeDialog({
  projectId, projectName, onClose, onChanged,
}: { projectId: string; projectName: string; onClose: () => void; onChanged: () => void }) {
  const [info, setInfo] = useState<ScopeInfo | null>(null);
  const [text, setText] = useState('');
  const [enforced, setEnforced] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [probe, setProbe] = useState('');
  const [result, setResult] = useState<ScopeCheckResult | null>(null);

  const load = useCallback(() => {
    projectsApi.getScope(projectId)
      .then((r) => { setInfo(r.data); setText(r.data.targets.join('\n')); setEnforced(r.data.enforced); setError(''); })
      .catch((e) => setError(apiError(e, 'Could not load the scope')));
  }, [projectId]);
  useEffect(() => { load(); }, [load]);

  const canEdit = info?.can_edit === true;
  const lines = text.split('\n').map((s) => s.trim()).filter(Boolean);
  const dirty = info !== null && (text.trim() !== info.targets.join('\n') || enforced !== info.enforced);

  const save = async () => {
    setBusy(true); setError('');
    try {
      await projectsApi.putScope(projectId, { targets: lines, enforced });
      notify('Scope saved', 'success');
      load(); onChanged();
    } catch (e) { setError(apiError(e, 'Could not save the scope')); }
    finally { setBusy(false); }
  };

  const test = async () => {
    if (!probe.trim()) return;
    try { setResult((await projectsApi.checkScope(projectId, probe.trim())).data); }
    catch (e) { setResult(null); notify(apiError(e, 'Could not test the target'), 'error'); }
  };

  const addSuggested = () => {
    if (!info) return;
    const have = new Set(lines);
    setText([...lines, ...info.suggested.filter((s) => !have.has(s))].join('\n'));
  };

  return (
    <Modal
      open title={`Authorized scope · ${projectName}`} onClose={onClose} width={720}
      footer={<>
        <button className="btn btn-ghost" onClick={onClose}>{canEdit && dirty ? 'Cancel' : 'Close'}</button>
        {canEdit && <button className="btn btn-primary" disabled={!dirty || busy} onClick={save}>Save scope</button>}
      </>}
    >
      {!info && !error && <div className="help">Loading…</div>}
      {error && <div role="alert" style={{ whiteSpace: 'pre-line', fontSize: '0.8125rem', color: 'var(--red)', marginBottom: '0.75rem' }}>{error}</div>}
      {info && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.9rem' }}>
            <Toggle label="Enforce the authorized scope" checked={enforced} onChange={setEnforced} disabled={!canEdit} />
            <div>
              <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>
                {enforced ? 'Enforced: only authorized targets can be scanned' : 'Not enforced: any target can be scanned'}
              </div>
              <div className="help">{canEdit ? 'Applies to scans, workflows, schedules, AI chat and tool calls.' : 'Only an administrator can change this.'}</div>
            </div>
            {enforced && lines.length === 0 && <span style={{ marginLeft: 'auto' }}><Pill tone="red" dot>Nothing authorized yet</Pill></span>}
          </div>

          <div>
            <label htmlFor="scope-text" className="lab" style={{ fontSize: '0.8125rem', fontWeight: 500, display: 'block', marginBottom: 6 }}>
              Authorized targets <span className="help" style={{ fontWeight: 400 }}>· one per line</span>
            </label>
            <textarea
              id="scope-text" className="input mono" rows={7} value={text} readOnly={!canEdit} spellCheck={false}
              onChange={(e) => setText(e.target.value)} style={{ resize: 'vertical' }}
              placeholder={'10.20.0.0/24\n10.30.1.10-10.30.1.50\napp.example.com\n*.example.com'}
            />
            <div className="help" style={{ marginTop: 6, lineHeight: 1.55 }}>
              Addresses, networks (/8 or longer), ranges (10.0.0.1-50), host names, and <b>*.domain</b> for subdomains. A name matches only itself:
              list <b>example.com</b> and <b>*.example.com</b> separately when you mean both. Names are never resolved to addresses.
            </div>
          </div>

          {(info.suggested.length > 0 || info.unreadable.length > 0 || info.requested) && (
            <div className="panel" style={{ margin: 0 }}>
              <div className="panel-head"><div><h3>Requested by the project owner</h3><p>Not enforced until an administrator approves it.</p></div>
                {canEdit && info.suggested.length > 0 && <div className="end"><button className="btn btn-ghost btn-sm" onClick={addSuggested}><Icon name="plus" size={13} /> Add {info.suggested.length} to the list</button></div>}
              </div>
              <div style={{ padding: '0.75rem 1.25rem', fontSize: '0.8125rem' }}>
                {info.requested && <pre className="mono" style={{ margin: 0, whiteSpace: 'pre-wrap', color: 'var(--text-secondary)' }}>{info.requested}</pre>}
                {info.suggested.length > 0 && <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>{info.suggested.map((s) => <span key={s} className="chip mono">{s}</span>)}</div>}
                {info.unreadable.length > 0 && <div className="help" style={{ marginTop: 8 }}>Could not be read as targets: {info.unreadable.join(' · ')}</div>}
              </div>
            </div>
          )}

          <div>
            <div className="lab" style={{ fontSize: '0.8125rem', fontWeight: 500, marginBottom: 6 }}>Test a target</div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <input className="input mono" value={probe} onChange={(e) => { setProbe(e.target.value); setResult(null); }} placeholder="10.20.0.15 or app.example.com"
                aria-label="Target to test" onKeyDown={(e) => { if (e.key === 'Enter') test(); }} />
              <button className="btn btn-ghost" onClick={test} disabled={!probe.trim()}>Test</button>
            </div>
            {result && (
              <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.8125rem' }}>
                <Pill tone={result.in_list ? 'green' : 'red'} dot>{result.in_list ? 'In the authorized list' : 'Not in the authorized list'}</Pill>
                <span className="help">{result.reason}{!result.enforced ? ' · scope is not enforced, so it would run anyway' : ''}</span>
              </div>
            )}
          </div>

          <div>
            <div className="lab" style={{ fontSize: '0.8125rem', fontWeight: 500, marginBottom: 6 }}>Recent activity</div>
            {info.events.length === 0 ? <div className="help">Nothing has been blocked, overridden or changed yet.</div> : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {info.events.slice(0, 8).map((e, i) => (
                  <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'baseline', fontSize: '0.78rem' }}>
                    <Pill tone={e.action === 'scope:blocked' ? 'red' : e.action === 'scope:override' ? 'amber' : 'gray'}>{EVENT_LABEL[e.action] ?? e.action}</Pill>
                    <span style={{ minWidth: 0, flex: 1, wordBreak: 'break-word' }}>{eventLine(e.action, e.details)}</span>
                    <span className="help" style={{ whiteSpace: 'nowrap' }}>{e.by ? `${e.by} · ` : ''}{timeAgo(e.at)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </Modal>
  );
}
