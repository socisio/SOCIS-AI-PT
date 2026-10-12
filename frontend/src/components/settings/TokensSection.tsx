'use client';

import { useCallback, useEffect, useState } from 'react';
import { apiKeysApi } from '@/lib/api';
import type { ApiToken } from '@/lib/api';
import Panel, { Pill } from '@/components/ui/Panel';
import Modal from '@/components/ui/Modal';
import Icon from '@/components/ui/Icon';
import { SectionHead } from '@/components/settings/SettingsShell';
import { askConfirm, notify } from '@/lib/dialogs';
import { apiError } from '@/lib/errors';
import { fmtDate, timeAgo } from '@/lib/format';

const EXPIRY: { label: string; days: number | null }[] = [
  { label: 'Never expires', days: null }, { label: '30 days', days: 30 }, { label: '90 days', days: 90 },
  { label: '180 days', days: 180 }, { label: '1 year', days: 365 },
];

function statusOf(t: ApiToken): { tone: 'green' | 'gray'; text: string } {
  if (!t.is_active) return { tone: 'gray', text: 'Revoked' };
  if (t.expires_at && new Date(t.expires_at).getTime() < Date.now()) return { tone: 'gray', text: 'Expired' };
  return { tone: 'green', text: 'Active' };
}

export default function TokensSection() {
  const [tokens, setTokens] = useState<ApiToken[] | null>(null);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState('');
  const [expiry, setExpiry] = useState(0);
  const [busy, setBusy] = useState(false);
  const [fresh, setFresh] = useState<string>('');   // the raw key, shown once

  const load = useCallback(() => {
    apiKeysApi.list().then((r) => setTokens(r.data)).catch(() => { setTokens([]); notify('Could not load your tokens', 'error'); });
  }, []);
  useEffect(() => { load(); }, [load]);

  const create = async () => {
    setBusy(true);
    try {
      const days = EXPIRY[expiry].days;
      const r = await apiKeysApi.create({ name: name.trim(), expires_at: days ? new Date(Date.now() + days * 86400000).toISOString() : null });
      setFresh(r.data.raw_key); setOpen(false); setName(''); setExpiry(0); load();
    } catch (e) { notify(apiError(e, 'Could not create the token'), 'error'); }
    finally { setBusy(false); }
  };

  const revoke = async (t: ApiToken) => {
    const ok = await askConfirm(`Revoke "${t.name}"? Anything using this token stops working immediately.`, { title: 'Revoke token', confirmLabel: 'Revoke', danger: true });
    if (!ok) return;
    try { await apiKeysApi.revoke(t.id); notify('Token revoked', 'success'); load(); }
    catch (e) { notify(apiError(e, 'Could not revoke the token'), 'error'); }
  };

  const regenerate = async (t: ApiToken) => {
    const ok = await askConfirm(
      `Regenerate "${t.name}"? The current secret stops working immediately and a brand-new one is issued. The token keeps its name, but you'll need to update anything using the old secret.`,
      { title: 'Regenerate token', confirmLabel: 'Regenerate', danger: true });
    if (!ok) return;
    setBusy(true);
    try {
      const r = await apiKeysApi.regenerate(t.id);
      setFresh(r.data.raw_key);   // shown once, same secure model as creation
      notify('Token regenerated', 'success');
      load();
    } catch (e) { notify(apiError(e, 'Could not regenerate the token'), 'error'); }
    finally { setBusy(false); }
  };

  return (
    <>
      <SectionHead title="API tokens" desc="Create and revoke tokens for scripts, CI pipelines and integrations." />
      {fresh && (
        <div className="banner" role="status">
          <span style={{ color: 'var(--green)' }}><Icon name="check" size={17} /></span>
          <div style={{ minWidth: 0 }}>
            <b>Token created.</b> Copy it now: for your security it is shown only once.
            <div className="tk" style={{ wordBreak: 'break-all' }}>
              {fresh}
              <button type="button" className="icon-btn" aria-label="Copy token" style={{ marginLeft: 'auto', width: 26, height: 26 }}
                onClick={() => { navigator.clipboard?.writeText(fresh).then(() => notify('Token copied', 'success')).catch(() => {}); }}><Icon name="copy" size={14} /></button>
            </div>
            <button className="btn btn-ghost btn-sm" style={{ marginTop: '0.6rem' }} onClick={() => setFresh('')}>I have copied it</button>
          </div>
        </div>
      )}
      <Panel
        title="Personal access tokens"
        desc="Use a token to call the SOCIS-AI-PT API from scripts and CI. A token acts with your permissions."
        end={<button className="btn btn-primary btn-sm" onClick={() => setOpen(true)}><Icon name="plus" size={14} /> Create token</button>}
      >
        {tokens === null ? (
          <div className="help" style={{ padding: '1.25rem' }}>Loading…</div>
        ) : tokens.length === 0 ? (
          <div className="help" style={{ padding: '1.5rem 1.25rem', textAlign: 'center' }}>No tokens yet. Create one to use the API from a script.</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="tbl">
              <thead><tr><th>Name</th><th>Created</th><th>Last used</th><th>Expires</th><th>Status</th><th /></tr></thead>
              <tbody>
                {tokens.map((t) => {
                  const st = statusOf(t);
                  return (
                    <tr key={t.id}>
                      <td><div className="who"><span className="av" style={{ borderRadius: 8 }}><Icon name="key" size={14} /></span><div><b>{t.name}</b><small className="mono">{t.prefix}…</small></div></div></td>
                      <td>{fmtDate(t.created_at)}</td>
                      <td>{timeAgo(t.last_used_at)}</td>
                      <td>{t.expires_at ? fmtDate(t.expires_at) : 'Never'}</td>
                      <td><Pill tone={st.tone} dot>{st.text}</Pill></td>
                      <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                        <button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => regenerate(t)}>Regenerate</button>
                        {st.text === 'Active' && <button className="btn btn-ghost btn-sm" style={{ color: 'var(--red)', marginLeft: 6 }} onClick={() => revoke(t)}>Revoke</button>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <div className="help" style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start', padding: '0 0.25rem' }}>
        <Icon name="info" size={14} style={{ marginTop: 2 }} />Tokens cannot create or revoke other tokens. Revoke any token you no longer recognise.
      </div>

      <Modal open={open} title="Create token" onClose={() => setOpen(false)} width={460}
        footer={<><button className="btn btn-ghost" onClick={() => setOpen(false)}>Cancel</button><button className="btn btn-primary" disabled={!name.trim() || busy} onClick={create}>Create token</button></>}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div><label className="lab" htmlFor="tk-name" style={{ display: 'block', marginBottom: 6 }}>Name</label>
            <input id="tk-name" className="input" placeholder="e.g. CI pipeline" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} /></div>
          <div><label className="lab" htmlFor="tk-exp" style={{ display: 'block', marginBottom: 6 }}>Expiry</label>
            <select id="tk-exp" className="input" value={expiry} onChange={(e) => setExpiry(Number(e.target.value))}>
              {EXPIRY.map((x, i) => <option key={x.label} value={i}>{x.label}</option>)}</select></div>
        </div>
      </Modal>
    </>
  );
}
