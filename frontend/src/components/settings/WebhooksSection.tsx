'use client';

import { useCallback, useEffect, useState } from 'react';
import { webhooksApi } from '@/lib/api';
import type { WebhookItem } from '@/lib/api';
import Panel, { Pill } from '@/components/ui/Panel';
import Modal from '@/components/ui/Modal';
import Toggle from '@/components/ui/Toggle';
import Icon from '@/components/ui/Icon';
import { SectionHead } from '@/components/settings/SettingsShell';
import { askConfirm, notify } from '@/lib/dialogs';
import { apiError } from '@/lib/errors';

interface EventInfo { name: string; description: string }

export default function WebhooksSection() {
  const [hooks, setHooks] = useState<WebhookItem[] | null>(null);
  const [events, setEvents] = useState<EventInfo[]>([]);
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState('');
  const [desc, setDesc] = useState('');
  const [secret, setSecret] = useState('');
  const [sel, setSel] = useState<string[]>(['scan.completed']);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    webhooksApi.list().then((r) => setHooks(r.data)).catch(() => { setHooks([]); notify('Could not load webhooks', 'error'); });
  }, []);
  useEffect(() => { load(); webhooksApi.events().then((r) => setEvents(r.data.events)).catch(() => {}); }, [load]);

  const create = async () => {
    setBusy(true);
    try {
      await webhooksApi.create({ url: url.trim(), events: sel, secret: secret.trim() || undefined, description: desc.trim() || undefined });
      setOpen(false); setUrl(''); setDesc(''); setSecret(''); setSel(['scan.completed']); load();
      notify('Webhook added', 'success');
    } catch (e) { notify(apiError(e, 'Could not add the webhook'), 'error'); }
    finally { setBusy(false); }
  };
  const toggle = async (h: WebhookItem, v: boolean) => {
    try { await webhooksApi.update(h.id, { is_active: v }); load(); } catch (e) { notify(apiError(e, 'Could not update the webhook'), 'error'); }
  };
  const test = async (h: WebhookItem) => {
    try {
      const r = await webhooksApi.ping(h.id);
      const res = r.data.results[0];
      if (res?.ok) notify(`Test delivered (HTTP ${res.status})`, 'success');
      else notify(`Test failed: ${res?.error ?? `HTTP ${res?.status ?? '?'}`}`, 'error');
    } catch (e) { notify(apiError(e, 'Could not send the test'), 'error'); }
  };
  const remove = async (h: WebhookItem) => {
    const ok = await askConfirm(`Delete the webhook for ${h.url}?`, { title: 'Delete webhook', confirmLabel: 'Delete', danger: true });
    if (!ok) return;
    try { await webhooksApi.remove(h.id); load(); } catch (e) { notify(apiError(e, 'Could not delete the webhook'), 'error'); }
  };
  const flip = (name: string) => setSel((s) => (s.includes(name) ? s.filter((x) => x !== name) : [...s, name]));

  return (
    <>
      <SectionHead title="Webhooks" desc="Send a signed HTTP POST to your own system when something happens, for example to open a ticket when a scan finds a critical issue." />
      <Panel
        title="Your webhooks"
        desc="Each delivery is signed with HMAC-SHA256 in the X-SOCIS-Signature-256 header when you set a secret."
        end={<button className="btn btn-primary btn-sm" onClick={() => setOpen(true)}><Icon name="plus" size={14} /> Add webhook</button>}
      >
        {hooks === null ? <div className="help" style={{ padding: '1.25rem' }}>Loading…</div>
          : hooks.length === 0 ? <div className="help" style={{ padding: '1.5rem 1.25rem', textAlign: 'center' }}>No webhooks yet.</div>
          : hooks.map((h) => (
            <div key={h.id} className="prov">
              <span className="lg"><Icon name="plug" size={16} /></span>
              <div style={{ minWidth: 0 }}>
                <h4 style={{ wordBreak: 'break-all' }}>{h.url}</h4>
                <small>{h.description ? `${h.description} · ` : ''}{h.events.join(', ')}</small>
              </div>
              <div className="end">
                <Pill tone={h.is_active ? 'green' : 'gray'} dot>{h.is_active ? 'Active' : 'Paused'}</Pill>
                <Toggle label={`Enable ${h.url}`} checked={h.is_active} onChange={(v) => toggle(h, v)} />
                <button className="btn btn-ghost btn-sm" onClick={() => test(h)}>Send test</button>
                <button className="icon-btn" aria-label="Delete webhook" style={{ color: 'var(--red)' }} onClick={() => remove(h)}><Icon name="trash" size={15} /></button>
              </div>
            </div>
          ))}
      </Panel>
      <div className="help" style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start', padding: '0 0.25rem' }}>
        <Icon name="info" size={14} style={{ marginTop: 2 }} />Addresses on private or internal networks are not allowed. Deliveries have a 10 second timeout and are not retried.
      </div>

      <Modal open={open} title="Add webhook" onClose={() => setOpen(false)} width={520}
        footer={<><button className="btn btn-ghost" onClick={() => setOpen(false)}>Cancel</button>
          <button className="btn btn-primary" disabled={busy || !url.trim() || sel.length === 0} onClick={create}>Add webhook</button></>}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div><label className="lab" htmlFor="wh-url" style={{ display: 'block', marginBottom: 6 }}>Endpoint URL</label>
            <input id="wh-url" className="input" type="url" placeholder="https://example.com/hooks/socis" value={url} onChange={(e) => setUrl(e.target.value)} /></div>
          <div><span className="lab" style={{ display: 'block', marginBottom: 6 }}>Events</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
              {events.map((ev) => (
                <label key={ev.name} style={{ display: 'flex', gap: '0.6rem', alignItems: 'flex-start', cursor: 'pointer', fontSize: '0.8125rem' }}>
                  <input type="checkbox" checked={sel.includes(ev.name)} onChange={() => flip(ev.name)} style={{ marginTop: 3 }} />
                  <span><span className="mono">{ev.name}</span><br /><span className="help">{ev.description}</span></span>
                </label>
              ))}
            </div></div>
          <div><label className="lab" htmlFor="wh-secret" style={{ display: 'block', marginBottom: 6 }}>Signing secret (optional)</label>
            <input id="wh-secret" className="input" type="password" autoComplete="new-password" value={secret} onChange={(e) => setSecret(e.target.value)} />
            <div className="help" style={{ marginTop: 4 }}>Stored encrypted and never shown again.</div></div>
          <div><label className="lab" htmlFor="wh-desc" style={{ display: 'block', marginBottom: 6 }}>Description (optional)</label>
            <input id="wh-desc" className="input" value={desc} maxLength={120} onChange={(e) => setDesc(e.target.value)} /></div>
        </div>
      </Modal>
    </>
  );
}
