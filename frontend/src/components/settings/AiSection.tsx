'use client';

import { useEffect, useState } from 'react';
import { settingsApi } from '@/lib/api';
import { fetchLlmOptions } from '@/components/LLMProviderSelector';
import type { LLMProviderOption } from '@/components/LLMProviderSelector';
import Panel, { Pill } from '@/components/ui/Panel';
import Icon from '@/components/ui/Icon';
import { SectionHead } from '@/components/settings/SettingsShell';
import { notify } from '@/lib/dialogs';
import { apiError } from '@/lib/errors';
import { normalizeProvider } from '@/lib/providers';

const TYPE_LABEL: Record<string, string> = { local: 'Local', remote: 'Remote server', cloud: 'Cloud' };

/**
 * AI providers: which provider and model the AI chat starts with. This is the same default the star in the chat saves.
 * (Older versions also stored personal API keys here. Nothing ever used them, so they were removed and purged: providers and
 * their credentials are managed by an administrator.)
 */
export default function AiSection() {
  const [opts, setOpts] = useState<LLMProviderOption[] | null>(null);
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [openId, setOpenId] = useState('');
  const [pick, setPick] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetchLlmOptions().then(setOpts);
    settingsApi.getLlmSettings().then((r) => setCfg((r.data ?? {}) as Record<string, unknown>)).catch(() => {});
  }, []);

  const defProvider = normalizeProvider(typeof cfg.chat_provider === 'string' ? cfg.chat_provider : null);
  const defModel = typeof cfg.chat_model === 'string' ? cfg.chat_model : '';

  const makeDefault = async (p: LLMProviderOption, model: string) => {
    setBusy(true);
    try {
      const next = { ...cfg, chat_provider: p.id, chat_model: model };
      await settingsApi.saveLlmSettings(next);
      setCfg(next);
      notify(`${p.label} · ${model} is now your default`, 'success');
    } catch (e) { notify(apiError(e, 'Could not save your default'), 'error'); }
    finally { setBusy(false); }
  };

  return (
    <>
      <SectionHead title="AI providers" desc="Choose the provider and model the AI chat starts with. Providers and their credentials are managed by an administrator." />
      <Panel title="Providers" desc="Pick a connected provider, then the model to use by default.">
        {opts === null ? <div className="help" style={{ padding: '1.25rem' }}>Loading…</div>
          : opts.length === 0 ? <div className="help" style={{ padding: '1.5rem 1.25rem', textAlign: 'center' }}>No AI providers are configured yet. An administrator can add one in Administration.</div>
          : opts.map((p) => {
            const isDef = normalizeProvider(p.id) === defProvider;
            const open = openId === p.id && p.connected;
            const model = pick[p.id] ?? (isDef && defModel ? defModel : p.default_model ?? p.models[0] ?? '');
            return (
              <div key={p.id}>
                <div className="prov" style={{ cursor: p.connected ? 'pointer' : 'default' }} onClick={() => p.connected && setOpenId(open ? '' : p.id)}>
                  <span className="lg">{p.label.charAt(0).toUpperCase()}</span>
                  <div><h4>{p.label}</h4><small>{TYPE_LABEL[p.icon] ?? 'Provider'}{p.models.length ? ` · ${p.models.length} model${p.models.length === 1 ? '' : 's'}` : ''}</small></div>
                  <div className="end">
                    {isDef && <Pill tone="blue">Your default{defModel ? ` · ${defModel}` : ''}</Pill>}
                    <Pill tone={p.connected ? 'green' : 'gray'} dot>{p.connected ? 'Connected' : 'Not configured'}</Pill>
                    {p.connected && <Icon name={open ? 'chevd' : 'chevr'} size={15} style={{ color: 'var(--text-muted)' }} />}
                  </div>
                </div>
                {open && (
                  <div className="expand" style={{ gridTemplateColumns: '1fr auto' }}>
                    <div>
                      <label htmlFor={`m-${p.id}`}>Model</label>
                      <select id={`m-${p.id}`} className="input" value={model} onChange={(e) => setPick({ ...pick, [p.id]: e.target.value })}>
                        {p.models.map((m) => <option key={m} value={m}>{m}</option>)}
                      </select>
                    </div>
                    <div style={{ alignSelf: 'end' }}>
                      <button className="btn btn-primary btn-sm" disabled={busy || !model || (isDef && model === defModel)} onClick={() => makeDefault(p, model)}>
                        {isDef && model === defModel ? 'Current default' : 'Use as my default'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
      </Panel>
    </>
  );
}
