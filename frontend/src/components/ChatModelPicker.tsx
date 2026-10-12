'use client';

/**
 * ChatModelPicker — the single compact "model" chip in the AI chat toolbar (replaces two stacked dropdowns).
 * Click it to choose a provider and a model. Choosing saves it as your default (the chat already did that on every change);
 * the star shows when the current choice is your saved default.
 */

import { useEffect, useRef, useState } from 'react';
import Icon from '@/components/ui/Icon';
import type { LLMProviderOption } from '@/components/LLMProviderSelector';
import { normalizeProvider } from '@/lib/providers';

const TYPE_LABEL: Record<string, string> = { local: 'Local', remote: 'Remote', cloud: 'Cloud' };

export default function ChatModelPicker({
  providers, loading, provider, model, isDefault, onProviderChange, onModelChange,
}: {
  providers: LLMProviderOption[];
  loading: boolean;
  provider: string;
  model: string;
  isDefault: boolean;
  onProviderChange: (id: string, defaultModel: string) => void;
  onModelChange: (model: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey); };
  }, [open]);

  const current = providers.find((p) => normalizeProvider(p.id) === normalizeProvider(provider));
  const models = current?.models ?? [];

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        type="button" className="sel pick-btn" aria-haspopup="dialog" aria-expanded={open}
        aria-label={`Model: ${model || 'none selected'}. Change provider or model`}
        onClick={() => setOpen((o) => !o)}
      >
        <Icon name="globe" size={14} />
        <b className="mono" style={{ fontSize: '0.74rem' }}>{model || (loading ? 'Loading…' : 'Choose a model')}</b>
        {isDefault && model && <Icon name="star" size={13} style={{ color: 'var(--amber)', fill: 'var(--amber)' }} />}
        <Icon name="chevd" size={13} />
      </button>

      {open && (
        <div className="pick-pop" role="dialog" aria-label="Choose provider and model">
          <div className="pick-grp">Provider</div>
          {loading && providers.length === 0 && <div className="pick-empty">Loading…</div>}
          {!loading && providers.length === 0 && <div className="pick-empty">No providers are configured. An administrator can add one in Administration.</div>}
          {providers.map((p) => {
            const on = normalizeProvider(p.id) === normalizeProvider(provider);
            return (
              <button
                key={p.id} type="button" className={`pick-row${on ? ' on' : ''}`} disabled={!p.connected} aria-pressed={on}
                onClick={() => { if (!on) onProviderChange(p.id, p.default_model ?? p.models[0] ?? ''); }}
              >
                <i className="pick-dot" style={{ background: p.connected ? 'var(--green)' : 'var(--text-muted)' }} />
                <span className="pick-name">{p.label}</span>
                <span className="pick-tag">{p.connected ? (TYPE_LABEL[p.icon] ?? '') : 'Not configured'}</span>
              </button>
            );
          })}

          {models.length > 0 && (
            <>
              <div className="pick-grp">Model</div>
              <div style={{ maxHeight: 220, overflowY: 'auto' }}>
                {models.map((m) => (
                  <button
                    key={m} type="button" className={`pick-row${m === model ? ' on' : ''}`} aria-pressed={m === model}
                    onClick={() => { onModelChange(m); setOpen(false); }}
                  >
                    <span className="pick-name mono" style={{ fontSize: '0.78rem' }}>{m}</span>
                    {m === model && <Icon name="check" size={14} />}
                  </button>
                ))}
              </div>
            </>
          )}
          <div className="pick-foot"><Icon name="star" size={12} style={{ color: 'var(--amber)', fill: 'var(--amber)' }} /> Your choice is saved as your default.</div>
        </div>
      )}
    </div>
  );
}
