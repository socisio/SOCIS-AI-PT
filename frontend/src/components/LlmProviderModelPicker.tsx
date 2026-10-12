'use client';
import { Loader2, RefreshCw } from 'lucide-react';
import type { LLMProviderOption } from '@/components/LLMProviderSelector';
import { normalizeProvider, providerLabel } from '@/lib/providers';

/**
 * Compact, inline provider + model picker — two plain dropdowns, for embedding inside a panel (Findings' Analyze
 * section, the Workflow LLM node's config). NOT the toolbar-styled popover in ChatModelPicker.tsx, which is built
 * specifically for the AI Chat header; this is the plain-field version for everywhere else.
 *
 * Deliberately stateless/controlled: the caller owns provider/model state (via useLlmProviders) and decides what,
 * if anything, to persist when they change — this component only renders the two dropdowns and reports changes up.
 */
export default function LlmProviderModelPicker({
  providers,
  provider,
  model,
  loading,
  onProviderChange,
  onModelChange,
  onRefresh,
  disabled,
  compact,
}: {
  providers: LLMProviderOption[];
  provider: string;
  model: string;
  loading: boolean;
  onProviderChange: (id: string) => void;
  onModelChange: (model: string) => void;
  onRefresh?: () => void;
  disabled?: boolean;
  compact?: boolean;
}) {
  const current = providers.find((p) => normalizeProvider(p.id) === normalizeProvider(provider));
  const models = current?.models ?? [];
  const fieldStyle = { fontSize: compact ? '0.75rem' : '0.8125rem', padding: compact ? '0.35rem 0.5rem' : undefined };

  return (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 140 }}>
        {!compact && <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Provider</label>}
        <select
          className="input"
          value={normalizeProvider(provider)}
          onChange={(e) => onProviderChange(e.target.value)}
          disabled={disabled || loading}
          style={fieldStyle}
        >
          {providers.length === 0 && <option value={normalizeProvider(provider)}>{providerLabel(provider)}</option>}
          {providers.map((p) => (
            <option key={p.id} value={normalizeProvider(p.id)}>{p.label}</option>
          ))}
        </select>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 160, flex: 1 }}>
        {!compact && <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Model</label>}
        <div style={{ display: 'flex', gap: 4 }}>
          {models.length > 0 ? (
            <select
              className="input"
              value={model}
              onChange={(e) => onModelChange(e.target.value)}
              disabled={disabled || loading}
              style={{ ...fieldStyle, flex: 1 }}
            >
              {!model && <option value="">— select model —</option>}
              {models.map((m) => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          ) : (
            <input
              className="input"
              value={model}
              placeholder={loading ? 'Loading…' : 'exact model name'}
              onChange={(e) => onModelChange(e.target.value)}
              disabled={disabled || loading}
              style={{ ...fieldStyle, flex: 1 }}
            />
          )}
          {onRefresh && (
            <button
              type="button"
              onClick={onRefresh}
              disabled={loading}
              title="Refresh provider/model list"
              className="btn btn-ghost"
              style={{ padding: '0.3rem 0.5rem' }}
            >
              {loading ? <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> : <RefreshCw size={12} />}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
