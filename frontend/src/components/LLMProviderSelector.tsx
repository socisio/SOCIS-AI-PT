'use client';
import React from 'react';
import { Server, Wifi, Cloud, Loader2, AlertTriangle, ChevronDown } from 'lucide-react';

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? '';

export interface LLMProviderOption {
  id: string;
  label: string;
  icon: 'local' | 'remote' | 'cloud';
  connected: boolean;
  models: string[];
  default_model?: string;
  url?: string;
}

export async function fetchLlmOptions(): Promise<LLMProviderOption[]> {
  try {
    const res = await fetch(`${API_BASE}/api/v1/tools/payload-generator/llm-options`, {
      credentials: 'include',
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.providers ?? [];
  } catch {
    return [];
  }
}

// ── Icons ────────────────────────────────────────────────────────────────────

function ProviderIcon({ icon, size = 15 }: { icon: string; size?: number }) {
  if (icon === 'local')  return <Server size={size} style={{ color: 'var(--cyan)' }} />;
  if (icon === 'remote') return <Wifi   size={size} style={{ color: 'var(--purple)' }} />;
  return <Cloud size={size} style={{ color: 'var(--orange)' }} />;
}

// ── Type badge colors ─────────────────────────────────────────────────────────

const TYPE_META: Record<string, { label: string; bg: string; border: string; color: string }> = {
  local:  { label: 'LOCAL',  bg: 'rgba(15,240,252,0.08)',  border: 'color-mix(in srgb, var(--cyan) 19%, transparent)', color: 'var(--cyan)' },
  remote: { label: 'REMOTE', bg: 'rgba(167,139,250,0.08)', border: 'color-mix(in srgb, var(--purple) 19%, transparent)', color: 'var(--purple)' },
  cloud:  { label: 'CLOUD',  bg: 'rgba(249,115,22,0.08)',  border: 'color-mix(in srgb, var(--orange) 19%, transparent)', color: 'var(--orange)' },
};

// ── Category ordering ─────────────────────────────────────────────────────────

const ICON_ORDER: Record<string, number> = { local: 0, remote: 1, cloud: 2 };

function sortProviders(providers: LLMProviderOption[]) {
  return [...providers].sort((a, b) => {
    const oa = ICON_ORDER[a.icon] ?? 99;
    const ob = ICON_ORDER[b.icon] ?? 99;
    return oa !== ob ? oa - ob : a.label.localeCompare(b.label);
  });
}

// ── Provider card (card-grid layout) ─────────────────────────────────────────

interface ProviderCardProps {
  prov: LLMProviderOption;
  selected: boolean;
  onSelect: () => void;
}

function ProviderCard({ prov, selected, onSelect }: ProviderCardProps) {
  const typeMeta = TYPE_META[prov.icon] ?? TYPE_META.cloud;
  return (
    <button
      type="button"
      onClick={onSelect}
      disabled={!prov.connected}
      style={{
        display: 'flex', alignItems: 'center', gap: '0.6rem',
        padding: '0.5rem 0.75rem',
        background: selected ? 'rgba(15,240,252,0.06)' : 'transparent',
        border: `1px solid ${selected ? 'var(--border-glow)' : 'var(--border)'}`,
        borderRadius: 'var(--radius-md)', cursor: prov.connected ? 'pointer' : 'not-allowed',
        transition: 'all 0.15s', textAlign: 'left', width: '100%',
        opacity: prov.connected ? 1 : 0.45,
      }}
    >
      <ProviderIcon icon={prov.icon} size={14} />
      <span style={{ flex: 1, fontSize: '0.8125rem', fontWeight: 500, color: selected ? 'var(--cyan)' : 'var(--text-primary)' }}>
        {prov.label}
      </span>
      {/* Type badge */}
      <span style={{
        fontSize: '0.6875rem', fontWeight: 700, letterSpacing: '0.07em',
        padding: '1px 6px', borderRadius: 99,
        background: typeMeta.bg, border: `1px solid ${typeMeta.border}`, color: typeMeta.color,
      }}>
        {typeMeta.label}
      </span>
      {/* Status dot */}
      <span style={{
        width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
        background: prov.connected ? 'var(--chart-green)' : 'var(--chart-red)',
        boxShadow: prov.connected ? '0 0 4px color-mix(in srgb, var(--green) 53%, transparent)' : 'none',
      }} />
    </button>
  );
}

// ── Main selector component ───────────────────────────────────────────────────

export interface AiModelSelectorProps {
  providers: LLMProviderOption[];
  loadingProviders: boolean;
  selectedProvider: string;
  selectedModel: string;
  onProviderChange: (id: string, defaultModel: string, url: string) => void;
  onModelChange: (model: string) => void;
  id: string;
  /** Use compact single-row dropdown UI instead of card-grid (default: false) */
  compact?: boolean;
}

export function AiModelSelector({
  providers, loadingProviders, selectedProvider, selectedModel,
  onProviderChange, onModelChange, id, compact = false,
}: AiModelSelectorProps) {
  const sorted = sortProviders(providers);
  const prov = providers.find(p => p.id === selectedProvider);
  const models = prov?.models ?? [];
  const effectiveModel = selectedModel || prov?.default_model || models[0] || '';

  const selectStyle: React.CSSProperties = {
    appearance: 'none',
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 8,
    color: 'var(--text-primary)',
    fontSize: '0.82rem',
    padding: '0.45rem 2rem 0.45rem 0.75rem',
    cursor: 'pointer',
    outline: 'none',
    minWidth: 0,
    width: '100%',
  };

  // ── Loading ────────────────────────────────────────────────────────────────
  if (loadingProviders) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
        <Loader2 size={13} className="animate-spin" /> Fetching configured providers…
      </div>
    );
  }

  // ── Empty state ────────────────────────────────────────────────────────────
  if (providers.length === 0) {
    return (
      <div style={{
        padding: '0.65rem 0.875rem', borderRadius: 'var(--radius-md)',
        background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)',
        color: 'var(--red)', fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: 6,
      }}>
        <AlertTriangle size={13} />
        No LLM providers configured — add one in{' '}
        <a href="/admin" style={{ color: 'var(--cyan)', textDecoration: 'underline', marginLeft: 2 }}>
          Admin → LLM Config
        </a>.
      </div>
    );
  }

  // ── Compact (single-row dropdown) — used by AI Chat header ────────────────
  if (compact) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
        {/* Provider dropdown */}
        <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
          <span style={{ position: 'absolute', left: 9, pointerEvents: 'none', display: 'flex', alignItems: 'center', zIndex: 1 }}>
            {prov ? <ProviderIcon icon={prov.icon} /> : <Server size={15} style={{ color: 'var(--text-muted)' }} />}
          </span>
          <select
            id={`${id}-provider`}
            value={selectedProvider}
            onChange={e => {
              const next = providers.find(p => p.id === e.target.value);
              if (next) onProviderChange(next.id, next.default_model ?? '', next.url ?? '');
            }}
            style={{ ...selectStyle, paddingLeft: '2.1rem' }}
          >
            {sorted.map(p => (
              <option key={p.id} value={p.id} disabled={!p.connected}>
                [{TYPE_META[p.icon]?.label ?? p.icon.toUpperCase()}] {p.label}{!p.connected ? ' (Offline)' : ''}
              </option>
            ))}
          </select>
          <ChevronDown size={13} style={{ position: 'absolute', right: 8, pointerEvents: 'none', color: 'var(--text-muted)' }} />
        </div>

        {/* Model + status row */}
        <ModelRow id={id} prov={prov} effectiveModel={effectiveModel} models={models} selectStyle={selectStyle} onModelChange={onModelChange} />
      </div>
    );
  }

  // ── Full card-grid layout (default) — used by Payload Generator & Wordlist ─
  const localProviders  = sorted.filter(p => p.icon === 'local');
  const remoteProviders = sorted.filter(p => p.icon === 'remote');
  const cloudProviders  = sorted.filter(p => p.icon === 'cloud');

  const groups: { key: string; label: string; items: LLMProviderOption[] }[] = [
    { key: 'local',  label: 'Local',  items: localProviders  },
    { key: 'remote', label: 'Remote', items: remoteProviders },
    { key: 'cloud',  label: 'Cloud',  items: cloudProviders  },
  ].filter(g => g.items.length > 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>

      {/* Section label */}
      <div style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
        Provider
      </div>

      {/* Provider groups */}
      {groups.map(group => {
        const meta = TYPE_META[group.key] ?? TYPE_META.cloud;
        return (
          <div key={group.key}>
            {/* Group header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.35rem' }}>
              <ProviderIcon icon={group.key} size={11} />
              <span style={{ fontSize: '0.6875rem', fontWeight: 700, color: meta.color, textTransform: 'uppercase', letterSpacing: '0.07em' }}>
                {group.label}
              </span>
              <span style={{ flex: 1, height: 1, background: meta.border }} />
            </div>
            {/* Provider cards */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              {group.items.map(p => (
                <ProviderCard
                  key={p.id}
                  prov={p}
                  selected={selectedProvider === p.id}
                  onSelect={() => onProviderChange(p.id, p.default_model ?? '', p.url ?? '')}
                />
              ))}
            </div>
          </div>
        );
      })}

      {/* Model row */}
      {prov && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
          <div style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Model
          </div>
          <ModelRow id={id} prov={prov} effectiveModel={effectiveModel} models={models} selectStyle={selectStyle} onModelChange={onModelChange} />
        </div>
      )}
    </div>
  );
}

// ── Shared model row ──────────────────────────────────────────────────────────

function ModelRow({
  id, prov, effectiveModel, models, selectStyle, onModelChange,
}: {
  id: string;
  prov: LLMProviderOption | undefined;
  effectiveModel: string;
  models: string[];
  selectStyle: React.CSSProperties;
  onModelChange: (m: string) => void;
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
      {/* Status pill */}
      <span style={{
        flexShrink: 0, display: 'flex', alignItems: 'center', gap: 4,
        fontSize: '0.6875rem', padding: '2px 8px', borderRadius: 99,
        background: prov?.connected ? 'rgba(74,222,128,0.1)' : 'rgba(248,113,113,0.1)',
        border: `1px solid ${prov?.connected ? 'color-mix(in srgb, var(--green) 25%, transparent)' : 'color-mix(in srgb, var(--red) 25%, transparent)'}`,
        color: prov?.connected ? 'var(--green)' : 'var(--red)',
      }}>
        <span style={{ width: 5, height: 5, borderRadius: '50%', background: prov?.connected ? 'var(--chart-green)' : 'var(--chart-red)' }} />
        {prov?.connected ? 'Online' : 'Offline'}
      </span>

      {/* Model dropdown */}
      {prov && prov.connected && models.length > 0 ? (
        <div style={{ position: 'relative', flex: 1 }}>
          <select
            id={`${id}-model`}
            value={effectiveModel}
            onChange={e => onModelChange(e.target.value)}
            style={{ ...selectStyle, fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}
          >
            {models.map(m => (
              <option key={m} value={m}>
                {m}{m === prov.default_model ? ' ★' : ''}
              </option>
            ))}
          </select>
          <ChevronDown size={13} style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none', color: 'var(--text-muted)' }} />
        </div>
      ) : prov && prov.connected ? (
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          No models — <a href="/admin" style={{ color: 'var(--cyan)', textDecoration: 'underline' }}>Admin → LLM Config</a>
        </span>
      ) : null}
    </div>
  );
}
