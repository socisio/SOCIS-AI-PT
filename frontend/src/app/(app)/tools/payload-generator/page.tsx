'use client';

import React, { useState, useEffect, useCallback, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { Wand2, Download, Copy, Loader2, CheckCheck, Sparkles, FileCode2, ShieldAlert, AlertTriangle } from 'lucide-react';
import { AiModelSelector, LLMProviderOption } from '@/components/LLMProviderSelector';

const VULN_TYPES = [
  { value: 'sqli',            label: 'SQL Injection',                  color: 'var(--orange)' },
  { value: 'xss',             label: 'Cross-Site Scripting (XSS)',     color: 'var(--amber)' },
  { value: 'lfi',             label: 'Local File Inclusion (LFI)',     color: 'var(--red)' },
  { value: 'rce',             label: 'Remote Code Execution (RCE)',    color: 'var(--red)' },
  { value: 'ssrf',            label: 'Server-Side Request Forgery',    color: 'var(--orange)' },
  { value: 'xxe',             label: 'XML External Entity (XXE)',      color: 'var(--purple)' },
  { value: 'ssti',            label: 'Template Injection (SSTI)',      color: 'var(--red)' },
  { value: 'open_redirect',   label: 'Open Redirect',                  color: 'var(--amber)' },
  { value: 'idor',            label: 'IDOR',                           color: 'var(--amber)' },
  { value: 'csrf',            label: 'Cross-Site Request Forgery',     color: 'var(--blue)' },
  { value: 'path_traversal',  label: 'Path Traversal',                 color: 'var(--orange)' },
  { value: 'header_injection',label: 'HTTP Header Injection',          color: 'var(--text-secondary)' },
];

// LLMProviderOption imported from @/components/LLMProviderSelector

interface GenerateResult {
  vuln_type: string;
  description: string;
  cve_id: string | null;
  source: string;
  count: number;
  payloads: string[];
  ai_available: boolean;
}

interface WordlistResult {
  total: number;
  ai_augmented: boolean;
  wordlist: string;
}

const inputStyle: React.CSSProperties = {
  width: '100%',
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-md)',
  padding: '0.6rem 0.875rem',
  color: 'var(--text-primary)',
  fontSize: '0.875rem',
  fontFamily: 'var(--font-sans)',
  outline: 'none',
  transition: 'border-color 0.2s, box-shadow 0.2s',
};

const labelStyle: React.CSSProperties = {
  display: 'block',
  fontSize: '0.78rem',
  fontWeight: 500,
  color: 'var(--text-secondary)',
  marginBottom: '0.375rem',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
};

// AiModelSelector imported from @/components/LLMProviderSelector

// The page reads ?tab= via useSearchParams(), which needs a <Suspense> boundary for `next build` (dev mode never complains).
export default function PayloadGeneratorRoute() {
  return (
    <Suspense fallback={null}>
      <PayloadGeneratorPage />
    </Suspense>
  );
}

function PayloadGeneratorPage() {
  const [vulnType, setVulnType]               = useState('sqli');
  const [targetContext, setTargetContext]      = useState('');
  const [cveId, setCveId]                     = useState('');
  const [count, setCount]                     = useState(10);
  const [useAi, setUseAi]                     = useState(true);
  const [aiProvider, setAiProvider]           = useState('');
  const [aiModel, setAiModel]                 = useState('');
  const [aiBaseUrl, setAiBaseUrl]             = useState('');
  const [wordlistTypes, setWordlistTypes]      = useState<string[]>(['sqli', 'xss']);
  const [includeAi, setIncludeAi]             = useState(false);
  const [wlAiProvider, setWlAiProvider]       = useState('');
  const [wlAiModel, setWlAiModel]             = useState('');
  const [wlAiBaseUrl, setWlAiBaseUrl]         = useState('');
  const [llmProviders, setLlmProviders]       = useState<LLMProviderOption[]>([]);
  const [loadingProviders, setLoadingProviders] = useState(false);
  const [result, setResult]                   = useState<GenerateResult | null>(null);
  const [wordlistResult, setWordlistResult]   = useState<WordlistResult | null>(null);
  const [loading, setLoading]                 = useState(false);
  const [wordlistLoading, setWordlistLoading] = useState(false);
  const [error, setError]                     = useState('');
  const [wordlistError, setWordlistError]     = useState('');
  const [copiedAll, setCopiedAll]             = useState(false);
  const [copiedIdx, setCopiedIdx]             = useState<number | null>(null);

  const searchParams = useSearchParams();
  const activeTab = (searchParams.get('tab') ?? 'generator') as 'generator' | 'wordlist';

  const fetchLlmOptions = useCallback(async () => {
    setLoadingProviders(true);
    try {
      const resp = await fetch('/api/v1/tools/payload-generator/llm-options', { credentials: 'include' });
      if (resp.ok) {
        const data = await resp.json();
        const opts: LLMProviderOption[] = data.providers ?? [];
        setLlmProviders(opts);
        // Auto-select first connected provider
        const first = opts.find(p => p.connected);
        if (first) {
          setAiProvider(p => p || first.id);
          setAiModel(m => m || first.default_model || (first.models[0] ?? ''));
          setAiBaseUrl(u => u || first.url || '');
          setWlAiProvider(p => p || first.id);
          setWlAiModel(m => m || first.default_model || (first.models[0] ?? ''));
          setWlAiBaseUrl(u => u || first.url || '');
        }
      }
    } catch { /* silently ignore */ }
    finally { setLoadingProviders(false); }
  }, []);

  useEffect(() => { fetchLlmOptions(); }, [fetchLlmOptions]);

  function handleProviderChange(pid: string, defaultModel: string, url: string) {
    setAiProvider(pid);
    setAiModel(defaultModel);
    setAiBaseUrl(url);
  }

  function handleWlProviderChange(pid: string, defaultModel: string, url: string) {
    setWlAiProvider(pid);
    setWlAiModel(defaultModel);
    setWlAiBaseUrl(url);
  }

  const activeProviderMeta = llmProviders.find(p => p.id === aiProvider);

  async function handleGenerate(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const resp = await fetch('/api/v1/tools/payload-generator/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          vuln_type: vulnType,
          target_context: targetContext || undefined,
          cve_id: cveId || undefined,
          count,
          use_ai: useAi,
          ai_provider: aiProvider,
          ai_model: aiModel || undefined,
          ai_base_url: aiBaseUrl || undefined,
        }),
      });
      if (!resp.ok) { const e = await resp.json().catch(() => ({})); throw new Error(e.detail || `HTTP ${resp.status}`); }
      setResult(await resp.json());
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to generate payloads');
    } finally { setLoading(false); }
  }

  async function handleWordlist(e: React.FormEvent) {
    e.preventDefault();
    setWordlistLoading(true);
    setWordlistError('');
    setWordlistResult(null);
    try {
      const resp = await fetch('/api/v1/tools/payload-generator/wordlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          vuln_types: wordlistTypes,
          include_ai: includeAi,
          deduplicate: true,
          ai_provider: wlAiProvider,
          ai_model: wlAiModel || undefined,
          ai_base_url: wlAiBaseUrl || undefined,
        }),
      });
      if (!resp.ok) { const e = await resp.json().catch(() => ({})); throw new Error(e.detail || `HTTP ${resp.status}`); }
      setWordlistResult(await resp.json());
    } catch (err: unknown) {
      setWordlistError(err instanceof Error ? err.message : 'Failed to generate wordlist');
    } finally { setWordlistLoading(false); }
  }

  function copyPayload(text: string, idx: number) {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 1800);
  }

  function copyAll() {
    if (!result) return;
    navigator.clipboard.writeText(result.payloads.join('\n')).catch(() => {});
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 2000);
  }

  function downloadWordlist() {
    if (!wordlistResult) return;
    const blob = new Blob([wordlistResult.wordlist], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `socis-wordlist-${wordlistTypes.join('-')}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function toggleWordlistType(vtype: string) {
    setWordlistTypes(prev => prev.includes(vtype) ? prev.filter(t => t !== vtype) : [...prev, vtype]);
  }

  const selectedVuln = VULN_TYPES.find(v => v.value === vulnType);

  return (
    <div className="animate-fadeIn" style={{ padding: '2rem', width: '100%' }}>

      {/* ── Page Header ─────────────────────────────────────── */}
      <div style={{ marginBottom: '1.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.375rem' }}>
          <div style={{
            width: 36, height: 36, borderRadius: 'var(--radius-md)',
            background: 'color-mix(in srgb, var(--cyan) 13%, transparent)',
            border: '1px solid var(--border-glow)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Wand2 size={18} style={{ color: 'var(--cyan)' }} />
          </div>
          <div>
            <h1 style={{ margin: 0, color: 'var(--text-primary)' }}>
              Payload Generator
            </h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', margin: 0 }}>
              AI-augmented security payloads & wordlist builder for penetration testing
            </p>
          </div>
        </div>
      </div>

      {/* ── Main Layout ─────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: '1.5rem', alignItems: 'start' }}>

        {/* ── Left Column ─────────────────────────────────── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>

          {/* ── Generator form ──────────────────────────── */}
          {activeTab === 'generator' && (
            <div className="card" style={{ padding: '1.5rem' }}>
              <form onSubmit={handleGenerate} style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>

                {/* Vuln type */}
                <div>
                  <label style={labelStyle}>Vulnerability Type</label>
                  <select
                    value={vulnType}
                    onChange={e => setVulnType(e.target.value)}
                    className="input"
                    style={{ ...inputStyle, cursor: 'pointer' }}
                  >
                    {VULN_TYPES.map(vt => (
                      <option key={vt.value} value={vt.value}>{vt.label}</option>
                    ))}
                  </select>
                  {selectedVuln && (
                    <div style={{
                      marginTop: '0.375rem', display: 'inline-flex', alignItems: 'center', gap: 4,
                      fontSize: '0.75rem', padding: '2px 8px', borderRadius: 999,
                      background: `color-mix(in srgb, ${selectedVuln.color} 9%, transparent)`, color: selectedVuln.color,
                      border: `1px solid color-mix(in srgb, ${selectedVuln.color} 27%, transparent)`,
                    }}>
                      <ShieldAlert size={10} />
                      {selectedVuln.label}
                    </div>
                  )}
                </div>

                {/* Target context */}
                <div>
                  <label style={labelStyle}>
                    Target Context
                    <span style={{ color: 'var(--text-muted)', fontWeight: 400, textTransform: 'none', marginLeft: 4 }}>(optional)</span>
                  </label>
                  <input
                    type="text"
                    value={targetContext}
                    onChange={e => setTargetContext(e.target.value)}
                    placeholder="e.g. login form on PHP Laravel app"
                    className="input"
                    style={inputStyle}
                  />
                </div>

                {/* CVE ID */}
                <div>
                  <label style={labelStyle}>
                    CVE ID
                    <span style={{ color: 'var(--text-muted)', fontWeight: 400, textTransform: 'none', marginLeft: 4 }}>(optional)</span>
                  </label>
                  <input
                    type="text"
                    value={cveId}
                    onChange={e => setCveId(e.target.value)}
                    placeholder="e.g. CVE-2021-44228"
                    className="input"
                    style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                  />
                </div>

                {/* Count */}
                <div>
                  <label style={labelStyle}>Payload Count</label>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <input
                      type="range"
                      min={1} max={100} value={count}
                      onChange={e => setCount(Number(e.target.value))}
                      style={{ flex: 1, accentColor: 'var(--cyan)' }}
                    />
                    <span style={{
                      minWidth: 38, textAlign: 'center', fontFamily: 'var(--font-mono)',
                      fontSize: '0.875rem', color: 'var(--cyan)', fontWeight: 600,
                      background: 'var(--cyan-glow)', border: '1px solid var(--border-glow)',
                      borderRadius: 'var(--radius-sm)', padding: '2px 6px',
                    }}>{count}</span>
                  </div>
                </div>

                {/* AI Enhancement card */}
                <div style={{
                  borderRadius: 'var(--radius-md)',
                  border: `1px solid ${useAi ? 'var(--border-glow)' : 'var(--border)'}`,
                  background: useAi ? 'linear-gradient(135deg, rgba(15,240,252,0.05), rgba(15,240,252,0.02))' : 'var(--bg-secondary)',
                  overflow: 'hidden',
                  transition: 'border-color 0.2s, background 0.2s',
                }}>
                  {/* Toggle header */}
                  <label style={{
                    display: 'flex', alignItems: 'center', gap: '0.75rem',
                    padding: '0.75rem 1rem', cursor: 'pointer',
                    borderBottom: useAi ? '1px solid var(--border-glow)' : '1px solid transparent',
                    transition: 'border-color 0.2s',
                  }}>
                    <input
                      type="checkbox" checked={useAi}
                      onChange={e => setUseAi(e.target.checked)}
                      style={{ accentColor: 'var(--cyan)', width: 15, height: 15 }}
                    />
                    <Sparkles size={14} style={{ color: useAi ? 'var(--cyan)' : 'var(--text-muted)', flexShrink: 0 }} />
                    <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: useAi ? 'var(--cyan)' : 'var(--text-secondary)', flex: 1 }}>
                      AI Enhancement
                    </span>
                    {useAi && activeProviderMeta && (
                      <span style={{
                        display: 'flex', alignItems: 'center', gap: 4,
                        fontSize: '0.6875rem', padding: '2px 8px', borderRadius: 999,
                        background: activeProviderMeta.connected ? 'rgba(34,197,94,0.1)' : 'rgba(248,113,113,0.1)',
                        border: `1px solid ${activeProviderMeta.connected ? 'color-mix(in srgb, var(--green) 25%, transparent)' : 'color-mix(in srgb, var(--red) 25%, transparent)'}`,
                        color: activeProviderMeta.connected ? 'var(--green)' : 'var(--red)', fontWeight: 600,
                      }}>
                        <span style={{ width: 5, height: 5, borderRadius: '50%', background: activeProviderMeta.connected ? 'var(--chart-green)' : 'var(--chart-red)' }} />
                        {activeProviderMeta.label}
                      </span>
                    )}
                  </label>

                  {/* Inline model selector */}
                  {useAi && (
                    <div style={{ padding: '0.875rem 1rem' }}>
                      <AiModelSelector
                        id="gen"
                        providers={llmProviders}
                        loadingProviders={loadingProviders}
                        selectedProvider={aiProvider}
                        selectedModel={aiModel}
                        onProviderChange={handleProviderChange}
                        onModelChange={setAiModel}
                      />
                    </div>
                  )}
                </div>

                {error && (
                  <div style={{
                    display: 'flex', alignItems: 'flex-start', gap: '0.5rem',
                    padding: '0.75rem', borderRadius: 'var(--radius-md)',
                    background: 'color-mix(in srgb, var(--red) 7%, transparent)', border: '1px solid color-mix(in srgb, var(--red) 19%, transparent)', color: 'var(--red)',
                    fontSize: '0.8125rem',
                  }}>
                    <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: 1 }} />
                    {error}
                  </div>
                )}

                <button
                  type="submit" disabled={loading}
                  className="btn btn-primary"
                  style={{ width: '100%', justifyContent: 'center', padding: '0.625rem', opacity: loading ? 0.65 : 1 }}
                >
                  {loading ? <Loader2 size={15} className="animate-spin" /> : <Wand2 size={15} />}
                  {loading ? 'Generating…' : 'Generate Payloads'}
                </button>
              </form>
            </div>
          )}

          {/* ── Wordlist Builder form ────────────────────── */}
          {activeTab === 'wordlist' && (
            <div className="card" style={{ padding: '1.5rem' }}>
              <form onSubmit={handleWordlist} style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>

                <div>
                  <label style={labelStyle}>Select Vulnerability Types</label>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.375rem', marginTop: '0.25rem' }}>
                    {VULN_TYPES.map(vt => {
                      const checked = wordlistTypes.includes(vt.value);
                      return (
                        <label key={vt.value} style={{
                          display: 'flex', alignItems: 'center', gap: 6,
                          padding: '0.4rem 0.6rem', borderRadius: 'var(--radius-sm)', cursor: 'pointer',
                          background: checked ? `color-mix(in srgb, ${vt.color} 9%, transparent)` : 'var(--bg-secondary)',
                          border: `1px solid ${checked ? `color-mix(in srgb, ${vt.color} 33%, transparent)` : 'var(--border)'}`,
                          transition: 'all 0.15s', fontSize: '0.75rem',
                          color: checked ? vt.color : 'var(--text-secondary)',
                        }}>
                          <input
                            type="checkbox" checked={checked}
                            onChange={() => toggleWordlistType(vt.value)}
                            style={{ accentColor: vt.color, width: 12, height: 12 }}
                          />
                          {vt.label}
                        </label>
                      );
                    })}
                  </div>
                </div>

                {/* Wordlist AI Enhancement card */}
                <div style={{
                  borderRadius: 'var(--radius-md)',
                  border: `1px solid ${includeAi ? 'var(--border-glow)' : 'var(--border)'}`,
                  background: includeAi ? 'linear-gradient(135deg, rgba(15,240,252,0.05), rgba(15,240,252,0.02))' : 'var(--bg-secondary)',
                  overflow: 'hidden',
                  transition: 'border-color 0.2s, background 0.2s',
                }}>
                  {/* Toggle header */}
                  <label style={{
                    display: 'flex', alignItems: 'center', gap: '0.75rem',
                    padding: '0.75rem 1rem', cursor: 'pointer',
                    borderBottom: includeAi ? '1px solid var(--border-glow)' : '1px solid transparent',
                    transition: 'border-color 0.2s',
                  }}>
                    <input
                      type="checkbox" checked={includeAi}
                      onChange={e => setIncludeAi(e.target.checked)}
                      style={{ accentColor: 'var(--cyan)', width: 15, height: 15 }}
                    />
                    <Sparkles size={14} style={{ color: includeAi ? 'var(--cyan)' : 'var(--text-muted)', flexShrink: 0 }} />
                    <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: includeAi ? 'var(--cyan)' : 'var(--text-secondary)', flex: 1 }}>
                      AI-generated variants
                    </span>
                    {includeAi && (() => { const p = llmProviders.find(p => p.id === wlAiProvider); return p ? (
                      <span style={{
                        display: 'flex', alignItems: 'center', gap: 4,
                        fontSize: '0.6875rem', padding: '2px 8px', borderRadius: 999,
                        background: p.connected ? 'rgba(34,197,94,0.1)' : 'rgba(248,113,113,0.1)',
                        border: `1px solid ${p.connected ? 'color-mix(in srgb, var(--green) 25%, transparent)' : 'color-mix(in srgb, var(--red) 25%, transparent)'}`,
                        color: p.connected ? 'var(--green)' : 'var(--red)', fontWeight: 600,
                      }}>
                        <span style={{ width: 5, height: 5, borderRadius: '50%', background: p.connected ? 'var(--chart-green)' : 'var(--chart-red)' }} />
                        {p.label}
                      </span>
                    ) : null; })()}
                  </label>

                  {/* Inline model selector */}
                  {includeAi && (
                    <div style={{ padding: '0.875rem 1rem' }}>
                      <AiModelSelector
                        id="wl"
                        providers={llmProviders}
                        loadingProviders={loadingProviders}
                        selectedProvider={wlAiProvider}
                        selectedModel={wlAiModel}
                        onProviderChange={handleWlProviderChange}
                        onModelChange={setWlAiModel}
                      />
                    </div>
                  )}
                </div>

                {wordlistError && (
                  <div style={{
                    display: 'flex', gap: '0.5rem', padding: '0.75rem', borderRadius: 'var(--radius-md)',
                    background: 'color-mix(in srgb, var(--red) 7%, transparent)', border: '1px solid color-mix(in srgb, var(--red) 19%, transparent)', color: 'var(--red)', fontSize: '0.8125rem',
                  }}>
                    <AlertTriangle size={14} style={{ flexShrink: 0, marginTop: 1 }} />
                    {wordlistError}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={wordlistLoading || wordlistTypes.length === 0}
                  className="btn"
                  style={{
                    width: '100%', justifyContent: 'center', padding: '0.625rem',
                    background: 'color-mix(in srgb, var(--green) 13%, transparent)',
                    border: '1px solid color-mix(in srgb, var(--green) 53%, transparent)', color: 'var(--green)',
                    opacity: (wordlistLoading || wordlistTypes.length === 0) ? 0.6 : 1,
                  }}
                >
                  {wordlistLoading ? <Loader2 size={15} className="animate-spin" /> : <Download size={15} />}
                  {wordlistLoading ? 'Building…' : `Build Wordlist${wordlistTypes.length > 0 ? ` (${wordlistTypes.length} types)` : ''}`}
                </button>
              </form>
            </div>
          )}
        </div>

        {/* ── Right Column: Results ────────────────────────── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>

          {/* ── Payload Results ──────────────────────────── */}
          {activeTab === 'generator' && (
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              {/* Results header */}
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '1rem 1.5rem',
                borderBottom: '1px solid var(--border)',
                background: 'linear-gradient(135deg, var(--bg-card), var(--bg-secondary))',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <FileCode2 size={16} style={{ color: 'var(--cyan)' }} />
                  <span style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-primary)' }}>
                    {result ? result.description : 'Payload Results'}
                  </span>
                  {result && (
                    <span style={{
                      fontSize: '0.75rem', padding: '2px 8px', borderRadius: 999,
                      background: 'var(--cyan-glow)', color: 'var(--cyan)',
                      border: '1px solid var(--border-glow)', fontFamily: 'var(--font-mono)',
                    }}>
                      {result.count} payloads
                    </span>
                  )}
                </div>

                {result && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
                    {result.source === 'ai+static' && (
                      <span style={{
                        display: 'flex', alignItems: 'center', gap: 4,
                        fontSize: '0.75rem', padding: '2px 8px', borderRadius: 999,
                        background: 'color-mix(in srgb, var(--purple) 13%, transparent)', color: 'var(--purple)',
                        border: '1px solid color-mix(in srgb, var(--purple) 27%, transparent)',
                      }}>
                        <Sparkles size={10} /> AI + Static
                      </span>
                    )}
                    {result.cve_id && (
                      <span style={{
                        fontSize: '0.75rem', padding: '2px 8px', borderRadius: 999,
                        background: 'color-mix(in srgb, var(--orange) 13%, transparent)', color: 'var(--orange)',
                        border: '1px solid color-mix(in srgb, var(--orange) 27%, transparent)', fontFamily: 'var(--font-mono)',
                      }}>
                        {result.cve_id}
                      </span>
                    )}
                    <button
                      onClick={copyAll}
                      className="btn btn-ghost"
                      style={{ padding: '4px 12px', fontSize: '0.75rem', gap: 4 }}
                    >
                      {copiedAll ? <CheckCheck size={13} /> : <Copy size={13} />}
                      {copiedAll ? 'Copied!' : 'Copy All'}
                    </button>
                  </div>
                )}
              </div>

              {/* Empty state */}
              {!result && !loading && (
                <div style={{
                  display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                  padding: '4rem 2rem', gap: '1rem',
                  color: 'var(--text-muted)', textAlign: 'center',
                }}>
                  <div style={{
                    width: 64, height: 64, borderRadius: '50%',
                    background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <Wand2 size={28} style={{ opacity: 0.3 }} />
                  </div>
                  <div>
                    <p style={{ fontWeight: 500, marginBottom: 4, color: 'var(--text-secondary)' }}>No payloads generated yet</p>
                    <p style={{ fontSize: '0.8125rem' }}>Configure the form and click Generate Payloads</p>
                  </div>
                </div>
              )}

              {/* Loading */}
              {loading && (
                <div style={{
                  display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                  padding: '4rem 2rem', gap: '0.875rem', color: 'var(--text-secondary)',
                }}>
                  <Loader2 size={32} style={{ color: 'var(--cyan)' }} className="animate-spin" />
                  <p style={{ fontSize: '0.875rem' }}>
                    Generating payloads{useAi ? ' with AI enhancement…' : '…'}
                  </p>
                </div>
              )}

              {/* Table */}
              {result && !loading && (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)' }}>
                        <th style={{ padding: '0.625rem 1rem', textAlign: 'left', width: 42, fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase' }}>#</th>
                        <th style={{ padding: '0.625rem 0.5rem', textAlign: 'left', fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase' }}>Payload</th>
                        <th style={{ padding: '0.625rem 1rem', width: 60 }}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.payloads.map((payload, idx) => (
                        <tr
                          key={idx}
                          style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.12s' }}
                          onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-hover)')}
                          onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                        >
                          <td style={{ padding: '0.5rem 1rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                            {String(idx + 1).padStart(2, '0')}
                          </td>
                          <td style={{ padding: '0.5rem 0.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', color: 'var(--green)', wordBreak: 'break-all' }}>
                            {payload}
                          </td>
                          <td style={{ padding: '0.5rem 1rem', textAlign: 'right' }}>
                            <button
                              onClick={() => copyPayload(payload, idx)}
                              title="Copy payload"
                              style={{
                                background: 'none', border: 'none', cursor: 'pointer', padding: 4,
                                color: copiedIdx === idx ? 'var(--cyan)' : 'var(--text-muted)',
                                borderRadius: 'var(--radius-sm)', transition: 'color 0.15s',
                              }}
                              onMouseEnter={e => { if (copiedIdx !== idx) e.currentTarget.style.color = 'var(--text-primary)'; }}
                              onMouseLeave={e => { if (copiedIdx !== idx) e.currentTarget.style.color = 'var(--text-muted)'; }}
                            >
                              {copiedIdx === idx ? <CheckCheck size={14} /> : <Copy size={14} />}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* ── Wordlist Results ─────────────────────────── */}
          {activeTab === 'wordlist' && (
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '1rem 1.5rem', borderBottom: '1px solid var(--border)',
                background: 'linear-gradient(135deg, var(--bg-card), var(--bg-secondary))',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <Download size={16} style={{ color: 'var(--green)' }} />
                  <span style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-primary)' }}>
                    Wordlist Output
                  </span>
                  {wordlistResult && (
                    <>
                      <span style={{
                        fontSize: '0.75rem', padding: '2px 8px', borderRadius: 999,
                        background: 'color-mix(in srgb, var(--green) 9%, transparent)', color: 'var(--green)', border: '1px solid color-mix(in srgb, var(--green) 27%, transparent)',
                        fontFamily: 'var(--font-mono)',
                      }}>
                        {wordlistResult.total} lines
                      </span>
                      {wordlistResult.ai_augmented && (
                        <span style={{
                          display: 'flex', alignItems: 'center', gap: 4,
                          fontSize: '0.75rem', padding: '2px 8px', borderRadius: 999,
                          background: 'color-mix(in srgb, var(--purple) 13%, transparent)', color: 'var(--purple)', border: '1px solid color-mix(in srgb, var(--purple) 27%, transparent)',
                        }}>
                          <Sparkles size={10} /> AI+
                        </span>
                      )}
                    </>
                  )}
                </div>
                {wordlistResult && (
                  <button onClick={downloadWordlist} className="btn btn-ghost" style={{ padding: '4px 12px', fontSize: '0.75rem', gap: 4, color: 'var(--green)', borderColor: 'color-mix(in srgb, var(--green) 33%, transparent)' }}>
                    <Download size={13} /> Download .txt
                  </button>
                )}
              </div>

              {!wordlistResult && !wordlistLoading && (
                <div style={{
                  display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                  padding: '4rem 2rem', gap: '1rem', color: 'var(--text-muted)', textAlign: 'center',
                }}>
                  <div style={{
                    width: 64, height: 64, borderRadius: '50%',
                    background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <Download size={28} style={{ opacity: 0.3 }} />
                  </div>
                  <div>
                    <p style={{ fontWeight: 500, marginBottom: 4, color: 'var(--text-secondary)' }}>No wordlist built yet</p>
                    <p style={{ fontSize: '0.8125rem' }}>Select vulnerability types and click Build Wordlist</p>
                  </div>
                </div>
              )}

              {wordlistLoading && (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '4rem 2rem', gap: '0.875rem', color: 'var(--text-secondary)' }}>
                  <Loader2 size={32} style={{ color: 'var(--green)' }} className="animate-spin" />
                  <p style={{ fontSize: '0.875rem' }}>Building wordlist{includeAi ? ' with AI variants…' : '…'}</p>
                </div>
              )}

              {wordlistResult && !wordlistLoading && (
                <textarea
                  readOnly
                  value={wordlistResult.wordlist}
                  style={{
                    display: 'block', width: '100%', minHeight: 480,
                    background: 'var(--bg-primary)', border: 'none', outline: 'none', resize: 'vertical',
                    fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', lineHeight: 1.7,
                    color: 'var(--green)', padding: '1rem 1.5rem',
                  }}
                />
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
