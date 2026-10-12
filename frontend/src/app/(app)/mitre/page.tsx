'use client';
import { useState, useEffect, useCallback } from 'react';
import {
  Target, Search, Users, Shield, ChevronRight, X, Download,
  RefreshCw, AlertTriangle, Loader2, Layers,
} from 'lucide-react';
import { mcpApi } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────

interface Technique {
  id: string;
  name: string;
  description?: string;
  tactics: string[];
  platforms: string[];
  is_subtechnique?: boolean;
  detection?: string;
  data_sources?: string[];
  permissions_required?: string[];
  revoked?: boolean;
}

interface Group {
  id: string;
  name: string;
  description?: string;
  aliases: string[];
}

interface Software {
  id: string;
  name: string;
  type?: string;
  description?: string;
  platforms?: string[];
  aliases?: string[];
}

interface Mitigation {
  id: string;
  name: string;
  description?: string;
}

interface Tactic {
  id: string;
  name: string;
  shortname: string;
  description?: string;
}

type TabType = 'matrix' | 'search' | 'actors' | 'navigator';

// ─── ATT&CK Tactic order (official) ───────────────────────────
const TACTIC_ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
  // Mobile (its 'credential-access' tactic is the one listed above; keys must be unique)
  'network-based', 'remote-service-abuse',
  // ICS
  'inhibit-response-function', 'impair-process-control',
];

const PLATFORMS = ['Windows', 'macOS', 'Linux', 'Cloud', 'Azure AD', 'Office 365', 'SaaS', 'IaaS', 'Network', 'Containers', 'Android', 'iOS', 'Field Controller/RTU/PLC/IED', 'Engineering Workstation', 'Historian', 'HMI', 'Control Server', 'Data Historian'];

const DOMAIN_OPTIONS = [
  { value: 'enterprise', label: 'Enterprise', badge: 'IT/Cloud', color: 'var(--cyan)' },
  { value: 'mobile', label: 'Mobile', badge: 'Android/iOS', color: 'var(--blue)' },
  { value: 'ics', label: 'ICS/OT', badge: 'Industrial', color: 'var(--amber)' },
];

type Domain = 'enterprise' | 'mobile' | 'ics';

// ─── MCP call helper ─────────────────────────────────────────

async function callMitre(tool: string, args: Record<string, unknown> = {}) {
  const res = await mcpApi.callTool('mitre_mcp', { tool, arguments: args });
  const content = res.data?.result?.content?.[0]?.text;
  if (!content) throw new Error('No response from MITRE MCP');
  return JSON.parse(content);
}

// ─── Domain Selector ──────────────────────────────────────────

function DomainSelector({ domain, onChange }: { domain: Domain; onChange: (d: Domain) => void }) {
  return (
    <div style={{ display: 'flex', gap: 6 }}>
      {DOMAIN_OPTIONS.map(opt => (
        <button key={opt.value} onClick={() => onChange(opt.value as Domain)}
          style={{
            padding: '4px 12px', borderRadius: 99, fontSize: '0.75rem', fontWeight: 600,
            border: `1px solid ${domain === opt.value ? opt.color : 'var(--border)'}`,
            background: domain === opt.value ? `color-mix(in srgb, ${opt.color} 9%, transparent)` : 'transparent',
            color: domain === opt.value ? opt.color : 'var(--text-muted)',
            cursor: 'pointer', transition: 'all 0.15s',
          }}>
          {opt.label} <span style={{ fontSize: '0.6875rem', opacity: 0.75 }}>{opt.badge}</span>
        </button>
      ))}
    </div>
  );
}

// ─── Detail Panel ─────────────────────────────────────────────

function TechniquePanel({ technique, domain, onClose }: { technique: Technique; domain: Domain; onClose: () => void }) {
  const [mitigations, setMitigations] = useState<Mitigation[]>([]);
  const [loadingMit, setLoadingMit] = useState(false);

  useEffect(() => {
    if (!technique.id) return;
    setLoadingMit(true);
    callMitre('get_mitigations_for_technique', { technique_id: technique.id, domain })
      .then(d => setMitigations(d.mitigations || []))
      .catch(() => setMitigations([]))
      .finally(() => setLoadingMit(false));
  }, [technique.id, domain]);

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'flex-start', justifyContent: 'flex-end',
    }} onClick={onClose}>
      <div
        style={{
          width: 480, height: '100vh', overflowY: 'auto',
          background: 'var(--bg-secondary)', borderLeft: '1px solid var(--border)',
          padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--cyan)', fontWeight: 700 }}>
              {technique.id}
            </span>
            <h2 style={{ fontSize: '1rem', fontWeight: 700, marginTop: 4 }}>{technique.name}</h2>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}>
            <X size={18} />
          </button>
        </div>

        {/* Tactics */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {technique.tactics.map(t => (
            <span key={t} style={{
              fontSize: '0.6875rem', fontWeight: 600, padding: '2px 8px', borderRadius: 99,
              background: 'rgba(15,240,252,0.12)', color: 'var(--cyan)', border: '1px solid rgba(15,240,252,0.25)',
              textTransform: 'uppercase', letterSpacing: '0.04em',
            }}>{t}</span>
          ))}
        </div>

        {/* Platforms */}
        {technique.platforms?.length > 0 && (
          <div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Platforms</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {technique.platforms.map(p => (
                <span key={p} style={{
                  fontSize: '0.6875rem', padding: '2px 7px', borderRadius: 'var(--radius-sm)',
                  background: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border)',
                }}>{p}</span>
              ))}
            </div>
          </div>
        )}

        {/* Description */}
        {technique.description && (
          <div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Description</div>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.65 }}>{technique.description}</p>
          </div>
        )}

        {/* Detection */}
        {technique.detection && (
          <div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Detection</div>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{technique.detection}</p>
          </div>
        )}

        {/* Data Sources */}
        {(technique.data_sources?.length ?? 0) > 0 && (
          <div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Data Sources</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {(technique.data_sources ?? []).slice(0, 8).map((ds, i) => (
                <span key={i} style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>• {ds}</span>
              ))}
            </div>
          </div>
        )}

        {/* Mitigations */}
        <div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Mitigations {loadingMit && <Loader2 size={10} style={{ display: 'inline', animation: 'spin 1s linear infinite' }} />}
          </div>
          {mitigations.length === 0 && !loadingMit
            ? <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>No specific mitigations listed</span>
            : mitigations.map(m => (
              <div key={m.id} style={{ marginBottom: 8, padding: '0.5rem 0.75rem', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)' }}>
                <div style={{ fontWeight: 600, fontSize: '0.8125rem', color: 'var(--cyan)' }}>{m.id} — {m.name}</div>
                {m.description && <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: 3, lineHeight: 1.55 }}>{m.description.slice(0, 200)}{m.description.length > 200 ? '…' : ''}</div>}
              </div>
            ))
          }
        </div>

        {/* Link removed — all data served in-platform */}
      </div>
    </div>
  );
}

// ─── Matrix Tab ───────────────────────────────────────────────

function MatrixTab({ domain }: { domain: Domain }) {
  const [tactics, setTactics] = useState<Tactic[]>([]);
  const [techniquesByTactic, setTechniquesByTactic] = useState<Record<string, Technique[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<Technique | null>(null);
  const [platformFilter, setPlatformFilter] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [tacticsData, techData] = await Promise.all([
        callMitre('get_all_tactics'),
        callMitre('get_all_techniques'),
      ]);
      const rawTactics: Tactic[] = tacticsData.tactics || [];
      // Sort by official tactic order
      const ordered = [...rawTactics].sort((a, b) => {
        const ai = TACTIC_ORDER.indexOf(a.shortname);
        const bi = TACTIC_ORDER.indexOf(b.shortname);
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
      });
      setTactics(ordered);

      const techniques: Technique[] = techData.techniques || [];
      const byTactic: Record<string, Technique[]> = {};
      for (const t of techniques) {
        for (const tactic of t.tactics) {
          const key = tactic.toLowerCase().replace(/ /g, '-');
          if (!byTactic[key]) byTactic[key] = [];
          byTactic[key].push(t);
        }
      }
      setTechniquesByTactic(byTactic);
    } catch (e: any) {
      setError(e?.message || 'Failed to load ATT&CK matrix. Ensure MITRE MCP server is online.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300, gap: 12, color: 'var(--text-muted)' }}>
      <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} /> Loading ATT&amp;CK matrix...
    </div>
  );

  if (error) return (
    <div style={{ display: 'flex', gap: 10, padding: '1rem 1.25rem', background: 'color-mix(in srgb, var(--red) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--red) 19%, transparent)', borderRadius: 'var(--radius-lg)', color: 'var(--red)', fontSize: '0.875rem' }}>
      <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: 1 }} /> {error}
    </div>
  );

  return (
    <div>
      {/* Platform filter */}
      <div style={{ display: 'flex', gap: 8, marginBottom: '1rem', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Filter platform:</span>
        {['', ...PLATFORMS.slice(0, 6)].map(p => (
          <button key={p} onClick={() => setPlatformFilter(p)}
            className={platformFilter === p ? 'btn btn-primary' : 'btn btn-ghost'}
            style={{ fontSize: '0.75rem', padding: '3px 10px' }}>
            {p || 'All'}
          </button>
        ))}
      </div>

      {/* Matrix grid */}
      <div style={{ overflowX: 'auto', paddingBottom: '1rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: `repeat(${tactics.length}, minmax(140px, 1fr))`, gap: 6, minWidth: 1400 }}>
          {/* Tactic headers */}
          {tactics.map(tactic => (
            <div key={tactic.shortname} style={{
              padding: '0.5rem 0.6rem', background: 'rgba(15,240,252,0.08)',
              border: '1px solid rgba(15,240,252,0.2)', borderRadius: 'var(--radius-md)', textAlign: 'center',
            }}>
              <div style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--cyan)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                {tactic.name}
              </div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: 2 }}>
                {(techniquesByTactic[tactic.shortname] || []).length} techniques
              </div>
            </div>
          ))}

          {/* Technique cells */}
          {tactics.map(tactic => {
            const techs = (techniquesByTactic[tactic.shortname] || []).filter(t =>
              !platformFilter || t.platforms.some(p => p.toLowerCase() === platformFilter.toLowerCase())
            );
            return (
              <div key={tactic.shortname} style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {techs.map(tech => (
                  <button key={tech.id} onClick={() => setSelected(tech)}
                    style={{
                      background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                      borderRadius: 'var(--radius-sm)', padding: '5px 7px', cursor: 'pointer', textAlign: 'left',
                      transition: 'all 0.15s',
                    }}
                    onMouseEnter={e => {
                      (e.currentTarget as HTMLButtonElement).style.background = 'rgba(15,240,252,0.08)';
                      (e.currentTarget as HTMLButtonElement).style.borderColor = 'rgba(15,240,252,0.4)';
                    }}
                    onMouseLeave={e => {
                      (e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-secondary)';
                      (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--border)';
                    }}
                  >
                    <div style={{ fontSize: '0.6875rem', color: 'var(--cyan)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{tech.id}</div>
                    <div style={{ fontSize: '0.6875rem', color: 'var(--text-primary)', marginTop: 1, lineHeight: 1.3 }}>{tech.name}</div>
                  </button>
                ))}
              </div>
            );
          })}
        </div>
      </div>

      {selected && <TechniquePanel technique={selected} domain={domain} onClose={() => setSelected(null)} />}
    </div>
  );
}

// ─── Search Tab ───────────────────────────────────────────────

function SearchTab({ domain }: { domain: Domain }) {
  const [query, setQuery] = useState('');
  const [platformFilter, setPlatformFilter] = useState('');
  const [tacticFilter, setTacticFilter] = useState('');
  const [results, setResults] = useState<Technique[]>([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [selected, setSelected] = useState<Technique | null>(null);

  const search = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setSearched(true);
    try {
      let data;
      // ATT&CK ID lookup
      if (/^T\d{4}/.test(query.trim().toUpperCase())) {
        data = await callMitre('get_technique_by_id', { technique_id: query.trim(), domain });
        setResults(data.error ? [] : [data]);
      } else {
        data = await callMitre('search_techniques', { query: query.trim(), limit: 40, domain });
        let res: Technique[] = data.results || [];
        if (platformFilter) res = res.filter(t => t.platforms.some(p => p.toLowerCase() === platformFilter.toLowerCase()));
        if (tacticFilter) res = res.filter(t => t.tactics.some(tc => tc.toLowerCase().replace(/ /g, '-') === tacticFilter));
        setResults(res);
      }
    } catch {
      setResults([]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {/* Search bar */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && search()}
          placeholder="Search techniques (name, description, or T1055)…"
          style={{
            flex: 1, minWidth: 260, padding: '0.6rem 0.875rem', borderRadius: 'var(--radius-md)',
            border: '1px solid var(--border)', background: 'var(--bg-secondary)',
            color: 'var(--text-primary)', fontSize: '0.875rem',
          }}
        />
        <select value={platformFilter} onChange={e => setPlatformFilter(e.target.value)}
          style={{ padding: '0.6rem 0.75rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: '0.8125rem' }}>
          <option value="">All Platforms</option>
          {PLATFORMS.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        <select value={tacticFilter} onChange={e => setTacticFilter(e.target.value)}
          style={{ padding: '0.6rem 0.75rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: '0.8125rem' }}>
          <option value="">All Tactics</option>
          {Array.from(new Set(TACTIC_ORDER)).map(t => <option key={t} value={t}>{t.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</option>)}
        </select>
        <button onClick={search} disabled={loading} className="btn btn-primary" style={{ gap: 6 }}>
          {loading ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Search size={14} />}
          Search
        </button>
      </div>

      {/* Results */}
      {searched && !loading && results.length === 0 && (
        <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', padding: '2rem', textAlign: 'center' }}>No techniques found.</div>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {results.map(tech => (
          <div key={tech.id} className="card" style={{ padding: '0.875rem 1.1rem', border: '1px solid var(--border)', cursor: 'pointer' }}
            onClick={() => setSelected(tech)}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--cyan)', fontWeight: 700 }}>{tech.id}</span>
                  {tech.is_subtechnique && <span style={{ fontSize: '0.6875rem', padding: '1px 6px', borderRadius: 99, background: 'rgba(96,165,250,0.15)', color: 'var(--blue)', border: '1px solid rgba(96,165,250,0.3)' }}>sub-technique</span>}
                  {tech.revoked && <span style={{ fontSize: '0.6875rem', padding: '1px 6px', borderRadius: 99, background: 'color-mix(in srgb, var(--red) 13%, transparent)', color: 'var(--red)' }}>revoked</span>}
                </div>
                <div style={{ fontWeight: 600, fontSize: '0.875rem', marginBottom: 4 }}>{tech.name}</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 4 }}>
                  {tech.tactics.map(t => (
                    <span key={t} style={{ fontSize: '0.6875rem', padding: '1px 7px', borderRadius: 99, background: 'rgba(15,240,252,0.1)', color: 'var(--cyan)', border: '1px solid rgba(15,240,252,0.2)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{t}</span>
                  ))}
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {tech.platforms.slice(0, 5).map(p => (
                    <span key={p} style={{ fontSize: '0.6875rem', padding: '1px 6px', borderRadius: 'var(--radius-sm)', background: 'var(--bg-tertiary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>{p}</span>
                  ))}
                </div>
              </div>
              <ChevronRight size={16} style={{ color: 'var(--text-muted)', flexShrink: 0, marginTop: 4 }} />
            </div>
            {tech.description && (
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 6, lineHeight: 1.55 }}>
                {tech.description.slice(0, 200)}{tech.description.length > 200 ? '…' : ''}
              </p>
            )}
            {tech.detection && (
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.5, borderTop: '1px solid var(--border)', paddingTop: 6 }}>
                <span style={{ fontWeight: 600, color: 'var(--text-secondary)', marginRight: 4 }}>Detection:</span>
                {tech.detection.slice(0, 160)}{tech.detection.length > 160 ? '…' : ''}
              </p>
            )}
          </div>
        ))}
      </div>

      {selected && <TechniquePanel technique={selected} domain={domain} onClose={() => setSelected(null)} />}
    </div>
  );
}

// ─── Threat Actors Tab ────────────────────────────────────────

function ActorsTab({ domain }: { domain: Domain }) {
  const [groups, setGroups] = useState<Group[]>([]);
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Group | null>(null);
  const [profile, setProfile] = useState<{ techniques: Technique[]; software: Software[] } | null>(null);
  const [loadingProfile, setLoadingProfile] = useState(false);

  useEffect(() => {
    setGroups([]);
    setLoading(true);
    setSelected(null);
    setProfile(null);
    callMitre('get_all_groups', { domain })
      .then(d => setGroups(d.groups || []))
      .catch(() => setGroups([]))
      .finally(() => setLoading(false));
  }, [domain]);

  const loadProfile = async (group: Group) => {
    setSelected(group);
    setLoadingProfile(true);
    try {
      const [techData, softData] = await Promise.all([
        callMitre('get_techniques_used_by_group', { group_id: group.id, domain }),
        callMitre('get_software_used_by_group', { group_id: group.id, domain }),
      ]);
      setProfile({ techniques: techData.techniques || [], software: softData.software || [] });
    } catch {
      setProfile({ techniques: [], software: [] });
    } finally {
      setLoadingProfile(false);
    }
  };

  const filtered = groups.filter(g =>
    !query || g.name.toLowerCase().includes(query.toLowerCase()) ||
    g.aliases.some(a => a.toLowerCase().includes(query.toLowerCase()))
  );

  return (
    <div style={{ display: 'flex', gap: '1.25rem' }}>
      {/* Group list */}
      <div style={{ width: 280, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <input value={query} onChange={e => setQuery(e.target.value)}
          placeholder="Search groups or aliases…"
          style={{ padding: '0.55rem 0.875rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: '0.8125rem', width: '100%' }}
        />
        {loading && <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', padding: '1rem', textAlign: 'center' }}><Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /></div>}
        <div style={{ maxHeight: 600, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4 }}>
          {filtered.map(g => (
            <button key={g.id} onClick={() => loadProfile(g)}
              style={{
                textAlign: 'left', padding: '0.6rem 0.75rem', borderRadius: 'var(--radius-md)', border: '1px solid',
                borderColor: selected?.id === g.id ? 'rgba(15,240,252,0.5)' : 'var(--border)',
                background: selected?.id === g.id ? 'rgba(15,240,252,0.08)' : 'var(--bg-secondary)',
                cursor: 'pointer', width: '100%',
              }}>
              <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>{g.name}</div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: 2 }}>
                {g.id} {g.aliases.length > 0 && `· ${g.aliases.slice(0, 2).join(', ')}`}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Profile panel */}
      <div style={{ flex: 1, minWidth: 0 }}>
        {!selected && (
          <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', padding: '3rem', textAlign: 'center' }}>
            <Users size={40} style={{ margin: '0 auto 1rem', opacity: 0.3 }} />
            Select a group to view their profile
          </div>
        )}
        {selected && (
          <div className="card" style={{ border: '1px solid var(--border)', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--cyan)', fontWeight: 700 }}>{selected.id}</div>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 700, marginTop: 4 }}>{selected.name}</h2>
                {selected.aliases.length > 0 && (
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>
                    Also known as: {selected.aliases.join(', ')}
                  </div>
                )}
              </div>
            </div>
            {selected.description && (
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.65 }}>
                {selected.description.slice(0, 500)}{selected.description.length > 500 ? '…' : ''}
              </p>
            )}

            {loadingProfile && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> Loading TTPs and software…
              </div>
            )}

            {profile && !loadingProfile && (
              <>
                {/* Techniques */}
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.8125rem', marginBottom: 8, color: 'var(--text-secondary)' }}>
                    Techniques Used ({profile.techniques.length})
                  </div>
                  <div style={{ maxHeight: 260, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {profile.techniques.map(t => (
                      <div key={t.id} style={{ display: 'flex', gap: 8, padding: '5px 8px', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-sm)', fontSize: '0.75rem' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)', fontWeight: 700, flexShrink: 0 }}>{t.id}</span>
                        <span style={{ color: 'var(--text-primary)' }}>{t.name}</span>
                        <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: '0.6875rem' }}>{t.tactics[0]}</span>
                      </div>
                    ))}
                  </div>
                </div>
                {/* Software */}
                {profile.software.length > 0 && (
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.8125rem', marginBottom: 8, color: 'var(--text-secondary)' }}>
                      Software Used ({profile.software.length})
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {profile.software.map(s => (
                        <span key={s.id} style={{
                          fontSize: '0.75rem', padding: '3px 9px', borderRadius: 99,
                          background: s.type === 'malware' ? 'rgba(239,68,68,0.12)' : 'rgba(96,165,250,0.12)',
                          color: s.type === 'malware' ? 'var(--red)' : 'var(--blue)',
                          border: `1px solid ${s.type === 'malware' ? 'rgba(239,68,68,0.3)' : 'rgba(96,165,250,0.3)'}`,
                        }}>
                          {s.name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Navigator Tab ────────────────────────────────────────────

function NavigatorTab({ domain }: { domain: Domain }) {
  const [scope, setScope] = useState<'all' | 'group' | 'tactic' | 'platform'>('group');
  const [value, setValue] = useState('APT29');
  const [layerName, setLayerName] = useState('SOCIS Layer');
  const [color, setColor] = useState('#0ff0fc');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [layerData, setLayerData] = useState<{ layer: any; technique_count: number } | null>(null);
  const [heatmap, setHeatmap] = useState<{ tactics: Tactic[]; byTactic: Record<string, Technique[]>; highlightedIds: Set<string> } | null>(null);
  const [selectedTech, setSelectedTech] = useState<Technique | null>(null);

  const generate = async () => {
    setLoading(true);
    setError('');
    setLayerData(null);
    setHeatmap(null);
    try {
      const [layerResult, tacticsResult, techsResult] = await Promise.all([
        callMitre('generate_layer', { scope, value, name: layerName, color, domain }),
        callMitre('get_all_tactics', { domain }),
        callMitre('get_all_techniques', { domain }),
      ]);
      setLayerData(layerResult);

      // Build highlighted IDs: layer uses exact ATT&CK IDs (e.g. T1059.001 for
      // subtechniques). Since the heatmap shows parent techniques only, we also
      // add the parent ID for every subtechnique so the cell lights up correctly.
      const highlightedIds = new Set<string>();
      for (const t of (layerResult.layer?.techniques || []) as any[]) {
        const id: string = t.techniqueID;
        if (!id) continue;
        highlightedIds.add(id);
        if (id.includes('.')) highlightedIds.add(id.split('.')[0]); // T1059.001 → T1059
      }
      const rawTactics: Tactic[] = tacticsResult.tactics || [];
      const ordered = [...rawTactics].sort((a, b) => {
        const ai = TACTIC_ORDER.indexOf(a.shortname);
        const bi = TACTIC_ORDER.indexOf(b.shortname);
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
      });
      const byTactic: Record<string, Technique[]> = {};
      for (const t of (techsResult.techniques || []) as Technique[]) {
        for (const tactic of t.tactics) {
          const key = tactic.toLowerCase().replace(/ /g, '-');
          if (!byTactic[key]) byTactic[key] = [];
          byTactic[key].push(t);
        }
      }
      setHeatmap({ tactics: ordered, byTactic, highlightedIds });
    } catch (e: any) {
      setError(e?.message || 'Failed to generate layer');
    } finally {
      setLoading(false);
    }
  };

  const download = () => {
    if (!layerData) return;
    const blob = new Blob([JSON.stringify(layerData.layer, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${layerName.replace(/\s+/g, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const scopeLabels: Record<string, string> = {
    all: 'All Techniques',
    group: 'Threat Actor Group',
    tactic: 'Tactic',
    platform: 'Platform',
  };
  const scopePlaceholders: Record<string, string> = {
    all: '(no value needed)',
    group: 'e.g. APT29, Lazarus Group, G0016',
    tactic: 'e.g. initial-access, lateral-movement',
    platform: 'e.g. Windows, Linux, Android, ICS',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Form */}
      <div className="card" style={{ border: '1px solid var(--border)', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ fontWeight: 700, fontSize: '0.875rem', display: 'flex', alignItems: 'center', gap: 8 }}>
          <Layers size={15} color="var(--cyan)" /> Generate Layer
          <span style={{ fontSize: '0.75rem', fontWeight: 400, color: 'var(--text-muted)', marginLeft: 4 }}>Visualised in-platform — no external services</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div>
            <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Scope</label>
            <select value={scope} onChange={e => { setScope(e.target.value as any); setValue(''); }}
              style={{ width: '100%', padding: '0.55rem 0.75rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: '0.875rem' }}>
              {Object.entries(scopeLabels).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </div>
          <div>
            <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Value</label>
            <input value={value} onChange={e => setValue(e.target.value)}
              placeholder={scopePlaceholders[scope]}
              disabled={scope === 'all'}
              style={{ width: '100%', padding: '0.55rem 0.75rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: scope === 'all' ? 'var(--bg-tertiary)' : 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: '0.875rem', boxSizing: 'border-box' }}
            />
          </div>
          <div>
            <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Layer Name</label>
            <input value={layerName} onChange={e => setLayerName(e.target.value)}
              style={{ width: '100%', padding: '0.55rem 0.75rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: '0.875rem', boxSizing: 'border-box' }}
            />
          </div>
          <div>
            <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Highlight Color</label>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input type="color" value={color} onChange={e => setColor(e.target.value)}
                style={{ width: 40, height: 36, borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'none', cursor: 'pointer', padding: 2 }}
              />
              <input value={color} onChange={e => setColor(e.target.value)}
                style={{ flex: 1, padding: '0.55rem 0.75rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)', fontSize: '0.875rem' }}
              />
            </div>
          </div>
        </div>
        <button onClick={generate} disabled={loading || (scope !== 'all' && !value.trim())} className="btn btn-primary" style={{ alignSelf: 'flex-start', gap: 8 }}>
          {loading ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Target size={14} />}
          {loading ? 'Loading matrix…' : 'Generate & Visualise'}
        </button>
      </div>

      {error && (
        <div style={{ display: 'flex', gap: 10, padding: '0.875rem 1.1rem', background: 'color-mix(in srgb, var(--red) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--red) 19%, transparent)', borderRadius: 'var(--radius-lg)', color: 'var(--red)', fontSize: '0.8125rem' }}>
          <AlertTriangle size={15} style={{ flexShrink: 0 }} /> {error}
        </div>
      )}

      {/* In-platform heatmap */}
      {heatmap && layerData && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Stats bar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ width: 14, height: 14, borderRadius: 'var(--radius-sm)', background: color, flexShrink: 0 }} />
              <span style={{ fontWeight: 700, fontSize: '1rem' }}>{layerData.layer.name}</span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', padding: '2px 10px', borderRadius: 99, background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                {layerData.technique_count} (sub-)techniques &middot; {heatmap.highlightedIds.size} cells highlighted
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                {layerData.layer.domain}
              </span>
            </div>
            <button onClick={download} className="btn btn-primary" style={{ gap: 6 }}>
              <Download size={13} /> Download Layer JSON
            </button>
          </div>

          {/* Legend */}
          <div style={{ display: 'flex', gap: 16, fontSize: '0.75rem', color: 'var(--text-muted)', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <div style={{ width: 12, height: 12, borderRadius: 'var(--radius-sm)', background: color, opacity: 0.85 }} />
              Highlighted
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <div style={{ width: 12, height: 12, borderRadius: 'var(--radius-sm)', background: 'var(--bg-secondary)', border: '1px solid var(--border)' }} />
              Not in scope
            </div>
            <span style={{ marginLeft: 8 }}>Click any cell for technique details</span>
          </div>

          {/* Heatmap grid */}
          <div style={{ overflowX: 'auto', paddingBottom: '0.5rem' }}>
            <div style={{
              display: 'grid',
              gridTemplateColumns: `repeat(${heatmap.tactics.length}, minmax(130px, 1fr))`,
              gap: 5,
              minWidth: heatmap.tactics.length * 135,
            }}>
              {/* Tactic column headers */}
              {heatmap.tactics.map(tactic => {
                const all = heatmap.byTactic[tactic.shortname] || [];
                const highlighted = all.filter(t => heatmap.highlightedIds.has(t.id ?? ''));
                return (
                  <div key={tactic.shortname} style={{
                    padding: '6px 8px',
                    background: highlighted.length > 0 ? `color-mix(in srgb, ${color} 9%, transparent)` : 'color-mix(in srgb, var(--text-primary) 3%, transparent)',
                    border: `1px solid ${highlighted.length > 0 ? `color-mix(in srgb, ${color} 31%, transparent)` : 'var(--border)'}`,
                    borderRadius: 'var(--radius-md)',
                    textAlign: 'center',
                  }}>
                    <div style={{ fontSize: '0.6875rem', fontWeight: 700, color: highlighted.length > 0 ? color : 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', lineHeight: 1.3 }}>
                      {tactic.name}
                    </div>
                    <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: 2 }}>
                      {highlighted.length}/{all.length}
                    </div>
                  </div>
                );
              })}

              {/* Technique cells per tactic column */}
              {heatmap.tactics.map(tactic => {
                const techs = heatmap.byTactic[tactic.shortname] || [];
                return (
                  <div key={tactic.shortname} style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                    {techs.map(tech => {
                      const isHit = heatmap.highlightedIds.has(tech.id ?? '');
                      return (
                        <button
                          key={tech.id}
                          onClick={() => setSelectedTech(tech)}
                          style={{
                            padding: '5px 7px',
                            borderRadius: 'var(--radius-sm)',
                            border: `1px solid ${isHit ? `color-mix(in srgb, ${color} 38%, transparent)` : 'var(--border)'}`,
                            borderLeft: `3px solid ${isHit ? color : 'transparent'}`,
                            background: isHit ? `color-mix(in srgb, ${color} 9%, transparent)` : 'var(--bg-secondary)',
                            cursor: 'pointer',
                            textAlign: 'left',
                            transition: 'all 0.12s',
                            opacity: isHit ? 1 : 0.45,
                          }}
                          onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.opacity = '1'; }}
                          onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.opacity = isHit ? '1' : '0.45'; }}
                        >
                          <div style={{ fontSize: '0.6875rem', fontFamily: 'var(--font-mono)', fontWeight: 700, color: isHit ? color : 'var(--text-muted)' }}>
                            {tech.id}
                          </div>
                          <div style={{ fontSize: '0.6875rem', color: isHit ? 'var(--text-primary)' : 'var(--text-muted)', lineHeight: 1.3, marginTop: 1 }}>
                            {tech.name}
                          </div>
                        </button>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {selectedTech && <TechniquePanel technique={selectedTech} domain={domain} onClose={() => setSelectedTech(null)} />}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────

const TAB_META: Record<TabType, { label: string; icon: React.ElementType; helper: string }> = {
  matrix: { label: 'ATT&CK Matrix', icon: Layers, helper: '14 tactics · click any technique for details' },
  search: { label: 'Technique Search', icon: Search, helper: 'Search by name, ID or keyword' },
  actors: { label: 'Threat Actors', icon: Users, helper: 'Groups, aliases & TTPs' },
  navigator: { label: 'Navigator Layers', icon: Target, helper: 'Generate & visualise ATT&CK layers' },
};

export default function MitrePage() {
  const [tab, setTab] = useState<TabType>('matrix');
  const [domain, setDomain] = useState<Domain>('enterprise');

  const handleDomainChange = (d: Domain) => {
    setDomain(d);
  };

  return (
    <div className="animate-fadeIn" style={{ padding: '2rem', width: '100%', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Target size={22} color="var(--cyan)" /> MITRE ATT&amp;CK Framework
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: 4 }}>
            Enterprise · Mobile · ICS/OT &mdash; 200+ techniques · 140+ groups · 700+ software entries
          </p>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 8 }}>
          <DomainSelector domain={domain} onChange={handleDomainChange} />
        </div>
      </div>

      {/* Tabs */}
      <div className="card" style={{ padding: '0.5rem', border: '1px solid var(--border)' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.5rem' }}>
          {(Object.entries(TAB_META) as [TabType, typeof TAB_META[TabType]][]).map(([t, meta]) => {
            const isActive = tab === t;
            const Icon = meta.icon;
            return (
              <button key={t} onClick={() => setTab(t)}
                className={isActive ? 'btn btn-primary' : 'btn btn-ghost'}
                style={{ justifyContent: 'flex-start', flexDirection: 'column', alignItems: 'flex-start', gap: '0.2rem', minHeight: 72 }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.875rem', fontWeight: 700 }}>
                  <Icon size={14} /> {meta.label}
                </span>
                <span style={{ fontSize: '0.75rem', opacity: isActive ? 0.95 : 0.7, fontWeight: 500 }}>{meta.helper}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab Content */}
      <div>
        {tab === 'matrix' && <MatrixTab domain={domain} />}
        {tab === 'search' && <SearchTab domain={domain} />}
        {tab === 'actors' && <ActorsTab domain={domain} />}
        {tab === 'navigator' && <NavigatorTab domain={domain} />}
      </div>
    </div>
  );
}
