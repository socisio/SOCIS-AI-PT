'use client';
import { useState, useEffect } from 'react';
import { Zap, CheckCircle, XCircle, RefreshCw, ExternalLink, Wrench, LayoutGrid, Radar, PlayCircle, Wifi, Shield, Search, Terminal, ShieldAlert, Braces, Database, Lock, AlertTriangle, TrendingUp, Bug, Radio, Globe, Key, FolderSearch, Package, Target, Filter, BookMarked, Activity, FileCode, Building2, Cloud, Container, Network, KeyRound, Fingerprint, Hammer, ClipboardCheck } from 'lucide-react';
import { mcpApi } from '@/lib/api';
import { MCPServer, ToolSchema } from '@/lib/types';
import { MCPToolExplorer } from '@/components/MCPToolExplorer';
import { MCPToolExecutor } from '@/components/MCPToolExecutor';

const BUILTIN_SERVERS = [
  // ── Network Scanning ──────────────────────────────────────────────────────
  { name: 'nmap_mcp',          label: 'Nmap MCP',           description: 'Network port scanning via MCP',                                           transport: 'http', category: 'Network Scanning'    },
  { name: 'masscan_mcp',       label: 'Masscan MCP',         description: 'Massively fast port scanner',                                             transport: 'http', category: 'Network Scanning'    },
  // ── Web Security ──────────────────────────────────────────────────────────
  { name: 'nuclei_mcp',        label: 'Nuclei MCP',          description: 'Template-based vulnerability scanner',                                    transport: 'http', category: 'Web Security'         },
  { name: 'nikto_mcp',         label: 'Nikto MCP',           description: 'Web server vulnerability scanner',                                        transport: 'http', category: 'Web Security'         },
  { name: 'wpscan_mcp',        label: 'WPScan MCP',          description: 'WordPress vulnerability scanner',                                         transport: 'http', category: 'Web Security'         },
  { name: 'waf_detection_mcp', label: 'WAF Detection MCP',   description: 'WAF fingerprinting and bypass analysis',                                  transport: 'http', category: 'Web Security'         },
  { name: 'ffuf_mcp',          label: 'ffuf MCP',            description: 'Directory & API fuzzing with ffuf',                                       transport: 'http', category: 'Web Security'         },
  { name: 'gobuster_mcp',      label: 'Gobuster MCP',        description: 'Directory, DNS and vhost brute-force',                                    transport: 'http', category: 'Web Security'         },
  // ── Exploitation ──────────────────────────────────────────────────────────
  { name: 'metasploit_mcp',    label: 'Metasploit MCP',      description: 'Metasploit RPC — exploit modules, sessions, payloads',                   transport: 'http', category: 'Exploitation'         },
  { name: 'sqlmap_mcp',        label: 'SQLMap MCP',          description: 'Automated SQL injection detection and exploitation',                       transport: 'http', category: 'Exploitation'         },
  { name: 'jwt_mcp',           label: 'JWT MCP',             description: 'JWT decode, forge and attack testing',                                    transport: 'http', category: 'Exploitation'         },
  // ── Threat Intelligence ───────────────────────────────────────────────────
  { name: 'cve_mcp',           label: 'CVE/NVD MCP',         description: 'CVE lookup and NVD search',                                               transport: 'http', category: 'Threat Intelligence' },
  { name: 'cisa_kev_mcp',      label: 'CISA KEV MCP',        description: 'CISA Known Exploited Vulnerabilities catalog',                            transport: 'http', category: 'Threat Intelligence' },
  { name: 'epss_mcp',          label: 'EPSS MCP',            description: 'Exploit Prediction Scoring System (FIRST.org)',                           transport: 'http', category: 'Threat Intelligence' },
  { name: 'poc_mcp',           label: 'PoC Index MCP',       description: 'Public PoC exploit search — Sploitus, GitHub, ExploitDB',                transport: 'http', category: 'Threat Intelligence' },
  { name: 'exploitdb_mcp',     label: 'ExploitDB MCP',       description: 'Exploit-DB — 47k+ exploits searchable by CVE, platform, type, author, tags', transport: 'http', category: 'Threat Intelligence' },
  { name: 'cve_lite_mcp',      label: 'CVE Lite MCP',        description: 'OWASP JS/TS dependency vulnerability scanning (OSV)',                    transport: 'http', category: 'Threat Intelligence' },
  { name: 'mitre_mcp',         label: 'MITRE ATT&CK MCP',    description: 'Full ATT&CK framework — techniques, groups, software, mitigations',     transport: 'http', category: 'Threat Intelligence' },
  // ── OSINT & Recon ─────────────────────────────────────────────────────────
  { name: 'osint_mcp',         label: 'OSINT MCP',           description: 'Open-source intelligence gathering',                                      transport: 'http', category: 'OSINT & Recon'       },
  { name: 'ssl_mcp',           label: 'SSL Labs MCP',        description: 'TLS/SSL configuration grading and vulnerability testing',                 transport: 'http', category: 'OSINT & Recon'       },
  // ── Active Directory ──────────────────────────────────────────────────────
  { name: 'ad_mcp',           label: 'Active Directory MCP', description: 'SMB/LDAP enum, user enum, password spray, AS-REP roast (NetExec/kerbrute)', transport: 'http', category: 'Active Directory'   },
  // ── Analysis ───────────────────────────────────────────────────────────────
  { name: 'anomaly_mcp',      label: 'Anomaly Detection MCP', description: 'ML-based traffic anomaly detection',                                      transport: 'http', category: 'Analysis'            },
  { name: 'payload_generator_mcp', label: 'Payload Generator MCP', description: 'Attack payload and wordlist generation',                             transport: 'http', category: 'Exploitation'        },
  // ── Cloud Recon ────────────────────────────────────────────────────────────
  { name: 'cloud_mcp',        label: 'Cloud Recon MCP',     description: 'Bucket enumeration, cloud fingerprinting, metadata-leak (SSRF) checks',   transport: 'http', category: 'Cloud Recon'        },
  // ── Container / Kubernetes ──────────────────────────────────────────────────
  { name: 'container_mcp',    label: 'Container & K8s MCP', description: 'Trivy image/Dockerfile/K8s-manifest scanning, exposed Docker API check',  transport: 'http', category: 'Container / Kubernetes' },
  // ── API Security ────────────────────────────────────────────────────────────
  { name: 'api_security_mcp', label: 'API Security MCP',   description: 'GraphQL introspection, OpenAPI discovery, CORS/verbose-error misconfig checks', transport: 'http', category: 'API Security' },
  // ── Secrets Scanning ─────────────────────────────────────────────────────────
  { name: 'secrets_mcp',      label: 'Secrets Scanning MCP', description: 'Detects live credentials (API keys, tokens, private keys) in code/config content', transport: 'http', category: 'Secrets Scanning' },
  // ── DNS Deep ─────────────────────────────────────────────────────────────────
  { name: 'dns_deep_mcp',     label: 'DNS Deep MCP',        description: 'Zone transfer checks, subdomain takeover detection, SPF/DKIM/DMARC posture', transport: 'http', category: 'DNS Deep' },
  // ── Password Cracking ────────────────────────────────────────────────────────
  { name: 'crack_mcp',        label: 'Password Cracking MCP', description: 'John the Ripper wordlist attacks against hashes dumped by other tools', transport: 'http', category: 'Password Cracking' },
  // ── Compliance Mapping ───────────────────────────────────────────────────────
  { name: 'compliance_mcp',   label: 'Compliance Mapping MCP', description: 'Maps findings to OWASP Top 10, PTES phases, and MITRE ATT&CK tactics', transport: 'http', category: 'Compliance Mapping' },
];

const CATEGORIES: Record<string, { color: string; icon: React.ElementType }> = {
  'Network Scanning':    { color: 'var(--cyan)', icon: Wifi         },
  'Web Security':        { color: 'var(--amber)', icon: ShieldAlert  },
  'Exploitation':        { color: 'var(--red)', icon: Terminal     },
  'Threat Intelligence': { color: 'var(--blue)', icon: Shield       },
  'OSINT & Recon':       { color: 'var(--purple)', icon: Search       },
  'Active Directory':    { color: 'var(--red)', icon: Building2     },
  'Analysis':            { color: 'var(--purple)', icon: Activity     },
  'Cloud Recon':         { color: 'var(--cyan)', icon: Cloud          },
  'Container / Kubernetes': { color: 'var(--blue)', icon: Container   },
  'API Security':        { color: 'var(--orange)', icon: Network     },
  'Secrets Scanning':    { color: 'var(--red)', icon: KeyRound        },
  'DNS Deep':            { color: 'var(--purple)', icon: Fingerprint  },
  'Password Cracking':   { color: 'var(--red)', icon: Hammer          },
  'Compliance Mapping':  { color: 'var(--green)', icon: ClipboardCheck },
};

const SERVER_ICONS: Record<string, React.ElementType> = {
  nmap_mcp:          Wifi,
  masscan_mcp:       Radio,
  nuclei_mcp:        Zap,
  nikto_mcp:         Bug,
  wpscan_mcp:        Globe,
  waf_detection_mcp: ShieldAlert,
  ffuf_mcp:          Braces,
  gobuster_mcp:      FolderSearch,
  metasploit_mcp:    Terminal,
  sqlmap_mcp:        Database,
  jwt_mcp:           Key,
  cve_mcp:           Shield,
  cisa_kev_mcp:      AlertTriangle,
  epss_mcp:          TrendingUp,
  poc_mcp:           Bug,
  exploitdb_mcp:     BookMarked,
  cve_lite_mcp:      Package,
  mitre_mcp:         Target,
  osint_mcp:         Search,
  ssl_mcp:           Lock,
  anomaly_mcp:           Activity,
  payload_generator_mcp: FileCode,
  ad_mcp:                Building2,
  cloud_mcp:             Cloud,
  container_mcp:         Container,
  api_security_mcp:      Network,
  secrets_mcp:           KeyRound,
  dns_deep_mcp:          Fingerprint,
  crack_mcp:             Hammer,
  compliance_mcp:        ClipboardCheck,
};

type TabType = 'overview' | 'tools' | 'executor';

export default function MCPPage() {
  const [tab, setTab] = useState<TabType>('overview');
  const [servers, setServers] = useState<MCPServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedTool, setSelectedTool] = useState<ToolSchema | null>(null);
  const [selectedServer, setSelectedServer] = useState<MCPServer | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>('all');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await mcpApi.servers();
      const serverList = Array.isArray(res.data?.servers) ? res.data.servers : [];
      setServers(serverList);
    } catch (err) {
      setError('Failed to load MCP servers');
      setServers([]);
    } finally {
      setLoading(false);
    }
  };

  const handleTest = async (name: string) => {
    setTesting(name);
    try {
      await mcpApi.test(name);
      setTimeout(() => load(), 500);
    } catch (err) {
      setTimeout(() => setTesting(null), 2000);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const mergedServers = BUILTIN_SERVERS.map(builtin => {
    const live = servers.find(s => s?.name === builtin.name);
    return live ? { ...builtin, ...live, status: live.status || 'unconfigured' } : { ...builtin, status: 'unconfigured', tools: [] };
  });

  const STATUS_COLOR: Record<string, string> = {
    online: 'var(--green)', error: 'var(--red)', unconfigured: 'var(--amber)', unknown: 'var(--text-secondary)',
  };

  const totalTools = servers.reduce((sum, s) => sum + (Array.isArray(s.tools) ? s.tools.length : 0), 0);
  const onlineCount = mergedServers.filter((s) => s.status === 'online').length;
  const errorCount = mergedServers.filter((s) => s.status === 'error').length;

  const TAB_META: Record<TabType, { label: string; icon: React.ElementType; helper: string }> = {
    overview: { label: 'Overview', icon: Radar, helper: 'Server health and availability' },
    tools: { label: 'Tool Explorer', icon: LayoutGrid, helper: 'Browse all available MCP tools' },
    executor: { label: 'Execute Tool', icon: PlayCircle, helper: 'Configure and run selected tools' },
  };

  const handleToolSelect = (tool: ToolSchema, server: MCPServer) => {
    setSelectedTool(tool);
    setSelectedServer(server);
    setTab('executor');
  };

  return (
    <div className="animate-fadeIn" style={{ padding: '2rem', width: '100%', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1>MCP Servers & Tools</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: 4 }}>
            Model Context Protocol — Browse, discover, and execute security tools
          </p>
        </div>
        <button onClick={load} disabled={loading} className="btn btn-ghost"><RefreshCw size={14} /></button>
      </div>

      {/* KPI Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: '0.85rem' }}>
        {[
          { label: 'Registered Servers', value: mergedServers.length, color: 'var(--cyan)' },
          { label: 'Online', value: onlineCount, color: 'var(--green)' },
          { label: 'Total Tools', value: totalTools, color: 'var(--blue)' },
          { label: 'Errors', value: errorCount, color: 'var(--red)' },
        ].map((item) => (
          <div key={item.label} className="stat-card" style={{ border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: item.color }}>{item.value}</div>
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              {item.label}
            </div>
          </div>
        ))}
      </div>

      {/* Error Banner */}
      {error && (
        <div style={{
          background: 'color-mix(in srgb, var(--red) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--red) 19%, transparent)', borderRadius: 'var(--radius-lg)',
          padding: '0.875rem 1.25rem', fontSize: '0.875rem', color: 'var(--red)',
        }}>
          {error}
        </div>
      )}

      {/* Info Banner */}
      <div style={{
        background: 'var(--cyan-glow)', border: '1px solid var(--border-glow)', borderRadius: 'var(--radius-lg)',
        padding: '0.875rem 1.25rem', fontSize: '0.875rem', color: 'var(--text-secondary)',
        display: 'flex', gap: '0.75rem', alignItems: 'center',
      }}>
        <Zap size={16} color="var(--cyan)" style={{ flexShrink: 0 }} />
        <span>
          {loading ? 'Loading MCP servers and tools...' : 
          `${servers.length} MCP servers available with ${totalTools} tools`}
        </span>
      </div>

      {/* Tabs */}
      <div className="card" style={{ padding: '0.5rem', border: '1px solid var(--border)' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.5rem' }}>
          {(['overview', 'tools', 'executor'] as const).map((t) => {
            const isActive = tab === t;
            const Icon = TAB_META[t].icon;
            return (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={isActive ? 'btn btn-primary' : 'btn btn-ghost'}
            style={{
              justifyContent: 'flex-start',
              flexDirection: 'column',
              alignItems: 'flex-start',
              gap: '0.2rem',
              minHeight: '72px',
            }}
          >
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.875rem', fontWeight: 700 }}>
              <Icon size={14} /> {TAB_META[t].label}
            </span>
            <span style={{ fontSize: '0.75rem', opacity: isActive ? 0.95 : 0.7, fontWeight: 500 }}>
              {TAB_META[t].helper}
            </span>
          </button>
            );
          })}
        </div>
      </div>

      {/* Tab Content */}
      {tab === 'overview' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>

          {/* ── Category Filter Bar ── */}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, marginRight: 4 }}>
              <Filter size={11} /> Filter
            </span>
            {['all', ...Object.keys(CATEGORIES)].map(cat => {
              const isActive = filterCategory === cat;
              const catColor = cat === 'all' ? 'var(--cyan)' : (CATEGORIES[cat]?.color ?? 'var(--cyan)');
              const catCount = cat === 'all'
                ? mergedServers.length
                : mergedServers.filter(s => (s as any).category === cat).length;
              return (
                <button key={cat} onClick={() => setFilterCategory(cat)} style={{
                  padding: '4px 12px', borderRadius: 'var(--radius-sm)', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer',
                  border: `1px solid ${isActive ? catColor : 'var(--border)'}`,
                  background: isActive ? `color-mix(in srgb, ${catColor} 9%, transparent)` : 'transparent',
                  color: isActive ? catColor : 'var(--text-muted)',
                  transition: 'all 0.15s',
                }}>
                  {cat === 'all' ? 'All' : cat}
                  <span style={{ opacity: 0.6, fontWeight: 400, marginLeft: 4 }}>({catCount})</span>
                </button>
              );
            })}
          </div>

          {/* ── Grouped Server Registry ── */}
          {Object.entries(
            mergedServers
              .filter(s => filterCategory === 'all' || (s as any).category === filterCategory)
              .reduce<Record<string, typeof mergedServers>>((acc, s) => {
                const cat = (s as any).category || 'Other';
                if (!acc[cat]) acc[cat] = [];
                acc[cat].push(s);
                return acc;
              }, {})
          ).map(([category, catServers]) => {
            const catMeta = CATEGORIES[category];
            const CatIcon = catMeta?.icon ?? Wrench;
            const catOnline = catServers.filter(s => s.status === 'online').length;

            return (
              <div key={category} style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>

                {/* Category header */}
                <div style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '0.65rem 1.2rem',
                  background: catMeta ? `color-mix(in srgb, ${catMeta.color} 3%, transparent)` : 'var(--bg-hover)',
                  borderBottom: '1px solid var(--border)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <div style={{
                      width: 26, height: 26, borderRadius: 'var(--radius-sm)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                      background: catMeta ? `color-mix(in srgb, ${catMeta.color} 9%, transparent)` : 'var(--bg-hover)',
                      border: `1px solid ${catMeta ? `color-mix(in srgb, ${catMeta.color} 21%, transparent)` : 'var(--border)'}`,
                    }}>
                      <CatIcon size={13} color={catMeta?.color ?? 'var(--text-muted)'} />
                    </div>
                    <span style={{ fontWeight: 700, fontSize: '0.875rem' }}>{category}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.6875rem' }}>
                    <span style={{
                      fontWeight: 700,
                      color: catOnline === catServers.length ? 'var(--green)' : catOnline > 0 ? 'var(--amber)' : 'var(--text-muted)',
                    }}>
                      {catOnline}/{catServers.length}
                    </span>
                    <span style={{ color: 'var(--text-muted)' }}>online</span>
                  </div>
                </div>

                {/* Server rows */}
                {catServers.map((server, idx) => {
                  const statusColor = STATUS_COLOR[server.status || 'unknown'] || 'var(--text-secondary)';
                  const isOnline = server.status === 'online';
                  const tools = Array.isArray(server.tools) ? server.tools : [];
                  const ServerIcon = SERVER_ICONS[server.name] ?? Wrench;
                  const isLast = idx === catServers.length - 1;

                  return (
                    <div
                      key={server.name}
                      style={{
                        display: 'grid', gridTemplateColumns: '1fr auto', alignItems: 'center',
                        padding: '0.8rem 1.2rem',
                        borderBottom: isLast ? 'none' : '1px solid var(--border)',
                        gap: '1.25rem', transition: 'background 0.12s',
                      }}
                      onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-hover)')}
                      onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                    >
                      {/* Left: pulse dot · icon · name · description · tool tags */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', minWidth: 0 }}>

                        {/* Status pulse dot */}
                        <div style={{ position: 'relative', width: 8, height: 8, flexShrink: 0 }}>
                          <div style={{ width: 8, height: 8, borderRadius: '50%', background: statusColor }} />
                          {isOnline && (
                            <div className="animate-ping" style={{
                              position: 'absolute', inset: 0, borderRadius: '50%', background: statusColor, opacity: 0.45,
                            }} />
                          )}
                        </div>

                        {/* Category-coloured server icon */}
                        <div style={{
                          width: 34, height: 34, borderRadius: 'var(--radius-md)', flexShrink: 0,
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          background: catMeta ? `color-mix(in srgb, ${catMeta.color} 7%, transparent)` : 'var(--bg-hover)',
                          border: `1px solid ${catMeta ? `color-mix(in srgb, ${catMeta.color} 16%, transparent)` : 'var(--border)'}`,
                        }}>
                          <ServerIcon size={16} color={catMeta?.color ?? 'var(--text-muted)'} />
                        </div>

                        {/* Name · internal id · description · tool tags */}
                        <div style={{ minWidth: 0, flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
                            <span style={{ fontWeight: 600, fontSize: '0.875rem', whiteSpace: 'nowrap' }}>
                              {(server as any).label}
                            </span>
                            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', opacity: 0.75, whiteSpace: 'nowrap' }}>
                              {server.name}
                            </span>
                          </div>
                          <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {(server as any).description}
                          </div>
                          {tools.length > 0 && (
                            <div style={{ marginTop: 5, display: 'flex', alignItems: 'center', gap: 5, overflow: 'hidden' }}>
                              <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 3, flexShrink: 0 }}>
                                <Wrench size={9} />{tools.length}
                              </span>
                              {tools.slice(0, 5).map((tool: any) => {
                                const tname = typeof tool === 'string' ? tool : tool.name;
                                return (
                                  <span key={tname} style={{
                                    fontSize: '0.6875rem', padding: '1px 5px', borderRadius: 'var(--radius-sm)',
                                    background: 'var(--bg-hover)', color: 'var(--text-muted)',
                                    border: '1px solid var(--border)', fontFamily: 'var(--font-mono)',
                                    whiteSpace: 'nowrap', flexShrink: 0,
                                  }}>{tname}</span>
                                );
                              })}
                              {tools.length > 5 && (
                                <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', flexShrink: 0 }}>
                                  +{tools.length - 5}
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Right: status badge · transport chip · test button */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                        <span style={{
                          fontSize: '0.6875rem', padding: '2px 8px', borderRadius: 'var(--radius-sm)', fontWeight: 600,
                          background: `color-mix(in srgb, ${statusColor} 7%, transparent)`, color: statusColor, border: `1px solid color-mix(in srgb, ${statusColor} 19%, transparent)`,
                          textTransform: 'capitalize', whiteSpace: 'nowrap',
                        }}>
                          {server.status || 'unconfigured'}
                        </span>
                        <span style={{
                          fontSize: '0.6875rem', padding: '2px 6px', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)',
                          background: 'var(--bg-hover)', color: 'var(--text-muted)', border: '1px solid var(--border)',
                        }}>
                          {(server as any).transport}
                        </span>
                        <button
                          onClick={() => handleTest(server.name)}
                          disabled={testing === server.name || loading}
                          className="btn btn-ghost"
                          style={{ padding: '4px 10px', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: 4, whiteSpace: 'nowrap' }}
                        >
                          {testing === server.name
                            ? <><RefreshCw size={11} className="animate-spin" /> Testing</>
                            : <><Zap size={11} /> Test</>}
                        </button>
                        {server.name === 'metasploit_mcp' && (
                          <a href="https://github.com/GH05TCREW/MetasploitMCP" target="_blank" rel="noreferrer"
                            className="btn btn-ghost" style={{ padding: '4px 8px' }}>
                            <ExternalLink size={11} />
                          </a>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>
      )}

      {tab === 'tools' && (
        <div className="card" style={{ minHeight: '560px', border: '1px solid var(--border)' }}>
          <MCPToolExplorer 
            servers={mergedServers} 
            onToolSelect={handleToolSelect}
            loading={loading}
          />
        </div>
      )}

      {tab === 'executor' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1rem', minHeight: '560px' }}>
          <div className="card" style={{ border: '1px solid var(--border)', display: 'flex', flexDirection: 'column' }}>
            <h3 style={{ fontSize: '0.875rem', fontWeight: 700, marginBottom: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Wrench size={16} />
              Tool Explorer
            </h3>
            <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '1rem', maxHeight: '620px', overflow: 'auto', background: 'var(--bg-secondary)' }}>
              <MCPToolExplorer 
                servers={mergedServers} 
                onToolSelect={handleToolSelect}
                loading={loading}
              />
            </div>
          </div>
          <div className="card" style={{ border: '1px solid var(--border)' }}>
            <h3 style={{ fontSize: '0.875rem', fontWeight: 700, marginBottom: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <PlayCircle size={16} /> Tool Executor
            </h3>
            <MCPToolExecutor tool={selectedTool} server={selectedServer} />
          </div>
        </div>
      )}
    </div>
  );
}
