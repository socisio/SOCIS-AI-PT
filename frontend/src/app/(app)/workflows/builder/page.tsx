'use client';

/**
 * SOCIS-AI-PT — Visual Workflow Builder
 * n8n-style drag-and-drop canvas for building pentest workflows.
 * Route: /workflows/builder          → new workflow
 * Route: /workflows/builder?id=<id>  → edit existing
 */

import { scopeBlock } from '@/lib/scope';
import { askScopeOverride } from '@/lib/dialogs';
import { apiError } from '@/lib/errors';
import { useState, useCallback, useRef, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  ReactFlow,
  ReactFlowProvider,
  addEdge,
  reconnectEdge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Connection,
  type NodeTypes,
  type Edge,
  BackgroundVariant,
  MarkerType,
  Panel,
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — types resolved during Docker build
} from '@xyflow/react';
// @ts-ignore
import '@xyflow/react/dist/style.css';

import {
  Save, Play, ChevronRight, ChevronLeft, X, Plus, Settings, Brain,
  Terminal, GitBranch, FileText, Loader2, CheckCircle, Globe2, Container,
  AlertCircle, Download, Upload, Trash2, RefreshCw, HelpCircle,
  // Enterprise builder additions
  Shield, Globe, Eye, Database, Bug, Key, AlertTriangle,
  BarChart2, Code2, Target, Crosshair, Zap, Lock,
  FolderSearch, Layers, Search, Hash, Clock, Activity,
  Network, Filter, ChevronDown, ChevronUp, Radar, Cpu, Package, BookMarked, KeyRound,
  Fingerprint, Hammer, ClipboardCheck,
} from 'lucide-react';

import { workflowsApi, projectsApi, llmApi, toolsApi } from '@/lib/api';
import { normalizeProvider, normalizeNodeProviders, PROVIDER_OPTIONS } from '@/lib/providers';
import { WORKFLOW_PRESETS } from '@/lib/workflow-presets';
import type { WFNode, WFEdge, WFNodeData, WFNodeEvent, WorkflowDefinition, Project } from '@/lib/types';

import { StartNode }     from '@/components/workflow/nodes/StartNode';
import { ToolNode }      from '@/components/workflow/nodes/ToolNode';
import { LlmNode }       from '@/components/workflow/nodes/LlmNode';
import { ConditionNode } from '@/components/workflow/nodes/ConditionNode';
import { ReportNode }    from '@/components/workflow/nodes/ReportNode';
import { notify } from '@/lib/dialogs';

// ── ReactFlow node type registry ─────────────────────────────────────────────

const NODE_TYPES: NodeTypes = {
  start:     StartNode     as any,
  tool:      ToolNode      as any,
  llm:       LlmNode       as any,
  condition: ConditionNode as any,
  report:    ReportNode    as any,
};

// ── Shared wordlist options (must match /usr/share/wordlists/ inside the container) ───
// These map to SecLists files downloaded at Docker image build time.
const WORDLIST_OPTIONS = [
  { value: 'common',     label: 'Common      — 4 750 entries  (web discovery, default)' },
  { value: 'big',        label: 'Big         — 20 481 entries (deeper web discovery)' },
  { value: 'subdomains', label: 'Subdomains  — 5 000 entries  (DNS enumeration)' },
  { value: 'parameters', label: 'Parameters  — 6 453 entries  (URL/form fuzzing)' },
  { value: 'passwords',  label: 'Passwords   — 10 000 entries (brute-force login)' },
  { value: 'usernames',  label: 'Usernames   — 400 entries    (username brute-force)' },
] as const;

// ── Condition node: tool → check definitions ─────────────────────────────────

type CheckDef = { value: string; label: string; hasParam?: boolean; paramLabel?: string; paramDefault?: string };

const CONDITION_TOOLS: { value: string; label: string }[] = [
  { value: 'true',       label: '✓ Always YES' },
  { value: 'false',      label: '✗ Always NO' },
  { value: 'any',        label: 'Any Tool' },
  { value: 'all',        label: 'All Tools' },
  { value: 'nmap',       label: 'Nmap' },
  { value: 'nuclei',     label: 'Nuclei' },
  { value: 'ffuf',       label: 'FFUF' },
  { value: 'sqlmap',      label: 'SQLMap (detect)' },
  { value: 'sqlmap_full', label: 'SQLMap Full Chain' },
  { value: 'nikto',      label: 'Nikto' },
  { value: 'wpscan',     label: 'WPScan' },
  { value: 'gobuster',   label: 'Gobuster' },
  { value: 'masscan',    label: 'Masscan' },
  { value: 'cisa_kev',   label: 'CISA KEV' },
  { value: 'epss',       label: 'EPSS' },
  { value: 'cve',        label: 'CVE Lookup' },
  { value: 'poc_index',  label: 'PoC Search' },
  { value: 'ssl',        label: 'SSL/TLS' },
  { value: 'waf',        label: 'WAF Detect' },
  { value: 'osint',      label: 'OSINT' },
  { value: 'metasploit', label: 'Metasploit' },
  { value: 'jwt',        label: 'JWT Analyzer' },
  { value: 'cve_lite',   label: 'CVE Lite' },
];

const CONDITION_CHECKS: Record<string, CheckDef[]> = {
  true:       [],
  false:      [],
  any:        [
    { value: 'success', label: 'Any tool succeeded' },
    { value: 'failed',  label: 'Any tool failed' },
  ],
  all:        [
    { value: 'success', label: 'All tools succeeded' },
  ],
  nmap:       [
    { value: 'host_up',        label: 'Host is up' },
    { value: 'has_open_ports', label: 'Any port open' },
    { value: 'has_http',       label: 'HTTP open (80/443/8080…)' },
    { value: 'has_ssl',        label: 'HTTPS/TLS open (443/8443)' },
    { value: 'has_ssh',        label: 'SSH open (22)' },
    { value: 'has_ftp',        label: 'FTP open (21)' },
    { value: 'has_smb',        label: 'SMB open (445/139)' },
    { value: 'has_mysql',      label: 'MySQL open (3306)' },
    { value: 'has_postgres',   label: 'PostgreSQL open (5432)' },
    { value: 'has_redis',      label: 'Redis open (6379)' },
    { value: 'port_open',      label: 'Specific port open…',              hasParam: true, paramLabel: 'Port number',                       paramDefault: '80'      },
    { value: 'ports_open',     label: 'All of these ports open…',          hasParam: true, paramLabel: 'Port numbers (comma-separated)',     paramDefault: '80,443'  },
    { value: 'any_ports_open', label: 'Any of these ports open…',          hasParam: true, paramLabel: 'Port numbers (comma-separated)',     paramDefault: '80,8080' },
    { value: 'ports_gt',       label: 'Open port count > N…',              hasParam: true, paramLabel: 'Minimum count',                      paramDefault: '0'       },
    { value: 'success',        label: 'Scan succeeded' },
  ],
  nuclei:     [
    { value: 'has_findings',  label: 'Any findings' },
    { value: 'has_critical',  label: 'Critical severity found' },
    { value: 'has_high',      label: 'High / Critical found' },
    { value: 'has_medium',    label: 'Medium+ severity found' },
    { value: 'findings_gt',   label: 'Finding count > N…', hasParam: true, paramLabel: 'Minimum count', paramDefault: '0' },
    { value: 'success',       label: 'Scan succeeded' },
  ],
  ffuf:       [
    { value: 'has_results',  label: 'Has results' },
    { value: 'results_gt',   label: 'Result count > N…', hasParam: true, paramLabel: 'Minimum count', paramDefault: '0' },
    { value: 'success',      label: 'Scan succeeded' },
  ],
  sqlmap:     [
    { value: 'is_vulnerable', label: 'Target is vulnerable (SQL injection found)' },
    { value: 'success',       label: 'Scan succeeded' },
  ],
  sqlmap_full: [
    { value: 'is_vulnerable', label: 'SQL injection found (vulnerable)' },
    { value: 'is_dba',        label: 'Current user has DBA privileges' },
    { value: 'has_databases', label: 'Databases enumerated successfully' },
    { value: 'has_users',     label: 'Database users discovered' },
    { value: 'success',       label: 'Full chain completed' },
  ],
  nikto:      [
    { value: 'has_findings', label: 'Has findings' },
    { value: 'success',      label: 'Scan succeeded' },
  ],
  wpscan:     [
    { value: 'has_findings', label: 'Has vulnerabilities' },
    { value: 'success',      label: 'Scan succeeded' },
  ],
  gobuster:   [
    { value: 'has_results', label: 'Has results' },
    { value: 'success',     label: 'Scan succeeded' },
  ],
  masscan:    [
    { value: 'has_open_ports', label: 'Open ports found' },
    { value: 'host_up',        label: 'Host responded' },
    { value: 'success',        label: 'Scan succeeded' },
  ],
  cisa_kev:   [
    { value: 'in_kev',      label: 'CVE is in KEV catalog (actively exploited)' },
    { value: 'has_entries', label: 'Has KEV entries' },
    { value: 'success',     label: 'Lookup succeeded' },
  ],
  epss:       [
    { value: 'high_risk',    label: 'High exploit risk (score > 0.5)' },
    { value: 'score_above',  label: 'Score above threshold…', hasParam: true, paramLabel: 'Threshold (0.0 – 1.0)', paramDefault: '0.5' },
    { value: 'success',      label: 'Lookup succeeded' },
  ],
  cve:        [
    { value: 'has_results',  label: 'Has CVE results' },
    { value: 'has_critical', label: 'Critical CVE found' },
    { value: 'has_high',     label: 'High / Critical CVE found' },
    { value: 'success',      label: 'Lookup succeeded' },
  ],
  poc_index:  [
    { value: 'has_findings', label: 'Public exploits / PoC found' },
    { value: 'success',      label: 'Search succeeded' },
  ],
  exploitdb:  [
    { value: 'has_findings', label: 'Exploits found' },
    { value: 'success',      label: 'Search succeeded' },
  ],
  ssl:        [
    { value: 'has_vulns', label: 'SSL vulnerabilities found' },
    { value: 'expired',   label: 'Certificate is expired' },
    { value: 'success',   label: 'Scan succeeded' },
  ],
  waf:        [
    { value: 'detected', label: 'WAF detected' },
    { value: 'success',  label: 'Scan succeeded' },
  ],
  osint:      [
    { value: 'success', label: 'Lookup succeeded' },
  ],
  metasploit: [
    { value: 'exploited',   label: 'Exploitation successful (session opened)' },
    { value: 'has_session', label: 'Session exists' },
    { value: 'success',     label: 'Module ran successfully' },
  ],
  jwt:        [
    { value: 'has_vulns', label: 'JWT vulnerabilities found' },
    { value: 'success',   label: 'Analysis succeeded' },
  ],
  cve_lite:   [
    { value: 'has_findings',       label: 'Vulnerable dependencies found' },
    { value: 'has_critical',       label: 'Critical severity found' },
    { value: 'has_high',           label: 'High / Critical severity found' },
    { value: 'threshold_reached',  label: 'fail-on threshold reached' },
    { value: 'findings_gt',        label: 'Finding count > N…', hasParam: true, paramLabel: 'Minimum count', paramDefault: '0' },
    { value: 'success',            label: 'Scan succeeded' },
  ],
};

/** Parse a condition expression into [tool, check, param]. */
function parseCondExpr(expr: string): [string, string, string] {
  const parts = (expr ?? 'nmap:host_up').split(':');
  const tool  = parts[0] || 'nmap';
  const check = parts[1] || (CONDITION_CHECKS[tool]?.[0]?.value ?? 'success');
  const param = parts[2] || '';
  return [tool, check, param];
}

/** Rebuild expression string from [tool, check, param]. */
function buildCondExpr(tool: string, check: string, param: string): string {
  if (tool === 'true' || tool === 'false') return tool;
  return param.trim() ? `${tool}:${check}:${param.trim()}` : `${tool}:${check}`;
}

// ── Tool library definition ───────────────────────────────────────────────────

const TOOL_LIBRARY = [
  {
    category: 'Discovery & Recon',
    hint: 'Needs: Network Target',
    color: 'var(--cyan)',
    icon: Radar,
    items: [
      { tool: 'nmap',    label: 'Nmap',        color: 'var(--cyan)', hint: 'Port & service scan',       icon: Radar,       risk: 'low'    },
      { tool: 'masscan', label: 'Masscan',      color: 'var(--cyan)', hint: 'Fast port scanner',         icon: Zap,         risk: 'low'    },
      { tool: 'osint',   label: 'OSINT Tools',  color: 'var(--teal)', hint: 'WHOIS, DNS, geoIP…',        icon: Eye,         risk: 'low'    },
      { tool: 'waf',     label: 'WAF Detect',   color: 'var(--indigo)', hint: 'Firewall fingerprint',      icon: Shield,      risk: 'low'    },
      { tool: 'ssl',     label: 'SSL/TLS',      color: 'var(--teal)', hint: 'Certificate analysis',      icon: Lock,        risk: 'low'    },
    ],
  },
  {
    category: 'Web Attacks',
    hint: 'Needs: Network Target or URL',
    color: 'var(--amber)',
    icon: Globe,
    items: [
      { tool: 'ffuf',        label: 'FFUF Fuzzer',       color: 'var(--amber)', hint: 'Directory brute force',       icon: Layers,      risk: 'medium' },
      { tool: 'sqlmap',      label: 'SQLMap (detect)',   color: 'var(--red)', hint: 'SQL injection detection',     icon: Database,    risk: 'medium' },
      { tool: 'sqlmap_full', label: 'SQLMap Full Chain', color: 'var(--red)', hint: 'Detect → exploit → dump all', icon: Database,    risk: 'critical'},
      { tool: 'nikto',       label: 'Nikto',             color: 'var(--orange)', hint: 'Web server vuln scanner',    icon: Bug,         risk: 'medium' },
      { tool: 'wpscan',      label: 'WPScan',            color: 'var(--purple)', hint: 'WordPress scanner',          icon: Globe,       risk: 'medium' },
      { tool: 'gobuster',    label: 'Gobuster',          color: 'var(--green)', hint: 'Dir & DNS brute-force',      icon: FolderSearch,risk: 'medium' },
      { tool: 'jwt',         label: 'JWT Analyzer',      color: 'var(--amber)', hint: 'JWT attack & decode',        icon: Key,         risk: 'medium' },
      { tool: 'cve_lite',    label: 'CVE Lite Scan',     color: 'var(--indigo)', hint: 'JS/TS dependency vulns (OSV)',icon: Package,     risk: 'low'    },
    ],
  },
  {
    category: 'Vulnerability Scan',
    hint: 'Needs: Network Target',
    color: 'var(--orange)',
    icon: Crosshair,
    items: [
      { tool: 'nuclei', label: 'Nuclei',     color: 'var(--orange)', hint: 'Template-based scanner',              icon: Crosshair,   risk: 'high'   },
      { tool: 'cve',    label: 'CVE Lookup', color: 'var(--pink)', hint: 'CVE ID or keyword → blank = from Start', icon: AlertTriangle, risk: 'low' },
    ],
  },
  {
    category: 'Threat Intel',
    hint: 'Needs: CVE ID or Keyword',
    color: 'var(--orange)',
    icon: Activity,
    items: [
      { tool: 'cisa_kev',  label: 'CISA KEV',          color: 'var(--orange)', hint: 'Known exploited CVEs',           icon: AlertTriangle, risk: 'high'   },
      { tool: 'epss',      label: 'EPSS Score',         color: 'var(--amber)', hint: 'Exploit probability score',      icon: BarChart2,     risk: 'low'    },
      { tool: 'poc_index', label: 'PoC Search',         color: 'var(--red)', hint: 'Exploit proof-of-concept',       icon: Code2,         risk: 'high'   },
      { tool: 'exploitdb', label: 'ExploitDB',          color: 'var(--orange)', hint: 'ExploitDB — CVE, platform, type', icon: BookMarked,   risk: 'high'   },
      { tool: 'mitre',     label: 'MITRE ATT&CK',       color: 'var(--cyan)', hint: 'Techniques, groups, mitigations',icon: Layers,        risk: 'low'    },
    ],
  },
  {
    category: 'Exploitation',
    hint: 'Needs: Network Target',
    color: 'var(--red)',
    icon: Target,
    items: [
      { tool: 'metasploit', label: 'Metasploit', color: 'var(--red)', hint: 'Exploitation framework', icon: Target, risk: 'critical' },
      { tool: 'payload_generator', label: 'Payload Generator', color: 'var(--orange)', hint: 'Attack payloads & wordlists', icon: Code2, risk: 'high' },
    ],
  },
  {
    category: 'Analysis',
    hint: 'ML-based traffic analysis',
    color: 'var(--purple)',
    icon: Activity,
    items: [
      { tool: 'anomaly', label: 'Anomaly Detection', color: 'var(--purple)', hint: 'ML traffic anomaly detection', icon: Activity, risk: 'low' },
    ],
  },
  {
    category: 'Active Directory',
    hint: 'Internal AD / SMB / LDAP',
    color: 'var(--red)',
    icon: Lock,
    items: [
      { tool: 'ad', label: 'Active Directory', color: 'var(--red)', hint: 'SMB/LDAP enum, user enum, password spray (NetExec)', icon: Lock, risk: 'high' },
    ],
  },
  {
    category: 'Cloud Recon',
    hint: 'Bucket name / domain',
    color: 'var(--cyan)',
    icon: Globe2,
    items: [
      { tool: 'cloud', label: 'Cloud Recon', color: 'var(--cyan)', hint: 'Bucket enum, cloud fingerprint, SSRF metadata check', icon: Globe2, risk: 'low' },
    ],
  },
  {
    category: 'Container / Kubernetes',
    hint: 'Image ref / file content',
    color: 'var(--blue)',
    icon: Container,
    items: [
      { tool: 'container', label: 'Container & K8s', color: 'var(--blue)', hint: 'Trivy image/Dockerfile/K8s-manifest scan, Docker API check', icon: Container, risk: 'medium' },
    ],
  },
  {
    category: 'API Security',
    hint: 'API / GraphQL endpoint URL',
    color: 'var(--orange)',
    icon: Network,
    items: [
      { tool: 'api_security', label: 'API Security', color: 'var(--orange)', hint: 'GraphQL introspection, OpenAPI discovery, CORS/misconfig checks', icon: Network, risk: 'low' },
    ],
  },
  {
    category: 'Secrets Scanning',
    hint: 'File / repo content',
    color: 'var(--red)',
    icon: KeyRound,
    items: [
      { tool: 'secrets', label: 'Secrets Scanning', color: 'var(--red)', hint: 'Detect live credentials in code/config content', icon: KeyRound, risk: 'medium' },
    ],
  },
  {
    category: 'DNS Deep',
    hint: 'Domain',
    color: 'var(--purple)',
    icon: Fingerprint,
    items: [
      { tool: 'dns_deep', label: 'DNS Deep', color: 'var(--purple)', hint: 'Zone transfer, subdomain takeover, SPF/DKIM/DMARC posture', icon: Fingerprint, risk: 'low' },
    ],
  },
  {
    category: 'Password Cracking',
    hint: 'Hash(es)',
    color: 'var(--red)',
    icon: Hammer,
    items: [
      { tool: 'crack', label: 'Password Cracking', color: 'var(--red)', hint: 'John the Ripper wordlist attack against hashes', icon: Hammer, risk: 'critical' },
    ],
  },
  {
    category: 'Compliance Mapping',
    hint: 'Tool name / finding text',
    color: 'var(--green)',
    icon: ClipboardCheck,
    items: [
      { tool: 'compliance', label: 'Compliance Mapping', color: 'var(--green)', hint: 'Map findings to OWASP Top 10 / PTES / MITRE ATT&CK', icon: ClipboardCheck, risk: 'low' },
    ],
  },
];

const SPECIAL_NODES = [
  { type: 'llm',       label: 'LLM Analysis', color: 'var(--purple)', icon: Brain },
  { type: 'condition', label: 'Condition',     color: 'var(--amber)', icon: GitBranch },
  { type: 'report',    label: 'Report',        color: 'var(--orange)', icon: FileText },
];

// ── Metasploit module lists ────────────────────────────────────────────────────

const MSF_AUX_MODULE_GROUPS: { label: string; modules: { value: string; label: string }[] }[] = [
  { label: 'SMB / Windows', modules: [
    { value: 'auxiliary/scanner/smb/smb_version',          label: 'SMB Version Scanner' },
    { value: 'auxiliary/scanner/smb/smb_login',            label: 'SMB Login Brute-Force' },
    { value: 'auxiliary/scanner/smb/smb_enumshares',       label: 'SMB Share Enumeration' },
    { value: 'auxiliary/scanner/smb/smb_enumusers',        label: 'SMB User Enumeration' },
    { value: 'auxiliary/scanner/smb/smb_ms17_010',         label: 'EternalBlue Check (MS17-010)' },
  ]},
  { label: 'SSH', modules: [
    { value: 'auxiliary/scanner/ssh/ssh_version',          label: 'SSH Version Scanner' },
    { value: 'auxiliary/scanner/ssh/ssh_login',            label: 'SSH Login Brute-Force' },
    { value: 'auxiliary/scanner/ssh/ssh_enumusers',        label: 'SSH User Enumeration' },
  ]},
  { label: 'HTTP / Web', modules: [
    { value: 'auxiliary/scanner/http/http_version',        label: 'HTTP Version Scanner' },
    { value: 'auxiliary/scanner/http/title',               label: 'HTTP Title Grabber' },
    { value: 'auxiliary/scanner/http/dir_scanner',         label: 'HTTP Directory Scanner' },
    { value: 'auxiliary/scanner/http/files_dir',           label: 'HTTP File & Dir Scanner' },
    { value: 'auxiliary/scanner/http/robots_txt',          label: 'Robots.txt Scanner' },
    { value: 'auxiliary/scanner/http/http_login',          label: 'HTTP Auth Brute-Force' },
    { value: 'auxiliary/scanner/http/wordpress_login',     label: 'WordPress Login Brute-Force' },
    { value: 'auxiliary/scanner/http/tomcat_mgr_login',    label: 'Tomcat Manager Brute-Force' },
  ]},
  { label: 'FTP', modules: [
    { value: 'auxiliary/scanner/ftp/ftp_version',          label: 'FTP Version Scanner' },
    { value: 'auxiliary/scanner/ftp/ftp_login',            label: 'FTP Login Brute-Force' },
    { value: 'auxiliary/scanner/ftp/anonymous',            label: 'FTP Anonymous Login Check' },
  ]},
  { label: 'Database', modules: [
    { value: 'auxiliary/scanner/mssql/mssql_ping',         label: 'MSSQL Ping Scanner' },
    { value: 'auxiliary/scanner/mssql/mssql_login',        label: 'MSSQL Login Brute-Force' },
    { value: 'auxiliary/scanner/mysql/mysql_version',      label: 'MySQL Version Scanner' },
    { value: 'auxiliary/scanner/mysql/mysql_login',        label: 'MySQL Login Brute-Force' },
    { value: 'auxiliary/scanner/postgres/postgres_login',  label: 'PostgreSQL Login Brute-Force' },
    { value: 'auxiliary/scanner/oracle/oracle_login',      label: 'Oracle Login Brute-Force' },
  ]},
  { label: 'SNMP / Network', modules: [
    { value: 'auxiliary/scanner/snmp/snmp_login',          label: 'SNMP Community Brute-Force' },
    { value: 'auxiliary/scanner/snmp/snmp_enum',           label: 'SNMP Enumeration' },
    { value: 'auxiliary/scanner/portscan/tcp',             label: 'TCP Port Scanner' },
    { value: 'auxiliary/scanner/portscan/syn',             label: 'SYN Port Scanner' },
  ]},
  { label: 'RDP / VNC', modules: [
    { value: 'auxiliary/scanner/rdp/rdp_scanner',          label: 'RDP Service Scanner' },
    { value: 'auxiliary/scanner/vnc/vnc_login',            label: 'VNC Login Brute-Force' },
    { value: 'auxiliary/scanner/vnc/vnc_none_auth',        label: 'VNC No-Auth Check' },
  ]},
  { label: 'SMTP / Mail', modules: [
    { value: 'auxiliary/scanner/smtp/smtp_version',        label: 'SMTP Version Scanner' },
    { value: 'auxiliary/scanner/smtp/smtp_enum',           label: 'SMTP User Enumeration' },
  ]},
  { label: 'DNS', modules: [
    { value: 'auxiliary/gather/dns_enum',                  label: 'DNS Enumeration' },
    { value: 'auxiliary/gather/dns_info',                  label: 'DNS Info Gather' },
    { value: 'auxiliary/scanner/dns/dns_amp',              label: 'DNS Amplification Check' },
  ]},
];
const MSF_AUX_MODULES = MSF_AUX_MODULE_GROUPS.flatMap(g => g.modules);

const MSF_EXPLOIT_MODULE_GROUPS: { label: string; modules: { value: string; label: string }[] }[] = [
  { label: 'Windows / SMB', modules: [
    { value: 'exploit/windows/smb/ms17_010_eternalblue',   label: 'MS17-010 EternalBlue (SMB)' },
    { value: 'exploit/windows/smb/ms17_010_psexec',        label: 'MS17-010 EternalBlue PSExec' },
    { value: 'exploit/windows/smb/psexec',                 label: 'PSExec (SMB)' },
    { value: 'exploit/windows/smb/ms08_067_netapi',        label: 'MS08-067 NetAPI (XP/2003)' },
    { value: 'exploit/windows/smb/ms10_061_spoolss',       label: 'MS10-061 Print Spooler' },
  ]},
  { label: 'Windows / RDP', modules: [
    { value: 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce', label: 'BlueKeep RCE (CVE-2019-0708)' },
  ]},
  { label: 'Windows / HTTP', modules: [
    { value: 'exploit/windows/http/rejetto_hfs_exec',      label: 'Rejetto HFS Remote Code Exec' },
    { value: 'exploit/windows/iis/iis_webdav_upload_asp',  label: 'IIS WebDAV ASP Upload' },
    { value: 'exploit/windows/http/hyak_exec',             label: 'Hyak HTTP Exec' },
  ]},
  { label: 'Linux / Unix', modules: [
    { value: 'exploit/unix/ftp/vsftpd_234_backdoor',       label: 'vsftpd 2.3.4 Backdoor' },
    { value: 'exploit/unix/misc/distcc_exec',              label: 'DistCC RCE' },
    { value: 'exploit/linux/http/nostromo_code_exec',      label: 'Nostromo HTTP Server RCE' },
    { value: 'exploit/linux/samba/is_known_pipename',      label: 'Samba is_known_pipename RCE' },
  ]},
  { label: 'Multi / Web', modules: [
    { value: 'exploit/multi/http/struts2_content_type_ognl', label: 'Apache Struts2 OGNL Injection' },
    { value: 'exploit/multi/http/jenkins_script_console',  label: 'Jenkins Script Console RCE' },
    { value: 'exploit/multi/http/tomcat_mgr_upload',       label: 'Tomcat Manager WAR Upload RCE' },
    { value: 'exploit/multi/http/log4shell_header_injection', label: 'Log4Shell (CVE-2021-44228)' },
    { value: 'exploit/multi/handler',                      label: 'Multi/Handler (Catch Reverse Shell)' },
  ]},
  { label: 'Databases', modules: [
    { value: 'exploit/windows/mssql/mssql_payload',        label: 'MSSQL Payload Execution' },
    { value: 'exploit/multi/postgres/postgres_copy_from_program', label: 'PostgreSQL COPY FROM PROGRAM RCE' },
  ]},
];
const MSF_EXPLOIT_MODULES = MSF_EXPLOIT_MODULE_GROUPS.flatMap(g => g.modules);

const MSF_POST_MODULE_GROUPS: { label: string; modules: { value: string; label: string }[] }[] = [
  { label: 'Windows — Gather', modules: [
    { value: 'post/windows/gather/enum_logged_on_users',   label: 'Enumerate Logged-On Users' },
    { value: 'post/windows/gather/enum_shares',            label: 'Enumerate Shares' },
    { value: 'post/windows/gather/enum_applications',      label: 'Enumerate Installed Applications' },
    { value: 'post/windows/gather/hashdump',               label: 'Dump Password Hashes' },
    { value: 'post/windows/gather/credentials/credential_collector', label: 'Credential Collector' },
    { value: 'post/windows/gather/smart_hashdump',         label: 'Smart Hashdump (DC-aware)' },
  ]},
  { label: 'Windows — Privilege Escalation', modules: [
    { value: 'post/windows/escalate/getsystem',            label: 'GetSystem (UAC Bypass)' },
    { value: 'post/multi/recon/local_exploit_suggester',   label: 'Local Exploit Suggester' },
  ]},
  { label: 'Windows — Lateral Movement', modules: [
    { value: 'post/windows/manage/migrate',                label: 'Migrate Process' },
    { value: 'post/windows/manage/persistence',            label: 'Persistence (Registry)' },
    { value: 'post/windows/manage/enable_rdp',             label: 'Enable RDP' },
  ]},
  { label: 'Linux — Gather', modules: [
    { value: 'post/linux/gather/enum_users_history',       label: 'Enumerate Users & History' },
    { value: 'post/linux/gather/hashdump',                 label: 'Dump /etc/shadow Hashes' },
    { value: 'post/linux/gather/enum_configs',             label: 'Enumerate Config Files' },
    { value: 'post/linux/gather/enum_system',              label: 'Enumerate System Info' },
  ]},
  { label: 'Multi — Gather', modules: [
    { value: 'post/multi/gather/env',                      label: 'Gather Environment Variables' },
    { value: 'post/multi/gather/ssh_creds',                label: 'Gather SSH Credentials' },
    { value: 'post/multi/manage/shell_to_meterpreter',     label: 'Upgrade Shell to Meterpreter' },
  ]},
];
const MSF_POST_MODULES = MSF_POST_MODULE_GROUPS.flatMap(g => g.modules);
const MSF_ALL_MODULES = [...MSF_AUX_MODULES, ...MSF_EXPLOIT_MODULES, ...MSF_POST_MODULES];

// ── LLM providers ─────────────────────────────────────────────────────────────

// Ollama is an external server (configured by an admin); the rest are hosted API providers.
const LLM_PROVIDERS = PROVIDER_OPTIONS;

// ── Utility ───────────────────────────────────────────────────────────────────

let _uid = 1;
function uid() { return `n${Date.now()}_${_uid++}`; }

/** Convert a WorkflowPreset (step-based) into ReactFlow nodes + edges for the canvas. */
function buildPresetGraph(presetId: string): { nodes: WFNode[]; edges: WFEdge[] } {
  const preset = WORKFLOW_PRESETS[presetId];
  if (!preset) return { nodes: [], edges: [] };

  // Purpose-built editable chain for the Metasploit use case:
  // recon -> vulnerability intelligence -> exploitation -> interactive terminal handoff.
  if (presetId === 'metasploit_full_chain') {
    const nodes: WFNode[] = [];
    const edges: WFEdge[] = [];

    const startId = uid();
    const nmapId = uid();
    const cveId = uid();
    const kevId = uid();
    const epssId = uid();
    const pocId = uid();
    const msfChainId = uid();
    const handoffId = uid();

    nodes.push({
      id: startId,
      type: 'start',
      position: { x: 300, y: 40 },
      data: { target: '' },
    } as WFNode);

    nodes.push({
      id: nmapId,
      type: 'tool',
      position: { x: 300, y: 180 },
      data: {
        tool: 'nmap',
        label: 'nmap',
        nmap_action: 'nmap_scan',
        nmap_flags: '-sV -sC -T4 --open',
      },
    } as WFNode);

    nodes.push({
      id: cveId,
      type: 'tool',
      position: { x: 80, y: 340 },
      data: {
        tool: 'cve',
        label: 'cve',
        cve_action: 'search_cves',
        cve_keyword: '(target)',
        cve_limit: 20,
      },
    } as WFNode);

    nodes.push({
      id: kevId,
      type: 'tool',
      position: { x: 300, y: 340 },
      data: {
        tool: 'cisa_kev',
        label: 'cisa_kev',
        kev_action: 'check_kev',
      },
    } as WFNode);

    nodes.push({
      id: epssId,
      type: 'tool',
      position: { x: 520, y: 340 },
      data: {
        tool: 'epss',
        label: 'epss',
        epss_action: 'get_epss_score',
      },
    } as WFNode);

    nodes.push({
      id: pocId,
      type: 'tool',
      position: { x: 300, y: 500 },
      data: {
        tool: 'poc_index',
        label: 'poc_index',
        poc_action: 'poc_risk_summary',
        poc_limit: 10,
      },
    } as WFNode);

    nodes.push({
      id: msfChainId,
      type: 'tool',
      position: { x: 300, y: 660 },
      data: {
        tool: 'metasploit',
        label: 'metasploit_chain',
        msf_action: 'run_full_chain',
        msf_chain_mode: 'balanced',
        msf_chain_exploit_checks: true,
        msf_chain_post: true,
        msf_chain_limit: 24,
        msf_auto_chain: true,
      },
    } as WFNode);

    nodes.push({
      id: handoffId,
      type: 'tool',
      position: { x: 300, y: 820 },
      data: {
        tool: 'metasploit',
        label: 'interactive_handoff',
        msf_action: 'interactive_handoff',
      },
    } as WFNode);

    edges.push({ id: uid(), source: startId, target: nmapId, type: 'smoothstep' } as WFEdge);
    edges.push({ id: uid(), source: nmapId, target: cveId, type: 'smoothstep' } as WFEdge);
    edges.push({ id: uid(), source: nmapId, target: kevId, type: 'smoothstep' } as WFEdge);
    edges.push({ id: uid(), source: nmapId, target: epssId, type: 'smoothstep' } as WFEdge);
    edges.push({ id: uid(), source: cveId, target: pocId, type: 'smoothstep' } as WFEdge);
    edges.push({ id: uid(), source: kevId, target: pocId, type: 'smoothstep' } as WFEdge);
    edges.push({ id: uid(), source: epssId, target: pocId, type: 'smoothstep' } as WFEdge);
    edges.push({ id: uid(), source: pocId, target: msfChainId, type: 'smoothstep' } as WFEdge);
    edges.push({ id: uid(), source: msfChainId, target: handoffId, type: 'smoothstep' } as WFEdge);

    return { nodes, edges };
  }

  const nodes: WFNode[] = [];
  const edges: WFEdge[] = [];

  const COL_X  = 280;   // horizontal center
  const ROW_GAP = 130;  // vertical gap between nodes
  let y = 60;

  // Start node
  const startId = uid();
  nodes.push({ id: startId, type: 'start', position: { x: COL_X, y }, data: { target: '' } } as WFNode);
  y += ROW_GAP;

  let prevId = startId;

  const buildToolConfig = (tool: string): Record<string, unknown> => {
    if (tool === 'metasploit' && presetId === 'metasploit_full_chain') {
      return {
        msf_action: 'run_full_chain',
        msf_chain_mode: 'balanced',
        msf_chain_exploit_checks: true,
        msf_chain_post: true,
        msf_chain_limit: 24,
        msf_auto_chain: true,
      };
    }
    return {};
  };

  for (const step of preset.steps) {
    const stepSourceId = prevId;
    const firstToolIds: string[] = [];

    // Each tool in the step fans out from the same prevId (parallel tools)
    for (let i = 0; i < step.tools.length; i++) {
      const toolId = uid();
      const tool   = step.tools[i];
      const offsetX = step.tools.length > 1 ? (i - (step.tools.length - 1) / 2) * 200 : 0;
      nodes.push({
        id: toolId,
        type: 'tool',
        position: { x: COL_X + offsetX, y },
        data: { tool, label: tool, ...buildToolConfig(tool) },
      } as WFNode);
      edges.push({ id: uid(), source: stepSourceId, target: toolId, type: 'smoothstep' } as WFEdge);
      firstToolIds.push(toolId);
    }

    // For connecting to the next step, use the first tool node of this step
    prevId = firstToolIds[0];
    y += ROW_GAP;
  }

  return { nodes, edges };
}

// ── Right panel: node config editor ──────────────────────────────────────────

/** Shared input/select/textarea style */
function useInpStyle() {
  const base: React.CSSProperties = {
    background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 6,
    color: 'var(--text-primary)', padding: '6px 8px', fontSize: 12, width: '100%',
    outline: 'none', marginTop: 4,
  };
  return base;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label style={{ color: 'var(--text-secondary)', display: 'block' }}>
      <span style={{ fontSize: '0.6875rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</span>
      {children}
      {hint && <span style={{ display: 'block', fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: 3 }}>{hint}</span>}
    </label>
  );
}

function Section({ title }: { title: string }) {
  return (
    <div style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--cyan)', textTransform: 'uppercase',
      letterSpacing: '0.08em', borderBottom: '1px solid var(--border)', paddingBottom: 4, marginTop: 4, opacity: 0.7 }}>
      {title}
    </div>
  );
}

// ── Manifest-driven MCP tools ───────────────────────────────────
// The full catalog of MCP tools, served by GET /tools/manifest (one entry per real tool, generated from the real
// server schemas). The "MCP Tool" node lets a customer pick ANY of these and get an auto-generated form, so every tool
// the platform has is reachable from the builder without a hand-written panel each.
interface ManifestField {
  name: string;
  type: 'text' | 'number' | 'bool' | 'list';
  required: boolean;
  default: unknown;
  enum: string[] | null;
  hint: string;
}
interface ManifestTool {
  server: string;
  action: string;
  label: string;
  category: string;
  needs: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  offensive: boolean;
  hint: string;
  fields: ManifestField[];
}

let _manifestCache: ManifestTool[] | null = null;
let _manifestPromise: Promise<ManifestTool[]> | null = null;
// server short-name -> actions its hand-written panel already renders natively (the builder appends every OTHER action).
let _nativeActions: Record<string, string[]> = {};

function useToolManifest(): { tools: ManifestTool[]; loading: boolean; nativeActions: Record<string, string[]> } {
  const [tools, setTools] = useState<ManifestTool[]>(_manifestCache ?? []);
  const [loading, setLoading] = useState(!_manifestCache);
  useEffect(() => {
    if (_manifestCache) { setTools(_manifestCache); setLoading(false); return; }
    const promise = _manifestPromise ?? (_manifestPromise = toolsApi.manifest()
      .then(res => {
        _manifestCache = (res.data?.tools ?? []) as ManifestTool[];
        _nativeActions = (res.data?.native_actions ?? {}) as Record<string, string[]>;
        return _manifestCache;
      })
      .catch(() => { _manifestCache = []; return _manifestCache; }));
    let alive = true;
    promise.then(t => { if (alive) { setTools(t); setLoading(false); } });
    return () => { alive = false; };
  }, []);
  return { tools, loading, nativeActions: _nativeActions };
}

// The actions a server has that its hand-written panel does NOT already render (so the panel can append them). Each is a
// full manifest tool with its own fields; selecting one here dispatches it via the worker's manifest path.
function useExtraActions(server: string): { extras: ManifestTool[]; loading: boolean } {
  const { tools, loading, nativeActions } = useToolManifest();
  const native = new Set(nativeActions[server] ?? []);
  const extras = tools.filter(t => t.server === server && !native.has(t.action));
  return { extras, loading };
}

const RISK_COLOR: Record<string, string> = {
  low: 'var(--green)', medium: 'var(--amber)', high: 'var(--orange)', critical: 'var(--red)',
};

// Auto-generated form for one manifest tool. Field values are stored namespaced ("<server>.<action>.<field>") so two
// different tools on the same node id never collide, and the worker's generic dispatcher reads exactly these keys.
function ManifestToolFields({ tool, d, upd, inp }: {
  tool: ManifestTool;
  d: WFNodeData;
  upd: (p: Partial<WFNodeData>) => void;
  inp: React.CSSProperties;
}) {
  const dd = d as unknown as Record<string, unknown>;
  const keyOf = (fname: string) => `${tool.server}.${tool.action}.${fname}`;
  return (
    <>
      {tool.offensive && (
        <div style={{ fontSize: '0.6875rem', color: 'var(--red)', background: 'color-mix(in srgb, var(--red) 8%, transparent)',
          border: '1px solid color-mix(in srgb, var(--red) 25%, transparent)', borderRadius: 6, padding: '6px 8px', marginBottom: 6 }}>
          Exploitation-class tool. It only runs if the server has SOCIS_AGENT_ALLOW_OFFENSIVE enabled; otherwise the step is skipped with a note.
        </div>
      )}
      {tool.fields.length === 0 && (
        <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
          No parameters. Runs against the Start node target.
        </div>
      )}
      {tool.fields.map(fld => {
        const k = keyOf(fld.name);
        const cur = dd[k];
        const labelText = fld.name.replace(/_/g, ' ') + (fld.required ? ' *' : '');
        const hint = fld.hint || (fld.required ? 'Required' : 'Optional');
        if (fld.enum && fld.enum.length > 0) {
          return (
            <Field key={k} label={labelText} hint={hint}>
              <select value={String(cur ?? fld.default ?? fld.enum[0])} onChange={e => upd({ [k]: e.target.value } as Partial<WFNodeData>)}
                style={{ ...inp, cursor: 'pointer' }}>
                {fld.enum.map(opt => <option key={opt} value={opt}>{opt}</option>)}
              </select>
            </Field>
          );
        }
        if (fld.type === 'bool') {
          return (
            <Field key={k} label={labelText} hint={hint}>
              <select value={cur === undefined ? String(!!fld.default) : String(!!cur)}
                onChange={e => upd({ [k]: e.target.value === 'true' } as Partial<WFNodeData>)} style={{ ...inp, cursor: 'pointer' }}>
                <option value="false">No</option>
                <option value="true">Yes</option>
              </select>
            </Field>
          );
        }
        return (
          <Field key={k} label={labelText} hint={hint}>
            <input type={fld.type === 'number' ? 'number' : 'text'}
              value={cur === undefined || cur === null ? '' : String(cur)}
              onChange={e => upd({ [k]: e.target.value } as Partial<WFNodeData>)}
              style={inp}
              placeholder={fld.default != null ? `default: ${fld.default}` : (fld.name in { target: 1, url: 1, hostname: 1, host: 1, ip: 1, domain: 1 } ? '(inherited from Start node)' : (fld.name in { cve: 1, cve_id: 1, keyword: 1, query: 1, search: 1 } ? '(inherited from Start node)' : ''))} />
          </Field>
        );
      })}
    </>
  );
}

// ── CVE Lite: project upload + pick widget ─────────────────────
function CveLiteProjectPicker({ value, onChange, inp }: {
  value: string;
  onChange: (path: string) => void;
  inp: React.CSSProperties;
}) {
  const [projects, setProjects] = useState<{ name: string; path: string }[]>([]);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [loadingProjects, setLoadingProjects] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const currentName = value.replace(/^\/projects\//, '');

  const fetchProjects = async () => {
    setLoadingProjects(true);
    try {
      const res = await toolsApi.cveLiteProjects();
      setProjects(res.data.projects ?? []);
    } catch {
      // silently ignore — list is optional
    } finally {
      setLoadingProjects(false);
    }
  };

  useEffect(() => { fetchProjects(); }, []);

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setUploadError('');
    try {
      const res = await toolsApi.cveLiteUpload(file);
      const { project_name, path } = res.data;
      onChange(path);
      await fetchProjects();
      // Show the new project selected
      setProjects(prev => prev.some(p => p.name === project_name) ? prev : [...prev, { name: project_name, path }]);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Upload failed.';
      setUploadError(msg);
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  };

  const handleDelete = async (name: string) => {
    try {
      await toolsApi.cveLiteDeleteProject(name);
      if (currentName === name) onChange('');
      await fetchProjects();
    } catch {
      // ignore
    }
  };

  const borderColor = uploadError ? 'var(--red)' : 'var(--text-muted)';

  return (
    <Field label="Project" hint="Upload a .zip or .tar.gz of the JS/TS project, then select it below">
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>

        {/* Upload button */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <button
            type="button"
            onClick={() => fileRef.current?.click()}
            disabled={uploading}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '6px 12px', borderRadius: 'var(--radius-sm)', fontSize: '0.75rem', cursor: uploading ? 'default' : 'pointer',
              background: uploading ? 'var(--bg-card)' : 'var(--bg-secondary)',
              border: '1px solid var(--border)', color: uploading ? 'var(--text-muted)' : 'var(--text-secondary)',
              transition: 'all 0.15s',
            }}
          >
            {uploading
              ? <><Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> Uploading…</>
              : <><Upload size={12} /> Upload project archive</>}
          </button>
          <button
            type="button"
            onClick={fetchProjects}
            title="Refresh project list"
            style={{ padding: '6px 8px', borderRadius: 'var(--radius-sm)', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-muted)', cursor: 'pointer' }}
          >
            <RefreshCw size={12} style={loadingProjects ? { animation: 'spin 1s linear infinite' } : {}} />
          </button>
          <input ref={fileRef} type="file" accept=".zip,.tar.gz,.tgz" style={{ display: 'none' }} onChange={handleUpload} />
        </div>

        {uploadError && (
          <span style={{ fontSize: '0.6875rem', color: 'var(--red)' }}>{uploadError}</span>
        )}

        {/* Project picker — shows uploaded projects + manual entry */}
        {projects.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {projects.map(p => (
              <div
                key={p.name}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '5px 10px', borderRadius: 'var(--radius-sm)', cursor: 'pointer',
                  border: `1px solid ${currentName === p.name ? 'var(--indigo)' : 'var(--border)'}`,
                  background: currentName === p.name ? 'var(--bg-hover)' : 'var(--bg-secondary)',
                  transition: 'all 0.15s',
                }}
                onClick={() => onChange(p.path)}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Package size={11} color={currentName === p.name ? 'var(--blue)' : 'var(--text-muted)'} />
                  <span style={{ fontSize: '0.75rem', color: currentName === p.name ? 'var(--blue)' : 'var(--text-secondary)' }}>{p.name}</span>
                </div>
                <button
                  type="button"
                  onClick={ev => { ev.stopPropagation(); handleDelete(p.name); }}
                  title="Delete project"
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2 }}
                >
                  <Trash2 size={11} />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
            No projects uploaded yet. Upload an archive above.
          </span>
        )}

        {/* Manual name entry (fallback) */}
        <div>
          <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>Or enter name manually:</span>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <span style={{ padding: '6px 8px', background: 'var(--bg-secondary)', border: `1px solid ${borderColor}`, borderRight: 'none', borderRadius: 'var(--radius-sm) 0 0 var(--radius-sm)', color: 'var(--text-muted)', fontSize: '0.6875rem', whiteSpace: 'nowrap', userSelect: 'none' }}>/projects/</span>
            <input
              value={currentName}
              onChange={e => {
                const name = e.target.value.replace(/[/\\]/g, '').replace(/\.\./g, '').replace(/\x00/g, '');
                onChange(name ? `/projects/${name}` : '');
              }}
              style={{ ...inp, borderRadius: '0 var(--radius-sm) var(--radius-sm) 0', flex: 1, borderColor }}
              placeholder="my-app"
              maxLength={64}
            />
          </div>
        </div>

      </div>
    </Field>
  );
}

// Appended to each native per-server panel: a dropdown of every action that server has beyond the ones the panel renders
// natively, plus the auto-generated form for the chosen one. This is what makes each panel list EVERY tool its server
// offers, without a hand-written option/field block per action. The chosen action is written to the panel's own
// "<actionKey>" (e.g. nmap_action, edb_action) so the worker routes it through the manifest dispatcher.
function ServerActionExtras({ server, actionKey, d, upd, inp }: {
  server: string;
  actionKey: string;
  d: WFNodeData;
  upd: (p: Partial<WFNodeData>) => void;
  inp: React.CSSProperties;
}) {
  const { extras, loading } = useExtraActions(server);
  const dd = d as unknown as Record<string, unknown>;
  const currentAction = dd[actionKey] as string | undefined;
  const selectedExtra = extras.find(t => t.action === currentAction);

  if (loading || extras.length === 0) return null;

  return (
    <div style={{ marginTop: 10, borderTop: '1px dashed var(--border)', paddingTop: 10 }}>
      <Field label="More Actions" hint={`${extras.length} more ${server} tool${extras.length === 1 ? '' : 's'} available`}>
        <select
          value={selectedExtra ? currentAction : ''}
          onChange={e => {
            const v = e.target.value;
            if (v) upd({ [actionKey]: v } as Partial<WFNodeData>);
          }}
          style={{ ...inp, cursor: 'pointer' }}>
          <option value="">— pick an additional {server} action —</option>
          {extras.map(t => (
            <option key={t.action} value={t.action}>
              {t.label}{t.offensive ? '  \u26A0 opt-in' : ''}
            </option>
          ))}
        </select>
      </Field>
      {selectedExtra && (
        <div style={{ marginTop: 6 }}>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 4 }}>{selectedExtra.hint}</div>
          <ManifestToolFields tool={selectedExtra} d={d} upd={upd} inp={inp} />
        </div>
      )}
    </div>
  );
}

/** Per-tool config fields rendered inside the tool node config panel */
function ToolSpecificFields({ d, upd, inp }: {
  d: WFNodeData;
  upd: (p: Partial<WFNodeData>) => void;
  inp: React.CSSProperties;
}) {
  const tool = d.tool ?? '';

  // ── nmap ──────────────────────────────────────────────────────
  if (tool === 'nmap') {
    const nmap_action = d.nmap_action ?? 'nmap_scan';
    return (
      <>
        <Field label="Action" hint="Which Nmap operation to run">
          <select value={nmap_action} onChange={e => upd({ nmap_action: e.target.value })}
            style={{ ...inp, cursor: 'pointer' }}>
            <option value="nmap_scan">Port Scan (nmap_scan)</option>
            <option value="port_check">Single Port Check</option>
            <option value="os_detect">OS Detection</option>
          </select>
        </Field>

        {nmap_action === 'nmap_scan' && <>
          <Field label="Nmap Flags" hint="Scan options passed directly to nmap">
            <input value={d.nmap_flags ?? d.flags ?? '-sV -sC -T4 --open'}
              onChange={e => upd({ nmap_flags: e.target.value, flags: e.target.value })}
              style={inp} placeholder="-sV -sC -T4 --open" />
          </Field>
          <Field label="Port Specification" hint="e.g. 22,80,443 or 1-1000 or top100. Leave blank for default.">
            <input value={d.nmap_ports ?? ''}
              onChange={e => upd({ nmap_ports: e.target.value })}
              style={inp} placeholder="(default nmap ports)" />
          </Field>
        </>}

        {nmap_action === 'port_check' && <>
          <Field label="Port" hint="Single port to check if open">
            <input type="number" value={d.nmap_check_port ?? 80}
              onChange={e => upd({ nmap_check_port: parseInt(e.target.value) || 80 })}
              style={inp} />
          </Field>
        </>}

        {nmap_action === 'os_detect' && (
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-secondary)', marginTop: 6, opacity: 0.7, fontStyle: 'italic' }}>
            No additional parameters required. Runs OS detection on Start node target.
          </div>
        )}
        <ServerActionExtras server="nmap" actionKey="nmap_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── cve ───────────────────────────────────────────────────────
  if (tool === 'cve') {
    const cve_action = d.cve_action ?? 'search_cves';
    return (
      <>
        <Field label="Action" hint="Which CVE database operation to run">
          <select value={cve_action} onChange={e => upd({ cve_action: e.target.value })}
            style={{ ...inp, cursor: 'pointer' }}>
            <option value="search_cves">Search CVEs by Keyword / Product</option>
            <option value="lookup_cve">Lookup Specific CVE</option>
            <option value="get_severity">Get CVSS Severity Score</option>
            <option value="cpe_search">Search by CPE (platform)</option>
          </select>
        </Field>

        {cve_action === 'search_cves' && <>
          <Field label="Search Keyword" hint="CVE-ID, software name, or keyword. Leave blank to use Start node value.">
            <input value={d.cve_keyword ?? ''}
              onChange={e => upd({ cve_keyword: e.target.value })}
              style={inp} placeholder="CVE-2021-44228, apache, openssl … (blank = from Start)" />
          </Field>
          <Field label="Severity Filter">
            <select value={d.cve_severity ?? ''} onChange={e => upd({ cve_severity: e.target.value })}
              style={{ ...inp, cursor: 'pointer' }}>
              <option value="">All severities</option>
              <option value="CRITICAL">Critical only</option>
              <option value="HIGH">High only</option>
              <option value="MEDIUM">Medium only</option>
              <option value="LOW">Low only</option>
            </select>
          </Field>
          <Field label="Max Results">
            <input type="number" value={d.cve_limit ?? 20}
              onChange={e => upd({ cve_limit: parseInt(e.target.value) || 20 })}
              style={inp} min={1} max={100} />
          </Field>
        </>}

        {(cve_action === 'lookup_cve' || cve_action === 'get_severity') && <>
          <Field label="CVE ID(s)" hint="Single CVE or comma-separated list. Leave blank to use Start node value.">
            <input value={d.cve_cve_id ?? ''}
              onChange={e => upd({ cve_cve_id: e.target.value })}
              style={inp} placeholder="CVE-2021-44228, CVE-2022-0847 (blank = from Start)" />
          </Field>
        </>}

        {cve_action === 'cpe_search' && <>
          <Field label="CPE String" hint="Common Platform Enumeration identifier">
            <input value={d.cve_cpe ?? ''}
              onChange={e => upd({ cve_cpe: e.target.value })}
              style={inp} placeholder="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" />
          </Field>
        </>}
        <ServerActionExtras server="cve" actionKey="cve_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── nuclei ────────────────────────────────────────────────────
  if (tool === 'nuclei') {
    const nuclei_action = d.nuclei_action ?? 'nuclei_scan';
    return (
      <>
        <Field label="Action" hint="Which Nuclei scan mode to use">
          <select value={nuclei_action} onChange={e => upd({ nuclei_action: e.target.value })}
            style={{ ...inp, cursor: 'pointer' }}>
            <option value="nuclei_scan">Full Vulnerability Scan</option>
            <option value="nuclei_cve_scan">CVE-Only Scan</option>
            <option value="nuclei_tech_detect">Technology Detection</option>
            <option value="list_templates">List Available Templates</option>
          </select>
        </Field>

        {nuclei_action === 'nuclei_scan' && <>
          <Field label="Templates / Tags" hint="Comma-separated nuclei template tags or paths. Leave blank for default.">
            <input value={d.nuclei_templates ?? ''}
              onChange={e => upd({ nuclei_templates: e.target.value })}
              style={inp} placeholder="cve,sqli,xss,rce" />
          </Field>
          <Field label="Severity Filter">
            <select value={d.nuclei_severity ?? ''} onChange={e => upd({ nuclei_severity: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
              <option value="">All severities</option>
              <option value="critical">Critical only</option>
              <option value="critical,high">Critical + High</option>
              <option value="critical,high,medium">Critical / High / Medium</option>
              <option value="low,info">Low + Info</option>
            </select>
          </Field>
          <Field label="Rate Limit (req/s)">
            <input type="number" value={d.nuclei_rate_limit ?? 100}
              onChange={e => upd({ nuclei_rate_limit: parseInt(e.target.value) || 100 })}
              style={inp} min={1} max={500} />
          </Field>
          <Field label="Concurrency (-c)" hint="Templates run in parallel per host">
            <input type="number" value={d.nuclei_concurrency ?? 25}
              onChange={e => upd({ nuclei_concurrency: parseInt(e.target.value) || 25 })}
              style={inp} min={1} max={100} />
          </Field>
          <Field label="Retries" hint="Retry failed requests N times">
            <input type="number" value={d.nuclei_retries ?? 1}
              onChange={e => upd({ nuclei_retries: parseInt(e.target.value) || 1 })}
              style={inp} min={0} max={5} />
          </Field>
          <Field label="Proxy URL" hint="e.g. http://127.0.0.1:8080">
            <input value={d.nuclei_proxy ?? ''}
              onChange={e => upd({ nuclei_proxy: e.target.value })}
              style={inp} placeholder="http://127.0.0.1:8080" />
          </Field>
          <Field label="Extra Headers" hint="One header per line: Name: Value">
            <textarea value={d.nuclei_headers ?? ''}
              onChange={e => upd({ nuclei_headers: e.target.value })}
              style={{ ...inp, height: 60 }} placeholder={'Authorization: Bearer token\nX-Custom: value'} />
          </Field>
          <Field label="Exclude Tags" hint="Comma-separated tags to skip e.g. dos,fuzz">
            <input value={d.nuclei_exclude_tags ?? ''}
              onChange={e => upd({ nuclei_exclude_tags: e.target.value })}
              style={inp} placeholder="dos,fuzz" />
          </Field>
          <Field label="Disable Interactsh" hint="Disable OOB server (use for isolated networks)">
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
              <input type="checkbox" checked={!!d.nuclei_no_interactsh}
                onChange={e => upd({ nuclei_no_interactsh: e.target.checked })} />
              <span style={{ fontSize: '0.6875rem' }}>No Interactsh</span>
            </label>
          </Field>
        </>}

        {nuclei_action === 'nuclei_cve_scan' && <>
          <Field label="CVE Year Filter" hint="0 = all years; e.g. 2024 for CVE-2024-* only">
            <input type="number" value={d.nuclei_year ?? 0}
              onChange={e => upd({ nuclei_year: parseInt(e.target.value) || 0 })}
              style={inp} min={0} max={2099} placeholder="0 (all years)" />
          </Field>
        </>}

        {nuclei_action === 'list_templates' && <>
          <Field label="Category Filter" hint="e.g. cves, exposures, misconfiguration">
            <input value={d.nuclei_category ?? ''}
              onChange={e => upd({ nuclei_category: e.target.value })}
              style={inp} placeholder="(all categories)" />
          </Field>
        </>}

        {nuclei_action === 'nuclei_tech_detect' && (
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-secondary)', marginTop: 6, opacity: 0.7, fontStyle: 'italic' }}>
            No additional parameters required. Detects technologies on Start node target.
          </div>
        )}
        <ServerActionExtras server="nuclei" actionKey="nuclei_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── subfinder ─────────────────────────────────────────────────
  if (tool === 'subfinder') return (
    <>
      <Field label="Domain" hint="Override target domain for subdomain enumeration">
        <input value={d.domain ?? ''}
          onChange={e => upd({ domain: e.target.value })}
          style={inp} placeholder="example.com (leave blank to use Start node target)" />
      </Field>
    </>
  );

  // ── dig / DNS Lookup ──────────────────────────────────────────
  if (tool === 'dig') return (
    <>
      <Field label="Domain">
        <input value={d.domain ?? ''}
          onChange={e => upd({ domain: e.target.value })}
          style={inp} placeholder="example.com" />
      </Field>
      <Field label="Record Type">
        <select value={d.record_type ?? 'A'} onChange={e => upd({ record_type: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
          {['A','AAAA','MX','TXT','NS','CNAME','SOA','PTR','SRV','CAA'].map(r => <option key={r} value={r}>{r}</option>)}
        </select>
      </Field>
    </>
  );

  // ── whois ─────────────────────────────────────────────────────
  if (tool === 'whois') return (
    <Field label="Domain / IP" hint="Leave blank to use the Start node target">
      <input value={d.domain ?? ''}
        onChange={e => upd({ domain: e.target.value })}
        style={inp} placeholder="example.com" />
    </Field>
  );

  // ── ssl ───────────────────────────────────────────────────────
  if (tool === 'ssl') return (
    <>
      <Field label="Hostname" hint="Leave blank to use Start node target">
        <input value={d.domain ?? ''}
          onChange={e => upd({ domain: e.target.value })}
          style={inp} placeholder="example.com" />
      </Field>
      <Field label="Port">
        <input type="number" value={d.nikto_port ?? 443}
          onChange={e => upd({ nikto_port: parseInt(e.target.value) || 443 })}
          style={inp} />
      </Field>
      <ServerActionExtras server="ssl" actionKey="ssl_action" d={d} upd={upd} inp={inp} />
    </>
  );

  // ── ffuf ─────────────────────────────────────────────────────
  if (tool === 'ffuf') return (
    <>
      <Field label="Target URL" hint="Use FUZZ as placeholder. Leave blank to auto-detect.">
        <input value={d.ffuf_url ?? ''}
          onChange={e => upd({ ffuf_url: e.target.value })}
          style={inp} placeholder="http://target/FUZZ" />
      </Field>
      <Field label="Wordlist" hint="Built-in wordlists from /usr/share/wordlists/">
        <select value={d.ffuf_wordlist ?? 'common'} onChange={e => upd({ ffuf_wordlist: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
          {WORDLIST_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      </Field>
      <Field label="Extensions (comma-sep)">
        <input value={d.ffuf_extensions ?? ''}
          onChange={e => upd({ ffuf_extensions: e.target.value })}
          style={inp} placeholder="php,html,js" />
      </Field>
      <Field label="HTTP Method">
        <select value={d.ffuf_method ?? 'GET'} onChange={e => upd({ ffuf_method: e.target.value })}
          style={{ ...inp, cursor: 'pointer' }}>
          {['GET','POST','PUT','DELETE','HEAD'].map(m => <option key={m} value={m}>{m}</option>)}
        </select>
      </Field>
      <Field label="Threads" hint="Concurrent threads (1-100)">
        <input type="number" value={d.ffuf_threads ?? 20}
          onChange={e => upd({ ffuf_threads: parseInt(e.target.value) || 20 })}
          style={inp} min={1} max={100} />
      </Field>
      <Field label="Rate Limit (req/s)" hint="0 = unlimited">
        <input type="number" value={d.ffuf_rate ?? 0}
          onChange={e => upd({ ffuf_rate: parseInt(e.target.value) || 0 })}
          style={inp} min={0} max={10000} />
      </Field>
      <Field label="Per-Request Timeout (s)">
        <input type="number" value={d.ffuf_timeout ?? 10}
          onChange={e => upd({ ffuf_timeout: parseInt(e.target.value) || 10 })}
          style={inp} min={1} max={60} />
      </Field>
      <Field label="Match Codes" hint="Show only these HTTP codes e.g. 200,301">
        <input value={d.ffuf_match_codes ?? ''}
          onChange={e => upd({ ffuf_match_codes: e.target.value })}
          style={inp} placeholder="200,301,302" />
      </Field>
      <Field label="Filter Codes" hint="Hide these HTTP status codes e.g. 404,400">
        <input value={d.ffuf_filter_codes ?? ''}
          onChange={e => upd({ ffuf_filter_codes: e.target.value })}
          style={inp} placeholder="404,400" />
      </Field>
      <Field label="Filter Size (bytes)" hint="Hide responses of this size e.g. 1234">
        <input value={d.ffuf_filter_size ?? ''}
          onChange={e => upd({ ffuf_filter_size: e.target.value })}
          style={inp} placeholder="1234" />
      </Field>
      <Field label="Filter Words" hint="Hide responses with this word count e.g. 42">
        <input value={d.ffuf_filter_words ?? ''}
          onChange={e => upd({ ffuf_filter_words: e.target.value })}
          style={inp} placeholder="42" />
      </Field>
      <Field label="POST Data" hint="Body data for POST fuzzing e.g. username=FUZZ&password=test">
        <input value={d.ffuf_data ?? ''}
          onChange={e => upd({ ffuf_data: e.target.value })}
          style={inp} placeholder="username=FUZZ&password=test" />
      </Field>
      <Field label="Extra Headers" hint="One header per line: Name: Value">
        <textarea value={d.ffuf_headers ?? ''}
          onChange={e => upd({ ffuf_headers: e.target.value })}
          style={{ ...inp, height: 60 }} placeholder={'Authorization: Bearer token\nX-Custom: value'} />
      </Field>
      <Field label="Recursion">
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
          <input type="checkbox" checked={!!d.ffuf_recursion}
            onChange={e => upd({ ffuf_recursion: e.target.checked })} />
          <span style={{ fontSize: '0.6875rem' }}>Enable recursive fuzzing</span>
        </label>
      </Field>
      {!!d.ffuf_recursion && (
        <Field label="Recursion Depth" hint="Max depth (1-5)">
          <input type="number" value={d.ffuf_recursion_depth ?? 2}
            onChange={e => upd({ ffuf_recursion_depth: parseInt(e.target.value) || 2 })}
            style={inp} min={1} max={5} />
        </Field>
      )}
      <ServerActionExtras server="ffuf" actionKey="ffuf_action" d={d} upd={upd} inp={inp} />
    </>
  );

  // ── sqlmap ────────────────────────────────────────────────────
  if (tool === 'sqlmap' || tool === 'sqlmap_full') {
    const isFullChain = tool === 'sqlmap_full';
    return (
      <>
        {isFullChain && (
          <div style={{ background: 'var(--bg-primary)', border: '1px solid var(--red)', borderRadius: 'var(--radius-sm)', padding: '6px 10px', fontSize: '0.6875rem', color: 'var(--red)', lineHeight: 1.6, marginBottom: 4 }}>
            <strong style={{ color: 'var(--red)' }}>Full Chain Mode</strong><br />
            Detects injection → auto-enumerates: databases, tables, users, password hashes, DBA status. Runs all techniques (BEUSTQ) at level 3/risk 2.
          </div>
        )}
        <Field label="Target URL" hint="URL with injectable parameter, e.g. http://site/page?id=1">
          <input value={d.sqlmap_url ?? ''}
            onChange={e => upd({ sqlmap_url: e.target.value })}
            style={inp} placeholder="http://target/page?id=1" />
        </Field>
        <Field label="POST Data (optional)" hint="Body data for POST requests">
          <input value={d.sqlmap_data ?? ''}
            onChange={e => upd({ sqlmap_data: e.target.value })}
            style={inp} placeholder="username=admin&password=1" />
        </Field>
        <Field label="Cookie" hint="Session cookie for authenticated scans (optional)">
          <input value={String(d.sqlmap_cookie ?? '')}
            onChange={e => upd({ sqlmap_cookie: e.target.value })}
            style={inp} placeholder="PHPSESSID=abc123" />
        </Field>
        <Field label="Technique">
          <select value={d.sqlmap_technique ?? 'BEUSTQ'} onChange={e => upd({ sqlmap_technique: e.target.value })}
            style={{ ...inp, cursor: 'pointer' }}>
            <option value="BEUSTQ">All techniques (BEUSTQ)</option>
            <option value="B">Boolean-based blind (B)</option>
            <option value="E">Error-based (E)</option>
            <option value="U">Union-based (U)</option>
            <option value="S">Stacked queries (S)</option>
            <option value="T">Time-based blind (T)</option>
            <option value="BT">Boolean + Time-based (BT)</option>
            <option value="UE">Union + Error-based (UE)</option>
          </select>
        </Field>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
          <Field label="Level (1-5)">
            <input type="number" value={Number(d.sqlmap_level ?? 3)} min={1} max={5}
              onChange={e => upd({ sqlmap_level: parseInt(e.target.value) || 3 })} style={inp} />
          </Field>
          <Field label="Risk (1-3)">
            <input type="number" value={Number(d.sqlmap_risk ?? 2)} min={1} max={3}
              onChange={e => upd({ sqlmap_risk: parseInt(e.target.value) || 2 })} style={inp} />
          </Field>
          <Field label="Threads">
            <input type="number" value={Number(d.sqlmap_threads ?? 4)} min={1} max={10}
              onChange={e => upd({ sqlmap_threads: parseInt(e.target.value) || 4 })} style={inp} />
          </Field>
        </div>
        <Field label="DBMS" hint="Force database type (leave blank for auto-detect)">
          <select value={d.sqlmap_dbms ?? ''} onChange={e => upd({ sqlmap_dbms: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
            <option value="">Auto-detect</option>
            <option value="MySQL">MySQL</option>
            <option value="PostgreSQL">PostgreSQL</option>
            <option value="Microsoft SQL Server">MSSQL</option>
            <option value="Oracle">Oracle</option>
            <option value="SQLite">SQLite</option>
            <option value="Microsoft Access">MS Access</option>
          </select>
        </Field>
        <Field label="Tamper Scripts" hint="Comma-separated tamper scripts e.g. space2comment,between">
          <input value={d.sqlmap_tamper ?? ''}
            onChange={e => upd({ sqlmap_tamper: e.target.value })}
            style={inp} placeholder="space2comment,between" />
        </Field>
        <Field label="Proxy URL" hint="e.g. http://127.0.0.1:8080">
          <input value={d.sqlmap_proxy ?? ''}
            onChange={e => upd({ sqlmap_proxy: e.target.value })}
            style={inp} placeholder="http://127.0.0.1:8080" />
        </Field>
        <Field label="Extra Headers" hint="One header per line: Name: Value">
          <textarea value={d.sqlmap_headers ?? ''}
            onChange={e => upd({ sqlmap_headers: e.target.value })}
            style={{ ...inp, height: 60 }} placeholder={'X-Forwarded-For: 127.0.0.1\nReferer: http://site/'} />
        </Field>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <Field label="Auth Type">
            <select value={d.sqlmap_auth_type ?? ''} onChange={e => upd({ sqlmap_auth_type: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
              <option value="">None</option>
              <option value="Basic">Basic</option>
              <option value="Digest">Digest</option>
              <option value="NTLM">NTLM</option>
            </select>
          </Field>
          <Field label="Auth Credentials" hint="user:pass">
            <input value={d.sqlmap_auth_cred ?? ''}
              onChange={e => upd({ sqlmap_auth_cred: e.target.value })}
              style={inp} placeholder="admin:password" />
          </Field>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <Field label="Delay (s)" hint="Seconds between requests">
            <input type="number" value={Number(d.sqlmap_delay ?? 0)} min={0} max={30}
              onChange={e => upd({ sqlmap_delay: parseInt(e.target.value) || 0 })} style={inp} />
          </Field>
          <Field label="Time-Based Sec" hint="Wait time for time-based blind (--time-sec)">
            <input type="number" value={Number(d.sqlmap_time_sec ?? 5)} min={1} max={30}
              onChange={e => upd({ sqlmap_time_sec: parseInt(e.target.value) || 5 })} style={inp} />
          </Field>
          <Field label="Timeout (s)">
            <input type="number" value={Number(d.sqlmap_timeout ?? 30)} min={5} max={120}
              onChange={e => upd({ sqlmap_timeout: parseInt(e.target.value) || 30 })} style={inp} />
          </Field>
          <Field label="Retries">
            <input type="number" value={Number(d.sqlmap_retries ?? 2)} min={0} max={10}
              onChange={e => upd({ sqlmap_retries: parseInt(e.target.value) || 2 })} style={inp} />
          </Field>
        </div>
        <ServerActionExtras server="sqlmap" actionKey="sqlmap_action" d={d} upd={upd} inp={inp} />
    </>
    );
  }

  // ── masscan ───────────────────────────────────────────────────
  if (tool === 'masscan') {
    const masscan_action = d.masscan_action ?? 'masscan_scan';
    return (
      <>
        <Field label="Action">
          <select value={masscan_action} onChange={e => upd({ masscan_action: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
            <option value="masscan_scan">Port Scan (custom range)</option>
            <option value="masscan_top_ports">Top Ports Scan</option>
            <option value="masscan_range">CIDR Range Scan</option>
          </select>
        </Field>
        {masscan_action === 'masscan_scan' && <>
          <Field label="Port Range" hint="e.g. 1-1024 or 80,443,8080">
            <input value={d.masscan_ports ?? '1-1024'} onChange={e => upd({ masscan_ports: e.target.value })} style={inp} placeholder="1-1024" />
          </Field>
        </>}
        {masscan_action === 'masscan_top_ports' && <>
          <Field label="Top N Ports">
            <select value={d.masscan_top ?? 1000} onChange={e => upd({ masscan_top: parseInt(e.target.value) })} style={{ ...inp, cursor: 'pointer' }}>
              <option value={100}>Top 100</option>
              <option value={1000}>Top 1000</option>
              <option value={10000}>Top 10000</option>
            </select>
          </Field>
        </>}
        {masscan_action === 'masscan_range' && <>
          <Field label="CIDR Range" hint="e.g. 192.168.1.0/24">
            <input value={d.masscan_cidr ?? ''} onChange={e => upd({ masscan_cidr: e.target.value })} style={inp} placeholder="192.168.1.0/24" />
          </Field>
          <Field label="Ports" hint="Comma-separated: 22,80,443,3389">
            <input value={d.masscan_ports ?? '22,80,443,445,3389,8080'} onChange={e => upd({ masscan_ports: e.target.value })} style={inp} placeholder="22,80,443,3389" />
          </Field>
        </>}
        <Field label="Rate (pps)" hint="Packets per second — max 10000">
          <input type="number" value={d.masscan_rate ?? 1000} min={1} max={10000} onChange={e => upd({ masscan_rate: parseInt(e.target.value) || 1000 })} style={inp} />
        </Field>
        <Field label="Extra Args" hint="Additional masscan flags, e.g. --banners or --source-port 61000">
          <input value={(d.masscan_extra_args as string) ?? ''} onChange={e => upd({ masscan_extra_args: e.target.value })} style={inp} placeholder="(optional)" />
        </Field>
        <ServerActionExtras server="masscan" actionKey="masscan_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── nikto ─────────────────────────────────────────────────────
  if (tool === 'nikto') {
    const nikto_action = d.nikto_action ?? 'nikto_scan';
    return (
      <>
        <Field label="Action">
          <select value={nikto_action} onChange={e => upd({ nikto_action: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
            <option value="nikto_scan">Full Scan</option>
            <option value="nikto_tuning">Targeted Scan (tuning)</option>
            <option value="nikto_ssl_only">SSL/TLS Scan Only</option>
          </select>
        </Field>
        <Field label="Target URL" hint="Leave blank to use Start node target">
          <input value={d.nikto_url ?? ''} onChange={e => upd({ nikto_url: e.target.value })} style={inp} placeholder="http://target.com" />
        </Field>
        {nikto_action === 'nikto_tuning' && <>
          <Field label="Tuning Codes" hint="1=Files, 2=Misconfig, 3=InfoDisc, 4=Injection, 5=RFI, 8=RCE, 9=SQLi">
            <input value={d.nikto_tuning ?? '1234'} onChange={e => upd({ nikto_tuning: e.target.value })} style={inp} placeholder="1234" />
          </Field>
        </>}
        <Field label="Port" hint="Default: 80 (HTTP) or 443 (SSL)">
          <input type="number" value={d.nikto_port ?? 80} onChange={e => upd({ nikto_port: parseInt(e.target.value) || 80 })} style={inp} />
        </Field>
        <Field label="User Agent" hint="Custom User-Agent string">
          <input value={d.nikto_useragent ?? ''}
            onChange={e => upd({ nikto_useragent: e.target.value })}
            style={inp} placeholder="Mozilla/5.0 ..." />
        </Field>
        <Field label="Proxy URL" hint="e.g. http://127.0.0.1:8080">
          <input value={d.nikto_proxy ?? ''}
            onChange={e => upd({ nikto_proxy: e.target.value })}
            style={inp} placeholder="http://127.0.0.1:8080" />
        </Field>
        <Field label="HTTP Auth" hint="Basic auth credentials user:pass">
          <input value={d.nikto_auth ?? ''}
            onChange={e => upd({ nikto_auth: e.target.value })}
            style={inp} placeholder="admin:password" />
        </Field>
        <Field label="Max Time" hint="Tells Nikto itself when to stop, e.g. 5m, 1h">
          <input value={d.nikto_maxtime ?? ''}
            onChange={e => upd({ nikto_maxtime: e.target.value })}
            style={inp} placeholder="5m" />
        </Field>
        <Field label="Evasion Techniques" hint="1-9: IDS/WAF bypass modes e.g. 12 for modes 1 and 2">
          <input value={d.nikto_evasion ?? ''}
            onChange={e => upd({ nikto_evasion: e.target.value })}
            style={inp} placeholder="12" />
        </Field>
        <Field label="Timeout (s)" hint="How long the platform waits for Nikto to finish before giving up. If you set Max Time above, keep this a bit higher (e.g. Max Time 15m -> Timeout 950+) or the run gets cut off before Nikto's own limit is reached.">
          <input type="number" value={Number(d.nikto_timeout ?? 600)} min={60} max={3600}
            onChange={e => upd({ nikto_timeout: parseInt(e.target.value) || 600 })} style={inp} />
        </Field>
        <ServerActionExtras server="nikto" actionKey="nikto_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── wpscan ────────────────────────────────────────────────────
  if (tool === 'wpscan') {
    const wpscan_action = d.wpscan_action ?? 'wp_scan';
    return (
      <>
        <Field label="Action">
          <select value={wpscan_action} onChange={e => upd({ wpscan_action: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
            <option value="wp_scan">Full WP Scan</option>
            <option value="wp_enum_users">Enumerate Users</option>
            <option value="wp_enum_plugins">Enumerate Plugins</option>
            <option value="wp_enum_themes">Enumerate Themes</option>
          </select>
        </Field>
        <Field label="Target URL" hint="WordPress site URL">
          <input value={d.wpscan_url ?? ''} onChange={e => upd({ wpscan_url: e.target.value })} style={inp} placeholder="https://target.com" />
        </Field>
        {wpscan_action === 'wp_scan' && <>
          <Field label="Enumerate" hint="u=users, vp=vuln plugins, vt=vuln themes, ap=all plugins, at=all themes">
            <input value={d.wpscan_enumerate ?? 'u,vp,vt'} onChange={e => upd({ wpscan_enumerate: e.target.value })} style={inp} placeholder="u,vp,vt" />
          </Field>
        </>}
        {(wpscan_action === 'wp_enum_plugins' || wpscan_action === 'wp_enum_themes') && <>
          <Field label="Detection Mode">
            <select value={d.wpscan_detection ?? 'mixed'} onChange={e => upd({ wpscan_detection: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
              <option value="passive">Passive</option>
              <option value="mixed">Mixed</option>
              <option value="aggressive">Aggressive</option>
            </select>
          </Field>
        </>}
        {wpscan_action === 'wp_enum_users' && <>
          <Field label="Username Wordlist" hint="Wordlist used to enumerate user accounts">
            <select value={d.wpscan_username_wordlist ?? 'usernames'} onChange={e => upd({ wpscan_username_wordlist: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
              {WORDLIST_OPTIONS.filter(o => ['usernames', 'common', 'big'].includes(o.value)).map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </Field>
          <Field label="Password Wordlist" hint="Optional — brute-force found users with this wordlist">
            <select value={d.wpscan_password_wordlist ?? ''} onChange={e => upd({ wpscan_password_wordlist: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
              <option value="">— No brute-force (enumerate only) —</option>
              {WORDLIST_OPTIONS.filter(o => ['passwords', 'common', 'big'].includes(o.value)).map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </Field>
        </>}
        <Field label="WPVulnDB API Token" hint="Optional — greatly improves vulnerability detection">
          <input value={d.wpscan_api_token ?? ''} onChange={e => upd({ wpscan_api_token: e.target.value })} style={inp} placeholder="(optional)" type="password" />
        </Field>
        <ServerActionExtras server="wpscan" actionKey="wpscan_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── jwt ───────────────────────────────────────────────────────
  if (tool === 'jwt') {
    const jwt_action = d.jwt_action ?? 'decode_jwt';
    return (
      <>
        <Field label="Action">
          <select value={jwt_action} onChange={e => upd({ jwt_action: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
            <option value="decode_jwt">Decode JWT</option>
            <option value="test_alg_none">Test Algorithm None (bypass)</option>
            <option value="test_weak_secret">Test Weak Secret (brute-force)</option>
            <option value="forge_jwt">Forge JWT (with known secret)</option>
            <option value="analyze_claims">Analyze Claims</option>
          </select>
        </Field>
        <Field label="JWT Token" hint="Paste the full JWT (eyJ...)">
          <textarea value={d.jwt_token ?? ''} onChange={e => upd({ jwt_token: e.target.value })} style={{ ...inp, minHeight: 60, resize: 'vertical', fontFamily: 'monospace', fontSize: '0.6875rem' }} placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." />
        </Field>
        {jwt_action === 'test_weak_secret' && <>
          <Field label="Secret Wordlist" hint="Wordlist used to brute-force the HMAC signing secret">
            <select value={d.jwt_wordlist ?? 'passwords'} onChange={e => upd({ jwt_wordlist: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
              {WORDLIST_OPTIONS.filter(o => ['passwords', 'common', 'big'].includes(o.value)).map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </Field>
        </>}
        {jwt_action === 'forge_jwt' && <>
          <Field label="Secret" hint="HMAC secret used to sign the forged token">
            <input value={d.jwt_secret ?? ''} onChange={e => upd({ jwt_secret: e.target.value })} style={inp} placeholder="secret" />
          </Field>
          <Field label="Algorithm">
            <select value={d.jwt_algorithm ?? 'HS256'} onChange={e => upd({ jwt_algorithm: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
              <option value="HS256">HS256</option>
              <option value="HS384">HS384</option>
              <option value="HS512">HS512</option>
              <option value="none">none (bypass)</option>
            </select>
          </Field>
        </>}
        <ServerActionExtras server="jwt" actionKey="jwt_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── gobuster ──────────────────────────────────────────────────
  if (tool === 'gobuster') {
    const gobuster_mode = d.gobuster_mode ?? 'dir';
    return (
      <>
        <Field label="Mode">
          <select value={gobuster_mode} onChange={e => upd({ gobuster_mode: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
            <option value="dir">Directory / File Brute-Force</option>
            <option value="dns">DNS Subdomain Enumeration</option>
            <option value="vhost">Virtual Host Discovery</option>
            <option value="fuzz">URL Fuzzing (FUZZ marker)</option>
          </select>
        </Field>
        {gobuster_mode !== 'dns' && <>
          <Field label="Target URL" hint={gobuster_mode === 'fuzz' ? 'URL with FUZZ marker' : 'Target base URL'}>
            <input value={d.gobuster_url ?? ''} onChange={e => upd({ gobuster_url: e.target.value })} style={inp} placeholder={gobuster_mode === 'fuzz' ? 'http://target/FUZZ' : 'http://target.com'} />
          </Field>
        </>}
        {gobuster_mode === 'dns' && <>
          <Field label="Domain" hint="Domain to enumerate subdomains for">
            <input value={d.gobuster_domain ?? ''} onChange={e => upd({ gobuster_domain: e.target.value })} style={inp} placeholder="example.com" />
          </Field>
        </>}
        {gobuster_mode === 'vhost' && <>
          <Field label="Base Domain" hint="Domain appended to each wordlist entry">
            <input value={d.gobuster_domain ?? ''} onChange={e => upd({ gobuster_domain: e.target.value })} style={inp} placeholder="example.com" />
          </Field>
        </>}
        <Field label="Wordlist" hint="Built-in SecLists wordlist — smart default per mode">
          <select
            value={d.gobuster_wordlist ?? (gobuster_mode === 'dns' ? 'subdomains' : gobuster_mode === 'fuzz' ? 'parameters' : 'common')}
            onChange={e => upd({ gobuster_wordlist: e.target.value })}
            style={{ ...inp, cursor: 'pointer' }}
          >
            {gobuster_mode === 'dns'
              ? WORDLIST_OPTIONS.filter(o => ['subdomains', 'common', 'big'].includes(o.value)).map(o => <option key={o.value} value={o.value}>{o.label}</option>)
              : gobuster_mode === 'fuzz'
              ? WORDLIST_OPTIONS.filter(o => ['parameters', 'common', 'big'].includes(o.value)).map(o => <option key={o.value} value={o.value}>{o.label}</option>)
              : WORDLIST_OPTIONS.filter(o => ['common', 'big', 'parameters'].includes(o.value)).map(o => <option key={o.value} value={o.value}>{o.label}</option>)
            }
          </select>
        </Field>
        {gobuster_mode === 'dir' && <>
          <Field label="Extensions (comma-sep)" hint="File extensions to append">
            <input value={d.gobuster_extensions ?? ''} onChange={e => upd({ gobuster_extensions: e.target.value })} style={inp} placeholder="php,html,js,txt" />
          </Field>
          <Field label="Status Codes" hint="Toggle ranges or edit codes directly">
            {(() => {
              const currentCodes = ((d.gobuster_status_codes as string) ?? '200,204,301,302,307,401,403').split(',').map((s: string) => s.trim()).filter(Boolean);
              const toggle = (codes: string[]) => {
                const set = new Set(currentCodes);
                const allPresent = codes.every(c => set.has(c));
                if (allPresent) codes.forEach(c => set.delete(c));
                else codes.forEach(c => set.add(c));
                upd({ gobuster_status_codes: Array.from(set).sort((a,b)=>Number(a)-Number(b)).join(',') });
              };
              const ranges: { label: string; codes: string[]; color: string }[] = [
                { label: '2xx', codes: ['200','201','204'], color: 'var(--green)' },
                { label: '3xx', codes: ['301','302','307'], color: 'var(--cyan)' },
                { label: '4xx', codes: ['400','401','403','405'], color: 'var(--amber)' },
                { label: '5xx', codes: ['500','503'], color: 'var(--red)' },
              ];
              return (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {ranges.map(r => {
                      const active = r.codes.every(c => currentCodes.includes(c));
                      return (
                        <button key={r.label} type="button" onClick={() => toggle(r.codes)}
                          style={{ padding: '3px 10px', borderRadius: 'var(--radius-sm)', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer',
                            border: `1px solid ${active ? r.color : 'var(--border)'}`,
                            background: active ? `color-mix(in srgb, ${r.color} 13%, transparent)` : 'transparent',
                            color: active ? r.color : 'var(--text-muted)', transition: 'all 0.15s' }}>
                          {r.label}
                        </button>
                      );
                    })}
                  </div>
                  <input
                    value={(d.gobuster_status_codes as string) ?? '200,204,301,302,307,401,403'}
                    onChange={e => upd({ gobuster_status_codes: e.target.value })}
                    style={{ ...inp, fontFamily: 'monospace', fontSize: '0.8125rem' }}
                    placeholder="200,204,301,302,307,401,403"
                  />
                </div>
              );
            })()}
          </Field>
          <Field label="Show Full URLs" hint="Display full URL in results instead of just path">
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
              <input type="checkbox" checked={!!d.gobuster_expanded}
                onChange={e => upd({ gobuster_expanded: e.target.checked })} />
              <span style={{ fontSize: '0.6875rem' }}>Expanded output (-e)</span>
            </label>
          </Field>
        </>}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <Field label="Threads" hint="Concurrent goroutines (1-100)">
            <input type="number" value={d.gobuster_threads ?? 20}
              onChange={e => upd({ gobuster_threads: parseInt(e.target.value) || 20 })}
              style={inp} min={1} max={100} />
          </Field>
          <Field label="Timeout (s)">
            <input type="number" value={d.gobuster_timeout ?? 300}
              onChange={e => upd({ gobuster_timeout: parseInt(e.target.value) || 300 })}
              style={inp} min={30} max={600} />
          </Field>
        </div>
        <Field label="Proxy URL" hint="HTTP/HTTPS proxy e.g. http://127.0.0.1:8080">
          <input value={d.gobuster_proxy ?? ''}
            onChange={e => upd({ gobuster_proxy: e.target.value })}
            style={inp} placeholder="http://127.0.0.1:8080" />
        </Field>
        <Field label="Extra Headers" hint="One header per line: Name: Value">
          <textarea value={d.gobuster_headers ?? ''}
            onChange={e => upd({ gobuster_headers: e.target.value })}
            style={{ ...inp, height: 60 }} placeholder={'Authorization: Bearer token\nX-Custom: value'} />
        </Field>
        {gobuster_mode !== 'dns' && <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <Field label="Username" hint="HTTP Basic auth">
              <input value={d.gobuster_username ?? ''}
                onChange={e => upd({ gobuster_username: e.target.value })}
                style={inp} placeholder="admin" />
            </Field>
            <Field label="Password" hint="HTTP Basic auth">
              <input type="password" value={d.gobuster_password ?? ''}
                onChange={e => upd({ gobuster_password: e.target.value })}
                style={inp} placeholder="password" />
            </Field>
          </div>
        </>}
        <ServerActionExtras server="gobuster" actionKey="gobuster_mode" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── cve_lite ──────────────────────────────────────────────────
  if (tool === 'cve_lite') {
    const cve_lite_action = d.cve_lite_action ?? 'scan';
    return (
      <>
        <Field label="Action" hint="Operation to run">
          <select value={cve_lite_action} onChange={e => upd({ cve_lite_action: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
            <option value="scan">Scan project for vulnerable dependencies</option>
            <option value="advisories_sync">Sync OSV advisory database (offline)</option>
            <option value="version">Show cve-lite version</option>
          </select>
        </Field>

        {cve_lite_action === 'scan' && <>
          <CveLiteProjectPicker
            value={d.cve_lite_project_path ?? ''}
            onChange={path => upd({ cve_lite_project_path: path })}
            inp={inp}
          />
          <Field label="Min Severity" hint="Minimum severity level to report">
            <select value={d.cve_lite_min_severity ?? 'medium'} onChange={e => upd({ cve_lite_min_severity: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
              <option value="none">None (all)</option>
              <option value="low">Low+</option>
              <option value="medium">Medium+ (default)</option>
              <option value="high">High+</option>
              <option value="critical">Critical only</option>
            </select>
          </Field>
          <Field label="Fail On" hint="Treat findings at or above this severity as threshold-reached">
            <select value={d.cve_lite_fail_on ?? 'critical'} onChange={e => upd({ cve_lite_fail_on: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
              <option value="none">Never (informational only)</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical (default)</option>
            </select>
          </Field>
          <Field label="Options" hint="Additional scan options">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                <input type="checkbox" checked={!!d.cve_lite_prod_only} onChange={e => upd({ cve_lite_prod_only: e.target.checked })} />
                Production deps only (exclude devDependencies)
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                <input type="checkbox" checked={!!d.cve_lite_all} onChange={e => upd({ cve_lite_all: e.target.checked })} />
                Include all deps (including dev)
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                <input type="checkbox" checked={!!d.cve_lite_usage} onChange={e => upd({ cve_lite_usage: e.target.checked })} />
                Include usage analysis (which files import vuln packages)
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                <input type="checkbox" checked={!!d.cve_lite_only_used} onChange={e => upd({ cve_lite_only_used: e.target.checked })} />
                Only report packages actually imported in source
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                <input type="checkbox" checked={!!d.cve_lite_offline} onChange={e => upd({ cve_lite_offline: e.target.checked })} />
                Offline mode (use local advisory DB)
              </label>
            </div>
          </Field>
          {d.cve_lite_offline && (
            <Field label="Offline DB Path" hint="Path to local SQLite advisory database">
              <input value={d.cve_lite_offline_db ?? '/var/cve-lite/advisories.sqlite3'} onChange={e => upd({ cve_lite_offline_db: e.target.value })} style={inp} placeholder="/var/cve-lite/advisories.sqlite3" />
            </Field>
          )}
        </>}

        {cve_lite_action === 'advisories_sync' && (
          <Field label="Output DB Path" hint="Where to save the synced SQLite advisory database">
            <input value={d.cve_lite_offline_db ?? '/var/cve-lite/advisories.sqlite3'} onChange={e => upd({ cve_lite_offline_db: e.target.value })} style={inp} placeholder="/var/cve-lite/advisories.sqlite3" />
          </Field>
        )}
        <ServerActionExtras server="cve_lite" actionKey="cve_lite_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── waf ───────────────────────────────────────────────────────
  if (tool === 'waf') {
    const waf_action = d.waf_action ?? 'fingerprint_waf';
    return (
      <>
        <Field label="Action" hint="Which WAF operation to run">
          <select value={waf_action} onChange={e => upd({ waf_action: e.target.value })}
            style={{ ...inp, cursor: 'pointer' }}>
            <option value="fingerprint_waf">Fingerprint WAF / IPS / IDS</option>
            <option value="test_bypass">Test WAF Bypass Techniques</option>
            <option value="analyze_evasion">Analyze Evasion Strategy</option>
          </select>
        </Field>

        {/* URL always shown */}
        <Field label="Target URL" hint="Leave blank to auto-detect from nmap">
          <input value={d.waf_url ?? ''}
            onChange={e => upd({ waf_url: e.target.value })}
            style={inp} placeholder="https://target.com" />
        </Field>

        {waf_action === 'fingerprint_waf' && <>
          <Field label="Protocol">
            <select value={d.waf_protocol ?? 'https'} onChange={e => upd({ waf_protocol: e.target.value })}
              style={{ ...inp, cursor: 'pointer' }}>
              <option value="https">HTTPS</option>
              <option value="http">HTTP</option>
              <option value="all">Both HTTP + HTTPS</option>
            </select>
          </Field>
        </>}

        {waf_action === 'test_bypass' && <>
          <Field label="Test Payload" hint="Payload to test WAF blocking (e.g. SQL injection)">
            <input value={d.waf_payload ?? ''}
              onChange={e => upd({ waf_payload: e.target.value })}
              style={inp} placeholder="' OR 1=1--" />
          </Field>
        </>}

        {waf_action === 'analyze_evasion' && <>
          <Field label="Attack Type">
            <select value={d.waf_attack_type ?? 'sqli'} onChange={e => upd({ waf_attack_type: e.target.value })}
              style={{ ...inp, cursor: 'pointer' }}>
              <option value="sqli">SQL Injection</option>
              <option value="xss">Cross-Site Scripting (XSS)</option>
              <option value="lfi">Local File Inclusion (LFI)</option>
              <option value="rce">Remote Code Execution (RCE)</option>
            </select>
          </Field>
          <Field label="Known WAF Type" hint="Auto-detected if left blank">
            <input value={d.waf_waf_type ?? ''}
              onChange={e => upd({ waf_waf_type: e.target.value })}
              style={inp} placeholder="cloudflare, modsecurity, …" />
          </Field>
        </>}
        <ServerActionExtras server="waf" actionKey="waf_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── metasploit ────────────────────────────────────────────────
  if (tool === 'metasploit') {
    const msf_action = d.msf_action ?? 'run_auxiliary';
    return (
      <>
        <Field label="Action" hint="Which Metasploit Framework operation to perform">
          <select value={msf_action} onChange={e => upd({ msf_action: e.target.value })}
            style={{ ...inp, cursor: 'pointer' }}>
            <optgroup label="Exploitation">
              <option value="run_full_chain">Run Full Chain (auto by open ports)</option>
              <option value="run_exploit">Run Exploit Module</option>
              <option value="run_auxiliary">Run Auxiliary Module</option>
              <option value="run_post">Run Post Module (on Session)</option>
            </optgroup>
            <optgroup label="Discovery">
              <option value="list_exploits">Search Exploit / Auxiliary Modules</option>
              <option value="list_payloads">List Payloads</option>
              <option value="get_module_info">Get Module Info</option>
            </optgroup>
            <optgroup label="Sessions">
              <option value="list_sessions">List Active Sessions</option>
              <option value="interactive_handoff">Interactive Session Handoff</option>
              <option value="send_command">Send Command to Session</option>
              <option value="terminate_session">Terminate Session</option>
            </optgroup>
            <optgroup label="Payloads & Listeners">
              <option value="generate_payload">Generate Payload File</option>
              <option value="start_listener">Start Listener (Handler)</option>
              <option value="list_listeners">List Active Listeners / Jobs</option>
              <option value="stop_job">Stop Job</option>
            </optgroup>
          </select>
        </Field>

        {/* ── run_exploit ── */}
        {msf_action === 'run_exploit' && <>
          <Field label="Exploit Module Path" hint="Select a common exploit or choose Custom to type your own">
            <select
              value={MSF_EXPLOIT_MODULES.some(m => m.value === (d.msf_module ?? '')) ? (d.msf_module ?? '') : '__custom__'}
              onChange={e => { if (e.target.value !== '__custom__') upd({ msf_module: e.target.value }); else upd({ msf_module: '' }); }}
              style={{ ...inp, cursor: 'pointer' }}>
              <option value="__custom__">— Custom (type below) —</option>
              {MSF_EXPLOIT_MODULE_GROUPS.map(g => (
                <optgroup key={g.label} label={g.label}>
                  {g.modules.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
                </optgroup>
              ))}
            </select>
          </Field>
          {(!MSF_EXPLOIT_MODULES.some(m => m.value === (d.msf_module ?? '')) || d.msf_module === '') && (
            <Field label="Custom Exploit Path">
              <input value={d.msf_module ?? ''} onChange={e => upd({ msf_module: e.target.value })}
                style={inp} placeholder="exploit/windows/smb/ms17_010_eternalblue" />
            </Field>
          )}
          <Field label="Payload">
            <input value={d.msf_payload ?? ''} onChange={e => upd({ msf_payload: e.target.value })}
              style={inp} placeholder="windows/x64/meterpreter/reverse_tcp" />
          </Field>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <Field label="LHOST">
              <input value={d.msf_lhost ?? ''} onChange={e => upd({ msf_lhost: e.target.value })}
                style={inp} placeholder="10.0.0.1" />
            </Field>
            <Field label="LPORT">
              <input type="number" value={d.msf_lport ?? 4444}
                onChange={e => upd({ msf_lport: parseInt(e.target.value) || 4444 })} style={inp} />
            </Field>
          </div>
          <Field label="RPORT (optional)" hint="Target port override">
            <input type="number" value={d.msf_target_port ?? ''}
              onChange={e => upd({ msf_target_port: parseInt(e.target.value) || undefined })} style={inp} placeholder="445" />
          </Field>
          <Field label="RHOSTS Override" hint="Leave blank to use Start node target">
            <input value={d.msf_rhosts ?? ''} onChange={e => upd({ msf_rhosts: e.target.value })}
              style={inp} placeholder="192.168.1.1" />
          </Field>
          <Field label="Extra Module Options" hint="Module-specific datastore options e.g. SITEPATH, TARGETURI">
            {(() => {
              const opts: Record<string, string> = (d.msf_options as Record<string, string>) ?? {};
              const entries = Object.entries(opts);
              const hasEmptyKey = '' in opts;
              return (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {entries.map(([k, v], i) => (
                    <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 4 }}>
                      <input value={k}
                        onChange={e => { const n = { ...opts }; delete n[k]; n[e.target.value] = v; upd({ msf_options: n }); }}
                        style={{ ...inp, fontSize: '0.6875rem' }} placeholder="Key e.g. SITEPATH" />
                      <input value={v}
                        onChange={e => { upd({ msf_options: { ...opts, [k]: e.target.value } }); }}
                        style={{ ...inp, fontSize: '0.6875rem' }} placeholder="Value" />
                      <button type="button" onClick={() => { const n = { ...opts }; delete n[k]; upd({ msf_options: n }); }}
                        style={{ padding: '2px 8px', background: 'color-mix(in srgb, var(--red) 13%, transparent)', border: '1px solid var(--red)', borderRadius: 'var(--radius-sm)', color: 'var(--red)', cursor: 'pointer', fontSize: '0.6875rem' }}>✕</button>
                    </div>
                  ))}
                  <button type="button"
                    onClick={() => { if (!hasEmptyKey) upd({ msf_options: { ...opts, '': '' } }); }}
                    disabled={hasEmptyKey}
                    title={hasEmptyKey ? 'Fill in the key field above first' : 'Add option'}
                    style={{ padding: '3px 10px', background: 'transparent', border: '1px dashed var(--border)', borderRadius: 'var(--radius-sm)', color: hasEmptyKey ? 'var(--text-muted)' : 'var(--text-secondary)', cursor: hasEmptyKey ? 'not-allowed' : 'pointer', fontSize: '0.6875rem', alignSelf: 'flex-start', opacity: hasEmptyKey ? 0.4 : 1 }}>+ Add Option</button>
                </div>
              );
            })()}
          </Field>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 6, fontSize: '0.75rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            <input type="checkbox" checked={d.msf_check_first ?? true}
              onChange={e => upd({ msf_check_first: e.target.checked })} />
            Run check before exploit
          </label>
        </>}

        {/* ── run_auxiliary ── */}
        {msf_action === 'run_auxiliary' && <>
          <Field label="Auxiliary Module Path" hint="Select a common module or choose Custom to type your own">
            <select
              value={MSF_AUX_MODULES.some(m => m.value === (d.msf_module ?? '')) ? (d.msf_module ?? '') : '__custom__'}
              onChange={e => { if (e.target.value !== '__custom__') upd({ msf_module: e.target.value }); else upd({ msf_module: '' }); }}
              style={{ ...inp, cursor: 'pointer' }}>
              <option value="__custom__">— Custom (type below) —</option>
              {MSF_AUX_MODULE_GROUPS.map(g => (
                <optgroup key={g.label} label={g.label}>
                  {g.modules.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
                </optgroup>
              ))}
            </select>
          </Field>
          {(!MSF_AUX_MODULES.some(m => m.value === (d.msf_module ?? '')) || d.msf_module === '') && (
            <Field label="Custom Module Path">
              <input value={d.msf_module ?? ''} onChange={e => upd({ msf_module: e.target.value })}
                style={inp} placeholder="auxiliary/scanner/smb/smb_version" />
            </Field>
          )}
          <Field label="RHOSTS Override" hint="Leave blank to use Start node target">
            <input value={d.msf_rhosts ?? ''} onChange={e => upd({ msf_rhosts: e.target.value })}
              style={inp} placeholder="192.168.1.0/24" />
          </Field>
          <Field label="Extra Module Options" hint="Module-specific datastore options">
            {(() => {
              const opts: Record<string, string> = (d.msf_options as Record<string, string>) ?? {};
              const entries = Object.entries(opts);
              const hasEmptyKey = '' in opts;
              return (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {entries.map(([k, v], i) => (
                    <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 4 }}>
                      <input value={k}
                        onChange={e => { const n = { ...opts }; delete n[k]; n[e.target.value] = v; upd({ msf_options: n }); }}
                        style={{ ...inp, fontSize: '0.6875rem' }} placeholder="Key" />
                      <input value={v}
                        onChange={e => { upd({ msf_options: { ...opts, [k]: e.target.value } }); }}
                        style={{ ...inp, fontSize: '0.6875rem' }} placeholder="Value" />
                      <button type="button" onClick={() => { const n = { ...opts }; delete n[k]; upd({ msf_options: n }); }}
                        style={{ padding: '2px 8px', background: 'color-mix(in srgb, var(--red) 13%, transparent)', border: '1px solid var(--red)', borderRadius: 'var(--radius-sm)', color: 'var(--red)', cursor: 'pointer', fontSize: '0.6875rem' }}>✕</button>
                    </div>
                  ))}
                  <button type="button"
                    onClick={() => { if (!hasEmptyKey) upd({ msf_options: { ...opts, '': '' } }); }}
                    disabled={hasEmptyKey}
                    title={hasEmptyKey ? 'Fill in the key field above first' : 'Add option'}
                    style={{ padding: '3px 10px', background: 'transparent', border: '1px dashed var(--border)', borderRadius: 'var(--radius-sm)', color: hasEmptyKey ? 'var(--text-muted)' : 'var(--text-secondary)', cursor: hasEmptyKey ? 'not-allowed' : 'pointer', fontSize: '0.6875rem', alignSelf: 'flex-start', opacity: hasEmptyKey ? 0.4 : 1 }}>+ Add Option</button>
                </div>
              );
            })()}
          </Field>
        </>}

        {/* ── run_full_chain ── */}
        {msf_action === 'run_full_chain' && <>
          <div style={{ background: 'color-mix(in srgb, var(--red) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--red) 33%, transparent)', borderRadius: 'var(--radius-sm)', padding: '8px 10px', fontSize: '0.6875rem', color: 'var(--red)', lineHeight: 1.45 }}>
            Runs multiple Metasploit modules based on Nmap open ports (auxiliary + exploit checks + optional post modules).
          </div>
          <Field label="Chain Mode">
            <select
              value={String(d.msf_chain_mode ?? 'balanced')}
              onChange={e => upd({ msf_chain_mode: (e.target.value as 'balanced' | 'aggressive') })}
              style={{ ...inp, cursor: 'pointer' }}>
              <option value="balanced">Balanced (recommended)</option>
              <option value="aggressive">Aggressive (more modules, slower)</option>
            </select>
          </Field>
          <Field label="Max Modules">
            <input
              type="number"
              value={Number(d.msf_chain_limit ?? 24)}
              onChange={e => upd({ msf_chain_limit: parseInt(e.target.value) || 24 })}
              style={inp}
              min={4}
              max={120}
            />
          </Field>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 2, fontSize: '0.75rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            <input type="checkbox" checked={Boolean(d.msf_chain_exploit_checks ?? true)}
              onChange={e => upd({ msf_chain_exploit_checks: e.target.checked })} />
            Include exploit module checks
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 2, fontSize: '0.75rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            <input type="checkbox" checked={Boolean(d.msf_chain_post ?? true)}
              onChange={e => upd({ msf_chain_post: e.target.checked })} />
            Run post-exploitation modules if sessions are opened
          </label>
          <Field label="RHOSTS Override" hint="Leave blank to use Start node target">
            <input value={String(d.msf_rhosts ?? '')} onChange={e => upd({ msf_rhosts: e.target.value })}
              style={inp} placeholder="192.168.1.0/24" />
          </Field>
          <Field label="Payload (optional)" hint="Used for exploit stage when applicable">
            <input value={String(d.msf_payload ?? '')} onChange={e => upd({ msf_payload: e.target.value })}
              style={inp} placeholder="windows/x64/meterpreter/reverse_tcp" />
          </Field>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <Field label="LHOST">
              <input value={String(d.msf_lhost ?? '')} onChange={e => upd({ msf_lhost: e.target.value })}
                style={inp} placeholder="10.10.10.1" />
            </Field>
            <Field label="LPORT">
              <input type="number" value={Number(d.msf_lport ?? 4444)}
                onChange={e => upd({ msf_lport: parseInt(e.target.value) || 4444 })} style={inp} />
            </Field>
          </div>
        </>}

        {/* ── run_post ── */}
        {msf_action === 'run_post' && <>
          <Field label="Post Module Path" hint="Select a common post-exploitation module or choose Custom">
            <select
              value={MSF_POST_MODULES.some(m => m.value === (d.msf_module ?? '')) ? (d.msf_module ?? '') : '__custom__'}
              onChange={e => { if (e.target.value !== '__custom__') upd({ msf_module: e.target.value }); else upd({ msf_module: '' }); }}
              style={{ ...inp, cursor: 'pointer' }}>
              <option value="__custom__">— Custom (type below) —</option>
              {MSF_POST_MODULE_GROUPS.map(g => (
                <optgroup key={g.label} label={g.label}>
                  {g.modules.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
                </optgroup>
              ))}
            </select>
          </Field>
          {(!MSF_POST_MODULES.some(m => m.value === (d.msf_module ?? '')) || d.msf_module === '') && (
            <Field label="Custom Post Module Path">
              <input value={d.msf_module ?? ''} onChange={e => upd({ msf_module: e.target.value })}
                style={inp} placeholder="post/windows/gather/enum_logged_on_users" />
            </Field>
          )}
          <Field label="Session ID">
            <input type="number" value={d.msf_session_id ?? 1}
              onChange={e => upd({ msf_session_id: parseInt(e.target.value) || 1 })} style={inp} />
          </Field>
        </>}

        {/* ── list_exploits ── */}
        {msf_action === 'list_exploits' && <>
          <Field label="Search Query" hint="CVE ID, name, platform or service (e.g. ms17_010, windows, smb)">
            <input value={d.msf_query ?? ''} onChange={e => upd({ msf_query: e.target.value })}
              style={inp} placeholder="ms17_010" />
          </Field>
          <Field label="Module Type">
            <select value={d.msf_module_type ?? 'exploit'} onChange={e => upd({ msf_module_type: e.target.value })}
              style={{ ...inp, cursor: 'pointer' }}>
              <option value="exploit">Exploit</option>
              <option value="auxiliary">Auxiliary</option>
              <option value="post">Post</option>
              <option value="payload">Payload</option>
            </select>
          </Field>
          <Field label="Max Results">
            <input type="number" value={d.msf_limit ?? 20}
              onChange={e => upd({ msf_limit: parseInt(e.target.value) || 20 })} style={inp} min={1} max={200} />
          </Field>
        </>}

        {/* ── list_payloads ── */}
        {msf_action === 'list_payloads' && <>
          <Field label="Search Query" hint="e.g. meterpreter, staged, reverse">
            <input value={d.msf_query ?? ''} onChange={e => upd({ msf_query: e.target.value })}
              style={inp} placeholder="meterpreter" />
          </Field>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <Field label="Platform">
              <input value={d.msf_platform ?? ''} onChange={e => upd({ msf_platform: e.target.value })}
                style={inp} placeholder="windows" />
            </Field>
            <Field label="Arch">
              <input value={d.msf_arch ?? ''} onChange={e => upd({ msf_arch: e.target.value })}
                style={inp} placeholder="x64" />
            </Field>
          </div>
          <Field label="Max Results">
            <input type="number" value={d.msf_limit ?? 20}
              onChange={e => upd({ msf_limit: parseInt(e.target.value) || 20 })} style={inp} min={1} max={200} />
          </Field>
        </>}

        {/* ── get_module_info ── */}
        {msf_action === 'get_module_info' && <>
          <Field label="Module Path" hint="Full module path to inspect">
            <select
              value={MSF_ALL_MODULES.some(m => m.value === (d.msf_module ?? '')) ? (d.msf_module ?? '') : '__custom__'}
              onChange={e => { if (e.target.value !== '__custom__') upd({ msf_module: e.target.value }); else upd({ msf_module: '' }); }}
              style={{ ...inp, cursor: 'pointer' }}>
              <option value="__custom__">— Custom (type below) —</option>
              <optgroup label="Auxiliary">
                {MSF_AUX_MODULE_GROUPS.map(g => (
                  <optgroup key={g.label} label={`  ${g.label}`}>
                    {g.modules.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
                  </optgroup>
                ))}
              </optgroup>
              <optgroup label="Exploits">
                {MSF_EXPLOIT_MODULE_GROUPS.map(g => (
                  <optgroup key={g.label} label={`  ${g.label}`}>
                    {g.modules.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
                  </optgroup>
                ))}
              </optgroup>
              <optgroup label="Post">
                {MSF_POST_MODULE_GROUPS.map(g => (
                  <optgroup key={g.label} label={`  ${g.label}`}>
                    {g.modules.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
                  </optgroup>
                ))}
              </optgroup>
            </select>
          </Field>
          {(!MSF_ALL_MODULES.some(m => m.value === (d.msf_module ?? '')) || d.msf_module === '') && (
            <Field label="Custom Module Path">
              <input value={d.msf_module ?? ''} onChange={e => upd({ msf_module: e.target.value })}
                style={inp} placeholder="exploit/windows/smb/ms17_010_eternalblue" />
            </Field>
          )}
        </>}

        {/* ── send_command ── */}
        {msf_action === 'send_command' && <>
          <Field label="Session ID">
            <input type="number" value={d.msf_session_id ?? 1}
              onChange={e => upd({ msf_session_id: parseInt(e.target.value) || 1 })} style={inp} />
          </Field>
          <Field label="Command">
            <input value={d.msf_command ?? ''} onChange={e => upd({ msf_command: e.target.value })}
              style={inp} placeholder="whoami" />
          </Field>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <Field label="Wait (ms)">
              <input type="number" value={d.msf_wait_ms ?? 300}
                onChange={e => upd({ msf_wait_ms: parseInt(e.target.value) || 300 })} style={inp} min={0} max={5000} />
            </Field>
            <Field label="Max Reads">
              <input type="number" value={d.msf_max_reads ?? 8}
                onChange={e => upd({ msf_max_reads: parseInt(e.target.value) || 8 })} style={inp} min={1} max={50} />
            </Field>
          </div>
        </>}

        {/* ── interactive_handoff ── */}
        {msf_action === 'interactive_handoff' && <>
          <div style={{ background: 'color-mix(in srgb, var(--green) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--green) 33%, transparent)', borderRadius: 'var(--radius-sm)', padding: '8px 10px', fontSize: '0.6875rem', color: 'var(--green)', lineHeight: 1.45 }}>
            Prepares a session handoff for the live terminal panel in run results.
            If Session ID is empty, the newest active session is selected automatically.
          </div>
          <Field label="Session ID (optional)">
            <input
              type="number"
              value={d.msf_session_id ?? ''}
              onChange={e => upd({ msf_session_id: e.target.value ? (parseInt(e.target.value) || undefined) : undefined })}
              style={inp}
              placeholder="auto-select latest"
            />
          </Field>
        </>}

        {/* ── terminate_session ── */}
        {msf_action === 'terminate_session' && <>
          <Field label="Session ID">
            <input type="number" value={d.msf_session_id ?? 1}
              onChange={e => upd({ msf_session_id: parseInt(e.target.value) || 1 })} style={inp} />
          </Field>
        </>}

        {/* ── generate_payload ── */}
        {msf_action === 'generate_payload' && <>
          <Field label="Payload Module">
            <input value={d.msf_payload ?? ''} onChange={e => upd({ msf_payload: e.target.value })}
              style={inp} placeholder="windows/meterpreter/reverse_tcp" />
          </Field>
          <Field label="Format">
            <select value={d.msf_format ?? 'exe'} onChange={e => upd({ msf_format: e.target.value })}
              style={{ ...inp, cursor: 'pointer' }}>
              <option value="exe">exe (Windows)</option>
              <option value="elf">elf (Linux)</option>
              <option value="raw">raw</option>
              <option value="python">python</option>
              <option value="ruby">ruby</option>
              <option value="bash">bash</option>
              <option value="powershell">powershell</option>
            </select>
          </Field>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <Field label="LHOST">
              <input value={d.msf_lhost ?? ''} onChange={e => upd({ msf_lhost: e.target.value })}
                style={inp} placeholder="10.0.0.1" />
            </Field>
            <Field label="LPORT">
              <input type="number" value={d.msf_lport ?? 4444}
                onChange={e => upd({ msf_lport: parseInt(e.target.value) || 4444 })} style={inp} />
            </Field>
          </div>
        </>}

        {/* ── start_listener ── */}
        {msf_action === 'start_listener' && <>
          <Field label="Payload">
            <input value={d.msf_payload ?? ''} onChange={e => upd({ msf_payload: e.target.value })}
              style={inp} placeholder="windows/meterpreter/reverse_tcp" />
          </Field>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <Field label="LHOST">
              <input value={d.msf_lhost ?? ''} onChange={e => upd({ msf_lhost: e.target.value })}
                style={inp} placeholder="10.0.0.1" />
            </Field>
            <Field label="LPORT">
              <input type="number" value={d.msf_lport ?? 4444}
                onChange={e => upd({ msf_lport: parseInt(e.target.value) || 4444 })} style={inp} />
            </Field>
          </div>
        </>}

        {/* ── stop_job ── */}
        {msf_action === 'stop_job' && <>
          <Field label="Job ID">
            <input type="number" value={d.msf_job_id ?? 0}
              onChange={e => upd({ msf_job_id: parseInt(e.target.value) || 0 })} style={inp} />
          </Field>
        </>}

        {/* list_sessions and list_listeners need no extra fields */}
        {(msf_action === 'list_sessions' || msf_action === 'list_listeners') && (
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-secondary)', marginTop: 6, opacity: 0.7, fontStyle: 'italic' }}>
            No additional parameters required.
          </div>
        )}
        <ServerActionExtras server="metasploit" actionKey="msf_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── osint ─────────────────────────────────────────────────────
  if (tool === 'osint') return (
    <>
      <Field label="OSINT Function">
        <select value={d.osint_tool ?? 'whois_lookup'}
          onChange={e => upd({ osint_tool: e.target.value })}
          style={{ ...inp, cursor: 'pointer' }}>
          <option value="whois_lookup">WHOIS Lookup</option>
          <option value="dns_lookup">DNS Lookup</option>
          <option value="http_headers">HTTP Headers</option>
          <option value="ip_geolocation">IP Geolocation</option>
          <option value="subdomain_enum">Subdomain Enumeration (CT logs)</option>
          <option value="ssl_info">SSL/TLS Certificate Info</option>
          <option value="tech_fingerprint">Tech Fingerprint</option>
        </select>
      </Field>
      <Field label="Target Override" hint="Leave blank to use Start node target">
        <input value={d.osint_target ?? ''}
          onChange={e => upd({ osint_target: e.target.value })}
          style={inp} placeholder="example.com or 1.2.3.4" />
      </Field>
      {(d.osint_tool === 'dns_lookup') && (
        <Field label="DNS Record Type">
          <select value={d.record_type ?? 'all'} onChange={e => upd({ record_type: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
            {['all','A','AAAA','MX','NS','TXT','CNAME','SOA','PTR','SRV','CAA'].map(r => <option key={r} value={r}>{r}</option>)}
          </select>
        </Field>
      )}
      {(d.osint_tool === 'ssl_info') && (
        <Field label="Port">
          <input type="number" value={d.nikto_port ?? 443}
            onChange={e => upd({ nikto_port: parseInt(e.target.value) || 443 })}
            style={inp} />
        </Field>
      )}
      <ServerActionExtras server="osint" actionKey="osint_tool" d={d} upd={upd} inp={inp} />
    </>
  );

  // ── cisa_kev ──────────────────────────────────────────────────
  if (tool === 'cisa_kev') return (
    <>
      <Field label="Action">
        <select value={d.kev_action ?? 'check_kev'}
          onChange={e => upd({ kev_action: e.target.value })}
          style={{ ...inp, cursor: 'pointer' }}>
          <option value="check_kev">Check CVE in KEV (single CVE)</option>
          <option value="search_kev">Search KEV by keyword</option>
          <option value="get_recent_kev">Get Recent KEV entries</option>
          <option value="get_kev_stats">KEV Statistics &amp; Top Vendors</option>
        </select>
      </Field>
      {(d.kev_action ?? 'check_kev') === 'check_kev' && (
        <Field label="CVE ID(s)" hint="Single CVE or comma-separated list. Leave blank to use Start node value.">
          <input value={d.kev_cve_id ?? ''}
            onChange={e => upd({ kev_cve_id: e.target.value })}
            style={inp} placeholder="CVE-2021-44228, CVE-2022-0847  (blank = from Start)" />
        </Field>
      )}
      {d.kev_action === 'search_kev' && (
        <>
          <Field label="Keyword" hint="Vendor, product, or vulnerability name. Leave blank to use Start node value.">
            <input value={d.kev_keyword ?? ''}
              onChange={e => upd({ kev_keyword: e.target.value })}
              style={inp} placeholder="Microsoft, Apache … (blank = from Start)" />
          </Field>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <Field label="Max Results">
              <input type="number" value={d.kev_limit ?? 15} min={1} max={50}
                onChange={e => upd({ kev_limit: parseInt(e.target.value) || 15 })} style={inp} />
            </Field>
            <Field label="Ransomware Only">
              <select value={d.kev_ransomware_only ? 'yes' : 'no'}
                onChange={e => upd({ kev_ransomware_only: e.target.value === 'yes' })}
                style={{ ...inp, cursor: 'pointer' }}>
                <option value="no">All</option>
                <option value="yes">Ransomware only</option>
              </select>
            </Field>
          </div>
          <ServerActionExtras server="cisa_kev" actionKey="kev_action" d={d} upd={upd} inp={inp} />
      </>
      )}
      {d.kev_action === 'get_recent_kev' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <Field label="Days Back">
            <input type="number" value={d.kev_days ?? 30} min={1} max={365}
              onChange={e => upd({ kev_days: parseInt(e.target.value) || 30 })} style={inp} />
          </Field>
          <Field label="Max Results">
            <input type="number" value={d.kev_limit ?? 20} min={1} max={100}
              onChange={e => upd({ kev_limit: parseInt(e.target.value) || 20 })} style={inp} />
          </Field>
        </div>
      )}
      {d.kev_action === 'get_kev_stats' && (
        <Field label="Top N Vendors">
          <input type="number" value={d.kev_limit ?? 10} min={1} max={50}
            onChange={e => upd({ kev_limit: parseInt(e.target.value) || 10 })} style={inp} />
        </Field>
      )}
    </>
  );

  // ── epss ──────────────────────────────────────────────────────
  if (tool === 'epss') return (
    <>
      <Field label="Action">
        <select value={d.epss_action ?? 'get_epss_score'}
          onChange={e => upd({ epss_action: e.target.value })}
          style={{ ...inp, cursor: 'pointer' }}>
          <option value="get_epss_score">Score Single CVE</option>
          <option value="get_epss_scores_bulk">Score Multiple CVEs (bulk)</option>
          <option value="get_high_epss_cves">Get High-Risk CVEs</option>
          <option value="epss_priority_analysis">Priority Analysis (bulk)</option>
        </select>
      </Field>
      {(d.epss_action ?? 'get_epss_score') === 'get_epss_score' && (
        <Field label="CVE ID" hint="Leave blank to use Start node value">
          <input value={d.epss_cve_id ?? ''}
            onChange={e => upd({ epss_cve_id: e.target.value })}
            style={inp} placeholder="CVE-2021-44228  (blank = from Start)" />
        </Field>
      )}
      {(d.epss_action === 'get_epss_scores_bulk' || d.epss_action === 'epss_priority_analysis') && (
        <Field label="CVE IDs (comma-separated)" hint="Up to 100 CVEs. Leave blank to use Start node value.">
          <input value={d.epss_cve_ids ?? ''}
            onChange={e => upd({ epss_cve_ids: e.target.value })}
            style={inp} placeholder="CVE-2021-44228, CVE-2022-0847  (blank = from Start)" />
        </Field>
      )}
      {d.epss_action === 'get_high_epss_cves' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <Field label="Min Score (0–1)">
            <input type="number" value={d.epss_min_score ?? 0.5} min={0} max={1} step={0.05}
              onChange={e => upd({ epss_min_score: parseFloat(e.target.value) || 0.5 })} style={inp} />
          </Field>
          <Field label="Max Results">
            <input type="number" value={d.epss_limit ?? 20} min={1} max={100}
              onChange={e => upd({ epss_limit: parseInt(e.target.value) || 20 })} style={inp} />
          </Field>
        </div>
      )}
      <ServerActionExtras server="epss" actionKey="epss_action" d={d} upd={upd} inp={inp} />
    </>
  );

  // ── poc_index ─────────────────────────────────────────────────
  if (tool === 'poc_index') return (
    <>
      <Field label="Action">
        <select value={d.poc_action ?? 'search_poc'}
          onChange={e => upd({ poc_action: e.target.value })}
          style={{ ...inp, cursor: 'pointer' }}>
          <option value="search_poc">Search PoC (Sploitus / ExploitDB)</option>
          <option value="search_github_poc">Search GitHub PoC Repos</option>
          <option value="get_exploitdb_entry">Search Exploit-DB</option>
          <option value="poc_risk_summary">PoC Risk Summary (CVE)</option>
        </select>
      </Field>
      {(d.poc_action === 'search_poc' || d.poc_action === 'get_exploitdb_entry' || !d.poc_action) && (
        <Field label="Search Query" hint="Software name, CVE ID, or keyword. Leave blank to use Start node value.">
          <input value={d.poc_query ?? ''}
            onChange={e => upd({ poc_query: e.target.value })}
            style={inp} placeholder="apache log4j, CVE-2021-44228 … (blank = from Start)" />
        </Field>
      )}
      {(d.poc_action === 'search_github_poc' || d.poc_action === 'poc_risk_summary') && (
        <Field label="CVE ID(s)" hint="Single CVE or comma-separated list. Leave blank to use Start node value.">
          <input value={d.poc_cve_id ?? ''}
            onChange={e => upd({ poc_cve_id: e.target.value })}
            style={inp} placeholder="CVE-2021-44228, CVE-2022-0847  (blank = from Start)" />
        </Field>
      )}
      <Field label="Max Results">
        <input type="number" value={d.poc_limit ?? 10} min={1} max={25}
          onChange={e => upd({ poc_limit: parseInt(e.target.value) || 10 })} style={inp} />
      </Field>
      <ServerActionExtras server="poc_index" actionKey="poc_action" d={d} upd={upd} inp={inp} />
    </>
  );

  // ── exploitdb ──────────────────────────────────────────────────
  if (tool === 'exploitdb') return (
    <>
      <Field label="Action">
        <select value={d.edb_action ?? 'search_exploits'}
          onChange={e => upd({ edb_action: e.target.value })}
          style={{ ...inp, cursor: 'pointer' }}>
          <option value="search_exploits">Search Exploits</option>
          <option value="find_by_cve">Find by CVE ID</option>
          <option value="get_exploit">Get Exploit by EDB-ID</option>
          <option value="get_recent_exploits">Recent Exploits</option>
          <option value="get_trending_exploits">Trending Exploits</option>
          <option value="search_by_platform">Search by Platform</option>
          <option value="search_by_type">Search by Type</option>
          <option value="export_search_results">Export Results</option>
        </select>
      </Field>

      {/* Query — search_exploits / export_search_results */}
      {(['search_exploits', 'export_search_results'].includes(d.edb_action ?? 'search_exploits')) && (
        <Field label="Search Query" hint="Keyword, software name, or CVE. Blank = from Start node.">
          <input value={d.edb_query ?? ''}
            onChange={e => upd({ edb_query: e.target.value })}
            style={inp} placeholder="apache struts, log4j, RCE … (blank = from Start)" />
        </Field>
      )}

      {/* CVE ID — find_by_cve */}
      {d.edb_action === 'find_by_cve' && (
        <Field label="CVE ID(s)" hint="Single CVE or comma-separated list. Blank = from Start node.">
          <input value={d.edb_cve_id ?? ''}
            onChange={e => upd({ edb_cve_id: e.target.value })}
            style={inp} placeholder="CVE-2021-44228  (blank = from Start)" />
        </Field>
      )}

      {/* EDB-ID — get_exploit */}
      {d.edb_action === 'get_exploit' && (
        <Field label="Exploit EDB-ID" hint="Numeric Exploit-DB entry ID">
          <input type="number" value={d.edb_exploit_id ?? ''}
            min={1}
            onChange={e => upd({ edb_exploit_id: parseInt(e.target.value) || undefined })}
            style={inp} placeholder="e.g. 50592" />
        </Field>
      )}

      {/* Platform — search_exploits, search_by_platform, export */}
      {(['search_exploits', 'search_by_platform', 'export_search_results'].includes(d.edb_action ?? 'search_exploits')) && (
        <Field label="Platform Filter" hint="Leave blank for all platforms">
          <select value={d.edb_platform ?? ''} onChange={e => upd({ edb_platform: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
            <option value="">All platforms</option>
            <option value="php">PHP</option>
            <option value="windows">Windows</option>
            <option value="linux">Linux</option>
            <option value="python">Python</option>
            <option value="ruby">Ruby</option>
            <option value="java">Java</option>
            <option value="android">Android</option>
            <option value="ios">iOS</option>
            <option value="hardware">Hardware</option>
            <option value="multiple">Multiple</option>
          </select>
        </Field>
      )}

      {/* Type — search_exploits, search_by_type, search_by_platform, export */}
      {(['search_exploits', 'search_by_type', 'search_by_platform', 'export_search_results'].includes(d.edb_action ?? 'search_exploits')) && (
        <Field label="Exploit Type" hint="Leave blank for all types">
          <select value={d.edb_type ?? ''} onChange={e => upd({ edb_type: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
            <option value="">All types</option>
            <option value="webapps">Web Applications</option>
            <option value="remote">Remote</option>
            <option value="local">Local</option>
            <option value="dos">DoS</option>
            <option value="hardware">Hardware</option>
          </select>
        </Field>
      )}

      {/* Verified only — search_exploits, search_by_platform, search_by_type */}
      {(['search_exploits', 'search_by_platform', 'search_by_type'].includes(d.edb_action ?? 'search_exploits')) && (
        <Field label="Verified Only">
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
            <input type="checkbox" checked={!!d.edb_verified_only}
              onChange={e => upd({ edb_verified_only: e.target.checked })} />
            <span style={{ fontSize: '0.8125rem' }}>Show only verified exploits</span>
          </label>
        </Field>
      )}

      {/* Days lookback — recent / trending */}
      {(['get_recent_exploits', 'get_trending_exploits']).includes(d.edb_action ?? '') && (
        <Field label="Lookback (days)">
          <input type="number" value={d.edb_days ?? 30} min={1} max={365}
            onChange={e => upd({ edb_days: parseInt(e.target.value) || 30 })} style={inp} />
        </Field>
      )}

      {/* Export format */}
      {d.edb_action === 'export_search_results' && (
        <Field label="Export Format">
          <select value={d.edb_format ?? 'json'} onChange={e => upd({ edb_format: e.target.value })} style={{ ...inp, cursor: 'pointer' }}>
            <option value="json">JSON</option>
            <option value="csv">CSV</option>
          </select>
        </Field>
      )}

      {/* Max results — all except get_exploit */}
      {d.edb_action !== 'get_exploit' && (
        <Field label="Max Results">
          <input type="number"
            value={d.edb_limit ?? 10}
            min={1}
            max={d.edb_action === 'export_search_results' ? 200 : 100}
            onChange={e => upd({ edb_limit: parseInt(e.target.value) || 10 })} style={inp} />
        </Field>
      )}
      <ServerActionExtras server="exploitdb" actionKey="edb_action" d={d} upd={upd} inp={inp} />
    </>
  );

  if (tool === 'mitre') return (
    <>
      <Field label="Action" hint="Which MITRE ATT&CK query to run">
        <select value={d.mitre_action ?? 'search_techniques'}
          onChange={e => upd({ mitre_action: e.target.value })}
          style={{ ...inp, cursor: 'pointer' }}>
          <optgroup label="Techniques">
            <option value="search_techniques">Search Techniques (by keyword)</option>
            <option value="get_technique_by_id">Get Technique by ID (T####)</option>
            <option value="get_techniques_by_tactic">Get Techniques by Tactic</option>
            <option value="get_techniques_by_platform">Get Techniques by Platform</option>
            <option value="get_subtechniques_of_technique">Get Sub-techniques of Technique</option>
            <option value="get_technique_tactics">Get Tactics for Technique</option>
          </optgroup>
          <optgroup label="Groups / Actors">
            <option value="search_groups">Search Threat Groups</option>
            <option value="get_techniques_used_by_group">Techniques Used by Group</option>
            <option value="get_groups_using_technique">Groups Using Technique</option>
          </optgroup>
          <optgroup label="Mitigations">
            <option value="get_mitigations_for_technique">Mitigations for Technique</option>
            <option value="get_techniques_mitigated_by">Techniques Mitigated By</option>
          </optgroup>
          <optgroup label="Software">
            <option value="search_software">Search Software / Malware</option>
            <option value="get_software_using_technique">Software Using Technique</option>
          </optgroup>
          <optgroup label="Overview">
            <option value="get_all_tactics">List All Tactics</option>
            <option value="get_data_stats">ATT&CK Stats Summary</option>
            <option value="generate_layer">Generate Navigator Layer</option>
          </optgroup>
        </select>
      </Field>

      <Field label="Domain" hint="ATT&CK knowledge base domain">
        <select value={d.mitre_domain ?? 'enterprise'}
          onChange={e => upd({ mitre_domain: e.target.value })}
          style={{ ...inp, cursor: 'pointer' }}>
          <option value="enterprise">Enterprise (IT / Cloud)</option>
          <option value="mobile">Mobile (Android / iOS)</option>
          <option value="ics">ICS / OT (Industrial)</option>
        </select>
      </Field>

      {/* Keyword / query actions */}
      {(d.mitre_action === 'search_techniques' || d.mitre_action === 'search_groups' || d.mitre_action === 'search_software' || !d.mitre_action) && (
        <Field label="Search Query" hint="Leave blank to use Start node value">
          <input value={d.mitre_query ?? ''}
            onChange={e => upd({ mitre_query: e.target.value })}
            style={inp} placeholder="lateral movement, APT28, mimikatz … (blank = from Start)" />
        </Field>
      )}

      {/* Technique ID actions */}
      {['get_technique_by_id','get_subtechniques_of_technique','get_technique_tactics',
        'get_groups_using_technique','get_mitigations_for_technique','get_software_using_technique'].includes(d.mitre_action ?? '') && (
        <Field label="Technique ID" hint="e.g. T1059 or T1059.001">
          <input value={d.mitre_technique_id ?? ''}
            onChange={e => upd({ mitre_technique_id: e.target.value.toUpperCase() })}
            style={inp} placeholder="T1059" />
        </Field>
      )}

      {/* Tactic filter */}
      {d.mitre_action === 'get_techniques_by_tactic' && (
        <Field label="Tactic" hint="e.g. initial-access, execution, lateral-movement">
          <input value={d.mitre_tactic ?? ''}
            onChange={e => upd({ mitre_tactic: e.target.value })}
            style={inp} placeholder="initial-access" />
        </Field>
      )}

      {/* Platform filter */}
      {d.mitre_action === 'get_techniques_by_platform' && (
        <Field label="Platform">
          <select value={d.mitre_platform ?? 'Linux'}
            onChange={e => upd({ mitre_platform: e.target.value })}
            style={{ ...inp, cursor: 'pointer' }}>
            {['Linux','Windows','macOS','Cloud','Containers','Network','Android','iOS'].map(p => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </Field>
      )}

      {/* Group ID actions */}
      {d.mitre_action === 'get_techniques_used_by_group' && (
        <Field label="Group Name or ID" hint="e.g. APT28, Lazarus Group, G0007">
          <input value={d.mitre_group_id ?? ''}
            onChange={e => upd({ mitre_group_id: e.target.value })}
            style={inp} placeholder="APT28" />
        </Field>
      )}

      {/* Mitigation ID */}
      {d.mitre_action === 'get_techniques_mitigated_by' && (
        <Field label="Mitigation ID" hint="e.g. M1036">
          <input value={d.mitre_mitigation_id ?? ''}
            onChange={e => upd({ mitre_mitigation_id: e.target.value.toUpperCase() })}
            style={inp} placeholder="M1036" />
        </Field>
      )}

      {/* Subtechniques toggle */}
      {(d.mitre_action === 'get_techniques_by_tactic' || d.mitre_action === 'get_techniques_by_platform') && (
        <Field label="Include Sub-techniques">
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
            <input type="checkbox" checked={d.mitre_include_subtechniques ?? true}
              onChange={e => upd({ mitre_include_subtechniques: e.target.checked })} />
            <span style={{ fontSize: '0.6875rem' }}>Include sub-techniques in results</span>
          </label>
        </Field>
      )}

      {/* Max results for search actions */}
      {['search_techniques','search_groups','search_software'].includes(d.mitre_action ?? 'search_techniques') && (
        <Field label="Max Results">
          <input type="number" value={d.mitre_limit ?? 20} min={1} max={50}
            onChange={e => upd({ mitre_limit: parseInt(e.target.value) || 20 })} style={inp} />
        </Field>
      )}
      <ServerActionExtras server="mitre" actionKey="mitre_action" d={d} upd={upd} inp={inp} />
    </>
  );

  // ── anomaly (ML traffic anomaly detection) — no hand-written actions; all via the manifest ──
  if (tool === 'anomaly') {
    return (
      <>
        <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 2 }}>
          Machine-learning traffic anomaly detection. Pick an operation below.
        </div>
        <ServerActionExtras server="anomaly" actionKey="anomaly_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── Active Directory — internal AD / SMB / LDAP enumeration + credential testing (all via the manifest) ──
  if (tool === 'ad') {
    return (
      <>
        <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 2 }}>
          Active Directory enumeration &amp; credential testing (NetExec / kerbrute). Target a domain controller or
          internal host. The spray / AS-REP-roast actions are offensive and only run with the server opt-in enabled.
        </div>
        <ServerActionExtras server="ad" actionKey="ad_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── Cloud Recon — unauthenticated bucket enum, cloud fingerprinting, SSRF metadata checks (all via the manifest) ──
  if (tool === 'cloud') {
    return (
      <>
        <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 2 }}>
          Unauthenticated, read-only cloud recon: public bucket enumeration (S3/Azure/GCS), cloud-provider
          fingerprinting, and SSRF-via-metadata checks. No credentials used — safe to run on any authorized target.
        </div>
        <ServerActionExtras server="cloud" actionKey="cloud_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── Container & Kubernetes — Trivy-based image/Dockerfile/manifest scanning (all via the manifest) ──
  if (tool === 'container') {
    return (
      <>
        <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 2 }}>
          Container image CVE scanning (Trivy) and Dockerfile / Kubernetes manifest misconfiguration checks, plus an
          exposed-Docker-API check. image_scan and docker_api_check take a target; the two manifest/Dockerfile scans
          take pasted file content.
        </div>
        <ServerActionExtras server="container" actionKey="container_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── API Security — GraphQL/OpenAPI/misconfig recon (all via the manifest) ──
  if (tool === 'api_security') {
    return (
      <>
        <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 2 }}>
          GraphQL introspection and risky-query detection, OpenAPI/Swagger spec discovery, and API misconfiguration
          checks (CORS, verbose errors, missing rate-limit headers). Target an API or GraphQL endpoint URL.
        </div>
        <ServerActionExtras server="api_security" actionKey="api_security_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── Secrets Scanning — live-credential detection in supplied content (all via the manifest) ──
  if (tool === 'secrets') {
    return (
      <>
        <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 2 }}>
          Scans pasted code or config content for live credentials (API keys, tokens, private keys, hardcoded
          passwords). Pure pattern-matching over supplied content — no network access, nothing to target.
        </div>
        <ServerActionExtras server="secrets" actionKey="secrets_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── DNS Deep — zone transfer, subdomain takeover, email security posture (all via the manifest) ──
  if (tool === 'dns_deep') {
    return (
      <>
        <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 2 }}>
          Zone transfer (AXFR) attempts, subdomain takeover detection against common cloud services, and SPF/DKIM/
          DMARC email-security posture. Target a domain.
        </div>
        <ServerActionExtras server="dns_deep" actionKey="dns_deep_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── Password Cracking — John the Ripper wordlist attacks (all via the manifest) ──
  if (tool === 'crack') {
    return (
      <>
        <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 2 }}>
          Time-boxed wordlist attack (John the Ripper) against hashes dumped by other tools (sqlmap, the AD server's
          NTLM/AS-REP hashes). Offensive — only runs with the server opt-in enabled.
        </div>
        <ServerActionExtras server="crack" actionKey="crack_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── Compliance Mapping — OWASP/PTES/ATT&CK classification (all via the manifest) ──
  if (tool === 'compliance') {
    return (
      <>
        <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 2 }}>
          Maps a tool name or finding description to OWASP Top 10 (2021), PTES phase, and MITRE ATT&CK tactics — for
          reports that need to cite which standard a finding falls under. Pure data lookup, nothing to target.
        </div>
        <ServerActionExtras server="compliance" actionKey="compliance_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  // ── payload_generator — no hand-written actions; all via the manifest ──
  if (tool === 'payload_generator') {
    return (
      <>
        <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginBottom: 2 }}>
          Generate attack payloads / wordlists. Pick an operation below.
        </div>
        <ServerActionExtras server="payload_generator" actionKey="payload_action" d={d} upd={upd} inp={inp} />
      </>
    );
  }

  return <div style={{ color: 'var(--text-muted)', fontSize: '0.6875rem', fontStyle: 'italic' }}>No extra options for this tool.</div>;
}

// The grouped, enterprise config-panel header from the approved Mockup 1: an accent icon tile, the node name, and a
// category · "needs" subline pulled from the tool manifest, with the close button.
function PanelHeader({ node, d, onClose }: { node: WFNode; d: WFNodeData; onClose: () => void }) {
  const { tools } = useToolManifest();
  const dd = d as unknown as Record<string, unknown>;
  // for a native panel the server short-name equals d.tool; find any manifest entry for it to get category/needs.
  const meta = tools.find(t => t.server === (d.tool ?? ''));
  const title = d.tool ? (d.label ?? d.tool) : node.type;
  const accent = TOOL_LIBRARY.flatMap(c => c.items).find(it => it.tool === (d.tool ?? ''))?.color ?? 'var(--cyan)';
  const sub = meta ? `${meta.category} · needs ${meta.needs.toLowerCase()}` : (node.type === 'start' ? 'Workflow entry point' : node.type);
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10, margin: '-1rem -1.25rem 4px', padding: '13px 15px',
      borderBottom: '1px solid var(--border)',
      background: `linear-gradient(180deg, color-mix(in srgb, ${accent} 8%, transparent), transparent)`,
    }}>
      <span style={{
        width: 32, height: 32, borderRadius: 9, flexShrink: 0, display: 'grid', placeItems: 'center',
        background: `color-mix(in srgb, ${accent} 15%, transparent)`, color: accent,
      }}>
        <Terminal size={16} />
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--text-primary)', textTransform: 'capitalize', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{title}</div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{sub}</div>
      </div>
      <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', flexShrink: 0 }}>
        <X size={14} />
      </button>
    </div>
  );
}

// The run status strip overlaid at the top of the canvas (the approved mock's "Running · 2 done · 1 running · 3 queued"
// bar). Shown only once a run has started; counts are derived live from each node's execStatus.
function RunStatusBar({ nodes, running }: { nodes: WFNode[]; running: boolean }) {
  const counts = { completed: 0, running: 0, failed: 0, pending: 0, skipped: 0 } as Record<string, number>;
  let total = 0;
  for (const n of nodes) {
    if (n.type === 'start') continue;
    total += 1;
    const st = (n.data as WFNodeData)?.execStatus ?? 'pending';
    counts[st] = (counts[st] ?? 0) + 1;
  }
  const done = counts.completed + counts.failed + counts.skipped;
  const anyActivity = running || done > 0;
  if (!anyActivity || total === 0) return null;

  const item = (color: string, label: string) => (
    <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <span style={{ width: 7, height: 7, borderRadius: '50%', background: color }} />{label}
    </span>
  );
  return (
    <div style={{
      position: 'absolute', top: 10, left: 10, right: 10, zIndex: 5,
      display: 'flex', alignItems: 'center', gap: 16,
      padding: '7px 14px', fontSize: 11, color: 'var(--text-muted)',
      background: 'color-mix(in srgb, var(--bg-card) 86%, transparent)',
      border: '1px solid var(--border)', borderRadius: 10,
      backdropFilter: 'blur(8px)', boxShadow: '0 4px 16px rgba(0,0,0,0.18)',
    }}>
      {running
        ? item('var(--cyan)', `Running · step ${Math.min(done + 1, total)} of ${total}`)
        : item(counts.failed > 0 ? 'var(--red)' : 'var(--green)', counts.failed > 0 ? 'Completed with failures' : 'Run complete')}
      {counts.completed > 0 && item('var(--green)', `${counts.completed} done`)}
      {counts.running > 0 && item('var(--cyan)', `${counts.running} running`)}
      {counts.failed > 0 && item('var(--red)', `${counts.failed} failed`)}
      {counts.pending > 0 && item('var(--text-muted)', `${counts.pending} queued`)}
    </div>
  );
}

function NodeConfigPanel({
  node,
  onChange,
  onClose,
  onDelete,
}: {
  node: WFNode | null;
  onChange: (id: string, data: Partial<WFNodeData>) => void;
  onClose: () => void;
  onDelete?: (id: string) => void;
}) {
  const inp = useInpStyle();

  // ── Ollama model fetching ──────────────────────────────────────
  // Renamed from "ollama"-specific to provider-generic: this used to only fetch a real model list for the Ollama
  // provider (`if (provider !== 'ollama_remote') { setOllamaModels([]); return; }`), leaving every other provider
  // (OpenAI, Anthropic, …) with just a bare text input and no way to see what models are actually configured.
  // llmApi.models() already returns per-provider model lists (ollama_remote via its own /api/tags, every other
  // provider from its admin-saved LLMConfig rows) — this now fetches for whatever provider the node has selected.
  const [ollamaModels, setOllamaModels] = useState<string[]>([]);
  const [ollamaLoading, setOllamaLoading] = useState(false);

  const fetchOllamaModels = useCallback((n: WFNode | null) => {
    if (!n || n.type !== 'llm') { setOllamaModels([]); return; }
    const provider = normalizeProvider(n.data.provider);
    setOllamaLoading(true);

    // Use authenticated API client to fetch models
    llmApi.models({
      provider,
      ...(provider === 'ollama_remote' && n.data.remote_url ? { remote_url: n.data.remote_url } : {})
    })
      .then(r => {
        const data = r.data;
        const byProvider: Record<string, string[]> = data.provider_models || {};
        const list: string[] = Array.isArray(byProvider[provider])
          ? byProvider[provider]
          : provider === 'ollama_remote'
            ? (data.ollama_remote_models ?? []).map((m: any) => m.name as string)
            : [];
        setOllamaModels(list);
      })
      .catch(err => {
        console.error('Failed to fetch models:', err);
        setOllamaModels([]);
      })
      .finally(() => setOllamaLoading(false));
  }, []);

  useEffect(() => {
    fetchOllamaModels(node);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [node?.id, node?.data?.provider, node?.data?.remote_url]);

  if (!node) {
    return (
      <div style={{ padding: '2rem 1.5rem', color: 'var(--text-muted)', fontSize: '0.8125rem', textAlign: 'center' }}>
        <Settings size={28} style={{ margin: '0 auto 0.75rem', display: 'block', opacity: 0.3 }} />
        Select a node to configure it
      </div>
    );
  }

  const d = node.data;
  const upd = (patch: Partial<WFNodeData>) => onChange(node.id, patch);

  return (
    <div style={{ padding: '1rem 1.25rem', fontSize: '0.75rem', display: 'flex', flexDirection: 'column', gap: 12 }}>
      <PanelHeader node={node} d={d} onClose={onClose} />

      {/* Label — all types except start */}
      {node.type !== 'start' && (
        <Field label="Label">
          <input value={d.label ?? ''} onChange={e => upd({ label: e.target.value })} style={inp} />
        </Field>
      )}

      {/* ── Start node ── */}
      {node.type === 'start' && (
        <>
          <Section title="Workflow Type" />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
            {([
              { value: 'network', icon: '🖧',  label: 'Network Scan',    sub: 'IP · Domain · CIDR' },
              { value: 'cve',     icon: '🔎',  label: 'CVE Research',    sub: 'CVE ID lookup' },
              { value: 'keyword', icon: '🔍',  label: 'Threat Intel',    sub: 'Keyword search' },
              { value: 'url',     icon: '🌐',  label: 'Web Audit',       sub: 'Single URL' },
              { value: 'webapp',  icon: '🕷️', label: 'Web App Pentest', sub: 'Full web testing' },
              { value: 'osint',   icon: '👁️', label: 'OSINT Recon',     sub: 'Domain · IP' },
              { value: 'exploit', icon: '💥',  label: 'Exploit Chain',   sub: 'CVE → PoC → MSF' },
              { value: 'pentest', icon: '🎯',  label: 'Full Pentest',    sub: 'IP / CIDR' },
              { value: 'code',    icon: '📦',  label: 'Code Audit',      sub: 'JS/TS dependencies' },
              { value: 'ssl',     icon: '🔒',  label: 'SSL/TLS Audit',   sub: 'Domain · IP' },
            ] as { value: string; icon: string; label: string; sub: string }[]).map(opt => {
              const active = (d.workflow_type ?? 'network') === opt.value;
              return (
                <button
                  key={opt.value}
                  onClick={() => upd({ workflow_type: opt.value as WFNodeData['workflow_type'] })}
                  style={{
                    background: active ? 'color-mix(in srgb, var(--green) 9%, transparent)' : 'var(--bg-card)',
                    border: `1.5px solid ${active ? 'var(--green)' : 'var(--border)'}`,
                    borderRadius: 'var(--radius-md)', padding: '8px 6px', cursor: 'pointer', textAlign: 'center',
                    color: active ? 'var(--green)' : 'var(--text-secondary)', transition: 'all 0.15s',
                  }}
                >
                  <div style={{ fontSize: '1rem', lineHeight: 1 }}>{opt.icon}</div>
                  <div style={{ fontWeight: 700, fontSize: '0.6875rem', marginTop: 4 }}>{opt.label}</div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: 2 }}>{opt.sub}</div>
                </button>
              );
            })}
          </div>

          <Section title="Start Value" />
          {(d.workflow_type ?? 'network') === 'network' && (
            <Field label="Target IP / Domain / CIDR" hint="e.g. 192.168.1.1 · 10.0.0.0/24 · example.com">
              <input value={d.target ?? ''} placeholder="192.168.1.1"
                onChange={e => upd({ target: e.target.value })} style={inp} />
            </Field>
          )}
          {d.workflow_type === 'cve' && (
            <Field label="CVE ID(s)" hint="Single CVE or comma-separated list, e.g. CVE-2021-44228, CVE-2023-0386">
              <input value={d.target ?? ''} placeholder="CVE-2021-44228, CVE-2023-0386"
                onChange={e => upd({ target: e.target.value })} style={inp} />
            </Field>
          )}
          {d.workflow_type === 'keyword' && (
            <Field label="Search Keyword" hint="Software name, vendor, or vulnerability keyword">
              <input value={d.target ?? ''} placeholder="apache log4j, openssl, Microsoft Exchange …"
                onChange={e => upd({ target: e.target.value })} style={inp} />
            </Field>
          )}
          {d.workflow_type === 'url' && (
            <Field label="Target URL" hint="Full URL including protocol">
              <input value={d.target ?? ''} placeholder="http://192.168.1.1:8080"
                onChange={e => upd({ target: e.target.value })} style={inp} />
            </Field>
          )}
          {d.workflow_type === 'webapp' && (
            <Field label="Target URL" hint="Full URL of the web application to pentest">
              <input value={d.target ?? ''} placeholder="http://target.com:8080"
                onChange={e => upd({ target: e.target.value })} style={inp} />
            </Field>
          )}
          {d.workflow_type === 'osint' && (
            <Field label="Target Domain / IP" hint="e.g. example.com · 192.168.1.1 — every OSINT action (WHOIS, DNS, geolocation, subdomains) and the Nmap/SSL/WAF steps after it need a domain or IP, not a company name">
              <input value={d.target ?? ''} placeholder="example.com"
                onChange={e => upd({ target: e.target.value })} style={inp} />
            </Field>
          )}
          {d.workflow_type === 'exploit' && (
            <Field label="CVE ID(s)" hint="CVE to research and exploit, e.g. CVE-2021-44228">
              <input value={d.target ?? ''} placeholder="CVE-2021-44228"
                onChange={e => upd({ target: e.target.value })} style={inp} />
            </Field>
          )}
          {d.workflow_type === 'pentest' && (
            <Field label="Target IP / CIDR" hint="Single host or network range, e.g. 10.0.0.0/24">
              <input value={d.target ?? ''} placeholder="10.0.0.0/24"
                onChange={e => upd({ target: e.target.value })} style={inp} />
            </Field>
          )}
          {d.workflow_type === 'code' && (
            <Field label="Project Name" hint="JS/TS project uploaded via the CVE Lite node">
              <input value={d.target ?? ''} placeholder="my-app"
                onChange={e => upd({ target: e.target.value })} style={inp} />
            </Field>
          )}
          {d.workflow_type === 'ssl' && (
            <Field label="Target Domain / IP" hint="e.g. example.com · 192.168.1.1">
              <input value={d.target ?? ''} placeholder="example.com"
                onChange={e => upd({ target: e.target.value })} style={inp} />
            </Field>
          )}

          <div style={{
            marginTop: 4, fontSize: '0.6875rem', color: 'var(--text-muted)',
            background: 'var(--bg-primary)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)', padding: '8px 10px', lineHeight: 1.7,
          }}>
            <div style={{ fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 3 }}>Suggested tools:</div>
            {({
              network: 'Nmap → Nuclei → WAF Detect → LLM  (add FFUF / SQLMap only if Nmap finds an HTTP/HTTPS port — they need a URL, not a bare IP)',
              cve:     'CVE Lookup → CISA KEV → EPSS Score → PoC Search → LLM',
              keyword: 'CVE Lookup → CISA KEV → PoC Search → LLM',
              url:     'FFUF → SQLMap → WAF Detect → LLM',
              webapp:  'Gobuster → FFUF → Nikto → WPScan → SQLMap → JWT → WAF Detect → LLM',
              osint:   'OSINT Tools → Nmap → SSL/TLS → WAF Detect → LLM',
              exploit: 'CVE Lookup → EPSS → CISA KEV → PoC Search → Metasploit → LLM',
              pentest: 'Masscan → Nmap → Nuclei → Metasploit → LLM',
              code:    'CVE Lite Scan → CVE Lookup → EPSS Score → LLM',
              ssl:     'SSL/TLS → Nmap → WAF Detect → LLM',
            } as Record<string, string>)[d.workflow_type ?? 'network']}
          </div>
        </>
      )}

      {/* ── Tool node ── */}
      {node.type === 'tool' && (
        <>
          <Section title="Tool Options" />
          <ToolSpecificFields d={d} upd={upd} inp={inp} />

          <Section title="Execution" />
          <Field label="Timeout (seconds)">
            <input type="number" value={d.timeout ?? 300}
              onChange={e => upd({ timeout: e.target.value ? parseInt(e.target.value) : undefined })}
              style={inp} />
          </Field>
          <Field label="Port Filter (run only if these ports open)" hint="Comma-separated, e.g. 80, 443, 8080">
            <input value={(d.port_filter ?? []).join(', ')} placeholder="80, 443"
              onChange={e => {
                const v = e.target.value.split(',').map(p => parseInt(p.trim())).filter(n => !isNaN(n));
                upd({ port_filter: v.length ? v : undefined });
              }} style={inp} />
          </Field>
        </>
      )}

      {/* ── LLM node ── */}
      {node.type === 'llm' && (
        <>
          <Section title="LLM Provider" />
          <Field label="Provider">
            <select value={normalizeProvider(d.provider)} onChange={e => upd({ provider: e.target.value as any })}
              style={{ ...inp, cursor: 'pointer' }}>
              {LLM_PROVIDERS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
            </select>
          </Field>
          {/* Model — a real dropdown for ANY provider once its configured models are fetched, text input as a
              fallback (e.g. nothing configured for that provider yet, or the admin hasn't saved a model list). */}
          <Field
            label="Model"
            hint={
              ollamaLoading ? 'Fetching models…'
                : ollamaModels.length > 0 ? `${ollamaModels.length} model(s) found`
                : normalizeProvider(d.provider) === 'ollama_remote' ? 'Could not fetch — enter manually'
                : 'No models configured for this provider in Admin → AI providers — enter the exact model name, or configure one there first'
            }
          >
            <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
              {ollamaModels.length > 0 ? (
                <select
                  value={d.model ?? ''}
                  onChange={e => upd({ model: e.target.value })}
                  style={{ ...inp, cursor: 'pointer', marginTop: 0, flex: 1 }}
                >
                  <option value="">— select model —</option>
                  {ollamaModels.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              ) : (
                <input
                  value={d.model ?? ''}
                  placeholder={normalizeProvider(d.provider) === 'ollama_remote' ? 'qwen2.5:7b' : 'gpt-4o'}
                  onChange={e => upd({ model: e.target.value })}
                  style={{ ...inp, marginTop: 0, flex: 1 }}
                />
              )}
              <button
                onClick={() => fetchOllamaModels(node)}
                disabled={ollamaLoading}
                title="Refresh model list"
                style={{
                  background: 'var(--bg-primary)', border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)', color: 'var(--text-muted)', cursor: ollamaLoading ? 'default' : 'pointer',
                  padding: '4px 7px', display: 'flex', alignItems: 'center',
                }}
              >
                <RefreshCw size={11} style={{ animation: ollamaLoading ? 'spin 1s linear infinite' : 'none' }} />
              </button>
            </div>
          </Field>
          {d.provider === 'ollama_remote' && (
            <Field label="Remote URL">
              <input value={d.remote_url ?? ''} placeholder="http://remote:11434"
                onChange={e => upd({ remote_url: e.target.value })} style={inp} />
            </Field>
          )}
          <Section title="Prompt" />
          <Field label="Prompt Template" hint="Leave blank or write a plain instruction — all upstream results are injected automatically. Use {{node_id.output}} for specific nodes.">
            <textarea value={d.prompt ?? ''}
              placeholder={'Summarize the findings from the workflow tools above. Only report what was actually found — do not add vulnerabilities or issues not explicitly present in the tool output.'}
              onChange={e => upd({ prompt: e.target.value })}
              rows={7}
              style={{ ...inp, resize: 'vertical', fontFamily: 'monospace', lineHeight: 1.5 }} />
          </Field>
          <Field label="Output Key" hint="Key used when other nodes reference this node's output">
            <input value={d.output_key ?? 'analysis'} onChange={e => upd({ output_key: e.target.value })} style={inp} />
          </Field>
        </>
      )}

      {/* ── Condition node ── */}
      {node.type === 'condition' && (() => {
        const [condTool, condCheck, condParam] = parseCondExpr(d.expression ?? 'nmap:host_up');
        const checks = CONDITION_CHECKS[condTool] ?? [];
        const checkDef = checks.find(c => c.value === condCheck) ?? checks[0];
        const needsParam = checkDef?.hasParam ?? false;

        const handleToolChange = (newTool: string) => {
          const firstCheck = CONDITION_CHECKS[newTool]?.[0]?.value ?? 'success';
          upd({ expression: buildCondExpr(newTool, firstCheck, '') });
        };
        const handleCheckChange = (newCheck: string) => {
          upd({ expression: buildCondExpr(condTool, newCheck, '') });
        };
        const handleParamChange = (newParam: string) => {
          upd({ expression: buildCondExpr(condTool, condCheck, newParam) });
        };

        return (
          <>
            <Section title="Branch Condition" />
            <Field label="Tool">
              <select value={condTool} onChange={e => handleToolChange(e.target.value)}
                style={{ ...inp, cursor: 'pointer' }}>
                {CONDITION_TOOLS.map(t => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </Field>
            {checks.length > 0 && (
              <Field label="Check">
                <select value={condCheck} onChange={e => handleCheckChange(e.target.value)}
                  style={{ ...inp, cursor: 'pointer' }}>
                  {checks.map(c => (
                    <option key={c.value} value={c.value}>{c.label}</option>
                  ))}
                </select>
              </Field>
            )}
            {needsParam && (
              <Field label={checkDef?.paramLabel ?? 'Parameter'}>
                <input
                  value={condParam}
                  placeholder={checkDef?.paramDefault ?? ''}
                  onChange={e => handleParamChange(e.target.value)}
                  style={inp}
                />
              </Field>
            )}
            <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '6px 8px', lineHeight: 1.6, marginTop: 4 }}>
              <span style={{ fontFamily: 'monospace', opacity: 0.7 }}>{d.expression ?? '—'}</span>
              <br />
              Connect the <span style={{ color: 'var(--green)', fontWeight: 700 }}>YES</span> handle (left) and <span style={{ color: 'var(--red)', fontWeight: 700 }}>NO</span> handle (right) to different branches.
            </div>
          </>
        );
      })()}

      {/* ── Report node ── */}
      {node.type === 'report' && (
        <>
          <Section title="Report Options" />
          <Field label="Template">
            <select value={d.template ?? 'standard'} onChange={e => upd({ template: e.target.value })}
              style={{ ...inp, cursor: 'pointer' }}>
              <option value="standard">Standard</option>
              <option value="executive">Executive Summary</option>
              <option value="technical">Technical Detail</option>
            </select>
          </Field>
          <Field label="Export Format">
            <select value={(d.report_format as string) ?? 'pdf'} onChange={e => upd({ report_format: e.target.value as WFNodeData['report_format'] })}
              style={{ ...inp, cursor: 'pointer' }}>
              <option value="pdf">PDF</option>
              <option value="html">HTML</option>
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
            </select>
          </Field>
          <Field label="Theme">
            <select value={(d.report_theme as string) ?? 'dark'} onChange={e => upd({ report_theme: e.target.value as WFNodeData['report_theme'] })}
              style={{ ...inp, cursor: 'pointer' }}>
              <option value="dark">🌑 Dark</option>
              <option value="light">☀️ Light</option>
            </select>
          </Field>
        </>
      )}

      {/* ── Delete node button ── */}
      {onDelete && (
        <div style={{ marginTop: 8, paddingTop: 10, borderTop: '1px solid var(--border)' }}>
          <button
            onClick={() => onDelete(node.id)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              width: '100%', padding: '7px 12px', borderRadius: 'var(--radius-sm)',
              border: '1px solid color-mix(in srgb, var(--red) 27%, transparent)', background: 'color-mix(in srgb, var(--red) 5%, transparent)',
              color: 'var(--red)', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600,
            }}
          >
            <Trash2 size={13} />
            Delete Node
          </button>
        </div>
      )}
    </div>
  );
}

// ── Main builder component (inner — needs ReactFlowProvider wrapper) ──────────

function BuilderInner({
  workflowId,
  initialPresetId,
}: {
  workflowId: string | null;
  initialPresetId: string | null;
}) {
  const router = useRouter();
  const [nodes, setNodes, onNodesChange] = useNodesState<WFNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<WFEdge>([]);
  const [name, setName] = useState('');
  // Auto-generate name when first tool node is added
  const autoNamedRef = useRef(false);
  const [selectedNode, setSelectedNode] = useState<WFNode | null>(null);
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState(false);
  const [runScanId, setRunScanId] = useState<string | null>(null);
  const [saveMsg, setSaveMsg] = useState<string | null>(null);
  const [defaultProvider, setDefaultProvider] = useState<string>('ollama_remote');
  const [defaultModel, setDefaultModel] = useState<string>('qwen2.5:7b');
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState<string>('');
  const [runTarget, setRunTarget] = useState<string>('');
  const [showRunModal, setShowRunModal] = useState(false);
  const [showGenModal, setShowGenModal] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [wsLog, setWsLog] = useState<WFNodeEvent[]>([]);
  const [genPrompt, setGenPrompt] = useState('');
  const [genTarget, setGenTarget] = useState('');
  const [generating, setGenerating] = useState(false);
  const [showGenHelp, setShowGenHelp] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reactFlowWrapper = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const loadedPresetRef = useRef<string | null>(null);
  const edgeReconnectSuccessful = useRef(true);

  // Enterprise builder state
  const [toolSearch, setToolSearch]   = useState('');
  const [libCollapsed, setLibCollapsed] = useState(false);  // hide the tool library to give the canvas more room
  const [isDirty, setIsDirty]         = useState(false);
  const [showLog, setShowLog]         = useState(false);
  const [collapsedCats, setCollapsedCats] = useState<Record<string, boolean>>({});
  const toggleCat = (cat: string) => setCollapsedCats(p => ({ ...p, [cat]: !p[cat] }));

  // Auto-name when nodes are added (only for new unsaved workflows)
  useEffect(() => {
    if (workflowId || autoNamedRef.current || name) return;
    const startNode = nodes.find((n: WFNode) => n.type === 'start');
    if (startNode?.data?.workflow_type) {
      const typeLabels: Record<string, string> = {
        network: 'Network Scan', cve: 'CVE Research', keyword: 'Threat Intel', url: 'Web Audit',
        webapp: 'Web App Pentest', osint: 'OSINT Recon', exploit: 'Exploit Chain',
        pentest: 'Full Pentest', code: 'Code Audit', ssl: 'SSL/TLS Audit',
      };
      setName(typeLabels[startNode.data.workflow_type as string] || 'My Workflow');
      autoNamedRef.current = true;
    }
  }, [nodes, workflowId, name]);

  // Mark dirty when nodes/edges change (after initial load)
  const didMountRef = useRef(false);
  useEffect(() => {
    if (!didMountRef.current) { didMountRef.current = true; return; }
    setIsDirty(true);
  }, [nodes, edges, name]);

  // Ctrl+S to save
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); handleSave(); }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges, name, workflowId, projectId, defaultProvider, defaultModel]);

  // Load existing workflow if editing
  useEffect(() => {
    if (workflowId) {
      workflowsApi.get(workflowId).then(r => {
        const wf: WorkflowDefinition = r.data;
        setName(wf.name);
        setNodes(normalizeNodeProviders(wf.nodes as WFNode[] ?? []));
        setEdges(wf.edges as WFEdge[] ?? []);
        if (wf.default_llm) {
          setDefaultProvider(normalizeProvider(wf.default_llm.provider));
          setDefaultModel(wf.default_llm.model);
        }
        if (wf.project_id) setProjectId(wf.project_id);
        // Pre-fill runTarget from start node
        const startNode = (wf.nodes as WFNode[]).find(n => n.type === 'start');
        if (startNode?.data?.target) setRunTarget(startNode.data.target);
      }).catch(() => {});
    } else if (
      initialPresetId &&
      WORKFLOW_PRESETS[initialPresetId] &&
      loadedPresetRef.current !== initialPresetId
    ) {
      const { nodes: presetNodes, edges: presetEdges } = buildPresetGraph(initialPresetId);
      if (presetNodes.length > 0) {
        setNodes(presetNodes);
        setEdges(presetEdges);
        setName(WORKFLOW_PRESETS[initialPresetId].name);
        loadedPresetRef.current = initialPresetId;
      }
    }
    projectsApi.list().then(r => setProjects(r.data?.projects ?? r.data ?? [])).catch(() => {});
  }, [workflowId, initialPresetId]);

  // Connect WS for live node events when running
  useEffect(() => {
    if (!runScanId) return;
    const apiBase = process.env.NEXT_PUBLIC_API_URL ||
      (typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8000');
    const token = document.cookie.split('; ').find(c => c.startsWith('access_token='))?.split('=')[1] ?? '';
    const wsUrl = apiBase.replace(/^http/, 'ws') + `/ws/scan/${runScanId}?token=${token}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (ev) => {
      try {
        const msg: WFNodeEvent = JSON.parse(ev.data);
        if (msg.type === 'node_start' || msg.type === 'node_complete' || msg.type === 'node_failed') {
          setWsLog(prev => [...prev.slice(-100), msg]);
          // Update the node's exec status on the canvas
          const execStatus =
            msg.type === 'node_start'    ? 'running'   :
            msg.type === 'node_complete' ? (msg.skipped ? 'skipped' : 'completed') :
            'failed';
          setNodes((prev: WFNode[]) => prev.map((n: WFNode) =>
            n.id === msg.node_id
              ? { ...n, data: { ...n.data, execStatus, execOutput: msg.output, execDuration: msg.duration_ms } }
              : n
          ));
        }
        // Backend sends type='complete' or type='status' with status='completed'/'failed'
        const t = (msg as any).type;
        const s = (msg as any).status;
        if (t === 'complete' || t === 'cancelled' || (t === 'status' && (s === 'completed' || s === 'failed'))) {
          setRunning(false);
          setRunScanId(null);
        }
      } catch {}
    };
    ws.onclose = () => setRunning(false);
    return () => ws.close();
  }, [runScanId]);

  // ── Drag-and-drop from library ─────────────────────────────
  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const raw = e.dataTransfer.getData('application/socis-node');
    if (!raw) return;
    const proto: { type: string; data: WFNodeData } = JSON.parse(raw);

    const bounds = reactFlowWrapper.current?.getBoundingClientRect();
    if (!bounds) return;

    // Approximate canvas position (without flowToScreenPosition we use raw coords)
    const position = {
      x: e.clientX - bounds.left - 80,
      y: e.clientY - bounds.top - 30,
    };

    const newNode: WFNode = {
      id: uid(),
      type: proto.type as any,
      position,
      data: proto.data,
    };
    setNodes((prev: WFNode[]) => [...prev, newNode]);
  }, [setNodes]);

  const onConnect = useCallback(
    (params: Connection) => setEdges((prev: WFEdge[]) => addEdge({ ...params, id: uid() }, prev) as WFEdge[]),
    [setEdges],
  );

  const onReconnectStart = useCallback(() => {
    edgeReconnectSuccessful.current = false;
  }, []);

  const onReconnect = useCallback(
    (oldEdge: Edge, newConnection: Connection) => {
      edgeReconnectSuccessful.current = true;
      setEdges((els) => reconnectEdge(oldEdge, newConnection, els) as WFEdge[]);
    },
    [setEdges],
  );

  const onReconnectEnd = useCallback(
    (_: MouseEvent | TouchEvent, edge: Edge) => {
      if (!edgeReconnectSuccessful.current) {
        setEdges((eds: WFEdge[]) => eds.filter((e: WFEdge) => e.id !== edge.id));
      }
      edgeReconnectSuccessful.current = true;
    },
    [setEdges],
  );

  const onNodeClick = useCallback((_: any, node: WFNode) => {
    setSelectedNode(node);
  }, []);

  const updateNodeData = useCallback((id: string, patch: Partial<WFNodeData>) => {
    setNodes((prev: WFNode[]) =>
      prev.map((n: WFNode) => n.id === id ? { ...n, data: { ...n.data, ...patch } } : n)
    );
    setSelectedNode((prev: WFNode | null) => prev?.id === id ? { ...prev, data: { ...prev.data, ...patch } } : prev);
  }, [setNodes]);

  // ── Save ──────────────────────────────────────────────────────
  const handleSave = async () => {
    setSaving(true);
    setSaveMsg(null);
    const payload = {
      name: name.trim() || 'My Workflow',
      nodes: nodes as any[],
      edges: edges as any[],
      project_id: projectId || undefined,
      default_llm: { provider: defaultProvider, model: defaultModel },
    };
    try {
      if (workflowId) {
        await workflowsApi.update(workflowId, payload);
        setSaveMsg('Saved!');
        setIsDirty(false);
      } else {
        const r = await workflowsApi.create(payload);
        router.replace(`/workflows/builder?id=${r.data.id}`);
        setSaveMsg('Created!');
        setIsDirty(false);
      }
    } catch {
      setSaveMsg('Save failed');
    } finally {
      setSaving(false);
      setTimeout(() => setSaveMsg(null), 2500);
    }
  };

  // ── Run ────────────────────────────────────────────────────────
  const handleRun = async () => {
    if (!workflowId) {
      await handleSave();
      return;
    }
    setWsLog([]);
    setRunning(true);
    setShowLog(true);
    // Reset exec status on all nodes
    setNodes((prev: WFNode[]) => prev.map((n: WFNode) => ({ ...n, data: { ...n.data, execStatus: 'pending', execOutput: undefined } })));
    try {
      const r = await workflowsApi.run(workflowId, {
        target: runTarget || undefined,
        project_id: projectId || undefined,
      });
      setRunScanId(r.data.id);
    } catch (err) {
      // This used to fail silently. A target outside the project's authorized scope is explained here, and an administrator can
      // run it anyway with a written reason; any other failure is now shown instead of just stopping.
      const block = scopeBlock(err);
      let started = false;
      if (block) {
        const reason = await askScopeOverride(block);
        if (reason) {
          try {
            const r2 = await workflowsApi.run(workflowId, { target: runTarget || undefined, project_id: projectId || undefined, scope_override_reason: reason });
            setRunScanId(r2.data.id);
            started = true;
          } catch (err2) {
            notify(apiError(err2, 'Could not start the workflow'), 'error');
          }
        }
      } else {
        notify(apiError(err, 'Could not start the workflow'), 'error');
      }
      if (!started) setRunning(false);
    }
    setShowRunModal(false);
  };

  // ── Export / Import ────────────────────────────────────────────
  const handleExport = async () => {
    if (!workflowId) { notify('Save the workflow first.', 'error'); return; }
    const r = await workflowsApi.exportWorkflow(workflowId);
    const url = URL.createObjectURL(r.data);
    const a = document.createElement('a');
    a.href = url; a.download = `${name}.socis-workflow.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]; if (!file) return;
    const text = await file.text();
    try {
      const json = JSON.parse(text);
      const r = await workflowsApi.importWorkflow(json);
      router.replace(`/workflows/builder?id=${r.data.id}`);
    } catch { notify('Invalid workflow file.', 'error'); }
    e.target.value = '';
  };

  // ── Add start node shortcut ────────────────────────────────────
  const addStartNode = () => {
    setNodes((prev: WFNode[]) => [
      ...prev,
      { id: uid(), type: 'start', position: { x: 200, y: 60 }, data: { target: '' } } as WFNode,
    ]);
  };

  // ── Load a preset template onto the canvas ─────────────────────
  const handleLoadTemplate = (presetId: string) => {
    const { nodes: tNodes, edges: tEdges } = buildPresetGraph(presetId);
    if (!tNodes.length) return;
    const preset = WORKFLOW_PRESETS[presetId];
    setNodes(tNodes);
    setEdges(tEdges);
    setName(preset.name);
    setShowTemplates(false);
  };

  // ── Delete node ────────────────────────────────────────────────
  const handleDeleteNode = useCallback((id: string) => {
    setNodes((prev: WFNode[]) => prev.filter((n: WFNode) => n.id !== id));
    setEdges((prev: WFEdge[]) => prev.filter((e: WFEdge) => e.source !== id && e.target !== id));
    setSelectedNode(prev => prev?.id === id ? null : prev);
  }, [setNodes, setEdges]);

  // Clear selectedNode if it was deleted from the canvas (e.g. via node × button)
  useEffect(() => {
    if (selectedNode && !nodes.find((n: WFNode) => n.id === selectedNode.id)) {
      setSelectedNode(null);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, selectedNode]);

  // ── Styles ─────────────────────────────────────────────────────
  const S: Record<string, React.CSSProperties> = {
    root:    { display: 'flex', flexDirection: 'column', height: '100vh', background: 'var(--bg-primary)', fontFamily: 'inherit' },
    topBar:  { display: 'flex', alignItems: 'center', gap: 10, padding: '0 1rem', height: 52, borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', flexShrink: 0 },
    body:    { display: 'flex', flex: 1, overflow: 'hidden' },
    left:    { width: 240, borderRight: '1px solid var(--border)', background: 'var(--bg-secondary)', overflowY: 'auto', flexShrink: 0, display: 'flex', flexDirection: 'column' },
    canvas:  { flex: 1, position: 'relative',
      // Canvas surface matches the theme: white in light theme, dark in dark theme (via --bg-secondary). A very soft
      // radial glow adds a little depth without tinting the surface away from the theme colour.
      background: 'var(--bg-secondary)',
      backgroundImage: 'radial-gradient(circle at 22% 18%, color-mix(in srgb, var(--cyan) 5%, transparent), transparent 45%), radial-gradient(circle at 80% 72%, color-mix(in srgb, var(--purple) 4%, transparent), transparent 48%)' },
    right:   { width: 320, borderLeft: '1px solid var(--border)', background: 'var(--bg-secondary)', overflowY: 'auto', flexShrink: 0 },
    logStrip:{ borderTop: '1px solid var(--border)', background: 'var(--bg-primary)', overflowY: 'auto', flexShrink: 0, padding: '6px 12px', fontFamily: 'monospace', fontSize: 11, color: 'var(--text-muted)', transition: 'height 0.2s ease' },
    btn:     { display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px', borderRadius: 6, border: 'none', cursor: 'pointer', fontWeight: 600, fontSize: 12 },
    catHdr:  { padding: '8px 10px 4px', fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' },
    libItem: { display: 'flex', alignItems: 'center', gap: 8, padding: '7px 10px', cursor: 'grab', borderRadius: 6, margin: '1px 6px', fontSize: 12, color: 'var(--text-secondary)' },
  };

  // ── Risk badge helper ──────────────────────────────────────────
  const RISK_BADGE: Record<string, { label: string; color: string; bg: string }> = {
    low:      { label: 'LOW',      color: 'var(--green)', bg: 'color-mix(in srgb, var(--green) 10%, transparent)' },
    medium:   { label: 'MED',      color: 'var(--amber)', bg: 'color-mix(in srgb, var(--amber) 10%, transparent)' },
    high:     { label: 'HIGH',     color: 'var(--orange)', bg: 'color-mix(in srgb, var(--orange) 13%, transparent)' },
    critical: { label: 'CRIT',     color: 'var(--red)', bg: 'color-mix(in srgb, var(--red) 13%, transparent)' },
  };

  // ── Filtered tool library ──────────────────────────────────────
  const filteredLibrary = toolSearch.trim()
    ? TOOL_LIBRARY.map(cat => ({
        ...cat,
        items: cat.items.filter(item =>
          item.label.toLowerCase().includes(toolSearch.toLowerCase()) ||
          item.hint.toLowerCase().includes(toolSearch.toLowerCase()) ||
          item.tool.toLowerCase().includes(toolSearch.toLowerCase())
        ),
      })).filter(cat => cat.items.length > 0)
    : TOOL_LIBRARY;

  // ── Workflow status badge ───────────────────────────────────────
  const statusBadge = saving
    ? { label: 'Saving…', color: 'var(--cyan)', bg: 'color-mix(in srgb, var(--cyan) 13%, transparent)' }
    : saveMsg === 'Saved!' || saveMsg === 'Created!'
    ? { label: 'Saved', color: 'var(--green)', bg: 'color-mix(in srgb, var(--green) 13%, transparent)' }
    : isDirty
    ? { label: 'Modified', color: 'var(--amber)', bg: 'color-mix(in srgb, var(--amber) 13%, transparent)' }
    : !workflowId
    ? { label: 'Draft', color: 'var(--text-muted)', bg: 'color-mix(in srgb, var(--text-muted) 13%, transparent)' }
    : { label: 'Saved', color: 'var(--green)', bg: 'color-mix(in srgb, var(--green) 13%, transparent)' };

  return (
    <div style={S.root}>
      {/* ── Top bar ── */}
      <div style={S.topBar}>
        {/* Back */}
        <button onClick={() => router.push('/workflows')}
          style={{ ...S.btn, background: 'none', color: 'var(--text-muted)', padding: '4px 6px', gap: 4, flexShrink: 0 }}>
          <ChevronRight size={13} style={{ transform: 'rotate(180deg)' }} />
          Workflows
        </button>

        {/* Divider */}
        <span style={{ color: 'var(--border)', fontSize: '1rem' }}>|</span>

        {/* Workflow name */}
        <input
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="Untitled Workflow…"
          style={{ background: 'none', border: 'none', color: 'var(--text-primary)', fontWeight: 700, fontSize: '0.875rem', outline: 'none', flex: 1, minWidth: 100 }}
        />

        {/* Status badge */}
        <span style={{ flexShrink: 0, fontSize: '0.6875rem', fontWeight: 700, letterSpacing: '0.06em', padding: '2px 8px', borderRadius: 'var(--radius-sm)', background: statusBadge.bg, color: statusBadge.color, border: `1px solid color-mix(in srgb, ${statusBadge.color} 27%, transparent)` }}>
          {statusBadge.label}
        </span>

        {/* Node / edge counter */}
        {nodes.length > 0 && (
          <span title={`${nodes.length} nodes, ${edges.length} connections`} style={{ flexShrink: 0, display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.6875rem', color: 'var(--text-muted)', background: 'var(--bg-hover)', borderRadius: 'var(--radius-sm)', padding: '2px 7px', cursor: 'default' }}>
            <Hash size={10} />
            {nodes.length}n · {edges.length}e
          </span>
        )}

        {/* Keyboard hint */}
        <span title="Ctrl+S to save" style={{ flexShrink: 0, fontSize: '0.6875rem', color: 'var(--text-muted)', opacity: 0.5 }}>⌘S</span>

        <div style={{ flexShrink: 0, display: 'flex', gap: 4 }}>
          <button onClick={() => fileInputRef.current?.click()} title="Import workflow"
            style={{ ...S.btn, background: 'var(--bg-hover)', border: '1px solid var(--border)', color: 'var(--text-muted)', padding: '5px 8px', fontSize: '0.6875rem' }}>
            <Upload size={13} /> Import
          </button>
          <input ref={fileInputRef} type="file" accept=".json" style={{ display: 'none' }} onChange={handleImportFile} />

          <button onClick={() => setShowGenModal(true)} title="AI Generate workflow"
            style={{ ...S.btn, background: 'var(--bg-hover)', border: '1px solid var(--border)', color: 'var(--purple)', padding: '5px 8px', fontSize: '0.6875rem' }}>
            <Brain size={13} /> AI Generate
          </button>

          {workflowId && (
            <button onClick={handleExport} title="Export workflow"
              style={{ ...S.btn, background: 'var(--bg-hover)', border: '1px solid var(--border)', color: 'var(--text-muted)', padding: '5px 8px', fontSize: '0.6875rem' }}>
              <Download size={13} />
            </button>
          )}
        </div>

        <button onClick={handleSave} disabled={saving}
          style={{ ...S.btn, flexShrink: 0, background: isDirty ? 'var(--cyan-glow)' : 'var(--bg-hover)', border: `1px solid ${isDirty ? 'var(--cyan)' : 'var(--border)'}`, color: isDirty ? 'var(--cyan)' : 'var(--text-muted)', fontSize: '0.75rem' }}>
          {saving ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />}
          Save
        </button>
        <button
          onClick={() => { if (!workflowId) { handleSave(); } else { setShowRunModal(true); } }}
          disabled={running}
          style={{ ...S.btn, flexShrink: 0, background: running ? 'var(--bg-hover)' : 'var(--green)', border: `1px solid ${running ? 'var(--border)' : 'var(--green)'}`, color: running ? 'var(--text-muted)' : 'var(--on-accent)', fontWeight: 700, fontSize: '0.75rem', boxShadow: running ? 'none' : '0 2px 10px color-mix(in srgb, var(--green) 40%, transparent)' }}>
          {running ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />}
          {running ? 'Running…' : 'Run'}
        </button>
      </div>

      <div style={S.body}>
        {/* ── LEFT: tool library (collapsible to give the canvas room) ── */}
        {libCollapsed ? (
          <div style={{ width: 34, borderRight: '1px solid var(--border)', background: 'var(--bg-secondary)', flexShrink: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', paddingTop: 10 }}>
            <button onClick={() => setLibCollapsed(false)} title="Show tool library"
              style={{ background: 'var(--bg-hover)', border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer', color: 'var(--text-secondary)', width: 24, height: 24, display: 'grid', placeItems: 'center' }}>
              <ChevronRight size={14} />
            </button>
            <div style={{ writingMode: 'vertical-rl', marginTop: 12, fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>Tools</div>
          </div>
        ) : (
        <div style={S.left}>
          {/* collapse toggle */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', padding: '6px 8px 0' }}>
            <button onClick={() => setLibCollapsed(true)} title="Hide tool library"
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}>
              Hide <ChevronLeft size={13} />
            </button>
          </div>
          {/* Start node button */}
          <div style={{ padding: '10px 8px 6px', borderBottom: '1px solid var(--border)' }}>
            <button onClick={addStartNode}
              style={{ ...S.btn, background: 'var(--bg-secondary)', border: '1px solid color-mix(in srgb, var(--green) 27%, transparent)', color: 'var(--green)', width: '100%', justifyContent: 'center', fontSize: '0.75rem', padding: '7px 0' }}>
              <Plus size={13} /> Start Node
            </button>
          </div>

          {/* Search */}
          <div style={{ padding: '8px 8px 4px', position: 'relative' }}>
            <Search size={12} style={{ position: 'absolute', left: 16, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
            <input
              value={toolSearch}
              onChange={e => setToolSearch(e.target.value)}
              placeholder="Search tools…"
              style={{ width: '100%', background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-secondary)', padding: '5px 8px 5px 26px', fontSize: '0.6875rem', outline: 'none', boxSizing: 'border-box' }}
            />
            {toolSearch && (
              <button onClick={() => setToolSearch('')} style={{ position: 'absolute', right: 14, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 0, display: 'flex' }}>
                <X size={11} />
              </button>
            )}
          </div>

          {/* Special (Logic & AI) nodes */}
          <div>
            <button onClick={() => toggleCat('__logic')}
              style={{ width: '100%', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 10px', color: 'var(--text-muted)', fontSize: '0.6875rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><Cpu size={11} />Logic &amp; AI</span>
              <ChevronDown size={11} style={{ transform: collapsedCats['__logic'] ? 'rotate(-90deg)' : 'none', transition: 'transform 0.15s' }} />
            </button>
            {!collapsedCats['__logic'] && SPECIAL_NODES.map(sn => (
              <div
                key={sn.type}
                draggable
                onDragStart={e => {
                  e.dataTransfer.setData('application/socis-node', JSON.stringify({ type: sn.type, data: { label: sn.label } }));
                }}
                style={{ ...S.libItem, borderLeft: `3px solid ${sn.color}`, background: `color-mix(in srgb, ${sn.color} 6%, transparent)` }}
              >
                <sn.icon size={13} color={sn.color} />
                <span>{sn.label}</span>
              </div>
            ))}
          </div>

          {/* Templates quick-start */}
          <div style={{ borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)' }}>
            <button
              onClick={() => setShowTemplates(v => !v)}
              style={{ width: '100%', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 10px', color: 'var(--text-muted)', fontSize: '0.6875rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}><FileText size={11} />Templates</span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ fontSize: '0.6875rem', background: 'var(--bg-hover)', borderRadius: 'var(--radius-sm)', padding: '1px 4px' }}>{Object.keys(WORKFLOW_PRESETS).length}</span>
                <ChevronDown size={11} style={{ transform: showTemplates ? 'none' : 'rotate(-90deg)', transition: 'transform 0.15s' }} />
              </span>
            </button>
            {showTemplates && (
              <div style={{ padding: '0 8px 8px' }}>
                {Object.entries(WORKFLOW_PRESETS).map(([id, preset]) => {
                  const accent = preset.color ?? 'var(--cyan)';
                  return (
                    <button key={id} onClick={() => handleLoadTemplate(id)} title={`Load "${preset.name}" template`}
                      style={{ width: '100%', background: `color-mix(in srgb, ${accent} 6%, transparent)`, border: `1px solid color-mix(in srgb, ${accent} 19%, transparent)`, borderLeft: `3px solid ${accent}`, borderRadius: 'var(--radius-sm)', marginBottom: 4, padding: '5px 8px', cursor: 'pointer', textAlign: 'left', display: 'flex', flexDirection: 'column', gap: 2 }}>
                      <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--text-primary)' }}>{preset.name}</div>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {preset.duration && <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', background: 'var(--bg-hover)', borderRadius: 'var(--radius-sm)', padding: '1px 4px' }}>{preset.duration}</span>}
                        {preset.category && <span style={{ fontSize: '0.6875rem', fontWeight: 600, background: `color-mix(in srgb, ${accent} 13%, transparent)`, color: accent, borderRadius: 'var(--radius-sm)', padding: '1px 4px' }}>{preset.category}</span>}
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Tool categories */}
          {filteredLibrary.map(cat => (
            <div key={cat.category}>
              <button
                onClick={() => toggleCat(cat.category)}
                style={{ width: '100%', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 10px', color: 'var(--text-muted)', fontSize: '0.6875rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', borderTop: '1px solid var(--border)' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: cat.color }}>
                  <cat.icon size={11} />
                  <span style={{ color: 'var(--text-muted)' }}>{cat.category}</span>
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={{ fontSize: '0.6875rem', background: 'var(--bg-hover)', borderRadius: 'var(--radius-sm)', padding: '1px 4px', color: 'var(--text-muted)' }}>{cat.items.length}</span>
                  <ChevronDown size={11} style={{ transform: collapsedCats[cat.category] ? 'rotate(-90deg)' : 'none', transition: 'transform 0.15s' }} />
                </div>
              </button>
              {!collapsedCats[cat.category] && cat.items.map(item => {
                const risk = RISK_BADGE[item.risk] ?? RISK_BADGE.low;
                return (
                  <div
                    key={item.tool}
                    draggable
                    onDragStart={e => {
                      e.dataTransfer.setData('application/socis-node', JSON.stringify({ type: 'tool', data: { tool: item.tool, label: item.label } }));
                    }}
                    style={{ ...S.libItem, borderLeft: `3px solid ${item.color}`, background: `color-mix(in srgb, ${item.color} 5%, transparent)`, flexDirection: 'column', alignItems: 'flex-start', gap: 3 }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%' }}>
                      <item.icon size={13} color={item.color} style={{ flexShrink: 0 }} />
                      <span style={{ flex: 1, fontWeight: 600, color: 'var(--text-primary)' }}>{item.label}</span>
                      <span style={{ fontSize: 8, fontWeight: 700, padding: '1px 4px', borderRadius: 'var(--radius-sm)', background: risk.bg, color: risk.color, flexShrink: 0 }}>{risk.label}</span>
                    </div>
                    <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', paddingLeft: 19, lineHeight: 1.3 }}>{item.hint}</div>
                  </div>
                );
              })}
            </div>
          ))}

          {/* No search results */}
          {filteredLibrary.length === 0 && (
            <div style={{ padding: '20px 12px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.6875rem' }}>
              No tools match &ldquo;{toolSearch}&rdquo;
            </div>
          )}
        </div>
        )}

        {/* ── CENTER: ReactFlow canvas ── */}
        <div ref={reactFlowWrapper} style={S.canvas}>
          <RunStatusBar nodes={nodes} running={running} />
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onReconnect={onReconnect}
            onReconnectStart={onReconnectStart}
            onReconnectEnd={onReconnectEnd}
            reconnectRadius={20}
            onDrop={onDrop}
            onDragOver={onDragOver}
            onNodeClick={onNodeClick}
            nodeTypes={NODE_TYPES}
            colorMode="system"
            fitView
            style={{ background: 'transparent' }}
            defaultEdgeOptions={{
              style: { stroke: 'var(--cyan)', strokeWidth: 2.5, opacity: 0.75 },
              animated: true,
              type: 'smoothstep',
              markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--cyan)', width: 16, height: 16 },
            }}
          >
            <Background variant={BackgroundVariant.Dots} color="color-mix(in srgb, var(--text-muted) 32%, transparent)" gap={22} size={1.4} />
            <Controls style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} />
            <MiniMap
              style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)' }}
              nodeColor={(n: any) => {
                const tool = n.data?.tool ?? '';
                const color: Record<string, string> = {
                  nmap: 'var(--cyan)', nuclei: 'var(--orange)', metasploit: 'var(--red)',
                  sqlmap: 'var(--red)', ffuf: 'var(--amber)',
                };
                if (n.type === 'start') return 'var(--green)';
                if (n.type === 'condition') return 'var(--amber)';
                if (n.type === 'report') return 'var(--orange)';
                if (n.type === 'llm') return 'var(--purple)';
                return color[tool] ?? 'var(--text-muted)';
              }}
              maskColor="color-mix(in srgb, var(--border) 60%, transparent)"
            />
            {nodes.length === 0 && (
              <Panel position="top-center">
                <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '1.25rem 2rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8125rem', marginTop: 40, maxWidth: 400 }}>
                  <Network size={32} style={{ margin: '0 auto 0.75rem', display: 'block', opacity: 0.2 }} />
                  <div style={{ fontWeight: 700, color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: 6 }}>
                    Build your pentest workflow
                  </div>
                  <div style={{ fontSize: '0.6875rem', marginBottom: 12, lineHeight: 1.7 }}>
                    Drag tools from the left panel · click a template to quick-start
                  </div>
                  <div style={{ fontSize: '0.6875rem', lineHeight: 2, textAlign: 'left', background: 'var(--bg-primary)', borderRadius: 'var(--radius-md)', padding: '10px 14px' }}>
                    <div><span style={{ color: 'var(--green)', fontWeight: 700 }}>Network scan</span> → Start → Nmap → Nuclei → LLM</div>
                    <div><span style={{ color: 'var(--pink)', fontWeight: 700 }}>CVE research</span> → Start (CVE) → CVE Lookup → CISA KEV → EPSS</div>
                    <div><span style={{ color: 'var(--purple)', fontWeight: 700 }}>Threat intel</span> → Start (keyword) → CVE Lookup → PoC Search</div>
                    <div><span style={{ color: 'var(--red)', fontWeight: 700 }}>Full pentest</span> → Start → Nmap → Metasploit Full Chain → Report</div>
                  </div>
                  <div style={{ marginTop: 10, fontSize: '0.6875rem', color: 'var(--text-muted)', opacity: 0.6 }}>
                    Tip: <kbd style={{ background: 'var(--bg-hover)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '1px 4px', fontFamily: 'monospace' }}>Ctrl+S</kbd> to save · Delete key removes selected node
                  </div>
                </div>
              </Panel>
            )}
          </ReactFlow>
        </div>

        {/* RIGHT: node config */}
        <div style={S.right}>
          <NodeConfigPanel
            node={selectedNode}
            onChange={updateNodeData}
            onClose={() => setSelectedNode(null)}
            onDelete={handleDeleteNode}
          />
        </div>
      </div>

      {/* ── Execution log panel (collapsible) ── */}
      {(running || wsLog.length > 0) && (
        <div style={{ ...S.logStrip, height: showLog ? 170 : 34, overflow: 'hidden', transition: 'height 0.2s' }}>
          {/* Header row */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: 22, marginBottom: showLog ? 6 : 0 }}>
            <button onClick={() => setShowLog(v => !v)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-secondary)', padding: 0 }}>
              <Activity size={12} color={running ? 'var(--cyan)' : 'var(--green)'} />
              <span style={{ fontWeight: 700, fontSize: '0.6875rem', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                {running ? 'Executing…' : 'Run Complete'}
              </span>
              <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                {wsLog.filter((e: any) => e.type === 'node_complete').length > 0 && <span style={{ color: 'var(--green)' }}>✓ {wsLog.filter((e: any) => e.type === 'node_complete').length}</span>}
                {wsLog.filter((e: any) => e.type === 'node_failed').length > 0 && <span style={{ color: 'var(--red)', marginLeft: 6 }}>✗ {wsLog.filter((e: any) => e.type === 'node_failed').length}</span>}
              </span>
              <ChevronUp size={11} style={{ transform: showLog ? 'none' : 'rotate(180deg)', transition: 'transform 0.2s' }} />
            </button>
            <div style={{ display: 'flex', gap: 8 }}>
              {runScanId && (
                <button onClick={() => router.push(`/scans/${runScanId}`)}
                  style={{ background: 'none', border: '1px solid var(--cyan)', borderRadius: 'var(--radius-sm)', padding: '1px 8px', color: 'var(--cyan)', fontSize: '0.6875rem', cursor: 'pointer' }}>
                  View Full Results →
                </button>
              )}
              <button onClick={() => { setWsLog([]); setShowLog(false); }}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', display: 'flex', alignItems: 'center' }}>
                <X size={12} />
              </button>
            </div>
          </div>
          {showLog && (
            <div style={{ overflowY: 'auto', height: 130 }}>
              {wsLog.length === 0
                ? <span style={{ color: 'var(--text-muted)', opacity: 0.5 }}>Waiting for events…</span>
                : wsLog.map((ev: any, i: number) => {
                    const nodeData = nodes.find((n: WFNode) => n.id === ev.node_id)?.data;
                    const label = nodeData?.label || ev.tool || ev.node_id;
                    let summary = '';
                    if (ev.type === 'node_complete' && ev.output) {
                      try {
                        const p = JSON.parse(ev.output);
                        const tool = nodeData?.tool ?? '';
                        if (tool === 'cve') summary = `${p.total ?? p.results?.length ?? 0} CVE(s)`;
                        else if (tool === 'cisa_kev' && typeof p.in_kev === 'boolean') summary = p.in_kev ? '🚨 IN KEV' : 'Not in KEV';
                        else if (tool === 'epss') summary = p.epss_score_pct ?? `${((p.epss_score ?? 0) * 100).toFixed(3)}%`;
                        else if (tool === 'poc_index') summary = `${p.count ?? p.exploits?.length ?? 0} PoC(s)`;
                        else if (tool === 'nmap') { const open = (p.hosts ?? []).flatMap((h: any) => (h.ports ?? []).filter((pt: any) => pt.state === 'open')); summary = `${open.length} open port(s)`; }
                        else if (tool === 'nuclei') summary = `${(p.findings ?? p.results ?? []).length} finding(s)`;
                        else if (tool === 'metasploit') summary = p.exploited ? '🔴 Exploited' : p.attempted_modules ? `${p.attempted_modules} modules` : '';
                      } catch {}
                    }
                    return (
                      <div key={i} style={{ marginBottom: 3, display: 'flex', gap: 6, alignItems: 'center', padding: '2px 0', borderBottom: '1px solid color-mix(in srgb, var(--text-primary) 2%, transparent)' }}>
                        <span style={{ color: 'var(--blue)', flexShrink: 0, fontSize: '0.6875rem' }}>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                        <span style={{ flexShrink: 0, fontWeight: 700, color: ev.type === 'node_start' ? 'var(--cyan)' : ev.type === 'node_complete' ? 'var(--green)' : 'var(--red)' }}>
                          {ev.type === 'node_start' ? '▶' : ev.type === 'node_complete' ? '✓' : '✗'}
                        </span>
                        <span style={{ color: 'var(--text-primary)', flex: 1, fontSize: '0.6875rem' }}>{label}</span>
                        {summary && <span style={{ color: ev.type === 'node_complete' ? 'var(--green)' : 'var(--red)', flexShrink: 0, fontSize: '0.6875rem' }}>{summary}</span>}
                        {ev.duration_ms && <span style={{ color: 'var(--blue)', flexShrink: 0, fontSize: '0.6875rem' }}>{(ev.duration_ms / 1000).toFixed(1)}s</span>}
                        {ev.error && <span style={{ color: 'var(--red)', fontSize: '0.6875rem' }}>⚠ {ev.error}</span>}
                      </div>
                    );
                  })
              }
            </div>
          )}
        </div>
      )}

      {/* Run modal */}
      {showRunModal && (
        <div style={{
          position: 'fixed', inset: 0, background: '#000a', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 999,
        }}>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '1.75rem', minWidth: 420, maxWidth: 500 }}>
            <div style={{ fontWeight: 700, fontSize: '0.875rem', color: 'var(--text-primary)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Play size={15} color="var(--green)" /> Run Workflow
            </div>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: 16 }}>
              Target (IP, domain, or CVE ID)
              <input value={runTarget} onChange={e => setRunTarget(e.target.value)}
                placeholder="192.168.1.1 or example.com or CVE-2021-44228"
                autoFocus
                onKeyDown={e => { if (e.key === 'Enter') handleRun(); }}
                style={{ display: 'block', width: '100%', marginTop: 6, background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', padding: '8px 10px', fontSize: '0.8125rem' }} />
            </label>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: 16 }}>
              Project
              <select value={projectId} onChange={e => setProjectId(e.target.value)}
                style={{ display: 'block', width: '100%', marginTop: 6, background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', padding: '8px 10px', fontSize: '0.8125rem' }}>
                <option value="">— Auto (first project) —</option>
                {projects.map((p: any) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
              {projects.length === 0 && (
                <span style={{ color: 'var(--red)', fontSize: '0.6875rem', marginTop: 4, display: 'block' }}>
                  No projects found. <a href="/projects" style={{ color: 'var(--red)' }}>Create one first.</a>
                </span>
              )}
            </label>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button onClick={() => setShowRunModal(false)}
                style={{ padding: '7px 18px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.8125rem' }}>
                Cancel
              </button>
              <button onClick={handleRun}
                disabled={projects.length === 0}
                style={{ padding: '7px 22px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--green)', background: projects.length === 0 ? 'var(--bg-hover)' : 'var(--green)', color: projects.length === 0 ? 'var(--text-muted)' : 'var(--on-accent)', fontWeight: 700, cursor: projects.length === 0 ? 'not-allowed' : 'pointer', fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Play size={13} /> Run
              </button>
            </div>
          </div>
        </div>
      )}

      {/* AI Generate modal */}
      {showGenModal && (
        <div style={{
          position: 'fixed', inset: 0, background: '#000a', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 999,
        }}>
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '1.75rem', minWidth: 480, maxWidth: 560 }}>
            <div style={{ fontWeight: 700, fontSize: '0.875rem', color: 'var(--text-primary)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
              ⚡ Generate Workflow
            </div>

            <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                Describe your workflow
                <button onClick={() => setShowGenHelp(v => !v)} title="View examples"
                  style={{ background: 'none', border: 'none', color: 'var(--cyan)', cursor: 'pointer', padding: 0, display: 'flex', alignItems: 'center' }}>
                  <HelpCircle size={14} />
                </button>
              </div>
              <textarea value={genPrompt} onChange={e => setGenPrompt(e.target.value)}
                placeholder="e.g., Run nmap port scan, then use nuclei to find vulnerabilities. Finally check SSL/TLS config."
                style={{ display: 'block', width: '100%', marginTop: 4, background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', padding: '8px 10px', fontSize: '0.8125rem', minHeight: 80, resize: 'vertical', fontFamily: 'inherit' }} />
            </label>

            {showGenHelp && (
              <div style={{ background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: 12, marginBottom: 12, fontSize: '0.75rem' }}>
                <div style={{ fontWeight: 600, color: 'var(--cyan)', marginBottom: 8 }}>Example prompts:</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {[
                    'nmap scan',
                    'nmap + nuclei scan',
                    'nmap scan + nuclei + whois',
                    'whois lookup + ssl scan',
                    'cve lookup for CVE-2021-44228',
                  ].map((ex, i) => (
                    <button key={i} onClick={() => { setGenPrompt(ex.split(' + ').join(' ')); setShowGenHelp(false); }}
                      style={{ textAlign: 'left', background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: '4px 8px', borderRadius: 'var(--radius-sm)', fontSize: '0.75rem' }}>
                      {i + 1}. {ex}
                    </button>
                  ))}
                </div>
                <div style={{ marginTop: 10, color: 'var(--text-muted)', fontSize: '0.6875rem' }}>
                  Available: nmap, nuclei, osint, whois, ssl, cve, cisa, epss, poc, waf, ffuf, sqlmap, metasploit
                </div>
              </div>
            )}

            <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: 16 }}>
              Target (IP, domain, or CVE ID)
              <input value={genTarget} onChange={e => setGenTarget(e.target.value)}
                placeholder="192.168.1.1 or example.com or CVE-2021-44228"
                style={{ display: 'block', width: '100%', marginTop: 4, background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', padding: '7px 10px', fontSize: '0.8125rem' }} />
            </label>

            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button onClick={() => setShowGenModal(false)}
                style={{ padding: '7px 18px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', background: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.8125rem' }}>
                Cancel
              </button>
              <button onClick={async () => {
                if (!genPrompt.trim()) { notify('Enter a prompt', 'error'); return; }
                setGenerating(true);
                try {
                  const wf = await workflowsApi.generate(genPrompt, genTarget);
                  const wdata = (wf as any).data || wf;
                  setNodes((wdata.nodes || []).map((n: any) => ({ ...n, position: n.position || { x: 200, y: 180 } })));
                  setEdges(wdata.edges || []);
                  setName(wdata.name || 'Generated Workflow');
                  setShowGenModal(false);
                  setSaveMsg('AI Generated!');
                } catch (e) { console.error(e); notify('Failed to generate', 'error'); }
                setGenerating(false);
              }}
                disabled={generating}
                style={{ padding: '7px 22px', borderRadius: 'var(--radius-sm)', border: 'none', background: 'var(--cyan-glow)', color: 'var(--cyan)', fontWeight: 700, cursor: generating ? 'not-allowed' : 'pointer', fontSize: '0.8125rem' }}>
                {generating ? <Loader2 size={13} className="animate-spin" /> : '⚡ Generate'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Public export: wraps with ReactFlowProvider + Suspense ───────────────────

function BuilderWithParams() {
  const params = useSearchParams();
  const workflowId = params.get('id');
  const initialPresetId = params.get('preset');

  return (
    <ReactFlowProvider>
      <BuilderInner workflowId={workflowId} initialPresetId={initialPresetId} />
    </ReactFlowProvider>
  );
}

export default function WorkflowBuilderPage() {
  return (
    <Suspense fallback={
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: 'var(--bg-primary)', color: 'var(--text-muted)' }}>
        Loading builder…
      </div>
    }>
      <BuilderWithParams />
    </Suspense>
  );
}

