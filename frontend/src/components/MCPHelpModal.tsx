'use client';
import { useEffect, useState } from 'react';
import { X, Terminal, Search, Cpu, Zap, Globe, Shield, Database, AlertTriangle, BookOpen, ChevronRight, RefreshCw, Bug, Wifi, Lock, Key, FolderSearch } from 'lucide-react';
import { mcpApi } from '@/lib/api';

interface Props {
  onClose: () => void;
}

// ─── Live data types ──────────────────────────────────────────

interface LiveTool {
  name: string;
  description: string;
  example: string;
}

interface LiveServer {
  server: string;
  url: string;
  status: string;
  tools: LiveTool[];
}

// ─── Static fallback data ─────────────────────────────────────

type SectionItem = {
  icon: React.ElementType;
  color: string;
  title: string;
  description?: string;
  examples: { prompt: string; note: string }[];
};

const STATIC_SECTIONS: SectionItem[] = [
  // ── [SEARCH:] shortcut covers these 4 servers in one call ──────────────
  {
    icon: Search,
    color: 'var(--cyan)',
    title: 'CVE Lookup — NVD (cve_mcp)',
    description: 'Always use [SEARCH: CVE-YYYY-NNNN] — it fetches NVD + KEV + EPSS + PoC in one call.',
    examples: [
      { prompt: '[SEARCH: CVE-2021-44228]', note: 'Full CVE report — NVD details + KEV + EPSS + PoC (preferred)' },
      { prompt: '[MCP: cve_mcp.search_cves {"query":"log4j","limit":10}]', note: 'Keyword search across NVD' },
      { prompt: '[MCP: cve_mcp.get_severity {"cve_id":"CVE-2021-44228"}]', note: 'CVSS score only' },
      { prompt: '[MCP: cve_mcp.cpe_search {"cpe":"cpe:2.3:a:apache:log4j:*"}]', note: 'CVEs by product CPE' },
    ],
  },
  {
    icon: AlertTriangle,
    color: 'var(--red)',
    title: 'CISA KEV — Known Exploited Vulnerabilities (cisa_kev_mcp)',
    description: 'Check if a CVE is actively exploited in the wild with a CISA remediation deadline.',
    examples: [
      { prompt: '[MCP: cisa_kev_mcp.check_kev {"cve_id":"CVE-2021-44228"}]', note: 'Is it in the KEV catalog?' },
      { prompt: '[MCP: cisa_kev_mcp.search_kev {"keyword":"log4j"}]', note: 'Keyword search in KEV' },
      { prompt: '[MCP: cisa_kev_mcp.get_recent_kev {"days":30}]', note: 'CVEs added to KEV in last 30 days' },
      { prompt: '[MCP: cisa_kev_mcp.get_kev_stats {}]', note: 'Overall KEV catalog statistics' },
    ],
  },
  {
    icon: Zap,
    color: 'var(--amber)',
    title: 'EPSS — Exploit Probability Scores (epss_mcp)',
    description: 'Get exploitation probability scores (0–100%) to prioritise patching.',
    examples: [
      { prompt: '[MCP: epss_mcp.get_epss_score {"cve_id":"CVE-2021-44228"}]', note: 'Score + percentile for one CVE' },
      { prompt: '[MCP: epss_mcp.get_epss_scores_bulk {"cve_ids":"CVE-2021-44228,CVE-2023-44487"}]', note: 'Scores for multiple CVEs at once' },
      { prompt: '[MCP: epss_mcp.get_high_epss_cves {"threshold":0.7}]', note: 'CVEs with >70% exploitation probability' },
      { prompt: '[MCP: epss_mcp.epss_priority_analysis {"cve_ids":"CVE-2021-44228,CVE-2023-44487"}]', note: 'Ranked priority list for a set of CVEs' },
    ],
  },
  {
    icon: BookOpen,
    color: 'var(--red)',
    title: 'PoC Index — Public Exploits (poc_mcp)',
    description: 'Search Sploitus, GitHub, and ExploitDB for public Proof-of-Concept exploits.',
    examples: [
      { prompt: '[MCP: poc_mcp.poc_risk_summary {"cve_id":"CVE-2021-44228"}]', note: 'Full PoC risk report — EDB IDs, GitHub repos, top exploits' },
      { prompt: '[MCP: poc_mcp.search_poc {"cve_id":"CVE-2021-44228"}]', note: 'Search all PoC sources' },
      { prompt: '[MCP: poc_mcp.search_github_poc {"cve_id":"CVE-2021-44228"}]', note: 'GitHub repos only' },
      { prompt: '[MCP: poc_mcp.get_exploitdb_entry {"edb_id":50592}]', note: 'Fetch a specific ExploitDB entry by ID' },
    ],
  },
  // ── Active scanning tools ───────────────────────────────────────────────
  {
    icon: Terminal,
    color: 'var(--purple)',
    title: 'Network Scanning (nmap_mcp)',
    description: 'Run Nmap scans against targets. AI picks the right tool based on your request.',
    examples: [
      { prompt: '[MCP: nmap_mcp.nmap_scan {"target":"192.168.1.1","flags":"-sV -O --script=default"}]', note: 'Full custom scan with any nmap flags' },
      { prompt: '[MCP: nmap_mcp.nmap_quick_scan {"target":"192.168.1.1"}]', note: 'Fast top-1000 port scan' },
      { prompt: '[MCP: nmap_mcp.nmap_service_scan {"target":"192.168.1.1"}]', note: 'Service version detection (-sV)' },
      { prompt: '[MCP: nmap_mcp.port_check {"target":"192.168.1.1","port":443}]', note: 'Check if a single specific port is open' },
      { prompt: '[MCP: nmap_mcp.os_detect {"target":"192.168.1.1"}]', note: 'OS fingerprinting (-O)' },
      { prompt: '[MCP: nmap_mcp.nmap_vuln_scan {"target":"192.168.1.1"}]', note: 'NSE vuln scripts (--script=vuln)' },
      { prompt: '[MCP: nmap_mcp.nmap_smb_scan {"target":"192.168.1.1"}]', note: 'SMB enumeration — shares, users, OS' },
      { prompt: '[MCP: nmap_mcp.nmap_http_scan {"target":"192.168.1.1"}]', note: 'HTTP nmap scripts — title, methods, headers' },
    ],
  },
  {
    icon: Globe,
    color: 'var(--cyan)',
    title: 'Web Vulnerability Scanning (nuclei_mcp)',
    description: 'Template-based web vulnerability scanning using Nuclei.',
    examples: [
      { prompt: '[MCP: nuclei_mcp.nuclei_scan {"target":"http://example.com"}]', note: 'Full scan — runs all default templates' },
      { prompt: '[MCP: nuclei_mcp.nuclei_cve_scan {"target":"http://example.com","cve_id":"CVE-2021-44228"}]', note: 'Scan for a specific CVE template' },
      { prompt: '[MCP: nuclei_mcp.nuclei_tech_detect {"target":"http://example.com"}]', note: 'Detect CMS, frameworks, server versions' },
      { prompt: '[MCP: nuclei_mcp.nuclei_exposed_scan {"target":"http://example.com"}]', note: 'Find exposed admin panels, sensitive files' },
      { prompt: '[MCP: nuclei_mcp.nuclei_dns_scan {"target":"example.com"}]', note: 'DNS misconfiguration — zone transfer, takeover' },
      { prompt: '[MCP: nuclei_mcp.nuclei_ssl_scan {"target":"example.com"}]', note: 'SSL/TLS vulnerability templates' },
      { prompt: '[MCP: nuclei_mcp.list_templates {}]', note: 'List all available Nuclei templates' },
    ],
  },
  {
    icon: Database,
    color: 'var(--amber)',
    title: 'OSINT & Passive Recon (osint_mcp)',
    description: 'Passive reconnaissance — no active scanning of the target.',
    examples: [
      { prompt: '[MCP: osint_mcp.whois_lookup {"domain":"example.com"}]', note: 'Registrar, dates, contacts' },
      { prompt: '[MCP: osint_mcp.dns_lookup {"domain":"example.com"}]', note: 'All DNS records — A, MX, NS, TXT, CNAME' },
      { prompt: '[MCP: osint_mcp.http_headers {"url":"http://example.com"}]', note: 'Raw HTTP headers — Server, X-Powered-By, security headers' },
      { prompt: '[MCP: osint_mcp.ip_geolocation {"ip":"8.8.8.8"}]', note: 'Geolocation, ASN, hosting provider' },
      { prompt: '[MCP: osint_mcp.subdomain_enum {"domain":"example.com"}]', note: 'Passive subdomain enum via DNS + cert transparency' },
      { prompt: '[MCP: osint_mcp.ssl_info {"hostname":"example.com"}]', note: 'Certificate — issuer, SANs, validity' },
      { prompt: '[MCP: osint_mcp.tech_fingerprint {"url":"http://example.com"}]', note: 'Technology fingerprinting from headers + response' },
    ],
  },
  {
    icon: Zap,
    color: 'var(--red)',
    title: 'Exploitation & Post-Exploitation (metasploit_mcp)',
    description: 'Search, run, and manage Metasploit modules and active sessions.',
    examples: [
      { prompt: '[MCP: metasploit_mcp.list_exploits {"search_term":"log4j"}]', note: 'Search exploit modules by keyword' },
      { prompt: '[MCP: metasploit_mcp.get_module_info {"module":"exploit/multi/handler"}]', note: 'Options and targets for a module' },
      { prompt: '[MCP: metasploit_mcp.run_auxiliary_module {"module":"scanner/http/http_version","options":{"RHOSTS":"192.168.1.0/24"}}]', note: 'Run an auxiliary scanner' },
      { prompt: '[MCP: metasploit_mcp.list_active_sessions {}]', note: 'Show all open Meterpreter/shell sessions' },
      { prompt: '[MCP: metasploit_mcp.send_session_command {"session_id":1,"command":"sysinfo"}]', note: 'Run a command in an active session' },
      { prompt: '[MCP: metasploit_mcp.start_listener {"payload":"windows/x64/meterpreter/reverse_tcp","lhost":"192.168.1.100","lport":4444}]', note: 'Start a reverse shell listener' },
      { prompt: '[MCP: metasploit_mcp.list_post_modules {}]', note: 'List post-exploitation modules' },
    ],
  },
  {
    icon: Shield,
    color: 'var(--green)',
    title: 'Deep SSL/TLS Analysis (ssl_mcp)',
    description: 'Inspect TLS configuration, certificate chain, and known vulnerabilities.',
    examples: [
      { prompt: '[MCP: ssl_mcp.check_ssl {"hostname":"example.com"}]', note: 'Full TLS audit — cert, chain, ciphers, protocols' },
      { prompt: '[MCP: ssl_mcp.get_ssl_grade {"hostname":"example.com"}]', note: 'Quick SSL grade (A+ / A / B / C / F)' },
      { prompt: '[MCP: ssl_mcp.check_ssl_vulnerabilities {"hostname":"example.com"}]', note: 'Test for Heartbleed, POODLE, BEAST, ROBOT, weak ciphers' },
    ],
  },
  {
    icon: Database,
    color: 'var(--teal)',
    title: 'WAF Detection & Bypass (waf_detection_mcp)',
    description: 'Identify WAF vendors, test payloads, and analyse evasion techniques.',
    examples: [
      { prompt: '[MCP: waf_detection_mcp.fingerprint_waf {"target":"http://example.com"}]', note: 'Identify WAF vendor — Cloudflare, AWS WAF, Akamai, ModSecurity…' },
      { prompt: '[MCP: waf_detection_mcp.test_bypass {"target":"http://example.com","payload":"<script>alert(1)</script>"}]', note: 'Test if a payload bypasses the WAF' },
      { prompt: '[MCP: waf_detection_mcp.analyze_evasion {"target":"http://example.com"}]', note: 'Suggest and test evasion techniques automatically' },
      { prompt: '[MCP: waf_detection_mcp.check_security_headers {"target":"http://example.com"}]', note: 'Check CSP, HSTS, X-Frame-Options, etc.' },
      { prompt: '[MCP: waf_detection_mcp.detect_rate_limit {"target":"http://example.com"}]', note: 'Probe rate-limiting thresholds' },
      { prompt: '[MCP: waf_detection_mcp.test_tls_fingerprint {"target":"example.com"}]', note: 'JA3/JA4 TLS fingerprint detection' },
    ],
  },
  {
    icon: Globe,
    color: 'var(--purple)',
    title: 'Web Fuzzing & Directory Brute-Force (ffuf_mcp)',
    description: 'Fast web directory, parameter, subdomain, and vhost fuzzing.',
    examples: [
      { prompt: '[MCP: ffuf_mcp.ffuf_fuzz {"target":"http://example.com/FUZZ","wordlist":"common"}]', note: 'Directory/path fuzzing — FUZZ marks injection point' },
      { prompt: '[MCP: ffuf_mcp.ffuf_subdomains {"domain":"example.com","wordlist":"subdomains"}]', note: 'Subdomain brute-force' },
      { prompt: '[MCP: ffuf_mcp.ffuf_parameters {"target":"http://example.com/page?FUZZ=test","wordlist":"parameters"}]', note: 'GET/POST parameter name fuzzing' },
      { prompt: '[MCP: ffuf_mcp.ffuf_vhost {"target":"http://example.com","wordlist":"common"}]', note: 'Virtual host header fuzzing' },
      { prompt: '[MCP: ffuf_mcp.ffuf_recursive {"target":"http://example.com/FUZZ","wordlist":"big"}]', note: 'Recursive directory fuzzing' },
      { prompt: '[MCP: ffuf_mcp.ffuf_filter_codes {"target":"http://example.com/FUZZ","wordlist":"common","filter_codes":"404,403"}]', note: 'Fuzz and filter specific HTTP status codes' },
      { prompt: '[MCP: ffuf_mcp.ffuf_list_wordlists {}]', note: 'List all available built-in wordlists' },
    ],
  },
  {
    icon: Database,
    color: 'var(--red)',
    title: 'SQL Injection Testing (sqlmap_mcp)',
    description: 'Detect and exploit SQL injection — runs async, use sqlmap_status to poll.',
    examples: [
      { prompt: '[MCP: sqlmap_mcp.sqlmap_scan {"url":"http://example.com/page?id=1","options":"--level=3 --risk=2"}]', note: 'Run SQLMap — returns scan_id for async results' },
      { prompt: '[MCP: sqlmap_mcp.sqlmap_status {"scan_id":"<id>"}]', note: 'Check if scan is still running' },
      { prompt: '[MCP: sqlmap_mcp.sqlmap_results {"scan_id":"<id>"}]', note: 'Retrieve results of a completed scan' },
      { prompt: '[MCP: sqlmap_mcp.sqlmap_enum_tables {"database":"target_db","scan_id":"<id>"}]', note: 'Enumerate tables after injection confirmed' },
      { prompt: '[MCP: sqlmap_mcp.sqlmap_is_dba {"target":"http://example.com/page?id=1"}]', note: 'Check if DB user has DBA privileges' },
      { prompt: '[MCP: sqlmap_mcp.sqlmap_read_file {"target":"http://example.com/page?id=1","file":"/etc/passwd"}]', note: 'Read a file via SQL injection' },
    ],
  },
  {
    icon: Bug,
    color: 'var(--orange)',
    title: 'Web Server Vulnerability Scanner (nikto_mcp)',
    description: 'Scan web servers for outdated software, dangerous files, misconfigurations, and CVEs.',
    examples: [
      { prompt: '[MCP: nikto_mcp.nikto_scan {"target":"http://example.com"}]', note: 'Full web server vulnerability scan' },
      { prompt: '[MCP: nikto_mcp.nikto_tuning {"target":"http://example.com","tuning":"1234"}]', note: 'Targeted scan: interesting files + injection + misconfig + info disclosure' },
      { prompt: '[MCP: nikto_mcp.nikto_ssl_only {"target":"example.com","port":443}]', note: 'SSL/TLS focused scan — expired certs, weak ciphers, HSTS' },
    ],
  },
  {
    icon: Wifi,
    color: 'var(--cyan)',
    title: 'Fast Port Scanner (masscan_mcp)',
    description: 'Massively fast network port scanner — much faster than nmap for large ranges.',
    examples: [
      { prompt: '[MCP: masscan_mcp.masscan_scan {"target":"192.168.1.1","ports":"1-1024","rate":1000}]', note: 'Scan a host across a port range' },
      { prompt: '[MCP: masscan_mcp.masscan_top_ports {"target":"192.168.1.1","top":1000}]', note: 'Quickly scan top 1000 ports' },
      { prompt: '[MCP: masscan_mcp.masscan_range {"cidr":"192.168.1.0/24","ports":"22,80,443,3389"}]', note: 'Scan an entire subnet for specific ports' },
    ],
  },
  {
    icon: Lock,
    color: 'var(--purple)',
    title: 'WordPress Vulnerability Scanner (wpscan_mcp)',
    description: 'Enumerate WordPress users, plugins, and themes — detect known CVEs via WPVulnDB.',
    examples: [
      { prompt: '[MCP: wpscan_mcp.wp_scan {"url":"https://example.com","enumerate":"u,vp,vt"}]', note: 'Full WP scan — users + vulnerable plugins + themes' },
      { prompt: '[MCP: wpscan_mcp.wp_enum_users {"url":"https://example.com","max_users":25}]', note: 'Enumerate WordPress user accounts' },
      { prompt: '[MCP: wpscan_mcp.wp_enum_plugins {"url":"https://example.com","detection_mode":"aggressive"}]', note: 'Aggressive plugin enumeration with CVE lookups' },
    ],
  },
  {
    icon: Key,
    color: 'var(--amber)',
    title: 'JWT Attack & Analysis (jwt_mcp)',
    description: 'Decode, forge, and test JWT tokens for common vulnerabilities — alg:none, weak secrets.',
    examples: [
      { prompt: '[MCP: jwt_mcp.decode_jwt {"token":"eyJ..."}]', note: 'Decode header + payload without verification' },
      { prompt: '[MCP: jwt_mcp.test_alg_none {"token":"eyJ..."}]', note: 'Test algorithm confusion — alg:none bypass' },
      { prompt: '[MCP: jwt_mcp.test_weak_secret {"token":"eyJ..."}]', note: 'Brute-force weak HMAC signing secret' },
      { prompt: '[MCP: jwt_mcp.forge_jwt {"secret":"found_secret","claims":{"role":"admin"}}]', note: 'Forge a JWT with modified claims using discovered secret' },
    ],
  },
  {
    icon: FolderSearch,
    color: 'var(--green)',
    title: 'Directory & DNS Brute-Force (gobuster_mcp)',
    description: 'Fast directory, subdomain, virtual host, and URL fuzzing with gobuster.',
    examples: [
      { prompt: '[MCP: gobuster_mcp.gobuster_dir {"url":"http://example.com","wordlist":"common"}]', note: 'Directory and file brute-force' },
      { prompt: '[MCP: gobuster_mcp.gobuster_dns {"domain":"example.com","wordlist":"subdomains"}]', note: 'Subdomain enumeration via DNS' },
      { prompt: '[MCP: gobuster_mcp.gobuster_vhost {"url":"http://example.com","domain":"example.com"}]', note: 'Virtual host discovery' },
      { prompt: '[MCP: gobuster_mcp.gobuster_fuzz {"url":"http://example.com/FUZZ","wordlist":"parameters"}]', note: 'Generic URL fuzzing (FUZZ is the injection point)' },
    ],
  },
  {
    icon: Shield,
    color: 'var(--indigo)',
    title: 'MITRE ATT&CK Framework (mitre_mcp)',
    description: 'Query the full MITRE ATT&CK knowledge base — techniques, tactics, groups, software, mitigations.',
    examples: [
      { prompt: '[MCP: mitre_mcp.search_techniques {"query":"phishing"}]', note: 'Search techniques by keyword' },
      { prompt: '[MCP: mitre_mcp.get_technique_by_id {"technique_id":"T1566"}]', note: 'Full technique details by ATT&CK ID' },
      { prompt: '[MCP: mitre_mcp.get_techniques_by_tactic {"tactic":"initial-access"}]', note: 'All techniques for a tactic' },
      { prompt: '[MCP: mitre_mcp.get_techniques_used_by_group {"group_name":"APT29"}]', note: 'TTPs of a specific threat group' },
      { prompt: '[MCP: mitre_mcp.get_mitigations_for_technique {"technique_id":"T1566"}]', note: 'Defences and mitigations' },
      { prompt: '[MCP: mitre_mcp.generate_layer {"techniques":["T1566","T1190"],"name":"My Layer"}]', note: 'Generate ATT&CK Navigator layer JSON' },
    ],
  },
  {
    icon: BookOpen,
    color: 'var(--orange)',
    title: 'Exploit-DB Intelligence (exploitdb_mcp)',
    description: 'Search 47,000+ exploits in the Exploit-DB archive by CVE, platform, type, author, or keyword.',
    examples: [
      { prompt: '[MCP: exploitdb_mcp.search_exploits {"query":"log4j","verified_only":true}]', note: 'Search exploits by keyword' },
      { prompt: '[MCP: exploitdb_mcp.find_by_cve {"cve_id":"CVE-2021-44228"}]', note: 'Find all ExploitDB entries for a CVE' },
      { prompt: '[MCP: exploitdb_mcp.get_exploit {"edb_id":50592}]', note: 'Retrieve full exploit + code by EDB-ID' },
      { prompt: '[MCP: exploitdb_mcp.get_recent_exploits {"days":7}]', note: 'Latest exploits in the past N days' },
      { prompt: '[MCP: exploitdb_mcp.search_by_platform {"platform":"linux","verified_only":true}]', note: 'Linux verified exploits' },
      { prompt: '[MCP: exploitdb_mcp.get_statistics {}]', note: 'Database statistics' },
    ],
  },
  {
    icon: Zap,
    color: 'var(--purple)',
    title: 'Payload Generator (payload_generator_mcp)',
    description: 'Generate CVE-aware exploit payloads and wordlists for SQLi, XSS, RCE, LFI, SSRF, and more.',
    examples: [
      { prompt: '[MCP: payload_generator_mcp.generate_payloads {"vuln_type":"sqli","target":"http://example.com/page?id=1"}]', note: 'SQL injection payloads for a target' },
      { prompt: '[MCP: payload_generator_mcp.generate_payloads {"vuln_type":"rce","cve_id":"CVE-2021-44228","target":"http://target.com"}]', note: 'CVE-specific RCE payload' },
      { prompt: '[MCP: payload_generator_mcp.generate_wordlist {"vuln_type":"xss","count":100}]', note: 'XSS wordlist for fuzzing' },
      { prompt: '[MCP: payload_generator_mcp.list_vuln_types {}]', note: 'List all supported vulnerability types' },
    ],
  },
  {
    icon: Database,
    color: 'var(--pink)',
    title: 'ML Anomaly Detection (anomaly_mcp)',
    description: 'Train and run an Isolation Forest model on network traffic CSV data to detect anomalies.',
    examples: [
      { prompt: '[MCP: anomaly_mcp.anomaly_train {"data_path":"/data/baseline.csv"}]', note: 'Train model on baseline traffic' },
      { prompt: '[MCP: anomaly_mcp.anomaly_score {"data_path":"/data/live_traffic.csv"}]', note: 'Detect anomalies in live traffic' },
      { prompt: '[MCP: anomaly_mcp.anomaly_status {}]', note: 'Check if model is trained and ready' },
    ],
  },
  {
    icon: Lock,
    color: 'var(--teal)',
    title: 'JS/TS Dependency Scanner (cve_lite_mcp)',
    description: 'Scan npm/yarn/pnpm projects for vulnerable dependencies via the OSV advisory database.',
    examples: [
      { prompt: '[MCP: cve_lite_mcp.cve_lite_scan {"project_path":"/projects/my-app"}]', note: 'Full dependency vulnerability scan' },
      { prompt: '[MCP: cve_lite_mcp.cve_lite_scan {"project_path":"/projects/my-app","min_severity":"high","prod_only":true}]', note: 'High-severity production-only scan' },
      { prompt: '[MCP: cve_lite_mcp.cve_lite_advisories_sync {"output_path":"/var/cve-lite/advisories.sqlite3"}]', note: 'Sync OSV DB for offline use' },
    ],
  },
];

// Map server names to icons/colors for live data
const SERVER_STYLE: Record<string, { icon: React.ElementType; color: string }> = {
  cve_mcp:          { icon: Search,        color: 'var(--cyan)' },
  nmap_mcp:         { icon: Terminal,      color: 'var(--purple)' },
  nuclei_mcp:       { icon: Globe,         color: 'var(--cyan)' },
  osint_mcp:        { icon: Database,      color: 'var(--amber)' },
  metasploit_mcp:   { icon: Zap,           color: 'var(--red)' },
  cisa_kev_mcp:     { icon: AlertTriangle, color: 'var(--red)' },
  epss_mcp:         { icon: Zap,           color: 'var(--amber)' },
  poc_mcp:          { icon: BookOpen,      color: 'var(--red)' },
  ssl_mcp:          { icon: Shield,        color: 'var(--green)' },
  waf_detection_mcp:{ icon: Database,      color: 'var(--teal)' },
  ffuf_mcp:         { icon: Globe,         color: 'var(--amber)' },
  sqlmap_mcp:       { icon: Database,      color: 'var(--red)' },
  nikto_mcp:        { icon: Bug,           color: 'var(--orange)' },
  masscan_mcp:      { icon: Wifi,          color: 'var(--cyan)' },
  wpscan_mcp:       { icon: Lock,          color: 'var(--purple)' },
  jwt_mcp:          { icon: Key,           color: 'var(--amber)' },
  gobuster_mcp:     { icon: FolderSearch,  color: 'var(--green)' },
  mitre_mcp:        { icon: Shield,        color: 'var(--indigo)' },
  exploitdb_mcp:    { icon: BookOpen,      color: 'var(--orange)' },
  payload_generator_mcp: { icon: Zap,      color: 'var(--purple)' },
  anomaly_mcp:      { icon: Database,      color: 'var(--pink)' },
  cve_lite_mcp:     { icon: Lock,          color: 'var(--teal)' },
};

function liveToSections(servers: LiveServer[]): SectionItem[] {
  return servers.map((srv) => {
    const style = SERVER_STYLE[srv.server] ?? { icon: Cpu, color: 'var(--text-muted)' };
    const label = srv.server
      .replace(/_mcp$/, '')
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());
    return {
      icon: style.icon,
      color: style.color,
      title: label + (srv.status === 'online' ? '' : ' (offline)'),
      description: `${srv.tools.length} tool${srv.tools.length !== 1 ? 's' : ''} — ${srv.url}`,
      examples: srv.tools.map((t) => ({
        prompt: t.example,
        note: t.description,
      })),
    };
  });
}


const TAG_SYNTAX = [
  { tag: '[SEARCH: CVE-2021-44228]', desc: 'Full CVE report — NVD + KEV + EPSS + PoC in one call' },
  { tag: '[MCP: cve_mcp.search_cves {"query":"log4j"}]', desc: 'Keyword CVE search across NVD' },
  { tag: '[MCP: nmap_mcp.nmap_service_scan {"target":"192.168.1.1"}]', desc: 'Service version scan via Nmap' },
  { tag: '[MCP: nuclei_mcp.nuclei_scan {"target":"http://example.com"}]', desc: 'Web vuln scan via Nuclei templates' },
  { tag: '[MCP: osint_mcp.subdomain_enum {"domain":"example.com"}]', desc: 'Passive subdomain enumeration' },
  { tag: '[MCP: waf_detection_mcp.fingerprint_waf {"target":"http://example.com"}]', desc: 'Detect WAF vendor' },
  { tag: '[MCP: ffuf_mcp.ffuf_fuzz {"target":"http://example.com/FUZZ","wordlist":"common"}]', desc: 'Directory brute-force' },
  { tag: '[MCP: sqlmap_mcp.sqlmap_scan {"url":"http://example.com/page?id=1"}]', desc: 'SQL injection scan' },
  { tag: '[MCP: metasploit_mcp.list_exploits {"search_term":"log4j"}]', desc: 'Search Metasploit modules' },
  { tag: '[MCP: ssl_mcp.check_ssl {"hostname":"example.com"}]', desc: 'Full TLS/certificate audit' },
];

export default function MCPHelpModal({ onClose }: Props) {
  const [sections, setSections] = useState<SectionItem[]>(STATIC_SECTIONS);
  const [loading, setLoading] = useState(true);
  const [liveCount, setLiveCount] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    mcpApi.toolGuide()
      .then((res) => {
        if (cancelled) return;
        const servers: LiveServer[] = res.data?.servers ?? [];
        if (servers.length > 0) {
          setSections(liveToSections(servers));
          setLiveCount(servers.length);
        }
      })
      .catch(() => { /* silently keep static fallback */ })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, zIndex: 1000,
          background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(4px)',
        }}
      />

      {/* Modal */}
      <div style={{
        position: 'fixed', inset: 0, zIndex: 1001,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        padding: '1rem', pointerEvents: 'none',
      }}>
        <div style={{
          pointerEvents: 'all',
          width: '100%', maxWidth: 760, maxHeight: '88vh',
          display: 'flex', flexDirection: 'column',
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)', overflow: 'hidden',
          boxShadow: '0 24px 80px rgba(0,0,0,0.5)',
        }}>

          {/* Header */}
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '1.1rem 1.5rem',
            borderBottom: '1px solid var(--border)',
            background: 'linear-gradient(135deg, color-mix(in srgb, var(--purple) 7%, transparent) 0%, color-mix(in srgb, var(--cyan) 6%, transparent) 100%)',
            flexShrink: 0,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <div style={{
                width: 36, height: 36, borderRadius: 'var(--radius-md)',
                background: 'var(--chart-purple)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                boxShadow: '0 0 12px color-mix(in srgb, var(--purple) 19%, transparent)',
              }}>
                <Cpu size={17} color="white" />
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: '1rem', letterSpacing: '0.01em' }}>MCP Tool Integration Guide</div>
                <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                  {loading
                    ? 'Loading live tool data…'
                    : liveCount !== null
                      ? `${liveCount} server${liveCount !== 1 ? 's' : ''} detected — live data`
                      : 'How to invoke security tools from the AI Chat'}
                </div>
              </div>
            </div>
            <button
              onClick={onClose}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: '0.25rem', borderRadius: 'var(--radius-sm)' }}
            >
              <X size={18} />
            </button>
          </div>

          {/* Scrollable body */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '1.25rem 1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

            {/* How it works banner */}
            <div style={{
              background: 'color-mix(in srgb, var(--purple) 3%, transparent)', border: '1px solid color-mix(in srgb, var(--purple) 15%, transparent)',
              borderRadius: 'var(--radius-lg)', padding: '0.85rem 1.1rem',
              fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.65,
            }}>
              <strong style={{ color: 'var(--text-primary)' }}>How it works:</strong> The AI automatically detects security intents and invokes the
              relevant MCP tools behind the scenes. You can also use explicit tag syntax to call any tool directly.
              Results are fetched live from the tool and synthesized into a professional analysis.
            </div>

            {/* Tag syntax reference */}
            <div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600, marginBottom: '0.6rem' }}>
                Direct Tag Syntax
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                {TAG_SYNTAX.map(({ tag, desc }) => (
                  <div key={tag} style={{
                    display: 'flex', alignItems: 'flex-start', gap: '0.75rem',
                    padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-md)',
                    background: 'var(--bg)', border: '1px solid var(--border)',
                  }}>
                    <code style={{
                      fontSize: '0.75rem', color: 'var(--cyan)', flexShrink: 0,
                      background: 'color-mix(in srgb, var(--cyan) 6%, transparent)', border: '1px solid color-mix(in srgb, var(--cyan) 13%, transparent)',
                      borderRadius: 'var(--radius-sm)', padding: '0.15em 0.4em',
                      fontFamily: 'var(--font-mono, monospace)',
                    }}>{tag}</code>
                    <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', paddingTop: '0.1rem' }}>{desc}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Tool sections */}
            <div>
              <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600, marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                Available MCP Integrations
                {loading && <RefreshCw size={11} color="var(--text-muted)" style={{ animation: 'spin 1s linear infinite' }} />}
                {!loading && liveCount !== null && (
                  <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0, color: 'var(--green)' }}>
                    — {liveCount} live
                  </span>
                )}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {sections.map(({ icon: Icon, color, title, description, examples }) => (
                  <div key={title} style={{
                    border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
                    overflow: 'hidden',
                  }}>
                    {/* Section header */}
                    <div style={{
                      display: 'flex', alignItems: 'center', gap: '0.6rem',
                      padding: '0.65rem 0.9rem',
                      borderBottom: '1px solid var(--border)',
                      background: `color-mix(in srgb, ${color} 3%, transparent)`,
                    }}>
                      <div style={{
                        width: 26, height: 26, borderRadius: 'var(--radius-sm)', flexShrink: 0,
                        background: `color-mix(in srgb, ${color} 13%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 19%, transparent)`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                      }}>
                        <Icon size={13} color={color} />
                      </div>
                      <div>
                        <div style={{ fontWeight: 600, fontSize: '0.8125rem', color: 'var(--text-primary)' }}>{title}</div>
                        {description && <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: 1 }}>{description}</div>}
                      </div>
                    </div>

                    {/* Examples */}
                    <div style={{ padding: '0.6rem 0.9rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                      {examples.map(({ prompt, note }) => (
                        <div key={prompt} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
                          <ChevronRight size={11} color={color} style={{ flexShrink: 0, marginTop: '0.3rem' }} />
                          <div style={{ flex: 1 }}>
                            <code style={{
                              fontSize: '0.75rem', color: 'var(--text-primary)',
                              fontFamily: 'var(--font-mono, monospace)',
                              background: 'var(--bg)', border: '1px solid var(--border)',
                              borderRadius: 'var(--radius-sm)', padding: '0.1em 0.4em',
                              display: 'inline-block', wordBreak: 'break-all',
                            }}>{prompt}</code>
                            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginLeft: '0.4rem' }}>— {note}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Tip footer */}
            <div style={{
              display: 'flex', alignItems: 'flex-start', gap: '0.5rem',
              background: 'color-mix(in srgb, var(--amber) 3%, transparent)', border: '1px solid color-mix(in srgb, var(--amber) 13%, transparent)',
              borderRadius: 'var(--radius-md)', padding: '0.65rem 0.9rem',
              fontSize: '0.75rem', color: 'var(--text-muted)',
            }}>
              <AlertTriangle size={13} color="var(--amber)" style={{ flexShrink: 0, marginTop: 2 }} />
              <span>
                <strong style={{ color: 'var(--amber)' }}>Note:</strong> MCP tools must be enabled in{' '}
                <a href="/settings" style={{ color: 'var(--cyan)', textDecoration: 'underline' }}>Settings → Tools &amp; MCP</a>{' '}
                to be available. Scan targets should be systems you are authorized to test.
              </span>
            </div>
          </div>

          {/* Footer */}
          <div style={{
            borderTop: '1px solid var(--border)', padding: '0.75rem 1.5rem',
            display: 'flex', justifyContent: 'flex-end', flexShrink: 0,
            background: 'var(--bg-card)',
          }}>
            <button onClick={onClose} className="btn btn-primary" style={{ fontSize: '0.8125rem', padding: '0.45rem 1.25rem' }}>
              Got it
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
