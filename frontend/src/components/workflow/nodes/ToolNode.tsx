'use client';
// @ts-ignore
import { Handle, Position, useReactFlow } from '@xyflow/react';
import { Terminal, ChevronDown, ChevronUp } from 'lucide-react';
import { useState } from 'react';
import { NodeHeader, NodeBody, NodeField, statusRingStyle } from './shared';
import MarkdownRenderer from '@/components/MarkdownRenderer';
import type { WFNodeData } from '@/lib/types';

const TOOL_COLORS: Record<string, string> = {
  nmap: 'var(--cyan)', nuclei: 'var(--orange)', metasploit: 'var(--red)',
  sqlmap: 'var(--red)', ffuf: 'var(--amber)',
  cve: 'var(--pink)', ssl: 'var(--teal)', waf: 'var(--indigo)',
  subfinder: 'var(--green)', nikto: 'var(--orange)',
  whois: 'var(--purple)', dig: 'var(--cyan)', whatweb: 'var(--indigo)',
  curl_headers: 'var(--text-secondary)',
  osint: 'var(--teal)',
  cisa_kev: 'var(--orange)', epss: 'var(--amber)', poc_index: 'var(--red)',
  masscan: 'var(--cyan)', wpscan: 'var(--purple)', jwt: 'var(--amber)', gobuster: 'var(--green)',
};

/** Returns the meaningful config rows to display for each tool */
function toolFields(d: WFNodeData): { label: string; value: string }[] {
  const tool = d.tool ?? '';
  const rows: { label: string; value: string }[] = [];

  switch (tool) {
    case 'nmap': {
      const action = d.nmap_action ?? 'nmap_scan';
      rows.push({ label: 'action', value: action });
      if (action === 'nmap_scan') {
        rows.push({ label: 'flags', value: d.nmap_flags ?? d.flags ?? '-sV -sC -T4 --open' });
        if (d.nmap_ports) rows.push({ label: 'ports', value: d.nmap_ports });
      }
      if (action === 'port_check') rows.push({ label: 'port', value: String(d.nmap_check_port ?? 80) });
      break;
    }
    case 'cve': {
      const action = d.cve_action ?? 'search_cves';
      rows.push({ label: 'action', value: action });
      if (action === 'search_cves') {
        rows.push({ label: 'keyword', value: d.cve_keyword || '(target)' });
        if (d.cve_severity) rows.push({ label: 'severity', value: d.cve_severity });
        rows.push({ label: 'limit', value: String(d.cve_limit ?? 20) });
      }
      if ((action === 'lookup_cve' || action === 'get_severity') && d.cve_cve_id)
        rows.push({ label: 'cve', value: d.cve_cve_id });
      if (action === 'cpe_search' && d.cve_cpe)
        rows.push({ label: 'cpe', value: d.cve_cpe });
      break;
    }
    case 'nuclei': {
      const action = d.nuclei_action ?? 'nuclei_scan';
      rows.push({ label: 'action', value: action });
      if (action === 'nuclei_scan') {
        if (d.nuclei_templates) rows.push({ label: 'templates', value: d.nuclei_templates });
        if (d.nuclei_severity) rows.push({ label: 'severity', value: d.nuclei_severity });
      }
      if (action === 'nuclei_cve_scan' && d.nuclei_year)
        rows.push({ label: 'year', value: String(d.nuclei_year) });
      if (action === 'list_templates' && d.nuclei_category)
        rows.push({ label: 'category', value: d.nuclei_category });
      break;
    }
    case 'subfinder':
    case 'whois':
      rows.push({ label: 'domain', value: d.domain || '(target)' });
      break;
    case 'dig':
      rows.push({ label: 'domain', value: d.domain || '(target)' });
      rows.push({ label: 'record', value: d.record_type ?? 'A' });
      break;
    case 'ssl':
      rows.push({ label: 'host', value: d.domain || '(target)' });
      rows.push({ label: 'port', value: String(d.nikto_port ?? 443) });
      break;
    case 'nikto':
      rows.push({ label: 'action', value: d.nikto_action ?? 'nikto_scan' });
      rows.push({ label: 'url', value: d.nikto_url || '(auto)' });
      rows.push({ label: 'port', value: String(d.nikto_port ?? 80) });
      break;
    case 'masscan': {
      const ma = d.masscan_action ?? 'masscan_scan';
      rows.push({ label: 'action', value: ma });
      if (ma === 'masscan_range') rows.push({ label: 'cidr', value: d.masscan_cidr || '(target)' });
      rows.push({ label: 'ports', value: d.masscan_ports || (ma === 'masscan_top_ports' ? `top ${d.masscan_top ?? 1000}` : '1-1024') });
      rows.push({ label: 'rate', value: `${d.masscan_rate ?? 1000} pps` });
      break;
    }
    case 'wpscan': {
      const wa = d.wpscan_action ?? 'wp_scan';
      rows.push({ label: 'action', value: wa });
      rows.push({ label: 'url', value: d.wpscan_url || '(auto)' });
      if (wa === 'wp_scan') rows.push({ label: 'enumerate', value: d.wpscan_enumerate ?? 'u,vp,vt' });
      if (wa === 'wp_enum_plugins' || wa === 'wp_enum_themes') rows.push({ label: 'detection', value: d.wpscan_detection ?? 'mixed' });
      break;
    }
    case 'jwt': {
      const ja = d.jwt_action ?? 'decode_jwt';
      rows.push({ label: 'action', value: ja });
      if (ja === 'forge_jwt') rows.push({ label: 'algorithm', value: d.jwt_algorithm ?? 'HS256' });
      break;
    }
    case 'gobuster': {
      const gm = d.gobuster_mode ?? 'dir';
      rows.push({ label: 'mode', value: gm });
      if (gm === 'dns') rows.push({ label: 'domain', value: d.gobuster_domain || '(required)' });
      else rows.push({ label: 'url', value: d.gobuster_url || '(auto)' });
      rows.push({ label: 'wordlist', value: d.gobuster_wordlist || 'common' });
      if (gm === 'dir' && d.gobuster_extensions) rows.push({ label: 'ext', value: d.gobuster_extensions });
      break;
    }
    case 'waf':
    case 'whatweb': {
      const action = d.waf_action ?? 'fingerprint_waf';
      rows.push({ label: 'action', value: action });
      rows.push({ label: 'url', value: d.waf_url || '(auto)' });
      if (action === 'test_bypass' && d.waf_payload) rows.push({ label: 'payload', value: d.waf_payload });
      if (action === 'analyze_evasion') rows.push({ label: 'attack', value: d.waf_attack_type ?? 'sqli' });
      break;
    }
    case 'ffuf':
      rows.push({ label: 'url', value: d.ffuf_url || '(auto)/FUZZ' });
      if (d.ffuf_extensions) rows.push({ label: 'ext', value: d.ffuf_extensions });
      rows.push({ label: 'method', value: d.ffuf_method ?? 'GET' });
      break;
    case 'sqlmap':
      rows.push({ label: 'url', value: d.sqlmap_url || '(auto)' });
      rows.push({ label: 'level/risk', value: `${d.sqlmap_level ?? 1}/${d.sqlmap_risk ?? 1}` });
      if (d.sqlmap_technique) rows.push({ label: 'technique', value: d.sqlmap_technique });
      break;
    case 'metasploit': {
      const action = d.msf_action ?? 'run_auxiliary';
      rows.push({ label: 'action', value: action });
      if (action === 'run_full_chain') {
        rows.push({ label: 'mode', value: String(d.msf_chain_mode ?? 'balanced') });
        rows.push({ label: 'max', value: String(d.msf_chain_limit ?? 24) });
        rows.push({ label: 'exploit checks', value: (d.msf_chain_exploit_checks ?? true) ? 'yes' : 'no' });
        rows.push({ label: 'post modules', value: (d.msf_chain_post ?? true) ? 'yes' : 'no' });
      }
      if (['run_exploit','run_auxiliary','run_post','get_module_info'].includes(action) && d.msf_module)
        rows.push({ label: 'module', value: d.msf_module });
      if (['run_exploit','generate_payload','start_listener'].includes(action) && d.msf_payload)
        rows.push({ label: 'payload', value: d.msf_payload });
      if (['run_exploit','generate_payload','start_listener'].includes(action) && d.msf_lhost)
        rows.push({ label: 'lhost', value: d.msf_lhost });
      if (['list_exploits','list_payloads'].includes(action) && d.msf_query)
        rows.push({ label: 'query', value: d.msf_query });
      if (['send_command','run_post','terminate_session'].includes(action))
        rows.push({ label: 'session', value: String(d.msf_session_id ?? 1) });
      if (action === 'send_command' && d.msf_command)
        rows.push({ label: 'cmd', value: d.msf_command });
      break;
    }
    case 'osint':
      rows.push({ label: 'fn', value: d.osint_tool || 'whois_lookup' });
      rows.push({ label: 'target', value: d.osint_target || '(target)' });
      if (d.osint_tool === 'dns_lookup') rows.push({ label: 'record', value: d.record_type ?? 'all' });
      break;
    case 'cisa_kev':
      rows.push({ label: 'action', value: d.kev_action || 'check_kev' });
      if (d.kev_action === 'check_kev' || !d.kev_action) rows.push({ label: 'cve', value: d.kev_cve_id || '(required)' });
      if (d.kev_action === 'search_kev') rows.push({ label: 'keyword', value: d.kev_keyword || '(required)' });
      if (d.kev_action === 'get_recent_kev') rows.push({ label: 'days', value: String(d.kev_days ?? 30) });
      break;
    case 'epss':
      rows.push({ label: 'action', value: d.epss_action || 'get_epss_score' });
      if ((d.epss_action ?? 'get_epss_score') === 'get_epss_score') rows.push({ label: 'cve', value: d.epss_cve_id || '(required)' });
      if (d.epss_action === 'get_high_epss_cves') rows.push({ label: 'min score', value: String(d.epss_min_score ?? 0.5) });
      if (d.epss_action === 'get_epss_scores_bulk' || d.epss_action === 'epss_priority_analysis') rows.push({ label: 'cves', value: d.epss_cve_ids ? `${d.epss_cve_ids.split(',').length} CVE(s)` : '(required)' });
      break;
    case 'poc_index':
      rows.push({ label: 'action', value: d.poc_action || 'search_poc' });
      if (d.poc_action === 'search_poc' || d.poc_action === 'get_exploitdb_entry' || !d.poc_action) rows.push({ label: 'query', value: d.poc_query || '(required)' });
      if (d.poc_action === 'search_github_poc' || d.poc_action === 'poc_risk_summary') rows.push({ label: 'cve', value: d.poc_cve_id || '(required)' });
      rows.push({ label: 'limit', value: String(d.poc_limit ?? 10) });
      break;
    default:
      rows.push({ label: 'tool', value: tool });
  }
  return rows;
}

// ── Smart output renderer ──────────────────────────────────────────────────────
function riskColor(label: string): string {
  const l = label?.toUpperCase() ?? '';
  if (l.includes('CRITICAL')) return 'var(--red)';
  if (l.includes('HIGH'))     return 'var(--orange)';
  if (l.includes('MEDIUM'))   return 'var(--amber)';
  return 'var(--green)';
}

function Pill({ text, color }: { text: string; color: string }) {
  return (
    <span style={{
      display: 'inline-block', fontSize: '0.6875rem', fontWeight: 700, letterSpacing: '0.04em',
      padding: '1px 6px', borderRadius: 'var(--radius-lg)',
      background: `color-mix(in srgb, ${color} 13%, transparent)`, color, border: `1px solid color-mix(in srgb, ${color} 33%, transparent)`,
    }}>{text}</span>
  );
}

function SmartOutput({ tool, raw }: { tool: string; raw: string }) {
  const [showRaw, setShowRaw] = useState(false);
  const tryParseJson = (input: string): any => {
    const parseMaybeNested = (txt: string): any => {
      try {
        const p = JSON.parse(txt);
        if (typeof p === 'string') {
          try { return JSON.parse(p); } catch { return p; }
        }
        return p;
      } catch {
        return null;
      }
    };

    const direct = parseMaybeNested(input);
    if (direct && typeof direct === 'object') return direct;

    const trimmed = input.trim();
    if ((trimmed.startsWith("'") && trimmed.endsWith("'")) || (trimmed.startsWith('"') && trimmed.endsWith('"'))) {
      const unwrapped = parseMaybeNested(trimmed.slice(1, -1));
      if (unwrapped && typeof unwrapped === 'object') return unwrapped;
    }

    // Balanced JSON extraction from mixed text/log output
    const extractBalanced = (txt: string, open: string, close: string): any => {
      for (let i = 0; i < txt.length; i++) {
        if (txt[i] !== open) continue;
        let depth = 0;
        let inString = false;
        let quote = '';
        let escaped = false;
        for (let j = i; j < txt.length; j++) {
          const ch = txt[j];
          if (inString) {
            if (escaped) {
              escaped = false;
            } else if (ch === '\\') {
              escaped = true;
            } else if (ch === quote) {
              inString = false;
            }
            continue;
          }
          if (ch === '"' || ch === "'") {
            inString = true;
            quote = ch;
            continue;
          }
          if (ch === open) depth++;
          if (ch === close) depth--;
          if (depth === 0) {
            const candidate = txt.slice(i, j + 1);
            const parsed = parseMaybeNested(candidate);
            if (parsed && typeof parsed === 'object') return parsed;
            break;
          }
        }
      }
      return null;
    };

    const obj = extractBalanced(input, '{', '}');
    if (obj) return obj;
    const arr = extractBalanced(input, '[', ']');
    if (arr) return arr;

    return null;
  };

  const parsed: any = tryParseJson(raw);

  const divider = (
    <div style={{ borderTop: '1px solid var(--border)', marginTop: 6, paddingTop: 6 }} />
  );

  const toMd = (): string => {
    const parseBulkItems = (): any[] => {
      if (!parsed || parsed.mode !== 'bulk' || !Array.isArray(parsed.results)) return [];
      return parsed.results.map((r: any) => {
        const inner = typeof r?.output === 'string' ? tryParseJson(r.output) : r?.output;
        return {
          cve_id: r?.cve_id,
          success: r?.success,
          inner: inner && typeof inner === 'object' ? inner : null,
        };
      });
    };

    // The full detail lines for ONE CVE object — shared by the single-CVE path and each item of the bulk path, so a bulk
    // lookup of 2-3 CVEs shows the same rich detail per CVE as a single lookup (not just id + severity).
    const cveDetailLines = (src: any, indent = ''): string[] => {
      if (!src || typeof src !== 'object') return [];
      const cwes: string[] = Array.isArray(src.cwes) ? src.cwes.filter(Boolean) : [];
      const products: string[] = Array.isArray(src.affected_products) ? src.affected_products.filter(Boolean)
        : Array.isArray(src.affected_cpe) ? src.affected_cpe.filter(Boolean) : [];
      const patchRaw = src.patch_references ?? src.patch_urls ?? [];
      const patches: string[] = (Array.isArray(patchRaw) ? patchRaw : [])
        .map((r: any) => typeof r === 'string' ? r : (r?.url ?? r?.link ?? ''))
        .filter((u: string) => /^https?:\/\//i.test(u)).slice(0, 3);
      const sev = src.severity ?? src.cvss_v3_severity ?? 'unknown';
      const cvss = src.cvss_v3_score ?? src.cvss_score ?? 'n/a';
      const L = (t: string) => `${indent}${t}`;
      return [
        src.severity != null ? L(`- **Severity:** ${String(sev).toUpperCase()}`) : '',
        (src.cvss_score != null || src.cvss_v3_score != null) ? L(`- **CVSS:** ${cvss}${src.cvss_vector ? ` (${src.cvss_vector})` : ''}`) : '',
        src.attack_vector ? L(`- **Attack Vector:** ${src.attack_vector}`) : '',
        src.published ? L(`- **Published:** ${String(src.published).slice(0, 10)}`) : '',
        src.last_modified ? L(`- **Last Modified:** ${String(src.last_modified).slice(0, 10)}`) : '',
        cwes.length ? L(`- **CWE:** ${cwes.slice(0, 4).join(', ')}`) : '',
        src.description ? L(`- **Summary:** ${String(src.description).slice(0, 260)}${String(src.description).length > 260 ? '...' : ''}`) : '',
        products.length ? L(`- **Affected (${products.length}):** ${products.slice(0, 3).map((p: string) => String(p).slice(0, 50)).join('; ')}${products.length > 3 ? ' …' : ''}`) : '',
        patches.length ? L(`- **Patches:** ${patches.length}`) : '',
        src.nvd_url ? L(`- **NVD:** [detail](${src.nvd_url})`) : '',
      ].filter(Boolean);
    };

    // Full detail for ONE CISA-KEV entry — shared by the single and bulk KEV paths.
    const kevDetailLines = (src: any, indent = ''): string[] => {
      if (!src || typeof src !== 'object') return [];
      const L = (t: string) => `${indent}${t}`;
      const inKev = src.in_kev;
      return [
        src.in_kev != null ? L(`- **Status:** ${inKev ? 'In KEV (actively exploited)' : 'Not in KEV'}`) : '',
        src.vendor ? L(`- **Vendor:** ${src.vendor}`) : '',
        src.product ? L(`- **Product:** ${src.product}`) : '',
        src.name ? L(`- **Name:** ${String(src.name).slice(0, 120)}`) : '',
        src.date_added ? L(`- **Date Added:** ${src.date_added}`) : '',
        src.due_date ? L(`- **Due Date:** ${src.due_date}`) : '',
        (src.ransomware_associated != null || src.ransomware_campaign) ? L(`- **Ransomware:** ${src.ransomware_associated || src.ransomware_campaign ? 'Yes' : 'No'}`) : '',
        src.cwe ? L(`- **CWE:** ${Array.isArray(src.cwe) ? src.cwe.slice(0, 3).join(', ') : src.cwe}`) : '',
        src.action_required ? L(`- **Action:** ${String(src.action_required).slice(0, 120)}`) : '',
      ].filter(Boolean);
    };

    // Full detail for ONE EPSS entry — shared by the single and bulk EPSS paths.
    const epssDetailLines = (src: any, indent = ''): string[] => {
      if (!src || typeof src !== 'object') return [];
      const L = (t: string) => `${indent}${t}`;
      const score = Number(src.epss_score);
      const pct = src.epss_score_pct ?? (Number.isFinite(score) ? `${(score * 100).toFixed(3)}%` : null);
      return [
        pct ? L(`- **EPSS:** ${pct}`) : '',
        src.percentile != null ? L(`- **Percentile:** ${(Number(src.percentile) * 100).toFixed(1)}%`) : '',
        src.date ? L(`- **As of:** ${src.date}`) : '',
      ].filter(Boolean);
    };

    if (!parsed) {
      const preview = raw
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 220);
      return [
        '### Output Summary',
        '',
        '- Structured JSON was not detected in this tool response.',
        preview ? `- Preview: ${preview}${raw.length > 220 ? '...' : ''}` : '',
        '- Open **Show raw output** for full details.',
      ].join('\n');
    }

    if (tool === 'cve') {
      const bulkItems = parseBulkItems();
      if (bulkItems.length > 0) {
        const matched = bulkItems.filter((i: any) => i.success !== false).length;
        const sevRank: Record<string, number> = { UNKNOWN: 0, INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
        let highest = 'UNKNOWN';
        let totalMatches = 0;
        for (const item of bulkItems) {
          const p = item.inner ?? {};
          const itemMatches = Number(
            p?.total ?? p?.total_matches ?? p?.totalResults ?? p?.count ??
            (Array.isArray(p?.results) ? p.results.length : 0)
          ) || 0;
          totalMatches += itemMatches;
          const s = String(p?.severity ?? p?.cvss_v3_severity ?? 'UNKNOWN').toUpperCase();
          if ((sevRank[s] ?? 0) > (sevRank[highest] ?? 0)) highest = s;
        }
        // Full detail per CVE (not just id + severity): each bulk item carries its complete CVE object in `inner`.
        const perCve: string[] = [];
        bulkItems.slice(0, 6).forEach((it: any) => {
          const status = it.success === false ? 'failed' : 'ok';
          perCve.push(`- **${it.cve_id ?? 'unknown'}** (${status})`);
          perCve.push(...cveDetailLines(it.inner, '  '));
        });
        if (bulkItems.length > 6) perCve.push(`- … and ${bulkItems.length - 6} more (see Show raw output)`);
        return [
          '### CVE Intelligence',
          '',
          `- **Mode:** Bulk (${bulkItems.length} CVE IDs)`,
          `- **Processed:** ${matched}/${bulkItems.length}`,
          `- **Matches:** ${totalMatches}`,
          `- **Highest Severity:** ${highest}`,
          '',
          ...perCve,
        ].join('\n');
      }

      const isLikelySingle = !!(parsed?.cve_id || parsed?.id || parsed?.cve);
      const listFromKnownKeys: any[] =
        Array.isArray(parsed?.results) ? parsed.results :
        Array.isArray(parsed?.vulnerabilities) ? parsed.vulnerabilities :
        Array.isArray(parsed?.cves) ? parsed.cves :
        Array.isArray(parsed) ? parsed : [];
      const results: any[] = listFromKnownKeys.length > 0 ? listFromKnownKeys : (isLikelySingle ? [parsed] : []);
      const first = results[0];
      const firstCve = first?.cve_id ?? first?.cveID ?? first?.id ?? first?.cve ?? null;
      const total = Number(
        parsed?.total ??
        parsed?.total_matches ??
        parsed?.totalResults ??
        parsed?.count ??
        results.length
      ) || 0;
      const sev = first?.severity ?? first?.cvss_v3_severity ?? parsed?.severity ?? 'unknown';
      const cvss = first?.cvss_v3_score ?? first?.cvss_score ?? parsed?.cvss_score ?? 'n/a';
      const err = parsed?.error ?? parsed?.message ?? '';

      const refsRaw =
        first?.references ?? first?.refs ?? first?.urls ??
        parsed?.references ?? parsed?.refs ?? parsed?.urls ?? [];
      const refsList: string[] = (Array.isArray(refsRaw) ? refsRaw : [])
        .map((r: any) => typeof r === 'string' ? r : (r?.url ?? r?.link ?? r?.href ?? r?.reference ?? ''))
        .filter((u: string) => /^https?:\/\//i.test(u))
        .slice(0, 5);

      // Full detail for the single CVE, via the same shared helper the bulk path uses (so both are consistent).
      const src: any = first ?? parsed ?? {};
      return [
        '### CVE Intelligence',
        '',
        `- **Matches:** ${total}`,
        firstCve ? `- **Top CVE:** ${firstCve}` : '- **Top CVE:** n/a',
        ...cveDetailLines(src),
        err ? `- **Status:** ${err}` : '',
        refsList.length ? '- **References:**' : '',
        ...refsList.map((u, i) => `  - [Reference ${i + 1}](${u})`),
      ].filter(Boolean).join('\n');
    }

    if (tool === 'cisa_kev') {
      const bulkItems = parseBulkItems();
      if (bulkItems.length > 0) {
        const inKev = bulkItems.filter((i: any) => i.inner?.in_kev === true).length;
        const perCve: string[] = [];
        bulkItems.slice(0, 6).forEach((it: any) => {
          const flag = it.inner?.in_kev === true ? '⚠ in KEV' : 'not in KEV';
          perCve.push(`- **${it.cve_id}** (${flag})`);
          perCve.push(...kevDetailLines(it.inner, '  '));
        });
        if (bulkItems.length > 6) perCve.push(`- … and ${bulkItems.length - 6} more`);
        return [
          '### CISA KEV Status',
          '',
          `- **Mode:** Bulk (${bulkItems.length} CVE IDs)`,
          `- **In KEV:** ${inKev} / ${bulkItems.length}`,
          '',
          ...perCve,
        ].filter(Boolean).join('\n');
      }

      const inKev = parsed.in_kev;
      return [
        '### CISA KEV Status',
        '',
        parsed.cve_id ? `- **CVE:** ${parsed.cve_id}` : '',
        ...kevDetailLines(parsed),
      ].filter(Boolean).join('\n');
    }

    if (tool === 'epss') {
      const bulkItems = parseBulkItems();
      if (bulkItems.length > 0) {
        const scores = bulkItems
          .map((i: any) => Number(i.inner?.epss_score))
          .filter((n: number) => Number.isFinite(n));
        const best = scores.length ? Math.max(...scores) : null;
        const avg = scores.length ? scores.reduce((a: number, b: number) => a + b, 0) / scores.length : null;
        // Per-CVE detail (sorted by EPSS, highest first), not just aggregates.
        const perCve: string[] = [];
        bulkItems.slice()
          .sort((a: any, b: any) => (Number(b.inner?.epss_score) || 0) - (Number(a.inner?.epss_score) || 0))
          .slice(0, 6)
          .forEach((it: any) => {
            perCve.push(`- **${it.cve_id}**`);
            perCve.push(...epssDetailLines(it.inner, '  '));
          });
        return [
          '### EPSS Risk',
          '',
          `- **Mode:** Bulk (${bulkItems.length} CVE IDs)`,
          `- **Scored:** ${scores.length}/${bulkItems.length}`,
          `- **Best EPSS:** ${best != null ? `${(best * 100).toFixed(3)}%` : 'N/A'}`,
          `- **Average EPSS:** ${avg != null ? `${(avg * 100).toFixed(3)}%` : 'N/A'}`,
          '',
          ...perCve,
        ].filter(Boolean).join('\n');
      }

      // Native EPSS bulk response shape from get_epss_scores_bulk
      const nativeBulkScores: any[] = Array.isArray(parsed?.scores) ? parsed.scores : [];
      if (nativeBulkScores.length > 0 || Number.isFinite(Number(parsed?.count))) {
        const scored = nativeBulkScores
          .map((s: any) => Number(s?.epss_score))
          .filter((n: number) => Number.isFinite(n));
        const best = scored.length ? Math.max(...scored) : null;
        const avg = scored.length ? scored.reduce((a: number, b: number) => a + b, 0) / scored.length : null;
        const count = Number(parsed?.count);
        const total = Number.isFinite(count) && count > 0 ? count : nativeBulkScores.length;
        return [
          '### EPSS Risk',
          '',
          `- **Mode:** Bulk (${total} CVE IDs)`,
          `- **Scored:** ${scored.length}/${total}`,
          `- **Best EPSS:** ${best != null ? `${(best * 100).toFixed(3)}%` : 'N/A'}`,
          `- **Average EPSS:** ${avg != null ? `${(avg * 100).toFixed(3)}%` : 'N/A'}`,
          '- **Top CVEs by EPSS:**',
          ...nativeBulkScores
            .slice()
            .sort((a: any, b: any) => (Number(b?.epss_score) || 0) - (Number(a?.epss_score) || 0))
            .slice(0, 5)
            .map((s: any) => {
              const cve = s?.cve_id ?? 'unknown';
              const pct = Number.isFinite(Number(s?.epss_score))
                ? `${(Number(s.epss_score) * 100).toFixed(3)}%`
                : 'N/A';
              return `  - ${cve}: ${pct}`;
            }),
        ].join('\n');
      }

      const score = parsed.epss_score;
      const scorePct = parsed.epss_score_pct ?? (score != null ? `${(score * 100).toFixed(3)}%` : 'N/A');
      const percentile = parsed.percentile_pct ?? (parsed.percentile != null ? `${(parsed.percentile * 100).toFixed(1)}%` : 'N/A');
      return [
        '### EPSS Risk',
        '',
        `- **EPSS Score:** ${scorePct}`,
        `- **Percentile:** ${percentile}`,
        parsed.risk_label ? `- **Risk Label:** ${parsed.risk_label}` : '',
      ].filter(Boolean).join('\n');
    }

    if (tool === 'poc_index') {
      const resolveUrl = (p: any): string => {
        if (typeof p?.url === 'string' && /^https?:\/\//i.test(p.url)) return p.url;
        if (typeof p?.html_url === 'string' && /^https?:\/\//i.test(p.html_url)) return p.html_url;
        if (typeof p?.github_url === 'string' && /^https?:\/\//i.test(p.github_url)) return p.github_url;
        if (typeof p?.link === 'string' && /^https?:\/\//i.test(p.link)) return p.link;
        if (p?.edb_id) return `https://www.exploit-db.com/exploits/${String(p.edb_id).replace(/^EDB-/i, '')}`;
        return '';
      };

      const bulkItems = parseBulkItems();
      if (bulkItems.length > 0) {
        let totalFindings = 0;
        const lines: string[] = ['### Public PoC Exposure', ''];
        lines.push(`- **Mode:** Bulk (${bulkItems.length} CVE IDs)`);
        lines.push('');
        for (const item of bulkItems) {
          const p = item.inner ?? {};
          const exploits: any[] = Array.isArray(p?.exploits) ? p.exploits.filter((e: any) => !e?.error && !e?.message) : [];
          const ghRepos: any[] = Array.isArray(p?.github_poc_repos) ? p.github_poc_repos.filter((e: any) => !e?.error) : [];
          const allFindings = [...exploits, ...ghRepos];
          totalFindings += allFindings.length;
          const badge = allFindings.length > 0 ? `⚠ ${allFindings.length} PoC${allFindings.length !== 1 ? 's' : ''}` : '✓ No PoC';
          lines.push(`- **${item.cve_id ?? 'unknown'}** — ${badge}`);
          for (const e of allFindings.slice(0, 4)) {
            const title = e?.title ?? e?.repo ?? e?.edb_id ?? 'PoC';
            const url = resolveUrl(e);
            const stars = typeof e?.stars === 'number' && e.stars > 0 ? ` ⭐${e.stars}` : '';
            const src = e?.type === 'GitHub PoC' || e?.repo ? '[GitHub]' : '[ExploitDB]';
            lines.push(url ? `  - ${src} [${title}](${url})${stars}` : `  - ${src} ${title}${stars}`);
          }
          if (allFindings.length > 4) lines.push(`  - *…and ${allFindings.length - 4} more*`);
        }
        lines.push('');
        lines.push(`- **Total Findings:** ${totalFindings}`);
        return lines.join('\n');
      }

      const listFromKnownKeys: any[] =
        Array.isArray(parsed?.exploits) ? parsed.exploits :
        Array.isArray(parsed?.github_poc_repos) ? parsed.github_poc_repos :
        Array.isArray(parsed?.top_exploits) ? parsed.top_exploits :
        Array.isArray(parsed?.top_github_repos) ? parsed.top_github_repos :
        Array.isArray(parsed) ? parsed : [];
      const hasSingleExploitShape = !!(parsed?.url || parsed?.title || parsed?.edb_id || parsed?.repo);
      const exploits: any[] = listFromKnownKeys.length > 0 ? listFromKnownKeys : (hasSingleExploitShape ? [parsed] : []);
      const count = Number(parsed?.count ?? parsed?.total_found ?? parsed?.github_poc_repos?.length ?? exploits.length) || 0;
      // Filter out error/message-only objects; keep real exploits + search_url fallbacks
      const validTop = exploits.filter((e: any) => !e?.error && !e?.message);
      const fallbackSearchUrl: string | null = exploits.find((e: any) => e?.search_url)?.search_url ?? null;
      const top = validTop.slice(0, 5);

      const resolveSingleUrl = (p: any): string => {
        if (typeof p?.url === 'string' && /^https?:\/\//i.test(p.url)) return p.url;
        if (typeof p?.html_url === 'string' && /^https?:\/\//i.test(p.html_url)) return p.html_url;
        if (typeof p?.github_url === 'string' && /^https?:\/\//i.test(p.github_url)) return p.github_url;
        if (typeof p?.link === 'string' && /^https?:\/\//i.test(p.link)) return p.link;
        if (typeof p?.reference === 'string' && /^https?:\/\//i.test(p.reference)) return p.reference;
        if (p?.edb_id) return `https://www.exploit-db.com/exploits/${String(p.edb_id).replace(/^EDB-/i, '')}`;
        return '';
      };

      return [
        '### Public PoC Exposure',
        '',
        `- **Findings:** ${top.length}`,
        parsed?.source ? `- **Source:** ${parsed.source}` : '',
        parsed?.query ? `- **Query:** \`${parsed.query}\`` : '',
        top.length
          ? '- **References:**'
          : fallbackSearchUrl
            ? `- *Not in local DB — [Search ExploitDB](${fallbackSearchUrl})*`
            : '- *No PoC exploits found for this query*',
        ...top.map((p: any, i: number) => {
          const title = p?.title ?? p?.repo ?? p?.id ?? p?.edb_id ?? `PoC ${i + 1}`;
          const url = resolveSingleUrl(p);
          const stars = typeof p?.stars === 'number' && p.stars > 0 ? ` ⭐${p.stars}` : '';
          const verified = p?.verified ? ' ✓' : '';
          const srcTag = p?.type === 'GitHub PoC' || p?.repo ? '[GitHub]' : '[ExploitDB]';
          const dateStr = p?.date ? ` (${String(p.date).slice(0, 10)})` : '';
          return url
            ? `  - ${srcTag} [${title}](${url})${stars}${verified}${dateStr}`
            : `  - ${srcTag} ${title}${stars}${verified}${dateStr}`;
        }),
      ].filter(Boolean).join('\n');
    }

    if (tool === 'sqlmap' || tool === 'sqlmap_full') {
      const vulnerable = parsed.vulnerable === true || parsed.injectable === true;
      const isFullChain = tool === 'sqlmap_full' || parsed.phase === 'complete';
      const injections: string[] = Array.isArray(parsed.injections) ? parsed.injections : [];
      const params: string[] = Array.isArray(parsed.parameters) ? parsed.parameters : [];
      const databases: string[] = Array.isArray(parsed.databases) ? parsed.databases : [];
      const tables: string[] = Array.isArray(parsed.tables) ? parsed.tables : [];
      const users: string[] = Array.isArray(parsed.users) ? parsed.users : [];
      const statusIcon = vulnerable ? '⚠️ VULNERABLE' : '✓ Not Vulnerable';
      const currentDb = parsed.current_db || parsed.db_enumerated || '';
      return [
        isFullChain ? '### SQL Injection Full Chain' : '### SQL Injection Analysis',
        '',
        `- **Status:** ${statusIcon}`,
        `- **Target:** ${parsed.target ?? '—'}`,
        isFullChain && parsed.phase === 'complete' ? '- **Mode:** Full Chain ✓ (auto-enumerated)' : '',
        parsed.dbms ? `- **DBMS:** ${parsed.dbms}` : '',
        currentDb ? `- **Current DB:** ${currentDb}` : '',
        parsed.current_user ? `- **User:** ${parsed.current_user}` : '',
        parsed.is_dba ? '- **DBA:** ⚠️ Yes (elevated privileges!)' : '',
        params.length ? `- **Injectable Params:** ${params.slice(0, 5).join(', ')}` : '',
        databases.length ? `- **Databases (${databases.length}):** ${databases.slice(0, 8).join(', ')}${databases.length > 8 ? '...' : ''}` : '',
        tables.length ? `- **Tables in ${currentDb || 'DB'} (${tables.length}):** ${tables.slice(0, 8).join(', ')}${tables.length > 8 ? '...' : ''}` : '',
        users.length ? `- **DB Users:** ${users.slice(0, 6).join(', ')}` : '',
        injections.length ? '- **Injections:**' : '',
        ...injections.slice(0, 4).map((i: string) => `  - ${i.slice(0, 120)}`),
        !vulnerable && parsed.message ? `- **Info:** ${parsed.message}` : '',
      ].filter(Boolean).join('\n');
    }

    if (tool === 'metasploit') {
      const sessions: any[] = Array.isArray(parsed.sessions_opened) ? parsed.sessions_opened : [];
      const failed: any[] = Array.isArray(parsed.failed_modules) ? parsed.failed_modules : [];
      const sessionDetails: any[] = Array.isArray(parsed.session_details) ? parsed.session_details : [];
      const mode = parsed.mode ?? 'single-module';

      // ── send_command: show the command + its output ──────────────────────
      if (mode === 'send_command') {
        return [
          '### Metasploit: Session Command',
          '',
          `- **Session:** ${parsed.session_id ?? parsed.session ?? '—'}`,
          `- **Command:** \`${parsed.command ?? '—'}\``,
          `- **Session Alive:** ${parsed.has_session ? 'Yes' : 'No'}`,
          parsed.output ? `- **Output:**\n\`\`\`\n${String(parsed.output).slice(0, 600)}\n\`\`\`` : '',
        ].filter(Boolean).join('\n');
      }

      // ── list_sessions: show each active session ──────────────────────────
      if (mode === 'list_sessions') {
        const lines = sessionDetails.map((s: any) =>
          `  - Session **${s.id}** (${s.type ?? '—'}) — ${s.tunnel_peer || '—'} via \`${(s.via_exploit ?? '').split('/').pop() || '—'}\``
        );
        return [
          '### Active Metasploit Sessions',
          '',
          `- **Active Sessions:** ${sessionDetails.length}`,
          ...lines,
        ].filter(Boolean).join('\n');
      }

      // ── list_listeners: show jobs + sessions ─────────────────────────────
      if (mode === 'list_listeners') {
        const jobLines = Object.entries(parsed.jobs ?? {}).map(
          ([id, name]: [string, any]) => `  - Job **${id}**: ${name}`
        );
        const sessLines = Object.entries(parsed.sessions ?? {}).map(
          ([id, info]: [string, any]) =>
            `  - Session **${id}** (${info?.type ?? '—'}) — ${info?.tunnel_peer ?? '—'}`
        );
        return [
          '### Active Listeners & Sessions',
          '',
          `- **Jobs:** ${parsed.job_count ?? 0}`,
          ...jobLines,
          `- **Sessions:** ${parsed.session_count ?? 0}`,
          ...sessLines,
        ].filter(Boolean).join('\n');
      }

      // ── Default: run_exploit / run_full_chain / run_auxiliary ─────────────
      return [
        '### Metasploit Execution',
        '',
        `- **Mode:** ${mode}`,
        parsed.target ? `- **Target:** ${parsed.target}` : '',
        parsed.open_ports ? `- **Open Ports:** ${Array.isArray(parsed.open_ports) ? parsed.open_ports.join(', ') : String(parsed.open_ports)}` : '',
        parsed.attempted_modules != null ? `- **Modules Attempted:** ${parsed.attempted_modules}` : '',
        parsed.successful_modules != null ? `- **Modules Succeeded:** ${parsed.successful_modules}` : '',
        `- **Session Opened:** ${sessions.length > 0 || parsed.has_session ? 'Yes' : 'No'}`,
        sessions.length ? `- **Sessions:** ${sessions.join(', ')}` : '',
        parsed.payload_used && parsed.payload_used !== parsed.payload_requested
          ? `- **Payload Used:** ${parsed.payload_used} *(requested: ${parsed.payload_requested})*` : '',
        parsed.payload_warning ? `- ⚠️ **Payload Warning:** ${parsed.payload_warning}` : '',
        failed.length ? `- **Failed Modules:** ${failed.slice(0, 8).join(', ')}${failed.length > 8 ? '...' : ''}` : '',
      ].filter(Boolean).join('\n');
    }

    if (tool === 'nmap') {
      // Nmap MCP server returns {target, host_up, open_ports: [{port, protocol, service, version}], os_guess}
      const portList: any[] = parsed.open_ports ?? [];
      const openPorts: string[] = portList.map((p: any) => {
        const ver = p.version ? ` ${p.version}` : '';
        return `${p.port}/${p.protocol ?? 'tcp'} — ${p.service ?? 'unknown'}${ver}`;
      });
      return [
        '### Network Exposure',
        '',
        `- **Target:** ${parsed.target ?? '—'}`,
        `- **Host Up:** ${parsed.host_up === true ? '✓ Yes' : parsed.host_up === false ? '✗ No' : '—'}`,
        `- **Open Ports:** ${openPorts.length}`,
        parsed.os_guess ? `- **OS Guess:** ${parsed.os_guess}` : '',
        openPorts.length ? '- **Ports:**' : '',
        ...openPorts.map((p) => `  - ${p}`),
      ].filter(Boolean).join('\n');
    }

    if (tool === 'masscan') {
      // Masscan MCP returns {target/cidr, open_ports: [{port, protocol, ip, state, service}], ...}
      const portList: any[] = Array.isArray(parsed.open_ports) ? parsed.open_ports : [];
      const openPorts: string[] = portList.map((p: any) => {
        const port = p?.port ?? '?';
        const proto = p?.protocol ?? 'tcp';
        const svc = p?.service ?? 'unknown';
        const ip = p?.ip ? ` @ ${p.ip}` : '';
        return `${port}/${proto} — ${svc}${ip}`;
      });

      return [
        '### Fast Port Discovery',
        '',
        parsed.target ? `- **Target:** ${parsed.target}` : '',
        parsed.cidr ? `- **CIDR:** ${parsed.cidr}` : '',
        parsed.ports ? `- **Port Scope:** ${parsed.ports}` : '',
        parsed.top_ports_requested ? `- **Top Ports Requested:** ${parsed.top_ports_requested}` : '',
        parsed.rate ? `- **Rate:** ${parsed.rate} pps` : '',
        `- **Open Ports:** ${openPorts.length}`,
        openPorts.length ? '- **Ports / Services:**' : '',
        ...openPorts.map((p) => `  - ${p}`),
      ].filter(Boolean).join('\n');
    }

    if (tool === 'nuclei') {
      const findings: any[] = parsed.findings ?? parsed.results ?? parsed.vulnerabilities ?? [];
      const bySeverity: Record<string, number> = {};
      findings.forEach((f: any) => {
        const s = String(f.severity ?? 'info').toLowerCase();
        bySeverity[s] = (bySeverity[s] ?? 0) + 1;
      });
      return [
        '### Vulnerability Findings',
        '',
        `- **Total Findings:** ${findings.length}`,
        ...Object.entries(bySeverity).map(([s, n]) => `- **${s.toUpperCase()}:** ${n}`),
      ].join('\n');
    }

    if (tool === 'cve_lite') {
      const findings: any[] = parsed.findings ?? [];
      const SEV_ICON: Record<string, string> = {
        critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪',
      };
      const bySeverity: Record<string, any[]> = {};
      findings.forEach((f: any) => {
        const s = String(f.severity ?? 'info').toLowerCase();
        (bySeverity[s] = bySeverity[s] ?? []).push(f);
      });
      const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
      const findingLines: string[] = [];
      for (const sev of sevOrder) {
        const group = bySeverity[sev] ?? [];
        if (!group.length) continue;
        findingLines.push(`**${SEV_ICON[sev] ?? '•'} ${sev.toUpperCase()} (${group.length})**`);
        group.slice(0, 5).forEach((f: any) => {
          const pkg = `${f.package ?? '?'}@${f.version ?? '?'}`;
          const aliases: string[] = Array.isArray(f.aliases) ? f.aliases : [];
          const cveId = aliases.find((a: string) => a.startsWith('CVE-')) ?? aliases[0] ?? '';
          const fix = f.fixedIn ? ` → fix: ${f.fixedIn}` : '';
          findingLines.push(`  - \`${pkg}\`${cveId ? ` — ${cveId}` : ''}${fix}`);
        });
        if (group.length > 5) findingLines.push(`  - *…and ${group.length - 5} more*`);
      }
      const fixCmd = parsed.suggested_fix_commands?.command ?? '';
      return [
        '### Dependency Vulnerability Scan',
        '',
        `- **Project:** \`${parsed.project_path ?? '—'}\``,
        `- **Packages Scanned:** ${parsed.package_count ?? '—'}`,
        `- **Vulnerabilities Found:** ${parsed.finding_count ?? findings.length}`,
        `- **Source:** ${parsed.source ?? '—'} (${parsed.mode ?? '—'})`,
        parsed.threshold_reached ? `- **⚠️ Fail Threshold Reached:** ${parsed.fail_on_severity?.toUpperCase()} or above` : '',
        '',
        ...findingLines,
        fixCmd ? '' : '',
        fixCmd ? `**Suggested Fix:**` : '',
        fixCmd ? `\`\`\`\n${fixCmd}\n\`\`\`` : '',
      ].filter(v => v !== undefined).join('\n');
    }

    if (tool === 'osint') {
      const fn = parsed.fn ?? parsed.tool ?? parsed.function ?? '';

      // whois_lookup → {target, fields, raw}
      if (parsed.fields || parsed.raw?.includes('Registrar')) {
        const f = parsed.fields ?? {};
        const ns: string[] = Array.isArray(f['Name Server']) ? f['Name Server'] : f['Name Server'] ? [f['Name Server']] : [];
        return [
          '### WHOIS Lookup',
          '',
          `- **Target:** ${parsed.target ?? '—'}`,
          f['Registrar'] ? `- **Registrar:** ${f['Registrar']}` : '',
          f['Creation Date'] ? `- **Created:** ${f['Creation Date']}` : '',
          f['Updated Date'] ? `- **Updated:** ${f['Updated Date']}` : '',
          f['Expiry Date'] ? `- **Expires:** ${f['Expiry Date']}` : '',
          f['Registrant Email'] ? `- **Registrant Email:** ${f['Registrant Email']}` : '',
          ns.length ? `- **Name Servers:** ${ns.slice(0, 4).join(', ')}` : '',
        ].filter(Boolean).join('\n');
      }

      // dns_lookup → {domain, records}
      if (parsed.domain && parsed.records) {
        const rec = parsed.records as Record<string, string[]>;
        const lines: string[] = ['### DNS Records', '', `- **Domain:** ${parsed.domain}`];
        for (const [type, vals] of Object.entries(rec)) {
          if (type.startsWith('_')) continue;
          const list = (vals as string[]).slice(0, 5);
          lines.push(`- **${type}:** ${list.join(', ')}${(vals as string[]).length > 5 ? ` … +${(vals as string[]).length - 5}` : ''}`);
        }
        return lines.filter(Boolean).join('\n');
      }

      // http_headers → {url, status_code, headers, redirect_count}
      if (parsed.status_code != null && parsed.headers) {
        const h = parsed.headers as Record<string, string>;
        const security = ['x-frame-options','content-security-policy','strict-transport-security',
          'x-content-type-options','x-xss-protection','permissions-policy'];
        const missing = security.filter(s => !Object.keys(h).find(k => k.toLowerCase() === s));
        return [
          '### HTTP Headers',
          '',
          `- **URL:** ${parsed.url}`,
          `- **Status:** ${parsed.status_code}`,
          `- **Redirects:** ${parsed.redirect_count ?? 0}`,
          h.server ? `- **Server:** ${h.server}` : '',
          h['x-powered-by'] ? `- **Powered By:** ${h['x-powered-by']}` : '',
          h['content-type'] ? `- **Content-Type:** ${h['content-type']}` : '',
          missing.length ? `- **Missing Security Headers (${missing.length}):** ${missing.join(', ')}` : '- **Security Headers:** All common headers present',
        ].filter(Boolean).join('\n');
      }

      // ip_geolocation → {ip, country, region, city, org, timezone, loc}
      if (parsed.ip && parsed.country != null) {
        return [
          '### IP Geolocation',
          '',
          `- **IP:** ${parsed.ip}`,
          parsed.hostname ? `- **Hostname:** ${parsed.hostname}` : '',
          `- **Location:** ${[parsed.city, parsed.region, parsed.country].filter(Boolean).join(', ')}`,
          parsed.org ? `- **ASN / Org:** ${parsed.org}` : '',
          parsed.timezone ? `- **Timezone:** ${parsed.timezone}` : '',
          parsed.loc ? `- **Coordinates:** ${parsed.loc}` : '',
        ].filter(Boolean).join('\n');
      }

      // subdomain_enum → {domain, total, subdomains}
      if (parsed.domain && parsed.subdomains != null) {
        const subs: string[] = Array.isArray(parsed.subdomains) ? parsed.subdomains : [];
        return [
          '### Subdomain Enumeration',
          '',
          `- **Domain:** ${parsed.domain}`,
          `- **Total Found:** ${parsed.total ?? subs.length}`,
          subs.length ? '- **Subdomains:**' : '',
          ...subs.slice(0, 15).map((s: string) => `  - ${s}`),
          subs.length > 15 ? `  - *…and ${subs.length - 15} more*` : '',
        ].filter(Boolean).join('\n');
      }

      // ssl_info → {domain, port, subject, issuer, expires, issued, raw}
      if (parsed.domain && parsed.port != null) {
        return [
          '### SSL Certificate Info',
          '',
          `- **Host:** ${parsed.domain}:${parsed.port}`,
          parsed.subject ? `- **Subject:** ${parsed.subject}` : '',
          parsed.issuer ? `- **Issuer:** ${parsed.issuer}` : '',
          parsed.issued ? `- **Issued:** ${parsed.issued}` : '',
          parsed.expires ? `- **Expires:** ${parsed.expires}` : '',
        ].filter(Boolean).join('\n');
      }

      // tech_fingerprint → {url, technologies, headers, ...}
      if (parsed.url && (parsed.technologies || parsed.tech)) {
        const techs: string[] = Array.isArray(parsed.technologies) ? parsed.technologies :
          Array.isArray(parsed.tech) ? parsed.tech : [];
        return [
          '### Technology Fingerprint',
          '',
          `- **URL:** ${parsed.url}`,
          parsed.status_code ? `- **Status:** ${parsed.status_code}` : '',
          techs.length ? `- **Detected (${techs.length}):** ${techs.slice(0, 10).join(', ')}` : '- **Detected:** nothing identified',
        ].filter(Boolean).join('\n');
      }
    }

    if (tool === 'ssl') {
      const GRADE_COLOR: Record<string, string> = {
        A: 'var(--green)', 'A+': 'var(--green)', 'A-': 'var(--green)',
        B: 'var(--amber)', C: 'var(--orange)', D: 'var(--red)',
        E: 'var(--red)', F: 'var(--red)', T: 'var(--text-secondary)',
      };
      const grade = String(parsed.grade ?? 'N/A');
      const gradeColor = GRADE_COLOR[grade] ?? 'var(--text-secondary)';
      const vulns: Record<string, boolean> = parsed.vulnerabilities ?? {};
      const vulnerableItems: string[] = Object.entries(vulns)
        .filter(([, v]) => v === true)
        .map(([k]) => k.toUpperCase());
      const cleanItems: string[] = Object.entries(vulns)
        .filter(([, v]) => v === false)
        .map(([k]) => k.toUpperCase());

      // check_ssl_vulnerabilities shape (has vulnerable_items field)
      if (parsed.vulnerable_items != null) {
        const vulnList: string[] = Array.isArray(parsed.vulnerable_items) ? parsed.vulnerable_items : [];
        const status = parsed.vulnerable ? '⚠️ VULNERABLE' : '✓ Clean';
        return [
          '### SSL/TLS Vulnerability Scan',
          '',
          `- **Host:** ${parsed.host ?? '—'}`,
          parsed.ip ? `- **IP:** ${parsed.ip}` : '',
          parsed.grade ? `- **Grade:** ${parsed.grade}` : '',
          `- **Status:** ${status}`,
          `- **Vulnerable Count:** ${parsed.vulnerable_count ?? vulnList.length}`,
          vulnList.length ? `- **⚠️ Vulnerable:** ${vulnList.map(v => v.toUpperCase()).join(', ')}` : '',
          !parsed.vulnerable ? '- **All checks passed — no known TLS vulnerabilities detected.**' : '',
        ].filter(Boolean).join('\n');
      }

      // check_ssl main shape
      const hsts = String(parsed.hsts ?? 'absent');
      const hstsOk = hsts === 'present' || hsts === 'set';
      return [
        '### SSL/TLS Assessment',
        '',
        `- **Host:** ${parsed.host ?? '—'}`,
        `- **IP:** ${parsed.ip ?? '—'}`,
        `- **Grade:** **${grade}**` + (gradeColor !== 'var(--text-secondary)' ? ` (${grade.startsWith('A') ? '✓ Good' : grade === 'B' ? '⚠ Fair' : '✗ Poor'})` : ''),
        `- **Status:** ${parsed.status ?? '—'}`,
        parsed.protocol ? `- **Protocol:** ${parsed.protocol}` : '',
        parsed.key_exchange && parsed.key_exchange !== '?' ? `- **Key Exchange:** ${parsed.key_exchange}` : '',
        parsed.cipher_strength != null ? `- **Cipher Strength:** ${parsed.cipher_strength} bit` : '',
        `- **Forward Secrecy:** ${parsed.forward_secrecy ? '✓ Yes' : '✗ No'}`,
        `- **HSTS:** ${hstsOk ? '✓ ' : '✗ '}${hsts}${parsed.hsts_max_age ? ` (max-age: ${parsed.hsts_max_age}s)` : ''}`,
        parsed.hsts_preload ? '- **HSTS Preload:** ✓ Yes' : '',
        vulnerableItems.length
          ? `- **⚠️ Vulnerable:** ${vulnerableItems.join(', ')}`
          : '- **Vulnerabilities:** ✓ None detected',
        cleanItems.length && vulnerableItems.length
          ? `- **Clean checks:** ${cleanItems.join(', ')}`
          : '',
        parsed.endpoints_count != null && parsed.endpoints_count > 1
          ? `- **Endpoints:** ${parsed.endpoints_count} (grades: ${(parsed.all_grades ?? []).join(', ')})`
          : '',
        parsed.error ? `- **Error:** ${parsed.error}` : '',
      ].filter(Boolean).join('\n');
    }

    // gobuster_dir / gobuster_dns / gobuster_vhost / gobuster_fuzz
    if (parsed.tool && String(parsed.tool).startsWith('gobuster_')) {
      const found: any[] = Array.isArray(parsed.found) ? parsed.found : [];
      const gTool = String(parsed.tool);
      if (gTool === 'gobuster_dir') {
        const byStatus: Record<string, string[]> = {};
        for (const f of found) {
          const code = String(f.status ?? '?');
          if (!byStatus[code]) byStatus[code] = [];
          byStatus[code].push(f.path);
        }
        const lines: string[] = [
          '### Gobuster — Directory Scan',
          '',
          `- **URL:** ${parsed.url ?? '—'}`,
          `- **Wordlist:** ${parsed.wordlist ?? '—'}`,
          `- **Paths Found:** ${found.length}`,
        ];
        if (found.length === 0) {
          lines.push('- *No paths found for the given status codes.*');
        } else {
          for (const [code, paths] of Object.entries(byStatus).sort()) {
            lines.push(`- **${code}:** ${paths.slice(0, 20).join(', ')}${paths.length > 20 ? ` … +${paths.length - 20} more` : ''}`);
          }
        }
        return lines.filter(Boolean).join('\n');
      }
      if (gTool === 'gobuster_dns') {
        const subs = found.map((f: any) => f.subdomain ?? f).filter(Boolean);
        return [
          '### Gobuster — DNS Subdomain Enum',
          '',
          `- **Domain:** ${parsed.domain ?? '—'}`,
          `- **Found:** ${subs.length}`,
          ...subs.slice(0, 20).map((s: string) => `  - ${s}`),
          subs.length > 20 ? `  - *…and ${subs.length - 20} more*` : '',
        ].filter(Boolean).join('\n');
      }
      if (gTool === 'gobuster_vhost') {
        return [
          '### Gobuster — VHost Discovery',
          '',
          `- **URL:** ${parsed.url ?? '—'}`,
          `- **Found:** ${found.length}`,
          ...found.slice(0, 20).map((f: any) => `  - ${f.vhost} (${f.status})`),
        ].filter(Boolean).join('\n');
      }
      // fuzz fallback
      return [
        '### Gobuster — Fuzz',
        '',
        `- **URL:** ${parsed.url ?? '—'}`,
        `- **Found:** ${found.length}`,
        ...found.slice(0, 15).map((f: any) => `  - ${JSON.stringify(f)}`),
      ].filter(Boolean).join('\n');
    }

    // Generic fallback — show EVERY meaningful field the tool returned, including arrays and nested objects (previously
    // these were skipped, which silently dropped most of a tool's output). Scalars render as "key: value"; arrays show
    // their items (capped); nested objects show their own key/values. Only the truly raw text blobs are omitted here —
    // they are still available via "Show raw output".
    const SKIP = new Set(['raw', 'raw_output', 'output', 'success']);
    const fmtScalar = (v: any) => String(v).slice(0, 200);
    const lines: string[] = ['### Tool Output', ''];
    for (const [k, v] of Object.entries(parsed)) {
      if (SKIP.has(k) || v == null || v === '') continue;
      if (Array.isArray(v)) {
        if (v.length === 0) continue;
        lines.push(`- **${k}** (${v.length}):`);
        v.slice(0, 10).forEach((item: any) => {
          const txt = (item && typeof item === 'object')
            ? Object.entries(item).filter(([, iv]) => iv != null && typeof iv !== 'object').map(([ik, iv]) => `${ik}: ${String(iv).slice(0, 60)}`).join(' · ')
            : String(item).slice(0, 120);
          lines.push(`  - ${txt || JSON.stringify(item).slice(0, 120)}`);
        });
        if (v.length > 10) lines.push(`  - … and ${v.length - 10} more`);
      } else if (typeof v === 'object') {
        const sub = Object.entries(v as Record<string, any>).filter(([, sv]) => sv != null && typeof sv !== 'object').slice(0, 8);
        if (sub.length) {
          lines.push(`- **${k}:**`);
          sub.forEach(([sk, sv]) => lines.push(`  - ${sk}: ${fmtScalar(sv)}`));
        }
      } else {
        lines.push(`- **${k}:** ${fmtScalar(v)}`);
      }
    }
    return lines.join('\n');
  };

  // Completeness guarantee for EVERY tool: after the tool-specific summary above, append any top-level field the server
  // returned that the summary didn't already mention — so no tool can silently drop data (the CVE problem, generalised).
  // Arrays and nested objects are summarised the same compact way as the generic fallback. Raw blobs stay out (they are
  // in "Show raw output"). This means each tool keeps its clean hand-written summary AND nothing is ever missing.
  const toMdComplete = (): string => {
    const base = toMd();
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return base;
    const shown = base.toLowerCase();
    const SKIP = new Set(['raw', 'raw_output', 'output', 'success', 'mode', 'results', 'error', 'message']);
    const extra: string[] = [];
    const fmt = (v: any) => String(v).slice(0, 200);
    for (const [k, v] of Object.entries(parsed as Record<string, any>)) {
      if (SKIP.has(k) || v == null || v === '') continue;
      // skip if the summary already references this field name (avoid duplicating what the hand-written branch showed)
      if (shown.includes(k.toLowerCase().replace(/_/g, ' ')) || shown.includes(k.toLowerCase())) continue;
      if (Array.isArray(v)) {
        if (v.length === 0) continue;
        extra.push(`- **${k}** (${v.length}):`);
        v.slice(0, 8).forEach((item: any) => {
          const txt = (item && typeof item === 'object')
            ? Object.entries(item).filter(([, iv]) => iv != null && typeof iv !== 'object').map(([ik, iv]) => `${ik}: ${String(iv).slice(0, 60)}`).join(' · ')
            : String(item).slice(0, 120);
          extra.push(`  - ${txt || JSON.stringify(item).slice(0, 120)}`);
        });
        if (v.length > 8) extra.push(`  - … and ${v.length - 8} more`);
      } else if (typeof v === 'object') {
        const sub = Object.entries(v as Record<string, any>).filter(([, sv]) => sv != null && typeof sv !== 'object').slice(0, 6);
        if (sub.length) {
          extra.push(`- **${k}:**`);
          sub.forEach(([sk, sv]) => extra.push(`  - ${sk}: ${fmt(sv)}`));
        }
      } else {
        extra.push(`- **${k}:** ${fmt(v)}`);
      }
    }
    if (extra.length === 0) return base;
    return base + '\n\n**More details:**\n' + extra.join('\n');
  };

  const summary = (
    // Render the FULL MarkdownRenderer (headings, lists, TABLES, blockquotes, code — everything toMd emits), exactly as
    // the proven-good original did, so no content is ever dropped. The only addition over the original is a height cap
    // with scroll, so a very large result can't blow the node up to full height and crowd out the rest of the workflow —
    // the complete output is still fully present (scroll it), and also in "Show raw output" and the config panel.
    <div style={{ fontSize: 10, maxHeight: 280, overflowY: 'auto', overflowX: 'auto' }} className="wf-node-output">
      <MarkdownRenderer content={toMdComplete()} />
    </div>
  );

  return (
    <div style={{ marginTop: 6 }}>
      {divider}
      {summary}
      <div
        onClick={() => setShowRaw(v => !v)}
        style={{ marginTop: 5, fontSize: '0.6875rem', color: 'var(--cyan)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 3, userSelect: 'none' }}>
        {showRaw ? <ChevronUp size={9} /> : <ChevronDown size={9} />}
        {showRaw ? 'Hide' : 'Show'} raw output
      </div>
      {showRaw && (
        <div style={{ marginTop: 4, border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
          {(() => {
            const preStyle: React.CSSProperties = {
              margin: 0, fontSize: 9, color: 'var(--text-muted)', fontFamily: 'monospace',
              background: 'var(--bg-primary)', padding: '6px 8px',
              overflowX: 'auto', maxHeight: 220, overflowY: 'auto',
              whiteSpace: 'pre-wrap', wordBreak: 'break-word', lineHeight: 1.6,
            };
            const secHdr = (title: string) => (
              <div style={{ fontSize: 8, fontWeight: 700, color: 'var(--cyan)', textTransform: 'uppercase',
                letterSpacing: '0.08em', background: 'var(--bg-secondary)', padding: '3px 8px',
                borderBottom: '1px solid var(--border)' }}>{title}</div>
            );
            if (!parsed) {
              const text = raw.length > 4000 ? raw.slice(0, 4000) + '\n… [truncated]' : raw;
              return <pre style={preStyle}>{text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')}</pre>;
            }

            // ── PoC Index rich renderer ───────────────────────────────────────
            if (tool === 'poc_index') {
              const resolveRawUrl = (p: any): string => {
                if (typeof p?.url === 'string' && /^https?:\/\//i.test(p.url)) return p.url;
                if (typeof p?.html_url === 'string' && /^https?:\/\//i.test(p.html_url)) return p.html_url;
                if (p?.edb_id) return `https://www.exploit-db.com/exploits/${String(p.edb_id).replace(/^EDB-/i, '')}`;
                return '';
              };
              const isBulk = parsed?.mode === 'bulk' && Array.isArray(parsed?.results);
              const allExploits: any[] = isBulk
                ? (parsed.results as any[]).flatMap((r: any) => {
                    const inner = typeof r?.output === 'string' ? (() => { try { return JSON.parse(r.output); } catch { return null; } })() : r?.output;
                    const exps: any[] = Array.isArray(inner?.exploits) ? inner.exploits : [];
                    const ghs: any[] = Array.isArray(inner?.github_poc_repos) ? inner.github_poc_repos : [];
                    return [...exps, ...ghs].map((e: any) => ({ ...e, _cve: r?.cve_id }));
                  })
                : [
                    ...(Array.isArray(parsed?.exploits) ? parsed.exploits : []),
                    ...(Array.isArray(parsed?.github_poc_repos) ? parsed.github_poc_repos : []),
                    ...(Array.isArray(parsed?.top_exploits) ? parsed.top_exploits : []),
                    ...(Array.isArray(parsed?.top_github_repos) ? parsed.top_github_repos : []),
                  ];
              // Keep real exploits; separately collect search_url fallbacks
              const validExploits = allExploits.filter((e: any) => !e?.error && !e?.message && (e?.url || e?.html_url || e?.edb_id || e?.repo || e?.title));
              const fallbackUrls: Array<{url: string; label: string; cve?: string}> = allExploits
                .filter((e: any) => e?.search_url && !e?.url)
                .map((e: any) => ({ url: e.search_url, label: `Search ExploitDB${e._cve ? ` for ${e._cve}` : ''}`, cve: e._cve }));
              const metaFields: Record<string, any> = {};
              for (const [k, v] of Object.entries(parsed)) {
                if (!['exploits','github_poc_repos','top_exploits','top_github_repos','results'].includes(k)) {
                  metaFields[k] = v;
                }
              }
              return (
                <>
                  {secHdr('Query Info')}
                  <pre style={preStyle}>{JSON.stringify(metaFields, null, 2)}</pre>
                  {secHdr(`PoC Results (${validExploits.length})`)}
                  <div style={{ padding: '6px 8px', maxHeight: 340, overflowY: 'auto' }}>
                    {validExploits.length === 0 && fallbackUrls.length === 0 && (
                      <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>No PoC exploits found in local database.</div>
                    )}
                    {fallbackUrls.map((fb, i) => (
                      <div key={`fb-${i}`} style={{ marginBottom: 5, padding: '4px 6px', borderRadius: 'var(--radius-sm)', background: 'rgba(239,68,68,0.07)', border: '1px dashed rgba(239,68,68,0.25)' }}>
                        <span style={{ fontSize: 8, color: 'var(--text-muted)' }}>Not in local DB → </span>
                        <a href={fb.url} target="_blank" rel="noopener noreferrer" style={{ fontSize: '0.6875rem', color: 'var(--red)', textDecoration: 'none', fontWeight: 600 }}>{fb.label} ↗</a>
                      </div>
                    ))}
                    {validExploits.map((e: any, i: number) => {
                      const url = resolveRawUrl(e);
                      const title = e?.title ?? e?.repo ?? e?.edb_id ?? `Result ${i + 1}`;
                      const src = e?.type === 'GitHub PoC' || e?.repo ? 'GitHub' : 'ExploitDB';
                      const stars = typeof e?.stars === 'number' ? ` · ⭐ ${e.stars}` : '';
                      const verified = e?.verified ? ' · ✓ verified' : '';
                      const cveTag = e?._cve ? ` · ${e._cve}` : '';
                      const dateStr = e?.date ? ` · ${String(e.date).slice(0, 10)}` : '';
                      return (
                        <div key={i} style={{ marginBottom: 6, paddingBottom: 6, borderBottom: '1px solid var(--border)' }}>
                          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 5 }}>
                            <span style={{
                              fontSize: 8, fontWeight: 700, padding: '1px 5px', borderRadius: 'var(--radius-sm)', flexShrink: 0,
                              background: src === 'GitHub' ? 'rgba(167,139,250,0.15)' : 'rgba(239,68,68,0.15)',
                              color: src === 'GitHub' ? 'var(--purple)' : 'var(--red)',
                              border: `1px solid ${src === 'GitHub' ? 'rgba(167,139,250,0.3)' : 'rgba(239,68,68,0.3)'}`,
                            }}>{src}</span>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              {url
                                ? <a href={url} target="_blank" rel="noopener noreferrer" style={{ fontSize: '0.6875rem', color: 'var(--cyan)', wordBreak: 'break-all', textDecoration: 'none', fontWeight: 600 }}>{title}</a>
                                : <span style={{ fontSize: '0.6875rem', color: 'var(--text-secondary)', fontWeight: 600 }}>{title}</span>
                              }
                              <div style={{ fontSize: 8, color: 'var(--text-muted)', marginTop: 1 }}>
                                {[cveTag, dateStr, stars, verified].filter(Boolean).join('')}
                              </div>
                              {e?.description && (
                                <div style={{ fontSize: 8, color: 'var(--text-muted)', marginTop: 2, fontStyle: 'italic' }}>
                                  {String(e.description).slice(0, 120)}{String(e.description).length > 120 ? '…' : ''}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </>
              );
            }

            // ── CISA KEV rich renderer ────────────────────────────────────────
            if (tool === 'cisa_kev') {
              const isBulk = parsed?.mode === 'bulk' && Array.isArray(parsed?.results);
              const metaKev: Record<string, any> = {};
              for (const [k, v] of Object.entries(parsed)) {
                if (k !== 'results') metaKev[k] = v;
              }
              if (!isBulk) {
                // Single CVE response — show key fields cleanly
                const fields: [string, any][] = [
                  ['CVE', parsed.cve_id], ['In KEV', parsed.in_kev ? '✓ Yes — Actively Exploited' : '✗ No'],
                  ['Vendor', parsed.vendor], ['Product', parsed.product],
                  ['Name', parsed.vuln_name], ['Date Added', parsed.date_added],
                  ['Due Date', parsed.due_date], ['Required Action', parsed.action_required],
                  ['CISA URL', parsed.cisa_url], ['NVD URL', parsed.nvd_url],
                ];
                return (
                  <div style={{ padding: '6px 8px' }}>
                    {fields.filter(([, v]) => v != null && v !== '').map(([k, v]) => (
                      <div key={String(k)} style={{ display: 'flex', gap: 6, marginBottom: 4, fontSize: '0.6875rem' }}>
                        <span style={{ color: 'var(--text-muted)', minWidth: 90, flexShrink: 0 }}>{String(k)}</span>
                        {typeof v === 'string' && /^https?:\/\//i.test(v)
                          ? <a href={v} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--cyan)', wordBreak: 'break-all', textDecoration: 'none' }}>{v}</a>
                          : <span style={{ color: String(k) === 'In KEV' && String(v).startsWith('✓') ? 'var(--green)' : 'var(--text-secondary)', fontWeight: String(k) === 'In KEV' ? 700 : 400 }}>{String(v)}</span>}
                      </div>
                    ))}
                  </div>
                );
              }
              // Bulk — one card per CVE result
              const results: any[] = parsed.results ?? [];
              return (
                <>
                  {secHdr(`KEV Results (${results.length} CVEs)`)}
                  <div style={{ maxHeight: 360, overflowY: 'auto', padding: '4px 0' }}>
                    {results.map((r: any, i: number) => {
                      const inner: any = (() => { try { return typeof r?.output === 'string' ? JSON.parse(r.output) : (r?.output ?? {}); } catch { return {}; } })();
                      const inKev: boolean = inner?.in_kev === true;
                      const cveId = r?.cve_id ?? inner?.cve_id ?? `Result ${i + 1}`;
                      const kevUrl = inner?.cisa_url ?? inner?.nvd_url ?? '';
                      return (
                        <div key={i} style={{ padding: '5px 8px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'flex-start', gap: 6 }}>
                          <span style={{
                            fontSize: 8, fontWeight: 700, padding: '1px 5px', borderRadius: 'var(--radius-sm)', flexShrink: 0, marginTop: 1,
                            background: inKev ? 'rgba(248,113,113,0.15)' : 'rgba(74,222,128,0.1)',
                            color: inKev ? 'var(--red)' : 'var(--green)',
                            border: `1px solid ${inKev ? 'rgba(248,113,113,0.3)' : 'rgba(74,222,128,0.2)'}`,
                          }}>{inKev ? 'KEV' : 'OK'}</span>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'monospace' }}>{cveId}</div>
                            {inner?.vendor && <div style={{ fontSize: 8, color: 'var(--text-muted)' }}>{inner.vendor} / {inner.product}</div>}
                            {inner?.date_added && <div style={{ fontSize: 8, color: 'var(--text-muted)' }}>Added: {inner.date_added}</div>}
                            {kevUrl && <a href={kevUrl} target="_blank" rel="noopener noreferrer" style={{ fontSize: 8, color: 'var(--cyan)', textDecoration: 'none' }}>View advisory ↗</a>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </>
              );
            }

            const TEXT_KEYS = ['raw', 'raw_output', 'output', 'body', 'text', 'content', 'stdout'];
            const textFields: [string, string][] = [];
            const display: Record<string, any> = {};
            for (const [k, v] of Object.entries(parsed)) {
              if (TEXT_KEYS.includes(k) && typeof v === 'string' && v.length > 60) {
                textFields.push([k, v]);
              } else {
                display[k] = v;
              }
            }
            return (
              <>
                {Object.keys(display).length > 0 && (
                  <>{secHdr('Structured Fields')}<pre style={preStyle}>{JSON.stringify(display, null, 2)}</pre></>
                )}
                {textFields.map(([k, v]) => {
                  const truncated = v.length > 4000;
                  const text = (truncated ? v.slice(0, 4000) : v)
                    .replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\t/g, '  ');
                  return (
                    <div key={k}>
                      {secHdr(k)}
                      <pre style={preStyle}>{text}{truncated && `\n… [${v.length - 4000} chars truncated]`}</pre>
                    </div>
                  );
                })}
              </>
            );
          })()}
        </div>
      )}
    </div>
  );
}

export function ToolNode({ id, data }: { id: string; data: WFNodeData }) {
  const { deleteElements } = useReactFlow();
  const accent = TOOL_COLORS[data.tool ?? ''] ?? 'var(--cyan)';
  const label = data.label || data.tool || 'Tool';
  const fields = toolFields(data);

  return (
    <div style={statusRingStyle(data)}>
      <Handle type="target" position={Position.Top} style={{ background: accent }} />
      <Handle type="target" id="t-left"  position={Position.Left}  style={{ background: accent, top: '38%', width: 6, height: 6, opacity: 0.35 }} />
      <Handle type="target" id="t-right" position={Position.Right} style={{ background: accent, top: '38%', width: 6, height: 6, opacity: 0.35 }} />
      <NodeHeader icon={<Terminal size={13} />} label={label} accent={accent} execStatus={data.execStatus}
        onDelete={() => deleteElements({ nodes: [{ id }] })} />
      <NodeBody>
        {fields.map(f => (
          <NodeField key={f.label} label={f.label} value={f.value} />
        ))}
        {data.timeout && data.timeout !== 300 && <NodeField label="timeout" value={`${data.timeout}s`} />}
        {data.port_filter && data.port_filter.length > 0 && (
          <NodeField label="ports" value={data.port_filter.join(', ')} />
        )}
        {data.execStatus === 'running' && (
          <div style={{ marginTop: 6, fontSize: '0.6875rem', color: 'var(--cyan)', display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{ display: 'inline-block', width: 7, height: 7, borderRadius: '50%', background: 'var(--chart-cyan)', animation: 'pulse 1s infinite' }} />
            Running…
          </div>
        )}
        {data.execOutput && data.execStatus !== 'running' && (
          <SmartOutput tool={data.tool ?? ''} raw={data.execOutput} />
        )}
      </NodeBody>
      <Handle type="source" position={Position.Bottom} style={{ background: accent }} />
      <Handle type="source" id="s-left"  position={Position.Left}  style={{ background: accent, top: '62%', width: 6, height: 6, opacity: 0.35 }} />
      <Handle type="source" id="s-right" position={Position.Right} style={{ background: accent, top: '62%', width: 6, height: 6, opacity: 0.35 }} />
    </div>
  );
}
