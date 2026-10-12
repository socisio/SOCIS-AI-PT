'use client';
import React from 'react';
import type { Finding } from '@/lib/types';

// Per-tool "pretty" renderers for raw scan output, extracted verbatim from findings/page.tsx (was ~800 lines inline).
// This is the single structured-output renderer; its per-tool helper components are defined within its body. A clean
// raw-output fallback handles any tool without a bespoke layout. Behaviour is unchanged by the extraction.

export default function StructuredFindingOutput({ finding }: { finding: Finding }) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const p = finding.parsed_output as Record<string, any> | null | undefined;
  const tool = finding.tool_name.toLowerCase().replace(/-/g, '_');

  if (!p || Object.keys(p).length === 0) {
    const raw = finding.raw_output;
    if (raw) {
      return (
        <pre style={{
          margin: 0, fontSize: '0.75rem', fontFamily: 'monospace', whiteSpace: 'pre-wrap',
          wordBreak: 'break-all', color: 'var(--text-secondary)', lineHeight: 1.6,
        }}>
          {raw.slice(0, 3000)}{raw.length > 3000 ? '\n…[truncated]' : ''}
        </pre>
      );
    }
    return <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>No output recorded</span>;
  }

  // ── helper components ──────────────────────────────────────────────────────

  const Section = ({ title, color = 'var(--cyan)', children }: { title: string; color?: string; children: React.ReactNode }) => (
    <div style={{ marginBottom: 16 }}>
      <div style={{
        fontSize: '0.6875rem', fontWeight: 700, color, textTransform: 'uppercase',
        letterSpacing: '0.08em', marginBottom: 6, borderBottom: `1px solid color-mix(in srgb, ${color} 19%, transparent)`, paddingBottom: 4,
      }}>
        {title}
      </div>
      {children}
    </div>
  );

  const Row = ({ label, value, mono = false, color }: { label: string; value: React.ReactNode; mono?: boolean; color?: string }) => (
    <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start', marginBottom: 5, fontSize: '0.8125rem' }}>
      <span style={{
        minWidth: 130, flexShrink: 0, fontSize: '0.6875rem', fontWeight: 600,
        color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.03em', paddingTop: 2,
      }}>
        {label}
      </span>
      <span style={{
        color: color || 'var(--text-primary)',
        fontFamily: mono ? 'monospace' : undefined,
        wordBreak: 'break-all', flex: 1,
      }}>
        {value}
      </span>
    </div>
  );

  const Badge = ({ text, color }: { text: string; color: string }) => (
    <span style={{
      display: 'inline-block', padding: '1px 7px', borderRadius: 99,
      background: `color-mix(in srgb, ${color} 9%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
      fontSize: '0.6875rem', fontWeight: 700, color, marginRight: 4,
    }}>
      {text}
    </span>
  );

  const Tag = ({ text }: { text: string }) => (
    <span style={{
      display: 'inline-block', padding: '2px 7px', borderRadius: 'var(--radius-sm)',
      background: 'color-mix(in srgb, var(--text-primary) 6%, transparent)', border: '1px solid var(--border)',
      fontSize: '0.75rem', fontFamily: 'monospace', marginBottom: 3, marginRight: 3,
      color: 'var(--text-secondary)',
    }}>
      {text}
    </span>
  );

  const LinkRow = ({ label, url }: { label: string; url: string }) => (
    <Row label={label} value={
      <a href={url} target="_blank" rel="noopener noreferrer" style={{
        color: 'var(--cyan)', textDecoration: 'none', fontSize: '0.75rem', wordBreak: 'break-all',
      }}>
        {url.length > 70 ? url.slice(0, 70) + '…' : url} ↗
      </a>
    } />
  );

  const Bullet = ({ children }: { children: React.ReactNode }) => (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6, marginBottom: 4 }}>
      <span style={{ color: 'var(--cyan)', fontSize: '0.6875rem', marginTop: 4 }}>◆</span>
      <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', flex: 1, wordBreak: 'break-word' }}>{children}</span>
    </div>
  );

  const sevColor = (s: string) => {
    const sl = String(s).toLowerCase();
    if (sl === 'critical') return 'var(--red)';
    if (sl === 'high') return 'var(--orange)';
    if (sl === 'medium') return 'var(--amber)';
    if (sl === 'low') return 'var(--green)';
    return 'var(--blue)';
  };

  // ── Tool-specific structured renderers ────────────────────────────────────

  // NMAP — {target, host_up, open_ports: [{port, protocol, service, version}], os_guess}
  if (p.open_ports !== undefined || tool.includes('nmap') || tool.includes('masscan')) {
    const ports = Array.isArray(p.open_ports) ? p.open_ports as Record<string, any>[] : [];
    return (
      <>
        <Section title="Host Info" color="var(--cyan)">
          {p.target && <Row label="Target" value={String(p.target)} mono />}
          <Row label="Host Status" value={
            <Badge
              text={p.host_up === true ? 'UP' : p.host_up === false ? 'DOWN' : 'Unknown'}
              color={p.host_up === true ? 'var(--green)' : 'var(--red)'}
            />
          } />
          {p.os_guess && <Row label="OS Guess" value={String(p.os_guess)} />}
          {p.rate && <Row label="Scan Rate" value={`${p.rate} pps`} />}
          {p.ports && !Array.isArray(p.open_ports) && <Row label="Port Range" value={String(p.ports)} />}
        </Section>
        <Section title={`Open Ports (${ports.length})`} color={ports.length > 0 ? 'var(--amber)' : 'var(--green)'}>
          {ports.length === 0 ? (
            <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>No open ports found</span>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {ports.map((pp, i) => {
                const port = pp.port ?? pp.portid;
                const proto = pp.protocol ?? pp.proto ?? 'tcp';
                const svc = pp.service ?? pp.name ?? 'unknown';
                const ver = pp.version ?? pp.product ?? '';
                return (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '5px 10px', borderRadius: 'var(--radius-sm)',
                    background: 'rgba(0,200,220,0.05)', border: '1px solid rgba(0,200,220,0.15)',
                  }}>
                    <span style={{ fontFamily: 'monospace', fontWeight: 700, color: 'var(--cyan)', fontSize: '0.875rem', minWidth: 60 }}>
                      {String(port)}/{String(proto)}
                    </span>
                    <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', flex: 1 }}>
                      {String(svc)}{ver ? ` — ${String(ver)}` : ''}
                    </span>
                    {pp.state && <Badge text={String(pp.state)} color="var(--green)" />}
                  </div>
                );
              })}
            </div>
          )}
        </Section>
      </>
    );
  }

  // NUCLEI / Vulnerability scan — {findings: [{name, severity, url, description, tags}]}
  if (Array.isArray(p.findings) && (p.findings as any[]).length > 0 && (p as any).findings[0]?.severity) {
    const findings = p.findings as Record<string, any>[];
    const bySev: Record<string, Record<string, any>[]> = {};
    findings.forEach((f) => {
      const s = String(f.severity ?? 'info').toLowerCase();
      (bySev[s] = bySev[s] || []).push(f);
    });
    const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
    return (
      <>
        <Section title="Vulnerability Summary" color="var(--amber)">
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
            {sevOrder.filter((s) => bySev[s]?.length).map((s) => (
              <Badge key={s} text={`${bySev[s].length} ${s}`} color={sevColor(s)} />
            ))}
          </div>
          {p.target && <Row label="Target" value={String(p.target)} mono />}
        </Section>
        {sevOrder.filter((s) => bySev[s]?.length).map((s) => (
          <Section key={s} title={`${s.toUpperCase()} (${bySev[s].length})`} color={sevColor(s)}>
            {bySev[s].map((f, i) => (
              <div key={i} style={{ marginBottom: 8, paddingBottom: 8, borderBottom: '1px solid var(--border)' }}>
                <div style={{ fontWeight: 600, fontSize: '0.8125rem', color: 'var(--text-primary)', marginBottom: 3 }}>
                  {String(f.name ?? f.vuln_name ?? f.id ?? `Finding ${i + 1}`)}
                </div>
                {f.description && (
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                    {String(f.description).slice(0, 200)}{String(f.description).length > 200 ? '…' : ''}
                  </div>
                )}
                {f.url && <div style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>{String(f.url)}</div>}
                {Array.isArray(f.tags) && (f.tags as string[]).slice(0, 5).map((t) => <Tag key={t} text={t} />)}
              </div>
            ))}
          </Section>
        ))}
      </>
    );
  }

  // GOBUSTER / FFUF — {found: [{path, status, size}], tool, url}
  if (Array.isArray(p.found)) {
    const found = p.found as Record<string, any>[];
    const byStatus: Record<string, Record<string, any>[]> = {};
    found.forEach((f) => {
      const code = String(f.status ?? f.status_code ?? '200');
      (byStatus[code] = byStatus[code] || []).push(f);
    });
    const statusColor = (c: string) => {
      if (c.startsWith('2')) return 'var(--green)';
      if (c.startsWith('3')) return 'var(--blue)';
      if (c.startsWith('4')) return 'var(--red)';
      return 'var(--text-muted)';
    };
    return (
      <>
        <Section title="Scan Info" color="var(--orange)">
          {p.url && <Row label="URL" value={String(p.url)} mono />}
          {p.domain && <Row label="Domain" value={String(p.domain)} mono />}
          {p.wordlist && <Row label="Wordlist" value={String(p.wordlist)} />}
          <Row label="Total Found" value={<Badge text={String(found.length)} color="var(--orange)" />} />
        </Section>
        {found.length === 0 ? (
          <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>No paths/entries found</span>
        ) : (
          Object.entries(byStatus).sort().map(([code, items]) => (
            <Section key={code} title={`HTTP ${code} (${items.length})`} color={statusColor(code)}>
              {items.slice(0, 30).map((item, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                  <Badge text={code} color={statusColor(code)} />
                  <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    {String(item.path ?? item.subdomain ?? item.vhost ?? item.url ?? JSON.stringify(item).slice(0, 80))}
                  </span>
                  {item.size !== undefined && <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>{String(item.size)}B</span>}
                </div>
              ))}
              {items.length > 30 && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>…and {items.length - 30} more</span>}
            </Section>
          ))
        )}
      </>
    );
  }

  // SUBDOMAIN ENUM — {domain, subdomains: [...], total}
  if (Array.isArray(p.subdomains)) {
    const subs = p.subdomains as string[];
    return (
      <>
        <Section title="Subdomain Enumeration" color="var(--green)">
          <Row label="Domain" value={String(p.domain ?? '—')} mono />
          <Row label="Total Found" value={<Badge text={String(p.total ?? subs.length)} color="var(--green)" />} />
        </Section>
        {subs.length > 0 && (
          <Section title="Subdomains" color="var(--green)">
            {subs.slice(0, 50).map((s, i) => <Bullet key={i}><code style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{s}</code></Bullet>)}
            {subs.length > 50 && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>…and {subs.length - 50} more</span>}
          </Section>
        )}
      </>
    );
  }

  // CISA KEV — single {in_kev, cve_id, vendor, product, date_added, due_date, ...}
  if ('in_kev' in p) {
    const inKev = p.in_kev === true;
    return (
      <>
        <Section title="CISA KEV Status" color={inKev ? 'var(--red)' : 'var(--green)'}>
          <Row label="KEV Status" value={
            <Badge text={inKev ? '⚠ Actively Exploited' : '✓ Not in KEV'} color={inKev ? 'var(--red)' : 'var(--green)'} />
          } />
          {p.cve_id && <Row label="CVE" value={String(p.cve_id)} mono />}
          {p.vendor && <Row label="Vendor" value={String(p.vendor)} />}
          {p.product && <Row label="Product" value={String(p.product)} />}
          {p.name && <Row label="Name" value={String(p.name)} />}
          {p.date_added && <Row label="Date Added" value={String(p.date_added)} />}
          {p.due_date && <Row label="Due Date" value={String(p.due_date)} />}
          {p.ransomware_campaign && p.ransomware_campaign !== 'Unknown' && (
            <Row label="Ransomware" value={<Badge text={String(p.ransomware_campaign)} color="var(--red)" />} />
          )}
        </Section>
        {p.action_required && (
          <Section title="Required Action" color="var(--amber)">
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              {String(p.action_required)}
            </div>
          </Section>
        )}
        {p.description && (
          <Section title="Description" color="var(--text-muted)">
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              {String(p.description)}
            </div>
          </Section>
        )}
        {(p.cisa_url || p.nvd_url) && (
          <Section title="References">
            {p.cisa_url && <LinkRow label="CISA Advisory" url={String(p.cisa_url)} />}
            {p.nvd_url && <LinkRow label="NVD Entry" url={String(p.nvd_url)} />}
            {typeof p.notes === 'string' && p.notes.split(';').filter((u) => URL_RE.test(u.trim())).map((u, i) => (
              <LinkRow key={i} label={`Reference ${i + 1}`} url={u.trim()} />
            ))}
          </Section>
        )}
      </>
    );
  }

  // EPSS — {cve_id, epss_score, percentile, risk_label} or bulk
  if ('epss_score' in p || 'epss' in p || (Array.isArray((p as any).scores))) {
    const score = Number(p.epss_score ?? p.epss);
    const pct = Number.isFinite(score) ? `${(score * 100).toFixed(3)}%` : null;
    const perc = p.percentile != null ? `${(Number(p.percentile) * 100).toFixed(1)}%` : null;
    const scores = Array.isArray((p as any).scores) ? (p as any).scores as Record<string, any>[] : [];
    return (
      <>
        <Section title="EPSS Risk Score" color="var(--amber)">
          {p.cve_id && <Row label="CVE" value={String(p.cve_id)} mono />}
          {pct && <Row label="EPSS Score" value={<Badge text={pct} color="var(--amber)" />} />}
          {perc && <Row label="Percentile" value={perc} />}
          {p.risk_label && <Row label="Risk Label" value={String(p.risk_label)} />}
          {p.count != null && <Row label="Total Scored" value={String(p.count)} />}
        </Section>
        {scores.length > 0 && (
          <Section title="Top CVEs by EPSS" color="var(--amber)">
            {scores.sort((a: any, b: any) => (Number(b.epss_score) || 0) - (Number(a.epss_score) || 0))
              .slice(0, 20).map((s: any, i) => (
              <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 4, alignItems: 'center' }}>
                <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--text-primary)', minWidth: 150 }}>{String(s.cve_id ?? '—')}</span>
                <span style={{
                  fontSize: '0.75rem', fontWeight: 600,
                  color: Number(s.epss_score) > 0.5 ? 'var(--red)' : Number(s.epss_score) > 0.1 ? 'var(--amber)' : 'var(--green)',
                }}>
                  {Number.isFinite(Number(s.epss_score)) ? `${(Number(s.epss_score) * 100).toFixed(3)}%` : '—'}
                </span>
              </div>
            ))}
          </Section>
        )}
      </>
    );
  }

  // PoC / ExploitDB — {count, exploits, github_poc_repos, source, query}
  if ('public_poc_exists' in p || Array.isArray(p.exploits) || Array.isArray((p as any).github_poc_repos) || Array.isArray((p as any).top_exploits)) {
    const edbExploits = Array.isArray(p.exploits) ? p.exploits as Record<string, any>[] :
      Array.isArray((p as any).top_exploits) ? (p as any).top_exploits as Record<string, any>[] : [];
    const ghRepos = Array.isArray((p as any).github_poc_repos) ? (p as any).github_poc_repos as Record<string, any>[] :
      Array.isArray((p as any).top_github_repos) ? (p as any).top_github_repos as Record<string, any>[] : [];
    const hasPoC = edbExploits.length > 0 || ghRepos.length > 0;
    const resolveUrl = (e: Record<string, any>): string => {
      if (typeof e.url === 'string' && URL_RE.test(e.url)) return e.url;
      if (typeof e.html_url === 'string' && URL_RE.test(e.html_url)) return e.html_url;
      if (e.edb_id) return `https://www.exploit-db.com/exploits/${String(e.edb_id).replace(/^EDB-/i, '')}`;
      return '';
    };
    return (
      <>
        <Section title="PoC Exposure Summary" color={hasPoC ? 'var(--red)' : 'var(--green)'}>
          {'public_poc_exists' in p && (
            <Row label="Public PoC" value={
              <Badge text={p.public_poc_exists ? '⚠ YES — Exploits Exist' : '✓ None Found'} color={p.public_poc_exists ? 'var(--red)' : 'var(--green)'} />
            } />
          )}
          {'risk_level' in p && <Row label="Risk Level" value={<Badge text={String(p.risk_level)} color={sevColor(String(p.risk_level).toLowerCase())} />} />}
          {'exploitation_difficulty' in p && (
            <Row label="Difficulty" value={String(p.exploitation_difficulty).split('—')[0].trim()} />
          )}
          {p.source && <Row label="Source" value={String(p.source)} />}
          {p.query && <Row label="Query" value={String(p.query)} mono />}
          <Row label="ExploitDB PoCs" value={String(edbExploits.length)} />
          <Row label="GitHub PoCs" value={String(ghRepos.length)} />
        </Section>
        {edbExploits.length > 0 && (
          <Section title={`ExploitDB Results (${edbExploits.length})`} color="var(--red)">
            {edbExploits.filter((e) => !e.message && !e.error).map((e, i) => {
              const url = resolveUrl(e);
              return (
                <div key={i} style={{ marginBottom: 8, paddingBottom: 8, borderBottom: '1px solid var(--border)' }}>
                  <div style={{ fontWeight: 600, fontSize: '0.8125rem', color: 'var(--text-primary)', marginBottom: 3 }}>
                    {url
                      ? <a href={url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--red)', textDecoration: 'none' }}>
                          {String(e.title ?? e.edb_id ?? `EDB Entry ${i + 1}`)} ↗
                        </a>
                      : String(e.title ?? e.edb_id ?? `Entry ${i + 1}`)}
                  </div>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {e.edb_id && <Badge text={String(e.edb_id)} color="var(--red)" />}
                    {e.type && <Badge text={String(e.type)} color="var(--orange)" />}
                    {e.platform && <Badge text={String(e.platform)} color="var(--text-muted)" />}
                    {e.verified && <Badge text="✓ Verified" color="var(--green)" />}
                    {e.date && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{String(e.date).slice(0, 10)}</span>}
                  </div>
                </div>
              );
            })}
            {edbExploits.some((e) => e.search_url) && (
              <div style={{ marginTop: 4 }}>
                {edbExploits.filter((e) => e.search_url).map((e, i) => (
                  <a key={i} href={String(e.search_url)} target="_blank" rel="noopener noreferrer"
                     style={{ fontSize: '0.75rem', color: 'var(--cyan)', display: 'block', marginBottom: 3 }}>
                    Not in local DB — Search ExploitDB ↗
                  </a>
                ))}
              </div>
            )}
          </Section>
        )}
        {ghRepos.length > 0 && (
          <Section title={`GitHub PoC Repos (${ghRepos.length})`} color="var(--purple)">
            {ghRepos.map((r, i) => {
              const url = resolveUrl(r);
              return (
                <div key={i} style={{ marginBottom: 8, paddingBottom: 8, borderBottom: '1px solid var(--border)' }}>
                  <div style={{ fontWeight: 600, fontSize: '0.8125rem', marginBottom: 3 }}>
                    {url
                      ? <a href={url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--purple)', textDecoration: 'none' }}>
                          {String(r.repo ?? r.full_name ?? `GitHub Repo ${i + 1}`)} ↗
                        </a>
                      : String(r.repo ?? r.full_name ?? `Repo ${i + 1}`)}
                  </div>
                  {r.description && (
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 3 }}>
                      {String(r.description).slice(0, 120)}
                    </div>
                  )}
                  <div style={{ display: 'flex', gap: 6 }}>
                    {r.stars != null && <Badge text={`⭐ ${r.stars}`} color="var(--amber)" />}
                    {r.pushed_at && <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>Updated: {String(r.pushed_at).slice(0, 10)}</span>}
                  </div>
                </div>
              );
            })}
          </Section>
        )}
        {Array.isArray((p as any).recommendations) && (p as any).recommendations.length > 0 && (
          <Section title="Recommendations" color="var(--amber)">
            {((p as any).recommendations as string[]).map((r, i) => <Bullet key={i}>{r}</Bullet>)}
          </Section>
        )}
      </>
    );
  }

  // SSL — {domain, port, subject, issuer, expires, grade, ...}
  if (p.domain && (p.port != null || p.issuer || p.grade || p.ssl_grade)) {
    const exp = p.expires ?? p.expiry;
    const expired = exp ? new Date(String(exp)) < new Date() : false;
    return (
      <>
        <Section title="SSL Certificate" color="var(--blue)">
          <Row label="Host" value={`${p.domain}${p.port ? `:${p.port}` : ''}`} mono />
          {(p.grade || p.ssl_grade) && <Row label="Grade" value={<Badge text={String(p.grade ?? p.ssl_grade)} color="var(--blue)" />} />}
          {p.subject && <Row label="Subject" value={String(p.subject)} />}
          {p.issuer && <Row label="Issuer" value={String(p.issuer)} />}
          {p.issued && <Row label="Issued" value={String(p.issued)} />}
          {exp && <Row label="Expires" value={<span style={{ color: expired ? 'var(--red)' : 'var(--green)' }}>{String(exp)}{expired ? ' ⚠ EXPIRED' : ''}</span>} />}
          {p.self_signed != null && <Row label="Self-Signed" value={<Badge text={p.self_signed ? 'Yes ⚠' : 'No'} color={p.self_signed ? 'var(--red)' : 'var(--green)'} />} />}
          {Array.isArray(p.san) && (p.san as string[]).length > 0 && (
            <Row label="SANs" value={<div>{(p.san as string[]).slice(0, 10).map((s) => <Tag key={s} text={s} />)}</div>} />
          )}
        </Section>
        {Array.isArray(p.issues) && (p.issues as string[]).length > 0 && (
          <Section title="Issues" color="var(--red)">
            {(p.issues as string[]).map((issue, i) => <Bullet key={i}>{issue}</Bullet>)}
          </Section>
        )}
      </>
    );
  }

  // WAF Detection — {waf_detected, waf_name, url, confidence, ...}
  if ('waf_detected' in p) {
    const detected = p.waf_detected === true;
    return (
      <Section title="WAF Detection" color={detected ? 'var(--amber)' : 'var(--green)'}>
        <Row label="WAF Detected" value={<Badge text={detected ? `⚠ ${p.waf_name || 'Unknown WAF'}` : '✓ No WAF'} color={detected ? 'var(--amber)' : 'var(--green)'} />} />
        {p.url && <Row label="URL" value={String(p.url)} mono />}
        {p.confidence && <Row label="Confidence" value={String(p.confidence)} />}
        {p.waf_vendor && <Row label="Vendor" value={String(p.waf_vendor)} />}
        {p.waf_version && <Row label="Version" value={String(p.waf_version)} />}
        {Array.isArray(p.bypass_suggestions) && (p.bypass_suggestions as string[]).length > 0 && (
          <>
            <div style={{ marginTop: 10, fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 5 }}>Bypass Hints</div>
            {(p.bypass_suggestions as string[]).map((s, i) => <Bullet key={i}>{s}</Bullet>)}
          </>
        )}
      </Section>
    );
  }

  // JWT — {algorithm, cracked, secret, tokens, ...}
  if (p.algorithm || 'cracked' in p || p.tokens) {
    const cracked = p.cracked === true;
    return (
      <>
        <Section title="JWT Analysis" color="var(--amber)">
          {p.algorithm && <Row label="Algorithm" value={<Badge text={String(p.algorithm)} color="var(--amber)" />} />}
          {'cracked' in p && (
            <Row label="Secret Cracked" value={<Badge text={cracked ? '⚠ YES — VULNERABLE' : '✓ No'} color={cracked ? 'var(--red)' : 'var(--green)'} />} />
          )}
          {p.secret && <Row label="Secret" value={String(p.secret)} mono />}
          {p.candidates_tested && <Row label="Candidates Tested" value={String(p.candidates_tested)} />}
        </Section>
        {typeof p.tokens === 'object' && p.tokens !== null && (
          <Section title="Tokens" color="var(--amber)">
            {Object.entries(p.tokens as Record<string, string>).map(([variant, token]) => (
              <Row key={variant} label={variant} value={<code style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>{String(token).slice(0, 100)}…</code>} />
            ))}
          </Section>
        )}
        {p.message && <Section title="Details"><div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{String(p.message)}</div></Section>}
      </>
    );
  }

  // CVE lookup — {cve_id, severity, cvss_score, description, references}
  if (p.cve_id || (p.severity && p.description)) {
    const refs: string[] = Array.isArray(p.references) ? (p.references as any[]).map((r) =>
      typeof r === 'string' ? r : (r?.url ?? r?.link ?? '')).filter((u: string) => URL_RE.test(u)).slice(0, 8) : [];
    return (
      <>
        <Section title="CVE Intelligence" color="var(--pink)">
          {p.cve_id && <Row label="CVE ID" value={String(p.cve_id)} mono />}
          {p.severity && <Row label="Severity" value={<Badge text={String(p.severity).toUpperCase()} color={sevColor(String(p.severity))} />} />}
          {(p.cvss_v3_score ?? p.cvss_score) != null && <Row label="CVSS Score" value={String(p.cvss_v3_score ?? p.cvss_score)} />}
          {p.vendor && <Row label="Vendor" value={String(p.vendor)} />}
          {p.published && <Row label="Published" value={String(p.published)} />}
        </Section>
        {p.description && (
          <Section title="Description" color="var(--text-muted)">
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.7 }}>{String(p.description)}</div>
          </Section>
        )}
        {refs.length > 0 && (
          <Section title="References">
            {refs.map((u, i) => <LinkRow key={i} label={`Ref ${i + 1}`} url={u} />)}
          </Section>
        )}
      </>
    );
  }

  // SQLMap — {vulnerable, target, dbms, databases, tables, parameters, injections}
  if ('vulnerable' in p || 'injectable' in p || p.dbms) {
    const vuln = p.vulnerable === true || p.injectable === true;
    const dbs = Array.isArray(p.databases) ? p.databases as string[] : [];
    const tables = Array.isArray(p.tables) ? p.tables as string[] : [];
    const injections = Array.isArray(p.injections) ? p.injections as string[] : [];
    const params = Array.isArray(p.parameters) ? p.parameters as string[] : [];
    return (
      <>
        <Section title="SQL Injection Analysis" color={vuln ? 'var(--red)' : 'var(--green)'}>
          <Row label="Status" value={<Badge text={vuln ? '⚠ VULNERABLE' : '✓ Not Vulnerable'} color={vuln ? 'var(--red)' : 'var(--green)'} />} />
          {p.target && <Row label="Target" value={String(p.target)} mono />}
          {p.dbms && <Row label="DBMS" value={String(p.dbms)} />}
          {p.current_db && <Row label="Current DB" value={String(p.current_db)} mono />}
          {p.current_user && <Row label="DB User" value={String(p.current_user)} mono />}
          {p.is_dba && <Row label="DBA Access" value={<Badge text="⚠ YES" color="var(--red)" />} />}
          {params.length > 0 && <Row label="Injectable Params" value={params.join(', ')} />}
        </Section>
        {dbs.length > 0 && (
          <Section title={`Databases (${dbs.length})`} color="var(--red)">
            {dbs.slice(0, 20).map((d) => <Tag key={d} text={d} />)}
            {dbs.length > 20 && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>…and {dbs.length - 20} more</span>}
          </Section>
        )}
        {tables.length > 0 && (
          <Section title={`Tables (${tables.length})`} color="var(--red)">
            {tables.slice(0, 30).map((t) => <Tag key={t} text={t} />)}
            {tables.length > 30 && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>…and {tables.length - 30} more</span>}
          </Section>
        )}
        {injections.length > 0 && (
          <Section title="Injection Points" color="var(--red)">
            {injections.slice(0, 5).map((inj, i) => <Bullet key={i}>{inj}</Bullet>)}
          </Section>
        )}
      </>
    );
  }

  // Metasploit — {mode, target, sessions_opened, failed_modules, ...}
  if (p.mode || Array.isArray((p as any).sessions_opened)) {
    const sessions = Array.isArray((p as any).sessions_opened) ? (p as any).sessions_opened as number[] : [];
    const failed = Array.isArray((p as any).failed_modules) ? (p as any).failed_modules as string[] : [];
    const hasSession = sessions.length > 0 || p.has_session === true;
    return (
      <>
        <Section title="Metasploit Execution" color={hasSession ? 'var(--red)' : 'var(--green)'}>
          <Row label="Mode" value={String(p.mode ?? 'single-module')} />
          {p.target && <Row label="Target" value={String(p.target)} mono />}
          <Row label="Session Opened" value={<Badge text={hasSession ? '⚠ YES — ACCESS GAINED' : '✓ No Session'} color={hasSession ? 'var(--red)' : 'var(--green)'} />} />
          {p.attempted_modules != null && <Row label="Modules Tried" value={String(p.attempted_modules)} />}
          {p.successful_modules != null && <Row label="Succeeded" value={String(p.successful_modules)} />}
          {sessions.length > 0 && <Row label="Session IDs" value={sessions.join(', ')} />}
        </Section>
        {failed.length > 0 && (
          <Section title={`Failed Modules (${failed.length})`} color="var(--text-muted)">
            {failed.slice(0, 10).map((m) => <Tag key={m} text={m} />)}
          </Section>
        )}
        {Array.isArray((p as any).open_ports) && (
          <Section title="Open Ports Found" color="var(--cyan)">
            {((p as any).open_ports as (string | number)[]).map((port) => <Tag key={port} text={String(port)} />)}
          </Section>
        )}
      </>
    );
  }

  // WhatWeb / Tech fingerprint — {url, technologies, status_code}
  if (p.url && (p.technologies || (p as any).tech || (p as any).detected_technologies)) {
    const techs = Array.isArray(p.technologies) ? p.technologies as string[] :
      Array.isArray((p as any).tech) ? (p as any).tech as string[] :
      Array.isArray((p as any).detected_technologies) ? (p as any).detected_technologies as string[] : [];
    return (
      <Section title="Technology Fingerprint" color="var(--indigo)">
        <Row label="URL" value={String(p.url)} mono />
        {p.status_code && <Row label="Status Code" value={String(p.status_code)} />}
        {p.server && <Row label="Server" value={String(p.server)} />}
        <Row label={`Technologies (${techs.length})`} value={<div style={{ marginTop: 2 }}>{techs.slice(0, 20).map((t) => <Tag key={t} text={t} />)}</div>} />
      </Section>
    );
  }

  // HTTP Headers — {url, status_code, headers, redirect_count}
  if (p.url && p.headers && typeof p.headers === 'object') {
    const headers = p.headers as Record<string, string>;
    const secHeaders = ['x-frame-options','content-security-policy','strict-transport-security','x-content-type-options','x-xss-protection','permissions-policy'];
    const missing = secHeaders.filter((h) => !Object.keys(headers).find((k) => k.toLowerCase() === h));
    return (
      <>
        <Section title="HTTP Response" color="var(--cyan)">
          <Row label="URL" value={String(p.url)} mono />
          <Row label="Status Code" value={String(p.status_code ?? '—')} />
          {p.redirect_count != null && <Row label="Redirects" value={String(p.redirect_count)} />}
          {headers.server && <Row label="Server" value={headers.server} />}
          {headers['x-powered-by'] && <Row label="Powered By" value={headers['x-powered-by']} />}
        </Section>
        {missing.length > 0 && (
          <Section title={`Missing Security Headers (${missing.length})`} color="var(--red)">
            {missing.map((h) => <Bullet key={h}><code style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{h}</code></Bullet>)}
          </Section>
        )}
      </>
    );
  }

  // DNS / OSINT — {domain, records: {...}, subdomains, registrar, ...}
  if (p.records && typeof p.records === 'object' && !Array.isArray(p.records)) {
    const records = p.records as Record<string, string[]>;
    return (
      <>
        <Section title="DNS Records" color="var(--cyan)">
          {p.domain && <Row label="Domain" value={String(p.domain)} mono />}
          {p._resolved_ip && <Row label="Resolved IP" value={String(p._resolved_ip)} mono />}
        </Section>
        {Object.entries(records).filter(([k]) => !k.startsWith('_')).map(([type, vals]) => (
          <Section key={type} title={`${type} Records`} color="var(--cyan)">
            {(vals as string[]).slice(0, 20).map((v, i) => <Bullet key={i}><code style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{v}</code></Bullet>)}
          </Section>
        ))}
      </>
    );
  }

  // IP Geolocation — {ip, country, city, org, timezone, loc}
  if (p.ip && (p.country || p.city)) {
    return (
      <Section title="IP Geolocation" color="var(--purple)">
        <Row label="IP Address" value={String(p.ip)} mono />
        {p.hostname && <Row label="Hostname" value={String(p.hostname)} mono />}
        {(p.city || p.region || p.country) && (
          <Row label="Location" value={[p.city, p.region, p.country].filter(Boolean).map(String).join(', ')} />
        )}
        {p.org && <Row label="ASN / Org" value={String(p.org)} />}
        {p.timezone && <Row label="Timezone" value={String(p.timezone)} />}
        {p.loc && <Row label="Coordinates" value={String(p.loc)} />}
      </Section>
    );
  }

  // Nikto / WPScan / tools with {output: string} — display the text output formatted
  if (typeof p.output === 'string' && p.output.trim().length > 0) {
    const target = p.target ?? p.url ?? '';
    return (
      <>
        {target && <Section title="Target"><Row label="Target" value={String(target)} mono /></Section>}
        <Section title="Tool Output">
          <pre style={{
            margin: 0, fontSize: '0.75rem', fontFamily: 'monospace', whiteSpace: 'pre-wrap',
            wordBreak: 'break-word', color: 'var(--text-secondary)', lineHeight: 1.6,
            maxHeight: 400, overflowY: 'auto',
          }}>
            {String(p.output).slice(0, 5000)}{String(p.output).length > 5000 ? '\n…[truncated]' : ''}
          </pre>
        </Section>
      </>
    );
  }

  // Whois / domain info — {domain, registrar, registrant, expiry, ...}
  if (p.registrar || p.registrant) {
    return (
      <Section title="WHOIS / Domain Info" color="var(--purple)">
        {p.domain && <Row label="Domain" value={String(p.domain)} mono />}
        {p.registrar && <Row label="Registrar" value={String(p.registrar)} />}
        {p.registrant && <Row label="Registrant" value={String(p.registrant)} />}
        {(p.expiry ?? p.expiry_date) && <Row label="Expiry" value={String(p.expiry ?? p.expiry_date)} />}
        {p.created && <Row label="Created" value={String(p.created)} />}
        {p.updated && <Row label="Updated" value={String(p.updated)} />}
        {p.name_servers && (
          <Row label="Name Servers" value={
            <div>{(Array.isArray(p.name_servers) ? p.name_servers as string[] : [String(p.name_servers)]).map((ns) => <Tag key={ns} text={ns} />)}</div>
          } />
        )}
      </Section>
    );
  }

  // ── Generic fallback — structured key/value with smart rendering ──────────
  const knownSkip = new Set(['raw', 'raw_output', 'stdout']);
  const entries = Object.entries(p).filter(([k]) => !knownSkip.has(k));

  return (
    <Section title="Output Fields">
      {entries.map(([key, val]) => {
        if (Array.isArray(val)) {
          if (val.length === 0) return <Row key={key} label={key.replace(/_/g, ' ')} value={<em style={{ color: 'var(--text-muted)' }}>empty</em>} />;
          const items = val as any[];
          // Simple string/number array
          if (typeof items[0] !== 'object') {
            return (
              <Row key={key} label={key.replace(/_/g, ' ')} value={
                <div>{items.slice(0, 30).map((item, i) => <Tag key={i} text={String(item)} />)}{items.length > 30 && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>…+{items.length - 30}</span>}</div>
              } />
            );
          }
          // Object array — show as compact list
          return (
            <div key={key} style={{ marginBottom: 10 }}>
              <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 5 }}>
                {key.replace(/_/g, ' ')} ({items.length})
              </div>
              {(items as Record<string, any>[]).slice(0, 15).map((item, i) => (
                <div key={i} style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: 'var(--text-secondary)', padding: '2px 6px', borderRadius: 'var(--radius-sm)', background: 'rgba(0,0,0,0.2)', marginBottom: 3 }}>
                  {Object.entries(item).slice(0, 4).map(([k, v]) => `${k}: ${String(v).slice(0, 50)}`).join(' · ')}
                </div>
              ))}
              {items.length > 15 && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>…and {items.length - 15} more</span>}
            </div>
          );
        }

        if (typeof val === 'object' && val !== null) {
          const nested = val as Record<string, unknown>;
          const nestedEntries = Object.entries(nested).filter(([, v]) => typeof v !== 'object' || v === null).slice(0, 8);
          if (nestedEntries.length > 0) {
            return (
              <div key={key} style={{ marginBottom: 10 }}>
                <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 5 }}>
                  {key.replace(/_/g, ' ')}
                </div>
                {nestedEntries.map(([k, v]) => (
                  <Row key={k} label={k.replace(/_/g, ' ')} value={
                    typeof v === 'boolean'
                      ? <Badge text={v ? 'Yes' : 'No'} color={v ? 'var(--green)' : 'var(--red)'} />
                      : String(v).length > 0 && URL_RE.test(String(v))
                        ? <a href={String(v)} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--cyan)', fontSize: '0.75rem', textDecoration: 'none' }}>{String(v).slice(0, 70)}↗</a>
                        : <span>{String(v).slice(0, 160)}</span>
                  } />
                ))}
              </div>
            );
          }
          return null;
        }

        if (typeof val === 'boolean') {
          return <Row key={key} label={key.replace(/_/g, ' ')} value={<Badge text={val ? 'Yes' : 'No'} color={val ? 'var(--green)' : 'var(--red)'} />} />;
        }

        const strVal = String(val);
        if (URL_RE.test(strVal)) {
          return <LinkRow key={key} label={key.replace(/_/g, ' ')} url={strVal} />;
        }

        return (
          <Row key={key} label={key.replace(/_/g, ' ')} value={strVal.slice(0, 300)} mono={strVal.length > 30 && !strVal.includes(' ')} />
        );
      })}
    </Section>
  );
}
