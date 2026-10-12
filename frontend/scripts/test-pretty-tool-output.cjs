#!/usr/bin/env node
/* Scan-output formatter test: how every tool's result is shown on the scan detail page.
 *
 * prettyToolOutput() lives inside app/(app)/scans/[id]/page.tsx. This test extracts that function (and its two helpers) from the
 * REAL source, transpiles it with the TypeScript compiler, and runs it against payloads shaped exactly like what the tool servers
 * return (read from mcp-servers/*.py), asserting what a customer would read.
 *
 *   node scripts/test-pretty-tool-output.cjs
 *
 * Needs the `typescript` package (frontend/node_modules, or global). Without it the test SKIPs rather than failing.
 */
const fs = require('fs');
const path = require('path');

let P = 0, F = 0;
const t = (name, ok, extra) => { if (ok) { P++; console.log('PASS ', name); } else { F++; console.log('FAIL ', name, extra === undefined ? '' : extra); } };
const finish = () => { console.log(`\nRESULT: ${P} passed, ${F} failed`); process.exit(F ? 1 : 0); };

let ts;
for (const base of [path.join(__dirname, '..'), process.cwd()]) {
  try { ts = require(require.resolve('typescript', { paths: [base] })); break; } catch (e) { /* try next */ }
}
if (!ts) {
  try { ts = require(path.join(require('child_process').execSync('npm root -g').toString().trim(), 'typescript')); } catch (e) { /* none */ }
}
if (!ts) { console.log('SKIP: the typescript package is not available here (this check runs where the frontend is built)'); finish(); }

// prettyToolOutput() lives in its own module (src/lib/prettyToolOutput.ts) specifically so it can be imported and
// tested directly, rather than text-extracted out of the page component.
const srcPath = path.join(__dirname, '..', 'src', 'lib', 'prettyToolOutput.ts');
if (!fs.existsSync(srcPath)) { t('prettyToolOutput.ts exists', false); finish(); }
const src = fs.readFileSync(srcPath, 'utf-8');
const js = ts.transpileModule(src, { compilerOptions: { target: 'ES2020', module: 'CommonJS' } }).outputText;
const mod = { exports: {} };
new Function('module', 'exports', js + '\nmodule.exports.prettyToolOutput = prettyToolOutput;')(mod, mod.exports);
const pretty = (o, name) => mod.exports.prettyToolOutput(typeof o === 'string' ? o : JSON.stringify(o), name || '');

// ── structure: the specific MITRE/ExploitDB formatters must run BEFORE the broad "anything with total/count" catch-all ──
// (when they sat after it they were dead code: the catch-all swallowed every list-shaped result first)
const pos = (needle) => src.indexOf(needle);
t('the MITRE formatter runs before the broad total/count catch-all (otherwise it never runs)', pos('// ── 12. MITRE ATT&CK') > 0 && pos('// ── 12. MITRE ATT&CK') < pos('// ── 15. CVE / CISA KEV / PoC / EPSS total'));
t('the ExploitDB formatter runs before the broad total/count catch-all', pos('// ── 13. ExploitDB') > 0 && pos('// ── 13. ExploitDB') < pos('// ── 15. CVE / CISA KEV / PoC / EPSS total'));

// ── MITRE ATT&CK (shapes from mcp-servers/mitre_server.py: _clean_technique / _clean_group / _clean_software) ──
const tech = { id: 'T1055', stix_id: 'attack-pattern--1', name: 'Process Injection', description: 'Adversaries may inject code into processes.', tactics: ['Defense Evasion', 'Privilege Escalation'], platforms: ['Windows', 'Linux'], is_subtechnique: false, detection: 'Monitor API calls.', data_sources: [], permissions_required: [], revoked: false, deprecated: false };
let out = pretty(tech);
t('a single technique shows its ID, name, tactics, platforms, description and detection', out.includes('ID          : T1055') && out.includes('Name        : Process Injection') && out.includes('Tactics     : Defense Evasion, Privilege Escalation') && out.includes('Platforms   : Windows, Linux') && out.includes('Adversaries may inject') && out.includes('Detection   : Monitor API calls.'), out);
out = pretty({ query: 'injection', total: 2, results: [tech, { ...tech, id: 'T1059', name: 'Command Injection' }] });
t('search_techniques/search_groups/search_software (which report "total", not "count") list names with their IDs', out.startsWith('Results : 2') && out.includes('T1055 — Process Injection') && out.includes('T1059 — Command Injection'), out);
out = pretty({ tactic: 'defense-evasion', techniques: [tech], count: 1 });
t('the get_* list tools (which report "count") list names with their IDs', out.startsWith('Results : 1') && out.includes('T1055 — Process Injection'), out);
out = pretty({ group: 'G0016', techniques: Array.from({ length: 20 }, (_, n) => ({ ...tech, id: `T${1000 + n}`, name: `Technique ${n}` })), count: 20 });
t('a long list is cut at 15 with a clear "and N more"', out.includes('Technique 14') && !out.includes('Technique 15') && out.includes('... and 5 more'), out);
out = pretty({ id: 'G0016', stix_id: 'intrusion-set--1', name: 'APT29', description: 'A threat group.', aliases: ['Cozy Bear', 'The Dukes'] });
t('a single group shows its aliases', out.includes('Name        : APT29') && out.includes('Aliases     : Cozy Bear, The Dukes'), out);
out = pretty({ software: [{ id: 'S0002', stix_id: 'x', name: 'Mimikatz', type: 'tool', description: '...', platforms: ['Windows'], aliases: [] }], count: 1 });
t('a software list shows the software name with its ID', out.includes('S0002 — Mimikatz'), out);
out = pretty({ name: 'Workflow Layer - example.com', versions: { attack: '15' }, domain: 'enterprise-attack', description: 'Generated by SOCIS-AI-PT — scope: tactic (defense-evasion)', techniques: [{ techniqueID: 'T1055', color: '#fff', comment: 'x', enabled: true, showSubtechniques: false }], gradient: {}, legendItems: [] });
t('generate_layer (an ATT&CK Navigator file, not meant to be read raw) is summarised in three lines', out.split('\n').length === 3 && out.includes('Techniques : 1 highlighted'), out);
t('an ATT&CK "not found" error reads as a one-line warning', pretty({ error: 'Technique T9999 not found' }) === '⚠ Technique T9999 not found');

// ── ExploitDB (shapes from mcp-servers/exploitdb_server.py: _row_to_dict + the handlers) ──
const ex = (id, d, extra) => ({ id, description: d, date: '2021-12-10', author: 'a', type: 'remote', platform: 'multiple', port: '', verified: false, codes: '', tags: [], file: 'x', source_url: '', cve: [], url: `https://www.exploit-db.com/exploits/${id}`, ...extra });
out = pretty({ query: { query: 'log4j', limit: 10, offset: 0, platform: '' }, count: 2, exploits: [ex('50592', 'Apache Log4j2 - RCE', { verified: true, cve: ['CVE-2021-44228'] }), ex('50593', 'Log4j - Denial of Service')] });
t('search_exploits (which echoes its whole argument dict as "query") shows a readable query line without paging noise', out.includes('Query      : query=log4j') && !out.includes('limit') && !out.includes('offset') && !out.includes('{'), out);
t('each exploit shows EDB-ID, title, a [verified] flag and its CVEs', out.includes('EDB-50592 — Apache Log4j2 - RCE [verified] (CVE-2021-44228)') && out.includes('EDB-50593 — Log4j - Denial of Service') && !out.includes('EDB-50593 — Log4j - Denial of Service ['), out);
out = pretty({ cve: 'CVE-2021-44228', count: 1, exploits: [ex('50592', 'Apache Log4j2 - RCE')] });
t('find_by_cve shows the CVE it searched for', out.includes('Query      : CVE-2021-44228') && out.includes('Results    : 1'), out);
out = pretty({ count: 1, exploits: [ex('1', 'Newest exploit')] });
t('get_recent_exploits (no query context) shows just the count and the list', out.startsWith('Results    : 1') && !out.includes('Query'), out);
out = pretty({ platform: 'linux', count: 0, exploits: [] });
t('an empty result reads "Results : 0" rather than a blank panel', out.includes('Results    : 0'), out);
out = pretty({ ...ex('50592', 'Apache Log4j2 - RCE', { verified: true, cve: ['CVE-2021-44228'] }), found: true, code: Array.from({ length: 40 }, (_, n) => `line ${n + 1}`).join('\n') });
t('get_exploit shows the details, then only the first 25 lines of source with a pointer to the rest (not the whole file on one line)', out.includes('EDB-50592 — Apache Log4j2 - RCE') && out.includes('Verified : yes') && out.includes('Source (40 lines):') && out.includes('line 25') && !out.includes('line 26') && out.includes('... and 15 more lines'), out);
t('an exploit that is not in the local cache reads as a one-line warning', pretty({ found: false, id: '999', message: 'EDB-999 not found in local cache' }) === '⚠ EDB-999 not found in local cache');
out = pretty({ total_exploits: 48000, verified_exploits: 12000, unverified: 36000, types: { remote: 20000, webapps: 15000 }, top_platforms: { linux: 12000, windows: 10000 }, top_authors: [{ author: 'm', count: 5 }], latest_date: '2026-01-01' });
t('get_statistics shows the real top platforms and types instead of "{ ... }"', out.includes('Total Exploits : 48000 (12000 verified)') && out.includes('linux (12000), windows (10000)') && out.includes('remote (20000)') && !out.includes('{ ... }'), out);

// ── regressions: shapes that must keep rendering exactly as before (the catch-all section still owns them) ──
out = pretty({ total: 1, results: [{ cve_id: 'CVE-2021-44228', severity: 'CRITICAL', cvss_score: 10.0, description: 'Apache Log4j2 RCE' }] });
t('CVE results still show severity, CVSS and the title', out.startsWith('Matches : 1') && out.includes('CVE-2021-44228  [CRITICAL]  CVSS:10'), out);
out = pretty({ total_matches: 1, results: [{ cve_id: 'CVE-2021-44228', vendor: 'Apache', product: 'Log4j2', name: 'Apache Log4j2 RCE', description: '...' }] });
t('CISA KEV results (which also have a "name") are NOT mistaken for MITRE items: they keep their own layout', out.startsWith('Matches : 1') && out.includes('Apache Log4j2 RCE  (Apache)') && !out.includes('Results'), out);
out = pretty({ keyword: 'log4j', total: 1, results: [{ cve_id: 'CVE-2021-44228', published: '2021-12-10', description: 'Apache Log4j2 RCE', cvss_score: 10.0, severity: 'CRITICAL', cwes: null, references: [], nvd_url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' }] });
t('search_cves (real shape: "total" + items with a cve_id) keeps its CVE layout and is not treated as MITRE', out.startsWith('Matches : 1') && out.includes('CVE-2021-44228  [CRITICAL]') && !out.includes('Results'), out);
// Defence in depth: a KEV-style item (has a name, but a cve_id rather than an id) under a "total" wrapper. Today's KEV uses
// "total_matches", which keeps it out of the MITRE branch on its own; this pins the "needs an id" rule for the day that changes.
out = pretty({ total: 1, results: [{ cve_id: 'CVE-2021-44228', vendor: 'Apache', name: 'Apache Log4j2 RCE', description: '...' }] });
t('an item with a name but a cve_id (not an id) under a "total" wrapper is still NOT treated as MITRE', out.startsWith('Matches : 1') && !out.includes('Results'), out);
out = pretty({ target: '10.0.0.5', open_ports: [{ port: 22, service: 'ssh' }], os_guess: 'Linux' });
t('nmap results are unchanged', out.includes('Open Ports : 1') && out.includes('22/tcp') && out.includes('OS         : Linux'), out);
t('plain text passes through untouched', pretty('plain text from a tool') === 'plain text from a tool');
t('empty output says so', pretty('') === '[No output]');

finish();
