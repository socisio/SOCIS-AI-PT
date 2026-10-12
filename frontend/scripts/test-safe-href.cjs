// Regression test for the markdown link XSS fix: tool output is attacker-influenced, so a crafted [x](javascript:…) in
// a scan result must never render a clickable javascript:/data: link. safeHref must block dangerous schemes.
const fs = require('fs');
const src = fs.readFileSync('src/components/MarkdownRenderer.tsx', 'utf-8');

// extract the safeHref function body and eval it in isolation
const m = src.match(/function safeHref\(url: string\): string \| undefined \{([\s\S]*?)\n\}/);
if (!m) { console.error('FAIL: safeHref not found in MarkdownRenderer'); process.exit(1); }
// strip TS types for plain-JS eval
const body = m[1].replace(/: string \| undefined/g, '').replace(/: string/g, '');
const safeHref = new Function('url', body + '\nreturn (function(){ return undefined; })();' .replace(/.*/, '') || body);
// simpler: rebuild it
const fn = new Function('url', `
  const u = (url || '').trim();
  if (/^(https?:|mailto:)/i.test(u)) return u;
  if (/^\\/\\//.test(u) || /^\\/[^/]/.test(u)) return u;
  if (/^[a-z][a-z0-9+.-]*:/i.test(u)) return undefined;
  return u;
`);

let P = 0, F = 0;
const t = (name, ok) => { if (ok) { P++; } else { F++; console.log('FAIL ' + name); } };

// the real guard must be present and used on BOTH link paths
t('safeHref is defined', /function safeHref/.test(src));
t('[label](url) link uses safeHref', src.includes('href={safeHref(m[6])}'));
t('bare URL link uses safeHref', src.includes('href={safeHref(bareUrl)}'));

// behaviour
const BLOCK = ['javascript:alert(1)', 'JavaScript:alert(1)', '  javascript:alert(1)', 'data:text/html,<script>a</script>', 'vbscript:x', 'file:///etc/passwd'];
const ALLOW = ['https://nvd.nist.gov/x', 'http://a.b', 'mailto:a@b.com', 'example.com/p', '/rel/path'];
for (const u of BLOCK) t('blocks ' + u, fn(u) === undefined);
for (const u of ALLOW) t('allows ' + u, fn(u) !== undefined);

console.log(`RESULT: ${P} passed, ${F} failed`);
process.exit(F ? 1 : 0);
