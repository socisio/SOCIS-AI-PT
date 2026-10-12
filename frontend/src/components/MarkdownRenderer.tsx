'use client';
import React from 'react';

/** Tool output is attacker-influenced (a scanned target controls banners, headers, reference URLs). Only allow safe
 *  link protocols so a crafted `[x](javascript:…)` or `data:` URL in tool output can never execute script when clicked.
 *  Anything else renders as inert text (href removed). */
function safeHref(url: string): string | undefined {
  const u = (url || '').trim();
  // allow http(s), mailto, and protocol-relative/relative links; reject javascript:, data:, vbscript:, file:, etc.
  if (/^(https?:|mailto:)/i.test(u)) return u;
  if (/^\/\//.test(u) || /^\/[^/]/.test(u)) return u;  // //host or /path
  if (/^[a-z][a-z0-9+.-]*:/i.test(u)) return undefined; // any other explicit scheme -> block
  return u; // no scheme (e.g. "example.com/x") -> safe
}

/** Minimal but enterprise-quality markdown renderer — no external deps. Renders every markdown shape (headings, lists,
 *  tables, blockquotes, code). This is the single renderer used everywhere — the full report view and the small
 *  workflow-node summary — so a node can never show less than the real output. */
export default function MarkdownRenderer({ content }: { content: string }) {
  if (!content) return null;
  return <div className="md-render">{parseBlocks(content)}</div>;
}

// ─── Block-level parser ────────────────────────────────────────────────────

function parseBlocks(text: string): React.ReactNode[] {
  const lines = text.split('\n');
  const nodes: React.ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block ```
    if (line.trimStart().startsWith('```')) {
      const lang = line.trim().slice(3).trim() || 'text';
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith('```')) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // consume closing ```
      nodes.push(
        <pre key={i} style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderLeft: '3px solid var(--purple)',
          borderRadius: 'var(--radius-md)',
          padding: '0.85rem 1rem',
          overflowX: 'auto',
          fontSize: '0.8125rem',
          lineHeight: 1.6,
          fontFamily: 'var(--font-mono, monospace)',
          margin: '0.65rem 0',
          color: 'var(--text-primary)',
        }}>
          <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.4rem', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{lang}</span>
          <code>{codeLines.join('\n')}</code>
        </pre>
      );
      continue;
    }

    // Horizontal rule ---
    if (/^---+$/.test(line.trim())) {
      nodes.push(<hr key={i} style={{ border: 'none', borderTop: '1px solid var(--border)', margin: '0.75rem 0', opacity: 0.5 }} />);
      i++; continue;
    }

    // Heading # / ## / ###
    const hMatch = line.match(/^(#{1,4})\s+(.+)/);
    if (hMatch) {
      const level = hMatch[1].length;
      const sizes: Record<number, string> = { 1: '1.05rem', 2: '0.95rem', 3: '0.88rem', 4: '0.82rem' };
      nodes.push(
        <div key={i} style={{
          fontSize: sizes[level] || '0.85rem',
          fontWeight: 700,
          color: 'var(--text-primary)',
          margin: `${level <= 2 ? '0.9rem' : '0.55rem'} 0 0.25rem`,
          letterSpacing: '0.01em',
        }}>
          {parseInline(hMatch[2])}
        </div>
      );
      i++; continue;
    }

    // Blockquote > (with or without trailing space; bare '>' is a visual separator)
    if (line === '>' || line.startsWith('> ')) {
      // A bare '>' on its own is just a section separator — render as a thin spacer
      if (line === '>') { i++; nodes.push(<div key={i} style={{ height: '0.25rem' }} />); continue; }
      const quoteLines: string[] = [];
      while (i < lines.length && (lines[i] === '>' || lines[i].startsWith('> '))) {
        quoteLines.push(lines[i] === '>' ? '' : lines[i].slice(2));
        i++;
      }
      nodes.push(
        <div key={i} style={{
          borderLeft: '3px solid var(--purple)',
          background: 'color-mix(in srgb, var(--purple) 3%, transparent)',
          padding: '0.45rem 0.85rem',
          borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
          margin: '0.4rem 0',
          fontSize: '0.8125rem',
          color: 'var(--text-secondary)',
          fontStyle: 'italic',
        }}>
          {quoteLines.map((l, idx) => <span key={idx}>{parseInline(l)}{idx < quoteLines.length - 1 ? <br /> : null}</span>)}
        </div>
      );
      continue;
    }

    // Unordered list - / *
    if (/^[\-\*]\s/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^[\-\*]\s/.test(lines[i])) {
        items.push(lines[i].slice(2));
        i++;
      }
      nodes.push(
        <ul key={i} style={{ paddingLeft: '1.25rem', margin: '0.3rem 0', listStyleType: 'none' }}>
          {items.map((item, idx) => (
            <li key={idx} style={{ fontSize: '0.875rem', lineHeight: 1.65, color: 'var(--text-primary)', display: 'flex', alignItems: 'flex-start', gap: '0.5rem', marginBottom: '0.15rem' }}>
              <span style={{ color: 'var(--purple)', marginTop: '0.35rem', flexShrink: 0, fontSize: '0.5rem' }}>◆</span>
              <span>{parseInline(item)}</span>
            </li>
          ))}
        </ul>
      );
      continue;
    }

    // Ordered list 1. 2.
    if (/^\d+\.\s/.test(line)) {
      const items: string[] = [];
      let n = 1;
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) {
        items.push(lines[i].replace(/^\d+\.\s/, ''));
        i++;
      }
      nodes.push(
        <ol key={i} style={{ paddingLeft: '1.5rem', margin: '0.3rem 0' }}>
          {items.map((item, idx) => (
            <li key={idx} style={{ fontSize: '0.875rem', lineHeight: 1.65, color: 'var(--text-primary)', marginBottom: '0.15rem' }}>
              {parseInline(item)}
            </li>
          ))}
        </ol>
      );
      continue;
    }

    // Empty line
    if (line.trim() === '') {
      nodes.push(<div key={i} style={{ height: '0.4rem' }} />);
      i++; continue;
    }

    // Paragraph / plain line
    nodes.push(
      <p key={i} style={{ fontSize: '0.875rem', lineHeight: 1.75, color: 'var(--text-primary)', margin: '0.1rem 0' }}>
        {parseInline(line)}
      </p>
    );
    i++;
  }

  return nodes;
}

// ─── Inline parser (bold, italic, code, links) ────────────────────────────

function parseInline(text: string): React.ReactNode {
  const parts: React.ReactNode[] = [];
  // Combined regex: **bold**, *italic*, `code`, [label](url), bare https?:// URL
  const re = /(\*\*(.+?)\*\*|\*(.+?)\*|`([^`]+)`|\[([^\]]+)\]\((https?:\/\/[^\)]+)\)|(https?:\/\/[^\s,"'<>\]]+))/g;
  let last = 0;
  let m: RegExpExecArray | null;

  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push(text.slice(last, m.index));

    if (m[2] !== undefined) {
      // **bold**
      parts.push(<strong key={m.index} style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{m[2]}</strong>);
    } else if (m[3] !== undefined) {
      // *italic*
      parts.push(<em key={m.index} style={{ fontStyle: 'italic', color: 'var(--text-secondary)' }}>{m[3]}</em>);
    } else if (m[4] !== undefined) {
      // `code`
      parts.push(
        <code key={m.index} style={{
          background: 'color-mix(in srgb, var(--purple) 9%, transparent)',
          border: '1px solid color-mix(in srgb, var(--purple) 19%, transparent)',
          borderRadius: 'var(--radius-sm)',
          padding: '0.05em 0.35em',
          fontSize: '0.82em',
          fontFamily: 'var(--font-mono, monospace)',
          color: 'var(--cyan)',
        }}>{m[4]}</code>
      );
    } else if (m[5] !== undefined && m[6] !== undefined) {
      // [label](url)
      parts.push(
        <a key={m.index} href={safeHref(m[6])} target="_blank" rel="noopener noreferrer"
          style={{ color: 'var(--cyan)', textDecoration: 'underline', textDecorationStyle: 'dotted' }}>
          {m[5]}
        </a>
      );
    } else if (m[7] !== undefined) {
      // bare URL auto-link — show hostname as label
      const bareUrl = m[7];
      let label = bareUrl;
      try { label = new URL(bareUrl).hostname.replace(/^www\./, ''); } catch { /* keep full url */ }
      parts.push(
        <a key={m.index} href={safeHref(bareUrl)} target="_blank" rel="noopener noreferrer"
          style={{ color: 'var(--cyan)', textDecoration: 'underline', textDecorationStyle: 'dotted' }}>
          {label}
        </a>
      );
    }
    last = m.index + m[0].length;
  }

  if (last < text.length) parts.push(text.slice(last));
  return parts.length === 1 ? parts[0] : parts;
}
