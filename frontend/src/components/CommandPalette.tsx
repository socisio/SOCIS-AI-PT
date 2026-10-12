'use client';

/**
 * CommandPalette — Ctrl/Cmd+K jump-to for pages and common actions.
 * Keyboard: type to filter, Up/Down to move, Enter to open, Esc to close.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Plus, FileText } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { visibleGroups } from '@/lib/nav';

interface Cmd {
  id: string;
  label: string;
  hint: string;
  href: string;
  external?: boolean;
  icon: LucideIcon;
}

export default function CommandPalette({
  open, onClose, isAdmin,
}: { open: boolean; onClose: () => void; isAdmin: boolean }) {
  const router = useRouter();
  const [q, setQ] = useState('');
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const cmds = useMemo<Cmd[]>(() => {
    const pages: Cmd[] = visibleGroups(isAdmin).flatMap((g) =>
      g.items.map((i) => ({ id: i.href, label: i.label, hint: g.label, href: i.href, external: i.external, icon: i.icon })),
    );
    return [
      { id: 'action-new-scan', label: 'New scan', hint: 'Action', href: '/scans/new', icon: Plus },
      { id: 'action-report', label: 'Generate report', hint: 'Action', href: '/reports', icon: FileText },
      ...pages,
    ];
  }, [isAdmin]);

  const results = useMemo(() => {
    const t = q.trim().toLowerCase();
    return t ? cmds.filter((c) => c.label.toLowerCase().includes(t) || c.hint.toLowerCase().includes(t)) : cmds;
  }, [q, cmds]);

  useEffect(() => {
    if (open) {
      setQ('');
      setIdx(0);
      const t = setTimeout(() => inputRef.current?.focus(), 0);
      return () => clearTimeout(t);
    }
  }, [open]);

  useEffect(() => { setIdx(0); }, [q]);

  if (!open) return null;

  const go = (c: Cmd) => {
    onClose();
    if (c.external) window.open(c.href, '_blank', 'noopener,noreferrer');
    else router.push(c.href);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setIdx((i) => Math.min(i + 1, results.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setIdx((i) => Math.max(i - 1, 0)); }
    else if (e.key === 'Enter') { e.preventDefault(); const c = results[idx]; if (c) go(c); }
    else if (e.key === 'Escape') { e.preventDefault(); onClose(); }
  };

  return (
    <div className="cmdk-backdrop" onMouseDown={onClose}>
      <div className="cmdk" role="dialog" aria-modal="true" aria-label="Command palette" onMouseDown={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Search pages and actions"
          aria-label="Search pages and actions"
          role="combobox"
          aria-expanded="true"
          aria-controls="cmdk-list"
          aria-activedescendant={results[idx] ? `cmdk-opt-${idx}` : undefined}
        />
        {results.length === 0 ? (
          <div className="empty">No matches. Try a page name such as Scans or Reports.</div>
        ) : (
          <ul id="cmdk-list" role="listbox">
            {results.map((c, i) => {
              const Icon = c.icon;
              return (
                <li
                  key={c.id}
                  id={`cmdk-opt-${i}`}
                  role="option"
                  aria-selected={i === idx}
                  onMouseEnter={() => setIdx(i)}
                  onClick={() => go(c)}
                >
                  <Icon size={16} />
                  {c.label}
                  <small>{c.hint}</small>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}
