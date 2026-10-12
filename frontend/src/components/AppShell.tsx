'use client';

/**
 * AppShell — sidebar, top bar (breadcrumbs, search, theme, notifications, account) and page area.
 * Owns the small bits of shell state: mobile drawer, command palette and who is signed in.
 */

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Search } from 'lucide-react';
import Sidebar from '@/components/Sidebar';
import ThemeToggle from '@/components/ThemeToggle';
import NotificationsCenter from '@/components/NotificationsCenter';
import CommandPalette from '@/components/CommandPalette';
import Icon from '@/components/ui/Icon';
import { authApi } from '@/lib/api';
import { crumbsFor } from '@/lib/nav';

function initials(name: string): string {
  const parts = name.replace(/@.*$/, '').split(/[\s._-]+/).filter(Boolean);
  if (parts.length === 0) return '?';
  const first = parts[0][0] || '';
  const second = parts.length > 1 ? parts[parts.length - 1][0] : (parts[0][1] || '');
  return (first + second).toUpperCase();
}

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [navOpen, setNavOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [userName, setUserName] = useState('');
  const [userEmail, setUserEmail] = useState('');
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const [mod, setMod] = useState('Ctrl');

  useEffect(() => {
    let mounted = true;
    authApi.me()
      .then((res) => {
        if (!mounted) return;
        const d = res?.data || {};
        setIsAdmin(Boolean(d.is_superuser) || String(d.role || '').toLowerCase() === 'admin');
        setUserName(String(d.full_name || d.username || d.email || ''));
        setUserEmail(String(d.email || ''));
      })
      .catch(() => {
        if (!mounted) return;
        setIsAdmin(false);
      });
    return () => { mounted = false; };
  }, []);

  // Close the mobile drawer and the account menu whenever the page changes.
  useEffect(() => { setNavOpen(false); setMenuOpen(false); }, [pathname]);

  // The account menu closes on outside click and Esc.
  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setMenuOpen(false); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey); };
  }, [menuOpen]);

  const signOut = async () => {
    try { await authApi.logout(); } catch { /* clear cookies regardless */ }
    window.location.href = '/login';
  };

  // Ctrl/Cmd+K toggles the command palette.
  useEffect(() => {
    if (/Mac/i.test(navigator.platform)) setMod('\u2318');
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const crumbs = crumbsFor(pathname);

  return (
    <div className="app-shell">
      <Sidebar isAdmin={isAdmin} open={navOpen} onClose={() => setNavOpen(false)} />
      <div className={`sidebar-backdrop${navOpen ? ' open' : ''}`} onClick={() => setNavOpen(false)} aria-hidden="true" />

      <div className="app-main">
        <header className="topbar">
          <button className="icon-btn burger" onClick={() => setNavOpen(true)} aria-label="Open navigation">
            <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16" /></svg>
          </button>

          <nav className="crumbs" aria-label="Breadcrumb">
            {crumbs.group && (
              <>
                <span className="crumb-group">{crumbs.group}</span>
                <span className="crumb-group">/</span>
              </>
            )}
            <strong>{crumbs.page}</strong>
            {crumbs.sub && (
              <>
                <span>/</span>
                <span>{crumbs.sub}</span>
              </>
            )}
          </nav>

          <button className="topbar-search" onClick={() => setPaletteOpen(true)} aria-label="Search pages and actions">
            <Search size={15} />
            <span className="label">Search pages and actions</span>
            <kbd className="kbd">{mod} K</kbd>
          </button>

          <ThemeToggle />
          <NotificationsCenter />
          <div className="acct" ref={menuRef}>
            <button
              className="avatar" style={{ border: 'none', cursor: 'pointer' }} title={userName || 'Account'}
              aria-label="Account menu" aria-haspopup="menu" aria-expanded={menuOpen} onClick={() => setMenuOpen((o) => !o)}
            >
              {initials(userName)}
            </button>
            {menuOpen && (
              <div className="acct-menu" role="menu">
                <div className="hd"><b>{userName || 'Account'}</b><small>{userEmail}</small></div>
                <Link href="/settings?section=profile" role="menuitem"><Icon name="user" size={15} />Profile</Link>
                <Link href="/settings?section=security" role="menuitem"><Icon name="lock" size={15} />Security</Link>
                <Link href="/settings?section=tokens" role="menuitem"><Icon name="key" size={15} />API tokens</Link>
                <button className="dng" role="menuitem" onClick={signOut}><Icon name="logout" size={15} />Sign out</button>
              </div>
            )}
          </div>
        </header>

        <main style={{ flex: 1, overflow: 'auto', background: 'var(--bg-primary)' }}>
          {children}
        </main>
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} isAdmin={isAdmin} />
    </div>
  );
}
