'use client';
import { useEffect, useState } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { LogOut, ChevronRight, ChevronLeft, ExternalLink, X } from 'lucide-react';
import { authApi } from '@/lib/api';
import { visibleGroups, isActive } from '@/lib/nav';

export default function Sidebar({
  isAdmin, open, onClose,
}: { isAdmin: boolean; open: boolean; onClose: () => void }) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  // On tablet-sized screens the menu starts as an icon rail.
  useEffect(() => {
    if (window.matchMedia('(min-width: 761px) and (max-width: 1100px)').matches) setCollapsed(true);
  }, []);

  const groups = visibleGroups(isAdmin);
  // The mobile drawer always shows full labels.
  const rail = collapsed && !open;

  const handleLogout = async () => {
    try { await authApi.logout(); } catch { /* clear cookies regardless */ }
    window.location.href = '/login';
  };

  return (
    <aside className={`sidebar${open ? ' open' : ''}`} style={{ width: rail ? 64 : 240 }} aria-label="Sidebar">
      {/* Brand — the logo image and its size are unchanged */}
      <div style={{
        padding: rail ? '1rem 0' : '1.25rem',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: rail ? 'center' : 'flex-start',
        gap: '0.75rem',
        minHeight: 68,
      }}>
        {!rail && (
          <div style={{ position: 'relative', width: 170, height: 52, flexShrink: 0 }}>
            <Image src="/logo.png" alt="SOCIS-AI-PT" fill sizes="170px" style={{ objectFit: 'contain', objectPosition: 'left center' }} priority />
          </div>
        )}
        <button
          className="icon-btn collapse-btn"
          onClick={() => setCollapsed(!collapsed)}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          style={{ marginLeft: rail ? 0 : 'auto', width: 28, height: 28 }}
        >
          {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </button>
        <button className="icon-btn burger" onClick={onClose} aria-label="Close navigation" style={{ marginLeft: 'auto' }}>
          <X size={18} />
        </button>
      </div>

      {/* Navigation */}
      <nav aria-label="Main navigation" style={{ flex: 1, padding: '0.25rem 0.625rem 0.75rem', display: 'flex', flexDirection: 'column', gap: 2 }}>
        {groups.map((g, gi) => (
          <div key={g.label} style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {rail ? (gi > 0 ? <div className="nav-divider" /> : null) : <div className="nav-group-label">{g.label}</div>}
            {g.items.map(({ href, label, icon: Icon, external }) => {
              const style = { justifyContent: rail ? 'center' : 'flex-start' } as const;
              if (external) {
                return (
                  <a
                    key={href}
                    href={href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="nav-item"
                    style={style}
                    title={rail ? label : 'Open monitoring dashboards'}
                  >
                    <Icon size={17} style={{ flexShrink: 0 }} />
                    {!rail && <span>{label}</span>}
                    {!rail && <ExternalLink size={13} style={{ marginLeft: 'auto', opacity: 0.5, flexShrink: 0 }} />}
                  </a>
                );
              }
              const active = isActive(pathname, href);
              return (
                <Link
                  key={href}
                  href={href}
                  className={`nav-item ${active ? 'active' : ''}`}
                  style={style}
                  title={rail ? label : undefined}
                  aria-current={active ? 'page' : undefined}
                >
                  <Icon size={17} style={{ flexShrink: 0 }} />
                  {!rail && <span>{label}</span>}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div style={{ padding: '0.75rem 0.625rem', borderTop: '1px solid var(--border)' }}>
        <button
          onClick={handleLogout}
          className="nav-item btn-danger"
          style={{
            width: '100%', justifyContent: rail ? 'center' : 'flex-start',
            border: 'none', background: 'transparent',
          }}
          title={rail ? 'Logout' : undefined}
        >
          <LogOut size={16} />
          {!rail && <span>Logout</span>}
        </button>
      </div>
    </aside>
  );
}
