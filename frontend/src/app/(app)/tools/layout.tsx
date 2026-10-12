'use client';

import React, { Suspense } from 'react';
import Link from 'next/link';
import { usePathname, useSearchParams } from 'next/navigation';
import { Wand2, ClipboardList, List } from 'lucide-react';

const TOOL_TABS = [
  { href: '/tools/payload-generator', tab: 'generator', label: 'Payload Generator', icon: Wand2 },
  { href: '/tools/payload-generator?tab=wordlist', tab: 'wordlist', label: 'Wordlist Builder', icon: ClipboardList },
];

// useSearchParams() must sit under a <Suspense> boundary: without one, `next build` fails for every static page under /tools
// (next dev never complains, which is why this stayed hidden). Only the tab bar needs the query string, so only it is wrapped.
function ToolTabs() {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const activeTab = searchParams.get('tab') ?? 'generator';
  return (
    <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--border)' }}>
      {TOOL_TABS.map((tab) => {
        const isActive = pathname === '/tools/payload-generator' && activeTab === tab.tab;
        return (
          <Link
            key={tab.tab}
            href={tab.href}
            style={{
              display: 'flex', alignItems: 'center', gap: 8, padding: '0.5rem 1rem',
              fontSize: '0.8125rem', fontWeight: 500, textDecoration: 'none', marginBottom: -1,
              color: isActive ? 'var(--cyan)' : 'var(--text-muted)',
              borderBottom: `2px solid ${isActive ? 'var(--cyan)' : 'transparent'}`,
            }}
          >
            <tab.icon size={16} />
            {tab.label}
          </Link>
        );
      })}
    </div>
  );
}

export default function ToolsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '1.5rem 1.75rem 0' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '0.75rem' }}>
          <List size={20} style={{ color: 'var(--cyan)' }} />
          <h1>Tools</h1>
        </div>
        <Suspense fallback={<div style={{ height: 38, borderBottom: '1px solid var(--border)' }} />}>
          <ToolTabs />
        </Suspense>
      </div>
      <div>{children}</div>
    </div>
  );
}
