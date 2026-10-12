'use client';

/**
 * SettingsShell — the page frame shared by Settings and Administration: title, a left section menu grouped by scope,
 * and the content. The section is in the URL (?section=security) so links, refresh and the back button all work.
 * It uses useSearchParams(), so the PAGE that renders it must wrap it in <Suspense> (next build requires that).
 */

import Link from 'next/link';
import { usePathname, useSearchParams } from 'next/navigation';
import Icon from '@/components/ui/Icon';
import type { IconName } from '@/components/ui/Icon';

export interface NavItem { key: string; label: string; icon: IconName }
export interface NavGroup { label: string; items: NavItem[] }

/** The active section from ?section=, falling back to the first item when it is missing or unknown. */
export function useSection(groups: NavGroup[]): string {
  const sp = useSearchParams();
  const all = groups.flatMap((g) => g.items.map((i) => i.key));
  const want = sp.get('section') ?? '';
  return all.includes(want) ? want : all[0];
}

export default function SettingsShell({
  title, subtitle, badge, groups, active, callout, children,
}: {
  title: string;
  subtitle: string;
  badge?: string;
  groups: NavGroup[];
  active: string;
  callout?: { title: string; text: string; href: string; cta: string };
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  return (
    <div className="pg">
      <div className="pg-head">
        <div>
          <h1 style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            {title} {badge && <span className="pill purple" style={{ fontSize: '0.7rem' }}>{badge}</span>}
          </h1>
          <p>{subtitle}</p>
        </div>
      </div>
      <div className="set-layout">
        <div className="set-side">
          <nav className="subnav" aria-label={`${title} sections`}>
            {groups.map((g) => (
              <div key={g.label} style={{ display: 'contents' }}>
                <div className="lbl">{g.label}</div>
                {g.items.map((i) => (
                  <Link
                    key={i.key}
                    href={`${pathname}?section=${i.key}`}
                    replace
                    scroll={false}
                    className={i.key === active ? 'on' : ''}
                    aria-current={i.key === active ? 'page' : undefined}
                  >
                    <Icon name={i.icon} size={16} />
                    {i.label}
                  </Link>
                ))}
              </div>
            ))}
          </nav>
          {callout && (
            <div className="callout">
              <strong>{callout.title}</strong>
              {callout.text}
              <br />
              <Link href={callout.href}>{callout.cta} <Icon name="arrow" size={13} /></Link>
            </div>
          )}
        </div>
        <div style={{ minWidth: 0 }}>{children}</div>
      </div>
    </div>
  );
}

export function SectionHead({ title, desc, actions }: { title: string; desc: string; actions?: React.ReactNode }) {
  return (
    <div className="sec-head" style={actions ? { display: 'flex', alignItems: 'flex-end', gap: '1rem' } : undefined}>
      <div>
        <h2>{title}</h2>
        <p>{desc}</p>
      </div>
      {actions && <div style={{ marginLeft: 'auto' }}>{actions}</div>}
    </div>
  );
}
