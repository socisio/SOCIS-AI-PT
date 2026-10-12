'use client';

/**
 * Settings: everything about ME (profile, security, tokens, notifications) and my workspace defaults.
 * Organization-wide settings live in Administration; this page no longer embeds it.
 * The section is in the URL (?section=security). useSearchParams() needs the <Suspense> wrapper below.
 */

import { Suspense, useEffect, useState } from 'react';
import { authApi } from '@/lib/api';
import type { MeUser } from '@/lib/api';
import SettingsShell, { useSection } from '@/components/settings/SettingsShell';
import type { NavGroup } from '@/components/settings/SettingsShell';
import ProfileSection from '@/components/settings/ProfileSection';
import SecuritySection from '@/components/settings/SecuritySection';
import TokensSection from '@/components/settings/TokensSection';
import NotificationsSection from '@/components/settings/NotificationsSection';
import AiSection from '@/components/settings/AiSection';
import ReportsSection from '@/components/settings/ReportsSection';
import ScanDefaultsSection from '@/components/settings/ScanDefaultsSection';
import WebhooksSection from '@/components/settings/WebhooksSection';

const GROUPS: NavGroup[] = [
  { label: 'Account', items: [
    { key: 'profile', label: 'Profile', icon: 'user' },
    { key: 'security', label: 'Security', icon: 'lock' },
    { key: 'tokens', label: 'API tokens', icon: 'key' },
    { key: 'notifications', label: 'Notifications', icon: 'bell' },
  ] },
  { label: 'Workspace', items: [
    { key: 'ai', label: 'AI providers', icon: 'cpu' },
    { key: 'reports', label: 'Reports & branding', icon: 'palette' },
    { key: 'scan', label: 'Scan defaults', icon: 'sliders' },
    { key: 'webhooks', label: 'Webhooks', icon: 'plug' },
  ] },
];

function SettingsInner() {
  const section = useSection(GROUPS);
  const [isAdmin, setIsAdmin] = useState(false);
  useEffect(() => {
    authApi.me().then((r) => { const u = r.data as MeUser; setIsAdmin(Boolean(u.is_superuser) || u.role === 'admin'); }).catch(() => {});
  }, []);

  return (
    <SettingsShell
      title="Settings" subtitle="Manage your account, security and personal preferences." groups={GROUPS} active={section}
      callout={isAdmin ? { title: 'Organization settings', text: 'Users, single sign-on, AI providers and policies are managed in Administration.', href: '/admin', cta: 'Open Administration' } : undefined}
    >
      {section === 'profile' && <ProfileSection />}
      {section === 'security' && <SecuritySection />}
      {section === 'tokens' && <TokensSection />}
      {section === 'notifications' && <NotificationsSection />}
      {section === 'ai' && <AiSection />}
      {section === 'reports' && <ReportsSection />}
      {section === 'scan' && <ScanDefaultsSection />}
      {section === 'webhooks' && <WebhooksSection />}
    </SettingsShell>
  );
}

export default function SettingsPage() {
  return <Suspense fallback={null}><SettingsInner /></Suspense>;
}
