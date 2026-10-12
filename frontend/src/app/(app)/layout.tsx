import type { Metadata } from 'next';
import AppShell from '@/components/AppShell';
import AuthGuard from '@/components/AuthGuard';

export const metadata: Metadata = { title: 'SOCIS-AI-PT' };

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <AppShell>{children}</AppShell>
    </AuthGuard>
  );
}
