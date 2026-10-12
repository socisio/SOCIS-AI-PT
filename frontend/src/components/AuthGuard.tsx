'use client';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { authApi } from '@/lib/api';

export default function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [verified, setVerified] = useState(false);

  useEffect(() => {
    authApi.me()
      .then(() => setVerified(true))
      .catch(() => {
        router.replace('/login');
      });
  }, [router]);

  if (!verified) return null;
  return <>{children}</>;
}
