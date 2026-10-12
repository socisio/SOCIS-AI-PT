'use client';
import { Suspense, useEffect, useRef, useState } from 'react';
import { useParams, useRouter, useSearchParams } from 'next/navigation';
import { authApi } from '@/lib/api';

/**
 * Where Google / Microsoft send the browser back to (the backend builds `${FRONTEND_URL}/auth/callback/<provider>`). This page did not
 * exist, so every SSO sign-in ended in a 404. It hands the one-time `code` and `state` to the backend (which also needs the `oauth_state`
 * cookie set when the sign-in started), then goes to the dashboard, or, for an account with two-factor, to the code step on the login page.
 */
function Callback() {
  const router = useRouter();
  const params = useParams<{ provider: string }>();
  const search = useSearchParams();
  const [error, setError] = useState('');
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;          // the code is single-use: never send it twice (React strict mode runs effects twice in dev)
    started.current = true;
    const provider = String(params?.provider || '');
    const code = search.get('code');
    const state = search.get('state');
    const providerError = search.get('error_description') || search.get('error');
    if (!['google', 'microsoft'].includes(provider)) { setError('Unknown sign-in provider.'); return; }
    if (providerError) { setError(providerError); return; }
    if (!code || !state) { setError('The sign-in response was incomplete. Please try again.'); return; }
    authApi.ssoCallback(provider as 'google' | 'microsoft', code, state)
      .then((res: any) => {
        if (res.status === 202 && res.data?.mfa_required && res.data?.mfa_token) {
          try { sessionStorage.setItem('socis_sso_mfa', String(res.data.mfa_token)); } catch { /* storage unavailable */ }
          router.replace('/login?sso_mfa=1');
          return;
        }
        router.replace('/dashboard');
      })
      .catch((e: any) => setError(e?.response?.data?.detail || 'Single sign-on failed. Please try again or use your password.'));
  }, [params, search, router]);

  return (
    <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', background: 'var(--bg-primary)', color: 'var(--text-primary)', padding: '1.5rem' }}>
      <div style={{ maxWidth: 420, textAlign: 'center' }}>
        {error ? (
          <>
            <h1 style={{ fontSize: '1.125rem', fontWeight: 700, marginBottom: '0.5rem' }}>Sign-in did not complete</h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', lineHeight: 1.6, marginBottom: '1.25rem' }}>{error}</p>
            <a href="/login" className="btn btn-primary" style={{ justifyContent: 'center' }}>Back to sign in</a>
          </>
        ) : (
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9375rem' }}>Completing sign-in…</p>
        )}
      </div>
    </div>
  );
}

export default function SsoCallbackPage() {
  return <Suspense fallback={null}><Callback /></Suspense>;
}
