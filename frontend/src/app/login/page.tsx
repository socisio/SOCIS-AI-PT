'use client';
import { useState, useEffect } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Eye, EyeOff, Loader2, ShieldCheck, Lock } from 'lucide-react';
import { authApi } from '@/lib/api';

export default function LoginPage() {
  const router = useRouter();
  const [form, setForm] = useState({ username: '', password: '' });
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  // Set when the password was right but the account has two-factor on: the server answers 202 + a temporary token.
  const [mfaToken, setMfaToken] = useState('');
  const [code, setCode] = useState('');
  const [ssoProviders, setSsoProviders] = useState({
    google: { enabled: false, configured: false },
    microsoft: { enabled: false, configured: false },
  });

  // Returning from Google / Microsoft for an account with two-factor on: the callback page left the temporary token here (see app/auth/callback).
  useEffect(() => {
    try {
      const t = sessionStorage.getItem('socis_sso_mfa');
      if (t) { sessionStorage.removeItem('socis_sso_mfa'); setMfaToken(t); }
    } catch { /* storage unavailable: the person signs in again */ }
  }, []);

  useEffect(() => {
    authApi.me()
      .then(() => router.replace('/dashboard'))
      .catch(() => {});
    authApi.ssoProviders()
      .then((res) => { if (res?.data) setSsoProviders(res.data); })
      .catch(() => {});
  }, [router]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await authApi.login(form.username, form.password);
      if (res.status === 202 && res.data?.mfa_required && res.data?.mfa_token) {
        setMfaToken(String(res.data.mfa_token));
        setCode('');
        return;
      }
      router.push('/dashboard');
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Invalid credentials. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      await authApi.verifyLoginMfa(mfaToken, code.trim());
      router.push('/dashboard');
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      setError(typeof detail === 'string' ? detail : 'That code did not work. Check your authenticator app and try again.');
      // The temporary token is single use and short lived: after these answers the user has to sign in again.
      if (err?.response?.status === 401 && /already used|Invalid MFA token|expired/i.test(String(detail))) {
        setMfaToken('');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleOAuth = async (provider: 'google' | 'microsoft') => {
    try {
      const res = provider === 'google'
        ? await authApi.googleAuthUrl()
        : await authApi.microsoftAuthUrl();
      window.location.href = res.data.auth_url;
    } catch {
      setError(`${provider} SSO is not configured`);
    }
  };

  const hasSSO = ssoProviders.google.enabled || ssoProviders.microsoft.enabled;

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg-primary)',
      position: 'relative',
      overflow: 'hidden',
    }}>

      {/* ── Hexagonal grid background ── */}
      <svg
        aria-hidden="true"
        style={{ position: 'fixed', inset: 0, width: '100%', height: '100%', opacity: 0.04, zIndex: 0, pointerEvents: 'none' }}
      >
        <defs>
          <pattern id="hexgrid" x="0" y="0" width="56" height="48" patternUnits="userSpaceOnUse">
            <polygon
              points="28,2 52,14.5 52,33.5 28,46 4,33.5 4,14.5"
              fill="none" stroke="var(--chart-cyan)" strokeWidth="0.6"
            />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#hexgrid)" />
      </svg>

      {/* ── Central radial glow ── */}
      <div aria-hidden="true" style={{
        position: 'fixed', top: '50%', left: '50%',
        transform: 'translate(-50%, -50%)',
        width: 1000, height: 700, borderRadius: '50%',
        background: 'radial-gradient(ellipse, color-mix(in srgb, var(--cyan) 6%, transparent) 0%, transparent 60%)',
        pointerEvents: 'none', zIndex: 0,
      }} />

      {/* ══════════════════════════════════════════════════════ */}
      {/* LOGIN CARD                                            */}
      {/* ══════════════════════════════════════════════════════ */}
      <div
        className="animate-fadeIn"
        style={{
          position: 'relative',
          zIndex: 1,
          width: '100%',
          maxWidth: 480,
          margin: '0 1rem',
          borderRadius: 'var(--radius-lg)',
          overflow: 'hidden',
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          boxShadow: 'var(--shadow-pop)',
        }}
      >
        {/* Top accent gradient bar */}
        <div style={{
          height: 2,
          background: 'linear-gradient(90deg, transparent 0%, var(--chart-cyan) 40%, var(--chart-purple) 70%, transparent 100%)',
        }} />

        <div style={{ padding: '2.5rem 2.75rem 2rem' }}>

          {/* ── Brand ── */}
          <div style={{ textAlign: 'center', marginBottom: '2.25rem', background: 'var(--brand-surface)', borderRadius: 'var(--radius-md)', padding: '0.75rem 0' }}>
            <div style={{
              position: 'relative',
              width: 300, height: 100,
              margin: '0 auto',
              filter: 'var(--logo-glow)',
            }}>
              <Image src="/logo.png" alt="SOCIS-AI-PT" fill sizes="300px" style={{ objectFit: 'contain' }} priority />
            </div>
          </div>

          {/* ── Divider ── */}
          <div style={{
            height: 1,
            background: 'linear-gradient(90deg, transparent, var(--border), transparent)',
            marginBottom: '2rem',
          }} />

          {/* ── Access notice + heading ── */}
          <div style={{ marginBottom: '1.5rem', textAlign: 'center' }}>
            <div style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              padding: '4px 10px', borderRadius: 'var(--radius-sm)', marginBottom: '0.875rem',
              background: 'color-mix(in srgb, var(--red) 6%, transparent)',
              border: '1px solid color-mix(in srgb, var(--red) 18%, transparent)',
            }}>
              <Lock size={11} color="var(--text-secondary)" />
              <span style={{
                fontSize: '0.6875rem', color: 'var(--text-secondary)',
                letterSpacing: '0.1em', textTransform: 'uppercase', fontWeight: 600,
              }}>
                Authorized Access Only
              </span>
            </div>

            <h1 style={{
              fontSize: '1.25rem',
              fontWeight: 700,
              color: 'var(--text-primary)',
              letterSpacing: '-0.025em',
              lineHeight: 1.3,
              textAlign: 'center',
            }}>
              {mfaToken ? 'Two-step verification' : 'Sign in to your workspace'}
            </h1>
          </div>

          {/* ── SSO buttons ── */}
          {!mfaToken && hasSSO && (
            <>
              <div style={{ display: 'flex', gap: '0.625rem', marginBottom: '1.125rem' }}>
                {ssoProviders.google.enabled && (
                  <button
                    onClick={() => handleOAuth('google')}
                    className="btn btn-ghost"
                    style={{ flex: 1, justifyContent: 'center', fontSize: '0.8125rem' }}
                  >
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none">
                      <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                      <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                      <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                      <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                    </svg>
                    Continue with Google
                  </button>
                )}
                {ssoProviders.microsoft.enabled && (
                  <button
                    onClick={() => handleOAuth('microsoft')}
                    className="btn btn-ghost"
                    style={{ flex: 1, justifyContent: 'center', fontSize: '0.8125rem' }}
                  >
                    <svg width="15" height="15" viewBox="0 0 21 21" fill="none">
                      <rect width="10" height="10" fill="#F25022"/>
                      <rect x="11" width="10" height="10" fill="#7FBA00"/>
                      <rect y="11" width="10" height="10" fill="#00A4EF"/>
                      <rect x="11" y="11" width="10" height="10" fill="#FFB900"/>
                    </svg>
                    Microsoft AD
                  </button>
                )}
              </div>

              <div style={{
                display: 'flex', alignItems: 'center', gap: '0.75rem',
                marginBottom: '1.25rem',
              }}>
                <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                  or continue with credentials
                </span>
                <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
              </div>
            </>
          )}

          {/* ── Two-step verification ── */}
          {mfaToken && (
            <form onSubmit={handleMfa} style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', lineHeight: 1.5, textAlign: 'center' }}>
                Open your authenticator app and enter the 6-digit code for <b style={{ color: 'var(--text-primary)' }}>{form.username}</b>.
              </p>
              <input
                className="input" inputMode="numeric" autoComplete="one-time-code" autoFocus required maxLength={6}
                pattern="[0-9]{6}" value={code} aria-label="6-digit verification code" placeholder="000000"
                onChange={(e) => setCode(e.target.value.replace(/[^0-9]/g, ''))}
                style={{ textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: '1.4rem', letterSpacing: '0.5em', minHeight: 52 }}
              />
              {error && (
                <div role="alert" style={{ fontSize: '0.8125rem', color: 'var(--red)', textAlign: 'center' }}>{error}</div>
              )}
              <button type="submit" disabled={loading || code.length !== 6} className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', padding: '0.72rem 1rem', fontWeight: 600 }}>
                {loading ? <><Loader2 size={15} className="animate-spin" /> Verifying…</> : <><ShieldCheck size={15} /> Verify and sign in</>}
              </button>
              <button type="button" className="btn btn-ghost" style={{ justifyContent: 'center' }} onClick={() => { setMfaToken(''); setCode(''); setError(''); }}>
                Use a different account
              </button>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center' }}>Codes refresh every 30 seconds.</p>
            </form>
          )}

          {/* ── Credential form ── */}
          {!mfaToken && (
          <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>

            {/* Username */}
            <div>
              <label style={{
                display: 'block', marginBottom: 7,
                fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)',
                letterSpacing: '0.08em', textTransform: 'uppercase',
              }}>
                Username or Email
              </label>
              <input
                className="input"
                type="text"
                value={form.username}
                onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                placeholder="admin"
                autoComplete="username"
                autoFocus
                required
                style={{ fontSize: '0.875rem' }}
              />
            </div>

            {/* Password */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 7 }}>
                <label style={{
                  fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)',
                  letterSpacing: '0.08em', textTransform: 'uppercase',
                }}>
                  Password
                </label>
                <Link
                  href="/forgot-password"
                  style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textDecoration: 'none', transition: 'color 0.15s' }}
                  onMouseEnter={e => (e.currentTarget.style.color = 'var(--cyan)')}
                  onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}
                >
                  Forgot password?
                </Link>
              </div>
              <div style={{ position: 'relative' }}>
                <input
                  className="input"
                  type={showPw ? 'text' : 'password'}
                  value={form.password}
                  onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  required
                  style={{ paddingRight: 44, fontSize: '0.875rem' }}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  style={{
                    position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--text-muted)', display: 'flex', padding: 0,
                    transition: 'color 0.15s',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-secondary)')}
                  onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}
                >
                  {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div style={{
                display: 'flex', alignItems: 'flex-start', gap: 9,
                padding: '0.7rem 0.875rem',
                background: 'color-mix(in srgb, var(--red) 8%, transparent)',
                border: '1px solid color-mix(in srgb, var(--red) 22%, transparent)',
                borderRadius: 'var(--radius-md)', color: 'var(--red)', fontSize: '0.8125rem', lineHeight: 1.5,
              }}>
                <span style={{ fontSize: '0.875rem', marginTop: 1, flexShrink: 0 }}>⚠</span>
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary"
              style={{
                width: '100%', justifyContent: 'center',
                padding: '0.72rem 1rem',
                fontSize: '0.875rem', fontWeight: 600,
                marginTop: 2,
              }}
            >
              {loading
                ? <><Loader2 size={15} className="animate-spin" /> Authenticating…</>
                : <><ShieldCheck size={15} /> Sign In</>
              }
            </button>
          </form>
          )}

          {/* ── System notice ── */}
          <p style={{
            marginTop: '1.75rem', textAlign: 'center',
            fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.6,
          }}>
            This system is restricted to authorized personnel only.<br />
            All access attempts are logged and monitored.
          </p>
        </div>
      </div>

      {/* ── Request access link ── */}
      <p style={{
        position: 'relative', zIndex: 1,
        marginTop: '1.5rem',
        fontSize: '0.8125rem', color: 'var(--text-muted)',
      }}>
        Don&apos;t have an account?{' '}
        <Link
          href="/register"
          style={{ color: 'var(--text-muted)', textDecoration: 'none', transition: 'color 0.15s' }}
          onMouseEnter={e => (e.currentTarget.style.color = 'var(--cyan)')}
          onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}
        >
          Request access →
        </Link>
      </p>

      {/* ── Page footer ── */}
      <div style={{
        position: 'fixed', bottom: '1.25rem', left: 0, right: 0,
        textAlign: 'center', zIndex: 1,
        fontSize: '0.6875rem', color: 'var(--text-muted)', letterSpacing: '0.04em',
      }}>
        © {new Date().getFullYear()} SOCIS-AI-PT · All rights reserved
      </div>
    </div>
  );
}
