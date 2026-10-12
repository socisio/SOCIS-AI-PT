'use client';
import { useState, useEffect, Suspense } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Eye, EyeOff, Loader2, Shield, ArrowLeft } from 'lucide-react';
import { authApi } from '@/lib/api';

function ResetPasswordForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get('token') ?? '';

  const [form, setForm] = useState({ password: '', confirm: '' });
  const [showPw, setShowPw] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (!token) setError('Missing reset token. Please use the link from the reset email.');
  }, [token]);

  const passwordRules = [
    { label: 'At least 12 characters', ok: form.password.length >= 12 },
    { label: 'Uppercase letter', ok: /[A-Z]/.test(form.password) },
    { label: 'Number', ok: /[0-9]/.test(form.password) },
    { label: 'Special character', ok: /[^A-Za-z0-9]/.test(form.password) },
  ];
  const passwordValid = passwordRules.every(r => r.ok);
  const passwordsMatch = form.password === form.confirm && form.confirm.length > 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passwordValid) { setError('Password does not meet the requirements.'); return; }
    if (!passwordsMatch) { setError('Passwords do not match.'); return; }

    setLoading(true);
    setError('');
    try {
      await authApi.resetPassword(token, form.password);
      setSuccess(true);
      setTimeout(() => router.push('/login'), 3000);
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Reset failed. The link may have expired.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="dot-grid" style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--bg-primary)',
    }}>
      {/* Glow */}
      <div style={{
        position: 'fixed', top: '20%', left: '50%', transform: 'translateX(-50%)',
        width: 600, height: 300, borderRadius: '50%',
        background: 'radial-gradient(ellipse, rgba(15,240,252,0.06) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />

      <div className="glass animate-fadeIn" style={{ width: 440, padding: '2.5rem' }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{ position: 'relative', width: 240, height: 80, margin: '0 auto 1rem' }}>
            <Image src="/logo.png" alt="SOCIS-AI-PT" fill sizes="240px" style={{ objectFit: 'contain' }} />
          </div>
          <h1 className="gradient-text" style={{ fontSize: '1.5rem', fontWeight: 800, marginBottom: 4 }}>
            Reset Password
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Set a new password for your account.
          </p>
        </div>

        {success ? (
          /* ── Success state ── */
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', textAlign: 'center' }}>
            <div style={{
              display: 'flex', justifyContent: 'center', marginBottom: '0.5rem',
              color: 'var(--cyan)',
            }}>
              <Shield size={48} />
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
              Password reset successfully!
            </p>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
              Redirecting to Sign In in a moment…
            </p>
            <Link href="/login" className="btn btn-primary" style={{ justifyContent: 'center' }}>
              Sign In now
            </Link>
          </div>
        ) : (
          /* ── Form state ── */
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
            {/* New password */}
            <div>
              <label style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
                New Password
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  className="input"
                  type={showPw ? 'text' : 'password'}
                  value={form.password}
                  onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                  placeholder="••••••••••••"
                  autoComplete="new-password"
                  required
                  style={{ paddingRight: 40 }}
                />
                <button type="button" onClick={() => setShowPw(!showPw)} style={{
                  position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)',
                }}>
                  {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>

              {/* Password strength rules */}
              {form.password.length > 0 && (
                <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 3 }}>
                  {passwordRules.map(r => (
                    <div key={r.label} style={{
                      fontSize: '0.75rem',
                      color: r.ok ? 'var(--cyan)' : 'var(--text-muted)',
                      display: 'flex', alignItems: 'center', gap: 5,
                    }}>
                      <span style={{ fontSize: '0.6875rem' }}>{r.ok ? '✓' : '○'}</span>
                      {r.label}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Confirm password */}
            <div>
              <label style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
                Confirm Password
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  className="input"
                  type={showConfirm ? 'text' : 'password'}
                  value={form.confirm}
                  onChange={e => setForm(f => ({ ...f, confirm: e.target.value }))}
                  placeholder="••••••••••••"
                  autoComplete="new-password"
                  required
                  style={{
                    paddingRight: 40,
                    borderColor: form.confirm.length > 0
                      ? (passwordsMatch ? 'var(--cyan)' : 'color-mix(in srgb, var(--red) 40%, transparent)')
                      : undefined,
                  }}
                />
                <button type="button" onClick={() => setShowConfirm(!showConfirm)} style={{
                  position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)',
                }}>
                  {showConfirm ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
              {form.confirm.length > 0 && !passwordsMatch && (
                <p style={{ marginTop: 4, fontSize: '0.75rem', color: 'var(--red)' }}>Passwords do not match.</p>
              )}
            </div>

            {error && (
              <div style={{
                padding: '0.625rem 0.875rem',
                background: 'color-mix(in srgb, var(--red) 9%, transparent)', border: '1px solid color-mix(in srgb, var(--red) 25%, transparent)',
                borderRadius: 'var(--radius-md)', color: 'var(--red)', fontSize: '0.8125rem',
              }}>
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !token}
              className="btn btn-primary"
              style={{ width: '100%', justifyContent: 'center', marginTop: 4, padding: '0.625rem' }}
            >
              {loading
                ? <><Loader2 size={15} className="animate-spin" /> Resetting...</>
                : <><Shield size={15} /> Reset Password</>}
            </button>

            <Link href="/login" style={{
              textAlign: 'center', fontSize: '0.8125rem', color: 'var(--text-muted)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4,
              textDecoration: 'none',
            }}>
              <ArrowLeft size={13} /> Back to Sign In
            </Link>
          </form>
        )}
      </div>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense>
      <ResetPasswordForm />
    </Suspense>
  );
}
