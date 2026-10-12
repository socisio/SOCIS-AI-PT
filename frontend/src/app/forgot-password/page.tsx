'use client';
import { useState } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { ArrowLeft, Loader2, Mail } from 'lucide-react';
import { authApi } from '@/lib/api';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [resetUrl, setResetUrl] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setResetUrl('');
    try {
      // The API never returns the reset token/URL (fix C-2). The link is
      // delivered out-of-band by email. We always show the same generic
      // confirmation regardless of whether the email exists.
      await authApi.forgotPassword(email);
      setResetUrl('__sent__');
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Something went wrong. Please try again.');
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

      <div className="glass animate-fadeIn" style={{ width: 420, padding: '2.5rem' }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{ position: 'relative', width: 240, height: 80, margin: '0 auto 1rem' }}>
            <Image src="/logo.png" alt="SOCIS-AI-PT" fill sizes="240px" style={{ objectFit: 'contain' }} />
          </div>
          <h1 className="gradient-text" style={{ fontSize: '1.5rem', fontWeight: 800, marginBottom: 4 }}>
            Forgot Password
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Enter your email to generate a password reset link.
          </p>
        </div>

        {resetUrl === '__sent__' ? (
          /* ── Generic "email sent" state (fix C-2) ── */
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{
              padding: '0.875rem 1rem',
              background: 'color-mix(in srgb, var(--cyan) 8%, transparent)',
              border: '1px solid color-mix(in srgb, var(--cyan) 25%, transparent)',
              borderRadius: 'var(--radius-lg)',
              fontSize: '0.8125rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.6,
            }}>
              <strong style={{ color: 'var(--cyan)' }}>Check your email.</strong>
              <br />
              If that email is registered to a local account, we&apos;ve sent a
              password reset link. It expires in <strong>30 minutes</strong>.
              <br /><br />
              <em style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                SSO accounts (Google / Microsoft) must reset their password
                through their identity provider.
              </em>
            </div>

            <Link href="/login" className="btn btn-ghost" style={{ justifyContent: 'center', marginTop: 4 }}>
              <ArrowLeft size={15} /> Back to Sign In
            </Link>
          </div>
        ) : (
          /* ── Form state ── */
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
            <div>
              <label style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
                Registered Email
              </label>
              <div style={{ position: 'relative' }}>
                <Mail size={15} style={{
                  position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)',
                  color: 'var(--text-muted)', pointerEvents: 'none',
                }} />
                <input
                  className="input"
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  autoComplete="email"
                  required
                  style={{ paddingLeft: 32 }}
                />
              </div>
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
              disabled={loading}
              className="btn btn-primary"
              style={{ width: '100%', justifyContent: 'center', marginTop: 4, padding: '0.625rem' }}
            >
              {loading
                ? <><Loader2 size={15} className="animate-spin" /> Generating link...</>
                : 'Generate Reset Link'}
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
