'use client';
import { useState } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Eye, EyeOff, Loader2, Shield } from 'lucide-react';
import { authApi } from '@/lib/api';

export default function RegisterPage() {
  const router = useRouter();
  const [form, setForm] = useState({ email: '', username: '', password: '', fullName: '' });
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    if (!form.email || !form.username || !form.password) {
      setError('Email, username, and password are required');
      setLoading(false);
      return;
    }

    if (form.password.length < 8) {
      setError('Password must be at least 8 characters');
      setLoading(false);
      return;
    }

    try {
      await authApi.register({
        email: form.email,
        username: form.username,
        password: form.password,
        full_name: form.fullName || form.username,
      });
      setSuccess('Registration successful! Redirecting to login...');
      setTimeout(() => router.push('/login'), 2000);
    } catch (e: any) {
      const errorMsg = e?.response?.data?.detail || e?.response?.data?.message || 'Registration failed. Please try again.';
      setError(Array.isArray(errorMsg) ? errorMsg[0]?.msg || errorMsg[0] : errorMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="dot-grid" style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--bg-primary)',
    }}>
      {/* Glow effect */}
      <div style={{
        position: 'fixed', top: '20%', left: '50%', transform: 'translateX(-50%)',
        width: 600, height: 300, borderRadius: '50%',
        background: 'radial-gradient(ellipse, rgba(15,240,252,0.06) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />

      <div className="glass animate-fadeIn" style={{ width: 420, padding: '2.5rem' }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{ position: 'relative', width: 260, height: 87, margin: '0 auto 0.75rem' }}>
            <Image src="/logo.png" alt="SOCIS-AI-PT" fill sizes="260px" style={{ objectFit: 'contain' }} />
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Create your account
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleRegister} style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
          <div>
            <label style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
              Email Address
            </label>
            <input className="input" type="email" value={form.email}
              onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
              placeholder="admin@example.com" autoComplete="email" required />
          </div>

          <div>
            <label style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
              Username
            </label>
            <input className="input" type="text" value={form.username}
              onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
              placeholder="admin" autoComplete="username" required />
          </div>

          <div>
            <label style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
              Full Name (optional)
            </label>
            <input className="input" type="text" value={form.fullName}
              onChange={e => setForm(f => ({ ...f, fullName: e.target.value }))}
              placeholder="Admin User" autoComplete="name" />
          </div>

          <div>
            <label style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
              Password
            </label>
            <div style={{ position: 'relative' }}>
              <input className="input" type={showPw ? 'text' : 'password'} value={form.password}
                onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                placeholder="••••••••" autoComplete="new-password" required
                style={{ paddingRight: 40 }}
              />
              <button type="button" onClick={() => setShowPw(!showPw)}
                style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}>
                {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>
              Minimum 8 characters required
            </p>
          </div>

          {error && (
            <div style={{ padding: '0.625rem 0.875rem', background: 'color-mix(in srgb, var(--red) 9%, transparent)', border: '1px solid color-mix(in srgb, var(--red) 25%, transparent)', borderRadius: 'var(--radius-md)', color: 'var(--red)', fontSize: '0.8125rem' }}>
              {error}
            </div>
          )}

          {success && (
            <div style={{ padding: '0.625rem 0.875rem', background: 'color-mix(in srgb, var(--green) 9%, transparent)', border: '1px solid color-mix(in srgb, var(--green) 25%, transparent)', borderRadius: 'var(--radius-md)', color: 'var(--green)', fontSize: '0.8125rem' }}>
              {success}
            </div>
          )}

          <button type="submit" disabled={loading} className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', marginTop: 4, padding: '0.625rem' }}>
            {loading ? <><Loader2 size={15} className="animate-spin" /> Creating account...</> : <><Shield size={15} /> Create Account</>}
          </button>
        </form>

        {/* Login link */}
        <p style={{ textAlign: 'center', marginTop: '1.25rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
          Already have an account?{' '}
          <Link href="/login" style={{ color: 'var(--cyan)', textDecoration: 'none' }}>
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}
