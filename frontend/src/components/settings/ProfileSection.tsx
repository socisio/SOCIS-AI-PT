'use client';

import { useEffect, useState } from 'react';
import { authApi } from '@/lib/api';
import type { MeUser } from '@/lib/api';
import Panel, { FormRow, Pill } from '@/components/ui/Panel';
import { SectionHead } from '@/components/settings/SettingsShell';
import { notify } from '@/lib/dialogs';
import { apiError } from '@/lib/errors';
import { applyTheme, getThemePref } from '@/lib/theme';
import type { ThemePref } from '@/lib/theme';

const ROLE_LABEL: Record<string, string> = { admin: 'Administrator', analyst: 'Analyst', viewer: 'Viewer' };

function initials(name: string): string {
  const p = name.trim().split(/\s+/).filter(Boolean);
  return ((p[0]?.[0] ?? '?') + (p.length > 1 ? p[p.length - 1][0] : '')).toUpperCase();
}

export default function ProfileSection() {
  const [me, setMe] = useState<MeUser | null>(null);
  const [name, setName] = useState('');
  const [saved, setSaved] = useState('');
  const [busy, setBusy] = useState(false);
  const [theme, setTheme] = useState<ThemePref>('dark');

  useEffect(() => {
    authApi.me()
      .then((r) => { const u = r.data as MeUser; setMe(u); setName(u.full_name ?? ''); setSaved(u.full_name ?? ''); })
      .catch(() => notify('Could not load your profile', 'error'));
    setTheme(getThemePref());
  }, []);

  const dirty = name.trim() !== saved.trim();
  const save = async () => {
    setBusy(true);
    try {
      await authApi.updateProfile({ full_name: name.trim() });
      setSaved(name.trim());
      notify('Profile updated', 'success');
    } catch (e) {
      notify(apiError(e, 'Could not update your profile'), 'error');
    } finally { setBusy(false); }
  };

  const pickTheme = (t: ThemePref) => { setTheme(t); applyTheme(t); };

  return (
    <>
      <SectionHead title="Profile" desc="Your name and contact details, shown to teammates and on reports you generate." />
      <Panel
        title="Personal information"
        foot={<>
          <span className="grow">{dirty ? 'You have unsaved changes' : ''}</span>
          <button className="btn btn-ghost btn-sm" disabled={!dirty || busy} onClick={() => setName(saved)}>Discard</button>
          <button className="btn btn-primary btn-sm" disabled={!dirty || busy || !name.trim()} onClick={save}>Save changes</button>
        </>}
      >
        <FormRow label="Photo" help="How teammates see you">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <span className="avatar-lg">{initials(name || me?.username || '?')}</span>
            <div className="help">Initials come from your name.<br />Shown on comments, audit entries and reports.</div>
          </div>
        </FormRow>
        <FormRow label="Full name" help="Your display name" htmlFor="pf-name">
          <input id="pf-name" className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={120} />
        </FormRow>
        <FormRow label="Email address" help="Used for sign-in notices and report delivery. Ask an administrator to change it." htmlFor="pf-email">
          <input id="pf-email" className="input" value={me?.email ?? ''} readOnly style={{ color: 'var(--text-muted)' }} />
        </FormRow>
        <FormRow label="Username" help="Used to sign in." htmlFor="pf-user">
          <input id="pf-user" className="input mono" value={me?.username ?? ''} readOnly style={{ color: 'var(--text-muted)' }} />
        </FormRow>
        <FormRow label="Role" help="Assigned by an administrator">
          <div><Pill tone="purple">{ROLE_LABEL[me?.role ?? ''] ?? me?.role ?? '—'}</Pill></div>
        </FormRow>
      </Panel>

      <Panel title="Appearance" desc="Choose how SOCIS-AI-PT looks on this device.">
        <FormRow label="Theme" help="Applies immediately">
          <div className="seg" role="radiogroup" aria-label="Theme" style={{ alignSelf: 'flex-start' }}>
            {(['dark', 'light', 'system'] as ThemePref[]).map((t) => (
              <span key={t} role="radio" aria-checked={theme === t} tabIndex={0} className={theme === t ? 'on' : ''}
                onClick={() => pickTheme(t)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pickTheme(t); } }}
                style={{ cursor: 'pointer', textTransform: 'capitalize' }}>{t}</span>
            ))}
          </div>
        </FormRow>
      </Panel>
    </>
  );
}
