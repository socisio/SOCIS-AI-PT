'use client';

import { useEffect, useState } from 'react';
import { authApi } from '@/lib/api';
import type { MeUser, MfaSetup } from '@/lib/api';
import Panel, { FormRow, Pill } from '@/components/ui/Panel';
import Icon from '@/components/ui/Icon';
import CodeInput from '@/components/settings/CodeInput';
import { SectionHead } from '@/components/settings/SettingsShell';
import { askConfirm, notify } from '@/lib/dialogs';
import { apiError } from '@/lib/errors';
import { passwordProblems } from '@/lib/passwordPolicy';

function PasswordPanel() {
  const [cur, setCur] = useState('');
  const [nw, setNw] = useState('');
  const [conf, setConf] = useState('');
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const problems = passwordProblems(nw);
  const score = 4 - problems.length;
  const barColor = score >= 4 ? 'var(--green)' : score === 3 ? 'var(--amber)' : 'var(--red)';
  const mismatch = conf.length > 0 && conf !== nw;
  const ready = cur.length > 0 && nw.length > 0 && problems.length === 0 && nw === conf && !busy;

  const submit = async () => {
    setBusy(true);
    try {
      await authApi.changePassword({ current_password: cur, new_password: nw });
      setCur(''); setNw(''); setConf('');
      notify('Password updated. Your other devices were signed out.', 'success');
    } catch (e) {
      notify(apiError(e, 'Could not change the password'), 'error');
    } finally { setBusy(false); }
  };

  return (
    <Panel
      title="Password"
      desc="Use a long, unique password. You will be signed out on other devices after changing it."
      foot={<><span className="grow" /><button className="btn btn-primary btn-sm" disabled={!ready} onClick={submit}>Update password</button></>}
    >
      <FormRow label="Current password" htmlFor="pw-cur">
        <input id="pw-cur" className="input" type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} />
      </FormRow>
      <FormRow label="New password" help="At least 12 characters with an uppercase letter, a digit and a special character." htmlFor="pw-new">
        <div style={{ position: 'relative' }}>
          <input id="pw-new" className="input" type={show ? 'text' : 'password'} autoComplete="new-password" value={nw} onChange={(e) => setNw(e.target.value)} style={{ paddingRight: '2.5rem' }} />
          <button type="button" className="icon-btn" aria-label={show ? 'Hide password' : 'Show password'} onClick={() => setShow((s) => !s)}
            style={{ position: 'absolute', right: 4, top: 3, width: 28, height: 28 }}><Icon name="eye" size={15} /></button>
        </div>
        {nw.length > 0 && (
          <>
            <div className="meter" aria-hidden="true">
              {[0, 1, 2, 3].map((i) => <i key={i} style={i < score ? { background: barColor } : undefined} />)}
            </div>
            <div className="help" style={{ color: problems.length ? 'var(--text-muted)' : 'var(--green)' }}>
              {problems.length ? `Still needs: ${problems.join(', ')}` : 'Strong password'}
            </div>
          </>
        )}
      </FormRow>
      <FormRow label="Confirm new password" htmlFor="pw-conf">
        <input id="pw-conf" className="input" type={show ? 'text' : 'password'} autoComplete="new-password" value={conf} onChange={(e) => setConf(e.target.value)} />
        {mismatch && <div className="help" style={{ color: 'var(--red)' }}>The passwords do not match.</div>}
      </FormRow>
    </Panel>
  );
}

function TwoFactorPanel() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [setup, setSetup] = useState<MfaSetup | null>(null);
  const [code, setCode] = useState('');
  const [turningOff, setTurningOff] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    authApi.me().then((r) => setEnabled(Boolean((r.data as MeUser).mfa_enabled))).catch(() => setEnabled(false));
  }, []);

  const start = async () => {
    setBusy(true);
    try { const r = await authApi.mfaSetup(); setSetup(r.data); setCode(''); }
    catch (e) { notify(apiError(e, 'Could not start two-factor setup'), 'error'); }
    finally { setBusy(false); }
  };
  const confirmSetup = async () => {
    setBusy(true);
    try { await authApi.mfaVerify(code); setEnabled(true); setSetup(null); setCode(''); notify('Two-factor authentication is on', 'success'); }
    catch (e) { notify(apiError(e, 'That code did not work'), 'error'); setCode(''); }
    finally { setBusy(false); }
  };
  const turnOff = async () => {
    setBusy(true);
    try { await authApi.mfaDisable(code); setEnabled(false); setTurningOff(false); setCode(''); notify('Two-factor authentication is off', 'success'); }
    catch (e) { notify(apiError(e, 'That code did not work'), 'error'); setCode(''); }
    finally { setBusy(false); }
  };

  const status = enabled === null ? null : enabled ? <Pill tone="green" dot>Enabled</Pill> : <Pill tone="amber" dot>Not enabled</Pill>;

  return (
    <Panel
      title="Two-factor authentication"
      desc="Require a code from your authenticator app each time you sign in."
      end={status}
      foot={setup ? (
        <>
          <span className="grow">Setup is not complete until you enter a valid code.</span>
          <button className="btn btn-ghost btn-sm" onClick={() => { setSetup(null); setCode(''); }}>Cancel</button>
          <button className="btn btn-primary btn-sm" disabled={code.length !== 6 || busy} onClick={confirmSetup}>Verify and enable</button>
        </>
      ) : turningOff ? (
        <>
          <span className="grow">Enter a current code to turn two-factor off.</span>
          <button className="btn btn-ghost btn-sm" onClick={() => { setTurningOff(false); setCode(''); }}>Cancel</button>
          <button className="btn btn-sm" disabled={code.length !== 6 || busy} onClick={turnOff} style={{ borderColor: 'var(--red)', color: 'var(--red)', background: 'transparent' }}>Turn off</button>
        </>
      ) : undefined}
    >
      {enabled === false && !setup && (
        <FormRow label="Authenticator app" help="Google Authenticator, Microsoft Authenticator, 1Password or any TOTP app.">
          <div><button className="btn btn-primary btn-sm" disabled={busy} onClick={start}><Icon name="phone" size={14} /> Set up</button></div>
        </FormRow>
      )}
      {enabled && !turningOff && (
        <FormRow label="Authenticator app" help="You are asked for a 6-digit code after your password. If you lose your device, an administrator can reset this for you.">
          <div><button className="btn btn-ghost btn-sm" onClick={() => { setTurningOff(true); setCode(''); }}>Turn off two-factor</button></div>
        </FormRow>
      )}
      {setup && (
        <div style={{ padding: '1.1rem 1.25rem 1.25rem' }}>
          <div className="steps">
            <span className="stp">1</span>
            <div>
              <div className="lab" style={{ fontSize: '0.8125rem', fontWeight: 500 }}>Scan the QR code with an authenticator app</div>
              <div className="help" style={{ marginBottom: '0.8rem' }}>Google Authenticator, Microsoft Authenticator, 1Password or any TOTP app.</div>
              <div style={{ display: 'flex', gap: '1.25rem', alignItems: 'center', flexWrap: 'wrap' }}>
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src={setup.qr_code} alt="Two-factor QR code" width={148} height={148} style={{ background: 'white', borderRadius: 10, padding: 8 }} />
                <div>
                  <div className="help" style={{ marginBottom: '0.35rem' }}>Cannot scan? Enter this key manually:</div>
                  <div className="mono" style={{ padding: '0.45rem 0.65rem', border: '1px solid var(--border)', borderRadius: 8, background: 'var(--bg-secondary)', display: 'inline-flex', gap: '0.7rem', alignItems: 'center', color: 'var(--text-primary)' }}>
                    {setup.secret.replace(/(.{4})/g, '$1 ').trim()}
                    <button type="button" className="icon-btn" aria-label="Copy key" style={{ width: 24, height: 24 }}
                      onClick={() => { navigator.clipboard?.writeText(setup.secret).then(() => notify('Key copied', 'success')).catch(() => {}); }}><Icon name="copy" size={14} /></button>
                  </div>
                </div>
              </div>
            </div>
            <span className="stp">2</span>
            <div>
              <div className="lab" style={{ fontSize: '0.8125rem', fontWeight: 500 }}>Enter the 6-digit code it shows</div>
              <div className="help" style={{ marginBottom: '0.7rem' }}>Codes refresh every 30 seconds.</div>
              <CodeInput value={code} onChange={setCode} label="6-digit code from your authenticator app" />
            </div>
          </div>
        </div>
      )}
      {turningOff && (
        <FormRow label="Verification code" help="From your authenticator app.">
          <CodeInput value={code} onChange={setCode} label="Current 6-digit code" />
        </FormRow>
      )}
    </Panel>
  );
}

function SessionsPanel() {
  const out = async () => {
    const ok = await askConfirm('This signs you out on every device, including this one. You will need to sign in again.', { title: 'Sign out everywhere?', confirmLabel: 'Sign out everywhere', danger: true });
    if (!ok) return;
    try { await authApi.logoutAll(); } catch (e) { notify(apiError(e, 'Could not sign you out everywhere'), 'error'); return; }
    window.location.href = '/login';
  };
  return (
    <Panel title="Sessions">
      <FormRow label="Sign out everywhere" help="Ends every active session on all devices. You will need to sign in again.">
        <div><button className="btn btn-sm" style={{ borderColor: 'var(--red)', color: 'var(--red)', background: 'transparent' }} onClick={out}>
          <Icon name="logout" size={13} /> Sign out of all devices</button></div>
      </FormRow>
    </Panel>
  );
}

export default function SecuritySection() {
  return (
    <>
      <SectionHead title="Security" desc="Protect your account with a strong password and two-factor authentication." />
      <PasswordPanel />
      <TwoFactorPanel />
      <SessionsPanel />
    </>
  );
}
