'use client';

/**
 * UsersPanel — admin user management: list, add user, change role, activate/deactivate,
 * reset password, delete. Every failure is shown to the admin (nothing fails silently).
 * The API refuses unsafe changes (self-lockout, removing the last admin) and signs users out
 * immediately when their access changes.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { Plus, Search, UserX, UserCheck, Trash2, Key, Copy, Check, AlertTriangle, CheckCircle } from 'lucide-react';
import { adminApi, authApi } from '@/lib/api';
import type { AdminUser, AdminRole } from '@/lib/api';
import Modal from '@/components/ui/Modal';
import Icon from '@/components/ui/Icon';
import Panel, { Pill } from '@/components/ui/Panel';
import { SectionHead } from '@/components/settings/SettingsShell';
import { askConfirm } from '@/lib/dialogs';
import { timeAgo } from '@/lib/format';
import Skeleton from '@/components/ui/Skeleton';
import EmptyState from '@/components/ui/EmptyState';

function apiError(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { detail?: unknown } } };
  const d = e?.response?.data?.detail;
  if (typeof d === 'string') return d;
  if (Array.isArray(d)) {
    const first = d[0] as { msg?: string } | undefined;
    if (first?.msg) return first.msg.replace(/^Value error, /, '');
  }
  return fallback;
}

function apiStatus(err: unknown): number | null {
  const e = err as { response?: { status?: number } };
  return typeof e?.response?.status === 'number' ? e.response.status : null;
}

type Notice = { kind: 'ok' | 'error'; text: string } | null;
type Dialog =
  | { kind: 'add' }
  | { kind: 'reset'; user: AdminUser }
  | { kind: 'delete'; user: AdminUser }
  | { kind: 'secret'; title: string; username: string; password: string }
  | null;

const PASSWORD_HINT = 'At least 12 characters with an uppercase letter, a digit and a special character.';

function passwordProblem(pw: string): string | null {
  if (pw.length < 12) return 'The password needs at least 12 characters.';
  if (!/[A-Z]/.test(pw)) return 'The password needs an uppercase letter.';
  if (!/[0-9]/.test(pw)) return 'The password needs a digit.';
  if (!/[^A-Za-z0-9]/.test(pw)) return 'The password needs a special character.';
  return null;
}

// ─── Password mode picker shared by "Add user" and "Reset password" ───────────
function PasswordChoice({
  mode, setMode, password, setPassword,
}: {
  mode: 'generate' | 'set';
  setMode: (m: 'generate' | 'set') => void;
  password: string;
  setPassword: (v: string) => void;
}) {
  return (
    <div style={{ marginBottom: '0.875rem' }}>
      <label className={`radio-row${mode === 'generate' ? ' on' : ''}`}>
        <input type="radio" name="pwmode" checked={mode === 'generate'} onChange={() => setMode('generate')} />
        <div><strong>Generate a temporary password</strong><span>Recommended. It is shown once so you can share it securely.</span></div>
      </label>
      <label className={`radio-row${mode === 'set' ? ' on' : ''}`}>
        <input type="radio" name="pwmode" checked={mode === 'set'} onChange={() => setMode('set')} />
        <div><strong>Set a password myself</strong><span>{PASSWORD_HINT}</span></div>
      </label>
      {mode === 'set' && (
        <input
          className="input" type="password" autoComplete="new-password" value={password}
          onChange={(e) => setPassword(e.target.value)} placeholder="New password" aria-label="New password"
        />
      )}
    </div>
  );
}

// ─── Dialogs ───────────────────────────────────────────────────────────────────
function AddUserDialog({
  roles, onClose, onCreated,
}: {
  roles: AdminRole[];
  onClose: () => void;
  onCreated: (u: AdminUser & { temporary_password?: string }) => void;
}) {
  const [fullName, setFullName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('viewer');
  const [mode, setMode] = useState<'generate' | 'set'>('generate');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const picked = roles.find((r) => r.name === role);

  const submit = async (e: { preventDefault: () => void }) => {
    e.preventDefault();
    setError(null);
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,49}$/.test(username.trim())) {
      setError('Username must be 3 to 50 characters: letters, digits, dot, underscore or hyphen.');
      return;
    }
    if (!/^\S+@\S+\.\S+$/.test(email.trim())) { setError('Enter a valid email address.'); return; }
    if (mode === 'set') {
      const problem = passwordProblem(password);
      if (problem) { setError(problem); return; }
    }
    setSubmitting(true);
    try {
      const r = await adminApi.createUser({
        email: email.trim(), username: username.trim(), full_name: fullName.trim() || undefined,
        role, password: mode === 'set' ? password : undefined,
      });
      onCreated(r.data);
    } catch (err) {
      setError(apiError(err, 'Could not create the user.'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      open title="Add user" onClose={onClose}
      footer={
        <>
          <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" form="add-user-form" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'Creating' : 'Create user'}
          </button>
        </>
      }
    >
      <form id="add-user-form" onSubmit={submit}>
        {error && <div className="alert alert-error" role="alert"><AlertTriangle size={15} /><span>{error}</span></div>}
        <div className="field-row">
          <div className="field">
            <label htmlFor="nu-name">Full name</label>
            <input id="nu-name" className="input" value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder="Alex Khan" />
          </div>
          <div className="field">
            <label htmlFor="nu-user">Username</label>
            <input id="nu-user" className="input" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="alex.khan" autoComplete="off" required />
          </div>
        </div>
        <div className="field">
          <label htmlFor="nu-email">Email</label>
          <input id="nu-email" className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="alex@company.com" autoComplete="off" required />
        </div>
        <div className="field">
          <label htmlFor="nu-role">Role</label>
          <select id="nu-role" className="input" value={role} onChange={(e) => setRole(e.target.value)}>
            {(roles.length ? roles.map((r) => r.name) : ['viewer', 'analyst', 'admin']).map((n) => (
              <option key={n} value={n}>{n.charAt(0).toUpperCase() + n.slice(1)}</option>
            ))}
          </select>
          {picked && <span className="hint">{picked.description || 'No description'} · {picked.permissions.length} permissions</span>}
        </div>
        <PasswordChoice mode={mode} setMode={setMode} password={password} setPassword={setPassword} />
      </form>
    </Modal>
  );
}

function ResetDialog({
  user, onClose, onDone,
}: {
  user: AdminUser;
  onClose: () => void;
  onDone: (temporaryPassword?: string) => void;
}) {
  const [mode, setMode] = useState<'generate' | 'set'>('generate');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: { preventDefault: () => void }) => {
    e.preventDefault();
    setError(null);
    if (mode === 'set') {
      const problem = passwordProblem(password);
      if (problem) { setError(problem); return; }
    }
    setSubmitting(true);
    try {
      const r = await adminApi.resetPassword(user.id, mode === 'set' ? { password } : {});
      onDone(r.data.temporary_password);
    } catch (err) {
      setError(apiError(err, 'Could not reset the password.'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      open title={`Reset password for ${user.username}`} onClose={onClose}
      footer={
        <>
          <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" form="reset-form" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'Resetting' : 'Reset password'}
          </button>
        </>
      }
    >
      <form id="reset-form" onSubmit={submit}>
        {error && <div className="alert alert-error" role="alert"><AlertTriangle size={15} /><span>{error}</span></div>}
        <div className="alert alert-warn"><AlertTriangle size={15} /><span>This signs {user.username} out on every device.</span></div>
        <PasswordChoice mode={mode} setMode={setMode} password={password} setPassword={setPassword} />
      </form>
    </Modal>
  );
}

function DeleteDialog({
  user, onClose, onDone, onDeactivate,
}: {
  user: AdminUser;
  onClose: () => void;
  onDone: () => void;
  onDeactivate: () => void;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // 409 = the account owns work (projects, scans, reports) or is still referenced: deleting is not possible.
  const [blocked, setBlocked] = useState(false);

  const confirm = async () => {
    setError(null);
    setSubmitting(true);
    try {
      await adminApi.deleteUser(user.id);
      onDone();
    } catch (err) {
      setBlocked(apiStatus(err) === 409);
      setError(apiError(err, 'Could not delete the user.'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      open title={`Delete ${user.username}?`} onClose={onClose}
      footer={
        <>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{blocked ? 'Close' : 'Cancel'}</button>
          {blocked ? (
            user.is_active && <button type="button" className="btn btn-primary" onClick={onDeactivate}>Deactivate instead</button>
          ) : (
            <button type="button" className="btn btn-danger" onClick={confirm} disabled={submitting}>
              {submitting ? 'Deleting' : 'Delete user'}
            </button>
          )}
        </>
      }
    >
      {error && (
        <div className={`alert ${blocked ? 'alert-warn' : 'alert-error'}`} role="alert">
          <AlertTriangle size={15} /><span>{error}</span>
        </div>
      )}
      {!blocked && (
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
          This permanently removes the account and signs the user out. Their past actions stay in the audit log.
          If you only want to block access for now, deactivate the account instead.
        </p>
      )}
    </Modal>
  );
}

function SecretDialog({
  title, username, password, onClose,
}: { title: string; username: string; password: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(password);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard needs HTTPS; the password stays selectable below */
    }
  };
  return (
    <Modal
      open title={title} onClose={onClose}
      footer={<button type="button" className="btn btn-primary" onClick={onClose}>I have saved it</button>}
    >
      <div className="alert alert-warn"><AlertTriangle size={15} /><span>This password is shown only once. Share it securely and ask {username} to change it after signing in.</span></div>
      <div className="field">
        <label>Username</label>
        <div className="secret-box">{username}</div>
      </div>
      <div className="field">
        <label>Temporary password</label>
        <div className="secret-box">
          <span style={{ flex: 1 }}>{password}</span>
          <button type="button" className="btn btn-ghost" onClick={copy} aria-label="Copy password">
            {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ─── The panel ─────────────────────────────────────────────────────────────────
export default function UsersPanel() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [total, setTotal] = useState(0);
  const [roles, setRoles] = useState<AdminRole[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [meId, setMeId] = useState('');
  const [busyId, setBusyId] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice>(null);
  const [dialog, setDialog] = useState<Dialog>(null);
  const noticeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const flash = useCallback((kind: 'ok' | 'error', text: string) => {
    setNotice({ kind, text });
    if (noticeTimer.current) clearTimeout(noticeTimer.current);
    noticeTimer.current = setTimeout(() => setNotice(null), 6000);
  }, []);

  const load = useCallback(async () => {
    try {
      const r = await adminApi.users({ per_page: 100, q: q.trim() || undefined });
      setUsers(r.data.users);
      setTotal(r.data.total);
      setLoadError(null);
    } catch (err) {
      setLoadError(apiError(err, 'Could not load users.'));
    } finally {
      setLoading(false);
    }
  }, [q]);

  // Typing in the search box waits briefly so we do not call the API on every key.
  useEffect(() => {
    const t = setTimeout(load, q ? 250 : 0);
    return () => clearTimeout(t);
  }, [load, q]);

  useEffect(() => {
    let alive = true;
    adminApi.roles().then((r) => { if (alive) setRoles(r.data.roles); }).catch(() => { /* the form falls back to the standard roles */ });
    authApi.me().then((r) => { if (alive) setMeId(String(r.data?.id ?? '')); }).catch(() => { /* self-protection also enforced by the API */ });
    return () => { alive = false; if (noticeTimer.current) clearTimeout(noticeTimer.current); };
  }, []);

  const changeRole = async (u: AdminUser, role: string) => {
    if (role === u.role) return;
    setBusyId(u.id);
    try {
      await adminApi.updateUser(u.id, { role });
      flash('ok', `${u.username} is now ${role}. Their sessions were refreshed.`);
    } catch (err) {
      flash('error', apiError(err, 'Could not change the role.'));
    } finally {
      setBusyId(null);
      load();
    }
  };

  const toggleActive = async (u: AdminUser) => {
    setBusyId(u.id);
    try {
      await adminApi.updateUser(u.id, { is_active: !u.is_active });
      flash('ok', u.is_active ? `${u.username} was deactivated and signed out.` : `${u.username} can sign in again.`);
    } catch (err) {
      flash('error', apiError(err, 'Could not change the account status.'));
    } finally {
      setBusyId(null);
      load();
    }
  };

  // Lost phone: turn two-factor off for that user (there are no recovery codes). They sign in with their password again.
  const resetMfa = async (u: AdminUser) => {
    const ok = await askConfirm(`Turn two-factor authentication off for ${u.username}? They will be signed out everywhere and can set it up again from Settings > Security.`, { title: 'Reset two-factor', confirmLabel: 'Reset two-factor', danger: true });
    if (!ok) return;
    setBusyId(u.id);
    try {
      await adminApi.resetMfa(u.id);
      flash('ok', `Two-factor was reset for ${u.username}. They were signed out everywhere.`);
    } catch (err) {
      flash('error', apiError(err, 'Could not reset two-factor.'));
    } finally {
      setBusyId(null);
      load();
    }
  };

  const shown = users.filter((u) => roleFilter === 'all' || u.role === roleFilter);
  const activeCount = users.filter((u) => u.is_active).length;
  const adminCount = users.filter((u) => u.role === 'admin').length;
  const mfaCount = users.filter((u) => u.mfa_enabled).length;
  const roleNames = roles.length ? roles.map((r) => r.name) : ['admin', 'analyst', 'viewer'];

  return (
    <div>
      <SectionHead
        title="Users & roles" desc="Add people, assign roles and keep access under control."
        actions={<button className="btn btn-primary" onClick={() => setDialog({ kind: 'add' })}><Plus size={16} /> Add user</button>}
      />

      {notice && (
        <div className={`alert ${notice.kind === 'ok' ? 'alert-ok' : 'alert-error'}`} role={notice.kind === 'ok' ? 'status' : 'alert'}>
          {notice.kind === 'ok' ? <CheckCircle size={15} /> : <AlertTriangle size={15} />}
          <span>{notice.text}</span>
        </div>
      )}
      {loadError && <div className="alert alert-error" role="alert"><AlertTriangle size={15} /><span>{loadError}</span></div>}

      <div className="kpis">
        <div><small>Users</small><b>{total}</b><i>{activeCount} active</i></div>
        <div><small>Administrators</small><b>{adminCount}</b><i>of {users.length} listed</i></div>
        <div><small>Two-factor enabled</small><b>{mfaCount}</b><i>of {users.length} listed</i></div>
      </div>

      <section className="panel">
        <div className="toolbar2">
          <div style={{ position: 'relative', flex: '0 1 320px' }}>
            <span style={{ position: 'absolute', left: 10, top: 8, color: 'var(--text-muted)', display: 'flex' }}><Search size={14} /></span>
            <input className="input" style={{ paddingLeft: '2rem', minHeight: 32 }} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search by name, username or email" aria-label="Search users" />
          </div>
          <div className="seg" role="radiogroup" aria-label="Filter by role">
            {['all', ...roleNames].map((r) => (
              <span key={r} role="radio" aria-checked={roleFilter === r} tabIndex={0} className={roleFilter === r ? 'on' : ''}
                onClick={() => setRoleFilter(r)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setRoleFilter(r); } }}
                style={{ cursor: 'pointer', textTransform: 'capitalize' }}>{r}</span>
            ))}
          </div>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="tbl">
            <thead><tr><th>User</th><th>Role</th><th>Two-factor</th><th>Last sign-in</th><th>Status</th><th style={{ textAlign: 'right' }}>Actions</th></tr></thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6}><Skeleton height={14} /></td></tr>
              ) : shown.length === 0 ? (
                <tr><td colSpan={6}><EmptyState title="No users found">Try a different search or filter, or add a user.</EmptyState></td></tr>
              ) : shown.map((u) => {
                const isMe = u.id === meId;
                const busy = busyId === u.id;
                const display = u.full_name || u.username;
                return (
                  <tr key={u.id}>
                    <td>
                      <div className="who">
                        <span className="av">{display.split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0]).join('').toUpperCase() || '?'}</span>
                        <div>
                          <b>{display} {isMe && <span className="chip">You</span>}</b>
                          <small>{u.username} · {u.email}</small>
                        </div>
                      </div>
                    </td>
                    <td style={{ minWidth: 130 }}>
                      <select
                        className="input" style={{ minHeight: 30, padding: '0.2rem 0.5rem', textTransform: 'capitalize' }}
                        value={u.role ?? ''} disabled={isMe || busy} aria-label={`Role for ${u.username}`}
                        title={isMe ? 'You cannot change your own role' : undefined}
                        onChange={(e) => changeRole(u, e.target.value)}
                      >
                        {!u.role && <option value="">No role</option>}
                        {roleNames.map((n) => (
                          <option key={n} value={n}>{n.charAt(0).toUpperCase() + n.slice(1)}</option>
                        ))}
                      </select>
                    </td>
                    <td>{u.mfa_enabled ? <Pill tone="green">On</Pill> : <Pill tone="amber">Off</Pill>}</td>
                    <td>{timeAgo(u.last_login)}</td>
                    <td>{u.is_active ? <Pill tone="green" dot>Active</Pill> : <Pill tone="gray" dot>Deactivated</Pill>}</td>
                    <td>
                      <div className="ra">
                        <button type="button" aria-label={`Reset password for ${u.username}`} title="Reset password"
                          onClick={() => !busy && setDialog({ kind: 'reset', user: u })}><Icon name="key" size={14} /></button>
                        {u.mfa_enabled && (
                          <button type="button" aria-label={`Reset two-factor for ${u.username}`} title="Reset two-factor (lost device)"
                            onClick={() => !busy && resetMfa(u)}><Icon name="phone" size={14} /></button>
                        )}
                        <button type="button" disabled={isMe || busy}
                          title={isMe ? 'You cannot deactivate yourself' : u.is_active ? 'Deactivate and sign out' : 'Activate'}
                          aria-label={u.is_active ? `Deactivate ${u.username}` : `Activate ${u.username}`}
                          style={isMe ? { opacity: 0.4, cursor: 'not-allowed' } : undefined}
                          onClick={() => !isMe && !busy && toggleActive(u)}>{u.is_active ? <UserX size={14} /> : <UserCheck size={14} />}</button>
                        <button type="button" disabled={isMe || busy} style={isMe ? { color: 'var(--red)', opacity: 0.4, cursor: 'not-allowed' } : { color: 'var(--red)' }}
                          title={isMe ? 'You cannot delete yourself' : 'Delete user'} aria-label={`Delete ${u.username}`}
                          onClick={() => !isMe && !busy && setDialog({ kind: 'delete', user: u })}><Trash2 size={14} /></button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <Panel title="Roles and permissions" desc="Every action is checked against the user's role. Changing a role signs the user out so it applies immediately.">
        {roles.length === 0 ? <div style={{ padding: '1rem 1.25rem' }}><Skeleton height={14} /></div> : roles.map((r) => (
          <details key={r.name} style={{ borderTop: '1px solid var(--border)' }}>
            <summary style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.8rem', padding: '0.75rem 1.25rem', fontSize: '0.8125rem', listStyle: 'none' }}>
              <b style={{ minWidth: 84, textTransform: 'capitalize', fontWeight: 600 }}>{r.name}</b>
              <span className="muted">{r.description || 'No description'}</span>
              <span className="pill gray" style={{ marginLeft: 'auto' }}>{r.user_count} {r.user_count === 1 ? 'user' : 'users'}</span>
              <Icon name="chevr" size={14} style={{ color: 'var(--text-muted)' }} />
            </summary>
            <div className="chip-list" style={{ padding: '0 1.25rem 1rem' }}>{r.permissions.map((p) => <span key={p} className="chip">{p}</span>)}</div>
          </details>
        ))}
      </Panel>

      {dialog?.kind === 'add' && (
        <AddUserDialog
          roles={roles}
          onClose={() => setDialog(null)}
          onCreated={(u) => {
            load();
            if (u.temporary_password) {
              setDialog({ kind: 'secret', title: 'User created', username: u.username, password: u.temporary_password });
            } else {
              setDialog(null);
              flash('ok', `${u.username} was created.`);
            }
          }}
        />
      )}
      {dialog?.kind === 'reset' && (
        <ResetDialog
          user={dialog.user}
          onClose={() => setDialog(null)}
          onDone={(tmp) => {
            const target = dialog.user;
            load();
            if (tmp) setDialog({ kind: 'secret', title: 'Password reset', username: target.username, password: tmp });
            else { setDialog(null); flash('ok', `Password updated for ${target.username}. They were signed out everywhere.`); }
          }}
        />
      )}
      {dialog?.kind === 'delete' && (
        <DeleteDialog
          user={dialog.user}
          onClose={() => setDialog(null)}
          onDone={() => { const name = dialog.user.username; setDialog(null); load(); flash('ok', `${name} was deleted.`); }}
          onDeactivate={() => { const u = dialog.user; setDialog(null); toggleActive(u); }}
        />
      )}
      {dialog?.kind === 'secret' && (
        <SecretDialog title={dialog.title} username={dialog.username} password={dialog.password} onClose={() => setDialog(null)} />
      )}
    </div>
  );
}
