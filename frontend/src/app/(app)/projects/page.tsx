'use client';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Plus, FolderKanban, Radar, Edit3, Trash2, ArrowRight, Archive } from 'lucide-react';
import { authApi, projectsApi } from '@/lib/api';
import type { MeUser } from '@/lib/api';
import type { Project } from '@/lib/types';
import ProjectScopeDialog from '@/components/projects/ProjectScopeDialog';
import Icon from '@/components/ui/Icon';
import { notify } from '@/lib/dialogs';

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', description: '', scope: '' });
  const [saving, setSaving] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [authorizeNow, setAuthorizeNow] = useState(true);
  const [scopeFor, setScopeFor] = useState<Project | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const res = await projectsApi.list();
      setProjects(res.data.projects || []);
      setTotal(res.data.total || 0);
    } catch (error: any) {
      setProjects([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);
  useEffect(() => {
    authApi.me().then((r) => { const u = r.data as MeUser; setIsAdmin(Boolean(u.is_superuser) || u.role === 'admin'); }).catch(() => {});
  }, []);

  const handleCreate = async () => {
    if (!form.name) {
      notify('Project name is required', 'error');
      return;
    }
    setSaving(true);
    try {
      // An administrator can authorize the requested targets right away; anyone else's request waits for an administrator.
      const authorize = isAdmin && authorizeNow && form.scope.trim()
        ? { scope_targets: form.scope.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean), scope_enforced: true }
        : {};
      await projectsApi.create({ ...form, ...authorize });
      setShowCreate(false);
      setForm({ name: '', description: '', scope: '' });
      load();
    } catch (error: any) {
      console.error('Create project error:', error);
      const errorMsg = error?.response?.data?.detail || error?.message || 'Failed to create project';
      notify(errorMsg, 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await projectsApi.delete(id);
      load();
    } catch (error: any) {
      console.error('Delete project error:', error);
      const errorMsg = error?.response?.data?.detail || error?.message || 'Failed to delete project';
      notify(errorMsg, 'error');
    }
  };

  const STATUS_COLORS: Record<string, string> = {
    active: 'var(--green)', completed: 'var(--blue)', archived: 'var(--text-secondary)', paused: 'var(--amber)',
  };

  return (
    <div className="animate-fadeIn" style={{ padding: '2rem', width: '100%' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1>Projects</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: 4 }}>{total} projects</p>
        </div>
        <button onClick={() => setShowCreate(true)} className="btn btn-primary">
          <Plus size={16} /> New Project
        </button>
      </div>

      {/* Create Modal */}
      {showCreate && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50,
        }}>
          <div className="card" style={{ width: 480, padding: '2rem' }}>
            <h2 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1.5rem' }}>Create Project</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
              <div>
                <label style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>Project Name *</label>
                <input className="input" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Q2 External PT" />
              </div>
              <div>
                <label style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>Description</label>
                <textarea className="input" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="Project goals, client info..." rows={3} style={{ resize: 'vertical' }} />
              </div>
              <div>
                <label style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>Requested scope (IP ranges, domains)</label>
                <input className="input" value={form.scope} onChange={e => setForm(f => ({ ...f, scope: e.target.value }))}
                  placeholder="192.168.1.0/24, example.com" />
                {isAdmin ? (
                  <label style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 8, fontSize: '0.8125rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                    <input type="checkbox" checked={authorizeNow} onChange={(e) => setAuthorizeNow(e.target.checked)} /> Also authorize these targets now
                  </label>
                ) : (
                  <div style={{ marginTop: 6, fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>An administrator approves targets before scans can run.</div>
                )}
              </div>
            </div>
            <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1.5rem', justifyContent: 'flex-end' }}>
              <button onClick={() => setShowCreate(false)} className="btn btn-ghost">Cancel</button>
              <button onClick={handleCreate} disabled={saving || !form.name} className="btn btn-primary">
                {saving ? 'Creating...' : 'Create Project'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Projects Grid */}
      {loading ? (
        <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '4rem' }}>Loading projects...</div>
      ) : projects.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '4rem', color: 'var(--text-muted)' }}>
          <FolderKanban size={48} style={{ margin: '0 auto 1rem', opacity: 0.3 }} />
          <p>No projects yet.</p>
          <button onClick={() => setShowCreate(true)} className="btn btn-primary" style={{ marginTop: '1rem' }}>
            <Plus size={15} /> Create your first project
          </button>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '1rem' }}>
          {projects.map(p => (
            <div key={p.id} className="card" style={{ position: 'relative' }}>
              {/* Status */}
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.875rem' }}>
                <span style={{
                  fontSize: '0.6875rem', padding: '2px 8px', borderRadius: 99,
                  background: `color-mix(in srgb, ${STATUS_COLORS[p.status] || 'var(--text-muted)'} 8%, transparent)`,
                  color: STATUS_COLORS[p.status] || 'var(--text-secondary)',
                  border: `1px solid color-mix(in srgb, ${STATUS_COLORS[p.status] || 'var(--border-strong)'} 19%, transparent)`,
                  textTransform: 'capitalize',
                }}>
                  {p.status}
                </span>
                <div style={{ display: 'flex', gap: 4 }}>
                  <button onClick={() => handleDelete(p.id)} className="btn btn-ghost" style={{ padding: '0.25rem', color: 'var(--red)' }}>
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>

              <h3 style={{ fontWeight: 600, fontSize: '1rem', marginBottom: '0.4rem' }}>{p.name}</h3>
              {p.description && <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginBottom: '0.875rem', lineHeight: 1.5 }}>{p.description}</p>}
              {p.scope && (
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '0.875rem' }}>
                  📍 {p.scope}
                </div>
              )}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.875rem' }}>
                <span className={`pill ${p.scope_enforced ? ((p.scope_targets ?? []).length === 0 ? 'red' : 'green') : 'amber'}`}>
                  {p.scope_enforced ? ((p.scope_targets ?? []).length === 0 ? 'Scope enforced · nothing authorized yet' : `Scope enforced · ${(p.scope_targets ?? []).length} authorized`) : 'Scope not enforced'}
                </span>
                <button className="btn btn-ghost btn-sm" style={{ marginLeft: 'auto' }} onClick={() => setScopeFor(p)}><Icon name="shieldcheck" size={13} /> Scope</button>
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: 'auto', paddingTop: '0.875rem', borderTop: '1px solid var(--border)' }}>
                <Link href={`/scans/new?project_id=${p.id}`} className="btn btn-ghost" style={{ flex: 1, justifyContent: 'center', fontSize: '0.8125rem', padding: '0.4rem' }}>
                  <Radar size={13} /> New Scan
                </Link>
                <Link href={`/scans?project_id=${p.id}`} className="btn btn-ghost" style={{ flex: 1, justifyContent: 'center', fontSize: '0.8125rem', padding: '0.4rem' }}>
                  View Scans <ArrowRight size={13} />
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}

      {scopeFor && <ProjectScopeDialog projectId={scopeFor.id} projectName={scopeFor.name} onClose={() => setScopeFor(null)} onChanged={load} />}
    </div>
  );
}
