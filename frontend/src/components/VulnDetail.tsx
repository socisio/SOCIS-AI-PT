'use client';
import React, { useState, useEffect, useCallback } from 'react';
import { Calendar, User, Tag, Clock, Send, Trash2, MessageSquare, ExternalLink, Save, Loader2 } from 'lucide-react';
import { vulnsApi, llmApi } from '@/lib/api';
import type { Vulnerability, VulnComment, DirectoryUser } from '@/lib/types';
import { notify } from '@/lib/dialogs';
import { SEV_COLORS, SEV_ON_COLOR, PRIORITY_META, STATUS_META, getSlaStatus } from '@/lib/vulns';

/**
 * The single, shared vulnerability detail view — management fields, comments, CVE/description, SLA.
 *
 * Replaces two near-identical implementations (the inline panel in vulnerabilities/page.tsx and the standalone
 * vulnerabilities/[id]/page.tsx). Both now render this. Every color is a CSS variable so it works in the
 * light and dark themes, and every failed action surfaces via notify() instead of being silently swallowed.
 *
 * Controlled only by `vuln` + `users`; it owns its own form/comment state and calls `onSaved` after a successful
 * save so the parent can refresh its list.
 */
export default function VulnDetail({
  vuln,
  users,
  onSaved,
  compact = false,
}: {
  vuln: Vulnerability;
  users: DirectoryUser[];
  onSaved?: () => void;
  compact?: boolean;
}) {
  const [status, setStatus] = useState(vuln.status || 'open');
  const [priority, setPriority] = useState(vuln.priority || '');
  const [assignedTo, setAssignedTo] = useState(vuln.assigned_to || '');
  const [dueDate, setDueDate] = useState(vuln.due_date ? vuln.due_date.slice(0, 10) : '');
  const [notes, setNotes] = useState(vuln.notes || '');
  const [tagInput, setTagInput] = useState((vuln.tags || []).join(', '));
  const [saving, setSaving] = useState(false);

  const [comments, setComments] = useState<VulnComment[]>([]);
  const [newComment, setNewComment] = useState('');
  const [postingComment, setPostingComment] = useState(false);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [cveData, setCveData] = useState<any>(null);
  const [loadingCve, setLoadingCve] = useState(false);

  // Re-sync form + reload comments whenever the subject vuln changes.
  useEffect(() => {
    setStatus(vuln.status || 'open');
    setPriority(vuln.priority || '');
    setAssignedTo(vuln.assigned_to || '');
    setDueDate(vuln.due_date ? vuln.due_date.slice(0, 10) : '');
    setNotes(vuln.notes || '');
    setTagInput((vuln.tags || []).join(', '));
    setCveData(null);

    vulnsApi.listComments(vuln.id)
      .then((r) => setComments(r.data || []))
      .catch(() => notify('Could not load comments for this vulnerability.', 'error'));

    if (vuln.cve_id && !vuln.cve_description) {
      setLoadingCve(true);
      llmApi.cve(vuln.cve_id)
        .then((r) => setCveData(r.data))
        .catch(() => {}) // CVE enrichment is best-effort; absence is not an error worth a toast
        .finally(() => setLoadingCve(false));
    }
  }, [vuln]);

  const handleSave = useCallback(async () => {
    setSaving(true);
    try {
      const tags = tagInput.split(',').map((t) => t.trim()).filter(Boolean);
      await vulnsApi.manage(vuln.id, {
        status,
        priority: priority || null,
        assigned_to: assignedTo || null,
        due_date: dueDate ? new Date(dueDate).toISOString() : null,
        notes: notes || null,
        tags,
      });
      notify('Changes saved', 'success');
      onSaved?.();
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.message || 'Unknown error';
      notify(`Save failed: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`, 'error');
    } finally {
      setSaving(false);
    }
  }, [vuln.id, status, priority, assignedTo, dueDate, notes, tagInput, onSaved]);

  const handlePostComment = useCallback(async () => {
    if (!newComment.trim()) return;
    setPostingComment(true);
    try {
      const res = await vulnsApi.addComment(vuln.id, newComment.trim());
      setComments((prev) => [...prev, res.data]);
      setNewComment('');
    } catch {
      notify('Could not post comment.', 'error');
    } finally {
      setPostingComment(false);
    }
  }, [vuln.id, newComment]);

  const handleDeleteComment = useCallback(async (commentId: string) => {
    try {
      await vulnsApi.deleteComment(vuln.id, commentId);
      setComments((prev) => prev.filter((c) => c.id !== commentId));
    } catch {
      notify('Could not delete comment.', 'error');
    }
  }, [vuln.id]);

  const sla = getSlaStatus(vuln);
  const sevColor = SEV_COLORS[vuln.severity] || 'var(--text-secondary)';
  const labelStyle: React.CSSProperties = { fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 };
  const description = vuln.cve_description || vuln.description;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: compact ? '1rem' : '1.5rem' }}>
      {/* Severity + identifiers */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ fontSize: '0.6875rem', fontWeight: 600, color: SEV_ON_COLOR, background: sevColor, borderRadius: 5, padding: '2px 8px', textTransform: 'capitalize' }}>
          {vuln.severity}
        </span>
        {vuln.cve_id && (
          <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{vuln.cve_id}</span>
        )}
        {vuln.owasp_category && (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>· {vuln.owasp_category}</span>
        )}
        {vuln.mitre_technique && (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>· {vuln.mitre_technique}</span>
        )}
        {sla && (
          <span style={{ fontSize: '0.75rem', color: sla.color, marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4 }}>
            <Clock size={12} /> {sla.label}
          </span>
        )}
      </div>

      {/* Description */}
      {description && (
        <div>
          <span style={labelStyle}>Description</span>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.7, margin: 0 }}>{description}</p>
        </div>
      )}

      {/* CVE enrichment */}
      {loadingCve && <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Loading CVE details…</p>}
      {cveData?.description && (
        <div style={{ background: 'var(--bg-secondary)', border: '0.5px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '0.75rem' }}>
          <span style={labelStyle}>CVE detail</span>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.7, margin: 0 }}>{cveData.description}</p>
        </div>
      )}

      {/* ── Management fields ── */}
      <div style={{ display: 'grid', gridTemplateColumns: compact ? '1fr' : '1fr 1fr', gap: '0.75rem' }}>
        <div>
          <label htmlFor="vd-status" style={labelStyle}>Status</label>
          <select id="vd-status" className="input" value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUS_META.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
        </div>
        <div>
          <label htmlFor="vd-priority" style={labelStyle}>Priority</label>
          <select id="vd-priority" className="input" value={priority} onChange={(e) => setPriority(e.target.value)}>
            <option value="">— none —</option>
            {Object.entries(PRIORITY_META).map(([id, m]) => <option key={id} value={id}>{m.longLabel}</option>)}
          </select>
        </div>
        <div>
          <label htmlFor="vd-assignee" style={labelStyle}><User size={12} style={{ verticalAlign: -2, marginRight: 4 }} />Assigned to</label>
          <select id="vd-assignee" className="input" value={assignedTo} onChange={(e) => setAssignedTo(e.target.value)}>
            <option value="">— unassigned —</option>
            {users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
          </select>
        </div>
        <div>
          <label htmlFor="vd-due" style={labelStyle}><Calendar size={12} style={{ verticalAlign: -2, marginRight: 4 }} />Due date</label>
          <input id="vd-due" type="date" className="input" value={dueDate} onChange={(e) => setDueDate(e.target.value)} />
        </div>
      </div>

      <div>
        <label htmlFor="vd-tags" style={labelStyle}><Tag size={12} style={{ verticalAlign: -2, marginRight: 4 }} />Tags (comma-separated)</label>
        <input id="vd-tags" className="input" value={tagInput} onChange={(e) => setTagInput(e.target.value)} placeholder="e.g. external, pci, prod" />
      </div>

      <div>
        <label htmlFor="vd-notes" style={labelStyle}>Notes</label>
        <textarea id="vd-notes" className="input" value={notes} onChange={(e) => setNotes(e.target.value)} rows={3} style={{ resize: 'vertical' }} />
      </div>

      <button onClick={handleSave} disabled={saving} className="btn btn-primary" style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: 6 }}>
        {saving ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Save size={14} />}
        {saving ? 'Saving…' : 'Save changes'}
      </button>

      {/* ── Comments ── */}
      <div style={{ borderTop: '0.5px solid var(--border)', paddingTop: '1rem' }}>
        <span style={{ ...labelStyle, display: 'flex', alignItems: 'center', gap: 5 }}>
          <MessageSquare size={13} /> Comments ({comments.length})
        </span>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '0.75rem' }}>
          {comments.map((c) => (
            <div key={c.id} style={{ background: 'var(--bg-secondary)', border: '0.5px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '0.5rem 0.75rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 2 }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-secondary)' }}>{c.username || 'User'}</span>
                <button
                  onClick={() => handleDeleteComment(c.id)}
                  className="btn btn-ghost"
                  aria-label="Delete comment"
                  style={{ padding: 2 }}
                ><Trash2 size={12} /></button>
              </div>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-primary)', margin: 0, whiteSpace: 'pre-wrap' }}>{c.content}</p>
            </div>
          ))}
          {comments.length === 0 && <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>No comments yet.</p>}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <input
            className="input"
            value={newComment}
            onChange={(e) => setNewComment(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handlePostComment(); } }}
            placeholder="Add a comment…"
            style={{ flex: 1 }}
          />
          <button onClick={handlePostComment} disabled={postingComment || !newComment.trim()} className="btn btn-primary" aria-label="Post comment" style={{ padding: '0 12px' }}>
            <Send size={14} />
          </button>
        </div>
      </div>

      {vuln.cve_references && vuln.cve_references.length > 0 && (
        <a href={vuln.cve_references[0]} target="_blank" rel="noopener noreferrer" style={{ fontSize: '0.8125rem', color: 'var(--cyan)', display: 'flex', alignItems: 'center', gap: 4 }}>
          <ExternalLink size={13} /> Reference
        </a>
      )}
    </div>
  );
}
