'use client';

/**
 * DialogHost — renders the confirm dialogs and toasts requested through lib/dialogs.ts.
 * Mounted once in the root layout, so every page (including sign-in) can use askConfirm() and notify().
 */

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { AlertTriangle, CheckCircle, X } from 'lucide-react';
import Modal from '@/components/ui/Modal';
import { dismissToast, getDialogState, resolveConfirm, resolveOverride, subscribe } from '@/lib/dialogs';
import type { OverrideRequest } from '@/lib/dialogs';

/** The "outside the authorized scope" dialog: the reason, and (administrators only) a written reason to run it anyway. */
function OverrideDialog({ req }: { req: OverrideRequest }) {
  const [reason, setReason] = useState('');
  const ok = reason.trim().length >= 10;
  return (
    <Modal
      open title="Outside the authorized scope" width={520} onClose={() => resolveOverride(req.id, null)}
      footer={req.canOverride ? (
        <>
          <button type="button" className="btn btn-ghost" onClick={() => resolveOverride(req.id, null)}>Cancel</button>
          <button type="button" className="btn btn-danger" disabled={!ok} onClick={() => resolveOverride(req.id, reason.trim())}>Run anyway (admin override)</button>
        </>
      ) : (
        <>
          <button type="button" className="btn btn-ghost" onClick={() => resolveOverride(req.id, null)}>Close</button>
          <Link href="/projects" className="btn btn-primary" onClick={() => resolveOverride(req.id, null)}>Open projects</Link>
        </>
      )}
    >
      <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>{req.message}</p>
      {req.canOverride && (
        <div style={{ marginTop: '1rem' }}>
          <label htmlFor="scope-reason" style={{ fontSize: '0.8125rem', fontWeight: 500, display: 'block', marginBottom: 6 }}>Written reason (kept in the audit log)</label>
          <textarea id="scope-reason" className="input" rows={3} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. The customer approved this host by email on 2026-10-07" />
          <div className="help" style={{ marginTop: 4 }}>{reason.trim().length < 10 ? `At least 10 characters (${reason.trim().length}/10)` : 'This override will be recorded with your name.'}</div>
        </div>
      )}
    </Modal>
  );
}

export default function DialogHost() {
  const [, force] = useState(0);
  useEffect(() => subscribe(() => force((n) => n + 1)), []);

  const { confirms, toasts, overrides } = getDialogState();
  const current = confirms[0];
  const override = overrides[0];

  return (
    <>
      {override && <OverrideDialog key={override.id} req={override} />}
      {current && (
        <Modal
          open
          title={current.title}
          width={440}
          onClose={() => resolveConfirm(current.id, false)}
          footer={
            <>
              <button type="button" className="btn btn-ghost" onClick={() => resolveConfirm(current.id, false)}>Cancel</button>
              <button
                type="button"
                className={`btn ${current.danger ? 'btn-danger' : 'btn-primary'}`}
                onClick={() => resolveConfirm(current.id, true)}
              >
                {current.confirmLabel}
              </button>
            </>
          }
        >
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>{current.message}</p>
        </Modal>
      )}

      <div className="toasts" role="region" aria-label="Notifications">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.kind}`} role={t.kind === 'error' ? 'alert' : 'status'}>
            {t.kind === 'error' ? <AlertTriangle size={15} /> : <CheckCircle size={15} />}
            <span>{t.text}</span>
            <button type="button" className="icon-btn" style={{ width: 24, height: 24 }} aria-label="Dismiss" onClick={() => dismissToast(t.id)}>
              <X size={13} />
            </button>
          </div>
        ))}
      </div>
    </>
  );
}
