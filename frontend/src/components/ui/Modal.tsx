'use client';

/**
 * Modal — an accessible dialog: Esc and backdrop click close it, Tab stays inside it,
 * focus returns to the control that opened it, and the page behind does not scroll.
 */

import { useEffect, useRef } from 'react';
import { X } from 'lucide-react';

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export default function Modal({
  open, title, onClose, children, footer, width = 520,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
  width?: number;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  // Keep the latest onClose without re-running the effect (a re-run would steal focus while typing).
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    if (!open) return;
    const opener = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const focusables = (): HTMLElement[] =>
      Array.from(panelRef.current ? panelRef.current.querySelectorAll<HTMLElement>(FOCUSABLE) : []);

    const t = setTimeout(() => {
      const first = focusables()[0];
      (first ?? panelRef.current)?.focus();
    }, 0);

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.preventDefault(); closeRef.current(); return; }
      if (e.key !== 'Tab') return;
      const f = focusables();
      if (f.length === 0) return;
      const first = f[0];
      const last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', onKey);

    return () => {
      clearTimeout(t);
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prevOverflow;
      opener?.focus();
    };
  }, [open]);

  if (!open) return null;

  return (
    <div className="modal-backdrop" onMouseDown={() => closeRef.current()}>
      <div
        ref={panelRef}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        tabIndex={-1}
        style={{ maxWidth: width }}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="modal-head">
          <h2 id="modal-title">{title}</h2>
          <button className="icon-btn" onClick={() => closeRef.current()} aria-label="Close dialog" type="button">
            <X size={16} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}
