'use client';

import { useRef, useState } from 'react';

/** Six digit boxes backed by ONE real input (so paste, autofill and one-time-code suggestions all work). */
export default function CodeInput({ value, onChange, label }: { value: string; onChange: (v: string) => void; label: string }) {
  const ref = useRef<HTMLInputElement>(null);
  const [focused, setFocused] = useState(false);
  return (
    <div className="code-boxes" style={{ position: 'relative' }} onClick={() => ref.current?.focus()}>
      {[0, 1, 2, 3, 4, 5].map((i) => (
        <b key={i} className={focused && i === Math.min(value.length, 5) ? 'f' : ''}>{value[i] ?? ''}</b>
      ))}
      <input
        ref={ref} value={value} inputMode="numeric" autoComplete="one-time-code" maxLength={6} aria-label={label}
        onChange={(e) => onChange(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
        onFocus={() => setFocused(true)} onBlur={() => setFocused(false)}
        style={{ position: 'absolute', inset: 0, width: '100%', opacity: 0, cursor: 'text', border: 'none', background: 'transparent' }}
      />
    </div>
  );
}
