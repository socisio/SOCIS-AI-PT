'use client';

/**
 * ThemeToggle — Switches between dark (default) and light theme
 * by toggling data-theme="light" on <html>. Persists to localStorage.
 * (layout.tsx applies the saved theme before first paint, so there is no flash.)
 */

import { useEffect, useState } from 'react';
import { Sun, Moon } from 'lucide-react';
import { applyTheme, getThemePref, resolveTheme } from '@/lib/theme';

export default function ThemeToggle() {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  useEffect(() => {
    // The saved preference may be "system": show what is actually applied.
    setTheme(resolveTheme(getThemePref()));
  }, []);

  const toggle = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    applyTheme(next);
  };

  const label = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
  return (
    <button className="icon-btn" onClick={toggle} title={label} aria-label={label}>
      {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
    </button>
  );
}
