'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';

interface MetasploitTerminalProps {
  scanId: string;
  sessionId?: number | null;
  height?: number;
}

function getTokenFromCookie(): string {
  if (typeof document === 'undefined') return '';
  return document.cookie.split('; ').find(c => c.startsWith('access_token='))?.split('=')[1] ?? '';
}

function makeWsBaseUrl(): string {
  const apiBase = process.env.NEXT_PUBLIC_API_URL ||
    (typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8000');
  return apiBase.replace(/^http/, 'ws');
}

export default function MetasploitTerminal({ scanId, sessionId, height = 360 }: MetasploitTerminalProps) {
  const termEl = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const [command, setCommand] = useState('');
  const [connected, setConnected] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);

  const disabled = useMemo(() => !sessionId || !scanId, [sessionId, scanId]);

  // Mount xterm once
  useEffect(() => {
    if (!termEl.current || termRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: 'JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace',
      fontSize: 12,
      theme: {
        background: '#0a0e17',
        foreground: '#f1f5f9',
        cursor: '#0ff0fc',
        selectionBackground: '#0ff0fc44',
      },
      convertEol: true,
      scrollback: 4000,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(termEl.current);
    fit.fit();

    term.writeln('SOCIS Metasploit Interactive Terminal');
    term.writeln('Select/attach a session, then run commands.');
    term.writeln('');

    termRef.current = term;
    fitRef.current = fit;

    const onResize = () => fitRef.current?.fit();
    window.addEventListener('resize', onResize);

    return () => {
      window.removeEventListener('resize', onResize);
      wsRef.current?.close();
      termRef.current?.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, []);

  // Connect/reconnect WebSocket when session changes
  useEffect(() => {
    if (disabled) {
      setConnected(false);
      wsRef.current?.close();
      wsRef.current = null;
      return;
    }

    const term = termRef.current;
    if (!term) return;

    wsRef.current?.close();

    const token = getTokenFromCookie();
    const wsUrl = `${makeWsBaseUrl()}/ws/metasploit/session/${sessionId}?scan_id=${encodeURIComponent(scanId)}&token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      setLastError(null);
      term.writeln(`\r\n[connected] session ${sessionId}`);
      term.write('\r\n$ ');
    };

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'output') {
          const out = String(msg.content || '');
          if (out.trim()) term.writeln(`\r\n${out}`);
          term.write('\r\n$ ');
          return;
        }
        if (msg.type === 'warning') {
          term.writeln(`\r\n[warn] ${String(msg.content || '')}`);
          term.write('\r\n$ ');
          return;
        }
        if (msg.type === 'error') {
          const text = String(msg.content || 'command error');
          setLastError(text);
          term.writeln(`\r\n[error] ${text}`);
          term.write('\r\n$ ');
        }
      } catch {
        term.writeln(`\r\n${String(ev.data)}`);
        term.write('\r\n$ ');
      }
    };

    ws.onclose = () => {
      setConnected(false);
      term.writeln('\r\n[disconnected]');
    };

    ws.onerror = () => {
      setConnected(false);
      setLastError('Terminal websocket failed');
    };

    return () => {
      ws.close();
      if (wsRef.current === ws) wsRef.current = null;
      setConnected(false);
    };
  }, [disabled, sessionId, scanId]);

  const runCommand = () => {
    const cmd = command.trim();
    if (!cmd || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    wsRef.current.send(JSON.stringify({ action: 'command', command: cmd }));
    termRef.current?.writeln(`\r\n> ${cmd}`);
    setCommand('');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div
        ref={termEl}
        style={{
          width: '100%',
          height,
          border: '1px solid var(--border)',
          borderRadius: 8,
          overflow: 'hidden',
          background: '#0a0e17',
        }}
      />

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <input
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') runCommand();
          }}
          placeholder={disabled ? 'Select a session first' : 'Enter shell/meterpreter command'}
          disabled={disabled || !connected}
          style={{
            flex: 1,
            background: 'var(--bg-card)',
            color: 'var(--text-primary)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            fontSize: 12,
            padding: '0.55rem 0.7rem',
            outline: 'none',
          }}
        />
        <button
          onClick={runCommand}
          disabled={disabled || !connected || !command.trim()}
          style={{
            border: '1px solid var(--cyan-dim)',
            color: 'var(--cyan)',
            background: 'transparent',
            borderRadius: 6,
            padding: '0.5rem 0.9rem',
            cursor: disabled || !connected ? 'not-allowed' : 'pointer',
            fontSize: 12,
            fontWeight: 600,
          }}
        >
          Run
        </button>
      </div>

      <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
        Status: {connected ? 'connected' : 'disconnected'}
        {sessionId ? ` | Session ${sessionId}` : ''}
        {lastError ? ` | Error: ${lastError}` : ''}
      </div>
    </div>
  );
}
