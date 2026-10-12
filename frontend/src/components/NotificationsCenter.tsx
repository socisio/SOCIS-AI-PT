'use client';

/**
 * NotificationsCenter — Bell icon with dropdown overlay.
 * Polls /api/v1/scans (recent) to surface newly completed / failed scans.
 * Can be extended to pull from a real /api/v1/notifications endpoint.
 */

import { useState, useEffect, useRef } from 'react';
import { Bell, CheckCircle, XCircle, Clock } from 'lucide-react';
import axios from 'axios';

interface Notification {
  id: string;
  type: 'completed' | 'failed' | 'running';
  title: string;
  detail: string;
  time: string;
  read: boolean;
}

function NotificationIcon({ type }: { type: Notification['type'] }) {
  if (type === 'completed') return <CheckCircle size={14} color="var(--green)" />;
  if (type === 'failed') return <XCircle size={14} color="var(--red)" />;
  return <Clock size={14} color="var(--amber)" />;
}

export default function NotificationsCenter() {
  const [open, setOpen] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const ref = useRef<HTMLDivElement>(null);

  const getToken = () => null;

  const fetchNotifications = async () => {
    try {
      const res = await axios.get(
        `${process.env.NEXT_PUBLIC_API_URL ?? ''}/api/v1/scans/?per_page=10`,
        { withCredentials: true }
      );
      // The list endpoint answers { scans: [...], total, page, per_page }. This used to read `items`, fall back to the whole
      // object and then throw on .slice(), which the catch below hid: the bell never showed anything.
      const scans = res.data?.scans ?? res.data?.items ?? (Array.isArray(res.data) ? res.data : []);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const mapped: Notification[] = scans.slice(0, 10).map((s: any) => ({
        id: s.id,
        type: s.status === 'completed' ? 'completed' : s.status === 'failed' ? 'failed' : 'running',
        title: `Scan: ${s.target}`,
        detail: s.status === 'completed'
          ? `${s.vulnerability_count ?? s.vulnerabilities?.length ?? 0} vulnerabilities found`
          : s.status === 'failed'
          ? 'Scan encountered an error'
          : `Status: ${s.status}`,
        time: s.updated_at ?? s.created_at,
        read: false,
      }));
      setNotifications(mapped);
    } catch {
      // ignore
    }
  };

  // Poll every 30 s
  useEffect(() => {
    fetchNotifications();
    const t = setInterval(fetchNotifications, 30_000);
    return () => clearInterval(t);
  }, []);

  // Close on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const markAllRead = () => setNotifications(n => n.map(x => ({ ...x, read: true })));
  const unread = notifications.filter(n => !n.read).length;

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        onClick={() => { setOpen(o => !o); if (!open) markAllRead(); }}
        style={{
          position: 'relative', background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--text-muted)', padding: '4px', borderRadius: 'var(--radius-sm)',
          display: 'flex', alignItems: 'center',
        }}
        title="Notifications"
      >
        <Bell size={18} />
        {unread > 0 && (
          <span style={{
            position: 'absolute', top: 0, right: 0, width: 14, height: 14, borderRadius: '50%',
            background: 'var(--chart-red)', fontSize: '0.55rem', fontWeight: 700, color: '#fff',
            display: 'flex', alignItems: 'center', justifyContent: 'center', lineHeight: 1,
          }}>
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div style={{
          position: 'absolute', right: 0, top: '110%', width: 340, zIndex: 100,
          background: 'var(--bg-secondary)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)', boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
          overflow: 'hidden',
        }}>
          <div style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            padding: '0.875rem 1rem', borderBottom: '1px solid var(--border)',
          }}>
            <span style={{ fontWeight: 700, fontSize: '0.875rem' }}>Recent Activity</span>
            <button onClick={markAllRead} style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '0.75rem', color: 'var(--cyan)' }}>
              Mark all read
            </button>
          </div>

          <div style={{ maxHeight: 400, overflowY: 'auto' }}>
            {notifications.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                No recent activity
              </div>
            ) : notifications.map(n => (
              <div key={n.id} style={{
                padding: '0.75rem 1rem', borderBottom: '1px solid var(--border)',
                display: 'flex', gap: '0.75rem', alignItems: 'flex-start',
                background: n.read ? 'transparent' : 'color-mix(in srgb, var(--cyan) 3%, transparent)',
              }}>
                <div style={{ marginTop: 2 }}><NotificationIcon type={n.type} /></div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: '0.8125rem', color: 'var(--text-primary)', marginBottom: 2 }}>
                    {n.title}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{n.detail}</div>
                  <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: 3 }}>
                    {new Date(n.time).toLocaleString()}
                  </div>
                </div>
                {!n.read && (
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--cyan)', flexShrink: 0, marginTop: 5 }} />
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
