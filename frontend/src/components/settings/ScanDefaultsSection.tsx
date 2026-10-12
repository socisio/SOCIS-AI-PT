'use client';

import { useState } from 'react';
import Panel, { FormRow } from '@/components/ui/Panel';
import Toggle from '@/components/ui/Toggle';
import { SectionHead } from '@/components/settings/SettingsShell';
import { notify } from '@/lib/dialogs';
import { apiError } from '@/lib/errors';
import { useSystemSettings } from '@/lib/useSystemSettings';

export default function ScanDefaultsSection() {
  const { data, setData, save, dirty, discard } = useSystemSettings();
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (!data) return;
    setBusy(true);
    try { await save(data); notify('Scan defaults saved', 'success'); }
    catch (e) { notify(apiError(e, 'Could not save'), 'error'); }
    finally { setBusy(false); }
  };
  const num = (v: string, fallback: number) => { const n = parseInt(v, 10); return Number.isFinite(n) && n > 0 ? n : fallback; };
  return (
    <>
      <SectionHead title="Scan defaults" desc="Limits that apply to the requests you make." />
      <Panel
        title="Rate limiting"
        foot={<><span className="grow">{dirty ? 'You have unsaved changes' : ''}</span>
          <button className="btn btn-ghost btn-sm" disabled={!dirty || busy} onClick={discard}>Discard</button>
          <button className="btn btn-primary btn-sm" disabled={!dirty || busy} onClick={submit}>Save changes</button></>}
      >
        {data === null ? <div className="help" style={{ padding: '1.25rem' }}>Loading…</div> : (
          <>
            <FormRow label="Enable rate limiting" help="Protects the platform from runaway request loops.">
              <Toggle label="Enable rate limiting" checked={data.rate_limit_enabled} onChange={(v) => setData({ ...data, rate_limit_enabled: v })} />
            </FormRow>
            {data.rate_limit_enabled && (
              <>
                <FormRow label="Requests per window" htmlFor="rl-req">
                  <input id="rl-req" className="input" type="number" min={1} value={data.rate_limit_requests} onChange={(e) => setData({ ...data, rate_limit_requests: num(e.target.value, data.rate_limit_requests) })} />
                </FormRow>
                <FormRow label="Time window (seconds)" htmlFor="rl-win">
                  <input id="rl-win" className="input" type="number" min={1} value={data.rate_limit_window} onChange={(e) => setData({ ...data, rate_limit_window: num(e.target.value, data.rate_limit_window) })} />
                </FormRow>
              </>
            )}
            <FormRow label="Deployment mode" help="Set by the DEPLOYMENT_MODE environment variable.">
              <div><code className="mono" style={{ padding: '0.2rem 0.5rem', background: 'var(--bg-hover)', borderRadius: 6 }}>{data.deployment_mode}</code></div>
            </FormRow>
          </>
        )}
      </Panel>
    </>
  );
}
