'use client';

import { useState } from 'react';
import Panel, { FormRow } from '@/components/ui/Panel';
import Toggle from '@/components/ui/Toggle';
import { SectionHead } from '@/components/settings/SettingsShell';
import { notify } from '@/lib/dialogs';
import { apiError } from '@/lib/errors';
import { useSystemSettings } from '@/lib/useSystemSettings';
import type { SystemForm } from '@/lib/useSystemSettings';

const ROWS: { key: 'email_on_scan_complete' | 'email_on_vulnerability' | 'email_on_critical_finding'; label: string; help: string }[] = [
  { key: 'email_on_scan_complete', label: 'Scan complete', help: 'An email when one of your scans finishes.' },
  { key: 'email_on_vulnerability', label: 'Vulnerability found', help: 'An email when a scan finds any vulnerability.' },
  { key: 'email_on_critical_finding', label: 'Critical finding', help: 'An email as soon as a critical finding is detected.' },
];

export default function NotificationsSection() {
  const { data, setData, save, dirty, discard } = useSystemSettings();
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (!data) return;
    setBusy(true);
    try { await save(data); notify('Notification preferences saved', 'success'); }
    catch (e) { notify(apiError(e, 'Could not save'), 'error'); }
    finally { setBusy(false); }
  };
  return (
    <>
      <SectionHead title="Notifications" desc="Choose which events send you an email. Delivery itself (SMTP or Microsoft Graph) is set up by an administrator." />
      <Panel
        title="Email me when"
        foot={<><span className="grow">{dirty ? 'You have unsaved changes' : ''}</span>
          <button className="btn btn-ghost btn-sm" disabled={!dirty || busy} onClick={discard}>Discard</button>
          <button className="btn btn-primary btn-sm" disabled={!dirty || busy} onClick={submit}>Save changes</button></>}
      >
        {data === null ? <div className="help" style={{ padding: '1.25rem' }}>Loading…</div> : ROWS.map((r) => (
          <FormRow key={r.key} label={r.label} help={r.help}>
            <Toggle label={r.label} checked={data[r.key]} onChange={(v) => setData({ ...data, [r.key]: v } as SystemForm)} />
          </FormRow>
        ))}
      </Panel>
    </>
  );
}
