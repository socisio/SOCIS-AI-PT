'use client';

import { useEffect, useState } from 'react';
import { settingsApi } from '@/lib/api';
import Panel, { FormRow } from '@/components/ui/Panel';
import { SectionHead } from '@/components/settings/SettingsShell';
import { notify } from '@/lib/dialogs';
import { apiError } from '@/lib/errors';

interface ReportForm {
  brand_name: string; brand_tagline: string; brand_color: string; brand_logo_url: string;
  customer_name: string; customer_logo_url: string; report_theme: 'dark' | 'light'; report_classification: string;
}

const DEFAULTS: ReportForm = {
  brand_name: 'SOCIS-AI-PT', brand_tagline: 'AI-Powered Penetration Testing Platform',
  brand_color: '#0ff0fc', // hex-ok: stored and injected into the PDF/HTML report template (--accent); a CSS variable cannot work there
  brand_logo_url: '', customer_name: '', customer_logo_url: '', report_theme: 'light', report_classification: 'Confidential',
};

export default function ReportsSection() {
  const [f, setF] = useState<ReportForm | null>(null);
  const [saved, setSaved] = useState<ReportForm | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    settingsApi.getReportSettings().catch(() => null).then((r) => {
      const v = { ...DEFAULTS, ...(r?.data ?? {}) } as ReportForm; setF(v); setSaved(v);
    });
  }, []);

  const dirty = f !== null && saved !== null && JSON.stringify(f) !== JSON.stringify(saved);
  const set = (patch: Partial<ReportForm>) => setF((cur) => (cur ? { ...cur, ...patch } : cur));
  const submit = async () => {
    if (!f) return;
    setBusy(true);
    try { await settingsApi.saveReportSettings({ ...f }); setSaved(f); notify('Report settings saved', 'success'); }
    catch (e) { notify(apiError(e, 'Could not save report settings'), 'error'); }
    finally { setBusy(false); }
  };
  if (!f) return <><SectionHead title="Reports & branding" desc="How your reports look." /><div className="help">Loading…</div></>;

  return (
    <>
      <SectionHead title="Reports & branding" desc="How the reports you generate look: your branding, an optional customer logo, and the classification label." />
      <Panel title="Platform branding" desc="Shown in the report header and cover page.">
        <FormRow label="Brand name" htmlFor="rb-name"><input id="rb-name" className="input" value={f.brand_name} onChange={(e) => set({ brand_name: e.target.value })} /></FormRow>
        <FormRow label="Tagline" htmlFor="rb-tag"><input id="rb-tag" className="input" value={f.brand_tagline} onChange={(e) => set({ brand_tagline: e.target.value })} /></FormRow>
        <FormRow label="Brand color" help="A hex color value, with the leading hash." htmlFor="rb-col">
          <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
            <input id="rb-col" className="input mono" value={f.brand_color} onChange={(e) => set({ brand_color: e.target.value })} />
            <span aria-hidden="true" style={{ width: 40, height: 34, borderRadius: 8, border: '1px solid var(--border)', background: f.brand_color, flexShrink: 0 }} />
          </div>
        </FormRow>
        <FormRow label="Logo URL" help="Shown at the top of each report." htmlFor="rb-logo">
          <input id="rb-logo" className="input" placeholder="https://example.com/logo.png" value={f.brand_logo_url} onChange={(e) => set({ brand_logo_url: e.target.value })} />
          {/* eslint-disable-next-line @next/next/no-img-element */}
          {f.brand_logo_url && <img src={f.brand_logo_url} alt="Brand logo preview" style={{ maxWidth: 120, maxHeight: 48, objectFit: 'contain', marginTop: 6 }} />}
        </FormRow>
      </Panel>
      <Panel title="Customer branding (white label)" desc="Optional: put your customer on the report as well.">
        <FormRow label="Customer name" htmlFor="rb-cust"><input id="rb-cust" className="input" placeholder="Leave empty for platform-only reports" value={f.customer_name} onChange={(e) => set({ customer_name: e.target.value })} /></FormRow>
        <FormRow label="Customer logo URL" htmlFor="rb-clogo">
          <input id="rb-clogo" className="input" placeholder="https://example.com/customer-logo.png" value={f.customer_logo_url} onChange={(e) => set({ customer_logo_url: e.target.value })} />
          {/* eslint-disable-next-line @next/next/no-img-element */}
          {f.customer_logo_url && <img src={f.customer_logo_url} alt="Customer logo preview" style={{ maxWidth: 120, maxHeight: 48, objectFit: 'contain', marginTop: 6 }} />}
        </FormRow>
      </Panel>
      <Panel
        title="Report options"
        foot={<><span className="grow">{dirty ? 'You have unsaved changes' : ''}</span>
          <button className="btn btn-ghost btn-sm" disabled={!dirty || busy} onClick={() => setF(saved)}>Discard</button>
          <button className="btn btn-primary btn-sm" disabled={!dirty || busy} onClick={submit}>Save changes</button></>}
      >
        <FormRow label="Report theme" htmlFor="rb-theme">
          <select id="rb-theme" className="input" value={f.report_theme} onChange={(e) => set({ report_theme: e.target.value === 'dark' ? 'dark' : 'light' })}>
            <option value="light">Light</option><option value="dark">Dark</option></select>
        </FormRow>
        <FormRow label="Classification label" help="Printed on every page, for example Confidential or Restricted." htmlFor="rb-class">
          <input id="rb-class" className="input" placeholder="Confidential" value={f.report_classification} onChange={(e) => set({ report_classification: e.target.value })} />
        </FormRow>
      </Panel>
    </>
  );
}
