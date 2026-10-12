// A titled card used by Settings and Administration: head, rows, optional footer (save bar).
export default function Panel({
  title, desc, end, foot, children,
}: { title?: string; desc?: string; end?: React.ReactNode; foot?: React.ReactNode; children?: React.ReactNode }) {
  return (
    <section className="panel">
      {(title || end) && (
        <div className="panel-head">
          <div>
            {title && <h3>{title}</h3>}
            {desc && <p>{desc}</p>}
          </div>
          {end && <div className="end">{end}</div>}
        </div>
      )}
      {children}
      {foot && <div className="panel-foot">{foot}</div>}
    </section>
  );
}

// One label + control row inside a Panel.
export function FormRow({
  label, help, htmlFor, children,
}: { label: string; help?: string; htmlFor?: string; children: React.ReactNode }) {
  return (
    <div className="frow">
      <div>
        <label className="lab" htmlFor={htmlFor} style={{ display: 'block' }}>{label}</label>
        {help && <div className="help">{help}</div>}
      </div>
      <div className="ctl">{children}</div>
    </div>
  );
}

export type PillTone = 'green' | 'amber' | 'red' | 'blue' | 'gray' | 'purple';

export function Pill({ tone = 'gray', dot, children }: { tone?: PillTone; dot?: boolean; children: React.ReactNode }) {
  return <span className={`pill ${tone}`}>{dot && <i className="d" />}{children}</span>;
}
