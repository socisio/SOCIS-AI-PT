export default function Card({
  title, right, children, className,
}: { title?: string; right?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <section className={`card${className ? ' ' + className : ''}`}>
      {(title || right) && (
        <div className="card-head">
          {title && <h2>{title}</h2>}
          {right && <div className="right">{right}</div>}
        </div>
      )}
      {children}
    </section>
  );
}
