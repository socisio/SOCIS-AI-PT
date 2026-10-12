// An accessible on/off switch (role="switch"), styled by the .sw classes.
export default function Toggle({
  checked, onChange, label, disabled,
}: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button
      type="button" role="switch" aria-checked={checked} aria-label={label} disabled={disabled}
      className={`sw${checked ? ' on' : ''}`} onClick={() => onChange(!checked)}
      style={{ border: 'none', padding: 0, cursor: disabled ? 'not-allowed' : 'pointer', opacity: disabled ? 0.5 : 1 }}
    />
  );
}
