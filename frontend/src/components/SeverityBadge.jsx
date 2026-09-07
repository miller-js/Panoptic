import { severityMeta } from '../severity'

// Severity as glyph + text label + colour — never colour alone.
export default function SeverityBadge({ severity, size = 'md' }) {
  const meta = severityMeta(severity)
  return (
    <span className={`sev-badge sev-${meta.statusKey} sev-${size}`}>
      <span className="sev-glyph" aria-hidden="true">
        {meta.glyph}
      </span>
      {meta.label}
    </span>
  )
}
