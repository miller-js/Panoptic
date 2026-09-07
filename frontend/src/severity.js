// Severity vocabulary shared across the UI. Colours map onto the design
// system's reserved status tokens (never reused as categorical series colours);
// severity is always shown as icon + label, never colour alone.

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational']

export const SEVERITY_META = {
  critical: { label: 'Critical', statusKey: 'critical', token: '--status-critical', glyph: '▲' },
  high: { label: 'High', statusKey: 'serious', token: '--status-serious', glyph: '▲' },
  medium: { label: 'Medium', statusKey: 'warning', token: '--status-warning', glyph: '●' },
  low: { label: 'Low', statusKey: 'good', token: '--status-good', glyph: '●' },
  informational: { label: 'Info', statusKey: 'neutral', token: '--text-muted', glyph: '·' },
}

// Band lower bounds — kept in sync with ml-service config.SeverityBands and the
// Go API's risk distribution bands.
const BANDS = [
  { min: 80, severity: 'critical' },
  { min: 60, severity: 'high' },
  { min: 40, severity: 'medium' },
  { min: 20, severity: 'low' },
  { min: 0, severity: 'informational' },
]

export function severityForScore(score) {
  const n = Number(score) || 0
  return (BANDS.find((b) => n >= b.min) ?? BANDS[BANDS.length - 1]).severity
}

export function severityMeta(severity) {
  return SEVERITY_META[severity] ?? SEVERITY_META.informational
}

export function severityColor(severity) {
  return `var(${severityMeta(severity).token})`
}

export function formatCompactNumber(value) {
  const n = Number(value) || 0
  return new Intl.NumberFormat('en', {
    notation: n >= 10000 ? 'compact' : 'standard',
    maximumFractionDigits: 1,
  }).format(n)
}

export function formatTimestamp(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return String(iso)
  return d.toLocaleString()
}
