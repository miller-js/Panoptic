// Buckets a 0-100 risk_score into the same good/warning/serious/critical
// status vocabulary the design system reserves for state (never reused as a
// categorical series color).
const THRESHOLDS = [
  { max: 39, key: 'good', label: 'Normal' },
  { max: 59, key: 'warning', label: 'Elevated' },
  { max: 79, key: 'serious', label: 'High' },
  { max: Infinity, key: 'critical', label: 'Critical' },
]

export function riskStatus(score) {
  const bucket = THRESHOLDS.find((t) => score <= t.max) ?? THRESHOLDS[THRESHOLDS.length - 1]
  return bucket
}

export function formatCompactNumber(value) {
  return new Intl.NumberFormat('en', {
    notation: value >= 10000 ? 'compact' : 'standard',
    maximumFractionDigits: 1,
  }).format(value)
}
