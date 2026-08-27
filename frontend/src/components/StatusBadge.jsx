import { riskStatus } from '../riskStatus'

// Status is never carried by color alone — always icon (dot) + label.
export default function StatusBadge({ prediction, riskScore }) {
  const isAnomaly = prediction === -1
  const status = isAnomaly ? { key: 'critical', label: 'Anomaly' } : riskStatus(riskScore)

  return (
    <span className={`status-badge status-${status.key}`}>
      <span className="dot" aria-hidden="true" />
      {isAnomaly ? 'Anomaly' : 'Normal'}
    </span>
  )
}
