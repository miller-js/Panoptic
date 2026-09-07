import { severityForScore, severityColor } from '../severity'

// Numeric risk score + a proportional bar, coloured by severity band.
export default function RiskScore({ score, showBar = true }) {
  const n = Math.round(Number(score) || 0)
  const color = severityColor(severityForScore(n))
  return (
    <div className="risk-score">
      <span className="risk-score-num" style={{ color }}>
        {n}
      </span>
      {showBar && (
        <div className="risk-bar-track" aria-hidden="true">
          <div className="risk-bar-fill" style={{ width: `${Math.max(0, Math.min(100, n))}%`, background: color }} />
        </div>
      )}
    </div>
  )
}
