import { riskStatus, formatCompactNumber } from '../riskStatus'

function StatTile({ label, value, statusKey }) {
  return (
    <div className="stat-tile">
      <div className="label">{label}</div>
      <div className={`value${statusKey ? ` status-${statusKey}` : ''}`}>{value}</div>
    </div>
  )
}

export default function StatsBar({ stats }) {
  if (!stats) return null

  const anomalyStatus = stats.anomaly_count > 0 ? 'critical' : 'good'
  const avgStatus = riskStatus(stats.avg_risk_score).key
  const maxStatus = riskStatus(stats.max_risk_score).key

  return (
    <div className="stats-bar">
      <StatTile label="Total logs scored" value={formatCompactNumber(stats.total)} />
      <StatTile
        label="Anomalies flagged"
        value={formatCompactNumber(stats.anomaly_count)}
        statusKey={anomalyStatus}
      />
      <StatTile
        label="Avg risk score"
        value={stats.avg_risk_score.toFixed(1)}
        statusKey={avgStatus}
      />
      <StatTile
        label="Max risk score"
        value={stats.max_risk_score.toFixed(0)}
        statusKey={maxStatus}
      />
    </div>
  )
}
