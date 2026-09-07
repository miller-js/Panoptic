import { formatCompactNumber, severityForScore, severityMeta } from '../severity'

function Card({ label, value, statusKey, hint }) {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className={`stat-value${statusKey ? ` status-${statusKey}` : ''}`}>{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  )
}

export default function StatCards({ stats }) {
  if (!stats) {
    return (
      <div className="stat-cards">
        {['Total alerts', 'Critical', 'High', 'Anomalies', 'Avg risk'].map((l) => (
          <Card key={l} label={l} value="—" />
        ))}
      </div>
    )
  }
  const sev = stats.by_severity || {}
  const avgStatus = severityMeta(severityForScore(stats.avg_risk_score)).statusKey
  return (
    <div className="stat-cards">
      <Card label="Total alerts" value={formatCompactNumber(stats.total)} hint={`${formatCompactNumber(stats.last_24h || 0)} in last 24h`} />
      <Card label="Critical" value={formatCompactNumber(sev.critical || 0)} statusKey={(sev.critical || 0) > 0 ? 'critical' : undefined} />
      <Card label="High" value={formatCompactNumber(sev.high || 0)} statusKey={(sev.high || 0) > 0 ? 'serious' : undefined} />
      <Card label="Model anomalies" value={formatCompactNumber(stats.anomaly_count)} hint="IsolationForest label −1" />
      <Card label="Avg risk score" value={(stats.avg_risk_score ?? 0).toFixed(1)} statusKey={avgStatus} hint={`max ${Math.round(stats.max_risk_score ?? 0)}`} />
    </div>
  )
}
