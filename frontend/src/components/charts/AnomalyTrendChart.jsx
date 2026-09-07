import {
  Area,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import ChartCard from './ChartCard'

function fmtTick(iso) {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

export default function AnomalyTrendChart({ timeline, loading, error, range, onRangeChange }) {
  const buckets = timeline?.buckets ?? []
  const data = buckets.map((b) => ({
    t: b.timestamp,
    total: b.total,
    anomalies: b.anomalies,
    high: b.high_or_critical,
  }))
  const isEmpty = data.every((d) => d.total === 0)

  return (
    <ChartCard
      title="Event & anomaly trend"
      subtitle="Scored events over time, with model anomalies and high/critical alerts"
      loading={loading}
      error={error}
      isEmpty={!loading && !error && isEmpty}
      actions={
        <select
          className="chart-range"
          value={range}
          onChange={(e) => onRangeChange(e.target.value)}
          aria-label="Time range"
        >
          <option value="all">All time</option>
          <option value="30d">Last 30 days</option>
          <option value="7d">Last 7 days</option>
        </select>
      }
    >
      <ResponsiveContainer width="100%" height={260}>
        <ComposedChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: -8 }}>
          <CartesianGrid stroke="var(--gridline)" vertical={false} />
          <XAxis dataKey="t" tickFormatter={fmtTick} stroke="var(--text-muted)" fontSize={11} minTickGap={24} />
          <YAxis stroke="var(--text-muted)" fontSize={11} allowDecimals={false} />
          <Tooltip
            contentStyle={{
              background: 'var(--surface-1)',
              border: '1px solid var(--border)',
              borderRadius: 8,
              fontSize: 12,
            }}
            labelFormatter={(v) => new Date(v).toLocaleString()}
          />
          <Legend wrapperStyle={{ fontSize: 12 }} />
          <Area
            type="monotone"
            dataKey="total"
            name="Events scored"
            stroke="var(--sequential-400)"
            fill="var(--sequential-400)"
            fillOpacity={0.12}
            strokeWidth={1}
          />
          <Line type="monotone" dataKey="anomalies" name="Model anomalies" stroke="var(--status-warning)" strokeWidth={2} dot={false} />
          <Line type="monotone" dataKey="high" name="High / critical" stroke="var(--status-critical)" strokeWidth={2} dot={false} />
        </ComposedChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
