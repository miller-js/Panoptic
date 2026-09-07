import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import ChartCard from './ChartCard'
import { SEVERITY_ORDER, severityColor, severityMeta } from '../../severity'

export default function SeverityBreakdown({ bySeverity, loading, error, onSelect }) {
  const counts = bySeverity ?? {}
  const data = SEVERITY_ORDER.map((s) => ({ severity: s, label: severityMeta(s).label, value: counts[s] || 0 })).filter(
    (d) => d.value > 0,
  )
  const total = data.reduce((a, d) => a + d.value, 0)
  const isEmpty = total === 0

  return (
    <ChartCard
      title="Severity breakdown"
      subtitle={isEmpty ? undefined : `${total.toLocaleString()} alerts`}
      loading={loading}
      error={error}
      isEmpty={!loading && !error && isEmpty}
    >
      <div className="sev-breakdown">
        <ResponsiveContainer width="55%" height={200}>
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="label" innerRadius={45} outerRadius={78} paddingAngle={2}>
              {data.map((d) => (
                <Cell
                  key={d.severity}
                  fill={severityColor(d.severity)}
                  cursor={onSelect ? 'pointer' : 'default'}
                  onClick={() => onSelect && onSelect(d.severity)}
                />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ background: 'var(--surface-1)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
              formatter={(v, n) => [`${v} (${Math.round((v / total) * 100)}%)`, n]}
            />
          </PieChart>
        </ResponsiveContainer>
        <ul className="sev-legend">
          {data.map((d) => (
            <li key={d.severity}>
              <button type="button" onClick={() => onSelect && onSelect(d.severity)} disabled={!onSelect}>
                <span className="sev-dot" style={{ background: severityColor(d.severity) }} aria-hidden="true" />
                <span className="sev-legend-label">{d.label}</span>
                <span className="sev-legend-count">{d.value.toLocaleString()}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </ChartCard>
  )
}
