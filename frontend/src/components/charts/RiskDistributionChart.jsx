import { Bar, BarChart, CartesianGrid, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import ChartCard from './ChartCard'
import { severityColor } from '../../severity'

export default function RiskDistributionChart({ distribution, loading, error, onSelectBand }) {
  const bands = distribution?.bands ?? []
  const data = bands.map((b) => ({
    label: b.key.replace(/^\d+-\d+\s/, ''),
    range: `${b.from}-${b.to}`,
    severity: b.severity,
    count: b.count,
  }))
  const isEmpty = data.every((d) => d.count === 0)

  return (
    <ChartCard
      title="Risk score distribution"
      subtitle="Alert count by 0–100 risk band"
      loading={loading}
      error={error}
      isEmpty={!loading && !error && isEmpty}
    >
      <ResponsiveContainer width="100%" height={240}>
        <BarChart data={data} margin={{ top: 16, right: 12, bottom: 4, left: -8 }}>
          <CartesianGrid stroke="var(--gridline)" vertical={false} />
          <XAxis dataKey="range" stroke="var(--text-muted)" fontSize={11} />
          <YAxis stroke="var(--text-muted)" fontSize={11} allowDecimals={false} />
          <Tooltip
            cursor={{ fill: 'var(--gridline)', opacity: 0.4 }}
            contentStyle={{ background: 'var(--surface-1)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
            formatter={(v) => [v, 'alerts']}
            labelFormatter={(l, p) => `${p?.[0]?.payload?.label ?? ''} (${l})`}
          />
          <Bar
            dataKey="count"
            radius={[3, 3, 0, 0]}
            cursor={onSelectBand ? 'pointer' : 'default'}
            onClick={(d) => onSelectBand && onSelectBand(d.severity)}
          >
            {data.map((d) => (
              <Cell key={d.severity} fill={severityColor(d.severity)} />
            ))}
            <LabelList dataKey="count" position="top" fontSize={11} fill="var(--text-secondary)" />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
