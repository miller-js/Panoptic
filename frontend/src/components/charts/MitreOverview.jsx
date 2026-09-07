import ChartCard from './ChartCard'

// Top ATT&CK techniques as a ranked bar list. Clicking a row filters the alert
// table by that technique.
export default function MitreOverview({ techniques, loading, error, activeTechnique, onSelect }) {
  const rows = techniques ?? []
  const max = rows.reduce((m, r) => Math.max(m, r.count), 0) || 1
  const isEmpty = rows.length === 0

  return (
    <ChartCard
      title="MITRE ATT&CK coverage"
      subtitle="Techniques mapped to detected alerts (rule-based)"
      loading={loading}
      error={error}
      isEmpty={!loading && !error && isEmpty}
    >
      <ul className="mitre-list">
        {rows.map((r) => (
          <li key={r.technique_id}>
            <button
              type="button"
              className={activeTechnique === r.technique_id ? 'mitre-row active' : 'mitre-row'}
              onClick={() => onSelect && onSelect(activeTechnique === r.technique_id ? '' : r.technique_id)}
            >
              <span className="mitre-id">{r.technique_id}</span>
              <span className="mitre-name" title={r.technique_name}>
                {r.technique_name}
                {r.tactic ? <span className="mitre-tactic"> · {r.tactic}</span> : null}
              </span>
              <span className="mitre-bar-wrap">
                <span className="mitre-bar" style={{ width: `${(r.count / max) * 100}%` }} />
              </span>
              <span className="mitre-count">{r.count}</span>
            </button>
          </li>
        ))}
      </ul>
    </ChartCard>
  )
}
