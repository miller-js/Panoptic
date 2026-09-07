import { SEVERITY_ORDER, severityMeta } from '../severity'

export const EMPTY_FILTERS = {
  severities: [],
  minRiskScore: '',
  maxRiskScore: '',
  host: '',
  user: '',
  eventType: '',
  technique: '',
  anomaly: false,
  range: 'all',
  q: '',
}

const RANGES = [
  { value: '24h', label: 'Last 24h' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: 'all', label: 'All time' },
]

export default function FilterBar({ filters, onChange, onReset, onRefresh, loading }) {
  const set = (key) => (e) => {
    const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value
    onChange({ ...filters, [key]: value })
  }

  const toggleSeverity = (sev) => {
    const next = filters.severities.includes(sev)
      ? filters.severities.filter((s) => s !== sev)
      : [...filters.severities, sev]
    onChange({ ...filters, severities: next })
  }

  const activeCount =
    filters.severities.length +
    [filters.minRiskScore, filters.maxRiskScore, filters.host, filters.user, filters.eventType, filters.technique, filters.q].filter(
      Boolean,
    ).length +
    (filters.anomaly ? 1 : 0)

  return (
    <div className="filter-bar">
      <div className="filter-row">
        <div className="sev-chips" role="group" aria-label="Filter by severity">
          {SEVERITY_ORDER.map((sev) => {
            const on = filters.severities.includes(sev)
            return (
              <button
                key={sev}
                type="button"
                className={`sev-chip sev-${severityMeta(sev).statusKey}${on ? ' on' : ''}`}
                aria-pressed={on}
                onClick={() => toggleSeverity(sev)}
              >
                <span aria-hidden="true">{severityMeta(sev).glyph}</span> {severityMeta(sev).label}
              </button>
            )
          })}
        </div>

        <label className="chk">
          <input type="checkbox" checked={filters.anomaly} onChange={set('anomaly')} />
          Anomalies only
        </label>

        <select value={filters.range} onChange={set('range')} aria-label="Time range">
          {RANGES.map((r) => (
            <option key={r.value} value={r.value}>
              {r.label}
            </option>
          ))}
        </select>
      </div>

      <div className="filter-row">
        <label>
          Risk ≥
          <input type="number" min="0" max="100" value={filters.minRiskScore} onChange={set('minRiskScore')} placeholder="0" />
        </label>
        <label>
          Risk ≤
          <input type="number" min="0" max="100" value={filters.maxRiskScore} onChange={set('maxRiskScore')} placeholder="100" />
        </label>
        <label>
          Host
          <input type="text" value={filters.host} onChange={set('host')} placeholder="hostname" />
        </label>
        <label>
          User
          <input type="text" value={filters.user} onChange={set('user')} placeholder="user / audit name" />
        </label>
        <label>
          Event type
          <input type="text" value={filters.eventType} onChange={set('eventType')} placeholder="SYSCALL" />
        </label>
        <label>
          Technique
          <input type="text" value={filters.technique} onChange={set('technique')} placeholder="T1059.004" />
        </label>
        <label className="grow">
          Search
          <input
            type="text"
            name="search"
            value={filters.q}
            onChange={set('q')}
            placeholder="explanation, command line, raw event…"
          />
        </label>

        <div className="filter-actions">
          {activeCount > 0 && (
            <button type="button" className="link-btn" onClick={onReset}>
              Clear ({activeCount})
            </button>
          )}
          <button type="button" onClick={onRefresh} disabled={loading}>
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>
    </div>
  )
}
