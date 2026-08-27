export default function FilterBar({ filters, onChange, onRefresh, loading }) {
  const set = (key) => (e) => {
    const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value
    onChange({ ...filters, [key]: value })
  }

  return (
    <div className="filter-bar">
      <label>
        <input type="checkbox" checked={filters.anomaly} onChange={set('anomaly')} />
        Anomalies only
      </label>

      <label>
        Min risk score
        <input
          type="number"
          min="0"
          max="100"
          placeholder="0"
          value={filters.minRiskScore}
          onChange={set('minRiskScore')}
          style={{ width: 60 }}
        />
      </label>

      <label>
        Audit type
        <input
          type="text"
          placeholder="e.g. SYSCALL"
          value={filters.auditType}
          onChange={set('auditType')}
        />
      </label>

      <label>
        Search
        <input
          type="text"
          name="search"
          placeholder="search raw audit line"
          value={filters.query}
          onChange={set('query')}
        />
      </label>

      <div className="spacer" />

      <button type="button" onClick={onRefresh} disabled={loading}>
        {loading ? 'Refreshing…' : 'Refresh'}
      </button>
    </div>
  )
}
