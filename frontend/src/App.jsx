import { useEffect, useState, useCallback } from 'react'
import { fetchLogs, fetchStats } from './api'
import StatsBar from './components/StatsBar'
import FilterBar from './components/FilterBar'
import LogsTable from './components/LogsTable'
import './App.css'

const PAGE_SIZE = 20

const DEFAULT_FILTERS = {
  anomaly: false,
  minRiskScore: '',
  auditType: '',
  query: '',
}

function App() {
  const [stats, setStats] = useState(null)
  const [result, setResult] = useState({ total: 0, items: [] })
  const [filters, setFilters] = useState(DEFAULT_FILTERS)
  const [sort, setSort] = useState({ sortBy: 'timestamp', order: 'desc' })
  const [page, setPage] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [logsResult, statsResult] = await Promise.all([
        fetchLogs({
          size: PAGE_SIZE,
          from: page * PAGE_SIZE,
          sort_by: sort.sortBy,
          order: sort.order,
          anomaly: filters.anomaly || undefined,
          min_risk_score: filters.minRiskScore,
          audit_type: filters.auditType,
          q: filters.query,
        }),
        fetchStats(),
      ])
      setResult(logsResult)
      setStats(statsResult)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [page, sort, filters])

  useEffect(() => {
    load()
  }, [load])

  const handleFiltersChange = (next) => {
    setFilters(next)
    setPage(0)
  }

  const handleSort = (sortKey) => {
    setSort((prev) =>
      prev.sortBy === sortKey
        ? { sortBy: sortKey, order: prev.order === 'asc' ? 'desc' : 'asc' }
        : { sortBy: sortKey, order: 'desc' },
    )
    setPage(0)
  }

  const totalPages = Math.max(1, Math.ceil(result.total / PAGE_SIZE))
  const rangeStart = result.total === 0 ? 0 : page * PAGE_SIZE + 1
  const rangeEnd = Math.min(result.total, (page + 1) * PAGE_SIZE)

  return (
    <div className="app">
      <header className="app-header">
        <h1>Panoptic</h1>
        <p>ML-enhanced audit log anomaly dashboard</p>
      </header>

      {error && <div className="error-banner">{error}</div>}

      <StatsBar stats={stats} />

      <FilterBar
        filters={filters}
        onChange={handleFiltersChange}
        onRefresh={load}
        loading={loading}
      />

      {loading && result.items.length === 0 ? (
        <div className="logs-table-wrap">
          <div className="state-message">Loading logs…</div>
        </div>
      ) : (
        <>
          <LogsTable items={result.items} sort={sort} onSort={handleSort} />

          <div className="pagination">
            <span>
              {rangeStart}-{rangeEnd} of {result.total.toLocaleString()}
            </span>
            <button type="button" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
              Previous
            </button>
            <span>
              Page {page + 1} of {totalPages}
            </span>
            <button
              type="button"
              disabled={page + 1 >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        </>
      )}
    </div>
  )
}

export default App
