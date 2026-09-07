import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  fetchAlert,
  fetchAlerts,
  fetchAlertStats,
  fetchMitreTechniques,
  fetchRiskDistribution,
  fetchTimeline,
} from './api'
import StatCards from './components/StatCards'
import FilterBar, { EMPTY_FILTERS } from './components/FilterBar'
import AlertsTable from './components/AlertsTable'
import AlertDetail from './components/AlertDetail'
import AnomalyTrendChart from './components/charts/AnomalyTrendChart'
import RiskDistributionChart from './components/charts/RiskDistributionChart'
import SeverityBreakdown from './components/charts/SeverityBreakdown'
import MitreOverview from './components/charts/MitreOverview'
import './App.css'

const PAGE_SIZE = 25

function rangeToFromTime(range) {
  if (range === 'all') return ''
  const now = Date.now()
  const ms = { '24h': 864e5, '7d': 7 * 864e5, '30d': 30 * 864e5 }[range] ?? 30 * 864e5
  return new Date(now - ms).toISOString()
}

function filtersToParams(filters, page) {
  return {
    size: PAGE_SIZE,
    from: page * PAGE_SIZE,
    severity: filters.severities,
    min_risk_score: filters.minRiskScore,
    max_risk_score: filters.maxRiskScore,
    host: filters.host,
    user: filters.user,
    event_type: filters.eventType,
    technique: filters.technique,
    anomaly: filters.anomaly || undefined,
    q: filters.q,
    from_time: rangeToFromTime(filters.range),
  }
}

export default function App() {
  const [filters, setFilters] = useState(EMPTY_FILTERS)
  const [sort, setSort] = useState({ sortBy: 'risk_score', order: 'desc' })
  const [page, setPage] = useState(0)

  const [result, setResult] = useState({ total: 0, items: [] })
  const [tableLoading, setTableLoading] = useState(true)
  const [tableError, setTableError] = useState(null)

  const [overview, setOverview] = useState({ stats: null, distribution: null, mitre: null })
  const [overviewLoading, setOverviewLoading] = useState(true)
  const [overviewError, setOverviewError] = useState(null)

  const [trendRange, setTrendRange] = useState('all')
  const [timeline, setTimeline] = useState(null)
  const [timelineState, setTimelineState] = useState({ loading: true, error: null })

  const [selected, setSelected] = useState(null)

  const params = useMemo(() => filtersToParams(filters, page), [filters, page])

  const loadTable = useCallback(async () => {
    setTableLoading(true)
    setTableError(null)
    try {
      const data = await fetchAlerts({ ...params, sort_by: sort.sortBy, order: sort.order })
      setResult(data)
    } catch (err) {
      setTableError(err.message)
      setResult({ total: 0, items: [] })
    } finally {
      setTableLoading(false)
    }
  }, [params, sort])

  const loadOverview = useCallback(async () => {
    setOverviewLoading(true)
    setOverviewError(null)
    try {
      const [stats, distribution, mitre] = await Promise.all([
        fetchAlertStats(),
        fetchRiskDistribution(),
        fetchMitreTechniques({ size: 12 }),
      ])
      setOverview({ stats, distribution, mitre: mitre.techniques || [] })
    } catch (err) {
      setOverviewError(err.message)
    } finally {
      setOverviewLoading(false)
    }
  }, [])

  const loadTimeline = useCallback(async () => {
    setTimelineState({ loading: true, error: null })
    try {
      const interval = trendRange === '24h' ? '1h' : trendRange === '7d' ? '3h' : '1d'
      const data = await fetchTimeline({ interval, from_time: rangeToFromTime(trendRange) })
      setTimeline(data)
      setTimelineState({ loading: false, error: null })
    } catch (err) {
      setTimelineState({ loading: false, error: err.message })
    }
  }, [trendRange])

  useEffect(() => {
    loadTable()
  }, [loadTable])
  useEffect(() => {
    loadOverview()
  }, [loadOverview])
  useEffect(() => {
    loadTimeline()
  }, [loadTimeline])

  const updateFilters = (next) => {
    setFilters(next)
    setPage(0)
  }
  const resetFilters = () => {
    setFilters(EMPTY_FILTERS)
    setPage(0)
  }
  const handleSort = (key) => {
    setSort((p) => (p.sortBy === key ? { sortBy: key, order: p.order === 'asc' ? 'desc' : 'asc' } : { sortBy: key, order: 'desc' }))
    setPage(0)
  }

  const openAlert = async (alert) => {
    setSelected(alert)
    try {
      const full = await fetchAlert(alert.id)
      setSelected(full)
    } catch {
      /* keep the summary row we already have */
    }
  }

  const refreshAll = () => {
    loadTable()
    loadOverview()
    loadTimeline()
  }

  const totalPages = Math.max(1, Math.ceil(result.total / PAGE_SIZE))
  const rangeStart = result.total === 0 ? 0 : page * PAGE_SIZE + 1
  const rangeEnd = Math.min(result.total, (page + 1) * PAGE_SIZE)

  return (
    <div className="app">
      <header className="app-header">
        <div>
          <h1>Panoptic</h1>
          <p>Security analytics · Linux auditd anomaly detection</p>
        </div>
      </header>

      {(tableError || overviewError) && (
        <div className="error-banner">{tableError || overviewError}</div>
      )}

      <StatCards stats={overview.stats} />

      <div className="chart-grid">
        <AnomalyTrendChart
          timeline={timeline}
          loading={timelineState.loading}
          error={timelineState.error}
          range={trendRange}
          onRangeChange={setTrendRange}
        />
        <RiskDistributionChart
          distribution={overview.distribution}
          loading={overviewLoading}
          error={overviewError}
          onSelectBand={(sev) => updateFilters({ ...filters, severities: [sev] })}
        />
        <SeverityBreakdown
          bySeverity={overview.stats?.by_severity}
          loading={overviewLoading}
          error={overviewError}
          onSelect={(sev) => updateFilters({ ...filters, severities: [sev] })}
        />
        <MitreOverview
          techniques={overview.mitre}
          loading={overviewLoading}
          error={overviewError}
          activeTechnique={filters.technique}
          onSelect={(tid) => updateFilters({ ...filters, technique: tid })}
        />
      </div>

      <div className="alert-center">
        <div className="alert-center-head">
          <h2>Alert center</h2>
          <span className="alert-count">{result.total.toLocaleString()} matching</span>
        </div>

        <FilterBar
          filters={filters}
          onChange={updateFilters}
          onReset={resetFilters}
          onRefresh={refreshAll}
          loading={tableLoading}
        />

        {tableLoading && result.items.length === 0 ? (
          <div className="alerts-wrap">
            <div className="state-message">Loading alerts…</div>
          </div>
        ) : (
          <>
            <AlertsTable
              alerts={result.items}
              sort={sort}
              onSort={handleSort}
              selectedId={selected?.id}
              onSelect={openAlert}
            />
            <div className="pagination">
              <span>
                {rangeStart}–{rangeEnd} of {result.total.toLocaleString()}
              </span>
              <button type="button" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                Previous
              </button>
              <span>
                Page {page + 1} of {totalPages}
              </span>
              <button type="button" disabled={page + 1 >= totalPages} onClick={() => setPage((p) => p + 1)}>
                Next
              </button>
            </div>
          </>
        )}
      </div>

      {selected && <AlertDetail alert={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
