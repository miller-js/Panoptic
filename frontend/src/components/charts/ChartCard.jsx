// Common frame for a dashboard chart: title, and consistent loading / error /
// empty states so a failed panel never blanks the whole dashboard.
export default function ChartCard({ title, subtitle, loading, error, isEmpty, children, actions }) {
  return (
    <section className="chart-card">
      <header className="chart-card-head">
        <div>
          <h3>{title}</h3>
          {subtitle && <p className="chart-card-sub">{subtitle}</p>}
        </div>
        {actions}
      </header>
      <div className="chart-card-body">
        {loading && <div className="chart-state">Loading…</div>}
        {!loading && error && <div className="chart-state chart-error">{error}</div>}
        {!loading && !error && isEmpty && <div className="chart-state">No data yet.</div>}
        {!loading && !error && !isEmpty && children}
      </div>
    </section>
  )
}
