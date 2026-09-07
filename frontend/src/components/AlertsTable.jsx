import SeverityBadge from './SeverityBadge'
import RiskScore from './RiskScore'
import { formatTimestamp } from '../severity'

function SortHeader({ label, sortKey, sort, onSort }) {
  const active = sort.sortBy === sortKey
  const arrow = active ? (sort.order === 'asc' ? ' ▲' : ' ▼') : ''
  return (
    <th className="sortable" onClick={() => onSort(sortKey)} aria-sort={active ? (sort.order === 'asc' ? 'ascending' : 'descending') : 'none'}>
      {label}
      {arrow}
    </th>
  )
}

export default function AlertsTable({ alerts, sort, onSort, selectedId, onSelect }) {
  if (alerts.length === 0) {
    return (
      <div className="alerts-wrap">
        <div className="state-message">No alerts match the current filters.</div>
      </div>
    )
  }

  return (
    <div className="alerts-wrap">
      <table className="alerts-table">
        <thead>
          <tr>
            <SortHeader label="Time" sortKey="event_time" sort={sort} onSort={onSort} />
            <th>Severity</th>
            <SortHeader label="Risk" sortKey="risk_score" sort={sort} onSort={onSort} />
            <th>Alert</th>
            <th>Host</th>
            <th>User</th>
            <th>Process</th>
            <th>ATT&CK</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => {
            const proc = a.process || {}
            return (
              <tr
                key={a.id}
                className={a.id === selectedId ? 'selected' : undefined}
                onClick={() => onSelect(a)}
                tabIndex={0}
                onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), onSelect(a))}
              >
                <td className="ts">{formatTimestamp(a.event?.timestamp || a['@timestamp'])}</td>
                <td>
                  <SeverityBadge severity={a.risk?.severity} size="sm" />
                </td>
                <td>
                  <RiskScore score={a.risk?.score} />
                </td>
                <td className="alert-title">{a.explanation?.title || `${a.event?.type || 'Event'} anomaly`}</td>
                <td>{a.host?.name || '—'}</td>
                <td>{a.user?.audit_name || a.user?.name || '—'}</td>
                <td className="proc" title={proc.command_line || proc.executable || ''}>
                  {proc.name || proc.executable || '—'}
                </td>
                <td className="mitre-cells">
                  {(a.mitre || []).slice(0, 3).map((m) => (
                    <span key={m.technique_id} className="mitre-chip" title={m.technique_name}>
                      {m.technique_id}
                    </span>
                  ))}
                  {(a.mitre || []).length > 3 && <span className="mitre-more">+{a.mitre.length - 3}</span>}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
