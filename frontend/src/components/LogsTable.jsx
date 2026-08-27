import { useState, Fragment } from 'react'
import StatusBadge from './StatusBadge'
import { riskStatus } from '../riskStatus'

function SortHeader({ label, sortKey, sort, onSort }) {
  const active = sort.sortBy === sortKey
  const arrow = active ? (sort.order === 'asc' ? ' ▲' : ' ▼') : ''
  return (
    <th className="sortable" onClick={() => onSort(sortKey)}>
      {label}
      {arrow}
    </th>
  )
}

function formatTimestamp(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString()
}

function RiskScoreCell({ score }) {
  const status = riskStatus(score)
  const pct = Math.max(0, Math.min(100, score))
  return (
    <div className="risk-score-cell">
      <span>{Math.round(score)}</span>
      <div className="bar-track">
        <div
          className="bar-fill"
          style={{ width: `${pct}%`, background: `var(--status-${status.key})` }}
        />
      </div>
    </div>
  )
}

export default function LogsTable({ items, sort, onSort }) {
  const [expandedId, setExpandedId] = useState(null)

  if (items.length === 0) {
    return (
      <div className="logs-table-wrap">
        <div className="state-message">No logs match the current filters.</div>
      </div>
    )
  }

  return (
    <div className="logs-table-wrap">
      <table className="logs-table">
        <thead>
          <tr>
            <SortHeader label="Time" sortKey="timestamp" sort={sort} onSort={onSort} />
            <th>Host</th>
            <th>Audit type</th>
            <th>Message</th>
            <SortHeader label="Risk score" sortKey="risk_score" sort={sort} onSort={onSort} />
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <Fragment key={item.id}>
              <tr onClick={() => setExpandedId(expandedId === item.id ? null : item.id)}>
                <td className="timestamp">{formatTimestamp(item.log_timestamp || item.timestamp)}</td>
                <td>{item.hostname || '—'}</td>
                <td>{item.audit_type || '—'}</td>
                <td className="message-cell" title={item.message}>
                  {item.message || '—'}
                </td>
                <td>
                  <RiskScoreCell score={item.risk_score} />
                </td>
                <td>
                  <StatusBadge prediction={item.prediction} riskScore={item.risk_score} />
                </td>
              </tr>
              {expandedId === item.id && (
                <tr className="log-detail-row">
                  <td colSpan={6}>
                    <div className="log-detail">
                      <pre>{JSON.stringify(item.log, null, 2)}</pre>
                    </div>
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}
