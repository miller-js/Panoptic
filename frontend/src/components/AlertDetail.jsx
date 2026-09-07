import { useEffect, useState } from 'react'
import SeverityBadge from './SeverityBadge'
import RiskScore from './RiskScore'
import { formatTimestamp } from '../severity'

function Row({ label, children }) {
  if (children === undefined || children === null || children === '') return null
  return (
    <div className="kv-row">
      <span className="kv-label">{label}</span>
      <span className="kv-value">{children}</span>
    </div>
  )
}

function Section({ title, children }) {
  return (
    <section className="detail-section">
      <h4>{title}</h4>
      {children}
    </section>
  )
}

export default function AlertDetail({ alert, onClose }) {
  const [showRaw, setShowRaw] = useState(false)

  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  if (!alert) return null
  const { event = {}, host = {}, user = {}, process = {}, network, detection = {}, risk = {}, explanation = {}, signals = {} } = alert
  const mitre = alert.mitre || []

  return (
    <>
      <div className="detail-scrim" onClick={onClose} aria-hidden="true" />
      <aside className="detail-panel" role="dialog" aria-label="Alert detail">
        <header className="detail-head">
          <div>
            <div className="detail-badges">
              <SeverityBadge severity={risk.severity} />
              <RiskScore score={risk.score} showBar={false} />
              <span className="detail-score-label">risk score</span>
            </div>
            <h2>{explanation.title || 'Alert'}</h2>
            <p className="detail-time">{formatTimestamp(event.timestamp || alert['@timestamp'])}</p>
          </div>
          <button type="button" className="detail-close" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>

        <div className="detail-body">
          {explanation.summary && (
            <Section title="Why this fired">
              <p className="detail-summary">{explanation.summary}</p>
              <ul className="factor-grid">
                {(explanation.factors || []).map((f) => (
                  <li key={f.label}>
                    <span className="factor-label">{f.label}</span>
                    <span className="factor-value">{f.value}</span>
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {(risk.factors || []).length > 0 && (
            <Section title="Risk factors">
              <div className="chip-row">
                {risk.factors.map((f) => (
                  <span key={f} className="factor-chip">
                    {f.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
              <div className="risk-components">
                <Row label="Impact">{fmt(risk.impact)}</Row>
                <Row label="Exploitability">{fmt(risk.exploitability)}</Row>
                <Row label="Technical severity">{fmt(risk.technical_severity)}</Row>
                <Row label="Context modifier">{fmt(risk.context_modifier)}×</Row>
              </div>
            </Section>
          )}

          {mitre.length > 0 && (
            <Section title="MITRE ATT&CK">
              <ul className="mitre-detail">
                {mitre.map((m) => (
                  <li key={m.technique_id}>
                    <a
                      href={`https://attack.mitre.org/techniques/${m.technique_id.replace('.', '/')}/`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {m.technique_id}
                    </a>
                    <span className="mitre-detail-name">{m.technique_name}</span>
                    <span className="mitre-detail-meta">
                      {m.tactic} · confidence {Math.round((m.confidence || 0) * 100)}%
                    </span>
                  </li>
                ))}
              </ul>
            </Section>
          )}

          <Section title="Event">
            <Row label="Type">{event.type}</Row>
            <Row label="Action">{event.action}</Row>
            <Row label="Outcome">{event.outcome}</Row>
            <Row label="Event ID">{event.id}</Row>
            <Row label="Module">{event.module}</Row>
          </Section>

          <Section title="Host & user">
            <Row label="Host">{host.name}</Row>
            <Row label="Host IP">{Array.isArray(host.ip) ? host.ip.join(', ') : host.ip}</Row>
            <Row label="Asset criticality">{host.criticality}</Row>
            <Row label="User">{user.name}{user.id !== undefined ? ` (uid ${user.id})` : ''}</Row>
            <Row label="Login identity">{user.audit_name}</Row>
            <Row label="Privileged">{user.is_root ? 'root' : 'no'}</Row>
            <Row label="Privilege transition">{user.privilege_transition ? 'yes' : 'no'}</Row>
          </Section>

          <Section title="Process">
            <Row label="Name">{process.name}</Row>
            <Row label="Executable">{process.executable}</Row>
            <Row label="Command line"><code>{process.command_line}</code></Row>
            <Row label="PID">{process.pid}</Row>
            <Row label="Parent PID">{process.parent_pid}</Row>
            <Row label="Working dir">{process.working_directory}</Row>
            <Row label="Audit key">{process.audit_key}</Row>
          </Section>

          {network && (
            <Section title="Network">
              <Row label="Direction">{network.direction}</Row>
              <Row label="Destination">{network.destination_ip}{network.destination_port ? `:${network.destination_port}` : ''}</Row>
              <Row label="Source IP">{network.source_ip}</Row>
            </Section>
          )}

          <Section title="Detection">
            <Row label="Model">{detection.model} v{detection.model_version}</Row>
            <Row label="Anomaly score">{fmt(detection.anomaly_score)}</Row>
            <Row label="Confidence">{detection.confidence != null ? fmt(detection.confidence) : '—'}</Row>
            <Row label="IsolationForest label">{detection.prediction === -1 ? '−1 (anomaly)' : '1 (normal)'}</Row>
            <Row label="Recent auth failures">{signals.recent_auth_failures}</Row>
            <Row label="Recent distinct ports">{signals.recent_distinct_ports}</Row>
          </Section>

          <Section title="Original event">
            <button type="button" className="link-btn" onClick={() => setShowRaw((v) => !v)}>
              {showRaw ? 'Hide' : 'Show'} raw document
            </button>
            {showRaw && <pre className="raw-json">{JSON.stringify(alert.log ?? {}, null, 2)}</pre>}
          </Section>
        </div>
      </aside>
    </>
  )
}

function fmt(v) {
  if (v === undefined || v === null) return '—'
  const n = Number(v)
  return Number.isFinite(n) ? n.toFixed(2) : String(v)
}
