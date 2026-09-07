import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('../api', () => ({
  fetchAlerts: vi.fn(),
  fetchAlert: vi.fn(),
  fetchAlertStats: vi.fn(),
  fetchTimeline: vi.fn(),
  fetchRiskDistribution: vi.fn(),
  fetchMitreTechniques: vi.fn(),
  BASE_URL: 'http://test',
}))

import * as api from '../api'
import App from '../App'

const stats = {
  total: 1200,
  anomaly_count: 40,
  avg_risk_score: 34.2,
  max_risk_score: 88,
  last_24h: 12,
  by_severity: { low: 900, medium: 200, high: 90, critical: 10 },
}

const oneAlert = {
  id: 'a1',
  '@timestamp': '2026-07-14T23:27:40Z',
  event: { type: 'SYSCALL', timestamp: '2026-07-14T23:27:29Z' },
  host: { name: 'web1' },
  user: { audit_name: 'alice' },
  process: { name: 'sudo', command_line: 'sudo su -' },
  detection: { prediction: -1, anomaly_score: 0.9 },
  risk: { score: 78, severity: 'high', factors: [] },
  mitre: [{ technique_id: 'T1548.003', technique_name: 'Sudo', tactic: 'Priv Esc', confidence: 0.8 }],
  explanation: { title: 'Privilege escalation', summary: 'sudo by root', factors: [] },
}

beforeEach(() => {
  vi.clearAllMocks()
  api.fetchAlertStats.mockResolvedValue(stats)
  api.fetchRiskDistribution.mockResolvedValue({
    total: 1200,
    bands: [
      { key: '0-19 informational', severity: 'informational', from: 0, to: 19, count: 0 },
      { key: '20-39 low', severity: 'low', from: 20, to: 39, count: 900 },
      { key: '40-59 medium', severity: 'medium', from: 40, to: 59, count: 200 },
      { key: '60-79 high', severity: 'high', from: 60, to: 79, count: 90 },
      { key: '80-100 critical', severity: 'critical', from: 80, to: 100, count: 10 },
    ],
  })
  api.fetchMitreTechniques.mockResolvedValue({
    techniques: [{ technique_id: 'T1110', technique_name: 'Brute Force', tactic: 'Credential Access', count: 9 }],
  })
  api.fetchTimeline.mockResolvedValue({
    interval: '1d',
    buckets: [{ timestamp: '2026-07-14T00:00:00Z', total: 100, anomalies: 5, high_or_critical: 2 }],
  })
  api.fetchAlerts.mockResolvedValue({ total: 1, items: [oneAlert] })
  api.fetchAlert.mockResolvedValue(oneAlert)
})

describe('App', () => {
  it('renders stats, charts and the alert table from API data', async () => {
    render(<App />)
    expect(await screen.findByText('Privilege escalation')).toBeInTheDocument()
    expect(screen.getByText('1,200')).toBeInTheDocument() // total alerts stat
    expect(screen.getByText('MITRE ATT&CK coverage')).toBeInTheDocument()
    expect(screen.getByText('T1110')).toBeInTheDocument()
  })

  it('shows an error banner when the alert query fails', async () => {
    api.fetchAlerts.mockRejectedValue(new Error('elasticsearch is down'))
    render(<App />)
    expect(await screen.findByText('elasticsearch is down')).toBeInTheDocument()
  })

  it('applies a severity filter when a severity chip is clicked', async () => {
    render(<App />)
    await screen.findByText('Privilege escalation')

    const sevGroup = screen.getByRole('group', { name: /filter by severity/i })
    await userEvent.click(within(sevGroup).getByRole('button', { name: /critical/i }))

    await waitFor(() => {
      const lastCall = api.fetchAlerts.mock.calls.at(-1)[0]
      expect(lastCall.severity).toEqual(['critical'])
    })
  })

  it('opens the detail panel on row click and fetches the full alert', async () => {
    render(<App />)
    await userEvent.click(await screen.findByText('Privilege escalation'))
    expect(api.fetchAlert).toHaveBeenCalledWith('a1')
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('sudo by root')).toBeInTheDocument()
  })

  it('filters by technique when a MITRE row is clicked', async () => {
    render(<App />)
    await screen.findByText('Privilege escalation')
    await userEvent.click(screen.getByRole('button', { name: /T1110/ }))
    await waitFor(() => {
      const lastCall = api.fetchAlerts.mock.calls.at(-1)[0]
      expect(lastCall.technique).toBe('T1110')
    })
  })
})
