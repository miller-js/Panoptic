import { describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import AlertsTable from '../components/AlertsTable'
import AlertDetail from '../components/AlertDetail'
import FilterBar, { EMPTY_FILTERS } from '../components/FilterBar'
import RiskDistributionChart from '../components/charts/RiskDistributionChart'
import MitreOverview from '../components/charts/MitreOverview'

const alert = {
  id: 'a1',
  '@timestamp': '2026-07-14T23:27:40Z',
  event: { type: 'SYSCALL', action: 'execve', timestamp: '2026-07-14T23:27:29Z' },
  host: { name: 'web1', ip: ['10.0.0.5'], criticality: 0.7 },
  user: { name: 'root', id: 0, audit_name: 'alice', is_root: true, privilege_transition: true },
  process: { name: 'sudo', executable: '/usr/bin/sudo', command_line: 'sudo su -' },
  detection: { model: 'isolation_forest', model_version: '2.0', anomaly_score: 0.94, confidence: 0.9, prediction: -1 },
  risk: { score: 78, severity: 'high', factors: ['privilege_transition', 'rare_behaviour'], impact: 0.6, exploitability: 0.5 },
  mitre: [{ technique_id: 'T1548.003', technique_name: 'Sudo', tactic: 'Privilege Escalation', confidence: 0.8 }],
  explanation: { title: 'Privilege escalation', summary: 'sudo run by root', factors: [{ label: 'Privilege context', value: 'Root' }] },
  signals: { recent_auth_failures: 0 },
  log: { event: { original: 'type=SYSCALL ...' } },
}

describe('AlertsTable', () => {
  it('renders a row and reacts to selection', async () => {
    const onSelect = vi.fn()
    render(<AlertsTable alerts={[alert]} sort={{ sortBy: 'risk_score', order: 'desc' }} onSort={() => {}} onSelect={onSelect} />)
    expect(screen.getByText('Privilege escalation')).toBeInTheDocument()
    expect(screen.getByText('T1548.003')).toBeInTheDocument()
    expect(screen.getByText('High')).toBeInTheDocument()
    await userEvent.click(screen.getByText('Privilege escalation'))
    expect(onSelect).toHaveBeenCalledWith(alert)
  })

  it('shows an empty state', () => {
    render(<AlertsTable alerts={[]} sort={{ sortBy: 'risk_score', order: 'desc' }} onSort={() => {}} onSelect={() => {}} />)
    expect(screen.getByText(/no alerts match/i)).toBeInTheDocument()
  })

  it('fires onSort when a sortable header is clicked', async () => {
    const onSort = vi.fn()
    render(<AlertsTable alerts={[alert]} sort={{ sortBy: 'risk_score', order: 'desc' }} onSort={onSort} onSelect={() => {}} />)
    await userEvent.click(screen.getByRole('columnheader', { name: /risk/i }))
    expect(onSort).toHaveBeenCalledWith('risk_score')
  })
})

describe('AlertDetail', () => {
  it('renders explanation, factors, mitre and detection sections', () => {
    render(<AlertDetail alert={alert} onClose={() => {}} />)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByText('sudo run by root')).toBeInTheDocument()
    expect(screen.getByText('privilege transition')).toBeInTheDocument() // risk factor chip
    const mitreLink = screen.getByRole('link', { name: 'T1548.003' })
    expect(mitreLink).toHaveAttribute('href', expect.stringContaining('T1548/003'))
    expect(screen.getByText(/1 \(normal\)|−1 \(anomaly\)/)).toBeInTheDocument()
  })

  it('closes on the close button and Escape', async () => {
    const onClose = vi.fn()
    render(<AlertDetail alert={alert} onClose={onClose} />)
    await userEvent.click(screen.getByRole('button', { name: /close/i }))
    expect(onClose).toHaveBeenCalled()
    await userEvent.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalledTimes(2)
  })
})

describe('FilterBar', () => {
  it('toggles a severity chip', async () => {
    const onChange = vi.fn()
    render(<FilterBar filters={EMPTY_FILTERS} onChange={onChange} onReset={() => {}} onRefresh={() => {}} />)
    await userEvent.click(screen.getByRole('button', { name: /critical/i }))
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ severities: ['critical'] }))
  })

  it('shows a clear button only when filters are active', () => {
    const { rerender } = render(
      <FilterBar filters={EMPTY_FILTERS} onChange={() => {}} onReset={() => {}} onRefresh={() => {}} />,
    )
    expect(screen.queryByText(/clear \(/i)).not.toBeInTheDocument()
    rerender(
      <FilterBar filters={{ ...EMPTY_FILTERS, host: 'web1' }} onChange={() => {}} onReset={() => {}} onRefresh={() => {}} />,
    )
    expect(screen.getByText(/clear \(1\)/i)).toBeInTheDocument()
  })
})

describe('charts', () => {
  it('RiskDistributionChart shows empty state with no data', () => {
    render(<RiskDistributionChart distribution={{ total: 0, bands: [] }} loading={false} error={null} />)
    expect(screen.getByText(/no data yet/i)).toBeInTheDocument()
  })

  it('RiskDistributionChart surfaces an error', () => {
    render(<RiskDistributionChart distribution={null} loading={false} error="boom" />)
    expect(screen.getByText('boom')).toBeInTheDocument()
  })

  it('MitreOverview lists techniques and toggles the filter', async () => {
    const onSelect = vi.fn()
    render(
      <MitreOverview
        techniques={[{ technique_id: 'T1110', technique_name: 'Brute Force', tactic: 'Credential Access', count: 9 }]}
        loading={false}
        error={null}
        activeTechnique=""
        onSelect={onSelect}
      />,
    )
    const row = screen.getByRole('button', { name: /T1110/ })
    await userEvent.click(row)
    expect(onSelect).toHaveBeenCalledWith('T1110')
  })
})
