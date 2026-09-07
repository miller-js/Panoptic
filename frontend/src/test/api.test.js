import { afterEach, describe, expect, it, vi } from 'vitest'
import { fetchAlerts, fetchAlertStats } from '../api'

function mockFetch(impl) {
  global.fetch = vi.fn(impl)
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('api client', () => {
  it('serialises array and skips empty params', async () => {
    let captured
    mockFetch((url) => {
      captured = url
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ total: 0, items: [] }) })
    })
    await fetchAlerts({ size: 25, severity: ['high', 'critical'], host: '', anomaly: false, technique: 'T1059.004' })
    const qs = new URL(captured).searchParams
    expect(qs.get('size')).toBe('25')
    expect(qs.get('severity')).toBe('high,critical')
    expect(qs.has('host')).toBe(false)
    expect(qs.has('anomaly')).toBe(false)
    expect(qs.get('technique')).toBe('T1059.004')
  })

  it('surfaces API error bodies', async () => {
    mockFetch(() => Promise.resolve({ ok: false, status: 400, json: () => Promise.resolve({ error: 'bad size' }) }))
    await expect(fetchAlertStats()).rejects.toThrow('bad size')
  })

  it('reports unreachable API', async () => {
    mockFetch(() => Promise.reject(new TypeError('failed')))
    await expect(fetchAlertStats()).rejects.toThrow(/Can't reach the Panoptic API/)
  })
})
