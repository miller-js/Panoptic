import { describe, expect, it } from 'vitest'
import { formatCompactNumber, severityForScore, severityMeta } from '../severity'

describe('severityForScore', () => {
  it.each([
    [0, 'informational'],
    [19, 'informational'],
    [20, 'low'],
    [45, 'medium'],
    [60, 'high'],
    [79, 'high'],
    [80, 'critical'],
    [100, 'critical'],
  ])('score %i -> %s', (score, expected) => {
    expect(severityForScore(score)).toBe(expected)
  })

  it('handles junk input', () => {
    expect(severityForScore(undefined)).toBe('informational')
    expect(severityForScore('nope')).toBe('informational')
  })
})

describe('severityMeta', () => {
  it('always returns a glyph + label', () => {
    for (const s of ['critical', 'high', 'medium', 'low', 'informational', 'bogus']) {
      const m = severityMeta(s)
      expect(m.label).toBeTruthy()
      expect(m.glyph).toBeTruthy()
    }
  })
})

describe('formatCompactNumber', () => {
  it('compacts large numbers', () => {
    expect(formatCompactNumber(1500)).toBe('1,500')
    expect(formatCompactNumber(25000)).toMatch(/25K/i)
  })
})
