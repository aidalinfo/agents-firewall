import { describe, expect, it } from 'vitest'
import {
  formatBytes,
  formatDuration,
  formatNumber,
  formatRelative,
  formatTime,
  ruleLabel,
  shortFlowId,
  verdictTone,
} from '../../app/utils/format'

// Intl uses narrow no-break spaces as group separators in French: normalise for assertions.
const n = (s: string) => s.replace(/[  ]/g, ' ')

describe('formatBytes', () => {
  it('formats French units like the mockup', () => {
    expect(formatBytes(0, 'fr')).toBe('0 o')
    expect(formatBytes(312, 'fr')).toBe('312 o')
    expect(n(formatBytes(9_400, 'fr'))).toBe('9,4 Ko')
    expect(n(formatBytes(182_000, 'fr'))).toBe('182 Ko')
    expect(n(formatBytes(4_100_000, 'fr'))).toBe('4,1 Mo')
    expect(n(formatBytes(1_000_000, 'fr'))).toBe('1 Mo')
    expect(n(formatBytes(2_500_000_000, 'fr'))).toBe('2,5 Go')
  })

  it('formats English units', () => {
    expect(formatBytes(312, 'en')).toBe('312 B')
    expect(formatBytes(4_100_000, 'en')).toBe('4.1 MB')
    expect(formatBytes(182_000, 'en')).toBe('182 kB')
  })

  it('handles missing and negative values', () => {
    expect(formatBytes(null, 'fr')).toBe('—')
    expect(formatBytes(-5, 'fr')).toBe('—')
  })
})

describe('formatDuration', () => {
  it('uses ms below one second, seconds below a minute, minutes above', () => {
    expect(formatDuration(2, 'fr')).toBe('2 ms')
    expect(formatDuration(84, 'fr')).toBe('84 ms')
    expect(formatDuration(6_200, 'fr')).toBe('6,2 s')
    expect(formatDuration(1_300, 'en')).toBe('1.3 s')
    expect(formatDuration(42_000, 'fr')).toBe('42 s')
    expect(formatDuration(240_000, 'fr')).toBe('4 min')
    expect(formatDuration(null, 'fr')).toBe('—')
  })
})

describe('formatNumber', () => {
  it('groups thousands per locale', () => {
    expect(n(formatNumber(48_120, 'fr'))).toBe('48 120')
    expect(formatNumber(48_120, 'en')).toBe('48,120')
  })
})

describe('formatTime', () => {
  it('prints local wall-clock time, optionally with milliseconds', () => {
    const at = new Date(2026, 9, 30, 14, 32, 7, 412).toISOString()
    expect(formatTime(at, { ms: true })).toBe('14:32:07.412')
    expect(formatTime(at)).toBe('14:32:07')
  })
})

describe('formatRelative', () => {
  const now = new Date(2026, 9, 30, 14, 40, 0)
  const ago = (ms: number) => new Date(now.getTime() - ms).toISOString()

  it('uses narrow French units', () => {
    expect(n(formatRelative(ago(20_000), 'fr', now))).toBe('il y a 20 s')
    expect(n(formatRelative(ago(6 * 60_000), 'fr', now))).toBe('il y a 6 min')
    expect(n(formatRelative(ago(3 * 3_600_000), 'fr', now))).toBe('il y a 3 h')
    expect(n(formatRelative(ago(2 * 86_400_000), 'fr', now))).toBe('il y a 2 j')
  })

  it('says never for null', () => {
    expect(formatRelative(null, 'fr', now)).toBe('jamais')
    expect(formatRelative(null, 'en', now)).toBe('never')
  })

  it('works in English', () => {
    expect(formatRelative(ago(6 * 60_000), 'en', now)).toBe('6 min ago')
  })
})

describe('ruleLabel', () => {
  it('prefixes baseline rules with S and leaves zone rules numeric', () => {
    expect(ruleLabel({ layer: 'baseline', rule_number: 3 })).toBe('S3')
    expect(ruleLabel({ layer: 'zone', rule_number: 12 })).toBe('12')
    expect(ruleLabel({ layer: 'implicit', rule_number: null })).toBe('—')
  })
})

describe('shortFlowId', () => {
  it('keeps the first six hex digits', () => {
    expect(shortFlowId('8c21e4a0-0000-4000-8000-000000000001')).toBe('f-8c21e4')
  })
})

describe('verdictTone', () => {
  it('maps a flow verdict to a tone', () => {
    expect(verdictTone({ verdict: 'allow', observed: false })).toBe('ok')
    expect(verdictTone({ verdict: 'deny', observed: false })).toBe('ko')
    expect(verdictTone({ verdict: 'allow', observed: true })).toBe('obs')
  })
})
