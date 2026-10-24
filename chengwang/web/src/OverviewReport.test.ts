import { describe, expect, it } from 'vitest'
import { decodeOverviewSnapshot, overviewTimeKey } from './overview-report'
import { currentProbeFixture, overviewFixture } from './overview-test-fixture'

describe('OverviewReport', () => {
  it('preserves explicit unknown inventories and detached source timestamps', () => {
    const v = overviewFixture(), decoded = decodeOverviewSnapshot(v)
    expect(decoded.subscription.sourceCount).toBeNull(); expect(decoded.generatedAt).toBe(v.generatedAt)
    v.mode = 'changed'; expect(decoded.mode).toBe('lab.prod')
  })
  it('rejects missing and additional fields at nested public boundaries', () => {
    const v = overviewFixture()
    expect(() => decodeOverviewSnapshot({ ...v, token: 'private' })).toThrow()
    expect(() => decodeOverviewSnapshot({ ...v, subscription: { ...v.subscription, sourceCount: 0 } })).toThrow()
    expect(() => decodeOverviewSnapshot({ ...v, observation: { ...v.observation, clock: {} } })).toThrow()
  })
  it('accepts custom modes within UTF8 limits and rejects unsafe labels', () => {
    expect(decodeOverviewSnapshot({ ...overviewFixture(), mode: 'Shadow/生产' }).mode).toBe('Shadow/生产')
    for (const mode of ['', ' lab', 'lab\u200b', '界'.repeat(22), '\ud800']) expect(() => decodeOverviewSnapshot({ ...overviewFixture(), mode })).toThrow()
  })
  it('validates UTC calendar years and preserves nanosecond ordering', () => {
    expect(overviewTimeKey('0000-02-29T00:00:00Z')).toBe('0000-02-29T00:00:00.000000000Z')
    expect(overviewTimeKey('2026-10-24T01:00:00.123456788Z') < overviewTimeKey('2026-10-24T01:00:00.123456789Z')).toBe(true)
    for (const generatedAt of ['1900-02-29T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T00:00:00+00:00', '0001-01-01T00:00:00Z']) expect(() => decodeOverviewSnapshot({ ...overviewFixture(), generatedAt })).toThrow()
  })
  it('requires current probe time windows at nanosecond precision', () => {
    expect(decodeOverviewSnapshot(currentProbeFixture()).probe.coverage?.retainedSamples).toBe(1)
    const v = currentProbeFixture(); v.generatedAt = v.probe.expiresAt!
    expect(() => decodeOverviewSnapshot(v)).toThrow()
  })
  it('rejects inconsistent coverage equations and false complete coverage', () => {
    const v = currentProbeFixture(); v.probe.coverage!.eligibleTotal = 2
    expect(() => decodeOverviewSnapshot(v)).toThrow()
    const other = currentProbeFixture(); other.coverage.missing.reverse()
    expect(() => decodeOverviewSnapshot(other)).toThrow()
    expect(() => decodeOverviewSnapshot({ ...overviewFixture(), coverage: { state: 'covered', missing: [] } })).toThrow()
  })
  it('rejects cached counts for stopped or unhealthy probe sources', () => {
    for (const field of ['running', 'clockHealthy', 'storageHealthy'] as const) {
      const v = currentProbeFixture(); v.probe[field] = false
      expect(() => decodeOverviewSnapshot(v)).toThrow()
    }
  })
  it('allows rollback timestamps only as explicitly unavailable evidence', () => {
    const v = overviewFixture(); v.observation.configured = true; v.observation.clock.state = 'unavailable'; v.observation.clock.reason = 'clock_untrusted'
    v.observation.lastAttemptAt = '2027-01-01T00:00:00Z'
    expect(decodeOverviewSnapshot(v).observation.fresh).toBe(false)
    v.observation.clock.state = 'available'
    expect(() => decodeOverviewSnapshot(v)).toThrow()
  })
  it('rejects stopped controllers masquerading as fresh observations', () => {
    const v = overviewFixture(); v.observation.controller.state = 'available'
    expect(() => decodeOverviewSnapshot(v)).toThrow()
  })
  it('requires trusted clock successful observation and zero failures for fresh controller evidence', () => {
    const v = overviewFixture(), at = '2026-10-24T01:00:00Z'
    v.observation = { configured: true, running: true, fresh: true, stale: false, lastAttemptAt: at, lastSuccessAt: at, consecutiveFailures: 0, controller: { state: 'available', reason: 'cache_current', observedAt: at, expiresAt: '2026-10-24T01:01:00Z' }, storage: { state: 'available', reason: 'cache_current', observedAt: null, expiresAt: null }, clock: { state: 'available', reason: 'cache_current', observedAt: null, expiresAt: null } }
    v.coverage.missing.shift(); v.coverage.state = 'partial'
    expect(decodeOverviewSnapshot(v).observation.fresh).toBe(true)
    for (const state of ['unknown', 'degraded'] as const) expect(() => decodeOverviewSnapshot({ ...v, observation: { ...v.observation, clock: { ...v.observation.clock, state } } })).toThrow()
    expect(() => decodeOverviewSnapshot({ ...v, observation: { ...v.observation, consecutiveFailures: 1 } })).toThrow()
    expect(() => decodeOverviewSnapshot({ ...v, observation: { ...v.observation, lastSuccessAt: null } })).toThrow()
  })
  it('rejects disabled source contradictions and expiry without an observed time', () => {
    const v = overviewFixture(); v.observation.running = true
    expect(() => decodeOverviewSnapshot(v)).toThrow()
    const other = overviewFixture(); other.probe.running = true
    expect(() => decodeOverviewSnapshot(other)).toThrow()
    const expiry = overviewFixture(); expiry.observation.controller.expiresAt = '2026-10-24T01:01:00Z'
    expect(() => decodeOverviewSnapshot(expiry)).toThrow()
  })
  it('rejects unknown enums and noninteger counters without reflecting input', () => {
    const v = overviewFixture(); v.observation.consecutiveFailures = 0.5
    expect(() => decodeOverviewSnapshot(v)).toThrow('实际总览格式不符合约定')
    expect(() => decodeOverviewSnapshot({ ...overviewFixture(), probe: { ...overviewFixture().probe, reason: 'private failure' } })).toThrow('实际总览格式不符合约定')
    for (const [role, state, reason] of [['controller', 'degraded', 'storage_unhealthy'], ['storage', 'unknown', 'worker_stopped'], ['clock', 'available', 'clock_untrusted']] as const) {
      const wrong = overviewFixture(); wrong.observation.configured = true; wrong.observation[role] = { state, reason, observedAt: null, expiresAt: null }
      expect(() => decodeOverviewSnapshot(wrong)).toThrow('实际总览格式不符合约定')
    }
  })
  it('requires source-consistent probe state and reason pairs', () => {
    const v = currentProbeFixture(); v.probe.reason = 'clock_rollback'
    expect(() => decodeOverviewSnapshot(v)).toThrow()
    const other = overviewFixture(); other.probe.configured = true
    expect(() => decodeOverviewSnapshot(other)).toThrow()
  })
  it('requires cached timestamps even when ready or partial counts are unavailable', () => {
    const v = overviewFixture(); v.probe = { ...v.probe, configured: true, running: true, clockHealthy: true, storageHealthy: true, state: 'partial', reason: 'no_current_evidence' }
    expect(() => decodeOverviewSnapshot(v)).toThrow()
  })
})
