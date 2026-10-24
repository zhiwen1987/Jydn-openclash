import type { CoverageMissing, OverviewSnapshot } from './overview-types'

const layerReasons = ['not_configured', 'no_current_evidence', 'cache_current', 'evidence_stale', 'read_failed', 'worker_stopped', 'clock_untrusted', 'storage_unhealthy']
const probeReasons = ['disabled', 'not_started', 'ok', 'partial_coverage', 'no_current_evidence', 'evidence_expired', 'content_rejected', 'clock_rollback', 'stopped', 'cache_expired', 'platform_unsupported', 'limit_rejected', 'storage_rejected', 'read_unavailable']
const coverageNumbers = ['declaredTargets', 'targetsWithSamples', 'targetsMissing', 'retainedSamples', 'validTotal', 'expiredTotal', 'eligibleTotal', 'rejectedTotal'] as const
const permanentMissing: CoverageMissing[] = ['businesses', 'node_pools', 'end_to_end_dns', 'device_inventory', 'traffic_topology']
function invalid(): never { throw new Error('实际总览格式不符合约定') }
function object(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid()
  const actual = Object.keys(value)
  if (actual.length !== keys.length || keys.some(key => !Object.prototype.hasOwnProperty.call(value, key))) return invalid()
  return value as Record<string, unknown>
}
function one(value: unknown, allowed: readonly unknown[]) { if (!allowed.includes(value)) invalid() }
function bool(value: unknown) { if (typeof value !== 'boolean') invalid() }
function count(value: unknown, max = 2147483647): asserts value is number { if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > max) invalid() }

// UTC calendar validation and a nine-digit lexical fraction preserve Go's nanoseconds.
// This deliberately does not consult the browser's wall clock or Date milliseconds.
export function overviewTimeKey(value: unknown): string {
  if (typeof value !== 'string') return invalid()
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(value)
  if (!m) return invalid()
  const [, y, mo, d, h, mi, s, fraction = ''] = m
  const year = Number(y), month = Number(mo), day = Number(d)
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1] || Number(h) > 23 || Number(mi) > 59 || Number(s) > 59) return invalid()
  return `${y}-${mo}-${d}T${h}:${mi}:${s}.${fraction.padEnd(9, '0')}Z`
}
function time(value: unknown): string | null {
  if (value === null) return null
  const key = overviewTimeKey(value)
  if (key === '0001-01-01T00:00:00.000000000Z') return invalid()
  return key
}
function windowTimes(observed: unknown, expires: unknown) {
  const a = time(observed), b = time(expires)
  if (b !== null && (a === null || a >= b)) invalid()
  return { a, b }
}
function layer(value: unknown, role: 'controller' | 'storage' | 'clock') {
  const v = object(value, ['state', 'reason', 'observedAt', 'expiresAt'])
  one(v.state, ['unknown', 'available', 'degraded', 'unavailable']); one(v.reason, layerReasons)
  const pairs: Record<string, readonly unknown[]> = {
    available: ['cache_current'],
    unknown: role === 'controller' ? ['not_configured', 'no_current_evidence', 'worker_stopped', 'clock_untrusted'] : ['not_configured', 'no_current_evidence'],
    degraded: [role === 'controller' ? 'evidence_stale' : role === 'storage' ? 'storage_unhealthy' : 'clock_untrusted'],
    unavailable: [role === 'controller' ? 'read_failed' : role === 'storage' ? 'storage_unhealthy' : 'clock_untrusted'],
  }
  if (!pairs[String(v.state)].includes(v.reason)) invalid()
  return { state: v.state, reason: v.reason, ...windowTimes(v.observedAt, v.expiresAt) }
}

export function decodeOverviewSnapshot(value: unknown): OverviewSnapshot {
  const v = object(value, ['schema', 'dataSource', 'generatedAt', 'mode', 'readOnly', 'advisoryOnly', 'coverage', 'observation', 'probe', 'subscription', 'unsupported'])
  one(v.schema, ['chengwang.overview-snapshot/v1']); one(v.dataSource, ['live']); one(v.readOnly, [true]); one(v.advisoryOnly, [true])
  const generated = time(v.generatedAt)
  if (generated === null || typeof v.mode !== 'string' || !v.mode || v.mode.trim() !== v.mode || /[\p{Cc}\p{Cf}\p{Cs}]/u.test(v.mode) || new TextEncoder().encode(v.mode).length > 64) invalid()
  const obs = object(v.observation, ['configured', 'running', 'fresh', 'stale', 'lastAttemptAt', 'lastSuccessAt', 'consecutiveFailures', 'controller', 'storage', 'clock'])
  for (const key of ['configured', 'running', 'fresh', 'stale']) bool(obs[key])
  count(obs.consecutiveFailures)
  const controller = layer(obs.controller, 'controller'), storage = layer(obs.storage, 'storage'), clock = layer(obs.clock, 'clock')
  const attempt = time(obs.lastAttemptAt), success = time(obs.lastSuccessAt)
  const trusted = clock.state === 'available'
  if (clock.state !== 'unavailable' && [attempt, success, controller.a, storage.a, clock.a].some(t => t !== null && t > generated)) invalid()
  const controllerCurrent = obs.configured === true && obs.running === true && trusted && obs.fresh === true && controller.state === 'available' && controller.a !== null && controller.b !== null && controller.a <= generated && generated < controller.b
  if (obs.fresh !== controllerCurrent || (obs.fresh === true && (obs.stale === true || obs.consecutiveFailures !== 0 || success === null || success !== controller.a))) invalid()
  if (controller.state === 'available' && obs.fresh !== true) invalid()
  if ((obs.running === false || !trusted) && controller.state !== 'unknown') invalid()
  if (obs.configured === false && (obs.running !== false || obs.fresh !== false || obs.stale !== false || attempt !== null || success !== null || obs.consecutiveFailures !== 0 || [controller, storage, clock].some(item => item.state !== 'unknown' || item.reason !== 'not_configured' || item.a !== null || item.b !== null))) invalid()
  const probe = object(v.probe, ['configured', 'running', 'state', 'reason', 'clockHealthy', 'storageHealthy', 'cachedAt', 'expiresAt', 'coverageState', 'coverage'])
  for (const key of ['configured', 'running', 'clockHealthy', 'storageHealthy']) bool(probe[key])
  one(probe.state, ['disabled', 'pending', 'unknown', 'partial', 'ready']); one(probe.reason, probeReasons); one(probe.coverageState, ['current', 'unavailable'])
  const cache = windowTimes(probe.cachedAt, probe.expiresAt)
  const pairs: Record<string, readonly unknown[]> = { disabled: ['disabled'], pending: ['not_started'], ready: ['ok'], partial: ['partial_coverage', 'no_current_evidence', 'evidence_expired'], unknown: probeReasons.filter(reason => !['disabled', 'not_started', 'ok', 'partial_coverage'].includes(reason)) }
  if (!pairs[String(probe.state)].includes(probe.reason) || (probe.configured === true && probe.state === 'disabled') || (['ready', 'partial'].includes(String(probe.state)) && (cache.a === null || cache.b === null))) invalid()
  if (probe.configured === false && (probe.running !== false || probe.clockHealthy !== false || probe.storageHealthy !== false || probe.state !== 'disabled' || probe.reason !== 'disabled' || cache.a !== null || cache.b !== null || probe.coverageState !== 'unavailable' || probe.coverage !== null)) invalid()
  if (probe.clockHealthy === false && probe.state !== 'unknown' && probe.state !== 'disabled') invalid()
  if (probe.clockHealthy === true && cache.a !== null && cache.a > generated) invalid()
  const probeCurrent = probe.configured === true && probe.running === true && probe.clockHealthy === true && probe.storageHealthy === true && ['ready', 'partial'].includes(String(probe.state)) && cache.a !== null && cache.b !== null && cache.a <= generated && generated < cache.b
  if ((probe.coverageState === 'current') !== probeCurrent) invalid()
  if (probeCurrent) {
    const c = object(probe.coverage, [...coverageNumbers, 'truncated', 'partial'])
    for (const key of coverageNumbers) count(c[key], key === 'declaredTargets' ? 256 : key === 'retainedSamples' ? 200 : 2147483647)
    bool(c.truncated); bool(c.partial)
    const n = c as Record<typeof coverageNumbers[number], number>
    if (n.targetsWithSamples > n.declaredTargets || n.targetsMissing !== n.declaredTargets - n.targetsWithSamples || n.expiredTotal > n.validTotal || n.eligibleTotal !== n.validTotal - n.expiredTotal || n.retainedSamples > n.eligibleTotal) invalid()
  } else if (probe.coverage !== null) invalid()
  const subscription = object(v.subscription, ['configured', 'inventoryState', 'sourceCount', 'nodeCount'])
  bool(subscription.configured); one(subscription.inventoryState, ['protected_not_read']); one(subscription.sourceCount, [null]); one(subscription.nodeCount, [null])
  const unsupported = object(v.unsupported, ['businesses', 'nodePools', 'endToEndDNS', 'deviceInventory', 'trafficTopology'])
  for (const flag of Object.values(unsupported)) one(flag, [true])
  const coverage = object(v.coverage, ['state', 'missing'])
  const expected: CoverageMissing[] = [...(controllerCurrent ? [] : ['controller_observation' as const]), ...(probeCurrent ? [] : ['probe_readback' as const]), ...permanentMissing]
  if (coverage.state !== (controllerCurrent || probeCurrent ? 'partial' : 'none') || !Array.isArray(coverage.missing) || coverage.missing.length !== expected.length || expected.some((code, i) => coverage.missing instanceof Array && coverage.missing[i] !== code)) invalid()
  // Detach the validated public DTO; no caller-owned object can mutate the visible evidence.
  return JSON.parse(JSON.stringify(value)) as OverviewSnapshot
}
