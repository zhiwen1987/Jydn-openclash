// Synthetic unit-test shapes only; these are not actual measurements or acceptance evidence.
import type { OverviewSnapshot } from './overview-types'

export function overviewFixture(): OverviewSnapshot {
  const missing = ['controller_observation', 'probe_readback', 'businesses', 'node_pools', 'end_to_end_dns', 'device_inventory', 'traffic_topology'] as const
  const unknown = () => ({ state: 'unknown' as const, reason: 'not_configured' as const, observedAt: null, expiresAt: null })
  return { schema: 'chengwang.overview-snapshot/v1', dataSource: 'live', generatedAt: '2026-10-24T01:00:00.123456789Z', mode: 'lab.prod', readOnly: true, advisoryOnly: true,
    coverage: { state: 'none', missing: [...missing] }, observation: { configured: false, running: false, fresh: false, stale: false, lastAttemptAt: null, lastSuccessAt: null, consecutiveFailures: 0, controller: unknown(), storage: unknown(), clock: unknown() },
    probe: { configured: false, running: false, state: 'disabled', reason: 'disabled', clockHealthy: false, storageHealthy: false, cachedAt: null, expiresAt: null, coverageState: 'unavailable', coverage: null },
    subscription: { configured: false, inventoryState: 'protected_not_read', sourceCount: null, nodeCount: null }, unsupported: { businesses: true, nodePools: true, endToEndDNS: true, deviceInventory: true, trafficTopology: true } }
}
export function currentProbeFixture(): OverviewSnapshot {
  const v = overviewFixture()
  v.probe = { configured: true, running: true, state: 'partial', reason: 'partial_coverage', clockHealthy: true, storageHealthy: true, cachedAt: '2026-10-24T01:00:00.123456788Z', expiresAt: '2026-10-24T01:00:00.123456790Z', coverageState: 'current', coverage: { declaredTargets: 2, targetsWithSamples: 1, targetsMissing: 1, retainedSamples: 1, validTotal: 2, expiredTotal: 1, eligibleTotal: 1, rejectedTotal: 0, truncated: false, partial: true } }
  v.coverage = { state: 'partial', missing: ['controller_observation', 'businesses', 'node_pools', 'end_to_end_dns', 'device_inventory', 'traffic_topology'] }
  return v
}
