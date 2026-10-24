// This metadata belongs only to the explicitly selected actual-evidence view.
// It never supplies or mutates the older Snapshot used by configuration editors.
export type OverviewDisplayState = {
  state: 'pending' | 'ready' | 'error'
  mode: string | null
}

export type OverviewNavigationPage = '设备读回' | '代理节点' | '订阅与提供者'

export type EvidenceOverviewProps = {
  onStateChange?: (state: OverviewDisplayState) => void
  onNavigate?: (page: OverviewNavigationPage) => void
}

export type OverviewTime = string | null
export type LayerReason = 'not_configured' | 'no_current_evidence' | 'cache_current' | 'evidence_stale' | 'read_failed' | 'worker_stopped' | 'clock_untrusted' | 'storage_unhealthy'
export type OverviewLayer = { state: 'unknown' | 'available' | 'degraded' | 'unavailable'; reason: LayerReason; observedAt: OverviewTime; expiresAt: OverviewTime }
export type ProbeReason = 'disabled' | 'not_started' | 'ok' | 'partial_coverage' | 'no_current_evidence' | 'evidence_expired' | 'content_rejected' | 'clock_rollback' | 'stopped' | 'cache_expired' | 'platform_unsupported' | 'limit_rejected' | 'storage_rejected' | 'read_unavailable'
export type ProbeCoverage = { declaredTargets: number; targetsWithSamples: number; targetsMissing: number; retainedSamples: number; validTotal: number; expiredTotal: number; eligibleTotal: number; rejectedTotal: number; truncated: boolean; partial: boolean }
export type CoverageMissing = 'controller_observation' | 'probe_readback' | 'businesses' | 'node_pools' | 'end_to_end_dns' | 'device_inventory' | 'traffic_topology'
export type OverviewSnapshot = {
  schema: 'chengwang.overview-snapshot/v1'; dataSource: 'live'; generatedAt: string; mode: string; readOnly: true; advisoryOnly: true
  coverage: { state: 'none' | 'partial'; missing: CoverageMissing[] }
  observation: { configured: boolean; running: boolean; fresh: boolean; stale: boolean; lastAttemptAt: OverviewTime; lastSuccessAt: OverviewTime; consecutiveFailures: number; controller: OverviewLayer; storage: OverviewLayer; clock: OverviewLayer }
  probe: { configured: boolean; running: boolean; state: 'disabled' | 'pending' | 'unknown' | 'partial' | 'ready'; reason: ProbeReason; clockHealthy: boolean; storageHealthy: boolean; cachedAt: OverviewTime; expiresAt: OverviewTime; coverageState: 'current' | 'unavailable'; coverage: ProbeCoverage | null }
  subscription: { configured: boolean; inventoryState: 'protected_not_read'; sourceCount: null; nodeCount: null }
  unsupported: { businesses: true; nodePools: true; endToEndDNS: true; deviceInventory: true; trafficTopology: true }
}
