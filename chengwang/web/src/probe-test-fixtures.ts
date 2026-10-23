import type { ProbeDetails, ProbeStatus } from './probe-types'

// Synthetic component fixtures only. These never prove a real agent/API path.
export function probeStatus(patch: Partial<ProbeStatus> = {}): ProbeStatus {
  return { schema: 'chengwang.probe-view-status/v1', configured: true, running: true, advisoryOnly: true, state: 'ready', reason: 'ok', clockHealthy: true, storageHealthy: true,
    cachedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(),
    coverage: { declaredTargets: 1, targetsWithSamples: 1, targetsMissing: 0, retainedSamples: 2, validTotal: 2, expiredTotal: 0, eligibleTotal: 2, rejectedTotal: 0, truncated: false, partial: false }, ...patch }
}
export function probeDetails(): ProbeDetails {
  const status = probeStatus()
  const layer = { state: 'available' as const, observedAt: status.cachedAt!, expiresAt: status.expiresAt!, latencyMillis: 10, reason: 'contract_match' }
  return { schema: 'chengwang.probe-view-details/v1', status, catalogDigest: 'a'.repeat(64), agentId: 'agent-fixture', independence: 'P1', advisoryOnly: true,
    targets: [{ probeId: 'business-fixture', pathId: 'direct-fixture', state: 'available', reason: 'two_consecutive_contract_matches', observedAt: status.cachedAt, expiresAt: status.expiresAt, consecutiveSuccess: 2, consecutiveFailure: 0, retainedSamples: 2 }],
    samples: [{ runId: 'run-fixture', probeId: 'business-fixture', pathId: 'direct-fixture', attemptedAt: status.cachedAt!, completedAt: status.cachedAt!, expiresAt: status.expiresAt!, conclusion: 'available', outcome: 'pass', responseBytes: 16, httpStatus: 200, layers: { dns: { ...layer }, connect: { ...layer }, tls: { ...layer }, http: { ...layer }, business: { ...layer } } }],
    rejections: { format: 0, integrity: 0, catalog: 0, future: 0, duplicate: 0, semantic: 0 } }
}
export function probeResponse(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }) }
