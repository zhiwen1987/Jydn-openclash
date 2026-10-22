import type { ImageTrustHistory, ImageTrustHistoryEntry, ImageTrustStatus } from './image-trust-types'

export function trustStatus(patch: Partial<ImageTrustStatus> = {}): ImageTrustStatus {
  return { boundary: 'ADVISORY_TRUST_POLICY_STATE', authorization: 'BLOCKED', deviceActionsExecuted: false,
    observedAtUnix: 1800000000, auditVerifiedAtUnix: 1800000000, healthy: true, fresh: true, storeId: '2'.repeat(32),
    generation: 2, catalogueSHA256: 'sha256:' + 'a'.repeat(64), notAfterUnix: 1800001000, sequence: 7,
    ledgerEntries: 1, ledgerCapacity: 4096, reserved: 0, consumed: 1, revokedKeys: 1, revokedApprovals: 2, revokedManifests: 3,
    policies: [{ policyId: 'policy-a', grantId: 'b'.repeat(32), revision: 1, manifestSHA256: 'sha256:' + 'b'.repeat(64), state: 'CONSUMED' }],
    refreshRequired: true, refreshFresh: true, refreshLastSuccessUnix: 1800000000, refreshUntilUnix: 1800000300, recoveryCompleted: 2, ...patch }
}
export function trustEntry(patch: Partial<ImageTrustHistoryEntry> = {}): ImageTrustHistoryEntry {
  return { operationId: 'd'.repeat(32), actorId: 'auditor-a', kind: 'update', state: 'COMMITTED', outcome: 'CATALOGUE_COMMITTED',
    acknowledged: true, policyId: '', grantId: '', generation: 2, catalogueSHA256: 'sha256:' + 'a'.repeat(64), preparedAuditHash: 'c'.repeat(64),
    resultAuditHash: 'd'.repeat(64), preparedAtUnix: 1800000000, resultAtUnix: 1800000001, ...patch }
}
export function trustHistory(patch: Partial<ImageTrustHistory> = {}): ImageTrustHistory {
  return { boundary: 'ADVISORY_TRUST_OPERATION_HISTORY', authorization: 'BLOCKED', deviceActionsExecuted: false,
    observedAtUnix: 1800000000, sequence: 7, total: 1, offset: 0, limit: 20, entries: [trustEntry()], ...patch }
}
export function trustResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}
