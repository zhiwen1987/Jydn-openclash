// SYNTHETIC UNIT FIXTURES ONLY. Not captured API/runtime or node-health evidence.
import type { SubscriptionAccess, SubscriptionCandidatePage, SubscriptionCode, SubscriptionNodePage, SubscriptionReceipt,
  SubscriptionScope, SubscriptionSourcePage } from './subscription-types'

export const subscriptionSourceId = 'src_' + '1'.repeat(32)
export const subscriptionCandidateId = 'cand_' + '2'.repeat(32)
export const subscriptionCommandId = 'cmd_' + '3'.repeat(32)
export const subscriptionDigest = 'hmac-sha256:' + '4'.repeat(64)
export const subscriptionTimestamp = '2026-10-23T12:00:00Z'
export function subscriptionScope(): SubscriptionScope { return { tenantId: 'synthetic-tenant', siteId: 'synthetic-site', environment: 'candidate' } }
export function subscriptionAccess(sourceId?: string): SubscriptionAccess {
  return { scope: subscriptionScope(), resource: { type: sourceId ? 'subscription-source' : 'subscription-store', id: sourceId ?? 'local' },
    writesEnabled: true, actions: sourceId ? ['subscription.read', 'subscription.import', 'subscription.admission.decide', 'subscription.source.approve', 'subscription.fetch', 'subscription.rollback'] : ['subscription.read', 'subscription.source.manage'],
    policyState: 'ready', references: [{ referenceId: 'synthetic-reference', revision: 1 }] }
}
export function subscriptionSourcePage(): SubscriptionSourcePage {
  return { total: 1, sources: [{ id: subscriptionSourceId, scope: subscriptionScope(), label: 'Synthetic source', revision: 3,
    acceptedCandidateId: subscriptionCandidateId, latestCandidateId: subscriptionCandidateId, updatedAt: subscriptionTimestamp }] }
}
export function subscriptionCandidatePage(): SubscriptionCandidatePage {
  return { total: 1, revision: 3, candidates: [{ id: subscriptionCandidateId, sourceId: subscriptionSourceId, digest: subscriptionDigest,
    format: 'mihomo-provider-yaml', state: 'admitted_local', baseRevision: 2, nodeCount: 2, duplicateCount: 0, createdAt: subscriptionTimestamp }] }
}
export function subscriptionNodePage(): SubscriptionNodePage {
  return { total: 2, revision: 3, nodes: ['5', '6'].map(n => ({ id: 'node_' + n.repeat(32), label: '节点-' + n.repeat(8), protocol: 'trojan', credentialConfigured: true, state: 'unknown' })) }
}
export function subscriptionReceipt(overrides: Partial<SubscriptionReceipt> = {}): SubscriptionReceipt {
  return { commandId: subscriptionCommandId, kind: 'create', sourceId: subscriptionSourceId, revision: 1, state: 'committed', replayed: false,
    stateMayHaveChanged: false, auditRecorded: true, preparedAuditHash: '7'.repeat(64), resultAuditHash: '8'.repeat(64), localAuditHash: '9'.repeat(64), completedAt: subscriptionTimestamp, ...overrides }
}
export function subscriptionEnvelope(result?: unknown, code?: SubscriptionCode, changed = false) {
  return { boundary: 'LOCAL_SUBSCRIPTION_ADMISSION_ONLY', authorization: 'BLOCKED', deviceActionsExecuted: false, stateMayHaveChanged: changed,
    ...(code === undefined ? { result } : { code }) }
}
export function subscriptionResponse(result: unknown, status = 200, code?: SubscriptionCode, changed = false, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(subscriptionEnvelope(result, code, changed)) + '\n', { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers } })
}
