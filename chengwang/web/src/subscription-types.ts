// Public subscription admission DTOs. Availability and device execution are not implied.
export type SubscriptionScope = { tenantId: string; siteId: string; environment: string }
export type SubscriptionFormat = 'mihomo-provider-yaml' | 'uri-list' | 'base64-uri-list'
export type SubscriptionProtocol = 'ss' | 'vmess' | 'vless' | 'trojan' | 'http' | 'socks5'
export type SubscriptionKind = 'create' | 'import' | 'approve' | 'fetch' | 'decide' | 'rollback'
export type SubscriptionAction = 'subscription.read' | 'subscription.source.manage' | 'subscription.import' |
  'subscription.admission.decide' | 'subscription.source.approve' | 'subscription.fetch' | 'subscription.rollback'
export type SubscriptionCode = 'subscription_command_invalid' | 'subscription_forbidden' | 'subscription_writes_disabled' |
  'subscription_unavailable' | 'subscription_command_conflict' | 'subscription_command_not_found' |
  'subscription_audit_degraded' | 'subscription_commit_unknown' | 'subscription_command_canceled' |
  'subscription_approval_required' | 'subscription_command_limit'
export type SubscriptionAccess = {
  scope: SubscriptionScope; resource: { type: 'subscription-store' | 'subscription-source'; id: string }
  writesEnabled: boolean; actions: SubscriptionAction[]; policyState: 'ready' | 'not_configured' | 'unavailable'
  references: { referenceId: string; revision: number }[]
}
export type SubscriptionSource = {
  id: string; scope: SubscriptionScope; label: string; revision: number; updatedAt: string
  acceptedCandidateId?: string; latestCandidateId?: string
}
export type SubscriptionSourcePage = { sources: SubscriptionSource[]; total: number }
export type SubscriptionCandidate = {
  id: string; sourceId: string; digest: string; format: SubscriptionFormat
  state: 'quarantined' | 'admitted_local' | 'rejected'; baseRevision: number
  nodeCount: number; duplicateCount: number; createdAt: string
}
export type SubscriptionCandidatePage = { candidates: SubscriptionCandidate[]; total: number; revision: number; nextOffset?: number }
export type SubscriptionNode = { id: string; label: string; protocol: SubscriptionProtocol; credentialConfigured: boolean; state: 'unknown' }
export type SubscriptionNodePage = { nodes: SubscriptionNode[]; total: number; revision: number; nextOffset?: number }
export type SubscriptionReceipt = {
  commandId: string; kind: SubscriptionKind; sourceId?: string; candidateId?: string; revision: number; candidateDigest?: string
  state: 'prepared' | 'committed' | 'approved' | 'noop' | 'failed' | 'unknown'; code?: SubscriptionCode
  replayed: boolean; stateMayHaveChanged: boolean; auditRecorded: boolean
  preparedAuditHash?: string; resultAuditHash?: string; localAuditHash?: string
  referenceId?: string; policyRevision?: number; policyDigest?: string; approvalId?: string; completedAt?: string
}
export type SubscriptionPageQuery = { limit: number; offset: number; revision?: number }
export type SubscriptionIntentInput =
  | { kind: 'create'; label: string }
  | { kind: 'import'; sourceId: string; expectedRevision: number; format: SubscriptionFormat | 'auto'; content: Uint8Array }
  | { kind: 'approve'; sourceId: string; expectedRevision: number; referenceId: string; policyRevision: number }
  | { kind: 'fetch'; sourceId: string; expectedRevision: number; approvalId: string; policyRevision: number }
  | { kind: 'decide'; sourceId: string; expectedRevision: number; candidateId: string; expectedDigest: string; decision: 'admitted_local' | 'rejected' }
  | { kind: 'rollback'; sourceId: string; expectedRevision: number; candidateId: string }
// Import content is intentionally absent: owned bytes live only in a private WeakMap.
export type SubscriptionIntent = Readonly<
  (Exclude<SubscriptionIntentInput, { kind: 'import' }> |
  Omit<Extract<SubscriptionIntentInput, { kind: 'import' }>, 'content'>) & { idempotencyKey: string }
>
