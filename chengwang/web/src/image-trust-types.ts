/** Sanitized observations only. None of these values authorize execution. */
export interface ImageTrustPolicy {
  policyId: string
  grantId: string
  revision: number
  manifestSHA256: string
  state: string
}

export interface ImageTrustStatus {
  boundary: 'ADVISORY_TRUST_POLICY_STATE'
  authorization: 'BLOCKED'
  deviceActionsExecuted: false
  observedAtUnix: number
  auditVerifiedAtUnix: number
  healthy: boolean
  fresh: boolean
  storeId: string
  generation: number
  catalogueSHA256: string
  notAfterUnix: number
  sequence: number
  ledgerEntries: number
  ledgerCapacity: number
  reserved: number
  consumed: number
  revokedKeys: number
  revokedApprovals: number
  revokedManifests: number
  policies: ImageTrustPolicy[]
  refreshRequired: boolean
  refreshFresh: boolean
  refreshLastSuccessUnix: number
  refreshUntilUnix: number
  recoveryCompleted: number
}

export interface ImageTrustHistoryEntry {
  operationId: string
  actorId: string
  kind: string
  state: string
  outcome: string
  acknowledged: boolean
  policyId: string
  grantId: string
  generation: number
  catalogueSHA256: string
  preparedAuditHash: string
  resultAuditHash: string
  preparedAtUnix: number
  resultAtUnix: number
}

export interface ImageTrustHistory {
  boundary: 'ADVISORY_TRUST_OPERATION_HISTORY'
  authorization: 'BLOCKED'
  deviceActionsExecuted: false
  observedAtUnix: number
  sequence: number
  total: number
  offset: number
  limit: number
  entries: ImageTrustHistoryEntry[]
}

export interface ImageTrustReadOptions {
  token: string
  signal: AbortSignal
  baseUrl?: string
  fetcher?: typeof fetch
}

export interface ImageTrustHistoryPage {
  limit: number
  offset: number
  sequence: number
}
