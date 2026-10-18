export type BusinessStatus = { id: string; name: string; strategy: string; activeRoute: string; status: string }
export type PoolStatus = { name: string; region: string; latencyMs: number; lossRate: number; available: number; total: number; status: string }
export type EventItem = { at: string; type: string; reason: string; result: string }
export type BusinessPolicy = {
  id: string; name: string; domains: string[]; strategy: string; candidates: string[]; fallback: string
  skipEmptyPools: boolean; failuresToSwitch: number; probeIntervalSec: number; sessionStickyMin: number; switchCooldownSec: number
}
export type NodePool = { id: string; name: string; members: string[]; capabilities?: string[] }
export type DNSPolicy = {
  domesticResolvers?: string[]; overseasResolvers?: string[]; hijackPort53?: boolean; leakProtection?: boolean
}
export type PolicyDraft = { name: string; baseVersion: string; businesses: BusinessPolicy[]; pools: NodePool[]; dns: DNSPolicy }
export type ProxyInterface = {
  id: string; name: string; type: 'http' | 'socks5' | 'mixed' | 'tun' | 'tproxy' | 'redirect' | 'api'
  core: string; listen: string; port: number; udp: boolean; lanAccess: boolean
  authMode: 'none' | 'password' | 'token' | 'mtls'; authReference?: string
  tls: boolean; tlsReference?: string; accessScope: 'local' | 'lan' | 'vpn' | 'custom'
  allowedCidrs?: string[]; maxConnections: number; idleTimeoutSec: number; rateLimitMbps: number
  auditEnabled: boolean; enabled: boolean; status: string; routingProfile: string; description?: string
}
export type ValidationIssue = { code: string; severity: string; path: string; message: string }
export type ValidationResult = { valid: boolean; issues: ValidationIssue[] }
export type Snapshot = {
  product: string; version: string; mode: string; status: string; dataSource: 'demo' | 'live'; publishLocked: boolean
  businesses: BusinessStatus[]; pools: PoolStatus[]; interfaces: ProxyInterface[]; events: EventItem[]; draft: PolicyDraft
}
export type MihomoVersion = { version: string; meta: boolean; premium: boolean }
export type MihomoConfig = {
  mode: string; allowLan: boolean; bindAddress: string; ipv6: boolean
  port: number; socksPort: number; mixedPort: number; redirPort: number; tproxyPort: number; externalController: string
}
export type MihomoProxy = { name: string; type: string; now?: string; all?: string[] }
export type MihomoRule = { type: string; payload: string; proxy: string }
export type MihomoRuntimeSnapshot = {
  observedAt: string; version: MihomoVersion; config: MihomoConfig; proxies: MihomoProxy[]; rules: MihomoRule[]
}
export type MihomoDrift = {
  kind: 'missing_proxy_group' | 'group_members_mismatch' | 'missing_domain_rule' | 'rule_target_mismatch' | string
  path: string; severity: string; expected?: unknown; actual?: unknown; message: string
}
export type MihomoReadbackReport = {
  observedAt: string; controllerVersion: string; match: boolean
  counts: { expectedGroups: number; observedGroups: number; expectedRules: number; observedRules: number }
  drifts: MihomoDrift[]
}

export type CapabilityState = 'live_readonly' | 'implemented_local' | 'design_only' | 'blocked'
export type SystemCapability = {
  id: string
  domain: string
  name: string
  state: CapabilityState
  readOnly: boolean
  evidence: string[]
  limitations: string[]
}
export type CapabilityReport = {
  generatedAt: string
  productionControlEnabled: boolean
  overallState: string
  capabilities: SystemCapability[]
}

export type OperationResource = {
  tenantId: string
  siteId: string
  objectType: string
  objectId: string
  environment: string
}

export type OperationRisk = 'low' | 'medium' | 'high' | 'critical'
export type OperationStatus =
  | 'planned'
  | 'awaiting_approval'
  | 'prechecking'
  | 'executing'
  | 'verifying'
  | 'observing'
  | 'succeeded'
  | 'partial'
  | 'rolled_back'
  | 'failed'
  | 'manual_takeover'

export type OperationSummary = {
  id: string
  identityBinding: 'durable' | 'legacy_unbound'
  environment: string
  scope: string
  targetVersion: string
  risk: OperationRisk
  status: OperationStatus
  createdAt: string
  updatedAt: string
}

export type OperationEnvelope = {
  effect: 'local_record_only'
  deviceActionsExecuted: boolean
  operations?: OperationSummary[]
  operation?: OperationSummary
  created?: boolean
  applied?: boolean
  replayed?: boolean
  auditRecorded?: boolean
  outcome?: string
  code?: string
  message?: string
}
