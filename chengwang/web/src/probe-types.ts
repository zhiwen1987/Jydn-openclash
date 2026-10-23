export type ProbeConclusion = 'unknown' | 'available' | 'degraded' | 'restricted' | 'unavailable' | 'rate_limited'
export interface ProbeCoverage {
  declaredTargets: number
  targetsWithSamples: number
  targetsMissing: number
  retainedSamples: number
  validTotal: number
  expiredTotal: number
  eligibleTotal: number
  rejectedTotal: number
  truncated: boolean
  partial: boolean
}
export interface ProbeStatus {
  schema: 'chengwang.probe-view-status/v1'
  configured: boolean
  running: boolean
  advisoryOnly: true
  state: 'disabled' | 'pending' | 'ready' | 'partial' | 'unknown'
  reason: string
  clockHealthy: boolean
  storageHealthy: boolean
  cachedAt?: string
  expiresAt?: string
  coverage: ProbeCoverage
}
export interface ProbeTarget {
  probeId: string
  pathId: string
  state: ProbeConclusion
  reason: string
  observedAt?: string
  expiresAt?: string
  consecutiveSuccess: number
  consecutiveFailure: number
  retainedSamples: number
}
export interface ProbeLayer {
  state: ProbeConclusion
  observedAt: string
  expiresAt: string
  latencyMillis: number
  retryAfterSeconds?: number
  reason: string
}
export interface ProbeSample {
  runId: string
  probeId: string
  pathId: string
  attemptedAt: string
  completedAt: string
  expiresAt: string
  conclusion: ProbeConclusion
  outcome: 'pass' | 'fail' | 'indeterminate'
  httpStatus?: number
  responseBytes?: number
  errorClass?: string
  layers: Record<'dns' | 'connect' | 'tls' | 'http' | 'business', ProbeLayer>
}
export interface ProbeDetails {
  schema: 'chengwang.probe-view-details/v1'
  status: ProbeStatus
  catalogDigest: string
  agentId: string
  independence: 'P1'
  advisoryOnly: true
  targets: ProbeTarget[]
  samples: ProbeSample[]
  rejections: Record<'format' | 'integrity' | 'catalog' | 'future' | 'duplicate' | 'semantic', number>
}
