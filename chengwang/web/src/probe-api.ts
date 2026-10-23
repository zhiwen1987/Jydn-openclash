import { isManagementTransportSecure } from './api'
import type { ProbeDetails, ProbeStatus } from './probe-types'

export class ProbeReadError extends Error {
  constructor(readonly status: number, readonly kind: 'transport' | 'authentication' | 'forbidden' | 'unavailable' | 'format') {
    super(kind) // Never retain a response body, token, URL or raw upstream error.
  }
}

const states = ['unknown', 'available', 'degraded', 'restricted', 'unavailable', 'rate_limited']
const coverageNumbers = ['declaredTargets', 'targetsWithSamples', 'targetsMissing', 'retainedSamples', 'validTotal', 'expiredTotal', 'eligibleTotal', 'rejectedTotal']
function ensure(value: unknown): asserts value { if (!value) throw new ProbeReadError(0, 'format') }
function object(value: unknown): Record<string, unknown> {
  ensure(value !== null && typeof value === 'object' && !Array.isArray(value))
  return value as Record<string, unknown>
}
function integer(value: unknown, max = Number.MAX_SAFE_INTEGER): boolean { return Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= max }
function text(value: unknown, max = 128): boolean { return typeof value === 'string' && value.length > 0 && value.length <= max && /^[\x20-\x7e]+$/.test(value) }
function date(value: unknown): boolean { return typeof value === 'string' && value.length <= 40 && /^\d{4}-\d\d-\d\dT/.test(value) && Number.isFinite(Date.parse(value)) }
function keys(value: Record<string, unknown>, allowed: string[]) { ensure(Object.keys(value).every(key => allowed.includes(key))) }
function optionalDates(v: Record<string, unknown>, fields: string[]) { for (const key of fields) ensure(v[key] === undefined || date(v[key])) }

export function decodeProbeStatus(value: unknown): ProbeStatus {
  const v = object(value)
  keys(v, ['schema', 'configured', 'running', 'advisoryOnly', 'state', 'reason', 'clockHealthy', 'storageHealthy', 'cachedAt', 'expiresAt', 'coverage'])
  ensure(v.schema === 'chengwang.probe-view-status/v1' && v.advisoryOnly === true)
  ensure(['configured', 'running', 'clockHealthy', 'storageHealthy'].every(key => typeof v[key] === 'boolean'))
  ensure(['disabled', 'pending', 'ready', 'partial', 'unknown'].includes(String(v.state)) && text(v.reason))
  optionalDates(v, ['cachedAt', 'expiresAt'])
  const c = object(v.coverage)
  keys(c, [...coverageNumbers, 'partial', 'truncated'])
  ensure(coverageNumbers.every(key => integer(c[key], 4224)))
  ensure(integer(c.declaredTargets, 256) && integer(c.targetsWithSamples, 256) && integer(c.targetsMissing, 256) && integer(c.retainedSamples, 200))
  ensure(Number(c.targetsWithSamples) + Number(c.targetsMissing) === c.declaredTargets)
  ensure(typeof c.partial === 'boolean' && typeof c.truncated === 'boolean')
  return v as unknown as ProbeStatus
}

export function decodeProbeDetails(value: unknown): ProbeDetails {
  const v = object(value)
  keys(v, ['schema', 'status', 'catalogDigest', 'agentId', 'independence', 'advisoryOnly', 'targets', 'samples', 'rejections'])
  ensure(v.schema === 'chengwang.probe-view-details/v1' && v.advisoryOnly === true && v.independence === 'P1')
  const status = decodeProbeStatus(v.status)
  ensure(typeof v.catalogDigest === 'string' && /^(?:sha256:)?[a-f0-9]{64}$/.test(v.catalogDigest) && text(v.agentId))
  ensure(Array.isArray(v.targets) && v.targets.length <= 256 && v.targets.length === status.coverage.declaredTargets)
  const seen = new Set<string>()
  for (const raw of v.targets) {
    const t = object(raw)
    keys(t, ['probeId', 'pathId', 'state', 'reason', 'observedAt', 'expiresAt', 'consecutiveSuccess', 'consecutiveFailure', 'retainedSamples'])
    ensure(text(t.probeId) && text(t.pathId) && states.includes(String(t.state)) && text(t.reason))
    ensure(['consecutiveSuccess', 'consecutiveFailure', 'retainedSamples'].every(key => integer(t[key], 200)))
    optionalDates(t, ['observedAt', 'expiresAt'])
    const key = `${t.probeId}\0${t.pathId}`
    ensure(!seen.has(key)); seen.add(key)
  }
  ensure(Array.isArray(v.samples) && v.samples.length <= 200)
  const runs = new Set<string>()
  for (const raw of v.samples) {
    const s = object(raw)
    keys(s, ['runId', 'probeId', 'pathId', 'attemptedAt', 'completedAt', 'expiresAt', 'conclusion', 'outcome', 'httpStatus', 'responseBytes', 'errorClass', 'layers'])
    ensure(text(s.runId) && !runs.has(String(s.runId)) && seen.has(`${s.probeId}\0${s.pathId}`)); runs.add(String(s.runId))
    ensure(['attemptedAt', 'completedAt', 'expiresAt'].every(key => date(s[key])))
    ensure(states.includes(String(s.conclusion)) && ['pass', 'fail', 'indeterminate'].includes(String(s.outcome)))
    ensure((s.responseBytes === undefined || integer(s.responseBytes)) && (s.httpStatus === undefined || (integer(s.httpStatus, 599) && Number(s.httpStatus) >= 100)))
    ensure(s.errorClass === undefined || text(s.errorClass))
    const layers = object(s.layers)
    keys(layers, ['dns', 'connect', 'tls', 'http', 'business'])
    for (const key of ['dns', 'connect', 'tls', 'http', 'business']) {
      const l = object(layers[key])
      keys(l, ['state', 'observedAt', 'expiresAt', 'latencyMillis', 'retryAfterSeconds', 'reason'])
      ensure(states.includes(String(l.state)) && text(l.reason) && date(l.observedAt) && date(l.expiresAt) && integer(l.latencyMillis))
      ensure(l.retryAfterSeconds === undefined || integer(l.retryAfterSeconds))
    }
  }
  const r = object(v.rejections)
  keys(r, ['format', 'integrity', 'catalog', 'future', 'duplicate', 'semantic'])
  ensure(['format', 'integrity', 'catalog', 'future', 'duplicate', 'semantic'].every(key => integer(r[key], 4224)))
  return v as unknown as ProbeDetails
}

function cancel(body: ReadableStream<Uint8Array> | null) { try { void body?.cancel().catch(() => {}) } catch { /* No upstream data retained. */ } }
async function read(path: string, signal: AbortSignal, token?: string): Promise<unknown> {
  if (token !== undefined) {
    if (!isManagementTransportSecure()) throw new ProbeReadError(426, 'transport')
    if (!token || token.length > 4096 || !/^[\x21-\x2b\x2d-\x7e]+$/.test(token)) throw new ProbeReadError(401, 'authentication')
  }
  const response = await fetch(path, {
    method: 'GET', signal, headers: { Accept: 'application/json', ...(token === undefined ? {} : { Authorization: `Bearer ${token}` }) },
    credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
  })
  if (!response.ok) {
    cancel(response.body)
    throw new ProbeReadError(response.status, response.status === 401 ? 'authentication' : response.status === 403 ? 'forbidden' : 'unavailable')
  }
  if (response.redirected || (response.url && new URL(response.url).origin !== window.location.origin)) {
    cancel(response.body); throw new ProbeReadError(0, 'transport')
  }
  const limit = 1 << 20
  const length = response.headers.get('Content-Length')
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('Content-Type') ?? '') ||
      (length !== null && (!/^\d+$/.test(length) || Number(length) > limit)) || !response.body) {
    cancel(response.body); throw new ProbeReadError(0, 'format')
  }
  const reader = response.body.getReader()
  let size = 0, body = ''
  const decoder = new TextDecoder('utf-8', { fatal: true })
  try {
    while (true) {
      const chunk = await reader.read()
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
      if (chunk.done) break
      size += chunk.value.byteLength
      if (size > limit) throw new ProbeReadError(0, 'format')
      body += decoder.decode(chunk.value, { stream: true })
    }
    body += decoder.decode()
    return JSON.parse(body) as unknown
  } catch (error) {
    if (signal.aborted || error instanceof ProbeReadError) throw error
    throw new ProbeReadError(0, 'format')
  } finally {
    // A hostile cancellation promise must not keep rejection/loading pending.
    try { void reader.cancel().catch(() => {}) } catch { /* no raw errors */ }
    reader.releaseLock()
  }
}
export async function getProbeStatus(signal: AbortSignal): Promise<ProbeStatus> { return decodeProbeStatus(await read('/api/v1/probes/status', signal)) }
export async function getProbeDetails(token: string, signal: AbortSignal): Promise<ProbeDetails> { return decodeProbeDetails(await read('/api/v1/probes/details', signal, token)) }
