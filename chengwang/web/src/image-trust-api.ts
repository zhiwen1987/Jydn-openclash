import type { ImageTrustHistory, ImageTrustHistoryPage, ImageTrustReadOptions, ImageTrustStatus } from './image-trust-types'

const MAX_RESPONSE_BYTES = 1 << 20
const MAX_POLICIES = 4096

export class ImageTrustReadError extends Error {
  constructor(public readonly status: number, public readonly classification: 'transport' | 'authentication' | 'forbidden' | 'conflict' | 'unavailable' | 'format') {
    // Never carry server body, URL, header or bearer credential in error text.
    super(classification)
  }
}

function loopback(host: string): boolean {
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]'
}

function endpoint(path: string, baseUrl: string): string {
  const page = new URL(window.location.href)
  if (page.protocol !== 'https:' && !(page.protocol === 'http:' && loopback(page.hostname))) throw new ImageTrustReadError(426, 'transport')
  let target: URL
  try {
    target = baseUrl ? new URL(baseUrl) : new URL(page.origin)
  } catch { throw new ImageTrustReadError(426, 'transport') }
  // Fixed origin only: never accept credentials, query, fragments or a path prefix.
  if (target.origin !== page.origin || target.username || target.password || target.search || target.hash || target.pathname !== '/' ||
    (target.protocol !== 'https:' && !(target.protocol === 'http:' && loopback(target.hostname)))) throw new ImageTrustReadError(426, 'transport')
  return baseUrl ? `${target.origin}${path}` : path
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ImageTrustReadError(0, 'format')
  return value as Record<string, unknown>
}
function integer(value: unknown, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max
}
function text(value: unknown, max = 256): value is string {
  return typeof value === 'string' && value.length <= max && [...value].every(ch => ch.charCodeAt(0) >= 32 && ch.charCodeAt(0) !== 127)
}
function hash(value: unknown, empty = false): boolean {
  return typeof value === 'string' && ((empty && value === '') || /^[a-f0-9]{64}$/.test(value))
}
function digest(value: unknown, empty = false): boolean {
  return typeof value === 'string' && ((empty && value === '') || /^sha256:[a-f0-9]{64}$/.test(value))
}
function ensure(condition: boolean): asserts condition {
  if (!condition) throw new ImageTrustReadError(0, 'format')
}
function boundary(v: Record<string, unknown>, expected: string) {
  ensure(v.boundary === expected && v.authorization === 'BLOCKED' && v.deviceActionsExecuted === false)
}

export function decodeImageTrustStatus(value: unknown): ImageTrustStatus {
  const v = object(value)
  boundary(v, 'ADVISORY_TRUST_POLICY_STATE')
  for (const key of ['observedAtUnix', 'auditVerifiedAtUnix', 'generation', 'notAfterUnix', 'sequence', 'ledgerEntries', 'ledgerCapacity', 'reserved', 'consumed', 'revokedKeys', 'revokedApprovals', 'revokedManifests', 'refreshLastSuccessUnix', 'refreshUntilUnix', 'recoveryCompleted']) ensure(integer(v[key]))
  for (const key of ['healthy', 'fresh', 'refreshRequired', 'refreshFresh']) ensure(typeof v[key] === 'boolean')
  for (const key of ['observedAtUnix', 'auditVerifiedAtUnix', 'notAfterUnix', 'refreshLastSuccessUnix', 'refreshUntilUnix']) ensure(integer(v[key], 253402300799))
  ensure(typeof v.storeId === 'string' && /^[a-f0-9]{32}$/.test(v.storeId) && digest(v.catalogueSHA256))
  ensure(Array.isArray(v.policies) && v.policies.length <= MAX_POLICIES)
  for (const raw of v.policies) {
    const p = object(raw)
    ensure(text(p.policyId) && text(p.grantId) && integer(p.revision) && digest(p.manifestSHA256) && text(p.state, 64))
  }
  return v as unknown as ImageTrustStatus
}

export function decodeImageTrustHistory(value: unknown, requested: ImageTrustHistoryPage): ImageTrustHistory {
  const v = object(value)
  boundary(v, 'ADVISORY_TRUST_OPERATION_HISTORY')
  ensure(integer(v.observedAtUnix, 253402300799) && integer(v.sequence) && integer(v.total, 4096) && integer(v.offset, 4096) && integer(v.limit, 50))
  ensure(v.limit === requested.limit && v.offset === requested.offset && (requested.sequence === 0 || v.sequence === requested.sequence))
  ensure(Array.isArray(v.entries) && v.entries.length <= requested.limit && (v.entries.length === 0 || v.entries.length + Number(v.offset) <= Number(v.total)))
  for (const raw of v.entries) {
    const e = object(raw)
    for (const key of ['operationId', 'actorId', 'kind', 'state', 'outcome', 'policyId', 'grantId']) ensure(text(e[key]))
    ensure(integer(e.generation))
    for (const key of ['preparedAtUnix', 'resultAtUnix']) ensure(integer(e[key], 253402300799))
    ensure(typeof e.acknowledged === 'boolean' && digest(e.catalogueSHA256, true) && hash(e.preparedAuditHash, true) && hash(e.resultAuditHash, true))
  }
  return v as unknown as ImageTrustHistory
}

function rejectUnreadResponse(response: Response, error: ImageTrustReadError): never {
  // Only release this rejected response. Do not abort the shared request
  // signal: an independent status/history read may still be authorized.
  // A custom or stalled upstream cancellation must never hold the error open.
  try { void response.body?.cancel().catch(() => {}) } catch { /* Never expose cancellation details. */ }
  throw error
}

async function read(path: string, options: ImageTrustReadOptions): Promise<unknown> {
  const url = endpoint(path, options.baseUrl ?? '')
  if (!options.token || options.token.length > 4096 || !/^[\x21-\x2b\x2d-\x7e]+$/.test(options.token)) throw new ImageTrustReadError(401, 'authentication')
  let response: Response
  try {
    response = await (options.fetcher ?? fetch)(url, {
      method: 'GET', headers: { Accept: 'application/json', Authorization: `Bearer ${options.token}` },
      signal: options.signal, credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    })
  } catch {
    throw new ImageTrustReadError(0, 'unavailable')
  }
  if (!response.ok) {
    const classification = response.status === 401 ? 'authentication' : response.status === 403 ? 'forbidden' : response.status === 409 ? 'conflict' : 'unavailable'
    rejectUnreadResponse(response, new ImageTrustReadError(response.status, classification))
  }
  if (response.redirected || (response.url && new URL(response.url).origin !== window.location.origin)) rejectUnreadResponse(response, new ImageTrustReadError(0, 'transport'))
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('Content-Type') ?? '')) rejectUnreadResponse(response, new ImageTrustReadError(0, 'format'))
  const length = response.headers.get('Content-Length')
  if (length && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES)) rejectUnreadResponse(response, new ImageTrustReadError(0, 'format'))
  if (!response.body) throw new ImageTrustReadError(0, 'format')
  const reader = response.body.getReader()
  const decoder = new TextDecoder('utf-8', { fatal: true })
  let size = 0
  let body = ''
  try {
    while (true) {
      const chunk = await reader.read()
      if (chunk.done) break
      size += chunk.value.byteLength
      if (size > MAX_RESPONSE_BYTES) throw new ImageTrustReadError(0, 'format')
      body += decoder.decode(chunk.value, { stream: true })
    }
    body += decoder.decode()
    if (options.signal.aborted) throw new ImageTrustReadError(0, 'unavailable')
    return JSON.parse(body) as unknown
  } catch (error) {
    if (error instanceof ImageTrustReadError) throw error
    throw new ImageTrustReadError(0, 'format')
  } finally {
    try { await reader.cancel() } catch { /* No upstream error details exposed. */ }
    reader.releaseLock()
  }
}

export async function getImageTrustStatus(options: ImageTrustReadOptions): Promise<ImageTrustStatus> {
  return decodeImageTrustStatus(await read('/api/v1/image-trust', options))
}

export async function getImageTrustHistory(options: ImageTrustReadOptions, page: ImageTrustHistoryPage): Promise<ImageTrustHistory> {
  ensure(integer(page.limit, 50) && page.limit > 0 && integer(page.offset, 4096) && integer(page.sequence))
  return decodeImageTrustHistory(await read(`/api/v1/image-trust/history?limit=${page.limit}&offset=${page.offset}&sequence=${page.sequence}`, options), page)
}
