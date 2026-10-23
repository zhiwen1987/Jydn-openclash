import type { SubscriptionAccess, SubscriptionAction, SubscriptionCandidatePage, SubscriptionCode, SubscriptionIntent,
  SubscriptionIntentInput, SubscriptionKind, SubscriptionNodePage, SubscriptionPageQuery, SubscriptionReceipt,
  SubscriptionScope, SubscriptionSourcePage } from './subscription-types'

const BASE = '/api/v1/subscriptions'
const MAX_WIRE = 3 << 19
const MAX_INPUT = 1 << 20
const part = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/
const ids = { source: /^src_[a-f0-9]{32}$/, candidate: /^cand_[a-f0-9]{32}$/, command: /^cmd_[a-f0-9]{32}$/, node: /^node_[a-f0-9]{32}$/ }
const hmac = /^hmac-sha256:[a-f0-9]{64}$/
const hash = /^[a-f0-9]{64}$/
const kinds: SubscriptionKind[] = ['create', 'import', 'approve', 'fetch', 'decide', 'rollback']
const formats = ['mihomo-provider-yaml', 'uri-list', 'base64-uri-list']
const protocols = ['ss', 'vmess', 'vless', 'trojan', 'http', 'socks5']
const actions: SubscriptionAction[] = ['subscription.read', 'subscription.source.manage', 'subscription.import',
  'subscription.admission.decide', 'subscription.source.approve', 'subscription.fetch', 'subscription.rollback']
const codes: SubscriptionCode[] = ['subscription_command_invalid', 'subscription_forbidden', 'subscription_writes_disabled',
  'subscription_unavailable', 'subscription_command_conflict', 'subscription_command_not_found', 'subscription_audit_degraded',
  'subscription_commit_unknown', 'subscription_command_canceled', 'subscription_approval_required', 'subscription_command_limit']
type FailureKind = 'transport' | 'authentication' | 'forbidden' | 'locked' | 'conflict' | 'limit' | 'unavailable' | 'format' | 'canceled'
export class SubscriptionAPIError extends Error {
  constructor(readonly status: number, readonly kind: FailureKind, readonly stateMayHaveChanged = false,
    readonly commandId?: string, readonly code?: SubscriptionCode) { super(kind) }
}
function need(v: unknown): asserts v { if (!v) throw new SubscriptionAPIError(0, 'format') }
type Obj = Record<string, unknown>
function obj(v: unknown): Obj { need(v !== null && typeof v === 'object' && !Array.isArray(v)); return v as Obj }
function exact(v: Obj, required: string[], optional: string[] = []) {
  need(required.every(k => Object.hasOwn(v, k)) && Object.keys(v).every(k => required.includes(k) || optional.includes(k)))
}
function int(v: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): v is number { return Number.isSafeInteger(v) && Number(v) >= min && Number(v) <= max }
function match(v: unknown, re: RegExp): v is string { return typeof v === 'string' && re.test(v) }
function date(v: unknown, zero = false): v is string {
  return typeof v === 'string' && v.length <= 40 && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) &&
    Number.isFinite(Date.parse(v)) && new Date(v).toISOString().slice(0, 19) === v.slice(0, 19) && (zero || !v.startsWith('0001-'))
}
function label(v: unknown): boolean {
  return typeof v === 'string' && new TextEncoder().encode(v).length <= 128 && v.length > 0 && v.trim() === v && /^[\p{L}\p{Nd} ._-]+$/u.test(v)
}
function scope(v: unknown): SubscriptionScope {
  const s = obj(v); exact(s, ['tenantId', 'siteId', 'environment']); need(Object.values(s).every(x => match(x, part)))
  return s as SubscriptionScope
}
export function sameSubscriptionScope(a: SubscriptionScope, b: SubscriptionScope) { return a.tenantId === b.tenantId && a.siteId === b.siteId && a.environment === b.environment }

// Small independent parser: no JSON.parse of the unbounded document and no
// duplicate-key loss. String tokens alone are decoded after byte/depth bounds.
function strictJSON(text: string): unknown {
  let at = 0, nodes = 0
  const ws = () => { while (/[\x20\t\r\n]/.test(text[at] ?? '') && at < text.length) at++ }
  const string = (): string => {
    need(text[at] === '"'); const start = at++
    while (at < text.length) {
      const c = text[at++]
      if (c === '"') {
        const value: unknown = JSON.parse(text.slice(start, at)); need(typeof value === 'string')
        for (let i = 0; i < value.length; i++) {
          const n = value.charCodeAt(i)
          if (n >= 0xd800 && n <= 0xdbff) { const next = value.charCodeAt(++i); need(next >= 0xdc00 && next <= 0xdfff) }
          else need(n < 0xdc00 || n > 0xdfff)
        }
        return value
      }
      need(c >= ' ')
      if (c === '\\') { need(at < text.length); at++ }
    }
    throw new SubscriptionAPIError(0, 'format')
  }
  const read = (depth: number): unknown => {
    need(depth <= 16 && ++nodes <= 16384); ws(); const c = text[at]
    if (c === '"') return string()
    if (c === '{') {
      at++; ws(); const value: Obj = Object.create(null)
      if (text[at] === '}') { at++; return value }
      while (at < text.length) {
        ws(); const key = string(); need(!Object.hasOwn(value, key)); ws(); need(text[at++] === ':'); value[key] = read(depth + 1); ws()
        const end = text[at++]; if (end === '}') return value; need(end === ',')
      }
    } else if (c === '[') {
      at++; ws(); const value: unknown[] = []
      if (text[at] === ']') { at++; return value }
      while (at < text.length) { value.push(read(depth + 1)); ws(); const end = text[at++]; if (end === ']') return value; need(end === ',') }
    } else {
      for (const [literal, value] of [['true', true], ['false', false], ['null', null]] as const) {
        if (text.startsWith(literal, at)) { at += literal.length; return value }
      }
      const number = /^(?:0|[1-9][0-9]*)/.exec(text.slice(at)); need(number); at += number[0].length
      const value = Number(number[0]); need(int(value)); return value
    }
    throw new SubscriptionAPIError(0, 'format')
  }
  const value = read(0); ws(); need(at === text.length); return value
}

function cancel(body: ReadableStream<Uint8Array> | null) { try { void body?.cancel().catch(() => {}) } catch { /* Never retain upstream data. */ } }
async function readBody(response: Response, signal: AbortSignal): Promise<unknown> {
  const length = response.headers.get('Content-Length')
  need(/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('Content-Type') ?? ''))
  need(length === null || /^(0|[1-9][0-9]*)$/.test(length) && int(Number(length), 1, MAX_WIRE))
  need(response.body); const reader = response.body.getReader(); const decoder = new TextDecoder('utf-8', { fatal: true })
  let bytes = 0, text = '', stop: (() => void) | undefined
  const aborted = new Promise<never>((_, reject) => {
    stop = () => { try { void reader.cancel().catch(() => {}) } catch { /* No wait on hostile stream. */ } reject(new SubscriptionAPIError(0, 'canceled')) }
    signal.addEventListener('abort', stop, { once: true })
  })
  try {
    if (signal.aborted) throw new SubscriptionAPIError(0, 'canceled')
    for (;;) {
      const chunk = await Promise.race([reader.read(), aborted]); if (chunk.done) break
      need(chunk.value instanceof Uint8Array); bytes += chunk.value.byteLength; need(bytes <= MAX_WIRE)
      text += decoder.decode(chunk.value, { stream: true })
    }
    text += decoder.decode()
    if (signal.aborted) throw new SubscriptionAPIError(0, 'canceled')
    need(bytes > 0 && (length === null || bytes === Number(length)))
    return strictJSON(text)
  } finally {
    if (stop) signal.removeEventListener('abort', stop)
    try { void reader.cancel().catch(() => {}) } catch { /* Preserve fixed failure. */ }
    reader.releaseLock()
  }
}
function secure(token: string, signal: AbortSignal) {
  let origin: URL
  try { origin = new URL(window.location.origin) } catch { throw new SubscriptionAPIError(426, 'transport') }
  if (window.location.protocol !== 'https:' || origin.protocol !== 'https:' || origin.username || origin.password) throw new SubscriptionAPIError(426, 'transport')
  if (typeof token !== 'string' || !token || token.length > 4096 || !/^[\x21-\x2b\x2d-\x7e]+$/.test(token)) throw new SubscriptionAPIError(401, 'authentication')
  need(signal && typeof signal.aborted === 'boolean' && typeof signal.addEventListener === 'function')
  if (signal.aborted) throw new SubscriptionAPIError(0, 'canceled')
  return origin.origin
}
function errorKind(code: SubscriptionCode, status: number): FailureKind {
  if (status === 401) return 'authentication'
  if (status === 426) return 'transport'
  if (code === 'subscription_forbidden') return 'forbidden'
  if (code === 'subscription_writes_disabled') return 'locked'
  if (code === 'subscription_command_conflict' || code === 'subscription_approval_required') return 'conflict'
  if (code === 'subscription_command_limit') return 'limit'
  if (code === 'subscription_command_invalid') return 'format'
  if (code === 'subscription_command_canceled') return 'canceled'
  return 'unavailable'
}
function errorStatus(code: SubscriptionCode, status: number) {
  const expected = { subscription_command_invalid: [400, 405, 413], subscription_forbidden: [401, 403, 426], subscription_writes_disabled: [423],
    subscription_command_conflict: [409], subscription_approval_required: [409], subscription_command_limit: [429], subscription_command_not_found: [404],
    subscription_unavailable: [503], subscription_audit_degraded: [503], subscription_commit_unknown: [503], subscription_command_canceled: [503] }
  return expected[code].includes(status)
}
async function request<T>(path: string, token: string, signal: AbortSignal, decode: (v: unknown) => T, body?: string, key?: string): Promise<T> {
  const origin = secure(token, signal); const write = body !== undefined
  const controller = new AbortController()
  const forwardAbort = () => controller.abort()
  const timer = setTimeout(forwardAbort, 30000)
  signal.addEventListener('abort', forwardAbort, { once: true })
  let interrupted: (() => void) | undefined
  const aborted = new Promise<never>((_, reject) => {
    interrupted = () => reject(new SubscriptionAPIError(0, 'canceled'))
    controller.signal.addEventListener('abort', interrupted, { once: true })
  })
  let attempted = false, response: Response | undefined, commandId: string | undefined
  try {
    if (signal.aborted) controller.abort()
    if (controller.signal.aborted) throw new SubscriptionAPIError(0, 'canceled')
    attempted = true
    const pending = fetch(path, { method: write ? 'POST' : 'GET', signal: controller.signal, mode: 'same-origin', credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
      headers: { Accept: 'application/json', Authorization: `Bearer ${token}`, ...(write ? { 'Content-Type': 'application/json', 'Idempotency-Key': key! } : {}) }, ...(write ? { body } : {}) })
    // Even an adapter that ignores abort cannot keep the caller waiting. Never
    // publish a late response, and dispose of its stream without awaiting it.
    void pending.then(late => { if (controller.signal.aborted) cancel(late.body) }, () => {})
    response = await Promise.race([pending, aborted])
    need(!response.redirected)
    if (response.url) { const actual = new URL(response.url); need(actual.origin === origin && actual.pathname + actual.search === path && !actual.hash && !actual.username && !actual.password) }
    const header = response.headers.get('X-Chengwang-Command-ID'); need(header === null || match(header, ids.command))
    commandId = header ?? undefined
    const envelope = obj(await readBody(response, controller.signal))
    exact(envelope, ['boundary', 'authorization', 'deviceActionsExecuted', 'stateMayHaveChanged'], ['code', 'result'])
    need(envelope.boundary === 'LOCAL_SUBSCRIPTION_ADMISSION_ONLY' && envelope.authorization === 'BLOCKED' && envelope.deviceActionsExecuted === false && typeof envelope.stateMayHaveChanged === 'boolean')
    if (response.status !== 200) {
      need(!Object.hasOwn(envelope, 'result') && match(envelope.code, /./) && codes.includes(envelope.code as SubscriptionCode))
      const code = envelope.code as SubscriptionCode; need(errorStatus(code, response.status))
      need(code !== 'subscription_commit_unknown' || envelope.stateMayHaveChanged === true)
      throw new SubscriptionAPIError(response.status, errorKind(code, response.status), envelope.stateMayHaveChanged, header ?? undefined, code)
    }
    need(header === null && !Object.hasOwn(envelope, 'code') && Object.hasOwn(envelope, 'result'))
    const value = decode(envelope.result)
    const receipt = value as SubscriptionReceipt
    need(envelope.stateMayHaveChanged === (typeof receipt.stateMayHaveChanged === 'boolean' ? receipt.stateMayHaveChanged : false))
    return value
  } catch (error) {
    cancel(response?.body ?? null)
    if (error instanceof SubscriptionAPIError) {
      // An invalid/unreadable response after a POST is not evidence of zero mutation.
      if (write && attempted && !error.code) throw new SubscriptionAPIError(error.status, error.kind, true, error.commandId ?? commandId)
      throw error
    }
    throw new SubscriptionAPIError(0, controller.signal.aborted ? 'canceled' : response ? 'format' : 'transport', write && attempted, commandId)
  } finally {
    clearTimeout(timer)
    signal.removeEventListener('abort', forwardAbort)
    if (interrupted) controller.signal.removeEventListener('abort', interrupted)
  }
}

function access(raw: unknown, sourceId?: string): SubscriptionAccess {
  const v = obj(raw); exact(v, ['scope', 'resource', 'writesEnabled', 'actions', 'policyState', 'references']); scope(v.scope)
  const r = obj(v.resource); exact(r, ['type', 'id'])
  need(r.type === (sourceId ? 'subscription-source' : 'subscription-store') && (sourceId ? r.id === sourceId : match(r.id, part)))
  need(typeof v.writesEnabled === 'boolean' && Array.isArray(v.actions) && v.actions.length <= actions.length && new Set(v.actions).size === v.actions.length && v.actions.every(x => actions.includes(x)))
  const allowed = v.actions
  need(allowed[0] === 'subscription.read')
  need(allowed.every((x, index) => index === 0 || actions.indexOf(allowed[index - 1]) < actions.indexOf(x)))
  need(allowed.every(x => sourceId ? x !== 'subscription.source.manage' : x === 'subscription.read' || x === 'subscription.source.manage'))
  need(['ready', 'not_configured', 'unavailable'].includes(String(v.policyState)) && Array.isArray(v.references) && v.references.length <= 32)
  let previous = ''
  for (const raw of v.references) { const ref = obj(raw); exact(ref, ['referenceId', 'revision']); need(match(ref.referenceId, part) && int(ref.revision, 1) && previous < ref.referenceId); previous = ref.referenceId }
  need(v.policyState === 'ready' ? v.references.length > 0 : v.references.length === 0)
  return v as SubscriptionAccess
}
function sources(raw: unknown): SubscriptionSourcePage {
  const v = obj(raw); exact(v, ['sources', 'total']); need(Array.isArray(v.sources) && int(v.total, 0, 32) && v.sources.length === v.total)
  const seen = new Set<string>(); let common: SubscriptionScope | undefined
  for (const raw of v.sources) {
    const s = obj(raw); exact(s, ['id', 'scope', 'label', 'revision', 'updatedAt'], ['acceptedCandidateId', 'latestCandidateId'])
    const current = scope(s.scope); need(!common || sameSubscriptionScope(common, current)); common = current
    need(match(s.id, ids.source) && !seen.has(s.id) && label(s.label) && int(s.revision, 1) && date(s.updatedAt)); seen.add(s.id)
    for (const key of ['acceptedCandidateId', 'latestCandidateId']) need(s[key] === undefined || match(s[key], ids.candidate))
  }
  return v as SubscriptionSourcePage
}
function query(q: SubscriptionPageQuery): string {
  const v = obj(q); exact(v, ['limit', 'offset'], ['revision']); need(int(q.limit, 1, 100) && int(q.offset, 0, 1024) && (q.revision === undefined || int(q.revision, 1)) && (q.offset === 0 || q.revision !== undefined))
  return `?limit=${q.limit}&offset=${q.offset}${q.revision === undefined ? '' : `&revision=${q.revision}`}`
}
function page(v: Obj, field: string, maximum: number, q: SubscriptionPageQuery) {
  exact(v, [field, 'total', 'revision'], ['nextOffset']); need(Array.isArray(v[field]) && int(v.total, 0, maximum) && int(v.revision, 1) && (!q.revision || v.revision === q.revision))
  const count = Math.min(q.limit, Math.max(0, v.total - q.offset)); need(v[field].length === count)
  need(q.offset + count < v.total ? v.nextOffset === q.offset + count : v.nextOffset === undefined)
}
function candidates(raw: unknown, sourceId: string, q: SubscriptionPageQuery): SubscriptionCandidatePage {
  const v = obj(raw); page(v, 'candidates', 64, q); const seen = new Set<string>()
  for (const raw of v.candidates as unknown[]) {
    const c = obj(raw); exact(c, ['id', 'sourceId', 'digest', 'format', 'state', 'baseRevision', 'nodeCount', 'duplicateCount', 'createdAt'])
    need(match(c.id, ids.candidate) && !seen.has(c.id) && c.sourceId === sourceId && match(c.digest, hmac) && formats.includes(String(c.format)) && ['quarantined', 'admitted_local', 'rejected'].includes(String(c.state)))
    need(int(c.baseRevision, 2, Number(v.revision)) && int(c.nodeCount, 1, 1024) && int(c.duplicateCount, 0, 1024 - c.nodeCount) && date(c.createdAt)); seen.add(c.id)
  }
  return v as SubscriptionCandidatePage
}
function nodes(raw: unknown, q: SubscriptionPageQuery): SubscriptionNodePage {
  const v = obj(raw); page(v, 'nodes', 1024, q); const seen = new Set<string>()
  for (const raw of v.nodes as unknown[]) {
    const n = obj(raw); exact(n, ['id', 'label', 'protocol', 'credentialConfigured', 'state'])
    need(match(n.id, ids.node) && !seen.has(n.id) && n.label === `节点-${n.id.slice(-8)}` && protocols.includes(String(n.protocol)) && typeof n.credentialConfigured === 'boolean' && n.state === 'unknown'); seen.add(n.id)
  }
  return v as SubscriptionNodePage
}
function receipt(raw: unknown): SubscriptionReceipt {
  const v = obj(raw); exact(v, ['commandId', 'kind', 'revision', 'state', 'replayed', 'stateMayHaveChanged', 'auditRecorded'],
    ['sourceId', 'candidateId', 'candidateDigest', 'code', 'preparedAuditHash', 'resultAuditHash', 'localAuditHash', 'referenceId', 'policyRevision', 'policyDigest', 'approvalId', 'completedAt'])
  need(match(v.commandId, ids.command) && kinds.includes(v.kind as SubscriptionKind) && int(v.revision) && ['prepared', 'committed', 'approved', 'noop', 'failed', 'unknown'].includes(String(v.state)))
  need(['replayed', 'stateMayHaveChanged', 'auditRecorded'].every(k => typeof v[k] === 'boolean'))
  for (const key of ['preparedAuditHash', 'resultAuditHash', 'localAuditHash']) need(v[key] === undefined || match(v[key], hash))
  for (const [key, re] of [['sourceId', ids.source], ['candidateId', ids.candidate], ['approvalId', ids.command], ['candidateDigest', hmac], ['policyDigest', hmac], ['referenceId', part]] as const) need(v[key] === undefined || match(v[key], re))
  need(v.policyRevision === undefined || int(v.policyRevision, 1)); need(v.code === undefined || codes.includes(v.code as SubscriptionCode)); need(v.completedAt === undefined || date(v.completedAt, true))
  if (v.auditRecorded) need(match(v.preparedAuditHash, hash) && match(v.resultAuditHash, hash))
  if (['committed', 'noop', 'approved'].includes(String(v.state))) {
    need(v.code === undefined && int(v.revision, 1) && match(v.sourceId, ids.source) && date(v.completedAt))
    need(v.state === 'committed' ? match(v.localAuditHash, hash) : v.localAuditHash === undefined)
  } else if (v.state === 'failed') need(v.code !== undefined && v.stateMayHaveChanged === false && date(v.completedAt))
  else need(v.code === 'subscription_commit_unknown' && v.stateMayHaveChanged === true)
  return v as SubscriptionReceipt
}

export function readSubscriptionAccess(token: string, signal: AbortSignal, sourceId?: string) {
  if (sourceId !== undefined) need(match(sourceId, ids.source))
  return request(`${BASE}${sourceId ? `/sources/${sourceId}` : ''}/access`, token, signal, v => access(v, sourceId))
}
export function readSubscriptionSources(token: string, signal: AbortSignal) { return request(`${BASE}/sources`, token, signal, sources) }
export function readSubscriptionCandidates(token: string, signal: AbortSignal, sourceId: string, q: SubscriptionPageQuery) {
  need(match(sourceId, ids.source)); const frozen = { ...q }; const path = `${BASE}/sources/${sourceId}/candidates${query(frozen)}`
  return request(path, token, signal, v => candidates(v, sourceId, frozen))
}
export function readSubscriptionNodes(token: string, signal: AbortSignal, sourceId: string, candidateId: string, q: SubscriptionPageQuery) {
  need(match(sourceId, ids.source) && match(candidateId, ids.candidate)); const frozen = { ...q }
  return request(`${BASE}/sources/${sourceId}/candidates/${candidateId}/nodes${query(frozen)}`, token, signal, v => nodes(v, frozen))
}
export function readSubscriptionReceipt(token: string, signal: AbortSignal, commandId: string) {
  need(match(commandId, ids.command)); return request(`${BASE}/commands/${commandId}`, token, signal, v => { const r = receipt(v); need(r.commandId === commandId); return r })
}

const intents = new WeakMap<object, { path: string; body: Obj; content?: Uint8Array; released: boolean }>()
export function createSubscriptionIntent(input: SubscriptionIntentInput): SubscriptionIntent {
  const v = obj(input); need(kinds.includes(v.kind as SubscriptionKind)); const kind = v.kind as SubscriptionKind
  const fields = { create: ['label'], import: ['expectedRevision', 'format', 'content'], approve: ['expectedRevision', 'referenceId', 'policyRevision'],
    fetch: ['expectedRevision', 'approvalId', 'policyRevision'], decide: ['expectedRevision', 'candidateId', 'expectedDigest', 'decision'], rollback: ['expectedRevision', 'candidateId'] }
  exact(v, ['kind', ...(kind === 'create' ? [] : ['sourceId']), ...fields[kind]])
  if (kind === 'create') need(label(v.label))
  else need(match(v.sourceId, ids.source) && int(v.expectedRevision, 1))
  if (kind === 'approve' || kind === 'fetch') need(int(v.policyRevision, 1) && (kind === 'approve' ? match(v.referenceId, part) : match(v.approvalId, ids.command)))
  if (kind === 'decide' || kind === 'rollback') need(match(v.candidateId, ids.candidate))
  if (kind === 'decide') need(match(v.expectedDigest, hmac) && ['admitted_local', 'rejected'].includes(String(v.decision)))
  let content: Uint8Array | undefined
  if (kind === 'import') {
    need(['auto', ...formats].includes(String(v.format)) && v.content instanceof Uint8Array && v.content.byteLength > 0 && v.content.byteLength <= MAX_INPUT)
    content = v.content.slice()
  }
  const random = new Uint8Array(16)
  try { globalThis.crypto.getRandomValues(random) } catch { throw new SubscriptionAPIError(0, 'unavailable') }
  const key = `sub_${Array.from(random, x => x.toString(16).padStart(2, '0')).join('')}`
  const metadata: Obj = { ...v, idempotencyKey: key }; delete metadata.content
  const intent = Object.freeze(metadata) as SubscriptionIntent
  const body: Obj = {}; for (const field of fields[kind]) if (field !== 'content') body[field] = v[field]
  const suffix = { create: '', import: '/candidates', approve: '/approvals', fetch: '/fetches', decide: '/decisions', rollback: '/rollbacks' }[kind]
  intents.set(intent, { path: `${BASE}/sources${kind === 'create' ? '' : `/${v.sourceId}`}${suffix}`, body, content, released: false })
  return intent
}
export function releaseSubscriptionIntent(intent: SubscriptionIntent) { const data = intents.get(intent); if (data) { data.content?.fill(0); data.content = undefined; data.released = true; intents.delete(intent) } }
function base64(bytes: Uint8Array) { let text = ''; for (let at = 0; at < bytes.length; at += 8192) text += String.fromCharCode(...bytes.subarray(at, at + 8192)); return btoa(text) }
export function writeSubscriptionCommand(token: string, signal: AbortSignal, intent: SubscriptionIntent): Promise<SubscriptionReceipt> {
  const data = intents.get(intent); need(data && !data.released && Object.isFrozen(intent))
  const body = JSON.stringify({ ...data.body, ...(data.content ? { contentBase64: base64(data.content) } : {}) }); need(new TextEncoder().encode(body).length <= MAX_WIRE)
  return request(data.path, token, signal, v => {
    const r = receipt(v); need(r.kind === intent.kind && (!('sourceId' in intent) || r.sourceId === intent.sourceId) && !r.code && r.auditRecorded && !r.stateMayHaveChanged && ['committed', 'noop', 'approved'].includes(r.state))
    // Correlate the immutable historical receipt, never the latest SourceView.
    if (intent.kind === 'create') need(r.state === 'committed' && r.revision === 1 && r.candidateId === undefined && r.candidateDigest === undefined)
    else if (intent.kind === 'approve') {
      need(r.state === 'approved' && r.revision === intent.expectedRevision && r.approvalId === r.commandId &&
        r.referenceId === intent.referenceId && r.policyRevision === intent.policyRevision && match(r.policyDigest, hmac) &&
        r.candidateId === undefined && r.candidateDigest === undefined)
    } else {
      need(match(r.candidateId, ids.candidate) && match(r.candidateDigest, hmac))
      if (intent.kind === 'import' || intent.kind === 'fetch') need(r.state === 'committed' ? r.revision === intent.expectedRevision + 1 : r.state === 'noop' && r.revision === intent.expectedRevision)
      else {
        need(r.state === 'committed' && r.revision === intent.expectedRevision + 1 && r.candidateId === intent.candidateId)
        if (intent.kind === 'decide') need(r.candidateDigest === intent.expectedDigest)
      }
    }
    return r
  }, body, intent.idempotencyKey)
}
