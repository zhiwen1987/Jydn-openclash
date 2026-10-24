// Passive CI metadata only. No I/O on import; never intercepts or sends requests.
import { readFileSync, writeSync } from 'node:fs'
import { probeBindingHeader, createBindingDiagnosticSink } from './probe-request-binding.mjs'

export const LIFECYCLE_PREFIX = 'CW_STATUS_NET:'
export const LIFECYCLE_FD_ENV = 'CHENGWANG_PROBE_LIFECYCLE_FD'
export const LIFECYCLE_EVENTS = Object.freeze(['Network.requestWillBeSent', 'Network.responseReceived',
  'Network.responseReceivedExtraInfo', 'Network.dataReceived', 'Network.loadingFinished', 'Network.loadingFailed',
  'Page.frameNavigated', 'Page.frameDetached', 'Runtime.executionContextCreated',
  'Runtime.executionContextDestroyed', 'Runtime.executionContextsCleared'])
const ORIGIN = 'https://127.0.0.1:17861', STATUS = ORIGIN + '/api/v1/probes/status'
const own = (v, k) => v && typeof v === 'object' ? Object.getOwnPropertyDescriptor(v, k)?.value : undefined
const int = (v, min = 0, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(v) && v >= min && v <= max
const id = v => typeof v === 'string' && v.length > 0 && v.length <= 256
const us = v => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= Number.MAX_SAFE_INTEGER / 1e6 ? Math.floor(v * 1e6) : null
const tri = v => v === true ? 'YES' : v === false ? 'NO' : 'NOT_OBSERVED'
const fail = () => { throw new Error('status network metadata rejected') }
const INVALID_EXTRA = Symbol('invalid bounded extra projection')

// Unassociated events may belong to assets/protected APIs or redirects. Retain
// only closed metadata (or a private sentinel), and defer rejection until the
// original request is identified as an anonymous status request. No raw header
// object, URL, error or protocol ID is written to the public evidence stream.
function safeExtraInfo(params, maximumFields) {
  try {
    const status = own(params, 'statusCode'), headers = own(params, 'headers')
    if (!int(status, 100, 599) || !headers || typeof headers !== 'object' || Array.isArray(headers)
      || Object.keys(headers).length > maximumFields) return INVALID_EXTRA
    const projected = framing(headers)
    return projected === null ? INVALID_EXTRA : { status, framing: projected }
  } catch { return INVALID_EXTRA }
}

export function loadLifecycleContract() {
  const raw = readFileSync(new URL('../../deploy/probe-readback/status-network-lifecycle-contract.json', import.meta.url))
  if (raw.length > 16384) fail()
  const c = JSON.parse(raw.toString('utf8'))
  if (c.schema !== 'chengwang.status-network-lifecycle-contract/v1' || c.maxRequests !== 7 || c.maxContexts !== 16
    || c.maxRows !== 128 || c.maxLineBytes !== 4096 || c.maxBytes !== 131072 || c.maxBodyBytes !== 1048576
    || ![c.protocols, c.blockedReasons, c.corsReasons].every(a => Array.isArray(a) && a.length <= 64
      && a.every(v => typeof v === 'string' && /^[A-Za-z0-9_./-]{1,100}$/.test(v)) && new Set(a).size === a.length)) fail()
  return c
}
export function createLifecycleSink(environment = process.env, write = writeSync) {
  return createBindingDiagnosticSink({ CHENGWANG_PROBE_BINDING_FD: own(environment, LIFECYCLE_FD_ENV) }, write)
}

// No coercion/getters/toJSON, raw headers, URL, cookies, nonce or protocol IDs survive.
export function framing(headers) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return null
  const out = {}
  for (const [name, field, values] of [['content-length', 'length', null],
    ['transfer-encoding', 'transfer', ['chunked', 'identity']], ['content-encoding', 'encoding', ['gzip', 'br', 'deflate', 'identity']],
    ['connection', 'connection', ['close', 'keep-alive']]]) {
    const keys = Object.keys(headers).filter(k => k.toLowerCase() === name)
    if (!keys.length) { out[field] = null; continue }
    if (keys.length !== 1) { out[field] = 'CONFLICT'; continue }
    const v = own(headers, keys[0])
    out[field] = name === 'content-length'
      ? typeof v === 'string' && /^(0|[1-9][0-9]{0,6})$/.test(v) && Number(v) <= 1048576 ? Number(v) : 'INVALID'
      : typeof v === 'string' && values.includes(v.toLowerCase()) ? v.toLowerCase() : 'UNKNOWN'
  }
  return out
}

export class StatusNetworkLifecycle {
  constructor(session, write = () => {}) {
    if (!(id(session) || (session !== null && typeof session === 'object')) || typeof write !== 'function') fail()
    this.contract = loadLifecycleContract(); this.session = session; this.write = write
    this.requests = new Map(); this.keys = new Set(); this.connections = new Map(); this.contexts = new Map()
    // Reuse the frozen limits: <=7 unassociated projections, <=128 ignored
    // non-status IDs. These private slots are not additional accepted targets.
    this.pendingExtras = new Map(); this.otherRequests = new Set()
    this.frame = null; this.phase = 'RUNNING'; this.sequence = 0; this.bytes = 0; this.contextEvents = 0
    this.rejected = 0; this.overflow = false; this.closed = false; this.sinkFailed = false
    this.emit('SESSION', {})
  }
  reject() { this.rejected = Math.min(128, this.rejected + 1) }
  emit(e, fields) {
    if (this.closed || this.sinkFailed) return
    const line = LIFECYCLE_PREFIX + JSON.stringify({ v: 1, e, q: this.sequence + 1, s: 1, ...fields }) + '\n'
    if (this.sequence >= this.contract.maxRows || Buffer.byteLength(line) > this.contract.maxLineBytes
      || this.bytes + Buffer.byteLength(line) > this.contract.maxBytes || !/^[\x20-\x7e]+\n$/.test(line)) { this.overflow = true; return }
    try { this.write(line); this.sequence++; this.bytes += Buffer.byteLength(line) }
    catch { this.sinkFailed = true; this.reject() }
  }
  context(k, c = null) {
    if (this.contextEvents >= 64) { this.overflow = true; return }
    this.contextEvents++; this.emit('CONTEXT', { k, c, phase: this.phase })
  }
  beginClosing() { this.phase = 'CLOSING' }
  handle(method, p, session) {
    if (this.closed) return
    if (session !== this.session) { this.reject(); return }
    try { this.observe(method, p) } catch { this.reject() }
  }
  observe(method, p) {
    if (method === 'Page.frameNavigated') {
      const f = own(p, 'frame')
      if (own(f, 'url') === 'about:blank') return
      if (own(f, 'url') !== ORIGIN + '/' || own(f, 'parentId') !== undefined || !id(own(f, 'id'))) { this.reject(); return }
      this.context(this.frame === null ? 'DOCUMENT' : 'DOCUMENT_CHANGED'); this.frame = own(f, 'id'); return
    }
    if (method === 'Page.frameDetached') {
      if (own(p, 'frameId') === this.frame && this.frame !== null) this.context('FRAME_DETACHED')
      return
    }
    if (method === 'Runtime.executionContextCreated') {
      const c = own(p, 'context'), aux = own(c, 'auxData'), key = own(c, 'id')
      if (own(c, 'origin') !== ORIGIN || own(aux, 'isDefault') !== true) return
      if (!int(key, 1) || !id(own(aux, 'frameId')) || this.contexts.has(key)) { this.reject(); return }
      if (this.contexts.size >= this.contract.maxContexts) { this.overflow = true; return }
      this.contexts.set(key, { c: this.contexts.size + 1, frame: own(aux, 'frameId'), active: true })
      this.context('DEFAULT_CREATED', this.contexts.get(key).c); return
    }
    if (method === 'Runtime.executionContextDestroyed') {
      const c = this.contexts.get(own(p, 'executionContextId'))
      if (c?.active) { c.active = false; this.context('DEFAULT_DESTROYED', c.c) }
      return
    }
    if (method === 'Runtime.executionContextsCleared') {
      for (const c of this.contexts.values()) c.active = false
      this.context('CONTEXTS_CLEARED'); return
    }
    if (method === 'Network.requestWillBeSent') {
      const r = own(p, 'request')
      if (own(r, 'url') !== STATUS) {
        const key = own(p, 'requestId')
        if (!id(key) || typeof own(r, 'url') !== 'string') return
        if (this.requests.has(key)) { this.reject(); return }
        this.pendingExtras.delete(key)
        if (!this.otherRequests.has(key)) {
          if (this.otherRequests.size >= this.contract.maxRows) { this.overflow = true; return }
          this.otherRequests.add(key)
        }
        return
      }
      const headers = own(r, 'headers'), b = probeBindingHeader(headers), key = own(p, 'requestId'), x = us(own(p, 'timestamp'))
      if (!b || own(r, 'method') !== 'GET' || !id(key) || this.requests.has(key) || this.otherRequests.has(key) || x === null || this.frame === null
        || own(p, 'frameId') !== this.frame || own(p, 'redirectResponse') !== undefined
        || Object.keys(headers).some(k => ['authorization', 'cookie', 'proxy-authorization', 'proxy-connection'].includes(k.toLowerCase()))) { this.reject(); return }
      const identity = `${b.doc}:${b.m}:${b.r}`
      if (this.keys.has(identity)) { this.reject(); return }
      if (this.requests.size >= this.contract.maxRequests) { this.overflow = true; return }
      this.keys.add(identity); this.requests.set(key, { n: this.requests.size + 1, m: b.m, r: b.r, startUs: x,
        responseUs: null, endUs: null, response: null, extra: null, chunks: null, dataBytes: null, encodedBytes: null,
        terminal: 'MISSING', canceled: null, error: null, blocked: null, cors: null, hasExtra: 'NOT_OBSERVED' })
      if (this.pendingExtras.has(key)) {
        const extra = this.pendingExtras.get(key); this.pendingExtras.delete(key)
        if (extra === INVALID_EXTRA) this.reject()
        else this.requests.get(key).extra = extra
      }
      return
    }
    if (method === 'Network.responseReceivedExtraInfo') {
      const key = own(p, 'requestId')
      if (!id(key)) { this.reject(); return }
      if (this.otherRequests.has(key)) return
      const request = this.requests.get(key)
      if (request) {
        if (request.extra !== null) { this.reject(); return }
        const extra = safeExtraInfo(p, this.contract.maxRows)
        if (extra === INVALID_EXTRA) this.reject()
        else request.extra = extra
      } else if (this.pendingExtras.has(key)) {
        // An unknown duplicate may be a normal non-target redirect. Do not
        // overwrite it or reject globally before its request is classified.
        this.pendingExtras.set(key, INVALID_EXTRA)
      } else if (this.pendingExtras.size >= this.contract.maxRequests) this.overflow = true
      else this.pendingExtras.set(key, safeExtraInfo(p, this.contract.maxRows))
      return
    }
    const r = this.requests.get(own(p, 'requestId'))
    if (!r) return
    if (!['Network.responseReceived', 'Network.dataReceived', 'Network.loadingFinished', 'Network.loadingFailed'].includes(method)) return
    const x = us(own(p, 'timestamp'))
    if (x === null || x < r.startUs || r.terminal !== 'MISSING') { this.reject(); return }
    if (method === 'Network.responseReceived') {
      const v = own(p, 'response'), st = own(v, 'status'), h = framing(own(v, 'headers'))
      if (r.response !== null || own(v, 'url') !== STATUS || !int(st, 100, 599) || h === null) { this.reject(); return }
      const connection = own(v, 'connectionId')
      let alias = null
      if (typeof connection === 'number' && Number.isFinite(connection) && connection >= 0) {
        if (!this.connections.has(connection)) this.connections.set(connection, this.connections.size + 1)
        alias = this.connections.get(connection)
      }
      const protocol = own(v, 'protocol')
      r.responseUs = x; r.hasExtra = tri(own(p, 'hasExtraInfo'))
      r.response = { status: st, protocol: this.contract.protocols.includes(protocol) ? protocol : 'UNKNOWN',
        connection: alias, reused: tri(own(v, 'connectionReused')), diskCache: tri(own(v, 'fromDiskCache')),
        serviceWorker: tri(own(v, 'fromServiceWorker')), prefetchCache: tri(own(v, 'fromPrefetchCache')), framing: h }; return
    }
    if (method === 'Network.dataReceived') {
      const d = own(p, 'dataLength'), e = own(p, 'encodedDataLength')
      if (!int(d, 0, this.contract.maxBodyBytes) || !int(e, 0, this.contract.maxBodyBytes)
        || (r.dataBytes ?? 0) + d > this.contract.maxBodyBytes || (r.encodedBytes ?? 0) + e > this.contract.maxBodyBytes
        || (r.chunks ?? 0) >= 1024) { this.overflow = true; return }
      r.chunks = (r.chunks ?? 0) + 1; r.dataBytes = (r.dataBytes ?? 0) + d; r.encodedBytes = (r.encodedBytes ?? 0) + e; return
    }
    r.endUs = x; r.terminal = method === 'Network.loadingFinished' ? 'FINISHED' : 'FAILED'
    if (r.terminal === 'FAILED') {
      const error = own(p, 'errorText'), blocked = own(p, 'blockedReason'), cors = own(own(p, 'corsErrorStatus'), 'corsError')
      r.canceled = tri(own(p, 'canceled')); r.error = error === 'net::ERR_ABORTED' ? 'ABORTED' : typeof error === 'string' ? 'OTHER' : 'NOT_OBSERVED'
      r.blocked = blocked === undefined ? null : this.contract.blockedReasons.includes(blocked) ? blocked : 'UNKNOWN'
      r.cors = cors === undefined ? null : this.contract.corsReasons.includes(cors) ? cors : 'UNKNOWN'
    }
  }
  finish() {
    if (this.closed) return
    // Unclassified or duplicate unknown events are not silently dropped as
    // complete. No retry, drain command, timeout or active waiting is added.
    for (let count = this.pendingExtras.size; count > 0; count--) this.reject()
    this.pendingExtras.clear()
    for (const r of this.requests.values()) this.emit('REQUEST', r)
    this.emit('META', { requests: this.requests.size, contexts: this.contextEvents,
      rejected: this.rejected, overflow: this.overflow, sinkFailed: this.sinkFailed })
    this.closed = true
  }
}
