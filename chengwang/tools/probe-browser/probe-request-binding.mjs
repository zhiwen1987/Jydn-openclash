// CI-only, observational request identities. Never logs protocol IDs, headers,
// document nonces, bodies, errors, or credentials; never changes browser gates.
import { writeSync } from 'node:fs'
import { FRONT_PREFIX, parseStatusDiagnostic } from './probe-status-diagnostics.mjs'

export const BINDING_PREFIX = 'CW_PROBE_BIND:'
export const BINDING_DIAGNOSTIC_PREFIX = 'CW_PROBE_BIND_DIAG:'
const DOCUMENT = 'https://127.0.0.1:17861/'
const STATUS = DOCUMENT + 'api/v1/probes/status'
const own = (o, k) => o && typeof o === 'object' ? Object.getOwnPropertyDescriptor(o, k)?.value : undefined
const integer = (v, min = 0, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(v) && v >= min && v <= max
const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && Object.keys(v).sort().join(',') === [...keys].sort().join(',')
const us = v => typeof v === 'number' && Number.isFinite(v) && v >= 0
  && v <= Number.MAX_SAFE_INTEGER / 1000000 ? Math.floor(v * 1000000) : null
const validID = v => typeof v === 'string' && v.length > 0 && v.length <= 256
const deny = () => { throw new Error('probe binding rejected') }

export function parseBindingDiagnostic(value) {
  try {
    if (typeof value !== 'string' || Buffer.byteLength(value) > 512 || !/^[\x20-\x7e]+$/.test(value)
      || !value.startsWith(BINDING_PREFIX)) return null
    const raw = value.slice(BINDING_PREFIX.length), p = JSON.parse(raw)
    const extra = p?.e === 'SEND' ? [] : p?.e === 'CANCEL_RESULT' ? ['o'] : null
    if (!extra || JSON.stringify(p) !== raw || !exact(p, ['v', 'e', 'doc', 'm', 'r', 't', 'a', ...extra])
      || p.v !== 1 || !/^[a-f0-9]{32}$/.test(p.doc) || !integer(p.m, 1, 128) || !integer(p.r, 1, 128)
      || !integer(p.t, 0, 2147483647) || typeof p.a !== 'boolean'
      || (p.e === 'CANCEL_RESULT' && !['RESOLVED', 'REJECTED', 'THREW', 'NO_BODY'].includes(p.o))) return null
    return p
  } catch { return null }
}

// Absence is allowed for ordinary requests. A present malformed/duplicate
// case-insensitive key always refuses; never return the raw header publicly.
export function probeBindingHeader(headers) {
  if (headers === null || typeof headers !== 'object' || Array.isArray(headers)) deny()
  const keys = Object.keys(headers).filter(k => k.toLowerCase() === 'x-cw-probe-request')
  if (!keys.length) return null
  if (keys.length !== 1) deny()
  const value = own(headers, keys[0])
  if (typeof value !== 'string' || value.length > 128) deny()
  const m = /^v1\.([a-f0-9]{32})\.([1-9][0-9]{0,2})\.([1-9][0-9]{0,2})$/.exec(value)
  if (!m || !integer(Number(m[2]), 1, 128) || !integer(Number(m[3]), 1, 128)) deny()
  return { doc: m[1], m: Number(m[2]), r: Number(m[3]) }
}

// Called only by real launch, not at module import. The supervisor validates the
// private root-owned pre-opened file. Chrome receives neither this env nor FD.
export function createBindingDiagnosticSink(environment = process.env, write = writeSync) {
  const raw = own(environment, 'CHENGWANG_PROBE_BINDING_FD')
  if (typeof raw !== 'string' || !/^[1-9][0-9]{0,3}$/.test(raw) || !integer(Number(raw), 3, 1023)) deny()
  const fd = Number(raw)
  return line => {
    const buffer = Buffer.from(line, 'ascii')
    let offset = 0
    while (offset < buffer.length) {
      const count = write(fd, buffer, offset, buffer.length - offset)
      if (!integer(count, 1, buffer.length - offset)) deny()
      offset += count
    }
  }
}

export class ProbeRequestBindingDiagnostics {
  constructor(session, write = () => {}) {
    if (!(validID(session) || (session !== null && typeof session === 'object')) || typeof write !== 'function') deny()
    this.session = session; this.write = write; this.sequence = 0; this.bytes = 0
    this.js = 0; this.sends = 0; this.results = 0; this.net = 0; this.rejected = 0
    this.closed = false; this.overflow = false; this.sinkFailed = false; this.frontend = 0
    this.frames = new Map(); this.contexts = new Map(); this.documents = new Map()
    this.requests = new Map(); this.networkKeys = new Set(); this.sendKeys = new Set(); this.resultKeys = new Set()
    this.mainFrame = null; this.contextCount = 0
    this.emit('SESSION', {})
  }
  reject() { this.rejected = Math.min(1024, this.rejected + 1) }
  emit(e, fields, final = false) {
    if (this.closed || this.sinkFailed) return false
    if (this.sequence >= (final ? 1024 : 1023)) { this.overflow = true; return false }
    const line = BINDING_DIAGNOSTIC_PREFIX + JSON.stringify({ v: 1, e, q: this.sequence + 1, s: 1, ...fields }) + '\n'
    const size = Buffer.byteLength(line)
    if (size > 512 || this.bytes + size > 524288 || !/^[\x20-\x7e]+\n$/.test(line)) { this.overflow = true; return false }
    try { this.write(line) } catch { this.sinkFailed = true; this.reject(); return false }
    this.sequence++; this.bytes += size; return true
  }
  documentAlias(doc) {
    if (!this.documents.has(doc)) {
      if (this.documents.size >= 16) { this.overflow = true; return null }
      this.documents.set(doc, { d: this.documents.size + 1, context: null })
    }
    return this.documents.get(doc)
  }
  contextReady(context) {
    if (!context.active || !context.default || context.frame !== this.mainFrame || context.origin !== DOCUMENT.slice(0, -1)) return false
    if (!context.c) {
      if (this.contextCount >= 16) { this.overflow = true; return false }
      context.c = ++this.contextCount
      this.emit('CONTEXT', { c: context.c, h: this.frames.get(context.frame), default: true })
    }
    return true
  }
  handle(method, params, session) {
    if (this.closed) return
    if (session !== this.session) { this.reject(); return }
    try { this.observe(method, params) } catch { this.reject() }
  }
  observe(method, p) {
    if (method === 'Page.frameNavigated') {
      const f = own(p, 'frame'), id = own(f, 'id')
      if (own(f, 'url') === 'about:blank') return
      if (own(f, 'url') !== DOCUMENT || own(f, 'parentId') !== undefined || !validID(id)
        || this.mainFrame !== null) { this.reject(); return }
      this.mainFrame = id; this.frames.set(id, 1)
      this.emit('DOCUMENT', { h: 1 })
      for (const c of this.contexts.values()) this.contextReady(c)
      return
    }
    if (method === 'Runtime.executionContextCreated') {
      const c = own(p, 'context'), id = own(c, 'id'), aux = own(c, 'auxData'), frame = own(aux, 'frameId')
      if (!integer(id, 1) || !validID(frame) || typeof own(aux, 'isDefault') !== 'boolean' || this.contexts.has(id)) { this.reject(); return }
      if (this.contexts.size >= 16) { this.overflow = true; return }
      const item = { active: true, default: own(aux, 'isDefault'), frame, origin: own(c, 'origin'), c: 0 }
      this.contexts.set(id, item); this.contextReady(item); return
    }
    if (method === 'Runtime.executionContextDestroyed') {
      const c = this.contexts.get(own(p, 'executionContextId'))
      if (c) c.active = false
      return
    }
    if (method === 'Runtime.executionContextsCleared') {
      for (const c of this.contexts.values()) c.active = false
      return
    }
    if (method === 'Runtime.consoleAPICalled') {
      const args = own(p, 'args'), raw = own(own(args, '0'), 'value')
      if (typeof raw !== 'string' || !(raw.startsWith(BINDING_PREFIX) || raw.startsWith(FRONT_PREFIX))) return
      const context = this.contexts.get(own(p, 'executionContextId'))
      if (own(p, 'type') !== 'info' || !Array.isArray(args) || args.length !== 1 || own(args[0], 'type') !== 'string'
        || !context || !this.contextReady(context)) { this.reject(); return }
      if (this.frontend >= 256) { this.overflow = true; return }
      if (raw.startsWith(FRONT_PREFIX)) {
        const parsed = parseStatusDiagnostic(raw)
        if (!parsed) { this.reject(); return }
        const { v: _v, e: j, ...fields } = parsed
        if (j === 'ABORT') { fields.cause = fields.c; delete fields.c }
        if (this.emit('JS', { c: context.c, j, ...fields })) { this.js++; this.frontend++ }
        return
      }
      const item = parseBindingDiagnostic(raw)
      if (!item) { this.reject(); return }
      const doc = this.documentAlias(item.doc)
      if (!doc || (doc.context !== null && doc.context !== context) || (context.doc && context.doc !== item.doc)) { this.reject(); return }
      const key = `${item.doc}:${item.m}:${item.r}`
      if (item.e === 'SEND') {
        if (this.sendKeys.has(key) || this.sendKeys.size >= 128) { this.reject(); return }
        this.sendKeys.add(key)
      } else {
        if (!this.sendKeys.has(key) || this.resultKeys.has(key)) { this.reject(); return }
        this.resultKeys.add(key)
      }
      doc.context = context; context.doc = item.doc
      const fields = { c: context.c, d: doc.d, m: item.m, r: item.r, t: item.t, a: item.a }
      if (item.e === 'CANCEL_RESULT') fields.o = item.o
      if (this.emit(item.e, fields)) { this.frontend++; if (item.e === 'SEND') this.sends++; else this.results++ }
      return
    }
    if (method === 'Network.requestWillBeSent') {
      const request = own(p, 'request'), headers = own(request, 'headers'), url = own(request, 'url')
      const binding = probeBindingHeader(headers ?? {})
      if (!binding && url !== STATUS) return
      if (!binding || url !== STATUS || own(request, 'method') !== 'GET'
        || Object.keys(headers).some(k => ['authorization', 'cookie', 'proxy-authorization', 'proxy-connection'].includes(k.toLowerCase()))
        || own(p, 'redirectResponse') !== undefined || own(p, 'frameId') !== this.mainFrame || this.mainFrame === null) { this.reject(); return }
      const id = own(p, 'requestId'), x = us(own(p, 'timestamp')), w = us(own(p, 'wallTime'))
      const key = `${binding.doc}:${binding.m}:${binding.r}`
      if (!validID(id) || this.requests.has(id) || this.networkKeys.has(key) || x === null || w === null) { this.reject(); return }
      if (this.requests.size >= 128) { this.overflow = true; return }
      const doc = this.documentAlias(binding.doc)
      if (!doc) return
      const n = this.net + 1
      if (this.emit('NET_START', { n, d: doc.d, m: binding.m, r: binding.r, h: 1, x, w })) {
        this.networkKeys.add(key); this.requests.set(id, { n, start: x, headers: false, end: false }); this.net++
      }
      return
    }
    if (!['Network.responseReceived', 'Network.loadingFinished', 'Network.loadingFailed'].includes(method)) return
    const request = this.requests.get(own(p, 'requestId'))
    if (!request) return
    const x = us(own(p, 'timestamp'))
    if (request.end || x === null || x < request.start) { this.reject(); return }
    if (method === 'Network.responseReceived') {
      const response = own(p, 'response'), st = own(response, 'status')
      if (request.headers || !integer(st, 100, 599) || own(response, 'url') !== STATUS) { this.reject(); return }
      request.headers = true; this.emit('NET_HEADERS', { n: request.n, x, st }); return
    }
    request.end = true
    if (method === 'Network.loadingFinished') this.emit('NET_FINISH', { n: request.n, x })
    else {
      const canceled = own(p, 'canceled'), error = own(p, 'errorText')
      this.emit('NET_FAIL', { n: request.n, x,
        canceled: canceled === true ? 'YES' : canceled === false ? 'NO' : 'UNKNOWN',
        error: error === 'net::ERR_ABORTED' ? 'ABORTED' : typeof error === 'string' ? 'OTHER' : 'UNKNOWN' })
    }
  }
  finish() {
    if (this.closed) return
    this.emit('META', { js: this.js, sends: this.sends, results: this.results, net: this.net,
      contexts: this.contextCount, docs: this.documents.size, rejected: this.rejected, overflow: this.overflow }, true)
    this.closed = true
  }
}
