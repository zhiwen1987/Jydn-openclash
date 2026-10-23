// CI diagnostic projection only. No browser launch, I/O, outcome changes, or
// JS/network causal matching occurs here. Original browser gates remain strict.
// Prefix CW_PROBE_DIAG: contains one canonical ASCII JSON object <=512 bytes.
// At most 511 event rows plus one META row are emitted. All rows have v/e/q.
// JS: u is Runtime.consoleAPICalled epoch milliseconds projected to integer
// microseconds; t is frontend mount-relative performance.now milliseconds.
// NET_*: x is CDP monotonic seconds projected to integer microseconds, w is
// requestWillBeSent epoch seconds projected likewise. Never subtract u/w/x/t
// across clock domains or infer unique JS ownership from request order alone.
// h/l/p are per-collector ordinal frame/loader aliases, never raw protocol IDs.
export const FRONT_PREFIX = 'CW_PROBE_STATUS:'
export const DIAGNOSTIC_PREFIX = 'CW_PROBE_DIAG:'
const STATUS = 'https://127.0.0.1:17861/api/v1/probes/status'
const DOCUMENT = 'https://127.0.0.1:17861/'
const own = (value, key) => value && typeof value === 'object'
  ? Object.getOwnPropertyDescriptor(value, key)?.value : undefined
const integer = (value, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) =>
  Number.isSafeInteger(value) && value >= minimum && value <= maximum
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',')
const microseconds = (value, factor) => typeof value === 'number' && Number.isFinite(value)
  && value >= 0 && value <= Number.MAX_SAFE_INTEGER / factor ? Math.floor(value * factor) : null
const EVENTS = new Map([
  ['MOUNT', []], ['BEGIN', ['tr']], ['ARM', []], ['HEADERS', []], ['EOF', ['n']],
  ['ABORT', ['c', 'p']], ['CLEANUP', []], ['READ_END', ['k', 'n', 'f']],
  ['CANCEL', ['p', 'n', 'f']], ['FINALLY', []],
])
const enumValue = (value, values) => typeof value === 'string' && values.includes(value)

// Re-serialization equality rejects duplicate keys, whitespace, escaped strings,
// exponent notation and any unknown payload. Only closed primitives survive.
export function parseStatusDiagnostic(value) {
  try {
    if (typeof value !== 'string' || value.length > 256 || Buffer.byteLength(value) > 256
      || !/^[\x20-\x7e]+$/.test(value) || !value.startsWith(FRONT_PREFIX)) return null
    const raw = value.slice(FRONT_PREFIX.length), parsed = JSON.parse(raw)
    const extra = EVENTS.get(parsed?.e)
    if (!extra || JSON.stringify(parsed) !== raw || !exact(parsed, ['v', 'e', 'm', 'r', 't', 'a', ...extra])
      || parsed.v !== 1 || !integer(parsed.m, 1, 128) || !integer(parsed.r, 0, 128) || !integer(parsed.t, 0, 2147483647)
      || typeof parsed.a !== 'boolean') return null
    if (parsed.e === 'MOUNT' && (parsed.r !== 0 || parsed.t !== 0 || parsed.a !== false)) return null
    if (!['MOUNT', 'CLEANUP'].includes(parsed.e) && parsed.r === 0) return null
    if (parsed.e === 'BEGIN' && !enumValue(parsed.tr, ['INITIAL', 'MANUAL', 'POLL'])) return null
    if (parsed.e === 'ABORT' && (!enumValue(parsed.c, ['DEADLINE', 'CLEANUP'])
      || !enumValue(parsed.p, ['BEFORE', 'AFTER']))) return null
    if (parsed.e === 'CANCEL' && !enumValue(parsed.p, ['BEFORE', 'AFTER'])) return null
    if (parsed.e === 'READ_END' && !enumValue(parsed.k,
      ['FETCH_ERROR', 'HEADERS_REJECT', 'READ_ERROR', 'UTF8_REJECT', 'SIZE_REJECT', 'JSON_REJECT', 'EOF_OK'])) return null
    if (['READ_END', 'CANCEL'].includes(parsed.e)
      && (!integer(parsed.n, 0, 1048577) || typeof parsed.f !== 'boolean')) return null
    if (parsed.e === 'EOF' && !integer(parsed.n, 0, 1048577)) return null
    return parsed
  } catch { return null }
}

export class ProbeStatusDiagnostics {
  constructor(write = line => process.stderr.write(line)) {
    this.write = write; this.sequence = 0; this.js = 0; this.net = 0; this.rejected = 0
    this.overflow = false; this.closed = false
    this.frames = new Map(); this.loaders = new Map(); this.requests = new Map()
  }
  reject() { this.rejected = Math.min(512, this.rejected + 1) }
  emit(event, fields) {
    if (this.closed) return false
    if (this.sequence >= 511) { this.overflow = true; return false }
    const row = { v: 1, e: event, q: this.sequence + 1, ...fields }
    const line = DIAGNOSTIC_PREFIX + JSON.stringify(row)
    if (Buffer.byteLength(line) > 512 || !/^[\x20-\x7e]+$/.test(line)) { this.reject(); return false }
    this.sequence++
    try { this.write(line + '\n') } catch { this.reject() }
    return true
  }
  alias(map, value) {
    if (typeof value !== 'string' || value.length < 1 || value.length > 256) return null
    if (!map.has(value)) {
      if (map.size >= 256) { this.overflow = true; return null }
      map.set(value, map.size + 1)
    }
    return map.get(value)
  }
  handle(method, params) {
    if (this.closed) return
    try { this.observe(method, params) } catch { this.reject() }
  }
  observe(method, params) {
    if (method === 'Runtime.consoleAPICalled') {
      const args = own(params, 'args')
      if (own(params, 'type') !== 'info' || !Array.isArray(args) || args.length !== 1) return
      const arg = own(args, '0'), raw = own(arg, 'value')
      if (own(arg, 'type') !== 'string' || typeof raw !== 'string' || !raw.startsWith(FRONT_PREFIX)) return
      const item = parseStatusDiagnostic(raw), u = microseconds(own(params, 'timestamp'), 1000)
      if (!item || u === null) { this.reject(); return }
      if (this.js >= 128) { this.overflow = true; return }
      const { v: _v, e: j, ...fields } = item
      if (this.emit('JS', { u, j, ...fields })) this.js++
      return
    }
    if (method === 'Page.frameNavigated') {
      const frame = own(params, 'frame'), id = own(frame, 'id')
      if (!this.frames.has(id) || own(frame, 'url') !== DOCUMENT) { this.reject(); return }
      const h = this.frames.get(id)
      const l = this.alias(this.loaders, own(frame, 'loaderId')), parent = own(frame, 'parentId')
      const p = parent === undefined ? 0 : this.frames.get(parent) ?? null
      if (h === null || l === null || p === null) { this.reject(); return }
      this.emit('FRAME_NAV', { h, l, p })
      return
    }
    if (method === 'Network.requestWillBeSent') {
      const request = own(params, 'request'), url = own(request, 'url')
      if (url !== STATUS && !(url === DOCUMENT && own(params, 'type') === 'Document')) return
      const headers = own(request, 'headers')
      if (own(request, 'method') !== 'GET' || headers === null || typeof headers !== 'object'
        || Object.keys(headers).some(name => ['authorization', 'cookie', 'proxy-authorization', 'proxy-connection'].includes(name.toLowerCase()))) {
        this.reject(); return
      }
      const x = microseconds(own(params, 'timestamp'), 1000000), w = microseconds(own(params, 'wallTime'), 1000000)
      const h = this.alias(this.frames, own(params, 'frameId')), l = this.alias(this.loaders, own(params, 'loaderId'))
      if (x === null || w === null || h === null || l === null) { this.reject(); return }
      if (url === DOCUMENT) { this.emit('DOCUMENT', { x, w, h, l }); return }
      const id = own(params, 'requestId')
      if (typeof id !== 'string' || id.length < 1 || id.length > 256 || this.requests.has(id)
        || own(params, 'redirectResponse') !== undefined) { this.reject(); return }
      if (this.net >= 128 || this.requests.size >= 128) { this.overflow = true; return }
      const s = this.net + 1
      if (this.emit('NET_START', { s, x, w, h, l })) { this.net++; this.requests.set(id, s) }
      return
    }
    if (!['Network.responseReceived', 'Network.loadingFinished', 'Network.loadingFailed'].includes(method)) return
    const id = own(params, 'requestId'), s = this.requests.get(id)
    if (!s) return
    const x = microseconds(own(params, 'timestamp'), 1000000)
    if (x === null) { this.reject(); return }
    if (method === 'Network.responseReceived') {
      const st = own(own(params, 'response'), 'status')
      if (!integer(st, 100, 599)) { this.reject(); return }
      this.emit('NET_HEADERS', { s, x, st }); return
    }
    this.requests.delete(id)
    if (method === 'Network.loadingFinished') this.emit('NET_FINISH', { s, x })
    else {
      const canceled = own(params, 'canceled'), error = own(params, 'errorText')
      this.emit('NET_FAIL', { s, x, c: canceled === true ? 'YES' : canceled === false ? 'NO' : 'UNKNOWN',
        ec: error === 'net::ERR_ABORTED' ? 'ABORTED' : typeof error === 'string' ? 'OTHER' : 'UNKNOWN' })
    }
  }
  finish() {
    if (this.closed) return
    const row = { v: 1, e: 'META', q: this.sequence + 1, js: this.js, net: this.net,
      rej: this.rejected, over: this.overflow || this.js === 128 }
    this.closed = true
    try { this.write(DIAGNOSTIC_PREFIX + JSON.stringify(row) + '\n') } catch { /* Diagnostic sink failure is not product evidence. */ }
  }
}
