// Passive CDP evidence collection. A 503 exception never authorizes another
// route, a missing 200 body, a decode failure, or browser/session teardown.
import { need, exact, sha, strictJSON, projectRequest, validateAnonymousGet, expectedStatus, validateUnknownOverview, validateUnavailableOverview } from './wire-contract.mjs'
import { safePublic, decodeBody, FAVICON } from '../subscription-ui-browser/ui-contract.mjs'
import { mimeClass, expectedMIME } from '../capability-truth-browser/ui-contract.mjs'

const RPC_GAP = 'BODY_RPC_REJECTED_AFTER_EXPECTED_503'
const BAD_CAPTURE = 'UNQUALIFIED_CAPTURE_FAILURE'
const kindCounts = { SNAPSHOT: 'snapshot', OVERVIEW: 'overview', OBSERVATION_STATUS: 'observationStatus', PROBE_STATUS: 'probeStatus' }
const integer = (n, low = 0, high = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(n) && n >= low && n <= high
const us = n => { need(typeof n === 'number' && Number.isFinite(n) && n >= 0 && n <= Number.MAX_SAFE_INTEGER / 1000000); return Math.floor(n * 1000000) }
const equal = (a, b) => {
  need(typeof a === typeof b && (a === null) === (b === null))
  if (Array.isArray(b)) { need(Array.isArray(a) && a.length === b.length); b.forEach((v, i) => equal(a[i], v)) }
  else if (b !== null && typeof b === 'object') { need(exact(a, Object.keys(b))); for (const k of Object.keys(b)) equal(a[k], b[k]) }
  else need(a === b)
}

export class OverviewJournal {
  constructor(contract, profile, graph, canaries, bodyReader, expectedFiles) {
    need(contract.schema === 'chengwang.overview-ui-browser-contract/v1' && contract.profiles.includes(profile))
    need(graph && Array.isArray(graph.allowed) && Array.isArray(graph.required) && graph.required.every(p => graph.allowed.includes(p)))
    need(typeof bodyReader === 'function' && expectedFiles instanceof Map)
    safePublic(Buffer.from(''), canaries)
    this.c = contract; this.profile = profile; this.b = contract.captureRules.bounds; this.policy = contract.profileFacts[profile]
    this.graph = graph; this.canaries = canaries; this.bodyReader = bodyReader; this.expectedFiles = expectedFiles
    this.requests = new Map(); this.ignored = new Set(); this.networkLogAliases = new Set(); this.events = []; this.rows = []; this.tasks = new Set()
    this.counters = Object.fromEntries(contract.counterRules.rawKeys.map(k => [k, 0]))
    this.finished = 0; this.terminalCount = 0; this.totalBytes = 0; this.failure = false; this.overflow = false; this.finalized = false; this.closing = false
  }
  emit(type, fields) {
    need(!this.finalized)
    const row = { seq: this.events.length + 1, type, ...fields }, bytes = Buffer.from(JSON.stringify(row))
    need(exact(row, this.c.driverEvents[type])); safePublic(bytes, this.canaries)
    if (this.events.length >= this.b.events || bytes.length > this.b.eventRowBytes) {
      this.overflow = true; this.failure = true; this.counters.captureErrors++; throw Error('overview event limit')
    }
    this.events.push(row)
  }
  reject(code = 'capture_error', item = null) {
    this.failure = true
    need(Object.hasOwn(this.c.counterRules.errorCodeToCounter, code))
    if (this.overflow) return
    this.counters[this.c.counterRules.errorCodeToCounter[code]]++
    if (!this.finalized) {
      try { this.emit('ERROR', { requestId: item?.requestId ?? null, kind: item?.kind ?? null, code, reason: BAD_CAPTURE }) }
      catch { this.overflow = true }
    }
  }
  expected503(item) {
    return !this.closing && this.profile === 'evidence_disabled' && item?.kind === 'OVERVIEW' && item.method === 'GET' &&
      item.path === '/api/v1/overview' && item.response?.status === 503 && item.safeHeaders === true &&
      !item.authorizationPresent && !item.cookiePresent && !item.queryPresent && !item.fragmentPresent && !item.userInfoPresent && !item.bodyPresent
  }
  handle(method, p) {
    let item = null
    try {
      need(!this.finalized)
      if (method === 'Runtime.exceptionThrown') this.reject('runtime_error')
      if (method === 'Runtime.consoleAPICalled' && p.type === 'error') this.reject('console_error')
      if (method === 'Runtime.consoleAPICalled' && ['warning', 'warn'].includes(p.type)) this.reject('console_warning')
      if (method === 'Log.entryAdded') {
        const entry = p.entry
        need(entry && typeof entry === 'object' && ['verbose', 'info', 'warning', 'error'].includes(entry.level))
        if (entry.level === 'error' || entry.level === 'warning') {
          item = typeof entry.networkRequestId === 'string' ? this.requests.get(entry.networkRequestId) : null
          const urlSameRequest = !!item && entry.url === this.c.origin + item.path
          const workerIdPresent = Object.hasOwn(entry, 'workerId'), categoryPresent = Object.hasOwn(entry, 'category'), beforeClose = !this.closing
          if (entry.source === 'network' && entry.level === 'error' && this.expected503(item) && urlSameRequest &&
              !workerIdPresent && !categoryPresent && !this.networkLogAliases.has(item.requestId)) {
            // Keep the real error count. Qualification means a recorded HTTP503
            // association, not a causal explanation of the browser diagnostic.
            this.counters.consoleErrors++
            this.networkLogAliases.add(item.requestId)
            this.emit('LOG_NETWORK_ERROR', { requestId: item.requestId, source: entry.source, level: entry.level, urlSameRequest, workerIdPresent, categoryPresent, beforeClose })
          } else this.reject(entry.source === 'security' ? 'csp_error' : entry.level === 'warning' ? 'console_warning' : 'console_error', item)
        }
      }
      if (['Network.webSocketCreated', 'Network.webTransportCreated', 'Network.directTCPSocketCreated', 'Network.directUDPSocketCreated'].includes(method)) this.reject('forbidden_request')
      if (method === 'Network.requestWillBeSent') {
        need(!this.closing)
        if (p.request?.url === FAVICON) {
          try { validateAnonymousGet(p.request); need(p.redirectResponse === undefined) }
          catch { this.reject('forbidden_request'); return }
          need(typeof p.requestId === 'string' && p.requestId.length > 0 && p.requestId.length <= 256 && !this.ignored.has(p.requestId) && !this.requests.has(p.requestId) && this.ignored.size < 4)
          this.ignored.add(p.requestId); return
        }
        need(typeof p.requestId === 'string' && p.requestId.length > 0 && p.requestId.length <= 256 && !this.requests.has(p.requestId) && !this.ignored.has(p.requestId) && this.requests.size < this.policy.requestsMax)
        let projection
        try { projection = projectRequest(p.request, this.graph.allowed, this.profile); need(p.redirectResponse === undefined) }
        catch { this.reject('forbidden_request'); return }
        const requestOrdinal = this.requests.size + 1
        item = { ...projection, requestId: 'r' + requestOrdinal, requestOrdinal, rawId: p.requestId, startedWallTimeUs: us(p.wallTime), startTimeUs: us(p.timestamp), response: null, terminal: null }
        this.requests.set(p.requestId, item); this.emit('REQUEST', { requestId: item.requestId, requestOrdinal, ...projection })
        const maximum = item.kind === 'DOCUMENT' ? 1 : item.kind === 'ASSET' ? this.b.assets : this.policy.apiCounts[kindCounts[item.kind]]
        if ([...this.requests.values()].filter(r => r.kind === item.kind).length > maximum) this.reject('forbidden_request', item)
      }
      if (this.ignored.has(p.requestId)) return
      if (method === 'Network.responseReceived') {
        item = this.requests.get(p.requestId); const r = p.response
        need(item && r && !item.response && !item.terminal)
        const entries = Object.entries(r.headers ?? {}); need(entries.length <= 128 && new Set(entries.map(([k]) => k.toLowerCase())).size === entries.length)
        const headers = Object.fromEntries(entries.map(([k, v]) => [k.toLowerCase(), v]))
        const fields = { requestId: item.requestId, status: r.status, mimeClass: mimeClass(r.mimeType), setCookiePresent: Object.hasOwn(headers, 'set-cookie'), redirected: r.url !== this.c.origin + item.path, diskCache: !!r.fromDiskCache || !!r.fromPrefetchCache, serviceWorker: !!r.fromServiceWorker }
        this.emit('HEADERS', fields)
        if (!integer(r.status, 100, 599) || r.status !== expectedStatus(item.kind, this.profile) || !expectedMIME(item, fields.mimeClass)) {
          this.reject(item.kind === 'ASSET' ? 'asset_error' : 'capture_error', item); return
        }
        need(!fields.setCookiePresent && !fields.redirected && !fields.diskCache && !fields.serviceWorker)
        if (!['DOCUMENT', 'ASSET'].includes(item.kind)) need(headers['content-type'] === 'application/json; charset=utf-8')
        item.response = r; item.safeHeaders = true; item.headerTimeUs = us(p.timestamp); need(item.headerTimeUs >= item.startTimeUs)
      }
      if (method === 'Network.loadingFinished' || method === 'Network.loadingFailed') {
        item = this.requests.get(p.requestId); need(item && item.response && !item.terminal)
        item.endTimeUs = us(p.timestamp); need(item.endTimeUs >= item.startTimeUs)
        if (method === 'Network.loadingFinished') {
          need(integer(p.encodedDataLength, 0, this.b.decodedTotal))
          item.terminal = { event: 'FINISH', encodedDataLength: p.encodedDataLength, canceled: null, blockedReasonPresent: null, corsErrorPresent: null }
          this.finished++; this.emit('FINISH', { requestId: item.requestId, encodedDataLength: p.encodedDataLength })
        } else {
          need(p.canceled === undefined || typeof p.canceled === 'boolean')
          item.terminal = { event: 'NET_FAIL', encodedDataLength: null, canceled: p.canceled === true, blockedReasonPresent: Object.hasOwn(p, 'blockedReason'), corsErrorPresent: Object.hasOwn(p, 'corsErrorStatus') }
          this.emit('NET_FAIL', { requestId: item.requestId, canceled: item.terminal.canceled, blockedReasonPresent: item.terminal.blockedReasonPresent, corsErrorPresent: item.terminal.corsErrorPresent })
          this.counters.failedRequests++
          need(this.expected503(item) && item.terminal.canceled && !item.terminal.blockedReasonPresent && !item.terminal.corsErrorPresent)
        }
        const ordinal = ++this.terminalCount
        const task = this.capture(item, ordinal).finally(() => this.tasks.delete(task)); this.tasks.add(task)
      }
    } catch { this.reject('capture_error', item) }
  }
  async capture(item, ordinal) {
    try {
      let response, unavailable = false
      // Keep this catch around only the RPC await. Every later body check is
      // outside it and can only fail the run, including fulfilled bad shapes.
      try { response = await this.bodyReader(item.rawId) }
      catch {
        if (!this.expected503(item)) throw Error('unqualified body RPC failure')
        unavailable = true; this.counters.captureErrors++
        this.emit('ERROR', { requestId: item.requestId, kind: item.kind, code: 'capture_error', reason: RPC_GAP })
      }
      let raw = null, errorCodeObserved = null
      if (!unavailable) {
        const maximum = item.kind === 'DOCUMENT' ? this.b.bodyDocument : item.kind === 'ASSET' ? this.b.bodyAsset : this.b.bodyAPI
        raw = decodeBody(response, maximum); safePublic(raw, this.canaries)
        this.totalBytes += raw.length; need(this.totalBytes <= this.b.decodedTotal)
        if (['DOCUMENT', 'ASSET'].includes(item.kind)) {
          const file = this.expectedFiles.get(item.kind === 'DOCUMENT' ? 'index.html' : item.path.slice(1))
          need(file && file.bytes === raw.length && file.sha256 === sha(raw))
        } else {
          const body = strictJSON(raw, this.b.bodyAPI)
          if (item.kind === 'OVERVIEW') {
            if (item.response.status === 503) { validateUnavailableOverview(body, this.profile); errorCodeObserved = body.code }
            else validateUnknownOverview(body, this.profile)
          } else if (item.kind === 'SNAPSHOT') {
            need(exact(body, this.c.wireKeys.snapshot) && body.dataSource === 'demo' && body.mode === 'candidate' && body.publishLocked === true)
          } else equal(body, this.c.apiExpected[item.kind === 'OBSERVATION_STATUS' ? 'observationStatusDisabled' : 'probeStatusDisabled'])
        }
      }
      const row = { schema: this.c.schemaNames.capture, ordinal, requestOrdinal: item.requestOrdinal, requestId: item.requestId, method: item.method, path: item.path, kind: item.kind, status: item.response.status, authorizationPresent: false, requestPublic: null,
        responseBase64: raw === null ? null : raw.toString('base64'), responseSHA256: raw === null ? null : sha(raw), responseBytes: raw?.length ?? null,
        startedWallTimeUs: item.startedWallTimeUs, startTimeUs: item.startTimeUs, headerTimeUs: item.headerTimeUs, endTimeUs: item.endTimeUs, terminal: { ...item.terminal }, bodyState: unavailable ? 'unavailable' : 'present', bodyUnavailableReason: unavailable ? RPC_GAP : null, errorCodeObserved, bodyRPC: { attempted: true, outcome: unavailable ? 'rejected' : 'fulfilled' } }
      need(exact(row, this.c.exactKeySchemas['captures.jsonl[]'])); safePublic(Buffer.from(JSON.stringify(row)), this.canaries)
      this.rows[ordinal - 1] = row
      this.emit('CAPTURE', { requestId: item.requestId, captureOrdinal: ordinal, responseBytes: row.responseBytes, responseSHA256: row.responseSHA256, bodyState: row.bodyState, bodyUnavailableReason: row.bodyUnavailableReason, bodyRPCOutcome: row.bodyRPC.outcome })
    } catch { this.reject('capture_error', item) }
  }
  idle() { return this.tasks.size === 0 && [...this.requests.values()].every(r => r.terminal !== null) }
  mutationCount() { return [...this.requests.values()].filter(r => r.method !== 'GET').length }
  qualification() {
    const aborted = this.rows.filter(r => r?.terminal.event === 'NET_FAIL').map(r => r.requestId)
    const gaps = this.rows.filter(r => r?.bodyState === 'unavailable').map(r => r.requestId)
    return { rawCounters: { ...this.counters }, qualifiedExpected503NetworkLogs: [...this.networkLogAliases], unexpectedConsoleErrors: this.counters.consoleErrors - this.networkLogAliases.size,
      qualifiedExpected503ReportedCanceled: aborted, qualifiedExpected503BodyUnavailable: gaps,
      unexpectedFailedRequests: this.counters.failedRequests - aborted.length, unexpectedCaptureErrors: this.counters.captureErrors - gaps.length,
      errorBodyCompleteness: this.profile === 'evidence_disabled' ? this.rows.filter(r => r?.kind === 'OVERVIEW' && r.bodyState === 'present').length === this.policy.apiCounts.overview : null }
  }
  complete() {
    need(!this.failure && !this.overflow && this.idle() && this.rows.length === this.requests.size && Array.from(this.rows).every(Boolean) && this.terminalCount === this.rows.length)
    const qualified = this.qualification()
    need(this.c.counterRules.strictZeroKeys.every(k => this.counters[k] === 0) && qualified.unexpectedConsoleErrors === 0 && qualified.unexpectedFailedRequests === 0 && qualified.unexpectedCaptureErrors === 0)
    for (const [kind, countName] of Object.entries(kindCounts)) need(this.rows.filter(r => r.kind === kind).length === this.policy.apiCounts[countName])
    need(this.rows.filter(r => r.kind === 'DOCUMENT').length === 1 && this.mutationCount() === 0)
    const assets = this.rows.filter(r => r.kind === 'ASSET').map(r => r.path)
    need(assets.length > 0 && assets.length <= this.b.assets && new Set(assets).size === assets.length && this.graph.required.every(p => assets.includes(p)))
    need(Buffer.byteLength(this.rows.map(r => JSON.stringify(r) + '\n').join('')) <= this.b.captureFile)
  }
  beginClose() { need(!this.closing && !this.finalized); this.complete(); this.closing = true }
  finalize() {
    this.complete(); need(this.closing && !this.finalized)
    this.emit('META', { requests: this.requests.size, headers: [...this.requests.values()].filter(r => r.response).length, finished: this.finished, failed: this.counters.failedRequests, captured: this.rows.length, pending: [...this.requests.values()].filter(r => !r.terminal).length, tasks: this.tasks.size, ignoredFavicon: this.ignored.size, mutations: this.mutationCount(), overflow: this.overflow })
    this.finalized = true
  }
}
