// Synthetic pure CPU contracts; none of these tests is browser evidence.
import test from 'node:test'
import assert from 'node:assert/strict'
import { StatusNetworkLifecycle, framing, createLifecycleSink, loadLifecycleContract,
  LIFECYCLE_PREFIX, LIFECYCLE_EVENTS } from './status-network-lifecycle.mjs'
const session = {}, origin = 'https://127.0.0.1:17861', url = origin + '/api/v1/probes/status'
const nonce = 'a'.repeat(32), frame = 'PRIVATE_FRAME'
function setup(write) {
  const lines = [], d = new StatusNetworkLifecycle(session, write ?? (line => lines.push(line)))
  const handle = (method, p, s = session) => d.handle(method, p, s)
  const document = () => handle('Page.frameNavigated', { frame: { id: frame, url: origin + '/' } })
  const context = (n = 1) => handle('Runtime.executionContextCreated', { context: { id: n, origin, auxData: { frameId: frame, isDefault: true } } })
  const start = (n = 1, extra = {}, req = {}) => handle('Network.requestWillBeSent', { requestId: 'PRIVATE_REQUEST_' + n,
    timestamp: n, frameId: frame, request: { url, method: 'GET', headers: { 'X-CW-Probe-Request': `v1.${nonce}.1.${n}` }, ...req }, ...extra })
  const response = (n = 1, extra = {}, p = {}) => handle('Network.responseReceived', { requestId: 'PRIVATE_REQUEST_' + n,
    timestamp: n + .01, hasExtraInfo: false, response: { url, status: 200, headers: { 'Content-Length': '455' }, protocol: 'http/1.1',
      connectionId: 999, connectionReused: true, fromDiskCache: false, fromServiceWorker: false, ...extra }, ...p })
  const data = (n = 1, extra = {}) => handle('Network.dataReceived', { requestId: 'PRIVATE_REQUEST_' + n,
    timestamp: n + .02, dataLength: 455, encodedDataLength: 455, ...extra })
  const end = (n = 1, failed = false, extra = {}) => handle(failed ? 'Network.loadingFailed' : 'Network.loadingFinished',
    { requestId: 'PRIVATE_REQUEST_' + n, timestamp: n + .03, ...(failed ? { canceled: true, errorText: 'net::ERR_ABORTED' } : {}), ...extra })
  const rows = () => lines.map(l => JSON.parse(l.slice(LIFECYCLE_PREFIX.length)))
  return { d, lines, handle, document, context, start, response, data, end, rows,
    finish() { d.finish(); return rows() } }
}
const ready = s => { s.document(); s.context(); return s }
const run = s => { for (let n = 1; n <= 7; n++) { s.start(n); s.response(n); s.data(n); s.end(n) } return s }
const requests = s => s.rows().filter(r => r.e === 'REQUEST')

test('lifecycle consumes the frozen seven-request contract without browser IO', () => {
  const c = loadLifecycleContract(); assert.equal(c.maxRequests, 7); assert.equal(c.maxBytes, 131072)
  assert.ok(LIFECYCLE_EVENTS.includes('Network.dataReceived')); assert.ok(!LIFECYCLE_EVENTS.includes('Fetch.requestPaused'))
})
test('lifecycle uses a separate inherited FD and handles partial writes', () => {
  let raw = ''; createLifecycleSink({ CHENGWANG_PROBE_LIFECYCLE_FD: '8' }, (fd, b, off) => {
    assert.equal(fd, 8); raw += String.fromCharCode(b[off]); return 1
  })('safe\n'); assert.equal(raw, 'safe\n')
  for (const v of [undefined, '2', '08', '1024', 'PRIVATE']) assert.throws(() => createLifecycleSink({ CHENGWANG_PROBE_LIFECYCLE_FD: v }))
})
test('lifecycle exports only seven bounded anonymous identities and connection aliases', () => {
  const s = run(ready(setup())); s.finish()
  assert.equal(requests(s).length, 7); assert.deepEqual(requests(s).map(r => r.n), [1, 2, 3, 4, 5, 6, 7])
  assert.ok(requests(s).every(r => r.response.connection === 1 && r.dataBytes === 455 && r.terminal === 'FINISHED'))
  const raw = s.lines.join(''); for (const secret of ['PRIVATE', nonce, origin, '"connection":999', 'X-CW']) assert.ok(!raw.includes(secret))
})
test('lifecycle keeps complete failed requests as failures without an acceptance claim', () => {
  const s = ready(setup()); s.start(); s.response(); s.data(); s.end(1, true); s.finish()
  assert.equal(requests(s)[0].terminal, 'FAILED'); assert.equal(requests(s)[0].error, 'ABORTED')
  assert.equal(requests(s)[0].canceled, 'YES'); assert.ok(!s.lines.join('').includes('acceptance'))
})
test('lifecycle keeps missing response data terminal and optional flags explicitly unknown', () => {
  const s = ready(setup()); s.start(); s.finish(); const r = requests(s)[0]
  for (const k of ['response', 'responseUs', 'endUs', 'chunks', 'dataBytes', 'encodedBytes', 'extra']) assert.equal(r[k], null)
  assert.equal(r.terminal, 'MISSING'); assert.equal(r.hasExtra, 'NOT_OBSERVED')
})
test('lifecycle supports extra info before response and after terminal without waiting', () => {
  for (const before of [true, false]) {
    const s = ready(setup()); s.start()
    const extra = () => s.handle('Network.responseReceivedExtraInfo', { requestId: 'PRIVATE_REQUEST_1', statusCode: 200,
      headers: { 'Content-Length': '455', 'Set-Cookie': 'PRIVATE_COOKIE' } })
    if (before) extra(); s.response(1, {}, { hasExtraInfo: true }); s.data(); s.end(); if (!before) extra()
    s.finish(); assert.equal(requests(s)[0].extra.status, 200); assert.ok(!s.lines.join('').includes('PRIVATE_COOKIE'))
  }
})
test('lifecycle does not invent missing expected extra info or missing cache booleans', () => {
  const s = ready(setup()); s.start(); s.response(1, { fromDiskCache: undefined }, { hasExtraInfo: true }); s.end(); s.finish()
  const r = requests(s)[0]; assert.equal(r.extra, null); assert.equal(r.hasExtra, 'YES'); assert.equal(r.response.diskCache, 'NOT_OBSERVED')
})
test('lifecycle never accesses excluded body headers raw errors or accessor fields', () => {
  let calls = 0; const bomb = { get() { calls++; throw new Error('PRIVATE_GETTER') }, enumerable: true }
  const s = ready(setup()); s.start(); const h = { 'Content-Length': '455' }
  Object.defineProperty(h, 'Set-Cookie', bomb); Object.defineProperty(h, 'Authorization', bomb)
  s.response(1, { headers: h }); const p = { requestId: 'PRIVATE_REQUEST_1', timestamp: 1.02, dataLength: 455, encodedDataLength: 5 }
  Object.defineProperty(p, 'data', bomb); s.handle('Network.dataReceived', p)
  s.end(1, true, { errorText: 'PRIVATE_ERROR', blockedReason: 'PRIVATE_BLOCK', corsErrorStatus: { corsError: 'PRIVATE_CORS', failedParameter: 'PRIVATE_HEADER' } })
  s.finish(); assert.equal(calls, 0); assert.equal(requests(s)[0].blocked, 'UNKNOWN'); assert.ok(!s.lines.join('').includes('PRIVATE'))
})
test('lifecycle framing detects duplicates malformed lengths and unknown encodings without raw values', () => {
  assert.deepEqual(framing({}), { length: null, transfer: null, encoding: null, connection: null })
  assert.equal(framing({ 'Content-Length': '4', 'content-length': '5' }).length, 'CONFLICT')
  for (const n of ['04', '1\n2', '-1', '1048577', 'PRIVATE']) assert.equal(framing({ 'Content-Length': n }).length, 'INVALID')
  assert.equal(framing({ 'Transfer-Encoding': 'PRIVATE' }).transfer, 'UNKNOWN')
  assert.equal(framing(Object.create({ 'Content-Length': '455' })).length, null)
})
test('lifecycle accessor safe values remain invalid without invoking getters or toJSON', () => {
  let calls = 0; const h = {}; Object.defineProperty(h, 'Content-Length', { enumerable: true, get() { calls++; return '455' } })
  Object.defineProperty(h, 'toJSON', { value() { calls++; throw Error() } })
  assert.equal(framing(h).length, 'INVALID'); assert.equal(calls, 0)
})
test('lifecycle rejects duplicate request IDs nonce identities wrong frame and authenticated status', () => {
  const s = ready(setup()); s.start(); s.start(); s.start(2, { frameId: 'PRIVATE_OTHER' })
  s.start(3, {}, { headers: { 'X-CW-Probe-Request': `v1.${nonce}.1.3`, Authorization: 'PRIVATE_TOKEN' } })
  s.finish(); assert.equal(s.rows().at(-1).rejected, 3); assert.equal(requests(s).length, 1)
})
test('lifecycle ignores unrelated URLs and all unrelated headers without retaining them', () => {
  const s = ready(setup()); s.start(1, {}, { url: origin + '/api/v1/probes/details', headers: { Authorization: 'PRIVATE' } })
  s.finish(); assert.equal(requests(s).length, 0); assert.equal(s.rows().at(-1).rejected, 0)
})
test('lifecycle eighth request marks overflow instead of quietly discarding coverage', () => {
  const s = run(ready(setup())); s.start(8); s.finish()
  assert.equal(requests(s).length, 7); assert.equal(s.rows().at(-1).overflow, true)
})
test('lifecycle bounded chunk bytes and count refuse infinite or oversized streams', () => {
  for (const extra of [{ dataLength: 1048577 }, { encodedDataLength: -1 }, { dataLength: Infinity }]) {
    const s = ready(setup()); s.start(); s.data(1, extra); s.finish(); assert.equal(s.rows().at(-1).overflow, true)
  }
  const s = ready(setup()); s.start(); for (let i = 0; i < 1025; i++) s.data(1, { dataLength: 0, encodedDataLength: 0 })
  s.finish(); assert.equal(requests(s)[0].chunks, 1024); assert.equal(s.rows().at(-1).overflow, true)
})
test('lifecycle cannot reinterpret compressed encoded bytes as decoded content length', () => {
  const s = ready(setup()); s.start(); s.response(1, { headers: { 'Content-Length': '40', 'Content-Encoding': 'gzip' } })
  s.data(1, { encodedDataLength: 40 }); s.end(); s.finish()
  const r = requests(s)[0]; assert.equal(r.dataBytes, 455); assert.equal(r.encodedBytes, 40); assert.equal(r.response.framing.length, 40)
})
test('lifecycle rejects cross-session and out-of-order terminal duplicates', () => {
  const s = ready(setup()); s.start(); s.response(); s.end(); s.end(); s.data()
  s.handle('Network.loadingFinished', {}, {}); s.finish(); assert.equal(s.rows().at(-1).rejected, 3)
})
test('lifecycle records observed context changes and closing phase without adding waits', () => {
  const s = ready(setup()); s.handle('Runtime.executionContextDestroyed', { executionContextId: 1 }); s.context(2)
  s.d.beginClosing(); s.handle('Runtime.executionContextsCleared', {}); s.handle('Page.frameDetached', { frameId: frame }); s.finish()
  const contexts = s.rows().filter(r => r.e === 'CONTEXT')
  assert.ok(contexts.some(r => r.k === 'DEFAULT_DESTROYED' && r.c === 1))
  assert.ok(contexts.some(r => r.k === 'FRAME_DETACHED' && r.phase === 'CLOSING'))
})
test('lifecycle bounds context churn and keeps unknown protocol distinct from a valid value', () => {
  const s = ready(setup()); for (let i = 2; i <= 17; i++) s.context(i)
  s.start(); s.response(1, { protocol: 'PRIVATE_PROTOCOL' }); s.finish()
  assert.equal(s.rows().at(-1).overflow, true); assert.equal(requests(s)[0].response.protocol, 'UNKNOWN')
})
test('lifecycle failed sink cannot be mistaken for a closed complete stream', () => {
  const s = setup(() => { throw Error('PRIVATE_WRITE') }); s.document(); s.start(); s.d.finish(); assert.equal(s.d.sinkFailed, true)
})
test('lifecycle finishing is idempotent and later events cannot modify evidence', () => {
  const s = run(ready(setup())); s.finish(); const raw = s.lines.join(''); s.finish(); s.start(8)
  assert.equal(s.lines.join(''), raw); assert.ok(Buffer.byteLength(raw) < 131072)
})

const extraInfo = (s, n = 1, extra = {}, actualSession = session) => s.handle('Network.responseReceivedExtraInfo', {
  requestId: 'PRIVATE_REQUEST_' + n, statusCode: 200, headers: { 'Content-Length': '455' }, ...extra,
}, actualSession)

test('lifecycle associates safe extra before request start only after seven real identity validations', () => {
  const s = ready(setup())
  for (let n = 1; n <= 7; n++) {
    extraInfo(s, n); assert.equal(s.d.pendingExtras.size, 1)
    s.start(n); assert.equal(s.d.pendingExtras.size, 0)
    s.response(n, {}, { hasExtraInfo: true }); s.data(n); s.end(n)
  }
  s.finish(); assert.equal(requests(s).length, 7)
  assert.ok(requests(s).every(r => r.extra.status === 200 && r.extra.framing.length === 455))
  assert.equal(s.rows().at(-1).rejected, 0); assert.equal(s.rows().at(-1).overflow, false)
  assert.ok(!s.lines.join('').includes('PRIVATE'))
})

test('lifecycle drops pre-start projections after identifying ordinary or protected non-status requests', () => {
  for (const url of [origin + '/assets/synthetic.js', origin + '/api/v1/probes/details']) {
    const s = ready(setup()); extraInfo(s); assert.equal(s.d.pendingExtras.size, 1)
    s.start(1, { redirectResponse: { private: 'PRIVATE_REDIRECT' } }, { url, method: 'POST', headers: { Authorization: 'PRIVATE_TOKEN' } })
    assert.equal(s.d.pendingExtras.size, 0); s.finish()
    assert.equal(s.rows().at(-1).rejected, 0); assert.equal(s.rows().at(-1).overflow, false)
    assert.equal(requests(s).length, 0); assert.ok(!s.lines.join('').includes('PRIVATE'))
  }
})

test('lifecycle ignores extra after a known non-status start without inspecting its headers', () => {
  let calls = 0; const s = ready(setup())
  s.start(1, {}, { url: origin + '/api/v1/probes/details', headers: { Authorization: 'PRIVATE_TOKEN' } })
  const p = { requestId: 'PRIVATE_REQUEST_1' }
  Object.defineProperty(p, 'headers', { enumerable: true, get() { calls++; throw Error('PRIVATE_HEADERS') } })
  Object.defineProperty(p, 'statusCode', { enumerable: true, get() { calls++; throw Error('PRIVATE_STATUS') } })
  s.handle('Network.responseReceivedExtraInfo', p); s.finish()
  assert.equal(calls, 0); assert.equal(s.d.pendingExtras.size, 0); assert.equal(s.rows().at(-1).rejected, 0)
})

test('lifecycle unassociated invalid or duplicate extras do not reject a later confirmed non-status redirect', () => {
  for (const malformed of [true, false]) {
    const s = ready(setup())
    extraInfo(s, 1, malformed ? { statusCode: 999, headers: null } : {})
    extraInfo(s, 1, { statusCode: 302, headers: { Location: 'PRIVATE_REDIRECT', 'Set-Cookie': 'PRIVATE_COOKIE' } })
    assert.equal(s.d.rejected, 0)
    s.start(1, { redirectResponse: { status: 302 } }, { url: origin + '/assets/redirected.js' })
    s.finish(); assert.equal(s.rows().at(-1).rejected, 0); assert.equal(s.rows().at(-1).overflow, false)
    assert.ok(!s.lines.join('').includes('PRIVATE'))
  }
})

test('lifecycle rejects duplicate pre-start extras if their request becomes a verified status target', () => {
  const s = ready(setup()); extraInfo(s); extraInfo(s, 1, { headers: { 'Content-Length': '470' } })
  s.start(); s.response(1, {}, { hasExtraInfo: true }); s.data(); s.end(); s.finish()
  assert.equal(requests(s)[0].extra, null); assert.equal(s.rows().at(-1).rejected, 1)
})

test('lifecycle never overwrites the first accepted extra with a duplicate after start', () => {
  const s = ready(setup()); extraInfo(s); s.start(); extraInfo(s, 1, { headers: { 'Content-Length': '470' } })
  s.response(1, {}, { hasExtraInfo: true }); s.data(); s.end(); s.finish()
  assert.equal(requests(s)[0].extra.framing.length, 455); assert.equal(s.rows().at(-1).rejected, 1)
})

test('lifecycle never matches extras by identical framing time order or private ID from another session', () => {
  const s = ready(setup()); extraInfo(s, 2); extraInfo(s, 1, {}, {})
  s.start(); s.response(1, {}, { hasExtraInfo: true }); s.data(); s.end(); s.finish()
  assert.equal(requests(s)[0].extra, null); assert.equal(s.rows().at(-1).rejected, 2)
  assert.equal(s.d.pendingExtras.size, 0)
})

test('lifecycle leaves hasExtra YES missing observations missing without fallback from response headers', () => {
  const s = ready(setup()); s.start(); s.response(1, { headers: { 'Content-Length': '455' } }, { hasExtraInfo: true })
  s.data(); s.end(); s.finish(); const r = requests(s)[0]
  assert.equal(r.hasExtra, 'YES'); assert.equal(r.response.framing.length, 455); assert.equal(r.extra, null)
})

test('lifecycle unclassified extras at finish are explicitly incomplete without an added wait', () => {
  const s = run(ready(setup())); extraInfo(s, 42); assert.equal(s.d.rejected, 0)
  s.finish(); assert.equal(s.rows().at(-1).rejected, 1); assert.equal(s.d.pendingExtras.size, 0)
  const raw = s.lines.join(''); extraInfo(s, 43); assert.equal(s.lines.join(''), raw)
})

test('lifecycle bounds pending extras by maxRequests and keeps overflow visible after non-status cleanup', () => {
  const s = ready(setup()); for (let n = 1; n <= 8; n++) extraInfo(s, n)
  assert.equal(s.d.pendingExtras.size, 7); assert.equal(s.d.overflow, true)
  for (let n = 1; n <= 7; n++) s.start(n, {}, { url: origin + '/assets/synthetic.js' })
  s.finish(); assert.equal(s.d.pendingExtras.size, 0); assert.equal(s.rows().at(-1).overflow, true)
})

test('lifecycle bounds ignored non-status IDs by maxRows without retaining any request headers', () => {
  const s = ready(setup())
  for (let n = 1; n <= 129; n++) s.start(n, {}, { url: origin + '/assets/synthetic.js', headers: { Authorization: 'PRIVATE_TOKEN' } })
  assert.equal(s.d.otherRequests.size, 128); s.finish()
  assert.equal(s.rows().at(-1).overflow, true); assert.ok(!s.lines.join('').includes('PRIVATE_TOKEN'))
})

test('lifecycle defers malformed oversized or hostile header projections until target classification', () => {
  const many = Object.fromEntries(Array.from({ length: 129 }, (_, n) => ['Private-' + n, 'PRIVATE_VALUE']))
  const hostile = new Proxy({}, { ownKeys() { throw Error('PRIVATE_PROXY_EXCEPTION') } })
  for (const headers of [null, many, hostile]) {
    for (const target of [false, true]) {
      const s = ready(setup()); extraInfo(s, 1, { headers }); assert.equal(s.d.rejected, 0)
      s.start(1, {}, target ? {} : { url: origin + '/assets/synthetic.js' }); s.finish()
      assert.equal(s.rows().at(-1).rejected, target ? 1 : 0); assert.ok(!s.lines.join('').includes('PRIVATE'))
    }
  }
})

test('lifecycle pending metadata owns only safe framing primitives and never invokes secret accessors', () => {
  let calls = 0; const headers = { 'Content-Length': '455' }
  Object.defineProperty(headers, 'Set-Cookie', { enumerable: true, get() { calls++; throw Error('PRIVATE_COOKIE') } })
  Object.defineProperty(headers, 'Authorization', { enumerable: true, get() { calls++; throw Error('PRIVATE_TOKEN') } })
  const s = ready(setup()); extraInfo(s, 1, { headers }); headers['Content-Length'] = '470'
  s.start(); s.response(1, {}, { hasExtraInfo: true }); s.data(); s.end(); s.finish()
  assert.equal(calls, 0); assert.equal(requests(s)[0].extra.framing.length, 455)
  assert.equal(s.rows().at(-1).rejected, 0); assert.ok(!s.lines.join('').includes('PRIVATE'))
})

test('lifecycle cannot attach pending extra through rejected credentials frame or reused non-status ID', () => {
  for (const fault of ['credentials', 'frame', 'nonstatus-reuse']) {
    const s = ready(setup()); extraInfo(s)
    if (fault === 'credentials') s.start(1, {}, { headers: { 'X-CW-Probe-Request': `v1.${nonce}.1.1`, Authorization: 'PRIVATE' } })
    if (fault === 'frame') s.start(1, { frameId: 'PRIVATE_OTHER' })
    if (fault === 'nonstatus-reuse') { s.start(1, {}, { url: origin + '/assets/synthetic.js' }); s.start() }
    s.finish(); assert.equal(requests(s).length, 0); assert.ok(s.rows().at(-1).rejected > 0)
  }
})
