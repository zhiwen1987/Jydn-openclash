import test from 'node:test'
import assert from 'node:assert/strict'
import { ProbeRequestBindingDiagnostics, parseBindingDiagnostic, probeBindingHeader,
  createBindingDiagnosticSink, BINDING_PREFIX, BINDING_DIAGNOSTIC_PREFIX } from './probe-request-binding.mjs'
import { safeRequest } from './browser-driver.mjs'

const origin = 'https://127.0.0.1:17861', url = origin + '/api/v1/probes/status'
const nonce = 'a'.repeat(32), otherNonce = 'b'.repeat(32), session = 'private-session-id'
const item = (e = 'SEND', extra = {}) => ({ v: 1, e, m: 1, r: 1, t: 2, a: false, doc: nonce, ...extra })
const raw = (e, extra) => BINDING_PREFIX + JSON.stringify(item(e, extra))
function setup(actualSession = session) {
  const lines = [], d = new ProbeRequestBindingDiagnostics(actualSession, l => lines.push(l))
  const handle = (m, p, s = actualSession) => d.handle(m, p, s)
  const frame = (extra = {}) => handle('Page.frameNavigated', { frame: { id: 'private-frame', url: origin + '/', ...extra } })
  const context = (id = 31, extra = {}) => handle('Runtime.executionContextCreated', { context: {
    id, origin, auxData: { frameId: 'private-frame', isDefault: true, ...extra } } })
  const console = (text, id = 31, extra = {}) => handle('Runtime.consoleAPICalled', {
    type: 'info', executionContextId: id, args: [{ type: 'string', value: text }], ...extra })
  const start = (extra = {}, requestExtra = {}) => handle('Network.requestWillBeSent', {
    requestId: 'private-request', frameId: 'private-frame', timestamp: 1, wallTime: 2,
    request: { url, method: 'GET', headers: { 'X-CW-Probe-Request': `v1.${nonce}.1.1` }, ...requestExtra }, ...extra })
  const rows = () => lines.map(l => JSON.parse(l.slice(BINDING_DIAGNOSTIC_PREFIX.length)))
  const finish = () => { d.finish(); return rows().at(-1) }
  return { d, lines, handle, frame, context, console, start, rows, finish }
}
const ready = s => { s.frame(); s.context(); return s }

test('binding parses only canonical closed frontend SEND and cancel settlements', () => {
  assert.deepEqual(parseBindingDiagnostic(raw('SEND')), item())
  for (const o of ['RESOLVED', 'REJECTED', 'THREW', 'NO_BODY']) assert.equal(parseBindingDiagnostic(raw('CANCEL_RESULT', { o })).o, o)
  for (const v of [raw('SEND') + ' ', raw('SEND', { unexpected: 'private' }), raw('SEND', { doc: nonce.toUpperCase() }),
    raw('SEND', { m: 0 }), raw('SEND', { r: 129 }), raw('CANCEL_RESULT', { o: 'RETURNED' }),
    BINDING_PREFIX + '{"v":1,"v":1,"e":"SEND"}']) assert.equal(parseBindingDiagnostic(v), null)
})
test('binding header parser rejects duplicate casing commas and noncanonical counters', () => {
  assert.deepEqual(probeBindingHeader({ 'x-Cw-pRoBe-ReQuEsT': `v1.${nonce}.1.128` }), { doc: nonce, m: 1, r: 128 })
  assert.equal(probeBindingHeader({ Accept: 'application/json' }), null)
  for (const h of [{ 'X-CW-Probe-Request': `v1.${nonce}.1.1`, 'x-cw-probe-request': `v1.${nonce}.1.1` },
    { 'X-CW-Probe-Request': `v1.${nonce}.01.1` }, { 'X-CW-Probe-Request': `v1.${nonce}.1.1,v1.${nonce}.1.2` },
    { 'X-CW-Probe-Request': 1 }, { 'X-CW-Probe-Request': `v1.${nonce}.1.129` }]) assert.throws(() => probeBindingHeader(h))
})
test('binding FD sink requires inherited bounded decimal descriptor without import IO', () => {
  for (const v of [undefined, '0', '2', '1024', '03', '-3', '3\n', '3.0']) {
    assert.throws(() => createBindingDiagnosticSink(v === undefined ? {} : { CHENGWANG_PROBE_BINDING_FD: v }))
  }
  const written = []
  createBindingDiagnosticSink({ CHENGWANG_PROBE_BINDING_FD: '9' }, (fd, b, offset, size) => {
    assert.equal(fd, 9); written.push(b.subarray(offset, offset + size).toString()); return size
  })('safe\n')
  assert.deepEqual(written, ['safe\n'])
})
test('binding FD sink completes partial writes and refuses zero progress', () => {
  const bytes = []
  createBindingDiagnosticSink({ CHENGWANG_PROBE_BINDING_FD: '3' }, (_fd, b, offset) => { bytes.push(b[offset]); return 1 })('abc\n')
  assert.equal(Buffer.from(bytes).toString(), 'abc\n')
  assert.throws(() => createBindingDiagnosticSink({ CHENGWANG_PROBE_BINDING_FD: '3' }, () => 0)('x'))
})
test('binding records the actual string session once and rejects wrong session', () => {
  const s = ready(setup()); s.handle('Page.frameNavigated', {}, 'wrong-private-session')
  assert.deepEqual(s.rows()[0], { v: 1, e: 'SESSION', q: 1, s: 1 }); assert.equal(s.finish().rejected, 1)
})
test('binding uses Playwright CDPSession object identity not unsupported private IDs', () => {
  const actual = {}, s = ready(setup(actual)); s.handle('Runtime.consoleAPICalled', {}, {})
  assert.equal(s.finish().rejected, 1); assert.throws(() => new ProbeRequestBindingDiagnostics(null))
})
test('binding caches initial aboutblank context and emits only the real default document context', () => {
  const s = setup(); s.handle('Page.frameNavigated', { frame: { id: 'private-frame', url: 'about:blank' } })
  s.handle('Runtime.executionContextCreated', { context: { id: 1, origin: '', auxData: { frameId: 'private-frame', isDefault: true } } })
  s.handle('Runtime.executionContextDestroyed', { executionContextId: 1 }); s.context(); s.frame()
  assert.deepEqual(s.rows().map(r => r.e), ['SESSION', 'DOCUMENT', 'CONTEXT']); assert.equal(s.finish().rejected, 0)
})
test('binding rejects subframe or foreign document navigation without exporting URLs', () => {
  const s = setup(); s.frame({ parentId: 'private-parent' }); s.frame({ url: 'https://private.invalid/' })
  assert.equal(s.finish().rejected, 2); assert.ok(!s.lines.join('').includes('private.invalid'))
})
test('binding rejects nondefault wrong-frame destroyed and cleared execution contexts', () => {
  const s = ready(setup()); s.context(32, { isDefault: false }); s.context(33, { frameId: 'private-other-frame' })
  s.console(raw('SEND'), 32); s.console(raw('SEND'), 33)
  s.handle('Runtime.executionContextDestroyed', { executionContextId: 31 }); s.console(raw('SEND'))
  s.context(34); s.handle('Runtime.executionContextsCleared', {}); s.console(raw('SEND'), 34)
  assert.equal(s.finish().rejected, 4); assert.equal(s.rows().filter(r => r.e === 'SEND').length, 0)
})
test('binding console parser refuses wrong type extra arguments and malformed payloads', () => {
  const s = ready(setup()); s.console(raw('SEND'), 31, { type: 'log' }); s.console(raw('SEND'), 31, { args: [
    { type: 'string', value: raw('SEND') }, { type: 'string', value: 'private' }] })
  s.console(BINDING_PREFIX + '{"secret":"private"}'); assert.equal(s.finish().rejected, 3)
})
test('binding projects original JS primitives preserving ABORT cause separate from context alias', () => {
  const s = ready(setup()); s.console('CW_PROBE_STATUS:' + JSON.stringify({ v: 1, e: 'ABORT', m: 1, r: 1, t: 4, a: true, c: 'DEADLINE', p: 'BEFORE' }))
  const row = s.rows().at(-1); assert.equal(row.e, 'JS'); assert.equal(row.c, 1); assert.equal(row.cause, 'DEADLINE')
  assert.equal(row.j, 'ABORT'); assert.equal(s.finish().js, 1)
})
test('binding SEND and network start join private identity independent of arrival order', () => {
  for (const networkFirst of [true, false]) {
    const s = ready(setup()); if (networkFirst) s.start(); s.console(raw('SEND')); if (!networkFirst) s.start()
    const send = s.rows().find(r => r.e === 'SEND'), net = s.rows().find(r => r.e === 'NET_START')
    assert.equal(send.d, net.d); assert.equal(send.m, net.m); assert.equal(send.r, net.r); assert.equal(s.finish().rejected, 0)
  }
})
test('binding refuses replayed SEND and duplicate network identity or request ID', () => {
  const s = ready(setup()); s.console(raw('SEND')); s.console(raw('SEND')); s.start(); s.start()
  s.start({ requestId: 'another-private-request' }); s.start({}, { headers: { 'X-CW-Probe-Request': `v1.${otherNonce}.1.1` } })
  assert.equal(s.finish().rejected, 4); assert.equal(s.d.net, 1)
})
test('binding document identity cannot migrate across active default contexts', () => {
  const s = ready(setup()); s.console(raw('SEND')); s.context(32); s.console(raw('SEND', { r: 2 }), 32)
  s.console(raw('SEND', { doc: otherNonce, r: 2 })); assert.equal(s.finish().rejected, 2)
})
test('binding cancellation settlements remain independent of network terminal order', () => {
  for (const resultFirst of [true, false]) {
    const s = ready(setup()); s.console(raw('SEND')); s.start()
    if (resultFirst) s.console(raw('CANCEL_RESULT', { t: 9, o: 'RESOLVED' }))
    s.handle('Network.loadingFinished', { requestId: 'private-request', timestamp: 2 })
    if (!resultFirst) s.console(raw('CANCEL_RESULT', { t: 9, o: 'RESOLVED' }))
    assert.equal(s.finish().results, 1); assert.equal(s.d.rejected, 0)
  }
})
test('binding refuses absent-send duplicate and unknown cancellation settlements', () => {
  const s = ready(setup()); s.console(raw('CANCEL_RESULT', { o: 'RESOLVED' })); s.console(raw('SEND'))
  s.console(raw('CANCEL_RESULT', { o: 'REJECTED' })); s.console(raw('CANCEL_RESULT', { o: 'RESOLVED' }))
  assert.equal(s.finish().rejected, 2); assert.equal(s.d.results, 1)
})
test('binding network metadata rejects credentials redirects wrong frames and absent identity', () => {
  const s = ready(setup()); s.start({ redirectResponse: {} }); s.start({ frameId: 'private-other-frame' })
  s.start({}, { headers: { 'X-CW-Probe-Request': `v1.${nonce}.1.1`, Authorization: 'private-token' } })
  s.start({}, { headers: {} }); s.start({}, { method: 'POST' }); assert.equal(s.finish().rejected, 5)
})
test('binding header is refused on all nonstatus protected and foreign requests', () => {
  const headers = { 'X-CW-Probe-Request': `v1.${nonce}.1.1` }
  assert.equal(safeRequest({ url, method: 'GET', headers }, 'Fetch').authorizationPresent, false)
  for (const path of ['/', '/assets/main.js', '/api/v1/snapshot', '/api/v1/observations/status', '/api/v1/probes/details']) {
    assert.throws(() => safeRequest({ url: origin + path, method: 'GET', headers: { ...headers,
      ...(path.endsWith('/details') ? { Authorization: 'private' } : {}) } }, 'Fetch'))
  }
  const s = ready(setup()); s.start({}, { url: 'https://private.invalid/', headers }); assert.equal(s.finish().rejected, 1)
})
test('binding lifecycle enforces headers once and one terminal without assuming headers clock precedes terminal', () => {
  const s = ready(setup()); s.start()
  s.handle('Network.responseReceived', { requestId: 'private-request', timestamp: 3, response: { status: 200, url } })
  s.handle('Network.responseReceived', { requestId: 'private-request', timestamp: 3, response: { status: 200, url } })
  s.handle('Network.loadingFinished', { requestId: 'private-request', timestamp: 2 })
  s.handle('Network.loadingFailed', { requestId: 'private-request', timestamp: 4, canceled: true, errorText: 'net::ERR_ABORTED' })
  assert.equal(s.finish().rejected, 2); assert.equal(s.rows().filter(r => r.e === 'NET_FINISH').length, 1)
})
test('binding rejects backwards invalid timestamps invalid status and redirect reuse', () => {
  const s = ready(setup()); s.start({ timestamp: NaN }); s.start()
  s.handle('Network.loadingFinished', { requestId: 'private-request', timestamp: 0.5 })
  s.handle('Network.responseReceived', { requestId: 'private-request', timestamp: 2, response: { status: 99, url } })
  s.start({ redirectResponse: { url: 'https://private.invalid/' } }); assert.equal(s.finish().rejected, 4)
})
test('binding failed network remains an explicit failure with only closed sanitized classifications', () => {
  for (const [canceled, errorText, c, error] of [[true, 'net::ERR_ABORTED', 'YES', 'ABORTED'],
    [false, 'private-error-token', 'NO', 'OTHER'], [undefined, undefined, 'UNKNOWN', 'UNKNOWN']]) {
    const s = ready(setup()); s.start(); s.handle('Network.loadingFailed', { requestId: 'private-request', timestamp: 2, canceled, errorText })
    assert.deepEqual(s.rows().at(-1), { v: 1, e: 'NET_FAIL', q: 5, s: 1, n: 1, x: 2000000, canceled: c, error })
    assert.ok(!s.lines.join('').includes('private-error-token'))
  }
})
test('binding ExtraInfo is optional unordered and never claimed as raw-wire proof', () => {
  const s = ready(setup()); s.handle('Network.requestWillBeSentExtraInfo', { requestId: 'private-request', headers: { secret: 'private' } })
  s.start(); s.handle('Network.responseReceivedExtraInfo', { requestId: 'private-request', statusCode: 200 })
  s.handle('Network.loadingFinished', { requestId: 'private-request', timestamp: 2 })
  assert.equal(s.finish().rejected, 0); assert.ok(!s.lines.join('').includes('private'))
})
test('binding bounds rows bytes contexts and frontend observations reserving one META', () => {
  const s = ready(setup()); for (let i = 0; i < 1100; i++) s.d.emit('DOCUMENT', { h: 1 })
  const meta = s.finish(); assert.equal(s.lines.length, 1024); assert.equal(meta.overflow, true)
  assert.ok(s.lines.every(l => Buffer.byteLength(l) <= 512)); assert.ok(Buffer.byteLength(s.lines.join('')) <= 524288)
  const c = setup(); for (let i = 1; i <= 17; i++) c.context(i); assert.equal(c.finish().overflow, true)
  const f = ready(setup()); for (let i = 0; i < 257; i++) f.console('CW_PROBE_STATUS:' + JSON.stringify({ v: 1, e: 'MOUNT', m: 1, r: 0, t: 0, a: false }))
  assert.equal(f.finish().overflow, true); assert.equal(f.d.js, 256)
})
test('binding sink failure and finish idempotence never leak private IDs or invent successful evidence', () => {
  const s = ready(setup()); s.console(raw('SEND')); s.start(); s.finish(); const count = s.lines.length
  s.d.finish(); s.console(raw('SEND')); assert.equal(s.lines.length, count)
  const exported = s.lines.join(''); for (const secret of [nonce, session, 'private-frame', 'private-request', url]) assert.ok(!exported.includes(secret))
  const broken = new ProbeRequestBindingDiagnostics(session, () => { throw new Error('private sink error') })
  broken.finish(); assert.equal(broken.sinkFailed, true); assert.equal(broken.sequence, 0)
  assert.doesNotThrow(() => new ProbeRequestBindingDiagnostics(session).finish())
})
