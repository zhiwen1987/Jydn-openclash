// Pure synthetic diagnostic tests. No browser, network, Go, TLS or namespace.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { FRONT_PREFIX, DIAGNOSTIC_PREFIX, parseStatusDiagnostic, ProbeStatusDiagnostics } from './probe-status-diagnostics.mjs'
import { NetworkJournal } from './browser-driver.mjs'

const token = 'PRIVATE_SENTINEL'
const base = (e, extra = {}) => ({ v: 1, e, m: 1, r: e === 'MOUNT' ? 0 : 1, t: e === 'MOUNT' ? 0 : 7, a: false, ...extra })
const encoded = object => FRONT_PREFIX + JSON.stringify(object)
const consoleEvent = payload => ({ type: 'info', timestamp: 1710000000000.5, args: [{ type: 'string', value: payload }] })
const start = (extra = {}) => ({ requestId: 'raw-request-' + token, type: 'Fetch', frameId: 'raw-frame-' + token,
  loaderId: 'raw-loader-' + token, timestamp: 100.125, wallTime: 1710000000.5,
  request: { url: 'https://127.0.0.1:17861/api/v1/probes/status', method: 'GET', headers: {} }, ...extra })
const setup = () => { const lines = []; return { lines, collector: new ProbeStatusDiagnostics(line => lines.push(line)) } }
const rows = lines => lines.map(line => JSON.parse(line.slice(DIAGNOSTIC_PREFIX.length)))

test('status diagnostic parser accepts every closed frontend event without rewriting primitives', () => {
  const events = [base('MOUNT'), base('BEGIN', { tr: 'INITIAL' }), base('ARM'), base('HEADERS'),
    base('EOF', { n: 10 }), base('ABORT', { c: 'DEADLINE', p: 'BEFORE' }), base('CLEANUP'),
    base('READ_END', { k: 'EOF_OK', n: 10, f: true }), base('CANCEL', { p: 'AFTER', n: 10, f: true }), base('FINALLY')]
  for (const event of events) assert.deepEqual(parseStatusDiagnostic(encoded(event)), event)
  for (const tr of ['INITIAL', 'MANUAL', 'POLL']) assert.ok(parseStatusDiagnostic(encoded(base('BEGIN', { tr }))))
  for (const k of ['FETCH_ERROR', 'HEADERS_REJECT', 'READ_ERROR', 'UTF8_REJECT', 'SIZE_REJECT', 'JSON_REJECT', 'EOF_OK']) {
    assert.ok(parseStatusDiagnostic(encoded(base('READ_END', { k, n: 1048577, f: true }))))
  }
})

test('status diagnostic parser rejects duplicate unknown noncanonical and out of budget inputs', () => {
  const valid = encoded(base('ARM'))
  for (const value of [null, {}, valid + ' ', valid.replace('"v":1', '"v":1,"v":1'),
    valid.replace('"m":1', '"m":1e0'), valid.replace('"ARM"', '"\\u0041RM"'),
    valid + token, FRONT_PREFIX + 'x'.repeat(257), FRONT_PREFIX + '{"e":"' + token + '"}',
    encoded(base('ARM', { url: token })), encoded(base('ARM', { m: 129 })), encoded(base('ARM', { r: 0 })),
    encoded(base('ARM', { t: 2147483648 })), encoded(base('ARM', { t: -1 })), encoded(base('ARM', { a: 0 })),
    encoded(base('MOUNT', { t: 1 })), encoded(base('MOUNT', { a: true })), encoded(base('BEGIN', { tr: token })),
    encoded(base('ABORT', { c: token, p: 'BEFORE' })), encoded(base('EOF', { n: 1048578 })),
    encoded(base('READ_END', { k: 'EOF_OK', n: 1, f: token })), encoded(base('CANCEL', { p: token, n: 0, f: false }))]) {
    assert.equal(parseStatusDiagnostic(value), null)
  }
})

test('status collector exports only one info string argument and never arbitrary console data', () => {
  const { collector, lines } = setup()
  collector.handle('Runtime.consoleAPICalled', consoleEvent(encoded(base('MOUNT'))))
  for (const p of [{ ...consoleEvent(encoded(base('ARM'))), type: 'error' },
    { ...consoleEvent(encoded(base('ARM'))), args: [{ type: 'string', value: token }] },
    { ...consoleEvent(encoded(base('ARM'))), args: [{ type: 'object', value: encoded(base('ARM')) }] },
    { ...consoleEvent(encoded(base('ARM'))), args: [{ type: 'string', value: encoded(base('ARM')) }, { value: token }] }]) {
    collector.handle('Runtime.consoleAPICalled', p)
  }
  collector.finish()
  assert.equal(rows(lines).length, 2)
  assert.deepEqual(rows(lines)[0], { v: 1, e: 'JS', q: 1, u: 1710000000000500, j: 'MOUNT', m: 1, r: 0, t: 0, a: false })
  assert.equal(rows(lines)[1].js, 1); assert.ok(!lines.join('').includes(token))
})

test('status collector records native request headers failure clocks without causal ownership claims', () => {
  const { collector, lines } = setup(), request = start()
  collector.handle('Network.requestWillBeSent', request)
  collector.handle('Network.responseReceived', { requestId: request.requestId, timestamp: 100.2, response: { status: 200 } })
  collector.handle('Network.loadingFailed', { requestId: request.requestId, timestamp: 100.3, canceled: true, errorText: 'net::ERR_ABORTED' })
  collector.finish()
  assert.deepEqual(rows(lines), [
    { v: 1, e: 'NET_START', q: 1, s: 1, x: 100125000, w: 1710000000500000, h: 1, l: 1 },
    { v: 1, e: 'NET_HEADERS', q: 2, s: 1, x: 100200000, st: 200 },
    { v: 1, e: 'NET_FAIL', q: 3, s: 1, x: 100300000, c: 'YES', ec: 'ABORTED' },
    { v: 1, e: 'META', q: 4, js: 0, net: 1, rej: 0, over: false }])
  assert.ok(!lines.join('').includes(token)); assert.ok(!lines.join('').includes('owner'))
})

test('status collector rejects non anonymous non GET foreign and details requests', () => {
  const { collector, lines } = setup()
  for (const patch of [{ method: 'POST' }, { headers: { aUThoRizATion: token } }, { headers: { Cookie: token } },
    { headers: { 'proxy-authorization': token } }, { url: 'https://foreign.example/' + token },
    { url: 'https://127.0.0.1:17861/api/v1/probes/details' }, { url: 'https://127.0.0.1:17861/api/v1/probes/status?token=' + token }]) {
    const event = start(); collector.handle('Network.requestWillBeSent', { ...event, request: { ...event.request, ...patch } })
  }
  collector.finish()
  assert.deepEqual(rows(lines), [{ v: 1, e: 'META', q: 1, js: 0, net: 0, rej: 4, over: false }])
  assert.ok(!lines.join('').includes(token))
})

test('status collector preserves frame loader aliases only within observed fixed document scope', () => {
  const { collector, lines } = setup(), event = start()
  collector.handle('Page.frameNavigated', { frame: { id: event.frameId, loaderId: event.loaderId, url: 'https://127.0.0.1:17861/' } })
  collector.handle('Network.requestWillBeSent', { ...event, type: 'Document', request: { ...event.request, url: 'https://127.0.0.1:17861/' } })
  collector.handle('Page.frameNavigated', { frame: { id: event.frameId, loaderId: event.loaderId, url: 'https://127.0.0.1:17861/' } })
  collector.handle('Page.frameNavigated', { frame: { id: event.frameId, loaderId: token, url: 'https://foreign.example/' } })
  collector.handle('Network.requestWillBeSent', event)
  collector.handle('Network.loadingFinished', { requestId: event.requestId, timestamp: 100.5 })
  collector.finish()
  assert.deepEqual(rows(lines).map(row => row.e), ['DOCUMENT', 'FRAME_NAV', 'NET_START', 'NET_FINISH', 'META'])
  assert.equal(rows(lines)[1].h, rows(lines)[2].h); assert.equal(rows(lines)[1].l, rows(lines)[2].l)
  assert.equal(rows(lines).at(-1).rej, 2); assert.ok(!lines.join('').includes(token))
})

test('status collector suppresses getters proxies and malformed protocol values without throwing', () => {
  const { collector, lines } = setup(); let invoked = false
  const getter = Object.defineProperty({}, 'type', { get() { invoked = true; throw Error(token) } })
  collector.handle('Runtime.consoleAPICalled', getter)
  collector.handle('Runtime.consoleAPICalled', new Proxy({}, { getOwnPropertyDescriptor() { throw Error(token) } }))
  for (const timestamp of [NaN, Infinity, -1, Number.MAX_SAFE_INTEGER, token]) {
    collector.handle('Runtime.consoleAPICalled', { ...consoleEvent(encoded(base('ARM'))), timestamp })
    collector.handle('Network.requestWillBeSent', start({ timestamp }))
  }
  collector.finish()
  assert.equal(invoked, false); assert.equal(lines.length, 1); assert.ok(!lines.join('').includes(token))
  assert.equal(rows(lines)[0].rej, 11)
})

test('status collector bounds frontend rows and emits one final capacity warning', () => {
  const { collector, lines } = setup()
  for (let i = 0; i < 140; i++) collector.handle('Runtime.consoleAPICalled', consoleEvent(encoded(base('ARM'))))
  collector.finish(); collector.finish()
  collector.handle('Runtime.consoleAPICalled', consoleEvent(encoded(base('ARM'))))
  assert.equal(lines.length, 129); assert.equal(rows(lines).at(-1).js, 128); assert.equal(rows(lines).at(-1).over, true)
  assert.ok(lines.every(line => Buffer.byteLength(line.trimEnd()) <= 512))
  assert.deepEqual(rows(lines).map(row => row.q), Array.from({ length: 129 }, (_, i) => i + 1))
})

test('status collector caps all event rows while retaining a final incomplete metadata row', () => {
  const { collector, lines } = setup(), event = start()
  collector.handle('Network.requestWillBeSent', event)
  for (let i = 0; i < 600; i++) collector.handle('Page.frameNavigated', { frame: {
    id: event.frameId, loaderId: event.loaderId, url: 'https://127.0.0.1:17861/' } })
  collector.finish()
  assert.equal(lines.length, 512); assert.equal(rows(lines).at(-1).e, 'META'); assert.equal(rows(lines).at(-1).over, true)
  assert.ok(Buffer.byteLength(lines.join('')) < 512 * 513)
})

test('status collector sink failures remain diagnostic only and never expose thrown content', () => {
  const collector = new ProbeStatusDiagnostics(() => { throw Error(token) })
  assert.doesNotThrow(() => collector.handle('Runtime.consoleAPICalled', consoleEvent(encoded(base('ARM')))))
  assert.doesNotThrow(() => collector.finish())
})

test('status collector integration preserves failed request counters and the original closed driver schema', () => {
  const journal = new NetworkJournal(async () => ({}), async () => {}), lines = []
  journal.diagnostics = new ProbeStatusDiagnostics(line => lines.push(line))
  const event = start(); journal.handle('Network.requestWillBeSent', event)
  journal.handle('Network.loadingFailed', { requestId: event.requestId, timestamp: 100.5, canceled: true, errorText: token })
  assert.equal(journal.counters.failedRequests, 1); assert.equal(journal.failure, false)
  assert.equal(Object.hasOwn(journal.evidence(), 'diagnostics'), false)
  journal.diagnostics.finish()
  assert.equal(rows(lines)[1].ec, 'OTHER'); assert.ok(!lines.join('').includes(token))
})

test('status collector integration observes both real adapters and always finalizes close diagnostics', async () => {
  const raw = await readFile(new URL('./browser-driver.mjs', import.meta.url), 'utf8')
  assert.ok(raw.includes("'Log.entryAdded', 'Page.frameNavigated']) session.on(method, params => journal?.handle(method, params))"))
  assert.ok(raw.includes('message.sessionId === session) journal?.handle(message.method, message.params ?? {})'))
  assert.ok(raw.includes('finally { journal.diagnostics.finish() }'))
  assert.ok(raw.includes('journal?.diagnostics.finish()'))
  assert.ok(!raw.includes('CW_PROBE_STATUS:'))
})
