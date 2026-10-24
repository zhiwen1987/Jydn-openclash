// Protocol models only. No product server, browser, socket or TLS is run.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { OverviewJournal } from './overview-journal.mjs'
import { sha, ORIGIN } from './wire-contract.mjs'
import { FAVICON } from '../subscription-ui-browser/ui-contract.mjs'

const contract = JSON.parse(readFileSync(new URL('../../deploy/overview-ui-browser/contract.json', import.meta.url), 'utf8'))
const rawJSON = value => Buffer.from(JSON.stringify(value))
const encoded = raw => ({ body: raw.toString('base64'), base64Encoded: true })
const canary = 'f'.repeat(64)
function harness(profile = 'evidence_disabled', overrides = {}) {
  const c = structuredClone(contract), bodies = new Map(), document = Buffer.from('<!doctype html><title>synthetic</title>'), asset = Buffer.from('/* synthetic asset */')
  const expected = new Map([['index.html', { bytes: document.length, sha256: sha(document) }], ['assets/main.js', { bytes: asset.length, sha256: sha(asset) }]])
  const read = overrides.reader ?? (id => { const body = bodies.get(id); if (body instanceof Error) throw body; return encoded(body) })
  const j = new OverviewJournal(c, profile, { allowed: ['/assets/main.js'], required: ['/assets/main.js'] }, [canary], read, expected)
  let number = 0
  const start = (path, raw, extra = {}) => {
    const id = 'private-' + ++number, timestamp = number + 1
    bodies.set(id, raw)
    j.handle('Network.requestWillBeSent', { requestId: id, timestamp, wallTime: 1700000000 + number, request: { url: ORIGIN + path, method: 'GET', headers: {}, ...extra } })
    return { id, timestamp, path }
  }
  const headers = (r, status = r.path === '/api/v1/overview' && profile === 'evidence_disabled' ? 503 : 200, extra = {}) => {
    j.handle('Network.responseReceived', { requestId: r.id, timestamp: r.timestamp + 0.2, response: { url: ORIGIN + r.path, status, mimeType: r.path === '/' ? 'text/html' : r.path.endsWith('.js') ? 'text/javascript' : 'application/json', headers: { 'Content-Type': 'application/json; charset=utf-8' }, ...extra } })
  }
  const finish = r => j.handle('Network.loadingFinished', { requestId: r.id, timestamp: r.timestamp + 0.1, encodedDataLength: 100 })
  const fail = (r, extra = {}) => j.handle('Network.loadingFailed', { requestId: r.id, timestamp: r.timestamp + 0.1, canceled: true, ...extra })
  const log = (r, extra = {}) => j.handle('Log.entryAdded', { entry: { source: 'network', level: 'error', url: ORIGIN + r.path, networkRequestId: r.id, text: canary, ...extra } })
  const one = (path, raw, mode = 'finish', details = {}, beforeTerminal = () => {}) => { const r = start(path, raw); headers(r); beforeTerminal(r); mode === 'fail' ? fail(r, details) : finish(r); return r }
  const overview = () => profile === 'evidence_disabled' ? rawJSON(c.expected503Union.present.body) : rawJSON({ ...structuredClone(c.apiExpected.overviewEnabled), generatedAt: '2026-10-24T01:02:03.123456789Z' })
  const full = (first = {}) => {
    one('/', document); one('/assets/main.js', asset)
    const snapshot = Object.fromEntries(c.wireKeys.snapshot.map(k => [k, []])); Object.assign(snapshot, { product: 'synthetic', version: 'unit', dataSource: 'demo', mode: 'candidate', publishLocked: true, status: 'synthetic', draft: {} })
    one('/api/v1/snapshot', rawJSON(snapshot))
    let firstRequest
    for (let i = 0; i < c.profileFacts[profile].apiCounts.overview; i++) {
      const r = one('/api/v1/overview', i === 0 && first.raw !== undefined ? first.raw : overview(), i === 0 ? first.mode : 'finish', first.details, i === 0 ? first.beforeTerminal : undefined)
      if (i === 0) firstRequest = r
    }
    if (profile === 'evidence_enabled_unknown') { one('/api/v1/observations/status', rawJSON(c.apiExpected.observationStatusDisabled)); one('/api/v1/probes/status', rawJSON(c.apiExpected.probeStatusDisabled)) }
    return firstRequest
  }
  const settle = async () => { while (j.tasks.size) await Promise.all([...j.tasks]) }
  return { c, j, bodies, start, headers, finish, fail, log, one, overview, full, settle, document, asset }
}

test('disabled 503 FINISH with actual bodies retains zero raw errors and complete body coverage', async () => {
  const h = harness(); h.full(); await h.settle(); h.j.complete(); h.j.beginClose(); h.j.finalize()
  assert.equal(h.j.qualification().errorBodyCompleteness, true); assert.equal(h.j.counters.captureErrors, 0)
  assert.equal(h.j.events.at(-1).type, 'META'); assert.equal(h.j.finalized, true)
  assert.deepEqual(h.j.rows[0].terminal, { event: 'FINISH', encodedDataLength: 100, canceled: null, blockedReasonPresent: null, corsErrorPresent: null })
  for (const phase of ['beforeTerminal', 'afterCapture']) {
    const observed = harness(), r = observed.full(phase === 'beforeTerminal' ? { beforeTerminal: request => observed.log(request) } : {})
    await observed.settle()
    if (phase === 'afterCapture') observed.log(r)
    observed.j.complete(); observed.j.beginClose(); observed.j.finalize()
    const q = observed.j.qualification(), event = observed.j.events.find(e => e.type === 'LOG_NETWORK_ERROR')
    assert.equal(q.rawCounters.consoleErrors, 1); assert.equal(q.unexpectedConsoleErrors, 0)
    assert.deepEqual(q.qualifiedExpected503NetworkLogs, [event.requestId])
    assert.deepEqual(event, { seq: event.seq, type: 'LOG_NETWORK_ERROR', requestId: event.requestId, source: 'network', level: 'error', urlSameRequest: true, workerIdPresent: false, categoryPresent: false, beforeClose: true })
    assert.equal(JSON.stringify(observed.j.events).includes(canary), false)
  }
})
test('disabled FINISH body RPC rejection preserves a qualified raw capture error', async () => {
  const h = harness(); h.full({ raw: new Error('private RPC text') }); await h.settle(); h.j.complete()
  const q = h.j.qualification(); assert.equal(q.rawCounters.captureErrors, 1); assert.equal(q.rawCounters.failedRequests, 0)
  assert.equal(q.qualifiedExpected503BodyUnavailable.length, 1); assert.equal(q.errorBodyCompleteness, false); assert.equal(q.unexpectedCaptureErrors, 0)
  const row = h.j.rows.find(r => r.bodyState === 'unavailable')
  for (const key of ['responseBytes', 'responseSHA256', 'responseBase64', 'errorCodeObserved']) assert.equal(row[key], null)
  assert.equal(JSON.stringify(h.j.events).includes('private RPC text'), false)
})
test('qualified canceled NET_FAIL with missing body retains both observed raw errors', async () => {
  const h = harness(); h.full({ mode: 'fail', raw: new Error('RPC rejected') }); await h.settle(); h.j.complete()
  const q = h.j.qualification(); assert.equal(q.rawCounters.failedRequests, 1); assert.equal(q.rawCounters.captureErrors, 1)
  assert.deepEqual(q.qualifiedExpected503ReportedCanceled, q.qualifiedExpected503BodyUnavailable)
  assert.equal(h.j.rows.find(r => r.terminal.event === 'NET_FAIL').terminal.encodedDataLength, null)
})
test('canceled NET_FAIL does not assume the error body must be unavailable', async () => {
  const h = harness(); h.full({ mode: 'fail' }); await h.settle(); h.j.complete()
  const q = h.j.qualification(); assert.equal(q.rawCounters.failedRequests, 1); assert.equal(q.rawCounters.captureErrors, 0); assert.equal(q.errorBodyCompleteness, true)
  assert.equal(h.j.rows.find(r => r.terminal.event === 'NET_FAIL').errorCodeObserved, 'overview_not_configured')
})
test('enabled unknown profile requires real complete 200 bodies and all raw errors zero', async () => {
  const h = harness('evidence_enabled_unknown'); h.full(); await h.settle(); h.j.complete()
  assert.equal(h.j.rows.filter(r => r.kind === 'OVERVIEW').length, 9); assert.equal(h.j.qualification().errorBodyCompleteness, null)
  assert.equal(Object.values(h.j.counters).every(v => v === 0), true)
})
test('a failed 200 body RPC never becomes an expected 503 body gap', async () => {
  const h = harness('evidence_enabled_unknown'); h.full({ raw: new Error('no body') }); await h.settle()
  assert.equal(h.j.failure, true); assert.equal(h.j.rows.some(r => r?.bodyState === 'unavailable'), false); assert.throws(() => h.j.complete())
})
test('fulfilled malformed UTF8 JSON schema size and body shapes cannot enter the RPC gap catch', async () => {
  const wrong = [Buffer.from([0xff]), Buffer.from('{'), rawJSON({ code: 'wrong', message: 'wrong' }), Buffer.alloc(65537, 32)]
  for (const raw of wrong) { const h = harness(); h.full({ raw }); await h.settle(); assert.equal(h.j.failure, true); assert.equal(h.j.qualification().qualifiedExpected503BodyUnavailable.length, 0) }
  for (const value of [{ body: '!!!!', base64Encoded: true }, { body: '{}', base64Encoded: 'false' }, { body: '{}', base64Encoded: false, extra: 1 }]) {
    const h = harness('evidence_disabled', { reader: () => value }); h.one('/api/v1/overview', Buffer.from('{}')); await h.settle()
    assert.equal(h.j.failure, true); assert.equal(h.j.qualification().qualifiedExpected503BodyUnavailable.length, 0)
  }
})
test('a secret fence rejection on a fulfilled 503 is fatal and never qualified as missing body', async () => {
  const h = harness(); h.full({ raw: rawJSON({ code: 'overview_not_configured', message: canary }) }); await h.settle()
  assert.equal(h.j.failure, true); assert.equal(h.j.qualification().qualifiedExpected503BodyUnavailable.length, 0)
  assert.equal(JSON.stringify(h.j.events).includes(canary), false)
})
test('NET_FAIL requires actual canceled true without blocked or CORS evidence', async () => {
  for (const details of [{ canceled: false }, { canceled: undefined }, { blockedReason: 'other' }, { corsErrorStatus: {} }]) {
    const h = harness(); h.full({ mode: 'fail', details }); await h.settle(); assert.equal(h.j.failure, true); assert.throws(() => h.j.complete())
  }
})
test('NET_FAIL on a 200 document or enabled overview always fails', async () => {
  for (const [profile, path] of [['evidence_disabled', '/'], ['evidence_enabled_unknown', '/api/v1/overview']]) {
    const h = harness(profile), r = h.start(path, path === '/' ? h.document : h.overview()); h.headers(r); h.fail(r); await h.settle()
    assert.equal(h.j.failure, true); assert.equal(h.j.counters.failedRequests, 1)
  }
})
test('response status MIME redirects cookies cache and service workers remain hard failures', async () => {
  for (const extra of [{ status: 403 }, { mimeType: 'text/html' }, { url: ORIGIN + '/other' }, { headers: { 'Set-Cookie': 'unit' } }, { fromDiskCache: true }, { fromServiceWorker: true }]) {
    const h = harness(), r = h.start('/api/v1/overview', h.overview()); h.headers(r, 503, extra); h.finish(r); await h.settle()
    assert.equal(h.j.failure, true); assert.throws(() => h.j.complete())
  }
})
test('credentials unsafe origins and extra overview requests preserve forbidden counters', async () => {
  for (const extra of [{ headers: { Authorization: 'unit' } }, { url: 'https://example.com/' }, { url: ORIGIN + '/api/v1/overview?' }]) {
    const h = harness(); h.start('/api/v1/overview', h.overview(), extra); assert.equal(h.j.counters.forbiddenRequests, 1); assert.equal(h.j.failure, true)
  }
  const h = harness(); h.full(); await h.settle(); h.one('/api/v1/overview', h.overview()); await h.settle(); assert.equal(h.j.failure, true); assert.equal(h.j.counters.forbiddenRequests, 1)
})
test('duplicate request header and terminal events cannot be accepted as retries', async () => {
  const h = harness(), r = h.start('/api/v1/overview', h.overview()); h.headers(r); h.headers(r); h.finish(r); h.finish(r); await h.settle()
  assert.equal(h.j.failure, true); assert.throws(() => h.j.complete())
  const h2 = harness(), r2 = h2.start('/api/v1/overview', h2.overview()); h2.j.handle('Network.requestWillBeSent', { requestId: r2.id }); assert.equal(h2.j.failure, true)
})
test('network completion may predate the header notification but not its own request start', async () => {
  const h = harness(); h.full(); await h.settle(); h.j.complete()
  assert.equal(h.j.rows.every(r => r.endTimeUs < r.headerTimeUs && r.endTimeUs >= r.startTimeUs), true)
  const h2 = harness(), r = h2.start('/api/v1/overview', h2.overview()); h2.headers(r)
  h2.j.handle('Network.loadingFinished', { requestId: r.id, timestamp: r.timestamp - 1, encodedDataLength: 1 }); assert.equal(h2.j.failure, true)
})
test('document and asset bytes must match the actual build metadata exactly', async () => {
  const h = harness(); h.one('/', Buffer.from('wrong source bytes')); await h.settle(); assert.equal(h.j.failure, true)
  const h2 = harness(); h2.one('/assets/main.js', Buffer.from('wrong asset bytes')); await h2.settle(); assert.equal(h2.j.failure, true)
})
test('capture ordinals follow terminal events even when body promises settle in reverse order', async () => {
  const resolvers = new Map(), h = harness('evidence_disabled', { reader: id => new Promise(resolve => resolvers.set(id, resolve)) })
  const one = h.one('/api/v1/overview', h.overview()), two = h.one('/api/v1/overview', h.overview())
  assert.throws(() => h.j.beginClose()); assert.equal(h.j.closing, false)
  resolvers.get(two.id)(encoded(h.overview())); await Promise.resolve(); resolvers.get(one.id)(encoded(h.overview())); await h.settle()
  assert.deepEqual(h.j.rows.map(r => [r.ordinal, r.requestId]), [[1, 'r1'], [2, 'r2']])
  assert.deepEqual(h.j.events.filter(e => e.type === 'CAPTURE').map(e => e.captureOrdinal), [2, 1])
})
test('browser cleanup cannot manufacture a qualified expected cancellation', async () => {
  const h = harness(); h.full(); await h.settle(); h.j.beginClose()
  h.one('/api/v1/overview', new Error('after close'), 'fail'); await h.settle(); assert.equal(h.j.failure, true); assert.throws(() => h.j.finalize())
})
test('event and decoded-byte budgets fail without zeroing their failure counters', async () => {
  const h = harness(); h.j.b.events = 1; h.one('/api/v1/overview', h.overview()); await h.settle(); assert.equal(h.j.failure, true); assert.equal(h.j.overflow, true); assert.ok(h.j.counters.captureErrors > 0)
  const h2 = harness(), r = h2.start('/api/v1/overview', h2.overview()); h2.headers(r); h2.j.b.decodedTotal = 1
  h2.j.handle('Network.loadingFinished', { requestId: r.id, timestamp: r.timestamp + 0.1, encodedDataLength: 0 }); await h2.settle(); assert.equal(h2.j.failure, true)
})
test('qualification cannot subtract unobserved errors or hide runtime warnings', async () => {
  assert.equal(harness().j.qualification().errorBodyCompleteness, false)
  const h = harness(); h.full(); await h.settle(); h.j.counters.captureErrors = 1
  assert.equal(h.j.qualification().unexpectedCaptureErrors, 1); assert.throws(() => h.j.complete())
  const h2 = harness(); h2.full(); await h2.settle(); h2.j.handle('Runtime.consoleAPICalled', { type: 'warning' })
  assert.equal(h2.j.counters.consoleWarnings, 1); assert.throws(() => h2.j.complete())
  for (const extra of [{ source: 'javascript' }, { source: 'security' }, { level: 'warning' }, { networkRequestId: undefined }, { networkRequestId: 'unobserved' }, { url: ORIGIN + '/api/v1/overview?' }, { url: undefined }, { workerId: undefined }, { workerId: null }, { category: 'cors' }, { category: undefined }]) {
    const bad = harness(), r = bad.full(); await bad.settle(); bad.log(r, extra)
    assert.equal(bad.j.failure, true); assert.throws(() => bad.j.complete())
    assert.equal(bad.j.qualification().qualifiedExpected503NetworkLogs.length, 0)
    assert.equal(bad.j.counters.consoleErrors + bad.j.counters.consoleWarnings + bad.j.counters.cspErrors, 1)
    assert.equal(JSON.stringify(bad.j.events).includes(canary), false)
  }
  for (const path of ['/', '/assets/main.js']) {
    const bad = harness(), r = bad.one(path, path === '/' ? bad.document : bad.asset); await bad.settle(); bad.log(r)
    assert.equal(bad.j.failure, true); assert.equal(bad.j.qualification().unexpectedConsoleErrors, 1)
  }
  const enabled = harness('evidence_enabled_unknown'), enabledRequest = enabled.full(); await enabled.settle(); enabled.log(enabledRequest)
  assert.equal(enabled.j.failure, true); assert.equal(enabled.j.qualification().unexpectedConsoleErrors, 1)
  const tooEarly = harness(), earlyRequest = tooEarly.start('/api/v1/overview', tooEarly.overview()); tooEarly.log(earlyRequest)
  assert.equal(tooEarly.j.failure, true); assert.equal(tooEarly.j.qualification().qualifiedExpected503NetworkLogs.length, 0)
  const tooLate = harness(), lateRequest = tooLate.full(); await tooLate.settle(); tooLate.j.beginClose(); tooLate.log(lateRequest)
  assert.equal(tooLate.j.failure, true); assert.throws(() => tooLate.j.finalize())
  const duplicate = harness(), duplicateRequest = duplicate.full(); await duplicate.settle(); duplicate.log(duplicateRequest); duplicate.log(duplicateRequest)
  assert.equal(duplicate.j.counters.consoleErrors, 2); assert.equal(duplicate.j.qualification().unexpectedConsoleErrors, 1); assert.throws(() => duplicate.j.complete())
  const unrelated = harness(), associated = unrelated.full(); await unrelated.settle(); unrelated.log(associated); unrelated.j.handle('Runtime.consoleAPICalled', { type: 'error' })
  assert.equal(unrelated.j.counters.consoleErrors, 2); assert.equal(unrelated.j.qualification().unexpectedConsoleErrors, 1); assert.throws(() => unrelated.j.complete())
  const forged = harness(), known = forged.full(); await forged.settle(); forged.log(known); forged.j.counters.consoleErrors = 0
  assert.equal(forged.j.qualification().unexpectedConsoleErrors, -1); assert.throws(() => forged.j.complete())
  const malformed = harness(); malformed.j.handle('Log.entryAdded', { entry: { source: 'network' } })
  assert.equal(malformed.j.failure, true); assert.equal(malformed.j.counters.captureErrors, 1)
  const informational = harness(), infoRequest = informational.full(); await informational.settle()
  informational.log(infoRequest, { level: 'info' }); informational.log(infoRequest, { level: 'verbose' }); informational.j.complete()
  assert.equal(informational.j.qualification().qualifiedExpected503NetworkLogs.length, 0)
})
test('only the fixed data favicon is ignored with a bounded non-reused request identity', () => {
  const h = harness()
  for (let i = 0; i < 4; i++) h.j.handle('Network.requestWillBeSent', { requestId: 'icon' + i, request: { url: FAVICON, method: 'GET' } })
  assert.equal(h.j.ignored.size, 4); assert.equal(h.j.requests.size, 0)
  h.j.handle('Network.requestWillBeSent', { requestId: 'icon4', request: { url: FAVICON, method: 'GET' } }); assert.equal(h.j.failure, true)
  for (const extra of [{ method: 'POST' }, { headers: { Authorization: 'unit' } }, { headers: { Cookie: 'unit' } }, { hasPostData: true }, { postData: '' }]) {
    const bad = harness(); bad.j.handle('Network.requestWillBeSent', { requestId: 'bad-icon', request: { url: FAVICON, method: 'GET', ...extra } })
    assert.equal(bad.j.failure, true); assert.equal(bad.j.ignored.size, 0); assert.equal(bad.j.counters.forbiddenRequests, 1)
  }
  const redirected = harness(); redirected.j.handle('Network.requestWillBeSent', { requestId: 'bad-icon', redirectResponse: {}, request: { url: FAVICON, method: 'GET' } }); assert.equal(redirected.j.failure, true)
})
