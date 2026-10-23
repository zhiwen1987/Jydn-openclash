// Frozen synthetic contracts only: no real browser/server/network/Go/namespace.
import assert from 'node:assert/strict'
import test from 'node:test'
import { readFile } from 'node:fs/promises'
import { ORIGIN, BODY_LIMIT, CASES, sha, parseArguments, parseProcess, versionProjection,
  expectedBody, responseBody, requestCase, readInPage, validateCase } from './matrix-contract.mjs'
import { MatrixJournal } from './matrix-driver.mjs'
const names = [], unit = (name, body) => { names.push(name); test(name, body) }
const uuid = 'a'.repeat(32), sentinel = 'PRIVATE_SENTINEL'
const args = engine => ['--root', '/tmp/chengwang-stream-matrix-' + uuid, '--bundle', '/tmp/chengwang-stream-tools-' + uuid,
  '--engine', engine ?? 'chrome-cdp', '--source-commit', 'b'.repeat(40)]
const reject = run => assert.throws(run)
const js = id => id.endsWith('-success') ? { bytes: expectedBody(id).length, eof: true, readEnd: 'EOF_OK',
  signalAborted: false, abortRequested: false, abortError: false, cancelAttempted: false, cancelCompleted: false,
  parsed: true, sha256: sha(expectedBody(id)), elapsedMs: 20, chunks: 2 }
  : { bytes: id === 'oversize' ? BODY_LIMIT + 1 : 6, eof: false,
    readEnd: id === 'oversize' ? 'SIZE_REJECT' : id === 'abort' ? 'ABORT_ERROR' : 'READ_ERROR',
    signalAborted: id === 'abort', abortRequested: id === 'abort', abortError: id === 'abort',
    cancelAttempted: true, cancelCompleted: id === 'oversize', parsed: false, sha256: null, elapsedMs: 20, chunks: 2 }
const terminal = id => id.endsWith('-success') || id === 'oversize'
  ? { event: 'FINISH', canceled: 'UNSPECIFIED', errorCode: 'NONE' }
  : { event: 'FAIL', canceled: id === 'abort' ? 'YES' : 'NO', errorCode: id === 'abort' ? 'ABORTED' : 'CONTENT_LENGTH_MISMATCH' }
const result = id => ({ case: id, js: js(id), networkOrdinal: CASES.indexOf(id) + 2, requestId: '123.' + (CASES.indexOf(id) + 2),
  terminal: terminal(id), hostBody: id.endsWith('-success') ? { bytes: expectedBody(id).length, sha256: sha(expectedBody(id)) } : null })
function start(journal, id, ordinal = journal.requests.size + 1) {
  const requestId = '123.' + ordinal, url = ORIGIN + (id === 'DOCUMENT' ? '/' : '/case/' + id)
  journal.handle('Network.requestWillBeSent', { requestId, timestamp: ordinal, wallTime: 1700000000 + ordinal,
    type: id === 'DOCUMENT' ? 'Document' : 'Fetch', request: { url, method: 'GET', headers: {} } })
  return requestId
}
function headers(journal, id, requestId, changed = {}) {
  const mime = id === 'DOCUMENT' ? 'text/html' : 'application/json'
  const h = { 'cache-control': 'no-store', 'content-type': mime }
  if (id !== 'oversize') h['content-length'] = String(id === 'DOCUMENT' ? 25 : expectedBody(id).length)
  journal.handle('Network.responseReceived', { requestId, timestamp: journal.requests.size + .1,
    response: { url: ORIGIN + (id === 'DOCUMENT' ? '/' : '/case/' + id), status: 200, mimeType: mime, headers: h, ...changed } })
}
function end(journal, id, requestId) {
  const failed = ['truncated', 'abort'].includes(id)
  journal.handle(failed ? 'Network.loadingFailed' : 'Network.loadingFinished', { requestId,
    timestamp: journal.requests.size + .2, encodedDataLength: 300,
    canceled: id === 'abort', errorText: id === 'abort' ? 'net::ERR_ABORTED' : 'net::ERR_CONTENT_LENGTH_MISMATCH' })
}
const filled = () => { const j = new MatrixJournal(); for (const id of ['DOCUMENT', ...CASES]) { const r = start(j, id); headers(j, id, r); end(j, id, r) }; return j }
async function fakePage(id, mode = 'normal') {
  const original = globalThis.fetch, calls = []; let index = 0, signal
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options }); signal = options.signal
    if (mode === 'fetch-error') throw Error(sentinel)
    const body = expectedBody(id), first = id === 'boundary-success' || id === 'oversize' ? body.length >> 1 : 6
    const reader = { async read() {
      if (index++ === 0) return { done: false, value: Uint8Array.from(body.subarray(0, first)) }
      if (id === 'truncated') throw TypeError(sentinel)
      if (id === 'abort' && signal.aborted) throw new DOMException(sentinel, 'AbortError')
      if (index === 2) return { done: false, value: Uint8Array.from(body.subarray(first)) }
      return { done: true }
    }, async cancel() { if (id === 'truncated' || id === 'abort') throw TypeError(sentinel) }, releaseLock() {} }
    return { status: mode === 'headers-error' ? 403 : 200,
      headers: new Map([['content-type', 'application/json'], ['cache-control', 'no-store']]), body: { getReader: () => reader } }
  }
  try { return { value: await readInPage(id), calls } } finally { globalThis.fetch = original }
}

unit('matrix arguments accept only both engines and exact fixture siblings', () => {
  for (const engine of ['chrome-cdp', 'playwright']) { const o = parseArguments(args(engine)); assert.equal(o.engine, engine); assert.equal(o.fixtureId, uuid) }
})
unit('matrix arguments reject duplicate missing extra and unknown options', () => {
  for (const a of [args().slice(2), [...args(), '--extra', 'x'], ['--root', 'x', ...args().slice(0, 6)], ['--alias', ...args().slice(1)]]) reject(() => parseArguments(a))
})
unit('matrix arguments reject traversal aliases mismatched fixtures and nonhex commits', () => {
  for (const [index, value] of [[1, '/tmp'], [1, args()[1] + '/'], [3, args()[3].replace(uuid, 'c'.repeat(32))], [5, 'cdp'], [7, 'b'.repeat(40) + '\n']]) {
    const a = args(); a[index] = value; reject(() => parseArguments(a))
  }
})
unit('matrix isolated alpha package and lock match the committed reference pin', async () => {
  const read = path => readFile(new URL(path, import.meta.url), 'utf8').then(JSON.parse)
  const [p, lock, pin] = await Promise.all([read('./package.json'), read('./package-lock.json'), read('../browser-runtime-candidate/pin.json')])
  const dependency = lock.packages['node_modules/playwright-core']
  assert.equal(p.devDependencies['playwright-core'], pin.playwrightCandidate.version)
  assert.equal(dependency.version, pin.playwrightCandidate.version); assert.equal(dependency.resolved, pin.playwrightCandidate.tarball)
  assert.equal(dependency.integrity, pin.playwrightCandidate.integrity); assert.ok(!p.scripts)
})
unit('matrix version projection retains observed revision and excludes user agent', () => {
  assert.deepEqual(versionProjection({ product: 'Chrome/157.0.8103.6', revision: '@' + '0'.repeat(40), protocolVersion: '1.3', userAgent: sentinel }), {
    product: 'Chrome/157.0.8103.6', revision: '@' + '0'.repeat(40), protocolVersion: '1.3' })
})
unit('matrix version projection rejects unsafe or fabricated protocol fields', () => {
  const v = { product: 'Chrome/157.0.8103.6', revision: '@' + 'c'.repeat(40), protocolVersion: '1.3' }
  for (const [k, value] of [['product', sentinel], ['revision', 'c'.repeat(40)], ['protocolVersion', '1.3\n']]) reject(() => versionProjection({ ...v, [k]: value }))
})
unit('matrix proc parser handles parentheses while preserving pid session and start ticks', () => {
  const f = ['S', '1', '12', '12', ...Array(15).fill('0'), '345']
  assert.deepEqual(parseProcess('12 (chrome (x)) ' + f.join(' ')), { pid: 12, group: 12, session: 12, startTicks: 345, state: 'S' })
})
unit('matrix proc parser rejects short zero and unsafe process records', () => {
  for (const v of ['', '1 (chrome) S 0', '12 (chrome) ' + Array(20).fill('0').join(' ')]) reject(() => parseProcess(v))
})
unit('matrix expected payloads preserve exact eleven boundary and oversize byte counts', () => {
  assert.equal(expectedBody('split-success').toString(), '{"ok":true}')
  assert.equal(expectedBody('boundary-success').length, BODY_LIMIT); assert.equal(expectedBody('oversize').length, BODY_LIMIT + 1)
  assert.equal(JSON.parse(expectedBody('boundary-success')).data.length, BODY_LIMIT - 11)
})
unit('matrix host response projection reads bounded utf8 and canonical base64 only', () => {
  const b = expectedBody('split-success')
  for (const base64Encoded of [false, true]) assert.deepEqual(responseBody({ body: b.toString(base64Encoded ? 'base64' : 'utf8'), base64Encoded }), b)
})
unit('matrix host response projection rejects malformed oversize and extra fields', () => {
  for (const v of [{ body: 'a'.repeat(BODY_LIMIT + 1), base64Encoded: false }, { body: '!', base64Encoded: true }, { body: '{}', base64Encoded: false, raw: sentinel }]) reject(() => responseBody(v))
})
unit('matrix requests allow the single document and five exact unauthenticated GET paths', () => {
  for (const id of ['DOCUMENT', ...CASES]) assert.equal(requestCase({ url: ORIGIN + (id === 'DOCUMENT' ? '/' : '/case/' + id), method: 'GET', headers: {} }), id)
})
unit('matrix requests reject query foreign origin extra resources credentials and post', () => {
  for (const v of [{ url: ORIGIN + '/case/abort?x=1', method: 'GET' }, { url: 'https://example.com/', method: 'GET' },
    { url: ORIGIN + '/favicon.ico', method: 'GET' }, { url: ORIGIN + '/', method: 'POST' },
    { url: ORIGIN + '/', method: 'GET', headers: { Authorization: sentinel } }]) reject(() => requestCase(v))
})
unit('matrix positive case acceptance requires exact eof json digest host and native finish', () => {
  for (const id of ['split-success', 'boundary-success']) assert.equal(validateCase(result(id)).case, id)
})
unit('matrix negative acceptance keeps oversize truncation and explicit abort distinct', () => {
  for (const id of ['oversize', 'truncated', 'abort']) assert.equal(validateCase(result(id)).case, id)
  const value = result('oversize'); value.terminal = { event: 'FAIL', canceled: 'YES', errorCode: 'ABORTED' }; validateCase(value)
})
unit('matrix case validation rejects simulated successful failures and substituted host bytes', () => {
  for (const [id, change] of [['split-success', v => { v.terminal.event = 'FAIL' }], ['boundary-success', v => { v.hostBody.sha256 = '0'.repeat(64) }],
    ['oversize', v => { v.js.bytes = BODY_LIMIT }], ['truncated', v => { v.js.eof = true }], ['abort', v => { v.js.abortRequested = false }]]) {
    const value = result(id); change(value); reject(() => validateCase(value))
  }
})
unit('matrix journal binds six unique native request identities and eighteen closed rows', () => {
  const j = filled(); j.complete(); assert.equal(j.requests.size, 6); assert.equal(j.rows.length, 18)
  assert.deepEqual([...j.byCase.keys()], ['DOCUMENT', ...CASES]); assert.equal(j.rows[0].clock, 'CDP_MONOTONIC_US')
})
unit('matrix journal rejects duplicates redirects and reused case identities', () => {
  const j = new MatrixJournal(); const r = start(j, 'DOCUMENT'); start(j, 'DOCUMENT', 2)
  assert.equal(j.failure, true); assert.ok(j.counters.captureErrors > 0); assert.equal(j.requests.size, 1)
  j.handle('Network.requestWillBeSent', { requestId: r, redirectResponse: {}, request: { url: ORIGIN + '/', method: 'GET' } })
  reject(() => j.complete())
})
unit('matrix journal rejects changed no store mime length and missing native response', () => {
  for (const changed of [{ headers: { 'cache-control': 'no-cache', 'content-type': 'text/html' } }, { mimeType: 'application/json' }, { status: 403 }]) {
    const j = new MatrixJournal(), r = start(j, 'DOCUMENT'); headers(j, 'DOCUMENT', r, changed); assert.equal(j.failure, true)
  }
})
unit('matrix journal never ignores a failed document or positive request', () => {
  for (const id of ['DOCUMENT', 'split-success', 'boundary-success']) {
    const j = new MatrixJournal()
    for (const earlier of ['DOCUMENT', ...CASES].slice(0, ['DOCUMENT', ...CASES].indexOf(id))) { const r = start(j, earlier); headers(j, earlier, r); end(j, earlier, r) }
    const r = start(j, id); headers(j, id, r); j.handle('Network.loadingFailed', { requestId: r, timestamp: 10, canceled: true, errorText: 'net::ERR_ABORTED' })
    assert.equal(j.counters.unexpectedFailedRequests, 1)
  }
})
unit('matrix journal missing or duplicate terminal observations cannot complete', () => {
  const j = filled(), r = j.byCase.get('abort').requestId
  j.handle('Network.loadingFailed', { requestId: r, timestamp: 9, errorText: 'net::ERR_ABORTED' }); reject(() => j.complete())
  const missing = filled(); missing.byCase.get('abort').terminal = null; reject(() => missing.complete())
})
unit('matrix journal independently preserves runtime console warning and security errors', () => {
  const j = filled()
  j.handle('Runtime.exceptionThrown', {}); j.handle('Runtime.consoleAPICalled', { type: 'error' }); j.handle('Runtime.consoleAPICalled', { type: 'warning' })
  j.handle('Log.entryAdded', { entry: { source: 'security', level: 'error' } })
  for (const k of ['runtimeErrors', 'consoleErrors', 'consoleWarnings', 'cspErrors']) assert.equal(j.counters[k], 1)
  reject(() => j.complete())
})
unit('matrix native journal exports no response bodies headers or arbitrary error text', () => {
  const j = filled(); assert.ok(!JSON.stringify(j.rows).includes(sentinel))
  assert.ok(j.rows.every(r => !Object.hasOwn(r, 'headers') && !Object.hasOwn(r, 'body') && !Object.hasOwn(r, 'errorText')))
})
unit('matrix synthetic page stream split positive reads eof and exact digest once', async () => {
  const { value, calls } = await fakePage('split-success'); assert.equal(calls.length, 1); assert.equal(value.readEnd, 'EOF_OK')
  assert.equal(value.bytes, 11); assert.equal(value.eof, true); assert.equal(value.sha256, sha(expectedBody('split-success')))
})
unit('matrix synthetic page exact one mib positive keeps the hard size boundary', async () => {
  const { value } = await fakePage('boundary-success'); assert.equal(value.bytes, BODY_LIMIT); assert.equal(value.parsed, true); assert.equal(value.sha256, sha(expectedBody('boundary-success')))
})
unit('matrix synthetic page oversize observes the extra byte and cancels without eof', async () => {
  const { value } = await fakePage('oversize'); assert.equal(value.bytes, BODY_LIMIT + 1); assert.equal(value.readEnd, 'SIZE_REJECT')
  assert.equal(value.eof, false); assert.equal(value.cancelAttempted, true); assert.equal(value.cancelCompleted, true); assert.equal(value.sha256, null)
})
unit('matrix synthetic page truncation preserves six bytes and actual read rejection', async () => {
  const { value } = await fakePage('truncated'); assert.equal(value.bytes, 6); assert.equal(value.readEnd, 'READ_ERROR'); assert.equal(value.eof, false); assert.equal(value.abortRequested, false)
})
unit('matrix synthetic page explicitly aborts after its first read and observes abort error', async () => {
  const { value } = await fakePage('abort'); assert.equal(value.bytes, 6); assert.equal(value.readEnd, 'ABORT_ERROR')
  assert.equal(value.abortRequested, true); assert.equal(value.abortError, true); assert.equal(value.signalAborted, true); assert.equal(value.eof, false)
})
unit('matrix synthetic page rejects fetch and headers without inventing usable bytes', async () => {
  for (const [mode, kind] of [['fetch-error', 'FETCH_ERROR'], ['headers-error', 'HEADERS_REJECT']]) {
    const { value, calls } = await fakePage('split-success', mode); assert.equal(value.bytes, 0); assert.equal(value.readEnd, kind); assert.equal(calls.length, 1)
    assert.ok(!JSON.stringify(value).includes(sentinel))
  }
})
unit('matrix page function serializes bounded reader code without response cloning or json shortcut', () => {
  const raw = readInPage.toString(); assert.ok(raw.includes('response.body.getReader()')); assert.ok(raw.includes('out.bytes > limit'))
  assert.ok(!raw.includes('.json(')); assert.ok(!raw.includes('.clone(')); assert.ok(raw.includes("cache: 'no-store'"))
})
unit('matrix real adapters retain native playwright evaluation and supervisor readiness gate', async () => {
  const raw = await readFile(new URL('./matrix-driver.mjs', import.meta.url), 'utf8')
  for (const text of ["launchPersistentContext(o.profile", 'await page.evaluate(readInPage, id)', "new Transport(socket)", "browserSend('Browser.getVersion')",
    "'/driver-ready.private.json'", "'/run.go'", 'await link(pending, path); await unlink(pending)']) assert.ok(raw.includes(text))
})
unit('matrix close evidence requires launcher wait and scopes process absence precisely', async () => {
  const raw = await readFile(new URL('./matrix-driver.mjs', import.meta.url), 'utf8')
  for (const text of ['chromeExit.joined === true', 'chromeExit.forced === false', 'launcherExit?.code === 0',
    "processScope: 'CHROME_SESSION_AND_LAUNCHER_ONLY'", 'await until(() => noLiveChrome(o, chrome), 5000)']) assert.ok(raw.includes(text))
})

assert.equal(names.length, 32)
assert.equal(new Set(names).size, 32)
assert.equal(sha([...names].sort().join('\n') + '\n'), 'f431b2b6b833b57ca39cb0e30ad0eb93d224ae20b32dd91500b1cb49a0404abb')
