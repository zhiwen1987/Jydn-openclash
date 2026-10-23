// Pure/fake contracts only. No browser, network, NSS, namespace or Go process.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { validateLaunchOptions, parseProcessStat, parseChromeStat, safeRequest, responseBytes, NetworkJournal,
  collectProbeDOM, launchProbeDriver, remoteEvaluationValue, classifyLaunchError, launchFatalLocations,
  driverOperationFailure } from './browser-driver.mjs'

const sha = raw => createHash('sha256').update(raw).digest('hex')
const uuid = 'a'.repeat(32), root = '/tmp/chengwang-probe-readback-' + uuid
const options = () => ({ engine: 'chrome-cdp', root, chrome: '/opt/google/chrome/google-chrome',
  sourceRoot: '/tmp/chengwang-probe-harness-' + uuid + '/source',
  launcher: '/tmp/chengwang-probe-harness-' + uuid + '/chrome-launcher' })
const rejected = action => assert.throws(action, { message: 'probe browser driver rejected' })
const request = (path, headers = {}) => ({ url: 'https://127.0.0.1:17861' + path, method: 'GET', headers })
function emit(journal, id, path, body = '{}', status = 200) {
  journal.handle('Network.requestWillBeSent', { requestId: id, type: 'Fetch', request: request(path,
    path === '/api/v1/probes/details' ? { Authorization: 'Bearer private-sentinel' } : {}) })
  journal.handle('Network.responseReceived', { requestId: id,
    response: { url: 'https://127.0.0.1:17861' + path, status, mimeType: 'application/json' } })
  journal.handle('Network.loadingFinished', { requestId: id })
  return body
}

test('driver accepts only canonical engine and exact same UUID paths', () => {
  for (const engine of ['chrome-cdp', 'playwright']) {
    const value = options(); value.engine = engine
    const actual = validateLaunchOptions(value)
    assert.equal(actual.fixtureId, uuid); assert.equal(actual.profile, root + '/browser/chrome-profile')
    assert.equal(actual.browserRoot, root + '/browser'); assert.notEqual(actual, value)
  }
})

test('driver rejects aliases extra keys and malformed engine', () => {
  for (const engine of ['cdp', 'Chrome', '', null, 'private-sentinel']) rejected(() => validateLaunchOptions({ ...options(), engine }))
  rejected(() => validateLaunchOptions({ ...options(), allowInsecure: true }))
})

test('driver rejects broad noncanonical and mismatched fixture roots', () => {
  for (const value of ['/', '/tmp', root + '/', root + '/../other', root.replace(uuid, 'b'.repeat(32)), 'relative']) {
    rejected(() => validateLaunchOptions({ ...options(), root: value }))
  }
})

test('driver launcher and readonly source must be exact UUID siblings', () => {
  rejected(() => validateLaunchOptions({ ...options(), sourceRoot: root + '/writable-source' }))
  rejected(() => validateLaunchOptions({ ...options(), launcher: '/usr/bin/google-chrome' }))
  rejected(() => validateLaunchOptions({ ...options(), chrome: root + '/writable-chrome' }))
  rejected(() => validateLaunchOptions({ ...options(), chrome: '/opt/private\nsentinel' }))
})

test('driver parses proc command names containing spaces and parentheses', () => {
  const fields = ['S', '20', '42', '42', ...Array(15).fill('0'), '98765', '0']
  assert.deepEqual(parseChromeStat('42 (chrome (test)) ' + fields.join(' ')),
    { pid: 42, group: 42, session: 42, startTicks: 98765, state: 'S' })
  for (const [group, session] of [[0, 0], [0, 42], [42, 0]]) {
    const general = [...fields]; general[2] = String(group); general[3] = String(session)
    const raw = '42 (unrelated process (test)) ' + general.join(' ')
    assert.deepEqual(parseProcessStat(raw), { pid: 42, group, session, startTicks: 98765, state: 'S' })
    rejected(() => parseChromeStat(raw))
  }
})

test('driver rejects missing zero and unsafe process identities', () => {
  for (const raw of ['', '42 (chrome) S 1', '0 (chrome) ' + ['S', '1', '1', '1', ...Array(16).fill('0')].join(' ')]) {
    rejected(() => parseProcessStat(raw)); rejected(() => parseChromeStat(raw))
  }
  const fields = ['S', '20', '42', '42', ...Array(15).fill('0'), '98765', '0']
  for (const [index, invalid] of [[2, '-1'], [3, '-1'], [19, '0'], [19, '-1'],
    [2, '9007199254740992'], [3, '9007199254740992'], [19, '9007199254740992'], [2, 'NaN'], [3, 'Infinity']]) {
    const malformed = [...fields]; malformed[index] = invalid
    const raw = '42 (chrome) ' + malformed.join(' ')
    rejected(() => parseProcessStat(raw)); rejected(() => parseChromeStat(raw))
  }
  for (const pid of ['-1', '1', '9007199254740992']) {
    const raw = pid + ' (chrome) ' + fields.join(' ')
    rejected(() => parseProcessStat(raw)); rejected(() => parseChromeStat(raw))
  }
})

test('driver accepts only the required GET resources and auth placement', () => {
  assert.equal(safeRequest(request('/api/v1/probes/status'), 'Fetch').authorizationPresent, false)
  const actual = safeRequest(request('/api/v1/probes/details', { Authorization: 'Bearer private-sentinel' }), 'XHR')
  assert.deepEqual(actual, { url: 'https://127.0.0.1:17861/api/v1/probes/details', method: 'GET', authorizationPresent: true, resourceType: 'xhr' })
  rejected(() => safeRequest(request('/api/v1/probes/details'), 'XHR'))
  rejected(() => safeRequest(request('/api/v1/probes/status', { authorization: 'private-sentinel' }), 'Fetch'))
})

test('driver rejects foreign URL method query fragment credentials and path', () => {
  for (const url of ['private-sentinel', 'https://private-sentinel.example/', 'http://127.0.0.1:17861/',
    'https://127.0.0.1:17861/?token=private-sentinel', 'https://127.0.0.1:17861/#private-sentinel',
    'https://private-sentinel@127.0.0.1:17861/', 'https://127.0.0.1:17861/api/v1/publish']) rejected(() => safeRequest({ ...request('/'), url }, 'Document'))
  rejected(() => safeRequest({ ...request('/'), method: 'POST' }, 'Document'))
})

test('driver never retains sensitive headers and rejects cookies and proxies', () => {
  const actual = safeRequest(request('/api/v1/probes/details', { Authorization: 'Bearer private-sentinel' }), 'Fetch')
  assert.ok(!JSON.stringify(actual).includes('private-sentinel')); assert.ok(!Object.hasOwn(actual, 'headers'))
  for (const name of ['Cookie', 'Proxy-Authorization', 'Proxy-Connection']) rejected(() => safeRequest(request('/', { [name]: 'private-sentinel' }), 'Document'))
})

test('driver preserves bounded UTF8 and canonical base64 response bytes', () => {
  const raw = Buffer.from('真实证据\n')
  assert.deepEqual(responseBytes({ body: raw.toString('utf8'), base64Encoded: false }, 100), raw)
  assert.deepEqual(responseBytes({ body: raw.toString('base64'), base64Encoded: true }, 100), raw)
})

test('driver rejects oversize malformed base64 and invalid response contract', () => {
  rejected(() => responseBytes({ body: 'x'.repeat(101), base64Encoded: false }, 100))
  rejected(() => responseBytes({ body: 'eA==private-sentinel', base64Encoded: true }, 100))
  rejected(() => responseBytes({ body: 'x', base64Encoded: 'false' }, 100))
  rejected(() => responseBytes({ body: 'x', base64Encoded: false }, 0))
})

test('driver network cursor observes completed bodies only and owns every copy', async () => {
  let release
  const journal = new NetworkJournal(() => new Promise(resolve => { release = resolve }), async () => {})
  emit(journal, '1', '/api/v1/probes/status')
  assert.deepEqual(journal.since(0), { cursor: 0, responses: [] })
  release({ body: '{}', base64Encoded: false }); await journal.flush()
  const first = journal.since(0); assert.equal(first.cursor, 1)
  assert.deepEqual(Object.keys(first.responses[0]).sort(), ['ordinal', 'url', 'method', 'status', 'authorizationPresent', 'resourceType', 'bodyBytes', 'bodySHA256', 'body', 'receivedUnixNano'].sort())
  assert.equal(first.responses[0].bodySHA256, sha(Buffer.from('{}')))
  assert.match(first.responses[0].receivedUnixNano, /^[0-9]+000000$/)
  first.responses[0].body[0] = 0; first.responses[0].url = 'private-sentinel'
  assert.equal(Buffer.from(journal.since(0).responses[0].body).toString(), '{}')
  assert.deepEqual(journal.since(1), { cursor: 1, responses: [] })
  rejected(() => journal.since(2))
})

test('driver all-site evidence strips response body and all header values', async () => {
  const journal = new NetworkJournal(async () => ({ body: '{}', base64Encoded: false }), async () => {})
  emit(journal, '1', '/api/v1/probes/details'); await journal.flush()
  const evidence = journal.evidence(); assert.equal(evidence.network.length, 1)
  assert.ok(!Object.hasOwn(evidence.network[0], 'body')); assert.ok(!Object.hasOwn(evidence.network[0], 'headers'))
  assert.ok(!JSON.stringify(evidence).includes('private-sentinel'))
  evidence.network[0].status = 999; assert.equal(journal.evidence().network[0].status, 200)
})

test('driver asynchronous capture failures are fatal and console messages stay private', async () => {
  for (const operation of ['NAVIGATE', 'CLICK', 'CLICK_TEXT', 'FILL', 'VIEWPORT', 'SNAPSHOT', 'SCREENSHOT', 'NETWORK']) {
    assert.equal(driverOperationFailure(operation), `PROBE_BROWSER_DRIVER_OPERATION=${operation}\n`)
  }
  for (const operation of ['private-sentinel', 'CLICK\nprivate-sentinel', null, {}, ['NETWORK']]) {
    rejected(() => driverOperationFailure(operation))
  }
  const kinds = ['PERMISSION', 'MODULE_NOT_FOUND', 'PYTHON_STARTUP', 'SHARED_LIBRARY', 'LAUNCHER_REJECTED', 'UNKNOWN']
  for (const [error, expected] of [
    [Object.assign(new Error('private-sentinel /secret/path'), { code: 'EACCES' }), 'PERMISSION'],
    [{ message: 'Permission denied private-sentinel' }, 'PERMISSION'],
    [{ code: 'ERR_MODULE_NOT_FOUND' }, 'MODULE_NOT_FOUND'],
    ['Cannot find package private-sentinel', 'MODULE_NOT_FOUND'],
    ['Fatal Python error: error evaluating path private-sentinel', 'PYTHON_STARTUP'],
    [Buffer.from('error while loading shared libraries: private-sentinel'), 'SHARED_LIBRARY'],
    ['PROBE_CHROME_LAUNCHER=FAIL raw_input_suppressed=true\n', 'LAUNCHER_REJECTED'],
    ['private-sentinel', 'UNKNOWN'], [{ message: 'private-sentinel', code: { toString() { throw Error('private-sentinel') } } }, 'UNKNOWN'],
    ['Permission denied' + 'x'.repeat(65536), 'UNKNOWN'], [Buffer.alloc(65537), 'UNKNOWN'],
    ['\u4e00'.repeat(22000), 'UNKNOWN'], [Object.create({ message: 'Permission denied' }), 'UNKNOWN'],
    [new Proxy({}, { getOwnPropertyDescriptor() { throw Error('private-sentinel') } }), 'UNKNOWN'],
  ]) {
    const actual = classifyLaunchError(error)
    assert.equal(actual, expected); assert.ok(kinds.includes(actual)); assert.ok(!actual.includes('private-sentinel'))
  }
  let accessorCalled = false
  const accessor = Object.defineProperty({}, 'message', { get() { accessorCalled = true; return 'Permission denied' } })
  assert.equal(classifyLaunchError(accessor), 'UNKNOWN'); assert.equal(accessorCalled, false)
  const fatal = 'private-sentinel [1:2:FATAL:content/browser/zygote_host/zygote_host_impl_linux.cc:207] private-sentinel\n'
  assert.deepEqual(launchFatalLocations(new Error(fatal)), ['content/browser/zygote_host/zygote_host_impl_linux.cc:207'])
  assert.deepEqual(launchFatalLocations(Buffer.from(fatal + fatal + '[FATAL:base/threading/platform_thread_posix.cc(162)] secret')),
    ['content/browser/zygote_host/zygote_host_impl_linux.cc:207', 'base/threading/platform_thread_posix.cc:162'])
  for (const invalid of ['[FATAL:/base/file.cc:1]', '[FATAL:../base/file.cc:1]', '[FATAL:base/../secret.cc:1]',
    '[FATAL:custom/file.cc:1]', '[FATAL:base/file.cc:0]', '[FATAL:base/file.cc:1000000]', '[FATAL:base/file.cc:01]',
    '[FATAL:base/file.cc:1]'.padEnd(65537, 'x'), fatal.repeat(3000)]) assert.deepEqual(launchFatalLocations(invalid), [])
  assert.deepEqual(launchFatalLocations(accessor), []); assert.equal(accessorCalled, false)
  assert.deepEqual(launchFatalLocations(Object.create({ message: fatal })), [])
  assert.deepEqual(launchFatalLocations(new Proxy({}, { getOwnPropertyDescriptor() { throw Error('private-sentinel') } })), [])
  const four = launchFatalLocations(Array.from({ length: 6 }, (_, i) => `[FATAL:base/file_${i}.cc:1] secret`).join('\n'))
  assert.deepEqual(four, Array.from({ length: 4 }, (_, i) => `base/file_${i}.cc:1`)); assert.ok(!JSON.stringify(four).includes('secret'))
  const journal = new NetworkJournal(async () => { throw new Error('private-sentinel') }, async () => {})
  journal.handle('Runtime.consoleAPICalled', { type: 'error', args: [{ value: 'private-sentinel' }] })
  journal.handle('Runtime.exceptionThrown', { exceptionDetails: { text: 'private-sentinel' } })
  assert.equal(journal.counters.consoleErrors, 1); assert.equal(journal.counters.runtimeErrors, 1)
  emit(journal, '1', '/api/v1/probes/status')
  await assert.rejects(journal.flush(), { message: 'probe browser driver rejected' })
  rejected(() => journal.evidence()); assert.ok(!JSON.stringify(journal.counters).includes('private-sentinel'))
})

test('driver DOM extractor reads presentation without HTML state clock or fetch mutation', async () => {
  const waiting = remoteEvaluationValue({ result: { type: 'object', subtype: 'null', value: null } })
  assert.equal(waiting, null)
  const ready = remoteEvaluationValue({ result: { type: 'object', value: { x: 24, y: 48 } } })
  assert.deepEqual([waiting, ready].filter(Boolean), [{ x: 24, y: 48 }])
  for (const remote of [{ type: 'object', subtype: 'error', value: null },
    { type: 'string', subtype: 'null', value: null }, { type: 'object', subtype: 'null', value: 'private-sentinel' }]) {
    rejected(() => remoteEvaluationValue({ result: remote }))
  }
  rejected(() => remoteEvaluationValue({ result: { value: 'private-sentinel' }, exceptionDetails: { text: 'private-sentinel' } }))
  const expression = collectProbeDOM.toString()
  for (const forbidden of ['innerHTML', 'outerHTML', 'fetch(', 'Date.now', '__react', 'localStorage.setItem']) assert.ok(!expression.includes(forbidden))
  assert.ok(!/\.value\s*=(?!=)|document\.cookie\s*=(?!=)/.test(expression))
  assert.ok(expression.includes('disclosure?.open && visible(sampleCode)'))
  const source = await readFile(new URL('./browser-driver.mjs', import.meta.url), 'utf8')
  const ownedScan = source.slice(source.indexOf('async function liveOwnedChrome('), source.indexOf('\nclass CDP'))
  assert.ok(ownedScan.includes("const stat = parseProcessStat(await readFile(`/proc/${name}/stat`, 'utf8'))"))
  assert.ok(!ownedScan.includes('parseChromeStat('))
  assert.ok(ownedScan.includes('if (stat.group === record.pid || bound) return true'))
  const chromeIdentity = source.slice(source.indexOf('async function actualChrome('), source.indexOf('async function liveOwnedChrome('))
  assert.equal((chromeIdentity.match(/parseChromeStat\(/g) ?? []).length, 2)
  assert.ok(chromeIdentity.includes('first.pid === record.pid && first.group === record.pid && first.session === record.pid && first.startTicks === record.startTicks'))
  assert.ok(source.includes('launchPersistentContext'))
  assert.ok(!source.includes('connectOverCDP('))
  assert.equal((source.match(/'--hide-scrollbars'/g) ?? []).length, 1)
  const cdpLaunch = source.slice(source.indexOf("if (options.engine === 'chrome-cdp')"), source.indexOf("const module = await import("))
  assert.ok(cdpLaunch.includes("'--headless=new', '--hide-scrollbars'"))
  assert.ok(!source.includes('ignoreDefaultArgs'))
  assert.ok(!/\bHOME\s*:/.test(source)); assert.ok(!source.includes('process.env.HOME ='))
  assert.ok(source.includes("process.env.TMPDIR === '/var/tmp'"))
  assert.ok(source.includes("await privateDirectory('/var/tmp')"))
  assert.ok(source.includes("TMPDIR: '/var/tmp'")); assert.ok(!source.includes("TMPDIR: join("))
  assert.ok(source.includes('info.uid === 10001 && info.gid === 10001 && (info.mode & 0o7777) === 0o700'))
  assert.ok(source.includes("'chrome-exit.private.json'")); assert.ok(source.includes('exit.exitCode === 0'))
  const checkpointStages = ['ENVIRONMENT', 'HOME', 'DIRECTORIES', 'CONFIG', 'CERTIFICATES', 'NSS_INIT',
    'NSS_IMPORT', 'NSS_READBACK', 'LAUNCH', 'IDENTITY', 'READY', 'EVIDENCE', 'CLOSE_DRAIN',
    'CLOSE_COMMAND', 'CLOSE_WAIT', 'CLOSE_SCAN', 'CLOSE_GUARD', 'CLOSE_RESCAN', 'CLOSE_DONE']
  assert.deepEqual([...source.matchAll(/checkpoint\('([A-Z_]+)'\)/g)].map(match => match[1]), checkpointStages)
  const checkpointExpression = source.match(/const checkpoint = (stage => process\.stderr\.write\(`[^`]*`\))/)?.[1]
  assert.ok(checkpointExpression)
  const checkpointWrites = []
  const mockCheckpoint = new Function('process', `return (${checkpointExpression})`)(
    { stderr: { write: value => { checkpointWrites.push(value); return true } } })
  for (const stage of checkpointStages) mockCheckpoint(stage)
  assert.deepEqual(checkpointWrites, checkpointStages.map(stage => `PROBE_BROWSER_DRIVER_STAGE=${stage}\n`))
  const closeEntries = checkpointWrites.filter(value => value.startsWith('PROBE_BROWSER_DRIVER_STAGE=CLOSE_'))
  assert.equal(closeEntries.length, 7)
  assert.ok(Buffer.byteLength([...closeEntries, ...closeEntries, 'PROBE_BROWSER_DRIVER_STAGE=EVIDENCE\n'].join('')) < 1024)
  assert.ok(!checkpointWrites.join('').includes('private-sentinel'))
  assert.ok(source.includes('Closed checkpoints mean entry into a factory step, never its completion.'))
  assert.ok(source.indexOf('const options = validateLaunchOptions(input)') < source.indexOf("checkpoint('ENVIRONMENT')"))
  assert.deepEqual([...source.matchAll(/guarded\('([A-Z_]+)'/g)].map(match => match[1]),
    ['NAVIGATE', 'CLICK', 'CLICK_TEXT', 'FILL', 'VIEWPORT', 'SNAPSHOT', 'SCREENSHOT', 'NETWORK'])
  assert.ok(source.includes('if (!operationFailurePrinted)'))
  assert.ok(source.includes('operationFailurePrinted = true\n          process.stderr.write(driverOperationFailure(operation))'))
})

test('driver invalid factory invocation is sanitized before any launch or filesystem work', async () => {
  const original = process.stderr.write, writes = []
  process.stderr.write = function (value) { writes.push(value); return true }
  try {
    await assert.rejects(launchProbeDriver({ engine: 'private-sentinel' }), { message: 'probe browser driver rejected' })
  } finally { process.stderr.write = original }
  assert.deepEqual(writes, [])
})
