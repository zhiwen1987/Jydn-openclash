// Synthetic fake-driver tests. No browser, TLS endpoint, Go or runtime proof.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { exerciseProbeBrowser } from './run-browser.mjs'

const diagnosticStages = ['NAVIGATE', 'NAVIGATION', 'FRESH_TOKEN', 'FRESH_API', 'FRESH_EXPAND',
  'FRESH_DESKTOP', 'FRESH_MOBILE', 'CLEAR', 'ANONYMOUS', 'HELD_FRESH', 'WITHDRAWN', 'EXPIRED']
const names = [], unit = (name, body) => {
  names.push(name)
  test(name, async () => {
    const diagnostics = [], original = process.stderr.write
    process.stderr.write = function (chunk, encoding, callback) {
      diagnostics.push(String(chunk))
      if (typeof encoding === 'function') encoding()
      else if (typeof callback === 'function') callback()
      return true
    }
    try { await body(diagnostics) } finally {
      process.stderr.write = original
      for (const line of diagnostics) {
        assert.ok(diagnosticStages.some(stage => line === `PROBE_BROWSER_FLOW_STAGE=${stage}\n`))
        assert.ok(!line.includes(token) && !line.includes('PRIVATE KEY') && !line.includes('Bearer '))
      }
      // Some negative tests invoke several independent flows in one test.
      assert.ok(Buffer.byteLength(diagnostics.join('')) < 65536)
    }
  })
}
const token = 'PRIVATE-FIXTURE-TOKEN-' + 'a'.repeat(40)
const bytes = value => Buffer.from(JSON.stringify(value)), sha = value => createHash('sha256').update(value).digest('hex')
const ids = ['limited', 'pass', 'restricted'], states = { limited: 'rate_limited', pass: 'available', restricted: 'restricted' }
const codes = { limited: 429, pass: 200, restricted: 403 }, labels = { unknown: '未评估', available: '可用', restricted: '业务受限', rate_limited: '限流' }
const date = value => new Date(value).toISOString(), clone = value => JSON.parse(JSON.stringify(value))
const reject = operation => assert.rejects(operation, error => error instanceof Error && error.message === 'probe browser flow rejected')

function fixture(epoch, expired = false, shortCache = false) {
  const cache = expired ? Date.now() : epoch - (shortCache ? 29500 : 50)
  const status = { schema: 'chengwang.probe-view-status/v1', configured: true, running: true, advisoryOnly: true,
    state: expired ? 'partial' : 'ready', reason: expired ? 'evidence_expired' : 'ok', clockHealthy: true, storageHealthy: true,
    cachedAt: date(cache), expiresAt: date(expired ? cache + 30000 : Math.min(cache + 30000, epoch + 799)),
    coverage: { declaredTargets: 3, targetsWithSamples: expired ? 0 : 3, targetsMissing: expired ? 3 : 0,
      retainedSamples: expired ? 0 : 6, validTotal: 6, expiredTotal: expired ? 6 : 0, eligibleTotal: expired ? 0 : 6,
      rejectedTotal: 0, truncated: false, partial: expired } }
  const samples = []
  if (!expired) for (let cycle = 0; cycle < 2; cycle++) for (let index = 0; index < 3; index++) {
    const id = ids[index], end = epoch - 120000 + 800 + cycle * 80 + index * 10
    const layers = Object.fromEntries(['dns', 'connect', 'tls', 'http', 'business'].map(name => [name, {
      state: name === 'business' ? states[id] : 'available', observedAt: date(name === 'dns' ? end - 2 : end),
      expiresAt: date(name === 'dns' ? end + 119999 : end + 120000), latencyMillis: name === 'business' ? 0 : 1,
      ...(name === 'business' && id === 'limited' ? { retryAfterSeconds: 30 } : {}), reason: name === 'business'
        ? id === 'pass' ? 'contract_matched' : id === 'restricted' ? 'access_restricted' : 'rate_limited'
        : { dns: 'resolved_and_pinned', connect: 'tcp_connected', tls: 'tls_verified', http: 'http_response_received' }[name],
    }]))
    samples.push({ runId: `fake-${id}-${cycle}`, probeId: id, pathId: 'direct', attemptedAt: date(end - 4), completedAt: date(end),
      expiresAt: date(end + 120000), conclusion: states[id], outcome: id === 'pass' ? 'pass' : 'indeterminate',
      httpStatus: codes[id], responseBytes: Buffer.byteLength(`chengwang-probe-${id}-v1\n`), ...(id === 'pass' ? {} : { errorClass: states[id] }), layers })
  }
  const targets = ids.map(id => {
    const latest = samples.find(sample => sample.runId === `fake-${id}-1`)
    return { probeId: id, pathId: 'direct', state: expired ? 'unknown' : states[id], reason: expired ? 'no_current_evidence'
      : id === 'pass' ? 'two_consecutive_contract_matches' : states[id], ...(expired ? {} : { observedAt: latest.completedAt, expiresAt: latest.expiresAt }),
      consecutiveSuccess: !expired && id === 'pass' ? 2 : 0, consecutiveFailure: 0, retainedSamples: expired ? 0 : 2 }
  })
  return { status, details: { schema: 'chengwang.probe-view-details/v1', status: clone(status), catalogDigest: 'sha256:' + 'b'.repeat(64),
    agentId: 'probe-readback-agent', independence: 'P1', advisoryOnly: true, targets, samples,
    rejections: { format: 0, integrity: 0, catalog: 0, future: 0, duplicate: 0, semantic: 0 } } }
}

class FakeDriver {
  constructor(options = {}) {
    this.options = options; this.engine = options.engine ?? 'chrome-cdp'; this.epoch = Date.now()
    this.initial = fixture(this.epoch, false, options.shortCache); this.expired = false
    this.events = []; this.clicks = []; this.input = ''; this.mounted = false; this.open = new Set(); this.viewport = { width: 1440, height: 1000 }
  }
  emit(path) {
    // Mirror a real immutable cache generation rather than inventing a new
    // millisecond timestamp independently for the two coherent API responses.
    if (this.expired && !this.expiredFixture) this.expiredFixture = fixture(this.epoch, true)
    const value = clone(this.expired ? this.expiredFixture : this.initial)
    if (path.endsWith('details') && this.options.mismatchedGeneration && !this.mismatchSent) {
      value.details.status.cachedAt = date(Date.parse(value.details.status.cachedAt) + 1); this.mismatchSent = true
    }
    if (path.endsWith('details') && this.options.badAPI) value.details.samples[0].httpStatus = 200
    const body = bytes(path.endsWith('status') ? value.status : value.details)
    this.events.push({ ordinal: this.events.length + 1, url: 'https://127.0.0.1:17861' + path, method: 'GET', status: 200,
      authorizationPresent: path.endsWith('details'), resourceType: 'fetch', bodyBytes: body.length, bodySHA256: sha(body), body,
      receivedUnixNano: (BigInt(Date.now()) * 1000000n).toString() })
    if (path.endsWith('details')) { this.loaded = value.details; this.mounted = true; this.open.clear() }
  }
  async navigate(url) { assert.equal(url, 'https://127.0.0.1:17861/') }
  async clickText(text, scope) {
    this.clicks.push(text)
    if (text === '代理节点') this.emit('/api/v1/probes/status')
    else {
      assert.equal(scope, '.probe-readback')
      if (text === '读取受保护明细') { assert.equal(this.input, token); this.emit('/api/v1/probes/details') }
      else if (text === '清除明细与令牌') { this.input = this.options.badClear ? token : ''; this.mounted = false }
      else if (text === '刷新探针摘要') { this.mounted = false; this.emit('/api/v1/probes/status') }
      else assert.fail('unrecognized fake action')
    }
  }
  async fill(selector, value) { assert.equal(selector, '#probe-token'); assert.equal(value, token); this.input = value; this.mounted = false }
  async click(selector) { const match = /^\.probe-targets li:nth-child\(([123])\) summary$/.exec(selector); assert.ok(match); this.open.add(Number(match[1]) - 1) }
  async setViewport(value) { this.viewport = value }
  async snapshot() {
    const current = this.mounted && Date.now() < Date.parse(this.loaded.status.expiresAt) && this.loaded.samples.length > 0
    const raw = { url: 'https://127.0.0.1:17861/', title: '澄网 · 网络代理与路由平台', heading: '代理节点观测',
      viewport: { ...this.viewport }, scrollWidth: this.viewport.width, clientWidth: this.viewport.width, inputType: 'password',
      tokenEmpty: this.input === '', storageEmpty: true, cookiesEmpty: true, detailMounted: this.mounted,
      catalogText: this.mounted ? this.loaded.catalogDigest : '', overlayCount: 0, targets: this.mounted ? ids.map((id, index) => ({
        probeId: id, pathId: 'direct', stateLabel: labels[current ? states[id] : 'unknown'],
        runId: current && this.open.has(index) ? `fake-${id}-1` : '', httpStatus: current && this.open.has(index) ? codes[id] : 0,
        layers: current && this.open.has(index) ? { dns: '可用', connect: '可用', tls: '可用', http: '可用', business: labels[states[id]] } : {},
      })) : [] }
    if (this.options.badDOM && this.mounted) raw.targets[0].runId = 'wrong-run'
    if (this.options.secretDOM) raw.html = `<input value="${token}">`
    return raw
  }
  async screenshot() {
    if (this.options.badPNG) return Buffer.from('not-png')
    if (this.options.latePNG) await new Promise(resolve => setTimeout(resolve, 1100))
    const header = Buffer.alloc(33); Buffer.from('89504e470d0a1a0a', 'hex').copy(header)
    header.writeUInt32BE(13, 8); header.write('IHDR', 12); header.writeUInt32BE(this.viewport.width + (this.options.widePNG ? 1 : 0), 16); header.writeUInt32BE(this.viewport.height, 20)
    return header // Deliberately synthetic header, never actual screenshot proof.
  }
  async networkSince(cursor) {
    const responses = this.events.filter(entry => entry.ordinal > cursor).map(entry => ({ ...entry, body: Buffer.from(entry.body) }))
    if (responses.length && this.options.badHash) responses[0].bodySHA256 = '0'.repeat(64)
    if (responses.length && this.options.secretMetadata) responses[0].headers = { Authorization: `Bearer ${token}` }
    if (responses.length && this.options.gap) responses[0].ordinal++
    if (responses.length && this.options.foreignURL) responses[0].url = 'https://elsewhere.invalid/api/v1/probes/status'
    return { cursor: this.events.length, responses }
  }
}
function setup(options = {}) {
  const driver = new FakeDriver(options), saved = new Map(), callbacks = []
  const input = { driver, token, deadline: Date.now() + (options.shortDeadline ? 100 : 5000),
    expectedForBodies: async body => { callbacks.push(body.phase); return true },
    savePublic: async (name, raw) => { assert.ok(!saved.has(name)); saved.set(name, Buffer.from(raw)) },
    phaseSignals: { waitExpired: async () => { driver.expired = true } } }
  return { driver, saved, callbacks, input }
}

unit('probe flow synthetic CDP performs all real-shaped actions but never claims runtime proof', async diagnostics => {
  const value = setup(); let freshNotified = false
  value.input.phaseSignals.freshReady = async () => {
    assert.equal(value.driver.loaded.samples.length, 6); assert.equal(value.driver.open.size, 3)
    assert.ok(Date.now() < Date.parse(value.driver.loaded.status.expiresAt)); freshNotified = true
  }
  value.input.phaseSignals.waitExpired = async () => { assert.ok(freshNotified); value.driver.expired = true }
  const result = await exerciseProbeBrowser(value.input)
  assert.equal(result.outcome, 'API_CAPTURE_UNBOUND'); assert.equal(result.runtimeProven, false); assert.equal(result.browserE2EProven, false)
  assert.equal(result.captures.length, 4); assert.equal(value.saved.size, 18); assert.equal(result.deadlineKind, 'EVIDENCE_TTL')
  assert.deepEqual(value.callbacks, ['fresh', 'fresh', 'expired']); assert.ok(value.driver.clicks.includes('清除明细与令牌'))
  assert.deepEqual(diagnostics, diagnosticStages.map(stage => `PROBE_BROWSER_FLOW_STAGE=${stage}\n`))
  assert.ok(Buffer.byteLength(diagnostics.join('')) < 1024)
})
unit('probe flow synthetic Playwright is separately labelled and uses the same safe projections', async () => {
  const value = setup({ engine: 'playwright' }), result = await exerciseProbeBrowser(value.input)
  assert.equal(result.engine, 'playwright'); assert.ok([...value.saved.keys()].every(name => name.startsWith('probe-browser-playwright-')))
})
unit('probe flow retries actual status details generation conflicts through UI refresh', async () => {
  const value = setup({ mismatchedGeneration: true }); await exerciseProbeBrowser(value.input)
  assert.ok(value.driver.mismatchSent); assert.ok(value.driver.clicks.filter(text => text === '读取受保护明细').length >= 4)
})
unit('probe flow secret request headers are rejected before any public write', async () => {
  const value = setup({ secretMetadata: true }); await reject(() => exerciseProbeBrowser(value.input)); assert.equal(value.saved.size, 0)
})
unit('probe flow response raw bytes must match actual metadata hash and length', async () => {
  const value = setup({ badHash: true }); await reject(() => exerciseProbeBrowser(value.input)); assert.equal(value.saved.size, 0)
})
unit('probe flow missing completion ordinals cannot be hidden by cursor advancement', async () => {
  const value = setup({ gap: true }); await reject(() => exerciseProbeBrowser(value.input)); assert.equal(value.saved.size, 0)
})
unit('probe flow invalid private token never reaches a browser adapter', async () => {
  const value = setup(); value.input.token = 'bad'; await reject(() => exerciseProbeBrowser(value.input)); assert.equal(value.driver.clicks.length, 0)
  await reject(() => exerciseProbeBrowser(undefined)); await reject(() => exerciseProbeBrowser(null))
  await reject(() => exerciseProbeBrowser({ ...setup().input, runtimeProven: true }))
  const missing = setup().input; delete missing.phaseSignals; await reject(() => exerciseProbeBrowser(missing))
  const badHook = setup(); badHook.input.phaseSignals.freshReady = true
  await reject(() => exerciseProbeBrowser(badHook.input)); assert.equal(badHook.driver.clicks.length, 0)
})
unit('probe flow callback errors remain closed and are not exported as authority', async () => {
  const value = setup(); value.input.expectedForBodies = async () => { throw new Error(token) }
  await reject(() => exerciseProbeBrowser(value.input)); assert.equal(value.saved.size, 0)
  const badHook = setup(); badHook.input.phaseSignals.freshReady = async () => { throw new Error(token) }
  await reject(() => exerciseProbeBrowser(badHook.input))
})
unit('probe flow wrong visible run ID is rejected within the absolute deadline', async () => {
  const value = setup({ badDOM: true, shortDeadline: true }); await reject(() => exerciseProbeBrowser(value.input))
})
unit('probe flow arbitrary HTML snapshots can never enter published captures', async () => {
  const value = setup({ secretDOM: true, shortDeadline: true }); await reject(() => exerciseProbeBrowser(value.input))
  assert.ok([...value.saved.values()].every(raw => !raw.includes(Buffer.from(token))))
})
unit('probe flow screenshot bytes dimensions and actual capture time are bounded', async () => {
  for (const options of [{ badPNG: true }, { widePNG: true }, { latePNG: true }]) {
    const value = setup(options); await reject(() => exerciseProbeBrowser(value.input))
  }
})
unit('probe flow clear must actually empty the input and unmount the details', async () => {
  const value = setup({ badClear: true, shortDeadline: true }); await reject(() => exerciseProbeBrowser(value.input))
})
unit('probe flow malformed public API success cannot be accepted by a true callback', async () => {
  const value = setup({ badAPI: true }); await reject(() => exerciseProbeBrowser(value.input)); assert.equal(value.saved.size, 0)
})
unit('probe flow hanging adapter commands are bounded without pretending cancellation succeeded', async () => {
  const value = setup({ shortDeadline: true }); value.driver.navigate = async () => new Promise(() => {})
  const started = Date.now(); await reject(() => exerciseProbeBrowser(value.input)); assert.ok(Date.now() - started < 1000)
})
unit('probe flow early expired signal cannot bypass real source TTL or relabel cache expiry', async () => {
  const value = setup({ shortCache: true }), start = Date.now(), result = await exerciseProbeBrowser(value.input)
  assert.equal(result.deadlineKind, 'CACHE_OR_EVIDENCE_DEADLINE'); assert.ok(Date.now() - start >= 850)
  assert.ok(result.captures.at(-1).observations[0].dom.targets.every(target => target.runId === '' && target.stateLabel === '未评估'))
})
unit('probe flow foreign response origins are rejected rather than written as public evidence', async () => {
  const value = setup({ foreignURL: true }); await reject(() => exerciseProbeBrowser(value.input)); assert.equal(value.saved.size, 0)
})

assert.equal(names.length, 16)
assert.equal(new Set(names).size, 16)
assert.equal(sha(Buffer.from([...names].sort().join('\n') + '\n')), '5aeaf893ca970640cba452210b3aff4de9246c7e22e53230ec972584e4665cc5')
