// Separate synthetic identity tests. No browser, Go, TLS, network or namespace.
// Freeze these names independently; they are not old driver32 or frontend190.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { BROWSER_IDENTITY_PREFIX, BROWSER_IDENTITY_SCHEMA, projectBrowserIdentity, emitBrowserIdentity } from './browser-identity.mjs'

const names = [], unit = (name, body) => { names.push(name); test(name, body) }
const sentinel = 'PRIVATE_SENTINEL'
const version = () => ({ product: 'Chrome/155.0.8059.39', revision: '@' + 'a'.repeat(40), protocolVersion: '1.3',
  userAgent: sentinel, jsVersion: sentinel })
const binding = () => ({ engine: 'chrome-cdp', fixtureId: 'b'.repeat(32), chrome: {
  pid: 12, startTicks: 345, argvSHA256: 'c'.repeat(64), uid: 10001, profile: sentinel } })
const project = (v = version(), b = binding()) => projectBrowserIdentity(v, b)
const emitted = (v = version(), b = binding()) => {
  const lines = []; return { accepted: emitBrowserIdentity(v, b, line => lines.push(line)), lines }
}

unit('browser identity projects exactly three observed version fields and owned process binding', () => {
  assert.deepEqual(project(), { schema: BROWSER_IDENTITY_SCHEMA, engine: 'chrome-cdp', fixtureId: 'b'.repeat(32),
    browser: { product: 'Chrome/155.0.8059.39', revision: '@' + 'a'.repeat(40), protocolVersion: '1.3' },
    chrome: { pid: 12, startTicks: 345, argvSHA256: 'c'.repeat(64) } })
})
unit('browser identity preserves real values for both adapters and headless product', () => {
  for (const engine of ['chrome-cdp', 'playwright']) {
    const b = binding(); b.engine = engine
    const v = version(); v.product = 'HeadlessChrome/157.1.8091.0'; v.protocolVersion = '2.41'
    assert.equal(project(v, b).engine, engine); assert.deepEqual(project(v, b).browser, {
      product: v.product, revision: v.revision, protocolVersion: v.protocolVersion })
  }
})
unit('browser identity observes a zero revision without manufacturing patch ancestry', () => {
  const v = version(); v.revision = '@' + '0'.repeat(40)
  assert.equal(project(v).browser.revision, v.revision)
  const raw = JSON.stringify(project(v))
  assert.ok(!/ancestry|patched|patchIncluded|sourceCommit|executable|sha256|bytes/.test(raw))
})
unit('browser identity never reads user agent javascript version profile or private extra getters', () => {
  let reads = 0; const v = version(), b = binding()
  for (const [object, keys] of [[v, ['userAgent', 'jsVersion', 'private']], [b.chrome, ['profile', 'uid', 'private']]]) {
    for (const key of keys) Object.defineProperty(object, key, { get() { reads++; throw Error(sentinel) } })
  }
  assert.ok(project(v, b)); assert.equal(reads, 0)
})
unit('browser identity rejects missing observed fields rather than filling defaults', () => {
  for (const key of ['product', 'revision', 'protocolVersion']) {
    const v = version(); delete v[key]; assert.equal(project(v), null)
  }
})
unit('browser identity rejects inherited or accessor version fields without invoking them', () => {
  let reads = 0
  assert.equal(project(Object.create(version())), null)
  for (const key of ['product', 'revision', 'protocolVersion']) {
    const v = version(); Object.defineProperty(v, key, { get() { reads++; throw Error(sentinel) } })
    assert.equal(project(v), null)
  }
  assert.equal(reads, 0)
})
unit('browser identity rejects malformed and noncanonical product strings', () => {
  for (const product of ['', 'Chromium/155.0.8059.39', 'Chrome/155', 'Chrome/1.2.3.4\n',
    'Chrome/1.2.3.4 ' + sentinel, 'Chrome/11111111111.2.3.4', null, 155, {}]) {
    assert.equal(project({ ...version(), product }), null)
  }
})
unit('browser identity rejects malformed or coerced revision strings', () => {
  for (const revision of ['', 'a'.repeat(40), '@' + 'A'.repeat(40), '@' + 'a'.repeat(39),
    '@' + 'a'.repeat(41), '@' + 'a'.repeat(40) + '\n', sentinel, null, { toString() { throw Error(sentinel) } }]) {
    assert.equal(project({ ...version(), revision }), null)
  }
})
unit('browser identity rejects malformed or unbounded protocol versions', () => {
  for (const protocolVersion of ['', '1', '1.3.0', '1.3\n', '1000.3', '1.1000', sentinel, null, 1.3]) {
    assert.equal(project({ ...version(), protocolVersion }), null)
  }
})
unit('browser identity rejects unknown engines without alias normalization', () => {
  for (const engine of ['', 'cdp', 'Chrome', sentinel, null, {}]) assert.equal(project(version(), { ...binding(), engine }), null)
})
unit('browser identity rejects malformed fixture identifiers', () => {
  for (const fixtureId of ['', 'b'.repeat(31), 'b'.repeat(33), 'B'.repeat(32), 'b'.repeat(32) + '\n', sentinel, null]) {
    assert.equal(project(version(), { ...binding(), fixtureId }), null)
  }
})
unit('browser identity rejects unsafe process identifiers and start ticks', () => {
  for (const key of ['pid', 'startTicks']) for (const value of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, Infinity, NaN, '12', null]) {
    const b = binding(); b.chrome[key] = value; assert.equal(project(version(), b), null)
  }
  const b = binding(); b.chrome.pid = 1; assert.equal(project(version(), b), null)
})
unit('browser identity rejects malformed process argument fingerprints', () => {
  for (const argvSHA256 of ['', 'c'.repeat(63), 'c'.repeat(65), 'C'.repeat(64), 'c'.repeat(64) + '\n', sentinel, null]) {
    const b = binding(); b.chrome.argvSHA256 = argvSHA256; assert.equal(project(version(), b), null)
  }
})
unit('browser identity rejects inherited and accessor binding fields without invoking them', () => {
  let reads = 0
  assert.equal(project(version(), Object.create(binding())), null)
  const b = binding(); b.chrome = Object.create(b.chrome); assert.equal(project(version(), b), null)
  for (const key of ['engine', 'fixtureId', 'chrome']) {
    const value = binding(); Object.defineProperty(value, key, { get() { reads++; throw Error(sentinel) } })
    assert.equal(project(version(), value), null)
  }
  for (const key of ['pid', 'startTicks', 'argvSHA256']) {
    const value = binding(); Object.defineProperty(value.chrome, key, { get() { reads++; throw Error(sentinel) } })
    assert.equal(project(version(), value), null)
  }
  assert.equal(reads, 0)
})
unit('browser identity rejects primitive arrays and throwing proxies without exposing content', () => {
  const throwing = new Proxy({}, { getOwnPropertyDescriptor() { throw Error(sentinel) } })
  for (const value of [null, undefined, false, 1, sentinel, [], throwing]) {
    assert.equal(projectBrowserIdentity(value, binding()), null)
    assert.equal(projectBrowserIdentity(version(), value), null)
    const b = binding(); b.chrome = value; assert.equal(project(version(), b), null)
  }
})
unit('browser identity emits one bounded canonical ascii line with the independent prefix', () => {
  const { accepted, lines } = emitted(); assert.equal(accepted, true); assert.equal(lines.length, 1)
  const line = lines[0]; assert.ok(Buffer.byteLength(line) <= 1025)
  assert.ok(/^[\x20-\x7e]+\n$/.test(line)); assert.ok(line.startsWith(BROWSER_IDENTITY_PREFIX))
  const raw = line.slice(BROWSER_IDENTITY_PREFIX.length, -1)
  assert.equal(raw, JSON.stringify(project())); assert.ok(!line.includes(sentinel))
})
unit('browser identity invalid inputs never reach the output sink', () => {
  for (const v of [null, {}, { ...version(), revision: sentinel }]) assert.deepEqual(emitted(v), { accepted: false, lines: [] })
})
unit('browser identity sink exceptions are suppressed without changing old driver outcomes', () => {
  assert.equal(emitBrowserIdentity(version(), binding(), () => { throw Error(sentinel) }), false)
})
unit('browser identity ignores toJSON hooks and never mutates source observations', () => {
  const v = version(), b = binding(), before = structuredClone({ v, b }); let calls = 0
  v.toJSON = b.toJSON = b.chrome.toJSON = () => { calls++; throw Error(sentinel) }
  const { accepted, lines } = emitted(v, b); assert.equal(accepted, true); assert.equal(calls, 0)
  delete v.toJSON; delete b.toJSON; delete b.chrome.toJSON
  assert.deepEqual({ v, b }, before); assert.ok(!lines.join('').includes(sentinel))
})
unit('browser identity integration observes actual version after owned process verification only once', async () => {
  const raw = await readFile(new URL('./browser-driver.mjs', import.meta.url), 'utf8')
  const sequence = ["const version = await browserSend('Browser.getVersion')", 'record = await actualChrome(options, browserSend)',
    'emitBrowserIdentity(version, { engine: options.engine, fixtureId: options.fixtureId, chrome: record })']
  const offsets = sequence.map(text => raw.indexOf(text)); assert.ok(offsets.every(value => value >= 0))
  assert.ok(offsets[0] < offsets[1] && offsets[1] < offsets[2])
  assert.equal(raw.split(sequence[2]).length - 1, 1)
  assert.ok(!raw.includes('getBrowserIdentity:')); assert.ok(!raw.includes('identity:'))
  assert.ok(raw.includes("schema: 'chengwang.probe-browser-driver/v1'"))
})

assert.equal(names.length, 20)
assert.equal(new Set(names).size, 20)
assert.equal(createHash('sha256').update([...names].sort().join('\n') + '\n').digest('hex'), '82236781b9611eae26fad42ac96071512a0a64a3d79a36591e200a0f9dbe0092')
