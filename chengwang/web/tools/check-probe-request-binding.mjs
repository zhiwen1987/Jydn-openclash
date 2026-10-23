// Pure CPU source-derived tests: no browser, fetch, server, timers or Vitest.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import ts from 'typescript'

async function load(name) {
  const source = readFileSync(new URL(`../src/${name}.ts`, import.meta.url), 'utf8')
  const result = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 }, reportDiagnostics: true })
  assert.deepEqual(result.diagnostics, [])
  return import(`data:text/javascript;base64,${Buffer.from(result.outputText).toString('base64')}#${name}`)
}
const { createProbeRequestBinding } = await load('probe-request-binding')
const names = []
const path = '/api/v1/probes/status'
function fixture(overrides = {}) {
  const contexts = new WeakMap(), lines = [], s = new AbortController().signal
  contexts.set(s, { m: 1, r: 1, t: 2, a: false })
  let randomCalls = 0
  const options = { enabled: () => true, origin: () => 'https://127.0.0.1:17861', context: signal => contexts.get(signal) ?? null,
    random: bytes => { randomCalls++; return bytes.fill(0xab) }, write: line => lines.push(line), ...overrides }
  const binding = createProbeRequestBinding(options)
  return { contexts, lines, s, options, binding, randomCalls: () => randomCalls,
    rows: () => lines.map(line => JSON.parse(line.slice('CW_PROBE_BIND:'.length))) }
}
async function check(name, run) { await run(); names.push(name) }
await check('binding disabled path is inert and never reads origin context or crypto', () => {
  const f = fixture({ enabled: () => false, origin: () => { throw Error() }, context: () => { throw Error() }, random: () => { throw Error() } })
  assert.deepEqual(f.binding.headers(f.s, path, true), {}); assert.equal(f.lines.length, 0)
})
await check('binding requires the exact isolated HTTPS loopback origin', () => {
  for (const origin of ['http://127.0.0.1:17861', 'https://localhost:17861', 'https://127.0.0.1:17862', 'https://127.0.0.1:17861/']) {
    const f = fixture({ origin: () => origin }); assert.deepEqual(f.binding.headers(f.s, path, true), {}); assert.equal(f.lines.length, 0)
  }
})
await check('binding excludes protected details foreign paths and nonanonymous reads', () => {
  const f = fixture()
  for (const value of ['/api/v1/probes/details', `${path}?x=1`, `https://127.0.0.1:17861${path}`]) assert.deepEqual(f.binding.headers(f.s, value, true), {})
  assert.deepEqual(f.binding.headers(f.s, path, false), {}); assert.equal(f.lines.length, 0)
})
await check('binding refuses unbound malformed and out of range signal contexts', () => {
  const f = fixture(); assert.deepEqual(f.binding.headers(new AbortController().signal, path, true), {})
  for (const context of [{ m: 0, r: 1, t: 0, a: false }, { m: 1, r: 129, t: 0, a: false }, { m: 1, r: 1, t: NaN, a: false }, { m: 1, r: 1, t: 0, a: 'false' }]) {
    f.contexts.set(f.s, context); assert.deepEqual(f.binding.headers(f.s, path, true), {})
  }
})
await check('binding suppresses context and origin getter failures without headers', () => {
  for (const overrides of [{ context: () => { throw Error('PRIVATE') } }, { origin: () => { throw Error('PRIVATE') } }]) {
    const f = fixture(overrides); assert.deepEqual(f.binding.headers(f.s, path, true), {}); assert.equal(f.lines.length, 0)
  }
})
await check('binding suppresses secure randomness failures without fallback identifiers', () => {
  const f = fixture({ random: () => { throw Error('PRIVATE') } }); assert.deepEqual(f.binding.headers(f.s, path, true), {}); assert.equal(f.lines.length, 0)
})
await check('binding rejects malformed random output instead of emitting a document identity', () => {
  for (const bytes of [new Uint8Array(15), Array(16).fill(1), null]) {
    const f = fixture({ random: () => bytes }); assert.deepEqual(f.binding.headers(f.s, path, true), {}); assert.equal(f.lines.length, 0)
  }
})
await check('binding generates one document nonce and unique mount request header values', () => {
  const f = fixture(), second = new AbortController().signal
  f.contexts.set(second, { m: 2, r: 2, t: 4, a: false })
  assert.deepEqual(f.binding.headers(f.s, path, true), { 'X-CW-Probe-Request': `v1.${'ab'.repeat(16)}.1.1` })
  assert.deepEqual(f.binding.headers(second, path, true), { 'X-CW-Probe-Request': `v1.${'ab'.repeat(16)}.2.2` }); assert.equal(f.randomCalls(), 1)
})
await check('binding rejects repeat signal and replayed mount request identity', () => {
  const f = fixture(); f.binding.headers(f.s, path, true)
  assert.deepEqual(f.binding.headers(f.s, path, true), {})
  const replay = new AbortController().signal; f.contexts.set(replay, { m: 1, r: 1, t: 3, a: false })
  assert.deepEqual(f.binding.headers(replay, path, true), {}); assert.equal(f.rows().length, 1)
})
await check('binding SEND projects only closed bounded context fields', () => {
  const f = fixture(); f.contexts.set(f.s, { m: 1, r: 1, t: 2, a: false, token: 'PRIVATE' }); f.binding.headers(f.s, path, true)
  assert.deepEqual(f.rows(), [{ v: 1, e: 'SEND', m: 1, r: 1, t: 2, a: false, doc: 'ab'.repeat(16) }])
  assert.ok(f.lines.every(line => line.length <= 512 && /^[\x20-\x7e]+$/.test(line))); assert.ok(!f.lines.join('').includes('PRIVATE'))
})
await check('binding observes real cancel fulfillment once after its Promise settles', async () => {
  const f = fixture(); f.binding.headers(f.s, path, true); let resolve, calls = 0
  const pending = new Promise(done => { resolve = done })
  assert.equal(f.binding.cancel(f.s, () => { calls++; return pending }), true)
  assert.equal(f.rows().length, 1); resolve(); await pending; await Promise.resolve()
  assert.equal(calls, 1); assert.equal(f.rows()[1].o, 'RESOLVED')
})
await check('binding observes cancel rejection without retaining the rejection value', async () => {
  const f = fixture(); f.binding.headers(f.s, path, true); const pending = Promise.reject(Error('PRIVATE'))
  assert.equal(f.binding.cancel(f.s, () => pending), true); await Promise.resolve()
  assert.equal(f.rows()[1].o, 'REJECTED'); assert.ok(!f.lines.join('').includes('PRIVATE'))
})
await check('binding observes synchronous cancel throw without throwing into the product', () => {
  const f = fixture(); f.binding.headers(f.s, path, true); let calls = 0
  assert.equal(f.binding.cancel(f.s, () => { calls++; throw Error('PRIVATE') }), true)
  assert.equal(calls, 1); assert.equal(f.rows()[1].o, 'THREW'); assert.ok(!f.lines.join('').includes('PRIVATE'))
})
await check('binding distinguishes absent body from fulfilled cancellation and ignores unsent signals', () => {
  const f = fixture(); assert.equal(f.binding.cancel(f.s, null), false); f.binding.headers(f.s, path, true)
  assert.equal(f.binding.cancel(f.s, null), true); assert.equal(f.rows()[1].o, 'NO_BODY')
})
await check('binding never waits for pending cancellation and caps emitted rows and attempts', async () => {
  const f = fixture(); f.binding.headers(f.s, path, true)
  assert.equal(f.binding.cancel(f.s, () => new Promise(() => {})), true); await Promise.resolve(); assert.equal(f.rows().length, 1)
  const g = fixture()
  for (let r = 1; r <= 129; r++) {
    const s = new AbortController().signal; g.contexts.set(s, { m: 1, r, t: r, a: false })
    const headers = g.binding.headers(s, path, true)
    assert.equal(Object.keys(headers).length, r <= 128 ? 1 : 0)
    g.binding.cancel(s, null)
  }
  assert.equal(g.rows().length, 256)
})
await check('binding sink failures stay inert and the original context getter remains read only', async () => {
  const f = fixture({ write: () => { throw Error('PRIVATE') } }); assert.deepEqual(f.binding.headers(f.s, path, true), {}); assert.equal(f.binding.cancel(f.s, null), false)
  const { mountProbeStatusObservation, beginProbeStatusObservation, getProbeStatusObservationContext } = await load('probe-status-observation')
  const original = console.info, oldLines = []; console.info = line => oldLines.push(line)
  try {
    const s = new AbortController().signal; assert.equal(getProbeStatusObservationContext(s), null)
    const m = mountProbeStatusObservation(); beginProbeStatusObservation(m, s, 'INITIAL'); const count = oldLines.length
    const one = getProbeStatusObservationContext(s); assert.equal(one.m, m); assert.equal(one.r, 1); one.m = 99
    assert.equal(getProbeStatusObservationContext(s).m, m); assert.equal(oldLines.length, count)
  } finally { console.info = original }
})
assert.equal(names.length, 16)
console.log(JSON.stringify({ schema: 'chengwang.probe-request-binding-synthetic/v1', syntheticOnly: true, realBrowserProof: false, runtimeStarted: false, passed: names.length, failed: 0, names,
  namesSHA256: createHash('sha256').update([...names].sort().join('\n')).digest('hex') }))
