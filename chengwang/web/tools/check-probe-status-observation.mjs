// Pure synthetic unit checks only: no browser, fetch, timer, socket, or Vitest.
// These do not diagnose a real cancellation or prove React/browser behavior.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

const source = readFileSync(new URL('../src/probe-status-observation.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText
const originalInfo = console.info
const originalPerformance = Object.getOwnPropertyDescriptor(globalThis, 'performance')
const names = []
let moduleId = 0

async function check(name, run) {
  const lines = []
  let clock = 1000
  console.info = (...args) => { assert.equal(args.length, 1); lines.push(args[0]) }
  Object.defineProperty(globalThis, 'performance', { configurable: true, value: { now: () => clock } })
  const api = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}#synthetic-${++moduleId}`)
  const records = () => lines.map(line => {
    assert.equal(typeof line, 'string')
    assert.ok(line.startsWith('CW_PROBE_STATUS:'))
    assert.ok(Buffer.byteLength(line) <= 256)
    assert.match(line, /^[\x20-\x7e]+$/)
    return JSON.parse(line.slice('CW_PROBE_STATUS:'.length))
  })
  try {
    await run({ api, lines, records, clock: value => { clock = value } })
    records()
    names.push(name)
  } finally {
    console.info = originalInfo
    if (originalPerformance) Object.defineProperty(globalThis, 'performance', originalPerformance)
    else delete globalThis.performance
  }
}

await check('synthetic mount relative monotonic clock and actual signal abort flags', ({ api, records, clock }) => {
  const m = api.mountProbeStatusObservation(), controller = new AbortController()
  clock(1007.9); api.beginProbeStatusObservation(m, controller.signal, 'INITIAL')
  clock(1009.8); api.observeProbeStatus(controller.signal, { e: 'ARM' })
  clock(1008); api.observeProbeStatus(controller.signal, { e: 'ABORT', c: 'DEADLINE', p: 'BEFORE' })
  controller.abort(); api.observeProbeStatus(controller.signal, { e: 'ABORT', c: 'DEADLINE', p: 'AFTER' })
  assert.deepEqual(records().map(({ e, t, a }) => ({ e, t, a })), [
    { e: 'MOUNT', t: 0, a: false }, { e: 'BEGIN', t: 7, a: false }, { e: 'ARM', t: 9, a: false },
    { e: 'ABORT', t: 9, a: false }, { e: 'ABORT', t: 9, a: true },
  ])
})
await check('synthetic all explicit triggers and independent mount request ownership', ({ api, records }) => {
  for (const tr of ['INITIAL', 'MANUAL', 'POLL']) api.beginProbeStatusObservation(api.mountProbeStatusObservation(), new AbortController().signal, tr)
  assert.deepEqual(records().filter(r => r.e === 'BEGIN').map(({ m, r, tr }) => [m, r, tr]), [[1, 1, 'INITIAL'], [2, 2, 'MANUAL'], [3, 3, 'POLL']])
})
await check('synthetic unbound detail signals and duplicate binding remain silent', ({ api, records }) => {
  const m = api.mountProbeStatusObservation(), status = new AbortController(), detail = new AbortController()
  api.beginProbeStatusObservation(m, status.signal, 'INITIAL')
  api.beginProbeStatusObservation(m, status.signal, 'MANUAL')
  api.observeProbeStatus(detail.signal, { e: 'HEADERS' })
  api.observeProbeStatus(status.signal, { e: 'HEADERS' })
  assert.deepEqual(records().map(r => r.e), ['MOUNT', 'BEGIN', 'HEADERS'])
})
await check('synthetic headers EOF read-end cancel finally sequence is representable not a browser proof', ({ api, records }) => {
  const signal = new AbortController().signal
  api.beginProbeStatusObservation(api.mountProbeStatusObservation(), signal, 'INITIAL')
  for (const event of [{ e: 'HEADERS' }, { e: 'EOF', n: 17 }, { e: 'READ_END', k: 'EOF_OK', n: 17, f: true },
    { e: 'CANCEL', p: 'BEFORE', n: 17, f: true }, { e: 'CANCEL', p: 'AFTER', n: 17, f: true }, { e: 'FINALLY' }]) api.observeProbeStatus(signal, event)
  assert.deepEqual(records().slice(2).map(r => r.e), ['HEADERS', 'EOF', 'READ_END', 'CANCEL', 'CANCEL', 'FINALLY'])
})
await check('synthetic all seven closed read reasons retain explicit EOF state', ({ api, records }) => {
  const signal = new AbortController().signal
  api.beginProbeStatusObservation(api.mountProbeStatusObservation(), signal, 'INITIAL')
  for (const k of ['FETCH_ERROR', 'HEADERS_REJECT', 'READ_ERROR', 'UTF8_REJECT', 'SIZE_REJECT', 'JSON_REJECT', 'EOF_OK']) api.observeProbeStatus(signal, { e: 'READ_END', k, n: 0, f: k === 'JSON_REJECT' || k === 'EOF_OK' })
  assert.equal(records().filter(r => r.e === 'READ_END').length, 7)
  assert.equal(records().find(r => r.k === 'JSON_REJECT').f, true)
})
await check('synthetic invalid event enums and counters are rejected not serialized', ({ api, records }) => {
  const signal = new AbortController().signal
  api.beginProbeStatusObservation(api.mountProbeStatusObservation(), signal, 'INITIAL')
  for (const event of [{ e: 'raw-secret' }, { e: 'ABORT', c: 'raw-secret', p: 'BEFORE' }, { e: 'ABORT', c: 'DEADLINE', p: 'raw-secret' },
    { e: 'READ_END', k: 'raw-secret', n: 0, f: false }, { e: 'EOF', n: -1 }, { e: 'EOF', n: 1.5 }, { e: 'EOF', n: 1048578 },
    { e: 'CANCEL', p: 'AFTER', n: 0, f: 'raw-secret' }]) api.observeProbeStatus(signal, event)
  api.beginProbeStatusObservation(1, new AbortController().signal, 'raw-secret')
  assert.equal(records().length, 2)
})
await check('synthetic closed projection ignores unexpected secret bearing properties', ({ api, lines, records }) => {
  const signal = new AbortController().signal
  api.beginProbeStatusObservation(api.mountProbeStatusObservation(), signal, 'INITIAL')
  api.observeProbeStatus(signal, { e: 'HEADERS', url: 'secret-url', token: 'secret-token', error: 'secret-error', stack: 'secret-stack' })
  assert.deepEqual(Object.keys(records().at(-1)).sort(), ['a', 'e', 'm', 'r', 't', 'v'])
  assert.ok(lines.every(line => !line.includes('secret')))
})
await check('synthetic module emission budget is exactly bounded at 128 lines', ({ api, lines, records }) => {
  const signal = new AbortController().signal
  api.beginProbeStatusObservation(api.mountProbeStatusObservation(), signal, 'INITIAL')
  for (let i = 0; i < 300; i++) api.observeProbeStatus(signal, { e: 'ARM' })
  assert.equal(lines.length, 128)
  assert.equal(api.mountProbeStatusObservation(), 0)
  assert.ok(records().every(r => r.m >= 1 && r.m <= 128 && r.r >= 0 && r.r <= 128))
})
await check('synthetic observer console exceptions never abort or throw into caller', ({ api }) => {
  console.info = () => { throw new Error('synthetic-console-error') }
  const controller = new AbortController()
  assert.doesNotThrow(() => {
    const m = api.mountProbeStatusObservation()
    api.beginProbeStatusObservation(m, controller.signal, 'INITIAL')
    api.observeProbeStatus(controller.signal, { e: 'FINALLY' })
    api.cleanupProbeStatusObservation(m, controller.signal)
  })
  assert.equal(controller.signal.aborted, false)
})
await check('synthetic observer broken clock cannot affect request behavior', ({ api, lines }) => {
  Object.defineProperty(globalThis, 'performance', { configurable: true, value: { now: () => { throw new Error('synthetic-clock-error') } } })
  assert.equal(api.mountProbeStatusObservation(), 0)
  assert.doesNotThrow(() => api.observeProbeStatus(new AbortController().signal, { e: 'HEADERS' }))
  assert.equal(lines.length, 0)
})
await check('synthetic elapsed time and byte counts remain bounded integers', ({ api, records, clock }) => {
  const signal = new AbortController().signal
  api.beginProbeStatusObservation(api.mountProbeStatusObservation(), signal, 'INITIAL')
  clock(Number.MAX_SAFE_INTEGER)
  api.observeProbeStatus(signal, { e: 'EOF', n: 1048577 })
  clock(Number.NaN); api.observeProbeStatus(signal, { e: 'FINALLY' })
  assert.equal(records().at(-1).t, 2147483647)
  assert.equal(records().at(-1).n, 1048577)
  assert.equal(records().length, 3)
})
await check('synthetic cleanup identifies active request or idle mount without cross ownership', ({ api, records }) => {
  const m = api.mountProbeStatusObservation(), other = api.mountProbeStatusObservation(), signal = new AbortController().signal
  api.beginProbeStatusObservation(m, signal, 'INITIAL')
  api.cleanupProbeStatusObservation(other, signal)
  api.cleanupProbeStatusObservation(m, signal)
  api.cleanupProbeStatusObservation(other)
  assert.deepEqual(records().filter(r => r.e === 'CLEANUP').map(({ m, r }) => [m, r]), [[1, 1], [2, 0]])
})

assert.equal(names.length, 12)
process.stdout.write(JSON.stringify({ schema: 'chengwang.probe-status-observation-synthetic/v1', syntheticOnly: true, realBrowserProof: false, passed: names.length, failed: 0, names }) + '\n')
