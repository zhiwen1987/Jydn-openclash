// CI-only synthetic contracts. No real browser, server or runtime acceptance.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { BROWSER_SCHEMA, ENGINES, parseProbePublicJSON, deriveProbeBrowserExpected, projectProbeDOM,
  projectProbeNetwork, createProbeBrowserEvidence } from './probe-browser-contract.mjs'

const names = []
const unit = (name, body) => { names.push(name); test(name, body) }
const base = Date.UTC(2026, 9, 23), date = seconds => new Date(base + seconds * 1000).toISOString()
const bytes = value => Buffer.from(JSON.stringify(value))
const hash = value => createHash('sha256').update(value).digest('hex')
const clone = value => JSON.parse(JSON.stringify(value))
const ids = ['limited', 'pass', 'restricted']
const states = { limited: 'rate_limited', pass: 'available', restricted: 'restricted' }
const codes = { limited: 429, pass: 200, restricted: 403 }
const label = { unknown: '未评估', available: '可用', restricted: '业务受限', rate_limited: '限流' }
const rejected = callback => assert.throws(callback, error => error instanceof Error && error.message === 'probe browser contract rejected')

function api(phase = 'fresh', cached = 100) {
  const expired = phase === 'expired'
  const status = { schema: 'chengwang.probe-view-status/v1', configured: true, running: true, advisoryOnly: true,
    state: expired ? 'partial' : 'ready', reason: expired ? 'evidence_expired' : 'ok', clockHealthy: true, storageHealthy: true,
    cachedAt: date(expired ? 300 : cached), expiresAt: date(expired ? 330 : Math.min(cached + 30, 120.002)),
    coverage: { declaredTargets: 3, targetsWithSamples: expired ? 0 : 3, targetsMissing: expired ? 3 : 0,
      retainedSamples: expired ? 0 : 6, validTotal: 6, expiredTotal: expired ? 6 : 0, eligibleTotal: expired ? 0 : 6,
      rejectedTotal: 0, truncated: false, partial: expired } }
  const samples = []
  if (!expired) for (let cycle = 0; cycle < 2; cycle++) for (let index = 0; index < 3; index++) {
    const id = ids[index], attempt = cycle * 60 + index, completedAt = date(attempt + .004), expiresAt = date(attempt + 120.004)
    const layers = Object.fromEntries(['dns', 'connect', 'tls', 'http', 'business'].map(name => [name, {
      state: name === 'business' ? states[id] : 'available', observedAt: name === 'dns' ? date(attempt + .002) : completedAt,
      expiresAt: name === 'dns' ? date(attempt + 120.002) : expiresAt, latencyMillis: name === 'business' ? 0 : 1,
      ...(id === 'limited' && name === 'business' ? { retryAfterSeconds: 30 } : {}),
      reason: name === 'business' ? id === 'pass' ? 'contract_matched' : id === 'restricted' ? 'access_restricted' : 'rate_limited'
        : { dns: 'resolved_and_pinned', connect: 'tcp_connected', tls: 'tls_verified', http: 'http_response_received' }[name],
    }]))
    samples.push({ runId: `run-${id}-${cycle}`, probeId: id, pathId: 'direct', attemptedAt: date(attempt), completedAt,
      expiresAt, conclusion: states[id], outcome: id === 'pass' ? 'pass' : 'indeterminate', httpStatus: codes[id],
      responseBytes: Buffer.byteLength(`chengwang-probe-${id}-v1\n`), ...(id === 'pass' ? {} : { errorClass: states[id] }), layers })
  }
  const targets = ids.map(id => {
    const latest = samples.find(sample => sample.runId === `run-${id}-1`)
    return { probeId: id, pathId: 'direct', state: expired ? 'unknown' : states[id],
      reason: expired ? 'no_current_evidence' : id === 'pass' ? 'two_consecutive_contract_matches' : states[id],
      ...(expired ? {} : { observedAt: latest.completedAt, expiresAt: latest.expiresAt }),
      consecutiveSuccess: !expired && id === 'pass' ? 2 : 0, consecutiveFailure: 0, retainedSamples: expired ? 0 : 2 }
  })
  const details = { schema: 'chengwang.probe-view-details/v1', status: clone(status), catalogDigest: 'sha256:' + 'b'.repeat(64),
    agentId: 'probe-readback-agent', independence: 'P1', advisoryOnly: true, targets, samples,
    rejections: { format: 0, integrity: 0, catalog: 0, future: 0, duplicate: 0, semantic: 0 } }
  return { status, details, phase }
}
function expected(fixture = api()) { return deriveProbeBrowserExpected({ statusBytes: bytes(fixture.status), detailsBytes: bytes(fixture.details), backendVerificationSHA256: 'a'.repeat(64), phase: fixture.phase }) }
function dom(expectation, phase = 'fresh', width = 1440) {
  const current = phase === 'fresh', clear = phase === 'cleared'
  return { url: 'https://127.0.0.1:17861/', title: '澄网 · 网络代理与路由平台', heading: '代理节点观测',
    viewport: { width, height: width === 375 ? 812 : 1000 }, clientWidth: width, scrollWidth: width, inputType: 'password',
    tokenEmpty: clear, storageEmpty: true, cookiesEmpty: true, detailMounted: !clear,
    catalogText: clear ? '' : expectation.catalogDigest, overlayCount: 0,
    targets: clear ? [] : expectation.targets.map(target => ({ probeId: target.probeId, pathId: target.pathId,
      stateLabel: label[current ? target.state : 'unknown'], runId: current ? target.runId : '', httpStatus: current ? target.httpStatus : 0,
      layers: current ? Object.fromEntries(Object.entries(target.layers).map(([key, value]) => [key, label[value]])) : {} })) }
}
function projection(expectation = expected(), phase = 'fresh') {
  return projectProbeDOM(dom(expectation, phase), expectation, { phase, observedAt: date(phase === 'expired' ? 301 : phase === 'withdrawn' ? 121 : 101) })
}
const network = () => ({ url: 'https://127.0.0.1:17861/api/v1/probes/details', method: 'GET', status: 200,
  authorizationPresent: true, resourceType: 'fetch', bodyBytes: 100, bodySHA256: 'c'.repeat(64) })
function evidence(engine = 'chrome-cdp') {
  return { engine, sourceCommit: 'd'.repeat(40), fixtureId: 'e'.repeat(32), backendVerificationSHA256: 'a'.repeat(64),
    webManifestSHA256: 'f'.repeat(64), observations: [projection()], network: [projectProbeNetwork(network())], artifacts: [] }
}

unit('probe browser synthetic fresh derives exactly three latest run IDs from six public samples', () => {
  const fixture = api(), value = expected(fixture)
  assert.equal(fixture.details.samples.length, 6); assert.equal(value.targets.length, 3)
  assert.deepEqual(value.targets.map(t => t.runId), ids.map(id => `run-${id}-1`)); assert.equal(value.detailsBodySHA256, hash(bytes(fixture.details)))
  assert.equal(value.backendReferenceScope, 'DIGEST_REFERENCE_REQUIRES_INDEPENDENT_RUNNER_BINDING'); assert.ok(Object.isFrozen(value.targets[0]))
})
unit('probe browser expired API projects unknown targets without retaining sample IDs', () => {
  const value = expected(api('expired')); assert.equal(value.phase, 'expired'); assert.ok(value.targets.every(t => t.state === 'unknown' && t.runId === ''))
})
unit('probe browser duplicate JSON keys including escaped aliases are rejected', () => {
  for (const text of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"nested":{"x":1,"x":2}}']) rejected(() => parseProbePublicJSON(Buffer.from(text)))
})
unit('probe browser malformed UTF8 BOM floats truncation and trailing bytes are rejected', () => {
  for (const raw of [Buffer.from([0xff]), Buffer.from('\ufeff{}'), Buffer.from('{"x":1.2}'), Buffer.from('{"x":1e2}'), Buffer.from('{'), Buffer.from('{}false')]) rejected(() => parseProbePublicJSON(raw))
})
unit('probe browser unknown secret fields are rejected without echoing values', () => {
  const fixture = api(); fixture.details.token = 'PRIVATE-SENTINEL'; rejected(() => expected(fixture))
  const raw = dom(expected()); raw.html = '<input value="PRIVATE-SENTINEL">'; rejected(() => projectProbeDOM(raw, expected(), { phase: 'fresh', observedAt: date(101) }))
})
unit('probe browser backend checker digest reference is mandatory', () => {
  const fixture = api(); rejected(() => deriveProbeBrowserExpected({ statusBytes: bytes(fixture.status), detailsBytes: bytes(fixture.details), backendVerificationSHA256: '', phase: 'fresh' }))
})
unit('probe browser run ID duplicates catalogue and target binding mutations are rejected', () => {
  for (const change of [f => { f.details.samples[1].runId = f.details.samples[0].runId }, f => { f.details.catalogDigest = 'b'.repeat(64) }, f => { f.details.samples[0].pathId = 'other' }]) {
    const fixture = api(); change(fixture); rejected(() => expected(fixture))
  }
})
unit('probe browser business layer classification and retry TTL facts remain distinct', () => {
  for (const change of [f => { f.details.samples[0].layers.business.state = 'available' }, f => { f.details.samples[0].layers.business.retryAfterSeconds = 29 }, f => { f.details.samples[0].layers.tls.expiresAt = date(1000) }]) {
    const fixture = api(); change(fixture); rejected(() => expected(fixture))
  }
})
unit('probe browser HTTP status and response size cannot be relabelled as success', () => {
  for (const change of [f => { f.details.samples[0].httpStatus = 200 }, f => { f.details.samples[0].responseBytes = true }]) { const fixture = api(); change(fixture); rejected(() => expected(fixture)) }
})
unit('probe browser original sample TTL cannot be extended and nanoseconds are respected', () => {
  const fixture = api(); fixture.details.samples[0].expiresAt = date(500); rejected(() => expected(fixture))
  const want = expected(); rejected(() => projectProbeDOM(dom(want), want, { phase: 'fresh', observedAt: want.deadline }))
})
unit('probe browser cache expiry is not falsely called original evidence expiry', () => {
  assert.equal(expected(api('fresh', 100)).deadlineKind, 'EVIDENCE_TTL')
  assert.equal(expected(api('fresh', 70)).deadlineKind, 'CACHE_OR_EVIDENCE_DEADLINE')
})
unit('probe browser independently read API status and details generations must match', () => {
  const fixture = api(); fixture.details.status.cachedAt = date(99); rejected(() => expected(fixture))
})
unit('probe browser fresh DOM binds catalogue three latest samples and fifteen layers', () => {
  const value = projection(); assert.equal(value.targets.length, 3); assert.equal(value.targets.reduce((n, t) => n + Object.keys(t.layers).length, 0), 15)
  const want = expected(), raw = dom(want); raw.targets[0].runId = 'run-pass-1'; rejected(() => projectProbeDOM(raw, want, { phase: 'fresh', observedAt: date(101) }))
})
unit('probe browser mobile projection requires a real bounded nonoverflowing viewport', () => {
  const want = expected(); assert.equal(projectProbeDOM(dom(want, 'fresh', 375), want, { phase: 'fresh', observedAt: date(101) }).viewport.width, 375)
  const raw = dom(want, 'fresh', 375); raw.scrollWidth = 376; rejected(() => projectProbeDOM(raw, want, { phase: 'fresh', observedAt: date(101) }))
})
unit('probe browser withdrawn DOM removes every visible current sample without clock shortcuts', () => {
  const want = expected(); const value = projection(want, 'withdrawn'); assert.ok(value.targets.every(t => t.runId === '' && Object.keys(t.layers).length === 0))
  rejected(() => projectProbeDOM(dom(want), want, { phase: 'withdrawn', observedAt: date(121) }))
})
unit('probe browser token clearing checks empty password storage cookies and detail removal', () => {
  const want = expected(); assert.equal(projection(want, 'cleared').tokenEmpty, true)
  for (const field of ['tokenEmpty', 'storageEmpty', 'cookiesEmpty']) { const raw = dom(want, 'cleared'); raw[field] = false; rejected(() => projectProbeDOM(raw, want, { phase: 'cleared', observedAt: date(101) })) }
})
unit('probe browser actual expired projection cannot retain green badges or sample IDs', () => {
  const want = expected(api('expired')); assert.equal(projection(want, 'expired').detailMounted, true)
  const raw = dom(want, 'expired'); raw.targets[0].stateLabel = '可用'; rejected(() => projectProbeDOM(raw, want, { phase: 'expired', observedAt: date(301) }))
})
unit('probe browser caller constructed expected projections are not accepted as module output', () => {
  const want = expected(); rejected(() => projectProbeDOM(dom(want), clone(want), { phase: 'fresh', observedAt: date(101) }))
})
unit('probe browser network projection contains no headers token URL parameters or HTML', () => {
  const value = projectProbeNetwork(network()); assert.equal(value.path, '/api/v1/probes/details'); assert.ok(!('url' in value))
  for (const field of ['headers', 'token', 'html', 'requestHeaders']) rejected(() => projectProbeNetwork({ ...network(), [field]: 'PRIVATE-SENTINEL' }))
})
unit('probe browser network is fixed same origin readonly GET without query credentials or fragment', () => {
  for (const url of ['http://127.0.0.1:17861/', 'https://other.invalid/', 'https://127.0.0.1:17861/?token=secret', 'https://user:secret@127.0.0.1:17861/', 'https://127.0.0.1:17861/#secret']) rejected(() => projectProbeNetwork({ ...network(), url }))
  rejected(() => projectProbeNetwork({ ...network(), method: 'POST' })); rejected(() => projectProbeNetwork({ ...network(), url: 'https://127.0.0.1:17861/api/v1/probes/status' }))
})
unit('probe browser static assets require the public build manifest allowlist', () => {
  const raw = { ...network(), url: 'https://127.0.0.1:17861/assets/index-abcdef.js', authorizationPresent: false, resourceType: 'script' }
  rejected(() => projectProbeNetwork(raw)); assert.equal(projectProbeNetwork(raw, { assetPaths: ['/assets/index-abcdef.js'] }).resourceType, 'script')
  rejected(() => projectProbeNetwork({ ...raw, bodySHA256: 'secret' }, { assetPaths: ['/assets/index-abcdef.js'] }))
})
unit('probe browser both engines remain explicitly contract only never runtime acceptance', () => {
  assert.deepEqual(ENGINES, ['chrome-cdp', 'playwright'])
  for (const engine of ENGINES) {
    const value = createProbeBrowserEvidence(evidence(engine)); assert.equal(value.schema, BROWSER_SCHEMA); assert.equal(value.engine, engine)
    assert.equal(value.outcome, 'CONTRACT_VALIDATED_ONLY'); assert.equal(value.browserE2EProven, false); assert.equal(value.runtimeProven, false); assert.equal(value.production, false)
  }
  rejected(() => createProbeBrowserEvidence({ ...evidence(), runtimeProven: true }))
})
unit('probe browser reports reject forged projections and another backend digest', () => {
  const first = evidence(); first.observations = [clone(first.observations[0])]; rejected(() => createProbeBrowserEvidence(first))
  rejected(() => createProbeBrowserEvidence({ ...evidence(), backendVerificationSHA256: '0'.repeat(64) }))
})
unit('probe browser artifact names engine suffix hashes and duplicate references are closed', () => {
  const value = evidence(), artifact = { name: 'probe-browser-cdp-fresh-desktop.png', kind: 'screenshot', bytes: 10, sha256: '1'.repeat(64) }
  value.artifacts = [artifact]; assert.equal(createProbeBrowserEvidence(value).artifacts.length, 1)
  for (const name of ['../secret.png', 'token.private', 'probe-browser-playwright-fresh-desktop.png']) rejected(() => createProbeBrowserEvidence({ ...evidence(), artifacts: [{ ...artifact, name }] }))
  rejected(() => createProbeBrowserEvidence({ ...evidence(), artifacts: [artifact, artifact] }))
})

assert.equal(names.length, 24)
assert.equal(new Set(names).size, 24)
assert.equal(hash(Buffer.from([...names].sort().join('\n') + '\n')), '284e603dc9edebcc889b0864265adc91ab9806f49621b47d147657e21e37aa37')
