// CI-only contracts shared by future CDP and Playwright adapters. No I/O, browser
// launch, NSS mutation or runtime-acceptance assertion belongs in this module.
import { createHash } from 'node:crypto'

export const BROWSER_SCHEMA = 'chengwang.probe-readback-browser/v1'
export const ENGINES = Object.freeze(['chrome-cdp', 'playwright'])
const origin = 'https://127.0.0.1:17861'
const ids = ['limited', 'pass', 'restricted']
const layerNames = ['dns', 'connect', 'tls', 'http', 'business']
const states = ['unknown', 'available', 'degraded', 'restricted', 'unavailable', 'rate_limited']
const labels = { unknown: '未评估', available: '可用', degraded: '待确认 / 降级', restricted: '业务受限', unavailable: '不可用', rate_limited: '限流' }
const expectedState = { limited: 'rate_limited', pass: 'available', restricted: 'restricted' }
const codes = { limited: 429, pass: 200, restricted: 403 }
const hex = /^[a-f0-9]{64}$/
const expectedProjections = new WeakSet(), domProjections = new WeakSet(), networkProjections = new WeakSet()
const fail = () => { throw new Error('probe browser contract rejected') }
const need = value => { if (!value) fail() }
const sha = raw => createHash('sha256').update(raw).digest('hex')
const integer = (value, low = 0, high = Number.MAX_SAFE_INTEGER) => need(Number.isSafeInteger(value) && value >= low && value <= high)
const exact = (value, keys, optional = []) => {
  need(value !== null && typeof value === 'object' && !Array.isArray(value))
  need(keys.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => keys.includes(key) || optional.includes(key)))
  return value
}
const stable = value => JSON.stringify(value, (_, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item)
const copy = value => JSON.parse(JSON.stringify(value))
function freeze(value) { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value) }; return value }
function branded(value, registry) { freeze(value); registry.add(value); return value }

// JSON.parse alone accepts duplicate keys. API bodies are bounded public bytes;
// this independent decoder rejects duplicates, noninteger numbers and bad UTF-8.
function parsePublicJSON(bytes) {
  need(bytes instanceof Uint8Array && bytes.byteLength > 0 && bytes.byteLength <= 1 << 20)
  let text
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) } catch { fail() }
  let at = 0
  const space = () => { while (/[\t\r\n ]/.test(text[at] ?? '\0')) at++ }
  const string = () => {
    const begin = at++; need(text[begin] === '"')
    while (at < text.length) {
      const ch = text[at++]
      if (ch === '"') { try { return JSON.parse(text.slice(begin, at)) } catch { fail() } }
      need(ch.charCodeAt(0) >= 32)
      if (ch === '\\') {
        const escaped = text[at++]; need('"\\/bfnrtu'.includes(escaped ?? '\0'))
        if (escaped === 'u') { need(/^[a-fA-F0-9]{4}$/.test(text.slice(at, at + 4))); at += 4 }
      }
    }
    fail()
  }
  const value = depth => {
    need(depth <= 20); space()
    if (text[at] === '"') return string()
    if (text[at] === '{') {
      at++; space(); const out = Object.create(null)
      if (text[at] === '}') { at++; return out }
      while (true) {
        space(); const key = string(); need(key.length <= 128 && !Object.hasOwn(out, key)); space(); need(text[at++] === ':')
        out[key] = value(depth + 1); need(Object.keys(out).length <= 128); space()
        const separator = text[at++]; if (separator === '}') return out; need(separator === ',')
      }
    }
    if (text[at] === '[') {
      at++; space(); const out = []
      if (text[at] === ']') { at++; return out }
      while (true) {
        out.push(value(depth + 1)); need(out.length <= 256); space()
        const separator = text[at++]; if (separator === ']') return out; need(separator === ',')
      }
    }
    for (const [word, parsed] of [['true', true], ['false', false], ['null', null]]) {
      if (text.slice(at, at + word.length) === word) { at += word.length; return parsed }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?![0-9.eE+-])/.exec(text.slice(at)); need(number)
    at += number[0].length; const parsed = Number(number[0]); need(Number.isSafeInteger(parsed)); return parsed
  }
  const parsed = value(0); space(); need(at === text.length); return parsed
}

function nanos(text) {
  need(typeof text === 'string')
  const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.([0-9]{1,9}))?Z$/.exec(text); need(match)
  const ms = Date.parse(match[1] + 'Z'); need(Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 19) === match[1])
  const result = BigInt(ms) * 1000000n + BigInt((match[2] ?? '').padEnd(9, '0')); need(result > 0n); return result
}
const statusKeys = ['schema', 'configured', 'running', 'advisoryOnly', 'state', 'reason', 'clockHealthy', 'storageHealthy', 'cachedAt', 'expiresAt', 'coverage']
const coverageKeys = ['declaredTargets', 'targetsWithSamples', 'targetsMissing', 'retainedSamples', 'validTotal', 'expiredTotal', 'eligibleTotal', 'rejectedTotal', 'truncated', 'partial']
function validateStatus(status, phase) {
  exact(status, statusKeys); exact(status.coverage, coverageKeys)
  need(status.schema === 'chengwang.probe-view-status/v1')
  for (const key of ['configured', 'running', 'advisoryOnly', 'clockHealthy', 'storageHealthy']) need(status[key] === true)
  const expired = phase === 'expired', c = status.coverage
  need(status.state === (expired ? 'partial' : 'ready') && status.reason === (expired ? 'evidence_expired' : 'ok'))
  const desired = { declaredTargets: 3, targetsWithSamples: expired ? 0 : 3, targetsMissing: expired ? 3 : 0,
    retainedSamples: expired ? 0 : 6, validTotal: 6, expiredTotal: expired ? 6 : 0, eligibleTotal: expired ? 0 : 6,
    rejectedTotal: 0, truncated: false, partial: expired }
  need(stable(c) === stable(desired))
  const cache = nanos(status.cachedAt), until = nanos(status.expiresAt)
  need(cache < until && until <= cache + 30000000000n)
}
function validateLayer(layer) {
  exact(layer, ['state', 'observedAt', 'expiresAt', 'latencyMillis', 'reason'], ['retryAfterSeconds'])
  need(states.includes(layer.state) && typeof layer.reason === 'string' && /^[a-z_]{1,64}$/.test(layer.reason))
  need(nanos(layer.observedAt) < nanos(layer.expiresAt)); integer(layer.latencyMillis, 0, 3000)
  if (Object.hasOwn(layer, 'retryAfterSeconds')) integer(layer.retryAfterSeconds, 1, 3600)
}

function deriveExpected(input) {
  exact(input, ['statusBytes', 'detailsBytes', 'backendVerificationSHA256', 'phase'])
  need(hex.test(input.backendVerificationSHA256) && ['fresh', 'expired'].includes(input.phase))
  const status = parsePublicJSON(input.statusBytes), details = parsePublicJSON(input.detailsBytes)
  validateStatus(status, input.phase)
  exact(details, ['schema', 'status', 'catalogDigest', 'agentId', 'independence', 'advisoryOnly', 'targets', 'samples', 'rejections'])
  need(details.schema === 'chengwang.probe-view-details/v1' && stable(details.status) === stable(status) &&
    /^sha256:[a-f0-9]{64}$/.test(details.catalogDigest) && details.agentId === 'probe-readback-agent' && details.independence === 'P1' && details.advisoryOnly === true)
  need(stable(details.rejections) === stable({ format: 0, integrity: 0, catalog: 0, future: 0, duplicate: 0, semantic: 0 }))
  need(Array.isArray(details.targets) && details.targets.length === 3 && details.targets.map(t => t.probeId).join(',') === ids.join(','))
  need(Array.isArray(details.samples) && details.samples.length === (input.phase === 'fresh' ? 6 : 0))
  const seen = new Set(), samples = new Map(ids.map(id => [id, []]))
  let evidenceUntil = null
  for (const sample of details.samples) {
    exact(sample, ['runId', 'probeId', 'pathId', 'attemptedAt', 'completedAt', 'expiresAt', 'conclusion', 'outcome', 'layers'], ['httpStatus', 'responseBytes', 'errorClass'])
    need(typeof sample.runId === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(sample.runId) && !seen.has(sample.runId)); seen.add(sample.runId)
    need(ids.includes(sample.probeId) && sample.pathId === 'direct' && sample.conclusion === expectedState[sample.probeId] && sample.httpStatus === codes[sample.probeId])
    need(sample.outcome === (sample.probeId === 'pass' ? 'pass' : 'indeterminate'))
    need((sample.errorClass ?? '') === (sample.probeId === 'pass' ? '' : expectedState[sample.probeId]))
    need(sample.responseBytes === Buffer.byteLength(`chengwang-probe-${sample.probeId}-v1\n`))
    need(nanos(sample.attemptedAt) <= nanos(sample.completedAt) && nanos(sample.completedAt) <= nanos(status.cachedAt) && nanos(sample.expiresAt) === nanos(sample.completedAt) + 120000000000n)
    need(nanos(sample.completedAt) - nanos(sample.attemptedAt) <= 3000000000n)
    exact(sample.layers, layerNames)
    for (const name of layerNames) {
      const layer = sample.layers[name]; validateLayer(layer)
      need(layer.state === (name === 'business' ? expectedState[sample.probeId] : 'available'))
      need(nanos(layer.expiresAt) > nanos(status.cachedAt))
      need(nanos(sample.attemptedAt) <= nanos(layer.observedAt) && nanos(layer.observedAt) <= nanos(sample.completedAt) && nanos(layer.expiresAt) <= nanos(sample.expiresAt))
      if (name === 'dns') need(nanos(layer.expiresAt) >= nanos(layer.observedAt) + 120000000000n)
      else need(layer.observedAt === sample.completedAt && layer.expiresAt === sample.expiresAt)
      need((layer.retryAfterSeconds ?? 0) === (name === 'business' && sample.probeId === 'limited' ? 30 : 0))
      const until = nanos(layer.expiresAt); evidenceUntil = evidenceUntil === null || until < evidenceUntil ? until : evidenceUntil
    }
    samples.get(sample.probeId).push(sample)
  }
  const targets = []
  for (const target of details.targets) {
    exact(target, ['probeId', 'pathId', 'state', 'reason', 'consecutiveSuccess', 'consecutiveFailure', 'retainedSamples'], ['observedAt', 'expiresAt'])
    const id = target.probeId; need(target.pathId === 'direct')
    need(target.state === (input.phase === 'fresh' ? expectedState[id] : 'unknown'))
    need(target.reason === (input.phase === 'expired' ? 'no_current_evidence' : id === 'pass' ? 'two_consecutive_contract_matches' : expectedState[id]))
    integer(target.consecutiveSuccess); integer(target.consecutiveFailure); integer(target.retainedSamples)
    need(target.consecutiveSuccess === (input.phase === 'fresh' && id === 'pass' ? 2 : 0) && target.consecutiveFailure === 0 && target.retainedSamples === (input.phase === 'fresh' ? 2 : 0))
    const pair = samples.get(id).sort((a, b) => nanos(a.completedAt) < nanos(b.completedAt) ? -1 : nanos(a.completedAt) > nanos(b.completedAt) ? 1 : a.runId.localeCompare(b.runId))
    if (input.phase === 'fresh') {
      need(pair.length === 2 && nanos(pair[0].completedAt) < nanos(pair[1].attemptedAt))
      const latest = pair[1]; need(target.observedAt === latest.completedAt && target.expiresAt === latest.expiresAt)
      targets.push({ probeId: id, pathId: 'direct', state: target.state, runId: latest.runId, httpStatus: latest.httpStatus,
        layers: Object.fromEntries(layerNames.map(name => [name, latest.layers[name].state])) })
    } else {
      need(!Object.hasOwn(target, 'observedAt') && !Object.hasOwn(target, 'expiresAt'))
      targets.push({ probeId: id, pathId: 'direct', state: 'unknown', runId: '', httpStatus: 0, layers: {} })
    }
  }
  const maximumDeadline = nanos(status.cachedAt) + 30000000000n
  need(nanos(status.expiresAt) === (evidenceUntil !== null && evidenceUntil < maximumDeadline ? evidenceUntil : maximumDeadline))
  return branded({ phase: input.phase, backendVerificationSHA256: input.backendVerificationSHA256,
    backendReferenceScope: 'DIGEST_REFERENCE_REQUIRES_INDEPENDENT_RUNNER_BINDING', statusBodySHA256: sha(input.statusBytes),
    detailsBodySHA256: sha(input.detailsBytes), catalogDigest: details.catalogDigest, cachedAt: status.cachedAt,
    deadline: status.expiresAt, deadlineKind: evidenceUntil !== null && nanos(status.expiresAt) === evidenceUntil ? 'EVIDENCE_TTL' : 'CACHE_OR_EVIDENCE_DEADLINE', targets }, expectedProjections)
}

function projectDOM(raw, expected, options) {
  exact(options, ['phase', 'observedAt']); need(['fresh', 'cleared', 'withdrawn', 'expired'].includes(options.phase))
  exact(raw, ['url', 'title', 'heading', 'viewport', 'scrollWidth', 'clientWidth', 'inputType', 'tokenEmpty', 'storageEmpty', 'cookiesEmpty', 'detailMounted', 'catalogText', 'targets', 'overlayCount'])
  need(raw.url === origin + '/' && raw.title === '澄网 · 网络代理与路由平台' && raw.heading === '代理节点观测')
  exact(raw.viewport, ['width', 'height']); integer(raw.viewport.width, 320, 1600); integer(raw.viewport.height, 320, 1200)
  need(raw.clientWidth === raw.viewport.width); integer(raw.scrollWidth, 1, raw.clientWidth)
  need(raw.inputType === 'password' && typeof raw.tokenEmpty === 'boolean' && raw.storageEmpty === true && raw.cookiesEmpty === true && raw.overlayCount === 0)
  const time = nanos(options.observedAt), phase = options.phase
  need(expectedProjections.has(expected))
  need(phase === 'expired' ? expected.phase === 'expired' : expected.phase === 'fresh')
  need(time >= nanos(expected.cachedAt))
  if (phase === 'fresh' || phase === 'cleared') need(time < nanos(expected.deadline))
  if (phase === 'withdrawn') need(time >= nanos(expected.deadline))
  need(Array.isArray(raw.targets))
  if (phase === 'cleared') need(raw.tokenEmpty === true && raw.detailMounted === false && raw.catalogText === '' && raw.targets.length === 0)
  else {
    need(raw.detailMounted === true && raw.catalogText === expected.catalogDigest && raw.targets.length === 3)
    for (let index = 0; index < raw.targets.length; index++) {
      const target = raw.targets[index], want = expected.targets[index]
      exact(target, ['probeId', 'pathId', 'stateLabel', 'runId', 'httpStatus', 'layers'])
      need(target.probeId === want.probeId && target.pathId === want.pathId)
      const current = phase === 'fresh'
      need(target.stateLabel === labels[current ? want.state : 'unknown'] && target.runId === (current ? want.runId : '') && target.httpStatus === (current ? want.httpStatus : 0))
      exact(target.layers, current ? layerNames : [])
      if (current) for (const name of layerNames) need(target.layers[name] === labels[want.layers[name]])
    }
  }
  return branded({ phase, observedAt: options.observedAt, backendVerificationSHA256: expected.backendVerificationSHA256,
    statusBodySHA256: expected.statusBodySHA256, detailsBodySHA256: expected.detailsBodySHA256,
    viewport: copy(raw.viewport), horizontalOverflow: false, inputType: 'password', tokenEmpty: raw.tokenEmpty,
    storageEmpty: true, cookiesEmpty: true, detailMounted: raw.detailMounted, catalogDigest: raw.catalogText,
    targets: copy(raw.targets), deadlineKind: phase === 'withdrawn' ? expected.deadlineKind : 'NOT_AN_EXPIRY_CLAIM' }, domProjections)
}

function projectNetwork(raw, options = { assetPaths: [] }) {
  exact(options, ['assetPaths'])
  need(Array.isArray(options.assetPaths) && options.assetPaths.length <= 128 && new Set(options.assetPaths).size === options.assetPaths.length)
  need(options.assetPaths.every(path => typeof path === 'string' && /^\/assets\/[A-Za-z0-9_-]{1,100}\.[A-Za-z0-9]{1,8}$/.test(path)))
  exact(raw, ['url', 'method', 'status', 'authorizationPresent', 'resourceType', 'bodyBytes', 'bodySHA256'])
  need(typeof raw.url === 'string' && raw.url.length <= 256)
  let url; try { url = new URL(raw.url) } catch { fail() }
  need(url.href === raw.url && url.origin === origin && !url.username && !url.password && !url.search && !url.hash && raw.method === 'GET')
  const api = ['/api/v1/snapshot', '/api/v1/observations/status', '/api/v1/probes/status', '/api/v1/probes/details']
  need(url.pathname === '/' || options.assetPaths.includes(url.pathname) || api.includes(url.pathname))
  need(typeof raw.authorizationPresent === 'boolean' && raw.authorizationPresent === (url.pathname === '/api/v1/probes/details'))
  integer(raw.status, 100, 599); need(raw.status === 200 || url.pathname === '/api/v1/probes/details' && [401, 403].includes(raw.status))
  need(['document', 'script', 'stylesheet', 'font', 'image', 'fetch', 'xhr', 'other'].includes(raw.resourceType))
  integer(raw.bodyBytes, 0, 16 << 20); need(hex.test(raw.bodySHA256))
  return branded({ method: 'GET', path: url.pathname, status: raw.status, authorizationPresent: raw.authorizationPresent,
    resourceType: raw.resourceType, bodyBytes: raw.bodyBytes, bodySHA256: raw.bodySHA256 }, networkProjections)
}

function createEvidence(input) {
  exact(input, ['engine', 'sourceCommit', 'fixtureId', 'backendVerificationSHA256', 'webManifestSHA256', 'observations', 'network', 'artifacts'])
  need(ENGINES.includes(input.engine) && /^[a-f0-9]{40}$/.test(input.sourceCommit) && /^[a-f0-9]{32}$/.test(input.fixtureId) && hex.test(input.backendVerificationSHA256) && hex.test(input.webManifestSHA256))
  need(Array.isArray(input.observations) && input.observations.length > 0 && input.observations.length <= 16)
  // Accept only immutable projections validated in this module instance. This
  // still proves contracts, not that a real browser/runner produced the inputs.
  need(input.observations.every(item => domProjections.has(item) && item.backendVerificationSHA256 === input.backendVerificationSHA256))
  need(Array.isArray(input.network) && input.network.length <= 128 && input.network.every(item => networkProjections.has(item)))
  need(Array.isArray(input.artifacts) && input.artifacts.length <= 64)
  const names = new Set()
  for (const artifact of input.artifacts) {
    exact(artifact, ['name', 'kind', 'bytes', 'sha256'])
    need(typeof artifact.name === 'string' && /^probe-browser-(?:cdp|playwright)-(?:fresh|cleared|withdrawn|expired)-(?:desktop|mobile|status|details|dom|network)\.(?:png|json|jsonl)$/.test(artifact.name) && !names.has(artifact.name)); names.add(artifact.name)
    need(['screenshot', 'api-body', 'safe-dom', 'safe-network'].includes(artifact.kind) && hex.test(artifact.sha256)); integer(artifact.bytes, 1, 16 << 20)
    need(artifact.name.startsWith(`probe-browser-${input.engine === 'chrome-cdp' ? 'cdp' : 'playwright'}-`))
    need(artifact.name.endsWith(artifact.kind === 'screenshot' ? '.png' : artifact.kind === 'safe-network' ? '.jsonl' : '.json'))
  }
  return freeze({ schema: BROWSER_SCHEMA, outcome: 'CONTRACT_VALIDATED_ONLY', engine: input.engine,
    sourceCommit: input.sourceCommit, fixtureId: input.fixtureId, backendVerificationSHA256: input.backendVerificationSHA256,
    webManifestSHA256: input.webManifestSHA256, authorization: 'BLOCKED', production: false, deviceActionsExecuted: false,
    advisoryOnly: true, runtimeProven: false, browserE2EProven: false, actualInternetReachabilityProven: false,
    agentIdentitySignatureProven: false, browserPluginUsed: false, acceptanceScope: 'CONTRACT_ONLY_NOT_RUNTIME_ACCEPTANCE',
    observations: copy(input.observations), network: copy(input.network), artifacts: copy(input.artifacts) })
}

const guarded = implementation => (...args) => { try { return implementation(...args) } catch { fail() } }
export const parseProbePublicJSON = guarded(parsePublicJSON)
export const deriveProbeBrowserExpected = guarded(deriveExpected)
export const projectProbeDOM = guarded(projectDOM)
export const projectProbeNetwork = guarded(projectNetwork)
export const createProbeBrowserEvidence = guarded(createEvidence)
