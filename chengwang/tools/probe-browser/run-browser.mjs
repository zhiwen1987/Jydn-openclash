// CI flow core only. Adapters own browser launch/TLS/cleanup; final independent
// verification owns runtime acceptance and the eventual backend gate digest.
import { createHash } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import { parseProbePublicJSON, projectProbeNetwork } from './probe-browser-contract.mjs'

const ORIGIN = 'https://127.0.0.1:17861'
const STATUS = '/api/v1/probes/status', DETAILS = '/api/v1/probes/details'
const ids = ['limited', 'pass', 'restricted'], layers = ['dns', 'connect', 'tls', 'http', 'business']
const states = { limited: 'rate_limited', pass: 'available', restricted: 'restricted' }
const codes = { limited: 429, pass: 200, restricted: 403 }
const labels = { unknown: '未评估', available: '可用', restricted: '业务受限', rate_limited: '限流' }
const failure = () => { throw new Error('probe browser flow rejected') }
const need = value => { if (!value) failure() }
const hex = /^[a-f0-9]{64}$/
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
const copy = value => JSON.parse(JSON.stringify(value))
const same = (a, b) => JSON.stringify(a, (_, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item) ===
  JSON.stringify(b, (_, item) => item && typeof item === 'object' && !Array.isArray(item)
    ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item)
function exact(value, required, optional = []) {
  need(value && typeof value === 'object' && !Array.isArray(value) && required.every(key => Object.hasOwn(value, key)) &&
    Object.keys(value).every(key => required.includes(key) || optional.includes(key)))
}
function integer(value, low = 0, high = Number.MAX_SAFE_INTEGER) { need(Number.isSafeInteger(value) && value >= low && value <= high) }
function ns(text) {
  need(typeof text === 'string')
  const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.([0-9]{1,9}))?Z$/.exec(text); need(match)
  const millis = Date.parse(match[1] + 'Z'); need(Number.isFinite(millis) && new Date(millis).toISOString().slice(0, 19) === match[1])
  return BigInt(millis) * 1000000n + BigInt((match[2] ?? '').padEnd(9, '0'))
}
const msCeil = nano => Number((nano + 999999n) / 1000000n)

function status(value, phase) {
  exact(value, ['schema', 'configured', 'running', 'advisoryOnly', 'state', 'reason', 'clockHealthy', 'storageHealthy', 'cachedAt', 'expiresAt', 'coverage'])
  need(value.schema === 'chengwang.probe-view-status/v1')
  for (const key of ['configured', 'running', 'advisoryOnly', 'clockHealthy', 'storageHealthy']) need(value[key] === true)
  const expired = phase === 'expired'
  need(value.state === (expired ? 'partial' : 'ready') && value.reason === (expired ? 'evidence_expired' : 'ok'))
  need(same(value.coverage, { declaredTargets: 3, targetsWithSamples: expired ? 0 : 3, targetsMissing: expired ? 3 : 0,
    retainedSamples: expired ? 0 : 6, validTotal: 6, expiredTotal: expired ? 6 : 0, eligibleTotal: expired ? 0 : 6,
    rejectedTotal: 0, truncated: false, partial: expired }))
  need(ns(value.cachedAt) < ns(value.expiresAt) && ns(value.expiresAt) <= ns(value.cachedAt) + 30000000000n)
}

// This capture-time check deliberately has no backendVerificationSHA field. It
// establishes API/DOM consistency only. The final checker must bind the original
// corpus and reproject these bytes after backend22 and cleanup are complete.
function fromBodies(statusBytes, detailsBytes, phase) {
  const summary = parseProbePublicJSON(statusBytes), detail = parseProbePublicJSON(detailsBytes)
  status(summary, phase)
  exact(detail, ['schema', 'status', 'catalogDigest', 'agentId', 'independence', 'advisoryOnly', 'targets', 'samples', 'rejections'])
  status(detail.status, phase)
  need(detail.schema === 'chengwang.probe-view-details/v1' && /^sha256:[a-f0-9]{64}$/.test(detail.catalogDigest) &&
    detail.agentId === 'probe-readback-agent' && detail.independence === 'P1' && detail.advisoryOnly === true)
  need(same(detail.rejections, { format: 0, integrity: 0, catalog: 0, future: 0, duplicate: 0, semantic: 0 }))
  need(Array.isArray(detail.targets) && detail.targets.length === 3 && detail.targets.map(target => target.probeId).join(',') === ids.join(','))
  need(Array.isArray(detail.samples) && detail.samples.length === (phase === 'fresh' ? 6 : 0))
  const groups = new Map(ids.map(id => [id, []])), seen = new Set(), expiry = []
  for (const sample of detail.samples) {
    exact(sample, ['runId', 'probeId', 'pathId', 'attemptedAt', 'completedAt', 'expiresAt', 'conclusion', 'outcome', 'layers'], ['httpStatus', 'responseBytes', 'errorClass'])
    need(typeof sample.runId === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(sample.runId) && !seen.has(sample.runId)); seen.add(sample.runId)
    need(ids.includes(sample.probeId) && sample.pathId === 'direct' && sample.conclusion === states[sample.probeId] && sample.httpStatus === codes[sample.probeId])
    need(sample.outcome === (sample.probeId === 'pass' ? 'pass' : 'indeterminate') && (sample.errorClass ?? '') === (sample.probeId === 'pass' ? '' : states[sample.probeId]))
    need(sample.responseBytes === Buffer.byteLength(`chengwang-probe-${sample.probeId}-v1\n`))
    need(ns(sample.attemptedAt) <= ns(sample.completedAt) && ns(sample.completedAt) <= ns(detail.status.cachedAt) && ns(sample.expiresAt) === ns(sample.completedAt) + 120000000000n)
    need(ns(sample.completedAt) - ns(sample.attemptedAt) <= 3000000000n); expiry.push(ns(sample.expiresAt))
    exact(sample.layers, layers)
    for (const name of layers) {
      const layer = sample.layers[name]
      exact(layer, ['state', 'observedAt', 'expiresAt', 'latencyMillis', 'reason'], ['retryAfterSeconds'])
      need(layer.state === (name === 'business' ? states[sample.probeId] : 'available') && /^[a-z_]{1,64}$/.test(layer.reason))
      integer(layer.latencyMillis, 0, 3000)
      need(ns(sample.attemptedAt) <= ns(layer.observedAt) && ns(layer.observedAt) <= ns(sample.completedAt) && ns(layer.expiresAt) <= ns(sample.expiresAt) && ns(layer.expiresAt) > ns(detail.status.cachedAt))
      need(name === 'dns' ? ns(layer.expiresAt) >= ns(layer.observedAt) + 120000000000n : layer.observedAt === sample.completedAt && layer.expiresAt === sample.expiresAt)
      need((layer.retryAfterSeconds ?? 0) === (name === 'business' && sample.probeId === 'limited' ? 30 : 0)); expiry.push(ns(layer.expiresAt))
    }
    groups.get(sample.probeId).push(sample)
  }
  const targets = []
  for (const target of detail.targets) {
    exact(target, ['probeId', 'pathId', 'state', 'reason', 'consecutiveSuccess', 'consecutiveFailure', 'retainedSamples'], ['observedAt', 'expiresAt'])
    const id = target.probeId
    need(target.pathId === 'direct' && target.state === (phase === 'fresh' ? states[id] : 'unknown') &&
      target.reason === (phase === 'fresh' ? id === 'pass' ? 'two_consecutive_contract_matches' : states[id] : 'no_current_evidence'))
    need(target.consecutiveSuccess === (phase === 'fresh' && id === 'pass' ? 2 : 0) && target.consecutiveFailure === 0 && target.retainedSamples === (phase === 'fresh' ? 2 : 0))
    if (phase === 'fresh') {
      const pair = groups.get(id).sort((a, b) => ns(a.completedAt) < ns(b.completedAt) ? -1 : 1)
      need(pair.length === 2 && ns(pair[0].completedAt) < ns(pair[1].attemptedAt))
      const latest = pair[1]; need(target.observedAt === latest.completedAt && target.expiresAt === latest.expiresAt)
      targets.push({ probeId: id, pathId: 'direct', state: target.state, runId: latest.runId, httpStatus: latest.httpStatus,
        layers: Object.fromEntries(layers.map(name => [name, latest.layers[name].state])) })
    } else {
      need(!Object.hasOwn(target, 'observedAt') && !Object.hasOwn(target, 'expiresAt'))
      targets.push({ probeId: id, pathId: 'direct', state: 'unknown', runId: '', httpStatus: 0, layers: {} })
    }
  }
  const minExpiry = expiry.length ? expiry.reduce((a, b) => a < b ? a : b) : null
  const maxExpiry = expiry.length ? expiry.reduce((a, b) => a > b ? a : b) : null
  const deadline = minExpiry !== null && minExpiry < ns(detail.status.cachedAt) + 30000000000n ? minExpiry : ns(detail.status.cachedAt) + 30000000000n
  need(ns(detail.status.expiresAt) === deadline)
  return { generationMatches: same(summary, detail.status), phase, catalogDigest: detail.catalogDigest, cachedAt: detail.status.cachedAt,
    deadline: detail.status.expiresAt, deadlineKind: minExpiry !== null && deadline === minExpiry ? 'EVIDENCE_TTL' : 'CACHE_OR_EVIDENCE_DEADLINE',
    minExpiry, maxExpiry, targets }
}

function safeDOM(raw, model, phase, observedAt) {
  exact(raw, ['url', 'title', 'heading', 'viewport', 'scrollWidth', 'clientWidth', 'inputType', 'tokenEmpty', 'storageEmpty', 'cookiesEmpty', 'detailMounted', 'catalogText', 'targets', 'overlayCount'])
  need(raw.url === ORIGIN + '/' && raw.title === '澄网 · 网络代理与路由平台' && raw.heading === '代理节点观测')
  exact(raw.viewport, ['width', 'height']); integer(raw.viewport.width, 320, 1600); integer(raw.viewport.height, 320, 1200)
  need(raw.clientWidth === raw.viewport.width); integer(raw.scrollWidth, 1, raw.clientWidth)
  need(raw.inputType === 'password' && typeof raw.tokenEmpty === 'boolean' && raw.storageEmpty === true && raw.cookiesEmpty === true && raw.overlayCount === 0)
  const when = ns(observedAt)
  need(when >= ns(model.cachedAt))
  if (phase === 'fresh' || phase === 'cleared') need(when < ns(model.deadline))
  if (phase === 'withdrawn') need(when >= ns(model.deadline))
  need(Array.isArray(raw.targets))
  if (phase === 'cleared') need(raw.tokenEmpty === true && raw.detailMounted === false && raw.catalogText === '' && raw.targets.length === 0)
  else {
    need(raw.detailMounted === true && raw.catalogText === model.catalogDigest && raw.targets.length === 3)
    for (let index = 0; index < 3; index++) {
      const target = raw.targets[index], want = model.targets[index], fresh = phase === 'fresh'
      exact(target, ['probeId', 'pathId', 'stateLabel', 'runId', 'httpStatus', 'layers'])
      need(target.probeId === want.probeId && target.pathId === 'direct' && target.stateLabel === labels[fresh ? want.state : 'unknown'] &&
        target.runId === (fresh ? want.runId : '') && target.httpStatus === (fresh ? want.httpStatus : 0))
      exact(target.layers, fresh ? layers : [])
      if (fresh) for (const name of layers) need(target.layers[name] === labels[want.layers[name]])
    }
  }
  return copy(raw)
}

/**
 * driver is a real adapter or a synthetic unit-test double. Only completed
 * probe API responses enter networkSince. Its cursor is a gapless completion
 * ordinal, not a request-start ordering assertion. Screenshots return bytes.
 * expectedForBodies is an extra corpus-check callback; its return is not proof.
 */
export async function exerciseProbeBrowser(input) {
  try {
    exact(input, ['driver', 'token', 'expectedForBodies', 'savePublic', 'phaseSignals', 'deadline'])
    const { driver, token, expectedForBodies, savePublic, phaseSignals, deadline } = input
    need(driver && ['chrome-cdp', 'playwright'].includes(driver.engine))
    for (const method of ['navigate', 'click', 'clickText', 'fill', 'setViewport', 'snapshot', 'screenshot', 'networkSince']) need(typeof driver[method] === 'function')
    need(typeof token === 'string' && /^[\x21-\x2b\x2d-\x7e]{32,4096}$/.test(token))
    need(typeof expectedForBodies === 'function' && typeof savePublic === 'function' && typeof phaseSignals?.waitExpired === 'function')
    need(phaseSignals.freshReady === undefined || typeof phaseSignals.freshReady === 'function')
    integer(deadline, Date.now() + 1, Date.now() + 360000)
    const engine = driver.engine, prefix = `probe-browser-${engine === 'chrome-cdp' ? 'cdp' : 'playwright'}-`
    const captures = [], events = [], sources = new Map(), written = new Set()
    let cursor = 0, highWall = Date.now()
    const now = () => { const wall = Date.now(); need(wall >= highWall && wall < deadline); highWall = wall; return wall }
    const bounded = async (operation, maximum = 5000) => {
      const left = Math.min(maximum, deadline - now()); need(left > 0)
      let timer
      try { return await Promise.race([Promise.resolve().then(operation), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('probe browser flow rejected')), left) })]) }
      finally { clearTimeout(timer) }
    }
    const sleep = async milliseconds => { now(); await delay(Math.min(80, Math.max(1, milliseconds), deadline - now())); now() }
    const publish = async (name, bytes) => {
      need(name.startsWith(prefix) && /^probe-browser-(?:cdp|playwright)-(?:fresh|cleared|withdrawn|expired)-(?:status|details|dom|network|desktop|mobile)\.(?:json|jsonl|png)$/.test(name) && !written.has(name))
      need(bytes instanceof Uint8Array && bytes.byteLength > 0 && bytes.byteLength <= 16 << 20)
      const raw = Buffer.from(bytes); need(!raw.includes(Buffer.from(token)) && !raw.includes(Buffer.from('PRIVATE KEY')) && !raw.includes(Buffer.from('Bearer ')))
      await bounded(() => savePublic(name, raw)); written.add(name)
      return { name, bytes: raw.length, sha256: sha(raw) }
    }
    const drain = async stage => {
      const batch = await bounded(() => driver.networkSince(cursor)); exact(batch, ['cursor', 'responses'])
      integer(batch.cursor, cursor); need(Array.isArray(batch.responses) && events.length + batch.responses.length <= 128)
      for (const entry of batch.responses) {
        exact(entry, ['ordinal', 'url', 'method', 'status', 'authorizationPresent', 'resourceType', 'bodyBytes', 'bodySHA256', 'body', 'receivedUnixNano'])
        need(entry.ordinal === cursor + 1 && [ORIGIN + STATUS, ORIGIN + DETAILS].includes(entry.url) && entry.status === 200)
        need(entry.body instanceof Uint8Array && entry.bodyBytes === entry.body.byteLength && entry.bodyBytes > 0 && entry.bodyBytes <= 1 << 20 && hex.test(entry.bodySHA256) && entry.bodySHA256 === sha(entry.body))
        need(typeof entry.receivedUnixNano === 'string' && /^[1-9][0-9]{18}$/.test(entry.receivedUnixNano))
        need(!Buffer.from(entry.body).includes(Buffer.from(token)))
        const projected = projectProbeNetwork(Object.fromEntries(['url', 'method', 'status', 'authorizationPresent', 'resourceType', 'bodyBytes', 'bodySHA256'].map(key => [key, entry[key]])))
        events.push({ stage, ordinal: entry.ordinal, receivedUnixNano: entry.receivedUnixNano, ...projected, body: Buffer.from(entry.body) }); cursor = entry.ordinal
      }
      need(batch.cursor === cursor)
    }
    const response = async (path, after, stage) => {
      const stop = Math.min(deadline, now() + 5000)
      while (now() < stop) {
        await drain(stage)
        const matches = events.filter(entry => entry.path === path && entry.ordinal > after)
        if (matches.length) return matches.at(-1)
        await sleep(60)
      }
      failure()
    }
    const summary = async stage => {
      const fence = cursor; await bounded(() => driver.clickText('刷新探针摘要', '.probe-readback'))
      return response(STATUS, fence, stage)
    }
    const readPair = async (stage, phase, initialStatus = null) => {
      let first = initialStatus
      for (let attempt = 0; attempt < 8; attempt++) {
        now(); first ??= await summary(stage)
        const fence = cursor
        await bounded(() => driver.fill('#probe-token', token))
        await bounded(() => driver.clickText('读取受保护明细', '.probe-readback'))
        const second = await response(DETAILS, fence, stage)
        const model = fromBodies(first.body, second.body, phase)
        if (!model.generationMatches) { first = null; continue }
        if (phase === 'fresh') need(BigInt(now()) * 1000000n < ns(model.deadline))
        await bounded(() => expectedForBodies({ phase, statusBytes: Buffer.from(first.body), detailsBytes: Buffer.from(second.body) }))
        const statusFile = await publish(prefix + stage + '-status.json', first.body)
        const detailsFile = await publish(prefix + stage + '-details.json', second.body)
        sources.set(stage, { sourcePhase: phase, status: statusFile, details: detailsFile, statusOrdinal: first.ordinal,
          detailsOrdinal: second.ordinal, cachedAt: model.cachedAt, deadline: model.deadline, deadlineKind: model.deadlineKind })
        return model
      }
      failure()
    }
    const expand = async () => { for (let index = 1; index <= 3; index++) await bounded(() => driver.click(`.probe-targets li:nth-child(${index}) summary`)) }
    const snap = async (model, phase) => {
      const stop = Math.min(deadline, now() + 3000)
      while (now() < stop) {
        const raw = await bounded(() => driver.snapshot()), observedAt = new Date(now()).toISOString()
        try { return { observedAt, dom: safeDOM(raw, model, phase, observedAt) } } catch { await sleep(60) }
      }
      failure()
    }
    const png = async (stage, viewport, model, phase, expectedWidth) => {
      const before = BigInt(now()) * 1000000n
      if (phase === 'fresh') need(before < ns(model.deadline))
      const raw = await bounded(() => driver.screenshot())
      const capturedAt = new Date(now()).toISOString()
      if (phase === 'fresh') need(ns(capturedAt) < ns(model.deadline))
      need(raw instanceof Uint8Array)
      const image = Buffer.from(raw)
      need(image.length >= 33 && image.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex')) &&
        image.readUInt32BE(8) === 13 && image.subarray(12, 16).toString('ascii') === 'IHDR' && image.readUInt32BE(16) === expectedWidth)
      integer(image.readUInt32BE(20), 1, 12000)
      // This is a bounded header check, not an independent PNG decoder or a
      // claim that a test double rendered a real screenshot.
      const artifact = await publish(prefix + stage + '-' + viewport + '.png', raw)
      await snap(model, phase)
      return { ...artifact, capturedAt }
    }
    const capture = async (stage, observations, screenshots, sourceStage = stage) => {
      const value = { schema: 'chengwang.probe-browser-capture/v1', outcome: 'API_CAPTURE_UNBOUND', runtimeProven: false,
        browserE2EProven: false, engine, stage, source: sources.get(sourceStage), observations, screenshots }
      need(value.source); const artifact = await publish(prefix + stage + '-dom.json', Buffer.from(JSON.stringify(value) + '\n'))
      captures.push({ ...value, artifact })
    }

    await bounded(() => driver.setViewport({ width: 1440, height: 1000 }))
    await bounded(() => driver.navigate(ORIGIN + '/'))
    await bounded(() => driver.clickText('代理节点'))
    const initial = await response(STATUS, 0, 'fresh')
    const fresh = await readPair('fresh', 'fresh', initial)
    await expand()
    const desktop = await snap(fresh, 'fresh'), desktopPNG = await png('fresh', 'desktop', fresh, 'fresh', 1440)
    await bounded(() => driver.setViewport({ width: 375, height: 812 }))
    const mobile = await snap(fresh, 'fresh'), mobilePNG = await png('fresh', 'mobile', fresh, 'fresh', 375)
    await capture('fresh', [desktop, mobile], [desktopPNG, mobilePNG])

    await bounded(() => driver.setViewport({ width: 1440, height: 1000 }))
    await drain('fresh')
    await bounded(() => driver.clickText('清除明细与令牌', '.probe-readback'))
    const cleared = await snap(fresh, 'cleared')
    const anonymous = await summary('cleared'); need(anonymous.authorizationPresent === false)
    status(parseProbePublicJSON(anonymous.body), 'fresh')
    await capture('cleared', [cleared], [], 'fresh')

    // A late real refresh makes the held details' deadline the original layer
    // TTL when possible, rather than silently claiming a 30s cache timeout is it.
    while (now() < msCeil(fresh.minExpiry) - 25000) await sleep(80)
    const held = await readPair('withdrawn', 'fresh')
    need(held.catalogDigest === fresh.catalogDigest && same(held.targets, fresh.targets))
    await expand(); await snap(held, 'fresh')
    if (phaseSignals.freshReady) await bounded(() => phaseSignals.freshReady())
    while (BigInt(now()) * 1000000n < ns(held.deadline)) await sleep(80)
    const withdrawn = await snap(held, 'withdrawn'), withdrawnPNG = await png('withdrawn', 'desktop', held, 'withdrawn', 1440)
    await capture('withdrawn', [withdrawn], [withdrawnPNG])

    await bounded(() => phaseSignals.waitExpired(), deadline - now())
    while (BigInt(now()) * 1000000n < held.maxExpiry) await sleep(80)
    const expired = await readPair('expired', 'expired')
    need(expired.catalogDigest === fresh.catalogDigest && ns(expired.cachedAt) >= held.maxExpiry)
    await expand()
    await bounded(() => driver.setViewport({ width: 375, height: 812 }))
    const expiredDOM = await snap(expired, 'expired'), expiredPNG = await png('expired', 'mobile', expired, 'expired', 375)
    await capture('expired', [expiredDOM], [expiredPNG])
    await drain('expired')
    for (const stage of ['fresh', 'cleared', 'withdrawn', 'expired']) {
      const publicEvents = events.filter(entry => entry.stage === stage).map(({ body: _body, ...entry }) => entry)
      need(publicEvents.length > 0)
      await publish(prefix + stage + '-network.jsonl', Buffer.from(publicEvents.map(entry => JSON.stringify(entry) + '\n').join('')))
    }
    return { schema: 'chengwang.probe-browser-flow/v1', outcome: 'API_CAPTURE_UNBOUND', runtimeProven: false,
      browserE2EProven: false, authorization: 'BLOCKED', production: false, deviceActionsExecuted: false, engine,
      captures, network: events.map(({ body: _body, ...entry }) => entry), files: [...written].sort(), deadlineKind: held.deadlineKind }
  } catch { failure() }
}
