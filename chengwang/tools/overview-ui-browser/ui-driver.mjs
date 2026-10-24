// Thin source-owned scene. Native lifecycle, passive wire journal and observed
// DOM validation remain separate; none is replaced by an expected UI object.
import { lstat } from 'node:fs/promises'
import { performance } from 'node:perf_hooks'
import { stableFile, publish, publishReady, until } from '../subscription-ui-browser/ui-driver.mjs'
import { openNativeSession, validateSessionOptions } from '../browser-scene-driver/native-session.mjs'
import { OverviewJournal } from './overview-journal.mjs'
import { domExpression, validateCheckpoint } from './ui-dom.mjs'
import { loadContract, validateInput, validateRun, validateBuild, apiFence, exactCounts, scope, need, exact, sha, safePublic, canaryVariants, strictJSON, stepsFor } from './ui-contract.mjs'

const settleExpression = '(async()=>{await document.fonts.ready;window.scrollTo(0,0);await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));return true})()'
const pageIdentity = origin => 'location.href===' + JSON.stringify(origin + '/') + '&&document.title==="澄网 · 网络代理与路由平台"&&!document.querySelector("vite-error-overlay,nextjs-portal,[data-vite-error-overlay]")'

// This is the same action loop used by the real default run. Explicit protocol
// fixtures can exercise it without giving runOverview an injectable launch path.
export async function orchestrateOverview(session, journal, c, input, o, io) {
  need(session && journal && exact(io, ['publish', 'ready', 'waitRun', 'wait', 'monotonic', 'wall', 'observe', 'validate', 'startedAt', 'canaries']))
  const profile = input.profile, fences = c.stepFences[profile], domRows = [], screenshots = []
  let nodesSince = null, closed = false
  const actionTimings = { nodeVisit: null }
  const deadline = () => need(io.monotonic() - io.startedAt <= 125000)
  const guard = () => {
    deadline(); need(!journal.failure && !journal.overflow)
    if (nodesSince !== null) need(io.monotonic() - nodesSince <= c.stepRules.nodesVisitSecondsMax * 1000)
    session.assertHealthy()
  }
  const currentRows = () => [...journal.rows].sort((a, b) => a.ordinal - b.ordinal)
  const click = async key => {
    guard(); const slot = c.controlSlots.find(v => v.key === key); need(slot)
    await session.click({ name: slot.label, ariaLabelOnly: slot.labelSource === 'ARIA_LABEL' }); guard()
  }
  const observeSettled = async fence => {
    guard(); need(await session.evaluate(settleExpression) === true)
    let observed = null
    await io.wait(async () => {
      guard()
      if (!journal.idle()) return false
      const rows = currentRows()
      if (!exactCounts(rows, fence)) return false
      need(await session.evaluate(pageIdentity(c.origin)) === true)
      const d = await io.observe(session, c)
      // These ordinals reference real completed capture rows, not invented DOM.
      d.apiFence = apiFence(rows)
      try { io.validate(fence[0], d, rows, c, profile) } catch { return false }
      observed = d; return true
    }, Math.max(1, Math.min(10000, 125000 - (io.monotonic() - io.startedAt))))
    guard(); need(observed); return observed
  }
  try {
    need(fences.map(v => v[0]).join(',') === stepsFor(profile).join(','))
    await io.ready(o.root + '/driver-ready.private.json', { schema: c.schemaNames.ready, scenario: c.scenario, profile, fixtureId: o.fixtureId, engine: o.engine, pid: process.pid, chromePid: session.chrome.pid })
    await io.waitRun(); guard()
    for (const fence of fences) {
      const [step, action] = fence; guard()
      if (action === 'navigate') { await session.resize(fence[5], fence[6]); await session.navigate(c.origin + '/') }
      else if (action === 'resize') await session.resize(fence[5], fence[6])
      else {
        if (action === 'cta_nodes') {
          nodesSince = io.monotonic()
          const enteredMonotonicUs = Math.floor(nodesSince * 1000)
          need(Number.isSafeInteger(enteredMonotonicUs) && enteredMonotonicUs >= 0)
          actionTimings.nodeVisit = { enteredMonotonicUs, returnedMonotonicUs: null }
        }
        await click(action)
      }
      const d = await observeSettled(fence), rows = currentRows()
      const row = { schema: c.schemaNames.domRow, ordinal: domRows.length + 1, step, captureCount: rows.length, mutationCount: journal.mutationCount(), dom: d }
      need(exact(row, c.exactKeySchemas['dom.jsonl[]']))
      const rowBytes = Buffer.from(JSON.stringify(row)); need(rowBytes.length <= c.captureRules.bounds.domRowBytes); safePublic(rowBytes, io.canaries); domRows.push(row)
      if (fence[10] !== null) {
        const bytes = await session.screenshot(); guard()
        need(Buffer.isBuffer(bytes) && bytes.length >= 24 && bytes.length <= c.pngFileBytesMax && bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) && bytes.readUInt32BE(16) === fence[5] && bytes.readUInt32BE(20) === fence[6])
        safePublic(bytes, io.canaries)
        const name = fence[10], metadata = await io.publish(o.root + '/' + name.replace(/\.png$/, '.private.png'), bytes, c.pngFileBytesMax)
        const capturedWallTimeUs = io.wall() * 1000; need(Number.isSafeInteger(capturedWallTimeUs) && capturedWallTimeUs > 0)
        screenshots.push({ path: name, step, ...metadata, viewport: { width: d.viewport.width, height: d.viewport.height }, scrollX: d.viewport.scrollX, scrollY: d.viewport.scrollY, capturedWallTimeUs })
      }
      if (step === 'actual_return_from_nodes') {
        guard()
        const returnedMonotonicUs = Math.ceil(io.monotonic() * 1000), visit = actionTimings.nodeVisit
        need(visit && Number.isSafeInteger(returnedMonotonicUs) && returnedMonotonicUs >= visit.enteredMonotonicUs && returnedMonotonicUs - visit.enteredMonotonicUs <= 10000000)
        visit.returnedMonotonicUs = returnedMonotonicUs; nodesSince = null
      }
      // Real same-source clicks must preserve the current exact GET fence.
      // Their observed DOM is checked without inventing an extra checkpoint.
      if (step === 'demo_desktop' || step === 'actual_enter_desktop') { await click(step === 'demo_desktop' ? 'source_demo' : 'source_actual'); await observeSettled(fence) }
    }
    guard(); need(nodesSince === null && domRows.length === fences.length && screenshots.length === 8)
    journal.complete()
    const documentRequest = [...journal.requests.values()].find(row => row.kind === 'DOCUMENT'); need(documentRequest?.response)
    const proof = await session.tlsProof(documentRequest.response, c.origin); guard()
    journal.beginClose()
    const close = await session.close(); closed = true; deadline()
    // assertHealthy intentionally rejects a correctly CLOSED native session.
    // Normal close's own final fault check and journal finalization apply here.
    journal.finalize()
    const capturesRaw = Buffer.from(currentRows().map(v => JSON.stringify(v)).join('\n') + '\n')
    const domRaw = Buffer.from(domRows.map(v => JSON.stringify(v)).join('\n') + '\n')
    safePublic(capturesRaw, io.canaries); safePublic(domRaw, io.canaries)
    const captures = await io.publish(o.root + '/captures.private.jsonl', capturesRaw, c.captureRules.bounds.captureFile)
    deadline(); await io.publish(o.root + '/dom.private.jsonl', domRaw, c.captureRules.bounds.domFileBytes); deadline()
    const report = { schema: c.schemaNames.driver, sourceCommit: o.sourceCommit, fixtureId: o.fixtureId, engine: o.engine, scenario: c.scenario, profile, production: false, origin: c.origin, scope: scope(), runtime: true, mockedResponses: false, injectedFetch: false, tlsBypass: false, browser: session.browser, chrome: session.chrome, normalTrust: session.normalTrust, tls: proof.tls, certificateChain: proof.certificateChain, counters: { ...journal.counters }, events: journal.events, close, steps: domRows.map(v => v.step), captures: { path: 'captures.jsonl', ...captures, records: journal.rows.length }, screenshots, actionTimings }
    need(exact(report, c.exactKeySchemas['driver.json']))
    const raw = Buffer.from(JSON.stringify(report) + '\n'); safePublic(raw, io.canaries)
    await io.publish(o.root + '/driver.private.json', raw, c.captureRules.bounds.driverFileBytes)
    deadline()
    return report
  } finally { if (!closed) await session.dispose() }
}

export async function runOverview(o) {
  validateSessionOptions(o)
  const startedAt = performance.now(), source = o.bundle + '/source/chengwang/'
  const c = loadContract(await stableFile(source + 'deploy/overview-ui-browser/contract.json', 131072))
  const input = validateInput(strictJSON(await stableFile(o.root + '/overview-input.private.json', 8192, true), 8192), o, c)
  const canaries = canaryVariants(input.fenceCanary)
  const manifestRaw = await stableFile(source + 'web/dist/.vite/manifest.json', c.captureRules.bounds.manifestBytes)
  const build = strictJSON(await stableFile(o.bundle + '/build.json', c.buildFileBytesMax), c.buildFileBytesMax)
  const server = await stableFile(o.bundle + '/server', 128 << 20)
  const { graph, expectedFiles } = validateBuild(build, manifestRaw, server, c, o)
  for (const [name, expected] of expectedFiles) {
    const bytes = await stableFile(source + 'web/dist/' + name, 16 << 20)
    need(bytes.length === expected.bytes && sha(bytes) === expected.sha256)
  }
  let session = null
  const journal = new OverviewJournal(c, input.profile, graph, canaries, rawId => {
    need(session); return session.pageSend('Network.getResponseBody', { requestId: rawId })
  }, expectedFiles)
  // Journal hooks exist before launch/attach; no producer event starts early.
  session = await openNativeSession(o, { onEvent: (method, params) => journal.handle(method, params), onFault: () => journal.reject('capture_error') })
  return orchestrateOverview(session, journal, c, input, o, {
    publish, ready: publishReady, wait: until, monotonic: () => performance.now(), wall: () => Date.now(), startedAt, canaries,
    observe: (actualSession, contract) => actualSession.evaluate(domExpression(contract)), validate: validateCheckpoint,
    waitRun: () => until(async () => {
      try {
        const path = o.root + '/run.go', raw = await stableFile(path, 4096), info = await lstat(path)
        need((info.mode & 0o7777) === 0o444); validateRun(strictJSON(raw, 4096), o, input, c); return true
      } catch (error) { if (error?.code === 'ENOENT') return false; throw error }
    }, 20000),
  })
}
