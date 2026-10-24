// Isolated real-browser producer. Importing this module never starts a process.
import { spawn, execFile } from 'node:child_process'
import { mkdir, lstat, readFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { pathToFileURL } from 'node:url'
import { promisify } from 'node:util'
import { setTimeout as delay } from 'node:timers/promises'
import { stableFile, ownedDirectory, publish, publishReady, until, Transport, chromeIdentity, noLiveChrome } from '../subscription-ui-browser/ui-driver.mjs'
import { versionProjection } from '../subscription-ui-browser/ui-contract.mjs'
import { need, exact, integer, us, sha, strictJSON, loadContract, validateInput, profileScope, manifestGraph, projectRequest, safeRequest, mimeClass, expectedMIME, canaryVariants, safePublic, decodeBody, FAVICON } from './ui-contract.mjs'
import { domExpression, validateCheckpoint } from './ui-dom.mjs'
const execute = promisify(execFile)
const errorCounters = { runtime_error: 'runtimeErrors', console_error: 'consoleErrors', console_warning: 'consoleWarnings', csp_error: 'cspErrors', asset_error: 'assetErrors', forbidden_request: 'forbiddenRequests', capture_error: 'captureErrors' }
const observedEvents = ['Network.requestWillBeSent', 'Network.responseReceived', 'Network.loadingFinished', 'Network.loadingFailed', 'Runtime.exceptionThrown', 'Runtime.consoleAPICalled', 'Log.entryAdded', 'Network.webSocketCreated', 'Network.webTransportCreated', 'Network.directTCPSocketCreated', 'Network.directUDPSocketCreated']

export class CapabilityJournal {
  constructor(c, graph, canaries, bodyReader, expectedFiles) {
    this.c = c; this.b = c.captureRules.bounds; this.graph = graph; this.canaries = canaries; this.bodyReader = bodyReader; this.expectedFiles = expectedFiles
    this.requests = new Map(); this.ignored = new Set(); this.events = []; this.rows = []; this.tasks = new Set(); this.finished = 0; this.totalBytes = 0; this.failure = false; this.overflow = false; this.finalized = false
    this.counters = Object.fromEntries(c.eightZero.map(k => [k, 0]))
  }
  emit(type, fields) {
    need(!this.finalized); const event = { seq: this.events.length + 1, type, ...fields }
    need(exact(event, this.c.nestedExactKeys['driver.events.' + type])); safePublic(Buffer.from(JSON.stringify(event)), this.canaries)
    if (this.events.length >= this.b.events || Buffer.byteLength(JSON.stringify(event)) > this.b.eventRowBytes) { this.overflow = true; this.failure = true; this.counters.captureErrors++; throw Error('capability event limit') }
    this.events.push(event)
  }
  reject(code = 'capture_error', item = null) {
    this.failure = true; need(Object.hasOwn(errorCounters, code)); this.counters[errorCounters[code]]++
    if (!this.overflow && !this.finalized) { try { this.emit('ERROR', { requestId: item?.requestId ?? null, code }) } catch { this.overflow = true } }
  }
  handle(method, p) {
    try {
      need(!this.finalized)
      if (method === 'Runtime.exceptionThrown') this.reject('runtime_error')
      if (method === 'Runtime.consoleAPICalled' && p.type === 'error') this.reject('console_error')
      if (method === 'Runtime.consoleAPICalled' && ['warning', 'warn'].includes(p.type)) this.reject('console_warning')
      if (method === 'Log.entryAdded' && p.entry?.source === 'security' && ['error', 'warning'].includes(p.entry.level)) this.reject('csp_error')
      if (['Network.webSocketCreated', 'Network.webTransportCreated', 'Network.directTCPSocketCreated', 'Network.directUDPSocketCreated'].includes(method)) this.reject('forbidden_request')
      if (method === 'Network.requestWillBeSent') {
        if (p.request?.url === FAVICON) { need(!this.ignored.has(p.requestId) && this.ignored.size < 4); this.ignored.add(p.requestId); return }
        need(typeof p.requestId === 'string' && p.requestId.length > 0 && p.requestId.length <= 256 && !this.requests.has(p.requestId) && this.requests.size < this.b.requests)
        const projection = projectRequest(p.request, this.graph, this.c), requestOrdinal = this.requests.size + 1
        const item = { ...projection, requestId: 'r' + requestOrdinal, requestOrdinal, rawId: p.requestId, startedWallTimeUs: us(p.wallTime), startTimeUs: us(p.timestamp), response: null, terminal: false }
        this.requests.set(p.requestId, item)
        this.emit('REQUEST', { requestId: item.requestId, requestOrdinal, ...projection })
        if (!safeRequest(projection) || p.redirectResponse) this.reject('forbidden_request', item)
      }
      if (this.ignored.has(p.requestId)) return
      if (method === 'Network.responseReceived') {
        const item = this.requests.get(p.requestId), r = p.response; need(item && r && !item.response && !item.terminal)
        const headers = Object.fromEntries(Object.entries(r.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]))
        const fields = { requestId: item.requestId, status: r.status, mimeClass: mimeClass(r.mimeType), setCookiePresent: Object.hasOwn(headers, 'set-cookie'), redirected: r.url !== this.c.origin + item.path, diskCache: !!r.fromDiskCache || !!r.fromPrefetchCache, serviceWorker: !!r.fromServiceWorker }
        this.emit('HEADERS', fields)
        if (r.status !== 200 || !expectedMIME(item, fields.mimeClass)) this.reject(item.kind === 'ASSET' ? 'asset_error' : 'capture_error', item)
        need(!fields.setCookiePresent && !fields.redirected && !fields.diskCache && !fields.serviceWorker)
        item.response = r; item.headerTimeUs = us(p.timestamp); need(item.headerTimeUs >= item.startTimeUs)
      }
      if (method === 'Network.loadingFailed') {
        const item = this.requests.get(p.requestId); need(item && !item.terminal); item.terminal = true; this.emit('NET_FAIL', { requestId: item.requestId }); this.counters.failedRequests++; this.failure = true
      }
      if (method === 'Network.loadingFinished') {
        const item = this.requests.get(p.requestId); need(item && item.response && !item.terminal && integer(p.encodedDataLength, 0, this.b.decodedTotal))
        item.terminal = true; item.endTimeUs = us(p.timestamp); need(item.endTimeUs >= item.headerTimeUs)
        const ordinal = ++this.finished; this.emit('FINISH', { requestId: item.requestId, encodedDataLength: p.encodedDataLength })
        const task = this.capture(item, ordinal, p.encodedDataLength).catch(() => this.reject('capture_error', item)).finally(() => this.tasks.delete(task)); this.tasks.add(task)
      }
    } catch { this.reject() }
  }
  async capture(item, ordinal, encodedDataLength) {
    const raw = decodeBody(await this.bodyReader(item.rawId), ['DOCUMENT', 'ASSET'].includes(item.kind) ? this.b.bodyAsset : this.b.bodyAPI)
    safePublic(raw, this.canaries); this.totalBytes += raw.length; need(this.totalBytes <= this.b.decodedTotal)
    if (['DOCUMENT', 'ASSET'].includes(item.kind)) { const f = this.expectedFiles.get(item.kind === 'DOCUMENT' ? 'index.html' : item.path.slice(1)); need(f && f.bytes === raw.length && f.sha256 === sha(raw)) }
    const row = { schema: this.c.schemaNames.capture, ordinal, requestOrdinal: item.requestOrdinal, requestId: item.requestId, method: item.method, path: item.path, kind: item.kind, status: item.response.status, authorizationPresent: item.authorizationPresent, requestPublic: null, responseBase64: raw.toString('base64'), responseSHA256: sha(raw), responseBytes: raw.length, startedWallTimeUs: item.startedWallTimeUs, startTimeUs: item.startTimeUs, headerTimeUs: item.headerTimeUs, endTimeUs: item.endTimeUs, terminal: { event: 'FINISH', encodedDataLength } }
    need(exact(row, this.c.exactKeySchemas['captures.jsonl[]'])); safePublic(Buffer.from(JSON.stringify(row)), this.canaries)
    this.rows.push(row); this.emit('CAPTURE', { requestId: item.requestId, captureOrdinal: ordinal, responseBytes: raw.length, responseSHA256: row.responseSHA256 })
  }
  mutationCount() { return [...this.requests.values()].filter(v => v.method !== 'GET').length }
  idle() { return this.tasks.size === 0 && [...this.requests.values()].every(v => v.terminal) }
  complete() {
    need(!this.failure && !this.overflow && this.idle() && this.rows.length === this.requests.size && this.finished === this.rows.length && this.mutationCount() === 0 && Object.values(this.counters).every(v => v === 0))
    for (const [kind, n] of [['DOCUMENT', 1], ['SNAPSHOT', 1], ['CAPABILITIES', 2]]) need(this.rows.filter(r => r.kind === kind).length === n)
    const assets = this.rows.filter(r => r.kind === 'ASSET').map(r => r.path); need(assets.length > 0 && assets.length <= this.b.assets && new Set(assets).size === assets.length && this.graph.required.every(p => assets.includes(p)))
  }
  finalize() {
    this.complete(); need(!this.finalized)
    this.emit('META', { requests: this.requests.size, headers: [...this.requests.values()].filter(v => v.response).length, finished: this.finished, failed: this.counters.failedRequests, captured: this.rows.length, pending: [...this.requests.values()].filter(v => !v.terminal).length, tasks: this.tasks.size, ignoredFavicon: this.ignored.size, mutations: this.mutationCount(), overflow: this.overflow }); this.finalized = true
  }
}

// Locked Playwright1.65.0-alpha-2026-10-23, official npm metadata gitHead
// 20a2087ea43412b90c172c88faef80786ee18b8b crPage.ts: _updateUserAgent/emulateLocale and
// emulateTimezone use these native CDP calls. This is not JS navigator patching.
// https://raw.githubusercontent.com/microsoft/playwright/20a2087ea43412b90c172c88faef80786ee18b8b/packages/playwright-core/src/server/chromium/crPage.ts
export async function configureNativeLocale(send, userAgent) {
  need(typeof userAgent === 'string' && userAgent.length > 0 && userAgent.length <= 1024)
  await send('Emulation.setUserAgentOverride', { userAgent, acceptLanguage: 'zh-CN' })
  await send('Emulation.setLocaleOverride', { locale: 'zh-CN' })
  await send('Emulation.setTimezoneOverride', { timezoneId: 'UTC' })
}
export function clickExpression(key, c) {
  const slot = c.controlSlots.find(s => s[0] === key); need(slot && ['nav_overview', 'nav_kernels', 'nav_capabilities', 'refresh_capabilities'].includes(key))
  return `(()=>{const name=${JSON.stringify(slot[1])},a=[...document.querySelectorAll('button')].filter(e=>(e.getAttribute('aria-label')?.trim()||(e.innerText??'').replace(/\\s+/g,' ').trim())===name);if(a.length!==1||a[0].disabled)throw Error('capability target rejected');const e=a[0];${key.startsWith('nav_') ? "if(e.getAttribute('aria-label')!==name)throw Error('capability nav rejected');" : ''}e.scrollIntoView({block:'center',inline:'nearest'});const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;if(!(r.width>0&&r.height>0&&x>=0&&y>=0&&x<innerWidth&&y<innerHeight&&e.contains(document.elementFromPoint(x,y))))throw Error('capability target rejected');return{x,y}})()`
}
export async function runCapabilityTruth(o) {
  let stage = 'ENVIRONMENT', journal, context, transport, browserSend, pageSend, childResult, closed = false, canaries
  const checkpoint = next => { stage = next; process.stderr.write('CAPABILITY_TRUTH_STAGE=' + next + '\n') }
  try {
    need(process.platform === 'linux' && process.getuid?.() === 10001 && process.getgid?.() === 10001 && !Object.hasOwn(process.env, 'HOME') && process.env.TMPDIR === '/var/tmp' && homedir() === o.home && typeof WebSocket === 'function')
    await ownedDirectory(o.root); await ownedDirectory('/var/tmp'); await ownedDirectory(o.home, true); await ownedDirectory(o.profile, true)
    const source = o.bundle + '/source/chengwang/', c = loadContract(await stableFile(source + 'deploy/capability-truth-browser/contract.json', 262144))
    const config = strictJSON(await stableFile(o.bundle + '/launch.json', 4096), 4096)
    need(exact(config, ['schema', 'engine', 'fixtureId', 'root', 'chrome', 'chromeSHA256']) && config.schema === 'chengwang.subscription-ui-launch/v1' && config.engine === o.engine && config.fixtureId === o.fixtureId && config.root === o.root && config.chrome === o.chrome && /^[a-f0-9]{64}$/.test(config.chromeSHA256))
    const input = validateInput(strictJSON(await stableFile(o.root + '/capability-input.private.json', 8192, true), 8192), o, c), sceneProfile = input.profile
    canaries = canaryVariants(input.fenceCanary)
    const manifestRaw = await stableFile(source + 'web/dist/.vite/manifest.json', c.captureRules.bounds.manifestBytes), graph = manifestGraph(strictJSON(manifestRaw, c.captureRules.bounds.manifestBytes), c)
    const build = strictJSON(await stableFile(o.bundle + '/build.json', c.buildFileBytesMax), c.buildFileBytesMax)
    need(exact(build, c.exactKeySchemas['build.json']) && build.schema === c.schemaNames.build && build.sourceCommit === o.sourceCommit && build.production === false && build.authorization === 'BLOCKED' && Buffer.from(build.manifestBase64, 'base64').equals(manifestRaw) && Buffer.from(build.manifestBase64, 'base64').toString('base64') === build.manifestBase64)
    need(Array.isArray(build.distFiles) && build.distFiles.length <= 512); const expectedFiles = new Map()
    for (const f of build.distFiles) { need(exact(f, ['path', 'bytes', 'sha256']) && typeof f.path === 'string' && integer(f.bytes, 1, 16 << 20) && /^[a-f0-9]{64}$/.test(f.sha256) && !expectedFiles.has(f.path)); expectedFiles.set(f.path, f) }
    need(expectedFiles.get('.vite/manifest.json')?.sha256 === sha(manifestRaw))
    const helper = await import(pathToFileURL(source + 'web/scripts/trust-browser-tls.mjs').href)
    const ca = await stableFile(o.root + '/api-ca.pem', 65536, true), leaf = await stableFile(o.root + '/api-leaf.pem', 65536, true), verified = helper.inspectPublicTLS(ca.toString(), leaf.toString())
    const data = o.home + '/.local/share', database = data + '/pki/nssdb'; await mkdir(database, { mode: 0o700, recursive: true })
    try { await lstat(o.home + '/.pki/nssdb'); need(false) } catch (e) { need(e?.code === 'ENOENT') }
    for (const name of ['config', 'cache']) await ownedDirectory(o.profile + '/' + name, true)
    const env = { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TZ: 'UTC', TMPDIR: '/var/tmp', XDG_DATA_HOME: data, XDG_CONFIG_HOME: o.profile + '/config', XDG_CACHE_HOME: o.profile + '/cache' }
    await stableFile('/usr/bin/certutil', 16 << 20); await stableFile(o.launcher, 131072)
    const certutil = args => execute('/usr/bin/certutil', args, { env, timeout: 10000, maxBuffer: 65536, encoding: 'utf8' })
    await certutil(['-N', '-d', 'sql:' + database, '--empty-password']); await certutil(['-A', '-d', 'sql:' + database, '-n', 'chengwang-capability-truth-root', '-t', 'C,,', '-i', o.root + '/api-ca.pem'])
    need(helper.inspectPublicTLS((await certutil(['-L', '-d', 'sql:' + database, '-n', 'chengwang-capability-truth-root', '-a'])).stdout, leaf.toString()).caSHA256 === verified.caSHA256)
    checkpoint('LAUNCH')
    const args = ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps', '--disable-extensions', '--no-first-run', '--no-default-browser-check', '--disable-features=MediaRouter,OptimizationHints', '--password-store=basic']
    let page
    if (o.engine === 'chrome-cdp') {
      const child = spawn(o.launcher, [...args, '--headless=new', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--user-data-dir=' + o.profile, 'about:blank'], { stdio: ['ignore', 'ignore', 'ignore'], env })
      childResult = new Promise(resolve => { child.once('error', () => resolve({ code: null, signal: null })); child.once('exit', (code, signal) => resolve({ code, signal })) })
      let endpoint; await until(async () => { need(child.exitCode === null && child.signalCode === null); try { const s = await readFile(o.profile + '/DevToolsActivePort', 'utf8'); need(s.length <= 1024); const a = s.trim().split('\n'); need(a.length === 2 && /^[1-9][0-9]{0,4}$/.test(a[0]) && Number(a[0]) <= 65535 && /^\/devtools\/browser\/[a-f0-9-]{1,80}$/.test(a[1])); endpoint = 'ws://127.0.0.1:' + a[0] + a[1]; return true } catch (e) { if (e?.code === 'ENOENT') return false; throw e } }, 20000)
      const socket = new WebSocket(endpoint); await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(Error('capability transport rejected')), 10000); socket.addEventListener('open', () => { clearTimeout(timer); resolve() }, { once: true }); socket.addEventListener('error', () => { clearTimeout(timer); reject(Error('capability transport rejected')) }, { once: true }) })
      transport = new Transport(socket); browserSend = (method, params) => transport.send(method, params)
      const target = await browserSend('Target.createTarget', { url: 'about:blank' }), sessionId = (await browserSend('Target.attachToTarget', { targetId: target.targetId, flatten: true })).sessionId
      pageSend = (method, params) => transport.send(method, params, sessionId); transport.listeners.push(m => { if (m.sessionId === sessionId) journal?.handle(m.method, m.params ?? {}) })
      const known = new Set((await browserSend('Target.getTargets')).targetInfos.map(v => v.targetId))
      transport.listeners.push(m => { if (m.method === 'Target.targetCreated' && ['page', 'service_worker', 'shared_worker'].includes(m.params?.targetInfo?.type) && !known.has(m.params.targetInfo.targetId)) journal?.reject('forbidden_request') })
      await browserSend('Target.setDiscoverTargets', { discover: true })
    } else {
      need(o.engine === 'playwright'); const dir = source + 'tools/subscription-ui-browser/node_modules/playwright-core/'
      need(strictJSON(await stableFile(dir + 'package.json', 65536), 65536).version === '1.65.0-alpha-2026-10-23')
      const pw = await import(pathToFileURL(dir + 'index.mjs').href)
      context = await pw.chromium.launchPersistentContext(o.profile, { executablePath: o.launcher, headless: true, chromiumSandbox: false, ignoreHTTPSErrors: false, bypassCSP: false, locale: c.browserEnvironment.language, timezoneId: c.browserEnvironment.timeZone, deviceScaleFactor: 1, args, env, timeout: 20000 })
      page = context.pages()[0]; need(page && context.pages().length === 1)
      const session = await context.newCDPSession(page), bs = await context.browser().newBrowserCDPSession(); pageSend = (method, params) => session.send(method, params); browserSend = (method, params) => bs.send(method, params)
      for (const event of observedEvents) session.on(event, p => journal?.handle(event, p))
      context.on('page', p => { if (p !== page) journal?.reject('forbidden_request') }); context.on('serviceworker', () => journal?.reject('forbidden_request'))
    }
    journal = new CapabilityJournal(c, graph, canaries, requestId => pageSend('Network.getResponseBody', { requestId }), expectedFiles)
    const version = await browserSend('Browser.getVersion'), browser = versionProjection(version), chrome = await chromeIdentity(o, browserSend); need(chrome.exeSHA256 === config.chromeSHA256)
    await Promise.all(['Runtime.enable', 'Page.enable', 'Log.enable'].map(method => pageSend(method))); await pageSend('Network.enable', { maxTotalBufferSize: 32 << 20, maxResourceBufferSize: 8 << 20 })
    if (!page) await configureNativeLocale(pageSend, version.userAgent)
    const evaluate = async expression => { if (page) return page.evaluate(expression); const r = await pageSend('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }); need(r && !r.exceptionDetails && Object.hasOwn(r.result ?? {}, 'value')); return r.result.value }
    const viewport = width => page ? page.setViewportSize({ width, height: 900 }) : pageSend('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: c.browserEnvironment.deviceScaleFactor, mobile: false })
    const click = async key => {
      const expression = clickExpression(key, c), slot = c.controlSlots.find(v => v[0] === key)
      if (page) { const locator = page.getByRole('button', { name: slot[1], exact: true }); need(await locator.count() === 1); if (key.startsWith('nav_')) need(await locator.getAttribute('aria-label') === slot[1]); await locator.click({ timeout: 10000 }) }
      else { const point = await evaluate(expression); need(exact(point, ['x', 'y']) && Number.isFinite(point.x) && Number.isFinite(point.y)); for (const type of ['mouseMoved', 'mousePressed', 'mouseReleased']) await pageSend('Input.dispatchMouseEvent', { type, ...point, ...(type === 'mouseMoved' ? {} : { button: 'left', clickCount: 1 }) }) }
    }
    const settle = () => evaluate('(async()=>{await document.fonts.ready;window.scrollTo(0,0);await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));return true})()')
    const domRows = [], screenshots = [], expression = domExpression(c)
    const record = async step => {
      await until(() => { need(!journal.failure); return journal.idle() }); await settle()
      need(await evaluate('location.href===' + JSON.stringify(c.origin + '/') + '&&document.title==="澄网 · 网络代理与路由平台"&&!document.querySelector("vite-error-overlay,nextjs-portal,[data-vite-error-overlay]")') === true)
      const d = await evaluate(expression), rows = [...journal.rows].sort((a,b) => a.ordinal-b.ordinal)
      d.apiFence = { snapshotCaptureOrdinal: rows.find(v => v.kind === 'SNAPSHOT')?.ordinal ?? 0, capabilitiesCaptureOrdinals: rows.filter(v => v.kind === 'CAPABILITIES').map(v => v.ordinal) }
      validateCheckpoint(step, d, rows, c, sceneProfile)
      const row = { schema: c.schemaNames.domRow, ordinal: domRows.length + 1, step, captureCount: rows.length, mutationCount: journal.mutationCount(), dom: d }; need(exact(row, c.exactKeySchemas['dom.jsonl[]']))
      const raw = Buffer.from(JSON.stringify(row)); need(raw.length <= c.captureRules.bounds.domRowBytes); safePublic(raw, canaries); domRows.push(row)
      const f = c.stepFences.find(v => v[0] === step)
      if (f[5]) {
        const bytes = page ? await page.screenshot({ type: 'png', fullPage: false, animations: 'disabled', timeout: 10000 }) : Buffer.from((await pageSend('Page.captureScreenshot', { format: 'png', fromSurface: true, captureBeyondViewport: false })).data, 'base64')
        need(bytes.length >= 1000 && bytes.length <= c.pngFileBytesMax && bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])) && bytes.readUInt32BE(16) === f[1] && bytes.readUInt32BE(20) === f[2]); safePublic(bytes, canaries)
        const name = f[5], metadata = await publish(o.root + '/' + name.replace(/\.png$/, '.private.png'), bytes, c.pngFileBytesMax)
        screenshots.push({ path: name, step, ...metadata, viewport: { width: d.viewport.width, height: d.viewport.height }, scrollX: d.viewport.scrollX, scrollY: d.viewport.scrollY, capturedWallTimeUs: Date.now() * 1000 })
      }
    }
    const waitPage = (name, capCount) => until(async () => { need(!journal.failure); const d = await evaluate(expression); return d.page === name && d.pageVisible && journal.idle() && journal.rows.filter(v => v.kind === 'CAPABILITIES').length === capCount && (name !== '系统闭环' || d.capabilities?.groups?.length > 0 && d.controls.find(v => v.key === 'refresh_capabilities')?.enabled) })
    await publishReady(o.root + '/driver-ready.private.json', { schema: c.schemaNames.ready, scenario: c.scenario, profile: sceneProfile, fixtureId: o.fixtureId, engine: o.engine, pid: process.pid, chromePid: chrome.pid })
    await until(async () => { try { const raw = await stableFile(o.root + '/run.go', 4096), s = await lstat(o.root + '/run.go'); need((s.mode & 0o7777) === 0o444); const v = strictJSON(raw, 4096); need(exact(v, c.runExactKeys) && v.schema === c.schemaNames.run && v.scenario === c.scenario && v.profile === sceneProfile && v.fixtureId === o.fixtureId && v.engine === o.engine); return true } catch (e) { if (e?.code === 'ENOENT') return false; throw e } }, 20000)
    checkpoint('NAVIGATE'); await viewport(1440)
    if (page) await page.goto(c.origin + '/', { waitUntil: 'load', timeout: 15000 }); else { const r = await pageSend('Page.navigate', { url: c.origin + '/' }); need(!r.errorText); await until(async () => await evaluate('document.readyState==="complete"') === true) }
    await until(() => { need(!journal.failure); return journal.idle() && journal.rows.some(v => v.kind === 'SNAPSHOT') })
    await record('overview_desktop'); checkpoint('KERNELS'); await click('nav_kernels'); await waitPage('内核与协议', 0); await record('kernels_desktop')
    checkpoint('CAPABILITIES'); await click('nav_capabilities'); await waitPage('系统闭环', 1); await record('capabilities_desktop')
    checkpoint('REFRESH'); await click('refresh_capabilities'); await waitPage('系统闭环', 2); await record('capabilities_refreshed')
    checkpoint('MOBILE'); await viewport(375); await record('capabilities_mobile'); await click('nav_kernels'); await waitPage('内核与协议', 2); await record('kernels_mobile'); await click('nav_overview'); await waitPage('运行总览', 2); await record('overview_mobile')
    need(domRows.map(v => v.step).join(',') === c.stepFences.map(v => v[0]).join(',')); journal.complete()
    const documentRequest = [...journal.requests.values()].find(v => v.kind === 'DOCUMENT'), certificateChain = (await pageSend('Network.getCertificate', { origin: c.origin })).tableNames
    need(documentRequest?.response); const tls = helper.browserTLSProof(documentRequest.response, certificateChain, verified)
    checkpoint('CLOSE'); if (context) await context.close(); else await browserSend('Browser.close')
    let chromeExit; await until(async () => { try { chromeExit = strictJSON(await stableFile(o.root + '/chrome-exit.private.json', 4096, true), 4096); return true } catch (e) { if (e?.code === 'ENOENT') return false; throw e } }, 20000)
    need(exact(chromeExit, c.nestedExactKeys['driver.close.chromeExit']) && chromeExit.schema === 'chengwang.subscription-ui-chrome-exit/v1' && chromeExit.engine === o.engine && chromeExit.fixtureId === o.fixtureId && chromeExit.pid === chrome.pid && chromeExit.startTicks === chrome.startTicks && chromeExit.exitCode === 0 && chromeExit.joined === true && chromeExit.forced === false)
    let launcherExit = null; if (childResult) { launcherExit = await Promise.race([childResult, delay(2000).then(() => null)]); need(launcherExit?.code === 0 && launcherExit.signal === null) }
    await until(() => noLiveChrome(o, chrome), 5000); closed = true; transport?.socket.close(); journal.finalize()
    const capturesRaw = Buffer.from([...journal.rows].sort((a,b) => a.ordinal-b.ordinal).map(v => JSON.stringify(v)).join('\n') + '\n'), domRaw = Buffer.from(domRows.map(v => JSON.stringify(v)).join('\n') + '\n')
    safePublic(capturesRaw, canaries); safePublic(domRaw, canaries)
    const captures = await publish(o.root + '/captures.private.jsonl', capturesRaw, c.captureRules.bounds.captureFile); await publish(o.root + '/dom.private.jsonl', domRaw, c.captureRules.bounds.domFileBytes)
    const report = { schema: c.schemaNames.driver, sourceCommit: o.sourceCommit, fixtureId: o.fixtureId, engine: o.engine, scenario: c.scenario, profile: sceneProfile, production: false, origin: c.origin, scope: profileScope(sceneProfile), runtime: true, mockedResponses: false, injectedFetch: false, tlsBypass: false, browser, chrome, normalTrust: { method: 'PRIVATE_NSS_SQL_XDG_LOCAL_CA', trustFlags: 'C,,', caSHA256: verified.caSHA256, leafSHA256: verified.leafSHA256, homeEnvironmentAbsent: true, legacyDatabaseAbsent: true }, tls, certificateChain, counters: journal.counters, events: journal.events, close: { normalCloseCommandCompleted: true, chromeExit, launcherExit, noLiveOwnedProcesses: true, processScope: 'CHROME_SESSION_AND_LAUNCHER_ONLY' }, steps: c.stepFences.map(v => v[0]), captures: { path: 'captures.jsonl', ...captures, records: journal.rows.length }, screenshots }
    need(exact(report, c.exactKeySchemas['driver.json'])); const raw = Buffer.from(JSON.stringify(report) + '\n'); safePublic(raw, canaries); await publish(o.root + '/driver.private.json', raw, c.captureRules.bounds.driverFileBytes); checkpoint('COMPLETE'); return report
  } catch (error) {
    // Private diagnostic is a failure observation, never a successful17 artifact.
    try { const d = { schema: 'chengwang.capability-truth-driver-failure/v1', stage, production: false, normalCloseCompleted: closed, events: journal?.events.length ?? 0, captures: journal?.rows.length ?? 0, failed: true }; const raw = Buffer.from(JSON.stringify(d) + '\n'); if (canaries) safePublic(raw, canaries); await publish(o.root + '/capability-failure.private.json', raw, 4096) } catch { /* Keep the original failure; never replace or downgrade it. */ }
    throw error
  } finally {
    if (!closed) { try { if (context) await context.close(); else if (browserSend) await browserSend('Browser.close') } catch { /* emergency cleanup is not normal close */ }; transport?.socket.close() }
  }
}
