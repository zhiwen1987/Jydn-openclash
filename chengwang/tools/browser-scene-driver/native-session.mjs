// CI-only native browser lifecycle. Import starts no browser, process or network.
import { spawn, execFile } from 'node:child_process'
import { lstat, mkdir, readFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { setTimeout as delay } from 'node:timers/promises'
import { promisify } from 'node:util'
import { pathToFileURL } from 'node:url'
import { stableFile, ownedDirectory, until, Transport, chromeIdentity, noLiveChrome } from '../subscription-ui-browser/ui-driver.mjs'
import { versionProjection } from '../subscription-ui-browser/ui-contract.mjs'
import { configureNativeLocale } from '../capability-truth-browser/ui-driver.mjs'
import { inspectPublicTLS, browserTLSProof } from '../../web/scripts/trust-browser-tls.mjs'

const execute = promisify(execFile)
const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join(',') === [...keys].sort().join(',')
const integer = (v, min, max) => Number.isSafeInteger(v) && v >= min && v <= max
const rejected = () => new Error('native browser session rejected')
const need = v => { if (!v) throw rejected() }
const protectedTypes = new Set(['page', 'service_worker', 'shared_worker'])
const targetId = v => typeof v === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(v)
const targetType = v => typeof v === 'string' && /^[a-z_]{1,64}$/.test(v)
const optionKeys = ['root', 'bundle', 'engine', 'sourceCommit', 'fixtureId', 'chrome', 'launcher', 'home', 'profile']
const exitKeys = ['schema', 'engine', 'fixtureId', 'pid', 'startTicks', 'exitCode', 'joined', 'forced']
export const SESSION_EVENTS = Object.freeze([
  'Network.requestWillBeSent', 'Network.responseReceived', 'Network.responseReceivedExtraInfo',
  'Network.loadingFinished', 'Network.loadingFailed', 'Runtime.exceptionThrown',
  'Runtime.consoleAPICalled', 'Log.entryAdded', 'Network.webSocketCreated',
  'Network.webTransportCreated', 'Network.directTCPSocketCreated',
  'Network.directUDPSocketCreated',
  'Runtime.executionContextDestroyed', 'Runtime.executionContextsCleared',
  'Page.frameNavigated', 'Page.frameDetached', 'Inspector.detached',
])
export const SESSION_FAULTS = Object.freeze([
  'EXTRA_TARGET', 'INVALID_TARGET_STATE', 'TRANSPORT_CLOSED', 'SESSION_DETACHED',
  'PAGE_CLOSED', 'PAGE_CRASHED', 'CONTEXT_CLOSED', 'HOOK_REJECTED',
  'PROTOCOL_REJECTED', 'STARTUP_REJECTED', 'CLOSE_REJECTED',
])
// Failure-only labels; no observation authorizes a target or retries startup.
export const NATIVE_OPEN_STAGES = Object.freeze([
  'ENVIRONMENT', 'OWNED_DIRECTORIES', 'LAUNCH_CONFIG', 'CERTIFICATES',
  'NSS_DIRECTORIES', 'EXECUTABLES', 'NSS_CREATE', 'NSS_IMPORT', 'NSS_VERIFY',
  'CDP_LAUNCH', 'CDP_PORT_WAIT', 'CDP_WEBSOCKET', 'CDP_TRANSPORT',
  'CDP_INITIAL_TARGETS', 'CDP_CREATE_TARGET', 'CDP_ATTACH_TARGET',
  'CDP_SESSION_BIND', 'CDP_POST_TARGETS', 'CDP_DISCOVER_TARGETS',
  'PW_PACKAGE', 'PW_LAUNCH', 'PW_ATTACH', 'PW_TARGETS', 'BROWSER_VERSION',
  'PROCESS_IDENTITY', 'DOMAINS_ENABLE', 'NETWORK_ENABLE', 'LOCALE', 'OPEN_COMPLETE',
])
export function projectInitialTargets(rows) {
  const invalid = () => ({ shape: 'INVALID', total: null, pages: null, blankPages: null })
  try {
    if (!Array.isArray(rows) || rows.length > 64) return invalid()
    let pages = 0, blankPages = 0
    for (let i = 0; i < rows.length; i++) {
      const row = Object.getOwnPropertyDescriptor(rows, String(i))?.value
      if (!row || typeof row !== 'object' || Array.isArray(row)) return invalid()
      const type = Object.getOwnPropertyDescriptor(row, 'type')
      if (!type || !Object.hasOwn(type, 'value') || !targetType(type.value)) return invalid()
      if (type.value === 'page') {
        pages++
        const url = Object.getOwnPropertyDescriptor(row, 'url')
        if (!url || !Object.hasOwn(url, 'value') || typeof url.value !== 'string') return invalid()
        if (url.value === 'about:blank') blankPages++
      }
    }
    return { shape: 'ARRAY', total: rows.length, pages, blankPages }
  } catch { return invalid() }
}
export function nativeOpenObservation(stage, firstFault, initialTargets) {
  need(NATIVE_OPEN_STAGES.includes(stage) && (firstFault === null || SESSION_FAULTS.includes(firstFault)))
  need(exact(initialTargets, ['shape', 'total', 'pages', 'blankPages']))
  const { shape, total, pages, blankPages } = initialTargets
  need(['UNOBSERVED', 'INVALID', 'ARRAY'].includes(shape))
  if (shape === 'ARRAY') need(integer(total, 0, 64) && integer(pages, 0, total) && integer(blankPages, 0, pages))
  else need(total === null && pages === null && blankPages === null)
  return { schema: 'chengwang.native-open-failure/v1', stage, firstFault, initialTargets: { shape, total, pages, blankPages } }
}

// The real PW session and CPU protocol tests share this registration path.
export function registerSessionEvents(session, onEvent) {
  need(session && typeof session.on === 'function' && typeof onEvent === 'function')
  for (const method of SESSION_EVENTS) session.on(method, params => onEvent(method, params))
}

export function validateSessionOptions(o) {
  need(exact(o, optionKeys) && /^[a-f0-9]{32}$/.test(o.fixtureId) && /^[a-f0-9]{40}$/.test(o.sourceCommit))
  need(['chrome-cdp', 'playwright'].includes(o.engine))
  need(o.root === '/tmp/chengwang-subscription-ui-' + o.fixtureId && o.bundle === '/tmp/chengwang-subscription-ui-tools-' + o.fixtureId)
  need(o.chrome === o.bundle + '/chrome/chrome' && o.launcher === o.bundle + '/ui-chrome-launcher')
  need(o.home === o.root + '/home' && o.profile === o.root + '/chrome-profile')
  return o
}

export function validateChromeExit(value, o, chrome) {
  need(exact(value, exitKeys) && value.schema === 'chengwang.subscription-ui-chrome-exit/v1')
  need(value.engine === o.engine && value.fixtureId === o.fixtureId && value.pid === chrome.pid && value.startTicks === chrome.startTicks)
  need(integer(value.pid, 2, Number.MAX_SAFE_INTEGER) && integer(value.startTicks, 1, Number.MAX_SAFE_INTEGER))
  need(value.exitCode === 0 && value.joined === true && value.forced === false)
  return value
}

// Pure bounded state machine. Raw identities remain private in memory; faults
// expose only a closed code, phase and safe type. No second-snapshot whitelisting.
export class TargetGuard {
  constructor(onFault) {
    need(typeof onFault === 'function')
    this.onFault = onFault; this.phase = 'BUFFERING'; this.baseline = null
    this.queue = []; this.selected = null; this.failed = false; this.destroyed = new Set(); this.initial = null
  }
  reject(code, kind = null) {
    this.failed = true
    this.onFault(code, { phase: this.phase, targetKind: protectedTypes.has(kind) ? kind : null })
  }
  freezeInitial(rows) {
    need(this.phase === 'BUFFERING' && this.initial === null && this.baseline === null && Array.isArray(rows) && rows.length > 0 && rows.length <= 64)
    const ids = new Set(), pages = []
    for (const row of rows) {
      need(row && targetId(row.targetId) && targetType(row.type) && !ids.has(row.targetId)); ids.add(row.targetId)
      if (row.type === 'page') pages.push(row)
      else need(!protectedTypes.has(row.type))
    }
    need(pages.length === 1 && pages[0].url === 'about:blank')
    this.initial = pages[0].targetId
  }
  setBaseline(rows, selected) {
    need(this.phase === 'BUFFERING' && this.baseline === null && Array.isArray(rows) && rows.length > 0 && rows.length <= 64 && targetId(selected))
    const map = new Map()
    for (const row of rows) { need(row && targetId(row.targetId) && targetType(row.type) && !map.has(row.targetId)); map.set(row.targetId, row.type) }
    need(map.get(selected) === 'page' && selected !== this.initial)
    const authorized = new Map([[selected, 'page']])
    if (this.initial !== null) { need(map.get(this.initial) === 'page'); authorized.set(this.initial, 'page') }
    for (const [id, kind] of map) if (protectedTypes.has(kind)) need(authorized.get(id) === kind)
    // A later snapshot is a consistency check, never an authorization source.
    this.baseline = authorized; this.selected = selected
  }
  observe(method, params) {
    if (!['Target.targetCreated', 'Target.targetDestroyed'].includes(method)) return
    const info = method === 'Target.targetCreated' ? params?.targetInfo : params
    const id = info?.targetId, kind = method === 'Target.targetCreated' ? info?.type : null
    if (!targetId(id) || method === 'Target.targetCreated' && !targetType(kind)) { this.reject('INVALID_TARGET_STATE'); return }
    const row = { method, id, kind }
    if (this.phase === 'BUFFERING') {
      if (this.queue.length >= 128) { this.reject('INVALID_TARGET_STATE'); return }
      this.queue.push(row); return
    }
    this.consume(row)
  }
  consume(row) {
    if (row.method === 'Target.targetDestroyed') {
      if (this.destroyed.size >= 64 && !this.destroyed.has(row.id)) { this.reject('INVALID_TARGET_STATE'); return }
      this.destroyed.add(row.id)
      if (row.id === this.selected && this.phase !== 'CLOSING' && this.phase !== 'CLOSED') this.reject('SESSION_DETACHED')
      return
    }
    if (this.baseline.has(row.id)) {
      if (this.baseline.get(row.id) !== row.kind || this.destroyed.has(row.id)) this.reject('INVALID_TARGET_STATE', row.kind)
    } else if (protectedTypes.has(row.kind)) this.reject('EXTRA_TARGET', row.kind)
  }
  arm() {
    need(this.phase === 'BUFFERING' && this.baseline !== null)
    const rows = this.queue; this.queue = []; this.phase = 'ARMED'
    for (const row of rows) this.consume(row)
    need(!this.failed)
  }
  beginClose() { need(this.phase === 'ARMED'); this.phase = 'CLOSING' }
  endClose() { need(this.phase === 'CLOSING' && !this.failed); this.phase = 'CLOSED' }
}

// The actual CDP launch path calls this same bounded protocol sequence. Only
// the initial launcher's explicit about:blank ID and created owned ID may enter
// the guard; queued events cannot be laundered through the post-create snapshot.
export async function initializeCDPTargets(send, guard, onAttached) {
  need(typeof send === 'function' && guard instanceof TargetGuard && typeof onAttached === 'function')
  const initial = await send('Target.getTargets'); guard.freezeInitial(initial?.targetInfos)
  const target = await send('Target.createTarget', { url: 'about:blank' }); need(targetId(target?.targetId))
  const attached = await send('Target.attachToTarget', { targetId: target.targetId, flatten: true }); need(targetId(attached?.sessionId))
  onAttached(attached.sessionId)
  const targets = await send('Target.getTargets'); guard.setBaseline(targets?.targetInfos, target.targetId)
  await send('Target.setDiscoverTargets', { discover: true }); guard.arm()
  return { targetId: target.targetId, sessionId: attached.sessionId }
}

export function nativeClickExpression(name, ariaLabelOnly = false) {
  need(typeof name === 'string' && name.length > 0 && name.length <= 256 && !/[\x00-\x1f\x7f]/.test(name) && typeof ariaLabelOnly === 'boolean')
  return `(()=>{const n=${JSON.stringify(name)},a=[...document.querySelectorAll('button')].filter(e=>${ariaLabelOnly ? "e.getAttribute('aria-label')===n" : "(e.getAttribute('aria-label')?.trim()||(e.innerText??'').replace(/\\s+/g,' ').trim())===n"});if(a.length!==1||a[0].disabled||a[0].getAttribute('aria-disabled')==='true')throw Error('native input rejected');const e=a[0];e.scrollIntoView({block:'center',inline:'nearest'});const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;if(!(r.width>0&&r.height>0&&x>=0&&y>=0&&x<innerWidth&&y<innerHeight&&e.contains(document.elementFromPoint(x,y))))throw Error('native input rejected');return{x,y}})()`
}

export async function dispatchNativeClick(send, point) {
  need(typeof send === 'function' && exact(point, ['x', 'y']) && [point.x, point.y].every(v => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 100000))
  for (const type of ['mouseMoved', 'mousePressed', 'mouseReleased']) await send('Input.dispatchMouseEvent', { type, ...point, ...(type === 'mouseMoved' ? {} : { button: 'left', clickCount: 1 }) })
}

// Dependency-explicit close logic is exported only for pure protocol tests.
// openNativeSession always supplies actual browser/launcher/proc mechanisms.
export async function finishNativeSession(o, chrome, mechanisms) {
  need(exact(mechanisms, ['closeBrowser', 'readExit', 'launcherResult', 'wait', 'noLive', 'pause']))
  await mechanisms.closeBrowser()
  let chromeExit
  await mechanisms.wait(async () => {
    try { chromeExit = validateChromeExit(await mechanisms.readExit(), o, chrome); return true }
    catch (error) { if (error?.code === 'ENOENT') return false; throw error }
  }, 20000)
  let launcherExit = null
  if (mechanisms.launcherResult !== null) {
    launcherExit = await Promise.race([mechanisms.launcherResult, mechanisms.pause(2000).then(() => null)])
    need(exact(launcherExit, ['code', 'signal']) && launcherExit.code === 0 && launcherExit.signal === null)
  }
  await mechanisms.wait(mechanisms.noLive, 5000)
  return { normalCloseCommandCompleted: true, chromeExit, launcherExit, noLiveOwnedProcesses: true, processScope: 'CHROME_SESSION_AND_LAUNCHER_ONLY' }
}

/**
 * Real CI session; no injectable I/O dependencies on this default path.
 * hooks.onEvent(method, params) receives selected-session raw CDP data in memory;
 * caller must install its journal BEFORE awaiting openNativeSession. onFault is
 * synchronous, receives closed codes plus {phase,targetKind}, and cannot clear a
 * sticky failure. No URL/target/session IDs appear in returned public metadata.
 * Optional onDiagnostic receives a closed failure-only observation before
 * disposal; its rejection is suppressed without changing the startup rejection.
 *
 * browser = {product,revision,protocolVersion} (serializable version metadata).
 * chrome = {pid,startTicks,uid,profile,argvSHA256,exeSHA256,exeBytes} (the existing
 * source-bound owned-process projection, NOT a Playwright Browser/context).
 * normalTrust = {method,trustFlags,caSHA256,leafSHA256,homeEnvironmentAbsent,
 * legacyDatabaseAbsent}. Internal page/context/process handles stay in closures.
 * close returns the existing 5-key close projection only after actual normal
 * close, exact exit0/joinedtrue/forcedfalse, launcher0 and no live owned Chrome.
 * dispose is emergency cleanup only; it never returns a success close record.
 */
export async function openNativeSession(o, hooks) {
  validateSessionOptions(o)
  need((exact(hooks, ['onEvent', 'onFault']) || exact(hooks, ['onEvent', 'onFault', 'onDiagnostic'])) && typeof hooks.onEvent === 'function' && typeof hooks.onFault === 'function'
    && (!Object.hasOwn(hooks, 'onDiagnostic') || typeof hooks.onDiagnostic === 'function'))
  let phase = 'STARTING', firstFault = null, context, page, transport, browserSendRaw, pageSendRaw, childResult = null, child
  let openStage = 'ENVIRONMENT', initialTargets = { shape: 'UNOBSERVED', total: null, pages: null, blankPages: null }
  const fault = (code, detail = { phase, targetKind: null }) => {
    need(SESSION_FAULTS.includes(code)); firstFault ??= code
    try { hooks.onFault(code, detail) } catch { firstFault = 'HOOK_REJECTED' }
  }
  const healthy = () => {
    if (transport?.closed && !['CLOSING', 'CLOSED', 'DISPOSED'].includes(phase) && firstFault === null) fault('TRANSPORT_CLOSED')
    need(firstFault === null && !['FAILED', 'CLOSED', 'DISPOSED'].includes(phase))
  }
  const event = (method, params) => {
    if (method === 'Inspector.detached' && phase !== 'CLOSING' && phase !== 'CLOSED') fault('SESSION_DETACHED')
    try { hooks.onEvent(method, params) } catch { fault('HOOK_REJECTED') }
  }
  const guard = new TargetGuard(fault)
  const dispose = async () => {
    if (phase === 'CLOSED' || phase === 'DISPOSED') return
    phase = 'DISPOSED'
    try { if (context) await context.close(); else if (browserSendRaw) await browserSendRaw('Browser.close') } catch { /* No successful-close evidence on this path. */ }
    try { transport?.socket.close() } catch { /* Supervisor owns final cleanup. */ }
  }
  try {
    need(process.platform === 'linux' && process.getuid?.() === 10001 && process.getgid?.() === 10001 && !Object.hasOwn(process.env, 'HOME') && process.env.TMPDIR === '/var/tmp' && homedir() === o.home && typeof WebSocket === 'function')
    openStage = 'OWNED_DIRECTORIES'
    await ownedDirectory(o.root); await ownedDirectory('/var/tmp'); await ownedDirectory(o.home, true); await ownedDirectory(o.profile, true)
    openStage = 'LAUNCH_CONFIG'
    const config = JSON.parse((await stableFile(o.bundle + '/launch.json', 4096)).toString())
    need(exact(config, ['schema', 'engine', 'fixtureId', 'root', 'chrome', 'chromeSHA256']) && config.schema === 'chengwang.subscription-ui-launch/v1' && config.engine === o.engine && config.fixtureId === o.fixtureId && config.root === o.root && config.chrome === o.chrome && /^[a-f0-9]{64}$/.test(config.chromeSHA256))
    openStage = 'CERTIFICATES'
    const ca = await stableFile(o.root + '/api-ca.pem', 65536, true), leaf = await stableFile(o.root + '/api-leaf.pem', 65536, true)
    const verified = inspectPublicTLS(ca.toString(), leaf.toString())
    const data = o.home + '/.local/share', database = data + '/pki/nssdb'
    openStage = 'NSS_DIRECTORIES'
    await mkdir(database, { mode: 0o700, recursive: true })
    for (const path of [o.home + '/.local', data, data + '/pki', database]) await ownedDirectory(path)
    try { await lstat(o.home + '/.pki/nssdb'); need(false) } catch (error) { need(error?.code === 'ENOENT') }
    for (const name of ['config', 'cache']) await ownedDirectory(o.profile + '/' + name, true)
    const env = { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TZ: 'UTC', TMPDIR: '/var/tmp', XDG_DATA_HOME: data, XDG_CONFIG_HOME: o.profile + '/config', XDG_CACHE_HOME: o.profile + '/cache' }
    openStage = 'EXECUTABLES'
    await stableFile('/usr/bin/certutil', 16 << 20); await stableFile(o.launcher, 131072)
    const certutil = args => execute('/usr/bin/certutil', args, { env, timeout: 10000, maxBuffer: 65536, encoding: 'utf8' })
    openStage = 'NSS_CREATE'; await certutil(['-N', '-d', 'sql:' + database, '--empty-password'])
    openStage = 'NSS_IMPORT'; await certutil(['-A', '-d', 'sql:' + database, '-n', 'chengwang-native-browser-root', '-t', 'C,,', '-i', o.root + '/api-ca.pem'])
    openStage = 'NSS_VERIFY'
    need(inspectPublicTLS((await certutil(['-L', '-d', 'sql:' + database, '-n', 'chengwang-native-browser-root', '-a'])).stdout, leaf.toString()).caSHA256 === verified.caSHA256)
    const args = ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps', '--disable-extensions', '--no-first-run', '--no-default-browser-check', '--disable-features=MediaRouter,OptimizationHints', '--password-store=basic']
    if (o.engine === 'chrome-cdp') {
      openStage = 'CDP_LAUNCH'
      child = spawn(o.launcher, [...args, '--headless=new', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--user-data-dir=' + o.profile, 'about:blank'], { stdio: ['ignore', 'ignore', 'ignore'], env })
      childResult = new Promise(resolve => { child.once('error', () => resolve({ code: null, signal: null })); child.once('exit', (code, signal) => resolve({ code, signal })) })
      let endpoint
      openStage = 'CDP_PORT_WAIT'
      await until(async () => { need(child.exitCode === null && child.signalCode === null); try { const raw = await readFile(o.profile + '/DevToolsActivePort', 'utf8'); need(raw.length <= 1024); const a = raw.trim().split('\n'); need(a.length === 2 && /^[1-9][0-9]{0,4}$/.test(a[0]) && Number(a[0]) <= 65535 && /^\/devtools\/browser\/[a-f0-9-]{1,80}$/.test(a[1])); endpoint = 'ws://127.0.0.1:' + a[0] + a[1]; return true } catch (error) { if (error?.code === 'ENOENT') return false; throw error } }, 20000)
      openStage = 'CDP_WEBSOCKET'
      const socket = new WebSocket(endpoint)
      await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(rejected()), 10000); socket.addEventListener('open', () => { clearTimeout(timer); resolve() }, { once: true }); socket.addEventListener('error', () => { clearTimeout(timer); reject(rejected()) }, { once: true }) })
      openStage = 'CDP_TRANSPORT'
      transport = new Transport(socket); browserSendRaw = (method, params) => transport.send(method, params)
      socket.addEventListener('close', () => { if (!['CLOSING', 'CLOSED', 'DISPOSED'].includes(phase)) fault('TRANSPORT_CLOSED') })
      socket.addEventListener('error', () => { if (!['CLOSING', 'CLOSED', 'DISPOSED'].includes(phase)) fault('TRANSPORT_CLOSED') })
      transport.listeners.push(m => { if (!m.sessionId) guard.observe(m.method, m.params) })
      let firstTargets = true
      const bootstrapSend = async (method, params) => {
        openStage = method === 'Target.getTargets' ? (firstTargets ? 'CDP_INITIAL_TARGETS' : 'CDP_POST_TARGETS')
          : ({ 'Target.createTarget': 'CDP_CREATE_TARGET', 'Target.attachToTarget': 'CDP_ATTACH_TARGET', 'Target.setDiscoverTargets': 'CDP_DISCOVER_TARGETS' })[method]
        need(NATIVE_OPEN_STAGES.includes(openStage))
        const result = await browserSendRaw(method, params)
        if (method === 'Target.getTargets' && firstTargets) { initialTargets = projectInitialTargets(result?.targetInfos); firstTargets = false }
        return result
      }
      await initializeCDPTargets(bootstrapSend, guard, sessionId => {
        openStage = 'CDP_SESSION_BIND'
        pageSendRaw = (method, params) => transport.send(method, params, sessionId)
        transport.listeners.push(m => { if (m.sessionId === sessionId) event(m.method, m.params ?? {}) })
      })
    } else {
      openStage = 'PW_PACKAGE'
      const dir = o.bundle + '/source/chengwang/tools/subscription-ui-browser/node_modules/playwright-core/'
      need(JSON.parse((await stableFile(dir + 'package.json', 65536)).toString()).version === '1.65.0-alpha-2026-10-23')
      const pw = await import(pathToFileURL(dir + 'index.mjs').href)
      openStage = 'PW_LAUNCH'
      context = await pw.chromium.launchPersistentContext(o.profile, { executablePath: o.launcher, headless: true, chromiumSandbox: false, ignoreHTTPSErrors: false, bypassCSP: false, locale: 'zh-CN', timezoneId: 'UTC', deviceScaleFactor: 1, args, env, timeout: 20000 })
      page = context.pages()[0]; need(page && context.pages().length === 1)
      context.on('page', p => { if (p !== page) fault('EXTRA_TARGET', { phase, targetKind: 'page' }) })
      context.on('serviceworker', () => fault('EXTRA_TARGET', { phase, targetKind: 'service_worker' }))
      context.on('close', () => { if (!['CLOSING', 'CLOSED', 'DISPOSED'].includes(phase)) fault('CONTEXT_CLOSED') })
      page.on('close', () => { if (!['CLOSING', 'CLOSED', 'DISPOSED'].includes(phase)) fault('PAGE_CLOSED') })
      page.on('crash', () => fault('PAGE_CRASHED'))
      openStage = 'PW_ATTACH'
      const session = await context.newCDPSession(page), bs = await context.browser().newBrowserCDPSession()
      pageSendRaw = (method, params) => session.send(method, params); browserSendRaw = (method, params) => bs.send(method, params)
      registerSessionEvents(session, event)
      openStage = 'PW_TARGETS'
      const target = await pageSendRaw('Target.getTargetInfo'); need(targetId(target?.targetInfo?.targetId))
      bs.on('Target.targetCreated', params => guard.observe('Target.targetCreated', params))
      bs.on('Target.targetDestroyed', params => guard.observe('Target.targetDestroyed', params))
      const targets = await browserSendRaw('Target.getTargets'); guard.setBaseline(targets?.targetInfos, target.targetInfo.targetId)
      await browserSendRaw('Target.setDiscoverTargets', { discover: true }); guard.arm()
    }
    healthy()
    openStage = 'BROWSER_VERSION'
    const version = await browserSendRaw('Browser.getVersion'), browser = versionProjection(version)
    openStage = 'PROCESS_IDENTITY'
    const chrome = await chromeIdentity(o, browserSendRaw)
    need(chrome.exeSHA256 === config.chromeSHA256)
    openStage = 'DOMAINS_ENABLE'
    await Promise.all(['Runtime.enable', 'Page.enable', 'Log.enable'].map(method => pageSendRaw(method)))
    openStage = 'NETWORK_ENABLE'
    await pageSendRaw('Network.enable', { maxTotalBufferSize: 32 << 20, maxResourceBufferSize: 8 << 20 })
    openStage = 'LOCALE'
    if (!page) await configureNativeLocale(pageSendRaw, version.userAgent)
    openStage = 'OPEN_COMPLETE'
    phase = 'OPEN'; healthy()
    const safeCall = async (method, params, send) => {
      healthy()
      try { return await send(method, params) } catch { if (transport?.closed) fault('TRANSPORT_CLOSED'); else if (method !== 'Network.getResponseBody') fault('PROTOCOL_REJECTED'); throw rejected() }
    }
    const action = async task => { try { healthy(); const result = await task(); healthy(); return result } catch { fault('PROTOCOL_REJECTED'); throw rejected() } }
    const evaluate = async expression => {
      healthy(); need(typeof expression === 'string' && Buffer.byteLength(expression) > 0 && Buffer.byteLength(expression) <= 262144)
      try { if (page) return await page.evaluate(expression); const r = await pageSendRaw('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }); need(r && !r.exceptionDetails && Object.hasOwn(r.result ?? {}, 'value')); return r.result.value }
      catch { fault('PROTOCOL_REJECTED'); throw rejected() }
    }
    return Object.freeze({
      browser: Object.freeze(browser), chrome: Object.freeze(chrome),
      normalTrust: Object.freeze({ method: 'PRIVATE_NSS_SQL_XDG_LOCAL_CA', trustFlags: 'C,,', caSHA256: verified.caSHA256, leafSHA256: verified.leafSHA256, homeEnvironmentAbsent: true, legacyDatabaseAbsent: true }),
      pageSend: (method, params = {}) => { if (method !== 'Network.getResponseBody') { fault('PROTOCOL_REJECTED'); throw rejected() }; return safeCall(method, params, pageSendRaw) },
      browserSend: (method, params = {}) => { if (!['Browser.getVersion', 'SystemInfo.getProcessInfo', 'Target.getTargets'].includes(method)) { fault('PROTOCOL_REJECTED'); throw rejected() }; return safeCall(method, params, browserSendRaw) },
      evaluate,
      navigate: url => action(async () => { need(typeof url === 'string' && url.length <= 2048 && new URL(url).protocol === 'https:'); if (page) await page.goto(url, { waitUntil: 'load', timeout: 15000 }); else { const r = await pageSendRaw('Page.navigate', { url }); need(!r.errorText); await until(async () => await evaluate('document.readyState==="complete"') === true) } }),
      resize: (width, height = 900) => action(async () => { need(integer(width, 320, 4096) && integer(height, 320, 4096)); if (page) await page.setViewportSize({ width, height }); else await pageSendRaw('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false }) }),
      click: value => action(async () => {
        need(value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(k => ['name', 'ariaLabelOnly'].includes(k)))
        const { name, ariaLabelOnly = false } = value, expression = nativeClickExpression(name, ariaLabelOnly)
        if (page) { const locator = page.getByRole('button', { name, exact: true }); need(await locator.count() === 1); if (ariaLabelOnly) need(await locator.getAttribute('aria-label') === name); await locator.click({ timeout: 10000 }) }
        else await dispatchNativeClick(pageSendRaw, await evaluate(expression))
      }),
      screenshot: () => action(async () => page ? await page.screenshot({ type: 'png', fullPage: false, animations: 'disabled', timeout: 10000 }) : Buffer.from((await pageSendRaw('Page.captureScreenshot', { format: 'png', fromSurface: true, captureBeyondViewport: false })).data, 'base64')),
      tlsProof: (response, origin) => action(async () => { need(typeof origin === 'string' && /^https:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(origin) && Number(new URL(origin).port) <= 65535); const chain = (await pageSendRaw('Network.getCertificate', { origin })).tableNames; return { tls: browserTLSProof(response, chain, verified), certificateChain: chain } }),
      async close() {
        healthy(); need(phase === 'OPEN'); phase = 'CLOSING'; guard.beginClose()
        try {
          const result = await finishNativeSession(o, chrome, { closeBrowser: () => context ? context.close() : browserSendRaw('Browser.close'), readExit: async () => JSON.parse((await stableFile(o.root + '/chrome-exit.private.json', 4096, true)).toString()), launcherResult: childResult, wait: until, noLive: () => noLiveChrome(o, chrome), pause: delay })
          need(firstFault === null); guard.endClose(); phase = 'CLOSED'; transport?.socket.close(); return result
        } catch { fault('CLOSE_REJECTED'); phase = 'FAILED'; throw rejected() }
      },
      dispose,
      assertHealthy: healthy,
    })
  } catch {
    fault('STARTUP_REJECTED')
    // A failed diagnostic sink cannot produce success or expose the exception.
    try { if (hooks.onDiagnostic) await hooks.onDiagnostic(nativeOpenObservation(openStage, firstFault, initialTargets)) } catch { /* Observation unavailable. */ }
    await dispose(); throw rejected()
  }
}
