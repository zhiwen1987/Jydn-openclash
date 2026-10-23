// CI-only two real transports. Imports perform no launch or network I/O.
import { spawn, execFile } from 'node:child_process'
import { constants } from 'node:fs'
import { lstat, stat, mkdir, open, readFile, readlink, readdir, link, unlink } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { homedir } from 'node:os'
import { setTimeout as delay } from 'node:timers/promises'
import { promisify } from 'node:util'
import { pathToFileURL } from 'node:url'
import { ORIGIN, STEPS, SCOPE, LABEL, FAVICON, sha, need, exact, integer, ascii, parseProcess, versionProjection,
  assetPaths, classifyRequest, canaryVariants, safePublic, decodeBody, validateStep } from './ui-contract.mjs'
import { NavigationDiagnostics, NAVIGATION_TARGET_EXPRESSION } from './navigation-diagnostics.mjs'
const execute = promisify(execFile)
const checkpoint = value => process.stderr.write('SUBSCRIPTION_UI_STAGE=' + value + '\n')
const sameStat = (a, b) => ['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'nlink', 'mtimeNs', 'ctimeNs'].every(k => a[k] === b[k])
const us = value => { need(typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER / 1000000); return Math.floor(value * 1000000) }

async function stableFile(path, limit, privateInput = false) {
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const before = await fd.stat({ bigint: true })
    need(before.isFile() && before.nlink === 1n && before.size > 0n && before.size <= BigInt(limit))
    need(privateInput ? before.uid === 10001n && before.gid === 10001n && (before.mode & 0o7777n) === 0o600n
      : before.uid === 0n && (before.mode & 0o022n) === 0n)
    const raw = await fd.readFile(), after = await fd.stat({ bigint: true }), named = await lstat(path, { bigint: true })
    need(BigInt(raw.length) === before.size && sameStat(before, after) && sameStat(before, named))
    return raw
  } finally { await fd.close() }
}
async function ownedDirectory(path, create = false) {
  if (create) await mkdir(path, { mode: 0o700 })
  const s = await lstat(path)
  need(s.isDirectory() && !s.isSymbolicLink() && s.uid === 10001 && s.gid === 10001 && (s.mode & 0o7777) === 0o700)
}
async function publish(path, value, maximum) {
  const raw = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === 'string' ? value : JSON.stringify(value) + '\n')
  need(raw.length > 0 && raw.length <= maximum)
  const fd = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try { await fd.writeFile(raw); await fd.sync() } finally { await fd.close() }
  return { bytes: raw.length, sha256: sha(raw) }
}
async function publishReady(path, value) {
  const pending = path + '.pending'
  await publish(pending, value, 4096)
  // link is exclusive; unlike rename it cannot replace another signal. The
  // supervisor waits through the transient two-link state before strict read.
  await link(pending, path); await unlink(pending)
}
async function until(predicate, milliseconds = 10000) {
  const end = Date.now() + milliseconds
  while (Date.now() < end) { if (await predicate()) return; await delay(10) }
  need(false)
}

class Transport {
  constructor(socket) {
    this.socket = socket; this.next = 0; this.pending = new Map(); this.listeners = []; this.closed = false
    socket.addEventListener('message', event => {
      try {
        // One allowed 8 MiB decoded asset may use base64 plus CDP framing.
        // The per-body and aggregate decoded-byte gates remain independent.
        need(typeof event.data === 'string' && event.data.length <= 12 << 20)
        const message = JSON.parse(event.data)
        if (message.id) {
          const task = this.pending.get(message.id); if (!task) return
          this.pending.delete(message.id); clearTimeout(task.timer)
          if (message.error) task.reject(Error('subscription UI rejected')); else task.resolve(message.result)
        } else for (const listener of this.listeners) listener(message)
      } catch { this.abort() }
    })
    socket.addEventListener('close', () => this.abort()); socket.addEventListener('error', () => this.abort())
  }
  abort() {
    this.closed = true
    for (const task of this.pending.values()) { clearTimeout(task.timer); task.reject(Error('subscription UI rejected')) }
    this.pending.clear()
  }
  send(method, params = {}, sessionId) {
    need(!this.closed && this.pending.size < 32)
    const id = ++this.next
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(Error('subscription UI rejected')) }, 15000)
      this.pending.set(id, { resolve, reject, timer }); this.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }))
    })
  }
}
async function chromeIdentity(o, send) {
  const record = JSON.parse((await stableFile(o.root + '/chrome-process.private.json', 4096, true)).toString())
  need(exact(record, ['pid', 'startTicks', 'uid', 'profile']) && record.uid === 10001 && record.profile === o.profile)
  need(integer(record.pid, 2) && integer(record.startTicks, 1))
  const info = await send('SystemInfo.getProcessInfo'), browsers = info.processInfo?.filter(p => p.type === 'browser')
  need(browsers?.length === 1 && browsers[0].id === record.pid)
  const before = parseProcess(await readFile('/proc/' + record.pid + '/stat', 'utf8'))
  need(before.pid === record.pid && before.group === record.pid && before.session === record.pid && before.startTicks === record.startTicks)
  need(await readlink('/proc/' + record.pid + '/exe') === o.chrome)
  const argv = await readFile('/proc/' + record.pid + '/cmdline'); need(argv.length <= 262144 && argv.at(-1) === 0)
  const args = argv.toString('utf8').slice(0, -1).split('\0')
  need(args.length <= 128 && args[0] === o.chrome && args.includes('--no-sandbox'))
  need(args.filter(a => a.startsWith('--user-data-dir')).join('') === '--user-data-dir=' + o.profile)
  need(!args.some(a => /^(?:--ignore-certificate-errors|--ignore-certificate-errors-spki-list|--ignore-ssl-errors|--allow-insecure-localhost|--disable-web-security|--unsafely-treat-insecure-origin-as-secure)(?:=|$)/.test(a)))
  const fd = await open(o.chrome, constants.O_RDONLY | constants.O_NOFOLLOW)
  let bytes = 0, digest
  try {
    const first = await fd.stat({ bigint: true }), proc = await stat('/proc/' + record.pid + '/exe', { bigint: true })
    need(first.isFile() && first.uid === 0n && first.nlink === 1n && first.size > 0n && first.size <= 512n << 20n && (first.mode & 0o022n) === 0n)
    need(first.dev === proc.dev && first.ino === proc.ino)
    const hash = createHash('sha256'), chunk = Buffer.alloc(65536)
    while (true) { const r = await fd.read(chunk, 0, chunk.length, null); if (!r.bytesRead) break; bytes += r.bytesRead; need(bytes <= 512 << 20); hash.update(chunk.subarray(0, r.bytesRead)) }
    need(BigInt(bytes) === first.size && sameStat(first, await fd.stat({ bigint: true })) && sameStat(first, await lstat(o.chrome, { bigint: true })))
    digest = hash.digest('hex')
  } finally { await fd.close() }
  const after = parseProcess(await readFile('/proc/' + record.pid + '/stat', 'utf8'))
  need(after.startTicks === record.startTicks && await readlink('/proc/' + record.pid + '/exe') === o.chrome)
  return { ...record, argvSHA256: sha(argv), exeSHA256: digest, exeBytes: bytes }
}
async function noLiveChrome(o, chrome) {
  const names = await readdir('/proc'); need(names.length <= 32768)
  for (const name of names.filter(v => /^[0-9]+$/.test(v))) {
    try {
      if ((await lstat('/proc/' + name)).uid !== 10001) continue
      const p = parseProcess(await readFile('/proc/' + name + '/stat', 'utf8'))
      if (['Z', 'X'].includes(p.state)) continue
      const args = (await readFile('/proc/' + name + '/cmdline')).toString('utf8').split('\0')
      if (p.group === chrome.pid || args.includes('--user-data-dir=' + o.profile)
        || args.some((arg, index) => {
          const location = /^--(?:database|metrics-dir)=/.test(arg) ? arg.slice(arg.indexOf('=') + 1)
            : ['--database', '--metrics-dir'].includes(arg) ? args[index + 1] : null
          return typeof location === 'string' && location.startsWith(o.profile + '/')
        })) return false
    } catch (error) { if (!['ENOENT', 'ESRCH'].includes(error?.code)) throw error }
  }
  return true
}

// This journal observes real CDP events in both adapters. It never performs an
// API call or retries a response. Completion ordinals are assigned synchronously
// on loadingFinished, independently from asynchronous body collection order.
export class SubscriptionJournal {
  constructor(assets, token, bodyReader) {
    this.assets = assets; this.token = token; this.bodyReader = bodyReader
    this.canaries = canaryVariants(token); this.requests = new Map(); this.ignored = new Set()
    this.rows = []; this.tasks = new Set(); this.failure = false; this.totalBytes = 0; this.finished = 0
    this.counters = { runtimeErrors: 0, consoleErrors: 0, consoleWarnings: 0, cspErrors: 0, assetErrors: 0,
      forbiddenRequests: 0, failedRequests: 0, captureErrors: 0 }
  }
  reject() { this.failure = true; this.counters.captureErrors++ }
  handle(method, p) {
    try {
      if (method === 'Runtime.exceptionThrown') this.counters.runtimeErrors++
      if (method === 'Runtime.consoleAPICalled' && p.type === 'error') this.counters.consoleErrors++
      if (method === 'Runtime.consoleAPICalled' && ['warning', 'warn'].includes(p.type)) this.counters.consoleWarnings++
      if (method === 'Log.entryAdded' && p.entry?.source === 'security' && p.entry.level === 'error') this.counters.cspErrors++
      if (['Network.webSocketCreated', 'Network.webTransportCreated', 'Network.directTCPSocketCreated'].includes(method)) this.counters.forbiddenRequests++
      if (method === 'Network.requestWillBeSent') {
        if (p.request?.url === FAVICON) { need(this.ignored.size < 4); this.ignored.add(p.requestId); return }
        let projection
        try { projection = classifyRequest(p.request, this.assets, this.token) } catch { this.counters.forbiddenRequests++; throw Error() }
        need(!p.redirectResponse && this.requests.size < 64 && !this.requests.has(p.requestId) && /^[A-Za-z0-9_.-]{1,80}$/.test(p.requestId))
        if (projection.kind === 'CREATE') need(![...this.requests.values()].some(v => v.kind === 'CREATE'))
        const item = { ...projection, requestId: p.requestId, requestOrdinal: this.requests.size + 1, startedWallTimeUs: us(p.wallTime), startTimeUs: us(p.timestamp), response: null, terminal: false }
        this.requests.set(p.requestId, item)
      }
      if (this.ignored.has(p.requestId)) return
      if (method === 'Network.responseReceived') {
        const item = this.requests.get(p.requestId), r = p.response
        need(item && !item.response && !item.terminal && r && r.url === ORIGIN + item.path && !r.fromDiskCache && !r.fromServiceWorker)
        if (item.kind === 'ASSET') {
          const allowed = item.path.endsWith('.js') ? ['text/javascript', 'application/javascript'] : item.path.endsWith('.css') ? ['text/css'] : item.path.endsWith('.svg') ? ['image/svg+xml'] : item.path.endsWith('.png') ? ['image/png'] : item.path.endsWith('.woff2') ? ['font/woff2'] : item.path.endsWith('.woff') ? ['font/woff'] : ['font/ttf']
          if (r.status !== 200 || !allowed.includes(r.mimeType)) this.counters.assetErrors++
        }
        need(r.status === 200 && (item.kind !== 'DOCUMENT' || r.mimeType === 'text/html'))
        const headers = Object.fromEntries(Object.entries(r.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]))
        need(headers['set-cookie'] === undefined)
        if (!['DOCUMENT', 'ASSET'].includes(item.kind)) need(r.mimeType === 'application/json')
        item.response = r; item.headerTimeUs = us(p.timestamp); need(item.headerTimeUs >= item.startTimeUs)
      }
      if (method === 'Network.loadingFailed') {
        need(this.requests.has(p.requestId)); this.requests.get(p.requestId).terminal = true
        this.counters.failedRequests++; this.failure = true
      }
      if (method === 'Network.loadingFinished') {
        const item = this.requests.get(p.requestId); need(item && item.response && !item.terminal)
        need(integer(p.encodedDataLength, 0, 16 << 20)); item.terminal = true; item.endTimeUs = us(p.timestamp); need(item.endTimeUs >= item.startTimeUs)
        const ordinal = ++this.finished
        const task = this.capture(item, ordinal, p.encodedDataLength).catch(() => this.reject()).finally(() => this.tasks.delete(task))
        this.tasks.add(task)
      }
    } catch { this.reject() }
  }
  async capture(item, ordinal, encodedDataLength) {
    const raw = decodeBody(await this.bodyReader(item.requestId), ['DOCUMENT', 'ASSET'].includes(item.kind) ? 8 << 20 : 65536)
    safePublic(raw, this.canaries); this.totalBytes += raw.length; need(this.totalBytes <= 16 << 20)
    const row = { schema: 'chengwang.subscription-ui-capture/v1', ordinal, requestOrdinal: item.requestOrdinal,
      requestId: item.requestId, method: item.method, path: item.path, kind: item.kind, status: item.response.status,
      authorizationPresent: item.authorizationPresent, requestPublic: item.requestPublic, responseBase64: raw.toString('base64'),
      responseSHA256: sha(raw), responseBytes: raw.length, startedWallTimeUs: item.startedWallTimeUs,
      startTimeUs: item.startTimeUs, headerTimeUs: item.headerTimeUs, endTimeUs: item.endTimeUs,
      terminal: { event: 'FINISH', encodedDataLength } }
    safePublic(Buffer.from(JSON.stringify(row)), this.canaries); this.rows.push(row)
  }
  mutationCount() { return [...this.requests.values()].filter(v => v.method !== 'GET').length }
  idle() { return this.tasks.size === 0 && [...this.requests.values()].every(v => v.terminal) }
  complete() {
    need(!this.failure && this.idle() && this.requests.size > 0 && this.rows.length === this.requests.size && this.finished === this.rows.length && Object.values(this.counters).every(v => v === 0))
    const kinds = this.rows.map(v => v.kind)
    for (const [kind, count] of [['DOCUMENT', 1], ['SNAPSHOT', 1], ['COLLECTION_ACCESS', 2], ['SOURCES', 2], ['CREATE', 1], ['SOURCE_ACCESS', 1], ['CANDIDATES', 1], ['RECEIPT', 1]]) need(kinds.filter(v => v === kind).length === count)
    need(kinds.filter(v => v === 'ASSET').length > 0 && this.mutationCount() === 1)
  }
}

// An allowlist, not an arbitrary selector/script entrypoint. Input is delivered
// through actual browser input APIs; evaluation only observes or scrolls DOM.
const BUTTONS = Object.freeze(['订阅与提供者', '运行总览', '连接订阅会话', '准备创建来源', '取消本次操作', '确认并提交本地操作', '读取命令回执', '清除会话与令牌'])
function targetExpression(kind, value) {
  need(kind === 'button' ? BUTTONS.includes(value) : kind === 'input' && ['subscription-token', 'subscription-source-label'].includes(value))
  return kind === 'input' ? `document.getElementById(${JSON.stringify(value)})`
    : `(()=>{const a=[...document.querySelectorAll('button')].filter(e=>e.textContent.trim()===${JSON.stringify(value)}||e.getAttribute('aria-label')===${JSON.stringify(value)});if(a.length!==1)throw Error('UI target rejected');return a[0]})()`
}
export async function runSubscriptionUI(o) {
  checkpoint('ENVIRONMENT')
  need(process.platform === 'linux' && process.getuid?.() === 10001 && process.getgid?.() === 10001 && !Object.hasOwn(process.env, 'HOME') && process.env.TMPDIR === '/var/tmp' && homedir() === o.home && typeof WebSocket === 'function')
  await ownedDirectory(o.root); await ownedDirectory('/var/tmp'); await ownedDirectory(o.home, true); await ownedDirectory(o.profile, true)
  const config = JSON.parse((await stableFile(o.bundle + '/launch.json', 4096)).toString())
  need(exact(config, ['schema', 'engine', 'fixtureId', 'root', 'chrome', 'chromeSHA256']) && config.schema === 'chengwang.subscription-ui-launch/v1' && config.engine === o.engine && config.fixtureId === o.fixtureId && config.root === o.root && config.chrome === o.chrome && /^[a-f0-9]{64}$/.test(config.chromeSHA256))
  const input = JSON.parse((await stableFile(o.root + '/browser-input.private.json', 8192, true)).toString())
  need(exact(input, ['schema', 'operatorToken', 'label']) && input.schema === 'chengwang.subscription-ui-input/v1' && input.label === LABEL)
  const canaries = canaryVariants(input.operatorToken)
  await stableFile(o.launcher, 131072)
  const source = o.bundle + '/source/chengwang/'
  const helper = await import(pathToFileURL(source + 'web/scripts/trust-browser-tls.mjs').href)
  const collector = await import(pathToFileURL(source + 'tools/subscription-browser/collect-subscription-dom.mjs').href)
  const manifest = JSON.parse((await stableFile(source + 'web/dist/.vite/manifest.json', 131072)).toString()), assets = assetPaths(manifest)
  const ca = await stableFile(o.root + '/api-ca.pem', 65536, true), leaf = await stableFile(o.root + '/api-leaf.pem', 65536, true), verified = helper.inspectPublicTLS(ca.toString('utf8'), leaf.toString('utf8'))
  const data = o.home + '/.local/share', database = data + '/pki/nssdb'
  await mkdir(database, { mode: 0o700, recursive: true }); try { await lstat(o.home + '/.pki/nssdb'); need(false) } catch (e) { need(e?.code === 'ENOENT') }
  for (const name of ['config', 'cache']) await ownedDirectory(o.profile + '/' + name, true)
  const environment = { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TMPDIR: '/var/tmp', XDG_DATA_HOME: data, XDG_CONFIG_HOME: o.profile + '/config', XDG_CACHE_HOME: o.profile + '/cache' }
  await stableFile('/usr/bin/certutil', 16 << 20)
  const certutil = args => execute('/usr/bin/certutil', args, { env: environment, timeout: 10000, maxBuffer: 65536, encoding: 'utf8' })
  await certutil(['-N', '-d', 'sql:' + database, '--empty-password']); await certutil(['-A', '-d', 'sql:' + database, '-n', 'chengwang-subscription-ui-root', '-t', 'C,,', '-i', o.root + '/api-ca.pem'])
  const imported = (await certutil(['-L', '-d', 'sql:' + database, '-n', 'chengwang-subscription-ui-root', '-a'])).stdout
  need(helper.inspectPublicTLS(imported, leaf.toString('utf8')).caSHA256 === verified.caSHA256)
  let context, page, transport, browserSend, pageSend, launcherChild, childResult, journal, closed = false, captured = false
  const diagnostics = new NavigationDiagnostics({ sourceCommit: o.sourceCommit, fixtureId: o.fixtureId, engine: o.engine, scenario: 'create_receipt' })
  try {
    checkpoint('LAUNCH')
    const args = ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps', '--disable-extensions', '--no-first-run', '--no-default-browser-check', '--disable-features=MediaRouter,OptimizationHints', '--password-store=basic']
    if (o.engine === 'chrome-cdp') {
      launcherChild = spawn(o.launcher, [...args, '--headless=new', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--user-data-dir=' + o.profile, 'about:blank'], { stdio: ['ignore', 'ignore', 'ignore'], env: environment })
      childResult = new Promise(resolve => { launcherChild.once('error', () => resolve({ code: null, signal: null })); launcherChild.once('exit', (code, signal) => resolve({ code, signal })) })
      let port
      await until(async () => { need(launcherChild.exitCode === null && launcherChild.signalCode === null); try { const raw = await readFile(o.profile + '/DevToolsActivePort', 'utf8'); need(raw.length <= 1024); const lines = raw.trim().split('\n'); need(lines.length === 2 && /^[1-9][0-9]{0,4}$/.test(lines[0]) && Number(lines[0]) <= 65535 && /^\/devtools\/browser\/[a-f0-9-]{1,80}$/.test(lines[1])); port = lines; return true } catch (e) { if (e?.code === 'ENOENT') return false; throw e } }, 20000)
      const socket = new WebSocket('ws://127.0.0.1:' + port[0] + port[1]); await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(Error('subscription UI rejected')), 10000); socket.addEventListener('open', () => { clearTimeout(timer); resolve() }, { once: true }); socket.addEventListener('error', () => { clearTimeout(timer); reject(Error('subscription UI rejected')) }, { once: true }) })
      transport = new Transport(socket); browserSend = (method, params) => transport.send(method, params)
      const target = await browserSend('Target.createTarget', { url: 'about:blank' }), sessionId = (await browserSend('Target.attachToTarget', { targetId: target.targetId, flatten: true })).sessionId
      pageSend = (method, params) => transport.send(method, params, sessionId)
      transport.listeners.push(m => { if (m.sessionId === sessionId) journal?.handle(m.method, m.params ?? {}) })
      const known = new Set((await browserSend('Target.getTargets')).targetInfos.map(v => v.targetId))
      transport.listeners.push(m => { if (m.method === 'Target.targetCreated' && ['page', 'service_worker', 'shared_worker'].includes(m.params?.targetInfo?.type) && !known.has(m.params.targetInfo.targetId)) { if (journal) { journal.failure = true; journal.counters.forbiddenRequests++ } } })
      await browserSend('Target.setDiscoverTargets', { discover: true })
    } else {
      const packageFile = source + 'tools/subscription-ui-browser/node_modules/playwright-core/'
      need(JSON.parse((await stableFile(packageFile + 'package.json', 65536)).toString()).version === '1.65.0-alpha-2026-10-23')
      const module = await import(pathToFileURL(packageFile + 'index.mjs').href)
      context = await module.chromium.launchPersistentContext(o.profile, { executablePath: o.launcher, headless: true, chromiumSandbox: false, ignoreHTTPSErrors: false, bypassCSP: false, args, env: environment, timeout: 20000 })
      page = context.pages()[0]; need(page && context.pages().length === 1)
      const session = await context.newCDPSession(page), browserSession = await context.browser().newBrowserCDPSession()
      pageSend = (method, params) => session.send(method, params); browserSend = (method, params) => browserSession.send(method, params)
      for (const event of ['Network.requestWillBeSent', 'Network.responseReceived', 'Network.loadingFinished', 'Network.loadingFailed', 'Runtime.exceptionThrown', 'Runtime.consoleAPICalled', 'Log.entryAdded', 'Network.webSocketCreated', 'Network.webTransportCreated', 'Network.directTCPSocketCreated']) session.on(event, p => journal?.handle(event, p))
      context.on('page', p => { if (p !== page && journal) { journal.failure = true; journal.counters.forbiddenRequests++ } }); context.on('serviceworker', () => { if (journal) { journal.failure = true; journal.counters.forbiddenRequests++ } })
    }
    journal = new SubscriptionJournal(assets, input.operatorToken, requestId => pageSend('Network.getResponseBody', { requestId }))
    const browser = versionProjection(await browserSend('Browser.getVersion')), chrome = await chromeIdentity(o, browserSend); need(chrome.exeSHA256 === config.chromeSHA256)
    await Promise.all(['Runtime.enable', 'Page.enable', 'Log.enable'].map(method => pageSend(method)))
    await pageSend('Network.enable', { maxTotalBufferSize: 32 << 20, maxResourceBufferSize: 8 << 20 })
    const evaluate = async expression => { if (page) return page.evaluate(expression); const r = await pageSend('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }); need(r && !r.exceptionDetails && Object.hasOwn(r.result ?? {}, 'value')); return r.result.value }
    const viewport = async width => { if (page) await page.setViewportSize({ width, height: 900 }); else await pageSend('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false }) }
    const click = async name => {
      need(BUTTONS.includes(name)); const expression = targetExpression('button', name)
      const initialNavigation = name === '订阅与提供者' && diagnostics.nextPhase === 'NAV_TARGET_FOUND'
      if (initialNavigation) diagnostics.enter('NAV_TARGET_FOUND', 'NAV_TARGET_QUERY_REJECTED')
      if (page) {
        const target = page.getByRole('button', { name, exact: true }), count = await target.count()
        if (initialNavigation) need(diagnostics.observePlaywrightTarget(count)); need(count === 1)
        if (initialNavigation) diagnostics.enter('INPUT_DISPATCHED', 'PW_CLICK_REJECTED')
        await target.click({ timeout: 10000 })
        if (initialNavigation) { diagnostics.playwrightClickReturned(); diagnostics.complete('INPUT_DISPATCHED') }
      } else {
        const observed = await evaluate(initialNavigation ? NAVIGATION_TARGET_EXPRESSION : `(()=>{const e=${expression};if(!e||e.disabled)throw Error('UI target rejected');e.scrollIntoView({block:'center',inline:'nearest'});const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;if(!(r.width>0&&r.height>0&&x>=0&&y>=0&&x<innerWidth&&y<innerHeight&&e.contains(document.elementFromPoint(x,y))))throw Error('UI target rejected');return{x,y}})()`)
        const point = initialNavigation ? diagnostics.observeCDPTarget(observed) : observed; need(point)
        if (initialNavigation) diagnostics.enter('INPUT_DISPATCHED', 'INPUT_MOVE_REJECTED')
        await pageSend('Input.dispatchMouseEvent', { type: 'mouseMoved', ...point })
        if (initialNavigation) { diagnostics.acknowledgeMouse('move'); diagnostics.setCause('INPUT_PRESS_REJECTED') }
        await pageSend('Input.dispatchMouseEvent', { type: 'mousePressed', button: 'left', clickCount: 1, ...point })
        if (initialNavigation) { diagnostics.acknowledgeMouse('press'); diagnostics.setCause('INPUT_RELEASE_REJECTED') }
        await pageSend('Input.dispatchMouseEvent', { type: 'mouseReleased', button: 'left', clickCount: 1, ...point })
        if (initialNavigation) { diagnostics.acknowledgeMouse('release'); diagnostics.complete('INPUT_DISPATCHED') }
      }
    }
    const fill = async (id, value) => {
      need(['subscription-token', 'subscription-source-label'].includes(id) && typeof value === 'string' && value.length <= 4096)
      if (page) await page.locator('#' + id).fill(value, { timeout: 10000 })
      else { const expression = targetExpression('input', id); need(await evaluate(`(()=>{const e=${expression};if(!e||e.disabled||e.value!=='')return false;e.scrollIntoView({block:'center'});e.focus();return document.activeElement===e})()`) === true); await pageSend('Input.insertText', { text: value }) }
    }
    const waitDOM = async predicate => { let d; await until(async () => { need(!journal.failure); d = await evaluate(collector.SUBSCRIPTION_DOM_EXPRESSION); collector.validateSubscriptionDOM(d); return journal.idle() && predicate(d) }); return d }
    const domRows = [], screenshots = []
    const record = async step => {
      await until(() => journal.idle()); need(!journal.failure)
      if (step === 'anonymous') diagnostics.setCause('ANON_IDENTITY_REJECTED')
      need(await evaluate('location.href===' + JSON.stringify(ORIGIN + '/') + '&&document.title==="澄网 · 网络代理与路由平台"&&!document.querySelector("vite-error-overlay,nextjs-portal,[data-vite-error-overlay]")') === true)
      if (step === 'anonymous') diagnostics.setCause('ANON_SHAPE_REJECTED')
      const dom = await evaluate(collector.SUBSCRIPTION_DOM_EXPRESSION); collector.validateSubscriptionDOM(dom)
      if (step === 'anonymous') diagnostics.setCause('ANON_STEP_REJECTED')
      validateStep(step, dom, journal.mutationCount())
      // Visible text and all non-password input values are inspected privately.
      // No raw text or observed input is retained in the public artifact.
      if (step === 'anonymous') diagnostics.setCause('ANON_CONTENT_FENCE_REJECTED')
      const text = await evaluate(`(()=>{const p=document.querySelector('.subscriptions');return[p?.innerText??'',[...document.querySelectorAll('input:not([type="password"]):not([type="file"]),textarea')].map(e=>e.value).join('\\n')].join('\\n')})()`)
      need(typeof text === 'string' && Buffer.byteLength(text) <= 131072); safePublic(Buffer.from(text), canaries)
      const row = { schema: 'chengwang.subscription-ui-dom-capture/v1', ordinal: domRows.length + 1, step, captureCount: journal.rows.length, mutationCount: journal.mutationCount(), dom }
      safePublic(Buffer.from(JSON.stringify(row)), canaries); domRows.push(row); return dom
    }
    const shot = async step => {
      const dom = domRows.at(-1).dom; need(domRows.at(-1).step === step && dom.session.tokenEmpty && dom.session.fileEmpty)
      const raw = page ? await page.screenshot({ type: 'png', fullPage: false, animations: 'disabled', timeout: 10000 }) : Buffer.from((await pageSend('Page.captureScreenshot', { format: 'png', fromSurface: true, captureBeyondViewport: false })).data, 'base64')
      need(raw.length >= 1000 && raw.length <= 4 << 20 && raw.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])))
      const mobile = step === 'created_mobile', name = mobile ? 'created-mobile' : 'created-desktop'
      const metadata = await publish(o.root + '/' + name + '.private.png', raw, 4 << 20)
      screenshots.push({ path: name + '.png', step, ...metadata, viewport: { width: dom.viewport.width, height: dom.viewport.height }, scrollX: dom.viewport.scrollX, scrollY: dom.viewport.scrollY, capturedWallTimeUs: Date.now() * 1000 })
    }
    await publishReady(o.root + '/driver-ready.private.json', { schema: 'chengwang.subscription-ui-driver-ready/v1', fixtureId: o.fixtureId, engine: o.engine, pid: process.pid, chromePid: chrome.pid })
    await until(async () => { try { const raw = await stableFile(o.root + '/run.go', 4096), s = await lstat(o.root + '/run.go'); need((s.mode & 0o7777) === 0o444); const v = JSON.parse(raw.toString()); need(exact(v, ['schema', 'fixtureId', 'engine']) && v.schema === 'chengwang.subscription-ui-run/v1' && v.fixtureId === o.fixtureId && v.engine === o.engine); return true } catch (e) { if (e?.code === 'ENOENT') return false; throw e } }, 20000)
    checkpoint('NAVIGATE'); await viewport(1440)
    diagnostics.enter('NAVIGATE_RETURN', 'NAVIGATE_CALL_REJECTED')
    if (page) { await page.goto(ORIGIN + '/', { waitUntil: 'load', timeout: 15000 }); diagnostics.complete('NAVIGATE_RETURN'); diagnostics.enter('READY', 'READY_WAIT_REJECTED') }
    else { const r = await pageSend('Page.navigate', { url: ORIGIN + '/' }); if (r.errorText) diagnostics.setCause('NAVIGATE_ERROR_PRESENT'); need(!r.errorText); diagnostics.complete('NAVIGATE_RETURN'); diagnostics.enter('READY', 'READY_WAIT_REJECTED'); await until(async () => await evaluate('location.href===' + JSON.stringify(ORIGIN + '/') + '&&document.readyState==="complete"') === true) }
    await until(() => journal.idle() && journal.rows.some(v => v.kind === 'SNAPSHOT'))
    diagnostics.complete('READY')
    await click('订阅与提供者'); diagnostics.enter('ANON_DOM', 'ANON_DOM_WAIT_REJECTED'); await waitDOM(d => d.pageVisible && !d.controls.find(v => v.key === 'prepare_create').enabled); await record('anonymous'); diagnostics.complete('ANON_DOM')
    diagnostics.enter('API_CERT', 'API_CERT_REJECTED')
    const documentRequest = [...journal.requests.values()].find(v => v.kind === 'DOCUMENT'); need(documentRequest?.response)
    const certificateChain = (await pageSend('Network.getCertificate', { origin: ORIGIN })).tableNames
    diagnostics.complete('API_CERT'); diagnostics.enter('TLS_VERIFIED', 'TLS_PROOF_REJECTED')
    const tls = helper.browserTLSProof(documentRequest.response, certificateChain, verified); diagnostics.complete('TLS_VERIFIED')
    checkpoint('CONNECT'); await fill('subscription-token', input.operatorToken); await click('连接订阅会话')
    await waitDOM(d => d.controls.find(v => v.key === 'prepare_create').enabled && d.session.tokenEmpty && journal.rows.some(v => v.kind === 'SOURCES')); await record('connected')
    await fill('subscription-source-label', input.label); await click('准备创建来源'); await waitDOM(d => d.confirmation?.kind === 'create'); await record('prepared')
    await click('取消本次操作'); await waitDOM(d => d.confirmation === null); await record('cancelled')
    await click('准备创建来源'); await waitDOM(d => d.confirmation?.kind === 'create'); await record('prepared_again')
    checkpoint('CONFIRM'); await click('确认并提交本地操作')
    await waitDOM(d => d.sources.length === 1 && d.sources[0].selected && d.receipt?.state === 'committed' && d.paging.candidates?.revision === 1 && d.controls.find(v => v.key === 'prepare_import').enabled)
    const settleLayout = () => evaluate('(async()=>{await document.fonts.ready;window.scrollTo(0,0);await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));return true})()')
    await settleLayout(); await record('created_desktop'); await shot('created_desktop')
    await viewport(375); await settleLayout(); await record('created_mobile'); await shot('created_mobile')
    checkpoint('RECEIPT'); await click('读取命令回执'); await waitDOM(d => d.receipt?.state === 'committed' && journal.rows.filter(v => v.kind === 'RECEIPT').length === 1); await record('receipt')
    await click('运行总览'); await waitDOM(d => !d.pageVisible); await record('hidden')
    await click('订阅与提供者'); await waitDOM(d => d.pageVisible); await record('returned')
    await click('清除会话与令牌'); await waitDOM(d => d.sources.length === 0 && d.receipt === null && !d.controls.find(v => v.key === 'prepare_create').enabled); await record('cleared')
    need(domRows.map(v => v.step).join(',') === STEPS.join(',')); journal.complete()
    checkpoint('CLOSE'); if (context) await context.close(); else await browserSend('Browser.close')
    let chromeExit; await until(async () => { try { chromeExit = JSON.parse((await stableFile(o.root + '/chrome-exit.private.json', 4096, true)).toString()); return true } catch (e) { if (e?.code === 'ENOENT') return false; throw e } }, 20000)
    need(exact(chromeExit, ['schema', 'engine', 'fixtureId', 'pid', 'startTicks', 'exitCode', 'joined', 'forced']) && chromeExit.schema === 'chengwang.subscription-ui-chrome-exit/v1' && chromeExit.engine === o.engine && chromeExit.fixtureId === o.fixtureId && chromeExit.pid === chrome.pid && chromeExit.startTicks === chrome.startTicks && chromeExit.exitCode === 0 && chromeExit.joined === true && chromeExit.forced === false)
    let launcherExit = null; if (childResult) { launcherExit = await Promise.race([childResult, delay(2000).then(() => null)]); need(launcherExit?.code === 0 && launcherExit.signal === null) }
    await until(() => noLiveChrome(o, chrome), 5000); closed = true; transport?.socket.close()
    const capturesRaw = Buffer.from([...journal.rows].sort((a, b) => a.ordinal - b.ordinal).map(v => JSON.stringify(v)).join('\n') + '\n'), domRaw = Buffer.from(domRows.map(v => JSON.stringify(v)).join('\n') + '\n')
    safePublic(capturesRaw, canaries); safePublic(domRaw, canaries)
    const captures = await publish(o.root + '/captures.private.jsonl', capturesRaw, 24 << 20); await publish(o.root + '/dom.private.jsonl', domRaw, 262144); captured = true
    const report = { schema: 'chengwang.subscription-ui-driver/v1', sourceCommit: o.sourceCommit, engine: o.engine, fixtureId: o.fixtureId, origin: ORIGIN, scope: SCOPE, runtime: true, mockedResponses: false, injectedFetch: false, tlsBypass: false,
      browser, chrome, normalTrust: { method: 'PRIVATE_NSS_SQL_XDG_LOCAL_CA', trustFlags: 'C,,', caSHA256: verified.caSHA256, leafSHA256: verified.leafSHA256, homeEnvironmentAbsent: true, legacyDatabaseAbsent: true }, tls, certificateChain, counters: journal.counters,
      close: { normalCloseCommandCompleted: true, chromeExit, launcherExit, noLiveOwnedProcesses: true, processScope: 'CHROME_SESSION_AND_LAUNCHER_ONLY' },
      steps: [...STEPS], captures: { path: 'captures.jsonl', ...captures, records: journal.rows.length }, screenshots, production: false, fullSubscriptionE2EProven: false }
    safePublic(Buffer.from(JSON.stringify(report)), canaries); await publish(o.root + '/driver.private.json', report, 65536); checkpoint('COMPLETE'); return report
  } catch (error) {
    await diagnostics.writeFailure(o.root, journal)
    throw error
  } finally {
    if (!closed) { try { if (context) await context.close(); else if (browserSend) await browserSend('Browser.close') } catch { /* Emergency cleanup is not normal-close evidence. */ }; transport?.socket.close() }
    if (!captured && journal?.rows.length) { try { const raw = Buffer.from([...journal.rows].sort((a, b) => a.ordinal - b.ordinal).map(v => JSON.stringify(v)).join('\n') + '\n'); safePublic(raw, canaries); await publish(o.root + '/captures.private.jsonl', raw, 24 << 20) } catch { /* Preserve originals; never replace failed evidence. */ } }
  }
}

// Neutral low-level mechanisms only. Scenario flows, journals, route policies
// and constants above remain private to the original create/receipt gate.
export { stableFile, ownedDirectory, publish, publishReady, until, Transport, chromeIdentity, noLiveChrome }
