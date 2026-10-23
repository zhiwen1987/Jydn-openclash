// CI-only two real transports. Imports perform no launch or network I/O.
import { spawn, execFile } from 'node:child_process'
import { constants } from 'node:fs'
import { lstat, stat, mkdir, open, readFile, readlink, readdir, link, unlink } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { homedir } from 'node:os'
import { setTimeout as delay } from 'node:timers/promises'
import { promisify } from 'node:util'
import { pathToFileURL } from 'node:url'
import { ORIGIN, BODY_LIMIT, CASES, sha, need, exact, integer, ascii, parseProcess, versionProjection,
  requestCase, responseBody, errorProjection, readInPage, validateCase } from './matrix-contract.mjs'
const execute = promisify(execFile)
const checkpoint = value => process.stderr.write('STREAM_MATRIX_STAGE=' + value + '\n')
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
  const raw = Buffer.from(typeof value === 'string' ? value : JSON.stringify(value) + '\n')
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

export class MatrixJournal {
  constructor() {
    this.requests = new Map(); this.byCase = new Map(); this.rows = []; this.ignored = new Set(); this.failure = false
    this.counters = { runtimeErrors: 0, consoleErrors: 0, consoleWarnings: 0, cspErrors: 0,
      forbiddenRequests: 0, unexpectedFailedRequests: 0, captureErrors: 0 }
  }
  row(event, item, timestamp, extra = {}) {
    need(this.rows.length < 64)
    this.rows.push({ v: 1, seq: this.rows.length + 1, event, ordinal: item.ordinal, requestId: item.requestId,
      case: item.case, clock: 'CDP_MONOTONIC_US', timeUs: us(timestamp), ...extra })
  }
  handle(method, p) {
    try {
      if (method === 'Runtime.exceptionThrown') this.counters.runtimeErrors++
      if (method === 'Runtime.consoleAPICalled' && p.type === 'error') this.counters.consoleErrors++
      if (method === 'Runtime.consoleAPICalled' && p.type === 'warning') this.counters.consoleWarnings++
      if (method === 'Log.entryAdded' && p.entry?.source === 'security' && p.entry.level === 'error') this.counters.cspErrors++
      if (method === 'Network.requestWillBeSent') {
        if (p.request?.url === 'data:,') { need(this.ignored.size < 8); this.ignored.add(p.requestId); return }
        let id
        try { id = requestCase(p.request) } catch { this.counters.forbiddenRequests++; throw Error() }
        need(!p.redirectResponse && this.requests.size < 6 && !this.requests.has(p.requestId) && !this.byCase.has(id))
        need(ascii(p.requestId) && /^[A-Za-z0-9_.-]{1,80}$/.test(p.requestId))
        const item = { case: id, ordinal: this.requests.size + 1, requestId: p.requestId, response: null, terminal: null }
        need(id === ['DOCUMENT', ...CASES][item.ordinal - 1])
        this.requests.set(p.requestId, item); this.byCase.set(id, item)
        this.row('START', item, p.timestamp, { wallTimeUs: us(p.wallTime) })
      }
      if (this.ignored.has(p.requestId)) return
      if (method === 'Network.responseReceived') {
        const item = this.requests.get(p.requestId); need(item && !item.response && !item.terminal)
        const r = p.response; need(r && r.url === ORIGIN + (item.case === 'DOCUMENT' ? '/' : '/case/' + item.case) && r.status === 200)
        const headers = Object.fromEntries(Object.entries(r.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]))
        need(headers['cache-control'] === 'no-store')
        const mime = item.case === 'DOCUMENT' ? 'text/html' : 'application/json'
        need(r.mimeType === mime && (headers['content-type'] === mime || item.case === 'DOCUMENT' && headers['content-type'] === 'text/html; charset=utf-8'))
        const length = headers['content-length'] === undefined ? null : Number(headers['content-length'])
        need(length === null || integer(length, 1, 65536 + BODY_LIMIT))
        if (item.case !== 'DOCUMENT') need(item.case === 'oversize' ? length === null : length === (item.case === 'boundary-success' ? BODY_LIMIT : 11))
        item.response = r
        this.row('HEADERS', item, p.timestamp, { status: 200, mimeType: mime, noStore: true, contentLength: length })
      }
      if (method === 'Network.loadingFinished' || method === 'Network.loadingFailed') {
        const item = this.requests.get(p.requestId); need(item && item.response && !item.terminal)
        if (method === 'Network.loadingFinished') {
          need(integer(p.encodedDataLength, 0, 2 << 20))
          item.terminal = { event: 'FINISH', canceled: 'UNSPECIFIED', errorCode: 'NONE' }
          this.row('FINISH', item, p.timestamp, { encodedDataLength: p.encodedDataLength })
        } else {
          const code = errorProjection(p.errorText), canceled = p.canceled === true ? 'YES' : p.canceled === false ? 'NO' : 'UNSPECIFIED'
          item.terminal = { event: 'FAIL', canceled, errorCode: code }
          const expected = item.case === 'oversize' && code === 'ABORTED'
            || item.case === 'truncated' && ['CONTENT_LENGTH_MISMATCH', 'OTHER'].includes(code)
            || item.case === 'abort' && code === 'ABORTED'
          if (!expected) this.counters.unexpectedFailedRequests++
          this.row('FAIL', item, p.timestamp, { canceled, errorCode: code })
        }
      }
    } catch { this.failure = true; this.counters.captureErrors++ }
  }
  complete() {
    need(!this.failure && this.requests.size === 6 && this.byCase.size === 6 && this.rows.length === 18)
    need([...this.requests.values()].every(item => item.response && item.terminal))
    need(Object.values(this.counters).every(count => count === 0))
    need(this.byCase.get('DOCUMENT').terminal.event === 'FINISH')
  }
}

class Transport {
  constructor(socket) {
    this.socket = socket; this.next = 0; this.pending = new Map(); this.listeners = []; this.closed = false
    socket.addEventListener('message', event => {
      try {
        need(typeof event.data === 'string' && event.data.length <= 4 << 20)
        const message = JSON.parse(event.data)
        if (message.id) {
          const task = this.pending.get(message.id); if (!task) return
          this.pending.delete(message.id); clearTimeout(task.timer)
          if (message.error) task.reject(Error('stream matrix rejected')); else task.resolve(message.result)
        } else for (const listener of this.listeners) listener(message)
      } catch { this.abort() }
    })
    socket.addEventListener('close', () => this.abort()); socket.addEventListener('error', () => this.abort())
  }
  abort() {
    this.closed = true
    for (const task of this.pending.values()) { clearTimeout(task.timer); task.reject(Error('stream matrix rejected')) }
    this.pending.clear()
  }
  send(method, params = {}, sessionId) {
    need(!this.closed && this.pending.size < 32)
    const id = ++this.next
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(Error('stream matrix rejected')) }, 15000)
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

export async function runMatrix(o) {
  checkpoint('ENVIRONMENT')
  need(process.platform === 'linux' && process.getuid?.() === 10001 && process.getgid?.() === 10001
    && !Object.hasOwn(process.env, 'HOME') && process.env.TMPDIR === '/var/tmp' && homedir() === o.home && typeof WebSocket === 'function')
  await ownedDirectory(o.root); await ownedDirectory('/var/tmp')
  await ownedDirectory(o.home, true); await ownedDirectory(o.profile, true)
  const config = JSON.parse((await stableFile(o.bundle + '/launch.json', 4096)).toString())
  need(exact(config, ['schema', 'engine', 'fixtureId', 'root', 'chrome', 'chromeSHA256'])
    && config.schema === 'chengwang.stream-matrix-launch/v1' && config.engine === o.engine && config.fixtureId === o.fixtureId
    && config.root === o.root && config.chrome === o.chrome && ascii(config.chromeSHA256) && /^[a-f0-9]{64}$/.test(config.chromeSHA256))
  await stableFile(o.launcher, 131072)
  const helper = await import(pathToFileURL(o.bundle + '/source/chengwang/web/scripts/trust-browser-tls.mjs').href)
  const ca = await stableFile(o.root + '/api-ca.pem', 65536, true), leaf = await stableFile(o.root + '/api-leaf.pem', 65536, true)
  const verified = helper.inspectPublicTLS(ca.toString('utf8'), leaf.toString('utf8'))
  const data = o.home + '/.local/share', database = data + '/pki/nssdb'
  await mkdir(database, { mode: 0o700, recursive: true })
  try { await lstat(o.home + '/.pki/nssdb'); need(false) } catch (error) { need(error?.code === 'ENOENT') }
  for (const name of ['config', 'cache']) await ownedDirectory(o.profile + '/' + name, true)
  const environment = { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TMPDIR: '/var/tmp',
    XDG_DATA_HOME: data, XDG_CONFIG_HOME: o.profile + '/config', XDG_CACHE_HOME: o.profile + '/cache' }
  await stableFile('/usr/bin/certutil', 16 << 20)
  const certutil = args => execute('/usr/bin/certutil', args, { env: environment, timeout: 10000, maxBuffer: 65536, encoding: 'utf8' })
  checkpoint('NSS')
  await certutil(['-N', '-d', 'sql:' + database, '--empty-password'])
  await certutil(['-A', '-d', 'sql:' + database, '-n', 'chengwang-stream-matrix-root', '-t', 'C,,', '-i', o.root + '/api-ca.pem'])
  const imported = (await certutil(['-L', '-d', 'sql:' + database, '-n', 'chengwang-stream-matrix-root', '-a'])).stdout
  need(helper.inspectPublicTLS(imported, leaf.toString('utf8')).caSHA256 === verified.caSHA256)
  let context, transport, page, browserSend, pageSend, launcherChild, childResult, closed = false, networkPublished = false
  const journal = new MatrixJournal()
  try {
    checkpoint('LAUNCH')
    const args = ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--disable-background-networking',
      '--disable-component-update', '--disable-sync', '--disable-default-apps', '--disable-extensions', '--no-first-run',
      '--no-default-browser-check', '--disable-features=MediaRouter,OptimizationHints', '--password-store=basic']
    if (o.engine === 'chrome-cdp') {
      launcherChild = spawn(o.launcher, [...args, '--headless=new', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--user-data-dir=' + o.profile, 'about:blank'],
        { stdio: ['ignore', 'ignore', 'ignore'], env: environment })
      childResult = new Promise(resolve => {
        launcherChild.once('error', () => resolve({ code: null, signal: null }))
        launcherChild.once('exit', (code, signal) => resolve({ code, signal }))
      })
      let port
      await until(async () => {
        need(launcherChild.exitCode === null && launcherChild.signalCode === null)
        try {
          const text = await readFile(o.profile + '/DevToolsActivePort', 'utf8'); need(text.length <= 1024)
          const lines = text.trim().split('\n'); need(lines.length === 2 && /^[1-9][0-9]{0,4}$/.test(lines[0]) && Number(lines[0]) <= 65535 && /^\/devtools\/browser\/[a-f0-9-]{1,80}$/.test(lines[1]))
          port = lines; return true
        } catch (error) { if (error?.code === 'ENOENT') return false; throw error }
      }, 20000)
      const socket = new WebSocket('ws://127.0.0.1:' + port[0] + port[1])
      await new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(Error('stream matrix rejected')), 10000)
        socket.addEventListener('open', () => { clearTimeout(t); resolve() }, { once: true })
        socket.addEventListener('error', () => { clearTimeout(t); reject(Error('stream matrix rejected')) }, { once: true })
      })
      transport = new Transport(socket); browserSend = (method, params) => transport.send(method, params)
      const target = await browserSend('Target.createTarget', { url: 'about:blank' })
      const sessionId = (await browserSend('Target.attachToTarget', { targetId: target.targetId, flatten: true })).sessionId
      pageSend = (method, params) => transport.send(method, params, sessionId)
      transport.listeners.push(m => { if (m.sessionId === sessionId) journal.handle(m.method, m.params ?? {}) })
      const known = new Set((await browserSend('Target.getTargets')).targetInfos.map(t => t.targetId))
      transport.listeners.push(m => {
        if (m.method === 'Target.targetCreated' && ['page', 'service_worker', 'shared_worker'].includes(m.params?.targetInfo?.type)
          && !known.has(m.params.targetInfo.targetId)) { journal.failure = true; journal.counters.forbiddenRequests++ }
      })
      await browserSend('Target.setDiscoverTargets', { discover: true })
    } else {
      const packageFile = o.bundle + '/source/chengwang/tools/browser-stream-matrix/node_modules/playwright-core/'
      need(JSON.parse((await stableFile(packageFile + 'package.json', 65536)).toString()).version === '1.65.0-alpha-2026-10-23')
      const module = await import(pathToFileURL(packageFile + 'index.mjs').href)
      context = await module.chromium.launchPersistentContext(o.profile, { executablePath: o.launcher, headless: true,
        chromiumSandbox: false, ignoreHTTPSErrors: false, bypassCSP: false, args, env: environment, timeout: 20000 })
      page = context.pages()[0]; need(page && context.pages().length === 1)
      const pageSession = await context.newCDPSession(page), browserSession = await context.browser().newBrowserCDPSession()
      pageSend = (method, params) => pageSession.send(method, params); browserSend = (method, params) => browserSession.send(method, params)
      for (const event of ['Network.requestWillBeSent', 'Network.responseReceived', 'Network.loadingFinished', 'Network.loadingFailed',
        'Runtime.exceptionThrown', 'Runtime.consoleAPICalled', 'Log.entryAdded']) pageSession.on(event, p => journal.handle(event, p))
      context.on('page', p => { if (p !== page) { journal.failure = true; journal.counters.forbiddenRequests++ } })
      context.on('serviceworker', () => { journal.failure = true; journal.counters.forbiddenRequests++ })
    }
    checkpoint('IDENTITY')
    const browser = versionProjection(await browserSend('Browser.getVersion')), chrome = await chromeIdentity(o, browserSend)
    need(chrome.exeSHA256 === config.chromeSHA256)
    await Promise.all(['Runtime.enable', 'Page.enable', 'Log.enable'].map(method => pageSend(method)))
    await pageSend('Network.enable', { maxTotalBufferSize: 4 << 20, maxResourceBufferSize: 2 << 20 })
    const evaluate = async expression => {
      const result = await pageSend('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
      need(result && !result.exceptionDetails && result.result && Object.hasOwn(result.result, 'value'))
      return result.result.value
    }
    await publishReady(o.root + '/driver-ready.private.json', { schema: 'chengwang.stream-matrix-driver-ready/v1', fixtureId: o.fixtureId,
      engine: o.engine, pid: process.pid, chromePid: chrome.pid })
    checkpoint('SUPERVISOR_GATE')
    await until(async () => {
      try {
        const raw = await stableFile(o.root + '/run.go', 4096), s = await lstat(o.root + '/run.go')
        need((s.mode & 0o7777) === 0o444)
        const run = JSON.parse(raw.toString())
        need(exact(run, ['schema', 'fixtureId', 'engine']) && run.schema === 'chengwang.stream-matrix-run/v1' && run.fixtureId === o.fixtureId && run.engine === o.engine)
        return true
      } catch (error) { if (error?.code === 'ENOENT') return false; throw error }
    }, 20000)
    checkpoint('NAVIGATE')
    if (page) await page.goto(ORIGIN + '/', { waitUntil: 'load', timeout: 10000 })
    else {
      const r = await pageSend('Page.navigate', { url: ORIGIN + '/' }); need(!r.errorText)
      await until(async () => await evaluate('location.href===' + JSON.stringify(ORIGIN + '/') + '&&document.readyState==="complete"') === true)
    }
    await until(() => Boolean(journal.byCase.get('DOCUMENT')?.terminal))
    need(journal.byCase.get('DOCUMENT').terminal.event === 'FINISH')
    const certificates = await pageSend('Network.getCertificate', { origin: ORIGIN }), certificateChain = certificates.tableNames
    const tls = helper.browserTLSProof(journal.byCase.get('DOCUMENT').response, certificateChain, verified)
    const cases = []
    for (const id of CASES) {
      checkpoint(id === 'split-success' ? 'SPLIT' : id === 'boundary-success' ? 'BOUNDARY' : id === 'oversize' ? 'OVERSIZE' : id === 'truncated' ? 'TRUNCATED' : 'ABORT')
      const js = page ? await page.evaluate(readInPage, id)
        : await evaluate('(' + readInPage.toString() + ')(' + JSON.stringify(id) + ')')
      await until(() => Boolean(journal.byCase.get(id)?.terminal))
      const item = journal.byCase.get(id); let hostBody = null
      if (id.endsWith('-success')) {
        try {
          const raw = responseBody(await pageSend('Network.getResponseBody', { requestId: item.requestId }))
          hostBody = { bytes: raw.length, sha256: sha(raw) }
        } catch {
          // Retain the failed candidate and continue the fixed no-retry matrix;
          // this counter and the null positive hostBody both reject acceptance.
          journal.counters.captureErrors++
        }
      }
      cases.push({ case: id, js, networkOrdinal: item.ordinal, requestId: item.requestId, terminal: item.terminal, hostBody })
    }
    checkpoint('CLOSE')
    if (context) await context.close(); else await browserSend('Browser.close')
    let chromeExit
    await until(async () => {
      try { chromeExit = JSON.parse((await stableFile(o.root + '/chrome-exit.private.json', 4096, true)).toString()); return true }
      catch (error) { if (error?.code === 'ENOENT') return false; throw error }
    }, 20000)
    need(exact(chromeExit, ['schema', 'engine', 'fixtureId', 'pid', 'startTicks', 'exitCode', 'joined', 'forced'])
      && chromeExit.schema === 'chengwang.stream-matrix-chrome-exit/v1' && chromeExit.engine === o.engine && chromeExit.fixtureId === o.fixtureId
      && chromeExit.pid === chrome.pid && chromeExit.startTicks === chrome.startTicks && chromeExit.exitCode === 0 && chromeExit.joined === true && chromeExit.forced === false)
    let launcherExit = null
    if (childResult) { launcherExit = await Promise.race([childResult, delay(2000).then(() => null)]); need(launcherExit?.code === 0 && launcherExit.signal === null) }
    await until(() => noLiveChrome(o, chrome), 5000); closed = true; transport?.socket.close()
    const network = journal.rows.map(row => JSON.stringify(row)).join('\n') + '\n'
    const networkFile = await publish(o.root + '/network.private.jsonl', network, 65536)
    networkPublished = true
    const report = { schema: 'chengwang.stream-matrix-driver/v1', sourceCommit: o.sourceCommit, engine: o.engine,
      fixtureId: o.fixtureId, origin: ORIGIN, runtime: true, mockedResponses: false, injectedFetch: false, tlsBypass: false,
      limits: { bodyBytes: BODY_LIMIT, cases: 5, requests: 6 }, browser, chrome,
      normalTrust: { method: 'PRIVATE_NSS_SQL_XDG_LOCAL_CA', trustFlags: 'C,,', caSHA256: verified.caSHA256,
        leafSHA256: verified.leafSHA256, homeEnvironmentAbsent: true, legacyDatabaseAbsent: true },
      tls, certificateChain, cases, counters: journal.counters,
      close: { normalCloseCommandCompleted: true, chromeExit, launcherExit, noLiveOwnedProcesses: true,
        processScope: 'CHROME_SESSION_AND_LAUNCHER_ONLY' },
      networkFile: { path: 'network.private.jsonl', ...networkFile, records: journal.rows.length }, production: false }
    // Preserve actual closed observations before evaluating case expectations.
    // A failed candidate remains evidence, never an accepted matrix.
    await publish(o.root + '/matrix-driver.private.json', report, 65536)
    journal.complete(); cases.forEach(validateCase)
    checkpoint('COMPLETE')
    return report
  } finally {
    if (!closed) {
      // Best-effort graceful close is not a normal-wait claim. The supervisor
      // owns mandatory bounded cleanup and records any forced intervention.
      try { if (context) await context.close(); else if (browserSend) await browserSend('Browser.close') } catch { /* Fixed CLI error only. */ }
      transport?.socket.close()
    }
    if (!networkPublished && journal.rows.length) {
      try { await publish(o.root + '/network.private.jsonl', journal.rows.map(row => JSON.stringify(row)).join('\n') + '\n', 65536) }
      catch { /* Existing original evidence is never overwritten on failure. */ }
    }
  }
}
