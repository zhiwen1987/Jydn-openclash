// CI-only adapters. Importing this file performs no I/O or browser launch.
import { spawn, execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat, mkdir, open, readFile, readdir } from 'node:fs/promises'
import { homedir } from 'node:os'
import { posix } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { promisify } from 'node:util'
import { pathToFileURL } from 'node:url'
import { parseProbePublicJSON } from './probe-browser-contract.mjs'

const execute = promisify(execFile)
const { dirname, isAbsolute, join, normalize } = posix
const ORIGIN = 'https://127.0.0.1:17861'
const PROBES = new Set(['/api/v1/probes/status', '/api/v1/probes/details'])
const API = new Set(['/api/v1/snapshot', '/api/v1/observations/status', ...PROBES])
const sha = raw => createHash('sha256').update(raw).digest('hex')
const reject = () => { throw new Error('probe browser driver rejected') }
const need = value => { if (!value) reject() }
const copy = value => structuredClone(value)
const unixNow = () => (BigInt(Date.now()) * 1000000n).toString()
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',')
const pathOK = value => typeof value === 'string' && value.length < 4096 && isAbsolute(value)
  && normalize(value) === value && !/[\x00-\x1f\x7f\\]/.test(value)
const sameStat = (a, b) => ['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'nlink', 'mtimeNs', 'ctimeNs'].every(k => a[k] === b[k])

// Diagnostic hints only: a matching marker is not proof of a root cause.
// Never coerce error objects or invoke message/code accessors.
export function classifyLaunchError(value) {
  try {
    let message = '', code = ''
    if (Buffer.isBuffer(value)) {
      if (value.length > 65536) return 'UNKNOWN'
      message = value.toString('utf8')
    } else if (typeof value === 'string') message = value
    else if (value && typeof value === 'object') {
      message = Object.getOwnPropertyDescriptor(value, 'message')?.value ?? ''
      code = Object.getOwnPropertyDescriptor(value, 'code')?.value ?? ''
    }
    if (typeof message !== 'string' || message.length > 65536 || Buffer.byteLength(message) > 65536
      || typeof code !== 'string' || code.length > 64) return 'UNKNOWN'
    if (['EACCES', 'EPERM'].includes(code) || /\b(?:EACCES|EPERM)\b|permission denied/i.test(message)) return 'PERMISSION'
    if (['MODULE_NOT_FOUND', 'ERR_MODULE_NOT_FOUND'].includes(code)
      || /\b(?:MODULE_NOT_FOUND|ERR_MODULE_NOT_FOUND)\b|cannot find (?:module|package)/i.test(message)) return 'MODULE_NOT_FOUND'
    if (/Fatal Python error:|error evaluating path|failed to get the Python codec of the filesystem encoding/i.test(message)) return 'PYTHON_STARTUP'
    if (/error while loading shared libraries:|cannot open shared object file/i.test(message)) return 'SHARED_LIBRARY'
    if (/(?:^|\n)PROBE_CHROME_LAUNCHER=FAIL raw_input_suppressed=true(?:\r?\n|$)/.test(message)) return 'LAUNCHER_REJECTED'
  } catch { /* Unknown objects, including throwing proxies, stay private. */ }
  return 'UNKNOWN'
}

export function launchFatalLocations(value) {
  try {
    const message = Buffer.isBuffer(value) ? (value.length <= 65536 ? value.toString('utf8') : null)
      : typeof value === 'string' ? value
        : value && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, 'message')?.value : null
    if (typeof message !== 'string' || message.length > 65536 || Buffer.byteLength(message) > 65536) return []
    const locations = new Set()
    // Chromium's two source-location forms only, not arbitrary paths or text.
    const pattern = /FATAL:((?:base|chrome|content|components|sandbox|third_party)\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+\.cc)(?::([1-9][0-9]{0,5})\]|\(([1-9][0-9]{0,5})\)\])/g
    for (const match of message.matchAll(pattern)) {
      locations.add(`${match[1]}:${match[2] ?? match[3]}`)
      if (locations.size === 4) break
    }
    return [...locations]
  } catch { return [] }
}

export function validateLaunchOptions(value) {
  need(exact(value, ['engine', 'root', 'chrome', 'sourceRoot', 'launcher']))
  need(['chrome-cdp', 'playwright'].includes(value.engine))
  need(typeof value.root === 'string' && /^\/tmp\/chengwang-probe-readback-[a-f0-9]{32}$/.test(value.root))
  const fixtureId = value.root.slice(-32)
  need(value.sourceRoot === `/tmp/chengwang-probe-harness-${fixtureId}/source`)
  need(value.launcher === `/tmp/chengwang-probe-harness-${fixtureId}/chrome-launcher`)
  need(pathOK(value.chrome) && value.chrome !== '/' && !value.chrome.startsWith(value.root + '/'))
  return { ...value, fixtureId, browserRoot: join(value.root, 'browser'), profile: join(value.root, 'browser/chrome-profile') }
}

export function parseChromeStat(raw) {
  need(typeof raw === 'string' && raw.length <= 8192)
  const end = raw.lastIndexOf(')'), pid = Number(raw.slice(0, raw.indexOf(' ')))
  const fields = raw.slice(end + 2).trim().split(/\s+/)
  need(end > 0 && fields.length >= 20 && Number.isSafeInteger(pid) && pid > 1)
  const [group, session, ticks] = [fields[2], fields[3], fields[19]].map(Number)
  need([group, session, ticks].every(n => Number.isSafeInteger(n) && n > 0))
  return { pid, group, session, startTicks: ticks, state: fields[0] }
}

export function safeRequest(request, type = 'Other') {
  need(request && typeof request.url === 'string' && request.url.length <= 256)
  let url
  try { url = new URL(request.url) } catch { reject() }
  need(url.href === request.url && url.origin === ORIGIN && !url.search && !url.hash && !url.username && !url.password)
  need(request.method === 'GET' && (url.pathname === '/' || API.has(url.pathname)
    || /^\/assets\/[A-Za-z0-9_-]{1,100}\.[A-Za-z0-9]{1,8}$/.test(url.pathname)))
  const names = Object.keys(request.headers ?? {}).map(name => name.toLowerCase())
  const authorizationPresent = names.includes('authorization')
  need(!names.some(name => ['cookie', 'proxy-authorization', 'proxy-connection'].includes(name)))
  need(authorizationPresent === (url.pathname === '/api/v1/probes/details'))
  const resourceType = ({ Document: 'document', Script: 'script', Stylesheet: 'stylesheet', Font: 'font',
    Image: 'image', Fetch: 'fetch', XHR: 'xhr', Other: 'other', Manifest: 'other' })[type]
  need(resourceType)
  return { url: url.href, method: 'GET', authorizationPresent, resourceType }
}

export function responseBytes(result, limit) {
  need(result && typeof result.body === 'string' && typeof result.base64Encoded === 'boolean')
  need(Number.isSafeInteger(limit) && limit > 0 && limit <= 16 << 20)
  need(result.body.length <= Math.ceil(limit * 4 / 3) + 4)
  const raw = Buffer.from(result.body, result.base64Encoded ? 'base64' : 'utf8')
  need(raw.length <= limit && (!result.base64Encoded || raw.toString('base64') === result.body))
  return raw
}

export function remoteEvaluationValue(result) {
  need(result && !result.exceptionDetails && result.result)
  const remote = result.result
  need(!Object.hasOwn(remote, 'subtype')
    || remote.type === 'object' && remote.subtype === 'null' && remote.value === null)
  return remote.value
}

async function privateDirectory(path, create = false) {
  if (create) await mkdir(path, { mode: 0o700 })
  const info = await lstat(path)
  need(info.isDirectory() && !info.isSymbolicLink() && info.uid === 10001 && info.gid === 10001 && (info.mode & 0o7777) === 0o700)
}

async function stableFile(path, limit, { privateInput = false, rootOwned = false } = {}) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | (constants.O_CLOEXEC ?? 0))
  try {
    const before = await handle.stat({ bigint: true })
    need(before.isFile() && before.nlink === 1n && before.size > 0n && before.size <= BigInt(limit))
    if (privateInput) need(before.uid === 10001n && before.gid === 10001n && (before.mode & 0o7777n) === 0o600n)
    if (rootOwned) need(before.uid === 0n && (before.mode & 0o022n) === 0n)
    const raw = await handle.readFile()
    const after = await handle.stat({ bigint: true }), named = await lstat(path, { bigint: true })
    need(BigInt(raw.length) === before.size && sameStat(before, after) && sameStat(before, named))
    return raw
  } finally { await handle.close() }
}

async function until(test, timeout = 10000) {
  const end = Date.now() + timeout
  while (Date.now() < end) {
    if (await test()) return
    await delay(25)
  }
  reject()
}

async function processRecord(path) { return parseProbePublicJSON(await stableFile(path, 4096, { privateInput: true })) }

async function actualChrome(options, sendBrowser) {
  const [info, record] = await Promise.all([sendBrowser('SystemInfo.getProcessInfo'), processRecord(join(options.browserRoot, 'chrome-process.private.json'))])
  need(exact(record, ['pid', 'startTicks', 'uid', 'profile']) && record.uid === 10001 && record.profile === options.profile)
  need(Number.isSafeInteger(record.pid) && record.pid > 1 && Number.isSafeInteger(record.startTicks) && record.startTicks > 0)
  need(Array.isArray(info.processInfo) && info.processInfo.length > 0 && info.processInfo.length <= 1024)
  const browsers = info.processInfo.filter(item => item.type === 'browser')
  need(browsers.length === 1 && browsers[0].id === record.pid)
  const first = parseChromeStat(await readFile(`/proc/${record.pid}/stat`, 'utf8'))
  const argv = await readFile(`/proc/${record.pid}/cmdline`)
  const args = argv.toString('utf8').split('\0')
  need(first.pid === record.pid && first.group === record.pid && first.session === record.pid && first.startTicks === record.startTicks)
  need(args.includes(`--user-data-dir=${options.profile}`) && !args.some(arg => /^(?:--ignore-certificate-errors|--allow-insecure-localhost|--ignore-certificate-errors-spki-list)(?:=|$)/.test(arg)))
  const second = parseChromeStat(await readFile(`/proc/${record.pid}/stat`, 'utf8'))
  need(first.startTicks === second.startTicks)
  return { ...record, argvSHA256: sha(argv) }
}

async function liveOwnedChrome(options, record) {
  const names = await readdir('/proc')
  need(names.filter(name => /^[0-9]+$/.test(name)).length <= 32768)
  const profile = options.profile
  for (const name of names.filter(name => /^[0-9]+$/.test(name))) {
    try {
      if ((await lstat(`/proc/${name}`)).uid !== 10001) continue
      const stat = parseChromeStat(await readFile(`/proc/${name}/stat`, 'utf8'))
      if (['Z', 'X'].includes(stat.state)) continue
      const rawargv = await readFile(`/proc/${name}/cmdline`)
      need(rawargv.length <= 262144)
      const argv = rawargv.toString('utf8').split('\0')
      const bound = argv.includes(`--user-data-dir=${profile}`) || argv.some((arg, index) => arg === '--user-data-dir' && argv[index + 1] === profile)
        || argv.some((arg, index) => {
          const candidate = /^--(?:database|metrics-dir)=/.test(arg) ? arg.slice(arg.indexOf('=') + 1)
            : ['--database', '--metrics-dir'].includes(arg) ? argv[index + 1] : null
          return typeof candidate === 'string' && pathOK(candidate) && candidate.startsWith(profile + '/')
        })
      if (stat.group === record.pid || bound) return true
    } catch (error) {
      if (error?.code !== 'ENOENT' && error?.code !== 'ESRCH') throw error
    }
  }
  return false
}

class CDP {
  constructor(socket) {
    this.socket = socket; this.next = 0; this.pending = new Map(); this.listeners = []; this.closed = false
    socket.addEventListener('message', event => {
      try {
        need(typeof event.data === 'string' && event.data.length <= 32 << 20)
        const message = JSON.parse(event.data)
        if (message.id) {
          const task = this.pending.get(message.id)
          if (!task) return
          this.pending.delete(message.id); clearTimeout(task.timer)
          if (message.error) task.reject(new Error('probe browser driver rejected'))
          else task.resolve(message.result)
        } else for (const listener of this.listeners) listener(message)
      } catch { this.abort() }
    })
    socket.addEventListener('close', () => this.abort())
    socket.addEventListener('error', () => this.abort())
  }
  abort() {
    this.closed = true
    for (const task of this.pending.values()) { clearTimeout(task.timer); task.reject(new Error('probe browser driver rejected')) }
    this.pending.clear()
  }
  send(method, params = {}, sessionId) {
    need(!this.closed && this.pending.size < 128)
    const id = ++this.next
    return new Promise((resolve, rejectResult) => {
      const timer = setTimeout(() => { this.pending.delete(id); rejectResult(new Error('probe browser driver rejected')) }, 10000)
      this.pending.set(id, { resolve, reject: rejectResult, timer })
      this.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }))
    })
  }
}

// Extract only rendered probe fields. No HTML, token value, storage value,
// cookie contents, React internals, or fabricated state is returned.
export function collectProbeDOM() {
  const visible = element => element && element.getClientRects().length > 0
    && getComputedStyle(element).visibility !== 'hidden' && getComputedStyle(element).display !== 'none'
  const panel = document.querySelector('.probe-readback'), input = panel?.querySelector('#probe-token')
  const detail = panel?.querySelector('.probe-detail')
  const layerNames = { DNS: 'dns', 连接: 'connect', TLS: 'tls', HTTP: 'http', 业务: 'business' }
  const targets = [...(panel?.querySelectorAll('.probe-targets > li') ?? [])].map(li => {
    const disclosure = li.querySelector('details'), summary = disclosure?.querySelector('summary')
    const sampleCode = disclosure?.querySelector(':scope > p.probe-caption code')
    const sampleVisible = disclosure?.open && visible(sampleCode)
    const layers = {}
    if (sampleVisible) for (const row of disclosure.querySelectorAll('.probe-layers > div')) {
      const key = layerNames[row.querySelector('dt')?.textContent.trim()]
      if (key && visible(row)) layers[key] = row.querySelector('dd')?.textContent.trim() ?? ''
    }
    return { probeId: summary?.querySelector('strong')?.textContent.trim() ?? '',
      pathId: (summary?.querySelector('small')?.textContent.trim() ?? '').replace(/^路径\s+/, ''),
      stateLabel: summary?.querySelector('.probe-badge')?.textContent.trim() ?? '',
      runId: sampleVisible ? sampleCode.textContent.trim() : '',
      httpStatus: sampleVisible ? Number(/HTTP\s+(\d{3})/.exec(sampleCode.parentElement.textContent)?.[1] ?? 0) : 0, layers }
  })
  let storageEmpty = false, cookiesEmpty = false
  try { storageEmpty = localStorage.length === 0 && sessionStorage.length === 0; cookiesEmpty = document.cookie === '' } catch { /* A false result fails the public contract. */ }
  return { url: location.href, title: document.title, heading: document.querySelector('.main-content h1')?.textContent.trim() ?? '',
    viewport: { width: innerWidth, height: innerHeight }, scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth, inputType: input?.type ?? '', tokenEmpty: input?.value === '',
    storageEmpty, cookiesEmpty, detailMounted: Boolean(visible(detail)),
    catalogText: visible(detail) ? detail.querySelector(':scope > p.probe-caption code')?.textContent.trim() ?? '' : '',
    targets, overlayCount: [...document.querySelectorAll('[role="dialog"],[aria-modal="true"],.modal-backdrop,.drawer-backdrop')].filter(visible).length }
}

export class NetworkJournal {
  constructor(send, proveTLS) {
    this.send = send; this.proveTLS = proveTLS; this.active = new Map(); this.tasks = new Set()
    this.network = []; this.probe = []; this.ordinal = 0; this.totalBytes = 0; this.failure = false
    this.counters = { runtimeErrors: 0, consoleErrors: 0, consoleWarnings: 0, cspErrors: 0,
      assetErrors: 0, forbiddenRequests: 0, failedRequests: 0, captureErrors: 0 }
  }
  handle(method, p) {
    try {
      if (method === 'Runtime.exceptionThrown') this.counters.runtimeErrors++
      if (method === 'Runtime.consoleAPICalled' && p.type === 'error') this.counters.consoleErrors++
      if (method === 'Runtime.consoleAPICalled' && p.type === 'warning') this.counters.consoleWarnings++
      if (method === 'Log.entryAdded' && p.entry?.source === 'security' && p.entry?.level === 'error') this.counters.cspErrors++
      if (method === 'Network.requestWillBeSent') {
        need(!p.redirectResponse && !this.active.has(p.requestId) && this.active.size < 128)
        // A data favicon is not a network request. It is never exported as an
        // HTTP observation and cannot satisfy any product API requirement.
        if (p.request?.url?.startsWith('data:image/svg+xml,')) return
        let request
        try { request = safeRequest(p.request, p.type) } catch { this.counters.forbiddenRequests++; reject() }
        this.active.set(p.requestId, { ...request, response: null, mime: '' })
      }
      if (method === 'Network.responseReceived') {
        const request = this.active.get(p.requestId)
        if (!request) return
        need(p.response.url === request.url && Number.isInteger(p.response.status) && p.response.status >= 100 && p.response.status <= 599)
        request.response = { status: p.response.status, securityState: p.response.securityState,
          securityDetails: p.response.securityDetails }
        request.mime = p.response.mimeType
      }
      if (method === 'Network.loadingFailed') {
        if (this.active.has(p.requestId)) {
          const item = this.active.get(p.requestId); this.active.delete(p.requestId)
          this.counters.failedRequests++
          if (!API.has(new URL(item.url).pathname)) this.counters.assetErrors++
        }
      }
      if (method === 'Network.loadingFinished' && this.active.has(p.requestId)) {
        const item = this.active.get(p.requestId); this.active.delete(p.requestId)
        const task = this.complete(p.requestId, item).catch(() => { this.failure = true; this.counters.captureErrors++ })
        this.tasks.add(task); task.finally(() => this.tasks.delete(task))
      }
    } catch { this.failure = true }
  }
  async complete(id, item) {
    need(item.response && this.network.length < 128)
    const path = new URL(item.url).pathname, isProbe = PROBES.has(path)
    if (API.has(path)) need(item.mime === 'application/json')
    const body = responseBytes(await this.send('Network.getResponseBody', { requestId: id }), API.has(path) ? 1 << 20 : 16 << 20)
    this.totalBytes += body.length; need(this.totalBytes <= 32 << 20)
    need(this.ordinal < 128)
    const row = { ordinal: ++this.ordinal, url: item.url, method: item.method, status: item.response.status,
      authorizationPresent: item.authorizationPresent, resourceType: item.resourceType, bodyBytes: body.length,
      bodySHA256: sha(body), receivedUnixNano: unixNow() }
    if (path === '/') await this.proveTLS(item.response)
    if (item.response.status !== 200 && !(path === '/api/v1/probes/details' && [401, 403].includes(item.response.status))) this.counters.assetErrors++
    this.network.push(row)
    if (isProbe) this.probe.push({ ...row, ordinal: this.probe.length + 1, body })
  }
  async flush() { await Promise.all([...this.tasks]); need(!this.failure) }
  since(cursor) {
    need(Number.isSafeInteger(cursor) && cursor >= 0 && cursor <= this.probe.length)
    return { cursor: this.probe.length, responses: this.probe.filter(r => r.ordinal > cursor).map(r => ({ ...r, body: Uint8Array.from(r.body) })) }
  }
  evidence() { need(!this.failure); return { network: copy(this.network).sort((a, b) => a.ordinal - b.ordinal), ...this.counters } }
}

async function launchImplementation(input) {
  const options = validateLaunchOptions(input)
  // Closed checkpoints mean entry into a factory step, never its completion.
  const checkpoint = stage => process.stderr.write(`PROBE_BROWSER_DRIVER_STAGE=${stage}\n`)
  checkpoint('ENVIRONMENT')
  need(process.platform === 'linux' && process.getuid?.() === 10001 && process.getgid?.() === 10001
    && !Object.hasOwn(process.env, 'HOME') && process.env.TMPDIR === '/var/tmp' && typeof WebSocket === 'function')
  checkpoint('HOME')
  const home = join(options.browserRoot, 'home')
  need(homedir() === home)
  checkpoint('DIRECTORIES')
  await privateDirectory('/var/tmp')
  await privateDirectory(options.root); await privateDirectory(options.browserRoot)
  await privateDirectory(home, true); await privateDirectory(options.profile, true)
  const data = join(home, '.local/share'), database = join(data, 'pki/nssdb')
  await mkdir(database, { mode: 0o700, recursive: true })
  try { await lstat(join(home, '.pki/nssdb')); reject() } catch (error) { if (error?.code !== 'ENOENT') throw new Error('probe browser driver rejected') }
  for (const name of ['config', 'cache', 'tmp']) await privateDirectory(join(options.profile, name), true)
  checkpoint('CONFIG')
  await stableFile(options.launcher, 65536, { rootOwned: true })
  const config = parseProbePublicJSON(await stableFile(join(dirname(options.launcher), 'browser-config.json'), 4096, { rootOwned: true }))
  need(exact(config, ['schema', 'engine', 'root', 'chrome']) && config.schema === 'chengwang.probe-browser-config/v1'
    && config.engine === options.engine && config.root === options.root && config.chrome === options.chrome)
  checkpoint('CERTIFICATES')
  const helper = await import(pathToFileURL(join(options.sourceRoot, 'chengwang/web/scripts/trust-browser-tls.mjs')).href)
  const [ca, leaf] = await Promise.all(['api-ca.pem', 'api-cert.pem'].map(name => stableFile(join(options.root, name), 65536, { privateInput: true })))
  const verified = helper.inspectPublicTLS(ca.toString('utf8'), leaf.toString('utf8'))
  const environment = { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
    XDG_DATA_HOME: data, XDG_CONFIG_HOME: join(options.profile, 'config'),
    XDG_CACHE_HOME: join(options.profile, 'cache'), TMPDIR: '/var/tmp' }
  checkpoint('NSS_INIT')
  await stableFile('/usr/bin/certutil', 16 << 20, { rootOwned: true })
  const certutil = args => execute('/usr/bin/certutil', args, { env: environment, timeout: 10000, maxBuffer: 65536, encoding: 'utf8' })
  try {
    await certutil(['-N', '-d', `sql:${database}`, '--empty-password'])
    checkpoint('NSS_IMPORT')
    await certutil(['-A', '-d', `sql:${database}`, '-n', 'chengwang-probe-browser-api-ca', '-t', 'C,,', '-i', join(options.root, 'api-ca.pem')])
    checkpoint('NSS_READBACK')
    const imported = (await certutil(['-L', '-d', `sql:${database}`, '-n', 'chengwang-probe-browser-api-ca', '-a'])).stdout
    need(helper.inspectPublicTLS(imported, leaf.toString('utf8')).caSHA256 === verified.caSHA256)
  } catch { reject() }

  let transport, context, page, launcherChild, childResult, pageSend, browserSend, record, closeEvidence = null
  let proof = null, chain = [], product = '', journal, screenshotCount = 0, closed = false
  let launchStderr = Buffer.alloc(0), launchStderrOverflow = false, launchDiagnosticPrinted = false, spawnError
  const launchDiagnostic = error => {
    if (launchDiagnosticPrinted) return
    launchDiagnosticPrinted = true
    const stderrKind = launchStderrOverflow ? 'UNKNOWN' : classifyLaunchError(launchStderr)
    const kind = stderrKind === 'UNKNOWN' ? classifyLaunchError(error) : stderrKind
    process.stderr.write(`PROBE_BROWSER_LAUNCH_ERROR=${kind}\n`)
    const locations = new Set([...(launchStderrOverflow ? [] : launchFatalLocations(launchStderr)), ...launchFatalLocations(error)])
    for (const location of [...locations].slice(0, 4)) process.stderr.write(`PROBE_BROWSER_LAUNCH_FATAL=${location}\n`)
  }
  const secrets = new Set()
  try {
    checkpoint('LAUNCH')
    const args = ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--disable-background-networking',
      '--disable-component-update', '--disable-sync', '--disable-default-apps', '--disable-extensions', '--no-first-run',
      '--no-default-browser-check', '--disable-features=MediaRouter,OptimizationHints', '--password-store=basic']
    if (options.engine === 'chrome-cdp') {
      launcherChild = spawn(options.launcher, [...args, '--headless=new', '--remote-debugging-address=127.0.0.1',
        '--remote-debugging-port=0', `--user-data-dir=${options.profile}`, 'about:blank'],
      { stdio: ['ignore', 'ignore', 'pipe'], env: environment })
      launcherChild.stderr.on('data', chunk => {
        if (launchStderrOverflow) return
        if (!Buffer.isBuffer(chunk) || chunk.length > 65536 - launchStderr.length) {
          launchStderr = Buffer.alloc(0); launchStderrOverflow = true; return
        }
        launchStderr = Buffer.concat([launchStderr, chunk])
      })
      childResult = new Promise(resolve => {
        launcherChild.once('error', error => { spawnError = error; launchDiagnostic(error); resolve({ code: null, signal: null }) })
        launcherChild.once('exit', (code, signal) => { if (code !== 0) launchDiagnostic(); resolve({ code, signal }) })
      })
      let active
      await until(async () => {
        need(launcherChild.exitCode === null && launcherChild.signalCode === null)
        try { active = (await stableFile(join(options.profile, 'DevToolsActivePort'), 1024)).toString('utf8').trim().split('\n'); return active.length === 2 && /^[1-9][0-9]{0,4}$/.test(active[0]) && Number(active[0]) <= 65535 && /^\/devtools\/browser\/[a-f0-9-]+$/.test(active[1]) } catch (error) { if (error?.code === 'ENOENT') return false; throw error }
      }, 20000)
      const socket = new WebSocket(`ws://127.0.0.1:${active[0]}${active[1]}`)
      await new Promise((resolve, failed) => {
        const timer = setTimeout(() => failed(new Error('probe browser driver rejected')), 10000)
        socket.addEventListener('open', () => { clearTimeout(timer); resolve() }, { once: true })
        socket.addEventListener('error', () => { clearTimeout(timer); failed(new Error('probe browser driver rejected')) }, { once: true })
      })
      transport = new CDP(socket); browserSend = (method, params = {}) => transport.send(method, params)
      const target = await browserSend('Target.createTarget', { url: 'about:blank' })
      const session = (await browserSend('Target.attachToTarget', { targetId: target.targetId, flatten: true })).sessionId
      pageSend = (method, params = {}) => transport.send(method, params, session)
      transport.listeners.push(message => { if (message.sessionId === session) journal?.handle(message.method, message.params ?? {}) })
    } else {
      const module = await import(pathToFileURL(join(options.sourceRoot, 'chengwang/tools/probe-browser/node_modules/playwright-core/index.mjs')).href)
      need(typeof module.chromium?.launchPersistentContext === 'function')
      try {
        context = await module.chromium.launchPersistentContext(options.profile, { executablePath: options.launcher,
          headless: true, chromiumSandbox: false, ignoreHTTPSErrors: false, bypassCSP: false,
          args, env: environment, timeout: 20000, viewport: { width: 1440, height: 1000 } })
      } catch (error) { launchDiagnostic(error); throw error }
      page = context.pages()[0]; need(page && context.pages().length === 1)
      const session = await context.newCDPSession(page), browserSession = await context.browser().newBrowserCDPSession()
      pageSend = (method, params = {}) => session.send(method, params)
      browserSend = (method, params = {}) => browserSession.send(method, params)
      for (const method of ['Network.requestWillBeSent', 'Network.responseReceived', 'Network.loadingFinished', 'Network.loadingFailed',
        'Runtime.exceptionThrown', 'Runtime.consoleAPICalled', 'Log.entryAdded']) session.on(method, params => journal?.handle(method, params))
    }
    checkpoint('IDENTITY')
    const version = await browserSend('Browser.getVersion')
    need(typeof version.product === 'string' && /^(?:Chrome|HeadlessChrome)\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(version.product))
    product = version.product; record = await actualChrome(options, browserSend)
    journal = new NetworkJournal(pageSend, async response => {
      const certificates = await pageSend('Network.getCertificate', { origin: ORIGIN })
      proof = helper.browserTLSProof(response, certificates.tableNames, verified)
      chain = [...certificates.tableNames]
    })
    const unexpectedTarget = () => { journal.failure = true; journal.counters.forbiddenRequests++ }
    if (context) {
      context.on('page', opened => { if (opened !== page) unexpectedTarget() })
      context.on('serviceworker', unexpectedTarget)
    } else {
      const known = new Set((await browserSend('Target.getTargets')).targetInfos.map(item => item.targetId))
      transport.listeners.push(message => {
        if (message.method === 'Target.targetCreated' && ['page', 'service_worker', 'shared_worker'].includes(message.params?.targetInfo?.type)
          && !known.has(message.params.targetInfo.targetId)) unexpectedTarget()
      })
      await browserSend('Target.setDiscoverTargets', { discover: true })
    }
    checkpoint('READY')
    await Promise.all(['Runtime.enable', 'Page.enable', 'Network.enable', 'Log.enable'].map(method => pageSend(method)))
    await pageSend('Network.setCacheDisabled', { cacheDisabled: true })
    const evaluate = async expression => {
      const result = await pageSend('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
      return remoteEvaluationValue(result)
    }
    const checkedString = value => { need(typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\x00-\x1f]/.test(value)); return value }
    const clickExpression = async expression => {
      let box
      await until(async () => {
        box = await evaluate(`(()=>{const e=${expression};if(!e||e.disabled)return null;e.scrollIntoView({block:'center'});const r=e.getBoundingClientRect();const x=r.x+r.width/2,y=r.y+r.height/2;if(r.width<=0||r.height<=0||!e.contains(document.elementFromPoint(x,y)))return null;return{x,y}})()`)
        return Boolean(box)
      })
      need(box && Number.isFinite(box.x) && Number.isFinite(box.y))
      await pageSend('Input.dispatchMouseEvent', { type: 'mouseMoved', ...box })
      await pageSend('Input.dispatchMouseEvent', { type: 'mousePressed', ...box, button: 'left', clickCount: 1 })
      await pageSend('Input.dispatchMouseEvent', { type: 'mouseReleased', ...box, button: 'left', clickCount: 1 })
    }
    const checkLeaks = async () => {
      const clean = await evaluate(`(()=>{const values=[location.href,document.body.innerText,...Object.entries(localStorage).flat(),...Object.entries(sessionStorage).flat(),document.cookie];return !${JSON.stringify([...secrets])}.some(secret=>values.some(value=>value.includes(secret)))})()`)
      need(clean)
    }
    const guarded = implementation => async (...values) => { try { need(!closed); return await implementation(...values) } catch { reject() } }
    const evidence = () => {
      need(record && journal)
      return { schema: 'chengwang.probe-browser-driver/v1', engine: options.engine, fixtureId: options.fixtureId,
        runtime: true, browserPluginUsed: false, mockedResponses: false, injectedFetch: false, tlsBypass: false,
        chromeSandbox: 'DISABLED_CI_ONLY_OUTER_ISOLATION_REQUIRED', realBrowser: product,
        responseBodyScope: 'CDP_DECODED_RESPONSE_BODY_NOT_RAW_TLS_WIRE', receivedClockResolution: 'UNIX_MILLISECONDS',
        normalTrust: { method: 'PRIVATE_NSS_SQL_XDG_LOCAL_CA', trustFlags: 'C,,', caSHA256: verified.caSHA256,
          leafSHA256: verified.leafSHA256, homeEnvironmentAbsent: true, legacyDatabaseAbsent: true },
        chrome: copy(record), tls: proof ? copy(proof) : null, certificateChain: [...chain],
        screenshotCount, ...journal.evidence(), close: closeEvidence ? copy(closeEvidence) : null }
    }
    const api = {
      engine: options.engine,
      navigate: guarded(async url => {
        need(url === ORIGIN + '/')
        if (page) await page.goto(url, { waitUntil: 'load', timeout: 10000 })
        else { const navigation = await pageSend('Page.navigate', { url }); need(!navigation.errorText); await until(() => evaluate(`location.href===${JSON.stringify(url)}&&document.readyState==='complete'`)) }
        await until(async () => { await journal.flush(); return proof !== null })
      }),
      click: guarded(async selector => {
        checkedString(selector)
        if (page) await page.locator(selector).click({ timeout: 10000 })
        else await clickExpression(`(()=>{const a=[...document.querySelectorAll(${JSON.stringify(selector)})].filter(e=>e.getClientRects().length&&getComputedStyle(e).visibility!=='hidden');return a.length===1?a[0]:null})()`)
      }),
      clickText: guarded(async (name, scope) => {
        checkedString(name); if (scope !== undefined) checkedString(scope)
        if (page) await (scope ? page.locator(scope) : page).getByRole('button', { name, exact: true }).filter({ visible: true }).click({ timeout: 10000 })
        else await clickExpression(`(()=>{const scope=${scope ? `document.querySelector(${JSON.stringify(scope)})` : 'document'};const a=[...(scope?.querySelectorAll('button')??[])].filter(e=>e.textContent.trim()===${JSON.stringify(name)}&&e.getClientRects().length&&getComputedStyle(e).visibility!=='hidden');return a.length===1?a[0]:null})()`)
      }),
      fill: guarded(async (selector, value) => {
        need(selector === '#probe-token' && typeof value === 'string' && value.length <= 4096 && /^[\x21-\x2b\x2d-\x7e]*$/.test(value))
        if (value) secrets.add(value)
        if (page) await page.locator(selector).fill(value, { timeout: 10000 })
        else {
          need(await evaluate(`(()=>{const e=document.querySelector('#probe-token');if(!e||e.type!=='password'||e.disabled)return false;e.focus();e.select();return true})()`))
          if (value) await pageSend('Input.insertText', { text: value })
          else { await pageSend('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Backspace', code: 'Backspace', windowsVirtualKeyCode: 8 }); await pageSend('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Backspace', code: 'Backspace', windowsVirtualKeyCode: 8 }) }
        }
      }),
      setViewport: guarded(async size => {
        need(exact(size, ['width', 'height']) && Number.isInteger(size.width) && size.width >= 320 && size.width <= 1600 && Number.isInteger(size.height) && size.height >= 320 && size.height <= 1200)
        if (page) await page.setViewportSize(size)
        else await pageSend('Emulation.setDeviceMetricsOverride', { ...size, deviceScaleFactor: 1, mobile: false })
      }),
      snapshot: guarded(async () => { await checkLeaks(); return evaluate(`(${collectProbeDOM.toString()})()`) }),
      screenshot: guarded(async () => {
        await checkLeaks(); need(++screenshotCount <= 16)
        let raw
        if (page) raw = await page.screenshot({ type: 'png', fullPage: true, timeout: 10000 })
        else { const metrics = await pageSend('Page.getLayoutMetrics'); const width = Math.ceil(metrics.cssContentSize.width), height = Math.ceil(metrics.cssContentSize.height); need(width > 0 && width <= 1600 && height > 0 && height <= 12000); const captured = await pageSend('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width, height, scale: 1 } }); raw = Buffer.from(captured.data, 'base64') }
        need(raw.length > 8 && raw.length <= 16 << 20 && raw.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'))); return Uint8Array.from(raw)
      }),
      networkSince: guarded(async (cursor = 0) => { await journal.flush(); return journal.since(cursor) }),
      getEvidence: async () => { try { await journal.flush(); return evidence() } catch { reject() } },
      close: async () => {
        try {
        if (closed) return copy(closeEvidence)
        await journal.flush(); need(journal.active.size === 0)
        if (context) await context.close()
        else await browserSend('Browser.close')
        let exit
        await until(async () => {
          try { exit = await processRecord(join(options.browserRoot, 'chrome-exit.private.json')); return true } catch (error) { if (error?.code === 'ENOENT') return false; throw error }
        }, 15000)
        need(exact(exit, ['schema', 'engine', 'fixtureId', 'pid', 'startTicks', 'exitCode', 'joined', 'forced'])
          && exit.schema === 'chengwang.probe-chrome-exit/v1' && exit.engine === options.engine && exit.fixtureId === options.fixtureId
          && exit.pid === record.pid && exit.startTicks === record.startTicks && exit.exitCode === 0 && exit.joined === true && exit.forced === false)
        if (childResult) { const status = await Promise.race([childResult, delay(2000).then(() => null)]); need(status?.code === 0 && status.signal === null) }
        await until(async () => !(await liveOwnedChrome(options, record)), 5000)
        const guardPath = join(options.sourceRoot, 'chengwang/tools/image-binding/scripts/browser-process-guard.py')
        // The existing guard is invoked only after a complete live scan proves
        // it has no target to signal. Any forced intervention fails before it.
        try { await execute('/usr/bin/python3', ['-B', guardPath, 'cleanup', options.browserRoot], { env: environment, timeout: 10000, maxBuffer: 4096 }) } catch { reject() }
        need(!(await liveOwnedChrome(options, record)))
        closed = true; transport?.socket.close()
        closeEvidence = { normalCloseCommandCompleted: true, chromeExit: copy(exit), guardExitCode: 0,
          noLiveOwnedProcessesBeforeGuard: true, noLiveOwnedProcessesAfterGuard: true, guardSignalIntervention: false }
        return copy(closeEvidence)
        } catch { reject() }
      },
    }
    return Object.freeze(api)
  } catch (error) {
    launchDiagnostic(spawnError ?? error)
    // An incomplete launch is never declared a normal close. The independent
    // namespace supervisor remains responsible for emergency cleanup.
    try { await context?.close() } catch { /* No normal-stop claim. */ }
    transport?.socket.close()
    reject()
  }
}

export async function launchProbeDriver(input) {
  try { return await launchImplementation(input) } catch { reject() }
}
