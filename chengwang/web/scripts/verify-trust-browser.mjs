// Real Chrome -> real candidate only. No browser dependencies, intercepted
// responses, injected fetch, route mocks, TLS bypass or credential artifacts.
import { spawn } from 'node:child_process'
import { readFile, writeFile, mkdir, stat, rename } from 'node:fs/promises'
import { resolve, join, isAbsolute } from 'node:path'
import { fileURLToPath } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'

const args = process.argv.slice(2)
function option(name) {
  const at = args.indexOf(name)
  if (at < 0 || !args[at + 1] || args.filter(v => v === name).length !== 1) throw new Error('invalid browser verifier arguments')
  return args[at + 1]
}
const fixtureRoot = option('--fixture-root')
const chrome = option('--chrome')
const evidenceDir = option('--evidence-dir')
if (args.length !== 6 || ![fixtureRoot, chrome, evidenceDir].every(isAbsolute) || ![fixtureRoot, evidenceDir].every(p => resolve(p) === p)) throw new Error('absolute private paths required')
if (process.platform !== 'linux' || typeof WebSocket !== 'function') throw new Error('isolated Linux and builtin WebSocket required')
const rootInfo = await stat(fixtureRoot)
if (!rootInfo.isDirectory() || rootInfo.mode & 0o077 || rootInfo.uid !== process.getuid()) throw new Error('private fixture root required')
const readyPath = join(fixtureRoot, 'ready.json')
const readyInfo = await stat(readyPath)
if (!readyInfo.isFile() || readyInfo.nlink !== 1 || readyInfo.mode & 0o077 || readyInfo.size > 16384 || readyInfo.uid !== process.getuid()) throw new Error('private fixture readiness required')
const ready = JSON.parse(await readFile(readyPath, 'utf8'))
if (Object.keys(ready).sort().join(',') !== 'auditorToken,url,viewerToken,wrongToken') throw new Error('invalid readiness shape')
const url = new URL(ready.url)
if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.pathname !== '/trust.html' || url.username || url.password || url.search || url.hash) throw new Error('loopback candidate required')
const secrets = [ready.auditorToken, ready.viewerToken, ready.wrongToken]
if (new Set(secrets).size !== 3 || !secrets.every(v => typeof v === 'string' && v.length >= 32 && v.length <= 4096 && /^[\x21-\x2b\x2d-\x7e]+$/.test(v))) throw new Error('invalid private fixture identities')

await mkdir(evidenceDir, { recursive: true, mode: 0o700 })
const profile = join(fixtureRoot, 'chrome-profile')
const guardPath = fileURLToPath(new URL('../../tools/image-binding/scripts/browser-process-guard.py', import.meta.url))
await mkdir(profile, { mode: 0o700 })
// This explicit CI-only sandbox exception is recorded below. Outer isolation
// remains non-root, no capabilities, NoNewPrivs, read-only source and loopback.
const chromeArguments = [
  '--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
  '--disable-background-networking', '--disable-component-update', '--disable-sync',
  '--disable-default-apps', '--disable-extensions', '--no-first-run', '--no-default-browser-check',
  '--disable-features=MediaRouter,OptimizationHints', '--password-store=basic',
  '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
  `--user-data-dir=${profile}`, 'about:blank',
]
// The private group initially waits on a pipe. If its supervisor dies before
// publishing the identity record, EOF exits the wrapper without launching
// Chrome. exec preserves PID/start ticks after the crash-visible handoff.
// This CI supervisor does not claim physical power-loss durability.
const child = spawn('/usr/bin/bash', ['--noprofile', '--norc', '-c',
  'IFS= read -r gate && test "$gate" = start || exit 78; exec "$@"',
  'chengwang-private-browser', chrome, ...chromeArguments,
], {
  stdio: ['pipe', 'ignore', 'ignore'], detached: true,
  env: { ...process.env, XDG_CONFIG_HOME: join(profile, 'config'), XDG_CACHE_HOME: join(profile, 'cache') },
})
let launchFailed = false
child.on('error', () => { launchFailed = true })
child.stdin?.on('error', () => { launchFailed = true })
let socket
let nextId = 0
const pending = new Map()
let sessionId
const checks = []
const requests = []
const responses = []
let runtimeErrors = 0
let cspErrors = 0
let assetErrors = 0
let forbiddenRequests = 0
let protectedDocument = false
let screenshotCount = 0
let browserGroupStopped = false
let cjkFontVerified = false
let cjkFonts = []
let interrupted = false
const deadline = Date.now() + 130000
function check(ok, name) {
  if (!ok) throw new Error(`browser assertion: ${name}`)
  checks.push(name)
}
async function until(fn, name, timeout = 10000) {
  const stop = Math.min(deadline, Date.now() + timeout)
  while (Date.now() < stop) {
    if (interrupted) throw new Error('browser interrupted')
    if (await fn()) return
    if (launchFailed || child.exitCode !== null) throw new Error('Chrome exited unexpectedly')
    await delay(80)
  }
  throw new Error(`browser timeout: ${name}`)
}
function send(method, params = {}, target = sessionId) {
  if (interrupted) return Promise.reject(new Error('browser interrupted'))
  const id = ++nextId
  return new Promise((resolveResult, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('CDP command timeout')) }, 10000)
    pending.set(id, { resolve: resolveResult, reject, timer })
    socket.send(JSON.stringify({ id, method, params, ...(target ? { sessionId: target } : {}) }))
  })
}
async function evaluate(expression) {
  const value = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
  if (value.exceptionDetails) throw new Error('browser expression failed')
  return value.result?.value
}
async function waitExpression(expression, name) { await until(() => evaluate(expression), name) }
function selectorButton(name) {
  return `[...document.querySelectorAll('button')].find(e=>e.textContent.trim()===${JSON.stringify(name)})`
}
async function clickExpression(expression) {
  const box = await evaluate(`(()=>{const e=${expression};if(!e||e.disabled)return null;e.scrollIntoView({block:'center'});const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`)
  if (!box) throw new Error('required enabled control missing')
  await send('Input.dispatchMouseEvent', { type: 'mouseMoved', ...box })
  await send('Input.dispatchMouseEvent', { type: 'mousePressed', ...box, button: 'left', clickCount: 1 })
  await send('Input.dispatchMouseEvent', { type: 'mouseReleased', ...box, button: 'left', clickCount: 1 })
}
async function button(name) { await clickExpression(selectorButton(name)) }
async function fill(selector, value) {
  const ok = await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)return false;e.focus();e.select();return true})()`)
  if (!ok) throw new Error('required input missing')
  if (value) await send('Input.insertText', { text: value })
  else {
    await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Backspace', code: 'Backspace', windowsVirtualKeyCode: 8 })
    await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Backspace', code: 'Backspace', windowsVirtualKeyCode: 8 })
  }
}
async function connect(token) {
  await fill('input[type="password"]', token)
  await button('连接并读取')
}
async function idle() { await waitExpression(`!document.querySelector('.it-live').textContent.includes('正在读取')`, 'read completion') }
async function leakCheck() {
  const safe = await evaluate(`(()=>{const secrets=${JSON.stringify(secrets)};const data=[location.href,document.body.innerText,...Object.entries(localStorage).flat(),...Object.entries(sessionStorage).flat(),document.cookie].join(' ');return !secrets.some(s=>data.includes(s))&&document.querySelector('input[type="password"]')!==null})()`)
  check(safe, 'credentials absent from URL visible text storage and cookies')
}
async function screenshot(name) {
  await leakCheck()
  await evaluate('window.scrollTo(0,0)')
  const metrics = await send('Page.getLayoutMetrics')
  const width = Math.ceil(metrics.cssContentSize.width)
  const height = Math.ceil(metrics.cssContentSize.height)
  check(width > 0 && height > 0 && width <= 1600 && height <= 12000, 'bounded real page screenshot')
  const capture = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width, height, scale: 1 } })
  await writeFile(join(evidenceDir, name), Buffer.from(capture.data, 'base64'), { mode: 0o600, flag: 'wx' })
  screenshotCount++
}
let browserVersion = ''
let outcome = 'FAIL'
let failure = ''
const onSignal = () => {
  interrupted = true
  for (const task of pending.values()) { clearTimeout(task.timer); task.reject(new Error('browser interrupted')) }
  pending.clear()
  try { socket?.close() } catch { /* The independent shell guard is the final fallback. */ }
}
for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.once(signal, onSignal)
try {
  let identity
  await until(async () => {
    if (!Number.isInteger(child.pid) || child.pid <= 1) return false
    try {
      const raw = await readFile(`/proc/${child.pid}/stat`, 'utf8')
      const fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/)
      if (Number(fields[2]) !== child.pid || Number(fields[3]) !== child.pid || !/^\d+$/.test(fields[19]) || !Number.isSafeInteger(Number(fields[19])) || Number(fields[19]) <= 0) return false
      identity = { pid: child.pid, startTicks: Number(fields[19]), uid: process.getuid(), profile }
      return true
    } catch { return false }
  }, 'private Chrome group identity')
  const temporary = join(fixtureRoot, '.chrome-process.tmp')
  await writeFile(temporary, JSON.stringify(identity) + '\n', { mode: 0o600, flag: 'wx' })
  await rename(temporary, join(fixtureRoot, 'chrome-process.private.json'))
  if (interrupted) throw new Error('browser interrupted')
  child.stdin.end('start\n')
  let active
  await until(async () => {
    try { active = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).trim().split('\n'); return active.length === 2 && /^\d+$/.test(active[0]) && active[1].startsWith('/devtools/browser/') } catch { return false }
  }, 'Chrome readiness', 20000)
  socket = new WebSocket(`ws://127.0.0.1:${active[0]}${active[1]}`)
  await new Promise((done, reject) => {
    const timer = setTimeout(() => reject(new Error('CDP handshake timeout')), 10000)
    socket.addEventListener('open', () => { clearTimeout(timer); done() }, { once: true })
    const failed = () => { clearTimeout(timer); reject(new Error('CDP unavailable')) }
    socket.addEventListener('error', failed, { once: true })
    socket.addEventListener('close', failed, { once: true })
  })
  socket.addEventListener('message', event => {
    const message = JSON.parse(String(event.data))
    if (message.id && pending.has(message.id)) {
      const task = pending.get(message.id); pending.delete(message.id); clearTimeout(task.timer)
      if (message.error) task.reject(new Error('CDP command rejected'))
      else task.resolve(message.result)
      return
    }
    if (message.sessionId !== sessionId) return
    const p = message.params || {}
    if (message.method === 'Runtime.exceptionThrown') runtimeErrors++
    if (message.method === 'Log.entryAdded' && p.entry?.source === 'security' && p.entry?.level === 'error') cspErrors++
    if (message.method === 'Network.requestWillBeSent') {
      const u = new URL(p.request.url)
      if (u.protocol !== 'http:' || u.origin !== url.origin || secrets.some(s => p.request.url.includes(s))) forbiddenRequests++
      if (u.pathname.startsWith('/api/')) {
        if (p.request.method !== 'GET' || !['/api/v1/image-trust', '/api/v1/image-trust/history'].includes(u.pathname)) forbiddenRequests++
        requests.push({ method: p.request.method, path: u.pathname })
      }
    }
    if (message.method === 'Network.responseReceived') {
      const u = new URL(p.response.url)
      if (p.type === 'Document' && u.pathname === '/trust.html') {
        const headers = Object.fromEntries(Object.entries(p.response.headers).map(([k, v]) => [k.toLowerCase(), v]))
        const csp = headers['content-security-policy'] || ''
        protectedDocument = csp.includes("default-src 'none'") && csp.includes("script-src 'self'") && csp.includes("connect-src 'self'") && csp.includes("frame-ancestors 'none'") && !csp.includes('unsafe-inline') && !csp.includes('unsafe-eval') && headers['cache-control'] === 'no-store' && headers['x-content-type-options'] === 'nosniff' && headers['x-frame-options'] === 'DENY' && headers['referrer-policy'] === 'no-referrer'
      }
      if (u.pathname.startsWith('/api/')) responses.push({ path: u.pathname, status: p.response.status })
      else if (p.response.status !== 200) assetErrors++
    }
    if (message.method === 'Network.loadingFailed' && !['Fetch', 'XHR'].includes(p.type)) assetErrors++
  })
  const version = await send('Browser.getVersion', {}, null)
  browserVersion = version.product
  const target = await send('Target.createTarget', { url: 'about:blank' }, null)
  sessionId = (await send('Target.attachToTarget', { targetId: target.targetId, flatten: true }, null)).sessionId
  await Promise.all([send('Runtime.enable'), send('Page.enable'), send('Network.enable'), send('Log.enable')])
  await send('DOM.enable')
  await send('CSS.enable')
  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false })
  await send('Page.navigate', { url: ready.url })
  await waitExpression(`document.querySelector('h1')?.textContent.includes('可信策略控制台')`, 'actual console mount')
  check(protectedDocument, 'actual browser document carries restrictive CSP no-store nosniff DENY and no-referrer')
  const documentRoot = await send('DOM.getDocument', { depth: 0 })
  const heading = await send('DOM.querySelector', { nodeId: documentRoot.root.nodeId, selector: '.it-heading h1' })
  const platformFonts = await send('CSS.getPlatformFontsForNode', { nodeId: heading.nodeId })
  cjkFonts = platformFonts.fonts.map(f => ({ family: f.familyName, postscript: f.postScriptName, glyphCount: f.glyphCount, custom: f.isCustomFont }))
  cjkFontVerified = cjkFonts.some(f => f.family === 'Noto Sans CJK SC' && f.glyphCount >= 7 && f.custom === false)
  check(cjkFontVerified, 'actual Chinese heading renders at least 7 glyphs using verified Noto Sans CJK SC')
  check(await evaluate(`document.body.innerText.includes('候选未部署 · 无设备执行授权') && document.body.innerText.includes('BLOCKED · 只读') && document.body.innerText.includes('尚未读取；所有状态未知。')`), 'unknown initial state and explicit candidate boundary')
  await delay(400)
  check(requests.length === 0, 'no automatic authenticated requests before connection')
  await screenshot('trust-console-desktop-disconnected.png')

  await connect(ready.auditorToken)
  await waitExpression(`document.querySelectorAll('.it-history>li').length===20`, 'actual auditor first page')
  await idle()
  check(await evaluate(`document.querySelector('.it-live').textContent.includes('读取完成') && document.querySelector('.it-metric small').textContent.includes('代次 3 ·') && document.querySelector('[aria-labelledby="it-history"] .it-pagination').textContent.includes('共 22 条')`), 'actual candidate generation and 22 persisted operation records')
  check(responses.some(v => v.path === '/api/v1/image-trust' && v.status === 200) && responses.some(v => v.path.endsWith('/history') && v.status === 200), 'browser received real status and history HTTP 200')
  check(await evaluate(`document.querySelectorAll('.it-policies>li').length===20 && document.querySelector('.it-policies').textContent.includes('ui-fixture-policy-00')`), 'actual signed policy catalogue first page has 20 of 25 definitions')
  await button('下一页策略')
  check(await evaluate(`document.querySelectorAll('.it-policies>li').length===5 && document.querySelector('.it-policies').textContent.includes('ui-fixture-policy-24')`), 'actual signed policy catalogue next page has remaining 5 definitions')
  await fill('[aria-labelledby="it-policies"] input', 'ui-fixture-policy-24')
  check(await evaluate(`document.querySelectorAll('.it-policies>li').length===1 && document.querySelector('.it-policies strong').textContent==='ui-fixture-policy-24'`), 'actual policy search spans fetched catalogue and resets page')
  await fill('[aria-labelledby="it-policies"] input', '')
  await waitExpression(`document.querySelectorAll('.it-policies>li').length===20`, 'actual policy search clear restores first page')
  const connectedCount = requests.length
  await delay(1100)
  check(requests.length === connectedCount, 'connected idle page makes no automatic network requests in observed window')
  await clickExpression(`document.querySelector('summary[aria-label="展开目录摘要"]')`)
  check(await evaluate(`(()=>{const code=document.querySelector('.it-facts details code');return Boolean(code&&/^sha256:[a-f0-9]{64}$/.test(code.textContent))})()`), 'actual prefixed catalogue digest expands in full')
  await clickExpression(`document.querySelector('.it-history .it-entry-details>summary')`)
  check(await evaluate(`document.querySelector('.it-history .it-entry-details[open] dl')?.textContent.includes('已确认')`), 'actual operation detail opens with audit acknowledgement')
  await screenshot('trust-console-desktop-auditor.png')

  await fill('[aria-labelledby="it-history"] input', 'no-such-operation-browser-check')
  await waitExpression(`document.querySelector('[aria-labelledby="it-history"]').textContent.includes('当前页没有匹配')`, 'current page search empty result')
  await fill('[aria-labelledby="it-history"] input', '')
  await waitExpression(`document.querySelectorAll('.it-history>li').length===20`, 'search clear restores page')
  await button('下一页记录')
  await waitExpression(`document.querySelectorAll('.it-history>li').length===2`, 'actual anchored second page')
  check(await evaluate(`document.querySelector('[aria-labelledby="it-history"] .it-pagination').textContent.includes('第 2 页')`), 'real second page pagination label')
  await button('上一页记录')
  await waitExpression(`document.querySelectorAll('.it-history>li').length===20`, 'actual return to first page')
  await button('手工刷新')
  await waitExpression(`document.querySelectorAll('.it-history>li').length===20`, 'actual manual refresh')

  await send('Emulation.setDeviceMetricsOverride', { width: 375, height: 812, deviceScaleFactor: 1, mobile: true })
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] })
  await delay(150)
  check(await evaluate(`document.documentElement.scrollWidth<=innerWidth && innerWidth===375`), '375px real authenticated page has no horizontal overflow')
  check(await evaluate(`[...document.querySelectorAll('.image-trust-console button')].filter(e=>e.getClientRects().length>0).every(e=>e.getBoundingClientRect().height>=44)`), 'all visible console buttons meet 44px target height')
  check(await evaluate(`matchMedia('(prefers-reduced-motion: reduce)').matches && getComputedStyle(document.querySelector('.it-primary')).transitionDuration.split(',').every(v=>parseFloat(v)===0)`), 'real reduced motion presentation')
  await evaluate(`document.querySelector('input[type="password"]').focus()`)
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 })
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 })
  check(await evaluate(`document.activeElement?.tagName==='BUTTON' && document.activeElement.textContent==='重新连接' && getComputedStyle(document.activeElement).outlineStyle!=='none'`), 'real keyboard navigation and visible focus')
  await screenshot('trust-console-mobile-auditor.png')
  await send('Emulation.setDeviceMetricsOverride', { width: 812, height: 375, deviceScaleFactor: 1, mobile: true })
  check(await evaluate('document.documentElement.scrollWidth<=innerWidth'), 'landscape page has no horizontal overflow')

  await button('断开并清除')
  check(await evaluate(`document.querySelector('input[type="password"]').value==='' && !document.querySelector('.it-facts') && document.querySelectorAll('.it-history>li').length===0`), 'disconnect clears credential and all observations')
  await connect(ready.viewerToken)
  await waitExpression(`document.querySelector('[aria-labelledby="it-history"]').textContent.includes('当前身份无权读取')`, 'actual viewer history 403')
  await idle()
  check(await evaluate(`document.querySelector('.it-live').textContent.includes('读取完成') && !!document.querySelector('.it-facts') && document.querySelectorAll('.it-history>li').length===0`), 'viewer keeps authorized status but cannot see history')
  check(responses.some(v => v.path.endsWith('/history') && v.status === 403), 'real browser history HTTP 403')
  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false })
  await screenshot('trust-console-desktop-viewer-forbidden.png')

  await button('断开并清除')
  await connect(ready.wrongToken)
  await waitExpression(`document.querySelector('.it-live').textContent.includes('凭据已失效或无效')`, 'actual wrong credential HTTP 401')
  check(await evaluate(`document.querySelector('input[type="password"]').value==='' && !document.querySelector('.it-facts') && document.querySelectorAll('.it-history>li').length===0`), 'HTTP 401 clears all successful observations and credential')
  check(responses.some(v => v.status === 401), 'real browser HTTP 401')
  await connect(ready.auditorToken)
  await waitExpression(`document.querySelectorAll('.it-history>li').length===20`, 'real reconnect after 401')
  await button('断开并清除')
  await delay(300)
  check(await evaluate(`document.querySelector('.it-live').textContent.includes('所有状态未知') && !document.querySelector('.it-facts')`), 'disconnected observations remain cleared')
  await leakCheck()
  const count = requests.length
  await delay(1100)
  check(requests.length === count, 'no idle automatic network polling')
  check(runtimeErrors === 0, 'no uncaught browser runtime exceptions')
  check(cspErrors === 0, 'no browser CSP security errors')
  check(assetErrors === 0, 'all actual built browser resources load successfully')
  check(forbiddenRequests === 0 && requests.every(r => r.method === 'GET'), 'all observed API calls same origin read-only GET')
  outcome = 'PASS'
} catch (error) {
  // All failure names are fixed strings from this verifier. Never serialize a
  // remote body, CDP event/command, exception stack, token or readiness object.
  failure = error instanceof Error && /^(browser assertion:|browser timeout:|CDP |Chrome |browser expression|required )/.test(error.message) ? error.message : 'browser verification failed (details withheld)'
} finally {
  for (const task of pending.values()) { clearTimeout(task.timer); task.reject(new Error('CDP closed')) }
  pending.clear()
  socket?.close()
  child.stdin?.destroy()
  const closed = child.exitCode !== null || child.signalCode !== null || launchFailed ? Promise.resolve() : new Promise(done => child.once('exit', done))
  // Use the same independently invocable pidfd guard as the shell supervisor.
  // A naked kill(-pid) here would reintroduce PID reuse and escaped-child gaps.
  const guard = spawn('/usr/bin/python3', ['-B', guardPath, 'cleanup', fixtureRoot], { stdio: ['ignore', 'ignore', 'ignore'] })
  const guardCode = await new Promise(done => {
    let settled = false
    const complete = code => { if (!settled) { settled = true; clearTimeout(timer); done(code) } }
    const timer = setTimeout(() => { guard.kill('SIGKILL'); complete(-1) }, 15000)
    guard.once('error', () => complete(-1))
    guard.once('exit', code => complete(code))
  })
  await Promise.race([closed, delay(2000)])
  browserGroupStopped = guardCode === 0 && (child.exitCode !== null || child.signalCode !== null || launchFailed)
  if (!browserGroupStopped) { outcome = 'FAIL'; failure = 'browser process group cleanup failed' }
  await writeFile(join(fixtureRoot, 'stop'), 'stop\n', { mode: 0o600 })
  const report = {
    schema: 'chengwang.trust-console-browser/v1', outcome, failure,
    boundary: 'ISOLATED_REAL_BROWSER_REAL_CANDIDATE', authorization: 'BLOCKED', deviceActionsExecuted: false,
    realBrowser: browserVersion, node: process.version,
    transport: 'HTTP_127_LOOPBACK_ONLY_NOT_BROWSER_TLS_ACCEPTANCE',
    chromeSandbox: 'DISABLED_CI_ONLY_OUTER_ISOLATION_REQUIRED',
    mockedResponses: false, injectedFetch: false, tlsBypass: false,
    checks, requestCount: requests.length, httpStatusCounts: responses.reduce((out, r) => { out[r.status] = (out[r.status] || 0) + 1; return out }, {}),
    runtimeErrors, cspErrors, assetErrors, forbiddenRequests, screenshotCount, browserGroupStopped, cjkFontVerified, cjkFonts,
  }
  const raw = JSON.stringify(report, null, 2) + '\n'
  if (secrets.some(s => raw.includes(s))) throw new Error('report credential containment failed')
  await writeFile(join(evidenceDir, 'trust-browser-report.json'), raw, { mode: 0o600, flag: 'wx' })
  console.log(`D8_REAL_BROWSER_${outcome} checks=${checks.length} screenshots=${screenshotCount}`)
  if (outcome !== 'PASS') { console.error(failure); process.exitCode = 1 }
}
