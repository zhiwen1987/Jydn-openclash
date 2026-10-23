// CI-only two real transports. Imports perform no launch or network I/O.
import { spawn, execFile } from 'node:child_process'
import { constants } from 'node:fs'
import { lstat, stat, mkdir, open, readFile, readlink, readdir, link, unlink } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { homedir } from 'node:os'
import { setTimeout as delay } from 'node:timers/promises'
import { promisify } from 'node:util'
import { pathToFileURL } from 'node:url'
import { ORIGIN,SCENARIO,SCOPE,STEPS,ACTIONS,ROLES,LABELS,FAVICON,need,exact,integer,sha,assetPaths,decodeBody,parseArguments,secretVariants,publicFence,validatePrivateInput,classifyAdmissionRequest,stepRole,stepMutations,validateAdmissionStep } from './admission-contract.mjs'
import { parseProcess,versionProjection } from './ui-contract.mjs'
import { stableFile,ownedDirectory,publish,publishReady,until,Transport,chromeIdentity,noLiveChrome } from './ui-driver.mjs'
const execute=promisify(execFile)
const checkpoint=value=>process.stderr.write('SUBSCRIPTION_UI_STAGE='+value+'\n')
const us=value=>{need(typeof value==='number'&&Number.isFinite(value)&&value>=0&&value<=Number.MAX_SAFE_INTEGER/1000000);return Math.floor(value*1000000)}
export class AdmissionJournal {
  constructor(assets, input, files, bodyReader) {
    this.assets = assets; this.input = input; this.files = files; this.bodyReader = bodyReader; this.facts = {sources:{},candidates:{},commands:{}}
    this.canaries = secretVariants([...Object.values(input.tokens),...Object.values(input.tokens).map(v=>'Bearer '+v),...input.canaries]); this.requests = new Map(); this.ignored = new Set()
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
        try { projection = classifyAdmissionRequest(p.request, this.assets, this.input, this.files, this.mutationCount(), this.facts) } catch { this.counters.forbiddenRequests++; throw Error() }
        need(!p.redirectResponse && this.requests.size < 256 && !this.requests.has(p.requestId) && /^[A-Za-z0-9_.-]{1,80}$/.test(p.requestId))

        const item = { ...projection, actionIndex: p.request.method === 'POST' ? this.mutationCount() : null, requestId: p.requestId, requestOrdinal: this.requests.size + 1, startedWallTimeUs: us(p.wallTime), startTimeUs: us(p.timestamp), response: null, terminal: false }
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
    publicFence(raw, this.canaries); this.totalBytes += raw.length; need(this.totalBytes <= 16 << 20)
    const row = { schema: 'chengwang.admission-ui-capture/v1', ordinal, requestOrdinal: item.requestOrdinal,
      requestId: item.requestId, method: item.method, path: item.path, kind: item.kind, status: item.response.status,
      authorizationPresent: item.authorizationPresent, actorRole: item.actorRole, requestPublic: item.requestPublic, responseBase64: raw.toString('base64'),
      responseSHA256: sha(raw), responseBytes: raw.length, startedWallTimeUs: item.startedWallTimeUs,
      startTimeUs: item.startTimeUs, headerTimeUs: item.headerTimeUs, endTimeUs: item.endTimeUs,
      terminal: { event: 'FINISH', encodedDataLength } }
    publicFence(Buffer.from(JSON.stringify(row)), this.canaries); this.rows.push(row)
    if(item.method==='POST')this.learn(item,raw)
  }
  mutationCount() { return [...this.requests.values()].filter(v => v.method !== 'GET').length }
  idle() { return this.tasks.size === 0 && [...this.requests.values()].every(v => v.terminal) }
  learn(item,raw) {
    const value=JSON.parse(raw.toString('utf8'));need(exact(value,['boundary','authorization','deviceActionsExecuted','stateMayHaveChanged','result'])&&value.boundary==='LOCAL_SUBSCRIPTION_ADMISSION_ONLY'&&value.authorization==='BLOCKED'&&value.deviceActionsExecuted===false&&value.stateMayHaveChanged===false)
    const r=value.result,a=ACTIONS[item.actionIndex];need(r&&r.kind===a.kind&&r.state==='committed'&&r.revision===a.toRevision&&r.auditRecorded===true&&r.stateMayHaveChanged===false&&r.replayed===false&&/^cmd_[a-f0-9]{32}$/.test(r.commandId)&&/^src_[a-f0-9]{32}$/.test(r.sourceId))
    if(a.kind==='create'){need(!this.facts.sources[a.source]);this.facts.sources[a.source]=r.sourceId}
    else need(r.sourceId===this.facts.sources[a.source])
    if(a.kind==='import'){need(/^cand_[a-f0-9]{32}$/.test(r.candidateId)&&typeof r.candidateDigest==='string'&&/^hmac-sha256:[a-f0-9]{64}$/.test(r.candidateDigest));this.facts.candidates[a.candidate]={id:r.candidateId,digest:r.candidateDigest,sourceId:r.sourceId}}
    else if(a.candidate)need(r.candidateId===this.facts.candidates[a.candidate].id)
    this.facts.commands[a.key]=r
  }
  complete() {
    need(!this.failure&&this.idle()&&this.requests.size>0&&this.rows.length===this.requests.size&&this.finished===this.rows.length&&Object.values(this.counters).every(v=>v===0)&&this.mutationCount()===10)
    const ids=new Set(Object.values(this.facts.sources));need(ids.size===2&&Object.keys(this.facts.candidates).length===4&&Object.keys(this.facts.commands).length===10)
    const writes=this.rows.filter(r=>r.method==='POST');need(new Set(writes.map(r=>r.requestPublic.idempotencyKey)).size===10)
    for(const row of this.rows){
      const path=/^\/api\/v1\/subscriptions\/sources\/(src_[a-f0-9]{32})(?:\/candidates\/(cand_[a-f0-9]{32})\/nodes)?/.exec(row.path)
      if(path){need(ids.has(path[1]));if(path[2])need(Object.values(this.facts.candidates).some(c=>c.id===path[2]&&c.sourceId===path[1]))}
      if(row.kind==='RECEIPT')need(row.path==='/api/v1/subscriptions/commands/'+this.facts.commands.rollback_a.commandId&&row.actorRole==='approver')
    }
    need(this.rows.filter(r=>r.kind==='DOCUMENT').length===1&&this.rows.filter(r=>r.kind==='SNAPSHOT').length===1&&this.rows.filter(r=>r.kind==='RECEIPT').length===1)
  }
}

const BUTTONS=Object.freeze(['订阅与提供者','运行总览','连接订阅会话','清除会话与令牌','准备创建来源','准备导入候选','准备接纳候选','准备拒绝候选','准备回退候选','确认并提交本地操作','取消本次操作','读取命令回执'])
function targetExpression(kind,value){
  if(kind==='button'){need(BUTTONS.includes(value));return `(()=>{const a=[...document.querySelectorAll('button')].filter(e=>e.textContent.trim()===${JSON.stringify(value)}||e.getAttribute('aria-label')===${JSON.stringify(value)});if(a.length!==1)throw Error('UI target rejected');return a[0]})()`}
  if(kind==='input'){need(['subscription-token','subscription-source-label'].includes(value));return `document.getElementById(${JSON.stringify(value)})`}
  if(kind==='checkbox')return 'document.querySelector(".subscription-confirmation[role=alertdialog] input[type=checkbox]")'
  need(['source','candidate'].includes(kind)&&new RegExp('^'+(kind==='source'?'src':'cand')+'_[a-f0-9]{32}$').test(value))
  const selector=kind==='source'?'.subscription-source-list > li > button':'.subscription-candidate-list > li > button'
  return `(()=>{const a=[...document.querySelectorAll(${JSON.stringify(selector)})].filter(e=>e.querySelector('code')?.textContent.trim()===${JSON.stringify(value)});if(a.length!==1)throw Error('UI target rejected');return a[0]})()`
}
export async function runAdmissionUI(o) {
  checkpoint('ENVIRONMENT')
  need(process.platform === 'linux' && process.getuid?.() === 10001 && process.getgid?.() === 10001 && !Object.hasOwn(process.env, 'HOME') && process.env.TMPDIR === '/var/tmp' && homedir() === o.home && typeof WebSocket === 'function')
  await ownedDirectory(o.root); await ownedDirectory('/var/tmp'); await ownedDirectory(o.home, true); await ownedDirectory(o.profile, true)
  const config = JSON.parse((await stableFile(o.bundle + '/launch.json', 4096)).toString())
  need(exact(config, ['schema', 'engine', 'fixtureId', 'root', 'chrome', 'chromeSHA256']) && config.schema === 'chengwang.subscription-ui-launch/v1' && config.engine === o.engine && config.fixtureId === o.fixtureId && config.root === o.root && config.chrome === o.chrome && /^[a-f0-9]{64}$/.test(config.chromeSHA256))
  const input = validatePrivateInput(JSON.parse((await stableFile(o.root + '/browser-input.private.json',65536,true)).toString()),o.root)
  const files = {}
  for(const file of input.files){const raw=await stableFile(file.path,1<<20,true);need(raw.length===file.bytes);files[file.key]=raw}
  const canaries=secretVariants([...Object.values(input.tokens),...Object.values(input.tokens).map(v=>'Bearer '+v),...input.canaries])
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
    journal = new AdmissionJournal(assets,input,files,requestId=>pageSend('Network.getResponseBody',{requestId}))
    const browser=versionProjection(await browserSend('Browser.getVersion')),chrome=await chromeIdentity(o,browserSend);need(chrome.exeSHA256===config.chromeSHA256)
    await Promise.all(['Runtime.enable','Page.enable','Log.enable'].map(method=>pageSend(method)))
    await pageSend('Network.enable',{maxTotalBufferSize:32<<20,maxResourceBufferSize:8<<20})
    const evaluate=async expression=>{if(page)return page.evaluate(expression);const r=await pageSend('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});need(r&&!r.exceptionDetails&&Object.hasOwn(r.result??{},'value'));return r.result.value}
    const viewport=async width=>{if(page)await page.setViewportSize({width,height:900});else await pageSend('Emulation.setDeviceMetricsOverride',{width,height:900,deviceScaleFactor:1,mobile:false})}
    const click=async(value,kind='button')=>{
      const expression=targetExpression(kind,value)
      if(page){
        let target
        if(kind==='button')target=page.getByRole('button',{name:value,exact:true})
        else if(kind==='checkbox')target=page.getByRole('checkbox',{name:'我已核对回退目标与当前来源版本',exact:true})
        else target=page.locator(kind==='source'?'.subscription-source-list > li > button':'.subscription-candidate-list > li > button').filter({has:page.locator('code',{hasText:new RegExp('^'+value+'$')})})
        need(await target.count()===1);await target.click({timeout:10000})
      }else{
        const point=await evaluate(`(()=>{const e=${expression};if(!e||e.disabled)throw Error('UI target rejected');e.scrollIntoView({block:'center',inline:'nearest'});const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;if(!(r.width>0&&r.height>0&&x>=0&&y>=0&&x<innerWidth&&y<innerHeight&&e.contains(document.elementFromPoint(x,y))))throw Error('UI target rejected');return{x,y}})()`)
        await pageSend('Input.dispatchMouseEvent',{type:'mouseMoved',...point});await pageSend('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',clickCount:1,...point});await pageSend('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',clickCount:1,...point})
      }
    }
    const fill=async(id,value)=>{need(['subscription-token','subscription-source-label'].includes(id)&&typeof value==='string'&&value.length<=4096);if(page)await page.locator('#'+id).fill(value,{timeout:10000});else{need(await evaluate(`(()=>{const e=${targetExpression('input',id)};if(!e||e.disabled||e.value!=='')return false;e.scrollIntoView({block:'center'});e.focus();return document.activeElement===e})()`));await pageSend('Input.insertText',{text:value})}}
    const waitDOM=async predicate=>{let dom;await until(async()=>{need(!journal.failure);dom=await evaluate(collector.SUBSCRIPTION_DOM_EXPRESSION);collector.validateSubscriptionDOM(dom);return journal.idle()&&predicate(dom)});return dom}
    let actorRole='anonymous';const domRows=[],screenshots=[]
    const record=async step=>{
      await until(()=>journal.idle());need(!journal.failure&&actorRole===stepRole(step))
      need(await evaluate('location.href==='+JSON.stringify(ORIGIN+'/')+'&&document.title==="澄网 · 网络代理与路由平台"&&!document.querySelector("vite-error-overlay,nextjs-portal,[data-vite-error-overlay]")')===true)
      const dom=await evaluate(collector.SUBSCRIPTION_DOM_EXPRESSION);collector.validateSubscriptionDOM(dom);validateAdmissionStep(step,dom,journal.mutationCount(),actorRole)
      const text=await evaluate(`(()=>{const p=document.querySelector('.subscriptions');return[p?.innerText??'',[...document.querySelectorAll('input:not([type="password"]):not([type="file"]),textarea')].map(e=>e.value).join('\\n')].join('\\n')})()`)
      need(typeof text==='string'&&Buffer.byteLength(text)<=131072);publicFence(Buffer.from(text),canaries)
      const row={schema:'chengwang.admission-ui-dom-capture/v1',ordinal:domRows.length+1,step,captureCount:journal.rows.length,mutationCount:journal.mutationCount(),actorRole,dom}
      publicFence(Buffer.from(JSON.stringify(row)),canaries);domRows.push(row);return dom
    }
    const currentRevision=alias=>ACTIONS.reduce((n,a)=>a.source===alias&&journal.facts.commands[a.key]?journal.facts.commands[a.key].revision:n,0)
    const sourceReady=(dom,alias)=>dom.sources.some(s=>s.id===journal.facts.sources[alias]&&s.selected&&s.revision===currentRevision(alias))&&dom.paging.candidates?.revision===currentRevision(alias)
    const selectSource=async alias=>{need(['a','b'].includes(alias)&&journal.facts.sources[alias]);await click(journal.facts.sources[alias],'source');await waitDOM(d=>sourceReady(d,alias)&&d.candidates.length===Object.keys(journal.facts.candidates).filter(k=>k.startsWith(alias)).length)}
    const selectCandidate=async alias=>{const candidate=journal.facts.candidates[alias];need(candidate);const count=journal.rows.filter(r=>r.kind==='NODES').length;await click(candidate.id,'candidate');await waitDOM(d=>d.candidates.some(c=>c.id===candidate.id&&c.selected)&&d.nodes.length===2&&journal.rows.filter(r=>r.kind==='NODES').length===count+1)}
    const connect=async role=>{
      need(ROLES.includes(role));await click('清除会话与令牌');actorRole='anonymous';await waitDOM(d=>d.sources.length===0&&d.receipt===null&&d.session.tokenEmpty)
      const count=journal.rows.filter(r=>r.kind==='SOURCES').length;await fill('subscription-token',input.tokens[role]);await click('连接订阅会话');actorRole=role
      await waitDOM(d=>journal.rows.filter(r=>r.kind==='SOURCES').length===count+1&&d.sources.length===Object.keys(journal.facts.sources).length&&d.session.tokenEmpty)
    }
    const upload=async key=>{
      const file=input.files.find(f=>f.key===key);need(file&&await evaluate('document.getElementById("subscription-format").value')==='mihomo-provider-yaml')
      if(page)await page.locator('#subscription-file').setInputFiles(file.path,{timeout:10000})
      else{const documentNode=(await pageSend('DOM.getDocument',{depth:0,pierce:false})).root.nodeId;const nodeId=(await pageSend('DOM.querySelector',{nodeId:documentNode,selector:'#subscription-file'})).nodeId;need(integer(nodeId,1));await pageSend('DOM.setFileInputFiles',{files:[file.path],nodeId})}
      await until(async()=>await evaluate(`(()=>{const e=document.getElementById('subscription-file');return e&&e.value===''&&[...document.querySelectorAll('.subscription-operations p')].some(p=>p.textContent.trim()===${JSON.stringify('已在内存读取 '+file.bytes+' 字节；不展示文件名与原文。')})})()` )===true)
    }
    const prepare=async(name,kind)=>{await click(name);await waitDOM(d=>d.confirmation?.kind===kind)}
    const submit=async key=>{const a=ACTIONS.find(v=>v.key===key);need(a);await click('确认并提交本地操作');await waitDOM(d=>journal.facts.commands[key]?.revision===a.toRevision&&sourceReady(d,a.source)&&d.receipt?.commandId===journal.facts.commands[key].commandId&&d.receipt.state==='committed'&&d.confirmation===null&&d.nodes.length===0)}
    const shot=async step=>{
      const d=domRows.at(-1).dom;need(domRows.at(-1).step===step&&d.session.tokenEmpty&&d.session.fileEmpty)
      const raw=page?await page.screenshot({type:'png',fullPage:false,animations:'disabled',timeout:10000}):Buffer.from((await pageSend('Page.captureScreenshot',{format:'png',fromSurface:true,captureBeyondViewport:false})).data,'base64')
      need(raw.length>=1000&&raw.length<=4<<20&&raw.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))
      const name=step==='final_mobile'?'created-mobile':'created-desktop',metadata=await publish(o.root+'/'+name+'.private.png',raw,4<<20)
      screenshots.push({path:name+'.png',step,...metadata,viewport:{width:d.viewport.width,height:d.viewport.height},scrollX:d.viewport.scrollX,scrollY:d.viewport.scrollY,capturedWallTimeUs:Date.now()*1000})
    }
    const settleLayout=()=>evaluate('(async()=>{await document.fonts.ready;window.scrollTo(0,0);await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));return true})()')
    await publishReady(o.root+'/driver-ready.private.json',{schema:'chengwang.subscription-ui-driver-ready/v1',scenario:SCENARIO,fixtureId:o.fixtureId,engine:o.engine,pid:process.pid,chromePid:chrome.pid})
    await until(async()=>{try{const raw=await stableFile(o.root+'/run.go',4096),s=await lstat(o.root+'/run.go');need((s.mode&0o7777)===0o444);const v=JSON.parse(raw.toString());need(exact(v,['schema','scenario','fixtureId','engine'])&&v.schema==='chengwang.subscription-ui-run/v1'&&v.scenario===SCENARIO&&v.fixtureId===o.fixtureId&&v.engine===o.engine);return true}catch(e){if(e?.code==='ENOENT')return false;throw e}},20000)
    checkpoint('NAVIGATE');await viewport(1440)
    if(page)await page.goto(ORIGIN+'/',{waitUntil:'load',timeout:15000});else{const r=await pageSend('Page.navigate',{url:ORIGIN+'/'});need(!r.errorText);await until(async()=>await evaluate('location.href==='+JSON.stringify(ORIGIN+'/')+'&&document.readyState==="complete"')===true)}
    await until(()=>journal.idle()&&journal.rows.some(r=>r.kind==='SNAPSHOT'));await click('订阅与提供者');await waitDOM(d=>d.pageVisible);await record('anonymous')
    const certificateChain=(await pageSend('Network.getCertificate',{origin:ORIGIN})).tableNames,documentRequest=[...journal.requests.values()].find(r=>r.kind==='DOCUMENT'),tls=helper.browserTLSProof(documentRequest.response,certificateChain,verified)
    checkpoint('CREATE');await connect('operator');await record('operator_connected')
    await fill('subscription-source-label',LABELS.a);await prepare('准备创建来源','create');await record('create_a_prepared');await click('取消本次操作');await waitDOM(d=>d.confirmation===null);await record('create_a_cancelled');await prepare('准备创建来源','create');await record('create_a_prepared_again');await submit('create_a');await record('created_a')
    await fill('subscription-source-label',LABELS.b);await prepare('准备创建来源','create');await submit('create_b');await record('created_b')
    checkpoint('IMPORT');await selectSource('a');await upload('first');await prepare('准备导入候选','import');await record('import_a_prepared');await click('取消本次操作');await waitDOM(d=>d.confirmation===null);await record('import_a_cancelled');await upload('first');await prepare('准备导入候选','import');await record('import_a_prepared_again');await submit('import_a');await record('imported_a');await selectCandidate('a1');await record('nodes_a')
    await selectSource('b');await upload('first');await prepare('准备导入候选','import');await submit('import_b');await record('imported_b');await selectCandidate('b1');await record('nodes_b')
    checkpoint('ROLES');await connect('viewer');await selectSource('a');await selectCandidate('a1');await record('viewer_a');await connect('auditor');await selectSource('b');await selectCandidate('b1');await record('auditor_b')
    checkpoint('DECIDE');await connect('approver');await selectSource('a');await selectCandidate('a1');await record('approver_a');await prepare('准备接纳候选','admit');await record('admit_a_prepared');await submit('admit_a');await record('admitted_a')
    await connect('operator');await selectSource('a');await record('operator_a');await upload('second');await prepare('准备导入候选','import');await submit('import_a2');await record('imported_a2');await connect('approver');await selectSource('a');await selectCandidate('a2');await record('approver_a2');await prepare('准备接纳候选','admit');await submit('admit_a2');await record('admitted_a2')
    await connect('operator');await selectSource('a');await record('operator_a3');await upload('third');await prepare('准备导入候选','import');await submit('import_a3');await record('imported_a3');await connect('approver');await selectSource('a');await selectCandidate('a3');await record('approver_a3');await prepare('准备拒绝候选','reject');await submit('reject_a3');await record('rejected_a3')
    checkpoint('ROLLBACK');await selectCandidate('a1');await prepare('准备回退候选','rollback');await record('rollback_prepared');await click('rollback','checkbox');await waitDOM(d=>d.confirmation?.rollbackChecked);await record('rollback_checked');await submit('rollback_a');await record('rolled_back');await selectCandidate('a1');await record('nodes_restored')
    await settleLayout();await record('final_desktop');await shot('final_desktop');await viewport(375);await settleLayout();await record('final_mobile');await shot('final_mobile')
    checkpoint('RECEIPT');await click('读取命令回执');await waitDOM(d=>d.receipt?.commandId===journal.facts.commands.rollback_a.commandId&&journal.rows.filter(r=>r.kind==='RECEIPT').length===1);await record('receipt');await click('运行总览');await waitDOM(d=>!d.pageVisible);await record('hidden');await click('订阅与提供者');await waitDOM(d=>d.pageVisible);await record('returned');await click('清除会话与令牌');actorRole='anonymous';await waitDOM(d=>d.sources.length===0&&d.receipt===null);await record('cleared')
    need(domRows.map(r=>r.step).join(',')===STEPS.join(','));journal.complete()
    checkpoint('CLOSE');if(context)await context.close();else await browserSend('Browser.close')
    let chromeExit;await until(async()=>{try{chromeExit=JSON.parse((await stableFile(o.root+'/chrome-exit.private.json',4096,true)).toString());return true}catch(e){if(e?.code==='ENOENT')return false;throw e}},20000)
    need(exact(chromeExit,['schema','engine','fixtureId','pid','startTicks','exitCode','joined','forced'])&&chromeExit.schema==='chengwang.subscription-ui-chrome-exit/v1'&&chromeExit.engine===o.engine&&chromeExit.fixtureId===o.fixtureId&&chromeExit.pid===chrome.pid&&chromeExit.startTicks===chrome.startTicks&&chromeExit.exitCode===0&&chromeExit.joined===true&&chromeExit.forced===false)
    let launcherExit=null;if(childResult){launcherExit=await Promise.race([childResult,delay(2000).then(()=>null)]);need(launcherExit?.code===0&&launcherExit.signal===null)}
    await until(()=>noLiveChrome(o,chrome),5000);closed=true;transport?.socket.close()
    const capturesRaw=Buffer.from([...journal.rows].sort((a,b)=>a.ordinal-b.ordinal).map(v=>JSON.stringify(v)).join('\n')+'\n'),domRaw=Buffer.from(domRows.map(v=>JSON.stringify(v)).join('\n')+'\n');publicFence(capturesRaw,canaries);publicFence(domRaw,canaries)
    const captures=await publish(o.root+'/captures.private.jsonl',capturesRaw,24<<20);await publish(o.root+'/dom.private.jsonl',domRaw,1<<20);captured=true
    const report={schema:'chengwang.admission-ui-driver/v1',scenario:SCENARIO,sourceCommit:o.sourceCommit,engine:o.engine,fixtureId:o.fixtureId,origin:ORIGIN,scope:SCOPE,runtime:true,mockedResponses:false,injectedFetch:false,tlsBypass:false,browser,chrome,
      normalTrust:{method:'PRIVATE_NSS_SQL_XDG_LOCAL_CA',trustFlags:'C,,',caSHA256:verified.caSHA256,leafSHA256:verified.leafSHA256,homeEnvironmentAbsent:true,legacyDatabaseAbsent:true},tls,certificateChain,counters:journal.counters,
      close:{normalCloseCommandCompleted:true,chromeExit,launcherExit,noLiveOwnedProcesses:true,processScope:'CHROME_SESSION_AND_LAUNCHER_ONLY'},steps:[...STEPS],captures:{path:'captures.jsonl',...captures,records:journal.rows.length},screenshots,production:false,fullSubscriptionE2EProven:false}
    publicFence(Buffer.from(JSON.stringify(report)),canaries);await publish(o.root+'/driver.private.json',report,65536);checkpoint('COMPLETE');return report
  }finally{
    if(!closed){try{if(context)await context.close();else if(browserSend)await browserSend('Browser.close')}catch{/* Emergency cleanup is not normal completion. */}transport?.socket.close()}
    if(!captured&&journal?.rows.length){try{const raw=Buffer.from([...journal.rows].sort((a,b)=>a.ordinal-b.ordinal).map(v=>JSON.stringify(v)).join('\n')+'\n');publicFence(raw,canaries);await publish(o.root+'/captures.private.jsonl',raw,24<<20)}catch{/* No replacement or raw error export. */}}
    for(const raw of Object.values(files))raw.fill(0)
  }
}
