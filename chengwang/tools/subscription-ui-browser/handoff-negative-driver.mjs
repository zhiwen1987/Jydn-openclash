// Independent B09 UI negative handoff; native API samples are explicitly separate.
import {spawn,execFile} from 'node:child_process'
import {lstat,mkdir,readFile} from 'node:fs/promises'
import {homedir} from 'node:os'
import {setTimeout as delay} from 'node:timers/promises'
import {promisify} from 'node:util'
import {pathToFileURL} from 'node:url'
import {C,ORIGIN,SCENARIO,SCOPE,STEPS,ROLES,need,exact,sha,assetPaths,validatePrivateInput,secretVariants,publicFence,stepExpectation,validateStep,commandFor,HandoffNegativeJournal} from './handoff-negative-contract.mjs'
import {versionProjection} from './ui-contract.mjs'
import {stableFile,ownedDirectory,publish,publishReady,until,Transport,chromeIdentity,noLiveChrome} from './ui-driver.mjs'
import {readWireFence} from './remote-fetch-driver.mjs'
import {HandoffAPISampler} from './handoff-api-sampler.mjs'
import {FeedbackObserver,feedbackExpression} from './handoff-feedback-observer.mjs'
import {HandoffNavigationDiagnostics,NAVIGATION_TARGET_EXPRESSION} from './handoff-navigation-diagnostics.mjs'
const execute=promisify(execFile)
const checkpoint=value=>process.stderr.write('SUBSCRIPTION_UI_STAGE='+value+'\n')
const BUTTONS=Object.freeze(['订阅与提供者','运行总览','连接订阅会话','清除会话与令牌','刷新来源','准备创建来源','准备批准来源','准备抓取候选','确认并提交本地操作','读取命令回执'])
const INPUTS=Object.freeze(['subscription-token','subscription-source-label','subscription-handoff','subscription-handoff-revision','subscription-command'])
function targetExpression(kind,value){
  if(kind==='button'){need(BUTTONS.includes(value));return `(()=>{const a=[...document.querySelectorAll('button')].filter(e=>e.textContent.trim()===${JSON.stringify(value)}||e.getAttribute('aria-label')===${JSON.stringify(value)});if(a.length!==1)throw Error('UI target rejected');return a[0]})()`}
  if(kind==='input'){need(INPUTS.includes(value));return `document.getElementById(${JSON.stringify(value)})`}
  if(kind==='reference')return 'document.getElementById("subscription-reference")'
  if(kind==='radio'){need(['session','handoff'].includes(value));return `document.querySelectorAll('[role="radiogroup"][aria-label="抓取批准方式"] input[type=radio]')[${value==='session'?0:1}]`}
  need(['source','candidate'].includes(kind)&&new RegExp('^'+(kind==='source'?'src':'cand')+'_[a-f0-9]{32}$').test(value));const selector=kind==='source'?'.subscription-source-list > li > button':'.subscription-candidate-list > li > button'
  return `(()=>{const a=[...document.querySelectorAll(${JSON.stringify(selector)})].filter(e=>e.querySelector('code')?.textContent.trim()===${JSON.stringify(value)});if(a.length!==1)throw Error('UI target rejected');return a[0]})()`
}
export async function runHandoffNegativeUI(o){
  checkpoint('ENVIRONMENT');need(process.platform==='linux'&&process.getuid?.()===10001&&process.getgid?.()===10001&&!Object.hasOwn(process.env,'HOME')&&process.env.TMPDIR==='/var/tmp'&&homedir()===o.home&&typeof WebSocket==='function')
  await ownedDirectory(o.root);await ownedDirectory('/var/tmp');await ownedDirectory(o.home,true);await ownedDirectory(o.profile,true)
  const config=JSON.parse((await stableFile(o.bundle+'/launch.json',4096)).toString());need(exact(config,['schema','engine','fixtureId','root','chrome','chromeSHA256'])&&config.schema==='chengwang.subscription-ui-launch/v1'&&config.engine===o.engine&&config.fixtureId===o.fixtureId&&config.root===o.root&&config.chrome===o.chrome&&/^[a-f0-9]{64}$/.test(config.chromeSHA256))
  const input=validatePrivateInput(JSON.parse((await stableFile(o.root+'/browser-input.private.json',65536,true)).toString())),canaries=secretVariants([...Object.values(input.tokens),...input.canaries])
  await stableFile(o.launcher,131072);const source=o.bundle+'/source/chengwang/',helper=await import(pathToFileURL(source+'web/scripts/trust-browser-tls.mjs').href),collector=await import(pathToFileURL(source+'tools/subscription-browser/collect-subscription-dom.mjs').href)
  const assets=assetPaths(JSON.parse((await stableFile(source+'web/dist/.vite/manifest.json',131072)).toString())),ca=await stableFile(o.root+'/api-ca.pem',65536,true),leaf=await stableFile(o.root+'/api-leaf.pem',65536,true),verified=helper.inspectPublicTLS(ca.toString('utf8'),leaf.toString('utf8'))
  const data=o.home+'/.local/share',database=data+'/pki/nssdb';await mkdir(database,{mode:0o700,recursive:true});try{await lstat(o.home+'/.pki/nssdb');need(false)}catch(e){need(e?.code==='ENOENT')}
  for(const n of ['config','cache'])await ownedDirectory(o.profile+'/'+n,true)
  const environment={PATH:'/usr/bin:/bin',LANG:'C.UTF-8',LC_ALL:'C.UTF-8',TMPDIR:'/var/tmp',XDG_DATA_HOME:data,XDG_CONFIG_HOME:o.profile+'/config',XDG_CACHE_HOME:o.profile+'/cache'}
  await stableFile('/usr/bin/certutil',16<<20);const certutil=args=>execute('/usr/bin/certutil',args,{env:environment,timeout:10000,maxBuffer:65536,encoding:'utf8'})
  await certutil(['-N','-d','sql:'+database,'--empty-password']);await certutil(['-A','-d','sql:'+database,'-n','chengwang-subscription-ui-root','-t','C,,','-i',o.root+'/api-ca.pem'])
  need(helper.inspectPublicTLS((await certutil(['-L','-d','sql:'+database,'-n','chengwang-subscription-ui-root','-a'])).stdout,leaf.toString('utf8')).caSHA256===verified.caSHA256)
  let context,page,transport,browserSend,pageSend,launcherChild,childResult,journal,closed=false,captured=false,sampler
  const diagnostics=new HandoffNavigationDiagnostics({sourceCommit:o.sourceCommit,fixtureId:o.fixtureId,engine:o.engine,scenario:SCENARIO})
  sampler=new HandoffAPISampler(o.root,input,ca,verified.leafSHA256);await sampler.initialize()
  try{
    checkpoint('LAUNCH');const args=['--no-sandbox','--disable-gpu','--disable-dev-shm-usage','--disable-background-networking','--disable-component-update','--disable-sync','--disable-default-apps','--disable-extensions','--no-first-run','--no-default-browser-check','--disable-features=MediaRouter,OptimizationHints','--password-store=basic']
    if(o.engine==='chrome-cdp'){
      launcherChild=spawn(o.launcher,[...args,'--headless=new','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+o.profile,'about:blank'],{stdio:['ignore','ignore','ignore'],env:environment});childResult=new Promise(resolve=>{launcherChild.once('error',()=>resolve({code:null,signal:null}));launcherChild.once('exit',(code,signal)=>resolve({code,signal}))})
      let port;await until(async()=>{need(launcherChild.exitCode===null&&launcherChild.signalCode===null);try{const raw=await readFile(o.profile+'/DevToolsActivePort','utf8');need(raw.length<=1024);const a=raw.trim().split('\n');need(a.length===2&&/^[1-9][0-9]{0,4}$/.test(a[0])&&Number(a[0])<=65535&&/^\/devtools\/browser\/[a-f0-9-]{1,80}$/.test(a[1]));port=a;return true}catch(e){if(e?.code==='ENOENT')return false;throw e}},20000)
      const socket=new WebSocket('ws://127.0.0.1:'+port[0]+port[1]);await new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(Error('remote UI rejected')),10000);socket.addEventListener('open',()=>{clearTimeout(t);resolve()},{once:true});socket.addEventListener('error',()=>{clearTimeout(t);reject(Error('remote UI rejected'))},{once:true})})
      transport=new Transport(socket);browserSend=(m,p)=>transport.send(m,p);const target=await browserSend('Target.createTarget',{url:'about:blank'}),sessionId=(await browserSend('Target.attachToTarget',{targetId:target.targetId,flatten:true})).sessionId;pageSend=(m,p)=>transport.send(m,p,sessionId)
      transport.listeners.push(m=>{if(m.sessionId===sessionId)journal?.handle(m.method,m.params??{})});const known=new Set((await browserSend('Target.getTargets')).targetInfos.map(v=>v.targetId));transport.listeners.push(m=>{if(m.method==='Target.targetCreated'&&['page','service_worker','shared_worker'].includes(m.params?.targetInfo?.type)&&!known.has(m.params.targetInfo.targetId)&&journal){journal.failure=true;journal.counters.forbiddenRequests++}});await browserSend('Target.setDiscoverTargets',{discover:true})
    }else{
      const packageFile=source+'tools/subscription-ui-browser/node_modules/playwright-core/';need(JSON.parse((await stableFile(packageFile+'package.json',65536)).toString()).version==='1.65.0-alpha-2026-10-23');const module=await import(pathToFileURL(packageFile+'index.mjs').href)
      context=await module.chromium.launchPersistentContext(o.profile,{executablePath:o.launcher,headless:true,chromiumSandbox:false,ignoreHTTPSErrors:false,bypassCSP:false,args,env:environment,timeout:20000});page=context.pages()[0];need(page&&context.pages().length===1)
      const session=await context.newCDPSession(page),browserSession=await context.browser().newBrowserCDPSession();pageSend=(m,p)=>session.send(m,p);browserSend=(m,p)=>browserSession.send(m,p)
      for(const event of ['Network.requestWillBeSent','Network.responseReceived','Network.loadingFinished','Network.loadingFailed','Runtime.exceptionThrown','Runtime.consoleAPICalled','Log.entryAdded','Network.webSocketCreated','Network.webTransportCreated','Network.directTCPSocketCreated'])session.on(event,p=>journal?.handle(event,p))
      context.on('page',p=>{if(p!==page&&journal){journal.failure=true;journal.counters.forbiddenRequests++}});context.on('serviceworker',()=>{if(journal){journal.failure=true;journal.counters.forbiddenRequests++}})
    }
    journal=new HandoffNegativeJournal(assets,input,id=>pageSend('Network.getResponseBody',{requestId:id}));const browser=versionProjection(await browserSend('Browser.getVersion')),chrome=await chromeIdentity(o,browserSend);need(chrome.exeSHA256===config.chromeSHA256)
    await Promise.all(['Runtime.enable','Page.enable','Log.enable'].map(m=>pageSend(m)));await pageSend('Network.enable',{maxTotalBufferSize:32<<20,maxResourceBufferSize:8<<20})
    const evaluate=async expression=>{if(page)return page.evaluate(expression);const r=await pageSend('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});need(r&&!r.exceptionDetails&&Object.hasOwn(r.result??{},'value'));return r.result.value}
    const viewport=async width=>{if(page)await page.setViewportSize({width,height:900});else await pageSend('Emulation.setDeviceMetricsOverride',{width,height:900,deviceScaleFactor:1,mobile:false})}
    const key=async(name,code,modifiers=0)=>{const domCode=name==='a'?'KeyA':name;await pageSend('Input.dispatchKeyEvent',{type:'rawKeyDown',key:name,code:domCode,windowsVirtualKeyCode:code,nativeVirtualKeyCode:code,modifiers});await pageSend('Input.dispatchKeyEvent',{type:'keyUp',key:name,code:domCode,windowsVirtualKeyCode:code,nativeVirtualKeyCode:code,modifiers})}

    const click=async(value,kind='button')=>{
      const expression=targetExpression(kind,value)
      const initialNavigation=kind==='button'&&value==='订阅与提供者'&&diagnostics.nextPhase==='NAV_TARGET_FOUND'
      if(initialNavigation)diagnostics.enter('NAV_TARGET_FOUND','NAV_TARGET_QUERY_REJECTED')
      if(page){
        let t;if(kind==='button')t=page.getByRole('button',{name:value,exact:true});else if(kind==='radio')t=page.getByRole('radio',{name:value==='session'?'本会话已读回批准':'交接批准ID（未核验）',exact:true});else if(kind==='reference')t=page.locator('#subscription-reference');else t=page.locator(kind==='source'?'.subscription-source-list > li > button':'.subscription-candidate-list > li > button').filter({has:page.locator('code',{hasText:new RegExp('^'+value+'$')})})
        const count=await t.count();if(initialNavigation)need(diagnostics.observePlaywrightTarget(count));need(count===1)
        if(initialNavigation)diagnostics.enter('INPUT_DISPATCHED','PW_CLICK_REJECTED')
        await t.click({timeout:10000})
        if(initialNavigation){diagnostics.playwrightClickReturned();diagnostics.complete('INPUT_DISPATCHED')}
      }else{
        const observed=await evaluate(initialNavigation?NAVIGATION_TARGET_EXPRESSION:`(()=>{const e=${expression};if(!e||e.disabled)throw Error('UI target rejected');e.scrollIntoView({block:'center',inline:'nearest'});const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;if(!(r.width>0&&r.height>0&&x>=0&&y>=0&&x<innerWidth&&y<innerHeight&&e.contains(document.elementFromPoint(x,y))))throw Error('UI target rejected');return{x,y}})()`)
        const point=initialNavigation?diagnostics.observeCDPTarget(observed):observed;need(point)
        if(initialNavigation)diagnostics.enter('INPUT_DISPATCHED','INPUT_MOVE_REJECTED')
        await pageSend('Input.dispatchMouseEvent',{type:'mouseMoved',...point})
        if(initialNavigation){diagnostics.acknowledgeMouse('move');diagnostics.setCause('INPUT_PRESS_REJECTED')}
        await pageSend('Input.dispatchMouseEvent',{type:'mousePressed',button:'left',clickCount:1,...point})
        if(initialNavigation){diagnostics.acknowledgeMouse('press');diagnostics.setCause('INPUT_RELEASE_REJECTED')}
        await pageSend('Input.dispatchMouseEvent',{type:'mouseReleased',button:'left',clickCount:1,...point})
        if(initialNavigation){diagnostics.acknowledgeMouse('release');diagnostics.complete('INPUT_DISPATCHED')}
      }
    }
    const fill=async(id,value,replace=false)=>{need(INPUTS.includes(id)&&typeof value==='string'&&value.length>0&&value.length<=4096);if(page)await page.locator('#'+id).fill(value,{timeout:10000});else{need(await evaluate(`(()=>{const e=${targetExpression('input',id)};if(!e||e.disabled||(${replace?'false':"e.value!==''"}))return false;e.scrollIntoView({block:'center'});e.focus();return document.activeElement===e})()`));if(replace){await key('a',65,2);await key('Backspace',8)}await pageSend('Input.insertText',{text:value})}}
    const waitDOM=async predicate=>{let d;await until(async()=>{need(!journal.failure);d=await evaluate(collector.SUBSCRIPTION_DOM_EXPRESSION);collector.validateSubscriptionDOM(d);return journal.idle()&&predicate(d)});return d}
    const waitWire=async count=>{let fence;await until(async()=>{try{fence=await readWireFence(o);return fence.eventCount===count}catch(error){if(error?.constructor?.name==='WireBusy')return false;throw error}});return fence}
    let actorRole='anonymous';const domRows=[],screenshots=[],feedbackObserver=new FeedbackObserver()
    const record=async step=>{
      const anonymous=step==='anonymous'&&diagnostics.phases.at(-1)?.phase==='ANON_DOM'&&!diagnostics.phases.at(-1).completed
      const cause=value=>{if(anonymous)diagnostics.setCause(value)}
      cause('ANON_JOURNAL_WAIT_REJECTED');await until(()=>journal.idle());need(!journal.failure);const e=stepExpectation(step)
      cause('ANON_WIRE_FENCE_REJECTED');const wire=await waitWire(e.wireEvents)
      cause('ANON_SAMPLER_FENCE_REJECTED');const sample=await sampler.fence()
      cause('ANON_IDENTITY_REJECTED');need(await evaluate('location.href==='+JSON.stringify(ORIGIN+'/')+'&&document.title==="澄网 · 网络代理与路由平台"&&!document.querySelector("vite-error-overlay,nextjs-portal,[data-vite-error-overlay]")')===true)
      cause('ANON_SHAPE_REJECTED');const observed=await evaluate(feedbackExpression(collector.SUBSCRIPTION_DOM_EXPRESSION));need(exact(observed,['dom','feedback']));const d=observed.dom;collector.validateSubscriptionDOM(d);cause('ANON_STEP_REJECTED');validateStep(step,d,journal.mutationCount(),actorRole,journal.facts,wire,sample)
      cause('ANON_CONTENT_FENCE_REJECTED');const text=await evaluate(`(()=>{const p=document.querySelector('.subscriptions');return[p?.innerText??'',[...document.querySelectorAll('input:not([type="password"]):not([type="file"]),textarea')].map(e=>e.value).join('\\n')].join('\\n')})()`);need(typeof text==='string'&&Buffer.byteLength(text)<=131072);publicFence(Buffer.from(text),canaries)
      const row={schema:C.domSchema,ordinal:domRows.length+1,step,captureCount:journal.rows.length,mutationCount:journal.mutationCount(),actorRole,wireFence:wire,samplerFence:sample,dom:d};publicFence(Buffer.from(JSON.stringify(row)),canaries);cause('ANON_FEEDBACK_REJECTED');feedbackObserver.record(row,observed.feedback);domRows.push(row);return d
    }
    const sourceReady=(d,key)=>d.sources.some(s=>s.id===journal.facts.sources[key]&&s.selected)&&d.paging.candidates?.revision===d.sources.find(s=>s.id===journal.facts.sources[key]).revision
    const connect=async role=>{need(ROLES.includes(role));await click('清除会话与令牌');actorRole='anonymous';await waitDOM(d=>!d.sources.length&&d.receipt===null&&d.session.tokenEmpty);const n=journal.rows.filter(r=>r.kind==='SOURCES').length;await fill('subscription-token',input.tokens[role]);await click('连接订阅会话');actorRole=role;await waitDOM(d=>journal.rows.filter(r=>r.kind==='SOURCES').length===n+1&&d.session.tokenEmpty)}
    const selectSource=async key=>{await click(journal.facts.sources[key],'source');await waitDOM(d=>sourceReady(d,key))}
    const reference=async value=>{need(['good-a','good-b'].includes(value));if(page)await page.locator('#subscription-reference').selectOption(value,{timeout:10000});else{await click('reference','reference');await key(value==='good-a'?'Home':'End',value==='good-a'?36:35);await key('Enter',13)}await waitDOM(d=>d.directory.references.some(r=>r.referenceId===value&&r.selected))}
    const prepare=async(name,kind)=>{await click(name);await waitDOM(d=>d.confirmation?.kind===kind)}
    const submit=async action=>{const a=C.actions.find(v=>v.key===action&&v.origin==='browser');need(a);await click('确认并提交本地操作');await waitDOM(d=>{const r=journal.facts.commands[action];return r&&d.confirmation===null&&(a.code?d.alertVisible&&d.stale.sources&&d.stale.candidates:d.receipt?.commandId===r.commandId&&sourceReady(d,a.source))})}
    const readReceipt=async(key,commandKey)=>{checkpoint('RECEIPT');journal.armReceipt(key);await fill('subscription-command',commandFor(journal.facts,commandKey),true);await click('读取命令回执');const c=C.receiptCases.find(v=>v.key===key);await waitDOM(d=>journal.rows.some(r=>r.caseKey===key)&&(c.status===403?d.alertVisible:d.receipt?.commandId===commandFor(journal.facts,commandKey)&&!d.alertVisible))}
    const recover=async()=>{const n=journal.rows.filter(r=>r.kind==='SOURCES').length;await click('刷新来源');await waitDOM(d=>journal.rows.filter(r=>r.kind==='SOURCES').length===n+1&&sourceReady(d,'a')&&!d.alertVisible&&!d.stale.sources&&!d.stale.candidates&&d.mode==='session')}
    const bind=async(key,policy)=>{await click('handoff','radio');await waitDOM(d=>d.mode==='handoff');await fill('subscription-handoff',commandFor(journal.facts,key),true);await fill('subscription-handoff-revision',String(policy),true);await waitDOM(d=>d.handoff?.approvalId===commandFor(journal.facts,key)&&d.handoff.policyRevision===policy)}
    const settle=()=>evaluate('(async()=>{await document.fonts.ready;window.scrollTo(0,0);await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));return true})()')
    const shot=async step=>{const d=domRows.at(-1).dom;need(domRows.at(-1).step===step&&d.session.tokenEmpty&&d.session.fileEmpty);const raw=page?await page.screenshot({type:'png',fullPage:false,animations:'disabled',timeout:10000}):Buffer.from((await pageSend('Page.captureScreenshot',{format:'png',fromSurface:true,captureBeyondViewport:false})).data,'base64');need(raw.length>=1000&&raw.length<=4<<20&&raw.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])));const name=step==='final_mobile'?'created-mobile':'created-desktop',m=await publish(o.root+'/'+name+'.private.png',raw,4<<20);screenshots.push({path:name+'.png',step,...m,viewport:{width:d.viewport.width,height:d.viewport.height},scrollX:d.viewport.scrollX,scrollY:d.viewport.scrollY,capturedWallTimeUs:Date.now()*1000})}
    await publishReady(o.root+'/driver-ready.private.json',{schema:'chengwang.subscription-ui-driver-ready/v1',scenario:SCENARIO,fixtureId:o.fixtureId,engine:o.engine,pid:process.pid,chromePid:chrome.pid})
    await until(async()=>{try{const raw=await stableFile(o.root+'/run.go',4096),s=await lstat(o.root+'/run.go');need((s.mode&0o7777)===0o444);const v=JSON.parse(raw.toString());need(exact(v,['schema','scenario','fixtureId','engine'])&&v.schema==='chengwang.subscription-ui-run/v1'&&v.scenario===SCENARIO&&v.fixtureId===o.fixtureId&&v.engine===o.engine);return true}catch(e){if(e?.code==='ENOENT')return false;throw e}},20000)

    checkpoint('NAVIGATE');diagnostics.enter('VIEWPORT','VIEWPORT_REJECTED');await viewport(1440);diagnostics.complete('VIEWPORT');diagnostics.enter('NAVIGATE_RETURN','NAVIGATE_CALL_REJECTED')
    if(page){await page.goto(ORIGIN+'/',{waitUntil:'load',timeout:15000});diagnostics.complete('NAVIGATE_RETURN');diagnostics.enter('READY','READY_WAIT_REJECTED')}
    else{const r=await pageSend('Page.navigate',{url:ORIGIN+'/'});if(r.errorText)diagnostics.setCause('NAVIGATE_ERROR_PRESENT');need(!r.errorText);diagnostics.complete('NAVIGATE_RETURN');diagnostics.enter('READY','READY_WAIT_REJECTED');await until(async()=>await evaluate('location.href==='+JSON.stringify(ORIGIN+'/')+'&&document.readyState==="complete"')===true)}
    await until(()=>journal.idle()&&journal.rows.some(r=>r.kind==='SNAPSHOT'));diagnostics.complete('READY')
    await click('订阅与提供者');diagnostics.enter('ANON_DOM','ANON_DOM_WAIT_REJECTED');await waitDOM(d=>d.pageVisible);await record('anonymous');diagnostics.complete('ANON_DOM')
    diagnostics.enter('API_CERT','API_CERT_REJECTED')
    const certificateChain=(await pageSend('Network.getCertificate',{origin:ORIGIN})).tableNames,documentRequest=[...journal.requests.values()].find(v=>v.kind==='DOCUMENT')
    diagnostics.complete('API_CERT');diagnostics.enter('TLS_VERIFIED','TLS_PROOF_REJECTED')
    const tls=helper.browserTLSProof(documentRequest.response,certificateChain,verified);diagnostics.complete('TLS_VERIFIED')
    checkpoint('CREATE');await connect('operator');await record('operator_connected')
    await fill('subscription-source-label',input.labels.a);await prepare('准备创建来源','create');await record('create_a_prepared');await submit('create_a');await record('created_a')
    await fill('subscription-source-label',input.labels.b,true);await prepare('准备创建来源','create');await record('create_b_prepared');await submit('create_b');await record('created_b')
    checkpoint('APPROVE');await connect('approver');await selectSource('a');await record('approver_a');await prepare('准备批准来源','approve');await record('approve_a_old_prepared');await submit('approve_a_old');await record('approved_a_old')
    await reference('good-b');await prepare('准备批准来源','approve');await record('approve_a_new_prepared');await submit('approve_a_new');await record('approved_a_new')
    await selectSource('b');await record('approver_b');await prepare('准备批准来源','approve');await record('approve_b_prepared');await submit('approve_b');await record('approved_b')
    checkpoint('HANDOFF');await connect('operator');await selectSource('a');await record('operator_a_disabled')
    for(const bad of [
      {prefix:'unknown',approval:'unknown',policy:1,action:'unknown_fetch',receipt:'unknown_receipt'},
      {prefix:'wrong_source',approval:'approve_b',policy:1,action:'wrong_source_fetch',receipt:'wrong_source_receipt'},
      {prefix:'wrong_policy',approval:'approve_a_new',policy:2,action:'wrong_policy_fetch',receipt:'wrong_policy_receipt'},
      {prefix:'superseded',approval:'approve_a_old',policy:1,action:'superseded_fetch',receipt:'superseded_receipt'}
    ]){
      checkpoint('HANDOFF');await bind(bad.approval,bad.policy);await record(bad.prefix+'_bound');await prepare('准备抓取候选','fetch_handoff');await record(bad.prefix+'_prepared');await submit(bad.action)
      if(bad.prefix==='unknown')await settle();await record(bad.prefix+'_failed');if(bad.prefix==='unknown')await shot('unknown_failed')
      await readReceipt(bad.receipt,bad.action);await record(bad.receipt);await recover();await record(bad.prefix+'_recovered')
    }
    await readReceipt('cross_owner_receipt','approve_a_new');await record('cross_owner_denied');await recover();await record('cross_owner_recovered')
    checkpoint('API_SAMPLER');await sampler.sample('api_approve_denied',journal.facts);await record('api_approve_denied')
    checkpoint('HANDOFF');await bind('approve_a_new',1);await record('valid_handoff_bound');await prepare('准备抓取候选','fetch_handoff');await record('valid_handoff_prepared')
    checkpoint('FETCH');await submit('valid_fetch');await waitWire(12);await record('fetched_quarantined')
    {const n=journal.rows.filter(r=>r.kind==='NODES').length;await click(journal.facts.candidate.id,'candidate');await waitDOM(d=>d.candidates.some(c=>c.id===journal.facts.candidate.id&&c.selected)&&d.nodes.length===2&&journal.rows.filter(r=>r.kind==='NODES').length===n+1)}await record('nodes_quarantined')
    checkpoint('API_SAMPLER');{const row=await sampler.sample('api_stale_fetch',journal.facts);journal.facts.commands.api_stale_fetch={commandId:row.commandIdHeader,sourceId:journal.facts.sources.a,kind:'fetch',state:'failed',revision:1,auditRecorded:true,replayed:false,code:'subscription_command_conflict'}}await record('api_stale_conflict')
    await readReceipt('stale_receipt','api_stale_fetch');await record('stale_receipt_failed');await settle();await record('final_desktop');await viewport(375);await settle();await record('final_mobile');await shot('final_mobile')
    await click('运行总览');await waitDOM(d=>!d.pageVisible);await record('hidden');await click('订阅与提供者');await waitDOM(d=>d.pageVisible);await record('returned');await click('清除会话与令牌');actorRole='anonymous';await waitDOM(d=>!d.sources.length&&d.receipt===null);await record('cleared')
    need(domRows.map(v=>v.step).join(',')===STEPS.join(','));journal.complete();feedbackObserver.complete();const sample=await sampler.fence();need(sample.recordCount===2);await sampler.close()
checkpoint('CLOSE');if(context)await context.close();else await browserSend('Browser.close')
    let chromeExit;await until(async()=>{try{chromeExit=JSON.parse((await stableFile(o.root+'/chrome-exit.private.json',4096,true)).toString());return true}catch(e){if(e?.code==='ENOENT')return false;throw e}},20000)
    need(exact(chromeExit,['schema','engine','fixtureId','pid','startTicks','exitCode','joined','forced'])&&chromeExit.schema==='chengwang.subscription-ui-chrome-exit/v1'&&chromeExit.engine===o.engine&&chromeExit.fixtureId===o.fixtureId&&chromeExit.pid===chrome.pid&&chromeExit.startTicks===chrome.startTicks&&chromeExit.exitCode===0&&chromeExit.joined===true&&chromeExit.forced===false)
    let launcherExit=null;if(childResult){launcherExit=await Promise.race([childResult,delay(2000).then(()=>null)]);need(launcherExit?.code===0&&launcherExit.signal===null)}await until(()=>noLiveChrome(o,chrome),5000);closed=true;transport?.socket.close()

    const capturesRaw=Buffer.from([...journal.rows].sort((a,b)=>a.ordinal-b.ordinal).map(v=>JSON.stringify(v)).join('\n')+'\n'),domRaw=Buffer.from(domRows.map(v=>JSON.stringify(v)).join('\n')+'\n');publicFence(capturesRaw,canaries);publicFence(domRaw,canaries);const captures=await publish(o.root+'/captures.private.jsonl',capturesRaw,24<<20);await publish(o.root+'/dom.private.jsonl',domRaw,1<<20);captured=true
    const report={schema:C.driverSchema,scenario:SCENARIO,sourceCommit:o.sourceCommit,engine:o.engine,fixtureId:o.fixtureId,origin:ORIGIN,scope:SCOPE,runtime:true,mockedResponses:false,injectedFetch:false,tlsBypass:false,browser,chrome,normalTrust:{method:'PRIVATE_NSS_SQL_XDG_LOCAL_CA',trustFlags:'C,,',caSHA256:verified.caSHA256,leafSHA256:verified.leafSHA256,homeEnvironmentAbsent:true,legacyDatabaseAbsent:true},tls,certificateChain,counters:journal.counters,close:{normalCloseCommandCompleted:true,chromeExit,launcherExit,noLiveOwnedProcesses:true,processScope:'CHROME_SESSION_AND_LAUNCHER_ONLY'},steps:[...STEPS],captures:{path:'captures.jsonl',...captures,records:journal.rows.length},screenshots,apiSampler:{path:'api-sampler.jsonl',bytes:sample.bytes,sha256:sample.sha256,records:sample.recordCount,source:C.apiSamplerSource},production:false,fullSubscriptionE2EProven:false};publicFence(Buffer.from(JSON.stringify(report)),canaries);await publish(o.root+'/driver.private.json',report,65536);checkpoint('COMPLETE');return report
  }catch(error){await diagnostics.writeFailure(o.root,journal);throw error}
  finally{try{await sampler?.close()}catch{}if(!closed){try{if(context)await context.close();else if(browserSend)await browserSend('Browser.close')}catch{}transport?.socket.close()}if(!captured&&journal?.rows.length){try{const raw=Buffer.from([...journal.rows].sort((a,b)=>a.ordinal-b.ordinal).map(v=>JSON.stringify(v)).join('\n')+'\n');publicFence(raw,canaries);await publish(o.root+'/captures.private.jsonl',raw,24<<20)}catch{}}}
}
