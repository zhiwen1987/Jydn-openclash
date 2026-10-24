import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { loadContract, manifestGraph, sha, canaryVariants, FAVICON } from './ui-contract.mjs'
import { CapabilityJournal, configureNativeLocale, clickExpression, FAILURE_OPERATIONS, failureObservation } from './ui-driver.mjs'
const c=loadContract(await readFile(new URL('../../deploy/capability-truth-browser/contract.json',import.meta.url)))
const graph=manifestGraph({'index.html':{file:'assets/main.js',isEntry:true}},c)
const canaries=canaryVariants('c'.repeat(64)), body=Buffer.from('actual-static-body')
const files=new Map([['index.html',{bytes:body.length,sha256:sha(body)}],['assets/main.js',{bytes:body.length,sha256:sha(body)}]])
function make(reader=async()=>({body:body.toString(),base64Encoded:false}),contract=c){return new CapabilityJournal(contract,graph,canaries,reader,files)}
function req(j,id='private.opaque/123',path='/',change={}){j.handle('Network.requestWillBeSent',{requestId:id,wallTime:1,timestamp:1,request:{url:c.origin+path,method:'GET',headers:{},...change}})}
function headers(j,id='private.opaque/123',path='/',mimeType='text/html',change={}){j.handle('Network.responseReceived',{requestId:id,timestamp:1.1,response:{url:c.origin+path,status:200,mimeType,headers:{},...change}})}
function finish(j,id='private.opaque/123',change={}){j.handle('Network.loadingFinished',{requestId:id,timestamp:1.2,encodedDataLength:3,...change})}
async function drain(j){await Promise.all([...j.tasks])}
async function full(){const j=make();for(const [i,path,mime] of [[1,'/','text/html'],[2,'/assets/main.js','text/javascript'],[3,'/api/v1/snapshot','application/json'],[4,'/api/v1/capabilities','application/json'],[5,'/api/v1/capabilities','application/json']]){const id='raw-'+i;req(j,id,path);headers(j,id,path,mime);finish(j,id)}await drain(j);return j}

test('journal records anonymous same-session aliases only',async()=>{const j=make();req(j);headers(j);finish(j);await drain(j);assert.equal(j.rows[0].requestId,'r1');assert(!JSON.stringify(j.events).includes('private.opaque'));assert.deepEqual(j.events.map(e=>e.type),['REQUEST','HEADERS','FINISH','CAPTURE'])})
test('completion ordinal follows FINISH rather than body promise order',async()=>{const resolves=[];const j=make(()=>new Promise(r=>resolves.push(r)));req(j,'a');headers(j,'a');req(j,'b','/api/v1/snapshot');headers(j,'b','/api/v1/snapshot','application/json');finish(j,'a');finish(j,'b');resolves[1]({body:'second',base64Encoded:false});resolves[0]({body:body.toString(),base64Encoded:false});await drain(j);assert.equal(j.rows.find(r=>r.requestId==='r1').ordinal,1);assert.equal(j.rows.find(r=>r.requestId==='r2').ordinal,2)})
test('normal synthetic graph closes with unique last META but proves no browser',async()=>{const j=await full();j.finalize();assert.equal(j.events.at(-1).type,'META');assert.equal(j.events.at(-1).requests,5);assert.equal(j.events.at(-1).mutations,0);assert.equal(j.events.filter(e=>e.type==='META').length,1);assert.throws(()=>j.finalize())})
test('duplicate request identity fails instead of replacing first alias',()=>{const j=make();req(j);req(j);assert(j.failure);assert.equal(j.requests.size,1);assert.equal(j.counters.captureErrors,1)})
test('duplicate headers and missing request fail closed',()=>{for(const mode of ['duplicate','missing']){const j=make();if(mode==='duplicate'){req(j);headers(j)}headers(j);assert(j.failure)}})
test('FINISH requires headers and cannot repeat',async()=>{const a=make();req(a);finish(a);assert(a.failure);const b=make();req(b);headers(b);finish(b);finish(b);await drain(b);assert(b.failure)})
test('failed request has explicit NET_FAIL terminal and nonzero eighth counter',()=>{const j=make();req(j);j.handle('Network.loadingFailed',{requestId:'private.opaque/123'});assert.equal(j.events.at(-1).type,'NET_FAIL');assert.equal(j.counters.failedRequests,1);assert.throws(()=>j.complete())})
test('unknown failure alias is rejected without raw ID export',()=>{const j=make();j.handle('Network.loadingFailed',{requestId:'secret-sensitive'});assert(j.failure);assert(!JSON.stringify(j.events).includes('secret-sensitive'))})
test('HTTP error or wrong asset MIME retains failure',()=>{for(const change of [{status:404},{mimeType:'text/html'}]){const j=make();req(j,'a','/assets/main.js');headers(j,'a','/assets/main.js','text/javascript',change);assert(j.failure);assert.equal(j.counters.assetErrors,1)}})
test('response SetCookie redirect disk and serviceworker flags fail',()=>{for(const change of [{headers:{'Set-Cookie':'private'}},{url:'https://foreign.invalid/'},{fromDiskCache:true},{fromServiceWorker:true},{fromPrefetchCache:true}]){const j=make();req(j);headers(j,undefined,undefined,undefined,change);assert(j.failure);assert(!JSON.stringify(j.events).includes('private\"'))}})
test('forbidden method cookie auth body and origin cannot close',()=>{for(const change of [{method:'POST'},{headers:{Cookie:'x'}},{headers:{Authorization:'x'}},{postData:'x'},{url:'https://example.com/'}]){const j=make();req(j,undefined,undefined,change);assert(j.failure);assert(j.counters.forbiddenRequests>0)}})
test('request redirect metadata is rejected even on safe URL',()=>{const j=make();j.handle('Network.requestWillBeSent',{requestId:'x',timestamp:1,wallTime:1,redirectResponse:{status:302},request:{url:c.origin+'/',method:'GET',headers:{}}});assert(j.failure)})
test('runtime console CSP and socket errors are safe closed tags',()=>{for(const [method,params,key] of [['Runtime.exceptionThrown',{},'runtimeErrors'],['Runtime.consoleAPICalled',{type:'error'},'consoleErrors'],['Runtime.consoleAPICalled',{type:'warning'},'consoleWarnings'],['Log.entryAdded',{entry:{source:'security',level:'error',text:'secret'}},'cspErrors'],['Network.webSocketCreated',{},'forbiddenRequests']]){const j=make();j.handle(method,params);assert.equal(j.counters[key],1);assert(!JSON.stringify(j.events).includes('secret'))}})
test('event overflow rejects rather than truncating into success',()=>{const reduced=structuredClone(c);reduced.captureRules.bounds.events=1;const j=make(undefined,reduced);req(j);headers(j);assert(j.overflow);assert(j.failure);assert.throws(()=>j.finalize())})
test('incomplete active body task cannot pass complete',()=>{const j=make(()=>new Promise(()=>{}));req(j);headers(j);finish(j);assert.equal(j.tasks.size,1);assert.throws(()=>j.complete())})
test('asset bytes must match actual build inventory',async()=>{const j=make(async()=>({body:'changed static',base64Encoded:false}));req(j);headers(j);finish(j);await drain(j);assert(j.failure);assert.equal(j.rows.length,0)})
test('body retrieval rejection preserves capture failure',async()=>{const j=make(async()=>{throw Error('raw secret')});req(j);headers(j);finish(j);await drain(j);assert(j.failure);assert.equal(j.events.at(-1).code,'capture_error');assert(!JSON.stringify(j.events).includes('raw secret'))})
test('secret response variants never enter public rows',async()=>{const j=make(async()=>({body:canaries[0],base64Encoded:false}));req(j);headers(j);finish(j);await drain(j);assert(j.failure);assert.equal(j.rows.length,0)})
test('response body API byte bound is enforced',async()=>{const j=make(async()=>({body:'a'.repeat(c.captureRules.bounds.bodyAPI+1),base64Encoded:false}));req(j,'x','/api/v1/snapshot');headers(j,'x','/api/v1/snapshot','application/json');finish(j,'x');await drain(j);assert(j.failure)})
test('favicon exception accepts only exact fixed data literal',()=>{const j=make();j.handle('Network.requestWillBeSent',{requestId:'f',request:{url:FAVICON}});assert.equal(j.ignored.size,1);assert.equal(j.requests.size,0);req(j,'x','/favicon.ico');assert(j.failure)})
test('close check rejects absent second actual capabilities request',async()=>{const j=await full();j.rows.pop();assert.throws(()=>j.complete())})
test('native locale uses actual UA plus three protocol methods',async()=>{const calls=[];await configureNativeLocale(async(m,p)=>calls.push([m,p]),'observed-UA');assert.deepEqual(calls,[['Emulation.setUserAgentOverride',{userAgent:'observed-UA',acceptLanguage:'zh-CN'}],['Emulation.setLocaleOverride',{locale:'zh-CN'}],['Emulation.setTimezoneOverride',{timezoneId:'UTC'}]])})
test('native locale protocol rejection is never ignored',async()=>{await assert.rejects(configureNativeLocale(async()=>{throw Error('not supported')},'observed-UA'));await assert.rejects(configureNativeLocale(async()=>{},''))})
test('native click expression only permits four actual controls',()=>{assert(clickExpression('nav_capabilities',c).includes("getAttribute('aria-label')"));assert(clickExpression('refresh_capabilities',c).includes('elementFromPoint'));assert.throws(()=>clickExpression('kernel_import',c));assert.throws(()=>clickExpression('arbitrary selector',c))})
test('real driver and CLI imports perform no launch or stdout side effects',()=>{const driver=fileURLToPath(new URL('./ui-driver.mjs',import.meta.url)),cli=fileURLToPath(new URL('./ui-cli.mjs',import.meta.url));for(const file of [driver,cli]){const r=spawnSync(process.execPath,['--input-type=module','-e',`await import(${JSON.stringify(pathToFileURL(file).href)})`],{encoding:'utf8',timeout:10000});assert.equal(r.status,0,r.stderr);assert.equal(r.stdout,'');assert.equal(r.stderr,'')}})
test('CLI rejects malformed args with fixed safe error only',()=>{const r=spawnSync(process.execPath,[fileURLToPath(new URL('./ui-cli.mjs',import.meta.url)),'raw-secret-token'],{encoding:'utf8',timeout:10000});assert.equal(r.status,1);assert.equal(r.stdout,'');assert.equal(r.stderr,'CAPABILITY_TRUTH=REJECTED raw_input_suppressed=true\n')})

test('failure observation uses explicit v2 without changing success event schemas',async()=>{
  assert.equal(FAILURE_OPERATIONS.length,41);assert.equal(new Set(FAILURE_OPERATIONS).size,41);assert(Object.isFrozen(FAILURE_OPERATIONS))
  const missing=failureObservation('NAVIGATE','GOTO',undefined,false)
  assert.deepEqual(Object.keys(missing).sort(),['schema','stage','production','normalCloseCompleted','events','captures','failed','operation','firstFailure','counters'].sort())
  assert.equal(missing.schema,'chengwang.capability-truth-driver-failure/v2');assert.equal(missing.firstFailure,null);assert.equal(missing.counters,null)
  const j=await full();j.finalize();assert.equal(j.firstFailure,null)
  assert.deepEqual(Object.keys(j.events.at(-1)).sort(),[...c.nestedExactKeys['driver.events.META']].sort())
  for(const e of j.events)assert.deepEqual(Object.keys(e).sort(),[...c.nestedExactKeys['driver.events.'+e.type]].sort())
  assert(!j.events.some(e=>Object.hasOwn(e,'operation')||Object.hasOwn(e,'firstFailure')))
})

test('first journal failure is immutable and never copies private identities',()=>{
  const j=make();j.handle('Runtime.exceptionThrown',{exceptionDetails:{text:'PRIVATE_EXCEPTION',url:'PRIVATE_URL',stackTrace:'PRIVATE_STACK'}})
  const first=j.firstFailure;j.handle('Runtime.consoleAPICalled',{type:'error',args:[{value:'PRIVATE_CONSOLE'}]})
  assert.equal(j.firstFailure,first);assert(Object.isFrozen(first))
  assert.deepEqual(first,{operation:'RUNTIME_EVENT',code:'runtime_error',requestId:null,kind:null})
  const d=failureObservation('NAVIGATE','SNAPSHOT_WAIT',j,false);assert.equal(d.counters.runtimeErrors,1);assert.equal(d.counters.consoleErrors,1)
  assert(!JSON.stringify(d).includes('PRIVATE_'));j.counters.runtimeErrors=2;assert.equal(d.counters.runtimeErrors,1)
  const unsafe=make();unsafe.reject('forbidden_request',{requestId:'PRIVATE_CDP_ID',kind:'PRIVATE_KIND'},'PRIVATE_OPERATION')
  const safe=failureObservation('NAVIGATE','GOTO',unsafe,false);assert.deepEqual(safe.firstFailure,{operation:'UNCLASSIFIED',code:'forbidden_request',requestId:null,kind:null});assert(!JSON.stringify(safe).includes('PRIVATE_'))
  const net=make();req(net);net.handle('Network.loadingFailed',{requestId:'private.opaque/123',errorText:'PRIVATE_NETWORK_ERROR'})
  const failure=failureObservation('NAVIGATE','SNAPSHOT_WAIT',net,false);assert.equal(failure.firstFailure.code,'net_fail');assert.equal(failure.firstFailure.operation,'EVENT_FAILURE');assert.equal(failure.counters.failedRequests,1)
})

test('request header and finish time rejection have separate operations',()=>{
  const request=make();request.handle('Network.requestWillBeSent',{requestId:'PRIVATE_ID',timestamp:1,request:{url:c.origin+'/',method:'GET',headers:{}}})
  assert.equal(request.firstFailure.operation,'EVENT_REQUEST_TIME')
  const header=make();req(header);header.handle('Network.responseReceived',{requestId:'private.opaque/123',timestamp:0.5,response:{url:c.origin+'/',status:200,mimeType:'text/html',headers:{}}})
  assert.equal(header.firstFailure.operation,'EVENT_HEADERS_TIME')
  const finished=make();req(finished);headers(finished);finish(finished,'private.opaque/123',{timestamp:0.95})
  assert.equal(finished.firstFailure.operation,'EVENT_FINISH_TIME')
  const structural=make();req(structural);finish(structural);assert.equal(structural.firstFailure.operation,'EVENT_FINISH')
  const event=make(),emit=event.emit.bind(event);event.emit=(type,fields)=>{if(type==='FINISH')throw Error('PRIVATE_EVENT');return emit(type,fields)}
  req(event);headers(event);finish(event);assert.equal(event.firstFailure.operation,'EVENT_FINISH')
  for(const j of [request,header,finished,structural,event]){assert(j.failure);assert.equal(j.counters.captureErrors,1);assert(!JSON.stringify(failureObservation('NAVIGATE','SNAPSHOT_WAIT',j,false)).includes('PRIVATE_ID'))}
  for(const timestamp of [undefined,null,'1.2',NaN,Infinity,-1,1e10]){const j=make();req(j);headers(j);finish(j,'private.opaque/123',{timestamp});assert(j.failure);assert.equal(j.firstFailure.operation,'EVENT_FINISH_TIME');assert.equal(j.rows.length,0);assert.equal(j.counters.captureErrors,1)}
})

test('same-session network completion may precede CDP response event observation time',async()=>{
  const j=make();req(j);headers(j);finish(j,'private.opaque/123',{timestamp:1.05});await drain(j)
  assert.equal(j.failure,false);assert.equal(j.firstFailure,null);assert.equal(j.rows.length,1)
  const row=j.rows[0];assert(row.endTimeUs>=row.startTimeUs);assert(row.headerTimeUs>=row.startTimeUs);assert(row.endTimeUs<row.headerTimeUs)
  assert.deepEqual(j.events.map(e=>e.type),['REQUEST','HEADERS','FINISH','CAPTURE']);assert(Object.values(j.counters).every(v=>v===0))
  assert.equal(row.requestId,'r1');assert.equal(row.responseSHA256,sha(body));assert.equal(row.responseBytes,body.length)
})

test('capture failure operations distinguish read decode fence and build binding',async()=>{
  const changed={...c,exactKeySchemas:{...c.exactKeySchemas,'captures.jsonl[]':[...c.exactKeySchemas['captures.jsonl[]'],'missing']}}
  const cases=[
    ['BODY_READ',async()=>{throw Error('PRIVATE_BODY_READ')},c],
    ['BODY_DECODE',async()=>({body:'PRIVATE_BODY',base64Encoded:'PRIVATE_TYPE'}),c],
    ['BODY_FENCE',async()=>({body:canaries[0],base64Encoded:false}),c],
    ['BODY_BUILD_BINDING',async()=>({body:'different-static-build-bytes',base64Encoded:false}),c],
    ['CAPTURE_ROW',async()=>({body:body.toString(),base64Encoded:false}),changed],
  ]
  for(const [operation,reader,contract]of cases){const j=make(reader,contract);req(j);headers(j);finish(j);await drain(j);const d=failureObservation('NAVIGATE','SNAPSHOT_WAIT',j,false);assert.equal(d.firstFailure.operation,operation);assert.equal(d.firstFailure.code,'capture_error');assert.equal(d.counters.captureErrors,1);assert(j.failure);assert(!JSON.stringify(d).includes('PRIVATE_'))}
  const j=make(),emit=j.emit.bind(j);j.emit=(type,fields)=>{if(type==='CAPTURE')throw Error('PRIVATE_EMIT');return emit(type,fields)}
  req(j);headers(j);finish(j);await drain(j);assert.equal(j.firstFailure.operation,'CAPTURE_EVENT');assert.equal(j.counters.captureErrors,1)
})

test('failure counters become unavailable without clamping or invented zeroes',()=>{
  const fresh=make();assert.deepEqual(failureObservation('NAVIGATE','GOTO',fresh,false).counters,Object.fromEntries(c.eightZero.map(k=>[k,0])))
  for(const invalid of [-1,513,true,NaN]){const j=make();j.reject('capture_error');j.counters.captureErrors=invalid;const d=failureObservation('NAVIGATE','SNAPSHOT_WAIT',j,false);assert.equal(d.counters,null);assert.equal(d.firstFailure.code,'capture_error')}
  const extra=make();extra.counters.PRIVATE_COUNTER=1;assert.equal(failureObservation('NAVIGATE','GOTO',extra,false).counters,null)
  const missing=make();delete missing.counters.captureErrors;assert.equal(failureObservation('NAVIGATE','GOTO',missing,false).counters,null)
  const inconsistent=make();inconsistent.rememberFailure('capture_error',null,'BODY_READ');assert.equal(failureObservation('NAVIGATE','SNAPSHOT_WAIT',inconsistent,false).counters,null)
})

test('failure projection rejects unknown operation code kind and alias',()=>{
  assert.throws(()=>failureObservation('PRIVATE_STAGE','GOTO',undefined,false));assert.throws(()=>failureObservation('NAVIGATE','PRIVATE_OPERATION',undefined,false))
  for(const change of [{operation:'PRIVATE_OPERATION'},{code:'PRIVATE_CODE'},{code:{toString:()=> 'capture_error'}},{requestId:'PRIVATE_ID'},{requestId:'r69'},{kind:'PRIVATE_KIND'},{rawError:'PRIVATE_ERROR'}]){
    const j=make();j.firstFailure={operation:'BODY_READ',code:'capture_error',requestId:'r1',kind:'DOCUMENT',...change};j.counters.captureErrors=1
    assert.throws(()=>failureObservation('NAVIGATE','SNAPSHOT_WAIT',j,false),e=>e.message==='capability truth rejected')
  }
  const coercible={toString:()=> 'capture_error'};assert.throws(()=>make().rememberFailure(coercible,null,'BODY_READ'));assert.throws(()=>make().reject(coercible))
  const j=make();j.firstFailure={operation:'BODY_READ',code:'capture_error',requestId:'r68',kind:null};j.counters.captureErrors=1
  const d=failureObservation('NAVIGATE','DOM_READ',j,false);assert.equal(d.firstFailure.requestId,'r68');assert.equal(d.firstFailure.kind,null);assert.notEqual(d.firstFailure.operation,d.operation)
})
