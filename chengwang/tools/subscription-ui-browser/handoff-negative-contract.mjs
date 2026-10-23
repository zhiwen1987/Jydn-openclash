// Independent negative handoff policy. No old scenario acceptance is widened.
import C from './handoff-negative-contract.json' with {type:'json'}
import {ORIGIN,FAVICON,need,exact,integer,sha,assetPaths,decodeBody,parseArguments} from './ui-contract.mjs'
import {actorFor,secretVariants,publicFence,wireFence} from './remote-fetch-contract.mjs'
export {C,ORIGIN,FAVICON,need,exact,integer,sha,assetPaths,decodeBody,parseArguments,secretVariants,publicFence,wireFence}
export const SCENARIO=C.scenario,SCOPE=C.scope,STEPS=Object.freeze(C.steps),ROLES=Object.freeze(C.roles)
export const BROWSER_ACTIONS=Object.freeze(C.actions.filter(a=>a.origin==='browser'))
export function validatePrivateInput(v){
  need(exact(v,C.privateInputKeys)&&v.schema===C.inputSchema&&v.scenario===SCENARIO&&exact(v.labels,['a','b'])&&v.labels.a===C.labels.a&&v.labels.b===C.labels.b&&exact(v.tokens,ROLES))
  need(Object.values(v.tokens).every(x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x))&&new Set(Object.values(v.tokens)).size===2)
  need(Array.isArray(v.canaries)&&v.canaries.length===22&&new Set(v.canaries).size===22);secretVariants(v.canaries);return v
}
export function stepExpectation(step){need(STEPS.includes(step));return Object.fromEntries(C.stateColumns.map((key,i)=>[key,C.stepStates[step][i]]))}
export function commandFor(facts,key){return key==='unknown'?C.unknownApprovalId:facts.commands[key]?.commandId}
export function safeHeaders(entries){
  need(Array.isArray(entries)&&entries.length<=128);const seen=new Set(),h={}
  for(const pair of entries){need(Array.isArray(pair)&&pair.length===2&&typeof pair[0]==='string'&&typeof pair[1]==='string');const key=pair[0].toLowerCase();need(!seen.has(key));seen.add(key);need(key!=='set-cookie');if(['x-chengwang-command-id','x-chengwang-denial-audit'].includes(key)){need(!/[,\r\n]/.test(pair[1]));h[key]=pair[1]}}
  const commandIdHeader=h['x-chengwang-command-id']??null,denialAuditHeader=h['x-chengwang-denial-audit']??null
  need(commandIdHeader===null||/^cmd_[a-f0-9]{32}$/.test(commandIdHeader));need(denialAuditHeader===null||denialAuditHeader==='recorded');return{commandIdHeader,denialAuditHeader}
}
export function responseEnvelope(raw,action,headers){
  const x=JSON.parse(raw.toString('utf8'));need(exact(x,['boundary','authorization','deviceActionsExecuted','stateMayHaveChanged',action.code?'code':'result'])&&x.boundary==='LOCAL_SUBSCRIPTION_ADMISSION_ONLY'&&x.authorization==='BLOCKED'&&x.deviceActionsExecuted===false&&x.stateMayHaveChanged===false)
  if(action.code)need(x.code===action.code)
  if(action.key==='api_approve_denied')need(headers.commandIdHeader===null&&headers.denialAuditHeader==='recorded')
  else if(action.code&&action.kind)need(headers.commandIdHeader!==null&&headers.denialAuditHeader===null)
  else need(headers.commandIdHeader===null&&headers.denialAuditHeader===null)
  return x
}
export function requestProjection(request,assets,input,index,facts,receiptCase){
  need(request&&typeof request.url==='string'&&request.url.length<=1024&&['GET','POST'].includes(request.method));const u=new URL(request.url)
  need(u.href===request.url&&u.origin===ORIGIN&&!u.username&&!u.password&&!u.hash);const path=u.pathname+u.search,{role,headers:h}=actorFor(request.headers,input.tokens);let kind,sourceId=null,caseKey=null,requestPublic=null
  if(request.method==='GET'&&!u.search){if(path==='/')kind='DOCUMENT';else if(assets.includes(path))kind='ASSET';else if(path==='/api/v1/snapshot')kind='SNAPSHOT';else if(path==='/api/v1/subscriptions/access')kind='COLLECTION_ACCESS';else if(path==='/api/v1/subscriptions/sources')kind='SOURCES';else if(/^\/api\/v1\/subscriptions\/sources\/src_[a-f0-9]{32}\/access$/.test(path))kind='SOURCE_ACCESS';else if(/^\/api\/v1\/subscriptions\/commands\/cmd_[a-f0-9]{32}$/.test(path))kind='RECEIPT'}
  const page=/^\/api\/v1\/subscriptions\/sources\/(src_[a-f0-9]{32})\/candidates(?:\/(cand_[a-f0-9]{32})\/nodes)?\?limit=20&offset=0&revision=([12])$/.exec(path)
  if(request.method==='GET'&&page){kind=page[2]?'NODES':'CANDIDATES';sourceId=page[1];if(Object.keys(facts.sources).length===2)need(Object.values(facts.sources).includes(sourceId));if(page[2])need(page[2]===facts.candidate?.id)}
  const end=/^\/api\/v1\/subscriptions\/sources(?:\/(src_[a-f0-9]{32})\/(approvals|fetches))?$/.exec(path)
  if(request.method==='POST'&&end){kind=end[2]==='approvals'?'APPROVE':end[2]==='fetches'?'FETCH':'CREATE';sourceId=end[1]??null}
  need(kind);const auth=!['DOCUMENT','ASSET','SNAPSHOT'].includes(kind);need(auth?role!=='anonymous':role==='anonymous')
  if(request.method==='GET'){
    need(!request.hasPostData&&request.postData===undefined&&h['idempotency-key']===undefined)
    if(kind==='SOURCE_ACCESS'&&Object.keys(facts.sources).length===2)need(Object.values(facts.sources).some(id=>path==='/api/v1/subscriptions/sources/'+id+'/access'))
    if(kind==='RECEIPT'){need(receiptCase&&role===receiptCase.actorRole&&path==='/api/v1/subscriptions/commands/'+commandFor(facts,receiptCase.commandKey));caseKey=receiptCase.key}
  }else{
    const a=BROWSER_ACTIONS[index];need(a&&a.actorRole===role&&a.kind.toUpperCase()===kind&&h['content-type']==='application/json'&&/^sub_[a-f0-9]{32}$/.test(h['idempotency-key']))
    need(typeof request.postData==='string'&&Buffer.byteLength(request.postData)<=2048);const b=JSON.parse(request.postData),idempotencyKey=h['idempotency-key'];caseKey=a.key
    if(kind==='CREATE'){need(exact(b,['label'])&&b.label===input.labels[a.source]);requestPublic={label:b.label,idempotencyKey}}
    else{need(sourceId===facts.sources[a.source]&&b.expectedRevision===a.expectedRevision);if(kind==='APPROVE')need(exact(b,['expectedRevision','referenceId','policyRevision'])&&b.referenceId===a.referenceId&&b.policyRevision===a.policyRevision);else need(exact(b,['expectedRevision','approvalId','policyRevision'])&&b.approvalId===commandFor(facts,a.approvalKey)&&b.policyRevision===a.policyRevision);requestPublic={sourceId,...b,idempotencyKey}}
  }
  return{method:request.method,path,kind,authorizationPresent:auth,actorRole:role,caseKey,requestPublic}
}
export function learnAction(facts,a,raw,headers){
  const x=responseEnvelope(raw,a,headers);need(!facts.commands[a.key]);if(a.code){facts.commands[a.key]={commandId:headers.commandIdHeader,sourceId:facts.sources[a.source],kind:a.kind,state:'failed',revision:a.revision,auditRecorded:true,replayed:false,code:a.code};return}
  const r=x.result;need(r&&r.kind===a.kind&&r.state===(a.kind==='approve'?'approved':'committed')&&r.revision===a.revision&&r.auditRecorded===true&&r.replayed===false&&r.stateMayHaveChanged===false&&/^cmd_[a-f0-9]{32}$/.test(r.commandId)&&/^src_[a-f0-9]{32}$/.test(r.sourceId)&&r.commandId!==C.unknownApprovalId)
  if(a.kind==='create'){need(!facts.sources[a.source]&&!Object.values(facts.sources).includes(r.sourceId));facts.sources[a.source]=r.sourceId}else need(r.sourceId===facts.sources[a.source])
  if(a.kind==='approve')need(r.approvalId===r.commandId&&r.referenceId===a.referenceId&&r.policyRevision===a.policyRevision&&/^hmac-sha256:[a-f0-9]{64}$/.test(r.policyDigest))
  if(a.kind==='fetch'){need(/^cand_[a-f0-9]{32}$/.test(r.candidateId)&&/^hmac-sha256:[a-f0-9]{64}$/.test(r.candidateDigest));facts.candidate={id:r.candidateId,digest:r.candidateDigest}}
  facts.commands[a.key]=r
}
export function validateStep(step,d,count,role,facts,wire,sampler){
  const e=stepExpectation(step);need(count===e.browserPosts&&role===e.actorRole&&wire.eventCount===e.wireEvents&&sampler.recordCount===e.samplerRecords)
  need(d.pageMounted&&d.pageVisible===(step!=='hidden')&&d.https&&d.alertVisible===e.alert&&d.session.tokenType==='password'&&d.session.tokenEmpty&&d.session.fileEmpty&&d.session.storageEmpty&&d.session.cookiesEmpty&&d.stale.sources===e.staleSources&&d.stale.candidates===e.staleCandidates&&!d.stale.nodes)
  const absent=['anonymous','operator_connected','create_a_prepared','cleared'].includes(step),keys=absent?[]:['a','b'].filter(k=>(k==='a'?e.revisionA:e.revisionB)>0)
  need(d.sources.length===keys.length);for(const k of keys){const s=d.sources.find(v=>v.id===facts.sources[k]);need(s&&s.revision===(k==='a'?e.revisionA:e.revisionB)&&s.selected===(k===e.selectedSource)&&!s.accepted)}
  need(d.mode===e.mode&&(d.confirmation?.kind??null)===e.dialog)
  if(e.selectedSource===null)need(d.directory.references.length===0);else{need(JSON.stringify(d.directory.references.map(({referenceId,revision})=>({referenceId,revision})))===JSON.stringify(C.references));need(d.directory.references.filter(v=>v.selected).length===1&&d.directory.references.find(v=>v.selected).referenceId===e.reference)}
  if(e.approvalKey)need(d.sessionApproval?.approvalId===commandFor(facts,e.approvalKey)&&d.sessionApproval.referenceId===C.actions.find(a=>a.key===e.approvalKey).referenceId&&d.sessionApproval.policyRevision===1);else need(d.sessionApproval===null)
  if(e.handoffKey)need(d.handoff?.unverifiedReferenceNotice&&d.handoff.approvalValid&&d.handoff.revisionValid&&d.handoff.approvalId===commandFor(facts,e.handoffKey)&&d.handoff.policyRevision===e.handoffPolicy);else need(d.handoff===null)
  if(e.dialog==='fetch_handoff')need(d.confirmation.unverifiedReference&&exact(d.confirmation.binding,['sourceId','expectedRevision','approvalId','policyRevision'])&&d.confirmation.binding.sourceId===facts.sources.a&&d.confirmation.binding.expectedRevision===1&&d.confirmation.binding.approvalId===commandFor(facts,e.handoffKey)&&d.confirmation.binding.policyRevision===e.handoffPolicy)
  const fetched=e.revisionA===2&&step!=='cleared';need(d.candidates.length===(fetched?1:0));if(fetched){const c=d.candidates[0];need(c.id===facts.candidate.id&&c.baseRevision===2&&c.nodeCount===2&&c.state==='quarantined'&&c.selected===e.candidateSelected)}
  need(d.nodes.length===(e.candidateSelected?2:0)&&d.nodes.every(n=>n.state==='unknown'&&n.credentialConfigured))
  if(e.receiptKey){const r=facts.commands[e.receiptKey];need(d.receipt?.commandId===r.commandId&&d.receipt.revision===r.revision&&d.receipt.state===r.state&&d.receipt.auditRecorded&&!d.receipt.replayed)}else need(d.receipt===null)
  if(role==='operator')need(!d.controls.find(v=>v.key==='prepare_approve')?.enabled)
  if(['unknown_failed','final_desktop','final_mobile'].includes(step))need(d.viewport.width===(step==='final_mobile'?375:1440)&&d.viewport.height===900&&d.viewport.scrollWidth===d.viewport.clientWidth&&d.viewport.scrollX===0&&d.viewport.scrollY===0&&d.boundaryVisible)
  return d
}
export class HandoffNegativeJournal{
  constructor(assets,input,reader){this.assets=assets;this.input=input;this.bodyReader=reader;this.facts={sources:{},candidate:null,commands:{}};this.canaries=secretVariants([...Object.values(input.tokens),...input.canaries]);this.requests=new Map();this.ignored=new Set();this.rows=[];this.tasks=new Set();this.failure=false;this.totalBytes=0;this.finished=0;this.receiptCase=null;this.counters={runtimeErrors:0,consoleErrors:0,consoleWarnings:0,cspErrors:0,assetErrors:0,forbiddenRequests:0,failedRequests:0,captureErrors:0}}
  armReceipt(key){need(this.receiptCase===null);this.receiptCase=C.receiptCases.find(v=>v.key===key);need(this.receiptCase)}
  reject(){this.failure=true;this.counters.captureErrors++}
  handle(method,p){try{
    if(method==='Runtime.exceptionThrown')this.counters.runtimeErrors++
    if(method==='Runtime.consoleAPICalled'&&p.type==='error')this.counters.consoleErrors++
    if(method==='Runtime.consoleAPICalled'&&['warning','warn'].includes(p.type))this.counters.consoleWarnings++
    if(method==='Log.entryAdded'&&p.entry?.source==='security'&&p.entry.level==='error')this.counters.cspErrors++
    if(['Network.webSocketCreated','Network.webTransportCreated','Network.directTCPSocketCreated'].includes(method))this.counters.forbiddenRequests++
    if(method==='Network.requestWillBeSent'){
      if(p.request?.url===FAVICON){need(this.ignored.size<4);this.ignored.add(p.requestId);return}
      let v;try{v=requestProjection(p.request,this.assets,this.input,this.mutationCount(),this.facts,this.receiptCase)}catch{this.counters.forbiddenRequests++;throw Error()}
      need(!p.redirectResponse&&this.requests.size<C.maxRequests&&!this.requests.has(p.requestId)&&/^[A-Za-z0-9_.-]{1,80}$/.test(p.requestId));const receipt=v.kind==='RECEIPT'?this.receiptCase:null;if(receipt)this.receiptCase=null
      const micros=x=>{need(typeof x==='number'&&Number.isFinite(x)&&x>=0&&x<=Number.MAX_SAFE_INTEGER/1e6);return Math.floor(x*1e6)}
      this.requests.set(p.requestId,{...v,receipt,action:v.method==='POST'?BROWSER_ACTIONS[this.mutationCount()]:null,requestId:p.requestId,requestOrdinal:this.requests.size+1,startedWallTimeUs:micros(p.wallTime),startTimeUs:micros(p.timestamp),response:null,terminal:false})
    }
    if(this.ignored.has(p.requestId))return
    if(method==='Network.responseReceived'){
      const r=p.response,v=this.requests.get(p.requestId);need(v&&!v.response&&!v.terminal&&r&&r.url===ORIGIN+v.path&&!r.fromDiskCache&&!r.fromServiceWorker)
      const expected=v.action??v.receipt??{status:200};need(r.status===expected.status);v.safe=safeHeaders(Object.entries(r.headers??{}));if(!v.action&&!v.receipt)need(v.safe.commandIdHeader===null&&v.safe.denialAuditHeader===null)
      if(v.kind==='ASSET'){const types=v.path.endsWith('.js')?['text/javascript','application/javascript']:v.path.endsWith('.css')?['text/css']:v.path.endsWith('.svg')?['image/svg+xml']:v.path.endsWith('.png')?['image/png']:v.path.endsWith('.woff2')?['font/woff2']:v.path.endsWith('.woff')?['font/woff']:['font/ttf'];if(!types.includes(r.mimeType))this.counters.assetErrors++}
      else need(r.mimeType===(v.kind==='DOCUMENT'?'text/html':'application/json'));v.response=r;v.headerTimeUs=Math.floor(p.timestamp*1e6);need(integer(v.headerTimeUs,v.startTimeUs))
    }
    if(method==='Network.loadingFailed'){need(this.requests.has(p.requestId));this.requests.get(p.requestId).terminal=true;this.counters.failedRequests++;this.failure=true}
    if(method==='Network.loadingFinished'){const v=this.requests.get(p.requestId);need(v&&v.response&&!v.terminal&&integer(p.encodedDataLength,0,16<<20));v.terminal=true;v.endTimeUs=Math.floor(p.timestamp*1e6);need(integer(v.endTimeUs,v.startTimeUs));const ordinal=++this.finished,task=this.capture(v,ordinal,p.encodedDataLength).catch(()=>this.reject()).finally(()=>this.tasks.delete(task));this.tasks.add(task)}
  }catch{this.reject()}}
  async capture(v,ordinal,encodedDataLength){
    const raw=decodeBody(await this.bodyReader(v.requestId),['DOCUMENT','ASSET'].includes(v.kind)?C.assetBodyLimitBytes:C.bodyLimitBytes);publicFence(raw,this.canaries);this.totalBytes+=raw.length;need(this.totalBytes<=C.maxCapturedDecodedBytes)
    const row={schema:C.captureSchema,ordinal,requestOrdinal:v.requestOrdinal,requestId:v.requestId,method:v.method,path:v.path,kind:v.kind,status:v.response.status,authorizationPresent:v.authorizationPresent,actorRole:v.actorRole,caseKey:v.caseKey,requestPublic:v.requestPublic,...v.safe,responseBase64:raw.toString('base64'),responseSHA256:sha(raw),responseBytes:raw.length,startedWallTimeUs:v.startedWallTimeUs,startTimeUs:v.startTimeUs,headerTimeUs:v.headerTimeUs,endTimeUs:v.endTimeUs,terminal:{event:'FINISH',encodedDataLength}}
    publicFence(Buffer.from(JSON.stringify(row)),this.canaries);if(v.action)learnAction(this.facts,v.action,raw,v.safe)
    if(v.receipt){const x=responseEnvelope(raw,v.receipt,v.safe);if(v.receipt.status===200){const r=x.result,f=this.facts.commands[v.receipt.commandKey];need(r?.commandId===f.commandId&&r.state===f.state&&r.revision===f.revision&&r.auditRecorded===true&&r.replayed===false)}}
    this.rows.push(row)
  }
  mutationCount(){return [...this.requests.values()].filter(v=>v.method==='POST').length}
  idle(){return this.tasks.size===0&&[...this.requests.values()].every(v=>v.terminal)}
  complete(){need(!this.failure&&this.idle()&&this.receiptCase===null&&this.rows.length===this.requests.size&&this.finished===this.rows.length&&Object.values(this.counters).every(v=>v===0)&&this.mutationCount()===10&&Object.keys(this.facts.commands).length===11&&this.facts.candidate&&Object.keys(this.facts.sources).length===2);need(this.rows.filter(v=>v.kind==='RECEIPT').length===6);need(new Set(this.rows.filter(v=>v.method==='POST').map(v=>v.requestPublic.idempotencyKey)).size===10);need(this.rows.filter(v=>v.kind==='DOCUMENT').length===1&&this.rows.filter(v=>v.kind==='SNAPSHOT').length===1&&this.rows.some(v=>v.kind==='ASSET'));for(const row of this.rows){const p=/^\/api\/v1\/subscriptions\/sources\/(src_[a-f0-9]{32})(?:\/candidates\/(cand_[a-f0-9]{32})\/nodes)?/.exec(row.path);if(p)need(Object.values(this.facts.sources).includes(p[1])&&(!p[2]||p[2]===this.facts.candidate.id))}}
}
