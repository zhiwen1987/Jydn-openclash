// Independent remote-fetch slice. Pure on import; old scenario policies stay closed.
import { ORIGIN,FAVICON,need,exact,integer,sha,assetPaths,decodeBody,parseArguments,canaryVariants } from './ui-contract.mjs'
export { ORIGIN,FAVICON,need,exact,integer,sha,assetPaths,decodeBody,parseArguments }
export const SCENARIO='remote_fetch'
export const SCOPE='REAL_PRODUCT_REMOTE_FETCH_APPROVAL_HANDOFF_PARTIAL_FULL_SUBSCRIPTION_PLAN_PENDING'
export const LABEL='browser-remote-source'
export const ROLES=Object.freeze(['operator','approver'])
export const REFERENCES=Object.freeze([{referenceId:'good-a',revision:1},{referenceId:'good-b',revision:1}])
export const STEPS=Object.freeze(['anonymous','operator_connected','create_prepared','created','approver_source','approve_b_prepared','approve_b_cancelled','approve_b_prepared_again','approved_b','approval_refreshed','reference_a_cleared','operator_source','handoff_empty','handoff_bound','fetch_prepared','fetch_cancelled','fetch_prepared_before_edit','handoff_edited','fetch_prepared_before_mode','session_mode_cleared','handoff_returned','fetch_prepared_final','fetched_quarantined','approver_candidate','admit_prepared','admitted','nodes_admitted','final_desktop','final_mobile','receipt','hidden','returned','cleared'])
export const ACTIONS=Object.freeze([{key:'create_source',role:'operator',kind:'create',fromRevision:0,toRevision:1},{key:'approve_b',role:'approver',kind:'approve',referenceId:'good-b',policyRevision:1,fromRevision:1,toRevision:1},{key:'fetch_b',role:'operator',kind:'fetch',fromRevision:1,toRevision:2},{key:'admit_fetched',role:'approver',kind:'decide',decision:'admitted_local',fromRevision:2,toRevision:3}])
export function secretVariants(secrets){need(Array.isArray(secrets)&&secrets.length>0&&secrets.length<=128);return [...new Set(secrets.flatMap(canaryVariants))]}
export function publicFence(raw,canaries){need(Buffer.isBuffer(raw)&&Array.isArray(canaries)&&canaries.length>0);for(const s of canaries)need(!raw.includes(Buffer.from(s)));return raw}
export function validatePrivateInput(v){
  need(exact(v,['schema','scenario','tokens','label','canaries'])&&v.schema==='chengwang.remote-fetch-ui-input/v1'&&v.scenario===SCENARIO&&v.label===LABEL&&exact(v.tokens,ROLES))
  need(Object.values(v.tokens).every(x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x))&&new Set(Object.values(v.tokens)).size===2)
  need(Array.isArray(v.canaries)&&v.canaries.length===22&&new Set(v.canaries).size===22);secretVariants(v.canaries);return v
}
export function actorFor(headers,tokens){
  const e=Object.entries(headers??{});need(e.length<=64&&new Set(e.map(([k])=>k.toLowerCase())).size===e.length)
  const h=Object.fromEntries(e.map(([k,v])=>[k.toLowerCase(),v]));need(!['cookie','proxy-authorization','proxy-connection'].some(k=>Object.hasOwn(h,k)))
  if(h.authorization===undefined)return{role:'anonymous',headers:h}
  const a=ROLES.filter(r=>h.authorization==='Bearer '+tokens[r]);need(a.length===1);return{role:a[0],headers:h}
}
export function classifyRemoteRequest(request,assets,input,index,facts){
  need(request&&typeof request.url==='string'&&request.url.length<=1024&&['GET','POST'].includes(request.method))
  const u=new URL(request.url);need(u.href===request.url&&u.origin===ORIGIN&&!u.username&&!u.password&&!u.hash)
  const path=u.pathname+u.search,{role,headers:h}=actorFor(request.headers,input.tokens);let kind,sourceId=null
  if(request.method==='GET'&&!u.search){
    if(path==='/')kind='DOCUMENT';else if(assets.includes(path))kind='ASSET';else if(path==='/api/v1/snapshot')kind='SNAPSHOT'
    else if(path==='/api/v1/subscriptions/access')kind='COLLECTION_ACCESS';else if(path==='/api/v1/subscriptions/sources')kind='SOURCES'
    else if(/^\/api\/v1\/subscriptions\/sources\/src_[a-f0-9]{32}\/access$/.test(path))kind='SOURCE_ACCESS'
    else if(/^\/api\/v1\/subscriptions\/commands\/cmd_[a-f0-9]{32}$/.test(path))kind='RECEIPT'
  }
  const page=/^\/api\/v1\/subscriptions\/sources\/(src_[a-f0-9]{32})\/candidates(?:\/(cand_[a-f0-9]{32})\/nodes)?\?limit=20&offset=0&revision=([1-3])$/.exec(path)
  if(request.method==='GET'&&page){kind=page[2]?'NODES':'CANDIDATES';sourceId=page[1];if(facts.sourceId!==null)need(sourceId===facts.sourceId);if(page[2]&&facts.candidate)need(page[2]===facts.candidate.id)}
  const end=/^\/api\/v1\/subscriptions\/sources(?:\/(src_[a-f0-9]{32})\/(approvals|fetches|decisions))?$/.exec(path)
  if(request.method==='POST'&&end){kind=end[2]==='approvals'?'APPROVE':end[2]==='fetches'?'FETCH':end[2]==='decisions'?'DECIDE':'CREATE';sourceId=end[1]??null}
  need(kind);const auth=!['DOCUMENT','ASSET','SNAPSHOT'].includes(kind);need(auth?role!=='anonymous':role==='anonymous')
  let requestPublic=null
  if(request.method==='GET'){
    need(!request.hasPostData&&request.postData===undefined&&h['idempotency-key']===undefined)
    if(kind==='SOURCE_ACCESS'&&facts.sourceId!==null)need(path==='/api/v1/subscriptions/sources/'+facts.sourceId+'/access')
    if(kind==='RECEIPT')need(role==='approver'&&path==='/api/v1/subscriptions/commands/'+facts.commands.admit_fetched?.commandId)
  }else{
    const a=ACTIONS[index];need(a&&a.role===role&&a.kind.toUpperCase()===kind&&h['content-type']==='application/json'&&/^sub_[a-f0-9]{32}$/.test(h['idempotency-key']))
    need(typeof request.postData==='string'&&Buffer.byteLength(request.postData)<=2048);const b=JSON.parse(request.postData),idempotencyKey=h['idempotency-key']
    if(kind==='CREATE'){need(exact(b,['label'])&&b.label===LABEL);requestPublic={label:b.label,idempotencyKey}}
    else{
      need(sourceId===facts.sourceId&&b.expectedRevision===a.fromRevision)
      if(kind==='APPROVE')need(exact(b,['expectedRevision','referenceId','policyRevision'])&&b.referenceId==='good-b'&&b.policyRevision===1)
      else if(kind==='FETCH')need(exact(b,['expectedRevision','approvalId','policyRevision'])&&b.approvalId===facts.approval?.commandId&&b.policyRevision===1)
      else need(exact(b,['expectedRevision','candidateId','expectedDigest','decision'])&&b.candidateId===facts.candidate?.id&&b.expectedDigest===facts.candidate?.digest&&b.decision==='admitted_local')
      requestPublic={sourceId,...b,idempotencyKey}
    }
  }
  return{method:request.method,path,kind,authorizationPresent:auth,actorRole:role,requestPublic}
}
export function wireFence(raw){
  need(Buffer.isBuffer(raw)&&raw.length<=262144);if(!raw.length)return{eventCount:0,bytes:0,sha256:sha(raw)}
  need(raw.at(-1)===10&&raw.toString('ascii')===raw.toString('utf8'));const lines=raw.toString('utf8').slice(0,-1).split('\n');need(lines.length<=12)
  for(const [i,line]of lines.entries()){
    const r=JSON.parse(line);need(exact(r,['schema','ordinal','connection','service','event','reference','queryType','status','bytes','tls','reason','receivedUnixNano']))
    need(JSON.stringify(Object.fromEntries(Object.keys(r).sort().map(k=>[k,r[k]])))===line&&r.schema==='chengwang.subscription-wire-event/v1'&&r.ordinal===i+1&&integer(r.connection,1,3)&&['dot','https'].includes(r.service))
    need(['connect','tls','dns','http','close'].includes(r.event)&&['ok','closed'].includes(r.reason)&&typeof r.tls==='boolean'&&['','good-b'].includes(r.reference)&&['','A','AAAA'].includes(r.queryType)&&[0,200].includes(r.status)&&integer(r.bytes,0,2<<20)&&typeof r.receivedUnixNano==='string'&&/^(?:|[1-9][0-9]{0,19})$/.test(r.receivedUnixNano))
  }
  if(lines.length===12){const rows=lines.map(v=>JSON.parse(v));need(rows.filter(r=>r.event==='close').length===3&&new Set(rows.map(r=>r.connection)).size===3);need(rows.filter(r=>r.event==='dns'&&r.reference==='good-b').length===2&&rows.filter(r=>r.event==='http'&&r.reference==='good-b'&&r.status===200).length===1)}
  return{eventCount:lines.length,bytes:raw.length,sha256:sha(raw)}
}
export function stepExpectation(step){
  need(STEPS.includes(step));const at=STEPS.indexOf(step),fetched=at>=STEPS.indexOf('fetched_quarantined'),admitted=at>=STEPS.indexOf('admitted')
  const role=['anonymous','cleared'].includes(step)?'anonymous':at>=STEPS.indexOf('approver_candidate')||at>=STEPS.indexOf('approver_source')&&at<=STEPS.indexOf('reference_a_cleared')?'approver':'operator'
  const mutations=admitted?4:fetched?3:at>=STEPS.indexOf('approved_b')?2:at>=STEPS.indexOf('created')?1:0
  const dialog=step==='create_prepared'?'create':['approve_b_prepared','approve_b_prepared_again'].includes(step)?'approve':['fetch_prepared','fetch_prepared_before_edit','fetch_prepared_before_mode','fetch_prepared_final'].includes(step)?'fetch_handoff':step==='admit_prepared'?'admit':null
  const approval=['approved_b','approval_refreshed'].includes(step)
  const handoff=at>=STEPS.indexOf('handoff_empty')&&at<=STEPS.indexOf('fetch_prepared_final')&&step!=='session_mode_cleared'
  return{role,mutations,wireCount:fetched?12:0,revision:admitted?3:fetched?2:mutations?1:0,dialog,approval,handoff,handoffRevision:step==='handoff_empty'?null:step==='handoff_edited'?2:1,
    reference:['approve_b_prepared','approve_b_cancelled','approve_b_prepared_again','approved_b','approval_refreshed'].includes(step)?'good-b':'good-a'}
}
export function validateRemoteStep(step,d,count,role,facts,fence){
  const e=stepExpectation(step);need(count===e.mutations&&role===e.role&&fence.eventCount===e.wireCount)
  need(d.pageMounted&&d.pageVisible===(step!=='hidden')&&d.https&&!d.alertVisible&&d.session.tokenType==='password'&&d.session.tokenEmpty&&d.session.fileEmpty&&d.session.storageEmpty&&d.session.cookiesEmpty&&!Object.values(d.stale).some(Boolean))
  const absent=['anonymous','operator_connected','create_prepared','cleared'].includes(step);need(d.sources.length===(absent?0:1))
  if(!absent)need(d.sources[0].id===facts.sourceId&&d.sources[0].selected&&d.sources[0].revision===e.revision&&d.sources[0].accepted===(e.revision===3))
  need((d.confirmation?.kind??null)===e.dialog)
  if(e.dialog==='fetch_handoff')need(d.confirmation.unverifiedReference&&exact(d.confirmation.binding,['sourceId','expectedRevision','approvalId','policyRevision'])&&d.confirmation.binding.sourceId===facts.sourceId&&d.confirmation.binding.expectedRevision===1&&d.confirmation.binding.approvalId===facts.approval.commandId&&d.confirmation.binding.policyRevision===1)
  if(absent)need(d.directory.references.length===0)
  else need(JSON.stringify(d.directory.references.map(({referenceId,revision})=>({referenceId,revision})))===JSON.stringify(REFERENCES)&&d.directory.references.filter(v=>v.selected).length===1&&d.directory.references.find(v=>v.selected).referenceId===e.reference)
  if(e.approval)need(d.sessionApproval?.approvalId===facts.approval.commandId&&d.sessionApproval.referenceId==='good-b'&&d.sessionApproval.policyRevision===1);else need(d.sessionApproval===null)
  need(d.mode===(e.handoff?'handoff':'session'))
  if(e.handoff){need(d.handoff?.unverifiedReferenceNotice&&d.handoff.approvalValid===(step!=='handoff_empty')&&d.handoff.revisionValid===(step!=='handoff_empty'));if(step!=='handoff_empty')need(d.handoff.approvalId===facts.approval.commandId&&d.handoff.policyRevision===e.handoffRevision)}else need(d.handoff===null)
  need(d.candidates.length===(e.revision>=2&&step!=='cleared'?1:0))
  const selected=['approver_candidate','admit_prepared','nodes_admitted','final_desktop','final_mobile','receipt','hidden','returned'].includes(step)
  if(d.candidates.length)need(d.candidates[0].id===facts.candidate.id&&d.candidates[0].baseRevision===2&&d.candidates[0].nodeCount===2&&d.candidates[0].state===(e.revision===3?'admitted_local':'quarantined')&&d.candidates[0].selected===selected)
  need(d.nodes.length===(selected?2:0)&&d.nodes.every(n=>n.state==='unknown'&&n.credentialConfigured))
  const receipt=step==='created'?facts.commands.create_source:['approved_b','approval_refreshed','reference_a_cleared'].includes(step)?facts.approval:step==='fetched_quarantined'?facts.commands.fetch_b:e.revision===3&&step!=='cleared'?facts.commands.admit_fetched:null
  if(receipt)need(d.receipt?.commandId===receipt.commandId&&d.receipt.revision===receipt.revision&&d.receipt.state===receipt.state&&d.receipt.auditRecorded&&!d.receipt.replayed);else need(d.receipt===null)
  const fetch=d.controls.find(v=>v.key==='prepare_fetch');need(fetch?.enabled===(role==='operator'&&e.handoff&&step!=='handoff_empty'))
  if(['final_desktop','final_mobile'].includes(step))need(d.viewport.width===(step==='final_mobile'?375:1440)&&d.viewport.height===900&&d.viewport.scrollWidth===d.viewport.clientWidth&&d.viewport.scrollX===0&&d.viewport.scrollY===0&&d.boundaryVisible)
  return d
}
