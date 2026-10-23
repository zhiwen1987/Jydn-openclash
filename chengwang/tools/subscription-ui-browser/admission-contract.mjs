// Pure local-admission contracts; no runtime or network operation on import.
import { createHash } from 'node:crypto'
import { ORIGIN, FAVICON, need, exact, integer, sha, assetPaths, decodeBody, parseArguments } from './ui-contract.mjs'
export { ORIGIN, FAVICON, need, exact, integer, sha, assetPaths, decodeBody, parseArguments }
export const SCENARIO = 'local_admission'
export const SCOPE = "REAL_PRODUCT_LOCAL_ADMISSION_FLOW_PARTIAL_FULL_SUBSCRIPTION_PLAN_PENDING"
export const STEPS = Object.freeze(["anonymous","operator_connected","create_a_prepared","create_a_cancelled","create_a_prepared_again","created_a","created_b","import_a_prepared","import_a_cancelled","import_a_prepared_again","imported_a","nodes_a","imported_b","nodes_b","viewer_a","auditor_b","approver_a","admit_a_prepared","admitted_a","operator_a","imported_a2","approver_a2","admitted_a2","operator_a3","imported_a3","approver_a3","rejected_a3","rollback_prepared","rollback_checked","rolled_back","nodes_restored","final_desktop","final_mobile","receipt","hidden","returned","cleared"])
export const ACTIONS = Object.freeze([{"key":"create_a","role":"operator","kind":"create","source":"a","fromRevision":0,"toRevision":1},{"key":"create_b","role":"operator","kind":"create","source":"b","fromRevision":0,"toRevision":1},{"key":"import_a","role":"operator","kind":"import","source":"a","file":"first","candidate":"a1","fromRevision":1,"toRevision":2},{"key":"import_b","role":"operator","kind":"import","source":"b","file":"first","candidate":"b1","fromRevision":1,"toRevision":2},{"key":"admit_a","role":"approver","kind":"decide","source":"a","candidate":"a1","decision":"admitted_local","fromRevision":2,"toRevision":3},{"key":"import_a2","role":"operator","kind":"import","source":"a","file":"second","candidate":"a2","fromRevision":3,"toRevision":4},{"key":"admit_a2","role":"approver","kind":"decide","source":"a","candidate":"a2","decision":"admitted_local","fromRevision":4,"toRevision":5},{"key":"import_a3","role":"operator","kind":"import","source":"a","file":"third","candidate":"a3","fromRevision":5,"toRevision":6},{"key":"reject_a3","role":"approver","kind":"decide","source":"a","candidate":"a3","decision":"rejected","fromRevision":6,"toRevision":7},{"key":"rollback_a","role":"approver","kind":"rollback","source":"a","candidate":"a1","fromRevision":7,"toRevision":8}])
export const ROLES = Object.freeze(['operator','approver','viewer','auditor'])
export const LABELS = Object.freeze({a:'browser-source-a',b:'browser-source-b'})
export function secretVariants(secrets) {
  need(Array.isArray(secrets) && secrets.length > 0 && secrets.length <= 256 && secrets.every(v => typeof v === 'string' && v.length > 0 && v.length <= 8192))
  const result = new Set()
  for (const text of secrets) { const b = Buffer.from(text); for (const v of [text,b.toString('base64'),b.toString('base64url'),b.toString('hex'),b.toString('hex').toUpperCase(),encodeURIComponent(text),createHash('sha256').update(b).digest('hex')]) result.add(v) }
  return [...result]
}
export function publicFence(raw, canaries) {
  need(Buffer.isBuffer(raw) && canaries.length > 0); for (const s of canaries) need(!raw.includes(Buffer.from(s))); return raw
}
export function validatePrivateInput(input, root) {
  need(exact(input,['schema','scenario','tokens','labels','files','canaries']) && input.schema === 'chengwang.admission-ui-input/v1' && input.scenario === SCENARIO && exact(input.tokens,ROLES) && new Set(Object.values(input.tokens)).size === 4 && Object.values(input.tokens).every(v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)))
  need(exact(input.labels,['a','b']) && input.labels.a===LABELS.a && input.labels.b===LABELS.b && Array.isArray(input.files) && input.files.length===3)
  input.files.forEach((f,i)=>need(exact(f,['key','path','bytes']) && f.key===['first','second','third'][i] && typeof f.path==='string' && f.path.startsWith(root+'/') && /^[A-Za-z0-9_.-]{1,96}\.yaml$/.test(f.path.slice(root.length+1)) && integer(f.bytes,1,1<<20)))
  need(new Set(input.files.map(f=>f.path)).size===3); secretVariants(input.canaries)
  return input
}
export function actorFor(headers,tokens) {
  const entries=Object.entries(headers??{}); need(entries.length<=64&&new Set(entries.map(([k])=>k.toLowerCase())).size===entries.length)
  const h=Object.fromEntries(entries.map(([k,v])=>[k.toLowerCase(),v])); need(!['cookie','proxy-authorization','proxy-connection'].some(k=>Object.hasOwn(h,k)))
  if(h.authorization===undefined)return {role:'anonymous',headers:h}
  const roles=ROLES.filter(r=>h.authorization==='Bearer '+tokens[r]); need(roles.length===1); return {role:roles[0],headers:h}
}
export function classifyAdmissionRequest(request,assets,input,files,actionIndex,facts) {
  need(request&&typeof request.url==='string'&&request.url.length<=1024&&['GET','POST'].includes(request.method))
  const u=new URL(request.url); need(u.href===request.url&&u.origin===ORIGIN&&!u.username&&!u.password&&!u.hash)
  const path=u.pathname+u.search,{role,headers:h}=actorFor(request.headers,input.tokens)
  let kind,sourceId=null,candidateId=null
  if(request.method==='GET'&&!u.search) {
    if(path==='/')kind='DOCUMENT'
    else if(assets.includes(path))kind='ASSET'
    else if(path==='/api/v1/snapshot')kind='SNAPSHOT'
    else if(path==='/api/v1/subscriptions/access')kind='COLLECTION_ACCESS'
    else if(path==='/api/v1/subscriptions/sources')kind='SOURCES'
    else if(/^\/api\/v1\/subscriptions\/sources\/src_[a-f0-9]{32}\/access$/.test(path))kind='SOURCE_ACCESS'
    else if(/^\/api\/v1\/subscriptions\/commands\/cmd_[a-f0-9]{32}$/.test(path))kind='RECEIPT'
  }
  const page=/^\/api\/v1\/subscriptions\/sources\/(src_[a-f0-9]{32})\/candidates(?:\/(cand_[a-f0-9]{32})\/nodes)?\?limit=20&offset=0&revision=([1-8])$/.exec(path)
  if(request.method==='GET'&&page){kind=page[2]?'NODES':'CANDIDATES';sourceId=page[1];candidateId=page[2]??null}
  const endpoint=/^\/api\/v1\/subscriptions\/sources(?:\/(src_[a-f0-9]{32})\/(candidates|decisions|rollbacks))?$/.exec(path)
  if(request.method==='POST'&&endpoint){kind=endpoint[2]==='candidates'?'IMPORT':endpoint[2]==='decisions'?'DECIDE':endpoint[2]==='rollbacks'?'ROLLBACK':'CREATE';sourceId=endpoint[1]??null}
  need(kind)
  const authenticated=!['DOCUMENT','ASSET','SNAPSHOT'].includes(kind);need(authenticated?role!=='anonymous':role==='anonymous')
  let requestPublic=null
  if(request.method==='GET')need(!request.hasPostData&&request.postData===undefined&&h['idempotency-key']===undefined)
  else{
    const action=ACTIONS[actionIndex];need(action&&action.role===role&&action.kind.toUpperCase()===kind)
    need(typeof h['idempotency-key']==='string'&&/^sub_[a-f0-9]{32}$/.test(h['idempotency-key'])&&h['content-type']==='application/json'&&typeof request.postData==='string'&&Buffer.byteLength(request.postData)<=2<<20)
    const body=JSON.parse(request.postData),idempotencyKey=h['idempotency-key']
    if(kind==='CREATE'){need(exact(body,['label'])&&body.label===LABELS[action.source]);requestPublic={label:body.label,idempotencyKey}}
    else{
      need(sourceId===facts.sources[action.source]&&body.expectedRevision===action.fromRevision)
      if(kind==='IMPORT'){
        need(exact(body,['expectedRevision','format','contentBase64'])&&body.format==='mihomo-provider-yaml'&&typeof body.contentBase64==='string')
        const bytes=Buffer.from(body.contentBase64,'base64');need(bytes.toString('base64')===body.contentBase64&&bytes.equals(files[action.file]))
        requestPublic={sourceId,expectedRevision:body.expectedRevision,format:body.format,contentBytes:bytes.length,idempotencyKey}
      }else if(kind==='DECIDE'){
        need(exact(body,['expectedRevision','candidateId','expectedDigest','decision'])&&body.candidateId===facts.candidates[action.candidate]?.id&&body.expectedDigest===facts.candidates[action.candidate]?.digest&&body.decision===action.decision)
        requestPublic={sourceId,...body,idempotencyKey}
      }else{
        need(exact(body,['expectedRevision','candidateId'])&&body.candidateId===facts.candidates[action.candidate]?.id)
        requestPublic={sourceId,...body,idempotencyKey}
      }
    }
  }
  return {method:request.method,path,kind,authorizationPresent:authenticated,actorRole:role,requestPublic}
}
export function stepRole(step) {
  need(STEPS.includes(step))
  if(['anonymous','cleared'].includes(step))return 'anonymous'
  if(step==='viewer_a')return 'viewer'
  if(step==='auditor_b')return 'auditor'
  if(['approver_a','admit_a_prepared','admitted_a','approver_a2','admitted_a2','approver_a3','rejected_a3','rollback_prepared','rollback_checked','rolled_back','nodes_restored','final_desktop','final_mobile','receipt','hidden','returned'].includes(step))return 'approver'
  return 'operator'
}
export function stepMutations(step) {
  need(STEPS.includes(step));let count=0
  for(const [at,n]of [['created_a',1],['created_b',2],['imported_a',3],['imported_b',4],['admitted_a',5],['imported_a2',6],['admitted_a2',7],['imported_a3',8],['rejected_a3',9],['rolled_back',10]])if(STEPS.indexOf(step)>=STEPS.indexOf(at))count=n
  return count
}
export function validateAdmissionStep(step,dom,count,role) {
  need(STEPS.includes(step)&&count===stepMutations(step)&&role===stepRole(step)&&dom.pageMounted&&dom.pageVisible===(step!=='hidden')&&dom.https&&!dom.alertVisible)
  need(dom.session.tokenEmpty&&dom.session.fileEmpty&&dom.session.storageEmpty&&dom.session.cookiesEmpty&&!Object.values(dom.stale).some(Boolean))
  need(dom.sessionApproval===null&&dom.handoff===null&&dom.nodes.every(n=>n.state==='unknown')&&dom.sources.length===(step==='anonymous'||step==='cleared'?0:stepMutations(step)>=2?2:stepMutations(step)>=1?1:0))
  const kinds={create_a_prepared:'create',create_a_prepared_again:'create',import_a_prepared:'import',import_a_prepared_again:'import',admit_a_prepared:'admit',rollback_prepared:'rollback',rollback_checked:'rollback'}
  need(dom.confirmation?.kind===kinds[step]);if(kinds[step]===undefined)need(dom.confirmation===null)
  if(step==='rollback_prepared')need(dom.confirmation.rollbackRequired&&!dom.confirmation.rollbackChecked&&!dom.controls.find(c=>c.key==='confirm').enabled)
  if(step==='rollback_checked')need(dom.confirmation.rollbackChecked&&dom.controls.find(c=>c.key==='confirm').enabled)
  if(['viewer','auditor'].includes(role))for(const key of ['prepare_create','prepare_import','prepare_approve','prepare_fetch','prepare_admit','prepare_reject','prepare_rollback'])need(!dom.controls.find(c=>c.key===key).enabled)
  if(['final_desktop','final_mobile'].includes(step))need(dom.viewport.width===(step==='final_mobile'?375:1440)&&dom.viewport.height===900&&dom.viewport.scrollWidth===dom.viewport.clientWidth&&dom.viewport.scrollX===0&&dom.viewport.scrollY===0&&dom.boundaryVisible)
  return dom
}
