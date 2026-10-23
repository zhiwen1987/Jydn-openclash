// Node v22.23.3 HTTPS, separate from browser Network evidence. Import is inert.
import https from 'node:https'
import {randomBytes} from 'node:crypto'
import {constants} from 'node:fs'
import {open,lstat} from 'node:fs/promises'
import {C,ORIGIN,need,exact,integer,sha,secretVariants,publicFence,safeHeaders,responseEnvelope,commandFor} from './handoff-negative-contract.mjs'
const same=(a,b)=>['dev','ino','size','mode','uid','gid','nlink','mtimeNs','ctimeNs'].every(k=>a[k]===b[k])
export function samplerRequest(key,facts,idempotencyKey){
  const a=C.actions.find(v=>v.key===key&&v.origin==='api-sampler');need(a&&/^sub_[a-f0-9]{32}$/.test(idempotencyKey)&&/^src_[a-f0-9]{32}$/.test(facts.sources.a))
  const b=a.kind==='approve'?{expectedRevision:1,referenceId:a.referenceId,policyRevision:1}:{expectedRevision:1,approvalId:commandFor(facts,a.approvalKey),policyRevision:1}
  if(a.kind==='fetch')need(/^cmd_[a-f0-9]{32}$/.test(b.approvalId));return{action:a,path:'/api/v1/subscriptions/sources/'+facts.sources.a+'/'+(a.kind==='approve'?'approvals':'fetches'),body:b,requestPublic:{sourceId:facts.sources.a,...b,idempotencyKey}}
}
export function validateSamplerRow(row,canaries,expectedLeaf){
  need(exact(row,C.samplerKeys)&&row.schema===C.samplerSchema&&integer(row.ordinal,1,2));const a=C.actions.filter(v=>v.origin==='api-sampler')[row.ordinal-1]
  need(row.caseKey===a.key&&row.method==='POST'&&row.actorRole==='operator'&&row.status===a.status&&/^\/api\/v1\/subscriptions\/sources\/src_[a-f0-9]{32}\/(approvals|fetches)$/.test(row.path))
  const keys=a.kind==='approve'?['sourceId','expectedRevision','referenceId','policyRevision','idempotencyKey']:['sourceId','expectedRevision','approvalId','policyRevision','idempotencyKey'];need(exact(row.requestPublic,keys)&&row.requestPublic.expectedRevision===1&&row.requestPublic.policyRevision===1&&/^sub_[a-f0-9]{32}$/.test(row.requestPublic.idempotencyKey)&&row.path==='/api/v1/subscriptions/sources/'+row.requestPublic.sourceId+'/'+(a.kind==='approve'?'approvals':'fetches'))
  if(a.kind==='approve')need(row.requestPublic.referenceId==='good-b');else need(/^cmd_[a-f0-9]{32}$/.test(row.requestPublic.approvalId))
  need(exact(row.tls,C.samplerTLSKeys)&&row.tls.authorized===true&&['TLSv1.2','TLSv1.3'].includes(row.tls.protocol));const der=Buffer.from(row.tls.leafDERBase64,'base64');need(der.length>=128&&der.length<=16384&&der.toString('base64')===row.tls.leafDERBase64&&sha(der)===row.tls.leafSHA256&&(!expectedLeaf||row.tls.leafSHA256===expectedLeaf));publicFence(der,canaries)
  need(exact(row.terminal,['event','complete','aborted'])&&row.terminal.event==='END'&&row.terminal.complete===true&&row.terminal.aborted===false)
  need(integer(row.startedWallTimeUs,1)&&integer(row.headerWallTimeUs,row.startedWallTimeUs)&&integer(row.endWallTimeUs,row.headerWallTimeUs)&&integer(row.responseBytes,1,C.bodyLimitBytes));const raw=Buffer.from(row.responseBase64,'base64');need(raw.length===row.responseBytes&&raw.toString('base64')===row.responseBase64&&sha(raw)===row.responseSHA256);publicFence(raw,canaries);responseEnvelope(raw,a,row);publicFence(Buffer.from(JSON.stringify(row)),canaries);return row
}
export function sampleHTTPS(spec,{ca,token,expectedLeaf,canaries,ordinal,request=https.request,now=()=>Date.now()*1000,timeoutMs=10000}){
  need(Buffer.isBuffer(ca)&&typeof token==='string'&&/^[a-f0-9]{64}$/.test(token)&&/^[a-f0-9]{64}$/.test(expectedLeaf));const startedWallTimeUs=now(),payload=Buffer.from(JSON.stringify(spec.body))
  return new Promise((resolve,reject)=>{
    let done=false,timer,req
    const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);if(error)reject(Error('handoff API sample rejected'));else resolve(value)}
    try{
      req=request({protocol:'https:',hostname:'127.0.0.1',port:17891,path:spec.path,method:'POST',ca,rejectUnauthorized:true,agent:false,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json','Content-Length':payload.length,'Idempotency-Key':spec.requestPublic.idempotencyKey}},res=>{
        try{
          need(!done&&res.statusCode===spec.action.status&&res.socket?.authorized===true);const peer=res.socket.getPeerCertificate(),protocol=res.socket.getProtocol();need(Buffer.isBuffer(peer?.raw)&&sha(peer.raw)===expectedLeaf&&['TLSv1.2','TLSv1.3'].includes(protocol));need(Array.isArray(res.rawHeaders)&&res.rawHeaders.length%2===0)
          const safe=safeHeaders(Array.from({length:res.rawHeaders.length/2},(_,i)=>[res.rawHeaders[i*2],res.rawHeaders[i*2+1]]));const tls={authorized:true,leafDERBase64:peer.raw.toString('base64'),leafSHA256:sha(peer.raw),protocol},headerWallTimeUs=now(),chunks=[];let size=0,aborted=false
          res.on('aborted',()=>{aborted=true;finish(true)});res.on('error',()=>finish(true));res.on('data',chunk=>{try{need(Buffer.isBuffer(chunk));size+=chunk.length;need(size<=C.bodyLimitBytes);chunks.push(chunk)}catch{req.destroy();finish(true)}})
          res.on('end',()=>{try{need(!done&&res.complete===true&&!res.aborted&&!aborted);const raw=Buffer.concat(chunks),row={schema:C.samplerSchema,ordinal,caseKey:spec.action.key,method:'POST',path:spec.path,actorRole:'operator',requestPublic:spec.requestPublic,status:res.statusCode,...safe,responseBase64:raw.toString('base64'),responseBytes:raw.length,responseSHA256:sha(raw),tls,startedWallTimeUs,headerWallTimeUs,endWallTimeUs:now(),terminal:{event:'END',complete:res.complete,aborted:res.aborted===true||aborted}};validateSamplerRow(row,canaries,expectedLeaf);finish(false,row)}catch{finish(true)}})
          res.on('close',()=>{if(!done)finish(true)})
        }catch{res.destroy();finish(true)}
      })
      req.on('error',()=>finish(true));timer=setTimeout(()=>{req.destroy();finish(true)},timeoutMs);req.end(payload)
    }catch{req?.destroy();finish(true)}
  })
}
export class HandoffAPISampler{
  constructor(root,input,ca,leaf){this.root=root;this.input=input;this.ca=ca;this.leaf=leaf;this.canaries=secretVariants([...Object.values(input.tokens),...input.canaries]);this.rows=[];this.fd=null;this.keys=new Set()}
  async initialize(){need(!this.fd);this.fd=await open(this.root+'/'+C.privateSamplerFile,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);await this.fd.chmod(0o600);await this.fd.sync();const s=await this.fd.stat();need(s.isFile()&&s.nlink===1&&s.uid===10001&&s.gid===10001&&(s.mode&0o7777)===0o600&&s.size===0)}
  async sample(key,facts){need(this.fd&&this.rows.length<2&&C.actions.filter(a=>a.origin==='api-sampler')[this.rows.length].key===key);const id='sub_'+randomBytes(16).toString('hex');need(!this.keys.has(id));this.keys.add(id);const spec=samplerRequest(key,facts,id),row=await sampleHTTPS(spec,{ca:this.ca,token:this.input.tokens.operator,expectedLeaf:this.leaf,canaries:this.canaries,ordinal:this.rows.length+1});const raw=Buffer.from(JSON.stringify(row)+'\n');need(raw.length<=C.maxSamplerFileBytes);publicFence(raw,this.canaries);await this.fd.writeFile(raw);await this.fd.sync();this.rows.push(row);return row}
  async fence(){const fd=await open(this.root+'/'+C.privateSamplerFile,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);try{const a=await fd.stat({bigint:true});need(a.isFile()&&a.nlink===1n&&a.uid===10001n&&a.gid===10001n&&(a.mode&0o7777n)===0o600n&&a.size<=BigInt(C.maxSamplerFileBytes));const raw=await fd.readFile(),b=await fd.stat({bigint:true}),c=await lstat(this.root+'/'+C.privateSamplerFile,{bigint:true});need(same(a,b)&&same(a,c)&&BigInt(raw.length)===a.size);publicFence(raw,this.canaries);const lines=raw.length?(need(raw.at(-1)===10),raw.toString('utf8').slice(0,-1).split('\n')):[];need(lines.length===this.rows.length&&lines.length<=2);for(const [i,line]of lines.entries()){const v=JSON.parse(line);need(JSON.stringify(v)===line&&v.ordinal===i+1);validateSamplerRow(v,this.canaries,this.leaf)}return{recordCount:lines.length,bytes:raw.length,sha256:sha(raw)}}finally{await fd.close()}}
  async close(){if(this.fd){const fd=this.fd;this.fd=null;try{await fd.sync()}finally{await fd.close()}}}
}
