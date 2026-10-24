// Pure protocol models of the actual exported orchestrator. These fake session,
// DOM and PNG values are not real browser, TLS or application measurements.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { orchestrateOverview, runOverview } from './ui-driver.mjs'
import { loadContract, parseArguments, sha } from './ui-contract.mjs'
import { main } from './ui-cli.mjs'

const c=loadContract(readFileSync(new URL('../../deploy/overview-ui-browser/contract.json',import.meta.url)))
const fixtureId='a'.repeat(32),sourceCommit='b'.repeat(40)
function model(profile,changes={}) {
  const o=parseArguments(['--root','/tmp/chengwang-subscription-ui-'+fixtureId,'--bundle','/tmp/chengwang-subscription-ui-tools-'+fixtureId,'--engine','chrome-cdp','--source-commit',sourceCommit])
  const input={profile},writes=new Map(),calls=[],rows=[],requests=new Map()
  let clock=0,closed=false,page='overview',actual=false,width=1440,height=900,disposeCount=0
  const add=kind=>{const row={ordinal:rows.length+1,kind,bodyState:'present'};rows.push(row);if(kind==='DOCUMENT')requests.set('document',{kind,response:{securityState:'secure'}})}
  const count=kind=>rows.filter(v=>v.kind===kind).length
  const labels={source_demo:'演示总览',source_actual:'实际证据',actual_refresh:'重新读取实际证据',cta_device:'查看设备读回',cta_nodes:'查看代理节点',cta_subscriptions:'查看订阅与提供者',nav_overview:'运行总览',nav_kernels:'内核与协议'}
  const journal={rows,requests,events:[],failure:false,overflow:false,counters:Object.fromEntries(c.counterRules.rawKeys.map(k=>[k,0])),
    idle:()=>!changes.stalled,mutationCount:()=>0,
    complete(){assert.equal(count('SNAPSHOT'),1);assert.equal(count('OVERVIEW'),profile==='evidence_disabled'?6:9);assert.equal(count('PROBE_STATUS'),profile==='evidence_disabled'?0:1);assert.equal(count('OBSERVATION_STATUS'),profile==='evidence_disabled'?0:1);assert.equal(this.failure,false);if(profile==='evidence_enabled_unknown')assert.equal(this.counters.failedRequests,0)},
    beginClose(){this.complete();this.closing=true;calls.push('beginClose')},finalize(){assert(closed);assert(this.closing);this.finalized=true;calls.push('finalize')}}
  const session={browser:{product:'HeadlessChrome/1.2.3.4',revision:'@'+'d'.repeat(40),protocolVersion:'1.3'},
    chrome:{pid:123,startTicks:456,uid:10001,profile:o.profile,argvSHA256:'e'.repeat(64),exeSHA256:'f'.repeat(64),exeBytes:10},
    normalTrust:{method:'PRIVATE_NSS_SQL_XDG_LOCAL_CA',trustFlags:'C,,',caSHA256:'d'.repeat(64),leafSHA256:'e'.repeat(64),homeEnvironmentAbsent:true,legacyDatabaseAbsent:true},
    assertHealthy(){assert.equal(closed,false,'caller must not assert healthy after normal close');if(changes.fault)throw Error('synthetic fault')},
    async evaluate(){clock++;return true},
    async resize(w,h){clock++;width=w;height=h;calls.push('resize:'+w);if(changes.resizeGET&&rows.length)add('OVERVIEW')},
    async navigate(url){assert.equal(url,c.origin+'/');calls.push('navigate');add('DOCUMENT');add('ASSET');add('SNAPSHOT')},
    async click({name,ariaLabelOnly}){
      clock++;const key=Object.keys(labels).find(k=>labels[k]===name);assert(key);calls.push(key)
      assert.equal(ariaLabelOnly,key.startsWith('nav_'))
      if(changes.failClick===key)throw Error('private fixture value must never create success')
      if(key==='source_demo'){actual=false;page='overview'}
      else if(key==='source_actual'){if(!actual||changes.sameSourceGET)add('OVERVIEW');actual=true;page='overview'}
      else if(key==='actual_refresh')add('OVERVIEW')
      else if(key==='nav_overview'){page='overview';if(actual)add('OVERVIEW')}
      else if(key==='nav_kernels')page='kernels'
      else if(key==='cta_device')page='device_readback'
      else if(key==='cta_subscriptions')page='subscriptions'
      else if(key==='cta_nodes'){page='proxy_observation';add('OBSERVATION_STATUS');add('PROBE_STATUS');if(changes.extraPoll)add('PROBE_STATUS');if(changes.slowNodes)clock+=10001}
    },
    async screenshot(){const raw=Buffer.alloc(24);Buffer.from([137,80,78,71,13,10,26,10]).copy(raw);raw.writeUInt32BE(changes.badPNG?1:width,16);raw.writeUInt32BE(height,20);return raw},
    async tlsProof(){calls.push('tls');return {tls:{securityState:'secure'},certificateChain:['synthetic-model-chain-not-certificate']}},
    async close(){assert(journal.closing);calls.push('close');if(changes.closeFail)throw Error('synthetic close failure');if(changes.slowClose)clock=125001;closed=true;return {normalCloseCommandCompleted:true,chromeExit:{schema:'chengwang.subscription-ui-chrome-exit/v1',engine:o.engine,fixtureId,pid:123,startTicks:456,exitCode:0,joined:true,forced:false},launcherExit:{code:0,signal:null},noLiveOwnedProcesses:true,processScope:'CHROME_SESSION_AND_LAUNCHER_ONLY'}},
    async dispose(){disposeCount++;calls.push('dispose')}}
  const io={startedAt:0,canaries:['private-model-canary'],monotonic:()=>clock,wall:()=>1760000000000,
    async publish(path,bytes,maximum){assert(bytes.length<=maximum);writes.set(path,Buffer.from(bytes));return {bytes:bytes.length,sha256:sha(bytes)}},
    async ready(path,value){assert.equal(path,o.root+'/driver-ready.private.json');assert.equal(value.profile,profile);calls.push('ready')},
    async waitRun(){calls.push('runBarrier');if(changes.barrierFail)throw Error('synthetic wrong run barrier')},
    async wait(predicate){for(let i=0;i<20;i++){clock+=10;if(await predicate())return}throw Error('synthetic bounded wait')},
    async observe(){return {viewKind:page==='overview'?(actual?'actual':'demo'):page,viewport:{width,height,scrollX:0,scrollY:0}}},
    validate(step,d,observed,contract,selected){assert.equal(selected,profile);const fence=contract.stepFences[profile].find(v=>v[0]===step);assert.equal(d.viewKind,fence[3]);assert.equal(d.viewport.width,fence[5]);assert.equal(d.apiFence.overviewCaptureOrdinals.length,fence[7]);assert.equal(d.apiFence.snapshotCaptureOrdinal,observed.find(r=>r.kind==='SNAPSHOT').ordinal)}}
  return {o,input,session,journal,io,writes,calls,count,get disposed(){return disposeCount},run:()=>orchestrateOverview(session,journal,c,input,o,io)}
}
test('d01 actual orchestrator completes both full profile plans eight PNGs and close ordering',async()=>{
  for(const profile of c.profiles){const m=model(profile),report=await m.run();assert.equal(report.steps.length,profile==='evidence_disabled'?11:17);assert.equal(report.screenshots.length,8);assert.equal(m.writes.size,11);assert.equal(m.disposed,0)
    if(profile==='evidence_disabled')assert.deepEqual(report.actionTimings,{nodeVisit:null})
    else{const v=report.actionTimings.nodeVisit;assert(Number.isSafeInteger(v.enteredMonotonicUs)&&v.enteredMonotonicUs>=0);assert(Number.isSafeInteger(v.returnedMonotonicUs)&&v.returnedMonotonicUs>=v.enteredMonotonicUs);assert(v.returnedMonotonicUs-v.enteredMonotonicUs<=10000000)}
    assert.deepEqual(m.calls.slice(0,2),['ready','runBarrier']);assert(m.calls.indexOf('beginClose')<m.calls.indexOf('close'));assert(m.calls.indexOf('close')<m.calls.indexOf('finalize'));assert(m.writes.has(m.o.root+'/driver.private.json'))}
})
test('d02 all three real CTA commands and independent Kernels roundtrip remain in enabled plan',async()=>{
  const m=model('evidence_enabled_unknown');await m.run()
  for(const key of ['cta_device','cta_nodes','cta_subscriptions','nav_kernels'])assert.equal(m.calls.filter(v=>v===key).length,1)
  assert.equal(m.calls.filter(v=>v==='nav_overview').length,4);assert.equal(m.count('OVERVIEW'),9)
})
test('d03 same-source clicks are actually issued without extra GETs and mobile refresh remains',async()=>{
  const m=model('evidence_disabled');await m.run();assert.equal(m.calls.filter(v=>v==='source_demo').length,3);assert.equal(m.calls.filter(v=>v==='source_actual').length,4)
  assert.equal(m.calls.filter(v=>v==='actual_refresh').length,2);assert.equal(m.calls.filter(v=>v==='resize:375').length,1);assert.equal(m.count('OVERVIEW'),6)
})
test('d04 rows and screenshot records bind completed capture ordinals and published bytes',async()=>{
  const m=model('evidence_enabled_unknown'),report=await m.run(),rows=m.writes.get(m.o.root+'/dom.private.jsonl').toString().trim().split('\n').map(JSON.parse)
  assert.equal(rows.length,17);assert(rows.every((r,i)=>r.ordinal===i+1&&r.captureCount>0&&r.mutationCount===0))
  const nodes=rows.find(r=>r.step==='nodes_page_desktop');assert.equal(nodes.dom.apiFence.observationStatusCaptureOrdinals.length,1);assert.equal(nodes.dom.apiFence.probeStatusCaptureOrdinals.length,1)
  for(const image of report.screenshots){const raw=m.writes.get(m.o.root+'/'+image.path.replace(/\.png$/,'.private.png'));assert.equal(image.sha256,sha(raw));assert.equal(image.bytes,raw.length)}
})
test('d05 default run rejects fake dependency options before any application I/O',async()=>{
  const m=model('evidence_disabled');await assert.rejects(runOverview({...m.o,openNativeSession:async()=>m.session}));assert.equal(m.calls.length,0)
})
test('d06 barrier failure and real action rejection dispose without publishing success driver',async()=>{
  for(const changes of [{barrierFail:true},{failClick:'cta_nodes'}]){const m=model('evidence_enabled_unknown',changes);await assert.rejects(m.run());assert.equal(m.disposed,1);assert.equal(m.writes.has(m.o.root+'/driver.private.json'),false)}
})
test('d07 stalled body journal or sticky native fault cannot pass a checkpoint',async()=>{
  for(const changes of [{stalled:true},{fault:true}]){const m=model('evidence_disabled',changes);await assert.rejects(m.run());assert.equal(m.disposed,1);assert.equal(m.calls.includes('close'),false)}
})
test('d08 same-source resize and extra node poll regressions fail exact API fences',async()=>{
  for(const changes of [{sameSourceGET:true},{resizeGET:true},{extraPoll:true}]){const m=model('evidence_enabled_unknown',changes);await assert.rejects(m.run());assert.equal(m.disposed,1);assert.equal(m.writes.has(m.o.root+'/driver.private.json'),false)}
})
test('d09 node visit and return exceeding ten seconds is rejected without timer changes',async()=>{
  const m=model('evidence_enabled_unknown',{slowNodes:true});await assert.rejects(m.run());assert.equal(m.disposed,1);assert.equal(m.count('PROBE_STATUS'),1)
})
test('d10 invalid screenshot and unsuccessful normal close never produce success driver',async()=>{
  for(const changes of [{badPNG:true},{closeFail:true}]){const m=model('evidence_disabled',changes);await assert.rejects(m.run());assert.equal(m.disposed,1);assert.equal(m.writes.has(m.o.root+'/driver.private.json'),false)}
})
test('d11 post-close overall deadline is checked without calling assertHealthy on CLOSED',async()=>{
  const m=model('evidence_disabled',{slowClose:true});await assert.rejects(m.run());assert.equal(m.disposed,0);assert.equal(m.writes.has(m.o.root+'/driver.private.json'),false)
})
test('d12 disabled raw failure counters are preserved rather than rewritten to original eight zero',async()=>{
  const m=model('evidence_disabled');m.journal.counters.failedRequests=2;m.journal.counters.captureErrors=1;const report=await m.run();assert.equal(report.counters.failedRequests,2);assert.equal(report.counters.captureErrors,1)
})
test('d13 CLI argument rejection has only fixed safe output and performs no launch',async()=>{
  let text='';const old=process.stderr.write;process.stderr.write=value=>{text+=value;return true}
  try{assert.equal(await main(['--private','SYNTHETIC-PRIVATE-MARKER']),1)}finally{process.stderr.write=old}
  assert.equal(text,'OVERVIEW_UI=REJECTED raw_input_suppressed=true\n');assert.equal(text.includes('SYNTHETIC-PRIVATE'),false)
})
