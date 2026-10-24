// Pure CPU protocol models only. This suite never launches Chrome, TLS or a server.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { validateSessionOptions, validateChromeExit, TargetGuard, initializeCDPTargets, registerSessionEvents, nativeClickExpression, dispatchNativeClick, finishNativeSession, openNativeSession, SESSION_EVENTS, SESSION_FAULTS, NATIVE_OPEN_STAGES, projectInitialTargets, projectPostTargets, projectFirstTargetFault, nativeOpenObservation } from './native-session.mjs'
import { OverviewJournal } from '../overview-ui-browser/overview-journal.mjs'

const fixtureId = 'a'.repeat(32), sourceCommit = 'b'.repeat(40)
const options = (engine = 'chrome-cdp') => { const root = '/tmp/chengwang-subscription-ui-' + fixtureId, bundle = '/tmp/chengwang-subscription-ui-tools-' + fixtureId; return { root, bundle, engine, fixtureId, sourceCommit, chrome: bundle + '/chrome/chrome', launcher: bundle + '/ui-chrome-launcher', home: root + '/home', profile: root + '/chrome-profile' } }
const chrome = { pid: 123, startTicks: 456 }
const exit = (engine = 'chrome-cdp') => ({ schema: 'chengwang.subscription-ui-chrome-exit/v1', engine, fixtureId, pid: chrome.pid, startTicks: chrome.startTicks, exitCode: 0, joined: true, forced: false })
const created = (id, type = 'page') => ({ targetInfo: { targetId: id, type } })
const make = () => { const faults = [], guard = new TargetGuard((code, detail) => faults.push({ code, ...detail })); return { guard, faults } }
// Explicit controlled launch identity; an observed later snapshot is not enough.
const baseline = g => { g.freezeInitial([{ targetId: 'initial', type: 'page', url: 'about:blank' }]); g.setBaseline([{ targetId: 'owned', type: 'page' }, { targetId: 'initial', type: 'page' }], 'owned') }
function closer(overrides = {}) {
  const calls = [], o = options(), mechanisms = {
    closeBrowser: async () => { calls.push('close') }, readExit: async () => exit(), launcherResult: Promise.resolve({ code: 0, signal: null }),
    wait: async (predicate, budget) => { calls.push(budget); assert.equal(await predicate(), true) },
    noLive: async () => { calls.push('proc'); return true }, pause: async () => null,
    ...overrides,
  }
  return { calls, o, mechanisms }
}

test('n01 exact options bind both engines to owned fixed paths', () => { for (const engine of ['chrome-cdp', 'playwright']) { const o = options(engine); assert.equal(validateSessionOptions(o), o) } })
test('n02 options reject arbitrary paths engines and extra fake dependencies', () => { for (const change of [{ root: '/tmp/other' }, { engine: 'fake' }, { chrome: '/usr/bin/chrome' }, { home: '/root' }, { profile: '/tmp/profile' }, { launcher: '/tmp/run' }, { fixtureId: '../private' }, { sourceCommit: 'main' }, { io: {} }]) assert.throws(() => validateSessionOptions({ ...options(), ...change }), /^Error: native browser session rejected$/) })
test('n03 invalid open arguments reject before process and filesystem setup', async () => { let calls = 0; await assert.rejects(openNativeSession({ ...options(), root: '/private-sensitive-value' }, { onEvent() { calls++ }, onFault() { calls++ } }), /^Error: native browser session rejected$/); assert.equal(calls, 0) })
test('n04 hooks must be present exact synchronous callback slots', async () => { for (const hooks of [{}, { onEvent() {}, onFault: false }, { onEvent() {}, onFault() {}, fakeTransport: true }, { onEvent() {}, onFault() {}, onDiagnostic: false }, { onEvent() {}, onFault() {}, onDiagnostic: undefined }]) await assert.rejects(openNativeSession(options(), hooks), /^Error: native browser session rejected$/) })
test('n05 chrome exit requires exact identity and actual zero normal join', () => { assert.equal(validateChromeExit(exit(), options(), chrome).joined, true); for (const change of [{ exitCode: 1 }, { forced: true }, { joined: false }, { pid: 124 }, { startTicks: 457 }, { engine: 'playwright' }, { fixtureId: 'c'.repeat(32) }, { extra: true }, { exitCode: false }]) assert.throws(() => validateChromeExit({ ...exit(), ...change }, options(), chrome)) })

test('n06 known discovery replays before baseline are reconciled without faults', () => { const { guard: g, faults } = make(); g.observe('Target.targetCreated', created('owned')); g.observe('Target.targetCreated', created('initial')); baseline(g); g.arm(); assert.equal(g.phase, 'ARMED'); assert.deepEqual(faults, []); assert.equal(g.queue.length, 0) })
test('n07 known replays after baseline and after arming stay idempotent', () => { const { guard: g, faults } = make(); baseline(g); g.observe('Target.targetCreated', created('owned')); g.arm(); g.observe('Target.targetCreated', created('owned')); assert.deepEqual(faults, []) })
test('n08 unknown queued pages are not lost before a journal exists', () => { const { guard: g, faults } = make(); g.observe('Target.targetCreated', created('secret-page')); baseline(g); assert.throws(() => g.arm()); assert.equal(g.failed, true); assert.equal(faults[0].code, 'EXTRA_TARGET'); assert(!JSON.stringify(faults).includes('secret-page')) })
test('n09 queued and active service and shared workers remain forbidden', () => { for (const kind of ['service_worker', 'shared_worker']) for (const early of [true, false]) { const { guard: g, faults } = make(); baseline(g); if (!early) g.arm(); g.observe('Target.targetCreated', created('unexpected', kind)); if (early) assert.throws(() => g.arm()); assert(g.failed); assert.equal(faults.at(-1).targetKind, kind) } })
test('n10 created then destroyed unknown page cannot disappear into a later snapshot', () => { const { guard: g, faults } = make(); g.observe('Target.targetCreated', created('unknown')); g.observe('Target.targetDestroyed', { targetId: 'unknown' }); baseline(g); assert.throws(() => g.arm()); assert.equal(faults[0].code, 'EXTRA_TARGET') })
test('n11 baseline cannot be expanded or replaced after it is frozen', () => { const { guard: g } = make(); baseline(g); assert.throws(() => g.setBaseline([{ targetId: 'unknown', type: 'page' }], 'unknown')); g.arm(); assert.throws(() => baseline(g)) })
test('n12 missing owned target duplicate identities and malformed baselines reject', () => { for (const rows of [[], [{ targetId: 'x', type: 'page' }], [{ targetId: 'owned', type: 'worker' }], [{ targetId: 'owned', type: 'page' }, { targetId: 'owned', type: 'page' }], [{ targetId: 'owned', type: 'page' }, { targetId: '../secret', type: 'page' }]]) { const { guard: g } = make(); assert.throws(() => g.setBaseline(rows, 'owned')) } })
test('n13 conflicting known target kind and destroyed identity reuse reject', () => { for (const destroy of [false, true]) { const { guard: g, faults } = make(); baseline(g); g.arm(); if (destroy) g.observe('Target.targetDestroyed', { targetId: 'initial' }); g.observe('Target.targetCreated', created('initial', destroy ? 'page' : 'service_worker')); assert.equal(faults.at(-1).code, 'INVALID_TARGET_STATE') } })
test('n14 selected page destruction is fatal before ordinary close', () => { const { guard: g, faults } = make(); baseline(g); g.arm(); g.observe('Target.targetDestroyed', { targetId: 'owned' }); assert.equal(faults[0].code, 'SESSION_DETACHED'); assert(g.failed) })
test('n15 ordinary close accepts selected destruction but never a new protected target', () => { const { guard: g, faults } = make(); baseline(g); g.arm(); g.beginClose(); g.observe('Target.targetDestroyed', { targetId: 'owned' }); assert.deepEqual(faults, []); g.observe('Target.targetCreated', created('popup')); assert.equal(faults[0].code, 'EXTRA_TARGET'); assert.throws(() => g.endClose()) })
test('n16 malformed target observations are bounded and do not export raw values', () => { const { guard: g, faults } = make(); for (const value of [created('../raw-secret'), created('valid', 'raw/secret'), null]) g.observe('Target.targetCreated', value); baseline(g); assert.throws(() => g.arm()); g.observe('Target.targetCreated', created('owned', 'privatecanaryvalue')); assert(faults.every(v => v.code === 'INVALID_TARGET_STATE')); assert(!JSON.stringify(faults).includes('raw-secret')); assert(!JSON.stringify(faults).includes('raw/secret')); assert(!JSON.stringify(faults).includes('privatecanaryvalue')); assert.equal(faults.at(-1).targetKind, null) })
test('n17 bootstrap queue overflow sets sticky failure instead of dropping events', () => { const { guard: g, faults } = make(); for (let i = 0; i < 129; i++) g.observe('Target.targetCreated', created('owned')); assert.equal(g.queue.length, 128); baseline(g); assert.throws(() => g.arm()); assert.equal(faults[0].code, 'INVALID_TARGET_STATE') })
test('n18 unrelated messages do not invent target observations', () => { const { guard: g, faults } = make(); g.observe('Network.responseReceived', { private: 'not-retained' }); baseline(g); g.arm(); assert.equal(g.failed, false); assert.deepEqual(faults, []) })

test('n19 CDP click dispatches only real pointer input in fixed order', async () => { const calls = []; await dispatchNativeClick(async (...args) => calls.push(args), { x: 10, y: 20 }); assert.deepEqual(calls.map(v => v[1].type), ['mouseMoved', 'mousePressed', 'mouseReleased']); assert(calls.every(v => v[0] === 'Input.dispatchMouseEvent')); assert.equal(calls[1][1].button, 'left'); assert.equal(calls[2][1].clickCount, 1) })
test('n20 click refuses invalid coordinate projections before sending input', async () => { for (const point of [{ x: NaN, y: 1 }, { x: 1, y: -1 }, { x: 1, y: Infinity }, { x: 100001, y: 1 }, { x: 1, y: 1, url: 'secret' }]) { let n = 0; await assert.rejects(dispatchNativeClick(async () => { n++ }, point)); assert.equal(n, 0) } })
test('n21 failed native press prevents release and propagates rejection', async () => { const calls = []; await assert.rejects(dispatchNativeClick(async (method, params) => { calls.push(params.type); if (params.type === 'mousePressed') throw Error('synthetic-only') }, { x: 1, y: 1 })); assert.deepEqual(calls, ['mouseMoved', 'mousePressed']) })
test('n22 click expression escapes labels and validates actual hit target', () => { const s = nativeClickExpression('x";unsafe()', true); assert(s.includes(JSON.stringify('x";unsafe()'))); for (const fragment of ["getAttribute('aria-label')===n", 'scrollIntoView', 'elementFromPoint', "getAttribute('aria-disabled')", 'a.length!==1']) assert(s.includes(fragment)); for (const forbidden of ['dispatchEvent(', '.click(', 'fetch(', 'setAttribute(']) assert(!s.includes(forbidden)); assert.throws(() => nativeClickExpression('bad\nlabel')) })

test('n23 pure close model requires command exit and proc proof in original budgets', async () => { const x = closer(), r = await finishNativeSession(x.o, chrome, x.mechanisms); assert.deepEqual(x.calls, ['close', 20000, 5000, 'proc']); assert.equal(r.normalCloseCommandCompleted, true); assert.equal(r.chromeExit.forced, false); assert.equal(r.launcherExit.code, 0) })
test('n24 close model propagates normal close rejection without reading exit', async () => { let read = false; const x = closer({ closeBrowser: async () => { throw Error('synthetic-only') }, readExit: async () => { read = true; return exit() } }); await assert.rejects(finishNativeSession(x.o, chrome, x.mechanisms)); assert.equal(read, false) })
test('n25 forced nonzero and unjoined Chrome records cannot pass close', async () => { for (const value of [{ ...exit(), forced: true }, { ...exit(), joined: false }, { ...exit(), exitCode: 1 }]) { const x = closer({ readExit: async () => value }); await assert.rejects(finishNativeSession(x.o, chrome, x.mechanisms)) } })
test('n26 missing exit can be polled but malformed exit never treated as missing', async () => { let reads = 0; const x = closer({ readExit: async () => { if (!reads++) throw Object.assign(Error(), { code: 'ENOENT' }); return exit() }, wait: async (p, budget) => { if (budget === 20000) { assert.equal(await p(), false); assert.equal(await p(), true) } else assert.equal(await p(), true) } }); await finishNativeSession(x.o, chrome, x.mechanisms); assert.equal(reads, 2); const y = closer({ readExit: async () => ({ secret: 'not-an-exit' }) }); await assert.rejects(finishNativeSession(y.o, chrome, y.mechanisms)) })
test('n27 launcher signal exit or timeout cannot produce success close', async () => { for (const result of [Promise.resolve({ code: 0, signal: 'SIGTERM' }), Promise.resolve({ code: 1, signal: null }), new Promise(() => {})]) { const x = closer({ launcherResult: result }); await assert.rejects(finishNativeSession(x.o, chrome, x.mechanisms)) } })
test('n28 live residual process and proc permission failure both reject close', async () => { for (const noLive of [async () => false, async () => { throw Error('synthetic-proc-denied') }]) { const x = closer({ noLive }); await assert.rejects(finishNativeSession(x.o, chrome, x.mechanisms)) } })
test('n29 playwright close has null launcher record and still requires no residue', async () => { const x = closer({ launcherResult: null, readExit: async () => exit('playwright') }); x.o = options('playwright'); const r = await finishNativeSession(x.o, chrome, x.mechanisms); assert.equal(r.launcherExit, null); assert(x.calls.includes('proc')) })
test('n30 session module has no business routes mock hooks or insecure launch switches', () => { const s = readFileSync(new URL('./native-session.mjs', import.meta.url), 'utf8'); assert(!s.includes('/api/v1/')); for (const forbidden of ['ignoreHTTPSErrors: true', 'bypassCSP: true', 'setIgnoreCertificateErrors', '--ignore-certificate-errors', '.route(', 'dispatchEvent(', 'fakeTransport']) assert(!s.includes(forbidden)); assert(s.includes('inspectPublicTLS')); assert(s.includes('configureNativeLocale')); assert(s.includes('noLiveChrome(o, chrome)')); assert(s.includes("phase = 'CLOSED'")) })
test('n31 closed event and fault lists contain no duplicate or arbitrary text channel', () => {
  assert.equal(new Set(SESSION_EVENTS).size, SESSION_EVENTS.length); assert.equal(new Set(SESSION_FAULTS).size, SESSION_FAULTS.length); assert(SESSION_EVENTS.includes('Network.loadingFailed')); assert(SESSION_EVENTS.includes('Network.responseReceivedExtraInfo')); assert(SESSION_EVENTS.includes('Network.directUDPSocketCreated')); assert(SESSION_FAULTS.every(v => /^[A-Z_]+$/.test(v)))
  assert.equal(new Set(NATIVE_OPEN_STAGES).size,NATIVE_OPEN_STAGES.length); assert(NATIVE_OPEN_STAGES.every(v=>/^[A-Z_]+$/.test(v)))
  const unseen={shape:'UNOBSERVED',total:null,pages:null,blankPages:null}
  assert.deepEqual(nativeOpenObservation('CDP_PORT_WAIT','STARTUP_REJECTED',unseen).initialTargets,unseen)
  assert.deepEqual(projectInitialTargets([]),{shape:'ARRAY',total:0,pages:0,blankPages:0})
  assert.deepEqual(projectInitialTargets([{type:'page',url:'about:blank',targetId:'PRIVATE-ID'},{type:'service_worker',url:'PRIVATE-URL'}]),{shape:'ARRAY',total:2,pages:1,blankPages:1})
  const invalid={shape:'INVALID',total:null,pages:null,blankPages:null}
  let getterCalls=0
  const hostile={get type(){getterCalls++;throw Error('PRIVATE-GETTER')}}
  for(const rows of [null,{},Array(65).fill({type:'page',url:'PRIVATE-URL'}),[hostile],[{type:'page',get url(){getterCalls++;return 'PRIVATE-URL'}}],Array(1)])assert.deepEqual(projectInitialTargets(rows),invalid)
  assert.equal(getterCalls,0)
  const safe=nativeOpenObservation('CDP_INITIAL_TARGETS','EXTRA_TARGET',projectInitialTargets([{type:'page',url:'PRIVATE-URL',targetId:'PRIVATE-ID'}]))
  assert(!JSON.stringify(safe).includes('PRIVATE'))
  for(const patch of [{shape:'ARRAY',total:true,pages:0,blankPages:0},{shape:'ARRAY',total:1,pages:2,blankPages:0},{...unseen,total:0},{...unseen,url:'PRIVATE'}])assert.throws(()=>nativeOpenObservation('CDP_INITIAL_TARGETS',null,patch))
  assert.throws(()=>nativeOpenObservation('PRIVATE-STAGE',null,unseen)); assert.throws(()=>nativeOpenObservation('CDP_PORT_WAIT','PRIVATE-FAULT',unseen))
  const postUnseen={shape:'UNOBSERVED',total:null,pages:null,blankPages:null,initialPresent:null,selectedPresent:null,selectedKind:null,extraProtectedCount:null}
  const postInvalid={...postUnseen,shape:'INVALID'}, none={phase:null,kind:null}
  assert.deepEqual(nativeOpenObservation('CDP_PORT_WAIT',null,unseen).postTargets,postUnseen)
  const rows=[{targetId:'PRIVATE-INITIAL',type:'page',url:'about:blank'},{targetId:'PRIVATE-OWNED',type:'page',url:'about:blank'},{targetId:'PRIVATE-EXTRA',type:'service_worker',url:'PRIVATE-URL'}]
  const post=projectPostTargets(rows,'PRIVATE-INITIAL','PRIVATE-OWNED')
  assert.deepEqual(post,{shape:'ARRAY',total:3,pages:2,blankPages:2,initialPresent:true,selectedPresent:true,selectedKind:'page',extraProtectedCount:1})
  assert.deepEqual(projectPostTargets([],'PRIVATE-INITIAL','PRIVATE-OWNED'),{...post,total:0,pages:0,blankPages:0,initialPresent:false,selectedPresent:false,selectedKind:'ABSENT',extraProtectedCount:0})
  for(const kind of ['page','service_worker','shared_worker','tab','browser','worker']){
    const r=projectPostTargets([{targetId:'PRIVATE-OWNED',type:kind,url:'about:blank'}],'PRIVATE-INITIAL','PRIVATE-OWNED')
    assert.equal(r.selectedKind,kind==='worker'?'other':kind);assert.equal(r.initialPresent,false);assert.equal(r.selectedPresent,true);assert.equal(r.extraProtectedCount,0)
  }
  const hostileID={type:'page',url:'about:blank',get targetId(){getterCalls++;return 'PRIVATE-OWNED'}}
  const hostileExtra={targetId:'PRIVATE-OWNED',type:'page',url:'about:blank',get title(){getterCalls++;return 'PRIVATE'}}
  for(const r of [null,{},Array(65).fill(rows[0]),Array(1),[hostile],[hostileID],[hostileExtra],[rows[0],rows[0]],[{targetId:'PRIVATE-OWNED',type:'page'}]])assert.deepEqual(projectPostTargets(r,'PRIVATE-INITIAL','PRIVATE-OWNED'),postInvalid)
  assert.equal(getterCalls,0)
  const fault=projectFirstTargetFault('EXTRA_TARGET',{phase:'ARMED',targetKind:'service_worker'})
  assert.deepEqual(fault,{phase:'ARMED',kind:'service_worker'})
  for(const phase of ['BUFFERING','ARMED','CLOSING','CLOSED'])assert.deepEqual(projectFirstTargetFault('INVALID_TARGET_STATE',{phase,targetKind:null}),{phase,kind:null})
  for(const [code,detail] of [['STARTUP_REJECTED',{phase:'ARMED',targetKind:'page'}],['EXTRA_TARGET',{phase:'OPEN',targetKind:'page'}],['EXTRA_TARGET',{phase:'ARMED',targetKind:'PRIVATE'}],['EXTRA_TARGET',{get phase(){getterCalls++;return 'ARMED'},targetKind:'page'}]])assert.deepEqual(projectFirstTargetFault(code,detail),none)
  assert.equal(getterCalls,0)
  const observation=nativeOpenObservation('CDP_POST_TARGETS','EXTRA_TARGET',unseen,post,fault)
  assert(!JSON.stringify(observation).includes('PRIVATE'));assert.deepEqual(observation.firstTargetFault,fault)
  for(const change of [{total:true},{pages:4},{blankPages:3},{initialPresent:1},{selectedPresent:null},{selectedKind:'PRIVATE'},{selectedPresent:false},{extraProtectedCount:4},{privateID:'PRIVATE'}])assert.throws(()=>nativeOpenObservation('CDP_POST_TARGETS','EXTRA_TARGET',unseen,{...post,...change},fault))
  // Preserve accessors for this case rather than invoking them in a spread.
  const accessorPost={...post};Object.defineProperty(accessorPost,'total',{get(){getterCalls++;return 3},enumerable:true})
  assert.throws(()=>nativeOpenObservation('CDP_POST_TARGETS','EXTRA_TARGET',unseen,accessorPost,fault))
  for(const bad of [{phase:true,kind:'page'},{phase:'PRIVATE',kind:'page'},{phase:null,kind:'page'},{phase:'ARMED',kind:'tab'},{phase:'ARMED',kind:'page',rawID:'PRIVATE'}])assert.throws(()=>nativeOpenObservation('CDP_POST_TARGETS','EXTRA_TARGET',unseen,post,bad))
  assert.throws(()=>nativeOpenObservation('CDP_POST_TARGETS','STARTUP_REJECTED',unseen,post,fault))
  assert.throws(()=>nativeOpenObservation('CDP_POST_TARGETS',null,unseen,{...postUnseen,total:0},none))
  assert.equal(getterCalls,0)
  const source=readFileSync(new URL('./native-session.mjs',import.meta.url),'utf8')
  assert(source.includes('await hooks.onDiagnostic(nativeOpenObservation(openStage, firstFault, initialTargets, guard.postTargets, firstTargetFault))'))
  assert(source.includes('if (firstFault === null) { firstFault = code; firstTargetFault = projectFirstTargetFault(code, detail) }'))
  assert(source.indexOf('await hooks.onDiagnostic(')<source.lastIndexOf('await dispose(); throw rejected()'))
})

test('n32 queued unknown target cannot be authorized by appearing in a later snapshot', () => {
  for (const kind of ['page', 'service_worker', 'shared_worker']) {
    const { guard: g } = make()
    g.observe('Target.targetCreated', created('queued-unexpected', kind))
    g.freezeInitial([{ targetId: 'initial', type: 'page', url: 'about:blank' }])
    assert.throws(() => g.setBaseline([{ targetId: 'initial', type: 'page' }, { targetId: 'owned', type: 'page' }, { targetId: 'queued-unexpected', type: kind }], 'owned'))
  }
})
test('n33 initial freeze requires the unique controlled aboutblank page without workers', () => {
  for (const rows of [[], [{ targetId: 'initial', type: 'page', url: 'https://example.invalid/' }],
    [{ targetId: 'initial', type: 'page', url: 'about:blank' }, { targetId: 'other', type: 'page', url: 'about:blank' }],
    ...['service_worker', 'shared_worker'].map(type => [{ targetId: 'initial', type: 'page', url: 'about:blank' }, { targetId: 'worker', type }]),
    [{ targetId: 'initial', type: 'page', url: 'about:blank' }, { targetId: 'initial', type: 'page', url: 'about:blank' }]]) {
    const { guard: g } = make(); assert.throws(() => g.freezeInitial(rows))
  }
  const { guard: g } = make(); g.freezeInitial([{ targetId: 'initial', type: 'page', url: 'about:blank' }])
  assert.throws(() => g.freezeInitial([{ targetId: 'replacement', type: 'page', url: 'about:blank' }]))
  assert.throws(() => g.setBaseline([{ targetId: 'initial', type: 'page' }], 'initial'))
})
test('n34 playwright baseline permits only the actual selected page', () => {
  const { guard: g } = make(); g.setBaseline([{ targetId: 'owned', type: 'page' }], 'owned'); g.arm(); assert.equal(g.phase, 'ARMED')
  for (const type of ['page', 'service_worker', 'shared_worker']) {
    const { guard: other } = make(); other.observe('Target.targetCreated', created('extra', type))
    assert.throws(() => other.setBaseline([{ targetId: 'owned', type: 'page' }, { targetId: 'extra', type }], 'owned'))
  }
})
test('n35 actual CDP initializer freezes before create and installs selected listener before postcheck', async () => {
  const { guard: g } = make(), calls = []
  let snapshots = 0, installed = false
  const send = async (method, params) => {
    calls.push(method)
    if (method === 'Target.getTargets') {
      if (!snapshots++) return { targetInfos: [{ targetId: 'initial', type: 'page', url: 'about:blank' }] }
      assert.equal(installed, true); return { targetInfos: [{ targetId: 'initial', type: 'page', url: 'about:blank' }, { targetId: 'owned', type: 'page', url: 'about:blank' }] }
    }
    if (method === 'Target.createTarget') { assert.equal(g.initial, 'initial'); assert.deepEqual(params, { url: 'about:blank', forTab: false }); return { targetId: 'owned' } }
    if (method === 'Target.attachToTarget') { assert.deepEqual(params, { targetId: 'owned', flatten: true }); return { sessionId: 'selected-session' } }
    assert.equal(method, 'Target.setDiscoverTargets'); assert.deepEqual(params, { discover: true }); return {}
  }
  const result = await initializeCDPTargets(send, g, id => { assert.equal(id, 'selected-session'); installed = true })
  assert.deepEqual(calls, ['Target.getTargets', 'Target.createTarget', 'Target.attachToTarget', 'Target.getTargets', 'Target.setDiscoverTargets'])
  assert.deepEqual(result, { targetId: 'owned', sessionId: 'selected-session' }); assert.equal(g.phase, 'ARMED')
  assert.deepEqual(g.postTargets,{shape:'ARRAY',total:2,pages:2,blankPages:2,initialPresent:true,selectedPresent:true,selectedKind:'page',extraProtectedCount:0})
  const {guard:stalled}=make();let reads=0
  await assert.rejects(initializeCDPTargets(async method=>{
    if(method==='Target.getTargets'){if(reads++)throw Error('PRIVATE-RPC');return{targetInfos:[{targetId:'initial',type:'page',url:'about:blank'}]}}
    if(method==='Target.createTarget')return{targetId:'owned'}
    return{sessionId:'selected-session'}
  },stalled,()=>{}))
  assert.equal(stalled.postTargets.shape,'UNOBSERVED');assert.equal(stalled.postTargets.total,null)
  const source = readFileSync(new URL('./native-session.mjs', import.meta.url), 'utf8')
  assert(source.includes('await initializeCDPTargets(bootstrapSend, guard, sessionId =>'))
  const wrapper = source.match(/const bootstrapSend = async \(method, params\) => \{([\s\S]*?)\n      \}/)?.[1]
  assert(wrapper); assert.equal((wrapper.match(/await browserSendRaw\(method, params\)/g)||[]).length,1)
  assert(wrapper.includes('initialTargets = projectInitialTargets(result?.targetInfos)')); assert(wrapper.includes('return result'))
  for(const forbidden of ['until(', 'setTimeout(', 'guard.', 'spawn(', 'catch'])assert(!wrapper.includes(forbidden))
  assert(source.includes("'--user-data-dir=' + o.profile, 'about:blank'"))
})
test('n36 actual CDP initializer rejects snapshot promotion before discovery can arm', async () => {
  for (const type of ['page', 'service_worker', 'shared_worker']) {
    const { guard: g } = make(), calls = []; let snapshots = 0
    const send = async method => {
      calls.push(method)
      if (method === 'Target.getTargets') return { targetInfos: !snapshots++ ? [{ targetId: 'initial', type: 'page', url: 'about:blank' }] :
        [{ targetId: 'initial', type: 'page', url: 'about:blank' }, { targetId: 'owned', type: 'page', url: 'about:blank' }, { targetId: 'extra', type, url: 'about:blank' }] }
      if (method === 'Target.createTarget') { g.observe('Target.targetCreated', created('extra', type)); return { targetId: 'owned' } }
      if (method === 'Target.attachToTarget') return { sessionId: 'selected-session' }
      throw Error('discovery must not run')
    }
    await assert.rejects(initializeCDPTargets(send, g, () => {})); assert.equal(calls.includes('Target.setDiscoverTargets'), false)
    assert.equal(g.postTargets.extraProtectedCount,1);assert.equal(g.postTargets.selectedKind,'page');assert.equal(g.baseline,null)
  }
})
test('n37 actual PW registration forwards forbidden UDP observations to the real journal', () => {
  const listeners = new Map(), session = { on(method, handler) { assert(!listeners.has(method)); listeners.set(method, handler) } }
  const c = JSON.parse(readFileSync(new URL('../../deploy/overview-ui-browser/contract.json', import.meta.url), 'utf8'))
  const journal = new OverviewJournal(c, 'evidence_enabled_unknown', { allowed: ['/assets/main.js'], required: [] }, ['synthetic-private-canary'], async () => { throw Error('body RPC must not run') }, new Map())
  registerSessionEvents(session, (method, params) => journal.handle(method, params))
  assert.equal(listeners.size, SESSION_EVENTS.length)
  listeners.get('Network.directUDPSocketCreated')({ identifier: 'synthetic-raw-udp-marker-not-for-export' })
  assert.equal(journal.failure, true); assert.equal(journal.counters.forbiddenRequests, 1)
  assert.equal(JSON.stringify(journal.events).includes('synthetic-raw-udp-marker'), false)
  const source = readFileSync(new URL('./native-session.mjs', import.meta.url), 'utf8')
  assert(source.includes('registerSessionEvents(session, event)'))
})
