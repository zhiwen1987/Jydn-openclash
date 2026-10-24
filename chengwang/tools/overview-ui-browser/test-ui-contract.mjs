// Source/CPU contracts only; synthetic bytes below are not built executables.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { loadContract, validateInput, validateRun, validateBuild, apiFence, exactCounts, parseArguments, sha, stepsFor } from './ui-contract.mjs'

const contractRaw = readFileSync(new URL('../../deploy/overview-ui-browser/contract.json', import.meta.url))
const c = loadContract(contractRaw), fixtureId = 'a'.repeat(32), sourceCommit = 'b'.repeat(40)
const args = ['--root', '/tmp/chengwang-subscription-ui-' + fixtureId, '--bundle', '/tmp/chengwang-subscription-ui-tools-' + fixtureId, '--engine', 'chrome-cdp', '--source-commit', sourceCommit]
const o = parseArguments(args)
const input = () => ({ schema: c.schemaNames.input, scenario: c.scenario, profile: c.profiles[0], fixtureId, sourceCommit, engine: 'chrome-cdp', fenceCanary: 'c'.repeat(64) })
function buildFixture(manifest = { 'index.html': { file: 'assets/main.js', isEntry: true, names: ['main'] } }) {
  const manifestRaw = Buffer.from(JSON.stringify(manifest)), serverRaw = Buffer.from([127,69,76,70,1])
  const files = new Map([['.vite/manifest.json', manifestRaw], ['assets/main.js', Buffer.from('source CPU fixture')], ['index.html', Buffer.from('<html/>')], ['trust.html', Buffer.from('<html/>')]])
  const build = { schema: c.schemaNames.build, sourceCommit, goVersion: c.buildAndTrust.goVersion, nodeVersion: c.buildAndTrust.nodeVersion, moduleMode: 'vendor', goDependencyDownloads: false, server: { name: 'server', bytes: serverRaw.length, sha256: sha(serverRaw) }, distFiles: [...files].sort(([a],[b]) => a.localeCompare(b, 'en')).map(([path, raw]) => ({ path, bytes: raw.length, sha256: sha(raw) })), manifestBase64: manifestRaw.toString('base64'), production: false, authorization: 'BLOCKED' }
  // ASCII source path ordering is deliberately the producer's lexical ordering.
  build.distFiles.sort((a,b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)
  return { build, manifestRaw, serverRaw }
}
test('c01 real source contract keeps both complete step plans and nineteen public files', () => {
  assert.equal(c.publicFiles.length, 19); assert.equal(stepsFor(c.profiles[0]).length, 11); assert.equal(stepsFor(c.profiles[1]).length, 17)
  for (const profile of c.profiles) assert.deepEqual(c.stepFences[profile].map(v => v[0]), stepsFor(profile))
})
test('c02 loader rejects incompatible schemas profiles missing manifest table and weakened budgets', () => {
  for (const patch of [v => { v.schema = 'other' }, v => { v.profiles.reverse() }, v => { delete v.manifestAlgorithm }, v => { v.captureRules.bounds.assets = 65 }, v => { v.captureRules.bounds.driverFileBytes++ }, v => { v.stepRules.extraPollAccepted = true }]) {
    const value = JSON.parse(contractRaw); patch(value); assert.throws(() => loadContract(Buffer.from(JSON.stringify(value))))
  }
})
test('c03 omitted reordered and screenshotless checkpoints fail the closed plan', () => {
  for (const patch of [v => v.stepFences.evidence_enabled_unknown.splice(5,2), v => v.stepFences.evidence_disabled.reverse(), v => { v.stepFences.evidence_disabled[0][10] = null }]) {
    const value = JSON.parse(contractRaw); patch(value); assert.throws(() => loadContract(Buffer.from(JSON.stringify(value))))
  }
})
test('c04 real private input binds source fixture engine and profile without identity token', () => {
  assert.equal(validateInput(input(),o,c).profile,'evidence_disabled')
  for (const change of [{ sourceCommit:'d'.repeat(40) }, { fixtureId:'d'.repeat(32) }, { engine:'playwright' }, { profile:'default' }, { identityToken:'private' }, { fenceCanary:'x'.repeat(64) }]) assert.throws(() => validateInput({...input(),...change},o,c))
})
test('c05 run barrier is exact and cannot release another profile or fixture', () => {
  const value={schema:c.schemaNames.run,scenario:c.scenario,profile:input().profile,fixtureId,engine:o.engine}
  assert.equal(validateRun(value,o,input(),c),value)
  for (const change of [{profile:c.profiles[1]},{fixtureId:'d'.repeat(32)},{engine:'playwright'},{pid:2}]) assert.throws(() => validateRun({...value,...change},o,input(),c))
})
test('c06 neutral argument parsing retains supervisor fixed roots and refuses injection', () => {
  assert.equal(o.profile,o.root+'/chrome-profile')
  for (const values of [[],[...args,'--fake','yes'],args.map(v=>v==='chrome-cdp'?'fake':v),args.map(v=>v.startsWith('/tmp/chengwang-subscription-ui-')?'/tmp/other':v)]) assert.throws(() => parseArguments(values))
})
test('c07 build binds actual supplied server and manifest byte hashes', () => {
  const f=buildFixture(),v=validateBuild(f.build,f.manifestRaw,f.serverRaw,c,o)
  assert.deepEqual(v.graph,{allowed:['/assets/main.js'],required:['/assets/main.js']}); assert(v.expectedFiles.has('index.html'))
  assert.throws(() => validateBuild(f.build,f.manifestRaw,Buffer.from('not ELF'),c,o))
  assert.throws(() => validateBuild(f.build,Buffer.from('{}'),f.serverRaw,c,o))
})
test('c08 toolchain provenance mode authorization and declared executable are closed', () => {
  for (const change of [{production:true},{authorization:'APPROVED'},{moduleMode:'mod'},{goDependencyDownloads:true},{goVersion:'other'},{nodeVersion:'other'},{sourceCommit:'d'.repeat(40)},{server:{name:'server',bytes:1,sha256:'a'.repeat(64)}}]) {
    const f=buildFixture(); assert.throws(() => validateBuild({...f.build,...change},f.manifestRaw,f.serverRaw,c,o))
  }
})
test('c09 noncanonical base64 unsafe paths duplicates and invalid file records reject', () => {
  for (const patch of [v => {v.manifestBase64+='\n'},v=>{v.distFiles[1].path='../private'},v=>{v.distFiles.push(v.distFiles[0])},v=>{v.distFiles[0].bytes=true},v=>{v.distFiles[1].sha256='bad'},v=>{v.distFiles.reverse()}]) {
    const f=buildFixture();patch(f.build);assert.throws(() => validateBuild(f.build,f.manifestRaw,f.serverRaw,c,o))
  }
})
test('c10 actual manifest optional names is supported while invented fields and broken edges reject', () => {
  for (const entry of [{file:'assets/main.js',isEntry:true,privateField:true},{file:'assets/main.js',isEntry:true,imports:['missing']},{file:'assets/main.js',isEntry:true,names:[1]}]) {
    const f=buildFixture({'index.html':entry});assert.throws(() => validateBuild(f.build,f.manifestRaw,f.serverRaw,c,o))
  }
})
test('c11 capture ordinal fence is derived from completed rows and preserves sparse kind positions', () => {
  const rows=[{ordinal:1,kind:'DOCUMENT'},{ordinal:2,kind:'SNAPSHOT'},{ordinal:3,kind:'ASSET'},{ordinal:4,kind:'OVERVIEW'},{ordinal:5,kind:'PROBE_STATUS'}]
  assert.deepEqual(apiFence(rows),{snapshotCaptureOrdinal:2,overviewCaptureOrdinals:[4],observationStatusCaptureOrdinals:[],probeStatusCaptureOrdinals:[5]})
  assert.throws(() => apiFence(rows.toReversed()));assert.throws(() => apiFence([{ordinal:true,kind:'SNAPSHOT'}]))
})
test('c12 exact API fences reject extra overview or polling requests', () => {
  const f=c.stepFences.evidence_enabled_unknown.find(r=>r[0]==='nodes_page_desktop')
  const rows=[{kind:'SNAPSHOT'},...Array.from({length:4},()=>({kind:'OVERVIEW'})),{kind:'OBSERVATION_STATUS'},{kind:'PROBE_STATUS'}]
  assert.equal(exactCounts(rows,f),true);assert.equal(exactCounts([...rows,{kind:'PROBE_STATUS'}],f),false)
  assert.equal(exactCounts([...rows,{kind:'OVERVIEW'}],f),false)
})
