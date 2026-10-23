/// <reference types="node" />
// @vitest-environment jsdom
// All HTTP bodies here are synthetic mocks, not actual product/TLS evidence.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { runInNewContext } from 'node:vm'
import { createSubscriptionIntent, readSubscriptionAccess, readSubscriptionCandidates, readSubscriptionNodes,
  readSubscriptionReceipt, readSubscriptionSources, releaseSubscriptionIntent, SubscriptionAPIError, writeSubscriptionCommand } from './subscription-api'
import type { SubscriptionCode, SubscriptionIntent, SubscriptionIntentInput } from './subscription-types'
import { subscriptionAccess, subscriptionCandidateId, subscriptionCandidatePage, subscriptionCommandId, subscriptionDigest,
  subscriptionEnvelope, subscriptionNodePage, subscriptionReceipt, subscriptionResponse, subscriptionSourceId, subscriptionSourcePage } from './subscription-test-fixtures'

const token = 'synthetic-memory-only'
const signal = () => new AbortController().signal
const q = () => ({ limit: 100, offset: 0, revision: 3 })
const sourceRead = () => readSubscriptionSources(token, signal())
function install(value: unknown) { const fn = vi.fn<typeof fetch>(async () => subscriptionResponse(value)); vi.stubGlobal('fetch', fn); return fn }
function rawResponse(raw: string | Uint8Array, headers: Record<string, string> = {}) {
  return new Response(raw as BodyInit, { headers: { 'Content-Type': 'application/json', ...headers } })
}
function rawFetch(raw: string | Uint8Array, headers: Record<string, string> = {}) { vi.stubGlobal('fetch', vi.fn(async () => rawResponse(raw, headers))) }
function bytes(value: string) { return new TextEncoder().encode(value) }
function input(kind: SubscriptionIntentInput['kind']): SubscriptionIntentInput {
  if (kind === 'create') return { kind, label: 'Synthetic source' }
  if (kind === 'import') return { kind, sourceId: subscriptionSourceId, expectedRevision: 3, format: 'auto', content: bytes('proxies: []\n') }
  if (kind === 'approve') return { kind, sourceId: subscriptionSourceId, expectedRevision: 3, referenceId: 'synthetic-reference', policyRevision: 1 }
  if (kind === 'fetch') return { kind, sourceId: subscriptionSourceId, expectedRevision: 3, approvalId: subscriptionCommandId, policyRevision: 1 }
  if (kind === 'decide') return { kind, sourceId: subscriptionSourceId, expectedRevision: 3, candidateId: subscriptionCandidateId, expectedDigest: subscriptionDigest, decision: 'admitted_local' }
  return { kind, sourceId: subscriptionSourceId, expectedRevision: 3, candidateId: subscriptionCandidateId }
}
function postedReceipt(kind: SubscriptionIntentInput['kind']) {
  return subscriptionReceipt({ kind, revision: kind === 'create' ? 1 : kind === 'approve' ? 3 : 4, ...(kind === 'import' || kind === 'fetch' || kind === 'decide' || kind === 'rollback' ? { candidateId: subscriptionCandidateId, candidateDigest: subscriptionDigest } : {}),
    ...(kind === 'approve' ? { state: 'approved', localAuditHash: undefined, referenceId: 'synthetic-reference', policyRevision: 1, policyDigest: subscriptionDigest, approvalId: subscriptionCommandId } : {}) })
}
async function rejected(value: unknown, call: () => Promise<unknown> = sourceRead) { install(value); await expect(call()).rejects.toBeInstanceOf(SubscriptionAPIError) }
beforeEach(() => { vi.stubGlobal('window', { location: { origin: 'https://console.example', protocol: 'https:' } }) })
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks() })

describe('subscription API', () => {
  it('rejects insecure transport including loopback', async () => {
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher)
    for (const host of ['127.0.0.1', 'localhost', '[::1]', '10.88.0.1']) {
      vi.stubGlobal('window', { location: { origin: `http://${host}`, protocol: 'http:' } })
      await expect(sourceRead()).rejects.toMatchObject({ kind: 'transport', stateMayHaveChanged: false })
    }
    expect(fetcher).not.toHaveBeenCalled()
  })
  it('rejects foreign origin and redirected responses', async () => {
    for (const props of [{ url: 'https://foreign.example/api/v1/subscriptions/sources' }, { redirected: true }, { url: 'https://console.example/api/v1/subscriptions/sources?unexpected=1' }]) {
      const response = subscriptionResponse(subscriptionSourcePage()); Object.defineProperties(response, Object.fromEntries(Object.entries(props).map(([k, value]) => [k, { value }])))
      vi.stubGlobal('fetch', vi.fn(async () => response)); await expect(sourceRead()).rejects.toMatchObject({ kind: 'format' })
    }
  })
  it('rejects invalid tokens before fetch', async () => {
    const f = vi.fn(); vi.stubGlobal('fetch', f)
    for (const bad of ['', 'bad token', 'bad,token', 'bad\r\nheader', 'x'.repeat(4097), '\u0080']) await expect(readSubscriptionSources(bad, signal())).rejects.toMatchObject({ kind: 'authentication' })
    expect(f).not.toHaveBeenCalled()
  })
  it('sends closed credential-free read options', async () => {
    const f = install(subscriptionSourcePage()); const abort = signal(); await readSubscriptionSources(token, abort)
    expect(f).toHaveBeenCalledWith('/api/v1/subscriptions/sources', { method: 'GET', signal: expect.any(AbortSignal), headers: { Accept: 'application/json', Authorization: `Bearer ${token}` }, mode: 'same-origin', credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer' })
    expect(f.mock.calls[0][1]?.signal).not.toBe(abort)
    expect(f.mock.calls).toHaveLength(1)
  })
  it('reads collection and source access metadata', async () => {
    const f = install(subscriptionAccess()); expect(await readSubscriptionAccess(token, signal())).toEqual(subscriptionAccess())
    expect(f.mock.calls[0][0]).toBe('/api/v1/subscriptions/access')
    install(subscriptionAccess(subscriptionSourceId)); expect(await readSubscriptionAccess(token, signal(), subscriptionSourceId)).toEqual(subscriptionAccess(subscriptionSourceId))
  })
  it('rejects invalid access actions and references', async () => {
    const read = () => readSubscriptionAccess(token, signal())
    for (const change of [{ actions: ['fetch'] }, { actions: ['subscription.source.manage', 'subscription.read'] }, { actions: ['subscription.read', 'subscription.read'] }, { references: [] }, { references: [{ referenceId: 'bad/url', revision: 1 }] }, { policyState: 'unavailable' }]) await rejected({ ...subscriptionAccess(), ...change }, read)
    install({ ...subscriptionAccess(), policyState: 'not_configured', references: [] }); await expect(read()).resolves.toMatchObject({ references: [] })
  })
  it('reads bounded source metadata', async () => { install(subscriptionSourcePage()); expect(await sourceRead()).toEqual(subscriptionSourcePage()); install({ total: 0, sources: [] }); await expect(sourceRead()).resolves.toEqual({ total: 0, sources: [] }) })
  it('rejects source scope ids labels and duplicates', async () => {
    for (const change of [{ id: '../private' }, { label: 'https://private.example' }, { revision: 0 }, { scope: { tenantId: '', siteId: 's', environment: 'candidate' } }, { password: 'not-public' }]) {
      const p = subscriptionSourcePage(); Object.assign(p.sources[0], change); await rejected(p)
    }
    const p = subscriptionSourcePage(); p.sources.push({ ...p.sources[0] }); p.total = 2; await rejected(p)
  })
  it('reads candidate pages without private nodes', async () => {
    install(subscriptionCandidatePage()); expect(await readSubscriptionCandidates(token, signal(), subscriptionSourceId, q())).toEqual(subscriptionCandidatePage())
    const p = subscriptionCandidatePage(); Object.assign(p.candidates[0], { nodes: [] }); await rejected(p, () => readSubscriptionCandidates(token, signal(), subscriptionSourceId, q()))
  })
  it('rejects invalid candidate digests and formats', async () => {
    for (const change of [{ digest: 'sha256:' + 'a'.repeat(64) }, { format: 'auto' }, { nodeCount: 0 }, { duplicateCount: 1024 }, { state: 'healthy' }, { baseRevision: 4 }]) {
      const p = subscriptionCandidatePage(); Object.assign(p.candidates[0], change); await rejected(p, () => readSubscriptionCandidates(token, signal(), subscriptionSourceId, q()))
    }
  })
  it('binds candidate pages to source and revision', async () => {
    let p = subscriptionCandidatePage(); p.candidates[0].sourceId = 'src_' + 'f'.repeat(32)
    await rejected(p, () => readSubscriptionCandidates(token, signal(), subscriptionSourceId, q()))
    p = subscriptionCandidatePage(); p.revision = 4; await rejected(p, () => readSubscriptionCandidates(token, signal(), subscriptionSourceId, q()))
  })
  it('reads safe unknown node pages', async () => { install(subscriptionNodePage()); expect(await readSubscriptionNodes(token, signal(), subscriptionSourceId, subscriptionCandidateId, q())).toEqual(subscriptionNodePage()) })
  it('rejects unsafe node labels and duplicate ids', async () => {
    for (const change of [{ label: 'private upstream name' }, { protocol: 'exec' }, { state: 'available' }, { credentialConfigured: 'yes' }, { config: {} }]) {
      const p = subscriptionNodePage(); Object.assign(p.nodes[0], change); await rejected(p, () => readSubscriptionNodes(token, signal(), subscriptionSourceId, subscriptionCandidateId, q()))
    }
    const p = subscriptionNodePage(); p.nodes[1] = { ...p.nodes[0] }; await rejected(p, () => readSubscriptionNodes(token, signal(), subscriptionSourceId, subscriptionCandidateId, q()))
  })
  it('rejects invalid paging before fetch', () => {
    const f = vi.fn(); vi.stubGlobal('fetch', f)
    for (const bad of [{ limit: 101, offset: 0 }, { limit: 1, offset: 1 }, { limit: 1, offset: -1 }, { limit: 1, offset: 0, revision: 0 }, { limit: 1, offset: 0, proxy: 'private' }]) expect(() => readSubscriptionCandidates(token, signal(), subscriptionSourceId, bad)).toThrow(SubscriptionAPIError)
    expect(() => readSubscriptionNodes(token, signal(), '../source', subscriptionCandidateId, q())).toThrow(SubscriptionAPIError); expect(f).not.toHaveBeenCalled()
  })
  it('binds node paging totals and next offset', async () => {
    const p = subscriptionNodePage(); p.nodes = p.nodes.slice(0, 1); Object.assign(p, { nextOffset: 1 }); install(p)
    await expect(readSubscriptionNodes(token, signal(), subscriptionSourceId, subscriptionCandidateId, { limit: 1, offset: 0, revision: 3 })).resolves.toMatchObject({ nextOffset: 1 })
    for (const change of [{ nextOffset: 2 }, { total: 1025 }, { revision: 4 }]) await rejected({ ...p, ...change }, () => readSubscriptionNodes(token, signal(), subscriptionSourceId, subscriptionCandidateId, { limit: 1, offset: 0, revision: 3 }))
  })
  it('reads immutable historical receipts', async () => {
    install(subscriptionReceipt()); const r = await readSubscriptionReceipt(token, signal(), subscriptionCommandId)
    expect(r.revision).toBe(1); expect(r.replayed).toBe(false)
  })
  it('accepts prepared failed and uncertain receipts', async () => {
    for (const r of [subscriptionReceipt({ state: 'prepared', revision: 0, code: 'subscription_commit_unknown', stateMayHaveChanged: true, auditRecorded: false, localAuditHash: undefined, resultAuditHash: undefined, completedAt: '0001-01-01T00:00:00Z' }),
      subscriptionReceipt({ state: 'unknown', code: 'subscription_commit_unknown', stateMayHaveChanged: true, localAuditHash: undefined }),
      subscriptionReceipt({ state: 'failed', code: 'subscription_unavailable', localAuditHash: undefined })]) {
      vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(subscriptionEnvelope(r, undefined, r.stateMayHaveChanged)), { headers: { 'Content-Type': 'application/json' } })))
      await expect(readSubscriptionReceipt(token, signal(), subscriptionCommandId)).resolves.toEqual(r)
    }
  })
  it('rejects invalid receipt states and hashes', async () => {
    for (const change of [{ state: 'audit_degraded' }, { localAuditHash: 'bad' }, { state: 'unknown', code: 'subscription_commit_unknown', stateMayHaveChanged: false }, { state: 'failed', stateMayHaveChanged: true }, { preparedAuditHash: '' }, { privateToken: 'never' }]) await rejected({ ...subscriptionReceipt(), ...change }, () => readSubscriptionReceipt(token, signal(), subscriptionCommandId))
  })
  it('rejects receipt command and envelope mismatches', async () => {
    await rejected(subscriptionReceipt({ commandId: 'cmd_' + 'f'.repeat(32) }), () => readSubscriptionReceipt(token, signal(), subscriptionCommandId))
    rawFetch(JSON.stringify({ ...subscriptionEnvelope(subscriptionReceipt()), authorization: 'APPROVED' })); await expect(readSubscriptionReceipt(token, signal(), subscriptionCommandId)).rejects.toMatchObject({ kind: 'format' })
  })
  it('rejects missing content type and invalid content length', async () => {
    const headers: Record<string, string>[] = [{ 'Content-Type': 'text/html' }, { 'Content-Type': 'application/json; charset=latin1' }, { 'Content-Length': '9999999' }, { 'Content-Length': '01' }, { 'Content-Length': '2' }]
    for (const h of headers) {
      rawFetch(JSON.stringify(subscriptionEnvelope(subscriptionSourcePage())), h); await expect(sourceRead()).rejects.toMatchObject({ kind: 'format' })
    }
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}'))); await expect(sourceRead()).rejects.toMatchObject({ kind: 'format' })
  })
  it('bounds streaming response bytes before parsing', async () => {
    let canceled = false
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array((3 << 19) + 1)) }, cancel() { canceled = true } }), { headers: { 'Content-Type': 'application/json' } })))
    await expect(sourceRead()).rejects.toMatchObject({ kind: 'format' }); expect(canceled).toBe(true)
  })
  it('rejects invalid utf8 and truncated streams', async () => {
    const serialized = JSON.stringify(subscriptionEnvelope(subscriptionSourcePage()))
    const foreign: Uint8Array = runInNewContext('new Uint8Array(values)', { values: Array.from(bytes(serialized)) })
    expect(foreign instanceof Uint8Array).toBe(false)
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream<Uint8Array>({ start(c) { c.enqueue(foreign); c.close() } }), { headers: { 'Content-Type': 'application/json' } })))
    await expect(sourceRead()).resolves.toEqual(subscriptionSourcePage())
    const wrongTag = new Uint16Array([1]); Object.defineProperty(wrongTag, Symbol.toStringTag, { value: 'Uint8Array' })
    for (const chunk of [new DataView(new ArrayBuffer(1)), new Uint8ClampedArray([1]), [1, 2], { byteLength: 1, [Symbol.toStringTag]: 'Uint8Array' }, wrongTag]) {
      vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream<Uint8Array>({ start(c) { c.enqueue(chunk as Uint8Array); c.close() } }), { headers: { 'Content-Type': 'application/json' } })))
      await expect(sourceRead()).rejects.toMatchObject({ kind: 'format' })
    }
    for (const raw of [new Uint8Array([0xff]), bytes('{"result":'), bytes('"\ud800"')]) { rawFetch(raw); await expect(sourceRead()).rejects.toMatchObject({ kind: 'format' }) }
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream({ start(c) { c.error(new Error('private upstream diagnostic')) } }), { headers: { 'Content-Type': 'application/json' } })))
    const e = await sourceRead().catch(e => e); expect(e).toMatchObject({ kind: 'format' }); expect(String(e)).not.toContain('private')
  })
  it('rejects duplicate json keys and trailing values', async () => {
    const good = JSON.stringify(subscriptionEnvelope(subscriptionSourcePage()))
    for (const raw of [good.replace('"boundary":', '"boundary":"bad","boundary":'), good + '{}', good.replace('"total":1', '"total":1,"total":1')]) { rawFetch(raw); await expect(sourceRead()).rejects.toMatchObject({ kind: 'format' }) }
  })
  it('rejects json depth nodes and unsafe numbers', async () => {
    for (const raw of ['['.repeat(18) + '0' + ']'.repeat(18), '[' + '0,'.repeat(16385) + '0]', JSON.stringify(subscriptionEnvelope(subscriptionSourcePage())).replace('"total":1', '"total":9007199254740992'), '{"x":NaN}', '{"x":1.2}']) { rawFetch(raw); await expect(sourceRead()).rejects.toMatchObject({ kind: 'format' }) }
  })
  it('rejects unknown envelope and dto fields', async () => {
    rawFetch(JSON.stringify({ ...subscriptionEnvelope(subscriptionSourcePage()), token: 'never' })); await expect(sourceRead()).rejects.toMatchObject({ kind: 'format' })
    await rejected({ ...subscriptionSourcePage(), nodes: [] })
  })
  it('creates immutable high entropy command intents', () => {
    const a = createSubscriptionIntent(input('create')), b = createSubscriptionIntent(input('create'))
    expect(Object.isFrozen(a)).toBe(true); expect(a.idempotencyKey).toMatch(/^sub_[a-f0-9]{32}$/); expect(a.idempotencyKey).not.toBe(b.idempotencyKey)
    expect(() => Object.assign(a, { label: 'changed' })).toThrow(); releaseSubscriptionIntent(a); releaseSubscriptionIntent(b)
  })
  it('keeps import bytes private and releases them', async () => {
    const raw = bytes('synthetic-private-import'); const intent = createSubscriptionIntent({ kind: 'import', sourceId: subscriptionSourceId, expectedRevision: 3, format: 'auto', content: raw }); raw.fill(0)
    expect(JSON.stringify(intent)).not.toMatch(/content|private-import/); const f = install(postedReceipt('import')); await writeSubscriptionCommand(token, signal(), intent)
    expect(JSON.parse(String(f.mock.calls[0][1]?.body)).contentBase64).toBe(btoa('synthetic-private-import')); releaseSubscriptionIntent(intent)
    expect(() => writeSubscriptionCommand(token, signal(), intent)).toThrow(SubscriptionAPIError)
  })
  it('validates exact create and import intents', async () => {
    for (const value of [{ kind: 'create', label: 'bad/url' }, { kind: 'create', label: 'source', url: 'never' }, { ...input('import'), content: new Uint8Array(0) }, { ...input('import'), content: new Uint8Array((1 << 20) + 1) }, { ...input('import'), format: 'json' }]) expect(() => createSubscriptionIntent(value as SubscriptionIntentInput)).toThrow(SubscriptionAPIError)
    const full = createSubscriptionIntent({ ...input('import'), kind: 'import', sourceId: subscriptionSourceId, expectedRevision: 3, format: 'auto', content: new Uint8Array(1 << 20).fill(120) })
    const f = install(postedReceipt('import')); await writeSubscriptionCommand(token, signal(), full)
    expect(new TextEncoder().encode(String(f.mock.calls[0][1]?.body)).byteLength).toBeLessThanOrEqual(3 << 19)
    releaseSubscriptionIntent(full)
    const foreign: Uint8Array = runInNewContext('new Uint8Array([120, 121])')
    expect(foreign instanceof Uint8Array).toBe(false)
    const crossRealm = createSubscriptionIntent({ ...input('import'), kind: 'import', sourceId: subscriptionSourceId, expectedRevision: 3, format: 'auto', content: foreign })
    foreign.fill(0); const copied = install(postedReceipt('import')); await writeSubscriptionCommand(token, signal(), crossRealm)
    expect(JSON.parse(String(copied.mock.calls[0][1]?.body)).contentBase64).toBe(btoa('xy')); releaseSubscriptionIntent(crossRealm)
    const wrongTag = new Uint16Array([120]); Object.defineProperty(wrongTag, Symbol.toStringTag, { value: 'Uint8Array' })
    for (const content of [new DataView(new ArrayBuffer(1)), new Uint8ClampedArray([120]), [120], { byteLength: 1, [Symbol.toStringTag]: 'Uint8Array' }, wrongTag]) expect(() => createSubscriptionIntent({ ...input('import'), content } as SubscriptionIntentInput)).toThrow(SubscriptionAPIError)
  })
  it('validates exact approve and fetch intents', () => {
    for (const value of [{ ...input('approve'), referenceId: 'private/url' }, { ...input('approve'), policyRevision: 0 }, { ...input('fetch'), approvalId: 'approval_bad' }, { ...input('fetch'), expectedRevision: 0 }, { ...input('approve'), proxy: true }]) expect(() => createSubscriptionIntent(value as SubscriptionIntentInput)).toThrow(SubscriptionAPIError)
  })
  it('validates exact decide and rollback intents', () => {
    for (const value of [{ ...input('decide'), expectedDigest: 'sha256:' + 'a'.repeat(64) }, { ...input('decide'), decision: 'available' }, { ...input('rollback'), candidateId: 'invalid' }, { ...input('rollback'), expectedDigest: subscriptionDigest }]) expect(() => createSubscriptionIntent(value as SubscriptionIntentInput)).toThrow(SubscriptionAPIError)
  })
  it('posts create and import to fixed routes', async () => {
    for (const kind of ['create', 'import'] as const) { const i = createSubscriptionIntent(input(kind)); const f = install(postedReceipt(kind)); await writeSubscriptionCommand(token, signal(), i); expect(f.mock.calls[0][0]).toBe('/api/v1/subscriptions/sources' + (kind === 'import' ? '/' + subscriptionSourceId + '/candidates' : '')); expect(f.mock.calls[0][1]).toMatchObject({ method: 'POST', credentials: 'omit', headers: { 'Idempotency-Key': i.idempotencyKey, 'Content-Type': 'application/json' } }); releaseSubscriptionIntent(i) }
    for (const kind of ['create', 'import'] as const) {
      const i = createSubscriptionIntent(input(kind)); install({ ...postedReceipt(kind), revision: 3 })
      await expect(writeSubscriptionCommand(token, signal(), i)).rejects.toMatchObject({ kind: 'format', stateMayHaveChanged: true })
      if (kind === 'import') { install({ ...postedReceipt(kind), state: 'noop', revision: 3, localAuditHash: undefined }); await expect(writeSubscriptionCommand(token, signal(), i)).resolves.toMatchObject({ state: 'noop', revision: 3 }) }
      releaseSubscriptionIntent(i)
    }
  })
  it('posts approve and fetch to fixed routes', async () => {
    for (const kind of ['approve', 'fetch'] as const) { const i = createSubscriptionIntent(input(kind)); const f = install(postedReceipt(kind)); await writeSubscriptionCommand(token, signal(), i); expect(f.mock.calls[0][0]).toBe(`/api/v1/subscriptions/sources/${subscriptionSourceId}/${kind === 'approve' ? 'approvals' : 'fetches'}`); expect(JSON.parse(String(f.mock.calls[0][1]?.body))).toMatchObject({ expectedRevision: 3, policyRevision: 1 }); releaseSubscriptionIntent(i) }
    const i = createSubscriptionIntent(input('approve'))
    for (const change of [{ approvalId: 'cmd_' + 'f'.repeat(32) }, { referenceId: 'other-reference' }, { policyRevision: 2 }, { revision: 4 }, { state: 'noop' }]) {
      install({ ...postedReceipt('approve'), ...change }); await expect(writeSubscriptionCommand(token, signal(), i)).rejects.toMatchObject({ kind: 'format', stateMayHaveChanged: true })
    }
    releaseSubscriptionIntent(i)
    const f = createSubscriptionIntent(input('fetch')); install({ ...postedReceipt('fetch'), candidateDigest: undefined }); await expect(writeSubscriptionCommand(token, signal(), f)).rejects.toMatchObject({ kind: 'format' }); releaseSubscriptionIntent(f)
  })
  it('posts decide and rollback to fixed routes', async () => {
    for (const kind of ['decide', 'rollback'] as const) { const i = createSubscriptionIntent(input(kind)); const f = install(postedReceipt(kind)); await writeSubscriptionCommand(token, signal(), i); expect(f.mock.calls[0][0]).toBe(`/api/v1/subscriptions/sources/${subscriptionSourceId}/${kind === 'decide' ? 'decisions' : 'rollbacks'}`); releaseSubscriptionIntent(i) }
    for (const kind of ['decide', 'rollback'] as const) {
      const i = createSubscriptionIntent(input(kind))
      for (const change of [{ candidateId: 'cand_' + 'f'.repeat(32) }, { revision: 3 }, { state: 'noop', localAuditHash: undefined }]) { install({ ...postedReceipt(kind), ...change }); await expect(writeSubscriptionCommand(token, signal(), i)).rejects.toMatchObject({ kind: 'format' }) }
      if (kind === 'decide') { install({ ...postedReceipt(kind), candidateDigest: 'hmac-sha256:' + 'f'.repeat(64) }); await expect(writeSubscriptionCommand(token, signal(), i)).rejects.toMatchObject({ kind: 'format' }) }
      // An idempotent service replay keeps the original revision, even if a
      // separately refreshed inventory has since advanced beyond it.
      install({ ...postedReceipt(kind), replayed: true }); await expect(writeSubscriptionCommand(token, signal(), i)).resolves.toMatchObject({ revision: 4, replayed: true })
      releaseSubscriptionIntent(i)
    }
  })
  it('preserves idempotency keys without automatic retries', async () => {
    const i = createSubscriptionIntent(input('fetch')); const f = vi.fn(async () => { throw new Error('upstream secret') }); vi.stubGlobal('fetch', f)
    await expect(writeSubscriptionCommand(token, signal(), i)).rejects.toMatchObject({ kind: 'transport', stateMayHaveChanged: true }); expect(f).toHaveBeenCalledTimes(1)
    install(postedReceipt('fetch')); await writeSubscriptionCommand(token, signal(), i); expect(i.idempotencyKey).toMatch(/^sub_[a-f0-9]{32}$/); releaseSubscriptionIntent(i)
  })
  it('preserves safe command ids and uncertain errors', async () => {
    const i = createSubscriptionIntent(input('fetch'))
    for (const code of ['subscription_audit_degraded', 'subscription_commit_unknown'] as const) {
      vi.stubGlobal('fetch', vi.fn(async () => subscriptionResponse(undefined, 503, code, true, { 'X-Chengwang-Command-ID': subscriptionCommandId })))
      const e = await writeSubscriptionCommand(token, signal(), i).catch(e => e); expect(e).toMatchObject({ commandId: subscriptionCommandId, code, stateMayHaveChanged: true }); expect(String(e)).not.toContain(token)
    }
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 503, headers: { 'Content-Type': 'application/json', 'X-Chengwang-Command-ID': subscriptionCommandId } })))
    await expect(writeSubscriptionCommand(token, signal(), i)).rejects.toMatchObject({ commandId: subscriptionCommandId, stateMayHaveChanged: true, kind: 'format' })
    releaseSubscriptionIntent(i)
  })
  it('translates authorization lock and conflict errors', async () => {
    for (const [status, code, kind] of [[401, 'subscription_forbidden', 'authentication'], [403, 'subscription_forbidden', 'forbidden'], [423, 'subscription_writes_disabled', 'locked'], [409, 'subscription_command_conflict', 'conflict'], [409, 'subscription_approval_required', 'conflict'], [429, 'subscription_command_limit', 'limit'], [503, 'subscription_unavailable', 'unavailable']] as const) {
      vi.stubGlobal('fetch', vi.fn(async () => subscriptionResponse(undefined, status, code))); await expect(sourceRead()).rejects.toMatchObject({ status, code, kind, stateMayHaveChanged: false })
    }
  })
  it('rejects unknown errors and unsafe command headers', async () => {
    for (const [code, header] of [['unknown_secret_error', ''], ['subscription_unavailable', 'cmd_private-not-an-id']]) {
      vi.stubGlobal('fetch', vi.fn(async () => subscriptionResponse(undefined, 503, code as SubscriptionCode, false, header ? { 'X-Chengwang-Command-ID': header } : {})))
      const e = await sourceRead().catch(e => e); expect(e).toMatchObject({ kind: 'format' }); expect(String(e)).not.toContain('secret')
    }
  })
  it('cancels reads without leaking upstream errors', async () => {
    const c = new AbortController(); const f = vi.fn(); vi.stubGlobal('fetch', f); c.abort(); await expect(readSubscriptionSources(token, c.signal)).rejects.toMatchObject({ kind: 'canceled', stateMayHaveChanged: false }); expect(f).not.toHaveBeenCalled()
    const d = new AbortController(); vi.stubGlobal('fetch', vi.fn(async () => { d.abort(); throw new Error('private URL') })); const e = await readSubscriptionSources(token, d.signal).catch(e => e); expect(e.kind).toBe('canceled'); expect(String(e)).not.toContain('private')
    vi.useFakeTimers(); const stalled = vi.fn(() => new Promise<Response>(() => {})); vi.stubGlobal('fetch', stalled)
    const pending = sourceRead().catch(e => e); await vi.advanceTimersByTimeAsync(30000)
    expect(await pending).toMatchObject({ kind: 'canceled', stateMayHaveChanged: false }); expect(stalled).toHaveBeenCalledOnce(); expect(vi.getTimerCount()).toBe(0)
  })
  it('treats interrupted writes as potentially changed', async () => {
    const i = createSubscriptionIntent(input('fetch')); const c = new AbortController(); const f = vi.fn(); vi.stubGlobal('fetch', f); c.abort(); await expect(writeSubscriptionCommand(token, c.signal, i)).rejects.toMatchObject({ stateMayHaveChanged: false }); expect(f).not.toHaveBeenCalled()
    rawFetch('{}'); await expect(writeSubscriptionCommand(token, signal(), i)).rejects.toMatchObject({ kind: 'format', stateMayHaveChanged: true })
    const d = new AbortController(); vi.stubGlobal('fetch', vi.fn(async () => { d.abort(); throw new Error('secret') })); await expect(writeSubscriptionCommand(token, d.signal, i)).rejects.toMatchObject({ kind: 'canceled', stateMayHaveChanged: true })
    vi.useFakeTimers(); const stalled = vi.fn(async () => new Response(new ReadableStream<Uint8Array>({ start() { /* No EOF until abort. */ } }), { status: 503, headers: { 'Content-Type': 'application/json', 'X-Chengwang-Command-ID': subscriptionCommandId } })); vi.stubGlobal('fetch', stalled)
    const pending = writeSubscriptionCommand(token, signal(), i).catch(e => e); await vi.advanceTimersByTimeAsync(30000)
    expect(await pending).toMatchObject({ kind: 'canceled', stateMayHaveChanged: true, commandId: subscriptionCommandId }); expect(stalled).toHaveBeenCalledOnce(); expect(vi.getTimerCount()).toBe(0)
    releaseSubscriptionIntent(i)
  })
  it('rejects forged mutated and released intents', () => {
    const f = vi.fn(); vi.stubGlobal('fetch', f); const i = createSubscriptionIntent(input('create'))
    expect(() => writeSubscriptionCommand(token, signal(), { ...i } as SubscriptionIntent)).toThrow(SubscriptionAPIError)
    expect(() => writeSubscriptionCommand(token, signal(), Object.freeze({ ...i, idempotencyKey: 'forged-key-000000' }) as SubscriptionIntent)).toThrow(SubscriptionAPIError)
    releaseSubscriptionIntent(i); expect(() => writeSubscriptionCommand(token, signal(), i)).toThrow(SubscriptionAPIError); expect(f).not.toHaveBeenCalled()
  })
})
