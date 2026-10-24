// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://console.example"}
import '@testing-library/jest-dom/vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { APIError, getSnapshot } from './api'
import { decodeSnapshotReport, SNAPSHOT_FORMAT_ERROR, SNAPSHOT_LIMITS } from './snapshot-report'

// Synthetic JSON-shaped fixture, not a real request or current runtime proof.
// Fields/nil/omitempty come from internal/domain/model.go and api/seed.go.
// Negative cases deliberately replace nested wire values with invalid shapes;
// repeating the production model would prevent those test-only mutations.
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- Deliberately malformed JSON mutation bag; decoded results keep production types.
type Raw = Record<string, any>
function wireSnapshot(): Raw {
  return {
    product: 'Synthetic Go-shaped snapshot', version: '尚未发布', mode: 'shadow', status: 'Synthetic source metadata', dataSource: 'demo', publishLocked: true,
    businesses: [{ id: 'chatgpt', name: 'Synthetic business', strategy: 'chatgpt_pool', activeRoute: 'Synthetic route', status: '未评估' }],
    pools: [{ name: 'Synthetic status pool', region: '未知', latencyMs: 0, lossRate: 0.2, available: 0, total: 1, status: '未评估' }],
    interfaces: [{ id: 'lan_mixed', name: 'Synthetic interface', type: 'mixed', core: 'Mihomo', listen: '0.0.0.0', port: 7890, udp: true, lanAccess: true,
      authMode: 'password', authReference: 'synthetic-credential-reference', tls: true, tlsReference: 'synthetic-certificate-reference', accessScope: 'lan', allowedCidrs: ['10.0.0.0/24'],
      maxConnections: 512, idleTimeoutSec: 300, rateLimitMbps: 200, auditEnabled: true, enabled: false, status: '待部署', routingProfile: 'Synthetic profile', description: 'Only a reference, never a credential.' }],
    events: [{ at: '2026-10-24T01:02:03.123456789Z', type: 'Synthetic event', reason: 'Synthetic supplied reason', result: '未评估' }],
    draft: { name: 'Synthetic draft', baseVersion: '',
      businesses: [{ id: 'chatgpt', name: 'Synthetic policy', domains: ['chatgpt.com'], strategy: 'chatgpt_pool', candidates: ['chatgpt_pool', 'DIRECT'], fallback: 'previous_stable',
        skipEmptyPools: true, failuresToSwitch: 3, probeIntervalSec: 30, sessionStickyMin: 30, switchCooldownSec: 300, requireCapabilities: ['chatgpt'] }],
      pools: [{ id: 'chatgpt_pool', name: 'Synthetic pool', members: ['synthetic-node'], capabilities: ['chatgpt'] }, { id: '台湾', name: '台湾', members: null }],
      dns: { domesticResolvers: ['223.5.5.5'], overseasResolvers: ['https://1.1.1.1/dns-query', 'tls://9.9.9.9'], hijackPort53: true, leakProtection: true } },
  }
}
function response(value: unknown) { return { ok: true, status: 200, json: async () => value } as Response }
function rejected(value: unknown) {
  let message: string | undefined
  try { decodeSnapshotReport(value) } catch (error) { message = error instanceof Error ? error.message : 'non-error rejection' }
  expect(message).toBe(SNAPSHOT_FORMAT_ERROR)
}
const nested: Array<{ pick: (v: Raw) => Raw; required: string[] }> = [
  { pick: v => v.businesses[0], required: ['id', 'name', 'strategy', 'activeRoute', 'status'] },
  { pick: v => v.pools[0], required: ['name', 'region', 'latencyMs', 'lossRate', 'available', 'total', 'status'] },
  { pick: v => v.interfaces[0], required: ['id', 'name', 'type', 'core', 'listen', 'port', 'udp', 'lanAccess', 'authMode', 'tls', 'accessScope', 'maxConnections', 'idleTimeoutSec', 'rateLimitMbps', 'auditEnabled', 'enabled', 'status', 'routingProfile'] },
  { pick: v => v.events[0], required: ['at', 'type', 'reason', 'result'] },
  { pick: v => v.draft, required: ['name', 'baseVersion', 'businesses', 'pools', 'dns'] },
  { pick: v => v.draft.businesses[0], required: ['id', 'name', 'domains', 'strategy', 'candidates', 'fallback', 'skipEmptyPools', 'failuresToSwitch', 'probeIntervalSec', 'sessionStickyMin', 'switchCooldownSec'] },
  { pick: v => v.draft.pools[0], required: ['id', 'name', 'members'] },
  { pick: v => v.draft.dns, required: ['domesticResolvers', 'overseasResolvers', 'hijackPort53', 'leakProtection'] },
]
const metricIntegerFields: Array<[(v: Raw) => Raw, string]> = [
  [v => v.pools[0], 'latencyMs'], [v => v.pools[0], 'available'], [v => v.pools[0], 'total'],
  ...['port', 'maxConnections', 'idleTimeoutSec', 'rateLimitMbps'].map(key => [(v: Raw) => v.interfaces[0], key] as [(v: Raw) => Raw, string]),
]
const integerFields: Array<[(v: Raw) => Raw, string]> = [
  ...metricIntegerFields,
  ...['failuresToSwitch', 'probeIntervalSec', 'sessionStickyMin', 'switchCooldownSec'].map(key => [(v: Raw) => v.draft.businesses[0], key] as [(v: Raw) => Raw, string]),
]

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('SnapshotTruth', () => {
  it('decodes the complete Go-shaped demo contract including nil members and required capabilities', () => {
    const value = decodeSnapshotReport(wireSnapshot())
    expect(value.dataSource).toBe('demo')
    expect(value.draft.pools[1].members).toEqual([])
    expect(value.draft.businesses[0].requireCapabilities).toEqual(['chatgpt'])
    expect(value.interfaces[0].enabled).toBe(false)
    expect(value.events[0].at).toBe('2026-10-24T01:02:03.123456789Z')
  })
  it('preserves an explicit live source and supplied status without inferring health', () => {
    const input = wireSnapshot(); input.dataSource = 'live'; input.status = 'upstream supplied unknown'
    const value = decodeSnapshotReport(input)
    expect(value.dataSource).toBe('live'); expect(value.status).toBe(input.status)
    expect(value.businesses[0].status).toBe('未评估'); expect(value.publishLocked).toBe(true)
  })
  it('normalizes explicitly present required Go nil slices to owned empty arrays', () => {
    const input = wireSnapshot()
    for (const key of ['businesses', 'pools', 'interfaces', 'events']) input[key] = null
    input.draft.businesses = null; input.draft.pools = null
    input.draft.dns.domesticResolvers = null; input.draft.dns.overseasResolvers = null
    const value = decodeSnapshotReport(input)
    expect([value.businesses, value.pools, value.interfaces, value.events, value.draft.businesses, value.draft.pools, value.draft.dns.domesticResolvers, value.draft.dns.overseasResolvers]).toEqual(Array.from({ length: 8 }, () => []))
    expect(input.events).toBeNull(); expect(value.dataSource).toBe('demo')
  })
  it('rejects every missing top-level field instead of inventing defaults', () => {
    for (const key of Object.keys(wireSnapshot())) { const input = wireSnapshot(); delete input[key]; rejected(input) }
  })
  it('rejects wrong top-level scalar and source types without coercing booleans', () => {
    for (const [key, value] of [['product', null], ['version', 1], ['mode', false], ['status', {}], ['dataSource', 'future'], ['dataSource', null], ['publishLocked', 'false'], ['publishLocked', 0]]) {
      rejected({ ...wireSnapshot(), [key as string]: value })
    }
  })
  it('rejects non-boolean values for every nested boolean rather than coercing flags', () => {
    const fields: Array<[(v: Raw) => Raw, string]> = [
      ...['udp', 'lanAccess', 'tls', 'auditEnabled', 'enabled'].map(key => [(v: Raw) => v.interfaces[0], key] as [(v: Raw) => Raw, string]),
      [(v: Raw) => v.draft.businesses[0], 'skipEmptyPools'], [(v: Raw) => v.draft.dns, 'hijackPort53'], [(v: Raw) => v.draft.dns, 'leakProtection'],
    ]
    for (const [pick, key] of fields) for (const value of ['false', 0, null, {}, []]) { const input = wireSnapshot(); pick(input)[key] = value; rejected(input) }
  })
  it('rejects non-object snapshot roots and unknown top-level fields', () => {
    for (const value of [null, [], 'snapshot', 1, true, {}, { ...wireSnapshot(), unreviewed: true }]) rejected(value)
  })
  it('requires every nested Go JSON field including all four DNS fields', () => {
    for (const spec of nested) for (const key of spec.required) { const input = wireSnapshot(); delete spec.pick(input)[key]; rejected(input) }
  })
  it('rejects non-object entries and nested objects even when their collection exists', () => {
    for (const key of ['businesses', 'pools', 'interfaces', 'events']) for (const value of [null, [], 1, 'row']) { const input = wireSnapshot(); input[key][0] = value; rejected(input) }
    for (const key of ['draft', 'dns']) for (const value of [null, [], false]) { const input = wireSnapshot(); if (key === 'draft') input.draft = value; else input.draft.dns = value; rejected(input) }
  })
  it('rejects malformed collection types while retaining explicit null slice compatibility', () => {
    for (const value of [{}, '', 1, true]) {
      for (const key of ['businesses', 'pools', 'interfaces', 'events']) rejected({ ...wireSnapshot(), [key]: value })
      for (const key of ['domains', 'candidates']) { const input = wireSnapshot(); input.draft.businesses[0][key] = value; rejected(input) }
      const input = wireSnapshot(); input.draft.pools[0].members = value; rejected(input)
    }
  })
  it('keeps omitted optional Go fields absent rather than adding fabricated values', () => {
    const input = wireSnapshot()
    for (const key of ['authReference', 'tlsReference', 'allowedCidrs', 'description']) delete input.interfaces[0][key]
    delete input.draft.businesses[0].requireCapabilities; delete input.draft.pools[0].capabilities
    const value = decodeSnapshotReport(input)
    for (const key of ['authReference', 'tlsReference', 'allowedCidrs', 'description']) expect(Object.hasOwn(value.interfaces[0], key)).toBe(false)
    expect(Object.hasOwn(value.draft.businesses[0], 'requireCapabilities')).toBe(false)
    expect(Object.hasOwn(value.draft.pools[0], 'capabilities')).toBe(false)
  })
  it('accepts optional empty arrays but rejects optional null omitted by Go encoding', () => {
    const input = wireSnapshot(); input.interfaces[0].allowedCidrs = []; input.draft.businesses[0].requireCapabilities = []; input.draft.pools[0].capabilities = []
    const value = decodeSnapshotReport(input)
    expect(value.interfaces[0].allowedCidrs).toEqual([]); expect(value.draft.businesses[0].requireCapabilities).toEqual([]); expect(value.draft.pools[0].capabilities).toEqual([])
    expect(Object.hasOwn(value.draft.pools[1], 'capabilities')).toBe(false)
    for (const [pick, key] of [[(v: Raw) => v.interfaces[0], 'allowedCidrs'], [(v: Raw) => v.draft.businesses[0], 'requireCapabilities'], [(v: Raw) => v.draft.pools[0], 'capabilities']] as Array<[(v: Raw) => Raw, string]>) { const changed = wireSnapshot(); pick(changed)[key] = null; rejected(changed) }
  })
  it('rejects malformed optional strings and optional array elements', () => {
    for (const key of ['authReference', 'tlsReference', 'description']) { const input = wireSnapshot(); input.interfaces[0][key] = null; rejected(input) }
    for (const pick of [(v: Raw) => v.interfaces[0].allowedCidrs, (v: Raw) => v.draft.businesses[0].requireCapabilities, (v: Raw) => v.draft.pools[0].capabilities]) {
      for (const value of [null, 1, {}, false]) { const input = wireSnapshot(); pick(input)[0] = value; rejected(input) }
    }
  })
  it('retains supplied credential and certificate references without resolving them', () => {
    const value = decodeSnapshotReport(wireSnapshot()).interfaces[0]
    expect(value.authReference).toBe('synthetic-credential-reference'); expect(value.tlsReference).toBe('synthetic-certificate-reference')
    expect(value.allowedCidrs).toEqual(['10.0.0.0/24']); expect(value.description).toBe('Only a reference, never a credential.')
  })
  it('rejects duplicate status identities and duplicate pool display keys', () => {
    for (const key of ['businesses', 'pools', 'interfaces']) { const input = wireSnapshot(); input[key].push({ ...input[key][0] }); rejected(input) }
  })
  it('accepts equal pool names in different regions but rejects repeated name-region pairs', () => {
    const input = wireSnapshot(); input.pools.push({ ...input.pools[0], region: '另一区域' })
    const value = decodeSnapshotReport(input)
    expect(value.pools).toHaveLength(2); expect(value.pools[0].name).toBe(value.pools[1].name); expect(value.pools[0].region).not.toBe(value.pools[1].region)
    input.pools.push({ ...input.pools[1] }); rejected(input)
  })
  it('rejects duplicate draft business and node-pool identifiers independently', () => {
    for (const key of ['businesses', 'pools']) { const input = wireSnapshot(); input.draft[key].push({ ...input.draft[key][0] }); rejected(input) }
  })
  it('preserves Unicode policy IDs and open Go strategy mode and core strings', () => {
    const input = wireSnapshot(); input.draft.pools[1].id = '区域.节点池 -1'; input.mode = 'isolated-custom'; input.interfaces[0].core = 'Unverified custom core'
    input.draft.businesses[0].strategy = 'unvalidated-pool-reference'; input.draft.businesses[0].fallback = 'unvalidated-fallback'
    const value = decodeSnapshotReport(input)
    expect(value.draft.pools[1].id).toBe('区域.节点池 -1'); expect(value.mode).toBe(input.mode); expect(value.interfaces[0].core).toBe(input.interfaces[0].core)
    expect(value.draft.businesses[0].strategy).toBe(input.draft.businesses[0].strategy)
  })
  it('rejects malformed policy and proxy identifiers without treating text as paths', () => {
    for (const id of ['', '../outside', 'id/child', 'x'.repeat(65)]) { const input = wireSnapshot(); input.draft.pools[0].id = id; rejected(input) }
    for (const id of ['a', 'Upper', 'id.with.dot', 'x'.repeat(49)]) { const input = wireSnapshot(); input.interfaces[0].id = id; rejected(input) }
  })
  it('rejects non-finite fractional and unsafe values for every Go integer field', () => {
    for (const [pick, key] of integerFields) for (const value of [NaN, Infinity, -Infinity, 0.25, Number.MAX_SAFE_INTEGER + 1]) { const input = wireSnapshot(); pick(input)[key] = value; rejected(input) }
  })
  it('rejects negative counts invalid loss percentages and impossible availability', () => {
    for (const [pick, key] of metricIntegerFields) { const input = wireSnapshot(); pick(input)[key] = -1; rejected(input) }
    for (const lossRate of [-1, 100.1, NaN, Infinity]) { const input = wireSnapshot(); input.pools[0].lossRate = lossRate; rejected(input) }
    const input = wireSnapshot(); input.pools[0].available = input.pools[0].total + 1; rejected(input)
  })
  it('enforces proxy numeric bounds from the existing validator', () => {
    for (const [key, value] of [['port', 65536], ['maxConnections', 1000001], ['idleTimeoutSec', 86401], ['rateLimitMbps', 100001]]) { const input = wireSnapshot(); input.interfaces[0][key as string] = value; rejected(input) }
  })
  it('accepts numeric zero defaults without claiming policy approval or runtime health', () => {
    const input = wireSnapshot(); for (const [pick, key] of integerFields) pick(input)[key] = 0
    input.pools[0].lossRate = 0; input.publishLocked = false; input.draft.businesses[0].skipEmptyPools = false
    for (const key of ['udp', 'lanAccess', 'tls', 'auditEnabled', 'enabled']) input.interfaces[0][key] = false
    input.draft.dns.hijackPort53 = false; input.draft.dns.leakProtection = false
    const value = decodeSnapshotReport(input)
    expect(value.interfaces[0].port).toBe(0); expect(value.draft.businesses[0].failuresToSwitch).toBe(0); expect(value.businesses[0].status).toBe('未评估'); expect(value.publishLocked).toBe(false)
    expect(value.interfaces[0].udp).toBe(false); expect(value.draft.dns.hijackPort53).toBe(false); expect(value.draft.dns.leakProtection).toBe(false)
  })
  it('retains signed draft thresholds for later policy validation rather than hiding the snapshot', () => {
    const input = wireSnapshot()
    for (const key of ['failuresToSwitch', 'probeIntervalSec', 'sessionStickyMin', 'switchCooldownSec']) input.draft.businesses[0][key] = -7
    const value = decodeSnapshotReport(input)
    expect(value.draft.businesses[0].failuresToSwitch).toBe(-7); expect(value.draft.businesses[0].probeIntervalSec).toBe(-7)
    expect(value.draft.businesses[0].sessionStickyMin).toBe(-7); expect(value.draft.businesses[0].switchCooldownSec).toBe(-7)
  })
  it('closes proxy type authentication and access-scope enums to implemented choices', () => {
    for (const [key, value] of [['type', 'future-protocol'], ['authMode', 'plaintext-secret'], ['accessScope', 'internet']]) { const input = wireSnapshot(); input.interfaces[0][key] = value; rejected(input) }
    for (const type of ['http', 'socks5', 'mixed', 'tun', 'tproxy', 'redirect', 'api']) { const input = wireSnapshot(); input.interfaces[0].type = type; if (type === 'tun') input.interfaces[0].port = 0; expect(decodeSnapshotReport(input).interfaces[0].type).toBe(type) }
    for (const authMode of ['none', 'password', 'token', 'mtls']) { const input = wireSnapshot(); input.interfaces[0].authMode = authMode; expect(decodeSnapshotReport(input).interfaces[0].authMode).toBe(authMode) }
    for (const accessScope of ['local', 'lan', 'vpn', 'custom']) { const input = wireSnapshot(); input.interfaces[0].accessScope = accessScope; expect(decodeSnapshotReport(input).interfaces[0].accessScope).toBe(accessScope) }
  })
  it('canonicalizes known proxy type aliases using the existing Go trim and lowercase rule', () => {
    const input = wireSnapshot(); input.interfaces[0].type = ' HTTP '
    expect(decodeSnapshotReport(input).interfaces[0].type).toBe('http'); expect(input.interfaces[0].type).toBe(' HTTP ')
    input.interfaces[0].type = '\ufeffHTTP\ufeff'; rejected(input); input.interfaces[0].type = 'http'
    input.interfaces[0].authMode = ' PASSWORD '; rejected(input)
    input.interfaces[0].authMode = 'password'; input.interfaces[0].accessScope = ' LAN '; rejected(input)
  })
  it('preserves valid RFC3339Nano precision offsets and leap dates', () => {
    for (const at of ['2026-10-24T01:02:03Z', '2026-10-24T01:02:03.1+08:00', '2024-02-29T23:59:59.123456789-03:30', '2026-10-24T01:02:03.123456789+23:59', '0000-02-29T00:00:00Z', '0001-01-01T00:00:00Z']) { const input = wireSnapshot(); input.events[0].at = at; expect(decodeSnapshotReport(input).events[0].at).toBe(at) }
  })
  it('rejects invalid calendars times offsets and excess fractional precision', () => {
    for (const at of ['2026-02-29T00:00:00Z', '2026-02-31T00:00:00Z', '2026-13-01T00:00:00Z', '2026-01-00T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T00:60:00Z', '2026-01-01T00:00:60Z', '2026-01-01T00:00:00+24:00', '2026-01-01T00:00:00+00:60', '2026-01-01T00:00:00.1234567890Z', 'not-a-time']) { const input = wireSnapshot(); input.events[0].at = at; rejected(input) }
  })
  it('retains supplied duplicate events and leaves empty events empty', () => {
    const input = wireSnapshot(); input.events.push({ ...input.events[0] }); expect(decodeSnapshotReport(input).events).toHaveLength(2)
    input.events = []; expect(decodeSnapshotReport(input).events).toEqual([])
  })
  it('bounds text widths and rejects control and bidirectional override characters', () => {
    for (const value of ['private\nline', 'private\u0000text', 'private\u202etext', 'x'.repeat(257), 1, null]) rejected({ ...wireSnapshot(), product: value })
    const input = wireSnapshot(); input.interfaces[0].description = 'x'.repeat(2049); rejected(input)
  })
  it('bounds collections total elements and aggregate cloned text before allocation grows', () => {
    const rows = wireSnapshot(); rows.events = Array.from({ length: SNAPSHOT_LIMITS.events + 1 }, () => ({ ...rows.events[0] })); rejected(rows)
    const elements = wireSnapshot(); elements.draft.pools = Array.from({ length: 5 }, (_, i) => ({ id: 'pool_' + i, name: 'Pool', members: Array(SNAPSHOT_LIMITS.members).fill('n') })); rejected(elements)
    const characters = wireSnapshot(); characters.draft.pools[0].members = Array(SNAPSHOT_LIMITS.members).fill('x'.repeat(256)); rejected(characters)
  })
  it('rejects sparse arrays and non-string nested list elements', () => {
    const sparse = wireSnapshot(); sparse.events = Array(1); rejected(sparse)
    for (const key of ['domesticResolvers', 'overseasResolvers']) { const input = wireSnapshot(); input.draft.dns[key] = [false]; rejected(input) }
    const input = wireSnapshot(); input.draft.businesses[0].domains = [{}]; rejected(input)
  })
  it('returns owned nested objects and arrays instead of input aliases', () => {
    const input = wireSnapshot(), value = decodeSnapshotReport(input)
    input.businesses[0].name = 'changed'; input.events[0].reason = 'changed'; input.interfaces[0].allowedCidrs[0] = 'changed'
    input.draft.businesses[0].domains[0] = 'changed'; input.draft.businesses[0].requireCapabilities[0] = 'changed'; input.draft.pools[0].members[0] = 'changed'; input.draft.pools[0].capabilities[0] = 'changed'; input.draft.dns.domesticResolvers[0] = 'changed'
    expect(value.businesses[0].name).toBe('Synthetic business'); expect(value.events[0].reason).toBe('Synthetic supplied reason'); expect(value.interfaces[0].allowedCidrs).toEqual(['10.0.0.0/24'])
    expect(value.draft.businesses[0].domains).toEqual(['chatgpt.com']); expect(value.draft.businesses[0].requireCapabilities).toEqual(['chatgpt']); expect(value.draft.pools[0].members).toEqual(['synthetic-node']); expect(value.draft.pools[0].capabilities).toEqual(['chatgpt']); expect(value.draft.dns.domesticResolvers).toEqual(['223.5.5.5'])
  })
  it('does not share normalized nil arrays or future outputs with a mutated result', () => {
    const input = wireSnapshot(); input.events = null
    const first = decodeSnapshotReport(input), second = decodeSnapshotReport(input)
    first.events.push({ at: '2026-01-01T00:00:00Z', type: 'changed', reason: '', result: '' }); first.draft.pools[1].members.push('changed')
    expect(second.events).toEqual([]); expect(second.draft.pools[1].members).toEqual([]); expect(input.events).toBeNull(); expect(input.draft.pools[1].members).toBeNull()
  })
  it('rejects unknown secret fields and suppresses nested accessor exceptions', () => {
    const secret = 'synthetic-private-credential-canary'
    for (const spec of nested) { const input = wireSnapshot(); spec.pick(input).password = secret; rejected(input) }
    const input = wireSnapshot(); Object.defineProperty(input, 'product', { enumerable: true, get() { throw new Error(secret) } }); rejected(input)
  })
  it('connects getSnapshot to the decoder while preserving the exact request signal and options', async () => {
    const input = wireSnapshot(), controller = new AbortController(), fetchMock = vi.fn<typeof fetch>().mockResolvedValue(response(input))
    vi.stubGlobal('fetch', fetchMock)
    const value = await getSnapshot(controller.signal)
    expect(value.draft.pools[1].members).toEqual([])
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/snapshot', { signal: controller.signal, headers: { Accept: 'application/json' } })
  })
  it('suppresses JSON parser fragments in snapshot response errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => { throw new SyntaxError('synthetic-private-body-fragment') } } as unknown as Response))
    await expect(getSnapshot()).rejects.toThrow(SNAPSHOT_FORMAT_ERROR)
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ ...wireSnapshot(), businesses: {} })))
    await expect(getSnapshot()).rejects.toThrow(SNAPSHOT_FORMAT_ERROR)
  })
  it('preserves caller abort as a fixed AbortError for rejected or late valid bodies', async () => {
    for (const fail of [false, true]) {
      const controller = new AbortController()
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => { controller.abort(); if (fail) throw new Error('synthetic-private-abort-fragment'); return wireSnapshot() } } as unknown as Response))
      await expect(getSnapshot(controller.signal)).rejects.toMatchObject({ name: 'AbortError', message: '快照读取已取消' })
    }
  })
  it('keeps cancellation authoritative before response status and during fetch rejection', async () => {
    for (const status of [200, 503]) {
      const controller = new AbortController(), json = vi.fn()
      vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => { controller.abort(); return { ok: status === 200, status, json } as unknown as Response }))
      await expect(getSnapshot(controller.signal)).rejects.toMatchObject({ name: 'AbortError', message: '快照读取已取消' }); expect(json).not.toHaveBeenCalled()
    }
    const controller = new AbortController(); controller.abort()
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('synthetic-private-fetch-abort-fragment')))
    await expect(getSnapshot(controller.signal)).rejects.toMatchObject({ name: 'AbortError', message: '快照读取已取消' })
  })
  it('replaces ordinary fetch rejections with a fixed transport error and no raw cause', async () => {
    const secret = 'synthetic-private-network-fragment'
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error(secret)))
    const error: unknown = await getSnapshot().catch((reason: unknown) => reason)
    expect(error).toBeInstanceOf(APIError)
    if (!(error instanceof APIError)) throw new Error('expected a safe transport error')
    expect(error).toMatchObject({ name: 'APIError', status: 0, code: 'transport', message: '无法连接本地控制面，当前状态未核验' })
    expect(Object.hasOwn(error, 'cause')).toBe(false); expect(error.stack ?? '').not.toContain(secret)
  })
  it('never exposes caller-supplied abort reasons during fetch or response-body failures', async () => {
    const secret = 'synthetic-private-caller-abort-reason'
    for (const stage of ['fetch', 'body']) {
      const controller = new AbortController(), reason = new Error(secret)
      if (stage === 'fetch') {
        controller.abort(reason); vi.stubGlobal('fetch', vi.fn().mockRejectedValue(controller.signal.reason))
      } else {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => { controller.abort(reason); throw controller.signal.reason } } as unknown as Response))
      }
      const error: unknown = await getSnapshot(controller.signal).catch((value: unknown) => value)
      expect(error).toBeInstanceOf(DOMException)
      if (!(error instanceof DOMException)) throw new Error('expected a safe caller abort')
      expect(error.name).toBe('AbortError'); expect(error.message).toBe('快照读取已取消'); expect(Object.hasOwn(error, 'cause')).toBe(false); expect(error.stack ?? '').not.toContain(secret)
    }
  })
  it('keeps the existing HTTP status failure separate without reading its body', async () => {
    const json = vi.fn(); vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 503, json } as unknown as Response))
    await expect(getSnapshot()).rejects.toThrow('读取系统状态失败 (503)'); expect(json).not.toHaveBeenCalled()
  })
  it('keeps malformed live snapshot arrays out of the rendered success branch', async () => {
    const input = wireSnapshot(); input.dataSource = 'live'; input.businesses = {}
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(input))); render(<App />)
    expect(await screen.findByText('演示模式：控制面快照格式不受支持，尚未核验')).toBeInTheDocument()
    expect(screen.getByText('当前总览没有接入真实运行数据')).toBeInTheDocument(); expect(screen.queryByText('Synthetic source metadata')).not.toBeInTheDocument()
  })
  it('renders legal live nil inventories as empty without inventing events or DNS health', async () => {
    const input = wireSnapshot(); input.dataSource = 'live'; input.businesses = null; input.pools = null; input.interfaces = null; input.events = null
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(input))); render(<App />)
    expect(await screen.findByText('Synthetic source metadata')).toBeInTheDocument()
    expect(screen.getByText('暂无已读取事件')).toBeInTheDocument(); expect(screen.getByRole('heading', { name: 'DNS 健康未核验' })).toBeInTheDocument()
    expect(screen.queryByText('本地演示数据已加载')).not.toBeInTheDocument()
  })
})
