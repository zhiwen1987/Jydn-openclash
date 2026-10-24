// Synthetic CPU contracts; never launches a product or browser.
import test from 'node:test'
import assert from 'node:assert/strict'
import { strictJSON, projectRequest as projectWireRequest, expectedStatus, utcTimestamp, validateUnknownOverview, validateUnavailableOverview, ORIGIN } from './wire-contract.mjs'

const json = value => Buffer.from(JSON.stringify(value))
const request = (path = '/api/v1/overview', extra = {}) => ({ url: ORIGIN + path, method: 'GET', headers: { Accept: 'application/json' }, ...extra })
const projectRequest = (value, assets, profile = 'evidence_enabled_unknown') => projectWireRequest(value, assets, profile)
const unknown = () => ({ state: 'unknown', reason: 'not_configured', observedAt: null, expiresAt: null })
const fixture = () => ({ schema: 'chengwang.overview-snapshot/v1', dataSource: 'live', generatedAt: '2026-10-24T01:02:03.123456789Z', mode: 'candidate', readOnly: true, advisoryOnly: true,
  coverage: { state: 'none', missing: ['controller_observation', 'probe_readback', 'businesses', 'node_pools', 'end_to_end_dns', 'device_inventory', 'traffic_topology'] },
  observation: { configured: false, running: false, fresh: false, stale: false, lastAttemptAt: null, lastSuccessAt: null, consecutiveFailures: 0, controller: unknown(), storage: unknown(), clock: unknown() },
  probe: { configured: false, running: false, state: 'disabled', reason: 'disabled', clockHealthy: false, storageHealthy: false, cachedAt: null, expiresAt: null, coverageState: 'unavailable', coverage: null },
  subscription: { configured: false, inventoryState: 'protected_not_read', sourceCount: null, nodeCount: null }, unsupported: { businesses: true, nodePools: true, endToEndDNS: true, deviceInventory: true, trafficTopology: true } })

test('strict JSON preserves Unicode and nested primitive values', () => {
  const value = { message: '中文😀', values: [true, false, null, -1.25, { key: 'value' }] }
  assert.deepEqual(strictJSON(json(value)), value)
})
test('duplicate keys are rejected at each object depth', () => {
  for (const raw of ['{"x":1,"x":2}', '{"nested":{"x":0,"x":1}}', '{"x":1,"\\u0078":2}']) assert.throws(() => strictJSON(Buffer.from(raw)))
})
test('prototype-looking keys remain own data without prototype mutation', () => {
  const value = strictJSON(Buffer.from('{"__proto__":{"polluted":true}}'))
  assert.equal(Object.getPrototypeOf(value), Object.prototype); assert.equal(Object.hasOwn(value, '__proto__'), true); assert.equal({}.polluted, undefined)
})
test('invalid UTF8 and unpaired surrogate strings are rejected', () => {
  for (const raw of [Buffer.from([0xff]), Buffer.from('"\\ud800"'), Buffer.from('"\\udc00"'), Buffer.from('{"\\ud800":0}')]) assert.throws(() => strictJSON(raw))
})
test('JSON parser rejects junk constants malformed grammar and overflow numbers', () => {
  for (const raw of ['', '{}x', 'NaN', 'Infinity', '1e999', '[1,]', '{"x":}', '01', '"unterminated', '{"x":1,}']) assert.throws(() => strictJSON(Buffer.from(raw)))
})
test('JSON parser enforces byte depth array and object budgets', () => {
  assert.equal(strictJSON(Buffer.from('123'), 3), 123)
  assert.throws(() => strictJSON(Buffer.from('123'), 2)); assert.throws(() => strictJSON(Buffer.from('{}'), 0))
  assert.throws(() => strictJSON(Buffer.from('['.repeat(66) + '0' + ']'.repeat(66))))
  assert.throws(() => strictJSON(json(Array(32769).fill(0)), 1 << 20))
  assert.throws(() => strictJSON(json(Object.fromEntries(Array.from({ length: 8193 }, (_, i) => ['k' + i, 0]))), 1 << 20))
})
test('anonymous request classification contains only closed wire projections', () => {
  const pairs = [['/', 'DOCUMENT'], ['/assets/app.js', 'ASSET'], ['/api/v1/snapshot', 'SNAPSHOT'], ['/api/v1/overview', 'OVERVIEW'], ['/api/v1/observations/status', 'OBSERVATION_STATUS'], ['/api/v1/probes/status', 'PROBE_STATUS']]
  for (const [path, kind] of pairs) assert.deepEqual(projectRequest(request(path), ['/assets/app.js']), { kind, method: 'GET', path, sameOrigin: true, queryPresent: false, fragmentPresent: false, userInfoPresent: false, authorizationPresent: false, cookiePresent: false, bodyPresent: false })
})
test('request origins canonical URLs queries fragments and private APIs fail closed', () => {
  for (const url of ['http://127.0.0.1:17891/', 'https://example.com/', ORIGIN + '/api/v1/overview?x=1', ORIGIN + '/api/v1/overview#x', 'https://u:p@127.0.0.1:17891/', ORIGIN + '/api/v1/subscriptions/sources', ORIGIN + '/a/../api/v1/overview']) assert.throws(() => projectRequest(request('/', { url }), []))
})
test('request methods bodies and idempotency state cannot be admitted', () => {
  for (const extra of [{ method: 'POST' }, { method: 'HEAD' }, { hasPostData: true }, { hasPostData: 1 }, { postData: '' }, { postDataEntries: [] }, { headers: { 'Idempotency-Key': 'unit' } }]) assert.throws(() => projectRequest(request('/api/v1/overview', extra), []))
})
test('bare query and fragment delimiters are not misreported as absent', () => {
  for (const suffix of ['?', '#', '?#', '#?']) assert.throws(() => projectRequest(request('/api/v1/overview' + suffix), []))
})
test('authorization cookies duplicate casing and malformed headers are rejected', () => {
  for (const headers of [{ Authorization: 'Bearer unit' }, { 'Proxy-Authorization': 'unit' }, { Cookie: 'unit' }, { 'Proxy-Connection': 'keep-alive' }, { Accept: 'a', accept: 'b' }, { Accept: 'a\r\nb' }, { 'bad name': 'a' }, { Accept: false }, []]) assert.throws(() => projectRequest(request('/api/v1/overview', { headers }), []))
})
test('asset allowlist must be bounded unique manifest-style paths', () => {
  for (const allowed of [['/assets/app.js', '/assets/app.js'], ['/api/v1/subscriptions/sources'], ['/assets/../secret.js'], Array.from({ length: 65 }, (_, i) => '/assets/a' + i + '.js')]) assert.throws(() => projectRequest(request('/assets/app.js'), allowed))
  assert.throws(() => projectRequest(request('/assets/unknown.js'), ['/assets/app.js']))
})
test('only disabled overview expects 503 and all other kinds require 200', () => {
  assert.equal(expectedStatus('OVERVIEW', 'evidence_disabled'), 503)
  assert.equal(expectedStatus('OVERVIEW', 'evidence_enabled_unknown'), 200)
  for (const kind of ['DOCUMENT', 'ASSET', 'SNAPSHOT', 'OBSERVATION_STATUS', 'PROBE_STATUS']) assert.equal(expectedStatus(kind, 'evidence_disabled'), 200)
  assert.throws(() => expectedStatus('OTHER', 'evidence_disabled')); assert.throws(() => expectedStatus('OVERVIEW', 'default'))
  for (const path of ['/api/v1/observations/status', '/api/v1/probes/status']) assert.throws(() => projectRequest(request(path), [], 'evidence_disabled'))
  assert.throws(() => projectWireRequest(request(), [])); assert.throws(() => projectWireRequest(request(), [], 'default'))
})
test('UTC assembly times preserve nanoseconds without client freshness inference', () => {
  for (const value of ['2026-10-24T01:02:03.123456789Z', '2024-02-29T00:00:00Z', '9999-12-31T23:59:59.9Z', '0001-01-01T00:00:00.000000001Z']) assert.equal(utcTimestamp(value), value)
})
test('invalid calendar nonUTC and unsupported timestamp precision fail', () => {
  for (const value of ['2026-02-29T00:00:00Z', '2026-13-01T00:00:00Z', '2026-01-01T24:00:00Z', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00.1234567890Z', 'not-a-time', '0001-01-01T00:00:00Z', '0001-01-01T00:00:00.000000000Z']) assert.throws(() => utcTimestamp(value))
})
test('unconfigured enabled overview admits only the exact unknown evidence shape', () => {
  const value = fixture(); assert.equal(validateUnknownOverview(value, 'evidence_enabled_unknown'), value)
  assert.throws(() => validateUnknownOverview(value, 'evidence_disabled'))
})
test('unknown overview cannot acquire availability fresh coverage or invented counts', () => {
  const changes = [v => { v.observation.fresh = true }, v => { v.observation.controller.state = 'available' }, v => { v.probe.coverageState = 'current' }, v => { v.probe.coverage = {} }, v => { v.subscription.sourceCount = 0 }, v => { v.subscription.nodeCount = 0 }, v => { v.coverage.state = 'partial' }]
  for (const change of changes) { const value = fixture(); change(value); assert.throws(() => validateUnknownOverview(value, 'evidence_enabled_unknown')) }
})
test('explicit nulls required keysets and ordered missing coverage are retained', () => {
  const changes = [v => { delete v.observation.controller.observedAt }, v => { v.probe.cachedAt = '2026-10-24T00:00:00Z' }, v => { v.extra = false }, v => { v.unsupported.businesses = false }, v => { v.coverage.missing.reverse() }, v => { v.observation.running = 0 }, v => { v.mode = 'production' }, v => { v.readOnly = false }]
  for (const change of changes) { const value = fixture(); change(value); assert.throws(() => validateUnknownOverview(value, 'evidence_enabled_unknown')) }
})
test('disabled error body is source-specific and never silently replaced by unknown data', () => {
  const value = { code: 'overview_not_configured', message: '实际证据汇总尚未启用' }
  assert.equal(validateUnavailableOverview(value, 'evidence_disabled'), value)
  for (const bad of [{ ...value, code: 'other' }, { ...value, message: 'upstream raw message' }, { ...value, extra: true }, { error: value }, fixture()]) assert.throws(() => validateUnavailableOverview(bad, 'evidence_disabled'))
  assert.throws(() => validateUnavailableOverview(value, 'evidence_enabled_unknown'))
})
