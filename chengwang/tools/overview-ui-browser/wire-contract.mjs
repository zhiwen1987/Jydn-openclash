// Pure producer-side wire checks for the two closed overview UI profiles.
// No browser/process/network operation or application decoder is imported.
import { createHash } from 'node:crypto'

export const ORIGIN = 'https://127.0.0.1:17891'
export const PROFILES = Object.freeze(['evidence_disabled', 'evidence_enabled_unknown'])
export const need = value => { if (!value) throw Error('overview wire rejected') }
export const sha = raw => createHash('sha256').update(raw).digest('hex')
export const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0')

// Validate the JSON grammar before JSON.parse can erase duplicate keys.
// Object keys use defineProperty so __proto__ cannot change a prototype.
export function strictJSON(raw, maximum = 65536) {
  need(Buffer.isBuffer(raw) && Number.isSafeInteger(maximum) && maximum > 0 && maximum <= 32 << 20 && raw.length > 0 && raw.length <= maximum)
  const text = new TextDecoder('utf-8', { fatal: true }).decode(raw)
  let at = 0
  const whitespace = () => { while (at < text.length && /[\x20\t\r\n]/.test(text[at])) at++ }
  const string = () => {
    const start = at++
    while (at < text.length) {
      const c = text[at++]
      if (c === '"') {
        const result = JSON.parse(text.slice(start, at))
        for (let i = 0; i < result.length; i++) {
          const n = result.charCodeAt(i)
          if (n >= 0xd800 && n <= 0xdbff) { need(i + 1 < result.length); const low = result.charCodeAt(++i); need(low >= 0xdc00 && low <= 0xdfff) }
          else need(n < 0xdc00 || n > 0xdfff)
        }
        return result
      }
      if (c === '\\') at++
    }
    need(false)
  }
  const value = depth => {
    need(depth <= 64); whitespace()
    const c = text[at]
    if (c === '{') {
      at++; const result = {}, keys = new Set(); whitespace()
      if (text[at] !== '}') while (true) {
        need(text[at] === '"'); const key = string(); need(!keys.has(key) && keys.size < 8192); keys.add(key)
        whitespace(); need(text[at++] === ':')
        Object.defineProperty(result, key, { value: value(depth + 1), enumerable: true, writable: true, configurable: true })
        whitespace(); if (text[at] !== ',') break; at++; whitespace()
      }
      need(text[at++] === '}'); return result
    }
    if (c === '[') {
      at++; const result = []; whitespace()
      if (text[at] !== ']') while (true) {
        need(result.length < 32768); result.push(value(depth + 1)); whitespace()
        if (text[at] !== ',') break; at++; whitespace()
      }
      need(text[at++] === ']'); return result
    }
    if (c === '"') return string()
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at))
    need(match); at += match[0].length
    const result = JSON.parse(match[0]); need(typeof result !== 'number' || Number.isFinite(result)); return result
  }
  const result = value(0); whitespace(); need(at === text.length); return result
}

const API_PATHS = Object.freeze({
  '/api/v1/snapshot': 'SNAPSHOT', '/api/v1/overview': 'OVERVIEW',
  '/api/v1/observations/status': 'OBSERVATION_STATUS', '/api/v1/probes/status': 'PROBE_STATUS',
})
const assetPath = value => typeof value === 'string' && /^\/assets\/[A-Za-z0-9][A-Za-z0-9_.-]{0,160}\.(?:js|css|woff2?|ttf|svg|png)$/.test(value)
export function validateAnonymousGet(request) {
  need(request && request.method === 'GET')
  need(request.headers === undefined || exact(request.headers, Object.keys(request.headers)))
  const entries = Object.entries(request.headers ?? {}), seen = new Set()
  need(entries.length <= 128)
  for (const [key, value] of entries) {
    need(/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/.test(key) && typeof value === 'string' && value.length <= 8192 && !/[\x00-\x1f\x7f]/.test(value))
    const lower = key.toLowerCase(); need(!seen.has(lower)); seen.add(lower)
  }
  need(!['authorization', 'proxy-authorization', 'cookie', 'proxy-connection', 'idempotency-key'].some(key => seen.has(key)))
  need((request.hasPostData === undefined || request.hasPostData === false) && request.postData === undefined && request.postDataEntries === undefined)
}
export function projectRequest(request, allowedAssets, profile) {
  need(PROFILES.includes(profile))
  need(Array.isArray(allowedAssets) && allowedAssets.length <= 64 && new Set(allowedAssets).size === allowedAssets.length && allowedAssets.every(assetPath))
  validateAnonymousGet(request)
  need(typeof request.url === 'string' && request.url.length <= 4096)
  const url = new URL(request.url)
  need(url.href === request.url && url.origin === ORIGIN && !url.search && !url.hash && !url.username && !url.password)
  // URL.search/hash are empty for a bare '?'/'#' delimiter. The fixed wire
  // routes forbid those delimiters as well, including Go's ForceQuery case.
  need(!request.url.includes('?') && !request.url.includes('#'))
  const kind = url.pathname === '/' ? 'DOCUMENT' : Object.hasOwn(API_PATHS, url.pathname) ? API_PATHS[url.pathname] : allowedAssets.includes(url.pathname) ? 'ASSET' : null
  need(kind)
  need(!['OBSERVATION_STATUS', 'PROBE_STATUS'].includes(kind) || profile === 'evidence_enabled_unknown')
  return { kind, method: 'GET', path: url.pathname, sameOrigin: true, queryPresent: false, fragmentPresent: false, userInfoPresent: false, authorizationPresent: false, cookiePresent: false, bodyPresent: false }
}

export function expectedStatus(kind, profile) {
  need(PROFILES.includes(profile) && ['DOCUMENT', 'ASSET', ...Object.values(API_PATHS)].includes(kind))
  return kind === 'OVERVIEW' && profile === 'evidence_disabled' ? 503 : 200
}

// This checks UTC syntax/calendar only. It never compares a client clock or
// turns the response assembly time into a freshness/health assertion.
export function utcTimestamp(value) {
  need(typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value))
  need(!/^0001-01-01T00:00:00(?:\.0{1,9})?Z$/.test(value))
  const parsed = Date.parse(value); need(Number.isFinite(parsed) && new Date(parsed).toISOString().slice(0, 19) === value.slice(0, 19))
  return value
}

const equal = (value, expected) => {
  need(typeof value === typeof expected && (value === null) === (expected === null))
  if (Array.isArray(expected)) { need(Array.isArray(value) && value.length === expected.length); expected.forEach((v, i) => equal(value[i], v)) }
  else if (expected !== null && typeof expected === 'object') { need(exact(value, Object.keys(expected))); for (const key of Object.keys(expected)) equal(value[key], expected[key]) }
  else need(value === expected)
}

export function validateUnknownOverview(value, profile) {
  need(profile === 'evidence_enabled_unknown')
  need(exact(value, ['schema', 'dataSource', 'generatedAt', 'mode', 'readOnly', 'advisoryOnly', 'coverage', 'observation', 'probe', 'subscription', 'unsupported']))
  utcTimestamp(value.generatedAt)
  const unknown = () => ({ state: 'unknown', reason: 'not_configured', observedAt: null, expiresAt: null })
  equal(value, {
    schema: 'chengwang.overview-snapshot/v1', dataSource: 'live', generatedAt: value.generatedAt, mode: 'candidate', readOnly: true, advisoryOnly: true,
    coverage: { state: 'none', missing: ['controller_observation', 'probe_readback', 'businesses', 'node_pools', 'end_to_end_dns', 'device_inventory', 'traffic_topology'] },
    observation: { configured: false, running: false, fresh: false, stale: false, lastAttemptAt: null, lastSuccessAt: null, consecutiveFailures: 0, controller: unknown(), storage: unknown(), clock: unknown() },
    probe: { configured: false, running: false, state: 'disabled', reason: 'disabled', clockHealthy: false, storageHealthy: false, cachedAt: null, expiresAt: null, coverageState: 'unavailable', coverage: null },
    subscription: { configured: false, inventoryState: 'protected_not_read', sourceCount: null, nodeCount: null },
    unsupported: { businesses: true, nodePools: true, endToEndDNS: true, deviceInventory: true, trafficTopology: true },
  })
  return value
}

export function validateUnavailableOverview(value, profile) {
  need(profile === 'evidence_disabled')
  equal(value, { code: 'overview_not_configured', message: '实际证据汇总尚未启用' })
  return value
}
