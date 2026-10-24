// Pure scene contracts. No browser, filesystem or network operation on import.
import { createHash } from 'node:crypto'
import { parseArguments as neutralArguments, canaryVariants, safePublic, decodeBody, FAVICON } from '../subscription-ui-browser/ui-contract.mjs'
export { canaryVariants, safePublic, decodeBody, FAVICON }
export const sha = value => createHash('sha256').update(value).digest('hex')
export const need = value => { if (!value) throw Error('capability truth rejected') }
export const integer = (v, min = 0, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(v) && v >= min && v <= max
export const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join('\0') === [...keys].sort().join('\0')
export const parseArguments = neutralArguments
export const us = value => { need(typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER / 1000000); return Math.floor(value * 1000000) }

// JSON.parse alone silently accepts duplicate keys. Parse the bounded JSON
// grammar first so a duplicate cannot choose a different manifest/input view.
export function strictJSON(raw, maximum) {
  need(Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= maximum)
  const s = new TextDecoder('utf-8', { fatal: true }).decode(raw); let p = 0, depth = 0
  const ws = () => { while (/[\x20\t\r\n]/.test(s[p] ?? '') && p < s.length) p++ }
  const string = () => { const start = p++; while (p < s.length) { const c = s[p++]; if (c === '"') return JSON.parse(s.slice(start, p)); if (c === '\\') p++ }; need(false) }
  function value() {
    ws(); need(++depth <= 64); let v; const c = s[p]
    if (c === '{') { p++; v = {}; const seen = new Set(); ws(); if (s[p] !== '}') while (true) { need(s[p] === '"'); const key = string(); need(!seen.has(key)); seen.add(key); ws(); need(s[p++] === ':'); Object.defineProperty(v, key, { value: value(), enumerable: true, configurable: true, writable: true }); ws(); if (s[p] !== ',') break; p++; ws() }; need(s[p++] === '}') }
    else if (c === '[') { p++; v = []; ws(); if (s[p] !== ']') while (true) { need(v.length < 32768); v.push(value()); ws(); if (s[p] !== ',') break; p++ }; need(s[p++] === ']') }
    else if (c === '"') v = string()
    else { const m = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(s.slice(p)); need(m); p += m[0].length; v = JSON.parse(m[0]); need(typeof v !== 'number' || Number.isFinite(v)) }
    depth--; return v
  }
  const result = value(); ws(); need(p === s.length); return result
}
export function loadContract(raw) {
  const c = strictJSON(raw, 262144)
  need(c.schema === 'chengwang.capability-truth-browser-contract/v1' && c.scenario === 'capability_truth')
  need(c.exactKeySchemas && c.nestedExactKeys && c.captureRules?.bounds && c.stepFences?.length === 7 && c.controlSlots?.length === 11)
  need(c.engines?.join(',') === 'chrome-cdp,playwright' && c.profiles?.includes('default') && c.profiles?.includes('backend_configured'))
  return c
}
export function validateInput(v, o, c) {
  need(exact(v, c.privateBrowserInputExactKeys) && v.schema === c.schemaNames.input && v.scenario === c.scenario && c.profiles.includes(v.profile))
  need(v.fixtureId === o.fixtureId && v.sourceCommit === o.sourceCommit && v.engine === o.engine && typeof v.fenceCanary === 'string' && /^[a-f0-9]{64}$/.test(v.fenceCanary))
  return v
}
export function profileScope(profile) {
  need(['default', 'backend_configured'].includes(profile))
  return { tenantId: profile === 'default' ? '' : 'capability-truth-lab', siteId: profile === 'default' ? '' : 'isolated', environment: 'candidate', objectType: 'control-plane', objectId: 'local' }
}
export function manifestGraph(manifest, c) {
  need(manifest && typeof manifest === 'object' && !Array.isArray(manifest) && Object.keys(manifest).length <= 256 && manifest['index.html']?.isEntry === true)
  const pathOK = p => typeof p === 'string' && /^assets\/[A-Za-z0-9][A-Za-z0-9_.-]{0,160}\.(?:js|css|woff2?|ttf|svg|png)$/.test(p)
  const allowed = new Set(), required = new Set(), visited = new Set(), staticVisited = new Set()
  const add = (p, set) => { need(pathOK(p)); set.add('/' + p) }
  for (const entry of Object.values(manifest)) {
    need(entry && typeof entry === 'object' && !Array.isArray(entry) && Object.keys(entry).every(k => c.manifestAlgorithm.keys.includes(k)) && pathOK(entry.file))
    for (const f of ['src', 'name']) need(entry[f] === undefined || typeof entry[f] === 'string' && entry[f].length <= 1024)
    for (const f of ['isEntry', 'isDynamicEntry']) need(entry[f] === undefined || typeof entry[f] === 'boolean')
    for (const f of ['css', 'assets', 'imports', 'dynamicImports', 'names']) need(entry[f] === undefined || Array.isArray(entry[f]) && entry[f].length <= 64 && entry[f].every(x => typeof x === 'string' && x.length <= 1024) && new Set(entry[f]).size === entry[f].length)
    for (const f of ['imports', 'dynamicImports']) for (const key of entry[f] ?? []) need(Object.hasOwn(manifest, key))
  }
  function visit(key, mandatory) {
    const seen = mandatory ? staticVisited : visited; if (seen.has(key)) return; seen.add(key)
    const e = manifest[key]; need(e); add(e.file, allowed); if (mandatory) add(e.file, required)
    for (const p of e.css ?? []) { add(p, allowed); if (mandatory) add(p, required) }
    for (const p of e.assets ?? []) add(p, allowed)
    for (const k of e.imports ?? []) visit(k, mandatory)
    for (const k of e.dynamicImports ?? []) visit(k, false)
  }
  visit('index.html', true); need(allowed.size > 0 && allowed.size <= c.captureRules.bounds.assets)
  return { allowed: [...allowed].sort(), required: [...required].sort() }
}
export function projectRequest(request, graph, c) {
  need(request && typeof request.url === 'string' && request.url.length <= 4096)
  const u = new URL(request.url), entries = Object.entries(request.headers ?? {})
  need(entries.length <= 128 && new Set(entries.map(([k]) => k.toLowerCase())).size === entries.length)
  const h = Object.fromEntries(entries.map(([k, v]) => [k.toLowerCase(), v]))
  const sameOrigin = u.origin === c.origin, queryPresent = !!u.search, fragmentPresent = !!u.hash, userInfoPresent = !!(u.username || u.password)
  const kind = u.pathname === '/' ? 'DOCUMENT' : u.pathname === '/api/v1/snapshot' ? 'SNAPSHOT' : u.pathname === '/api/v1/capabilities' ? 'CAPABILITIES' : graph.allowed.includes(u.pathname) ? 'ASSET' : null
  const method = request.method === 'GET' ? 'GET' : 'OTHER', authorizationPresent = Object.hasOwn(h, 'authorization') || Object.hasOwn(h, 'proxy-authorization')
  const cookiePresent = Object.hasOwn(h, 'cookie'), bodyPresent = request.hasPostData === true || request.postData !== undefined || request.postDataEntries !== undefined
  return { kind, method, path: kind ? u.pathname : null, sameOrigin, queryPresent, fragmentPresent, userInfoPresent, authorizationPresent, cookiePresent, bodyPresent }
}
export const safeRequest = p => p.kind && p.path && p.method === 'GET' && p.sameOrigin && !p.queryPresent && !p.fragmentPresent && !p.userInfoPresent && !p.authorizationPresent && !p.cookiePresent && !p.bodyPresent
export function mimeClass(value) {
  return ({ 'text/html': 'HTML', 'application/json': 'JSON', 'text/javascript': 'JS', 'application/javascript': 'JS', 'text/css': 'CSS', 'image/svg+xml': 'SVG', 'image/png': 'PNG', 'font/woff2': 'FONT', 'font/woff': 'FONT', 'font/ttf': 'FONT' })[value] ?? 'OTHER'
}
export function expectedMIME(item, mime) {
  return item.kind === 'DOCUMENT' ? mime === 'HTML' : item.kind !== 'ASSET' ? mime === 'JSON' : mime === (item.path.endsWith('.js') ? 'JS' : item.path.endsWith('.css') ? 'CSS' : item.path.endsWith('.svg') ? 'SVG' : item.path.endsWith('.png') ? 'PNG' : 'FONT')
}
export function validateCapabilities(v, c, profile) {
  need(exact(v, ['generatedAt', 'productionControlEnabled', 'overallState', 'capabilities']) && v.productionControlEnabled === false && v.overallState === 'foundation')
  need(typeof v.generatedAt === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v.generatedAt) && new Date(v.generatedAt).toISOString().replace('.000Z', 'Z') === v.generatedAt)
  need(Array.isArray(v.capabilities) && v.capabilities.length === c.frozenRegistrySourceProjection.length)
  const text = s => typeof s === 'string' && s.length <= 2048 && !/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/.test(s)
  for (let i = 0; i < v.capabilities.length; i++) {
    const a = v.capabilities[i], f = c.frozenRegistrySourceProjection[i]
    need(exact(a, ['id', 'domain', 'name', 'state', 'readOnly', 'evidence', 'limitations']) && ['live_readonly', 'implemented_local', 'design_only', 'blocked'].includes(a.state))
    for (const key of ['id', 'domain', 'name', 'readOnly']) need(a[key] === f[key])
    for (const key of ['evidence', 'limitations']) need(Array.isArray(a[key]) && a[key].length <= 32 && a[key].every(text))
    need(a.limitations.length > 0)
    if (f.stateSource === 'StateDesignOnly') need(a.state === 'design_only')
    if (f.stateSource === 'StateImplementedLocal') need(a.state === 'implemented_local')
    const state = c.profilePolicies[profile].selectedStates[a.id]; if (state) need(a.state === state)
  }
  return v
}
