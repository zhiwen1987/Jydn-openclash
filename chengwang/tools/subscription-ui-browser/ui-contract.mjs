// Closed, pure contracts. No browser launch or network operation on import.
import { createHash } from 'node:crypto'
export const ORIGIN = 'https://127.0.0.1:17891'
export const STEPS = Object.freeze(['anonymous', 'connected', 'prepared', 'cancelled', 'prepared_again', 'created_desktop', 'created_mobile', 'receipt', 'hidden', 'returned', 'cleared'])
export const SCOPE = 'REAL_PRODUCT_CREATE_RECEIPT_FLOW_PARTIAL_FULL_SUBSCRIPTION_PLAN_PENDING'
export const LABEL = 'browser-ui-source'
export const FAVICON = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%231769e8'/%3E%3Cpath d='M9 10h14M9 16h14M9 22h14M12 7v18M20 7v18' stroke='white' stroke-width='2' stroke-linecap='round'/%3E%3C/svg%3E"
export const sha = bytes => createHash('sha256').update(bytes).digest('hex')
export const need = value => { if (!value) throw Error('subscription UI rejected') }
export const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join(',') === [...keys].sort().join(',')
export const integer = (v, min = 0, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(v) && v >= min && v <= max
export const ascii = v => typeof v === 'string' && !/[^\x20-\x7e]/.test(v)
export function parseArguments(args) {
  need(Array.isArray(args) && args.length === 8); const v = {}
  for (let i = 0; i < 8; i += 2) { need(['--root', '--bundle', '--engine', '--source-commit'].includes(args[i]) && !Object.hasOwn(v, args[i]) && typeof args[i + 1] === 'string'); v[args[i]] = args[i + 1] }
  const root = v['--root'], fixtureId = root?.slice(-32), bundle = v['--bundle'], engine = v['--engine'], sourceCommit = v['--source-commit']
  need(ascii(root) && /^\/tmp\/chengwang-subscription-ui-[a-f0-9]{32}$/.test(root) && bundle === '/tmp/chengwang-subscription-ui-tools-' + fixtureId)
  need(['chrome-cdp', 'playwright'].includes(engine) && /^[a-f0-9]{40}$/.test(sourceCommit))
  return { root, fixtureId, bundle, engine, sourceCommit, chrome: bundle + '/chrome/chrome', launcher: bundle + '/ui-chrome-launcher', home: root + '/home', profile: root + '/chrome-profile' }
}
export function parseProcess(raw) {
  need(typeof raw === 'string' && raw.length <= 8192); const end = raw.lastIndexOf(')'), pid = Number(raw.slice(0, raw.indexOf(' '))), fields = raw.slice(end + 2).trim().split(/\s+/)
  need(end > 0 && fields.length >= 20 && integer(pid, 2)); const [group, session, startTicks] = [fields[2], fields[3], fields[19]].map(Number)
  need(integer(group) && integer(session) && integer(startTicks, 1)); return { pid, group, session, startTicks, state: fields[0] }
}
export function versionProjection(v) {
  need(v && ascii(v.product) && /^(?:Chrome|HeadlessChrome)\/[0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}$/.test(v.product))
  need(ascii(v.revision) && /^@[a-f0-9]{40}$/.test(v.revision) && ascii(v.protocolVersion) && /^[0-9]{1,3}\.[0-9]{1,3}$/.test(v.protocolVersion))
  return { product: v.product, revision: v.revision, protocolVersion: v.protocolVersion }
}
export function canaryVariants(token) {
  need(ascii(token) && token.length >= 24 && token.length <= 4096 && /^[\x21-\x2b\x2d-\x7e]+$/.test(token))
  const values = [token, 'Bearer ' + token], result = new Set()
  for (const value of values) { const b = Buffer.from(value); for (const item of [value, b.toString('base64'), b.toString('base64url'), b.toString('hex'), b.toString('hex').toUpperCase(), encodeURIComponent(value), sha(b)]) result.add(item) }
  return [...result]
}
export function safePublic(raw, canaries) {
  need(Buffer.isBuffer(raw) && Array.isArray(canaries) && canaries.length > 0 && canaries.every(v => typeof v === 'string' && v.length > 0))
  for (const value of canaries) need(!raw.includes(Buffer.from(value)))
  return raw
}
export function decodeBody(value, limit) {
  need(exact(value, ['body', 'base64Encoded']) && typeof value.body === 'string' && typeof value.base64Encoded === 'boolean' && integer(limit, 1, 8 << 20))
  need(value.body.length <= Math.ceil(limit * 4 / 3) + 4); const raw = Buffer.from(value.body, value.base64Encoded ? 'base64' : 'utf8')
  need(raw.length > 0 && raw.length <= limit && (!value.base64Encoded || raw.toString('base64') === value.body)); return raw
}
export function assetPaths(manifest) {
  need(manifest && typeof manifest === 'object' && !Array.isArray(manifest) && Object.keys(manifest).length <= 128)
  need(manifest['index.html']?.isEntry === true); const visited = new Set(), paths = new Set()
  const add = path => { need(typeof path === 'string' && /^assets\/[A-Za-z0-9][A-Za-z0-9_.-]{0,160}\.(?:js|css|woff2?|ttf|svg|png)$/.test(path)); paths.add('/' + path) }
  const visit = key => { need(typeof key === 'string' && Object.hasOwn(manifest, key)); if (visited.has(key)) return; visited.add(key); const entry = manifest[key]; need(entry && typeof entry === 'object'); add(entry.file); for (const field of ['css', 'assets']) { need(entry[field] === undefined || Array.isArray(entry[field]) && entry[field].length <= 64); for (const path of entry[field] ?? []) add(path) }; need(entry.imports === undefined || Array.isArray(entry.imports) && entry.imports.length <= 64); for (const child of entry.imports ?? []) visit(child) }
  visit('index.html'); need(paths.size > 0 && paths.size <= 64); return [...paths].sort()
}
export function classifyRequest(request, allowedAssets, token) {
  need(request && typeof request.url === 'string' && request.url.length <= 1024 && ['GET', 'POST'].includes(request.method))
  const url = new URL(request.url); need(url.href === request.url && url.origin === ORIGIN && !url.username && !url.password && !url.hash)
  const entries = Object.entries(request.headers ?? {}); need(entries.length <= 64 && new Set(entries.map(([k]) => k.toLowerCase())).size === entries.length)
  const headers = Object.fromEntries(entries.map(([k, v]) => [k.toLowerCase(), v]))
  need(!['cookie', 'proxy-authorization', 'proxy-connection'].some(k => Object.hasOwn(headers, k)))
  const path = url.pathname + url.search; let kind
  if (request.method === 'GET' && !url.search) {
    if (path === '/') kind = 'DOCUMENT'
    else if (allowedAssets.includes(path)) kind = 'ASSET'
    else if (path === '/api/v1/snapshot') kind = 'SNAPSHOT'
    else if (path === '/api/v1/subscriptions/access') kind = 'COLLECTION_ACCESS'
    else if (path === '/api/v1/subscriptions/sources') kind = 'SOURCES'
    else if (/^\/api\/v1\/subscriptions\/sources\/src_[a-f0-9]{32}\/access$/.test(path)) kind = 'SOURCE_ACCESS'
    else if (/^\/api\/v1\/subscriptions\/commands\/cmd_[a-f0-9]{32}$/.test(path)) kind = 'RECEIPT'
  }
  if (request.method === 'GET' && /^\/api\/v1\/subscriptions\/sources\/src_[a-f0-9]{32}\/candidates\?limit=20&offset=0&revision=1$/.test(path)) kind = 'CANDIDATES'
  if (request.method === 'POST' && path === '/api/v1/subscriptions/sources') kind = 'CREATE'
  need(kind); const auth = !['DOCUMENT', 'ASSET', 'SNAPSHOT'].includes(kind)
  need(auth ? headers.authorization === 'Bearer ' + token : headers.authorization === undefined)
  let requestPublic = null
  if (kind === 'CREATE') {
    need(typeof request.postData === 'string' && Buffer.byteLength(request.postData) <= 1024)
    const body = JSON.parse(request.postData); need(exact(body, ['label']) && body.label === LABEL && headers['content-type'] === 'application/json')
    need(typeof headers['idempotency-key'] === 'string' && /^sub_[a-f0-9]{32}$/.test(headers['idempotency-key']))
    requestPublic = { label: body.label, idempotencyKey: headers['idempotency-key'] }
  } else need(!request.hasPostData && request.postData === undefined && headers['idempotency-key'] === undefined)
  return { method: request.method, path, kind, authorizationPresent: auth, requestPublic }
}
export function validateStep(step, dom, mutationCount) {
  need(STEPS.includes(step) && dom.pageMounted && dom.pageVisible === (step !== 'hidden') && dom.https && !dom.alertVisible && dom.session.tokenType === 'password' && dom.session.tokenEmpty && dom.session.fileEmpty && dom.session.storageEmpty && dom.session.cookiesEmpty)
  need(!Object.values(dom.stale).some(Boolean) && dom.candidates.length === 0 && dom.nodes.length === 0 && dom.sessionApproval === null && dom.handoff === null)
  const created = STEPS.indexOf(step) >= STEPS.indexOf('created_desktop') && step !== 'cleared'; need(mutationCount === (created || step === 'cleared' ? 1 : 0))
  need(dom.sources.length === (created ? 1 : 0)); if (created) need(dom.sources[0].selected && dom.sources[0].revision === 1 && !dom.sources[0].accepted && dom.receipt?.state === 'committed' && dom.receipt.revision === 1 && dom.receipt.auditRecorded)
  else need(dom.receipt === null)
  need((dom.confirmation?.kind === 'create') === ['prepared', 'prepared_again'].includes(step)); if (!['prepared', 'prepared_again'].includes(step)) need(dom.confirmation === null)
  const create = dom.controls.find(v => v.key === 'prepare_create'); need(create?.enabled === !['anonymous', 'cleared'].includes(step))
  if (['created_desktop', 'created_mobile'].includes(step)) need(dom.viewport.width === (step === 'created_mobile' ? 375 : 1440) && dom.viewport.height === 900 && dom.viewport.scrollWidth === dom.viewport.clientWidth && dom.viewport.scrollX === 0 && dom.viewport.scrollY === 0 && dom.boundaryVisible)
  return dom
}
