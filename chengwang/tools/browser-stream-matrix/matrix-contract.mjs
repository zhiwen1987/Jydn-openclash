// Pure contracts for a synthetic no-store stream matrix, not product E2E.
import { createHash } from 'node:crypto'
export const ORIGIN = 'https://127.0.0.1:17881'
export const BODY_LIMIT = 1048576
export const CASES = Object.freeze(['split-success', 'boundary-success', 'oversize', 'truncated', 'abort'])
export const sha = bytes => createHash('sha256').update(bytes).digest('hex')
export const fail = () => { throw new Error('stream matrix rejected') }
export const need = value => { if (!value) fail() }
export const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && Object.keys(v).sort().join(',') === [...keys].sort().join(',')
export const integer = (v, low = 0, high = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(v) && v >= low && v <= high
export const ascii = v => typeof v === 'string' && !/[^\x20-\x7e]/.test(v)
export function parseArguments(args) {
  need(Array.isArray(args) && args.length === 8)
  const found = {}
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i]
    need(['--root', '--bundle', '--engine', '--source-commit'].includes(key) && !Object.hasOwn(found, key))
    need(typeof args[i + 1] === 'string'); found[key] = args[i + 1]
  }
  const root = found['--root'], bundle = found['--bundle'], engine = found['--engine'], sourceCommit = found['--source-commit']
  need(ascii(root) && /^\/tmp\/chengwang-stream-matrix-[a-f0-9]{32}$/.test(root))
  const fixtureId = root.slice(-32)
  need(bundle === '/tmp/chengwang-stream-tools-' + fixtureId)
  need(['chrome-cdp', 'playwright'].includes(engine) && ascii(sourceCommit) && /^[a-f0-9]{40}$/.test(sourceCommit))
  return { root, bundle, engine, sourceCommit, fixtureId, chrome: bundle + '/chrome/chrome',
    launcher: bundle + '/matrix-chrome-launcher', profile: root + '/chrome-profile', home: root + '/home' }
}
export function parseProcess(raw) {
  need(typeof raw === 'string' && raw.length <= 8192)
  const end = raw.lastIndexOf(')'), pid = Number(raw.slice(0, raw.indexOf(' '))), fields = raw.slice(end + 2).trim().split(/\s+/)
  need(end > 0 && fields.length >= 20 && integer(pid, 2))
  const [group, session, startTicks] = [fields[2], fields[3], fields[19]].map(Number)
  need(integer(group) && integer(session) && integer(startTicks, 1))
  return { pid, group, session, startTicks, state: fields[0] }
}
export function versionProjection(v) {
  need(v && ascii(v.product) && /^(?:Chrome|HeadlessChrome)\/[0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}$/.test(v.product))
  need(ascii(v.revision) && /^@[a-f0-9]{40}$/.test(v.revision))
  need(ascii(v.protocolVersion) && /^[0-9]{1,3}\.[0-9]{1,3}$/.test(v.protocolVersion))
  return { product: v.product, revision: v.revision, protocolVersion: v.protocolVersion }
}
export function expectedBody(id) {
  need(CASES.includes(id))
  if (['split-success', 'truncated', 'abort'].includes(id)) return Buffer.from('{"ok":true}')
  return Buffer.from('{"data":"' + 'a'.repeat((id === 'oversize' ? BODY_LIMIT + 1 : BODY_LIMIT) - 11) + '"}')
}
export function responseBody(v, limit = BODY_LIMIT) {
  need(exact(v, ['body', 'base64Encoded']) && typeof v.body === 'string' && typeof v.base64Encoded === 'boolean')
  need(integer(limit, 1, BODY_LIMIT) && v.body.length <= Math.ceil(limit * 4 / 3) + 4)
  const raw = Buffer.from(v.body, v.base64Encoded ? 'base64' : 'utf8')
  need(raw.length <= limit && (!v.base64Encoded || raw.toString('base64') === v.body))
  return raw
}
export function requestCase(request) {
  need(request && typeof request.url === 'string' && request.url.length <= 128 && request.method === 'GET')
  const url = new URL(request.url)
  need(url.href === request.url && url.origin === ORIGIN && !url.search && !url.hash && !url.username && !url.password)
  const names = Object.keys(request.headers ?? {}).map(n => n.toLowerCase())
  need(!names.some(n => ['cookie', 'authorization', 'proxy-authorization', 'proxy-connection'].includes(n)))
  if (url.pathname === '/') return 'DOCUMENT'
  const id = url.pathname.slice('/case/'.length)
  need(url.pathname === '/case/' + id && CASES.includes(id))
  return id
}
export function errorProjection(text) {
  return text === 'net::ERR_ABORTED' ? 'ABORTED' : text === 'net::ERR_CONTENT_LENGTH_MISMATCH' ? 'CONTENT_LENGTH_MISMATCH' : 'OTHER'
}
export function validateCase(value) {
  need(exact(value, ['case', 'js', 'networkOrdinal', 'requestId', 'terminal', 'hostBody']) && CASES.includes(value.case))
  const j = value.js
  need(exact(j, ['bytes', 'eof', 'readEnd', 'signalAborted', 'abortRequested', 'abortError', 'cancelAttempted', 'cancelCompleted', 'parsed', 'sha256', 'elapsedMs', 'chunks']))
  need(integer(j.bytes, 0, BODY_LIMIT + 1) && integer(j.elapsedMs, 0, 30000) && integer(j.chunks, 0, 8192))
  need(['eof', 'signalAborted', 'abortRequested', 'abortError', 'cancelAttempted', 'cancelCompleted', 'parsed'].every(k => typeof j[k] === 'boolean'))
  need(integer(value.networkOrdinal, 2, 6) && ascii(value.requestId) && /^[A-Za-z0-9_.-]{1,80}$/.test(value.requestId))
  const t = value.terminal
  need(exact(t, ['event', 'canceled', 'errorCode']) && ['FINISH', 'FAIL'].includes(t.event)
    && ['YES', 'NO', 'UNSPECIFIED'].includes(t.canceled) && ['NONE', 'ABORTED', 'CONTENT_LENGTH_MISMATCH', 'OTHER'].includes(t.errorCode))
  if (value.case.endsWith('-success')) {
    const body = expectedBody(value.case), digest = sha(body)
    need(j.bytes === body.length && j.eof && j.readEnd === 'EOF_OK' && j.parsed && j.sha256 === digest
      && !j.signalAborted && !j.abortRequested && !j.abortError && !j.cancelAttempted && !j.cancelCompleted)
    need(t.event === 'FINISH' && t.canceled === 'UNSPECIFIED' && t.errorCode === 'NONE')
    need(exact(value.hostBody, ['bytes', 'sha256']) && value.hostBody.bytes === body.length && value.hostBody.sha256 === digest)
  } else {
    need(value.hostBody === null && !j.eof && !j.parsed && j.sha256 === null && j.cancelAttempted)
    if (value.case === 'oversize') {
      need(j.bytes === BODY_LIMIT + 1 && j.readEnd === 'SIZE_REJECT' && !j.abortRequested && !j.abortError && !j.signalAborted && j.cancelCompleted)
      need(t.event === 'FINISH' && t.errorCode === 'NONE' && t.canceled === 'UNSPECIFIED'
        || t.event === 'FAIL' && t.errorCode === 'ABORTED')
    } else if (value.case === 'truncated') {
      need(j.bytes === 6 && j.readEnd === 'READ_ERROR' && !j.abortRequested && !j.abortError && !j.signalAborted)
      need(t.event === 'FAIL' && ['CONTENT_LENGTH_MISMATCH', 'OTHER'].includes(t.errorCode))
    } else {
      need(j.bytes === 6 && j.readEnd === 'ABORT_ERROR' && j.abortRequested && j.abortError && j.signalAborted)
      need(t.event === 'FAIL' && t.errorCode === 'ABORTED')
    }
  }
  return value
}

// Serialized into the actual page; this function is not run on host imports.
// No injected response/fetch wrapper, body cloning, unbounded json(), or retries.
export async function readInPage(id) {
  const limit = 1048576, start = performance.now(), controller = new AbortController()
  const out = { bytes: 0, eof: false, readEnd: 'FETCH_ERROR', signalAborted: false, abortRequested: false,
    abortError: false, cancelAttempted: false, cancelCompleted: false, parsed: false, sha256: null, elapsedMs: 0, chunks: 0 }
  let reader, parts = []
  const deadline = setTimeout(() => controller.abort(), 10000)
  try {
    if (!['split-success', 'boundary-success', 'oversize', 'truncated', 'abort'].includes(id)) return out
    const response = await fetch('/case/' + id, { method: 'GET', cache: 'no-store', credentials: 'omit', redirect: 'error', signal: controller.signal })
    if (response.status !== 200 || response.headers.get('content-type') !== 'application/json'
      || response.headers.get('cache-control') !== 'no-store' || !response.body) { out.readEnd = 'HEADERS_REJECT'; return out }
    reader = response.body.getReader(); out.readEnd = 'READ_ERROR'
    while (true) {
      let next
      try { next = await reader.read() }
      catch (error) {
        out.abortError = error?.name === 'AbortError'
        out.readEnd = out.abortError ? 'ABORT_ERROR' : 'READ_ERROR'; return out
      }
      if (next.done) { out.eof = true; break }
      if (!(next.value instanceof Uint8Array) || next.value.byteLength < 1 || ++out.chunks > 8192) return out
      out.bytes += next.value.byteLength
      if (out.bytes > limit) { out.readEnd = 'SIZE_REJECT'; return out }
      parts.push(next.value)
      if (id === 'abort' && out.chunks === 1) { out.abortRequested = true; controller.abort() }
    }
    const bytes = new Uint8Array(out.bytes); let offset = 0
    for (const part of parts) { bytes.set(part, offset); offset += part.length }
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    out.parsed = id === 'split-success' ? value?.ok === true && Object.keys(value).length === 1
      : id === 'boundary-success' && typeof value?.data === 'string' && value.data.length === limit - 11
        && /^a*$/.test(value.data) && Object.keys(value).length === 1
    out.sha256 = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(b => b.toString(16).padStart(2, '0')).join('')
    out.readEnd = 'EOF_OK'; return out
  } catch { return out }
  finally {
    clearTimeout(deadline)
    if (reader && !out.eof) {
      out.cancelAttempted = true
      try { await reader.cancel(); out.cancelCompleted = true } catch { /* Closed enum/booleans only. */ }
    }
    try { reader?.releaseLock() } catch { /* No raw exceptions cross the page. */ }
    parts = []; out.signalAborted = controller.signal.aborted
    out.elapsedMs = Math.max(0, Math.floor(performance.now() - start))
  }
}
