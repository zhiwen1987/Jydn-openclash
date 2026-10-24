import { decodeOverviewSnapshot } from './overview-report'
import type { OverviewSnapshot } from './overview-types'

export type OverviewErrorKind = 'network' | 'http' | 'timeout' | 'format' | 'aborted'
const messages: Record<OverviewErrorKind, string> = { network: '无法连接实际总览接口，请检查连接后重试。', http: '控制面暂未提供可用的实际总览，请确认功能已启用后重试。', timeout: '读取实际总览超过 5 秒，请稍后重试。', format: '实际总览响应格式不符合约定，已停止展示。', aborted: '本次实际总览读取已取消。' }
export class OverviewReadError extends Error {
  readonly kind: OverviewErrorKind
  constructor(kind: OverviewErrorKind) { super(messages[kind]); this.name = 'OverviewReadError'; this.kind = kind }
}
function cancel(body: ReadableStream<Uint8Array> | null) { try { void body?.cancel().catch(() => undefined) } catch { /* cancellation is best effort, never a new result */ } }

export async function getOverview(external?: AbortSignal): Promise<OverviewSnapshot> {
  const controller = new AbortController()
  let settled = false, timedOut = false, reader: ReadableStreamDefaultReader<Uint8Array> | null = null, complete = false
  const abortError = () => new OverviewReadError(timedOut ? 'timeout' : 'aborted')
  const forward = () => { if (!settled) controller.abort() }
  external?.addEventListener('abort', forward, { once: true })
  if (external?.aborted) controller.abort()
  const timer = setTimeout(() => { if (!settled) { timedOut = true; controller.abort() } }, 5000)
  async function bounded<T>(promise: Promise<T>): Promise<T> {
    if (controller.signal.aborted) { void promise.catch(() => undefined); throw abortError() }
    let listener: (() => void) | undefined
    const stopped = new Promise<never>((_, reject) => {
      listener = () => reject(abortError())
      controller.signal.addEventListener('abort', listener, { once: true })
    })
    try { return await Promise.race([promise, stopped]) }
    finally { if (listener) controller.signal.removeEventListener('abort', listener) }
  }
  try {
    if (controller.signal.aborted) throw abortError()
    const pending = fetch('/api/v1/overview', { method: 'GET', headers: { Accept: 'application/json' }, credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal })
    // A late response from a transport which ignores abort must not retain an unread body.
    void pending.then(response => { if (controller.signal.aborted && !reader) cancel(response.body) }, () => undefined)
    let response: Response
    try { response = await bounded(pending) }
    catch (error) { if (error instanceof OverviewReadError) throw error; throw new OverviewReadError('network') }
    if (response.redirected || (response.url && typeof location !== 'undefined' && response.url !== new URL('/api/v1/overview', location.href).href)) { cancel(response.body); throw new OverviewReadError('format') }
    if (!response.ok) { cancel(response.body); throw new OverviewReadError('http') }
    const contentType = response.headers.get('content-type')
    const contentLength = response.headers.get('content-length')
    if (!contentType || !/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*$/i.test(contentType) || (contentLength !== null && (!/^\d+$/.test(contentLength) || !Number.isSafeInteger(Number(contentLength)) || Number(contentLength) > 65536)) || !response.body) { cancel(response.body); throw new OverviewReadError('format') }
    reader = response.body.getReader()
    const decoder = new TextDecoder('utf-8', { fatal: true })
    let size = 0, emptyChunks = 0, text = ''
    try {
      while (true) {
        let chunk: ReadableStreamReadResult<Uint8Array>
        try { chunk = await bounded(reader.read()) }
        catch (error) { if (controller.signal.aborted) throw abortError(); if (error instanceof OverviewReadError) throw error; throw new OverviewReadError('network') }
        if (chunk.done) break
        if (!(chunk.value instanceof Uint8Array)) throw new OverviewReadError('format')
        // Repeated immediately resolved empty chunks cannot be allowed to starve
        // the deadline's event-loop turn. Nonempty reads remain bounded by bytes.
        if (chunk.value.byteLength === 0 && ++emptyChunks > 1024) throw new OverviewReadError('format')
        size += chunk.value.byteLength
        if (size > 65536) throw new OverviewReadError('format')
        text += decoder.decode(chunk.value, { stream: true })
      }
      text += decoder.decode()
      if (controller.signal.aborted) throw abortError()
      const result = decodeOverviewSnapshot(JSON.parse(text))
      complete = true
      return result
    } catch (error) { if (controller.signal.aborted) throw abortError(); if (error instanceof OverviewReadError) throw error; throw new OverviewReadError('format') }
  } catch (error) {
    if (error instanceof OverviewReadError) throw error
    throw new OverviewReadError(controller.signal.aborted ? timedOut ? 'timeout' : 'aborted' : 'network')
  } finally {
    settled = true
    clearTimeout(timer)
    external?.removeEventListener('abort', forward)
    if (reader) {
      if (!complete) { try { void reader.cancel().catch(() => undefined) } catch { /* never wait for cancellation */ } }
      try { reader.releaseLock() } catch { /* ignored pending reads may still own their lock */ }
    }
  }
}
