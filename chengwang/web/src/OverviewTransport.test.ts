import { afterEach, describe, expect, it, vi } from 'vitest'
import { getOverview } from './overview-api'
import { overviewFixture } from './overview-test-fixture'

afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals() })
function reply(body = JSON.stringify(overviewFixture()), headers = { 'content-type': 'application/json' }) { return new Response(body, { headers }) }
function trackedRead(chunks: Uint8Array[], options: { stuck?: boolean; cancelStuck?: boolean; failRead?: boolean } = {}) {
  let index = 0
  const releaseLock = vi.fn(), cancel = vi.fn(() => options.cancelStuck ? new Promise<void>(() => undefined) : Promise.resolve())
  const read = vi.fn(() => options.failRead ? Promise.reject(new Error('private socket')) : index < chunks.length ? Promise.resolve({ done: false, value: chunks[index++] }) : options.stuck ? new Promise<ReadableStreamReadResult<Uint8Array>>(() => undefined) : Promise.resolve({ done: true, value: undefined }))
  return { response: { ok: true, redirected: false, url: '', headers: new Headers({ 'content-type': 'application/json' }), body: { getReader: () => ({ read, releaseLock, cancel }) } } as unknown as Response, releaseLock, cancel }
}
describe('OverviewTransport', () => {
  it('uses only the fixed anonymous GET and releases successful EOF without cancellation', async () => {
    const body = trackedRead([new TextEncoder().encode(JSON.stringify(overviewFixture()))]), fetcher = vi.fn().mockResolvedValue(body.response)
    vi.stubGlobal('fetch', fetcher)
    expect((await getOverview()).mode).toBe('lab.prod')
    expect(fetcher).toHaveBeenCalledWith('/api/v1/overview', expect.objectContaining({ method: 'GET', credentials: 'omit', redirect: 'error', cache: 'no-store', headers: { Accept: 'application/json' } }))
    expect(body.releaseLock).toHaveBeenCalledOnce(); expect(body.cancel).not.toHaveBeenCalled()
  })
  it('decodes a split UTF8 sequence without treating an empty chunk as EOF', async () => {
    const v = overviewFixture(); v.mode = '生产'
    const bytes = new TextEncoder().encode(JSON.stringify(v)), split = bytes.indexOf(0xe7) + 1
    const body = trackedRead([bytes.slice(0, split), new Uint8Array(), bytes.slice(split)])
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(body.response))
    expect((await getOverview()).mode).toBe('生产')
  })
  it('rejects fatal UTF8 and cancels format failures without awaiting cancellation', async () => {
    const body = trackedRead([new Uint8Array([0xff])], { cancelStuck: true })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(body.response))
    await expect(getOverview()).rejects.toMatchObject({ kind: 'format' })
    expect(body.cancel).toHaveBeenCalledOnce(); expect(body.releaseLock).toHaveBeenCalledOnce()
  })
  it('rejects oversized declared and streamed bodies', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reply('{}', { 'content-type': 'application/json', 'content-length': '65537' })))
    await expect(getOverview()).rejects.toMatchObject({ kind: 'format' })
    const body = trackedRead([new Uint8Array(65537)]); vi.stubGlobal('fetch', vi.fn().mockResolvedValue(body.response))
    await expect(getOverview()).rejects.toMatchObject({ kind: 'format' }); expect(body.cancel).toHaveBeenCalledOnce()
  })
  it('distinguishes safe network HTTP and format errors without reflecting upstream text', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('private credential')))
    await expect(getOverview()).rejects.toMatchObject({ kind: 'network', message: '无法连接实际总览接口，请检查连接后重试。' })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('private credential', { status: 503 })))
    await expect(getOverview()).rejects.toMatchObject({ kind: 'http' })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reply('{private credential')))
    await expect(getOverview()).rejects.toMatchObject({ kind: 'format' })
  })
  it('bounds an ignored fetch abort with the total five second deadline', async () => {
    vi.useFakeTimers(); vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(() => undefined)))
    const result = getOverview().catch(error => error)
    await vi.advanceTimersByTimeAsync(5000)
    expect(await result).toMatchObject({ kind: 'timeout' })
  })
  it('bounds a stalled read and does not await a stalled cancel', async () => {
    vi.useFakeTimers(); const body = trackedRead([], { stuck: true, cancelStuck: true }); vi.stubGlobal('fetch', vi.fn().mockResolvedValue(body.response))
    const result = getOverview().catch(error => error)
    await vi.advanceTimersByTimeAsync(5000)
    expect(await result).toMatchObject({ kind: 'timeout' }); expect(body.cancel).toHaveBeenCalledOnce()
    const empty = trackedRead(Array.from({ length: 1025 }, () => new Uint8Array()))
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(empty.response))
    await expect(getOverview()).rejects.toMatchObject({ kind: 'format' }); expect(empty.cancel).toHaveBeenCalledOnce()
  })
  it('honors pre-abort without fetching and clears timers after settlement', async () => {
    vi.useFakeTimers(); const fetcher = vi.fn().mockResolvedValue(reply()); vi.stubGlobal('fetch', fetcher)
    const signal = new AbortController(); signal.abort()
    await expect(getOverview(signal.signal)).rejects.toMatchObject({ kind: 'aborted' }); expect(fetcher).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
    const completed = new AbortController()
    await getOverview(completed.signal); expect(vi.getTimerCount()).toBe(0)
    const finishedSignal = fetcher.mock.calls[0][1].signal as AbortSignal
    completed.abort(); expect(finishedSignal.aborted).toBe(false)
  })
  it('cancels an ignored late fetch response after the caller has aborted', async () => {
    let resolve!: (value: Response) => void
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(accept => { resolve = accept })))
    const controller = new AbortController(), result = getOverview(controller.signal).catch(error => error)
    controller.abort(); expect(await result).toMatchObject({ kind: 'aborted' })
    const cancel = vi.fn().mockResolvedValue(undefined)
    resolve({ body: { cancel } } as unknown as Response)
    await Promise.resolve(); expect(cancel).toHaveBeenCalledOnce()
  })
  it('owns read rejections at a synchronous abort boundary and reports cancellation', async () => {
    const controller = new AbortController(), cancel = vi.fn().mockResolvedValue(undefined), releaseLock = vi.fn()
    const response = { ok: true, redirected: false, url: '', headers: new Headers({ 'content-type': 'application/json' }), body: { getReader() { controller.abort(); return { read: () => Promise.reject(new Error('private read failure')), cancel, releaseLock } } } } as unknown as Response
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response))
    await expect(getOverview(controller.signal)).rejects.toMatchObject({ kind: 'aborted' })
    await Promise.resolve(); expect(cancel).toHaveBeenCalledOnce(); expect(releaseLock).toHaveBeenCalledOnce()
  })
  it('reports a transport stream failure as network rather than DTO corruption', async () => {
    const body = trackedRead([], { failRead: true })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(body.response))
    await expect(getOverview()).rejects.toMatchObject({ kind: 'network' }); expect(body.cancel).toHaveBeenCalledOnce()
  })
})
