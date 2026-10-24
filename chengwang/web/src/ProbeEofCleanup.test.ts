// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://127.0.0.1:17861/"}
// SYNTHETIC TRANSPORT TESTS ONLY: no browser, server, TLS or network-cause proof.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { getProbeDetails, getProbeStatus } from './probe-api'
import { beginProbeStatusObservation, mountProbeStatusObservation } from './probe-status-observation'
import { probeDetails, probeResponse, probeStatus } from './probe-test-fixtures'

const signal = () => new AbortController().signal
const bytes = (text: string) => new TextEncoder().encode(text)
function interceptedReader(chunks: Uint8Array<ArrayBuffer>[], cancel = vi.fn(async () => {})) {
  let offset = 0
  const reader = {
    read: vi.fn(async (): Promise<ReadableStreamReadResult<Uint8Array<ArrayBuffer>>> =>
      offset < chunks.length ? { done: false, value: chunks[offset++] } : { done: true, value: undefined }),
    cancel, releaseLock: vi.fn(),
  }
  const response = probeResponse(probeStatus())
  vi.spyOn(response.body!, 'getReader').mockReturnValue(reader as unknown as ReadableStreamDefaultReader<Uint8Array<ArrayBuffer>>)
  const fetcher = vi.fn(async () => response)
  vi.stubGlobal('fetch', fetcher)
  return { reader, response, fetcher }
}
function binding() {
  vi.stubEnv('VITE_PROBE_REQUEST_BINDING', '1')
  vi.stubGlobal('crypto', { getRandomValues: (value: Uint8Array) => value.fill(0x43) })
  const log = vi.spyOn(console, 'info').mockImplementation(() => {})
  const requestSignal = signal()
  beginProbeStatusObservation(mountProbeStatusObservation(), requestSignal, 'MANUAL')
  return { requestSignal, lines: () => log.mock.calls.map(args => String(args[0])) }
}

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks() })

describe('ProbeEofCleanup', () => {
  it('releases a multichunk status reader after JSON EOF without cancelling it', async () => {
    const raw = JSON.stringify(probeStatus()), cut = Math.floor(raw.length / 2)
    const { reader, fetcher } = interceptedReader([bytes(raw.slice(0, cut)), bytes(raw.slice(cut))])
    await expect(getProbeStatus(signal())).resolves.toMatchObject({ state: 'ready', advisoryOnly: true })
    expect(reader.read).toHaveBeenCalledTimes(3); expect(reader.cancel).not.toHaveBeenCalled()
    expect(reader.releaseLock).toHaveBeenCalledOnce(); expect(fetcher).toHaveBeenCalledOnce()
  })
  it('releases a protected details reader after JSON EOF without cancelling it', async () => {
    const { reader, fetcher } = interceptedReader([bytes(JSON.stringify(probeDetails()))])
    await expect(getProbeDetails('synthetic-memory-only', signal())).resolves.toMatchObject({ agentId: 'agent-fixture' })
    expect(reader.cancel).not.toHaveBeenCalled(); expect(reader.releaseLock).toHaveBeenCalledOnce()
    expect(fetcher).toHaveBeenCalledWith('/api/v1/probes/details', expect.objectContaining({ headers: { Accept: 'application/json', Authorization: 'Bearer synthetic-memory-only' } }))
  })
  it('unlocks an actual synthetic single-chunk response after successful EOF', async () => {
    const response = probeResponse(probeStatus()), reader = response.body!.getReader()
    const cancel = vi.spyOn(reader, 'cancel'), release = vi.spyOn(reader, 'releaseLock')
    vi.spyOn(response.body!, 'getReader').mockReturnValue(reader)
    vi.stubGlobal('fetch', vi.fn(async () => response))
    expect(response.body!.locked).toBe(true)
    await expect(getProbeStatus(signal())).resolves.toMatchObject({ state: 'ready' })
    expect(cancel).not.toHaveBeenCalled(); expect(release).toHaveBeenCalledOnce()
    expect(response.body!.locked).toBe(false)
  })
  it('does not mistake an empty byte chunk for EOF before valid JSON completes', async () => {
    const { reader } = interceptedReader([new Uint8Array(0), bytes(JSON.stringify(probeStatus())), new Uint8Array(0)])
    await expect(getProbeStatus(signal())).resolves.toMatchObject({ state: 'ready' })
    expect(reader.read).toHaveBeenCalledTimes(4); expect(reader.cancel).not.toHaveBeenCalled()
    expect(reader.releaseLock).toHaveBeenCalledOnce()
  })
  it('records JSON EOF success without fabricating cancellation events or settlements', async () => {
    const { requestSignal, lines } = binding(), { reader } = interceptedReader([bytes(JSON.stringify(probeStatus()))])
    await expect(getProbeStatus(requestSignal)).resolves.toMatchObject({ state: 'ready' })
    await Promise.resolve()
    const events = lines().filter(line => line.startsWith('CW_PROBE_STATUS:')).map(line => JSON.parse(line.slice('CW_PROBE_STATUS:'.length)))
    expect(events.filter(row => row.e === 'EOF')).toHaveLength(1)
    expect(events.filter(row => row.e === 'READ_END')).toEqual([expect.objectContaining({ k: 'EOF_OK', f: true })])
    expect(events.filter(row => row.e === 'CANCEL')).toEqual([])
    expect(lines().filter(line => line.startsWith('CW_PROBE_BIND:') && line.includes('"e":"CANCEL_RESULT"'))).toEqual([])
    expect(reader.cancel).not.toHaveBeenCalled(); expect(reader.releaseLock).toHaveBeenCalledOnce()
  })
  it('keeps the ordinary successful request free of opt-in diagnostic headers', async () => {
    const { reader, fetcher } = interceptedReader([bytes(JSON.stringify(probeStatus()))])
    await getProbeStatus(signal())
    expect(fetcher).toHaveBeenCalledWith('/api/v1/probes/status', expect.objectContaining({ headers: { Accept: 'application/json' }, credentials: 'omit', cache: 'no-store', redirect: 'error' }))
    expect(reader.cancel).not.toHaveBeenCalled(); expect(reader.releaseLock).toHaveBeenCalledOnce()
  })
  it('still cancels a forbidden unread body without acquiring a reader', async () => {
    const cancel = vi.fn(async () => {}), response = new Response(new ReadableStream({ cancel }), { status: 403 })
    const getReader = vi.spyOn(response.body!, 'getReader')
    vi.stubGlobal('fetch', vi.fn(async () => response))
    await expect(getProbeStatus(signal())).rejects.toMatchObject({ kind: 'forbidden' })
    expect(cancel).toHaveBeenCalledOnce(); expect(getReader).not.toHaveBeenCalled()
  })
  it('still cancels a declared oversized body before reading any chunks', async () => {
    const cancel = vi.fn(async () => {}), response = new Response(new ReadableStream({ cancel }), { headers: { 'Content-Type': 'application/json', 'Content-Length': '1048577' } })
    const getReader = vi.spyOn(response.body!, 'getReader')
    vi.stubGlobal('fetch', vi.fn(async () => response))
    await expect(getProbeStatus(signal())).rejects.toMatchObject({ kind: 'format' })
    expect(cancel).toHaveBeenCalledOnce(); expect(getReader).not.toHaveBeenCalled()
  })
  it('still cancels a redirected success before accepting its body', async () => {
    const cancel = vi.fn(async () => {}), response = new Response(new ReadableStream({ cancel }), { headers: { 'Content-Type': 'application/json' } })
    Object.defineProperty(response, 'redirected', { value: true })
    const getReader = vi.spyOn(response.body!, 'getReader')
    vi.stubGlobal('fetch', vi.fn(async () => response))
    await expect(getProbeStatus(signal())).rejects.toMatchObject({ kind: 'transport' })
    expect(cancel).toHaveBeenCalledOnce(); expect(getReader).not.toHaveBeenCalled()
  })
  it('still cancels and releases an undeclared oversized stream before EOF', async () => {
    const { reader } = interceptedReader([new Uint8Array(1048577)])
    await expect(getProbeStatus(signal())).rejects.toMatchObject({ kind: 'format' })
    expect(reader.read).toHaveBeenCalledOnce(); expect(reader.cancel).toHaveBeenCalledOnce()
    expect(reader.releaseLock).toHaveBeenCalledOnce()
  })
  it('still cancels and releases a stream with invalid UTF-8 before EOF', async () => {
    const { reader } = interceptedReader([new Uint8Array([0xff])])
    await expect(getProbeStatus(signal())).rejects.toMatchObject({ kind: 'format' })
    expect(reader.read).toHaveBeenCalledOnce(); expect(reader.cancel).toHaveBeenCalledOnce()
    expect(reader.releaseLock).toHaveBeenCalledOnce()
  })
  it('still cancels and releases when reading rejects before EOF without exposing the raw error', async () => {
    const { reader } = interceptedReader([])
    reader.read.mockRejectedValueOnce(Error('PRIVATE_EOF_READ_ERROR'))
    const error = await getProbeStatus(signal()).catch(error => error)
    expect(error).toMatchObject({ kind: 'format' }); expect(String(error)).not.toContain('PRIVATE_EOF_READ_ERROR')
    expect(reader.cancel).toHaveBeenCalledOnce(); expect(reader.releaseLock).toHaveBeenCalledOnce()
  })
  it('still cancels when malformed JSON is rejected after observed EOF', async () => {
    const { reader } = interceptedReader([bytes('{')])
    await expect(getProbeStatus(signal())).rejects.toMatchObject({ kind: 'format' })
    expect(reader.read).toHaveBeenCalledTimes(2); expect(reader.cancel).toHaveBeenCalledOnce()
    expect(reader.releaseLock).toHaveBeenCalledOnce()
  })
  it('still cancels when an incomplete UTF-8 sequence fails the EOF flush', async () => {
    const { reader } = interceptedReader([new Uint8Array([0xc3])])
    await expect(getProbeStatus(signal())).rejects.toMatchObject({ kind: 'format' })
    expect(reader.read).toHaveBeenCalledTimes(2); expect(reader.cancel).toHaveBeenCalledOnce()
    expect(reader.releaseLock).toHaveBeenCalledOnce()
  })
  it('keeps abort rejection and cancellation when a non-EOF read observes an aborted signal', async () => {
    const controller = new AbortController(), { reader } = interceptedReader([bytes(JSON.stringify(probeStatus()))])
    reader.read.mockImplementationOnce(async () => { controller.abort(); return { done: false, value: bytes('{}') } })
    await expect(getProbeStatus(controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(reader.read).toHaveBeenCalledOnce(); expect(reader.cancel).toHaveBeenCalledOnce()
    expect(reader.releaseLock).toHaveBeenCalledOnce()
  })
  it('does not publish parsed success when the EOF read observes an aborted signal', async () => {
    const controller = new AbortController(), { reader } = interceptedReader([bytes(JSON.stringify(probeStatus()))])
    reader.read.mockImplementationOnce(async () => ({ done: false, value: bytes(JSON.stringify(probeStatus())) }))
    reader.read.mockImplementationOnce(async () => { controller.abort(); return { done: true, value: undefined } })
    await expect(getProbeStatus(controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(reader.read).toHaveBeenCalledTimes(2); expect(reader.cancel).toHaveBeenCalledOnce()
    expect(reader.releaseLock).toHaveBeenCalledOnce()
  })
  it('does not await a hostile cancellation promise after JSON rejection at EOF', async () => {
    const cancel = vi.fn(() => new Promise<void>(() => {})), { reader } = interceptedReader([bytes('{')], cancel)
    await expect(getProbeStatus(signal())).rejects.toMatchObject({ kind: 'format' })
    expect(cancel).toHaveBeenCalledOnce(); expect(reader.releaseLock).toHaveBeenCalledOnce()
  })
  it('does not expose a synchronous cancellation error or skip lock release after JSON rejection', async () => {
    const cancel = vi.fn((): Promise<void> => { throw Error('PRIVATE_EOF_CANCEL_ERROR') }), { reader } = interceptedReader([bytes('{')], cancel)
    const error = await getProbeStatus(signal()).catch(error => error)
    expect(error).toMatchObject({ kind: 'format' }); expect(String(error)).not.toContain('PRIVATE_EOF_CANCEL_ERROR')
    expect(cancel).toHaveBeenCalledOnce(); expect(reader.releaseLock).toHaveBeenCalledOnce()
  })
})
