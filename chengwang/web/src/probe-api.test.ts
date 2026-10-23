// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { decodeProbeDetails, decodeProbeStatus, getProbeDetails, getProbeStatus } from './probe-api'
import { probeDetails, probeResponse, probeStatus } from './probe-test-fixtures'
import { beginProbeStatusObservation, mountProbeStatusObservation } from './probe-status-observation'

afterEach(() => vi.unstubAllGlobals())
afterEach(() => { vi.unstubAllEnvs(); vi.restoreAllMocks() })
const signal = () => new AbortController().signal

describe('P1 probe read-only transport', () => {
  it('reads anonymous status with fixed GET and no credential or redirect', async () => {
    const fetcher = vi.fn(async () => probeResponse(probeStatus()))
    vi.stubGlobal('fetch', fetcher)
    await expect(getProbeStatus(signal())).resolves.toMatchObject({ advisoryOnly: true, state: 'ready' })
    expect(fetcher).toHaveBeenCalledWith('/api/v1/probes/status', expect.objectContaining({ method: 'GET', headers: { Accept: 'application/json' }, credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer' }))
  })
  it('uses a fixed protected path and bearer only in headers', async () => {
    const fetcher = vi.fn(async () => probeResponse(probeDetails()))
    vi.stubGlobal('fetch', fetcher)
    await expect(getProbeDetails('memory-only', signal())).resolves.toMatchObject({ agentId: 'agent-fixture' })
    expect(fetcher).toHaveBeenCalledWith('/api/v1/probes/details', expect.objectContaining({ headers: { Accept: 'application/json', Authorization: 'Bearer memory-only' } }))
  })
  it('rejects a LAN HTTP token before any request', async () => {
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher)
    vi.stubGlobal('window', { location: { protocol: 'http:', hostname: '10.88.0.249' } })
    await expect(getProbeDetails('must-not-send', signal())).rejects.toMatchObject({ kind: 'transport' })
    expect(fetcher).not.toHaveBeenCalled()
  })
  it.each(['', 'bad\r\ntoken', 'bad,token', 'x'.repeat(4097)])('rejects malformed credential %s before fetch', async token => {
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher)
    await expect(getProbeDetails(token, signal())).rejects.toMatchObject({ kind: 'authentication' })
    expect(fetcher).not.toHaveBeenCalled()
  })
  it.each([401, 403, 503])('rejects HTTP %s without reading or echoing error data', async code => {
    const cancel = vi.fn(() => Promise.resolve())
    const body = new ReadableStream({ cancel })
    vi.stubGlobal('fetch', vi.fn(async () => new Response(body, { status: code })))
    const error = await getProbeDetails('secret-memory', signal()).catch(e => e)
    expect(error.status).toBe(code); expect(String(error)).not.toMatch(/secret|html|token/); expect(cancel).toHaveBeenCalledOnce()
  })
  it('does not wait for a hostile cancellation promise when rejecting unread data', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream({ cancel: () => new Promise(() => {}) }), { status: 403 })))
    await expect(getProbeDetails('memory-only', signal())).rejects.toMatchObject({ kind: 'forbidden' })
  })
  it.each(['text/html', 'application/json; charset=iso-8859-1'])('rejects unsafe content type %s', async contentType => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { headers: { 'Content-Type': contentType } })))
    await expect(getProbeStatus(signal())).rejects.toMatchObject({ kind: 'format' })
  })
  it('rejects a declared oversized response without draining its body', async () => {
    const cancel = vi.fn(() => Promise.resolve())
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream({ cancel }), { headers: { 'Content-Type': 'application/json', 'Content-Length': '1048577' } })))
    await expect(getProbeStatus(signal())).rejects.toMatchObject({ kind: 'format' }); expect(cancel).toHaveBeenCalledOnce()
  })
  it('rejects an undeclared oversized stream at the byte limit', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new Uint8Array(1048577), { headers: { 'Content-Type': 'application/json' } })))
    await expect(getProbeStatus(signal())).rejects.toMatchObject({ kind: 'format' })
  })
  it('honors an aborted response instead of publishing completed data', async () => {
    const controller = new AbortController()
    vi.stubGlobal('fetch', vi.fn(async () => { controller.abort(); return probeResponse(probeStatus()) }))
    await expect(getProbeStatus(controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
  })
  it('rejects anonymous responses containing an identity or raw field', () => {
    expect(() => decodeProbeStatus({ ...probeStatus(), agentId: 'private-agent' })).toThrow()
  })
  it('rejects non-advisory or inconsistent coverage summaries', () => {
    expect(() => decodeProbeStatus({ ...probeStatus(), advisoryOnly: false })).toThrow()
    const value = probeStatus(); value.coverage.targetsMissing = 1
    expect(() => decodeProbeStatus(value)).toThrow()
  })
  it('accepts explicit restricted and rate-limited business conclusions', () => {
    const value = probeDetails(); value.targets[0].state = 'restricted'; value.samples[0].conclusion = 'rate_limited'
    expect(decodeProbeDetails(value).targets[0].state).toBe('restricted')
  })
  it('rejects detail over-bounds, duplicate identities and unsafe raw fields', () => {
    const value = probeDetails()
    expect(() => decodeProbeDetails({ ...value, targets: Array(257).fill(value.targets[0]) })).toThrow()
    expect(() => decodeProbeDetails({ ...value, samples: [value.samples[0], value.samples[0]] })).toThrow()
    expect(() => decodeProbeDetails({ ...value, samples: [{ ...value.samples[0], evidenceRef: '/private/file' }] })).toThrow()
    expect(() => decodeProbeDetails({ ...value, samples: [{ ...value.samples[0], layers: { ...value.samples[0].layers, dns: { ...value.samples[0].layers.dns, host: 'secret.example' } } }] })).toThrow()
  })
  it('rejects redirected success even if its payload is otherwise valid', async () => {
    const response = probeResponse(probeStatus()); Object.defineProperty(response, 'redirected', { value: true })
    vi.stubGlobal('fetch', vi.fn(async () => response))
    await expect(getProbeStatus(signal())).rejects.toMatchObject({ kind: 'transport' })
  })
  function bindingEnvironment() {
    vi.stubEnv('VITE_PROBE_REQUEST_BINDING', '1')
    vi.stubGlobal('window', { location: { origin: 'https://127.0.0.1:17861', protocol: 'https:', hostname: '127.0.0.1' } })
    vi.stubGlobal('crypto', { getRandomValues: (bytes: Uint8Array) => bytes.fill(0x42) })
    const info = vi.spyOn(console, 'info').mockImplementation(() => {})
    const bound = () => { const s = signal(); beginProbeStatusObservation(mountProbeStatusObservation(), s, 'MANUAL'); return s }
    const rows = () => info.mock.calls.map(args => args[0]).filter((line): line is string => typeof line === 'string' && line.startsWith('CW_PROBE_BIND:')).map(line => JSON.parse(line.slice('CW_PROBE_BIND:'.length)))
    return { bound, rows, info }
  }
  it('adds a binding header only for an opted-in bound anonymous loopback status request', async () => {
    const { bound, rows } = bindingEnvironment(), fetcher = vi.fn(async () => probeResponse(probeStatus()))
    vi.stubGlobal('fetch', fetcher)
    await expect(getProbeStatus(bound())).resolves.toMatchObject({ state: 'ready' })
    const headers = fetcher.mock.calls[0] as unknown as [string, RequestInit]
    expect(headers[1].headers).toEqual({ Accept: 'application/json', 'X-CW-Probe-Request': expect.stringMatching(/^v1\.[a-f0-9]{32}\.[1-9]\d*\.[1-9]\d*$/) })
    expect(rows().filter(row => row.e === 'SEND')).toHaveLength(1)
    expect(fetcher).toHaveBeenCalledOnce()
  })
  it('keeps diagnostic headers absent on ordinary and protected requests', async () => {
    const { bound, rows } = bindingEnvironment(), fetcher = vi.fn(async (path: string) => probeResponse(path.endsWith('/details') ? probeDetails() : probeStatus()))
    vi.stubGlobal('fetch', fetcher)
    vi.stubEnv('VITE_PROBE_REQUEST_BINDING', '0'); await getProbeStatus(bound())
    vi.stubEnv('VITE_PROBE_REQUEST_BINDING', '1'); await getProbeStatus(signal())
    vi.stubGlobal('window', { location: { origin: 'https://example.invalid', protocol: 'https:', hostname: 'example.invalid' } }); await getProbeStatus(bound())
    vi.stubGlobal('window', { location: { origin: 'https://127.0.0.1:17861', protocol: 'https:', hostname: '127.0.0.1' } }); await getProbeDetails('memory-only', bound())
    for (const call of fetcher.mock.calls as unknown as [string, RequestInit][]) expect(call[1].headers).not.toHaveProperty('X-CW-Probe-Request')
    expect(rows()).toEqual([])
  })
  it('observes cancel fulfillment and rejection without awaiting or changing the read result', async () => {
    const { bound, rows, info } = bindingEnvironment()
    for (const outcome of ['RESOLVED', 'REJECTED']) {
      let resolve!: () => void, reject!: (error: Error) => void
      const pending = new Promise<void>((yes, no) => { resolve = yes; reject = no })
      const reader = { read: vi.fn().mockResolvedValueOnce({ done: false, value: new TextEncoder().encode(JSON.stringify(probeStatus())) }).mockResolvedValueOnce({ done: true }), cancel: vi.fn(() => pending), releaseLock: vi.fn() }
      const response = probeResponse(probeStatus()); vi.spyOn(response.body!, 'getReader').mockReturnValue(reader as unknown as ReadableStreamDefaultReader<Uint8Array>)
      vi.stubGlobal('fetch', vi.fn(async () => response))
      const before = rows().filter(row => row.e === 'CANCEL_RESULT').length
      await expect(getProbeStatus(bound())).resolves.toMatchObject({ state: 'ready' })
      expect(reader.cancel).toHaveBeenCalledOnce(); expect(reader.releaseLock).toHaveBeenCalledOnce()
      expect(rows().filter(row => row.e === 'CANCEL_RESULT')).toHaveLength(before)
      if (outcome === 'RESOLVED') resolve(); else reject(Error('PRIVATE_CANCEL_ERROR'))
      await Promise.resolve(); await Promise.resolve()
      expect(rows().filter(row => row.e === 'CANCEL_RESULT').at(-1)?.o).toBe(outcome)
      const after = info.mock.calls.map(args => String(args[0]))
      expect(after.map(line => line.includes('"e":"CANCEL"') && line.includes('"p":"AFTER"')).lastIndexOf(true)).toBeLessThan(after.map(line => line.startsWith('CW_PROBE_BIND:') && line.includes('"e":"CANCEL_RESULT"')).lastIndexOf(true))
    }
    expect(JSON.stringify(info.mock.calls)).not.toContain('PRIVATE_CANCEL_ERROR')
  })
  it('preserves synchronous and absent cancellation outcomes without exposing errors', async () => {
    const { bound, rows, info } = bindingEnvironment(), cancel = vi.fn(() => { throw Error('PRIVATE_CANCEL_ERROR') })
    const response = new Response(null, { status: 403 }); Object.defineProperty(response, 'body', { value: { cancel } })
    vi.stubGlobal('fetch', vi.fn(async () => response))
    await expect(getProbeStatus(bound())).rejects.toMatchObject({ kind: 'forbidden' })
    expect(cancel).toHaveBeenCalledOnce(); expect(rows().at(-1)?.o).toBe('THREW')
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 403 })))
    await expect(getProbeStatus(bound())).rejects.toMatchObject({ kind: 'forbidden' })
    expect(rows().at(-1)?.o).toBe('NO_BODY'); expect(JSON.stringify(info.mock.calls)).not.toContain('PRIVATE_CANCEL_ERROR')
  })
})
