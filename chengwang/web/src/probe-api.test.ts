// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { decodeProbeDetails, decodeProbeStatus, getProbeDetails, getProbeStatus } from './probe-api'
import { probeDetails, probeResponse, probeStatus } from './probe-test-fixtures'

afterEach(() => vi.unstubAllGlobals())
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
})
