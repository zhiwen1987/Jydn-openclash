// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { decodeImageTrustHistory, decodeImageTrustStatus, getImageTrustHistory, getImageTrustStatus } from './image-trust-api'
import { trustHistory, trustResponse, trustStatus } from './image-trust-test-fixtures'

afterEach(() => vi.unstubAllGlobals())
const options = (fetcher: typeof fetch) => ({ token: 'test-memory-token', signal: new AbortController().signal, fetcher })

describe('image trust read-only transport', () => {
  it('uses only GET with no redirect, ambient credentials, cache or referrer', async () => {
    const fetcher = vi.fn(async () => trustResponse(trustStatus()))
    await expect(getImageTrustStatus(options(fetcher))).resolves.toMatchObject({ generation: 2 })
    expect(fetcher).toHaveBeenCalledWith('/api/v1/image-trust', expect.objectContaining({ method: 'GET', redirect: 'error', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', headers: { Accept: 'application/json', Authorization: 'Bearer test-memory-token' } }))
  })
  it('requests a canonical fenced history page', async () => {
    const fetcher = vi.fn(async () => trustResponse(trustHistory()))
    await getImageTrustHistory(options(fetcher), { limit: 20, offset: 0, sequence: 7 })
    expect(fetcher).toHaveBeenCalledWith('/api/v1/image-trust/history?limit=20&offset=0&sequence=7', expect.anything())
  })
  it.each(['http://10.88.0.254', 'https://foreign.example', 'http://localhost.evil', 'https://user:secret@localhost', 'http://localhost/?secret=x', 'http://localhost/prefix'])('rejects unsafe or cross-origin endpoint %s before fetch', async baseUrl => {
    const fetcher = vi.fn()
    await expect(getImageTrustStatus({ ...options(fetcher), baseUrl })).rejects.toMatchObject({ classification: 'transport' })
    expect(fetcher).not.toHaveBeenCalled()
  })
  it('blocks token transmission when the page itself is LAN HTTP', async () => {
    vi.stubGlobal('window', { location: { href: 'http://10.88.0.249/trust.html', origin: 'http://10.88.0.249' } })
    const fetcher = vi.fn()
    await expect(getImageTrustStatus(options(fetcher))).rejects.toMatchObject({ classification: 'transport' })
    expect(fetcher).not.toHaveBeenCalled()
  })
  it.each([401, 403, 409, 503])('classifies HTTP %s without exposing unsafe upstream body', async code => {
    const fetcher = vi.fn(async () => trustResponse({ token: 'server-secret', html: '<script>secret</script>' }, code))
    const error = await getImageTrustStatus(options(fetcher)).catch(e => e)
    expect(error.status).toBe(code)
    expect(String(error)).not.toMatch(/secret|script|token/)
  })
  it('rejects redirected success responses', async () => {
    const response = trustResponse(trustStatus())
    Object.defineProperty(response, 'redirected', { value: true })
    await expect(getImageTrustStatus(options(vi.fn(async () => response)))).rejects.toMatchObject({ classification: 'transport' })
  })
  it('rejects HTML, malformed UTF-8, oversized declared and streamed bodies', async () => {
    const invalid = [new Response('<html>secret</html>', { headers: { 'Content-Type': 'text/html' } }),
      new Response(new Uint8Array([0xff]), { headers: { 'Content-Type': 'application/json' } }),
      new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': '1048577' } }),
      new Response(' '.repeat(1048577), { headers: { 'Content-Type': 'application/json' } })]
    for (const response of invalid) await expect(getImageTrustStatus(options(vi.fn(async () => response)))).rejects.toMatchObject({ classification: 'format' })
  })
  it('rejects malformed tokens without making requests', async () => {
    const fetcher = vi.fn()
    for (const token of ['', 'secret\n', 'one,two', 'a'.repeat(4097)]) await expect(getImageTrustStatus({ ...options(fetcher), token })).rejects.toMatchObject({ classification: 'authentication' })
    expect(fetcher).not.toHaveBeenCalled()
  })
})

describe('image trust observation schema', () => {
  it('keeps the real backend prefixed catalogue/manifest digests distinct from bare audit hashes', () => {
    expect(decodeImageTrustStatus(trustStatus()).catalogueSHA256).toMatch(/^sha256:[a-f0-9]{64}$/)
    expect(decodeImageTrustHistory(trustHistory(), { limit: 20, offset: 0, sequence: 0 }).entries[0]).toMatchObject({ kind: 'update', state: 'COMMITTED', outcome: 'CATALOGUE_COMMITTED', preparedAuditHash: 'c'.repeat(64) })
    expect(() => decodeImageTrustStatus(trustStatus({ catalogueSHA256: 'a'.repeat(64) }))).toThrow()
    expect(() => decodeImageTrustHistory(trustHistory({ entries: [{ ...trustHistory().entries[0], preparedAuditHash: 'sha256:' + 'c'.repeat(64) }] }), { limit: 20, offset: 0, sequence: 0 })).toThrow()
  })
  it.each([{ authorization: 'ALLOWED' }, { deviceActionsExecuted: true }, { healthy: 'true' }, { observedAtUnix: -1 }, { notAfterUnix: 1e15 }, { generation: Number.MAX_SAFE_INTEGER + 1 }, { catalogueSHA256: 'invalid' }, { policies: null }])('rejects invalid status %j', patch => {
    expect(() => decodeImageTrustStatus({ ...trustStatus(), ...patch })).toThrow()
  })
  it('rejects missing observation timestamps and unbounded policy arrays', () => {
    const { auditVerifiedAtUnix: omitted, ...old } = trustStatus()
    void omitted
    expect(() => decodeImageTrustStatus(old)).toThrow()
    expect(() => decodeImageTrustStatus(trustStatus({ policies: Array(4097).fill(trustStatus().policies[0]) }))).toThrow()
  })
  it('rejects mixed snapshot, wrong page shape and more than 50 entries', () => {
    const requested = { limit: 20, offset: 0, sequence: 7 }
    for (const patch of [{ sequence: 8 }, { offset: 20 }, { entries: Array(51).fill(trustHistory().entries[0]), total: 51 }, { authorization: 'ALLOWED' }]) expect(() => decodeImageTrustHistory({ ...trustHistory(), ...patch }, requested)).toThrow()
  })
  it('keeps real unknown zero timestamps without fabricating a time', () => {
    expect(decodeImageTrustStatus(trustStatus({ auditVerifiedAtUnix: 0 }))).toMatchObject({ auditVerifiedAtUnix: 0 })
    expect(decodeImageTrustHistory(trustHistory({ entries: [] , total: 0 }), { limit: 20, offset: 0, sequence: 0 }).entries).toEqual([])
    expect(decodeImageTrustHistory(trustHistory({ entries: [], total: 0, offset: 20 }), { limit: 20, offset: 20, sequence: 0 }).offset).toBe(20)
    expect(decodeImageTrustHistory(trustHistory({ entries: [{ ...trustHistory().entries[0], generation: 0, catalogueSHA256: '', preparedAuditHash: '', resultAuditHash: '', preparedAtUnix: 0, resultAtUnix: 0 }] }), { limit: 20, offset: 0, sequence: 0 }).entries[0].generation).toBe(0)
  })
})
