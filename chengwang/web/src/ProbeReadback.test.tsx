// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ProbeReadback } from './ProbeReadback'
import { probeDetails, probeResponse, probeStatus } from './probe-test-fixtures'

afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks() })
function connect() {
  fireEvent.change(screen.getByLabelText('探针明细管理令牌'), { target: { value: 'memory-token' } })
  fireEvent.click(screen.getByRole('button', { name: '读取受保护明细' }))
}

describe('P1 ProbeReadback lifecycle', () => {
  it('starts loading without demo health and reads only the anonymous cache', async () => {
    const fetcher = vi.fn(async () => probeResponse(probeStatus({ configured: false, state: 'disabled', reason: 'disabled', expiresAt: undefined })))
    vi.stubGlobal('fetch', fetcher); render(<ProbeReadback/>)
    expect(screen.getByText('正在读取脱敏摘要…')).toBeInTheDocument()
    expect(await screen.findByText('未配置')).toBeInTheDocument()
    expect(screen.queryByText('可用')).not.toBeInTheDocument()
    expect(fetcher).toHaveBeenCalledOnce()
  })
  it('shows partial coverage without calling it fully healthy', async () => {
    const value = probeStatus({ state: 'partial', reason: 'partial_coverage' }); value.coverage = { ...value.coverage, declaredTargets: 2, targetsMissing: 1, partial: true }
    vi.stubGlobal('fetch', vi.fn(async () => probeResponse(value))); render(<ProbeReadback/>)
    expect(await screen.findByText('覆盖不足')).toBeInTheDocument()
    expect(screen.getByText('覆盖完整也不等于业务全部正常。', { exact: false })).toBeInTheDocument()
  })
  it('reads protected details on demand and expands actual per-layer states', async () => {
    const details = probeDetails(); details.targets[0].state = 'restricted'; details.samples[0].layers.business.state = 'rate_limited'
    details.samples.unshift({ ...details.samples[0], runId: 'older-run-must-not-show', completedAt: new Date(Date.now() - 1000).toISOString(), httpStatus: 500 })
    const fetcher = vi.fn(async (input: RequestInfo | URL) => probeResponse(String(input).endsWith('/details') ? details : details.status))
    vi.stubGlobal('fetch', fetcher); render(<ProbeReadback/>); await screen.findByText('已读回'); connect()
    expect(await screen.findByText('business-fixture')).toBeInTheDocument()
    expect(screen.getByText('业务受限')).toBeInTheDocument(); expect(screen.getByText('限流')).toBeInTheDocument()
    fireEvent.click(screen.getByText('business-fixture'))
    expect(screen.getByText('run-fixture').closest('p')).toHaveTextContent('样本 run-fixture')
    expect(screen.queryByText('older-run-must-not-show')).not.toBeInTheDocument()
    expect(fetcher).toHaveBeenCalledTimes(2)
  })
  it('clears old details immediately on token change and never persists credentials', async () => {
    const storage = vi.spyOn(Storage.prototype, 'setItem')
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => probeResponse(String(input).endsWith('/details') ? probeDetails() : probeStatus())))
    render(<ProbeReadback/>); await screen.findByText('已读回'); connect(); await screen.findByText('business-fixture')
    fireEvent.change(screen.getByLabelText('探针明细管理令牌'), { target: { value: 'another-token' } })
    expect(screen.queryByText('business-fixture')).not.toBeInTheDocument(); expect(storage).not.toHaveBeenCalled()
  })
  it('clears details and token on authentication failure without echoing upstream data', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => String(input).endsWith('/details') ? probeResponse({ secret: 'never-display' }, 401) : probeResponse(probeStatus())))
    render(<ProbeReadback/>); await screen.findByText('已读回'); connect()
    expect(await screen.findByRole('alert')).toHaveTextContent('身份验证失败')
    expect(screen.getByLabelText('探针明细管理令牌')).toHaveValue(''); expect(screen.queryByText('never-display')).not.toBeInTheDocument()
  })
  it('blocks management input on LAN HTTP while leaving anonymous summary readable', async () => {
    vi.stubGlobal('window', { location: { protocol: 'http:', hostname: '10.88.0.249', origin: 'http://10.88.0.249' } })
    const fetcher = vi.fn(async () => probeResponse(probeStatus())); vi.stubGlobal('fetch', fetcher)
    render(<ProbeReadback/>); await screen.findByText('已读回')
    expect(screen.getByLabelText('探针明细管理令牌')).toBeDisabled()
    expect(screen.getByRole('button', { name: '读取受保护明细' })).toBeDisabled(); expect(fetcher).toHaveBeenCalledOnce()
  })
  it('hides formerly healthy samples when their TTL expires without a refresh', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] })
    const details = probeDetails(); const expiry = new Date(Date.now() + 2000).toISOString()
    details.status.expiresAt = expiry; details.targets[0].expiresAt = expiry; details.samples[0].expiresAt = expiry
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => probeResponse(String(input).endsWith('/details') ? details : details.status)))
    render(<ProbeReadback/>); await screen.findByText('已读回'); connect(); await screen.findByText('business-fixture')
    expect(screen.getAllByText('可用').length).toBeGreaterThan(0)
    act(() => { vi.advanceTimersByTime(3000) })
    expect(screen.queryByText('可用')).not.toBeInTheDocument()
    expect(screen.getByText(/明细已过期或当前无法验证/)).toBeInTheDocument()
  })
  it('aborts pending summary and detail reads on unmount', async () => {
    const signals: AbortSignal[] = []
    vi.stubGlobal('fetch', vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => { signals.push(init!.signal as AbortSignal); return new Promise<Response>(() => {}) }))
    const view = render(<ProbeReadback/>); connect(); expect(signals).toHaveLength(2)
    view.unmount(); expect(signals.every(signal => signal.aborted)).toBe(true)
  })
  it('does not resurrect green results after the browser wall clock rolls back', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] })
    const details = probeDetails()
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => probeResponse(String(input).endsWith('/details') ? details : details.status)))
    render(<ProbeReadback/>); await screen.findByText('已读回'); connect(); await screen.findByText('business-fixture')
    vi.setSystemTime(Date.now() - 60_000)
    act(() => { vi.advanceTimersByTime(1000) })
    expect(screen.queryByText('可用')).not.toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('检测到时钟回退')
  })
  it('rejects a stale deferred detail completion after changing credentials', async () => {
    let finish!: (response: Response) => void
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => String(input).endsWith('/details') ? new Promise<Response>(resolve => { finish = resolve }) : Promise.resolve(probeResponse(probeStatus()))))
    render(<ProbeReadback/>); await screen.findByText('已读回'); connect()
    fireEvent.change(screen.getByLabelText('探针明细管理令牌'), { target: { value: 'replacement-token' } })
    await act(async () => { finish(probeResponse(probeDetails())); await Promise.resolve() })
    expect(screen.queryByText('business-fixture')).not.toBeInTheDocument()
  })
  it('cancels pending protected details when the anonymous summary is refreshed', async () => {
    let finish!: (response: Response) => void
    let detailSignal: AbortSignal | undefined
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/details')) { detailSignal = init!.signal as AbortSignal; return new Promise<Response>(resolve => { finish = resolve }) }
      return Promise.resolve(probeResponse(probeStatus()))
    }))
    render(<ProbeReadback/>); await screen.findByText('已读回'); connect()
    fireEvent.click(screen.getByRole('button', { name: '刷新探针摘要' }))
    expect(detailSignal?.aborted).toBe(true)
    await act(async () => { finish(probeResponse(probeDetails())); await Promise.resolve() })
    expect(screen.queryByText('business-fixture')).not.toBeInTheDocument()
  })
  it('clears old conclusions and offers retry after a summary failure', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(probeResponse(probeStatus())).mockRejectedValueOnce(new Error('raw-network-secret'))
    vi.stubGlobal('fetch', fetcher); render(<ProbeReadback/>); await screen.findByText('已读回')
    fireEvent.click(screen.getByRole('button', { name: '刷新探针摘要' }))
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('暂时无法读取'))
    expect(screen.queryByText('已读回')).not.toBeInTheDocument(); expect(screen.queryByText('raw-network-secret')).not.toBeInTheDocument()
  })
})
