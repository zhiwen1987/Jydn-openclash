// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { StrictMode } from 'react'
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
  it('does not abort a manual summary when the automatic poll overlaps it', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] })
    let finish!: (response: Response) => void
    const signals: AbortSignal[] = []
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      signals.push(init!.signal as AbortSignal)
      return signals.length === 2 ? new Promise<Response>(resolve => { finish = resolve }) : Promise.resolve(probeResponse(probeStatus()))
    })
    vi.stubGlobal('fetch', fetcher); render(<ProbeReadback/>); await screen.findByText('已读回')
    act(() => { vi.advanceTimersByTime(29_000) })
    const button = screen.getByRole('button', { name: '刷新探针摘要' })
    fireEvent.click(button)
    expect(button).toHaveAttribute('aria-busy', 'true')
    act(() => { vi.advanceTimersByTime(2000) })
    fireEvent.click(button)
    expect(fetcher).toHaveBeenCalledTimes(2)
    expect(signals[1].aborted).toBe(false)
    await act(async () => { finish(probeResponse(probeStatus())) })
    expect(button).toHaveAttribute('aria-busy', 'false')
    await act(async () => { vi.advanceTimersByTime(29_000) })
    expect(fetcher).toHaveBeenCalledTimes(3)
    expect(signals.every(signal => !signal.aborted)).toBe(true)
    expect(button).toHaveAttribute('aria-busy', 'false')
  })
  it('shares an active automatic summary instead of cancelling it on a click', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] })
    let finish!: (response: Response) => void
    let pollSignal!: AbortSignal
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      if (fetcher.mock.calls.length === 2) {
        pollSignal = init!.signal as AbortSignal
        return new Promise<Response>(resolve => { finish = resolve })
      }
      return Promise.resolve(probeResponse(probeStatus()))
    })
    vi.stubGlobal('fetch', fetcher); render(<ProbeReadback/>); await screen.findByText('已读回')
    act(() => { vi.advanceTimersByTime(30_000) })
    const button = screen.getByRole('button', { name: '刷新探针摘要' })
    expect(button).toHaveAttribute('aria-busy', 'true'); fireEvent.click(button)
    expect(fetcher).toHaveBeenCalledTimes(2); expect(pollSignal.aborted).toBe(false)
    await act(async () => { finish(probeResponse(probeStatus())) })
    expect(button).toHaveAttribute('aria-busy', 'false')
    await act(async () => { fireEvent.click(button) })
    expect(fetcher).toHaveBeenCalledTimes(3); expect(button).toHaveAttribute('aria-busy', 'false')
  })
  it('releases the single-flight latch after a real abort rejection at the deadline', async () => {
    vi.useFakeTimers()
    let timeoutSignal!: AbortSignal
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      if (fetcher.mock.calls.length === 2) {
        timeoutSignal = init!.signal as AbortSignal
        return new Promise<Response>((_resolve, reject) => timeoutSignal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true }))
      }
      return Promise.resolve(probeResponse(probeStatus()))
    })
    vi.stubGlobal('fetch', fetcher)
    await act(async () => { render(<ProbeReadback/>) })
    expect(screen.getByRole('status')).toHaveTextContent('已读回')
    const button = screen.getByRole('button', { name: '刷新探针摘要' })
    fireEvent.click(button)
    await act(async () => { await vi.advanceTimersByTimeAsync(10_001) })
    expect(timeoutSignal.aborted).toBe(true)
    expect(screen.getByRole('status')).toHaveTextContent('暂时无法读取')
    expect(screen.queryByText('已读回')).not.toBeInTheDocument(); expect(button).toHaveAttribute('aria-busy', 'false')
    await act(async () => { fireEvent.click(button) })
    expect(screen.getByRole('status')).toHaveTextContent('已读回'); expect(fetcher).toHaveBeenCalledTimes(3)
  })
  it('does not let an obsolete StrictMode completion unlock a newer summary', async () => {
    let oldFinish!: (response: Response) => void
    let newFinish!: (response: Response) => void
    const signals: AbortSignal[] = []
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      signals.push(init!.signal as AbortSignal)
      if (signals.length === 1) return new Promise<Response>(resolve => { oldFinish = resolve })
      if (signals.length === 3) return new Promise<Response>(resolve => { newFinish = resolve })
      return Promise.resolve(probeResponse(probeStatus()))
    })
    vi.stubGlobal('fetch', fetcher); render(<StrictMode><ProbeReadback/></StrictMode>); await screen.findByText('已读回')
    expect(signals).toHaveLength(2); expect(signals[0].aborted).toBe(true)
    const button = screen.getByRole('button', { name: '刷新探针摘要' })
    fireEvent.click(button)
    await act(async () => { oldFinish(probeResponse(probeStatus())) })
    expect(button).toHaveAttribute('aria-busy', 'true'); expect(signals[2].aborted).toBe(false)
    await act(async () => { newFinish(probeResponse(probeStatus())) })
    expect(button).toHaveAttribute('aria-busy', 'false'); expect(fetcher).toHaveBeenCalledTimes(3)
  })
  it('clears protected reads immediately even when a summary refresh is joined', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] })
    let finishStatus!: (response: Response) => void
    let finishDetails!: (response: Response) => void
    let detailSignal!: AbortSignal
    let summaryReads = 0
    const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/details')) {
        detailSignal = init!.signal as AbortSignal
        return new Promise<Response>(resolve => { finishDetails = resolve })
      }
      summaryReads++
      return summaryReads === 2 ? new Promise<Response>(resolve => { finishStatus = resolve }) : Promise.resolve(probeResponse(probeStatus()))
    })
    vi.stubGlobal('fetch', fetcher); render(<ProbeReadback/>); await screen.findByText('已读回'); connect()
    act(() => { vi.advanceTimersByTime(30_000) })
    const button = screen.getByRole('button', { name: '刷新探针摘要' })
    // Two events in one React batch exercise the synchronous owner latch, not
    // merely a rendered disabled button. The protected read is still revoked.
    act(() => { fireEvent.click(button); fireEvent.click(button) })
    expect(summaryReads).toBe(2); expect(detailSignal.aborted).toBe(true)
    await act(async () => { finishDetails(probeResponse(probeDetails())); finishStatus(probeResponse(probeStatus())) })
    expect(screen.queryByText('business-fixture')).not.toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('已读回')
    expect(fetcher).toHaveBeenCalledTimes(3)
  })
  it('rejects a timed-out late success without unlocking or overwriting its retry', async () => {
    vi.useFakeTimers()
    let oldFinish!: (response: Response) => void
    let retryFinish!: (response: Response) => void
    const signals: AbortSignal[] = []
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      signals.push(init!.signal as AbortSignal)
      if (signals.length === 2) return new Promise<Response>(resolve => { oldFinish = resolve }) // Ignores abort deliberately.
      if (signals.length === 3) return new Promise<Response>(resolve => { retryFinish = resolve })
      return Promise.resolve(probeResponse(probeStatus()))
    })
    vi.stubGlobal('fetch', fetcher); await act(async () => { render(<ProbeReadback/>) })
    const button = screen.getByRole('button', { name: '刷新探针摘要' })
    fireEvent.click(button)
    await act(async () => { await vi.advanceTimersByTimeAsync(10_001) })
    expect(signals[1].aborted).toBe(true); expect(button).toHaveAttribute('aria-busy', 'false')
    expect(screen.getByRole('status')).toHaveTextContent('暂时无法读取')
    fireEvent.click(button)
    await act(async () => { oldFinish(probeResponse(probeStatus())) })
    expect(screen.getByRole('status')).toHaveTextContent('正在读取脱敏摘要')
    expect(button).toHaveAttribute('aria-busy', 'true'); expect(signals[2].aborted).toBe(false)
    fireEvent.click(button); expect(fetcher).toHaveBeenCalledTimes(3)
    await act(async () => { retryFinish(probeResponse(probeStatus({ configured: false, state: 'disabled', reason: 'disabled' }))) })
    expect(screen.getByRole('status')).toHaveTextContent('未配置')
    expect(screen.queryByText('已读回')).not.toBeInTheDocument(); expect(button).toHaveAttribute('aria-busy', 'false')
  })
  it('stops polling and deadlines on unmount and ignores late summary completion', async () => {
    vi.useFakeTimers()
    let finish!: (response: Response) => void
    let signal!: AbortSignal
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      signal = init!.signal as AbortSignal
      return new Promise<Response>(resolve => { finish = resolve })
    })
    vi.stubGlobal('fetch', fetcher)
    const view = render(<ProbeReadback/>)
    view.unmount(); expect(signal.aborted).toBe(true)
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); finish(probeResponse(probeStatus())) })
    expect(fetcher).toHaveBeenCalledOnce(); expect(vi.getTimerCount()).toBe(0)
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })
})
