// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ImageTrustConsole } from './ImageTrustConsole'
import { trustEntry, trustHistory, trustResponse, trustStatus } from './image-trust-test-fixtures'
import type { ImageTrustHistory, ImageTrustStatus } from './image-trust-types'

const OPERATION_ID = 'd'.repeat(32)

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); vi.unstubAllGlobals() })
function connect(token = 'memory-secret') {
  fireEvent.change(screen.getByLabelText('Bearer 令牌'), { target: { value: token } })
  fireEvent.click(screen.getByRole('button', { name: '连接并读取' }))
}
function backend(status: ImageTrustStatus = trustStatus(), history: ImageTrustHistory = trustHistory()) {
  return vi.fn(async (input: RequestInfo | URL) => trustResponse(String(input).includes('/history?') ? history : status))
}
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(r => { resolve = r })
  return { promise, resolve }
}

describe('ImageTrustConsole read-only lifecycle', () => {
  it('starts unknown, has no demo data or automatic requests and preserves the blocked boundary', () => {
    const fetcher = backend()
    render(<ImageTrustConsole fetcher={fetcher} />)
    expect(fetcher).not.toHaveBeenCalled()
    expect(screen.getByText('候选未部署 · 无设备执行授权')).toBeInTheDocument()
    expect(screen.getByText('BLOCKED · 只读')).toBeInTheDocument()
    expect(screen.queryByText('policy-a')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /验证|更新|消费|部署/ })).not.toBeInTheDocument()
  })
  it('reads two independent GETs, never stores or logs a credential, and disconnect clears everything', async () => {
    const storage = vi.spyOn(Storage.prototype, 'setItem')
    const log = vi.spyOn(console, 'log')
    const fetcher = backend()
    render(<ImageTrustConsole fetcher={fetcher} />)
    connect()
    expect(await screen.findByText('policy-a')).toBeInTheDocument()
    expect(screen.getByText(OPERATION_ID)).toBeInTheDocument()
    expect(fetcher).toHaveBeenCalledTimes(2)
    expect(storage).not.toHaveBeenCalled()
    expect(log).not.toHaveBeenCalled()
    expect(window.location.href).not.toContain('memory-secret')
    for (const call of fetcher.mock.calls) expect(String(call[0])).not.toMatch(/memory-secret|verifications|catalogue/)
    fireEvent.click(screen.getByRole('button', { name: '断开并清除' }))
    expect(screen.getByLabelText('Bearer 令牌')).toHaveValue('')
    expect(screen.queryByText('policy-a')).not.toBeInTheDocument()
    expect(screen.queryByText(OPERATION_ID)).not.toBeInTheDocument()
  })
  it('history 403 does not hide an authorized status observation', async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL) => String(input).includes('/history?') ? trustResponse({ code: 'forbidden' }, 403) : trustResponse(trustStatus()))
    render(<ImageTrustConsole fetcher={fetcher} />)
    connect()
    expect(await screen.findByText('policy-a')).toBeInTheDocument()
    expect(screen.getByText(/当前身份无权读取此区域/)).toBeInTheDocument()
  })
  it.each(['status', 'history'])('401 from %s clears all successful observations and permits reconnection', async source => {
    let unauthorized = true
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const history = String(input).includes('/history?')
      return unauthorized && history === (source === 'history') ? trustResponse({}, 401) : trustResponse(history ? trustHistory() : trustStatus())
    })
    render(<ImageTrustConsole fetcher={fetcher} />)
    connect()
    expect(await screen.findByText(/凭据已失效或无效/)).toBeInTheDocument()
    expect(screen.queryByText('policy-a')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Bearer 令牌')).toHaveValue('')
    unauthorized = false
    connect('fresh-secret')
    expect(await screen.findByText('policy-a')).toBeInTheDocument()
  })
  it('503 or malformed status never preserves a previous healthy result', async () => {
    let failed = false
    const fetcher = vi.fn(async (input: RequestInfo | URL) => String(input).includes('/history?') ? trustResponse(trustHistory()) : failed ? trustResponse({ healthy: true }, 503) : trustResponse(trustStatus()))
    render(<ImageTrustConsole fetcher={fetcher} />)
    connect()
    expect(await screen.findByText('签名时效内')).toBeInTheDocument()
    failed = true
    fireEvent.click(screen.getByRole('button', { name: '手工刷新' }))
    expect(await screen.findByText(/服务不可用、超时或网络异常/)).toBeInTheDocument()
    expect(screen.queryByText('签名时效内')).not.toBeInTheDocument()
    expect(screen.queryByText('policy-a')).not.toBeInTheDocument()
  })
  it('disconnect aborts in-flight requests and ignores late successful responses', async () => {
    const held = deferred<Response>()
    const signals: AbortSignal[] = []
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => { signals.push(init?.signal as AbortSignal); return held.promise })
    render(<ImageTrustConsole fetcher={fetcher} />)
    connect()
    fireEvent.click(screen.getByRole('button', { name: '断开并清除' }))
    expect(signals.every(s => s.aborted)).toBe(true)
    await act(async () => { held.resolve(trustResponse(trustStatus())); await held.promise })
    expect(screen.queryByText('policy-a')).not.toBeInTheDocument()
    expect(screen.getByText('尚未读取；所有状态未知。')).toBeInTheDocument()
  })
  it('token editing invalidates the old request before a new connection', async () => {
    const old = deferred<Response>()
    let count = 0
    const fetcher = vi.fn((input: RequestInfo | URL) => {
      if (++count <= 2) return old.promise
      return Promise.resolve(trustResponse(String(input).includes('/history?') ? trustHistory() : trustStatus({ storeId: '3'.repeat(32) })))
    })
    render(<ImageTrustConsole fetcher={fetcher} />)
    connect('old-secret')
    fireEvent.change(screen.getByLabelText('Bearer 令牌'), { target: { value: 'new-secret' } })
    fireEvent.click(screen.getByRole('button', { name: '连接并读取' }))
    expect(await screen.findByText('3'.repeat(32))).toBeInTheDocument()
    await act(async () => { old.resolve(trustResponse(trustStatus({ storeId: '4'.repeat(32) }))); await old.promise })
    expect(screen.queryByText('4'.repeat(32))).not.toBeInTheDocument()
  })
  it('unmount aborts pending requests', () => {
    const signals: AbortSignal[] = []
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => { signals.push(init?.signal as AbortSignal); return new Promise<Response>(() => {}) })
    const view = render(<ImageTrustConsole fetcher={fetcher} />)
    connect()
    view.unmount()
    expect(signals).toHaveLength(2)
    expect(signals.every(s => s.aborted)).toBe(true)
  })
  it('changing the configured source remounts the session and cannot retain credentials or data', async () => {
    const fetcher = backend()
    const view = render(<ImageTrustConsole fetcher={fetcher} />)
    connect()
    expect(await screen.findByText('policy-a')).toBeInTheDocument()
    view.rerender(<ImageTrustConsole fetcher={fetcher} baseUrl={window.location.origin} />)
    expect(screen.getByLabelText('Bearer 令牌')).toHaveValue('')
    expect(screen.queryByText('policy-a')).not.toBeInTheDocument()
    expect(fetcher).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('button', { name: '手工刷新' })).toBeDisabled()
  })
  it('times out in-flight reads, aborts both requests and leaves no green observation', async () => {
    vi.useFakeTimers()
    const signals: AbortSignal[] = []
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      const signal = init?.signal as AbortSignal; signals.push(signal)
      signal.addEventListener('abort', () => reject(new Error('private upstream timeout details')), { once: true })
    }))
    render(<ImageTrustConsole fetcher={fetcher} />)
    connect()
    await act(async () => { await vi.advanceTimersByTimeAsync(15001) })
    expect(signals.every(s => s.aborted)).toBe(true)
    expect(screen.getByText('请求已超时或取消，当前状态未知。')).toBeInTheDocument()
    expect(screen.queryByText(/private upstream/)).not.toBeInTheDocument()
    expect(screen.queryByText('签名时效内')).not.toBeInTheDocument()
  })
})

describe('ImageTrustConsole evidence presentation and paging', () => {
  it('shows unknown zero audit timestamps, distinguishes source from audit, and never implies network availability', async () => {
    render(<ImageTrustConsole fetcher={backend(trustStatus({ auditVerifiedAtUnix: 0, refreshFresh: false }), trustHistory({ entries: [trustEntry({ preparedAtUnix: 0, resultAtUnix: 0 })] }))} />)
    connect()
    expect(await screen.findByText('policy-a')).toBeInTheDocument()
    expect(screen.getAllByText('陈旧 / 未确认')).toHaveLength(2)
    fireEvent.click(screen.getByText('查看摘要'))
    expect(screen.getAllByText('未知（未取得真实时间）').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText(/不独立证明发布方最新/)).toBeInTheDocument()
    expect(screen.getByText(/仅健康存储的审计缺口/)).toBeInTheDocument()
  })
  it('bounds policies to 20 per page, searches policies and provides full digest disclosure', async () => {
    const policies = Array.from({ length: 51 }, (_, i) => ({ ...trustStatus().policies[0], policyId: `policy-${i}`, grantId: i.toString(16).padStart(32, '0') }))
    render(<ImageTrustConsole fetcher={backend(trustStatus({ policies }))} />)
    connect()
    expect(await screen.findByText('policy-0')).toBeInTheDocument()
    expect(screen.queryByText('policy-20')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '下一页策略' }))
    expect(screen.getByText('policy-20')).toBeInTheDocument()
    expect(screen.queryByText('policy-0')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('搜索策略'), { target: { value: 'policy-50' } })
    expect(screen.getByText('policy-50')).toBeInTheDocument()
    fireEvent.click(screen.getByLabelText('展开目录摘要'))
    expect(screen.getByLabelText('展开目录摘要').closest('details')).toHaveTextContent('sha256:' + 'a'.repeat(64))
  })
  it('fences history pages and resets on 409 without automatic retries or mixed snapshots', async () => {
    const requests: string[] = []
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input); requests.push(path)
      if (!path.includes('/history?')) return trustResponse(trustStatus())
      if (path.includes('offset=20')) return trustResponse({}, 409)
      return trustResponse(trustHistory({ total: 40, entries: Array.from({ length: 20 }, (_, i) => trustEntry({ operationId: i.toString(16).padStart(32, '0') })) }))
    })
    render(<ImageTrustConsole fetcher={fetcher} />)
    connect()
    expect(await screen.findByText('0'.repeat(32))).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '下一页记录' }))
    expect(await screen.findByText(/记录快照已变化/)).toBeInTheDocument()
    expect(requests.some(r => r.includes('offset=20&sequence=7'))).toBe(true)
    expect(screen.queryByText('0'.repeat(32))).not.toBeInTheDocument()
    const before = requests.length
    fireEvent.click(screen.getByRole('button', { name: '手工刷新' }))
    expect(await screen.findByText('0'.repeat(32))).toBeInTheDocument()
    expect(requests.length).toBe(before + 2)
    expect(requests.at(-1)).toContain('offset=0&sequence=0')
  })
  it('only searches the currently fetched history page', async () => {
    const fetcher = backend()
    render(<ImageTrustConsole fetcher={fetcher} />)
    connect()
    expect(await screen.findByText(OPERATION_ID)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('搜索当前页记录'), { target: { value: 'not-in-page' } })
    expect(screen.getByText('当前页没有匹配的操作记录')).toBeInTheDocument()
    expect(fetcher).toHaveBeenCalledTimes(2)
  })
  it('copies only the full public digest, never the bearer credential', async () => {
    const copy = vi.fn(async () => {})
    vi.stubGlobal('navigator', { clipboard: { writeText: copy } })
    render(<ImageTrustConsole fetcher={backend()} />)
    connect()
    expect(await screen.findByText('policy-a')).toBeInTheDocument()
    fireEvent.click(screen.getByLabelText('展开目录摘要'))
    fireEvent.click(screen.getByRole('button', { name: /^复制目录摘要$/ }))
    await waitFor(() => expect(copy).toHaveBeenCalledWith('sha256:' + 'a'.repeat(64)))
    expect(copy).not.toHaveBeenCalledWith('memory-secret')
    expect(await screen.findByRole('button', { name: '已复制' })).toBeInTheDocument()
  })
  it('does not mark source fresh when the signed catalogue has already expired', async () => {
    render(<ImageTrustConsole fetcher={backend(trustStatus({ notAfterUnix: 1799999999, refreshFresh: true }))} />)
    connect()
    expect(await screen.findByText('过期 / 未确认')).toBeInTheDocument()
    expect(screen.queryByText('本地窗口内')).not.toBeInTheDocument()
    expect(screen.getByText('已核对（30 秒窗口）')).toBeInTheDocument()
  })
  it('counts slow response duration rather than renewing TTL at browser receipt time', async () => {
    const original = performance.now()
    const clock = vi.spyOn(performance, 'now').mockReturnValue(original)
    const held = deferred<Response>()
    const fetcher = vi.fn((input: RequestInfo | URL) => String(input).includes('/history?') ? Promise.resolve(trustResponse(trustHistory())) : held.promise)
    render(<ImageTrustConsole fetcher={fetcher} />)
    connect()
    clock.mockReturnValue(original + 31000)
    await act(async () => { held.resolve(trustResponse(trustStatus({ notAfterUnix: 1800000010 }))); await held.promise })
    expect(await screen.findByText('过期 / 未确认')).toBeInTheDocument()
    expect(screen.queryByText('已核对（30 秒窗口）')).not.toBeInTheDocument()
  })
  it('never revives the same observation after the wall clock jumps forward then backward', async () => {
    render(<ImageTrustConsole fetcher={backend()} />)
    connect()
    expect(await screen.findByText('签名时效内')).toBeInTheDocument()
    const wall = Date.now()
    const clock = vi.spyOn(Date, 'now').mockReturnValue(wall + 2000000)
    act(() => { document.dispatchEvent(new Event('visibilitychange')) })
    expect(screen.getByText('过期 / 未确认')).toBeInTheDocument()
    clock.mockReturnValue(wall)
    act(() => { document.dispatchEvent(new Event('visibilitychange')) })
    expect(screen.getByText('过期 / 未确认')).toBeInTheDocument()
    expect(screen.queryByText('本地窗口内')).not.toBeInTheDocument()
    expect(screen.queryByText('已核对（30 秒窗口）')).not.toBeInTheDocument()
  })
  it('resets the policy page after a read returns a shorter catalogue', async () => {
    let reduced = false
    const policies = Array.from({ length: 51 }, (_, i) => ({ ...trustStatus().policies[0], policyId: `page-policy-${i}`, grantId: i.toString(16).padStart(32, '0') }))
    const fetcher = vi.fn(async (input: RequestInfo | URL) => trustResponse(String(input).includes('/history?') ? trustHistory() : trustStatus({ policies: reduced ? [policies[0]] : policies })))
    render(<ImageTrustConsole fetcher={fetcher} />)
    connect()
    expect(await screen.findByText('page-policy-0')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '下一页策略' }))
    fireEvent.click(screen.getByRole('button', { name: '下一页策略' }))
    expect(screen.getByText('page-policy-50')).toBeInTheDocument()
    reduced = true
    fireEvent.click(screen.getByRole('button', { name: '手工刷新' }))
    expect(await screen.findByText('page-policy-0')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '上一页策略' })).toBeDisabled()
    expect(screen.queryByText('没有匹配的策略')).not.toBeInTheDocument()
  })
  it('downgrades TTL and audit health without making network calls', async () => {
    const fetcher = backend(trustStatus({ notAfterUnix: 1800000002, refreshUntilUnix: 1800000001 }))
    render(<ImageTrustConsole fetcher={fetcher} />)
    connect()
    expect(await screen.findByText('签名时效内')).toBeInTheDocument()
    const realNow = performance.now()
    vi.spyOn(performance, 'now').mockReturnValue(realNow + 31000)
    await waitFor(() => expect(screen.queryByText('签名时效内')).not.toBeInTheDocument(), { timeout: 1600 })
    expect(screen.queryByText('本地窗口内')).not.toBeInTheDocument()
    expect(screen.queryByText('已核对（30 秒窗口）')).not.toBeInTheDocument()
    expect(fetcher).toHaveBeenCalledTimes(2)
  })
})
