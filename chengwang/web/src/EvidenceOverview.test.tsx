// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://console.example"}
import '@testing-library/jest-dom/vitest'
import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { EvidenceOverview } from './EvidenceOverview'
import { currentProbeFixture, overviewFixture } from './overview-test-fixture'
import { getOverview, OverviewReadError } from './overview-api'

vi.mock('./overview-api', async importOriginal => {
  const actual = await importOriginal<typeof import('./overview-api')>()
  return { ...actual, getOverview: vi.fn() }
})
const read = vi.mocked(getOverview)
function deferred<T>() { let resolve!: (value: T) => void; let reject!: (error: unknown) => void; const promise = new Promise<T>((accept, fail) => { resolve = accept; reject = fail }); return { promise, resolve, reject } }
afterEach(() => { cleanup(); read.mockReset() })
describe('EvidenceOverview', () => {
  it('shows unknown protected inventories without fabricating zero counts or business health', async () => {
    read.mockResolvedValue(overviewFixture()); render(<EvidenceOverview />)
    await screen.findByText('服务端模式：lab.prod')
    expect(screen.getAllByText('未知，未读取')).toHaveLength(2)
    expect(screen.getByText('未知，未展示缓存计数')).toBeInTheDocument()
    expect(screen.getByText(/不代表生产控制已启用/)).toBeInTheDocument()
    expect(screen.queryByText('0ms')).not.toBeInTheDocument()
  })
  it('labels current probe coverage as evidence completeness rather than success rate', async () => {
    read.mockResolvedValue(currentProbeFixture()); render(<EvidenceOverview />)
    await screen.findByText('当前缓存覆盖')
    expect(screen.getByText('声明目标数')).toBeInTheDocument()
    expect(screen.getByText('覆盖数量描述证据完整性，不是节点或业务成功率。')).toBeInTheDocument()
    expect(screen.getByText(/本阶段不宣称全网健康/)).toBeInTheDocument()
  })
  it('clears old report and mode immediately and joins a pending refresh', async () => {
    const later = deferred<ReturnType<typeof overviewFixture>>(), callback = vi.fn()
    read.mockResolvedValueOnce(overviewFixture()).mockReturnValueOnce(later.promise)
    render(<EvidenceOverview onStateChange={callback} />)
    await screen.findByText('服务端模式：lab.prod')
    const refresh = screen.getByRole('button', { name: '重新读取实际证据' }); fireEvent.click(refresh); fireEvent.click(refresh)
    expect(read).toHaveBeenCalledTimes(2); expect(refresh).toBeDisabled()
    expect(screen.queryByText('服务端模式：lab.prod')).not.toBeInTheDocument()
    expect(callback).toHaveBeenLastCalledWith({ state: 'pending', mode: null })
    await act(async () => later.resolve(overviewFixture()))
    expect(callback).toHaveBeenLastCalledWith({ state: 'ready', mode: 'lab.prod' })
  })
  it('keeps failures distinct and allows retry without demo fallback', async () => {
    read.mockRejectedValueOnce(new OverviewReadError('timeout')).mockResolvedValueOnce(overviewFixture())
    const callback = vi.fn(); render(<EvidenceOverview onStateChange={callback} />)
    expect(await screen.findByRole('alert')).toHaveTextContent('超过 5 秒')
    expect(callback).toHaveBeenLastCalledWith({ state: 'error', mode: null })
    fireEvent.click(screen.getByRole('button', { name: '重新读取实际证据' }))
    await screen.findByText('服务端模式：lab.prod'); expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
  it('aborts only pending ownership on unmount and never emits late callbacks', async () => {
    const later = deferred<ReturnType<typeof overviewFixture>>(), callback = vi.fn()
    read.mockReturnValue(later.promise); const view = render(<EvidenceOverview onStateChange={callback} />)
    const signal = read.mock.calls[0][0]!
    view.unmount(); expect(signal.aborted).toBe(true)
    await act(async () => later.resolve(overviewFixture()))
    expect(callback).toHaveBeenCalledTimes(1)
  })
  it('does not abort a successfully settled request during unmount', async () => {
    read.mockResolvedValue(overviewFixture()); const view = render(<EvidenceOverview />)
    await screen.findByText('服务端模式：lab.prod')
    const signal = read.mock.calls[0][0]!
    view.unmount(); expect(signal.aborted).toBe(false)
  })
  it('rejects stale StrictMode ownership without clearing the newer request', async () => {
    const old = deferred<ReturnType<typeof overviewFixture>>(), current = deferred<ReturnType<typeof overviewFixture>>()
    read.mockReturnValueOnce(old.promise).mockReturnValueOnce(current.promise)
    const callback = vi.fn(); render(<StrictMode><EvidenceOverview onStateChange={callback} /></StrictMode>)
    expect(read).toHaveBeenCalledTimes(2); expect(read.mock.calls[0][0]!.aborted).toBe(true)
    await act(async () => old.resolve({ ...overviewFixture(), mode: 'stale' }))
    expect(screen.getByRole('status')).toBeInTheDocument(); expect(screen.queryByText('服务端模式：stale')).not.toBeInTheDocument()
    await act(async () => current.resolve(overviewFixture()))
    expect(callback).toHaveBeenLastCalledWith({ state: 'ready', mode: 'lab.prod' })
  })
  it('uses updated callback without another request and navigates only on explicit clicks', async () => {
    read.mockResolvedValue(overviewFixture()); const navigate = vi.fn(), first = vi.fn(), second = vi.fn()
    const view = render(<EvidenceOverview onStateChange={first} onNavigate={navigate} />)
    await screen.findByText('服务端模式：lab.prod')
    view.rerender(<EvidenceOverview onStateChange={second} onNavigate={navigate} />)
    expect(read).toHaveBeenCalledOnce(); expect(navigate).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: '查看设备读回' })); expect(navigate).toHaveBeenCalledWith('设备读回')
    fireEvent.click(screen.getByRole('button', { name: '重新读取实际证据' }))
    await waitFor(() => expect(second).toHaveBeenLastCalledWith({ state: 'ready', mode: 'lab.prod' }))
  })
})
