// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://console.example"}
import '@testing-library/jest-dom/vitest'
import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { SystemReadiness } from './SystemReadiness'
import { decodeCapabilityReport } from './capability-report'
import type { CapabilityReport, Snapshot } from './types'

function report(): CapabilityReport {
  return { generatedAt: '2026-10-24T01:00:00Z', overallState: 'foundation', productionControlEnabled: false,
    capabilities: [{ id: 'mihomo_runtime_readback', domain: 'kernel', name: 'Synthetic configured reader', state: 'live_readonly', readOnly: true,
      evidence: ['GET /api/v1/kernels/mihomo/status'], limitations: ['配置不证明可达性或生产验收'] }] }
}
function response(value: unknown) { return { ok: true, status: 200, json: async () => value } as Response }
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(accept => { resolve = accept })
  return { promise, resolve }
}
function fetchReport(value: unknown = report()) { vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(response(value)))) }
function liveSnapshot(): Snapshot {
  return { product: 'Synthetic metadata', version: 'synthetic', mode: 'shadow', status: 'Synthetic control snapshot', dataSource: 'live', publishLocked: true,
    businesses: [], pools: [], interfaces: [], events: [], draft: { name: 'Synthetic draft', baseVersion: '', businesses: [], pools: [], dns: {} } }
}
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals() })

describe('CapabilityTruth', () => {
  it('labels a configured reader without inferring a production connection or health', async () => {
    fetchReport(); render(<SystemReadiness />)
    expect(await screen.findByText('Synthetic configured reader')).toBeInTheDocument()
    expect(screen.getAllByText('只读接入已配置')).toHaveLength(2)
    expect(screen.queryByText('生产只读')).not.toBeInTheDocument()
    expect(screen.queryByText(/已连接真实运行环境/)).not.toBeInTheDocument()
    expect(screen.getByText(/配置不代表连接成功/)).toBeInTheDocument()
  })
  it('keeps local write implementations separate from production authority', async () => {
    const v = report(); v.capabilities[0].state = 'implemented_local'; v.capabilities[0].readOnly = false
    fetchReport(v); render(<SystemReadiness />)
    expect(await screen.findByText('生产写入保持关闭')).toBeInTheDocument()
    expect(screen.getByText('包含写入能力')).toBeInTheDocument()
    expect(screen.queryByText('生产写入已启用')).not.toBeInTheDocument()
  })
  it('distinguishes inventory generation time and API routes from observed evidence', async () => {
    fetchReport(); render(<SystemReadiness />)
    expect(await screen.findByText('清单生成时间')).toBeInTheDocument()
    expect(screen.queryByText('证据生成时间')).not.toBeInTheDocument()
    expect(screen.getByText('GET /api/v1/kernels/mihomo/status')).toBeInTheDocument()
    expect(screen.getAllByText('可核验入口与实现依据').length).toBeGreaterThan(0)
  })
  it('removes the old inventory immediately while a refresh remains pending', async () => {
    const pending = deferred<Response>(); const fetchMock = vi.fn().mockResolvedValueOnce(response(report())).mockImplementationOnce(() => pending.promise)
    vi.stubGlobal('fetch', fetchMock); render(<SystemReadiness />)
    await screen.findByText('Synthetic configured reader')
    fireEvent.click(screen.getByRole('button', { name: '重新核验' }))
    expect(screen.queryByText('Synthetic configured reader')).not.toBeInTheDocument()
    expect(screen.getByText('正在读取系统能力证据')).toBeInTheDocument()
    await act(async () => pending.resolve(response({ ...report(), capabilities: [] })))
    expect(await screen.findByText('控制面尚未登记任何能力')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
  it('does not keep a previously accepted report after a refresh failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(response(report())).mockRejectedValueOnce(new Error('synthetic offline')))
    render(<SystemReadiness />); await screen.findByText('Synthetic configured reader')
    fireEvent.click(screen.getByRole('button', { name: '重新核验' }))
    expect(await screen.findByText('未能核验系统闭环状态')).toBeInTheDocument()
    expect(screen.queryByText('Synthetic configured reader')).not.toBeInTheDocument()
    expect(screen.queryByText('生产写入保持关闭')).not.toBeInTheDocument()
  })
  it('ignores an obsolete StrictMode success after the current refresh has failed', async () => {
    const old = deferred<Response>(); const fetchMock = vi.fn().mockImplementationOnce(() => old.promise).mockResolvedValueOnce(response(report())).mockRejectedValueOnce(new Error('synthetic refresh failure'))
    vi.stubGlobal('fetch', fetchMock); render(<StrictMode><SystemReadiness /></StrictMode>)
    await screen.findByText('Synthetic configured reader')
    fireEvent.click(screen.getByRole('button', { name: '重新核验' }))
    await screen.findByText('未能核验系统闭环状态')
    await act(async () => old.resolve(response(report())))
    expect(screen.queryByText('Synthetic configured reader')).not.toBeInTheDocument()
    expect(screen.getByText('未能核验系统闭环状态')).toBeInTheDocument()
    expect(fetchMock.mock.calls[0][1]?.signal?.aborted).toBe(true)
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })
  it('aborts the owned read on unmount without allowing a late failure to render', async () => {
    const pending = deferred<Response>(); const fetchMock = vi.fn<typeof fetch>(() => pending.promise)
    vi.stubGlobal('fetch', fetchMock); const view = render(<SystemReadiness />); view.unmount()
    expect(fetchMock.mock.calls[0][1]?.signal?.aborted).toBe(true)
    await act(async () => pending.resolve(response({ invalid: true })))
    expect(screen.queryByText('未能核验系统闭环状态')).not.toBeInTheDocument()
  })
  it('renders an unknown wire state as an unverified error instead of crashing', async () => {
    const v = report(); (v.capabilities[0] as { state: string }).state = 'synthetic_future_state'
    fetchReport(v); render(<SystemReadiness />)
    expect(await screen.findByText('未能核验系统闭环状态')).toBeInTheDocument()
    expect(screen.queryByText('Synthetic configured reader')).not.toBeInTheDocument()
  })
  it('rejects duplicate capability identities rather than counting them twice', () => {
    const v = report(); v.capabilities.push({ ...v.capabilities[0] })
    expect(() => decodeCapabilityReport(v)).toThrow('能力清单格式不受支持')
  })
  it('rejects wrong boolean and collection types without coercing authority', () => {
    for (const patch of [{ productionControlEnabled: 'false' }, { capabilities: {} }, { capabilities: null }]) {
      expect(() => decodeCapabilityReport({ ...report(), ...patch })).toThrow('能力清单格式不受支持')
    }
  })
  it('rejects missing and unsupported fields and invalid generation timestamps', () => {
    for (const value of [{ ...report(), generatedAt: 'not-a-date' }, { ...report(), generatedAt: '2026-02-31T00:00:00Z' }, { ...report(), unexpected: true }, { generatedAt: report().generatedAt }]) {
      expect(() => decodeCapabilityReport(value)).toThrow('能力清单格式不受支持')
    }
  })
  it('bounds inventory cardinality and rejects invisible control text', () => {
    const v = report(); v.capabilities[0].name = 'hidden\u202eidentity'
    expect(() => decodeCapabilityReport(v)).toThrow('能力清单格式不受支持')
    expect(() => decodeCapabilityReport({ ...report(), capabilities: Array(257).fill(report().capabilities[0]) })).toThrow('能力清单格式不受支持')
  })
  it('owns its decoded nested arrays and retains compatible hyphenated IDs and Chinese domains', () => {
    const v = report(); v.capabilities[0].id = 'synthetic-reader'; v.capabilities[0].domain = '运行观测'
    const decoded = decodeCapabilityReport(v); v.capabilities[0].limitations[0] = 'changed'; v.capabilities[0].evidence.length = 0
    expect(decoded.capabilities[0].limitations[0]).toBe('配置不证明可达性或生产验收')
    expect(decoded.capabilities[0].evidence).toHaveLength(1)
  })
  it('shows kernel adaptation targets without claiming installed or running instances', () => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {}))); render(<App />)
    fireEvent.click(screen.getByRole('button', { name: '内核与协议' }))
    expect(screen.getByRole('heading', { name: '内核适配目标' })).toBeInTheDocument()
    expect(screen.queryByText('已安装的内核')).not.toBeInTheDocument()
    expect(screen.queryByText('运行中')).not.toBeInTheDocument()
    expect(screen.queryByText('就绪')).not.toBeInTheDocument()
    for (const label of ['检查更新', '导入内核', '新增运行实例', '管理版本', '启动并行实例', '切换默认内核']) expect(screen.getByRole('button', { name: label })).toBeDisabled()
  })
  it('renders unverified kernel status neutrally and marks the matrix as untested planning', () => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {}))); render(<App />)
    fireEvent.click(screen.getByRole('button', { name: '内核与协议' }))
    expect(screen.getByText(/参考规划，目标版本尚未逐项实测/)).toBeInTheDocument()
    const states = screen.getAllByText('未核验').filter(x => x.classList.contains('status'))
    expect(states).toHaveLength(2)
    for (const item of states) expect(item).toHaveClass('neutral')
    expect(screen.getByRole('heading', { name: '适配器生命周期（设计目标，尚未执行）' })).toBeInTheDocument()
  })
  it('keeps an empty live snapshot free of fabricated topology DNS delays and events', async () => {
    fetchReport(liveSnapshot()); render(<App />)
    expect(await screen.findByText('Synthetic control snapshot')).toBeInTheDocument()
    expect(screen.getByText('暂无已读取事件')).toBeInTheDocument()
    for (const text of ['在线 12 台', '3 个订阅源', '28 ms', '本地演示数据已加载', '运行中', '国内外隔离']) expect(screen.queryByText(text)).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '流量拓扑尚未接入' })).toBeInTheDocument()
  })
  it('retains actual live metadata and supplied business rows without inventing DNS health', async () => {
    const v = liveSnapshot(); v.businesses.push({ id: 'synthetic', name: 'Supplied business', strategy: 'Supplied strategy', activeRoute: 'Supplied route', status: '未评估' })
    fetchReport(v); render(<App />)
    expect(await screen.findByText('Supplied business')).toBeInTheDocument()
    expect(screen.getByText('Supplied strategy')).toBeInTheDocument()
    expect(screen.getByText('Synthetic metadata')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'DNS 健康未核验' })).toBeInTheDocument()
    expect(screen.queryByText('家庭主网')).not.toBeInTheDocument()
  })
  it('rejects an unsupported snapshot source instead of entering the live success branch', async () => {
    fetchReport({ ...liveSnapshot(), dataSource: 'synthetic_unknown' }); render(<App />)
    await waitFor(() => expect(screen.getByText('演示模式：控制面数据源不受支持，尚未核验')).toBeInTheDocument())
    expect(screen.getByText('当前总览没有接入真实运行数据')).toBeInTheDocument()
    expect(screen.queryByText('Synthetic control snapshot')).not.toBeInTheDocument()
  })
  it('ends a never-settling inventory read at the deadline and permits an explicit retry', async () => {
    vi.useFakeTimers()
    const fetchMock = vi.fn<typeof fetch>().mockImplementationOnce(() => new Promise<Response>(() => {})).mockResolvedValueOnce(response(report()))
    vi.stubGlobal('fetch', fetchMock); render(<SystemReadiness />)
    await act(async () => { vi.advanceTimersByTime(10000) })
    expect(screen.getByText(/读取能力清单超时/)).toBeInTheDocument()
    expect(fetchMock.mock.calls[0][1]?.signal?.aborted).toBe(true)
    expect(screen.getByRole('button', { name: '重新核验' })).toBeEnabled()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '重新核验' })) })
    expect(screen.getByText('Synthetic configured reader')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
  it('does not let a timed-out late success replace the retry result or restore authority', async () => {
    vi.useFakeTimers(); const old = deferred<Response>()
    const fetchMock = vi.fn<typeof fetch>().mockImplementationOnce(() => old.promise).mockResolvedValueOnce(response({ ...report(), capabilities: [] }))
    vi.stubGlobal('fetch', fetchMock); render(<SystemReadiness />)
    await act(async () => { vi.advanceTimersByTime(10000) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '重新核验' })) })
    expect(screen.getByText('控制面尚未登记任何能力')).toBeInTheDocument()
    await act(async () => { old.resolve(response({ ...report(), productionControlEnabled: true })) })
    expect(screen.getByText('控制面尚未登记任何能力')).toBeInTheDocument()
    expect(screen.queryByText('生产写入已启用')).not.toBeInTheDocument()
    expect(screen.queryByText('Synthetic configured reader')).not.toBeInTheDocument()
  })
})
