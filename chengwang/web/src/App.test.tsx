// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://console.example"}
import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { subscriptionAccess, subscriptionResponse, subscriptionSourcePage } from './subscription-test-fixtures'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('App', () => {
  it('opens real subscription resources and retains session across navigation', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = new URL(String(input), window.location.origin).pathname
      if (path === '/api/v1/snapshot') return new Promise<Response>(() => {})
      if (path === '/api/v1/subscriptions/access') return Promise.resolve(subscriptionResponse(subscriptionAccess()))
      if (path === '/api/v1/subscriptions/sources') return Promise.resolve(subscriptionResponse(subscriptionSourcePage()))
      return Promise.reject(new Error('unexpected synthetic route'))
    })
    vi.stubGlobal('fetch', fetchMock)
    render(<App />)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: '订阅与提供者' }))
    expect(screen.getByRole('heading', { name: '订阅资源' })).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(1)
    fireEvent.change(screen.getByLabelText('订阅管理令牌'), { target: { value: 'synthetic-subscription-token' } })
    fireEvent.click(screen.getByRole('button', { name: '连接订阅会话' }))
    expect(await screen.findByText('Synthetic source')).toBeInTheDocument()
    expect(screen.getByLabelText('订阅管理令牌')).toHaveValue('')
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
    fireEvent.click(screen.getByRole('button', { name: '运行总览' }))
    expect(screen.queryByRole('heading', { name: '订阅资源' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '订阅与提供者' }))
    expect(screen.getByRole('heading', { name: '订阅资源' })).toBeInTheDocument()
    expect(screen.getByText('Synthetic source')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(screen.getByRole('button', { name: '清除会话与令牌' })).toBeEnabled()
  })

  it('renders safe shadow-mode fallback when API is unavailable', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('offline'))))
    render(<App />)
    expect(screen.getByRole('heading', { name: '运行总览' })).toBeInTheDocument()
    expect(await screen.findByText('演示模式：无法读取本地控制面')).toBeInTheDocument()
    expect(screen.getByText('当前总览没有接入真实运行数据')).toBeInTheDocument()
    expect(screen.queryByText('在线 12 台')).not.toBeInTheDocument()
  })

  it('opens policy workflow and keeps publish disabled before validation', () => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})))
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: '策略路由' }))
    expect(screen.getByRole('heading', { name: '策略路由' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '发布变更' })).toBeDisabled()
    expect(screen.getAllByText('国内精确规则').length).toBeGreaterThan(0)
    expect(screen.getByText('流量决策模拟器')).toBeInTheDocument()
  })

  it('shows the multi-kernel capability matrix', () => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})))
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: '内核与协议' }))
    expect(screen.getByRole('heading', { name: '内核与协议' })).toBeInTheDocument()
    expect(screen.getAllByText('sing-box').length).toBeGreaterThan(0)
    expect(screen.getByText('Hysteria2')).toBeInTheDocument()
  })

  it('shows truthful layered passive observation without inferring business health', async () => {
    const status = {
      configured: true, mode: 'passive_read_only', running: true, fresh: true, stale: false,
      lastAttemptAt: '2026-10-18T08:00:00Z', lastSuccessAt: '2026-10-18T08:00:00Z', consecutiveFailures: 0,
      controller: { state: 'available', observedAt: '2026-10-18T08:00:00Z', reason: 'Mihomo Controller 周期读回成功' },
      nodeTechnical: { state: 'unknown', reason: '尚未启用独立节点技术探针' },
      internet: { state: 'unknown', reason: '尚未启用端到端互联网探针' },
      business: { state: 'unknown', reason: '尚未启用按业务定义的许可清单探针' },
      dns: { state: 'unknown', reason: '尚未启用 DNS 路径与泄漏探针' },
      storage: { state: 'available', reason: '观测摘要持久化正常' },
      clock: { state: 'available', reason: '观测时钟单调性正常' },
    }
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/api/v1/snapshot')) return new Promise(() => {})
      if (url.endsWith('/api/v1/observations/status')) return Promise.resolve({ ok: true, status: 200, json: async () => status } as Response)
      return Promise.reject(new Error(`unexpected request: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)
    render(<App />)
    const observationNavigation = screen.getByRole('button', { name: '代理节点' })
    // The icon-only mobile sidebar must retain a programmatic name even when
    // its visual text span is hidden by responsive CSS.
    expect(observationNavigation).toHaveAttribute('aria-label', '代理节点')
    fireEvent.click(observationNavigation)
    expect(await screen.findByText('Mihomo Controller 周期读回成功')).toBeInTheDocument()
    expect(screen.getByText('延迟和控制器可达不等于业务可用')).toBeInTheDocument()
    expect(screen.getAllByText('未评估').length).toBeGreaterThanOrEqual(4)
    expect(screen.queryByText('ChatGPT 可用')).not.toBeInTheDocument()
    // The independent probe panel reads its own anonymous cache; it does not
    // turn the passive controller's four unknown layers into business health.
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
  })

  it('manages proxy server interfaces without enabling production publish', () => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})))
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: '代理接口' }))
    expect(screen.getByRole('heading', { name: '代理接口' })).toBeInTheDocument()
    expect(screen.getByText('局域网 SOCKS5')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '应用到数据面' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: /新增代理服务/ }))
    expect(screen.getByRole('heading', { name: '新增代理服务' })).toBeInTheDocument()
    expect(screen.getByDisplayValue('new_proxy_service')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '取消新增' }))
    expect(screen.getByRole('heading', { name: '本机 Mixed' })).toBeInTheDocument()
  })

  it('reads Mihomo runtime state and expands readback drift evidence', async () => {
    const snapshot = {
      product: '澄网 · 网络代理与路由平台', version: 'v1', mode: 'shadow', status: '演示快照 · 已连接控制面', dataSource: 'demo', publishLocked: true,
      businesses: [], pools: [], interfaces: [], events: [],
      draft: {
        name: 'readback', baseVersion: 'v1',
        pools: [{ id: 'chatgpt_pool', name: 'ChatGPT', members: ['美国-01'] }],
        businesses: [{ id: 'chatgpt', name: 'ChatGPT', domains: ['chatgpt.com'], strategy: 'chatgpt_pool', candidates: ['chatgpt_pool'], fallback: 'DIRECT', skipEmptyPools: true, failuresToSwitch: 3, probeIntervalSec: 30, sessionStickyMin: 30, switchCooldownSec: 300 }],
        dns: { domesticResolvers: ['223.5.5.5'], overseasResolvers: ['https://1.1.1.1/dns-query'] },
      },
    }
    const runtime = {
      observedAt: '2026-10-18T06:00:00Z', version: { version: 'v1.19.0', meta: true, premium: false },
      config: { mode: 'rule', allowLan: false, bindAddress: '127.0.0.1', ipv6: false, port: 0, socksPort: 0, mixedPort: 7890, redirPort: 0, tproxyPort: 0, externalController: '127.0.0.1:9090' },
      proxies: [{ name: 'chatgpt_pool', type: 'Selector', now: '日本-01', all: ['日本-01'] }],
      rules: [{ type: 'DomainSuffix', payload: 'chatgpt.com', proxy: 'DIRECT' }],
    }
    const report = {
      observedAt: '2026-10-18T06:01:00Z', controllerVersion: 'v1.19.0', match: false,
      counts: { expectedGroups: 1, observedGroups: 1, expectedRules: 1, observedRules: 1 },
      drifts: [{ kind: 'rule_target_mismatch', path: 'businesses[0].domains[0]', severity: 'error', expected: 'chatgpt_pool', actual: 'DIRECT', message: '域名规则的实际目标与期望策略不一致' }],
    }
    const response = (body: unknown) => Promise.resolve({ ok: true, status: 200, json: async () => body } as Response)
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/api/v1/snapshot')) return response(snapshot)
		if (url.endsWith('/api/v1/kernels/mihomo/runtime')) {
			expect(init?.headers).toMatchObject({ Authorization: 'Bearer diagnostic-test-token' })
			return response(runtime)
		}
		if (url.endsWith('/api/v1/kernels/mihomo/readback')) {
			expect(init?.headers).toMatchObject({ Authorization: 'Bearer diagnostic-test-token' })
			return response(report)
		}
      return Promise.reject(new Error(`unexpected request: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)
    render(<App />)
    expect(await screen.findByText('演示快照 · 已连接控制面')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '设备读回' }))
		expect(fetchMock).toHaveBeenCalledTimes(1)
		fireEvent.change(screen.getByLabelText('管理令牌'), { target: { value: 'diagnostic-test-token' } })
		fireEvent.click(screen.getByRole('button', { name: '刷新状态' }))
    expect((await screen.findAllByText('v1.19.0')).length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('button', { name: /执行读回对账/ }))
    expect(await screen.findByText('规则目标错误')).toBeInTheDocument()
    const expand = screen.getByRole('button', { name: /规则目标错误/ })
    fireEvent.click(expand)
    expect(screen.getByText('域名规则的实际目标与期望策略不一致')).toBeInTheDocument()
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
		fireEvent.change(screen.getByLabelText('管理令牌'), { target: { value: 'replacement-token' } })
		expect(screen.queryAllByText('v1.19.0')).toHaveLength(0)
		expect(screen.getByRole('button', { name: /执行读回对账/ })).toBeDisabled()
  })

  it('shows an explicit boundary when the Mihomo controller is not configured', async () => {
    const snapshot = {
      product: '澄网 · 网络代理与路由平台', version: 'v1', mode: 'shadow', status: '演示快照 · 已连接控制面', dataSource: 'demo', publishLocked: true,
      businesses: [], pools: [], interfaces: [], events: [],
      draft: {
        name: 'readback', baseVersion: 'v1', pools: [], businesses: [],
        dns: { domesticResolvers: ['223.5.5.5'], overseasResolvers: ['https://1.1.1.1/dns-query'] },
      },
    }
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/api/v1/snapshot')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => snapshot } as Response)
      }
		if (url.endsWith('/api/v1/kernels/mihomo/runtime')) {
        return Promise.resolve({
          ok: false,
          status: 503,
          json: async () => ({ code: 'mihomo_not_configured', message: 'Mihomo controller is not configured' }),
        } as Response)
      }
      return Promise.reject(new Error(`unexpected request: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)
    render(<App />)
    expect(await screen.findByText('演示快照 · 已连接控制面')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '设备读回' }))
		fireEvent.change(screen.getByLabelText('管理令牌'), { target: { value: 'diagnostic-test-token' } })
		fireEvent.click(screen.getByRole('button', { name: '刷新状态' }))
    expect(await screen.findByText('尚未配置 Mihomo 控制器')).toBeInTheDocument()
    expect(screen.getByText('设置 CHENGWANG_MIHOMO_URL 和本机令牌后重新读取。')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重试' })).toBeInTheDocument()
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
  })

  it('shows evidence-backed capability states without claiming design work is complete', async () => {
    const report = {
      generatedAt: '2026-10-18T07:30:00Z',
      productionControlEnabled: false,
      overallState: 'foundation',
      capabilities: [
        {
          id: 'mihomo-readback', domain: '运行观测', name: 'Mihomo 设备读回', state: 'live_readonly', readOnly: true,
          evidence: ['GET /api/v1/kernels/mihomo/status'], limitations: ['不证明具体业务端到端可用'],
        },
        {
          id: 'auto-repair', domain: '自动化', name: '自动修复', state: 'design_only', readOnly: false,
          evidence: [], limitations: ['尚未实现生产执行器'],
        },
      ],
    }
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/api/v1/snapshot')) return new Promise(() => {})
      if (url.endsWith('/api/v1/capabilities')) {
        return Promise.resolve({ ok: true, status: 200, json: async () => report } as Response)
      }
      return Promise.reject(new Error(`unexpected request: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: '系统闭环' }))
    expect(await screen.findByText('生产写入保持关闭')).toBeInTheDocument()
    expect(screen.getByText('Mihomo 设备读回')).toBeInTheDocument()
    // This wire enum reports adapter configuration, never production health.
    expect(screen.getAllByText('只读接入已配置').length).toBeGreaterThan(0)
    expect(screen.queryByText('生产只读')).not.toBeInTheDocument()
    expect(screen.getByText('自动修复')).toBeInTheDocument()
    expect(screen.getAllByText('仅设计').length).toBeGreaterThan(0)
    expect(screen.getByText('GET /api/v1/kernels/mihomo/status')).toBeInTheDocument()
    expect(screen.getByText('尚未实现生产执行器')).toBeInTheDocument()
    expect(screen.queryByText(/%/)).not.toBeInTheDocument()
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
  })

  it('marks capability status as unverified when the registry API fails', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/api/v1/snapshot')) return new Promise(() => {})
      if (url.endsWith('/api/v1/capabilities')) return Promise.reject(new Error('offline'))
      return Promise.reject(new Error(`unexpected request: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)
    render(<App />)
    fireEvent.click(screen.getByRole('button', { name: '系统闭环' }))
    expect(await screen.findByText('未能核验系统闭环状态')).toBeInTheDocument()
    expect(screen.getByText(/页面不会沿用旧结果/)).toBeInTheDocument()
    expect(screen.queryByText('生产写入保持关闭')).not.toBeInTheDocument()
  })
})
