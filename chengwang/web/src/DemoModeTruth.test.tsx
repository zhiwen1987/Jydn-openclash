// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://console.example"}
import '@testing-library/jest-dom/vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'

function supplySnapshot(mode: string, publishLocked: boolean) {
  const snapshot = { product: 'Synthetic mode metadata', version: 'synthetic', mode,
    status: 'Synthetic mode source', dataSource: 'demo', publishLocked,
    businesses: null, pools: null, interfaces: null, events: null,
    draft: { name: 'Synthetic draft', baseVersion: '', businesses: null, pools: null,
      dns: { domesticResolvers: null, overseasResolvers: null, hijackPort53: false, leakProtection: false } } }
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => snapshot } as unknown as Response))
}

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('DemoModeTruth', () => {
  it('shows the actual candidate mode without claiming global shadow execution', async () => {
    supplySnapshot('candidate', false)
    render(<App />)
    await screen.findByText('Synthetic mode metadata')
    const overview = within(screen.getByRole('main'))
    expect(overview.getByText('candidate')).toBeInTheDocument()
    expect(overview.getByText('总览只读')).toBeInTheDocument()
    expect(overview.getByText('总览仅展示数据边界；执行权限以服务端授权为准')).toBeInTheDocument()
    expect(screen.queryByText('Shadow')).not.toBeInTheDocument()
    expect(screen.queryByText('影子模式下只观察，不改变现网')).not.toBeInTheDocument()
    expect(overview.getByRole('button', { name: '刷新' })).toBeDisabled()
  })

  it('preserves an open control-plane mode while limiting read-only claims to this overview', async () => {
    supplySnapshot('governed-enterprise', true)
    render(<App />)
    await screen.findByText('Synthetic mode metadata')
    const overview = within(screen.getByRole('main'))
    expect(overview.getByText('governed-enterprise')).toBeInTheDocument()
    expect(overview.getByText('总览只读')).toBeInTheDocument()
    expect(overview.getByText('当前总览没有接入真实运行数据')).toBeInTheDocument()
    expect(overview.queryByText('只读')).not.toBeInTheDocument()
    expect(overview.queryByText('全系统只读')).not.toBeInTheDocument()
    expect(overview.queryByText('已接管生产')).not.toBeInTheDocument()
  })
})
