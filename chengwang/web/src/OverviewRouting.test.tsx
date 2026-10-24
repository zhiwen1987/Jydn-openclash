// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://console.example"}
// Synthetic component integration only; not actual HTTP or browser evidence.
import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { getSnapshot } from './api'
import { getOverview, OverviewReadError } from './overview-api'
import { overviewFixture } from './overview-test-fixture'
import type { Snapshot } from './types'

vi.mock('./api', async importOriginal => {
  const actual = await importOriginal<typeof import('./api')>()
  return { ...actual, getSnapshot: vi.fn() }
})
vi.mock('./overview-api', async importOriginal => {
  const actual = await importOriginal<typeof import('./overview-api')>()
  return { ...actual, getOverview: vi.fn() }
})
const snapshotRead = vi.mocked(getSnapshot), actualRead = vi.mocked(getOverview)
const version = () => document.querySelector('.topbar .version')!
function demo(): Snapshot {
  return { product: 'Synthetic overview shell', version: 'not released', mode: 'candidate', status: 'Synthetic source only', dataSource: 'demo', publishLocked: true,
    businesses: [], pools: [], interfaces: [], events: [], draft: { name: 'Synthetic editor draft', baseVersion: '', businesses: [], pools: [], dns: {} } }
}
function deferred() {
  let resolve!: (value: ReturnType<typeof overviewFixture>) => void
  const promise = new Promise<ReturnType<typeof overviewFixture>>(accept => { resolve = accept })
  return { promise, resolve }
}
afterEach(() => { cleanup(); snapshotRead.mockReset(); actualRead.mockReset() })

describe('OverviewRouting', () => {
  it('keeps the original demo default and makes no actual overview request before explicit selection', async () => {
    snapshotRead.mockResolvedValue(demo())
    render(<App />)
    await screen.findByText('Synthetic overview shell')
    expect(screen.getByRole('button', { name: '演示总览' })).toHaveAttribute('aria-pressed', 'true')
    expect(actualRead).not.toHaveBeenCalled()
    expect(version()).toHaveTextContent('演示草稿')
    expect(version()).toHaveTextContent('candidate')
  })
  it('uses only validated actual view metadata in the top bar after explicit selection', async () => {
    snapshotRead.mockResolvedValue(demo()); actualRead.mockResolvedValue(overviewFixture())
    render(<App />); await screen.findByText('Synthetic overview shell')
    fireEvent.click(screen.getByRole('button', { name: '实际证据' }))
    await waitFor(() => expect(version()).toHaveTextContent('实际证据汇总'))
    expect(version()).toHaveTextContent('lab.prod')
    expect(version()).not.toHaveTextContent('演示草稿')
    expect(actualRead).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('heading', { name: '实际证据总览' })).toBeInTheDocument()
  })
  it('keeps actual evidence reachable when the legacy snapshot request fails', async () => {
    snapshotRead.mockRejectedValue(new Error('synthetic failure')); actualRead.mockResolvedValue(overviewFixture())
    render(<App />)
    await screen.findByText('演示模式：无法读取本地控制面')
    fireEvent.click(screen.getByRole('button', { name: '实际证据' }))
    await waitFor(() => expect(version()).toHaveTextContent('lab.prod'))
    expect(actualRead).toHaveBeenCalledTimes(1)
  })
  it('withdraws prior actual metadata when a refresh fails and does not switch to demo', async () => {
    snapshotRead.mockResolvedValue(demo())
    actualRead.mockResolvedValueOnce(overviewFixture()).mockRejectedValueOnce(new OverviewReadError('format'))
    render(<App />); await screen.findByText('Synthetic overview shell')
    fireEvent.click(screen.getByRole('button', { name: '实际证据' }))
    await waitFor(() => expect(version()).toHaveTextContent('lab.prod'))
    fireEvent.click(screen.getByRole('button', { name: '重新读取实际证据' }))
    await screen.findByRole('alert')
    expect(version()).toHaveTextContent('实际证据 · 未核验')
    expect(version()).not.toHaveTextContent('lab.prod')
    expect(version()).not.toHaveTextContent('演示草稿')
    expect(screen.getByRole('button', { name: '实际证据' })).toHaveAttribute('aria-pressed', 'true')
  })
  it('clears old actual mode before the next request when navigating away and back', async () => {
    const next = deferred()
    snapshotRead.mockResolvedValue(demo()); actualRead.mockResolvedValueOnce(overviewFixture()).mockReturnValueOnce(next.promise)
    render(<App />); await screen.findByText('Synthetic overview shell')
    fireEvent.click(screen.getByRole('button', { name: '实际证据' }))
    await waitFor(() => expect(version()).toHaveTextContent('lab.prod'))
    fireEvent.click(screen.getByRole('button', { name: '内核与协议' }))
    fireEvent.click(screen.getByRole('button', { name: '运行总览' }))
    await waitFor(() => expect(actualRead).toHaveBeenCalledTimes(2))
    expect(version()).toHaveTextContent('实际证据 · 未核验')
    expect(version()).not.toHaveTextContent('lab.prod')
    const latest = overviewFixture(); latest.mode = 'new.mode'
    await act(async () => { next.resolve(latest) })
    await waitFor(() => expect(version()).toHaveTextContent('new.mode'))
  })
  it('ignores late actual completion after selecting demo and preserves the editor snapshot mode', async () => {
    const pending = deferred()
    snapshotRead.mockResolvedValue(demo()); actualRead.mockReturnValue(pending.promise)
    render(<App />); await screen.findByText('Synthetic overview shell')
    fireEvent.click(screen.getByRole('button', { name: '实际证据' }))
    await waitFor(() => expect(actualRead).toHaveBeenCalledTimes(1))
    fireEvent.click(screen.getByRole('button', { name: '演示总览' }))
    await act(async () => { pending.resolve(overviewFixture()) })
    expect(version()).toHaveTextContent('演示草稿')
    expect(version()).toHaveTextContent('candidate')
    expect(version()).not.toHaveTextContent('lab.prod')
    expect(screen.queryByRole('heading', { name: '实际证据总览' })).not.toBeInTheDocument()
  })
})
