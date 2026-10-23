// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://127.0.0.1:17861/"}
// SYNTHETIC COMPONENT TESTS ONLY: no real browser, server, TLS or node-health proof.
import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Subscriptions } from './Subscriptions'
import * as api from './subscription-api'
import type { SubscriptionReceipt } from './subscription-types'
import { subscriptionAccess, subscriptionCandidatePage, subscriptionCommandId, subscriptionNodePage,
  subscriptionReceipt, subscriptionSourcePage } from './subscription-test-fixtures'

vi.mock('./subscription-api', async importOriginal => {
  const actual = await importOriginal<typeof import('./subscription-api')>()
  return { ...actual, readSubscriptionAccess: vi.fn(), readSubscriptionSources: vi.fn(),
    readSubscriptionCandidates: vi.fn(), readSubscriptionNodes: vi.fn(),
    readSubscriptionReceipt: vi.fn(), writeSubscriptionCommand: vi.fn() }
})
const readAccess = vi.mocked(api.readSubscriptionAccess), readSources = vi.mocked(api.readSubscriptionSources)
const readCandidates = vi.mocked(api.readSubscriptionCandidates), readNodes = vi.mocked(api.readSubscriptionNodes)
const readReceipt = vi.mocked(api.readSubscriptionReceipt), write = vi.mocked(api.writeSubscriptionCommand)
const waiting = '正在等待服务端结果；尚未确认成功。'
const pendingWithId = '操作结果待核对；请读取命令回执，不要重复写入。'
const pendingWithoutId = '操作结果待核对；未取得命令 ID，请联系管理员对账，不要重复写入。'
const pendingAudit = '服务端结果或审计待确认；仅可读取命令回执，不会自动重新提交。'
const historical = '已读取历史回执，未重复执行业务动作。'
const otherId = 'cmd_' + 'a'.repeat(32)
function button(name: string) { return screen.getByRole('button', { name }) }
function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (reason: unknown) => void
  const promise = new Promise<T>((a, b) => { resolve = a; reject = b })
  return { promise, resolve, reject }
}
async function login() {
  fireEvent.change(screen.getByLabelText('订阅管理令牌'), { target: { value: 'synthetic-feedback-token' } })
  fireEvent.click(button('连接订阅会话'))
  await screen.findByRole('button', { name: /Synthetic source/ })
}
async function ready() { render(<Subscriptions/>); await login() }
function submit() {
  fireEvent.change(screen.getByLabelText('来源名称'), { target: { value: 'Feedback source' } })
  fireEvent.click(button('准备创建来源')); fireEvent.click(button('确认并提交本地操作'))
}
function getReceipt(id = subscriptionCommandId) {
  fireEvent.change(screen.getByLabelText('命令 ID'), { target: { value: id } })
  fireEvent.click(button('读取命令回执'))
}
function failedReceipt(commandId = subscriptionCommandId) {
  return subscriptionReceipt({ commandId, state: 'failed', code: 'subscription_command_conflict', localAuditHash: undefined })
}
function unknownWrite(commandId?: string) {
  write.mockRejectedValueOnce(new api.SubscriptionAPIError(503, 'unavailable', true, commandId, 'subscription_commit_unknown'))
}
async function refreshUnlocked() {
  fireEvent.click(button('刷新来源'))
  await waitFor(() => expect(button('准备创建来源')).toBeEnabled())
}
async function refreshStillLocked() {
  fireEvent.click(button('刷新来源'))
  await waitFor(() => expect(screen.getByRole('button', { name: /Synthetic source/ })).toBeEnabled())
  expect(button('准备创建来源')).toBeDisabled()
}

beforeEach(() => {
  vi.clearAllMocks()
  readAccess.mockReset().mockImplementation(async (_t, _s, id) => subscriptionAccess(id))
  readSources.mockReset().mockImplementation(async () => subscriptionSourcePage())
  readCandidates.mockReset().mockImplementation(async () => subscriptionCandidatePage())
  readNodes.mockReset().mockImplementation(async () => subscriptionNodePage())
  readReceipt.mockReset().mockImplementation(async () => subscriptionReceipt())
  write.mockReset().mockImplementation(async () => subscriptionReceipt())
})
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks() })

describe('SubscriptionsFeedback', () => {
  it('clears waiting after a known conflict without locking equivalent future writes', async () => {
    const slow = deferred<SubscriptionReceipt>(); write.mockReturnValueOnce(slow.promise)
    await ready(); submit(); expect(screen.getByRole('status')).toHaveTextContent(waiting)
    await act(async () => slow.reject(new api.SubscriptionAPIError(409, 'conflict', false, subscriptionCommandId, 'subscription_approval_required')))
    expect(screen.getByRole('alert')).toHaveTextContent('版本或批准已变化')
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    expect(screen.getByLabelText('命令 ID')).toHaveValue(subscriptionCommandId)
    expect(screen.queryByText(/存在未决命令/)).not.toBeInTheDocument()
    await refreshUnlocked(); expect(write).toHaveBeenCalledTimes(1); expect(readReceipt).not.toHaveBeenCalled()
  })
  it('clears waiting after a known closed write gate without retrying', async () => {
    write.mockRejectedValueOnce(new api.SubscriptionAPIError(423, 'locked', false, undefined, 'subscription_writes_disabled'))
    await ready(); submit(); await screen.findByText(/服务端订阅写入门已关闭/)
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    expect(screen.queryByText(/存在未决命令/)).not.toBeInTheDocument(); expect(write).toHaveBeenCalledTimes(1)
  })
  it('clears waiting after a known forbidden response without claiming success', async () => {
    write.mockRejectedValueOnce(new api.SubscriptionAPIError(403, 'forbidden', false, undefined, 'subscription_forbidden'))
    await ready(); submit(); await screen.findByText(/请联系权限管理员/)
    expect(screen.queryByRole('status')).not.toBeInTheDocument(); expect(write).toHaveBeenCalledTimes(1)
    expect(screen.queryByText(/本地已提交；仅本地准入/)).not.toBeInTheDocument()
  })
  it('clears waiting after a validated unavailable response without inventing a command', async () => {
    write.mockRejectedValueOnce(new api.SubscriptionAPIError(503, 'unavailable', false, undefined, 'subscription_unavailable'))
    await ready(); submit(); await screen.findByText(/服务暂不可用/)
    expect(screen.queryByRole('status')).not.toBeInTheDocument(); expect(screen.getByLabelText('命令 ID')).toHaveValue('')
    expect(screen.queryByText(/存在未决命令/)).not.toBeInTheDocument(); await refreshUnlocked()
    expect(write).toHaveBeenCalledTimes(1)
  })
  it('replaces waiting with reconciliation guidance for an unknown write with a handle', async () => {
    unknownWrite(subscriptionCommandId); await ready(); submit()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingWithId))
    expect(screen.getByLabelText('命令 ID')).toHaveValue(subscriptionCommandId)
    expect(button('准备创建来源')).toBeDisabled(); expect(screen.getByText(/存在未决命令/)).toBeInTheDocument()
    await refreshStillLocked()
    expect(write).toHaveBeenCalledTimes(1); expect(readReceipt).not.toHaveBeenCalled()
  })
  it('requires administrator reconciliation when an unknown write has no handle', async () => {
    unknownWrite(); await ready(); submit()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingWithoutId))
    expect(screen.getByLabelText('命令 ID')).toHaveValue(''); expect(button('准备创建来源')).toBeDisabled()
    await refreshStillLocked()
    expect(write).toHaveBeenCalledTimes(1); expect(readReceipt).not.toHaveBeenCalled()
  })
  it('treats an unreadable HTTP response after POST as unresolved rather than still waiting', async () => {
    write.mockRejectedValueOnce(new api.SubscriptionAPIError(502, 'format', true, subscriptionCommandId))
    await ready(); submit(); await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingWithId))
    expect(screen.getByRole('alert')).toHaveTextContent('服务端可能已执行操作')
    expect(button('准备创建来源')).toBeDisabled(); expect(write).toHaveBeenCalledTimes(1)
  })
  it('does not expose raw exceptions while replacing waiting for an unclassified write failure', async () => {
    write.mockRejectedValueOnce(new Error('private-feedback-canary'))
    await ready(); submit(); await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingWithoutId))
    expect(document.body.textContent).not.toContain('private-feedback-canary')
    expect(button('准备创建来源')).toBeDisabled(); expect(write).toHaveBeenCalledTimes(1)
  })
  it('keeps audit-degraded writes unresolved even when the changed flag is false', async () => {
    write.mockRejectedValueOnce(new api.SubscriptionAPIError(503, 'unavailable', false, subscriptionCommandId, 'subscription_audit_degraded'))
    await ready(); submit(); await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingWithId))
    expect(screen.getByRole('alert')).toHaveTextContent('审计确认降级')
    expect(button('准备创建来源')).toBeDisabled(); expect(write).toHaveBeenCalledTimes(1)
  })
  it('replaces waiting for a pending write receipt without releasing its unresolved lock', async () => {
    write.mockResolvedValueOnce(subscriptionReceipt({ state: 'unknown', stateMayHaveChanged: true, auditRecorded: false, code: 'subscription_commit_unknown' }))
    await ready(); submit(); await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingAudit))
    expect(screen.getByRole('alert')).toHaveTextContent(pendingAudit)
    expect(button('准备创建来源')).toBeDisabled(); expect(write).toHaveBeenCalledTimes(1)
    expect(readReceipt).not.toHaveBeenCalled()
  })
  it('requires reconciliation when a terminal-looking write receipt lacks audit confirmation', async () => {
    write.mockResolvedValueOnce(subscriptionReceipt({ auditRecorded: false }))
    await ready(); submit(); await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingAudit))
    expect(button('准备创建来源')).toBeDisabled(); expect(screen.getByText(/存在未决命令/)).toBeInTheDocument()
    expect(write).toHaveBeenCalledTimes(1)
  })
  it('replaces waiting on write timeout and ignores a late successful response', async () => {
    const slow = deferred<SubscriptionReceipt>(); write.mockReturnValueOnce(slow.promise)
    await ready(); vi.useFakeTimers(); submit()
    const signal = write.mock.calls[0][1]
    await act(async () => { await vi.advanceTimersByTimeAsync(35_000) })
    expect(signal.aborted).toBe(true); expect(screen.getByRole('status')).toHaveTextContent(pendingWithoutId)
    expect(screen.getByRole('alert')).toHaveTextContent('等待结果超时')
    await act(async () => slow.resolve(subscriptionReceipt()))
    expect(screen.getByRole('status')).toHaveTextContent(pendingWithoutId)
    expect(button('准备创建来源')).toBeDisabled(); expect(readSources).toHaveBeenCalledTimes(1)
    expect(write).toHaveBeenCalledTimes(1); expect(readReceipt).not.toHaveBeenCalled()
  })
  it('restores historical notice when the matching failed receipt resolves an unknown write', async () => {
    unknownWrite(subscriptionCommandId); await ready(); submit()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingWithId))
    readReceipt.mockResolvedValueOnce(failedReceipt()); getReceipt()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(historical))
    expect(screen.getByText('操作已失败')).toBeInTheDocument(); expect(screen.queryByText(/存在未决命令/)).not.toBeInTheDocument()
    await refreshUnlocked(); expect(write).toHaveBeenCalledTimes(1); expect(readReceipt).toHaveBeenCalledTimes(1)
  })
  it('keeps another known unresolved handle locked after reading an unrelated historical receipt', async () => {
    unknownWrite(subscriptionCommandId); await ready(); submit()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingWithId))
    readReceipt.mockResolvedValueOnce(failedReceipt(otherId)); getReceipt(otherId)
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('其他未决结果仍待核对；写入暂停。'))
    expect(screen.getByText(/存在未决命令/)).toBeInTheDocument(); expect(button('准备创建来源')).toBeDisabled()
    await refreshStillLocked()
    readReceipt.mockResolvedValueOnce(failedReceipt()); getReceipt()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(historical))
    expect(screen.getByRole('status')).not.toHaveTextContent('其他未决结果'); expect(write).toHaveBeenCalledTimes(1)
  })
  it('does not resolve a no-handle write by reading an arbitrary terminal receipt', async () => {
    unknownWrite(); await ready(); submit()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingWithoutId))
    readReceipt.mockResolvedValueOnce(failedReceipt()); getReceipt()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('其他未决结果仍待核对；写入暂停。'))
    expect(screen.getByText(/存在未决命令/)).toBeInTheDocument(); expect(button('准备创建来源')).toBeDisabled()
    await refreshStillLocked()
    expect(write).toHaveBeenCalledTimes(1)
  })
  it('preserves reconciliation guidance for a still-pending receipt readback', async () => {
    unknownWrite(subscriptionCommandId); await ready(); submit()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingWithId))
    readReceipt.mockResolvedValueOnce(subscriptionReceipt({ state: 'prepared', stateMayHaveChanged: true, code: 'subscription_commit_unknown' })); getReceipt()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('回执仍未确认；请勿重复写入。'))
    expect(button('准备创建来源')).toBeDisabled(); expect(write).toHaveBeenCalledTimes(1)
  })
  it('preserves unresolved guidance after a forbidden receipt without changing ownership', async () => {
    unknownWrite(subscriptionCommandId); await ready(); submit()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingWithId))
    readReceipt.mockRejectedValueOnce(new api.SubscriptionAPIError(403, 'forbidden', false, undefined, 'subscription_forbidden')); getReceipt(otherId)
    await screen.findByText(/请联系权限管理员/)
    expect(screen.getByRole('status')).toHaveTextContent(pendingWithId); expect(screen.getByLabelText('命令 ID')).toHaveValue(otherId)
    expect(button('准备创建来源')).toBeDisabled(); expect(write).toHaveBeenCalledTimes(1)
  })
  it('clears a historical success notice after a forbidden read while retaining the prior receipt', async () => {
    await ready(); getReceipt(); await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(historical))
    readReceipt.mockRejectedValueOnce(new api.SubscriptionAPIError(403, 'forbidden', false, undefined, 'subscription_forbidden'))
    getReceipt(otherId); await screen.findByText(/请联系权限管理员/)
    expect(screen.queryByRole('status')).not.toBeInTheDocument(); expect(screen.getByText('本地已提交')).toBeInTheDocument()
    expect(screen.getByLabelText('命令 ID')).toHaveValue(otherId); expect(screen.getByText(subscriptionCommandId)).toBeInTheDocument()
    expect(button('准备创建来源')).toBeEnabled(); expect(write).not.toHaveBeenCalled()
  })
  it('does not replace an active write waiting notice with a historical read success', async () => {
    const slow = deferred<SubscriptionReceipt>(); write.mockReturnValueOnce(slow.promise)
    await ready(); submit(); readReceipt.mockResolvedValueOnce(subscriptionReceipt({ commandId: otherId }))
    getReceipt(otherId); await waitFor(() => expect(screen.getByText('本地已提交')).toBeInTheDocument())
    expect(screen.getByRole('status')).toHaveTextContent(waiting); expect(button('准备创建来源')).toBeDisabled()
    await act(async () => slow.reject(new api.SubscriptionAPIError(409, 'conflict', false, undefined, 'subscription_command_conflict')))
    expect(screen.queryByRole('status')).not.toBeInTheDocument(); expect(write).toHaveBeenCalledTimes(1)
  })
  it('keeps active write waiting feedback when a concurrent receipt read is forbidden', async () => {
    const slow = deferred<SubscriptionReceipt>(); write.mockReturnValueOnce(slow.promise)
    await ready(); submit()
    readReceipt.mockRejectedValueOnce(new api.SubscriptionAPIError(403, 'forbidden', false, undefined, 'subscription_forbidden'))
    getReceipt(otherId); await screen.findByText(/请联系权限管理员/)
    expect(screen.getByRole('status')).toHaveTextContent(waiting); expect(button('准备创建来源')).toBeDisabled()
    await act(async () => slow.resolve(subscriptionReceipt()))
    expect(screen.getByRole('status')).toHaveTextContent('本地已提交；仅本地准入')
    expect(write).toHaveBeenCalledTimes(1)
  })
  it('keeps unresolved notice after receipt timeout and ignores its late terminal result', async () => {
    unknownWrite(subscriptionCommandId); await ready(); submit()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingWithId))
    const slow = deferred<SubscriptionReceipt>(); readReceipt.mockReturnValueOnce(slow.promise)
    vi.useFakeTimers(); getReceipt(); const signal = readReceipt.mock.calls[0][1]
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })
    expect(signal.aborted).toBe(true); expect(screen.getByRole('status')).toHaveTextContent(pendingWithId)
    expect(screen.getByRole('alert')).toHaveTextContent('回执读取超时')
    await act(async () => slow.resolve(failedReceipt()))
    expect(screen.getByRole('status')).toHaveTextContent(pendingWithId); expect(button('准备创建来源')).toBeDisabled()
    expect(write).toHaveBeenCalledTimes(1)
  })
  it('clears waiting on authentication failure while removing the expired session', async () => {
    write.mockRejectedValueOnce(new api.SubscriptionAPIError(401, 'authentication', false, undefined, 'subscription_forbidden'))
    await ready(); submit(); await screen.findByText(/身份验证失败/)
    expect(screen.queryByRole('status')).not.toBeInTheDocument(); expect(screen.queryByText('Synthetic source')).not.toBeInTheDocument()
    expect(button('准备创建来源')).toBeDisabled(); expect(write).toHaveBeenCalledTimes(1)
  })
  it('does not restore waiting or success after clearing a session with an active write', async () => {
    const slow = deferred<SubscriptionReceipt>(); write.mockReturnValueOnce(slow.promise)
    await ready(); submit(); const signal = write.mock.calls[0][1]
    fireEvent.click(button('清除会话与令牌'))
    expect(signal.aborted).toBe(true); expect(screen.getByRole('status')).toHaveTextContent('本地会话与令牌已清除')
    await act(async () => slow.resolve(subscriptionReceipt()))
    expect(screen.getByRole('status')).toHaveTextContent('本地会话与令牌已清除')
    expect(screen.getByRole('status')).not.toHaveTextContent(waiting); expect(screen.queryByText('审计已确认')).not.toBeInTheDocument()
    expect(readSources).toHaveBeenCalledTimes(1); expect(write).toHaveBeenCalledTimes(1)
  })
  it('ignores an old write rejection after reconnecting a new session', async () => {
    const slow = deferred<SubscriptionReceipt>(); write.mockReturnValueOnce(slow.promise)
    await ready(); submit(); await login()
    expect(screen.getByRole('status')).toHaveTextContent('令牌仅在本次内存会话中使用。')
    await act(async () => slow.reject(new Error('late-private-canary')))
    expect(screen.getByRole('status')).toHaveTextContent('令牌仅在本次内存会话中使用。')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument(); expect(document.body.textContent).not.toContain('late-private-canary')
    expect(button('准备创建来源')).toBeEnabled(); expect(write).toHaveBeenCalledTimes(1)
  })
  it('ignores an obsolete receipt callback after the command input changes', async () => {
    unknownWrite(subscriptionCommandId); await ready(); submit()
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(pendingWithId))
    const slow = deferred<SubscriptionReceipt>(); readReceipt.mockReturnValueOnce(slow.promise); getReceipt()
    const signal = readReceipt.mock.calls[0][1]
    fireEvent.change(screen.getByLabelText('命令 ID'), { target: { value: otherId } })
    await act(async () => slow.resolve(failedReceipt()))
    expect(signal.aborted).toBe(true); expect(screen.getByLabelText('命令 ID')).toHaveValue(otherId)
    expect(screen.getByRole('status')).toHaveTextContent(pendingWithId); expect(button('准备创建来源')).toBeDisabled()
    expect(write).toHaveBeenCalledTimes(1)
  })
})
