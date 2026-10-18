// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { OperationCenter } from './OperationCenter'
import type { OperationEnvelope, OperationStatus, OperationSummary } from './types'

function response(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve({ ok: status >= 200 && status < 300, status, json: async () => body } as Response)
}

function envelope(overrides: Partial<OperationEnvelope> = {}): OperationEnvelope {
  return { effect: 'local_record_only', deviceActionsExecuted: false, ...overrides }
}

function operation(status: OperationStatus, risk: OperationSummary['risk'] = 'low'): OperationSummary {
  return {
    id: 'op-verified-001', identityBinding: 'durable', environment: 'shadow', scope: 'sha256:opaque',
    targetVersion: 'config-v2', risk, status, createdAt: '2026-10-18T08:00:00Z', updatedAt: '2026-10-18T08:01:00Z',
  }
}

function enterScopeAndToken(token = 'primary-secret') {
  fireEvent.change(screen.getByLabelText('Bearer 令牌'), { target: { value: token } })
  fireEvent.change(screen.getByLabelText('tenant'), { target: { value: 'tenant-a' } })
  fireEvent.change(screen.getByLabelText('site'), { target: { value: 'site-a' } })
  fireEvent.change(screen.getByLabelText('objectType'), { target: { value: 'router' } })
  fireEvent.change(screen.getByLabelText('objectId'), { target: { value: 'router-a' } })
}

beforeEach(() => {
  let sequence = 0
  vi.stubGlobal('crypto', { randomUUID: vi.fn(() => `00000000-0000-4000-8000-${String(++sequence).padStart(12, '0')}`) })
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('OperationCenter safety boundaries', () => {
  it('keeps tokens in component memory only and renders no fabricated operations', async () => {
    const storageWrite = vi.spyOn(Storage.prototype, 'setItem')
    const fetchMock = vi.fn((input: RequestInfo | URL, options?: RequestInit) => {
      void input
      void options
      return response(envelope({ operations: [] }))
    })
    vi.stubGlobal('fetch', fetchMock)
    render(<OperationCenter />)

    expect(screen.getByText('尚未读取操作记录')).toBeInTheDocument()
    expect(screen.queryByText('config-v2')).not.toBeInTheDocument()
    enterScopeAndToken('memory-only-secret')
    fireEvent.click(screen.getByRole('button', { name: '读取操作' }))

    expect(await screen.findByText('当前范围没有操作记录')).toBeInTheDocument()
    expect(storageWrite).not.toHaveBeenCalled()
    expect(window.localStorage.getItem('memory-only-secret')).toBeNull()
    expect(window.sessionStorage.getItem('memory-only-secret')).toBeNull()
    const [, options] = fetchMock.mock.calls[0]
    expect(String(fetchMock.mock.calls[0][0])).not.toContain('memory-only-secret')
    expect((options as RequestInit).headers).toMatchObject({ Authorization: 'Bearer memory-only-secret' })

    fireEvent.click(screen.getByRole('button', { name: '清除令牌与列表' }))
    expect(screen.getByLabelText('Bearer 令牌')).toHaveValue('')
    expect(screen.getByText('尚未读取操作记录')).toBeInTheDocument()
  })

  it('expresses an unconfigured operation plane as the exact 503 boundary', async () => {
    vi.stubGlobal('fetch', vi.fn(() => response({
      effect: 'local_record_only', code: 'operation_control_not_configured', message: '本地操作控制面尚未配置',
    }, 503)))
    render(<OperationCenter />)
    enterScopeAndToken()
    fireEvent.click(screen.getByRole('button', { name: '读取操作' }))
    expect(await screen.findByText('HTTP 503 · operation_control_not_configured · 本地操作控制面尚未配置')).toBeInTheDocument()
    expect(screen.queryByText('当前范围没有操作记录')).not.toBeInTheDocument()
  })

  it('expresses the write gate as HTTP 423 and does not claim a created plan', async () => {
    vi.stubGlobal('fetch', vi.fn(() => response({
      effect: 'local_record_only', code: 'operation_writes_disabled', message: '本地操作写入开关未启用',
    }, 423)))
    render(<OperationCenter />)
    enterScopeAndToken()
    fireEvent.change(screen.getByLabelText('目标版本'), { target: { value: 'config-v2' } })
    fireEvent.click(screen.getByRole('button', { name: '创建影子计划' }))
    expect(await screen.findByText('HTTP 423 · operation_writes_disabled · 本地操作写入开关未启用')).toBeInTheDocument()
    expect(screen.queryByText(/本地影子计划已记录/)).not.toBeInTheDocument()
  })

  it('shows a scope authorization denial without retaining an old list', async () => {
    vi.stubGlobal('fetch', vi.fn(() => response({ effect: 'local_record_only', code: 'forbidden', message: '无权读取该范围的操作' }, 403)))
    render(<OperationCenter />)
    enterScopeAndToken()
    fireEvent.click(screen.getByRole('button', { name: '读取操作' }))
    expect(await screen.findByText('HTTP 403 · forbidden · 无权读取该范围的操作')).toBeInTheDocument()
    expect(screen.getByText('尚未读取操作记录')).toBeInTheDocument()
  })

  it('handles an idempotent create response and confirms it only by GET readback', async () => {
    const stored = operation('planned')
    const fetchMock = vi.fn((input: RequestInfo | URL, options?: RequestInit) => {
      if (String(input) === '/api/v1/operations' && options?.method === 'POST') {
        return response(envelope({ operation: stored, created: false, auditRecorded: true, outcome: 'planned' }))
      }
      return response(envelope({ operations: [stored] }))
    })
    vi.stubGlobal('fetch', fetchMock)
    render(<OperationCenter />)
    enterScopeAndToken()
    fireEvent.change(screen.getByLabelText('目标版本'), { target: { value: 'config-v2' } })
    fireEvent.click(screen.getByRole('button', { name: '创建影子计划' }))

    expect(await screen.findByText('幂等响应：服务器复用了已有本地计划；已重新读回列表。')).toBeInTheDocument()
    expect(screen.getByText('config-v2')).toBeInTheDocument()
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    const postOptions = fetchMock.mock.calls[0][1] as RequestInit
    expect(postOptions.headers).toMatchObject({
      Authorization: 'Bearer primary-secret',
      'Idempotency-Key': expect.stringMatching(/^chengwang-ui-create-/),
    })
    expect(String(postOptions.body)).not.toContain('primary-secret')
  })

  it('uses an independent approver token for a high-risk approval transition', async () => {
    const awaiting = operation('awaiting_approval', 'high')
    const approved = operation('prechecking', 'high')
    let listCount = 0
    const fetchMock = vi.fn((input: RequestInfo | URL, options?: RequestInit) => {
      if (String(input).includes('/transitions')) {
        expect((options?.headers as Record<string, string>).Authorization).toBe('Bearer independent-approver')
        return response(envelope({ operation: approved, applied: true, auditRecorded: true, outcome: 'transitioned' }))
      }
      listCount += 1
      return response(envelope({ operations: [listCount === 1 ? awaiting : approved] }))
    })
    vi.stubGlobal('fetch', fetchMock)
    render(<OperationCenter />)
    enterScopeAndToken('initiator-token')
    fireEvent.click(screen.getByRole('button', { name: '读取操作' }))
    expect(await screen.findByText('等待独立审批')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('独立审批人令牌 op-verified-001'), { target: { value: 'independent-approver' } })
    fireEvent.click(screen.getByRole('button', { name: '审批并进入预检' }))

    expect(await screen.findByText('预检中')).toBeInTheDocument()
    expect(screen.getByText(/未执行任何设备动作/)).toBeInTheDocument()
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
    expect((fetchMock.mock.calls[2][1] as RequestInit).headers).toMatchObject({ Authorization: 'Bearer initiator-token' })
  })

  it('only offers the safe planned-to-approval transition for high-risk records', async () => {
    const planned = operation('planned', 'high')
    const awaiting = operation('awaiting_approval', 'high')
    let listCount = 0
    const fetchMock = vi.fn((input: RequestInfo | URL, options?: RequestInit) => {
      if (String(input).includes('/transitions') && options?.method === 'POST') {
        expect(JSON.parse(String(options.body))).toMatchObject({ to: 'awaiting_approval' })
        return response(envelope({ operation: awaiting, applied: true, auditRecorded: true, outcome: 'transitioned' }))
      }
      listCount += 1
      return response(envelope({ operations: [listCount === 1 ? planned : awaiting] }))
    })
    vi.stubGlobal('fetch', fetchMock)
    render(<OperationCenter />)
    enterScopeAndToken()
    fireEvent.click(screen.getByRole('button', { name: '读取操作' }))
    expect(await screen.findByRole('button', { name: '申请独立审批' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /执行/ })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '申请独立审批' }))
    expect(await screen.findByText('等待独立审批')).toBeInTheDocument()
    expect(screen.getByLabelText('独立审批人令牌 op-verified-001')).toBeInTheDocument()
  })

  it('keeps the last read state when commit outcome is unknown and automatically reads back', async () => {
    const planned = operation('planned', 'low')
    let getCount = 0
    const fetchMock = vi.fn((input: RequestInfo | URL, options?: RequestInit) => {
      if (String(input).includes('/transitions') && options?.method === 'POST') {
        return response({ effect: 'local_record_only', code: 'commit_unknown', message: '本地持久化结果未知，必须读回后重试' }, 503)
      }
      getCount += 1
      return response(envelope({ operations: [planned] }))
    })
    vi.stubGlobal('fetch', fetchMock)
    render(<OperationCenter />)
    enterScopeAndToken()
    fireEvent.click(screen.getByRole('button', { name: '读取操作' }))
    expect(await screen.findByText('已计划')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '进入预检' }))

    expect(await screen.findByText('HTTP 503 · commit_unknown · 本地持久化结果未知，必须读回后重试')).toBeInTheDocument()
    expect(screen.getByText('已计划')).toBeInTheDocument()
    expect(screen.queryByText('预检中')).not.toBeInTheDocument()
    expect(screen.getByText(/未把响应当成成功/)).toBeInTheDocument()
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
    expect(getCount).toBe(2)
  })
})
