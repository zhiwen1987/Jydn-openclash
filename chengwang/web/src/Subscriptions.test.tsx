// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://127.0.0.1:17861/"}
// SYNTHETIC COMPONENT TESTS ONLY: no real browser, server, TLS or node-health proof.
import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Subscriptions } from './Subscriptions'
import * as api from './subscription-api'
import type { SubscriptionCandidatePage, SubscriptionIntent, SubscriptionSourcePage } from './subscription-types'
import { subscriptionAccess, subscriptionCandidateId, subscriptionCandidatePage, subscriptionCommandId,
  subscriptionNodePage, subscriptionReceipt, subscriptionSourceId, subscriptionSourcePage } from './subscription-test-fixtures'

vi.mock('./subscription-api', async importOriginal => {
  const actual = await importOriginal<typeof import('./subscription-api')>()
  return { ...actual, createSubscriptionIntent: vi.fn(actual.createSubscriptionIntent), releaseSubscriptionIntent: vi.fn(actual.releaseSubscriptionIntent),
    readSubscriptionAccess: vi.fn(), readSubscriptionSources: vi.fn(), readSubscriptionCandidates: vi.fn(),
    readSubscriptionNodes: vi.fn(), readSubscriptionReceipt: vi.fn(), writeSubscriptionCommand: vi.fn() }
})
const readAccess = vi.mocked(api.readSubscriptionAccess), readSources = vi.mocked(api.readSubscriptionSources)
const readCandidates = vi.mocked(api.readSubscriptionCandidates), readNodes = vi.mocked(api.readSubscriptionNodes)
const readReceipt = vi.mocked(api.readSubscriptionReceipt), write = vi.mocked(api.writeSubscriptionCommand)
const token = 'synthetic-private-token'
const secondId = 'src_' + 'a'.repeat(32)
function deferred<T>() { let resolve!: (value: T) => void; let reject!: (reason: unknown) => void; const promise = new Promise<T>((a, b) => { resolve = a; reject = b }); return { promise, resolve, reject } }
function button(name: string) { return screen.getByRole('button', { name }) }
function setup() { return render(<Subscriptions/>) }
async function login() {
  fireEvent.change(screen.getByLabelText('订阅管理令牌'), { target: { value: token } })
  fireEvent.click(button('连接订阅会话'))
  await screen.findByRole('button', { name: /Synthetic source/ })
}
async function select() {
  fireEvent.click(screen.getByRole('button', { name: /Synthetic source/ }))
  await waitFor(() => expect(button('准备导入候选')).toBeEnabled())
}
async function ready() { setup(); await login(); await select() }
async function chooseCandidate(name = /本地已接纳 · 2 个节点/) {
  fireEvent.click(screen.getByRole('button', { name }))
  await screen.findByText('节点-55555555')
}
function mockUndecidedCandidate(baseRevision = 3) {
  const sources = subscriptionSourcePage(); delete sources.sources[0].acceptedCandidateId
  const page = subscriptionCandidatePage(); page.candidates[0] = { ...page.candidates[0], state: 'quarantined', baseRevision }
  readSources.mockResolvedValue(sources); readCandidates.mockResolvedValue(page)
}
function prepareCreate() { fireEvent.change(screen.getByLabelText('来源名称'), { target: { value: 'New local source' } }); fireEvent.click(button('准备创建来源')) }
function confirm() { fireEvent.click(button('确认并提交本地操作')) }
async function importFile(text = 'synthetic-secret-subscription') {
  const raw = new TextEncoder().encode(text)
  const file = new File([raw], 'private-file.yaml', { type: 'text/plain' })
  Object.defineProperty(file, 'arrayBuffer', { value: async () => raw.slice().buffer })
  fireEvent.change(screen.getByLabelText('订阅文件'), { target: { files: [file] } })
  await screen.findByText(new RegExp(`已在内存读取 ${raw.length} 字节`))
}
beforeEach(() => {
  vi.clearAllMocks()
  readAccess.mockReset().mockImplementation(async (_t, _s, id) => subscriptionAccess(id))
  readSources.mockReset().mockImplementation(async () => subscriptionSourcePage())
  readCandidates.mockReset().mockImplementation(async () => subscriptionCandidatePage())
  readNodes.mockReset().mockImplementation(async () => subscriptionNodePage())
  readReceipt.mockReset().mockImplementation(async () => subscriptionReceipt())
  write.mockReset().mockImplementation(async (_t, _s, intent) => subscriptionReceipt({ kind: intent.kind,
    revision: intent.kind === 'create' ? 1 : intent.kind === 'approve' ? intent.expectedRevision : intent.expectedRevision + 1,
    ...(intent.kind === 'approve' ? { state: 'approved', approvalId: subscriptionCommandId, referenceId: intent.referenceId, policyRevision: intent.policyRevision } : {}),
    ...('candidateId' in intent ? { candidateId: intent.candidateId } : {}) }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks() })

describe('Subscriptions', () => {
  it('starts signed out without requests or health claims', () => {
    setup(); expect(screen.getByRole('heading', { level: 1, name: '订阅资源' })).toBeInTheDocument()
    expect(readAccess).not.toHaveBeenCalled(); expect(readSources).not.toHaveBeenCalled(); expect(write).not.toHaveBeenCalled()
    expect(screen.getByText(/没有自动调度/)).toBeInTheDocument(); expect(screen.queryByText('Synthetic source')).not.toBeInTheDocument()
  })
  it('refuses HTTP including loopback before sending token', () => {
    const original = window
    vi.stubGlobal('window', new Proxy(original, { get(target, name) { return name === 'location' ? { protocol: 'http:', origin: 'http://127.0.0.1' } : Reflect.get(target, name) } }))
    setup(); fireEvent.change(screen.getByLabelText('订阅管理令牌'), { target: { value: token } })
    expect(button('连接订阅会话')).toBeDisabled(); fireEvent.click(button('连接订阅会话'))
    expect(readAccess).not.toHaveBeenCalled(); expect(screen.getByText(/当前不是 HTTPS/)).toBeInTheDocument()
  })
  it('connects a memory token and clears the password field', async () => {
    setup(); await login(); expect(screen.getByLabelText('订阅管理令牌')).toHaveValue('')
    expect(readSources.mock.calls[0][0]).toBe(token); expect(readAccess.mock.calls[0][0]).toBe(token)
    expect(screen.getByText(/仅在本次内存会话/)).toBeInTheDocument()
  })
  it('never persists credentials or imported content', async () => {
    const stored = vi.spyOn(Storage.prototype, 'setItem'); await ready(); await importFile()
    expect(stored).not.toHaveBeenCalled(); expect(document.body.textContent).not.toContain(token)
    expect(document.body.textContent).not.toContain('synthetic-secret-subscription'); expect(document.body.textContent).not.toContain('private-file.yaml')
    expect(document.cookie).toBe(''); expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0)
  })
  it('clears the session immediately when the token is edited', async () => {
    await ready(); fireEvent.change(screen.getByLabelText('订阅管理令牌'), { target: { value: 'next-identity' } })
    expect(screen.queryByText('Synthetic source')).not.toBeInTheDocument(); expect(button('准备导入候选')).toBeDisabled()
    expect(readSources).toHaveBeenCalledTimes(1); expect(screen.getByText(/旧会话数据已清除/)).toBeInTheDocument()
  })
  it('aborts the session and ignores late signed out results', async () => {
    const slow = deferred<SubscriptionSourcePage>(); readSources.mockReturnValueOnce(slow.promise)
    setup(); fireEvent.change(screen.getByLabelText('订阅管理令牌'), { target: { value: token } }); fireEvent.click(button('连接订阅会话'))
    const signal = readSources.mock.calls[0][1]; fireEvent.click(button('清除会话与令牌')); expect(signal.aborted).toBe(true)
    await act(async () => slow.resolve(subscriptionSourcePage())); expect(screen.queryByText('Synthetic source')).not.toBeInTheDocument()
  })
  it('ignores old source results after selection changes', async () => {
    const page = subscriptionSourcePage(); page.sources.push({ ...page.sources[0], id: secondId, label: 'Second source' }); page.total = 2
    readSources.mockResolvedValue(page); const slow = deferred<SubscriptionCandidatePage>(); readCandidates.mockReturnValueOnce(slow.promise)
    setup(); await login(); fireEvent.click(screen.getByRole('button', { name: /Synthetic source/ }))
    fireEvent.click(screen.getByRole('button', { name: /Second source/ }))
    expect(readCandidates.mock.calls[0][1].aborted).toBe(true)
    await act(async () => slow.resolve(subscriptionCandidatePage()))
    expect(screen.queryByRole('button', { name: /本地已接纳 · 2 个节点/ })).not.toBeInTheDocument()
    expect(screen.getByText(/Second source · 固定来源版本/)).toBeInTheDocument()
  })
  it('loads real sources and access independently', async () => {
    setup(); await login(); expect(readSources).toHaveBeenCalledTimes(1); expect(readAccess.mock.calls[0][2]).toBeUndefined()
    await select(); expect(readAccess.mock.calls[1][2]).toBe(subscriptionSourceId)
    expect(readCandidates).toHaveBeenCalledWith(token, expect.any(AbortSignal), subscriptionSourceId, { limit: 20, offset: 0, revision: 3 })
    const foreign = subscriptionAccess(subscriptionSourceId); foreign.scope.tenantId = 'different-scope'; readAccess.mockResolvedValueOnce(subscriptionAccess()).mockResolvedValueOnce(foreign)
    fireEvent.click(button('刷新来源')); await waitFor(() => expect(screen.queryByText('Synthetic source')).not.toBeInTheDocument())
    expect(screen.queryByText('节点-55555555')).not.toBeInTheDocument()
  })
  it('refreshes sources without optimistic rows', async () => {
    setup(); await login(); const slow = deferred<SubscriptionSourcePage>(); readSources.mockReturnValueOnce(slow.promise)
    fireEvent.click(button('刷新来源')); expect(screen.getByText(/正在读取真实来源/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Synthetic source/ })).toBeDisabled(); expect(write).not.toHaveBeenCalled()
    await act(async () => slow.resolve({ sources: [], total: 0 })); expect(screen.queryByText('Synthetic source')).not.toBeInTheDocument()
  })
  it('renders empty and loading states', async () => {
    readSources.mockResolvedValue({ sources: [], total: 0 }); setup()
    fireEvent.change(screen.getByLabelText('订阅管理令牌'), { target: { value: token } }); fireEvent.click(button('连接订阅会话'))
    expect(screen.getByText(/正在读取真实来源/)).toBeInTheDocument(); await screen.findByText(/没有来源。具备权限/)
    expect(button('准备导入候选')).toBeDisabled()
  })
  it('explains disabled role and write gate actions', async () => {
    readAccess.mockImplementation(async (_t, _s, id) => ({ ...subscriptionAccess(id), writesEnabled: !id, actions: ['subscription.read'] }))
    setup(); await login(); fireEvent.click(screen.getByRole('button', { name: /Synthetic source/ })); await waitFor(() => expect(readCandidates).toHaveBeenCalled())
    expect(button('准备创建来源')).toBeDisabled(); expect(button('准备批准来源')).toBeDisabled(); expect(button('准备抓取候选')).toBeDisabled()
    expect(screen.getAllByText(/写入门已关闭/).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/没有此资源的相应操作权限/).length).toBeGreaterThan(0)
  })
  it('shows actionable authentication and authorization errors', async () => {
    readSources.mockRejectedValueOnce(new api.SubscriptionAPIError(401, 'authentication'))
    setup(); fireEvent.change(screen.getByLabelText('订阅管理令牌'), { target: { value: token } }); fireEvent.click(button('连接订阅会话'))
    await screen.findByText(/身份验证失败/); expect(button('准备创建来源')).toBeDisabled()
    readSources.mockRejectedValueOnce(new api.SubscriptionAPIError(403, 'forbidden'))
    fireEvent.change(screen.getByLabelText('订阅管理令牌'), { target: { value: token } }); fireEvent.click(button('连接订阅会话'))
    await screen.findByText(/请联系权限管理员/)
    readSources.mockRejectedValueOnce(new api.SubscriptionAPIError(0, 'transport')); fireEvent.click(button('刷新来源'))
    await screen.findByText(/不能据此认定请求未发送/); expect(screen.getByRole('alert')).not.toHaveTextContent('令牌未发送')
  })
  it('retains last known good sources as stale on read failure', async () => {
    setup(); await login(); readSources.mockRejectedValueOnce(new api.SubscriptionAPIError(503, 'unavailable'))
    fireEvent.click(button('刷新来源')); await screen.findByText(/旧数据 · 未确认当前版本/)
    expect(screen.getByRole('button', { name: /Synthetic source/ })).toBeInTheDocument(); expect(button('准备创建来源')).toBeDisabled()
  })
  it('restarts candidate paging when revision changes', async () => {
    const page = subscriptionCandidatePage(); page.nextOffset = 20; readCandidates.mockResolvedValueOnce(page)
    await ready(); readCandidates.mockRejectedValueOnce(new api.SubscriptionAPIError(409, 'conflict')); fireEvent.click(button('下一页候选'))
    await screen.findByText(/版本或批准已变化/); expect(screen.queryByText(/候选第/)).not.toBeInTheDocument()
    const sources = subscriptionSourcePage(); sources.sources[0].revision = 4; readSources.mockResolvedValue(sources)
    readCandidates.mockResolvedValue({ ...subscriptionCandidatePage(), revision: 4 }); fireEvent.click(button('刷新当前版本'))
    await screen.findByText('候选第 1 页 · 版本 4'); expect(readCandidates.mock.calls.at(-1)?.[3]).toEqual({ limit: 20, offset: 0, revision: 4 })
  })
  it('pages candidates with one pinned revision', async () => {
    const first = subscriptionCandidatePage(); first.nextOffset = 20; readCandidates.mockResolvedValueOnce(first)
    await ready(); readCandidates.mockResolvedValueOnce({ candidates: [], revision: 3, total: 21 })
    fireEvent.click(button('下一页候选')); await screen.findByText('候选第 2 页 · 版本 3')
    expect(readCandidates.mock.calls.at(-1)?.[3]).toEqual({ limit: 20, offset: 20, revision: 3 })
    expect(screen.queryByRole('button', { name: /本地已接纳 · 2 个节点/ })).not.toBeInTheDocument()
  })
  it('pages nodes with one pinned revision', async () => {
    const first = subscriptionNodePage(); first.nextOffset = 20; readNodes.mockResolvedValueOnce(first)
    await ready(); await chooseCandidate(); readNodes.mockResolvedValueOnce({ nodes: [], total: 21, revision: 3 })
    fireEvent.click(button('下一页节点')); await screen.findByText('节点第 2 页 · 版本 3')
    expect(readNodes.mock.calls.at(-1)?.[4]).toEqual({ limit: 20, offset: 20, revision: 3 }); expect(screen.queryByText('节点-55555555')).not.toBeInTheDocument()
  })
  it('never merges nodes across revisions', async () => {
    const first = subscriptionNodePage(); first.nextOffset = 20; readNodes.mockResolvedValueOnce(first)
    await ready(); await chooseCandidate(); readNodes.mockResolvedValueOnce({ ...subscriptionNodePage(), revision: 4 })
    fireEvent.click(button('下一页节点')); await screen.findByText(/版本或批准已变化/)
    expect(screen.queryByText('节点-55555555')).not.toBeInTheDocument(); expect(screen.queryByText('节点第 2 页 · 版本 4')).not.toBeInTheDocument()
  })
  it('creates a source only after explicit confirmation', async () => {
    setup(); await login(); prepareCreate(); expect(write).not.toHaveBeenCalled(); expect(screen.getByRole('alertdialog')).toHaveTextContent('创建本地来源')
    confirm(); await waitFor(() => expect(write).toHaveBeenCalledTimes(1)); expect(write.mock.calls[0][2]).toMatchObject({ kind: 'create', label: 'New local source' })
  })
  it('reads import files privately and clears inputs on submit', async () => {
    await ready(); await importFile(); fireEvent.click(button('准备导入候选'))
    expect(screen.getByLabelText('订阅文件')).toHaveValue(''); expect(screen.queryByText(/已在内存读取/)).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain('synthetic-secret-subscription'); expect(write).not.toHaveBeenCalled()
    confirm(); await waitFor(() => expect(write).toHaveBeenCalledTimes(1)); expect(write.mock.calls[0][2]).not.toHaveProperty('content')
  })
  it('imports YAML URI and base64 only by explicit choice', async () => {
    await ready()
    for (const format of ['mihomo-provider-yaml', 'uri-list', 'base64-uri-list']) {
      fireEvent.change(screen.getByLabelText('文件格式'), { target: { value: format } }); await importFile()
      fireEvent.click(button('准备导入候选')); expect(vi.mocked(api.createSubscriptionIntent).mock.calls.at(-1)?.[0]).toMatchObject({ kind: 'import', format })
      fireEvent.click(button('取消本次操作'))
    }
    expect(write).not.toHaveBeenCalled()
  })
  it('approves only server supplied references and revisions', async () => {
    await ready(); fireEvent.click(button('准备批准来源')); expect(vi.mocked(api.createSubscriptionIntent).mock.calls.at(-1)?.[0]).toMatchObject({ kind: 'approve', referenceId: 'synthetic-reference', policyRevision: 1, expectedRevision: 3 })
    expect(screen.queryByLabelText(/URL/)).not.toBeInTheDocument(); fireEvent.click(button('取消本次操作'))
    readReceipt.mockResolvedValueOnce(subscriptionReceipt({ kind: 'approve', state: 'approved', revision: 3, referenceId: 'synthetic-reference', policyRevision: 1, approvalId: subscriptionCommandId }))
    fireEvent.change(screen.getByLabelText('命令 ID'), { target: { value: subscriptionCommandId } }); fireEvent.click(button('读取命令回执'))
    await waitFor(() => expect(button('准备抓取候选')).toBeEnabled())
    readAccess.mockImplementation(async (_t, _s, id) => ({ ...subscriptionAccess(id), references: [{ referenceId: 'synthetic-reference', revision: 2 }] }))
    fireEvent.click(button('刷新当前版本')); await waitFor(() => expect(screen.getByRole('option', { name: 'synthetic-reference · 策略版本 2' })).toBeInTheDocument())
    expect(button('准备抓取候选')).toBeDisabled()
    fireEvent.click(screen.getByRole('radio', { name: '交接批准ID（未核验）' }))
    fireEvent.change(screen.getByLabelText('交接批准 ID'), { target: { value: subscriptionCommandId } })
    fireEvent.change(screen.getByLabelText('交接策略版本'), { target: { value: '2' } })
    readAccess.mockImplementation(async (_t, _s, id) => ({ ...subscriptionAccess(id), policyState: 'unavailable', references: [] }))
    fireEvent.click(button('刷新当前版本')); await waitFor(() => expect(button('准备批准来源')).toBeDisabled())
    await screen.findByText(/无法列举引用/)
    expect(screen.getByRole('radio', { name: '本会话已读回批准' })).toBeChecked()
    fireEvent.click(screen.getByRole('radio', { name: '交接批准ID（未核验）' }))
    expect(screen.getByLabelText('交接批准 ID')).toHaveValue(''); expect(screen.getByLabelText('交接策略版本')).toHaveValue('')
  })
  it('fetches only with a known approval', async () => {
    // Both directory references deliberately share revision 2. The fetch API
    // binds approval ID, not the unrelated new-approval dropdown reference.
    readAccess.mockImplementation(async (_t, _s, id) => ({ ...subscriptionAccess(id), references: [{ referenceId: 'synthetic-reference', revision: 2 }, { referenceId: 'z-reference', revision: 2 }] }))
    await ready(); expect(button('准备抓取候选')).toBeDisabled()
    fireEvent.change(screen.getByLabelText('目录引用'), { target: { value: 'z-reference' } })
    write.mockResolvedValueOnce(subscriptionReceipt({ kind: 'approve', state: 'approved', revision: 3, referenceId: 'z-reference', policyRevision: 2, approvalId: subscriptionCommandId }))
    fireEvent.click(button('准备批准来源')); confirm(); await waitFor(() => expect(button('准备抓取候选')).toBeEnabled())
    fireEvent.click(button('刷新当前版本')); await waitFor(() => expect(button('准备抓取候选')).toBeEnabled())
    expect(screen.getByLabelText('目录引用')).toHaveValue('z-reference')
    fireEvent.click(button('准备抓取候选')); expect(vi.mocked(api.createSubscriptionIntent).mock.calls.at(-1)?.[0]).toMatchObject({ kind: 'fetch', approvalId: subscriptionCommandId, expectedRevision: 3, policyRevision: 2 })
    fireEvent.click(button('取消本次操作'))
    const handedOff = 'cmd_' + 'a'.repeat(32)
    fireEvent.click(screen.getByRole('radio', { name: '交接批准ID（未核验）' }))
    fireEvent.change(screen.getByLabelText('交接批准 ID'), { target: { value: handedOff } })
    for (const invalid of ['', '0', '-1', '1.5', '1e2', ' 2', '02', '9007199254740992']) {
      fireEvent.change(screen.getByLabelText('交接策略版本'), { target: { value: invalid } }); expect(button('准备抓取候选')).toBeDisabled()
    }
    fireEvent.change(screen.getByLabelText('交接策略版本'), { target: { value: '2' } })
    fireEvent.click(button('准备抓取候选'))
    expect(vi.mocked(api.createSubscriptionIntent).mock.calls.at(-1)?.[0]).toMatchObject({ kind: 'fetch', approvalId: handedOff, expectedRevision: 3, policyRevision: 2 })
    expect(screen.getByRole('alertdialog')).toHaveTextContent(`来源 ID：${subscriptionSourceId}；预期来源版本：3；批准 ID：${handedOff}；策略版本：2`)
    expect(screen.getByRole('alertdialog')).toHaveTextContent('实际目录引用未读回；由批准ID决定；准备新批准的下拉引用不绑定本次抓取')
    fireEvent.change(screen.getByLabelText('交接策略版本'), { target: { value: '3' } }); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    fireEvent.click(button('准备抓取候选')); expect(vi.mocked(api.createSubscriptionIntent).mock.calls.at(-1)?.[0]).toMatchObject({ approvalId: handedOff, policyRevision: 3 })
    fireEvent.click(screen.getByRole('radio', { name: '本会话已读回批准' })); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    fireEvent.click(button('准备抓取候选')); expect(vi.mocked(api.createSubscriptionIntent).mock.calls.at(-1)?.[0]).toMatchObject({ approvalId: subscriptionCommandId, policyRevision: 2 })
    fireEvent.click(screen.getByRole('radio', { name: '交接批准ID（未核验）' })); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('交接策略版本'), { target: { value: '2' } })
    fireEvent.change(screen.getByLabelText('目录引用'), { target: { value: 'synthetic-reference' } })
    expect(screen.getByLabelText('交接批准 ID')).toHaveValue(handedOff)
    fireEvent.click(button('准备抓取候选')); expect(vi.mocked(api.createSubscriptionIntent).mock.calls.at(-1)?.[0]).toMatchObject({ approvalId: handedOff, policyRevision: 2 })
    fireEvent.change(screen.getByLabelText('交接批准 ID'), { target: { value: 'invalid' } }); expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(button('准备抓取候选')).toBeDisabled()
    fireEvent.click(button('清除会话与令牌'))
    readAccess.mockImplementation(async (_t, _s, id) => ({ ...subscriptionAccess(id), actions: id ? ['subscription.read', 'subscription.fetch'] : ['subscription.read'] }))
    await login(); fireEvent.click(screen.getByRole('button', { name: /Synthetic source/ })); await waitFor(() => expect(screen.getByLabelText('目录引用')).toBeEnabled())
    expect(button('准备批准来源')).toBeDisabled(); expect(button('准备抓取候选')).toBeDisabled()
    fireEvent.click(screen.getByRole('radio', { name: '交接批准ID（未核验）' }))
    expect(screen.getByLabelText('交接批准 ID')).toHaveValue(''); expect(screen.getByLabelText('交接策略版本')).toHaveValue('')
    fireEvent.change(screen.getByLabelText('交接批准 ID'), { target: { value: handedOff } })
    fireEvent.change(screen.getByLabelText('交接策略版本'), { target: { value: '7' } })
    expect(button('准备抓取候选')).toBeEnabled(); expect(screen.getByText(/页面未验证该批准/)).toBeInTheDocument()
    fireEvent.click(button('准备抓取候选')); expect(vi.mocked(api.createSubscriptionIntent).mock.calls.at(-1)?.[0]).toMatchObject({ kind: 'fetch', approvalId: handedOff, policyRevision: 7, expectedRevision: 3 })
    const slow = deferred<ReturnType<typeof subscriptionReceipt>>(); write.mockReturnValueOnce(slow.promise); confirm()
    expect(screen.getByLabelText('交接批准 ID')).toBeDisabled(); expect(screen.getByLabelText('交接策略版本')).toBeDisabled()
    expect(screen.getByRole('radio', { name: '本会话已读回批准' })).toBeDisabled(); expect(screen.getByRole('radio', { name: '交接批准ID（未核验）' })).toBeDisabled()
    expect(readReceipt).not.toHaveBeenCalled()
    await act(async () => slow.resolve(subscriptionReceipt({ kind: 'fetch', revision: 4 })))
  })
  it('admits a selected candidate after inline confirmation', async () => {
    mockUndecidedCandidate(); await ready(); await chooseCandidate(/待审候选 · 2 个节点/); fireEvent.click(button('准备接纳候选')); expect(write).not.toHaveBeenCalled(); confirm()
    await waitFor(() => expect(write).toHaveBeenCalledTimes(1)); expect(write.mock.calls[0][2]).toMatchObject({ kind: 'decide', candidateId: subscriptionCandidateId, decision: 'admitted_local', expectedRevision: 3 })
    expect(screen.getAllByText(/未评估/).length).toBeGreaterThan(0)
  })
  it('rejects a selected candidate after inline confirmation', async () => {
    mockUndecidedCandidate(); await ready(); await chooseCandidate(/待审候选 · 2 个节点/); fireEvent.click(button('准备拒绝候选')); expect(write).not.toHaveBeenCalled(); confirm()
    await waitFor(() => expect(write).toHaveBeenCalledTimes(1)); expect(write.mock.calls[0][2]).toMatchObject({ kind: 'decide', decision: 'rejected', candidateId: subscriptionCandidateId })
  })
  it('disables decisions for an already admitted candidate without preparing or writing', async () => {
    await ready(); await chooseCandidate()
    expect(button('准备接纳候选')).toBeDisabled(); expect(button('准备拒绝候选')).toBeDisabled()
    expect(screen.getByText('候选状态为“本地已接纳”，仅待审候选可接纳或拒绝。')).toBeInTheDocument()
    fireEvent.click(button('准备接纳候选')); fireEvent.click(button('准备拒绝候选'))
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(api.createSubscriptionIntent).not.toHaveBeenCalled(); expect(write).not.toHaveBeenCalled()
  })
  it('disables decisions for an already rejected candidate without preparing or writing', async () => {
    const sources = subscriptionSourcePage(); delete sources.sources[0].acceptedCandidateId
    const page = subscriptionCandidatePage(); page.candidates[0] = { ...page.candidates[0], state: 'rejected' }
    readSources.mockResolvedValue(sources); readCandidates.mockResolvedValue(page)
    await ready(); await chooseCandidate(/已拒绝 · 2 个节点/)
    expect(button('准备接纳候选')).toBeDisabled(); expect(button('准备拒绝候选')).toBeDisabled()
    expect(screen.getByText('候选状态为“已拒绝”，仅待审候选可接纳或拒绝。')).toBeInTheDocument()
    fireEvent.click(button('准备接纳候选')); fireEvent.click(button('准备拒绝候选'))
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(api.createSubscriptionIntent).not.toHaveBeenCalled(); expect(write).not.toHaveBeenCalled()
  })
  it('disables decisions for a quarantined candidate from an older source revision', async () => {
    mockUndecidedCandidate(2); await ready(); await chooseCandidate(/待审候选 · 2 个节点/)
    expect(button('准备接纳候选')).toBeDisabled(); expect(button('准备拒绝候选')).toBeDisabled()
    expect(screen.getByText('候选基准版本与当前来源版本不一致，请刷新并选择当前版本的待审候选。')).toBeInTheDocument()
    fireEvent.click(button('准备接纳候选')); fireEvent.click(button('准备拒绝候选'))
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument(); expect(api.createSubscriptionIntent).not.toHaveBeenCalled(); expect(write).not.toHaveBeenCalled()
  })
  it('requires a separate rollback confirmation and revision', async () => {
    await ready(); await chooseCandidate(); fireEvent.click(button('准备回退候选'))
    expect(button('确认并提交本地操作')).toBeDisabled(); confirm(); expect(write).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('checkbox', { name: '我已核对回退目标与当前来源版本' })); confirm()
    await waitFor(() => expect(write).toHaveBeenCalledTimes(1)); expect(write.mock.calls[0][2]).toMatchObject({ kind: 'rollback', expectedRevision: 3, candidateId: subscriptionCandidateId })
  })
  it('submits each immutable intent at most once', async () => {
    const slow = deferred<ReturnType<typeof subscriptionReceipt>>(); write.mockReturnValueOnce(slow.promise)
    setup(); await login(); prepareCreate(); const intent = vi.mocked(api.createSubscriptionIntent).mock.results.at(-1)!.value as SubscriptionIntent
    expect(Object.isFrozen(intent)).toBe(true); confirm(); expect(write).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('button', { name: '确认并提交本地操作' })).not.toBeInTheDocument(); expect(button('准备创建来源')).toBeDisabled()
    await act(async () => slow.resolve(subscriptionReceipt())); expect(write).toHaveBeenCalledTimes(1)
  })
  it('never retries pending or commit unknown writes', async () => {
    write.mockResolvedValueOnce(subscriptionReceipt({ state: 'unknown', stateMayHaveChanged: true, auditRecorded: false }))
    setup(); await login(); prepareCreate(); confirm(); await screen.findByText(/服务端结果或审计待确认/)
    expect(button('准备创建来源')).toBeDisabled(); expect(write).toHaveBeenCalledTimes(1)
    const unrelated = 'cmd_' + 'a'.repeat(32); readReceipt.mockResolvedValueOnce(subscriptionReceipt({ commandId: unrelated }))
    fireEvent.change(screen.getByLabelText('命令 ID'), { target: { value: unrelated } }); fireEvent.click(button('读取命令回执'))
    await waitFor(() => expect(readReceipt).toHaveBeenCalledTimes(1)); expect(button('准备创建来源')).toBeDisabled()
    fireEvent.click(button('清除会话与令牌')); await login(); write.mockRejectedValueOnce(new api.SubscriptionAPIError(503, 'unavailable', true, subscriptionCommandId, 'subscription_commit_unknown'))
    prepareCreate(); confirm(); await screen.findByText(/服务端可能已执行操作/); expect(button('准备创建来源')).toBeDisabled(); expect(write).toHaveBeenCalledTimes(2)
  })
  it('reads receipts without repeating mutations', async () => {
    setup(); await login(); fireEvent.change(screen.getByLabelText('命令 ID'), { target: { value: subscriptionCommandId } }); fireEvent.click(button('读取命令回执'))
    await screen.findByText('审计已确认'); expect(readReceipt).toHaveBeenCalledWith(token, expect.any(AbortSignal), subscriptionCommandId); expect(write).not.toHaveBeenCalled()
    const slow = deferred<ReturnType<typeof subscriptionReceipt>>(); readReceipt.mockReturnValueOnce(slow.promise)
    fireEvent.click(button('读取命令回执')); const signal = readReceipt.mock.calls.at(-1)![1]
    const other = 'cmd_' + 'b'.repeat(32); fireEvent.change(screen.getByLabelText('命令 ID'), { target: { value: other } })
    expect(signal.aborted).toBe(true); await act(async () => slow.resolve(subscriptionReceipt()))
    expect(screen.getByLabelText('命令 ID')).toHaveValue(other); expect(write).not.toHaveBeenCalled()
  })
  it('preserves last valid data after a failed write', async () => {
    await ready(); write.mockRejectedValueOnce(new api.SubscriptionAPIError(503, 'unavailable'))
    prepareCreate(); confirm(); await screen.findByText(/服务暂不可用/)
    expect(screen.getByRole('button', { name: /Synthetic source/ })).toHaveTextContent('已有本地有效候选')
    expect(screen.getByRole('button', { name: /本地已接纳 · 2 个节点/ })).toBeInTheDocument(); expect(screen.getByText(/候选为旧数据/)).toBeInTheDocument()
  })
  it('handles conflict locked not found and unavailable results', async () => {
    setup(); await login()
    for (const [status, kind, message] of [[409, 'conflict', '版本或批准已变化'], [423, 'locked', '服务端订阅写入门已关闭'], [404, 'unavailable', '来源、候选或命令未找到'], [503, 'unavailable', '服务暂不可用']] as const) {
      readSources.mockRejectedValueOnce(new api.SubscriptionAPIError(status, kind)); fireEvent.click(button('刷新来源')); await screen.findByText(new RegExp(message))
    }
    expect(write).not.toHaveBeenCalled()
  })
  it('focuses labelled validation errors without raw failure text', async () => {
    setup(); fireEvent.click(button('连接订阅会话')); expect(screen.getByRole('alert')).toHaveFocus(); expect(screen.getByLabelText('订阅管理令牌')).toHaveAttribute('aria-invalid', 'true')
    fireEvent.click(screen.getByRole('link', { name: '检查对应字段' })); expect(screen.getByLabelText('订阅管理令牌')).toHaveFocus()
    await login(); readSources.mockRejectedValueOnce(new Error('secret-url-password-sentinel')); fireEvent.click(button('刷新来源'))
    await screen.findByText(/请求未能完成/); expect(document.body.textContent).not.toContain('secret-url-password-sentinel')
  })
  it('releases intents and aborts reads on unmount', async () => {
    const view = setup(); await login(); prepareCreate(); const intent = vi.mocked(api.createSubscriptionIntent).mock.results.at(-1)!.value
    const slow = deferred<SubscriptionSourcePage>(); readSources.mockReturnValueOnce(slow.promise); fireEvent.click(button('刷新来源'))
    const signal = readSources.mock.calls.at(-1)![1]; view.unmount(); expect(signal.aborted).toBe(true); expect(api.releaseSubscriptionIntent).toHaveBeenCalledWith(intent)
    await act(async () => slow.resolve(subscriptionSourcePage())); expect(write).not.toHaveBeenCalled()
  })
})
