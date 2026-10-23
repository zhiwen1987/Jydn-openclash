import { useEffect, useRef, useState } from 'react'
import { AlertCircle, FileKey2, LockKeyhole, RefreshCw, ShieldCheck } from 'lucide-react'
import {
  createSubscriptionIntent, readSubscriptionAccess, readSubscriptionCandidates, readSubscriptionNodes,
  readSubscriptionReceipt, readSubscriptionSources, releaseSubscriptionIntent, sameSubscriptionScope,
  SubscriptionAPIError, writeSubscriptionCommand,
} from './subscription-api'
import type {
  SubscriptionAccess, SubscriptionAction, SubscriptionCandidate, SubscriptionCandidatePage,
  SubscriptionFormat, SubscriptionIntent, SubscriptionIntentInput, SubscriptionNodePage,
  SubscriptionReceipt, SubscriptionScope, SubscriptionSource, SubscriptionSourcePage,
} from './subscription-types'
import './subscriptions.css'

type Cache<T> = { value: T | null; loading: boolean; stale: boolean }
type Session = { token: string }
type Request = { session: Session; controller: AbortController; timer: ReturnType<typeof setTimeout> }
type Confirmation = { intent: SubscriptionIntent; title: string; description: string; rollback: boolean }
type Issue = { message: string; field?: string }
function empty<T>(): Cache<T> { return { value: null, loading: false, stale: false } }
const PAGE_SIZE = 20
const actionFor = {
  create: 'subscription.source.manage', import: 'subscription.import', approve: 'subscription.source.approve',
  fetch: 'subscription.fetch', decide: 'subscription.admission.decide', rollback: 'subscription.rollback',
} satisfies Record<SubscriptionIntent['kind'], SubscriptionAction>
const states = { quarantined: '待审候选', admitted_local: '本地已接纳', rejected: '已拒绝' }
const receiptStates = { prepared: '结果待核对', unknown: '结果待核对', committed: '本地已提交', approved: '批准已记录', noop: '内容未变', failed: '操作已失败' }
function errorText(error: unknown): string {
  if (error instanceof SubscriptionAPIError) {
    if (error.status === 401) return '身份验证失败，请重新输入订阅管理令牌。'
    if (error.status === 403) return '当前身份没有此资源的操作权限，请联系权限管理员。'
    if (error.status === 404) return '来源、候选或命令未找到，请刷新后重新选择。'
    if (error.status === 409) return '版本或批准已变化，请刷新来源与权限；不会自动重试写入。'
    if (error.status === 423) return '服务端订阅写入门已关闭；仍可读取已有数据。'
    if (error.code === 'subscription_audit_degraded') return '审计确认降级，操作结果尚未确认；请只读核对命令回执。'
    if (error.code === 'subscription_commit_unknown' || error.stateMayHaveChanged) return '服务端可能已执行操作，结果待核对；请读取命令回执，不要重复提交。'
    if (error.kind === 'format') return '响应未通过安全契约校验，未展示未确认数据。'
    if (error.kind === 'transport' && error.status === 426) return '此页面只允许 HTTPS，包括本机回环地址；令牌未发送。'
    if (error.kind === 'transport') return '连接未完成，未确认读取结果；不会自动重试，也不能据此认定请求未发送。'
    if (error.kind === 'limit') return '请求超过服务限额，请稍后手动刷新读取。'
    if (error.status === 503) return '服务暂不可用，保留上次有效数据并标记为旧数据；请手动刷新读取。'
  }
  return '请求未能完成；未确认成功，不会自动重试写入。'
}
function pendingReceipt(value: SubscriptionReceipt) {
  return value.stateMayHaveChanged || !value.auditRecorded || value.state === 'prepared' || value.state === 'unknown'
}
function pendingNotice(commandId: string | null) {
  return commandId
    ? '操作结果待核对；请读取命令回执，不要重复写入。'
    : '操作结果待核对；未取得命令 ID，请联系管理员对账，不要重复写入。'
}
function scopeText(scope: SubscriptionScope) { return `${scope.tenantId} / ${scope.siteId} / ${scope.environment}` }

export function Subscriptions() {
  const session = useRef<Session | null>(null)
  const requests = useRef(new Map<string, Request>())
  const mounted = useRef(true)
  const selectedRef = useRef<SubscriptionSource | null>(null)
  const scopeRef = useRef<SubscriptionScope | null>(null)
  const sourceAccessRef = useRef<SubscriptionAccess | null>(null)
  const confirmationRef = useRef<Confirmation | null>(null)
  const inFlightIntent = useRef<SubscriptionIntent | null>(null)
  const approvalRef = useRef<SubscriptionReceipt | null>(null)
  // undefined = no unresolved write; null = unresolved write without a known command ID.
  const pendingCommand = useRef<string | null | undefined>(undefined)
  const writingRef = useRef(false)
  const imported = useRef<Uint8Array | null>(null)
  const fileGeneration = useRef(0)
  const fileInput = useRef<HTMLInputElement>(null)
  const errorSummary = useRef<HTMLDivElement>(null)
  const [tokenDraft, setTokenDraft] = useState('')
  const [connected, setConnected] = useState(false)
  const [collectionAccess, setCollectionAccess] = useState<SubscriptionAccess | null>(null)
  const [sourceAccess, setSourceAccess] = useState<SubscriptionAccess | null>(null)
  const [sources, setSources] = useState<Cache<SubscriptionSourcePage>>(empty)
  const [selected, setSelected] = useState<SubscriptionSource | null>(null)
  const [candidates, setCandidates] = useState<Cache<SubscriptionCandidatePage>>(empty)
  const [candidate, setCandidate] = useState<SubscriptionCandidate | null>(null)
  const [candidateOffset, setCandidateOffset] = useState(0)
  const [nodes, setNodes] = useState<Cache<SubscriptionNodePage>>(empty)
  const [nodeOffset, setNodeOffset] = useState(0)
  const [sourceLabel, setSourceLabel] = useState('')
  const [format, setFormat] = useState<SubscriptionFormat>('mihomo-provider-yaml')
  const [importBytes, setImportBytes] = useState(0)
  const [referenceId, setReferenceId] = useState('')
  const [approval, setApproval] = useState<SubscriptionReceipt | null>(null)
  const [handoffApproval, setHandoffApproval] = useState('')
  const [handoffPolicyRevision, setHandoffPolicyRevision] = useState('')
  const [fetchMode, setFetchMode] = useState<'session' | 'handoff'>('session')
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null)
  const [rollbackChecked, setRollbackChecked] = useState(false)
  const [writing, setWriting] = useState(false)
  const [unresolved, setUnresolved] = useState(false)
  const [commandId, setCommandId] = useState('')
  const [receipt, setReceipt] = useState<SubscriptionReceipt | null>(null)
  const [receiptLoading, setReceiptLoading] = useState(false)
  const [issue, setIssue] = useState<Issue | null>(null)
  const [notice, setNotice] = useState('')
  const https = window.location.protocol === 'https:'

  useEffect(() => { if (issue) errorSummary.current?.focus() }, [issue])
  useEffect(() => {
    mounted.current = true
    const activeRequests = requests.current
    return () => {
      mounted.current = false
      for (const request of activeRequests.values()) { clearTimeout(request.timer); request.controller.abort() }
      activeRequests.clear(); session.current = null
      imported.current?.fill(0); imported.current = null
      if (confirmationRef.current) releaseSubscriptionIntent(confirmationRef.current.intent)
      if (inFlightIntent.current) releaseSubscriptionIntent(inFlightIntent.current)
      inFlightIntent.current = null
      confirmationRef.current = null
    }
  }, [])

  function abortChannel(channel: string) {
    const old = requests.current.get(channel)
    if (old) { clearTimeout(old.timer); old.controller.abort(); requests.current.delete(channel) }
  }
  function begin(channel: string, timeout: number, onTimeout: () => void): Request | null {
    const current = session.current
    if (!current || !https) return null
    abortChannel(channel)
    const request = { session: current, controller: new AbortController(), timer: undefined as unknown as ReturnType<typeof setTimeout> }
    request.timer = setTimeout(() => {
      if (!valid(channel, request)) return
      requests.current.delete(channel); request.controller.abort(); onTimeout()
    }, timeout)
    requests.current.set(channel, request)
    return request
  }
  function valid(channel: string, request: Request) {
    return mounted.current && session.current === request.session && requests.current.get(channel) === request && !request.controller.signal.aborted
  }
  function finish(channel: string, request: Request) {
    clearTimeout(request.timer)
    if (requests.current.get(channel) === request) requests.current.delete(channel)
  }
  function discardImport() {
    fileGeneration.current++; imported.current?.fill(0); imported.current = null; setImportBytes(0)
    if (fileInput.current) fileInput.current.value = ''
  }
  function cancelConfirmation() {
    if (confirmationRef.current) releaseSubscriptionIntent(confirmationRef.current.intent)
    confirmationRef.current = null; setConfirmation(null); setRollbackChecked(false)
  }
  function clearSource() {
    for (const key of ['source', 'candidates', 'nodes']) abortChannel(key)
    selectedRef.current = null; sourceAccessRef.current = null; setSelected(null); setSourceAccess(null)
    setCandidates(empty()); setCandidate(null); setCandidateOffset(0); setNodes(empty()); setNodeOffset(0)
    approvalRef.current = null; setApproval(null); setHandoffApproval(''); setHandoffPolicyRevision(''); setFetchMode('session'); setReferenceId(''); discardImport(); cancelConfirmation()
  }
  function clearSession() {
    for (const request of requests.current.values()) { clearTimeout(request.timer); request.controller.abort() }
    requests.current.clear(); session.current = null; scopeRef.current = null
    if (inFlightIntent.current) releaseSubscriptionIntent(inFlightIntent.current)
    inFlightIntent.current = null; pendingCommand.current = undefined
    setConnected(false); setCollectionAccess(null); setSources(empty()); clearSource()
    setReceipt(null); setCommandId(''); setUnresolved(false); setWriting(false); writingRef.current = false
    setTokenDraft(''); setSourceLabel(''); setIssue(null); setNotice(''); setReceiptLoading(false)
  }
  function fail(error: unknown) {
    if (error instanceof SubscriptionAPIError && error.status === 401) clearSession()
    setIssue({ message: errorText(error) })
  }
  function scopeMatches(value: SubscriptionAccess, source?: SubscriptionSource) {
    return scopeRef.current !== null && sameSubscriptionScope(value.scope, scopeRef.current) &&
      (source ? value.resource.type === 'subscription-source' && value.resource.id === source.id && sameSubscriptionScope(source.scope, value.scope)
        : value.resource.type === 'subscription-store')
  }
  async function loadOverview(preferId?: string) {
    const request = begin('overview', 10_000, () => {
      setSources(old => ({ ...old, loading: false, stale: !!old.value })); setIssue({ message: '读取超时，上次数据已标旧；请手动刷新。' })
    })
    if (!request) return
    setSources(old => ({ ...old, loading: true })); setIssue(null)
    try {
      const [access, page] = await Promise.all([
        readSubscriptionAccess(request.session.token, request.controller.signal),
        readSubscriptionSources(request.session.token, request.controller.signal),
      ])
      if (!valid('overview', request)) return
      if (access.resource.type !== 'subscription-store' || page.sources.some(s => !sameSubscriptionScope(s.scope, access.scope))) throw new SubscriptionAPIError(0, 'format')
      const changedScope = scopeRef.current && !sameSubscriptionScope(scopeRef.current, access.scope)
      if (changedScope) { clearSource(); setReceipt(null); setCommandId(''); pendingCommand.current = undefined; setUnresolved(false); setNotice('权限范围已变化，旧范围数据与回执已清除。') }
      scopeRef.current = access.scope; setCollectionAccess(access); setSources({ value: page, loading: false, stale: false })
      const nextId = changedScope ? undefined : preferId ?? selectedRef.current?.id
      const next = page.sources.find(s => s.id === nextId)
      if (next) void selectSource(next)
      else if (selectedRef.current) clearSource()
    } catch (error) {
      if (!valid('overview', request)) return
      setSources(old => ({ ...old, loading: false, stale: !!old.value })); fail(error)
    } finally { finish('overview', request) }
  }
  function connect() {
    if (!https) { setIssue({ message: '此页面只允许 HTTPS，包括本机回环地址；令牌未发送。', field: 'subscription-token' }); return }
    if (!tokenDraft.trim()) { setIssue({ message: '请输入订阅管理令牌。', field: 'subscription-token' }); return }
    const token = tokenDraft
    clearSession(); session.current = { token }; setConnected(true); setNotice('令牌仅在本次内存会话中使用。')
    void loadOverview()
  }
  async function selectSource(source: SubscriptionSource) {
    if (!scopeRef.current || !sameSubscriptionScope(source.scope, scopeRef.current) || writingRef.current) return
    const keptApproval = approvalRef.current?.sourceId === source.id && approvalRef.current.revision === source.revision ? approvalRef.current : null
    clearSource(); selectedRef.current = source; setSelected(source)
    approvalRef.current = keptApproval; setApproval(keptApproval)
    const request = begin('source', 10_000, () => {
      setCandidates(old => ({ ...old, loading: false, stale: !!old.value })); setIssue({ message: '来源权限或候选读取超时，请重新选择或刷新。' })
    })
    if (!request) return
    setCandidates({ value: null, loading: true, stale: false })
    try {
      const [access, page] = await Promise.all([
        readSubscriptionAccess(request.session.token, request.controller.signal, source.id),
        readSubscriptionCandidates(request.session.token, request.controller.signal, source.id, { limit: PAGE_SIZE, offset: 0, revision: source.revision }),
      ])
      if (!valid('source', request) || selectedRef.current?.id !== source.id) return
      if (!scopeRef.current || !sameSubscriptionScope(access.scope, scopeRef.current)) {
        clearSource(); setSources(empty()); setCollectionAccess(null); scopeRef.current = null
        setReceipt(null); setCommandId(''); setIssue({ message: '权限范围已变化，旧范围数据已清除；请重新连接会话。' }); return
      }
      if (!scopeMatches(access, source) || page.revision !== source.revision || page.candidates.some(c => c.sourceId !== source.id)) throw new SubscriptionAPIError(0, 'format')
      const stillApproved = keptApproval && access.references.some(r => r.referenceId === keptApproval.referenceId && r.revision === keptApproval.policyRevision) ? keptApproval : null
      approvalRef.current = stillApproved; setApproval(stillApproved)
      sourceAccessRef.current = access; setSourceAccess(access); setReferenceId(stillApproved?.referenceId ?? access.references[0]?.referenceId ?? '')
      setCandidates({ value: page, loading: false, stale: false })
    } catch (error) {
      if (!valid('source', request)) return
      sourceAccessRef.current = null; setSourceAccess(null); setCandidates(old => ({ ...old, loading: false, stale: !!old.value })); fail(error)
    } finally { finish('source', request) }
  }
  async function loadCandidates(offset: number) {
    const source = selectedRef.current
    if (!source || !sourceAccessRef.current) return
    const request = begin('candidates', 10_000, () => { setCandidates(old => ({ ...old, loading: false, stale: !!old.value })); setIssue({ message: '候选分页读取超时，请刷新来源。' }) })
    if (!request) return
    abortChannel('nodes'); setCandidate(null); setNodes(empty()); setNodeOffset(0); setCandidates(old => ({ ...old, loading: true }))
    try {
      const page = await readSubscriptionCandidates(request.session.token, request.controller.signal, source.id, { limit: PAGE_SIZE, offset, revision: source.revision })
      if (!valid('candidates', request) || selectedRef.current?.id !== source.id) return
      if (page.revision !== source.revision || page.candidates.some(c => c.sourceId !== source.id)) throw new SubscriptionAPIError(409, 'conflict')
      setCandidates({ value: page, loading: false, stale: false }); setCandidateOffset(offset)
    } catch (error) {
      if (!valid('candidates', request)) return
      if (error instanceof SubscriptionAPIError && (error.status === 409 || error.kind === 'format')) {
        setCandidates(empty()); setCandidateOffset(0); sourceAccessRef.current = null; setSourceAccess(null)
      } else setCandidates(old => ({ ...old, loading: false, stale: !!old.value }))
      fail(error)
    } finally { finish('candidates', request) }
  }
  async function loadNodes(nextCandidate: SubscriptionCandidate, offset = 0) {
    const source = selectedRef.current
    if (!source || nextCandidate.sourceId !== source.id) return
    const request = begin('nodes', 10_000, () => { setNodes(old => ({ ...old, loading: false, stale: !!old.value })); setIssue({ message: '节点分页读取超时，请刷新来源。' }) })
    if (!request) return
    setCandidate(nextCandidate); setNodes(old => ({ value: offset ? old.value : null, stale: false, loading: true }))
    try {
      const page = await readSubscriptionNodes(request.session.token, request.controller.signal, source.id, nextCandidate.id, { limit: PAGE_SIZE, offset, revision: source.revision })
      if (!valid('nodes', request) || selectedRef.current?.id !== source.id) return
      if (page.revision !== source.revision) throw new SubscriptionAPIError(409, 'conflict')
      setNodes({ value: page, loading: false, stale: false }); setNodeOffset(offset)
    } catch (error) {
      if (!valid('nodes', request)) return
      if (error instanceof SubscriptionAPIError && (error.status === 409 || error.kind === 'format')) {
        setNodes(empty()); setNodeOffset(0); setCandidate(null); setCandidates(old => ({ ...old, stale: !!old.value }))
      }
      else setNodes(old => ({ ...old, loading: false, stale: !!old.value }))
      fail(error)
    } finally { finish('nodes', request) }
  }
  function disabledReason(action: SubscriptionAction): string {
    if (!https) return '仅允许 HTTPS；不会发送令牌。'
    if (!connected) return '请先连接订阅会话。'
    if (writing) return '当前操作尚在等待确认，请勿重复提交。'
    if (unresolved) return '存在未决命令，请先只读核对回执；不会自动重写。'
    const access = action === 'subscription.source.manage' ? collectionAccess : sourceAccess
    if (!access) return '尚未取得此资源的权限元数据，默认禁止写入。'
    if (!access.writesEnabled) return '服务端订阅写入门已关闭。'
    if (!access.actions.includes(action)) return '当前身份没有此资源的相应操作权限。'
    if (sources.stale || candidates.stale || sources.loading) return '数据已标旧或正在刷新，请先读取当前版本。'
    return ''
  }
  function prepare(input: SubscriptionIntentInput, title: string, description: string) {
    const reason = disabledReason(actionFor[input.kind])
    if (reason) { setIssue({ message: reason }); return }
    try {
      const next = { intent: createSubscriptionIntent(input), title, description, rollback: input.kind === 'rollback' }
      cancelConfirmation(); confirmationRef.current = next; setConfirmation(next); setIssue(null); setRollbackChecked(false)
    } catch { setIssue({ message: '请检查字段内容与当前版本，未生成提交意图。' }) }
  }
  async function readFile(file?: File) {
    discardImport(); setIssue(null)
    if (!file) return
    if (file.size < 1 || file.size > (1 << 20)) { setIssue({ message: '请选择 1 字节至 1 MiB 的订阅文件。', field: 'subscription-file' }); return }
    const generation = fileGeneration.current, owner = session.current
    try {
      const bytes = new Uint8Array(await file.arrayBuffer())
      if (!mounted.current || generation !== fileGeneration.current || owner !== session.current || !owner) { bytes.fill(0); return }
      imported.current = bytes; setImportBytes(bytes.length)
      if (fileInput.current) fileInput.current.value = ''
    } catch { if (generation === fileGeneration.current) setIssue({ message: '文件读取失败，未展示或提交原文。', field: 'subscription-file' }) }
  }
  function prepareImport() {
    if (!selected || !imported.current) { setIssue({ message: '请先选择订阅文件。', field: 'subscription-file' }); return }
    prepare({ kind: 'import', sourceId: selected.id, expectedRevision: selected.revision, format, content: imported.current }, '导入本地候选', `版本 ${selected.revision} · ${format} · ${importBytes} 字节；原文不会显示。`)
    if (confirmationRef.current?.intent.kind === 'import') discardImport()
  }
  function prepareApproval() {
    const reference = sourceAccess?.references.find(r => r.referenceId === referenceId)
    if (!selected || !reference || sourceAccess?.policyState !== 'ready') { setIssue({ message: '仅可选择服务端当前提供的受信引用。', field: 'subscription-reference' }); return }
    prepare({ kind: 'approve', sourceId: selected.id, expectedRevision: selected.revision, referenceId: reference.referenceId, policyRevision: reference.revision }, '批准受信来源', `引用 ${reference.referenceId} · 策略版本 ${reference.revision} · 来源版本 ${selected.revision}；批准不等于抓取或节点健康。`)
  }
  function changeReference(value: string) {
    cancelConfirmation(); approvalRef.current = null; setApproval(null); setReferenceId(value)
  }
  function changeFetchMode(value: 'session' | 'handoff') {
    cancelConfirmation(); setFetchMode(value)
  }
  function prepareFetch() {
    if (!selected || fetchReason) return
    const approvalId = fetchMode === 'session' ? approval?.approvalId : handoffApproval
    const policyRevision = fetchMode === 'session' ? approval?.policyRevision : parsedHandoffRevision
    if (!approvalId || !policyRevision) return
    const binding = `来源 ID：${selected.id}；预期来源版本：${selected.revision}；批准 ID：${approvalId}；策略版本：${policyRevision}。`
    const explanation = fetchMode === 'handoff'
      ? '实际目录引用未读回；由批准ID决定；准备新批准的下拉引用不绑定本次抓取。'
      : `本会话已读回批准，目录引用 ${approval?.referenceId}；服务端仍会重新核验。`
    prepare({ kind: 'fetch', sourceId: selected.id, expectedRevision: selected.revision, approvalId, policyRevision },
      fetchMode === 'handoff' ? '抓取交接批准（未核验）' : '抓取本会话已读回批准',
      `${binding}${explanation}失败保留最后有效候选；不会自动接纳或发布。`)
  }
  function rememberReceipt(value: SubscriptionReceipt, fromWrite = false) {
    setReceipt(value); setCommandId(value.commandId)
    if (fromWrite || pendingCommand.current === value.commandId) {
      pendingCommand.current = pendingReceipt(value) ? value.commandId : undefined
      setUnresolved(pendingCommand.current !== undefined)
    }
    if (value.kind === 'approve' && value.state === 'approved' && !pendingReceipt(value)) { approvalRef.current = value; setApproval(value) }
  }
  async function submit() {
    const pending = confirmationRef.current
    if (!pending || writingRef.current || (pending.rollback && !rollbackChecked)) return
    const reason = disabledReason(actionFor[pending.intent.kind])
    if (reason) { setIssue({ message: reason }); return }
    if (pending.intent.kind !== 'create' && (pending.intent.sourceId !== selectedRef.current?.id || pending.intent.expectedRevision !== selectedRef.current?.revision)) {
      cancelConfirmation(); setIssue({ message: '来源或版本已变化，请刷新后重新准备操作。' }); return
    }
    writingRef.current = true; setWriting(true); setIssue(null); setNotice('正在等待服务端结果；尚未确认成功。')
    inFlightIntent.current = pending.intent
    confirmationRef.current = null; setConfirmation(null)
    const request = begin('write', 35_000, () => {
      writingRef.current = false; setWriting(false); pendingCommand.current = null; setUnresolved(true)
      setNotice(pendingNotice(null))
      releaseSubscriptionIntent(pending.intent); setIssue({ message: '等待结果超时，服务端可能已执行；中止等待不代表撤销。请核对命令回执，不要重复写入。' })
    })
    if (!request) { writingRef.current = false; setWriting(false); releaseSubscriptionIntent(pending.intent); return }
    try {
      const value = await writeSubscriptionCommand(request.session.token, request.controller.signal, pending.intent)
      if (!valid('write', request)) return
      rememberReceipt(value, true)
      if (pendingReceipt(value)) {
        setNotice('服务端结果或审计待确认；仅可读取命令回执，不会自动重新提交。')
        setIssue({ message: '服务端结果或审计待确认；仅可读取命令回执，不会自动重新提交。' })
      }
      else { setNotice(`${receiptStates[value.state]}；仅本地准入，不代表设备发布或节点可用。`); setSourceLabel(''); void loadOverview(value.sourceId) }
    } catch (error) {
      if (!valid('write', request)) return
      if (error instanceof SubscriptionAPIError && error.commandId) setCommandId(error.commandId)
      if (!(error instanceof SubscriptionAPIError) || error.stateMayHaveChanged || error.code === 'subscription_audit_degraded' || error.code === 'subscription_commit_unknown') {
        pendingCommand.current = error instanceof SubscriptionAPIError ? error.commandId ?? null : null; setUnresolved(true)
        setNotice(pendingNotice(pendingCommand.current))
      } else setNotice('')
      setSources(old => ({ ...old, stale: !!old.value })); setCandidates(old => ({ ...old, stale: !!old.value })); fail(error)
    } finally {
      releaseSubscriptionIntent(pending.intent)
      if (inFlightIntent.current === pending.intent) inFlightIntent.current = null
      if (valid('write', request)) { writingRef.current = false; setWriting(false) }
      finish('write', request)
    }
  }
  async function loadReceipt() {
    if (!/^cmd_[a-f0-9]{32}$/.test(commandId)) { setIssue({ message: '请输入有效的命令 ID。', field: 'subscription-command' }); return }
    const request = begin('receipt', 10_000, () => {
      setReceiptLoading(false)
      if (pendingCommand.current !== undefined) setNotice(pendingNotice(pendingCommand.current))
      else if (!writingRef.current) setNotice('')
      setIssue({ message: '回执读取超时，未决状态保留；不会重新提交命令。' })
    })
    if (!request) return
    setReceiptLoading(true); setIssue(null)
    try {
      const value = await readSubscriptionReceipt(request.session.token, request.controller.signal, commandId)
      if (!valid('receipt', request)) return
      if (value.commandId !== commandId) throw new SubscriptionAPIError(0, 'format')
      rememberReceipt(value)
      setNotice(writingRef.current ? '正在等待服务端结果；尚未确认成功。'
        : pendingReceipt(value) ? '回执仍未确认；请勿重复写入。'
        : pendingCommand.current !== undefined ? '已读取历史回执，未重复执行业务动作。其他未决结果仍待核对；写入暂停。'
          : '已读取历史回执，未重复执行业务动作。')
    } catch (error) {
      if (valid('receipt', request)) {
        if (pendingCommand.current !== undefined) setNotice(pendingNotice(pendingCommand.current))
        else if (!writingRef.current) setNotice('')
        fail(error)
      }
    }
    finally { if (valid('receipt', request)) setReceiptLoading(false); finish('receipt', request) }
  }
  function changeCommand(value: string) {
    abortChannel('receipt'); setReceiptLoading(false); setCommandId(value)
  }

  const createReason = disabledReason('subscription.source.manage')
  const importReason = disabledReason('subscription.import')
  const approvalReason = disabledReason('subscription.source.approve') || (sourceAccess?.policyState !== 'ready' ? '受信目录尚未就绪或无法列举引用，当前不能在页面批准。' : '')
  const knownApproval = approval && selected && approval.sourceId === selected.id && approval.revision === selected.revision && approval.referenceId === referenceId && sourceAccess?.references.some(r => r.referenceId === approval.referenceId && r.revision === approval.policyRevision)
  const parsedHandoffRevision = /^[1-9][0-9]{0,15}$/.test(handoffPolicyRevision) ? Number(handoffPolicyRevision) : 0
  const handoffValid = /^cmd_[a-f0-9]{32}$/.test(handoffApproval) && Number.isSafeInteger(parsedHandoffRevision) && parsedHandoffRevision > 0
  const fetchReason = disabledReason('subscription.fetch') || (sourceAccess?.policyState !== 'ready' ? '受信目录未就绪。' : '') ||
    (fetchMode === 'session' ? !knownApproval ? '本会话尚无匹配当前来源、引用与版本的已读回批准。' : ''
      : !handoffValid ? '请输入有效的交接批准 ID 与正十进制安全整数策略版本；页面尚未核验该批准。' : '')
  const decideReason = disabledReason('subscription.admission.decide') || (!candidate ? '请先选择当前版本中的候选。'
    : candidate.state !== 'quarantined' ? `候选状态为“${states[candidate.state]}”，仅待审候选可接纳或拒绝。`
      : !selected || candidate.baseRevision !== selected.revision ? '候选基准版本与当前来源版本不一致，请刷新并选择当前版本的待审候选。' : '')
  const rollbackReason = disabledReason('subscription.rollback') || (!candidate || candidate.state !== 'admitted_local' ? '请先选择已在本地接纳的历史候选。' : '')

  return <section className="subscriptions" aria-label="订阅资源工作区">
    <header className="subscription-heading"><div><p className="subscription-eyebrow">LOCAL ADMISSION / 本地准入</p><h1>订阅资源</h1><p>受信来源、候选与回执。接纳不等于发布，节点状态始终为未评估。</p></div><span className="subscription-boundary"><LockKeyhole size={16} aria-hidden="true"/>设备发布未授权</span></header>
    <aside className="subscription-safety"><ShieldCheck size={19} aria-hidden="true"/><p>来源创建只保存本地记录；此页不能编辑私有目录 URL、CA 或秘密。没有自动调度，也不执行内核或设备发布。</p></aside>
    <section className="panel subscription-session" aria-labelledby="subscription-session-title"><h2 id="subscription-session-title">本次管理会话</h2><div className="subscription-inline">
      <label htmlFor="subscription-token">订阅管理令牌<input id="subscription-token" type="password" autoComplete="off" value={tokenDraft} onChange={event => { const value = event.target.value; clearSession(); setTokenDraft(value); setNotice('身份输入已改变，旧会话数据已清除；中止等待不撤销服务端动作。') }} aria-invalid={issue?.field === 'subscription-token'} aria-describedby="subscription-session-help subscription-field-error"/></label>
      <button className="primary" onClick={connect} disabled={!https}>连接订阅会话</button><button className="secondary" onClick={() => { clearSession(); setNotice('本地会话与令牌已清除；中止等待不撤销已到达服务端的动作。') }}>清除会话与令牌</button>
    </div><p id="subscription-session-help" className="subscription-muted">仅内存，不写浏览器存储；连接后清空密码框。{!https ? '当前不是 HTTPS，包括本机回环也禁止发送令牌。' : connected ? '已连接；权限以服务端逐请求鉴权为准。' : '尚未连接，不会自动读取或写入。'}</p>
      {collectionAccess ? <p className="subscription-scope">当前范围：{scopeText(collectionAccess.scope)} · {collectionAccess.writesEnabled ? '写入门已开启（仍须资源权限）' : '写入门关闭 / 只读'}</p> : null}
    </section>
    {issue ? <div className="subscription-error" role="alert" tabIndex={-1} ref={errorSummary}><AlertCircle size={18} aria-hidden="true"/><div><strong>操作未确认</strong><p id="subscription-field-error">{issue.message}</p>{issue.field ? <a href={`#${issue.field}`} onClick={() => document.getElementById(issue.field!)?.focus()}>检查对应字段</a> : null}</div></div> : null}
    {notice ? <p className="subscription-notice" role="status">{notice}</p> : null}
    <div className="subscription-workspace">
      <section className="panel subscription-sources" aria-labelledby="subscription-sources-title"><div className="section-title"><div><h2 id="subscription-sources-title">来源</h2><p>先选择来源，再检查其版本与权限。</p></div><button className="secondary" disabled={!connected || sources.loading || writing} onClick={() => void loadOverview()}><RefreshCw size={15} aria-hidden="true"/>刷新来源</button></div>
        {sources.loading ? <p className="subscription-placeholder">正在读取真实来源与权限…</p> : null}
        {sources.stale ? <p className="subscription-stale">旧数据 · 未确认当前版本，写入已暂停。</p> : null}
        {sources.value?.sources.length ? <ul className="subscription-source-list">{sources.value.sources.map(source => <li key={source.id}><button className={selected?.id === source.id ? 'is-selected' : ''} aria-pressed={selected?.id === source.id} disabled={writing || sources.loading} onClick={() => void selectSource(source)}><strong>{source.label}</strong><span>版本 {source.revision} · {source.acceptedCandidateId ? '已有本地有效候选' : '尚无本地有效候选'}</span><code>{source.id}</code></button></li>)}</ul> : !sources.loading ? <p className="subscription-placeholder">{connected ? '没有来源。具备权限时可创建本地来源记录。' : '连接后读取真实来源；此处没有演示数据。'}</p> : null}
        <form className="subscription-form" onSubmit={event => { event.preventDefault(); if (!sourceLabel.trim()) setIssue({ message: '请输入来源名称。', field: 'subscription-source-label' }); else prepare({ kind: 'create', label: sourceLabel }, '创建本地来源', `名称 ${sourceLabel}；仅创建记录，不抓取网络。`) }}>
          <h3>创建来源记录</h3><label htmlFor="subscription-source-label">来源名称<input id="subscription-source-label" maxLength={128} value={sourceLabel} onChange={e => setSourceLabel(e.target.value)} aria-invalid={issue?.field === 'subscription-source-label'} aria-describedby="subscription-create-reason subscription-field-error"/></label>
          <button className="secondary" disabled={!!createReason}>准备创建来源</button><p id="subscription-create-reason" className="subscription-muted">{createReason || '下一步检查不可变提交意图，再显式确认。'}</p>
        </form>
      </section>
      <div className="subscription-detail">
        <section className="panel" aria-labelledby="subscription-candidates-title"><div className="section-title"><div><h2 id="subscription-candidates-title">候选与节点</h2><p>{selected ? `${selected.label} · 固定来源版本 ${selected.revision}` : '请选择一个真实来源。'}</p></div>{selected ? <button className="secondary" disabled={writing || candidates.loading} onClick={() => void loadOverview(selected.id)}>刷新当前版本</button> : null}</div>
          {candidates.loading ? <p className="subscription-placeholder">正在读取此来源权限与候选…</p> : null}{candidates.stale ? <p className="subscription-stale">候选为旧数据，不能据此写入。</p> : null}
          {candidates.value ? <><ul className="subscription-candidate-list">{candidates.value.candidates.map(value => <li key={value.id}><button disabled={writing} aria-pressed={candidate?.id === value.id} onClick={() => void loadNodes(value)}><span><strong>{states[value.state]}</strong> · {value.nodeCount} 个节点 · {value.format}</span><code>{value.id}</code><span className="subscription-muted">创建于 {new Date(value.createdAt).toLocaleString('zh-CN')} · 基准版本 {value.baseRevision}</span></button></li>)}</ul>{!candidates.value.candidates.length ? <p className="subscription-placeholder">当前版本没有候选。可手工导入，或在批准后抓取。</p> : null}<nav className="subscription-paging" aria-label="候选分页"><button className="secondary" disabled={!candidateOffset || candidates.loading} onClick={() => void loadCandidates(Math.max(0, candidateOffset - PAGE_SIZE))}>上一页候选</button><span>候选第 {Math.floor(candidateOffset / PAGE_SIZE) + 1} 页 · 版本 {candidates.value.revision}</span><button className="secondary" disabled={candidates.value.nextOffset === undefined || candidates.loading} onClick={() => void loadCandidates(candidates.value!.nextOffset!)}>下一页候选</button></nav></> : !candidates.loading ? <p className="subscription-placeholder">尚未读取候选；不会将不同来源或版本的数据拼接。</p> : null}
          {candidate ? <div className="subscription-nodes"><h3>节点安全摘要 <span className="subscription-tag">未评估</span></h3><p className="subscription-muted">不显示地址、密码或原始名称；本地接纳不证明节点连通。</p>{nodes.loading ? <p>正在读取节点分页…</p> : null}{nodes.stale ? <p className="subscription-stale">节点为旧数据。</p> : null}<ul>{nodes.value?.nodes.map(node => <li key={node.id}><strong>{node.label}</strong><span>{node.protocol} · {node.credentialConfigured ? '已配置凭据（不展示）' : '未配置凭据'} · 未评估</span><code>{node.id}</code></li>)}</ul>{nodes.value ? <nav className="subscription-paging" aria-label="节点分页"><button className="secondary" disabled={!nodeOffset || nodes.loading} onClick={() => void loadNodes(candidate, Math.max(0, nodeOffset - PAGE_SIZE))}>上一页节点</button><span>节点第 {Math.floor(nodeOffset / PAGE_SIZE) + 1} 页 · 版本 {nodes.value.revision}</span><button className="secondary" disabled={nodes.value.nextOffset === undefined || nodes.loading} onClick={() => void loadNodes(candidate, nodes.value!.nextOffset!)}>下一页节点</button></nav> : null}</div> : null}
        </section>
        <section className="panel subscription-operations" aria-labelledby="subscription-operations-title"><div className="section-title"><div><h2 id="subscription-operations-title">本地准入工作流</h2><p>每次写入均须显式确认；权限元数据不是批准，也不替代服务端鉴权。</p></div></div><div className="subscription-operation-grid">
          <fieldset><legend><FileKey2 size={16} aria-hidden="true"/>手工导入</legend><label htmlFor="subscription-format">文件格式<select id="subscription-format" value={format} onChange={e => { cancelConfirmation(); setFormat(e.target.value as SubscriptionFormat) }}><option value="mihomo-provider-yaml">YAML 提供者</option><option value="uri-list">URI 列表</option><option value="base64-uri-list">Base64 URI 列表</option></select></label><label htmlFor="subscription-file">订阅文件<input ref={fileInput} id="subscription-file" type="file" accept=".yaml,.yml,.txt" disabled={!!importReason} onChange={e => void readFile(e.target.files?.[0])} aria-describedby="subscription-import-reason"/></label><p className="subscription-muted">{importBytes ? `已在内存读取 ${importBytes} 字节；不展示文件名与原文。` : '最多 1 MiB；提交准备后清空文件输入。'}</p><button className="secondary" disabled={!!importReason} onClick={prepareImport}>准备导入候选</button><p id="subscription-import-reason" className="subscription-muted">{importReason || '仅进入本地候选库，仍须独立接纳。'}</p></fieldset>
          <fieldset><legend>受信目录批准与抓取</legend>
            <label htmlFor="subscription-reference">目录引用<select id="subscription-reference" disabled={!sourceAccess || sourceAccess.policyState !== 'ready' || writing} value={referenceId} onChange={e => changeReference(e.target.value)}>{!sourceAccess?.references.length ? <option value="">没有可列举的受信引用</option> : sourceAccess.references.map(ref => <option key={ref.referenceId} value={ref.referenceId}>{ref.referenceId} · 策略版本 {ref.revision}</option>)}</select></label>
            <button className="secondary" disabled={!!approvalReason} onClick={prepareApproval}>准备批准来源</button><p className="subscription-muted">{approvalReason || '只使用服务端列举的引用；不会接收任意 URL。'}</p>
            <div className="subscription-fetch-modes" role="radiogroup" aria-label="抓取批准方式">
              <label className="subscription-choice"><input type="radio" name="subscription-fetch-mode" checked={fetchMode === 'session'} disabled={!selected || writing} onChange={() => changeFetchMode('session')}/>本会话已读回批准</label>
              <label className="subscription-choice"><input type="radio" name="subscription-fetch-mode" checked={fetchMode === 'handoff'} disabled={!selected || writing} onChange={() => changeFetchMode('handoff')}/>交接批准ID（未核验）</label>
            </div>
            {fetchMode === 'session' ? knownApproval ? <p className="subscription-muted">本会话已读回批准：<code>{approval!.approvalId}</code> · 引用 {approval!.referenceId} · 策略版本 {approval!.policyRevision}</p> : <p className="subscription-muted">需在本会话取得匹配的批准回执，不使用交接输入作为后备。</p> : <>
              <label htmlFor="subscription-handoff">交接批准 ID<input id="subscription-handoff" value={handoffApproval} disabled={!selected || writing} onChange={e => { cancelConfirmation(); setHandoffApproval(e.target.value) }} autoComplete="off" spellCheck={false} aria-describedby="subscription-handoff-help"/></label>
              <label htmlFor="subscription-handoff-revision">交接策略版本<input id="subscription-handoff-revision" type="text" inputMode="numeric" maxLength={16} value={handoffPolicyRevision} disabled={!selected || writing} onChange={e => { cancelConfirmation(); setHandoffPolicyRevision(e.target.value) }} autoComplete="off" spellCheck={false} aria-describedby="subscription-handoff-help"/></label>
              <p id="subscription-handoff-help" className="subscription-muted">页面未验证该批准。实际目录引用未读回；由批准ID决定；准备新批准的下拉引用不绑定本次抓取。按当前来源版本与显式输入的策略版本提交，由服务端权威核验。</p>
            </>}
            <button className="secondary" disabled={!!fetchReason} onClick={prepareFetch}>准备抓取候选</button><p className="subscription-muted">{fetchReason || '抓取成功也不自动接纳或发布。'}</p>
          </fieldset>
          <fieldset><legend>候选决定与回退</legend><p className="subscription-muted">{candidate ? `目标 ${candidate.id}` : '请从当前版本候选列表中选择目标。'}</p><div className="subscription-button-row"><button className="secondary" disabled={!!decideReason} onClick={() => { if (selected && candidate) prepare({ kind: 'decide', sourceId: selected.id, expectedRevision: selected.revision, candidateId: candidate.id, expectedDigest: candidate.digest, decision: 'admitted_local' }, '接纳本地候选', `当前来源版本 ${selected.revision}；仅修改本地接纳状态，节点仍未评估。`) }}>准备接纳候选</button><button className="secondary subscription-danger" disabled={!!decideReason} onClick={() => { if (selected && candidate) prepare({ kind: 'decide', sourceId: selected.id, expectedRevision: selected.revision, candidateId: candidate.id, expectedDigest: candidate.digest, decision: 'rejected' }, '拒绝本地候选', `版本 ${selected.revision}；不会删除最后有效配置或发布设备。`) }}>准备拒绝候选</button></div><p className="subscription-muted">{decideReason || '确认前不会发送决定。'}</p><button className="secondary subscription-danger" disabled={!!rollbackReason} onClick={() => { if (selected && candidate) prepare({ kind: 'rollback', sourceId: selected.id, expectedRevision: selected.revision, candidateId: candidate.id }, '回退本地引用', `将版本 ${selected.revision} 的本地有效引用切换至 ${candidate.id}；不执行设备回滚。`) }}>准备回退候选</button><p className="subscription-muted">{rollbackReason || '回退需要额外确认目标与当前版本。'}</p></fieldset>
        </div></section>
      </div>
    </div>
    {confirmation ? <section className="subscription-confirmation panel" role="alertdialog" aria-labelledby="subscription-confirm-title" aria-describedby="subscription-confirm-description"><h2 id="subscription-confirm-title">确认：{confirmation.title}</h2><p id="subscription-confirm-description">{confirmation.description}</p><p className="subscription-muted">本次意图已冻结；修改表单不会改写此意图。取消将丢弃它，不自动提交或重试。</p>{confirmation.rollback ? <label className="subscription-checkbox"><input type="checkbox" checked={rollbackChecked} onChange={e => setRollbackChecked(e.target.checked)}/>我已核对回退目标与当前来源版本</label> : null}<div className="subscription-button-row"><button className="primary" disabled={writing || (confirmation.rollback && !rollbackChecked) || !!disabledReason(actionFor[confirmation.intent.kind])} onClick={() => void submit()}>确认并提交本地操作</button><button className="secondary" onClick={cancelConfirmation}>取消本次操作</button></div></section> : null}
    <section className="panel subscription-receipt" aria-labelledby="subscription-receipt-title"><div className="section-title"><div><h2 id="subscription-receipt-title">只读命令回执</h2><p>未决结果不重写。中止浏览器等待不等于撤销服务端动作。</p></div></div><div className="subscription-form"><div className="subscription-inline"><label htmlFor="subscription-command">命令 ID<input id="subscription-command" value={commandId} onChange={e => changeCommand(e.target.value)} autoComplete="off" spellCheck={false} aria-invalid={issue?.field === 'subscription-command'} aria-describedby="subscription-field-error"/></label><button className="secondary" disabled={!connected || receiptLoading} onClick={() => void loadReceipt()}>{receiptLoading ? '正在读取回执…' : '读取命令回执'}</button></div>{unresolved ? <p className="subscription-stale">存在未决命令。请读取回执；未取得命令 ID 时请联系管理员对账，不要新建等价写入。</p> : null}{receipt ? <dl className="subscription-receipt-grid"><div><dt>状态</dt><dd>{receiptStates[receipt.state]}{receipt.replayed ? ' · 历史重放，未重新执行' : ''}</dd></div><div><dt>命令</dt><dd><code>{receipt.commandId}</code></dd></div><div><dt>本地版本</dt><dd>{receipt.revision}</dd></div><div><dt>审计</dt><dd>{receipt.auditRecorded ? '审计已确认' : '审计待确认'}</dd></div></dl> : <p className="subscription-muted">尚无已读取回执；不会显示演示命令。</p>}</div></section>
  </section>
}
