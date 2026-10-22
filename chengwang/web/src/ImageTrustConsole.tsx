import { useEffect, useRef, useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import { ClipboardList, LockKeyhole, RefreshCw, ShieldCheck, Unplug } from 'lucide-react'
import { getImageTrustHistory, getImageTrustStatus, ImageTrustReadError } from './image-trust-api'
import type { ImageTrustHistory, ImageTrustHistoryEntry, ImageTrustStatus } from './image-trust-types'
import './image-trust.css'

export interface ImageTrustConsoleProps { baseUrl?: string; fetcher?: typeof fetch }

const PAGE_SIZE = 20
const errorText = (error: unknown): string => {
  if (!(error instanceof ImageTrustReadError)) return '读取失败，当前状态未知。'
  if (error.classification === 'authentication') return '凭据已失效或无效，已清除读取数据，请重新连接。'
  if (error.classification === 'forbidden') return '当前身份无权读取此区域。操作记录仅 auditor / admin 可见。'
  if (error.classification === 'conflict') return '记录快照已变化，已回到第一页；请手工刷新，避免混合不同快照。'
  if (error.classification === 'transport') return '连接被阻止：仅允许同源 HTTPS 或本机 loopback HTTP，未发送凭据。'
  if (error.classification === 'format') return '响应格式或边界无效，当前状态未知。'
  return '服务不可用、超时或网络异常，当前状态未知。'
}

function time(value: number): string {
  if (value <= 0 || value > 253402300799) return '未知（未取得真实时间）'
  const date = new Date(value * 1000)
  return Number.isNaN(date.getTime()) ? '未知（无效时间）' : date.toLocaleString('zh-CN', { hour12: false })
}

function Digest({ value, label }: { value: string; label: string }) {
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>('idle')
  if (!value) return <span className="it-muted">未知</span>
  return <details className="it-digest"><summary aria-label={`展开${label}`}>{value.slice(0, 12)}…{value.slice(-8)}</summary><code>{value}</code><button type="button" onClick={async () => {
    try { await navigator.clipboard.writeText(value); setCopyState('copied') } catch { setCopyState('failed') }
  }}>{copyState === 'copied' ? '已复制' : copyState === 'failed' ? '复制失败，请手工选择摘要' : `复制${label}`}</button></details>
}

function Metric({ label, value, note, tone = '' }: { label: string; value: ReactNode; note: ReactNode; tone?: string }) {
  return <article className={`it-metric ${tone}`}><span>{label}</span><strong>{value}</strong><small>{note}</small></article>
}

function HistoryDetails({ entry }: { entry: ImageTrustHistoryEntry }) {
  return <details className="it-entry-details"><summary>查看摘要</summary><dl>
    <dt>操作者</dt><dd>{entry.actorId || '未知'}</dd><dt>策略 / Grant</dt><dd>{entry.policyId || '—'} / {entry.grantId || '—'}</dd>
    <dt>目录代次</dt><dd>{entry.generation}</dd><dt>目录摘要</dt><dd><Digest value={entry.catalogueSHA256} label="记录目录摘要" /></dd>
    <dt>Prepared 时间</dt><dd>{time(entry.preparedAtUnix)}</dd><dt>Prepared 审计摘要</dt><dd><Digest value={entry.preparedAuditHash} label="Prepared 摘要" /></dd>
    <dt>Result 时间</dt><dd>{time(entry.resultAtUnix)}</dd><dt>Result 审计摘要</dt><dd><Digest value={entry.resultAuditHash} label="Result 摘要" /></dd>
    <dt>审计确认</dt><dd>{entry.acknowledged ? '已确认' : '未确认 / 可能待恢复'}</dd>
  </dl></details>
}

function ImageTrustSession({ baseUrl = '', fetcher }: ImageTrustConsoleProps) {
  const [token, setToken] = useState('')
  const credential = useRef('')
  const [connected, setConnected] = useState(false)
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState<ImageTrustStatus | null>(null)
  const [history, setHistory] = useState<ImageTrustHistory | null>(null)
  const [statusError, setStatusError] = useState('')
  const [historyError, setHistoryError] = useState('')
  const [policySearch, setPolicySearch] = useState('')
  const [historySearch, setHistorySearch] = useState('')
  const [policyPage, setPolicyPage] = useState(0)
  const [offset, setOffset] = useState(0)
  const [sequence, setSequence] = useState(0)
  const [elapsed, setElapsed] = useState(0)
  const observedClock = useRef(0)
  const observedWall = useRef(0)
  const serial = useRef(0)
  const request = useRef<AbortController | null>(null)
  const requestTimeout = useRef<number | undefined>(undefined)

  useEffect(() => {
    const version = serial, pending = request, timer = requestTimeout, bearer = credential
    return () => { version.current++; pending.current?.abort(); window.clearTimeout(timer.current); bearer.current = '' }
  }, [])
  useEffect(() => {
    if (!status) return
    const tick = () => setElapsed(previous => Math.max(previous, 0, (performance.now() - observedClock.current) / 1000, (Date.now() - observedWall.current) / 1000))
    const timer = window.setInterval(tick, 1000)
    document.addEventListener('visibilitychange', tick)
    return () => { window.clearInterval(timer); document.removeEventListener('visibilitychange', tick) }
  }, [status])

  function invalidate(clearInput = true) {
    serial.current++
    request.current?.abort()
    window.clearTimeout(requestTimeout.current)
    request.current = null
    credential.current = ''
    if (clearInput) setToken('')
    setConnected(false); setLoading(false); setStatus(null); setHistory(null)
    setStatusError(''); setHistoryError(''); setOffset(0); setSequence(0); setElapsed(0)
    setPolicySearch(''); setHistorySearch(''); setPolicyPage(0)
  }

  async function load(nextOffset = 0, anchor = 0) {
    request.current?.abort()
    window.clearTimeout(requestTimeout.current)
    const controller = new AbortController()
    request.current = controller
    const id = ++serial.current
    const started = performance.now(), startedWall = Date.now()
    setLoading(true); setStatusError(''); setHistoryError('')
    // Clear old observations during every read. Errors cannot preserve a green status.
    setStatus(null); setHistory(null)
    const timeout = window.setTimeout(() => controller.abort(), 15000)
    requestTimeout.current = timeout
    const options = { token: credential.current, signal: controller.signal, baseUrl, fetcher }
    try {
      const [s, h] = await Promise.allSettled([
        getImageTrustStatus(options), getImageTrustHistory(options, { limit: PAGE_SIZE, offset: nextOffset, sequence: anchor }),
      ])
      if (serial.current !== id) return
      if (controller.signal.aborted) {
        setStatusError('请求已超时或取消，当前状态未知。'); setHistoryError('请求已超时或取消，当前记录未知。'); return
      }
      const unauthorized = [s, h].some(result => result.status === 'rejected' && result.reason instanceof ImageTrustReadError && result.reason.status === 401)
      if (unauthorized) { invalidate(); setStatusError(errorText(new ImageTrustReadError(401, 'authentication'))); return }
      if (s.status === 'fulfilled') {
        // Count the entire request duration conservatively; slow reads must not extend a freshness lease.
        observedClock.current = started; observedWall.current = startedWall
        setElapsed(Math.max(0, (performance.now() - started) / 1000, (Date.now() - startedWall) / 1000)); setStatus(s.value); setPolicyPage(0)
      }
      else setStatusError(errorText(s.reason))
      if (h.status === 'fulfilled') { setHistory(h.value); setOffset(h.value.offset); setSequence(h.value.sequence) }
      else {
        setHistoryError(errorText(h.reason))
        if (h.reason instanceof ImageTrustReadError && h.reason.status === 409) { setOffset(0); setSequence(0); setHistorySearch('') }
      }
    } finally {
      window.clearTimeout(timeout)
      if (serial.current === id) setLoading(false)
    }
  }

  function connect(event: FormEvent) {
    event.preventDefault()
    invalidate(false)
    if (!token) { setStatusError('请输入 Bearer 令牌。'); return }
    credential.current = token
    setConnected(true)
    void load()
  }

  const observedNow = status ? status.observedAtUnix + elapsed : 0
  const catalogueFresh = !!status && status.observedAtUnix > 0 && status.fresh && status.notAfterUnix > observedNow
  const sourceFresh = !!status && status.observedAtUnix > 0 && status.refreshRequired && status.refreshFresh && status.refreshLastSuccessUnix > 0 && status.refreshLastSuccessUnix <= observedNow && status.refreshUntilUnix > observedNow && catalogueFresh
  const auditHealthy = !!status && status.healthy && status.auditVerifiedAtUnix > 0 && status.auditVerifiedAtUnix <= observedNow && status.auditVerifiedAtUnix + 30 > observedNow
  const policies = status?.policies.filter(p => `${p.policyId} ${p.grantId} ${p.state}`.toLowerCase().includes(policySearch.toLowerCase())) ?? []
  const pagePolicies = policies.slice(policyPage * PAGE_SIZE, (policyPage + 1) * PAGE_SIZE)
  const entries = history?.entries.filter(e => `${e.operationId} ${e.actorId} ${e.policyId} ${e.kind} ${e.state} ${e.outcome}`.toLowerCase().includes(historySearch.toLowerCase())) ?? []

  return <div className="image-trust-console">
    <header className="it-heading"><div><span className="it-eyebrow">TRUST POLICY · READ ONLY</span><h1><ShieldCheck aria-hidden="true" size={25} />可信策略控制台</h1><p>从可信后端读取目录与审计记录，不发起验证、不更新策略。</p></div><span className="it-badge"><LockKeyhole size={15} aria-hidden="true" />BLOCKED · 只读</span></header>
    <aside className="it-boundary" aria-label="运行边界"><strong>候选未部署 · 无设备执行授权</strong><p>这里显示的是控制面观察证据，不代表生产已上线、网络可用或业务可访问。来源新鲜度 ≠ 审计健康；任何未知均不视为健康。</p></aside>
    <section className="it-panel" aria-labelledby="it-connect"><h2 id="it-connect">连接可信控制面</h2><form className="it-connection" onSubmit={connect}><label>Bearer 令牌<input type="password" autoComplete="off" spellCheck={false} value={token} onChange={e => { invalidate(false); setToken(e.target.value) }} aria-describedby="it-token-help" /></label><button className="it-primary" type="submit" disabled={!token || loading}>{connected ? '重新连接' : '连接并读取'}</button><button type="button" onClick={() => invalidate()} disabled={!connected && !token}><Unplug size={16} aria-hidden="true" />断开并清除</button><button type="button" onClick={() => void load(offset, sequence)} disabled={!connected || loading}><RefreshCw size={16} aria-hidden="true" />手工刷新</button></form><p id="it-token-help" className="it-muted">令牌仅驻留当前组件内存，不写入浏览器存储或地址栏；仅同源 HTTPS / 本机 HTTP。页面无自动网络轮询。</p></section>
    <div className="it-live" data-testid="image-trust-message" role="status" aria-live="polite">{loading ? '正在读取真实状态与记录…' : statusError || (status ? `读取完成 · 观察时间 ${time(status.observedAtUnix)}` : '尚未读取；所有状态未知。')}</div>
    <section className="it-metrics" data-testid="image-trust-status" aria-label="可信状态摘要">
      <Metric label="可信目录" value={!status ? '未知' : catalogueFresh ? '签名时效内' : '过期 / 未确认'} note={status ? `代次 ${status.generation} · sequence ${status.sequence}` : '等待已认证读取'} tone={catalogueFresh ? 'it-good' : ''} />
      <Metric label="来源新鲜度" value={!status ? '未知' : !status.refreshRequired ? '未启用' : sourceFresh ? '本地窗口内' : '陈旧 / 未确认'} note="不独立证明发布方最新，不能证明业务可用" tone={sourceFresh ? 'it-good' : ''} />
      <Metric label="审计健康" value={!status ? '未知' : auditHealthy ? '已核对（30 秒窗口）' : '陈旧 / 未确认'} note={status ? `实际核对 ${time(status.auditVerifiedAtUnix)}` : '读取失败不会推断为健康'} tone={auditHealthy ? 'it-good' : ''} />
      <Metric label="本次启动补审计" value={status ? status.recoveryCompleted : '未知'} note="仅健康存储的审计缺口；不是恢复业务或重建授权" />
    </section>
    {status ? <section className="it-panel" aria-labelledby="it-catalogue"><h2 id="it-catalogue">目录、撤销与持久状态</h2><dl className="it-facts"><dt>Store ID</dt><dd>{status.storeId}</dd><dt>目录 SHA-256</dt><dd><Digest value={status.catalogueSHA256} label="目录摘要" /></dd><dt>签名截止</dt><dd>{time(status.notAfterUnix)}</dd><dt>来源刷新</dt><dd>{status.refreshRequired ? '已启用' : '未启用'} · 最后成功 {time(status.refreshLastSuccessUnix)} · 有效至 {time(status.refreshUntilUnix)}</dd><dt>防回放账本</dt><dd>{status.ledgerEntries} / {status.ledgerCapacity} · RESERVED {status.reserved} · CONSUMED {status.consumed}</dd><dt>累计撤销</dt><dd>密钥 {status.revokedKeys} · 审批 {status.revokedApprovals} · 镜像 {status.revokedManifests}</dd></dl></section> : null}
    <section className="it-panel" aria-labelledby="it-policies"><div className="it-section-heading"><div><h2 id="it-policies">当前策略</h2><p>目录定义与授权状态；不是设备部署状态。</p></div><label>搜索策略<input type="search" value={policySearch} onChange={e => { setPolicySearch(e.target.value); setPolicyPage(0) }} placeholder="策略 / Grant / 状态" /></label></div>
      {!status ? <p className="it-empty">尚无已确认的策略数据</p> : pagePolicies.length === 0 ? <p className="it-empty">没有匹配的策略</p> : <ul className="it-policies">{pagePolicies.map(p => <li key={`${p.policyId}:${p.grantId}`}><div><strong>{p.policyId}</strong><span className="it-state">{p.state}</span></div><p>Grant {p.grantId} · revision {p.revision}</p><Digest value={p.manifestSHA256} label={`策略 ${p.policyId} 镜像摘要`} /></li>)}</ul>}
      <div className="it-pagination"><span>{policies.length} 条策略 · 每页 {PAGE_SIZE} 条</span><button type="button" disabled={policyPage === 0} onClick={() => setPolicyPage(p => Math.max(0, p - 1))}>上一页策略</button><button type="button" disabled={(policyPage + 1) * PAGE_SIZE >= policies.length} onClick={() => setPolicyPage(p => p + 1)}>下一页策略</button></div>
    </section>
    <section className="it-panel" data-testid="image-trust-history" aria-labelledby="it-history"><div className="it-section-heading"><div><h2 id="it-history"><ClipboardList size={19} aria-hidden="true" />操作记录</h2><p>仅 auditor / admin · 按追加顺序从旧到新；搜索只覆盖当前页。</p></div><label>搜索当前页记录<input type="search" value={historySearch} onChange={e => setHistorySearch(e.target.value)} placeholder="操作 / 操作者 / 策略 / 结果" /></label></div>
      {historyError ? <p className="it-message" role="status">{historyError}</p> : !history ? <p className="it-empty">尚未读取操作记录</p> : entries.length === 0 ? <p className="it-empty">当前页没有匹配的操作记录</p> : <ol className="it-history">{entries.map(e => <li key={e.operationId}><div className="it-record-head"><strong>{e.kind} · {e.state}</strong><span>{e.outcome || '结果未知'}</span></div><p className="it-record-id">{e.operationId}</p><HistoryDetails entry={e} /></li>)}</ol>}
      <div className="it-pagination"><span>{history ? `共 ${history.total} 条 · 第 ${Math.floor(history.offset / PAGE_SIZE) + 1} 页 · sequence ${history.sequence}` : '记录快照未知'}</span><button type="button" disabled={!history || loading || offset === 0} onClick={() => { setHistorySearch(''); void load(Math.max(0, offset - PAGE_SIZE), sequence) }}>上一页记录</button><button type="button" disabled={!history || loading || offset + PAGE_SIZE >= history.total} onClick={() => { setHistorySearch(''); void load(offset + PAGE_SIZE, sequence) }}>下一页记录</button></div>
    </section>
  </div>
}

// A source change creates a new authenticated session; old observations and credentials never cross it.
export function ImageTrustConsole({ baseUrl = '', fetcher }: ImageTrustConsoleProps) {
  return <ImageTrustSession key={baseUrl} baseUrl={baseUrl} fetcher={fetcher} />
}

export default ImageTrustConsole
