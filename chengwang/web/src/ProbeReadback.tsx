import { useEffect, useRef, useState } from 'react'
import { AlertCircle, LockKeyhole, RefreshCw, ShieldCheck } from 'lucide-react'
import { getProbeDetails, getProbeStatus, ProbeReadError } from './probe-api'
import { isManagementTransportSecure } from './api'
import type { ProbeConclusion, ProbeDetails, ProbeStatus } from './probe-types'
import './probe-readback.css'

const labels: Record<ProbeConclusion, string> = { unknown: '未评估', available: '可用', degraded: '待确认 / 降级', restricted: '业务受限', unavailable: '不可用', rate_limited: '限流' }
const reasons: Record<string, string> = {
  disabled: '尚未配置探针证据导入', not_started: '等待首次读取', ok: '证据已验证，不代表全部业务可用',
  partial_coverage: '证据覆盖不完整', no_current_evidence: '没有当前有效证据', evidence_expired: '探针证据已过期',
  content_rejected: '部分证据未通过校验', read_unavailable: '读取失败，旧结论已清除', storage_rejected: '存储安全检查未通过',
  limit_rejected: '证据超过读取限额', platform_unsupported: '当前平台不支持安全导入', cache_expired: '缓存已过期，等待新证据',
  clock_rollback: '检测到时钟回退，暂停使用结论', stopped: '读取工作进程已停止',
  two_consecutive_contract_matches: '连续两次符合业务检测约定', three_consecutive_transport_failures: '连续三次明确传输失败',
  awaiting_success_confirmation: '仅一次成功，等待再次确认', failure_below_unavailable_threshold: '失败次数尚未达到不可用门槛',
  insufficient_evidence: '证据不足', evidence_stale_or_clock_invalid: '证据过期或时钟异常', rate_limited: '目标返回限流',
}
function reason(code: string): string { return reasons[code] ?? '检测结论仅限当前目标与路径' }
function time(value?: string) { return value ? new Date(value).toLocaleString('zh-CN') : '暂无证据时间' }
function expired(status: ProbeStatus, now: number) { return !!status.expiresAt && Date.parse(status.expiresAt) <= now }
function readError(error: unknown): string {
  if (error instanceof ProbeReadError) {
    if (error.kind === 'transport') return '明细需要 HTTPS 或本机回环，令牌未发送。'
    if (error.kind === 'authentication') return '身份验证失败，请重新输入管理令牌。'
    if (error.kind === 'forbidden') return '当前身份没有此范围的读取权限。'
    if (error.kind === 'format') return '响应不符合安全契约，已拒绝展示。'
    if (error.status === 503) return '探针导入未配置或暂不可用。'
  }
  return '暂时无法读取，请重试；旧结论已清除。'
}

export function ProbeReadback() {
  const [status, setStatus] = useState<ProbeStatus | null>(null)
  const [summaryError, setSummaryError] = useState('')
  const [generation, setGeneration] = useState(0)
  const [now, setNow] = useState(Date.now)
  const [clientClockHealthy, setClientClockHealthy] = useState(true)
  const highWall = useRef(0)
  const [token, setToken] = useState('')
  const [requestToken, setRequestToken] = useState('')
  const [details, setDetails] = useState<ProbeDetails | null>(null)
  const [detailError, setDetailError] = useState('')
  const [loadingDetails, setLoadingDetails] = useState(false)
  const [detailGeneration, setDetailGeneration] = useState(0)
  const detailAbort = useRef<AbortController | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    let current = true
    const deadline = setTimeout(() => controller.abort(), 10_000)
    getProbeStatus(controller.signal).then(value => {
      if (!current || controller.signal.aborted) return
      setStatus(value); setSummaryError(''); setNow(Date.now())
    }).catch(error => {
      if (!current) return
      setStatus(null); setDetails(null); setSummaryError(readError(error))
    }).finally(() => clearTimeout(deadline))
    return () => { current = false; clearTimeout(deadline); controller.abort() }
  }, [generation])

  useEffect(() => {
    // Only cached anonymous status is polled. This never triggers probe execution.
    const timer = setInterval(() => setGeneration(value => value + 1), 30_000)
    highWall.current = Math.max(highWall.current, Date.now())
    const clock = setInterval(() => {
      const current = Date.now()
      if (current < highWall.current) setClientClockHealthy(false)
      highWall.current = Math.max(highWall.current, current)
      setNow(current)
    }, 1_000)
    return () => { clearInterval(timer); clearInterval(clock) }
  }, [])

  useEffect(() => {
    if (!requestToken) return
    const controller = new AbortController()
    detailAbort.current = controller
    let current = true
    const deadline = setTimeout(() => controller.abort(), 10_000)
    getProbeDetails(requestToken, controller.signal).then(value => {
      if (!current || controller.signal.aborted) return
      setDetails(value); setDetailError(''); setNow(Date.now())
    }).catch(error => {
      if (!current) return
      setDetails(null); setDetailError(readError(error))
      if (error instanceof ProbeReadError && (error.kind === 'authentication' || error.kind === 'forbidden')) { setToken(''); setRequestToken('') }
    }).finally(() => { clearTimeout(deadline); if (current) setLoadingDetails(false) })
    return () => { current = false; clearTimeout(deadline); controller.abort(); detailAbort.current = null }
  }, [requestToken, detailGeneration])

  function clearDetails() {
    detailAbort.current?.abort()
    setRequestToken(''); setDetails(null); setLoadingDetails(false); setDetailError('')
  }
  const stale = status ? expired(status, now) : true
  const usable = clientClockHealthy && status !== null && status.running && status.clockHealthy && status.storageHealthy && !stale && (status.state === 'ready' || status.state === 'partial')
  const detailUsable = usable && details !== null && details.status.running && details.status.clockHealthy && details.status.storageHealthy && !expired(details.status, now) && (details.status.state === 'ready' || details.status.state === 'partial')
  const secure = isManagementTransportSecure()

  return <section className="panel probe-readback" aria-labelledby="probe-heading">
    <header className="probe-heading"><div><p className="probe-eyebrow">独立于控制器的证据视图 · P1</p><h2 id="probe-heading"><ShieldCheck size={20} aria-hidden="true"/>主动探针证据（只读导入）</h2></div>
      <button className="secondary" type="button" onClick={() => { clearDetails(); setStatus(null); setSummaryError(''); setGeneration(value => value + 1) }}><RefreshCw size={16} aria-hidden="true"/>刷新探针摘要</button></header>
    <p className="probe-boundary">只读取已授权探针留下的证据，不发起测速、不切换节点、不修改生产。P1 是本地受控来源，不是外部独立见证。</p>
    <div className="probe-live" role="status" aria-live="polite" aria-atomic="true">
      {summaryError ? <><AlertCircle size={18} aria-hidden="true"/>{summaryError}</> : status ? <><span className="probe-state">{!status.configured ? '未配置' : !usable ? '未评估' : status.coverage.partial ? '覆盖不足' : '已读回'}</span>{reason(!clientClockHealthy ? 'clock_rollback' : stale ? 'cache_expired' : status.reason)}</> : '正在读取脱敏摘要…'}
    </div>
    {status ? <><dl className="probe-metrics"><div><dt>证据覆盖</dt><dd>{status.coverage.targetsWithSamples} / {status.coverage.declaredTargets}<small>目标；缺少 {status.coverage.targetsMissing} 个</small></dd></div>
      <div><dt>保留样本</dt><dd>{status.coverage.retainedSamples}<small>全局最多 200 条{status.coverage.truncated ? ' · 已截断' : ''}</small></dd></div>
      <div><dt>缓存截止</dt><dd className="probe-time">{time(status.expiresAt)}<small>{stale ? '当前不可用作健康依据' : '刷新页面不会延长探针 TTL'}</small></dd></div></dl>
      <p className="probe-caption">缓存读取：{time(status.cachedAt)} · 校验拒绝 {status.coverage.rejectedTotal} 条 · 过期 {status.coverage.expiredTotal} 条。覆盖完整也不等于业务全部正常。</p></> : null}
    <form className="probe-auth" onSubmit={event => {
      event.preventDefault(); detailAbort.current?.abort(); setDetails(null); setDetailError(''); setLoadingDetails(true); setRequestToken(token); setDetailGeneration(value => value + 1)
    }}>
      <label htmlFor="probe-token"><LockKeyhole size={15} aria-hidden="true"/>探针明细管理令牌</label>
      <div className="probe-auth-controls"><input id="probe-token" type="password" value={token} autoComplete="off" spellCheck={false} disabled={!secure} onChange={event => { clearDetails(); setToken(event.target.value) }} aria-describedby="probe-token-help"/>
        <button type="submit" className="secondary" disabled={!secure || !token || loadingDetails}>{loadingDetails ? '读取明细中…' : '读取受保护明细'}</button>
        <button type="button" className="secondary" onClick={() => { clearDetails(); setToken('') }}>清除明细与令牌</button></div>
      <small id="probe-token-help">{secure ? '仅保留在当前页面内存，不写入地址或浏览器存储；切换令牌会立即清除旧明细。' : '当前是局域网明文 HTTP，已禁止输入或发送管理令牌。请使用 HTTPS。'}</small>
    </form>
    {detailError ? <p className="probe-error" role="alert">{detailError}</p> : null}
    {details ? <div className="probe-detail"><h3>目标与路径</h3><p className="probe-caption">来源 {details.agentId} · catalog <code>{details.catalogDigest}</code> · 仅建议，不构成发布授权。</p>
      {!detailUsable ? <p className="probe-warning">明细已过期或当前无法验证，所有目标按“未评估”展示，历史样本不显示为可用。</p> : null}
      {details.targets.length === 0 ? <p>目录中没有目标，尚未评估任何业务。</p> : <ul className="probe-targets">{details.targets.map(target => {
        const targetUsable = detailUsable && (!target.expiresAt || Date.parse(target.expiresAt) > now)
        const state = targetUsable ? target.state : 'unknown'
        const sample = targetUsable ? details.samples.filter(item => item.probeId === target.probeId && item.pathId === target.pathId && Date.parse(item.expiresAt) > now)
          .sort((a, b) => Date.parse(b.completedAt) - Date.parse(a.completedAt) || b.runId.localeCompare(a.runId))[0] : undefined
        return <li key={`${target.probeId}/${target.pathId}`}><details><summary><span><strong>{target.probeId}</strong><small>路径 {target.pathId}</small></span><span className={`probe-badge ${state}`}>{labels[state]}</span></summary>
          <p>{reason(targetUsable ? target.reason : 'evidence_expired')}</p><p className="probe-caption">观测：{time(target.observedAt)} · 成功 {target.consecutiveSuccess} / 失败 {target.consecutiveFailure} · 保留 {target.retainedSamples} 条</p>
          {sample ? <><p className="probe-caption">样本 <code>{sample.runId}</code> · HTTP {sample.httpStatus ?? '无状态码'}</p><dl className="probe-layers">{([['dns', 'DNS'], ['connect', '连接'], ['tls', 'TLS'], ['http', 'HTTP'], ['business', '业务']] as const).map(([key, title]) => {
            const layer = sample.layers[key]
            const layerState = Date.parse(layer.expiresAt) > now ? layer.state : 'unknown'
            return <div key={key}><dt>{title}</dt><dd className={`probe-badge ${layerState}`}>{labels[layerState]}</dd></div>
          })}</dl></> : <p className="probe-caption">没有可展示的当前样本。</p>}
        </details></li>
      })}</ul>}
    </div> : null}
  </section>
}
