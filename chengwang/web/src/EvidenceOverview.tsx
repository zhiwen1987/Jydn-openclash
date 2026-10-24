import { useCallback, useEffect, useRef, useState } from 'react'
import { getOverview, OverviewReadError } from './overview-api'
import type { EvidenceOverviewProps, OverviewLayer, OverviewSnapshot, ProbeReason } from './overview-types'
import './evidence-overview.css'

const layerLabels: Record<OverviewLayer['state'], string> = { unknown: '未知', available: '来源自报可用', degraded: '来源自报降级', unavailable: '不可用' }
const reasonLabels: Record<OverviewLayer['reason'], string> = { not_configured: '未配置', no_current_evidence: '没有当前证据', cache_current: '汇总时缓存证据有效', evidence_stale: '汇总时证据已过期', read_failed: '读取失败', worker_stopped: '采集进程已停止', clock_untrusted: '来源时钟不可信', storage_unhealthy: '来源存储异常' }
const probeReasons: Record<ProbeReason, string> = { disabled: '未启用', not_started: '尚未开始', ok: '汇总时缓存视图可读', partial_coverage: '汇总时仅有部分覆盖', no_current_evidence: '没有当前证据', evidence_expired: '汇总时证据已过期', content_rejected: '内容未通过校验', clock_rollback: '来源时钟回拨', stopped: '采集进程已停止', cache_expired: '汇总时缓存过期', platform_unsupported: '平台不支持', limit_rejected: '超过读取限制', storage_rejected: '存储校验未通过', read_unavailable: '当前不可读取' }
function Timestamp({ value }: { value: string | null }) { return value === null ? <>未记录</> : <time dateTime={value}>{value}</time> }
function LayerFacts({ value }: { value: OverviewLayer }) { return <><dt>组件状态</dt><dd>{layerLabels[value.state]}</dd><dt>依据</dt><dd>{reasonLabels[value.reason]}</dd><dt>来源观测时间</dt><dd><Timestamp value={value.observedAt} /></dd><dt>来源有效期至</dt><dd><Timestamp value={value.expiresAt} /></dd></> }
type RequestOwner = { generation: number; controller: AbortController; pending: boolean }

export function EvidenceOverview({ onStateChange, onNavigate }: EvidenceOverviewProps) {
  const [report, setReport] = useState<OverviewSnapshot | null>(null)
  const [pending, setPending] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const owner = useRef<RequestOwner | null>(null), generation = useRef(0), mounted = useRef(false)
  const callback = useRef(onStateChange)
  useEffect(() => { callback.current = onStateChange }, [onStateChange])
  const refresh = useCallback(() => {
    if (!mounted.current || owner.current?.pending) return
    const request: RequestOwner = { generation: ++generation.current, controller: new AbortController(), pending: true }
    owner.current = request
    setReport(null); setError(null); setPending(true)
    callback.current?.({ state: 'pending', mode: null })
    const owns = () => mounted.current && owner.current === request && generation.current === request.generation && !request.controller.signal.aborted
    void getOverview(request.controller.signal).then(result => {
      if (!owns()) return
      request.pending = false; owner.current = null
      setReport(result); setPending(false)
      callback.current?.({ state: 'ready', mode: result.mode })
    }, failure => {
      if (!owns()) return
      request.pending = false; owner.current = null
      setReport(null); setPending(false)
      setError(failure instanceof OverviewReadError ? failure.message : '读取实际总览失败，请稍后重试。')
      callback.current?.({ state: 'error', mode: null })
    })
  }, [])
  useEffect(() => {
    mounted.current = true; refresh()
    return () => {
      mounted.current = false; generation.current += 1
      const current = owner.current
      owner.current = null
      if (current?.pending) current.controller.abort()
    }
  }, [refresh])
  const obs = report?.observation, probe = report?.probe
  return <div className="page evidence-overview-page">
    <div className="page-heading"><div><h1>实际证据总览</h1><p>只读展示控制面已有证据；不读取受保护清单，不执行修复。</p></div><button className="secondary" disabled={pending} onClick={refresh}>重新读取实际证据</button></div>
    <div className="eo-boundary">只读 · 仅供判断参考。控制面可读、组件自报可用或探针视图就绪，都不证明业务、互联网或端到端 DNS 健康，也不代表生产控制已启用。<br />以下状态对应本次读回的服务端汇总时点。页面不会自动更新，状态可能已变化；请重新读取确认。</div>
    {pending && <div className="eo-pending" role="status">正在读取实际总览证据</div>}
    {error && <div className="eo-error" role="alert">{error}</div>}
    {report && obs && probe && <>
      <div className="eo-summary"><span>实际来源：控制面聚合</span><span>服务端模式：{report.mode}</span><span>本次读回的服务端组装时间：<Timestamp value={report.generatedAt} /></span><span>组装时间不是来源采样时间；各来源不保证同时采样。</span></div>
      <div className="eo-source-grid">
        <section className="panel eo-source-card"><div className="eo-card-heading"><h2>控制器观测缓存</h2><span className={`eo-state${obs.fresh ? ' current' : ''}`}>{obs.fresh ? '汇总时证据有效' : '汇总时无当前证据'}</span></div><dl className="eo-facts"><dt>接入配置</dt><dd>{obs.configured ? '已配置' : '未配置'}</dd><dt>采集进程</dt><dd>{obs.running ? '运行中' : '未运行'}</dd><dt>旧证据</dt><dd>{obs.stale ? '已标记过期' : '未标记过期'}</dd><LayerFacts value={obs.controller} /><dt>最近尝试</dt><dd><Timestamp value={obs.lastAttemptAt} /></dd><dt>最近成功</dt><dd><Timestamp value={obs.lastSuccessAt} /></dd><dt>连续失败次数</dt><dd>{obs.consecutiveFailures}</dd></dl><h3>来源存储</h3><dl className="eo-facts"><LayerFacts value={obs.storage} /></dl><h3>来源时钟</h3><dl className="eo-facts"><LayerFacts value={obs.clock} /></dl><button className="secondary" disabled={!onNavigate} onClick={() => onNavigate?.('设备读回')}>查看设备读回</button></section>
        <section className="panel eo-source-card"><div className="eo-card-heading"><h2>探针只读视图</h2><span className={`eo-state${probe.coverageState === 'current' ? ' current' : ''}`}>{probe.coverageState === 'current' ? '汇总时有缓存覆盖' : '汇总时覆盖未知'}</span></div><dl className="eo-facts"><dt>接入配置</dt><dd>{probe.configured ? '已配置' : '未配置'}</dd><dt>采集进程</dt><dd>{probe.running ? '运行中' : '未运行'}</dd><dt>缓存视图</dt><dd>{probeReasons[probe.reason]}</dd><dt>来源时钟</dt><dd>{probe.clockHealthy ? '汇总时来源自报正常' : '不可信或未知'}</dd><dt>来源存储</dt><dd>{probe.storageHealthy ? '汇总时来源自报正常' : '异常或未知'}</dd><dt>缓存时间</dt><dd><Timestamp value={probe.cachedAt} /></dd><dt>来源有效期至</dt><dd><Timestamp value={probe.expiresAt} /></dd>{probe.coverage ? <><dt>声明目标数</dt><dd>{probe.coverage.declaredTargets}</dd><dt>已有样本目标数</dt><dd>{probe.coverage.targetsWithSamples}</dd><dt>缺少样本目标数</dt><dd>{probe.coverage.targetsMissing}</dd><dt>保留样本数</dt><dd>{probe.coverage.retainedSamples}</dd><dt>有效记录总数</dt><dd>{probe.coverage.validTotal}</dd><dt>其中过期记录</dt><dd>{probe.coverage.expiredTotal}</dd><dt>未过期记录数</dt><dd>{probe.coverage.eligibleTotal}</dd><dt>拒绝记录数</dt><dd>{probe.coverage.rejectedTotal}</dd><dt>结果截断</dt><dd>{probe.coverage.truncated ? '是' : '否'}</dd><dt>部分覆盖</dt><dd>{probe.coverage.partial ? '是' : '否'}</dd></> : <><dt>样本覆盖数量</dt><dd>未知，未展示缓存计数</dd></>}</dl><p className="eo-source-footnote">覆盖数量描述证据完整性，不是节点或业务成功率。</p><button className="secondary" disabled={!onNavigate} onClick={() => onNavigate?.('代理节点')}>查看代理节点</button></section>
        <section className="panel eo-source-card"><h2>订阅编排接入</h2><dl className="eo-facts"><dt>接入配置</dt><dd>{report.subscription.configured ? '已配置' : '未配置'}</dd><dt>来源清单</dt><dd>受保护，未读取</dd><dt>来源数量</dt><dd>未知，未读取</dd><dt>节点数量</dt><dd>未知，未读取</dd></dl><p>配置存在不证明连通性、授权或订阅刷新成功。</p><button className="secondary" disabled={!onNavigate} onClick={() => onNavigate?.('订阅与提供者')}>查看订阅与提供者</button></section>
      </div>
      <section className="panel eo-unsupported"><h2>本次尚未覆盖</h2><p>业务可用性、节点池、端到端 DNS、设备清单和流量拓扑均未采集，不能从当前缓存推算。</p><p>汇总时覆盖：{report.coverage.state === 'partial' ? '部分来源有有效证据' : '没有当前来源证据'}；本阶段不宣称全网健康或完整覆盖。</p></section>
    </>}
  </div>
}
