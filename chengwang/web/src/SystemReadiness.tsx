import { useEffect, useMemo, useRef, useState } from 'react'
import { AlertCircle, CheckCircle2, CircleDashed, FileCheck2, LockKeyhole, RefreshCw, ShieldCheck } from 'lucide-react'
import { getCapabilities } from './api'
import type { CapabilityReport, CapabilityState, SystemCapability } from './types'

const statePresentation: Record<CapabilityState, { label: string; description: string }> = {
  live_readonly: { label: '只读接入已配置', description: '配置不代表连接成功、健康或生产验收；实际状态须独立读回' },
  implemented_local: { label: '本地实现', description: '已在控制面实现，尚未接管生产数据面' },
  design_only: { label: '仅设计', description: '已有设计边界，但还没有可执行实现' },
  blocked: { label: '受阻', description: '缺少前置条件，当前无法完成验收' },
}

const stateOrder: CapabilityState[] = ['live_readonly', 'implemented_local', 'design_only', 'blocked']

function formatObservedAt(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '时间不可用' : date.toLocaleString('zh-CN', { hour12: false })
}

function CapabilityRow({ capability }: { capability: SystemCapability }) {
  const state = statePresentation[capability.state]
  return <article className="readiness-capability">
    <div className="capability-identity">
      <strong>{capability.name}</strong>
      <span>{capability.id}</span>
    </div>
    <div className={`readiness-state ${capability.state}`}>
      <i aria-hidden="true" />
      <span>{state.label}</span>
      <small>{capability.readOnly ? '只读' : '包含写入能力'}</small>
    </div>
    <div className="capability-evidence">
      <strong>可核验入口与实现依据</strong>
      {capability.evidence.length > 0
        ? <ul>{capability.evidence.map(item => <li key={item}>{item}</li>)}</ul>
        : <span className="readiness-empty">暂无可核验入口</span>}
    </div>
    <div className="capability-limitations">
      <strong>当前限制</strong>
      {capability.limitations.length > 0
        ? <ul>{capability.limitations.map(item => <li key={item}>{item}</li>)}</ul>
        : <span className="readiness-empty">未声明额外限制</span>}
    </div>
  </article>
}

export function SystemReadiness() {
  const [report, setReport] = useState<CapabilityReport | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [requestID, setRequestID] = useState(0)
  const activeRequest = useRef<AbortController | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    activeRequest.current = controller
    const deadline = window.setTimeout(() => {
      if (controller.signal.aborted) return
      controller.abort()
      setReport(null)
      setError('读取能力清单超时，当前状态未核验；可以重新核验')
      setLoading(false)
    }, 10000)
    getCapabilities(controller.signal)
      .then(value => { if (!controller.signal.aborted) setReport(value) })
      .catch(reason => {
        if (controller.signal.aborted) return
        setReport(null)
        setError(reason instanceof Error ? reason.message : '无法连接本地控制面')
      })
      .finally(() => {
        window.clearTimeout(deadline)
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => { controller.abort(); window.clearTimeout(deadline); if (activeRequest.current === controller) activeRequest.current = null }
  }, [requestID])

  const groups = useMemo(() => {
    const result = new Map<string, SystemCapability[]>()
    for (const capability of report?.capabilities ?? []) {
      const current = result.get(capability.domain) ?? []
      current.push(capability)
      result.set(capability.domain, current)
    }
    return [...result.entries()]
  }, [report])

  const counts = useMemo(() => {
    const result: Record<CapabilityState, number> = { live_readonly: 0, implemented_local: 0, design_only: 0, blocked: 0 }
    for (const capability of report?.capabilities ?? []) result[capability.state] += 1
    return result
  }, [report])

  function retry() {
    // Invalidate immediately, before React schedules the next effect. A stale
    // transport that ignores AbortSignal must not restore the old inventory.
    activeRequest.current?.abort()
    setReport(null)
    setLoading(true)
    setError('')
    setRequestID(value => value + 1)
  }

  return <div className="readiness-page">
    <div className="page-heading readiness-heading">
      <div><h1>系统闭环</h1><p><span className="unknown-dot" />能力状态以控制面证据为准<span>不把设计态、本地实现或模拟结果标记为生产完成</span></p></div>
      <button className="secondary" onClick={retry} disabled={loading}><RefreshCw size={16}/>{loading ? '正在核验…' : '重新核验'}</button>
    </div>

    {loading && !report ? <section className="panel readiness-loading" role="status"><CircleDashed size={24}/><strong>正在读取系统能力证据</strong><span>仅查询控制面，不执行生产变更。</span></section> : null}

    {error ? <section className="readiness-error" role="alert"><AlertCircle size={20}/><div><strong>未能核验系统闭环状态</strong><span>{error}。页面不会沿用旧结果，也不会推断任何能力已完成。</span></div><button className="secondary" onClick={retry}>重试</button></section> : null}

    {report ? <>
      <section className={`readiness-boundary ${report.productionControlEnabled ? 'write-enabled' : ''}`} role="status">
        {report.productionControlEnabled ? <AlertCircle size={20}/> : <LockKeyhole size={20}/>}<div>
          <strong>{report.productionControlEnabled ? '生产写入已启用' : '生产写入保持关闭'}</strong>
          <span>{report.productionControlEnabled ? '执行生产操作前仍需经过备份、校验、灰度和回滚门禁。' : '当前页面只展示能力证据，不会发布配置、切换节点或重启网络服务。'}</span>
        </div>
      </section>

      <div className="readiness-summary" aria-label="能力状态汇总">
        {stateOrder.map((state, index) => {
          const Icon = [ShieldCheck, CheckCircle2, FileCheck2, AlertCircle][index]
          return <div key={state}><Icon/><span>{statePresentation[state].label}</span><strong>{counts[state]}</strong><small>{statePresentation[state].description}</small></div>
        })}
      </div>

      <section className="panel readiness-meta">
        <div><span>整体阶段</span><strong>{report.overallState}</strong></div>
        <div><span>清单生成时间</span><strong>{formatObservedAt(report.generatedAt)}</strong></div>
        <div><span>能力条目</span><strong>{report.capabilities.length}</strong></div>
        <div><span>生产控制</span><strong>{report.productionControlEnabled ? '已启用' : '未启用'}</strong></div>
      </section>

      {groups.length > 0 ? <div className="readiness-groups">{groups.map(([domain, capabilities]) => <section className="panel readiness-group" key={domain}>
        <div className="section-title"><div><h2>{domain}</h2><p>{capabilities.length} 项能力，每项分别展示证据与限制</p></div></div>
        <div className="readiness-capability-head" aria-hidden="true"><span>能力</span><span>状态与边界</span><span>可核验入口与实现依据</span><span>当前限制</span></div>
        {capabilities.map(capability => <CapabilityRow capability={capability} key={capability.id}/>)}</section>)}</div>
        : <section className="panel readiness-loading"><FileCheck2 size={24}/><strong>控制面尚未登记任何能力</strong><span>空清单不等于全部完成；需要先建立证据条目。</span></section>}
    </> : null}
  </div>
}
