import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { Activity, AlertCircle, CircleDashed, Database, Globe2, RefreshCw, Server } from 'lucide-react'
import { getObservationStatus } from './api'
import type { ObservationLayer, ObservationStatus as ObservationStatusType } from './types'

function label(state: ObservationLayer['state']): string {
  if (state === 'available') return '可用'
  if (state === 'degraded') return '已过期/降级'
  if (state === 'unavailable') return '不可用'
  return '未评估'
}

function LayerCard({ title, layer, icon }: { title: string; layer: ObservationLayer; icon: ReactNode }) {
  return <article className={`observation-layer ${layer.state}`}>
    <div>{icon}<strong>{title}</strong><span>{label(layer.state)}</span></div>
    <p>{layer.reason}</p>
    {layer.observedAt ? <small>证据时间：{new Date(layer.observedAt).toLocaleString('zh-CN')}</small> : <small>当前没有可用证据</small>}
  </article>
}

export function ObservationStatus() {
  const [status, setStatus] = useState<ObservationStatusType | null>(null)
  const [error, setError] = useState('')
  const [generation, setGeneration] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    getObservationStatus(controller.signal)
      .then(setStatus)
      .catch(err => {
        if (err instanceof DOMException && err.name === 'AbortError') return
        setStatus(null)
        setError(err instanceof Error ? err.message : '持续观测状态读取失败')
      })
    return () => controller.abort()
  }, [generation])

  return <div className="observation-page">
    <div className="page-heading"><div><h1>代理节点观测</h1><p>被动读取控制器状态；不测速、不切换节点、不修改 OpenClash</p></div><button className="secondary" onClick={() => { setError(''); setStatus(null); setGeneration(value => value + 1) }}><RefreshCw size={16}/>刷新</button></div>
    <section className="observation-boundary" role="status"><AlertCircle size={20}/><div><strong>延迟和控制器可达不等于业务可用</strong><span>没有独立探针证据的层级一律显示“未评估”，不会用历史绿色或演示数据补齐。</span></div></section>
    {error ? <section className="readiness-error" role="alert"><AlertCircle size={20}/><div><strong>无法读取持续观测状态</strong><span>{error}。旧状态已清除。</span></div></section> : null}
    {!status && !error ? <section className="panel readiness-loading" role="status"><CircleDashed size={24}/><strong>正在读取观测事实</strong></section> : null}
    {status ? <>
      <section className="observation-summary panel">
        <div><span>采集模式</span><strong>{status.configured ? '周期只读' : '未配置'}</strong></div>
        <div><span>调度器</span><strong>{status.running ? '运行中' : '已停止'}</strong></div>
        <div><span>证据状态</span><strong>{status.fresh ? '新鲜' : status.stale ? '已过期' : '未知'}</strong></div>
        <div><span>连续失败</span><strong>{status.consecutiveFailures}</strong></div>
      </section>
      <section className="observation-grid">
        <LayerCard title="Mihomo 控制器" layer={status.controller} icon={<Server size={20}/>}/>
        <LayerCard title="节点技术能力" layer={status.nodeTechnical} icon={<Database size={20}/>}/>
        <LayerCard title="互联网连通" layer={status.internet} icon={<Globe2 size={20}/>}/>
        <LayerCard title="具体业务能力" layer={status.business} icon={<Activity size={20}/>}/>
        <LayerCard title="DNS 路径" layer={status.dns} icon={<Globe2 size={20}/>}/>
        <LayerCard title="历史存储" layer={status.storage} icon={<Database size={20}/>}/>
        <LayerCard title="观测时钟" layer={status.clock} icon={<Activity size={20}/>}/>
      </section>
      <section className="panel observation-limitations"><h2>当前验收边界</h2><ul><li>只证明 Mihomo Controller 周期读取结果和证据新鲜度。</li><li>没有主动 HTTP、TLS、DNS 或业务探测，不给 ChatGPT、Gemini 等业务下可用结论。</li><li>完整历史属于管理明细，必须通过 TLS 或本机回环并完成身份授权。</li></ul></section>
    </> : null}
  </div>
}

