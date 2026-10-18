import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import {
  AlertCircle, CheckCircle2, ChevronDown, ChevronRight, CircleHelp, Database, FileDiff,
  RefreshCw, Router, ShieldCheck,
} from 'lucide-react'
import { APIError, getMihomoRuntime, isManagementTransportSecure, readbackMihomo } from './api'
import type { MihomoDrift, MihomoReadbackReport, MihomoRuntimeSnapshot, Snapshot } from './types'

type View = 'diff' | 'groups' | 'rules'

const driftLabels: Record<string, string> = {
  missing_proxy_group: '策略组缺失',
  group_members_mismatch: '成员或顺序漂移',
  missing_domain_rule: '域名规则缺失',
  rule_target_mismatch: '规则目标错误',
}

function errorMessage(error: unknown): { title: string; detail: string } {
  if (error instanceof APIError) {
    if (error.code === 'mihomo_not_configured') return { title: '尚未配置 Mihomo 控制器', detail: '设置 CHENGWANG_MIHOMO_URL 和本机令牌后重新读取。' }
    if (error.code === 'mihomo_auth_failed') return { title: '控制器鉴权失败', detail: '检查本机环境变量中的 Controller 令牌，不要把令牌填写到页面。' }
    if (error.code === 'mihomo_timeout') return { title: '控制器读取超时', detail: '当前证据不可用，系统不会把旧状态标记为正常。' }
    if (error.code === 'diagnostic_auth_not_configured') return { title: '安全诊断身份尚未配置', detail: '服务端未配置身份文件和管理范围，敏感运行态保持关闭。' }
    if (error.code === 'secure_transport_required') return { title: '需要安全连接', detail: '管理令牌不能通过局域网明文 HTTP 发送，请先启用 HTTPS。' }
    if (error.code === 'unauthorized' || error.code === 'management_token_required') return { title: '管理身份验证失败', detail: '请输入有效的管理令牌；令牌仅保存在当前页面内存中。' }
    return { title: '无法读取 Mihomo 状态', detail: error.message }
  }
  return { title: '无法读取 Mihomo 状态', detail: '控制面不可达或响应无效，请稍后重试。' }
}

function formatValue(value: unknown): string {
  if (value === undefined || value === null) return '未读取到'
  if (Array.isArray(value)) return value.length ? value.join(' → ') : '空列表'
  if (typeof value === 'object') return Object.entries(value as Record<string, unknown>).map(([key, item]) => `${key}: ${String(item)}`).join('；')
  return String(value)
}

function formatTime(value?: string): string {
  if (!value) return '尚未读取'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { hour12: false })
}

export function MihomoReadback({ snapshot }: { snapshot: Snapshot }) {
  const [runtime, setRuntime] = useState<MihomoRuntimeSnapshot | null>(null)
  const [report, setReport] = useState<MihomoReadbackReport | null>(null)
  const [view, setView] = useState<View>('diff')
  const [expanded, setExpanded] = useState('')
  const [token, setToken] = useState('')
  const [loading, setLoading] = useState(false)
  const [comparing, setComparing] = useState(false)
  const [error, setError] = useState<unknown>(null)
	const request = useRef<AbortController | null>(null)
	const secureTransport = isManagementTransportSecure()

	useEffect(() => () => request.current?.abort(), [])

	function resetForCredentialChange(value: string) {
		request.current?.abort()
		request.current = null
		setToken(value)
		setRuntime(null)
		setReport(null)
		setError(null)
		setLoading(false)
		setComparing(false)
	}

	async function loadRuntime() {
		if (!secureTransport) {
			setError(new APIError('管理令牌不能通过局域网明文 HTTP 发送', 426, 'secure_transport_required'))
			return
		}
    if (!token.trim()) {
      setError(new APIError('请输入管理令牌', 401, 'management_token_required'))
      return
    }
		request.current?.abort()
		const controller = new AbortController()
		request.current = controller
    setLoading(true)
    setError(null)
		setRuntime(null)
		setReport(null)
    try {
			setRuntime(await getMihomoRuntime(token, controller.signal))
    } catch (requestError) {
      if (!(requestError instanceof DOMException && requestError.name === 'AbortError')) setError(requestError)
    } finally {
			if (request.current === controller) {
				request.current = null
				setLoading(false)
			}
    }
  }

  async function compareDesiredState() {
		if (!secureTransport || !token.trim() || !runtime) {
			setError(new APIError('需要安全连接、管理令牌和最新运行态', secureTransport ? 401 : 426, secureTransport ? 'management_token_required' : 'secure_transport_required'))
			return
		}
		request.current?.abort()
		const controller = new AbortController()
		request.current = controller
    setComparing(true)
    setError(null)
		setReport(null)
    try {
			const result = await readbackMihomo(snapshot.draft, token, controller.signal)
      setReport(result)
      setView('diff')
    } catch (requestError) {
			if (!(requestError instanceof DOMException && requestError.name === 'AbortError')) setError(requestError)
    } finally {
			if (request.current === controller) {
				request.current = null
				setComparing(false)
			}
    }
  }

  const groups = runtime?.proxies.filter(proxy => proxy.all !== undefined) ?? []
	const canCompare = secureTransport && Boolean(token.trim()) && snapshot.draft.businesses.length > 0 && Boolean(runtime) && !loading && !comparing
  const currentError = error ? errorMessage(error) : null

  return <div className="readback-page">
    <div className="page-heading readback-heading">
      <div><h1>设备读回与差异</h1><p><span className={runtime ? 'healthy-dot' : 'unknown-dot'}/>{runtime ? 'Mihomo 实际状态已读取' : '敏感运行态需要安全诊断身份'}<span>用户提交值不会冒充设备生效值</span></p></div>
      <div className="actions">
		<label className="diagnostic-token"><span>管理令牌</span><input aria-label="管理令牌" type="password" autoComplete="off" value={token} disabled={!secureTransport} onChange={event => resetForCredentialChange(event.target.value)} placeholder={secureTransport ? '仅保存在当前页面内存' : '需使用 HTTPS 管理入口'} /></label>
		<button className="secondary" disabled={loading || !secureTransport} onClick={() => void loadRuntime()}><RefreshCw size={16}/>{loading ? '读取中…' : '刷新状态'}</button>
        <button className="primary" disabled={!canCompare} onClick={() => void compareDesiredState()}><FileDiff size={16}/>{comparing ? '对账中…' : '执行读回对账'}</button>
      </div>
    </div>

	{!secureTransport ? <div className="readback-alert warning" role="alert"><LockTransport/><div><strong>明文管理入口已锁定</strong><span>当前页面不是 HTTPS 或本机回环地址，浏览器不会发送任何管理令牌。请使用 HTTPS 管理入口。</span></div></div> : null}
    {currentError ? <div className="readback-alert error" role="alert"><AlertCircle size={19}/><div><strong>{currentError.title}</strong><span>{currentError.detail}</span></div><button className="secondary" onClick={() => void loadRuntime()}>重试</button></div> : null}
    {!snapshot.draft.businesses.length ? <div className="readback-alert warning"><CircleHelp size={19}/><div><strong>当前没有可对账的策略草稿</strong><span>先在策略路由中保存有效草稿；系统不会用空目标得出“一致”结论。</span></div></div> : null}

    <section className="readback-summary" aria-label="Mihomo 运行摘要">
      <Summary icon={<Router/>} label="控制器版本" value={runtime?.version.version ?? '未读取'} note={runtime?.version.meta ? 'Mihomo Meta' : '等待真实证据'} />
      <Summary icon={<ShieldCheck/>} label="运行模式" value={runtime?.config.mode ?? '未知'} note={runtime ? `LAN ${runtime.config.allowLan ? '允许' : '禁止'} · IPv6 ${runtime.config.ipv6 ? '开启' : '关闭'}` : '不使用演示状态'} />
      <Summary icon={<Database/>} label="策略组 / 规则" value={runtime ? `${groups.length} / ${runtime.rules.length}` : '— / —'} note="实际 Controller 读回" />
      <Summary icon={report?.match ? <CheckCircle2/> : <FileDiff/>} label="对账结论" value={report ? (report.match ? '完全一致' : `${report.drifts.length} 项漂移`) : '尚未对账'} note={report ? formatTime(report.observedAt) : '需使用当前草稿执行'} tone={report ? (report.match ? 'success' : 'danger') : undefined} />
    </section>

    <div className="readback-layout">
      <section className="panel readback-main">
        <div className="readback-tabs" role="tablist" aria-label="读回视图">
          <button role="tab" aria-selected={view === 'diff'} className={view === 'diff' ? 'active' : ''} onClick={() => setView('diff')}>差异对账 <b>{report?.drifts.length ?? 0}</b></button>
          <button role="tab" aria-selected={view === 'groups'} className={view === 'groups' ? 'active' : ''} onClick={() => setView('groups')}>实际策略组 <b>{groups.length}</b></button>
          <button role="tab" aria-selected={view === 'rules'} className={view === 'rules' ? 'active' : ''} onClick={() => setView('rules')}>实际规则 <b>{runtime?.rules.length ?? 0}</b></button>
        </div>
        {view === 'diff' ? <DriftTable report={report} expanded={expanded} onExpand={setExpanded}/> : null}
        {view === 'groups' ? <GroupTable runtime={runtime} groups={groups}/> : null}
        {view === 'rules' ? <RuleTable runtime={runtime}/> : null}
      </section>
      <ReadbackEvidence runtime={runtime} report={report}/>
    </div>
  </div>
}

function Summary({ icon, label, value, note, tone }: { icon: ReactNode; label: string; value: string; note: string; tone?: 'success' | 'danger' }) {
  return <div className={tone ? `summary-${tone}` : ''}>{icon}<span>{label}</span><strong>{value}</strong><small>{note}</small></div>
}

function DriftTable({ report, expanded, onExpand }: { report: MihomoReadbackReport | null; expanded: string; onExpand: (path: string) => void }) {
  if (!report) return <EmptyState title="尚未执行读回对账" detail="点击“执行读回对账”，系统将重新读取 Mihomo，再与当前策略草稿逐项比较。"/>
  if (report.match) return <EmptyState success title="目标与实际状态一致" detail="本次已检查的策略组和域名规则没有发现漂移；这不代表 DNS、TLS 或真实业务已经验证。"/>
  return <div className="table-scroll"><table className="drift-table"><thead><tr><th>配置项 / 路径</th><th>期望状态</th><th>实际读回</th><th>结论</th><th>详情</th></tr></thead><tbody>{report.drifts.map((drift, index) => {
    const key = `${drift.path}-${index}`
    const open = expanded === key
    return <DriftRows key={key} drift={drift} rowKey={key} open={open} onToggle={() => onExpand(open ? '' : key)}/>
  })}</tbody></table></div>
}

function DriftRows({ drift, rowKey, open, onToggle }: { drift: MihomoDrift; rowKey: string; open: boolean; onToggle: () => void }) {
  return <>
    <tr className="drift-row"><td><button aria-expanded={open} aria-controls={`detail-${rowKey}`} onClick={onToggle}>{open ? <ChevronDown size={15}/> : <ChevronRight size={15}/>}<span><strong>{driftLabels[drift.kind] ?? drift.kind}</strong><small>{drift.path}</small></span></button></td><td>{formatValue(drift.expected)}</td><td className="actual-mismatch">{formatValue(drift.actual)}</td><td><span className="drift-badge"><AlertCircle size={14}/>不一致</span></td><td><button className="text-action" onClick={onToggle}>{open ? '收起' : '查看'}</button></td></tr>
    {open ? <tr id={`detail-${rowKey}`} className="drift-detail"><td colSpan={5}><strong>设备读回说明</strong><span>{drift.message}</span><code>{drift.kind}</code><span>严重度：{drift.severity}</span></td></tr> : null}
  </>
}

function GroupTable({ runtime, groups }: { runtime: MihomoRuntimeSnapshot | null; groups: MihomoRuntimeSnapshot['proxies'] }) {
  if (!runtime) return <EmptyState title="尚未读取策略组" detail="刷新实际状态后显示 Controller 当前返回的策略组、选择结果和成员顺序。"/>
	const visibleGroups = groups.slice(0, 200)
	return <><div className="table-scroll"><table><thead><tr><th>策略组</th><th>类型</th><th>当前选择</th><th>成员数</th><th>成员顺序</th></tr></thead><tbody>{visibleGroups.map(group => <tr key={group.name}><td><strong>{group.name}</strong></td><td>{group.type}</td><td>{group.now || '未选择'}</td><td>{group.all?.length ?? 0}</td><td className="member-list">{group.all?.slice(0, 50).join(' → ') || '空组'}{(group.all?.length ?? 0) > 50 ? ' → …' : ''}</td></tr>)}</tbody></table></div>{groups.length > visibleGroups.length ? <div className="table-limit">为保持页面流畅，仅展示前 200 个策略组。</div> : null}</>
}

function LockTransport() {
	return <ShieldCheck size={19}/>
}

function RuleTable({ runtime }: { runtime: MihomoRuntimeSnapshot | null }) {
  if (!runtime) return <EmptyState title="尚未读取规则" detail="刷新实际状态后显示 Controller 当前正在使用的规则及其目标策略。"/>
  const visibleRules = runtime.rules.slice(0, 200)
  return <><div className="table-scroll"><table><thead><tr><th>#</th><th>规则类型</th><th>匹配内容</th><th>实际目标</th></tr></thead><tbody>{visibleRules.map((rule, index) => <tr key={`${rule.type}-${rule.payload}-${index}`}><td>{index + 1}</td><td>{rule.type}</td><td><code>{rule.payload || '—'}</code></td><td><strong>{rule.proxy}</strong></td></tr>)}</tbody></table></div>{runtime.rules.length > visibleRules.length ? <div className="table-limit">为保持页面流畅，仅展示前 200 条；对账仍使用全部 {runtime.rules.length} 条规则。</div> : null}</>
}

function ReadbackEvidence({ runtime, report }: { runtime: MihomoRuntimeSnapshot | null; report: MihomoReadbackReport | null }) {
  return <aside className="panel readback-evidence"><div className="section-title"><div><h2>证据与安全边界</h2><p>本页只展示独立设备读回</p></div><ShieldCheck size={20}/></div>
    <dl><dt>证据来源</dt><dd>Mihomo Controller API</dd><dt>最近读取</dt><dd>{formatTime(report?.observedAt ?? runtime?.observedAt)}</dd><dt>控制器版本</dt><dd>{report?.controllerVersion ?? runtime?.version.version ?? '未知'}</dd><dt>对账状态</dt><dd>{report ? (report.match ? '一致' : '发现漂移') : '未执行'}</dd></dl>
    <div className="evidence-counts"><strong>本次检查范围</strong><span>目标策略组 <b>{report?.counts.expectedGroups ?? '—'}</b></span><span>实际策略组 <b>{report?.counts.observedGroups ?? '—'}</b></span><span>目标域名规则 <b>{report?.counts.expectedRules ?? '—'}</b></span><span>实际规则 <b>{report?.counts.observedRules ?? runtime?.rules.length ?? '—'}</b></span></div>
    <div className="safety-boundary"><strong>当前不会执行</strong><span>重载配置或重启内核</span><span>切换代理节点</span><span>清理缓存</span><span>自动修复或回滚</span></div>
    <div className="evidence-note"><AlertCircle size={16}/><span>配置一致只证明已检查字段一致，不能替代 DNS、TCP、TLS、HTTP 和真实业务验证。</span></div>
  </aside>
}

function EmptyState({ title, detail, success }: { title: string; detail: string; success?: boolean }) {
  return <div className={success ? 'readback-empty success' : 'readback-empty'}>{success ? <CheckCircle2 size={34}/> : <FileDiff size={34}/>}<strong>{title}</strong><span>{detail}</span></div>
}
