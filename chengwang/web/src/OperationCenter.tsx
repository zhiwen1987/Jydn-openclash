import { useCallback, useEffect, useRef, useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import {
  AlertCircle, CheckCircle2, ClipboardList, KeyRound, LockKeyhole, RefreshCw, ShieldCheck, Trash2,
} from 'lucide-react'
import { APIError, createOperation, getOperations, isManagementTransportSecure, transitionOperation } from './api'
import type { OperationEnvelope, OperationResource, OperationRisk, OperationStatus, OperationSummary } from './types'

const emptyResource: OperationResource = {
  tenantId: '', siteId: '', objectType: '', objectId: '', environment: 'shadow',
}

const riskLabels: Record<OperationRisk, string> = {
  low: '低风险', medium: '中风险', high: '高风险', critical: '关键风险',
}

const statusLabels: Record<OperationStatus, string> = {
  planned: '已计划', awaiting_approval: '等待独立审批', prechecking: '预检中', executing: '执行中',
  verifying: '验证中', observing: '观察中', succeeded: '成功', partial: '部分完成',
  rolled_back: '已回滚', failed: '失败', manual_takeover: '人工接管',
}

function newIdempotencyKey(kind: 'create' | 'transition'): string {
  if (!globalThis.crypto?.randomUUID) throw new Error('当前浏览器缺少安全随机数能力，无法生成幂等键')
  return `chengwang-ui-${kind}-${globalThis.crypto.randomUUID()}`
}

function formatTime(value: string): string {
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString('zh-CN', { hour12: false })
}

function errorBoundary(error: unknown): string {
  if (error instanceof APIError) return `HTTP ${error.status} · ${error.code} · ${error.message}`
  return error instanceof Error ? error.message : '本地操作请求失败'
}

function validate(resource: OperationResource, token: string): string {
  if (!token.trim()) return '请输入 Bearer 令牌；令牌仅保存在当前页面内存。'
  if (!resource.tenantId.trim() || !resource.environment.trim()) return 'tenant 与 environment 为必填范围。'
  return ''
}

type MutationResult = { envelope?: OperationEnvelope; error?: unknown }

export function OperationCenter() {
	const secureTransport = isManagementTransportSecure()
  const [resource, setResource] = useState<OperationResource>(emptyResource)
  const [token, setToken] = useState('')
  const [approverToken, setApproverToken] = useState('')
  const [risk, setRisk] = useState<OperationRisk>('low')
  const [targetVersion, setTargetVersion] = useState('')
  const [operations, setOperations] = useState<OperationSummary[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [mutating, setMutating] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])

  const load = useCallback(async (requestToken = token): Promise<boolean> => {
    const validation = validate(resource, requestToken)
    if (validation) {
      setError(validation)
      return false
    }
    setLoading(true)
    setError('')
    try {
      const result = await getOperations(resource, requestToken)
      if (!mounted.current) return false
      setOperations(result.operations ?? [])
      return true
    } catch (requestError) {
      if (!mounted.current) return false
      setOperations(null)
      setError(errorBoundary(requestError))
      return false
    } finally {
      if (mounted.current) setLoading(false)
    }
  }, [resource, token])

  async function reconcileAfterMutation(result: MutationResult, successText: string, readToken: string) {
    if (!mounted.current) return
    if (result.error) {
      const boundary = errorBoundary(result.error)
      setError(boundary)
      if (result.error instanceof APIError && result.error.status === 503) {
        setNotice(result.error.code === 'commit_unknown'
          ? '提交结果未知：未把响应当成成功，正在按当前范围重新读回；确认前请勿重复提交。'
          : '服务端返回 503：未把错误响应当成成功，正在按当前范围重新读回。')
        const readBack = await load(readToken)
        if (mounted.current) {
          setError(readBack ? boundary : `${boundary}；自动重新读回也失败，状态仍未确认。`)
        }
      }
      return
    }
    setNotice(successText)
    const readBack = await load(readToken)
    if (!readBack && mounted.current) {
      setNotice('写接口已返回成功，但列表重新读回失败；页面不确认最新状态。')
    }
  }

  async function submitCreate(event: FormEvent) {
    event.preventDefault()
    const validation = validate(resource, token)
    if (validation || !targetVersion.trim()) {
      setError(validation || '目标版本不能为空。')
      return
    }
    setMutating(true)
    setError('')
    setNotice('')
    let result: MutationResult
    try {
      result = { envelope: await createOperation(resource, risk, targetVersion.trim(), token, newIdempotencyKey('create')) }
    } catch (requestError) {
      result = { error: requestError }
    }
    const successText = result.envelope?.created === false
      ? '幂等响应：服务器复用了已有本地计划；已重新读回列表。'
      : '本地影子计划已记录；未执行任何设备动作，已重新读回列表。'
    await reconcileAfterMutation(result, successText, token)
    if (mounted.current) setMutating(false)
  }

  async function transition(item: OperationSummary, to: OperationStatus) {
    const usingApprover = item.status === 'awaiting_approval' && to === 'prechecking'
    const requestToken = usingApprover ? approverToken : token
    const validation = validate(resource, requestToken)
    if (validation) {
      setError(usingApprover ? '请输入独立审批人 Bearer 令牌；不能使用发起人令牌代替审批。' : validation)
      return
    }
    setMutating(true)
    setError('')
    setNotice('')
    let result: MutationResult
    try {
      result = { envelope: await transitionOperation(item.id, resource, to, requestToken, newIdempotencyKey('transition')) }
    } catch (requestError) {
      result = { error: requestError }
    }
    const replayed = result.envelope?.replayed === true
    await reconcileAfterMutation(
      result,
      replayed ? '幂等响应：服务器已记录相同转换；已重新读回列表。' : '本地状态转换已记录；未执行任何设备动作，已重新读回列表。',
      usingApprover ? token : requestToken,
    )
    if (mounted.current) setMutating(false)
  }

  function updateResource(field: keyof OperationResource, value: string) {
    setResource(current => ({ ...current, [field]: value }))
    setOperations(null)
    setError('')
    setNotice('范围已改变，请重新读取；旧列表已清除。')
  }

  function clearCredentials() {
    setToken('')
    setApproverToken('')
    setOperations(null)
    setError('')
    setNotice('内存中的全部令牌和读回列表已清除。')
  }

	function updateToken(value: string) {
		setToken(value)
		setApproverToken('')
		setOperations(null)
		setError('')
		setNotice('身份已改变，请重新读取；旧列表已清除。')
	}

  return <div className="operation-page">
    <div className="page-heading operation-heading">
      <div><h1>操作中心</h1><p><span className="unknown-dot"/>仅本地影子记录，不执行设备动作<span>所有变更以重新读回为准</span></p></div>
		<button className="secondary" onClick={() => void load()} disabled={loading || mutating || !secureTransport}><RefreshCw size={16}/>{loading ? '读取中…' : '读取操作'}</button>
    </div>

    <section className="operation-boundary" role="status"><LockKeyhole size={20}/><div><strong>执行器保持锁定</strong><span>本页只能创建计划并推进到预检状态；不会发布配置、切换节点、重启服务或执行设备动作。</span></div></section>
	{!secureTransport ? <section className="operation-feedback error" role="alert"><LockKeyhole size={18}/><div><strong>明文管理入口已锁定</strong><span>当前页面不是 HTTPS 或本机回环地址，浏览器不会发送任何 Bearer 令牌。</span></div></section> : null}

    <div className="operation-layout">
      <aside className="panel operation-controls">
        <div className="section-title"><div><h2>身份与资源范围</h2><p>身份令牌只保存在 React 内存，离开页面或点击清除即丢弃</p></div><KeyRound size={19}/></div>
        <div className="operation-control-body">
		<label className="operation-field full">Bearer 令牌<input aria-label="Bearer 令牌" type="password" autoComplete="off" value={token} disabled={!secureTransport} onChange={event => updateToken(event.target.value)} placeholder={secureTransport ? '输入读取或操作令牌' : '需使用 HTTPS 管理入口'}/></label>
          <button className="credential-clear" type="button" onClick={clearCredentials}><Trash2 size={15}/>清除令牌与列表</button>
          <div className="operation-scope-grid">
            <label className="operation-field">Tenant *<input aria-label="tenant" value={resource.tenantId} onChange={event => updateResource('tenantId', event.target.value)} /></label>
            <label className="operation-field">Site<input aria-label="site" value={resource.siteId} onChange={event => updateResource('siteId', event.target.value)} /></label>
            <label className="operation-field">对象类型<input aria-label="objectType" value={resource.objectType} onChange={event => updateResource('objectType', event.target.value)} /></label>
            <label className="operation-field">对象 ID<input aria-label="objectId" value={resource.objectId} onChange={event => updateResource('objectId', event.target.value)} /></label>
            <label className="operation-field full">Environment *<input aria-label="environment" value={resource.environment} onChange={event => updateResource('environment', event.target.value)} /></label>
          </div>
          <div className="credential-note"><ShieldCheck size={15}/><span>不写入 localStorage、sessionStorage、URL 或页面日志；请求只使用 Authorization 标头。</span></div>
        </div>

        <form className="operation-create" onSubmit={submitCreate}>
          <div><h2>创建本地计划</h2><p>每次点击都会生成新的安全幂等键。</p></div>
          <label className="operation-field">风险等级<select aria-label="风险等级" value={risk} onChange={event => setRisk(event.target.value as OperationRisk)}><option value="low">低风险</option><option value="medium">中风险</option><option value="high">高风险</option><option value="critical">关键风险</option></select></label>
          <label className="operation-field">目标版本 *<input aria-label="目标版本" value={targetVersion} onChange={event => setTargetVersion(event.target.value)} placeholder="例如配置版本或变更编号"/></label>
		<button className="primary" type="submit" disabled={mutating || !secureTransport}>{mutating ? '正在提交…' : '创建影子计划'}</button>
        </form>
      </aside>

      <section className="panel operation-list">
        <div className="section-title"><div><h2>当前范围的操作记录</h2><p>只显示服务端摘要，不读取或展示证据正文</p></div><span className="shadow-badge">LOCAL SHADOW</span></div>
        {error ? <div className="operation-feedback error" role="alert"><AlertCircle size={18}/><div><strong>请求未确认</strong><span>{error}</span></div></div> : null}
        {notice ? <div className="operation-feedback notice" role="status"><CheckCircle2 size={18}/><span>{notice}</span></div> : null}
        {operations === null && !loading ? <OperationEmpty icon={<ClipboardList/>} title="尚未读取操作记录" detail="填写身份和资源范围后点击“读取操作”；页面不会生成示例操作。"/> : null}
        {loading ? <OperationEmpty icon={<RefreshCw className="spin"/>} title="正在读取服务端摘要" detail="读取期间不会沿用其他范围的旧结果。"/> : null}
        {operations?.length === 0 && !loading ? <OperationEmpty icon={<ClipboardList/>} title="当前范围没有操作记录" detail="这是服务端返回的空列表，不是演示数据。"/> : null}
		{operations && operations.length > 0 && !loading ? <div className="table-scroll"><table className="operation-table"><thead><tr><th>操作 / 目标版本</th><th>风险</th><th>状态</th><th>更新时间</th><th>安全转换</th></tr></thead><tbody>{operations.map(item => <OperationRow key={item.id} item={item} disabled={mutating || !secureTransport} approverToken={approverToken} onApproverToken={value => { setApproverToken(value); setError(''); setNotice('') }} onTransition={transition}/>)}</tbody></table></div> : null}
      </section>
    </div>
  </div>
}

function OperationRow({ item, disabled, approverToken, onApproverToken, onTransition }: {
  item: OperationSummary
  disabled: boolean
  approverToken: string
  onApproverToken: (value: string) => void
  onTransition: (item: OperationSummary, to: OperationStatus) => void
}) {
  const needsApproval = item.status === 'awaiting_approval'
  const canRequestApproval = item.status === 'planned' && (item.risk === 'high' || item.risk === 'critical')
  const canPrecheck = item.status === 'planned' && (item.risk === 'low' || item.risk === 'medium')
  return <tr>
    <td><div className="operation-identity"><strong>{item.targetVersion}</strong><code>{item.id}</code><small>{item.identityBinding === 'durable' ? '身份已持久绑定' : '旧记录未绑定身份'}</small></div></td>
    <td><span className={`risk-label ${item.risk}`}>{riskLabels[item.risk]}</span></td>
    <td><span className={`operation-status ${item.status}`}>{statusLabels[item.status]}</span></td>
    <td>{formatTime(item.updatedAt)}</td>
    <td className="operation-actions">
      {canRequestApproval ? <button className="secondary" disabled={disabled} onClick={() => void onTransition(item, 'awaiting_approval')}>申请独立审批</button> : null}
      {canPrecheck ? <button className="secondary" disabled={disabled} onClick={() => void onTransition(item, 'prechecking')}>进入预检</button> : null}
      {needsApproval ? <div className="approval-action"><label>独立审批人令牌<input aria-label={`独立审批人令牌 ${item.id}`} type="password" autoComplete="off" value={approverToken} onChange={event => onApproverToken(event.target.value)} /></label><button className="secondary" disabled={disabled} onClick={() => void onTransition(item, 'prechecking')}>审批并进入预检</button></div> : null}
      {!canRequestApproval && !canPrecheck && !needsApproval ? <span className="no-transition">前端无可用转换</span> : null}
    </td>
  </tr>
}

function OperationEmpty({ icon, title, detail }: { icon: ReactNode; title: string; detail: string }) {
  return <div className="operation-empty">{icon}<strong>{title}</strong><span>{detail}</span></div>
}
