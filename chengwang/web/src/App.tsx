import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import {
  Activity, AlertCircle, Bell, Bot, Cable, ChevronDown, CircleDollarSign, CloudCog, Database, Gauge,
  ClipboardList, FileDiff, GitBranch, Globe2, History, Home, LockKeyhole, MonitorDot,
  KeyRound, Network, Plus, RefreshCw, Route, Search, Server, Settings, ShieldCheck, SlidersHorizontal,
  Sparkles, Users, Wrench, X,
} from 'lucide-react'
import { getSnapshot, validateProxyInterfaces } from './api'
import { SNAPSHOT_FORMAT_ERROR } from './snapshot-report'
import type { BusinessPolicy, BusinessStatus, ProxyInterface, Snapshot, ValidationResult } from './types'
import { MihomoReadback } from './MihomoReadback'
import { SystemReadiness } from './SystemReadiness'
import { OperationCenter } from './OperationCenter'
import { ObservationStatus } from './ObservationStatus'
import ImageTrustConsole from './ImageTrustConsole'
import { Subscriptions } from './Subscriptions'
import { EvidenceOverview } from './EvidenceOverview'
import type { OverviewDisplayState } from './overview-types'

const nav = [
  { group: '流量控制', items: [['运行总览', Home], ['配置方案', SlidersHorizontal], ['代理节点', Database], ['代理接口', Cable], ['策略路由', Route], ['DNS', Globe2], ['连接与流量', Activity]] },
  { group: '资源管理', items: [['订阅与提供者', CloudCog], ['内核与协议', Gauge], ['设备读回', FileDiff], ['透明代理', GitBranch], ['自动化', Wrench]] },
  { group: '系统管理', items: [['操作中心', ClipboardList], ['可信策略', KeyRound], ['系统闭环', ShieldCheck], ['日志与诊断', MonitorDot], ['备份与恢复', History], ['系统设置', Settings]] },
] as const

const demoSnapshot: Snapshot = {
  product: '澄网 · 网络代理与路由平台', version: '尚未发布', mode: 'shadow', status: '演示快照 · 未配置 Mihomo 实时读回', dataSource: 'demo', publishLocked: true,
  businesses: [
    { id: 'chatgpt', name: '对话助手 (ChatGPT)', strategy: 'ChatGPT 专用节点池', activeRoute: '美国专用池', status: '正常' },
    { id: 'gemini', name: 'Gemini', strategy: 'Gemini 专用节点池', activeRoute: '新加坡专用池', status: '正常' },
    { id: 'domestic', name: '国内网站', strategy: 'DIRECT', activeRoute: '中国大陆', status: '正常' },
    { id: 'payments', name: '支付与交易', strategy: '固定出口', activeRoute: '国内固定出口', status: '已锁定' },
  ],
  pools: [
    { name: '美国专用池', region: '美国', latencyMs: 128, lossRate: .2, available: 8, total: 8, status: '正常' },
    { name: '新加坡专用池', region: '新加坡', latencyMs: 86, lossRate: .1, available: 6, total: 6, status: '正常' },
    { name: '日本专用池', region: '日本', latencyMs: 112, lossRate: .3, available: 5, total: 6, status: '正常' },
  ],
  interfaces: [
    { id: 'local_mixed', name: '本机 Mixed', type: 'mixed', core: 'Mihomo', listen: '127.0.0.1', port: 7890, udp: true, lanAccess: false, authMode: 'none', tls: false, accessScope: 'local', maxConnections: 512, idleTimeoutSec: 300, rateLimitMbps: 0, auditEnabled: true, enabled: true, status: '影子配置', routingProfile: '家庭主网', description: '为本机应用同时提供 HTTP 与 SOCKS5 代理。' },
    { id: 'lan_socks5', name: '局域网 SOCKS5', type: 'socks5', core: 'Mihomo', listen: '0.0.0.0', port: 7891, udp: true, lanAccess: true, authMode: 'password', authReference: 'lan-proxy-users', tls: false, accessScope: 'lan', allowedCidrs: ['10.88.0.0/24'], maxConnections: 256, idleTimeoutSec: 300, rateLimitMbps: 200, auditEnabled: true, enabled: false, status: '待部署', routingProfile: '家庭主网', description: '供可信局域网设备按账号访问。' },
    { id: 'control_api', name: '本机控制 API', type: 'api', core: 'Mihomo', listen: '127.0.0.1', port: 9090, udp: false, lanAccess: false, authMode: 'token', authReference: 'local-control-token', tls: false, accessScope: 'local', maxConnections: 64, idleTimeoutSec: 60, rateLimitMbps: 0, auditEnabled: true, enabled: false, status: '待部署', routingProfile: '家庭主网', description: '仅限本机控制面使用。' },
  ],
  events: [], draft: { name: '精准分流草稿', baseVersion: '', businesses: [], pools: [], dns: {} },
}

function App() {
  const [page, setPage] = useState('运行总览')
  const [snapshot, setSnapshot] = useState<Snapshot>(demoSnapshot)
  const [notice, setNotice] = useState('正在连接本地控制面…')
  const [overviewSource, setOverviewSource] = useState<'demo' | 'evidence'>('demo')
  const [overviewDisplay, setOverviewDisplay] = useState<OverviewDisplayState>({ state: 'pending', mode: null })

  const navigate = (nextPage: string) => {
    if (nextPage === page) return
    setOverviewDisplay({ state: 'pending', mode: null })
    setPage(nextPage)
  }
  const selectOverviewSource = (source: 'demo' | 'evidence') => {
    if (source === overviewSource) return
    setOverviewDisplay({ state: 'pending', mode: null })
    setOverviewSource(source)
  }
  const actualOverview = page === '运行总览' && overviewSource === 'evidence'

  useEffect(() => {
    const controller = new AbortController()
    getSnapshot(controller.signal)
      .then(data => {
        if (controller.signal.aborted) return
        if (!data || !['demo', 'live'].includes(data.dataSource)) {
          setNotice('演示模式：控制面数据源不受支持，尚未核验')
          return
        }
        setSnapshot(data)
        setNotice(data.dataSource === 'demo' ? '演示总览：实际状态请查看设备读回' : '控制面快照；实际运行与生产状态须独立核验')
      })
      .catch(reason => {
        if (controller.signal.aborted) return
        setNotice(reason instanceof Error && reason.message === SNAPSHOT_FORMAT_ERROR
          ? '演示模式：控制面快照格式不受支持，尚未核验'
          : '演示模式：无法读取本地控制面')
      })
    return () => controller.abort()
  }, [])

  return (
    <div className="app-shell">
      <TopBar snapshot={snapshot} actualOverview={actualOverview ? overviewDisplay : undefined} />
      <aside className="sidebar" aria-label="主导航">
        <nav>{nav.map(section => <div className="nav-group" key={section.group}><span className="nav-group-title">{section.group}</span>{section.items.map(([label, Icon]) => (
          <button key={label} aria-label={label} title={label} className={page === label ? 'nav-item active' : 'nav-item'} onClick={() => navigate(label)}>
            <Icon size={18} /><span>{label}</span>
          </button>
        ))}</div>)}</nav>
        <div className="mode-note"><ShieldCheck size={18}/><div><strong>安全运行</strong><span>{actualOverview ? '实际证据汇总仅展示已有观测，生产状态仍须独立核验' : notice}</span></div></div>
      </aside>
      <main className="main-content">
        {page === '运行总览' ? <>
          <div className="overview-source-switch" role="group" aria-label="总览数据源">
            <button type="button" className="secondary" aria-pressed={overviewSource === 'demo'} onClick={() => selectOverviewSource('demo')}>演示总览</button>
            <button type="button" className="secondary" aria-pressed={overviewSource === 'evidence'} onClick={() => selectOverviewSource('evidence')}>实际证据</button>
          </div>
          {actualOverview ? <EvidenceOverview onStateChange={setOverviewDisplay} onNavigate={navigate} /> : <Overview snapshot={snapshot} />}
        </> : page === '代理节点' ? <ObservationStatus /> : page === '代理接口' ? <ProxyInterfaces snapshot={snapshot} /> : page === '策略路由' ? <Policies snapshot={snapshot} /> : page === '内核与协议' ? <Kernels /> : page === '设备读回' ? <MihomoReadback snapshot={snapshot} /> : page === '操作中心' ? <OperationCenter /> : page === '可信策略' ? <ImageTrustConsole /> : page === '系统闭环' ? <SystemReadiness /> : page === '订阅与提供者' ? null : <EmptyPage page={page} />}
        {/* Keep uncertain command receipts in this memory session across navigation.
            The signed-out component does not make requests or retain a token. */}
        <div hidden={page !== '订阅与提供者'}><Subscriptions /></div>
      </main>
    </div>
  )
}

function TopBar({ snapshot, actualOverview }: { snapshot: Snapshot; actualOverview?: OverviewDisplayState }) {
  const demo = snapshot.dataSource === 'demo'
  const source = actualOverview ? (actualOverview.state === 'ready' ? '实际证据汇总' : '实际证据 · 未核验') : (demo ? '演示草稿' : '控制面快照')
  const mode = actualOverview ? (actualOverview.state === 'ready' ? actualOverview.mode ?? '未核验' : '未核验') : snapshot.mode
  return <header className="topbar">
    <div className="brand"><div className="brand-mark"><Network size={23}/></div><strong>{snapshot.product}</strong></div>
    <div className="version">来源 <b>{source}</b><span>内核</span><b>未核验</b><span>控制面模式</span><b>{mode}</b></div>
    <label className="command"><Search size={17}/><input aria-label="全局搜索" placeholder="全局搜索尚未接入" disabled/><kbd>Ctrl K</kbd></label>
    <button className="freeze" disabled title="冻结执行器尚未接入"><LockKeyhole size={16}/>安全冻结<ChevronDown size={15}/></button>
    <button className="icon-button" aria-label="通知" disabled title="通知中心尚未接入"><Bell size={19}/></button>
    <div className="avatar">管</div>
  </header>
}

function Overview({ snapshot }: { snapshot: Snapshot }) {
  if (snapshot.dataSource === 'demo') return <DemoOverview snapshot={snapshot}/>
  return <>
    <div className="page-heading"><div><h1>运行总览</h1><p><span className="unknown-dot"/>{snapshot.status}<span>控制面上报字段，尚无独立运行态观测时间</span></p></div><button className="secondary" disabled title="运行态刷新尚未接入"><RefreshCw size={16}/>刷新</button></div>
    <div className="core-strip">
      <div><Gauge/><span>当前内核</span><strong>未核验</strong><Status value="未知"/></div>
      <div><Route/><span>流量路由</span><strong>未核验</strong><Status value="未知"/></div>
      <div><Globe2/><span>DNS 状态</span><strong>未核验</strong><Status value="未知"/></div>
      <div><CloudCog/><span>订阅运行状态</span><strong>未核验</strong><Status value="未知"/></div>
    </div>
    <section className="panel topology-panel">
      <div className="section-title"><div><h2>流量拓扑尚未接入</h2><p>当前快照不含设备、入站、DNS 或出口的实际观测；不生成模拟流量路径。</p></div><button className="text-action" disabled>查看拓扑详情</button></div>
    </section>
    <div className="overview-grid">
      <BusinessTable businesses={snapshot.businesses}/>
      <PoolTable pools={snapshot.pools}/>
      <section className="panel dns-panel"><div className="section-title"><h2>DNS 健康未核验</h2></div><p>缺少独立解析与泄漏观测，不显示示例延迟或正常结论。</p></section>
    </div>
    <Events events={snapshot.events}/>
  </>
}

function DemoOverview({ snapshot }: { snapshot: Snapshot }) {
  const boundaries = [
    ['Mihomo 运行状态', '已提供独立只读接口', '前往“设备读回”查看实时证据'],
    ['业务分流状态', '尚未接入实际数据', '不显示模拟正常或模拟故障'],
    ['节点能力评估', '尚未接入实际探测器', '不生成虚构延迟、丢包和可用率'],
    ['DNS 健康状态', '尚未接入实际探测器', '不生成虚构解析耗时和泄漏结论'],
    ['自动化与拓扑', '当前仅有产品设计', '不冒充已执行动作或实时流量路径'],
  ]
  return <>
    <div className="page-heading"><div><h1>运行总览</h1><p><span className="unknown-dot"/>{snapshot.status}<span>总览仅展示数据边界；执行权限以服务端授权为准</span></p></div><button className="secondary" disabled title="运行态刷新尚未接入"><RefreshCw size={16}/>刷新</button></div>
    <div className="demo-source-alert" role="alert"><AlertCircle size={19}/><div><strong>当前总览没有接入真实运行数据</strong><span>为防止把界面示例误认为生产状态，本页已隐藏设备数量、订阅数量、业务健康、节点延迟、DNS 延迟和自动化事件等演示值。</span></div></div>
    <div className="core-strip evidence-strip">
      <div><ShieldCheck/><span>控制面模式</span><strong>{snapshot.mode}</strong><Status value="总览只读"/></div>
      <div><FileDiff/><span>真实设备证据</span><strong>设备读回</strong><Status value="可查看"/></div>
      <div><Activity/><span>业务评估</span><strong>未接入</strong><Status value="未知"/></div>
      <div><Globe2/><span>DNS 评估</span><strong>未接入</strong><Status value="未知"/></div>
    </div>
    <section className="panel truth-boundary-panel"><div className="section-title"><div><h2>当前数据边界</h2><p>只有具备独立数据来源的结果才会标记为真实状态</p></div><span className="demo-badge">演示总览</span></div>
      <table><thead><tr><th>能力域</th><th>当前证据</th><th>界面处理</th></tr></thead><tbody>{boundaries.map(row => <tr key={row[0]}><td><strong>{row[0]}</strong></td><td>{row[1]}</td><td>{row[2]}</td></tr>)}</tbody></table>
      <div className="evidence-note"><AlertCircle size={16}/><span>“设备读回”仅证明 Mihomo 控制器返回的配置与状态，不等于 DNS、TCP、TLS、HTTP 或具体业务端到端可用。</span></div>
    </section>
  </>
}

function BusinessTable({ businesses }: { businesses: BusinessStatus[] }) {
  const icons = [Bot, Sparkles, Globe2, CircleDollarSign]
  return <section className="panel business-panel"><div className="section-title"><h2>快照上报业务（未独立核验）</h2><button className="text-action" disabled>全部业务</button></div>
    <table><thead><tr><th>业务 / 应用</th><th>分流策略</th><th>使用节点 / 出口</th><th>状态</th></tr></thead><tbody>{businesses.map((item, index) => { const Icon = icons[index] ?? Activity; return <tr key={item.id}><td><Icon size={18}/><strong>{item.name}</strong></td><td>{item.strategy}</td><td>{item.activeRoute}</td><td><Status value={item.status}/></td></tr> })}</tbody></table>
  </section>
}

function PoolTable({ pools }: { pools: Snapshot['pools'] }) {
  return <section className="panel pool-panel"><div className="section-title"><h2>快照上报节点（未独立核验）</h2><button className="text-action" disabled>测试全部</button></div><table><thead><tr><th>节点池</th><th>上报延迟</th><th>上报丢包</th><th>上报可用</th></tr></thead><tbody>{pools.map(pool => <tr key={JSON.stringify([pool.name, pool.region])}><td><strong>{pool.name}</strong><small> · {pool.region}</small></td><td>{pool.latencyMs} ms</td><td>{pool.lossRate}%</td><td><Status value={`${pool.available}/${pool.total}`}/></td></tr>)}</tbody></table></section>
}

function Events({ events }: { events: Snapshot['events'] }) {
  return <section className="panel event-panel"><div className="section-title"><h2>控制面上报事件</h2><button className="text-action" disabled>全部事件</button></div>{events.length === 0 ? <p>暂无已读取事件</p> : <table><thead><tr><th>时间</th><th>事件</th><th>原因与详情</th><th>处理结果</th></tr></thead><tbody>{events.map((event, i) => <tr key={`${event.at}-${i}`}><td>{new Date(event.at).toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit'})}</td><td><strong>{event.type}</strong></td><td>{event.reason}</td><td><Status value={event.result}/></td></tr>)}</tbody></table>}</section>
}

const routingRows = [
  ['1','安全与强制规则','LAN 直连 / 管理地址 / 黑名单','REJECT / DIRECT','正常'],
  ['2','自定义业务','支付与交易 · alipay.com / wechatpay.com','固定出口','正常'],
  ['3','自定义业务','对话助手 (ChatGPT) · chatgpt.com / openai.com','AI 专用池','1 条提示'],
  ['4','自定义业务','Gemini · gemini.google.com','Gemini 专用池','正常'],
  ['5','国内精确规则','.cn / 中国 ASN / 国内 IP','DIRECT','正常'],
  ['6','国外业务规则','Netflix / YouTube / Disney+','流媒体池','正常'],
  ['7','区域与网络规则','GeoIP / ASN / 指定国家或地区','按区域选择','正常'],
  ['8','最终兜底','所有未命中的流量','默认策略','正常'],
]

function Policies({ snapshot }: { snapshot: Snapshot }) {
  const seeded = snapshot.draft.businesses.length ? snapshot.draft.businesses : fallbackPolicies()
  const selected = seeded[0]
  const [validated, setValidated] = useState(false)
  const choices = useMemo(() => ['默认策略','DIRECT','REJECT','稳定自动','自动选择','手动选择','ChatGPT 专用节点池','香港','台湾','日本','新加坡','韩国','美国','英国','德国'], [])
  return <div className="policy-layout precise"><div className="policy-main">
    <div className="page-heading"><div><h1>策略路由</h1><p>自定义业务优先匹配，国内、国外和区域规则依次兜底，每次决策都有命中证据。</p></div><div className="actions"><button className="secondary">测试流量</button><button className="secondary" onClick={() => setValidated(true)}>验证草稿</button><button className="primary" disabled={!validated || snapshot.publishLocked}>发布变更</button></div></div>
    <section className="panel layer-table"><table><thead><tr><th>优先级</th><th>层级</th><th>匹配来源（示例）</th><th>执行动作</th><th>冲突检查</th><th>启用</th></tr></thead><tbody>{routingRows.map((row,index)=><tr key={row[0]} className={index===2?'selected':''}>{row.map((cell,i)=><td key={cell}>{i===0?<b className="priority">{cell}</b>:i===1||i===3?<strong>{cell}</strong>:i===4?<Status value={cell}/>:cell}</td>)}<td><input type="checkbox" defaultChecked aria-label={`启用 ${row[1]} ${row[0]}`}/></td></tr>)}</tbody></table></section>
    <TrafficSimulator validated={validated} onValidate={() => setValidated(true)}/>
  </div><PolicyInspector policy={selected} choices={choices}/></div>
}

function TrafficSimulator({ validated, onValidate }: { validated: boolean; onValidate: () => void }) {
  return <section className="simulator"><div className="simulator-heading"><div><h2>流量决策模拟器</h2><p>输入源设备、域名或 IP，查看实际路由决策及全部命中证据。</p></div><button className="primary">开始模拟</button></div>
    <div className="simulator-inputs"><label>源设备<select defaultValue="pc"><option value="pc">我的电脑（192.168.1.100）</option></select></label><label>域名 / IP<input defaultValue="chatgpt.com"/></label><label>端口<input defaultValue="443"/></label><label>协议<select defaultValue="tcp"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label>进程 / 应用<input defaultValue="chrome.exe"/></label></div>
    <div className="decision-grid"><div className="decision-result"><strong>模拟结果</strong><p><b>chatgpt.com</b><span>→</span>自定义业务 / 对话助手<span>→</span>AI 专用池<span>→</span><b>美国节点</b></p></div><div className="evidence"><strong>命中证据</strong><ol><li>域名后缀：chatgpt.com</li><li>GeoSite：openai</li><li>规则层级：自定义业务</li></ol></div><div className="conflicts"><strong>冲突检查</strong><p>1 条阴影规则提示</p><p>无不可达规则</p></div></div>
    <div className={`preflight ${validated?'done':''}`}><span>发布前校验：结构 · 悬空引用 · 循环 · 空节点池 · DNS 冲突 · 内核兼容</span><button className="secondary" onClick={onValidate}>{validated?'校验通过':'开始校验'}</button></div>
  </section>
}

function PolicyInspector({ policy, choices }: { policy: BusinessPolicy; choices: string[] }) {
  const [strategy, setStrategy] = useState(policy.strategy)
  const matchRows = [['域名后缀','chatgpt.com'],['域名后缀','openai.com'],['域名关键字','openai'],['GeoSite','openai']]
  return <aside className="inspector precise-inspector"><div className="inspector-title"><div><span>编辑业务规则</span><h2>{policy.name}</h2></div><SlidersHorizontal size={19}/></div>
    <fieldset><legend>规则信息</legend><label className="stacked">名称<input defaultValue={policy.name}/></label><label className="stacked">描述<input defaultValue="OpenAI 对话服务及相关域名"/></label></fieldset>
    <fieldset><legend>匹配条件</legend><div className="logic-switch"><button>AND（同时满足）</button><button className="active">OR（任一满足）</button></div>{matchRows.map(([type,value])=><div className="condition" key={type+value}><select defaultValue={type}><option>{type}</option><option>IP CIDR</option><option>ASN</option><option>来源设备</option><option>目标端口</option><option>进程 / 应用</option></select><input defaultValue={value}/></div>)}<button className="text-action">＋ 添加条件</button></fieldset>
    <fieldset><legend>执行动作</legend><select value={strategy} onChange={e => setStrategy(e.target.value)}>{choices.map(x => <option key={x}>{x}</option>)}</select></fieldset>
    <fieldset><legend>高级选项</legend><label className="checkbox"><input type="checkbox" defaultChecked/>会话保持</label><label className="checkbox"><input type="checkbox" defaultChecked/>跳过空节点池</label><label className="checkbox"><input type="checkbox" defaultChecked/>失败后回退上一稳定节点</label></fieldset>
    <fieldset><legend>故障条件</legend><div className="form-pair"><label>连续失败次数<input type="number" defaultValue={policy.failuresToSwitch}/></label><label>检测间隔（秒）<input type="number" defaultValue={policy.probeIntervalSec}/></label></div></fieldset>
    <div className="inspector-actions"><button className="secondary">放弃修改</button><button className="primary">保存草稿</button></div>
  </aside>
}

const blankProxyInterface: ProxyInterface = {
  id: 'new_proxy_service', name: '新代理服务', type: 'socks5', core: 'Mihomo', listen: '0.0.0.0', port: 7893,
  udp: true, lanAccess: true, authMode: 'password', authReference: 'lan-proxy-users', tls: false,
  accessScope: 'lan', allowedCidrs: ['10.88.0.0/24'], maxConnections: 256, idleTimeoutSec: 300,
  rateLimitMbps: 0, auditEnabled: true, enabled: false, status: '草稿', routingProfile: '家庭主网',
  description: '新建代理服务端入站；保存后仍需通过校验和数据面适配才能启用。',
}

const proxyTypeNames: Record<ProxyInterface['type'], string> = {
  http: 'HTTP', socks5: 'SOCKS5', mixed: 'Mixed', tun: 'TUN', tproxy: 'TProxy', redirect: 'Redirect', api: '控制 API',
}

function ProxyInterfaces({ snapshot }: { snapshot: Snapshot }) {
  const [selectedID, setSelectedID] = useState(snapshot.interfaces[0]?.id ?? '')
  const [created, setCreated] = useState<ProxyInterface[]>([])
  const [overrides, setOverrides] = useState<Record<string, ProxyInterface>>({})
  const [creating, setCreating] = useState(false)
  const [checking, setChecking] = useState(false)
  const [validation, setValidation] = useState<ValidationResult | null>(null)
  const [saved, setSaved] = useState('')
  const interfaces = [...snapshot.interfaces.map(item => overrides[item.id] ?? item), ...created]
  const selected = interfaces.find(item => item.id === selectedID) ?? interfaces[0] ?? blankProxyInterface
  const editor = creating ? blankProxyInterface : selected
  const lanServices = interfaces.filter(item => item.lanAccess).length
  const enabledServices = interfaces.filter(item => item.enabled).length

  async function checkInterfaces() {
    setChecking(true)
    setSaved('')
    try {
      setValidation(await validateProxyInterfaces(interfaces))
    } catch {
      setValidation({ valid: false, issues: [{ code: 'control_plane_unavailable', severity: 'error', path: '', message: '本地控制面不可用，未完成服务端校验' }] })
    } finally {
      setChecking(false)
    }
  }

  function saveDraft(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const type = String(data.get('type')) as ProxyInterface['type']
    const authMode = String(data.get('authMode')) as ProxyInterface['authMode']
    const accessScope = String(data.get('accessScope')) as ProxyInterface['accessScope']
    const next: ProxyInterface = {
      ...editor,
      id: String(data.get('id')).trim(), name: String(data.get('name')).trim(), type,
      core: String(data.get('core')), listen: String(data.get('listen')).trim(),
      port: type === 'tun' ? 0 : Number(data.get('port')), udp: data.get('udp') === 'on',
      lanAccess: data.get('lanAccess') === 'on', authMode,
      authReference: authMode === 'none' ? undefined : String(data.get('authReference')).trim(),
      tls: data.get('tls') === 'on', tlsReference: data.get('tls') === 'on' ? String(data.get('tlsReference')).trim() : undefined,
      accessScope, allowedCidrs: String(data.get('allowedCidrs')).split(/[,\n]/).map(value => value.trim()).filter(Boolean),
      maxConnections: Number(data.get('maxConnections')), idleTimeoutSec: Number(data.get('idleTimeoutSec')),
      rateLimitMbps: Number(data.get('rateLimitMbps')), auditEnabled: data.get('auditEnabled') === 'on',
      enabled: false, status: '草稿', routingProfile: String(data.get('routingProfile')).trim(),
      description: String(data.get('description')).trim(),
    }
    if (creating) {
      setCreated(current => [...current.filter(item => item.id !== next.id), next])
      setSelectedID(next.id)
      setCreating(false)
    } else {
      setOverrides(current => ({ ...current, [next.id]: next }))
    }
    setValidation(null)
    setSaved('草稿已保存在本次会话，尚未应用到任何数据面。')
  }

  return <div className="proxy-page">
    <div className="page-heading"><div><h1>代理接口</h1><p>统一管理应用代理、透明入站和控制 API，并为局域网客户端提供受控代理服务。</p></div><div className="actions"><button className="secondary" onClick={checkInterfaces} disabled={checking}>{checking ? '正在校验…' : '端口与安全检查'}</button><button className="primary" onClick={() => { setCreating(true); setSaved('') }}><Plus size={16}/>新增代理服务</button></div></div>
    <div className="proxy-summary">
      <div><Cable/><span>接口总数</span><strong>{interfaces.length}</strong><small>应用代理与透明入站</small></div>
      <div><Server/><span>影子启用</span><strong>{enabledServices}</strong><small>未绑定真实数据面</small></div>
      <div><Users/><span>局域网服务</span><strong>{lanServices}</strong><small>必须经过认证与 ACL</small></div>
      <div><ShieldCheck/><span>发布状态</span><strong>{snapshot.publishLocked ? '已冻结' : '可发布'}</strong><small>{snapshot.publishLocked ? '不会监听或修改现网' : '仍需发布前检查'}</small></div>
    </div>
    {validation ? <div className={`proxy-validation ${validation.valid ? 'valid' : 'invalid'}`} role="status"><ShieldCheck size={17}/><strong>{validation.valid ? '校验通过' : `发现 ${validation.issues.length} 个问题`}</strong><span>{validation.valid ? '端口、认证、ACL 和内核能力检查通过；仍未执行部署。' : validation.issues[0]?.message}</span></div> : null}
    {saved ? <div className="proxy-draft-note" role="status">{saved}</div> : null}
    <div className="proxy-layout">
      <section className="panel proxy-table"><div className="section-title"><div><h2>入站与服务端</h2><p>HTTP / SOCKS5 / Mixed 供客户端连接，TUN / TProxy / Redirect 用于透明接管</p></div><span className="shadow-badge">SHADOW</span></div>
        <div className="table-scroll"><table><thead><tr><th>名称</th><th>类型</th><th>监听</th><th>内核</th><th>访问范围</th><th>认证</th><th>状态</th></tr></thead><tbody>{interfaces.map(item => <tr key={item.id} className={!creating && item.id === selected.id ? 'selected' : ''} onClick={() => { setSelectedID(item.id); setCreating(false); setSaved('') }}>
          <td><button className="row-select" aria-label={`编辑 ${item.name}`}><strong>{item.name}</strong><small>{item.id}</small></button></td>
          <td><span className="protocol-badge">{proxyTypeNames[item.type]}</span>{item.udp ? <small>UDP</small> : null}</td>
          <td><code>{item.type === 'tun' ? item.listen : `${item.listen}:${item.port}`}</code></td><td>{item.core}</td>
          <td>{item.accessScope === 'local' ? '仅本机' : item.accessScope === 'lan' ? '局域网' : item.accessScope === 'vpn' ? 'VPN' : '自定义'}</td>
          <td>{item.authMode === 'none' ? '无需认证' : item.authMode === 'password' ? '账号密码' : item.authMode === 'token' ? 'Token' : 'mTLS'}</td><td><Status value={item.status}/></td>
        </tr>)}</tbody></table></div>
      </section>
      <aside className="panel proxy-editor">
        <div className="inspector-title"><div><span>{creating ? '创建服务端入站' : '接口与服务策略'}</span><h2>{creating ? '新增代理服务' : selected.name}</h2></div>{creating ? <button className="icon-button" aria-label="取消新增" onClick={() => setCreating(false)}><X size={18}/></button> : <KeyRound size={19}/>}</div>
        <form key={creating ? 'new' : selected.id} onSubmit={saveDraft}>
          <fieldset><legend>基本信息</legend><div className="form-pair"><label>接口 ID<input name="id" defaultValue={editor.id} readOnly={!creating}/></label><label>显示名称<input name="name" defaultValue={editor.name}/></label></div><div className="form-pair"><label>入站类型<select name="type" defaultValue={editor.type}>{Object.entries(proxyTypeNames).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label><label>数据面内核<select name="core" defaultValue={editor.core}><option>Mihomo</option><option>sing-box</option><option>Xray</option></select></label></div></fieldset>
          <fieldset><legend>监听与路由</legend><div className="form-pair"><label>监听地址 / 设备<input name="listen" defaultValue={editor.listen}/></label><label>端口（TUN 留空）<input name="port" type="number" min="0" max="65535" defaultValue={editor.port}/></label></div><label className="stacked">路由方案<input name="routingProfile" defaultValue={editor.routingProfile}/></label><div className="check-row"><label><input name="udp" type="checkbox" defaultChecked={editor.udp}/>UDP</label><label><input name="lanAccess" type="checkbox" defaultChecked={editor.lanAccess}/>允许局域网访问</label></div></fieldset>
          <fieldset><legend>服务端安全</legend><div className="form-pair"><label>认证<select name="authMode" defaultValue={editor.authMode}><option value="none">无需认证</option><option value="password">账号密码</option><option value="token">Token</option><option value="mtls">mTLS</option></select></label><label>凭据引用<input name="authReference" defaultValue={editor.authReference ?? ''} placeholder="只填写密钥库引用"/></label></div><div className="form-pair"><label>访问范围<select name="accessScope" defaultValue={editor.accessScope}><option value="local">仅本机</option><option value="lan">局域网</option><option value="vpn">VPN</option><option value="custom">自定义 CIDR</option></select></label><label>允许网段<input name="allowedCidrs" defaultValue={editor.allowedCidrs?.join(', ') ?? ''} placeholder="10.88.0.0/24"/></label></div><div className="check-row"><label><input name="tls" type="checkbox" defaultChecked={editor.tls}/>启用 TLS</label><label><input name="auditEnabled" type="checkbox" defaultChecked={editor.auditEnabled}/>记录安全审计</label></div><label className="stacked">证书引用<input name="tlsReference" defaultValue={editor.tlsReference ?? ''} placeholder="启用 TLS 时必填"/></label></fieldset>
          <fieldset><legend>容量与保护</legend><div className="form-triple"><label>最大连接数<input name="maxConnections" type="number" min="0" defaultValue={editor.maxConnections}/></label><label>空闲超时（秒）<input name="idleTimeoutSec" type="number" min="0" defaultValue={editor.idleTimeoutSec}/></label><label>限速（Mbps）<input name="rateLimitMbps" type="number" min="0" defaultValue={editor.rateLimitMbps}/></label></div><label className="stacked">说明<textarea name="description" defaultValue={editor.description}/></label></fieldset>
          <div className="proxy-security-note"><ShieldCheck size={16}/><span>局域网应用代理强制认证；控制 API 对外开放时强制 TLS + Token/mTLS。任何凭据都不会写入快照。</span></div>
          <div className="inspector-actions"><button type="button" className="secondary" onClick={() => setCreating(false)}>放弃修改</button><button type="submit" className="primary">保存草稿</button><button type="button" className="primary" disabled={snapshot.publishLocked}>应用到数据面</button></div>
        </form>
      </aside>
    </div>
  </div>
}

const capabilityRows = [
  ['Shadowsocks','原生','原生','适配'], ['VMess','适配','适配','原生'], ['VLESS','原生','原生','原生'],
  ['Trojan','原生','原生','原生'], ['Hysteria2','适配','原生','不支持'], ['TUIC','适配','原生','不支持'],
  ['AnyTLS','适配','原生','不支持'], ['WireGuard','适配','原生','适配'], ['TUN / TProxy','原生','原生','适配'],
  ['Rule Provider','原生','适配','适配'], ['DNS 分流','原生','原生','适配'], ['链式代理','原生','原生','原生'],
]

function Kernels() {
  const kernels = [
    ['Mihomo','未核验','只读适配','未核验','实际状态请显式进入设备读回'],
    ['sing-box','未核验','适配目标','尚未实现','现代多协议与独立 DNS（规划）'],
    ['Xray','未核验','适配目标','尚未实现','VMess / VLESS / Reality（规划）'],
    ['Hysteria','未核验','适配目标','尚未实现','Hysteria2 / QUIC（规划）'],
  ]
  return <div className="kernel-page"><div className="page-heading"><div><h1>内核与协议</h1><p>适配规划；尚无主机安装库存或实例运行证据。下列操作未接执行器，保持禁用。</p></div><div className="actions"><button className="secondary" disabled>检查更新</button><button className="secondary" disabled>导入内核</button><button className="primary" disabled>新增运行实例</button></div></div>
    <section className="panel kernel-table"><div className="section-title"><h2>内核适配目标</h2><button className="text-action" disabled>管理版本</button></div><table><thead><tr><th>内核</th><th>版本证据</th><th>实现范围</th><th>实例状态</th><th>当前边界</th></tr></thead><tbody>{kernels.map((row,index)=><tr className={index===0?'selected':''} key={row[0]}>{row.map((cell,i)=><td key={`${i}-${cell}`}>{i===0?<strong>{cell}</strong>:i===3?<Status value={cell}/>:cell}</td>)}</tr>)}</tbody></table></section>
    <div className="kernel-grid"><section className="panel capability"><div className="section-title"><div><h2>能力矩阵</h2><p>参考规划，目标版本尚未逐项实测；不表示已安装或当前可用。</p></div><button className="text-action" disabled>对比所选内核</button></div><table><thead><tr><th>功能</th><th>Mihomo</th><th>sing-box</th><th>Xray</th></tr></thead><tbody>{capabilityRows.map(row=><tr key={row[0]}>{row.map((cell,i)=><td key={cell+i}>{i===0?<strong>{cell}</strong>:<span className="support pending"><i/>待核验（参考：{cell}）</span>}</td>)}</tr>)}</tbody></table></section>
      <aside className="panel instance"><div className="section-title"><h2>Mihomo 实例证据</h2><Status value="未核验"/></div><dl><dt>可执行文件</dt><dd>未核验，发现适配器尚未接入</dd><dt>完整性校验</dt><dd>尚未执行</dd><dt>配置绑定</dt><dd>未接入</dd><dt>监听接口</dt><dd>未核验</dd><dt>重启与回滚</dt><dd>执行器尚未实现</dd><dt>业务健康</dt><dd>需独立业务探测，不由控制器配置推导</dd></dl><div className="instance-actions"><button className="secondary" disabled>启动并行实例</button><button className="primary" disabled>切换默认内核</button></div></aside>
    </div><section className="panel lifecycle"><div className="section-title"><h2>适配器生命周期（设计目标，尚未执行）</h2></div><div>{['发现内核','能力协商','隔离编译','语法检查','沙箱冒烟','灰度验证','正式启用','回滚预案'].map((item,index)=><span key={item}><b>{index+1}</b>{item}</span>)}</div></section>
  </div>
}

function Status({ value }: { value: string }) { return <span className={value.includes('锁') ? 'status locked' : 'status neutral'}><i/>{value}</span> }

function EmptyPage({ page }: { page: string }) { return <div className="empty-page"><Gauge size={40}/><h1>{page}</h1><p>该模块将在独立适配器阶段接入。当前不会读取或修改生产环境。</p></div> }

function fallbackPolicies(): BusinessPolicy[] { return [
  { id:'chatgpt', name:'对话助手 (ChatGPT)', domains:['chatgpt.com','openai.com','oaistatic.com'], strategy:'ChatGPT 专用节点池', candidates:['美国','日本','新加坡','稳定自动','DIRECT'], fallback:'previous_stable', skipEmptyPools:true, failuresToSwitch:3, probeIntervalSec:30, sessionStickyMin:30, switchCooldownSec:300 },
  { id:'gemini', name:'Gemini', domains:['gemini.google.com','generativelanguage.googleapis.com'], strategy:'自动选择', candidates:['香港','美国','日本'], fallback:'previous_stable', skipEmptyPools:true, failuresToSwitch:3, probeIntervalSec:30, sessionStickyMin:30, switchCooldownSec:300 },
  { id:'domestic', name:'国内网站', domains:['cn'], strategy:'DIRECT', candidates:['DIRECT'], fallback:'DIRECT', skipEmptyPools:true, failuresToSwitch:3, probeIntervalSec:60, sessionStickyMin:30, switchCooldownSec:300 },
  { id:'payments', name:'支付与交易', domains:['paypal.com'], strategy:'DIRECT', candidates:['DIRECT'], fallback:'DIRECT', skipEmptyPools:true, failuresToSwitch:5, probeIntervalSec:60, sessionStickyMin:1440, switchCooldownSec:1800 },
] }

export default App
