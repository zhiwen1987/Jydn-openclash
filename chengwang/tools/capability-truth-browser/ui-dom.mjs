// Observation only: never assigns app state, fetch, route, storage or navigator.
import { need, exact, integer, validateCapabilities } from './ui-contract.mjs'
export function observeCapabilityDOM(slots, schema) {
  const q = (s, root = document) => root?.querySelector(s) ?? null
  const all = (s, root = document) => [...(root?.querySelectorAll(s) ?? [])]
  const text = e => (e?.textContent ?? '').replace(/\s+/g, ' ').trim()
  const visible = e => { if (!e || !e.isConnected) return false; for (let p = e; p; p = p.parentElement) { const s = getComputedStyle(p); if (s.display === 'none' || s.visibility === 'hidden' || s.visibility === 'collapse' || Number(s.opacity) === 0 || p.hidden) return false }; const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 }
  const rect = e => { if (!visible(e)) return null; const r = e.getBoundingClientRect(); return { x: r.x, y: r.y, width: r.width, height: r.height } }
  const label = e => e?.getAttribute('aria-label')?.trim() || (e?.innerText ?? '').replace(/\s+/g, ' ').trim() || null
  const buttons = all('button')
  const controls = slots.map(([key, name]) => {
    const matches = buttons.filter(e => label(e) === name), e = matches.length === 1 ? matches[0] : null
    if (matches.length > 1) throw Error('ambiguous capability control')
    const r = rect(e), x = r ? r.x + r.width / 2 : -1, y = r ? r.y + r.height / 2 : -1
    const inViewport = !!r && r.x < innerWidth && r.y < innerHeight && r.x + r.width > 0 && r.y + r.height > 0
    const center = x >= 0 && y >= 0 && x < innerWidth && y < innerHeight
    return { key, label: e ? label(e) : null, labelSource: e ? e.getAttribute('aria-label')?.trim() ? 'ARIA_LABEL' : 'VISIBLE_TEXT' : null, present: !!e, visible: visible(e), enabled: !!e && !e.disabled && e.getAttribute('aria-disabled') !== 'true', inViewport, unobstructed: !!e && center && e.contains(document.elementFromPoint(x, y)), rect: r }
  })
  const h = q('.main-content > .page-heading h1') || q('.main-content .kernel-page h1') || q('.main-content .readiness-page h1')
  const active = q('.sidebar .nav-item.active'), page = label(active), overviewActive = page === '运行总览', kernelActive = page === '内核与协议', capabilityActive = page === '系统闭环'
  const n = e => ({ text: text(e), visible: visible(e), rect: rect(e) }), vb = all('.topbar .version b')
  let overview = null, kernels = null, capabilities = null
  if (overviewActive) {
    const p = q('.main-content > .page-heading p'), strips = all('.evidence-strip > div'), first = strips[0]
    overview = { status: [...(p?.childNodes ?? [])].filter(n => n.nodeType === 3).map(n => n.textContent).join('').trim(), mode: text(q('strong', first)), badge: text(q('.status', first)), boundaryText: text(q('span:last-child', p)), demoAlertTitle: text(q('.demo-source-alert strong')), demoAlertText: text(q('.demo-source-alert span')), evidenceStrip: strips.map(e => ({ label: text(q(':scope > span', e)), value: text(q('strong', e)), status: text(q('.status', e)), statusClass: q('.status', e)?.className ?? '' })), boundaryRows: all('.truth-boundary-panel tbody tr').map(e => { const a = all('td', e); return { domain: text(a[0]), evidence: text(a[1]), handling: text(a[2]) } }), businessTablePresent: !!q('.main-content .business-panel'), poolTablePresent: !!q('.main-content .pool-panel'), eventsTablePresent: !!q('.main-content .event-panel'), metricCardsPresent: !!q('.main-content .metric-grid,.main-content .metric-cards'), simulatedTopologyPresent: !!q('.main-content .topology'), dnsHealthObservedPresent: !!q('.main-content .dns-row') }
  }
  if (kernelActive) {
    const root = q('.kernel-page'), table = q('.kernel-table', root), matrix = q('.capability', root), inst = q('.instance', root), terms = all('dt', inst), values = all('dd', inst)
    kernels = { heading: text(q('h1', root)), description: text(q('.page-heading p', root)), rows: all('tbody tr', table).map(e => { const a = all('td', e); return { name: text(a[0]), versionEvidence: text(a[1]), scope: text(a[2]), instanceState: text(a[3]), boundary: text(a[4]), statusClass: q('.status', a[3])?.className ?? '' } }), matrixHeading: text(q('h2', matrix)), matrixDescription: text(q('.section-title p', matrix)), matrixRows: all('tbody tr', matrix).map(e => { const a = all('td', e); return { feature: text(a[0]), cells: a.slice(1).map(td => ({ text: text(td), className: q('span', td)?.className ?? '' })) } }), evidenceHeading: text(q('h2', inst)), evidenceStatus: text(q('.section-title .status', inst)), evidenceFields: terms.map((e, i) => ({ label: text(e), value: text(values[i]) })) }
  }
  if (capabilityActive) {
    const root = q('.readiness-page'), meta = all('.readiness-meta > div', root), boundary = q('.readiness-boundary', root)
    capabilities = { heading: text(q('h1', root)), boundary: { title: text(q('strong', boundary)), text: text(q('span', boundary)), writeEnabled: !!boundary?.classList.contains('write-enabled') }, summary: all('.readiness-summary > div', root).map(e => ({ stateClass: e.className, label: text(q('span', e)), count: text(q('strong', e)), description: text(q('small', e)) })), meta: { overallState: text(q('strong', meta[0])), generatedAtLabel: text(q('span', meta[1])), generatedAtText: text(q('strong', meta[1])), capabilityCount: text(q('strong', meta[2])), productionLabel: text(q('strong', meta[3])) }, groups: all('.readiness-group', root).map(e => ({ domain: text(q('h2', e)), count: text(q('.section-title p', e)), rows: all('.readiness-capability', e).map(a => ({ id: text(q('.capability-identity span', a)), name: text(q('.capability-identity strong', a)), stateClass: q('.readiness-state', a)?.className ?? '', stateLabel: text(q('.readiness-state span', a)), readOnlyLabel: text(q('.readiness-state small', a)), evidenceLabel: text(q('.capability-evidence strong', a)), evidence: all('.capability-evidence li', a).map(text), emptyEvidenceLabel: text(q('.capability-evidence .readiness-empty', a)), limitationsLabel: text(q('.capability-limitations strong', a)), limitations: all('.capability-limitations li', a).map(text) })) })) }
  }
  return { schema, page, pageMounted: !!h && text(h) === page, pageVisible: visible(h), https: location.protocol === 'https:', viewport: { width: innerWidth, height: innerHeight, scrollX, scrollY, clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth }, environment: { language: navigator.language, timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone }, browserStorage: { localEmpty: localStorage.length === 0, sessionEmpty: sessionStorage.length === 0, cookiesEmpty: document.cookie === '' }, topbar: { product: n(q('.topbar .brand strong')), sourceLabel: n(vb[0]), mode: n(vb[2]), kernel: n(vb[1]) }, controls, apiFence: { snapshotCaptureOrdinal: 0, capabilitiesCaptureOrdinals: [] }, overview, kernels, capabilities }
}
export const domExpression = c => '(' + observeCapabilityDOM.toString() + ')(' + JSON.stringify(c.controlSlots) + ',' + JSON.stringify(c.schemaNames.dom) + ')'

export function validateDOM(d, c) {
  const keys = c.nestedExactKeys, check = (v, name) => need(exact(v, keys[name]))
  check(d, 'dom.dom'); check(d.viewport, 'dom.viewport'); check(d.environment, 'dom.environment'); check(d.browserStorage, 'dom.browserStorage'); check(d.topbar, 'dom.topbar'); check(d.apiFence, 'dom.apiFence')
  need(d.schema === c.schemaNames.dom && d.pageMounted === true && d.pageVisible === true && d.https === true && d.environment.language === c.browserEnvironment.language && d.environment.timeZone === c.browserEnvironment.timeZone)
  need(Object.values(d.browserStorage).every(v => v === true) && ['运行总览', '内核与协议', '系统闭环'].includes(d.page))
  need(d.controls.length === c.controlSlots.length)
  for (let i = 0; i < d.controls.length; i++) { const v = d.controls[i]; check(v, 'dom.controls[]'); need(v.key === c.controlSlots[i][0]); for (const k of ['present', 'visible', 'enabled', 'inViewport', 'unobstructed']) need(typeof v[k] === 'boolean'); if (!v.present) need(v.label === null && v.labelSource === null && v.rect === null && !v.visible && !v.enabled && !v.inViewport && !v.unobstructed); else need(v.label === c.controlSlots[i][1] && ['ARIA_LABEL', 'VISIBLE_TEXT'].includes(v.labelSource)); if (v.rect) { check(v.rect, 'dom.controls[].rect'); need(v.rect.width >= 0 && v.rect.height >= 0) }; need(v.visible ? v.rect !== null : v.rect === null); if (i < 3) need(v.present && v.visible && v.enabled && v.labelSource === 'ARIA_LABEL'); if (i === 3) need(v.present === (d.page === '系统闭环') && v.enabled === (d.page === '系统闭环')); if (i >= 4) need(v.present === (d.page === '内核与协议') && !v.enabled) }
  for (const v of Object.values(d.topbar)) { check(v, 'dom.topbar.node'); need(typeof v.visible === 'boolean' && (v.visible ? v.rect !== null : v.rect === null)); if (v.rect) check(v.rect, 'dom.controls[].rect') }
  const active = d.page === '运行总览' ? 'overview' : d.page === '内核与协议' ? 'kernels' : 'capabilities'
  for (const k of ['overview', 'kernels', 'capabilities']) { if (k !== active) need(d[k] === null); else check(d[k], 'dom.' + k) }
  if (d.overview) { for (const v of d.overview.evidenceStrip) check(v, 'dom.overview.evidenceStrip[]'); for (const v of d.overview.boundaryRows) check(v, 'dom.overview.boundaryRows[]'); need(d.overview.evidenceStrip.length === 4 && d.overview.boundaryRows.length === 5); for (const k of ['businessTablePresent', 'poolTablePresent', 'eventsTablePresent', 'metricCardsPresent', 'simulatedTopologyPresent', 'dnsHealthObservedPresent']) need(d.overview[k] === false) }
  if (d.kernels) { need(d.kernels.rows.length === 4 && d.kernels.matrixRows.length === 12 && d.kernels.evidenceFields.length === 6); for (const v of d.kernels.rows) check(v, 'dom.kernels.rows[]'); for (const v of d.kernels.matrixRows) { check(v, 'dom.kernels.matrixRows[]'); need(v.cells.length === 3); for (const x of v.cells) check(x, 'dom.kernels.matrixRows[].cells[]') }; for (const v of d.kernels.evidenceFields) check(v, 'dom.kernels.evidenceFields[]') }
  if (d.capabilities) { const v = d.capabilities; check(v.boundary, 'dom.capabilities.boundary'); check(v.meta, 'dom.capabilities.meta'); need(v.summary.length === 4 && v.groups.length > 0 && v.groups.length <= 256); for (const a of v.summary) check(a, 'dom.capabilities.summary[]'); for (const g of v.groups) { check(g, 'dom.capabilities.groups[]'); need(Array.isArray(g.rows) && g.rows.length > 0 && g.rows.length <= 256); for (const a of g.rows) check(a, 'dom.capabilities.groups[].rows[]') } }
  const walk = v => { if (typeof v === 'string') need(v.length <= 2048 && !/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/.test(v)); else if (typeof v === 'number') need(Number.isFinite(v)); else if (Array.isArray(v)) { need(v.length <= 256); v.forEach(walk) } else if (v && typeof v === 'object') Object.values(v).forEach(walk) }
  walk(d); need(Buffer.byteLength(JSON.stringify(d)) <= c.captureRules.bounds.domRowBytes); return d
}
export function validateCheckpoint(step, d, rows, c, profile) {
  validateDOM(d, c); const f = c.stepFences.find(v => v[0] === step); need(f)
  need(d.viewport.width === f[1] && d.viewport.height === f[2] && d.viewport.scrollWidth === d.viewport.clientWidth && d.viewport.scrollX === 0 && d.viewport.scrollY === 0)
  const snap = rows.filter(v => v.kind === 'SNAPSHOT'), caps = rows.filter(v => v.kind === 'CAPABILITIES').sort((a,b) => a.ordinal-b.ordinal)
  need(snap.length === f[3] && caps.length === f[4] && d.apiFence.snapshotCaptureOrdinal === snap[0].ordinal && d.apiFence.capabilitiesCaptureOrdinals.join(',') === caps.map(v => v.ordinal).join(','))
  const snapshot = JSON.parse(Buffer.from(snap[0].responseBase64, 'base64').toString('utf8')); need(snapshot.dataSource === 'demo' && snapshot.mode === 'candidate')
  need(d.topbar.product.text === snapshot.product && d.topbar.sourceLabel.text === '演示草稿' && d.topbar.mode.text === snapshot.mode && d.topbar.kernel.text === '未核验')
  if (d.overview) need(d.overview.status === snapshot.status && d.overview.mode === snapshot.mode && d.overview.badge === '总览只读' && d.overview.boundaryText === '总览仅展示数据边界；执行权限以服务端授权为准')
  if (d.capabilities) {
    const response = validateCapabilities(JSON.parse(Buffer.from(caps.at(-1).responseBase64, 'base64').toString('utf8')), c, profile), v = d.capabilities
    need(v.boundary.writeEnabled === false && v.boundary.title === '生产写入保持关闭' && v.meta.overallState === response.overallState && v.meta.capabilityCount === String(response.capabilities.length) && v.meta.productionLabel === '未启用' && v.meta.generatedAtLabel === '清单生成时间')
    const matches = v.meta.generatedAtText.match(/^(\d{4})[/-](\d{1,2})[/-](\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})$/); need(matches); need(matches.slice(1).map(Number).join(',') === response.generatedAt.match(/\d+/g).map(Number).join(','))
    const actual = v.groups.flatMap(g => g.rows), byId = new Map(actual.map(a => [a.id, a])); need(actual.length === response.capabilities.length && byId.size === actual.length)
    const presentation = { live_readonly: ['只读接入已配置','配置不代表连接成功、健康或生产验收；实际状态须独立读回'], implemented_local: ['本地实现','已在控制面实现，尚未接管生产数据面'], design_only: ['仅设计','已有设计边界，但还没有可执行实现'], blocked: ['受阻','缺少前置条件，当前无法完成验收'] }
    const grouped = new Map(); for (const a of response.capabilities) { if (!grouped.has(a.domain)) grouped.set(a.domain, []); grouped.get(a.domain).push(a) }
    need(v.groups.map(g => g.domain).join(',') === [...grouped.keys()].join(','))
    for (const g of v.groups) { const actual = grouped.get(g.domain); need(g.count === `${actual.length} 项能力，每项分别展示证据与限制` && g.rows.map(a=>a.id).join(',') === actual.map(a=>a.id).join(',')) }
    for (const a of response.capabilities) { const b = byId.get(a.id); need(b && b.name === a.name && b.stateClass === 'readiness-state ' + a.state && b.stateLabel === presentation[a.state][0] && b.readOnlyLabel === (a.readOnly ? '只读' : '包含写入能力') && JSON.stringify(b.evidence) === JSON.stringify(a.evidence) && JSON.stringify(b.limitations) === JSON.stringify(a.limitations)); need(b.evidenceLabel === '可核验入口与实现依据' && b.limitationsLabel === '当前限制' && b.emptyEvidenceLabel === (a.evidence.length ? '' : '暂无可核验入口')); need(v.groups.find(g => g.rows.includes(b))?.domain === a.domain) }
    for (let i = 0; i < 4; i++) { const state = ['live_readonly','implemented_local','design_only','blocked'][i]; need(v.summary[i].stateClass === '' && v.summary[i].count === String(response.capabilities.filter(a => a.state === state).length) && v.summary[i].label === presentation[state][0] && v.summary[i].description === presentation[state][1]) }
  }
  return d
}
