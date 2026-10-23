// Read-only rendered DOM projection. This is not a browser driver or backend proof.
// Keep this function self-contained: both engines evaluate these exact bytes.
export function collectSubscriptionDOM() {
  const fail = () => { throw Error('subscription DOM rejected') }
  const need = value => { if (!value) fail() }
  const text = element => element?.textContent?.trim() ?? ''
  const all = (scope, selector) => [...(scope?.querySelectorAll(selector) ?? [])]
  const one = (scope, selector) => { const found = all(scope, selector); need(found.length <= 1); return found[0] ?? null }
  const visible = element => Boolean(element && element.getClientRects().length && getComputedStyle(element).visibility !== 'hidden' && getComputedStyle(element).display !== 'none')
  const number = raw => { need(/^(0|[1-9][0-9]{0,15})$/.test(raw)); const value = Number(raw); need(Number.isSafeInteger(value)); return value }
  const id = (raw, prefix) => { need(new RegExp(`^${prefix}_[a-f0-9]{32}$`).test(raw)); return raw }
  const rect = element => {
    if (!visible(element)) return null
    const r = element.getBoundingClientRect()
    return { x: Math.round(r.x), y: Math.round(r.y), width: Math.round(r.width), height: Math.round(r.height) }
  }
  const panel = one(document, 'section.subscriptions[aria-label="订阅资源工作区"]')
  const button = name => {
    const found = all(panel, 'button').filter(element => text(element) === name)
    need(found.length <= 1); return found[0] ?? null
  }
  const state = (key, element) => {
    const box = rect(element)
    let inViewport = false, unobstructed = false
    if (box) {
      const r = element.getBoundingClientRect(), x = r.x + r.width / 2, y = r.y + r.height / 2
      inViewport = x >= 0 && x < innerWidth && y >= 0 && y < innerHeight
      if (inViewport) unobstructed = element.contains(document.elementFromPoint(x, y))
    }
    return { key, present: Boolean(element), visible: visible(element), enabled: Boolean(element && !element.disabled), inViewport, unobstructed, rect: box }
  }
  const fixed = [
    ['connect', '连接订阅会话'], ['clear', '清除会话与令牌'], ['refresh_sources', '刷新来源'],
    ['prepare_create', '准备创建来源'], ['refresh_source', '刷新当前版本'], ['prepare_import', '准备导入候选'],
    ['prepare_approve', '准备批准来源'], ['prepare_fetch', '准备抓取候选'], ['prepare_admit', '准备接纳候选'],
    ['prepare_reject', '准备拒绝候选'], ['prepare_rollback', '准备回退候选'], ['confirm', '确认并提交本地操作'],
    ['cancel', '取消本次操作'], ['candidate_previous', '上一页候选'], ['candidate_next', '下一页候选'],
    ['node_previous', '上一页节点'], ['node_next', '下一页节点'],
  ]
  const controls = fixed.map(([key, name]) => state(key, button(name)))
  const receiptButton = button('读取命令回执'), busyReceiptButton = button('正在读取回执…')
  need(!(receiptButton && busyReceiptButton))
  controls.push(state('read_receipt', receiptButton ?? busyReceiptButton))
  const token = one(panel, '#subscription-token'), file = one(panel, '#subscription-file')
  let storageEmpty = false, cookiesEmpty = false
  try { storageEmpty = localStorage.length === 0 && sessionStorage.length === 0; cookiesEmpty = document.cookie === '' } catch { /* false is not a proof of emptiness */ }
  const sources = all(panel, '.subscription-source-list > li').map(li => {
    const item = one(li, 'button'), code = one(item, 'code'), revision = /^版本 ([1-9][0-9]*) · (已有本地有效候选|尚无本地有效候选)$/.exec(text(one(item, 'span')))
    need(item && revision)
    return { id: id(text(code), 'src'), revision: number(revision[1]), selected: item.getAttribute('aria-pressed') === 'true', accepted: revision[2] === '已有本地有效候选', disabled: Boolean(item.disabled) }
  })
  const candidates = all(panel, '.subscription-candidate-list > li').map(li => {
    const item = one(li, 'button'), spans = all(item, 'span')
    const info = /^(待审候选|本地已接纳|已拒绝) · (0|[1-9][0-9]*) 个节点 · (mihomo-provider-yaml|uri-list|base64-uri-list)$/.exec(text(spans[0]))
    const base = / · 基准版本 ([1-9][0-9]*)$/.exec(text(spans[1]))
    need(item && spans.length === 2 && info && base)
    return { id: id(text(one(item, 'code')), 'cand'), state: ({ 待审候选: 'quarantined', 本地已接纳: 'admitted_local', 已拒绝: 'rejected' })[info[1]],
      nodeCount: number(info[2]), format: info[3], baseRevision: number(base[1]), selected: item.getAttribute('aria-pressed') === 'true' }
  })
  const nodes = all(panel, '.subscription-nodes > ul > li').map(li => {
    const nodeId = id(text(one(li, 'code')), 'node'), info = /^(ss|vmess|vless|trojan|http|socks5) · (已配置凭据（不展示）|未配置凭据) · 未评估$/.exec(text(one(li, 'span')))
    need(info && text(one(li, 'strong')) === `节点-${nodeId.slice(-8)}`)
    return { id: nodeId, protocol: info[1], credentialConfigured: info[2] === '已配置凭据（不展示）', state: 'unknown' }
  })
  const paging = label => {
    const element = one(panel, `nav[aria-label="${label}分页"]`)
    if (!element) return null
    const parsed = new RegExp(`^${label}第 ([1-9][0-9]*) 页 · 版本 ([1-9][0-9]*)$`).exec(text(one(element, 'span')))
    need(parsed); return { page: number(parsed[1]), revision: number(parsed[2]) }
  }
  const modes = all(panel, '[role="radiogroup"][aria-label="抓取批准方式"] input[type="radio"]')
  need(modes.length === 0 || (modes.length === 2 && modes.filter(e => e.checked).length === 1))
  const mode = modes.length ? (modes[0].checked ? 'session' : 'handoff') : 'absent'
  const reference = one(panel, '#subscription-reference')
  const directory = { present: Boolean(reference), disabled: Boolean(reference?.disabled), references: [] }
  for (const option of all(reference, 'option')) {
    if (option.value === '') { need(text(option) === '没有可列举的受信引用'); continue }
    need(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(option.value))
    const match = /^([A-Za-z0-9][A-Za-z0-9_.-]{0,63}) · 策略版本 ([1-9][0-9]{0,15})$/.exec(text(option)); need(match && match[1] === option.value)
    directory.references.push({ referenceId: option.value, revision: number(match[2]), selected: Boolean(option.selected) })
  }
  const approved = all(panel, '.subscription-operations fieldset p').filter(element => text(element).startsWith('本会话已读回批准：'))
  need(approved.length <= 1)
  let sessionApproval = null
  if (approved.length) {
    const parsed = /^本会话已读回批准：(cmd_[a-f0-9]{32}) · 引用 ([A-Za-z0-9][A-Za-z0-9_.-]{0,63}) · 策略版本 ([1-9][0-9]{0,15})$/.exec(text(approved[0])); need(parsed)
    sessionApproval = { approvalId: parsed[1], referenceId: parsed[2], policyRevision: number(parsed[3]) }
  }
  const handoffInput = one(panel, '#subscription-handoff'), handoffRevision = one(panel, '#subscription-handoff-revision')
  let handoff = null
  if (handoffInput || handoffRevision) {
    need(handoffInput && handoffRevision && mode === 'handoff')
    const approvalValid = /^cmd_[a-f0-9]{32}$/.test(handoffInput.value), revisionValid = /^[1-9][0-9]{0,15}$/.test(handoffRevision.value) && Number.isSafeInteger(Number(handoffRevision.value))
    handoff = { approvalValid, approvalId: approvalValid ? handoffInput.value : null, revisionValid, policyRevision: revisionValid ? Number(handoffRevision.value) : null,
      unverifiedReferenceNotice: text(one(panel, '#subscription-handoff-help')).includes('实际目录引用未读回；由批准ID决定；准备新批准的下拉引用不绑定本次抓取。') }
  }
  const dialog = one(panel, '.subscription-confirmation[role="alertdialog"]')
  let confirmation = null
  if (dialog) {
    const titles = { '确认：创建本地来源': 'create', '确认：导入本地候选': 'import', '确认：批准受信来源': 'approve', '确认：抓取交接批准（未核验）': 'fetch_handoff',
      '确认：抓取本会话已读回批准': 'fetch_session', '确认：接纳本地候选': 'admit', '确认：拒绝本地候选': 'reject', '确认：回退本地引用': 'rollback' }
    const title = text(one(dialog, '#subscription-confirm-title')); need(Object.hasOwn(titles, title)); const kind = titles[title]
    const description = text(one(dialog, '#subscription-confirm-description'))
    let binding = null, unverifiedReference = false
    if (kind === 'fetch_handoff' || kind === 'fetch_session') {
      const match = /^来源 ID：(src_[a-f0-9]{32})；预期来源版本：([1-9][0-9]{0,15})；批准 ID：(cmd_[a-f0-9]{32})；策略版本：([1-9][0-9]{0,15})。(.+)$/u.exec(description)
      need(match)
      const handoffTail = '实际目录引用未读回；由批准ID决定；准备新批准的下拉引用不绑定本次抓取。失败保留最后有效候选；不会自动接纳或发布。'
      const sessionTail = /^本会话已读回批准，目录引用 [A-Za-z0-9][A-Za-z0-9_.-]{0,63}；服务端仍会重新核验。失败保留最后有效候选；不会自动接纳或发布。$/u
      need(kind === 'fetch_handoff' ? match[5] === handoffTail : sessionTail.test(match[5]))
      binding = { sourceId: match[1], expectedRevision: number(match[2]), approvalId: match[3], policyRevision: number(match[4]) }
      unverifiedReference = kind === 'fetch_handoff'
    }
    const checkbox = one(dialog, 'input[type="checkbox"]')
    need(Boolean(checkbox) === (kind === 'rollback'))
    confirmation = { kind, binding, unverifiedReference, rollbackRequired: Boolean(checkbox), rollbackChecked: Boolean(checkbox?.checked) }
  }
  const receiptGrid = one(panel, '.subscription-receipt-grid')
  let receipt = null
  if (receiptGrid) {
    const rows = all(receiptGrid, ':scope > div'); need(rows.length === 4)
    const labels = ['状态', '命令', '本地版本', '审计']; rows.forEach((row, index) => need(text(one(row, 'dt')) === labels[index]))
    const stateText = text(one(rows[0], 'dd')), replayed = stateText.endsWith(' · 历史重放，未重新执行')
    const states = { 结果待核对: 'pending', 本地已提交: 'committed', 批准已记录: 'approved', 内容未变: 'noop', 操作已失败: 'failed' }
    const stateLabel = stateText.replace(/ · 历史重放，未重新执行$/, ''); need(Object.hasOwn(states, stateLabel)); const receiptState = states[stateLabel]
    const audit = text(one(rows[3], 'dd')); need(audit === '审计已确认' || audit === '审计待确认')
    receipt = { commandId: id(text(one(rows[1], 'code')), 'cmd'), revision: number(text(one(rows[2], 'dd'))), state: receiptState, replayed, auditRecorded: audit === '审计已确认' }
  }
  const stale = selector => all(panel, selector).some(element => visible(element))
  return { schema: 'chengwang.subscription-browser-dom/v1', pageMounted: Boolean(panel), pageVisible: visible(panel), https: location.protocol === 'https:',
    viewport: { width: innerWidth, height: innerHeight, scrollX: Math.round(scrollX), scrollY: Math.round(scrollY), clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth },
    session: { tokenMounted: Boolean(token), tokenType: token ? token.type === 'password' ? 'password' : 'invalid' : 'absent', tokenEmpty: token ? token.value === '' : null,
      fileMounted: Boolean(file), fileEmpty: file ? file.value === '' : null, storageEmpty, cookiesEmpty }, controls,
    sources, candidates, nodes, paging: { candidates: paging('候选'), nodes: paging('节点') }, mode, directory, sessionApproval, handoff, confirmation, receipt,
    stale: { sources: stale('.subscription-sources .subscription-stale'), candidates: stale('.subscription-detail > section[aria-labelledby="subscription-candidates-title"] > p.subscription-stale'), nodes: stale('.subscription-nodes .subscription-stale') },
    alertVisible: visible(one(panel, '.subscription-error[role="alert"]')), boundaryVisible: visible(one(panel, '.subscription-boundary')) }
}

export const SUBSCRIPTION_DOM_EXPRESSION = `(${collectSubscriptionDOM.toString().replace(/\r\n/g, '\n')})()`
export const SUBSCRIPTION_DOM_CONTROL_KEYS = Object.freeze(['connect', 'clear', 'refresh_sources', 'prepare_create', 'refresh_source', 'prepare_import', 'prepare_approve', 'prepare_fetch', 'prepare_admit', 'prepare_reject', 'prepare_rollback', 'confirm', 'cancel', 'candidate_previous', 'candidate_next', 'node_previous', 'node_next', 'read_receipt'])

const reject = () => { throw Error('subscription DOM rejected') }
const need = value => { if (!value) reject() }
const exact = (value, keys) => { need(value !== null && typeof value === 'object' && !Array.isArray(value)); need(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))) }
const integer = (value, min = 0, max = Number.MAX_SAFE_INTEGER) => need(Number.isSafeInteger(value) && value >= min && value <= max)
const bool = value => need(typeof value === 'boolean')
const identifier = (value, prefix) => need(typeof value === 'string' && new RegExp(`^${prefix}_[a-f0-9]{32}$`).test(value))
const nullableBool = value => { if (value !== null) bool(value) }
const unique = (items, max, inspect) => { need(Array.isArray(items) && items.length <= max); const seen = new Set(); for (const item of items) { inspect(item); need(!seen.has(item.id)); seen.add(item.id) } }

// Closed schema only. It deliberately does not infer server grants, health or causality.
export function validateSubscriptionDOM(value) {
  exact(value, ['schema', 'pageMounted', 'pageVisible', 'https', 'viewport', 'session', 'controls', 'sources', 'candidates', 'nodes', 'paging', 'mode', 'directory', 'sessionApproval', 'handoff', 'confirmation', 'receipt', 'stale', 'alertVisible', 'boundaryVisible'])
  need(value.schema === 'chengwang.subscription-browser-dom/v1')
  for (const key of ['pageMounted', 'pageVisible', 'https', 'alertVisible', 'boundaryVisible']) bool(value[key])
  need(!value.pageVisible || value.pageMounted)
  exact(value.viewport, ['width', 'height', 'scrollX', 'scrollY', 'clientWidth', 'scrollWidth'])
  for (const key of ['width', 'height', 'clientWidth', 'scrollWidth']) integer(value.viewport[key], 1, 100000)
  for (const key of ['scrollX', 'scrollY']) integer(value.viewport[key], -100000, 100000)
  need(value.viewport.scrollWidth >= value.viewport.clientWidth)
  exact(value.session, ['tokenMounted', 'tokenType', 'tokenEmpty', 'fileMounted', 'fileEmpty', 'storageEmpty', 'cookiesEmpty'])
  for (const key of ['tokenMounted', 'fileMounted', 'storageEmpty', 'cookiesEmpty']) bool(value.session[key])
  need(['password', 'invalid', 'absent'].includes(value.session.tokenType))
  nullableBool(value.session.tokenEmpty); nullableBool(value.session.fileEmpty)
  need(value.session.tokenMounted === (value.session.tokenType !== 'absent') && value.session.tokenMounted === (value.session.tokenEmpty !== null) && value.session.fileMounted === (value.session.fileEmpty !== null))
  need(Array.isArray(value.controls) && value.controls.length === SUBSCRIPTION_DOM_CONTROL_KEYS.length)
  value.controls.forEach((control, index) => {
    exact(control, ['key', 'present', 'visible', 'enabled', 'inViewport', 'unobstructed', 'rect']); need(control.key === SUBSCRIPTION_DOM_CONTROL_KEYS[index])
    for (const key of ['present', 'visible', 'enabled', 'inViewport', 'unobstructed']) bool(control[key])
    need((!control.visible && !control.enabled && !control.inViewport && !control.unobstructed) || control.present)
    need(control.visible === (control.rect !== null)); need(!control.inViewport || control.visible); need(!control.unobstructed || control.inViewport)
    if (control.rect !== null) { exact(control.rect, ['x', 'y', 'width', 'height']); integer(control.rect.x, -100000, 100000); integer(control.rect.y, -100000, 100000); integer(control.rect.width, 0, 100000); integer(control.rect.height, 0, 100000) }
  })
  unique(value.sources, 32, source => { exact(source, ['id', 'revision', 'selected', 'accepted', 'disabled']); identifier(source.id, 'src'); integer(source.revision, 1); bool(source.selected); bool(source.accepted); bool(source.disabled) })
  need(value.sources.filter(source => source.selected).length <= 1)
  unique(value.candidates, 20, candidate => {
    exact(candidate, ['id', 'state', 'nodeCount', 'format', 'baseRevision', 'selected']); identifier(candidate.id, 'cand'); need(['quarantined', 'admitted_local', 'rejected'].includes(candidate.state)); integer(candidate.nodeCount, 1, 1024); integer(candidate.baseRevision, 2); bool(candidate.selected); need(['mihomo-provider-yaml', 'uri-list', 'base64-uri-list'].includes(candidate.format))
  })
  need(value.candidates.filter(candidate => candidate.selected).length <= 1)
  unique(value.nodes, 20, node => { exact(node, ['id', 'protocol', 'credentialConfigured', 'state']); identifier(node.id, 'node'); need(['ss', 'vmess', 'vless', 'trojan', 'http', 'socks5'].includes(node.protocol)); bool(node.credentialConfigured); need(node.state === 'unknown') })
  exact(value.paging, ['candidates', 'nodes'])
  for (const paging of Object.values(value.paging)) if (paging !== null) { exact(paging, ['page', 'revision']); integer(paging.page, 1); integer(paging.revision, 1) }
  need(['absent', 'session', 'handoff'].includes(value.mode))
  exact(value.directory, ['present', 'disabled', 'references']); bool(value.directory.present); bool(value.directory.disabled)
  need(Array.isArray(value.directory.references) && value.directory.references.length <= 32)
  const references = new Set()
  for (const reference of value.directory.references) {
    exact(reference, ['referenceId', 'revision', 'selected']); need(typeof reference.referenceId === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(reference.referenceId)); integer(reference.revision, 1); bool(reference.selected)
    need(!references.has(reference.referenceId)); references.add(reference.referenceId)
  }
  need(value.directory.references.filter(reference => reference.selected).length <= 1)
  need(value.directory.present || (!value.directory.disabled && value.directory.references.length === 0))
  if (value.sessionApproval !== null) {
    exact(value.sessionApproval, ['approvalId', 'referenceId', 'policyRevision']); identifier(value.sessionApproval.approvalId, 'cmd'); integer(value.sessionApproval.policyRevision, 1)
    need(typeof value.sessionApproval.referenceId === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(value.sessionApproval.referenceId))
  }
  if (value.handoff !== null) {
    need(value.mode === 'handoff'); exact(value.handoff, ['approvalValid', 'approvalId', 'revisionValid', 'policyRevision', 'unverifiedReferenceNotice'])
    for (const key of ['approvalValid', 'revisionValid', 'unverifiedReferenceNotice']) bool(value.handoff[key])
    if (value.handoff.approvalValid) identifier(value.handoff.approvalId, 'cmd'); else need(value.handoff.approvalId === null)
    if (value.handoff.revisionValid) integer(value.handoff.policyRevision, 1); else need(value.handoff.policyRevision === null)
  }
  if (value.confirmation !== null) {
    const confirmation = value.confirmation; exact(confirmation, ['kind', 'binding', 'unverifiedReference', 'rollbackRequired', 'rollbackChecked'])
    need(['create', 'import', 'approve', 'fetch_handoff', 'fetch_session', 'admit', 'reject', 'rollback'].includes(confirmation.kind))
    for (const key of ['unverifiedReference', 'rollbackRequired', 'rollbackChecked']) bool(confirmation[key])
    const fetch = ['fetch_handoff', 'fetch_session'].includes(confirmation.kind)
    need(fetch === (confirmation.binding !== null) && confirmation.unverifiedReference === (confirmation.kind === 'fetch_handoff'))
    need(confirmation.rollbackRequired === (confirmation.kind === 'rollback') && (!confirmation.rollbackChecked || confirmation.rollbackRequired))
    if (fetch) { exact(confirmation.binding, ['sourceId', 'expectedRevision', 'approvalId', 'policyRevision']); identifier(confirmation.binding.sourceId, 'src'); identifier(confirmation.binding.approvalId, 'cmd'); integer(confirmation.binding.expectedRevision, 1); integer(confirmation.binding.policyRevision, 1) }
  }
  if (value.receipt !== null) { exact(value.receipt, ['commandId', 'revision', 'state', 'replayed', 'auditRecorded']); identifier(value.receipt.commandId, 'cmd'); integer(value.receipt.revision); need(['pending', 'committed', 'approved', 'noop', 'failed'].includes(value.receipt.state)); bool(value.receipt.replayed); bool(value.receipt.auditRecorded) }
  exact(value.stale, ['sources', 'candidates', 'nodes']); Object.values(value.stale).forEach(bool)
  if (!value.pageMounted) need(!value.pageVisible && value.sources.length === 0 && value.candidates.length === 0 && value.nodes.length === 0 && value.mode === 'absent' && !value.directory.present && value.sessionApproval === null && value.handoff === null && value.confirmation === null && value.receipt === null && !value.session.tokenMounted && !value.session.fileMounted && value.controls.every(control => !control.present))
  return value
}

// Private canaries remain in the caller. No canary or observed text is in errors.
export function assertNoPublicCanaries(value, canaries) {
  validateSubscriptionDOM(value)
  need(Array.isArray(canaries) && canaries.length > 0 && canaries.length <= 256 && canaries.every(item => typeof item === 'string' && item.length > 0 && item.length <= 8192))
  const serialized = JSON.stringify(value)
  need(!canaries.some(item => serialized.includes(item)))
  return value
}
