// SYNTHETIC ONLY: fake DOM interfaces in node:vm, no browser, network or Go.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import vm from 'node:vm'
import { collectSubscriptionDOM, SUBSCRIPTION_DOM_EXPRESSION, SUBSCRIPTION_DOM_CONTROL_KEYS, validateSubscriptionDOM, assertNoPublicCanaries } from './collect-subscription-dom.mjs'

const sid = 'src_' + 'a'.repeat(32), cid = 'cand_' + 'b'.repeat(32), nid = 'node_' + 'c'.repeat(32), cmd = 'cmd_' + 'd'.repeat(32)
const rejected = action => assert.throws(action, { message: 'subscription DOM rejected' })
const clone = value => JSON.parse(JSON.stringify(value))
function element(content = '', selectors = {}, options = {}) {
  const node = { textContent: content, value: '', type: '', checked: false, disabled: false, ...options,
    querySelectorAll(selector) {
      const result = selectors[selector] ?? []
      for (const child of result) if (!child.parentElement) child.parentElement = node
      return result
    },
    getClientRects() {
      // A narrow synthetic ancestry model, not a CSS/layout engine. The real
      // browser supplies getClientRects; these hand-built interfaces do not.
      for (let ancestor = node; ancestor; ancestor = ancestor.parentElement) if (ancestor.hidden) return []
      return [{}]
    },
    getBoundingClientRect() { return node.box ?? { x: 10, y: 10, width: 120, height: 30 } },
    contains(other) { return other === node || other === node.hitChild },
    getAttribute(name) { return node.attributes?.[name] ?? null },
  }
  return node
}
function fixture({ mounted = true, width = 1440, height = 900 } = {}) {
  const selectors = {}, rootSelectors = {}, token = element('', {}, { type: 'password' }), file = element('', {}, { type: 'file' })
  const panel = element('', selectors), document = element('', rootSelectors), wrapper = element()
  panel.parentElement = wrapper; wrapper.parentElement = document
  document.documentElement = { clientWidth: width, scrollWidth: width }; document.cookie = ''
  document.elementFromPoint = () => context.hit ?? null
  selectors['#subscription-token'] = [token]; selectors['#subscription-file'] = [file]
  selectors['button'] = ['连接订阅会话', '清除会话与令牌', '刷新来源', '准备创建来源', '准备导入候选', '准备批准来源', '准备抓取候选', '准备接纳候选', '准备拒绝候选', '准备回退候选', '读取命令回执'].map(name => element(name, {}, { disabled: !['连接订阅会话', '清除会话与令牌'].includes(name) }))
  // Product JSX renders both choices and the disabled directory even signed out.
  selectors['[role="radiogroup"][aria-label="抓取批准方式"] input[type="radio"]'] = [element('', {}, { checked: true, disabled: true }), element('', {}, { checked: false, disabled: true })]
  selectors['#subscription-reference'] = [element('', { option: [element('没有可列举的受信引用', {}, { value: '', selected: true })] }, { disabled: true })]
  selectors['.subscription-boundary'] = [element('设备发布未授权')]
  if (mounted) rootSelectors['section.subscriptions[aria-label="订阅资源工作区"]'] = [panel]
  const context = { document, innerWidth: width, innerHeight: height, scrollX: 0, scrollY: 0, location: { protocol: 'https:' },
    localStorage: { length: 0 }, sessionStorage: { length: 0 }, getComputedStyle: node => ({ visibility: node.hidden ? 'hidden' : 'visible', display: node.hidden ? 'none' : 'block' }),
  }
  const run = () => JSON.parse(JSON.stringify(vm.runInNewContext(SUBSCRIPTION_DOM_EXPRESSION, context, { timeout: 1000 })))
  return { selectors, rootSelectors, panel, wrapper, context, token, file, run }
}
function source(id = sid, revision = 3, selected = true) {
  const button = element('', { code: [element(id)], span: [element(`版本 ${revision} · 尚无本地有效候选`)], strong: [element('PRIVATE_SOURCE_LABEL')] }, { attributes: { 'aria-pressed': String(selected) } })
  return element('', { button: [button] })
}
function candidate(id = cid, state = '待审候选') {
  return element('', { button: [element('', { code: [element(id)], span: [element(`${state} · 21 个节点 · mihomo-provider-yaml`), element('创建于 local date · 基准版本 2')] }, { attributes: { 'aria-pressed': 'true' } })] })
}
function node(id = nid, label = `节点-${id.slice(-8)}`, health = '未评估') {
  return element('', { code: [element(id)], strong: [element(label)], span: [element(`vless · 已配置凭据（不展示） · ${health}`)] })
}
function handoff(f, approvalId = cmd, revision = '7') {
  f.selectors['[role="radiogroup"][aria-label="抓取批准方式"] input[type="radio"]'] = [element('', {}, { checked: false }), element('', {}, { checked: true })]
  f.selectors['#subscription-handoff'] = [element('', {}, { value: approvalId })]
  f.selectors['#subscription-handoff-revision'] = [element('', {}, { value: revision })]
  f.selectors['#subscription-handoff-help'] = [element('页面未验证该批准。实际目录引用未读回；由批准ID决定；准备新批准的下拉引用不绑定本次抓取。')]
}
const handoffTail = '实际目录引用未读回；由批准ID决定；准备新批准的下拉引用不绑定本次抓取。失败保留最后有效候选；不会自动接纳或发布。'
const fetchDescription = tail => `来源 ID：${sid}；预期来源版本：3；批准 ID：${cmd}；策略版本：7。${tail}`
function confirmation(f, title = '确认：抓取交接批准（未核验）', description = fetchDescription(handoffTail), checkbox = null) {
  const selectors = { '#subscription-confirm-title': [element(title)], '#subscription-confirm-description': [element(description)] }
  if (checkbox) selectors['input[type="checkbox"]'] = [checkbox]
  f.selectors['.subscription-confirmation[role="alertdialog"]'] = [element('', selectors)]
}
function receipt(f, stateText = '本地已提交', revision = '3') {
  const values = [stateText, cmd, revision, '审计已确认'], labels = ['状态', '命令', '本地版本', '审计']
  f.selectors['.subscription-receipt-grid'] = [element('', { ':scope > div': labels.map((label, i) => element('', { dt: [element(label)], dd: [element(values[i])], ...(i === 1 ? { code: [element(cmd)] } : {}) })) })]
}

test('subscription DOM expression is byte-identical self-contained code for both engines', () => {
  assert.equal(SUBSCRIPTION_DOM_EXPRESSION, `(${collectSubscriptionDOM.toString().replace(/\r\n/g, '\n')})()`)
  const f = fixture(), cdp = f.run(), pw = JSON.parse(JSON.stringify(vm.runInNewContext(`(${collectSubscriptionDOM.toString()})()`, f.context)))
  assert.deepEqual(cdp, pw); assert.equal(validateSubscriptionDOM(cdp), cdp)
})
test('subscription DOM observes a mounted signed-out page without invented inventory', () => {
  const value = validateSubscriptionDOM(fixture().run())
  assert.equal(value.pageMounted, true); assert.equal(value.session.tokenEmpty, true); assert.equal(value.mode, 'session')
  assert.deepEqual(value.directory, { present: true, disabled: true, references: [] }); assert.equal(value.handoff, null)
  assert.ok(value.controls.filter(control => control.present && !['connect', 'clear'].includes(control.key)).every(control => !control.enabled))
  assert.deepEqual([value.sources, value.candidates, value.nodes], [[], [], []]); assert.equal(value.confirmation, null); assert.equal(value.receipt, null)
})
test('subscription DOM represents a genuinely unmounted page with absent controls', () => {
  const value = validateSubscriptionDOM(fixture({ mounted: false }).run())
  assert.equal(value.pageMounted, false); assert.equal(value.session.tokenEmpty, null); assert.equal(value.session.fileEmpty, null)
  assert.equal(value.controls.every(control => !control.present), true)
})
test('subscription DOM distinguishes hidden mounted navigation from destroyed session', () => {
  const f = fixture(); f.wrapper.hidden = true; f.token.value = 'PRIVATE_TOKEN'
  let value = validateSubscriptionDOM(f.run()); assert.equal(value.pageMounted, true); assert.equal(value.pageVisible, false); assert.equal(value.session.tokenEmpty, false)
  assert.equal(value.mode, 'session'); assert.equal(value.session.tokenMounted, true); assert.equal(value.boundaryVisible, false)
  assert.ok(value.controls.filter(control => control.present).every(control => !control.visible && !control.inViewport && !control.unobstructed && control.rect === null))
  f.wrapper.hidden = false; value = validateSubscriptionDOM(f.run())
  assert.equal(value.pageVisible, true); assert.equal(value.boundaryVisible, true); assert.equal(value.controls[0].visible, true); assert.equal(value.session.tokenEmpty, false)
})
test('subscription DOM never exports token file cookie or storage contents', () => {
  const f = fixture(); f.token.value = 'PRIVATE_TOKEN'; f.file.value = 'C:/PRIVATE_FILENAME.yaml'
  f.context.document.cookie = 'PRIVATE_COOKIE'; f.context.localStorage = { length: 1, PRIVATE_STORAGE: 'PRIVATE_VALUE' }
  const value = validateSubscriptionDOM(f.run()), raw = JSON.stringify(value)
  assert.equal(value.session.tokenEmpty, false); assert.equal(value.session.fileEmpty, false); assert.equal(value.session.cookiesEmpty, false); assert.equal(value.session.storageEmpty, false)
  for (const forbidden of ['PRIVATE_TOKEN', 'PRIVATE_FILENAME', 'PRIVATE_COOKIE', 'PRIVATE_STORAGE', 'PRIVATE_VALUE']) assert.ok(!raw.includes(forbidden))
})
test('subscription DOM projects safe source IDs and revision but no arbitrary source label', () => {
  const f = fixture(); f.selectors['.subscription-source-list > li'] = [source()]
  const value = validateSubscriptionDOM(f.run()); assert.deepEqual(value.sources, [{ id: sid, revision: 3, selected: true, accepted: false, disabled: false }]); assert.ok(!JSON.stringify(value).includes('PRIVATE_SOURCE_LABEL'))
})
test('subscription DOM projects current candidate IDs states and base revision', () => {
  const f = fixture(); f.selectors['.subscription-candidate-list > li'] = [candidate()]
  const value = validateSubscriptionDOM(f.run()); assert.deepEqual(value.candidates, [{ id: cid, state: 'quarantined', nodeCount: 21, format: 'mihomo-provider-yaml', baseRevision: 2, selected: true }])
})
test('subscription DOM observes safe node summary as unknown not healthy', () => {
  const f = fixture(); f.selectors['.subscription-nodes > ul > li'] = [node()]
  assert.deepEqual(validateSubscriptionDOM(f.run()).nodes, [{ id: nid, protocol: 'vless', credentialConfigured: true, state: 'unknown' }])
})
test('subscription DOM rejects rendered healthy node claims and private node labels', () => {
  for (const item of [node(nid, 'PRIVATE_NODE_LABEL'), node(nid, undefined, '健康')]) {
    const f = fixture(); f.selectors['.subscription-nodes > ul > li'] = [item]; rejected(f.run)
  }
})
test('subscription DOM projects valid handoff ID and independently entered policy revision', () => {
  const f = fixture(); handoff(f)
  assert.deepEqual(validateSubscriptionDOM(f.run()).handoff, { approvalValid: true, approvalId: cmd, revisionValid: true, policyRevision: 7, unverifiedReferenceNotice: true })
})
test('subscription DOM separates directory choice from session approval and handoff binding', () => {
  const f = fixture(); handoff(f); confirmation(f)
  f.selectors['#subscription-reference'] = [element('', { option: [element('source-a · 策略版本 7', {}, { value: 'source-a', selected: true }), element('source-b · 策略版本 7', {}, { value: 'source-b', selected: false })] })]
  f.selectors['.subscription-operations fieldset p'] = [element(`本会话已读回批准：${cmd} · 引用 source-b · 策略版本 7`)]
  const value = validateSubscriptionDOM(f.run())
  assert.equal(value.directory.references[0].referenceId, 'source-a'); assert.equal(value.sessionApproval.referenceId, 'source-b'); assert.equal(value.confirmation.binding.approvalId, cmd)
  assert.equal(value.confirmation.unverifiedReference, true)
})
test('subscription DOM directory rejects private URLs duplicated references and unsafe revisions', () => {
  const f = fixture(); f.selectors['#subscription-reference'] = [element('', { option: [element('PRIVATE_URL', {}, { value: 'https://private.invalid/' })] })]; rejected(f.run)
  const base = fixture().run(); base.directory = { present: true, disabled: false, references: [{ referenceId: 'source-a', revision: 7, selected: true }, { referenceId: 'source-a', revision: 7, selected: false }] }; rejected(() => validateSubscriptionDOM(base))
  base.directory.references.pop(); base.directory.references[0].revision = 9007199254740992; rejected(() => validateSubscriptionDOM(base))
})
test('subscription DOM reports invalid handoff fields without exporting arbitrary input', () => {
  const f = fixture(); handoff(f, 'PRIVATE_INVALID_APPROVAL', 'PRIVATE_INVALID_REVISION')
  const value = validateSubscriptionDOM(f.run()); assert.deepEqual(value.handoff, { approvalValid: false, approvalId: null, revisionValid: false, policyRevision: null, unverifiedReferenceNotice: true }); assert.ok(!JSON.stringify(value).includes('PRIVATE_INVALID'))
})
test('subscription DOM captures all four immutable fetch confirmation parameters', () => {
  const f = fixture(); handoff(f); confirmation(f)
  const value = validateSubscriptionDOM(f.run()); assert.deepEqual(value.confirmation, { kind: 'fetch_handoff', binding: { sourceId: sid, expectedRevision: 3, approvalId: cmd, policyRevision: 7 }, unverifiedReference: true, rollbackRequired: false, rollbackChecked: false })
})
test('subscription DOM rejects missing duplicated or ambiguous fetch confirmation parameters', () => {
  const original = fetchDescription(handoffTail)
  for (const description of [original.replace(`批准 ID：${cmd}；`, ''), original.replace('策略版本：7。', '策略版本：7；策略版本：8。'), original + `来源 ID：${sid}；`, original.replace('预期来源版本：3', '预期来源版本：9007199254740992')]) {
    const f = fixture(); confirmation(f, undefined, description); rejected(f.run)
  }
})
test('subscription DOM keeps verified session and unverified handoff explanations separate', () => {
  const tail = '本会话已读回批准，目录引用 source-b；服务端仍会重新核验。失败保留最后有效候选；不会自动接纳或发布。'
  const f = fixture(); confirmation(f, '确认：抓取本会话已读回批准', fetchDescription(tail))
  assert.equal(validateSubscriptionDOM(f.run()).confirmation.unverifiedReference, false)
  confirmation(f, '确认：抓取交接批准（未核验）', fetchDescription(tail)); rejected(f.run)
})
test('subscription DOM rejects prototype-key confirmation labels without echoing text', () => {
  for (const title of ['__proto__', 'constructor', 'PRIVATE_TITLE']) { const f = fixture(); confirmation(f, title); rejected(f.run) }
})
test('subscription DOM requires the extra rollback checkbox and observes its checked state', () => {
  const f = fixture(); confirmation(f, '确认：回退本地引用', 'PRIVATE_NONEXPORTED_DESCRIPTION', element('', {}, { checked: true }))
  const value = validateSubscriptionDOM(f.run()); assert.equal(value.confirmation.rollbackRequired, true); assert.equal(value.confirmation.rollbackChecked, true); assert.ok(!JSON.stringify(value).includes('PRIVATE_NONEXPORTED_DESCRIPTION'))
  confirmation(f, '确认：回退本地引用'); rejected(f.run)
})
test('subscription DOM reads actual immutable receipt display without manufacturing kind', () => {
  const f = fixture(); receipt(f, '本地已提交 · 历史重放，未重新执行')
  assert.deepEqual(validateSubscriptionDOM(f.run()).receipt, { commandId: cmd, revision: 3, state: 'committed', replayed: true, auditRecorded: true })
})
test('subscription DOM retains pending receipt ambiguity instead of inventing unknown outcome', () => {
  const f = fixture(); receipt(f, '结果待核对', '0'); assert.equal(validateSubscriptionDOM(f.run()).receipt.state, 'pending')
})
test('subscription DOM reports actual desktop and 375-width mobile geometry', () => {
  for (const [width, height] of [[1440, 900], [375, 812]]) {
    const f = fixture({ width, height }); f.context.scrollY = 120
    assert.deepEqual(validateSubscriptionDOM(f.run()).viewport, { width, height, scrollX: 0, scrollY: 120, clientWidth: width, scrollWidth: width })
  }
})
test('subscription DOM records horizontal overflow without declaring layout accepted', () => {
  const f = fixture({ width: 375 }); f.context.document.documentElement.scrollWidth = 810
  const value = validateSubscriptionDOM(f.run()); assert.equal(value.viewport.scrollWidth, 810); assert.ok(!Object.hasOwn(value, 'layoutPassed'))
})
test('subscription DOM hit test records occluded and unobstructed controls independently', () => {
  const f = fixture(), connect = f.selectors.button[0]; f.context.hit = connect
  let value = validateSubscriptionDOM(f.run()); assert.equal(value.controls[0].unobstructed, true); assert.equal(value.controls[1].unobstructed, false)
  connect.box = { x: 4000, y: 10, width: 120, height: 30 }; value = validateSubscriptionDOM(f.run()); assert.equal(value.controls[0].inViewport, false); assert.equal(value.controls[0].unobstructed, false)
})
test('subscription DOM records real paging revision without inferring backend membership', () => {
  const f = fixture(); f.selectors['nav[aria-label="节点分页"]'] = [element('', { span: [element('节点第 2 页 · 版本 8')] })]
  assert.deepEqual(validateSubscriptionDOM(f.run()).paging, { candidates: null, nodes: { page: 2, revision: 8 } })
  // Actual product hierarchy: the node div is nested under the candidate panel.
  // A broad descendant query therefore sees a node-only stale paragraph too.
  const nodeOnlyStale = element('节点为旧数据。')
  f.selectors['.subscription-detail .subscription-stale'] = [nodeOnlyStale]
  f.selectors['.subscription-nodes .subscription-stale'] = [nodeOnlyStale]
  assert.deepEqual(validateSubscriptionDOM(f.run()).stale, { sources: false, candidates: false, nodes: true })
  f.selectors['.subscription-detail > section[aria-labelledby="subscription-candidates-title"] > p.subscription-stale'] = [element('候选为旧数据，不能据此写入。')]
  assert.deepEqual(validateSubscriptionDOM(f.run()).stale, { sources: false, candidates: true, nodes: true })
})
test('subscription DOM rejects duplicate fixed controls instead of choosing first match', () => {
  const f = fixture(); f.selectors.button.push(element('准备抓取候选')); rejected(f.run)
  const g = fixture(); g.rootSelectors['section.subscriptions[aria-label="订阅资源工作区"]'].push(g.panel); rejected(g.run)
})
test('subscription DOM schema rejects extra fields at every populated boundary', () => {
  const f = fixture(); f.selectors['.subscription-source-list > li'] = [source()]; f.selectors['.subscription-candidate-list > li'] = [candidate()]; f.selectors['.subscription-nodes > ul > li'] = [node()]; handoff(f); confirmation(f); receipt(f)
  const base = f.run()
  const paths = [[], ['viewport'], ['session'], ['controls', 0], ['controls', 0, 'rect'], ['sources', 0], ['candidates', 0], ['nodes', 0], ['paging'], ['directory'], ['handoff'], ['confirmation'], ['confirmation', 'binding'], ['receipt'], ['stale']]
  for (const path of paths) { const value = clone(base); let target = value; for (const part of path) target = target[part]; target.private = 'PRIVATE_EXTRA'; rejected(() => validateSubscriptionDOM(value)) }
})
test('subscription DOM schema rejects unsafe integers fractional values and wrong types', () => {
  const base = fixture().run()
  for (const invalid of [NaN, Infinity, 9007199254740992, -1, 0, 1.5, '375', null]) {
    const value = clone(base); value.viewport.width = invalid; rejected(() => validateSubscriptionDOM(value))
  }
  const f = fixture(); handoff(f); confirmation(f); const bound = f.run()
  for (const field of ['expectedRevision', 'policyRevision']) { const value = clone(bound); value.confirmation.binding[field] = 9007199254740992; rejected(() => validateSubscriptionDOM(value)) }
})
test('subscription DOM schema rejects duplicate source candidate and node identities', () => {
  const f = fixture(); f.selectors['.subscription-source-list > li'] = [source()]; f.selectors['.subscription-candidate-list > li'] = [candidate()]; f.selectors['.subscription-nodes > ul > li'] = [node()]
  const base = f.run()
  for (const key of ['sources', 'candidates', 'nodes']) { const value = clone(base); value[key].push(clone(value[key][0])); rejected(() => validateSubscriptionDOM(value)) }
})
test('subscription DOM schema rejects multiple selected resources and known-health nodes', () => {
  const f = fixture(); f.selectors['.subscription-source-list > li'] = [source(), source('src_' + 'e'.repeat(32))]; rejected(() => validateSubscriptionDOM(f.run()))
  const g = fixture(); g.selectors['.subscription-nodes > ul > li'] = [node()]; const value = g.run(); value.nodes[0].state = 'healthy'; rejected(() => validateSubscriptionDOM(value))
})
test('subscription DOM schema requires frozen control order and closed semantic states', () => {
  const base = fixture().run(); assert.deepEqual(base.controls.map(control => control.key), [...SUBSCRIPTION_DOM_CONTROL_KEYS])
  for (const mutate of [value => value.controls.reverse(), value => value.mode = 'automatic', value => value.controls[0].key = 'arbitrary_css', value => value.controls[0].present = false, value => value.session.tokenType = 'text']) {
    const value = clone(base); mutate(value); rejected(() => validateSubscriptionDOM(value))
  }
})
test('subscription DOM schema rejects malformed identifiers without leaking their value', () => {
  for (const invalid of ['PRIVATE_TOKEN', sid + '?token=PRIVATE_TOKEN', sid.toUpperCase(), 'src_' + 'a'.repeat(31)]) {
    const f = fixture(); f.selectors['.subscription-source-list > li'] = [source(invalid)]; rejected(f.run)
  }
})
test('subscription DOM private canary scanner rejects valid-shaped secrets too', () => {
  const f = fixture(); f.selectors['.subscription-source-list > li'] = [source()]
  rejected(() => assertNoPublicCanaries(f.run(), [sid])); assert.equal(assertNoPublicCanaries(f.run(), ['PRIVATE_TOKEN']).schema, 'chengwang.subscription-browser-dom/v1')
})
test('subscription DOM canary scanner rejects missing unbounded and empty canaries', () => {
  for (const invalid of [undefined, [], [''], ['x'.repeat(8193)], Array(257).fill('private'), [null]]) rejected(() => assertNoPublicCanaries(fixture().run(), invalid))
})
test('subscription DOM extractor is readonly and avoids raw content state and network APIs', () => {
  const source = collectSubscriptionDOM.toString()
  for (const forbidden of ['innerHTML', 'outerHTML', 'innerText', 'fetch(', '__react', 'setTimeout(', 'Date.now', 'localStorage.setItem', 'sessionStorage.setItem', 'Object.entries(localStorage)', 'document.title', 'location.href']) assert.ok(!source.includes(forbidden))
  assert.ok(!/\.value\s*=(?!=)|\.checked\s*=(?!=)|document\.cookie\s*=(?!=)/.test(source))
  assert.equal(createHash('sha256').update(SUBSCRIPTION_DOM_EXPRESSION).digest('hex').length, 64)
})
test('subscription DOM resource bounds reject oversized pages and unsafe candidate counts', () => {
  const value = fixture().run(); value.sources = Array.from({ length: 33 }, (_, i) => ({ id: 'src_' + i.toString(16).padStart(32, '0'), revision: 1, selected: false, accepted: false, disabled: false })); rejected(() => validateSubscriptionDOM(value))
  const f = fixture(); f.selectors['.subscription-candidate-list > li'] = [candidate()]; const candidateValue = f.run(); candidateValue.candidates[0].nodeCount = Number.MAX_SAFE_INTEGER + 1; rejected(() => validateSubscriptionDOM(candidateValue))
})
test('subscription DOM module introduces no dependency or existing probe-driver coupling', async () => {
  const source = await readFile(new URL('./collect-subscription-dom.mjs', import.meta.url), 'utf8')
  assert.ok(!/^import /m.test(source)); assert.ok(!source.includes('probe-browser')); assert.ok(!source.includes('launchProbeDriver'))
})
