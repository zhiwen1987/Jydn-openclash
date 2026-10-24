// Synthetic-only CPU DOM models and producer-validator negatives; no browser,
// application runtime, jsdom, HTTP or substitute real-scene PASS report.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { observeOverviewDOM, domExpression, validateDOM, validateCheckpoint } from './ui-dom.mjs'
import { sha } from './wire-contract.mjs'

const C = JSON.parse(readFileSync(new URL('../../deploy/overview-ui-browser/contract.json', import.meta.url), 'utf8'))
const clone = v => structuredClone(v)
const box = () => ({ x: 100, y: 100, width: 80, height: 44 })
const timestamp = n => '2026-10-24T12:00:00.' + String(n).padStart(9, '0') + 'Z'
const snapshot = () => ({ product: 'SYNTHETIC CPU PRODUCT', version: 'SYNTHETIC', mode: 'candidate', status: 'SYNTHETIC CPU STATUS', dataSource: 'demo', publishLocked: true, businesses: [], pools: [], interfaces: [], events: [], draft: {} })
function capture(kind, value, ordinal, status = 200) {
  const raw = Buffer.from(JSON.stringify(value)), path = { SNAPSHOT: '/api/v1/snapshot', OVERVIEW: '/api/v1/overview', OBSERVATION_STATUS: '/api/v1/observations/status', PROBE_STATUS: '/api/v1/probes/status' }[kind]
  return { kind, ordinal, requestOrdinal: ordinal, requestId: 'r' + ordinal, method: 'GET', path, status, bodyState: 'present', responseBase64: raw.toString('base64'), responseBytes: raw.length, responseSHA256: sha(raw), bodyRPC: { attempted: true, outcome: 'fulfilled' }, bodyUnavailableReason: null, errorCodeObserved: status === 503 ? 'overview_not_configured' : null }
}
function fixture(profile, step) {
  const f = C.stepFences[profile].find(r => r[0] === step), enabled = profile === 'evidence_enabled_unknown', view = f[3], actual = view === 'actual', ready = actual && enabled
  const rows = [capture('SNAPSHOT', snapshot(), 1)]
  for (let i = 1; i <= f[7]; i++) rows.push(capture('OVERVIEW', enabled ? { ...clone(C.apiExpected.overviewEnabled), generatedAt: timestamp(i) } : C.expected503Union.present.body, rows.length + 1, enabled ? 200 : 503))
  for (let i = 0; i < f[8]; i++) rows.push(capture('OBSERVATION_STATUS', C.apiExpected.observationStatusDisabled, rows.length + 1))
  for (let i = 0; i < f[9]; i++) rows.push(capture('PROBE_STATUS', C.apiExpected.probeStatusDisabled, rows.length + 1))
  const expected = enabled ? C.domSemantics.enabled : C.domSemantics.disabled
  const node = text => ({ text, present: true, rendered: f[5] > 900, inViewport: f[5] > 900, rect: f[5] > 900 ? box() : null })
  const controls = C.controlSlots.map(slot => {
    const present = slot.key.startsWith('nav_') || slot.key.startsWith('source_') && ['demo', 'actual'].includes(view) || slot.key === 'actual_refresh' && actual || slot.key.startsWith('cta_') && ready
    return { key: slot.key, label: present ? slot.label : null, labelSource: present ? slot.labelSource : null, present, rendered: present, enabled: present, inViewport: present, unobstructed: present, ariaPressed: present && slot.key.startsWith('source_') ? ((slot.key === 'source_demo') === (view === 'demo') ? 'true' : 'false') : null, rect: present ? box() : null }
  })
  const d = { schema: C.schemaNames.dom, navigationPage: f[2], viewKind: view, heading: f[4], pageMounted: true, pageVisible: true, https: true,
    viewport: { width: f[5], height: f[6], scrollX: 0, scrollY: 0, clientWidth: f[5], scrollWidth: f[5] }, environment: { language: 'zh-CN', timeZone: 'UTC' }, browserStorage: { localEmpty: true, sessionEmpty: true, cookiesEmpty: true },
    topbar: { product: node(snapshot().product), sourceLabel: node(actual ? expected.sourceBadge : '演示草稿'), mode: node(actual ? expected.modeBadge : 'candidate'), kernel: node('未核验') }, controls,
    apiFence: { snapshotCaptureOrdinal: 1, overviewCaptureOrdinals: rows.filter(r => r.kind === 'OVERVIEW').map(r => r.ordinal), observationStatusCaptureOrdinals: rows.filter(r => r.kind === 'OBSERVATION_STATUS').map(r => r.ordinal), probeStatusCaptureOrdinals: rows.filter(r => r.kind === 'PROBE_STATUS').map(r => r.ordinal) }, actual: null, demo: null, detail: null }
  if (actual) {
    const sections = [C.domSemantics.controllerSections, [{ heading: null, facts: C.domSemantics.probeFacts }], [{ heading: null, facts: C.domSemantics.subscriptionFacts }]]
    d.actual = { state: expected.state, alert: expected.alert, pendingText: null, boundaryText: C.domSemantics.actualBoundary + ' ' + C.domSemantics.asOfNotice,
      summary: ready ? C.domSemantics.summaryText.map(s => s.replace('{generatedAt}', timestamp(f[7]))) : [],
      sourceCards: ready ? sections.map((group, i) => ({ heading: C.domSemantics.cardHeadings[i], badge: i === 0 ? expected.controllerBadge : i === 1 ? expected.probeBadge : '', badgeCurrent: false, sections: group.map(s => ({ heading: s.heading, facts: s.facts.map(([label, text]) => ({ label, text, dateTime: null })) })), buttonLabel: C.controlSlots.find(s => s.key === ['cta_device', 'cta_nodes', 'cta_subscriptions'][i]).label })) : [],
      unsupported: ready ? clone(C.domSemantics.unsupported) : null, timeElements: ready ? [{ dateTime: timestamp(f[7]), text: timestamp(f[7]) }] : [], healthMetricsPresent: false }
  } else if (view === 'demo') d.demo = { status: snapshot().status, mode: 'candidate', badge: '总览只读', boundaryText: '总览仅展示数据边界；执行权限以服务端授权为准', demoAlertTitle: '当前总览没有接入真实运行数据', demoAlertText: '为防止把界面示例误认为生产状态，本页已隐藏设备数量、订阅数量、业务健康、节点延迟、DNS 延迟和自动化事件等演示值。', businessTablePresent: false, poolTablePresent: false, eventsTablePresent: false, metricCardsPresent: false, simulatedTopologyPresent: false, dnsHealthObservedPresent: false }
  else d.detail = { kind: view, heading: f[4], tokenInputsEmpty: true, authenticatedResultVisible: false, observationStatusVisible: view === 'proxy_observation', probeStatusVisible: view === 'proxy_observation' }
  return { d, rows, profile, step }
}
const check = x => validateCheckpoint(x.step, x.d, x.rows, C, x.profile)
const ready = () => fixture('evidence_enabled_unknown', 'actual_enter_desktop')
const rejectsMutation = mutate => { const x = ready(); mutate(x); assert.throws(() => check(x)) }

// Minimal synthetic tree supports only the DOM operations used by the collector.
// It is not a browser layout engine and cannot establish actual CSS visibility.
class Element {
  constructor(tag, text = '') { this.tagName = tag; this.nodeType = 1; this.nodeValue = null; this.parentElement = null; this.isConnected = true; this.hidden = false; this.disabled = false; this.attrs = {}; this.value = ''; this.children = []; this.childNodes = text ? [{ nodeType: 3, nodeValue: text, textContent: text }] : []; this.queries = new Map(); this.style = { display: 'block', visibility: 'visible', opacity: '1' }; this.bbox = box(); this.classes = new Set(); this.classList = { contains: c => this.classes.has(c) } }
  get textContent() { return this.childNodes.map(n => n.nodeType === 3 ? n.nodeValue : n.textContent).join('') }
  get innerText() { return this.style.display === 'none' ? '' : this.textContent }
  getAttribute(key) { return Object.hasOwn(this.attrs, key) ? this.attrs[key] : null }
  getBoundingClientRect() { return { ...this.bbox } }
  contains(other) { return this === other || this.children.some(e => e.contains(other)) }
  querySelectorAll(selector) { if (this.queries.has(selector)) return this.queries.get(selector); return selector.includes(',') ? [...new Set(selector.split(',').flatMap(s => this.querySelectorAll(s)))] : [] }
  querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null }
  set(selector, ...values) { this.queries.set(selector, values); for (const value of values) if (!value.parentElement) value.parentElement = this; return this }
  append(...elements) { this.children.push(...elements); this.childNodes.push(...elements); for (const e of elements) e.parentElement = this; return this }
}
function syntheticWindow() {
  const x = ready(), doc = new Element('DOCUMENT'), main = new Element('MAIN'), root = new Element('DIV'), h = new Element('H1', 'OBSERVED ACTUAL HEADING')
  const nav = new Element('BUTTON'); nav.attrs['aria-label'] = '运行总览'
  doc.documentElement = { clientWidth: 1440, scrollWidth: 1440 }; doc.cookie = ''; doc.hit = new Map(); doc.elementFromPoint = (a, b) => doc.hit.get(a + ':' + b) ?? null
  doc.set('.main-content', main).set('.sidebar .nav-item.active', nav); main.set('.evidence-overview-page', root); root.set('h1', h)
  const boundary = new Element('DIV').append(new Element('SPAN', 'OBSERVED FIRST'), new Element('BR'), new Element('SPAN', 'OBSERVED SECOND'))
  root.set('.eo-boundary', boundary).set('.eo-summary', new Element('DIV')).set('.eo-summary > span', ...x.d.actual.summary.map(s => new Element('SPAN', s)))
  const times = x.d.actual.timeElements.map(v => { const t = new Element('TIME', v.text); t.attrs.datetime = v.dateTime; return t }); root.set('time', ...times)
  const cards = x.d.actual.sourceCards.map(card => {
    const e = new Element('SECTION'), head = new Element('H2', card.heading), badge = new Element('SPAN', card.badge), button = new Element('BUTTON', card.buttonLabel)
    e.set('h2', head).set('button', button); if (card.badge) e.set('.eo-state', badge)
    for (const section of card.sections) {
      if (section.heading) e.append(new Element('H3', section.heading))
      const dl = new Element('DL'), terms = section.facts.map(f => new Element('DT', f.label)), values = section.facts.map(f => new Element('DD', f.text))
      dl.set('dt', ...terms).set('dd', ...values); e.append(dl)
    }
    return e
  }); root.set('.eo-source-card', ...cards)
  const unsupported = new Element('SECTION').set('h2', new Element('H2', x.d.actual.unsupported.heading)).set('p', new Element('P', x.d.actual.unsupported.text), new Element('P', x.d.actual.unsupported.coverageText)); root.set('.eo-unsupported', unsupported)
  const product = new Element('STRONG', 'OBSERVED PRODUCT'), values = ['OBSERVED SOURCE', 'OBSERVED KERNEL', 'OBSERVED MODE'].map(s => new Element('B', s))
  doc.set('.topbar .brand strong', product).set('.topbar .version b', ...values)
  const selectors = new Map()
  C.controlSlots.forEach((slot, i) => {
    const state = x.d.controls[i]; if (!state.present) return
    const e = new Element('BUTTON', slot.label); if (slot.labelSource === 'ARIA_LABEL') e.attrs['aria-label'] = slot.label
    if (state.ariaPressed !== null) e.attrs['aria-pressed'] = state.ariaPressed
    e.bbox.x = i * 90; e.bbox.y = 100; doc.hit.set((e.bbox.x + 40) + ':122', e)
    if (!selectors.has(slot.selector)) selectors.set(slot.selector, []); selectors.get(slot.selector).push(e)
  })
  for (const [selector, values] of selectors) doc.set(selector, ...values)
  const globals = { document: doc, getComputedStyle: e => e.style, innerWidth: 1440, innerHeight: 900, scrollX: 0, scrollY: 0, location: { protocol: 'https:' }, navigator: { language: 'zh-CN' }, localStorage: { length: 0 }, sessionStorage: { length: 0 } }
  const run = fn => { const saved = new Map(Object.keys(globals).map(k => [k, Object.getOwnPropertyDescriptor(globalThis, k)])); try { for (const [k, value] of Object.entries(globals)) Object.defineProperty(globalThis, k, { configurable: true, writable: true, value }); return fn() } finally { for (const [k, descriptor] of saved) if (descriptor) Object.defineProperty(globalThis, k, descriptor); else delete globalThis[k] } }
  return { x, doc, main, root, h, boundary, cards, product, values, globals, run }
}

test('d01 synthetic profile matrix accepts all eleven and seventeen declared steps', () => { for (const profile of C.profiles) for (const f of C.stepFences[profile]) assert.equal(check(fixture(profile, f[0])).viewKind, f[3]) })
test('d02 actual nav label and nested actual heading are distinct observations', () => {
  const w = syntheticWindow(), d = w.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom))
  assert.equal(d.navigationPage, '运行总览'); assert.equal(d.viewKind, 'actual'); assert.equal(d.heading, 'OBSERVED ACTUAL HEADING'); assert.equal(d.apiFence.snapshotCaptureOrdinal, 0); assert.deepEqual(d.apiFence.overviewCaptureOrdinals, [])
  const subscription = (tree, title, hidden = false) => {
    const wrapper = new Element('DIV'), section = new Element('SECTION'), heading = new Element('H1', title)
    wrapper.hidden = hidden; wrapper.parentElement = tree.main; wrapper.append(section); section.set('h1', heading)
    return { wrapper, section, heading }
  }
  // The actual App retains Subscriptions inside a hidden sibling DIV even on
  // the demo page. Query presence must not replace the visible page identity.
  for (const hide of [s => s.wrapper.hidden = true, s => s.wrapper.style.display = 'none', s => s.wrapper.style.visibility = 'hidden', s => s.wrapper.style.opacity = '0', s => s.section.isConnected = false]) {
    const demo = syntheticWindow(), mounted = subscription(demo, 'HIDDEN SUBSCRIPTION HEADING')
    hide(mounted); demo.main.set('.evidence-overview-page').set('.subscriptions', mounted.section)
    const heading = new Element('H1', 'OBSERVED DEMO HEADING')
    demo.main.set(':scope > .page-heading h1', heading).set('h1', heading)
    const observed = demo.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom))
    assert.equal(observed.viewKind, 'demo'); assert.equal(observed.heading, 'OBSERVED DEMO HEADING'); assert.equal(observed.pageVisible, true); assert.equal(observed.detail, null)
  }
  const actual = syntheticWindow(), hidden = subscription(actual, 'HIDDEN SUBSCRIPTION HEADING', true)
  actual.main.set('.subscriptions', hidden.section)
  assert.equal(actual.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom)).viewKind, 'actual')
  const active = syntheticWindow(), absent = subscription(active, 'HIDDEN OLD HEADING', true), visible = subscription(active, 'OBSERVED SUBSCRIPTION HEADING')
  active.main.set('.evidence-overview-page').set('.subscriptions', absent.section, visible.section)
  const observed = active.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom))
  assert.equal(observed.viewKind, 'subscriptions'); assert.equal(observed.heading, 'OBSERVED SUBSCRIPTION HEADING'); assert.equal(observed.pageVisible, true)
  const duplicate = subscription(active, 'SECOND VISIBLE SUBSCRIPTION')
  active.main.set('.subscriptions', visible.section, duplicate.section)
  assert.throws(() => active.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom)))
  const mixed = syntheticWindow(), other = subscription(mixed, 'VISIBLE SUBSCRIPTION BESIDE ACTUAL')
  mixed.main.set('.subscriptions', other.section)
  assert.throws(() => mixed.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom)))
})
test('d03 collector reads both actual boundary paragraphs across br without constants', () => { const w = syntheticWindow(), d = w.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom)); assert.equal(d.actual.boundaryText, 'OBSERVED FIRST OBSERVED SECOND'); assert(!d.actual.boundaryText.includes(C.domSemantics.asOfNotice)); assert.equal(d.actual.sourceCards[0].sections[0].facts[0].text, '未配置') })
test('d04 changing actual observed fact survives capture and is rejected by mapping', () => { const w = syntheticWindow(); w.cards[0].children[0].querySelectorAll('dd')[0].childNodes[0].nodeValue = 'OBSERVED DIFFERENT'; const observed = w.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom)); assert.equal(observed.actual.sourceCards[0].sections[0].facts[0].text, 'OBSERVED DIFFERENT'); const x = ready(); x.d.actual.sourceCards = observed.actual.sourceCards; assert.throws(() => check(x)) })
test('d05 hidden mobile topbar retains mounted text without pretending it rendered', () => { const w = syntheticWindow(); for (const node of [w.product, ...w.values]) node.style.display = 'none'; const d = w.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom)); assert.equal(d.topbar.product.text, 'OBSERVED PRODUCT'); assert.equal(d.topbar.product.present, true); assert.equal(d.topbar.product.rendered, false); assert.equal(d.topbar.product.inViewport, false); assert.equal(d.topbar.product.rect, null) })
test('d06 belowfold control rendering viewport and obstruction remain separate', () => { const w = syntheticWindow(); const e = w.doc.querySelectorAll('.eo-source-card button')[0]; e.bbox.y = 1200; const d = w.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom)); const v = d.controls.find(a => a.key === 'cta_device'); assert.equal(v.rendered, true); assert.equal(v.inViewport, false); assert.equal(v.unobstructed, false); assert(v.rect.y > 900) })
test('d07 missing control never receives a contract label or pressed state', () => { const w = syntheticWindow(); w.doc.queries.set('.overview-source-switch button', []); const d = w.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom)); const v = d.controls.find(a => a.key === 'source_actual'); assert.equal(v.present, false); assert.equal(v.label, null); assert.equal(v.ariaPressed, null) })
test('d08 duplicate matching controls are rejected rather than picked arbitrarily', () => { const w = syntheticWindow(); const a = w.doc.querySelectorAll('.overview-source-switch button'); w.doc.queries.set('.overview-source-switch button', [...a, a[0]]); assert.throws(() => w.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom))) })
test('d09 protected result visibility is observed and password values never exported', () => { const w = syntheticWindow(); w.main.queries.delete('.evidence-overview-page'); const r = new Element('DIV'), h = new Element('H1', 'OBSERVED DEVICE'), input = new Element('INPUT'), marker = new Element('SPAN'); input.value = 'SYNTHETIC-PASSWORD-DO-NOT-EXPORT'; r.set('h1', h).set('input[type="password"]', input).set('.readback-heading .healthy-dot,.probe-detail,.subscription-scope', marker); w.main.set('.readback-page', r); const d = w.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom)); assert.equal(d.detail.tokenInputsEmpty, false); assert.equal(d.detail.authenticatedResultVisible, true); assert(!JSON.stringify(d).includes(input.value)); marker.style.display = 'none'; assert.equal(w.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom)).detail.authenticatedResultVisible, false) })
test('d10 actual time text and datetime are retained independently', () => { const w = syntheticWindow(), t = w.root.querySelector('time'); t.childNodes[0].nodeValue = 'OBSERVED TIME TEXT'; t.attrs.datetime = 'OBSERVED DATETIME'; const d = w.run(() => observeOverviewDOM(C.controlSlots, C.schemaNames.dom)); assert.deepEqual(d.actual.timeElements, [{ text: 'OBSERVED TIME TEXT', dateTime: 'OBSERVED DATETIME' }]) })
test('d11 collector source is self contained and has no state network or input mutation', () => { const s = observeOverviewDOM.toString(), expression = domExpression(C); assert(expression.startsWith('(')); assert(expression.includes(s)); for (const pattern of [/\bfetch\s*\(/, /dispatchEvent\s*\(/, /setAttribute\s*\(/, /\.click\s*\(/, /\.setItem\s*\(/, /Date\.now\s*\(/, /scrollTo\s*\(/, /scrollIntoView\s*\(/]) assert(!pattern.test(s), String(pattern)); assert(!s.includes('domSemantics')); assert(!s.includes('apiExpected')) })

test('d12 extra nested keys and old fabricated authenticated field reject', () => { rejectsMutation(x => { x.d.actual.syntheticHealthy = true }); const x = fixture('evidence_enabled_unknown', 'device_page_desktop'); x.d.detail.authenticatedReadPerformed = false; assert.throws(() => check(x)) })
test('d13 unknown or wrong step profile cannot be certified', () => { const x = ready(); assert.throws(() => validateCheckpoint('not-a-step', x.d, x.rows, C, x.profile)); assert.throws(() => validateCheckpoint(x.step, x.d, x.rows, C, 'production')) })
test('d14 page nav heading mounted TLS locale and storage assertions are exact', () => { for (const mutate of [x => x.d.navigationPage = '系统闭环', x => x.d.heading = '运行总览', x => x.d.pageMounted = false, x => x.d.pageVisible = false, x => x.d.https = false, x => x.d.environment.language = 'en-US', x => x.d.environment.timeZone = 'Asia/Shanghai', x => x.d.browserStorage.localEmpty = false]) rejectsMutation(mutate) })
test('d15 root horizontal overflow and nonzero scroll never pass screenshot checkpoint', () => { for (const mutate of [x => x.d.viewport.scrollWidth++, x => x.d.viewport.scrollWidth--, x => x.d.viewport.scrollX = 1, x => x.d.viewport.scrollY = 1, x => x.d.viewport.width = 375]) rejectsMutation(mutate) })
test('d16 fake visible mobile metadata and nonexistent hidden nodes reject', () => { const x = fixture('evidence_enabled_unknown', 'actual_mobile'); x.d.topbar.mode.rendered = true; x.d.topbar.mode.inViewport = true; x.d.topbar.mode.rect = box(); assert.throws(() => check(x)); const y = ready(); y.d.topbar.sourceLabel.present = false; assert.throws(() => check(y)) })
test('d17 wrong topbar scope and stale previous mode reject', () => { rejectsMutation(x => x.d.topbar.sourceLabel.text = '演示草稿'); rejectsMutation(x => x.d.topbar.mode.text = 'shadow'); const x = fixture('evidence_enabled_unknown', 'kernels_page_desktop'); x.d.topbar.sourceLabel.text = '实际证据汇总'; assert.throws(() => check(x)) })
test('d18 source pressed attributes must reflect actual selected view', () => { rejectsMutation(x => x.d.controls.find(v => v.key === 'source_actual').ariaPressed = 'false'); rejectsMutation(x => x.d.controls.find(v => v.key === 'source_demo').ariaPressed = true) })
test('d19 controls cannot hide absent controls add labels or forge geometry', () => { for (const mutate of [x => x.d.controls.find(v => v.key === 'nav_nodes').present = false, x => x.d.controls.find(v => v.key === 'actual_refresh').enabled = false, x => x.d.controls[0].rect.width = Infinity, x => { x.d.controls[0].inViewport = false; x.d.controls[0].unobstructed = true }, x => Object.assign(x.d.controls.find(v => v.key === 'cta_nodes'), { rendered: false, inViewport: false, unobstructed: false, rect: null })]) rejectsMutation(mutate) })
test('d20 latest response fence and exact per kind counts prevent old mount reuse', () => { const x = fixture('evidence_enabled_unknown', 'actual_refresh_desktop'); x.d.apiFence.overviewCaptureOrdinals.pop(); assert.throws(() => check(x)); const y = ready(); y.rows.push(clone(y.rows.at(-1))); assert.throws(() => check(y)); rejectsMutation(z => z.d.apiFence.snapshotCaptureOrdinal = 0) })
test('d21 raw body canonical base64 bytes hash and JSON are independently required', () => { for (const mutate of [x => x.rows.at(-1).responseBytes++, x => x.rows.at(-1).responseSHA256 = '0'.repeat(64), x => x.rows.at(-1).responseBase64 += '\n', x => x.rows.at(-1).responseBase64 = Buffer.from('{"bad":').toString('base64')]) rejectsMutation(mutate) })
test('d22 current raw generatedAt must equal both displayed text and datetime', () => { rejectsMutation(x => x.d.actual.timeElements[0].text = timestamp(999)); rejectsMutation(x => x.d.actual.timeElements[0].dateTime = timestamp(999)); rejectsMutation(x => x.d.actual.summary[2] = x.d.actual.summary[2].replace(timestamp(1), timestamp(999))) })
test('d23 equal assembly timestamps across distinct refresh requests remain valid', () => { const x = fixture('evidence_enabled_unknown', 'actual_refresh_desktop'); const body = { ...clone(C.apiExpected.overviewEnabled), generatedAt: timestamp(1) }; x.rows[2] = capture('OVERVIEW', body, 3); x.d.actual.summary = C.domSemantics.summaryText.map(s => s.replace('{generatedAt}', timestamp(1))); x.d.actual.timeElements = [{ text: timestamp(1), dateTime: timestamp(1) }]; assert.equal(check(x).actual.state, 'ready') })
test('d24 boundary truncation or inserted nonobserved asof language reject', () => { rejectsMutation(x => x.d.actual.boundaryText = C.domSemantics.actualBoundary); rejectsMutation(x => x.d.actual.boundaryText += ' refreshed automatically') })
test('d25 no source facts cannot become healthy current counts or zero inventory', () => { for (const mutate of [x => x.d.actual.sourceCards[0].badgeCurrent = true, x => x.d.actual.sourceCards[1].sections[0].facts.at(-1).text = '0', x => x.d.actual.sourceCards[2].sections[0].facts.at(-1).text = '0', x => x.d.actual.healthMetricsPresent = true, x => x.d.actual.unsupported.coverageText = '全部正常']) rejectsMutation(mutate) })
test('d26 fact section heading order labels values and source time nulls are exact', () => { for (const mutate of [x => x.d.actual.sourceCards.reverse(), x => x.d.actual.sourceCards[0].sections[1].heading = 'OTHER', x => x.d.actual.sourceCards[0].sections[0].facts[0].label = 'OTHER', x => x.d.actual.sourceCards[0].sections[0].facts[5].dateTime = timestamp(1)]) rejectsMutation(mutate) })
test('d27 disabled fixed HTTP error clears report cards timestamps and stale mode', () => { const x = fixture('evidence_disabled', 'actual_enter_desktop'); assert.equal(check(x).actual.state, 'error'); for (const mutate of [y => y.d.actual.alert = 'network failed', y => y.d.actual.summary = ['old'], y => y.d.actual.sourceCards = ready().d.actual.sourceCards, y => y.d.actual.timeElements = [{ text: timestamp(1), dateTime: timestamp(1) }], y => y.d.topbar.mode.text = 'candidate']) { const y = clone(x); mutate(y); assert.throws(() => check(y)) } })
test('d28 qualified missing 503 body checks actual null union without pretending privacy', () => { const x = fixture('evidence_disabled', 'actual_enter_desktop'), row = x.rows.at(-1); Object.assign(row, { bodyState: 'unavailable', bodyUnavailableReason: 'BODY_RPC_REJECTED_AFTER_EXPECTED_503', bodyRPC: { attempted: true, outcome: 'rejected' }, responseBase64: null, responseSHA256: null, responseBytes: null, errorCodeObserved: null }); assert.equal(check(x).actual.state, 'error'); for (const change of [{ responseBytes: 0 }, { bodyRPC: { attempted: false, outcome: 'rejected' } }, { bodyUnavailableReason: 'ANY_ERROR' }, { errorCodeObserved: 'overview_not_configured' }]) { const y = clone(x); Object.assign(y.rows.at(-1), change); assert.throws(() => check(y)) } })
test('d29 200 missing body and wrong disabled body code cannot be accepted', () => { rejectsMutation(x => Object.assign(x.rows.at(-1), { bodyState: 'unavailable', responseBase64: null })); const x = fixture('evidence_disabled', 'actual_enter_desktop'); x.rows[1] = capture('OVERVIEW', { code: 'overview_projection_invalid', message: 'different' }, 2, 503); assert.throws(() => check(x)) })
test('d30 detail authenticated result token and both status observations are enforced', () => { for (const mutate of [x => x.d.detail.authenticatedResultVisible = true, x => x.d.detail.tokenInputsEmpty = false, x => x.d.detail.observationStatusVisible = false, x => x.d.detail.probeStatusVisible = false]) { const x = fixture('evidence_enabled_unknown', 'nodes_page_desktop'); mutate(x); assert.throws(() => check(x)) } })
test('d31 demo editing scope cannot claim actual or revive synthetic health tables', () => { const x = fixture('evidence_disabled', 'demo_return_desktop'); assert.equal(check(x).demo.mode, 'candidate'); for (const key of ['businessTablePresent', 'poolTablePresent', 'eventsTablePresent', 'metricCardsPresent', 'simulatedTopologyPresent', 'dnsHealthObservedPresent']) { const y = clone(x); y.d.demo[key] = true; assert.throws(() => check(y)) } })
test('d32 schema bounds reject control characters huge text and mismatched payload kind', () => { rejectsMutation(x => x.d.heading += '\nSECRET'); rejectsMutation(x => x.d.actual.boundaryText = 'a'.repeat(2049)); rejectsMutation(x => x.d.demo = fixture('evidence_disabled', 'demo_desktop').d.demo); const x = ready(); x.d.viewport.scrollX = NaN; assert.throws(() => validateDOM(x.d, C)) })
test('d33 rendered but offscreen CTA remains valid without on screen screenshot claim', () => { const x = ready(), v = x.d.controls.find(v => v.key === 'cta_device'); v.rect.y = 1200; v.inViewport = false; v.unobstructed = false; assert.equal(check(x).controls.find(v => v.key === 'cta_device').rendered, true) })
test('d34 stale source report can never be retained alongside pending state', () => { const x = ready(); x.d.actual.state = 'pending'; x.d.actual.pendingText = C.domSemantics.pendingText; x.d.controls.find(v => v.key === 'actual_refresh').enabled = false; assert.throws(() => check(x)) })
