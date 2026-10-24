// Passive window observation and producer-side validation. No application decoder.
import { need, exact, strictJSON, sha, validateUnknownOverview, validateUnavailableOverview } from './wire-contract.mjs'

// Entirely self-contained so its source can run in the actual browser window.
// Slot labels select controls; observed text, facts and timestamps are never
// supplied by contract/profile constants. API ordinals are filled outside this
// observation by the caller from actually settled capture rows.
export function observeOverviewDOM(slots, schema) {
  const q = (selector, root = document) => root?.querySelector(selector) ?? null
  const all = (selector, root = document) => [...(root?.querySelectorAll(selector) ?? [])]
  const rawText = node => {
    if (!node) return ''
    if (node.nodeType === 3) return node.nodeValue ?? node.textContent ?? ''
    if (node.tagName === 'BR') return ' '
    if (node.childNodes?.length) return [...node.childNodes].map(rawText).join('')
    return node.textContent ?? ''
  }
  const text = node => rawText(node).replace(/\s+/g, ' ').trim()
  const rendered = node => {
    if (!node || !node.isConnected) return false
    for (let p = node; p; p = p.parentElement) {
      const s = getComputedStyle(p)
      if (p.hidden || s.display === 'none' || ['hidden', 'collapse'].includes(s.visibility) || Number(s.opacity) === 0) return false
    }
    const r = node.getBoundingClientRect(); return r.width > 0 && r.height > 0
  }
  const rect = node => { if (!rendered(node)) return null; const r = node.getBoundingClientRect(); return { x: r.x, y: r.y, width: r.width, height: r.height } }
  const inViewport = r => !!r && r.x < innerWidth && r.y < innerHeight && r.x + r.width > 0 && r.y + r.height > 0
  const observedNode = node => { const r = rect(node); return { text: text(node), present: !!node, rendered: rendered(node), inViewport: inViewport(r), rect: r } }
  const visibleLabel = node => (node?.innerText ?? '').replace(/\s+/g, ' ').trim()
  const actualLabel = node => node?.getAttribute('aria-label')?.trim() || visibleLabel(node) || null
  const controls = slots.map(slot => {
    const matches = all(slot.selector).filter(e => actualLabel(e) === slot.label)
    if (matches.length > 1) throw Error('overview DOM rejected')
    const e = matches[0] ?? null, r = rect(e), x = r ? r.x + r.width / 2 : -1, y = r ? r.y + r.height / 2 : -1
    return { key: slot.key, label: e ? actualLabel(e) : null, labelSource: e ? e.getAttribute('aria-label')?.trim() ? 'ARIA_LABEL' : 'VISIBLE_TEXT' : null,
      present: !!e, rendered: rendered(e), enabled: !!e && !e.disabled && e.getAttribute('aria-disabled') !== 'true', inViewport: inViewport(r),
      unobstructed: !!e && !!r && x >= 0 && y >= 0 && x < innerWidth && y < innerHeight && e.contains(document.elementFromPoint(x, y)),
      ariaPressed: e?.getAttribute('aria-pressed') ?? null, rect: r }
  })
  const main = q('.main-content')
  // App preserves a hidden subscription sibling across navigation. Mounted
  // roots alone cannot identify the current page; use observed rendering.
  const activeRoot = selector => {
    const matches = all(selector, main).filter(rendered)
    if (matches.length > 1) throw Error('overview DOM rejected')
    return matches[0] ?? null
  }
  const evidence = activeRoot('.evidence-overview-page'), kernel = activeRoot('.kernel-page')
  const device = activeRoot('.readback-page'), nodes = activeRoot('.observation-page'), subscription = activeRoot('.subscriptions')
  if ([evidence, kernel, device, nodes, subscription].filter(Boolean).length > 1) throw Error('overview DOM rejected')
  const active = q('.sidebar .nav-item.active'), navigationPage = actualLabel(active)
  const root = evidence || kernel || device || nodes || subscription || main
  const viewKind = evidence ? 'actual' : kernel ? 'kernels' : device ? 'device_readback' : nodes ? 'proxy_observation' : subscription ? 'subscriptions' : rendered(q(':scope > .page-heading h1', main)) ? 'demo' : 'unknown'
  const h = q('h1', root), vb = all('.topbar .version b')
  let actual = null, demo = null, detail = null
  if (evidence) {
    const alert = q('.eo-error', evidence), pending = q('.eo-pending', evidence), summary = q('.eo-summary', evidence), unsupported = q('.eo-unsupported', evidence)
    const sourceCards = all('.eo-source-card', evidence).map(card => {
      const badge = q('.eo-state', card), sections = []; let heading = null
      for (const child of [...card.children]) {
        if (child.tagName === 'H3') heading = text(child)
        if (child.tagName === 'DL') {
          const labels = all('dt', child), values = all('dd', child)
          if (labels.length !== values.length) throw Error('overview DOM rejected')
          sections.push({ heading, facts: labels.map((label, i) => ({ label: text(label), text: text(values[i]), dateTime: q('time', values[i])?.getAttribute('datetime') ?? null })) })
        }
      }
      return { heading: text(q('h2', card)), badge: text(badge), badgeCurrent: !!badge?.classList.contains('current'), sections, buttonLabel: actualLabel(q('button', card)) }
    })
    actual = { state: alert ? 'error' : pending ? 'pending' : summary ? 'ready' : 'unknown', alert: alert ? text(alert) : null,
      pendingText: pending ? text(pending) : null, boundaryText: text(q('.eo-boundary', evidence)), summary: all('.eo-summary > span', evidence).map(text), sourceCards,
      unsupported: unsupported ? { heading: text(q('h2', unsupported)), text: text(all('p', unsupported)[0]), coverageText: text(all('p', unsupported)[1]) } : null,
      timeElements: all('time', evidence).map(e => ({ dateTime: e.getAttribute('datetime'), text: text(e) })),
      healthMetricsPresent: !!q('.metric-grid,.metric-cards,.business-panel,.pool-panel,.event-panel,.topology,.dns-row', evidence) }
  } else if (viewKind === 'demo') {
    const p = q(':scope > .page-heading p', main), strip = q('.evidence-strip > div', main)
    demo = { status: [...(p?.childNodes ?? [])].filter(n => n.nodeType === 3).map(n => n.textContent).join('').trim(), mode: text(q('strong', strip)), badge: text(q('.status', strip)),
      boundaryText: text(q('span:last-child', p)), demoAlertTitle: text(q('.demo-source-alert strong', main)), demoAlertText: text(q('.demo-source-alert span', main)),
      businessTablePresent: !!q('.business-panel', main), poolTablePresent: !!q('.pool-panel', main), eventsTablePresent: !!q('.event-panel', main), metricCardsPresent: !!q('.metric-grid,.metric-cards', main), simulatedTopologyPresent: !!q('.topology', main), dnsHealthObservedPresent: !!q('.dns-row', main) }
  } else if (['kernels', 'device_readback', 'proxy_observation', 'subscriptions'].includes(viewKind)) {
    detail = { kind: viewKind, heading: text(h), tokenInputsEmpty: all('input[type="password"]', root).every(e => e.value === ''),
      authenticatedResultVisible: all('.readback-heading .healthy-dot,.probe-detail,.subscription-scope', root).some(rendered),
      observationStatusVisible: rendered(q('.observation-summary', root)), probeStatusVisible: rendered(q('.probe-metrics', root)) }
  }
  return { schema, navigationPage, viewKind, heading: text(h), pageMounted: !!root && !!h, pageVisible: rendered(h), https: location.protocol === 'https:',
    viewport: { width: innerWidth, height: innerHeight, scrollX, scrollY, clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth },
    environment: { language: navigator.language, timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone },
    browserStorage: { localEmpty: localStorage.length === 0, sessionEmpty: sessionStorage.length === 0, cookiesEmpty: document.cookie === '' },
    topbar: { product: observedNode(q('.topbar .brand strong')), sourceLabel: observedNode(vb[0]), mode: observedNode(vb[2]), kernel: observedNode(vb[1]) },
    controls, apiFence: { snapshotCaptureOrdinal: 0, overviewCaptureOrdinals: [], observationStatusCaptureOrdinals: [], probeStatusCaptureOrdinals: [] }, actual, demo, detail }
}

export const domExpression = c => '(' + observeOverviewDOM.toString() + ')(' + JSON.stringify(c.controlSlots) + ',' + JSON.stringify(c.schemaNames.dom) + ')'
const bool = v => typeof v === 'boolean'
const integer = (v, min, max) => Number.isSafeInteger(v) && v >= min && v <= max
const same = (a, b) => {
  if (a === b) return true
  if (a === null || b === null || typeof a !== typeof b || typeof a !== 'object') return false
  if (Array.isArray(b)) return Array.isArray(a) && a.length === b.length && b.every((v, i) => same(a[i], v))
  return exact(a, Object.keys(b)) && Object.keys(b).every(key => same(a[key], b[key]))
}

export function validateDOM(d, c) {
  const check = (v, key) => need(exact(v, c.nestedExactKeys[key]))
  check(d, 'dom'); check(d.viewport, 'dom.viewport'); check(d.environment, 'dom.environment'); check(d.browserStorage, 'dom.browserStorage'); check(d.topbar, 'dom.topbar'); check(d.apiFence, 'dom.apiFence')
  need(d.schema === c.schemaNames.dom && bool(d.pageMounted) && bool(d.pageVisible) && bool(d.https))
  need(['demo', 'actual', 'kernels', 'device_readback', 'proxy_observation', 'subscriptions', 'unknown'].includes(d.viewKind))
  need(d.navigationPage === null || typeof d.navigationPage === 'string'); need(typeof d.heading === 'string')
  need(Object.values(d.browserStorage).every(bool) && typeof d.environment.language === 'string' && typeof d.environment.timeZone === 'string')
  for (const key of ['width', 'height', 'clientWidth', 'scrollWidth']) need(integer(d.viewport[key], 0, 100000))
  for (const key of ['scrollX', 'scrollY']) need(typeof d.viewport[key] === 'number' && Number.isFinite(d.viewport[key]))
  const geometry = v => {
    need(bool(v.present) && bool(v.rendered) && bool(v.inViewport))
    need(v.rendered ? v.present && v.rect !== null : v.rect === null && !v.inViewport)
    if (!v.present) need(!v.rendered && !v.inViewport)
    if (v.rect !== null) {
      check(v.rect, 'rect'); need(Object.values(v.rect).every(n => typeof n === 'number' && Number.isFinite(n)) && v.rect.width > 0 && v.rect.height > 0)
      const r = v.rect, intersects = r.x < d.viewport.width && r.y < d.viewport.height && r.x + r.width > 0 && r.y + r.height > 0
      need(v.inViewport === intersects)
    }
  }
  for (const value of Object.values(d.topbar)) { check(value, 'dom.topbar.node'); need(typeof value.text === 'string'); geometry(value); if (!value.present) need(value.text === '') }
  need(Array.isArray(d.controls) && d.controls.length === c.controlSlots.length)
  d.controls.forEach((v, i) => {
    check(v, 'dom.controls[]'); need(v.key === c.controlSlots[i].key && bool(v.enabled) && bool(v.unobstructed)); geometry(v)
    need(v.ariaPressed === null || v.ariaPressed === 'true' || v.ariaPressed === 'false')
    if (v.present) need(v.label === c.controlSlots[i].label && v.labelSource === c.controlSlots[i].labelSource)
    else need(v.label === null && v.labelSource === null && v.ariaPressed === null && !v.enabled && !v.unobstructed)
    if (v.unobstructed) need(v.rendered && v.inViewport && v.rect.x + v.rect.width / 2 >= 0 && v.rect.y + v.rect.height / 2 >= 0 && v.rect.x + v.rect.width / 2 < d.viewport.width && v.rect.y + v.rect.height / 2 < d.viewport.height)
  })
  need(integer(d.apiFence.snapshotCaptureOrdinal, 0, 77))
  for (const key of ['overviewCaptureOrdinals', 'observationStatusCaptureOrdinals', 'probeStatusCaptureOrdinals']) {
    const a = d.apiFence[key]; need(Array.isArray(a) && a.length <= 77 && a.every((n, i) => integer(n, 1, 77) && (i === 0 || n > a[i - 1])))
  }
  need((d.actual !== null) === (d.viewKind === 'actual') && (d.demo !== null) === (d.viewKind === 'demo') && (d.detail !== null) === ['kernels', 'device_readback', 'proxy_observation', 'subscriptions'].includes(d.viewKind))
  if (d.actual) {
    const a = d.actual; check(a, 'dom.actual'); need(['pending', 'ready', 'error', 'unknown'].includes(a.state)); need(a.alert === null || typeof a.alert === 'string'); need(a.pendingText === null || typeof a.pendingText === 'string'); need(typeof a.boundaryText === 'string' && bool(a.healthMetricsPresent))
    need(Array.isArray(a.summary) && a.summary.length <= 4 && a.summary.every(s => typeof s === 'string') && Array.isArray(a.sourceCards) && a.sourceCards.length <= 3 && Array.isArray(a.timeElements))
    for (const card of a.sourceCards) { check(card, 'dom.actual.sourceCards[]'); need(typeof card.heading === 'string' && typeof card.badge === 'string' && bool(card.badgeCurrent) && (card.buttonLabel === null || typeof card.buttonLabel === 'string') && Array.isArray(card.sections) && card.sections.length <= 3)
      for (const section of card.sections) { check(section, 'dom.actual.sourceCards[].sections[]'); need(section.heading === null || typeof section.heading === 'string'); need(Array.isArray(section.facts) && section.facts.length <= 16); for (const fact of section.facts) { check(fact, 'dom.actual.facts[]'); need(typeof fact.label === 'string' && typeof fact.text === 'string' && (fact.dateTime === null || typeof fact.dateTime === 'string')) } }
    }
    if (a.unsupported !== null) { check(a.unsupported, 'dom.actual.unsupported'); need(Object.values(a.unsupported).every(s => typeof s === 'string')) }
    for (const time of a.timeElements) { check(time, 'dom.actual.timeElements[]'); need(typeof time.dateTime === 'string' && typeof time.text === 'string') }
  }
  if (d.demo) { check(d.demo, 'dom.demo'); for (const key of ['businessTablePresent', 'poolTablePresent', 'eventsTablePresent', 'metricCardsPresent', 'simulatedTopologyPresent', 'dnsHealthObservedPresent']) need(bool(d.demo[key])); for (const [key, value] of Object.entries(d.demo)) if (!key.endsWith('Present')) need(typeof value === 'string') }
  if (d.detail) { check(d.detail, 'dom.detail'); need(d.detail.kind === d.viewKind && typeof d.detail.heading === 'string'); for (const key of ['tokenInputsEmpty', 'authenticatedResultVisible', 'observationStatusVisible', 'probeStatusVisible']) need(bool(d.detail[key])) }
  const walk = value => { if (typeof value === 'string') need(value.length <= 2048 && !/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/.test(value)); else if (Array.isArray(value)) { need(value.length <= 256); value.forEach(walk) } else if (value && typeof value === 'object') Object.values(value).forEach(walk) }
  walk(d); need(Buffer.byteLength(JSON.stringify(d)) <= c.captureRules.bounds.domRowBytes); return d
}

const readBody = (row, maximum) => {
  need(row.bodyState === 'present' && typeof row.responseBase64 === 'string')
  const raw = Buffer.from(row.responseBase64, 'base64'); need(raw.toString('base64') === row.responseBase64 && raw.length === row.responseBytes && sha(raw) === row.responseSHA256)
  return strictJSON(raw, maximum)
}

export function validateCheckpoint(step, d, rows, c, profile) {
  validateDOM(d, c); need(c.profiles.includes(profile) && Array.isArray(rows))
  const fence = c.stepFences[profile].find(r => r[0] === step); need(fence)
  need(d.navigationPage === fence[2] && d.viewKind === fence[3] && d.heading === fence[4] && d.pageMounted === true && d.pageVisible === true && d.https === true)
  need(d.viewport.width === fence[5] && d.viewport.height === fence[6] && d.viewport.scrollWidth === d.viewport.clientWidth && d.viewport.scrollX === 0 && d.viewport.scrollY === 0)
  need(d.environment.language === c.browserEnvironment.language && d.environment.timeZone === c.browserEnvironment.timeZone && Object.values(d.browserStorage).every(v => v === true))
  const byKind = kind => rows.filter(r => r.kind === kind).sort((a, b) => a.ordinal - b.ordinal)
  const snapshots = byKind('SNAPSHOT'), overview = byKind('OVERVIEW'), observation = byKind('OBSERVATION_STATUS'), probe = byKind('PROBE_STATUS')
  need(snapshots.length === 1 && overview.length === fence[7] && observation.length === fence[8] && probe.length === fence[9])
  need(d.apiFence.snapshotCaptureOrdinal === snapshots[0].ordinal && same(d.apiFence.overviewCaptureOrdinals, overview.map(r => r.ordinal)) && same(d.apiFence.observationStatusCaptureOrdinals, observation.map(r => r.ordinal)) && same(d.apiFence.probeStatusCaptureOrdinals, probe.map(r => r.ordinal)))
  const snapshot = readBody(snapshots[0], c.captureRules.bounds.bodyAPI)
  need(exact(snapshot, c.wireKeys.snapshot) && snapshot.dataSource === 'demo' && snapshot.mode === 'candidate' && snapshot.publishLocked === true)
  need(d.topbar.product.text === snapshot.product && d.topbar.kernel.text === '未核验')
  for (const node of Object.values(d.topbar)) { need(node.present); if (d.viewport.width <= 900) need(!node.rendered && !node.inViewport && node.rect === null); else need(node.rendered && node.inViewport) }
  const controls = new Map(d.controls.map(v => [v.key, v]))
  for (const slot of c.controlSlots) {
    const v = controls.get(slot.key)
    if (slot.key.startsWith('nav_')) need(v.present && v.rendered && v.enabled && v.ariaPressed === null)
    else if (slot.key.startsWith('source_')) { const present = ['demo', 'actual'].includes(d.viewKind); need(v.present === present && v.rendered === present && v.enabled === present); if (present) need(v.inViewport && v.ariaPressed === ((slot.key === 'source_demo') === (d.viewKind === 'demo') ? 'true' : 'false')) }
    else if (slot.key === 'actual_refresh') need(v.present === (d.viewKind === 'actual') && v.rendered === (d.viewKind === 'actual') && v.enabled === (d.viewKind === 'actual' && d.actual.state !== 'pending') && (!v.present || v.inViewport))
    else need(v.present === (d.viewKind === 'actual' && d.actual.state === 'ready') && v.rendered === (d.viewKind === 'actual' && d.actual.state === 'ready') && v.enabled === (d.viewKind === 'actual' && d.actual.state === 'ready'))
  }
  if (d.viewKind === 'actual') {
    const a = d.actual, expected = profile === 'evidence_disabled' ? c.domSemantics.disabled : c.domSemantics.enabled
    need(a.state === expected.state && a.alert === expected.alert && a.pendingText === null && a.healthMetricsPresent === false)
    need(a.boundaryText === c.domSemantics.actualBoundary + ' ' + c.domSemantics.asOfNotice)
    need(d.topbar.sourceLabel.text === expected.sourceBadge && d.topbar.mode.text === expected.modeBadge)
    const last = overview.at(-1); need(last && last.status === (profile === 'evidence_disabled' ? 503 : 200))
    if (profile === 'evidence_disabled') {
      if (last.bodyState === 'present') validateUnavailableOverview(readBody(last, c.captureRules.bounds.bodyAPI), profile)
      else need(last.bodyState === 'unavailable' && last.bodyUnavailableReason === 'BODY_RPC_REJECTED_AFTER_EXPECTED_503' && exact(last.bodyRPC, ['attempted', 'outcome']) && last.bodyRPC.attempted === true && last.bodyRPC.outcome === 'rejected' && [last.responseBase64, last.responseSHA256, last.responseBytes, last.errorCodeObserved].every(v => v === null))
      need(a.summary.length === 0 && a.sourceCards.length === 0 && a.timeElements.length === 0 && a.unsupported === null)
    } else {
      const body = validateUnknownOverview(readBody(last, c.captureRules.bounds.bodyAPI), profile)
      need(same(a.summary, c.domSemantics.summaryText.map(s => s.replace('{generatedAt}', body.generatedAt))))
      need(same(a.timeElements, [{ dateTime: body.generatedAt, text: body.generatedAt }]) && same(a.unsupported, c.domSemantics.unsupported))
      need(a.sourceCards.length === 3 && same(a.sourceCards.map(card => card.heading), c.domSemantics.cardHeadings) && a.sourceCards.every(card => card.badgeCurrent === false))
      const expectedSections = [c.domSemantics.controllerSections, [{ heading: null, facts: c.domSemantics.probeFacts }], [{ heading: null, facts: c.domSemantics.subscriptionFacts }]]
      a.sourceCards.forEach((card, i) => {
        need(card.badge === (i === 0 ? expected.controllerBadge : i === 1 ? expected.probeBadge : '') && card.buttonLabel === c.controlSlots.find(s => s.key === ['cta_device', 'cta_nodes', 'cta_subscriptions'][i]).label)
        const target = expectedSections[i].map(section => ({ heading: section.heading, facts: section.facts.map(([label, text]) => ({ label, text, dateTime: null })) }))
        need(same(card.sections, target))
      })
    }
  } else {
    need(d.topbar.sourceLabel.text === '演示草稿' && d.topbar.mode.text === snapshot.mode)
    if (d.viewKind === 'demo') {
      need(d.demo.status === snapshot.status && d.demo.mode === snapshot.mode && d.demo.badge === '总览只读' && d.demo.boundaryText === '总览仅展示数据边界；执行权限以服务端授权为准')
      need(d.demo.demoAlertTitle === '当前总览没有接入真实运行数据' && d.demo.demoAlertText === '为防止把界面示例误认为生产状态，本页已隐藏设备数量、订阅数量、业务健康、节点延迟、DNS 延迟和自动化事件等演示值。')
      for (const key of ['businessTablePresent', 'poolTablePresent', 'eventsTablePresent', 'metricCardsPresent', 'simulatedTopologyPresent', 'dnsHealthObservedPresent']) need(d.demo[key] === false)
    } else {
      need(d.detail.heading === fence[4] && d.detail.tokenInputsEmpty === true && d.detail.authenticatedResultVisible === false)
      need(d.detail.observationStatusVisible === (d.viewKind === 'proxy_observation') && d.detail.probeStatusVisible === (d.viewKind === 'proxy_observation'))
    }
  }
  return d
}
