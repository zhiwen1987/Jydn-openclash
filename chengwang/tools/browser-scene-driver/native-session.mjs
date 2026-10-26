// CI-only native browser lifecycle. Import starts no browser, process or network.
import { spawn, execFile } from 'node:child_process'
import { lstat, mkdir, readFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { setTimeout as delay } from 'node:timers/promises'
import { promisify } from 'node:util'
import { pathToFileURL } from 'node:url'
import { stableFile, ownedDirectory, until, Transport, chromeIdentity, noLiveChrome } from '../subscription-ui-browser/ui-driver.mjs'
import { versionProjection } from '../subscription-ui-browser/ui-contract.mjs'
import { configureNativeLocale } from '../capability-truth-browser/ui-driver.mjs'
import { inspectPublicTLS, browserTLSProof } from '../../web/scripts/trust-browser-tls.mjs'

const execute = promisify(execFile)
const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join(',') === [...keys].sort().join(',')
const integer = (v, min, max) => Number.isSafeInteger(v) && v >= min && v <= max
const rejected = () => new Error('native browser session rejected')
const need = v => { if (!v) throw rejected() }
const protectedTypes = new Set(['page', 'service_worker', 'shared_worker'])
const targetId = v => typeof v === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(v)
const targetType = v => typeof v === 'string' && /^[a-z_]{1,64}$/.test(v)
const optionKeys = ['root', 'bundle', 'engine', 'sourceCommit', 'fixtureId', 'chrome', 'launcher', 'home', 'profile']
const exitKeys = ['schema', 'engine', 'fixtureId', 'pid', 'startTicks', 'exitCode', 'joined', 'forced']
export const SESSION_EVENTS = Object.freeze([
  'Network.requestWillBeSent', 'Network.responseReceived', 'Network.responseReceivedExtraInfo',
  'Network.loadingFinished', 'Network.loadingFailed', 'Runtime.exceptionThrown',
  'Runtime.consoleAPICalled', 'Log.entryAdded', 'Network.webSocketCreated',
  'Network.webTransportCreated', 'Network.directTCPSocketCreated',
  'Network.directUDPSocketCreated',
  'Runtime.executionContextDestroyed', 'Runtime.executionContextsCleared',
  'Page.frameNavigated', 'Page.frameDetached', 'Inspector.detached',
])
export const SESSION_FAULTS = Object.freeze([
  'EXTRA_TARGET', 'INVALID_TARGET_STATE', 'TRANSPORT_CLOSED', 'SESSION_DETACHED',
  'PAGE_CLOSED', 'PAGE_CRASHED', 'CONTEXT_CLOSED', 'HOOK_REJECTED',
  'PROTOCOL_REJECTED', 'STARTUP_REJECTED', 'CLOSE_REJECTED',
])
// Failure-only labels; no observation authorizes a target or retries startup.
export const NATIVE_OPEN_STAGES = Object.freeze([
  'ENVIRONMENT', 'OWNED_DIRECTORIES', 'LAUNCH_CONFIG', 'CERTIFICATES',
  'NSS_DIRECTORIES', 'EXECUTABLES', 'NSS_CREATE', 'NSS_IMPORT', 'NSS_VERIFY',
  'CDP_LAUNCH', 'CDP_PORT_WAIT', 'CDP_WEBSOCKET', 'CDP_TRANSPORT',
  'CDP_INITIAL_TARGETS', 'CDP_CREATE_TARGET', 'CDP_ATTACH_TARGET',
  'CDP_SESSION_BIND', 'CDP_POST_TARGETS', 'CDP_DISCOVER_TARGETS',
  'PW_PACKAGE', 'PW_LAUNCH', 'PW_ATTACH', 'PW_TARGETS', 'BROWSER_VERSION',
  'PROCESS_IDENTITY', 'DOMAINS_ENABLE', 'NETWORK_ENABLE', 'LOCALE', 'OPEN_COMPLETE',
])
const typeKeys = ['page', 'serviceWorker', 'sharedWorker', 'tab', 'browser', 'other', 'invalid']
const initialKeys = ['shape', 'total', 'pages', 'blankPages', 'types', 'rowsValid', 'idsValid', 'idsUnique', 'guardPredicate']
const postKeys = ['shape', 'total', 'pages', 'blankPages', 'types', 'rowsValid', 'idsValid', 'idsUnique', 'guardPredicate', 'initialPresent', 'initialKind', 'selectedPresent', 'selectedKind', 'extraProtectedCount', 'extraWorkers']
const initialPredicates = ['UNOBSERVED', 'INPUT_INVALID', 'PASS', 'EMPTY_OR_BOUNDS', 'ROW_INVALID', 'ID_INVALID', 'TYPE_INVALID', 'ID_DUPLICATE', 'PROTECTED_NON_PAGE', 'PAGE_COUNT', 'INITIAL_PAGE_URL']
const postPredicates = ['UNOBSERVED', 'INPUT_INVALID', 'PASS', 'EMPTY_OR_BOUNDS', 'ROW_INVALID', 'ID_INVALID', 'TYPE_INVALID', 'ID_DUPLICATE', 'SELECTED_NOT_PAGE', 'SELECTED_EQUALS_INITIAL', 'INITIAL_NOT_PAGE', 'UNAUTHORIZED_PROTECTED']
const publicKinds = ['page', 'service_worker', 'shared_worker', 'tab', 'browser', 'OTHER', 'INVALID', 'ABSENT']
const workerTypeKeys = ['serviceWorker', 'sharedWorker']
const urlSchemeKeys = ['EMPTY', 'ABOUT', 'CHROME_INTERNAL', 'CHROME_EXTENSION', 'DEVTOOLS', 'HTTP', 'HTTPS', 'DATA_BLOB', 'OTHER', 'INVALID']
const openerRelationKeys = ['INITIAL', 'SELECTED', 'BOTH', 'OTHER', 'MISSING', 'INVALID']
const contextRelationKeys = ['MATCH', 'DIFFERENT', 'WORKER_MISSING', 'REFERENCE_MISSING', 'BOTH_MISSING', 'INVALID']
const extraWorkerKeys = ['total', 'types', 'urlSchemes', 'openerRelations', 'contextToInitial', 'contextToSelected',
  'hasExtraWorkers', 'anyOpenerMatchesInitial', 'anyOpenerMatchesSelected', 'anyContextMatchesInitial',
  'anyContextMatchesSelected', 'anyOpenerMissing', 'anyContextMissing', 'anyInvalidField']
const emptyTypes = () => ({ page: 0, serviceWorker: 0, sharedWorker: 0, tab: 0, browser: 0, other: 0, invalid: 0 })
const histogram = keys => Object.fromEntries(keys.map(key => [key, 0]))
const typeProjection = value => {
  if (!targetType(value)) return { bucket: 'invalid', kind: 'INVALID' }
  if (value === 'service_worker') return { bucket: 'serviceWorker', kind: value }
  if (value === 'shared_worker') return { bucket: 'sharedWorker', kind: value }
  if (['page', 'tab', 'browser'].includes(value)) return { bucket: value, kind: value }
  return { bucket: 'other', kind: 'OTHER' }
}
const emptyInitialTargets = shape => ({ shape, total: null, pages: null, blankPages: null, types: null,
  rowsValid: null, idsValid: null, idsUnique: null, guardPredicate: shape === 'UNOBSERVED' ? 'UNOBSERVED' : 'INPUT_INVALID' })
export function projectInitialTargets(rows) {
  try {
    if (!Array.isArray(rows) || rows.length > 64) return emptyInitialTargets('INVALID')
    const types = emptyTypes(), observedIds = new Set(), guardIds = new Set()
    let pages = 0, blankPages = 0, rowsValid = true, idsValid = true, idsUnique = true
    let guardPredicate = rows.length === 0 ? 'EMPTY_OR_BOUNDS' : 'PASS', initialPageURL = false
    for (let i = 0; i < rows.length; i++) {
      const slot = Object.getOwnPropertyDescriptor(rows, String(i)), row = slot && Object.hasOwn(slot, 'value') ? dataRecord(slot.value) : null
      if (!row) { rowsValid = false; idsValid = false; idsUnique = false; types.invalid++; if (guardPredicate === 'PASS') guardPredicate = 'ROW_INVALID'; continue }
      const idOK = targetId(row.targetId), duplicate = idOK && observedIds.has(row.targetId), type = typeProjection(row.type)
      types[type.bucket]++
      if (!idOK) { idsValid = false; if (guardPredicate === 'PASS') guardPredicate = 'ID_INVALID' }
      else { if (duplicate) idsUnique = false; observedIds.add(row.targetId) }
      if (guardPredicate === 'PASS' && type.kind === 'INVALID') guardPredicate = 'TYPE_INVALID'
      if (guardPredicate === 'PASS' && guardIds.has(row.targetId)) guardPredicate = 'ID_DUPLICATE'
      if (idOK && type.kind !== 'INVALID' && !guardIds.has(row.targetId)) guardIds.add(row.targetId)
      if (type.kind === 'page') {
        pages++
        if (typeof row.url === 'string' && row.url === 'about:blank') { blankPages++; initialPageURL = pages === 1 }
      } else if (protectedTypes.has(type.kind) && guardPredicate === 'PASS') guardPredicate = 'PROTECTED_NON_PAGE'
    }
    if (guardPredicate === 'PASS' && pages !== 1) guardPredicate = 'PAGE_COUNT'
    if (guardPredicate === 'PASS' && !initialPageURL) guardPredicate = 'INITIAL_PAGE_URL'
    return { shape: 'ARRAY', total: rows.length, pages, blankPages, types, rowsValid, idsValid, idsUnique, guardPredicate }
  } catch { return emptyInitialTargets('INVALID') }
}
const targetPhases = ['BUFFERING', 'ARMED', 'CLOSING', 'CLOSED']
const targetFaults = ['EXTRA_TARGET', 'INVALID_TARGET_STATE', 'SESSION_DETACHED']
const emptyPostTargets = shape => ({ shape, total: null, pages: null, blankPages: null, types: null,
  rowsValid: null, idsValid: null, idsUnique: null, guardPredicate: shape === 'UNOBSERVED' ? 'UNOBSERVED' : 'INPUT_INVALID',
  initialPresent: null, initialKind: null, selectedPresent: null, selectedKind: null, extraProtectedCount: null, extraWorkers: null })
// Read own data descriptors only: a diagnostic must not invoke a getter or
// expose the private identities used for the two membership comparisons.
function dataRecord(value, keys = null) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const descriptors = Object.getOwnPropertyDescriptors(value), names = Object.keys(descriptors)
  if (keys && (names.length !== keys.length || names.some(key => !keys.includes(key)))) return null
  if (names.some(key => !Object.hasOwn(descriptors[key], 'value'))) return null
  return Object.fromEntries(names.map(key => [key, descriptors[key].value]))
}
function validateTypes(value, total, pages) {
  const types = dataRecord(value, typeKeys)
  return types !== null && typeKeys.every(key => integer(types[key], 0, total))
    && typeKeys.reduce((sum, key) => sum + types[key], 0) === total && types.page === pages
}
function ownField(value, key, validate) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { state: 'INVALID', value: null }
  const field = Object.getOwnPropertyDescriptor(value, key)
  if (!field) return { state: 'MISSING', value: null }
  if (!Object.hasOwn(field, 'value') || !validate(field.value)) return { state: 'INVALID', value: null }
  return { state: 'VALUE', value: field.value }
}
function contextField(value) {
  return ownField(value, 'browserContextId', id => typeof id === 'string' && id.length >= 1 && id.length <= 256 && !/[\x00-\x1f\x7f]/.test(id))
}
function contextRelation(worker, reference) {
  if (worker.state === 'INVALID' || reference.state === 'INVALID') return 'INVALID'
  if (worker.state === 'MISSING' && reference.state === 'MISSING') return 'BOTH_MISSING'
  if (worker.state === 'MISSING') return 'WORKER_MISSING'
  if (reference.state === 'MISSING') return 'REFERENCE_MISSING'
  return worker.value === reference.value ? 'MATCH' : 'DIFFERENT'
}
function urlScheme(value) {
  const field = ownField(value, 'url', url => typeof url === 'string')
  if (field.state !== 'VALUE') return 'INVALID'
  if (field.value.length === 0) return 'EMPTY'
  if (field.value.length > 4096 || /[\x00-\x1f\x7f]/.test(field.value)) return 'INVALID'
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(field.value)
  if (!match) return 'INVALID'
  const scheme = match[1].toLowerCase()
  if (scheme === 'about') return 'ABOUT'
  if (['chrome', 'chrome-untrusted', 'chrome-search', 'chrome-native', 'chrome-internal'].includes(scheme)) return 'CHROME_INTERNAL'
  if (scheme === 'chrome-extension') return 'CHROME_EXTENSION'
  if (scheme === 'devtools' || scheme === 'chrome-devtools') return 'DEVTOOLS'
  if (scheme === 'http') return 'HTTP'
  if (scheme === 'https') return 'HTTPS'
  if (scheme === 'data' || scheme === 'blob') return 'DATA_BLOB'
  return 'OTHER'
}
function openerRelation(value, initial, selected) {
  const field = ownField(value, 'openerId', targetId)
  if (field.state === 'MISSING') return 'MISSING'
  if (field.state !== 'VALUE') return 'INVALID'
  const matchesInitial = field.value === initial, matchesSelected = field.value === selected
  if (matchesInitial && matchesSelected) return 'BOTH'
  if (matchesInitial) return 'INITIAL'
  if (matchesSelected) return 'SELECTED'
  return 'OTHER'
}
function projectExtraWorkers(rows, initial, selected) {
  const safe = []
  for (let i = 0; i < rows.length; i++) {
    const slot = Object.getOwnPropertyDescriptor(rows, String(i))
    if (!slot || !Object.hasOwn(slot, 'value')) continue
    const value = slot.value
    const id = ownField(value, 'targetId', targetId), type = ownField(value, 'type', targetType)
    if (id.state === 'VALUE' && type.state === 'VALUE') safe.push({ value, id: id.value, type: type.value })
  }
  const referenceContext = id => {
    const matches = safe.filter(row => row.id === id)
    return matches.length === 1 ? contextField(matches[0].value) : matches.length === 0 ? { state: 'MISSING', value: null } : { state: 'INVALID', value: null }
  }
  const initialContext = referenceContext(initial), selectedContext = referenceContext(selected)
  const workers = safe.filter(row => ['service_worker', 'shared_worker'].includes(row.type) && row.id !== initial && row.id !== selected)
  const types = histogram(workerTypeKeys), urlSchemes = histogram(urlSchemeKeys), openerRelations = histogram(openerRelationKeys)
  const contextToInitial = histogram(contextRelationKeys), contextToSelected = histogram(contextRelationKeys)
  for (const worker of workers) {
    types[worker.type === 'service_worker' ? 'serviceWorker' : 'sharedWorker']++
    urlSchemes[urlScheme(worker.value)]++
    openerRelations[openerRelation(worker.value, initial, selected)]++
    const context = contextField(worker.value)
    contextToInitial[contextRelation(context, initialContext)]++
    contextToSelected[contextRelation(context, selectedContext)]++
  }
  const total = workers.length
  return { total, types, urlSchemes, openerRelations, contextToInitial, contextToSelected,
    hasExtraWorkers: total > 0,
    anyOpenerMatchesInitial: openerRelations.INITIAL + openerRelations.BOTH > 0,
    anyOpenerMatchesSelected: openerRelations.SELECTED + openerRelations.BOTH > 0,
    anyContextMatchesInitial: contextToInitial.MATCH > 0,
    anyContextMatchesSelected: contextToSelected.MATCH > 0,
    anyOpenerMissing: openerRelations.MISSING > 0,
    anyContextMissing: ['WORKER_MISSING', 'REFERENCE_MISSING', 'BOTH_MISSING'].some(key => contextToInitial[key] + contextToSelected[key] > 0),
    anyInvalidField: urlSchemes.INVALID + openerRelations.INVALID + contextToInitial.INVALID + contextToSelected.INVALID > 0 }
}
function histogramProjection(value, keys, total) {
  const projected = dataRecord(value, keys)
  return projected !== null && keys.every(key => integer(projected[key], 0, total))
    && keys.reduce((sum, key) => sum + projected[key], 0) === total ? projected : null
}
export function projectPostTargets(rows, initial, selected) {
  try {
    if (!Array.isArray(rows) || rows.length > 64 || !targetId(initial) || !targetId(selected)) return emptyPostTargets('INVALID')
    const observedIds = new Set(), guardIds = new Set(), kinds = new Map(), types = emptyTypes()
    let pages = 0, blankPages = 0, rowsValid = true, idsValid = true, idsUnique = true
    let guardPredicate = rows.length === 0 ? 'EMPTY_OR_BOUNDS' : 'PASS'
    let initialPresent = false, initialKind = 'ABSENT', selectedPresent = false, selectedKind = 'ABSENT', extraProtectedCount = 0
    for (let i = 0; i < rows.length; i++) {
      const slot = Object.getOwnPropertyDescriptor(rows, String(i))
      const row = slot && Object.hasOwn(slot, 'value') ? dataRecord(slot.value) : null
      if (!row) { rowsValid = false; idsValid = false; idsUnique = false; types.invalid++; if (guardPredicate === 'PASS') guardPredicate = 'ROW_INVALID'; continue }
      const idOK = targetId(row.targetId), duplicate = idOK && observedIds.has(row.targetId), type = typeProjection(row.type)
      types[type.bucket]++
      if (!idOK) { idsValid = false; if (guardPredicate === 'PASS') guardPredicate = 'ID_INVALID' }
      else { if (duplicate) idsUnique = false; observedIds.add(row.targetId) }
      if (guardPredicate === 'PASS' && type.kind === 'INVALID') guardPredicate = 'TYPE_INVALID'
      if (guardPredicate === 'PASS' && guardIds.has(row.targetId)) guardPredicate = 'ID_DUPLICATE'
      if (idOK && type.kind !== 'INVALID' && !guardIds.has(row.targetId)) { guardIds.add(row.targetId); kinds.set(row.targetId, type.kind) }
      if (type.kind === 'page') { pages++; if (typeof row.url === 'string' && row.url === 'about:blank') blankPages++ }
      if (idOK && row.targetId === initial) { initialPresent = true; initialKind = type.kind }
      if (idOK && row.targetId === selected) { selectedPresent = true; selectedKind = type.kind }
      if (idOK && protectedTypes.has(type.kind) && row.targetId !== initial && row.targetId !== selected) extraProtectedCount++
    }
    if (guardPredicate === 'PASS' && kinds.get(selected) !== 'page') guardPredicate = 'SELECTED_NOT_PAGE'
    if (guardPredicate === 'PASS' && selected === initial) guardPredicate = 'SELECTED_EQUALS_INITIAL'
    if (guardPredicate === 'PASS' && kinds.get(initial) !== 'page') guardPredicate = 'INITIAL_NOT_PAGE'
    if (guardPredicate === 'PASS' && [...kinds].some(([id, kind]) => protectedTypes.has(kind) && id !== initial && id !== selected)) guardPredicate = 'UNAUTHORIZED_PROTECTED'
    const extraWorkers = projectExtraWorkers(rows, initial, selected)
    return { shape: 'ARRAY', total: rows.length, pages, blankPages, types, rowsValid, idsValid, idsUnique, guardPredicate,
      initialPresent, initialKind, selectedPresent, selectedKind, extraProtectedCount, extraWorkers }
  } catch { return emptyPostTargets('INVALID') }
}
export function projectFirstTargetFault(code, detail) {
  try {
    const value = dataRecord(detail, ['phase', 'targetKind'])
    if (targetFaults.includes(code) && value && targetPhases.includes(value.phase)
      && (value.targetKind === null || protectedTypes.has(value.targetKind))) return { phase: value.phase, kind: value.targetKind }
  } catch { /* No safe observation. */ }
  return { phase: null, kind: null }
}
export function nativeOpenObservation(stage, firstFault, initialTargets, postTargets = emptyPostTargets('UNOBSERVED'), firstTargetFault = { phase: null, kind: null }) {
  need(NATIVE_OPEN_STAGES.includes(stage) && (firstFault === null || SESSION_FAULTS.includes(firstFault)))
  const initial = dataRecord(initialTargets, initialKeys)
  need(initial)
  const { shape, total, pages, blankPages, types, rowsValid, idsValid, idsUnique, guardPredicate } = initial
  need(['UNOBSERVED', 'INVALID', 'ARRAY'].includes(shape))
  if (shape === 'ARRAY') need(integer(total, 0, 64) && integer(pages, 0, total) && integer(blankPages, 0, pages)
    && validateTypes(types, total, pages) && [rowsValid, idsValid, idsUnique].every(v => typeof v === 'boolean')
    && initialPredicates.slice(2).includes(guardPredicate))
  else need([total, pages, blankPages, types, rowsValid, idsValid, idsUnique].every(v => v === null)
    && guardPredicate === (shape === 'UNOBSERVED' ? 'UNOBSERVED' : 'INPUT_INVALID'))
  const post = dataRecord(postTargets, postKeys), targetFault = dataRecord(firstTargetFault, ['phase', 'kind'])
  need(post && ['UNOBSERVED', 'INVALID', 'ARRAY'].includes(post.shape) && targetFault)
  if (post.shape === 'ARRAY') {
    need(integer(post.total, 0, 64) && integer(post.pages, 0, post.total) && integer(post.blankPages, 0, post.pages)
      && validateTypes(post.types, post.total, post.pages)
      && [post.rowsValid, post.idsValid, post.idsUnique].every(v => typeof v === 'boolean')
      && postPredicates.slice(2).includes(post.guardPredicate)
      && typeof post.initialPresent === 'boolean' && typeof post.selectedPresent === 'boolean'
      && publicKinds.includes(post.initialKind) && publicKinds.includes(post.selectedKind)
      && (post.initialKind === 'ABSENT') === !post.initialPresent
      && (post.selectedKind === 'ABSENT') === !post.selectedPresent
      && integer(post.extraProtectedCount, 0, post.total)
      && (!post.initialPresent || post.total > 0) && (!post.selectedPresent || post.total > 0)
      && (post.selectedKind !== 'page' || post.pages > 0))
    const workers = dataRecord(post.extraWorkers, extraWorkerKeys)
    need(workers && integer(workers.total, 0, post.total))
    const workerTypes = histogramProjection(workers.types, workerTypeKeys, workers.total)
    const urlSchemes = histogramProjection(workers.urlSchemes, urlSchemeKeys, workers.total)
    const openerRelations = histogramProjection(workers.openerRelations, openerRelationKeys, workers.total)
    const contextToInitial = histogramProjection(workers.contextToInitial, contextRelationKeys, workers.total)
    const contextToSelected = histogramProjection(workers.contextToSelected, contextRelationKeys, workers.total)
    need(workerTypes && urlSchemes && openerRelations && contextToInitial && contextToSelected)
    const booleans = extraWorkerKeys.slice(6)
    need(booleans.every(key => typeof workers[key] === 'boolean')
      && workers.hasExtraWorkers === (workers.total > 0)
      && workers.anyOpenerMatchesInitial === (workers.openerRelations.INITIAL + workers.openerRelations.BOTH > 0)
      && workers.anyOpenerMatchesSelected === (workers.openerRelations.SELECTED + workers.openerRelations.BOTH > 0)
      && workers.anyContextMatchesInitial === (workers.contextToInitial.MATCH > 0)
      && workers.anyContextMatchesSelected === (workers.contextToSelected.MATCH > 0)
      && workers.anyOpenerMissing === (workers.openerRelations.MISSING > 0)
      && workers.anyContextMissing === (['WORKER_MISSING', 'REFERENCE_MISSING', 'BOTH_MISSING'].some(key => workers.contextToInitial[key] + workers.contextToSelected[key] > 0))
      && workers.anyInvalidField === (workers.urlSchemes.INVALID + workers.openerRelations.INVALID + workers.contextToInitial.INVALID + workers.contextToSelected.INVALID > 0))
    post.extraWorkers = { total: workers.total, types: workerTypes, urlSchemes, openerRelations, contextToInitial, contextToSelected,
      ...Object.fromEntries(booleans.map(key => [key, workers[key]])) }
  } else need(postKeys.filter(key => !['shape', 'guardPredicate'].includes(key)).every(key => post[key] === null)
    && post.guardPredicate === (post.shape === 'UNOBSERVED' ? 'UNOBSERVED' : 'INPUT_INVALID'))
  need(targetFault.phase === null ? targetFault.kind === null : targetFaults.includes(firstFault)
    && targetPhases.includes(targetFault.phase) && (targetFault.kind === null || protectedTypes.has(targetFault.kind)))
  return { schema: 'chengwang.native-open-failure/v3', stage, firstFault,
    initialTargets: { shape, total, pages, blankPages, types, rowsValid, idsValid, idsUnique, guardPredicate }, postTargets: post, firstTargetFault: targetFault }
}

// The real PW session and CPU protocol tests share this registration path.
export function registerSessionEvents(session, onEvent) {
  need(session && typeof session.on === 'function' && typeof onEvent === 'function')
  for (const method of SESSION_EVENTS) session.on(method, params => onEvent(method, params))
}

export function validateSessionOptions(o) {
  need(exact(o, optionKeys) && /^[a-f0-9]{32}$/.test(o.fixtureId) && /^[a-f0-9]{40}$/.test(o.sourceCommit))
  need(['chrome-cdp', 'playwright'].includes(o.engine))
  need(o.root === '/tmp/chengwang-subscription-ui-' + o.fixtureId && o.bundle === '/tmp/chengwang-subscription-ui-tools-' + o.fixtureId)
  need(o.chrome === o.bundle + '/chrome/chrome' && o.launcher === o.bundle + '/ui-chrome-launcher')
  need(o.home === o.root + '/home' && o.profile === o.root + '/chrome-profile')
  return o
}

export function validateChromeExit(value, o, chrome) {
  need(exact(value, exitKeys) && value.schema === 'chengwang.subscription-ui-chrome-exit/v1')
  need(value.engine === o.engine && value.fixtureId === o.fixtureId && value.pid === chrome.pid && value.startTicks === chrome.startTicks)
  need(integer(value.pid, 2, Number.MAX_SAFE_INTEGER) && integer(value.startTicks, 1, Number.MAX_SAFE_INTEGER))
  need(value.exitCode === 0 && value.joined === true && value.forced === false)
  return value
}

// Pure bounded state machine. Raw identities remain private in memory; faults
// expose only a closed code, phase and safe type. No second-snapshot whitelisting.
export class TargetGuard {
  constructor(onFault) {
    need(typeof onFault === 'function')
    this.onFault = onFault; this.phase = 'BUFFERING'; this.baseline = null
    this.queue = []; this.selected = null; this.failed = false; this.destroyed = new Set(); this.initial = null
    this.postTargets = emptyPostTargets('UNOBSERVED')
  }
  reject(code, kind = null) {
    this.failed = true
    this.onFault(code, { phase: this.phase, targetKind: protectedTypes.has(kind) ? kind : null })
  }
  freezeInitial(rows) {
    need(this.phase === 'BUFFERING' && this.initial === null && this.baseline === null && Array.isArray(rows) && rows.length > 0 && rows.length <= 64)
    const ids = new Set(), pages = []
    for (const row of rows) {
      need(row && targetId(row.targetId) && targetType(row.type) && !ids.has(row.targetId)); ids.add(row.targetId)
      if (row.type === 'page') pages.push(row)
      else need(!protectedTypes.has(row.type))
    }
    need(pages.length === 1 && pages[0].url === 'about:blank')
    this.initial = pages[0].targetId
  }
  setBaseline(rows, selected) {
    need(this.phase === 'BUFFERING' && this.baseline === null && Array.isArray(rows) && rows.length > 0 && rows.length <= 64 && targetId(selected))
    const map = new Map()
    for (const row of rows) { need(row && targetId(row.targetId) && targetType(row.type) && !map.has(row.targetId)); map.set(row.targetId, row.type) }
    need(map.get(selected) === 'page' && selected !== this.initial)
    const authorized = new Map([[selected, 'page']])
    if (this.initial !== null) { need(map.get(this.initial) === 'page'); authorized.set(this.initial, 'page') }
    for (const [id, kind] of map) if (protectedTypes.has(kind)) need(authorized.get(id) === kind)
    // A later snapshot is a consistency check, never an authorization source.
    this.baseline = authorized; this.selected = selected
  }
  observe(method, params) {
    if (!['Target.targetCreated', 'Target.targetDestroyed'].includes(method)) return
    const info = method === 'Target.targetCreated' ? params?.targetInfo : params
    const id = info?.targetId, kind = method === 'Target.targetCreated' ? info?.type : null
    if (!targetId(id) || method === 'Target.targetCreated' && !targetType(kind)) { this.reject('INVALID_TARGET_STATE'); return }
    const row = { method, id, kind }
    if (this.phase === 'BUFFERING') {
      if (this.queue.length >= 128) { this.reject('INVALID_TARGET_STATE'); return }
      this.queue.push(row); return
    }
    this.consume(row)
  }
  consume(row) {
    if (row.method === 'Target.targetDestroyed') {
      if (this.destroyed.size >= 64 && !this.destroyed.has(row.id)) { this.reject('INVALID_TARGET_STATE'); return }
      this.destroyed.add(row.id)
      if (row.id === this.selected && this.phase !== 'CLOSING' && this.phase !== 'CLOSED') this.reject('SESSION_DETACHED')
      return
    }
    if (this.baseline.has(row.id)) {
      if (this.baseline.get(row.id) !== row.kind || this.destroyed.has(row.id)) this.reject('INVALID_TARGET_STATE', row.kind)
    } else if (protectedTypes.has(row.kind)) this.reject('EXTRA_TARGET', row.kind)
  }
  arm() {
    need(this.phase === 'BUFFERING' && this.baseline !== null)
    const rows = this.queue; this.queue = []; this.phase = 'ARMED'
    for (const row of rows) this.consume(row)
    need(!this.failed)
  }
  beginClose() { need(this.phase === 'ARMED'); this.phase = 'CLOSING' }
  endClose() { need(this.phase === 'CLOSING' && !this.failed); this.phase = 'CLOSED' }
}

// The actual CDP launch path calls this same bounded protocol sequence. Only
// the initial launcher's explicit about:blank ID and created owned ID may enter
// the guard; queued events cannot be laundered through the post-create snapshot.
export async function initializeCDPTargets(send, guard, onAttached) {
  need(typeof send === 'function' && guard instanceof TargetGuard && typeof onAttached === 'function')
  const initial = await send('Target.getTargets'); guard.freezeInitial(initial?.targetInfos)
  const target = await send('Target.createTarget', { url: 'about:blank', forTab: false }); need(targetId(target?.targetId))
  const attached = await send('Target.attachToTarget', { targetId: target.targetId, flatten: true }); need(targetId(attached?.sessionId))
  onAttached(attached.sessionId)
  const targets = await send('Target.getTargets')
  guard.postTargets = projectPostTargets(Object.getOwnPropertyDescriptor(targets ?? {}, 'targetInfos')?.value, guard.initial, target.targetId)
  guard.setBaseline(targets?.targetInfos, target.targetId)
  await send('Target.setDiscoverTargets', { discover: true }); guard.arm()
  return { targetId: target.targetId, sessionId: attached.sessionId }
}

export function nativeClickExpression(name, ariaLabelOnly = false) {
  need(typeof name === 'string' && name.length > 0 && name.length <= 256 && !/[\x00-\x1f\x7f]/.test(name) && typeof ariaLabelOnly === 'boolean')
  return `(()=>{const n=${JSON.stringify(name)},a=[...document.querySelectorAll('button')].filter(e=>${ariaLabelOnly ? "e.getAttribute('aria-label')===n" : "(e.getAttribute('aria-label')?.trim()||(e.innerText??'').replace(/\\s+/g,' ').trim())===n"});if(a.length!==1||a[0].disabled||a[0].getAttribute('aria-disabled')==='true')throw Error('native input rejected');const e=a[0];e.scrollIntoView({block:'center',inline:'nearest'});const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;if(!(r.width>0&&r.height>0&&x>=0&&y>=0&&x<innerWidth&&y<innerHeight&&e.contains(document.elementFromPoint(x,y))))throw Error('native input rejected');return{x,y}})()`
}

export async function dispatchNativeClick(send, point) {
  need(typeof send === 'function' && exact(point, ['x', 'y']) && [point.x, point.y].every(v => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 100000))
  for (const type of ['mouseMoved', 'mousePressed', 'mouseReleased']) await send('Input.dispatchMouseEvent', { type, ...point, ...(type === 'mouseMoved' ? {} : { button: 'left', clickCount: 1 }) })
}

// Dependency-explicit close logic is exported only for pure protocol tests.
// openNativeSession always supplies actual browser/launcher/proc mechanisms.
export async function finishNativeSession(o, chrome, mechanisms) {
  need(exact(mechanisms, ['closeBrowser', 'readExit', 'launcherResult', 'wait', 'noLive', 'pause']))
  await mechanisms.closeBrowser()
  let chromeExit
  await mechanisms.wait(async () => {
    try { chromeExit = validateChromeExit(await mechanisms.readExit(), o, chrome); return true }
    catch (error) { if (error?.code === 'ENOENT') return false; throw error }
  }, 20000)
  let launcherExit = null
  if (mechanisms.launcherResult !== null) {
    launcherExit = await Promise.race([mechanisms.launcherResult, mechanisms.pause(2000).then(() => null)])
    need(exact(launcherExit, ['code', 'signal']) && launcherExit.code === 0 && launcherExit.signal === null)
  }
  await mechanisms.wait(mechanisms.noLive, 5000)
  return { normalCloseCommandCompleted: true, chromeExit, launcherExit, noLiveOwnedProcesses: true, processScope: 'CHROME_SESSION_AND_LAUNCHER_ONLY' }
}

/**
 * Real CI session; no injectable I/O dependencies on this default path.
 * hooks.onEvent(method, params) receives selected-session raw CDP data in memory;
 * caller must install its journal BEFORE awaiting openNativeSession. onFault is
 * synchronous, receives closed codes plus {phase,targetKind}, and cannot clear a
 * sticky failure. No URL/target/session IDs appear in returned public metadata.
 * Optional onDiagnostic receives a closed failure-only observation before
 * disposal; its rejection is suppressed without changing the startup rejection.
 *
 * browser = {product,revision,protocolVersion} (serializable version metadata).
 * chrome = {pid,startTicks,uid,profile,argvSHA256,exeSHA256,exeBytes} (the existing
 * source-bound owned-process projection, NOT a Playwright Browser/context).
 * normalTrust = {method,trustFlags,caSHA256,leafSHA256,homeEnvironmentAbsent,
 * legacyDatabaseAbsent}. Internal page/context/process handles stay in closures.
 * close returns the existing 5-key close projection only after actual normal
 * close, exact exit0/joinedtrue/forcedfalse, launcher0 and no live owned Chrome.
 * dispose is emergency cleanup only; it never returns a success close record.
 */
export async function openNativeSession(o, hooks) {
  validateSessionOptions(o)
  need((exact(hooks, ['onEvent', 'onFault']) || exact(hooks, ['onEvent', 'onFault', 'onDiagnostic'])) && typeof hooks.onEvent === 'function' && typeof hooks.onFault === 'function'
    && (!Object.hasOwn(hooks, 'onDiagnostic') || typeof hooks.onDiagnostic === 'function'))
  let phase = 'STARTING', firstFault = null, context, page, transport, browserSendRaw, pageSendRaw, childResult = null, child
  let openStage = 'ENVIRONMENT', initialTargets = emptyInitialTargets('UNOBSERVED')
  let firstTargetFault = { phase: null, kind: null }
  const fault = (code, detail = { phase, targetKind: null }) => {
    need(SESSION_FAULTS.includes(code))
    if (firstFault === null) { firstFault = code; firstTargetFault = projectFirstTargetFault(code, detail) }
    try { hooks.onFault(code, detail) } catch { firstFault = 'HOOK_REJECTED'; firstTargetFault = { phase: null, kind: null } }
  }
  const healthy = () => {
    if (transport?.closed && !['CLOSING', 'CLOSED', 'DISPOSED'].includes(phase) && firstFault === null) fault('TRANSPORT_CLOSED')
    need(firstFault === null && !['FAILED', 'CLOSED', 'DISPOSED'].includes(phase))
  }
  const event = (method, params) => {
    if (method === 'Inspector.detached' && phase !== 'CLOSING' && phase !== 'CLOSED') fault('SESSION_DETACHED')
    try { hooks.onEvent(method, params) } catch { fault('HOOK_REJECTED') }
  }
  const guard = new TargetGuard(fault)
  const dispose = async () => {
    if (phase === 'CLOSED' || phase === 'DISPOSED') return
    phase = 'DISPOSED'
    try { if (context) await context.close(); else if (browserSendRaw) await browserSendRaw('Browser.close') } catch { /* No successful-close evidence on this path. */ }
    try { transport?.socket.close() } catch { /* Supervisor owns final cleanup. */ }
  }
  try {
    need(process.platform === 'linux' && process.getuid?.() === 10001 && process.getgid?.() === 10001 && !Object.hasOwn(process.env, 'HOME') && process.env.TMPDIR === '/var/tmp' && homedir() === o.home && typeof WebSocket === 'function')
    openStage = 'OWNED_DIRECTORIES'
    await ownedDirectory(o.root); await ownedDirectory('/var/tmp'); await ownedDirectory(o.home, true); await ownedDirectory(o.profile, true)
    openStage = 'LAUNCH_CONFIG'
    const config = JSON.parse((await stableFile(o.bundle + '/launch.json', 4096)).toString())
    need(exact(config, ['schema', 'engine', 'fixtureId', 'root', 'chrome', 'chromeSHA256']) && config.schema === 'chengwang.subscription-ui-launch/v1' && config.engine === o.engine && config.fixtureId === o.fixtureId && config.root === o.root && config.chrome === o.chrome && /^[a-f0-9]{64}$/.test(config.chromeSHA256))
    openStage = 'CERTIFICATES'
    const ca = await stableFile(o.root + '/api-ca.pem', 65536, true), leaf = await stableFile(o.root + '/api-leaf.pem', 65536, true)
    const verified = inspectPublicTLS(ca.toString(), leaf.toString())
    const data = o.home + '/.local/share', database = data + '/pki/nssdb'
    openStage = 'NSS_DIRECTORIES'
    await mkdir(database, { mode: 0o700, recursive: true })
    for (const path of [o.home + '/.local', data, data + '/pki', database]) await ownedDirectory(path)
    try { await lstat(o.home + '/.pki/nssdb'); need(false) } catch (error) { need(error?.code === 'ENOENT') }
    for (const name of ['config', 'cache']) await ownedDirectory(o.profile + '/' + name, true)
    const env = { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TZ: 'UTC', TMPDIR: '/var/tmp', XDG_DATA_HOME: data, XDG_CONFIG_HOME: o.profile + '/config', XDG_CACHE_HOME: o.profile + '/cache' }
    openStage = 'EXECUTABLES'
    await stableFile('/usr/bin/certutil', 16 << 20); await stableFile(o.launcher, 131072)
    const certutil = args => execute('/usr/bin/certutil', args, { env, timeout: 10000, maxBuffer: 65536, encoding: 'utf8' })
    openStage = 'NSS_CREATE'; await certutil(['-N', '-d', 'sql:' + database, '--empty-password'])
    openStage = 'NSS_IMPORT'; await certutil(['-A', '-d', 'sql:' + database, '-n', 'chengwang-native-browser-root', '-t', 'C,,', '-i', o.root + '/api-ca.pem'])
    openStage = 'NSS_VERIFY'
    need(inspectPublicTLS((await certutil(['-L', '-d', 'sql:' + database, '-n', 'chengwang-native-browser-root', '-a'])).stdout, leaf.toString()).caSHA256 === verified.caSHA256)
    const args = ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps', '--disable-extensions', '--no-first-run', '--no-default-browser-check', '--disable-features=MediaRouter,OptimizationHints', '--password-store=basic']
    if (o.engine === 'chrome-cdp') {
      openStage = 'CDP_LAUNCH'
      child = spawn(o.launcher, [...args, '--headless=new', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', '--user-data-dir=' + o.profile, 'about:blank'], { stdio: ['ignore', 'ignore', 'ignore'], env })
      childResult = new Promise(resolve => { child.once('error', () => resolve({ code: null, signal: null })); child.once('exit', (code, signal) => resolve({ code, signal })) })
      let endpoint
      openStage = 'CDP_PORT_WAIT'
      await until(async () => { need(child.exitCode === null && child.signalCode === null); try { const raw = await readFile(o.profile + '/DevToolsActivePort', 'utf8'); need(raw.length <= 1024); const a = raw.trim().split('\n'); need(a.length === 2 && /^[1-9][0-9]{0,4}$/.test(a[0]) && Number(a[0]) <= 65535 && /^\/devtools\/browser\/[a-f0-9-]{1,80}$/.test(a[1])); endpoint = 'ws://127.0.0.1:' + a[0] + a[1]; return true } catch (error) { if (error?.code === 'ENOENT') return false; throw error } }, 20000)
      openStage = 'CDP_WEBSOCKET'
      const socket = new WebSocket(endpoint)
      await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(rejected()), 10000); socket.addEventListener('open', () => { clearTimeout(timer); resolve() }, { once: true }); socket.addEventListener('error', () => { clearTimeout(timer); reject(rejected()) }, { once: true }) })
      openStage = 'CDP_TRANSPORT'
      transport = new Transport(socket); browserSendRaw = (method, params) => transport.send(method, params)
      socket.addEventListener('close', () => { if (!['CLOSING', 'CLOSED', 'DISPOSED'].includes(phase)) fault('TRANSPORT_CLOSED') })
      socket.addEventListener('error', () => { if (!['CLOSING', 'CLOSED', 'DISPOSED'].includes(phase)) fault('TRANSPORT_CLOSED') })
      transport.listeners.push(m => { if (!m.sessionId) guard.observe(m.method, m.params) })
      let firstTargets = true
      const bootstrapSend = async (method, params) => {
        openStage = method === 'Target.getTargets' ? (firstTargets ? 'CDP_INITIAL_TARGETS' : 'CDP_POST_TARGETS')
          : ({ 'Target.createTarget': 'CDP_CREATE_TARGET', 'Target.attachToTarget': 'CDP_ATTACH_TARGET', 'Target.setDiscoverTargets': 'CDP_DISCOVER_TARGETS' })[method]
        need(NATIVE_OPEN_STAGES.includes(openStage))
        const result = await browserSendRaw(method, params)
        if (method === 'Target.getTargets' && firstTargets) { initialTargets = projectInitialTargets(result?.targetInfos); firstTargets = false }
        return result
      }
      await initializeCDPTargets(bootstrapSend, guard, sessionId => {
        openStage = 'CDP_SESSION_BIND'
        pageSendRaw = (method, params) => transport.send(method, params, sessionId)
        transport.listeners.push(m => { if (m.sessionId === sessionId) event(m.method, m.params ?? {}) })
      })
    } else {
      openStage = 'PW_PACKAGE'
      const dir = o.bundle + '/source/chengwang/tools/subscription-ui-browser/node_modules/playwright-core/'
      need(JSON.parse((await stableFile(dir + 'package.json', 65536)).toString()).version === '1.65.0-alpha-2026-10-23')
      const pw = await import(pathToFileURL(dir + 'index.mjs').href)
      openStage = 'PW_LAUNCH'
      context = await pw.chromium.launchPersistentContext(o.profile, { executablePath: o.launcher, headless: true, chromiumSandbox: false, ignoreHTTPSErrors: false, bypassCSP: false, locale: 'zh-CN', timezoneId: 'UTC', deviceScaleFactor: 1, args, env, timeout: 20000 })
      page = context.pages()[0]; need(page && context.pages().length === 1)
      context.on('page', p => { if (p !== page) fault('EXTRA_TARGET', { phase, targetKind: 'page' }) })
      context.on('serviceworker', () => fault('EXTRA_TARGET', { phase, targetKind: 'service_worker' }))
      context.on('close', () => { if (!['CLOSING', 'CLOSED', 'DISPOSED'].includes(phase)) fault('CONTEXT_CLOSED') })
      page.on('close', () => { if (!['CLOSING', 'CLOSED', 'DISPOSED'].includes(phase)) fault('PAGE_CLOSED') })
      page.on('crash', () => fault('PAGE_CRASHED'))
      openStage = 'PW_ATTACH'
      const session = await context.newCDPSession(page), bs = await context.browser().newBrowserCDPSession()
      pageSendRaw = (method, params) => session.send(method, params); browserSendRaw = (method, params) => bs.send(method, params)
      registerSessionEvents(session, event)
      openStage = 'PW_TARGETS'
      const target = await pageSendRaw('Target.getTargetInfo'); need(targetId(target?.targetInfo?.targetId))
      bs.on('Target.targetCreated', params => guard.observe('Target.targetCreated', params))
      bs.on('Target.targetDestroyed', params => guard.observe('Target.targetDestroyed', params))
      const targets = await browserSendRaw('Target.getTargets'); guard.setBaseline(targets?.targetInfos, target.targetInfo.targetId)
      await browserSendRaw('Target.setDiscoverTargets', { discover: true }); guard.arm()
    }
    healthy()
    openStage = 'BROWSER_VERSION'
    const version = await browserSendRaw('Browser.getVersion'), browser = versionProjection(version)
    openStage = 'PROCESS_IDENTITY'
    const chrome = await chromeIdentity(o, browserSendRaw)
    need(chrome.exeSHA256 === config.chromeSHA256)
    openStage = 'DOMAINS_ENABLE'
    await Promise.all(['Runtime.enable', 'Page.enable', 'Log.enable'].map(method => pageSendRaw(method)))
    openStage = 'NETWORK_ENABLE'
    await pageSendRaw('Network.enable', { maxTotalBufferSize: 32 << 20, maxResourceBufferSize: 8 << 20 })
    openStage = 'LOCALE'
    if (!page) await configureNativeLocale(pageSendRaw, version.userAgent)
    openStage = 'OPEN_COMPLETE'
    phase = 'OPEN'; healthy()
    const safeCall = async (method, params, send) => {
      healthy()
      try { return await send(method, params) } catch { if (transport?.closed) fault('TRANSPORT_CLOSED'); else if (method !== 'Network.getResponseBody') fault('PROTOCOL_REJECTED'); throw rejected() }
    }
    const action = async task => { try { healthy(); const result = await task(); healthy(); return result } catch { fault('PROTOCOL_REJECTED'); throw rejected() } }
    const evaluate = async expression => {
      healthy(); need(typeof expression === 'string' && Buffer.byteLength(expression) > 0 && Buffer.byteLength(expression) <= 262144)
      try { if (page) return await page.evaluate(expression); const r = await pageSendRaw('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }); need(r && !r.exceptionDetails && Object.hasOwn(r.result ?? {}, 'value')); return r.result.value }
      catch { fault('PROTOCOL_REJECTED'); throw rejected() }
    }
    return Object.freeze({
      browser: Object.freeze(browser), chrome: Object.freeze(chrome),
      normalTrust: Object.freeze({ method: 'PRIVATE_NSS_SQL_XDG_LOCAL_CA', trustFlags: 'C,,', caSHA256: verified.caSHA256, leafSHA256: verified.leafSHA256, homeEnvironmentAbsent: true, legacyDatabaseAbsent: true }),
      pageSend: (method, params = {}) => { if (method !== 'Network.getResponseBody') { fault('PROTOCOL_REJECTED'); throw rejected() }; return safeCall(method, params, pageSendRaw) },
      browserSend: (method, params = {}) => { if (!['Browser.getVersion', 'SystemInfo.getProcessInfo', 'Target.getTargets'].includes(method)) { fault('PROTOCOL_REJECTED'); throw rejected() }; return safeCall(method, params, browserSendRaw) },
      evaluate,
      navigate: url => action(async () => { need(typeof url === 'string' && url.length <= 2048 && new URL(url).protocol === 'https:'); if (page) await page.goto(url, { waitUntil: 'load', timeout: 15000 }); else { const r = await pageSendRaw('Page.navigate', { url }); need(!r.errorText); await until(async () => await evaluate('document.readyState==="complete"') === true) } }),
      resize: (width, height = 900) => action(async () => { need(integer(width, 320, 4096) && integer(height, 320, 4096)); if (page) await page.setViewportSize({ width, height }); else await pageSendRaw('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false }) }),
      click: value => action(async () => {
        need(value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(k => ['name', 'ariaLabelOnly'].includes(k)))
        const { name, ariaLabelOnly = false } = value, expression = nativeClickExpression(name, ariaLabelOnly)
        if (page) { const locator = page.getByRole('button', { name, exact: true }); need(await locator.count() === 1); if (ariaLabelOnly) need(await locator.getAttribute('aria-label') === name); await locator.click({ timeout: 10000 }) }
        else await dispatchNativeClick(pageSendRaw, await evaluate(expression))
      }),
      screenshot: () => action(async () => page ? await page.screenshot({ type: 'png', fullPage: false, animations: 'disabled', timeout: 10000 }) : Buffer.from((await pageSendRaw('Page.captureScreenshot', { format: 'png', fromSurface: true, captureBeyondViewport: false })).data, 'base64')),
      tlsProof: (response, origin) => action(async () => { need(typeof origin === 'string' && /^https:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(origin) && Number(new URL(origin).port) <= 65535); const chain = (await pageSendRaw('Network.getCertificate', { origin })).tableNames; return { tls: browserTLSProof(response, chain, verified), certificateChain: chain } }),
      async close() {
        healthy(); need(phase === 'OPEN'); phase = 'CLOSING'; guard.beginClose()
        try {
          const result = await finishNativeSession(o, chrome, { closeBrowser: () => context ? context.close() : browserSendRaw('Browser.close'), readExit: async () => JSON.parse((await stableFile(o.root + '/chrome-exit.private.json', 4096, true)).toString()), launcherResult: childResult, wait: until, noLive: () => noLiveChrome(o, chrome), pause: delay })
          need(firstFault === null); guard.endClose(); phase = 'CLOSED'; transport?.socket.close(); return result
        } catch { fault('CLOSE_REJECTED'); phase = 'FAILED'; throw rejected() }
      },
      dispose,
      assertHealthy: healthy,
    })
  } catch {
    fault('STARTUP_REJECTED')
    // A failed diagnostic sink cannot produce success or expose the exception.
    try { if (hooks.onDiagnostic) await hooks.onDiagnostic(nativeOpenObservation(openStage, firstFault, initialTargets, guard.postTargets, firstTargetFault)) } catch { /* Observation unavailable. */ }
    await dispose(); throw rejected()
  }
}
