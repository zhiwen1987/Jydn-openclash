// Failure-only bounded observations. Importing starts no browser or service.
import { constants } from 'node:fs'
import { open, lstat } from 'node:fs/promises'
import definition from './navigation-diagnostics-contract.json' with { type: 'json' }

const need = value => { if (!value) throw Error('navigation diagnostics rejected') }
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(',')
const integer = (value, maximum) => Number.isSafeInteger(value) && value >= 0 && value <= maximum
const frozen = value => { if (value && typeof value === 'object') { for (const item of Object.values(value)) frozen(item); Object.freeze(value) }; return value }
export const NAVIGATION_DIAGNOSTICS_CONTRACT = frozen(definition)
const C = NAVIGATION_DIAGNOSTICS_CONTRACT

// This is the original single query/scroll/rectangle/center-hit operation,
// with fixed outcomes instead of discarding every rejection as one exception.
// Coordinates stay in Node memory and are never part of the observation.
export const NAVIGATION_TARGET_EXPRESSION = `(()=>{
  const a=[...document.querySelectorAll('button')].filter(e=>e.textContent.trim()==='订阅与提供者'||e.getAttribute('aria-label')==='订阅与提供者');
  if(a.length!==1)return{count:a.length===0?0:2,outcome:a.length===0?'ZERO':'MULTIPLE'};
  const e=a[0];if(!e||e.disabled)return{count:1,outcome:'DISABLED'};
  e.scrollIntoView({block:'center',inline:'nearest'});
  const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;
  if(!(r.width>0&&r.height>0))return{count:1,outcome:'RECT_EMPTY'};
  if(!(x>=0&&y>=0&&x<innerWidth&&y<innerHeight))return{count:1,outcome:'OUTSIDE_VIEWPORT'};
  if(!e.contains(document.elementFromPoint(x,y)))return{count:1,outcome:'HIT_MISMATCH'};
  return{count:1,outcome:'PASS',x,y};
})()`

function validateJournal(value, scenario) {
  need(value && typeof value.available === 'boolean')
  if (!value.available) { need(exact(value, C.journalUnavailableKeys)); return }
  need(exact(value, C.journalAvailableKeys) && typeof value.failure === 'boolean' && exact(value.counters, C.counterNames))
  for (const key of C.counterNames) need(integer(value.counters[key], C.maxCounter))
  for (const key of ['requests', 'terminal', 'pending', 'captures', 'tasks']) need(integer(value[key], C.maxRequestsByScenario[scenario]))
  need(integer(value.mutations, C.maxMutationsByScenario[scenario]) && value.terminal + value.pending === value.requests && value.captures <= value.terminal && value.mutations <= value.requests)
}

export function validateNavigationObservation(value) {
  need(exact(value, C.observationKeys) && value.schema === C.observationSchema && value.scope === C.scope)
  need(typeof value.sourceCommit === 'string' && /^[a-f0-9]{40}$/.test(value.sourceCommit) && typeof value.fixtureId === 'string' && /^[a-f0-9]{32}$/.test(value.fixtureId))
  need(typeof value.engine === 'string' && Object.hasOwn(C.phasesByEngine, value.engine) && C.scenarios.includes(value.scenario) && Array.isArray(value.phases))
  const sequence = C.phasesByEngine[value.engine]
  need(value.phases.length <= sequence.length)
  for (const [index, row] of value.phases.entries()) need(exact(row, C.phaseKeys) && row.phase === sequence[index] && row.entered === true && typeof row.completed === 'boolean' && (index === value.phases.length - 1 || row.completed))
  const last = value.phases.at(-1)
  if (!last || last.completed) need(value.cause === C.completedCause)
  else need(C.causesByPhase[last.phase].includes(value.cause))
  const inputPhase = value.phases.find(row => row.phase === 'INPUT_DISPATCHED')
  if (!inputPhase) need(value.input === null)
  else if (value.engine === 'chrome-cdp') {
    need(exact(value.input, ['kind', 'mask']) && value.input.kind === 'CDP_ACK_MASK' && C.cdpAcknowledgementMasks.includes(value.input.mask))
    if (inputPhase.completed) need(value.input.mask === 7)
    else need(({ INPUT_MOVE_REJECTED: 0, INPUT_PRESS_REJECTED: 1, INPUT_RELEASE_REJECTED: 3 })[value.cause] === value.input.mask)
  } else {
    need(exact(value.input, ['kind', 'returned']) && value.input.kind === 'PW_CLICK_RETURN' && typeof value.input.returned === 'boolean')
    need(inputPhase.completed ? value.input.returned : !value.input.returned && value.cause === 'PW_CLICK_REJECTED')
  }
  validateJournal(value.journal, value.scenario)
  return value
}

export function navigationJournalSnapshot(journal, scenario) {
  try {
    need(C.scenarios.includes(scenario) && journal && journal.requests instanceof Map && journal.tasks instanceof Set && Array.isArray(journal.rows) && typeof journal.failure === 'boolean' && exact(journal.counters, C.counterNames))
    const counters = Object.fromEntries(C.counterNames.map(key => [key, journal.counters[key]]))
    let terminal = 0, mutations = 0
    for (const item of journal.requests.values()) { need(typeof item.terminal === 'boolean' && ['GET', 'POST'].includes(item.method)); if (item.terminal) terminal++; if (item.method !== 'GET') mutations++ }
    const value = { available: true, failure: journal.failure, counters, requests: journal.requests.size, terminal, pending: journal.requests.size - terminal, captures: journal.rows.length, tasks: journal.tasks.size, mutations }
    validateJournal(value, scenario)
    return value
  } catch { return { available: false } }
}

export class NavigationDiagnostics {
  constructor(binding) {
    need(exact(binding, ['sourceCommit', 'fixtureId', 'engine', 'scenario']))
    this.binding = { ...binding }; this.phases = []; this.cause = C.completedCause; this.input = null
    validateNavigationObservation(this.snapshot(undefined))
  }
  get nextPhase() { return C.phasesByEngine[this.binding.engine][this.phases.length] ?? null }
  enter(phase, cause) {
    need(this.nextPhase === phase && (!this.phases.length || this.phases.at(-1).completed) && C.causesByPhase[phase]?.includes(cause))
    this.phases.push({ phase, entered: true, completed: false }); this.cause = cause
    if (phase === 'INPUT_DISPATCHED') this.input = this.binding.engine === 'chrome-cdp' ? { kind: 'CDP_ACK_MASK', mask: 0 } : { kind: 'PW_CLICK_RETURN', returned: false }
  }
  setCause(cause) { const last = this.phases.at(-1); need(last && !last.completed && C.causesByPhase[last.phase].includes(cause)); this.cause = cause }
  complete(phase) {
    const last = this.phases.at(-1); need(last?.phase === phase && !last.completed)
    if (phase === 'INPUT_DISPATCHED') need(this.binding.engine === 'chrome-cdp' ? this.input?.mask === 7 : this.input?.returned === true)
    last.completed = true; this.cause = C.completedCause
  }
  acknowledgeMouse(kind) {
    need(this.binding.engine === 'chrome-cdp' && this.phases.at(-1)?.phase === 'INPUT_DISPATCHED' && !this.phases.at(-1).completed)
    const previous = { move: 0, press: 1, release: 3 }, next = { move: 1, press: 3, release: 7 }
    need(Object.hasOwn(previous, kind) && this.input?.mask === previous[kind]); this.input.mask = next[kind]
  }
  playwrightClickReturned() { need(this.binding.engine === 'playwright' && this.phases.at(-1)?.phase === 'INPUT_DISPATCHED' && !this.phases.at(-1).completed && this.input?.returned === false); this.input.returned = true }
  observePlaywrightTarget(count) {
    need(this.binding.engine === 'playwright' && this.phases.at(-1)?.phase === 'NAV_TARGET_FOUND' && !this.phases.at(-1).completed)
    if (!integer(count, Number.MAX_SAFE_INTEGER)) return false
    if (count !== 1) { this.setCause(count === 0 ? 'NAV_TARGET_ZERO' : 'NAV_TARGET_MULTIPLE'); return false }
    this.complete('NAV_TARGET_FOUND'); return true
  }
  observeCDPTarget(value) {
    need(this.binding.engine === 'chrome-cdp' && this.phases.at(-1)?.phase === 'NAV_TARGET_FOUND' && !this.phases.at(-1).completed)
    if (!value || ![0, 1, 2].includes(value.count)) return null
    if (value.count !== 1) {
      if (exact(value, ['count', 'outcome']) && value.outcome === (value.count === 0 ? 'ZERO' : 'MULTIPLE')) this.setCause(value.count === 0 ? 'NAV_TARGET_ZERO' : 'NAV_TARGET_MULTIPLE')
      return null
    }
    const rejects = ['DISABLED', 'RECT_EMPTY', 'OUTSIDE_VIEWPORT', 'HIT_MISMATCH']
    if (!(rejects.includes(value.outcome) && exact(value, ['count', 'outcome']) || value.outcome === 'PASS' && exact(value, ['count', 'outcome', 'x', 'y']) && [value.x, value.y].every(v => typeof v === 'number' && Number.isFinite(v) && v >= 0))) return null
    this.complete('NAV_TARGET_FOUND'); this.enter('NAV_TARGET_ACTIONABLE', value.outcome === 'PASS' ? 'NAV_TARGET_DISABLED' : 'NAV_TARGET_' + value.outcome)
    if (value.outcome !== 'PASS') return null
    this.complete('NAV_TARGET_ACTIONABLE'); return { x: value.x, y: value.y }
  }
  snapshot(journal) {
    const value = { schema: C.observationSchema, ...this.binding, scope: C.scope, phases: this.phases.map(row => ({ ...row })), cause: this.cause, input: this.input === null ? null : { ...this.input }, journal: navigationJournalSnapshot(journal, this.binding.scenario) }
    validateNavigationObservation(value); return frozen(value)
  }
  async writeFailure(root, journal, io = { open, lstat }) {
    // Snapshot synchronously before the first filesystem await or any cleanup.
    let fd
    try {
      const snapshot = this.snapshot(journal), raw = Buffer.from(JSON.stringify(snapshot) + '\n')
      need(root === '/tmp/chengwang-subscription-ui-' + this.binding.fixtureId && raw.length > 0 && raw.length <= C.maxBytes)
      const directory = await io.lstat(root, { bigint: true })
      need(directory.isDirectory() && !directory.isSymbolicLink() && directory.uid === 10001n && directory.gid === 10001n && (directory.mode & 0o7777n) === 0o700n)
      const path = root + '/' + C.privateFile
      fd = await io.open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_NONBLOCK, C.mode)
      const before = await fd.stat({ bigint: true })
      need(before.isFile() && before.nlink === 1n && before.uid === 10001n && before.gid === 10001n && (before.mode & 0o7777n) === 0o600n && before.size === 0n)
      await fd.writeFile(raw); await fd.sync()
      const after = await fd.stat({ bigint: true }), named = await io.lstat(path, { bigint: true })
      need(after.size === BigInt(raw.length) && ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink'].every(key => before[key] === after[key]) && ['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'nlink', 'mtimeNs', 'ctimeNs'].every(key => after[key] === named[key]))
      return true
    } catch { return false } // Never replaces the original failure or invents success.
    finally { if (fd) { try { await fd.close() } catch { /* Original failure remains authoritative. */ } } }
  }
}
