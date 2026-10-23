// Diagnostic-only, anonymous STATUS lifecycle observations. This is not a
// health conclusion, retry policy, or evidence that a browser request finished.
// One console.info string: CW_PROBE_STATUS: + closed ASCII JSON <=256 bytes.
// Common fields: v=1; e=event; m=mount ID; r=request ID (0 without a request);
// t=nondecreasing integer performance milliseconds since this mount; a=aborted.
// BEGIN adds tr=INITIAL|MANUAL|POLL. ABORT adds c=DEADLINE|CLEANUP and
// p=BEFORE|AFTER. READ_END adds k=one of the reasons below, n=capped bytes,
// f=observed EOF. CANCEL adds p,n,f. EOF adds n at the actual reader done.
// EOF_OK only means stream/UTF8/JSON success, never DTO shape validation.
// All other events have no extra fields.
// The module stops silently after 128 attempted lines. Nothing is persisted.

export type ProbeStatusTrigger = 'INITIAL' | 'MANUAL' | 'POLL'
type ReadEnd = 'FETCH_ERROR' | 'HEADERS_REJECT' | 'READ_ERROR' | 'UTF8_REJECT' | 'SIZE_REJECT' | 'JSON_REJECT' | 'EOF_OK'
type StatusEvent =
  | { e: 'ARM' | 'HEADERS' | 'FINALLY' }
  | { e: 'EOF'; n: number }
  | { e: 'ABORT'; c: 'DEADLINE' | 'CLEANUP'; p: 'BEFORE' | 'AFTER' }
  | { e: 'READ_END'; k: ReadEnd; n: number; f: boolean }
  | { e: 'CANCEL'; p: 'BEFORE' | 'AFTER'; n: number; f: boolean }

type Mount = { start: number; last: number }
type Context = { m: number; r: number }
const mounts = new Map<number, Mount>()
const requests = new WeakMap<AbortSignal, Context>()
const prefix = 'CW_PROBE_STATUS:'
const limit = 128
let lines = 0, nextMount = 0, nextRequest = 0

function emit(m: number, r: number, a: boolean, event: Record<string, string | number | boolean>) {
  try {
    if (lines >= limit) return
    const mount = mounts.get(m)
    if (!mount) return
    const current = performance.now()
    if (!Number.isFinite(current)) return
    const t = event.e === 'MOUNT' ? 0 : Math.max(mount.last, Math.min(2147483647, Math.max(0, Math.floor(current - mount.start))))
    mount.last = t
    const line = prefix + JSON.stringify({ v: 1, ...event, m, r, t, a })
    // All emitted values are closed ASCII enums/integers/booleans; byte length
    // equals string length. Console/clock failures must not affect product code.
    if (line.length > 256) return
    lines++
    console.info(line)
  } catch { /* Observation is optional and cannot change request outcomes. */ }
}

export function mountProbeStatusObservation(): number {
  try {
    if (lines >= limit || nextMount >= limit) return 0
    const start = performance.now()
    if (!Number.isFinite(start)) return 0
    const m = ++nextMount
    mounts.set(m, { start, last: 0 })
    emit(m, 0, false, { e: 'MOUNT' })
    return m
  } catch { return 0 }
}

export function beginProbeStatusObservation(m: number, signal: AbortSignal, tr: ProbeStatusTrigger) {
  try {
    if (lines >= limit || nextRequest >= limit || !mounts.has(m) || requests.has(signal) || !['INITIAL', 'MANUAL', 'POLL'].includes(tr)) return
    const r = ++nextRequest
    requests.set(signal, { m, r })
    emit(m, r, signal.aborted, { e: 'BEGIN', tr })
  } catch { /* No raw signal/error data is exported. */ }
}

export function observeProbeStatus(signal: AbortSignal, event: StatusEvent) {
  try {
    const context = requests.get(signal)
    if (!context || lines >= limit) return
    const { m, r } = context
    if (event.e === 'ARM' || event.e === 'HEADERS' || event.e === 'FINALLY') {
      emit(m, r, signal.aborted, { e: event.e })
    } else if (event.e === 'EOF' && Number.isSafeInteger(event.n) && event.n >= 0 && event.n <= 1048577) {
      emit(m, r, signal.aborted, { e: event.e, n: event.n })
    } else if (event.e === 'ABORT' && ['DEADLINE', 'CLEANUP'].includes(event.c) && ['BEFORE', 'AFTER'].includes(event.p)) {
      emit(m, r, signal.aborted, { e: event.e, c: event.c, p: event.p })
    } else if ((event.e === 'READ_END' || event.e === 'CANCEL') && Number.isSafeInteger(event.n) && event.n >= 0 && event.n <= 1048577 && typeof event.f === 'boolean') {
      if (event.e === 'READ_END' && ['FETCH_ERROR', 'HEADERS_REJECT', 'READ_ERROR', 'UTF8_REJECT', 'SIZE_REJECT', 'JSON_REJECT', 'EOF_OK'].includes(event.k)) {
        emit(m, r, signal.aborted, { e: event.e, k: event.k, n: event.n, f: event.f })
      } else if (event.e === 'CANCEL' && ['BEFORE', 'AFTER'].includes(event.p)) {
        emit(m, r, signal.aborted, { e: event.e, p: event.p, n: event.n, f: event.f })
      }
    }
  } catch { /* Observation must never alter abort/read/finally behavior. */ }
}

export function cleanupProbeStatusObservation(m: number, signal?: AbortSignal) {
  try {
    const context = signal ? requests.get(signal) : undefined
    if (signal && context?.m !== m) return
    emit(m, context?.r ?? 0, signal?.aborted ?? false, { e: 'CLEANUP' })
  } catch { /* No request data retained outside the signal WeakMap. */ }
}

// Read-only optional bridge. It never binds a signal, advances a counter/clock,
// emits an old event, or exposes the signal itself.
export function getProbeStatusObservationContext(signal: AbortSignal): { m: number; r: number; t: number; a: boolean } | null {
  try {
    const context = requests.get(signal)
    const mount = context ? mounts.get(context.m) : undefined
    if (!context || !mount) return null
    const now = performance.now()
    if (!Number.isFinite(now)) return null
    return { ...context, t: Math.max(mount.last, Math.min(2147483647, Math.max(0, Math.floor(now - mount.start)))), a: signal.aborted }
  } catch { return null }
}
