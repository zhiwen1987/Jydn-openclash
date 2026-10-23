// Isolated opt-in request identity observations, never cancellation causality.
// The factory has no browser/module side effects and the default path is inert.
type Context = { m: number; r: number; t: number; a: boolean }
type Options = {
  enabled: () => boolean
  origin: () => string
  context: (signal: AbortSignal) => Context | null
  random: (bytes: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>
  write: (line: string) => void
}
const prefix = 'CW_PROBE_BIND:'
const integer = (n: number, min: number, max: number) => Number.isSafeInteger(n) && n >= min && n <= max
function valid(context: Context | null): context is Context {
  return context !== null && integer(context.m, 1, 128) && integer(context.r, 1, 128)
    && integer(context.t, 0, 2147483647) && typeof context.a === 'boolean'
}

export function createProbeRequestBinding(options: Options) {
  let doc: string | null = null, lines = 0
  const sent = new WeakMap<AbortSignal, { m: number; r: number; last: number; doc: string; cancelled: boolean }>()
  const identities = new Set<string>()
  function emit(signal: AbortSignal, event: 'SEND' | 'CANCEL_RESULT', outcome?: 'RESOLVED' | 'REJECTED' | 'THREW' | 'NO_BODY'): boolean {
    try {
      const context = options.context(signal), record = sent.get(signal)
      if (!valid(context) || !record || context.m !== record.m || context.r !== record.r || lines >= 256) return false
      const t = Math.max(record.last, context.t)
      const row = { v: 1, e: event, m: context.m, r: context.r, t, a: context.a, doc: record.doc,
        ...(event === 'CANCEL_RESULT' ? { o: outcome } : {}) }
      const line = prefix + JSON.stringify(row)
      if (line.length > 512 || !/^[\x20-\x7e]+$/.test(line)) return false
      lines++; record.last = t
      options.write(line)
      return true
    } catch { return false }
  }
  function headers(signal: AbortSignal, path: string, anonymous: boolean): Record<string, string> {
    try {
      if (!options.enabled() || options.origin() !== 'https://127.0.0.1:17861'
        || path !== '/api/v1/probes/status' || !anonymous || sent.has(signal) || identities.size >= 128 || lines >= 256) return {}
      const context = options.context(signal)
      if (!valid(context)) return {}
      const key = `${context.m}.${context.r}`
      if (identities.has(key)) return {}
      if (doc === null) {
        const bytes = options.random(new Uint8Array(16))
        if (!(bytes instanceof Uint8Array) || bytes.length !== 16) return {}
        doc = [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('')
      }
      sent.set(signal, { m: context.m, r: context.r, last: context.t, doc, cancelled: false })
      identities.add(key)
      if (!emit(signal, 'SEND')) { sent.delete(signal); identities.delete(key); return {} }
      return { 'X-CW-Probe-Request': `v1.${doc}.${key}` }
    } catch { return {} }
  }
  // Returns false only when the caller must execute its unchanged legacy path.
  // Cancellation is invoked once and observed without awaiting its settlement.
  function cancel(signal: AbortSignal, call: (() => Promise<void>) | null): boolean {
    const record = sent.get(signal)
    if (!record || record.cancelled) return false
    record.cancelled = true
    if (call === null) { emit(signal, 'CANCEL_RESULT', 'NO_BODY'); return true }
    try {
      const result = call()
      void result.then(() => { emit(signal, 'CANCEL_RESULT', 'RESOLVED') }, () => { emit(signal, 'CANCEL_RESULT', 'REJECTED') })
    } catch { emit(signal, 'CANCEL_RESULT', 'THREW') }
    return true
  }
  return { headers, cancel }
}
