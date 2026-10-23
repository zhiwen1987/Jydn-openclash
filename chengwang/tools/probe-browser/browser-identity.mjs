// Independent CI-only identity sidecar. No browser launch or I/O on import.
// This projection does not change the original driver report or its gates.
// Browser.getVersion fields: ChromeDevTools/devtools-protocol
// pdl/domains/Browser.pdl. Chromium's browser_handler.cc returns the build's
// CHROMIUM_GIT_REVISION; build/util/chromium_git_revision.h.in prefixes @.
// A revision (including @000...000) is an observation, NOT patch ancestry proof.
export const BROWSER_IDENTITY_PREFIX = 'CW_PROBE_BROWSER_IDENTITY:'
export const BROWSER_IDENTITY_SCHEMA = 'chengwang.probe-browser-identity-observation/v1'
const own = (value, key) => value !== null && typeof value === 'object' && !Array.isArray(value)
  ? Object.getOwnPropertyDescriptor(value, key)?.value : undefined
const integer = (value, minimum) => Number.isSafeInteger(value) && value >= minimum
const matches = (value, expression) => typeof value === 'string'
  && !/[^\x20-\x7e]/.test(value) && expression.test(value)

// Read only explicit own data descriptors. Do not invoke getters, toJSON,
// coercions, or traverse excluded userAgent/jsVersion/private record fields.
export function projectBrowserIdentity(version, binding) {
  try {
    const engine = own(binding, 'engine'), fixtureId = own(binding, 'fixtureId')
    const chrome = own(binding, 'chrome')
    const product = own(version, 'product'), revision = own(version, 'revision')
    const protocolVersion = own(version, 'protocolVersion')
    const pid = own(chrome, 'pid'), startTicks = own(chrome, 'startTicks')
    const argvSHA256 = own(chrome, 'argvSHA256')
    if (!['chrome-cdp', 'playwright'].includes(engine)
      || !matches(fixtureId, /^[a-f0-9]{32}$/)
      || !matches(product, /^(?:Chrome|HeadlessChrome)\/[0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}$/)
      || !matches(revision, /^@[a-f0-9]{40}$/)
      || !matches(protocolVersion, /^[0-9]{1,3}\.[0-9]{1,3}$/)
      || !integer(pid, 2) || !integer(startTicks, 1)
      || !matches(argvSHA256, /^[a-f0-9]{64}$/)) return null
    return { schema: BROWSER_IDENTITY_SCHEMA, engine, fixtureId,
      browser: { product, revision, protocolVersion }, chrome: { pid, startTicks, argvSHA256 } }
  } catch { return null }
}

// Called once by each real adapter after actualChrome has verified the process.
// The trusted outer supervisor supplies sourceCommit and hashes the actual ELF;
// those are not invented here or represented as Browser.getVersion observations.
// A missing/rejected sidecar must fail its independent identity gate. It never
// rewrites counters, changes an old outcome, or exposes raw exceptions.
export function emitBrowserIdentity(version, binding, write = line => process.stderr.write(line)) {
  try {
    const projected = projectBrowserIdentity(version, binding)
    if (projected === null) return false
    const line = BROWSER_IDENTITY_PREFIX + JSON.stringify(projected)
    if (Buffer.byteLength(line) > 1024 || !/^[\x20-\x7e]+$/.test(line)) return false
    write(line + '\n')
    return true
  } catch { return false }
}
