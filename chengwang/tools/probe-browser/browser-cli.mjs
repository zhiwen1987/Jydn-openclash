// CI-only controller. Secrets are read from the owned fixture, never argv/env.
import { constants } from 'node:fs'
import { open, lstat, link, unlink } from 'node:fs/promises'
import { posix } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { launchProbeDriver } from './browser-driver.mjs'
import { exerciseProbeBrowser } from './run-browser.mjs'
import { parseProbePublicJSON } from './probe-browser-contract.mjs'

let stage = 'ARGUMENTS', driver
const reject = () => { throw new Error('probe browser controller rejected') }
const need = value => { if (!value) reject() }
const known = ['--root', '--engine', '--chrome', '--launcher', '--source-root', '--source-commit']
const values = new Map()
const until = Date.now() + 330000
const flags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
async function readPrivate(path, owner = 10001, mode = 0o600, limit = 16384) {
  const handle = await open(path, flags)
  try {
    const before = await handle.stat({ bigint: true })
    need(before.isFile() && before.uid === BigInt(owner) && before.gid === BigInt(owner === 0 ? 0 : 10001)
      && before.nlink === 1n && (before.mode & 0o7777n) === BigInt(mode) && before.size > 0n && before.size <= BigInt(limit))
    const raw = await handle.readFile(), after = await handle.stat({ bigint: true })
    need(raw.length === Number(before.size) && ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs']
      .every(key => before[key] === after[key]))
    return raw
  } finally { await handle.close() }
}
async function exclusive(path, bytes) {
  need(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= 8 << 20)
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
  try { await handle.writeFile(bytes); await handle.sync() } finally { await handle.close() }
}
const json = value => Buffer.from(JSON.stringify(value) + '\n')
async function publishSignal(path, value) {
  const pending = path + '.pending'
  await exclusive(pending, json(value))
  try { await link(pending, path) } finally { await unlink(pending) }
}
async function phase(root, name) {
  const path = posix.join(root, 'browser', name + '.go')
  while (Date.now() < until) {
    try {
      const info = await lstat(path)
      need(info.isFile() && !info.isSymbolicLink() && info.uid === 0 && info.gid === 0 && (info.mode & 0o7777) === 0o444)
      return parseProbePublicJSON(await readPrivate(path, 0, 0o444))
    } catch (error) { if (error.code !== 'ENOENT') throw error }
    await delay(40)
  }
  reject()
}

try {
  const args = process.argv.slice(2)
  need(args.length === known.length * 2 && process.platform === 'linux' && process.getuid() === 10001 && process.getgid() === 10001 && !Object.hasOwn(process.env, 'HOME'))
  for (let at = 0; at < args.length; at += 2) {
    need(known.includes(args[at]) && !values.has(args[at]) && typeof args[at + 1] === 'string' && args[at + 1])
    values.set(args[at], args[at + 1])
  }
  const root = values.get('--root'), engine = values.get('--engine'), sourceCommit = values.get('--source-commit')
  need(/^\/tmp\/chengwang-probe-readback-[a-f0-9]{32}$/.test(root) && ['chrome-cdp', 'playwright'].includes(engine)
    && /^[a-f0-9]{40}$/.test(sourceCommit))
  const tokenBytes = await readPrivate(posix.join(root, 'viewer-token.private'), 10001, 0o600, 4096)
  const token = tokenBytes.toString('utf8')
  need(/^[A-Za-z0-9_-]{32,4096}$/.test(token))
  stage = 'PREWARM'
  driver = await launchProbeDriver({ engine, root, chrome: values.get('--chrome'),
    sourceRoot: values.get('--source-root'), launcher: values.get('--launcher') })
  await publishSignal(posix.join(root, 'browser/prewarmed.private.json'), { schema: 'chengwang.probe-browser-ready/v1', engine, sourceCommit })
  await phase(root, 'fresh')
  stage = 'FLOW'
  const label = engine === 'chrome-cdp' ? 'cdp' : 'playwright'
  const report = await exerciseProbeBrowser({ driver, token, expectedForBodies: async () => {},
    savePublic: async (name, bytes) => {
      need(new RegExp(`^probe-browser-${label}-(?:fresh|cleared|withdrawn|expired)-(?:status|details|dom|network|desktop|mobile)\\.(?:json|jsonl|png)$`).test(name))
      need(!Buffer.from(bytes).includes(tokenBytes) && !Buffer.from(bytes).includes(Buffer.from('PRIVATE KEY')))
      await exclusive(posix.join(root, 'browser/out', name), bytes)
    }, phaseSignals: {
      freshReady: async () => publishSignal(posix.join(root, 'browser/fresh-complete.private.json'), { phase: 'fresh-complete', observedAt: new Date().toISOString() }),
      waitExpired: async () => { stage = 'WAIT_EXPIRED'; const value = await phase(root, 'expired'); need(value.phase === 'expired'); stage = 'EXPIRED' },
    }, deadline: until })
  stage = 'CLOSE'
  await driver.close()
  const evidence = await driver.getEvidence()
  await exclusive(posix.join(root, 'browser/out/browser-captures.json'), json(report))
  await exclusive(posix.join(root, 'browser/out/browser-driver.json'), json(evidence))
  stage = 'DONE'
} catch {
  process.stderr.write(`PROBE_BROWSER_CONTROLLER=FAIL stage=${stage} raw_input_suppressed=true\n`)
  process.exitCode = 1
  if (driver) { try { await driver.close() } catch { /* isolated PID namespace cleanup remains fail-closed */ } }
}
