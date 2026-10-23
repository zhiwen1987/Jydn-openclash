// Pure auxiliary contracts. These tests never start a browser or contact an API.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { supportedNode, validateLock } from './check-toolchain.mjs'

const manifest = JSON.parse(readFileSync(new URL('./package.json', import.meta.url)))
const lock = JSON.parse(readFileSync(new URL('./package-lock.json', import.meta.url)))
const copy = () => [structuredClone(manifest), structuredClone(lock)]
const rejects = change => {
  const [m, l] = copy()
  change(m, l)
  assert.throws(() => validateLock(m, l), /^Error: LOCK_REJECTED$/)
}

test('toolchain accepts the declared supported Node lines', () => {
  for (const value of ['22.22.2', 'v22.23.3', '22.100.0', '24.15.0', 'v24.16.2', '26.0.0', '28.1.0']) {
    assert.equal(supportedNode(value), true, value)
  }
})

test('toolchain rejects unsupported and prerelease Node versions', () => {
  for (const value of ['20.19.0', '22.22.1', '22.21.99', '23.0.0', '24.14.99', '25.2.1', '26.0.0-rc.1']) {
    assert.equal(supportedNode(value), false, value)
  }
})

test('toolchain rejects malformed or unsafe numeric versions', () => {
  for (const value of [null, 26, {}, [], '', 'v26', '26.0', '026.0.0', '26.00.0', '26.0.00', '26.0.0\n', '9007199254740992.0.0']) {
    assert.equal(supportedNode(value), false)
  }
})

test('toolchain accepts only the checked-in isolated lock', () => {
  validateLock(manifest, lock)
  assert.deepEqual(Object.keys(lock.packages), ['', 'node_modules/playwright-core'])
  assert.equal(manifest.devDependencies['playwright-core'], '1.64.1')
})

test('toolchain rejects ranges scripts and manifest drift', () => {
  for (const mutate of [
    m => { m.devDependencies['playwright-core'] = '^1.64.1' },
    m => { m.scripts.postinstall = 'unexpected' },
    m => { m.scripts['check:toolchain'] = 'node other.mjs' },
    m => { m.engines.node = '>=20' },
    m => { m.dependencies = {} },
    m => { m.private = false },
  ]) rejects(m => mutate(m))
})

test('toolchain rejects changed registry integrity and package version', () => {
  for (const mutate of [
    e => { e.resolved = 'https://example.invalid/package.tgz' },
    e => { e.resolved += '?token=unexpected' },
    e => { e.integrity = 'sha512-unexpected' },
    e => { e.version = '1.64.2' },
    e => { e.dev = false },
    e => { e.hasInstallScript = true },
  ]) rejects((_m, l) => mutate(l.packages['node_modules/playwright-core']))
})

test('toolchain rejects extra missing or inconsistent lock entries', () => {
  for (const mutate of [
    l => { l.packages['node_modules/unexpected'] = {} },
    l => { delete l.packages['node_modules/playwright-core'] },
    l => { l.packages[''].devDependencies['playwright-core'] = '1.64.2' },
    l => { l.lockfileVersion = 2 },
    l => { l.requires = false },
    l => { l.packages['node_modules/playwright-core'].dependencies = {} },
  ]) rejects((_m, l) => mutate(l))
})

test('toolchain validation leaves input objects unchanged', () => {
  const before = JSON.stringify([manifest, lock])
  validateLock(manifest, lock)
  assert.equal(JSON.stringify([manifest, lock]), before)
})

test('toolchain CLI rejects and suppresses unrecognized arguments', () => {
  const result = spawnSync(process.execPath, [fileURLToPath(new URL('./check-toolchain.mjs', import.meta.url)), '--SECRET_SENTINEL'], {
    encoding: 'utf8', timeout: 10000, windowsHide: true,
  })
  assert.equal(result.error, undefined)
  assert.equal(result.status, 1)
  assert.equal(result.stdout, '')
  assert.equal(result.stderr, 'PROBE_BROWSER_TOOLCHAIN=FAIL reason=ARGUMENTS_REJECTED acceptanceScope=TOOLCHAIN_ONLY runtime=false\n')
  assert.equal(result.stderr.includes('SECRET_SENTINEL'), false)
})
