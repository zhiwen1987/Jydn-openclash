// CI toolchain validation only: importing this module never launches a browser.
import { readFileSync, realpathSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = dirname(fileURLToPath(import.meta.url))
const version = '1.64.1'
const registry = 'https://registry.npmjs.org/playwright-core/-/playwright-core-1.64.1.tgz'
const integrity = 'sha512-BC4s8y6SEVA6Q1rSxZTto8hI1KUI3xXlHGZgvGqP4IqPdI/a6FX9H29IDNz7vKo9l21b6LfYosScPL6M3xxyDQ=='
const nodeRange = '^22.22.2 || ^24.15.0 || >=26.0.0'
const reasons = new Set(['ARGUMENTS_REJECTED', 'UNSUPPORTED_NODE', 'LOCK_REJECTED', 'INSTALLED_PACKAGE_REJECTED', 'INTERFACE_REJECTED'])

function requireFact(value, reason) {
  if (!value) throw new Error(reason)
}

function exactKeys(value, expected) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...expected].sort().join(',')
}

export function supportedNode(value) {
  if (typeof value !== 'string') return false
  const match = /^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.exec(value)
  if (!match) return false
  const [major, minor, patch] = match.slice(1).map(Number)
  if (![major, minor, patch].every(Number.isSafeInteger)) return false
  return major >= 26 || major === 22 && (minor > 22 || minor === 22 && patch >= 2)
    || major === 24 && minor >= 15
}

export function validateLock(manifest, lock) {
  const rejected = 'LOCK_REJECTED'
  requireFact(exactKeys(manifest, ['name', 'version', 'private', 'type', 'scripts', 'engines', 'devDependencies']), rejected)
  requireFact(manifest.name === 'chengwang-probe-browser-tools' && manifest.version === '0.1.0'
    && manifest.private === true && manifest.type === 'module', rejected)
  requireFact(exactKeys(manifest.scripts, ['check:toolchain'])
    && manifest.scripts['check:toolchain'] === 'node check-toolchain.mjs', rejected)
  requireFact(exactKeys(manifest.engines, ['node']) && manifest.engines.node === nodeRange, rejected)
  requireFact(exactKeys(manifest.devDependencies, ['playwright-core'])
    && manifest.devDependencies['playwright-core'] === version, rejected)
  requireFact(exactKeys(lock, ['name', 'version', 'lockfileVersion', 'requires', 'packages'])
    && lock.name === manifest.name && lock.version === manifest.version
    && lock.lockfileVersion === 3 && lock.requires === true, rejected)
  requireFact(exactKeys(lock.packages, ['', 'node_modules/playwright-core']), rejected)
  const owner = lock.packages['']
  requireFact(exactKeys(owner, ['name', 'version', 'devDependencies', 'engines'])
    && owner.name === manifest.name && owner.version === manifest.version
    && exactKeys(owner.devDependencies, ['playwright-core']) && owner.devDependencies['playwright-core'] === version
    && exactKeys(owner.engines, ['node']) && owner.engines.node === nodeRange, rejected)
  const entry = lock.packages['node_modules/playwright-core']
  requireFact(exactKeys(entry, ['version', 'resolved', 'integrity', 'dev', 'license', 'bin', 'engines'])
    && entry.version === version && entry.resolved === registry && entry.integrity === integrity
    && entry.dev === true && entry.license === 'Apache-2.0'
    && exactKeys(entry.bin, ['playwright-core']) && entry.bin['playwright-core'] === 'cli.js'
    && exactKeys(entry.engines, ['node']) && entry.engines.node === '>=20', rejected)
}

function readJSON(path) {
  const raw = readFileSync(path)
  requireFact(raw.length > 0 && raw.length <= 131072, 'LOCK_REJECTED')
  return JSON.parse(raw.toString('utf8'))
}

export async function main(args = process.argv.slice(2)) {
  try {
    requireFact(args.length === 0, 'ARGUMENTS_REJECTED')
    requireFact(supportedNode(process.version), 'UNSUPPORTED_NODE')
    validateLock(readJSON(join(root, 'package.json')), readJSON(join(root, 'package-lock.json')))
    const require = createRequire(import.meta.url)
    const packagePath = require.resolve('playwright-core/package.json')
    requireFact(realpathSync(packagePath) === join(realpathSync(root), 'node_modules', 'playwright-core', 'package.json'), 'INSTALLED_PACKAGE_REJECTED')
    const installed = readJSON(packagePath)
    requireFact(installed.name === 'playwright-core' && installed.version === version, 'INSTALLED_PACKAGE_REJECTED')
    const playwright = await import('playwright-core')
    requireFact(typeof playwright.chromium?.launch === 'function', 'INTERFACE_REJECTED')
    console.log(JSON.stringify({ schema: 'chengwang.probe-browser-toolchain/v1', outcome: 'PASS',
      acceptanceScope: 'TOOLCHAIN_ONLY', runtime: false, browserStarted: false,
      nodeVersion: process.version, playwrightVersion: version, chromiumLaunchAvailable: true }))
    return 0
  } catch (error) {
    const reason = error instanceof Error && reasons.has(error.message) ? error.message : 'TOOLCHAIN_REJECTED'
    console.error(`PROBE_BROWSER_TOOLCHAIN=FAIL reason=${reason} acceptanceScope=TOOLCHAIN_ONLY runtime=false`)
    return 1
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) process.exitCode = await main()
