// Source-owned scene contracts. Import performs no launch or application I/O.
import { parseArguments, canaryVariants, safePublic } from '../subscription-ui-browser/ui-contract.mjs'
import { manifestGraph } from '../capability-truth-browser/ui-contract.mjs'
import { strictJSON, exact, need, sha, PROFILES, ORIGIN } from './wire-contract.mjs'
export { parseArguments, canaryVariants, safePublic, manifestGraph, strictJSON, exact, need, sha }
export const integer = (n, min = 0, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(n) && n >= min && n <= max
export const scope = () => ({ tenantId: '', siteId: '', environment: 'candidate', objectType: 'control-plane', objectId: 'local' })
const commonSteps = ['demo_desktop', 'actual_enter_desktop', 'actual_refresh_desktop', 'demo_return_desktop', 'actual_reenter_desktop']
const lastSteps = ['kernels_page_desktop', 'actual_return_from_kernels', 'actual_mobile', 'actual_mobile_refresh', 'demo_mobile', 'actual_mobile_reenter']
export const stepsFor = profile => {
  need(PROFILES.includes(profile))
  return [...commonSteps, ...(profile === 'evidence_enabled_unknown' ? ['device_page_desktop', 'actual_return_from_device', 'nodes_page_desktop', 'actual_return_from_nodes', 'subscriptions_page_desktop', 'actual_return_from_subscriptions'] : []), ...lastSteps]
}
export function loadContract(raw) {
  const c = strictJSON(raw, 131072)
  need(c.schema === 'chengwang.overview-ui-browser-contract/v1' && c.scenario === 'overview_ui' && c.origin === ORIGIN)
  need(Array.isArray(c.profiles) && c.profiles.join(',') === PROFILES.join(',') && c.engines?.join(',') === 'chrome-cdp,playwright')
  need(c.privateInputFilename === 'overview-input.private.json' && c.driverEntrypoint === 'chengwang/tools/overview-ui-browser/ui-cli.mjs')
  need(Array.isArray(c.publicFiles) && c.publicFiles.length === 19 && new Set(c.publicFiles).size === 19 && c.publicFiles.filter(v => v.endsWith('.png')).length === 8)
  need(c.exactKeySchemas && c.nestedExactKeys && c.schemaNames && c.captureRules?.bounds && c.manifestAlgorithm?.keys)
  need(c.captureRules.bounds.assets === 64 && c.captureRules.bounds.driverFileBytes === 1048576 && c.captureRules.bounds.domFileBytes === 2097152 && c.captureRules.bounds.domRowBytes === 131072)
  need(c.stepRules.nodesVisitSecondsMax === 10 && c.stepRules.productProbePollIntervalSeconds === 30 && c.stepRules.extraPollAccepted === false)
  for (const profile of PROFILES) {
    const rows = c.stepFences[profile]
    need(Array.isArray(rows) && rows.length === stepsFor(profile).length && rows.map(v => v[0]).join(',') === stepsFor(profile).join(','))
    need(rows.every(v => Array.isArray(v) && v.length === 11 && v[6] === 900 && [375, 1440].includes(v[5])))
    need(rows.filter(v => v[10] !== null).length === 8 && rows.every(v => v[10] === null || c.publicFiles.includes(v[10])))
  }
  return c
}
export function validateInput(v, o, c) {
  need(exact(v, c.exactKeySchemas.input) && v.schema === c.schemaNames.input && v.scenario === c.scenario && PROFILES.includes(v.profile))
  need(v.sourceCommit === o.sourceCommit && v.fixtureId === o.fixtureId && v.engine === o.engine && typeof v.fenceCanary === 'string' && /^[a-f0-9]{64}$/.test(v.fenceCanary))
  return v
}
export function validateRun(v, o, input, c) {
  need(exact(v, c.exactKeySchemas.run) && v.schema === c.schemaNames.run && v.scenario === c.scenario && v.profile === input.profile && v.fixtureId === o.fixtureId && v.engine === o.engine)
  return v
}
const safePath = name => typeof name === 'string' && (['index.html', 'trust.html', '.vite/manifest.json'].includes(name) || /^assets\/[A-Za-z0-9][A-Za-z0-9_.-]{0,160}\.(?:js|css|woff2?|ttf|svg|png)$/.test(name))
export function validateBuild(build, manifestRaw, serverRaw, c, o) {
  need(exact(build, c.exactKeySchemas['build.json']) && build.schema === c.schemaNames.build && build.sourceCommit === o.sourceCommit && build.production === false && build.authorization === 'BLOCKED')
  need(build.goVersion === c.buildAndTrust.goVersion && build.nodeVersion === c.buildAndTrust.nodeVersion && build.moduleMode === 'vendor' && build.goDependencyDownloads === false)
  need(Buffer.isBuffer(serverRaw) && serverRaw.length > 4 && serverRaw.length <= 128 << 20 && serverRaw.subarray(0, 4).equals(Buffer.from([127, 69, 76, 70])))
  need(exact(build.server, ['name', 'bytes', 'sha256']) && build.server.name === 'server' && integer(build.server.bytes, 1, 128 << 20) && build.server.bytes === serverRaw.length && build.server.sha256 === sha(serverRaw))
  need(Buffer.isBuffer(manifestRaw) && manifestRaw.length > 0 && manifestRaw.length <= c.captureRules.bounds.manifestBytes && typeof build.manifestBase64 === 'string')
  const decoded = Buffer.from(build.manifestBase64, 'base64')
  need(decoded.equals(manifestRaw) && decoded.toString('base64') === build.manifestBase64)
  need(Array.isArray(build.distFiles) && build.distFiles.length >= 4 && build.distFiles.length <= 512)
  const expectedFiles = new Map(); let previous = ''
  for (const row of build.distFiles) {
    need(exact(row, ['path', 'bytes', 'sha256']) && safePath(row.path) && row.path > previous && integer(row.bytes, 1, 16 << 20) && typeof row.sha256 === 'string' && /^[a-f0-9]{64}$/.test(row.sha256))
    expectedFiles.set(row.path, { ...row }); previous = row.path
  }
  need(['index.html', 'trust.html', '.vite/manifest.json'].every(v => expectedFiles.has(v)))
  const manifest = expectedFiles.get('.vite/manifest.json'); need(manifest.bytes === manifestRaw.length && manifest.sha256 === sha(manifestRaw))
  const graph = manifestGraph(strictJSON(manifestRaw, c.captureRules.bounds.manifestBytes), c)
  need(graph.allowed.every(name => expectedFiles.has(name.slice(1))))
  return { graph, expectedFiles }
}
export function apiFence(rows) {
  need(Array.isArray(rows) && rows.every((r, i) => r && integer(r.ordinal, 1, 77) && (i === 0 || rows[i - 1].ordinal < r.ordinal)))
  const by = kind => rows.filter(r => r.kind === kind).map(r => r.ordinal)
  return { snapshotCaptureOrdinal: by('SNAPSHOT')[0] ?? 0, overviewCaptureOrdinals: by('OVERVIEW'), observationStatusCaptureOrdinals: by('OBSERVATION_STATUS'), probeStatusCaptureOrdinals: by('PROBE_STATUS') }
}
export function exactCounts(rows, fence) {
  const count = kind => rows.filter(r => r.kind === kind).length
  return count('SNAPSHOT') === 1 && count('OVERVIEW') === fence[7] && count('OBSERVATION_STATUS') === fence[8] && count('PROBE_STATUS') === fence[9]
}
