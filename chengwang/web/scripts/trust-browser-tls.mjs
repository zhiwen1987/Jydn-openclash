// CI-only normal certificate trust. Never changes the OS trust store or disables
// Chrome verification. NSS is user-wide, so --user-data-dir alone is insufficient.
import { X509Certificate, createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import { constants } from 'node:fs'
import { lstat, mkdir, open } from 'node:fs/promises'
import { posix } from 'node:path'
import { promisify } from 'node:util'

const execute = promisify(execFile)
const invalid = () => { throw new Error('invalid private HTTPS browser fixture') }
const exact = (object, names) => object && typeof object === 'object' && !Array.isArray(object) && Object.keys(object).sort().join(',') === [...names].sort().join(',')
const fingerprint = certificate => createHash('sha256').update(certificate.raw).digest('hex')

export function verifierTransport(args) {
  const known = ['--fixture-root', '--chrome', '--evidence-dir', '--transport']
  if (args.length !== 6 && args.length !== 8) invalid()
  const found = new Map()
  for (let index = 0; index < args.length; index += 2) {
    if (!known.includes(args[index]) || found.has(args[index]) || typeof args[index + 1] !== 'string' || !args[index + 1]) invalid()
    found.set(args[index], args[index + 1])
  }
  if (!known.slice(0, 3).every(key => found.has(key))) invalid()
  const transport = found.get('--transport') ?? 'http'
  if (!['http', 'https'].includes(transport)) invalid()
  return transport
}

export function loopbackURL(value, protocol = 'https:') {
  if (typeof value !== 'string' || value.length > 256) invalid()
  let url
  try { url = new URL(value) } catch { invalid() }
  if (url.href !== value || url.protocol !== protocol || url.hostname !== '127.0.0.1' || !url.port || url.pathname !== '/trust.html' || url.username || url.password || url.search || url.hash) invalid()
  return url
}

export function validateHTTPSReadiness(ready, root) {
  if (!exact(ready, ['url', 'auditorToken', 'viewerToken', 'wrongToken', 'tls', 'productScope']) || !exact(ready.tls, ['caFile', 'serverCertFile', 'untrustedURL', 'wrongSANURL', 'expiredURL'])) invalid()
  if (!exact(ready.productScope, ['tenantId', 'siteId', 'objectType', 'objectId', 'environment'])) invalid()
  if (!Object.values(ready.productScope).every(value => typeof value === 'string' && /^[A-Za-z0-9._-]{1,128}$/.test(value)) || ready.productScope.objectType !== 'control-plane' || ready.productScope.environment !== 'candidate') invalid()
  if (typeof root !== 'string' || !posix.isAbsolute(root) || posix.normalize(root) !== root || root === '/') invalid()
  for (const key of ['caFile', 'serverCertFile']) {
    const file = ready.tls[key]
    if (typeof file !== 'string' || !posix.isAbsolute(file) || posix.normalize(file) !== file || posix.dirname(file) !== root || !/^[A-Za-z0-9._-]+\.pem$/.test(posix.basename(file))) invalid()
  }
  if (ready.tls.caFile === ready.tls.serverCertFile) invalid()
  const positive = loopbackURL(ready.url)
  const negatives = [
    { kind: 'untrusted', url: ready.tls.untrustedURL, expected: 'net::ERR_CERT_AUTHORITY_INVALID' },
    { kind: 'wrong-san', url: ready.tls.wrongSANURL, expected: 'net::ERR_CERT_COMMON_NAME_INVALID' },
    { kind: 'expired', url: ready.tls.expiredURL, expected: 'net::ERR_CERT_DATE_INVALID' },
  ].map(value => ({ ...value, origin: loopbackURL(value.url).origin }))
  if (new Set([positive.origin, ...negatives.map(value => value.origin)]).size !== 4) invalid()
  return { positive, negatives, scope: { ...ready.productScope } }
}

export function privateNSSLayout(profile) {
  if (typeof profile !== 'string' || !posix.isAbsolute(profile) || posix.normalize(profile) !== profile || profile === '/' || !profile.endsWith('/chrome-profile')) invalid()
  const home = posix.join(profile, 'home')
  return { home, data: posix.join(home, '.local', 'share'), database: posix.join(home, '.local', 'share', 'pki', 'nssdb'), legacy: posix.join(home, '.pki', 'nssdb') }
}

export function inspectPublicTLS(caPEM, leafPEM, now = Date.now()) {
  let ca, leaf
  try {
    for (const pem of [caPEM, leafPEM]) if (typeof pem !== 'string' || pem.length > 65536 || !/^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----\s*$/.test(pem) || (pem.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length !== 1 || pem.includes('PRIVATE KEY')) invalid()
    ca = new X509Certificate(caPEM); leaf = new X509Certificate(leafPEM)
    const live = certificate => Date.parse(certificate.validFrom) <= now && now < Date.parse(certificate.validTo) && Date.parse(certificate.validTo) <= now + 86400000
    if (!ca.ca || !ca.verify(ca.publicKey) || !live(ca) || leaf.ca || !live(leaf) || !leaf.checkIssued(ca) || !leaf.verify(ca.publicKey) || leaf.checkIP('127.0.0.1') !== '127.0.0.1') invalid()
  } catch { invalid() }
  return { ca, leaf, caSHA256: fingerprint(ca), leafSHA256: fingerprint(leaf) }
}

async function publicCertificate(file, root) {
  if (posix.dirname(file) !== root) invalid()
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  try {
    const before = await handle.stat()
    if (!before.isFile() || before.nlink !== 1 || before.uid !== process.getuid() || (before.mode & 0o7777) !== 0o600 || before.size <= 0 || before.size > 65536) invalid()
    const data = await handle.readFile({ encoding: 'utf8' })
    const after = await handle.stat()
    if (before.ino !== after.ino || before.dev !== after.dev || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) invalid()
    return data
  } finally { await handle.close() }
}

export async function preparePrivateNSS(ready, root, profile) {
  if (process.platform !== 'linux' || process.getuid() === 0) invalid()
  validateHTTPSReadiness(ready, root)
  if (profile !== posix.join(root, 'chrome-profile')) invalid()
  const layout = privateNSSLayout(profile)
  const tool = process.env.CERTUTIL_BINARY || '/usr/bin/certutil'
  if (!posix.isAbsolute(tool) || posix.normalize(tool) !== tool) invalid()
  const rootInfo = await lstat(root), profileInfo = await lstat(profile), toolInfo = await lstat(tool)
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink() || rootInfo.uid !== process.getuid() || (rootInfo.mode & 0o7777) !== 0o700 || !profileInfo.isDirectory() || profileInfo.isSymbolicLink() || profileInfo.uid !== process.getuid() || (profileInfo.mode & 0o7777) !== 0o700 || !toolInfo.isFile() || toolInfo.uid !== 0 || toolInfo.mode & 0o022) invalid()
  const caPEM = await publicCertificate(ready.tls.caFile, root)
  const leafPEM = await publicCertificate(ready.tls.serverCertFile, root)
  const verified = inspectPublicTLS(caPEM, leafPEM)
  // mkdir is deliberately exclusive: never reuse another run's user trust DB.
  await mkdir(layout.home, { mode: 0o700 })
  await mkdir(layout.database, { recursive: true, mode: 0o700 })
  try { await lstat(layout.legacy); invalid() } catch (error) { if (error.code !== 'ENOENT') throw error }
  const environment = { HOME: layout.home, XDG_DATA_HOME: layout.data, XDG_CONFIG_HOME: posix.join(profile, 'config'), XDG_CACHE_HOME: posix.join(profile, 'cache') }
  const run = args => execute(tool, args, { env: { ...process.env, ...environment }, encoding: 'utf8', timeout: 10000, killSignal: 'SIGKILL', maxBuffer: 65536, windowsHide: true })
  let imported
  try {
    await run(['-N', '-d', `sql:${layout.database}`, '--empty-password'])
    await run(['-A', '-d', `sql:${layout.database}`, '-n', 'chengwang-ci-browser-root', '-t', 'C,,', '-i', ready.tls.caFile])
    imported = (await run(['-L', '-d', `sql:${layout.database}`, '-n', 'chengwang-ci-browser-root', '-a'])).stdout
  } catch { throw new Error('private browser trust setup failed') }
  if (fingerprint(new X509Certificate(imported)) !== verified.caSHA256) invalid()
  return { environment, verified, evidence: { method: 'PRIVATE_NSS_SQL_LOCAL_CA', legacyDatabaseAbsent: true, trustFlags: 'C,,', tool: 'preinstalled-certutil', caSHA256: verified.caSHA256, leafSHA256: verified.leafSHA256 } }
}

export function browserTLSProof(response, chain, verified, now = Date.now()) {
  const details = response?.securityDetails
  if (response?.securityState !== 'secure' || !details || !['TLS 1.2', 'TLS 1.3'].includes(details.protocol) || !Array.isArray(details.sanList) || !details.sanList.includes('127.0.0.1') || !Number.isFinite(details.validFrom) || !Number.isFinite(details.validTo) || details.validFrom * 1000 > now || details.validTo * 1000 <= now || !Array.isArray(chain) || chain.length < 1 || chain.length > 8) invalid()
  let leaf
  try {
    for (const encoded of chain) if (typeof encoded !== 'string' || encoded.length > 65536 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || Buffer.from(encoded, 'base64').toString('base64') !== encoded) invalid()
    leaf = new X509Certificate(Buffer.from(chain[0], 'base64'))
    if (fingerprint(leaf) !== verified.leafSHA256 || !leaf.verify(verified.ca.publicKey) || leaf.checkIP('127.0.0.1') !== '127.0.0.1') invalid()
  } catch { invalid() }
  return { securityState: 'secure', protocol: details.protocol, cipher: String(details.cipher ?? '').slice(0, 128), leafSHA256: verified.leafSHA256, caSHA256: verified.caSHA256, serverChainLength: chain.length, leafSignatureVerified: true, ipSANVerified: true }
}

export function negativeTLSResult(kind, expected, navigation, observed) {
  const errors = { untrusted: 'net::ERR_CERT_AUTHORITY_INVALID', 'wrong-san': 'net::ERR_CERT_COMMON_NAME_INVALID', expired: 'net::ERR_CERT_DATE_INVALID' }
  if (!Object.hasOwn(errors, kind) || errors[kind] !== expected || navigation?.errorText !== expected || observed.errorText !== expected || observed.httpResponses !== 0 || observed.apiRequests !== 0 || observed.authorizationHeaders !== 0 || observed.businessMounted !== false || observed.navigationRequests !== 1) invalid()
  return { kind, error: expected, businessMounted: false, httpResponses: 0, apiRequests: 0, authorizationHeaders: 0 }
}
