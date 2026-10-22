// Pure contract tests. These do not substitute for the actual Linux NSS/Chrome gate.
import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import { verifierTransport, validateHTTPSReadiness, privateNSSLayout, inspectPublicTLS, browserTLSProof, negativeTLSResult } from './trust-browser-tls.mjs'

const now = Date.UTC(2026, 9, 22, 12)
const root = '/private/fixture'
const scope = { tenantId: 'fixture-tenant', siteId: 'fixture-site', objectType: 'control-plane', objectId: 'fixture-management', environment: 'candidate' }
const ready = () => ({ url: 'https://127.0.0.1:31001/trust.html', auditorToken: 'a'.repeat(40), viewerToken: 'b'.repeat(40), wrongToken: 'c'.repeat(40), tls: { caFile: `${root}/ca.pem`, serverCertFile: `${root}/server-cert.pem`, untrustedURL: 'https://127.0.0.1:31002/trust.html', wrongSANURL: 'https://127.0.0.1:31003/trust.html', expiredURL: 'https://127.0.0.1:31004/trust.html' }, productScope: { ...scope } })

// Small DER fixture writer: keys/signatures are generated in memory, never files.
const der = (tag, ...chunks) => {
  const bytes = Buffer.concat(chunks.map(chunk => Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)))
  const length = bytes.length < 128 ? [bytes.length] : bytes.length < 256 ? [0x81, bytes.length] : [0x82, bytes.length >> 8, bytes.length & 255]
  return Buffer.concat([Buffer.from([tag, ...length]), bytes])
}
const seq = (...chunks) => der(0x30, ...chunks)
const oid = hex => der(0x06, Buffer.from(hex, 'hex'))
const algorithm = seq(oid('2a8648ce3d040302'))
const name = value => seq(der(0x31, seq(oid('550403'), der(0x0c, Buffer.from(value)))))
const date = value => der(0x17, Buffer.from(new Date(value).toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z'))
const extension = (id, value, critical = false) => seq(oid(id), ...(critical ? [der(0x01, [255])] : []), der(0x04, value))
const keys = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
function certificate(pair, issuer, issuerName, subject, { ca = false, ip = [127, 0, 0, 1], from = now - 60000, until = now + 1800000 } = {}) {
  const extensions = [extension('551d13', seq(...(ca ? [der(0x01, [255])] : [])), true), extension('551d0f', der(0x03, ca ? [1, 6] : [7, 128]), true)]
  if (!ca) extensions.push(extension('551d11', seq(der(0x87, ip))), extension('551d25', seq(oid('2b06010505070301'))))
  const body = seq(der(0xa0, der(0x02, [2])), der(0x02, [1]), algorithm, name(issuerName), seq(date(from), date(until)), name(subject), pair.publicKey.export({ type: 'spki', format: 'der' }), der(0xa3, seq(...extensions)))
  const raw = seq(body, algorithm, der(0x03, [0], sign('sha256', body, issuer.privateKey)))
  return `-----BEGIN CERTIFICATE-----\n${raw.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`
}
const caKeys = keys(), leafKeys = keys(), otherKeys = keys()
const ca = certificate(caKeys, caKeys, 'private test CA', 'private test CA', { ca: true })
const leaf = certificate(leafKeys, caKeys, 'private test CA', 'private leaf')
const otherCA = certificate(otherKeys, otherKeys, 'other test CA', 'other test CA', { ca: true })

test('D9 transport remains HTTP by default and strictly opts into HTTPS', () => {
  const args = ['--fixture-root', root, '--chrome', '/chrome', '--evidence-dir', '/evidence']
  assert.equal(verifierTransport(args), 'http')
  assert.equal(verifierTransport([...args, '--transport', 'https']), 'https')
  for (const tail of [['--transport', 'ftp'], ['--transport', ''], ['--fixture-root', '/other'], ['--unknown', 'https']]) assert.throws(() => verifierTransport([...args, ...tail]))
  assert.throws(() => verifierTransport(args.slice(0, 4)))
})

test('D9 readiness accepts only exact HTTPS ports public files and explicit product scope', () => {
  assert.deepEqual(validateHTTPSReadiness(ready(), root).scope, scope)
  const cases = [
    value => { value.extra = 'forbidden' },
    value => { value.tls.privateKey = '/secret.pem' },
    value => { value.tls.caFile = '/outside/ca.pem' },
    value => { value.tls.caFile = `${root}/../ca.pem` },
    value => { value.tls.caFile = value.tls.serverCertFile },
    value => { value.tls.wrongSANURL = value.url },
    value => { value.url = value.url.replace('https:', 'http:') },
    value => { value.url = value.url.replace('127.0.0.1', 'localhost') },
    value => { value.url += '?token=forbidden' },
    value => { value.url = value.url.replace('https://', 'https://user@') },
    value => { value.productScope.extra = 'forbidden' },
    value => { value.productScope.environment = 'production' },
    value => { value.productScope.objectType = 'image-trust' },
    value => { value.productScope.objectId = '../escape' },
  ]
  for (const mutate of cases) { const value = ready(); mutate(value); assert.throws(() => validateHTTPSReadiness(value, root)) }
})

test('D9 NSS database is modern user-wide storage inside private browser HOME', () => {
  assert.deepEqual(privateNSSLayout(`${root}/chrome-profile`), { home: `${root}/chrome-profile/home`, data: `${root}/chrome-profile/home/.local/share`, database: `${root}/chrome-profile/home/.local/share/pki/nssdb`, legacy: `${root}/chrome-profile/home/.pki/nssdb` })
  for (const path of ['/', 'relative/chrome-profile', `${root}/../chrome-profile`, `${root}/not-profile`]) assert.throws(() => privateNSSLayout(path))
})

test('D9 public TLS evidence verifies actual signatures IP SAN and short validity', () => {
  const verified = inspectPublicTLS(ca, leaf, now)
  assert.match(verified.caSHA256, /^[a-f0-9]{64}$/)
  assert.notEqual(verified.caSHA256, verified.leafSHA256)
  const wrongSAN = certificate(leafKeys, caKeys, 'private test CA', 'private leaf', { ip: [127, 0, 0, 2] })
  const expired = certificate(leafKeys, caKeys, 'private test CA', 'private leaf', { from: now - 120000, until: now - 1000 })
  const future = certificate(leafKeys, caKeys, 'private test CA', 'private leaf', { from: now + 1000 })
  const long = certificate(leafKeys, caKeys, 'private test CA', 'private leaf', { until: now + 90000000 })
  for (const [rootCA, cert] of [[otherCA, leaf], [ca, wrongSAN], [ca, expired], [ca, future], [ca, long], [ca, ca], [leaf, leaf], [ca + ca, leaf], [ca, leaf + 'PRIVATE KEY'], [ca, 'not a certificate']]) assert.throws(() => inspectPublicTLS(rootCA, cert, now))
})

test('D9 browser TLS proof binds Chrome secure response and DER leaf to fixture CA', () => {
  const verified = inspectPublicTLS(ca, leaf, now)
  const response = { securityState: 'secure', securityDetails: { protocol: 'TLS 1.3', cipher: 'AES_128_GCM', sanList: ['127.0.0.1'], validFrom: (now - 60000) / 1000, validTo: (now + 1800000) / 1000 } }
  const chain = [verified.leaf.raw.toString('base64'), verified.ca.raw.toString('base64')]
  const proof = browserTLSProof(response, chain, verified, now)
  assert.equal(proof.leafSignatureVerified, true)
  assert.equal(proof.ipSANVerified, true)
  assert.equal(proof.serverChainLength, 2)
  assert.equal(proof.protocol, 'TLS 1.3')
  for (const mutate of [r => { r.securityState = 'insecure' }, r => { r.securityDetails.protocol = 'TLS 1.1' }, r => { r.securityDetails.sanList = [] }, r => { r.securityDetails.validTo = now / 1000 }, r => { r.securityDetails.validFrom = now / 1000 + 1 }]) { const value = structuredClone(response); mutate(value); assert.throws(() => browserTLSProof(value, chain, verified, now)) }
  for (const invalid of [[], [chain[1]], ['not base64!'], [chain[0] + '='], Array(9).fill(chain[0])]) assert.throws(() => browserTLSProof(response, invalid, verified, now))
})

test('D9 negative TLS proof requires exact browser certificate errors and zero application traffic', () => {
  for (const [kind, expected] of [['untrusted', 'net::ERR_CERT_AUTHORITY_INVALID'], ['wrong-san', 'net::ERR_CERT_COMMON_NAME_INVALID'], ['expired', 'net::ERR_CERT_DATE_INVALID']]) {
    const observed = { errorText: expected, httpResponses: 0, apiRequests: 0, authorizationHeaders: 0, businessMounted: false, navigationRequests: 1 }
    assert.equal(negativeTLSResult(kind, expected, { errorText: expected }, observed).error, expected)
    assert.throws(() => negativeTLSResult(kind, expected, {}, observed))
    for (const field of ['httpResponses', 'apiRequests', 'authorizationHeaders', 'navigationRequests']) assert.throws(() => negativeTLSResult(kind, expected, { errorText: expected }, { ...observed, [field]: observed[field] + 1 }))
    assert.throws(() => negativeTLSResult(kind, expected, { errorText: expected }, { ...observed, businessMounted: true }))
    assert.throws(() => negativeTLSResult(kind, expected, { errorText: expected }, { ...observed, errorText: 'net::ERR_CONNECTION_REFUSED' }))
    assert.throws(() => negativeTLSResult(kind, 'net::ERR_CONNECTION_REFUSED', { errorText: 'net::ERR_CONNECTION_REFUSED' }, { ...observed, errorText: 'net::ERR_CONNECTION_REFUSED' }))
  }
})
