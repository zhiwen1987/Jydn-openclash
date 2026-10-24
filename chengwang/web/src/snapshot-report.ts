import type { BusinessPolicy, BusinessStatus, DNSPolicy, EventItem, NodePool, PolicyDraft, PoolStatus, ProxyInterface, Snapshot } from './types'

export const SNAPSHOT_FORMAT_ERROR = '系统快照格式不受支持，当前状态未核验'

// Client allocation limits, not claims that the Go domain imposes these caps.
// The HTTP body is already parsed here; this does not bound network/body bytes.
export const SNAPSHOT_LIMITS = Object.freeze({ rows: 1024, events: 4096, members: 4096, items: 16384, characters: 1 << 20 })

function need(value: unknown): asserts value {
  if (!value) throw new Error(SNAPSHOT_FORMAT_ERROR)
}
function own(value: Record<string, unknown>, key: string) { return Object.hasOwn(value, key) }
function object(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  need(value !== null && typeof value === 'object' && !Array.isArray(value))
  const row = value as Record<string, unknown>, allowed = new Set([...required, ...optional])
  need(required.every(key => own(row, key)) && Object.keys(row).every(key => allowed.has(key)))
  return row
}
function integer(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  need(typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= maximum)
  return value
}
function draftInteger(value: unknown): number {
  need(typeof value === 'number' && Number.isSafeInteger(value))
  return value
}
function boolean(value: unknown): boolean { need(typeof value === 'boolean'); return value }
function displayText(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index)
    if (code <= 0x1f || code >= 0x7f && code <= 0x9f || code >= 0x202a && code <= 0x202e || code >= 0x2066 && code <= 0x2069) return false
  }
  return true
}
function choice<T extends string>(value: unknown, values: readonly T[]): T {
  need(typeof value === 'string' && values.includes(value as T))
  return value as T
}
function unique<T>(rows: T[], key: (value: T) => string): T[] {
  const keys = new Set<string>()
  for (const row of rows) { const id = key(row); need(!keys.has(id)); keys.add(id) }
  return rows
}

// time.Time.MarshalJSON uses RFC3339Nano, including up to nine fractional
// digits and explicit offsets. Validate the original calendar, not Date's
// permissive day rollover, and preserve the original precision and offset.
function timestamp(value: unknown): string {
  need(typeof value === 'string' && value.length <= 35)
  const parts = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/.exec(value)
  need(parts)
  const year = Number(parts[1]), month = Number(parts[2]), day = Number(parts[3])
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  need(month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1])
  need(Number(parts[4]) <= 23 && Number(parts[5]) <= 59 && Number(parts[6]) <= 59)
  if (parts[8] !== 'Z') need(Number(parts[8].slice(1, 3)) <= 23 && Number(parts[8].slice(4)) <= 59)
  need(Number.isFinite(Date.parse(value)))
  return value
}

class SnapshotReader {
  private characters = 0
  private items = 0

  text(value: unknown, maximum = 256): string {
    need(typeof value === 'string' && value.length <= maximum && displayText(value))
    this.characters += value.length
    need(this.characters <= SNAPSHOT_LIMITS.characters)
    return value
  }

  // A required Go slice is present even when nil: JSON null means no elements.
  // Normalize only an explicitly supplied null; a missing field is rejected by
  // object(). Empty arrays do not imply inventory completeness or health.
  slice<T>(value: unknown, decode: (item: unknown) => T, maximum: number = SNAPSHOT_LIMITS.rows): T[] {
    if (value === null) return []
    need(Array.isArray(value) && value.length <= maximum)
    this.items += value.length
    need(this.items <= SNAPSHOT_LIMITS.items)
    const result: T[] = []
    for (let index = 0; index < value.length; index++) { need(Object.hasOwn(value, index)); result.push(decode(value[index])) }
    return result
  }

  strings(value: unknown, maximum: number = SNAPSHOT_LIMITS.rows, width = 256): string[] {
    return this.slice(value, item => this.text(item, width), maximum)
  }

  id(value: unknown, proxy = false): string {
    const id = this.text(value, proxy ? 48 : 128)
    need(proxy ? /^[a-z][a-z0-9_-]{1,47}$/.test(id) : /^[\p{L}\p{N}][\p{L}\p{N}._ -]{0,63}$/u.test(id))
    return id
  }

  business(value: unknown): BusinessStatus {
    const v = object(value, ['id', 'name', 'strategy', 'activeRoute', 'status'])
    return { id: this.id(v.id), name: this.text(v.name, 160), strategy: this.text(v.strategy), activeRoute: this.text(v.activeRoute), status: this.text(v.status) }
  }

  pool(value: unknown): PoolStatus {
    const v = object(value, ['name', 'region', 'latencyMs', 'lossRate', 'available', 'total', 'status'])
    need(typeof v.lossRate === 'number' && Number.isFinite(v.lossRate) && v.lossRate >= 0 && v.lossRate <= 100)
    const available = integer(v.available), total = integer(v.total)
    need(available <= total)
    return { name: this.text(v.name, 160), region: this.text(v.region, 160), latencyMs: integer(v.latencyMs), lossRate: v.lossRate, available, total, status: this.text(v.status) }
  }

  interface(value: unknown): ProxyInterface {
    const v = object(value, ['id', 'name', 'type', 'core', 'listen', 'port', 'udp', 'lanAccess', 'authMode', 'tls', 'accessScope', 'maxConnections', 'idleTimeoutSec', 'rateLimitMbps', 'auditEnabled', 'enabled', 'status', 'routingProfile'], ['authReference', 'tlsReference', 'allowedCidrs', 'description'])
    // Within this safe display subset, canonicalize known kinds as the Go
    // validator does. JS trim also removes BOM, which Go TrimSpace does not;
    // reject BOM explicitly, and keep the stricter control-character policy.
    const rawKind = this.text(v.type, 32)
    need(!rawKind.includes('\ufeff'))
    const kind = rawKind.trim().toLowerCase()
    const result: ProxyInterface = {
      id: this.id(v.id, true), name: this.text(v.name, 160), type: choice(kind, ['http', 'socks5', 'mixed', 'tun', 'tproxy', 'redirect', 'api'] as const),
      core: this.text(v.core, 64), listen: this.text(v.listen), port: integer(v.port, 65535), udp: boolean(v.udp), lanAccess: boolean(v.lanAccess),
      authMode: choice(v.authMode, ['none', 'password', 'token', 'mtls'] as const), tls: boolean(v.tls), accessScope: choice(v.accessScope, ['local', 'lan', 'vpn', 'custom'] as const),
      maxConnections: integer(v.maxConnections, 1000000), idleTimeoutSec: integer(v.idleTimeoutSec, 86400), rateLimitMbps: integer(v.rateLimitMbps, 100000),
      auditEnabled: boolean(v.auditEnabled), enabled: boolean(v.enabled), status: this.text(v.status), routingProfile: this.text(v.routingProfile),
    }
    if (own(v, 'authReference')) result.authReference = this.text(v.authReference)
    if (own(v, 'tlsReference')) result.tlsReference = this.text(v.tlsReference)
    if (own(v, 'allowedCidrs')) { need(Array.isArray(v.allowedCidrs)); result.allowedCidrs = this.strings(v.allowedCidrs, 1024, 128) }
    if (own(v, 'description')) result.description = this.text(v.description, 2048)
    return result
  }

  event(value: unknown): EventItem {
    const v = object(value, ['at', 'type', 'reason', 'result'])
    return { at: timestamp(v.at), type: this.text(v.type), reason: this.text(v.reason, 2048), result: this.text(v.result, 2048) }
  }

  policy(value: unknown): BusinessPolicy {
    const v = object(value, ['id', 'name', 'domains', 'strategy', 'candidates', 'fallback', 'skipEmptyPools', 'failuresToSwitch', 'probeIntervalSec', 'sessionStickyMin', 'switchCooldownSec'], ['requireCapabilities'])
    const result: BusinessPolicy = {
      id: this.id(v.id), name: this.text(v.name, 160), domains: this.strings(v.domains, 1024, 253), strategy: this.text(v.strategy),
      candidates: this.strings(v.candidates), fallback: this.text(v.fallback), skipEmptyPools: boolean(v.skipEmptyPools),
      // These are editable draft values, not observed counts. Keep signed
      // safe integers so the separate policy validator can explain failures.
      failuresToSwitch: draftInteger(v.failuresToSwitch), probeIntervalSec: draftInteger(v.probeIntervalSec), sessionStickyMin: draftInteger(v.sessionStickyMin), switchCooldownSec: draftInteger(v.switchCooldownSec),
    }
    if (own(v, 'requireCapabilities')) { need(Array.isArray(v.requireCapabilities)); result.requireCapabilities = this.strings(v.requireCapabilities) }
    return result
  }

  nodePool(value: unknown): NodePool {
    const v = object(value, ['id', 'name', 'members'], ['capabilities'])
    const result: NodePool = { id: this.id(v.id), name: this.text(v.name, 160), members: this.strings(v.members, SNAPSHOT_LIMITS.members) }
    if (own(v, 'capabilities')) { need(Array.isArray(v.capabilities)); result.capabilities = this.strings(v.capabilities) }
    return result
  }

  dns(value: unknown): DNSPolicy {
    const v = object(value, ['domesticResolvers', 'overseasResolvers', 'hijackPort53', 'leakProtection'])
    return { domesticResolvers: this.strings(v.domesticResolvers, 1024, 2048), overseasResolvers: this.strings(v.overseasResolvers, 1024, 2048), hijackPort53: boolean(v.hijackPort53), leakProtection: boolean(v.leakProtection) }
  }

  draft(value: unknown): PolicyDraft {
    const v = object(value, ['name', 'baseVersion', 'businesses', 'pools', 'dns'])
    return { name: this.text(v.name, 160), baseVersion: this.text(v.baseVersion), businesses: unique(this.slice(v.businesses, item => this.policy(item)), item => item.id), pools: unique(this.slice(v.pools, item => this.nodePool(item)), item => item.id), dns: this.dns(v.dns) }
  }

  snapshot(value: unknown): Snapshot {
    const v = object(value, ['product', 'version', 'mode', 'status', 'dataSource', 'publishLocked', 'businesses', 'pools', 'interfaces', 'events', 'draft'])
    return {
      product: this.text(v.product), version: this.text(v.version), mode: this.text(v.mode, 64), status: this.text(v.status), dataSource: choice(v.dataSource, ['demo', 'live'] as const), publishLocked: boolean(v.publishLocked),
      businesses: unique(this.slice(v.businesses, item => this.business(item)), item => item.id), pools: unique(this.slice(v.pools, item => this.pool(item)), item => JSON.stringify([item.name, item.region])),
      interfaces: unique(this.slice(v.interfaces, item => this.interface(item)), item => item.id), events: this.slice(v.events, item => this.event(item), SNAPSHOT_LIMITS.events), draft: this.draft(v.draft),
    }
  }
}

export function decodeSnapshotReport(value: unknown): Snapshot {
  // Never include field values, JSON fragments, nested exceptions or causes in
  // errors. Allocation validation is not policy approval or data-plane health.
  try { return new SnapshotReader().snapshot(value) } catch { throw new Error(SNAPSHOT_FORMAT_ERROR) }
}
