import type { CapabilityReport, CapabilityState, SystemCapability } from './types'

// Configuration inventory is not a health sample or an execution authority.
// Reject malformed/unknown reports before rendering or counting their states.
const states: readonly CapabilityState[] = ['live_readonly', 'implemented_local', 'design_only', 'blocked']
function requireShape(value: unknown): asserts value {
  if (!value) throw new Error('能力清单格式不受支持，当前状态未核验')
}
function record(value: unknown): Record<string, unknown> {
  requireShape(value !== null && typeof value === 'object' && !Array.isArray(value))
  return value as Record<string, unknown>
}
function exactKeys(value: Record<string, unknown>, expected: string[]) {
  requireShape(Object.keys(value).length === expected.length && expected.every(key => Object.hasOwn(value, key)))
}
function text(value: unknown, limit: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit && !/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(value)
}
function lines(value: unknown): string[] {
  requireShape(Array.isArray(value) && value.length <= 32 && value.every(line => text(line, 2048)))
  return [...value] as string[]
}
export function decodeCapabilityReport(value: unknown): CapabilityReport {
  const v = record(value)
  exactKeys(v, ['generatedAt', 'productionControlEnabled', 'overallState', 'capabilities'])
  requireShape(typeof v.generatedAt === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(v.generatedAt) && Number.isFinite(Date.parse(v.generatedAt)))
  requireShape(new Date(v.generatedAt).toISOString().replace('.000Z', 'Z') === v.generatedAt)
  requireShape(typeof v.productionControlEnabled === 'boolean' && text(v.overallState, 64))
  requireShape(Array.isArray(v.capabilities) && v.capabilities.length <= 256)
  const ids = new Set<string>()
  const capabilities: SystemCapability[] = v.capabilities.map(raw => {
    const item = record(raw)
    exactKeys(item, ['id', 'domain', 'name', 'state', 'readOnly', 'evidence', 'limitations'])
    requireShape(typeof item.id === 'string' && /^[A-Za-z][A-Za-z0-9_-]{0,127}$/.test(item.id) && !ids.has(item.id))
    requireShape(text(item.domain, 64))
    requireShape(text(item.name, 160) && states.includes(item.state as CapabilityState) && typeof item.readOnly === 'boolean')
    ids.add(item.id)
    const evidence = lines(item.evidence), limitations = lines(item.limitations)
    requireShape(limitations.length > 0)
    return { id: item.id, domain: item.domain, name: item.name, state: item.state as CapabilityState, readOnly: item.readOnly, evidence, limitations }
  })
  return { generatedAt: v.generatedAt, productionControlEnabled: v.productionControlEnabled, overallState: v.overallState, capabilities }
}
