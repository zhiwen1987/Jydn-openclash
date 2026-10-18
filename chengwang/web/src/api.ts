import type {
  CapabilityReport, MihomoReadbackReport, MihomoRuntimeSnapshot, OperationEnvelope, OperationResource,
  OperationRisk, OperationStatus, PolicyDraft, ProxyInterface, Snapshot, ValidationResult,
} from './types'

export class APIError extends Error {
  constructor(message: string, readonly status: number, readonly code = 'request_failed') {
    super(message)
    this.name = 'APIError'
  }
}

export function isManagementTransportSecure(location?: Pick<Location, 'protocol' | 'hostname'>): boolean {
	const current = location ?? (typeof window === 'undefined' ? undefined : window.location)
	if (!current) return false
	if (current.protocol === 'https:') return true
	const host = current.hostname.toLowerCase()
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]'
}

function requireManagementTransport(): void {
  if (!isManagementTransportSecure()) {
    throw new APIError('管理令牌不能通过局域网明文 HTTP 发送', 426, 'secure_transport_required')
  }
}

async function throwAPIError(response: Response, fallback: string): Promise<never> {
  let code = 'request_failed'
  let message = fallback
  try {
    const body = await response.json() as { code?: string; message?: string }
    code = body.code ?? code
    message = body.message ?? message
  } catch {
    // A non-JSON proxy error still becomes a bounded, user-facing API error.
  }
  throw new APIError(message, response.status, code)
}

export async function getSnapshot(signal?: AbortSignal): Promise<Snapshot> {
  const response = await fetch('/api/v1/snapshot', { signal, headers: { Accept: 'application/json' } })
  if (!response.ok) throw new Error(`读取系统状态失败 (${response.status})`)
  return response.json() as Promise<Snapshot>
}

export async function validateProxyInterfaces(items: ProxyInterface[]): Promise<ValidationResult> {
  const response = await fetch('/api/v1/proxy/interfaces/validate', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify(items),
  })
  if (!response.ok) throw new Error(`代理接口校验失败 (${response.status})`)
  return response.json() as Promise<ValidationResult>
}

export async function getMihomoRuntime(token: string, signal?: AbortSignal): Promise<MihomoRuntimeSnapshot> {
	requireManagementTransport()
  const response = await fetch('/api/v1/kernels/mihomo/runtime', { signal, headers: operationHeaders(token) })
  if (!response.ok) return throwAPIError(response, `读取 Mihomo 状态失败 (${response.status})`)
  return response.json() as Promise<MihomoRuntimeSnapshot>
}

export async function readbackMihomo(draft: PolicyDraft, token: string, signal?: AbortSignal): Promise<MihomoReadbackReport> {
	requireManagementTransport()
  const response = await fetch('/api/v1/kernels/mihomo/readback', {
    method: 'POST',
    signal,
    headers: { ...operationHeaders(token), 'Content-Type': 'application/json' },
    body: JSON.stringify(draft),
  })
  if (!response.ok) return throwAPIError(response, `Mihomo 读回对账失败 (${response.status})`)
  return response.json() as Promise<MihomoReadbackReport>
}

export async function getCapabilities(signal?: AbortSignal): Promise<CapabilityReport> {
  const response = await fetch('/api/v1/capabilities', { signal, headers: { Accept: 'application/json' } })
  if (!response.ok) return throwAPIError(response, `读取系统闭环状态失败 (${response.status})`)
  return response.json() as Promise<CapabilityReport>
}

function operationHeaders(token: string, idempotencyKey?: string): HeadersInit {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    Authorization: `Bearer ${token}`,
  }
  if (idempotencyKey) {
    headers['Content-Type'] = 'application/json'
    headers['Idempotency-Key'] = idempotencyKey
  }
  return headers
}

function operationScopeQuery(resource: OperationResource): string {
  const query = new URLSearchParams()
  query.set('tenantId', resource.tenantId)
  if (resource.siteId) query.set('siteId', resource.siteId)
  if (resource.objectType) query.set('objectType', resource.objectType)
  if (resource.objectId) query.set('objectId', resource.objectId)
  query.set('environment', resource.environment)
  return query.toString()
}

async function readOperationEnvelope(response: Response): Promise<OperationEnvelope> {
  const result = await response.json() as OperationEnvelope
  if (result.effect !== 'local_record_only' || result.deviceActionsExecuted !== false) {
    throw new APIError('服务端未能证明请求仅产生本地影子记录', 502, 'unsafe_operation_response')
  }
  return result
}

export async function getOperations(resource: OperationResource, token: string, signal?: AbortSignal): Promise<OperationEnvelope> {
	requireManagementTransport()
  const response = await fetch(`/api/v1/operations?${operationScopeQuery(resource)}`, {
    signal,
    headers: operationHeaders(token),
  })
  if (!response.ok) return throwAPIError(response, `读取本地操作记录失败 (${response.status})`)
  return readOperationEnvelope(response)
}

export async function createOperation(
  resource: OperationResource,
  risk: OperationRisk,
  targetVersion: string,
  token: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<OperationEnvelope> {
	requireManagementTransport()
  const response = await fetch('/api/v1/operations', {
    method: 'POST',
    signal,
    headers: operationHeaders(token, idempotencyKey),
    body: JSON.stringify({ resource, risk, targetVersion }),
  })
  if (!response.ok) return throwAPIError(response, `创建本地操作计划失败 (${response.status})`)
  return readOperationEnvelope(response)
}

export async function transitionOperation(
  id: string,
  resource: OperationResource,
  to: OperationStatus,
  token: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<OperationEnvelope> {
	requireManagementTransport()
  const response = await fetch(`/api/v1/operations/${encodeURIComponent(id)}/transitions`, {
    method: 'POST',
    signal,
    headers: operationHeaders(token, idempotencyKey),
    body: JSON.stringify({ resource, to }),
  })
  if (!response.ok) return throwAPIError(response, `更新本地操作状态失败 (${response.status})`)
  return readOperationEnvelope(response)
}
