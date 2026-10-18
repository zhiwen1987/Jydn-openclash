// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { APIError, getMihomoRuntime, getObservationStatus, isManagementTransportSecure } from './api'

afterEach(() => {
	vi.unstubAllGlobals()
})

describe('management transport boundary', () => {
	it('accepts HTTPS and exact loopback hosts only', () => {
		expect(isManagementTransportSecure({ protocol: 'https:', hostname: '10.88.0.254' })).toBe(true)
		expect(isManagementTransportSecure({ protocol: 'http:', hostname: 'localhost' })).toBe(true)
		expect(isManagementTransportSecure({ protocol: 'http:', hostname: '127.0.0.1' })).toBe(true)
		expect(isManagementTransportSecure({ protocol: 'http:', hostname: '10.88.0.254' })).toBe(false)
		expect(isManagementTransportSecure({ protocol: 'http:', hostname: 'localhost.example' })).toBe(false)
	})

	it('rejects a LAN HTTP token before fetch', async () => {
		const fetchMock = vi.fn()
		vi.stubGlobal('fetch', fetchMock)
		vi.stubGlobal('window', { location: { protocol: 'http:', hostname: '10.88.0.254' } })
		await expect(getMihomoRuntime('must-not-leave-browser')).rejects.toMatchObject<Partial<APIError>>({
			status: 426,
			code: 'secure_transport_required',
		})
		expect(fetchMock).not.toHaveBeenCalled()
	})
})

describe('passive observation API', () => {
	it('reads the anonymous cached status without credentials', async () => {
		const status = { configured: true, mode: 'passive_read_only', running: true, fresh: false, stale: false, consecutiveFailures: 0 }
		let capturedInit: RequestInit | undefined
		const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
			expect(String(input)).toBe('/api/v1/observations/status')
			capturedInit = init
			return Promise.resolve({ ok: true, status: 200, json: async () => status } as Response)
		})
		vi.stubGlobal('fetch', fetchMock)
		await expect(getObservationStatus()).resolves.toEqual(status)
		expect(fetchMock).toHaveBeenCalledWith('/api/v1/observations/status', expect.objectContaining({ headers: { Accept: 'application/json' } }))
		expect(capturedInit?.headers).not.toHaveProperty('Authorization')
	})
})

