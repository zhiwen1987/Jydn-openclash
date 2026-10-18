// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { APIError, getMihomoRuntime, isManagementTransportSecure } from './api'

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

