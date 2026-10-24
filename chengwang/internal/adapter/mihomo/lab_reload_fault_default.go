//go:build !chengwang_mihomo_faults

package mihomo

import "net/http"

// The ordinary build retains the original concrete transport and behavior.
func wrapLabReloadTransport(transport *http.Transport) http.RoundTripper {
	return transport
}
