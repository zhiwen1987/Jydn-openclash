package mihomo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxReloadPayloadBytes  = 1 << 20
	maxReloadResponseBytes = 4096
	maxReloadTokenBytes    = 4096
	writeClientDebug       = "mihomo.WriteClient(scope=loopback_reload_only)"
)

// ReloadState describes an individual controller request, not deployment,
// persistence, readback, business health or successful rollback.
type ReloadState string

const (
	ReloadAcknowledged ReloadState = "acknowledged"
	ReloadRejected     ReloadState = "rejected"
	ReloadUnknown      ReloadState = "unknown"
)

// ReloadResult never includes the controller address, credentials, payload,
// response body or transport error. Dispatched means Do was invoked; it does
// not prove that bytes reached the controller or that configuration changed.
type ReloadResult struct {
	State      ReloadState `json:"state"`
	Dispatched bool        `json:"dispatched"`
	StatusCode int         `json:"statusCode"`
}

var (
	errWriteClientInput = errors.New("mihomo write client input rejected")
	errReloadUnsent     = errors.New("mihomo reload was not dispatched")
	errReloadRejected   = errors.New("mihomo reload was rejected")
	errReloadUnknown    = errors.New("mihomo reload outcome is unknown")
)

// WriteClient is a separate, deliberately narrow write capability. It only
// reloads a supplied configuration at a literal loopback HTTP controller.
// Approval, owned-target identity, backup and reconciliation belong to the
// lifecycle coordinator; constructing this client does not supply them.
type writeClientCore struct {
	endpoint   string
	token      string
	httpClient *http.Client
}
type WriteClient struct{ *writeClientCore }

var (
	_ fmt.Stringer   = WriteClient{}
	_ fmt.GoStringer = WriteClient{}
	_ json.Marshaler = WriteClient{}
	_ fmt.Formatter  = (*WriteClient)(nil)
)

// Value receivers also protect ordinary copied values from reflective debug
// formatting. These are capability labels, never readiness or authorization.
func (c WriteClient) String() string   { return writeClientDebug }
func (c WriteClient) GoString() string { return writeClientDebug }

func (c WriteClient) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"loopback_reload_only"}`), nil
}

// Ordinary verbs use fixed text; special unsupported struct formatting sees
// only the opaque core pointer. fmt handles a typed nil value receiver safely.
func (c WriteClient) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, writeClientDebug)
}

// NewWriteClient performs no I/O. Remote controllers, alternate transports,
// environment proxies and base paths require a separately reviewed capability.
func NewWriteClient(rawURL, token string, timeout time.Duration) (*WriteClient, error) {
	if len(rawURL) == 0 || len(rawURL) > 2048 || strings.TrimSpace(rawURL) != rawURL ||
		!strings.HasPrefix(rawURL, "http://") || strings.ContainsAny(rawURL, "?#") {
		return nil, errWriteClientInput
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil ||
		parsed.Opaque != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawFragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errWriteClientInput
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || len(port) == 0 || len(port) > 5 {
		return nil, errWriteClientInput
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || !ip.Unmap().IsLoopback() {
		return nil, errWriteClientInput
	}
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return nil, errWriteClientInput
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errWriteClientInput
	}
	if token == "" || len(token) > maxReloadTokenBytes || !utf8.ValidString(token) {
		return nil, errWriteClientInput
	}
	for _, character := range token {
		if unicode.IsControl(character) || unicode.IsSpace(character) || unicode.Is(unicode.Cf, character) {
			return nil, errWriteClientInput
		}
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if timeout > 30*time.Second {
		return nil, errWriteClientInput
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: 16 << 10,
		ResponseHeaderTimeout:  timeout,
	}
	endpoint := url.URL{Scheme: "http", Host: parsed.Host, Path: "/configs", RawQuery: "force=true"}
	return &WriteClient{writeClientCore: &writeClientCore{
		endpoint: endpoint.String(),
		token:    token,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}}, nil
}

// Reload makes one PUT attempt and never retries or initiates rollback.
// A 204 acknowledges only this request; all subsequent verification is separate.
func (c *WriteClient) Reload(ctx context.Context, payload []byte) (ReloadResult, error) {
	unsent := ReloadResult{State: ReloadRejected}
	if c == nil || c.writeClientCore == nil || c.httpClient == nil || ctx == nil || ctx.Err() != nil ||
		len(payload) == 0 || len(payload) > maxReloadPayloadBytes || !utf8.Valid(payload) {
		return unsent, errReloadUnsent
	}
	encoded, err := json.Marshal(struct {
		Payload string `json:"payload"`
		Path    string `json:"path"`
	}{Payload: string(payload), Path: ""})
	if err != nil {
		return unsent, errReloadUnsent
	}
	// A non-replayable reader and fresh, non-keepalive HTTP/1 connections keep
	// net/http's reused-connection retry path out of this write capability.
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.endpoint, io.NopCloser(bytes.NewReader(encoded)))
	if err != nil {
		return unsent, errReloadUnsent
	}
	req.ContentLength = int64(len(encoded))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if ctx.Err() != nil {
		return unsent, errReloadUnsent
	}
	result := ReloadResult{State: ReloadUnknown, Dispatched: true}
	response, err := c.httpClient.Do(req)
	if response != nil {
		result.StatusCode = response.StatusCode
	}
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return result, errReloadUnknown
	}
	if response == nil || response.Body == nil {
		return result, errReloadUnknown
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxReloadResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || ctx.Err() != nil || len(body) > maxReloadResponseBytes {
		return result, errReloadUnknown
	}
	if response.StatusCode == http.StatusNoContent {
		lengths := response.Header.Values("Content-Length")
		if len(body) != 0 || response.ContentLength < -1 || response.ContentLength > 0 || len(response.TransferEncoding) != 0 ||
			len(response.Header.Values("Transfer-Encoding")) != 0 ||
			(len(lengths) != 0 && (len(lengths) != 1 || lengths[0] != "0")) {
			return result, errReloadUnknown
		}
		result.State = ReloadAcknowledged
		return result, nil
	}
	if response.StatusCode >= 400 && response.StatusCode <= 499 {
		result.State = ReloadRejected
		return result, errReloadRejected
	}
	return result, errReloadUnknown
}
