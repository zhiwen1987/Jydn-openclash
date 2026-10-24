//go:build linux && chengwang_mihomo_faults

package mihomo

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
)

const labReloadFaultDebug = "mihomo.LabReloadFaultHandle(scope=isolated_response_loss_only)"
const labReloadFaultSchema = "chengwang.mihomo-reload-response-loss-observation/v1"
const labReloadFaultEndpoint = "http://127.0.0.1:28412/configs?force=true"

var errLabReloadFault = errors.New("mihomo laboratory response loss unavailable")
var errLabReloadResponseLost = errors.New("mihomo laboratory response unavailable")
var processLabReloadFaultIssuer labReloadFaultIssuer

// LabReloadFaultObservation is instrumentation, never approval or proof of
// server payload application. Nil means the corresponding event was not seen.
type LabReloadFaultObservation struct {
	Schema              string  `json:"schema"`
	State               string  `json:"state"`
	Claimed             bool    `json:"claimed"`
	UnderlyingRoundTrips int     `json:"underlyingRoundTrips"`
	StatusCode          *int    `json:"statusCode"`
	BodyBytes           *int    `json:"bodyBytes"`
	EOFObserved         *bool   `json:"eofObserved"`
	CloseSucceeded      *bool   `json:"closeSucceeded"`
	Injected            bool    `json:"injected"`
	FailureCode         *string `json:"failureCode"`
}

type labReloadFaultIssuer struct {
	mu        sync.Mutex
	attempted bool
	issued    *labReloadFaultCore
}

type labReloadFaultCore struct {
	issuer *labReloadFaultIssuer
	nonce  [32]byte
	value  LabReloadFaultObservation
}

// The single private pointer also protects fmt's special-verb fallback from
// traversing nonce/state. This handle is process-local and has no JSON loader.
type LabReloadFaultHandle struct{ core *labReloadFaultCore }

var _ json.Marshaler = LabReloadFaultHandle{}

func (h LabReloadFaultHandle) String() string { return labReloadFaultDebug }
func (h LabReloadFaultHandle) GoString() string { return labReloadFaultDebug }
func (h LabReloadFaultHandle) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, labReloadFaultDebug)
}
func (h LabReloadFaultHandle) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"isolated_response_loss_only"}`), nil
}

// BeginLabReloadResponseLoss is compiled only for the isolated Linux fault
// experiment. The attempt is irrevocably spent before CSPRNG access. It takes
// no callback, URL, credentials, HTTP switch, reset or dispatch permission.
func BeginLabReloadResponseLoss() (*LabReloadFaultHandle, error) {
	return processLabReloadFaultIssuer.issue()
}

func (issuer *labReloadFaultIssuer) issue() (*LabReloadFaultHandle, error) {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if issuer.attempted {
		return nil, errLabReloadFault
	}
	issuer.attempted = true
	core := &labReloadFaultCore{issuer: issuer}
	if _, err := rand.Read(core.nonce[:]); err != nil || core.nonce == ([32]byte{}) {
		return nil, errLabReloadFault
	}
	core.value = LabReloadFaultObservation{Schema: labReloadFaultSchema, State: "ISSUED"}
	issuer.issued = core
	return &LabReloadFaultHandle{core: core}, nil
}

func labReloadFaultCopy(value LabReloadFaultObservation) LabReloadFaultObservation {
	if value.StatusCode != nil { v := *value.StatusCode; value.StatusCode = &v }
	if value.BodyBytes != nil { v := *value.BodyBytes; value.BodyBytes = &v }
	if value.EOFObserved != nil { v := *value.EOFObserved; value.EOFObserved = &v }
	if value.CloseSucceeded != nil { v := *value.CloseSucceeded; value.CloseSucceeded = &v }
	if value.FailureCode != nil { v := *value.FailureCode; value.FailureCode = &v }
	return value
}

func (h *LabReloadFaultHandle) Observe() (LabReloadFaultObservation, error) {
	if h == nil || h.core == nil || h.core.issuer == nil {
		return LabReloadFaultObservation{}, errLabReloadFault
	}
	issuer := h.core.issuer
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if !issuer.attempted || issuer.issued != h.core || h.core.nonce == ([32]byte{}) {
		return LabReloadFaultObservation{}, errLabReloadFault
	}
	return labReloadFaultCopy(h.core.value), nil
}

func wrapLabReloadTransport(transport *http.Transport) http.RoundTripper {
	processLabReloadFaultIssuer.mu.Lock()
	attempted := processLabReloadFaultIssuer.attempted
	processLabReloadFaultIssuer.mu.Unlock()
	if !attempted {
		return transport
	}
	return &labReloadFaultTransport{inner: transport, issuer: &processLabReloadFaultIssuer}
}

// Default construction always supplies its own real *http.Transport. Only
// same-package MODEL tests can assemble a private fake inner transport.
type labReloadFaultTransport struct {
	inner  http.RoundTripper
	issuer *labReloadFaultIssuer
}

func labReloadFaultMatches(request *http.Request) bool {
	return request != nil && request.URL != nil && request.Method == http.MethodPut &&
		request.URL.String() == labReloadFaultEndpoint && request.URL.User == nil &&
		request.URL.Opaque == "" && request.URL.RawPath == "" && request.URL.Fragment == "" &&
		request.URL.RawFragment == "" && !request.URL.ForceQuery &&
		(request.Host == "" || request.Host == "127.0.0.1:28412")
}

func labReloadFaultFraming(response *http.Response) bool {
	lengths := response.Header.Values("Content-Length")
	return response.ContentLength >= -1 && response.ContentLength <= 0 &&
		len(response.TransferEncoding) == 0 && len(response.Header.Values("Transfer-Encoding")) == 0 &&
		(len(lengths) == 0 || (len(lengths) == 1 && lengths[0] == "0"))
}

func (transport *labReloadFaultTransport) finish(core *labReloadFaultCore, state, code string,
	status *int, size *int, eof, closed *bool, injected bool) {
	transport.issuer.mu.Lock()
	defer transport.issuer.mu.Unlock()
	core.value.State = state
	core.value.StatusCode = status
	core.value.BodyBytes = size
	core.value.EOFObserved = eof
	core.value.CloseSucceeded = closed
	core.value.Injected = injected
	if code != "" { core.value.FailureCode = &code }
}

func (transport *labReloadFaultTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport == nil || transport.inner == nil || transport.issuer == nil || request == nil {
		return nil, errLabReloadFault
	}
	if !labReloadFaultMatches(request) {
		return transport.inner.RoundTrip(request)
	}
	issuer := transport.issuer
	issuer.mu.Lock()
	core := issuer.issued
	if !issuer.attempted || core == nil || core.issuer != issuer || core.value.State != "ISSUED" {
		issuer.mu.Unlock()
		return nil, errLabReloadFault
	}
	core.value.State = "CLAIMED"
	core.value.Claimed = true
	// This counter describes entry into the one underlying call, not receipt.
	core.value.UnderlyingRoundTrips++
	issuer.mu.Unlock()
	response, err := transport.inner.RoundTrip(request)
	var status *int
	if response != nil { v := response.StatusCode; status = &v }
	if err != nil {
		transport.finish(core, "PASSTHROUGH", "UNDERLYING_ERROR", status, nil, nil, nil, false)
		return response, err
	}
	if response == nil {
		transport.finish(core, "PASSTHROUGH", "NO_RESPONSE", nil, nil, nil, nil, false)
		return response, nil
	}
	code := ""
	if response.StatusCode != http.StatusNoContent { code = "STATUS_NOT_204" } else if response.Body == nil {
		code = "BODY_UNAVAILABLE"
	} else if !labReloadFaultFraming(response) { code = "FRAMING_REJECTED" } else if request.Context().Err() != nil {
		code = "CONTEXT_REJECTED"
	}
	if code != "" {
		transport.finish(core, "PASSTHROUGH", code, status, nil, nil, nil, false)
		return response, nil
	}
	// Actual consumption begins here. On any anomaly we retain the observed
	// facts and fail closed, rather than inventing a replay of a consumed body.
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxReloadResponseBytes+1))
	size := len(body)
	eof := readErr == nil && size < maxReloadResponseBytes+1
	closeErr := response.Body.Close()
	closed := closeErr == nil
	if readErr != nil { code = "READ_REJECTED" } else if size != 0 { code = "BODY_NOT_EMPTY" } else if closeErr != nil {
		code = "CLOSE_REJECTED"
	} else if request.Context().Err() != nil { code = "CONTEXT_REJECTED" }
	if code != "" {
		transport.finish(core, "FAILED", code, status, &size, &eof, &closed, false)
		return nil, errLabReloadResponseLost
	}
	transport.finish(core, "INJECTED", "", status, &size, &eof, &closed, true)
	return nil, errLabReloadResponseLost
}
