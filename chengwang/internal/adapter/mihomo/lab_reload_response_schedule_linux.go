//go:build linux && chengwang_mihomo_recovery_continuous_fault

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

const labReloadResponseScheduleDebug = "mihomo.LabReloadResponseLossSchedule(scope=fixed_loss_pass_loss)"
const labReloadResponseChildDebug = "mihomo.LabReloadResponseLossChild(scope=one_real_client)"
const labReloadResponseScheduleSchema = "chengwang.mihomo-reload-response-loss-schedule/v1"
const labReloadResponseScheduleEndpoint = "http://127.0.0.1:28412/configs?force=true"

var errLabReloadResponseSchedule = errors.New("mihomo laboratory response schedule unavailable")
var errLabScheduledResponseLost = errors.New("mihomo laboratory scheduled response unavailable")

type LabReloadResponseLossStepObservation struct {
	Sequence             int     `json:"sequence"`
	Action               string  `json:"action"`
	State                string  `json:"state"`
	UnderlyingRoundTrips int     `json:"underlyingRoundTrips"`
	StatusCode           *int    `json:"statusCode"`
	BodyBytes            *int    `json:"bodyBytes"`
	EOFObserved          *bool   `json:"eofObserved"`
	CloseSucceeded       *bool   `json:"closeSucceeded"`
	Injected             bool    `json:"injected"`
	FailureCode          *string `json:"failureCode"`
}

type LabReloadResponseLossScheduleObservation struct {
	Schema               string                                         `json:"schema"`
	State                string                                         `json:"state"`
	BoundChildren        int                                            `json:"boundChildren"`
	UnderlyingRoundTrips int                                            `json:"underlyingRoundTrips"`
	Injected             int                                            `json:"injected"`
	Steps                []LabReloadResponseLossStepObservation         `json:"steps"`
}

type labReloadResponseScheduleIssuer struct {
	mu        sync.Mutex
	attempted bool
	issued    *LabReloadResponseLossSchedule
}

type labReloadResponseScheduleCore struct {
	issuer        *labReloadResponseScheduleIssuer
	identity      *labReloadResponseScheduleCore
	nonce         [32]byte
	bound         map[*writeClientCore]*labReloadResponseChildCore
	children      [3]*labReloadResponseChildCore
	boundCount    int
	roundTrips    int
	injected      int
	closed        bool
	poisoned      bool
}

type LabReloadResponseLossSchedule struct{ core *labReloadResponseScheduleCore }

type labReloadResponseChildCore struct {
	root       *labReloadResponseScheduleCore
	identity   *labReloadResponseChildCore
	handle     *LabReloadResponseLossChild
	client     *writeClientCore
	nonce      [32]byte
	sequence   int
	action     string
	state      string
	underlying int
	status     *int
	bodyBytes  *int
	eof        *bool
	closed     *bool
	injected   bool
	failure    *string
}

type LabReloadResponseLossChild struct{ core *labReloadResponseChildCore }

var processLabReloadResponseScheduleIssuer labReloadResponseScheduleIssuer

func (LabReloadResponseLossSchedule) String() string   { return labReloadResponseScheduleDebug }
func (LabReloadResponseLossSchedule) GoString() string { return labReloadResponseScheduleDebug }
func (LabReloadResponseLossSchedule) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, labReloadResponseScheduleDebug)
}
func (LabReloadResponseLossSchedule) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"fixed_loss_pass_loss"}`), nil
}
func (*LabReloadResponseLossSchedule) UnmarshalJSON([]byte) error { return errLabReloadResponseSchedule }

func (LabReloadResponseLossChild) String() string   { return labReloadResponseChildDebug }
func (LabReloadResponseLossChild) GoString() string { return labReloadResponseChildDebug }
func (LabReloadResponseLossChild) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, labReloadResponseChildDebug)
}
func (LabReloadResponseLossChild) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"one_real_client"}`), nil
}
func (*LabReloadResponseLossChild) UnmarshalJSON([]byte) error { return errLabReloadResponseSchedule }

// BeginLabReloadResponseLossSchedule issues one process-local fixed schedule.
// It has no reset, seed, callback, URL, credential or caller-selected slot.
func BeginLabReloadResponseLossSchedule() (*LabReloadResponseLossSchedule, error) {
	i := &processLabReloadResponseScheduleIssuer
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.attempted {
		return nil, errLabReloadResponseSchedule
	}
	i.attempted = true
	core := &labReloadResponseScheduleCore{issuer: i, bound: map[*writeClientCore]*labReloadResponseChildCore{}}
	core.identity = core
	if _, err := rand.Read(core.nonce[:]); err != nil || core.nonce == ([32]byte{}) {
		return nil, errLabReloadResponseSchedule
	}
	h := &LabReloadResponseLossSchedule{core: core}
	i.issued = h
	return h, nil
}

func labReloadResponseScheduleValid(i *labReloadResponseScheduleIssuer, h *LabReloadResponseLossSchedule) bool {
	return i != nil && h != nil && h.core != nil && i.attempted && i.issued == h && h.core.issuer == i &&
		h.core.identity == h.core && h.core.nonce != ([32]byte{}) && h.core.bound != nil
}

// Bind signs the next child for this exact freshly-created WriteClient. The
// ordinal and LOSS/PASS action are internal; callers cannot select either.
func (h *LabReloadResponseLossSchedule) Bind(client *WriteClient) (*LabReloadResponseLossChild, error) {
	if h == nil || h.core == nil || h.core.issuer == nil {
		return nil, errLabReloadResponseSchedule
	}
	i := h.core.issuer
	i.mu.Lock()
	defer i.mu.Unlock()
	root := h.core
	if !labReloadResponseScheduleValid(i, h) || root.closed || root.poisoned || root.boundCount >= len(root.children) ||
		root.boundCount != root.roundTrips ||
		client == nil || client.writeClientCore == nil || client.httpClient == nil || client.httpClient.Transport == nil ||
		client.endpoint != labReloadResponseScheduleEndpoint || root.bound[client.writeClientCore] != nil {
		return nil, errLabReloadResponseSchedule
	}
	sequence := root.boundCount + 1
	action := "LOSS"
	if sequence == 2 {
		action = "PASS"
	}
	childCore := &labReloadResponseChildCore{root: root, client: client.writeClientCore, sequence: sequence, action: action, state: "BOUND"}
	childCore.identity = childCore
	if _, err := rand.Read(childCore.nonce[:]); err != nil || childCore.nonce == ([32]byte{}) {
		root.poisoned = true
		return nil, errLabReloadResponseSchedule
	}
	child := &LabReloadResponseLossChild{core: childCore}
	childCore.handle = child
	inner := client.httpClient.Transport
	client.httpClient.Transport = &labReloadResponseScheduledTransport{inner: inner, child: childCore}
	root.children[root.boundCount] = childCore
	root.bound[client.writeClientCore] = childCore
	root.boundCount++
	return child, nil
}

func (h *LabReloadResponseLossSchedule) Close() error {
	if h == nil || h.core == nil || h.core.issuer == nil {
		return errLabReloadResponseSchedule
	}
	i := h.core.issuer
	i.mu.Lock()
	defer i.mu.Unlock()
	if !labReloadResponseScheduleValid(i, h) {
		return errLabReloadResponseSchedule
	}
	h.core.closed = true
	return nil
}

func labReloadResponseCloneStep(core *labReloadResponseChildCore) LabReloadResponseLossStepObservation {
	v := LabReloadResponseLossStepObservation{Sequence: core.sequence, Action: core.action, State: core.state,
		UnderlyingRoundTrips: core.underlying, Injected: core.injected}
	if core.status != nil { n := *core.status; v.StatusCode = &n }
	if core.bodyBytes != nil { n := *core.bodyBytes; v.BodyBytes = &n }
	if core.eof != nil { b := *core.eof; v.EOFObserved = &b }
	if core.closed != nil { b := *core.closed; v.CloseSucceeded = &b }
	if core.failure != nil { s := *core.failure; v.FailureCode = &s }
	return v
}

func (h *LabReloadResponseLossSchedule) Observe() (LabReloadResponseLossScheduleObservation, error) {
	var zero LabReloadResponseLossScheduleObservation
	if h == nil || h.core == nil || h.core.issuer == nil {
		return zero, errLabReloadResponseSchedule
	}
	i := h.core.issuer
	i.mu.Lock()
	defer i.mu.Unlock()
	if !labReloadResponseScheduleValid(i, h) {
		return zero, errLabReloadResponseSchedule
	}
	root := h.core
	state := "ACTIVE"
	if root.poisoned { state = "POISONED" } else if root.closed { state = "CLOSED" } else if root.roundTrips == len(root.children) { state = "TERMINAL" }
	v := LabReloadResponseLossScheduleObservation{Schema: labReloadResponseScheduleSchema, State: state,
		BoundChildren: root.boundCount, UnderlyingRoundTrips: root.roundTrips, Injected: root.injected,
		Steps: []LabReloadResponseLossStepObservation{}}
	for _, child := range root.children {
		if child != nil {
			v.Steps = append(v.Steps, labReloadResponseCloneStep(child))
		}
	}
	return v, nil
}

func (h *LabReloadResponseLossChild) Observe() (LabReloadResponseLossStepObservation, error) {
	if h == nil || h.core == nil || h.core.root == nil || h.core.root.issuer == nil {
		return LabReloadResponseLossStepObservation{}, errLabReloadResponseSchedule
	}
	i := h.core.root.issuer
	i.mu.Lock()
	defer i.mu.Unlock()
	c := h.core
	if c.identity != c || c.handle != h || c.nonce == ([32]byte{}) || c.root.identity != c.root ||
		c.sequence < 1 || c.sequence > len(c.root.children) || c.root.children[c.sequence-1] != c {
		return LabReloadResponseLossStepObservation{}, errLabReloadResponseSchedule
	}
	return labReloadResponseCloneStep(c), nil
}

type labReloadResponseScheduledTransport struct {
	inner http.RoundTripper
	child *labReloadResponseChildCore
}

func labReloadResponseScheduleMatches(request *http.Request) bool {
	return request != nil && request.URL != nil && request.Method == http.MethodPut &&
		request.URL.String() == labReloadResponseScheduleEndpoint && request.URL.User == nil && request.URL.Opaque == "" &&
		request.URL.RawPath == "" && request.URL.Fragment == "" && request.URL.RawFragment == "" && !request.URL.ForceQuery &&
		(request.Host == "" || request.Host == "127.0.0.1:28412")
}

func labReloadResponseScheduleFraming(response *http.Response) bool {
	lengths := response.Header.Values("Content-Length")
	return response.ContentLength >= -1 && response.ContentLength <= 0 && len(response.TransferEncoding) == 0 &&
		len(response.Header.Values("Transfer-Encoding")) == 0 && (len(lengths) == 0 || (len(lengths) == 1 && lengths[0] == "0"))
}

func (t *labReloadResponseScheduledTransport) failLocked(code string) {
	t.child.state = "FAILED"
	t.child.root.poisoned = true
	if code != "" { v := code; t.child.failure = &v }
}

func (t *labReloadResponseScheduledTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t == nil || t.inner == nil || t.child == nil || t.child.root == nil || t.child.root.issuer == nil {
		return nil, errLabReloadResponseSchedule
	}
	i := t.child.root.issuer
	i.mu.Lock()
	c, root := t.child, t.child.root
	if !labReloadResponseScheduleMatches(request) || root.identity != root || root.closed || root.poisoned ||
		c.identity != c || c.handle == nil || c.client == nil || c.nonce == ([32]byte{}) || c.state != "BOUND" ||
		c.sequence != root.roundTrips+1 || root.children[c.sequence-1] != c {
		i.mu.Unlock()
		return nil, errLabReloadResponseSchedule
	}
	c.state = "CLAIMED"
	c.underlying++
	root.roundTrips++
	i.mu.Unlock()

	response, err := t.inner.RoundTrip(request)
	i.mu.Lock()
	defer i.mu.Unlock()
	if response != nil { status := response.StatusCode; c.status = &status }
	if c.action == "PASS" {
		c.state = "PASSTHROUGH"
		if err != nil { t.failLocked("UNDERLYING_ERROR") } else if response == nil { t.failLocked("NO_RESPONSE") }
		return response, err
	}
	if err != nil { t.failLocked("UNDERLYING_ERROR"); return response, err }
	if response == nil { t.failLocked("NO_RESPONSE"); return nil, nil }
	code := ""
	if response.StatusCode != http.StatusNoContent { code = "STATUS_NOT_204" } else if response.Body == nil { code = "BODY_UNAVAILABLE" } else if !labReloadResponseScheduleFraming(response) { code = "FRAMING_REJECTED" } else if request.Context().Err() != nil { code = "CONTEXT_REJECTED" }
	if code != "" { t.failLocked(code); return response, nil }
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxReloadResponseBytes+1))
	size := len(body)
	eof := readErr == nil && size < maxReloadResponseBytes+1
	closeErr := response.Body.Close()
	closed := closeErr == nil
	c.bodyBytes, c.eof, c.closed = &size, &eof, &closed
	if readErr != nil { code = "READ_REJECTED" } else if size != 0 { code = "BODY_NOT_EMPTY" } else if closeErr != nil { code = "CLOSE_REJECTED" } else if request.Context().Err() != nil { code = "CONTEXT_REJECTED" }
	if code != "" { t.failLocked(code); return nil, errLabScheduledResponseLost }
	c.state, c.injected = "INJECTED", true
	root.injected++
	return nil, errLabScheduledResponseLost
}

var _ json.Marshaler = LabReloadResponseLossSchedule{}
var _ json.Marshaler = LabReloadResponseLossChild{}
