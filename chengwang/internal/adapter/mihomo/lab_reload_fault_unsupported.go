//go:build !linux && chengwang_mihomo_faults

package mihomo

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

const labReloadFaultDebug = "mihomo.LabReloadFaultHandle(scope=isolated_response_loss_only)"

var errLabReloadFault = errors.New("mihomo laboratory response loss unavailable")

type LabReloadFaultObservation struct {
	Schema               string  `json:"schema"`
	State                string  `json:"state"`
	Claimed              bool    `json:"claimed"`
	UnderlyingRoundTrips int     `json:"underlyingRoundTrips"`
	StatusCode           *int    `json:"statusCode"`
	BodyBytes            *int    `json:"bodyBytes"`
	EOFObserved          *bool   `json:"eofObserved"`
	CloseSucceeded       *bool   `json:"closeSucceeded"`
	Injected             bool    `json:"injected"`
	FailureCode          *string `json:"failureCode"`
}

type labReloadFaultCore struct{}
type LabReloadFaultHandle struct{ core *labReloadFaultCore }

func (h LabReloadFaultHandle) String() string   { return labReloadFaultDebug }
func (h LabReloadFaultHandle) GoString() string { return labReloadFaultDebug }
func (h LabReloadFaultHandle) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, labReloadFaultDebug)
}
func (h LabReloadFaultHandle) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"isolated_response_loss_only"}`), nil
}
func BeginLabReloadResponseLoss() (*LabReloadFaultHandle, error) { return nil, errLabReloadFault }
func (h *LabReloadFaultHandle) Observe() (LabReloadFaultObservation, error) {
	return LabReloadFaultObservation{}, errLabReloadFault
}

type labReloadFaultUnsupportedTransport struct{}

func (labReloadFaultUnsupportedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errLabReloadFault
}
func wrapLabReloadTransport(*http.Transport) http.RoundTripper {
	return labReloadFaultUnsupportedTransport{}
}
