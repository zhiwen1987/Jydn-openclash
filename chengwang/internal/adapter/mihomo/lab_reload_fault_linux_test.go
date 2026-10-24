//go:build linux && chengwang_mihomo_faults

package mihomo

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// MODEL: only the actual private capsule/original Reload control flow is
// exercised. This fake inner transport is not a Mihomo/controller execution,
// and cannot be supplied through Begin or the default runtime constructor.
type labReloadFaultModelBody struct {
	reader *strings.Reader
	readError error
	closeError error
	cancel context.CancelFunc
	closed atomic.Int32
}

type labReloadFaultModelRoundTrip func(*http.Request) (*http.Response, error)
func (f labReloadFaultModelRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body != nil { defer request.Body.Close() }
	return f(request)
}

func (body *labReloadFaultModelBody) Read(buffer []byte) (int, error) {
	if body.cancel != nil { body.cancel() }
	if body.readError != nil { return 0, body.readError }
	return body.reader.Read(buffer)
}
func (body *labReloadFaultModelBody) Close() error {
	body.closed.Add(1)
	return body.closeError
}

func labReloadFaultModel(t *testing.T, inner http.RoundTripper) (*WriteClient, *LabReloadFaultHandle, *labReloadFaultIssuer) {
	t.Helper()
	issuer := &labReloadFaultIssuer{}
	handle, err := issuer.issue()
	if err != nil { t.Fatal("MODEL issue") }
	client, err := NewWriteClient("http://127.0.0.1:28412", "MODEL_private_controller_token", time.Second)
	if err != nil { t.Fatal("MODEL client") }
	client.httpClient.Transport = &labReloadFaultTransport{inner: inner, issuer: issuer}
	return client, handle, issuer
}

func labReloadFaultModelObserve(t *testing.T, handle *LabReloadFaultHandle) LabReloadFaultObservation {
	t.Helper()
	value, err := handle.Observe()
	if err != nil { t.Fatal("MODEL observation") }
	return value
}

func TestLabReloadFaultCapsuleModelBoundaries(t *testing.T) {
	t.Run("unarmed_global_preserves_original_concrete_transport", func(t *testing.T) {
		original := &http.Transport{}
		if wrapLabReloadTransport(original) != original { t.Fatal("MODEL unarmed transport changed") }
	})
	t.Run("actual_wrapper_and_original_reload_unknown_without_second_call", func(t *testing.T) {
		body := &labReloadFaultModelBody{reader: strings.NewReader("")}
		var calls atomic.Int32
		client, handle, issuer := labReloadFaultModel(t, labReloadFaultModelRoundTrip(func(request *http.Request) (*http.Response, error) {
			calls.Add(1)
			if request.URL.String() != labReloadFaultEndpoint || request.Method != http.MethodPut ||
				request.Header.Get("Authorization") != "Bearer MODEL_private_controller_token" {
				t.Fatal("MODEL request was altered")
			}
			return &http.Response{StatusCode: 204, Body: body, Header: http.Header{}, ContentLength: 0}, nil
		}))
		result, err := client.Reload(context.Background(), []byte("MODEL complete configuration"))
		assertWriteOutcome(t, result, err, ReloadUnknown, true, 0)
		if err.Error() != errReloadUnknown.Error() { t.Fatal("MODEL transport cause escaped original Reload") }
		value := labReloadFaultModelObserve(t, handle)
		if value.Schema != labReloadFaultSchema || value.State != "INJECTED" || !value.Claimed || !value.Injected ||
			value.UnderlyingRoundTrips != 1 || value.StatusCode == nil || *value.StatusCode != 204 ||
			value.BodyBytes == nil || *value.BodyBytes != 0 || value.EOFObserved == nil || !*value.EOFObserved ||
			value.CloseSucceeded == nil || !*value.CloseSucceeded || value.FailureCode != nil || calls.Load() != 1 || body.closed.Load() != 1 {
			t.Fatal("MODEL actual observations missing")
		}
		result, err = client.Reload(context.Background(), []byte("MODEL complete configuration"))
		assertWriteOutcome(t, result, err, ReloadUnknown, true, 0)
		if calls.Load() != 1 || body.closed.Load() != 1 { t.Fatal("MODEL fault replayed underlying transport") }
		if again, err := issuer.issue(); err == nil || again != nil { t.Fatal("MODEL issuer reset") }
		*value.StatusCode = 1; *value.BodyBytes = 42; *value.EOFObserved = false; *value.CloseSucceeded = false
		again := labReloadFaultModelObserve(t, handle)
		if *again.StatusCode != 204 || *again.BodyBytes != 0 || !*again.EOFObserved || !*again.CloseSucceeded {
			t.Fatal("MODEL observation aliases internal values")
		}
	})
	t.Run("non204_is_original_response_and_original_reload", func(t *testing.T) {
		for _, status := range []int{200, 302, 403, 429, 503} {
			t.Run(fmt.Sprint(status), func(t *testing.T) {
				body := &labReloadFaultModelBody{reader: strings.NewReader("MODEL response")}
				client, handle, _ := labReloadFaultModel(t, labReloadFaultModelRoundTrip(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: status, Body: body, Header: http.Header{}}, nil
				}))
				result, err := client.Reload(context.Background(), []byte("MODEL payload"))
				state := ReloadUnknown
				if status >= 400 && status <= 499 { state = ReloadRejected }
				assertWriteOutcome(t, result, err, state, true, status)
				value := labReloadFaultModelObserve(t, handle)
				if value.State != "PASSTHROUGH" || value.Injected || value.StatusCode == nil || *value.StatusCode != status ||
					value.BodyBytes != nil || value.EOFObserved != nil || value.CloseSucceeded != nil ||
					value.FailureCode == nil || *value.FailureCode != "STATUS_NOT_204" || body.closed.Load() != 1 {
					t.Fatal("MODEL non204 was consumed or invented")
				}
				*value.FailureCode = "MODEL caller modification"
				if *labReloadFaultModelObserve(t, handle).FailureCode != "STATUS_NOT_204" { t.Fatal("MODEL failure code aliases internal state") }
			})
		}
	})
	t.Run("framing_anomalies_delegate_without_consumption", func(t *testing.T) {
		for _, kind := range []string{"positive_length", "invalid_length", "transfer_encoding", "transfer_header", "length_header", "duplicate_length"} {
			t.Run(kind, func(t *testing.T) {
				body := &labReloadFaultModelBody{reader: strings.NewReader("")}
				response := &http.Response{StatusCode: 204, Body: body, Header: http.Header{}}
				switch kind {
				case "positive_length": response.ContentLength = 1
				case "invalid_length": response.ContentLength = -2
				case "transfer_encoding": response.TransferEncoding = []string{"chunked"}
				case "transfer_header": response.Header["Transfer-Encoding"] = []string{"chunked"}
				case "length_header": response.Header["Content-Length"] = []string{"00"}
				case "duplicate_length": response.Header["Content-Length"] = []string{"0", "0"}
				}
				client, handle, _ := labReloadFaultModel(t, labReloadFaultModelRoundTrip(func(*http.Request) (*http.Response, error) { return response, nil }))
				result, err := client.Reload(context.Background(), []byte("MODEL payload"))
				assertWriteOutcome(t, result, err, ReloadUnknown, true, 204)
				value := labReloadFaultModelObserve(t, handle)
				if value.Injected || value.State != "PASSTHROUGH" || value.BodyBytes != nil ||
					value.FailureCode == nil || *value.FailureCode != "FRAMING_REJECTED" || body.closed.Load() != 1 {
					t.Fatal("MODEL framing anomaly was injected")
				}
			})
		}
	})
	t.Run("consumed_anomalies_preserve_observation_and_cannot_pass", func(t *testing.T) {
		for _, kind := range []string{"read", "close", "nonempty", "limit", "cancel_during_read"} {
			t.Run(kind, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				body := &labReloadFaultModelBody{reader: strings.NewReader("")}
				wantCode := ""
				switch kind {
				case "read": body.readError = errors.New("MODEL private read error"); wantCode = "READ_REJECTED"
				case "close": body.closeError = errors.New("MODEL private close error"); wantCode = "CLOSE_REJECTED"
				case "nonempty": body.reader = strings.NewReader("x"); wantCode = "BODY_NOT_EMPTY"
				case "limit": body.reader = strings.NewReader(strings.Repeat("x", maxReloadResponseBytes+2)); wantCode = "BODY_NOT_EMPTY"
				case "cancel_during_read": body.cancel = cancel; wantCode = "CONTEXT_REJECTED"
				}
				client, handle, _ := labReloadFaultModel(t, labReloadFaultModelRoundTrip(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 204, Body: body, Header: http.Header{}}, nil
				}))
				result, err := client.Reload(ctx, []byte("MODEL payload"))
				assertWriteOutcome(t, result, err, ReloadUnknown, true, 0)
				value := labReloadFaultModelObserve(t, handle)
				if value.State != "FAILED" || value.Injected || value.UnderlyingRoundTrips != 1 || value.StatusCode == nil ||
					*value.StatusCode != 204 || value.BodyBytes == nil || value.EOFObserved == nil || value.CloseSucceeded == nil ||
					value.FailureCode == nil || *value.FailureCode != wantCode || body.closed.Load() != 1 {
					t.Fatal("MODEL consumed failure lost observed facts")
				}
				if kind == "read" && (*value.BodyBytes != 0 || *value.EOFObserved) { t.Fatal("MODEL read error became EOF") }
				if kind == "close" && (!*value.EOFObserved || *value.CloseSucceeded) { t.Fatal("MODEL close error became success") }
				if kind == "limit" && (*value.BodyBytes != maxReloadResponseBytes+1 || *value.EOFObserved) { t.Fatal("MODEL limit became natural EOF") }
			})
		}
	})
	t.Run("cancel_before_dispatch_does_not_claim", func(t *testing.T) {
		var calls atomic.Int32
		client, handle, _ := labReloadFaultModel(t, labReloadFaultModelRoundTrip(func(*http.Request) (*http.Response, error) {
			calls.Add(1); return nil, errors.New("MODEL unexpected request")
		}))
		ctx, cancel := context.WithCancel(context.Background()); cancel()
		result, err := client.Reload(ctx, []byte("MODEL payload"))
		assertWriteOutcome(t, result, err, ReloadRejected, false, 0)
		value := labReloadFaultModelObserve(t, handle)
		if value.State != "ISSUED" || value.Claimed || value.UnderlyingRoundTrips != 0 || value.StatusCode != nil || calls.Load() != 0 {
			t.Fatal("MODEL unsent cancellation became a transport observation")
		}
	})
	t.Run("cancel_after_headers_before_body_is_original_reload", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background()); defer cancel()
		body := &labReloadFaultModelBody{reader: strings.NewReader("")}
		client, handle, _ := labReloadFaultModel(t, labReloadFaultModelRoundTrip(func(*http.Request) (*http.Response, error) {
			cancel(); return &http.Response{StatusCode: 204, Body: body, Header: http.Header{}}, nil
		}))
		result, err := client.Reload(ctx, []byte("MODEL payload"))
		assertWriteOutcome(t, result, err, ReloadUnknown, true, 204)
		value := labReloadFaultModelObserve(t, handle)
		if value.Injected || value.State != "PASSTHROUGH" || value.BodyBytes != nil || value.FailureCode == nil ||
			*value.FailureCode != "CONTEXT_REJECTED" || body.closed.Load() != 1 { t.Fatal("MODEL canceled headers were injected") }
	})
	t.Run("underlying_error_and_nil_response_are_not_injected", func(t *testing.T) {
		for _, kind := range []string{"error", "nil_response", "nil_body"} {
			t.Run(kind, func(t *testing.T) {
				client, handle, _ := labReloadFaultModel(t, labReloadFaultModelRoundTrip(func(*http.Request) (*http.Response, error) {
					if kind == "error" { return nil, errors.New("MODEL private original error") }
					if kind == "nil_body" { return &http.Response{StatusCode: 204, Header: http.Header{}}, nil }
					return nil, nil
				}))
				result, err := client.Reload(context.Background(), []byte("MODEL payload"))
				value := labReloadFaultModelObserve(t, handle)
				if value.Injected || value.State != "PASSTHROUGH" || value.BodyBytes != nil || value.CloseSucceeded != nil ||
					value.UnderlyingRoundTrips != 1 { t.Fatal("MODEL missing response invented completion") }
				if kind != "nil_body" { assertWriteOutcome(t, result, err, ReloadUnknown, true, 0) } else {
					// http.Client may supply an empty body for an actual response.
					if value.StatusCode == nil || *value.StatusCode != 204 { t.Fatal("MODEL status disappeared") }
				}
			})
		}
	})
	t.Run("response_and_error_are_delegated_by_identity_without_body_read", func(t *testing.T) {
		issuer := &labReloadFaultIssuer{}
		handle, err := issuer.issue(); if err != nil { t.Fatal("MODEL issue") }
		body := &labReloadFaultModelBody{reader: strings.NewReader("MODEL original body")}
		original := &http.Response{StatusCode: 204, Header: http.Header{}, Body: body}
		cause := errors.New("MODEL original private transport error")
		transport := &labReloadFaultTransport{issuer: issuer, inner: labReloadFaultModelRoundTrip(func(*http.Request) (*http.Response, error) { return original, cause })}
		request, _ := http.NewRequest(http.MethodPut, labReloadFaultEndpoint, nil)
		response, returned := transport.RoundTrip(request)
		value := labReloadFaultModelObserve(t, handle)
		if response != original || returned != cause || body.closed.Load() != 0 || body.reader.Len() != len("MODEL original body") ||
			value.StatusCode == nil || *value.StatusCode != 204 || value.Injected || value.BodyBytes != nil ||
			value.FailureCode == nil || *value.FailureCode != "UNDERLYING_ERROR" { t.Fatal("MODEL original error/response was rewritten") }
		_ = body.Close()
	})
	t.Run("fixed_request_match_does_not_claim_other_targets", func(t *testing.T) {
		issuer := &labReloadFaultIssuer{}
		handle, err := issuer.issue(); if err != nil { t.Fatal("MODEL issue") }
		var calls atomic.Int32
		transport := &labReloadFaultTransport{issuer: issuer, inner: labReloadFaultModelRoundTrip(func(*http.Request) (*http.Response, error) {
			calls.Add(1); return &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody}, nil
		})}
		for _, address := range []string{"http://127.0.0.1:28413/configs?force=true", "http://127.0.0.1:28412/configs?force=false", labReloadFaultEndpoint + "#x", labReloadFaultEndpoint + "&x=1"} {
			request, err := http.NewRequest(http.MethodPut, address, nil); if err != nil { t.Fatal("MODEL request") }
			response, err := transport.RoundTrip(request); if err != nil || response.StatusCode != 200 { t.Fatal("MODEL delegated request changed") }
			_ = response.Body.Close()
		}
		request, _ := http.NewRequest(http.MethodGet, labReloadFaultEndpoint, nil)
		_, _ = transport.RoundTrip(request)
		value := labReloadFaultModelObserve(t, handle)
		if value.Claimed || value.State != "ISSUED" || value.UnderlyingRoundTrips != 0 || calls.Load() != 5 {
			t.Fatal("MODEL other target claimed the fault")
		}
	})
	t.Run("concurrent_claims_have_one_underlying_call", func(t *testing.T) {
		issuer := &labReloadFaultIssuer{}
		handle, err := issuer.issue(); if err != nil { t.Fatal("MODEL issue") }
		var calls atomic.Int32
		transport := &labReloadFaultTransport{issuer: issuer, inner: labReloadFaultModelRoundTrip(func(*http.Request) (*http.Response, error) {
			calls.Add(1); return &http.Response{StatusCode: 204, Header: http.Header{}, Body: http.NoBody}, nil
		})}
		var group sync.WaitGroup
		for i := 0; i < 8; i++ {
			group.Add(1)
			go func() { defer group.Done(); request, _ := http.NewRequest(http.MethodPut, labReloadFaultEndpoint, nil); _, _ = transport.RoundTrip(request) }()
		}
		group.Wait()
		value := labReloadFaultModelObserve(t, handle)
		if calls.Load() != 1 || value.UnderlyingRoundTrips != 1 || !value.Injected { t.Fatal("MODEL concurrent replay reached underlying transport") }
	})
	t.Run("spent_issue_attempt_and_foreign_handles_cannot_revive", func(t *testing.T) {
		spent := &labReloadFaultIssuer{attempted: true} // MODEL of a failed random attempt; not an actual CSPRNG failure.
		if h, err := spent.issue(); err == nil || h != nil { t.Fatal("MODEL failed attempt retried") }
		issuer := &labReloadFaultIssuer{}
		handle, err := issuer.issue(); if err != nil { t.Fatal("MODEL issue") }
		foreign := &LabReloadFaultHandle{core: &labReloadFaultCore{issuer: issuer, nonce: handle.core.nonce}}
		if _, err := foreign.Observe(); err == nil { t.Fatal("MODEL unissued clone accepted") }
		empty := LabReloadFaultHandle{}
		if _, err := empty.Observe(); err == nil { t.Fatal("MODEL empty handle accepted") }
		var decoded LabReloadFaultHandle
		if err := json.Unmarshal([]byte(`{"core":{"nonce":[1,2,3]}}`), &decoded); err != nil { t.Fatal("MODEL JSON") }
		if _, err := decoded.Observe(); err == nil { t.Fatal("MODEL JSON minted a handle") }
	})
	t.Run("debug_and_json_are_fixed_and_nonce_free", func(t *testing.T) {
		issuer := &labReloadFaultIssuer{}
		handle, err := issuer.issue(); if err != nil { t.Fatal("MODEL issue") }
		for _, value := range []any{handle, *handle} {
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x"} {
				if fmt.Sprintf(format, value) != labReloadFaultDebug { t.Fatal("MODEL debug traversed handle") }
			}
			for _, format := range []string{"%p", "%T"} {
				text := fmt.Sprintf(format, value)
				if strings.Contains(text, hex.EncodeToString(handle.core.nonce[:])) || strings.Contains(text, "issuer:") || strings.Contains(text, "nonce:") || strings.Contains(text, labReloadFaultEndpoint) {
					t.Fatal("MODEL special format traversed opaque core")
				}
			}
			encoded, err := json.Marshal(value)
			if err != nil || string(encoded) != `{"scope":"isolated_response_loss_only"}` { t.Fatal("MODEL JSON leaked state") }
		}
		var absent *LabReloadFaultHandle
		if _, err := absent.Observe(); err == nil { t.Fatal("MODEL nil handle accepted") }
		if fmt.Sprintf("%v", absent) != "<nil>" { t.Fatal("MODEL typed nil formatting") }
		encoded, err := json.Marshal(absent)
		if err != nil || string(encoded) != "null" { t.Fatal("MODEL nil JSON") }
		initial := labReloadFaultModelObserve(t, handle)
		if initial.StatusCode != nil || initial.BodyBytes != nil || initial.EOFObserved != nil || initial.CloseSucceeded != nil || initial.FailureCode != nil {
			t.Fatal("MODEL unobserved fields were filled")
		}
	})
}

var _ io.ReadCloser = (*labReloadFaultModelBody)(nil)
