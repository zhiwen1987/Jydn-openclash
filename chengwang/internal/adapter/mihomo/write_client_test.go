package mihomo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type writeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f writeRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	defer r.Body.Close()
	return f(r)
}

type writeFaultBody struct {
	reader   io.Reader
	readErr  error
	closeErr error
}

func (b *writeFaultBody) Read(p []byte) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.reader.Read(p)
}

func (b *writeFaultBody) Close() error { return b.closeErr }

func newWriteTestClient(t *testing.T, address string) *WriteClient {
	t.Helper()
	client, err := NewWriteClient(address, "synthetic-control-token", time.Second)
	if err != nil {
		t.Fatal("valid isolated write client rejected")
	}
	return client
}

func writeEmptyResponse(status int) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}
}

func assertWriteOutcome(t *testing.T, result ReloadResult, err error, state ReloadState, dispatched bool, status int) {
	t.Helper()
	if result.State != state || result.Dispatched != dispatched || result.StatusCode != status || (err == nil) != (state == ReloadAcknowledged) {
		t.Fatalf("unexpected safe outcome: state=%s dispatched=%t status=%d errorPresent=%t", result.State, result.Dispatched, result.StatusCode, err != nil)
	}
}

func TestWriteClientRejectsNonLiteralOrExtendedControllerURLs(t *testing.T) {
	addresses := []string{
		"", " http://127.0.0.1:9090", "http://127.0.0.1:9090 ", "https://127.0.0.1:9090",
		"HTTP://127.0.0.1:9090", "http://localhost:9090", "http://example.invalid:9090", "http://10.0.0.1:9090",
		"http://0.0.0.0:9090", "http://[::]:9090", "http://[fe80::1%25lo]:9090", "http://127.0.0.1",
		"http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:-1", "http://127.0.0.1:",
		"http://::1:9090", "http://user:secret@127.0.0.1:9090", "http://127.0.0.1:9090/base",
		"http://127.0.0.1:9090/%2f", "http://127.0.0.1:9090/%2e", "http://127.0.0.1:9090?",
		"http://127.0.0.1:9090?x=1", "http://127.0.0.1:9090#", "http://127.0.0.1:9090#x",
		"http://2130706433:9090", "http://0177.0.0.1:9090", "unix:///tmp/controller",
	}
	for index, address := range addresses {
		if client, err := NewWriteClient(address, "synthetic-control-token", time.Second); err == nil || client != nil || err.Error() != errWriteClientInput.Error() {
			t.Fatalf("unsafe address accepted at case %d", index)
		}
	}
}

func TestWriteClientConstructorAcceptsOnlyLoopbackRootsWithoutIO(t *testing.T) {
	for _, address := range []string{"http://127.0.0.1:1", "http://127.0.0.2:65535/", "http://[::1]:9090", "http://[::ffff:127.0.0.1]:9090/"} {
		client, err := NewWriteClient(address, "synthetic-control-token", 0)
		if err != nil || client == nil || client.httpClient.Timeout != 5*time.Second {
			t.Fatal("valid literal root or default timeout rejected")
		}
	}
}

func TestWriteClientRejectsEmptyControlWhitespaceAndOversizedTokens(t *testing.T) {
	for _, token := range []string{"", " ", " leading", "trailing ", "a\r\nb", "a\tb", "a\x00b", "a\x7fb", "a\u0085b", "a\u200eb", string([]byte{0xff}), strings.Repeat("x", maxReloadTokenBytes+1)} {
		client, err := NewWriteClient("http://127.0.0.1:9090", token, time.Second)
		if client != nil || err == nil || err.Error() != errWriteClientInput.Error() {
			t.Fatal("invalid token was accepted or error was not fixed")
		}
	}
	if _, err := NewWriteClient("http://127.0.0.1:9090", strings.Repeat("x", maxReloadTokenBytes), time.Second); err != nil {
		t.Fatal("bounded valid token rejected")
	}
}

func TestWriteClientTimeoutIsDefaultedAndHardBounded(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		client, err := NewWriteClient("http://127.0.0.1:9090", "synthetic-control-token", timeout)
		if err != nil || client.httpClient.Timeout != 5*time.Second {
			t.Fatal("default timeout changed")
		}
	}
	client, err := NewWriteClient("http://127.0.0.1:9090", "synthetic-control-token", 30*time.Second)
	if err != nil || client.httpClient.Timeout != 30*time.Second {
		t.Fatal("maximum supported timeout rejected")
	}
	if client, err := NewWriteClient("http://127.0.0.1:9090", "synthetic-control-token", 30*time.Second+1); client != nil || err == nil {
		t.Fatal("unbounded timeout accepted")
	}
}

func TestWriteClientSendsExactlyOneAuthenticatedFixedPUTAndJSONPayload(t *testing.T) {
	var calls atomic.Int32
	payload := "mode: rule\n# 中文配置\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPut || r.URL.Path != "/configs" || r.URL.RawQuery != "force=true" || r.Header.Get("Authorization") != "Bearer synthetic-control-token" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Cookie") != "" {
			t.Error("fixed authenticated request contract changed")
		}
		var body map[string]string
		decoder := json.NewDecoder(r.Body)
		if decoder.Decode(&body) != nil || len(body) != 2 || body["payload"] != payload || body["path"] != "" || decoder.Decode(&struct{}{}) != io.EOF {
			t.Error("request payload envelope changed")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	result, err := newWriteTestClient(t, server.URL).Reload(context.Background(), []byte(payload))
	assertWriteOutcome(t, result, err, ReloadAcknowledged, true, 204)
	if calls.Load() != 1 {
		t.Fatal("reload did not issue exactly one PUT")
	}
}

func TestWriteClientInvalidPayloadNeverInvokesTransport(t *testing.T) {
	client := newWriteTestClient(t, "http://127.0.0.1:9090")
	var calls atomic.Int32
	client.httpClient.Transport = writeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return writeEmptyResponse(204), nil
	})
	for _, payload := range [][]byte{nil, {}, {0xff}, bytes.Repeat([]byte("x"), maxReloadPayloadBytes+1)} {
		result, err := client.Reload(context.Background(), payload)
		assertWriteOutcome(t, result, err, ReloadRejected, false, 0)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid payload reached transport")
	}
}

func TestWriteClientPayloadByteLimitAndUTF8BoundaryRemainUsable(t *testing.T) {
	client := newWriteTestClient(t, "http://127.0.0.1:9090")
	var calls atomic.Int32
	client.httpClient.Transport = writeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return writeEmptyResponse(204), nil
	})
	for _, payload := range [][]byte{[]byte("规则: 中文\n"), bytes.Repeat([]byte("x"), maxReloadPayloadBytes)} {
		result, err := client.Reload(context.Background(), payload)
		assertWriteOutcome(t, result, err, ReloadAcknowledged, true, 204)
	}
	if calls.Load() != 2 {
		t.Fatal("valid calls were retried or omitted")
	}
}

func TestWriteClientCanceledExpiredAndNilContextsStayUnsent(t *testing.T) {
	client := newWriteTestClient(t, "http://127.0.0.1:9090")
	var calls atomic.Int32
	client.httpClient.Transport = writeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return writeEmptyResponse(204), nil
	})
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, finish := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer finish()
	for _, ctx := range []context.Context{canceled, expired, nil} {
		result, err := client.Reload(ctx, []byte("mode: rule\n"))
		assertWriteOutcome(t, result, err, ReloadRejected, false, 0)
	}
	if calls.Load() != 0 {
		t.Fatal("already canceled request was dispatched")
	}
}

func TestWriteClientCancellationAfterDispatchIsUnknownWithoutRetry(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var first sync.Once
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		first.Do(func() { close(started) })
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	client := newWriteTestClient(t, server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		result ReloadResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := client.Reload(ctx, []byte("mode: rule\n"))
		done <- outcome{result, err}
	}()
	select {
	case <-started:
		cancel()
	case <-time.After(3 * time.Second):
		t.Fatal("isolated request did not start")
	}
	select {
	case value := <-done:
		assertWriteOutcome(t, value.result, value.err, ReloadUnknown, true, 0)
	case <-time.After(3 * time.Second):
		t.Fatal("canceled reload did not terminate")
	}
	if calls.Load() != 1 {
		t.Fatal("canceled write was repeated")
	}
	lateContext, lateCancel := context.WithCancel(context.Background())
	defer lateCancel()
	lateClient := newWriteTestClient(t, "http://127.0.0.1:9090")
	lateClient.httpClient.Transport = writeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		lateCancel()
		return writeEmptyResponse(204), nil
	})
	result, err := lateClient.Reload(lateContext, []byte("mode: rule\n"))
	assertWriteOutcome(t, result, err, ReloadUnknown, true, 204)
}

func TestWriteClientClientDeadlineIsUnknownAndTransportIsCalledOnce(t *testing.T) {
	client := newWriteTestClient(t, "http://127.0.0.1:9090")
	client.httpClient.Timeout = 10 * time.Millisecond
	var calls atomic.Int32
	client.httpClient.Transport = writeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	result, err := client.Reload(context.Background(), []byte("mode: rule\n"))
	assertWriteOutcome(t, result, err, ReloadUnknown, true, 0)
	if calls.Load() != 1 {
		t.Fatal("timeout was retried")
	}
}

func TestWriteClientRedirectsNeverForwardPayloadOrCredentials(t *testing.T) {
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(204)
	}))
	defer target.Close()
	for _, status := range []int{301, 302, 303, 307, 308} {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			http.Redirect(w, r, target.URL+"/untrusted", status)
		}))
		result, err := newWriteTestClient(t, server.URL).Reload(context.Background(), []byte("mode: rule\n"))
		server.Close()
		assertWriteOutcome(t, result, err, ReloadUnknown, true, status)
		if calls.Load() != 1 || forwarded.Load() != 0 {
			t.Fatal("redirect forwarded or repeated a controller write")
		}
	}
}

func TestWriteClientOnly204AcknowledgesAndOnlyComplete4xxRejects(t *testing.T) {
	for _, status := range []int{204, 400, 401, 403, 404, 409, 422, 429, 200, 201, 202, 304, 500, 503} {
		client := newWriteTestClient(t, "http://127.0.0.1:9090")
		client.httpClient.Transport = writeRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return writeEmptyResponse(status), nil
		})
		state := ReloadUnknown
		if status == 204 {
			state = ReloadAcknowledged
		} else if status >= 400 && status <= 499 {
			state = ReloadRejected
		}
		result, err := client.Reload(context.Background(), []byte("mode: rule\n"))
		assertWriteOutcome(t, result, err, state, true, status)
	}
}

func TestWriteClientResponseBodyLimitIsBoundedAndNeverExported(t *testing.T) {
	for _, size := range []int{maxReloadResponseBytes, maxReloadResponseBytes + 1} {
		client := newWriteTestClient(t, "http://127.0.0.1:9090")
		client.httpClient.Transport = writeRoundTripFunc(func(*http.Request) (*http.Response, error) {
			response := writeEmptyResponse(400)
			response.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", size)))
			return response, nil
		})
		state := ReloadRejected
		if size > maxReloadResponseBytes {
			state = ReloadUnknown
		}
		result, err := client.Reload(context.Background(), []byte("mode: rule\n"))
		assertWriteOutcome(t, result, err, state, true, 400)
	}
}

func TestWriteClientReadOrCloseFailureCannotAcknowledgeOrReject(t *testing.T) {
	for _, status := range []int{204, 400} {
		for _, readFailure := range []bool{true, false} {
			client := newWriteTestClient(t, "http://127.0.0.1:9090")
			client.httpClient.Transport = writeRoundTripFunc(func(*http.Request) (*http.Response, error) {
				body := &writeFaultBody{reader: strings.NewReader("")}
				if readFailure {
					body.readErr = errors.New("synthetic-private-body-error")
				} else {
					body.closeErr = errors.New("synthetic-private-close-error")
				}
				response := writeEmptyResponse(status)
				response.Body = body
				return response, nil
			})
			result, err := client.Reload(context.Background(), []byte("mode: rule\n"))
			assertWriteOutcome(t, result, err, ReloadUnknown, true, status)
			if strings.Contains(err.Error(), "private") {
				t.Fatal("response failure text escaped")
			}
		}
	}
}

func TestWriteClientObservable204BodyOrFramingAnomalyIsUnknown(t *testing.T) {
	for _, kind := range []string{"body", "length", "invalid_negative_length", "length_header", "duplicate_length", "transfer_encoding", "transfer_header"} {
		client := newWriteTestClient(t, "http://127.0.0.1:9090")
		client.httpClient.Transport = writeRoundTripFunc(func(*http.Request) (*http.Response, error) {
			response := writeEmptyResponse(204)
			switch kind {
			case "body":
				response.Body = io.NopCloser(strings.NewReader("unexpected"))
			case "length":
				response.ContentLength = 1
			case "invalid_negative_length":
				response.ContentLength = -2
			case "length_header":
				response.Header.Set("Content-Length", "1")
			case "duplicate_length":
				response.Header["Content-Length"] = []string{"0", "0"}
			case "transfer_encoding":
				response.TransferEncoding = []string{"chunked"}
			case "transfer_header":
				response.Header.Set("Transfer-Encoding", "chunked")
			}
			return response, nil
		})
		result, err := client.Reload(context.Background(), []byte("mode: rule\n"))
		assertWriteOutcome(t, result, err, ReloadUnknown, true, 204)
	}
}

func TestWriteClientTransportErrorIsUnknownRedactedAndNotRetried(t *testing.T) {
	client := newWriteTestClient(t, "http://127.0.0.1:9090")
	var calls atomic.Int32
	client.httpClient.Transport = writeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("http://private.invalid/token/payload/response")
	})
	result, err := client.Reload(context.Background(), []byte("mode: rule\n"))
	assertWriteOutcome(t, result, err, ReloadUnknown, true, 0)
	if calls.Load() != 1 || err.Error() != errReloadUnknown.Error() {
		t.Fatal("transport error was exposed or retried")
	}
}

func TestWriteClientDoesNotInheritAnyEnvironmentProxy(t *testing.T) {
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalls.Add(1)
		w.WriteHeader(500)
	}))
	defer proxy.Close()
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	var directCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directCalls.Add(1)
		w.WriteHeader(204)
	}))
	defer server.Close()
	client := newWriteTestClient(t, server.URL)
	transport := client.httpClient.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("environment proxy function installed")
	}
	result, err := client.Reload(context.Background(), []byte("mode: rule\n"))
	assertWriteOutcome(t, result, err, ReloadAcknowledged, true, 204)
	if directCalls.Load() != 1 || proxyCalls.Load() != 0 {
		t.Fatal("credential-bearing controller request reached a proxy")
	}
}

func TestWriteClientFreshTransportAndRequestHaveNoReplayMechanism(t *testing.T) {
	client := newWriteTestClient(t, "http://127.0.0.1:9090")
	transport := client.httpClient.Transport.(*http.Transport)
	if !transport.DisableKeepAlives || !transport.DisableCompression || transport.ForceAttemptHTTP2 || transport.MaxResponseHeaderBytes != 16<<10 {
		t.Fatal("fresh bounded transport contract changed")
	}
	client.httpClient.Transport = writeRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.GetBody != nil || r.Header.Get("Idempotency-Key") != "" || r.Header.Get("X-Idempotency-Key") != "" {
			t.Error("write became transport-replayable")
		}
		return writeEmptyResponse(204), nil
	})
	result, err := client.Reload(context.Background(), []byte("mode: rule\n"))
	assertWriteOutcome(t, result, err, ReloadAcknowledged, true, 204)
}

func TestWriteClientAbruptConnectionFailureDoesNotRepeatThePUT(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error("isolated HTTP hijack failed")
			return
		}
		_ = connection.Close()
	}))
	defer server.Close()
	result, err := newWriteTestClient(t, server.URL).Reload(context.Background(), []byte("mode: rule\n"))
	assertWriteOutcome(t, result, err, ReloadUnknown, true, 0)
	if calls.Load() != 1 {
		t.Fatal("abrupt failure repeated a fresh controller write")
	}
}

func TestWriteClientConcurrentCallsDoNotShareRequestOrOutcomeState(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(204)
	}))
	defer server.Close()
	client := newWriteTestClient(t, server.URL)
	type reply struct {
		result ReloadResult
		err    error
	}
	results := make(chan reply, 8)
	var group sync.WaitGroup
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := client.Reload(context.Background(), []byte("mode: rule\n"))
			results <- reply{result, err}
		}()
	}
	group.Wait()
	close(results)
	for value := range results {
		assertWriteOutcome(t, value.result, value.err, ReloadAcknowledged, true, 204)
	}
	if calls.Load() != 8 {
		t.Fatal("concurrent calls were lost or repeated")
	}
}

func TestWriteClientResultAndErrorsCannotDiscloseSecretBearingInputs(t *testing.T) {
	client := newWriteTestClient(t, "http://127.0.0.1:9090")
	copyOfClient := *client
	for _, view := range []any{client, copyOfClient, &copyOfClient} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if actual := fmt.Sprintf(verb, view); actual != writeClientDebug {
				t.Fatal("client debug output differs from fixed safe metadata")
			}
		}
		encoded, encodeErr := json.Marshal(view)
		if encodeErr != nil || string(encoded) != `{"scope":"loopback_reload_only"}` {
			t.Fatal("client JSON differs from fixed safe metadata")
		}
	}
	if copyOfClient.String() != writeClientDebug || copyOfClient.GoString() != writeClientDebug || client.String() != writeClientDebug || client.GoString() != writeClientDebug {
		t.Fatal("client string methods expose instance fields")
	}
	var absent *WriteClient
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if actual := fmt.Sprintf(verb, absent); actual != "<nil>" {
			t.Fatal("nil client debug representation is unsafe")
		}
	}
	nilJSON, nilErr := json.Marshal(absent)
	if nilErr != nil || string(nilJSON) != "null" {
		t.Fatal("nil client JSON representation changed")
	}
	client.httpClient.Transport = writeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		response := writeEmptyResponse(403)
		response.Body = io.NopCloser(strings.NewReader("synthetic-private-controller-response"))
		return response, nil
	})
	result, err := client.Reload(context.Background(), []byte("synthetic-private-config-payload"))
	assertWriteOutcome(t, result, err, ReloadRejected, true, 403)
	public, marshalErr := json.Marshal(result)
	if marshalErr != nil || string(public) != `{"state":"rejected","dispatched":true,"statusCode":403}` {
		t.Fatal("public result shape changed")
	}
	for _, private := range []string{"synthetic-control-token", "synthetic-private-controller-response", "synthetic-private-config-payload", "127.0.0.1", "http://"} {
		if strings.Contains(string(public)+err.Error(), private) {
			t.Fatal("private input escaped safe result")
		}
	}
}

func TestWriteClientUninitializedClientOrRequestConstructionFailureStaysUnsent(t *testing.T) {
	var missing *WriteClient
	result, err := missing.Reload(context.Background(), []byte("mode: rule\n"))
	assertWriteOutcome(t, result, err, ReloadRejected, false, 0)
	client := newWriteTestClient(t, "http://127.0.0.1:9090")
	client.endpoint = ":invalid-private-address"
	result, err = client.Reload(context.Background(), []byte("mode: rule\n"))
	assertWriteOutcome(t, result, err, ReloadRejected, false, 0)
	if strings.Contains(err.Error(), "private-address") {
		t.Fatal("request construction error escaped")
	}
}
