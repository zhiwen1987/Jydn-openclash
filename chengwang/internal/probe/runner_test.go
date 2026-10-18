package probe

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const fakePublicIP = "8.8.8.8"

func TestRunnerUsesPinnedIPAndStrictHTTPClient(t *testing.T) {
	var requests atomic.Int32
	var wrongProtocol atomic.Bool
	var seenSNI string
	var seenCookie string
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		if req.ProtoMajor != 1 {
			wrongProtocol.Store(true)
		}
		mu.Lock()
		seenSNI = req.TLS.ServerName
		seenCookie = req.Header.Get("Cookie")
		mu.Unlock()
		w.Header().Set("Set-Cookie", "probe-secret=must-not-return")
		_, _ = w.Write([]byte("service-ready private-response"))
	}))
	defer server.Close()

	runner, target, resolved, catalog, dialed := localRunnerFixture(t, server, "/ready", []int{200}, "service-ready", 1024)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	result := runner.runResolved(context.Background(), catalog, target.ID, resolved)
	if result.Conclusion != ConclusionAvailable || result.Outcome != OutcomePass || result.ErrorClass != "" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Layers.DNS.State != LayerAvailable || result.Layers.Connect.State != LayerAvailable || result.Layers.TLS.State != LayerAvailable || result.Layers.HTTP.State != LayerAvailable || result.Layers.Business.State != LayerAvailable {
		t.Fatalf("unexpected layers: %#v", result.Layers)
	}
	binding, err := bindCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if reason := validateSpoolResult(result, binding, result.CompletedAt, defaultFutureSkew, true, true); reason != "" {
		t.Fatalf("runner produced a result rejected by the spool contract: %s", reason)
	}
	if requests.Load() != 1 || wrongProtocol.Load() {
		t.Fatalf("requests=%d wrongProtocol=%v", requests.Load(), wrongProtocol.Load())
	}
	mu.Lock()
	gotSNI, gotCookie := seenSNI, seenCookie
	mu.Unlock()
	if gotSNI != target.Host {
		t.Fatalf("SNI = %q, want %q", gotSNI, target.Host)
	}
	if gotCookie != "" {
		t.Fatalf("unexpected cookie %q", gotCookie)
	}
	second := runner.runResolved(context.Background(), catalog, target.ID, resolved)
	if second.Outcome != OutcomePass {
		t.Fatalf("second result: %#v", second)
	}
	mu.Lock()
	gotCookie = seenCookie
	mu.Unlock()
	if gotCookie != "" {
		t.Fatalf("cookie jar retained server cookie: %q", gotCookie)
	}
	if len(*dialed) != 2 || (*dialed)[0] != resolved.DialAddress || (*dialed)[1] != resolved.DialAddress {
		t.Fatalf("dialed addresses = %#v, want two isolated dials to %q", *dialed, resolved.DialAddress)
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(raw)
	for _, prohibited := range []string{target.Host, fakePublicIP, "private-response", "probe-secret", "Set-Cookie", "/ready"} {
		if strings.Contains(serialized, prohibited) {
			t.Fatalf("serialized result leaked %q: %s", prohibited, serialized)
		}
	}
}

func TestRunnerClassifiesHTTPWithoutFollowingRedirect(t *testing.T) {
	var followed atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "/follow")
			w.WriteHeader(http.StatusFound)
		case "/follow":
			followed.Add(1)
			_, _ = w.Write([]byte("ready"))
		case "/restricted":
			w.WriteHeader(http.StatusForbidden)
		case "/limited":
			w.Header().Set("Retry-After", "75")
			w.WriteHeader(http.StatusTooManyRequests)
		case "/failure":
			w.WriteHeader(http.StatusBadGateway)
		case "/mismatch":
			_, _ = w.Write([]byte("pending"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tests := []struct {
		path       string
		statuses   []int
		marker     string
		conclusion Conclusion
		state      LayerState
		errorClass string
		retry      int64
	}{
		{"/redirect", []int{302}, "", ConclusionUnknown, LayerUnknown, "redirect_blocked", 0},
		{"/restricted", []int{403}, "", ConclusionRestricted, LayerRestricted, "restricted", 0},
		{"/limited", []int{429}, "", ConclusionRateLimited, LayerRateLimited, "rate_limited", 75},
		{"/failure", []int{502}, "", ConclusionUnknown, LayerUnknown, "service_failure", 0},
		{"/mismatch", []int{200}, "ready", ConclusionUnknown, LayerUnknown, "contract_mismatch", 0},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			runner, target, resolved, catalog, _ := localRunnerFixture(t, server, test.path, test.statuses, test.marker, 1024)
			result := runner.runResolved(context.Background(), catalog, target.ID, resolved)
			assertRunnerResultAccepted(t, catalog, result)
			if result.Conclusion != test.conclusion || result.Layers.Business.State != test.state || result.ErrorClass != test.errorClass || result.Layers.Business.RetryAfterSeconds != test.retry {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
	if followed.Load() != 0 {
		t.Fatalf("redirect target was contacted %d times", followed.Load())
	}
}

func TestRunnerBoundsResponseBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte(strings.Repeat("x", 65)))
	}))
	defer server.Close()
	runner, target, resolved, catalog, _ := localRunnerFixture(t, server, "/large", []int{200}, "", 64)
	result := runner.runResolved(context.Background(), catalog, target.ID, resolved)
	assertRunnerResultAccepted(t, catalog, result)
	if result.ErrorClass != "response_too_large" || result.ResponseBytes != 64 || result.ContentDigest != "" || result.Outcome != OutcomeIndeterminate {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestRunnerClassifiesTLSConnectAndTimeoutFailures(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/slow" {
			time.Sleep(500 * time.Millisecond)
		}
		_, _ = w.Write([]byte("ready"))
	}))
	defer server.Close()

	t.Run("tls", func(t *testing.T) {
		runner, target, resolved, catalog, _ := localRunnerFixture(t, server, "/ready", []int{200}, "ready", 1024)
		runner.rootCAs = nil
		result := runner.runResolved(context.Background(), catalog, target.ID, resolved)
		assertRunnerResultAccepted(t, catalog, result)
		if result.ErrorClass != "tls_failure" || result.Layers.Connect.State != LayerAvailable || result.Layers.TLS.State != LayerUnavailable {
			t.Fatalf("unexpected result: %#v", result)
		}
	})

	t.Run("connect", func(t *testing.T) {
		runner, target, resolved, catalog, _ := localRunnerFixture(t, server, "/ready", []int{200}, "ready", 1024)
		runner.dialContext = func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("synthetic dial failure")
		}
		result := runner.runResolved(context.Background(), catalog, target.ID, resolved)
		assertRunnerResultAccepted(t, catalog, result)
		if result.ErrorClass != "connect_failure" || result.Layers.Connect.State != LayerUnavailable {
			t.Fatalf("unexpected result: %#v", result)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		runner, target, resolved, catalog, _ := localRunnerFixture(t, server, "/slow", []int{200}, "ready", 1024)
		runner.timeout = 100 * time.Millisecond
		result := runner.runResolved(context.Background(), catalog, target.ID, resolved)
		assertRunnerResultAccepted(t, catalog, result)
		unavailableStages := 0
		for _, layer := range []LayerResult{result.Layers.Connect, result.Layers.TLS, result.Layers.HTTP} {
			if layer.State == LayerUnavailable {
				unavailableStages++
			}
		}
		if result.ErrorClass != "timeout" || result.Outcome != OutcomeFail || unavailableStages != 1 {
			t.Fatalf("unexpected result: %#v", result)
		}
	})
}

func TestRunnerConnectDeadlineWithCompletedTraceStaysAtConnectLayer(t *testing.T) {
	catalog := validCatalog()
	digest, err := DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalog.Digest = digest
	target := catalog.Probes[0]
	attempted := time.Unix(1_700_000_000, 0).UTC()
	completed := attempted.Add(100 * time.Millisecond)
	result := newUnknownResult(attempted)
	result.RunID = "connect-deadline"
	result.ProbeID = target.ID
	result.CatalogDigest = catalog.Digest
	result.AgentID = catalog.Agent.ID
	result.Independence = catalog.Agent.Independence
	result.PathID = target.PathID
	result.ExpiresAt = attempted.Add(time.Duration(target.TTLSeconds) * time.Second)
	result.Layers.DNS = layerResult(LayerAvailable, attempted, result.ExpiresAt, 0, "resolved_and_pinned")
	runner := &Runner{now: func() time.Time { return completed }}
	trace := traceSnapshot{connectStart: attempted, connectEnd: completed, connectDone: true, connectErr: context.DeadlineExceeded}
	result = runner.finishTransportError(result, trace, context.DeadlineExceeded, context.DeadlineExceeded)
	if result.Layers.Connect.State != LayerUnavailable || result.Layers.TLS.State != LayerUnknown {
		t.Fatalf("connect timeout was assigned to the wrong layer: %+v", result.Layers)
	}
	assertRunnerResultAccepted(t, catalog, result)
}

func TestRunnerRejectsUnvalidatedInputsBeforeDial(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ready")) }))
	defer server.Close()
	runner, target, resolved, catalog, dialed := localRunnerFixture(t, server, "/ready", []int{200}, "ready", 1024)

	tests := []struct {
		name     string
		catalog  Catalog
		targetID string
		resolved ResolvedTarget
		class    string
	}{
		{"digest mismatch", func() Catalog { c := catalog; c.Revision = "mutated"; return c }(), target.ID, resolved, "catalog_digest_mismatch"},
		{"not allowlisted", catalog, "missing-target", resolved, "target_not_allowlisted"},
		{"invalid target id", catalog, "https://secret.invalid/", resolved, "invalid_probe_id"},
		{"unsafe resolved address", catalog, target.ID, func() ResolvedTarget {
			r := resolved
			r.IP = netip.MustParseAddr("127.0.0.1")
			r.ValidatedIPs = []netip.Addr{r.IP}
			r.DialAddress = net.JoinHostPort(r.IP.String(), strconv.Itoa(int(r.Port)))
			return r
		}(), "invalid_resolved_target"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := len(*dialed)
			result := runner.runResolved(context.Background(), test.catalog, test.targetID, test.resolved)
			if result.ErrorClass != test.class || result.Outcome != OutcomeIndeterminate {
				t.Fatalf("unexpected result: %#v", result)
			}
			if len(*dialed) != before {
				t.Fatal("invalid input reached dialer")
			}
			if test.class == "invalid_probe_id" && result.ProbeID != "" {
				t.Fatalf("invalid target identifier was retained: %q", result.ProbeID)
			}
		})
	}
}

func TestRunnerResolveAndRunClassifiesDNS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ready")) }))
	defer server.Close()

	t.Run("success", func(t *testing.T) {
		runner, target, _, catalog, _ := localRunnerFixture(t, server, "/ready", []int{200}, "ready", 1024)
		resolver := runnerTestResolver{addresses: []netip.Addr{netip.MustParseAddr(fakePublicIP)}}
		result := runner.ResolveAndRun(context.Background(), catalog, target.ID, resolver)
		assertRunnerResultAccepted(t, catalog, result)
		if result.Outcome != OutcomePass || result.Layers.DNS.State != LayerAvailable {
			t.Fatalf("unexpected result: %#v", result)
		}
		if result.StageTimings.TotalMillis < result.StageTimings.DNSMillis {
			t.Fatalf("total timing %#v excludes DNS", result.StageTimings)
		}
	})

	t.Run("failure", func(t *testing.T) {
		runner, target, _, catalog, dialed := localRunnerFixture(t, server, "/ready", []int{200}, "ready", 1024)
		resolver := runnerTestResolver{lookupErr: errors.New("synthetic DNS failure")}
		result := runner.ResolveAndRun(context.Background(), catalog, target.ID, resolver)
		assertRunnerResultAccepted(t, catalog, result)
		if result.ErrorClass != "dns_failure" || result.Conclusion != ConclusionUnavailable || result.Layers.DNS.State != LayerUnavailable {
			t.Fatalf("unexpected result: %#v", result)
		}
		if len(*dialed) != 0 {
			t.Fatal("DNS failure reached dialer")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		runner, target, _, catalog, dialed := localRunnerFixture(t, server, "/ready", []int{200}, "ready", 1024)
		runner.timeout = 100 * time.Millisecond
		resolver := runnerTestResolver{block: true}
		result := runner.ResolveAndRun(context.Background(), catalog, target.ID, resolver)
		assertRunnerResultAccepted(t, catalog, result)
		if result.ErrorClass != "dns_timeout" || result.Layers.DNS.State != LayerUnavailable {
			t.Fatalf("unexpected result: %#v", result)
		}
		if len(*dialed) != 0 {
			t.Fatal("DNS timeout reached dialer")
		}
	})

	t.Run("canceled", func(t *testing.T) {
		runner, target, _, catalog, dialed := localRunnerFixture(t, server, "/ready", []int{200}, "ready", 1024)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		resolver := runnerTestResolver{block: true}
		result := runner.ResolveAndRun(ctx, catalog, target.ID, resolver)
		assertRunnerResultAccepted(t, catalog, result)
		if result.ErrorClass != "canceled" || result.Conclusion != ConclusionUnknown || result.Outcome != OutcomeIndeterminate || result.Layers.DNS.State != LayerUnknown {
			t.Fatalf("unexpected result: %#v", result)
		}
		if len(*dialed) != 0 {
			t.Fatal("canceled DNS probe reached dialer")
		}
	})
}

func localRunnerFixture(t *testing.T, server *httptest.Server, path string, statuses []int, marker string, maxBody int64) (*Runner, Target, ResolvedTarget, Catalog, *[]string) {
	t.Helper()
	serverAddress := server.Listener.Addr().String()
	certificate := server.Certificate()
	host := "example.com"
	if len(certificate.DNSNames) > 0 {
		host = strings.ToLower(certificate.DNSNames[0])
	}
	target := Target{
		ID: "business-check", PathID: "direct", Kind: ProbeHTTPS,
		Host: host, Port: 443, RequestPath: path, Method: http.MethodGet,
		ExpectedStatus: statuses, RequiredMarker: marker,
		IntervalSeconds: 30, TimeoutSeconds: 1, TTLSeconds: 60, MaxBodyBytes: maxBody,
	}
	catalog := Catalog{
		Schema: CatalogSchemaV1, Revision: "test-v1",
		Agent: AgentSpec{ID: "local-test", Independence: IndependenceP1, AdvisoryOnly: true},
		Paths: []Path{{ID: "direct", Kind: PathKindDirect}}, Probes: []Target{target},
	}
	digest, err := DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalog.Digest = digest
	public := netip.MustParseAddr(fakePublicIP)
	resolved := ResolvedTarget{
		TargetID: target.ID, Host: target.Host, CanonicalChain: []string{target.Host}, CanonicalName: target.Host, ServerName: target.Host, Port: target.Port,
		IP: public, ValidatedIPs: []netip.Addr{public}, DialAddress: net.JoinHostPort(public.String(), "443"),
	}
	runner, err := NewRunner(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	runner.rootCAs = pool
	dialed := &[]string{}
	runner.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		*dialed = append(*dialed, address)
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	}
	runner.newRunID = func() (string, error) { return fmt.Sprintf("run-%d", len(*dialed)+1), nil }
	return runner, target, resolved, catalog, dialed
}

func assertRunnerResultAccepted(t *testing.T, catalog Catalog, result ProbeResult) {
	t.Helper()
	binding, err := bindCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if reason := validateSpoolResult(result, binding, result.CompletedAt, defaultFutureSkew, true, true); reason != "" {
		t.Fatalf("runner produced a result rejected by the spool contract: %s; result=%+v", reason, result)
	}
}

type runnerTestResolver struct {
	addresses []netip.Addr
	lookupErr error
	block     bool
}

func (r runnerTestResolver) ResolveHost(ctx context.Context, host string) (DNSResolution, error) {
	if r.block {
		<-ctx.Done()
		return DNSResolution{}, ctx.Err()
	}
	if r.lookupErr != nil {
		return DNSResolution{}, r.lookupErr
	}
	return DNSResolution{CanonicalChain: []string{host}, Addresses: append([]netip.Addr(nil), r.addresses...)}, nil
}
