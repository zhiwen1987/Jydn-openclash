package subscription

// These helpers use a package-private dial seam and loopback TLS fixtures.
// They are not native-network-namespace, actual Internet or product-API proof.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"chengwang/internal/probe"
)

const fetchTestHost = "subscription.example"
const fetchTestSecret = "private-fetch-sentinel"

type fetchTestResolver func(context.Context, string) (probe.DNSResolution, error)

func (resolver fetchTestResolver) ResolveHost(ctx context.Context, host string) (probe.DNSResolution, error) {
	return resolver(ctx, host)
}

func fetchTestPolicy() SourcePolicy {
	return SourcePolicy{Scope: Scope{TenantID: "tenant-a", SiteID: "site-a", Environment: "isolated"},
		SourceID: "src_" + strings.Repeat("a", 32), URL: "https://" + fetchTestHost + "/subscription?token=" + fetchTestSecret,
		AllowedCNAMEs: []string{"edge.subscription.example"}}
}

func fetchTestDNS() probe.Resolver {
	return fetchTestResolver(func(_ context.Context, host string) (probe.DNSResolution, error) {
		if host != fetchTestHost {
			return probe.DNSResolution{}, errors.New(fetchTestSecret)
		}
		return probe.DNSResolution{CanonicalChain: []string{host, "edge.subscription.example"},
			Addresses: []netip.Addr{netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("2001:4860:4860::8888")}}, nil
	})
}

type fetchTestEndpoint struct {
	server   *httptest.Server
	roots    *x509.CertPool
	ca       *x509.Certificate
	dials    atomic.Int32
	requests atomic.Int32
}

func fetchTestCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate fixture key")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "private fetch fixture CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("create fixture CA")
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("parse fixture CA")
	}
	return key, certificate, der
}

func newFetchTest(t *testing.T, certHost string, handler http.HandlerFunc) (*Fetcher, *fetchTestEndpoint) {
	t.Helper()
	if certHost == "" {
		certHost = fetchTestHost
	}
	caKey, ca, caDER := fetchTestCA(t)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate fixture leaf key")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: certHost}, DNSNames: []string{certHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("create fixture leaf")
	}
	endpoint := &fetchTestEndpoint{roots: x509.NewCertPool(), ca: ca}
	endpoint.roots.AddCert(ca)
	endpoint.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoint.requests.Add(1)
		handler(w, r)
	}))
	endpoint.server.TLS = &tls.Config{MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}}
	endpoint.server.EnableHTTP2 = false
	endpoint.server.StartTLS()
	t.Cleanup(endpoint.server.Close)
	fetcher, err := NewFetcher(fetchTestPolicy(), FetchConfig{Resolver: fetchTestDNS(), RootCAs: endpoint.roots})
	if err != nil {
		t.Fatal("construct fixture fetcher")
	}
	fetcher.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		endpoint.dials.Add(1)
		if network != "tcp" || address != "8.8.4.4:443" {
			return nil, errors.New(fetchTestSecret)
		}
		dialer := net.Dialer{}
		return dialer.DialContext(ctx, "tcp", endpoint.server.Listener.Addr().String())
	}
	return fetcher, endpoint
}

func fetchTestCode(t *testing.T, err error, expected Code) {
	t.Helper()
	var failure *Failure
	if !errors.As(err, &failure) || failure.Code != expected {
		t.Fatalf("expected closed failure code %s", expected)
	}
	encoded, encodeErr := json.Marshal(failure)
	if encodeErr != nil || bytes.Contains(encoded, []byte(fetchTestSecret)) || strings.Contains(err.Error(), fetchTestSecret) {
		t.Fatal("failure exposed private input")
	}
}

func TestFetchPolicyRejectsUnsafeExactURLs(t *testing.T) {
	for _, raw := range []string{"http://subscription.example/", "https://user:pass@subscription.example/",
		"https://subscription.example/#fragment", "https://subscription.example/#", "https://subscription.example:444/",
		"https://subscription.example:0443/", "https://subscription.example:/", "https://subscription.example./",
		"https://SUBSCRIPTION.example/", "https://127.0.0.1/", "https://subscription.example/a%2Fb",
		"https://subscription.example/a%20b", "https://subscription.example/a/../b", "https://subscription.example//b",
		"https://subscription.example/?token=%0D%0Asecret", "https://subscription.example/?token=%252F",
		"https://subscription.example/?token=%2f", "https://subscription.example/?token=%GG",
		"https://subscription.example/?", "https://subscription.example/\\evil", " https://subscription.example/",
		"https://subscription.example/\nsecret", "https://subscription.example/" + strings.Repeat("x", MaxScalarBytes)} {
		policy := fetchTestPolicy()
		policy.URL = raw
		_, err := NewFetcher(policy, FetchConfig{Resolver: fetchTestDNS()})
		fetchTestCode(t, err, CodeFetchPolicy)
	}
	policy := fetchTestPolicy()
	policy.URL = "https://subscription.example:443/sub?token=a%2Bb%2Fc"
	if _, err := NewFetcher(policy, FetchConfig{Resolver: fetchTestDNS()}); err != nil {
		t.Fatal("canonical private query rejected")
	}
}

func TestFetcherRequiresTrustedResolverAndScope(t *testing.T) {
	for _, mutate := range []func(*SourcePolicy){func(p *SourcePolicy) { p.Scope = Scope{} },
		func(p *SourcePolicy) { p.SourceID = "other" }, func(p *SourcePolicy) { p.AllowedCNAMEs = []string{"*"} }} {
		policy := fetchTestPolicy()
		mutate(&policy)
		_, err := NewFetcher(policy, FetchConfig{Resolver: fetchTestDNS()})
		fetchTestCode(t, err, CodeFetchPolicy)
	}
	for _, resolver := range []probe.Resolver{nil, fetchTestResolver(nil)} {
		_, err := NewFetcher(fetchTestPolicy(), FetchConfig{Resolver: resolver})
		fetchTestCode(t, err, CodeFetchPolicy)
	}
	var nilFetcher *Fetcher
	_, err := nilFetcher.Fetch(context.Background())
	fetchTestCode(t, err, CodeFetchPolicy)
	_, err = (&Fetcher{}).Fetch(context.Background())
	fetchTestCode(t, err, CodeFetchPolicy)
}

func TestFetchPinsCompleteSnapshotAndNormalTLS(t *testing.T) {
	fetcher, endpoint := newFetchTest(t, "", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.ServerName != fetchTestHost || r.Host != fetchTestHost || r.URL.RawQuery != "token="+fetchTestSecret {
			t.Error("fixed identity or exact private query changed")
		}
		_, _ = io.WriteString(w, "private subscription bytes")
	})
	result, err := fetcher.Fetch(context.Background())
	if err != nil || string(result.Content) != "private subscription bytes" || result.ResponseBytes != len(result.Content) ||
		result.Scope != fetchTestPolicy().Scope || result.SourceID != fetchTestPolicy().SourceID ||
		result.AttemptedAt.IsZero() || result.CompletedAt.Before(result.AttemptedAt) {
		t.Fatal("normal TLS private-byte fetch failed")
	}
	if endpoint.dials.Load() != 1 || endpoint.requests.Load() != 1 {
		t.Fatal("fetch did not use exactly one pinned connection")
	}
}

func TestFetchRejectsMixedAndUnsafeDNSBeforeDial(t *testing.T) {
	for _, addresses := range [][]netip.Addr{
		{netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("fc00::1")},
		{netip.MustParseAddr("169.254.169.254")}, {netip.MustParseAddr("::ffff:8.8.4.4")},
		{netip.MustParseAddr("192.0.2.1")}, {netip.Addr{}}, {},
	} {
		resolver := fetchTestResolver(func(context.Context, string) (probe.DNSResolution, error) {
			return probe.DNSResolution{CanonicalChain: []string{fetchTestHost}, Addresses: addresses}, nil
		})
		fetcher, err := NewFetcher(fetchTestPolicy(), FetchConfig{Resolver: resolver})
		if err != nil {
			t.Fatal("construct DNS-negative fixture")
		}
		var calls int
		fetcher.dialContext = func(context.Context, string, string) (net.Conn, error) {
			calls++
			return nil, errors.New(fetchTestSecret)
		}
		_, err = fetcher.Fetch(context.Background())
		fetchTestCode(t, err, CodeFetchPolicy)
		if calls != 0 {
			t.Fatal("unsafe DNS reached dial")
		}
	}
}

func TestFetchRejectsIncompleteUnapprovedCNAMEChains(t *testing.T) {
	for _, chain := range [][]string{nil, {"edge.subscription.example"}, {fetchTestHost, "unapproved.example"},
		{fetchTestHost, "edge.subscription.example", fetchTestHost}} {
		resolver := fetchTestResolver(func(context.Context, string) (probe.DNSResolution, error) {
			return probe.DNSResolution{CanonicalChain: chain, Addresses: []netip.Addr{netip.MustParseAddr("8.8.4.4")}}, nil
		})
		fetcher, err := NewFetcher(fetchTestPolicy(), FetchConfig{Resolver: resolver})
		if err != nil {
			t.Fatal("construct chain-negative fixture")
		}
		_, err = fetcher.Fetch(context.Background())
		fetchTestCode(t, err, CodeFetchPolicy)
	}
}

func TestFetchRejectsTLSMismatchAndUntrustedRoots(t *testing.T) {
	for _, wrongName := range []bool{true, false} {
		host := ""
		if wrongName {
			host = "wrong.subscription.example"
		}
		fetcher, endpoint := newFetchTest(t, host, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "unused") })
		if !wrongName {
			fetcher.rootCAs = x509.NewCertPool()
		}
		_, err := fetcher.Fetch(context.Background())
		fetchTestCode(t, err, CodeFetchUnavailable)
		if endpoint.requests.Load() != 0 {
			t.Fatal("unverified TLS reached HTTP handler")
		}
	}
}

func TestFetchRejectsRedirectWithoutFollowing(t *testing.T) {
	fetcher, endpoint := newFetchTest(t, "", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://other.example/"+fetchTestSecret)
		w.WriteHeader(http.StatusFound)
	})
	_, err := fetcher.Fetch(context.Background())
	fetchTestCode(t, err, CodeFetchHTTP)
	if endpoint.requests.Load() != 1 || endpoint.dials.Load() != 1 {
		t.Fatal("redirect caused a second request")
	}
}

func TestFetchRejectsHTTPStatusesAndRateLimit(t *testing.T) {
	for _, status := range []int{201, 204, 301, 401, 403, 404, 429, 500, 503} {
		fetcher, endpoint := newFetchTest(t, "", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", fetchTestSecret)
			w.WriteHeader(status)
			_, _ = io.WriteString(w, fetchTestSecret)
		})
		_, err := fetcher.Fetch(context.Background())
		code := CodeFetchHTTP
		if status == 429 {
			code = CodeFetchRateLimited
		}
		fetchTestCode(t, err, code)
		if endpoint.requests.Load() != 1 {
			t.Fatal("HTTP failure was retried")
		}
	}
}

func TestFetchRejectsEncodedAndCookieResponses(t *testing.T) {
	for _, headers := range []http.Header{{"Content-Encoding": {"gzip"}}, {"Content-Encoding": {"br"}},
		{"Content-Encoding": {"deflate"}}, {"Content-Encoding": {"identity", "identity"}}, {"Set-Cookie": {"private=" + fetchTestSecret}}} {
		fetcher, _ := newFetchTest(t, "", func(w http.ResponseWriter, _ *http.Request) {
			for name, values := range headers {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}
			_, _ = io.WriteString(w, fetchTestSecret)
		})
		_, err := fetcher.Fetch(context.Background())
		fetchTestCode(t, err, CodeFetchHTTP)
	}
	fetcher, _ := newFetchTest(t, "", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "identity")
		_, _ = io.WriteString(w, "ok")
	})
	if _, err := fetcher.Fetch(context.Background()); err != nil {
		t.Fatal("identity content encoding rejected")
	}
}

func TestFetchEnforcesBodyBudgetAndTruncation(t *testing.T) {
	for _, size := range []int{1, MaxInputBytes, MaxInputBytes + 1} {
		fetcher, _ := newFetchTest(t, "", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(bytes.Repeat([]byte("x"), size)) })
		result, err := fetcher.Fetch(context.Background())
		if size > MaxInputBytes {
			fetchTestCode(t, err, CodeInputLimit)
		} else if err != nil || len(result.Content) != size {
			t.Fatal("bounded body result mismatch")
		}
	}
	fetcher, _ := newFetchTest(t, "", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "short")
	})
	_, err := fetcher.Fetch(context.Background())
	fetchTestCode(t, err, CodeFetchUnavailable)
	fetcher, _ = newFetchTest(t, "", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	_, err = fetcher.Fetch(context.Background())
	fetchTestCode(t, err, CodeEmpty)
	fetcher, _ = newFetchTest(t, "", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(MaxInputBytes+1))
		w.WriteHeader(http.StatusOK)
	})
	_, err = fetcher.Fetch(context.Background())
	fetchTestCode(t, err, CodeInputLimit)
}

func TestFetchEnforcesHeaderBudget(t *testing.T) {
	fetcher, _ := newFetchTest(t, "", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Private", strings.Repeat(fetchTestSecret, fetchMaxHeaderBytes/len(fetchTestSecret)+1))
		_, _ = io.WriteString(w, "ok")
	})
	_, err := fetcher.Fetch(context.Background())
	fetchTestCode(t, err, CodeFetchUnavailable)
}

func TestFetchUsesFixedTimeoutBudgets(t *testing.T) {
	if fetchConnectTimeout != 3*time.Second || fetchTLSTimeout != 5*time.Second || fetchHeaderTimeout != 5*time.Second || fetchTotalTimeout != 15*time.Second {
		t.Fatal("fixed deadline contract changed")
	}
	fetcher, err := NewFetcher(fetchTestPolicy(), FetchConfig{Resolver: fetchTestDNS()})
	if err != nil {
		t.Fatal("construct deadline fixture")
	}
	resolved, err := probe.ResolveAndPin(context.Background(), fetchTestDNS(), fetcher.target)
	if err != nil {
		t.Fatal("prepare fixed pin")
	}
	transport := fetcher.transport(resolved)
	if transport.TLSHandshakeTimeout != 5*time.Second || transport.ResponseHeaderTimeout != 5*time.Second || transport.MaxResponseHeaderBytes != fetchMaxHeaderBytes ||
		transport.Proxy != nil || !transport.DisableCompression || !transport.DisableKeepAlives || transport.ForceAttemptHTTP2 {
		t.Fatal("unsafe transport budgets")
	}
	fetcher.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 3*time.Second || time.Until(deadline) <= 0 {
			t.Error("connect deadline absent")
		}
		return nil, errors.New(fetchTestSecret)
	}
	_, _ = transport.DialContext(context.Background(), "tcp", fetchTestHost+":443")
	var observed bool
	fetcher.resolver = fetchTestResolver(func(ctx context.Context, _ string) (probe.DNSResolution, error) {
		deadline, ok := ctx.Deadline()
		observed = ok && time.Until(deadline) <= 15*time.Second && time.Until(deadline) > 0
		return probe.DNSResolution{}, errors.New(fetchTestSecret)
	})
	_, _ = fetcher.Fetch(context.Background())
	if !observed {
		t.Fatal("DNS was outside total deadline")
	}
}

func TestFetchHonorsContextCancellationAcrossPhases(t *testing.T) {
	for _, phase := range []string{"dns", "dial", "tls", "header", "body"} {
		entered := make(chan struct{})
		var fetcher *Fetcher
		if phase == "header" || phase == "body" {
			fetcher, _ = newFetchTest(t, "", func(w http.ResponseWriter, r *http.Request) {
				if phase == "body" {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
				}
				close(entered)
				<-r.Context().Done()
			})
		} else {
			var err error
			fetcher, err = NewFetcher(fetchTestPolicy(), FetchConfig{Resolver: fetchTestDNS()})
			if err != nil {
				t.Fatal("construct cancellation fixture")
			}
			if phase == "dns" {
				fetcher.resolver = fetchTestResolver(func(ctx context.Context, _ string) (probe.DNSResolution, error) {
					close(entered)
					<-ctx.Done()
					return probe.DNSResolution{}, ctx.Err()
				})
			}
			if phase == "dial" {
				fetcher.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
					close(entered)
					<-ctx.Done()
					return nil, ctx.Err()
				}
			}
			if phase == "tls" {
				client, peer := net.Pipe()
				defer peer.Close()
				fetcher.dialContext = func(context.Context, string, string) (net.Conn, error) { return client, nil }
				go func() {
					var first [1]byte
					if _, err := peer.Read(first[:]); err == nil {
						close(entered)
					}
				}()
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		finished := make(chan error, 1)
		go func() { _, err := fetcher.Fetch(ctx); finished <- err }()
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			cancel()
			t.Fatal("cancellation phase was never reached")
		}
		cancel()
		select {
		case err := <-finished:
			fetchTestCode(t, err, CodeFetchUnavailable)
		case <-time.After(3 * time.Second):
			t.Fatal("cancellation did not join")
		}
	}
}

func TestFetchIgnoresEnvironmentProxyAndSendsNoCookies(t *testing.T) {
	for _, name := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy"} {
		t.Setenv(name, "http://127.0.0.1:1/"+fetchTestSecret)
	}
	t.Setenv("NO_PROXY", "")
	fetcher, endpoint := newFetchTest(t, "", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("request sent forbidden ambient headers")
		}
		_, _ = io.WriteString(w, "ok")
	})
	if _, err := fetcher.Fetch(context.Background()); err != nil {
		t.Fatal("ambient proxy affected fixed direct transport")
	}
	if endpoint.requests.Load() != 1 {
		t.Fatal("fixed request missing")
	}
}

func TestFetchPolicyAndResultsDoNotSerializePrivateBytes(t *testing.T) {
	fetcher, _ := newFetchTest(t, "", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, fetchTestSecret) })
	result, err := fetcher.Fetch(context.Background())
	if err != nil {
		t.Fatal("fetch privacy fixture")
	}
	config := FetchConfig{Resolver: struct {
		probe.Resolver
		Secret string
	}{fetchTestDNS(), fetchTestSecret}, RootCAs: fetcher.rootCAs}
	for _, value := range []any{fetchTestPolicy(), result, fetcher, *fetcher, config, &config} {
		encoded, err := json.Marshal(value)
		if err != nil || bytes.Contains(encoded, []byte(fetchTestSecret)) || bytes.Contains(encoded, []byte("subscription.example")) {
			t.Fatal("JSON exported private fetch data")
		}
	}
	for _, value := range []any{fetchTestPolicy(), result, fetcher, *fetcher, config, &config} {
		if strings.Contains(fmt.Sprintf("%+v %#v", value, value), fetchTestSecret) {
			t.Fatal("formatting exported private fetch data")
		}
	}
}

func TestFetchErrorsNeverExposeSecretSentinel(t *testing.T) {
	fetcher, err := NewFetcher(fetchTestPolicy(), FetchConfig{Resolver: fetchTestResolver(func(context.Context, string) (probe.DNSResolution, error) {
		return probe.DNSResolution{}, errors.New("URL/header/body/" + fetchTestSecret)
	})})
	if err != nil {
		t.Fatal("construct error privacy fixture")
	}
	_, err = fetcher.Fetch(context.Background())
	fetchTestCode(t, err, CodeFetchUnavailable)
	fetcher.resolver = fetchTestDNS()
	fetcher.dialContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New(fetchTestSecret) }
	_, err = fetcher.Fetch(context.Background())
	fetchTestCode(t, err, CodeFetchUnavailable)
}

func TestFetchDoesNotRetryOrFetchNestedProviders(t *testing.T) {
	body := "proxy-providers:\n  private:\n    url: https://other.example/" + fetchTestSecret + "\n"
	fetcher, endpoint := newFetchTest(t, "", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
	result, err := fetcher.Fetch(context.Background())
	if err != nil || string(result.Content) != body || endpoint.requests.Load() != 1 || endpoint.dials.Load() != 1 {
		t.Fatal("fetch transformed bytes or followed a nested provider")
	}
	var dials atomic.Int32
	fetcher.dialContext = func(context.Context, string, string) (net.Conn, error) { dials.Add(1); return nil, io.ErrUnexpectedEOF }
	_, err = fetcher.Fetch(context.Background())
	fetchTestCode(t, err, CodeFetchUnavailable)
	if dials.Load() != 1 {
		t.Fatal("transport retried a failed dial")
	}
}

func TestFetcherCopiesTrustedPolicyAndRoots(t *testing.T) {
	_, endpoint := newFetchTest(t, "", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	policy := fetchTestPolicy()
	fetcher, err := NewFetcher(policy, FetchConfig{Resolver: fetchTestDNS(), RootCAs: endpoint.roots})
	if err != nil {
		t.Fatal("construct copied policy fixture")
	}
	policy.URL = "https://other.example/" + fetchTestSecret
	policy.AllowedCNAMEs[0] = "other.example"
	if fetcher.policy.URL != fetchTestPolicy().URL || fetcher.target.AllowedCNAMEs[0] != "edge.subscription.example" || fetcher.policy.AllowedCNAMEs[0] != "edge.subscription.example" {
		t.Fatal("caller mutated fixed policy")
	}
	if fetcher.rootCAs == endpoint.roots || !fetcher.rootCAs.Equal(endpoint.roots) {
		t.Fatal("root trust was not cloned")
	}
	_, otherCA, _ := fetchTestCA(t)
	endpoint.roots.AddCert(otherCA)
	if fetcher.rootCAs.Equal(endpoint.roots) {
		t.Fatal("caller mutation changed retained root trust")
	}
}
