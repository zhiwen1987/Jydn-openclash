package refresh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chengwang/image-binding/trustcatalog"
)

type material struct {
	key     trustcatalog.Key
	private ed25519.PrivateKey
}

func newMaterial(t *testing.T) material {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return material{trustcatalog.Key{ID: trustcatalog.KeyID(pub), PublicKey: pub}, priv}
}
func encode(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func (m material) catalogue(t *testing.T, generation uint64, padding int) []byte {
	t.Helper()
	now := time.Now().Unix()
	doc := trustcatalog.Document{Schema: trustcatalog.Schema, StoreID: strings.Repeat("a", 32), Generation: generation, NotBeforeUnix: now - 10, NotAfterUnix: now + 3600, RootKeys: []trustcatalog.Key{m.key}, Threshold: 1, Approvers: []trustcatalog.Key{}, Grants: []trustcatalog.Grant{}, PolicyFloors: map[string]uint64{}, RevokedKeys: []string{}, RevokedApprovals: []string{}, RevokedManifests: []string{}}
	payload := append(encode(t, doc), bytes.Repeat([]byte(" "), padding)...)
	return encode(t, trustcatalog.Envelope{Payload: payload, Signatures: []trustcatalog.Signature{{KeyID: m.key.ID, Signature: ed25519.Sign(m.private, append([]byte(trustcatalog.Schema+"\x00"), payload...))}}})
}
func tlsFixture(t *testing.T, handler http.Handler) (*httptest.Server, Config) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "refresh.fixture.invalid"}, DNSNames: []string{"refresh.fixture.invalid"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return server, Config{BaseURL: "https://refresh.fixture.invalid:" + strconv.Itoa(server.Listener.Addr().(*net.TCPAddr).Port) + "/catalogues", IP: "127.0.0.1", SPKI: digest(cert.RawSubjectPublicKeyInfo), Roots: pool, Timeout: 2 * time.Second}
}
func respond(w http.ResponseWriter, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}
func mustClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
func reject(t *testing.T, c *Client, generation uint64, hash string) {
	t.Helper()
	raw, err := c.Fetch(context.Background(), generation, hash)
	if err == nil || len(raw) != 0 {
		t.Fatal("invalid refresh returned candidates", err)
	}
}

func TestRefreshSequentialCatchupAndExactNoop(t *testing.T) {
	m := newMaterial(t)
	one, two, three := m.catalogue(t, 1, 0), m.catalogue(t, 2, 0), m.catalogue(t, 3, 0)
	var paths []string
	var mu sync.Mutex
	_, cfg := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("Accept-Encoding") != "" {
			t.Error("unexpected method/credentials/encoding")
		}
		switch r.URL.Path {
		case "/catalogues/latest.json":
			respond(w, three)
		case "/catalogues/2.json":
			respond(w, two)
		default:
			http.NotFound(w, r)
		}
	}))
	c := mustClient(t, cfg)
	raw, err := c.Fetch(context.Background(), 1, digest(one))
	if err != nil || len(raw) != 2 || !bytes.Equal(raw[0], two) || !bytes.Equal(raw[1], three) {
		t.Fatal("missing or reordered catchup", err)
	}
	anchor := trustcatalog.Anchor{StoreID: strings.Repeat("a", 32), InitialSHA256: digest(one), Keys: []trustcatalog.Key{m.key}, Threshold: 1}
	cat, err := trustcatalog.Replay(anchor, append([][]byte{one}, raw...))
	if err != nil || cat.Generation() != 3 {
		t.Fatal("test catchup signature chain invalid", err)
	}
	if len(paths) != 2 || paths[0] != "/catalogues/latest.json" || paths[1] != "/catalogues/2.json" {
		t.Fatal("unconfigured endpoint requested", paths)
	}
	raw, err = c.Fetch(context.Background(), 3, digest(three))
	if err != nil || len(raw) != 0 {
		t.Fatal("same raw catalogue not no-op", err)
	}
	if c.Interval() != time.Minute || c.MaxAge() != 5*time.Minute || c.Timeout() != 2*time.Second {
		t.Fatal("default duration getters")
	}
}
func TestRefreshRejectsRollbackForkGapAndIncompleteBatch(t *testing.T) {
	m := newMaterial(t)
	one, two, three := m.catalogue(t, 1, 0), m.catalogue(t, 2, 0), m.catalogue(t, 3, 0)
	for _, kind := range []string{"rollback", "same_generation_fork", "gap_budget", "wrong_intermediate", "missing_intermediate", "invalid_hint", "signature_shape"} {
		t.Run(kind, func(t *testing.T) {
			latest := three
			middle := two
			current := uint64(1)
			hash := digest(one)
			switch kind {
			case "rollback":
				latest = one
				current = 2
				hash = digest(two)
			case "same_generation_fork":
				latest = m.catalogue(t, 1, 1)
			case "gap_budget":
				latest = m.catalogue(t, 66, 0)
			case "wrong_intermediate":
				middle = one
			case "invalid_hint":
				latest = []byte(`{"payload":"e30=","signatures":[]}`)
			case "signature_shape":
				latest = bytes.Replace(three, []byte(`"signature":`), []byte(`"Signature":`), 1)
			}
			_, cfg := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/catalogues/latest.json" {
					respond(w, latest)
				} else if kind == "missing_intermediate" {
					http.NotFound(w, r)
				} else {
					respond(w, middle)
				}
			}))
			reject(t, mustClient(t, cfg), current, hash)
		})
	}
}
func TestRefreshPinsTLSIPAndRejectsProxyRedirectAuth(t *testing.T) {
	m := newMaterial(t)
	raw := m.catalogue(t, 1, 0)
	var received atomic.Int32
	_, cfg := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1); respond(w, raw) }))
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	if _, err := mustClient(t, cfg).Fetch(context.Background(), 1, digest(raw)); err != nil {
		t.Fatal("proxy environment or DNS used", err)
	}
	for _, kind := range []string{"wrong_spki", "wrong_ca", "wrong_hostname"} {
		t.Run(kind, func(t *testing.T) {
			copy := cfg
			switch kind {
			case "wrong_spki":
				copy.SPKI = "sha256:" + strings.Repeat("e", 64)
			case "wrong_ca":
				copy.Roots = x509.NewCertPool()
			case "wrong_hostname":
				copy.BaseURL = strings.Replace(cfg.BaseURL, "refresh.fixture.invalid", "other.fixture.invalid", 1)
			}
			before := received.Load()
			reject(t, mustClient(t, copy), 1, digest(raw))
			if received.Load() != before {
				t.Fatal("untrusted TLS emitted HTTP")
			}
		})
	}
	for _, code := range []int{301, 302, 307, 308, 401, 404, 304} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			var target atomic.Int32
			leak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { target.Add(1) }))
			defer leak.Close()
			_, config := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", leak.URL)
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+leak.URL+`"`)
				w.WriteHeader(code)
			}))
			reject(t, mustClient(t, config), 1, digest(raw))
			if target.Load() != 0 {
				t.Fatal("redirect/realm escaped source")
			}
		})
	}
}
func TestRefreshHTTPResponseAndBatchBudgets(t *testing.T) {
	m := newMaterial(t)
	raw := m.catalogue(t, 2, 0)
	for _, kind := range []string{"oversized", "encoding", "wrong_type", "missing_length", "short_body", "duplicate_type", "trailer"} {
		t.Run(kind, func(t *testing.T) {
			_, cfg := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "oversized":
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Content-Length", strconv.Itoa(MaxCatalogueBytes+1))
					w.WriteHeader(200)
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
					respond(w, raw)
				case "wrong_type":
					w.Header().Set("Content-Type", "text/plain")
					w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
					_, _ = w.Write(raw)
				case "missing_length":
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					_, _ = w.Write(raw)
				case "short_body":
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Content-Length", strconv.Itoa(len(raw)+1))
					_, _ = w.Write(raw)
				case "duplicate_type":
					w.Header().Add("Content-Type", "application/json")
					w.Header().Add("Content-Type", "application/json")
					w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
					_, _ = w.Write(raw)
				case "trailer":
					w.Header().Set("Trailer", "Checksum")
					respond(w, raw)
				}
			}))
			reject(t, mustClient(t, cfg), 1, digest([]byte("old")))
		})
	}
	t.Run("total_batch", func(t *testing.T) {
		large := make(map[string][]byte)
		for gen := uint64(2); gen <= 65; gen++ {
			large[fmt.Sprintf("/catalogues/%d.json", gen)] = m.catalogue(t, gen, 60<<10)
		}
		latest := large["/catalogues/65.json"]
		_, cfg := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/catalogues/latest.json" {
				respond(w, latest)
			} else {
				respond(w, large[r.URL.Path])
			}
		}))
		cfg.Timeout = 30 * time.Second
		reject(t, mustClient(t, cfg), 1, digest([]byte("old")))
	})
}
func TestRefreshCancellationDeadlineAndSingleFlight(t *testing.T) {
	entered := make(chan struct{})
	exited := make(chan struct{})
	var once sync.Once
	_, cfg := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		<-r.Context().Done()
		close(exited)
	}))
	c := mustClient(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := c.Fetch(ctx, 1, digest([]byte("old"))); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("fetch not started")
	}
	if raw, err := c.Fetch(context.Background(), 1, digest([]byte("old"))); err != ErrBusy || raw != nil {
		t.Fatal("parallel fetch queued")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled fetch succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled fetch stuck")
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("source connection leaked after cancel")
	}
	// A separate blocked-header call must respect the whole Fetch deadline.
	_, deadlineCfg := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	deadlineCfg.Timeout = 100 * time.Millisecond
	started := time.Now()
	reject(t, mustClient(t, deadlineCfg), 1, digest([]byte("old")))
	if time.Since(started) > 2*time.Second {
		t.Fatal("fetch total timeout ignored")
	}
}
func TestRefreshStrictWireHintsDoNotGrantSignatureAuthority(t *testing.T) {
	m := newMaterial(t)
	good := m.catalogue(t, 2, 0)
	var envelope trustcatalog.Envelope
	if err := json.Unmarshal(good, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signatures[0].Signature[0] ^= 1
	badSignature := encode(t, envelope)
	if gen, ok := generationHint(badSignature); !ok || gen != 2 {
		t.Fatal("transport unexpectedly pretends to verify signatures")
	}
	for name, raw := range map[string][]byte{"duplicate": append([]byte(`{"payload":"e30=",`), good[1:]...), "alias": bytes.Replace(good, []byte(`"payload"`), []byte(`"Payload"`), 1), "escaped": bytes.Replace(good, []byte(`"payload"`), []byte(`"pay\u006coad"`), 1), "invalid_utf8": append(bytes.Clone(good), 0xff), "trailing": append(bytes.Clone(good), []byte(` {}`)...), "depth": []byte(`{"x":[[[[[[[[[[[0]]]]]]]]]]]}`), "bad_base64": []byte(`{"payload":"YR==","signatures":[]}`)} {
		t.Run(name, func(t *testing.T) {
			if _, ok := generationHint(raw); ok {
				t.Fatal("ambiguous hint accepted")
			}
		})
	}
	for _, value := range []string{"0", "-1", "1.0", "1e0", "18446744073709551616"} {
		t.Run(value, func(t *testing.T) {
			payload := []byte(`{"generation":` + value + `}`)
			raw := encode(t, map[string]any{"payload": base64.StdEncoding.EncodeToString(payload), "signatures": envelope.Signatures})
			if _, ok := generationHint(raw); ok {
				t.Fatal("ambiguous/invalid generation accepted")
			}
		})
	}
}
func TestRefreshConfigurationRejectsMutableSources(t *testing.T) {
	_, cfg := tlsFixture(t, http.NotFoundHandler())
	for name, mutate := range map[string]func(*Config){"http": func(c *Config) { c.BaseURL = strings.Replace(c.BaseURL, "https:", "http:", 1) }, "query": func(c *Config) { c.BaseURL += "?x=1" }, "bare_query": func(c *Config) { c.BaseURL += "?" }, "fragment": func(c *Config) { c.BaseURL += "#x" }, "credentials": func(c *Config) { c.BaseURL = strings.Replace(c.BaseURL, "https://", "https://user:secret@", 1) }, "escaped_path": func(c *Config) { c.BaseURL += "/%2e" }, "traversal": func(c *Config) { c.BaseURL += "/../x" }, "double_slash": func(c *Config) { c.BaseURL += "//x" }, "invalid_ip": func(c *Config) { c.IP = "mutable.invalid" }, "zone": func(c *Config) { c.IP = "fe80::1%eth0" }, "mapped_ip": func(c *Config) { c.IP = "::ffff:127.0.0.1" }, "unspecified": func(c *Config) { c.IP = "0.0.0.0" }, "multicast": func(c *Config) { c.IP = "224.0.0.1" }, "nil_roots": func(c *Config) { c.Roots = nil }, "bad_spki": func(c *Config) { c.SPKI = strings.ToUpper(c.SPKI) }, "negative_interval": func(c *Config) { c.Interval = -time.Second }, "maxage": func(c *Config) { c.MaxAge = time.Second }, "timeout": func(c *Config) { c.Timeout = 3 * time.Minute }} {
		t.Run(name, func(t *testing.T) {
			candidate := cfg
			mutate(&candidate)
			if client, err := New(candidate); err != ErrInvalid || client != nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	client := mustClient(t, cfg)
	for _, age := range []time.Duration{time.Hour + time.Nanosecond, 24 * time.Hour} {
		candidate := cfg
		candidate.MaxAge = age
		if c, err := New(candidate); err != ErrInvalid || c != nil {
			t.Fatal("refresh MaxAge exceeded product source freshness bound")
		}
	}
	tooLong := cfg
	tooLong.BaseURL += "/" + strings.Repeat("a", 2048)
	if c, err := New(tooLong); err != ErrInvalid || c != nil {
		t.Fatal("unbounded source URL accepted")
	}
	for _, ctx := range []context.Context{nil, func() context.Context { c, cancel := context.WithCancel(context.Background()); cancel(); return c }()} {
		if raw, err := client.Fetch(ctx, 1, digest([]byte("old"))); err == nil || len(raw) != 0 {
			t.Fatal("invalid context accepted")
		}
	}
	reject(t, client, 0, digest([]byte("old")))
	reject(t, client, 1, "not-a-digest")
}
func TestRefreshRunImmediatePeriodicAndStops(t *testing.T) {
	_, cfg := tlsFixture(t, http.NotFoundHandler())
	c := mustClient(t, cfg)
	c.interval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	done := make(chan error, 1)
	first := make(chan struct{})
	var once sync.Once
	go func() {
		done <- c.Run(ctx, func(attempt context.Context) error {
			if _, ok := attempt.Deadline(); !ok {
				t.Error("callback deadline missing")
			}
			calls.Add(1)
			once.Do(func() { close(first) })
			return nil
		})
	}()
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("first refresh not immediate")
	}
	if err := c.Run(ctx, func(context.Context) error { return nil }); err != ErrBusy {
		t.Fatal("duplicate scheduler started")
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for calls.Load() < 2 {
		select {
		case <-deadline.C:
			t.Fatal("success interval not scheduled")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("scheduler cancellation stuck")
	}
	at := calls.Load()
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != at {
		t.Fatal("callback outlived Run")
	}
}
func TestRefreshRunFailureBackoffAndDeadline(t *testing.T) {
	_, cfg := tlsFixture(t, http.NotFoundHandler())
	c := mustClient(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	var calls atomic.Int32
	err := c.Run(ctx, func(context.Context) error { calls.Add(1); return errors.New("safe failure") })
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatal("failed refresh hot-looped or ignored cancel", err, calls.Load())
	}
	if err := c.Run(nil, func(context.Context) error { return nil }); err != ErrInvalid {
		t.Fatal("nil context scheduler accepted")
	}
	if err := c.Run(context.Background(), nil); err != ErrInvalid {
		t.Fatal("nil callback scheduler accepted")
	}
}
