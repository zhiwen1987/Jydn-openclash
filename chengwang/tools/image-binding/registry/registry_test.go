package registry_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chengwang/image-binding/policy"
	"chengwang/image-binding/registry"
)

const ociManifest = "application/vnd.oci.image.manifest.v1+json"
const dockerManifest = "application/vnd.docker.distribution.manifest.v2+json"

type imageObject struct {
	raw               []byte
	mediaType, digest string
}
type recordedRequest struct{ method, path, host, auth string }
type fixtureRegistry struct {
	server                                          *httptest.Server
	objects                                         map[string]imageObject
	manifest                                        []byte
	manifestDigest, configDigest, layerDigest, host string
	roots                                           *x509.CertPool
	mu                                              sync.Mutex
	requests                                        []recordedRequest
	counts                                          map[string]int
	intercept                                       func(http.ResponseWriter, *http.Request, imageObject, int) bool
}

func sha(raw []byte) string { h := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(h[:]) }
func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func desc(raw []byte, mediaType string) map[string]any {
	return map[string]any{"mediaType": mediaType, "digest": sha(raw), "size": len(raw)}
}

func newRegistry(t *testing.T, format string) *fixtureRegistry {
	return newRegistryWithTLS(t, format, nil)
}

func newRegistryWithTLS(t *testing.T, format string, tlsConfig *tls.Config) *fixtureRegistry {
	t.Helper()
	f := &fixtureRegistry{objects: map[string]imageObject{}, counts: map[string]int{}}
	layerPlain := []byte("local verification fixture; never executed or extracted\n")
	layer := bytes.Clone(layerPlain)
	layerType := "application/vnd.oci.image.layer.v1.tar"
	manifestType, configType := ociManifest, "application/vnd.oci.image.config.v1+json"
	if format != "oci-raw" {
		var compressed bytes.Buffer
		g := gzip.NewWriter(&compressed)
		if _, err := g.Write(layer); err != nil {
			t.Fatal(err)
		}
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
		layer = compressed.Bytes()
		layerType += "+gzip"
	}
	if format == "docker-gzip" {
		manifestType = dockerManifest
		configType = "application/vnd.docker.container.image.v1+json"
		layerType = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	}
	config := jsonBytes(t, map[string]any{"architecture": "amd64", "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{sha(layerPlain)}}, "config": map[string]any{"Env": []string{"TEST_SECRET=not-returned"}}})
	f.manifest = jsonBytes(t, map[string]any{"schemaVersion": 2, "mediaType": manifestType, "config": desc(config, configType), "layers": []any{desc(layer, layerType)}})
	f.manifestDigest, f.configDigest, f.layerDigest = sha(f.manifest), sha(config), sha(layer)
	f.objects["/v2/team/image/manifests/"+f.manifestDigest] = imageObject{f.manifest, manifestType, f.manifestDigest}
	f.objects["/v2/team/image/blobs/"+f.configDigest] = imageObject{config, "application/octet-stream", f.configDigest}
	f.objects["/v2/team/image/blobs/"+f.layerDigest] = imageObject{layer, "application/octet-stream", f.layerDigest}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, recordedRequest{r.Method, r.URL.Path, r.Host, r.Header.Get("Authorization")})
		f.counts[r.Method+" "+r.URL.Path]++
		count := f.counts[r.Method+" "+r.URL.Path]
		f.mu.Unlock()
		object, ok := f.objects[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if f.intercept != nil && f.intercept(w, r, object, count) {
			return
		}
		serveObject(w, r, object)
	}))
	if tlsConfig != nil {
		f.server.TLS = tlsConfig.Clone()
	}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	u, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	f.host = "example.com:" + u.Port()
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.server.Certificate())
	return f
}
func serveObject(w http.ResponseWriter, r *http.Request, o imageObject) {
	w.Header().Set("Content-Type", o.mediaType)
	w.Header().Set("Content-Length", strconv.Itoa(len(o.raw)))
	w.Header().Set("Docker-Content-Digest", o.digest)
	w.Header().Set("Etag", "\"fixture\"")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		w.Write(o.raw)
	}
}
func (f *fixtureRegistry) reference() string { return f.host + "/team/image@" + f.manifestDigest }
func (f *fixtureRegistry) recorded() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedRequest(nil), f.requests...)
}
func (f *fixtureRegistry) replaceManifest(t *testing.T, change func(map[string]any)) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(f.manifest, &m); err != nil {
		t.Fatal(err)
	}
	change(m)
	delete(f.objects, "/v2/team/image/manifests/"+f.manifestDigest)
	f.manifest = jsonBytes(t, m)
	f.manifestDigest = sha(f.manifest)
	f.objects["/v2/team/image/manifests/"+f.manifestDigest] = imageObject{f.manifest, m["mediaType"].(string), f.manifestDigest}
}

func approved(t *testing.T, reference, spki string, ips []string, architecture string, start, end int64) policy.Approved {
	t.Helper()
	trust, envelope := approvalInput(t, reference, spki, ips, architecture, start, end)
	a, err := policy.Verify(context.Background(), trust, envelope, time.Unix(start+1, 0))
	if err != nil {
		t.Fatalf("construct signed local approval: %v", err)
	}
	return a
}

func approvalInput(t *testing.T, reference, spki string, ips []string, architecture string, start, end int64) (policy.Trust, []byte) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{73}, ed25519.SeedSize))
	_, artifact, _ := strings.Cut(reference, "@")
	document := map[string]any{"schema": policy.Schema, "policyID": "registry-test", "revision": 1, "approverKeyID": "registry-test-key", "notBeforeUnix": start, "notAfterUnix": end, "reference": reference, "os": "linux", "architecture": architecture, "variant": "", "registryIPs": ips, "registrySPKISHA256": spki, "signature": map[string]any{"artifactSHA256": artifact, "trustedRootSHA256": "sha256:" + strings.Repeat("1", 64), "logID": strings.Repeat("2", 64), "issuer": "https://issuer.example", "san": "registry-test", "kind": "message-signature"}}
	if spki == "" {
		delete(document, "registrySPKISHA256")
	}
	payload := jsonBytes(t, document)
	message := append([]byte(policy.Schema+"\x00"), payload...)
	envelope := jsonBytes(t, map[string]string{"payload": base64.StdEncoding.EncodeToString(payload), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))})
	return policy.Trust{KeyID: "registry-test-key", PublicKey: key.Public().(ed25519.PublicKey), PolicySHA256: sha(payload), Revision: 1}, envelope
}
func (f *fixtureRegistry) approval(t *testing.T) policy.Approved {
	now := time.Now().Unix()
	return approved(t, f.reference(), f.spki(), []string{"127.0.0.1"}, "amd64", now-60, now+3600)
}
func (f *fixtureRegistry) spki() string { return sha(f.server.Certificate().RawSubjectPublicKeyInfo) }
func failure(t *testing.T, ctx context.Context, a policy.Approved, roots *x509.CertPool, token string, want error) {
	t.Helper()
	o, err := registry.Read(ctx, a, roots, token)
	if !errors.Is(err, want) {
		t.Fatalf("error=%v want=%v", err, want)
	}
	if want == registry.ErrInvalid && err != registry.ErrInvalid {
		t.Fatal("variable remote error escaped")
	}
	if !reflect.DeepEqual(o, registry.Observation{}) || o.Verified() || o.Reference() != "" || o.ApprovalSHA256() != "" || o.RegistryHost() != "" || !o.ObservedAt().IsZero() || o.Graph().GraphSHA256() != "" {
		t.Fatal("failure returned nonzero observation")
	}
	if err != nil && strings.Contains(err.Error(), token) && token != "" {
		t.Fatal("token escaped in error")
	}
}

func TestReadApprovedRegistryGraph(t *testing.T) {
	for _, format := range []string{"oci-raw", "oci-gzip", "docker-gzip"} {
		t.Run(format, func(t *testing.T) {
			f := newRegistry(t, format)
			a := f.approval(t)
			before := time.Now()
			token := "local-token-never-log"
			o, err := registry.Read(context.Background(), a, f.roots, token)
			if err != nil || !o.Verified() {
				t.Fatalf("read failed: %v", err)
			}
			if o.Reference() != f.reference() || o.RegistryHost() != f.host || o.ApprovalSHA256() != a.SHA256() || o.ObservedAt().Before(before) || o.ObservedAt().After(time.Now()) {
				t.Fatal("observation did not bind approved source and current read")
			}
			if o.Graph().Content().ManifestDigest() != f.manifestDigest || o.Graph().Content().ConfigDigest() != f.configDigest || o.Graph().LayerCount() != 1 || o.Graph().GraphSHA256() == "" {
				t.Fatal("graph not validated")
			}
			requests := f.recorded()
			if len(requests) != 12 {
				t.Fatalf("request count=%d want12", len(requests))
			}
			for _, r := range requests {
				if r.host != f.host || r.auth != "Bearer "+token || (r.method != http.MethodGet && r.method != http.MethodHead) {
					t.Fatal("request left fixed host/read-only credentials boundary")
				}
			}
			if strings.Contains(fmt.Sprintf("%+v", o), token) || strings.Contains(fmt.Sprintf("%+v", o), "TEST_SECRET") {
				t.Fatal("sensitive raw material retained in observation")
			}
		})
	}
}

func TestPinnedIPBypassesDNSAndEnvironmentProxy(t *testing.T) {
	f := newRegistry(t, "oci-raw")
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "http://unapproved-proxy.invalid:9")
	}
	old := net.DefaultResolver
	var dnsCalls atomic.Int32
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		dnsCalls.Add(1)
		return nil, errors.New("DNS forbidden")
	}}
	t.Cleanup(func() { net.DefaultResolver = old })
	o, err := registry.Read(context.Background(), f.approval(t), f.roots, "")
	if err != nil || !o.Verified() || dnsCalls.Load() != 0 {
		t.Fatalf("IP pin or no-proxy boundary failed, error=%v DNS calls=%d", err, dnsCalls.Load())
	}
}

func TestDigestHeaderMayBeAbsent(t *testing.T) {
	f := newRegistry(t, "oci-raw")
	f.intercept = func(w http.ResponseWriter, r *http.Request, o imageObject, _ int) bool {
		w.Header().Set("Content-Type", o.mediaType)
		w.Header().Set("Content-Length", strconv.Itoa(len(o.raw)))
		w.WriteHeader(200)
		if r.Method == http.MethodGet {
			w.Write(o.raw)
		}
		return true
	}
	o, err := registry.Read(context.Background(), f.approval(t), f.roots, "")
	if err != nil || !o.Verified() {
		t.Fatalf("optional OCI digest header rejected: %v", err)
	}
}

func TestRejectApprovalAndTLSFailures(t *testing.T) {
	for _, name := range []string{"zero_approval", "expired", "future", "wrong_ip", "wrong_certificate_host", "wrong_roots", "invalid_token"} {
		t.Run(name, func(t *testing.T) {
			f := newRegistry(t, "oci-raw")
			a := f.approval(t)
			roots := f.roots
			token := ""
			now := time.Now().Unix()
			switch name {
			case "zero_approval":
				a = policy.Approved{}
			case "expired":
				a = approved(t, f.reference(), f.spki(), []string{"127.0.0.1"}, "amd64", now-120, now-60)
			case "future":
				a = approved(t, f.reference(), f.spki(), []string{"127.0.0.1"}, "amd64", now+60, now+120)
			case "wrong_ip":
				a = approved(t, f.reference(), f.spki(), []string{"127.0.0.2"}, "amd64", now-60, now+3600)
			case "wrong_certificate_host":
				a = approved(t, strings.Replace(f.reference(), "example.com", "registry.invalid", 1), f.spki(), []string{"127.0.0.1"}, "amd64", now-60, now+3600)
			case "wrong_roots":
				roots = x509.NewCertPool()
			case "invalid_token":
				token = "token\r\nInjected: bad"
			}
			failure(t, context.Background(), a, roots, token, registry.ErrInvalid)
			if len(f.recorded()) != 0 {
				t.Fatal("invalid approval/TLS/token permitted HTTP read")
			}
		})
	}
}

func TestRejectRedirectAndAuthRealmWithoutLeakingToken(t *testing.T) {
	for _, name := range []string{"redirect", "authentication_realm"} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
			defer target.Close()
			f := newRegistry(t, "oci-raw")
			token := "never-send-to-second-server"
			f.intercept = func(w http.ResponseWriter, r *http.Request, o imageObject, _ int) bool {
				if name == "redirect" {
					w.Header().Set("Location", target.URL+"/secret?token="+token)
					w.WriteHeader(307)
				} else {
					w.Header().Set("WWW-Authenticate", `Bearer realm="`+target.URL+`/token",service="unapproved"`)
					w.WriteHeader(401)
				}
				return true
			}
			failure(t, context.Background(), f.approval(t), f.roots, token, registry.ErrInvalid)
			if calls.Load() != 0 {
				t.Fatal("redirect/realm received request")
			}
		})
	}
}

func rawResponse(w http.ResponseWriter, header string, body []byte) {
	conn, buffer, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	buffer.WriteString(header)
	buffer.Write(body)
	buffer.Flush()
}

func TestRejectResponseFramingAndMetadata(t *testing.T) {
	for _, name := range []string{"status_partial", "status_error", "bare_lf_hidden_content_length", "content_type_wrong", "content_type_missing", "content_type_duplicate", "length_missing", "length_negative", "length_oversize", "length_duplicate", "length_conflict", "digest_wrong", "digest_duplicate", "digest_comma", "digest_empty", "content_encoding", "transfer_encoding", "header_fold", "header_oversize", "interim_response", "get_short_body", "get_long_body", "head_body", "etag_invalid", "modified_invalid"} {
		t.Run(name, func(t *testing.T) {
			f := newRegistry(t, "oci-raw")
			f.intercept = func(w http.ResponseWriter, r *http.Request, o imageObject, _ int) bool {
				if strings.HasPrefix(name, "get_") && r.Method == http.MethodHead {
					return false
				}
				status := "200 OK"
				ct := "Content-Type: " + o.mediaType + "\r\n"
				cl := "Content-Length: " + strconv.Itoa(len(o.raw)) + "\r\n"
				dcd := "Docker-Content-Digest: " + o.digest + "\r\n"
				extra := ""
				body := []byte(nil)
				if r.Method == http.MethodGet {
					body = o.raw
				}
				switch name {
				case "bare_lf_hidden_content_length":
					// Both lengths are identical; ReadResponse alone normalizes them.
					status += "\n" + strings.TrimSuffix(cl, "\r\n")
				case "status_partial":
					status = "206 Partial Content"
				case "status_error":
					status = "500 Internal Server Error"
				case "content_type_wrong":
					ct = "Content-Type: text/html\r\n"
				case "content_type_missing":
					ct = ""
				case "content_type_duplicate":
					ct += ct
				case "length_missing":
					cl = ""
				case "length_negative":
					cl = "Content-Length: -1\r\n"
				case "length_oversize":
					cl = "Content-Length: 1048577\r\n"
				case "length_duplicate":
					cl += cl
				case "length_conflict":
					cl += "Content-Length: 1\r\n"
				case "digest_wrong":
					dcd = "Docker-Content-Digest: sha256:" + strings.Repeat("0", 64) + "\r\n"
				case "digest_duplicate":
					dcd += dcd
				case "digest_comma":
					dcd = "Docker-Content-Digest: " + o.digest + ", " + o.digest + "\r\n"
				case "digest_empty":
					dcd = "Docker-Content-Digest: \r\n"
				case "content_encoding":
					extra = "Content-Encoding: identity\r\n"
				case "transfer_encoding":
					extra = "Transfer-Encoding: chunked\r\n"
				case "header_fold":
					extra = "X-Thing: first\r\n folded\r\n"
				case "header_oversize":
					extra = "X-Thing: " + strings.Repeat("x", (32<<10)+1) + "\r\n"
				case "interim_response":
					rawResponse(w, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"+ct+cl+dcd+"\r\n", body)
					return true
				case "get_short_body":
					body = body[:len(body)-1]
				case "get_long_body":
					body = append(bytes.Clone(body), 'x')
				case "head_body":
					body = []byte("unexpected HEAD body")
				case "etag_invalid":
					extra = "Etag: invalid\r\n"
				case "modified_invalid":
					extra = "Last-Modified: invalid\r\n"
				}
				rawResponse(w, "HTTP/1.1 "+status+"\r\n"+ct+cl+dcd+extra+"Connection: close\r\n\r\n", body)
				return true
			}
			failure(t, context.Background(), f.approval(t), f.roots, "sensitive-token", registry.ErrInvalid)
		})
	}
}

func TestRejectReadbackDriftAndGraphMismatch(t *testing.T) {
	for _, name := range []string{"head_get_drift", "head_after_drift", "final_manifest_drift", "manifest_changed", "config_changed", "layer_changed", "platform_mismatch", "layer_diff_id_mismatch"} {
		t.Run(name, func(t *testing.T) {
			f := newRegistry(t, "oci-raw")
			a := f.approval(t)
			if name == "platform_mismatch" {
				now := time.Now().Unix()
				a = approved(t, f.reference(), f.spki(), []string{"127.0.0.1"}, "arm64", now-60, now+3600)
			}
			if name == "layer_diff_id_mismatch" {
				old := f.objects["/v2/team/image/blobs/"+f.configDigest]
				var c map[string]any
				json.Unmarshal(old.raw, &c)
				c["rootfs"].(map[string]any)["diff_ids"] = []string{"sha256:" + strings.Repeat("0", 64)}
				raw := jsonBytes(t, c)
				f.configDigest = sha(raw)
				f.objects["/v2/team/image/blobs/"+f.configDigest] = imageObject{raw, old.mediaType, f.configDigest}
				f.replaceManifest(t, func(m map[string]any) { m["config"] = desc(raw, "application/vnd.oci.image.config.v1+json") })
				a = f.approval(t)
			}
			f.intercept = func(w http.ResponseWriter, r *http.Request, o imageObject, count int) bool {
				change := name == "head_get_drift" && r.Method == http.MethodGet || name == "head_after_drift" && r.Method == http.MethodHead && count == 2 || name == "final_manifest_drift" && strings.Contains(r.URL.Path, "/manifests/") && r.Method == http.MethodHead && count == 3
				if change {
					w.Header().Set("Etag", "\"changed\"")
					w.Header().Set("Content-Type", o.mediaType)
					w.Header().Set("Content-Length", strconv.Itoa(len(o.raw)))
					w.Header().Set("Docker-Content-Digest", o.digest)
					w.WriteHeader(200)
					if r.Method == http.MethodGet {
						w.Write(o.raw)
					}
					return true
				}
				corrupt := r.Method == http.MethodGet && (name == "manifest_changed" && strings.Contains(r.URL.Path, "/manifests/") && count == 2 || name == "config_changed" && strings.HasSuffix(r.URL.Path, f.configDigest) || name == "layer_changed" && strings.HasSuffix(r.URL.Path, f.layerDigest))
				if corrupt {
					o.raw = bytes.Clone(o.raw)
					o.raw[len(o.raw)-1] ^= 1
					serveObject(w, r, o)
					return true
				}
				return false
			}
			failure(t, context.Background(), a, f.roots, "", registry.ErrInvalid)
		})
	}
}

func TestRejectDeclaredImageBudgets(t *testing.T) {
	for _, name := range []string{"config_size", "layer_size", "layer_count", "total_size", "image_index", "foreign_layer_url"} {
		t.Run(name, func(t *testing.T) {
			f := newRegistry(t, "oci-raw")
			f.replaceManifest(t, func(m map[string]any) {
				config := m["config"].(map[string]any)
				layer := m["layers"].([]any)[0].(map[string]any)
				switch name {
				case "config_size":
					config["size"] = (1 << 20) + 1
				case "layer_size":
					layer["size"] = (128 << 20) + 1
				case "layer_count":
					layers := make([]any, 129)
					for i := range layers {
						layers[i] = layer
					}
					m["layers"] = layers
				case "total_size":
					layer["size"] = 128 << 20
					m["layers"] = []any{layer, layer, layer, layer, layer}
				case "image_index":
					m["mediaType"] = "application/vnd.oci.image.index.v1+json"
				case "foreign_layer_url":
					layer["urls"] = []string{"https://unapproved.invalid/layer"}
				}
			})
			failure(t, context.Background(), f.approval(t), f.roots, "", registry.ErrInvalid)
			for _, r := range f.recorded() {
				if strings.Contains(r.path, "/blobs/") {
					t.Fatal("invalid manifest budget caused blob fetch")
				}
			}
		})
	}
}

func TestContextAndApprovalExpiry(t *testing.T) {
	t.Run("nil_context", func(t *testing.T) {
		f := newRegistry(t, "oci-raw")
		failure(t, nil, f.approval(t), f.roots, "", registry.ErrInvalid)
	})
	t.Run("already_canceled", func(t *testing.T) {
		f := newRegistry(t, "oci-raw")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		failure(t, ctx, f.approval(t), f.roots, "", context.Canceled)
		if len(f.recorded()) != 0 {
			t.Fatal("canceled call sent a request")
		}
	})
	t.Run("header_deadline", func(t *testing.T) {
		f := newRegistry(t, "oci-raw")
		f.intercept = func(w http.ResponseWriter, r *http.Request, _ imageObject, _ int) bool {
			<-r.Context().Done()
			return true
		}
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer cancel()
		failure(t, ctx, f.approval(t), f.roots, "", context.DeadlineExceeded)
	})
	t.Run("cancel_in_flight", func(t *testing.T) {
		f := newRegistry(t, "oci-raw")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.intercept = func(w http.ResponseWriter, r *http.Request, _ imageObject, _ int) bool {
			cancel()
			<-r.Context().Done()
			return true
		}
		failure(t, ctx, f.approval(t), f.roots, "", context.Canceled)
	})
	t.Run("expiry_after_first_request", func(t *testing.T) {
		f := newRegistry(t, "oci-raw")
		now := time.Now().Unix()
		end := now + 1
		a := approved(t, f.reference(), f.spki(), []string{"127.0.0.1"}, "amd64", now-60, end)
		f.intercept = func(w http.ResponseWriter, r *http.Request, o imageObject, _ int) bool {
			timer := time.NewTimer(time.Until(time.Unix(end, 0)) + 10*time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
				serveObject(w, r, o)
			case <-r.Context().Done():
			}
			return true
		}
		failure(t, context.Background(), a, f.roots, "", registry.ErrInvalid)
		if len(f.recorded()) > 1 {
			t.Fatal("expired approval allowed another network request")
		}
	})
}

func TestApprovalExpiryInterruptsBlockedResponse(t *testing.T) {
	for _, phase := range []string{"body", "eof"} {
		t.Run(phase, func(t *testing.T) {
			f := newRegistry(t, "oci-raw")
			// Integer policy timestamps require a second boundary. Choose the
			// first boundary at least 400ms away, rather than sleeping to align.
			expiry := time.Unix(time.Now().Add(400*time.Millisecond).Unix()+1, 0)
			a := approved(t, f.reference(), f.spki(), []string{"127.0.0.1"}, "amd64", expiry.Unix()-60, expiry.Unix())
			var entered atomic.Bool
			closed := make(chan struct{})
			f.intercept = func(w http.ResponseWriter, r *http.Request, o imageObject, _ int) bool {
				if r.Method != http.MethodGet {
					return false
				}
				entered.Store(true)
				if phase == "body" {
					w.Header().Set("Content-Type", o.mediaType)
					w.Header().Set("Content-Length", strconv.Itoa(len(o.raw)))
					w.Header().Set("Docker-Content-Digest", o.digest)
					w.WriteHeader(200)
					w.Write(o.raw[:len(o.raw)/2])
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					close(closed)
					return true
				}
				conn, buffer, err := w.(http.Hijacker).Hijack()
				if err != nil {
					close(closed)
					return true
				}
				defer conn.Close()
				fmt.Fprintf(buffer, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nDocker-Content-Digest: %s\r\nConnection: close\r\n\r\n", o.mediaType, len(o.raw), o.digest)
				buffer.Write(o.raw)
				buffer.Flush()
				// Deliberately omit server EOF. The approval deadline must close
				// the client connection even though the complete body is present.
				conn.SetReadDeadline(expiry.Add(3 * time.Second))
				var probe [1]byte
				conn.Read(probe[:])
				close(closed)
				return true
			}
			caller, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			started := time.Now()
			maximum := time.Until(expiry) + 800*time.Millisecond
			failure(t, caller, a, f.roots, "", registry.ErrInvalid)
			if !entered.Load() {
				t.Fatal("approval expired before blocked response was exercised")
			}
			if time.Since(started) > maximum {
				t.Fatal("approval expiry did not promptly interrupt the response")
			}
			if caller.Err() != nil {
				t.Fatal("internal approval expiry was confused with caller cancellation")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("server connection remained open after approval expiry")
			}
		})
	}
}

func alternateRegistryCertificate(t *testing.T) (tls.Certificate, *x509.CertPool, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "independent local test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey, Leaf: leaf}, roots, leaf
}

func TestRegistrySPKIPinRejectsDifferentTrustedKey(t *testing.T) {
	original := newRegistry(t, "oci-raw")
	certificate, roots, leaf := alternateRegistryCertificate(t)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "example.com", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("alternate certificate must independently pass CA/hostname verification: %v", err)
	}
	alternate := newRegistryWithTLS(t, "oci-raw", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if alternate.spki() == original.spki() {
		t.Fatal("regression requires a genuinely different leaf key")
	}
	now := time.Now().Unix()
	// The caller deliberately trusts the alternate CA. The signed independent
	// approval still pins the original key for this exact Registry endpoint.
	a := approved(t, alternate.reference(), original.spki(), []string{"127.0.0.1"}, "amd64", now-60, now+3600)
	if !a.ValidAt(time.Now()) {
		t.Fatal("wrong key pin must still be a correctly signed policy")
	}
	failure(t, context.Background(), a, roots, "must-not-reach-http", registry.ErrInvalid)
	if len(alternate.recorded()) != 0 {
		t.Fatal("alternate trusted CA/key received authenticated HTTP")
	}
	// A separately signed approval for the actual alternate key must work;
	// otherwise the negative could merely be an unrelated certificate failure.
	a = approved(t, alternate.reference(), alternate.spki(), []string{"127.0.0.1"}, "amd64", now-60, now+3600)
	o, err := registry.Read(context.Background(), a, roots, "")
	if err != nil || !o.Verified() {
		t.Fatalf("matching alternate key pin failed: %v", err)
	}
}

func TestRegistrySPKIPinMissingOrWrong(t *testing.T) {
	t.Run("wrong_valid_policy_pin", func(t *testing.T) {
		f := newRegistry(t, "oci-raw")
		now := time.Now().Unix()
		a := approved(t, f.reference(), "sha256:"+strings.Repeat("0", 64), []string{"127.0.0.1"}, "amd64", now-60, now+3600)
		if !a.ValidAt(time.Now()) {
			t.Fatal("incorrect pin did not exercise a verified signed policy")
		}
		failure(t, context.Background(), a, f.roots, "must-not-reach-http", registry.ErrInvalid)
		if len(f.recorded()) != 0 {
			t.Fatal("wrong SPKI pin permitted authenticated HTTP")
		}
	})
	t.Run("missing_pin_cannot_mint_approval", func(t *testing.T) {
		f := newRegistry(t, "oci-raw")
		now := time.Now().Unix()
		trust, envelope := approvalInput(t, f.reference(), "", []string{"127.0.0.1"}, "amd64", now-60, now+3600)
		a, err := policy.Verify(context.Background(), trust, envelope, time.Now())
		if err != policy.ErrInvalid || a.ValidAt(time.Now()) {
			t.Fatal("missing required pin minted an approval")
		}
		failure(t, context.Background(), a, f.roots, "must-not-reach-http", registry.ErrInvalid)
		if len(f.recorded()) != 0 {
			t.Fatal("missing SPKI pin permitted HTTP")
		}
	})
}
