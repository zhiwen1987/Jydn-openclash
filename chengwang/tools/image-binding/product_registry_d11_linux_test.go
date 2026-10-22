//go:build linux && productregistry

package binding_test

// This driver is only a client and offline material preparer. The server under
// test is the independently inspected image entrypoint, never an httptest API.
import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	verifier "chengwang-image-verifier"
	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
	"golang.org/x/sys/unix"
)

const d11Repository = "registry.fixture.invalid:5443/chengwang/product-candidate"
const d11Registry = "https://registry.fixture.invalid:5443"
const d11VerifyPath = "/api/v1/image-trust/verifications"
const d11CataloguePath = "/api/v1/image-trust/catalogue"

type d11Descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}
type d11Graph struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Config        d11Descriptor   `json:"config"`
	Layers        []d11Descriptor `json:"layers"`
}

// These are Docker-save envelope helpers, not Registry OCI descriptors or
// authenticated provenance. Moby v28.0.4 manifestItem/Descriptor defines these
// optional fields. This scratch fixture rejects all non-local auxiliary data.
type d11SavedLayerSource struct {
	MediaType   string            `json:"mediaType,omitempty"`
	Size        int64             `json:"size,omitempty"`
	Digest      string            `json:"digest,omitempty"`
	URLs        []string          `json:"urls,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Platform    json.RawMessage   `json:"platform,omitempty"`
}
type d11SavedImage struct {
	Config       string
	RepoTags     []string
	Layers       []string
	Parent       string                         `json:",omitempty"`
	LayerSources map[string]d11SavedLayerSource `json:",omitempty"`
}

func d11SavedLayerMetadata(saved d11SavedImage, diffIDs []string, layers [][]byte) bool {
	if saved.Parent != "" || len(layers) == 0 || len(layers) != len(diffIDs) || len(saved.Layers) != len(layers) {
		return false
	}
	seen := map[string]bool{}
	for i, diffID := range diffIDs {
		if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(diffID) || seen[diffID] || len(layers[i]) == 0 || len(layers[i]) > 128<<20 || hashed(layers[i]) != diffID {
			return false
		}
		seen[diffID] = true
	}
	// Older Docker-save envelopes have no helper map. Its absence cannot
	// bypass the real config/diffID/layer checks above or the OCI checks later.
	if saved.LayerSources == nil {
		return true
	}
	if len(saved.LayerSources) != len(layers) {
		return false
	}
	for i, diffID := range diffIDs {
		source, found := saved.LayerSources[diffID]
		if !found || source.MediaType != "application/vnd.oci.image.layer.v1.tar" || source.Digest != diffID || source.Size != int64(len(layers[i])) || len(source.URLs) != 0 || len(source.Annotations) != 0 || len(source.Platform) != 0 {
			return false
		}
	}
	return true
}

// This pure helper is only for the synthetic metadata test. The actual archive
// uses d11Decode (the same DisallowUnknownFields plus EOF contract) for safe
// rejection diagnostics, followed by d11SavedLayerMetadata on actual bytes.
func d11SavedMetadataAccepts(raw []byte, diffIDs []string, layers [][]byte) bool {
	var saved []d11SavedImage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(&saved) == nil && decoder.Decode(new(any)) == io.EOF && len(saved) == 1 && d11SavedLayerMetadata(saved[0], diffIDs, layers)
}

type d11Policy struct {
	Name                   string `json:"name"`
	PolicyID               string `json:"policyID"`
	GrantID                string `json:"grantID"`
	ApprovalSHA256         string `json:"approvalSHA256"`
	ApprovalEnvelopeSHA256 string `json:"approvalEnvelopeSHA256"`
	BundleSHA256           string `json:"bundleSHA256"`
	BundleArtifactSHA256   string `json:"bundleArtifactSHA256"`
	TrustedRootSHA256      string `json:"trustedRootSHA256"`
	RegistrySPKI           string `json:"registrySPKI"`
}
type d11Material struct {
	Kind             string              `json:"kind"`
	SourceCommit     string              `json:"sourceCommit"`
	LocalImageID     string              `json:"localImageID"`
	ManifestSHA256   string              `json:"manifestSHA256"`
	ConfigSHA256     string              `json:"configSHA256"`
	LayerSHA256s     []string            `json:"layerSHA256s"`
	DiffIDs          []string            `json:"diffIDs"`
	Catalogue1SHA256 string              `json:"catalogue1SHA256"`
	Catalogue2SHA256 string              `json:"catalogue2SHA256"`
	StoreID          string              `json:"storeID"`
	Anchor           trustcatalog.Anchor `json:"-"`
	Policies         []d11Policy         `json:"policies"`
}
type d11Case struct {
	Name                   string              `json:"name"`
	Method                 string              `json:"method"`
	Path                   string              `json:"path"`
	HTTPStatus             int                 `json:"httpStatus"`
	ErrorCode              string              `json:"errorCode"`
	StateMayHaveChanged    bool                `json:"stateMayHaveChanged"`
	PolicyID               string              `json:"policyID"`
	GrantID                string              `json:"grantID"`
	ApprovalSHA256         string              `json:"approvalSHA256"`
	ApprovalEnvelopeSHA256 string              `json:"approvalEnvelopeSHA256"`
	BundleSHA256           string              `json:"bundleSHA256"`
	TrustedRootSHA256      string              `json:"trustedRootSHA256"`
	RequestSHA256          string              `json:"requestSHA256"`
	StatusBefore           imagetrust.Status   `json:"statusBefore"`
	StatusAfter            imagetrust.Status   `json:"statusAfter"`
	HistoryBefore          imagetrust.History  `json:"historyBefore"`
	HistoryAfter           imagetrust.History  `json:"historyAfter"`
	Receipt                *imagetrust.Receipt `json:"receipt,omitempty"`
}
type d11Report struct {
	Schema string `json:"schema"`
	Action string `json:"action"`
	Case   int    `json:"case"`
	d11Material
	Authority                    string                    `json:"authority"`
	GraphOrigin                  string                    `json:"graphOrigin"`
	Authorization                string                    `json:"authorization"`
	Production                   bool                      `json:"production"`
	DeviceActionsExecuted        bool                      `json:"deviceActionsExecuted"`
	Cases                        []d11Case                 `json:"cases"`
	Inspection                   *truststate.Inspection    `json:"inspection,omitempty"`
	Journal                      []truststate.JournalEntry `json:"journal,omitempty"`
	Audit                        *evidence.VerifyReport    `json:"audit,omitempty"`
	JournalAuditBindingsVerified bool                      `json:"journalAuditBindingsVerified"`
}

func d11Require(t *testing.T, ok bool) {
	t.Helper()
	if !ok {
		_, ownFile, _, _ := runtime.Caller(0)
		if _, file, line, found := runtime.Caller(1); found && file == ownFile {
			fmt.Printf("D11_PRODUCT_REGISTRY_ASSERT_LINE=%d\n", line)
		}
		if _, file, line, found := runtime.Caller(2); found && file == ownFile {
			fmt.Printf("D11_PRODUCT_REGISTRY_ASSERT_CONTEXT_LINE=%d\n", line)
		}
		t.Fatal("isolated product registry fixture rejected")
	}
}

// EvidenceEvent.Data is omitempty: a rejected operation's empty map becomes
// nil after durable JSON replay. Compare semantic string maps, as the product
// recovery path does, without accepting a missing or changed non-empty value.
func d11SameData(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		other, ok := b[key]
		if !ok || other != value {
			return false
		}
	}
	return true
}
func d11Dir(t *testing.T, name string) {
	t.Helper()
	var st unix.Stat_t
	d11Require(t, unix.Lstat(name, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&07777 == 0700 && st.Uid == 10001 && st.Gid == 10001)
}
func d11Mkdir(t *testing.T, name string) {
	t.Helper()
	d11Require(t, os.Mkdir(name, 0700) == nil)
	d11Dir(t, name)
}
func d11Read(t *testing.T, name string, limit int64) []byte {
	t.Helper()
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	d11Require(t, err == nil)
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	d11Require(t, unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == 10001 && st.Gid == 10001 && st.Nlink == 1 && st.Size > 0 && st.Size <= limit)
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	d11Require(t, e == nil && int64(len(raw)) == st.Size)
	return raw
}
func d11Write(t *testing.T, name string, raw []byte) {
	t.Helper()
	fd, e := unix.Open(name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	d11Require(t, e == nil)
	f := os.NewFile(uintptr(fd), name)
	n, e := f.Write(raw)
	d11Require(t, e == nil && n == len(raw) && f.Sync() == nil && f.Close() == nil)
	d11Require(t, bytes.Equal(d11Read(t, name, int64(len(raw))+1), raw))
}
func d11JSON(t *testing.T, name string, v any) { t.Helper(); d11Write(t, name, encode(t, v)) }
func d11Decode(t *testing.T, raw []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	first := dec.Decode(v)
	if first != nil {
		reason := "OTHER"
		var syntax *json.SyntaxError
		var mismatch *json.UnmarshalTypeError
		switch {
		case strings.HasPrefix(first.Error(), "json: unknown field "):
			reason = "UNKNOWN_FIELD"
		case errors.As(first, &syntax):
			reason = "SYNTAX"
		case errors.As(first, &mismatch):
			reason = "TYPE"
		}
		fmt.Printf("D11_PRODUCT_REGISTRY_JSON_REJECTION=%s\n", reason)
		d11Require(t, false)
	}
	trailing := dec.Decode(new(any))
	if trailing != io.EOF {
		fmt.Println("D11_PRODUCT_REGISTRY_JSON_REJECTION=TRAILING")
		d11Require(t, false)
	}
}
func d11Base(t *testing.T) (string, string, string, string) {
	t.Helper()
	root, kind := os.Getenv("CHENGWANG_D11_ROOT"), os.Getenv("CHENGWANG_D11_KIND")
	commit, id := os.Getenv("CHENGWANG_D11_COMMIT"), os.Getenv("CHENGWANG_D11_IMAGE_ID")
	d11Require(t, os.Geteuid() == 10001 && os.Getegid() == 10001 && regexp.MustCompile(`^/tmp/chengwang-product-registry-[0-9a-f]{32}$`).MatchString(root))
	d11Require(t, kind == "message-signature" || kind == "dsse")
	d11Require(t, regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) && regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(id))
	d11Dir(t, root)
	d11Require(t, string(d11Read(t, filepath.Join(root, ".fixture-owner"), 64)) == strings.TrimPrefix(root, "/tmp/chengwang-product-registry-")+"\n")
	return root, kind, commit, id
}

func TestProductRegistryD11Fixture(t *testing.T) {
	root, kind, commit, id := d11Base(t)
	action := os.Getenv("CHENGWANG_D11_ACTION")
	switch action {
	case "prepare":
		d11Prepare(t, root, kind, commit, id)
	case "exercise", "resume":
		n, e := strconv.Atoi(os.Getenv("CHENGWANG_D11_CASE"))
		d11Require(t, e == nil && n >= 1 && n <= 4)
		d11Exercise(t, root, kind, commit, id, action, n)
	case "catalogue":
		d11Catalogue(t, root, kind, commit, id)
	case "verify":
		d11Reopen(t, root, kind, commit, id)
	default:
		d11Require(t, false)
	}
}

// No extraction, subprocess or external image is used to form this graph.
func d11Archive(t *testing.T, root, commit, id string) ([]byte, []byte, [][]byte, []string) {
	t.Helper()
	file := os.Getenv("CHENGWANG_D11_ARCHIVE")
	d11Require(t, file == filepath.Join(root, "bin", "product-image.private.tar"))
	raw := d11Read(t, file, 512<<20)
	tr := tar.NewReader(bytes.NewReader(raw))
	entries := map[string][]byte{}
	count := 0
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		d11Require(t, e == nil)
		count++
		d11Require(t, count <= 4096 && h.Name != "" && !strings.Contains(h.Name, "\\") && !strings.HasPrefix(h.Name, "/") && path.Clean(strings.TrimSuffix(h.Name, "/")) == strings.TrimSuffix(h.Name, "/") && !strings.HasPrefix(h.Name, "../"))
		if h.Typeflag == tar.TypeDir {
			continue
		}
		d11Require(t, (h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA) && h.Linkname == "" && h.Size >= 0 && h.Size <= 256<<20 && entries[h.Name] == nil)
		b, e := io.ReadAll(io.LimitReader(tr, h.Size+1))
		d11Require(t, e == nil && int64(len(b)) == h.Size)
		entries[h.Name] = b
	}
	var saved []d11SavedImage
	d11Decode(t, entries["manifest.json"], &saved)
	d11Require(t, len(saved) == 1 && len(saved[0].Layers) > 0 && len(saved[0].Layers) <= 128)
	config := entries[saved[0].Config]
	d11Require(t, len(config) > 0 && len(config) <= 1<<20 && hashed(config) == id)
	var cfg struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
		RootFS       struct {
			Type    string   `json:"type"`
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	d11Require(t, json.Unmarshal(config, &cfg) == nil && cfg.OS == "linux" && cfg.Architecture == "amd64" && cfg.Variant == "" && cfg.RootFS.Type == "layers" && cfg.Config.Labels["org.opencontainers.image.revision"] == commit && len(cfg.RootFS.DiffIDs) == len(saved[0].Layers))
	layers := make([][]byte, 0, len(saved[0].Layers))
	descriptors := make([]d11Descriptor, 0, len(saved[0].Layers))
	var total int64
	for i, name := range saved[0].Layers {
		b, ok := entries[name]
		d11Require(t, ok && len(b) > 0)
		if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
			z, e := gzip.NewReader(bytes.NewReader(b))
			d11Require(t, e == nil)
			b, e = io.ReadAll(io.LimitReader(z, (128<<20)+1))
			d11Require(t, e == nil && z.Close() == nil)
		}
		total += int64(len(b))
		d11Require(t, len(b) > 0 && len(b) <= 128<<20 && total <= 512<<20 && hashed(b) == cfg.RootFS.DiffIDs[i])
		layers = append(layers, b)
		descriptors = append(descriptors, d11Descriptor{"application/vnd.oci.image.layer.v1.tar", hashed(b), int64(len(b))})
	}
	d11Require(t, d11SavedLayerMetadata(saved[0], cfg.RootFS.DiffIDs, layers))
	manifest := encode(t, d11Graph{2, imageType, d11Descriptor{"application/vnd.oci.image.config.v1+json", id, int64(len(config))}, descriptors})
	return manifest, config, layers, cfg.RootFS.DiffIDs
}

func d11Client(t *testing.T, root string, registry bool) *http.Client {
	t.Helper()
	ca := "api-ca.pem"
	host := "api.fixture.invalid"
	port := "17821"
	if os.Getenv("CHENGWANG_D11_KIND") == "dsse" {
		port = "17822"
	}
	if registry {
		ca = "registry-ca.pem"
		host = "registry.fixture.invalid"
		port = "5443"
	}
	roots := x509.NewCertPool()
	d11Require(t, roots.AppendCertsFromPEM(d11Read(t, filepath.Join(root, ca), 256<<10)))
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: host, NextProtos: []string{"http/1.1"}}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" || addr != net.JoinHostPort(host, port) {
			return nil, fmt.Errorf("fixture destination rejected")
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 90 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func d11HTTP(t *testing.T, c *http.Client, method, target, token, contentType string, body []byte) (int, http.Header, []byte) {
	t.Helper()
	req, e := http.NewRequest(method, target, bytes.NewReader(body))
	d11Require(t, e == nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if (method == http.MethodGet || method == http.MethodHead) && req.URL.Scheme == "https" && req.URL.Host == "registry.fixture.invalid:5443" && req.URL.User == nil && req.URL.RawPath == "" && req.URL.RawQuery == "" && !req.URL.ForceQuery && req.URL.Fragment == "" && regexp.MustCompile(`^/v2/chengwang/product-candidate/manifests/sha256:[0-9a-f]{64}$`).MatchString(req.URL.Path) {
		req.Header.Set("Accept", imageType)
	}
	res, e := c.Do(req)
	d11Require(t, e == nil)
	defer res.Body.Close()
	limit := int64(128 << 20)
	if strings.HasPrefix(target, "https://api.fixture.invalid:") {
		limit = 4 << 20
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, limit+1))
	d11Require(t, e == nil && int64(len(raw)) <= limit)
	return res.StatusCode, res.Header.Clone(), raw
}
func d11Upload(t *testing.T, root, endpoint string, manifest, config []byte, layers [][]byte) {
	t.Helper()
	c := d11Client(t, root, true)
	prefix := "/v2/chengwang/product-candidate/"
	for _, b := range append([][]byte{config}, layers...) {
		status, h, _ := d11HTTP(t, c, "POST", d11Registry+prefix+"blobs/uploads/", "", "", nil)
		d11Require(t, status == 202)
		u, e := url.Parse(h.Get("Location"))
		d11Require(t, e == nil)
		base, _ := url.Parse(d11Registry)
		u = base.ResolveReference(u)
		d11Require(t, u.Scheme == "https" && u.Host == base.Host && u.User == nil && u.Fragment == "" && strings.HasPrefix(u.Path, prefix+"blobs/uploads/"))
		q := u.Query()
		q.Set("digest", hashed(b))
		u.RawQuery = q.Encode()
		status, h, _ = d11HTTP(t, c, "PUT", u.String(), "", "application/octet-stream", b)
		d11Require(t, status == 201 && h.Get("Docker-Content-Digest") == hashed(b))
	}
	status, h, _ := d11HTTP(t, c, "PUT", d11Registry+prefix+"manifests/"+hashed(manifest), "", imageType, manifest)
	d11Require(t, status == 201 && h.Get("Docker-Content-Digest") == hashed(manifest))
	// Graph proof is made from Registry readback bytes, not merely upload inputs.
	d11Mkdir(t, filepath.Join(endpoint, "graph"))
	d11Mkdir(t, filepath.Join(endpoint, "graph", "blobs"))
	status, h, b := d11HTTP(t, c, "GET", d11Registry+prefix+"manifests/"+hashed(manifest), "", "", nil)
	digestMatched, bytesMatched := h.Get("Docker-Content-Digest") == hashed(manifest), bytes.Equal(b, manifest)
	if status != 200 || !digestMatched || !bytesMatched {
		if status >= 100 && status <= 599 {
			fmt.Printf("D11_PRODUCT_REGISTRY_MANIFEST_READBACK status=%d digest_matches=%t bytes_match=%t\n", status, digestMatched, bytesMatched)
		}
	}
	d11Require(t, status == 200 && digestMatched && bytesMatched)
	d11Write(t, filepath.Join(endpoint, "graph", "manifest.json"), b)
	seen := map[string]bool{}
	for _, original := range append([][]byte{config}, layers...) {
		digest := hashed(original)
		if seen[digest] {
			continue
		}
		seen[digest] = true
		status, h, b = d11HTTP(t, c, "GET", d11Registry+prefix+"blobs/"+digest, "", "", nil)
		d11Require(t, status == 200 && h.Get("Docker-Content-Digest") == digest && bytes.Equal(b, original))
		d11Write(t, filepath.Join(endpoint, "graph", "blobs", strings.TrimPrefix(digest, "sha256:")), b)
	}
}

func d11Prepare(t *testing.T, root, kind, commit, id string) {
	t.Helper()
	endpoint := filepath.Join(root, kind)
	d11Mkdir(t, endpoint)
	d11Mkdir(t, filepath.Join(endpoint, "data"))
	manifest, config, layers, diffs := d11Archive(t, root, commit, id)
	fmt.Printf("D11_PRODUCT_REGISTRY_STAGE=archive-validated kind=%s\n", kind)
	d11Upload(t, root, endpoint, manifest, config, layers)
	fmt.Printf("D11_PRODUCT_REGISTRY_STAGE=uploaded-readback-matched kind=%s\n", kind)
	leaf, _ := pem.Decode(d11Read(t, filepath.Join(root, "registry-cert.pem"), 256<<10))
	d11Require(t, leaf != nil)
	cert, e := x509.ParseCertificate(leaf.Bytes)
	d11Require(t, e == nil)
	spki := hashed(cert.RawSubjectPublicKeyInfo)
	k := verifier.KindMessageSignature
	if kind == "dsse" {
		k = verifier.KindDSSE
	}
	// B is another valid OCI manifest, signed by the exact same PKI as A. No
	// corruption, unrelated issuer, or wrong trust root substitutes this test.
	crossManifest := append(bytes.Clone(manifest), '\n')
	bundle, crossBundle, trustRoot, expected, _ := signedBundlePair(t, k, manifest, crossManifest, d11Repository)
	materials := make([]managedMaterial, 0, 4)
	metadata := make([]d11Policy, 0, 4)
	for _, name := range []string{"accepted", "cross", "revoked", "spki"} {
		pin := spki
		if name == "spki" {
			pin = "sha256:" + strings.Repeat("1", 64)
			d11Require(t, pin != spki)
		}
		m := material{manifest: manifest, config: config, bundle: bundle, root: trustRoot, repository: d11Repository, reference: d11Repository + "@" + hashed(manifest)}
		approveImage(t, &m, expected, pin)
		var env struct {
			Payload   []byte `json:"payload"`
			Signature []byte `json:"signature"`
		}
		d11Decode(t, m.approval, &env)
		var payload map[string]any
		d11Require(t, json.Unmarshal(env.Payload, &payload) == nil)
		payload["policyID"] = "d11-" + name
		// This intermediate unsigned template is reissued by newManagedMaterial's
		// fresh authority before it can ever be stored or sent to the product.
		env.Payload = encode(t, payload)
		m.approval = encode(t, env)
		managed := newManagedMaterial(t, m)
		materials = append(materials, managed)
		sentBundle := bundle
		if name == "cross" {
			sentBundle = crossBundle
		}
		artifact := hashed(manifest)
		if name == "cross" {
			artifact = hashed(crossManifest)
		}
		p := d11Policy{Name: name, PolicyID: "d11-" + name, GrantID: managed.document.Grants[0].ID, ApprovalSHA256: managed.trust.PolicySHA256, ApprovalEnvelopeSHA256: hashed(managed.approval), BundleSHA256: hashed(sentBundle), BundleArtifactSHA256: artifact, TrustedRootSHA256: hashed(trustRoot), RegistrySPKI: pin}
		metadata = append(metadata, p)
		d11Write(t, filepath.Join(endpoint, name+"-approval.private.json"), managed.approval)
		d11Write(t, filepath.Join(endpoint, name+"-bundle.private.json"), sentBundle)
	}
	doc := materials[0].document
	for _, m := range materials[1:] {
		doc.Approvers = append(doc.Approvers, m.document.Approvers...)
		doc.Grants = append(doc.Grants, m.document.Grants...)
		for key, v := range m.document.PolicyFloors {
			doc.PolicyFloors[key] = v
		}
	}
	cat1 := signManagedCatalogue(t, doc, materials[0].rootKey)
	anchor := materials[0].anchor
	anchor.InitialSHA256 = hashed(cat1)
	_, e = trustcatalog.Replay(anchor, [][]byte{cat1})
	d11Require(t, e == nil)
	doc.Generation = 2
	doc.Grants = append(append([]trustcatalog.Grant{}, doc.Grants[:2]...), doc.Grants[3:]...)
	doc.RevokedApprovals = []string{metadata[2].ApprovalSHA256}
	cat2 := signManagedCatalogue(t, doc, materials[0].rootKey)
	_, e = trustcatalog.Replay(anchor, [][]byte{cat1, cat2})
	d11Require(t, e == nil)
	fmt.Printf("D11_PRODUCT_REGISTRY_STAGE=signed-catalogues-validated kind=%s\n", kind)
	d11Write(t, filepath.Join(endpoint, "catalogue1.private.json"), cat1)
	d11Write(t, filepath.Join(endpoint, "catalogue2.private.json"), cat2)
	d11Write(t, filepath.Join(endpoint, "trusted-root.private.json"), trustRoot)
	d11JSON(t, filepath.Join(endpoint, "anchor.json"), anchor)
	for _, name := range []string{"api-ca.pem", "api-cert.pem", "api-key.private.pem", "registry-ca.pem"} {
		d11Write(t, filepath.Join(endpoint, name), d11Read(t, filepath.Join(root, name), 256<<10))
	}
	store, e := truststate.Create(context.Background(), filepath.Join(endpoint, "trust"), anchor, cat1)
	d11Require(t, e == nil && store.Close() == nil)
	fmt.Printf("D11_PRODUCT_REGISTRY_STAGE=store-created kind=%s\n", kind)
	audit, e := evidence.Open(filepath.Join(endpoint, "data", "evidence"))
	d11Require(t, e == nil && audit.Close() == nil)
	scope := authz.ResourceScope{TenantID: "d11-tenant", SiteID: "d11-site", ObjectType: "image-trust", ObjectID: anchor.StoreID, Environment: "candidate"}
	management := scope
	management.ObjectType = "control-plane"
	management.ObjectID = "d11-management"
	token, tokenHash, e := authn.GenerateToken(32)
	d11Require(t, e == nil)
	d11Write(t, filepath.Join(endpoint, "admin-token.private"), []byte(token))
	d11JSON(t, filepath.Join(endpoint, "identities.json"), authn.File{Version: authn.FileVersion, Identities: []authn.Identity{{TokenID: "d11-admin-token", TokenHash: tokenHash, Principal: authz.Principal{ID: "d11-admin", TenantID: scope.TenantID, Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{scope, management}}}}})
	port := "17821"
	if kind == "dsse" {
		port = "17822"
	}
	addr := "127.0.0.1:" + port
	common := map[string]any{"addr": addr, "identitiesFile": filepath.Join(endpoint, "identities.json"), "tlsCertFile": filepath.Join(endpoint, "api-cert.pem"), "tlsKeyFile": filepath.Join(endpoint, "api-key.private.pem"), "tenantId": scope.TenantID, "siteId": scope.SiteID, "environment": "candidate"}
	trustConfig := map[string]any{}
	for key, v := range common {
		trustConfig[key] = v
	}
	trustConfig["storePath"] = filepath.Join(endpoint, "trust")
	trustConfig["anchorFile"] = filepath.Join(endpoint, "anchor.json")
	trustConfig["auditDir"] = filepath.Join(endpoint, "data", "evidence")
	trustConfig["registryCAFile"] = filepath.Join(endpoint, "registry-ca.pem")
	trustConfig["writesEnabled"] = true
	trustConfig["webDir"] = "/app/web"
	d11JSON(t, filepath.Join(endpoint, "trust-config.json"), trustConfig)
	common["dataDir"] = filepath.Join(endpoint, "data")
	common["managementObjectId"] = management.ObjectID
	d11JSON(t, filepath.Join(endpoint, "product-config.json"), common)
	info := d11Material{Kind: kind, SourceCommit: commit, LocalImageID: id, ManifestSHA256: hashed(manifest), ConfigSHA256: hashed(config), DiffIDs: diffs, Catalogue1SHA256: hashed(cat1), Catalogue2SHA256: hashed(cat2), StoreID: anchor.StoreID, Anchor: anchor, Policies: metadata, LayerSHA256s: []string{}}
	for _, b := range layers {
		info.LayerSHA256s = append(info.LayerSHA256s, hashed(b))
	}
	d11JSON(t, filepath.Join(endpoint, "materials.private.json"), info)
	r := d11NewReport(info, "prepare", 0)
	d11SaveReport(t, root, kind, "prepare", r)
	fmt.Printf("D11_PRODUCT_REGISTRY_PREPARE=PASS kind=%s authorization=BLOCKED production=false\n", kind)
}

func d11NewReport(info d11Material, action string, n int) d11Report {
	return d11Report{Schema: "chengwang.product-registry-action/v1", Action: action, Case: n, d11Material: info, Authority: "EPHEMERAL_TEST_ONLY", GraphOrigin: "NORMAL_TLS_REGISTRY_READBACK_MATCHED_UPLOAD", Authorization: "BLOCKED", Cases: []d11Case{}}
}
func d11Info(t *testing.T, root, kind, commit, id string) d11Material {
	t.Helper()
	var info d11Material
	d11Decode(t, d11Read(t, filepath.Join(root, kind, "materials.private.json"), 256<<10), &info)
	d11Decode(t, d11Read(t, filepath.Join(root, kind, "anchor.json"), 8<<10), &info.Anchor)
	d11Require(t, info.Kind == kind && info.SourceCommit == commit && info.LocalImageID == id && info.ConfigSHA256 == id && len(info.Policies) == 4 && reflect.DeepEqual(info.LayerSHA256s, info.DiffIDs))
	d11Require(t, info.StoreID == info.Anchor.StoreID && info.Anchor.InitialSHA256 == info.Catalogue1SHA256)
	return info
}
func d11ReportPath(root, kind, action string) string {
	return filepath.Join(root, "evidence", "product-registry-"+kind+"-"+action+".json")
}
func d11SaveReport(t *testing.T, root, kind, action string, r d11Report) {
	t.Helper()
	d11Dir(t, filepath.Join(root, "evidence"))
	d11JSON(t, d11ReportPath(root, kind, action), r)
}
func d11LoadReport(t *testing.T, root, kind, action string) d11Report {
	t.Helper()
	var r d11Report
	d11Decode(t, d11Read(t, d11ReportPath(root, kind, action), 2<<20), &r)
	d11Require(t, r.Schema == "chengwang.product-registry-action/v1" && r.Kind == kind && r.Authorization == "BLOCKED" && !r.Production && !r.DeviceActionsExecuted)
	return r
}
func d11APIBase(kind string) string {
	if kind == "dsse" {
		return "https://api.fixture.invalid:17822"
	}
	return "https://api.fixture.invalid:17821"
}
func d11Snapshot(t *testing.T, c *http.Client, root, kind, token string) (imagetrust.Status, imagetrust.History) {
	t.Helper()
	var s imagetrust.Status
	var h imagetrust.History
	status, _, b := d11HTTP(t, c, "GET", d11APIBase(kind)+"/api/v1/image-trust", token, "", nil)
	d11Require(t, status == 200)
	d11Decode(t, b, &s)
	status, _, b = d11HTTP(t, c, "GET", d11APIBase(kind)+"/api/v1/image-trust/history?limit=50", token, "", nil)
	d11Require(t, status == 200)
	d11Decode(t, b, &h)
	d11Require(t, s.Boundary == imagetrust.StatusBoundary && s.Authorization == "BLOCKED" && !s.DeviceActionsExecuted && s.Healthy && s.Fresh && h.Boundary == imagetrust.HistoryBoundary && h.Authorization == "BLOCKED" && !h.DeviceActionsExecuted && h.Sequence == s.Sequence && h.Total == len(h.Entries))
	for _, e := range h.Entries {
		d11Require(t, e.Acknowledged && len(e.PreparedAuditHash) == 64 && len(e.ResultAuditHash) == 64)
	}
	return s, h
}
func d11CheckState(t *testing.T, s imagetrust.Status, h imagetrust.History, seq, gen uint64, ledger, reserved, journal int, cat string) {
	t.Helper()
	d11Require(t, s.Sequence == seq && s.Generation == gen && s.CatalogueSHA256 == cat && s.LedgerEntries == ledger && s.Reserved == reserved && s.Consumed == 1 && h.Total == journal && h.Sequence == seq)
}

func d11Call(t *testing.T, c *http.Client, root, kind, token string, info d11Material, name, method, route string, body []byte, pol *d11Policy, wantStatus int) d11Case {
	t.Helper()
	r := d11Case{Name: name, Method: method, Path: route, RequestSHA256: hashed(body)}
	if pol != nil {
		r.PolicyID = pol.PolicyID
		r.GrantID = pol.GrantID
		r.ApprovalSHA256 = pol.ApprovalSHA256
		r.ApprovalEnvelopeSHA256 = pol.ApprovalEnvelopeSHA256
		r.BundleSHA256 = pol.BundleSHA256
		r.TrustedRootSHA256 = pol.TrustedRootSHA256
	}
	r.StatusBefore, r.HistoryBefore = d11Snapshot(t, c, root, kind, token)
	// Reject an out-of-order/repeated request before any mutating HTTP call.
	type expectedState struct {
		sequence, generation      uint64
		ledger, reserved, journal int
	}
	before := map[string]expectedState{
		"success": {1, 1, 0, 0, 0}, "replay": {6, 1, 1, 0, 1}, "approval-tamper": {10, 1, 1, 0, 2}, "crossed-bundle": {14, 1, 1, 0, 3},
		"replay-after-restart": {19, 1, 2, 1, 4}, "revocation-install": {23, 1, 2, 1, 5}, "rollback-rejected": {27, 2, 2, 1, 6},
		"revoked-unused": {31, 2, 2, 1, 7}, "wrong-spki": {35, 2, 2, 1, 8}, "reserved-replay": {40, 2, 3, 2, 9},
	}
	ex, ok := before[name]
	d11Require(t, ok)
	cat := info.Catalogue1SHA256
	if ex.generation == 2 {
		cat = info.Catalogue2SHA256
	}
	d11Require(t, r.StatusBefore.StoreID == info.Anchor.StoreID && r.StatusBefore.Sequence == ex.sequence && r.StatusBefore.Generation == ex.generation && r.StatusBefore.CatalogueSHA256 == cat && r.StatusBefore.LedgerEntries == ex.ledger && r.StatusBefore.Reserved == ex.reserved && r.HistoryBefore.Total == ex.journal)
	status, _, raw := d11HTTP(t, c, method, d11APIBase(kind)+route, token, "application/json", body)
	r.HTTPStatus = status
	d11Require(t, status == wantStatus)
	if status == 400 {
		var failure struct {
			Boundary              string `json:"boundary"`
			Authorization         string `json:"authorization"`
			DeviceActionsExecuted bool   `json:"deviceActionsExecuted"`
			Code                  string `json:"code"`
			StateMayHaveChanged   bool   `json:"stateMayHaveChanged"`
		}
		d11Decode(t, raw, &failure)
		d11Require(t, failure.Boundary == imagetrust.StatusBoundary && failure.Authorization == "BLOCKED" && !failure.DeviceActionsExecuted && failure.Code == "image_trust_invalid" && failure.StateMayHaveChanged)
		r.ErrorCode = failure.Code
		r.StateMayHaveChanged = failure.StateMayHaveChanged
	} else if route == d11VerifyPath {
		var receipt imagetrust.Receipt
		d11Decode(t, raw, &receipt)
		d11Require(t, pol != nil && receipt.Boundary == imagetrust.VerifiedBoundary && receipt.Authorization == "BLOCKED" && !receipt.DeviceActionsExecuted && receipt.Verified && receipt.GrantID == pol.GrantID && receipt.ManifestSHA256 == info.ManifestSHA256 && receipt.CatalogueSHA256 == info.Catalogue1SHA256 && receipt.Generation == 1 && regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(receipt.EvidenceSHA256))
		r.Receipt = &receipt
	} else {
		var s imagetrust.Status
		d11Decode(t, raw, &s)
		d11Require(t, s.Generation == 2 && s.CatalogueSHA256 == info.Catalogue2SHA256 && s.Authorization == "BLOCKED" && !s.DeviceActionsExecuted)
	}
	r.StatusAfter, r.HistoryAfter = d11Snapshot(t, c, root, kind, token)
	d11Require(t, r.StatusAfter.StoreID == info.Anchor.StoreID && r.HistoryAfter.Total == r.HistoryBefore.Total+1)
	return r
}

func d11Exercise(t *testing.T, root, kind, commit, id, action string, n int) {
	t.Helper()
	info := d11Info(t, root, kind, commit, id)
	endpoint := filepath.Join(root, kind)
	d11Write(t, filepath.Join(endpoint, "intent-"+action+"-"+strconv.Itoa(n)+".private"), []byte("SINGLE_ATTEMPT_ONLY\n"))
	// Immutable reports are the ordering fence. A failed/partial action is never
	// retried, re-signed, or blessed by changing expected state.
	previous := "prepare"
	if n > 1 {
		previous = action + "-" + strconv.Itoa(n-1)
	} else if action == "resume" {
		previous = "verify-first"
	}
	d11LoadReport(t, root, kind, previous)
	if action == "resume" && n == 2 {
		d11LoadReport(t, root, kind, "catalogue")
	}
	pidx := 0
	names := []string{"success", "replay", "approval-tamper", "crossed-bundle"}
	want := 400
	if action == "exercise" {
		if n == 1 {
			want = 200
		}
		if n == 4 {
			pidx = 1
		}
	} else {
		names = []string{"replay-after-restart", "revoked-unused", "wrong-spki", "reserved-replay"}
		pidx = []int{0, 2, 3, 1}[n-1]
	}
	pol := info.Policies[pidx]
	approval := d11Read(t, filepath.Join(endpoint, pol.Name+"-approval.private.json"), 64<<10)
	bundle := d11Read(t, filepath.Join(endpoint, pol.Name+"-bundle.private.json"), 1<<20)
	trustRoot := d11Read(t, filepath.Join(endpoint, "trusted-root.private.json"), 1<<20)
	d11Require(t, hashed(approval) == pol.ApprovalEnvelopeSHA256 && hashed(bundle) == pol.BundleSHA256 && hashed(trustRoot) == pol.TrustedRootSHA256)
	if action == "exercise" && n == 3 {
		var envelope struct {
			Payload   []byte `json:"payload"`
			Signature []byte `json:"signature"`
		}
		d11Decode(t, approval, &envelope)
		d11Require(t, len(envelope.Signature) == 64)
		envelope.Signature[0] ^= 1
		approval = encode(t, envelope)
		pol.ApprovalEnvelopeSHA256 = hashed(approval)
	}
	body := encode(t, imagetrust.VerifyRequest{PolicyID: pol.PolicyID, Approval: approval, Bundle: bundle, TrustedRoot: trustRoot})
	c := d11Client(t, root, false)
	token := string(d11Read(t, filepath.Join(endpoint, "admin-token.private"), 512))
	result := d11Call(t, c, root, kind, token, info, names[n-1], "POST", d11VerifyPath, body, &pol, want)
	if action == "exercise" {
		seq := []uint64{6, 10, 14, 19}[n-1]
		ledger, reserved := 1, 0
		if n == 4 {
			ledger = 2
			reserved = 1
		}
		d11CheckState(t, result.StatusAfter, result.HistoryAfter, seq, 1, ledger, reserved, n, info.Catalogue1SHA256)
	} else {
		seq := []uint64{23, 35, 40, 44}[n-1]
		ledger, reserved := 2, 1
		if n >= 3 {
			ledger = 3
			reserved = 2
		}
		journal := []int{5, 8, 9, 10}[n-1]
		if n == 1 {
			d11CheckState(t, result.StatusAfter, result.HistoryAfter, 23, 1, 2, 1, 5, info.Catalogue1SHA256)
		} else {
			d11CheckState(t, result.StatusAfter, result.HistoryAfter, seq, 2, ledger, reserved, journal, info.Catalogue2SHA256)
		}
	}
	r := d11NewReport(info, action, n)
	r.Cases = append(r.Cases, result)
	d11SaveReport(t, root, kind, action+"-"+strconv.Itoa(n), r)
	if n == 4 {
		all := d11NewReport(info, action, 0)
		for i := 1; i <= 4; i++ {
			part := d11LoadReport(t, root, kind, action+"-"+strconv.Itoa(i))
			all.Cases = append(all.Cases, part.Cases...)
		}
		d11SaveReport(t, root, kind, action, all)
	}
	fmt.Printf("D11_PRODUCT_REGISTRY_%s=PASS kind=%s case=%d authorization=BLOCKED production=false\n", strings.ToUpper(action), kind, n)
}
func d11Catalogue(t *testing.T, root, kind, commit, id string) {
	t.Helper()
	info := d11Info(t, root, kind, commit, id)
	d11LoadReport(t, root, kind, "resume-1")
	c := d11Client(t, root, false)
	endpoint := filepath.Join(root, kind)
	d11Write(t, filepath.Join(endpoint, "intent-catalogue.private"), []byte("SINGLE_ATTEMPT_ONLY\n"))
	token := string(d11Read(t, filepath.Join(endpoint, "admin-token.private"), 512))
	r := d11NewReport(info, "catalogue", 0)
	for i, name := range []string{"revocation-install", "rollback-rejected"} {
		file := "catalogue2.private.json"
		want := 200
		if i == 1 {
			file = "catalogue1.private.json"
			want = 400
		}
		body := d11Read(t, filepath.Join(endpoint, file), 256<<10)
		expected := info.Catalogue2SHA256
		if i == 1 {
			expected = info.Catalogue1SHA256
		}
		d11Require(t, hashed(body) == expected)
		result := d11Call(t, c, root, kind, token, info, name, "PUT", d11CataloguePath, body, nil, want)
		d11CheckState(t, result.StatusAfter, result.HistoryAfter, uint64(27+i*4), 2, 2, 1, 6+i, info.Catalogue2SHA256)
		r.Cases = append(r.Cases, result)
	}
	d11SaveReport(t, root, kind, "catalogue", r)
	fmt.Printf("D11_PRODUCT_REGISTRY_CATALOGUE=PASS kind=%s authorization=BLOCKED production=false\n", kind)
}

func d11Reopen(t *testing.T, root, kind, commit, id string) {
	t.Helper()
	info := d11Info(t, root, kind, commit, id)
	phase := "first"
	expected := d11LoadReport(t, root, kind, "exercise")
	if _, e := os.Lstat(d11ReportPath(root, kind, "resume")); e == nil {
		phase = "final"
		expected = d11LoadReport(t, root, kind, "resume")
	}
	d11Require(t, len(expected.Cases) == 4)
	last := expected.Cases[3]
	endpoint := filepath.Join(root, kind)
	store, e := truststate.Open(context.Background(), filepath.Join(endpoint, "trust"), info.Anchor)
	d11Require(t, e == nil)
	defer store.Close()
	inspection, e := store.Inspect(context.Background())
	d11Require(t, e == nil)
	journal, e := store.Journal(context.Background())
	d11Require(t, e == nil && len(journal) == last.HistoryAfter.Total)
	audit, e := evidence.Open(filepath.Join(endpoint, "data", "evidence"))
	d11Require(t, e == nil)
	defer audit.Close()
	proof, e := audit.Verify()
	d11Require(t, e == nil && proof.Valid && proof.Count == uint64(2*len(journal)) && proof.Count == proof.ExpectedCount && proof.LastHash == proof.ExpectedLastHash)
	view, e := audit.RecoverySnapshot()
	d11Require(t, e == nil)
	reserved, consumed := 0, 0
	for _, l := range inspection.Consumptions {
		switch l.Status {
		case "RESERVED":
			reserved++
		case "CONSUMED":
			consumed++
		default:
			d11Require(t, false)
		}
		d11Require(t, l.ManifestSHA256 == info.ManifestSHA256)
		if l.Status == "CONSUMED" {
			d11Require(t, l.GrantID == info.Policies[0].GrantID && l.EvidenceSHA256 == expectedReceipt(t, root, kind))
		}
	}
	d11Require(t, inspection.Authorization == "BLOCKED" && inspection.CatalogueValid && inspection.Sequence == last.StatusAfter.Sequence && inspection.Catalogue.Generation == last.StatusAfter.Generation && inspection.Catalogue.SHA256 == last.StatusAfter.CatalogueSHA256 && inspection.LedgerUsed == last.StatusAfter.LedgerEntries && reserved == last.StatusAfter.Reserved && consumed == last.StatusAfter.Consumed)
	for i, entry := range journal {
		base, ok := view.HashAt(entry.Operation.AuditBaseCount)
		d11Require(t, ok && base == entry.Operation.AuditBaseHash && entry.Operation.AuditBaseCount == uint64(2*i))
		prepared, ok := view.Lookup("image-trust/" + entry.Operation.ID + "/prepared")
		d11Require(t, ok && prepared.Hash == entry.Operation.PreparedAuditHash && prepared.TraceID == entry.Operation.ID && prepared.Action == "image_trust."+entry.Operation.Kind && prepared.Result == "prepared" && d11SameData(prepared.Data, entry.Operation.Data))
		result, ok := view.Lookup("image-trust/" + entry.Operation.ID + "/result")
		resultName := "rejected"
		switch entry.Outcome {
		case truststate.OutcomeCatalogueCommitted:
			resultName = "completed"
		case truststate.OutcomeVerificationConsumed:
			resultName = "verification_consumed"
		}
		scope := authz.ResourceScope{TenantID: "d11-tenant", SiteID: "d11-site", ObjectType: "image-trust", ObjectID: info.Anchor.StoreID, Environment: "candidate"}
		d11Require(t, entry.Operation.ScopeSHA256 == hashed(encode(t, scope)) && prepared.ActorID == "d11-admin" && result.ActorID == prepared.ActorID && prepared.Target == "image-trust/"+info.Anchor.StoreID && result.Target == prepared.Target && result.Result == resultName)
		d11Require(t, ok && entry.Acknowledged && result.Hash == entry.ResultAuditHash && result.TraceID == entry.Operation.ID && result.Action == prepared.Action && d11SameData(result.Data, entry.OutcomeData))
		h := last.HistoryAfter.Entries[len(journal)-1-i]
		// Bind each operation by ID, rather than trusting pagination order.
		found := false
		for _, candidate := range last.HistoryAfter.Entries {
			if candidate.OperationID == entry.Operation.ID {
				h = candidate
				found = true
				break
			}
		}
		d11Require(t, found && h.Acknowledged && h.State == entry.State && h.Outcome == entry.Outcome && h.PreparedAuditHash == entry.Operation.PreparedAuditHash && h.ResultAuditHash == entry.ResultAuditHash)
	}
	r := d11NewReport(info, "verify-"+phase, 0)
	r.Inspection = &inspection
	r.Journal = journal
	r.Audit = &proof
	r.JournalAuditBindingsVerified = true
	d11SaveReport(t, root, kind, "verify-"+phase, r)
	d11Require(t, store.Close() == nil && audit.Close() == nil)
	fmt.Printf("D11_PRODUCT_REGISTRY_VERIFY=PASS kind=%s phase=%s authorization=BLOCKED production=false\n", kind, phase)
}
func expectedReceipt(t *testing.T, root, kind string) string {
	t.Helper()
	r := d11LoadReport(t, root, kind, "exercise-1")
	d11Require(t, len(r.Cases) == 1 && r.Cases[0].Receipt != nil)
	return r.Cases[0].Receipt.EvidenceSHA256
}

// Deliberately independent of TestProductRegistryD11Fixture and its root/env.
// Synthetic metadata success is never evidence of an actual image/API read.
func TestProductRegistryD11DockerSaveMetadata(t *testing.T) {
	layer := []byte("synthetic Docker-save layer metadata test; not a runnable image")
	diffID := hashed(layer)
	layers := [][]byte{layer}
	diffIDs := []string{diffID}
	base := d11SavedImage{Config: "config.json", RepoTags: []string{}, Layers: []string{"layer.tar"}, LayerSources: map[string]d11SavedLayerSource{diffID: {MediaType: "application/vnd.oci.image.layer.v1.tar", Digest: diffID, Size: int64(len(layer))}}}
	secondLayer := []byte("second synthetic Docker-save layer; never executed")
	secondID := hashed(secondLayer)
	twoLayers := [][]byte{layer, secondLayer}
	twoIDs := []string{diffID, secondID}
	twoSources := func(v *d11SavedImage) {
		v.Layers = []string{"layer.tar", "second.tar"}
		v.LayerSources[secondID] = d11SavedLayerSource{MediaType: "application/vnd.oci.image.layer.v1.tar", Digest: secondID, Size: int64(len(secondLayer))}
	}
	type sample struct {
		name   string
		change func(*d11SavedImage)
		raw    []byte
		want   bool
		diffs  []string
		layers [][]byte
	}
	cases := []sample{
		{name: "legacy-no-helpers", change: func(v *d11SavedImage) { v.LayerSources = nil }, want: true},
		{name: "matching-local-source", want: true},
		{name: "nonempty-parent", change: func(v *d11SavedImage) { v.Parent = diffID }},
		{name: "missing-source", raw: []byte(`[{"Config":"config.json","RepoTags":[],"Layers":["layer.tar"],"LayerSources":{}}]`)},
		{name: "extra-source", change: func(v *d11SavedImage) { v.LayerSources[hashed([]byte("other"))] = v.LayerSources[diffID] }},
		{name: "wrong-source-digest", change: func(v *d11SavedImage) {
			s := v.LayerSources[diffID]
			s.Digest = hashed([]byte("wrong"))
			v.LayerSources[diffID] = s
		}},
		{name: "wrong-source-size", change: func(v *d11SavedImage) { s := v.LayerSources[diffID]; s.Size++; v.LayerSources[diffID] = s }},
		{name: "wrong-source-media-type", change: func(v *d11SavedImage) {
			s := v.LayerSources[diffID]
			s.MediaType = "application/vnd.oci.image.layer.v1.tar+gzip"
			v.LayerSources[diffID] = s
		}},
		{name: "foreign-url", change: func(v *d11SavedImage) {
			s := v.LayerSources[diffID]
			s.URLs = []string{"https://unreachable.invalid/layer"}
			v.LayerSources[diffID] = s
		}},
		{name: "platform", change: func(v *d11SavedImage) {
			s := v.LayerSources[diffID]
			s.Platform = json.RawMessage(`{"os":"linux"}`)
			v.LayerSources[diffID] = s
		}},
		{name: "annotation", change: func(v *d11SavedImage) {
			s := v.LayerSources[diffID]
			s.Annotations = map[string]string{"untrusted": "value"}
			v.LayerSources[diffID] = s
		}},
		{name: "unknown-outer-field", raw: []byte(`[{"Config":"config.json","RepoTags":[],"Layers":["layer.tar"],"Unknown":true}]`)},
		{name: "unknown-source-field", raw: []byte(fmt.Sprintf(`[{"Config":"config.json","RepoTags":[],"Layers":["layer.tar"],"LayerSources":{%q:{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":%q,"size":%d,"Unknown":true}}}]`, diffID, diffID, len(layer)))},
		{name: "source-key-not-diff-id", change: func(v *d11SavedImage) {
			s := v.LayerSources[diffID]
			delete(v.LayerSources, diffID)
			v.LayerSources[hashed([]byte("wrong-key"))] = s
		}},
		{name: "two-layer-ordered", change: twoSources, want: true, diffs: twoIDs, layers: twoLayers},
		{name: "two-layer-order-swapped", change: twoSources, diffs: twoIDs, layers: [][]byte{secondLayer, layer}},
		{name: "two-layer-source-missing-one", change: func(v *d11SavedImage) {
			twoSources(v)
			delete(v.LayerSources, secondID)
		}, diffs: twoIDs, layers: twoLayers},
	}
	d11Require(t, len(cases) == 17)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			raw := test.raw
			if raw == nil {
				var value d11SavedImage
				d11Decode(t, encode(t, base), &value)
				if test.change != nil {
					test.change(&value)
				}
				raw = encode(t, []d11SavedImage{value})
			}
			caseDiffs, caseLayers := test.diffs, test.layers
			if caseDiffs == nil {
				caseDiffs, caseLayers = diffIDs, layers
			}
			if d11SavedMetadataAccepts(raw, caseDiffs, caseLayers) != test.want {
				t.Fatal("synthetic Docker-save metadata boundary mismatch")
			}
		})
	}
	if t.Failed() {
		return
	}
	fmt.Println("D11_DOCKER_SAVE_METADATA=PASS cases=17 synthetic=true actual_registry_not_proven=true authorization=BLOCKED production=false")
}

type d11HeaderRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip d11HeaderRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

// A synthetic request-construction test only. Its transport cannot dial, and
// neither a successful header check nor its fake response proves Registry IO.
func TestProductRegistryD11ManifestAcceptHeader(t *testing.T) {
	digest := hashed([]byte("synthetic header target"))
	cases := []struct{ name, method, target, accept string }{
		{"manifest-get", http.MethodGet, d11Registry + "/v2/chengwang/product-candidate/manifests/" + digest, imageType},
		{"manifest-head", http.MethodHead, d11Registry + "/v2/chengwang/product-candidate/manifests/" + digest, imageType},
		{"blob-get", http.MethodGet, d11Registry + "/v2/chengwang/product-candidate/blobs/" + digest, ""},
		{"api-post", http.MethodPost, d11APIBase("message-signature") + d11VerifyPath, ""},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: d11HeaderRoundTripper(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != test.method || request.URL.String() != test.target || request.Header.Get("Accept") != test.accept {
					t.Fatal("synthetic manifest Accept scope mismatch")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
			})}
			status, _, body := d11HTTP(t, client, test.method, test.target, "", "", nil)
			if status != 200 || calls != 1 || len(body) != 0 {
				t.Fatal("synthetic header transport mismatch")
			}
		})
	}
	if t.Failed() {
		return
	}
	fmt.Println("D11_MANIFEST_ACCEPT_HEADER=PASS cases=4 synthetic=true actual_registry_not_proven=true authorization=BLOCKED production=false")
}
