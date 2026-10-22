package binding_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	verifier "chengwang-image-verifier"
	"chengwang/image-binding/policy"
)

const fixtureIssuer = "https://issuer.fixture.invalid"
const fixtureIdentity = "builder@fixture.invalid"
const imageType = "application/vnd.oci.image.manifest.v1+json"

type material struct {
	manifest, config, layer, bundle, root, approval []byte
	trust                                           policy.Trust
	reference, repository                           string
}

func hashed(raw []byte) string { h := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(h[:]) }
func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// All bytes and approval keys are generated only for isolated tests. Signing
// PKI and verification are real; none of these identities approve a release.
func signedImage(t *testing.T, endpoint string, kind verifier.Kind, registrySPKI string) material {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	m := material{repository: u.Host + "/chengwang/fixture"}
	var layer bytes.Buffer
	w := tar.NewWriter(&layer)
	content := []byte("Chengwang isolated Registry acceptance fixture\n")
	if err := w.WriteHeader(&tar.Header{Name: "fixture.txt", Mode: 0644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	m.layer = layer.Bytes()
	m.config = encode(t, map[string]any{"architecture": "amd64", "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{hashed(m.layer)}}, "config": map[string]any{"Env": []string{"SECRET_FIXTURE=DO_NOT_PROJECT_CONFIG"}}})
	descriptor := func(media string, raw []byte) map[string]any {
		return map[string]any{"mediaType": media, "digest": hashed(raw), "size": len(raw)}
	}
	m.manifest = encode(t, map[string]any{"schemaVersion": 2, "mediaType": imageType, "config": descriptor("application/vnd.oci.image.config.v1+json", m.config), "layers": []any{descriptor("application/vnd.oci.image.layer.v1.tar", m.layer)}})
	m.reference = m.repository + "@" + hashed(m.manifest)
	var expected verifier.Expected
	m.bundle, m.root, expected = signedBundle(t, kind, m.manifest, m.repository)
	approveImage(t, &m, expected, registrySPKI)
	return m
}

// approveImage approves only the selected material/Expected pair for an
// isolated test. Its ephemeral approver key is not product release authority.
func approveImage(t *testing.T, m *material, expected verifier.Expected, registrySPKI string) {
	t.Helper()
	if m == nil || expected.ArtifactSHA256 != hashed(m.manifest) || m.reference != m.repository+"@"+expected.ArtifactSHA256 {
		t.Fatal("fixture approval does not match the selected image")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	sigPolicy := map[string]any{"kind": string(expected.Kind), "artifactSHA256": expected.ArtifactSHA256, "trustedRootSHA256": expected.TrustedRootSHA256, "logID": expected.LogID, "issuer": expected.Issuer, "san": expected.SAN}
	if expected.Kind == verifier.KindDSSE {
		sigPolicy["subjectName"] = expected.SubjectName
		sigPolicy["predicateType"] = expected.PredicateType
	}
	doc := encode(t, map[string]any{"schema": policy.Schema, "policyID": "isolated-fixture", "revision": 1, "approverKeyID": "isolated-test-authority", "notBeforeUnix": now - 10, "notAfterUnix": now + 300, "reference": m.reference, "os": "linux", "architecture": "amd64", "variant": "", "registryIPs": []string{"127.0.0.1"}, "registrySPKISHA256": registrySPKI, "signature": sigPolicy})
	m.trust = policy.Trust{KeyID: "isolated-test-authority", PublicKey: public, PolicySHA256: hashed(doc), Revision: 1}
	m.approval = encode(t, map[string]any{"payload": doc, "signature": ed25519.Sign(private, append([]byte(policy.Schema+"\x00"), doc...))})
	if _, err := policy.Verify(context.Background(), m.trust, m.approval, time.Now()); err != nil {
		t.Fatal("fixture approval rejected", err)
	}
}

// Uploads are fixture preparation only. Product Read/Bind has no write path.
func uploadImage(t *testing.T, client *http.Client, endpoint string, m material) {
	t.Helper()
	base, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, blob := range [][]byte{m.config, m.layer} {
		req, err := http.NewRequest(http.MethodPost, endpoint+"/v2/chengwang/fixture/blobs/uploads/", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		location := resp.Header.Get("Location")
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("fixture upload start: %d", resp.StatusCode)
		}
		u, err := url.Parse(location)
		if err != nil {
			t.Fatal(err)
		}
		u = base.ResolveReference(u)
		if u.Scheme != base.Scheme || u.Host != base.Host || !strings.HasPrefix(u.Path, "/v2/chengwang/fixture/blobs/uploads/") {
			t.Fatal("fixture upload escaped isolated Registry")
		}
		query := u.Query()
		query.Set("digest", hashed(blob))
		u.RawQuery = query.Encode()
		req, err = http.NewRequest(http.MethodPut, u.String(), bytes.NewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("fixture upload blob: %d", resp.StatusCode)
		}
	}
	req, err := http.NewRequest(http.MethodPut, endpoint+"/v2/chengwang/fixture/manifests/"+hashed(m.manifest), bytes.NewReader(m.manifest))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", imageType)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		t.Fatal(fmt.Sprintf("fixture manifest upload status=%d: %s", resp.StatusCode, body))
	}
}
