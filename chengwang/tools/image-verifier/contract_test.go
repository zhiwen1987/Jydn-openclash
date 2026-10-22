package verifier

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

func TestStrictJSONBudgetsAndAmbiguity(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"depth", []byte(`{"a":` + strings.Repeat(`[`, maxJSONDepth+1) + `1` + strings.Repeat(`]`, maxJSONDepth+1) + `}`)},
		{"nodes", []byte(`{"a":[` + strings.Repeat(`0,`, maxJSONNodes) + `0]}`)},
		{"escaped_duplicate", []byte(`{"a":1,"\u0061":2}`)},
		{"invalid_utf8", []byte{'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'}},
		{"unpaired_surrogate_key", []byte(`{"\ud800":1}`)},
		{"unpaired_surrogate_value", []byte(`{"a":"\udc00"}`)},
		{"null", []byte(`{"a":null}`)},
		{"trailing", []byte(`{} {}`)},
		{"mismatched_array", []byte(`{"a":[1}}`)},
		{"missing_colon", []byte(`{"a" 1}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := strictJSON(tc.raw); err != ErrInvalid {
				t.Fatalf("invalid input accepted: %v", err)
			}
		})
	}
	if _, err := strictJSON([]byte(`{"a":[true,false,0,"value",{}],"b":{"c":1}}`)); err != nil {
		t.Fatal("valid bounded JSON rejected")
	}
}

func TestOpaqueResultCannotBeImported(t *testing.T) {
	var r Result
	if err := json.Unmarshal([]byte(`{"verified":true,"artifactHash":"forged","boundary":"ADVISORY_SIGSTORE_BUNDLE_VERIFIED","authorization":"ALLOWED"}`), &r); err != nil {
		t.Fatal(err)
	}
	if r != (Result{}) || r.Verified() || r.Boundary() != "" || r.Authorization() != "BLOCKED" {
		t.Fatal("untrusted JSON imported verification or authorization")
	}
	raw, err := json.Marshal(Result{verified: true, artifactHash: "not a receipt"})
	if err != nil || !bytes.Equal(raw, []byte(`{}`)) {
		t.Fatal("opaque result became a transferable receipt")
	}
}

func TestCheckpointTreeSizeIsBound(t *testing.T) {
	for _, name := range []string{"message", "dsse"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/" + name + ".sigstore.json")
			if err != nil {
				t.Fatal(err)
			}
			b := &bundle.Bundle{}
			if err := b.UnmarshalJSON(raw); err != nil {
				t.Fatal(err)
			}
			e := Expected{Kind: KindMessageSignature, ArtifactSHA256: "sha256:a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf", LogID: "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"}
			if name == "dsse" {
				e.Kind = KindDSSE
				e.SubjectName = "a.txt"
				e.PredicateType = "https://slsa.dev/provenance/v1"
			}
			if _, ok := validBundle(b, e); !ok {
				t.Fatal("official original shape rejected")
			}
			b.VerificationMaterial.TlogEntries[0].InclusionProof.TreeSize++
			if _, ok := validBundle(b, e); ok {
				t.Fatal("unsigned proof size diverged from signed checkpoint")
			}
		})
	}
}

// This is a source-contract regression guard, not a general security audit.
// Both production library files must remain pure, offline SDK wrappers. CLI
// I/O is intentionally outside the library and cannot mint a library Result.
func TestOfflineSourceContract(t *testing.T) {
	allowed := map[string]bool{}
	for _, path := range []string{
		"bytes", "context", "crypto/sha256", "encoding/hex", "encoding/json", "errors", "io", "net/url", "strings", "time", "unicode/utf8",
		"github.com/sigstore/protobuf-specs/gen/pb-go/common/v1",
		"github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1",
		"github.com/sigstore/rekor/pkg/util",
		"github.com/sigstore/sigstore-go/pkg/bundle",
		"github.com/sigstore/sigstore-go/pkg/root",
		"github.com/sigstore/sigstore-go/pkg/verify",
		"google.golang.org/protobuf/encoding/protojson",
		"google.golang.org/protobuf/reflect/protoreflect",
	} {
		allowed[path] = true
	}
	sdkAllowed := map[string]bool{
		"util.SignedCheckpoint": true,
		"bundle.Bundle":         true, "root.NewTrustedRootFromJSON": true, "root.TrustedRootMediaType01": true,
		"verify.NewShortCertificateIdentity": true, "verify.NewVerifier": true,
		"verify.WithTransparencyLog": true, "verify.WithIntegratedTimestamps": true,
		"verify.WithSignedCertificateTimestamps": true, "verify.NewPolicy": true,
		"verify.WithArtifactDigest": true, "verify.WithCertificateIdentity": true,
	}
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range files {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		count++
		if entry.Name() != "strictjson.go" && entry.Name() != "verifier.go" {
			t.Fatal("new production file requires source contract review")
		}
		f, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range f.Imports {
			path, err := strconv.Unquote(im.Path.Value)
			if err != nil || !allowed[path] {
				t.Fatal("unexpected import in offline library")
			}
			if im.Name != nil && im.Name.Name != "protocommon" && im.Name.Name != "prototrustroot" {
				t.Fatal("unexpected import alias")
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if _, ok := n.(*ast.GoStmt); ok {
				t.Fatal("library must not hide uninterruptible verification behind a goroutine")
			}
			if s, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := s.X.(*ast.Ident); ok && (id.Name == "verify" || id.Name == "root" || id.Name == "bundle" || id.Name == "util") && !sdkAllowed[id.Name+"."+s.Sel.Name] {
					t.Fatal("unexpected SDK API, fetch or unsafe option")
				}
			}
			return true
		})
	}
	if count != 2 {
		t.Fatal("production library source set changed")
	}
}
