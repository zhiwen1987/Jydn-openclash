package restoreimage

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"chengwang/internal/restorecurrent"
	"chengwang/internal/restoreruntime"
)

func associationFixture(t *testing.T) (Content, runtimeFacts) {
	t.Helper()
	expected, manifest, config := testFixture(t, false, "amd64", "", 1)
	content, err := ValidateLocal(expected, manifest, config)
	if err != nil {
		t.Fatal(err)
	}
	return content, runtimeFacts{
		schema: restoreruntime.ObservationSchemaV1, boundary: restoreruntime.ObservationBoundary,
		authorization: AuthorizationBlocked, candidateID: "candidate-" + strings.Repeat("c", 32),
		containerID: strings.Repeat("d", 64), imageID: testSHA(config), runtimeSHA256: "sha256:" + strings.Repeat("e", 64),
		blockers: []restorecurrent.BlockerCode{
			restorecurrent.BlockerCandidateIDAttestationMissing,
			restorecurrent.BlockerComposeSourceAttestationMissing,
			restorecurrent.BlockerComposeRenderedAttestationMissing,
			restorecurrent.BlockerImageIdentityAttestationMissing,
			restorecurrent.BlockerLiveContainerIdentityNotObserved,
			restorecurrent.BlockerLiveQuiesceNotAuthorized,
			restorecurrent.BlockerStateWriterQuiesceUnproven,
			restorecurrent.BlockerProbeStatePathBindingUnproven,
			restorecurrent.BlockerExternalTimeAnchorMissing,
		},
	}
}

func TestAssociationKeepsDigestRolesAndNineBlockers(t *testing.T) {
	content, facts := associationFixture(t)
	result, err := bindFacts(content, facts)
	if err != nil {
		t.Fatal(err)
	}
	if result.Schema() != AssociationSchemaV1 || result.Boundary() != AssociationBoundary ||
		result.Authorization() != "BLOCKED" || result.Reference() != content.Reference() ||
		result.ManifestDigest() != content.ManifestDigest() || result.ConfigDigest() != content.ConfigDigest() ||
		result.RuntimeImageID() != content.ConfigDigest() || result.CandidateID() != facts.candidateID ||
		result.ContainerID() != facts.containerID || result.RuntimeSHA256() != facts.runtimeSHA256 ||
		!exactBlockers(result.Blockers()) {
		t.Fatalf("unexpected association: %+v", result)
	}
	if result.ManifestDigest() == result.RuntimeImageID() {
		t.Fatal("fixture does not distinguish digest roles")
	}
	facts.blockers[0] = "MUTATED-INPUT"
	returned := result.Blockers()
	returned[0] = "MUTATED-OUTPUT"
	if !exactBlockers(result.Blockers()) {
		t.Fatal("blockers alias caller state")
	}
	raw, err := json.Marshal(result)
	if err != nil || string(raw) != "{}" {
		t.Fatal("association acquired a serialized trust surface")
	}
	for i := 0; i < reflect.TypeOf(result).NumField(); i++ {
		if reflect.TypeOf(result).Field(i).IsExported() {
			t.Fatal("association has exported writable fields")
		}
	}
}

func TestAssociationRejectsIncompleteAndSubstitutedRuntime(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*runtimeFacts)
	}{
		{"schema", func(v *runtimeFacts) { v.schema = "other" }},
		{"boundary", func(v *runtimeFacts) { v.boundary = "ACCEPTED" }},
		{"authorization", func(v *runtimeFacts) { v.authorization = "ALLOWED" }},
		{"candidate", func(v *runtimeFacts) { v.candidateID = "short" }},
		{"candidate-is-not-sha256", func(v *runtimeFacts) { v.candidateID = "sha256:" + strings.Repeat("c", 64) }},
		{"candidate-uppercase", func(v *runtimeFacts) { v.candidateID = "candidate-" + strings.Repeat("C", 32) }},
		{"candidate-truncated", func(v *runtimeFacts) { v.candidateID = "candidate-" + strings.Repeat("c", 31) }},
		{"container", func(v *runtimeFacts) { v.containerID = "short" }},
		{"snapshot-digest", func(v *runtimeFacts) { v.runtimeSHA256 = "short" }},
		{"wrong-config", func(v *runtimeFacts) { v.imageID = "sha256:" + strings.Repeat("f", 64) }},
		{"missing-blocker", func(v *runtimeFacts) { v.blockers = v.blockers[:8] }},
		{"duplicate-blocker", func(v *runtimeFacts) { v.blockers[0] = v.blockers[1] }},
		{"replaced-blocker", func(v *runtimeFacts) { v.blockers[0] = "FAKE" }},
		{"extra-blocker", func(v *runtimeFacts) { v.blockers = append(v.blockers, "FAKE") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content, facts := associationFixture(t)
			tc.mutate(&facts)
			result, err := bindFacts(content, facts)
			if !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(result, Association{}) {
				t.Fatal("unsafe association accepted")
			}
		})
	}
	t.Run("manifest-digest-is-not-runtime-image-id", func(t *testing.T) {
		content, facts := associationFixture(t)
		facts.imageID = content.ManifestDigest()
		if _, err := bindFacts(content, facts); !errors.Is(err, ErrInvalid) {
			t.Fatal("manifest substituted for config image ID")
		}
	})
}

// The producer and consumer must agree on identity formats. Synthetic runtime
// facts alone previously hid a SHA-256-vs-candidate-ID compatibility bug.
func TestCandidateIDContractMatchesActualUpstreamProducer(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate upstream contract")
	}
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(source), "..", "restorecurrent", "identity.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range spec.Names {
			if name.Name != "candidateIDPattern" {
				continue
			}
			if i >= len(spec.Values) {
				t.Fatal("upstream candidate contract has no expression")
			}
			call, ok := spec.Values[i].(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				t.Fatal("upstream candidate contract changed shape")
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok {
				t.Fatal("upstream candidate contract is no longer literal")
			}
			pattern, err := strconv.Unquote(literal.Value)
			if err != nil || pattern != candidateIDPattern.String() {
				t.Fatal("consumer disagrees with actual upstream candidate ID format")
			}
			found = true
		}
		return true
	})
	if !found {
		t.Fatal("actual upstream candidate ID contract was not checked")
	}
}

func TestBindLocalRejectsZeroOpaqueInputs(t *testing.T) {
	content, facts := associationFixture(t)
	if _, err := BindLocal(content, restoreruntime.Observation{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero runtime accepted")
	}
	if _, err := BindLocal(Content{}, restoreruntime.Observation{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero content accepted")
	}
	if _, err := bindFacts(Content{}, facts); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero content with runtime accepted")
	}
	projected := factsFromRuntime(restoreruntime.Observation{})
	if !reflect.DeepEqual(projected, runtimeFacts{}) {
		t.Fatal("opaque runtime adapter invented facts")
	}
}

func TestLocalBytesCannotAuthenticateRepositoryOrLayerContent(t *testing.T) {
	expected, manifest, config := testFixture(t, false, "amd64", "", 1)
	first, err := ValidateLocal(expected, manifest, config)
	if err != nil {
		t.Fatal(err)
	}
	expected.Reference = "another.example.test/other/probe@" + testSHA(manifest)
	second, err := ValidateLocal(expected, manifest, config)
	if err != nil {
		t.Fatal(err)
	}
	if first.ManifestDigest() != second.ManifestDigest() || first.Reference() == second.Reference() ||
		second.Boundary() != "ADVISORY_LOCAL_OCI_BYTES_BOUND" {
		t.Fatal("local bytes acquired independent repository assurance")
	}
	// The synthetic layer descriptors have no layer byte input. That is an
	// explicit diagnostic limitation, never a verified layer-content claim.
	if second.LayerCount() != 1 {
		t.Fatal("manifest layer declaration not retained")
	}
}
