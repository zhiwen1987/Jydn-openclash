//go:build linux

package subscription

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func storeTestScope() Scope { return Scope{TenantID: "tenant-a", SiteID: "site-a", Environment: "lab"} }
func storeTestOpen(t *testing.T) (*Store, string) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal("fixture permissions")
	}
	dir := filepath.Join(parent, "private")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal("open private store", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}
func storeTestCode(t *testing.T, err error, want Code) {
	t.Helper()
	var e *Failure
	if !errors.As(err, &e) || e.Code != want || err.Error() != string(want) {
		t.Fatalf("expected closed code %s", want)
	}
}
func storeTestCreate(t *testing.T, s *Store, label, key string) SourceView {
	t.Helper()
	v, err := s.CreateSource(storeTestScope(), label, "operator-a", key)
	if err != nil {
		t.Fatal("create source", err)
	}
	return v
}
func storeTestBody(name, server string) []byte {
	raw, _ := json.Marshal(map[string]any{"proxies": []any{map[string]any{"name": name, "type": "trojan", "server": server, "port": 443, "password": "private-sentinel-password", "sni": server, "skip-cert-verify": false}}})
	return raw
}
func storeTestImport(t *testing.T, s *Store, source SourceView, body []byte, key string) CandidateView {
	t.Helper()
	v, err := s.Import(ImportRequest{Scope: source.Scope, SourceID: source.ID, ExpectedRevision: source.Revision, ActorID: "operator-a", IdempotencyKey: key, Format: FormatMihomo, Content: body})
	if err != nil {
		t.Fatal("import candidate", err)
	}
	return v
}
func storeTestCurrent(t *testing.T, s *Store, id string) SourceView {
	t.Helper()
	list, err := s.Sources(storeTestScope())
	if err != nil {
		t.Fatal("read sources", err)
	}
	for _, v := range list {
		if v.ID == id {
			return v
		}
	}
	t.Fatal("missing source")
	return SourceView{}
}
func storeTestDecision(t *testing.T, s *Store, c CandidateView, d CandidateState, key string) SourceView {
	t.Helper()
	src := storeTestCurrent(t, s, c.SourceID)
	v, err := s.Decide(DecisionRequest{Scope: c.Scope, SourceID: c.SourceID, CandidateID: c.ID, ExpectedRevision: src.Revision, ExpectedDigest: c.Digest, ActorID: "operator-a", IdempotencyKey: key, Decision: d})
	if err != nil {
		t.Fatal("local decision", err)
	}
	return v
}
func storeTestAdmitted(t *testing.T, s *Store) (SourceView, CandidateView) {
	t.Helper()
	src := storeTestCreate(t, s, "Source A", "create-source-key-0001")
	c := storeTestImport(t, s, src, storeTestBody("private-sentinel-name", "one.example"), "import-source-key-0001")
	return storeTestDecision(t, s, c, CandidateAdmitted, "decide-source-key-0001"), c
}
func storeTestRaw(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(path, storeSnapshotName))
	if err != nil {
		t.Fatal("read private fixture")
	}
	return b
}
func storeTestRewrite(t *testing.T, path string, change func(*storeSnapshot)) {
	t.Helper()
	var state storeSnapshot
	if storeDecode(storeTestRaw(t, path), &state) != nil {
		t.Fatal("decode fixture")
	}
	change(&state)
	raw, err := storeEncode(state)
	if err != nil {
		t.Fatal("encode fixture")
	}
	if os.WriteFile(filepath.Join(path, storeSnapshotName), raw, 0600) != nil {
		t.Fatal("rewrite fixture")
	}
}

func TestSubscriptionStoreCreateSourcePrivateAndDetached(t *testing.T) {
	s, dir := storeTestOpen(t)
	v := storeTestCreate(t, s, "Source A", "create-source-key-0001")
	if !validSource(v.ID) || v.Revision != 1 || v.AcceptedCandidateID != "" || v.UpdatedAt.IsZero() {
		t.Fatal("invalid new source")
	}
	for _, name := range []string{storeSnapshotName, storeLockName} {
		st, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("private mode")
		}
	}
	v.Label = "changed"
	if storeTestCurrent(t, s, v.ID).Label != "Source A" {
		t.Fatal("source view alias")
	}
}
func TestSubscriptionStoreSourceScopeIsolation(t *testing.T) {
	s, _ := storeTestOpen(t)
	src := storeTestCreate(t, s, "Source A", "create-source-key-0001")
	other := src.Scope
	other.TenantID = "other"
	v, err := s.Sources(other)
	if err != nil || len(v) != 0 {
		t.Fatal("scope list leak")
	}
	_, err = s.Candidates(other, src.ID)
	storeTestCode(t, err, CodeScopeDenied)
}
func TestSubscriptionStoreTwoSourceProvenance(t *testing.T) {
	s, _ := storeTestOpen(t)
	a := storeTestCreate(t, s, "Source A", "create-source-key-0001")
	b := storeTestCreate(t, s, "Source A", "create-source-key-0002")
	raw := storeTestBody("private-sentinel-name", "one.example")
	ca := storeTestImport(t, s, a, raw, "import-source-key-0001")
	cb := storeTestImport(t, s, b, raw, "import-source-key-0002")
	if a.ID == b.ID || ca.ID == cb.ID || ca.Nodes[0].ID == cb.Nodes[0].ID || ca.Digest == cb.Digest {
		t.Fatal("sources lost private provenance")
	}
}
func TestSubscriptionStoreImportQuarantinedByDefault(t *testing.T) {
	s, _ := storeTestOpen(t)
	src := storeTestCreate(t, s, "Source A", "create-source-key-0001")
	raw := storeTestBody("private-sentinel-name", "one.example")
	c := storeTestImport(t, s, src, raw, "import-source-key-0001")
	cur := storeTestCurrent(t, s, src.ID)
	if c.State != CandidateQuarantined || c.BaseRevision != 2 || cur.Revision != 2 || cur.LatestCandidateID != c.ID || cur.AcceptedCandidateID != "" || c.Nodes[0].State != "unknown" {
		t.Fatal("import gained runtime/admission authority")
	}
	raw[0] = 'x'
	if s.state.Candidates[0].Raw[0] == 'x' {
		t.Fatal("caller input retained")
	}
	c.Nodes[0].Label = "mutated"
	again, err := s.Candidate(src.Scope, src.ID, c.ID)
	if err != nil || again.Nodes[0].Label == "mutated" {
		t.Fatal("candidate alias")
	}
}
func TestSubscriptionStoreAdmitAdvancesLocalPointer(t *testing.T) {
	s, _ := storeTestOpen(t)
	src, c := storeTestAdmitted(t, s)
	if src.Revision != 3 || src.AcceptedCandidateID != c.ID {
		t.Fatal("local pointer not advanced")
	}
	v, err := s.Candidate(src.Scope, src.ID, c.ID)
	if err != nil || v.State != CandidateAdmitted || v.Nodes[0].State != "unknown" {
		t.Fatal("admission asserted node health")
	}
}
func TestSubscriptionStoreRejectPreservesLastKnownValid(t *testing.T) {
	s, _ := storeTestOpen(t)
	src, old := storeTestAdmitted(t, s)
	next := storeTestImport(t, s, src, storeTestBody("private-new-name", "two.example"), "import-source-key-0002")
	out := storeTestDecision(t, s, next, CandidateRejected, "decide-source-key-0002")
	if out.AcceptedCandidateID != old.ID || out.LatestCandidateID != next.ID || out.Revision != 5 {
		t.Fatal("rejection cleared last local admission")
	}
}
func TestSubscriptionStoreParseFailurePreservesLastKnownValid(t *testing.T) {
	s, dir := storeTestOpen(t)
	src, _ := storeTestAdmitted(t, s)
	before := storeTestRaw(t, dir)
	_, err := s.Import(ImportRequest{Scope: src.Scope, SourceID: src.ID, ExpectedRevision: src.Revision, ActorID: "operator-a", IdempotencyKey: "import-source-key-0002", Format: FormatMihomo, Content: []byte(`{"proxies":[]}`)})
	storeTestCode(t, err, CodeEmpty)
	if !bytes.Equal(before, storeTestRaw(t, dir)) || storeTestCurrent(t, s, src.ID) != src {
		t.Fatal("failed parse changed LKV or audit")
	}
}
func TestSubscriptionStoreRepeatedContentIsIdempotent(t *testing.T) {
	s, dir := storeTestOpen(t)
	src := storeTestCreate(t, s, "Source A", "create-source-key-0001")
	raw := storeTestBody("private-sentinel-name", "one.example")
	c := storeTestImport(t, s, src, raw, "import-source-key-0001")
	before := storeTestRaw(t, dir)
	cur := storeTestCurrent(t, s, src.ID)
	for i := 0; i < 4; i++ {
		v, err := s.Import(ImportRequest{Scope: src.Scope, SourceID: src.ID, ExpectedRevision: cur.Revision, ActorID: "operator-a", IdempotencyKey: fmt.Sprintf("duplicate-content-%04d", i), Format: FormatAuto, Content: raw})
		if err != nil || v.ID != c.ID {
			t.Fatal("duplicate not coalesced")
		}
	}
	if !bytes.Equal(before, storeTestRaw(t, dir)) {
		t.Fatal("duplicate content grew local history")
	}
}
func TestSubscriptionStoreRenameKeepsStableNodes(t *testing.T) {
	s, _ := storeTestOpen(t)
	src := storeTestCreate(t, s, "Source A", "create-source-key-0001")
	a := storeTestImport(t, s, src, storeTestBody("private-name-a", "one.example"), "import-source-key-0001")
	b := storeTestImport(t, s, storeTestCurrent(t, s, src.ID), storeTestBody("private-name-b", "one.example"), "import-source-key-0002")
	if a.ID == b.ID || a.Nodes[0].ID != b.Nodes[0].ID || a.Nodes[0].Label != b.Nodes[0].Label {
		t.Fatal("rename changed stable node identity")
	}
}
func TestSubscriptionStoreReorderedNodesKeepIdentity(t *testing.T) {
	s, _ := storeTestOpen(t)
	src := storeTestCreate(t, s, "Source A", "create-source-key-0001")
	var a, b map[string][]map[string]any
	_ = json.Unmarshal(storeTestBody("name-a", "one.example"), &a)
	_ = json.Unmarshal(storeTestBody("name-b", "two.example"), &b)
	left, _ := json.Marshal(map[string]any{"proxies": []any{a["proxies"][0], b["proxies"][0]}})
	right, _ := json.Marshal(map[string]any{"proxies": []any{b["proxies"][0], a["proxies"][0]}})
	x := storeTestImport(t, s, src, left, "import-source-key-0001")
	y := storeTestImport(t, s, storeTestCurrent(t, s, src.ID), right, "import-source-key-0002")
	if len(x.Nodes) != 2 || x.Nodes[0] != y.Nodes[0] || x.Nodes[1] != y.Nodes[1] {
		t.Fatal("order changed node identities")
	}
}
func TestSubscriptionStoreIdempotencyMismatchRejected(t *testing.T) {
	s, dir := storeTestOpen(t)
	a := storeTestCreate(t, s, "Source A", "create-source-key-0001")
	before := storeTestRaw(t, dir)
	b, err := s.CreateSource(a.Scope, "Source A", "operator-a", "create-source-key-0001")
	if err != nil || a.ID != b.ID {
		t.Fatal("same key replay")
	}
	_, err = s.CreateSource(a.Scope, "Source B", "operator-a", "create-source-key-0001")
	storeTestCode(t, err, CodeConflict)
	if !bytes.Equal(before, storeTestRaw(t, dir)) {
		t.Fatal("conflicting replay changed state")
	}
	for _, key := range []string{"", strings.Repeat("k", 15), strings.Repeat("k", 129), "private/url/key-is-not-safe"} {
		_, err := s.CreateSource(a.Scope, "Source C", "operator-a", key)
		storeTestCode(t, err, CodeInputInvalid)
	}
}
func TestSubscriptionStoreIdempotencyActorAndScopeBound(t *testing.T) {
	s, _ := storeTestOpen(t)
	a := storeTestCreate(t, s, "Source A", "create-source-key-0001")
	b, err := s.CreateSource(a.Scope, "Source A", "operator-b", "create-source-key-0001")
	if err != nil || b.ID == a.ID {
		t.Fatal("another actor's key namespace was occupied")
	}
	scope := a.Scope
	scope.SiteID = "site-b"
	c, err := s.CreateSource(scope, "Source A", "operator-a", "create-source-key-0001")
	if err != nil || c.ID == a.ID || c.ID == b.ID {
		t.Fatal("another scope's key namespace was occupied")
	}
	_, err = s.CreateSource(scope, "Changed source", "operator-a", "create-source-key-0001")
	storeTestCode(t, err, CodeConflict)
}
func TestSubscriptionStoreExpectedRevisionConflict(t *testing.T) {
	s, dir := storeTestOpen(t)
	src := storeTestCreate(t, s, "Source A", "create-source-key-0001")
	before := storeTestRaw(t, dir)
	_, err := s.Import(ImportRequest{Scope: src.Scope, SourceID: src.ID, ExpectedRevision: 0, ActorID: "operator-a", IdempotencyKey: "import-source-key-0001", Format: FormatMihomo, Content: storeTestBody("name", "one.example")})
	storeTestCode(t, err, CodeConflict)
	if !bytes.Equal(before, storeTestRaw(t, dir)) {
		t.Fatal("CAS changed state")
	}
	s.state.Sources[0].Revision = math.MaxUint64
	_, err = s.Import(ImportRequest{Scope: src.Scope, SourceID: src.ID, ExpectedRevision: math.MaxUint64, ActorID: "operator-a", IdempotencyKey: "import-source-key-0002", Format: FormatMihomo, Content: storeTestBody("name", "one.example")})
	storeTestCode(t, err, CodeConflict)
	if !bytes.Equal(before, storeTestRaw(t, dir)) {
		t.Fatal("synthetic overflow mutated bytes")
	}
}
func TestSubscriptionStoreStaleCandidateCannotAdmit(t *testing.T) {
	s, _ := storeTestOpen(t)
	src := storeTestCreate(t, s, "Source A", "create-source-key-0001")
	old := storeTestImport(t, s, src, storeTestBody("old", "one.example"), "import-source-key-0001")
	_ = storeTestImport(t, s, storeTestCurrent(t, s, src.ID), storeTestBody("new", "two.example"), "import-source-key-0002")
	cur := storeTestCurrent(t, s, src.ID)
	_, err := s.Decide(DecisionRequest{Scope: src.Scope, SourceID: src.ID, CandidateID: old.ID, ExpectedRevision: cur.Revision, ExpectedDigest: old.Digest, ActorID: "operator-a", IdempotencyKey: "decide-source-key-0001", Decision: CandidateAdmitted})
	storeTestCode(t, err, CodeConflict)
	if storeTestCurrent(t, s, src.ID).AcceptedCandidateID != "" {
		t.Fatal("stale candidate admitted")
	}
}
func TestSubscriptionStoreRollbackRequiresPreviouslyAdmitted(t *testing.T) {
	s, _ := storeTestOpen(t)
	src := storeTestCreate(t, s, "Source A", "create-source-key-0001")
	c := storeTestImport(t, s, src, storeTestBody("name", "one.example"), "import-source-key-0001")
	cur := storeTestCurrent(t, s, src.ID)
	_, err := s.Rollback(src.Scope, src.ID, c.ID, cur.Revision, "operator-a", "rollback-source-key-01")
	storeTestCode(t, err, CodeConflict)
	cur = storeTestDecision(t, s, c, CandidateRejected, "decide-source-key-0001")
	_, err = s.Rollback(src.Scope, src.ID, c.ID, cur.Revision, "operator-a", "rollback-source-key-02")
	storeTestCode(t, err, CodeConflict)
}
func TestSubscriptionStoreRollbackCreatesNewRevision(t *testing.T) {
	s, _ := storeTestOpen(t)
	src, a := storeTestAdmitted(t, s)
	b := storeTestImport(t, s, src, storeTestBody("new", "two.example"), "import-source-key-0002")
	src = storeTestDecision(t, s, b, CandidateAdmitted, "decide-source-key-0002")
	out, err := s.Rollback(src.Scope, src.ID, a.ID, src.Revision, "operator-a", "rollback-source-key-01")
	if err != nil || out.Revision != 6 || out.AcceptedCandidateID != a.ID || out.LatestCandidateID != b.ID {
		t.Fatal("rollback did not create a new local revision")
	}
	again, err := s.Rollback(src.Scope, src.ID, a.ID, src.Revision, "operator-a", "rollback-source-key-01")
	if err != nil || again != out {
		t.Fatal("rollback replay mutated revision")
	}
}
func TestSubscriptionStoreRollbackExpectedRevisionConflict(t *testing.T) {
	s, dir := storeTestOpen(t)
	src, c := storeTestAdmitted(t, s)
	before := storeTestRaw(t, dir)
	_, err := s.Rollback(src.Scope, src.ID, c.ID, src.Revision-1, "operator-a", "rollback-source-key-01")
	storeTestCode(t, err, CodeConflict)
	if !bytes.Equal(before, storeTestRaw(t, dir)) {
		t.Fatal("stale rollback wrote")
	}
}
func TestSubscriptionStoreRestartRevalidatesPrivateSnapshot(t *testing.T) {
	s, dir := storeTestOpen(t)
	src, c := storeTestAdmitted(t, s)
	before := storeTestRaw(t, dir)
	if s.Close() != nil {
		t.Fatal("close")
	}
	r, err := OpenStore(dir)
	if err != nil {
		t.Fatal("reopen", err)
	}
	defer r.Close()
	if storeTestCurrent(t, r, src.ID) != src {
		t.Fatal("source changed after reopen")
	}
	v, err := r.Candidate(src.Scope, src.ID, c.ID)
	if err != nil || v.Nodes[0].ID != c.Nodes[0].ID || !bytes.Equal(before, storeTestRaw(t, dir)) {
		t.Fatal("restart identity/LKV changed")
	}
}
func TestSubscriptionStorePublicViewsNeverRevealPrivateMaterial(t *testing.T) {
	s, _ := storeTestOpen(t)
	src, c := storeTestAdmitted(t, s)
	if fmt.Sprintf("%+v %#v", s, s) != "subscription private store subscription private store" {
		t.Fatal("store formatting exposed its private snapshot")
	}
	if fmt.Sprintf("%+v %#v", *s, *s) != "subscription private store subscription private store" {
		t.Fatal("store value formatting exposed its private snapshot")
	}
	copy := *s
	if copy.storeCore != s.storeCore {
		t.Fatal("copied store does not share the private controller")
	}
	list, err := s.Candidates(src.Scope, src.ID)
	if err != nil {
		t.Fatal("list")
	}
	raw, _ := json.Marshal([]any{src, c, list})
	for _, secret := range []string{"private-sentinel-name", "private-sentinel-password", "one.example", "canonicalConfig", "privateNodes", "identityKey"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("private ingress material escaped public view")
		}
	}
	if !strings.HasPrefix(c.Digest, "hmac-sha256:") {
		t.Fatal("keyed digest mislabelled")
	}
}
func TestSubscriptionStoreTamperedRawRejectedOnOpen(t *testing.T) {
	s, dir := storeTestOpen(t)
	_, _ = storeTestAdmitted(t, s)
	_ = s.Close()
	storeTestRewrite(t, dir, func(st *storeSnapshot) { st.Candidates[0].Raw = storeTestBody("private-sentinel-name", "evil.example") })
	_, err := OpenStore(dir)
	storeTestCode(t, err, CodeStoreUnsafe)
}
func TestSubscriptionStoreTamperedConfigRejectedOnOpen(t *testing.T) {
	s, dir := storeTestOpen(t)
	_, _ = storeTestAdmitted(t, s)
	_ = s.Close()
	storeTestRewrite(t, dir, func(st *storeSnapshot) { st.Candidates[0].Nodes[0].Config = json.RawMessage(`{"name":"forged"}`) })
	_, err := OpenStore(dir)
	storeTestCode(t, err, CodeStoreUnsafe)
}
func TestSubscriptionStoreUnknownDuplicateAndTrailingJSONRejected(t *testing.T) {
	for i := 0; i < 3; i++ {
		s, dir := storeTestOpen(t)
		_ = storeTestCreate(t, s, "Source A", "create-source-key-0001")
		_ = s.Close()
		raw := storeTestRaw(t, dir)
		switch i {
		case 0:
			raw = append([]byte(`{"unknown":true,`), raw[1:]...)
		case 1:
			raw = append([]byte(`{"schema":"chengwang.subscription-store/v1",`), raw[1:]...)
		case 2:
			raw = append(raw, []byte("{}")...)
		}
		if os.WriteFile(filepath.Join(dir, storeSnapshotName), raw, 0600) != nil {
			t.Fatal("fixture write")
		}
		_, err := OpenStore(dir)
		storeTestCode(t, err, CodeStoreUnsafe)
	}
}
func TestSubscriptionStoreSourceCandidateAuditAndByteLimits(t *testing.T) {
	s, _ := storeTestOpen(t)
	for i := 0; i < MaxSources; i++ {
		storeTestCreate(t, s, "Source", fmt.Sprintf("source-limit-key-%04d", i))
	}
	_, err := s.CreateSource(storeTestScope(), "Source", "operator-a", "source-limit-extra-key")
	storeTestCode(t, err, CodeStoreLimit)
	r, _ := storeTestOpen(t)
	src := storeTestCreate(t, r, "Source", "create-source-key-0001")
	other := storeTestCreate(t, r, "Other source", "create-source-key-0002")
	for i := 0; i < MaxCandidates; i++ {
		target := src
		if i%2 != 0 {
			target = other
		}
		_ = storeTestImport(t, r, storeTestCurrent(t, r, target.ID), storeTestBody(fmt.Sprintf("name-%d", i), "one.example"), fmt.Sprintf("candidate-limit-%04d", i))
	}
	left, err := r.Candidates(src.Scope, src.ID)
	if err != nil || len(left) != MaxCandidates/2 {
		t.Fatal("first source budget fixture")
	}
	right, err := r.Candidates(other.Scope, other.ID)
	if err != nil || len(right) != MaxCandidates/2 || len(r.state.Candidates) != MaxCandidates {
		t.Fatal("global candidate budget fixture")
	}
	cur := storeTestCurrent(t, r, src.ID)
	_, err = r.Import(ImportRequest{Scope: cur.Scope, SourceID: cur.ID, ExpectedRevision: cur.Revision, ActorID: "operator-a", IdempotencyKey: "candidate-limit-extra", Format: FormatMihomo, Content: storeTestBody("extra", "one.example")})
	storeTestCode(t, err, CodeStoreLimit)
	r.state.Audit = make([]storeAudit, MaxAuditEntries)
	r.state.Requests = make([]storeRequest, MaxAuditEntries)
	_, err = r.CreateSource(storeTestScope(), "Another", "operator-a", "synthetic-audit-limit")
	storeTestCode(t, err, CodeStoreLimit)
	t.Log("audit-capacity fault is synthetic in-memory injection, not an actual crash")
	_, err = storeEncode(storeSnapshot{IdentityKey: make([]byte, MaxStoreBytes)})
	storeTestCode(t, err, CodeStoreLimit)
}
func TestSubscriptionStoreConcurrentMutationSerialized(t *testing.T) {
	s, _ := storeTestOpen(t)
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := s.CreateSource(storeTestScope(), "Source", "operator-a", fmt.Sprintf("concurrent-source-%04d", n))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("concurrent mutation", err)
		}
	}
	v, err := s.Sources(storeTestScope())
	if err != nil || len(v) != 12 || len(s.state.Audit) != 12 {
		t.Fatal("serialized mutations lost")
	}
}
func TestSubscriptionStoreSecondControllerRejected(t *testing.T) {
	s, dir := storeTestOpen(t)
	_ = storeTestCreate(t, s, "Source A", "create-source-key-0001")
	_, err := OpenStore(dir)
	storeTestCode(t, err, CodeStoreLocked)
}
func TestSubscriptionStoreCloseReleasesProcessLock(t *testing.T) {
	var zero Store
	var absent *Store
	if zero.Close() != nil || absent.Close() != nil {
		t.Fatal("zero and nil stores must close safely")
	}
	_, err := zero.Sources(storeTestScope())
	storeTestCode(t, err, CodeStoreClosed)
	_, err = absent.Sources(storeTestScope())
	storeTestCode(t, err, CodeStoreClosed)
	s, dir := storeTestOpen(t)
	if s.Close() != nil || s.Close() != nil {
		t.Fatal("close")
	}
	_, err = s.Sources(storeTestScope())
	storeTestCode(t, err, CodeStoreClosed)
	r, err := OpenStore(dir)
	if err != nil {
		t.Fatal("lock not released")
	}
	_ = r.Close()
}
func TestSubscriptionStoreExistingWideDirectoryRejectedUnchanged(t *testing.T) {
	parent := t.TempDir()
	if os.Chmod(parent, 0700) != nil {
		t.Fatal("fixture")
	}
	dir := filepath.Join(parent, "wide")
	if os.Mkdir(dir, 0755) != nil || os.Chmod(dir, 0755) != nil {
		t.Fatal("fixture")
	}
	_, err := OpenStore(dir)
	storeTestCode(t, err, CodeStoreUnsafe)
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0755 {
		t.Fatal("unsafe existing permissions repaired")
	}
}
func TestSubscriptionStoreSymlinkAncestorsAndFilesRejected(t *testing.T) {
	s, dir := storeTestOpen(t)
	_ = s.Close()
	parent := filepath.Dir(dir)
	alias := filepath.Join(parent, "alias")
	if os.Symlink(dir, alias) != nil {
		t.Fatal("fixture symlink")
	}
	_, err := OpenStore(alias)
	storeTestCode(t, err, CodeStoreUnsafe)
	_, err = OpenStore(filepath.Join(alias, "child"))
	storeTestCode(t, err, CodeStoreUnsafe)
	snapshot := filepath.Join(dir, storeSnapshotName)
	original := filepath.Join(parent, "original.json")
	if os.Rename(snapshot, original) != nil || os.Symlink(original, snapshot) != nil {
		t.Fatal("fixture symlink")
	}
	_, err = OpenStore(dir)
	storeTestCode(t, err, CodeStoreUnsafe)
}
func TestSubscriptionStoreHardlinkAndFIFORejected(t *testing.T) {
	s, dir := storeTestOpen(t)
	_ = s.Close()
	snapshot := filepath.Join(dir, storeSnapshotName)
	if os.Link(snapshot, filepath.Join(filepath.Dir(dir), "alias.json")) != nil {
		t.Fatal("fixture hardlink")
	}
	_, err := OpenStore(dir)
	storeTestCode(t, err, CodeStoreUnsafe)
	q, other := storeTestOpen(t)
	_ = q.Close()
	target := filepath.Join(other, storeSnapshotName)
	if os.Remove(target) != nil || syscall.Mkfifo(target, 0600) != nil {
		t.Fatal("fixture FIFO")
	}
	_, err = OpenStore(other)
	storeTestCode(t, err, CodeStoreUnsafe)
}
func TestSubscriptionStoreWrongOwnerAndModesRejected(t *testing.T) {
	s, dir := storeTestOpen(t)
	_ = s.Close()
	p := filepath.Join(dir, storeSnapshotName)
	if os.Chmod(p, 0640) != nil {
		t.Fatal("fixture chmod")
	}
	_, err := OpenStore(dir)
	storeTestCode(t, err, CodeStoreUnsafe)
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0640 {
		t.Fatal("unsafe mode repaired")
	}
	fake := syscall.Stat_t{Mode: syscall.S_IFREG | 0600, Uid: uint32(os.Geteuid()) + 1, Gid: uint32(os.Getegid()), Nlink: 1}
	if storeFileSafe(fake, uint32(os.Geteuid()), uint32(os.Getegid())) {
		t.Fatal("wrong-owner stat admitted")
	}
	fake.Mode = syscall.S_IFDIR | 0700
	if storeDirectorySafe(fake, true, dir, uint32(os.Geteuid()), uint32(os.Getegid())) {
		t.Fatal("wrong-owner leaf directory stat admitted")
	}
	t.Log("wrong-owner branch is explicit synthetic stat injection; no privileged chown claimed")
}
func TestSubscriptionStoreReplacedDirectoryLockOrSnapshotFailClosed(t *testing.T) {
	for i := 0; i < 3; i++ {
		s, dir := storeTestOpen(t)
		_ = storeTestCreate(t, s, "Source A", "create-source-key-0001")
		switch i {
		case 0:
			if os.Rename(dir, dir+"-old") != nil || os.Mkdir(dir, 0700) != nil {
				t.Fatal("replace directory")
			}
		case 1, 2:
			name := storeLockName
			if i == 2 {
				name = storeSnapshotName
			}
			p := filepath.Join(dir, name)
			raw, err := os.ReadFile(p)
			if err != nil || os.Rename(p, filepath.Join(filepath.Dir(dir), fmt.Sprintf("old-%d", i))) != nil || os.WriteFile(p, raw, 0600) != nil {
				t.Fatal("replace file")
			}
		}
		_, err := s.Sources(storeTestScope())
		storeTestCode(t, err, CodeStoreUnsafe)
	}
}
func TestSubscriptionStoreFailedPreRenameWritePreservesSnapshot(t *testing.T) {
	s, dir := storeTestOpen(t)
	_ = storeTestCreate(t, s, "Source A", "create-source-key-0001")
	before := storeTestRaw(t, dir)
	disk := s.disk.(*storeLinuxDisk)
	disk.beforeRename = func() error { return errors.New("injected-private-failure") }
	_, err := s.CreateSource(storeTestScope(), "Source B", "operator-a", "create-source-key-0002")
	storeTestCode(t, err, CodeStoreUnsafe)
	if !bytes.Equal(before, storeTestRaw(t, dir)) {
		t.Fatal("pre-rename fault changed snapshot")
	}
	// Replace only the synthetic owned temporary entry with equal bytes. The
	// held writer FD must not authorize renaming a different same-name inode.
	disk.beforeRename = func() error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".store-") && strings.HasSuffix(entry.Name(), ".tmp") {
				name := filepath.Join(dir, entry.Name())
				raw, err := os.ReadFile(name)
				if err != nil {
					return err
				}
				if err := os.Remove(name); err != nil {
					return err
				}
				return os.WriteFile(name, raw, 0600)
			}
		}
		return errors.New("fixture temporary missing")
	}
	_, err = s.CreateSource(storeTestScope(), "Source B", "operator-a", "create-source-key-0002")
	storeTestCode(t, err, CodeStoreUnsafe)
	if !bytes.Equal(before, storeTestRaw(t, dir)) {
		t.Fatal("substituted temporary inode replaced snapshot")
	}
	disk.beforeRename = nil
	_ = storeTestCreate(t, s, "Source B", "create-source-key-0002")
	t.Log("synthetic pre-rename fault injection, not actual process kill")
}
func TestSubscriptionStoreDirectorySyncFailurePoisonsStore(t *testing.T) {
	s, dir := storeTestOpen(t)
	_ = storeTestCreate(t, s, "Source A", "create-source-key-0001")
	disk := s.disk.(*storeLinuxDisk)
	disk.syncDirectory = func(*os.File) error { return errors.New("injected-private-failure") }
	_, err := s.CreateSource(storeTestScope(), "Source B", "operator-a", "create-source-key-0002")
	storeTestCode(t, err, CodeCommitUncertain)
	_, err = s.Sources(storeTestScope())
	storeTestCode(t, err, CodeCommitUncertain)
	_, err = s.CreateSource(storeTestScope(), "Source C", "operator-a", "create-source-key-0003")
	storeTestCode(t, err, CodeCommitUncertain)
	_ = s.Close()
	r, err := OpenStore(dir)
	if err != nil {
		t.Fatal("reopen actual renamed bytes", err)
	}
	defer r.Close()
	v, err := r.Sources(storeTestScope())
	if err != nil || len(v) != 2 {
		t.Fatal("reopen did not reconcile actual bytes")
	}
	t.Log("synthetic directory fsync fault after real rename; not actual power loss")
}
func TestSubscriptionStoreAuditRecordsBoundedAndSecretFree(t *testing.T) {
	s, _ := storeTestOpen(t)
	src, c := storeTestAdmitted(t, s)
	raw, _ := json.Marshal(s.state.Audit)
	for _, secret := range []string{"private-sentinel-password", "private-sentinel-name", "one.example", "create-source-key-0001", "import-source-key-0001", "decide-source-key-0001"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("local audit leaked private input")
		}
	}
	if len(s.state.Audit) != 3 {
		t.Fatal("local audit count")
	}
	for i, a := range s.state.Audit {
		if a.Sequence != uint64(i+1) || a.Scope != src.Scope || a.SourceID != src.ID || a.Actor != "operator-a" || a.Hash != storeAuditHash(a) {
			t.Fatal("local audit binding")
		}
	}
	if s.state.Audit[2].CandidateID != c.ID || s.state.Audit[2].Revision != 3 || s.state.Audit[2].Result != string(CandidateAdmitted) {
		t.Fatal("decision audit mismatch")
	}
	s.state.Audit[1].Actor = "foreign"
	if storeValidate(s.state) == nil {
		t.Fatal("tampered local audit accepted")
	}
}
