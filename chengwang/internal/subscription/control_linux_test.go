//go:build linux

package subscription

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func controlTestPrepared(t *testing.T, s *Store, kind, source string, revision uint64, key string) ControlCommand {
	t.Helper()
	scope := storeTestScope()
	identity, err := s.ControlIdentity(scope, "owner@example.test", key, []byte("private command material"))
	if err != nil {
		t.Fatal(err)
	}
	c := ControlCommand{ID: identity.ID, Scope: scope, ActorID: identity.ActorID, Kind: kind, SourceID: source, ExpectedRevision: revision, Fingerprint: identity.Fingerprint, OwnerID: "owner@example.test", CoreKey: identity.CoreKey, KeyDigest: identity.KeyDigest, PreparedAt: time.Now().UTC(), PreparedAuditHash: strings.Repeat("a", 64)}
	created, err := s.RecordControlPrepared(c)
	if err != nil || !created {
		t.Fatal("prepare fixture")
	}
	return c
}
func controlTestCreate(t *testing.T, s *Store, key string) (ControlCommand, SourceView, ControlResult) {
	t.Helper()
	c := controlTestPrepared(t, s, "create", "", 0, key)
	source, err := s.CreateSource(c.Scope, "Source", c.ActorID, c.CoreKey)
	if err != nil {
		t.Fatal(err)
	}
	m, ok, err := s.MutationReceipt(c.Scope, c.ActorID, c.CoreKey)
	if err != nil || !ok {
		t.Fatal("missing actual receipt")
	}
	r := ControlResult{SourceID: m.SourceID, CandidateID: m.CandidateID, Revision: m.Revision, Digest: m.Digest, State: "committed", LocalAuditHash: m.LocalAuditHash, CompletedAt: m.CompletedAt}
	if err := s.RecordControlResult(c.Scope, c.ID, r); err != nil {
		t.Fatal(err)
	}
	return c, source, r
}

func TestSubscriptionStoreControlMutationReceiptUsesHistoricalAudit(t *testing.T) {
	s, _ := storeTestOpen(t)
	scope := storeTestScope()
	source, err := s.CreateSource(scope, "Source", "operator", "create-receipt-key-0001")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Import(ImportRequest{Scope: scope, SourceID: source.ID, ExpectedRevision: source.Revision, ActorID: "operator", IdempotencyKey: "import-receipt-key-0001", Content: []byte("http://proxy.example:8080")})
	if err != nil {
		t.Fatal(err)
	}
	m, ok, err := s.MutationReceipt(scope, "operator", "create-receipt-key-0001")
	current, readErr := s.Source(scope, source.ID)
	if err != nil || readErr != nil || !ok || m.Revision != 1 || current.Revision != 2 || m.State != "created" || m.Action != "create" || m.LocalAuditHash == "" {
		t.Fatal("receipt followed current view")
	}
}
func TestSubscriptionStoreControlMutationReceiptBindsScopeActorKey(t *testing.T) {
	s, _ := storeTestOpen(t)
	scope := storeTestScope()
	_, err := s.CreateSource(scope, "Source", "operator", "create-receipt-key-0002")
	if err != nil {
		t.Fatal(err)
	}
	other := scope
	other.SiteID = "other"
	for _, input := range []struct {
		scope      Scope
		actor, key string
	}{{other, "operator", "create-receipt-key-0002"}, {scope, "other", "create-receipt-key-0002"}} {
		_, found, err := s.MutationReceipt(input.scope, input.actor, input.key)
		if err != nil || found {
			t.Fatal("receipt crossed scope or actor binding")
		}
	}
	_, ok, err := s.MutationReceipt(scope, "operator", "missing-receipt-key-0002")
	if err != nil || ok {
		t.Fatal("invented receipt")
	}
}
func TestSubscriptionStoreControlMutationReceiptAbsentOnNoop(t *testing.T) {
	s, _ := storeTestOpen(t)
	source := storeTestCreate(t, s, "Source", "control-source-key-0003")
	raw := []byte("http://proxy.example:8080")
	first, err := s.Import(ImportRequest{Scope: source.Scope, SourceID: source.ID, ExpectedRevision: source.Revision, ActorID: "operator-a", IdempotencyKey: "control-import-key-0003", Content: raw})
	if err != nil {
		t.Fatal(err)
	}
	current := storeTestCurrent(t, s, source.ID)
	c := controlTestPrepared(t, s, "import", source.ID, current.Revision, "control-noop-key-0003")
	v, err := s.Import(ImportRequest{Scope: c.Scope, SourceID: source.ID, ExpectedRevision: current.Revision, ActorID: c.ActorID, IdempotencyKey: c.CoreKey, Content: raw})
	if err != nil || v.ID != first.ID {
		t.Fatal("noop import")
	}
	_, found, err := s.MutationReceipt(c.Scope, c.ActorID, c.CoreKey)
	if err != nil || found {
		t.Fatal("noop invented mutation audit")
	}
	r := ControlResult{SourceID: source.ID, CandidateID: v.ID, Revision: current.Revision, Digest: v.Digest, State: "noop", CompletedAt: time.Now().UTC()}
	if err := s.RecordControlResult(c.Scope, c.ID, r); err != nil {
		t.Fatal(err)
	}
}
func TestSubscriptionStoreControlLegacySnapshotCompatible(t *testing.T) {
	s, path := storeTestOpen(t)
	storeTestCreate(t, s, "Legacy", "control-legacy-key-0004")
	before := storeTestRaw(t, path)
	if bytes.Contains(before, []byte(`"commands"`)) || bytes.Contains(before, []byte(`"approvals"`)) {
		t.Fatal("empty extension changed legacy wire")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !bytes.Equal(before, storeTestRaw(t, path)) {
		t.Fatal("legacy open rewrote bytes")
	}
}
func TestSubscriptionStoreControlImmutableCommandBindings(t *testing.T) {
	s, _ := storeTestOpen(t)
	identity, err := s.ControlIdentity(storeTestScope(), "private-owner@example.test", "control-private-key-0005", []byte("private material"))
	if err != nil {
		t.Fatal(err)
	}
	rawIdentity, err := json.Marshal(identity)
	if err != nil || string(rawIdentity) != "{}" {
		t.Fatal("private identity exported through JSON")
	}
	c := controlTestPrepared(t, s, "create", "", 0, "control-immutable-key-0005")
	created, err := s.RecordControlPrepared(c)
	if err != nil || created {
		t.Fatal("prepare replay wrote")
	}
	c.OwnerID = "other@example.test"
	_, err = s.RecordControlPrepared(c)
	storeTestCode(t, err, CodeConflict)
}
func TestSubscriptionStoreControlResultAndAckMonotonic(t *testing.T) {
	s, _ := storeTestOpen(t)
	c, _, r := controlTestCreate(t, s, "control-result-key-0006")
	if err := s.RecordControlResult(c.Scope, c.ID, r); err != nil {
		t.Fatal(err)
	}
	changed := r
	changed.Revision++
	storeTestCode(t, s.RecordControlResult(c.Scope, c.ID, changed), CodeConflict)
	if err := s.AcknowledgeControl(c.Scope, c.ID, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if err := s.AcknowledgeControl(c.Scope, c.ID, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	storeTestCode(t, s.AcknowledgeControl(c.Scope, c.ID, strings.Repeat("c", 64)), CodeConflict)
}
func TestSubscriptionStoreControlRestartValidation(t *testing.T) {
	s, path := storeTestOpen(t)
	c, _, r := controlTestCreate(t, s, "control-restart-key-0007")
	if err := s.AcknowledgeControl(c.Scope, c.ID, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, ok, err := reopened.ControlCommand(c.Scope, c.ID)
	if err != nil || !ok || got.OwnerID != c.OwnerID || got.CoreKey != c.CoreKey || got.Result == nil || *got.Result != r || !got.Acknowledged {
		t.Fatal("restart lost immutable control record")
	}
}
func TestSubscriptionStoreControlUnknownDoesNotReplay(t *testing.T) {
	s, path := storeTestOpen(t)
	c := controlTestPrepared(t, s, "create", "", 0, "control-unknown-key-0008")
	result := ControlResult{State: "unknown", Code: "subscription_commit_unknown", StateMayHaveChanged: true, CompletedAt: time.Now().UTC()}
	if err := s.RecordControlResult(c.Scope, c.ID, result); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	m, ok, err := reopened.MutationReceipt(c.Scope, c.ActorID, c.CoreKey)
	if err != nil || ok || m.LocalAuditHash != "" {
		t.Fatal("unknown manufactured actual mutation")
	}
	sources, err := reopened.Sources(c.Scope)
	if err != nil || len(sources) != 0 {
		t.Fatal("unknown replayed create")
	}
}
func TestSubscriptionStoreControlApprovalPersistentHMAC(t *testing.T) {
	s, path := storeTestOpen(t)
	source := storeTestCreate(t, s, "Source", "control-policy-key-0009")
	scope := storeTestScope()
	digest, err := s.SealPolicy(scope, source.ID, []byte("private URL and credentials"))
	if err != nil || !strings.HasPrefix(digest, "hmac-sha256:") {
		t.Fatal("missing private policy commitment")
	}
	other, err := s.CreateSource(scope, "Other", "operator", "control-policy-key-other")
	if err != nil {
		t.Fatal(err)
	}
	separated, err := s.SealPolicy(scope, other.ID, []byte("private URL and credentials"))
	if err != nil || digest == separated {
		t.Fatal("policy crossed source boundary")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.SealPolicy(scope, source.ID, []byte("private URL and credentials"))
	if err != nil || again != digest {
		t.Fatal("policy HMAC changed on restart")
	}
}
func TestSubscriptionStoreControlApprovalCASAndInvalidation(t *testing.T) {
	s, _ := storeTestOpen(t)
	source := storeTestCreate(t, s, "Source", "control-approval-source")
	c := controlTestPrepared(t, s, "approve", source.ID, source.Revision, "control-approval-key-0010")
	digest, _ := s.SealPolicy(c.Scope, source.ID, []byte("material-one"))
	a, err := s.RecordApproval(c.Scope, c.ID, "reference", 1, digest, source.Revision)
	if err != nil {
		t.Fatal(err)
	}
	current, ok, err := s.CurrentApproval(c.Scope, source.ID)
	if err != nil || !ok || current.CommandID != a.CommandID {
		t.Fatal("approval was not durable")
	}
	c2 := controlTestPrepared(t, s, "approve", source.ID, source.Revision, "control-approval-key-0020")
	digest2, _ := s.SealPolicy(c.Scope, source.ID, []byte("material-two"))
	a2, err := s.RecordApproval(c.Scope, c2.ID, "reference", 2, digest2, source.Revision)
	if err != nil {
		t.Fatal(err)
	}
	current, _, _ = s.CurrentApproval(c.Scope, source.ID)
	if current.CommandID != a2.CommandID || current.PolicyDigest == a.PolicyDigest {
		t.Fatal("old approval remains current")
	}
	_, err = s.RecordApproval(c.Scope, c2.ID, "reference", 2, digest2, source.Revision+1)
	storeTestCode(t, err, CodeInputInvalid)
}
func TestSubscriptionStoreControlJournalCapacity(t *testing.T) {
	s, _ := storeTestOpen(t)
	c := controlTestPrepared(t, s, "create", "", 0, "control-capacity-key-0011")
	// Synthetic capacity fixture, persisted through the real Linux writer once;
	// it does not claim 4096 external audit operations were actually performed.
	next := storeClone(s.state)
	next.Commands = nil
	for i := 0; i < MaxControlCommands; i++ {
		id, err := s.ControlIdentity(c.Scope, c.OwnerID, fmt.Sprintf("capacity-key-%06d", i), []byte("material"))
		if err != nil {
			t.Fatal(err)
		}
		copy := c
		copy.ID, copy.ActorID, copy.CoreKey, copy.KeyDigest, copy.Fingerprint = id.ID, id.ActorID, id.CoreKey, id.KeyDigest, id.Fingerprint
		d := controlToDisk(copy)
		d.Seal = controlCommandSeal(next.IdentityKey, d)
		next.Commands = append(next.Commands, d)
	}
	if err := s.controlPersist(next); err != nil {
		t.Fatal(err)
	}
	_, err := s.RecordControlPrepared(c)
	storeTestCode(t, err, CodeStoreLimit)
}
func TestSubscriptionStoreControlTamperRejected(t *testing.T) {
	s, path := storeTestOpen(t)
	controlTestPrepared(t, s, "create", "", 0, "control-tamper-key-0012")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, storeSnapshotName)
	var state storeSnapshot
	if err := json.Unmarshal(storeTestRaw(t, path), &state); err != nil {
		t.Fatal(err)
	}
	state.Commands[0].OwnerID = "different@example.test"
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = OpenStore(path)
	storeTestCode(t, err, CodeStoreUnsafe)
}
