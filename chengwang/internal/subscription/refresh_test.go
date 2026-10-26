//go:build linux

package subscription

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type refreshLegacyControlCommandV1 struct {
	ID                string         `json:"id"`
	Scope             Scope          `json:"scope"`
	ActorID           string         `json:"actorId"`
	Kind              string         `json:"kind"`
	SourceID          string         `json:"sourceId,omitempty"`
	ExpectedRevision  uint64         `json:"expectedRevision"`
	Fingerprint       string         `json:"fingerprint"`
	PreparedAt        time.Time      `json:"preparedAt"`
	PreparedAuditHash string         `json:"preparedAuditHash"`
	Result            *ControlResult `json:"result,omitempty"`
	ResultAuditHash   string         `json:"resultAuditHash,omitempty"`
	Acknowledged      bool           `json:"acknowledged"`
}
type refreshLegacyControlDiskV1 struct {
	Record    refreshLegacyControlCommandV1 `json:"record"`
	OwnerID   string                        `json:"ownerId"`
	CoreKey   string                        `json:"coreKey"`
	KeyDigest string                        `json:"keyDigest"`
	Seal      string                        `json:"seal"`
}
type refreshLegacyStoreV1 struct {
	Schema      string                       `json:"schema"`
	IdentityKey []byte                       `json:"identityKey"`
	Sources     []SourceView                 `json:"sources"`
	Candidates  []storeCandidate             `json:"candidates"`
	Requests    []storeRequest               `json:"requests"`
	Audit       []storeAudit                 `json:"audit"`
	Commands    []refreshLegacyControlDiskV1 `json:"commands,omitempty"`
	Approvals   []ControlApproval            `json:"approvals,omitempty"`
}

func refreshTestBinding(source SourceView) RefreshBinding {
	return RefreshBinding{SourceID: source.ID, ReferenceID: "enterprise-a", PolicyRevision: 1, ApprovalID: "cmd_" + strings.Repeat("a", 32), ApprovalSourceRevision: source.Revision, IntervalSeconds: 60, ApprovalTTLSeconds: 600, MaxStaleSeconds: 300, MaxBackoffSeconds: 600}
}
func refreshTestCapacity() StoreCapacity {
	return StoreCapacity{CommandsMax: MaxControlCommands, CandidatesMax: MaxCandidates, DomainAuditMax: MaxAuditEntries, EncodedBytesMax: MaxStoreBytes}
}
func refreshTestOpen(t *testing.T) (*RefreshStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "refresh-v3")
	s, err := OpenRefreshStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}
func refreshCompleteUnknown(t *testing.T, s *RefreshStore, a RefreshView, now time.Time) {
	t.Helper()
	_, err := s.Complete(a.Scope, a.Binding.SourceID, RefreshCompletion{AttemptKey: a.AttemptKey, AttemptSequence: a.AttemptSequence, BindingSeal: a.BindingSeal, Fence: a.Fence, State: RefreshUnknown, Failure: RefreshFailureUnknown, StateMayHaveChanged: true, Lease: a.Lease}, now)
	if err != nil {
		t.Fatal(err)
	}
}
func refreshCompleteBlocked(t *testing.T, s *RefreshStore, a RefreshView, now time.Time) {
	t.Helper()
	_, err := s.Complete(a.Scope, a.Binding.SourceID, RefreshCompletion{AttemptKey: a.AttemptKey, AttemptSequence: a.AttemptSequence, BindingSeal: a.BindingSeal, Fence: a.Fence, State: RefreshBlocked, Failure: RefreshFailureApproval, Lease: a.Lease}, now)
	if err != nil {
		t.Fatal(err)
	}
}
func refreshTestSnapshot(t *testing.T, s *RefreshStore) refreshSnapshot {
	t.Helper()
	s.mu.Lock()
	raw, err := refreshEncode(s.state)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var out refreshSnapshot
	if err = refreshDecode(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func refreshTestMemoryRaw(t *testing.T, s *RefreshStore) []byte {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := refreshEncode(s.state)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func refreshTestWriteSnapshot(t *testing.T, dir string, snapshot refreshSnapshot) {
	t.Helper()
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err = os.WriteFile(filepath.Join(dir, storeSnapshotName), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func refreshTestRejectReopen(t *testing.T, s *RefreshStore, dir string, snapshot refreshSnapshot) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	refreshTestWriteSnapshot(t, dir, snapshot)
	reopened, err := OpenRefreshStore(dir)
	if err == nil {
		_ = reopened.Close()
		t.Fatal("invalid canonical snapshot reopened")
	}
	storeTestCode(t, err, CodeStoreUnsafe)
}
func refreshTestAcceptReopen(t *testing.T, s *RefreshStore, dir string) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRefreshStore(dir)
	if err != nil {
		t.Fatal("producer state did not reopen", err)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
}
func refreshTestNotCommitted(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrRefreshCommitNotCommitted) {
		t.Fatal("expected known-not-committed sidecar failure", err)
	}
}

func TestRefreshV3RestartRecoveryIsSingleUseAndUnknownTerminal(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Refresh", "refresh-create-key-0001")
	sidecar, dir := refreshTestOpen(t)
	now := time.Date(2026, 10, 26, 1, 2, 3, 0, time.UTC)
	if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	attempt, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now)
	if err != nil || !claimed || attempt.State != RefreshRunning {
		t.Fatal("claim failed")
	}
	forged := RefreshCompletion{AttemptKey: attempt.AttemptKey, AttemptSequence: attempt.AttemptSequence, BindingSeal: attempt.BindingSeal, Fence: attempt.Fence, State: RefreshBlocked, Failure: RefreshFailureApproval, Lease: &RefreshAttemptLease{}}
	if _, err = sidecar.Complete(source.Scope, source.ID, forged, now); err == nil {
		t.Fatal("forged completion capability was accepted")
	}
	if _, claimed, err = sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now); err != nil || claimed {
		t.Fatal("live claim was incorrectly replayed")
	}
	liveRecovery, err := sidecar.TakeRecovery()
	if err != nil {
		t.Fatal(err)
	}
	if _, claimed, err = sidecar.ClaimRecovery(source.Scope, source.ID, liveRecovery, now); err == nil || claimed {
		t.Fatal("live process forged restart entitlement")
	}
	if err = sidecar.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRefreshStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovery, err := reopened.TakeRecovery()
	if err != nil {
		t.Fatal(err)
	}
	recovered, claimed, err := reopened.ClaimRecovery(source.Scope, source.ID, recovery, now)
	if err != nil || !claimed || recovered.AttemptKey != attempt.AttemptKey || recovered.Fence != attempt.Fence {
		t.Fatal("restart recovery lost durable identity")
	}
	if _, claimed, err = reopened.ClaimRecovery(source.Scope, source.ID, recovery, now); err == nil || claimed {
		t.Fatal("restart claim was recovered twice")
	}
	refreshCompleteUnknown(t, reopened, recovered, now.Add(time.Second))
	blocked, claimed, err := reopened.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
	if err != nil || claimed || blocked.State != RefreshUnknown || !blocked.NextAttemptAt.IsZero() {
		t.Fatal("unknown was blindly retried")
	}
}

func TestRefreshV3AttemptIdentityNeverRepeatsAcrossBindingDeleteReaddAndRestart(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Generation", "refresh-create-key-0002")
	sidecar, dir := refreshTestOpen(t)
	now := time.Date(2026, 10, 26, 2, 0, 0, 0, time.UTC)
	binding := refreshTestBinding(source)
	if err := sidecar.Reconcile(source.Scope, []RefreshBinding{binding}, now); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	first, ok, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now)
	if err != nil || !ok {
		t.Fatal("first claim failed")
	}
	refreshCompleteBlocked(t, sidecar, first, now.Add(time.Second))
	binding.PolicyRevision++
	binding.ApprovalID = "cmd_" + strings.Repeat("b", 32)
	if err = sidecar.Reconcile(source.Scope, []RefreshBinding{binding}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	second, ok, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now)
	if err != nil || !ok {
		t.Fatal("changed binding claim failed")
	}
	if first.AttemptKey == second.AttemptKey || first.Fence == second.Fence || first.AttemptSequence >= second.AttemptSequence || first.BindingSeal == second.BindingSeal {
		t.Fatal("changed binding reused attempt identity")
	}
	refreshCompleteBlocked(t, sidecar, second, now.Add(time.Second))
	if err = sidecar.Reconcile(source.Scope, []RefreshBinding{}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = sidecar.Reconcile(source.Scope, []RefreshBinding{binding}, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	third, ok, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now)
	if err != nil || !ok || third.AttemptSequence <= second.AttemptSequence || third.AttemptKey == second.AttemptKey {
		t.Fatal("delete/readd reused attempt identity")
	}
	if err = sidecar.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRefreshStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovery, err := reopened.TakeRecovery()
	if err != nil {
		t.Fatal(err)
	}
	recovered, ok, err := reopened.ClaimRecovery(source.Scope, source.ID, recovery, now)
	if err != nil || !ok || recovered.AttemptSequence != third.AttemptSequence || recovered.AttemptKey != third.AttemptKey {
		t.Fatal("restart changed in-flight identity")
	}
}

func TestRefreshV3ClockRollbackAndForwardJumpFreeze(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Clock", "refresh-create-key-0003")
	sidecar, _ := refreshTestOpen(t)
	now := time.Date(2026, 10, 26, 3, 0, 0, 0, time.UTC)
	if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
		t.Fatal(err)
	}
	view, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(-time.Second))
	if err != nil || claimed || view.ClockState != RefreshClockFrozen || view.ClockReason != "wall_clock_rollback" || !view.Stale {
		t.Fatal("rollback did not freeze scheduler")
	}
	other, _ := refreshTestOpen(t)
	if err = other.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
		t.Fatal(err)
	}
	view, claimed, err = other.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(MaxRefreshClockStep+time.Second))
	if err != nil || claimed || view.ClockState != RefreshClockFrozen || view.ClockReason != "wall_clock_forward_jump" {
		t.Fatal("forward jump did not freeze scheduler")
	}
}

func TestRefreshV3SequenceOverflowAndTenantScopeFailClosed(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Overflow", "refresh-create-key-0004")
	sidecar, _ := refreshTestOpen(t)
	now := time.Date(2026, 10, 26, 4, 0, 0, 0, time.UTC)
	if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
		t.Fatal(err)
	}
	sidecar.mu.Lock()
	next := sidecar.state
	next.LastSequence = math.MaxUint64
	if err := sidecar.persist(next); err != nil {
		sidecar.mu.Unlock()
		t.Fatal(err)
	}
	sidecar.mu.Unlock()
	view, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
	if err != nil || claimed || view.State != RefreshBlocked || view.Failure != RefreshFailureSequence {
		t.Fatal("sequence exhaustion was not terminal")
	}
	foreign := source.Scope
	foreign.TenantID = "tenant-foreign"
	if _, err = sidecar.Refresh(foreign, source.ID, now.Add(time.Minute)); err == nil {
		t.Fatal("foreign tenant read crossed sidecar scope")
	}
	if err = sidecar.Reconcile(foreign, []RefreshBinding{refreshTestBinding(source)}, now.Add(time.Minute)); err == nil {
		t.Fatal("foreign tenant reconcile reused ledger")
	}
}

func TestRefreshV3CandidatePreservesAcceptedVersion(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source, accepted := storeTestAdmitted(t, domain)
	sidecar, _ := refreshTestOpen(t)
	now := source.UpdatedAt.Add(time.Minute)
	binding := refreshTestBinding(source)
	if err := sidecar.Reconcile(source.Scope, []RefreshBinding{binding}, now); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	attempt, ok, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now)
	if err != nil || !ok {
		t.Fatal("claim failed")
	}
	identity, err := domain.ControlIdentity(source.Scope, "refresh-machine", attempt.AttemptKey, []byte("automated refresh material"))
	if err != nil {
		t.Fatal(err)
	}
	command := ControlCommand{ID: identity.ID, Scope: source.Scope, ActorID: identity.ActorID, OwnerID: "refresh-machine", CoreKey: identity.CoreKey, KeyDigest: identity.KeyDigest, Fingerprint: identity.Fingerprint, Kind: "fetch", SourceID: source.ID, ExpectedRevision: source.Revision, PreparedAt: now, PreparedAuditHash: strings.Repeat("a", 64)}
	if created, err := domain.RecordControlPrepared(command); err != nil || !created {
		t.Fatal("prepare failed")
	}
	candidate, err := domain.Import(ImportRequest{Scope: source.Scope, SourceID: source.ID, ExpectedRevision: source.Revision, ActorID: identity.ActorID, IdempotencyKey: identity.CoreKey, Format: FormatMihomo, Content: storeTestBody("new", "new.example")})
	if err != nil {
		t.Fatal(err)
	}
	m, exists, err := domain.MutationReceipt(source.Scope, identity.ActorID, identity.CoreKey)
	if err != nil || !exists {
		t.Fatal("receipt missing")
	}
	result := ControlResult{SourceID: m.SourceID, CandidateID: m.CandidateID, Revision: m.Revision, Digest: m.Digest, State: "committed", LocalAuditHash: m.LocalAuditHash, CompletedAt: m.CompletedAt}
	if err = domain.RecordControlResult(source.Scope, command.ID, result); err != nil {
		t.Fatal(err)
	}
	if err = domain.AcknowledgeControl(source.Scope, command.ID, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if err = sidecar.BindCommand(source.Scope, source.ID, attempt, "refresh-machine", command.ID); err != nil {
		t.Fatal(err)
	}
	view, err := sidecar.Complete(source.Scope, source.ID, RefreshCompletion{AttemptKey: attempt.AttemptKey, AttemptSequence: attempt.AttemptSequence, BindingSeal: attempt.BindingSeal, Fence: attempt.Fence, State: RefreshCandidateQuarantined, CommandID: command.ID, CandidateID: candidate.ID, CandidateDigest: candidate.Digest, ResultRevision: candidate.BaseRevision, AuditRecorded: true, Lease: attempt.Lease}, now.Add(time.Second))
	if err != nil || view.State != RefreshCandidateQuarantined || !view.NextAttemptAt.IsZero() {
		t.Fatal("candidate not terminal")
	}
	current := storeTestCurrent(t, domain, source.ID)
	if current.AcceptedCandidateID != accepted.ID || current.LatestCandidateID != candidate.ID {
		t.Fatal("accepted LKV changed")
	}
}

func TestRefreshV3DurableReservationIsGlobalBoundedAndUnknownRetained(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Reservation", "refresh-create-key-0005")
	sidecar, dir := refreshTestOpen(t)
	now := time.Date(2026, 10, 26, 5, 0, 0, 0, time.UTC)
	if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
		t.Fatal(err)
	}
	full := refreshTestCapacity()
	full.CommandsUsed = full.CommandsMax
	if _, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, full, now.Add(time.Minute)); err == nil || claimed {
		t.Fatal("global command capacity was not fail closed")
	}
	cap := refreshTestCapacity()
	cap.EncodedBytes = cap.EncodedBytesMax - MaxRefreshReservationBytes + 1
	if _, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, cap, now.Add(time.Minute)); err == nil || claimed {
		t.Fatal("encoded byte reservation was not enforced")
	}
	attempt, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
	if err != nil || !claimed || attempt.Reservation == nil {
		t.Fatal("durable reservation missing")
	}
	boundCommand := "cmd_" + strings.Repeat("c", 32)
	owner := "refresh-machine"
	if err = sidecar.BindCommand(source.Scope, source.ID, attempt, owner, boundCommand); err != nil {
		t.Fatal(err)
	}
	if err = sidecar.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRefreshStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reserved, err := reopened.ReservedCapacity()
	if err != nil || reserved.CommandsUsed != 1 || reserved.CandidatesUsed != 1 || reserved.DomainAuditUsed != 1 || reserved.EncodedBytes != MaxStoreBytes {
		t.Fatal("restart lost capacity ownership")
	}
	recovery, err := reopened.TakeRecovery()
	if err != nil {
		t.Fatal(err)
	}
	recovered, ok, err := reopened.ClaimRecovery(source.Scope, source.ID, recovery, now.Add(time.Minute))
	if err != nil || !ok || recovered.CommandID != boundCommand || recovered.CommandOwnerID != owner || recovered.CommandEpoch == "" {
		t.Fatal("issuer-bound command mapping was not recoverable")
	}
	if err = reopened.BindCommand(source.Scope, source.ID, recovered, "different-owner", boundCommand); err == nil {
		t.Fatal("recovery lease rebound automated owner")
	}
	if err = reopened.BindCommand(source.Scope, source.ID, recovered, owner, boundCommand); err != nil {
		t.Fatal("issuer-bound recovery mapping did not revalidate")
	}
	if err = reopened.BindCommand(source.Scope, source.ID, recovered, owner, boundCommand); err == nil {
		t.Fatal("recovery lease was reusable")
	}
	refreshCompleteUnknown(t, reopened, recovered, now.Add(2*time.Minute))
	view, err := reopened.Refresh(source.Scope, source.ID, now.Add(2*time.Minute))
	if err != nil || view.CommandID != boundCommand || view.CommandOwnerID != owner {
		t.Fatal("unknown lost automated command association")
	}
	reserved, err = reopened.ReservedCapacity()
	if err != nil || reserved.CommandsUsed != 1 {
		t.Fatal("unknown released protected ownership")
	}
	changed := refreshTestBinding(source)
	changed.PolicyRevision++
	changed.ApprovalID = "cmd_" + strings.Repeat("d", 32)
	if err = reopened.Reconcile(source.Scope, []RefreshBinding{changed}, now.Add(3*time.Minute)); err == nil {
		t.Fatal("unknown binding was silently replaced")
	}
}

func TestRefreshV3CheckpointRotationRevokesInflightAndSingleStoreMismatchIsVisible(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Checkpoint", "refresh-create-key-0006")
	sidecar, _ := refreshTestOpen(t)
	now := time.Date(2026, 10, 26, 6, 0, 0, 0, time.UTC)
	epoch, _, _, ready, err := sidecar.Checkpoint()
	if err != nil || ready {
		t.Fatal("new checkpoint state invalid")
	}
	marker := "cmd_" + strings.Repeat("d", 32)
	if err = sidecar.FinalizeCheckpoint(epoch, marker); err != nil {
		t.Fatal(err)
	}
	if err = sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute)); err != nil || !ok {
		t.Fatal("claim failed")
	}
	recovery, err := sidecar.TakeRecovery()
	if err != nil {
		t.Fatal(err)
	}
	if err = sidecar.RotateCheckpoint(recovery, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	rotated, id, previous, ready, err := sidecar.Checkpoint()
	if err != nil || ready || id != "" || previous != marker || rotated == epoch {
		t.Fatal("restore did not rotate pending epoch")
	}
	view, err := sidecar.Refresh(source.Scope, source.ID, now.Add(2*time.Minute))
	if err != nil || view.State != RefreshUnknown || view.Reservation == nil {
		t.Fatal("restore did not revoke inflight as unknown")
	}
	if rotated == epoch {
		t.Fatal("single-store restore would be indistinguishable")
	}
}

func TestRefreshV3MainStoreWireHasNoAutomationField(t *testing.T) {
	domain, dir := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Wire", "refresh-create-key-0007")
	identity, err := domain.ControlIdentity(source.Scope, "refresh-machine", "refresh-wire-key-00001", []byte("wire"))
	if err != nil {
		t.Fatal(err)
	}
	command := ControlCommand{ID: identity.ID, Scope: source.Scope, ActorID: identity.ActorID, OwnerID: "refresh-machine", CoreKey: identity.CoreKey, KeyDigest: identity.KeyDigest, Fingerprint: identity.Fingerprint, Kind: "fetch", SourceID: source.ID, ExpectedRevision: source.Revision, PreparedAt: time.Now().UTC(), PreparedAuditHash: strings.Repeat("e", 64)}
	if created, err := domain.RecordControlPrepared(command); err != nil || !created {
		t.Fatal("prepare failed")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("\"automated\"")) {
		t.Fatal("strict v1 wire gained automation field")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var legacy refreshLegacyStoreV1
	if err = decoder.Decode(&legacy); err != nil {
		t.Fatal("historical strict v1 DTO rejected wire", err)
	}
	if err = decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatal("historical strict v1 DTO accepted trailing data")
	}
	if len(legacy.Commands) != 1 {
		t.Fatal("historical strict v1 DTO lost command")
	}
	if err = domain.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal("strict v1 reader rejected automation command", err)
	}
	defer reopened.Close()
}

func TestRefreshV3MainCheckpointAnchorIsStrictAndScopeBound(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Anchor", "refresh-create-key-0008")
	epoch := strings.Repeat("f", 64)
	identity, err := domain.ControlIdentity(source.Scope, "refresh-machine", "refresh-anchor-key-0001", []byte("refresh-checkpoint-v3:"+epoch))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	command := ControlCommand{ID: identity.ID, Scope: source.Scope, ActorID: identity.ActorID, OwnerID: "refresh-machine", CoreKey: identity.CoreKey, KeyDigest: identity.KeyDigest, Fingerprint: identity.Fingerprint, Kind: "fetch", SourceID: source.ID, ExpectedRevision: source.Revision, PreparedAt: at, PreparedAuditHash: strings.Repeat("a", 64)}
	if created, err := domain.RecordControlPrepared(command); err != nil || !created {
		t.Fatal("prepare failed")
	}
	result := ControlResult{SourceID: source.ID, Revision: source.Revision, State: "failed", Code: "subscription_unavailable", ReferenceID: "refresh-epoch-" + epoch, CompletedAt: at}
	if err = domain.RecordControlResult(source.Scope, command.ID, result); err != nil {
		t.Fatal(err)
	}
	if err = domain.AcknowledgeControl(source.Scope, command.ID, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	id, got, found, err := domain.LatestRefreshCheckpoint(source.Scope)
	if err != nil || !found || id != command.ID || got != epoch {
		t.Fatal("main checkpoint anchor not reconstructed")
	}
	foreign := source.Scope
	foreign.TenantID = "tenant-foreign"
	if _, _, found, err = domain.LatestRefreshCheckpoint(foreign); err != nil || found {
		t.Fatal("checkpoint crossed tenant scope")
	}
}

func TestRefreshV3SchemaAndStateTruthTableRejectSilentDowngrade(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Truth", "refresh-create-key-0009")
	sidecar, _ := refreshTestOpen(t)
	now := time.Date(2026, 10, 26, 7, 0, 0, 0, time.UTC)
	if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
		t.Fatal(err)
	}
	sidecar.mu.Lock()
	snapshot := sidecar.state
	sidecar.mu.Unlock()
	snapshot.Schema = refreshLegacySchema
	if err := validateRefreshSnapshot(snapshot); err == nil {
		t.Fatal("legacy schema was silently accepted")
	}
	snapshot.Schema = refreshSchema
	snapshot.Refreshes[0].State = RefreshRunning
	snapshot.Refreshes[0].AttemptSequence = 1
	snapshot.Refreshes[0].AttemptKey = "refresh_" + strings.Repeat("a", 32)
	snapshot.Refreshes[0].Fence = strings.Repeat("b", 64)
	snapshot.Refreshes[0].StartedAt = now
	snapshot.Refreshes[0].NextAttemptAt = time.Time{}
	snapshot.LastSequence = 1
	snapshot.Ledgers[0].LastIssuedSequence = 1
	snapshot.Refreshes[0].Reservation = nil
	if err := validateRefreshSnapshot(snapshot); err == nil {
		t.Fatal("running state without reservation was accepted")
	}
}

func TestRefreshV3RestoreEpochPreventsAttemptReplayAfterSequenceRollback(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Epoch", "refresh-create-key-0010")
	sidecar, _ := refreshTestOpen(t)
	now := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
		t.Fatal(err)
	}
	recovery, err := sidecar.TakeRecovery()
	if err != nil {
		t.Fatal(err)
	}
	sidecar.mu.Lock()
	raw, err := refreshEncode(sidecar.state)
	sidecar.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var before refreshSnapshot
	if err = refreshDecode(raw, &before); err != nil {
		t.Fatal(err)
	}
	first, ok, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
	if err != nil || !ok {
		t.Fatal("first claim failed")
	}
	refreshCompleteBlocked(t, sidecar, first, now.Add(2*time.Minute))
	sidecar.mu.Lock()
	if err = sidecar.persist(before); err != nil {
		sidecar.mu.Unlock()
		t.Fatal(err)
	}
	sidecar.mu.Unlock()
	if err = sidecar.RotateCheckpoint(recovery, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	second, ok, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(4*time.Minute))
	if err != nil || !ok || second.AttemptSequence != first.AttemptSequence || second.AttemptKey == first.AttemptKey || second.Fence == first.Fence {
		t.Fatal("restored sequence replayed old attempt identity")
	}
}

func TestRefreshV4BindCommandDefiniteFailureRetainsCapabilityForExactRetry(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Bind retry", "refresh-v4-bind-create-0001")
	sidecar, dir := refreshTestOpen(t)
	now := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
		t.Fatal(err)
	}
	attempt, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
	if err != nil || !claimed {
		t.Fatal("claim failed")
	}
	identity, err := domain.ControlIdentity(source.Scope, "refresh-machine", attempt.AttemptKey, []byte("v4 bind retry material"))
	if err != nil {
		t.Fatal(err)
	}
	commandID := identity.ID
	command := ControlCommand{ID: commandID, Scope: source.Scope, ActorID: identity.ActorID, OwnerID: "refresh-machine", CoreKey: identity.CoreKey, KeyDigest: identity.KeyDigest, Fingerprint: identity.Fingerprint, Kind: "fetch", SourceID: source.ID, ExpectedRevision: source.Revision, PreparedAt: now.Add(time.Minute), PreparedAuditHash: strings.Repeat("1", 64)}
	if created, err := domain.RecordControlPrepared(command); err != nil || !created {
		t.Fatal("main command prepare failed", err)
	}
	mainBefore, err := domain.Capacity(source.Scope)
	if err != nil || mainBefore.CommandsUsed != 1 {
		t.Fatal("main command capacity missing", err)
	}
	before := storeTestRaw(t, dir)
	writes := 0
	disk := sidecar.disk.(*storeLinuxDisk)
	disk.beforeRename = func() error {
		writes++
		if writes == 1 {
			return errors.New("injected-definite-before-rename")
		}
		return nil
	}
	err = sidecar.BindCommand(source.Scope, source.ID, attempt, "refresh-machine", commandID)
	refreshTestNotCommitted(t, err)
	if !bytes.Equal(before, storeTestRaw(t, dir)) || !bytes.Equal(before, refreshTestMemoryRaw(t, sidecar)) {
		t.Fatal("definite bind failure changed durable or in-memory snapshot")
	}
	if attempt.Lease.bound {
		t.Fatal("definite bind failure consumed capability")
	}
	if err = sidecar.BindCommand(source.Scope, source.ID, attempt, "refresh-machine", commandID); err != nil {
		t.Fatal("same capability could not retry exact bind", err)
	}
	if writes != 2 {
		t.Fatal("bind retry did not reach writer")
	}
	if !attempt.Lease.bound {
		t.Fatal("successful bind did not consume capability")
	}
	mainAfter, err := domain.Capacity(source.Scope)
	if err != nil || mainAfter.CommandsUsed != mainBefore.CommandsUsed {
		t.Fatal("sidecar retry duplicated main command", err)
	}
	if err = sidecar.BindCommand(source.Scope, source.ID, attempt, "refresh-machine", commandID); err == nil {
		t.Fatal("used bind capability replayed")
	}
	foreign, _ := refreshTestOpen(t)
	if err = foreign.BindCommand(source.Scope, source.ID, attempt, "refresh-machine", commandID); err == nil {
		t.Fatal("foreign store accepted bind capability")
	}
	if err = sidecar.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRefreshStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	snapshot := refreshTestSnapshot(t, reopened)
	if snapshot.Refreshes[0].CommandID != commandID {
		t.Fatal("bind retry did not survive reopen")
	}
}

func TestRefreshV4CompleteDefiniteFailureRetainsCapabilityForExactRetry(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Complete retry", "refresh-v4-complete-create-0001")
	sidecar, dir := refreshTestOpen(t)
	now := time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)
	if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
		t.Fatal(err)
	}
	attempt, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
	if err != nil || !claimed {
		t.Fatal("claim failed")
	}
	completedAt := now.Add(2 * time.Minute)
	if _, err = sidecar.Refresh(source.Scope, source.ID, completedAt); err != nil {
		t.Fatal(err)
	}
	before := storeTestRaw(t, dir)
	calls := 0
	disk := sidecar.disk.(*storeLinuxDisk)
	disk.beforeRename = func() error {
		calls++
		if calls == 2 {
			return errors.New("injected-definite-before-rename")
		}
		return nil
	}
	completion := RefreshCompletion{AttemptKey: attempt.AttemptKey, AttemptSequence: attempt.AttemptSequence, BindingSeal: attempt.BindingSeal, Fence: attempt.Fence, State: RefreshBlocked, Failure: RefreshFailureApproval, Lease: attempt.Lease}
	_, err = sidecar.Complete(source.Scope, source.ID, completion, completedAt)
	refreshTestNotCommitted(t, err)
	if calls != 2 {
		t.Fatal("fault did not target completion persist")
	}
	if !bytes.Equal(before, storeTestRaw(t, dir)) || !bytes.Equal(before, refreshTestMemoryRaw(t, sidecar)) {
		t.Fatal("definite completion failure changed durable or in-memory target state")
	}
	if attempt.Lease.completed {
		t.Fatal("definite completion failure consumed capability")
	}
	if got := refreshTestSnapshot(t, sidecar).Refreshes[0]; got.State != RefreshRunning {
		t.Fatal("definite completion failure changed in-memory producer state")
	}
	if _, err = sidecar.Complete(source.Scope, source.ID, completion, completedAt); err != nil {
		t.Fatal("same capability could not retry exact completion", err)
	}
	if calls != 4 {
		t.Fatal("completion retry did not reach observe and completion writers")
	}
	if !attempt.Lease.completed {
		t.Fatal("successful completion did not consume capability")
	}
	if _, err = sidecar.Complete(source.Scope, source.ID, completion, completedAt); err == nil {
		t.Fatal("used completion capability replayed")
	}
	if err = sidecar.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRefreshStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if snapshot := refreshTestSnapshot(t, reopened); snapshot.Refreshes[0].State != RefreshBlocked {
		t.Fatal("completion retry did not survive reopen")
	}
}

func TestRefreshV4RotateDefiniteFailureRetainsRecoveryCapabilityForExactRetry(t *testing.T) {
	sidecar, dir := refreshTestOpen(t)
	recovery, err := sidecar.TakeRecovery()
	if err != nil {
		t.Fatal(err)
	}
	epoch, _, _, _, err := sidecar.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	before := storeTestRaw(t, dir)
	writes := 0
	disk := sidecar.disk.(*storeLinuxDisk)
	disk.beforeRename = func() error {
		writes++
		if writes == 1 {
			return errors.New("injected-definite-before-rename")
		}
		return nil
	}
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	err = sidecar.RotateCheckpoint(recovery, now)
	refreshTestNotCommitted(t, err)
	if !bytes.Equal(before, storeTestRaw(t, dir)) || !bytes.Equal(before, refreshTestMemoryRaw(t, sidecar)) {
		t.Fatal("definite rotation failure changed durable or in-memory snapshot")
	}
	if recovery.closed || recovery.store != sidecar {
		t.Fatal("definite rotation failure consumed recovery capability")
	}
	if err = sidecar.RotateCheckpoint(recovery, now); err != nil {
		t.Fatal("same recovery capability could not retry rotation", err)
	}
	if writes != 2 {
		t.Fatal("rotation retry did not reach writer")
	}
	rotated, _, _, _, err := sidecar.Checkpoint()
	if err != nil || rotated == epoch {
		t.Fatal("successful retry did not rotate epoch")
	}
	if err = sidecar.RotateCheckpoint(recovery, now); err == nil {
		t.Fatal("used recovery capability replayed")
	}
	foreign, _ := refreshTestOpen(t)
	foreignRecovery, err := foreign.TakeRecovery()
	if err != nil {
		t.Fatal(err)
	}
	if err = sidecar.RotateCheckpoint(foreignRecovery, now); err == nil {
		t.Fatal("foreign recovery capability was accepted")
	}
	if err = sidecar.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRefreshStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopenedEpoch, _, _, _, err := reopened.Checkpoint()
	if err != nil || reopenedEpoch != rotated {
		t.Fatal("rotation retry did not survive reopen")
	}
}

func TestRefreshV4UncertainBindPoisonsAndCannotReplayCapability(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Bind uncertain", "refresh-v4-uncertain-create-0001")
	sidecar, dir := refreshTestOpen(t)
	now := time.Date(2026, 10, 26, 13, 0, 0, 0, time.UTC)
	if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
		t.Fatal(err)
	}
	attempt, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
	if err != nil || !claimed {
		t.Fatal("claim failed")
	}
	commandID := "cmd_" + strings.Repeat("2", 32)
	disk := sidecar.disk.(*storeLinuxDisk)
	disk.syncDirectory = func(*os.File) error { return errors.New("injected-uncertain-directory-sync") }
	err = sidecar.BindCommand(source.Scope, source.ID, attempt, "refresh-machine", commandID)
	storeTestCode(t, err, CodeCommitUncertain)
	if attempt.Lease.bound {
		t.Fatal("uncertain bind fabricated a committed capability state")
	}
	err = sidecar.BindCommand(source.Scope, source.ID, attempt, "refresh-machine", commandID)
	storeTestCode(t, err, CodeCommitUncertain)
	if err = sidecar.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRefreshStore(dir)
	if err != nil {
		t.Fatal("reopen could not reconcile renamed uncertain bytes", err)
	}
	defer reopened.Close()
	snapshot := refreshTestSnapshot(t, reopened)
	if len(snapshot.Refreshes) != 1 || snapshot.Refreshes[0].CommandID != commandID || snapshot.Refreshes[0].CommandOwnerID != "refresh-machine" {
		t.Fatal("reopen did not recover actual uncertain bind bytes")
	}
}

func TestRefreshV4UncertainCompleteAndRotatePoisonWithoutReplay(t *testing.T) {
	t.Run("complete", func(t *testing.T) {
		domain, _ := storeTestOpen(t)
		source := storeTestCreate(t, domain, "Complete uncertain", "refresh-v4-uncertain-create-0002")
		sidecar, dir := refreshTestOpen(t)
		now := time.Date(2026, 10, 26, 13, 10, 0, 0, time.UTC)
		if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
			t.Fatal(err)
		}
		attempt, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
		if err != nil || !claimed {
			t.Fatal("claim failed")
		}
		completedAt := now.Add(2 * time.Minute)
		if _, err = sidecar.Refresh(source.Scope, source.ID, completedAt); err != nil {
			t.Fatal(err)
		}
		disk := sidecar.disk.(*storeLinuxDisk)
		syncDirectory := disk.syncDirectory
		calls := 0
		disk.syncDirectory = func(file *os.File) error {
			calls++
			if calls == 2 {
				return errors.New("injected-uncertain-directory-sync")
			}
			return syncDirectory(file)
		}
		completion := RefreshCompletion{AttemptKey: attempt.AttemptKey, AttemptSequence: attempt.AttemptSequence, BindingSeal: attempt.BindingSeal, Fence: attempt.Fence, State: RefreshBlocked, Failure: RefreshFailureApproval, Lease: attempt.Lease}
		_, err = sidecar.Complete(source.Scope, source.ID, completion, completedAt)
		storeTestCode(t, err, CodeCommitUncertain)
		if calls != 2 {
			t.Fatal("fault did not target completion directory sync")
		}
		if attempt.Lease.completed {
			t.Fatal("uncertain completion fabricated a committed capability state")
		}
		_, err = sidecar.Complete(source.Scope, source.ID, completion, completedAt)
		storeTestCode(t, err, CodeCommitUncertain)
		if err = sidecar.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenRefreshStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		snapshot := refreshTestSnapshot(t, reopened)
		if snapshot.Refreshes[0].State != RefreshBlocked || snapshot.Refreshes[0].Failure != RefreshFailureApproval {
			t.Fatal("reopen did not recover actual uncertain completion bytes")
		}
	})
	t.Run("rotate", func(t *testing.T) {
		sidecar, dir := refreshTestOpen(t)
		recovery, err := sidecar.TakeRecovery()
		if err != nil {
			t.Fatal(err)
		}
		beforeEpoch, _, _, _, err := sidecar.Checkpoint()
		if err != nil {
			t.Fatal(err)
		}
		disk := sidecar.disk.(*storeLinuxDisk)
		disk.syncDirectory = func(*os.File) error { return errors.New("injected-uncertain-directory-sync") }
		err = sidecar.RotateCheckpoint(recovery, time.Date(2026, 10, 26, 13, 20, 0, 0, time.UTC))
		storeTestCode(t, err, CodeCommitUncertain)
		if recovery.closed || recovery.store != sidecar {
			t.Fatal("uncertain rotation fabricated a consumed capability state")
		}
		err = sidecar.RotateCheckpoint(recovery, time.Date(2026, 10, 26, 13, 20, 0, 0, time.UTC))
		storeTestCode(t, err, CodeCommitUncertain)
		if err = sidecar.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenRefreshStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		epoch, _, _, _, err := reopened.Checkpoint()
		if err != nil || epoch == beforeEpoch {
			t.Fatal("reopen did not recover actual uncertain rotation bytes")
		}
	})
}

func TestRefreshV4CanonicalReopenRejectsUnreachableProducerStates(t *testing.T) {
	setup := func(t *testing.T, name, key string) (*RefreshStore, string, SourceView, time.Time) {
		domain, _ := storeTestOpen(t)
		source := storeTestCreate(t, domain, name, key)
		sidecar, dir := refreshTestOpen(t)
		now := time.Date(2026, 10, 26, 14, 0, 0, 0, time.UTC)
		if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
			t.Fatal(err)
		}
		return sidecar, dir, source, now
	}
	t.Run("failed_without_attempt_or_completion", func(t *testing.T) {
		sidecar, dir, _, now := setup(t, "Failed impossible", "refresh-v4-truth-create-0001")
		snapshot := refreshTestSnapshot(t, sidecar)
		snapshot.Refreshes[0].State = RefreshFailed
		snapshot.Refreshes[0].Failure = RefreshFailureTransport
		snapshot.Refreshes[0].ConsecutiveFailures = 1
		snapshot.Refreshes[0].NextAttemptAt = now.Add(time.Minute)
		refreshTestRejectReopen(t, sidecar, dir, snapshot)
	})
	t.Run("idle_with_completion_residue", func(t *testing.T) {
		sidecar, dir, _, now := setup(t, "Idle impossible", "refresh-v4-truth-create-0002")
		snapshot := refreshTestSnapshot(t, sidecar)
		snapshot.Refreshes[0].CompletedAt = now
		refreshTestRejectReopen(t, sidecar, dir, snapshot)
	})
	t.Run("idle_with_failure_counter_residue", func(t *testing.T) {
		sidecar, dir, _, _ := setup(t, "Idle failure residue", "refresh-v4-truth-create-0006")
		snapshot := refreshTestSnapshot(t, sidecar)
		snapshot.Refreshes[0].ConsecutiveFailures = 1
		refreshTestRejectReopen(t, sidecar, dir, snapshot)
	})
	t.Run("succeeded_noop_without_success_window_or_next", func(t *testing.T) {
		sidecar, dir, source, now := setup(t, "Noop impossible", "refresh-v4-truth-create-0003")
		attempt, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
		if err != nil || !claimed {
			t.Fatal("claim failed")
		}
		commandID := "cmd_" + strings.Repeat("3", 32)
		if err = sidecar.BindCommand(source.Scope, source.ID, attempt, "refresh-machine", commandID); err != nil {
			t.Fatal(err)
		}
		_, err = sidecar.Complete(source.Scope, source.ID, RefreshCompletion{AttemptKey: attempt.AttemptKey, AttemptSequence: attempt.AttemptSequence, BindingSeal: attempt.BindingSeal, Fence: attempt.Fence, State: RefreshSucceededNoop, CommandID: commandID, CandidateID: "cand_" + strings.Repeat("3", 32), CandidateDigest: "hmac-sha256:" + strings.Repeat("3", 64), ResultRevision: source.Revision, AuditRecorded: true, Lease: attempt.Lease}, now.Add(2*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		snapshot := refreshTestSnapshot(t, sidecar)
		snapshot.Refreshes[0].LastSuccessAt = time.Time{}
		snapshot.Refreshes[0].FreshUntil = time.Time{}
		snapshot.Refreshes[0].NextAttemptAt = time.Time{}
		refreshTestRejectReopen(t, sidecar, dir, snapshot)
	})
	t.Run("aggregate_running_reservations_exceed_global_slot_and_bytes", func(t *testing.T) {
		domain, _ := storeTestOpen(t)
		first := storeTestCreate(t, domain, "Aggregate first", "refresh-v4-truth-create-0004")
		second := storeTestCreate(t, domain, "Aggregate second", "refresh-v4-truth-create-0005")
		sidecar, dir := refreshTestOpen(t)
		now := time.Date(2026, 10, 26, 15, 0, 0, 0, time.UTC)
		if err := sidecar.Reconcile(first.Scope, []RefreshBinding{refreshTestBinding(first), refreshTestBinding(second)}, now); err != nil {
			t.Fatal(err)
		}
		snapshot := refreshTestSnapshot(t, sidecar)
		snapshot.LastSequence = 2
		for i := range snapshot.Refreshes {
			sequence := uint64(i + 1)
			v := &snapshot.Refreshes[i]
			v.State = RefreshRunning
			v.AttemptCount = 1
			v.AttemptSequence = sequence
			v.AttemptKey = "refresh_" + strings.Repeat(string(rune('a'+i)), 32)
			v.Fence = strings.Repeat(string(rune('c'+i)), 64)
			v.StartedAt = now.Add(time.Minute)
			v.NextAttemptAt = time.Time{}
			v.Reservation = &RefreshReservation{AttemptSequence: sequence, AttemptKey: v.AttemptKey, Fence: v.Fence, CommandSlots: 1, CandidateSlots: 1, DomainAuditSlots: 1, Bytes: MaxStoreBytes}
			for j := range snapshot.Ledgers {
				if snapshot.Ledgers[j].SourceID == v.Binding.SourceID {
					snapshot.Ledgers[j].LastIssuedSequence = sequence
				}
			}
		}
		refreshTestRejectReopen(t, sidecar, dir, snapshot)
	})
}

func TestRefreshV4EveryProducerStatePersistsAndReopens(t *testing.T) {
	states := []RefreshState{RefreshIdle, RefreshRunning, RefreshSucceededNoop, RefreshCandidateQuarantined, RefreshFailed, RefreshBlocked, RefreshUnknown, RefreshState("sequence_blocked")}
	for index, state := range states {
		t.Run(string(state), func(t *testing.T) {
			domain, _ := storeTestOpen(t)
			source := storeTestCreate(t, domain, "Producer "+string(state), "refresh-v4-producer-create-"+strings.Repeat(string(rune('a'+index)), 4))
			sidecar, dir := refreshTestOpen(t)
			now := time.Date(2026, 10, 26, 16, index, 0, 0, time.UTC)
			if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
				t.Fatal(err)
			}
			if state == RefreshIdle {
				refreshTestAcceptReopen(t, sidecar, dir)
				return
			}
			if state == RefreshState("sequence_blocked") {
				sidecar.mu.Lock()
				snapshot := sidecar.state
				snapshot.LastSequence = math.MaxUint64
				if err := sidecar.persist(snapshot); err != nil {
					sidecar.mu.Unlock()
					t.Fatal(err)
				}
				sidecar.mu.Unlock()
				view, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
				if err != nil || claimed || view.State != RefreshBlocked || view.Failure != RefreshFailureSequence {
					t.Fatal("sequence exhaustion producer failed")
				}
				refreshTestAcceptReopen(t, sidecar, dir)
				return
			}
			attempt, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
			if err != nil || !claimed {
				t.Fatal("claim failed")
			}
			if state == RefreshRunning {
				refreshTestAcceptReopen(t, sidecar, dir)
				return
			}
			completedAt := now.Add(2 * time.Minute)
			switch state {
			case RefreshSucceededNoop, RefreshCandidateQuarantined:
				commandID := "cmd_" + strings.Repeat(string(rune('4'+index)), 32)
				if err = sidecar.BindCommand(source.Scope, source.ID, attempt, "refresh-machine", commandID); err != nil {
					t.Fatal(err)
				}
				_, err = sidecar.Complete(source.Scope, source.ID, RefreshCompletion{AttemptKey: attempt.AttemptKey, AttemptSequence: attempt.AttemptSequence, BindingSeal: attempt.BindingSeal, Fence: attempt.Fence, State: state, CommandID: commandID, CandidateID: "cand_" + strings.Repeat(string(rune('4'+index)), 32), CandidateDigest: "hmac-sha256:" + strings.Repeat(string(rune('4'+index)), 64), ResultRevision: source.Revision, AuditRecorded: true, Lease: attempt.Lease}, completedAt)
			case RefreshFailed:
				_, err = sidecar.Complete(source.Scope, source.ID, RefreshCompletion{AttemptKey: attempt.AttemptKey, AttemptSequence: attempt.AttemptSequence, BindingSeal: attempt.BindingSeal, Fence: attempt.Fence, State: RefreshFailed, Failure: RefreshFailureTransport, Lease: attempt.Lease}, completedAt)
			case RefreshBlocked:
				_, err = sidecar.Complete(source.Scope, source.ID, RefreshCompletion{AttemptKey: attempt.AttemptKey, AttemptSequence: attempt.AttemptSequence, BindingSeal: attempt.BindingSeal, Fence: attempt.Fence, State: RefreshBlocked, Failure: RefreshFailureApproval, Lease: attempt.Lease}, completedAt)
			case RefreshUnknown:
				_, err = sidecar.Complete(source.Scope, source.ID, RefreshCompletion{AttemptKey: attempt.AttemptKey, AttemptSequence: attempt.AttemptSequence, BindingSeal: attempt.BindingSeal, Fence: attempt.Fence, State: RefreshUnknown, Failure: RefreshFailureUnknown, StateMayHaveChanged: true, Lease: attempt.Lease}, completedAt)
			}
			if err != nil {
				t.Fatal(err)
			}
			refreshTestAcceptReopen(t, sidecar, dir)
		})
	}
}

func TestRefreshV5AllRemainingMutatorsDefiniteCutPreserveOwnedPreimageAndRetry(t *testing.T) {
	assertPreimage := func(t *testing.T, s *RefreshStore, dir string, before []byte) {
		t.Helper()
		if !bytes.Equal(before, storeTestRaw(t, dir)) || !bytes.Equal(before, refreshTestMemoryRaw(t, s)) {
			t.Fatal("definite cut changed durable or owned in-memory preimage")
		}
	}
	t.Run("finalize_checkpoint", func(t *testing.T) {
		sidecar, dir := refreshTestOpen(t)
		epoch, _, _, _, err := sidecar.Checkpoint()
		if err != nil {
			t.Fatal(err)
		}
		before := storeTestRaw(t, dir)
		calls := 0
		disk := sidecar.disk.(*storeLinuxDisk)
		disk.beforeRename = func() error {
			calls++
			if calls == 1 {
				return errors.New("definite")
			}
			return nil
		}
		commandID := "cmd_" + strings.Repeat("4", 32)
		err = sidecar.FinalizeCheckpoint(epoch, commandID)
		refreshTestNotCommitted(t, err)
		assertPreimage(t, sidecar, dir, before)
		if err = sidecar.FinalizeCheckpoint(epoch, commandID); err != nil || calls != 2 {
			t.Fatal("finalize retry did not rewrite", err)
		}
		if err = sidecar.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenRefreshStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		_, id, _, ready, err := reopened.Checkpoint()
		if err != nil || !ready || id != commandID {
			t.Fatal("finalize retry did not survive reopen")
		}
	})
	t.Run("observe", func(t *testing.T) {
		sidecar, dir := refreshTestOpen(t)
		now := time.Date(2026, 10, 27, 1, 0, 0, 0, time.UTC)
		before := storeTestRaw(t, dir)
		calls := 0
		disk := sidecar.disk.(*storeLinuxDisk)
		disk.beforeRename = func() error {
			calls++
			if calls == 1 {
				return errors.New("definite")
			}
			return nil
		}
		_, err := sidecar.Refreshes(storeTestScope(), now)
		refreshTestNotCommitted(t, err)
		assertPreimage(t, sidecar, dir, before)
		if _, err = sidecar.Refreshes(storeTestScope(), now); err != nil || calls != 2 {
			t.Fatal("observe retry did not rewrite", err)
		}
		if err = sidecar.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenRefreshStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		snapshot := refreshTestSnapshot(t, reopened)
		if !snapshot.LastWallClock.Equal(now) {
			t.Fatal("observe retry did not survive reopen")
		}
	})
	t.Run("reconcile", func(t *testing.T) {
		domain, _ := storeTestOpen(t)
		source := storeTestCreate(t, domain, "Reconcile retry", "refresh-v5-reconcile-create-0001")
		sidecar, dir := refreshTestOpen(t)
		now := time.Date(2026, 10, 27, 2, 0, 0, 0, time.UTC)
		if _, err := sidecar.Refreshes(source.Scope, now); err != nil {
			t.Fatal(err)
		}
		before := storeTestRaw(t, dir)
		calls := 0
		disk := sidecar.disk.(*storeLinuxDisk)
		disk.beforeRename = func() error {
			calls++
			if calls == 2 {
				return errors.New("definite")
			}
			return nil
		}
		err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now)
		refreshTestNotCommitted(t, err)
		if calls != 2 {
			t.Fatal("fault missed reconcile target")
		}
		assertPreimage(t, sidecar, dir, before)
		if err = sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil || calls != 4 {
			t.Fatal("reconcile retry did not rewrite target", err)
		}
		if err = sidecar.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenRefreshStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		if snapshot := refreshTestSnapshot(t, reopened); len(snapshot.Refreshes) != 1 {
			t.Fatal("reconcile retry did not survive reopen")
		}
	})
	t.Run("claim", func(t *testing.T) {
		domain, _ := storeTestOpen(t)
		source := storeTestCreate(t, domain, "Claim retry", "refresh-v5-claim-create-0001")
		sidecar, dir := refreshTestOpen(t)
		now := time.Date(2026, 10, 27, 3, 0, 0, 0, time.UTC)
		if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
			t.Fatal(err)
		}
		claimAt := now.Add(time.Minute)
		if _, err := sidecar.Refresh(source.Scope, source.ID, claimAt); err != nil {
			t.Fatal(err)
		}
		before := storeTestRaw(t, dir)
		calls := 0
		disk := sidecar.disk.(*storeLinuxDisk)
		disk.beforeRename = func() error {
			calls++
			if calls == 2 {
				return errors.New("definite")
			}
			return nil
		}
		_, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), claimAt)
		refreshTestNotCommitted(t, err)
		if claimed || calls != 2 {
			t.Fatal("failed claim issued authority or missed target")
		}
		assertPreimage(t, sidecar, dir, before)
		attempt, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), claimAt)
		if err != nil || !claimed || attempt.Lease == nil || calls != 4 {
			t.Fatal("claim retry did not rewrite target")
		}
		if err = sidecar.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenRefreshStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		if snapshot := refreshTestSnapshot(t, reopened); snapshot.Refreshes[0].State != RefreshRunning {
			t.Fatal("claim retry did not survive reopen")
		}
	})
	t.Run("reservation", func(t *testing.T) {
		domain, _ := storeTestOpen(t)
		source := storeTestCreate(t, domain, "Reservation retry", "refresh-v5-reservation-create-0001")
		sidecar, dir := refreshTestOpen(t)
		now := time.Date(2026, 10, 27, 4, 0, 0, 0, time.UTC)
		if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
			t.Fatal(err)
		}
		attempt, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
		if err != nil || !claimed {
			t.Fatal("claim failed")
		}
		commandID := "cmd_" + strings.Repeat("5", 32)
		if err = sidecar.BindCommand(source.Scope, source.ID, attempt, "refresh-machine", commandID); err != nil {
			t.Fatal(err)
		}
		command := &ControlCommand{ID: commandID, Scope: source.Scope, OwnerID: "refresh-machine", SourceID: source.ID}
		before := storeTestRaw(t, dir)
		calls := 0
		disk := sidecar.disk.(*storeLinuxDisk)
		disk.beforeRename = func() error {
			calls++
			if calls == 1 {
				return errors.New("definite")
			}
			return nil
		}
		err = sidecar.ReconcileReservation(source.Scope, source.ID, attempt, command)
		refreshTestNotCommitted(t, err)
		assertPreimage(t, sidecar, dir, before)
		if err = sidecar.ReconcileReservation(source.Scope, source.ID, attempt, command); err != nil || calls != 2 {
			t.Fatal("reservation retry did not rewrite", err)
		}
		if err = sidecar.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenRefreshStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		snapshot := refreshTestSnapshot(t, reopened)
		if snapshot.Refreshes[0].Reservation == nil || snapshot.Refreshes[0].Reservation.CommandSlots != 0 {
			t.Fatal("reservation retry did not survive reopen")
		}
	})
}

func TestRefreshV5ReturnedReservationsAreDetachedFromOwnedState(t *testing.T) {
	domain, _ := storeTestOpen(t)
	source := storeTestCreate(t, domain, "Detached", "refresh-v5-detached-create-0001")
	sidecar, dir := refreshTestOpen(t)
	now := time.Date(2026, 10, 27, 5, 0, 0, 0, time.UTC)
	if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
		t.Fatal(err)
	}
	attempt, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
	if err != nil || !claimed || attempt.Reservation == nil {
		t.Fatal("claim failed")
	}
	owned := refreshTestMemoryRaw(t, sidecar)
	attempt.Reservation.Bytes = 0
	attempt.Reservation.CommandSlots = 0
	if !bytes.Equal(owned, refreshTestMemoryRaw(t, sidecar)) {
		t.Fatal("ClaimLive leaked reservation pointer")
	}
	views, err := sidecar.Refreshes(source.Scope, now.Add(time.Minute))
	if err != nil || len(views) != 1 || views[0].Reservation == nil {
		t.Fatal("list failed")
	}
	single, err := sidecar.Refresh(source.Scope, source.ID, now.Add(time.Minute))
	if err != nil || single.Reservation == nil {
		t.Fatal("read failed")
	}
	snapshotViews, err := sidecar.SnapshotRefreshes(source.Scope, now.Add(time.Minute))
	if err != nil || len(snapshotViews) != 1 || snapshotViews[0].Reservation == nil {
		t.Fatal("snapshot list failed")
	}
	snapshotSingle, err := sidecar.SnapshotRefresh(source.Scope, source.ID, now.Add(time.Minute))
	if err != nil || snapshotSingle.Reservation == nil {
		t.Fatal("snapshot read failed")
	}
	owned = refreshTestMemoryRaw(t, sidecar)
	views[0].Reservation.Bytes = 1
	single.Reservation.CandidateSlots = 0
	snapshotViews[0].Reservation.DomainAuditSlots = 0
	snapshotSingle.Reservation.CommandSlots = 0
	if !bytes.Equal(owned, refreshTestMemoryRaw(t, sidecar)) {
		t.Fatal("read APIs leaked reservation pointer")
	}
	reserved, err := sidecar.ReservedCapacity()
	if err != nil || reserved.CommandsUsed != 1 || reserved.CandidatesUsed != 1 || reserved.EncodedBytes != MaxStoreBytes {
		t.Fatal("detached mutation changed capacity authority")
	}
	if err = sidecar.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRefreshStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovery, err := reopened.TakeRecovery()
	if err != nil {
		t.Fatal(err)
	}
	recovered, ok, err := reopened.ClaimRecovery(source.Scope, source.ID, recovery, now.Add(time.Minute))
	if err != nil || !ok || recovered.Reservation == nil {
		t.Fatal("recovery claim failed")
	}
	reopenedOwned := refreshTestMemoryRaw(t, reopened)
	recovered.Reservation.DomainAuditSlots = 0
	if !bytes.Equal(reopenedOwned, refreshTestMemoryRaw(t, reopened)) {
		t.Fatal("ClaimRecovery leaked reservation pointer")
	}
}

func TestRefreshV5CanonicalReopenRejectsPositiveAttemptBelowLedgerHighwater(t *testing.T) {
	for _, state := range []RefreshState{RefreshRunning, RefreshBlocked, RefreshUnknown} {
		t.Run(string(state), func(t *testing.T) {
			domain, _ := storeTestOpen(t)
			source := storeTestCreate(t, domain, "Ledger "+string(state), "refresh-v5-ledger-create-"+string(state))
			sidecar, dir := refreshTestOpen(t)
			now := time.Date(2026, 10, 27, 6, 0, 0, 0, time.UTC)
			if err := sidecar.Reconcile(source.Scope, []RefreshBinding{refreshTestBinding(source)}, now); err != nil {
				t.Fatal(err)
			}
			attempt, claimed, err := sidecar.ClaimLive(source.Scope, source.ID, refreshTestCapacity(), now.Add(time.Minute))
			if err != nil || !claimed {
				t.Fatal("claim failed")
			}
			if state == RefreshBlocked {
				refreshCompleteBlocked(t, sidecar, attempt, now.Add(2*time.Minute))
			} else if state == RefreshUnknown {
				refreshCompleteUnknown(t, sidecar, attempt, now.Add(2*time.Minute))
			}
			snapshot := refreshTestSnapshot(t, sidecar)
			snapshot.LastSequence++
			snapshot.Ledgers[0].LastIssuedSequence = snapshot.LastSequence
			refreshTestRejectReopen(t, sidecar, dir, snapshot)
		})
	}
}
