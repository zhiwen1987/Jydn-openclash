package mihomodeploy

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
)

// MODEL ONLY. No authenticated actor, kernel process, real head collector,
// dispatch permission, filesystem durability, controller, or network is used.
type lifecycleModelDisk struct {
	raw             []byte
	exists          bool
	state           lifecycleCommitState
	writeErr        error
	verifyErr       error
	reads, writes   int
	corruptReadback bool
	closed          bool
}

func (d *lifecycleModelDisk) verify() error { return d.verifyErr }
func (d *lifecycleModelDisk) readControl() ([]byte, bool, error) {
	d.reads++
	raw := bytes.Clone(d.raw)
	if d.corruptReadback && d.writes > 0 {
		raw = append(raw, ' ')
	}
	return raw, d.exists, nil
}
func (d *lifecycleModelDisk) replaceControl(raw []byte) (lifecycleCommitState, error) {
	d.writes++
	if d.state == lifecycleCommitted || d.state == lifecycleUnknown {
		d.raw = bytes.Clone(raw)
		d.exists = true
	}
	return d.state, d.writeErr
}
func (d *lifecycleModelDisk) close() error { d.closed = true; return nil }

func lifecycleTestSeal(t *testing.T, r lifecycleRecord) lifecycleRecord {
	t.Helper()
	var err error
	r.wire.RecordSHA256, err = lifecycleRecordHash(*r.wire)
	if err != nil {
		t.Fatal("model digest failed")
	}
	return r
}
func lifecycleTestRecord(t *testing.T) (lifecycleRecord, Plan, time.Time) {
	t.Helper()
	spec, now := planTestFixture(t)
	h := &lifecycleHead{Schema: lifecycleHeadSchema, DeviceRef: spec.Target.DeviceRef, Scope: spec.Target.Scope,
		Generation: spec.Target.Generation, Artifact: spec.Backup.Artifact, KernelSHA256: spec.Target.KernelSHA256,
		PID: spec.Target.PID, StartTicks: spec.Target.StartTicks, NetNSInode: spec.Target.NetNSInode,
		ControllerPort: spec.Target.ControllerPort, MixedPort: spec.Target.MixedPort,
		VerificationSHA256: strings.Repeat("5", 64), VerifiedAt: now}
	previous := strings.Repeat("6", 64)
	h.PreviousHeadSHA256 = &previous
	var err error
	h.HeadSHA256, err = lifecycleHeadHash(*h)
	if err != nil {
		t.Fatal("model head failed")
	}
	spec.Target.HeadSHA256 = h.HeadSHA256
	spec.Backup, err = newBackupDescriptor(spec.OperationID, spec.Backup.Artifact, spec.Target)
	if err != nil {
		t.Fatal("model backup failed")
	}
	p := planTestBuild(t, spec, now)
	r := lifecycleRecord{wire: &lifecycleWire{Schema: lifecycleSchema, Boundary: lifecycleBoundary, Revision: 1, LastTrustedAt: now, Head: h, Tombstones: []lifecycleTombstone{}}}
	return lifecycleTestSeal(t, r), p, now
}
func lifecycleTestOpen(t *testing.T, r lifecycleRecord) (*lifecycleStore, *lifecycleModelDisk) {
	t.Helper()
	raw, err := encodeLifecycleRecord(r)
	if err != nil {
		t.Fatal("model record rejected")
	}
	d := &lifecycleModelDisk{raw: raw, exists: true, state: lifecycleCommitted}
	s, err := openLifecycleStore(d)
	if err != nil {
		t.Fatal("model store rejected")
	}
	return s, d
}
func lifecycleTestOwner(t *testing.T, s *lifecycleStore, now time.Time) *lifecycleOwnerToken {
	t.Helper()
	token, err := s.acquireOwner(now, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal("model owner rejected")
	}
	return token
}
func lifecycleTestPrepared(t *testing.T, p Plan, now time.Time) *PreparedReload {
	t.Helper()
	old := labConfigTestSpec()
	candidate := labConfigTestSpec()
	candidate.DefaultTarget = "REJECT"
	return &PreparedReload{preparedReloadCore: &preparedReloadCore{descriptor: ReloadPreparationDescriptor{Schema: ReloadPreparationSchema, Boundary: ReloadPreparationBoundary, Plan: p.Descriptor(), PreparedAt: now},
		candidate: labConfigTestBuild(t, candidate).Bytes(), backup: labConfigTestBuild(t, old).Bytes()}}
}
func lifecycleTestArmed(t *testing.T) (*lifecycleStore, *lifecycleModelDisk, *lifecycleOwnerToken, Plan, time.Time) {
	t.Helper()
	r, p, now := lifecycleTestRecord(t)
	s, d := lifecycleTestOpen(t, r)
	token := lifecycleTestOwner(t, s, now)
	if s.recordPlan(token, p, now) != nil || s.recordApproval(token, planTestApproval(p, now), now) != nil ||
		s.recordPrepared(token, lifecycleTestPrepared(t, p, now), now) != nil || s.recordIntent(token, p.binding.Target.HeadSHA256, now) != nil {
		t.Fatal("model structural intent rejected")
	}
	return s, d, token, p, now
}
func lifecycleTestReject(t *testing.T, r lifecycleRecord) {
	t.Helper()
	r = lifecycleTestSeal(t, r)
	if _, err := encodeLifecycleRecord(r); !errors.Is(err, errLifecycleUnsafe) {
		t.Fatal("invalid model record accepted")
	}
}

func TestLifecycleCanonicalRecordHeadAndIntentBindings(t *testing.T) {
	s, _, _, _, _ := lifecycleTestArmed(t)
	raw, err := encodeLifecycleRecord(s.record)
	if err != nil {
		t.Fatal(err)
	}
	r, err := decodeLifecycleRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := encodeLifecycleRecord(r)
	if err != nil || !bytes.Equal(raw, again) || !reflect.DeepEqual(s.record, r) {
		t.Fatal("canonical model roundtrip changed")
	}
	if strings.HasSuffix(string(raw), "\n") {
		t.Fatal("wire gained newline")
	}
}
func TestLifecycleRejectsDuplicateUnknownMissingNullAndNoncanonicalJSON(t *testing.T) {
	r, _, _ := lifecycleTestRecord(t)
	raw, _ := encodeLifecycleRecord(r)
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"revision":1`), []byte(`"revision":1,"revision":1`), 1),
		bytes.Replace(raw, []byte(`"revision":1`), []byte(`"revision":1,"extra":0`), 1),
		bytes.Replace(raw, []byte(`"revision":1,`), nil, 1),
		bytes.Replace(raw, []byte(`"revision":1`), []byte(`"revision":null`), 1),
		append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"tombstones":[]`), []byte(`"tombstones":null`), 1),
	} {
		if _, err := decodeLifecycleRecord(bad); err == nil {
			t.Fatal("malformed wire accepted")
		}
	}
	for _, field := range []string{"requirements", "blockers"} {
		r, _, _ = lifecycleTestRecord(t)
		if field == "requirements" {
			r.wire.Head.Artifact.Config.Requirements = nil
		} else {
			r.wire.Head.Artifact.Config.Blockers = nil
		}
		var err error
		r.wire.Head.Artifact.RecordSHA256, err = lifecycleHash(artifactRecordFor(r.wire.Head.Artifact))
		if err != nil || validateArtifactDescriptor(r.wire.Head.Artifact) != nil {
			t.Fatal("null-list fixture did not isolate old descriptor acceptance")
		}
		r.wire.Head.HeadSHA256, err = lifecycleHeadHash(*r.wire.Head)
		if err != nil {
			t.Fatal("null-list fixture head digest")
		}
		lifecycleTestReject(t, r)
		for _, location := range []string{"candidate", "backup"} {
			_, p, _ := lifecycleTestRecord(t)
			descriptor := p.Descriptor()
			artifact := &descriptor.Artifact
			if location == "backup" {
				artifact = &descriptor.Backup.Artifact
			}
			if field == "requirements" {
				artifact.Config.Requirements = nil
			} else {
				artifact.Config.Blockers = nil
			}
			artifact.RecordSHA256, err = lifecycleHash(artifactRecordFor(*artifact))
			if err != nil || validateArtifactDescriptor(*artifact) != nil {
				t.Fatal("active null-list fixture did not isolate descriptor acceptance")
			}
			if location == "backup" {
				descriptor.Backup.BackupSHA256, err = lifecycleHash(backupRecordFor(descriptor.Backup))
				if err != nil {
					t.Fatal("backup null-list digest")
				}
			}
			descriptor.PlanSHA256, err = lifecycleHash(planBinding{Schema: descriptor.Schema, Boundary: descriptor.Boundary, OperationID: descriptor.OperationID,
				DeclaredInitiatorRef: descriptor.DeclaredInitiatorRef, Target: descriptor.Target, Artifact: descriptor.Artifact, Backup: descriptor.Backup, CreatedAt: descriptor.CreatedAt, ExpiresAt: descriptor.ExpiresAt})
			if err != nil {
				t.Fatal("active null-list plan digest")
			}
			if _, err := lifecyclePlan(descriptor); err == nil {
				t.Fatal("active candidate or backup null-list accepted")
			}
		}
	}
}
func TestLifecycleRejectsFloatBooleanStringOverflowAndLossyIntegers(t *testing.T) {
	r, _, _ := lifecycleTestRecord(t)
	raw, _ := encodeLifecycleRecord(r)
	for _, value := range []string{"1.0", "1e0", "true", `"1"`, "18446744073709551616", "-1"} {
		if _, err := decodeLifecycleRecord(bytes.Replace(raw, []byte(`"revision":1`), []byte(`"revision":`+value), 1)); err == nil {
			t.Fatal("non-uint64 accepted")
		}
	}
	r.wire.Revision = 9007199254740993
	r = lifecycleTestSeal(t, r)
	raw, err := encodeLifecycleRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeLifecycleRecord(raw)
	if err != nil || decoded.wire.Revision != 9007199254740993 {
		t.Fatal("exact integer lost precision")
	}
}
func TestLifecycleRejectsDepthAndTwoMiBResourceOverflow(t *testing.T) {
	for _, raw := range [][]byte{bytes.Repeat([]byte(" "), maxLifecycleControlBytes+1), []byte(strings.Repeat("[", 26) + "0" + strings.Repeat("]", 26))} {
		if _, err := decodeLifecycleRecord(raw); err == nil {
			t.Fatal("resource overflow accepted")
		}
	}
}
func TestLifecycleDigestTamperingAndCompleteHeadBackupBindingReject(t *testing.T) {
	r, p, _ := lifecycleTestRecord(t)
	r.wire.Head.Artifact = p.binding.Artifact
	lifecycleTestReject(t, r)
	r, _, _ = lifecycleTestRecord(t)
	r.wire.Head.KernelSHA256 = strings.Repeat("7", 64)
	lifecycleTestReject(t, r)
	s, _, _, _, _ := lifecycleTestArmed(t)
	r, _ = s.copyRecord()
	r.wire.Active.Plan.Backup.Artifact = r.wire.Active.Plan.Artifact
	lifecycleTestReject(t, r)
}
func TestLifecycleOpenMissingControlNeverBootstraps(t *testing.T) {
	d := &lifecycleModelDisk{state: lifecycleCommitted}
	if _, err := openLifecycleStore(d); err == nil || d.writes != 0 {
		t.Fatal("missing control granted initialization")
	}
}
func TestLifecycleTypedNilDiskAndZeroStoreFailClosed(t *testing.T) {
	var d *lifecycleModelDisk
	if _, err := openLifecycleStore(d); err == nil {
		t.Fatal("typed nil disk accepted")
	}
	var s lifecycleStore
	if _, err := s.acquireOwner(time.Now().UTC(), time.Now().UTC()); err == nil {
		t.Fatal("zero store accepted")
	}
	if s.close() == nil {
		t.Fatal("zero store close accepted")
	}
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	for _, store := range []*lifecycleStore{nil, &s} {
		for _, call := range []func() error{
			func() error { return store.verify() }, func() error { _, err := store.copyRecord(); return err },
			func() error { return store.commit(lifecycleRecord{}, now) }, func() error { return store.trustedNow(now) },
			func() error { return store.token(&lifecycleOwnerToken{}, false, now) },
			func() error { return store.renewOwner(nil, now, now) }, func() error { return store.recordPlan(nil, Plan{}, now) },
			func() error { return store.recordApproval(nil, ApprovalMaterial{}, now) }, func() error { return store.recordPrepared(nil, nil, now) },
			func() error { return store.recordIntent(nil, "", now) }, func() error { return store.recordResult(nil, "", mihomo.ReloadResult{}, now) },
			func() error { return store.recordRevocation(nil, "", "", now) },
		} {
			if call() == nil {
				t.Fatal("nil core entry accepted")
			}
		}
	}
	if _, err := encodeLifecycleRecord(lifecycleRecord{}); err == nil {
		t.Fatal("nil wire accepted")
	}
}
func TestLifecycleNoHeadCannotAcquireOwnerOrCreateActive(t *testing.T) {
	r, _, now := lifecycleTestRecord(t)
	r.wire.Head = nil
	r = lifecycleTestSeal(t, r)
	s, d := lifecycleTestOpen(t, r)
	if _, err := s.acquireOwner(now, now.Add(time.Minute)); err == nil || d.writes != 0 {
		t.Fatal("missing head acquired owner")
	}
}
func TestLifecycleLiveOwnerCannotBeRestoredFromJSONOrCopiedToken(t *testing.T) {
	r, _, now := lifecycleTestRecord(t)
	s, d := lifecycleTestOpen(t, r)
	token := lifecycleTestOwner(t, s, now)
	forged := *token
	if s.renewOwner(&forged, now, now.Add(3*time.Minute)) == nil {
		t.Fatal("copied token accepted")
	}
	reopened, err := openLifecycleStore(d)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.renewOwner(token, now, now.Add(3*time.Minute)) == nil {
		t.Fatal("serialized owner restored possession")
	}
	if _, err := reopened.acquireOwner(now, now.Add(4*time.Minute)); err == nil {
		t.Fatal("live recorded owner preempted")
	}
}
func TestLifecycleOwnerFenceMonotonicAndOverflowReject(t *testing.T) {
	r, _, now := lifecycleTestRecord(t)
	s, _ := lifecycleTestOpen(t, r)
	first := lifecycleTestOwner(t, s, now)
	second, err := s.acquireOwner(now.Add(3*time.Minute), now.Add(4*time.Minute))
	if err != nil || second.fence != first.fence+1 {
		t.Fatal("fence failed to advance")
	}
	if s.renewOwner(first, now.Add(3*time.Minute), now.Add(5*time.Minute)) == nil {
		t.Fatal("stale fence accepted")
	}
	r = s.record
	r.wire.LastFence = ^uint64(0)
	r.wire.Owner.Fence = ^uint64(0)
	r = lifecycleTestSeal(t, r)
	s, _ = lifecycleTestOpen(t, r)
	if _, err := s.acquireOwner(now.Add(5*time.Minute), now.Add(6*time.Minute)); err == nil {
		t.Fatal("fence wrapped")
	}
}
func TestLifecycleRevisionOverflowNeverWrites(t *testing.T) {
	r, _, now := lifecycleTestRecord(t)
	r.wire.Revision = ^uint64(0)
	r = lifecycleTestSeal(t, r)
	s, d := lifecycleTestOpen(t, r)
	if _, err := s.acquireOwner(now, now.Add(time.Minute)); err == nil || d.writes != 0 {
		t.Fatal("revision overflow wrote record")
	}
}
func TestLifecycleClockRollbackAndNonUTCReject(t *testing.T) {
	r, _, now := lifecycleTestRecord(t)
	s, d := lifecycleTestOpen(t, r)
	token := lifecycleTestOwner(t, s, now)
	if s.renewOwner(token, now, now) == nil || s.poisoned || s.live != token {
		t.Fatal("invalid expiry poisoned trusted clock")
	}
	if s.renewOwner(token, now.Add(-time.Nanosecond), now.Add(3*time.Minute)) == nil || !s.poisoned || s.live != nil {
		t.Fatal("clock rollback accepted")
	}
	if err := s.renewOwner(token, now, now.Add(3*time.Minute)); !errors.Is(err, errLifecyclePoisoned) {
		t.Fatal("corrected time silently revived poisoned owner")
	}
	reopened, err := openLifecycleStore(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.acquireOwner(now.Add(3*time.Minute), now.Add(4*time.Minute)); err != nil {
		t.Fatal("reopen lost durable trusted time")
	}
	if reopened.renewOwner(reopened.live, now.Add(-time.Nanosecond), now.Add(5*time.Minute)) == nil {
		t.Fatal("reopened time fence lost")
	}
	r.wire.LastTrustedAt = now.In(time.FixedZone("offset", 3600))
	lifecycleTestReject(t, r)
}
func TestLifecycleCASDetectsExternalRevisionBytesAndHeadReplacement(t *testing.T) {
	r, _, now := lifecycleTestRecord(t)
	s, d := lifecycleTestOpen(t, r)
	token := lifecycleTestOwner(t, s, now)
	next, _ := s.copyRecord()
	next.wire.Head.VerificationSHA256 = strings.Repeat("9", 64)
	next.wire.Head.HeadSHA256, _ = lifecycleHeadHash(*next.wire.Head)
	before := bytes.Clone(d.raw)
	if s.commit(next, now) == nil || !bytes.Equal(before, d.raw) {
		t.Fatal("private commit silently replaced head without collector")
	}
	other := s.record
	other.wire.Revision++
	other = lifecycleTestSeal(t, other)
	d.raw, _ = encodeLifecycleRecord(other)
	if s.renewOwner(token, now, now.Add(3*time.Minute)) == nil {
		t.Fatal("external CAS change accepted")
	}
	if _, err := s.acquireOwner(now.Add(3*time.Minute), now.Add(4*time.Minute)); !errors.Is(err, errLifecyclePoisoned) {
		t.Fatal("CAS conflict did not remain fail-closed")
	}
	_, disk, _, _, when := lifecycleTestArmed(t)
	// Reopening a real model ARMED record creates UNKNOWN with no fabricated
	// result. Give that shape to commit: phase alone must prevent replay.
	blocked, err := openLifecycleStore(disk)
	if err != nil {
		t.Fatal(err)
	}
	retry, _ := blocked.copyRecord()
	retry.wire.Active.Phase = "DISPATCH_ARMED"
	before = bytes.Clone(disk.raw)
	if blocked.commit(retry, when) == nil || !bytes.Equal(before, disk.raw) {
		t.Fatal("unknown phase rearmed same intent")
	}
	for _, from := range []string{"UNKNOWN", "MANUAL_REQUIRED", "RESPONSE_REJECTED"} {
		if lifecyclePhaseTransition(from, "DISPATCH_ARMED") || !lifecyclePhaseTransition(from, from) {
			t.Fatal("closed phase transition table changed")
		}
	}
}
func TestLifecycleCommittedLabelRequiresActualExactSemanticReadback(t *testing.T) {
	r, _, now := lifecycleTestRecord(t)
	s, d := lifecycleTestOpen(t, r)
	d.corruptReadback = true
	if _, err := s.acquireOwner(now, now.Add(time.Minute)); !errors.Is(err, errLifecycleCommitUnknown) {
		t.Fatal("dishonest committed label accepted")
	}
	if !s.poisoned || s.live != nil {
		t.Fatal("unknown commit retained usable owner")
	}
}
func TestLifecycleUnknownCommitPoisonsWithoutInventingResult(t *testing.T) {
	r, _, now := lifecycleTestRecord(t)
	s, d := lifecycleTestOpen(t, r)
	d.state = lifecycleUnknown
	if _, err := s.acquireOwner(now, now.Add(time.Minute)); !errors.Is(err, errLifecycleCommitUnknown) {
		t.Fatal("uncertain commit accepted")
	}
	if s.record.wire.Active != nil || !s.poisoned {
		t.Fatal("uncertainty invented result")
	}
}
func TestLifecycleDefinitePrecommitFailureIsNotCommitUnknown(t *testing.T) {
	r, _, now := lifecycleTestRecord(t)
	s, d := lifecycleTestOpen(t, r)
	d.state = lifecycleNotCommitted
	d.writeErr = errors.New("model precommit failure")
	if _, err := s.acquireOwner(now, now.Add(time.Minute)); errors.Is(err, errLifecycleCommitUnknown) || err == nil {
		t.Fatal("definite precommit mislabeled")
	}
	if s.poisoned || s.record.wire.Revision != 1 {
		t.Fatal("definite unchanged record advanced")
	}
}
func TestLifecycleUnsafeDiskFailureIsStickyPoison(t *testing.T) {
	r, _, now := lifecycleTestRecord(t)
	s, d := lifecycleTestOpen(t, r)
	d.state = lifecycleNotCommitted
	d.writeErr = errLifecycleUnsafe
	if _, err := s.acquireOwner(now, now.Add(time.Minute)); !errors.Is(err, errLifecycleUnsafe) {
		t.Fatal("unsafe failure lost")
	}
	if _, err := s.acquireOwner(now, now.Add(time.Minute)); !errors.Is(err, errLifecyclePoisoned) {
		t.Fatal("unsafe failure not sticky")
	}
}
func TestLifecycleApprovalDerivedIDDoesNotBecomeAuthority(t *testing.T) {
	r, p, now := lifecycleTestRecord(t)
	s, _ := lifecycleTestOpen(t, r)
	token := lifecycleTestOwner(t, s, now)
	if s.recordPlan(token, p, now) != nil || s.recordApproval(token, planTestApproval(p, now), now) != nil {
		t.Fatal("model material rejected")
	}
	a := s.record.wire.Active
	if a.Approval.AuthoritySnapshotRef != nil || a.Approval.ApprovalID != lifecycleApprovalID(a.Plan) || a.Attempt != 0 || a.Intent != nil {
		t.Fatal("structural approval created dispatch")
	}
	r = s.record
	r.wire.Active.Approval.ApprovalID = "caller-ticket"
	lifecycleTestReject(t, r)
}
func TestLifecyclePreparedBodyAndPlanMustMatchActualPrivatePreparation(t *testing.T) {
	r, p, now := lifecycleTestRecord(t)
	s, _ := lifecycleTestOpen(t, r)
	token := lifecycleTestOwner(t, s, now)
	if s.recordPlan(token, p, now) != nil || s.recordApproval(token, planTestApproval(p, now), now) != nil {
		t.Fatal("model setup")
	}
	before := bytes.Clone(s.raw)
	revision := s.record.wire.Revision
	for _, missing := range []*PreparedReload{nil, {}} {
		if err := s.recordPrepared(token, missing, now); !errors.Is(err, errLifecycleUnsafe) || s.record.wire.Active.Phase != "APPROVED" || s.record.wire.Revision != revision || !bytes.Equal(s.raw, before) {
			t.Fatal("missing private backing accepted or altered approved record")
		}
	}
	prepared := lifecycleTestPrepared(t, p, now)
	prepared.candidate = []byte("substituted")
	if s.recordPrepared(token, prepared, now) == nil {
		t.Fatal("substituted prepared bytes accepted")
	}
	if s.recordPrepared(token, lifecycleTestPrepared(t, p, now), now) != nil {
		t.Fatal("valid model preparation rejected")
	}
}
func TestLifecycleIntentIsSingleAttemptAndExactExpectedHead(t *testing.T) {
	s, _, token, p, now := lifecycleTestArmed(t)
	intent := s.record.wire.Active.Intent.IntentSHA256
	if s.recordIntent(token, p.binding.Target.HeadSHA256, now) == nil {
		t.Fatal("second intent accepted")
	}
	if s.record.wire.Active.Intent.IntentSHA256 != intent || s.record.wire.Active.Attempt != 1 {
		t.Fatal("attempt rewritten")
	}
	r := s.record
	r.wire.Active.Intent.ExpectedHeadSHA256 = strings.Repeat("8", 64)
	r.wire.Active.Intent.IntentSHA256, _ = lifecycleIntentHash(*r.wire.Active.Intent)
	lifecycleTestReject(t, r)
}
func TestLifecycleArmedReopenPersistsUnknownWithoutResultOrHandle(t *testing.T) {
	s, d, token, _, now := lifecycleTestArmed(t)
	reopened, err := openLifecycleStore(d)
	if err != nil || reopened.record.wire.Active.Phase != "UNKNOWN" || reopened.record.wire.Active.Result != nil || reopened.live != nil {
		t.Fatal("armed reopen fabricated outcome")
	}
	if reopened.recordResult(token, s.record.wire.Active.Intent.IntentSHA256, mihomo.ReloadResult{State: mihomo.ReloadAcknowledged, Dispatched: true, StatusCode: 204}, now) == nil {
		t.Fatal("old process owner replayed")
	}
	if _, err := reopened.acquireOwner(now.Add(3*time.Minute), now.Add(4*time.Minute)); err == nil {
		t.Fatal("TTL escaped unknown")
	}
}
func TestLifecycleExpiredReopenedPrearmOwnerCanRevokeWithoutLosingPlan(t *testing.T) {
	for _, phase := range []string{"PLANNED", "APPROVED", "PREPARED"} {
		r, p, now := lifecycleTestRecord(t)
		s, d := lifecycleTestOpen(t, r)
		old := lifecycleTestOwner(t, s, now)
		if s.recordPlan(old, p, now) != nil {
			t.Fatal("model plan failed")
		}
		if phase != "PLANNED" && s.recordApproval(old, planTestApproval(p, now), now) != nil {
			t.Fatal("model approval failed")
		}
		if phase == "PREPARED" && s.recordPrepared(old, lifecycleTestPrepared(t, p, now), now) != nil {
			t.Fatal("model preparation failed")
		}
		before := s.record.wire.Active.Plan
		reopened, err := openLifecycleStore(d)
		if err != nil {
			t.Fatal(err)
		}
		later := now.Add(3 * time.Minute)
		owner, err := reopened.acquireOwner(later, later.Add(time.Minute))
		if err != nil || owner.fence != old.fence+1 || !reflect.DeepEqual(reopened.record.wire.Active.Plan, before) || reopened.record.wire.Active.Phase != phase {
			t.Fatal("prearm recovery discarded plan")
		}
		if reopened.recordRevocation(owner, "EXPLICIT_REVOKED", "opaque-recovery-operator", later) != nil {
			t.Fatal("prearm recovery could not record revoke")
		}
		if reopened.record.wire.Active.Phase != "REVOKED" || len(reopened.record.wire.Tombstones) != 1 || reopened.recordPlan(owner, p, later) == nil {
			t.Fatal("prearm recovery revived old operation")
		}
	}
}
func TestLifecycleExpiredReopenedSentStatesNeverUsePrearmTakeover(t *testing.T) {
	for _, phase := range []string{"DISPATCH_ARMED", "ACKNOWLEDGED", "UNKNOWN", "RESPONSE_REJECTED", "MANUAL_REQUIRED"} {
		s, d, token, _, now := lifecycleTestArmed(t)
		switch phase {
		case "ACKNOWLEDGED":
			if s.recordResult(token, s.record.wire.Active.Intent.IntentSHA256, mihomo.ReloadResult{State: mihomo.ReloadAcknowledged, Dispatched: true, StatusCode: 204}, now) != nil {
				t.Fatal("model ack failed")
			}
		case "UNKNOWN":
			if s.recordResult(token, s.record.wire.Active.Intent.IntentSHA256, mihomo.ReloadResult{State: mihomo.ReloadUnknown, Dispatched: true}, now) != nil {
				t.Fatal("model unknown failed")
			}
		case "RESPONSE_REJECTED":
			if s.recordResult(token, s.record.wire.Active.Intent.IntentSHA256, mihomo.ReloadResult{State: mihomo.ReloadRejected, Dispatched: true, StatusCode: 403}, now) != nil {
				t.Fatal("model rejection failed")
			}
		case "MANUAL_REQUIRED":
			r, _ := s.copyRecord()
			r.wire.Active.Phase = phase
			r = lifecycleTestSeal(t, r)
			d.raw, _ = encodeLifecycleRecord(r)
		}
		reopened, err := openLifecycleStore(d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reopened.acquireOwner(now.Add(3*time.Minute), now.Add(4*time.Minute)); err == nil {
			t.Fatal("sent state acquired prearm recovery owner")
		}
		if reopened.live != nil || reopened.record.wire.Active.Attempt != 1 {
			t.Fatal("sent state manufactured handle")
		}
	}
}
func TestLifecycleAcknowledgedReopenUnknownPreservesObservedResult(t *testing.T) {
	s, d, token, _, now := lifecycleTestArmed(t)
	result := mihomo.ReloadResult{State: mihomo.ReloadAcknowledged, Dispatched: true, StatusCode: 204}
	if s.recordResult(token, s.record.wire.Active.Intent.IntentSHA256, result, now) != nil {
		t.Fatal("model result rejected")
	}
	reopened, err := openLifecycleStore(d)
	if err != nil || reopened.record.wire.Active.Phase != "UNKNOWN" || reopened.record.wire.Active.Result.Reload != result {
		t.Fatal("ack reopen discarded observation")
	}
}
func TestLifecycleConcurrentRevocationRetainsActuallyObservedResult(t *testing.T) {
	s, _, token, _, now := lifecycleTestArmed(t)
	intent := s.record.wire.Active.Intent.IntentSHA256
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs <- s.recordRevocation(token, "EXPLICIT_REVOKED", "opaque-revoker", now) }()
	go func() {
		defer wg.Done()
		errs <- s.recordResult(token, intent, mihomo.ReloadResult{State: mihomo.ReloadAcknowledged, Dispatched: true, StatusCode: 204}, now)
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("model concurrent mutation rejected")
		}
	}
	a := s.record.wire.Active
	if a.Revocation == nil || a.Result == nil || a.Result.Reload.StatusCode != 204 || a.Phase != "ACKNOWLEDGED" {
		t.Fatal("concurrent facts overwritten")
	}
}
func TestLifecycleExpiredOwnerAndApprovalDoNotEraseObservedResult(t *testing.T) {
	s, _, token, _, now := lifecycleTestArmed(t)
	later := now.Add(20 * time.Minute)
	if s.recordRevocation(token, "EXPIRED", "opaque-time-observer", later) != nil {
		t.Fatal("expiry fact rejected")
	}
	result := mihomo.ReloadResult{State: mihomo.ReloadUnknown, Dispatched: true}
	if s.recordResult(token, s.record.wire.Active.Intent.IntentSHA256, result, later) != nil {
		t.Fatal("expired owner lost already observed result")
	}
	raw, err := encodeLifecycleRecord(s.record)
	if err != nil {
		t.Fatal(err)
	}
	r, err := decodeLifecycleRecord(raw)
	if err != nil || r.wire.Active.Result.Reload != result || r.wire.Active.Revocation.Reason != "EXPIRED" {
		t.Fatal("expiry discarded facts")
	}
}
func TestLifecycleAllReloadResultCombinationsAreClosed(t *testing.T) {
	for _, bad := range []mihomo.ReloadResult{{}, {State: mihomo.ReloadAcknowledged}, {State: mihomo.ReloadAcknowledged, Dispatched: true, StatusCode: 200},
		{State: mihomo.ReloadUnknown}, {State: mihomo.ReloadUnknown, Dispatched: true, StatusCode: 99}, {State: mihomo.ReloadRejected, Dispatched: true, StatusCode: 500}} {
		if lifecycleResultValid(bad) {
			t.Fatal("invalid result accepted")
		}
	}
	if !lifecycleResultValid(mihomo.ReloadResult{State: mihomo.ReloadUnknown, Dispatched: true, StatusCode: 204}) {
		t.Fatal("actual ambiguous 204 cannot be recorded")
	}
}
func TestLifecycleUnsentRejectionTombstonePreventsOperationReplay(t *testing.T) {
	s, _, token, p, now := lifecycleTestArmed(t)
	if s.recordResult(token, s.record.wire.Active.Intent.IntentSHA256, mihomo.ReloadResult{State: mihomo.ReloadRejected}, now) != nil {
		t.Fatal("unsent result rejected")
	}
	if len(s.record.wire.Tombstones) != 1 || s.record.wire.Tombstones[0].Attempt != 1 || s.record.wire.Tombstones[0].IntentSHA256 == nil {
		t.Fatal("attempt fact missing from tombstone")
	}
	if s.recordPlan(token, p, now) == nil {
		t.Fatal("operation replay accepted")
	}
}
func TestLifecycleResponseRejectionAndUnknownRemainBlocking(t *testing.T) {
	for _, result := range []mihomo.ReloadResult{{State: mihomo.ReloadRejected, Dispatched: true, StatusCode: 403}, {State: mihomo.ReloadUnknown, Dispatched: true}} {
		s, _, token, p, now := lifecycleTestArmed(t)
		if s.recordResult(token, s.record.wire.Active.Intent.IntentSHA256, result, now) != nil {
			t.Fatal("model result rejected")
		}
		if s.recordPlan(token, p, now) == nil {
			t.Fatal("unreconciled attempt replaced")
		}
		if _, err := s.acquireOwner(now.Add(3*time.Minute), now.Add(4*time.Minute)); err == nil {
			t.Fatal("unreconciled attempt preempted")
		}
	}
}
func TestLifecyclePreArmRevocationCannotBeClearedByReapproval(t *testing.T) {
	r, p, now := lifecycleTestRecord(t)
	s, _ := lifecycleTestOpen(t, r)
	token := lifecycleTestOwner(t, s, now)
	if s.recordPlan(token, p, now) != nil || s.recordRevocation(token, "AUTHORITY_CHANGED", "opaque-revoker", now) != nil {
		t.Fatal("model revoke failed")
	}
	if s.recordApproval(token, planTestApproval(p, now), now) == nil || s.recordPlan(token, p, now) == nil {
		t.Fatal("revoked operation revived")
	}
	if s.record.wire.Active.Revocation == nil || len(s.record.wire.Tombstones) != 1 {
		t.Fatal("revocation history lost")
	}
}
func TestLifecycleTombstoneCapacityRejectsWithoutGarbageCollection(t *testing.T) {
	r, p, now := lifecycleTestRecord(t)
	r.wire.Revision = 300
	for i := 0; i < maxLifecycleTombstones; i++ {
		r.wire.Tombstones = append(r.wire.Tombstones, lifecycleTombstone{OperationID: fmt.Sprintf("used-%d", i), PlanSHA256: fmt.Sprintf("%064x", i+1), Phase: "REVOKED", TerminalRevision: uint64(i + 1)})
	}
	r = lifecycleTestSeal(t, r)
	s, d := lifecycleTestOpen(t, r)
	token := lifecycleTestOwner(t, s, now)
	before := bytes.Clone(d.raw)
	if s.recordPlan(token, p, now) == nil || len(s.record.wire.Tombstones) != 256 || !bytes.Equal(before, d.raw) {
		t.Fatal("capacity silently removed replay evidence")
	}
	next, _ := s.copyRecord()
	next.wire.Tombstones = next.wire.Tombstones[1:]
	if s.commit(next, now) == nil || !bytes.Equal(before, d.raw) {
		t.Fatal("private commit discarded tombstone history")
	}
	r.wire.Tombstones = append(r.wire.Tombstones, r.wire.Tombstones[0])
	lifecycleTestReject(t, r)
}
func TestLifecycleTombstoneIdentityAndTerminalRevisionMustBeUnique(t *testing.T) {
	r, _, _ := lifecycleTestRecord(t)
	r.wire.Revision = 3
	r.wire.Tombstones = []lifecycleTombstone{{OperationID: "used-a", PlanSHA256: strings.Repeat("8", 64), Phase: "REVOKED", TerminalRevision: 2}, {OperationID: "used-a", PlanSHA256: strings.Repeat("9", 64), Phase: "REVOKED", TerminalRevision: 3}}
	lifecycleTestReject(t, r)
	r.wire.Tombstones[1].OperationID = "used-b"
	r.wire.Tombstones[1].TerminalRevision = 2
	lifecycleTestReject(t, r)
}
func TestLifecycleCurrentCodecRejectsUnimplementedSuccessReadbackRecovery(t *testing.T) {
	for _, phase := range []string{"VERIFIED_SUCCESS", "RECONCILED_CURRENT_POSTCONDITION", lifecycleCompletedPhase} {
		s, _, _, _, _ := lifecycleTestArmed(t)
		r := s.record
		r.wire.Active.Phase = phase
		lifecycleTestReject(t, r)
	}
	s, _, _, _, now := lifecycleTestArmed(t)
	r := s.record
	r.wire.Active.Readback = &lifecycleReadback{Conclusion: "OBSERVED_NEW_PROJECTION", EvidenceSHA256: strings.Repeat("8", 64), ObservedAt: now}
	lifecycleTestReject(t, r)
	r.wire.Active.Readback = nil
	raw := json.RawMessage(`{}`)
	r.wire.Active.Recovery = &raw
	lifecycleTestReject(t, r)
}
func TestLifecycleAuditProjectionRejectsUnknownDuplicateOrArbitraryText(t *testing.T) {
	s, _, _, _, _ := lifecycleTestArmed(t)
	for _, keys := range [][]string{nil, {"arbitrary private event"}, {"PLANNED", "PLANNED"}} {
		r, _ := s.copyRecord()
		r.wire.Active.AuditProjection = keys
		lifecycleTestReject(t, r)
	}
}
func TestLifecycleRecordOwnerStoreFormattingAndJSONNeverExportPrivateIdentity(t *testing.T) {
	s, _, token, _, _ := lifecycleTestArmed(t)
	record := s.record
	privateRaw, _ := encodeLifecycleRecord(record)
	needles := []string{token.nonce, hex.EncodeToString([]byte(token.nonce)), base64.StdEncoding.EncodeToString([]byte(token.nonce)),
		string(privateRaw), hex.EncodeToString(privateRaw), base64.StdEncoding.EncodeToString(privateRaw),
		record.wire.Head.HeadSHA256, record.wire.Head.DeviceRef, record.wire.Active.Plan.DeclaredInitiatorRef}
	for _, value := range []any{record, &record, *token, token, *s, s, lifecycleRecord{}, lifecycleOwnerToken{}, lifecycleStore{}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%x"} {
			if got := fmt.Sprintf(verb, value); got != lifecycleDebug {
				t.Fatal("formatter exposed private structure")
			}
		}
		// fmt can bypass methods for an invalid value %p. The wrapper must
		// contain only an opaque pointer, so even that diagnostic stays safe.
		// Type/address output is not promised to be the fixed label.
		for _, verb := range []string{"%p", "%d", "%T", "%x"} {
			got := fmt.Sprintf(verb, value)
			for _, needle := range needles {
				if needle != "" && strings.Contains(got, needle) {
					t.Fatal("format fallback exposed private material")
				}
			}
		}
		expected := `{"scope":"STRUCTURAL_RECORD_NOT_AUTHORIZATION"}`
		switch value.(type) {
		case lifecycleOwnerToken, *lifecycleOwnerToken:
			expected = `{"scope":"IN_MEMORY_OWNER_NOT_AUTHORIZATION"}`
		case lifecycleStore, *lifecycleStore:
			expected = `{"scope":"PRIVATE_LIFECYCLE_STORE_NOT_AUTHORIZATION"}`
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != expected {
			t.Fatal("JSON exposed owner or identity")
		}
	}
	var recordNil *lifecycleRecord
	var ownerNil *lifecycleOwnerToken
	var storeNil *lifecycleStore
	// Only typed nil pointers exercise these Formatter implementations.
	// Untyped nil with %x is a standard fmt diagnostic, not their output.
	for _, value := range []any{recordNil, ownerNil, storeNil} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%x"} {
			if got := fmt.Sprintf(verb, value); got != "<nil>" {
				t.Fatal("typed nil formatting changed")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != "null" {
			t.Fatal("nil JSON changed")
		}
	}
	for _, value := range []any{lifecycleRecord{}, lifecycleStore{}, lifecycleOwnerToken{}} {
		typ := reflect.TypeOf(value)
		if typ.NumField() != 1 || typ.Field(0).Type.Kind() != reflect.Pointer {
			t.Fatal("opaque wrapper grew inline private state")
		}
	}
}
func TestLifecycleCloseInvalidatesOwnerAndCannotBeReused(t *testing.T) {
	r, _, now := lifecycleTestRecord(t)
	s, d := lifecycleTestOpen(t, r)
	token := lifecycleTestOwner(t, s, now)
	if s.close() != nil || !d.closed || s.live != nil {
		t.Fatal("close retained owner")
	}
	if s.renewOwner(token, now, now.Add(3*time.Minute)) == nil || s.close() == nil {
		t.Fatal("closed store reused")
	}
}
