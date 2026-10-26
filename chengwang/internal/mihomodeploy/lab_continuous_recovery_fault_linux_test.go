//go:build linux && chengwang_mihomo_recovery_continuous_fault && chengwang_mihomo_recovery_native

package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
)

type labContinuousSecondRecoveryModel struct {
	runtime       *labLifecycleRuntime
	current       *lifecycleStore
	recovery      *lifecycleRecoveryStore
	recoveryOwner *lifecycleRecoveryOwnerToken
	plan          labRecoveryPlan
	revision      uint64
	recordSHA256  string
	disk          *labBootstrapModelDisk
	history       []lifecycleRecoveryTxn
	now           time.Time
}

var _ labRuntimeDisk = (*labBootstrapModelDisk)(nil)

// MODEL only: derive the exact strict COMPLETED wire shape from the existing
// verified fixture, reopen it through the production decoder, and bind the
// same private facade identities that Completion would hand to the runtime.
// This issues no real Completion cap and claims no native process evidence;
// the subsequent facade commits and beginNextRecovery publication are the
// production paths under test.
func labContinuousCompletedRecoveryModel(t *testing.T) (*lifecycleRecoveryStore, *labBootstrapModelDisk, *lifecycleRecoveryOwnerToken, *lifecycleStore, *lifecycleOwnerToken, time.Time) {
	t.Helper()
	_, _, _, _, verified := lifecycleVerifiedBoundsModel(t)
	completed := lifecycleV3Copy(t, verified)
	committedAt := completed.core.LastTrustedAt.Add(10 * time.Nanosecond)
	checkpoint, err := lifecycleRecoveryCheckpoint(verified.core, lifecycleRecoveryCheckpointVerified)
	if err != nil {
		t.Fatal("MODEL verified checkpoint", err)
	}
	b := completed.core.Recovery
	completedSchema, ok := lifecycleRecoveryVerifiedToCompletedSchema(b.Execution.Schema)
	if !ok {
		t.Fatal("MODEL verified execution schema")
	}
	b.Execution.Schema = completedSchema
	b.Execution.CompletionSource = &lifecycleRecoveryCompletionSource{Schema: lifecycleRecoveryCompletionSourceSchema, Root: checkpoint, CommitDeadline: committedAt.Add(time.Second)}
	previous := completed.core.Current.Head
	observation := b.Execution.Verification.Observation
	id := observation.StartupIdentity
	head := previous
	head.Generation++
	head.Artifact = cloneArtifactDescriptor(b.Plan.TargetArtifact)
	head.KernelSHA256, head.PID, head.StartTicks, head.NetNSInode = id.ELFSHA256, id.PID, id.StartTicks, id.NetNSInode
	head.ControllerPort, head.MixedPort = id.ControllerPort, id.MixedPort
	prior := previous.HeadSHA256
	head.PreviousHeadSHA256 = &prior
	head.VerificationSHA256, head.VerifiedAt = observation.VerificationSHA256, observation.ObservedAt
	head.HeadSHA256, err = lifecycleHeadHash(head)
	if err != nil {
		t.Fatal("MODEL recovered head", err)
	}
	completed.core.Revision++
	completed.core.LastTrustedAt = committedAt
	b.Phase = "COMPLETED"
	b.Completion = &lifecycleRecoveryCompletion{PreviousHead: previous, Head: head, EvidenceSHA256: observation.VerificationSHA256, CommitRevision: completed.core.Revision, CommittedAt: committedAt}
	b.UpdatedAt = committedAt
	retiredSHA, err := lifecycleHash(completed.core.Current)
	if err != nil {
		t.Fatal("MODEL retired ledger", err)
	}
	completed.core.RetiredEpochs = append(completed.core.RetiredEpochs, lifecycleRetiredEpoch{Ledger: completed.core.Current, RetiredAt: committedAt, CommitRevision: completed.core.Revision, RecoveryID: b.Plan.RecoveryID, LedgerSHA256: retiredSHA})
	completed.core.RecoveryHistory = append(completed.core.RecoveryHistory, *b)
	currentOwner, err := lifecycleRecoveryNewCurrentOwner(committedAt)
	if err != nil {
		t.Fatal("MODEL current owner", err)
	}
	recoveryID := b.Plan.RecoveryID
	completed.core.Current = lifecycleEpochLedger{Anchor: lifecycleEpochAnchor{Kind: "RECOVERED_EPOCH", InitialHead: head, RecoveryID: &recoveryID, SourceControlSHA256: completed.core.SourceV2.ControlSHA256},
		Head: head, Owner: &currentOwner, LastFence: currentOwner.Fence, Tombstones: []lifecycleTombstone{}, Completed: []lifecycleCompletion{}, Terminated: []lifecycleTerminalArchive{}, Observations: []lifecycleObservationRecord{}}
	lifecycleVerifiedBoundsResealRecord(t, &completed)
	raw, err := encodeLifecycleV3Record(completed)
	if err != nil {
		t.Fatal("MODEL completed strict record", err)
	}
	disk := &labBootstrapModelDisk{lifecycleModelDisk: &lifecycleModelDisk{raw: bytes.Clone(raw), exists: true, state: lifecycleCommitted}, binding: completed.core.Provisioning}
	recovery, err := openLifecycleRecoveryStore(disk, committedAt)
	if err != nil {
		t.Fatal("MODEL completed strict reopen", err)
	}
	recoveryOwnerCore := &lifecycleRecoveryOwnerCore{store: recovery.core, nonce: recovery.core.record.core.RecoveryOwner.OwnerNonce, fence: recovery.core.record.core.RecoveryOwner.Fence}
	recovery.core.live = recoveryOwnerCore
	recoveryOwner := &lifecycleRecoveryOwnerToken{core: recoveryOwnerCore}
	anchorSHA, err := lifecycleHash(recovery.core.record.core.Current.Anchor)
	if err != nil {
		t.Fatal("MODEL current anchor", err)
	}
	h := &lifecycleRecoveryCurrentHandoffCore{store: recovery.core, disk: disk, canonical: string(raw), epochIndex: uint64(len(recovery.core.record.core.RetiredEpochs)),
		anchorSHA256: anchorSHA, headSHA256: recovery.core.record.core.Current.Head.HeadSHA256, owner: currentOwner}
	store, boundDisk, canonical, epoch, anchor, headSHA, ownerValue := recovery.core, lifecycleDisk(disk), h.canonical, h.epochIndex, h.anchorSHA256, h.headSHA256, h.owner
	h.binding = func(candidate *lifecycleRecoveryCurrentHandoffCore) bool {
		return candidate == h && candidate.store == store && lifecycleRecoverySameDisk(candidate.disk, boundDisk) && candidate.canonical == canonical && candidate.epochIndex == epoch &&
			candidate.anchorSHA256 == anchor && candidate.headSHA256 == headSHA && reflect.DeepEqual(candidate.owner, ownerValue)
	}
	current, currentOwnerToken, err := adoptLifecycleCurrentEpoch(&lifecycleRecoveryCurrentHandoff{core: h}, recovery)
	if err != nil {
		t.Fatal("MODEL actual current facade adoption", err)
	}
	return recovery, disk, recoveryOwner, current, currentOwnerToken, committedAt
}

func labContinuousOrdinaryPlanModel(t *testing.T, current *lifecycleStore, operationID string, candidateSpec, backupSpec LabConfigSpec, sourceSHA string, sourceBytes int, now time.Time) (Plan, *PreparedReload) {
	t.Helper()
	head := current.record.wire.Head
	target := TargetBinding{DeviceRef: head.DeviceRef, Scope: head.Scope, Generation: head.Generation, HeadSHA256: head.HeadSHA256,
		KernelSHA256: head.KernelSHA256, PID: head.PID, StartTicks: head.StartTicks, NetNSInode: head.NetNSInode, ControllerPort: head.ControllerPort, MixedPort: head.MixedPort}
	candidate := labConfigTestBuild(t, candidateSpec)
	artifact, err := newArtifactDescriptor(candidate.Descriptor(), sourceSHA, sourceBytes, candidateSpec.ControllerPort, candidateSpec.MixedPort)
	if err != nil {
		t.Fatal("MODEL ordinary candidate", err)
	}
	backup, err := newBackupDescriptor(operationID, cloneArtifactDescriptor(head.Artifact), target)
	if err != nil {
		t.Fatal("MODEL ordinary backup", err)
	}
	plan, err := NewPlan(PlanSpec{OperationID: operationID, DeclaredInitiatorRef: "MODEL_continuous_initiator", Target: target, Artifact: artifact, Backup: backup, ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal("MODEL ordinary plan", err)
	}
	prepared := &PreparedReload{preparedReloadCore: &preparedReloadCore{descriptor: ReloadPreparationDescriptor{Schema: ReloadPreparationSchema, Boundary: ReloadPreparationBoundary, Plan: plan.Descriptor(), PreparedAt: now},
		candidate: candidate.Bytes(), backup: labConfigTestBuild(t, backupSpec).Bytes()}}
	return plan, prepared
}

func labContinuousSecondRecoveryBeginModel(t *testing.T) labContinuousSecondRecoveryModel {
	t.Helper()
	recovery, disk, recoveryOwner, current, currentOwner, completedAt := labContinuousCompletedRecoveryModel(t)
	now := completedAt.Add(time.Nanosecond)
	oldSpec := labConfigTestSpec()
	newSpec := labConfigTestSpec()
	newSpec.DefaultTarget = "REJECT"
	ack, ackPrepared := labContinuousOrdinaryPlanModel(t, current, "continuous-ack", oldSpec, newSpec, strings.Repeat("3", 64), 512, now)
	if current.recordPlan(currentOwner, ack, now) != nil || current.recordApproval(currentOwner, planTestApproval(ack, now), now) != nil ||
		current.recordPrepared(currentOwner, ackPrepared, now) != nil || current.recordIntent(currentOwner, ack.binding.Target.HeadSHA256, now) != nil ||
		current.recordResult(currentOwner, current.record.wire.Active.Intent.IntentSHA256, mihomo.ReloadResult{State: mihomo.ReloadAcknowledged, Dispatched: true, StatusCode: 204}, now) != nil {
		t.Fatal("MODEL facade ACK path")
	}
	ackCompleted := labV2ModelCompleted(t, current, now)
	if current.commitTransition(ackCompleted, now, lifecycleAppendCompletion) != nil {
		t.Fatal("MODEL facade ACK publication")
	}
	now = now.Add(time.Nanosecond)
	unknown, unknownPrepared := labContinuousOrdinaryPlanModel(t, current, "continuous-unknown", newSpec, oldSpec, strings.Repeat("4", 64), 513, now)
	if current.recordPlan(currentOwner, unknown, now) != nil || current.recordApproval(currentOwner, planTestApproval(unknown, now), now) != nil ||
		current.recordPrepared(currentOwner, unknownPrepared, now) != nil || current.recordIntent(currentOwner, unknown.binding.Target.HeadSHA256, now) != nil ||
		current.recordResult(currentOwner, current.record.wire.Active.Intent.IntentSHA256, mihomo.ReloadResult{State: mihomo.ReloadUnknown, Dispatched: true}, now) != nil {
		t.Fatal("MODEL facade UNKNOWN path")
	}
	source, err := recovery.core.copyRecord()
	if err != nil {
		t.Fatal("MODEL second recovery source", err)
	}
	plan, err := labRecoveryPlanForCurrentEpoch(source, "labrec_99999999999999999999999999999999", "MODEL_second_recovery", unknown.Descriptor().Artifact, now, source.core.RecoveryOwner.ExpiresAt)
	if err != nil {
		t.Fatal("MODEL second recovery plan", err)
	}
	return labContinuousSecondRecoveryModel{runtime: &labLifecycleRuntime{core: &labLifecycleRuntimeCore{disk: disk, recovery: recovery, current: current}}, current: current,
		recovery: recovery, recoveryOwner: recoveryOwner, plan: plan, revision: source.core.Revision, recordSHA256: source.core.RecordSHA256, disk: disk,
		history: lifecycleCloneSlice(source.core.RecoveryHistory, func(v lifecycleRecoveryTxn) lifecycleRecoveryTxn { return (&lifecycleCloneState{}).recovery(v) }), now: now}
}

func TestLabContinuousRecoveryFaultZeroAndDebugRemainNonAuthorityMODEL(t *testing.T) {
	var zero LabContinuousRecoveryFaultHandle
	raw, err := json.Marshal(zero)
	if err != nil || string(raw) != `{"scope":"PRIVATE_CONTINUOUS_RECOVERY_FAULT_NOT_AUTHORIZATION"}` {
		t.Fatal("MODEL zero debug JSON changed")
	}
	formatted := fmt.Sprintf("%v|%+v|%#v", zero, zero, zero)
	if strings.Contains(formatted, "127.0.0.1") || strings.Contains(formatted, "28412") || strings.Contains(formatted, "nonce") {
		t.Fatal("MODEL debug formatting leaked private state")
	}
	if _, err := BeginLabContinuousRecoveryResponseLoss(nil); err == nil {
		t.Fatal("MODEL nil service issued schedule")
	}
	if _, err := zero.Observe(); err == nil || zero.Close() == nil {
		t.Fatal("MODEL zero handle became usable")
	}
	if json.Unmarshal([]byte(`{"scope":"PRIVATE_CONTINUOUS_RECOVERY_FAULT_NOT_AUTHORIZATION"}`), &zero) == nil {
		t.Fatal("MODEL JSON reconstructed schedule")
	}
	t.Run("create-stage-is-exact-bounded-diagnostic-only", func(t *testing.T) {
		service := &labServiceCore{}
		foreign := &labServiceCore{}
		core := &labContinuousRecoveryFaultCore{service: service, recoveryCreatesBounded: true}
		core.identity = core
		diagnostic := &processLabContinuousRecoveryCreateDiagnostic
		diagnostic.mu.Lock()
		previous := diagnostic.core
		diagnostic.core = core
		diagnostic.mu.Unlock()
		t.Cleanup(func() {
			diagnostic.mu.Lock()
			diagnostic.core = previous
			diagnostic.mu.Unlock()
		})
		labContinuousRecoveryRecoveryCreateStage(foreign, "ENTERED")
		labContinuousRecoveryRecoveryCreateStage(service, "ENTERED")
		labContinuousRecoveryRecoveryCreateStage(service, "ACCEPTED")
		diagnostic.mu.Lock()
		got := append([]LabContinuousRecoveryCreateStage(nil), core.recoveryCreates...)
		bounded := core.recoveryCreatesBounded
		diagnostic.mu.Unlock()
		if !bounded || len(got) != 2 || got[0].Sequence != 1 || got[0].Stage != "ENTERED" ||
			got[1].Sequence != 2 || got[1].Stage != "ACCEPTED" {
			t.Fatal("MODEL create-stage diagnostic lost exact source binding")
		}
		labContinuousRecoveryRecoveryCreateStage(service, "dynamic-error-text")
		diagnostic.mu.Lock()
		bounded = core.recoveryCreatesBounded
		diagnostic.mu.Unlock()
		if bounded {
			t.Fatal("MODEL dynamic create-stage diagnostic was accepted")
		}
	})
	t.Run("completed-archive-allows-one-fresh-second-recovery-begin", func(t *testing.T) {
		m := labContinuousSecondRecoveryBeginModel(t)
		writes := m.disk.writes
		if err := m.runtime.beginNextRecovery(m.current, m.recovery, m.recoveryOwner, &m.plan, m.revision, m.recordSHA256, m.now); err != nil {
			t.Fatal("MODEL actual second begin rejected", err)
		}
		if m.disk.writes != writes+1 || !m.current.closed || m.runtime.core.current != nil || m.recovery.core.record.core.Recovery == nil ||
			m.recovery.core.record.core.Recovery.Phase != "PLANNED" || m.recovery.core.record.core.Recovery.Execution != nil ||
			!reflect.DeepEqual(m.history, m.recovery.core.record.core.RecoveryHistory) {
			t.Fatal("MODEL second begin changed archive, retained facade, or injected execution")
		}
	})
	t.Run("second-begin-publication-failure-retains-completed-facade", func(t *testing.T) {
		m := labContinuousSecondRecoveryBeginModel(t)
		writes := m.disk.writes
		m.disk.state = lifecycleNotCommitted
		m.disk.writeErr = fmt.Errorf("MODEL bounded publication failure")
		if err := m.runtime.beginNextRecovery(m.current, m.recovery, m.recoveryOwner, &m.plan, m.revision, m.recordSHA256, m.now); err == nil ||
			m.disk.writes != writes+1 || m.current.closed || m.runtime.core.current != m.current || m.recovery.core.record.core.Recovery == nil ||
			m.recovery.core.record.core.Recovery.Phase != "COMPLETED" || !reflect.DeepEqual(m.history, m.recovery.core.record.core.RecoveryHistory) {
			t.Fatal("MODEL failed publication retired facade or changed completed archive")
		}
	})
	t.Run("second-begin-rejects-changed-archive-before-publication", func(t *testing.T) {
		m := labContinuousSecondRecoveryBeginModel(t)
		writes := m.disk.writes
		m.recovery.core.record.core.RecoveryHistory[len(m.recovery.core.record.core.RecoveryHistory)-1].UpdatedAt = m.now.Add(time.Nanosecond)
		if err := m.runtime.beginNextRecovery(m.current, m.recovery, m.recoveryOwner, &m.plan, m.revision, m.recordSHA256, m.now); err == nil ||
			m.disk.writes != writes || m.current.closed || m.runtime.core.current != m.current {
			t.Fatal("MODEL changed completed archive reached publication or retired facade")
		}
	})
	t.Run("terminal-replacement-rejects-execution-injection-and-unpaired-history", func(t *testing.T) {
		m := labContinuousSecondRecoveryBeginModel(t)
		before := m.recovery.core.record.core
		candidate := lifecycleV3Copy(t, m.recovery.core.record)
		archivedExecution := candidate.core.Recovery.Execution
		candidate.core.Recovery = &lifecycleRecoveryTxn{Plan: m.plan.descriptor(), Phase: "PLANNED", FailedQuiescence: []labQuiescenceObservation{}, UpdatedAt: m.now, Execution: archivedExecution}
		if lifecycleV3Transition(before, candidate.core) {
			t.Fatal("MODEL fresh plan injected archived execution")
		}
		candidate.core.Recovery.Execution = nil
		candidate.core.RecoveryHistory[len(candidate.core.RecoveryHistory)-1].UpdatedAt = m.now.Add(time.Nanosecond)
		if lifecycleV3Transition(before, candidate.core) {
			t.Fatal("MODEL fresh plan replaced a terminal slot without exact archive pairing")
		}
	})
}
