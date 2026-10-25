//go:build linux && chengwang_mihomo_service && chengwang_mihomo_faults && chengwang_mihomo_recovery_native && chengwang_mihomo_completion_native

package mihomodeploy

// This acceptance-only test extends the existing real native recovery chain by
// exactly one first Completion transition. It does not expose an API, rebind
// LabService, publish an ordinary mutation, or attempt a second recovery.
import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authz"
)

const labNativeCompletionScope = "ACTUAL_FIRST_RECOVERY_COMPLETION_NOT_API_REBIND_ORDINARY_PUBLISH_SECOND_RECOVERY_OR_PRODUCTION"

var labNativeCompletionMode = flag.String("chengwang-native-completion-mode", "positive", "fixed isolated Completion publication variant")

func labNativeCompletionModeValid(mode string) bool {
	return mode == "positive" || mode == "not-committed" || mode == "unknown" || mode == "readback"
}

// The wrapper is installed transparently before S2 so the genuine verified
// custody binds its disk identity. It is armed only after S2 and after the real
// completion capability has been issued. Counters therefore describe only the
// Completion publication, never the preceding S2 publication.
type labNativeCompletionDisk struct {
	labRuntimeDisk
	mu                                                              sync.Mutex
	mode                                                            string
	armed                                                           bool
	replaceAttempts, forwardedWrites, postWriteReads, injectedReads int
	underlyingCommitted                                             bool
}

func (d *labNativeCompletionDisk) replaceControl(raw []byte) (lifecycleCommitState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.armed {
		return d.labRuntimeDisk.replaceControl(raw)
	}
	d.replaceAttempts++
	if d.replaceAttempts != 1 {
		return lifecycleNotCommitted, errLabNativeRecovery
	}
	if d.mode == "not-committed" {
		return lifecycleNotCommitted, errLabNativeRecovery
	}
	d.forwardedWrites++
	state, err := d.labRuntimeDisk.replaceControl(raw)
	d.underlyingCommitted = state == lifecycleCommitted && err == nil
	if !d.underlyingCommitted {
		return state, err
	}
	if d.mode == "unknown" {
		return lifecycleUnknown, errLabNativeRecovery
	}
	return state, err
}

func (d *labNativeCompletionDisk) readControl() ([]byte, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	raw, exists, err := d.labRuntimeDisk.readControl()
	if d.armed && d.underlyingCommitted {
		d.postWriteReads++
		if d.mode == "readback" && d.injectedReads == 0 && err == nil && exists {
			d.injectedReads++
			return append(bytes.Clone(raw), ' '), exists, nil
		}
	}
	return raw, exists, err
}

type labNativeCompletionPublication struct {
	Schema                   string    `json:"schema"`
	Scope                    string    `json:"scope"`
	Mode                     string    `json:"mode"`
	AttemptedAt              time.Time `json:"attemptedAt"`
	ReturnedAt               time.Time `json:"returnedAt"`
	ReplaceAttempts          int       `json:"replaceAttempts"`
	ForwardedWrites          int       `json:"forwardedWrites"`
	PostWriteReads           int       `json:"postWriteReads"`
	InjectedReads            int       `json:"injectedReads"`
	UnderlyingCommitted      bool      `json:"underlyingCommitted"`
	RecordReturnedError      bool      `json:"recordReturnedError"`
	CapReplayRejected        bool      `json:"capReplayRejected"`
	CapSpent                 bool      `json:"capSpent"`
	StorePoisoned            bool      `json:"storePoisoned"`
	HandoffReturned          bool      `json:"handoffReturned"`
	RuntimeAdopted           bool      `json:"runtimeAdopted"`
	CloseExclusionHeld       bool      `json:"closeExclusionHeld"`
	HandoffReplayRejected    bool      `json:"handoffReplayRejected"`
	SourceRevision           uint64    `json:"sourceRevision"`
	SourceRecordSHA256       string    `json:"sourceRecordSHA256"`
	SourceControlSHA256      string    `json:"sourceControlSHA256"`
	MemoryRevision           uint64    `json:"memoryRevision"`
	MemoryRecordSHA256       string    `json:"memoryRecordSHA256"`
	MemoryControlSHA256      string    `json:"memoryControlSHA256"`
	DiskRevision             uint64    `json:"diskRevision"`
	DiskRecordSHA256         string    `json:"diskRecordSHA256"`
	DiskControlSHA256        string    `json:"diskControlSHA256"`
	DiskPhase                string    `json:"diskPhase"`
	S1PreimageSHA256         string    `json:"s1PreimageSHA256"`
	S2PreimageSHA256         *string   `json:"s2PreimageSHA256"`
	PreviousHeadSHA256       string    `json:"previousHeadSHA256"`
	NewHeadSHA256            *string   `json:"newHeadSHA256"`
	RetiredEpochCount        int       `json:"retiredEpochCount"`
	RecoveryHistoryCount     int       `json:"recoveryHistoryCount"`
	NoCompletionNativeCalls  bool      `json:"noCompletionNativeCalls"`
	NativePrefixCount        int       `json:"nativePrefixCount"`
	NativePrefixSHA256       string    `json:"nativePrefixSHA256"`
	ColdReopenMatchedDisk    bool      `json:"coldReopenMatchedDisk"`
	ReopenTransition         string    `json:"reopenTransition"`
	ServiceRebindProven      bool      `json:"serviceRebindProven"`
	APIRouteProven           bool      `json:"apiRouteProven"`
	OrdinaryPublishProven    bool      `json:"ordinaryPublishProven"`
	SecondRecoveryProven     bool      `json:"secondRecoveryProven"`
	Production               bool      `json:"production"`
}

type labNativeCompletionReport struct {
	Schema          string                         `json:"schema"`
	Scope           string                         `json:"scope"`
	Mode            string                         `json:"mode"`
	SourceCommit    string                         `json:"sourceCommit"`
	Outcome         string                         `json:"outcome"`
	FailureCode     string                         `json:"failureCode"`
	OldIdentity     *labKernelIdentity             `json:"oldIdentity"`
	NewIdentity     *labKernelIdentity             `json:"newIdentity"`
	OldCore         uint64                         `json:"oldCore"`
	NewCore         uint64                         `json:"newCore"`
	S1              *labNativeRecoveryCheckpoint   `json:"s1"`
	S2              *labNativeRecoveryCheckpoint   `json:"s2"`
	Reopened        *labNativeRecoveryCheckpoint   `json:"reopened"`
	ControlPlane    *labRecoveryObservedValue       `json:"controlPlane"`
	Completion      *labNativeCompletionPublication `json:"completion"`
	NativeCalls     []labNativeRecoveryCall        `json:"nativeCalls"`
	CountersBounded bool                           `json:"countersBounded"`
	ClosedPorts     []uint16                       `json:"closedPorts"`
	CleanupProbes   []labQuiescenceProbe           `json:"cleanupProbes"`
	FixtureCleanup  []labLocalFixtureCleanup       `json:"fixtureCleanup"`
	OldCleanup      *labKernelExit                  `json:"oldCleanup"`
	NewCleanup      *labKernelExit                  `json:"newCleanup"`
	RuntimeClosed   bool                           `json:"runtimeClosed"`
	DiskOwnerClosed bool                           `json:"diskOwnerClosed"`
}

func labNativeCompletionWrite(name string, raw []byte) error {
	allowed := name == "completion-report.private.json" || name == "completion-s1.private.json" ||
		name == "completion-s2.private.json" || name == "completion-attempted.private.json" ||
		name == "completion-reopened.private.json"
	if !allowed || len(raw) > maxLifecycleControlBytes || !labKernelPlain(labNativeRecoveryPrivate) {
		return errLabNativeRecovery
	}
	var st syscall.Stat_t
	if syscall.Lstat(labNativeRecoveryPrivate, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		st.Mode&07777 != 0700 || st.Uid != 10001 || st.Gid != 10001 {
		return errLabNativeRecovery
	}
	f, err := os.OpenFile(labNativeRecoveryPrivate+"/"+name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errLabNativeRecovery
	}
	_, writeErr := f.Write(raw)
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errLabNativeRecovery
	}
	d, err := os.Open(labNativeRecoveryPrivate)
	if err != nil {
		return errLabNativeRecovery
	}
	syncErr, closeErr = d.Sync(), d.Close()
	if syncErr != nil || closeErr != nil {
		return errLabNativeRecovery
	}
	return nil
}

func labNativeCompletionSnapshot(raw []byte, name string) (lifecycleV3Record, labNativeRecoveryCheckpoint, error) {
	var zero lifecycleV3Record
	w, err := decodeLifecycleV3Record(raw)
	if err != nil || w.core == nil || w.core.Recovery == nil {
		return zero, labNativeRecoveryCheckpoint{}, errLabNativeRecovery
	}
	if err := labNativeCompletionWrite(name, raw); err != nil {
		return zero, labNativeRecoveryCheckpoint{}, err
	}
	return w, labNativeRecoveryCheckpoint{Stage: name, ControlSHA256: labConfigHash(raw), RecordSHA256: w.core.RecordSHA256,
		Revision: w.core.Revision, Phase: w.core.Recovery.Phase}, nil
}

func labNativeCompletionReopen(expected []byte, mode string) (labNativeRecoveryCheckpoint, []byte, error) {
	var zero labNativeRecoveryCheckpoint
	before, err := decodeLifecycleV3Record(expected)
	if err != nil || before.core == nil || before.core.Recovery == nil || !labNativeCompletionModeValid(mode) {
		return zero, nil, errLabNativeRecovery
	}
	d, fresh, err := openLabRuntimeDisk()
	if err != nil || d == nil || fresh {
		if d != nil {
			_ = d.close()
		}
		return zero, nil, errLabNativeRecovery
	}
	s, err := openLifecycleRecoveryStore(d, time.Now().UTC())
	if err != nil {
		_ = d.close()
		return zero, nil, err
	}
	x := s.core
	raw, exists, err := x.disk.readControl()
	if err != nil || !exists || !bytes.Equal(raw, x.raw) || x.verify() != nil {
		_ = s.close()
		return zero, nil, errLabNativeRecovery
	}
	w, err := decodeLifecycleV3Record(raw)
	if err != nil || w.core.Recovery == nil || x.live != nil || x.currentLive != nil || x.permit != nil ||
		x.startedRecord != nil || x.verificationRecord != nil || x.completionRecord != nil ||
		x.retainedStarted != nil || x.retainedVerified != nil || x.currentPublication != nil ||
		x.activeBase != nil || x.activePrepared != nil {
		_ = s.close()
		return zero, nil, errLabNativeRecovery
	}
	if mode == "not-committed" {
		if bytes.Equal(raw, expected) || before.core.Recovery.Phase != "START_ARMED" || before.core.Recovery.Failure != nil ||
			w.core.Revision != before.core.Revision+1 || w.core.RecordSHA256 == before.core.RecordSHA256 ||
			w.core.Recovery.Phase != "RECOVERY_UNKNOWN" || w.core.Recovery.Failure == nil ||
			w.core.Recovery.Failure.Code != "PROCESS_REOPENED" || !lifecycleTime(w.core.Recovery.Failure.At) ||
			!w.core.LastTrustedAt.Equal(w.core.Recovery.Failure.At) || !w.core.Recovery.UpdatedAt.Equal(w.core.Recovery.Failure.At) {
			_ = s.close()
			return zero, nil, errLabNativeRecovery
		}
		projected, projectErr := decodeLifecycleV3Record(expected)
		if projectErr != nil {
			_ = s.close()
			return zero, nil, errLabNativeRecovery
		}
		projected.core.Revision = w.core.Revision
		projected.core.RecordSHA256 = w.core.RecordSHA256
		projected.core.LastTrustedAt = w.core.LastTrustedAt
		projected.core.Recovery.Phase = w.core.Recovery.Phase
		failure := *w.core.Recovery.Failure
		projected.core.Recovery.Failure = &failure
		projected.core.Recovery.UpdatedAt = w.core.Recovery.UpdatedAt
		if !reflect.DeepEqual(projected.core, w.core) {
			_ = s.close()
			return zero, nil, errLabNativeRecovery
		}
	} else if !bytes.Equal(raw, expected) || w.core.Recovery.Phase != "COMPLETED" {
		_ = s.close()
		return zero, nil, errLabNativeRecovery
	}
	if err := labNativeCompletionWrite("completion-reopened.private.json", raw); err != nil {
		_ = s.close()
		return zero, nil, err
	}
	if err := s.close(); err != nil || !x.closed {
		return zero, nil, errLabNativeRecovery
	}
	return labNativeRecoveryCheckpoint{Stage: "completion-reopened", ControlSHA256: labConfigHash(raw), RecordSHA256: w.core.RecordSHA256,
		Revision: w.core.Revision, Phase: w.core.Recovery.Phase}, bytes.Clone(raw), nil
}

func TestLabRecoveryCompletionNativeFirstTransitionAndOwnedCleanup(t *testing.T) {
	mode := *labNativeCompletionMode
	if !labNativeCompletionModeValid(mode) {
		t.Fatal("unknown native Completion variant")
	}
	report := labNativeCompletionReport{Schema: "chengwang.mihomo-native-completion-experiment/v1", Scope: labNativeCompletionScope,
		Mode: mode, SourceCommit: os.Getenv("CHENGWANG_MIHOMO_APPLY_SOURCE_COMMIT"), Outcome: "FAIL", FailureCode: "NOT_COMPLETED",
		NativeCalls: []labNativeRecoveryCall{}, ClosedPorts: []uint16{}, CleanupProbes: []labQuiescenceProbe{}, FixtureCleanup: []labLocalFixtureCleanup{}}
	var service *LabService
	var runner *labNativeRecoveryRunner
	var managerClosed bool
	var manager interface{ Close() error }
	var cancel context.CancelFunc
	defer func() {
		if service != nil && !service.core.closed {
			ctx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
			if runner != nil {
				if err := runner.cleanup(ctx); err != nil {
					t.Error("actual retained Completion resources were not settled")
				}
			} else if err := service.Close(ctx); err != nil {
				t.Error("actual retained service was not settled")
			}
			cleanupCancel()
		}
		if cancel != nil {
			cancel()
		}
		if manager != nil && !managerClosed {
			if err := manager.Close(); err != nil {
				t.Error("actual identity manager close was not observed")
			}
		}
		if runner != nil {
			report.NewCleanup = runner.newExit
		}
		if service != nil {
			service.core.mu.Lock()
			report.FixtureCleanup = append([]labLocalFixtureCleanup{}, service.core.fixtureCloseObservations...)
			service.core.mu.Unlock()
			report.OldCleanup = service.core.kernelCloseObservation
			report.RuntimeClosed = service.core.runtime != nil && service.core.runtime.core.closed
			if service.core.runtime != nil && service.core.runtime.core.recovery != nil {
				report.DiskOwnerClosed = service.core.runtime.core.recovery.core.closed
			}
		}
		report.NativeCalls, report.CountersBounded = labNativeRecoveryReadCalls()
		if t.Failed() {
			report.Outcome = "FAIL"
			if report.FailureCode == "NONE" {
				report.FailureCode = "FINALIZATION_REJECTED"
			}
		}
		raw, err := json.Marshal(report)
		if err != nil || labNativeCompletionWrite("completion-report.private.json", raw) != nil {
			t.Error("actual private Completion report was not durably retained")
		}
	}()
	if labServiceEnvelope() != nil || len(report.SourceCommit) != 40 {
		report.FailureCode = "ENVELOPE"
		t.Fatal("source-owned isolated Linux envelope required")
	}
	events, bounded := labNativeRecoveryReadCalls()
	if !bounded || len(events) != 0 {
		report.FailureCode = "FRESH_PROCESS"
		t.Fatal("Completion experiment requires a fresh process")
	}
	identityManager, headers, err := labNativeRecoveryIdentities()
	if err != nil {
		report.FailureCode = "IDENTITIES"
		t.Fatal("real private current identities unavailable")
	}
	manager = identityManager
	scope := authz.ResourceScope{TenantID: "native-tenant", SiteID: "native-site", ObjectType: LabObjectType,
		ObjectID: "native-device", Environment: LabEnvironment}
	lifetime, lifetimeCancel := context.WithCancel(context.Background())
	cancel = lifetimeCancel
	service, err = OpenIsolatedLabService(lifetime, identityManager, scope)
	if err != nil || service == nil || !service.DiagnosticReady() {
		report.FailureCode = "BOOTSTRAP"
		t.Fatal("real owned fixed kernel service unavailable")
	}
	planned, err := service.Create(lifetime, headers["initiator"], LabCreateRequest{service.core.candidate.RecordSHA256, 120})
	if err != nil || planned.Phase != "PLANNED" {
		report.FailureCode = "ORIGINAL_PLAN"
		t.Fatal("actual original plan failed")
	}
	approved, err := service.Approve(lifetime, headers["approver"], planned.OperationID, LabApprovalRequest{planned.PlanSHA256, planned.Revision})
	if err != nil || approved.Phase != "APPROVED" {
		report.FailureCode = "ORIGINAL_APPROVAL"
		t.Fatal("actual original independent approval failed")
	}
	fault, err := mihomo.BeginLabReloadResponseLoss()
	if err != nil {
		report.FailureCode = "RESPONSE_LOSS"
		t.Fatal("actual response loss capsule unavailable")
	}
	unknown, err := service.Execute(lifetime, headers["initiator"], planned.OperationID, LabExecuteRequest{approved.PlanSHA256, approved.Revision})
	if err != nil || unknown.Phase != "UNKNOWN" || !unknown.WriteBlocked || unknown.HeadAdvanced {
		report.FailureCode = "ACTUAL_UNKNOWN"
		t.Fatal("actual unknown outcome was not retained")
	}
	observation, err := fault.Observe()
	if err != nil || observation.State != "INJECTED" || !observation.Claimed || observation.UnderlyingRoundTrips != 1 || !observation.Injected {
		report.FailureCode = "RESPONSE_LOSS_OBSERVATION"
		t.Fatal("actual response loss was not independently observed")
	}
	runner, err = newLabNativeRecoveryRunner(service)
	if err != nil || runner == nil {
		report.FailureCode = "NATIVE_OWNERSHIP"
		t.Fatal("actual source-owned recovery runner unavailable")
	}
	report.OldIdentity = &runner.oldIdentity
	report.OldCore, bounded = labNativeRecoveryReadCore(runner.old)
	if !bounded {
		t.Fatal("old actual core did not emit native observations")
	}
	if err := runner.run(headers["initiator"], headers["approver"], headers["initiator"]); err != nil {
		report.FailureCode = labNativeRecoveryFailureCode(err)
		t.Fatal("actual native recovery-to-Started chain rejected")
	}
	report.NewIdentity = &runner.newIdentity
	report.NewCore, bounded = labNativeRecoveryReadCore(runner.next)
	if !bounded || report.NewCore == report.OldCore {
		t.Fatal("new actual process core was not independently observed")
	}
	if err := runner.awaitNewKernelWait(); err != nil {
		t.Fatal("actual new kernel did not enter its sole pending Wait")
	}
	runner.store.core.mu.Lock()
	s1Raw := bytes.Clone(runner.store.core.raw)
	nativeCustody := runner.store.core.retainedStarted
	runner.store.core.mu.Unlock()
	s1, s1Point, err := labNativeCompletionSnapshot(s1Raw, "completion-s1.private.json")
	if err != nil || nativeCustody == nil || s1.core.Recovery.Execution == nil || s1.core.Recovery.Execution.Schema != lifecycleRecoveryExecutionSchema {
		report.FailureCode = "S1"
		t.Fatal("actual S1 image or retained custody unavailable")
	}
	report.S1 = &s1Point
	service.core.mu.Lock()
	service.core.runtime.core.mu.Lock()
	runner.store.core.mu.Lock()
	actualDisk := service.core.runtime.core.disk
	if actualDisk == nil || !lifecycleRecoverySameDisk(actualDisk, runner.store.core.disk) {
		runner.store.core.mu.Unlock()
		service.core.runtime.core.mu.Unlock()
		service.core.mu.Unlock()
		t.Fatal("actual disk custody differs before S2")
	}
	completionDisk := &labNativeCompletionDisk{labRuntimeDisk: actualDisk, mode: mode}
	service.core.runtime.core.disk = completionDisk
	runner.store.core.disk = completionDisk
	runner.store.core.mu.Unlock()
	service.core.runtime.core.mu.Unlock()
	service.core.mu.Unlock()
	collector, err := newLabRecoveryCollector(service, runner.authority, runner.session, runner.next)
	if err != nil {
		report.FailureCode = "S2_COLLECTOR"
		t.Fatal("actual recovery collector could not bind retained objects")
	}
	controlCtx, controlCancel := context.WithTimeout(service.core.ctx, 12*time.Second)
	defer controlCancel()
	observed, err := collector.collect(controlCtx, headers["initiator"])
	if err != nil || observed == nil || observed.core == nil {
		report.FailureCode = "S2_CAPTURE"
		t.Fatal("actual eight-GET and local marker observation failed")
	}
	controlValue, recordCap, err := collector.consumeForRecord(controlCtx, headers["initiator"], observed)
	if err != nil || recordCap == nil || recordCap.core == nil || controlValue.Readback.RequestsObserved != 8 || controlValue.LocalPath == nil {
		report.FailureCode = "S2_CONSUME"
		t.Fatal("actual S2 observation did not issue its record capability")
	}
	report.ControlPlane = &controlValue
	if err := runner.store.recordRecoveryVerification(runner.owner, recordCap, time.Now().UTC()); err != nil {
		report.FailureCode = "S2_RECORD"
		t.Fatal("actual S2 publication did not succeed before Completion faulting")
	}
	runner.store.core.mu.Lock()
	s2Raw := bytes.Clone(runner.store.core.raw)
	verifiedCustody := runner.store.core.retainedVerified
	s2Poisoned := runner.store.core.poisoned
	runner.store.core.mu.Unlock()
	s2, s2Point, err := labNativeCompletionSnapshot(s2Raw, "completion-s2.private.json")
	if err != nil || s2Poisoned || verifiedCustody == nil || s2.core.Recovery.Execution == nil ||
		s2.core.Recovery.Execution.Schema != lifecycleRecoveryVerifiedExecutionSchema || s2.core.Recovery.Execution.Verification == nil ||
		s2.core.Recovery.Execution.CompletionSource != nil || s2.core.Recovery.Completion != nil {
		report.FailureCode = "S2_NOT_VERIFIED"
		t.Fatal("actual S2 success was not independently retained before Completion")
	}
	s1Preimage, err := lifecycleRecoveryVerificationPreimage(s2.core, *s2.core.Recovery)
	if err != nil || !bytes.Equal(s1Preimage, s1Raw) {
		report.FailureCode = "S1_PREIMAGE"
		t.Fatal("actual S2 did not bind the exact S1 preimage")
	}
	report.S2 = &s2Point
	service.core.mu.Lock()
	closeExclusionHeld := runner.holdsClose && service.core.busy && !service.core.closed && !service.core.closing
	service.core.mu.Unlock()
	if !closeExclusionHeld {
		report.FailureCode = "COMPLETION_CLOSE_EXCLUSION"
		t.Fatal("actual Completion caller did not retain the service close/busy exclusion")
	}
	beforeCompletionCalls, bounded := labNativeRecoveryReadCalls()
	if !bounded {
		t.Fatal("native call prefix unavailable before Completion")
	}
	beforeCompletionRaw, err := json.Marshal(beforeCompletionCalls)
	if err != nil || len(beforeCompletionCalls) == 0 {
		t.Fatal("native call prefix encoding unavailable before Completion")
	}
	completionCtx, completionCancel := context.WithTimeout(service.core.ctx, 5*time.Second)
	defer completionCancel()
	cap, err := collector.completionCap(completionCtx, headers["initiator"])
	if err != nil || cap == nil || cap.core == nil {
		report.FailureCode = "COMPLETION_CAP"
		t.Fatal("actual current S2 custody did not issue Completion capability")
	}
	completionDisk.mu.Lock()
	completionDisk.armed = true
	completionDisk.mu.Unlock()
	attemptedAt := time.Now().UTC()
	handoff, recordErr := runner.store.recordRecoveryCompletion(runner.owner, cap, attemptedAt)
	returnedAt := time.Now().UTC()
	if (mode == "positive") != (recordErr == nil) {
		report.FailureCode = "COMPLETION_RESULT"
		t.Fatal("Completion variant did not observe its fixed publication result")
	}
	processLabRecoveryCompletionIssuer.mu.Lock()
	capSpent := !processLabRecoveryCompletionIssuer.issued[cap.core]
	processLabRecoveryCompletionIssuer.mu.Unlock()
	if !capSpent {
		t.Fatal("actual Completion capability was not irreversibly spent")
	}
	if replay, replayErr := runner.store.recordRecoveryCompletion(runner.owner, cap, time.Now().UTC()); replayErr == nil || replay != nil {
		t.Fatal("spent actual Completion capability replayed")
	}
	completionDisk.mu.Lock()
	replaceAttempts, forwardedWrites := completionDisk.replaceAttempts, completionDisk.forwardedWrites
	postWriteReads, injectedReads := completionDisk.postWriteReads, completionDisk.injectedReads
	underlyingCommitted := completionDisk.underlyingCommitted
	completionDisk.mu.Unlock()
	if replaceAttempts != 1 || (mode == "not-committed" && (forwardedWrites != 0 || underlyingCommitted || postWriteReads != 0)) ||
		(mode != "not-committed" && (forwardedWrites != 1 || !underlyingCommitted)) ||
		(mode == "unknown" && postWriteReads != 0) || (mode == "readback" && (postWriteReads != 1 || injectedReads != 1)) ||
		(mode == "positive" && (postWriteReads != 1 || injectedReads != 0)) {
		report.FailureCode = "COMPLETION_FAULT_POINT"
		t.Fatal("fixed Completion replace/readback injection point was not reached exactly")
	}
	runner.store.core.mu.Lock()
	memoryRaw := bytes.Clone(runner.store.core.raw)
	memoryRecord := runner.store.core.record
	storePoisoned := runner.store.core.poisoned
	runner.store.core.mu.Unlock()
	diskRaw, exists, err := actualDisk.readControl()
	if err != nil || !exists {
		t.Fatal("actual post-Completion disk bytes unavailable")
	}
	diskRecord, diskPoint, err := labNativeCompletionSnapshot(diskRaw, "completion-attempted.private.json")
	if err != nil {
		t.Fatal("actual post-Completion disk record rejected strict decode")
	}
	memoryDecoded, err := decodeLifecycleV3Record(memoryRaw)
	if err != nil || memoryRecord.core == nil || !reflect.DeepEqual(memoryDecoded.core, memoryRecord.core) {
		t.Fatal("post-Completion memory image is not its strict typed record")
	}
	publication := &labNativeCompletionPublication{Schema: "chengwang.mihomo-native-completion-publication/v1", Scope: labNativeCompletionScope, Mode: mode,
		AttemptedAt: attemptedAt, ReturnedAt: returnedAt, ReplaceAttempts: replaceAttempts, ForwardedWrites: forwardedWrites,
		PostWriteReads: postWriteReads, InjectedReads: injectedReads, UnderlyingCommitted: underlyingCommitted, RecordReturnedError: recordErr != nil,
		CapReplayRejected: true, CapSpent: capSpent, StorePoisoned: storePoisoned, HandoffReturned: handoff != nil,
		CloseExclusionHeld: closeExclusionHeld,
		SourceRevision: s2.core.Revision, SourceRecordSHA256: s2.core.RecordSHA256, SourceControlSHA256: labConfigHash(s2Raw),
		MemoryRevision: memoryDecoded.core.Revision, MemoryRecordSHA256: memoryDecoded.core.RecordSHA256, MemoryControlSHA256: labConfigHash(memoryRaw),
		DiskRevision: diskRecord.core.Revision, DiskRecordSHA256: diskRecord.core.RecordSHA256, DiskControlSHA256: diskPoint.ControlSHA256,
		DiskPhase: diskRecord.core.Recovery.Phase, S1PreimageSHA256: labConfigHash(s1Preimage), PreviousHeadSHA256: s2.core.Current.Head.HeadSHA256}
	if mode == "not-committed" {
		if handoff != nil || !storePoisoned || !bytes.Equal(memoryRaw, s2Raw) || !bytes.Equal(diskRaw, s2Raw) {
			t.Fatal("definite precommit Completion failure changed or adopted its candidate")
		}
	} else if mode != "positive" {
		if handoff != nil || !storePoisoned || !bytes.Equal(memoryRaw, s2Raw) || bytes.Equal(diskRaw, s2Raw) || diskRecord.core.Recovery.Phase != "COMPLETED" {
			t.Fatal("uncertain Completion result adopted memory or failed to persist its actual candidate")
		}
	} else {
		if handoff == nil || storePoisoned || !bytes.Equal(memoryRaw, diskRaw) || diskRecord.core.Recovery.Phase != "COMPLETED" {
			t.Fatal("successful Completion did not adopt its exact disk candidate")
		}
	}
	if mode != "not-committed" {
		preimage, preimageErr := lifecycleRecoveryCompletionPreimage(diskRecord.core, *diskRecord.core.Recovery)
		if preimageErr != nil || !bytes.Equal(preimage, s2Raw) || diskRecord.core.Recovery.Completion == nil ||
			len(diskRecord.core.RetiredEpochs) != 1 || len(diskRecord.core.RecoveryHistory) != 1 ||
			!reflect.DeepEqual(diskRecord.core.RecoveryHistory[0], *diskRecord.core.Recovery) {
			t.Fatal("completed disk image did not bind S2, retired epoch and history")
		}
		digest := labConfigHash(preimage)
		newHead := diskRecord.core.Current.Head.HeadSHA256
		publication.S2PreimageSHA256 = &digest
		publication.NewHeadSHA256 = &newHead
		publication.RetiredEpochCount = len(diskRecord.core.RetiredEpochs)
		publication.RecoveryHistoryCount = len(diskRecord.core.RecoveryHistory)
		if diskRecord.core.Recovery.Completion.PreviousHead.HeadSHA256 != publication.PreviousHeadSHA256 ||
			diskRecord.core.Recovery.Completion.Head.HeadSHA256 != newHead || newHead == publication.PreviousHeadSHA256 ||
			diskRecord.core.Current.Head.Generation != s2.core.Current.Head.Generation+1 {
			t.Fatal("Completion did not create the exact next head generation")
		}
	}
	if mode == "positive" {
		facade, ordinaryOwner, adoptErr := service.core.runtime.adoptCurrentEpoch(handoff, runner.store)
		if adoptErr != nil || facade == nil || ordinaryOwner == nil || service.core.runtime.core.current != facade || facade.currentEpoch == nil {
			t.Fatal("successful Completion handoff was not adopted by the actual runtime")
		}
		publication.RuntimeAdopted = true
		if replayOwner, replayErr := handoff.consumeCurrent(runner.store.core); replayErr == nil || replayOwner != nil {
			t.Fatal("consumed current-epoch handoff replayed")
		}
		publication.HandoffReplayRejected = true
	} else {
		if service.core.runtime.core.current != nil {
			t.Fatal("failed Completion installed an ordinary runtime facade")
		}
	}
	afterCompletionCalls, bounded := labNativeRecoveryReadCalls()
	if !bounded || !reflect.DeepEqual(beforeCompletionCalls, afterCompletionCalls) {
		t.Fatal("Completion metadata transition dispatched a physical kernel operation")
	}
	afterCompletionRaw, err := json.Marshal(afterCompletionCalls)
	if err != nil || !bytes.Equal(beforeCompletionRaw, afterCompletionRaw) {
		t.Fatal("Completion native-call prefix did not remain byte-identical")
	}
	publication.NoCompletionNativeCalls = true
	publication.NativePrefixCount = len(afterCompletionCalls)
	publication.NativePrefixSHA256 = labConfigHash(afterCompletionRaw)
	report.Completion = publication
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
	err = runner.cleanup(cleanupCtx)
	cleanupCancel()
	if err != nil || !service.core.closed || !service.core.runtime.core.closed || !runner.store.core.closed {
		report.FailureCode = "OWNED_CLEANUP"
		t.Fatal("actual Completion resources were not closed by their retained owner")
	}
	for _, port := range []uint16{28411, 28412, 28413, 28414, 28415} {
		probeCtx, probeCancel := context.WithTimeout(context.Background(), time.Second)
		probe := labNativeRecoveryCleanupDial(probeCtx, port)
		probeCancel()
		report.CleanupProbes = append(report.CleanupProbes, probe)
		if !probe.Attempted || probe.Result != "CONNECTION_REFUSED" {
			report.FailureCode = "CLEANUP_PROBE"
			t.Fatal("actual owned endpoint remained or closure was inconclusive")
		}
		report.ClosedPorts = append(report.ClosedPorts, port)
	}
	reopened, reopenedRaw, err := labNativeCompletionReopen(diskRaw, mode)
	if err != nil {
		report.FailureCode = "COLD_REOPEN"
		t.Fatal("strict cold reopen did not preserve or safely normalize actual post-Completion disk bytes")
	}
	report.Reopened = &reopened
	if mode == "not-committed" {
		if bytes.Equal(reopenedRaw, diskRaw) || reopened.Revision != diskPoint.Revision+1 || reopened.Phase != "RECOVERY_UNKNOWN" {
			report.FailureCode = "COLD_REOPEN_NORMALIZATION"
			t.Fatal("strict cold reopen did not perform the sole START_ARMED normalization")
		}
		publication.ReopenTransition = "START_ARMED_TO_RECOVERY_UNKNOWN"
	} else {
		if !bytes.Equal(reopenedRaw, diskRaw) || reopened.ControlSHA256 != diskPoint.ControlSHA256 ||
			reopened.RecordSHA256 != diskPoint.RecordSHA256 || reopened.Revision != diskPoint.Revision || reopened.Phase != diskPoint.Phase {
			report.FailureCode = "COLD_REOPEN_CHANGED_COMPLETED"
			t.Fatal("strict cold reopen changed a completed disk image")
		}
		publication.ReopenTransition = "COMPLETED_UNCHANGED"
	}
	publication.ColdReopenMatchedDisk = true
	if err := identityManager.Close(); err != nil {
		t.Fatal("actual identity manager did not close")
	}
	managerClosed = true
	report.Outcome, report.FailureCode = "PASS", "NONE"
}
