//go:build linux && chengwang_mihomo_service && chengwang_mihomo_faults && chengwang_mihomo_recovery_native

package mihomodeploy

// Real pinned-kernel/native-disk acceptance. This file never calls a MODEL
// helper, seeds a WAL, writes an issuer registry or mints a private cap.
// It has no skip path. Only the isolated Linux worker may satisfy its envelope.
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
	"chengwang/internal/authn"
	"chengwang/internal/authz"
)

var labNativeVerificationMode = flag.String("chengwang-native-verification-mode", "positive", "fixed isolated verification publication variant")

func labNativeVerificationModeValid(mode string) bool {
	return mode == "positive" || mode == "not-committed" || mode == "unknown" || mode == "readback"
}

// This test-only forwarding owner retains the actual namespace-owned disk.
// It is installed before cap admission and never swaps that disk afterward.
// The only injected behaviors are three fixed publication outcomes.
type labNativeVerificationDisk struct {
	labRuntimeDisk
	mu sync.Mutex
	mode string
	armed bool
	replaceAttempts, forwardedWrites, postWriteReads, injectedReads int
	underlyingCommitted bool
}

func (d *labNativeVerificationDisk) replaceControl(raw []byte) (lifecycleCommitState, error) {
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

func (d *labNativeVerificationDisk) readControl() ([]byte, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	raw, exists, err := d.labRuntimeDisk.readControl()
	if d.armed && d.underlyingCommitted {
		d.postWriteReads++
		if d.mode == "readback" && d.injectedReads == 0 && err == nil && exists {
			d.injectedReads++
			// Corrupt only the publisher's actual post-write return, not the
			// disk file. Cold reopen must independently find the real bytes.
			return append(bytes.Clone(raw), ' '), exists, nil
		}
	}
	return raw, exists, err
}

type labNativeVerificationRecord struct {
	Schema string `json:"schema"`
	Scope string `json:"scope"`
	Mode string `json:"mode"`
	AttemptedAt time.Time `json:"attemptedAt"`
	ReturnedAt time.Time `json:"returnedAt"`
	ReplaceAttempts int `json:"replaceAttempts"`
	ForwardedWrites int `json:"forwardedWrites"`
	PostWriteReads int `json:"postWriteReads"`
	InjectedReads int `json:"injectedReads"`
	UnderlyingCommitted bool `json:"underlyingCommitted"`
	CapKnownBefore bool `json:"capKnownBefore"`
	CapSpent bool `json:"capSpent"`
	CapCopyRejected bool `json:"capCopyRejected"`
	CapReplayRejected bool `json:"capReplayRejected"`
	RecordReturnedError bool `json:"recordReturnedError"`
	StorePoisoned bool `json:"storePoisoned"`
	CandidateAdopted bool `json:"candidateAdopted"`
	LiveOwnerCleared bool `json:"liveOwnerCleared"`
	TransientProofCleared bool `json:"transientProofCleared"`
	RetainedStartedCleared bool `json:"retainedStartedCleared"`
	SourceRevision uint64 `json:"sourceRevision"`
	SourceRecordSHA256 string `json:"sourceRecordSHA256"`
	SourceControlSHA256 string `json:"sourceControlSHA256"`
	MemoryRevision uint64 `json:"memoryRevision"`
	MemoryRecordSHA256 string `json:"memoryRecordSHA256"`
	DiskRevision uint64 `json:"diskRevision"`
	DiskRecordSHA256 string `json:"diskRecordSHA256"`
	DiskControlSHA256 string `json:"diskControlSHA256"`
	ExecutionSchema string `json:"executionSchema"`
	ReceiptPresent bool `json:"receiptPresent"`
	ReceiptSHA256 *string `json:"receiptSHA256"`
	ObservationSHA256 *string `json:"observationSHA256"`
	VerificationCommitRevision *uint64 `json:"verificationCommitRevision"`
	RecordedAt *time.Time `json:"recordedAt"`
	S1PreimageSHA256 *string `json:"s1PreimageSHA256"`
	SourceCurrentSHA256 string `json:"sourceCurrentSHA256"`
	DiskCurrentSHA256 string `json:"diskCurrentSHA256"`
	CompletionAbsent bool `json:"completionAbsent"`
	NoNewPhysicalCalls bool `json:"noNewPhysicalCalls"`
	FullPrivateReceiptIndependentlyProven bool `json:"fullPrivateReceiptIndependentlyProven"`
}

// Forensic read of the same underlying owned disk after a publication
// failure. This does not clear poison, adopt bytes or mint live authority.
func labNativeVerificationCheckpoint(r *labNativeRecoveryRunner, disk labRuntimeDisk) (lifecycleV3Record, error) {
	if r == nil || disk == nil || disk.verify() != nil {
		return lifecycleV3Record{}, errLabNativeRecovery
	}
	raw, exists, err := disk.readControl()
	if err != nil || !exists || disk.verify() != nil {
		return lifecycleV3Record{}, errLabNativeRecovery
	}
	w, err := decodeLifecycleV3Record(raw)
	original, originalErr := decodeLifecycleRecord(r.legacy)
	if err != nil || originalErr != nil || w.core.Recovery == nil || w.core.Recovery.Execution == nil || w.core.Recovery.Completion != nil ||
		!bytes.Equal(w.core.SourceV2.ControlBytes, r.legacy) || !reflect.DeepEqual(w.core.Current, lifecycleLegacyLedger(original, r.legacy)) || len(w.core.RetiredEpochs) != 0 {
		return lifecycleV3Record{}, errLabNativeRecovery
	}
	if err := labNativeRecoveryWrite("verification-attempted-control.private.json", raw); err != nil {
		return lifecycleV3Record{}, err
	}
	r.stages = append(r.stages, labNativeRecoveryCheckpoint{"verification-attempted", labConfigHash(raw), w.core.RecordSHA256, w.core.Revision, w.core.Recovery.Phase})
	return w, nil
}

func labNativeVerificationReopen(legacy []byte, execution lifecycleRecoveryExecution) (labNativeRecoveryCheckpoint, error) {
	var zero labNativeRecoveryCheckpoint
	d, fresh, err := openLabRuntimeDisk()
	if err != nil || d == nil || fresh {
		if d != nil {
			_ = d.close()
		}
		return zero, errLabNativeRecovery
	}
	s, err := openLifecycleRecoveryStore(d, time.Now().UTC())
	if err != nil {
		_ = d.close()
		return zero, err
	}
	defer s.close()
	x := s.core
	raw, exists, err := x.disk.readControl()
	if err != nil || !exists || !bytes.Equal(raw, x.raw) || x.verify() != nil {
		return zero, errLabNativeRecovery
	}
	w, err := decodeLifecycleV3Record(raw)
	if err != nil || w.core.Recovery == nil || w.core.Recovery.Phase != "RECOVERY_UNKNOWN" || w.core.Recovery.Completion != nil ||
		w.core.Recovery.Execution == nil || !reflect.DeepEqual(*w.core.Recovery.Execution, execution) ||
		!bytes.Equal(w.core.SourceV2.ControlBytes, legacy) || x.live != nil || x.permit != nil || x.quiescenceSHA != "" ||
		x.retainedStarted != nil || x.verificationRecord != nil {
		return zero, errLabNativeRecovery
	}
	processLabRecoveryVerificationIssuer.mu.Lock()
	for core := range processLabRecoveryVerificationIssuer.issued {
		if core.store == x {
			processLabRecoveryVerificationIssuer.mu.Unlock()
			return zero, errLabNativeRecovery
		}
	}
	processLabRecoveryVerificationIssuer.mu.Unlock()
	if _, err := s.armRecoveryStart(nil, time.Now().UTC()); err == nil {
		return zero, errLabNativeRecovery
	}
	if err := s.recordRecoveryVerification(nil, nil, time.Now().UTC()); err == nil {
		return zero, errLabNativeRecovery
	}
	if err := labNativeRecoveryWrite("reopened-control.private.json", raw); err != nil {
		return zero, err
	}
	if err := s.close(); err != nil || !x.closed {
		return zero, errLabNativeRecovery
	}
	return labNativeRecoveryCheckpoint{"reopened", labConfigHash(raw), w.core.RecordSHA256, w.core.Revision, w.core.Recovery.Phase}, nil
}

type labNativeRecoveryReport struct {
	Schema                              string                             `json:"schema"`
	VerificationMode                    string                             `json:"verificationMode"`
	Scope                               string                             `json:"scope"`
	SourceCommit                        string                             `json:"sourceCommit"`
	Outcome                             string                             `json:"outcome"`
	FailureCode                         string                             `json:"failureCode"`
	OriginalUnknown                     *LabDeploymentView                 `json:"originalUnknown"`
	Fault                               *mihomo.LabReloadFaultObservation  `json:"fault"`
	ReloadBefore                        mihomo.ReloadCounters              `json:"reloadBefore"`
	ReloadUnknown                       mihomo.ReloadCounters              `json:"reloadUnknown"`
	ReloadFinal                         mihomo.ReloadCounters              `json:"reloadFinal"`
	OldIdentity                         *labKernelIdentity                 `json:"oldIdentity"`
	NewIdentity                         *labKernelIdentity                 `json:"newIdentity"`
	BootstrapStart                      *labKernelStartObservation         `json:"bootstrapStart"`
	OldCore                             uint64                             `json:"oldCore"`
	NewCore                             uint64                             `json:"newCore"`
	Quiescence                          *labQuiescenceObservation          `json:"quiescence"`
	Start                               *labRecoveryStartObservation       `json:"start"`
	StartedSHA256                       string                             `json:"startedSHA256"`
	Stages                              []labNativeRecoveryCheckpoint      `json:"stages"`
	ReplayRejected                      bool                               `json:"replayRejected"`
	RecoverySelfApprovalDenied          bool                               `json:"recoverySelfApprovalDenied"`
	Reopened                            *labNativeRecoveryCheckpoint       `json:"reopened"`
	OldCleanup                          *labKernelExit                     `json:"oldCleanup"`
	NewCleanup                          *labKernelExit                     `json:"newCleanup"`
	Syntax                              []labKernelStartObservation        `json:"syntax"`
	NativeCalls                         []labNativeRecoveryCall            `json:"nativeCalls"`
	EventCheckpoints                    []labNativeRecoveryEventCheckpoint `json:"eventCheckpoints"`
	DualOwnerCloseRejectedTwice         bool                               `json:"dualOwnerCloseRejectedTwice"`
	CountersBounded                     bool                               `json:"countersBounded"`
	ClosedPorts                         []uint16                           `json:"closedPorts"`
	FixtureCleanup                      []labLocalFixtureCleanup           `json:"fixtureCleanup"`
	CleanupProbes                       []labQuiescenceProbe               `json:"cleanupProbes"`
	RuntimeClosed                       bool                               `json:"runtimeClosed"`
	NewDiskOwnerClosed                  bool                               `json:"newDiskOwnerClosed"`
	CleanupReplayNoOp                   bool                               `json:"cleanupReplayNoOp"`
	ControlPlane                        *labRecoveryObservedValue          `json:"controlPlane"`
	ControlEvents                       []labNativeRecoveryEventCheckpoint `json:"controlEvents"`
	ControlBeforeSHA256                 string                             `json:"controlBeforeSHA256"`
	ControlAfterSHA256                  string                             `json:"controlAfterSHA256"`
	ControlProofReplayRejected          bool                               `json:"controlProofReplayRejected"`
	ControlRecollectRejected            bool                               `json:"controlRecollectRejected"`
	ControlCopiedStartedRejected        bool                               `json:"controlCopiedStartedRejected"`
	ControlCopiedProofRejected          bool                               `json:"controlCopiedProofRejected"`
	LocalCopiedFixtureRejected          bool                               `json:"localCopiedFixtureRejected"`
	VerificationRecord                  *labNativeVerificationRecord       `json:"verificationRecord"`
	VerificationEvents                  []labNativeRecoveryEventCheckpoint `json:"verificationEvents"`
	ReopenedExecutionPreserved          bool                               `json:"reopenedExecutionPreserved"`
	ReopenedRecordCapabilityAbsent      bool                               `json:"reopenedRecordCapabilityAbsent"`
	HTTPRecoveryProven                  bool                               `json:"httpRecoveryProven"`
	CompletionProven                    bool                               `json:"completionProven"`
	FullPrivateWALIndependentlyProven   bool                               `json:"fullPrivateWALIndependentlyProven"`
	SyntaxRawStreamsIndependentlyProven bool                               `json:"syntaxRawStreamsIndependentlyProven"`
	InternetBusinessProven              bool                               `json:"internetBusinessProven"`
	Production                          bool                               `json:"production"`
}

// Non-secret identity profiles are source generated; plaintext tokens remain
// private disclosure-fence inputs. No fixed credentials are embedded.
func labNativeRecoveryIdentities() (*authn.SnapshotManager, map[string][]string, error) {
	scope := authz.ResourceScope{TenantID: "native-tenant", SiteID: "native-site", ObjectType: LabObjectType,
		ObjectID: "native-device", Environment: LabEnvironment}
	profile := authn.File{Version: authn.FileVersion, Identities: []authn.Identity{}}
	headers := map[string][]string{}
	tokens := map[string]string{}
	for _, item := range []struct {
		name string
		role authz.Role
	}{{"initiator", authz.RoleAdmin}, {"approver", authz.RoleApprover}, {"viewer", authz.RoleViewer}} {
		token, digest, err := authn.GenerateToken(32)
		if err != nil {
			return nil, nil, err
		}
		headers[item.name] = []string{"Bearer " + token}
		tokens[item.name] = token
		profile.Identities = append(profile.Identities, authn.Identity{TokenID: "native-" + item.name, TokenHash: digest,
			Principal: authz.Principal{ID: "native-" + item.name, TenantID: scope.TenantID, Roles: []authz.Role{item.role}, AllowedScopes: []authz.ResourceScope{scope}}})
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(labServiceCredentialsPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, nil, err
	}
	_, writeErr := f.Write(raw)
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return nil, nil, errLabNativeRecovery
	}
	raw, err = json.Marshal(tokens)
	if err != nil || labNativeRecoveryWrite("tokens.private.json", raw) != nil {
		return nil, nil, errLabNativeRecovery
	}
	manager, err := authn.OpenSnapshotManager(labServiceCredentialsPath, time.Now().UTC())
	return manager, headers, err
}

func labNativeRecoveryCount(events []labNativeRecoveryCall, kind string, core uint64) int {
	count := 0
	for _, e := range events {
		if e.Kind == kind && e.Core == core {
			count++
		}
	}
	return count
}

func TestLabRecoveryNativeUnknownStartedReplayReopenAndOwnedCleanup(t *testing.T) {
	mode := *labNativeVerificationMode
	if !labNativeVerificationModeValid(mode) {
		t.Fatal("unknown native verification variant")
	}
	report := labNativeRecoveryReport{Schema: "chengwang.mihomo-native-recovery-experiment/v5", VerificationMode: mode,
		Scope: labNativeRecoveryScope, SourceCommit: os.Getenv("CHENGWANG_MIHOMO_APPLY_SOURCE_COMMIT"),
		Outcome: "FAIL", FailureCode: "NOT_COMPLETED", Stages: []labNativeRecoveryCheckpoint{}, Syntax: []labKernelStartObservation{},
		NativeCalls: []labNativeRecoveryCall{}, EventCheckpoints: []labNativeRecoveryEventCheckpoint{}, ClosedPorts: []uint16{},
		FixtureCleanup: []labLocalFixtureCleanup{}, CleanupProbes: []labQuiescenceProbe{}, ControlEvents: []labNativeRecoveryEventCheckpoint{}}
	var service *LabService
	var runner *labNativeRecoveryRunner
	var manager *authn.SnapshotManager
	var cancel context.CancelFunc
	defer func() {
		// Any retained service or runner is cleaned even when a real assertion
		// fails. A cleanup failure is a failure, never a report-only success.
		if service != nil && !service.core.closed {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			var err error
			if runner != nil {
				err = runner.cleanup(ctx)
			} else {
				err = service.Close(ctx)
			}
			cancel()
			if err != nil {
				t.Error("actual retained native resources were not settled")
			}
		}
		if cancel != nil {
			cancel()
		}
		if manager != nil && manager.Close() != nil {
			t.Error("actual identity manager close was not observed")
		}
		if runner != nil {
			report.Stages = append([]labNativeRecoveryCheckpoint{}, runner.stages...)
			report.NewCleanup = runner.newExit
			report.Quiescence = &runner.quiescence
			report.Start = &runner.start
			report.RecoverySelfApprovalDenied = runner.selfApprovalDenied
			report.EventCheckpoints = append([]labNativeRecoveryEventCheckpoint{}, runner.eventCheckpoints...)
		}
		if service != nil {
			service.core.mu.Lock()
			report.FixtureCleanup = append([]labLocalFixtureCleanup{}, service.core.fixtureCloseObservations...)
			service.core.mu.Unlock()
			report.OldCleanup = service.core.kernelCloseObservation
			report.RuntimeClosed = service.core.runtime != nil && service.core.runtime.core.closed
			if service.core.runtime != nil && service.core.runtime.core.recovery != nil {
				report.NewDiskOwnerClosed = service.core.runtime.core.recovery.core.closed
			}
			for _, o := range service.core.syntaxObservations {
				report.Syntax = append(report.Syntax, labRecoveryStartedCloneStart(o.core.observation))
			}
		}
		report.NativeCalls, report.CountersBounded = labNativeRecoveryReadCalls()
		report.ReloadFinal = mihomo.ObserveReloadCounters()
		if t.Failed() {
			if report.FailureCode == "NONE" {
				report.FailureCode = "FINALIZATION_REJECTED"
			}
			report.Outcome = "FAIL"
		}
		raw, err := json.Marshal(report)
		if err != nil || labNativeRecoveryWrite("native-report.private.json", raw) != nil {
			t.Error("actual private native report was not durably retained")
		}
	}()
	if labServiceEnvelope() != nil || len(report.SourceCommit) != 40 {
		report.FailureCode = "ENVELOPE"
		t.Fatal("source-owned isolated Linux envelope required")
	}
	events, bounded := labNativeRecoveryReadCalls()
	if !bounded || len(events) != 0 {
		report.FailureCode = "FRESH_PROCESS"
		t.Fatal("native experiment requires a fresh process")
	}
	manager, headers, err := labNativeRecoveryIdentities()
	if err != nil {
		report.FailureCode = "IDENTITIES"
		t.Fatal("real private current identities unavailable")
	}
	scope := authz.ResourceScope{TenantID: "native-tenant", SiteID: "native-site", ObjectType: LabObjectType,
		ObjectID: "native-device", Environment: LabEnvironment}
	lifetime, cancel := context.WithCancel(context.Background())
	service, err = OpenIsolatedLabService(lifetime, manager, scope)
	if err != nil || service == nil || !service.DiagnosticReady() {
		report.FailureCode = "BOOTSTRAP"
		t.Fatal("real owned fixed kernel service unavailable")
	}
	bootstrapStart := service.core.kernel.startObservation()
	if !bootstrapStart.Attempted || bootstrapStart.Started == nil || !*bootstrapStart.Started || bootstrapStart.WaitReturned == nil || *bootstrapStart.WaitReturned {
		t.Fatal("actual bootstrap Start observation unavailable")
	}
	report.BootstrapStart = &bootstrapStart
	report.ReloadBefore = mihomo.ObserveReloadCounters()
	if report.ReloadBefore.ReloadInvocations != 0 || report.ReloadBefore.DoInvocations != 0 {
		t.Fatal("fresh service already dispatched")
	}
	planned, err := service.Create(lifetime, headers["initiator"], LabCreateRequest{service.core.candidate.RecordSHA256, 120})
	if err != nil || planned.Phase != "PLANNED" {
		report.FailureCode = "ORIGINAL_PLAN"
		t.Fatal("actual original plan failed")
	}
	if _, err := service.Approve(lifetime, headers["initiator"], planned.OperationID, LabApprovalRequest{planned.PlanSHA256, planned.Revision}); err == nil {
		t.Fatal("actual original self approval accepted")
	}
	approved, err := service.Approve(lifetime, headers["approver"], planned.OperationID, LabApprovalRequest{planned.PlanSHA256, planned.Revision})
	if err != nil || approved.Phase != "APPROVED" {
		report.FailureCode = "ORIGINAL_APPROVAL"
		t.Fatal("actual original independent approval failed")
	}
	fault, err := mihomo.BeginLabReloadResponseLoss()
	if err != nil {
		t.Fatal("actual response loss capsule unavailable")
	}
	unknown, err := service.Execute(lifetime, headers["initiator"], planned.OperationID, LabExecuteRequest{approved.PlanSHA256, approved.Revision})
	if err != nil || unknown.Phase != "UNKNOWN" || !unknown.WriteBlocked || unknown.HeadAdvanced || unknown.Transport == nil ||
		unknown.Transport.Origin != "ADAPTER" || unknown.Transport.Result.State != mihomo.ReloadUnknown || !unknown.Transport.Result.Dispatched {
		report.FailureCode = "ACTUAL_UNKNOWN"
		t.Fatal("actual unknown outcome was not retained")
	}
	report.OriginalUnknown = &unknown
	observation, err := fault.Observe()
	if err != nil || observation.State != "INJECTED" || !observation.Claimed || observation.UnderlyingRoundTrips != 1 ||
		observation.StatusCode == nil || *observation.StatusCode != 204 || observation.EOFObserved == nil || !*observation.EOFObserved ||
		observation.CloseSucceeded == nil || !*observation.CloseSucceeded || !observation.Injected {
		t.Fatal("original controller response loss not independently observed")
	}
	report.Fault = &observation
	report.ReloadUnknown = mihomo.ObserveReloadCounters()
	if report.ReloadUnknown.ReloadInvocations != 1 || report.ReloadUnknown.DoInvocations != 1 {
		t.Fatal("original unknown did not use exactly one reload and Do")
	}
	runner, err = newLabNativeRecoveryRunner(service)
	if err != nil || runner == nil {
		report.FailureCode = "NATIVE_OWNERSHIP"
		t.Fatal("actual source-owned recovery runner unavailable")
	}
	report.OldIdentity = &runner.oldIdentity
	report.OldCore, bounded = labNativeRecoveryReadCore(runner.old)
	if !bounded {
		t.Fatal("old original core did not emit native observations")
	}
	// Real authorization negative controls precede the one actual run. They
	// cannot mint a plan/permit and never call native dispatch.
	if _, err := runner.authority.captureInitiator(headers["viewer"], time.Now().UTC()); err == nil {
		t.Fatal("current viewer acquired recovery prepare authority")
	}
	legacyOwner := service.core.runtime.core.store
	legacyDisk := service.core.runtime.core.disk
	beforeFailedTransfer := bytes.Clone(legacyOwner.raw)
	if _, err := service.core.runtime.evolveForRecovery(nil, time.Now().UTC()); err == nil ||
		service.core.runtime.core.store != legacyOwner || service.core.runtime.core.recovery != nil ||
		legacyOwner.disk != legacyDisk || legacyOwner.closed || !bytes.Equal(legacyOwner.raw, beforeFailedTransfer) {
		t.Fatal("failed actual transfer lost or replaced its original close owner")
	}
	if err := runner.run(headers["initiator"], headers["approver"], headers["initiator"]); err != nil {
		report.FailureCode = labNativeRecoveryFailureCode(err)
		t.Fatal("actual native recovery-to-Started chain rejected")
	}
	approvedRaw, err := os.ReadFile(labNativeRecoveryPrivate + "/approved-control.private.json")
	if err != nil {
		t.Fatal("actual approval transition bytes unavailable")
	}
	approvedRecord, err := decodeLifecycleV3Record(approvedRaw)
	if err != nil || approvedRecord.core.Recovery == nil || approvedRecord.core.Recovery.Phase != "APPROVED" ||
		approvedRecord.core.Recovery.Approval == nil ||
		!approvedRecord.core.Recovery.Approval.IssuedAt.Equal(approvedRecord.core.Recovery.UpdatedAt) ||
		!approvedRecord.core.LastTrustedAt.Equal(approvedRecord.core.Recovery.UpdatedAt) {
		t.Fatal("actual approval issuance and record did not retain one logical transition time")
	}
	report.NewIdentity = &runner.newIdentity
	report.NewCore, bounded = labNativeRecoveryReadCore(runner.next)
	if !bounded || report.NewCore == report.OldCore || runner.newIdentity.PID == runner.oldIdentity.PID && runner.newIdentity.StartTicks == runner.oldIdentity.StartTicks {
		t.Fatal("new actual process tuple was not independently observed")
	}
	w, err := decodeLifecycleV3Record(runner.store.core.raw)
	if err != nil || w.core.Recovery == nil || w.core.Recovery.Execution == nil || w.core.Recovery.Phase != "START_ARMED" ||
		w.core.Recovery.Completion != nil || !bytes.Equal(w.core.SourceV2.ControlBytes, runner.legacy) ||
		!reflect.DeepEqual(w.core.Recovery.Execution.Started.Observation, runner.start) || w.core.Recovery.Execution.StartedCommitRevision != w.core.Revision ||
		w.core.Recovery.Execution.Started.Observation.StartObservation == nil || !w.core.Recovery.Execution.Started.Observation.StartObservation.Attempted {
		t.Fatal("actual Started publication/readback relation failed")
	}
	execution := *w.core.Recovery.Execution
	report.StartedSHA256 = execution.Started.StartedSHA256
	runner.store.core.mu.Lock()
	nativeCustody := runner.store.core.retainedStarted
	runner.store.core.mu.Unlock()
	if nativeCustody == nil {
		t.Fatal("actual successful Started publication retained no observation custody")
	}
	if err := runner.awaitNewKernelWait(); err != nil {
		t.Fatal("actual new kernel did not enter its sole pending Wait")
	}
	beforeReplay, bounded := labNativeRecoveryReadCalls()
	if !bounded || labNativeRecoveryCount(beforeReplay, "RECOVERY_STOP_DISPATCH", report.OldCore) != 1 ||
		labNativeRecoveryCount(beforeReplay, "RECOVERY_START_DISPATCH", 0) != 1 ||
		labNativeRecoveryCount(beforeReplay, "KERNEL_OS_START_ATTEMPT", report.OldCore) != 1 ||
		labNativeRecoveryCount(beforeReplay, "KERNEL_OS_START_ATTEMPT", report.NewCore) != 1 ||
		labNativeRecoveryCount(beforeReplay, "KERNEL_OS_WAIT_RETURN", report.OldCore) != 1 ||
		labNativeRecoveryCount(beforeReplay, "KERNEL_OS_WAIT_RETURN", report.NewCore) != 0 ||
		labNativeRecoveryCount(beforeReplay, "KERNEL_OS_TERM_ATTEMPT", report.OldCore) != 1 ||
		labNativeRecoveryCount(beforeReplay, "SYNTAX_OS_START_ATTEMPT", 0) != 1 {
		t.Fatal("source dispatch and OS-attempt originals disagree")
	}
	if err := runner.rejectReplay(); err != nil {
		report.FailureCode = "REPLAY"
		t.Fatal("spent original permit or Started capability replayed")
	}
	if _, err := service.core.runtime.evolveForRecovery(nil, time.Now().UTC()); err == nil ||
		service.core.runtime.core.store != nil || service.core.runtime.core.recovery != runner.store {
		t.Fatal("actual runtime adopted another writer after sole-owner transfer")
	}
	beforeRunnerReplay, checkpointErr := runner.captureEvents("before-runner-replay")
	if checkpointErr != nil {
		t.Fatal("actual runner replay baseline unavailable")
	}
	if err := runner.run(headers["initiator"], headers["approver"], headers["initiator"]); err == nil {
		t.Fatal("same runner dispatched another recovery")
	}
	afterRunnerReplay, checkpointErr := runner.captureEvents("after-runner-replay")
	if checkpointErr != nil || !reflect.DeepEqual(beforeRunnerReplay, afterRunnerReplay) {
		t.Fatal("runner replay changed actual native event prefix")
	}
	afterReplay, bounded := labNativeRecoveryReadCalls()
	if !bounded || !reflect.DeepEqual(beforeReplay, afterReplay) {
		t.Fatal("replay added a real native call")
	}
	report.ReplayRejected = true
	// S2 observes the actual post-S1 new core. Original spent-cap/runner replay
	// above must not clear or reissue its original retained source custody.
	runner.store.core.mu.Lock()
	controlBefore := bytes.Clone(runner.store.core.raw)
	retainedAfterReplay := runner.store.core.retainedStarted
	runner.store.core.mu.Unlock()
	if retainedAfterReplay != nativeCustody {
		t.Fatal("failed original replay replaced actual post-S1 custody")
	}
	// Copying metadata cannot recreate the native registry identity. This is
	// the original native core's shallow copy, never an issued capability.
	copiedStartedCore := *runner.started.core
	copiedStarted := &labRecoveryStartedEpoch{core: &copiedStartedCore}
	if err := runner.store.recordRecoveryStarted(runner.owner, copiedStarted, time.Now().UTC()); err == nil {
		t.Fatal("copied actual Started core bypassed the spent issuer")
	}
	runner.store.core.mu.Lock()
	copyRejectedWithoutMutation := runner.store.core.retainedStarted == nativeCustody && bytes.Equal(controlBefore, runner.store.core.raw)
	runner.store.core.mu.Unlock()
	if !copyRejectedWithoutMutation {
		t.Fatal("copied Started rejection changed retained custody or actual WAL")
	}
	report.ControlCopiedStartedRejected = true
	controlCallsBefore, bounded := labNativeRecoveryReadCalls()
	if !bounded || len(controlCallsBefore) == 0 {
		t.Fatal("actual S2 native-event baseline unavailable")
	}
	controlRawBefore, err := json.Marshal(controlCallsBefore)
	if err != nil {
		t.Fatal("actual S2 native-event baseline encoding unavailable")
	}
	report.ControlEvents = append(report.ControlEvents, labNativeRecoveryEventCheckpoint{
		Stage: "before-control-plane", Count: len(controlCallsBefore), LastSequence: controlCallsBefore[len(controlCallsBefore)-1].Sequence, EventsSHA256: labConfigHash(controlRawBefore)})
	report.ControlBeforeSHA256 = labConfigHash(controlBefore)
	// Install a forwarding wrapper around the actual still-owned disk before
	// admission. The record cap binds this identity, not a later replacement.
	service.core.mu.Lock()
	service.core.runtime.core.mu.Lock()
	runner.store.core.mu.Lock()
	actualDisk := service.core.runtime.core.disk
	if actualDisk == nil || !lifecycleRecoverySameDisk(actualDisk, runner.store.core.disk) {
		runner.store.core.mu.Unlock()
		service.core.runtime.core.mu.Unlock()
		service.core.mu.Unlock()
		t.Fatal("actual disk custody differs before record-cap admission")
	}
	publicationDisk := &labNativeVerificationDisk{labRuntimeDisk: actualDisk, mode: mode}
	service.core.runtime.core.disk = publicationDisk
	runner.store.core.disk = publicationDisk
	runner.store.core.mu.Unlock()
	service.core.runtime.core.mu.Unlock()
	service.core.mu.Unlock()
	// Copy the actually issued fixture seal, not an invented fixture or a
	// synthetic issuer entry. Restore its exact source pointer before using
	// the genuine service; no network call or registry mutation is made here.
	service.core.mu.Lock()
	fixtureSeal := service.core.fixtureCustody
	if fixtureSeal == nil {
		service.core.mu.Unlock()
		t.Fatal("successful service lost its retained actual fixture seal")
	}
	copiedFixtureSeal := *fixtureSeal
	service.core.fixtureCustody = &copiedFixtureSeal
	service.core.mu.Unlock()
	copiedFixtureCollector, copyFixtureErr := newLabRecoveryCollector(service, runner.authority, runner.session, runner.next)
	service.core.mu.Lock()
	service.core.fixtureCustody = fixtureSeal
	service.core.mu.Unlock()
	if copyFixtureErr == nil || copiedFixtureCollector != nil {
		t.Fatal("copied actual fixture seal became source ownership")
	}
	report.LocalCopiedFixtureRejected = true
	collector, err := newLabRecoveryCollector(service, runner.authority, runner.session, runner.next)
	if err != nil {
		report.FailureCode = "CONTROL_COLLECTOR"
		t.Fatal("actual recovery collector could not bind retained objects")
	}
	controlCtx, controlCancel := context.WithTimeout(service.core.ctx, 10*time.Second)
	defer controlCancel()
	observed, err := collector.collect(controlCtx, headers["initiator"])
	if err != nil || observed == nil || observed.core == nil {
		report.FailureCode = "CONTROL_CAPTURE"
		t.Fatal("actual post-S1 eight-GET and owned local marker observation failed")
	}
	copiedObservedCore := *observed.core
	if _, err := collector.consume(controlCtx, headers["initiator"], &labRecoveryObservedEvidence{core: &copiedObservedCore}); err == nil {
		t.Fatal("copied observation core became a source-issued proof")
	}
	report.ControlCopiedProofRejected = true
	controlValue, recordCap, err := collector.consumeForRecord(controlCtx, headers["initiator"], observed)
	if err != nil || controlValue.SourceRevision != w.core.Revision || controlValue.SourceRecordSHA256 != w.core.RecordSHA256 ||
		controlValue.StartedSHA256 != report.StartedSHA256 || controlValue.StartupIdentity != runner.newIdentity ||
		!reflect.DeepEqual(controlValue.Artifact, execution.Started.Binding.TargetArtifact) || controlValue.VerificationSHA256 == "" ||
		controlValue.Readback.Conclusion != mihomo.LabTargetProjectionMatched || controlValue.Readback.SampleCount != 2 || controlValue.Readback.RequestsObserved != 8 ||
		controlValue.Readback.DataplaneProven || controlValue.Readback.FullPayloadProven || controlValue.Readback.AuthorizationProven || controlValue.Readback.Production ||
		controlValue.Schema != "chengwang.mihomo-recovery-control-observation/v2" || controlValue.LocalPath == nil ||
		!labRecoveryMarkerValueValid(*controlValue.LocalPath) || controlValue.LocalPath.ExpectedRole != "B" ||
		controlValue.LocalPath.StartedAt.Before(controlValue.ObservedAt) || !controlValue.LocalPath.ReturnedAt.Before(controlValue.Deadline) ||
		controlValue.LocalMarkerSHA256 == "" || recordCap == nil || recordCap.core == nil {
		report.FailureCode = "CONTROL_CONSUME"
		t.Fatal("actual one-use observation did not bind current S1 and selected target")
	}
	// The marker is an actual retained three-endpoint loopback observation,
	// separate from selected-target control-plane evidence. It does not make
	// the generic readback a data-plane or Internet business proof.
	markerRaw, err := json.Marshal(controlValue.LocalPath)
	if err != nil || labConfigHash(markerRaw) != controlValue.LocalMarkerSHA256 ||
		!reflect.DeepEqual(service.core.fixture.snapshot(), controlValue.LocalPath.Route.CountersAfter) {
		t.Fatal("actual marker bodies, private original or retained fixture counters differ")
	}
	markerCounters := service.core.fixture.snapshot()
	report.ControlPlane = &controlValue
	if _, err := collector.consume(controlCtx, headers["initiator"], observed); err == nil {
		t.Fatal("spent actual S2 observation proof replayed")
	}
	report.ControlProofReplayRejected = true
	anotherCollector, err := newLabRecoveryCollector(service, runner.authority, runner.session, runner.next)
	if err != nil {
		t.Fatal("same retained S2 objects could not be reopened for replay rejection")
	}
	if _, err := anotherCollector.collect(controlCtx, headers["initiator"]); err == nil {
		t.Fatal("a second collector reset the actual custody attempt")
	}
	report.ControlRecollectRejected = true
	if !reflect.DeepEqual(markerCounters, service.core.fixture.snapshot()) {
		t.Fatal("spent proof or collector replay repeated an actual marker route")
	}
	runner.store.core.mu.Lock()
	controlAfter := bytes.Clone(runner.store.core.raw)
	retainedAfterControl := runner.store.core.retainedStarted
	runner.store.core.mu.Unlock()
	report.ControlAfterSHA256 = labConfigHash(controlAfter)
	controlCallsAfter, bounded := labNativeRecoveryReadCalls()
	if !bounded || !bytes.Equal(controlBefore, controlAfter) || retainedAfterControl != nativeCustody || !reflect.DeepEqual(controlCallsBefore, controlCallsAfter) {
		t.Fatal("read-only S2 changed the actual WAL, custody or physical call prefix")
	}
	controlRawAfter, err := json.Marshal(controlCallsAfter)
	if err != nil || len(controlCallsAfter) == 0 {
		t.Fatal("actual S2 native-event ending unavailable")
	}
	report.ControlEvents = append(report.ControlEvents, labNativeRecoveryEventCheckpoint{
		Stage: "after-control-plane", Count: len(controlCallsAfter), LastSequence: controlCallsAfter[len(controlCallsAfter)-1].Sequence, EventsSHA256: labConfigHash(controlRawAfter)})
	// The collection-only invariant above remains separate. Only now does
	// the actual original one-use source cap attempt a durable append.
	processLabRecoveryVerificationIssuer.mu.Lock()
	knownBefore := processLabRecoveryVerificationIssuer.issued[recordCap.core]
	processLabRecoveryVerificationIssuer.mu.Unlock()
	if !knownBefore {
		t.Fatal("genuine observation did not issue its actual record cap")
	}
	copiedRecordCore := *recordCap.core
	if err := runner.store.recordRecoveryVerification(runner.owner, &labRecoveryVerificationRecordCap{core: &copiedRecordCore}, time.Now().UTC()); err == nil {
		t.Fatal("copied genuine record core became a registered capability")
	}
	processLabRecoveryVerificationIssuer.mu.Lock()
	stillKnown := processLabRecoveryVerificationIssuer.issued[recordCap.core]
	processLabRecoveryVerificationIssuer.mu.Unlock()
	if !stillKnown {
		t.Fatal("copied record core spent its genuine source")
	}
	point := func(stage string) labNativeRecoveryEventCheckpoint {
		calls, ok := labNativeRecoveryReadCalls()
		encoded, encodeErr := json.Marshal(calls)
		if !ok || encodeErr != nil || len(calls) == 0 {
			t.Fatal("record publication event snapshot unavailable")
		}
		return labNativeRecoveryEventCheckpoint{stage, len(calls), calls[len(calls)-1].Sequence, labConfigHash(encoded)}
	}
	report.VerificationEvents = append(report.VerificationEvents, point("before-verification-record"))
	publicationDisk.mu.Lock()
	publicationDisk.armed = true
	publicationDisk.mu.Unlock()
	attemptedAt := time.Now().UTC()
	recordErr := runner.store.recordRecoveryVerification(runner.owner, recordCap, attemptedAt)
	returnedAt := time.Now().UTC()
	if (mode == "positive") != (recordErr == nil) {
		t.Fatal("record variant did not observe its fixed publication result")
	}
	processLabRecoveryVerificationIssuer.mu.Lock()
	spent := !processLabRecoveryVerificationIssuer.issued[recordCap.core]
	processLabRecoveryVerificationIssuer.mu.Unlock()
	if !spent || runner.store.recordRecoveryVerification(runner.owner, recordCap, time.Now().UTC()) == nil {
		t.Fatal("actual publication cap was not irreversibly consumed")
	}
	publicationDisk.mu.Lock()
	replaceAttempts, forwardedWrites, postWriteReads, injectedReads, underlyingCommitted := publicationDisk.replaceAttempts, publicationDisk.forwardedWrites, publicationDisk.postWriteReads, publicationDisk.injectedReads, publicationDisk.underlyingCommitted
	publicationDisk.mu.Unlock()
	if replaceAttempts != 1 || (mode == "not-committed" && (forwardedWrites != 0 || underlyingCommitted || postWriteReads != 0)) ||
		(mode != "not-committed" && (forwardedWrites != 1 || !underlyingCommitted)) ||
		(mode == "unknown" && postWriteReads != 0) ||
		(mode == "readback" && (postWriteReads != 1 || injectedReads != 1)) ||
		(mode == "positive" && (postWriteReads != 1 || injectedReads != 0)) {
		t.Fatal("actual fixed write/readback injection point was not reached exactly")
	}
	runner.store.core.mu.Lock()
	memory := runner.store.core.record
	memoryRevision, memorySHA := memory.core.Revision, memory.core.RecordSHA256
	poisoned, clearedOwner := runner.store.core.poisoned, runner.store.core.live == nil
	proofCleared := runner.store.core.verificationRecord == nil
	startedCleared := runner.store.core.retainedStarted == nil
	adopted := !bytes.Equal(runner.store.core.raw, controlBefore)
	runner.store.core.mu.Unlock()
	if !proofCleared || !startedCleared || (mode == "positive" && (poisoned || clearedOwner || !adopted)) ||
		(mode != "positive" && (!poisoned || !clearedOwner || adopted)) {
		t.Fatal("publication result adopted an uncertain candidate or restored a capability")
	}
	diskRecord, err := labNativeVerificationCheckpoint(runner, actualDisk)
	if err != nil {
		t.Fatal("actual post-attempt disk checkpoint unavailable")
	}
	diskExecution := diskRecord.core.Recovery.Execution
	currentBefore, err := json.Marshal(w.core.Current)
	currentAfter, currentErr := json.Marshal(diskRecord.core.Current)
	if err != nil || currentErr != nil || !bytes.Equal(currentBefore, currentAfter) || diskRecord.core.Recovery.Completion != nil {
		t.Fatal("verification publication changed Current or completed recovery")
	}
	projection := &labNativeVerificationRecord{Schema: "chengwang.mihomo-native-verification-record/v1", Scope: "REDACTED_ACTUAL_WAL_FACT_NOT_AUTHORIZATION_OR_COMPLETE_PRIVATE_RECEIPT", Mode: mode,
		AttemptedAt: attemptedAt, ReturnedAt: returnedAt, ReplaceAttempts: replaceAttempts, ForwardedWrites: forwardedWrites, PostWriteReads: postWriteReads, InjectedReads: injectedReads,
		UnderlyingCommitted: underlyingCommitted, CapKnownBefore: knownBefore, CapSpent: spent, CapCopyRejected: true, CapReplayRejected: true, RecordReturnedError: recordErr != nil,
		StorePoisoned: poisoned, CandidateAdopted: adopted, LiveOwnerCleared: clearedOwner, TransientProofCleared: proofCleared, RetainedStartedCleared: startedCleared,
		SourceRevision: w.core.Revision, SourceRecordSHA256: w.core.RecordSHA256, SourceControlSHA256: labConfigHash(controlBefore), MemoryRevision: memoryRevision, MemoryRecordSHA256: memorySHA,
		DiskRevision: diskRecord.core.Revision, DiskRecordSHA256: diskRecord.core.RecordSHA256, DiskControlSHA256: runner.stages[len(runner.stages)-1].ControlSHA256,
		ExecutionSchema: diskExecution.Schema, ReceiptPresent: diskExecution.Verification != nil, SourceCurrentSHA256: labConfigHash(currentBefore), DiskCurrentSHA256: labConfigHash(currentAfter), CompletionAbsent: true}
	if mode == "not-committed" {
		if diskExecution.Verification != nil || diskExecution.Schema != lifecycleRecoveryExecutionSchema || diskRecord.core.Revision != w.core.Revision || projection.DiskControlSHA256 != projection.SourceControlSHA256 {
			t.Fatal("definite precommit failure changed the real disk")
		}
	} else {
		v := diskExecution.Verification
		preimage, preimageErr := lifecycleRecoveryVerificationPreimage(diskRecord.core, *diskRecord.core.Recovery)
		if v == nil || diskExecution.Schema != lifecycleRecoveryVerifiedExecutionSchema || preimageErr != nil || !bytes.Equal(preimage, controlBefore) ||
			!reflect.DeepEqual(v.Observation, lifecycleRecoveryObservedFromValue(controlValue)) || v.VerificationCommitRevision != w.core.Revision+1 {
			t.Fatal("actual persisted typed fact did not bind the complete S1 image")
		}
		receiptBytes, receiptErr := json.Marshal(v)
		if receiptErr != nil {
			t.Fatal("actual persisted receipt hash unavailable")
		}
		receiptSHA, observationSHA, revision, recordedAt, sourceSHA := labConfigHash(receiptBytes), v.ObservationSHA256, v.VerificationCommitRevision, v.RecordedAt, labConfigHash(preimage)
		projection.ReceiptSHA256, projection.ObservationSHA256, projection.VerificationCommitRevision, projection.RecordedAt, projection.S1PreimageSHA256 = &receiptSHA, &observationSHA, &revision, &recordedAt, &sourceSHA
	}
	afterRecordCalls, recordBounded := labNativeRecoveryReadCalls()
	if !recordBounded || !reflect.DeepEqual(controlCallsAfter, afterRecordCalls) {
		t.Fatal("record-only append dispatched a physical operation")
	}
	projection.NoNewPhysicalCalls = true
	report.VerificationEvents = append(report.VerificationEvents, point("after-verification-record"))
	report.VerificationRecord = projection
	projectionRaw, projectionErr := json.Marshal(projection)
	if projectionErr != nil || labNativeRecoveryWrite("verification-record.private.json", projectionRaw) != nil {
		t.Fatal("redacted actual record projection unavailable")
	}
	// Only the execution actually read from disk is expected at cold reopen.
	// It is v1 for NotCommitted and v2 for committed/uncertain outcomes.
	execution = *diskExecution
	// Owned-metadata negative control only: these are the actual retired
	// closed legacy object and the actual migrated new disk owner. No disk,
	// record, capability or public setter is constructed for this case.
	runtime := service.core.runtime.core
	runtime.mu.Lock()
	originalStore, actualRecovery := runtime.store, runtime.recovery
	legacyHistory := service.core.store
	if originalStore != nil || actualRecovery != runner.store || legacyHistory == nil || !legacyHistory.closed || legacyHistory.disk != nil {
		runtime.mu.Unlock()
		t.Fatal("actual sole-owner image is not suitable for metadata negative control")
	}
	runtime.store = legacyHistory
	runtime.mu.Unlock()
	firstCloseError := service.core.runtime.close()
	secondCloseError := service.core.runtime.close()
	runtime.mu.Lock()
	actualRecovery.core.mu.Lock()
	dualUnchanged := !runtime.closed && runtime.store == legacyHistory && runtime.recovery == actualRecovery && !actualRecovery.core.closed
	actualRecovery.core.mu.Unlock()
	// Restore only the exact original legal XOR, even when the assertions
	// fail. Never reset closed/poison or erase an actual close observation.
	runtime.store = originalStore
	runtime.mu.Unlock()
	if firstCloseError == nil || secondCloseError == nil || !dualUnchanged {
		t.Fatal("inconsistent dual owner became a close success or changed owners")
	}
	report.DualOwnerCloseRejectedTwice = true
	if _, err := runner.captureEvents("before-cleanup"); err != nil {
		t.Fatal("actual cleanup event baseline unavailable")
	}
	cleanup, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
	err = runner.cleanup(cleanup)
	cleanupCancel()
	if err != nil || !service.core.closed || !service.core.runtime.core.closed || !runner.store.core.closed ||
		service.core.runtime.core.store != nil || service.core.runtime.core.recovery != runner.store {
		report.FailureCode = "OWNED_CLEANUP"
		t.Fatal("two generations or new sole disk owner were not actually closed")
	}
	if service.core.kernelCloseObservation == nil || !labQuiescenceExitDrained(*service.core.kernelCloseObservation) ||
		runner.newExit == nil || !labQuiescenceExitDrained(*runner.newExit) || !labQuiescenceExitEqual(*service.core.kernelCloseObservation, *runner.quiescence.Stop) {
		t.Fatal("actual old/new Wait and pipe cleanup observations missing")
	}
	if _, err := runner.captureEvents("after-cleanup"); err != nil {
		t.Fatal("actual cleanup event readback unavailable")
	}
	beforeCleanupReplay, checkpointErr := runner.captureEvents("before-cleanup-replay")
	if checkpointErr != nil {
		t.Fatal("actual cleanup replay event baseline unavailable")
	}
	cleanup, cleanupCancel = context.WithTimeout(context.Background(), 2*time.Second)
	err = runner.cleanup(cleanup)
	cleanupCancel()
	afterCleanupReplay, checkpointErr := runner.captureEvents("after-cleanup-replay")
	if err != nil || checkpointErr != nil || !reflect.DeepEqual(beforeCleanupReplay, afterCleanupReplay) {
		t.Fatal("repeated cleanup added a signal, Wait or Start")
	}
	report.CleanupReplayNoOp = true
	service.core.mu.Lock()
	fixtureCleanup := append([]labLocalFixtureCleanup{}, service.core.fixtureCloseObservations...)
	fixtureSettled := service.core.fixtureSettled
	service.core.mu.Unlock()
	if !fixtureSettled || len(fixtureCleanup) != 3 {
		report.FailureCode = "FIXTURE_CLEANUP"
		t.Fatal("actual fixture owner shutdown observations missing")
	}
	for i, role := range []string{"origin", "A", "B"} {
		observed := fixtureCleanup[i]
		if observed.Role != role || !observed.ShutdownReturned || !observed.ServeReturned ||
			observed.ForcedConnectionsClosed < 0 || observed.ErrorClass != "NONE" {
			report.FailureCode = "FIXTURE_CLEANUP"
			t.Fatal("actual fixture Shutdown and Serve join did not settle")
		}
	}
	// These negative controls make no connection and cannot close any resource.
	if rejected := labNativeRecoveryCleanupDial(context.Background(), 28416); rejected.Attempted || rejected.Result != "OTHER" {
		t.Fatal("cleanup probe accepted an endpoint outside its fixed allowlist")
	}
	cancelledProbe, cancelProbe := context.WithCancel(context.Background())
	cancelProbe()
	if rejected := labNativeRecoveryCleanupDial(cancelledProbe, 28413); rejected.Attempted || rejected.Result != "CONTEXT_REJECTED" {
		t.Fatal("cleanup probe attempted a connection after entry cancellation")
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
	if _, err := runner.captureEvents("before-reopen"); err != nil {
		t.Fatal("actual reopen event baseline unavailable")
	}
	reopened, err := labNativeVerificationReopen(runner.legacy, execution)
	if err != nil {
		report.FailureCode = "ACTUAL_REOPEN"
		t.Fatal("actual strict disk reopen did not preserve Started and fail closed")
	}
	report.Reopened = &reopened
	report.ReopenedExecutionPreserved = true
	report.ReopenedRecordCapabilityAbsent = true
	if _, err := runner.captureEvents("after-reopen"); err != nil {
		t.Fatal("actual reopen event readback unavailable")
	}
	finalEvents, bounded := labNativeRecoveryReadCalls()
	if !bounded || !reflect.DeepEqual(finalEvents, afterCleanupReplay) ||
		labNativeRecoveryCount(finalEvents, "KERNEL_OS_WAIT_RETURN", report.OldCore) != 1 ||
		labNativeRecoveryCount(finalEvents, "KERNEL_OS_WAIT_RETURN", report.NewCore) != 1 ||
		labNativeRecoveryCount(finalEvents, "KERNEL_OS_TERM_ATTEMPT", report.NewCore) != 1 ||
		labNativeRecoveryCount(finalEvents, "OWNED_STOP_HELPER_ENTER", report.OldCore) != 2 ||
		labNativeRecoveryCount(finalEvents, "OWNED_STOP_HELPER_ENTER", report.NewCore) != 1 {
		t.Fatal("reopen invoked a native action or cleanup Wait count changed")
	}
	if len(service.core.syntaxObservations) != 1 || !service.core.syntaxObservations[0].settled() {
		t.Fatal("original syntax process cleanup was not separately observed")
	}
	report.Outcome, report.FailureCode = "PASS", "NONE"
}
