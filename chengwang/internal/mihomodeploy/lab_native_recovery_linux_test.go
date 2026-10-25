//go:build linux && chengwang_mihomo_service && chengwang_mihomo_faults && chengwang_mihomo_recovery_native

package mihomodeploy

// Real pinned-kernel/native-disk acceptance. This file never calls a MODEL
// helper, seeds a WAL, writes an issuer registry or constructs a private cap.
// It has no skip path. Only the isolated Linux worker may satisfy its envelope.
import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
)

type labNativeRecoveryReport struct {
	Schema                              string                             `json:"schema"`
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
	report := labNativeRecoveryReport{Schema: "chengwang.mihomo-native-recovery-experiment/v2",
		Scope: labNativeRecoveryScope, SourceCommit: os.Getenv("CHENGWANG_MIHOMO_APPLY_SOURCE_COMMIT"),
		Outcome: "FAIL", FailureCode: "NOT_COMPLETED", Stages: []labNativeRecoveryCheckpoint{}, Syntax: []labKernelStartObservation{},
		NativeCalls: []labNativeRecoveryCall{}, EventCheckpoints: []labNativeRecoveryEventCheckpoint{}, ClosedPorts: []uint16{},
		FixtureCleanup: []labLocalFixtureCleanup{}, CleanupProbes: []labQuiescenceProbe{}}
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
	reopened, err := labNativeRecoveryReopen(runner.legacy, execution)
	if err != nil {
		report.FailureCode = "ACTUAL_REOPEN"
		t.Fatal("actual strict disk reopen did not preserve Started and fail closed")
	}
	report.Reopened = &reopened
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
