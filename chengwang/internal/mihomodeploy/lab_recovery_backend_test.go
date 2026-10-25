package mihomodeploy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/authz"
)

func TestLabRecoveryRecordContextCoversRecordAndCancelsAfterReturnMODEL(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "error"}[fail], func(t *testing.T) {
			var during context.Context
			sentinel := errors.New("MODEL record failure")
			err := labRecoveryWithRecordContext(context.Background(), time.Second, func(ctx context.Context) error {
				during = ctx
				if ctx.Err() != nil {
					t.Fatal("MODEL record observed an already-cancelled capability context")
				}
				if fail {
					return sentinel
				}
				return nil
			})
			if during == nil || during.Err() != context.Canceled || fail && !errors.Is(err, sentinel) || !fail && err != nil {
				t.Fatal("MODEL context was not live during record and cancelled immediately after return")
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if err := labRecoveryWithRecordContext(cancelled, time.Second, func(context.Context) error {
		called = true
		return nil
	}); !errors.Is(err, context.Canceled) || called {
		t.Fatal("MODEL cancelled caller was replaced by a fresh/background record context")
	}
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	called = false
	if err := labRecoveryWithRecordContext(expired, time.Second, func(context.Context) error {
		called = true
		return nil
	}); !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatal("MODEL expired caller entered the capability record action")
	}
}

func TestLabRecoveryReconciliationRetryRetainsCustodyOnceAndThenLocksMODEL(t *testing.T) {
	id := "labrec_55555555555555555555555555555555"
	planSHA, actorRef, recordSHA := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	op := &labRecoveryOperation{id: id, plan: labRecoveryPlanDescriptor{PlanSHA256: planSHA, DeclaredInitiatorRef: actorRef},
		owner: &lifecycleRecoveryOwnerToken{core: &lifecycleRecoveryOwnerCore{fence: 7}}, failureCode: "START_UNCERTAIN",
		reconcileState: labRecoveryReconcileReady}
	canonical := `{"schema":"chengwang.mihomo-recovery-kernel-cleanup/v1"}`
	issuer := &labRecoveryCleanupIssuer{issued: map[*labRecoveryCleanupCustody]bool{}}
	custody := &labRecoveryCleanupCustody{issuer: issuer, operation: op, canonical: canonical, digest: labConfigHash([]byte(canonical)), settled: true}
	issuer.issued[custody] = true
	custody.binding = func(candidate *labRecoveryCleanupCustody, current *labRecoveryOperation) bool {
		return candidate == custody && current == op && candidate.operation == op && !candidate.used &&
			candidate.canonical == canonical && candidate.digest == labConfigHash([]byte(canonical)) && candidate.settled
	}
	op.cleanup = custody
	check := labRecoveryCheck{core: &labRecoveryCheckCore{"RECOVERY_RECONCILE_AUTHORIZATION_CHECK", actorRef,
		id, planSHA, 9, recordSHA, 7, "START_UNCERTAIN"}}
	foreign := check
	foreign.core = &labRecoveryCheckCore{"RECOVERY_RECONCILE_AUTHORIZATION_CHECK", strings.Repeat("d", 64),
		id, planSHA, 9, recordSHA, 7, "START_UNCERTAIN"}
	if op.beginAuthorizedReconciliationAttempt(custody, foreign) || op.reconcileAttempts != 0 || op.reconcileState != labRecoveryReconcileReady {
		t.Fatal("MODEL foreign caller consumed reconciliation budget")
	}
	if !op.beginAuthorizedReconciliationAttempt(custody, check) {
		t.Fatal("MODEL initial reconciliation attempt rejected")
	}
	op.reconciliationPrePermitFailed()
	if !op.reconciliationRetryable() || op.cleanup != custody || custody.used || !issuer.issued[custody] || op.reconcileAttempts != 1 {
		t.Fatal("MODEL pre-permit failure released source custody or removed the sole retry")
	}
	if !op.beginAuthorizedReconciliationAttempt(custody, check) {
		t.Fatal("MODEL sole explicit reconciliation retry rejected")
	}
	op.reconciliationPrePermitFailed()
	if op.reconcileState != labRecoveryReconcileLocked || op.reconciliationRetryable() || op.cleanup != custody || custody.used || !issuer.issued[custody] || op.reconcileAttempts != labRecoveryReconcileMaxAttempts {
		t.Fatal("MODEL reconciliation retries were unbounded or custody was rewritten")
	}
	op.reconcileState = labRecoveryReconcileArmed
	if op.reconciliationRetryable() {
		t.Fatal("MODEL armed core permit became retryable")
	}
}

func TestLabRecoveryStaleAuthorizedCheckCannotSpendAttemptMODEL(t *testing.T) {
	store, _, owner, _, _, now := lifecycleRecoveryModelArmed(t)
	if err := store.recordRecoveryFailure(owner, "START_UNCERTAIN", nil, now); err != nil {
		t.Fatal("MODEL durable UNKNOWN")
	}
	store.core.mu.Lock()
	w := store.core.record.core
	id, plan, revision, recordSHA, fence := w.Recovery.Plan.RecoveryID, w.Recovery.Plan, w.Revision, w.RecordSHA256, w.LastRecoveryFence
	store.core.mu.Unlock()
	op := &labRecoveryOperation{id: id, store: store, owner: owner, plan: plan, failureCode: "START_UNCERTAIN",
		reconcileState: labRecoveryReconcileReady}
	canonical := `{"schema":"chengwang.mihomo-recovery-kernel-cleanup/v1"}`
	custody := &labRecoveryCleanupCustody{operation: op, canonical: canonical, digest: labConfigHash([]byte(canonical)), settled: true}
	custody.binding = func(candidate *labRecoveryCleanupCustody, current *labRecoveryOperation) bool {
		return candidate == custody && current == op && candidate.operation == op && !candidate.used &&
			candidate.canonical == canonical && candidate.digest == labConfigHash([]byte(canonical)) && candidate.settled
	}
	op.cleanup = custody
	valid := labRecoveryCheck{core: &labRecoveryCheckCore{"RECOVERY_RECONCILE_AUTHORIZATION_CHECK", plan.DeclaredInitiatorRef,
		id, plan.PlanSHA256, revision, recordSHA, fence, "START_UNCERTAIN"}}
	stale := valid
	stale.core = &labRecoveryCheckCore{"RECOVERY_RECONCILE_AUTHORIZATION_CHECK", plan.DeclaredInitiatorRef,
		id, plan.PlanSHA256, revision - 1, strings.Repeat("d", 64), fence, "START_UNCERTAIN"}
	if op.beginCurrentAuthorizedReconciliationAttempt(custody, stale) || op.reconcileAttempts != 0 || op.reconcileState != labRecoveryReconcileReady {
		t.Fatal("MODEL stale post-auth CAS check consumed reconciliation budget")
	}
	if !op.beginCurrentAuthorizedReconciliationAttempt(custody, valid) || op.reconcileAttempts != 1 {
		t.Fatal("MODEL current exact authorization could not claim one attempt")
	}
}

func labRecoveryBusyReconcileMODEL(t *testing.T) (*labRecoveryAuthorityModel, *labRecoveryCoordinator, *labRecoveryOperation, LabRecoveryExecuteRequest) {
	t.Helper()
	m := labRecoveryAuthorityTestModel(t)
	m.armStart(t)
	if err := m.store.recordRecoveryFailure(m.owner, "START_UNCERTAIN", nil, m.f.now); err != nil {
		t.Fatal("MODEL durable UNKNOWN")
	}
	m.store.core.mu.Lock()
	w := m.store.core.record.core
	id, plan, revision := w.Recovery.Plan.RecoveryID, w.Recovery.Plan, w.Revision
	m.store.core.mu.Unlock()
	op := &labRecoveryOperation{id: id, session: m.session, store: m.store, owner: m.owner, plan: plan,
		physical: true, failureCode: "START_UNCERTAIN", failureRecorded: true, reconcileState: labRecoveryReconcileReady}
	canonical := `{"schema":"chengwang.mihomo-recovery-kernel-cleanup/v1"}`
	issuer := &labRecoveryCleanupIssuer{issued: map[*labRecoveryCleanupCustody]bool{}}
	custody := &labRecoveryCleanupCustody{issuer: issuer, operation: op, canonical: canonical,
		digest: labConfigHash([]byte(canonical)), settled: true}
	custody.binding = func(candidate *labRecoveryCleanupCustody, current *labRecoveryOperation) bool {
		return candidate == custody && current == op && candidate.operation == op && !candidate.used &&
			candidate.canonical == canonical && candidate.digest == labConfigHash([]byte(canonical)) && candidate.settled
	}
	if !issuer.issue(custody) {
		t.Fatal("MODEL cleanup custody")
	}
	op.cleanup = custody
	service := &labServiceCore{}
	coordinator := &labRecoveryCoordinator{service: &LabService{core: service}, authority: m.a,
		operations: map[string]*labRecoveryOperation{id: op}, activeID: id}
	return m, coordinator, op, LabRecoveryExecuteRequest{PlanSHA256: plan.PlanSHA256, Revision: revision}
}

func TestLabRecoveryReconcileAuthenticatesBeforeBusyOrExecutingConflictMODEL(t *testing.T) {
	assertState := func(t *testing.T, c *labRecoveryCoordinator, op *labRecoveryOperation, busy, executing bool) {
		t.Helper()
		s := c.service.core
		if s.busy != busy || op.executing != executing || op.reconcileAttempts != 0 ||
			op.reconcileState != labRecoveryReconcileReady || op.cleanup == nil || op.cleanup.used {
			t.Fatal("MODEL authorization or conflict changed reconciliation state")
		}
	}
	for _, state := range []struct {
		name      string
		busy      bool
		executing bool
	}{{"busy", true, false}, {"executing", false, true}} {
		t.Run(state.name, func(t *testing.T) {
			m, c, op, request := labRecoveryBusyReconcileMODEL(t)
			c.service.core.busy, op.executing = state.busy, state.executing
			if _, err := c.execute(context.Background(), m.f.headers["outsider"], op.id, request); err == nil {
				t.Fatal("MODEL foreign caller observed busy state instead of authorization rejection")
			} else {
				var backend *LabBackendError
				if !errors.As(err, &backend) || backend.Code == LabBackendConflict {
					t.Fatal("MODEL foreign caller received pre-authorization conflict")
				}
			}
			assertState(t, c, op, state.busy, state.executing)
			if _, err := c.execute(context.Background(), m.f.headers["initiator"], op.id, request); err == nil {
				t.Fatal("MODEL exact initiator bypassed busy/executing conflict")
			} else {
				var backend *LabBackendError
				if !errors.As(err, &backend) || backend.Code != LabBackendConflict {
					t.Fatal("MODEL exact initiator did not reach the post-authorization conflict")
				}
			}
			assertState(t, c, op, state.busy, state.executing)
		})
	}

	t.Run("revoked-initiator", func(t *testing.T) {
		m, c, op, request := labRecoveryBusyReconcileMODEL(t)
		c.service.core.busy = true
		m.f.edit(t, "initiator", func(i *authn.Identity) { i.Principal.Roles = []authz.Role{authz.RoleViewer} })
		if _, err := c.execute(context.Background(), m.f.headers["initiator"], op.id, request); err == nil {
			t.Fatal("MODEL revoked initiator observed busy state instead of authorization rejection")
		} else {
			var backend *LabBackendError
			if !errors.As(err, &backend) || backend.Code == LabBackendConflict {
				t.Fatal("MODEL revoked initiator received pre-authorization conflict")
			}
		}
		assertState(t, c, op, true, false)
	})
}

func labRecoveryCleanupIssuerMODEL(t *testing.T, withChild bool) (*labRecoveryCleanupIssuer, *labRecoveryOperation, *labRecoveryCleanupCustody, *labRecoveryUnstartedCleanupCustody) {
	t.Helper()
	now := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	op := &labRecoveryOperation{id: "labrec_66666666666666666666666666666666"}
	issuer := &labRecoveryCleanupIssuer{issued: map[*labRecoveryCleanupCustody]bool{}}
	canonical := `{"schema":"chengwang.mihomo-recovery-kernel-cleanup/v1"}`
	parent := &labRecoveryCleanupCustody{issuer: issuer, operation: op, canonical: canonical,
		digest: labConfigHash([]byte(canonical)), settled: true}
	parent.binding = func(candidate *labRecoveryCleanupCustody, current *labRecoveryOperation) bool {
		return candidate == parent && current == op && candidate.operation == op && !candidate.used &&
			candidate.canonical == canonical && candidate.digest == labConfigHash([]byte(canonical)) && candidate.settled
	}
	var child *labRecoveryUnstartedCleanupCustody
	if withChild {
		child = &labRecoveryUnstartedCleanupCustody{issuer: issuer, parent: parent, operation: op,
			service: &labServiceCore{}, kernel: &ownedLabKernelCore{}, observedAt: now,
			stdoutSHA256: labConfigHash(nil), stderrSHA256: labConfigHash(nil)}
		child.binding = func(candidate *labRecoveryUnstartedCleanupCustody, candidateParent *labRecoveryCleanupCustody, current *labRecoveryOperation) bool {
			return candidate == child && candidateParent == parent && current == op && candidate.issuer == issuer &&
				candidate.parent == parent && candidate.operation == op && !candidate.used
		}
		parent.unstartedNext = child
	}
	op.cleanup = parent
	if !issuer.issue(parent) {
		t.Fatal("MODEL cleanup issuer setup")
	}
	return issuer, op, parent, child
}

func TestLabRecoveryCleanupIssuerDiscardIsExactAtomicAndReleasesGraphMODEL(t *testing.T) {
	issuer, op, parent, child := labRecoveryCleanupIssuerMODEL(t, true)
	copyParent := *parent
	if issuer.discard(&copyParent, op) || !issuer.contains(parent) {
		t.Fatal("MODEL copied parent discarded source custody")
	}
	if issuer.discard(parent, &labRecoveryOperation{id: op.id}) || !issuer.contains(parent) {
		t.Fatal("MODEL foreign operation discarded source custody")
	}
	if !issuer.discard(parent, op) || issuer.contains(parent) || !parent.used || !child.used ||
		parent.operation != nil || parent.unstartedNext != nil || child.parent != nil || child.kernel != nil {
		t.Fatal("MODEL exact discard retained parent/child authority graph")
	}
	if _, claimed := issuer.claim(parent); claimed {
		t.Fatal("MODEL discarded custody was later claimed")
	}

	for range 32 {
		racingIssuer, racingOp, racingParent, _ := labRecoveryCleanupIssuerMODEL(t, false)
		start := make(chan struct{})
		var claimed, discarded bool
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, claimed = racingIssuer.claim(racingParent)
		}()
		go func() {
			defer wg.Done()
			<-start
			discarded = racingIssuer.discard(racingParent, racingOp)
		}()
		close(start)
		wg.Wait()
		if claimed == discarded || racingIssuer.contains(racingParent) {
			t.Fatal("MODEL claim/discard race did not have exactly one winner")
		}
	}
}

func TestLabRecoveryTerminalPrePermitFailureAndCloseDiscardUnclaimedCustodyMODEL(t *testing.T) {
	issuer, op, parent, child := labRecoveryCleanupIssuerMODEL(t, true)
	service := &labServiceCore{}
	coordinator := &labRecoveryCoordinator{service: &LabService{core: service}}
	op.reconcileState, op.reconcileAttempts = labRecoveryReconcileReady, 1
	coordinator.reconciliationPrePermitFailure(op, parent)
	if op.reconcileState != labRecoveryReconcileReady || op.cleanup != parent || !issuer.contains(parent) || parent.used || child.used {
		t.Fatal("MODEL first authorized pre-permit failure discarded the sole retry")
	}
	op.reconcileAttempts = labRecoveryReconcileMaxAttempts
	coordinator.reconciliationPrePermitFailure(op, parent)
	if op.reconcileState != labRecoveryReconcileLocked || op.cleanup != nil || issuer.contains(parent) || !parent.used || !child.used {
		t.Fatal("MODEL terminal pre-permit failure orphaned issued custody")
	}

	closeIssuer, closeOp, closeParent, closeChild := labRecoveryCleanupIssuerMODEL(t, true)
	base := &labAuthority{core: &labAuthorityCore{}}
	coordinator = &labRecoveryCoordinator{operations: map[string]*labRecoveryOperation{closeOp.id: closeOp},
		authority: &labRecoveryAuthority{core: &labRecoveryAuthorityCore{base: base,
			initiators: map[*labRecoveryInitiator]*labRecoveryInitiatorCore{}, sessions: map[*labRecoverySession]*labRecoverySessionCore{}}}}
	if err := coordinator.close(); err != nil || closeIssuer.contains(closeParent) || !closeParent.used || !closeChild.used || closeOp.cleanup != nil {
		t.Fatal("MODEL coordinator Close retained an unclaimed cleanup graph")
	}
}

type labRecoveryRuntimeDiskMODEL struct {
	*lifecycleModelDisk
	binding lifecycleProvisioning
}

func (d *labRecoveryRuntimeDiskMODEL) provisioning() (lifecycleProvisioning, error) {
	return d.binding, nil
}
func (*labRecoveryRuntimeDiskMODEL) artifactDirectory() string { return "/MODEL/not-production" }

// MODEL only: trusted timestamps are advanced directly. This does not claim a
// real five-minute wait, kernel adoption, HTTP request or Completion run.
func TestLabRecoveryOwnerExpiryReplacementRejectsOldTokenAndPreservesHistoryMODEL(t *testing.T) {
	store, _, oldOwner, _, now := lifecycleRecoveryModelPlanned(t)
	if store.revokeRecovery(oldOwner, "MODEL_revoker", "EXPLICIT_REVOKED", now) != nil {
		t.Fatal("MODEL terminal recovery")
	}
	store.core.mu.Lock()
	oldFence := store.core.record.core.LastRecoveryFence
	expires := store.core.record.core.RecoveryOwner.ExpiresAt
	history := lifecycleCloneSlice(store.core.record.core.RecoveryHistory, func(v lifecycleRecoveryTxn) lifecycleRecoveryTxn {
		return (&lifecycleCloneState{}).recovery(v)
	})
	store.core.mu.Unlock()
	if _, fresh, err := labRecoveryOwnerExpiry(store, oldOwner, expires.Add(-time.Nanosecond)); err != nil || !fresh {
		t.Fatal("MODEL fresh warm owner was not reusable")
	}
	newOwner, err := store.acquireRecoveryOwner(expires, expires.Add(time.Minute))
	if err != nil || newOwner == nil || newOwner.core == nil {
		t.Fatal("MODEL expired owner replacement")
	}
	store.core.mu.Lock()
	defer store.core.mu.Unlock()
	if store.core.record.core.LastRecoveryFence != oldFence+1 || store.core.live != newOwner.core ||
		store.core.token(oldOwner, false, expires) == nil || store.core.token(newOwner, true, expires) != nil ||
		!reflect.DeepEqual(history, store.core.record.core.RecoveryHistory) {
		t.Fatal("MODEL replacement revived an old token or changed history")
	}
}

func TestLabRecoveryCaptureNamespaceIsDistinctAndSourceDerivedMODEL(t *testing.T) {
	a, errA := labRecoveryCaptureNamespace("labrec_11111111111111111111111111111111")
	b, errB := labRecoveryCaptureNamespace("labrec_22222222222222222222222222222222")
	if errA != nil || errB != nil || a == b || !labRecoveryCaptureNamespaceValid(a) || !labRecoveryCaptureNamespaceValid(b) ||
		labDiagnosticName(a+"/transcript.json") == false || labDiagnosticName(b+"/local-marker.json") == false {
		t.Fatal("MODEL source-derived recovery capture namespace")
	}
}

func TestLabRecoveryRevokedFirstPlanBeginsFreshV1WithoutFacadeMODEL(t *testing.T) {
	store, disk, owner, oldPlan, now := lifecycleRecoveryModelPlanned(t)
	if store.revokeRecovery(owner, "MODEL_revoker", "EXPLICIT_REVOKED", now) != nil {
		t.Fatal("MODEL revoke")
	}
	store.core.mu.Lock()
	source, err := store.core.copyRecord()
	beforeHistory := lifecycleCloneSlice(store.core.record.core.RecoveryHistory, func(v lifecycleRecoveryTxn) lifecycleRecoveryTxn {
		return (&lifecycleCloneState{}).recovery(v)
	})
	revision, recordSHA, writes := store.core.record.core.Revision, store.core.record.core.RecordSHA256, disk.writes
	adapter := &labRecoveryRuntimeDiskMODEL{lifecycleModelDisk: disk, binding: store.core.record.core.Provisioning}
	store.core.disk = adapter
	store.core.mu.Unlock()
	if err != nil || len(beforeHistory) != 1 || beforeHistory[0].Phase != "REVOKED_UNSTARTED" {
		t.Fatal("MODEL revoked history was not retained")
	}
	at := now.Add(time.Millisecond)
	expires, fresh, err := labRecoveryOwnerExpiry(store, owner, at)
	if err != nil || !fresh {
		t.Fatal("MODEL warm owner was not fresh")
	}
	target := oldPlan.descriptor().TargetArtifact
	plan, err := labRecoveryPlanForCurrentEpoch(source, "labrec_33333333333333333333333333333333", "MODEL_new_initiator", target, at, expires)
	if err != nil || plan.core == nil || plan.core.descriptor.Schema != labRecoveryPlanSchema || plan.core.descriptor.Source != nil {
		t.Fatal("MODEL legacy current epoch did not select exact v1 source")
	}
	runtime := &labLifecycleRuntime{core: &labLifecycleRuntimeCore{disk: adapter, recovery: store}}
	if err := runtime.beginRecoveryWithoutCurrent(store, owner, &plan, revision, recordSHA, at); err != nil {
		t.Fatal("MODEL fresh begin without nonexistent facade", err)
	}
	store.core.mu.Lock()
	defer store.core.mu.Unlock()
	if store.core.record.core.Recovery == nil || store.core.record.core.Recovery.Plan.RecoveryID != plan.core.descriptor.RecoveryID ||
		store.core.record.core.Recovery.Phase != "PLANNED" || !reflect.DeepEqual(beforeHistory, store.core.record.core.RecoveryHistory) ||
		store.core.currentLive != nil || runtime.core.current != nil || runtime.core.store != nil || disk.writes != writes+1 {
		t.Fatal("MODEL fresh begin changed old history, invented facade, or missed one durable write")
	}
}

func TestLabRecoveryWithoutFacadeNeverDowngradesOrBypassesV2CurrentOwnerMODEL(t *testing.T) {
	store, disk, owner, _, now := lifecycleRecoveryModelPlanned(t)
	adapter := &labRecoveryRuntimeDiskMODEL{lifecycleModelDisk: disk, binding: store.core.record.core.Provisioning}
	store.core.mu.Lock()
	store.core.disk = adapter
	revision, recordSHA, writes := store.core.record.core.Revision, store.core.record.core.RecordSHA256, disk.writes
	store.core.mu.Unlock()
	runtime := &labLifecycleRuntime{core: &labLifecycleRuntimeCore{disk: adapter, recovery: store}}
	plan := &labRecoveryPlan{core: &labRecoveryPlanCore{descriptor: labRecoveryPlanDescriptor{Schema: labRecoveryPlanSchemaV2}}}
	if runtime.beginRecoveryWithoutCurrent(store, owner, plan, revision, recordSHA, now) == nil || disk.writes != writes {
		t.Fatal("MODEL v2 recovery bypassed missing current owner/facade")
	}
}

func TestLabRecoveryPhysicalFailureStagesExposeBoundedInspectExitMODEL(t *testing.T) {
	for _, code := range []string{"QUIESCENCE_REJECTED", "SERVICE_CONTEXT_CANCELLED", "AUTHORITY_CHANGED", "START_UNCERTAIN"} {
		t.Run(code, func(t *testing.T) {
			store, _, owner, _, _, now := lifecycleRecoveryModelArmed(t)
			if store.recordRecoveryFailure(owner, code, nil, now) != nil {
				t.Fatal("MODEL durable failure")
			}
			store.core.mu.Lock()
			id := store.core.record.core.Recovery.Plan.RecoveryID
			store.core.mu.Unlock()
			op := &labRecoveryOperation{id: id, store: store, owner: owner, physical: true, failureCode: code,
				failureRecorded: true, settled: true, failure: &LabRecoveryFailureView{Schema: LabRecoveryFailureViewSchema,
					Code: code, CleanupState: "SETTLED", CleanupSHA256: strings.Repeat("f", 64), NextAction: "CORE_RECONCILIATION_REQUIRED"}}
			view, err := (&labRecoveryCoordinator{}).viewLocked(op, false)
			if err != nil || view.Phase != "RECOVERY_UNKNOWN" || !view.WriteBlocked || view.Failure == nil ||
				view.Failure.Code != code || view.Failure.CleanupState != "SETTLED" || view.Failure.NextAction != "CORE_RECONCILIATION_REQUIRED" {
				t.Fatal("MODEL physical failure did not expose a bounded authorized Inspect exit")
			}
		})
	}
}

func TestLabRecoveryCleanupCustodyCannotSerializeOrSurviveMutationMODEL(t *testing.T) {
	op := &labRecoveryOperation{id: "labrec_44444444444444444444444444444444"}
	canonical := `{"schema":"chengwang.mihomo-recovery-kernel-cleanup/v1"}`
	custody := &labRecoveryCleanupCustody{operation: op, old: &ownedLabKernelCore{}, canonical: canonical,
		digest: labConfigHash([]byte(canonical)), settled: true}
	operation, owned, sealed, digest := op, custody.old, custody.canonical, custody.digest
	custody.binding = func(candidate *labRecoveryCleanupCustody, current *labRecoveryOperation) bool {
		return candidate == custody && current == operation && candidate.operation == operation && candidate.old == owned &&
			candidate.canonical == sealed && candidate.digest == digest && candidate.settled && labConfigHash([]byte(candidate.canonical)) == candidate.digest
	}
	if !custody.matches(op) {
		t.Fatal("MODEL exact cleanup custody rejected")
	}
	if raw, err := json.Marshal(custody); err == nil || raw != nil {
		t.Fatal("MODEL cleanup custody serialized")
	}
	custody.canonical += " "
	if custody.matches(op) {
		t.Fatal("MODEL mutated cleanup custody remained valid")
	}
}

func TestLabRecoveryUnstartedCleanupCustodyIsAtomicOneUseForNormalAndAbsentMODEL(t *testing.T) {
	for _, schema := range []string{labRecoveryStartObservationSchema, labRecoveryAbsentStartObservationSchema} {
		t.Run(schema, func(t *testing.T) {
			now := time.Date(2026, 10, 26, 5, 0, 0, 0, time.UTC)
			started, waited := false, false
			stream := labKernelStream{SHA256: labConfigHash(nil), Complete: true}
			start := labKernelStartObservation{Attempted: true, Started: &started, WaitReturned: &waited,
				WaitErrorClass: "NOT_WAITED", Stdout: &stream, Stderr: &stream}
			attempt := &labRecoveryStartObservation{Schema: schema, StartObservation: &start}
			op := &labRecoveryOperation{id: "labrec_55555555555555555555555555555555"}
			service, kernel := &labServiceCore{}, &ownedLabKernelCore{}
			issuer := &labRecoveryCleanupIssuer{issued: map[*labRecoveryCleanupCustody]bool{}}
			canonical := `{"schema":"MODEL"}`
			parent := &labRecoveryCleanupCustody{issuer: issuer, operation: op, service: service,
				canonical: canonical, digest: labConfigHash([]byte(canonical)), settled: true}
			parent.binding = func(candidate *labRecoveryCleanupCustody, current *labRecoveryOperation) bool {
				return candidate == parent && current == op
			}
			u := &labRecoveryUnstartedCleanupCustody{issuer: issuer, parent: parent, operation: op, service: service,
				kernel: kernel, observation: labRecoveryStartedCloneStart(start), stdout: stream, stderr: stream,
				stdoutSHA256: labConfigHash(nil), stderrSHA256: labConfigHash(nil), observedAt: now}
			u.binding = func(candidate *labRecoveryUnstartedCleanupCustody, candidateParent *labRecoveryCleanupCustody, current *labRecoveryOperation) bool {
				return candidate == u && candidateParent == parent && current == op
			}
			parent.unstartedNext = u
			if !issuer.issue(parent) || !parent.matches(op) {
				t.Fatal("MODEL exact unstarted cleanup graph was not issued")
			}
			if raw, err := json.Marshal(u); err == nil || raw != nil {
				t.Fatal("MODEL unstarted cleanup custody serialized")
			}
			copyU := *u
			if copyU.matches(parent, op) || u.matches(parent, &labRecoveryOperation{id: op.id}) {
				t.Fatal("MODEL copied or foreign unstarted custody matched")
			}
			claimed, ok := issuer.claim(parent)
			if !ok || claimed != u || !u.used || !parent.used || issuer.issued[parent] {
				t.Fatal("MODEL unstarted cleanup graph was not atomically consumed")
			}
			if _, replay := issuer.claim(parent); replay {
				t.Fatal("MODEL unstarted cleanup graph replayed")
			}
			if err := u.consumeRecoveryUnstartedCleanup(parent, op, attempt, now.Add(time.Second)); err != nil {
				t.Fatal("MODEL typed-false source custody rejected", err)
			}
			mutated := labRecoveryStartedCloneObservation(*attempt)
			*mutated.StartObservation.Started = true
			if u.consumeRecoveryUnstartedCleanup(parent, op, &mutated, now.Add(time.Second)) == nil {
				t.Fatal("MODEL mutated started observation reused unstarted custody")
			}
		})
	}
}
