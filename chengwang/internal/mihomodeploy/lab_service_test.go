//go:build linux

package mihomodeploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authn"
)

// Only credential files/authn/authz and the explicitly named Go MODEL child
// are real here. The lifecycle disk/head is synthetic; none of these cases
// proves actual Mihomo, HTTP product execution or a publisher receipt.
func labServiceReadModel(t *testing.T) (*LabService, *labAuthorityFixture, string) {
	t.Helper()
	f := labAuthorityTestFixture(t)
	id := "labop_" + strings.Repeat("a", 32)
	m := labAuthorityTestModelOperation(t, f, id)
	// Read-only backend samples its own current time. Give it a fresh manager,
	// not a fabricated clock callback or a caller Principal.
	manager, err := authn.OpenSnapshotManager(f.path, time.Now().UTC())
	if err != nil {
		t.Fatal("actual manager")
	}
	a, err := newLabAuthority(manager, f.scope)
	if err != nil {
		t.Fatal("actual authority")
	}
	t.Cleanup(func() { _ = a.close(); _ = manager.Close() })
	c := &labServiceCore{scope: f.scope, authority: a, store: m.store, owner: m.owner, base: m.plan.binding.Backup.Artifact, candidate: m.plan.binding.Artifact, sessions: map[string]*labSession{}, observations: map[string]*LabObservationView{}, once: map[string]string{}, gates: map[*labServiceGateEvidenceCore]bool{}}
	return &LabService{core: c}, f, id
}
func TestLabServiceFactoryCannotBootstrapFromMissingManagerOrContext(t *testing.T) {
	if s, e := OpenIsolatedLabService(nil, nil, TargetBinding{}.Scope); e == nil || s != nil {
		t.Fatal("nil context started service")
	}
	if s, e := OpenIsolatedLabService(context.Background(), nil, TargetBinding{}.Scope); e == nil || s != nil {
		t.Fatal("missing manager started service")
	}
}
func TestLabServiceActualReadHeadersAndScopeProtectModelExistence(t *testing.T) {
	s, f, id := labServiceReadModel(t)
	v, e := s.Inspect(context.Background(), f.headers["viewer"], id)
	if e != nil || v.OperationID != id {
		t.Fatal("current real reader rejected")
	}
	for _, h := range [][]string{nil, f.headers["outsider"], {f.headers["viewer"][0], f.headers["viewer"][0]}} {
		if _, e := s.Inspect(context.Background(), h, id); e == nil {
			t.Fatal("unauthenticated or wrongscope existence disclosed")
		}
	}
	f.edit(t, "viewer", func(i *authn.Identity) { i.Disabled = true })
	if _, e := s.Inspect(context.Background(), f.headers["viewer"], id); e == nil {
		t.Fatal("disabled identity read stale snapshot")
	}
}
func TestLabServiceHeadRecoversActualActiveIDWithDetachedPointer(t *testing.T) {
	s, f, id := labServiceReadModel(t)
	v, e := s.Head(context.Background(), f.headers["viewer"])
	if e != nil || v.ActiveOperationID == nil || *v.ActiveOperationID != id {
		t.Fatal("active operation not discoverable")
	}
	*v.ActiveOperationID = "changed"
	again, e := s.Head(context.Background(), f.headers["viewer"])
	if e != nil || again.ActiveOperationID == nil || *again.ActiveOperationID != id {
		t.Fatal("view aliases WAL")
	}
	list, e := s.Candidates(context.Background(), f.headers["viewer"])
	if e != nil || !list.WriteBlocked || len(list.Candidates) != 2 || list.Candidates[0].IsCurrent || list.Candidates[1].IsCurrent {
		t.Fatal("unowned model advertised current runtime")
	}
}
func TestLabServiceReadOnlyModelCannotExecuteOrCreateFromCallerComparisons(t *testing.T) {
	s, f, id := labServiceReadModel(t)
	v, e := s.Inspect(context.Background(), f.headers["viewer"], id)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Create(context.Background(), f.headers["initiator"], LabCreateRequest{CandidateRecordSHA256: s.core.candidate.RecordSHA256, TTLSeconds: 30}); e == nil {
		t.Fatal("unowned head created plan")
	}
	if _, e = s.Execute(context.Background(), f.headers["executor"], id, LabExecuteRequest{PlanSHA256: v.PlanSHA256, Revision: v.Revision}); e == nil {
		t.Fatal("model caller comparison became send permission")
	}
	if len(s.core.once) != 0 || s.core.lastObservedResult != nil {
		t.Fatal("rejected model invented adapter result")
	}
}
func TestLabServiceGateIsOneUseAndCannotMasqueradeAsAdapter(t *testing.T) {
	s, _, owner, _, now := labV2TestArmed(t)
	a := s.record.wire.Active
	intent := a.Intent.IntentSHA256
	c := &labServiceCore{once: map[string]string{intent: "ARMED"}, gates: map[*labServiceGateEvidenceCore]bool{}}
	e := c.mintServiceGate(a, "FINAL_AUTHORIZATION_REJECTED", now)
	if e == nil || c.once[intent] != "BLOCKED" {
		t.Fatal("actual once not blocked")
	}
	if s.recordServiceGate(owner, intent, e, now) != nil {
		t.Fatal("issued model gate rejected")
	}
	r := s.record.wire.Active.Result
	if r == nil || r.Origin != "SERVICE_GATE" || r.ServiceGate == nil || r.Reload.State != mihomo.ReloadRejected || r.Reload.Dispatched || r.Reload.StatusCode != 0 {
		t.Fatal("service gate became adapter ACK")
	}
	if s.recordResult(owner, intent, mihomo.ReloadResult{State: mihomo.ReloadAcknowledged, Dispatched: true, StatusCode: 204}, now) == nil {
		t.Fatal("second adapter result after noDo gate")
	}
	if _, err := e.consumeServiceGate(intent, now); err == nil {
		t.Fatal("gate replay")
	}
}
func TestLabServiceGateCannotBeMintedAfterCallClaimOrRestoredAfterFailedConsume(t *testing.T) {
	s, _, _, _, now := labV2TestArmed(t)
	a := s.record.wire.Active
	intent := a.Intent.IntentSHA256
	c := &labServiceCore{once: map[string]string{intent: "RELOAD_CALL_CLAIMED"}, gates: map[*labServiceGateEvidenceCore]bool{}}
	if c.mintServiceGate(a, "OWNED_IDENTITY_REJECTED", now) != nil {
		t.Fatal("claimed call declared unsent")
	}
	c.once[intent] = "ARMED"
	e := c.mintServiceGate(a, "SERVICE_CONTEXT_CANCELLED", now)
	if e == nil {
		t.Fatal("model gate")
	}
	if _, err := e.consumeServiceGate(strings.Repeat("f", 64), now); err == nil {
		t.Fatal("foreign intent accepted")
	}
	if _, err := e.consumeServiceGate(intent, now); err == nil {
		t.Fatal("failed gate resurrected")
	}
	var restored labServiceGateEvidence
	if json.Unmarshal([]byte(`{"reason":"SERVICE_CONTEXT_CANCELLED"}`), &restored) == nil {
		t.Fatal("JSON restored gate")
	}
}
func TestLabServiceHistoricalCompletedViewUsesArchivedHeadAfterNewPlan(t *testing.T) {
	s, _, owner, p, now := labV2TestCompleted(t)
	old := s.record.wire.V2.Completed[0]
	oldID := old.Active.Plan.OperationID
	newID := "new-model-operation"
	target := lifecycleHeadTarget(*s.record.wire.Head)
	backup, e := newBackupDescriptor(newID, s.record.wire.Head.Artifact, target)
	if e != nil {
		t.Fatal(e)
	}
	next, e := NewPlan(PlanSpec{OperationID: newID, DeclaredInitiatorRef: p.binding.DeclaredInitiatorRef, Target: target, Artifact: p.binding.Backup.Artifact, Backup: backup, ExpiresAt: now.Add(time.Minute)}, now)
	if e != nil || s.recordPlan(owner, next, now) != nil {
		t.Fatal("model next plan")
	}
	c := &labServiceCore{scope: s.record.wire.Head.Scope, store: s, observations: map[string]*LabObservationView{}}
	v, e := c.view(oldID, true)
	if e != nil || v.Phase != "COMPLETED" || v.HeadSHA256 != old.Head.HeadSHA256 || v.Revision != old.CommitRevision || v.Transport == nil || v.Transport.Result.State != mihomo.ReloadAcknowledged || v.Observation == nil || v.Observation.ObservedProjectionSHA256 != nil || !v.Replayed {
		t.Fatal("history lost or current head fabricated")
	}
	t.Run("terminated-gate-history", func(t *testing.T) {
		s, _, owner, p, now := labV2TestArmed(t)
		active := s.record.wire.Active
		oldID := active.Plan.OperationID
		intent := active.Intent.IntentSHA256
		model := &labServiceCore{scope: s.record.wire.Head.Scope, store: s, once: map[string]string{intent: "ARMED"}, gates: map[*labServiceGateEvidenceCore]bool{}, observations: map[string]*LabObservationView{}}
		proof := model.mintServiceGate(active, "SERVICE_CONTEXT_CANCELLED", now)
		if s.recordServiceGate(owner, intent, proof, now) != nil {
			t.Fatal("model noDo result")
		}
		archive := s.record.wire.V2.Terminated[0]
		target := lifecycleHeadTarget(*s.record.wire.Head)
		backup, e := newBackupDescriptor("following-model", s.record.wire.Head.Artifact, target)
		if e != nil {
			t.Fatal(e)
		}
		next, e := NewPlan(PlanSpec{OperationID: "following-model", DeclaredInitiatorRef: p.binding.DeclaredInitiatorRef, Target: target, Artifact: p.binding.Artifact, Backup: backup, ExpiresAt: now.Add(time.Minute)}, now)
		if e != nil || s.recordPlan(owner, next, now) != nil {
			t.Fatal("model next after gate")
		}
		v, e := model.view(oldID, true)
		if e != nil || v.Phase != "UNSENT_REJECTED" || v.Revision != archive.CommitRevision || v.HeadSHA256 != archive.Head.HeadSHA256 || v.Transport == nil || v.Transport.Origin != "SERVICE_GATE" || v.Transport.GateReason == nil || *v.Transport.GateReason != "SERVICE_CONTEXT_CANCELLED" {
			t.Fatal("terminated fact lost after new plan")
		}
	})
}
func TestLabServiceUnknownPreservesOriginalTransportAndBlocksNewWrites(t *testing.T) {
	s, _, owner, _, now := labV2TestArmed(t)
	intent := s.record.wire.Active.Intent.IntentSHA256
	if s.recordResult(owner, intent, mihomo.ReloadResult{State: mihomo.ReloadAcknowledged, Dispatched: true, StatusCode: 204}, now) != nil {
		t.Fatal("model ACK")
	}
	raw := append([]byte(nil), s.raw...)
	disk := &lifecycleModelDisk{raw: raw, exists: true, state: lifecycleCommitted}
	reopened, e := openLifecycleStore(disk)
	if e != nil {
		t.Fatal("model reopen")
	}
	c := &labServiceCore{scope: reopened.record.wire.Head.Scope, store: reopened, observations: map[string]*LabObservationView{}}
	v, e := c.view(reopened.record.wire.Active.Plan.OperationID, false)
	if e != nil || v.Phase != "UNKNOWN" || !v.WriteBlocked || v.HeadAdvanced || v.Transport == nil || v.Transport.Result.State != mihomo.ReloadAcknowledged {
		t.Fatal("UNKNOWN rewrote original ACK or unlocked")
	}
	if _, e := reopened.acquireOwner(now.Add(time.Hour), now.Add(2*time.Hour)); e == nil {
		t.Fatal("elapsed lease unlocked unknown")
	}
	t.Run("response_rejected_barrier", func(t *testing.T) {
		// The actual child is the Go MODEL listener process; the WAL and 403
		// result are structural MODEL facts, never a real Mihomo response.
		_, k := labCollectorModelEvidence(t)
		s, _, owner, _, now := labV2TestArmed(t)
		intent := s.record.wire.Active.Intent.IntentSHA256
		if s.recordResult(owner, intent, mihomo.ReloadResult{State: mihomo.ReloadRejected, Dispatched: true, StatusCode: 403}, now) != nil {
			t.Fatal("model rejected result")
		}
		c := &labServiceCore{ready: true, kernel: k, scope: s.record.wire.Head.Scope, store: s, observations: map[string]*LabObservationView{}}
		if !c.blocked(s.record.wire) {
			t.Fatal("sent rejected phase advertised writable")
		}
		v, err := c.view(s.record.wire.Active.Plan.OperationID, false)
		if err != nil || !v.WriteBlocked || v.Phase != "RESPONSE_REJECTED" {
			t.Fatal("API view disagrees with durable barrier")
		}
	})
}
func TestLabServiceCloseRetainsUncertainOwnedHandleUntilActualModelWait(t *testing.T) {
	in, ops := labKernelModelFixture(t, "quiet")
	gate := make(chan struct{})
	ops.waitGate = gate
	var release sync.Once
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	k, e := startLabKernelWith(ctx, in, labKernelModelArtifact(t), ops)
	if e != nil {
		cancel()
		t.Fatal("MODEL start")
	}
	defer func() { release.Do(func() { close(gate) }); cancel(); _, _ = k.stop(context.Background()) }()
	s := &LabService{core: &labServiceCore{kernel: k}}
	for i := 0; i < 2; i++ {
		closeCtx, end := context.WithTimeout(context.Background(), 3*time.Second)
		err := s.Close(closeCtx)
		end()
		if err == nil || s.core.closed || s.core.kernel != k || s.core.kernelSettled {
			t.Fatal("unknown stop became successful close")
		}
	}
	release.Do(func() { close(gate) })
	select {
	case <-k.done:
	case <-time.After(3 * time.Second):
		t.Fatal("MODEL Wait did not finish")
	}
	if s.Close(context.Background()) != nil || !s.core.closed || !s.core.kernelSettled {
		t.Fatal("actual Wait did not permit settled close")
	}
}
func TestLabServiceStickyCleanupUncertaintyNeverBecomesSecondSuccess(t *testing.T) {
	s := &LabService{core: &labServiceCore{closeUncertain: true, closing: true}}
	for i := 0; i < 2; i++ {
		if s.Close(context.Background()) == nil || s.core.closed {
			t.Fatal("uncertain cleanup hidden by idempotency")
		}
	}
}
func TestLabServiceUnprovenSyntaxCleanupRetainsObservationAndBlocksClose(t *testing.T) {
	// This is immutable MODEL metadata, not a forged success boolean. The
	// missing group observation must keep an otherwise reaped child uncertain.
	yes := true
	pid := 30001
	observation := &labSyntaxCleanupObservation{core: &labSyntaxCleanupCore{process: &os.Process{Pid: pid}, observation: labKernelStartObservation{Attempted: true, Started: &yes, PID: &pid, WaitReturned: &yes, WaitErrorClass: "EXIT_STATUS", Stdout: &labKernelStream{Complete: true, SHA256: labConfigHash(nil)}, Stderr: &labKernelStream{Complete: true, SHA256: labConfigHash(nil)}}}}
	s := &LabService{core: &labServiceCore{syntaxObservations: []*labSyntaxCleanupObservation{observation}}}
	for i := 0; i < 2; i++ {
		if s.Close(context.Background()) == nil || s.core.closed || s.core.syntaxObservations[0] != observation {
			t.Fatal("syntax cleanup observation discarded by Close")
		}
	}
}
func TestLabServiceIdleExpiryReacquiresOnlyEmptyOrArchivedTerminalOwner(t *testing.T) {
	// MODEL time is advanced as data; no actual sleep, auth bypass or PUT.
	t.Run("empty", func(t *testing.T) {
		r, _, now := labV2TestRecord(t)
		s, _ := lifecycleTestOpen(t, r)
		owner := lifecycleTestOwner(t, s, now)
		fence := owner.fence
		c := &labServiceCore{scope: r.wire.Head.Scope, store: s, owner: owner}
		if c.ensureOwner(now.Add(time.Hour)) != nil || c.owner == owner || c.owner.fence != fence+1 || s.record.wire.Active != nil {
			t.Fatal("idle empty owner failed to reacquire")
		}
	})
	t.Run("archived_terminal", func(t *testing.T) {
		s, _, owner, _, now := labV2TestCompleted(t)
		fence := owner.fence
		history := len(s.record.wire.V2.Completed)
		c := &labServiceCore{scope: s.record.wire.Head.Scope, store: s, owner: owner}
		if c.ensureOwner(now.Add(time.Hour)) != nil || c.owner.fence != fence+1 || len(s.record.wire.V2.Completed) != history || s.record.wire.Active != nil {
			t.Fatal("terminal history lost or idle lease stuck")
		}
	})
	for _, phase := range []string{"PREPARED", "UNKNOWN", "RESPONSE_REJECTED"} {
		t.Run(phase, func(t *testing.T) {
			var s *lifecycleStore
			var d *lifecycleModelDisk
			var owner *lifecycleOwnerToken
			var now time.Time
			if phase == "PREPARED" {
				s, d, owner, _, now = labV2TestPrepared(t)
			} else {
				s, d, owner, _, now = labV2TestArmed(t)
				result := mihomo.ReloadResult{State: mihomo.ReloadUnknown, Dispatched: true}
				if phase == "RESPONSE_REJECTED" {
					result = mihomo.ReloadResult{State: mihomo.ReloadRejected, Dispatched: true, StatusCode: 403}
				}
				if s.recordResult(owner, s.record.wire.Active.Intent.IntentSHA256, result, now) != nil {
					t.Fatal("model outcome")
				}
			}
			writes := d.writes
			fence := owner.fence
			c := &labServiceCore{scope: s.record.wire.Head.Scope, store: s, owner: owner}
			if c.ensureOwner(now.Add(time.Hour)) == nil || d.writes != writes || c.owner.fence != fence || s.record.wire.Active.Phase != phase {
				t.Fatal("TTL revived unresolved operation")
			}
		})
	}
}
func TestLabServiceDiagnosticReopenCannotCrossTenantOrSite(t *testing.T) {
	s, f, id := labServiceReadModel(t)
	if !s.DiagnosticReady() {
		t.Fatal("verified model diagnostic store rejected")
	}
	s.core.scope.SiteID = "another-site"
	if s.DiagnosticReady() {
		t.Fatal("changed startup scope read old state")
	}
	if _, err := s.Inspect(context.Background(), f.headers["viewer"], id); err == nil {
		t.Fatal("cross-scope state disclosed")
	}
	s.core.scope = f.scope
	s.core.store.disk.(*lifecycleModelDisk).verifyErr = errLifecycleUnsafe
	if s.DiagnosticReady() {
		t.Fatal("unsafe storage advertised diagnostic ready")
	}
}

type labServiceNilContext struct{ context.Context }

func TestLabServiceTypedNilContextCannotPanicOrStartWork(t *testing.T) {
	var ctx *labServiceNilContext
	s, f, id := labServiceReadModel(t)
	if _, e := OpenIsolatedLabService(ctx, f.manager, f.scope); e == nil {
		t.Fatal("typed nil factory context")
	}
	if _, e := s.Inspect(ctx, f.headers["viewer"], id); e == nil {
		t.Fatal("typed nil inspect")
	}
	if _, e := s.Head(ctx, f.headers["viewer"]); e == nil {
		t.Fatal("typed nil head")
	}
	if _, e := s.Execute(ctx, f.headers["executor"], id, LabExecuteRequest{}); e == nil {
		t.Fatal("typed nil execute")
	}
	if e := s.Close(ctx); e == nil || s.core.closing {
		t.Fatal("typed nil cleanup started work")
	}
}
func TestLabServiceActualClientReturnAndPoisonedModelWALNeverClaimsUnchanged(t *testing.T) {
	// This is an actual loopback HTTP client call to a MODEL server, not Mihomo.
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if r.Method != "PUT" || r.URL.Path != "/configs" || r.URL.RawQuery != "force=true" {
			t.Error("client request shape")
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	writer, e := mihomo.NewWriteClient(server.URL, "MODEL-private-controller", time.Second)
	if e != nil {
		t.Fatal("MODEL writer")
	}
	result, e := writer.Reload(context.Background(), []byte("MODEL input"))
	if e != nil || count.Load() != 1 || result.State != mihomo.ReloadAcknowledged {
		t.Fatal("actual MODEL client call")
	}
	s, f, id := labServiceReadModel(t)
	s.core.lastObservedResult = &result
	s.core.store.disk.(*lifecycleModelDisk).verifyErr = errLifecycleUnsafe
	_, err := s.core.completedView(f.headers["viewer"], id)
	var safe *LabBackendError
	if !errors.As(err, &safe) || !safe.StateMayHaveChanged {
		t.Fatal("post-client failure claimed unchanged")
	}
	if _, err = s.Execute(context.Background(), f.headers["executor"], id, LabExecuteRequest{PlanSHA256: strings.Repeat("a", 64), Revision: 1}); err == nil {
		t.Fatal("poisoned WAL allowed replay")
	}
	if count.Load() != 1 {
		t.Fatal("second client call after uncertainty")
	}
}
func TestLabServiceClockAndStorageFailureAreUnavailableNotPermissionDenial(t *testing.T) {
	for _, code := range []string{"clock_invalid", "authority_closed", "authority_unavailable", "wal_unavailable"} {
		var e *LabBackendError
		if !errors.As(labServiceAuthError(labAuthorityFailure(code)), &e) || e.Code != LabBackendUnavailable {
			t.Fatal("infrastructure misclassified as permission")
		}
	}
	var e *LabBackendError
	if !errors.As(labServiceAuthError(labAuthorityFailure("authorization_denied")), &e) || e.Code != LabBackendForbidden {
		t.Fatal("permission gate relaxed")
	}
}
func TestLabServiceDebugPointerValueAndJSONHideCoreAndGateFacts(t *testing.T) {
	secret := "private-core-operation"
	s := LabService{core: &labServiceCore{stages: map[string]string{secret: "private-stage"}}}
	g := labServiceGateEvidence{core: &labServiceGateEvidenceCore{fact: labServiceGateFact{OperationID: secret}}}
	for _, v := range []any{s, &s, g, &g, (*LabService)(nil), (*labServiceGateEvidence)(nil)} {
		raw, _ := json.Marshal(v)
		formatted := fmt.Sprintf("%v %+v %#v %s %d %x %p", v, v, v, v, v, v, v)
		if strings.Contains(formatted, secret) || strings.Contains(string(raw), secret) || strings.Contains(formatted, "private-stage") {
			t.Fatal("private service detail escaped")
		}
	}
}
