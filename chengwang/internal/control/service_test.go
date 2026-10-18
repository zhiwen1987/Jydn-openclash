package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/operation"
)

var fixedNow = time.Date(2026, 10, 18, 7, 30, 0, 0, time.UTC)

type fakeEvidence struct {
	mu         sync.Mutex
	records    map[string]evidence.EvidenceEvent
	failAction map[string]int
	calls      []evidence.EvidenceEvent
}

func newFakeEvidence() *fakeEvidence {
	return &fakeEvidence{
		records:    make(map[string]evidence.EvidenceEvent),
		failAction: make(map[string]int),
	}
}

func (f *fakeEvidence) AppendOnce(event evidence.EvidenceEvent, key string) (evidence.EvidenceEvent, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, event)
	if f.failAction[event.Action] > 0 {
		f.failAction[event.Action]--
		return evidence.EvidenceEvent{}, false, errors.New("simulated evidence outage")
	}
	if existing, ok := f.records[key]; ok {
		if !sameSemanticEvidence(existing, event) {
			return evidence.EvidenceEvent{}, false, evidence.ErrIdempotencyConflict
		}
		return existing, false, nil
	}
	f.records[key] = event
	return event, true, nil
}

func sameSemanticEvidence(left, right evidence.EvidenceEvent) bool {
	left.ID, right.ID = "", ""
	left.Hash, right.Hash = "", ""
	left.PreviousHash, right.PreviousHash = "", ""
	left.OccurredAt, right.OccurredAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(left, right)
}

func newTestService(t *testing.T, appender *fakeEvidence) (*Service, *operation.MemoryStore) {
	t.Helper()
	store := operation.NewMemoryStore()
	service, err := New(store, appender)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	service.now = func() time.Time { return fixedNow }
	return service, store
}

func testScope() authz.ResourceScope {
	return authz.ResourceScope{
		TenantID:    "tenant-a",
		SiteID:      "site-1",
		ObjectType:  "router",
		ObjectID:    "edge-1",
		Environment: "production",
	}
}

func testPrincipal(id string, role authz.Role) authz.Principal {
	return authz.Principal{
		ID:            id,
		TenantID:      "tenant-a",
		Roles:         []authz.Role{role},
		AllowedScopes: []authz.ResourceScope{{TenantID: "tenant-a", SiteID: "site-1"}},
	}
}

func testCreate(principal authz.Principal, risk authz.Risk, key string) CreateRequest {
	return CreateRequest{
		Principal:      principal,
		Resource:       testScope(),
		Risk:           risk,
		TargetVersion:  "version-42",
		IdempotencyKey: key,
		TraceID:        "trace-request-1",
	}
}

func testTransition(principal authz.Principal, id string, to operation.Status, key string) TransitionRequest {
	return TransitionRequest{
		Principal:      principal,
		Resource:       testScope(),
		OperationID:    id,
		To:             to,
		IdempotencyKey: key,
		TraceID:        "trace-request-2",
	}
}

func serviceCode(t *testing.T, err error, want ErrorCode) *ServiceError {
	t.Helper()
	var serviceErr *ServiceError
	if !errors.As(err, &serviceErr) {
		t.Fatalf("error = %v, want *ServiceError", err)
	}
	if serviceErr.Code != want {
		t.Fatalf("error code = %q, want %q", serviceErr.Code, want)
	}
	return serviceErr
}

func TestNewRequiresDependencies(t *testing.T) {
	appender := newFakeEvidence()
	if _, err := New(nil, appender); err == nil {
		t.Fatal("New(nil, evidence) succeeded")
	}
	if _, err := New(operation.NewMemoryStore(), nil); err == nil {
		t.Fatal("New(store, nil) succeeded")
	}
}

func TestCreateDeniesBeforeStoreAndEvidence(t *testing.T) {
	appender := newFakeEvidence()
	service, store := newTestService(t, appender)
	principal := testPrincipal("viewer-1", authz.RoleViewer)

	result, err := service.Create(testCreate(principal, authz.RiskLow, "denied-create"))
	denied := serviceCode(t, err, CodeAuthorizationDenied)
	if denied.AuthzReason != authz.ReasonDenyRoleNotPermitted {
		t.Fatalf("reason = %q", denied.AuthzReason)
	}
	if result.Outcome != OutcomeRejected {
		t.Fatalf("denied outcome = %q", result.Outcome)
	}
	if got := len(store.List()); got != 0 {
		t.Fatalf("stored operations = %d, want 0", got)
	}
	if got := len(appender.calls); got != 0 {
		t.Fatalf("evidence calls = %d, want 0", got)
	}
}

func TestCreateEnforcesResourceScope(t *testing.T) {
	appender := newFakeEvidence()
	service, store := newTestService(t, appender)
	req := testCreate(testPrincipal("operator-1", authz.RoleOperator), authz.RiskLow, "wrong-scope")
	req.Resource.SiteID = "site-2"

	_, err := service.Create(req)
	denied := serviceCode(t, err, CodeAuthorizationDenied)
	if denied.AuthzReason != authz.ReasonDenyScopeMismatch {
		t.Fatalf("reason = %q", denied.AuthzReason)
	}
	if len(store.List()) != 0 {
		t.Fatal("scope-denied create reached operation store")
	}
}

func TestCreateRecordsOnlyOpaqueSafeEvidence(t *testing.T) {
	appender := newFakeEvidence()
	service, _ := newTestService(t, appender)
	req := testCreate(testPrincipal("operator-1", authz.RoleOperator), authz.RiskLow, "raw-idempotency-value")
	req.TargetVersion = "must-not-appear-in-evidence"

	result, err := service.Create(req)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !result.Created || !result.AuditRecorded || result.Outcome != OutcomePlanned {
		t.Fatalf("Create() = %+v", result)
	}
	if result.Operation.Status != operation.StatusPlanned {
		t.Fatalf("status = %q", result.Operation.Status)
	}
	if result.Operation.Scope == "" || strings.Contains(result.Operation.Scope, req.Resource.ObjectID) {
		t.Fatalf("scope is not opaque: %q", result.Operation.Scope)
	}

	var recorded evidence.EvidenceEvent
	for _, event := range appender.records {
		if event.Action == "operation.create.result" {
			recorded = event
		}
	}
	encoded, _ := json.Marshal(recorded)
	for _, forbidden := range []string{req.IdempotencyKey, req.TargetVersion, req.Resource.ObjectID, "token", "body"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("evidence contains forbidden value %q: %s", forbidden, encoded)
		}
	}
	if recorded.Action != "operation.create.result" || recorded.Result != "planned" {
		t.Fatalf("event = %+v", recorded)
	}
	if recorded.Data["operationId"] != result.Operation.ID || recorded.Data["idempotencyDigest"] == "" {
		t.Fatalf("event data = %+v", recorded.Data)
	}
}

func TestCreateAuditFailureLeavesPlannedAndRetryRepairsEvidence(t *testing.T) {
	appender := newFakeEvidence()
	appender.failAction["operation.create.result"] = 1
	service, store := newTestService(t, appender)
	req := testCreate(testPrincipal("operator-1", authz.RoleOperator), authz.RiskLow, "create-retry")

	first, err := service.Create(req)
	degraded := serviceCode(t, err, CodeAuditDegraded)
	if !degraded.Partial || first.Outcome != OutcomeAuditDegraded || first.Operation.Status != operation.StatusPlanned {
		t.Fatalf("first = %+v, error = %+v", first, degraded)
	}

	second, err := service.Create(req)
	if err != nil {
		t.Fatalf("retry error = %v", err)
	}
	if second.Created || !second.AuditRecorded || second.Operation.ID != first.Operation.ID {
		t.Fatalf("retry = %+v", second)
	}
	if got := len(store.List()); got != 1 {
		t.Fatalf("operations = %d, want 1", got)
	}
	if got := len(appender.records); got != 2 {
		t.Fatalf("evidence records = %d, want 2", got)
	}
}

func TestCreatePreEvidenceFailureCannotMutateState(t *testing.T) {
	appender := newFakeEvidence()
	appender.failAction["operation.create.pre"] = 1
	service, store := newTestService(t, appender)

	result, err := service.Create(testCreate(testPrincipal("operator-1", authz.RoleOperator), authz.RiskLow, "create-pre-failure"))
	degraded := serviceCode(t, err, CodeAuditDegraded)
	if degraded.Partial || result.Outcome != OutcomeAuditDegraded {
		t.Fatalf("result = %+v, error = %+v", result, degraded)
	}
	if got := len(store.List()); got != 0 {
		t.Fatalf("pre-evidence failure created %d operations", got)
	}
}

func TestCreateIdempotencyCannotChangeInitiator(t *testing.T) {
	appender := newFakeEvidence()
	service, store := newTestService(t, appender)
	first := testCreate(testPrincipal("operator-1", authz.RoleOperator), authz.RiskLow, "identity-bound-create")
	created, err := service.Create(first)
	if err != nil {
		t.Fatal(err)
	}
	forged := first
	forged.Principal = testPrincipal("operator-2", authz.RoleOperator)
	result, err := service.Create(forged)
	serviceCode(t, err, CodeIdempotencyConflict)
	if result.Outcome != OutcomeRejected {
		t.Fatalf("forged replay outcome = %q", result.Outcome)
	}
	persisted, _ := store.Get(created.Operation.ID)
	if persisted.InitiatorID != "operator-1" || len(store.List()) != 1 {
		t.Fatalf("forged replay changed initiator: %+v", persisted)
	}
}

func TestTransitionPreEvidenceFailureDoesNotChangeState(t *testing.T) {
	appender := newFakeEvidence()
	service, store := newTestService(t, appender)
	principal := testPrincipal("operator-1", authz.RoleOperator)
	created, err := service.Create(testCreate(principal, authz.RiskLow, "pre-create"))
	if err != nil {
		t.Fatal(err)
	}
	appender.failAction["operation.transition.pre"] = 1

	request := testTransition(principal, created.Operation.ID, operation.StatusPrechecking, "pre-fails")
	result, err := service.Transition(request)
	degraded := serviceCode(t, err, CodeAuditDegraded)
	if degraded.Partial {
		t.Fatal("pre-evidence failure incorrectly marked partial mutation")
	}
	if result.Outcome != OutcomeAuditDegraded {
		t.Fatalf("outcome = %q", result.Outcome)
	}
	stored, _ := store.Get(created.Operation.ID)
	if stored.Status != operation.StatusPlanned || len(stored.Events) != 1 {
		t.Fatalf("operation mutated: %+v", stored)
	}
}

func TestTransitionResultEvidenceFailureIsPartialAndRetryDoesNotReapply(t *testing.T) {
	appender := newFakeEvidence()
	service, store := newTestService(t, appender)
	principal := testPrincipal("operator-1", authz.RoleOperator)
	created, err := service.Create(testCreate(principal, authz.RiskLow, "result-create"))
	if err != nil {
		t.Fatal(err)
	}
	appender.failAction["operation.transition.result"] = 1
	request := testTransition(principal, created.Operation.ID, operation.StatusPrechecking, "result-retry")

	first, err := service.Transition(request)
	degraded := serviceCode(t, err, CodeAuditDegraded)
	if !degraded.Partial || !first.Applied || first.Outcome != OutcomeAuditDegraded {
		t.Fatalf("first = %+v, error = %+v", first, degraded)
	}
	stored, _ := store.Get(created.Operation.ID)
	if stored.Status != operation.StatusPrechecking || len(stored.Events) != 2 {
		t.Fatalf("stored after partial = %+v", stored)
	}

	second, err := service.Transition(request)
	if err != nil {
		t.Fatalf("retry error = %v", err)
	}
	if second.Applied || !second.Replayed || !second.AuditRecorded || second.Outcome != OutcomeTransitioned {
		t.Fatalf("retry = %+v", second)
	}
	stored, _ = store.Get(created.Operation.ID)
	if len(stored.Events) != 2 {
		t.Fatalf("retry applied transition twice: %+v", stored.Events)
	}
	if got := len(appender.records); got != 4 { // create pre/result, transition pre/result
		t.Fatalf("evidence records = %d, want 4", got)
	}
}

func TestTransitionReplayWithDifferentTargetConflicts(t *testing.T) {
	appender := newFakeEvidence()
	service, _ := newTestService(t, appender)
	principal := testPrincipal("operator-1", authz.RoleOperator)
	created, err := service.Create(testCreate(principal, authz.RiskLow, "conflict-create"))
	if err != nil {
		t.Fatal(err)
	}
	req := testTransition(principal, created.Operation.ID, operation.StatusPrechecking, "same-transition-key")
	if _, err := service.Transition(req); err != nil {
		t.Fatal(err)
	}
	req.To = operation.StatusFailed
	_, err = service.Transition(req)
	serviceCode(t, err, CodeIdempotencyConflict)
}

func TestTransitionHighAndCriticalSeparationOfDuty(t *testing.T) {
	t.Run("high risk self approval denied", func(t *testing.T) {
		appender := newFakeEvidence()
		service, _ := newTestService(t, appender)
		admin := testPrincipal("admin-1", authz.RoleAdmin)
		created, err := service.Create(testCreate(admin, authz.RiskHigh, "high-create"))
		if err != nil {
			t.Fatal(err)
		}
		await := testTransition(admin, created.Operation.ID, operation.StatusAwaitingApproval, "high-await")
		if _, err := service.Transition(await); err != nil {
			t.Fatal(err)
		}
		approve := testTransition(admin, created.Operation.ID, operation.StatusPrechecking, "high-approve-self")
		_, err = service.Transition(approve)
		denied := serviceCode(t, err, CodeAuthorizationDenied)
		if denied.AuthzReason != authz.ReasonDenySelfApproval {
			t.Fatalf("reason = %q", denied.AuthzReason)
		}

		approver := testPrincipal("approver-2", authz.RoleApprover)
		approve.Principal = approver
		approve.IdempotencyKey = "high-approve-other"
		appender.failAction["operation.transition.result"] = 1
		first, err := service.Transition(approve)
		degraded := serviceCode(t, err, CodeAuditDegraded)
		if !degraded.Partial || !first.Applied {
			t.Fatalf("approval partial result = %+v, error = %+v", first, degraded)
		}
		second, err := service.Transition(approve)
		if err != nil {
			t.Fatalf("independent approval retry error = %v", err)
		}
		if !second.Replayed || !second.AuditRecorded {
			t.Fatalf("approval retry = %+v", second)
		}
	})

	t.Run("critical execution needs independent approval", func(t *testing.T) {
		appender := newFakeEvidence()
		service, _ := newTestService(t, appender)
		admin := testPrincipal("admin-1", authz.RoleAdmin)
		created, err := service.Create(testCreate(admin, authz.RiskCritical, "critical-create"))
		if err != nil {
			t.Fatal(err)
		}
		toPrecheck := testTransition(admin, created.Operation.ID, operation.StatusPrechecking, "critical-precheck-denied")
		_, err = service.Transition(toPrecheck)
		denied := serviceCode(t, err, CodeAuthorizationDenied)
		if denied.AuthzReason != authz.ReasonDenyIndependentApprovalRequired {
			t.Fatalf("reason = %q", denied.AuthzReason)
		}
		await := testTransition(admin, created.Operation.ID, operation.StatusAwaitingApproval, "critical-await")
		if _, err := service.Transition(await); err != nil {
			t.Fatal(err)
		}
		selfApprove := testTransition(admin, created.Operation.ID, operation.StatusPrechecking, "critical-self-approve")
		_, err = service.Transition(selfApprove)
		denied = serviceCode(t, err, CodeAuthorizationDenied)
		if denied.AuthzReason != authz.ReasonDenySelfApproval {
			t.Fatalf("self approval reason = %q", denied.AuthzReason)
		}
		approver := testPrincipal("approver-2", authz.RoleApprover)
		approve := testTransition(approver, created.Operation.ID, operation.StatusPrechecking, "critical-independent-approve")
		approved, err := service.Transition(approve)
		if err != nil {
			t.Fatalf("approved critical transition error = %v", err)
		}
		if approved.Operation.ApprovedByID != approver.ID {
			t.Fatalf("approval identity not persisted: %+v", approved.Operation)
		}
		execute := testTransition(admin, created.Operation.ID, operation.StatusExecuting, "critical-execute")
		if _, err := service.Transition(execute); err != nil {
			t.Fatalf("critical execute with persisted approval error = %v", err)
		}
	})
}

func TestTransitionUsesPersistedIdentityAndSurvivesRestart(t *testing.T) {
	directory := t.TempDir()
	store, err := operation.NewFileStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	appender := newFakeEvidence()
	service, err := New(store, appender)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return fixedNow }
	initiator := testPrincipal("initiator-real", authz.RoleAdmin)
	created, err := service.Create(testCreate(initiator, authz.RiskCritical, "restart-identity-create"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Transition(testTransition(initiator, created.Operation.ID, operation.StatusAwaitingApproval, "restart-await")); err != nil {
		t.Fatal(err)
	}
	approver := testPrincipal("approver-real", authz.RoleApprover)
	if _, err := service.Transition(testTransition(approver, created.Operation.ID, operation.StatusPrechecking, "restart-approve")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := operation.NewFileStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted, err := New(reopened, appender)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return fixedNow }
	persisted, err := reopened.Get(created.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.InitiatorID != initiator.ID || persisted.ApprovedByID != approver.ID {
		t.Fatalf("persisted identities = %+v", persisted)
	}
	if _, err := restarted.Transition(testTransition(initiator, persisted.ID, operation.StatusExecuting, "restart-execute")); err != nil {
		t.Fatalf("execute after restart error = %v", err)
	}
}

func TestRealEvidenceStoreAcceptsBoundedControlKeys(t *testing.T) {
	evidenceStore, err := evidence.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer evidenceStore.Close()
	service, err := New(operation.NewMemoryStore(), evidenceStore)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return fixedNow }
	principal := testPrincipal("operator-1", authz.RoleOperator)
	created, err := service.Create(testCreate(principal, authz.RiskLow, strings.Repeat("k", 200)))
	if err != nil {
		t.Fatalf("create with real evidence store: %v", err)
	}
	if _, err := service.Transition(testTransition(principal, created.Operation.ID, operation.StatusPrechecking, strings.Repeat("t", 200))); err != nil {
		t.Fatalf("transition with real evidence store: %v", err)
	}
	report, err := evidenceStore.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !report.Valid || report.Count != 4 {
		t.Fatalf("verify report = %+v, want four valid events", report)
	}
}

func TestConcurrentTransitionWithSameKeyAppliesOnce(t *testing.T) {
	appender := newFakeEvidence()
	service, store := newTestService(t, appender)
	principal := testPrincipal("operator-1", authz.RoleOperator)
	created, err := service.Create(testCreate(principal, authz.RiskLow, "concurrent-create"))
	if err != nil {
		t.Fatal(err)
	}
	req := testTransition(principal, created.Operation.ID, operation.StatusPrechecking, "concurrent-transition")

	const workers = 16
	results := make(chan TransitionResult, workers)
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, transitionErr := service.Transition(req)
			results <- result
			errorsFound <- transitionErr
		}()
	}
	wait.Wait()
	close(results)
	close(errorsFound)
	for transitionErr := range errorsFound {
		if transitionErr != nil {
			t.Errorf("concurrent transition error = %v", transitionErr)
		}
	}
	applied := 0
	for result := range results {
		if result.Applied {
			applied++
		}
	}
	if applied != 1 {
		t.Fatalf("applied results = %d, want 1", applied)
	}
	stored, _ := store.Get(created.Operation.ID)
	if len(stored.Events) != 2 || stored.Status != operation.StatusPrechecking {
		t.Fatalf("stored = %+v", stored)
	}
}

func TestConcurrentIndependentApproversBindExactlyOneIdentity(t *testing.T) {
	appender := newFakeEvidence()
	service, store := newTestService(t, appender)
	initiator := testPrincipal("admin-1", authz.RoleAdmin)
	created, err := service.Create(testCreate(initiator, authz.RiskCritical, "concurrent-approval-create"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Transition(testTransition(initiator, created.Operation.ID, operation.StatusAwaitingApproval, "concurrent-approval-await")); err != nil {
		t.Fatal(err)
	}

	approvers := []authz.Principal{
		testPrincipal("approver-1", authz.RoleApprover),
		testPrincipal("approver-2", authz.RoleApprover),
	}
	var wait sync.WaitGroup
	wins := make(chan string, len(approvers))
	for index, approver := range approvers {
		wait.Add(1)
		go func(index int, approver authz.Principal) {
			defer wait.Done()
			request := testTransition(approver, created.Operation.ID, operation.StatusPrechecking, "concurrent-approval-"+string(rune('a'+index)))
			if result, transitionErr := service.Transition(request); transitionErr == nil && result.Applied {
				wins <- approver.ID
			}
		}(index, approver)
	}
	wait.Wait()
	close(wins)
	var winner string
	for id := range wins {
		if winner != "" {
			t.Fatalf("multiple approval winners: %q and %q", winner, id)
		}
		winner = id
	}
	if winner == "" {
		t.Fatal("no approval winner")
	}
	persisted, _ := store.Get(created.Operation.ID)
	if persisted.ApprovedByID != winner || persisted.ApprovedByID == persisted.InitiatorID {
		t.Fatalf("persisted approval = %+v, winner = %q", persisted, winner)
	}
}

func TestTransitionResourceMustMatchPersistedScope(t *testing.T) {
	appender := newFakeEvidence()
	service, store := newTestService(t, appender)
	principal := testPrincipal("operator-1", authz.RoleOperator)
	created, err := service.Create(testCreate(principal, authz.RiskLow, "scope-create"))
	if err != nil {
		t.Fatal(err)
	}
	req := testTransition(principal, created.Operation.ID, operation.StatusPrechecking, "scope-transition")
	req.Resource.ObjectID = "different-router"

	_, err = service.Transition(req)
	serviceCode(t, err, CodeScopeMismatch)
	stored, _ := store.Get(created.Operation.ID)
	if stored.Status != operation.StatusPlanned {
		t.Fatalf("scope mismatch changed state to %q", stored.Status)
	}
}

func TestTerminalOperationRemainsFrozen(t *testing.T) {
	appender := newFakeEvidence()
	service, store := newTestService(t, appender)
	principal := testPrincipal("operator-1", authz.RoleOperator)
	created, err := service.Create(testCreate(principal, authz.RiskLow, "terminal-create"))
	if err != nil {
		t.Fatal(err)
	}
	fail := testTransition(principal, created.Operation.ID, operation.StatusFailed, "terminal-fail")
	if _, err := service.Transition(fail); err != nil {
		t.Fatal(err)
	}

	revive := testTransition(principal, created.Operation.ID, operation.StatusPrechecking, "terminal-revive")
	result, err := service.Transition(revive)
	serviceCode(t, err, CodeTransitionConflict)
	if !result.AuditRecorded || result.Outcome != OutcomeRejected {
		t.Fatalf("terminal rejection result = %+v", result)
	}
	stored, _ := store.Get(created.Operation.ID)
	if stored.Status != operation.StatusFailed || len(stored.Events) != 2 {
		t.Fatalf("terminal operation changed: %+v", stored)
	}
}

type failFirstTransitionStore struct {
	*operation.MemoryStore
	failed bool
}

func (s *failFirstTransitionStore) TransitionWithApproval(id string, to operation.Status, reason, approverID string) (operation.Operation, error) {
	if !s.failed {
		s.failed = true
		return operation.Operation{}, errors.New("temporary persistence failure")
	}
	return s.MemoryStore.TransitionWithApproval(id, to, reason, approverID)
}

func TestTransitionRetryAfterStoreFailureRecordsRejectedAndAppliedEvidence(t *testing.T) {
	appender := newFakeEvidence()
	store := &failFirstTransitionStore{MemoryStore: operation.NewMemoryStore()}
	service, err := New(store, appender)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return fixedNow }
	principal := testPrincipal("operator-1", authz.RoleOperator)
	created, err := service.Create(testCreate(principal, authz.RiskLow, "transient-create"))
	if err != nil {
		t.Fatal(err)
	}
	req := testTransition(principal, created.Operation.ID, operation.StatusPrechecking, "transient-transition")

	first, err := service.Transition(req)
	serviceCode(t, err, CodeOperationStore)
	if first.Outcome != OutcomeRejected || !first.AuditRecorded {
		t.Fatalf("first result = %+v", first)
	}

	second, err := service.Transition(req)
	if err != nil {
		t.Fatalf("retry error = %v", err)
	}
	if !second.Applied || second.Outcome != OutcomeTransitioned || !second.AuditRecorded {
		t.Fatalf("retry result = %+v", second)
	}

	results := map[string]bool{}
	for _, event := range appender.records {
		if event.Action == "operation.transition.result" {
			results[event.Result] = true
		}
	}
	if !results["rejected"] || !results["applied"] {
		t.Fatalf("transition results = %+v, want rejected and applied", results)
	}
}

type uncertainCreateStore struct {
	*operation.MemoryStore
	once bool
}

func (s *uncertainCreateStore) Create(req operation.CreateRequest) (operation.Operation, bool, error) {
	op, created, err := s.MemoryStore.Create(req)
	if err != nil {
		return op, created, err
	}
	if !s.once {
		s.once = true
		return operation.Operation{}, false, fmt.Errorf("directory sync result: %w", operation.ErrCommitUncertain)
	}
	return op, created, nil
}

func TestCreateCommitUncertainIsUnknownThenRetryReadsPlanned(t *testing.T) {
	appender := newFakeEvidence()
	store := &uncertainCreateStore{MemoryStore: operation.NewMemoryStore()}
	service, err := New(store, appender)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return fixedNow }
	req := testCreate(testPrincipal("operator-1", authz.RoleOperator), authz.RiskLow, "uncertain-create")

	first, err := service.Create(req)
	serviceErr := serviceCode(t, err, CodeCommitUnknown)
	if !serviceErr.Partial || first.Outcome != OutcomeCommitUnknown || !first.AuditRecorded {
		t.Fatalf("uncertain create result = %+v error = %+v", first, serviceErr)
	}
	second, err := service.Create(req)
	if err != nil {
		t.Fatalf("retry create: %v", err)
	}
	if second.Created || second.Operation.ID == "" || second.Outcome != OutcomePlanned || !second.AuditRecorded {
		t.Fatalf("retry did not read durable planned operation: %+v", second)
	}
	results := map[string]bool{}
	for _, event := range appender.records {
		if event.Action == "operation.create.result" {
			results[event.Result] = true
		}
	}
	if !results["unknown"] || !results["planned"] || results["rejected"] {
		t.Fatalf("create evidence outcomes = %+v", results)
	}
}

type uncertainTransitionStore struct {
	*operation.MemoryStore
	once bool
}

func (s *uncertainTransitionStore) TransitionWithApproval(id string, to operation.Status, reason, approverID string) (operation.Operation, error) {
	op, err := s.MemoryStore.TransitionWithApproval(id, to, reason, approverID)
	if err != nil {
		return op, err
	}
	if !s.once {
		s.once = true
		return operation.Operation{}, fmt.Errorf("directory sync result: %w", operation.ErrCommitUncertain)
	}
	return op, nil
}

func TestTransitionCommitUncertainIsUnknownThenRetryReadsApplied(t *testing.T) {
	appender := newFakeEvidence()
	store := &uncertainTransitionStore{MemoryStore: operation.NewMemoryStore()}
	service, err := New(store, appender)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return fixedNow }
	principal := testPrincipal("operator-1", authz.RoleOperator)
	created, err := service.Create(testCreate(principal, authz.RiskLow, "uncertain-transition-create"))
	if err != nil {
		t.Fatal(err)
	}
	req := testTransition(principal, created.Operation.ID, operation.StatusPrechecking, "uncertain-transition")

	first, err := service.Transition(req)
	serviceErr := serviceCode(t, err, CodeCommitUnknown)
	if !serviceErr.Partial || first.Outcome != OutcomeCommitUnknown || !first.AuditRecorded {
		t.Fatalf("uncertain transition result = %+v error = %+v", first, serviceErr)
	}
	second, err := service.Transition(req)
	if err != nil {
		t.Fatalf("retry transition: %v", err)
	}
	if !second.Replayed || second.Applied || second.Operation.Status != operation.StatusPrechecking || second.Outcome != OutcomeTransitioned {
		t.Fatalf("retry did not read durable applied transition: %+v", second)
	}
	results := map[string]bool{}
	for _, event := range appender.records {
		if event.Action == "operation.transition.result" {
			results[event.Result] = true
		}
	}
	if !results["unknown"] || !results["applied"] || results["rejected"] {
		t.Fatalf("transition evidence outcomes = %+v", results)
	}
}
