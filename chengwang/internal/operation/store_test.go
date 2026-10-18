package operation

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func validRequest(key string) CreateRequest {
	return CreateRequest{
		IdempotencyKey: key,
		InitiatorID:    "operator-1",
		Environment:    "production",
		Scope:          "mihomo:10.88.0.254",
		TargetVersion:  "v2026.10.18",
		Risk:           RiskLow,
	}
}

func TestCreateHasStableIDAndRequiredFields(t *testing.T) {
	store := NewMemoryStore()
	op, created, err := store.Create(validRequest("deploy-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first request must create operation")
	}
	if !operationIDPattern.MatchString(op.ID) {
		t.Fatalf("unexpected operation ID %q", op.ID)
	}
	if op.Environment == "" || op.Scope == "" || op.TargetVersion == "" || op.Risk == "" ||
		op.InitiatorID != "operator-1" || op.IdentityBinding != IdentityBindingDurable {
		t.Fatalf("missing required operation fields: %+v", op)
	}
	if op.Status != StatusPlanned || len(op.Events) != 1 || op.Events[0].Reason == "" || op.Events[0].At.IsZero() {
		t.Fatalf("invalid initial lifecycle: %+v", op)
	}

	again, created, err := store.Create(validRequest("deploy-1"))
	if err != nil {
		t.Fatal(err)
	}
	if created || again.ID != op.ID {
		t.Fatalf("idempotent create returned a different operation: %+v", again)
	}
}

func TestApprovalIdentityIsAtomicImmutableAndIndependent(t *testing.T) {
	store := NewMemoryStore()
	req := validRequest("durable-approval")
	req.Risk = RiskCritical
	op, _, err := store.Create(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(op.ID, StatusPrechecking, "bypass approval"); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("direct precheck error = %v, want approval required", err)
	}
	op, err = store.Transition(op.ID, StatusAwaitingApproval, "request approval")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.TransitionWithApproval(op.ID, StatusPrechecking, "self approval", req.InitiatorID); !errors.Is(err, ErrInvalidApprover) {
		t.Fatalf("self approval error = %v", err)
	}
	op, err = store.TransitionWithApproval(op.ID, StatusPrechecking, "independent approval", "approver-2")
	if err != nil {
		t.Fatal(err)
	}
	if op.ApprovedByID != "approver-2" {
		t.Fatalf("approvedById = %q", op.ApprovedByID)
	}
	if _, err := store.TransitionWithApproval(op.ID, StatusExecuting, "execute", "approver-3"); !errors.Is(err, ErrInvalidApprover) {
		t.Fatalf("approval rewrite error = %v", err)
	}
	op, err = store.Transition(op.ID, StatusExecuting, "execute with durable approval")
	if err != nil {
		t.Fatal(err)
	}
	if op.ApprovedByID != "approver-2" {
		t.Fatalf("durable approval changed: %+v", op)
	}
}

func TestIdempotencyConflictForDifferentPayload(t *testing.T) {
	store := NewMemoryStore()
	if _, _, err := store.Create(validRequest("same-key")); err != nil {
		t.Fatal(err)
	}
	changed := validRequest("same-key")
	changed.TargetVersion = "different"
	if _, _, err := store.Create(changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
}

func TestConcurrentIdempotentCreateReturnsOneOperation(t *testing.T) {
	store := NewMemoryStore()
	const workers = 64
	var wg sync.WaitGroup
	var created atomic.Int32
	ids := make(chan string, workers)
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op, wasCreated, err := store.Create(validRequest("concurrent"))
			if err != nil {
				errs <- err
				return
			}
			if wasCreated {
				created.Add(1)
			}
			ids <- op.ID
		}()
	}
	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		t.Fatal(err)
	}
	if created.Load() != 1 {
		t.Fatalf("expected one creation, got %d", created.Load())
	}
	var want string
	for id := range ids {
		if want == "" {
			want = id
		}
		if id != want {
			t.Fatalf("got multiple IDs: %q and %q", want, id)
		}
	}
}

func TestExplicitTransitionsAndMonotonicEvents(t *testing.T) {
	store := NewMemoryStore()
	base := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	var tick atomic.Int64
	store.now = func() time.Time { return base.Add(time.Duration(tick.Add(1)) * time.Second) }
	op, _, err := store.Create(validRequest("lifecycle"))
	if err != nil {
		t.Fatal(err)
	}
	path := []Status{StatusAwaitingApproval, StatusPrechecking, StatusExecuting, StatusVerifying, StatusObserving, StatusSucceeded}
	for _, status := range path {
		if status == StatusPrechecking {
			op, err = store.TransitionWithApproval(op.ID, status, "acceptance gate passed", "approver-2")
		} else {
			op, err = store.Transition(op.ID, status, "acceptance gate passed")
		}
		if err != nil {
			t.Fatalf("transition to %s: %v", status, err)
		}
	}
	if !op.Terminal() {
		t.Fatal("succeeded must be terminal")
	}
	for i, event := range op.Events {
		if event.Sequence != uint64(i+1) {
			t.Fatalf("event %d has sequence %d", i, event.Sequence)
		}
		if event.At.IsZero() || event.Reason == "" {
			t.Fatalf("event lacks timestamp or reason: %+v", event)
		}
		if i > 0 && event.At.Before(op.Events[i-1].At) {
			t.Fatalf("event time moved backwards: %+v", op.Events)
		}
	}
}

func TestIllegalTransitionRejectedWithoutEvent(t *testing.T) {
	store := NewMemoryStore()
	op, _, _ := store.Create(validRequest("illegal"))
	if _, err := store.Transition(op.ID, StatusSucceeded, "skipped all gates"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected invalid transition, got %v", err)
	}
	stored, _ := store.Get(op.ID)
	if stored.Status != StatusPlanned || len(stored.Events) != 1 {
		t.Fatalf("illegal transition mutated operation: %+v", stored)
	}
}

func TestTerminalStatesCannotTransition(t *testing.T) {
	terminalPaths := map[Status][]Status{
		StatusSucceeded:      {StatusPrechecking, StatusExecuting, StatusVerifying, StatusSucceeded},
		StatusPartial:        {StatusPrechecking, StatusExecuting, StatusPartial},
		StatusRolledBack:     {StatusPrechecking, StatusExecuting, StatusRolledBack},
		StatusFailed:         {StatusFailed},
		StatusManualTakeover: {StatusManualTakeover},
	}
	for terminal, path := range terminalPaths {
		t.Run(string(terminal), func(t *testing.T) {
			store := NewMemoryStore()
			op, _, _ := store.Create(validRequest("terminal-" + string(terminal)))
			var err error
			for _, state := range path {
				op, err = store.Transition(op.ID, state, "test path")
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.Transition(op.ID, StatusPrechecking, "must reject"); !errors.Is(err, ErrTerminalOperation) {
				t.Fatalf("expected terminal error, got %v", err)
			}
		})
	}
}

func TestConcurrentTransitionHasSingleWinner(t *testing.T) {
	store := NewMemoryStore()
	op, _, _ := store.Create(validRequest("transition-race"))
	const workers = 32
	var wg sync.WaitGroup
	var wins atomic.Int32
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.Transition(op.ID, StatusAwaitingApproval, "concurrent approval request"); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("expected one transition winner, got %d", wins.Load())
	}
	stored, _ := store.Get(op.ID)
	if len(stored.Events) != 2 || stored.Events[1].Sequence != 2 {
		t.Fatalf("unexpected events after transition race: %+v", stored.Events)
	}
}

func TestReturnedOperationsAreDetached(t *testing.T) {
	store := NewMemoryStore()
	op, _, _ := store.Create(validRequest("clone"))
	op.Events[0].Reason = "mutated"
	stored, _ := store.Get(op.ID)
	if stored.Events[0].Reason == "mutated" {
		t.Fatal("caller mutated stored event")
	}
}

func TestOperationJSONDoesNotExposeIdempotencyKeyOrSecretFields(t *testing.T) {
	store := NewMemoryStore()
	op, _, _ := store.Create(validRequest("private-idempotency-key"))
	encoded, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, forbidden := range []string{"private-idempotency-key", "password", "token", "secret", "authorization"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Fatalf("operation JSON contains forbidden secret field/value %q: %s", forbidden, text)
		}
	}
}

func TestSecretBearingReasonIsRejectedWithoutPersistence(t *testing.T) {
	store := NewMemoryStore()
	op, _, _ := store.Create(validRequest("safe-events"))
	if _, err := store.Transition(op.ID, StatusPrechecking, "authorization: Bearer must-not-store"); !errors.Is(err, ErrSensitiveReason) {
		t.Fatalf("expected sensitive reason rejection, got %v", err)
	}
	stored, _ := store.Get(op.ID)
	encoded, err := json.Marshal(stored.Events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "must-not-store") || len(stored.Events) != 1 {
		t.Fatalf("sensitive reason was persisted: %s", encoded)
	}
}

func TestValidationAndUnknownOperation(t *testing.T) {
	store := NewMemoryStore()
	request := validRequest("")
	if _, _, err := store.Create(request); err == nil {
		t.Fatal("expected validation error")
	}
	if _, err := store.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
	if _, err := store.Transition("missing", StatusPrechecking, "check"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestCreateRequestTextLimits(t *testing.T) {
	tests := []struct {
		name string
		max  int
		set  func(*CreateRequest, string)
	}{
		{"initiator", maxIdentityBytes, func(req *CreateRequest, value string) { req.InitiatorID = value }},
		{"environment", maxEnvironmentBytes, func(req *CreateRequest, value string) { req.Environment = value }},
		{"scope", maxScopeBytes, func(req *CreateRequest, value string) { req.Scope = value }},
		{"target version", maxTargetVersionBytes, func(req *CreateRequest, value string) { req.TargetVersion = value }},
	}
	for _, test := range tests {
		t.Run(test.name+" exact", func(t *testing.T) {
			req := validRequest("exact-" + test.name)
			test.set(&req, strings.Repeat("x", test.max))
			if _, _, err := NewMemoryStore().Create(req); err != nil {
				t.Fatalf("exact limit rejected: %v", err)
			}
		})
		t.Run(test.name+" over", func(t *testing.T) {
			req := validRequest("over-" + test.name)
			test.set(&req, strings.Repeat("x", test.max+1))
			if _, _, err := NewMemoryStore().Create(req); !errors.Is(err, ErrStoreLimit) {
				t.Fatalf("over limit error = %v", err)
			}
		})
	}
}

func TestRuntimeCollectionLimitsFailBeforeMutation(t *testing.T) {
	store := NewMemoryStore()
	for index := 0; index < maxOperations; index++ {
		id := fmt.Sprintf("synthetic-%05d", index)
		store.operations[id] = &Operation{ID: id}
	}
	if _, _, err := store.Create(validRequest("operation-limit")); !errors.Is(err, ErrStoreLimit) {
		t.Fatalf("operation limit error = %v", err)
	}

	transitionStore := NewMemoryStore()
	op, _, err := transitionStore.Create(validRequest("event-runtime-limit"))
	if err != nil {
		t.Fatal(err)
	}
	transitionStore.operations[op.ID].Events = make([]Event, maxEventsPerOperation)
	if _, err := transitionStore.Transition(op.ID, StatusPrechecking, "must not append"); !errors.Is(err, ErrStoreLimit) {
		t.Fatalf("event limit error = %v", err)
	}
}
