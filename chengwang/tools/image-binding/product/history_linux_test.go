//go:build linux

package product

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"chengwang/image-binding/truststate"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
)

func TestProductD8HistoryRealAuditPaginationAndRedaction(t *testing.T) {
	f := newProductFixture(t, true)
	ctx := context.Background()
	admin := f.actor(authz.RoleAdmin)
	if _, err := f.service.Update(ctx, admin, []byte("{}")); err == nil {
		t.Fatal("invalid catalogue accepted")
	}
	doc := f.doc
	doc.Generation = 2
	raw := f.sign(t, doc)
	if _, err := f.service.Update(ctx, admin, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Verify(ctx, f.actor(authz.RoleOperator), f.request()); err == nil {
		t.Fatal("invalid fixture bundle accepted")
	}
	before, err := f.store.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	auditCount := f.audit.Status().Count
	page, err := f.service.History(ctx, f.actor(authz.RoleAuditor), imagetrust.HistoryRequest{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if page.Authorization != "BLOCKED" || page.Boundary != imagetrust.HistoryBoundary || page.DeviceActionsExecuted || page.ObservedAtUnix <= 0 || page.Sequence != before.Sequence || page.Total != 3 || page.Offset != 0 || page.Limit != 2 || len(page.Entries) != 2 {
		t.Fatal("history page metadata mismatch")
	}
	if page.Entries[0].State != "PREPARED" || page.Entries[0].Outcome != truststate.OutcomeRejected || page.Entries[1].State != "COMMITTED" || page.Entries[1].CatalogueSHA256 != digest(raw) {
		t.Fatal("history order/facts mismatch")
	}
	next, err := f.service.History(ctx, admin, imagetrust.HistoryRequest{Limit: 2, Offset: 2, Sequence: page.Sequence})
	if err != nil || len(next.Entries) != 1 || next.Entries[0].State != "RESERVED" || next.Entries[0].Outcome != truststate.OutcomeVerificationReserved || next.Entries[0].PolicyID != "fixture-policy" {
		t.Fatalf("second page mismatch: %v", err)
	}
	view, err := f.audit.RecoverySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range append(page.Entries, next.Entries...) {
		prepared, ok := view.Lookup("image-trust/" + entry.OperationID + "/prepared")
		if !ok || prepared.Hash != entry.PreparedAuditHash || entry.PreparedAtUnix != prepared.OccurredAt.Unix() {
			t.Fatal("prepared timestamp not from actual bound audit")
		}
		result, ok := view.Lookup("image-trust/" + entry.OperationID + "/result")
		if !ok || result.Hash != entry.ResultAuditHash || entry.ResultAtUnix != result.OccurredAt.Unix() || !entry.Acknowledged {
			t.Fatal("result timestamp not from actual ACK audit")
		}
	}
	for _, p := range []imagetrust.History{page, next} {
		body := productJSON(t, p)
		for _, excluded := range [][]byte{[]byte("payload"), []byte("publicKey"), []byte("token"), []byte("TEST-ONLY-SERVER-TOKEN"), []byte("outcomeData"), []byte("scopeSHA256"), f.initial, f.approval} {
			if bytes.Contains(body, excluded) {
				t.Fatal("history leaked excluded material")
			}
		}
	}
	after, err := f.store.Inspect(ctx)
	if err != nil || after.Sequence != before.Sequence || f.audit.Status().Count != auditCount {
		t.Fatal("history read mutated trust state or audit")
	}
	if _, err = f.service.Verify(ctx, f.actor(authz.RoleOperator), f.request()); err == nil {
		t.Fatal("history projection revived grant")
	}
}

func TestProductD8HistoryRBACWriteDisabledAndInvalidBounds(t *testing.T) {
	f := newProductFixture(t, false)
	ctx := context.Background()
	for _, role := range []authz.Role{authz.RoleViewer, authz.RoleOperator, authz.RoleApprover, authz.RoleAuditor, authz.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			page, err := f.service.History(ctx, f.actor(role), imagetrust.HistoryRequest{})
			if role == authz.RoleAuditor || role == authz.RoleAdmin {
				if err != nil || page.Limit != 20 || page.Total != 0 || page.Entries == nil {
					t.Fatal("read-only history needs no write gate", err)
				}
			} else {
				expectCode(t, err, imagetrust.CodeForbidden, false)
			}
		})
	}
	for _, request := range []imagetrust.HistoryRequest{{Limit: -1}, {Limit: 51}, {Offset: -1}, {Offset: 4097}} {
		_, err := f.service.History(ctx, f.actor(authz.RoleAdmin), request)
		expectCode(t, err, imagetrust.CodeInvalid, false)
	}
	actor := f.actor(authz.RoleAdmin)
	actor.AllowedScopes[0].Environment = "production"
	_, err := f.service.History(ctx, actor, imagetrust.HistoryRequest{})
	expectCode(t, err, imagetrust.CodeForbidden, false)
	if _, err = f.service.Status(ctx, f.actor(authz.RoleViewer)); err != nil {
		t.Fatal("history denial broke viewer status", err)
	}
	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.History(ctx, f.actor(authz.RoleViewer), imagetrust.HistoryRequest{})
	expectCode(t, err, imagetrust.CodeForbidden, false)
}

func TestProductD8HistoryUnknownAuditTimeAndSnapshotConflict(t *testing.T) {
	f := newProductFixture(t, false)
	ctx := context.Background()
	auditState := f.audit.Status()
	op := truststate.Operation{ID: strings.Repeat("d", 32), ActorID: "fixture-actor", ScopeSHA256: f.service.scopeDigest(), Kind: "update", Data: map[string]string{"catalogueSHA256": digest([]byte("not-installed"))}, AuditBaseCount: auditState.Count, AuditBaseHash: auditState.LastHash}
	if err := f.store.PrepareOperation(ctx, op); err != nil {
		t.Fatal(err)
	}
	page, err := f.service.History(ctx, f.actor(authz.RoleAuditor), imagetrust.HistoryRequest{})
	if err != nil || len(page.Entries) != 1 || page.Entries[0].PreparedAtUnix != 0 || page.Entries[0].ResultAtUnix != 0 {
		t.Fatal("missing event time was invented", err)
	}
	prepared, _, err := f.audit.AppendOnce(f.service.preparedEvent(op), "image-trust/"+op.ID+"/prepared")
	if err != nil {
		t.Fatal(err)
	}
	unbound, err := f.service.History(ctx, f.actor(authz.RoleAuditor), imagetrust.HistoryRequest{})
	if err != nil || unbound.Entries[0].PreparedAtUnix != 0 {
		t.Fatal("unbound event acquired trusted timestamp", err)
	}
	if err = f.store.BindPreparedAudit(ctx, op.ID, prepared.Hash); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.History(ctx, f.actor(authz.RoleAuditor), imagetrust.HistoryRequest{Sequence: page.Sequence})
	expectCode(t, err, imagetrust.CodeConflict, false)
	current, err := f.service.History(ctx, f.actor(authz.RoleAuditor), imagetrust.HistoryRequest{})
	if err != nil || current.Entries[0].PreparedAtUnix != prepared.OccurredAt.Unix() || current.Entries[0].ResultAtUnix != 0 {
		t.Fatal("bound actual timestamp missing", err)
	}
	end, err := f.service.History(ctx, f.actor(authz.RoleAuditor), imagetrust.HistoryRequest{Limit: 50, Offset: 4096, Sequence: current.Sequence})
	if err != nil || end.Total != 1 || len(end.Entries) != 0 || end.Offset != 4096 {
		t.Fatal("end-of-history pagination mismatch", err)
	}
}

func TestProductD8HistoryConcurrentWriterDoesNotPoison(t *testing.T) {
	f := newProductFixture(t, false)
	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i <= 20; i++ {
			report := f.audit.Status()
			op := truststate.Operation{ID: fmt.Sprintf("%032x", i), ActorID: "fixture-actor", ScopeSHA256: f.service.scopeDigest(), Kind: "update", Data: map[string]string{"catalogueSHA256": digest([]byte(fmt.Sprint(i)))}, AuditBaseCount: report.Count, AuditBaseHash: report.LastHash}
			if err := f.store.PrepareOperation(ctx, op); err != nil {
				t.Errorf("writer: %v", err)
				return
			}
		}
	}()
	for i := 0; i < 20; i++ {
		_, err := f.service.History(ctx, f.actor(authz.RoleAuditor), imagetrust.HistoryRequest{Limit: 5})
		if err != nil {
			expectCode(t, err, imagetrust.CodeConflict, false)
		}
	}
	wg.Wait()
	if f.service.unavailable() {
		t.Fatal("healthy snapshot race poisoned service")
	}
	page, err := f.service.History(ctx, f.actor(authz.RoleAuditor), imagetrust.HistoryRequest{})
	if err != nil || page.Total != 20 {
		t.Fatal("stable history unavailable after writer stopped", err)
	}
}

func TestProductD8HistoryBadAuditBindingFailsWithoutRepair(t *testing.T) {
	for _, kind := range []string{"missing-acked-audit", "corrupt-checkpoint"} {
		t.Run(kind, func(t *testing.T) {
			f := newProductFixture(t, true)
			ctx := context.Background()
			doc := f.doc
			doc.Generation = 2
			if _, err := f.service.Update(ctx, f.actor(authz.RoleAdmin), f.sign(t, doc)); err != nil {
				t.Fatal(err)
			}
			before, err := f.store.Inspect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "missing-acked-audit" {
				other, err := evidence.Open(filepath.Join(t.TempDir(), "empty-audit"))
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				f.service.audit = other
			} else {
				if err := os.WriteFile(filepath.Join(f.auditPath, "checkpoint.json"), []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, err = f.service.History(ctx, f.actor(authz.RoleAuditor), imagetrust.HistoryRequest{})
			expectCode(t, err, imagetrust.CodeAuditDegraded, false)
			after, err := f.store.Inspect(ctx)
			if err != nil || after.Sequence != before.Sequence {
				t.Fatal("history failure changed journal")
			}
			if kind == "missing-acked-audit" {
				if f.service.audit.Status().Count != 0 {
					t.Fatal("missing ACK history was silently rebuilt")
				}
			} else {
				raw, err := os.ReadFile(filepath.Join(f.auditPath, "checkpoint.json"))
				if err != nil || string(raw) != "{}\n" {
					t.Fatal("history repaired corrupt checkpoint")
				}
			}
		})
	}
}
