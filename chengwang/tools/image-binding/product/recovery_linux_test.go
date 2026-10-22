//go:build linux

package product

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
)

func d7NewService(t *testing.T, f productFixture, store *truststate.Store, audit *evidence.Store) (*Service, error) {
	t.Helper()
	return New(context.Background(), Config{Store: store, Audit: audit, Scope: f.service.Scope(), WritesEnabled: true, RegistryRoots: x509.NewCertPool()})
}
func d7CloseFixture(t *testing.T, f productFixture) {
	t.Helper()
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.audit.Close(); err != nil {
		t.Fatal(err)
	}
}

// Each child exits through os.Exit at an actual product durability boundary.
// Store and evidence are reopened by a fresh process-owned Service. Hooks only
// select that exit point; no fake database, fake audit or power-loss claim is used.
func TestProductD7RecoveryRealProcessExitAndIdempotence(t *testing.T) {
	stages := []string{"after-journal-prepare", "after-prepared-audit", "before-result-audit", "after-journal-outcome", "after-result-audit", "after-journal-ack"}
	for _, kind := range []string{"update", "verify"} {
		for _, stage := range stages {
			t.Run(kind+"/"+stage, func(t *testing.T) {
				f := newProductFixture(t, true)
				doc := f.doc
				doc.Generation = 2
				update := f.sign(t, doc)
				d7CloseFixture(t, f)
				cmd := exec.Command(os.Args[0], "-test.run=^TestProductD7RecoveryProcessHelper$")
				cmd.Env = append(os.Environ(), "CHENGWANG_PRODUCT_D7_STAGE="+stage, "CHENGWANG_PRODUCT_D7_KIND="+kind, "CHENGWANG_PRODUCT_D7_STORE="+f.path, "CHENGWANG_PRODUCT_D7_AUDIT="+f.auditPath, "CHENGWANG_PRODUCT_D7_ANCHOR="+base64.StdEncoding.EncodeToString(productJSON(t, f.anchor)), "CHENGWANG_PRODUCT_D7_SCOPE="+base64.StdEncoding.EncodeToString(productJSON(t, f.service.Scope())), "CHENGWANG_PRODUCT_D7_APPROVAL="+base64.StdEncoding.EncodeToString(f.approval), "CHENGWANG_PRODUCT_D7_UPDATE="+base64.StdEncoding.EncodeToString(update))
				output, err := cmd.CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 91 {
					t.Fatalf("child missed requested process-exit boundary: %v %s", err, output)
				}
				store, err := truststate.Open(context.Background(), f.path, f.anchor)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				audit, err := evidence.Open(f.auditPath)
				if err != nil {
					t.Fatal(err)
				}
				defer audit.Close()
				service, err := d7NewService(t, f, store, audit)
				if err != nil {
					t.Fatalf("healthy interrupted outbox could not reconcile: %v", err)
				}
				entries, err := store.Journal(context.Background())
				if err != nil || len(entries) != 1 || !entries[0].Acknowledged || entries[0].ResultAuditHash == "" || entries[0].Operation.PreparedAuditHash == "" {
					t.Fatal("recovery did not acknowledge exact audit bindings")
				}
				entry := entries[0]
				early := stage == "after-journal-prepare" || stage == "after-prepared-audit"
				state, err := store.Inspect(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if early {
					if entry.State != "PREPARED" || entry.Outcome != truststate.OutcomeInterrupted || state.LedgerUsed != 0 || state.Catalogue.Generation != 1 {
						t.Fatal("recovery replayed an interrupted domain mutation")
					}
				}
				if !early && kind == "update" {
					if entry.State != "COMMITTED" || entry.Outcome != truststate.OutcomeCatalogueCommitted || state.Catalogue.Generation != 2 || state.Catalogue.SHA256 != digest(update) {
						t.Fatal("committed catalogue fact lost during recovery")
					}
				}
				if !early && kind == "verify" {
					if entry.State != "RESERVED" || entry.Outcome != truststate.OutcomeVerificationReserved || state.LedgerUsed != 1 || state.Consumptions[0].Status != "RESERVED" {
						t.Fatal("interrupted verification acquired success or lost its burn")
					}
					if _, err = store.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, truststate.ErrReplay) {
						t.Fatal("recovery made grant reusable")
					}
				}
				view, err := audit.RecoverySnapshot()
				if err != nil {
					t.Fatal(err)
				}
				prepared, found := view.Lookup("image-trust/" + entry.Operation.ID + "/prepared")
				if !found || prepared.Hash != entry.Operation.PreparedAuditHash || !eventMatches(prepared, service.preparedEvent(entry.Operation)) {
					t.Fatal("prepared evidence mismatch")
				}
				result, found := view.Lookup("image-trust/" + entry.Operation.ID + "/result")
				if !found || result.Hash != entry.ResultAuditHash || !eventMatches(result, service.resultEvent(entry)) {
					t.Fatal("result evidence mismatch")
				}
				if result.Result == "verification_consumed" {
					t.Fatal("reserved/intent recovery forged verification success")
				}
				report, err := audit.Verify()
				if err != nil || !report.Valid || report.Count != 2 {
					t.Fatal("recovery duplicated or lost the two exact audit events")
				}
				sequence := state.Sequence
				count := report.Count
				if _, err = d7NewService(t, f, store, audit); err != nil {
					t.Fatal("idempotent second constructor", err)
				}
				after, err := store.Inspect(context.Background())
				if err != nil || after.Sequence != sequence || audit.Status().Count != count {
					t.Fatal("repeated startup replayed an acknowledged outbox")
				}
			})
		}
	}
}

func TestProductD7RecoveryProcessHelper(t *testing.T) {
	stage := os.Getenv("CHENGWANG_PRODUCT_D7_STAGE")
	if stage == "" {
		return
	}
	decode := func(name string) []byte {
		v, err := base64.StdEncoding.DecodeString(os.Getenv(name))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	var anchor trustcatalog.Anchor
	var scope authz.ResourceScope
	if json.Unmarshal(decode("CHENGWANG_PRODUCT_D7_ANCHOR"), &anchor) != nil || json.Unmarshal(decode("CHENGWANG_PRODUCT_D7_SCOPE"), &scope) != nil {
		t.Fatal("invalid public child inputs")
	}
	store, err := truststate.Open(context.Background(), os.Getenv("CHENGWANG_PRODUCT_D7_STORE"), anchor)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := evidence.Open(os.Getenv("CHENGWANG_PRODUCT_D7_AUDIT"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(context.Background(), Config{Store: store, Audit: audit, Scope: scope, WritesEnabled: true, RegistryRoots: x509.NewCertPool()})
	if err != nil {
		t.Fatal(err)
	}
	service.fault = func(at string) {
		if at == stage {
			os.Exit(91)
		}
	}
	actor := authz.Principal{ID: "fixture-actor", TenantID: scope.TenantID, Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{scope}}
	if os.Getenv("CHENGWANG_PRODUCT_D7_KIND") == "update" {
		_, _ = service.Update(context.Background(), actor, decode("CHENGWANG_PRODUCT_D7_UPDATE"))
	} else {
		f := productFixture{service: service, approval: decode("CHENGWANG_PRODUCT_D7_APPROVAL")}
		_, _ = service.Verify(context.Background(), actor, f.request())
	}
	t.Fatal("requested process exit boundary was never reached")
}

func TestProductD7RecoveryRejectsLostOrConflictingEvidence(t *testing.T) {
	for _, kind := range []string{"acked-audit-missing", "prepared-audit-missing", "wrong-prefix", "prepared-key-conflict", "result-key-conflict", "wrong-scope", "bad-checkpoint"} {
		t.Run(kind, func(t *testing.T) {
			f := newProductFixture(t, true)
			ctx := context.Background()
			actor := f.actor(authz.RoleAdmin)
			if kind == "wrong-prefix" {
				if _, _, err := f.audit.AppendOnce(evidence.EvidenceEvent{TraceID: "original-base", ActorID: actor.ID, Action: "image_trust.read", Target: "image-trust/" + f.doc.StoreID, Result: "observed"}, "original-base"); err != nil {
					t.Fatal(err)
				}
			}
			doc := f.doc
			doc.Generation = 2
			raw := f.sign(t, doc)
			if kind == "acked-audit-missing" {
				if _, err := f.service.Update(ctx, actor, raw); err != nil {
					t.Fatal(err)
				}
			} else {
				op, err := f.service.preAudit(ctx, actor, "image_trust.update", map[string]string{"catalogueSHA256": digest(raw)})
				if err != nil {
					t.Fatal(err)
				}
				if kind == "result-key-conflict" {
					if err = f.store.UpdateTracked(ctx, raw, op); err != nil {
						t.Fatal(err)
					}
					entry, err := f.service.operation(ctx, op)
					if err != nil {
						t.Fatal(err)
					}
					event := f.service.resultEvent(entry)
					event.Result = "rejected"
					if _, _, err = f.audit.AppendOnce(event, "image-trust/"+op+"/result"); err != nil {
						t.Fatal(err)
					}
				}
			}
			entries, err := f.store.Journal(ctx)
			if err != nil || len(entries) != 1 {
				t.Fatal("missing original operation")
			}
			entry := entries[0]
			audit := f.audit
			scope := f.service.Scope()
			switch kind {
			case "acked-audit-missing", "prepared-audit-missing", "wrong-prefix", "prepared-key-conflict":
				audit, err = evidence.Open(filepath.Join(t.TempDir(), "replacement-audit"))
				if err != nil {
					t.Fatal(err)
				}
				defer audit.Close()
				if kind == "wrong-prefix" {
					_, _, err = audit.AppendOnce(evidence.EvidenceEvent{TraceID: "different-base", ActorID: actor.ID, Action: "image_trust.read", Target: "image-trust/" + f.doc.StoreID, Result: "different"}, "different-base")
					if err != nil {
						t.Fatal(err)
					}
				}
				if kind == "prepared-key-conflict" {
					event := f.service.preparedEvent(entry.Operation)
					event.ActorID = "other-actor"
					if _, _, err = audit.AppendOnce(event, "image-trust/"+entry.Operation.ID+"/prepared"); err != nil {
						t.Fatal(err)
					}
				}
			case "wrong-scope":
				scope.SiteID = "other-site"
			case "bad-checkpoint":
				if err = os.WriteFile(filepath.Join(f.auditPath, "checkpoint.json"), []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			count := audit.Status().Count
			state, err := f.store.Inspect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if service, err := New(ctx, Config{Store: f.store, Audit: audit, Scope: scope, WritesEnabled: true, RegistryRoots: x509.NewCertPool()}); err == nil || service != nil {
				t.Fatal("invalid cross-store bindings recovered as healthy")
			}
			after, err := f.store.Inspect(ctx)
			if err != nil || after.Sequence != state.Sequence || kind != "bad-checkpoint" && audit.Status().Count != count {
				t.Fatal("failed constructor repaired evidence or changed journal")
			}
			if kind == "bad-checkpoint" {
				unchanged, err := os.ReadFile(filepath.Join(f.auditPath, "checkpoint.json"))
				if err != nil || string(unchanged) != "{}\n" {
					t.Fatal("constructor rewrote corrupt checkpoint")
				}
			}
		})
	}
}
