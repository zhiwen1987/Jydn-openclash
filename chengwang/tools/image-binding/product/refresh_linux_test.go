//go:build linux

package product

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"chengwang/image-binding/trustcatalog"
	"chengwang/internal/authz"
	"chengwang/internal/imagetrust"
)

func productD7RefreshService(t *testing.T, f *productFixture) {
	t.Helper()
	var err error
	f.service, err = New(context.Background(), Config{Store: f.store, Audit: f.audit, Scope: f.service.scope, WritesEnabled: true, RegistryRoots: x509.NewCertPool(), RefreshMaxAge: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProductD7RefreshRequiresConfirmedExactStateBeforeConsumption(t *testing.T) {
	f := newProductFixture(t, true)
	productD7RefreshService(t, &f)
	ctx := context.Background()
	before, _ := f.store.Inspect(ctx)
	_, err := f.service.Verify(ctx, f.actor(authz.RoleOperator), f.request())
	expectCode(t, err, imagetrust.CodeUnavailable, false)
	after, _ := f.store.Inspect(ctx)
	if before.Sequence != after.Sequence || after.LedgerUsed != 0 || f.audit.Status().Count != 0 {
		t.Fatal("unconfirmed source consumed or audited")
	}
	if err = f.service.ConfirmRefresh(ctx, 2, digest(f.initial)); err == nil {
		t.Fatal("wrong generation confirmed")
	}
	if err = f.service.ConfirmRefresh(ctx, 1, digest([]byte("other"))); err == nil {
		t.Fatal("wrong bytes confirmed")
	}
	if err = f.service.ConfirmRefresh(ctx, 1, digest(f.initial)); err != nil {
		t.Fatal(err)
	}
	status, err := f.service.Status(ctx, f.actor(authz.RoleViewer))
	if err != nil || !status.RefreshRequired || !status.RefreshFresh || status.RefreshLastSuccessUnix <= 0 || status.RefreshUntilUnix <= 0 {
		t.Fatal("confirmed source status missing")
	}
	_, err = f.service.Verify(ctx, f.actor(authz.RoleOperator), f.request())
	if err == nil {
		t.Fatal("invalid real SDK fixture accepted")
	}
	after, _ = f.store.Inspect(ctx)
	if after.LedgerUsed != 1 || after.Consumptions[0].Status != "RESERVED" {
		t.Fatal("confirmed source did not reach real verifier reservation")
	}
}

func TestProductD7RefreshStaleOrChangedStateCannotConsume(t *testing.T) {
	for _, kind := range []string{"stale", "clock-backward", "manual-update", "restart"} {
		t.Run(kind, func(t *testing.T) {
			f := newProductFixture(t, true)
			productD7RefreshService(t, &f)
			ctx := context.Background()
			if err := f.service.ConfirmRefresh(ctx, 1, digest(f.initial)); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "stale":
				f.service.refreshUntil = time.Now().Add(-time.Second)
			case "clock-backward":
				f.service.refreshAt = time.Now().Add(time.Hour)
			case "manual-update":
				doc := f.doc
				doc.Generation++
				if _, err := f.service.Update(ctx, f.actor(authz.RoleAdmin), f.sign(t, doc)); err != nil {
					t.Fatal(err)
				}
			case "restart":
				productD7RefreshService(t, &f)
			}
			before, _ := f.store.Inspect(ctx)
			count := f.audit.Status().Count
			_, err := f.service.Verify(ctx, f.actor(authz.RoleOperator), f.request())
			expectCode(t, err, imagetrust.CodeUnavailable, false)
			after, _ := f.store.Inspect(ctx)
			if before.Sequence != after.Sequence || after.LedgerUsed != 0 || f.audit.Status().Count != count {
				t.Fatal("stale source changed durable state")
			}
			status, err := f.service.Status(ctx, f.actor(authz.RoleViewer))
			if err != nil || status.RefreshFresh {
				t.Fatal("stale source shown fresh")
			}
		})
	}
}

func TestProductD7RefreshCanInstallWhileStaleAndRejectBadOrRacingConfirm(t *testing.T) {
	f := newProductFixture(t, true)
	productD7RefreshService(t, &f)
	ctx := context.Background()
	doc := f.doc
	doc.Generation = 2
	doc.Grants = []trustcatalog.Grant{}
	doc.RevokedManifests = []string{f.doc.Grants[0].ManifestSHA256}
	raw := f.sign(t, doc)
	if err := f.service.ApplyRefresh(ctx, []byte("{}")); err == nil {
		t.Fatal("unsigned refresh installed")
	}
	if err := f.service.ApplyRefresh(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if err := f.service.ConfirmRefresh(ctx, 1, digest(f.initial)); err == nil {
		t.Fatal("older response renewed source freshness")
	}
	if err := f.service.ConfirmRefresh(ctx, 2, digest(raw)); err != nil {
		t.Fatal(err)
	}
	status, err := f.service.Status(ctx, f.actor(authz.RoleViewer))
	if err != nil || !status.RefreshFresh || status.Generation != 2 || status.RevokedManifests != 1 {
		t.Fatal("stale source could not recover with signed update")
	}
	entries, err := f.store.Journal(ctx)
	if err != nil || len(entries) != 2 || entries[0].State != "PREPARED" || entries[0].Outcome != "REJECTED" || !entries[0].Acknowledged || entries[1].Outcome != "CATALOGUE_COMMITTED" || !entries[1].Acknowledged {
		t.Fatal("rejected/committed refresh journal mismatch")
	}
	if entries[1].Operation.ActorID != "image-trust-refresh" {
		t.Fatal("automation actor not distinct")
	}
	// Models the second read in the final product check observing a new,
	// already confirmed epoch. A fresh gen2 is not fresh authority for gen1.
	expectCode(t, f.service.finalSourceState(ctx, 1, digest(f.initial), time.Now().Add(time.Minute).Unix()), imagetrust.CodeConflict, true)
	if err = f.service.finalSourceState(ctx, 2, digest(raw), time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatal("matching final epoch rejected", err)
	}
	expectCode(t, f.service.finalSourceState(ctx, 2, digest(raw), time.Now().Unix()-1), imagetrust.CodeInvalid, true)
}

func TestProductD7MaintenanceRefreshesHealthWithoutStateWrites(t *testing.T) {
	f := newProductFixture(t, false)
	ctx := context.Background()
	before, _ := f.store.Inspect(ctx)
	count := f.audit.Status().Count
	if err := f.service.Maintenance(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := f.store.Inspect(ctx)
	if before.Sequence != after.Sequence || f.audit.Status().Count != count {
		t.Fatal("maintenance mutated domain or audit")
	}
	if err := f.audit.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.service.Maintenance(ctx); err == nil {
		t.Fatal("audit outage reported healthy")
	}
	if _, err := f.service.Status(ctx, f.actor(authz.RoleViewer)); err == nil {
		t.Fatal("maintenance cleared integrity poison")
	}
}
