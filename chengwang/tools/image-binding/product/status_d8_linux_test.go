//go:build linux

package product

import (
	"context"
	"testing"
	"time"

	"chengwang/internal/authz"
)

func TestProductD8StatusObservationUsesActualAuditClockWithoutWrites(t *testing.T) {
	f := newProductFixture(t, false)
	before, err := f.store.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	audit := f.audit.Status()
	start := time.Now().Unix()
	status, err := f.service.Status(context.Background(), f.actor(authz.RoleViewer))
	if err != nil || status.ObservedAtUnix < start || status.ObservedAtUnix > time.Now().Unix() || status.AuditVerifiedAtUnix != audit.VerifiedAt.Unix() || !status.Healthy {
		t.Fatalf("actual observation/audit clocks missing: %#v %v", status, err)
	}
	after, err := f.store.Inspect(context.Background())
	if err != nil || before.Sequence != after.Sequence || f.audit.Status() != audit {
		t.Fatal("status read changed durable state or renewed cached audit verification")
	}
}
