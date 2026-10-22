//go:build linux

package truststate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestProductTrustStateInspectReadOnlyDetachedAndRedacted(t *testing.T) {
	f := newStateFixture(t)
	s, path := createFixture(t, f)
	before := marshalFixture(t, s.current)
	observed := s.lastObserved
	state, err := s.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.Authorization != "BLOCKED" || !state.CatalogueValid || state.Catalogue.Generation != 1 || state.Catalogue.SHA256 != hash(f.initial) || state.Catalogue.StoreID != f.anchor.StoreID || state.Sequence != 1 || state.LedgerUsed != 0 || state.LedgerRemaining != maxLedgerEntries {
		t.Fatal("inspection metadata mismatch")
	}
	state.Catalogue.Grants[0].ID = "ffffffffffffffffffffffffffffffff"
	state.Catalogue.PolicyFloors["fixture-policy"] = 100
	if !bytes.Equal(before, marshalFixture(t, s.current)) || s.lastObserved != observed {
		t.Fatal("Inspect changed persistent state or time high-water")
	}
	ticket := beginFixture(t, s, f)
	state, err = s.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.LedgerUsed != 1 || len(state.Consumptions) != 1 || state.Consumptions[0].Status != "RESERVED" || state.Consumptions[0].GrantID != ticket.GrantID() {
		t.Fatal("reservation missing from inspection")
	}
	if err = s.Complete(context.Background(), ticket, hash([]byte("evidence"))); err != nil {
		t.Fatal(err)
	}
	state, err = s.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw := marshalFixture(t, state)
	for _, secret := range [][]byte{[]byte("publicKey"), []byte("tokenSHA256"), []byte("history"), []byte("payload"), []byte("signature"), f.approval, f.initial} {
		if bytes.Contains(raw, secret) {
			t.Fatal("inspection leaked excluded material")
		}
	}
	if state.Consumptions[0].Status != "CONSUMED" {
		t.Fatal("consumption missing from inspection")
	}
	var imported Inspection
	if err = json.Unmarshal(raw, &imported); err != nil {
		t.Fatal(err)
	}
	imported.Consumptions[0].Status = "RESERVED"
	if _, err = s.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, ErrReplay) {
		t.Fatal("inspection JSON acquired authority")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path, f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got, err := reopened.Inspect(context.Background()); err != nil || got.LedgerUsed != 1 || got.Consumptions[0].Status != "CONSUMED" {
		t.Fatalf("reopen Inspect: %v", err)
	}
}

func TestProductTrustStateInspectExpiredAndClockReadOnly(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	before := marshalFixture(t, s.current)
	observed := s.lastObserved
	s.clock = func() time.Time { return time.Unix(f.document.NotAfterUnix, 0) }
	state, err := s.Inspect(context.Background())
	if err != nil || state.CatalogueValid {
		t.Fatalf("expired metadata should be visible but inactive: %v", err)
	}
	if !bytes.Equal(before, marshalFixture(t, s.current)) || observed != s.lastObserved {
		t.Fatal("Inspect advanced sequence or clock floor")
	}
	s.clock = func() time.Time { return time.Now().Add(-time.Hour) }
	if _, err = s.Inspect(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("backward clock Inspect: %v", err)
	}
	if !bytes.Equal(before, marshalFixture(t, s.current)) || observed != s.lastObserved {
		t.Fatal("failed Inspect advanced state")
	}
	s.clock = time.Now
	if _, err = s.Inspect(context.Background()); err != nil {
		t.Fatal("diagnostic clock check unexpectedly changed store state")
	}
}

func TestProductTrustStateInspectInvalidContextsAndClosed(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	if _, err = s.Inspect(nil); err == nil {
		t.Fatal("nil context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = s.Inspect(ctx); err == nil {
		t.Fatal("canceled context")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Inspect(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed Inspect: %v", err)
	}
	var absent *Store
	if _, err := absent.Inspect(context.Background()); err == nil {
		t.Fatal("nil Store Inspect")
	}
}
