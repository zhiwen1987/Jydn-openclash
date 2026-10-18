package restorelease

import (
	"errors"
	"testing"
)

func TestNilAndZeroLeaseFailClosed(t *testing.T) {
	var nilLease *Lease
	if !errors.Is(nilLease.Verify(), ErrClosed) || nilLease.Close() != nil {
		t.Fatal("nil lease did not fail closed")
	}
	zero := &Lease{}
	if !errors.Is(zero.Verify(), ErrClosed) || zero.CandidateRoot() != "" {
		t.Fatal("zero lease did not fail closed")
	}
	if err := zero.Close(); err != nil {
		t.Fatal(err)
	}
}
