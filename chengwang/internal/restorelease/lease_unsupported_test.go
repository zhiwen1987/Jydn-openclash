//go:build !linux

package restorelease

import (
	"errors"
	"testing"
)

func TestUnsupportedPlatformNeverSimulatesLease(t *testing.T) {
	if _, err := Acquire("/var/lib/chengwang-m2b-candidate/probe"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Acquire error=%v", err)
	}
}
