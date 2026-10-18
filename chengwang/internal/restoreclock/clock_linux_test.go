//go:build linux

package restoreclock

import (
	"testing"
	"time"
)

func TestLinuxClockReadsKernelBootAndBoottime(t *testing.T) {
	clock, first, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	second, err := clock.ObserveWithin(first, 30*time.Second, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if second.BootID() != first.BootID() || second.BoottimeNS() < first.BoottimeNS() || second.WallUTC().Before(first.WallUTC()) {
		t.Fatalf("non-monotonic kernel samples: first=%+v second=%+v", first, second)
	}
}
