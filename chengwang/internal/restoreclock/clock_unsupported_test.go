//go:build !linux

package restoreclock

import (
	"errors"
	"testing"
)

func TestUnsupportedPlatformFailsClosed(t *testing.T) {
	if _, _, err := Open(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Open error=%v", err)
	}
}
