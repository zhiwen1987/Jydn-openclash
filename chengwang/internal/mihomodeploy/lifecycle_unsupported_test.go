//go:build !linux

package mihomodeploy

import (
	"errors"
	"testing"
)

func TestLifecycleUnsupportedPlatformNeverCreatesDurableBackend(t *testing.T) {
	disk, err := openLifecycleDisk()
	if disk != nil || !errors.Is(err, errLifecycleUnsupported) {
		t.Fatal("unsupported platform returned a durable writer")
	}
}
