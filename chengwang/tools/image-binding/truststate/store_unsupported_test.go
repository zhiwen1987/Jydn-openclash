//go:build !linux

package truststate

import (
	"context"
	"errors"
	"testing"

	"chengwang/image-binding/trustcatalog"
)

func TestTrustStateUnsupportedNeverInitializes(t *testing.T) {
	if _, err := Open(context.Background(), "not-a-production-path", trustcatalog.Anchor{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Open=%v", err)
	}
}
