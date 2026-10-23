//go:build !linux

package probe

import (
	"context"
	"errors"
	"testing"
)

func TestProbeSecureP1StoreUnsupportedDoesNotFallback(t *testing.T) {
	report, err := ReadStoreSecure(context.Background(), "not-a-real-directory", SecureReadOptions{})
	if !errors.Is(err, ErrSecureUnsupported) || report.Results != nil || report.Healthy {
		t.Fatal("non-Linux secure read fell back to an unsafe path")
	}
}

func TestProbeSecureP1CatalogUnsupportedDoesNotFallback(t *testing.T) {
	_, err := ReadCatalogSecure(context.Background(), "not-a-real-catalog", SecureFileOwner{})
	if !errors.Is(err, ErrSecureUnsupported) {
		t.Fatal("non-Linux secure catalog read fell back to an unsafe path")
	}
}
