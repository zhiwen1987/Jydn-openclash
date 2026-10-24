//go:build !linux

package mihomodeploy

import (
	"context"
	"errors"
	"testing"
)

func TestLabKernelUnsupportedHasNoProcessCapability(t *testing.T) {
	if in, err := openLabKernelInput(); in != nil || !errors.Is(err, errLabKernelUnsupported) {
		t.Fatal("unsupported input opened")
	}
	if kernel, err := startOwnedLabKernel(context.Background(), nil, nil); kernel != nil || !errors.Is(err, errLabKernelUnsupported) {
		t.Fatal("unsupported process started")
	}
	var kernel *ownedLabKernel
	if _, err := kernel.identity(); !errors.Is(err, errLabKernelUnsupported) {
		t.Fatal("unsupported identity accepted")
	}
	if err := kernel.verifyListeners(); !errors.Is(err, errLabKernelUnsupported) {
		t.Fatal("unsupported listener accepted")
	}
	if _, err := kernel.stop(context.Background()); !errors.Is(err, errLabKernelUnsupported) {
		t.Fatal("unsupported stop accepted")
	}
}
