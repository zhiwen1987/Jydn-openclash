//go:build linux

package mihomodeploy

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This is an actual Linux os/exec Start failure against a nonexistent path.
// It is not a Mihomo execution and does not prove the native recovery E2E.
func TestLabRecoveryUnstartedCleanupConsumesActualLinuxStartFailureOnce(t *testing.T) {
	in, ops := labKernelModelFixture(t, "quiet")
	ops.command = func(ctx context.Context, home string, _ []byte) *exec.Cmd {
		return exec.CommandContext(ctx, filepath.Join(home, "MODEL-does-not-exist"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	returned, err := startLabKernelWith(ctx, in, labKernelModelArtifact(t), ops)
	var startErr *labKernelStartError
	if returned != nil || !errors.As(err, &startErr) || startErr == nil || startErr.owned() == nil {
		t.Fatal("actual Linux Start failure did not retain its owned wrapper")
	}
	owned := startErr.owned()
	before := startErr.observation()
	if before.Started == nil || *before.Started || before.PID != nil || before.StartTicks != nil {
		t.Fatal("actual Linux Start failure invented a started identity")
	}
	cancelled, cancelPreflight := context.WithCancel(context.Background())
	cancelPreflight()
	if receipt, _, _, cleanupErr := labRecoverySettleUnstartedKernel(cancelled, owned); cleanupErr == nil || receipt.Schema != "" {
		t.Fatal("pre-cancelled cleanup released source custody")
	}
	receipt, stdout, stderr, cleanupErr := labRecoverySettleUnstartedKernel(ctx, owned)
	if cleanupErr != nil || !labRecoveryUnstartedCleanupReceiptValid(receipt) ||
		!labRecoveryCleanupStreamSnapshotMatches(receipt.Stdout, stdout) ||
		!labRecoveryCleanupStreamSnapshotMatches(receipt.Stderr, stderr) ||
		receipt.Observation.Started == nil || *receipt.Observation.Started || receipt.Observation.PID != nil || receipt.Observation.StartTicks != nil {
		t.Fatal("actual Linux unstarted wrapper did not produce exact no-process cleanup evidence")
	}
	old, _ := labKernelModelStart(t, "quiet")
	oldExit, oldStopErr := old.stop(context.Background())
	if oldStopErr != nil || !labQuiescenceExitDrained(oldExit) {
		t.Fatal("MODEL old ownership anchor did not settle")
	}
	service := &labServiceCore{kernel: owned, ready: true}
	service.mu.Lock()
	rebound := labRecoveryRebindUnstartedKernelLocked(service, owned, old, oldExit, true)
	service.mu.Unlock()
	if !rebound || service.kernel != old || !service.kernelSettled || !service.kernelStreamsSaved || service.ready {
		t.Fatal("unstarted cleanup did not restore the warm old-handle alias for absent custody")
	}
	if replay, _, _, replayErr := labRecoverySettleUnstartedKernel(ctx, owned); replayErr == nil || replay.Schema != "" {
		t.Fatal("actual Linux unstarted wrapper cleanup replayed")
	}
}

func TestLabRecoveryUnstartedCleanupRejectsProcessUnknownAndUnjoinedMODEL(t *testing.T) {
	started, _ := labKernelModelStart(t, "quiet")
	if receipt, _, _, err := labRecoverySettleUnstartedKernel(context.Background(), started); err == nil || receipt.Schema != "" {
		t.Fatal("MODEL running process entered no-process cleanup")
	}
	if _, err := started.stop(context.Background()); err != nil && err != errLabKernelStop {
		t.Fatal("MODEL started process cleanup failed")
	}
	if receipt, _, _, err := labRecoverySettleUnstartedKernel(context.Background(), started); err == nil || receipt.Schema != "" {
		t.Fatal("MODEL exited process entered no-process cleanup")
	}

	unknown := &ownedLabKernel{&ownedLabKernelCore{done: make(chan struct{}), cancel: func() {}, stdout: &labKernelWriter{}, stderr: &labKernelWriter{}, exit: labKernelExit{WaitErrorClass: "NOT_WAITED"}}}
	if receipt, _, _, err := labRecoverySettleUnstartedKernel(context.Background(), unknown); err == nil || receipt.Schema != "" || unknown.closed {
		t.Fatal("MODEL unknown Start state was consumed or closed")
	}

	unjoined := &ownedLabKernel{&ownedLabKernelCore{done: make(chan struct{}), cancel: func() {}, startKnown: true,
		stdout: &labKernelWriter{}, stderr: &labKernelWriter{}, exit: labKernelExit{WaitErrorClass: "NOT_WAITED"}}}
	joinCtx, joinCancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer joinCancel()
	if receipt, _, _, err := labRecoverySettleUnstartedKernel(joinCtx, unjoined); err == nil || receipt.Schema != "" || !unjoined.closed {
		t.Fatal("MODEL unjoined source returned custody or remained reusable")
	}
}
