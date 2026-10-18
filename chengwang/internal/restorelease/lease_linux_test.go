//go:build linux && restorelease_root

package restorelease

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func rootFixture(t *testing.T) (string, acquireOptions) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("restorelease root tests require uid 0")
	}
	root := os.Getenv("RESTORELEASE_ROOT_TEST_DIR")
	if root == "" {
		t.Fatal("RESTORELEASE_ROOT_TEST_DIR is required")
	}
	caseRoot, err := os.MkdirTemp(root, "lease-case-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(caseRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	root = caseRoot
	trustedParent := filepath.Join(root, "trusted")
	base := filepath.Join(trustedParent, "candidate-base")
	candidate := filepath.Join(base, "probe1")
	global := filepath.Join(root, "run")
	for _, directory := range []string{root, trustedParent, base, candidate, global} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(candidate, candidateMarkerName), []byte(candidateMarkerValue), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(candidate, candidateMarkerName), 0o600); err != nil {
		t.Fatal(err)
	}
	return candidate, acquireOptions{globalDir: global, candidateBase: base, testOnly: true}
}

func TestLinuxLeaseAcquiresExactGlobalAndCandidateLocks(t *testing.T) {
	candidate, options := rootFixture(t)
	p, identity, err := acquireWithOptions(candidate, options)
	if err != nil {
		t.Fatal(err)
	}
	lease := &Lease{platform: p, identity: identity}
	defer lease.Close()
	if err := lease.Verify(); err != nil {
		t.Fatal(err)
	}
	if identity.CandidateRoot != candidate || identity.GlobalLock.Inode == 0 || identity.CandidateLock.MountID == 0 {
		t.Fatalf("incomplete identity: %+v", identity)
	}
	for _, path := range []string{filepath.Join(options.globalDir, globalLockName), filepath.Join(candidate, candidateLockName)} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 || info.Size() != 0 || !info.Mode().IsRegular() {
			t.Fatalf("unsafe lock metadata at %s: %v", path, info.Mode())
		}
	}
}

func TestLinuxLeaseProductionAcquireUsesFixedPaths(t *testing.T) {
	candidate := os.Getenv("RESTORELEASE_PRODUCTION_ROOT")
	if candidate != "/var/lib/chengwang-m2b-candidate/prod1" {
		t.Fatalf("unexpected production fixture %q", candidate)
	}
	if err := os.MkdirAll(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(candidate), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, candidateMarkerName), []byte(candidateMarkerValue), 0o600); err != nil {
		t.Fatal(err)
	}
	lease, err := Acquire(candidate)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if lease.CandidateRoot() != candidate || lease.Identity().GlobalDir.MountID == 0 {
		t.Fatalf("production identity=%+v", lease.Identity())
	}
	if err := lease.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxLeaseExcludesSecondGoHolder(t *testing.T) {
	candidate, options := rootFixture(t)
	first, _, err := acquireWithOptions(candidate, options)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	if second, _, err := acquireWithOptions(candidate, options); !errors.Is(err, ErrBusy) {
		if second != nil {
			_ = second.close()
		}
		t.Fatalf("second holder error=%v", err)
	}
}

func TestLinuxLeaseShellHolderBlocksGo(t *testing.T) {
	candidate, options := rootFixture(t)
	flock := requireFlock(t)
	globalLock := filepath.Join(options.globalDir, globalLockName)
	if err := os.WriteFile(globalLock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(globalLock, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(flock, "-n", globalLock, "/bin/sh", "-c", "echo locked; exec sleep 30")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
			return
		}
		ready <- ""
	}()
	select {
	case line := <-ready:
		if line != "locked" {
			t.Fatalf("shell holder did not report readiness: %q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shell holder readiness timed out")
	}
	if lease, _, err := acquireWithOptions(candidate, options); !errors.Is(err, ErrBusy) {
		if lease != nil {
			_ = lease.close()
		}
		t.Fatalf("Go acquisition while shell holds global lock: %v", err)
	}
}

func TestLinuxLeaseGoHolderBlocksShell(t *testing.T) {
	candidate, options := rootFixture(t)
	flock := requireFlock(t)
	p, _, err := acquireWithOptions(candidate, options)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	lockPath := filepath.Join(candidate, candidateLockName)
	command := exec.Command(flock, "-n", lockPath, "/bin/true")
	err = command.Run()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 {
		t.Fatalf("shell contention exit=%v", err)
	}
	if err := p.close(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(flock, "-n", lockPath, "/bin/true").Run(); err != nil {
		t.Fatalf("shell could not acquire lock after Go release: %v", err)
	}
}

func TestLinuxLeaseCloseIsIdempotentAndReopens(t *testing.T) {
	candidate, options := rootFixture(t)
	p, identity, err := acquireWithOptions(candidate, options)
	if err != nil {
		t.Fatal(err)
	}
	lease := &Lease{platform: p, identity: identity}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed Verify error=%v", err)
	}
	reopened, _, err := acquireWithOptions(candidate, options)
	if err != nil {
		t.Fatal(err)
	}
	_ = reopened.close()
}

func TestLinuxLeaseDetectsCandidateLockReplacementAndPoisons(t *testing.T) {
	candidate, options := rootFixture(t)
	p, identity, err := acquireWithOptions(candidate, options)
	if err != nil {
		t.Fatal(err)
	}
	lease := &Lease{platform: p, identity: identity}
	defer lease.Close()
	lockPath := filepath.Join(candidate, candidateLockName)
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("replacement error=%v", err)
	}
	if err := lease.Verify(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("poison was not sticky: %v", err)
	}
}

func TestLinuxLeaseDetectsMarkerReplacementAndPoisons(t *testing.T) {
	candidate, options := rootFixture(t)
	p, identity, err := acquireWithOptions(candidate, options)
	if err != nil {
		t.Fatal(err)
	}
	lease := &Lease{platform: p, identity: identity}
	defer lease.Close()
	markerPath := filepath.Join(candidate, candidateMarkerName)
	if err := os.Remove(markerPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, []byte(candidateMarkerValue), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("replacement error=%v", err)
	}
}

func TestLinuxLeaseDetectsGlobalLockReplacementAndPoisons(t *testing.T) {
	candidate, options := rootFixture(t)
	p, identity, err := acquireWithOptions(candidate, options)
	if err != nil {
		t.Fatal(err)
	}
	lease := &Lease{platform: p, identity: identity}
	defer lease.Close()
	lockPath := filepath.Join(options.globalDir, globalLockName)
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("replacement error=%v", err)
	}
}

func TestLinuxLeaseDetectsCandidateDirectoryReplacementAndPoisons(t *testing.T) {
	candidate, options := rootFixture(t)
	p, identity, err := acquireWithOptions(candidate, options)
	if err != nil {
		t.Fatal(err)
	}
	lease := &Lease{platform: p, identity: identity}
	defer lease.Close()
	moved := candidate + "-moved"
	if err := os.Rename(candidate, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, candidateMarkerName), []byte(candidateMarkerValue), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("replacement error=%v", err)
	}
}

func TestLinuxLeaseDetectsEveryOtherHeldDirectoryReplacement(t *testing.T) {
	for _, target := range []string{"global", "trusted-parent", "base"} {
		t.Run(target, func(t *testing.T) {
			candidate, options := rootFixture(t)
			p, identity, err := acquireWithOptions(candidate, options)
			if err != nil {
				t.Fatal(err)
			}
			lease := &Lease{platform: p, identity: identity}
			defer lease.Close()
			path := options.globalDir
			switch target {
			case "trusted-parent":
				path = filepath.Dir(options.candidateBase)
			case "base":
				path = options.candidateBase
			}
			moved := path + "-moved"
			if err := os.Rename(path, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := lease.Verify(); !errors.Is(err, ErrPoisoned) {
				t.Fatalf("replacement error=%v", err)
			}
		})
	}
}

func TestLinuxLeaseDescriptorsAreCloseOnExec(t *testing.T) {
	candidate, options := rootFixture(t)
	p, _, err := acquireWithOptions(candidate, options)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	script := `for fd in /proc/self/fd/*; do target=$(readlink "$fd" 2>/dev/null || true); case "$target" in *chengwang-m2b-probe-lifecycle.lock|*.probe-lifecycle.lock|*candidate-base*|*/run) exit 42;; esac; done`
	if output, err := exec.Command("/bin/sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("lease descriptor leaked across exec: %v output=%q", err, output)
	}
}

func TestLinuxLeaseRejectsUnsafeMarkerAndLockObjects(t *testing.T) {
	t.Run("marker mode", func(t *testing.T) {
		candidate, options := rootFixture(t)
		if err := os.Chmod(filepath.Join(candidate, candidateMarkerName), 0o644); err != nil {
			t.Fatal(err)
		}
		if p, _, err := acquireWithOptions(candidate, options); err == nil {
			_ = p.close()
			t.Fatal("unsafe marker accepted")
		}
	})
	t.Run("marker special mode bits", func(t *testing.T) {
		candidate, options := rootFixture(t)
		if err := os.Chmod(filepath.Join(candidate, candidateMarkerName), 0o600|os.ModeSetuid); err != nil {
			t.Fatal(err)
		}
		if p, _, err := acquireWithOptions(candidate, options); err == nil {
			_ = p.close()
			t.Fatal("marker with special mode bits accepted")
		}
	})
	t.Run("hardlinked candidate lock", func(t *testing.T) {
		candidate, options := rootFixture(t)
		lockPath := filepath.Join(candidate, candidateLockName)
		if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(lockPath, filepath.Join(candidate, "lock-copy")); err != nil {
			t.Fatal(err)
		}
		if p, _, err := acquireWithOptions(candidate, options); err == nil {
			_ = p.close()
			t.Fatal("hardlinked lock accepted")
		}
	})
	t.Run("fifo candidate lock", func(t *testing.T) {
		candidate, options := rootFixture(t)
		if err := syscall.Mkfifo(filepath.Join(candidate, candidateLockName), 0o600); err != nil {
			t.Fatal(err)
		}
		if p, _, err := acquireWithOptions(candidate, options); err == nil {
			_ = p.close()
			t.Fatal("FIFO lock accepted")
		}
	})
}

func requireFlock(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("flock")
	if err != nil {
		t.Fatalf("util-linux flock is required for shell interoperability: %v", err)
	}
	return path
}
