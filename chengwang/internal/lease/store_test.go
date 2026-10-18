package lease

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *manualClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *manualClock) Set(value time.Time) {
	clock.mu.Lock()
	clock.now = value
	clock.mu.Unlock()
}

func (clock *manualClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

var testScope = Scope{Tenant: "tenant-a", Site: "site-1", Object: "router-254", Environment: "production"}

func newTestStore(t *testing.T, directory string, clock Clock) *FileStore {
	t.Helper()
	store, err := NewFileStore(directory, WithClock(clock))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestAcquireRenewReleaseAndFencingHistoryAcrossRestart(t *testing.T) {
	directory := t.TempDir()
	clock := &manualClock{now: time.Date(2026, 10, 18, 8, 0, 0, 0, time.UTC)}
	store := newTestStore(t, directory, clock)

	first, err := store.Acquire(testScope, "controller-a", time.Minute)
	if err != nil || first.Token != 1 {
		t.Fatalf("first Acquire = %#v, %v", first, err)
	}
	clock.Advance(10 * time.Second)
	renewed, err := store.Renew(testScope, "controller-a", first.Token, 2*time.Minute)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if renewed.Token != first.Token || !renewed.ExpiresAt.Equal(clock.Now().Add(2*time.Minute)) {
		t.Fatalf("unexpected renewal: %#v", renewed)
	}
	if err := store.Release(testScope, "controller-a", first.Token); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := store.Get(testScope); !errors.Is(err, ErrLeaseNotHeld) {
		t.Fatalf("Get after release = %v, want ErrLeaseNotHeld", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened := newTestStore(t, directory, clock)
	second, err := reopened.Acquire(testScope, "controller-b", time.Minute)
	if err != nil {
		t.Fatalf("Acquire after restart: %v", err)
	}
	if second.Token != 2 {
		t.Fatalf("token after release and restart = %d, want 2", second.Token)
	}
}

func TestExpiredLeaseCanBeTakenOverWithHigherToken(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)}
	store := newTestStore(t, t.TempDir(), clock)
	first, err := store.Acquire(testScope, "controller-a", MinTTL)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(MinTTL) // Expiry is exclusive: equality is expired.
	if _, err := store.Get(testScope); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("Get expired = %v, want ErrLeaseExpired", err)
	}
	if _, err := store.Renew(testScope, "controller-a", first.Token, MinTTL); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("Renew expired = %v, want ErrLeaseExpired", err)
	}
	second, err := store.Acquire(testScope, "controller-b", MinTTL)
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if second.Token != first.Token+1 || second.Owner != "controller-b" {
		t.Fatalf("unexpected takeover lease: %#v", second)
	}
}

func TestOwnerAndTokenMismatchAreRejected(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)}
	store := newTestStore(t, t.TempDir(), clock)
	value, err := store.Acquire(testScope, "controller-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Renew(testScope, "controller-b", value.Token, time.Minute); !errors.Is(err, ErrOwnerMismatch) {
		t.Fatalf("wrong owner renew = %v", err)
	}
	if _, err := store.Renew(testScope, "controller-a", value.Token+1, time.Minute); !errors.Is(err, ErrTokenMismatch) {
		t.Fatalf("wrong token renew = %v", err)
	}
	if err := store.Release(testScope, "controller-b", value.Token); !errors.Is(err, ErrOwnerMismatch) {
		t.Fatalf("wrong owner release = %v", err)
	}
	if err := store.Release(testScope, "controller-a", value.Token+1); !errors.Is(err, ErrTokenMismatch) {
		t.Fatalf("wrong token release = %v", err)
	}
	active, err := store.Get(testScope)
	if err != nil || active != value {
		t.Fatalf("mismatch attempts changed lease: %#v, %v", active, err)
	}
}

func TestTTLBoundsAndStableScopeValidation(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 10, 18, 11, 0, 0, 0, time.UTC)}
	store := newTestStore(t, t.TempDir(), clock)
	for _, ttl := range []time.Duration{0, MinTTL - time.Nanosecond, MaxTTL + time.Nanosecond} {
		if _, err := store.Acquire(testScope, "controller", ttl); err == nil {
			t.Fatalf("Acquire accepted invalid TTL %s", ttl)
		}
	}
	invalid := testScope
	invalid.Object = "../router"
	if _, err := store.Acquire(invalid, "controller", MinTTL); err == nil {
		t.Fatal("Acquire accepted traversal-like scope")
	}
	trimmed := testScope
	trimmed.Tenant = " tenant-a "
	lease, err := store.Acquire(trimmed, " controller ", MinTTL)
	if err != nil {
		t.Fatalf("Acquire canonical input: %v", err)
	}
	if lease.Scope != testScope || lease.Owner != "controller" {
		t.Fatalf("input was not canonicalized: %#v", lease)
	}
}

func TestConcurrentAcquireHasSingleWinner(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	store := newTestStore(t, t.TempDir(), clock)
	const contenders = 32
	start := make(chan struct{})
	results := make(chan error, contenders)
	var wait sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := store.Acquire(testScope, "controller", time.Minute)
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	winners, held := 0, 0
	for err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrLeaseHeld):
			held++
		default:
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if winners != 1 || held != contenders-1 {
		t.Fatalf("winners=%d held=%d", winners, held)
	}
}

func TestSecondWriterIsRejectedUntilClose(t *testing.T) {
	directory := t.TempDir()
	clock := &manualClock{now: time.Date(2026, 10, 18, 13, 0, 0, 0, time.UTC)}
	first, err := NewFileStore(directory, WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(directory, WithClock(clock)); !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("second NewFileStore = %v, want ErrStoreLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := NewFileStore(directory, WithClock(clock))
	if err != nil {
		t.Fatalf("open after close: %v", err)
	}
	_ = second.Close()
}

func TestClockRollbackPoisonsOpenStoreAndFailsRestart(t *testing.T) {
	directory := t.TempDir()
	initial := time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC)
	clock := &manualClock{now: initial}
	store := newTestStore(t, directory, clock)
	if _, err := store.Acquire(testScope, "controller", time.Minute); err != nil {
		t.Fatal(err)
	}
	clock.Set(initial.Add(-time.Second))
	if _, err := store.Get(testScope); !errors.Is(err, ErrClockRollback) || !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("rollback Get = %v, want clock rollback and poisoned", err)
	}
	clock.Set(initial.Add(time.Hour))
	if _, err := store.Get(testScope); !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("poison did not persist in memory: %v", err)
	}
	_ = store.Close()

	clock.Set(initial.Add(-time.Second))
	if _, err := NewFileStore(directory, WithClock(clock)); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("restart under rollback = %v, want ErrClockRollback", err)
	}
}

func TestUncertainCommitPoisonsStoreButDefiniteFailureDoesNot(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 10, 18, 15, 0, 0, 0, time.UTC)}
	store := newTestStore(t, t.TempDir(), clock)
	original := store.write
	store.write = func(string, snapshot) writeResult {
		return writeResult{state: commitNotCommitted, err: errors.New("disk full")}
	}
	if _, err := store.Acquire(testScope, "controller", time.Minute); err == nil || errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("definite failure = %v", err)
	}
	store.write = original
	if _, err := store.Acquire(testScope, "controller", time.Minute); err != nil {
		t.Fatalf("retry after definite failure: %v", err)
	}

	otherScope := testScope
	otherScope.Object = "router-253"
	store.write = func(string, snapshot) writeResult {
		return writeResult{state: commitUncertain, err: errors.New("directory sync failed")}
	}
	if _, err := store.Acquire(otherScope, "controller", time.Minute); !errors.Is(err, ErrCommitUncertain) || !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("uncertain failure = %v", err)
	}
	store.write = original
	if _, err := store.Get(testScope); !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("store accepted request after uncertainty: %v", err)
	}
}

func TestAtomicWriterReportsDirectorySyncUncertainty(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, snapshotName)
	now := time.Date(2026, 10, 18, 16, 0, 0, 0, time.UTC)
	result := writeSnapshotWithSync(path, snapshot{Version: schemaVersion, LastObservedAt: now, Records: []record{}}, func(string) error {
		return errors.New("fsync unavailable")
	})
	if result.state != commitUncertain || !errors.Is(commitError(result), ErrCommitUncertain) {
		t.Fatalf("write result = %#v", result)
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("renamed snapshot should be visible despite uncertain durability: %v, %#v", err, info)
	}
}

func TestSnapshotAndPathTamperingFailClosed(t *testing.T) {
	t.Run("snapshot replaced while open", func(t *testing.T) {
		directory := t.TempDir()
		clock := &manualClock{now: time.Date(2026, 10, 18, 16, 30, 0, 0, time.UTC)}
		store := newTestStore(t, directory, clock)
		path := filepath.Join(directory, snapshotName)
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		replacement := filepath.Join(directory, "replacement")
		contents = append(contents, ' ')
		if err := os.WriteFile(replacement, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Acquire(testScope, "controller", time.Minute); !errors.Is(err, ErrStorePoisoned) {
			t.Fatalf("Acquire after external replacement = %v, want ErrStorePoisoned", err)
		}
	})

	t.Run("unknown JSON field", func(t *testing.T) {
		directory := t.TempDir()
		clock := &manualClock{now: time.Date(2026, 10, 18, 17, 0, 0, 0, time.UTC)}
		store := newTestStore(t, directory, clock)
		_ = store.Close()
		path := filepath.Join(directory, snapshotName)
		if err := os.WriteFile(path, []byte(`{"version":1,"lastObservedAt":"2026-10-18T17:00:00Z","records":[],"extra":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewFileStore(directory, WithClock(clock)); err == nil {
			t.Fatal("corrupt snapshot was accepted")
		}
	})

	t.Run("snapshot symlink", func(t *testing.T) {
		if os.Getenv("GOOS") == "windows" {
			t.Skip("symlink privileges are environment-specific on Windows")
		}
		directory := t.TempDir()
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(directory, snapshotName)); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		clock := &manualClock{now: time.Date(2026, 10, 18, 17, 0, 0, 0, time.UTC)}
		if _, err := NewFileStore(directory, WithClock(clock)); err == nil {
			t.Fatal("snapshot symlink was accepted")
		}
	})
}

func TestCloseIsIdempotentAndMethodsFailClosed(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 10, 18, 18, 0, 0, 0, time.UTC)}
	store, err := NewFileStore(t.TempDir(), WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acquire(testScope, "controller", time.Minute); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Acquire after Close = %v", err)
	}
}
