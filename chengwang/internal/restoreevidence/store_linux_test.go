//go:build linux && restoreevidence_root

package restoreevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"chengwang/internal/restorecontracts"
)

func linuxTestDirectory(t testing.TB) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("authoritative Linux persistence tests require uid 0")
	}
	root := os.Getenv("RESTOREEVIDENCE_ROOT_TEST_DIR")
	if root == "" || !pathpkg.IsAbs(root) || pathpkg.Clean(root) != root || root == "/root" || !strings.HasPrefix(root, "/root/") {
		t.Fatal("RESTOREEVIDENCE_ROOT_TEST_DIR must be a clean absolute directory below /root")
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat root fixture: %v", err)
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != 0 || rootStat.Gid != 0 || rootInfo.Mode().Perm()&0o022 != 0 {
		t.Fatal("root fixture must be root:root and not group/world writable")
	}
	dir, err := os.MkdirTemp(root, "case-")
	if err != nil {
		t.Fatalf("create root fixture: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dir, &fs); err != nil {
		t.Fatal(err)
	}
	if uint64(fs.Type) != ext4SuperMagic && uint64(fs.Type) != xfsSuperMagic {
		t.Fatalf("fixture filesystem must be ext4 or XFS, got type=0x%x", uint64(fs.Type))
	}
	return dir
}

func openLinuxTestStore(t testing.TB, dir string, clock clockSnapshot, fault faultInjector) *Store {
	t.Helper()
	s, err := openForTest(dir, testOptions{clock: func() (clockSnapshot, error) { return clock, nil }, fault: fault})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestLinuxPublishReadAndIdempotence(t *testing.T) {
	dir := linuxTestDirectory(t)
	raw, context, clock := evidenceFixture(t)
	s := openLinuxTestStore(t, dir, clock, nil)
	result, err := s.Publish(raw, context)
	if err != nil {
		t.Fatal(err)
	}
	if result.CommitState() != Committed || result.Reliability() != ReliabilityLinuxDurable || result.MountID() == 0 || string(result.RawBytes()) != string(raw) {
		t.Fatalf("unexpected result state=%s reliability=%s mount=%d", result.CommitState(), result.Reliability(), result.MountID())
	}
	info, err := os.Stat(filepath.Join(dir, result.Name()))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}
	read, err := s.Read(context)
	if err != nil || read.RawSHA256() != result.RawSHA256() || string(read.RawBytes()) != string(raw) {
		t.Fatalf("read=%+v err=%v", read, err)
	}
	idempotent, err := s.Publish(raw, context)
	if err != nil || idempotent.CommitState() != Committed || idempotent.Inode() != result.Inode() {
		t.Fatalf("idempotent=%+v err=%v", idempotent, err)
	}
}

func TestLinuxPlatformClockUsesKernelSources(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	first, err := platformClock()
	if err != nil {
		t.Fatal(err)
	}
	second, err := platformClock()
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC().Add(time.Second)
	if first.Wall.Before(before) || first.Wall.After(after) || second.Wall.Before(first.Wall) {
		t.Fatalf("unexpected wall clock samples: first=%s second=%s", first.Wall, second.Wall)
	}
	bootIDPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if first.BootID != second.BootID || !bootIDPattern.MatchString(first.BootID) {
		t.Fatalf("invalid or unstable boot ID: first=%q second=%q", first.BootID, second.BootID)
	}
	if first.BoottimeNS == 0 || second.BoottimeNS < first.BoottimeNS {
		t.Fatalf("invalid CLOCK_BOOTTIME samples: first=%d second=%d", first.BoottimeNS, second.BoottimeNS)
	}
}

func TestLinuxPublishRejectsInvalidAndStaleInputs(t *testing.T) {
	raw, context, clock := evidenceFixture(t)
	cases := []struct {
		name   string
		mutate func([]byte, restorecontracts.EvidenceContext, clockSnapshot) ([]byte, restorecontracts.EvidenceContext, clockSnapshot)
		want   error
	}{
		{name: "digest mismatch", want: ErrDigestMismatch, mutate: func(b []byte, c restorecontracts.EvidenceContext, k clockSnapshot) ([]byte, restorecontracts.EvidenceContext, clockSnapshot) {
			c.RawBytesSHA256 = hex.EncodeToString(make([]byte, 32))
			return b, c, k
		}},
		{name: "missing field", mutate: func(b []byte, c restorecontracts.EvidenceContext, k clockSnapshot) ([]byte, restorecontracts.EvidenceContext, clockSnapshot) {
			var v map[string]any
			_ = json.Unmarshal(b, &v)
			delete(v, "schema")
			b, _ = json.Marshal(v)
			b, c = withRawHashLinux(b, c)
			return b, c, k
		}},
		{name: "expired", mutate: func(b []byte, c restorecontracts.EvidenceContext, k clockSnapshot) ([]byte, restorecontracts.EvidenceContext, clockSnapshot) {
			k.Wall = fixtureNow.Add(30 * time.Second)
			return b, c, k
		}},
		{name: "future wall", mutate: func(b []byte, c restorecontracts.EvidenceContext, k clockSnapshot) ([]byte, restorecontracts.EvidenceContext, clockSnapshot) {
			k.Wall = fixtureNow.Add(-10 * time.Second)
			return b, c, k
		}},
		{name: "boot mismatch", mutate: func(b []byte, c restorecontracts.EvidenceContext, k clockSnapshot) ([]byte, restorecontracts.EvidenceContext, clockSnapshot) {
			k.BootID = "223e4567-e89b-42d3-a456-426614174000"
			return b, c, k
		}},
		{name: "boottime stale", mutate: func(b []byte, c restorecontracts.EvidenceContext, k clockSnapshot) ([]byte, restorecontracts.EvidenceContext, clockSnapshot) {
			k.BoottimeNS += uint64(10 * time.Second)
			return b, c, k
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := linuxTestDirectory(t)
			input, expected, now := tc.mutate(append([]byte(nil), raw...), context, clock)
			s := openLinuxTestStore(t, dir, now, nil)
			result, err := s.Publish(input, expected)
			if err == nil || result.CommitState() != NotCommitted {
				t.Fatalf("state=%s err=%v", result.CommitState(), err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("wanted %v got %v", tc.want, err)
			}
			name, _ := evidenceNameFromContext(expected)
			if _, statErr := os.Stat(filepath.Join(dir, name)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("invalid input was published: %v", statErr)
			}
		})
	}
}

func TestLinuxFaultStagesAreTriStateAndPoisonAfterLink(t *testing.T) {
	raw, context, clock := evidenceFixture(t)
	for _, stage := range allFaultStages {
		t.Run(string(stage), func(t *testing.T) {
			dir := linuxTestDirectory(t)
			injected := errors.New("injected failure")
			s := openLinuxTestStore(t, dir, clock, func(got faultStage) error {
				if got == stage {
					return injected
				}
				return nil
			})
			result, err := s.Publish(raw, context)
			if !errors.Is(err, injected) {
				t.Fatalf("error=%v", err)
			}
			postLink := faultAtOrAfter(stage, faultAfterLink)
			postCommit := faultAtOrAfter(stage, faultAfterCommitDirectoryFsync)
			wantState := NotCommitted
			if postLink {
				wantState = Uncertain
			}
			if postCommit {
				wantState = Committed
			}
			if result.CommitState() != wantState {
				t.Fatalf("state=%s want=%s", result.CommitState(), wantState)
			}
			name, _ := evidenceNameFromContext(context)
			_, statErr := os.Stat(filepath.Join(dir, name))
			if postLink && statErr != nil {
				t.Fatalf("authoritative target lost after link: %v", statErr)
			}
			if !postLink && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("pre-link target exists: %v", statErr)
			}
			if postLink {
				if _, err := s.ReadDiagnostic(context); !errors.Is(err, ErrPoisoned) {
					t.Fatalf("store not poisoned: %v", err)
				}
			}
			matches, _ := filepath.Glob(filepath.Join(dir, tempPrefix+"*"))
			if postLink && !postCommit && len(matches) != 1 {
				t.Fatalf("pre-commit post-link failure must preserve one temporary: %v", matches)
			}
			if !postLink && len(matches) != 0 {
				t.Fatalf("pre-link cleanup left temporary files: %v", matches)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if postLink && len(matches) != 0 {
				if reopened, err := Open(dir); !errors.Is(err, ErrUnsafeObject) {
					if reopened != nil {
						_ = reopened.Close()
					}
					t.Fatalf("reopen must reject preserved orphan: %v", err)
				}
			} else if postCommit {
				reopened, err := Open(dir)
				if err != nil {
					t.Fatalf("reopen committed target: %v", err)
				}
				defer reopened.Close()
				if got, err := reopened.ReadDiagnostic(context); err != nil || string(got.RawBytes()) != string(raw) {
					t.Fatalf("committed target not complete: err=%v", err)
				}
			}
		})
	}
}

func TestLinuxEEXISTCleanupFailureIsNeverIdempotentSuccess(t *testing.T) {
	dir := linuxTestDirectory(t)
	raw, context, clock := evidenceFixture(t)
	s := openLinuxTestStore(t, dir, clock, nil)
	if _, err := s.Publish(raw, context); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("cleanup fsync injected")
	s.fault = func(stage faultStage) error {
		if stage == faultBeforeCleanupDirectoryFsync {
			return injected
		}
		return nil
	}
	result, err := s.Publish(raw, context)
	if !errors.Is(err, injected) || result.CommitState() != NotCommitted {
		t.Fatalf("EEXIST cleanup failure state=%s err=%v", result.CommitState(), err)
	}
	if _, err := s.ReadDiagnostic(context); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("EEXIST cleanup uncertainty did not poison: %v", err)
	}
}

func TestLinuxReadbackRejectsSameLengthMutation(t *testing.T) {
	dir := linuxTestDirectory(t)
	raw, context, clock := evidenceFixture(t)
	name, err := evidenceNameFromContext(context)
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), raw...)
	mutated[len(mutated)-2] ^= 1
	s := openLinuxTestStore(t, dir, clock, func(stage faultStage) error {
		if stage != faultBeforeReadback {
			return nil
		}
		return os.WriteFile(filepath.Join(dir, name), mutated, 0o600)
	})
	result, err := s.Publish(raw, context)
	if err == nil || result.CommitState() != Committed {
		t.Fatalf("state=%s err=%v", result.CommitState(), err)
	}
	if _, err := s.ReadDiagnostic(context); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("mutated readback did not poison store: %v", err)
	}
}

func TestLinuxConflictPoisonsButNeverOverwrites(t *testing.T) {
	dir := linuxTestDirectory(t)
	raw, context, clock := evidenceFixture(t)
	s := openLinuxTestStore(t, dir, clock, nil)
	first, err := s.Publish(raw, context)
	if err != nil {
		t.Fatal(err)
	}
	other, otherContext := evidenceWithReason(t, raw, context, "OPERATOR_RECHECK")
	result, err := s.Publish(other, otherContext)
	if !errors.Is(err, ErrConflict) || result.CommitState() != NotCommitted {
		t.Fatalf("state=%s err=%v", result.CommitState(), err)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, first.Name()))
	if err != nil || string(onDisk) != string(raw) {
		t.Fatal("conflict overwrote authoritative evidence")
	}
	if _, err := s.Publish(raw, context); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("conflict did not poison instance: %v", err)
	}
}

func TestLinuxConcurrentDifferentBytesHasOneWinner(t *testing.T) {
	dir := linuxTestDirectory(t)
	raw, context, clock := evidenceFixture(t)
	s := openLinuxTestStore(t, dir, clock, nil)
	const count = 8
	var wg sync.WaitGroup
	states := make(chan CommitState, count)
	for i := 0; i < count; i++ {
		input, expected := evidenceWithReason(t, raw, context, fmt.Sprintf("CONCURRENT_%d", i))
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, _ := s.Publish(input, expected)
			states <- result.CommitState()
		}()
	}
	wg.Wait()
	close(states)
	winners := 0
	for state := range states {
		if state == Committed {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("committed winners=%d", winners)
	}
}

func TestLinuxRejectsUnsafeObjectsDirectoryRebindLockAndOrphan(t *testing.T) {
	raw, context, clock := evidenceFixture(t)
	name, _ := evidenceNameFromContext(context)
	t.Run("symlink target", func(t *testing.T) {
		dir := linuxTestDirectory(t)
		source := filepath.Join(dir, "source")
		if err := os.WriteFile(source, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(source, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		s := openLinuxTestStore(t, dir, clock, nil)
		if _, err := s.Publish(raw, context); !errors.Is(err, ErrConflict) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("hardlink target", func(t *testing.T) {
		dir := linuxTestDirectory(t)
		source := filepath.Join(dir, "source")
		if err := os.WriteFile(source, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(source, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		s := openLinuxTestStore(t, dir, clock, nil)
		if _, err := s.Publish(raw, context); !errors.Is(err, ErrConflict) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("lock replacement", func(t *testing.T) {
		dir := linuxTestDirectory(t)
		s := openLinuxTestStore(t, dir, clock, nil)
		if err := os.Remove(filepath.Join(dir, lockFilename)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, lockFilename), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Publish(raw, context); !errors.Is(err, ErrUnsafeObject) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("orphan left for inspection", func(t *testing.T) {
		dir := linuxTestDirectory(t)
		orphan := filepath.Join(dir, tempPrefix+"0123456789abcdef01234567")
		if err := os.WriteFile(orphan, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir); !errors.Is(err, ErrUnsafeObject) {
			t.Fatalf("got %v", err)
		}
		if _, err := os.Stat(orphan); err != nil {
			t.Fatalf("orphan was removed: %v", err)
		}
	})
	t.Run("directory replacement", func(t *testing.T) {
		dir := linuxTestDirectory(t)
		old := dir + "-old"
		var once sync.Once
		s := openLinuxTestStore(t, dir, clock, func(stage faultStage) error {
			if stage == faultBeforeLink {
				once.Do(func() {
					if err := os.Rename(dir, old); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				})
			}
			return nil
		})
		result, err := s.Publish(raw, context)
		if !errors.Is(err, ErrUnsafeObject) || result.CommitState() != NotCommitted {
			t.Fatalf("state=%s err=%v", result.CommitState(), err)
		}
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("published into replacement: %v", err)
		}
		_ = s.Close()
		_ = os.RemoveAll(dir)
		if err := os.Rename(old, dir); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLinuxExclusiveWriterLock(t *testing.T) {
	dir := linuxTestDirectory(t)
	_, _, clock := evidenceFixture(t)
	first := openLinuxTestStore(t, dir, clock, nil)
	if _, err := Open(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second writer error=%v", err)
	}
	_ = first.Close()
}

func TestLinuxSecurityMetadataAndDirectoryLimit(t *testing.T) {
	t.Run("gid rejected", func(t *testing.T) {
		st := syscall.Stat_t{Mode: syscall.S_IFREG | 0o600, Uid: 0, Gid: 1, Nlink: 1}
		if err := secureFileStat("bad", st, 1); !errors.Is(err, ErrUnsafeObject) {
			t.Fatalf("got %v", err)
		}
		dirStat := syscall.Stat_t{Mode: syscall.S_IFDIR | 0o700, Uid: 0, Gid: 1}
		if err := secureDirectoryStat(dirStat, true); !errors.Is(err, ErrUnsafeObject) {
			t.Fatalf("directory gid got %v", err)
		}
	})
	t.Run("device and mount mismatch", func(t *testing.T) {
		dir := linuxTestDirectory(t)
		fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.Close(fd)
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			t.Fatal(err)
		}
		mount, err := mountIDForFD(fd)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, "bound")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		fileFD, err := syscall.Open(file, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.Close(fileFD)
		var fileStat syscall.Stat_t
		if err := syscall.Fstat(fileFD, &fileStat); err != nil {
			t.Fatal(err)
		}
		badDev := st
		badDev.Dev++
		if _, err := secureBoundFileStat(fileFD, "bound", fileStat, 1, badDev, mount); !errors.Is(err, ErrUnsafeObject) {
			t.Fatalf("device mismatch=%v", err)
		}
		if _, err := secureBoundFileStat(fileFD, "bound", fileStat, 1, st, mount+1); !errors.Is(err, ErrUnsafeObject) {
			t.Fatalf("mount mismatch=%v", err)
		}
	})
	t.Run("directory entry cap", func(t *testing.T) {
		dir := linuxTestDirectory(t)
		for i := 0; i < maxDirectoryEntries; i++ {
			name := filepath.Join(dir, fmt.Sprintf("entry-%04d", i))
			if err := os.WriteFile(name, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if store, err := Open(dir); !errors.Is(err, ErrDirectoryLimit) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("got %v", err)
		}
	})
	t.Run("long lived store preserves publish headroom", func(t *testing.T) {
		dir := linuxTestDirectory(t)
		raw, context, clock := evidenceFixture(t)
		s := openLinuxTestStore(t, dir, clock, nil)
		for i := 0; i < maxDirectoryEntries-3; i++ {
			name := filepath.Join(dir, fmt.Sprintf("late-entry-%04d", i))
			if err := os.WriteFile(name, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		first, err := s.Publish(raw, context)
		if err != nil || first.CommitState() != Committed {
			t.Fatalf("boundary publish state=%s err=%v", first.CommitState(), err)
		}
		retry, err := s.Publish(raw, context)
		if err != nil || retry.CommitState() != Committed || retry.Inode() != first.Inode() {
			t.Fatalf("boundary retry state=%s err=%v", retry.CommitState(), err)
		}
		newRaw, newContext := evidenceWithOperation(t, raw, context, "restore-02")
		result, err := s.Publish(newRaw, newContext)
		if !errors.Is(err, ErrDirectoryLimit) || result.CommitState() != NotCommitted {
			t.Fatalf("state=%s err=%v", result.CommitState(), err)
		}
		name, _ := evidenceNameFromContext(newContext)
		if _, statErr := os.Stat(filepath.Join(dir, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("capacity failure published target: %v", statErr)
		}
	})
	t.Run("near cap target name must still be a secure file", func(t *testing.T) {
		dir := linuxTestDirectory(t)
		raw, context, clock := evidenceFixture(t)
		name, err := evidenceNameFromContext(context)
		if err != nil {
			t.Fatal(err)
		}
		s := openLinuxTestStore(t, dir, clock, nil)
		if err := os.Symlink("missing", filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < maxDirectoryEntries-3; i++ {
			entry := filepath.Join(dir, fmt.Sprintf("unsafe-entry-%04d", i))
			if err := os.WriteFile(entry, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		result, err := s.Publish(raw, context)
		if !errors.Is(err, ErrUnsafeObject) || result.CommitState() != NotCommitted {
			t.Fatalf("state=%s err=%v", result.CommitState(), err)
		}
		matches, err := filepath.Glob(filepath.Join(dir, tempPrefix+"*"))
		if err != nil || len(matches) != 0 {
			t.Fatalf("unsafe near-cap target created a temporary: %v err=%v", matches, err)
		}
	})
}

func faultAtOrAfter(stage, boundary faultStage) bool {
	stageIndex, boundaryIndex := -1, -1
	for index, item := range allFaultStages {
		if item == stage {
			stageIndex = index
		}
		if item == boundary {
			boundaryIndex = index
		}
	}
	return stageIndex >= boundaryIndex && boundaryIndex >= 0
}

func evidenceWithReason(t testing.TB, raw []byte, context restorecontracts.EvidenceContext, reason string) ([]byte, restorecontracts.EvidenceContext) {
	t.Helper()
	var value restorecontracts.RestoreEvidenceV1
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	value.ReasonCode = reason
	changed, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	context.ReasonCode = reason
	return withRawHashLinux(changed, context)
}

func evidenceWithOperation(t testing.TB, raw []byte, context restorecontracts.EvidenceContext, operationID string) ([]byte, restorecontracts.EvidenceContext) {
	t.Helper()
	var value restorecontracts.RestoreEvidenceV1
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	value.OperationID = operationID
	changed, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	context.OperationID = operationID
	return withRawHashLinux(changed, context)
}

func withRawHashLinux(raw []byte, context restorecontracts.EvidenceContext) ([]byte, restorecontracts.EvidenceContext) {
	sum := sha256.Sum256(raw)
	context.RawBytesSHA256 = hex.EncodeToString(sum[:])
	return raw, context
}
