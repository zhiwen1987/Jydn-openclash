//go:build linux && proberestore_root

package proberestore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

var (
	crashNonceFlag = flag.String("proberestore-crash-nonce", "", "internal crash-test nonce")
	crashDirFlag   = flag.String("proberestore-crash-dir", "", "internal crash-test control directory")
	crashStageFlag = flag.String("proberestore-crash-stage", "", "internal crash-test stage")
)

func TestMain(m *testing.M) {
	flag.Parse()
	mode := os.Getenv("PROBERESTORE_CRASH_HELPER")
	if mode == "" {
		if *crashNonceFlag != "" || *crashDirFlag != "" || *crashStageFlag != "" {
			fmt.Fprintln(os.Stderr, "crash helper flags require guarded helper mode")
			os.Exit(2)
		}
		os.Exit(m.Run())
	}
	if mode != "v1" {
		fmt.Fprintln(os.Stderr, "invalid crash helper mode")
		os.Exit(2)
	}
	if err := runLinuxCrashHelper(); err != nil {
		fmt.Fprintln(os.Stderr, "crash helper rejected or failed:", err)
		os.Exit(2)
	}
	// A successful helper always terminates itself at the requested syscall
	// boundary. Reaching this point must never be mistaken for a passing test.
	os.Exit(3)
}

func linuxControlDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("authoritative durability tests require root")
	}
	d, err := os.MkdirTemp("/root", "proberestore-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func openLinuxStore(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if errors.Is(err, ErrDurabilityUnsupported) {
		t.Fatalf("current /root filesystem is outside the ext4/XFS durability contract: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLinuxStoreCreateSaveReopenAndSingleWriter(t *testing.T) {
	d := linuxControlDir(t)
	s := openLinuxStore(t, d)
	j := validJournal(t)
	if err := s.Create(j); err != nil {
		t.Fatal(err)
	}
	next := advance(t, j, PhaseLocked)
	if err := s.Save(next); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(d); !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("second Open=%v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openLinuxStore(t, d)
	defer s.Close()
	got, err := s.Load()
	if err != nil || got.Sequence != 2 {
		t.Fatalf("Load=%v %v", got, err)
	}
}

func TestLinuxCommitFsyncFailurePoisonsStore(t *testing.T) {
	d := linuxControlDir(t)
	s := openLinuxStore(t, d)
	defer s.Close()
	s.commitFn = func(controlRecord) error { return errors.New("injected file fsync failure") }
	if err := s.Create(validJournal(t)); !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("Create=%v", err)
	}
	if _, err := s.Load(); !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("Load=%v", err)
	}
}

func TestLinuxTruncatedControlRecordFailsOnReopen(t *testing.T) {
	d := linuxControlDir(t)
	s := openLinuxStore(t, d)
	if err := s.Create(validJournal(t)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(d, controlFilename)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b[:len(b)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(d); err == nil {
		t.Fatal("truncated control record accepted")
	}
}

func TestLinuxOldCompleteControlReplayFailsClosed(t *testing.T) {
	d := linuxControlDir(t)
	s := openLinuxStore(t, d)
	defer s.Close()
	j := validJournal(t)
	if err := s.Create(j); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(filepath.Join(d, controlFilename))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(advance(t, j, PhaseLocked)); err != nil {
		t.Fatal(err)
	}
	if err := s.platform.replace(controlFilename, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); !errors.Is(err, ErrReplayDetected) || !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("Load replay=%v", err)
	}
}

func TestLinuxLockUnlinkRecreateDetected(t *testing.T) {
	d := linuxControlDir(t)
	s := openLinuxStore(t, d)
	defer s.Close()
	if err := os.Remove(filepath.Join(d, lockFilename)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, lockFilename), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(validJournal(t)); !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("Create=%v", err)
	}
}

func TestLinuxRejectsNonEmptyLock(t *testing.T) {
	d := linuxControlDir(t)
	if err := os.WriteFile(filepath.Join(d, lockFilename), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(d); err == nil {
		t.Fatal("non-empty lock accepted")
	}
}

func TestLinuxControlDirectoryPathReplacementDetected(t *testing.T) {
	d := linuxControlDir(t)
	s := openLinuxStore(t, d)
	defer s.Close()
	moved := d + "-moved"
	if err := os.Rename(d, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(moved) })
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(validJournal(t)); !errors.Is(err, ErrStorePoisoned) {
		t.Fatalf("Create=%v", err)
	}
}

func TestLinuxTerminalReceiptPreventsAllIdentityReplay(t *testing.T) {
	d := linuxControlDir(t)
	s := openLinuxStore(t, d)
	defer s.Close()
	j := validJournal(t)
	if err := s.Create(j); err != nil {
		t.Fatal(err)
	}
	terminal := advance(t, j, PhaseFailed)
	if err := s.Save(terminal); err != nil {
		t.Fatal(err)
	}
	sameBackup, err := New("restore-02", Identity{"site-a", "probe-a", j.Identity.BackupID}, Digests{hashOf('f'), hashOf('1'), hashOf('2'), hashOf('3')}, j.UpdatedAt.Add(10))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create(sameBackup); !errors.Is(err, ErrBackupConsumed) {
		t.Fatalf("same backup Create=%v", err)
	}
	sameOperation, err := New(j.OperationID, Identity{"site-a", "probe-a", "backup-02"}, Digests{hashOf('f'), hashOf('1'), hashOf('2'), hashOf('3')}, j.UpdatedAt.Add(10))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create(sameOperation); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("same operation Create=%v", err)
	}
	sameManifest, err := New("restore-03", Identity{"site-a", "probe-a", "backup-03"}, Digests{j.Digests.BackupManifestSHA256, hashOf('1'), hashOf('2'), hashOf('3')}, j.UpdatedAt.Add(10))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create(sameManifest); !errors.Is(err, ErrBackupConsumed) {
		t.Fatalf("same manifest with changed IDs Create=%v", err)
	}
}

func TestLinuxRejectsUnsafeAncestorsAndPermissions(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("authoritative durability tests require root")
	}
	unsafe, err := os.MkdirTemp("/tmp", "proberestore-unsafe-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(unsafe)
	if err := os.Chmod(unsafe, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(unsafe); err == nil {
		t.Fatal("world-writable /tmp ancestor accepted")
	}
	d := linuxControlDir(t)
	if err := os.Chmod(d, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(d); err == nil {
		t.Fatal("0750 dir accepted")
	}
}

func TestLinuxControlFilesRoot0600SingleLink(t *testing.T) {
	d := linuxControlDir(t)
	s := openLinuxStore(t, d)
	defer s.Close()
	if err := s.Create(validJournal(t)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{lockFilename, controlFilename} {
		var st syscall.Stat_t
		if err := syscall.Stat(filepath.Join(d, name), &st); err != nil {
			t.Fatal(err)
		}
		if st.Uid != 0 || st.Mode&0o777 != 0o600 || st.Nlink != 1 {
			t.Fatalf("%s metadata uid=%d mode=%o nlink=%d", name, st.Uid, st.Mode&0o777, st.Nlink)
		}
		if name == lockFilename && st.Size != 0 {
			t.Fatalf("lock size=%d", st.Size)
		}
	}
}

func TestLinuxRejectsHardLinkedControlRecord(t *testing.T) {
	d := linuxControlDir(t)
	s := openLinuxStore(t, d)
	if err := s.Create(validJournal(t)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(d, controlFilename), filepath.Join(d, "control-copy")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(d); err == nil {
		t.Fatal("hard-linked control record accepted")
	}
}

func TestLinuxOpenHandlesOrphanTempsSafely(t *testing.T) {
	t.Run("strict-orphan-cleanup", func(t *testing.T) {
		d := linuxControlDir(t)
		orphan := filepath.Join(d, ".tmp-0123456789abcdef01234567")
		if err := os.WriteFile(orphan, []byte("orphaned but non-authoritative"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := openLinuxStore(t, d)
		defer s.Close()
		if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("strict orphan was not removed: %v", err)
		}
	})
	t.Run("suspicious-entry-prevents-partial-cleanup", func(t *testing.T) {
		d := linuxControlDir(t)
		valid := filepath.Join(d, ".tmp-0123456789abcdef01234567")
		malformed := filepath.Join(d, ".tmp-malformed")
		if err := os.WriteFile(valid, []byte("valid orphan"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(malformed, []byte("suspicious"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(d); err == nil {
			t.Fatal("mixed orphan set was accepted")
		}
		for _, path := range []string{valid, malformed} {
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("orphan was modified before validation completed: %s: %v", path, err)
			}
		}
	})

	suspicious := []struct {
		name  string
		setup func(*testing.T, string) string
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, d string) string {
				p := filepath.Join(d, ".tmp-0123456789abcdef01234567")
				if err := os.Symlink(controlFilename, p); err != nil {
					t.Fatal(err)
				}
				return p
			},
		},
		{
			name: "hardlink",
			setup: func(t *testing.T, d string) string {
				source := filepath.Join(d, "orphan-hardlink-source")
				if err := os.WriteFile(source, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(d, ".tmp-0123456789abcdef01234567")
				if err := os.Link(source, p); err != nil {
					t.Fatal(err)
				}
				return p
			},
		},
		{
			name: "wrong-permissions",
			setup: func(t *testing.T, d string) string {
				p := filepath.Join(d, ".tmp-0123456789abcdef01234567")
				if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(p, 0o640); err != nil {
					t.Fatal(err)
				}
				return p
			},
		},
		{
			name: "fifo",
			setup: func(t *testing.T, d string) string {
				p := filepath.Join(d, ".tmp-0123456789abcdef01234567")
				if err := syscall.Mkfifo(p, 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			},
		},
		{
			name: "malformed-name",
			setup: func(t *testing.T, d string) string {
				p := filepath.Join(d, ".tmp-not-a-generated-name")
				if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			},
		},
	}
	for _, tt := range suspicious {
		t.Run(tt.name, func(t *testing.T) {
			d := linuxControlDir(t)
			suspicious := tt.setup(t, d)
			if _, err := Open(d); err == nil {
				t.Fatal("suspicious orphan temporary was accepted")
			}
			if _, err := os.Lstat(suspicious); err != nil {
				t.Fatalf("suspicious orphan was modified or deleted: %v", err)
			}
		})
	}
}

func TestLinuxCommitFaultBoundariesNeverExposePartialControl(t *testing.T) {
	tests := []struct {
		stage   replaceStage
		newDisk bool
	}{
		{replaceBeforeWrite, false},
		{replaceAfterWrite, false},
		{replaceBeforeSync, false},
		{replaceAfterSync, false},
		{replaceBeforeRename, false},
		{replaceAfterRename, true},
		{replaceBeforeDirSync, true},
		{replaceAfterDirSync, true},
	}
	for _, tt := range tests {
		t.Run(string(tt.stage), func(t *testing.T) {
			d := linuxControlDir(t)
			s := openLinuxStore(t, d)
			old := validJournal(t)
			if err := s.Create(old); err != nil {
				t.Fatal(err)
			}
			newJournal := advance(t, old, PhaseLocked)
			s.platform.replaceFault = func(stage replaceStage) error {
				if stage == tt.stage {
					return errors.New("injected durability-boundary failure")
				}
				return nil
			}
			if err := s.Save(newJournal); !errors.Is(err, ErrStorePoisoned) {
				t.Fatalf("Save=%v", err)
			}
			if _, err := s.Load(); !errors.Is(err, ErrStorePoisoned) {
				t.Fatalf("poisoned Load=%v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			assertCompleteControlChoice(t, d, old, newJournal, tt.newDisk)
			assertNoTemporaryControls(t, d)
		})
	}
}

func TestLinuxCrashAtRenameBoundariesReopensCompleteControl(t *testing.T) {
	t.Run("directory-fsync-failure", func(t *testing.T) {
		d := linuxControlDir(t)
		s := openLinuxStore(t, d)
		old := validJournal(t)
		if err := s.Create(old); err != nil {
			t.Fatal(err)
		}
		newJournal := advance(t, old, PhaseLocked)
		s.platform.dirSync = func(int) error { return syscall.EIO }
		if err := s.Save(newJournal); !errors.Is(err, syscall.EIO) || !errors.Is(err, ErrStorePoisoned) {
			t.Fatalf("Save=%v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		assertCompleteControlChoice(t, d, old, newJournal, true)
	})

	tests := []struct {
		stage     replaceStage
		expectNew bool
	}{
		{replaceBeforeRename, false},
		{replaceAfterRename, true},
	}
	for _, tt := range tests {
		t.Run(string(tt.stage), func(t *testing.T) {
			d := linuxControlDir(t)
			s := openLinuxStore(t, d)
			old := validJournal(t)
			if err := s.Create(old); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			newJournal := advance(t, old, PhaseLocked)

			runCrashSubprocess(t, d, tt.stage)
			assertCompleteControlChoice(t, d, old, newJournal, tt.expectNew)
			assertNoTemporaryControls(t, d)
		})
	}
}

func runCrashSubprocess(t *testing.T, dir string, stage replaceStage) {
	t.Helper()
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^$",
		"-test.timeout=10s",
		"-proberestore-crash-nonce="+nonce,
		"-proberestore-crash-dir="+dir,
		"-proberestore-crash-stage="+string(stage),
	)
	cmd.Env = append(crashHelperBaseEnv(os.Environ()),
		"PROBERESTORE_CRASH_HELPER=v1",
		"PROBERESTORE_CRASH_NONCE="+nonce,
	)
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("crash helper exceeded timeout: %v", ctx.Err())
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("helper was not killed: %v", err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("helper exit status=%v err=%v", exitErr.Sys(), err)
	}
}

func runLinuxCrashHelper() error {
	nonce := os.Getenv("PROBERESTORE_CRASH_NONCE")
	if len(nonce) != 64 || nonce != *crashNonceFlag || !lowerHex(nonce) {
		return errors.New("nonce mismatch")
	}
	dir := *crashDirFlag
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("invalid control directory")
	}
	stage := replaceStage(*crashStageFlag)
	if stage != replaceBeforeRename && stage != replaceAfterRename {
		return errors.New("invalid crash stage")
	}
	s, err := Open(dir)
	if err != nil {
		return err
	}
	j, err := s.Load()
	if err != nil {
		return err
	}
	next, err := j.Transition(requestFor(j, PhaseLocked))
	if err != nil {
		return err
	}
	s.platform.replaceFault = func(current replaceStage) error {
		if current == stage {
			if err := syscall.Kill(syscall.Getpid(), syscall.SIGKILL); err != nil {
				return err
			}
			return errors.New("SIGKILL returned without terminating process")
		}
		return nil
	}
	return s.Save(next)
}

func crashHelperBaseEnv(env []string) []string {
	clean := make([]string, 0, len(env))
	for _, entry := range env {
		if strings.HasPrefix(entry, "PROBERESTORE_CRASH_HELPER=") || strings.HasPrefix(entry, "PROBERESTORE_CRASH_NONCE=") {
			continue
		}
		clean = append(clean, entry)
	}
	return clean
}

func lowerHex(value string) bool {
	for _, ch := range value {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

func assertCompleteControlChoice(t *testing.T, dir string, old, next Journal, expectNew bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, controlFilename))
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeControl(raw)
	if err != nil {
		t.Fatalf("control record is not complete and valid: %v", err)
	}
	oldControl := newControl(old, nil)
	wantControl := oldControl
	if expectNew {
		wantControl = advanceControl(next, oldControl)
	}
	if !reflect.DeepEqual(record, wantControl) {
		t.Fatalf("disk control record does not exactly match expected old/new record\ngot:  %#v\nwant: %#v", record, wantControl)
	}
	s := openLinuxStore(t, dir)
	defer s.Close()
	got, err := s.Load()
	if err != nil {
		t.Fatalf("reopen Load=%v", err)
	}
	if !reflect.DeepEqual(got, wantControl.Journal) {
		t.Fatalf("reopened journal does not exactly match expected journal\ngot:  %#v\nwant: %#v", got, wantControl.Journal)
	}
}

func assertNoTemporaryControls(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			t.Fatalf("temporary control survived: %s", entry.Name())
		}
	}
}
