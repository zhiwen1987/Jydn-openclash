//go:build linux && proberestore_root

package proberestore

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

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
