//go:build linux

package mihomodeploy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openArtifactFixture(t *testing.T) (*ArtifactStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "artifacts")
	s, err := OpenArtifactStore(path)
	if err != nil {
		t.Fatalf("open private store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}
func TestArtifactLinuxDurableReopenAndExactBackupRestoration(t *testing.T) {
	s, path := openArtifactFixture(t)
	ctx := context.Background()
	d, err := s.Put(ctx, artifactFixtureSpec())
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateBackup(ctx, "durable-operation", artifactFixtureTarget(), d.RecordSHA256)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.ReadPrivate(ctx, d.RecordSHA256)
	if err != nil {
		t.Fatal(err)
	}
	original := a.Bytes()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenArtifactStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	backup, err := reopened.ReadBackupPrivate(ctx, b.BackupSHA256, "durable-operation", artifactFixtureTarget())
	if err != nil || !bytes.Equal(backup.Bytes(), original) || len(backup.Bytes()) != d.Config.Bytes {
		t.Fatal("durable exact backup lost")
	}
	for _, name := range []string{"writer.lock", "index.json", filepath.Join("objects", d.Config.SHA256), filepath.Join("objects", d.SourceSpecSHA256)} {
		info, err := os.Lstat(filepath.Join(path, name))
		if err != nil || info.Mode().Perm() != 0600 || !info.Mode().IsRegular() {
			t.Fatal("private file mode invalid")
		}
	}
}
func TestArtifactLinuxExclusiveLockPreventsSecondController(t *testing.T) {
	s, path := openArtifactFixture(t)
	if other, err := OpenArtifactStore(path); err == nil {
		_ = other.Close()
		t.Fatal("second writer admitted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenArtifactStore(path)
	if err != nil {
		t.Fatal("lock not released")
	}
	_ = reopened.Close()
}
func TestArtifactLinuxRejectsSymlinkParentAndWrongPrivateModes(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if os.Mkdir(real, 0700) != nil || os.Symlink(real, filepath.Join(base, "link")) != nil {
		t.Fatal("fixture setup")
	}
	if s, err := OpenArtifactStore(filepath.Join(base, "link")); err == nil {
		_ = s.Close()
		t.Fatal("symlink root accepted")
	}
	if os.Chmod(real, 0750) != nil {
		t.Fatal("fixture mode")
	}
	if s, err := OpenArtifactStore(real); err == nil {
		_ = s.Close()
		t.Fatal("nonprivate root accepted")
	}
}
func TestArtifactLinuxObjectSymlinkHardlinkAndCorruptionAreRejected(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "corruption"} {
		t.Run(kind, func(t *testing.T) {
			s, path := openArtifactFixture(t)
			d, err := s.Put(context.Background(), artifactFixtureSpec())
			if err != nil {
				t.Fatal(err)
			}
			object := filepath.Join(path, "objects", d.Config.SHA256)
			if kind == "symlink" {
				if os.Remove(object) != nil || os.Symlink("../index.json", object) != nil {
					t.Fatal("symlink fixture")
				}
			} else if kind == "hardlink" {
				if os.Link(object, filepath.Join(filepath.Dir(path), "linked")) != nil {
					t.Fatal("hardlink fixture")
				}
			} else if os.WriteFile(object, []byte("corrupted"), 0600) != nil {
				t.Fatal("corruption fixture")
			}
			if _, err := s.ReadPrivate(context.Background(), d.RecordSHA256); err == nil {
				t.Fatal("unsafe object accepted")
			}
			if _, err := s.Describe(context.Background(), d.RecordSHA256); !errors.Is(err, ErrArtifactPoisoned) {
				t.Fatal("unsafe store not poisoned")
			}
			if kind == "corruption" {
				fresh, freshPath := openArtifactFixture(t)
				old, err := fresh.Put(context.Background(), artifactFixtureSpec())
				if err != nil {
					t.Fatal(err)
				}
				candidate := artifactFixtureSpec()
				candidate.DefaultTarget = "REJECT"
				built, err := BuildLabConfig(candidate)
				if err != nil {
					t.Fatal(err)
				}
				orphan := built.Bytes()
				orphan[0] ^= 1
				if os.WriteFile(filepath.Join(freshPath, "objects", built.Descriptor().SHA256), orphan, 0600) != nil {
					t.Fatal("unsafe orphan fixture")
				}
				if _, err := fresh.Put(context.Background(), candidate); !errors.Is(err, ErrArtifactUnsafe) {
					t.Fatal("corrupt existing orphan not rejected by Put")
				}
				if _, err := fresh.Describe(context.Background(), old.RecordSHA256); !errors.Is(err, ErrArtifactPoisoned) {
					t.Fatal("observed orphan corruption left store usable")
				}
				candidate.ControllerSecret = strings.Repeat("z", 40)
				if _, err := fresh.Put(context.Background(), candidate); !errors.Is(err, ErrArtifactPoisoned) {
					t.Fatal("unrelated candidate bypassed integrity failure")
				}
			}
		})
	}
}
func TestArtifactLinuxIndexReplacementPoisonsWriterAndNeverClaimsRollbackProtectionAfterOpen(t *testing.T) {
	s, path := openArtifactFixture(t)
	first, err := s.Put(context.Background(), artifactFixtureSpec())
	if err != nil {
		t.Fatal(err)
	}
	prior, err := os.ReadFile(filepath.Join(path, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec := artifactFixtureSpec()
	spec.DefaultTarget = "REJECT"
	if _, err := s.Put(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(filepath.Join(path, "index.json"), prior, 0600) != nil {
		t.Fatal("fixture replay")
	}
	if _, err := s.ReadPrivate(context.Background(), first.RecordSHA256); err == nil {
		t.Fatal("active writer accepted replaced head")
	}
	// A fresh process has no independent anti-rollback anchor. Do not assert that
	// reopening a complete valid old index must detect whole-disk replay.
}
func TestArtifactLinuxPostRenameDirectorySyncFailureIsUnknownAndRequiresReopen(t *testing.T) {
	s, path := openArtifactFixture(t)
	disk := s.core.disk.(*artifactLinuxDisk)
	disk.syncDirectory = func(dir *os.File) error {
		if dir == disk.directory() {
			return errors.New("synthetic directory sync fault")
		}
		return dir.Sync()
	}
	if _, err := s.Put(context.Background(), artifactFixtureSpec()); !errors.Is(err, ErrArtifactCommitUnknown) {
		t.Fatal("post-rename fault called uncommitted/success")
	}
	if _, err := s.Put(context.Background(), artifactFixtureSpec()); !errors.Is(err, ErrArtifactPoisoned) {
		t.Fatal("uncertain write blindly retried")
	}
	if s.Close() != nil {
		t.Fatal("close")
	}
	reopened, err := OpenArtifactStore(path)
	if err != nil {
		t.Fatal("reopen recovery")
	}
	defer reopened.Close()
	d, err := reopened.Put(context.Background(), artifactFixtureSpec())
	if err != nil {
		t.Fatal(err)
	}
	a, err := reopened.ReadPrivate(context.Background(), d.RecordSHA256)
	if err != nil || labConfigHash(a.Bytes()) != d.Config.SHA256 {
		t.Fatal("unknown local commit not reconciled")
	}
}
func TestArtifactLinuxObjectDirectorySyncFailureNeverPublishesReference(t *testing.T) {
	s, path := openArtifactFixture(t)
	disk := s.core.disk.(*artifactLinuxDisk)
	disk.syncDirectory = func(dir *os.File) error {
		if dir == disk.objects {
			return errors.New("synthetic blob sync fault")
		}
		return dir.Sync()
	}
	if _, err := s.Put(context.Background(), artifactFixtureSpec()); !errors.Is(err, ErrArtifactCommitUnknown) || len(s.core.index.Artifacts) != 0 {
		t.Fatal("uncertain object published")
	}
	if s.Close() != nil {
		t.Fatal("close")
	}
	reopened, err := OpenArtifactStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(reopened.core.index.Artifacts) != 0 {
		t.Fatal("orphan became published artifact")
	}
	if _, err := reopened.Put(context.Background(), artifactFixtureSpec()); err != nil {
		t.Fatal("valid orphan prevented recovery")
	}
}
func TestArtifactLinuxRecoversOnlyOwnedTemporaryFilesAndRetainsValidOrphans(t *testing.T) {
	s, path := openArtifactFixture(t)
	if s.Close() != nil {
		t.Fatal("close")
	}
	temp := filepath.Join(path, "objects", ".tmp-"+strings.Repeat("a", 32))
	if os.WriteFile(temp, []byte("partial private temp"), 0600) != nil {
		t.Fatal("temp fixture")
	}
	orphan := []byte("synthetic durable orphan")
	orphanPath := filepath.Join(path, "objects", labConfigHash(orphan))
	if os.WriteFile(orphanPath, orphan, 0600) != nil {
		t.Fatal("orphan fixture")
	}
	reopened, err := OpenArtifactStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := os.Lstat(temp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned temporary file not recovered")
	}
	if raw, err := os.ReadFile(orphanPath); err != nil || !bytes.Equal(raw, orphan) {
		t.Fatal("immutable orphan was silently deleted")
	}
}
func TestArtifactLinuxMalformedReferencedObjectPreventsReopen(t *testing.T) {
	s, path := openArtifactFixture(t)
	d, err := s.Put(context.Background(), artifactFixtureSpec())
	if err != nil {
		t.Fatal(err)
	}
	if s.Close() != nil {
		t.Fatal("close")
	}
	if os.Remove(filepath.Join(path, "objects", d.SourceSpecSHA256)) != nil {
		t.Fatal("fixture removal")
	}
	if reopened, err := OpenArtifactStore(path); err == nil {
		_ = reopened.Close()
		t.Fatal("missing full source silently accepted")
	}
}

func TestArtifactLinuxMissingIndexCannotResetNonemptyLibrary(t *testing.T) {
	s, path := openArtifactFixture(t)
	if _, err := s.Put(context.Background(), artifactFixtureSpec()); err != nil {
		t.Fatal(err)
	}
	if s.Close() != nil {
		t.Fatal("close")
	}
	objects := filepath.Join(path, "objects")
	entries, err := os.ReadDir(objects)
	if err != nil {
		t.Fatal("read fixture objects")
	}
	before := map[string][]byte{}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(objects, entry.Name()))
		if err != nil {
			t.Fatal("read fixture object")
		}
		before[entry.Name()] = raw
	}
	if len(before) == 0 || os.Remove(filepath.Join(path, "index.json")) != nil {
		t.Fatal("missing-index fixture")
	}
	if reopened, err := OpenArtifactStore(path); !errors.Is(err, ErrArtifactUnsafe) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatal("missing index silently initialized")
	}
	if _, err := os.Lstat(filepath.Join(path, "index.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing index recreated")
	}
	after, err := os.ReadDir(objects)
	if err != nil || len(after) != len(before) {
		t.Fatal("orphan objects changed")
	}
	for _, entry := range after {
		raw, err := os.ReadFile(filepath.Join(objects, entry.Name()))
		if err != nil || !bytes.Equal(raw, before[entry.Name()]) {
			t.Fatal("unreferenced original modified")
		}
	}
}
