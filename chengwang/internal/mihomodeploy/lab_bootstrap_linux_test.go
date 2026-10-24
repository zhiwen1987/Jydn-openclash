//go:build linux

package mihomodeploy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func labBootstrapLinuxPrivateBase(t *testing.T) string {
	t.Helper()
	// testing.TempDir's numbered leaf is created with 0777 before umask.
	// Create the exact private base required by the product, including for
	// downstream rejection tests, without changing the process-wide umask.
	base := filepath.Join(t.TempDir(), "private-state")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal("private base fixture mkdir failed")
	}
	info, err := os.Lstat(base)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private base fixture mode failed")
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	if !ok || identity.Mode&07777 != 0700 || identity.Uid != uint32(os.Geteuid()) || identity.Gid != uint32(os.Getegid()) {
		t.Fatal("private base fixture ownership failed")
	}
	return base
}

func labBootstrapLinuxFixture(t *testing.T) (labRuntimeDisk, string) {
	t.Helper()
	base := labBootstrapLinuxPrivateBase(t)
	d, fresh, err := openLabRuntimeDiskAt(base)
	if err != nil || !fresh {
		t.Fatal("private runtime mkdir failed")
	}
	t.Cleanup(func() { _ = d.close() })
	return d, base
}
func labBootstrapLinuxSeedModel(t *testing.T, d labRuntimeDisk) []byte {
	t.Helper()
	r, _, _ := labV2TestRecord(t)
	binding, err := d.provisioning()
	if err != nil {
		t.Fatal("private marker")
	}
	r.wire.V2.Provisioning = binding
	r = lifecycleTestSeal(t, r)
	raw := mustLabV2Encode(t, r)
	state, err := d.replaceControl(raw)
	if err != nil || state != lifecycleCommitted {
		t.Fatal("MODEL record bytes did not commit")
	}
	return raw
}
func TestLabBootstrapLinuxExclusiveRuntimeCreatesMarkerWithoutHead(t *testing.T) {
	d, base := labBootstrapLinuxFixture(t)
	if _, exists, err := d.readControl(); err != nil || exists {
		t.Fatal("directory creation invented a head")
	}
	marker := filepath.Join(base, "runtime", "provision.marker")
	info, err := os.Lstat(marker)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatal("marker is not private")
	}
	wal, err := os.ReadDir(filepath.Join(base, "runtime", "wal"))
	if err != nil || len(wal) != 1 || wal[0].Name() != "writer.lock" {
		t.Fatal("WAL allowlist changed or head fabricated")
	}
	if d.close() != nil {
		t.Fatal("close")
	}
	before, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal("marker read")
	}
	if reopened, _, err := openLabRuntimeDiskAt(base); err == nil {
		_ = reopened.close()
		t.Fatal("missing control reinitialized")
	}
	after, err := os.ReadFile(marker)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed reopen changed original marker")
	}
}
func TestLabBootstrapLinuxExistingEmptyRuntimeNeverBecomesFresh(t *testing.T) {
	base := labBootstrapLinuxPrivateBase(t)
	runtime := filepath.Join(base, "runtime")
	if os.Mkdir(runtime, 0700) != nil {
		t.Fatal("fixture")
	}
	if d, _, err := openLabRuntimeDiskAt(base); err == nil {
		_ = d.close()
		t.Fatal("empty existing root treated as fresh")
	}
	entries, err := os.ReadDir(runtime)
	if err != nil || len(entries) != 0 {
		t.Fatal("partial bootstrap was repaired or erased")
	}
}
func TestLabBootstrapLinuxLostRuntimeWithRetainedStateLockRejects(t *testing.T) {
	base := labBootstrapLinuxPrivateBase(t)
	if os.WriteFile(filepath.Join(base, "writer.lock"), nil, 0600) != nil {
		t.Fatal("fixture")
	}
	if d, _, err := openLabRuntimeDiskAt(base); err == nil {
		_ = d.close()
		t.Fatal("retained lock became fresh state")
	}
	if _, err := os.Lstat(filepath.Join(base, "runtime")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("new root created over loss evidence")
	}
}
func TestLabBootstrapLinuxMarkerIsSiblingAndWALStillRejectsExtraMarker(t *testing.T) {
	d, base := labBootstrapLinuxFixture(t)
	marker, err := os.ReadFile(filepath.Join(base, "runtime", "provision.marker"))
	if err != nil {
		t.Fatal("marker")
	}
	if os.WriteFile(filepath.Join(base, "runtime", "wal", "provision.marker"), marker, 0600) != nil {
		t.Fatal("fixture")
	}
	if d.verify() == nil {
		t.Fatal("marker widened old WAL allowlist")
	}
}
func TestLabBootstrapLinuxMarkerReplacementModeAndLinkFailuresAreSticky(t *testing.T) {
	for _, kind := range []string{"replace", "mode", "hardlink", "truncate"} {
		t.Run(kind, func(t *testing.T) {
			d, base := labBootstrapLinuxFixture(t)
			marker := filepath.Join(base, "runtime", "provision.marker")
			switch kind {
			case "replace":
				if os.Rename(marker, marker+".original") != nil || os.WriteFile(marker, []byte(`{}`), 0600) != nil {
					t.Fatal("fixture")
				}
			case "mode":
				if os.Chmod(marker, 0644) != nil {
					t.Fatal("fixture")
				}
			case "hardlink":
				if os.Link(marker, filepath.Join(base, "link")) != nil {
					t.Fatal("fixture")
				}
			case "truncate":
				if os.Truncate(marker, 0) != nil {
					t.Fatal("fixture")
				}
			}
			if d.verify() == nil {
				t.Fatal("marker custody loss accepted")
			}
			if kind == "mode" {
				_ = os.Chmod(marker, 0600)
			}
			if !errors.Is(d.verify(), errLifecyclePoisoned) {
				t.Fatal("unsafe runtime revived")
			}
		})
	}
}
func TestLabBootstrapLinuxDirectorySymlinksAndUnsafeParentReject(t *testing.T) {
	for _, kind := range []string{"base-mode", "runtime-link", "marker-link"} {
		t.Run(kind, func(t *testing.T) {
			base := labBootstrapLinuxPrivateBase(t)
			if kind == "base-mode" {
				if os.Chmod(base, 0755) != nil {
					t.Fatal("fixture")
				}
			} else if kind == "runtime-link" {
				other := labBootstrapLinuxPrivateBase(t)
				if os.Symlink(other, filepath.Join(base, "runtime")) != nil {
					t.Fatal("fixture")
				}
			} else {
				if os.Mkdir(filepath.Join(base, "runtime"), 0700) != nil || os.Symlink("/dev/null", filepath.Join(base, "runtime", "provision.marker")) != nil {
					t.Fatal("fixture")
				}
			}
			if d, _, err := openLabRuntimeDiskAt(base); err == nil {
				_ = d.close()
				t.Fatal("unsafe provisioning accepted")
			}
		})
	}
}
func TestLabBootstrapLinuxActualControlBytesReopenWithSameMarker(t *testing.T) {
	d, base := labBootstrapLinuxFixture(t)
	// Real filesystem exercise of explicitly MODEL head bytes. This does not
	// bypass the product bootstrap entrypoint to claim an observed kernel.
	raw := labBootstrapLinuxSeedModel(t, d)
	binding, err := d.provisioning()
	if err != nil {
		t.Fatal("binding")
	}
	if d.close() != nil {
		t.Fatal("close")
	}
	next, fresh, err := openLabRuntimeDiskAt(base)
	if err != nil || fresh {
		t.Fatal("existing bytes not reopened")
	}
	t.Cleanup(func() { _ = next.close() })
	after, exists, err := next.readControl()
	bindingAfter, bindingErr := next.provisioning()
	if err != nil || !exists || !bytes.Equal(after, raw) || bindingErr != nil || binding != bindingAfter {
		t.Fatal("readback or marker changed")
	}
	runtime, p, err := ownLabLifecycleRuntime(next, false)
	if err != nil || p != nil {
		t.Fatal("reopen created permit")
	}
	if _, err := runtime.existingStore(); err != nil {
		t.Fatal("existing model record unreadable")
	}
	_ = runtime.close()
}
func TestLabBootstrapLinuxControlLossPreservesMarkerAndArtifacts(t *testing.T) {
	d, base := labBootstrapLinuxFixture(t)
	labBootstrapLinuxSeedModel(t, d)
	artifacts := filepath.Join(base, "runtime", "artifacts")
	if os.Mkdir(artifacts, 0700) != nil || os.WriteFile(filepath.Join(artifacts, "MODEL-preserved"), []byte("model"), 0600) != nil {
		t.Fatal("fixture")
	}
	marker, _ := os.ReadFile(filepath.Join(base, "runtime", "provision.marker"))
	_ = d.close()
	if os.Remove(filepath.Join(base, "runtime", "wal", "control.json")) != nil {
		t.Fatal("fixture")
	}
	if next, _, err := openLabRuntimeDiskAt(base); err == nil {
		_ = next.close()
		t.Fatal("lost control bootstrapped")
	}
	after, err := os.ReadFile(filepath.Join(base, "runtime", "provision.marker"))
	original, e := os.ReadFile(filepath.Join(artifacts, "MODEL-preserved"))
	if err != nil || e != nil || !bytes.Equal(marker, after) || string(original) != "model" {
		t.Fatal("loss recovery erased originals")
	}
}
func TestLabBootstrapLinuxMarkerMalformedCanonicalAndUnknownFieldsReject(t *testing.T) {
	for _, raw := range []string{`{}`, `{"schema":"chengwang.mihomo-lab-provision/v1","runtimeID":null}`, `{"schema":"chengwang.mihomo-lab-provision/v1","runtimeID":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":0}`, `{"schema":"chengwang.mihomo-lab-provision/v1","runtimeID":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}` + "\n"} {
		base := labBootstrapLinuxPrivateBase(t)
		runtime := filepath.Join(base, "runtime")
		if os.Mkdir(runtime, 0700) != nil || os.WriteFile(filepath.Join(runtime, "provision.marker"), []byte(raw), 0600) != nil {
			t.Fatal("fixture")
		}
		if d, _, err := openLabRuntimeDiskAt(base); err == nil {
			_ = d.close()
			t.Fatal("malformed marker accepted")
		}
		after, err := os.ReadFile(filepath.Join(runtime, "provision.marker"))
		if err != nil || string(after) != raw {
			t.Fatal("rejected marker modified")
		}
	}
}
func TestLabBootstrapLinuxParentReplacementPoisonsRetainedPermitDisk(t *testing.T) {
	d, base := labBootstrapLinuxFixture(t)
	old := base + ".model-original"
	if os.Rename(base, old) != nil {
		t.Fatal("fixture")
	}
	t.Cleanup(func() {
		if os.Remove(base) != nil || os.Rename(old, base) != nil {
			t.Error("model directory restore failed")
		}
	})
	if os.Mkdir(base, 0700) != nil {
		t.Fatal("fixture")
	}
	if d.verify() == nil {
		t.Fatal("substituted base retained valid permit")
	}
	if !errors.Is(d.verify(), errLifecyclePoisoned) {
		t.Fatal("parent replacement not sticky")
	}
}
