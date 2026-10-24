//go:build linux

package mihomodeploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func lifecycleLinuxFixture(t *testing.T) (*lifecycleLinuxDisk, string, string) {
	t.Helper(); base := t.TempDir(); path := filepath.Join(base, "records"); global := filepath.Join(base, "global.lock")
	disk, err := openLifecycleDiskAt(path, global)
	if err != nil { t.Fatalf("private lifecycle open failed: %v", err) }
	d := disk.(*lifecycleLinuxDisk); t.Cleanup(func() { _ = d.close() }); return d, path, global
}
func lifecycleLinuxSeed(t *testing.T, d *lifecycleLinuxDisk, raw []byte) {
	t.Helper(); state, err := d.replaceControl(raw)
	if state != lifecycleCommitted || err != nil { t.Fatal("real private control commit failed") }
}
func TestLifecycleLinuxMissingControlDoesNotInitializeOrCreateHead(t *testing.T) {
	d, path, _ := lifecycleLinuxFixture(t)
	raw, exists, err := d.readControl()
	if err != nil || exists || raw != nil { t.Fatal("missing control became an initialized record") }
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 || entries[0].Name() != "writer.lock" { t.Fatal("opener created state instead of only a writer lock") }
}
func TestLifecycleLinuxOpaqueCommitReopensExactBytes(t *testing.T) {
	d, path, global := lifecycleLinuxFixture(t)
	input := []byte("opaque-not-a-policy-or-approval\x00\n")
	lifecycleLinuxSeed(t, d, input)
	raw, exists, err := d.readControl()
	if err != nil || !exists || !bytes.Equal(raw, input) { t.Fatal("committed bytes lost") }
	raw[0] ^= 1
	if d.close() != nil { t.Fatal("close") }
	reopened, err := openLifecycleDiskAt(path, global)
	if err != nil { t.Fatal("reopen") }; defer reopened.close()
	raw, exists, err = reopened.readControl()
	if err != nil || !exists || !bytes.Equal(raw, input) { t.Fatal("opaque exact bytes did not survive reopen") }
	for _, name := range []string{global, filepath.Join(path, "writer.lock"), filepath.Join(path, "control.json")} {
		info, err := os.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 { t.Fatal("private mode lost") }
	}
}
func TestLifecycleLinuxBoundsRejectBeforePublishing(t *testing.T) {
	d, _, _ := lifecycleLinuxFixture(t)
	for _, raw := range [][]byte{nil, []byte{}, make([]byte, maxLifecycleControlBytes+1)} {
		state, err := d.replaceControl(raw)
		if state != lifecycleNotCommitted || err == nil || d.poisoned { t.Fatal("size rejection became a commit or uncertainty") }
	}
	if _, exists, err := d.readControl(); err != nil || exists { t.Fatal("rejection created control") }
}
func TestLifecycleLinuxPreRenameFaultsKeepExactOldControl(t *testing.T) {
	for _, phase := range []string{"file-sync", "file-close", "rename"} {
		t.Run(phase, func(t *testing.T) {
			d, _, _ := lifecycleLinuxFixture(t); lifecycleLinuxSeed(t, d, []byte("old"))
			fault := errors.New("synthetic no-rename fault")
			switch phase {
			case "file-sync": d.syncFile = func(*os.File) error { return fault }
			case "file-close": d.closeFile = func(f *os.File) error { _ = f.Close(); return fault }
			case "rename": d.rename = func(*os.File, string, string) error { return fault }
			}
			state, err := d.replaceControl([]byte("new"))
			if state != lifecycleNotCommitted || err == nil || d.poisoned { t.Fatal("pre-rename fault mislabeled") }
			raw, exists, err := d.readControl()
			if err != nil || !exists || string(raw) != "old" { t.Fatal("pre-rename fault replaced durable control") }
		})
	}
}
func TestLifecycleLinuxFileIsActuallyClosedBeforeRename(t *testing.T) {
	d, _, _ := lifecycleLinuxFixture(t); var written *os.File
	d.closeFile = func(f *os.File) error { written = f; return f.Close() }
	d.rename = func(dir *os.File, a, b string) error {
		if written == nil || written.Fd() != ^uintptr(0) { return errors.New("temp was not closed before rename") }
		return syscall.Renameat(int(dir.Fd()), a, int(dir.Fd()), b)
	}
	lifecycleLinuxSeed(t, d, []byte("closed-and-durable"))
}
func TestLifecycleLinuxPostRenameFaultsPoisonAndNeverClaimCommitted(t *testing.T) {
	for _, phase := range []string{"directory-sync", "read-error", "missing-readback", "wrong-readback", "post-read-verify"} {
		t.Run(phase, func(t *testing.T) {
			d, path, global := lifecycleLinuxFixture(t); lifecycleLinuxSeed(t, d, []byte("old"))
			switch phase {
			case "directory-sync": d.syncDirectory = func(*os.File) error { return errors.New("synthetic dirsync fault") }
			case "read-error": d.readback = func() ([]byte, bool, error) { return nil, false, errors.New("synthetic readback fault") }
			case "missing-readback": d.readback = func() ([]byte, bool, error) { return nil, false, nil }
			case "wrong-readback": d.readback = func() ([]byte, bool, error) { return []byte("wrong"), true, nil }
			case "post-read-verify": d.readback = func() ([]byte, bool, error) { raw, exists, err := d.readControl(); d.lockIdentity.Ino++; return raw, exists, err }
			}
			state, err := d.replaceControl([]byte("new"))
			if state != lifecycleUnknown || !errors.Is(err, errLifecycleCommitUnknown) || !d.poisoned { t.Fatal("post-rename failure called success/uncommitted") }
			if _, _, err := d.readControl(); !errors.Is(err, errLifecyclePoisoned) { t.Fatal("uncertain disk remained readable") }
			if state, err := d.replaceControl([]byte("third")); state != lifecycleNotCommitted || !errors.Is(err, errLifecyclePoisoned) { t.Fatal("uncertain disk accepted another write") }
			if d.close() != nil { t.Fatal("close") }
			reopened, err := openLifecycleDiskAt(path, global)
			if err != nil { t.Fatal("reopen after unknown") }; defer reopened.close()
			raw, exists, err := reopened.readControl()
			if err != nil || !exists || string(raw) != "new" { t.Fatal("reopen did not observe actual renamed bytes") }
		})
	}
}
func TestLifecycleLinuxSameUIDControlReplacementAndInPlaceMutationPoison(t *testing.T) {
	for _, kind := range []string{"replacement", "in-place"} {
		t.Run(kind, func(t *testing.T) {
			d, path, _ := lifecycleLinuxFixture(t); lifecycleLinuxSeed(t, d, []byte("old"))
			control := filepath.Join(path, "control.json")
			if kind == "replacement" {
				temp := filepath.Join(filepath.Dir(path), "replacement")
				if os.WriteFile(temp, []byte("old"), 0600) != nil || os.Rename(temp, control) != nil { t.Fatal("replacement fixture") }
			} else if os.WriteFile(control, []byte("longer changed bytes"), 0600) != nil { t.Fatal("in-place fixture") }
			if _, _, err := d.readControl(); err == nil || !d.poisoned { t.Fatal("external control mutation accepted") }
		})
	}
}
func TestLifecycleLinuxBothLockNameReplacementsPoison(t *testing.T) {
	for _, kind := range []string{"global", "directory"} {
		t.Run(kind, func(t *testing.T) {
			d, path, global := lifecycleLinuxFixture(t); lock := global
			if kind == "directory" { lock = filepath.Join(path, "writer.lock") }
			if os.Remove(lock) != nil || os.WriteFile(lock, nil, 0600) != nil { t.Fatal("lock replacement fixture") }
			if d.verify() == nil || !d.poisoned { t.Fatal("replaced lock accepted") }
		})
	}
}
func TestLifecycleLinuxDirectoryNameReplacementPoisons(t *testing.T) {
	d, path, _ := lifecycleLinuxFixture(t)
	if os.Rename(path, path+"-old") != nil || os.Mkdir(path, 0700) != nil { t.Fatal("directory replacement fixture") }
	if d.verify() == nil || !d.poisoned { t.Fatal("replacement directory accepted") }
}
func TestLifecycleLinuxSymlinkHardlinkAndWrongModesReject(t *testing.T) {
	for _, kind := range []string{"global-symlink", "global-hardlink", "control-symlink", "control-hardlink", "control-mode", "directory-mode", "parent-symlink"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir(); path := filepath.Join(base, "records"); global := filepath.Join(base, "global.lock")
			if kind == "global-symlink" {
				if os.WriteFile(filepath.Join(base, "target"), nil, 0600) != nil || os.Symlink("target", global) != nil { t.Fatal("fixture") }
			} else if kind == "global-hardlink" {
				if os.WriteFile(global, nil, 0600) != nil || os.Link(global, filepath.Join(base, "linked")) != nil { t.Fatal("fixture") }
			} else if kind == "parent-symlink" {
				if os.Mkdir(filepath.Join(base, "real"), 0700) != nil || os.Symlink("real", filepath.Join(base, "link")) != nil { t.Fatal("fixture") }
				path = filepath.Join(base, "link", "records")
			} else {
				if os.Mkdir(path, 0700) != nil { t.Fatal("fixture") }
				control := filepath.Join(path, "control.json")
				switch kind {
				case "control-symlink": if os.Symlink("../target", control) != nil { t.Fatal("fixture") }
				case "control-hardlink": if os.WriteFile(control, []byte("old"), 0600) != nil || os.Link(control, filepath.Join(base, "linked")) != nil { t.Fatal("fixture") }
				case "control-mode": if os.WriteFile(control, []byte("old"), 0644) != nil { t.Fatal("fixture") }
				case "directory-mode": if os.Chmod(path, 0750) != nil { t.Fatal("fixture") }
				}
			}
			d, err := openLifecycleDiskAt(path, global)
			if err == nil { _ = d.close(); t.Fatal("unsafe path or inode accepted") }
		})
	}
}
func TestLifecycleLinuxMissingControlAndStrayTempAreNotRepaired(t *testing.T) {
	d, path, global := lifecycleLinuxFixture(t); lifecycleLinuxSeed(t, d, []byte("old")); _ = d.close()
	if os.Remove(filepath.Join(path, "control.json")) != nil { t.Fatal("fixture") }
	reopened, err := openLifecycleDiskAt(path, global)
	if err != nil { t.Fatal("missing bytes are an observation, not initialization") }
	if _, exists, err := reopened.readControl(); err != nil || exists { t.Fatal("missing control reconstructed") }; _ = reopened.close()
	temp := filepath.Join(path, ".tmp-00000000000000000000000000000000")
	if os.WriteFile(temp, []byte("partial"), 0600) != nil { t.Fatal("fixture") }
	if other, err := openLifecycleDiskAt(path, global); err == nil { _ = other.close(); t.Fatal("stray partial silently repaired") }
	if raw, err := os.ReadFile(temp); err != nil || string(raw) != "partial" { t.Fatal("unknown partial was deleted") }
}
func TestLifecycleLinuxMountIdentityAndFilesystemPolicyFailClosed(t *testing.T) {
	d, _, _ := lifecycleLinuxFixture(t); d.chain[len(d.chain)-1].mount++
	if d.verify() == nil || !d.poisoned { t.Fatal("expected mount identity mismatch accepted") }
	for _, fs := range []syscall.Statfs_t{{Type: 0xef53}, {Type: 0x58465342}, {Type: 0x01021994}} { if !lifecycleSupported(fs) { t.Fatal("fixed filesystem policy rejected") } }
	if lifecycleSupported(syscall.Statfs_t{Type: 0x794c7630}) { t.Fatal("unsupported overlay durability silently accepted") }
}
func TestLifecycleLinuxCloseIsIdempotentAndInvalidatesDisk(t *testing.T) {
	d, _, _ := lifecycleLinuxFixture(t)
	if d.close() != nil || d.close() != nil { t.Fatal("close not idempotent") }
	if err := d.verify(); !errors.Is(err, errLifecyclePoisoned) { t.Fatal("closed disk verified") }
	if _, _, err := d.readControl(); !errors.Is(err, errLifecyclePoisoned) { t.Fatal("closed disk read") }
	if state, err := d.replaceControl([]byte("new")); state != lifecycleNotCommitted || !errors.Is(err, errLifecyclePoisoned) { t.Fatal("closed disk wrote") }
	for _, invalid := range []*lifecycleLinuxDisk{nil, &lifecycleLinuxDisk{}} {
		if invalid.close() != nil { t.Fatal("nil/zero close") }
		if _, _, err := invalid.readControl(); err == nil { t.Fatal("nil/zero read accepted") }
		if _, err := invalid.replaceControl([]byte("new")); err == nil { t.Fatal("nil/zero write accepted") }
	}
}

type lifecycleFDProbe struct { FD int `json:"fd"`; Dev uint64 `json:"dev"`; Ino uint64 `json:"ino"` }
type lifecycleProbeOutput struct { mu sync.Mutex; raw []byte }
func (b *lifecycleProbeOutput) Write(raw []byte) (int, error) { b.mu.Lock(); defer b.mu.Unlock(); left := 4096-len(b.raw); if left > len(raw) { left = len(raw) }; if left > 0 { b.raw = append(b.raw, raw[:left]...) }; return len(raw), nil }
func lifecycleRunProbe(t *testing.T, mode, root, global string, descriptors []lifecycleFDProbe) {
	t.Helper(); raw, err := json.Marshal(descriptors); if err != nil { t.Fatal("probe fixture") }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second); defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycleLinuxProcessProbe$")
	cmd.Env = append(os.Environ(), "CHENGWANG_LIFECYCLE_PROBE="+mode, "CHENGWANG_LIFECYCLE_ROOT="+root, "CHENGWANG_LIFECYCLE_GLOBAL="+global, "CHENGWANG_LIFECYCLE_FDS="+string(raw))
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = time.Second
	var out lifecycleProbeOutput; cmd.Stdout, cmd.Stderr = &out, &out
	runtime.LockOSThread(); defer runtime.UnlockOSThread()
	if err := cmd.Run(); err != nil || ctx.Err() != nil { t.Fatal("owned bounded child probe failed") }
}
func TestLifecycleLinuxGlobalFlockSerializesTwoProcessesAndDifferentRoots(t *testing.T) {
	d, path, global := lifecycleLinuxFixture(t); _ = d
	other := filepath.Join(filepath.Dir(path), "second-root")
	lifecycleRunProbe(t, "global-lock", other, global, nil)
	if _, err := os.Lstat(other); !errors.Is(err, os.ErrNotExist) { t.Fatal("global lock checked after creating a second root") }
}
func TestLifecycleLinuxDirectoryFlockRejectsDifferentPrivateGlobalAlias(t *testing.T) {
	d, path, global := lifecycleLinuxFixture(t)
	other, err := openLifecycleDiskAt(path, global+"-alternate")
	if other != nil { _ = other.close() }
	if !errors.Is(err, errLifecycleLocked) { t.Fatal("directory lock did not serialize the same record root") }
	if d.verify() != nil { t.Fatal("failed contender released or changed original locks") }
}
func TestLifecycleLinuxCloexecLocksAndDirectoryDescriptorsDoNotSurviveExec(t *testing.T) {
	d, path, global := lifecycleLinuxFixture(t); var fds []lifecycleFDProbe
	all := []*os.File{d.global, d.lock}; for _, c := range d.chain { all = append(all, c.file) }; for _, c := range d.globalChain { all = append(all, c.file) }
	for _, f := range all {
		flags, _, err := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFD, 0)
		st, statErr := artifactStat(f)
		if err != 0 || flags&syscall.FD_CLOEXEC == 0 || statErr != nil { t.Fatal("descriptor missing CLOEXEC") }
		fds = append(fds, lifecycleFDProbe{int(f.Fd()), st.Dev, st.Ino})
	}
	lifecycleRunProbe(t, "fd-inheritance", path, global, fds)
}
func TestLifecycleLinuxProcessProbe(t *testing.T) {
	mode := os.Getenv("CHENGWANG_LIFECYCLE_PROBE"); if mode == "" { return }
	switch mode {
	case "global-lock":
		d, err := openLifecycleDiskAt(os.Getenv("CHENGWANG_LIFECYCLE_ROOT"), os.Getenv("CHENGWANG_LIFECYCLE_GLOBAL"))
		if d != nil { _ = d.close() }; if !errors.Is(err, errLifecycleLocked) { t.Fatal("second process acquired global lock") }
	case "fd-inheritance":
		var fds []lifecycleFDProbe
		if json.Unmarshal([]byte(os.Getenv("CHENGWANG_LIFECYCLE_FDS")), &fds) != nil || len(fds) == 0 { t.Fatal("probe fixture") }
		for _, expected := range fds { var actual syscall.Stat_t; if syscall.Fstat(expected.FD, &actual) == nil && actual.Dev == expected.Dev && actual.Ino == expected.Ino { t.Fatal("owned descriptor survived exec: " + strconv.Itoa(expected.FD)) } }
	default: t.Fatal("unknown source-owned probe")
	}
}
func TestLifecycleLinuxSharedWriterRejectsPathEscapesAndMissingPolicy(t *testing.T) {
	d, path, _ := lifecycleLinuxFixture(t)
	for _, name := range []string{"../escape", "x/control.json", "", "control.json"} {
		uncertain, err := privateAtomicReplace(d.directory(), name, []byte("body"), privateAtomicPolicy{})
		if uncertain || err == nil { t.Fatal("invalid private atomic capability accepted") }
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 || entries[0].Name() != "writer.lock" { t.Fatal("rejected writer mutated directory") }
}
func TestLifecycleLinuxExistingControlRecoversOnlySafeAbandonedTemps(t *testing.T) {
	d, path, global := lifecycleLinuxFixture(t); lifecycleLinuxSeed(t, d, []byte("original-control")); _ = d.close()
	temp := filepath.Join(path, ".tmp-11111111111111111111111111111111")
	if os.WriteFile(temp, []byte("incomplete-not-a-head"), 0600) != nil { t.Fatal("temp fixture") }
	reopened, err := openLifecycleDiskAt(path, global)
	if err != nil { t.Fatal("safe abandoned temp prevented recovery") }; defer reopened.close()
	raw, exists, err := reopened.readControl()
	if err != nil || !exists || string(raw) != "original-control" { t.Fatal("temp changed committed bytes") }
	if _, err := os.Lstat(temp); !errors.Is(err, os.ErrNotExist) { t.Fatal("safe temp was not discarded") }
}
func TestLifecycleLinuxUnsafeTempBatchIsPreservedWithoutPartialDeletion(t *testing.T) {
	for _, kind := range []string{"unknown-name", "symlink", "hardlink", "wrong-mode", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			d, path, global := lifecycleLinuxFixture(t); lifecycleLinuxSeed(t, d, []byte("original-control")); _ = d.close()
			safe := filepath.Join(path, ".tmp-11111111111111111111111111111111")
			bad := filepath.Join(path, ".tmp-22222222222222222222222222222222")
			if os.WriteFile(safe, []byte("safe-but-do-not-delete"), 0600) != nil { t.Fatal("fixture") }
			switch kind {
			case "unknown-name": bad = filepath.Join(path, "unrecognized"); if os.WriteFile(bad, []byte("bad"), 0600) != nil { t.Fatal("fixture") }
			case "symlink": if os.Symlink("control.json", bad) != nil { t.Fatal("fixture") }
			case "hardlink": if os.Link(filepath.Join(path, "control.json"), bad) != nil { t.Fatal("fixture") }
			case "wrong-mode": if os.WriteFile(bad, []byte("bad"), 0644) != nil { t.Fatal("fixture") }
			case "oversized": if os.WriteFile(bad, make([]byte, maxLifecycleControlBytes+1), 0600) != nil { t.Fatal("fixture") }
			}
			if other, err := openLifecycleDiskAt(path, global); err == nil { _ = other.close(); t.Fatal("unsafe abandoned batch recovered") }
			if raw, err := os.ReadFile(safe); err != nil || string(raw) != "safe-but-do-not-delete" { t.Fatal("partial deletion happened before batch validation") }
			if _, err := os.Lstat(bad); err != nil { t.Fatal("unsafe temp was removed") }
		})
	}
}
func TestLifecycleLinuxTempCleanupDirectorySyncFailurePoisons(t *testing.T) {
	d, path, _ := lifecycleLinuxFixture(t); lifecycleLinuxSeed(t, d, []byte("original-control"))
	if os.WriteFile(filepath.Join(path, ".tmp-33333333333333333333333333333333"), []byte("partial"), 0600) != nil { t.Fatal("fixture") }
	d.syncDirectory = func(*os.File) error { return errors.New("synthetic cleanup dirsync fault") }
	if d.recoverAbandonedTemps() == nil || !d.poisoned { t.Fatal("cleanup sync failure called recovered") }
	if _, _, err := d.readControl(); !errors.Is(err, errLifecyclePoisoned) { t.Fatal("failed recovery left disk open") }
	raw, err := os.ReadFile(filepath.Join(path, "control.json"))
	if err != nil || string(raw) != "original-control" { t.Fatal("cleanup modified committed control") }
}
func TestLifecycleLinuxDiskValuePointerNilFormattingNeverReflectsPrivateState(t *testing.T) {
	d, path, global := lifecycleLinuxFixture(t); body := []byte("opaque-private-control-cannot-be-logged")
	lifecycleLinuxSeed(t, d, body)
	for _, value := range []any{d, *d} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d", "%b", "%o", "%O", "%f", "%e", "%g", "%c", "%U", "%t"} {
			if fmt.Sprintf(verb, value) != "private Mihomo lifecycle disk" { t.Fatal("ordinary formatter did not use fixed private scope") }
		}
		for _, verb := range []string{"%p", "%T", "%w"} {
			text := fmt.Sprintf(verb, value)
			for _, forbidden := range []string{path, global, string(body), "writer.lock", "control.json", "syncDirectory", "uid:"} {
				if strings.Contains(text, forbidden) { t.Fatal("special fmt bad-verb path reflected private state") }
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `{"scope":"PRIVATE_LIFECYCLE_DISK_NOT_AUTHORIZATION"}` { t.Fatal("disk JSON reflected private state") }
	}
	var absent *lifecycleLinuxDisk
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d", "%q"} {
		if fmt.Sprintf(verb, absent) != "<nil>" { t.Fatal("fmt typed-nil catch no longer protects value receiver") }
	}
	raw, err := json.Marshal(absent); if err != nil || string(raw) != "null" { t.Fatal("typed nil JSON unsafe") }
	actual, exists, err := d.readControl()
	if err != nil || !exists || !bytes.Equal(actual, body) { t.Fatal("safe formatting changed opaque control bytes") }
}
