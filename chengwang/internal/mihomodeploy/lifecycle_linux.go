//go:build linux

package mihomodeploy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type lifecycleDirectory struct {
	file *os.File
	name string
	identity syscall.Stat_t
	mount uint64
	filesystem syscall.Statfs_t
}
// A value copy contains one opaque pointer only. Even fmt's %p bad-verb path,
// which bypasses Formatter, cannot expand nested paths, locks or syscall hooks.
type lifecycleLinuxDisk struct { *lifecycleLinuxDiskCore }
type lifecycleLinuxDiskCore struct {
	globalChain, chain []lifecycleDirectory
	global, lock *os.File
	globalIdentity, lockIdentity, controlIdentity syscall.Stat_t
	globalMount, lockMount uint64
	controlExists, closed, poisoned bool
	uid, gid uint32
	// Source-owned fault seams, not runtime configuration or API parameters.
	syncFile func(*os.File) error
	closeFile func(*os.File) error
	rename func(*os.File, string, string) error
	syncDirectory func(*os.File) error
	readback func() ([]byte, bool, error)
}
func (lifecycleLinuxDisk) String() string { return "private Mihomo lifecycle disk" }
func (lifecycleLinuxDisk) GoString() string { return "private Mihomo lifecycle disk" }
func (lifecycleLinuxDisk) MarshalJSON() ([]byte, error) { return []byte(`{"scope":"PRIVATE_LIFECYCLE_DISK_NOT_AUTHORIZATION"}`), nil }
// A value receiver protects ordinary verbs on both values and pointers. fmt's
// fixed Go1.23.12 catchPanic handles a typed nil pointer as <nil>; %T and %p are
// fmt's built-in special cases, not claims of fixed-text formatting.
func (lifecycleLinuxDisk) Format(state fmt.State, verb rune) { _, _ = io.WriteString(state, "private Mihomo lifecycle disk") }

// These are cooperating writers in the same host/mount-lock scope. An advisory
// flock is neither a distributed lease nor a fence against an external curl.
func openLifecycleDisk() (lifecycleDisk, error) {
	return openLifecycleDiskAt(lifecycleRootPath, lifecycleGlobalLockPath)
}

func lifecycleMountID(file *os.File) (uint64, error) {
	f, err := os.Open("/proc/self/fdinfo/" + strconv.Itoa(int(file.Fd())))
	if err != nil { return 0, errLifecycleUnsafe }; defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) > 8192 { return 0, errLifecycleUnsafe }
	var result uint64
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "mnt_id:") {
			if result != 0 { return 0, errLifecycleUnsafe }
			v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:")), 10, 64)
			if err != nil || v == 0 { return 0, errLifecycleUnsafe }; result = v
		}
	}
	if result == 0 { return 0, errLifecycleUnsafe }; return result, nil
}
func lifecycleFilesystem(f *os.File) (syscall.Statfs_t, error) {
	var v syscall.Statfs_t
	if syscall.Fstatfs(int(f.Fd()), &v) != nil { return v, errLifecycleUnsafe }; return v, nil
}
func lifecycleSupported(v syscall.Statfs_t) bool { return v.Type == 0xef53 || v.Type == 0x58465342 || v.Type == 0x01021994 }
func lifecycleSameFilesystem(a, b syscall.Statfs_t) bool { return a.Type == b.Type && a.Fsid == b.Fsid && a.Flags == b.Flags }
func (d *lifecycleLinuxDisk) fileSafe(v syscall.Stat_t, empty bool) bool {
	return d != nil && d.lifecycleLinuxDiskCore != nil && v.Mode&syscall.S_IFMT == syscall.S_IFREG && v.Mode&07777 == 0600 && v.Uid == d.uid && v.Gid == d.gid && v.Nlink == 1 &&
		v.Size >= 0 && (empty || v.Size > 0) && v.Size <= maxLifecycleControlBytes
}
func (d *lifecycleLinuxDisk) directorySafe(v syscall.Stat_t, leaf bool, path string) bool {
	if d == nil || d.lifecycleLinuxDiskCore == nil { return false }
	if v.Mode&syscall.S_IFMT != syscall.S_IFDIR { return false }
	if leaf { return v.Uid == d.uid && v.Gid == d.gid && v.Mode&07777 == 0700 }
	if path == "/tmp" && v.Uid == 0 && v.Mode&07777 == 01777 { return true }
	return (v.Uid == 0 || v.Uid == d.uid) && v.Mode&0022 == 0 && v.Mode&07000 == 0
}
func (d *lifecycleLinuxDisk) openChain(path string, leaf, create bool) ([]lifecycleDirectory, error) {
	if d == nil || d.lifecycleLinuxDiskCore == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" { return nil, errLifecycleUnsafe }
	var chain []lifecycleDirectory
	keep := false; defer func() { if !keep { for i := len(chain)-1; i >= 0; i-- { _ = chain[i].file.Close() } } }()
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|artifactOpenFlags, 0)
	if err != nil { return nil, errLifecycleUnsafe }
	f := os.NewFile(uintptr(fd), "/")
	st, e1 := artifactStat(f); mnt, e2 := lifecycleMountID(f); fs, e3 := lifecycleFilesystem(f)
	if e1 != nil || e2 != nil || e3 != nil || !d.directorySafe(st, false, "/") { _ = f.Close(); return nil, errLifecycleUnsafe }
	chain = append(chain, lifecycleDirectory{file: f, identity: st, mount: mnt, filesystem: fs})
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/"); current := ""
	for i, name := range parts {
		parent := chain[len(chain)-1].file; current += "/" + name
		child, err := artifactOpen(parent, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		if errors.Is(err, syscall.ENOENT) && create && i == len(parts)-1 {
			if syscall.Mkdirat(int(parent.Fd()), name, 0700) != nil || parent.Sync() != nil { return nil, errLifecycleUnsafe }
			child, err = artifactOpen(parent, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		}
		if err != nil { return nil, errLifecycleUnsafe }
		v, e1 := artifactStat(child); mnt, e2 := lifecycleMountID(child); fs, e3 := lifecycleFilesystem(child)
		if e1 != nil || e2 != nil || e3 != nil || !d.directorySafe(v, leaf && i == len(parts)-1, current) { _ = child.Close(); return nil, errLifecycleUnsafe }
		chain = append(chain, lifecycleDirectory{child, name, v, mnt, fs})
	}
	if !lifecycleSupported(chain[len(chain)-1].filesystem) { return nil, errLifecycleUnsupported }
	keep = true; return chain, nil
}

// Alternate paths are package-private test inputs only. No exported constructor
// or HTTP surface may choose the durable directory or host lock path.
func openLifecycleDiskAt(path, globalPath string) (lifecycleDisk, error) {
	if !filepath.IsAbs(globalPath) || filepath.Clean(globalPath) != globalPath || globalPath == "/" ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || globalPath == path ||
		strings.HasPrefix(globalPath, path+"/") { return nil, errLifecycleUnsafe }
	d := &lifecycleLinuxDisk{lifecycleLinuxDiskCore: &lifecycleLinuxDiskCore{uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()),
		syncFile: func(f *os.File) error { return f.Sync() }, closeFile: func(f *os.File) error { return f.Close() },
		rename: func(dir *os.File, a, b string) error { return syscall.Renameat(int(dir.Fd()), a, int(dir.Fd()), b) },
		syncDirectory: func(f *os.File) error { return f.Sync() }}}
	keep := false; defer func() { if !keep { _ = d.close() } }()
	var err error
	d.globalChain, err = d.openChain(filepath.Dir(globalPath), false, false)
	if err != nil { return nil, err }
	parent := d.globalChain[len(d.globalChain)-1].file
	d.global, err = artifactOpen(parent, filepath.Base(globalPath), syscall.O_RDWR|syscall.O_CREAT, 0600)
	if err != nil { return nil, errLifecycleUnsafe }
	d.globalIdentity, err = artifactStat(d.global)
	if err != nil || !d.fileSafe(d.globalIdentity, true) || d.globalIdentity.Size != 0 { return nil, errLifecycleUnsafe }
	d.globalMount, err = lifecycleMountID(d.global); if err != nil { return nil, err }
	if syscall.Flock(int(d.global.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil { return nil, errLifecycleLocked }
	if d.global.Sync() != nil || parent.Sync() != nil { return nil, errLifecycleUnsafe }
	d.chain, err = d.openChain(path, true, true)
	if err != nil { return nil, err }
	d.lock, err = artifactOpen(d.directory(), "writer.lock", syscall.O_RDWR|syscall.O_CREAT, 0600)
	if err != nil { return nil, errLifecycleUnsafe }
	d.lockIdentity, err = artifactStat(d.lock)
	if err != nil || !d.fileSafe(d.lockIdentity, true) || d.lockIdentity.Size != 0 { return nil, errLifecycleUnsafe }
	d.lockMount, err = lifecycleMountID(d.lock); if err != nil { return nil, err }
	if syscall.Flock(int(d.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil { return nil, errLifecycleLocked }
	if d.lock.Sync() != nil || d.directory().Sync() != nil { return nil, errLifecycleUnsafe }
	f, err := artifactOpen(d.directory(), "control.json", syscall.O_RDONLY, 0)
	if err == nil {
		d.controlIdentity, err = artifactStat(f); mount, mountErr := lifecycleMountID(f); closeErr := f.Close()
		if err != nil || mountErr != nil || closeErr != nil || !d.fileSafe(d.controlIdentity, false) || mount != d.chain[len(d.chain)-1].mount { return nil, errLifecycleUnsafe }
		d.controlExists = true
	} else if !errors.Is(err, syscall.ENOENT) { return nil, errLifecycleUnsafe }
	d.readback = d.readControl
	if err := d.recoverAbandonedTemps(); err != nil { return nil, err }
	if err := d.verify(); err != nil { return nil, err }
	keep = true; return d, nil
}
func (d *lifecycleLinuxDisk) directory() *os.File { if d == nil || d.lifecycleLinuxDiskCore == nil || len(d.chain) == 0 { return nil }; return d.chain[len(d.chain)-1].file }
func (d *lifecycleLinuxDisk) checkChain(chain []lifecycleDirectory) error {
	if d == nil || d.lifecycleLinuxDiskCore == nil || len(chain) == 0 { return errLifecycleUnsafe }
	for i, c := range chain {
		st, e1 := artifactStat(c.file); mount, e2 := lifecycleMountID(c.file); fs, e3 := lifecycleFilesystem(c.file)
		if e1 != nil || e2 != nil || e3 != nil || !artifactSame(c.identity, st, false) || mount != c.mount || !lifecycleSameFilesystem(c.filesystem, fs) { return errLifecycleUnsafe }
		if i > 0 && d.named(chain[i-1].file, c.name, st, mount, false) != nil { return errLifecycleUnsafe }
	}
	return nil
}
func (d *lifecycleLinuxDisk) named(dir *os.File, name string, expected syscall.Stat_t, expectedMount uint64, content bool) error {
	if d == nil || d.lifecycleLinuxDiskCore == nil { return errLifecycleUnsafe }
	f, err := artifactOpen(dir, name, syscall.O_RDONLY, 0)
	if err != nil { return errLifecycleUnsafe }
	actual, e1 := artifactStat(f); mount, e2 := lifecycleMountID(f); e3 := f.Close()
	if e1 != nil || e2 != nil || e3 != nil || !artifactSame(expected, actual, content) || mount != expectedMount { return errLifecycleUnsafe }
	return nil
}
func (d *lifecycleLinuxDisk) verifyCustody() error {
	if d == nil || d.lifecycleLinuxDiskCore == nil || d.closed || d.poisoned { return errLifecyclePoisoned }
	if d.global == nil || d.lock == nil || d.checkChain(d.globalChain) != nil || d.checkChain(d.chain) != nil { return errLifecycleUnsafe }
	if d.named(d.globalChain[len(d.globalChain)-1].file, d.global.Name(), d.globalIdentity, d.globalMount, true) != nil ||
		d.named(d.directory(), "writer.lock", d.lockIdentity, d.lockMount, true) != nil { return errLifecycleUnsafe }
	if d.controlExists {
		if d.named(d.directory(), "control.json", d.controlIdentity, d.chain[len(d.chain)-1].mount, true) != nil { return errLifecycleUnsafe }
	} else {
		f, err := artifactOpen(d.directory(), "control.json", syscall.O_RDONLY, 0)
		if err == nil { _ = f.Close(); return errLifecycleUnsafe }; if !errors.Is(err, syscall.ENOENT) { return errLifecycleUnsafe }
	}
	return nil
}
func (d *lifecycleLinuxDisk) verifyAllow(temp string) error {
	if err := d.verifyCustody(); err != nil { return err }
	listing, err := artifactOpen(d.directory(), ".", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil { return errLifecycleUnsafe }; defer listing.Close()
	entries, err := listing.ReadDir(4)
	if err != nil && !errors.Is(err, io.EOF) { return errLifecycleUnsafe }
	if len(entries) > 3 { return errLifecycleUnsafe }
	for _, entry := range entries {
		if entry.Name() != "writer.lock" && entry.Name() != "control.json" && (temp == "" || entry.Name() != temp || !artifactTemp(temp)) { return errLifecycleUnsafe }
	}
	return nil
}

// Discard only a validated abandoned temp while both writer locks are held and
// a stable control already exists. A temp is never promoted or interpreted.
// The owner trust boundary is cooperative: advisory flock and repeated inode
// checks cannot atomically exclude arbitrary rogue same-UID path replacement.
func (d *lifecycleLinuxDisk) recoverAbandonedTemps() (err error) {
	defer func() { if err != nil && d != nil && d.lifecycleLinuxDiskCore != nil { d.poisoned = true } }()
	if err := d.verifyCustody(); err != nil { return err }
	listing, err := artifactOpen(d.directory(), ".", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil { return errLifecycleUnsafe }
	entries, readErr := listing.ReadDir(35); closeErr := listing.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(entries) > 34 { return errLifecycleUnsafe }
	type abandoned struct { name string; identity syscall.Stat_t }
	var temps []abandoned
	for _, entry := range entries {
		name := entry.Name()
		if name == "writer.lock" || name == "control.json" { continue }
		if !d.controlExists || !artifactTemp(name) { return errLifecycleUnsafe }
		f, err := artifactOpen(d.directory(), name, syscall.O_RDONLY, 0)
		if err != nil { return errLifecycleUnsafe }
		st, e1 := artifactStat(f); mount, e2 := lifecycleMountID(f); e3 := f.Close()
		if e1 != nil || e2 != nil || e3 != nil || !d.fileSafe(st, true) || mount != d.chain[len(d.chain)-1].mount ||
			d.named(d.directory(), name, st, mount, true) != nil { return errLifecycleUnsafe }
		temps = append(temps, abandoned{name, st})
	}
	if len(temps) == 0 { return nil }
	baseline, err := d.readControlBytes()
	if err != nil { return err }
	for _, temp := range temps {
		if d.verifyCustody() != nil || d.named(d.directory(), temp.name, temp.identity, d.chain[len(d.chain)-1].mount, true) != nil { return errLifecycleUnsafe }
		current, err := d.readControlBytes()
		if err != nil || !bytes.Equal(current, baseline) { return errLifecycleUnsafe }
		if syscall.Unlinkat(int(d.directory().Fd()), temp.name) != nil { return errLifecycleUnsafe }
	}
	if d.syncDirectory == nil || d.syncDirectory(d.directory()) != nil || d.verifyCustody() != nil { return errLifecycleUnsafe }
	current, err := d.readControlBytes()
	if err != nil || !bytes.Equal(current, baseline) { return errLifecycleUnsafe }
	return nil
}
func (d *lifecycleLinuxDisk) verify() error {
	err := d.verifyAllow("")
	if err != nil && d != nil && d.lifecycleLinuxDiskCore != nil && !d.closed { d.poisoned = true }
	return err
}
func (d *lifecycleLinuxDisk) readControl() ([]byte, bool, error) {
	if err := d.verify(); err != nil { return nil, false, err }
	if !d.controlExists { return nil, false, nil }
	raw, err := d.readControlBytes()
	if err != nil || d.verify() != nil { d.poisoned = true; return nil, false, errLifecycleUnsafe }
	return raw, true, nil
}
func (d *lifecycleLinuxDisk) readControlBytes() ([]byte, error) {
	if d == nil || d.lifecycleLinuxDiskCore == nil || !d.controlExists || d.verifyCustody() != nil { return nil, errLifecycleUnsafe }
	f, err := artifactOpen(d.directory(), "control.json", syscall.O_RDONLY, 0)
	if err != nil { return nil, errLifecycleUnsafe }
	before, e1 := artifactStat(f)
	if e1 != nil || !d.fileSafe(before, false) || !artifactSame(d.controlIdentity, before, true) { _ = f.Close(); return nil, errLifecycleUnsafe }
	raw, e2 := io.ReadAll(io.LimitReader(f, maxLifecycleControlBytes+1)); after, e3 := artifactStat(f); closeErr := f.Close()
	if e2 != nil || e3 != nil || closeErr != nil || !artifactSame(before, after, true) || int64(len(raw)) != before.Size || d.verifyCustody() != nil {
		return nil, errLifecycleUnsafe
	}
	return raw, nil
}
func (d *lifecycleLinuxDisk) replaceControl(raw []byte) (lifecycleCommitState, error) {
	if d == nil || d.lifecycleLinuxDiskCore == nil || d.closed || d.poisoned { return lifecycleNotCommitted, errLifecyclePoisoned }
	if len(raw) == 0 || len(raw) > maxLifecycleControlBytes { return lifecycleNotCommitted, errLifecycleUnsafe }
	if err := d.verify(); err != nil { return lifecycleNotCommitted, err }
	uncertain, err := privateAtomicReplace(d.directory(), "control.json", raw, privateAtomicPolicy{
		kind: privateAtomicLifecycle, unsafe: errLifecycleUnsafe, unknown: errLifecycleCommitUnknown,
		verify: d.verify, safe: func(st syscall.Stat_t) bool { return d.fileSafe(st, true) },
		named: func(dir *os.File, name string, st syscall.Stat_t) error { return d.named(dir, name, st, d.chain[len(d.chain)-1].mount, true) },
		syncFile: d.syncFile, closeFile: d.closeFile, rename: d.rename, syncDirectory: d.syncDirectory,
		beforeRename: func(temp string) error { return d.verifyAllow(temp) },
		afterRename: func(_ *os.File) error {
			f, err := artifactOpen(d.directory(), "control.json", syscall.O_RDONLY, 0)
			if err != nil { return errLifecycleUnsafe }
			st, e1 := artifactStat(f); mount, e2 := lifecycleMountID(f); e3 := f.Close()
			if e1 != nil || e2 != nil || e3 != nil || !d.fileSafe(st, false) || mount != d.chain[len(d.chain)-1].mount { return errLifecycleUnsafe }
			d.controlIdentity, d.controlExists = st, true
			if d.readback == nil { return errLifecycleUnsafe }
			actual, exists, err := d.readback()
			if err != nil || !exists || !bytes.Equal(actual, raw) || d.verify() != nil { return errLifecycleUnsafe }
			return nil
		},
	})
	if uncertain { d.poisoned = true; return lifecycleUnknown, errLifecycleCommitUnknown }
	if err != nil { return lifecycleNotCommitted, err }
	return lifecycleCommitted, nil
}
func (d *lifecycleLinuxDisk) close() error {
	if d == nil || d.lifecycleLinuxDiskCore == nil || d.closed { return nil }; d.closed = true; failed := false
	if d.lock != nil { if syscall.Flock(int(d.lock.Fd()), syscall.LOCK_UN) != nil { failed = true }; if d.lock.Close() != nil { failed = true } }
	for i := len(d.chain)-1; i >= 0; i-- { if d.chain[i].file.Close() != nil { failed = true } }
	if d.global != nil { if syscall.Flock(int(d.global.Fd()), syscall.LOCK_UN) != nil { failed = true }; if d.global.Close() != nil { failed = true } }
	for i := len(d.globalChain)-1; i >= 0; i-- { if d.globalChain[i].file.Close() != nil { failed = true } }
	if failed { return errLifecycleUnsafe }; return nil
}
