//go:build linux

package subscription

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const storeSnapshotName = "store.json"
const storeLockName = "store.lock"
const storeOpenFlags = syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK

type storeDirectory struct {
	file     *os.File
	name     string
	identity syscall.Stat_t
}
type storeLinuxDisk struct {
	chain            []storeDirectory
	lock             *os.File
	lockIdentity     syscall.Stat_t
	snapshotIdentity syscall.Stat_t
	snapshotExists   bool
	uid, gid         uint32
	closed           bool
	// Unexported seams are used only by explicit synthetic write-fault tests.
	beforeRename  func() error
	syncDirectory func(*os.File) error
}

func storeStat(file *os.File) (syscall.Stat_t, error) {
	var value syscall.Stat_t
	if syscall.Fstat(int(file.Fd()), &value) != nil {
		return value, fail(CodeStoreUnsafe)
	}
	return value, nil
}
func storeSame(a, b syscall.Stat_t, content bool) bool {
	if a.Dev != b.Dev || a.Ino != b.Ino || a.Mode != b.Mode || a.Uid != b.Uid || a.Gid != b.Gid {
		return false
	}
	// Parent-directory link counts legitimately change when unrelated siblings
	// are created. Regular files still require exact nlink=1 custody.
	if a.Mode&syscall.S_IFMT != syscall.S_IFDIR && a.Nlink != b.Nlink {
		return false
	}
	return !content || a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func storeFileSafe(value syscall.Stat_t, uid, gid uint32) bool {
	return value.Mode&syscall.S_IFMT == syscall.S_IFREG && value.Mode&07777 == 0600 && value.Uid == uid && value.Gid == gid && value.Nlink == 1 && value.Size >= 0
}
func storeDirectorySafe(value syscall.Stat_t, leaf bool, path string, uid, gid uint32) bool {
	if value.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return false
	}
	if leaf {
		return value.Uid == uid && value.Gid == gid && value.Mode&07777 == 0700
	}
	if path == "/tmp" && value.Uid == 0 && value.Mode&07777 == 01777 {
		return true
	}
	return (value.Uid == 0 || value.Uid == uid) && value.Mode&0022 == 0 && value.Mode&07000 == 0
}
func storeNativeFS(file *os.File) bool {
	var fs syscall.Statfs_t
	if syscall.Fstatfs(int(file.Fd()), &fs) != nil {
		return false
	}
	return fs.Type == 0xef53 || fs.Type == 0x58465342 || fs.Type == 0x01021994
}
func storeOpenAt(dir *os.File, name string, flags int, mode uint32) (*os.File, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, flags|storeOpenFlags, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func storeOpenDisk(path string) (storeDiskIO, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, fail(CodeStoreUnsafe)
	}
	d := &storeLinuxDisk{uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()), syncDirectory: func(f *os.File) error { return f.Sync() }}
	keep := false
	defer func() {
		if !keep {
			_ = d.close()
		}
	}()
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|storeOpenFlags, 0)
	if err != nil {
		return nil, fail(CodeStoreUnsafe)
	}
	root := os.NewFile(uintptr(fd), "/")
	info, err := storeStat(root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	if !storeDirectorySafe(info, false, "/", d.uid, d.gid) {
		_ = root.Close()
		return nil, fail(CodeStoreUnsafe)
	}
	d.chain = append(d.chain, storeDirectory{file: root, identity: info})
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := ""
	for i, name := range parts {
		if name == "" || name == "." || name == ".." {
			return nil, fail(CodeStoreUnsafe)
		}
		parent := d.chain[len(d.chain)-1].file
		child, err := storeOpenAt(parent, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		if errors.Is(err, syscall.ENOENT) && i == len(parts)-1 {
			if syscall.Mkdirat(int(parent.Fd()), name, 0700) != nil {
				return nil, fail(CodeStoreUnsafe)
			}
			if parent.Sync() != nil {
				return nil, fail(CodeStoreUnsafe)
			}
			child, err = storeOpenAt(parent, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		}
		if err != nil {
			return nil, fail(CodeStoreUnsafe)
		}
		info, err := storeStat(child)
		current += "/" + name
		if err != nil || !storeDirectorySafe(info, i == len(parts)-1, current, d.uid, d.gid) {
			_ = child.Close()
			return nil, fail(CodeStoreUnsafe)
		}
		d.chain = append(d.chain, storeDirectory{file: child, name: name, identity: info})
	}
	if !storeNativeFS(d.directory()) {
		return nil, fail(CodeStoreUnsafe)
	}
	if err := d.entries(); err != nil {
		return nil, err
	}
	// Existing private files are checked before any lock-file creation. No
	// chmod/chown repairs an unsafe pre-existing object.
	for _, name := range []string{storeLockName, storeSnapshotName} {
		f, err := storeOpenAt(d.directory(), name, syscall.O_RDONLY, 0)
		if errors.Is(err, syscall.ENOENT) {
			continue
		}
		if err != nil {
			return nil, fail(CodeStoreUnsafe)
		}
		st, err := storeStat(f)
		_ = f.Close()
		if err != nil || !storeFileSafe(st, d.uid, d.gid) {
			return nil, fail(CodeStoreUnsafe)
		}
	}
	lock, err := storeOpenAt(d.directory(), storeLockName, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL, 0600)
	newLock := err == nil
	if errors.Is(err, syscall.EEXIST) {
		lock, err = storeOpenAt(d.directory(), storeLockName, syscall.O_RDWR, 0)
	}
	if err != nil {
		return nil, fail(CodeStoreUnsafe)
	}
	d.lock = lock
	d.lockIdentity, err = storeStat(lock)
	if err != nil || !storeFileSafe(d.lockIdentity, d.uid, d.gid) || !storeNativeFS(lock) {
		return nil, fail(CodeStoreUnsafe)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fail(CodeStoreLocked)
		}
		return nil, fail(CodeStoreUnsafe)
	}
	if newLock && (lock.Sync() != nil || d.directory().Sync() != nil) {
		return nil, fail(CodeStoreUnsafe)
	}
	f, err := storeOpenAt(d.directory(), storeSnapshotName, syscall.O_RDONLY, 0)
	if errors.Is(err, syscall.ENOENT) {
		if !newLock {
			return nil, fail(CodeStoreUnsafe)
		}
	} else if err != nil {
		return nil, fail(CodeStoreUnsafe)
	} else {
		info, err := storeStat(f)
		_ = f.Close()
		if err != nil || !storeFileSafe(info, d.uid, d.gid) {
			return nil, fail(CodeStoreUnsafe)
		}
		d.snapshotExists = true
		d.snapshotIdentity = info
	}
	if err := d.verify(); err != nil {
		return nil, err
	}
	keep = true
	return d, nil
}
func (d *storeLinuxDisk) directory() *os.File { return d.chain[len(d.chain)-1].file }
func (d *storeLinuxDisk) entries() error {
	f, err := storeOpenAt(d.directory(), ".", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fail(CodeStoreUnsafe)
	}
	defer f.Close()
	entries, err := f.ReadDir(3)
	if err != nil && !errors.Is(err, io.EOF) {
		return fail(CodeStoreUnsafe)
	}
	if len(entries) > 2 {
		return fail(CodeStoreUnsafe)
	}
	for _, e := range entries {
		if e.Name() != storeLockName && e.Name() != storeSnapshotName {
			return fail(CodeStoreUnsafe)
		}
	}
	return nil
}
func (d *storeLinuxDisk) named(name string, expected syscall.Stat_t, content bool) error {
	f, err := storeOpenAt(d.directory(), name, syscall.O_RDONLY, 0)
	if err != nil {
		return fail(CodeStoreUnsafe)
	}
	defer f.Close()
	value, err := storeStat(f)
	if err != nil || !storeFileSafe(value, d.uid, d.gid) || !storeSame(value, expected, content) {
		return fail(CodeStoreUnsafe)
	}
	return nil
}
func (d *storeLinuxDisk) verify() error {
	if d.closed {
		return fail(CodeStoreClosed)
	}
	current := ""
	for i, component := range d.chain {
		value, err := storeStat(component.file)
		if err != nil || !storeSame(value, component.identity, false) {
			return fail(CodeStoreUnsafe)
		}
		if i == 0 {
			continue
		}
		current += "/" + component.name
		if !storeDirectorySafe(value, i == len(d.chain)-1, current, d.uid, d.gid) {
			return fail(CodeStoreUnsafe)
		}
		f, err := storeOpenAt(d.chain[i-1].file, component.name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		if err != nil {
			return fail(CodeStoreUnsafe)
		}
		named, err := storeStat(f)
		_ = f.Close()
		if err != nil || !storeSame(value, named, false) {
			return fail(CodeStoreUnsafe)
		}
	}
	if !storeNativeFS(d.directory()) {
		return fail(CodeStoreUnsafe)
	}
	if err := d.entries(); err != nil {
		return err
	}
	if err := d.named(storeLockName, d.lockIdentity, true); err != nil {
		return err
	}
	if d.snapshotExists {
		return d.named(storeSnapshotName, d.snapshotIdentity, true)
	}
	f, err := storeOpenAt(d.directory(), storeSnapshotName, syscall.O_RDONLY, 0)
	if err == nil {
		_ = f.Close()
		return fail(CodeStoreUnsafe)
	}
	if !errors.Is(err, syscall.ENOENT) {
		return fail(CodeStoreUnsafe)
	}
	return nil
}
func (d *storeLinuxDisk) read() ([]byte, bool, error) {
	if err := d.verify(); err != nil {
		return nil, false, err
	}
	if !d.snapshotExists {
		return nil, false, nil
	}
	f, err := storeOpenAt(d.directory(), storeSnapshotName, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, false, fail(CodeStoreUnsafe)
	}
	defer f.Close()
	before, err := storeStat(f)
	if err != nil || before.Size > MaxStoreBytes || !storeSame(before, d.snapshotIdentity, true) {
		return nil, false, fail(CodeStoreUnsafe)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxStoreBytes+1))
	if err != nil || int64(len(raw)) != before.Size {
		return nil, false, fail(CodeStoreUnsafe)
	}
	after, err := storeStat(f)
	if err != nil || !storeSame(before, after, true) {
		return nil, false, fail(CodeStoreUnsafe)
	}
	if err := d.verify(); err != nil {
		return nil, false, err
	}
	return raw, true, nil
}
func (d *storeLinuxDisk) write(raw []byte) (bool, error) {
	if len(raw) == 0 || len(raw) > MaxStoreBytes {
		return false, fail(CodeStoreLimit)
	}
	if err := d.verify(); err != nil {
		return false, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return false, fail(CodeStoreUnsafe)
	}
	name := ".store-" + hex.EncodeToString(random[:]) + ".tmp"
	f, err := storeOpenAt(d.directory(), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0600)
	if err != nil {
		return false, fail(CodeStoreUnsafe)
	}
	renamed := false
	defer func() {
		_ = f.Close()
		if !renamed {
			_ = syscall.Unlinkat(int(d.directory().Fd()), name)
		}
	}()
	if st, err := storeStat(f); err != nil || !storeFileSafe(st, d.uid, d.gid) {
		return false, fail(CodeStoreUnsafe)
	}
	if _, err := io.Copy(f, bytes.NewReader(raw)); err != nil {
		return false, fail(CodeStoreUnsafe)
	}
	if f.Sync() != nil {
		return false, fail(CodeStoreUnsafe)
	}
	written, err := storeStat(f)
	if err != nil || !storeFileSafe(written, d.uid, d.gid) || written.Size != int64(len(raw)) {
		return false, fail(CodeStoreUnsafe)
	}
	if d.beforeRename != nil && d.beforeRename() != nil {
		return false, fail(CodeStoreUnsafe)
	}
	// Bind all parents and both original live objects again immediately before
	// replacement; the temporary file is the one additional owned entry here.
	if err := d.verifyForRename(name, written); err != nil {
		return false, err
	}
	stable, err := storeStat(f)
	if err != nil || !storeSame(written, stable, true) {
		return false, fail(CodeStoreUnsafe)
	}
	if syscall.Renameat(int(d.directory().Fd()), name, int(d.directory().Fd()), storeSnapshotName) != nil {
		return false, fail(CodeStoreUnsafe)
	}
	renamed = true
	if d.syncDirectory(d.directory()) != nil {
		return true, fail(CodeCommitUncertain)
	}
	value, err := storeStat(f)
	if err != nil {
		return true, fail(CodeCommitUncertain)
	}
	d.snapshotIdentity = value
	d.snapshotExists = true
	if err := d.verify(); err != nil {
		return true, fail(CodeCommitUncertain)
	}
	return false, nil
}
func (d *storeLinuxDisk) verifyForRename(temporary string, expected syscall.Stat_t) error {
	// Temporarily exclude only our exact private temporary name from directory
	// enumeration. All other identity checks are identical to normal reads.
	f, err := storeOpenAt(d.directory(), ".", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fail(CodeStoreUnsafe)
	}
	defer f.Close()
	entries, err := f.ReadDir(4)
	if err != nil && !errors.Is(err, io.EOF) {
		return fail(CodeStoreUnsafe)
	}
	if len(entries) > 3 {
		return fail(CodeStoreUnsafe)
	}
	seen := false
	for _, e := range entries {
		if e.Name() == temporary {
			seen = true
			continue
		}
		if e.Name() != storeSnapshotName && e.Name() != storeLockName {
			return fail(CodeStoreUnsafe)
		}
	}
	if !seen {
		return fail(CodeStoreUnsafe)
	}
	if err := d.named(temporary, expected, true); err != nil {
		return err
	}
	for i, c := range d.chain {
		v, err := storeStat(c.file)
		if err != nil || !storeSame(v, c.identity, false) {
			return fail(CodeStoreUnsafe)
		}
		if i > 0 {
			n, err := storeOpenAt(d.chain[i-1].file, c.name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
			if err != nil {
				return fail(CodeStoreUnsafe)
			}
			x, err := storeStat(n)
			_ = n.Close()
			if err != nil || !storeSame(v, x, false) {
				return fail(CodeStoreUnsafe)
			}
		}
	}
	if err := d.named(storeLockName, d.lockIdentity, true); err != nil {
		return err
	}
	if d.snapshotExists {
		return d.named(storeSnapshotName, d.snapshotIdentity, true)
	}
	return nil
}
func (d *storeLinuxDisk) close() error {
	if d.closed {
		return nil
	}
	d.closed = true
	failed := false
	if d.lock != nil {
		if syscall.Flock(int(d.lock.Fd()), syscall.LOCK_UN) != nil {
			failed = true
		}
		if d.lock.Close() != nil {
			failed = true
		}
	}
	for i := len(d.chain) - 1; i >= 0; i-- {
		if d.chain[i].file.Close() != nil {
			failed = true
		}
	}
	if failed {
		return fail(CodeStoreUnsafe)
	}
	return nil
}
