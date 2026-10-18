//go:build linux

package proberestore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type platformStore struct {
	dirPath      string
	dir          *os.File
	lock         *os.File
	dirStat      syscall.Stat_t
	lockStat     syscall.Stat_t
	replaceFault func(replaceStage) error
	dirSync      func(int) error
}

// replaceStage names the durability boundary immediately before or after each
// operation in the single-file commit protocol. replaceFault is nil in
// production; authoritative Linux tests use it to prove that every observed
// result is an old complete record, a new complete record, or a fail-closed
// store. The hook must never be used to recover or continue a failed write.
type replaceStage string

const (
	replaceBeforeWrite   replaceStage = "before-temp-write"
	replaceAfterWrite    replaceStage = "after-temp-write"
	replaceBeforeSync    replaceStage = "before-temp-sync"
	replaceAfterSync     replaceStage = "after-temp-sync"
	replaceBeforeRename  replaceStage = "before-renameat"
	replaceAfterRename   replaceStage = "after-renameat"
	replaceBeforeDirSync replaceStage = "before-directory-fsync"
	replaceAfterDirSync  replaceStage = "after-directory-fsync"
)

const (
	ext4SuperMagic = 0xEF53
	xfsSuperMagic  = 0x58465342
)

func openPlatformStore(path string) (*platformStore, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("control directory must be absolute")
	}
	if err := validateRootOwnedAncestors(path); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	d := os.NewFile(uintptr(fd), path)
	ok := false
	defer func() {
		if !ok {
			_ = d.Close()
		}
	}()
	var ds syscall.Stat_t
	if err := syscall.Fstat(fd, &ds); err != nil {
		return nil, err
	}
	if ds.Mode&syscall.S_IFMT != syscall.S_IFDIR || ds.Uid != 0 || ds.Mode&0o777 != 0o700 {
		return nil, errors.New("control directory must be root-owned mode 0700")
	}
	var fs syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &fs); err != nil {
		return nil, err
	}
	fsType := uint64(fs.Type)
	if fsType != ext4SuperMagic && fsType != xfsSuperMagic {
		return nil, fmt.Errorf("%w: control directory filesystem type 0x%x is not ext4 or XFS", ErrDurabilityUnsupported, fsType)
	}
	lfd, err := syscall.Openat(fd, lockFilename, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(lfd), lockFilename)
	lockOK := false
	defer func() {
		if !lockOK {
			_ = lock.Close()
		}
	}()
	var ls syscall.Stat_t
	if err := syscall.Fstat(lfd, &ls); err != nil {
		return nil, err
	}
	if err := secureRootFileStat("writer lock", ls); err != nil {
		return nil, err
	}
	if ls.Size != 0 {
		return nil, errors.New("writer lock must have size 0")
	}
	if err := syscall.Flock(lfd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrStoreLocked
		}
		return nil, err
	}
	p := &platformStore{dirPath: path, dir: d, lock: lock, dirStat: ds, lockStat: ls, dirSync: syscall.Fsync}
	if err := p.verifyBindings(); err != nil {
		_ = syscall.Flock(lfd, syscall.LOCK_UN)
		return nil, err
	}
	if err := p.cleanupOrphanTemps(); err != nil {
		_ = syscall.Flock(lfd, syscall.LOCK_UN)
		return nil, err
	}
	ok, lockOK = true, true
	return p, nil
}
func (p *platformStore) durableWrites() bool { return true }
func (p *platformStore) close() error {
	if p == nil {
		return nil
	}
	var errs []error
	if p.lock != nil {
		errs = append(errs, syscall.Flock(int(p.lock.Fd()), syscall.LOCK_UN), p.lock.Close())
		p.lock = nil
	}
	if p.dir != nil {
		errs = append(errs, p.dir.Close())
		p.dir = nil
	}
	return errors.Join(errs...)
}
func (p *platformStore) verifyBindings() error {
	var ds syscall.Stat_t
	if err := syscall.Fstat(int(p.dir.Fd()), &ds); err != nil {
		return err
	}
	if ds.Dev != p.dirStat.Dev || ds.Ino != p.dirStat.Ino || ds.Uid != 0 || ds.Mode&0o777 != 0o700 {
		return errors.New("control directory fd identity changed")
	}
	pathFD, err := syscall.Open(p.dirPath, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("reopen control directory path: %w", err)
	}
	var pathStat syscall.Stat_t
	statErr := syscall.Fstat(pathFD, &pathStat)
	closeErr := syscall.Close(pathFD)
	if statErr != nil {
		return statErr
	}
	if closeErr != nil {
		return closeErr
	}
	if pathStat.Dev != p.dirStat.Dev || pathStat.Ino != p.dirStat.Ino {
		return errors.New("control directory path was replaced")
	}
	fd, err := syscall.Openat(int(p.dir.Fd()), lockFilename, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("reopen writer lock: %w", err)
	}
	defer syscall.Close(fd)
	var ls syscall.Stat_t
	if err := syscall.Fstat(fd, &ls); err != nil {
		return err
	}
	if err := secureRootFileStat("writer lock", ls); err != nil {
		return err
	}
	if ls.Size != 0 {
		return errors.New("writer lock must have size 0")
	}
	if ls.Dev != p.lockStat.Dev || ls.Ino != p.lockStat.Ino {
		return errors.New("writer lock was unlinked or replaced")
	}
	return nil
}
func (p *platformStore) read(name string, limit int) ([]byte, error) {
	if err := p.verifyBindings(); err != nil {
		return nil, err
	}
	fd, err := syscall.Openat(int(p.dir.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if err := secureRootFileStat(name, st); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errors.New("control record exceeds size limit")
	}
	checkFD, err := syscall.Openat(int(p.dir.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var check syscall.Stat_t
	statErr := syscall.Fstat(checkFD, &check)
	closeErr := syscall.Close(checkFD)
	if statErr != nil {
		return nil, statErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if check.Dev != st.Dev || check.Ino != st.Ino {
		return nil, fmt.Errorf("%s path was replaced while reading", name)
	}
	if err := p.verifyBindings(); err != nil {
		return nil, err
	}
	return b, nil
}
func (p *platformStore) replace(name string, data []byte) error {
	if err := p.verifyBindings(); err != nil {
		return err
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	tmp := ".tmp-" + hex.EncodeToString(random)
	fd, err := syscall.Openat(int(p.dir.Fd()), tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = syscall.Unlinkat(int(p.dir.Fd()), tmp)
		}
	}()
	f := os.NewFile(uintptr(fd), tmp)
	var tempStat syscall.Stat_t
	if err := syscall.Fstat(fd, &tempStat); err != nil {
		_ = f.Close()
		return err
	}
	if err := secureRootFileStat(tmp, tempStat); err != nil {
		_ = f.Close()
		return err
	}
	if err := p.injectReplaceFault(replaceBeforeWrite); err != nil {
		_ = f.Close()
		return err
	}
	n, werr := f.Write(data)
	if werr == nil && n != len(data) {
		werr = io.ErrShortWrite
	}
	if werr == nil {
		werr = p.injectReplaceFault(replaceAfterWrite)
	}
	if werr == nil {
		werr = p.injectReplaceFault(replaceBeforeSync)
	}
	if werr == nil {
		werr = f.Sync()
	}
	if werr == nil {
		werr = p.injectReplaceFault(replaceAfterSync)
	}
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	if err := p.injectReplaceFault(replaceBeforeRename); err != nil {
		return err
	}
	if err := syscall.Renameat(int(p.dir.Fd()), tmp, int(p.dir.Fd()), name); err != nil {
		return err
	}
	cleanup = false
	if err := p.injectReplaceFault(replaceAfterRename); err != nil {
		return err
	}
	if err := p.injectReplaceFault(replaceBeforeDirSync); err != nil {
		return err
	}
	if err := p.dirSync(int(p.dir.Fd())); err != nil {
		return err
	}
	if err := p.injectReplaceFault(replaceAfterDirSync); err != nil {
		return err
	}
	if err := p.verifyBindings(); err != nil {
		return err
	}
	fd, err = syscall.Openat(int(p.dir.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Dev != tempStat.Dev || st.Ino != tempStat.Ino {
		return fmt.Errorf("%s committed path does not reference the flushed temporary inode", name)
	}
	return secureRootFileStat(name, st)
}

func (p *platformStore) injectReplaceFault(stage replaceStage) error {
	if p.replaceFault == nil {
		return nil
	}
	return p.replaceFault(stage)
}

// cleanupOrphanTemps runs only after the exclusive writer lock is held. A
// crash may leave a fully written temporary inode before rename; such an inode
// is not authoritative state and is safe to unlink only when its name and
// metadata exactly match files created by replace. Anything suspicious fails
// Open closed and is left untouched for operator inspection.
func (p *platformStore) cleanupOrphanTemps() error {
	names, err := p.dir.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("enumerate control directory: %w", err)
	}
	var orphans []string
	for _, name := range names {
		if !strings.HasPrefix(name, ".tmp-") {
			continue
		}
		if !validOrphanTempName(name) {
			return fmt.Errorf("unsafe orphan temporary name %q", name)
		}
		fd, err := syscall.Openat(int(p.dir.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return fmt.Errorf("inspect orphan temporary %q: %w", name, err)
		}
		var st syscall.Stat_t
		statErr := syscall.Fstat(fd, &st)
		closeErr := syscall.Close(fd)
		if statErr != nil {
			return fmt.Errorf("stat orphan temporary %q: %w", name, statErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close orphan temporary %q: %w", name, closeErr)
		}
		if err := secureRootFileStat(name, st); err != nil {
			return fmt.Errorf("unsafe orphan temporary: %w", err)
		}
		orphans = append(orphans, name)
	}
	for _, name := range orphans {
		if err := syscall.Unlinkat(int(p.dir.Fd()), name); err != nil {
			return fmt.Errorf("remove orphan temporary %q: %w", name, err)
		}
	}
	if len(orphans) > 0 {
		if err := p.dirSync(int(p.dir.Fd())); err != nil {
			return fmt.Errorf("sync orphan cleanup: %w", err)
		}
	}
	return p.verifyBindings()
}

func validOrphanTempName(name string) bool {
	if len(name) != len(".tmp-")+24 || !strings.HasPrefix(name, ".tmp-") {
		return false
	}
	for _, ch := range name[len(".tmp-"):] {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

func secureRootFileStat(name string, st syscall.Stat_t) error {
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != 0 || st.Mode&0o777 != 0o600 || st.Nlink != 1 {
		return fmt.Errorf("%s must be root-owned mode 0600 single-link regular file", name)
	}
	return nil
}
func validateRootOwnedAncestors(path string) error {
	clean := filepath.Clean(path)
	parts := strings.Split(strings.TrimPrefix(clean, string(os.PathSeparator)), string(os.PathSeparator))
	current := string(os.PathSeparator)
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		var st syscall.Stat_t
		if err := syscall.Lstat(current, &st); err != nil {
			return err
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
			return fmt.Errorf("control path ancestor must be root-owned and not group/other writable: %s", current)
		}
	}
	return nil
}
