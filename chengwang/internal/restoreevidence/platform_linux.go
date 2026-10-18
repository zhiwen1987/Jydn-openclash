//go:build linux

package restoreevidence

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const clockBoottime = 7

const (
	ext4SuperMagic = 0xEF53
	xfsSuperMagic  = 0x58465342
	lockFilename   = ".restore-evidence.lock"
	tempPrefix     = ".restore-evidence-tmp-"
)

type platformStore struct {
	dirPath  string
	dir      *os.File
	lock     *os.File
	stat     syscall.Stat_t
	lockStat syscall.Stat_t
	mountID  uint64
}

func openPlatformStore(dir string) (*platformStore, error) {
	if !pathpkg.IsAbs(dir) || pathpkg.Clean(dir) != dir || strings.Contains(dir, "\\") {
		return nil, errors.New("evidence directory must be an absolute clean POSIX path")
	}
	fd, st, err := openDirectoryPath(dir)
	if err != nil {
		return nil, err
	}
	if err := secureDirectoryStat(st, true); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	mountID, err := mountIDForFD(fd)
	if err != nil || mountID == 0 {
		_ = syscall.Close(fd)
		return nil, errors.Join(ErrUnsupported, fmt.Errorf("read evidence directory mount ID: %w", err))
	}
	var fs syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &fs); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	fsType := uint64(fs.Type)
	if fsType != ext4SuperMagic && fsType != xfsSuperMagic {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("%w: filesystem type 0x%x is not ext4 or XFS", ErrUnsupported, fsType)
	}
	lockFD, err := syscall.Openat(fd, lockFilename, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	var lockStat syscall.Stat_t
	if err := syscall.Fstat(lockFD, &lockStat); err != nil {
		_ = syscall.Close(lockFD)
		_ = syscall.Close(fd)
		return nil, err
	}
	if _, err := secureBoundFileStat(lockFD, lockFilename, lockStat, 1, st, mountID); err != nil || lockStat.Size != 0 {
		_ = syscall.Close(lockFD)
		_ = syscall.Close(fd)
		return nil, errors.Join(err, errors.New("evidence writer lock must be empty"))
	}
	if err := syscall.Flock(lockFD, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = syscall.Close(lockFD)
		_ = syscall.Close(fd)
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, err
	}
	p := &platformStore{dirPath: dir, dir: os.NewFile(uintptr(fd), dir), lock: os.NewFile(uintptr(lockFD), lockFilename), stat: st, lockStat: lockStat, mountID: mountID}
	if err := p.rejectOrphanTemps(); err != nil {
		_ = p.close()
		return nil, err
	}
	if err := p.verifyBinding(); err != nil {
		_ = p.close()
		return nil, err
	}
	return p, nil
}

func (p *platformStore) durableWrites() bool { return true }

func (p *platformStore) close() error {
	if p == nil || p.dir == nil {
		return nil
	}
	var errs []error
	if p.lock != nil {
		errs = append(errs, syscall.Flock(int(p.lock.Fd()), syscall.LOCK_UN), p.lock.Close())
		p.lock = nil
	}
	errs = append(errs, p.dir.Close())
	p.dir = nil
	return errors.Join(errs...)
}

func (p *platformStore) publish(name string, data []byte, limit int, fault func(faultStage) error) (out publishOutcome, retErr error) {
	out.state = NotCommitted
	fail := func(err error) (publishOutcome, error) { return out, err }
	if len(data) == 0 || len(data) > limit {
		return fail(ErrTooLarge)
	}
	if err := safeLeaf(name); err != nil {
		return fail(err)
	}
	if err := p.verifyBinding(); err != nil {
		return fail(err)
	}
	if err := p.ensurePublishCapacity(name, limit); err != nil {
		return fail(err)
	}
	if err := fault(faultBeforeTempCreate); err != nil {
		return fail(err)
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return fail(err)
	}
	tmp := tempPrefix + hex.EncodeToString(random)
	dirfd := int(p.dir.Fd())
	fd, err := syscall.Openat(dirfd, tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fail(err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	closed := false
	defer func() {
		if !closed {
			if err := f.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close temporary: %w", err))
				out.poison = true
			}
		}
	}()
	var before syscall.Stat_t
	cleanupBeforeLink := func(original error) (publishOutcome, error) {
		if cleanupErr := p.cleanupTemp(tmp, before, 1, fault); cleanupErr != nil {
			out.poison = true
			return out, errors.Join(original, cleanupErr)
		}
		if err := f.Close(); err != nil {
			closed = true
			out.poison = true
			return out, errors.Join(original, fmt.Errorf("close temporary: %w", err))
		}
		closed = true
		return out, original
	}
	postLinkFailure := func(err error) (publishOutcome, error) {
		out.poison = true
		return out, err
	}
	if err := syscall.Fstat(fd, &before); err != nil {
		out.poison = true
		return fail(err)
	}
	tempMount, err := p.secureBoundFile(fd, tmp, before, 1)
	if err != nil {
		return cleanupBeforeLink(err)
	}
	out.meta = fileMeta{digest: sha256Hex(data), size: len(data), device: uint64(before.Dev), inode: before.Ino, mount: tempMount}
	if err := fault(faultAfterTempCreate); err != nil {
		return cleanupBeforeLink(err)
	}
	if err := fault(faultBeforeWrite); err != nil {
		return cleanupBeforeLink(err)
	}
	for written := 0; written < len(data); {
		n, err := f.Write(data[written:])
		if err != nil {
			return cleanupBeforeLink(err)
		}
		if n == 0 {
			return cleanupBeforeLink(io.ErrShortWrite)
		}
		written += n
	}
	if err := fault(faultAfterWrite); err != nil {
		return cleanupBeforeLink(err)
	}
	if err := fault(faultBeforeTempFileFsync); err != nil {
		return cleanupBeforeLink(err)
	}
	if err := f.Sync(); err != nil {
		return cleanupBeforeLink(err)
	}
	if err := fault(faultAfterTempFileFsync); err != nil {
		return cleanupBeforeLink(err)
	}
	if err := fault(faultBeforeTempDirectoryFsync); err != nil {
		return cleanupBeforeLink(err)
	}
	if err := syscall.Fsync(dirfd); err != nil {
		return cleanupBeforeLink(err)
	}
	if err := fault(faultAfterTempDirectoryFsync); err != nil {
		return cleanupBeforeLink(err)
	}
	if err := fault(faultBeforeLink); err != nil {
		return cleanupBeforeLink(err)
	}
	if err := p.verifyBinding(); err != nil {
		return cleanupBeforeLink(err)
	}
	if err := linkatNoReplace(dirfd, tmp, dirfd, name); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return cleanupBeforeLink(ErrAlreadyExists)
		}
		if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL) {
			return cleanupBeforeLink(errors.Join(ErrNoClobberMissing, err))
		}
		return cleanupBeforeLink(err)
	}
	out.state = Uncertain
	if err := fault(faultAfterLink); err != nil {
		return postLinkFailure(err)
	}
	if err := fault(faultBeforePublishedFileFsync); err != nil {
		return postLinkFailure(err)
	}
	publishedFD, err := syscall.Openat(dirfd, name, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return postLinkFailure(err)
	}
	var published syscall.Stat_t
	statErr := syscall.Fstat(publishedFD, &published)
	var publishedMount uint64
	if statErr == nil && (published.Dev != before.Dev || published.Ino != before.Ino) {
		statErr = errors.New("published path does not reference flushed temporary inode")
	}
	if statErr == nil {
		publishedMount, statErr = p.secureBoundFile(publishedFD, name, published, 2)
	}
	if statErr == nil && publishedMount != tempMount {
		statErr = errors.New("published path mount differs from temporary inode")
	}
	if statErr == nil {
		statErr = syscall.Fsync(publishedFD)
	}
	closeErr := syscall.Close(publishedFD)
	if statErr != nil {
		return postLinkFailure(statErr)
	}
	if closeErr != nil {
		return postLinkFailure(closeErr)
	}
	if err := fault(faultAfterPublishedFileFsync); err != nil {
		return postLinkFailure(err)
	}
	if err := fault(faultBeforeCommitDirectoryFsync); err != nil {
		return postLinkFailure(err)
	}
	if err := syscall.Fsync(dirfd); err != nil {
		return postLinkFailure(err)
	}
	out.state = Committed
	if err := fault(faultAfterCommitDirectoryFsync); err != nil {
		return postLinkFailure(err)
	}
	if err := p.cleanupTemp(tmp, before, 2, fault); err != nil {
		return postLinkFailure(err)
	}
	if err := f.Close(); err != nil {
		closed = true
		return postLinkFailure(err)
	}
	closed = true
	if err := fault(faultBeforeReadback); err != nil {
		return postLinkFailure(err)
	}
	meta, readback, err := p.read(name, limit)
	if err != nil {
		return postLinkFailure(err)
	}
	if meta.device != uint64(before.Dev) || meta.inode != before.Ino || meta.mount != tempMount || len(readback) != len(data) || meta.digest != sha256Hex(data) || !bytes.Equal(readback, data) {
		return postLinkFailure(errors.New("published evidence identity, mount, or digest changed during readback"))
	}
	if err := fault(faultAfterReadback); err != nil {
		return postLinkFailure(err)
	}
	out.meta = meta
	return out, nil
}

func (p *platformStore) cleanupTemp(tmp string, expected syscall.Stat_t, links uint64, fault func(faultStage) error) error {
	fd, err := syscall.Openat(int(p.dir.Fd()), tmp, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	var current syscall.Stat_t
	statErr := syscall.Fstat(fd, &current)
	if statErr == nil {
		_, statErr = p.secureBoundFile(fd, tmp, current, links)
	}
	closeErr := syscall.Close(fd)
	if statErr != nil {
		return statErr
	}
	if closeErr != nil {
		return closeErr
	}
	if current.Dev != expected.Dev || current.Ino != expected.Ino {
		return errors.Join(ErrUnsafeObject, errors.New("temporary evidence path was replaced"))
	}
	if err := fault(faultBeforeTempUnlink); err != nil {
		return err
	}
	if err := syscall.Unlinkat(int(p.dir.Fd()), tmp); err != nil {
		return err
	}
	if err := fault(faultAfterTempUnlink); err != nil {
		return err
	}
	if err := fault(faultBeforeCleanupDirectoryFsync); err != nil {
		return err
	}
	if err := syscall.Fsync(int(p.dir.Fd())); err != nil {
		return err
	}
	return fault(faultAfterCleanupDirectoryFsync)
}

func (p *platformStore) read(name string, limit int) (fileMeta, []byte, error) {
	if err := safeLeaf(name); err != nil {
		return fileMeta{}, nil, err
	}
	if err := p.verifyBinding(); err != nil {
		return fileMeta{}, nil, err
	}
	dirfd := int(p.dir.Fd())
	fd, err := syscall.Openat(dirfd, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fileMeta{}, nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fileMeta{}, nil, err
	}
	fileMount, err := p.secureBoundFile(fd, name, st, 1)
	if err != nil {
		return fileMeta{}, nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil {
		return fileMeta{}, nil, err
	}
	if len(b) > limit {
		return fileMeta{}, nil, ErrTooLarge
	}
	checkFD, err := syscall.Openat(dirfd, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fileMeta{}, nil, err
	}
	var check syscall.Stat_t
	statErr := syscall.Fstat(checkFD, &check)
	var checkMount uint64
	if statErr == nil {
		checkMount, statErr = p.secureBoundFile(checkFD, name, check, 1)
	}
	closeErr := syscall.Close(checkFD)
	if statErr != nil {
		return fileMeta{}, nil, statErr
	}
	if closeErr != nil {
		return fileMeta{}, nil, closeErr
	}
	if check.Dev != st.Dev || check.Ino != st.Ino {
		return fileMeta{}, nil, errors.Join(ErrUnsafeObject, errors.New("evidence path changed while reading"))
	}
	if checkMount != fileMount {
		return fileMeta{}, nil, errors.Join(ErrUnsafeObject, errors.New("evidence mount changed while reading"))
	}
	if err := p.verifyBinding(); err != nil {
		return fileMeta{}, nil, err
	}
	return fileMeta{digest: sha256Hex(b), size: len(b), device: uint64(st.Dev), inode: st.Ino, mount: fileMount}, b, nil
}

func (p *platformStore) verifyBinding() error {
	if p == nil || p.dir == nil {
		return ErrClosed
	}
	var current syscall.Stat_t
	if err := syscall.Fstat(int(p.dir.Fd()), &current); err != nil {
		return err
	}
	if current.Dev != p.stat.Dev || current.Ino != p.stat.Ino {
		return errors.Join(ErrUnsafeObject, errors.New("evidence directory fd identity changed"))
	}
	if err := secureDirectoryStat(current, true); err != nil {
		return err
	}
	currentMount, err := mountIDForFD(int(p.dir.Fd()))
	if err != nil || currentMount != p.mountID {
		return errors.Join(ErrUnsafeObject, errors.New("evidence directory mount binding changed"), err)
	}
	var fs syscall.Statfs_t
	if err := syscall.Fstatfs(int(p.dir.Fd()), &fs); err != nil {
		return err
	}
	if fsType := uint64(fs.Type); fsType != ext4SuperMagic && fsType != xfsSuperMagic {
		return fmt.Errorf("%w: evidence filesystem changed to type 0x%x", ErrUnsupported, fsType)
	}
	if p.lock == nil {
		return errors.Join(ErrUnsafeObject, errors.New("evidence writer lock is missing"))
	}
	var heldLock syscall.Stat_t
	if err := syscall.Fstat(int(p.lock.Fd()), &heldLock); err != nil {
		return err
	}
	if _, err := p.secureBoundFile(int(p.lock.Fd()), lockFilename, heldLock, 1); err != nil || heldLock.Size != 0 || heldLock.Dev != p.lockStat.Dev || heldLock.Ino != p.lockStat.Ino {
		return errors.Join(ErrUnsafeObject, errors.New("evidence writer lock fd changed"), err)
	}
	lockFD, err := syscall.Openat(int(p.dir.Fd()), lockFilename, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	var pathLock syscall.Stat_t
	lockStatErr := syscall.Fstat(lockFD, &pathLock)
	if lockStatErr == nil {
		_, lockStatErr = p.secureBoundFile(lockFD, lockFilename, pathLock, 1)
	}
	lockCloseErr := syscall.Close(lockFD)
	if lockStatErr != nil {
		return lockStatErr
	}
	if lockCloseErr != nil {
		return lockCloseErr
	}
	if pathLock.Dev != p.lockStat.Dev || pathLock.Ino != p.lockStat.Ino {
		return errors.Join(ErrUnsafeObject, errors.New("evidence writer lock was unlinked or replaced"))
	}
	fd, resolved, err := openDirectoryPath(p.dirPath)
	if err != nil {
		return err
	}
	resolvedMount, mountErr := mountIDForFD(fd)
	closeErr := syscall.Close(fd)
	if mountErr != nil {
		return mountErr
	}
	if closeErr != nil {
		return closeErr
	}
	if resolved.Dev != p.stat.Dev || resolved.Ino != p.stat.Ino || resolvedMount != p.mountID {
		return errors.Join(ErrUnsafeObject, errors.New("evidence directory path was replaced"))
	}
	return nil
}

func openDirectoryPath(dir string) (int, syscall.Stat_t, error) {
	root, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return -1, syscall.Stat_t{}, err
	}
	fd := root
	var rootStat syscall.Stat_t
	if err := syscall.Fstat(root, &rootStat); err != nil {
		_ = syscall.Close(root)
		return -1, syscall.Stat_t{}, err
	}
	if err := secureDirectoryStat(rootStat, false); err != nil {
		_ = syscall.Close(root)
		return -1, syscall.Stat_t{}, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		if component == "" {
			continue
		}
		next, openErr := syscall.Openat(fd, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if fd != root {
			_ = syscall.Close(fd)
		}
		if openErr != nil {
			_ = syscall.Close(root)
			return -1, syscall.Stat_t{}, openErr
		}
		var componentStat syscall.Stat_t
		if statErr := syscall.Fstat(next, &componentStat); statErr != nil {
			_ = syscall.Close(next)
			_ = syscall.Close(root)
			return -1, syscall.Stat_t{}, statErr
		}
		if statErr := secureDirectoryStat(componentStat, false); statErr != nil {
			_ = syscall.Close(next)
			_ = syscall.Close(root)
			return -1, syscall.Stat_t{}, statErr
		}
		fd = next
	}
	if fd != root {
		_ = syscall.Close(root)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return -1, syscall.Stat_t{}, err
	}
	return fd, st, nil
}

func secureDirectoryStat(st syscall.Stat_t, target bool) error {
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Uid != 0 || st.Gid != 0 || st.Mode&0o022 != 0 {
		return errors.Join(ErrUnsafeObject, errors.New("evidence path directories must be root-owned and not group/world writable"))
	}
	if target && st.Mode&0o777 != 0o700 {
		return errors.Join(ErrUnsafeObject, errors.New("evidence target directory must be root-owned mode 0700"))
	}
	return nil
}

func secureFileStat(name string, st syscall.Stat_t, links uint64) error {
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != 0 || st.Gid != 0 || st.Mode&0o777 != 0o600 || uint64(st.Nlink) != links {
		return errors.Join(ErrUnsafeObject, fmt.Errorf("%s must be a root-owned mode 0600 regular file with %d link(s)", name, links))
	}
	return nil
}

func (p *platformStore) secureBoundFile(fd int, name string, st syscall.Stat_t, links uint64) (uint64, error) {
	return secureBoundFileStat(fd, name, st, links, p.stat, p.mountID)
}

func secureBoundFileStat(fd int, name string, st syscall.Stat_t, links uint64, dirStat syscall.Stat_t, dirMount uint64) (uint64, error) {
	if err := secureFileStat(name, st, links); err != nil {
		return 0, err
	}
	if st.Dev != dirStat.Dev {
		return 0, errors.Join(ErrUnsafeObject, fmt.Errorf("%s device differs from evidence directory", name))
	}
	mount, err := mountIDForFD(fd)
	if err != nil {
		return 0, err
	}
	if mount != dirMount {
		return 0, errors.Join(ErrUnsafeObject, fmt.Errorf("%s mount differs from evidence directory", name))
	}
	return mount, nil
}

func safeLeaf(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return ErrUnsafeObject
	}
	return nil
}

func (p *platformStore) rejectOrphanTemps() error {
	names, err := p.boundedDirectoryNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		if strings.HasPrefix(name, tempPrefix) {
			return errors.Join(ErrUnsafeObject, fmt.Errorf("orphan evidence temporary %q requires operator inspection", name))
		}
	}
	return nil
}

func (p *platformStore) ensurePublishCapacity(target string, limit int) error {
	names, err := p.boundedDirectoryNames()
	if err != nil {
		return err
	}
	targetExists := false
	for _, name := range names {
		if strings.HasPrefix(name, tempPrefix) {
			return errors.Join(ErrUnsafeObject, fmt.Errorf("orphan evidence temporary %q requires operator inspection", name))
		}
		if name == target {
			targetExists = true
		}
	}
	// A new immutable object temporarily needs two directory entries: the
	// flushed temporary and its no-clobber hard link. An existing target needs
	// only the temporary entry because linkat must return EEXIST. The later
	// secure read decides whether that target is identical or a conflict.
	if len(names) <= maxDirectoryEntries-2 {
		return nil
	}
	if len(names) == maxDirectoryEntries-1 && targetExists {
		// Near the hard entry bound, a mere matching directory name is not
		// enough to spend the final slot. Validate the existing target through
		// the same root-owned, regular, single-link and mount-bound read path
		// used after EEXIST. Publication still executes the complete protocol.
		_, _, err := p.read(target, limit)
		if err != nil {
			return errors.Join(ErrUnsafeObject, err)
		}
		return nil
	}
	return ErrDirectoryLimit
}

func (p *platformStore) boundedDirectoryNames() ([]string, error) {
	fd, err := syscall.Openat(int(p.dir.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	d := os.NewFile(uintptr(fd), p.dirPath)
	defer d.Close()
	names, err := d.Readdirnames(maxDirectoryEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > maxDirectoryEntries {
		return nil, ErrDirectoryLimit
	}
	return names, nil
}

func mountIDForFD(fd int) (uint64, error) {
	f, err := os.Open(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, 4096))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "mnt_id:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:"))
		id, err := strconv.ParseUint(value, 10, 64)
		if err != nil || id == 0 {
			return 0, ErrUnsafeObject
		}
		return id, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("mount ID unavailable in fdinfo")
}

func linkatNoReplace(oldDir int, oldName string, newDir int, newName string) error {
	oldPtr, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPtr, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT, uintptr(oldDir), uintptr(unsafe.Pointer(oldPtr)), uintptr(newDir), uintptr(unsafe.Pointer(newPtr)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func platformClock() (clockSnapshot, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return clockSnapshot{}, err
	}
	if len(boot) > 128 {
		return clockSnapshot{}, ErrInvalidClock
	}
	var ts syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockBoottime, uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 {
		return clockSnapshot{}, errno
	}
	if ts.Sec < 0 || ts.Nsec < 0 || ts.Nsec >= 1_000_000_000 {
		return clockSnapshot{}, ErrInvalidClock
	}
	ns := uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
	return clockSnapshot{Wall: time.Now().UTC(), BootID: strings.TrimSpace(string(boot)), BoottimeNS: ns}, nil
}
