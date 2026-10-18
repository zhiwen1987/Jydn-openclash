//go:build linux

package restorelease

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const (
	globalDirectory      = "/run"
	globalLockName       = "chengwang-m2b-probe-lifecycle.lock"
	candidateLockName    = ".probe-lifecycle.lock"
	candidateMarkerName  = ".chengwang-m2b-candidate-root"
	candidateMarkerValue = "chengwang-m2b-candidate-root/v1\n"
	ext4SuperMagic       = 0xEF53
	xfsSuperMagic        = 0x58465342
	tmpfsSuperMagic      = 0x01021994
)

var instancePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,19}$`)

type heldObject struct {
	path    string
	parent  *os.File
	file    *os.File
	parentS syscall.Stat_t
	fileS   syscall.Stat_t
	parentM uint64
	fileM   uint64
}

type platformLease struct {
	global        heldObject
	trustedParent directoryObject
	base          directoryObject
	candidate     heldObject
	marker        heldMarker
}

type heldMarker struct {
	file  *os.File
	stat  syscall.Stat_t
	mount uint64
}

type directoryObject struct {
	path  string
	file  *os.File
	stat  syscall.Stat_t
	mount uint64
}

type acquireOptions struct {
	globalDir     string
	candidateBase string
	testOnly      bool
}

func acquirePlatform(candidateRoot string) (*platformLease, Identity, error) {
	base, err := productionBase(candidateRoot)
	if err != nil {
		return nil, Identity{}, err
	}
	return acquireWithOptions(candidateRoot, acquireOptions{globalDir: globalDirectory, candidateBase: base})
}

func productionBase(candidateRoot string) (string, error) {
	if candidateRoot == "" || !pathpkg.IsAbs(candidateRoot) || pathpkg.Clean(candidateRoot) != candidateRoot || strings.ContainsAny(candidateRoot, "\\\x00") || strings.HasSuffix(candidateRoot, "/") {
		return "", errors.Join(ErrUnsafePath, errors.New("candidate root must be a clean absolute POSIX path"))
	}
	for _, base := range []string{"/var/lib/chengwang-m2b-candidate", "/srv/chengwang-m2b-candidate"} {
		prefix := base + "/"
		if !strings.HasPrefix(candidateRoot, prefix) {
			continue
		}
		instance := strings.TrimPrefix(candidateRoot, prefix)
		if !instancePattern.MatchString(instance) {
			return "", errors.Join(ErrUnsafePath, errors.New("candidate instance is invalid"))
		}
		return base, nil
	}
	return "", errors.Join(ErrUnsafePath, errors.New("candidate root is outside the production allowlist"))
}

func acquireWithOptions(candidateRoot string, options acquireOptions) (*platformLease, Identity, error) {
	if os.Geteuid() != 0 {
		return nil, Identity{}, errors.Join(ErrUnsafePath, errors.New("lifecycle lease requires root"))
	}
	if !options.testOnly {
		base, err := productionBase(candidateRoot)
		if err != nil {
			return nil, Identity{}, err
		}
		if base != options.candidateBase || options.globalDir != globalDirectory {
			return nil, Identity{}, errors.Join(ErrUnsafePath, errors.New("production lock paths are fixed"))
		}
	}
	if err := cleanAbsolute(options.globalDir); err != nil {
		return nil, Identity{}, err
	}
	if err := cleanAbsolute(options.candidateBase); err != nil {
		return nil, Identity{}, err
	}
	if err := cleanAbsolute(candidateRoot); err != nil {
		return nil, Identity{}, err
	}
	if pathpkg.Dir(candidateRoot) != options.candidateBase || !instancePattern.MatchString(pathpkg.Base(candidateRoot)) {
		return nil, Identity{}, errors.Join(ErrCandidateMismatch, errors.New("candidate must be one direct instance below the allowed base"))
	}

	global, err := acquireHeld(options.globalDir, globalLockName, true)
	if err != nil {
		return nil, Identity{}, err
	}
	failGlobal := func(err error) (*platformLease, Identity, error) {
		_ = releaseHeld(&global)
		return nil, Identity{}, err
	}

	trustedParentPath := pathpkg.Dir(options.candidateBase)
	parentFD, parentStat, parentMount, err := openSecureDirectory(trustedParentPath, false)
	if err != nil {
		return failGlobal(err)
	}
	if err := requireFilesystem(parentFD, false); err != nil {
		_ = syscall.Close(parentFD)
		return failGlobal(err)
	}
	trustedParent := directoryObject{path: trustedParentPath, file: os.NewFile(uintptr(parentFD), trustedParentPath), stat: parentStat, mount: parentMount}
	failParent := func(err error) (*platformLease, Identity, error) {
		_ = releaseDirectory(&trustedParent)
		return failGlobal(err)
	}

	baseFD, baseStat, baseMount, err := openSecureDirectory(options.candidateBase, false)
	if err != nil {
		return failParent(err)
	}
	if err := requireFilesystem(baseFD, false); err != nil {
		_ = syscall.Close(baseFD)
		return failParent(err)
	}
	if parentStat.Dev != baseStat.Dev || parentMount != baseMount {
		_ = syscall.Close(baseFD)
		return failParent(errors.Join(ErrUnsafePath, errors.New("candidate base is an independent or bind mount")))
	}
	base := directoryObject{path: options.candidateBase, file: os.NewFile(uintptr(baseFD), options.candidateBase), stat: baseStat, mount: baseMount}
	failBase := func(err error) (*platformLease, Identity, error) {
		_ = releaseDirectory(&base)
		return failParent(err)
	}

	candidateFD, candidateStat, candidateMount, err := openSecureDirectory(candidateRoot, true)
	if err != nil {
		return failBase(err)
	}
	if candidateStat.Dev != baseStat.Dev || candidateMount != baseMount {
		_ = syscall.Close(candidateFD)
		return failBase(errors.Join(ErrUnsafePath, errors.New("candidate root is an independent or bind mount")))
	}
	if err := requireFilesystem(candidateFD, false); err != nil {
		_ = syscall.Close(candidateFD)
		return failBase(err)
	}
	candidate, err := acquireHeldOpen(candidateRoot, candidateLockName, false, candidateFD, candidateStat, candidateMount)
	if err != nil {
		return failBase(err)
	}
	marker, err := openMarker(int(candidate.parent.Fd()), candidate.parentS, candidate.parentM)
	if err != nil {
		_ = releaseHeld(&candidate)
		return failBase(err)
	}
	p := &platformLease{global: global, trustedParent: trustedParent, base: base, candidate: candidate, marker: marker}
	if err := p.verify(); err != nil {
		_ = p.close()
		return nil, Identity{}, err
	}
	identity := Identity{
		CandidateRoot: candidateRoot,
		GlobalDir:     objectIdentity(global.parentS, global.parentM),
		GlobalLock:    objectIdentity(global.fileS, global.fileM),
		CandidateDir:  objectIdentity(candidate.parentS, candidate.parentM),
		CandidateLock: objectIdentity(candidate.fileS, candidate.fileM),
	}
	return p, identity, nil
}

func cleanAbsolute(value string) error {
	if value == "" || !pathpkg.IsAbs(value) || pathpkg.Clean(value) != value || strings.ContainsAny(value, "\\\x00") || (value != "/" && strings.HasSuffix(value, "/")) {
		return errors.Join(ErrUnsafePath, fmt.Errorf("unsafe absolute path %q", value))
	}
	return nil
}

func acquireHeld(directory, name string, allowTmpfs bool) (heldObject, error) {
	fd, st, mount, err := openSecureDirectory(directory, true)
	if err != nil {
		return heldObject{}, err
	}
	if err := requireFilesystem(fd, allowTmpfs); err != nil {
		_ = syscall.Close(fd)
		return heldObject{}, err
	}
	return acquireHeldOpen(directory, name, allowTmpfs, fd, st, mount)
}

// acquireHeldOpen consumes fd on every return path. Keeping the already
// validated directory descriptor closes the preflight-to-flock rebind window.
func acquireHeldOpen(directory, name string, allowTmpfs bool, fd int, st syscall.Stat_t, mount uint64) (heldObject, error) {
	created := false
	lockFD, err := syscall.Openat(fd, name, syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err == nil {
		created = true
	}
	if errors.Is(err, syscall.EEXIST) {
		lockFD, err = syscall.Openat(fd, name, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	}
	if err != nil {
		_ = syscall.Close(fd)
		return heldObject{}, err
	}
	cleanup := func() {
		_ = syscall.Close(lockFD)
		_ = syscall.Close(fd)
	}
	if created {
		if err := syscall.Fchmod(lockFD, 0o600); err != nil {
			cleanup()
			return heldObject{}, err
		}
	}
	var lockStat syscall.Stat_t
	if err := syscall.Fstat(lockFD, &lockStat); err != nil {
		cleanup()
		return heldObject{}, err
	}
	lockMount, err := verifyLockObject(lockFD, name, lockStat, st, mount)
	if err != nil {
		cleanup()
		return heldObject{}, err
	}
	if err := syscall.Flock(lockFD, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		cleanup()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return heldObject{}, ErrBusy
		}
		return heldObject{}, err
	}
	h := heldObject{path: directory, parent: os.NewFile(uintptr(fd), directory), file: os.NewFile(uintptr(lockFD), name), parentS: st, fileS: lockStat, parentM: mount, fileM: lockMount}
	if err := verifyHeld(&h, allowTmpfs); err != nil {
		_ = releaseHeld(&h)
		return heldObject{}, err
	}
	return h, nil
}

func (p *platformLease) verify() error {
	if p == nil {
		return ErrClosed
	}
	if err := verifyHeld(&p.global, true); err != nil {
		return err
	}
	if err := verifyDirectory(&p.trustedParent, false); err != nil {
		return err
	}
	if err := verifyDirectory(&p.base, false); err != nil {
		return err
	}
	if p.base.stat.Dev != p.trustedParent.stat.Dev || p.base.mount != p.trustedParent.mount {
		return errors.Join(ErrUnsafePath, errors.New("candidate base no longer shares the trusted parent mount"))
	}
	if err := verifyHeld(&p.candidate, false); err != nil {
		return err
	}
	if p.candidate.parentS.Dev != p.base.stat.Dev || p.candidate.parentM != p.base.mount {
		return errors.Join(ErrUnsafePath, errors.New("candidate root no longer shares the allowed base mount"))
	}
	return verifyMarkerHeld(&p.marker, int(p.candidate.parent.Fd()), p.candidate.parentS, p.candidate.parentM)
}

func verifyHeld(h *heldObject, allowTmpfs bool) error {
	if h == nil || h.parent == nil || h.file == nil {
		return ErrClosed
	}
	pfd, lfd := int(h.parent.Fd()), int(h.file.Fd())
	var parentNow, fileNow syscall.Stat_t
	if err := syscall.Fstat(pfd, &parentNow); err != nil {
		return err
	}
	if err := secureDirectoryStat(parentNow, true); err != nil || parentNow.Dev != h.parentS.Dev || parentNow.Ino != h.parentS.Ino {
		return errors.Join(ErrUnsafePath, errors.New("held directory identity changed"), err)
	}
	parentMount, err := mountIDForFD(pfd)
	if err != nil || parentMount != h.parentM {
		return errors.Join(ErrUnsafePath, errors.New("held directory mount changed"), err)
	}
	if err := requireFilesystem(pfd, allowTmpfs); err != nil {
		return err
	}
	if err := syscall.Fstat(lfd, &fileNow); err != nil {
		return err
	}
	fileMount, err := verifyLockObject(lfd, pathpkg.Base(h.file.Name()), fileNow, parentNow, parentMount)
	if err != nil || fileNow.Dev != h.fileS.Dev || fileNow.Ino != h.fileS.Ino || fileMount != h.fileM {
		return errors.Join(ErrUnsafePath, errors.New("held lock identity changed"), err)
	}

	pathLock, err := syscall.Openat(pfd, pathpkg.Base(h.file.Name()), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	var pathLockStat syscall.Stat_t
	statErr := syscall.Fstat(pathLock, &pathLockStat)
	pathLockMount := uint64(0)
	if statErr == nil {
		pathLockMount, statErr = verifyLockObject(pathLock, pathpkg.Base(h.file.Name()), pathLockStat, parentNow, parentMount)
	}
	closeErr := syscall.Close(pathLock)
	if statErr != nil || closeErr != nil {
		return errors.Join(statErr, closeErr)
	}
	if pathLockStat.Dev != h.fileS.Dev || pathLockStat.Ino != h.fileS.Ino || pathLockMount != h.fileM {
		return errors.Join(ErrUnsafePath, errors.New("lock path was unlinked or replaced"))
	}

	pathFD, pathStat, pathMount, err := openSecureDirectory(h.path, true)
	if err != nil {
		return err
	}
	closeErr = syscall.Close(pathFD)
	if closeErr != nil {
		return closeErr
	}
	if pathStat.Dev != h.parentS.Dev || pathStat.Ino != h.parentS.Ino || pathMount != h.parentM {
		return errors.Join(ErrUnsafePath, errors.New("directory path was replaced"))
	}
	return nil
}

func (p *platformLease) close() error {
	if p == nil {
		return nil
	}
	return errors.Join(releaseMarker(&p.marker), releaseHeld(&p.candidate), releaseDirectory(&p.base), releaseDirectory(&p.trustedParent), releaseHeld(&p.global))
}

func verifyDirectory(directory *directoryObject, target bool) error {
	if directory == nil || directory.file == nil {
		return ErrClosed
	}
	fd := int(directory.file.Fd())
	var current syscall.Stat_t
	if err := syscall.Fstat(fd, &current); err != nil {
		return err
	}
	if err := secureDirectoryStat(current, target); err != nil || current.Dev != directory.stat.Dev || current.Ino != directory.stat.Ino {
		return errors.Join(ErrUnsafePath, errors.New("held base directory identity changed"), err)
	}
	mount, err := mountIDForFD(fd)
	if err != nil || mount != directory.mount {
		return errors.Join(ErrUnsafePath, errors.New("held base directory mount changed"), err)
	}
	if err := requireFilesystem(fd, false); err != nil {
		return err
	}
	pathFD, pathStat, pathMount, err := openSecureDirectory(directory.path, target)
	if err != nil {
		return err
	}
	closeErr := syscall.Close(pathFD)
	if closeErr != nil {
		return closeErr
	}
	if pathStat.Dev != directory.stat.Dev || pathStat.Ino != directory.stat.Ino || pathMount != directory.mount {
		return errors.Join(ErrUnsafePath, errors.New("base directory path was replaced"))
	}
	return nil
}

func releaseDirectory(directory *directoryObject) error {
	if directory == nil || directory.file == nil {
		return nil
	}
	err := directory.file.Close()
	directory.file = nil
	return err
}

func releaseHeld(h *heldObject) error {
	if h == nil {
		return nil
	}
	var errs []error
	if h.file != nil {
		errs = append(errs, syscall.Flock(int(h.file.Fd()), syscall.LOCK_UN), h.file.Close())
		h.file = nil
	}
	if h.parent != nil {
		errs = append(errs, h.parent.Close())
		h.parent = nil
	}
	return errors.Join(errs...)
}

func openSecureDirectory(directory string, target bool) (int, syscall.Stat_t, uint64, error) {
	if err := cleanAbsolute(directory); err != nil {
		return -1, syscall.Stat_t{}, 0, err
	}
	root, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return -1, syscall.Stat_t{}, 0, err
	}
	fd := root
	for _, component := range strings.Split(strings.TrimPrefix(directory, "/"), "/") {
		if component == "" {
			continue
		}
		next, openErr := syscall.Openat(fd, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if fd != root {
			_ = syscall.Close(fd)
		}
		if openErr != nil {
			_ = syscall.Close(root)
			return -1, syscall.Stat_t{}, 0, openErr
		}
		var componentStat syscall.Stat_t
		if statErr := syscall.Fstat(next, &componentStat); statErr != nil {
			_ = syscall.Close(next)
			_ = syscall.Close(root)
			return -1, syscall.Stat_t{}, 0, statErr
		}
		if statErr := secureDirectoryStat(componentStat, false); statErr != nil {
			_ = syscall.Close(next)
			_ = syscall.Close(root)
			return -1, syscall.Stat_t{}, 0, statErr
		}
		fd = next
	}
	if fd != root {
		_ = syscall.Close(root)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return -1, syscall.Stat_t{}, 0, err
	}
	if err := secureDirectoryStat(st, target); err != nil {
		_ = syscall.Close(fd)
		return -1, syscall.Stat_t{}, 0, err
	}
	mount, err := mountIDForFD(fd)
	if err != nil || mount == 0 {
		_ = syscall.Close(fd)
		return -1, syscall.Stat_t{}, 0, errors.Join(ErrUnsupported, errors.New("directory mount ID is unavailable"), err)
	}
	return fd, st, mount, nil
}

func secureDirectoryStat(st syscall.Stat_t, target bool) error {
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Uid != 0 || st.Gid != 0 || st.Mode&0o022 != 0 {
		return errors.Join(ErrUnsafePath, errors.New("directories must be root-owned and not group/world writable"))
	}
	if target && st.Mode&0o7777 != 0o700 && st.Mode&0o7777 != 0o755 {
		return errors.Join(ErrUnsafePath, errors.New("lock directory must be mode 0700 or 0755"))
	}
	return nil
}

func requireFilesystem(fd int, allowTmpfs bool) error {
	var fs syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &fs); err != nil {
		return err
	}
	kind := uint64(fs.Type)
	if kind == ext4SuperMagic || kind == xfsSuperMagic || (allowTmpfs && kind == tmpfsSuperMagic) {
		return nil
	}
	return errors.Join(ErrUnsupported, fmt.Errorf("filesystem type 0x%x is not approved", kind))
}

func openMarker(candidateFD int, candidateStat syscall.Stat_t, candidateMount uint64) (heldMarker, error) {
	fd, err := syscall.Openat(candidateFD, candidateMarkerName, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return heldMarker{}, errors.Join(ErrUnsafePath, err)
	}
	f := os.NewFile(uintptr(fd), candidateMarkerName)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = f.Close()
		return heldMarker{}, err
	}
	if err := validateMarkerObject(f, st, candidateStat, candidateMount); err != nil {
		_ = f.Close()
		return heldMarker{}, err
	}
	mount, err := mountIDForFD(fd)
	if err != nil {
		_ = f.Close()
		return heldMarker{}, err
	}
	return heldMarker{file: f, stat: st, mount: mount}, nil
}

func verifyMarkerHeld(marker *heldMarker, candidateFD int, candidateStat syscall.Stat_t, candidateMount uint64) error {
	if marker == nil || marker.file == nil {
		return ErrClosed
	}
	var heldNow syscall.Stat_t
	if err := syscall.Fstat(int(marker.file.Fd()), &heldNow); err != nil {
		return err
	}
	if heldNow.Dev != marker.stat.Dev || heldNow.Ino != marker.stat.Ino {
		return errors.Join(ErrUnsafePath, errors.New("held candidate marker identity changed"))
	}
	if err := validateMarkerObject(marker.file, heldNow, candidateStat, candidateMount); err != nil {
		return err
	}

	pathMarker, err := openMarker(candidateFD, candidateStat, candidateMount)
	if err != nil {
		return err
	}
	defer releaseMarker(&pathMarker)
	if pathMarker.stat.Dev != marker.stat.Dev || pathMarker.stat.Ino != marker.stat.Ino || pathMarker.mount != marker.mount {
		return errors.Join(ErrUnsafePath, errors.New("candidate marker path was unlinked or replaced"))
	}
	return nil
}

func validateMarkerObject(file *os.File, st syscall.Stat_t, candidateStat syscall.Stat_t, candidateMount uint64) error {
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != 0 || st.Gid != 0 || st.Mode&0o7777 != 0o600 || st.Nlink != 1 || st.Size != int64(len(candidateMarkerValue)) || st.Dev != candidateStat.Dev {
		return errors.Join(ErrUnsafePath, errors.New("candidate marker metadata is invalid"))
	}
	mount, err := mountIDForFD(int(file.Fd()))
	if err != nil || mount != candidateMount {
		return errors.Join(ErrUnsafePath, errors.New("candidate marker mount differs from candidate root"), err)
	}
	raw := make([]byte, len(candidateMarkerValue))
	n, err := file.ReadAt(raw, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if n != len(raw) || !bytes.Equal(raw, []byte(candidateMarkerValue)) {
		return errors.Join(ErrUnsafePath, errors.New("candidate marker content is invalid"))
	}
	return nil
}

func releaseMarker(marker *heldMarker) error {
	if marker == nil || marker.file == nil {
		return nil
	}
	err := marker.file.Close()
	marker.file = nil
	return err
}

func verifyLockObject(fd int, name string, st syscall.Stat_t, parent syscall.Stat_t, parentMount uint64) (uint64, error) {
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != 0 || st.Gid != 0 || st.Mode&0o7777 != 0o600 || st.Nlink != 1 || st.Size != 0 || st.Dev != parent.Dev {
		return 0, errors.Join(ErrUnsafePath, fmt.Errorf("%s must be an empty root-owned mode 0600 single-link regular file", name))
	}
	mount, err := mountIDForFD(fd)
	if err != nil || mount != parentMount {
		return 0, errors.Join(ErrUnsafePath, fmt.Errorf("%s mount differs from parent", name), err)
	}
	return mount, nil
}

func objectIdentity(st syscall.Stat_t, mount uint64) ObjectIdentity {
	return ObjectIdentity{Device: uint64(st.Dev), Inode: st.Ino, MountID: mount}
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
		id, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:")), 10, 64)
		if err != nil || id == 0 {
			return 0, ErrUnsafePath
		}
		return id, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("mount ID unavailable in fdinfo")
}
