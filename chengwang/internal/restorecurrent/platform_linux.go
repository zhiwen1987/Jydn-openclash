//go:build linux

package restorecurrent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"strconv"
	"strings"
	"syscall"

	"chengwang/internal/restorelease"
)

type heldDirectory struct {
	name  string
	file  *os.File
	stat  syscall.Stat_t
	mount uint64
	uid   uint32
	gid   uint32
	mode  uint32
}

type heldFile struct {
	name     string
	file     *os.File
	stat     syscall.Stat_t
	mount    uint64
	uid      uint32
	gid      uint32
	mode     uint32
	maxBytes int64
	digest   string
}

type platformSnapshot struct {
	rootPath string
	root     heldDirectory
	config   heldDirectory
	files    []*heldFile
}

type fileSpec struct {
	name     string
	uid      uint32
	gid      uint32
	mode     uint32
	maxBytes int64
}

var candidateFileSpecs = []fileSpec{
	{name: "probe.env", uid: 0, gid: 0, mode: 0o600, maxBytes: 32 << 10},
	{name: "catalog.json", uid: 0, gid: 10001, mode: 0o640, maxBytes: 256 << 10},
	{name: "dot-ca.pem", uid: 0, gid: 10001, mode: 0o640, maxBytes: 1 << 20},
	{name: "egress-policy.json", uid: 0, gid: 10001, mode: 0o640, maxBytes: 256 << 10},
}

func openPlatform(candidateRoot string, leaseIdentity restorelease.Identity) (*platformSnapshot, configurationContents, error) {
	root, err := openAbsoluteDirectory(candidateRoot, "candidate-root", 0, 0, 0, false)
	if err != nil {
		return nil, configurationContents{}, err
	}
	p := &platformSnapshot{rootPath: candidateRoot, root: root}
	fail := func(cause error) (*platformSnapshot, configurationContents, error) {
		return nil, configurationContents{}, errors.Join(cause, p.close())
	}
	if root.stat.Dev != leaseIdentity.CandidateDir.Device || root.stat.Ino != leaseIdentity.CandidateDir.Inode || root.mount != leaseIdentity.CandidateDir.MountID {
		return fail(errors.Join(ErrInvalid, errors.New("candidate root does not match the lifecycle lease identity")))
	}
	config, err := openChildDirectory(&p.root, "config", 0, 10001, 0o750)
	if err != nil {
		return fail(err)
	}
	p.config = config
	contentsByName := make(map[string][]byte, len(candidateFileSpecs))
	identities := map[[2]uint64]string{}
	for _, spec := range candidateFileSpecs {
		held, raw, err := openChildFile(&p.config, spec)
		if err != nil {
			return fail(err)
		}
		key := [2]uint64{uint64(held.stat.Dev), held.stat.Ino}
		if prior, duplicate := identities[key]; duplicate {
			_ = held.file.Close()
			return fail(errors.Join(ErrInvalid, fmt.Errorf("candidate files %s and %s alias one inode", prior, spec.name)))
		}
		identities[key] = spec.name
		p.files = append(p.files, held)
		contentsByName[spec.name] = raw
	}
	if err := p.verify(); err != nil {
		return fail(err)
	}
	return p, configurationContents{
		env: contentsByName["probe.env"], catalog: contentsByName["catalog.json"],
		ca: contentsByName["dot-ca.pem"], policy: contentsByName["egress-policy.json"],
	}, nil
}

func (p *platformSnapshot) verify() error {
	if p == nil || p.root.file == nil || p.config.file == nil || len(p.files) != len(candidateFileSpecs) {
		return ErrClosed
	}
	reopened, err := openAbsoluteDirectory(p.rootPath, "candidate-root", 0, 0, 0, false)
	if err != nil {
		return err
	}
	rootCompareErr := compareDirectory(&p.root, &reopened)
	closeErr := reopened.file.Close()
	if rootCompareErr != nil || closeErr != nil {
		return errors.Join(rootCompareErr, closeErr)
	}
	for _, pair := range []struct {
		parent *heldDirectory
		child  *heldDirectory
	}{{&p.root, &p.config}} {
		if err := verifyDirectory(pair.parent, pair.child); err != nil {
			return err
		}
	}
	for _, file := range p.files {
		if err := verifyFile(&p.config, file); err != nil {
			return err
		}
	}
	return nil
}

func (p *platformSnapshot) close() error {
	if p == nil {
		return nil
	}
	var result error
	for index := len(p.files) - 1; index >= 0; index-- {
		if p.files[index] != nil && p.files[index].file != nil {
			result = errors.Join(result, p.files[index].file.Close())
			p.files[index].file = nil
		}
	}
	p.files = nil
	for _, directory := range []*heldDirectory{&p.config, &p.root} {
		if directory.file != nil {
			result = errors.Join(result, directory.file.Close())
			directory.file = nil
		}
	}
	return result
}

func openAbsoluteDirectory(value, name string, uid, gid uint32, mode uint32, enforceExact bool) (heldDirectory, error) {
	if value == "" || !pathpkg.IsAbs(value) || pathpkg.Clean(value) != value || strings.ContainsAny(value, "\\\x00") {
		return heldDirectory{}, errors.Join(ErrInvalid, errors.New("candidate directory path is unsafe"))
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return heldDirectory{}, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			_ = syscall.Close(fd)
			return heldDirectory{}, errors.Join(ErrInvalid, errors.New("candidate directory component is unsafe"))
		}
		next, openErr := syscall.Openat(fd, component, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return heldDirectory{}, openErr
		}
		fd = next
	}
	held, err := directoryFromFD(fd, name, uid, gid, mode, enforceExact)
	if err != nil {
		_ = syscall.Close(fd)
		return heldDirectory{}, err
	}
	return held, nil
}

func openChildDirectory(parent *heldDirectory, name string, uid, gid uint32, mode uint32) (heldDirectory, error) {
	if parent == nil || parent.file == nil || strings.ContainsAny(name, "/\\\x00") || name == "" || name == "." || name == ".." {
		return heldDirectory{}, ErrInvalid
	}
	fd, err := syscall.Openat(int(parent.file.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return heldDirectory{}, err
	}
	held, err := directoryFromFD(fd, name, uid, gid, mode, true)
	if err != nil {
		_ = syscall.Close(fd)
		return heldDirectory{}, err
	}
	if held.stat.Dev != parent.stat.Dev || held.mount != parent.mount {
		_ = held.file.Close()
		return heldDirectory{}, errors.Join(ErrInvalid, fmt.Errorf("candidate directory %s crosses a device or mount boundary", name))
	}
	return held, nil
}

func directoryFromFD(fd int, name string, uid, gid uint32, mode uint32, enforceExact bool) (heldDirectory, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return heldDirectory{}, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || stat.Nlink == 0 {
		return heldDirectory{}, errors.Join(ErrInvalid, fmt.Errorf("candidate directory %s is not a linked directory", name))
	}
	if enforceExact && (stat.Uid != uid || stat.Gid != gid || stat.Mode&0o7777 != mode) {
		return heldDirectory{}, errors.Join(ErrInvalid, fmt.Errorf("candidate directory %s ownership or mode is invalid", name))
	}
	mount, err := mountIDForFD(fd)
	if err != nil {
		return heldDirectory{}, err
	}
	return heldDirectory{name: name, file: os.NewFile(uintptr(fd), name), stat: stat, mount: mount, uid: uid, gid: gid, mode: mode}, nil
}

func openChildFile(parent *heldDirectory, spec fileSpec) (*heldFile, []byte, error) {
	fd, err := syscall.Openat(int(parent.file.Fd()), spec.name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), spec.name)
	fail := func(cause error) (*heldFile, []byte, error) {
		return nil, nil, errors.Join(cause, file.Close())
	}
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil {
		return fail(err)
	}
	if before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Uid != spec.uid || before.Gid != spec.gid || before.Mode&0o7777 != spec.mode || before.Nlink != 1 || before.Size <= 0 || before.Size > spec.maxBytes {
		return fail(errors.Join(ErrInvalid, fmt.Errorf("candidate file %s metadata is invalid", spec.name)))
	}
	mount, err := mountIDForFD(fd)
	if err != nil {
		return fail(err)
	}
	if before.Dev != parent.stat.Dev || mount != parent.mount {
		return fail(errors.Join(ErrInvalid, fmt.Errorf("candidate file %s crosses a device or mount boundary", spec.name)))
	}
	raw, err := readHeldFile(file, spec.maxBytes)
	if err != nil {
		return fail(err)
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(fd, &after); err != nil {
		return fail(err)
	}
	if !sameFileStat(before, after) {
		return fail(errors.Join(ErrInvalid, fmt.Errorf("candidate file %s changed while being read", spec.name)))
	}
	held := &heldFile{name: spec.name, file: file, stat: after, mount: mount, uid: spec.uid, gid: spec.gid, mode: spec.mode, maxBytes: spec.maxBytes, digest: digest(raw)}
	if err := verifyFile(parent, held); err != nil {
		return fail(err)
	}
	return held, raw, nil
}

func verifyDirectory(parent, held *heldDirectory) error {
	if parent == nil || parent.file == nil || held == nil || held.file == nil {
		return ErrClosed
	}
	var current syscall.Stat_t
	if err := syscall.Fstat(int(held.file.Fd()), &current); err != nil {
		return err
	}
	mount, err := mountIDForFD(int(held.file.Fd()))
	if err != nil || !sameDirectoryStat(held.stat, current) || mount != held.mount {
		return errors.Join(ErrInvalid, fmt.Errorf("held candidate directory %s changed", held.name), err)
	}
	reopened, err := openChildDirectory(parent, held.name, held.uid, held.gid, held.mode)
	if err != nil {
		return err
	}
	compareErr := compareDirectory(held, &reopened)
	closeErr := reopened.file.Close()
	return errors.Join(compareErr, closeErr)
}

func compareDirectory(left, right *heldDirectory) error {
	if left == nil || right == nil || !sameDirectoryStat(left.stat, right.stat) || left.mount != right.mount {
		return errors.Join(ErrInvalid, errors.New("candidate directory path was replaced"))
	}
	return nil
}

func verifyFile(parent *heldDirectory, held *heldFile) error {
	if parent == nil || parent.file == nil || held == nil || held.file == nil {
		return ErrClosed
	}
	var current syscall.Stat_t
	if err := syscall.Fstat(int(held.file.Fd()), &current); err != nil {
		return err
	}
	mount, err := mountIDForFD(int(held.file.Fd()))
	if err != nil || !sameFileStat(held.stat, current) || mount != held.mount {
		return errors.Join(ErrInvalid, fmt.Errorf("held candidate file %s changed", held.name), err)
	}
	raw, err := readHeldFile(held.file, held.maxBytes)
	if err != nil {
		return err
	}
	if digest(raw) != held.digest {
		return errors.Join(ErrInvalid, fmt.Errorf("held candidate file %s content changed", held.name))
	}
	fd, err := syscall.Openat(int(parent.file.Fd()), held.name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	var pathStat syscall.Stat_t
	statErr := syscall.Fstat(fd, &pathStat)
	pathMount := uint64(0)
	if statErr == nil {
		pathMount, statErr = mountIDForFD(fd)
	}
	closeErr := syscall.Close(fd)
	if statErr != nil || closeErr != nil {
		return errors.Join(statErr, closeErr)
	}
	if pathStat.Dev != held.stat.Dev || pathStat.Ino != held.stat.Ino || pathMount != held.mount {
		return errors.Join(ErrInvalid, fmt.Errorf("candidate file path %s was replaced", held.name))
	}
	return nil
}

func readHeldFile(file *os.File, limit int64) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, ErrInvalid
	}
	return raw, nil
}

func sameDirectoryStat(left, right syscall.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && right.Nlink != 0 && left.Mode == right.Mode && left.Uid == right.Uid && left.Gid == right.Gid
}

func sameFileStat(left, right syscall.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && right.Nlink == 1 && left.Mode == right.Mode && left.Uid == right.Uid && left.Gid == right.Gid && left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func mountIDForFD(fd int) (uint64, error) {
	file, err := os.Open("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 16<<10))
	for scanner.Scan() {
		line := scanner.Bytes()
		if !bytes.HasPrefix(line, []byte("mnt_id:")) {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(string(line), "mnt_id:"))
		mount, err := strconv.ParseUint(value, 10, 64)
		if err != nil || mount == 0 {
			return 0, errors.New("candidate object mount identity is invalid")
		}
		return mount, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("candidate object mount identity is unavailable")
}
