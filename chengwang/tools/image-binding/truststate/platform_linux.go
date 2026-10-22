//go:build linux

package truststate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type objectIdentity struct {
	Device uint64
	Inode  uint64
	Mount  uint64
}
type platformStore struct {
	path             string
	dir              *os.File
	identity         objectIdentity
	ancestors        []objectIdentity
	database         *os.File // Owned and closed by bbolt, not by platformStore.
	databaseIdentity objectIdentity
	markerIdentity   objectIdentity
	marker           []byte
	create           bool
	opened           bool
}

func openPlatform(path string, create bool, anchorHash, storeID string) (*platformStore, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, "\\\x00") {
		return nil, ErrInvalid
	}
	var dir *os.File
	var id objectIdentity
	var chain []objectIdentity
	var err error
	if create {
		dir, id, chain, err = createDirectory(path)
	} else {
		dir, id, chain, err = openDirectory(path, true)
	}
	if err != nil {
		return nil, ErrInvalid
	}
	p := &platformStore{path: path, dir: dir, identity: id, ancestors: chain, create: create}
	ok := false
	defer func() {
		if !ok {
			_ = p.close()
		}
	}()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(dir.Fd()), &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC && fs.Type != unix.XFS_SUPER_MAGIC {
		return nil, ErrUnsupported
	}
	p.marker, err = json.Marshal(struct {
		Schema       string `json:"schema"`
		StoreID      string `json:"storeID"`
		AnchorSHA256 string `json:"anchorSHA256"`
	}{markerSchema, storeID, anchorHash})
	if err != nil {
		return nil, ErrInvalid
	}
	if !create {
		if err = p.checkMarker(); err != nil {
			return nil, ErrInvalid
		}
	}
	ok = true
	return p, nil
}

// Keep the parent descriptor through mkdir, leaf open and full-path rebinding.
// A concurrent rename must not redirect Create into another empty directory.
func createDirectory(path string) (*os.File, objectIdentity, []objectIdentity, error) {
	parent, _, parentChain, err := openDirectory(filepath.Dir(path), false)
	if err != nil {
		return nil, objectIdentity{}, nil, ErrInvalid
	}
	defer parent.Close()
	if err = unix.Mkdirat(int(parent.Fd()), filepath.Base(path), 0700); err != nil {
		return nil, objectIdentity{}, nil, ErrInvalid
	}
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, objectIdentity{}, nil, ErrInvalid
	}
	leaf := os.NewFile(uintptr(fd), path)
	ok := false
	defer func() {
		if !ok {
			_ = leaf.Close()
		}
	}()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || secureDirectory(st, true) != nil {
		return nil, objectIdentity{}, nil, ErrInvalid
	}
	id, err := identity(fd, st)
	if err != nil {
		return nil, objectIdentity{}, nil, ErrInvalid
	}
	if err = parent.Sync(); err != nil {
		return nil, objectIdentity{}, nil, ErrInvalid
	}
	resolved, resolvedID, chain, err := openDirectory(path, true)
	if err != nil {
		return nil, objectIdentity{}, nil, ErrInvalid
	}
	closeErr := resolved.Close()
	if closeErr != nil || resolvedID != id || len(chain) != len(parentChain)+1 || !reflect.DeepEqual(chain[:len(parentChain)], parentChain) {
		return nil, objectIdentity{}, nil, ErrInvalid
	}
	ok = true
	return leaf, id, chain, nil
}

// bbolt normally adds O_CREATE and initializes zero-length databases. We ignore
// those flags and supply an already directory-bound descriptor. Reopen never
// creates a file and rejects empty/truncated files before bbolt can initialize.
func (p *platformStore) openDatabase(_ string, _ int, _ os.FileMode) (*os.File, error) {
	if p.opened || p.verifyDirectory() != nil {
		return nil, ErrInvalid
	}
	p.opened = true
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if p.create {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Openat(int(p.dir.Fd()), databaseName, flags, 0600)
	if err != nil {
		return nil, ErrInvalid
	}
	f := os.NewFile(uintptr(fd), filepath.Join(p.path, databaseName))
	id, st, err := secureFile(fd, p.identity)
	if err != nil || st.Size > maxDatabaseBytes || !p.create && st.Size < 16384 {
		_ = f.Close()
		return nil, ErrInvalid
	}
	p.database = f
	p.databaseIdentity = id
	if p.verifyDirectory() != nil {
		_ = f.Close()
		return nil, ErrInvalid
	}
	return f, nil
}

func (p *platformStore) finishCreate() error {
	if p.verifyDirectory() != nil {
		return ErrInvalid
	}
	fd, err := unix.Openat(int(p.dir.Fd()), markerName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrInvalid
	}
	f := os.NewFile(uintptr(fd), markerName)
	id, _, err := secureFile(fd, p.identity)
	if err == nil {
		var n int
		n, err = f.Write(p.marker)
		if err == nil && n != len(p.marker) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err == nil {
		err = p.dir.Sync()
	}
	if err != nil {
		return ErrInvalid
	}
	p.markerIdentity = id
	return p.verify()
}

func (p *platformStore) verifyDirectory() error {
	if p == nil || p.dir == nil {
		return ErrInvalid
	}
	var st unix.Stat_t
	if unix.Fstat(int(p.dir.Fd()), &st) != nil || secureDirectory(st, true) != nil {
		return ErrInvalid
	}
	id, err := identity(int(p.dir.Fd()), st)
	if err != nil || id != p.identity {
		return ErrInvalid
	}
	f, current, chain, err := openDirectory(p.path, true)
	if err != nil {
		return ErrInvalid
	}
	closeErr := f.Close()
	if closeErr != nil || current != p.identity || !reflect.DeepEqual(chain, p.ancestors) {
		return ErrInvalid
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(p.dir.Fd()), &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC && fs.Type != unix.XFS_SUPER_MAGIC {
		return ErrUnsupported
	}
	return nil
}
func (p *platformStore) verify() error {
	if p.verifyDirectory() != nil || p.database == nil {
		return ErrInvalid
	}
	held, st, err := secureFile(int(p.database.Fd()), p.identity)
	if err != nil || held != p.databaseIdentity || st.Size < 16384 || st.Size > maxDatabaseBytes {
		return ErrInvalid
	}
	fd, err := unix.Openat(int(p.dir.Fd()), databaseName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return ErrInvalid
	}
	current, _, err := secureFile(fd, p.identity)
	closeErr := unix.Close(fd)
	if err != nil || closeErr != nil || current != p.databaseIdentity {
		return ErrInvalid
	}
	return p.checkMarker()
}
func (p *platformStore) checkMarker() error {
	fd, err := unix.Openat(int(p.dir.Fd()), markerName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return ErrInvalid
	}
	f := os.NewFile(uintptr(fd), markerName)
	defer f.Close()
	id, st, err := secureFile(fd, p.identity)
	if err != nil || st.Size != int64(len(p.marker)) || p.markerIdentity != (objectIdentity{}) && id != p.markerIdentity {
		return ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || !bytes.Equal(raw, p.marker) {
		return ErrInvalid
	}
	check, err := unix.Openat(int(p.dir.Fd()), markerName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return ErrInvalid
	}
	other, _, err := secureFile(check, p.identity)
	closeErr := unix.Close(check)
	if err != nil || closeErr != nil || id != other {
		return ErrInvalid
	}
	p.markerIdentity = id
	return nil
}
func (p *platformStore) close() error {
	if p == nil || p.dir == nil {
		return nil
	}
	err := p.dir.Close()
	p.dir = nil
	return err
}

func openDirectory(path string, target bool) (*os.File, objectIdentity, []objectIdentity, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, objectIdentity{}, nil, err
	}
	chain := []objectIdentity{}
	var st unix.Stat_t
	check := func(final bool) error {
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		if err := secureDirectory(st, final); err != nil {
			return err
		}
		id, err := identity(fd, st)
		if err != nil {
			return err
		}
		chain = append(chain, id)
		return nil
	}
	if err = check(path == "/" && target); err != nil {
		_ = unix.Close(fd)
		return nil, objectIdentity{}, nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, objectIdentity{}, nil, err
		}
		fd = next
		if err = check(target && i == len(parts)-1); err != nil {
			_ = unix.Close(fd)
			return nil, objectIdentity{}, nil, err
		}
	}
	return os.NewFile(uintptr(fd), path), chain[len(chain)-1], chain, nil
}
func secureDirectory(st unix.Stat_t, target bool) error {
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 && st.Uid != uid {
		return ErrInvalid
	}
	if target {
		if st.Uid != uid || st.Gid != gid || st.Mode&07777 != 0700 {
			return ErrInvalid
		}
		return nil
	}
	if st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0) {
		return ErrInvalid
	}
	return nil
}
func secureFile(fd int, dir objectIdentity) (objectIdentity, unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return objectIdentity{}, st, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(os.Getegid()) || st.Mode&07777 != 0600 || st.Nlink != 1 {
		return objectIdentity{}, st, ErrInvalid
	}
	id, err := identity(fd, st)
	if err != nil || id.Device != dir.Device || id.Mount != dir.Mount {
		return objectIdentity{}, st, ErrInvalid
	}
	return id, st, nil
}
func identity(fd int, st unix.Stat_t) (objectIdentity, error) {
	// fdinfo's mount ID distinguishes bind-mounted objects with equal dev/inode.
	raw, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		return objectIdentity{}, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "mnt_id:") {
			v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:")), 10, 64)
			if err != nil || v == 0 {
				return objectIdentity{}, ErrInvalid
			}
			return objectIdentity{uint64(st.Dev), st.Ino, v}, nil
		}
	}
	return objectIdentity{}, ErrUnsupported
}
