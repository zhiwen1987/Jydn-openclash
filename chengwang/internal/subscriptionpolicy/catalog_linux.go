//go:build linux

package subscriptionpolicy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const directoryFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
const regularFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC

type fileIdentity struct {
	device, inode, links                                   uint64
	mode, uid, gid                                         uint32
	size, mtimeSeconds, mtimeNano, ctimeSeconds, ctimeNano int64
}

func observeFile(file *os.File) (fileIdentity, error) {
	var value syscall.Stat_t
	if syscall.Fstat(int(file.Fd()), &value) != nil {
		return fileIdentity{}, ErrUnavailable
	}
	return fileIdentity{device: uint64(value.Dev), inode: value.Ino, links: uint64(value.Nlink), mode: value.Mode, uid: value.Uid, gid: value.Gid,
		size: value.Size, mtimeSeconds: int64(value.Mtim.Sec), mtimeNano: int64(value.Mtim.Nsec), ctimeSeconds: int64(value.Ctim.Sec), ctimeNano: int64(value.Ctim.Nsec)}, nil
}

func supportedFilesystem(kind int64, ancestor bool) bool {
	return kind == 0xef53 || kind == 0x58465342 || kind == 0x01021994 || ancestor && kind == 0x794c7630
}

func checkFilesystem(file *os.File, ancestor bool) error {
	var info syscall.Statfs_t
	if syscall.Fstatfs(int(file.Fd()), &info) != nil {
		return ErrUnavailable
	}
	if !supportedFilesystem(int64(info.Type), ancestor) {
		return ErrUnsupported
	}
	return nil
}

func osFailure(ctx context.Context, err error) error {
	if canceled := contextError(ctx); canceled != nil {
		return canceled
	}
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
		return ErrUnsafe
	}
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EAGAIN) {
		return ErrChanged
	}
	return ErrUnavailable
}

func sameDirectory(before, after fileIdentity, leaf bool) bool {
	if leaf {
		return before == after
	}
	return before.device == after.device && before.inode == after.inode && before.mode == after.mode && before.uid == after.uid && before.gid == after.gid
}

func checkDirectory(info fileIdentity, owner Owner, leaf bool) error {
	if info.mode&syscall.S_IFMT != syscall.S_IFDIR {
		return ErrUnsafe
	}
	mode := info.mode & 0o7777
	if leaf {
		if info.uid != owner.UID || info.gid != owner.GID || mode != 0o700 {
			return ErrUnsafe
		}
	} else if !(info.uid == 0 && mode == 0o1777) {
		if info.uid != 0 && info.uid != owner.UID || mode&0o7022 != 0 {
			return ErrUnsafe
		}
	}
	return nil
}

func checkRegular(info fileIdentity, owner Owner, device uint64) error {
	if info.mode&syscall.S_IFMT != syscall.S_IFREG || info.links != 1 || info.uid != owner.UID || info.gid != owner.GID ||
		info.mode&0o7777 != 0o600 || info.device != device {
		return ErrUnsafe
	}
	if info.size <= 0 || info.size > MaxCatalogBytes {
		return ErrInvalid
	}
	return nil
}

type heldDirectory struct {
	file   *os.File
	name   string
	before fileIdentity
}

func pathParts(path string) ([]string, error) {
	if path == "" || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.TrimSpace(path) != path || strings.ContainsAny(path, "\x00\\") {
		return nil, ErrInvalid
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 2 || len(parts) > 64 {
		return nil, ErrInvalid
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return nil, ErrInvalid
		}
	}
	return parts, nil
}

// LoadSecure never creates, chmods, locks, repairs or follows a configuration
// path. Actual catalog parent/file custody is exactly owner 0700/0600 on native
// ext4/xfs/tmpfs. Ancestors may be root/owner non-writable, with root sticky
// traversal directories as an explicit exception. Overlay is ancestor-only.
// Cancellation is cooperative between bounded syscalls, not hard cancellation
// of a wedged kernel filesystem. No background I/O goroutine or retry is used.
func LoadSecure(ctx context.Context, path string, owner Owner) (*Catalog, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	parts, err := pathParts(path)
	if err != nil {
		return nil, err
	}
	directories := make([]heldDirectory, 0, len(parts))
	defer func() {
		for i := len(directories) - 1; i >= 0; i-- {
			_ = directories[i].file.Close()
		}
	}()
	for index := 0; index < len(parts); index++ {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		var fd int
		name := ""
		if index == 0 {
			fd, err = syscall.Open("/", directoryFlags, 0)
		} else {
			name = parts[index-1]
			fd, err = syscall.Openat(int(directories[index-1].file.Fd()), name, directoryFlags, 0)
		}
		if err != nil {
			return nil, osFailure(ctx, err)
		}
		file := os.NewFile(uintptr(fd), "subscription-policy-directory")
		before, statErr := observeFile(file)
		leaf := index == len(parts)-1
		if statErr == nil {
			statErr = checkDirectory(before, owner, leaf)
		}
		if statErr == nil {
			statErr = checkFilesystem(file, !leaf)
		}
		if statErr != nil {
			_ = file.Close()
			return nil, statErr
		}
		directories = append(directories, heldDirectory{file: file, name: name, before: before})
	}
	parent := directories[len(directories)-1]
	name := parts[len(parts)-1]
	openRegular := func() (*os.File, fileIdentity, error) {
		if err := contextError(ctx); err != nil {
			return nil, fileIdentity{}, err
		}
		fd, err := syscall.Openat(int(parent.file.Fd()), name, regularFlags, 0)
		if err != nil {
			return nil, fileIdentity{}, osFailure(ctx, err)
		}
		file := os.NewFile(uintptr(fd), "subscription-policy-file")
		info, err := observeFile(file)
		if err == nil {
			err = checkRegular(info, owner, parent.before.device)
		}
		if err == nil {
			err = checkFilesystem(file, false)
		}
		if err != nil {
			_ = file.Close()
			return nil, fileIdentity{}, err
		}
		return file, info, nil
	}
	file, before, err := openRegular()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw := make([]byte, 0, int(before.size))
	var buffer [16 << 10]byte
	for len(raw) <= MaxCatalogBytes {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		limit := min(len(buffer), MaxCatalogBytes+1-len(raw))
		count, readErr := syscall.Read(int(file.Fd()), buffer[:limit])
		if count > 0 {
			raw = append(raw, buffer[:count]...)
		}
		if errors.Is(readErr, syscall.EINTR) {
			continue
		}
		if readErr != nil {
			return nil, osFailure(ctx, readErr)
		}
		if count == 0 {
			break
		}
	}
	if int64(len(raw)) != before.size {
		return nil, ErrChanged
	}
	catalog, err := ParseBytes(raw)
	if err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	after, err := observeFile(file)
	if err != nil {
		return nil, err
	}
	if before != after {
		return nil, ErrChanged
	}
	named, namedInfo, err := openRegular()
	if err != nil {
		return nil, err
	}
	_ = named.Close()
	if before != namedInfo {
		return nil, ErrChanged
	}
	for index, held := range directories {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		leaf := index == len(directories)-1
		current, err := observeFile(held.file)
		if err != nil {
			return nil, err
		}
		if !sameDirectory(held.before, current, leaf) {
			return nil, ErrChanged
		}
		var fd int
		if index == 0 {
			fd, err = syscall.Open("/", directoryFlags, 0)
		} else {
			fd, err = syscall.Openat(int(directories[index-1].file.Fd()), held.name, directoryFlags, 0)
		}
		if err != nil {
			return nil, osFailure(ctx, err)
		}
		named := os.NewFile(uintptr(fd), "subscription-policy-directory-check")
		info, statErr := observeFile(named)
		fsErr := checkFilesystem(named, !leaf)
		_ = named.Close()
		if statErr != nil {
			return nil, statErr
		}
		if fsErr != nil {
			return nil, fsErr
		}
		if !sameDirectory(held.before, info, leaf) {
			return nil, ErrChanged
		}
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return catalog, nil
}
