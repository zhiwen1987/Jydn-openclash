//go:build windows

package restoreevidence

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type platformStore struct {
	dir  string
	info syscall.ByHandleFileInformation
}

func openPlatformStore(dir string) (*platformStore, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(abs) != abs {
		return nil, ErrUnsafeObject
	}
	info, err := inspectWindowsPath(abs, true)
	if err != nil {
		return nil, err
	}
	return &platformStore{dir: abs, info: info}, nil
}

func (p *platformStore) durableWrites() bool { return false }
func (p *platformStore) close() error        { return nil }

func (p *platformStore) publish(string, []byte, int, func(faultStage) error) (publishOutcome, error) {
	return publishOutcome{state: NotCommitted}, ErrUnsupported
}

func (p *platformStore) read(name string, limit int) (fileMeta, []byte, error) {
	if err := safeWindowsLeaf(name); err != nil {
		return fileMeta{}, nil, err
	}
	if err := p.verifyDirectory(); err != nil {
		return fileMeta{}, nil, err
	}
	full := filepath.Join(p.dir, name)
	ptr, err := syscall.UTF16PtrFromString(full)
	if err != nil {
		return fileMeta{}, nil, err
	}
	h, err := syscall.CreateFile(ptr, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fileMeta{}, nil, err
	}
	f := os.NewFile(uintptr(h), full)
	defer f.Close()
	var first syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &first); err != nil {
		return fileMeta{}, nil, err
	}
	if first.FileAttributes&(syscall.FILE_ATTRIBUTE_DIRECTORY|syscall.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || first.NumberOfLinks != 1 {
		return fileMeta{}, nil, ErrUnsafeObject
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil {
		return fileMeta{}, nil, err
	}
	if len(b) > limit {
		return fileMeta{}, nil, ErrTooLarge
	}
	second, err := inspectWindowsPath(full, false)
	if err != nil {
		return fileMeta{}, nil, err
	}
	if !sameWindowsFile(first, second) || second.NumberOfLinks != 1 {
		return fileMeta{}, nil, ErrUnsafeObject
	}
	if err := p.verifyDirectory(); err != nil {
		return fileMeta{}, nil, err
	}
	inode := uint64(first.FileIndexHigh)<<32 | uint64(first.FileIndexLow)
	return fileMeta{digest: sha256Hex(b), size: len(b), device: uint64(first.VolumeSerialNumber), inode: inode}, b, nil
}

func (p *platformStore) verifyDirectory() error {
	current, err := inspectWindowsPath(p.dir, true)
	if err != nil {
		return err
	}
	if !sameWindowsFile(p.info, current) {
		return errors.Join(ErrUnsafeObject, errors.New("evidence directory path was replaced"))
	}
	return nil
}

func inspectWindowsPath(path string, directory bool) (syscall.ByHandleFileInformation, error) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return syscall.ByHandleFileInformation{}, err
	}
	flags := uint32(syscall.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= syscall.FILE_FLAG_BACKUP_SEMANTICS
	}
	h, err := syscall.CreateFile(ptr, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, flags, 0)
	if err != nil {
		return syscall.ByHandleFileInformation{}, err
	}
	defer syscall.CloseHandle(h)
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		return syscall.ByHandleFileInformation{}, err
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return syscall.ByHandleFileInformation{}, ErrUnsafeObject
	}
	if directory != (info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0) {
		return syscall.ByHandleFileInformation{}, ErrUnsafeObject
	}
	return info, nil
}

func sameWindowsFile(a, b syscall.ByHandleFileInformation) bool {
	return a.VolumeSerialNumber == b.VolumeSerialNumber && a.FileIndexHigh == b.FileIndexHigh && a.FileIndexLow == b.FileIndexLow
}

func safeWindowsLeaf(name string) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return ErrUnsafeObject
	}
	if strings.TrimRight(name, " .") != name {
		return ErrUnsafeObject
	}
	for _, ch := range name {
		if ch < 0x20 || strings.ContainsRune(`<>:"/\\|?*`, ch) {
			return ErrUnsafeObject
		}
	}
	stem := strings.ToLower(strings.SplitN(name, ".", 2)[0])
	if stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" ||
		(len(stem) == 4 && (strings.HasPrefix(stem, "com") || strings.HasPrefix(stem, "lpt")) && stem[3] >= '1' && stem[3] <= '9') {
		return ErrUnsafeObject
	}
	return nil
}

func platformClock() (clockSnapshot, error) { return clockSnapshot{}, ErrUnsupported }
