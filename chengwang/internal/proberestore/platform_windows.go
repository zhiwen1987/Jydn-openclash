//go:build windows

package proberestore

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type platformStore struct{ dir string }

func openPlatformStore(path string) (*platformStore, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(h)
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.New("control directory must be a real directory")
	}
	return &platformStore{dir: path}, nil
}
func (p *platformStore) durableWrites() bool { return false }
func (p *platformStore) close() error        { return nil }
func (p *platformStore) read(name string, limit int) ([]byte, error) {
	path := filepath.Join(p.dir, name)
	q, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(q, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&(syscall.FILE_ATTRIBUTE_DIRECTORY|syscall.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 {
		return nil, errors.New("control record must be a single-link regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errors.New("control record exceeds size limit")
	}
	return b, nil
}
func (p *platformStore) replace(string, []byte) error { return ErrDurabilityUnsupported }
