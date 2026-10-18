//go:build windows

package operation

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Windows uses a kernel byte-range lock held by the open handle. The lock
// file is opened with FILE_FLAG_OPEN_REPARSE_POINT and then inspected through
// that same handle, avoiding a path-check/open race. Windows does not map
// chmod(0600) to a POSIX owner-only ACL; directory ACL hardening remains a
// deployment responsibility and the production container uses the Unix path.

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
	errorLockViolation      = syscall.Errno(33)
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

type processLock struct {
	file       *os.File
	overlapped syscall.Overlapped
}

func acquireProcessLock(path string) (*processLock, error) {
	pathUTF16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode operation file store lock path: %w", err)
	}
	handle, err := syscall.CreateFile(
		pathUTF16,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open operation file store lock: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, fmt.Errorf("inspect operation file store lock: %w", err)
	}
	fileType, err := syscall.GetFileType(handle)
	if err != nil {
		return nil, fmt.Errorf("inspect operation file store type: %w", err)
	}
	if fileType != syscall.FILE_TYPE_DISK || info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, errors.New("operation file store lock must be a regular file, not a reparse point")
	}
	lock := &processLock{file: file}
	result, _, callErr := procLockFileEx.Call(
		file.Fd(),
		uintptr(lockfileExclusiveLock|lockfileFailImmediately),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&lock.overlapped)),
	)
	if result == 0 {
		if errors.Is(callErr, errorLockViolation) {
			return nil, ErrStoreLocked
		}
		return nil, fmt.Errorf("lock operation file store: %w", callErr)
	}
	closeOnError = false
	return lock, nil
}

func (l *processLock) release() error {
	if l == nil || l.file == nil {
		return nil
	}
	result, _, callErr := procUnlockFileEx.Call(
		l.file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&l.overlapped)),
	)
	errUnlock := error(nil)
	if result == 0 {
		errUnlock = fmt.Errorf("unlock operation file store: %w", callErr)
	}
	errClose := l.file.Close()
	l.file = nil
	return errors.Join(errUnlock, errClose)
}
