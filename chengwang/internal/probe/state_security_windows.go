//go:build windows

package probe

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Windows ACL ownership and hard-link counts are not represented by
// os.FileInfo. The validator still enforces non-reparse regular files, stable
// identity, bounded bytes, and content digests. Production deployment targets
// Linux, where the POSIX implementation also enforces owner-only mode, owner
// equality, and nlink=1.
func stateSecurityMetadataAvailable() bool { return false }

func stateFileIdentity(os.FileInfo) string { return "unavailable" }

func validateStateSecurity(info os.FileInfo, _ bool) (uint64, uint64, uint64, error) {
	return 0, 0, 1, nil
}

func acquireStateValidationLock(path string) (func() error, error) {
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() != 0 {
		return nil, errors.New("state writer lock must be an empty non-symlink regular file")
	}
	pathUTF16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(pathUTF16, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	after, statErr := file.Stat()
	if statErr != nil || !after.Mode().IsRegular() || after.Size() != 0 || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, errors.New("state writer lock identity or type changed while opening")
	}
	var overlapped syscall.Overlapped
	result, _, callErr := spoolProcLockFileEx.Call(file.Fd(), uintptr(spoolLockExclusive|spoolLockFailImmediately), 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if result == 0 {
		_ = file.Close()
		if errors.Is(callErr, spoolErrorLockViolation) {
			return nil, ErrSpoolLocked
		}
		return nil, fmt.Errorf("test state writer lock: %w", callErr)
	}
	closed := false
	return func() error {
		if closed {
			return nil
		}
		closed = true
		result, _, callErr := spoolProcUnlockFileEx.Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
		var unlockErr error
		if result == 0 {
			unlockErr = fmt.Errorf("release state writer lock test: %w", callErr)
		}
		return errors.Join(unlockErr, file.Close())
	}, nil
}
