//go:build windows

package evidence

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
)

var (
	kernel32DLL      = syscall.NewLazyDLL("kernel32.dll")
	lockFileExProc   = kernel32DLL.NewProc("LockFileEx")
	unlockFileExProc = kernel32DLL.NewProc("UnlockFileEx")
)

func acquireEvidenceLock(path string) (*os.File, error) {
	pathPointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode evidence writer lock path: %w", err)
	}
	handle, err := syscall.CreateFile(
		pathPointer,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open evidence writer lock: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	var overlapped syscall.Overlapped
	result, _, callErr := lockFileExProc.Call(
		uintptr(handle),
		lockfileExclusiveLock|lockfileFailImmediately,
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if result == 0 {
		file.Close()
		if errno, ok := callErr.(syscall.Errno); ok && (errno == syscall.Errno(33) || errno == syscall.Errno(158)) {
			return nil, ErrStoreLocked
		}
		return nil, fmt.Errorf("acquire evidence writer lock: %w", callErr)
	}
	return file, nil
}

func releaseEvidenceLock(file *os.File) error {
	if file == nil {
		return nil
	}
	var overlapped syscall.Overlapped
	result, _, callErr := unlockFileExProc.Call(
		file.Fd(),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	var unlockErr error
	if result == 0 {
		unlockErr = fmt.Errorf("release evidence writer lock: %w", callErr)
	}
	return errors.Join(unlockErr, file.Close())
}
