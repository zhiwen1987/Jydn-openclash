//go:build !windows

package lease

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

type processLock struct{ file *os.File }

func acquireProcessLock(path string) (*processLock, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lease lock without following symlinks: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, errors.New("lease lock must be a regular file")
	}
	if err := syscall.Fchmod(fd, 0o600); err != nil {
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrStoreLocked
		}
		return nil, err
	}
	closeOnError = false
	return &processLock{file: file}, nil
}

func (lock *processLock) release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := errors.Join(syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN), lock.file.Close())
	lock.file = nil
	return err
}
