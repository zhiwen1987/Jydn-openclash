//go:build !windows

package probe

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

type spoolProcessLock struct{ file *os.File }

func acquireSpoolProcessLock(path string) (*spoolProcessLock, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open probe spool lock without following symlinks: %w", err)
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
		return nil, errors.New("probe spool lock must be a regular file")
	}
	if err := syscall.Fchmod(fd, 0o600); err != nil {
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrSpoolLocked
		}
		return nil, err
	}
	closeOnError = false
	return &spoolProcessLock{file: file}, nil
}

func (l *spoolProcessLock) release() error {
	if l == nil || l.file == nil {
		return nil
	}
	errUnlock := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	errClose := l.file.Close()
	l.file = nil
	return errors.Join(errUnlock, errClose)
}
