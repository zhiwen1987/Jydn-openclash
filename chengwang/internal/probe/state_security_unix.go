//go:build !windows

package probe

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func stateSecurityMetadataAvailable() bool { return true }

func stateFileIdentity(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "unavailable"
	}
	return fmt.Sprintf("%d:%d", uint64(stat.Dev), uint64(stat.Ino))
}

func validateStateSecurity(info os.FileInfo, directory bool) (uint64, uint64, uint64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, errors.New("POSIX ownership and link metadata are unavailable")
	}
	want := os.FileMode(0o600)
	if directory {
		want = 0o700
	}
	actual := info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	if actual != want {
		return 0, 0, 0, errors.New("permissions must be owner-only")
	}
	if !directory && uint64(stat.Nlink) != 1 {
		return 0, 0, 0, errors.New("regular state files must have exactly one hard link")
	}
	return uint64(stat.Uid), uint64(stat.Gid), uint64(stat.Nlink), nil
}

func acquireStateValidationLock(path string) (*stateValidationLock, error) {
	before, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("required state writer lock is missing")
		}
		return nil, fmt.Errorf("inspect state writer lock: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("state writer lock must be a regular file")
	}
	if before.Size() != 0 {
		return nil, errors.New("state writer lock file must be empty")
	}
	if _, _, _, err := validateStateSecurity(before, false); err != nil {
		return nil, fmt.Errorf("unsafe state writer lock: %w", err)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	after, statErr := file.Stat()
	if statErr != nil || !after.Mode().IsRegular() || after.Size() != 0 || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, errors.New("state writer lock identity or type changed while opening")
	}
	if _, _, _, err := validateStateSecurity(after, false); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("unsafe opened state writer lock: %w", err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrSpoolLocked
		}
		return nil, err
	}
	verify := func() error {
		held, err := file.Stat()
		if err != nil || !held.Mode().IsRegular() || held.Size() != 0 || !os.SameFile(after, held) {
			return errors.Join(errors.New("held state writer lock identity or type changed"), err)
		}
		if _, _, _, err := validateStateSecurity(held, false); err != nil {
			return fmt.Errorf("unsafe held state writer lock: %w", err)
		}
		current, err := os.Lstat(path)
		if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || current.Size() != 0 || !os.SameFile(after, current) {
			return errors.Join(errors.New("state writer lock path was replaced"), err)
		}
		if _, _, _, err := validateStateSecurity(current, false); err != nil {
			return fmt.Errorf("unsafe state writer lock path: %w", err)
		}
		return nil
	}
	return &stateValidationLock{
		verify: verify,
		release: func() error {
			return errors.Join(syscall.Flock(fd, syscall.LOCK_UN), file.Close())
		},
	}, nil
}
