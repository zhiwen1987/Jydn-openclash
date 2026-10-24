//go:build linux

package authn

import (
	"errors"
	"os"
	"syscall"
)

func snapshotPlatformSupported() bool { return true }

func openCredentialFile(path string, _ bool) (*os.File, error) {
	// Nonblocking prevents a replaced regular-file path from hanging on a FIFO.
	// NOFOLLOW rejects a final-component symlink introduced after Lstat.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "credential file"), nil
}

func credentialMetadata(info os.FileInfo, strict, directory bool) (credentialOSState, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return credentialOSState{}, errors.New("credential metadata unavailable")
	}
	state := credentialOSState{uid: uint64(stat.Uid), gid: uint64(stat.Gid), links: uint64(stat.Nlink), ctimeSec: int64(stat.Ctim.Sec), ctimeNsec: int64(stat.Ctim.Nsec)}
	if strict {
		if directory {
			if !info.IsDir() || (stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0) {
				return credentialOSState{}, errors.New("credential directory owner rejected")
			}
			if info.Mode().Perm()&0022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
				return credentialOSState{}, errors.New("credential directory is writable by another identity")
			}
		} else if !info.Mode().IsRegular() || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
			return credentialOSState{}, errors.New("credential file owner or links rejected")
		}
	}
	return state, nil
}
