//go:build linux

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func readPrivate(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, "\\\x00") {
		return nil, errConfiguration
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errConfiguration
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, errConfiguration
		}
		fd = next
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || (stat.Mode&0022 != 0 && !(stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0)) {
			_ = unix.Close(fd)
			return nil, errConfiguration
		}
	}
	defer unix.Close(fd)
	var parent unix.Stat_t
	if unix.Fstat(fd, &parent) != nil || parent.Uid != uint32(os.Geteuid()) || parent.Gid != uint32(os.Getegid()) || parent.Mode&07777 != 0700 {
		return nil, errConfiguration
	}
	fileFD, err := unix.Openat(fd, filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errConfiguration
	}
	file := os.NewFile(uintptr(fileFD), "private-candidate-input")
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fileFD, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0600 || before.Nlink != 1 || before.Uid != uint32(os.Geteuid()) || before.Gid != uint32(os.Getegid()) || before.Size <= 0 || before.Size > limit {
		return nil, errConfiguration
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != before.Size || unix.Fstat(fileFD, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, errConfiguration
	}
	return raw, nil
}

// The candidate opens an already provisioned audit history. evidence.Open's
// general-purpose empty-log initialization must not hide accidental deletion.
func requireExistingAudit(directory string) error {
	if _, err := readPrivate(filepath.Join(directory, "checkpoint.json"), 8<<10); err != nil {
		return errConfiguration
	}
	var event unix.Stat_t
	if unix.Lstat(filepath.Join(directory, "events.jsonl"), &event) != nil || event.Mode&unix.S_IFMT != unix.S_IFREG || event.Mode&07777 != 0600 || event.Nlink != 1 || event.Uid != uint32(os.Geteuid()) || event.Gid != uint32(os.Getegid()) {
		return errConfiguration
	}
	return nil
}
