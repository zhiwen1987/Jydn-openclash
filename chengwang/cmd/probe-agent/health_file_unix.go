//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

func validateHealthDirectoryMetadata(info os.FileInfo) error {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("probe-agent health directory metadata is unavailable")
	}
	if metadata.Uid != uint32(os.Geteuid()) {
		return errors.New("probe-agent health directory must be owned by the effective user")
	}
	return nil
}

func validateHealthFileMetadata(info os.FileInfo) error {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("probe-agent health file metadata is unavailable")
	}
	if metadata.Uid != uint32(os.Geteuid()) {
		return errors.New("probe-agent health file must be owned by the effective user")
	}
	if uint64(metadata.Nlink) != 1 {
		return errors.New("probe-agent health file must have exactly one hard link")
	}
	return nil
}

func replaceHealthFile(source, destination string) error {
	return os.Rename(source, destination)
}

func syncHealthDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
