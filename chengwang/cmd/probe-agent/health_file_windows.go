//go:build windows

package main

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func validateHealthDirectoryMetadata(os.FileInfo) error { return nil }

func validateHealthFileMetadata(os.FileInfo) error { return nil }

const moveFileReplaceExisting = 0x1

var moveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func replaceHealthFile(source, destination string) error {
	from, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	result, _, callErr := moveFileExW.Call(
		uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), uintptr(moveFileReplaceExisting),
	)
	runtime.KeepAlive(from)
	runtime.KeepAlive(to)
	if result == 0 {
		return callErr
	}
	return nil
}

func syncHealthDirectory(string) error { return nil }
