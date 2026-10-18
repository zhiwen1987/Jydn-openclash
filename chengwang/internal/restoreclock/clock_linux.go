//go:build linux

package restoreclock

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const clockBoottime = 7

func platformSample() (rawSample, error) {
	bootRaw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return rawSample{}, err
	}
	if len(bootRaw) == 0 || len(bootRaw) > 128 {
		return rawSample{}, ErrInvalid
	}
	var ts syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockBoottime, uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 {
		return rawSample{}, errno
	}
	if ts.Sec < 0 || ts.Nsec < 0 || ts.Nsec >= 1_000_000_000 {
		return rawSample{}, ErrInvalid
	}
	seconds := uint64(ts.Sec)
	if seconds > (^uint64(0)-uint64(ts.Nsec))/1_000_000_000 {
		return rawSample{}, errors.Join(ErrInvalid, errors.New("boottime overflows nanoseconds"))
	}
	return rawSample{
		wall:       time.Now().UTC(),
		bootID:     strings.TrimSpace(string(bootRaw)),
		boottimeNS: seconds*1_000_000_000 + uint64(ts.Nsec),
	}, nil
}
