//go:build linux && chengwang_capacity_profile

package mihomodeploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const capacityProfilePrivate = "/tmp/chengwang-capacity-profile-private"
const capacityProfileLimit = 8 << 20
const capacityProfileTest = "^TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop$"
const capacityProfileHome = "/tmp/chengwang-capacity-profile-home"
const capacityProfileParentFile = "full-contracts-parent.json"

type capacityProfileParent struct {
	Schema         string `json:"schema"`
	DiagnosticMode string `json:"diagnosticMode"`
	SourceCommit   string `json:"sourceCommit"`
	ParentPID      int    `json:"parentPID"`
}

func capacityProfileOwned(info os.FileInfo, mode os.FileMode) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 10001 && st.Gid == 10001
}

func capacityProfileUnderHome(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path &&
		(path == capacityProfileHome || strings.HasPrefix(path, capacityProfileHome+string(os.PathSeparator)))
}

func capacityProfileParentFileValid(info os.FileInfo) bool {
	if !capacityProfileOwned(info, 0600) || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16384 {
		return false
	}
	return info.Sys().(*syscall.Stat_t).Nlink == 1
}

// Only these two exact selfexec entries occur in the bound original MODEL
// tests. One intentionally drops the profile environment; the other inherits
// it. Neither an arbitrary -run nor an environment marker alone is admitted.
func capacityProfileModelChild() bool {
	if len(os.Args) != 2 || os.Getuid() != 10001 || os.Getgid() != 10001 {
		return false
	}
	kernel := os.Args[1] == "-test.run=^TestLabKernelModelHelper$"
	probe := os.Args[1] == "-test.run=^TestLifecycleLinuxProcessProbe$"
	if !kernel && !probe {
		return false
	}
	if kernel {
		mode := os.Getenv("CHENGWANG_LAB_KERNEL_MODEL")
		switch mode {
		case "quiet", "listen", "wildcard", "ignore-term", "private-output", "large-output":
		default:
			return false
		}
		allowed := map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "LANG": true, "LC_ALL": true, "TZ": true, "GORACE": true, "CHENGWANG_LAB_KERNEL_MODEL": true}
		seen := map[string]bool{}
		for _, entry := range os.Environ() {
			key, _, ok := strings.Cut(entry, "=")
			if !ok || !allowed[key] || seen[key] {
				return false
			}
			seen[key] = true
		}
		cwd, err := os.Getwd()
		if len(seen) != len(allowed) || err != nil || !capacityProfileUnderHome(cwd) || os.Getenv("HOME") != cwd || os.Getenv("TMPDIR") != cwd ||
			os.Getenv("PATH") != "/usr/bin:/bin" || os.Getenv("LANG") != "C.UTF-8" || os.Getenv("LC_ALL") != "C.UTF-8" || os.Getenv("TZ") != "UTC" || os.Getenv("GORACE") != "atexit_sleep_ms=0" {
			return false
		}
	} else {
		mode := os.Getenv("CHENGWANG_LIFECYCLE_PROBE")
		if (mode != "global-lock" && mode != "fd-inheritance") || os.Getenv("CHENGWANG_LAB_KERNEL_MODEL") != "" ||
			os.Getenv("CHENGWANG_CAPACITY_PROFILE_MODE") != "FULL_CONTRACTS" ||
			!capacityProfileUnderHome(os.Getenv("CHENGWANG_LIFECYCLE_ROOT")) || !capacityProfileUnderHome(os.Getenv("CHENGWANG_LIFECYCLE_GLOBAL")) {
			return false
		}
		fds := os.Getenv("CHENGWANG_LIFECYCLE_FDS")
		if len(fds) == 0 || len(fds) > 16384 || !json.Valid([]byte(fds)) {
			return false
		}
	}
	// This full-only file is created by the actual profiling parent AFTER its
	// fixed timeout/run/commit/uid guard. It is not inherited via environment.
	// Helpers only read this provenance: they never open/modify cpu.pprof or
	// profile-state.json, and grandchildren cannot reuse the direct-parent PID.
	directory, err := os.Lstat(capacityProfilePrivate)
	if err != nil || !directory.IsDir() || !capacityProfileOwned(directory, 0700) {
		return false
	}
	path := filepath.Join(capacityProfilePrivate, capacityProfileParentFile)
	before, err := os.Lstat(path)
	if err != nil || !capacityProfileParentFileValid(before) {
		return false
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	opened, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, 16385))
	closeErr := file.Close()
	after, namedErr := os.Lstat(path)
	if statErr != nil || readErr != nil || closeErr != nil || namedErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) ||
		!capacityProfileParentFileValid(opened) || !capacityProfileParentFileValid(after) || before.Size() != int64(len(raw)) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return false
	}
	var parent capacityProfileParent
	if json.Unmarshal(raw, &parent) != nil || parent.Schema != "chengwang.capacity-profile-parent/v1" || parent.DiagnosticMode != "FULL_CONTRACTS" ||
		parent.ParentPID < 2 || parent.ParentPID != os.Getppid() || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(parent.SourceCommit) || parent.SourceCommit == "0000000000000000000000000000000000000000" {
		return false
	}
	canonical, err := json.Marshal(parent)
	if err != nil || !bytes.Equal(append(canonical, '\n'), raw) || (probe && os.Getenv("CHENGWANG_CAPACITY_PROFILE_SOURCE_COMMIT") != parent.SourceCommit) {
		return false
	}
	self, selfErr := os.Stat("/proc/self/exe")
	ancestor, parentErr := os.Stat("/proc/" + strconv.Itoa(parent.ParentPID) + "/exe")
	return selfErr == nil && parentErr == nil && os.SameFile(self, ancestor)
}

// StopCPUProfile waits for the writer but does not report its write failures.
// Track actual short writes/errors independently; a retained prefix is never
// called a complete profile. This writer receives no config/WAL/credentials.
type capacityProfileWriter struct {
	file    *os.File
	bytes   int64
	failed  bool
	limited bool
}

func (w *capacityProfileWriter) Write(p []byte) (int, error) {
	remaining := int64(capacityProfileLimit) - w.bytes
	if int64(len(p)) > remaining {
		w.failed, w.limited = true, true
		if remaining <= 0 {
			return 0, io.ErrShortWrite
		}
		n, err := w.file.Write(p[:int(remaining)])
		w.bytes += int64(n)
		if err != nil {
			return n, err
		}
		return n, io.ErrShortWrite
	}
	n, err := w.file.Write(p)
	w.bytes += int64(n)
	if err != nil || n != len(p) {
		w.failed = true
		if err == nil {
			err = io.ErrShortWrite
		}
	}
	return n, err
}

func capacityProfileWriteJSON(name string, value any) bool {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 16384 {
		return false
	}
	f, err := os.OpenFile(filepath.Join(capacityProfilePrivate, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return false
	}
	n, writeErr := f.Write(append(raw, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	return writeErr == nil && n == len(raw)+1 && syncErr == nil && closeErr == nil
}

// Only this independent opt-in tag installs a TestMain. The exact original
// TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop body is not
// copied, shortened or modified. There is no HTTP pprof listener or label API.
func TestMain(m *testing.M) {
	flag.Parse()
	if capacityProfileModelChild() {
		// Run the original exact MODEL helper, preserving its actual exit.
		// No profiler, parent profile file, timer or state writer is installed.
		os.Exit(m.Run())
	}
	commit := os.Getenv("CHENGWANG_CAPACITY_PROFILE_SOURCE_COMMIT")
	mode := os.Getenv("CHENGWANG_CAPACITY_PROFILE_MODE")
	runPattern, timerSeconds, stateSchema := capacityProfileTest, 60, "chengwang.capacity-cpu-profile-state/v1"
	if mode == "FULL_CONTRACTS" {
		runPattern, timerSeconds, stateSchema = "^Test", 120, "chengwang.capacity-cpu-profile-state/v2"
	}
	timeout, err := time.ParseDuration(flag.Lookup("test.timeout").Value.String())
	info, statErr := os.Lstat(capacityProfilePrivate)
	if (mode != "" && mode != "FULL_CONTRACTS") || err != nil || timeout != 180*time.Second || flag.Lookup("test.run").Value.String() != runPattern ||
		flag.Lookup("test.count").Value.String() != "1" || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(commit) ||
		commit == "0000000000000000000000000000000000000000" || os.Getuid() != 10001 || os.Getgid() != 10001 ||
		statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		fmt.Fprintln(os.Stderr, "CAPACITY_PROFILE=REJECTED setup_unavailable=true")
		os.Exit(2)
	}
	file, err := os.OpenFile(filepath.Join(capacityProfilePrivate, "cpu.pprof"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CAPACITY_PROFILE=REJECTED file_unavailable=true")
		os.Exit(2)
	}
	w := &capacityProfileWriter{file: file}
	if pprof.StartCPUProfile(w) != nil {
		_ = file.Close()
		fmt.Fprintln(os.Stderr, "CAPACITY_PROFILE=REJECTED start_unavailable=true")
		os.Exit(2)
	}
	if mode == "FULL_CONTRACTS" && !capacityProfileWriteJSON(capacityProfileParentFile, capacityProfileParent{"chengwang.capacity-profile-parent/v1", mode, commit, os.Getpid()}) {
		pprof.StopCPUProfile()
		_ = file.Sync()
		_ = file.Close()
		fmt.Fprintln(os.Stderr, "CAPACITY_PROFILE=REJECTED parent_provenance_unavailable=true")
		os.Exit(2)
	}
	started := time.Now()
	var once sync.Once
	var captureOK bool
	stop := func(reason string) {
		once.Do(func() {
			// Go1.23.12 pprof.go:836-848: this joins all profile writes. The
			// timer itself completes Sync/Close/receipt, even if the test will
			// later panic at180s and never return through TestMain.
			pprof.StopCPUProfile()
			synced := file.Sync() == nil
			closed := file.Close() == nil
			stopped := time.Now()
			raw, readErr := os.ReadFile(filepath.Join(capacityProfilePrivate, "cpu.pprof"))
			digest := sha256.Sum256(raw)
			complete := !w.failed && !w.limited && synced && closed && readErr == nil && len(raw) > 0 && len(raw) <= capacityProfileLimit && int64(len(raw)) == w.bytes
			value := struct {
				Schema              string    `json:"schema"`
				SourceCommit        string    `json:"sourceCommit"`
				StopReason          string    `json:"stopReason"`
				StartedAt           time.Time `json:"startedAt"`
				StoppedAt           time.Time `json:"stoppedAt"`
				DurationNanoseconds int64     `json:"durationNanoseconds"`
				ProfileBytes        int       `json:"profileBytes"`
				ProfileSHA256       string    `json:"profileSHA256"`
				WriterFailed        bool      `json:"writerFailed"`
				LimitReached        bool      `json:"limitReached"`
				SyncSucceeded       bool      `json:"syncSucceeded"`
				CloseSucceeded      bool      `json:"closeSucceeded"`
				Complete            bool      `json:"complete"`
				TimerSeconds        int       `json:"timerSeconds"`
				TestTimeoutSeconds  int       `json:"testTimeoutSeconds"`
				DiagnosticMode      string    `json:"diagnosticMode,omitempty"`
			}{stateSchema, commit, reason, started.UTC(), stopped.UTC(), stopped.Sub(started).Nanoseconds(), len(raw), hex.EncodeToString(digest[:]), w.failed, w.limited, synced, closed, complete, timerSeconds, 180, mode}
			captureOK = capacityProfileWriteJSON("profile-state.json", value) && complete
		})
	}
	timer := time.AfterFunc(time.Duration(timerSeconds)*time.Second, func() { stop(fmt.Sprintf("TIMER_%d_SECONDS", timerSeconds)) })
	code := m.Run()
	_ = timer.Stop()
	stop("M_RUN_RETURNED") // sync.Once also joins an already-running timer stop
	_ = capacityProfileWriteJSON("testmain-return.json", struct {
		Schema       string `json:"schema"`
		SourceCommit string `json:"sourceCommit"`
		Code         int    `json:"code"`
	}{"chengwang.capacity-testmain-return/v1", commit, code})
	// Keep an actual nonzero m.Run result. Capture errors may reject an otherwise
	// passing diagnosis but may never turn a failing original test into a pass.
	if code == 0 && !captureOK {
		code = 2
	}
	os.Exit(code)
}
