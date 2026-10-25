//go:build linux && chengwang_capacity_profile

package mihomodeploy

import (
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
	"sync"
	"testing"
	"time"
)

const capacityProfilePrivate = "/tmp/chengwang-capacity-profile-private"
const capacityProfileLimit = 8 << 20
const capacityProfileTest = "^TestLifecycleRecoveryCapacityAndRevisionReserveFailBeforeStop$"

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
	commit := os.Getenv("CHENGWANG_CAPACITY_PROFILE_SOURCE_COMMIT")
	timeout, err := time.ParseDuration(flag.Lookup("test.timeout").Value.String())
	info, statErr := os.Lstat(capacityProfilePrivate)
	if err != nil || timeout != 180*time.Second || flag.Lookup("test.run").Value.String() != capacityProfileTest ||
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
			}{"chengwang.capacity-cpu-profile-state/v1", commit, reason, started.UTC(), stopped.UTC(), stopped.Sub(started).Nanoseconds(), len(raw), hex.EncodeToString(digest[:]), w.failed, w.limited, synced, closed, complete, 60, 180}
			captureOK = capacityProfileWriteJSON("profile-state.json", value) && complete
		})
	}
	timer := time.AfterFunc(60*time.Second, func() { stop("TIMER_60_SECONDS") })
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
