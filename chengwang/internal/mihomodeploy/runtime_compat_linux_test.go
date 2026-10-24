//go:build linux && chengwang_mihomo_compat

package mihomodeploy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"chengwang/internal/domain"
)

// This opt-in laboratory file executes only the pinned binary's version and
// configuration-test branches. It never starts a listener, sends PUT, or proves
// service/dataplane/business availability. Missing inputs fail; none are skipped.
const (
	compatKernel        = "/tmp/mihomo-compat-kernel/mihomo"
	compatReceipt       = "/tmp/mihomo-compat-kernel/consumption.json"
	compatOutput        = "/tmp/mihomo-compat-private"
	compatHome          = "/tmp/mihomo-compat-home"
	compatExecSchema    = "chengwang.mihomo-compat-exec/v1"
	compatPrivateSchema = "chengwang.mihomo-compat-private-secrets/v1"
	compatUpstream      = "88dcbf7f1614a67c3b36b848ee3592dfa92ada36"
	compatArchive       = "306f81e723e60ce6b828899a6fe83e1d00e9ecefb2dc8d4d849312a5bc00efdc"
	compatStdioMax      = 65536
)

type compatStdio struct {
	Bytes      int    `json:"bytes"`
	SHA256     string `json:"sha256"`
	TotalBytes int64  `json:"totalBytes"`
	Truncated  bool   `json:"truncated"`
}
type compatExecution struct {
	Schema               string       `json:"schema"`
	SourceCommit         string       `json:"sourceCommit"`
	Case                 string       `json:"case"`
	BinarySHA256         string       `json:"binarySHA256"`
	BinaryBytes          int64        `json:"binaryBytes"`
	ConsumptionSHA256    string       `json:"consumptionSHA256"`
	ArgvClass            string       `json:"argvClass"`
	InputSHA256          *string      `json:"inputSHA256"`
	InputBytes           int          `json:"inputBytes"`
	Started              bool         `json:"started"`
	PID                  *int         `json:"pid"`
	ProcStartTicks       *uint64      `json:"procStartTicks"`
	ProcObservationState string       `json:"procObservationState"`
	WaitReturned         bool         `json:"waitReturned"`
	WaitErrorClass       string       `json:"waitErrorClass"`
	ExitCode             *int         `json:"exitCode"`
	Signal               *int         `json:"signal"`
	TimedOut             bool         `json:"timedOut"`
	KillSent             bool         `json:"killSent"`
	ProcessGroupAbsent   *bool        `json:"processGroupAbsent"`
	Stdout               *compatStdio `json:"stdout"`
	Stderr               *compatStdio `json:"stderr"`
}
type compatBoundedWriter struct {
	mu    sync.Mutex
	raw   []byte
	total int64
}

func (w *compatBoundedWriter) Write(raw []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total += int64(len(raw))
	remaining := compatStdioMax - len(w.raw)
	if remaining > len(raw) {
		remaining = len(raw)
	}
	if remaining > 0 {
		w.raw = append(w.raw, raw[:remaining]...)
	}
	// Keep draining after the bound so truncation cannot deadlock the child.
	return len(raw), nil
}
func (w *compatBoundedWriter) snapshot() ([]byte, *compatStdio) {
	w.mu.Lock()
	defer w.mu.Unlock()
	raw := append([]byte{}, w.raw...)
	return raw, &compatStdio{len(raw), labConfigHash(raw), w.total, w.total != int64(len(raw))}
}

type compatFixture struct {
	sourceCommit, binarySHA256, consumptionSHA256 string
	binaryBytes                                   int64
	kernelIdentity, receiptIdentity               syscall.Stat_t
	bodies                                        map[string][]byte
}

func (compatFixture) String() string   { return "private fixed-kernel compatibility fixture" }
func (compatFixture) GoString() string { return "private fixed-kernel compatibility fixture" }
func (compatFixture) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"PRIVATE_COMPAT_FIXTURE"}`), nil
}

var compatOnce sync.Once
var compatPrivate *compatFixture
var compatSetupError error
var compatHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var compatCommit = regexp.MustCompile(`^[a-f0-9]{40}$`)

func compatSame(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func compatStat(file *os.File) (syscall.Stat_t, error) {
	var value syscall.Stat_t
	if syscall.Fstat(int(file.Fd()), &value) != nil {
		return value, ErrArtifactUnsafe
	}
	return value, nil
}
func compatPlain(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrArtifactUnsafe
	}
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrArtifactUnsafe
		}
		if p == "/" {
			break
		}
	}
	return nil
}

// Only small receipts are retained. ELF bytes are hashed as a bounded stream.
func compatReadPinned(path string, maximum int64, mode uint32, retain bool) ([]byte, string, int64, syscall.Stat_t, error) {
	var zero syscall.Stat_t
	if compatPlain(path) != nil {
		return nil, "", 0, zero, ErrArtifactUnsafe
	}
	var named syscall.Stat_t
	if syscall.Lstat(path, &named) != nil {
		return nil, "", 0, zero, ErrArtifactUnsafe
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", 0, zero, ErrArtifactUnsafe
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	before, err := compatStat(file)
	if err != nil || !compatSame(named, before) || before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Mode&07777 != mode || before.Uid != 10001 || before.Gid != 10001 || before.Nlink != 1 || before.Size <= 0 || before.Size > maximum {
		return nil, "", 0, zero, ErrArtifactUnsafe
	}
	hash := sha256.New()
	var saved bytes.Buffer
	var writer io.Writer = hash
	if retain {
		writer = io.MultiWriter(hash, &saved)
	}
	count, err := io.Copy(writer, io.LimitReader(file, maximum+1))
	after, statErr := compatStat(file)
	var final syscall.Stat_t
	if err != nil || statErr != nil || count != before.Size || count > maximum || syscall.Lstat(path, &final) != nil || !compatSame(before, after) || !compatSame(before, final) || compatPlain(path) != nil {
		return nil, "", 0, zero, ErrArtifactUnsafe
	}
	return saved.Bytes(), hex.EncodeToString(hash.Sum(nil)), count, before, nil
}
func compatPrivateDirectory(path string) error {
	if compatPlain(path) != nil {
		return ErrArtifactUnsafe
	}
	var v syscall.Stat_t
	if syscall.Lstat(path, &v) != nil || v.Mode&syscall.S_IFMT != syscall.S_IFDIR || v.Mode&07777 != 0700 || v.Uid != 10001 || v.Gid != 10001 {
		return ErrArtifactUnsafe
	}
	return nil
}
func compatWritePrivate(name string, raw []byte) error {
	if filepath.Base(name) != name || name == "." || compatPrivateDirectory(compatOutput) != nil {
		return ErrArtifactUnsafe
	}
	dfd, err := syscall.Open(compatOutput, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return ErrArtifactUnsafe
	}
	directory := os.NewFile(uintptr(dfd), compatOutput)
	defer directory.Close()
	before, err := compatStat(directory)
	if err != nil {
		return ErrArtifactUnsafe
	}
	fd, err := syscall.Openat(dfd, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return ErrArtifactUnsafe
	}
	file := os.NewFile(uintptr(fd), name)
	if _, err := io.Copy(file, bytes.NewReader(raw)); err != nil {
		_ = file.Close()
		return ErrArtifactUnsafe
	}
	if file.Sync() != nil {
		_ = file.Close()
		return ErrArtifactUnsafe
	}
	st, err := compatStat(file)
	closeErr := file.Close()
	var named syscall.Stat_t
	if err != nil || closeErr != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07777 != 0600 || st.Uid != 10001 || st.Gid != 10001 || st.Nlink != 1 || st.Size != int64(len(raw)) || directory.Sync() != nil || syscall.Lstat(compatOutput, &named) != nil || named.Dev != before.Dev || named.Ino != before.Ino || named.Mode != before.Mode || named.Uid != before.Uid || named.Gid != before.Gid {
		return ErrArtifactUnsafe
	}
	return nil
}
func compatInitialize() (*compatFixture, error) {
	if os.Geteuid() != 10001 || os.Getegid() != 10001 || os.Getenv("CHENGWANG_MIHOMO_COMPAT_ELF") != compatKernel || os.Getenv("CHENGWANG_MIHOMO_COMPAT_OUT") != compatOutput || os.Getenv("CHENGWANG_MIHOMO_COMPAT_RECEIPT") != compatReceipt || os.Getenv("HOME") != compatHome || !compatCommit.MatchString(os.Getenv("CHENGWANG_MIHOMO_COMPAT_SOURCE_COMMIT")) || compatPrivateDirectory(compatOutput) != nil || compatPrivateDirectory(compatHome) != nil {
		return nil, ErrArtifactUnsafe
	}
	raw, receiptHash, _, receiptStat, err := compatReadPinned(compatReceipt, 256<<10, 0400, true)
	if err != nil {
		return nil, err
	}
	var receipt struct {
		Schema    string `json:"schema"`
		State     string `json:"state"`
		Component string `json:"component"`
		Version   string `json:"version"`
		Upstream  string `json:"upstreamSourceCommit"`
		Source    struct {
			Commit string `json:"projectSourceCommit"`
		} `json:"source"`
		Archive struct {
			SHA256 string `json:"sha256"`
		} `json:"archive"`
		ELF struct {
			SHA256 string `json:"sha256"`
			Bytes  int64  `json:"bytes"`
		} `json:"elf"`
		RuntimeExecuted    *bool `json:"runtimeExecuted"`
		ProductionApproved *bool `json:"productionApproved"`
		Production         *bool `json:"production"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.Schema != "chengwang.mihomo-candidate-consumption/v1" || receipt.State != "PINNED_GZIP_EXPANDED_NOT_EXECUTED" || receipt.Component != "MetaCubeX/mihomo" || receipt.Version != "v1.19.32" || receipt.Upstream != compatUpstream || receipt.Archive.SHA256 != compatArchive || receipt.Source.Commit != os.Getenv("CHENGWANG_MIHOMO_COMPAT_SOURCE_COMMIT") || receipt.RuntimeExecuted == nil || *receipt.RuntimeExecuted || receipt.ProductionApproved == nil || *receipt.ProductionApproved || receipt.Production == nil || *receipt.Production {
		return nil, ErrArtifactBinding
	}
	_, binaryHash, binaryBytes, kernelStat, err := compatReadPinned(compatKernel, 128<<20, 0500, false)
	if err != nil || !compatHash.MatchString(receipt.ELF.SHA256) || binaryHash != receipt.ELF.SHA256 || binaryBytes != receipt.ELF.Bytes {
		return nil, ErrArtifactBinding
	}
	var first, second [32]byte
	if _, err := rand.Read(first[:]); err != nil {
		return nil, ErrArtifactUnsafe
	}
	if _, err := rand.Read(second[:]); err != nil {
		return nil, ErrArtifactUnsafe
	}
	baseSecret, candidateSecret := hex.EncodeToString(first[:]), hex.EncodeToString(second[:])
	if baseSecret == candidateSecret {
		return nil, ErrArtifactUnsafe
	}
	secrets, err := json.Marshal(struct {
		Schema    string `json:"schema"`
		Base      string `json:"base"`
		Candidate string `json:"candidate"`
	}{compatPrivateSchema, baseSecret, candidateSecret})
	if err != nil || compatWritePrivate(".secrets.private.json", secrets) != nil {
		return nil, ErrArtifactUnsafe
	}
	bodies := map[string][]byte{}
	for _, role := range []string{"base", "candidate"} {
		secret := baseSecret
		strategy := "DIRECT"
		if role == "candidate" {
			secret = candidateSecret
			strategy = "compat-egress"
		}
		spec := LabConfigSpec{MixedPort: 28401, ControllerPort: 28402, ControllerSecret: secret, DefaultTarget: strategy,
			HTTPNodes: []LabHTTPNode{{ID: "compat-http", Server: "127.0.0.1", Port: 28403}},
			Draft:     domain.PolicyDraft{Name: "fixed-kernel-compat-" + role, Pools: []domain.NodePool{{ID: "compat-egress", Name: "laboratory HTTP pool", Members: []string{"compat-http"}}}, Businesses: []domain.BusinessPolicy{{ID: "compat-business", Name: "laboratory business", Domains: []string{"example.com"}, Strategy: strategy, Candidates: []string{"DIRECT", "REJECT", "compat-egress"}}}}}
		artifact, err := BuildLabConfig(spec)
		if err != nil || artifact.AdmissionError() != nil {
			return nil, ErrArtifactBinding
		}
		body := artifact.Bytes()
		if compatWritePrivate(role+".config.private.yaml", body) != nil {
			return nil, ErrArtifactUnsafe
		}
		bodies[role] = body
	}
	return &compatFixture{receipt.Source.Commit, binaryHash, receiptHash, binaryBytes, kernelStat, receiptStat, bodies}, nil
}
func compatRequire(t *testing.T) *compatFixture {
	t.Helper()
	compatOnce.Do(func() { compatPrivate, compatSetupError = compatInitialize() })
	if compatSetupError != nil || compatPrivate == nil {
		t.Fatal("private fixed-kernel compatibility setup rejected")
	}
	return compatPrivate
}
func (f *compatFixture) inputsStable() bool {
	_, digest, size, st, err := compatReadPinned(compatKernel, 128<<20, 0500, false)
	if err != nil || digest != f.binarySHA256 || size != f.binaryBytes || !compatSame(st, f.kernelIdentity) {
		return false
	}
	_, digest, _, st, err = compatReadPinned(compatReceipt, 256<<10, 0400, true)
	return err == nil && digest == f.consumptionSHA256 && compatSame(st, f.receiptIdentity)
}
func compatObserveStart(pid int) (*uint64, string) {
	file, err := os.Open("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return nil, "NOT_OBSERVED"
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(raw) > 8192 || !bytes.HasPrefix(raw, []byte(strconv.Itoa(pid)+" (")) {
		return nil, "NOT_OBSERVED"
	}
	closing := bytes.LastIndexByte(raw, ')')
	if closing < 0 {
		return nil, "NOT_OBSERVED"
	}
	fields := strings.Fields(string(raw[closing+1:]))
	if len(fields) < 20 {
		return nil, "NOT_OBSERVED"
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 || ticks > 1<<63-1 {
		return nil, "NOT_OBSERVED"
	}
	return &ticks, "OBSERVED"
}
func compatSignalOwnedGroup(pid int, killed *atomic.Bool) error {
	if pid <= 1 {
		return ErrArtifactUnsafe
	}
	err := syscall.Kill(-pid, syscall.SIGKILL)
	if err == nil {
		killed.Store(true)
		return nil
	}
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return ErrArtifactUnsafe
}
func compatGroupAbsent(pid int, killed *atomic.Bool) *bool {
	if pid <= 1 {
		return nil
	}
	err := syscall.Kill(-pid, 0)
	if errors.Is(err, syscall.ESRCH) {
		value := true
		return &value
	}
	if err != nil {
		return nil
	}
	// Setpgid on this successful Start established the owned group. Its presence
	// after direct-child Wait is unexpected: clean it, but record killSent=true.
	if compatSignalOwnedGroup(pid, killed) != nil {
		return nil
	}
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		err = syscall.Kill(-pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			value := true
			return &value
		}
		if err != nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	value := false
	return &value
}
func compatRun(t *testing.T, role string, input []byte) (compatExecution, []byte, []byte) {
	t.Helper()
	fixture := compatRequire(t)
	if role != "version" && role != "base" && role != "candidate" && role != "malformed" {
		t.Fatal("unknown fixed compatibility case")
	}
	if role == "version" && len(input) != 0 {
		t.Fatal("version case must not receive configuration")
	}
	if (role == "base" || role == "candidate") && (len(input) == 0 || !bytes.Equal(input, fixture.bodies[role])) {
		t.Fatal("generated compatibility input differs")
	}
	if role == "malformed" && !bytes.Equal(input, []byte("mixed-port: [\n")) {
		t.Fatal("malformed compatibility fixture differs")
	}
	if !fixture.inputsStable() {
		t.Fatal("fixed compatibility input custody rejected")
	}
	home := filepath.Join(compatHome, role)
	if os.Mkdir(home, 0700) != nil || compatPrivateDirectory(home) != nil || os.Mkdir(filepath.Join(home, "tmp"), 0700) != nil {
		t.Fatal("private compatibility home rejected")
	}
	args := []string{"-v"}
	argvClass := "VERSION"
	if role != "version" {
		args = []string{"-t", "-d", home, "-f", "-"}
		argvClass = "STDIN_TEST"
	}
	record := compatExecution{Schema: compatExecSchema, SourceCommit: fixture.sourceCommit, Case: role, BinarySHA256: fixture.binarySHA256, BinaryBytes: fixture.binaryBytes, ConsumptionSHA256: fixture.consumptionSHA256, ArgvClass: argvClass, InputBytes: len(input), ProcObservationState: "NOT_OBSERVED", WaitErrorClass: "NOT_WAITED"}
	if role != "version" {
		digest := labConfigHash(input)
		record.InputSHA256 = &digest
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, compatKernel, args...)
	command.Dir = home
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "TMPDIR=" + filepath.Join(home, "tmp"), "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"}
	command.Stdin = bytes.NewReader(input)
	stdout, stderr := &compatBoundedWriter{}, &compatBoundedWriter{}
	command.Stdout = stdout
	command.Stderr = stderr
	command.WaitDelay = 2 * time.Second
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	var timedOut, killed atomic.Bool
	command.Cancel = func() error {
		timedOut.Store(true)
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return compatSignalOwnedGroup(command.Process.Pid, &killed)
	}
	// Linux Pdeathsig is tied to the creating thread. Keep it alive through Wait.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var outRaw, errRaw []byte
	startErr := command.Start()
	if startErr == nil {
		record.Started = true
		pid := command.Process.Pid
		record.PID = &pid
		record.ProcStartTicks, record.ProcObservationState = compatObserveStart(pid)
		waitErr := command.Wait()
		record.WaitReturned = true
		record.WaitErrorClass = "NONE"
		if waitErr != nil {
			var exit *exec.ExitError
			if errors.As(waitErr, &exit) {
				record.WaitErrorClass = "EXIT_STATUS"
			} else {
				record.WaitErrorClass = "WAIT_ERROR"
			}
		}
		if command.ProcessState != nil {
			if status, ok := command.ProcessState.Sys().(syscall.WaitStatus); ok {
				if status.Signaled() {
					signal := int(status.Signal())
					record.Signal = &signal
				} else if status.Exited() {
					code := status.ExitStatus()
					record.ExitCode = &code
				}
			}
		}
		record.ProcessGroupAbsent = compatGroupAbsent(pid, &killed)
		outRaw, record.Stdout = stdout.snapshot()
		errRaw, record.Stderr = stderr.snapshot()
		if compatWritePrivate(role+".stdout", outRaw) != nil || compatWritePrivate(role+".stderr", errRaw) != nil {
			t.Fatal("private compatibility stream persistence rejected")
		}
	}
	// Start failures intentionally retain null PID/exit/streams; no zero-byte
	// placeholders are invented for streams whose execution was never observed.
	record.TimedOut = timedOut.Load() || errors.Is(ctx.Err(), context.DeadlineExceeded)
	record.KillSent = killed.Load()
	raw, err := json.Marshal(record)
	if err != nil || compatWritePrivate(role+".exec.json", raw) != nil {
		t.Fatal("private compatibility execution record rejected")
	}
	if !fixture.inputsStable() {
		t.Fatal("fixed compatibility input changed")
	}
	return record, outRaw, errRaw
}
func compatRequireCompletion(t *testing.T, record compatExecution, outRaw, errRaw []byte) {
	t.Helper()
	if !record.Started || record.PID == nil || *record.PID <= 1 || !record.WaitReturned || record.TimedOut || record.KillSent || record.ProcessGroupAbsent == nil || !*record.ProcessGroupAbsent || record.Signal != nil || record.ExitCode == nil || record.Stdout == nil || record.Stderr == nil || record.Stdout.Truncated || record.Stderr.Truncated || !utf8.Valid(outRaw) || !utf8.Valid(errRaw) || len(errRaw) != 0 {
		t.Fatal("fixed kernel did not complete a bounded clean compatibility command")
	}
}
func TestMihomoCompatVersion(t *testing.T) {
	record, stdout, stderr := compatRun(t, "version", nil)
	compatRequireCompletion(t, record, stdout, stderr)
	if record.WaitErrorClass != "NONE" || *record.ExitCode != 0 || !bytes.HasPrefix(stdout, []byte("Mihomo Meta v1.19.32 linux amd64 with ")) {
		t.Fatal("fixed kernel version rejected")
	}
}
func TestMihomoCompatGeneratedConfigs(t *testing.T) {
	t.Run("base", func(t *testing.T) {
		fixture := compatRequire(t)
		record, stdout, stderr := compatRun(t, "base", append([]byte{}, fixture.bodies["base"]...))
		compatRequireCompletion(t, record, stdout, stderr)
		if record.WaitErrorClass != "NONE" || *record.ExitCode != 0 || !bytes.Contains(stdout, []byte("test is successful")) {
			t.Fatal("fixed kernel base syntax rejected")
		}
	})
	t.Run("candidate", func(t *testing.T) {
		fixture := compatRequire(t)
		record, stdout, stderr := compatRun(t, "candidate", append([]byte{}, fixture.bodies["candidate"]...))
		compatRequireCompletion(t, record, stdout, stderr)
		if record.WaitErrorClass != "NONE" || *record.ExitCode != 0 || !bytes.Contains(stdout, []byte("test is successful")) {
			t.Fatal("fixed kernel candidate syntax rejected")
		}
	})
}
func TestMihomoCompatMalformedYAML(t *testing.T) {
	record, stdout, stderr := compatRun(t, "malformed", []byte("mixed-port: [\n"))
	compatRequireCompletion(t, record, stdout, stderr)
	if record.WaitErrorClass != "EXIT_STATUS" || *record.ExitCode == 0 || !bytes.Contains(stdout, []byte("configuration test failed")) {
		t.Fatal("fixed kernel malformed syntax was not normally rejected")
	}
}
