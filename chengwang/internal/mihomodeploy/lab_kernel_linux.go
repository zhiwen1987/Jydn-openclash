//go:build linux

package mihomodeploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

const labKernelPath = "/tmp/mihomo-apply-kernel/mihomo"
const labKernelReceiptPath = "/tmp/mihomo-apply-kernel/consumption.json"
const labKernelHome = "/tmp/mihomo-apply-home"
const labKernelPublished = "306f81e723e60ce6b828899a6fe83e1d00e9ecefb2dc8d4d849312a5bc00efdc"
const labKernelUpstream = "88dcbf7f1614a67c3b36b848ee3592dfa92ada36"
const labKernelStreamLimit = 64 << 10

var labKernelCommit = regexp.MustCompile(`^[a-f0-9]{40}$`)
var labKernelDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type labKernelInputCore struct {
	commit, binaryHash, receiptHash string
	binaryBytes                     int64
	binaryStat, receiptStat         syscall.Stat_t
}
type labKernelReceipt struct {
	Schema string `json:"schema"`
	State  string `json:"state"`
	Source struct {
		Commit string `json:"projectSourceCommit"`
		Files  []struct {
			Path   string `json:"path"`
			Bytes  int64  `json:"bytes"`
			SHA256 string `json:"sha256"`
		} `json:"sourceFiles"`
		PinSHA256 string `json:"pinSHA256"`
	} `json:"source"`
	Component string `json:"component"`
	Version   string `json:"version"`
	Upstream  string `json:"upstreamSourceCommit"`
	Archive   struct {
		Name     string `json:"name"`
		Bytes    int64  `json:"bytes"`
		SHA256   string `json:"sha256"`
		PinBasis string `json:"pinBasis"`
	} `json:"archive"`
	Gzip struct {
		Single   *bool  `json:"singleMember"`
		Complete *bool  `json:"complete"`
		CRC      string `json:"trailerCRC32"`
		Size     uint64 `json:"trailerISIZE"`
	} `json:"gzip"`
	ELF struct {
		Bytes           int64  `json:"bytes"`
		SHA256          string `json:"sha256"`
		ByteOrder       string `json:"byteOrder"`
		Class           string `json:"elfClass"`
		Machine         string `json:"machine"`
		Type            string `json:"type"`
		Entry           uint64 `json:"entryPoint"`
		Programs        uint16 `json:"programHeaderCount"`
		Loads           uint16 `json:"loadSegments"`
		Sections        uint16 `json:"sectionHeaderCount"`
		ExecutableEntry *bool  `json:"executableEntryMapped"`
	} `json:"elf"`
	Output struct {
		Path          string `json:"path"`
		Mode          string `json:"mode"`
		ReceiptMode   string `json:"receiptMode"`
		DirectoryMode string `json:"directoryMode"`
	} `json:"output"`
	RuntimeExecuted *bool `json:"runtimeExecuted"`
	Compatibility   *bool `json:"runtimeCompatibilityProven"`
	Business        *bool `json:"businessAvailabilityProven"`
	Signature       *bool `json:"publisherSignatureProven"`
	Approved        *bool `json:"productionApproved"`
	Production      *bool `json:"production"`
}

func labKernelSame(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func labKernelPlain(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for p := path; ; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil || i.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if p == "/" {
			return true
		}
	}
}
func labKernelFile(path string, limit int64, mode uint32, keep bool) ([]byte, string, syscall.Stat_t, error) {
	var zero syscall.Stat_t
	if !labKernelPlain(path) {
		return nil, "", zero, errLabKernelInput
	}
	var named syscall.Stat_t
	if syscall.Lstat(path, &named) != nil {
		return nil, "", zero, errLabKernelInput
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, "", zero, errLabKernelInput
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var before, after, final syscall.Stat_t
	var fs syscall.Statfs_t
	if syscall.Fstat(fd, &before) != nil || !labKernelSame(named, before) || before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Mode&07777 != mode || before.Uid != 10001 || before.Gid != 10001 || before.Nlink != 1 || before.Size <= 0 || before.Size > limit || syscall.Fstatfs(fd, &fs) != nil || fs.Flags&1 == 0 {
		return nil, "", zero, errLabKernelInput
	}
	h := sha256.New()
	var saved bytes.Buffer
	var w io.Writer = h
	if keep {
		w = io.MultiWriter(h, &saved)
	}
	n, e := io.Copy(w, io.LimitReader(f, limit+1))
	if e != nil || n != before.Size || n > limit || syscall.Fstat(fd, &after) != nil || syscall.Lstat(path, &final) != nil || !labKernelSame(before, after) || !labKernelSame(before, final) || !labKernelPlain(path) {
		return nil, "", zero, errLabKernelInput
	}
	return saved.Bytes(), hex.EncodeToString(h.Sum(nil)), before, nil
}

// Token validation rejects duplicate keys before typed decoding. Typed fields
// reject bool/float aliases for numbers; unknown keys are never ignored.
func labKernelJSON(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errLabKernelInput
		}
		tok, e := d.Token()
		tokens++
		if e != nil || tokens > 4096 {
			return errLabKernelInput
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, e := d.Token()
					s, ok := key.(string)
					if e != nil || !ok || seen[s] {
						return errLabKernelInput
					}
					seen[s] = true
					if value(depth+1) != nil {
						return errLabKernelInput
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return errLabKernelInput
				}
			case '[':
				for d.More() {
					if value(depth+1) != nil {
						return errLabKernelInput
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return errLabKernelInput
				}
			default:
				return errLabKernelInput
			}
		}
		return nil
	}
	if value(0) != nil {
		return errLabKernelInput
	}
	if _, e := d.Token(); e != io.EOF {
		return errLabKernelInput
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return errLabKernelInput
	}
	return nil
}

// encoding/json's struct decoder also accepts case-folded field aliases. The
// receipt wire contract does not: each decoded key must equal its exact JSON
// tag, including every nested object. Do not normalize case or Unicode here.
func labKernelExactKeys(raw json.RawMessage, keys ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != len(keys) {
		return nil, errLabKernelInput
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return nil, errLabKernelInput
		}
	}
	return object, nil
}
func labKernelReceiptKeys(raw []byte) error {
	root, e := labKernelExactKeys(raw, "schema", "state", "source", "component", "version", "upstreamSourceCommit", "archive", "gzip", "elf", "output", "runtimeExecuted", "runtimeCompatibilityProven", "businessAvailabilityProven", "publisherSignatureProven", "productionApproved", "production")
	if e != nil {
		return e
	}
	source, e := labKernelExactKeys(root["source"], "projectSourceCommit", "sourceFiles", "pinSHA256")
	if e != nil {
		return e
	}
	var files []json.RawMessage
	if json.Unmarshal(source["sourceFiles"], &files) != nil {
		return errLabKernelInput
	}
	for _, file := range files {
		if _, e := labKernelExactKeys(file, "path", "bytes", "sha256"); e != nil {
			return e
		}
	}
	if _, e := labKernelExactKeys(root["archive"], "name", "bytes", "sha256", "pinBasis"); e != nil {
		return e
	}
	if _, e := labKernelExactKeys(root["gzip"], "singleMember", "complete", "trailerCRC32", "trailerISIZE"); e != nil {
		return e
	}
	if _, e := labKernelExactKeys(root["elf"], "bytes", "sha256", "byteOrder", "elfClass", "machine", "type", "entryPoint", "programHeaderCount", "loadSegments", "sectionHeaderCount", "executableEntryMapped"); e != nil {
		return e
	}
	if _, e := labKernelExactKeys(root["output"], "path", "mode", "receiptMode", "directoryMode"); e != nil {
		return e
	}
	return nil
}
func labKernelReceiptValid(raw []byte, commit string) (labKernelReceipt, error) {
	var r labKernelReceipt
	if len(raw) == 0 || len(raw) > 256<<10 || labKernelJSON(raw, &r) != nil || labKernelReceiptKeys(raw) != nil || !labKernelCommit.MatchString(commit) || r.Schema != "chengwang.mihomo-candidate-consumption/v1" || r.State != "PINNED_GZIP_EXPANDED_NOT_EXECUTED" || r.Component != "MetaCubeX/mihomo" || r.Version != "v1.19.32" || r.Upstream != labKernelUpstream || r.Source.Commit != commit || !labKernelDigest.MatchString(r.Source.PinSHA256) {
		return r, errLabKernelInput
	}
	for _, p := range []*bool{r.RuntimeExecuted, r.Compatibility, r.Business, r.Signature, r.Approved, r.Production} {
		if p == nil || *p {
			return r, errLabKernelInput
		}
	}
	if r.Archive.Name != "mihomo-linux-amd64-v1-v1.19.32.gz" || r.Archive.SHA256 != labKernelPublished || r.Archive.Bytes < 18 || r.Archive.Bytes > 64<<20 || r.Archive.PinBasis != "PUBLISHED_RELEASE_ASSET_SHA256_NOT_SIGNATURE_APPROVAL" || r.Gzip.Single == nil || !*r.Gzip.Single || r.Gzip.Complete == nil || !*r.Gzip.Complete || len(r.Gzip.CRC) != 8 {
		return r, errLabKernelInput
	}
	if _, e := hex.DecodeString(r.Gzip.CRC); e != nil {
		return r, errLabKernelInput
	}
	if r.ELF.Bytes < 64 || r.ELF.Bytes > 128<<20 || !labKernelDigest.MatchString(r.ELF.SHA256) || r.Gzip.Size != uint64(r.ELF.Bytes) || r.ELF.ByteOrder != "little" || r.ELF.Class != "ELF64" || r.ELF.Machine != "AMD64" || (r.ELF.Type != "EXEC" && r.ELF.Type != "DYN") || r.ELF.Entry == 0 || r.ELF.Programs == 0 || r.ELF.Programs > 1024 || r.ELF.Loads == 0 || r.ELF.Loads > r.ELF.Programs || r.ELF.ExecutableEntry == nil || !*r.ELF.ExecutableEntry {
		return r, errLabKernelInput
	}
	if r.Output.Path != "mihomo" || r.Output.Mode != "0500" || r.Output.ReceiptMode != "0400" || r.Output.DirectoryMode != "0700" {
		return r, errLabKernelInput
	}
	names := []string{"pin.json", "consume_pin.py", "check_consumption.py", "test_consume_pin.py", "README.md"}
	if len(r.Source.Files) != len(names) {
		return r, errLabKernelInput
	}
	for i, f := range r.Source.Files {
		if f.Path != "chengwang/tools/mihomo-runtime-candidate/"+names[i] || f.Bytes <= 0 || f.Bytes > 256<<10 || !labKernelDigest.MatchString(f.SHA256) {
			return r, errLabKernelInput
		}
	}
	if r.Source.Files[0].SHA256 != r.Source.PinSHA256 {
		return r, errLabKernelInput
	}
	return r, nil
}

// The receipt is not a signature. This constructor is valid only inside the
// source-owned worker envelope which independently consumed the pinned gzip.
func openLabKernelInput() (*labKernelInput, error) {
	if os.Getuid() != 10001 || os.Geteuid() != 10001 || os.Getgid() != 10001 || os.Getegid() != 10001 || runtime.GOARCH != "amd64" {
		return nil, errLabKernelInput
	}
	commit := os.Getenv("CHENGWANG_MIHOMO_APPLY_SOURCE_COMMIT")
	if !labKernelCommit.MatchString(commit) {
		return nil, errLabKernelInput
	}
	var parent syscall.Stat_t
	if !labKernelPlain(filepath.Dir(labKernelPath)) || syscall.Lstat(filepath.Dir(labKernelPath), &parent) != nil || parent.Mode&syscall.S_IFMT != syscall.S_IFDIR || parent.Mode&07777 != 0755 || parent.Uid != 0 || parent.Gid != 0 {
		return nil, errLabKernelInput
	}
	raw, rh, rs, e := labKernelFile(labKernelReceiptPath, 256<<10, 0400, true)
	if e != nil {
		return nil, e
	}
	r, e := labKernelReceiptValid(raw, commit)
	if e != nil {
		return nil, e
	}
	_, bh, bs, e := labKernelFile(labKernelPath, 128<<20, 0500, false)
	if e != nil || bh != r.ELF.SHA256 || bs.Size != r.ELF.Bytes {
		return nil, errLabKernelInput
	}
	f, e := os.Open(labKernelPath)
	if e != nil {
		return nil, errLabKernelInput
	}
	ef, e := elf.NewFile(f)
	if e != nil {
		_ = f.Close()
		return nil, errLabKernelInput
	}
	kind := ""
	if ef.Type == elf.ET_EXEC {
		kind = "EXEC"
	}
	if ef.Type == elf.ET_DYN {
		kind = "DYN"
	}
	loads := 0
	mapped := false
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD {
			loads++
			if p.Flags&elf.PF_X != 0 && ef.Entry >= p.Vaddr && ef.Entry-p.Vaddr < p.Filesz {
				mapped = true
			}
		}
	}
	valid := ef.Class == elf.ELFCLASS64 && ef.Data == elf.ELFDATA2LSB && ef.Machine == elf.EM_X86_64 && kind == r.ELF.Type && ef.Entry == r.ELF.Entry && len(ef.Progs) == int(r.ELF.Programs) && len(ef.Sections) == int(r.ELF.Sections) && loads == int(r.ELF.Loads) && mapped
	_ = ef.Close()
	_ = f.Close()
	if !valid {
		return nil, errLabKernelInput
	}
	in := &labKernelInput{&labKernelInputCore{commit: commit, binaryHash: bh, receiptHash: rh, binaryBytes: bs.Size, binaryStat: bs, receiptStat: rs}}
	if in.verify() != nil {
		return nil, errLabKernelInput
	}
	return in, nil
}
func (in *labKernelInput) verify() error {
	if in == nil || in.labKernelInputCore == nil {
		return errLabKernelInput
	}
	_, bh, bs, e := labKernelFile(labKernelPath, 128<<20, 0500, false)
	if e != nil || bh != in.binaryHash || !labKernelSame(bs, in.binaryStat) {
		return errLabKernelInput
	}
	_, rh, rs, e := labKernelFile(labKernelReceiptPath, 256<<10, 0400, false)
	if e != nil || rh != in.receiptHash || !labKernelSame(rs, in.receiptStat) {
		return errLabKernelInput
	}
	return nil
}

type labKernelWriter struct {
	mu       sync.Mutex
	raw      []byte
	hash     hash.Hash
	total    int64
	complete bool
}

func (w *labKernelWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.hash == nil {
		w.hash = sha256.New()
	}
	_, _ = w.hash.Write(p)
	w.total += int64(len(p))
	n := labKernelStreamLimit - len(w.raw)
	if n > len(p) {
		n = len(p)
	}
	if n > 0 {
		w.raw = append(w.raw, p[:n]...)
	}
	return len(p), nil
}
func (w *labKernelWriter) finish(e error) { w.mu.Lock(); w.complete = e == nil; w.mu.Unlock() }
func (w *labKernelWriter) snapshot() ([]byte, labKernelStream) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.hash == nil {
		w.hash = sha256.New()
	}
	return append([]byte(nil), w.raw...), labKernelStream{Bytes: len(w.raw), TotalBytes: w.total, SHA256: hex.EncodeToString(w.hash.Sum(nil)), Truncated: w.total > int64(len(w.raw)), Complete: w.complete}
}

// Dependencies are private per-instance seams. Only tests supply MODEL
// command/input/home functions; there is no global mutable factory or public
// caller-controlled executable/path/PID constructor.
type labKernelOps struct {
	verifyInput func() error
	home        func() (string, error)
	command     func(context.Context, string, []byte) *exec.Cmd
	observe     func(int) (labKernelIdentity, error)
	// MODEL-only scheduling seam: production never supplies a gate. This is
	// not evidence that a real kernel or OS Wait was made to hang.
	waitGate <-chan struct{}
}
type ownedLabKernelCore struct {
	mu                          sync.Mutex
	stopMu                      sync.Mutex
	process                     *os.Process
	input                       *labKernelInput
	ops                         labKernelOps
	bound                       labKernelIdentity
	done                        chan struct{}
	cancel                      context.CancelFunc
	closed                      bool
	startAttempted, startKnown  bool
	captureStarted              bool
	observedPID                 *int
	observedTicks               *uint64
	exit                        labKernelExit
	stdout, stderr              *labKernelWriter
	controllerInode, mixedInode uint64
}

func labKernelNewHome() (string, error) {
	var st syscall.Stat_t
	if !labKernelPlain(labKernelHome) || syscall.Lstat(labKernelHome, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Mode&07777 != 0700 || st.Uid != 10001 || st.Gid != 10001 {
		return "", errLabKernelInput
	}
	h, e := os.MkdirTemp(labKernelHome, "session-")
	if e != nil {
		return "", errLabKernelInput
	}
	if os.Chmod(h, 0700) != nil || os.Mkdir(filepath.Join(h, "tmp"), 0700) != nil {
		return "", errLabKernelInput
	}
	return h, nil
}

// A non-nil handle must always be retained and stopped, including alongside an
// error. The error records execution uncertainty; it does not mean no Start.
func startOwnedLabKernel(ctx context.Context, in *labKernelInput, a *LabConfigArtifact) (*ownedLabKernel, error) {
	if in == nil || in.labKernelInputCore == nil {
		return nil, errLabKernelInput
	}
	ops := labKernelOps{verifyInput: in.verify, home: labKernelNewHome}
	ops.command = func(ctx context.Context, home string, raw []byte) *exec.Cmd {
		cmd := exec.CommandContext(ctx, labKernelPath, "-d", home, "-f", "-")
		cmd.Stdin = bytes.NewReader(raw)
		cmd.Dir = home
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "TMPDIR=" + filepath.Join(home, "tmp"), "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"}
		return cmd
	}
	ops.observe = func(pid int) (labKernelIdentity, error) { return labKernelObserve(pid, in) }
	return startLabKernelWith(ctx, in, a, ops)
}
func startLabKernelWith(ctx context.Context, in *labKernelInput, a *LabConfigArtifact, ops labKernelOps) (*ownedLabKernel, error) {
	if ctx == nil || ctx.Err() != nil || in == nil || in.labKernelInputCore == nil || a == nil || a.AdmissionError() != nil || ops.verifyInput == nil || ops.home == nil || ops.command == nil || ops.observe == nil || ops.verifyInput() != nil {
		return nil, errLabKernelInput
	}
	raw := a.Bytes()
	desc := a.Descriptor()
	if len(raw) == 0 || len(raw) != desc.Bytes || labConfigHash(raw) != desc.SHA256 {
		return nil, errLabKernelInput
	}
	var cfg labRawConfig
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if d.Decode(&cfg) != nil || d.Decode(&struct{}{}) != io.EOF || cfg.MixedPort < 1024 || cfg.Mode != "rule" || cfg.BindAddress != "127.0.0.1" {
		return nil, errLabKernelInput
	}
	_, port, found := strings.Cut(cfg.ExternalController, "127.0.0.1:")
	p, pe := strconv.ParseUint(port, 10, 16)
	if !found || pe != nil || p < 1024 || uint16(p) == cfg.MixedPort || cfg.ExternalController != "127.0.0.1:"+strconv.FormatUint(p, 10) {
		return nil, errLabKernelInput
	}
	home, e := ops.home()
	if e != nil {
		return nil, errLabKernelInput
	}
	session, cancel := context.WithCancel(ctx)
	c := &ownedLabKernelCore{input: in, ops: ops, done: make(chan struct{}), cancel: cancel, stdout: &labKernelWriter{}, stderr: &labKernelWriter{}, exit: labKernelExit{WaitErrorClass: "NOT_WAITED"}}
	k := &ownedLabKernel{c}
	ready := make(chan error, 1)
	go c.run(session, home, raw, labKernelIdentity{SourceCommit: in.commit, ArtifactSHA256: desc.SHA256, ControllerPort: uint16(p), MixedPort: cfg.MixedPort}, ready)
	budget := time.NewTimer(5 * time.Second)
	defer budget.Stop()
	select {
	case e := <-ready:
		if e == nil {
			return k, nil
		}
		failure := &labKernelStartError{&labKernelStartErrorCore{kernel: k}}
		obs := failure.observation()
		if obs.Started != nil && !*obs.Started {
			return nil, failure
		}
		return k, failure
	case <-ctx.Done():
		cancel()
		return k, &labKernelStartError{&labKernelStartErrorCore{kernel: k}}
	case <-budget.C:
		cancel()
		return k, &labKernelStartError{&labKernelStartErrorCore{kernel: k}}
	}
}
func (c *ownedLabKernelCore) run(ctx context.Context, home string, raw []byte, want labKernelIdentity, ready chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(c.done)
	defer c.cancel()
	cmd := c.ops.command(ctx, home, raw)
	if cmd == nil {
		c.mu.Lock()
		c.startKnown = true
		c.mu.Unlock()
		ready <- errLabKernelStart
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = time.Second
	// os.Process owns Go's pidfd (when available) or its synchronized PID
	// fallback. Never use FindProcess, Release, or a numeric group kill.
	cmd.Cancel = func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		p := c.process
		if p == nil {
			p = cmd.Process
		}
		if p == nil {
			return os.ErrProcessDone
		}
		labNativeRecoveryObserveCancelKillAttempt(c)
		e := p.Kill()
		labNativeRecoveryObserveCancelKillReturn(c)
		if e == nil {
			c.exit.KillSent = true
		}
		return e
	}
	or, ow, e := os.Pipe()
	if e != nil {
		c.mu.Lock()
		c.startKnown = true
		c.mu.Unlock()
		ready <- errLabKernelStart
		return
	}
	er, ew, e := os.Pipe()
	if e != nil {
		_ = or.Close()
		_ = ow.Close()
		c.mu.Lock()
		c.startKnown = true
		c.mu.Unlock()
		ready <- errLabKernelStart
		return
	}
	cmd.Stdout = ow
	cmd.Stderr = ew
	readers := make(chan struct{}, 2)
	c.mu.Lock()
	c.captureStarted = true
	c.mu.Unlock()
	for _, pair := range []struct {
		f *os.File
		w *labKernelWriter
	}{{or, c.stdout}, {er, c.stderr}} {
		go func(f *os.File, w *labKernelWriter) {
			_, e := io.Copy(w, f)
			w.finish(e)
			_ = f.Close()
			readers <- struct{}{}
		}(pair.f, pair.w)
	}
	c.mu.Lock()
	c.startAttempted = true
	c.mu.Unlock()
	labNativeRecoveryObserve(c, "KERNEL_OS_START_ATTEMPT")
	e = cmd.Start()
	labNativeRecoveryObserve(c, "KERNEL_OS_START_RETURN")
	_ = ow.Close()
	_ = ew.Close()
	if e != nil {
		c.mu.Lock()
		c.startKnown = true
		c.mu.Unlock()
		_ = or.SetReadDeadline(time.Now().Add(time.Second))
		_ = er.SetReadDeadline(time.Now().Add(time.Second))
		<-readers
		<-readers
		ready <- errLabKernelStart
		return
	}
	c.mu.Lock()
	c.startKnown = true
	c.process = cmd.Process
	c.exit.Started = true
	pid := cmd.Process.Pid
	c.observedPID = &pid
	c.mu.Unlock()
	measured, observeErr := c.ops.observe(cmd.Process.Pid)
	if observeErr == nil && measured.StartTicks > 0 {
		c.mu.Lock()
		ticks := measured.StartTicks
		c.observedTicks = &ticks
		c.mu.Unlock()
	}
	if observeErr == nil && ctx.Err() == nil && measured.PID == cmd.Process.Pid && measured.StartTicks > 0 && measured.NetNSInode > 0 && measured.ELFSHA256 == c.input.binaryHash && measured.ELFBytes == c.input.binaryBytes && c.ops.verifyInput() == nil {
		measured.SourceCommit = want.SourceCommit
		measured.ArtifactSHA256 = want.ArtifactSHA256
		measured.ControllerPort = want.ControllerPort
		measured.MixedPort = want.MixedPort
		c.mu.Lock()
		c.bound = measured
		c.mu.Unlock()
		ready <- nil
	} else {
		c.mu.Lock()
		labNativeRecoveryObserveIdentityKillAttempt(c)
		killErr := c.process.Kill()
		labNativeRecoveryObserveIdentityKillReturn(c)
		if killErr == nil {
			c.exit.KillSent = true
		}
		c.mu.Unlock()
		observeErr = errLabKernelIdentity
		ready <- errLabKernelIdentity
	}
	if c.ops.waitGate != nil {
		<-c.ops.waitGate
	}
	labNativeRecoveryObserve(c, "KERNEL_OS_WAIT_ENTER")
	waitErr := cmd.Wait()
	labNativeRecoveryObserve(c, "KERNEL_OS_WAIT_RETURN")
	c.mu.Lock()
	c.exit.WaitReturned = true
	c.exit.WaitErrorClass = "NONE"
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			c.exit.WaitErrorClass = "EXIT_STATUS"
		} else {
			c.exit.WaitErrorClass = "WAIT_ERROR"
		}
	}
	if cmd.ProcessState != nil {
		if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				sig := int(status.Signal())
				c.exit.Signal = &sig
			} else {
				code := status.ExitStatus()
				c.exit.ExitCode = &code
			}
		}
	}
	c.mu.Unlock()
	// These are our pipes, not exec's hidden copier goroutines. EOF is measured;
	// a descendant keeping a pipe open results in incomplete metadata, not an
	// invented complete stream. No process group signal is used to "fix" it.
	_ = or.SetReadDeadline(time.Now().Add(time.Second))
	_ = er.SetReadDeadline(time.Now().Add(time.Second))
	<-readers
	<-readers
	_, out := c.stdout.snapshot()
	_, errout := c.stderr.snapshot()
	c.mu.Lock()
	c.exit.Stdout = out
	c.exit.Stderr = errout
	if e := syscall.Kill(-cmd.Process.Pid, 0); e == syscall.ESRCH {
		v := true
		c.exit.GroupAbsent = &v
	} else if e == nil {
		v := false
		c.exit.GroupAbsent = &v
	}
	c.mu.Unlock()
}

func labKernelProcStat(raw []byte, pid int) (uint64, int, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return 0, 0, errLabKernelIdentity
	}
	text := string(raw)
	open, close := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if open <= 0 || close <= open {
		return 0, 0, errLabKernelIdentity
	}
	p, e := strconv.Atoi(strings.TrimSpace(text[:open]))
	fields := strings.Fields(text[close+1:])
	if e != nil || p != pid || len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return 0, 0, errLabKernelIdentity
	}
	ticks, e := strconv.ParseUint(fields[19], 10, 63)
	group, ge := strconv.Atoi(fields[2])
	if e != nil || ge != nil || ticks == 0 || group != pid {
		return 0, 0, errLabKernelIdentity
	}
	return ticks, group, nil
}
func labKernelRead(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errLabKernelIdentity
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errLabKernelIdentity
	}
	return b, nil
}
func labKernelNS(path string) (uint64, error) {
	s, e := os.Readlink(path)
	if e != nil || !strings.HasPrefix(s, "net:[") || !strings.HasSuffix(s, "]") {
		return 0, errLabKernelIdentity
	}
	n, e := strconv.ParseUint(s[5:len(s)-1], 10, 63)
	if e != nil || n == 0 {
		return 0, errLabKernelIdentity
	}
	return n, nil
}
func labKernelObserve(pid int, in *labKernelInput) (labKernelIdentity, error) {
	var zero labKernelIdentity
	if pid < 2 || in == nil || in.labKernelInputCore == nil {
		return zero, errLabKernelIdentity
	}
	prefix := "/proc/" + strconv.Itoa(pid)
	raw, e := labKernelRead(prefix+"/stat", 4096)
	if e != nil {
		return zero, e
	}
	ticks, _, e := labKernelProcStat(raw, pid)
	if e != nil {
		return zero, e
	}
	ns, e := labKernelNS(prefix + "/ns/net")
	self, se := labKernelNS("/proc/self/ns/net")
	if e != nil || se != nil || ns != self {
		return zero, errLabKernelIdentity
	}
	f, e := os.Open(prefix + "/exe")
	if e != nil {
		return zero, errLabKernelIdentity
	}
	var before, after syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &before) != nil || !labKernelSame(before, in.binaryStat) {
		_ = f.Close()
		return zero, errLabKernelIdentity
	}
	h := sha256.New()
	count, e := io.Copy(h, io.LimitReader(f, 128<<20+1))
	statErr := syscall.Fstat(int(f.Fd()), &after)
	closeErr := f.Close()
	if e != nil || statErr != nil || closeErr != nil || !labKernelSame(before, after) || count != in.binaryBytes || hex.EncodeToString(h.Sum(nil)) != in.binaryHash {
		return zero, errLabKernelIdentity
	}
	last, e := labKernelRead(prefix+"/stat", 4096)
	if e != nil {
		return zero, e
	}
	again, _, e := labKernelProcStat(last, pid)
	endNS, ne := labKernelNS(prefix + "/ns/net")
	if e != nil || ne != nil || again != ticks || endNS != ns {
		return zero, errLabKernelIdentity
	}
	return labKernelIdentity{PID: pid, StartTicks: ticks, NetNSInode: ns, ELFSHA256: in.binaryHash, ELFBytes: in.binaryBytes}, nil
}
func (k *ownedLabKernel) identity() (labKernelIdentity, error) {
	if k == nil || k.ownedLabKernelCore == nil {
		return labKernelIdentity{}, errLabKernelClosed
	}
	c := k.ownedLabKernelCore
	c.mu.Lock()
	if c.closed || c.process == nil {
		c.mu.Unlock()
		return labKernelIdentity{}, errLabKernelClosed
	}
	want := c.bound
	// A retained cleanup handle is not an established identity. In particular,
	// initial observation failure leaves bound zero: never probe PID 0 or try
	// to reconstruct authority by asking the observer to fill missing fields.
	if c.input == nil || c.input.labKernelInputCore == nil || c.done == nil || c.cancel == nil ||
		c.stdout == nil || c.stderr == nil || c.ops.verifyInput == nil || c.ops.observe == nil ||
		c.ops.home == nil || c.ops.command == nil || !c.startAttempted || !c.startKnown || !c.exit.Started || c.exit.WaitReturned ||
		want.PID < 2 || want.PID > 1<<31-1 || want.PID != c.process.Pid ||
		c.observedPID == nil || *c.observedPID != want.PID ||
		want.StartTicks == 0 || want.StartTicks > 1<<63-1 || c.observedTicks == nil || *c.observedTicks != want.StartTicks ||
		want.NetNSInode == 0 || want.NetNSInode > 1<<63-1 ||
		!labKernelDigest.MatchString(want.ELFSHA256) || want.ELFSHA256 == strings.Repeat("0", 64) ||
		want.ELFSHA256 != c.input.binaryHash || want.ELFBytes < 64 || want.ELFBytes > 128<<20 || want.ELFBytes != c.input.binaryBytes ||
		!labKernelCommit.MatchString(want.SourceCommit) || want.SourceCommit == strings.Repeat("0", 40) || want.SourceCommit != c.input.commit ||
		!labKernelDigest.MatchString(want.ArtifactSHA256) || want.ArtifactSHA256 == strings.Repeat("0", 64) ||
		want.ControllerPort < 1024 || want.MixedPort < 1024 || want.ControllerPort == want.MixedPort {
		c.mu.Unlock()
		return labKernelIdentity{}, errLabKernelIdentity
	}
	c.mu.Unlock()
	select {
	case <-c.done:
		return labKernelIdentity{}, errLabKernelClosed
	default:
	}
	if c.ops.verifyInput() == nil {
		got, e := c.ops.observe(want.PID)
		if e == nil && got.PID == want.PID && got.StartTicks == want.StartTicks && got.NetNSInode == want.NetNSInode && got.ELFSHA256 == want.ELFSHA256 && got.ELFBytes == want.ELFBytes {
			c.mu.Lock()
			closed := c.closed || c.exit.WaitReturned
			c.mu.Unlock()
			if closed {
				return labKernelIdentity{}, errLabKernelClosed
			}
			select {
			case <-c.done:
				return labKernelIdentity{}, errLabKernelClosed
			default:
				return want, nil
			}
		}
	}
	return labKernelIdentity{}, errLabKernelIdentity
}
func labKernelSockets(pid int) (map[uint64]bool, error) {
	base := "/proc/" + strconv.Itoa(pid) + "/fd"
	entries, e := os.ReadDir(base)
	if e != nil || len(entries) > 4096 {
		return nil, errLabKernelListeners
	}
	out := map[uint64]bool{}
	for _, entry := range entries {
		s, e := os.Readlink(base + "/" + entry.Name())
		if e != nil {
			continue
		}
		if strings.HasPrefix(s, "socket:[") && strings.HasSuffix(s, "]") {
			n, e := strconv.ParseUint(s[8:len(s)-1], 10, 64)
			if e != nil || n == 0 {
				return nil, errLabKernelListeners
			}
			out[n] = true
		}
	}
	return out, nil
}
func labKernelTCP(raw []byte, owned map[uint64]bool, controller, mixed uint16, ipv6 bool) (map[uint16]uint64, error) {
	if len(raw) > 2<<20 {
		return nil, errLabKernelListeners
	}
	found := map[uint16]uint64{}
	for i, line := range strings.Split(string(raw), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 10 {
			return nil, errLabKernelListeners
		}
		if f[3] != "0A" {
			continue
		}
		parts := strings.Split(f[1], ":")
		if len(parts) != 2 {
			return nil, errLabKernelListeners
		}
		p, e := strconv.ParseUint(parts[1], 16, 16)
		if e != nil {
			return nil, errLabKernelListeners
		}
		if uint16(p) != controller && uint16(p) != mixed {
			continue
		}
		inode, e := strconv.ParseUint(f[9], 10, 64)
		if e != nil {
			return nil, errLabKernelListeners
		}
		if !owned[inode] {
			continue
		}
		if ipv6 || parts[0] != "0100007F" || found[uint16(p)] != 0 {
			return nil, errLabKernelListeners
		}
		found[uint16(p)] = inode
	}
	return found, nil
}
func (k *ownedLabKernel) verifyListeners() error {
	id, e := k.identity()
	if e != nil {
		return e
	}
	before, e := labKernelSockets(id.PID)
	if e != nil {
		return e
	}
	prefix := "/proc/" + strconv.Itoa(id.PID) + "/net/"
	tcp, e := labKernelRead(prefix+"tcp", 2<<20)
	if e != nil {
		return errLabKernelListeners
	}
	found, e := labKernelTCP(tcp, before, id.ControllerPort, id.MixedPort, false)
	if e != nil {
		return e
	}
	// tcp6 may be absent when IPv6 is disabled in this namespace.
	if _, statErr := os.Stat(prefix + "tcp6"); statErr == nil {
		raw, e := labKernelRead(prefix+"tcp6", 2<<20)
		if e != nil {
			return errLabKernelListeners
		}
		if _, e = labKernelTCP(raw, before, id.ControllerPort, id.MixedPort, true); e != nil {
			return e
		}
	} else if !os.IsNotExist(statErr) {
		return errLabKernelListeners
	}
	if found[id.ControllerPort] == 0 || found[id.MixedPort] == 0 || found[id.ControllerPort] == found[id.MixedPort] {
		return errLabKernelListeners
	}
	after, e := labKernelSockets(id.PID)
	if e != nil || !after[found[id.ControllerPort]] || !after[found[id.MixedPort]] {
		return errLabKernelListeners
	}
	end, e := k.identity()
	if e != nil || end != id {
		return errLabKernelListeners
	}
	k.mu.Lock()
	k.controllerInode = found[id.ControllerPort]
	k.mixedInode = found[id.MixedPort]
	k.mu.Unlock()
	return nil
}
func labKernelCopyExit(v labKernelExit) labKernelExit {
	if v.ExitCode != nil {
		n := *v.ExitCode
		v.ExitCode = &n
	}
	if v.Signal != nil {
		n := *v.Signal
		v.Signal = &n
	}
	if v.GroupAbsent != nil {
		n := *v.GroupAbsent
		v.GroupAbsent = &n
	}
	return v
}
func (k *ownedLabKernel) stop(ctx context.Context) (labKernelExit, error) {
	if k == nil || k.ownedLabKernelCore == nil || ctx == nil {
		return labKernelExit{}, errLabKernelClosed
	}
	c := k.ownedLabKernelCore
	labNativeRecoveryObserve(c, "OWNED_STOP_HELPER_ENTER")
	c.stopMu.Lock()
	defer c.stopMu.Unlock()
	c.mu.Lock()
	c.closed = true
	proc := c.process
	cancel := c.cancel
	c.mu.Unlock()
	if proc == nil {
		if cancel != nil {
			cancel()
		}
		return labKernelExit{}, errLabKernelStop
	}
	select {
	case <-c.done:
		return c.exitSnapshot()
	default:
	}
	// Signal only the original os.Process object. Go's pidfd/sigMu/status
	// synchronizes it with the single Wait, avoiding naked PID/PGID reuse.
	c.mu.Lock()
	labNativeRecoveryObserve(c, "KERNEL_OS_TERM_ATTEMPT")
	e := proc.Signal(syscall.SIGTERM)
	labNativeRecoveryObserve(c, "KERNEL_OS_TERM_RETURN")
	if e == nil {
		c.exit.TermSent = true
	}
	c.mu.Unlock()
	grace := time.NewTimer(250 * time.Millisecond)
	select {
	case <-c.done:
		if !grace.Stop() {
			select {
			case <-grace.C:
			default:
			}
		}
		return c.exitSnapshot()
	case <-grace.C:
	case <-ctx.Done():
		if !grace.Stop() {
			select {
			case <-grace.C:
			default:
			}
		}
	}
	c.mu.Lock()
	labNativeRecoveryObserveStopKillAttempt(c)
	e = proc.Kill()
	labNativeRecoveryObserveStopKillReturn(c)
	if e == nil {
		c.exit.KillSent = true
	}
	c.mu.Unlock()
	limit := time.NewTimer(1500 * time.Millisecond)
	defer limit.Stop()
	select {
	case <-c.done:
		return c.exitSnapshot()
	case <-limit.C:
		c.mu.Lock()
		out := labKernelCopyExit(c.exit)
		c.mu.Unlock()
		_, out.Stdout = c.stdout.snapshot()
		_, out.Stderr = c.stderr.snapshot()
		return out, errLabKernelStop
	}
}
func (c *ownedLabKernelCore) exitSnapshot() (labKernelExit, error) {
	c.mu.Lock()
	v := labKernelCopyExit(c.exit)
	c.mu.Unlock()
	if !v.WaitReturned || v.WaitErrorClass == "WAIT_ERROR" || !v.Stdout.Complete || !v.Stderr.Complete || v.Stdout.Truncated || v.Stderr.Truncated || v.GroupAbsent == nil || !*v.GroupAbsent {
		return v, errLabKernelStop
	}
	return v, nil
}

func (k *ownedLabKernel) startObservation() labKernelStartObservation {
	if k == nil || k.ownedLabKernelCore == nil {
		return labKernelStartObservation{}
	}
	c := k.ownedLabKernelCore
	c.mu.Lock()
	exit := labKernelCopyExit(c.exit)
	v := labKernelStartObservation{Attempted: c.startAttempted, WaitErrorClass: exit.WaitErrorClass, ExitCode: exit.ExitCode, Signal: exit.Signal, GroupAbsent: exit.GroupAbsent}
	if c.startKnown {
		known, waited := exit.Started, exit.WaitReturned
		v.Started = &known
		v.WaitReturned = &waited
	}
	if c.observedPID != nil {
		pid := *c.observedPID
		v.PID = &pid
		term, killed := exit.TermSent, exit.KillSent
		v.TermSent = &term
		v.KillSent = &killed
	}
	if c.observedTicks != nil {
		ticks := *c.observedTicks
		v.StartTicks = &ticks
	}
	captured := c.captureStarted
	c.mu.Unlock()
	if captured {
		_, stdout := c.stdout.snapshot()
		_, stderr := c.stderr.snapshot()
		v.Stdout = &stdout
		v.Stderr = &stderr
	}
	return v
}
