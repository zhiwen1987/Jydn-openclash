// Package restoreevidence persists already-collected restore evidence without
// interpreting it as authorization to perform a restore. Linux publication is
// fail-closed and no-clobber. Other platforms may expose diagnostic reads, but
// never claim durable publication.
package restoreevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"chengwang/internal/restorecontracts"
)

const (
	defaultMaxBoottimeAge = 30 * time.Second
	maximumBoottimeAge    = 5 * time.Minute
	maxDirectoryEntries   = 4096
)

var (
	ErrUnsupported      = errors.New("reliable restore evidence persistence is unsupported on this platform")
	ErrAlreadyExists    = errors.New("restore evidence already exists")
	ErrUnsafeObject     = errors.New("unsafe restore evidence filesystem object")
	ErrTooLarge         = errors.New("restore evidence exceeds size limit")
	ErrDigestMismatch   = errors.New("restore evidence raw digest mismatch")
	ErrClockRollback    = errors.New("restore evidence clock rollback detected")
	ErrBootMismatch     = errors.New("restore evidence boot identity mismatch")
	ErrClosed           = errors.New("restore evidence store is closed")
	ErrPoisoned         = errors.New("restore evidence store is fail-closed after uncertain or conflicting publication")
	ErrConflict         = errors.New("restore evidence key already contains different bytes")
	ErrLocked           = errors.New("restore evidence store already has an active writer")
	ErrNoClobberMissing = errors.New("atomic no-clobber publication is unsupported")
	ErrInvalidClock     = errors.New("invalid restore evidence clock snapshot")
	ErrDirectoryLimit   = errors.New("restore evidence directory entry limit exceeded")
)

type clockSnapshot struct {
	Wall       time.Time
	BootID     string
	BoottimeNS uint64
}

type clockFunc func() (clockSnapshot, error)

type faultStage string

const (
	faultBeforeTempCreate            faultStage = "before-temp-create"
	faultAfterTempCreate             faultStage = "after-temp-create"
	faultBeforeWrite                 faultStage = "before-write"
	faultAfterWrite                  faultStage = "after-write"
	faultBeforeTempFileFsync         faultStage = "before-temp-file-fsync"
	faultAfterTempFileFsync          faultStage = "after-temp-file-fsync"
	faultBeforeTempDirectoryFsync    faultStage = "before-temp-directory-fsync"
	faultAfterTempDirectoryFsync     faultStage = "after-temp-directory-fsync"
	faultBeforeLink                  faultStage = "before-link"
	faultAfterLink                   faultStage = "after-link"
	faultBeforePublishedFileFsync    faultStage = "before-published-file-fsync"
	faultAfterPublishedFileFsync     faultStage = "after-published-file-fsync"
	faultBeforeCommitDirectoryFsync  faultStage = "before-commit-directory-fsync"
	faultAfterCommitDirectoryFsync   faultStage = "after-commit-directory-fsync"
	faultBeforeTempUnlink            faultStage = "before-temp-unlink"
	faultAfterTempUnlink             faultStage = "after-temp-unlink"
	faultBeforeCleanupDirectoryFsync faultStage = "before-cleanup-directory-fsync"
	faultAfterCleanupDirectoryFsync  faultStage = "after-cleanup-directory-fsync"
	faultBeforeReadback              faultStage = "before-readback"
	faultAfterReadback               faultStage = "after-readback"
)

var allFaultStages = []faultStage{
	faultBeforeTempCreate, faultAfterTempCreate, faultBeforeWrite, faultAfterWrite,
	faultBeforeTempFileFsync, faultAfterTempFileFsync,
	faultBeforeTempDirectoryFsync, faultAfterTempDirectoryFsync,
	faultBeforeLink, faultAfterLink,
	faultBeforePublishedFileFsync, faultAfterPublishedFileFsync,
	faultBeforeCommitDirectoryFsync, faultAfterCommitDirectoryFsync,
	faultBeforeTempUnlink, faultAfterTempUnlink,
	faultBeforeCleanupDirectoryFsync, faultAfterCleanupDirectoryFsync,
	faultBeforeReadback, faultAfterReadback,
}

type faultInjector func(faultStage) error

type storeOptions struct {
	clock          clockFunc
	maxBytes       int
	maxBoottimeAge time.Duration
	fault          faultInjector
}

type Reliability string

const (
	ReliabilityLinuxDurable Reliability = "LINUX_DURABLE"
	ReliabilityDiagnostic   Reliability = "DIAGNOSTIC_ONLY"
)

type CommitState string

const (
	NotCommitted CommitState = "NOT_COMMITTED"
	Committed    CommitState = "COMMITTED"
	Uncertain    CommitState = "UNCERTAIN"
)

// Result is immutable from the caller's perspective. Evidence returns a copy.
type Result struct {
	parsed      restorecontracts.ParsedEvidence
	name        string
	digest      string
	size        int
	device      uint64
	inode       uint64
	mount       uint64
	reliability Reliability
	commitState CommitState
	raw         []byte
}

func (r Result) Evidence() restorecontracts.ParsedEvidence { return r.parsed }
func (r Result) Name() string                              { return r.name }
func (r Result) RawSHA256() string                         { return r.digest }
func (r Result) Size() int                                 { return r.size }
func (r Result) Device() uint64                            { return r.device }
func (r Result) Inode() uint64                             { return r.inode }
func (r Result) MountID() uint64                           { return r.mount }
func (r Result) Reliability() Reliability                  { return r.reliability }
func (r Result) CommitState() CommitState                  { return r.commitState }
func (r Result) RawBytes() []byte                          { return append([]byte(nil), r.raw...) }

// DiagnosticResult is deliberately a different type from Result. It exposes
// validated bytes for investigation but has no commit-state API and therefore
// cannot be passed off as a durable local publication result.
type DiagnosticResult struct{ result Result }

func (r DiagnosticResult) Evidence() restorecontracts.ParsedEvidence { return r.result.parsed }
func (r DiagnosticResult) Name() string                              { return r.result.name }
func (r DiagnosticResult) RawSHA256() string                         { return r.result.digest }
func (r DiagnosticResult) Size() int                                 { return r.result.size }
func (r DiagnosticResult) Device() uint64                            { return r.result.device }
func (r DiagnosticResult) Inode() uint64                             { return r.result.inode }
func (r DiagnosticResult) MountID() uint64                           { return r.result.mount }
func (r DiagnosticResult) Reliability() Reliability                  { return ReliabilityDiagnostic }
func (r DiagnosticResult) RawBytes() []byte                          { return r.result.RawBytes() }

type Store struct {
	mu             sync.Mutex
	platform       *platformStore
	clock          clockFunc
	maxBytes       int
	maxBoottimeAge time.Duration
	fault          faultInjector
	lastClock      *clockSnapshot
	closed         bool
	poisoned       error
}

func Open(dir string) (*Store, error) {
	return openWithOptions(dir, storeOptions{})
}

func openWithOptions(dir string, options storeOptions) (*Store, error) {
	if options.maxBytes == 0 {
		options.maxBytes = restorecontracts.MaxDocumentBytes
	}
	if options.maxBytes < 1 || options.maxBytes > restorecontracts.MaxDocumentBytes {
		return nil, fmt.Errorf("max bytes must be in [1,%d]", restorecontracts.MaxDocumentBytes)
	}
	if options.maxBoottimeAge == 0 {
		options.maxBoottimeAge = defaultMaxBoottimeAge
	}
	if options.maxBoottimeAge < time.Nanosecond || options.maxBoottimeAge > maximumBoottimeAge {
		return nil, fmt.Errorf("max boottime age must be in [1ns,%s]", maximumBoottimeAge)
	}
	p, err := openPlatformStore(dir)
	if err != nil {
		return nil, err
	}
	clock := options.clock
	if clock == nil {
		clock = platformClock
	}
	return &Store{platform: p, clock: clock, maxBytes: options.maxBytes, maxBoottimeAge: options.maxBoottimeAge, fault: options.fault}, nil
}

func (s *Store) Close() error {
	if s == nil {
		return ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.platform == nil {
		return ErrClosed
	}
	return s.platform.close()
}

// Publish validates the exact raw bytes against independently observed Linux
// clock/boot context, then performs an atomic no-clobber publication.
func (s *Store) Publish(raw []byte, expected restorecontracts.EvidenceContext) (out Result, retErr error) {
	defer func() {
		if out.commitState == "" {
			out.commitState = NotCommitted
			out.raw = append([]byte(nil), raw...)
			out.size = len(raw)
			if len(raw) > 0 {
				out.digest = sha256Hex(raw)
			}
		}
	}()
	if s == nil {
		return Result{}, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return Result{}, err
	}
	if len(raw) == 0 || len(raw) > s.maxBytes {
		return Result{}, ErrTooLarge
	}
	digest := sha256Hex(raw)
	if expected.RawBytesSHA256 != digest {
		return Result{}, ErrDigestMismatch
	}
	now, err := s.observeClock()
	if err != nil {
		return Result{}, err
	}
	expected = bindClock(expected, now, s.maxBoottimeAge)
	parsed, err := restorecontracts.ParseRestoreEvidenceV1(raw, expected)
	if err != nil {
		return Result{}, err
	}
	name := evidenceName(parsed)
	published, err := s.platform.publish(name, raw, s.maxBytes, s.inject)
	if err != nil {
		partial := result(parsed, name, raw, published.meta, ReliabilityLinuxDurable, published.state)
		if errors.Is(err, ErrAlreadyExists) {
			if published.poison {
				s.poisoned = err
				return partial, err
			}
			existingMeta, existing, readErr := s.platform.read(name, s.maxBytes)
			if readErr == nil && existingMeta.digest == digest && bytes.Equal(existing, raw) {
				return result(parsed, name, existing, existingMeta, ReliabilityLinuxDurable, Committed), nil
			}
			conflict := errors.Join(ErrConflict, err, readErr)
			s.poisoned = conflict
			return partial, conflict
		}
		if published.state == Uncertain || published.poison {
			s.poisoned = err
		}
		return partial, err
	}
	meta := published.meta
	if meta.digest != digest || meta.size != len(raw) {
		s.poisoned = ErrDigestMismatch
		return result(parsed, name, raw, meta, ReliabilityLinuxDurable, Uncertain), ErrDigestMismatch
	}
	return result(parsed, name, raw, meta, ReliabilityLinuxDurable, Committed), nil
}

// Read validates a Linux-persisted document using independently observed time.
// It does not exist as a reliable operation on platforms without durable writes.
func (s *Store) Read(expected restorecontracts.EvidenceContext) (Result, error) {
	if s == nil {
		return Result{}, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readable(); err != nil {
		return Result{}, err
	}
	if !s.platform.durableWrites() {
		return Result{}, ErrUnsupported
	}
	now, err := s.observeClock()
	if err != nil {
		return Result{}, err
	}
	expected = bindClock(expected, now, s.maxBoottimeAge)
	return s.readWithContext(expected, ReliabilityLinuxDurable)
}

// ReadDiagnostic uses caller-supplied time and boot context. The result is
// deliberately marked DIAGNOSTIC_ONLY and must not authorize restore actions.
func (s *Store) ReadDiagnostic(expected restorecontracts.EvidenceContext) (DiagnosticResult, error) {
	if s == nil {
		return DiagnosticResult{}, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readable(); err != nil {
		return DiagnosticResult{}, err
	}
	result, err := s.readWithContext(expected, ReliabilityDiagnostic)
	if err != nil {
		return DiagnosticResult{}, err
	}
	return DiagnosticResult{result: result}, nil
}

func (s *Store) readWithContext(expected restorecontracts.EvidenceContext, reliability Reliability) (Result, error) {
	name, err := evidenceNameFromContext(expected)
	if err != nil {
		return Result{}, err
	}
	meta, raw, err := s.platform.read(name, s.maxBytes)
	if err != nil {
		return Result{}, err
	}
	digest := sha256Hex(raw)
	if expected.RawBytesSHA256 != digest || meta.digest != digest {
		return Result{}, ErrDigestMismatch
	}
	parsed, err := restorecontracts.ParseRestoreEvidenceV1(raw, expected)
	if err != nil {
		return Result{}, err
	}
	if evidenceName(parsed) != name {
		return Result{}, ErrDigestMismatch
	}
	return result(parsed, name, raw, meta, reliability, Committed), nil
}

func (s *Store) writable() error {
	if err := s.readable(); err != nil {
		return err
	}
	if !s.platform.durableWrites() {
		return ErrUnsupported
	}
	return nil
}

func (s *Store) readable() error {
	if s.closed || s.platform == nil {
		return ErrClosed
	}
	if s.poisoned != nil {
		return errors.Join(ErrPoisoned, s.poisoned)
	}
	return nil
}

func (s *Store) observeClock() (clockSnapshot, error) {
	if s.clock == nil {
		return clockSnapshot{}, ErrInvalidClock
	}
	now, err := s.clock()
	if err != nil {
		return clockSnapshot{}, err
	}
	if now.Wall.IsZero() || now.BootID == "" || now.BoottimeNS == 0 {
		return clockSnapshot{}, ErrInvalidClock
	}
	now.Wall = now.Wall.UTC()
	if s.lastClock != nil {
		if now.BootID != s.lastClock.BootID {
			return clockSnapshot{}, ErrBootMismatch
		}
		if now.Wall.Before(s.lastClock.Wall) || now.BoottimeNS < s.lastClock.BoottimeNS {
			return clockSnapshot{}, ErrClockRollback
		}
	}
	copy := now
	s.lastClock = &copy
	return now, nil
}

func bindClock(c restorecontracts.EvidenceContext, now clockSnapshot, maxAge time.Duration) restorecontracts.EvidenceContext {
	c.Now = now.Wall
	c.BootID = now.BootID
	c.CurrentBoottimeNS = now.BoottimeNS
	c.MaxBoottimeAgeNS = uint64(maxAge)
	return c
}

func evidenceName(parsed restorecontracts.ParsedEvidence) string {
	v := parsed.Snapshot()
	return fmt.Sprintf("%s.%020d.%s.json", v.OperationID, v.TransitionSequence, v.Kind)
}

func evidenceNameFromContext(c restorecontracts.EvidenceContext) (string, error) {
	if c.OperationID == "" || c.Kind == "" || c.TransitionSequence == 0 {
		return "", errors.New("evidence identity context is incomplete")
	}
	// The strict contract parser is the final authority. This precheck only
	// prevents separators from ever reaching an *at syscall.
	for _, value := range []string{c.OperationID, c.Kind} {
		for _, ch := range value {
			if ch == '/' || ch == '\\' || ch == 0 {
				return "", ErrUnsafeObject
			}
		}
	}
	return fmt.Sprintf("%s.%020d.%s.json", c.OperationID, c.TransitionSequence, c.Kind), nil
}

func result(parsed restorecontracts.ParsedEvidence, name string, raw []byte, meta fileMeta, reliability Reliability, state CommitState) Result {
	return Result{parsed: parsed, name: name, digest: meta.digest, size: meta.size, device: meta.device, inode: meta.inode, mount: meta.mount, reliability: reliability, commitState: state, raw: append([]byte(nil), raw...)}
}

func (s *Store) inject(stage faultStage) error {
	if s.fault == nil {
		return nil
	}
	return s.fault(stage)
}

func sha256Hex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

type fileMeta struct {
	digest string
	size   int
	device uint64
	inode  uint64
	mount  uint64
}

type publishOutcome struct {
	meta   fileMeta
	state  CommitState
	poison bool
}
