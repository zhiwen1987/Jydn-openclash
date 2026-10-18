// Package evidence provides a small, append-only, tamper-evident event log.
//
// It is deliberately a single-host safety mechanism. The hash chain and local
// checkpoint detect accidental edits, reordering and truncation, but they are
// not a WORM store and do not protect against an administrator replacing both
// files. Callers that need adversarial tamper resistance must replicate signed
// checkpoints to an independent system.
package evidence

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	logFilename            = "events.jsonl"
	checkpointFilename     = "checkpoint.json"
	lockFilename           = "writer.lock"
	genesisHash            = "0000000000000000000000000000000000000000000000000000000000000000"
	maxLineBytes           = 16 * 1024
	maxDataEntries         = 32
	maxDataBytes           = 8 * 1024
	maxIdempotencyKeyBytes = 128
	// IssueCheckpointStale is returned when the JSONL file has a valid-looking
	// tail beyond the durable checkpoint. That tail is deliberately not
	// auto-promoted: the unkeyed hash chain proves continuity, not that the
	// extra records were committed by this Store rather than injected.
	IssueCheckpointStale = "checkpoint_stale"
)

var (
	// ErrIntegrity means the evidence log no longer agrees with its hash chain
	// or durable local checkpoint.
	ErrIntegrity = errors.New("evidence log integrity verification failed")
	// ErrIdempotencyConflict means an idempotency key has already committed a
	// semantically different event. Callers may use errors.Is to handle this
	// stable conflict independently from validation and storage failures.
	ErrIdempotencyConflict = errors.New("evidence idempotency key conflict")
	// ErrStorePoisoned means a write may have reached durable storage without
	// all of its commit metadata becoming durably visible. The affected Store
	// instance is permanently read-only; callers must close over it, repair or
	// inspect the files, and Open a freshly verified instance before appending.
	ErrStorePoisoned = errors.New("evidence store is unavailable after uncertain write")
	// ErrStoreLocked means another Store instance holds the lifecycle writer
	// lock for the same directory.
	ErrStoreLocked = errors.New("evidence store already has an active writer")
	// ErrStoreClosed means Close has released this Store's writer lock.
	ErrStoreClosed = errors.New("evidence store is closed")
	safeName       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
)

// EvidenceEvent is the only record persisted in the JSONL evidence log. Data
// is restricted to small textual summaries and opaque references. Raw HTTP
// bodies and values whose keys could contain credentials are rejected.
type EvidenceEvent struct {
	ID             string            `json:"id"`
	IdempotencyKey string            `json:"idempotencyKey,omitempty"`
	TraceID        string            `json:"traceId"`
	ActorID        string            `json:"actorId"`
	Action         string            `json:"action"`
	Target         string            `json:"target"`
	Result         string            `json:"result"`
	OccurredAt     time.Time         `json:"occurredAt"`
	Data           map[string]string `json:"data,omitempty"`
	PreviousHash   string            `json:"previousHash"`
	Hash           string            `json:"hash"`
}

type idempotencyRecord struct {
	event       EvidenceEvent
	fingerprint string
}

type checkpoint struct {
	Count    uint64 `json:"count"`
	LastHash string `json:"lastHash"`
}

// VerifyReport describes the verified prefix and its checkpoint. Issue is
// empty only when Valid is true.
type VerifyReport struct {
	Valid            bool      `json:"valid"`
	Count            uint64    `json:"count"`
	ExpectedCount    uint64    `json:"expectedCount"`
	LastHash         string    `json:"lastHash"`
	ExpectedLastHash string    `json:"expectedLastHash"`
	Issue            string    `json:"issue,omitempty"`
	VerifiedAt       time.Time `json:"verifiedAt"`
}

// Store serializes appends in-process and fsyncs each event before advancing
// the local checkpoint.
type Store struct {
	dir              string
	logPath          string
	checkpointPath   string
	lockPath         string
	mu               sync.Mutex
	statusMu         sync.RWMutex
	status           VerifyReport
	count            uint64
	lastHash         string
	idempotency      map[string]idempotencyRecord
	poisonErr        error
	checkpointCommit func(checkpoint) error
	syncDir          func(string) error
	lock             *os.File
	dirInfo          os.FileInfo
	lockInfo         os.FileInfo
	closed           bool
}

// Open creates or opens an evidence store and verifies the complete chain
// before returning it. Existing corruption therefore fails closed at startup.
func Open(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("evidence directory is required")
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve evidence directory: %w", err)
	}
	if err := rejectSymlinkComponents(absDir, true); err != nil {
		return nil, err
	}
	_, dirStatErr := os.Lstat(absDir)
	dirExisted := dirStatErr == nil
	if dirStatErr != nil && !errors.Is(dirStatErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect evidence directory: %w", dirStatErr)
	}
	if err := os.MkdirAll(absDir, 0o700); err != nil {
		return nil, fmt.Errorf("create evidence directory: %w", err)
	}
	if !dirExisted {
		if err := os.Chmod(absDir, 0o700); err != nil {
			return nil, fmt.Errorf("secure evidence directory: %w", err)
		}
	}
	if err := rejectSymlinkComponents(absDir, false); err != nil {
		return nil, err
	}
	dirInfo, err := os.Lstat(absDir)
	if err != nil {
		return nil, fmt.Errorf("inspect evidence directory: %w", err)
	}
	if !dirInfo.IsDir() {
		return nil, errors.New("evidence directory is not a directory")
	}
	if err := requirePermissions("evidence directory", dirInfo, 0o700); err != nil {
		return nil, err
	}
	dirHandle, err := os.Open(absDir)
	if err != nil {
		return nil, fmt.Errorf("open evidence directory: %w", err)
	}
	openedDirInfo, statErr := dirHandle.Stat()
	closeErr := dirHandle.Close()
	if statErr != nil {
		return nil, fmt.Errorf("inspect opened evidence directory: %w", statErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close evidence directory: %w", closeErr)
	}
	if !openedDirInfo.IsDir() || !os.SameFile(dirInfo, openedDirInfo) {
		return nil, errors.New("evidence directory changed while opening")
	}
	s := &Store{
		dir:            absDir,
		logPath:        filepath.Join(absDir, logFilename),
		checkpointPath: filepath.Join(absDir, checkpointFilename),
		lockPath:       filepath.Join(absDir, lockFilename),
		lastHash:       genesisHash,
		idempotency:    make(map[string]idempotencyRecord),
		syncDir:        syncDirectory,
		dirInfo:        dirInfo,
	}
	s.checkpointCommit = s.writeCheckpoint

	lockExisted, err := regularPathExists(s.lockPath, "evidence lock", 0o600)
	if err != nil {
		return nil, err
	}
	lock, err := acquireEvidenceLock(s.lockPath)
	if err != nil {
		return nil, err
	}
	s.lock = lock
	opened := false
	defer func() {
		if !opened {
			_ = releaseEvidenceLock(s.lock)
		}
	}()
	if !lockExisted {
		if err := lock.Chmod(0o600); err != nil {
			return nil, fmt.Errorf("secure evidence lock: %w", err)
		}
	}
	if err := verifyOpenedRegularFile(s.lockPath, "evidence lock", lock, 0o600); err != nil {
		return nil, err
	}
	s.lockInfo, err = lock.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect evidence lock: %w", err)
	}

	file, err := openRegularFile(s.logPath, "evidence log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open evidence log: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close evidence log: %w", err)
	}

	checkpointExists, err := regularPathExists(s.checkpointPath, "evidence checkpoint", 0o600)
	if err != nil {
		return nil, err
	}
	if !checkpointExists {
		info, statErr := os.Lstat(s.logPath)
		if statErr != nil {
			return nil, statErr
		}
		if info.Size() != 0 {
			return nil, integrityError("checkpoint_missing", "non-empty log has no checkpoint")
		}
		if err := s.writeCheckpoint(checkpoint{LastHash: genesisHash}); err != nil {
			return nil, err
		}
	}
	if err := s.ensureDirectoryIdentityLocked(); err != nil {
		return nil, fmt.Errorf("revalidate evidence store paths: %w", err)
	}

	report, index, err := s.verifyAndIndexLocked()
	if err != nil {
		return nil, err
	}
	s.count = report.Count
	s.lastHash = report.LastHash
	s.idempotency = index
	s.setStatus(report)
	opened = true
	return s, nil
}

// Close releases the lifecycle writer lock. It is idempotent. Reopen the
// directory to obtain a newly verified Store after closing.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.setStatus(VerifyReport{
		Valid: false, Count: s.count, ExpectedCount: s.count,
		LastHash: s.lastHash, ExpectedLastHash: s.lastHash, Issue: "store_closed",
	})
	err := releaseEvidenceLock(s.lock)
	s.lock = nil
	return err
}

// Append validates, normalizes, appends and fsyncs one event. Caller-provided
// hash fields are rejected so only the store can extend the chain.
func (s *Store) Append(event EvidenceEvent) (EvidenceEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if event.ID != "" {
		return EvidenceEvent{}, errors.New("id is managed by the evidence store")
	}
	if event.IdempotencyKey != "" {
		return EvidenceEvent{}, errors.New("idempotencyKey is only accepted by AppendOnce")
	}
	return s.appendLocked(event)
}

// AppendOnce durably appends an event at most once for a normalized
// idempotency key. Keys are trimmed, converted to lower case, limited to 128
// bytes and restricted to the same portable character set as IDs.
//
// Event identity deliberately excludes store-managed metadata (ID, event
// time, hash linkage and the idempotency key itself). A retry therefore
// returns the exact originally persisted event, including its original ID and
// OccurredAt. Reusing the key for different actor/action/target/result/data is
// rejected with ErrIdempotencyConflict.
func (s *Store) AppendOnce(event EvidenceEvent, key string) (persisted EvidenceEvent, created bool, err error) {
	if event.ID != "" {
		return EvidenceEvent{}, false, errors.New("id is managed by the evidence store")
	}
	normalizedKey, err := normalizeIdempotencyKey(key)
	if err != nil {
		return EvidenceEvent{}, false, err
	}
	if event.IdempotencyKey != "" {
		eventKey, keyErr := normalizeIdempotencyKey(event.IdempotencyKey)
		if keyErr != nil {
			return EvidenceEvent{}, false, keyErr
		}
		if eventKey != normalizedKey {
			return EvidenceEvent{}, false, errors.New("event idempotencyKey does not match AppendOnce key")
		}
	}
	event.IdempotencyKey = normalizedKey
	event = cloneEvidenceEvent(event)
	event = normalizeEventDefaults(event)
	if event.Hash != "" || event.PreviousHash != "" {
		return EvidenceEvent{}, false, errors.New("hash fields are managed by the evidence store")
	}
	validationEvent := event
	if validationEvent.ID == "" {
		validationEvent.ID = "pending"
	}
	if err := validateEvent(validationEvent); err != nil {
		return EvidenceEvent{}, false, err
	}
	fingerprint, err := idempotencyFingerprint(event)
	if err != nil {
		return EvidenceEvent{}, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writableLocked(); err != nil {
		return EvidenceEvent{}, false, err
	}
	if existing, ok := s.idempotency[normalizedKey]; ok {
		if existing.fingerprint != fingerprint {
			return EvidenceEvent{}, false, ErrIdempotencyConflict
		}
		return cloneEvidenceEvent(existing.event), false, nil
	}

	persisted, err = s.appendLocked(event)
	if err != nil {
		return EvidenceEvent{}, false, err
	}
	s.idempotency[normalizedKey] = idempotencyRecord{event: cloneEvidenceEvent(persisted), fingerprint: fingerprint}
	return cloneEvidenceEvent(persisted), true, nil
}

func (s *Store) appendLocked(event EvidenceEvent) (EvidenceEvent, error) {
	if err := s.writableLocked(); err != nil {
		return EvidenceEvent{}, err
	}

	if event.Hash != "" || event.PreviousHash != "" {
		return EvidenceEvent{}, errors.New("hash fields are managed by the evidence store")
	}
	if event.ID == "" {
		id, err := newID()
		if err != nil {
			return EvidenceEvent{}, err
		}
		event.ID = id
	}
	event = normalizeEventDefaults(event)
	if err := validateEvent(event); err != nil {
		return EvidenceEvent{}, err
	}

	event.PreviousHash = s.lastHash
	hash, err := eventHash(event)
	if err != nil {
		return EvidenceEvent{}, err
	}
	event.Hash = hash
	line, err := json.Marshal(event)
	if err != nil {
		return EvidenceEvent{}, fmt.Errorf("encode evidence event: %w", err)
	}
	if len(line)+1 > maxLineBytes {
		return EvidenceEvent{}, fmt.Errorf("evidence event exceeds %d bytes", maxLineBytes)
	}
	line = append(line, '\n')

	file, err := openRegularFile(s.logPath, "evidence log", os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return EvidenceEvent{}, fmt.Errorf("open evidence log for append: %w", err)
	}
	written, err := file.Write(line)
	if err != nil {
		file.Close()
		return EvidenceEvent{}, s.poisonLocked("append evidence event", err)
	}
	if written != len(line) {
		file.Close()
		return EvidenceEvent{}, s.poisonLocked("append evidence event", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return EvidenceEvent{}, s.poisonLocked("fsync evidence event", err)
	}
	if err := file.Close(); err != nil {
		return EvidenceEvent{}, s.poisonLocked("close evidence log", err)
	}

	next := checkpoint{Count: s.count + 1, LastHash: event.Hash}
	if err := s.checkpointCommit(next); err != nil {
		return EvidenceEvent{}, s.poisonLocked("commit evidence checkpoint", err)
	}
	s.count = next.Count
	s.lastHash = next.LastHash
	s.setStatus(VerifyReport{
		Valid: true, Count: s.count, ExpectedCount: s.count,
		LastHash: s.lastHash, ExpectedLastHash: s.lastHash,
	})
	return event, nil
}

// Verify checks the entire JSONL chain and compares its tail with the local
// checkpoint, detecting edits, line reordering, partial lines and truncation.
func (s *Store) Verify() (report VerifyReport, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { s.setStatus(report) }()
	if s.closed {
		return VerifyReport{Issue: "store_closed"}, ErrStoreClosed
	}
	if err := s.ensureDirectoryIdentityLocked(); err != nil {
		poisoned := s.poisonLocked("evidence directory identity changed", err)
		return VerifyReport{Issue: "directory_changed"}, errors.Join(ErrIntegrity, poisoned)
	}
	report, err = s.verifyLocked()
	if err != nil {
		if s.poisonErr != nil {
			// Preserve both facts: the files currently fail integrity
			// verification and this instance has an uncertain commit history.
			return report, errors.Join(err, s.poisonErr)
		}
		return report, err
	}
	if s.poisonErr != nil {
		report.Valid = false
		report.Issue = "store_poisoned"
		return report, s.poisonErr
	}
	return report, nil
}

// Status returns the most recent integrity result in constant time. Open
// performs a full verification before the Store becomes available, successful
// appends advance the cached checkpoint atomically, and later Verify calls
// replace this status. Callers that need a fresh disk scan must call Verify;
// request-time liveness paths should use Status to avoid history-dependent
// work under attacker-controlled request rates.
func (s *Store) Status() VerifyReport {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.status
}

func (s *Store) setStatus(report VerifyReport) {
	report.VerifiedAt = time.Now().UTC()
	s.statusMu.Lock()
	s.status = report
	s.statusMu.Unlock()
}

func (s *Store) writableLocked() error {
	if s.closed {
		return ErrStoreClosed
	}
	if s.poisonErr != nil {
		return s.poisonErr
	}
	if err := s.ensureDirectoryIdentityLocked(); err != nil {
		return s.poisonLocked("evidence directory identity changed", err)
	}
	return nil
}

func (s *Store) ensureDirectoryIdentityLocked() error {
	info, err := os.Lstat(s.dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || !os.SameFile(s.dirInfo, info) {
		return errors.New("evidence directory was replaced")
	}
	if err := requirePermissions("evidence directory", info, 0o700); err != nil {
		return err
	}
	if s.lock == nil || s.lockInfo == nil {
		return errors.New("evidence writer lock is unavailable")
	}
	lockInfo, err := os.Lstat(s.lockPath)
	if err != nil {
		return fmt.Errorf("inspect evidence writer lock: %w", err)
	}
	if !lockInfo.Mode().IsRegular() || !os.SameFile(s.lockInfo, lockInfo) {
		return errors.New("evidence writer lock was replaced")
	}
	return requirePermissions("evidence lock", lockInfo, 0o600)
}

func (s *Store) poisonLocked(stage string, err error) error {
	if s.poisonErr == nil {
		s.poisonErr = fmt.Errorf("%w: %s: %v", ErrStorePoisoned, stage, err)
	}
	s.setStatus(VerifyReport{
		Valid: false, Count: s.count, ExpectedCount: s.count,
		LastHash: s.lastHash, ExpectedLastHash: s.lastHash, Issue: "store_poisoned",
	})
	return s.poisonErr
}

func (s *Store) verifyLocked() (VerifyReport, error) {
	report, _, err := s.verifyAndIndexLocked()
	return report, err
}

func (s *Store) verifyAndIndexLocked() (VerifyReport, map[string]idempotencyRecord, error) {
	index := make(map[string]idempotencyRecord)
	eventIDs := make(map[string]struct{})
	cpFile, err := openRegularFile(s.checkpointPath, "evidence checkpoint", os.O_RDONLY, 0o600)
	if err != nil {
		return VerifyReport{}, nil, integrityWrap("checkpoint_unreadable", err)
	}
	cpData, readErr := io.ReadAll(io.LimitReader(cpFile, maxLineBytes+1))
	closeErr := cpFile.Close()
	if readErr != nil {
		return VerifyReport{}, nil, integrityWrap("checkpoint_unreadable", readErr)
	}
	if closeErr != nil {
		return VerifyReport{}, nil, integrityWrap("checkpoint_unreadable", closeErr)
	}
	if len(cpData) > maxLineBytes {
		return VerifyReport{}, nil, integrityError("checkpoint_invalid", "checkpoint exceeds size limit")
	}
	var cp checkpoint
	if err := strictUnmarshal(cpData, &cp); err != nil {
		return VerifyReport{}, nil, integrityWrap("checkpoint_invalid", err)
	}
	if cp.LastHash == "" {
		cp.LastHash = genesisHash
	}
	if !validHash(cp.LastHash) {
		return VerifyReport{}, nil, integrityError("checkpoint_invalid", "invalid checkpoint hash")
	}

	file, err := openRegularFile(s.logPath, "evidence log", os.O_RDONLY, 0o600)
	if err != nil {
		return VerifyReport{}, nil, integrityWrap("log_unreadable", err)
	}
	defer file.Close()

	report := VerifyReport{ExpectedCount: cp.Count, ExpectedLastHash: cp.LastHash, LastHash: genesisHash}
	reader := bufio.NewReaderSize(file, maxLineBytes)
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > maxLineBytes {
			return invalidReportWithIndex(report, "line_too_large", "evidence line exceeds size limit")
		}
		if len(line) > 0 {
			if line[len(line)-1] != '\n' {
				return invalidReportWithIndex(report, "partial_line", "evidence log ends with a partial line")
			}
			line = line[:len(line)-1]
			if len(line) == 0 {
				return invalidReportWithIndex(report, "blank_line", "blank evidence line")
			}
			var event EvidenceEvent
			if err := strictUnmarshal(line, &event); err != nil {
				return invalidReportWithIndex(report, "invalid_json", err.Error())
			}
			if err := validateStoredEvent(event); err != nil {
				return invalidReportWithIndex(report, "invalid_event", err.Error())
			}
			if _, exists := eventIDs[event.ID]; exists {
				return invalidReportWithIndex(report, "duplicate_event_id", fmt.Sprintf("event id %q appears more than once", event.ID))
			}
			eventIDs[event.ID] = struct{}{}
			if event.PreviousHash != report.LastHash {
				return invalidReportWithIndex(report, "chain_mismatch", fmt.Sprintf("event %d previous hash mismatch", report.Count+1))
			}
			expectedHash, err := eventHash(event)
			if err != nil {
				return invalidReportWithIndex(report, "hash_error", err.Error())
			}
			if event.Hash != expectedHash {
				return invalidReportWithIndex(report, "hash_mismatch", fmt.Sprintf("event %d hash mismatch", report.Count+1))
			}
			if event.IdempotencyKey != "" {
				key, err := normalizeIdempotencyKey(event.IdempotencyKey)
				if err != nil || key != event.IdempotencyKey {
					return invalidReportWithIndex(report, "invalid_idempotency_key", "stored idempotency key is not canonical")
				}
				fingerprint, err := idempotencyFingerprint(event)
				if err != nil {
					return invalidReportWithIndex(report, "idempotency_fingerprint_error", err.Error())
				}
				if existing, ok := index[key]; ok {
					issue := "duplicate_idempotency_key"
					if existing.fingerprint != fingerprint {
						issue = "idempotency_conflict"
					}
					return invalidReportWithIndex(report, issue, "idempotency key appears more than once")
				}
				index[key] = idempotencyRecord{event: event, fingerprint: fingerprint}
			}
			report.Count++
			report.LastHash = event.Hash
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return VerifyReport{}, nil, integrityWrap("log_read_error", readErr)
		}
	}

	if report.Count != cp.Count {
		kind := "checkpoint_mismatch"
		if report.Count < cp.Count {
			kind = "log_truncated"
		} else if report.Count > cp.Count {
			// Even a structurally valid, continuous extra tail is not proof of
			// commit because the chain is deliberately unkeyed. Recovery remains
			// fail-closed and requires an explicit operator decision.
			kind = IssueCheckpointStale
		}
		return invalidReportWithIndex(report, kind, fmt.Sprintf("event count is %d, checkpoint expects %d", report.Count, cp.Count))
	}
	if report.LastHash != cp.LastHash {
		return invalidReportWithIndex(report, "checkpoint_mismatch", "log tail hash does not match checkpoint")
	}
	report.Valid = true
	return report, index, nil
}

func validateStoredEvent(event EvidenceEvent) error {
	if event.Hash == "" || event.PreviousHash == "" || !validHash(event.Hash) || !validHash(event.PreviousHash) {
		return errors.New("invalid hash fields")
	}
	hash, previous := event.Hash, event.PreviousHash
	event.Hash, event.PreviousHash = "", ""
	if err := validateEvent(event); err != nil {
		return err
	}
	event.Hash, event.PreviousHash = hash, previous
	return nil
}

func validateEvent(event EvidenceEvent) error {
	fields := []struct {
		name  string
		value string
		max   int
		safe  bool
	}{
		{"id", event.ID, 128, true},
		{"traceId", event.TraceID, 128, true},
		{"actorId", event.ActorID, 128, true},
		{"action", event.Action, 128, true},
		{"target", event.Target, 256, false},
		{"result", event.Result, 64, true},
	}
	if event.IdempotencyKey != "" {
		key, err := normalizeIdempotencyKey(event.IdempotencyKey)
		if err != nil {
			return err
		}
		if key != event.IdempotencyKey {
			return errors.New("idempotencyKey must be canonical")
		}
	}
	for _, field := range fields {
		if field.value == "" {
			return fmt.Errorf("%s is required", field.name)
		}
		if len(field.value) > field.max {
			return fmt.Errorf("%s exceeds %d bytes", field.name, field.max)
		}
		if strings.TrimSpace(field.value) != field.value || hasControl(field.value) {
			return fmt.Errorf("%s contains invalid whitespace or control characters", field.name)
		}
		if field.safe && !safeName.MatchString(field.value) {
			return fmt.Errorf("%s contains unsupported characters", field.name)
		}
	}
	if event.OccurredAt.IsZero() {
		return errors.New("occurredAt is required")
	}
	if len(event.Data) > maxDataEntries {
		return fmt.Errorf("data exceeds %d entries", maxDataEntries)
	}
	dataBytes, err := json.Marshal(event.Data)
	if err != nil {
		return fmt.Errorf("encode data: %w", err)
	}
	if len(dataBytes) > maxDataBytes {
		return fmt.Errorf("data exceeds %d bytes", maxDataBytes)
	}
	for key, value := range event.Data {
		if key == "" || len(key) > 64 || len(value) > 1024 || hasControl(key) || hasControl(value) {
			return fmt.Errorf("data field %q violates size or character limits", key)
		}
		if forbiddenDataKey(key) {
			return fmt.Errorf("data field %q may contain secret or raw body material", key)
		}
	}
	return nil
}

func normalizeEventDefaults(event EvidenceEvent) EvidenceEvent {
	if event.TraceID == "" {
		event.TraceID = "unknown"
	}
	if event.ActorID == "" {
		event.ActorID = "unknown"
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	} else {
		event.OccurredAt = event.OccurredAt.UTC()
	}
	return event
}

func cloneEvidenceEvent(event EvidenceEvent) EvidenceEvent {
	if event.Data != nil {
		cloned := make(map[string]string, len(event.Data))
		for key, value := range event.Data {
			cloned[key] = value
		}
		event.Data = cloned
	}
	return event
}

func normalizeIdempotencyKey(key string) (string, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return "", errors.New("idempotency key is required")
	}
	if len(key) > maxIdempotencyKeyBytes {
		return "", fmt.Errorf("idempotency key exceeds %d bytes", maxIdempotencyKeyBytes)
	}
	if !safeName.MatchString(key) {
		return "", errors.New("idempotency key contains unsupported characters")
	}
	return key, nil
}

func idempotencyFingerprint(event EvidenceEvent) (string, error) {
	// Store-generated identity, timestamps and hash-chain metadata do not
	// participate. This makes a delayed retry equivalent to the first request.
	payload := struct {
		TraceID string            `json:"traceId"`
		ActorID string            `json:"actorId"`
		Action  string            `json:"action"`
		Target  string            `json:"target"`
		Result  string            `json:"result"`
		Data    map[string]string `json:"data,omitempty"`
	}{
		TraceID: event.TraceID,
		ActorID: event.ActorID,
		Action:  event.Action,
		Target:  event.Target,
		Result:  event.Result,
		Data:    event.Data,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode idempotency fingerprint: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func forbiddenDataKey(key string) bool {
	var normalized strings.Builder
	for _, r := range strings.ToLower(key) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			normalized.WriteRune(r)
		}
	}
	value := normalized.String()
	for _, secret := range []string{
		"password", "passwd", "token", "secret", "privatekey", "authorization",
		"apikey", "accesskey", "credential", "cookie", "setcookie",
	} {
		if strings.Contains(value, secret) {
			return true
		}
	}
	switch value {
	case "body", "rawbody", "requestbody", "responsebody", "httpbody", "payload", "requestpayload", "responsepayload":
		return true
	default:
		return false
	}
}

func eventHash(event EvidenceEvent) (string, error) {
	event.Hash = ""
	payload, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func validHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func newID() (string, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate evidence id: %w", err)
	}
	return fmt.Sprintf("evt-%d-%s", time.Now().UTC().UnixMilli(), hex.EncodeToString(random)), nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func strictUnmarshal(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func rejectSymlinkComponents(path string, allowMissing bool) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(absPath)
	remainder := strings.TrimPrefix(absPath, volume)
	remainder = strings.TrimLeft(remainder, string(os.PathSeparator))
	current := volume + string(os.PathSeparator)
	if volume == "" {
		current = string(os.PathSeparator)
	}
	for _, part := range strings.Split(remainder, string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && allowMissing {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect evidence path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("evidence path must not contain symbolic links")
		}
	}
	return nil
}

func requirePermissions(name string, info os.FileInfo, expected os.FileMode) error {
	// FileMode cannot express Windows ACLs. The Windows lock still provides
	// single-writer exclusion, while deployment must apply an equivalent ACL.
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm() != expected || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("%s permissions must be %04o, got %04o", name, expected, info.Mode().Perm())
	}
	return nil
}

func regularPathExists(path, name string, expected os.FileMode) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", name)
	}
	if err := requirePermissions(name, info, expected); err != nil {
		return false, err
	}
	return true, nil
}

func openRegularFile(path, name string, flags int, permissions os.FileMode) (*os.File, error) {
	existed, err := regularPathExists(path, name, permissions)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, flags, permissions)
	if err != nil {
		return nil, err
	}
	if !existed {
		if err := file.Chmod(permissions); err != nil {
			file.Close()
			return nil, fmt.Errorf("secure %s: %w", name, err)
		}
	}
	if err := verifyOpenedRegularFile(path, name, file, permissions); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func verifyOpenedRegularFile(path, name string, file *os.File, permissions os.FileMode) error {
	openedInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened %s: %w", name, err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s after open: %w", name, err)
	}
	if !openedInfo.Mode().IsRegular() || !pathInfo.Mode().IsRegular() || !os.SameFile(openedInfo, pathInfo) {
		return fmt.Errorf("%s changed while opening or is not a regular file", name)
	}
	return requirePermissions(name, openedInfo, permissions)
}

func (s *Store) writeCheckpoint(cp checkpoint) error {
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".checkpoint-*")
	if err != nil {
		return fmt.Errorf("create checkpoint: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	tmpInfo, err := tmp.Stat()
	if err != nil {
		tmp.Close()
		return fmt.Errorf("inspect checkpoint temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.checkpointPath); err != nil {
		return fmt.Errorf("replace checkpoint: %w", err)
	}
	checkpointInfo, err := os.Lstat(s.checkpointPath)
	if err != nil {
		return fmt.Errorf("inspect replaced checkpoint: %w", err)
	}
	if !checkpointInfo.Mode().IsRegular() || !os.SameFile(tmpInfo, checkpointInfo) {
		return errors.New("replaced checkpoint is not the committed regular file")
	}
	if err := requirePermissions("evidence checkpoint", checkpointInfo, 0o600); err != nil {
		return err
	}
	// Rename makes the new checkpoint visible, but on POSIX the directory
	// entry itself is not crash-durable until the containing directory is
	// synced. Windows uses its platform-specific best-effort implementation.
	if err := s.syncDir(s.dir); err != nil {
		return fmt.Errorf("fsync checkpoint directory: %w", err)
	}
	if err := s.ensureDirectoryIdentityLocked(); err != nil {
		return fmt.Errorf("revalidate evidence store paths: %w", err)
	}
	return nil
}

func invalidReport(report VerifyReport, issue, detail string) (VerifyReport, error) {
	report.Issue = issue
	return report, integrityError(issue, detail)
}

func invalidReportWithIndex(report VerifyReport, issue, detail string) (VerifyReport, map[string]idempotencyRecord, error) {
	report, err := invalidReport(report, issue, detail)
	return report, nil, err
}

func integrityError(issue, detail string) error {
	return fmt.Errorf("%w: %s: %s", ErrIntegrity, issue, detail)
}

func integrityWrap(issue string, err error) error {
	return fmt.Errorf("%w: %s: %v", ErrIntegrity, issue, err)
}
