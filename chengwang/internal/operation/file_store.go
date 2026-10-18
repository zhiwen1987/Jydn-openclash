package operation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	fileStoreSchemaVersion = 2
	legacySchemaVersion    = 1
	fileStoreName          = "operations.json"
	fileStoreLockName      = ".operations.lock"
	maxSnapshotBytes       = 16 << 20
	maxOperations          = 10_000
	maxEventsPerOperation  = 1_000
	maxIdempotencyRecords  = maxOperations
)

var (
	ErrStoreLocked     = errors.New("operation file store is locked by another controller")
	ErrStoreClosed     = errors.New("operation file store is closed")
	ErrStorePoisoned   = errors.New("operation file store is fail-closed after an uncertain commit")
	ErrCommitUncertain = errors.New("operation snapshot rename succeeded but directory durability is uncertain")
	ErrStoreLimit      = errors.New("operation file store limit exceeded")
)

type diskIdempotencyRecord struct {
	Key         string `json:"key"`
	OperationID string `json:"operationId"`
	Digest      string `json:"digest"`
}

type diskSnapshot struct {
	Version     int                     `json:"version"`
	Operations  []Operation             `json:"operations"`
	Idempotency []diskIdempotencyRecord `json:"idempotency"`
}

type commitState uint8

const (
	commitNotCommitted commitState = iota
	commitCommitted
	commitUncertain
)

type writeResult struct {
	state commitState
	err   error
}

type snapshotWriter func(path string, snapshot diskSnapshot) writeResult

// FileStore is a concurrency-safe operation store backed by one atomically
// replaced JSON snapshot in directory. It preserves operations, events, and
// idempotency records across process restarts.
//
// FileStore is deliberately a single-controller store. A process-lifetime OS
// file lock rejects a second controller for the same directory. It provides no
// distributed transaction, lease or consensus across independent filesystems.
type FileStore struct {
	mu          sync.RWMutex
	directory   string
	path        string
	operations  map[string]*Operation
	idempotency map[string]idempotencyRecord
	now         func() time.Time
	newID       func(time.Time) (string, error)
	write       snapshotWriter
	processLock *processLock
	closed      bool
	poisoned    error
}

// NewFileStore opens or creates a single-controller store in directory. The
// directory is restricted to 0700 and its operations.json snapshot to 0600.
// Existing state is decoded with unknown fields rejected and every lifecycle
// and idempotency invariant revalidated before the store is returned.
func NewFileStore(directory string) (*FileStore, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return nil, errors.New("operation file store directory is required")
	}
	absDirectory, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve operation file store directory: %w", err)
	}
	if err := ensurePrivateDirectory(absDirectory); err != nil {
		return nil, err
	}
	lock, err := acquireProcessLock(filepath.Join(absDirectory, fileStoreLockName))
	if err != nil {
		return nil, fmt.Errorf("acquire operation file store lock: %w", err)
	}
	opened := false
	defer func() {
		if !opened {
			_ = lock.release()
		}
	}()

	s := &FileStore{
		directory:   absDirectory,
		path:        filepath.Join(absDirectory, fileStoreName),
		operations:  make(map[string]*Operation),
		idempotency: make(map[string]idempotencyRecord),
		now:         func() time.Time { return time.Now().UTC() },
		newID:       randomOperationID,
		write:       writeSnapshotAtomically,
		processLock: lock,
	}

	_, err = os.Lstat(s.path)
	switch {
	case err == nil:
		contents, err := readSnapshotFile(s.path)
		if err != nil {
			return nil, fmt.Errorf("read operation file store snapshot: %w", err)
		}
		snapshot, migrated, err := decodeAndValidateSnapshot(contents)
		if err != nil {
			return nil, fmt.Errorf("load operation file store snapshot: %w", err)
		}
		s.operations, s.idempotency, err = mapsFromSnapshot(snapshot)
		if err != nil {
			return nil, fmt.Errorf("load operation file store snapshot: %w", err)
		}
		if migrated {
			if err := committedWriteError(s.write(s.path, snapshot)); err != nil {
				return nil, fmt.Errorf("persist operation file store migration: %w", err)
			}
		}
	case errors.Is(err, os.ErrNotExist):
		if err := committedWriteError(s.write(s.path, makeDiskSnapshot(s.operations, s.idempotency))); err != nil {
			return nil, fmt.Errorf("initialize operation file store snapshot: %w", err)
		}
	default:
		return nil, fmt.Errorf("inspect operation file store snapshot: %w", err)
	}
	opened = true
	return s, nil
}

// Create has the same validation and idempotency semantics as MemoryStore. A
// candidate snapshot is committed to disk before it replaces in-memory state.
func (s *FileStore) Create(req CreateRequest) (operation Operation, created bool, err error) {
	if err := validateCreateRequest(req); err != nil {
		return Operation{}, false, err
	}
	digest, err := requestDigest(req)
	if err != nil {
		return Operation{}, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usableLocked(); err != nil {
		return Operation{}, false, err
	}
	if record, ok := s.idempotency[req.IdempotencyKey]; ok {
		if record.digest != digest {
			return Operation{}, false, ErrIdempotencyConflict
		}
		op, ok := s.operations[record.operationID]
		if !ok {
			// NewFileStore validation prevents this. Keep the guard so a future
			// internal mutation cannot turn corruption into a panic.
			return Operation{}, false, errors.New("operation file store idempotency record is corrupt")
		}
		return cloneOperation(*op), false, nil
	}
	if len(s.operations) >= maxOperations || len(s.idempotency) >= maxIdempotencyRecords {
		return Operation{}, false, ErrStoreLimit
	}

	now := s.now().UTC()
	id, err := s.newID(now)
	if err != nil {
		return Operation{}, false, fmt.Errorf("generate operation ID: %w", err)
	}
	if _, exists := s.operations[id]; exists {
		return Operation{}, false, fmt.Errorf("generate operation ID: collision %q", id)
	}
	op := Operation{
		ID:              id,
		InitiatorID:     strings.TrimSpace(req.InitiatorID),
		IdentityBinding: IdentityBindingDurable,
		Environment:     strings.TrimSpace(req.Environment),
		Scope:           strings.TrimSpace(req.Scope),
		TargetVersion:   strings.TrimSpace(req.TargetVersion),
		Risk:            req.Risk,
		Status:          StatusPlanned,
		CreatedAt:       now,
		UpdatedAt:       now,
		Events: []Event{{
			Sequence: 1,
			At:       now,
			To:       StatusPlanned,
			Reason:   "operation planned",
		}},
	}

	operations := cloneOperations(s.operations)
	idempotency := cloneIdempotency(s.idempotency)
	operations[id] = &op
	idempotency[req.IdempotencyKey] = idempotencyRecord{operationID: id, digest: digest}
	write := s.write(s.path, makeDiskSnapshot(operations, idempotency))
	if write.state == commitUncertain {
		s.poisonLocked(write.err)
		return Operation{}, false, fmt.Errorf("persist created operation: %w", committedWriteError(write))
	}
	if err := committedWriteError(write); err != nil {
		return Operation{}, false, fmt.Errorf("persist created operation: %w", err)
	}
	s.operations = operations
	s.idempotency = idempotency
	return cloneOperation(op), true, nil
}

// Get returns a detached snapshot of an operation.
func (s *FileStore) Get(id string) (Operation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.usableLocked(); err != nil {
		return Operation{}, err
	}
	op, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	return cloneOperation(*op), nil
}

// List returns detached snapshots ordered by creation time and then ID.
func (s *FileStore) List() ([]Operation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.usableLocked(); err != nil {
		return nil, err
	}
	result := make([]Operation, 0, len(s.operations))
	for _, op := range s.operations {
		result = append(result, cloneOperation(*op))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

// Transition has the same lifecycle semantics as MemoryStore. The transition
// becomes visible in memory only after the complete candidate snapshot has
// been atomically persisted.
func (s *FileStore) Transition(id string, to Status, reason string) (Operation, error) {
	return s.TransitionWithApproval(id, to, reason, "")
}

// TransitionWithApproval persists the lifecycle transition and any successful
// approval identity in the same atomic snapshot replacement.
func (s *FileStore) TransitionWithApproval(id string, to Status, reason, approverID string) (Operation, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return Operation{}, errors.New("transition reason is required")
	}
	if len(reason) > 512 {
		return Operation{}, errors.New("transition reason exceeds 512 bytes")
	}
	if sensitiveReasonPattern.MatchString(reason) {
		return Operation{}, ErrSensitiveReason
	}
	if !isKnownStatus(to) {
		return Operation{}, fmt.Errorf("%w: unknown destination %q", ErrInvalidTransition, to)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usableLocked(); err != nil {
		return Operation{}, err
	}
	current, ok := s.operations[id]
	if !ok {
		return Operation{}, ErrNotFound
	}
	if len(current.Events) >= maxEventsPerOperation {
		return Operation{}, ErrStoreLimit
	}
	if IsTerminal(current.Status) {
		return Operation{}, fmt.Errorf("%w: %s", ErrTerminalOperation, current.Status)
	}
	if !allowedTransitions[current.Status][to] {
		return Operation{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, current.Status, to)
	}
	approvalID, err := validateIdentityTransition(*current, to, approverID)
	if err != nil {
		return Operation{}, err
	}

	now := s.now().UTC()
	if now.Before(current.UpdatedAt) {
		now = current.UpdatedAt
	}
	candidate := cloneOperation(*current)
	from := candidate.Status
	candidate.Status = to
	if approvalID != "" {
		candidate.ApprovedByID = approvalID
	}
	candidate.UpdatedAt = now
	candidate.Events = append(candidate.Events, Event{
		Sequence: uint64(len(candidate.Events) + 1),
		At:       now,
		From:     from,
		To:       to,
		Reason:   reason,
	})

	operations := cloneOperations(s.operations)
	operations[id] = &candidate
	write := s.write(s.path, makeDiskSnapshot(operations, s.idempotency))
	if write.state == commitUncertain {
		s.poisonLocked(write.err)
		return Operation{}, fmt.Errorf("persist operation transition: %w", committedWriteError(write))
	}
	if err := committedWriteError(write); err != nil {
		return Operation{}, fmt.Errorf("persist operation transition: %w", err)
	}
	s.operations = operations
	return cloneOperation(candidate), nil
}

// Close releases the process-lifetime writer lock. It is idempotent. All
// methods fail with ErrStoreClosed afterwards.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.processLock == nil {
		return nil
	}
	err := s.processLock.release()
	s.processLock = nil
	return err
}

func (s *FileStore) usableLocked() error {
	if s.closed {
		return ErrStoreClosed
	}
	if s.poisoned != nil {
		return errors.Join(ErrStorePoisoned, s.poisoned)
	}
	return nil
}

func (s *FileStore) poisonLocked(cause error) {
	if cause == nil {
		cause = ErrCommitUncertain
	}
	s.poisoned = errors.Join(ErrCommitUncertain, cause)
}

func ensurePrivateDirectory(directory string) error {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return fmt.Errorf("resolve operation file store directory: %w", err)
	}
	volume := filepath.VolumeName(abs)
	remainder := strings.TrimPrefix(abs[len(volume):], string(filepath.Separator))
	current := volume + string(filepath.Separator)
	if volume == "" {
		current = string(filepath.Separator)
	}
	for _, component := range strings.Split(remainder, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		switch {
		case statErr == nil:
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("operation file store path component %q must not be a symlink", current)
			}
			if !info.IsDir() {
				return fmt.Errorf("operation file store path component %q is not a directory", current)
			}
		case errors.Is(statErr, os.ErrNotExist):
			if err := os.Mkdir(current, 0o700); err != nil {
				return fmt.Errorf("create operation file store path component %q: %w", current, err)
			}
			created, err := os.Lstat(current)
			if err != nil || created.Mode()&os.ModeSymlink != 0 || !created.IsDir() {
				return fmt.Errorf("verify created operation file store path component %q", current)
			}
		default:
			return fmt.Errorf("inspect operation file store path component %q: %w", current, statErr)
		}
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("restrict operation file store directory: %w", err)
	}
	return nil
}

func readSnapshotFile(path string) ([]byte, error) {
	return readSnapshotFileWithOpen(path, os.Open)
}

func readSnapshotFileWithOpen(path string, open func(string) (*os.File, error)) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("operation file store snapshot must be a regular file, not a symlink")
	}
	file, err := open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("operation file store snapshot changed while opening")
	}
	if after.Size() > maxSnapshotBytes {
		return nil, fmt.Errorf("%w: snapshot exceeds %d bytes", ErrStoreLimit, maxSnapshotBytes)
	}
	if err := file.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("restrict operation file store snapshot: %w", err)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > maxSnapshotBytes {
		return nil, fmt.Errorf("%w: snapshot exceeds %d bytes", ErrStoreLimit, maxSnapshotBytes)
	}
	return contents, nil
}

func writeSnapshotAtomically(path string, snapshot diskSnapshot) writeResult {
	return writeSnapshotAtomicallyWithSync(path, snapshot, syncDirectory)
}

func writeSnapshotAtomicallyWithSync(path string, snapshot diskSnapshot, directorySync func(string) error) writeResult {
	if err := validateSnapshot(snapshot); err != nil {
		return writeResult{state: commitNotCommitted, err: fmt.Errorf("validate snapshot before write: %w", err)}
	}
	encoded, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return writeResult{state: commitNotCommitted, err: fmt.Errorf("encode snapshot: %w", err)}
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxSnapshotBytes {
		return writeResult{state: commitNotCommitted, err: fmt.Errorf("%w: encoded snapshot exceeds %d bytes", ErrStoreLimit, maxSnapshotBytes)}
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return writeResult{state: commitNotCommitted, err: fmt.Errorf("create temporary snapshot: %w", err)}
	}
	temporaryPath := temporary.Name()
	keepTemporary := true
	defer func() {
		_ = temporary.Close()
		if keepTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return writeResult{state: commitNotCommitted, err: fmt.Errorf("restrict temporary snapshot: %w", err)}
	}
	if _, err := temporary.Write(encoded); err != nil {
		return writeResult{state: commitNotCommitted, err: fmt.Errorf("write temporary snapshot: %w", err)}
	}
	if err := temporary.Sync(); err != nil {
		return writeResult{state: commitNotCommitted, err: fmt.Errorf("sync temporary snapshot: %w", err)}
	}
	if err := temporary.Close(); err != nil {
		return writeResult{state: commitNotCommitted, err: fmt.Errorf("close temporary snapshot: %w", err)}
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return writeResult{state: commitNotCommitted, err: fmt.Errorf("replace operation snapshot: %w", err)}
	}
	keepTemporary = false
	if err := directorySync(directory); err != nil {
		return writeResult{state: commitUncertain, err: fmt.Errorf("sync operation snapshot directory after rename: %w", err)}
	}
	return writeResult{state: commitCommitted}
}

func committedWriteError(result writeResult) error {
	switch result.state {
	case commitCommitted:
		if result.err != nil {
			return fmt.Errorf("committed snapshot reported an error: %w", result.err)
		}
		return nil
	case commitUncertain:
		if result.err == nil {
			return ErrCommitUncertain
		}
		return errors.Join(ErrCommitUncertain, result.err)
	case commitNotCommitted:
		if result.err == nil {
			return errors.New("snapshot write did not commit")
		}
		return result.err
	default:
		return errors.New("snapshot writer returned an unknown commit state")
	}
}

func syncDirectory(directory string) error {
	// Windows does not expose directory fsync through os.File.Sync. The file
	// itself is still flushed before MoveFileEx-backed os.Rename. POSIX systems
	// additionally fsync the directory so the rename is crash durable.
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func makeDiskSnapshot(operations map[string]*Operation, idempotency map[string]idempotencyRecord) diskSnapshot {
	snapshot := diskSnapshot{
		Version:     fileStoreSchemaVersion,
		Operations:  make([]Operation, 0, len(operations)),
		Idempotency: make([]diskIdempotencyRecord, 0, len(idempotency)),
	}
	for _, op := range operations {
		snapshot.Operations = append(snapshot.Operations, cloneOperation(*op))
	}
	sort.Slice(snapshot.Operations, func(i, j int) bool {
		if snapshot.Operations[i].CreatedAt.Equal(snapshot.Operations[j].CreatedAt) {
			return snapshot.Operations[i].ID < snapshot.Operations[j].ID
		}
		return snapshot.Operations[i].CreatedAt.Before(snapshot.Operations[j].CreatedAt)
	})
	for key, record := range idempotency {
		snapshot.Idempotency = append(snapshot.Idempotency, diskIdempotencyRecord{
			Key:         key,
			OperationID: record.operationID,
			Digest:      hex.EncodeToString(record.digest[:]),
		})
	}
	sort.Slice(snapshot.Idempotency, func(i, j int) bool {
		return snapshot.Idempotency[i].Key < snapshot.Idempotency[j].Key
	})
	return snapshot
}

func decodeAndValidateSnapshot(contents []byte) (diskSnapshot, bool, error) {
	if len(contents) > maxSnapshotBytes {
		return diskSnapshot{}, false, fmt.Errorf("%w: snapshot exceeds %d bytes", ErrStoreLimit, maxSnapshotBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var snapshot diskSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return diskSnapshot{}, false, fmt.Errorf("decode strict JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return diskSnapshot{}, false, errors.New("decode strict JSON: multiple JSON values")
		}
		return diskSnapshot{}, false, fmt.Errorf("decode strict JSON trailer: %w", err)
	}
	if snapshot.Operations == nil || snapshot.Idempotency == nil {
		return diskSnapshot{}, false, errors.New("snapshot operations and idempotency arrays are required")
	}
	switch snapshot.Version {
	case fileStoreSchemaVersion:
		if err := validateSnapshot(snapshot); err != nil {
			return diskSnapshot{}, false, err
		}
		return snapshot, false, nil
	case legacySchemaVersion:
		if err := validateLegacySnapshot(snapshot); err != nil {
			return diskSnapshot{}, false, err
		}
		for index := range snapshot.Operations {
			snapshot.Operations[index].IdentityBinding = IdentityBindingLegacyUnbound
		}
		snapshot.Version = fileStoreSchemaVersion
		if err := validateSnapshot(snapshot); err != nil {
			return diskSnapshot{}, false, fmt.Errorf("validate migrated snapshot: %w", err)
		}
		return snapshot, true, nil
	default:
		return diskSnapshot{}, false, fmt.Errorf("unsupported snapshot version %d", snapshot.Version)
	}
}

func validateSnapshot(snapshot diskSnapshot) error {
	if len(snapshot.Operations) > maxOperations {
		return fmt.Errorf("%w: operation count exceeds %d", ErrStoreLimit, maxOperations)
	}
	if len(snapshot.Idempotency) > maxIdempotencyRecords {
		return fmt.Errorf("%w: idempotency count exceeds %d", ErrStoreLimit, maxIdempotencyRecords)
	}
	operations := make(map[string]Operation, len(snapshot.Operations))
	for index, op := range snapshot.Operations {
		if _, duplicate := operations[op.ID]; duplicate {
			return fmt.Errorf("duplicate operation ID %q", op.ID)
		}
		if err := validatePersistedOperation(op); err != nil {
			return fmt.Errorf("operation %d (%q): %w", index, op.ID, err)
		}
		operations[op.ID] = op
	}

	keys := make(map[string]struct{}, len(snapshot.Idempotency))
	operationReferences := make(map[string]string, len(snapshot.Idempotency))
	for index, record := range snapshot.Idempotency {
		if strings.TrimSpace(record.Key) == "" || len(record.Key) > 200 {
			return fmt.Errorf("idempotency record %d has an invalid key", index)
		}
		if _, duplicate := keys[record.Key]; duplicate {
			return fmt.Errorf("duplicate idempotency key %q", record.Key)
		}
		keys[record.Key] = struct{}{}
		op, exists := operations[record.OperationID]
		if !exists {
			return fmt.Errorf("idempotency key %q references unknown operation %q", record.Key, record.OperationID)
		}
		if otherKey, duplicate := operationReferences[record.OperationID]; duplicate {
			return fmt.Errorf("operation %q has conflicting idempotency keys %q and %q", record.OperationID, otherKey, record.Key)
		}
		operationReferences[record.OperationID] = record.Key
		digestBytes, err := hex.DecodeString(record.Digest)
		if err != nil || len(digestBytes) != 32 {
			return fmt.Errorf("idempotency key %q has an invalid digest", record.Key)
		}
		request := CreateRequest{
			InitiatorID: op.InitiatorID, Environment: op.Environment, Scope: op.Scope,
			TargetVersion: op.TargetVersion, Risk: op.Risk, IdempotencyKey: record.Key,
		}
		var expected [sha256.Size]byte
		if op.IdentityBinding == IdentityBindingLegacyUnbound {
			expected, err = legacyRequestDigest(request)
		} else {
			expected, err = requestDigest(request)
		}
		if err != nil {
			return fmt.Errorf("idempotency key %q: derive request digest: %w", record.Key, err)
		}
		if !bytes.Equal(digestBytes, expected[:]) {
			return fmt.Errorf("idempotency key %q conflicts with operation %q", record.Key, record.OperationID)
		}
	}
	for id := range operations {
		if _, exists := operationReferences[id]; !exists {
			return fmt.Errorf("operation %q has no idempotency record", id)
		}
	}
	return nil
}

func validatePersistedOperation(op Operation) error {
	if !operationIDPattern.MatchString(op.ID) {
		return errors.New("invalid operation ID")
	}
	if strings.TrimSpace(op.Environment) == "" || strings.TrimSpace(op.Scope) == "" || strings.TrimSpace(op.TargetVersion) == "" {
		return errors.New("required immutable field is empty")
	}
	if len(op.Environment) > maxEnvironmentBytes || len(op.Scope) > maxScopeBytes || len(op.TargetVersion) > maxTargetVersionBytes {
		return ErrStoreLimit
	}
	if len(op.Events) > maxEventsPerOperation {
		return fmt.Errorf("%w: event count exceeds %d", ErrStoreLimit, maxEventsPerOperation)
	}
	if op.Environment != strings.TrimSpace(op.Environment) || op.Scope != strings.TrimSpace(op.Scope) || op.TargetVersion != strings.TrimSpace(op.TargetVersion) {
		return errors.New("immutable text fields must be normalized")
	}
	switch op.Risk {
	case RiskLow, RiskMedium, RiskHigh, RiskCritical:
	default:
		return fmt.Errorf("unknown risk %q", op.Risk)
	}
	switch op.IdentityBinding {
	case IdentityBindingDurable:
		if strings.TrimSpace(op.InitiatorID) == "" || op.InitiatorID != strings.TrimSpace(op.InitiatorID) {
			return errors.New("durably bound operation has an invalid initiator identity")
		}
		if len(op.InitiatorID) > maxIdentityBytes || len(op.ApprovedByID) > maxIdentityBytes {
			return ErrStoreLimit
		}
		if op.ApprovedByID != strings.TrimSpace(op.ApprovedByID) || op.ApprovedByID == op.InitiatorID {
			return errors.New("operation has an invalid approver identity")
		}
	case IdentityBindingLegacyUnbound:
		if op.InitiatorID != "" || op.ApprovedByID != "" {
			return errors.New("legacy unbound operation unexpectedly contains identities")
		}
	default:
		return fmt.Errorf("unknown identity binding %q", op.IdentityBinding)
	}
	if !isKnownStatus(op.Status) {
		return fmt.Errorf("unknown status %q", op.Status)
	}
	if op.CreatedAt.IsZero() || op.UpdatedAt.IsZero() {
		return errors.New("createdAt and updatedAt are required")
	}
	if len(op.Events) == 0 {
		return errors.New("at least one event is required")
	}

	approvalTransition := false
	directHighRiskPrecheck := false
	executed := false
	for index, event := range op.Events {
		wantSequence := uint64(index + 1)
		if event.Sequence != wantSequence {
			return fmt.Errorf("event %d has sequence %d, want %d", index, event.Sequence, wantSequence)
		}
		if event.At.IsZero() {
			return fmt.Errorf("event %d has no timestamp", index)
		}
		if strings.TrimSpace(event.Reason) == "" || len(event.Reason) > 512 {
			return fmt.Errorf("event %d has an invalid reason", index)
		}
		if event.Reason != strings.TrimSpace(event.Reason) {
			return fmt.Errorf("event %d reason is not normalized", index)
		}
		if sensitiveReasonPattern.MatchString(event.Reason) {
			return fmt.Errorf("event %d contains a secret-bearing reason", index)
		}
		if !isKnownStatus(event.To) {
			return fmt.Errorf("event %d has unknown destination %q", index, event.To)
		}
		if index == 0 {
			if event.From != "" || event.To != StatusPlanned {
				return errors.New("first event must enter planned from an empty state")
			}
			if event.Reason != "operation planned" {
				return errors.New("first event has an invalid creation reason")
			}
			if !event.At.Equal(op.CreatedAt) {
				return errors.New("createdAt does not match first event")
			}
			continue
		}
		previous := op.Events[index-1]
		if event.At.Before(previous.At) {
			return fmt.Errorf("event %d timestamp precedes event %d", index, index-1)
		}
		if event.From != previous.To {
			return fmt.Errorf("event %d source %q does not match prior destination %q", index, event.From, previous.To)
		}
		if IsTerminal(previous.To) {
			return fmt.Errorf("event %d follows terminal status %q", index, previous.To)
		}
		if !allowedTransitions[event.From][event.To] {
			return fmt.Errorf("event %d has invalid transition %s -> %s", index, event.From, event.To)
		}
		if event.From == StatusAwaitingApproval && event.To == StatusPrechecking {
			approvalTransition = true
		}
		if event.From == StatusPlanned && event.To == StatusPrechecking && (op.Risk == RiskHigh || op.Risk == RiskCritical) {
			directHighRiskPrecheck = true
		}
		if event.To == StatusExecuting {
			executed = true
		}
	}
	if op.IdentityBinding == IdentityBindingDurable {
		if approvalTransition != (op.ApprovedByID != "") {
			return errors.New("approver identity does not match lifecycle approval")
		}
		if directHighRiskPrecheck {
			return errors.New("high-risk operation bypassed durable approval")
		}
		if op.Risk == RiskCritical && executed && !approvalTransition {
			return errors.New("critical execution has no durable approval")
		}
	}
	tail := op.Events[len(op.Events)-1]
	if op.Status != tail.To {
		return fmt.Errorf("status %q does not match tail event %q", op.Status, tail.To)
	}
	if !op.UpdatedAt.Equal(tail.At) {
		return errors.New("updatedAt does not match tail event")
	}
	return nil
}

func validateLegacySnapshot(snapshot diskSnapshot) error {
	if len(snapshot.Operations) > maxOperations {
		return fmt.Errorf("%w: legacy operation count exceeds %d", ErrStoreLimit, maxOperations)
	}
	if len(snapshot.Idempotency) > maxIdempotencyRecords {
		return fmt.Errorf("%w: legacy idempotency count exceeds %d", ErrStoreLimit, maxIdempotencyRecords)
	}
	operations := make(map[string]Operation, len(snapshot.Operations))
	for index, op := range snapshot.Operations {
		if op.InitiatorID != "" || op.ApprovedByID != "" || op.IdentityBinding != "" {
			return fmt.Errorf("legacy operation %d contains unsupported identity fields", index)
		}
		legacy := op
		legacy.IdentityBinding = IdentityBindingLegacyUnbound
		if err := validatePersistedOperation(legacy); err != nil {
			return fmt.Errorf("legacy operation %d (%q): %w", index, op.ID, err)
		}
		if _, duplicate := operations[op.ID]; duplicate {
			return fmt.Errorf("duplicate operation ID %q", op.ID)
		}
		operations[op.ID] = op
	}

	keys := make(map[string]struct{}, len(snapshot.Idempotency))
	operationReferences := make(map[string]string, len(snapshot.Idempotency))
	for index, record := range snapshot.Idempotency {
		if strings.TrimSpace(record.Key) == "" || len(record.Key) > 200 {
			return fmt.Errorf("idempotency record %d has an invalid key", index)
		}
		if _, duplicate := keys[record.Key]; duplicate {
			return fmt.Errorf("duplicate idempotency key %q", record.Key)
		}
		keys[record.Key] = struct{}{}
		op, exists := operations[record.OperationID]
		if !exists {
			return fmt.Errorf("idempotency key %q references unknown operation %q", record.Key, record.OperationID)
		}
		if otherKey, duplicate := operationReferences[record.OperationID]; duplicate {
			return fmt.Errorf("operation %q has conflicting idempotency keys %q and %q", record.OperationID, otherKey, record.Key)
		}
		operationReferences[record.OperationID] = record.Key
		digestBytes, err := hex.DecodeString(record.Digest)
		if err != nil || len(digestBytes) != sha256.Size {
			return fmt.Errorf("idempotency key %q has an invalid digest", record.Key)
		}
		expected, err := legacyRequestDigest(CreateRequest{
			Environment: op.Environment, Scope: op.Scope, TargetVersion: op.TargetVersion, Risk: op.Risk,
		})
		if err != nil || !bytes.Equal(digestBytes, expected[:]) {
			return fmt.Errorf("idempotency key %q conflicts with operation %q", record.Key, record.OperationID)
		}
	}
	for id := range operations {
		if _, exists := operationReferences[id]; !exists {
			return fmt.Errorf("operation %q has no idempotency record", id)
		}
	}
	return nil
}

func mapsFromSnapshot(snapshot diskSnapshot) (map[string]*Operation, map[string]idempotencyRecord, error) {
	operations := make(map[string]*Operation, len(snapshot.Operations))
	for _, persisted := range snapshot.Operations {
		op := cloneOperation(persisted)
		operations[op.ID] = &op
	}
	idempotency := make(map[string]idempotencyRecord, len(snapshot.Idempotency))
	for _, persisted := range snapshot.Idempotency {
		digestBytes, err := hex.DecodeString(persisted.Digest)
		if err != nil || len(digestBytes) != 32 {
			return nil, nil, fmt.Errorf("idempotency key %q has an invalid digest", persisted.Key)
		}
		var digest [32]byte
		copy(digest[:], digestBytes)
		idempotency[persisted.Key] = idempotencyRecord{operationID: persisted.OperationID, digest: digest}
	}
	return operations, idempotency, nil
}

func cloneOperations(source map[string]*Operation) map[string]*Operation {
	result := make(map[string]*Operation, len(source))
	for id, op := range source {
		cloned := cloneOperation(*op)
		result[id] = &cloned
	}
	return result
}

func cloneIdempotency(source map[string]idempotencyRecord) map[string]idempotencyRecord {
	result := make(map[string]idempotencyRecord, len(source))
	for key, record := range source {
		result[key] = record
	}
	return result
}
