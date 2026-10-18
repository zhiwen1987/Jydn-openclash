package lease

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	schemaVersion    = 1
	snapshotName     = "leases.json"
	lockName         = ".leases.lock"
	maxSnapshotBytes = 4 << 20
	maxRecords       = 10_000
)

type storeOptions struct{ clock Clock }

type record struct {
	Scope     Scope  `json:"scope"`
	LastToken uint64 `json:"lastToken"`
	Lease     *Lease `json:"lease,omitempty"`
}

type snapshot struct {
	Version        int       `json:"version"`
	LastObservedAt time.Time `json:"lastObservedAt"`
	Records        []record  `json:"records"`
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

type snapshotWriter func(string, snapshot) writeResult

// FileStore persists all fencing history in one atomically replaced snapshot.
// It deliberately permits one writer process per directory; it is not a
// distributed lease or consensus service.
type FileStore struct {
	mu            sync.Mutex
	directory     string
	directoryInfo os.FileInfo
	path          string
	snapshotInfo  os.FileInfo
	snapshotHash  [sha256.Size]byte
	lockPath      string
	lockInfo      os.FileInfo
	records       map[string]record
	lastObserved  time.Time
	clock         Clock
	write         snapshotWriter
	processLock   *processLock
	closed        bool
	poisoned      error
}

// NewFileStore opens or creates a private durable lease store.
func NewFileStore(directory string, options ...Option) (*FileStore, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return nil, errors.New("lease store directory is required")
	}
	configuration := storeOptions{clock: ClockFunc(func() time.Time { return time.Now().UTC() })}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("nil lease store option")
		}
		if err := option(&configuration); err != nil {
			return nil, err
		}
	}
	abs, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve lease directory: %w", err)
	}
	if err := ensurePrivateDirectory(abs); err != nil {
		return nil, err
	}
	directoryInfo, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("inspect lease directory: %w", err)
	}
	lockPath := filepath.Join(abs, lockName)
	processLock, err := acquireProcessLock(lockPath)
	if err != nil {
		return nil, fmt.Errorf("acquire lease store lock: %w", err)
	}
	opened := false
	defer func() {
		if !opened {
			_ = processLock.release()
		}
	}()
	lockInfo, err := os.Lstat(lockPath)
	if err != nil || !lockInfo.Mode().IsRegular() {
		return nil, errors.New("lease store lock is not a regular file")
	}
	if err := requirePermissions("lease store lock", lockInfo, 0o600); err != nil {
		return nil, err
	}
	currentDirectoryInfo, err := os.Lstat(abs)
	if err != nil || !currentDirectoryInfo.IsDir() || !os.SameFile(directoryInfo, currentDirectoryInfo) {
		return nil, errors.New("lease directory changed while acquiring writer lock")
	}

	now := configuration.clock.Now().UTC()
	if now.IsZero() {
		return nil, errors.New("lease clock returned zero time")
	}
	store := &FileStore{
		directory: abs, directoryInfo: directoryInfo, path: filepath.Join(abs, snapshotName),
		lockPath: lockPath, lockInfo: lockInfo, records: make(map[string]record),
		clock: configuration.clock, write: writeSnapshotAtomically, processLock: processLock,
	}
	contents, openedSnapshotInfo, err := readSnapshot(store.path)
	switch {
	case err == nil:
		loaded, err := decodeSnapshot(contents)
		if err != nil {
			return nil, fmt.Errorf("load lease snapshot: %w", err)
		}
		if now.Before(loaded.LastObservedAt) {
			return nil, fmt.Errorf("%w: current %s precedes persisted %s", ErrClockRollback, now, loaded.LastObservedAt)
		}
		store.lastObserved = loaded.LastObservedAt
		for _, item := range loaded.Records {
			store.records[scopeKey(item.Scope)] = cloneRecord(item)
		}
		store.snapshotInfo = openedSnapshotInfo
		store.snapshotHash = sha256.Sum256(contents)
	case errors.Is(err, os.ErrNotExist):
		store.lastObserved = now
		result := store.write(store.path, store.makeSnapshot(store.records, now))
		if err := commitError(result); err != nil {
			return nil, fmt.Errorf("initialize lease snapshot: %w", err)
		}
		contents, store.snapshotInfo, err = readSnapshot(store.path)
		if err != nil {
			return nil, fmt.Errorf("read initialized lease snapshot: %w", err)
		}
		store.snapshotHash = sha256.Sum256(contents)
	default:
		return nil, fmt.Errorf("read lease snapshot: %w", err)
	}
	if err != nil || !store.snapshotInfo.Mode().IsRegular() {
		return nil, errors.New("lease snapshot is not a regular file after opening")
	}
	if err := requirePermissions("lease snapshot", store.snapshotInfo, 0o600); err != nil {
		return nil, err
	}
	opened = true
	return store, nil
}

// Acquire creates a lease when the scope is free or expired. Every successful
// acquisition increments the scope's persisted fencing token.
func (s *FileStore) Acquire(scope Scope, owner string, ttl time.Duration) (Lease, error) {
	scope, owner, err := validateRequest(scope, owner, ttl)
	if err != nil {
		return Lease{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now, err := s.usableNowLocked()
	if err != nil {
		return Lease{}, err
	}
	key := scopeKey(scope)
	current := s.records[key]
	if current.Lease != nil && now.Before(current.Lease.ExpiresAt) {
		return Lease{}, ErrLeaseHeld
	}
	if current.LastToken == math.MaxUint64 {
		return Lease{}, ErrTokenExhausted
	}
	token := current.LastToken + 1
	lease := Lease{Scope: scope, Owner: owner, Token: token, AcquiredAt: now, RenewedAt: now, ExpiresAt: now.Add(ttl)}
	if !lease.ExpiresAt.After(now) {
		return Lease{}, errors.New("lease expiry overflowed clock range")
	}
	candidate := cloneRecords(s.records)
	candidate[key] = record{Scope: scope, LastToken: token, Lease: &lease}
	if err := s.commitLocked(candidate, now); err != nil {
		return Lease{}, fmt.Errorf("persist lease acquisition: %w", err)
	}
	return lease, nil
}

// Renew extends a live lease only when both owner and fencing token match.
func (s *FileStore) Renew(scope Scope, owner string, token uint64, ttl time.Duration) (Lease, error) {
	scope, owner, err := validateRequest(scope, owner, ttl)
	if err != nil {
		return Lease{}, err
	}
	if token == 0 {
		return Lease{}, ErrTokenMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now, err := s.usableNowLocked()
	if err != nil {
		return Lease{}, err
	}
	current, ok := s.records[scopeKey(scope)]
	if !ok || current.Lease == nil {
		return Lease{}, ErrLeaseNotHeld
	}
	if current.Lease.Owner != owner {
		return Lease{}, ErrOwnerMismatch
	}
	if current.Lease.Token != token {
		return Lease{}, ErrTokenMismatch
	}
	if !now.Before(current.Lease.ExpiresAt) {
		return Lease{}, ErrLeaseExpired
	}
	lease := *current.Lease
	lease.RenewedAt, lease.ExpiresAt = now, now.Add(ttl)
	if !lease.ExpiresAt.After(now) {
		return Lease{}, errors.New("lease expiry overflowed clock range")
	}
	candidate := cloneRecords(s.records)
	updated := candidate[scopeKey(scope)]
	updated.Lease = &lease
	candidate[scopeKey(scope)] = updated
	if err := s.commitLocked(candidate, now); err != nil {
		return Lease{}, fmt.Errorf("persist lease renewal: %w", err)
	}
	return lease, nil
}

// Release frees a live lease while retaining its fencing-token history.
func (s *FileStore) Release(scope Scope, owner string, token uint64) error {
	var err error
	scope, err = normalizeScope(scope)
	if err != nil {
		return err
	}
	owner, err = normalizeOwner(owner)
	if err != nil {
		return err
	}
	if token == 0 {
		return ErrTokenMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now, err := s.usableNowLocked()
	if err != nil {
		return err
	}
	key := scopeKey(scope)
	current, ok := s.records[key]
	if !ok || current.Lease == nil {
		return ErrLeaseNotHeld
	}
	if current.Lease.Owner != owner {
		return ErrOwnerMismatch
	}
	if current.Lease.Token != token {
		return ErrTokenMismatch
	}
	if !now.Before(current.Lease.ExpiresAt) {
		return ErrLeaseExpired
	}
	candidate := cloneRecords(s.records)
	current.Lease = nil
	candidate[key] = current
	if err := s.commitLocked(candidate, now); err != nil {
		return fmt.Errorf("persist lease release: %w", err)
	}
	return nil
}

// Get returns the active lease for scope. Expired leases remain in the durable
// record until takeover, but are never reported as active.
func (s *FileStore) Get(scope Scope) (Lease, error) {
	scope, err := normalizeScope(scope)
	if err != nil {
		return Lease{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now, err := s.usableNowLocked()
	if err != nil {
		return Lease{}, err
	}
	current, ok := s.records[scopeKey(scope)]
	if !ok || current.Lease == nil {
		return Lease{}, ErrLeaseNotHeld
	}
	if !now.Before(current.Lease.ExpiresAt) {
		return Lease{}, ErrLeaseExpired
	}
	return *current.Lease, nil
}

func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.processLock.release()
	s.processLock = nil
	return err
}

func (s *FileStore) usableNowLocked() (time.Time, error) {
	if s.closed {
		return time.Time{}, ErrStoreClosed
	}
	if s.poisoned != nil {
		return time.Time{}, errors.Join(ErrStorePoisoned, s.poisoned)
	}
	if err := s.ensureIdentityLocked(); err != nil {
		return time.Time{}, s.poisonLocked(err)
	}
	now := s.clock.Now().UTC()
	if now.IsZero() {
		return time.Time{}, s.poisonLocked(errors.New("clock returned zero time"))
	}
	if now.Before(s.lastObserved) {
		return time.Time{}, s.poisonLocked(fmt.Errorf("%w: current %s precedes %s", ErrClockRollback, now, s.lastObserved))
	}
	// Remember observations within this process even when an operation is
	// rejected, preventing a later backward jump from reviving an old lease.
	s.lastObserved = now
	return now, nil
}

func (s *FileStore) commitLocked(records map[string]record, now time.Time) error {
	candidateSnapshot := s.makeSnapshot(records, now)
	result := s.write(s.path, candidateSnapshot)
	if result.state == commitUncertain {
		return s.poisonLocked(commitError(result))
	}
	if err := commitError(result); err != nil {
		return err
	}
	committedBytes, committedInfo, err := readSnapshot(s.path)
	if err != nil {
		return s.poisonLocked(errors.New("committed lease snapshot is unavailable or not regular"))
	}
	if s.snapshotInfo != nil && os.SameFile(s.snapshotInfo, committedInfo) {
		return s.poisonLocked(errors.New("committed lease snapshot was not atomically replaced"))
	}
	if err := requirePermissions("lease snapshot", committedInfo, 0o600); err != nil {
		return s.poisonLocked(err)
	}
	expectedBytes, err := encodeSnapshot(candidateSnapshot)
	if err != nil || !bytes.Equal(expectedBytes, committedBytes) {
		return s.poisonLocked(errors.New("committed lease snapshot does not match candidate state"))
	}
	s.snapshotInfo = committedInfo
	s.snapshotHash = sha256.Sum256(committedBytes)
	s.records, s.lastObserved = records, now
	return nil
}

func (s *FileStore) poisonLocked(cause error) error {
	if cause == nil {
		cause = ErrCommitUncertain
	}
	if s.poisoned == nil {
		s.poisoned = cause
	}
	return errors.Join(ErrStorePoisoned, s.poisoned)
}

func (s *FileStore) ensureIdentityLocked() error {
	directoryInfo, err := os.Lstat(s.directory)
	if err != nil || !directoryInfo.IsDir() || !os.SameFile(s.directoryInfo, directoryInfo) {
		return errors.New("lease directory was replaced")
	}
	if err := requirePermissions("lease directory", directoryInfo, 0o700); err != nil {
		return err
	}
	lockInfo, err := os.Lstat(s.lockPath)
	if err != nil || !lockInfo.Mode().IsRegular() || !os.SameFile(s.lockInfo, lockInfo) {
		return errors.New("lease writer lock was replaced")
	}
	if err := requirePermissions("lease store lock", lockInfo, 0o600); err != nil {
		return err
	}
	snapshotBytes, snapshotInfo, err := readSnapshot(s.path)
	if err != nil || s.snapshotInfo == nil || !os.SameFile(s.snapshotInfo, snapshotInfo) {
		return errors.New("lease snapshot was replaced outside the store")
	}
	if sha256.Sum256(snapshotBytes) != s.snapshotHash {
		return errors.New("lease snapshot contents changed outside the store")
	}
	return nil
}

func validateRequest(scope Scope, owner string, ttl time.Duration) (Scope, string, error) {
	scope, err := normalizeScope(scope)
	if err != nil {
		return Scope{}, "", err
	}
	owner, err = normalizeOwner(owner)
	if err != nil {
		return Scope{}, "", err
	}
	if err := validateTTL(ttl); err != nil {
		return Scope{}, "", err
	}
	return scope, owner, nil
}

func scopeKey(scope Scope) string {
	return scope.Tenant + "\x00" + scope.Site + "\x00" + scope.Object + "\x00" + scope.Environment
}

func cloneRecord(value record) record {
	if value.Lease != nil {
		lease := *value.Lease
		value.Lease = &lease
	}
	return value
}

func cloneRecords(source map[string]record) map[string]record {
	result := make(map[string]record, len(source))
	for key, value := range source {
		result[key] = cloneRecord(value)
	}
	return result
}

func (s *FileStore) makeSnapshot(records map[string]record, observed time.Time) snapshot {
	result := snapshot{Version: schemaVersion, LastObservedAt: observed.UTC(), Records: make([]record, 0, len(records))}
	for _, value := range records {
		result.Records = append(result.Records, cloneRecord(value))
	}
	sort.Slice(result.Records, func(i, j int) bool { return scopeKey(result.Records[i].Scope) < scopeKey(result.Records[j].Scope) })
	return result
}

func validateSnapshot(value snapshot) error {
	if value.Version != schemaVersion {
		return fmt.Errorf("unsupported lease snapshot version %d", value.Version)
	}
	if value.LastObservedAt.IsZero() || value.LastObservedAt.Location() != time.UTC {
		return errors.New("lastObservedAt must be a UTC timestamp")
	}
	if len(value.Records) > maxRecords {
		return ErrStoreLimit
	}
	seen := make(map[string]struct{}, len(value.Records))
	for index := range value.Records {
		item := &value.Records[index]
		normalized, err := normalizeScope(item.Scope)
		if err != nil || normalized != item.Scope {
			return fmt.Errorf("record %d has non-canonical scope", index)
		}
		key := scopeKey(item.Scope)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate scope at record %d", index)
		}
		seen[key] = struct{}{}
		if item.LastToken == 0 {
			return fmt.Errorf("record %d has zero fencing history", index)
		}
		if item.Lease == nil {
			continue
		}
		lease := item.Lease
		owner, err := normalizeOwner(lease.Owner)
		if err != nil || owner != lease.Owner {
			return fmt.Errorf("record %d has invalid owner", index)
		}
		if lease.Scope != item.Scope || lease.Token == 0 || lease.Token != item.LastToken {
			return fmt.Errorf("record %d has invalid fencing identity", index)
		}
		if lease.AcquiredAt.IsZero() || lease.RenewedAt.Before(lease.AcquiredAt) || !lease.ExpiresAt.After(lease.RenewedAt) {
			return fmt.Errorf("record %d has invalid timestamps", index)
		}
		if lease.AcquiredAt.Location() != time.UTC || lease.RenewedAt.Location() != time.UTC || lease.ExpiresAt.Location() != time.UTC {
			return fmt.Errorf("record %d timestamps must be UTC", index)
		}
		if lease.ExpiresAt.Sub(lease.RenewedAt) < MinTTL || lease.ExpiresAt.Sub(lease.RenewedAt) > MaxTTL {
			return fmt.Errorf("record %d has invalid TTL", index)
		}
		if lease.RenewedAt.After(value.LastObservedAt) {
			return fmt.Errorf("record %d was renewed after lastObservedAt", index)
		}
	}
	return nil
}

func decodeSnapshot(contents []byte) (snapshot, error) {
	if len(contents) > maxSnapshotBytes {
		return snapshot{}, ErrStoreLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var result snapshot
	if err := decoder.Decode(&result); err != nil {
		return snapshot{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return snapshot{}, errors.New("multiple JSON values")
		}
		return snapshot{}, err
	}
	if err := validateSnapshot(result); err != nil {
		return snapshot{}, err
	}
	return result, nil
}

func readSnapshot(path string) ([]byte, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, errors.New("lease snapshot must be a regular file, not a symlink")
	}
	if err := requirePermissions("lease snapshot", before, 0o600); err != nil {
		return nil, nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, nil, errors.New("lease snapshot changed while opening")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(contents) > maxSnapshotBytes {
		return nil, nil, ErrStoreLimit
	}
	// Bind the decoded bytes to the still-current path entry. Without this
	// second comparison, a same-user replacement between ReadAll and return
	// could make in-memory state diverge from the snapshot identity we track.
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(after, current) {
		return nil, nil, errors.New("lease snapshot changed after reading")
	}
	return contents, current, nil
}

func writeSnapshotAtomically(path string, value snapshot) writeResult {
	return writeSnapshotWithSync(path, value, syncDirectory)
}

func writeSnapshotWithSync(path string, value snapshot, syncDir func(string) error) writeResult {
	if err := validateSnapshot(value); err != nil {
		return writeResult{state: commitNotCommitted, err: err}
	}
	encoded, err := encodeSnapshot(value)
	if err != nil {
		return writeResult{state: commitNotCommitted, err: err}
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".leases.tmp-")
	if err != nil {
		return writeResult{state: commitNotCommitted, err: err}
	}
	temporaryPath := temporary.Name()
	renamed := false
	defer func() {
		_ = temporary.Close()
		if !renamed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return writeResult{state: commitNotCommitted, err: err}
	}
	if _, err := temporary.Write(encoded); err != nil {
		return writeResult{state: commitNotCommitted, err: err}
	}
	if err := temporary.Sync(); err != nil {
		return writeResult{state: commitNotCommitted, err: err}
	}
	temporaryInfo, err := temporary.Stat()
	if err != nil {
		return writeResult{state: commitNotCommitted, err: err}
	}
	if err := temporary.Close(); err != nil {
		return writeResult{state: commitNotCommitted, err: err}
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return writeResult{state: commitNotCommitted, err: err}
	}
	renamed = true
	committedInfo, err := os.Lstat(path)
	if err != nil || !committedInfo.Mode().IsRegular() || !os.SameFile(temporaryInfo, committedInfo) {
		return writeResult{state: commitUncertain, err: errors.New("replaced lease snapshot identity is uncertain")}
	}
	if err := requirePermissions("lease snapshot", committedInfo, 0o600); err != nil {
		return writeResult{state: commitUncertain, err: err}
	}
	if err := syncDir(directory); err != nil {
		return writeResult{state: commitUncertain, err: err}
	}
	return writeResult{state: commitCommitted}
}

func encodeSnapshot(value snapshot) ([]byte, error) {
	if err := validateSnapshot(value); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxSnapshotBytes {
		return nil, ErrStoreLimit
	}
	return encoded, nil
}

func commitError(result writeResult) error {
	switch result.state {
	case commitCommitted:
		if result.err != nil {
			return fmt.Errorf("committed snapshot reported error: %w", result.err)
		}
		return nil
	case commitUncertain:
		if result.err == nil {
			return ErrCommitUncertain
		}
		return errors.Join(ErrCommitUncertain, result.err)
	case commitNotCommitted:
		if result.err == nil {
			return errors.New("lease snapshot did not commit")
		}
		return result.err
	default:
		return errors.New("unknown lease commit state")
	}
}

func ensurePrivateDirectory(directory string) error {
	if err := rejectSymlinkComponents(directory, true); err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create lease directory: %w", err)
	}
	if err := rejectSymlinkComponents(directory, false); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() {
		return errors.New("lease directory is not a directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("restrict lease directory: %w", err)
	}
	return nil
}

func rejectSymlinkComponents(path string, allowMissing bool) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(abs)
	remainder := strings.TrimLeft(strings.TrimPrefix(abs, volume), string(os.PathSeparator))
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
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("lease path component %q must not be a symbolic link", current)
		}
	}
	return nil
}

func requirePermissions(name string, info os.FileInfo, expected os.FileMode) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm() != expected || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("%s permissions must be %04o", name, expected)
	}
	return nil
}
