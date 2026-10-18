package probe

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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	StartLedgerSchemaV2         = "chengwang.probe-start-ledger/v2"
	DefaultStartLedgerEntries   = 128
	MaximumStartLedgerEntries   = 512
	DefaultStartLedgerBytes     = int64(128 << 10)
	MinimumStartLedgerBytes     = int64(16 << 10)
	MaximumStartLedgerBytes     = int64(1 << 20)
	maximumLedgerSnapshotFiles  = 8
	startLedgerSnapshotsDir     = "snapshots"
	startLedgerLockFilename     = ".probe-start-ledger.lock"
	startLedgerSnapshotSuffix   = ".json"
	startLedgerTemporaryPattern = ".start-ledger-*.tmp"
)

var (
	ErrStartLedgerLocked   = errors.New("probe start ledger is locked by another writer")
	ErrStartLedgerClosed   = errors.New("probe start ledger is closed")
	ErrStartLedgerReadOnly = errors.New("probe start ledger is degraded and read-only")
	ErrStartLedgerClock    = errors.New("probe start ledger clock is invalid")
	ErrStartLedgerFull     = errors.New("probe start ledger capacity is exhausted")

	startLedgerSnapshotName = regexp.MustCompile(`^[0-9]{20}-[0-9a-f]{16}\.json$`)
)

// StartLedgerOptions bounds the complete durable ledger. Now exists so clock
// behavior can be tested deterministically; production callers normally omit
// it and use the system clock.
type StartLedgerOptions struct {
	MaxEntries int
	MaxBytes   int64
	Now        func() time.Time
}

// StartLedgerEntry contains only scheduler identity and time data. It cannot
// contain a URL, address, request data, header, or credential.
type StartLedgerEntry struct {
	StartID     string     `json:"startId"`
	ProbeID     string     `json:"probeId"`
	StartedAt   time.Time  `json:"startedAt"`
	SettledAt   *time.Time `json:"settledAt,omitempty"`
	ResultRunID string     `json:"resultRunId,omitempty"`
}

// StartLedgerRateLimit retains a verified 429 delay independently of start
// settlement. A later successful settlement never clears this fact early.
type StartLedgerRateLimit struct {
	ProbeID     string    `json:"probeId"`
	SourceRunID string    `json:"sourceRunId"`
	ObservedAt  time.Time `json:"observedAt"`
	NotBefore   time.Time `json:"notBefore"`
}

type StartLedgerSnapshot struct {
	Healthy          bool                   `json:"healthy"`
	Writable         bool                   `json:"writable"`
	Issue            string                 `json:"issue,omitempty"`
	CatalogDigest    string                 `json:"catalogDigest"`
	LastClock        time.Time              `json:"lastClock"`
	RecentStartTimes []time.Time            `json:"recentStartTimes"`
	InFlight         []StartLedgerEntry     `json:"inFlight"`
	NotBefore        map[string]time.Time   `json:"notBefore"`
	RateLimits       []StartLedgerRateLimit `json:"rateLimits,omitempty"`
}

type startLedgerDisk struct {
	Schema          string                 `json:"schema"`
	CatalogDigest   string                 `json:"catalogDigest"`
	DirectoryDigest string                 `json:"directoryDigest"`
	AgentID         string                 `json:"agentId"`
	Sequence        uint64                 `json:"sequence"`
	LastClock       time.Time              `json:"lastClock"`
	Starts          []StartLedgerEntry     `json:"starts"`
	RateLimits      []StartLedgerRateLimit `json:"rateLimits,omitempty"`
	Digest          string                 `json:"digest"`
}

type startLedgerDigestPayload struct {
	Schema          string                 `json:"schema"`
	CatalogDigest   string                 `json:"catalogDigest"`
	DirectoryDigest string                 `json:"directoryDigest"`
	AgentID         string                 `json:"agentId"`
	Sequence        uint64                 `json:"sequence"`
	LastClock       time.Time              `json:"lastClock"`
	Starts          []StartLedgerEntry     `json:"starts"`
	RateLimits      []StartLedgerRateLimit `json:"rateLimits,omitempty"`
}

type startLedgerFile struct {
	name string
	size int64
}

// StartLedger durably records starts before execution, so a restart cannot
// reset the one-minute scheduler budget. It is deliberately independent from
// result evidence storage.
type StartLedger struct {
	mu              sync.Mutex
	directory       string
	snapshotDir     string
	binding         catalogBinding
	directoryDigest string
	maxEntries      int
	maxBytes        int64
	state           startLedgerDisk
	lastSeen        time.Time
	files           []startLedgerFile
	bytes           int64
	lock            *spoolProcessLock
	now             func() time.Time
	healthy         bool
	writable        bool
	issue           string
	closed          bool
	removeFile      func(string) error
	syncDir         func(string) error
}

// OpenStartLedger opens one exclusive writer and restores the newest valid
// snapshot. Every snapshot is bound to both the exact directory and catalog.
func OpenStartLedger(directory string, catalog Catalog, options StartLedgerOptions) (*StartLedger, error) {
	binding, err := bindCatalog(catalog)
	if err != nil {
		return nil, fmt.Errorf("bind start ledger catalog: %w", err)
	}
	maxEntries, maxBytes, err := normalizeStartLedgerLimits(options.MaxEntries, options.MaxBytes)
	if err != nil {
		return nil, err
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	now := options.Now()
	if now.IsZero() || now.UnixNano() < 0 {
		return nil, errors.New("start ledger current time is invalid")
	}
	absDirectory, snapshotDir, err := secureStartLedgerDirectory(directory)
	if err != nil {
		return nil, err
	}
	lock, err := acquireSpoolProcessLock(filepath.Join(absDirectory, startLedgerLockFilename))
	if err != nil {
		if errors.Is(err, ErrSpoolLocked) {
			return nil, ErrStartLedgerLocked
		}
		return nil, fmt.Errorf("acquire start ledger writer lock: %w", err)
	}
	opened := false
	defer func() {
		if !opened {
			_ = lock.release()
		}
	}()

	ledger := &StartLedger{
		directory: absDirectory, snapshotDir: snapshotDir, binding: binding,
		directoryDigest: digestStartLedgerDirectory(absDirectory),
		maxEntries:      maxEntries, maxBytes: maxBytes, lock: lock, now: options.Now,
		healthy: true, writable: true, removeFile: os.Remove, syncDir: syncSpoolDirectory,
	}
	if err := cleanupStartLedgerTemps(snapshotDir); err != nil {
		return nil, fmt.Errorf("clean interrupted start ledger snapshot: %w", err)
	}
	state, files, totalBytes, err := readStartLedgerSnapshots(snapshotDir, binding, ledger.directoryDigest, maxEntries, maxBytes, now)
	if err != nil {
		return nil, err
	}
	ledger.files = files
	ledger.bytes = totalBytes
	if state == nil {
		initial := startLedgerDisk{
			Schema: StartLedgerSchemaV2, CatalogDigest: binding.digest,
			DirectoryDigest: ledger.directoryDigest, AgentID: binding.agentID,
			Sequence: 1, LastClock: now,
		}
		if _, err := ledger.persistLocked(initial); err != nil {
			return nil, fmt.Errorf("initialize start ledger: %w", err)
		}
		ledger.state = initial
		ledger.lastSeen = now
	} else {
		ledger.state = *state
		ledger.lastSeen = state.LastClock
		if err := ledger.removeOldSnapshotsLocked(); err != nil {
			return nil, fmt.Errorf("compact start ledger snapshots: %w", err)
		}
	}
	opened = true
	return ledger, nil
}

// RecordStart must be called before the network attempt begins. A successful
// return proves the one-minute budget fact is durable.
func (l *StartLedger) RecordStart(startID, probeID string, startedAt time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now, err := l.mutableClockLocked()
	if err != nil {
		return err
	}
	if !spoolIdentityPattern.MatchString(startID) || !idPattern.MatchString(probeID) {
		return errors.New("start ledger identity is invalid")
	}
	if _, known := l.binding.targets[probeID]; !known {
		return errors.New("start ledger probe is not in the bound catalog")
	}
	if startedAt.IsZero() || startedAt.UnixNano() < 0 || startedAt.After(now) || !startedAt.After(now.Add(-time.Minute)) {
		l.degradeLocked("start_time_invalid")
		return ErrStartLedgerClock
	}
	candidate := cloneStartLedgerState(l.state)
	pruneStartLedgerState(&candidate, now)
	for _, entry := range candidate.Starts {
		if entry.StartID == startID {
			return errors.New("start ledger start ID already exists")
		}
	}
	if len(candidate.Starts) >= l.maxEntries {
		return ErrStartLedgerFull
	}
	// Persist the ledger's own commit clock rather than trusting a caller's
	// slightly earlier sample. This keeps concurrent settle/start operations
	// ordered without weakening rollback detection, which is enforced by
	// mutableClockLocked before every mutation.
	candidate.Starts = append(candidate.Starts, StartLedgerEntry{StartID: startID, ProbeID: probeID, StartedAt: now})
	candidate.LastClock = now
	return l.commitLocked(candidate)
}

// Settle binds an independently generated start ID to a fully verified probe
// result. The start remains in the minute budget; a verified 429 extends
// NotBefore. StartID is separate because Runner creates RunID inside the task.
func (l *StartLedger) Settle(startID string, result ProbeResult) error {
	return l.settle(startID, result, true)
}

// SettleRecovered repairs a crash boundary where immutable result evidence
// was committed before ledger settlement. Expiry is not corruption, so
// historical evidence is allowed; future-dated data remains rejected.
func (l *StartLedger) SettleRecovered(startID string, result ProbeResult) error {
	return l.settle(startID, result, false)
}

func (l *StartLedger) settle(startID string, result ProbeResult, requireFresh bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now, err := l.mutableClockLocked()
	if err != nil {
		return err
	}
	if !spoolIdentityPattern.MatchString(startID) {
		return errors.New("start ledger start ID is invalid")
	}
	if result.EvidenceRef != startID {
		return errors.New("start ledger settlement evidence reference mismatch")
	}
	if reason := validateSpoolResult(result, l.binding, now, 0, true, requireFresh); reason != "" {
		if reason == "future_result" {
			l.degradeLocked("future_time_invalid")
			return ErrStartLedgerClock
		}
		return fmt.Errorf("invalid start ledger settlement: %s", reason)
	}
	candidate := cloneStartLedgerState(l.state)
	pruneStartLedgerState(&candidate, now)
	index := -1
	for i := range candidate.Starts {
		if candidate.Starts[i].StartID == startID {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("start ledger start ID is not active")
	}
	entry := &candidate.Starts[index]
	if entry.ProbeID != result.ProbeID || result.AttemptedAt.Before(entry.StartedAt) {
		return errors.New("start ledger settlement does not match its start")
	}
	if entry.SettledAt != nil {
		if entry.ResultRunID == result.RunID && entry.SettledAt.Equal(result.CompletedAt) {
			return nil
		}
		return errors.New("start ledger run is already settled")
	}
	completed := result.CompletedAt
	entry.SettledAt = &completed
	entry.ResultRunID = result.RunID
	if retrySeconds := result.Layers.Business.RetryAfterSeconds; result.Conclusion == ConclusionRateLimited && retrySeconds > 0 {
		fact := StartLedgerRateLimit{
			ProbeID: result.ProbeID, SourceRunID: result.RunID,
			ObservedAt: result.CompletedAt,
			NotBefore:  result.CompletedAt.Add(time.Duration(retrySeconds) * time.Second),
		}
		mergeStartLedgerRateLimit(&candidate, fact)
	}
	candidate.LastClock = now
	return l.commitLocked(candidate)
}

// Snapshot returns only starts still inside the one-minute budget, unresolved
// in-flight attempts, and unexpired verified rate-limit facts.
func (l *StartLedger) Snapshot() (StartLedgerSnapshot, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return StartLedgerSnapshot{}, ErrStartLedgerClosed
	}
	if !l.writable {
		return l.snapshotLocked(l.state.LastClock), ErrStartLedgerReadOnly
	}
	now := l.now()
	if now.IsZero() || now.UnixNano() < 0 || now.Before(l.lastSeen) {
		l.degradeLocked("clock_rollback")
		return l.snapshotLocked(now), ErrStartLedgerClock
	}
	l.lastSeen = now
	return l.snapshotLocked(now), nil
}

func (l *StartLedger) Health() StartLedgerSnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return l.snapshotLocked(l.state.LastClock)
	}
	now := l.now()
	if now.IsZero() || now.UnixNano() < 0 || now.Before(l.lastSeen) {
		l.degradeLocked("clock_rollback")
		return l.snapshotLocked(l.state.LastClock)
	}
	l.lastSeen = now
	return l.snapshotLocked(now)
}

func (l *StartLedger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	l.writable = false
	if l.lock == nil {
		return nil
	}
	err := l.lock.release()
	l.lock = nil
	return err
}

func (l *StartLedger) mutableClockLocked() (time.Time, error) {
	if l.closed {
		return time.Time{}, ErrStartLedgerClosed
	}
	if !l.writable {
		return time.Time{}, ErrStartLedgerReadOnly
	}
	now := l.now()
	if now.IsZero() || now.UnixNano() < 0 || now.Before(l.lastSeen) {
		l.degradeLocked("clock_rollback")
		return time.Time{}, ErrStartLedgerClock
	}
	l.lastSeen = now
	return now, nil
}

func (l *StartLedger) commitLocked(candidate startLedgerDisk) error {
	if l.state.Sequence == ^uint64(0) {
		l.degradeLocked("sequence_exhausted")
		return ErrStartLedgerReadOnly
	}
	candidate.Sequence = l.state.Sequence + 1
	candidate.Schema = StartLedgerSchemaV2
	candidate.CatalogDigest = l.binding.digest
	candidate.DirectoryDigest = l.directoryDigest
	candidate.AgentID = l.binding.agentID
	committed, err := l.persistLocked(candidate)
	if committed {
		l.state = candidate
	}
	if err != nil {
		l.degradeLocked("persistence_failed")
		return err
	}
	return nil
}

func (l *StartLedger) persistLocked(candidate startLedgerDisk) (bool, error) {
	if reason := validateStartLedgerState(candidate, l.binding, l.directoryDigest, l.maxEntries, candidate.LastClock); reason != "" {
		return false, fmt.Errorf("invalid start ledger state: %s", reason)
	}
	digest, err := digestStartLedgerState(candidate)
	if err != nil {
		return false, err
	}
	candidate.Digest = digest
	payload, err := json.Marshal(candidate)
	if err != nil {
		return false, err
	}
	// A second complete snapshot must fit beside the current one so a mutation
	// never needs to destroy its rollback point before committing.
	if int64(len(payload)) > l.maxBytes/2 || l.bytes+int64(len(payload)) > l.maxBytes {
		return false, ErrStartLedgerFull
	}
	name := startLedgerFileName(candidate)
	destination := filepath.Join(l.snapshotDir, name)
	if _, err := os.Lstat(destination); err == nil {
		return false, errors.New("start ledger snapshot already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect start ledger destination: %w", err)
	}
	temporary, err := os.CreateTemp(l.snapshotDir, startLedgerTemporaryPattern)
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false, err
	}
	if _, err := temporary.Write(payload); err != nil {
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return false, err
	}
	committed = true
	l.files = append(l.files, startLedgerFile{name: name, size: int64(len(payload))})
	l.bytes += int64(len(payload))
	if err := l.syncDir(l.snapshotDir); err != nil {
		return true, err
	}
	if err := l.removeOldSnapshotsLocked(); err != nil {
		return true, err
	}
	return true, nil
}

func (l *StartLedger) removeOldSnapshotsLocked() error {
	if len(l.files) <= 1 {
		return nil
	}
	sort.Slice(l.files, func(i, j int) bool { return l.files[i].name < l.files[j].name })
	keep := l.files[len(l.files)-1]
	for _, file := range l.files[:len(l.files)-1] {
		if err := l.removeFile(filepath.Join(l.snapshotDir, file.name)); err != nil {
			return err
		}
		l.bytes -= file.size
	}
	l.files = []startLedgerFile{keep}
	return l.syncDir(l.snapshotDir)
}

func (l *StartLedger) snapshotLocked(now time.Time) StartLedgerSnapshot {
	result := StartLedgerSnapshot{
		Healthy: !l.closed && l.healthy, Writable: !l.closed && l.writable,
		Issue: l.issue, CatalogDigest: l.binding.digest, LastClock: l.state.LastClock,
		NotBefore: make(map[string]time.Time),
	}
	cutoff := now.Add(-time.Minute - MaximumStartPersistenceDelay)
	for _, entry := range l.state.Starts {
		if entry.StartedAt.After(cutoff) && !entry.StartedAt.After(now) {
			budgetTime := entry.StartedAt.Add(MaximumStartPersistenceDelay)
			if budgetTime.After(now) {
				budgetTime = now
			}
			result.RecentStartTimes = append(result.RecentStartTimes, budgetTime)
			if entry.SettledAt == nil {
				result.InFlight = append(result.InFlight, entry)
			}
		}
	}
	for _, fact := range l.state.RateLimits {
		if fact.NotBefore.After(now) {
			result.RateLimits = append(result.RateLimits, fact)
			if fact.NotBefore.After(result.NotBefore[fact.ProbeID]) {
				result.NotBefore[fact.ProbeID] = fact.NotBefore
			}
		}
	}
	sort.Slice(result.RecentStartTimes, func(i, j int) bool { return result.RecentStartTimes[i].Before(result.RecentStartTimes[j]) })
	sort.Slice(result.InFlight, func(i, j int) bool { return result.InFlight[i].StartedAt.Before(result.InFlight[j].StartedAt) })
	sort.Slice(result.RateLimits, func(i, j int) bool { return result.RateLimits[i].ProbeID < result.RateLimits[j].ProbeID })
	return result
}

func (l *StartLedger) degradeLocked(issue string) {
	l.healthy = false
	l.writable = false
	if l.issue == "" {
		l.issue = issue
	}
}

func cloneStartLedgerState(source startLedgerDisk) startLedgerDisk {
	copyState := source
	copyState.Starts = append([]StartLedgerEntry(nil), source.Starts...)
	copyState.RateLimits = append([]StartLedgerRateLimit(nil), source.RateLimits...)
	copyState.Digest = ""
	return copyState
}

func pruneStartLedgerState(state *startLedgerDisk, now time.Time) {
	cutoff := now.Add(-time.Minute - MaximumStartPersistenceDelay)
	starts := state.Starts[:0]
	for _, entry := range state.Starts {
		if entry.StartedAt.After(cutoff) {
			starts = append(starts, entry)
		}
	}
	state.Starts = starts
	limits := state.RateLimits[:0]
	for _, fact := range state.RateLimits {
		if fact.NotBefore.After(now) {
			limits = append(limits, fact)
		}
	}
	state.RateLimits = limits
}

func mergeStartLedgerRateLimit(state *startLedgerDisk, fact StartLedgerRateLimit) {
	for i := range state.RateLimits {
		if state.RateLimits[i].ProbeID == fact.ProbeID {
			if fact.NotBefore.After(state.RateLimits[i].NotBefore) {
				state.RateLimits[i] = fact
			}
			return
		}
	}
	state.RateLimits = append(state.RateLimits, fact)
}

func normalizeStartLedgerLimits(entries int, bytesLimit int64) (int, int64, error) {
	if entries == 0 {
		entries = DefaultStartLedgerEntries
	}
	if bytesLimit == 0 {
		bytesLimit = DefaultStartLedgerBytes
	}
	if entries < 1 || entries > MaximumStartLedgerEntries {
		return 0, 0, fmt.Errorf("start ledger entry limit must be between 1 and %d", MaximumStartLedgerEntries)
	}
	if bytesLimit < MinimumStartLedgerBytes || bytesLimit > MaximumStartLedgerBytes {
		return 0, 0, fmt.Errorf("start ledger byte limit must be between %d and %d", MinimumStartLedgerBytes, MaximumStartLedgerBytes)
	}
	return entries, bytesLimit, nil
}

func secureStartLedgerDirectory(directory string) (string, string, error) {
	if strings.TrimSpace(directory) == "" {
		return "", "", errors.New("start ledger directory is required")
	}
	absDirectory, err := filepath.Abs(directory)
	if err != nil {
		return "", "", fmt.Errorf("resolve start ledger directory: %w", err)
	}
	if err := rejectSymlinkPathComponents(absDirectory); err != nil {
		return "", "", err
	}
	info, err := os.Lstat(absDirectory)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(absDirectory, 0o700); err != nil {
			return "", "", fmt.Errorf("create start ledger directory: %w", err)
		}
		info, err = os.Lstat(absDirectory)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", "", errors.New("start ledger path must be a real directory")
	}
	if err := os.Chmod(absDirectory, 0o700); err != nil {
		return "", "", fmt.Errorf("restrict start ledger directory: %w", err)
	}
	snapshotDir := filepath.Join(absDirectory, startLedgerSnapshotsDir)
	snapshotInfo, snapshotErr := os.Lstat(snapshotDir)
	if errors.Is(snapshotErr, os.ErrNotExist) {
		if err := os.Mkdir(snapshotDir, 0o700); err != nil {
			return "", "", fmt.Errorf("create start ledger snapshot directory: %w", err)
		}
		snapshotInfo, snapshotErr = os.Lstat(snapshotDir)
	}
	if snapshotErr != nil || snapshotInfo.Mode()&os.ModeSymlink != 0 || !snapshotInfo.IsDir() {
		return "", "", errors.New("start ledger snapshot path must be a real directory")
	}
	if err := os.Chmod(snapshotDir, 0o700); err != nil {
		return "", "", fmt.Errorf("restrict start ledger snapshot directory: %w", err)
	}
	return absDirectory, snapshotDir, nil
}

func readStartLedgerSnapshots(directory string, binding catalogBinding, directoryDigest string, maxEntries int, maxBytes int64, now time.Time) (*startLedgerDisk, []startLedgerFile, int64, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, nil, 0, err
	}
	if len(entries) > maximumLedgerSnapshotFiles {
		return nil, nil, 0, errors.New("start ledger snapshot directory entry limit exceeded")
	}
	files := make([]startLedgerFile, 0, len(entries))
	states := make([]startLedgerDisk, 0, len(entries))
	var totalBytes int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || entry.Type()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !startLedgerSnapshotName.MatchString(entry.Name()) {
			return nil, nil, 0, fmt.Errorf("unexpected start ledger snapshot entry %q", entry.Name())
		}
		if info.Size() <= 0 || info.Size() > maxBytes/2 || info.Size() > maxBytes-totalBytes {
			return nil, nil, 0, errors.New("start ledger snapshot byte limit exceeded")
		}
		totalBytes += info.Size()
		state, err := readStartLedgerSnapshot(filepath.Join(directory, entry.Name()), binding, directoryDigest, maxEntries, now, maxBytes/2)
		if err != nil {
			return nil, nil, 0, err
		}
		if startLedgerFileName(state) != entry.Name() {
			return nil, nil, 0, errors.New("start ledger snapshot filename mismatch")
		}
		files = append(files, startLedgerFile{name: entry.Name(), size: info.Size()})
		states = append(states, state)
	}
	if len(states) == 0 {
		return nil, files, totalBytes, nil
	}
	sort.Slice(states, func(i, j int) bool { return states[i].Sequence < states[j].Sequence })
	for i := 1; i < len(states); i++ {
		if states[i].Sequence == states[i-1].Sequence {
			return nil, nil, 0, errors.New("duplicate start ledger sequence")
		}
	}
	latest := states[len(states)-1]
	return &latest, files, totalBytes, nil
}

// cleanupStartLedgerTemps removes only regular, non-symlink temporary files
// created by os.CreateTemp in persistLocked. The exclusive ledger lock is held
// by the caller, so these can only be remnants of an interrupted prior writer.
// Every other unexpected directory entry remains a fail-closed error.
func cleanupStartLedgerTemps(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".start-ledger-") || !strings.HasSuffix(name, ".tmp") {
			continue
		}
		info, err := entry.Info()
		if err != nil || entry.Type()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("unsafe interrupted start ledger entry %q", name)
		}
		if err := os.Remove(filepath.Join(directory, name)); err != nil {
			return err
		}
	}
	return syncSpoolDirectory(directory)
}

func readStartLedgerSnapshot(path string, binding catalogBinding, directoryDigest string, maxEntries int, now time.Time, maxBytes int64) (startLedgerDisk, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBytes {
		return startLedgerDisk{}, errors.New("start ledger snapshot is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return startLedgerDisk{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return startLedgerDisk{}, errors.New("start ledger snapshot identity changed")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(payload)) > maxBytes {
		return startLedgerDisk{}, errors.New("start ledger snapshot read failed")
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return startLedgerDisk{}, errors.New("start ledger snapshot has duplicate JSON keys")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var state startLedgerDisk
	if err := decoder.Decode(&state); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return startLedgerDisk{}, errors.New("start ledger snapshot JSON is invalid")
	}
	if reason := validateStartLedgerState(state, binding, directoryDigest, maxEntries, now); reason != "" {
		return startLedgerDisk{}, fmt.Errorf("invalid start ledger snapshot: %s", reason)
	}
	expected, err := digestStartLedgerState(state)
	if err != nil || state.Digest != expected {
		return startLedgerDisk{}, errors.New("start ledger snapshot digest mismatch")
	}
	return state, nil
}

func validateStartLedgerState(state startLedgerDisk, binding catalogBinding, directoryDigest string, maxEntries int, now time.Time) string {
	if state.Schema != StartLedgerSchemaV2 || state.CatalogDigest != binding.digest || state.DirectoryDigest != directoryDigest || state.AgentID != binding.agentID || state.Sequence == 0 {
		return "binding_invalid"
	}
	if state.LastClock.IsZero() || state.LastClock.UnixNano() < 0 || state.LastClock.After(now) {
		return "clock_invalid"
	}
	if len(state.Starts) > maxEntries || len(state.RateLimits) > len(binding.targets) {
		return "entry_limit"
	}
	seenRuns := make(map[string]struct{}, len(state.Starts))
	for _, entry := range state.Starts {
		if !spoolIdentityPattern.MatchString(entry.StartID) || !idPattern.MatchString(entry.ProbeID) {
			return "identity_invalid"
		}
		if _, known := binding.targets[entry.ProbeID]; !known {
			return "catalog_membership_mismatch"
		}
		if _, duplicate := seenRuns[entry.StartID]; duplicate {
			return "duplicate_start_id"
		}
		seenRuns[entry.StartID] = struct{}{}
		if entry.StartedAt.IsZero() || entry.StartedAt.UnixNano() < 0 || entry.StartedAt.After(state.LastClock) {
			return "start_time_invalid"
		}
		if entry.SettledAt != nil {
			if entry.SettledAt.Before(entry.StartedAt) || entry.SettledAt.After(state.LastClock) {
				return "settlement_time_invalid"
			}
			if !spoolIdentityPattern.MatchString(entry.ResultRunID) {
				return "settlement_identity_invalid"
			}
		} else if entry.ResultRunID != "" {
			return "settlement_identity_invalid"
		}
	}
	seenLimits := make(map[string]struct{}, len(state.RateLimits))
	for _, fact := range state.RateLimits {
		if !idPattern.MatchString(fact.ProbeID) || !spoolIdentityPattern.MatchString(fact.SourceRunID) {
			return "rate_limit_identity_invalid"
		}
		if _, known := binding.targets[fact.ProbeID]; !known {
			return "catalog_membership_mismatch"
		}
		if _, duplicate := seenLimits[fact.ProbeID]; duplicate {
			return "duplicate_rate_limit"
		}
		seenLimits[fact.ProbeID] = struct{}{}
		if fact.ObservedAt.IsZero() || fact.ObservedAt.After(state.LastClock) || !fact.NotBefore.After(fact.ObservedAt) || fact.NotBefore.Sub(fact.ObservedAt) > maxRetryAfter {
			return "rate_limit_time_invalid"
		}
	}
	return ""
}

func digestStartLedgerState(state startLedgerDisk) (string, error) {
	payload := startLedgerDigestPayload{
		Schema: state.Schema, CatalogDigest: state.CatalogDigest,
		DirectoryDigest: state.DirectoryDigest, AgentID: state.AgentID,
		Sequence: state.Sequence, LastClock: state.LastClock,
		Starts: state.Starts, RateLimits: state.RateLimits,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func startLedgerFileName(state startLedgerDisk) string {
	digest := strings.TrimPrefix(state.Digest, "sha256:")
	if len(digest) > 16 {
		digest = digest[:16]
	}
	return fmt.Sprintf("%020d-%s%s", state.Sequence, digest, startLedgerSnapshotSuffix)
}

func digestStartLedgerDirectory(directory string) string {
	digest := sha256.Sum256([]byte(filepath.Clean(directory)))
	return "sha256:" + hex.EncodeToString(digest[:])
}
