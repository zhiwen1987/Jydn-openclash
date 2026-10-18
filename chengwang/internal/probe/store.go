package probe

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const spoolLockFilename = ".probe-spool.lock"

var (
	ErrSpoolLocked   = errors.New("probe spool is locked by another writer")
	ErrSpoolClosed   = errors.New("probe spool is closed")
	ErrSpoolReadOnly = errors.New("probe spool is degraded and read-only")
)

type StoreLimits struct {
	MaxEntries int
	MaxBytes   int64
}

type StoreHealth struct {
	Healthy      bool   `json:"healthy"`
	Writable     bool   `json:"writable"`
	Issue        string `json:"issue,omitempty"`
	Entries      int    `json:"entries"`
	Bytes        int64  `json:"bytes"`
	ValidResults int    `json:"validResults"`
}

// Store is an independent, single-writer probe spool. Each result is an
// immutable segment and no observation/evidence lock or directory is shared.
type Store struct {
	mu         sync.RWMutex
	directory  string
	segmentDir string
	binding    catalogBinding
	maxEntries int
	maxBytes   int64
	entries    int
	bytes      int64
	segments   []spoolMeta
	runIDs     map[string]struct{}
	lock       *spoolProcessLock
	healthy    bool
	writable   bool
	issue      string
	closed     bool
	now        func() time.Time
	removeFile func(string) error
	syncDir    func(string) error
}

func OpenStore(directory string, catalog Catalog, limits StoreLimits) (*Store, error) {
	binding, err := bindCatalog(catalog)
	if err != nil {
		return nil, fmt.Errorf("bind probe catalog: %w", err)
	}
	maxEntries, maxBytes, err := normalizeSpoolLimits(limits.MaxEntries, limits.MaxBytes)
	if err != nil {
		return nil, err
	}
	absDirectory, err := secureSpoolDirectory(directory, true)
	if err != nil {
		return nil, err
	}
	lock, err := acquireSpoolProcessLock(filepath.Join(absDirectory, spoolLockFilename))
	if err != nil {
		return nil, fmt.Errorf("acquire probe spool writer lock: %w", err)
	}
	opened := false
	defer func() {
		if !opened {
			_ = lock.release()
		}
	}()
	segmentDir := filepath.Join(absDirectory, spoolSegmentsDirectory)
	now := time.Now()
	scan, err := scanSpoolSegments(segmentDir, binding, now, defaultFutureSkew, false, false, maxEntries, maxBytes)
	if err != nil {
		return nil, err
	}
	store := &Store{
		directory: absDirectory, segmentDir: segmentDir, binding: binding,
		maxEntries: maxEntries, maxBytes: maxBytes, entries: scan.totalEntries, bytes: scan.totalBytes,
		segments: append([]spoolMeta(nil), scan.valid...), runIDs: make(map[string]struct{}, len(scan.valid)),
		lock: lock, healthy: len(scan.issues) == 0, writable: true, now: time.Now,
		removeFile: os.Remove, syncDir: syncSpoolDirectory,
	}
	if len(scan.issues) > 0 {
		store.issue = scan.issues[0].Reason
	}
	for _, meta := range scan.valid {
		store.runIDs[meta.result.RunID] = struct{}{}
	}
	if err := store.trimForLocked(0, 0); err != nil {
		store.degradeLocked("startup_retention_failed", true)
	}
	opened = true
	return store, nil
}

func (s *Store) Append(result ProbeResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSpoolClosed
	}
	if !s.writable {
		return ErrSpoolReadOnly
	}
	if reason := validateSpoolResult(result, s.binding, s.now(), defaultFutureSkew, true, true); reason != "" {
		return fmt.Errorf("invalid probe result: %s", reason)
	}
	if _, exists := s.runIDs[result.RunID]; exists {
		return errors.New("probe result run ID already exists")
	}
	digest, err := spoolContentDigest(SpoolSchemaV1, s.binding.digest, result)
	if err != nil {
		return err
	}
	segment := spoolSegment{Schema: SpoolSchemaV1, CatalogDigest: s.binding.digest, Result: result, Digest: digest}
	payload, err := json.Marshal(segment)
	if err != nil {
		return err
	}
	if int64(len(payload)) > MaximumSpoolSegmentBytes {
		return errors.New("probe spool segment exceeds size limit")
	}
	name := spoolSegmentFileName(segment)
	destination := filepath.Join(s.segmentDir, name)
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("probe spool segment already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect probe spool destination: %w", err)
	}
	if err := s.trimForLocked(1, int64(len(payload))); err != nil {
		s.degradeLocked("retention_failed", true)
		return err
	}
	committed, err := writeSpoolSegmentAtomically(s.segmentDir, destination, payload, s.syncDir)
	if err != nil {
		s.degradeLocked("segment_write_failed", committed)
		if committed {
			s.entries++
			s.bytes += int64(len(payload))
			s.segments = append(s.segments, spoolMeta{name: name, size: int64(len(payload)), result: result})
			s.runIDs[result.RunID] = struct{}{}
		}
		return err
	}
	s.entries++
	s.bytes += int64(len(payload))
	s.segments = append(s.segments, spoolMeta{name: name, size: int64(len(payload)), result: result})
	s.runIDs[result.RunID] = struct{}{}
	return nil
}

func (s *Store) trimForLocked(addEntries int, addBytes int64) error {
	removed := false
	for s.entries+addEntries > s.maxEntries || s.bytes+addBytes > s.maxBytes {
		if len(s.segments) == 0 {
			s.degradeLocked("spool_limit_blocked_by_unmanaged_entries", true)
			return errors.New("probe spool cannot reclaim enough bounded space")
		}
		oldest := s.segments[0]
		if err := s.removeFile(filepath.Join(s.segmentDir, oldest.name)); err != nil {
			s.degradeLocked("retention_delete_failed", true)
			return fmt.Errorf("remove expired probe segment: %w", err)
		}
		delete(s.runIDs, oldest.result.RunID)
		s.segments = s.segments[1:]
		s.entries--
		s.bytes -= oldest.size
		removed = true
	}
	if removed {
		if err := s.syncDir(s.segmentDir); err != nil {
			s.degradeLocked("retention_sync_failed", true)
			return err
		}
	}
	return nil
}

func (s *Store) Health() StoreHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return StoreHealth{
		Healthy: !s.closed && s.healthy, Writable: !s.closed && s.writable,
		Issue: s.issue, Entries: s.entries, Bytes: s.bytes, ValidResults: len(s.segments),
	}
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.writable = false
	if s.lock == nil {
		return nil
	}
	err := s.lock.release()
	s.lock = nil
	return err
}

func (s *Store) degradeLocked(issue string, readOnly bool) {
	s.healthy = false
	if s.issue == "" {
		s.issue = issue
	}
	if readOnly {
		s.writable = false
	}
}

func writeSpoolSegmentAtomically(directory, destination string, payload []byte, syncDir func(string) error) (bool, error) {
	temporary, err := os.CreateTemp(directory, ".probe-*.tmp")
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
	if err := syncDir(directory); err != nil {
		return true, err
	}
	return true, nil
}
