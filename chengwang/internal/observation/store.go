package observation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	storeSchemaVersion = 1
	storeDirectoryName = "samples"
	storeLockName      = ".observation.lock"
	maxSampleBytes     = 4 << 10
	defaultMaxSamples  = 4096
	maxDirectoryItems  = defaultMaxSamples * 2
)

var (
	ErrStoreLocked   = errors.New("observation store is locked by another controller")
	ErrStoreClosed   = errors.New("observation store is closed")
	ErrStoreReadOnly = errors.New("observation store is degraded and read-only")
)

type diskSample struct {
	Version int    `json:"version"`
	Sample  Sample `json:"sample"`
}

// Store persists each bounded sample as one atomically created segment. This
// avoids rewriting the entire history every collection cycle. Corrupt segments
// are preserved for operator inspection, excluded from API history, and make
// Healthy return false without preventing the control plane from starting.
type Store struct {
	mu          sync.RWMutex
	directory   string
	sampleDir   string
	maxSamples  int
	samples     []Sample
	files       []string
	processLock *processLock
	healthy     bool
	issue       string
	writable    bool
	closed      bool
	removeFile  func(string) error
	syncDir     func(string) error
}

func OpenStore(directory string, maxSamples int) (*Store, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return nil, errors.New("observation store directory is required")
	}
	if maxSamples <= 0 {
		maxSamples = defaultMaxSamples
	}
	if maxSamples > defaultMaxSamples {
		return nil, fmt.Errorf("observation sample limit exceeds %d", defaultMaxSamples)
	}
	absDirectory, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve observation store directory: %w", err)
	}
	if err := ensurePrivateDirectory(absDirectory); err != nil {
		return nil, err
	}
	lock, err := acquireProcessLock(filepath.Join(absDirectory, storeLockName))
	if err != nil {
		return nil, fmt.Errorf("acquire observation store lock: %w", err)
	}
	opened := false
	defer func() {
		if !opened {
			_ = lock.release()
		}
	}()
	sampleDir := filepath.Join(absDirectory, storeDirectoryName)
	if err := ensurePrivateDirectory(sampleDir); err != nil {
		return nil, err
	}
	samples, files, healthy, issue, writable, err := loadSegments(sampleDir, maxSamples, maxDirectoryItems)
	if err != nil {
		return nil, err
	}
	s := &Store{
		directory: absDirectory, sampleDir: sampleDir, maxSamples: maxSamples,
		samples: samples, files: files, processLock: lock, healthy: healthy, issue: issue,
		writable: writable, removeFile: os.Remove, syncDir: syncDirectory,
	}
	opened = true
	return s, nil
}

func ensurePrivateDirectory(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("observation store path must be a real directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect observation store directory: %w", err)
	} else if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create observation store directory: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("restrict observation store directory: %w", err)
	}
	return nil
}

func (s *Store) Append(sample Sample) error {
	if err := validateSample(sample); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if !s.writable {
		return ErrStoreReadOnly
	}
	if len(s.samples) > 0 {
		last := s.samples[len(s.samples)-1]
		if sample.Sequence <= last.Sequence || sample.AttemptedAt.Before(last.CompletedAt) {
			return errors.New("observation sample ordering is invalid")
		}
	}
	// Retire the oldest segment before publishing the replacement. This keeps
	// the on-disk set bounded even if deletion fails or the host crashes between
	// retention and publication. A failed publication may lose one old telemetry
	// sample, but it can never grow the store without bound.
	if len(s.samples) >= s.maxSamples {
		oldest := filepath.Join(s.sampleDir, s.files[0])
		if err := s.removeFile(oldest); err != nil {
			s.degradeLocked("retention_delete_failed")
			s.writable = false
			return fmt.Errorf("remove expired observation segment: %w", err)
		}
		s.samples = s.samples[1:]
		s.files = s.files[1:]
		if err := s.syncDir(s.sampleDir); err != nil {
			s.degradeLocked("retention_sync_failed")
			s.writable = false
			return fmt.Errorf("sync observation segment directory after retention: %w", err)
		}
	}
	name := sampleFileName(sample)
	path := filepath.Join(s.sampleDir, name)
	if _, err := os.Lstat(path); err == nil {
		return errors.New("observation sample file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect observation sample path: %w", err)
	}
	committed, err := writeSampleAtomically(s.sampleDir, path, sample)
	if err != nil {
		s.degradeLocked("sample_write_failed")
		if committed {
			s.samples = append(s.samples, sample)
			s.files = append(s.files, name)
			s.writable = false
		}
		return err
	}
	s.samples = append(s.samples, sample)
	s.files = append(s.files, name)
	return nil
}

func (s *Store) List(limit int) []Sample {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.samples) {
		limit = len(s.samples)
	}
	start := len(s.samples) - limit
	result := make([]Sample, limit)
	copy(result, s.samples[start:])
	return result
}

func (s *Store) Last() (Sample, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.samples) == 0 {
		return Sample{}, false
	}
	return s.samples[len(s.samples)-1], true
}

func (s *Store) Healthy() (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.closed && s.healthy, s.issue
}

func (s *Store) Close() error {
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

func (s *Store) degradeLocked(issue string) {
	s.healthy = false
	if s.issue == "" {
		s.issue = issue
	}
}

func loadSegments(directory string, maxSamples, maxItems int) ([]Sample, []string, bool, string, bool, error) {
	dir, err := os.Open(directory)
	if err != nil {
		return nil, nil, false, "", false, fmt.Errorf("open observation segment directory: %w", err)
	}
	defer dir.Close()
	names := make([]string, 0, maxSamples)
	healthy, issue := true, ""
	writable := true
	totalEntries := 0
	scanComplete := true
scan:
	for {
		entries, readErr := dir.ReadDir(128)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return nil, nil, false, "", false, fmt.Errorf("list observation segments: %w", readErr)
		}
		for _, entry := range entries {
			totalEntries++
			if totalEntries > maxItems {
				healthy, issue = false, firstIssue(issue, "directory_entry_limit")
				writable = false
				scanComplete = false
				break scan
			}
			if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".json") {
				names = append(names, entry.Name())
			} else {
				healthy, issue = false, firstIssue(issue, "unexpected_directory_entry")
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	sort.Strings(names)
	samples := make([]Sample, 0, min(len(names), maxSamples))
	validNames := make([]string, 0, cap(samples))
	for _, name := range names {
		sample, err := readSampleFile(filepath.Join(directory, name))
		if err != nil || name != sampleFileName(sample) {
			healthy, issue = false, firstIssue(issue, "corrupt_segment")
			continue
		}
		if len(samples) > 0 {
			last := samples[len(samples)-1]
			if sample.Sequence <= last.Sequence || sample.AttemptedAt.Before(last.CompletedAt) {
				healthy, issue = false, firstIssue(issue, "segment_ordering_invalid")
				continue
			}
		}
		samples = append(samples, sample)
		validNames = append(validNames, name)
	}
	if len(samples) > maxSamples {
		excess := len(samples) - maxSamples
		deletedAny := false
		for index := 0; index < excess; index++ {
			if err := os.Remove(filepath.Join(directory, validNames[index])); err != nil {
				healthy, issue = false, firstIssue(issue, "retention_recovery_failed")
				writable = false
				break
			}
			deletedAny = true
		}
		if deletedAny {
			if err := syncDirectory(directory); err != nil {
				healthy, issue = false, firstIssue(issue, "retention_sync_failed")
				writable = false
			}
		}
		start := len(samples) - maxSamples
		samples = append([]Sample(nil), samples[start:]...)
		validNames = append([]string(nil), validNames[start:]...)
	}
	if !scanComplete {
		writable = false
	}
	return samples, validNames, healthy, issue, writable, nil
}

func readSampleFile(path string) (Sample, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Sample{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxSampleBytes {
		return Sample{}, errors.New("observation segment is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return Sample{}, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxSampleBytes+1))
	if err != nil || len(contents) > maxSampleBytes {
		return Sample{}, errors.New("observation segment exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var record diskSample
	if err := decoder.Decode(&record); err != nil {
		return Sample{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF || record.Version != storeSchemaVersion {
		return Sample{}, errors.New("observation segment schema is invalid")
	}
	if err := validateSample(record.Sample); err != nil {
		return Sample{}, err
	}
	return record.Sample, nil
}

func writeSampleAtomically(directory, destination string, sample Sample) (bool, error) {
	payload, err := json.Marshal(diskSample{Version: storeSchemaVersion, Sample: sample})
	if err != nil {
		return false, err
	}
	if len(payload) > maxSampleBytes {
		return false, errors.New("observation segment exceeds size limit")
	}
	temporary, err := os.CreateTemp(directory, ".sample-*.tmp")
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
	if err := syncDirectory(directory); err != nil {
		return true, err
	}
	return true, nil
}

func sampleFileName(sample Sample) string {
	return fmt.Sprintf("%020d-%020d.json", sample.Sequence, sample.CompletedAt.UnixNano())
}

func firstIssue(current, next string) string {
	if current != "" {
		return current
	}
	return next
}

func validateSample(sample Sample) error {
	if sample.Sequence == 0 || sample.AttemptedAt.IsZero() || sample.CompletedAt.IsZero() || sample.CompletedAt.Before(sample.AttemptedAt) {
		return errors.New("observation sample time or sequence is invalid")
	}
	if sample.CompletedAt.UnixNano() < 0 {
		return errors.New("observation sample time is outside the supported range")
	}
	if sample.DurationMillis < 0 || sample.ProxyObjectCount < 0 || sample.SelectorGroupCount < 0 || sample.LeafProxyCount < 0 || sample.RuleCount < 0 {
		return errors.New("observation sample contains negative values")
	}
	if sample.Success && sample.ErrorClass != "" {
		return errors.New("successful observation must not contain an error class")
	}
	if len(sample.ControllerVersion) > 128 {
		return errors.New("controller version exceeds length limit")
	}
	if sample.ProxyObjectCount > 20_000 || sample.SelectorGroupCount > 20_000 || sample.LeafProxyCount > 20_000 || sample.RuleCount > 50_000 {
		return errors.New("observation sample count exceeds limit")
	}
	if sample.Success && sample.SelectorGroupCount+sample.LeafProxyCount != sample.ProxyObjectCount {
		return errors.New("successful observation proxy counts are inconsistent")
	}
	if !sample.Success {
		switch sample.ErrorClass {
		case "timeout", "authentication", "upstream_http", "network", "read_failed":
		default:
			return errors.New("failed observation has an invalid error class")
		}
		if sample.ControllerVersion != "" || sample.ProxyObjectCount != 0 || sample.SelectorGroupCount != 0 || sample.LeafProxyCount != 0 || sample.RuleCount != 0 {
			return errors.New("failed observation must not contain runtime summary fields")
		}
	}
	return nil
}
