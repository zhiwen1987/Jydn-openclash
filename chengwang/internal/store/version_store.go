package store

import (
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
	"sync"
	"time"

	"chengwang/internal/domain"
)

var versionIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

const (
	maxVersionFiles          = 1_000
	maxVersionFileBytes      = 1 << 20
	maxVersionAggregateBytes = 16 << 20
	maxCurrentPointerBytes   = 256
)

type VersionStore struct {
	dir string
	mu  sync.Mutex
}

func NewVersionStore(root string) (*VersionStore, error) {
	dir := filepath.Join(root, "versions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &VersionStore{dir: dir}, nil
}

func (s *VersionStore) CurrentID() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentID()
}

func (s *VersionStore) Publish(draft domain.PolicyDraft, author, expected string) (domain.Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.currentID()
	if err != nil {
		return domain.Version{}, err
	}
	if current != expected {
		return domain.Version{}, fmt.Errorf("version conflict: current=%q expected=%q", current, expected)
	}
	payload, err := json.Marshal(draft)
	if err != nil {
		return domain.Version{}, err
	}
	digestBytes := sha256.Sum256(payload)
	digest := hex.EncodeToString(digestBytes[:])
	now := time.Now().UTC()
	id := now.Format("20060102T150405.000000000Z") + "-" + digest[:12]
	version := domain.Version{ID: id, CreatedAt: now, Author: author, Draft: draft, Digest: digest}
	encoded, err := json.MarshalIndent(version, "", "  ")
	if err != nil {
		return domain.Version{}, err
	}
	_, fileCount, aggregateBytes, err := s.scanVersionFiles(false)
	if err != nil {
		return domain.Version{}, err
	}
	if fileCount >= maxVersionFiles {
		return domain.Version{}, fmt.Errorf("version store reached %d file limit", maxVersionFiles)
	}
	if aggregateBytes+int64(len(encoded)) > maxVersionAggregateBytes {
		return domain.Version{}, fmt.Errorf("version store would exceed %d aggregate bytes", maxVersionAggregateBytes)
	}
	if err := atomicWrite(filepath.Join(s.dir, id+".json"), encoded, 0o600); err != nil {
		return domain.Version{}, err
	}
	if err := atomicWrite(filepath.Join(s.dir, "CURRENT"), []byte(id+"\n"), 0o600); err != nil {
		return domain.Version{}, err
	}
	return version, nil
}

func (s *VersionStore) List() ([]domain.Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions, _, _, err := s.scanVersionFiles(true)
	if err != nil {
		return nil, err
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i].CreatedAt.After(versions[j].CreatedAt) })
	return versions, nil
}

// scanVersionFiles reads the directory in bounded batches. This prevents a
// corrupted or externally flooded store from forcing os.ReadDir to allocate
// an unbounded slice before the hard file quota can be enforced.
func (s *VersionStore) scanVersionFiles(load bool) ([]domain.Version, int, int64, error) {
	dir, err := os.Open(s.dir)
	if err != nil {
		return nil, 0, 0, err
	}
	defer dir.Close()
	versions := make([]domain.Version, 0)
	versionFiles := 0
	aggregateBytes := int64(0)
	for {
		entries, readDirErr := dir.ReadDir(64)
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return nil, 0, 0, fmt.Errorf("version file %s must not be a symbolic link", entry.Name())
			}
			versionFiles++
			if versionFiles > maxVersionFiles {
				return nil, 0, 0, fmt.Errorf("version store exceeds %d files", maxVersionFiles)
			}
			info, infoErr := entry.Info()
			if infoErr != nil {
				return nil, 0, 0, infoErr
			}
			if !info.Mode().IsRegular() || info.Size() > maxVersionFileBytes {
				return nil, 0, 0, fmt.Errorf("version file %s is not a bounded regular file", entry.Name())
			}
			aggregateBytes += info.Size()
			if aggregateBytes > maxVersionAggregateBytes {
				return nil, 0, 0, fmt.Errorf("version store exceeds %d aggregate bytes", maxVersionAggregateBytes)
			}
			if !load {
				continue
			}
			file, openErr := os.Open(filepath.Join(s.dir, entry.Name()))
			if openErr != nil {
				return nil, 0, 0, openErr
			}
			data, readErr := io.ReadAll(io.LimitReader(file, maxVersionFileBytes+1))
			closeErr := file.Close()
			if readErr != nil {
				return nil, 0, 0, readErr
			}
			if closeErr != nil {
				return nil, 0, 0, closeErr
			}
			if len(data) > maxVersionFileBytes {
				return nil, 0, 0, fmt.Errorf("version file %s exceeds size limit", entry.Name())
			}
			var version domain.Version
			if err := json.Unmarshal(data, &version); err != nil {
				return nil, 0, 0, fmt.Errorf("decode %s: %w", entry.Name(), err)
			}
			versions = append(versions, version)
		}
		if errors.Is(readDirErr, io.EOF) {
			break
		}
		if readDirErr != nil {
			return nil, 0, 0, readDirErr
		}
	}
	return versions, versionFiles, aggregateBytes, nil
}

func (s *VersionStore) currentID() (string, error) {
	file, err := os.Open(filepath.Join(s.dir, "CURRENT"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxCurrentPointerBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if len(data) > maxCurrentPointerBytes {
		return "", errors.New("CURRENT pointer exceeds size limit")
	}
	id := string(data)
	for len(id) > 0 && (id[len(id)-1] == '\n' || id[len(id)-1] == '\r') {
		id = id[:len(id)-1]
	}
	if id != "" && !versionIDPattern.MatchString(id) {
		return "", errors.New("invalid CURRENT pointer")
	}
	return id, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".chengwang-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
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
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
