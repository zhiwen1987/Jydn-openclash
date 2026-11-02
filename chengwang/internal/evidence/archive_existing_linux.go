//go:build linux

package evidence

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"chengwang/internal/nativefs"
)

const archiveExistingOpenFlags = syscall.O_CLOEXEC | syscall.O_NOFOLLOW

var archiveEvidenceNames = []string{checkpointFilename, logFilename, lockFilename}

type existingArchiveDirectory struct {
	file     *os.File
	name     string
	path     string
	identity syscall.Stat_t
	leaf     bool
}

type existingArchiveSnapshotState struct {
	mu         sync.Mutex
	chain      []existingArchiveDirectory
	lock       *os.File
	log        *os.File
	checkpoint *os.File
	limits     ArchiveExistingReadLimits
	closed     bool
}

type archiveCheckpointRead struct {
	value checkpoint
	stat  syscall.Stat_t
	hash  [32]byte
	raw   []byte
}

type archiveEntrySetValue struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type archiveHashCounter struct {
	hash hash.Hash
	size uint64
}

func (w *archiveHashCounter) Write(value []byte) (int, error) {
	n, err := w.hash.Write(value)
	w.size += uint64(n)
	return n, err
}

// OpenExistingArchiveSnapshot opens and verifies only already-existing source
// state. It never calls Open and contains no create, repair, or write path.
func OpenExistingArchiveSnapshot(root string, limits ArchiveExistingReadLimits) (*ExistingArchiveSnapshot, error) {
	if limits.MaxLogBytes == 0 || limits.MaxLogBytes > uint64(math.MaxInt64-1) || limits.MaxEvents == 0 {
		return nil, ErrArchiveExistingLimit
	}
	chain, err := archiveOpenExistingDirectory(root)
	if err != nil {
		return nil, ErrArchiveExistingUnsafe
	}
	snapshot := &ExistingArchiveSnapshot{state: &existingArchiveSnapshotState{chain: chain, limits: limits}}
	keep := false
	defer func() {
		if !keep {
			_ = snapshot.closeLocked()
		}
	}()
	leaf := snapshot.state.directory()
	if _, ok := archiveNativeClass(leaf); !ok {
		return nil, ErrArchiveExistingUnsafe
	}
	if err := archiveRequireExactEntries(leaf); err != nil {
		return nil, ErrArchiveExistingUnsafe
	}
	lock, err := archiveOpenAt(leaf, lockFilename, syscall.O_RDWR)
	if err != nil {
		return nil, ErrArchiveExistingUnsafe
	}
	snapshot.state.lock = lock
	if _, err := archiveValidateRegular(lock, true); err != nil {
		return nil, ErrArchiveExistingUnsafe
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrStoreLocked
		}
		return nil, ErrArchiveExistingUnsafe
	}
	logFile, err := archiveOpenAt(leaf, logFilename, syscall.O_RDONLY|syscall.O_NONBLOCK)
	if err != nil {
		return nil, ErrArchiveExistingUnsafe
	}
	snapshot.state.log = logFile
	if _, err := archiveValidateRegular(logFile, false); err != nil {
		return nil, ErrArchiveExistingUnsafe
	}
	checkpointFile, err := archiveOpenAt(leaf, checkpointFilename, syscall.O_RDONLY|syscall.O_NONBLOCK)
	if err != nil {
		return nil, ErrArchiveExistingUnsafe
	}
	snapshot.state.checkpoint = checkpointFile
	if _, err := archiveValidateRegular(checkpointFile, false); err != nil {
		return nil, ErrArchiveExistingUnsafe
	}
	anchor, err := snapshot.captureLocked()
	if err != nil {
		if errors.Is(err, ErrArchiveExistingLimit) {
			return nil, ErrArchiveExistingLimit
		}
		return nil, ErrArchiveExistingUnsafe
	}
	snapshot.anchor = anchor
	keep = true
	return snapshot, nil
}

// Revalidate repeats full stable reads and compares to the immutable Open-time
// anchor. It never updates that cache.
func (s *ExistingArchiveSnapshot) Revalidate() error {
	if s == nil || s.state == nil {
		return ErrStoreClosed
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if s.state.closed {
		return ErrStoreClosed
	}
	anchor, err := s.captureLocked()
	if errors.Is(err, ErrArchiveExistingLimit) {
		return ErrArchiveExistingLimit
	}
	if err != nil || anchor != s.anchor {
		return ErrArchiveExistingUnsafe
	}
	return nil
}

// Close releases every retained descriptor even after an earlier close error.
func (s *ExistingArchiveSnapshot) Close() error {
	if s == nil {
		return nil
	}
	if s.state == nil {
		return nil
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if s.state.closed {
		return nil
	}
	s.state.closed = true
	if s.closeLocked() != nil {
		return ErrStoreClosed
	}
	return nil
}

func (s *ExistingArchiveSnapshot) closeLocked() error {
	if s == nil || s.state == nil {
		return nil
	}
	var result error
	closeFile := func(file **os.File) {
		if *file == nil {
			return
		}
		result = errors.Join(result, (*file).Close())
		*file = nil
	}
	closeFile(&s.state.checkpoint)
	closeFile(&s.state.log)
	if s.state.lock != nil {
		result = errors.Join(result, syscall.Flock(int(s.state.lock.Fd()), syscall.LOCK_UN))
		closeFile(&s.state.lock)
	}
	for i := len(s.state.chain) - 1; i >= 0; i-- {
		result = errors.Join(result, s.state.chain[i].file.Close())
	}
	s.state.chain = nil
	return result
}

func (s *ExistingArchiveSnapshot) captureLocked() (ArchiveEvidenceAnchor, error) {
	var empty ArchiveEvidenceAnchor
	if s == nil || s.state == nil {
		return empty, ErrStoreClosed
	}
	if err := archiveRevalidateChain(s.state.chain); err != nil {
		return empty, err
	}
	leaf := s.state.directory()
	if _, ok := archiveNativeClass(leaf); !ok {
		return empty, ErrArchiveExistingUnsafe
	}
	if err := archiveRequireExactEntries(leaf); err != nil {
		return empty, err
	}
	files := []struct {
		name string
		file *os.File
	}{
		{lockFilename, s.state.lock},
		{logFilename, s.state.log},
		{checkpointFilename, s.state.checkpoint},
	}
	stats := make(map[string]syscall.Stat_t, len(files))
	for _, value := range files {
		st, err := archiveValidateRegular(value.file, value.name == lockFilename)
		if err != nil || archiveEnsureNamed(leaf, value.name, value.file, st) != nil {
			return empty, ErrArchiveExistingUnsafe
		}
		stats[value.name] = st
	}
	cpRead, err := archiveReadCheckpoint(s.state.checkpoint)
	if err != nil {
		return empty, err
	}
	eventCount, eventHead, logStat, logHash, err := archiveReadAndVerifyLog(
		leaf,
		s.state.log,
		s.state.checkpoint,
		cpRead,
		s.state.limits,
	)
	if err != nil {
		return empty, err
	}
	lockStat, lockHash, err := archiveReadZeroLock(s.state.lock)
	if err != nil {
		return empty, err
	}
	stats[lockFilename] = lockStat
	stats[logFilename] = logStat
	stats[checkpointFilename] = cpRead.stat
	for _, value := range files {
		if archiveEnsureNamed(leaf, value.name, value.file, stats[value.name]) != nil {
			return empty, ErrArchiveExistingUnsafe
		}
	}
	if err := archiveRequireExactEntries(leaf); err != nil {
		return empty, err
	}
	rootStat, err := archiveFstat(leaf)
	if err != nil || !archiveDirectorySafe(rootStat, true, s.state.chain[len(s.state.chain)-1].path) {
		return empty, ErrArchiveExistingUnsafe
	}
	entryHash, err := archiveEntrySetHash(stats)
	if err != nil {
		return empty, err
	}
	eventDigest, ok := archiveHexDigest(eventHead)
	if !ok {
		return empty, ErrArchiveExistingUnsafe
	}
	cpDigest, ok := archiveHexDigest(cpRead.value.LastHash)
	if !ok || eventCount != cpRead.value.Count || eventDigest != cpDigest {
		return empty, ErrArchiveExistingUnsafe
	}
	return ArchiveEvidenceAnchor{
		Root: ArchiveDirectoryAnchor{
			Identity:       archiveIdentity(rootStat),
			EntryCount:     uint32(len(archiveEvidenceNames)),
			EntrySetSHA256: entryHash,
		},
		Lock:            ArchiveFileAnchor{Identity: archiveIdentity(lockStat), Length: 0, SHA256: lockHash},
		Log:             ArchiveFileAnchor{Identity: archiveIdentity(logStat), Length: uint64(logStat.Size), SHA256: logHash},
		Checkpoint:      ArchiveFileAnchor{Identity: archiveIdentity(cpRead.stat), Length: uint64(cpRead.stat.Size), SHA256: cpRead.hash},
		EventCount:      eventCount,
		EventHead:       eventDigest,
		CheckpointCount: cpRead.value.Count,
		CheckpointHead:  cpDigest,
	}, nil
}

func (s *existingArchiveSnapshotState) directory() *os.File {
	return s.chain[len(s.chain)-1].file
}

func archiveOpenExistingDirectory(path string) ([]existingArchiveDirectory, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, ErrArchiveExistingUnsafe
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|archiveExistingOpenFlags, 0)
	if err != nil {
		return nil, ErrArchiveExistingUnsafe
	}
	root := os.NewFile(uintptr(fd), "/")
	rootStat, err := archiveFstat(root)
	if err != nil || !archiveDirectorySafeOwner(rootStat, false, "/", uid, gid) {
		_ = root.Close()
		return nil, ErrArchiveExistingUnsafe
	}
	chain := []existingArchiveDirectory{{file: root, path: "/", identity: rootStat}}
	keep := false
	defer func() {
		if !keep {
			for i := len(chain) - 1; i >= 0; i-- {
				_ = chain[i].file.Close()
			}
		}
	}()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := ""
	for i, name := range parts {
		if name == "" || name == "." || name == ".." {
			return nil, ErrArchiveExistingUnsafe
		}
		parent := chain[len(chain)-1].file
		parentBefore, err := archiveFstat(parent)
		if err != nil {
			return nil, ErrArchiveExistingUnsafe
		}
		child, err := archiveOpenAt(parent, name, syscall.O_RDONLY|syscall.O_DIRECTORY)
		if err != nil {
			return nil, ErrArchiveExistingUnsafe
		}
		childStat, statErr := archiveFstat(child)
		parentAfter, parentErr := archiveFstat(parent)
		current += "/" + name
		leaf := i == len(parts)-1
		if statErr != nil || parentErr != nil || !archiveSameStat(parentBefore, parentAfter, false, false) || !archiveDirectorySafeOwner(childStat, leaf, current, uid, gid) {
			_ = child.Close()
			return nil, ErrArchiveExistingUnsafe
		}
		chain = append(chain, existingArchiveDirectory{file: child, name: name, path: current, identity: childStat, leaf: leaf})
	}
	keep = true
	return chain, nil
}

func archiveRevalidateChain(chain []existingArchiveDirectory) error {
	if len(chain) < 2 {
		return ErrArchiveExistingUnsafe
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	for i := range chain {
		current, err := archiveFstat(chain[i].file)
		if err != nil || !archiveDirectorySafeOwner(current, chain[i].leaf, chain[i].path, uid, gid) || !archiveSameStat(current, chain[i].identity, false, chain[i].leaf) {
			return ErrArchiveExistingUnsafe
		}
		if i == 0 {
			continue
		}
		reopened, err := archiveOpenAt(chain[i-1].file, chain[i].name, syscall.O_RDONLY|syscall.O_DIRECTORY)
		if err != nil {
			return ErrArchiveExistingUnsafe
		}
		reopenedStat, statErr := archiveFstat(reopened)
		closeErr := reopened.Close()
		if statErr != nil || closeErr != nil || !archiveSameStat(reopenedStat, chain[i].identity, false, chain[i].leaf) {
			return ErrArchiveExistingUnsafe
		}
	}
	return nil
}

func archiveOpenAt(directory *os.File, name string, flags int) (*os.File, error) {
	fd, err := syscall.Openat(int(directory.Fd()), name, flags|archiveExistingOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func archiveFstat(file *os.File) (syscall.Stat_t, error) {
	var value syscall.Stat_t
	if file == nil || syscall.Fstat(int(file.Fd()), &value) != nil {
		return value, ErrArchiveExistingUnsafe
	}
	return value, nil
}

func archiveDirectorySafe(value syscall.Stat_t, leaf bool, path string) bool {
	return archiveDirectorySafeOwner(value, leaf, path, uint32(os.Geteuid()), uint32(os.Getegid()))
}

func archiveDirectorySafeOwner(value syscall.Stat_t, leaf bool, path string, uid, gid uint32) bool {
	if value.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return false
	}
	if leaf {
		return value.Uid == uid && value.Gid == gid && value.Mode&07777 == 0700
	}
	if path == "/tmp" && value.Uid == 0 && value.Mode&07777 == 01777 {
		return true
	}
	return (value.Uid == 0 || value.Uid == uid) && value.Mode&0022 == 0 && value.Mode&07000 == 0
}

func archiveSameStat(a, b syscall.Stat_t, content, exactDirectoryLinks bool) bool {
	if a.Dev != b.Dev || a.Ino != b.Ino || a.Mode != b.Mode || a.Uid != b.Uid || a.Gid != b.Gid {
		return false
	}
	directory := a.Mode&syscall.S_IFMT == syscall.S_IFDIR
	if !directory || exactDirectoryLinks {
		if a.Nlink != b.Nlink {
			return false
		}
	}
	return !content || a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func archiveNativeClass(file *os.File) (nativefs.LinuxClass, bool) {
	var value syscall.Statfs_t
	if file == nil || syscall.Fstatfs(int(file.Fd()), &value) != nil {
		return nativefs.LinuxUnknown, false
	}
	return nativefs.ClassifyLinuxMagic(int64(value.Type))
}

func archiveValidateRegular(file *os.File, zero bool) (syscall.Stat_t, error) {
	value, err := archiveFstat(file)
	if err != nil {
		return value, err
	}
	if value.Mode&syscall.S_IFMT != syscall.S_IFREG || value.Mode&07777 != 0600 || value.Uid != uint32(os.Geteuid()) || value.Gid != uint32(os.Getegid()) || value.Nlink != 1 || value.Size < 0 || zero && value.Size != 0 {
		return value, ErrArchiveExistingUnsafe
	}
	if _, ok := archiveNativeClass(file); !ok {
		return value, ErrArchiveExistingUnsafe
	}
	return value, nil
}

func archiveRequireExactEntries(directory *os.File) error {
	listing, err := archiveOpenAt(directory, ".", syscall.O_RDONLY|syscall.O_DIRECTORY)
	if err != nil {
		return ErrArchiveExistingUnsafe
	}
	entries, readErr := listing.ReadDir(len(archiveEvidenceNames) + 1)
	closeErr := listing.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) != len(archiveEvidenceNames) {
		return ErrArchiveExistingUnsafe
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	for i := range names {
		if names[i] != archiveEvidenceNames[i] {
			return ErrArchiveExistingUnsafe
		}
	}
	return nil
}

func archiveEnsureNamed(directory *os.File, name string, retained *os.File, retainedStat syscall.Stat_t) error {
	opened, err := archiveOpenAt(directory, name, syscall.O_RDONLY|syscall.O_NONBLOCK)
	if err != nil {
		return ErrArchiveExistingUnsafe
	}
	openedStat, statErr := archiveFstat(opened)
	closeErr := opened.Close()
	current, retainedErr := archiveFstat(retained)
	if statErr != nil || closeErr != nil || retainedErr != nil || !archiveSameStat(openedStat, retainedStat, true, false) || !archiveSameStat(current, retainedStat, true, false) {
		return ErrArchiveExistingUnsafe
	}
	return nil
}

func archiveReadZeroLock(file *os.File) (syscall.Stat_t, [32]byte, error) {
	var empty [32]byte
	before, err := archiveValidateRegular(file, true)
	if err != nil {
		return before, empty, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return before, empty, ErrArchiveExistingUnsafe
	}
	var one [1]byte
	if n, readErr := file.Read(one[:]); n != 0 || !errors.Is(readErr, io.EOF) {
		return before, empty, ErrArchiveExistingUnsafe
	}
	after, err := archiveValidateRegular(file, true)
	if err != nil || !archiveSameStat(before, after, true, false) {
		return before, empty, ErrArchiveExistingUnsafe
	}
	return after, sha256.Sum256(nil), nil
}

func archiveReadCheckpoint(file *os.File) (archiveCheckpointRead, error) {
	var result archiveCheckpointRead
	before, err := archiveValidateRegular(file, false)
	if err != nil || before.Size <= 0 || before.Size > maxLineBytes {
		return result, ErrArchiveExistingUnsafe
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return result, ErrArchiveExistingUnsafe
	}
	raw := make([]byte, int(before.Size))
	if _, err := io.ReadFull(file, raw); err != nil {
		return result, ErrArchiveExistingUnsafe
	}
	var one [1]byte
	if n, readErr := file.Read(one[:]); n != 0 || !errors.Is(readErr, io.EOF) {
		return result, ErrArchiveExistingUnsafe
	}
	after, err := archiveValidateRegular(file, false)
	if err != nil || !archiveSameStat(before, after, true, false) || strictUnmarshal(raw, &result.value) != nil {
		return result, ErrArchiveExistingUnsafe
	}
	if result.value.LastHash == "" {
		result.value.LastHash = genesisHash
	}
	if !validHash(result.value.LastHash) {
		return result, ErrArchiveExistingUnsafe
	}
	result.stat = after
	result.hash = sha256.Sum256(raw)
	result.raw = raw
	return result, nil
}

func archiveReadAndVerifyLog(
	directory *os.File,
	file *os.File,
	checkpointFile *os.File,
	cp archiveCheckpointRead,
	limits ArchiveExistingReadLimits,
) (uint64, string, syscall.Stat_t, [32]byte, error) {
	var empty [32]byte
	before, err := archiveValidateRegular(file, false)
	if err != nil || before.Size < 0 {
		return 0, "", before, empty, ErrArchiveExistingUnsafe
	}
	if uint64(before.Size) > limits.MaxLogBytes {
		after, stableErr := archiveValidateRegular(file, false)
		if stableErr != nil || !archiveSameStat(before, after, true, false) || archiveEnsureNamed(directory, logFilename, file, after) != nil {
			return 0, "", before, empty, ErrArchiveExistingUnsafe
		}
		return 0, "", after, empty, ErrArchiveExistingLimit
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, "", before, empty, ErrArchiveExistingUnsafe
	}
	counter := &archiveHashCounter{hash: sha256.New()}
	reader := bufio.NewReaderSize(io.TeeReader(io.LimitReader(file, before.Size+1), counter), maxLineBytes)
	eventIDs := make(map[string]struct{})
	idempotency := make(map[string]string)
	count := uint64(0)
	head := genesisHash
	for {
		line, readErr := reader.ReadSlice('\n')
		if errors.Is(readErr, bufio.ErrBufferFull) || len(line) > maxLineBytes {
			return 0, "", before, empty, ErrArchiveExistingUnsafe
		}
		if len(line) != 0 {
			if line[len(line)-1] != '\n' || len(line) == 1 {
				return 0, "", before, empty, ErrArchiveExistingUnsafe
			}
			var event EvidenceEvent
			if strictUnmarshal(line[:len(line)-1], &event) != nil {
				return 0, "", before, empty, ErrArchiveExistingUnsafe
			}
			nextHead, eventErr := archiveValidateLogEvent(event, head, eventIDs, idempotency, count < limits.MaxEvents)
			if eventErr != nil {
				return 0, "", before, empty, ErrArchiveExistingUnsafe
			}
			if count == limits.MaxEvents {
				if limits.MaxEvents == math.MaxUint64 {
					return 0, "", before, empty, ErrArchiveExistingUnsafe
				}
				proofOrdinal := limits.MaxEvents + 1
				stableCheckpoint, stableErr := archiveProofWindowStable(directory, file, checkpointFile, before, cp)
				if stableErr != nil || stableCheckpoint.Count < proofOrdinal || stableCheckpoint.Count == proofOrdinal && stableCheckpoint.LastHash != nextHead {
					return 0, "", before, empty, ErrArchiveExistingUnsafe
				}
				return 0, "", before, empty, ErrArchiveExistingLimit
			}
			count++
			head = nextHead
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return 0, "", before, empty, ErrArchiveExistingUnsafe
		}
	}
	if counter.size != uint64(before.Size) {
		return 0, "", before, empty, ErrArchiveExistingUnsafe
	}
	after, err := archiveValidateRegular(file, false)
	if err != nil || !archiveSameStat(before, after, true, false) || count != cp.value.Count || head != cp.value.LastHash {
		return 0, "", before, empty, ErrArchiveExistingUnsafe
	}
	var digest [32]byte
	copy(digest[:], counter.hash.Sum(nil))
	return count, head, after, digest, nil
}

func archiveValidateLogEvent(
	event EvidenceEvent,
	head string,
	eventIDs map[string]struct{},
	idempotency map[string]string,
	record bool,
) (string, error) {
	if validateStoredEvent(event) != nil || event.PreviousHash != head {
		return "", ErrArchiveExistingUnsafe
	}
	if _, exists := eventIDs[event.ID]; exists {
		return "", ErrArchiveExistingUnsafe
	}
	expected, err := eventHash(event)
	if err != nil || expected != event.Hash {
		return "", ErrArchiveExistingUnsafe
	}
	key, fingerprint := "", ""
	if event.IdempotencyKey != "" {
		var keyErr, fingerprintErr error
		key, keyErr = normalizeIdempotencyKey(event.IdempotencyKey)
		fingerprint, fingerprintErr = idempotencyFingerprint(event)
		if keyErr != nil || key != event.IdempotencyKey || fingerprintErr != nil {
			return "", ErrArchiveExistingUnsafe
		}
		if _, exists := idempotency[key]; exists {
			return "", ErrArchiveExistingUnsafe
		}
	}
	if record {
		eventIDs[event.ID] = struct{}{}
		if key != "" {
			idempotency[key] = fingerprint
		}
	}
	return event.Hash, nil
}

func archiveProofWindowStable(
	directory *os.File,
	logFile *os.File,
	checkpointFile *os.File,
	logBefore syscall.Stat_t,
	cpBefore archiveCheckpointRead,
) (checkpoint, error) {
	logAfter, err := archiveValidateRegular(logFile, false)
	if err != nil || !archiveSameStat(logBefore, logAfter, true, false) || archiveEnsureNamed(directory, logFilename, logFile, logAfter) != nil {
		return checkpoint{}, ErrArchiveExistingUnsafe
	}
	cpAfter, err := archiveReadCheckpoint(checkpointFile)
	if err != nil || !archiveSameStat(cpBefore.stat, cpAfter.stat, true, false) || cpBefore.hash != cpAfter.hash || !bytes.Equal(cpBefore.raw, cpAfter.raw) || cpBefore.value != cpAfter.value || archiveEnsureNamed(directory, checkpointFilename, checkpointFile, cpAfter.stat) != nil {
		return checkpoint{}, ErrArchiveExistingUnsafe
	}
	return cpAfter.value, nil
}

func archiveEntrySetHash(stats map[string]syscall.Stat_t) ([32]byte, error) {
	var empty [32]byte
	values := make([]archiveEntrySetValue, 0, len(archiveEvidenceNames))
	for _, name := range archiveEvidenceNames {
		value, ok := stats[name]
		if !ok {
			return empty, ErrArchiveExistingUnsafe
		}
		values = append(values, archiveEntrySetValue{Name: name, Type: "regular", Device: uint64(value.Dev), Inode: value.Ino})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Name < values[j].Name })
	raw, err := json.Marshal(values)
	if err != nil || len(raw) < 2 || len(raw) > 4096 {
		return empty, ErrArchiveExistingUnsafe
	}
	domain := []byte("chengwang/archive/source-entry-set/v1")
	framed := make([]byte, 0, 8+len(domain)+len(raw))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(domain)))
	framed = append(framed, length[:]...)
	framed = append(framed, domain...)
	binary.BigEndian.PutUint32(length[:], uint32(len(raw)))
	framed = append(framed, length[:]...)
	framed = append(framed, raw...)
	return sha256.Sum256(framed), nil
}

func archiveIdentity(value syscall.Stat_t) ArchivePosixIdentity {
	return ArchivePosixIdentity{
		Device: uint64(value.Dev), Inode: value.Ino, Mode: value.Mode,
		UID: value.Uid, GID: value.Gid, LinkCount: value.Nlink,
	}
}

func archiveHexDigest(value string) ([32]byte, bool) {
	var result [32]byte
	if !validHash(value) {
		return result, false
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != len(result) {
		return result, false
	}
	copy(result[:], raw)
	return result, true
}
