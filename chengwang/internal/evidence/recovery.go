package evidence

import (
	"bufio"
	"errors"
	"os"
)

// RecoveryView is an immutable, bounded view of an already verified local
// audit prefix. It is not a recovery permit, and never repairs the log or its
// checkpoint. Only public event summaries and hashes are retained.
type RecoveryView struct {
	events map[string]EvidenceEvent
	hashes []string
}

func (v RecoveryView) Lookup(key string) (EvidenceEvent, bool) {
	normalized, err := normalizeIdempotencyKey(key)
	if err != nil {
		return EvidenceEvent{}, false
	}
	e, ok := v.events[normalized]
	return cloneEvidenceEvent(e), ok
}

func (v RecoveryView) HashAt(count uint64) (string, bool) {
	if count >= uint64(len(v.hashes)) {
		return "", false
	}
	return v.hashes[count], true
}

// RecoverySnapshot takes a single verified snapshot, avoiding a complete log
// scan per journal operation. The hard cap is deliberately fail-closed; this is
// not automatic audit compaction or a general audit export API.
func (s *Store) RecoverySnapshot() (RecoveryView, error) {
	if s == nil {
		return RecoveryView{}, ErrStoreClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writableLocked(); err != nil {
		return RecoveryView{}, err
	}
	report, index, err := s.verifyAndIndexLocked()
	if err != nil || !report.Valid {
		return RecoveryView{}, ErrIntegrity
	}
	if report.Count > 16384 {
		return RecoveryView{}, errors.New("audit recovery view capacity exceeded")
	}
	file, err := openRegularFile(s.logPath, "evidence log", os.O_RDONLY, 0o600)
	if err != nil {
		return RecoveryView{}, err
	}
	defer file.Close()
	view := RecoveryView{events: make(map[string]EvidenceEvent, len(index)), hashes: []string{genesisHash}}
	for key, entry := range index {
		view.events[key] = cloneEvidenceEvent(entry.event)
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxLineBytes)
	for scanner.Scan() {
		var event EvidenceEvent
		if len(view.hashes) > 16384 || strictUnmarshal(scanner.Bytes(), &event) != nil || event.PreviousHash != view.hashes[len(view.hashes)-1] {
			return RecoveryView{}, ErrIntegrity
		}
		computed, e := eventHash(event)
		if e != nil || computed != event.Hash {
			return RecoveryView{}, ErrIntegrity
		}
		view.hashes = append(view.hashes, event.Hash)
	}
	if scanner.Err() != nil || uint64(len(view.hashes)-1) != report.Count || view.hashes[len(view.hashes)-1] != report.LastHash {
		return RecoveryView{}, ErrIntegrity
	}
	if err := s.ensureDirectoryIdentityLocked(); err != nil {
		return RecoveryView{}, err
	}
	// A view must correspond to the writer's current committed prefix, not to
	// a valid older on-disk copy that happens to carry a matching checkpoint.
	if report.Count != s.count || report.LastHash != s.lastHash {
		return RecoveryView{}, ErrIntegrity
	}
	s.setStatus(report)
	return view, nil
}
