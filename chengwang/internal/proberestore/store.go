package proberestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
)

const (
	controlFilename = "control.json"
	lockFilename    = "writer.lock"
	controlSchema   = "chengwang.probe-restore-control/v1"
	maxControlBytes = 256 * 1024
)

var (
	ErrStoreLocked           = errors.New("probe restore journal already has an active writer")
	ErrStoreClosed           = errors.New("probe restore journal store is closed")
	ErrStorePoisoned         = errors.New("probe restore journal store is fail-closed after uncertain write")
	ErrDurabilityUnsupported = errors.New("durable probe restore journal writes are unsupported on this platform")
	ErrReplayDetected        = errors.New("probe restore control record replay detected")
	ErrBackupConsumed        = errors.New("probe restore backup was already consumed")
)

type LedgerHead struct {
	OperationID    string `json:"operationId"`
	BackupID       string `json:"backupId"`
	ManifestSHA256 string `json:"manifestSha256"`
	Sequence       uint64 `json:"sequence"`
	HeadSHA256     string `json:"headSha256"`
	Phase          Phase  `json:"phase"`
}

type TerminalReceipt struct {
	OperationID    string `json:"operationId"`
	BackupID       string `json:"backupId"`
	ManifestSHA256 string `json:"manifestSha256"`
	Sequence       uint64 `json:"sequence"`
	HeadSHA256     string `json:"headSha256"`
	TerminalPhase  Phase  `json:"terminalPhase"`
}

// controlRecord is the single atomic durability and anti-replay unit. Journal,
// head, generation, and terminal receipts must never be persisted separately.
type controlRecord struct {
	Schema     string            `json:"schema"`
	Generation uint64            `json:"generation"`
	Journal    Journal           `json:"journal"`
	Head       LedgerHead        `json:"head"`
	Receipts   []TerminalReceipt `json:"receipts"`
}

type Store struct {
	platform *platformStore
	mu       sync.Mutex
	closed   bool
	poisoned error
	current  *controlRecord
	commitFn func(controlRecord) error
}

func Open(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("control directory path must not be blank")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	p, err := openPlatformStore(abs)
	if err != nil {
		return nil, err
	}
	s := &Store{platform: p}
	s.commitFn = s.commitControl
	ok := false
	defer func() {
		if !ok {
			_ = p.close()
		}
	}()
	r, err := s.loadControl()
	if err != nil {
		return nil, err
	}
	s.current = r
	ok = true
	return s, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.platform.close()
}

func (s *Store) Load() (Journal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readable(); err != nil {
		return Journal{}, err
	}
	r, err := s.loadControl()
	if err != nil {
		return Journal{}, s.poison("load", err)
	}
	if err := s.verifyCached(r); err != nil {
		return Journal{}, s.poison("load monotonicity", err)
	}
	s.current = r
	if r == nil {
		return Journal{}, os.ErrNotExist
	}
	return r.Journal, nil
}

// Create starts a journal. A new operation may replace only a terminal current
// journal. Operation, backup, and manifest identities are all single-use once
// represented by a terminal receipt.
func (s *Store) Create(j Journal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return err
	}
	if err := j.Validate(); err != nil {
		return err
	}
	if j.Sequence != 1 || j.Phase != PhaseNew {
		return fmt.Errorf("%w: create requires NEW journal", ErrInvalidJournal)
	}
	current, err := s.loadControl()
	if err != nil {
		return s.poison("load before create", err)
	}
	if err := s.verifyCached(current); err != nil {
		return s.poison("create monotonicity", err)
	}
	if current != nil && !IsTerminal(current.Journal.Phase) {
		return errors.New("nonterminal journal already exists")
	}
	if current != nil {
		for _, r := range current.Receipts {
			if r.BackupID == j.Identity.BackupID || r.ManifestSHA256 == j.Digests.BackupManifestSHA256 {
				return ErrBackupConsumed
			}
			if r.OperationID == j.OperationID {
				return ErrReplayDetected
			}
		}
	}
	next := newControl(j, current)
	if err := s.commitFn(next); err != nil {
		return s.poison("create control record", err)
	}
	s.current = &next
	return nil
}

func (s *Store) Save(next Journal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return err
	}
	current, err := s.loadControl()
	if err != nil {
		return s.poison("load before save", err)
	}
	if err := s.verifyCached(current); err != nil {
		return s.poison("save monotonicity", err)
	}
	if current == nil {
		return s.poison("save missing control record", ErrReplayDetected)
	}
	prior := current.Journal
	if next.OperationID != prior.OperationID || next.Sequence != prior.Sequence+1 || len(next.Events) != len(prior.Events)+1 || !CanTransition(prior.Phase, next.Phase) {
		return fmt.Errorf("%w: save is not next transition", ErrInvalidJournal)
	}
	for i := range prior.Events {
		if prior.Events[i] != next.Events[i] {
			return fmt.Errorf("%w: history rewrite", ErrInvalidJournal)
		}
	}
	if next.Identity != prior.Identity || next.Digests != prior.Digests || !next.CreatedAt.Equal(prior.CreatedAt) {
		return fmt.Errorf("%w: immutable field changed", ErrInvalidJournal)
	}
	if err := next.Validate(); err != nil {
		return err
	}
	updated := advanceControl(next, *current)
	if err := s.commitFn(updated); err != nil {
		return s.poison("save control record", err)
	}
	s.current = &updated
	return nil
}

func (s *Store) readable() error {
	if s.closed {
		return ErrStoreClosed
	}
	if s.poisoned != nil {
		return errors.Join(ErrStorePoisoned, s.poisoned)
	}
	return nil
}

func (s *Store) writable() error {
	if err := s.readable(); err != nil {
		return err
	}
	if !s.platform.durableWrites() {
		return ErrDurabilityUnsupported
	}
	return nil
}

func (s *Store) poison(stage string, err error) error {
	if s.poisoned == nil {
		s.poisoned = fmt.Errorf("%s: %w", stage, err)
	}
	return errors.Join(ErrStorePoisoned, s.poisoned)
}

func newControl(j Journal, previous *controlRecord) controlRecord {
	r := controlRecord{Schema: controlSchema, Generation: 1, Journal: j, Head: headFor(j), Receipts: []TerminalReceipt{}}
	if previous != nil {
		r.Generation = previous.Generation + 1
		r.Receipts = append(r.Receipts, previous.Receipts...)
	}
	return r
}

func advanceControl(j Journal, r controlRecord) controlRecord {
	r.Generation++
	r.Journal = j
	r.Head = headFor(j)
	if IsTerminal(j.Phase) {
		r.Receipts = append(r.Receipts, TerminalReceipt{j.OperationID, j.Identity.BackupID, j.Digests.BackupManifestSHA256, j.Sequence, j.Events[len(j.Events)-1].Hash, j.Phase})
	}
	return r
}

func headFor(j Journal) LedgerHead {
	return LedgerHead{j.OperationID, j.Identity.BackupID, j.Digests.BackupManifestSHA256, j.Sequence, j.Events[len(j.Events)-1].Hash, j.Phase}
}

func (s *Store) commitControl(r controlRecord) error {
	if err := validateControl(r); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(b)+1 > maxControlBytes {
		return errors.New("control record exceeds size limit")
	}
	return s.platform.replace(controlFilename, append(b, '\n'))
}

func (s *Store) loadControl() (*controlRecord, error) {
	b, err := s.platform.read(controlFilename, maxControlBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r, err := decodeControl(b)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// verifyCached detects replacement by an older or different complete control
// record while this writer owns the store. Fresh Open cannot detect whole-disk
// rollback; that limitation is part of the package threat boundary.
func (s *Store) verifyCached(disk *controlRecord) error {
	if s.current == nil {
		return nil
	}
	if disk == nil || disk.Generation != s.current.Generation || !reflect.DeepEqual(*disk, *s.current) {
		return ErrReplayDetected
	}
	return nil
}

func decodeJournal(b []byte) (Journal, error) {
	if err := validateJournalKeys(b); err != nil {
		return Journal{}, err
	}
	var j Journal
	if err := strictDecode(b, &j); err != nil {
		return Journal{}, err
	}
	if err := j.Validate(); err != nil {
		return Journal{}, err
	}
	return j, nil
}

func decodeControl(b []byte) (controlRecord, error) {
	if err := validateControlKeys(b); err != nil {
		return controlRecord{}, err
	}
	var r controlRecord
	if err := strictDecode(b, &r); err != nil {
		return controlRecord{}, err
	}
	if err := validateControl(r); err != nil {
		return controlRecord{}, err
	}
	return r, nil
}

func strictDecode(b []byte, target any) error {
	if len(b) > maxControlBytes {
		return errors.New("control record exceeds size limit")
	}
	if err := rejectDuplicateJSONKeys(b); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := d.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("control record contains trailing JSON")
	}
	return nil
}

func validateControl(r controlRecord) error {
	if r.Schema != controlSchema || r.Generation == 0 {
		return ErrReplayDetected
	}
	if err := r.Journal.Validate(); err != nil {
		return err
	}
	if r.Head != headFor(r.Journal) || r.Receipts == nil {
		return ErrReplayDetected
	}
	seenOps := map[string]bool{}
	seenBackups := map[string]bool{}
	seenManifests := map[string]bool{}
	currentMatches := 0
	for _, receipt := range r.Receipts {
		if !safeID.MatchString(receipt.OperationID) || !safeID.MatchString(receipt.BackupID) || !isHash(receipt.ManifestSHA256) || receipt.Sequence == 0 || !isHash(receipt.HeadSHA256) || !IsTerminal(receipt.TerminalPhase) || seenOps[receipt.OperationID] || seenBackups[receipt.BackupID] || seenManifests[receipt.ManifestSHA256] {
			return ErrReplayDetected
		}
		seenOps[receipt.OperationID] = true
		seenBackups[receipt.BackupID] = true
		seenManifests[receipt.ManifestSHA256] = true
		collides := receipt.OperationID == r.Journal.OperationID || receipt.BackupID == r.Journal.Identity.BackupID || receipt.ManifestSHA256 == r.Journal.Digests.BackupManifestSHA256
		if collides {
			currentMatches++
			if !IsTerminal(r.Journal.Phase) || receipt.OperationID != r.Journal.OperationID || receipt.BackupID != r.Journal.Identity.BackupID || receipt.ManifestSHA256 != r.Journal.Digests.BackupManifestSHA256 || receipt.Sequence != r.Journal.Sequence || receipt.HeadSHA256 != r.Journal.Events[len(r.Journal.Events)-1].Hash || receipt.TerminalPhase != r.Journal.Phase {
				return ErrReplayDetected
			}
		}
	}
	if IsTerminal(r.Journal.Phase) && currentMatches != 1 {
		return ErrReplayDetected
	}
	if !IsTerminal(r.Journal.Phase) && currentMatches != 0 {
		return ErrReplayDetected
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		if x, ok := t.(json.Delim); ok {
			switch x {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, err := d.Token()
					if err != nil {
						return err
					}
					key, ok := k.(string)
					if !ok {
						return errors.New("non-string object key")
					}
					if seen[key] {
						return fmt.Errorf("duplicate JSON key %q", key)
					}
					seen[key] = true
					if err := walk(); err != nil {
						return err
					}
				}
				_, err = d.Token()
				return err
			case '[':
				for d.More() {
					if err := walk(); err != nil {
						return err
					}
				}
				_, err = d.Token()
				return err
			}
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func exactKeys(raw json.RawMessage, allowed map[string]bool) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if len(m) != len(allowed) {
		return errors.New("JSON object field set mismatch")
	}
	for k := range m {
		if !allowed[k] {
			return fmt.Errorf("unexpected exact JSON key %q", k)
		}
	}
	return nil
}

func validateJournalKeys(b []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return err
	}
	if err := exactKeys(b, set("schema", "operationId", "sequence", "phase", "identity", "digests", "createdAt", "updatedAt", "events")); err != nil {
		return err
	}
	if err := exactKeys(top["identity"], set("candidateId", "projectId", "backupId")); err != nil {
		return err
	}
	if err := exactKeys(top["digests"], set("backupManifestSha256", "bindingSha256", "oldStateSha256", "newStateSha256")); err != nil {
		return err
	}
	var events []json.RawMessage
	if err := json.Unmarshal(top["events"], &events); err != nil {
		return err
	}
	for i, e := range events {
		keys := set("sequence", "at", "to", "reasonCode", "bindingHash", "previousHash", "hash")
		if i > 0 {
			keys["from"] = true
			keys["evidenceSha256"] = true
		}
		if err := exactKeys(e, keys); err != nil {
			return err
		}
	}
	return nil
}

func validateControlKeys(b []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return err
	}
	if err := exactKeys(b, set("schema", "generation", "journal", "head", "receipts")); err != nil {
		return err
	}
	if err := validateJournalKeys(top["journal"]); err != nil {
		return err
	}
	if err := exactKeys(top["head"], set("operationId", "backupId", "manifestSha256", "sequence", "headSha256", "phase")); err != nil {
		return err
	}
	var receipts []json.RawMessage
	if err := json.Unmarshal(top["receipts"], &receipts); err != nil {
		return err
	}
	for _, receipt := range receipts {
		if err := exactKeys(receipt, set("operationId", "backupId", "manifestSha256", "sequence", "headSha256", "terminalPhase")); err != nil {
			return err
		}
	}
	return nil
}

func set(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}
