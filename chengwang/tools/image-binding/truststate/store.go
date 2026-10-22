// Package truststate persists trusted catalogue history and one-use grants.
// It provides advisory verification state, never deployment authority. Local
// state cannot detect a complete disk/anchor rollback by its administrator.
package truststate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"sync"
	"time"

	"chengwang/image-binding/policy"
	"chengwang/image-binding/trustcatalog"
	bolt "go.etcd.io/bbolt"
)

var (
	ErrInvalid     = errors.New("invalid managed trust state")
	ErrClosed      = errors.New("managed trust state is closed")
	ErrPoisoned    = errors.New("managed trust state is fail-closed")
	ErrUnsupported = errors.New("managed trust state durability is unsupported")
	ErrBusy        = errors.New("managed trust state has another writer")
	ErrReplay      = errors.New("managed grant is already reserved or consumed")
	ErrCapacity    = errors.New("managed trust state capacity reached")
)

const (
	stateSchema      = "chengwang.trust-state/v1"
	markerSchema     = "chengwang.trust-state-marker/v1"
	databaseName     = "trust.db"
	markerName       = "anchor.json"
	maxRecordBytes   = 8 << 20
	maxDatabaseBytes = 64 << 20
	maxLedgerEntries = 4096
)

var bucketName = []byte("trusted-state-v1")
var recordName = []byte("state")

type ledgerEntry struct {
	GrantID              string `json:"grantID"`
	PolicyID             string `json:"policyID"`
	ApprovalSHA256       string `json:"approvalSHA256"`
	ManifestSHA256       string `json:"manifestSHA256"`
	Generation           uint64 `json:"generation"`
	CatalogueSHA256      string `json:"catalogueSHA256"`
	TokenSHA256          string `json:"tokenSHA256"`
	ApprovalNotAfterUnix int64  `json:"approvalNotAfterUnix"`
	Status               string `json:"status"`
	EvidenceSHA256       string `json:"evidenceSHA256"`
}

type stateRecord struct {
	Schema           string        `json:"schema"`
	RecordSHA256     string        `json:"recordSHA256"`
	AnchorSHA256     string        `json:"anchorSHA256"`
	History          [][]byte      `json:"history"`
	Sequence         uint64        `json:"sequence"`
	LastWallUnixNano int64         `json:"lastWallUnixNano"`
	Ledger           []ledgerEntry `json:"ledger"`
}

// Ticket is an in-process capability. Its zero value and JSON imports cannot
// reserve or complete a grant; tokens and owner identities are never exported.
type Ticket struct {
	owner                *Store
	token                [32]byte
	grant                trustcatalog.Grant
	trust                policy.Trust
	generation           uint64
	catalogueSHA256      string
	approvalNotAfterUnix int64
	validUntilUnix       int64
}

func (t Ticket) Trust() policy.Trust     { r := t.trust; r.PublicKey = bytes.Clone(r.PublicKey); return r }
func (t Ticket) GrantID() string         { return t.grant.ID }
func (t Ticket) Generation() uint64      { return t.generation }
func (t Ticket) CatalogueSHA256() string { return t.catalogueSHA256 }
func (t Ticket) ManifestSHA256() string  { return t.grant.ManifestSHA256 }

// ValidUntilUnix is authenticated metadata, not a caller-selected deadline.
// It is the earlier of the verified approval and current signed catalogue.
func (t Ticket) ValidUntilUnix() int64 { return t.validUntilUnix }

// Store deliberately exposes neither the database nor mutable sync options.
// The lifetime database lock excludes other processes. Catalogue updates during
// a network verification must go through this same Store instance.
type Store struct {
	mu            sync.Mutex
	db            *bolt.DB
	platform      *platformStore
	anchor        trustcatalog.Anchor
	anchorSHA256  string
	current       stateRecord
	closed        bool
	poisoned      bool
	clock         func() time.Time
	fault         func(string) error
	lastObserved  int64
	pendingSHA256 string
}

func Create(ctx context.Context, path string, anchor trustcatalog.Anchor, initial []byte) (*Store, error) {
	return openStore(ctx, path, anchor, initial, true)
}

func Open(ctx context.Context, path string, anchor trustcatalog.Anchor) (*Store, error) {
	return openStore(ctx, path, anchor, nil, false)
}

func openStore(ctx context.Context, path string, anchor trustcatalog.Anchor, initial []byte, create bool) (*Store, error) {
	if contextError(ctx) != nil {
		return nil, ErrInvalid
	}
	anchor = cloneAnchor(anchor)
	anchorRaw, err := json.Marshal(anchor)
	if err != nil {
		return nil, ErrInvalid
	}
	anchorHash := hash(anchorRaw)
	var initialCatalogue trustcatalog.Catalogue
	if create {
		initial = bytes.Clone(initial)
		initialCatalogue, err = trustcatalog.Replay(anchor, [][]byte{initial})
		if err != nil || !initialCatalogue.ValidAt(time.Now()) {
			return nil, ErrInvalid
		}
	}
	p, err := openPlatform(path, create, anchorHash, anchor.StoreID)
	if err != nil {
		return nil, err
	}
	s := &Store{platform: p, anchor: anchor, anchorSHA256: anchorHash, clock: time.Now}
	ok := false
	defer func() {
		if !ok {
			if s.db != nil {
				_ = s.db.Close()
			}
			_ = p.close()
		}
	}()
	timeout := 200 * time.Millisecond
	if deadline, yes := ctx.Deadline(); yes {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return nil, ErrInvalid
	}
	s.db, err = bolt.Open(databaseName, 0600, &bolt.Options{Timeout: timeout, OpenFile: p.openDatabase})
	if err != nil {
		if errors.Is(err, bolt.ErrTimeout) {
			return nil, ErrBusy
		}
		return nil, ErrInvalid
	}
	if s.db.NoSync || s.db.NoGrowSync {
		return nil, ErrInvalid
	}
	s.db.AllocSize = 1 << 20
	if create {
		s.current = stateRecord{Schema: stateSchema, AnchorSHA256: anchorHash, History: [][]byte{initial}, Sequence: 1, LastWallUnixNano: s.clock().UnixNano(), Ledger: []ledgerEntry{}}
		if _, err = encodeRecord(&s.current); err != nil {
			return nil, ErrInvalid
		}
		if err = s.writeInitial(); err != nil {
			return nil, ErrInvalid
		}
		if err = p.finishCreate(); err != nil {
			return nil, ErrInvalid
		}
	} else {
		if err = s.db.View(func(tx *bolt.Tx) error {
			r, _, e := s.read(tx)
			if e == nil {
				s.current = r
			}
			return e
		}); err != nil {
			return nil, ErrInvalid
		}
	}
	if err = p.verify(); err != nil || contextError(ctx) != nil || s.clock().UnixNano() < s.current.LastWallUnixNano {
		return nil, ErrInvalid
	}
	s.lastObserved = s.current.LastWallUnixNano
	ok = true
	return s, nil
}

func (s *Store) Begin(ctx context.Context, policyID string, approvalRaw []byte) (Ticket, error) {
	if s == nil || contextError(ctx) != nil || len(approvalRaw) == 0 || len(approvalRaw) > policy.MaxEnvelopeBytes {
		return Ticket{}, ErrInvalid
	}
	approvalRaw = bytes.Clone(approvalRaw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(ctx); err != nil {
		return Ticket{}, err
	}
	var ticket Ticket
	err := s.db.Update(func(tx *bolt.Tx) error {
		r, cat, err := s.readCurrent(tx)
		if err != nil {
			return s.poison()
		}
		now, err := s.now(r)
		if err != nil {
			return s.poison()
		}
		grant, trust, found := cat.Resolve(policyID, now)
		if !found {
			return ErrInvalid
		}
		approved, err := policy.Verify(ctx, trust, approvalRaw, now)
		if err != nil || approved.ID() != grant.PolicyID || approved.Revision() != grant.Revision || approved.SHA256() != grant.ApprovalSHA256 || approved.KeyID() != grant.ApproverKeyID || approved.SignatureExpected().ArtifactSHA256 != grant.ManifestSHA256 {
			return ErrInvalid
		}
		for _, entry := range r.Ledger {
			if entry.GrantID == grant.ID {
				return ErrReplay
			}
		}
		if len(r.Ledger) >= maxLedgerEntries {
			return ErrCapacity
		}
		ticket = Ticket{owner: s, grant: grant, trust: trust, generation: cat.Generation(), catalogueSHA256: cat.SHA256(), approvalNotAfterUnix: approved.NotAfterUnix()}
		ticket.validUntilUnix = approved.NotAfterUnix()
		if expiry := cat.Summary().NotAfterUnix; expiry < ticket.validUntilUnix {
			ticket.validUntilUnix = expiry
		}
		if _, err = rand.Read(ticket.token[:]); err != nil {
			return s.poison()
		}
		r.Ledger = append(r.Ledger, ledgerEntry{GrantID: grant.ID, PolicyID: grant.PolicyID, ApprovalSHA256: grant.ApprovalSHA256, ManifestSHA256: grant.ManifestSHA256, Generation: cat.Generation(), CatalogueSHA256: cat.SHA256(), TokenSHA256: hash(ticket.token[:]), ApprovalNotAfterUnix: approved.NotAfterUnix(), Status: "RESERVED"})
		return s.put(tx, &r, now)
	})
	if err = s.afterTransaction(ctx, err); err != nil {
		return Ticket{}, err
	}
	return ticket, nil
}

func (s *Store) Complete(ctx context.Context, ticket Ticket, evidenceSHA256 string) error {
	if s == nil || contextError(ctx) != nil || ticket.owner != s || !validHash(evidenceSHA256) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(ctx); err != nil {
		return err
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		r, cat, err := s.readCurrent(tx)
		if err != nil {
			return s.poison()
		}
		now, err := s.now(r)
		if err != nil {
			return s.poison()
		}
		grant, trust, found := cat.Resolve(ticket.grant.PolicyID, now)
		if !found || now.Unix() >= ticket.approvalNotAfterUnix || cat.Generation() != ticket.generation || cat.SHA256() != ticket.catalogueSHA256 || grant != ticket.grant || !sameTrust(trust, ticket.trust) {
			return ErrInvalid
		}
		for i, entry := range r.Ledger {
			if entry.GrantID != ticket.grant.ID {
				continue
			}
			if entry.Status != "RESERVED" || entry.ApprovalNotAfterUnix != ticket.approvalNotAfterUnix || entry.TokenSHA256 != hash(ticket.token[:]) || entry.PolicyID != grant.PolicyID || entry.ApprovalSHA256 != grant.ApprovalSHA256 || entry.ManifestSHA256 != grant.ManifestSHA256 || entry.Generation != ticket.generation || entry.CatalogueSHA256 != ticket.catalogueSHA256 {
				return ErrReplay
			}
			r.Ledger[i].Status = "CONSUMED"
			r.Ledger[i].EvidenceSHA256 = evidenceSHA256
			return s.put(tx, &r, now)
		}
		return ErrReplay
	})
	if err = s.afterTransaction(ctx, err); err != nil {
		return err
	}
	// Sync and authoritative readback can cross an expiry boundary. A durable
	// CONSUMED record is never rolled back merely because the final freshness
	// check fails; the grant remains burned even when no result is returned.
	cat, err := trustcatalog.Replay(s.anchor, s.current.History)
	if err != nil {
		return s.poison()
	}
	now, err := s.now(s.current)
	if err != nil {
		return s.poison()
	}
	grant, trust, found := cat.Resolve(ticket.grant.PolicyID, now)
	if !cat.ValidAt(now) || !found || now.Unix() >= ticket.approvalNotAfterUnix || cat.Generation() != ticket.generation || cat.SHA256() != ticket.catalogueSHA256 || grant != ticket.grant || !sameTrust(trust, ticket.trust) || contextError(ctx) != nil {
		return ErrInvalid
	}
	return nil
}

func (s *Store) Update(ctx context.Context, raw []byte) error {
	if s == nil || contextError(ctx) != nil || len(raw) == 0 || len(raw) > 256<<10 {
		return ErrInvalid
	}
	raw = bytes.Clone(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(ctx); err != nil {
		return err
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		r, cat, err := s.readCurrent(tx)
		if err != nil {
			return s.poison()
		}
		now, err := s.now(r)
		if err != nil {
			return s.poison()
		}
		if _, err = trustcatalog.Advance(cat, raw, now); err != nil {
			return ErrInvalid
		}
		r.History = append(r.History, raw)
		if _, err = trustcatalog.Replay(s.anchor, r.History); err != nil {
			return ErrCapacity
		}
		return s.put(tx, &r, now)
	})
	return s.afterTransaction(ctx, err)
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.db != nil {
		err = s.db.Close()
	}
	if s.platform != nil {
		err = errors.Join(err, s.platform.close())
	}
	return err
}

func (s *Store) usable(ctx context.Context) error {
	if contextError(ctx) != nil {
		return ErrInvalid
	}
	if s.closed {
		return ErrClosed
	}
	if s.poisoned {
		return ErrPoisoned
	}
	if s.db == nil || s.db.NoSync || s.db.NoGrowSync || s.platform.verify() != nil {
		return s.poison()
	}
	return nil
}
func (s *Store) poison() error { s.poisoned = true; return ErrPoisoned }
func (s *Store) now(r stateRecord) (time.Time, error) {
	now := s.clock()
	if now.IsZero() || now.UnixNano() < r.LastWallUnixNano || now.UnixNano() < s.lastObserved {
		return time.Time{}, ErrInvalid
	}
	s.lastObserved = now.UnixNano()
	return now, nil
}
func (s *Store) hook(stage string) error {
	if s.fault != nil {
		return s.fault(stage)
	}
	return nil
}

func (s *Store) writeInitial() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketName) != nil {
			return ErrInvalid
		}
		b, err := tx.CreateBucket(bucketName)
		if err != nil {
			return err
		}
		raw, err := encodeRecord(&s.current)
		if err != nil {
			return err
		}
		return b.Put(recordName, raw)
	})
}
func (s *Store) readCurrent(tx *bolt.Tx) (stateRecord, trustcatalog.Catalogue, error) {
	r, cat, err := s.read(tx)
	if err != nil {
		return r, cat, err
	}
	if !reflect.DeepEqual(r, s.current) {
		return stateRecord{}, trustcatalog.Catalogue{}, ErrInvalid
	}
	return r, cat, nil
}
func (s *Store) read(tx *bolt.Tx) (stateRecord, trustcatalog.Catalogue, error) {
	var r stateRecord
	b := tx.Bucket(bucketName)
	if b == nil {
		return r, trustcatalog.Catalogue{}, ErrInvalid
	}
	// The database has one authoritative bucket and exactly one strict record.
	buckets := 0
	if err := tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		buckets++
		if !bytes.Equal(name, bucketName) {
			return ErrInvalid
		}
		return nil
	}); err != nil || buckets != 1 {
		return r, trustcatalog.Catalogue{}, ErrInvalid
	}
	keys := 0
	if err := b.ForEach(func(k, v []byte) error {
		keys++
		if !bytes.Equal(k, recordName) || v == nil {
			return ErrInvalid
		}
		return nil
	}); err != nil || keys != 1 {
		return r, trustcatalog.Catalogue{}, ErrInvalid
	}
	raw := b.Get(recordName)
	if len(raw) == 0 || len(raw) > maxRecordBytes {
		return r, trustcatalog.Catalogue{}, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, trustcatalog.Catalogue{}, ErrInvalid
	}
	if dec.Decode(new(any)) != io.EOF {
		return r, trustcatalog.Catalogue{}, ErrInvalid
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return r, trustcatalog.Catalogue{}, ErrInvalid
	}
	expectedHash := r.RecordSHA256
	if !validHash(expectedHash) {
		return r, trustcatalog.Catalogue{}, ErrInvalid
	}
	if _, err = encodeRecord(&r); err != nil || r.RecordSHA256 != expectedHash {
		return r, trustcatalog.Catalogue{}, ErrInvalid
	}
	if r.Schema != stateSchema || r.AnchorSHA256 != s.anchorSHA256 || r.Sequence == 0 || r.LastWallUnixNano <= 0 || r.Ledger == nil || len(r.Ledger) > maxLedgerEntries {
		return r, trustcatalog.Catalogue{}, ErrInvalid
	}
	seen := map[string]bool{}
	for _, e := range r.Ledger {
		if !validID(e.GrantID) || seen[e.GrantID] || e.PolicyID == "" || !validHash(e.ApprovalSHA256) || !validHash(e.ManifestSHA256) || e.Generation == 0 || !validHash(e.CatalogueSHA256) || !validHash(e.TokenSHA256) || e.ApprovalNotAfterUnix <= 0 || (e.Status != "RESERVED" && e.Status != "CONSUMED") || e.Status == "RESERVED" && e.EvidenceSHA256 != "" || e.Status == "CONSUMED" && !validHash(e.EvidenceSHA256) {
			return r, trustcatalog.Catalogue{}, ErrInvalid
		}
		seen[e.GrantID] = true
	}
	cat, err := trustcatalog.Replay(s.anchor, r.History)
	if err != nil {
		return r, trustcatalog.Catalogue{}, ErrInvalid
	}
	return r, cat, nil
}
func (s *Store) put(tx *bolt.Tx, r *stateRecord, now time.Time) error {
	if r.Sequence == math.MaxUint64 {
		return ErrCapacity
	}
	r.Sequence++
	r.LastWallUnixNano = now.UnixNano()
	raw, err := encodeRecord(r)
	if err != nil || len(raw) > maxRecordBytes {
		return ErrCapacity
	}
	// Bound growth before committing: one record needs at most its pages plus
	// the current record, metadata, bucket/freelist and one conservative 8 MiB
	// allowance. Existing oversized databases are rejected by platform.verify.
	if int64(tx.Size())+int64(len(raw))*2+(8<<20) > maxDatabaseBytes {
		return ErrCapacity
	}
	if s.platform.verify() != nil || s.hook("before-put") != nil {
		return s.poison()
	}
	if err = tx.Bucket(bucketName).Put(recordName, raw); err != nil {
		return s.poison()
	}
	if s.hook("before-commit") != nil {
		return s.poison()
	}
	s.pendingSHA256 = r.RecordSHA256
	return nil
}

// This public checksum detects accidental changes to otherwise parseable state
// bytes. An owner able to rewrite the database can recompute it; it is not a
// signature, trusted monotonic witness, or defence against a hostile same UID.
func encodeRecord(r *stateRecord) ([]byte, error) {
	r.RecordSHA256 = ""
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	r.RecordSHA256 = hash(raw)
	return json.Marshal(r)
}
func (s *Store) afterTransaction(ctx context.Context, err error) error {
	defer func() { s.pendingSHA256 = "" }()
	if err != nil {
		if errors.Is(err, ErrInvalid) || errors.Is(err, ErrReplay) || errors.Is(err, ErrCapacity) || errors.Is(err, ErrPoisoned) {
			return err
		}
		return s.poison()
	}
	if s.hook("after-commit") != nil || s.platform.verify() != nil {
		return s.poison()
	}
	if err = s.db.View(func(tx *bolt.Tx) error {
		r, _, e := s.read(tx)
		if e == nil && (s.pendingSHA256 == "" || r.RecordSHA256 != s.pendingSHA256 || r.Sequence != s.current.Sequence+1) {
			return ErrInvalid
		}
		if e == nil {
			s.current = r
		}
		return e
	}); err != nil {
		return s.poison()
	}
	if contextError(ctx) != nil {
		return ErrInvalid
	}
	return nil
}
func cloneAnchor(a trustcatalog.Anchor) trustcatalog.Anchor {
	a.Keys = append([]trustcatalog.Key(nil), a.Keys...)
	for i := range a.Keys {
		a.Keys[i].PublicKey = bytes.Clone(a.Keys[i].PublicKey)
	}
	return a
}
func sameTrust(a, b policy.Trust) bool {
	return a.KeyID == b.KeyID && a.PolicySHA256 == b.PolicySHA256 && a.Revision == b.Revision && bytes.Equal(a.PublicKey, b.PublicKey)
}
func hash(raw []byte) string  { v := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(v[:]) }
func validHash(s string) bool { return len(s) == 71 && s[:7] == "sha256:" && validHex(s[7:]) }
func validID(s string) bool   { return len(s) == 32 && validHex(s) }
func validHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != ""
}
func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	return ctx.Err()
}
