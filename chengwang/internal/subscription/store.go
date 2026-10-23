package subscription

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const storeSchema = "chengwang.subscription-store/v1"

var storeCandidatePattern = regexp.MustCompile(`^cand_[a-f0-9]{32}$`)
var storeDigestPattern = regexp.MustCompile(`^hmac-sha256:[a-f0-9]{64}$`)
var storeHexPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type storeDiskIO interface {
	verify() error
	read() ([]byte, bool, error)
	write([]byte) (bool, error)
	close() error
}

// Store is a single-controller, private local admission store. Its audit is
// bounded local history, not an independently witnessed enterprise audit.
// No method publishes configuration or proves runtime/node health.
type Store struct {
	*storeCore
}

// Copying the public handle shares one locked private core. In particular,
// value-receiver formatting must not copy a mutex or expose persistence data.
type storeCore struct {
	mu               sync.Mutex
	disk             storeDiskIO
	state            storeSnapshot
	closed, poisoned bool
	now              func() time.Time
}

func (Store) String() string   { return "subscription private store" }
func (Store) GoString() string { return "subscription private store" }

// These persistence DTOs are intentionally separate from public views.
type storeNode struct {
	ID                   string          `json:"id"`
	Protocol             string          `json:"protocol"`
	PrivateName          string          `json:"privateName"`
	Config               json.RawMessage `json:"canonicalConfig"`
	CredentialConfigured bool            `json:"credentialConfigured"`
}
type storeCandidate struct {
	View  CandidateView `json:"view"`
	Raw   []byte        `json:"raw"`
	Nodes []storeNode   `json:"privateNodes"`
}
type storeRequest struct {
	Key         string `json:"idempotencyDigest"`
	Fingerprint string `json:"requestDigest"`
	Action      string `json:"action"`
	SourceID    string `json:"sourceId"`
	CandidateID string `json:"candidateId,omitempty"`
}
type storeAudit struct {
	Sequence      uint64    `json:"sequence"`
	Actor         string    `json:"actor"`
	Scope         Scope     `json:"scope"`
	SourceID      string    `json:"sourceId"`
	CandidateID   string    `json:"candidateId,omitempty"`
	Revision      uint64    `json:"revision"`
	Action        string    `json:"action"`
	Result        string    `json:"result"`
	Key           string    `json:"idempotencyDigest"`
	RequestDigest string    `json:"requestDigest"`
	At            time.Time `json:"at"`
	PreviousHash  string    `json:"previousHash"`
	Hash          string    `json:"hash"`
}
type storeSnapshot struct {
	Schema      string               `json:"schema"`
	IdentityKey []byte               `json:"identityKey"`
	Sources     []SourceView         `json:"sources"`
	Candidates  []storeCandidate     `json:"candidates"`
	Requests    []storeRequest       `json:"requests"`
	Audit       []storeAudit         `json:"audit"`
	Commands    []controlCommandDisk `json:"commands,omitempty"`
	Approvals   []ControlApproval    `json:"approvals,omitempty"`
}

func OpenStore(dir string) (*Store, error) {
	disk, err := storeOpenDisk(dir)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = disk.close()
		}
	}()
	raw, exists, err := disk.read()
	if err != nil {
		return nil, err
	}
	s := &Store{storeCore: &storeCore{disk: disk, now: func() time.Time { return time.Now().UTC() }}}
	if exists {
		if err := storeDecode(raw, &s.state); err != nil {
			return nil, fail(CodeStoreUnsafe)
		}
		if err := storeValidate(s.state); err != nil {
			return nil, err
		}
		canonical, err := storeEncode(s.state)
		if err != nil || !bytes.Equal(raw, canonical) {
			return nil, fail(CodeStoreUnsafe)
		}
	} else {
		s.state = storeSnapshot{Schema: storeSchema, IdentityKey: make([]byte, 32), Sources: []SourceView{}, Candidates: []storeCandidate{}, Requests: []storeRequest{}, Audit: []storeAudit{}}
		if _, err := rand.Read(s.state.IdentityKey); err != nil {
			return nil, fail(CodeStoreUnsafe)
		}
		encoded, err := storeEncode(s.state)
		if err != nil {
			return nil, err
		}
		if _, err := disk.write(encoded); err != nil {
			return nil, err
		}
	}
	keep = true
	return s, nil
}

func (s *Store) Close() error {
	if s == nil || s.storeCore == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.disk.close()
}

func (s *Store) usable() error {
	if s.closed {
		return fail(CodeStoreClosed)
	}
	if s.poisoned {
		return fail(CodeCommitUncertain)
	}
	return s.disk.verify()
}

func storeValidLabel(label string) bool {
	if label == "" || len(label) > 128 || !utf8.ValidString(label) || strings.TrimSpace(label) != label {
		return false
	}
	for _, r := range label {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune(" ._-", r) {
			return false
		}
	}
	return true
}
func storeValidCaller(scope Scope, actor, key string) bool {
	return validScope(scope) && validActor(actor) && validIdempotency(key)
}
func (s *Store) request(scope Scope, actor, key, action string, data any) storeRequest {
	raw, _ := json.Marshal(data)
	return storeRequest{Key: keyedDigest(s.state.IdentityKey, []byte("idempotency"), []byte(scopeKey(scope)), []byte(actor), []byte(key)), Fingerprint: keyedDigest(s.state.IdentityKey, []byte("request"), []byte(scopeKey(scope)), []byte(actor), []byte(action), raw), Action: action}
}
func (s *Store) replay(req storeRequest) (storeRequest, bool, error) {
	for _, old := range s.state.Requests {
		if old.Key == req.Key {
			if old.Fingerprint != req.Fingerprint || old.Action != req.Action {
				return storeRequest{}, false, fail(CodeConflict)
			}
			return old, true, nil
		}
	}
	return storeRequest{}, false, nil
}
func storeSource(state *storeSnapshot, scope Scope, id string) (int, error) {
	if !validScope(scope) || !validSource(id) {
		return -1, fail(CodeInputInvalid)
	}
	for i, source := range state.Sources {
		if source.ID == id {
			if source.Scope != scope {
				return -1, fail(CodeScopeDenied)
			}
			return i, nil
		}
	}
	return -1, fail(CodeNotFound)
}
func storeCandidateIndex(state *storeSnapshot, sourceID, id string) (int, error) {
	if !storeCandidatePattern.MatchString(id) {
		return -1, fail(CodeInputInvalid)
	}
	for i, candidate := range state.Candidates {
		if candidate.View.ID == id && candidate.View.SourceID == sourceID {
			return i, nil
		}
	}
	return -1, fail(CodeNotFound)
}
func storeDetached(value CandidateView) CandidateView {
	value.Nodes = append([]NodeView{}, value.Nodes...)
	return value
}
func storeClone(value storeSnapshot) storeSnapshot {
	raw, _ := json.Marshal(value)
	var result storeSnapshot
	_ = json.Unmarshal(raw, &result)
	return result
}
func storeAuditHash(entry storeAudit) string {
	entry.Hash = ""
	raw, _ := json.Marshal(entry)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
func storeNext(revision uint64) (uint64, error) {
	if revision == math.MaxUint64 {
		return 0, fail(CodeConflict)
	}
	return revision + 1, nil
}

func (s *Store) commit(next storeSnapshot, request storeRequest, source SourceView, candidateID, actor, action, result string) error {
	if len(next.Audit) >= MaxAuditEntries {
		return fail(CodeStoreLimit)
	}
	at := s.now().UTC()
	if at.IsZero() || (len(next.Audit) != 0 && at.Before(next.Audit[len(next.Audit)-1].At)) {
		return fail(CodeStoreUnsafe)
	}
	previous := strings.Repeat("0", 64)
	if len(next.Audit) != 0 {
		previous = next.Audit[len(next.Audit)-1].Hash
	}
	entry := storeAudit{Sequence: uint64(len(next.Audit) + 1), Actor: actor, Scope: source.Scope, SourceID: source.ID, CandidateID: candidateID, Revision: source.Revision, Action: action, Result: result, Key: request.Key, RequestDigest: request.Fingerprint, At: at, PreviousHash: previous}
	entry.Hash = storeAuditHash(entry)
	request.SourceID, request.CandidateID = source.ID, candidateID
	next.Requests = append(next.Requests, request)
	next.Audit = append(next.Audit, entry)
	for i := range next.Sources {
		if next.Sources[i].ID == source.ID {
			next.Sources[i].UpdatedAt = at
		}
	}
	if err := storeValidate(next); err != nil {
		return err
	}
	raw, err := storeEncode(next)
	if err != nil {
		return err
	}
	uncertain, err := s.disk.write(raw)
	if err != nil {
		if uncertain {
			s.poisoned = true
			return fail(CodeCommitUncertain)
		}
		return err
	}
	s.state = next
	return nil
}

func (s *Store) CreateSource(scope Scope, label, actor, idempotency string) (SourceView, error) {
	if s == nil || s.storeCore == nil {
		return SourceView{}, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return SourceView{}, err
	}
	if !storeValidCaller(scope, actor, idempotency) || !storeValidLabel(label) {
		return SourceView{}, fail(CodeInputInvalid)
	}
	req := s.request(scope, actor, idempotency, "create", label)
	if old, yes, err := s.replay(req); err != nil {
		return SourceView{}, err
	} else if yes {
		i, err := storeSource(&s.state, scope, old.SourceID)
		if err != nil {
			return SourceView{}, err
		}
		return s.state.Sources[i], nil
	}
	if len(s.state.Sources) >= MaxSources {
		return SourceView{}, fail(CodeStoreLimit)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return SourceView{}, fail(CodeStoreUnsafe)
	}
	source := SourceView{ID: "src_" + hex.EncodeToString(random[:]), Scope: scope, Label: label, Revision: 1}
	for _, existing := range s.state.Sources {
		if existing.ID == source.ID {
			return SourceView{}, fail(CodeConflict)
		}
	}
	next := storeClone(s.state)
	next.Sources = append(next.Sources, source)
	if err := s.commit(next, req, source, "", actor, "create", "created"); err != nil {
		return SourceView{}, err
	}
	return s.state.Sources[len(s.state.Sources)-1], nil
}

func (s *Store) Import(input ImportRequest) (CandidateView, error) {
	if s == nil || s.storeCore == nil {
		return CandidateView{}, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return CandidateView{}, err
	}
	if !storeValidCaller(input.Scope, input.ActorID, input.IdempotencyKey) {
		return CandidateView{}, fail(CodeInputInvalid)
	}
	si, err := storeSource(&s.state, input.Scope, input.SourceID)
	if err != nil {
		return CandidateView{}, err
	}
	if len(input.Content) > MaxInputBytes {
		return CandidateView{}, fail(CodeInputLimit)
	}
	req := s.request(input.Scope, input.ActorID, input.IdempotencyKey, "import", struct {
		Source   string
		Revision uint64
		Format   Format
		Content  []byte
	}{input.SourceID, input.ExpectedRevision, input.Format, input.Content})
	if old, yes, err := s.replay(req); err != nil {
		return CandidateView{}, err
	} else if yes {
		i, err := storeCandidateIndex(&s.state, input.SourceID, old.CandidateID)
		if err != nil {
			return CandidateView{}, err
		}
		return storeDetached(s.state.Candidates[i].View), nil
	}
	source := s.state.Sources[si]
	if source.Revision != input.ExpectedRevision {
		return CandidateView{}, fail(CodeConflict)
	}
	parsed, err := Parse(ParseInput{Scope: input.Scope, SourceID: input.SourceID, Format: input.Format, Content: append([]byte{}, input.Content...), IdentityKey: append([]byte{}, s.state.IdentityKey...)})
	if err != nil {
		return CandidateView{}, err
	}
	id := "cand_" + keyedDigest(s.state.IdentityKey, []byte("candidate"), []byte(scopeKey(input.Scope)), []byte(input.SourceID), []byte(parsed.Digest))[:32]
	for _, old := range s.state.Candidates {
		if old.View.ID == id {
			if old.View.SourceID != source.ID || !bytes.Equal(old.Raw, input.Content) {
				return CandidateView{}, fail(CodeConflict)
			}
			return storeDetached(old.View), nil
		}
	}
	if len(s.state.Candidates) >= MaxCandidates {
		return CandidateView{}, fail(CodeStoreLimit)
	}
	count := 0
	for _, old := range s.state.Candidates {
		if old.View.SourceID == source.ID {
			count++
		}
	}
	if count >= MaxCandidates {
		return CandidateView{}, fail(CodeStoreLimit)
	}
	revision, err := storeNext(source.Revision)
	if err != nil {
		return CandidateView{}, err
	}
	view := CandidateView{ID: id, SourceID: source.ID, Scope: source.Scope, Digest: parsed.Digest, Format: parsed.Format, State: CandidateQuarantined, BaseRevision: revision, NodeCount: len(parsed.Nodes), DuplicateCount: parsed.DuplicateCount, Nodes: []NodeView{}, CreatedAt: s.now().UTC()}
	private := storeCandidate{View: view, Raw: append([]byte{}, input.Content...), Nodes: []storeNode{}}
	for _, node := range parsed.Nodes {
		private.View.Nodes = append(private.View.Nodes, nodeView(node))
		private.Nodes = append(private.Nodes, storeNode{ID: node.ID, Protocol: node.Protocol, PrivateName: node.PrivateName, Config: append(json.RawMessage{}, node.Config...), CredentialConfigured: node.CredentialConfigured})
	}
	next := storeClone(s.state)
	source.Revision, source.LatestCandidateID = revision, id
	next.Sources[si] = source
	next.Candidates = append(next.Candidates, private)
	if err := s.commit(next, req, source, id, input.ActorID, "import", string(CandidateQuarantined)); err != nil {
		return CandidateView{}, err
	}
	return storeDetached(private.View), nil
}

func (s *Store) Decide(input DecisionRequest) (SourceView, error) {
	if s == nil || s.storeCore == nil {
		return SourceView{}, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return SourceView{}, err
	}
	if !storeValidCaller(input.Scope, input.ActorID, input.IdempotencyKey) || (input.Decision != CandidateAdmitted && input.Decision != CandidateRejected) {
		return SourceView{}, fail(CodeInputInvalid)
	}
	si, err := storeSource(&s.state, input.Scope, input.SourceID)
	if err != nil {
		return SourceView{}, err
	}
	ci, err := storeCandidateIndex(&s.state, input.SourceID, input.CandidateID)
	if err != nil {
		return SourceView{}, err
	}
	req := s.request(input.Scope, input.ActorID, input.IdempotencyKey, "decide", struct {
		Source, Candidate string
		Revision          uint64
		Digest            string
		Decision          CandidateState
	}{input.SourceID, input.CandidateID, input.ExpectedRevision, input.ExpectedDigest, input.Decision})
	if _, yes, err := s.replay(req); err != nil {
		return SourceView{}, err
	} else if yes {
		return s.state.Sources[si], nil
	}
	source, candidate := s.state.Sources[si], s.state.Candidates[ci].View
	if input.ExpectedRevision != source.Revision || candidate.BaseRevision != source.Revision || input.ExpectedDigest != candidate.Digest || candidate.State != CandidateQuarantined {
		return SourceView{}, fail(CodeConflict)
	}
	revision, err := storeNext(source.Revision)
	if err != nil {
		return SourceView{}, err
	}
	next := storeClone(s.state)
	source.Revision = revision
	if input.Decision == CandidateAdmitted {
		source.AcceptedCandidateID = candidate.ID
	}
	next.Sources[si] = source
	next.Candidates[ci].View.State = input.Decision
	if err := s.commit(next, req, source, candidate.ID, input.ActorID, "decide", string(input.Decision)); err != nil {
		return SourceView{}, err
	}
	return s.state.Sources[si], nil
}

// Rollback selects a previously admitted local candidate under CURRENT source
// CAS. Its historical BaseRevision is not authorization for a new decision.
// It creates a new revision and does not execute any runtime/device rollback.
func (s *Store) Rollback(scope Scope, sourceID, candidateID string, expectedRevision uint64, actor, idempotency string) (SourceView, error) {
	if s == nil || s.storeCore == nil {
		return SourceView{}, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return SourceView{}, err
	}
	if !storeValidCaller(scope, actor, idempotency) {
		return SourceView{}, fail(CodeInputInvalid)
	}
	si, err := storeSource(&s.state, scope, sourceID)
	if err != nil {
		return SourceView{}, err
	}
	ci, err := storeCandidateIndex(&s.state, sourceID, candidateID)
	if err != nil {
		return SourceView{}, err
	}
	req := s.request(scope, actor, idempotency, "rollback", struct {
		Source, Candidate string
		Revision          uint64
	}{sourceID, candidateID, expectedRevision})
	if _, yes, err := s.replay(req); err != nil {
		return SourceView{}, err
	} else if yes {
		return s.state.Sources[si], nil
	}
	source := s.state.Sources[si]
	if source.Revision != expectedRevision || s.state.Candidates[ci].View.State != CandidateAdmitted {
		return SourceView{}, fail(CodeConflict)
	}
	revision, err := storeNext(source.Revision)
	if err != nil {
		return SourceView{}, err
	}
	next := storeClone(s.state)
	source.Revision, source.AcceptedCandidateID = revision, candidateID
	next.Sources[si] = source
	if err := s.commit(next, req, source, candidateID, actor, "rollback", string(CandidateAdmitted)); err != nil {
		return SourceView{}, err
	}
	return s.state.Sources[si], nil
}

func (s *Store) Sources(scope Scope) ([]SourceView, error) {
	if s == nil || s.storeCore == nil {
		return nil, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return nil, err
	}
	if !validScope(scope) {
		return nil, fail(CodeInputInvalid)
	}
	items := []SourceView{}
	for _, source := range s.state.Sources {
		if source.Scope == scope {
			items = append(items, source)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}
func (s *Store) Candidates(scope Scope, sourceID string) ([]CandidateView, error) {
	if s == nil || s.storeCore == nil {
		return nil, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return nil, err
	}
	if _, err := storeSource(&s.state, scope, sourceID); err != nil {
		return nil, err
	}
	items := []CandidateView{}
	for _, candidate := range s.state.Candidates {
		if candidate.View.SourceID == sourceID {
			items = append(items, storeDetached(candidate.View))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}
func (s *Store) Candidate(scope Scope, sourceID, candidateID string) (CandidateView, error) {
	if s == nil || s.storeCore == nil {
		return CandidateView{}, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return CandidateView{}, err
	}
	if _, err := storeSource(&s.state, scope, sourceID); err != nil {
		return CandidateView{}, err
	}
	i, err := storeCandidateIndex(&s.state, sourceID, candidateID)
	if err != nil {
		return CandidateView{}, err
	}
	return storeDetached(s.state.Candidates[i].View), nil
}

func storeEncode(state storeSnapshot) ([]byte, error) {
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, fail(CodeStoreUnsafe)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxStoreBytes {
		return nil, fail(CodeStoreLimit)
	}
	// A successful commit must remain readable under the same bounded strict
	// decoder after restart, including its token/depth budgets.
	var bounded storeSnapshot
	if err := storeDecode(raw, &bounded); err != nil {
		return nil, fail(CodeStoreLimit)
	}
	return raw, nil
}
func storeDecode(raw []byte, state *storeSnapshot) error {
	if len(raw) == 0 || len(raw) > MaxStoreBytes {
		return fail(CodeStoreUnsafe)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var value func(int) error
	value = func(depth int) error {
		if depth > MaxDepth+8 {
			return fail(CodeStoreUnsafe)
		}
		tokens++
		if tokens > 1<<20 {
			return fail(CodeStoreUnsafe)
		}
		token, err := d.Token()
		if err != nil {
			return fail(CodeStoreUnsafe)
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return fail(CodeStoreUnsafe)
					}
					name, ok := key.(string)
					if !ok || seen[name] {
						return fail(CodeStoreUnsafe)
					}
					seen[name] = true
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return fail(CodeStoreUnsafe)
				}
			case '[':
				for d.More() {
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return fail(CodeStoreUnsafe)
				}
			default:
				return fail(CodeStoreUnsafe)
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fail(CodeStoreUnsafe)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(state) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return fail(CodeStoreUnsafe)
	}
	return nil
}

func storeValidate(state storeSnapshot) error {
	bad := func() error { return fail(CodeStoreUnsafe) }
	if state.Schema != storeSchema || len(state.IdentityKey) != 32 || state.Sources == nil || state.Candidates == nil || state.Requests == nil || state.Audit == nil || len(state.Sources) > MaxSources || len(state.Candidates) > MaxCandidates || len(state.Audit) > MaxAuditEntries || len(state.Requests) != len(state.Audit) {
		return bad()
	}
	sources := map[string]SourceView{}
	candidates := map[string]storeCandidate{}
	perSource := map[string]int{}
	for _, src := range state.Sources {
		if !validSource(src.ID) || !validScope(src.Scope) || !storeValidLabel(src.Label) || src.Revision == 0 || src.UpdatedAt.IsZero() {
			return bad()
		}
		if _, ok := sources[src.ID]; ok {
			return bad()
		}
		sources[src.ID] = src
	}
	for _, c := range state.Candidates {
		v := c.View
		src, ok := sources[v.SourceID]
		if !ok || v.Scope != src.Scope || !storeCandidatePattern.MatchString(v.ID) || !storeDigestPattern.MatchString(v.Digest) || v.BaseRevision < 2 || v.BaseRevision > src.Revision || v.CreatedAt.IsZero() || v.Nodes == nil || c.Nodes == nil || len(c.Raw) == 0 || len(c.Raw) > MaxInputBytes {
			return bad()
		}
		if _, ok := candidates[v.ID]; ok {
			return bad()
		}
		perSource[v.SourceID]++
		if perSource[v.SourceID] > MaxCandidates {
			return bad()
		}
		parsed, err := Parse(ParseInput{Scope: v.Scope, SourceID: v.SourceID, Format: v.Format, Content: append([]byte{}, c.Raw...), IdentityKey: append([]byte{}, state.IdentityKey...)})
		if err != nil {
			return bad()
		}
		expectedID := "cand_" + keyedDigest(state.IdentityKey, []byte("candidate"), []byte(scopeKey(v.Scope)), []byte(v.SourceID), []byte(parsed.Digest))[:32]
		if v.ID != expectedID || v.Digest != parsed.Digest || v.Format != parsed.Format || v.NodeCount != len(parsed.Nodes) || v.DuplicateCount != parsed.DuplicateCount || len(c.Nodes) != len(parsed.Nodes) || len(v.Nodes) != len(parsed.Nodes) {
			return bad()
		}
		for i, n := range parsed.Nodes {
			p := c.Nodes[i]
			if p.ID != n.ID || p.Protocol != n.Protocol || p.PrivateName != n.PrivateName || p.CredentialConfigured != n.CredentialConfigured || !bytes.Equal(p.Config, n.Config) || v.Nodes[i] != nodeView(n) {
				return bad()
			}
		}
		candidates[v.ID] = c
	}
	current := map[string]SourceView{}
	states := map[string]CandidateState{}
	seenKeys := map[string]bool{}
	previous := strings.Repeat("0", 64)
	var last time.Time
	for i, a := range state.Audit {
		if a.Sequence != uint64(i+1) || !validActor(a.Actor) || !validScope(a.Scope) || !storeHexPattern.MatchString(a.Key) || !storeHexPattern.MatchString(a.RequestDigest) || seenKeys[a.Key] || a.At.IsZero() || a.At.Before(last) || a.PreviousHash != previous || a.Hash != storeAuditHash(a) {
			return bad()
		}
		src, ok := sources[a.SourceID]
		if !ok || src.Scope != a.Scope {
			return bad()
		}
		r := state.Requests[i]
		if r.Key != a.Key || r.Fingerprint != a.RequestDigest || r.Action != a.Action || r.SourceID != a.SourceID || r.CandidateID != a.CandidateID {
			return bad()
		}
		seenKeys[a.Key] = true
		cur, exists := current[a.SourceID]
		if a.Action == "create" {
			if exists || a.Revision != 1 || a.CandidateID != "" || a.Result != "created" {
				return bad()
			}
			cur = SourceView{ID: src.ID, Scope: src.Scope, Label: src.Label, Revision: 1}
		} else {
			if !exists || cur.Revision == math.MaxUint64 || a.Revision != cur.Revision+1 {
				return bad()
			}
			c, ok := candidates[a.CandidateID]
			if !ok || c.View.SourceID != src.ID {
				return bad()
			}
			switch a.Action {
			case "import":
				if _, ok := states[a.CandidateID]; ok || c.View.BaseRevision != a.Revision || a.Result != string(CandidateQuarantined) || c.View.CreatedAt.After(a.At) {
					return bad()
				}
				states[a.CandidateID] = CandidateQuarantined
				cur.LatestCandidateID = a.CandidateID
			case "decide":
				if states[a.CandidateID] != CandidateQuarantined || c.View.BaseRevision != cur.Revision {
					return bad()
				}
				switch CandidateState(a.Result) {
				case CandidateAdmitted:
					states[a.CandidateID] = CandidateAdmitted
					cur.AcceptedCandidateID = a.CandidateID
				case CandidateRejected:
					states[a.CandidateID] = CandidateRejected
				default:
					return bad()
				}
			case "rollback":
				if states[a.CandidateID] != CandidateAdmitted || a.Result != string(CandidateAdmitted) {
					return bad()
				}
				cur.AcceptedCandidateID = a.CandidateID
			default:
				return bad()
			}
			cur.Revision = a.Revision
		}
		cur.UpdatedAt = a.At
		current[a.SourceID] = cur
		previous, last = a.Hash, a.At
	}
	if len(current) != len(sources) || len(states) != len(candidates) {
		return bad()
	}
	for id, src := range sources {
		if current[id] != src {
			return bad()
		}
	}
	for id, c := range candidates {
		if states[id] != c.View.State {
			return bad()
		}
	}
	return storeValidateControl(state)
}
