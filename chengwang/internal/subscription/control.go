package subscription

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

const MaxControlCommands = 4096

type StoreCapacity struct {
	CommandsUsed    int `json:"commandsUsed"`
	CommandsMax     int `json:"commandsMax"`
	CandidatesUsed  int `json:"candidatesUsed"`
	CandidatesMax   int `json:"candidatesMax"`
	DomainAuditUsed int `json:"domainAuditUsed"`
	DomainAuditMax  int `json:"domainAuditMax"`
	EncodedBytes    int `json:"encodedBytes"`
	EncodedBytesMax int `json:"encodedBytesMax"`
}

func (s *Store) Capacity(scope Scope) (StoreCapacity, error) {
	if s == nil || s.storeCore == nil {
		return StoreCapacity{}, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return StoreCapacity{}, err
	}
	if !validScope(scope) {
		return StoreCapacity{}, fail(CodeInputInvalid)
	}
	raw, err := storeEncode(s.state)
	if err != nil {
		return StoreCapacity{}, err
	}
	return StoreCapacity{CommandsUsed: len(s.state.Commands), CommandsMax: MaxControlCommands, CandidatesUsed: len(s.state.Candidates), CandidatesMax: MaxCandidates, DomainAuditUsed: len(s.state.Audit), DomainAuditMax: MaxAuditEntries, EncodedBytes: len(raw), EncodedBytesMax: MaxStoreBytes}, nil
}

const refreshCheckpointPrefix = "refresh-epoch-"

// LatestRefreshCheckpoint uses only fields understood by the strict v1
// reader. Commands are append-only, so the last valid marker is authoritative.
func (s *Store) LatestRefreshCheckpoint(scope Scope) (string, string, bool, error) {
	if s == nil || s.storeCore == nil {
		return "", "", false, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return "", "", false, err
	}
	if !validScope(scope) {
		return "", "", false, fail(CodeInputInvalid)
	}
	var id, epoch string
	for _, d := range s.state.Commands {
		c := d.Record
		if c.Scope != scope || !c.Acknowledged || c.Result == nil || c.Result.State != "failed" || !strings.HasPrefix(c.Result.ReferenceID, refreshCheckpointPrefix) {
			continue
		}
		e := strings.TrimPrefix(c.Result.ReferenceID, refreshCheckpointPrefix)
		if !storeHexPattern.MatchString(e) {
			return "", "", false, fail(CodeStoreUnsafe)
		}
		id, epoch = c.ID, e
	}
	return id, epoch, id != "", nil
}

var controlIDPattern = regexp.MustCompile(`^cmd_[a-f0-9]{32}$`)
var controlReferencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// MutationReceipt is reconstructed from the ORIGINAL immutable domain audit,
// not a current SourceView or CandidateView. No-op imports have no receipt.
type MutationReceipt struct {
	Scope                                  Scope
	ActorID, Action, SourceID, CandidateID string
	Revision                               uint64
	Digest, State, LocalAuditHash          string
	CompletedAt                            time.Time
}

type ControlIdentity struct {
	ID          string `json:"-"`
	ActorID     string `json:"-"`
	CoreKey     string `json:"-"`
	KeyDigest   string `json:"-"`
	Fingerprint string `json:"-"`
}

func (ControlIdentity) String() string   { return "subscription private command identity" }
func (ControlIdentity) GoString() string { return "subscription private command identity" }

// ControlResult is an immutable safe projection. State is committed, noop,
// approved, failed or unknown. Unknown never authorizes automatic replay.
type ControlResult struct {
	SourceID            string    `json:"sourceId,omitempty"`
	CandidateID         string    `json:"candidateId,omitempty"`
	Revision            uint64    `json:"revision"`
	Digest              string    `json:"digest,omitempty"`
	State               string    `json:"state"`
	Code                string    `json:"code,omitempty"`
	StateMayHaveChanged bool      `json:"stateMayHaveChanged"`
	LocalAuditHash      string    `json:"localAuditHash,omitempty"`
	ReferenceID         string    `json:"referenceId,omitempty"`
	PolicyRevision      uint64    `json:"policyRevision,omitempty"`
	PolicyDigest        string    `json:"policyDigest,omitempty"`
	ApprovalID          string    `json:"approvalId,omitempty"`
	CompletedAt         time.Time `json:"completedAt"`
}

type ControlCommand struct {
	ID                string         `json:"id"`
	Scope             Scope          `json:"scope"`
	ActorID           string         `json:"actorId"`
	Kind              string         `json:"kind"`
	SourceID          string         `json:"sourceId,omitempty"`
	ExpectedRevision  uint64         `json:"expectedRevision"`
	Fingerprint       string         `json:"fingerprint"`
	PreparedAt        time.Time      `json:"preparedAt"`
	PreparedAuditHash string         `json:"preparedAuditHash"`
	Result            *ControlResult `json:"result,omitempty"`
	ResultAuditHash   string         `json:"resultAuditHash,omitempty"`
	Acknowledged      bool           `json:"acknowledged"`
	OwnerID           string         `json:"-"`
	CoreKey           string         `json:"-"`
	KeyDigest         string         `json:"-"`
}

func (ControlCommand) String() string   { return "subscription private command record" }
func (ControlCommand) GoString() string { return "subscription private command record" }

type controlCommandDisk struct {
	Record    ControlCommand `json:"record"`
	OwnerID   string         `json:"ownerId"`
	CoreKey   string         `json:"coreKey"`
	KeyDigest string         `json:"keyDigest"`
	Seal      string         `json:"seal"`
}

type ControlApproval struct {
	CommandID      string    `json:"commandId"`
	Scope          Scope     `json:"scope"`
	SourceID       string    `json:"sourceId"`
	ReferenceID    string    `json:"referenceId"`
	PolicyRevision uint64    `json:"policyRevision"`
	PolicyDigest   string    `json:"policyDigest"`
	SourceRevision uint64    `json:"sourceRevision"`
	ApprovedAt     time.Time `json:"approvedAt"`
	Seal           string    `json:"seal"`
}

func controlActor(identity []byte, scope Scope, owner string) string {
	key, _ := hex.DecodeString(keyedDigest(identity, []byte("control-actor-key"), []byte(scopeKey(scope))))
	return "act_" + keyedDigest(key, []byte(owner))[:60]
}

// ControlActorFactory captures only a derived scope key at startup. Denial
// auditing can subsequently classify an actor without disk/private reads.
func (s *Store) ControlActorFactory(scope Scope) (func(string) string, error) {
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
	key, _ := hex.DecodeString(keyedDigest(s.state.IdentityKey, []byte("control-actor-key"), []byte(scopeKey(scope))))
	return func(owner string) string { return "act_" + keyedDigest(key, []byte(owner))[:60] }, nil
}

func (s *Store) ControlIdentity(scope Scope, owner, key string, material []byte) (ControlIdentity, error) {
	if s == nil || s.storeCore == nil {
		return ControlIdentity{}, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return ControlIdentity{}, err
	}
	if !validScope(scope) || !parserText(owner, false) || strings.TrimSpace(owner) != owner || !validIdempotency(key) || len(material) > MaxInputBytes+16384 {
		return ControlIdentity{}, fail(CodeInputInvalid)
	}
	digest := keyedDigest(s.state.IdentityKey, []byte("control-key"), []byte(scopeKey(scope)), []byte(owner), []byte(key))
	return ControlIdentity{ID: "cmd_" + digest[:32], ActorID: controlActor(s.state.IdentityKey, scope, owner), CoreKey: "ctl_" + digest[:60], KeyDigest: digest, Fingerprint: "hmac-sha256:" + keyedDigest(s.state.IdentityKey, []byte("control-fingerprint"), []byte(scopeKey(scope)), []byte(owner), material)}, nil
}

func (s *Store) Source(scope Scope, sourceID string) (SourceView, error) {
	if s == nil || s.storeCore == nil {
		return SourceView{}, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return SourceView{}, err
	}
	i, err := storeSource(&s.state, scope, sourceID)
	if err != nil {
		return SourceView{}, err
	}
	return s.state.Sources[i], nil
}

func (s *Store) SealPolicy(scope Scope, sourceID string, material []byte) (string, error) {
	if s == nil || s.storeCore == nil {
		return "", fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return "", err
	}
	if _, err := storeSource(&s.state, scope, sourceID); err != nil {
		return "", err
	}
	if len(material) == 0 || len(material) > MaxInputBytes {
		return "", fail(CodeInputLimit)
	}
	return "hmac-sha256:" + keyedDigest(s.state.IdentityKey, []byte("control-policy"), []byte(scopeKey(scope)), []byte(sourceID), material), nil
}

func controlToDisk(command ControlCommand) controlCommandDisk {
	d := controlCommandDisk{Record: command, OwnerID: command.OwnerID, CoreKey: command.CoreKey, KeyDigest: command.KeyDigest}
	d.Record.OwnerID, d.Record.CoreKey, d.Record.KeyDigest = "", "", ""
	if command.Result != nil {
		result := *command.Result
		d.Record.Result = &result
	}
	return d
}
func controlFromDisk(d controlCommandDisk) ControlCommand {
	c := d.Record
	c.OwnerID, c.CoreKey, c.KeyDigest = d.OwnerID, d.CoreKey, d.KeyDigest
	if c.Result != nil {
		result := *c.Result
		c.Result = &result
	}
	return c
}
func controlCommandSeal(key []byte, d controlCommandDisk) string {
	d.Seal = ""
	raw, _ := json.Marshal(d)
	return keyedDigest(key, []byte("control-command-record"), raw)
}
func controlApprovalSeal(key []byte, a ControlApproval) string {
	a.Seal = ""
	raw, _ := json.Marshal(a)
	return keyedDigest(key, []byte("control-approval-record"), raw)
}
func controlIndex(state *storeSnapshot, scope Scope, id string) (int, error) {
	if !validScope(scope) || !controlIDPattern.MatchString(id) {
		return -1, fail(CodeInputInvalid)
	}
	for i, d := range state.Commands {
		if d.Record.ID == id {
			if d.Record.Scope != scope {
				return -1, fail(CodeScopeDenied)
			}
			return i, nil
		}
	}
	return -1, fail(CodeNotFound)
}

func (s *Store) ControlCommand(scope Scope, id string) (ControlCommand, bool, error) {
	if s == nil || s.storeCore == nil {
		return ControlCommand{}, false, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return ControlCommand{}, false, err
	}
	i, err := controlIndex(&s.state, scope, id)
	if e, ok := err.(*Failure); ok && e.Code == CodeNotFound {
		return ControlCommand{}, false, nil
	}
	if err != nil {
		return ControlCommand{}, false, err
	}
	return controlFromDisk(s.state.Commands[i]), true, nil
}
func (s *Store) ControlCommands(scope Scope) ([]ControlCommand, error) {
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
	result := []ControlCommand{}
	for _, d := range s.state.Commands {
		if d.Record.Scope == scope {
			result = append(result, controlFromDisk(d))
		}
	}
	return result, nil
}

// controlPersist changes only control metadata. Domain bytes in this snapshot
// are already validated under the same Store mutex. Do not call Parse during
// result/ACK recovery; the original full validator still runs on OpenStore and
// every actual domain commit.
func (s *Store) controlPersist(next storeSnapshot) error {
	if err := storeValidateControl(next); err != nil {
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

// RecordControlPrepared is called only AFTER durable external prepared audit.
func (s *Store) RecordControlPrepared(command ControlCommand) (bool, error) {
	if s == nil || s.storeCore == nil {
		return false, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return false, err
	}
	for _, old := range s.state.Commands {
		if old.Record.ID == command.ID {
			d := controlToDisk(command)
			d.Seal = old.Seal
			original := old
			original.Record.Result = nil
			original.Record.ResultAuditHash = ""
			original.Record.Acknowledged = false
			original.Seal = old.Seal
			a, _ := json.Marshal(original)
			b, _ := json.Marshal(d)
			if !bytes.Equal(a, b) {
				return false, fail(CodeConflict)
			}
			return false, nil
		}
	}
	if len(s.state.Commands) >= MaxControlCommands {
		return false, fail(CodeStoreLimit)
	}
	if command.Result != nil || command.ResultAuditHash != "" || command.Acknowledged {
		return false, fail(CodeInputInvalid)
	}
	next := storeClone(s.state)
	d := controlToDisk(command)
	d.Seal = controlCommandSeal(next.IdentityKey, d)
	next.Commands = append(next.Commands, d)
	if err := s.controlPersist(next); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) RecordControlResult(scope Scope, id string, result ControlResult) error {
	if s == nil || s.storeCore == nil {
		return fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	i, err := controlIndex(&s.state, scope, id)
	if err != nil {
		return err
	}
	if existing := s.state.Commands[i].Record.Result; existing != nil {
		a, _ := json.Marshal(existing)
		b, _ := json.Marshal(result)
		if bytes.Equal(a, b) {
			return nil
		}
		return fail(CodeConflict)
	}
	next := storeClone(s.state)
	next.Commands[i].Record.Result = &result
	next.Commands[i].Seal = controlCommandSeal(next.IdentityKey, next.Commands[i])
	return s.controlPersist(next)
}
func (s *Store) AcknowledgeControl(scope Scope, id, hash string) error {
	if s == nil || s.storeCore == nil {
		return fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	i, err := controlIndex(&s.state, scope, id)
	if err != nil {
		return err
	}
	c := s.state.Commands[i].Record
	if c.Result == nil || !storeHexPattern.MatchString(hash) {
		return fail(CodeInputInvalid)
	}
	if c.Acknowledged {
		if c.ResultAuditHash == hash {
			return nil
		}
		return fail(CodeConflict)
	}
	next := storeClone(s.state)
	next.Commands[i].Record.ResultAuditHash = hash
	next.Commands[i].Record.Acknowledged = true
	next.Commands[i].Seal = controlCommandSeal(next.IdentityKey, next.Commands[i])
	return s.controlPersist(next)
}

func mutationFromState(state *storeSnapshot, scope Scope, actor, key string) (MutationReceipt, bool, error) {
	if !validScope(scope) || !validActor(actor) || !validIdempotency(key) {
		return MutationReceipt{}, false, fail(CodeInputInvalid)
	}
	digest := keyedDigest(state.IdentityKey, []byte("idempotency"), []byte(scopeKey(scope)), []byte(actor), []byte(key))
	for i, r := range state.Requests {
		if r.Key == digest {
			a := state.Audit[i]
			if a.Scope != scope || a.Actor != actor {
				return MutationReceipt{}, false, fail(CodeScopeDenied)
			}
			out := MutationReceipt{Scope: a.Scope, ActorID: a.Actor, Action: a.Action, SourceID: a.SourceID, CandidateID: a.CandidateID, Revision: a.Revision, State: a.Result, LocalAuditHash: a.Hash, CompletedAt: a.At}
			for _, candidate := range state.Candidates {
				if candidate.View.ID == a.CandidateID {
					out.Digest = candidate.View.Digest
				}
			}
			return out, true, nil
		}
	}
	return MutationReceipt{}, false, nil
}
func (s *Store) MutationReceipt(scope Scope, actor, key string) (MutationReceipt, bool, error) {
	if s == nil || s.storeCore == nil {
		return MutationReceipt{}, false, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return MutationReceipt{}, false, err
	}
	return mutationFromState(&s.state, scope, actor, key)
}

func (s *Store) CurrentApproval(scope Scope, sourceID string) (ControlApproval, bool, error) {
	if s == nil || s.storeCore == nil {
		return ControlApproval{}, false, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return ControlApproval{}, false, err
	}
	if _, err := storeSource(&s.state, scope, sourceID); err != nil {
		return ControlApproval{}, false, err
	}
	for i := len(s.state.Approvals) - 1; i >= 0; i-- {
		a := s.state.Approvals[i]
		if a.Scope == scope && a.SourceID == sourceID {
			return a, true, nil
		}
	}
	return ControlApproval{}, false, nil
}
func (s *Store) ApprovalForCommand(scope Scope, id string) (ControlApproval, bool, error) {
	if s == nil || s.storeCore == nil {
		return ControlApproval{}, false, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return ControlApproval{}, false, err
	}
	for _, a := range s.state.Approvals {
		if a.CommandID == id {
			if a.Scope != scope {
				return ControlApproval{}, false, fail(CodeScopeDenied)
			}
			return a, true, nil
		}
	}
	return ControlApproval{}, false, nil
}
func (s *Store) RecordApproval(scope Scope, id, reference string, revision uint64, digest string, expected uint64) (ControlApproval, error) {
	if s == nil || s.storeCore == nil {
		return ControlApproval{}, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return ControlApproval{}, err
	}
	i, err := controlIndex(&s.state, scope, id)
	if err != nil {
		return ControlApproval{}, err
	}
	c := s.state.Commands[i].Record
	if c.Kind != "approve" || c.Result != nil || c.ExpectedRevision != expected || !controlReferencePattern.MatchString(reference) || revision == 0 || !storeDigestPattern.MatchString(digest) {
		return ControlApproval{}, fail(CodeInputInvalid)
	}
	si, err := storeSource(&s.state, scope, c.SourceID)
	if err != nil {
		return ControlApproval{}, err
	}
	if s.state.Sources[si].Revision != expected {
		return ControlApproval{}, fail(CodeConflict)
	}
	for _, a := range s.state.Approvals {
		if a.CommandID == id {
			if a.ReferenceID == reference && a.PolicyRevision == revision && a.PolicyDigest == digest {
				return a, nil
			}
			return ControlApproval{}, fail(CodeConflict)
		}
	}
	a := ControlApproval{CommandID: id, Scope: scope, SourceID: c.SourceID, ReferenceID: reference, PolicyRevision: revision, PolicyDigest: digest, SourceRevision: expected, ApprovedAt: s.now().UTC()}
	a.Seal = controlApprovalSeal(s.state.IdentityKey, a)
	next := storeClone(s.state)
	next.Approvals = append(next.Approvals, a)
	if err := s.controlPersist(next); err != nil {
		return ControlApproval{}, err
	}
	return a, nil
}

func storeValidateControl(state storeSnapshot) error {
	bad := func() error { return fail(CodeStoreUnsafe) }
	if len(state.Commands) > MaxControlCommands || len(state.Approvals) > MaxControlCommands {
		return bad()
	}
	commands := map[string]controlCommandDisk{}
	keys := map[string]bool{}
	for _, d := range state.Commands {
		c := d.Record
		if !controlIDPattern.MatchString(c.ID) || !validScope(c.Scope) || !validActor(c.ActorID) || !parserText(d.OwnerID, false) || strings.TrimSpace(d.OwnerID) != d.OwnerID || !storeHexPattern.MatchString(d.KeyDigest) || c.ID != "cmd_"+d.KeyDigest[:32] || d.CoreKey != "ctl_"+d.KeyDigest[:60] || c.ActorID != controlActor(state.IdentityKey, c.Scope, d.OwnerID) || !storeDigestPattern.MatchString(c.Fingerprint) || c.PreparedAt.IsZero() || !storeHexPattern.MatchString(c.PreparedAuditHash) || d.Seal != controlCommandSeal(state.IdentityKey, d) || c.OwnerID != "" || c.CoreKey != "" || c.KeyDigest != "" {
			return bad()
		}
		if _, ok := commands[c.ID]; ok || keys[d.KeyDigest] {
			return bad()
		}
		keys[d.KeyDigest] = true
		if !parserMember(c.Kind, "create import decide rollback approve fetch") {
			return bad()
		}
		if c.Kind == "create" {
			if c.SourceID != "" || c.ExpectedRevision != 0 {
				return bad()
			}
		} else {
			if !validSource(c.SourceID) || c.ExpectedRevision == 0 {
				return bad()
			}
		}
		if c.Result == nil {
			if c.Acknowledged || c.ResultAuditHash != "" {
				return bad()
			}
		} else {
			r := c.Result
			if r.CompletedAt.IsZero() || r.CompletedAt.Before(c.PreparedAt) || !parserMember(r.State, "committed noop approved failed unknown") || r.Code != "" && !parserMember(r.Code, "subscription_command_invalid subscription_forbidden subscription_writes_disabled subscription_unavailable subscription_command_conflict subscription_command_not_found subscription_audit_degraded subscription_commit_unknown subscription_command_canceled subscription_approval_required subscription_command_limit subscription_fetch_policy_rejected subscription_fetch_unavailable subscription_fetch_http_rejected subscription_fetch_rate_limited") {
				return bad()
			}
			if r.SourceID != "" && !validSource(r.SourceID) || r.CandidateID != "" && !storeCandidatePattern.MatchString(r.CandidateID) || r.Digest != "" && !storeDigestPattern.MatchString(r.Digest) {
				return bad()
			}
			if c.Kind != "create" && r.SourceID != c.SourceID {
				return bad()
			}
			m, found, err := mutationFromState(&state, c.Scope, c.ActorID, d.CoreKey)
			if err != nil {
				return bad()
			}
			if r.State == "committed" {
				action := c.Kind
				if action == "fetch" {
					action = "import"
				}
				if !found || m.Action != action || r.LocalAuditHash != m.LocalAuditHash || r.SourceID != m.SourceID || r.CandidateID != m.CandidateID || r.Revision != m.Revision || r.Digest != m.Digest || !r.CompletedAt.Equal(m.CompletedAt) || r.Code != "" || r.StateMayHaveChanged {
					return bad()
				}
			} else if r.LocalAuditHash != "" || found {
				return bad()
			}
			if r.State == "unknown" {
				if r.Code != "subscription_commit_unknown" || !r.StateMayHaveChanged {
					return bad()
				}
			}
			if r.State == "failed" && (r.Code == "" || r.StateMayHaveChanged) {
				return bad()
			}
			if r.State == "noop" {
				if c.Kind != "import" && c.Kind != "fetch" || r.Code != "" || r.StateMayHaveChanged || r.Revision != c.ExpectedRevision || r.CandidateID == "" {
					return bad()
				}
				valid := false
				for _, v := range state.Candidates {
					if v.View.ID == r.CandidateID && v.View.SourceID == r.SourceID && v.View.Scope == c.Scope && v.View.Digest == r.Digest {
						valid = true
					}
				}
				if !valid {
					return bad()
				}
			}
			if c.Acknowledged != (c.ResultAuditHash != "") || c.ResultAuditHash != "" && !storeHexPattern.MatchString(c.ResultAuditHash) {
				return bad()
			}
		}
		commands[c.ID] = d
	}
	seen := map[string]bool{}
	for _, a := range state.Approvals {
		d, ok := commands[a.CommandID]
		if !ok || seen[a.CommandID] || d.Record.Kind != "approve" || a.Scope != d.Record.Scope || a.SourceID != d.Record.SourceID || a.SourceRevision != d.Record.ExpectedRevision || a.SourceRevision == 0 || !controlReferencePattern.MatchString(a.ReferenceID) || a.PolicyRevision == 0 || !storeDigestPattern.MatchString(a.PolicyDigest) || a.ApprovedAt.IsZero() || a.ApprovedAt.Before(d.Record.PreparedAt) || a.Seal != controlApprovalSeal(state.IdentityKey, a) {
			return bad()
		}
		if _, err := storeSource(&state, a.Scope, a.SourceID); err != nil {
			return bad()
		}
		seen[a.CommandID] = true
		if r := d.Record.Result; r != nil && r.State == "approved" {
			if r.ApprovalID != a.CommandID || r.ReferenceID != a.ReferenceID || r.PolicyRevision != a.PolicyRevision || r.PolicyDigest != a.PolicyDigest || r.Revision != a.SourceRevision || !r.CompletedAt.Equal(a.ApprovedAt) || r.Code != "" || r.StateMayHaveChanged {
				return bad()
			}
		}
	}
	for _, d := range commands {
		if d.Record.Result != nil && d.Record.Result.State == "approved" && !seen[d.Record.ID] {
			return bad()
		}
	}
	return nil
}
