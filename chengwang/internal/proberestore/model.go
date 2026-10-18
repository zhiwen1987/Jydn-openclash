// Package proberestore defines the fail-closed state model and durable journal
// for restoring probe state. It does not control Docker or exchange live state.
//
// The local hash chain and single atomic control record detect partial writes
// and local replay while the same writer retains its in-memory monotonic head.
// They do not resist a privileged administrator replacing a complete valid
// control record before a fresh Open, replacing the whole control directory,
// or rolling back the complete disk/filesystem snapshot. Independent
// signed/WORM anchoring is required for that threat model.
//
// EvidenceSHA256 only binds a transition to an immutable evidence artifact. It
// does not establish that the artifact is truthful or sufficient. A later
// coordinator must read an already-fsynced artifact and verify its strict
// schema, candidate identity, operation identity, topology and freshness before
// asking this package to record a transition. This package never authorizes or
// performs a live restore.
package proberestore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	Schema      = "chengwang.probe-restore-journal/v1"
	GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	ErrInvalidTransition = errors.New("invalid probe restore transition")
	ErrClockRollback     = errors.New("probe restore clock moved backwards")
	ErrInvalidJournal    = errors.New("invalid probe restore journal")
	safeID               = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	safeReason           = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	hashPattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Phase string

const (
	PhaseNew                        Phase = "NEW"
	PhaseLocked                     Phase = "LOCKED"
	PhaseInputVerified              Phase = "INPUT_VERIFIED"
	PhaseLiveQuiesced               Phase = "LIVE_QUIESCED"
	PhaseCurrentBackupDurable       Phase = "CURRENT_BACKUP_DURABLE"
	PhaseStaged                     Phase = "STAGED"
	PhaseStagedValidated            Phase = "STAGED_VALIDATED"
	PhaseSwitchArmed                Phase = "SWITCH_ARMED"
	PhaseStateExchanged             Phase = "STATE_EXCHANGED"
	PhaseContainerRecreated         Phase = "CONTAINER_RECREATED"
	PhaseEgressRebound              Phase = "EGRESS_REBOUND"
	PhaseContainerStarted           Phase = "CONTAINER_STARTED"
	PhaseLocalHealthPassed          Phase = "LOCAL_HEALTH_PASSED"
	PhaseIndependentProbePassed     Phase = "INDEPENDENT_PROBE_PASSED"
	PhaseCommitted                  Phase = "COMMITTED"
	PhaseRollbackArmed              Phase = "ROLLBACK_ARMED"
	PhaseStateRollbackExchanged     Phase = "STATE_ROLLBACK_EXCHANGED"
	PhaseRollbackContainerRecreated Phase = "ROLLBACK_CONTAINER_RECREATED"
	PhaseRollbackEgressRebound      Phase = "ROLLBACK_EGRESS_REBOUND"
	PhaseRollbackContainerStarted   Phase = "ROLLBACK_CONTAINER_STARTED"
	PhaseRollbackHealthPassed       Phase = "ROLLBACK_HEALTH_PASSED"
	PhaseRolledBack                 Phase = "ROLLED_BACK"
	PhaseFailed                     Phase = "FAILED"
	PhaseRescueRequired             Phase = "RESCUE_REQUIRED"
	PhaseRescueLockdown             Phase = "RESCUE_LOCKDOWN"
)

var allPhases = []Phase{PhaseNew, PhaseLocked, PhaseInputVerified, PhaseLiveQuiesced, PhaseCurrentBackupDurable, PhaseStaged, PhaseStagedValidated, PhaseSwitchArmed, PhaseStateExchanged, PhaseContainerRecreated, PhaseEgressRebound, PhaseContainerStarted, PhaseLocalHealthPassed, PhaseIndependentProbePassed, PhaseCommitted, PhaseRollbackArmed, PhaseStateRollbackExchanged, PhaseRollbackContainerRecreated, PhaseRollbackEgressRebound, PhaseRollbackContainerStarted, PhaseRollbackHealthPassed, PhaseRolledBack, PhaseFailed, PhaseRescueRequired, PhaseRescueLockdown}
var transitions = map[Phase]map[Phase]bool{
	PhaseNew: {PhaseLocked: true, PhaseFailed: true, PhaseRescueRequired: true}, PhaseLocked: {PhaseInputVerified: true, PhaseFailed: true, PhaseRescueRequired: true}, PhaseInputVerified: {PhaseLiveQuiesced: true, PhaseFailed: true, PhaseRescueRequired: true}, PhaseLiveQuiesced: {PhaseCurrentBackupDurable: true, PhaseFailed: true, PhaseRescueRequired: true}, PhaseCurrentBackupDurable: {PhaseStaged: true, PhaseFailed: true, PhaseRescueRequired: true}, PhaseStaged: {PhaseStagedValidated: true, PhaseFailed: true, PhaseRescueRequired: true}, PhaseStagedValidated: {PhaseSwitchArmed: true, PhaseFailed: true, PhaseRescueRequired: true}, PhaseSwitchArmed: {PhaseStateExchanged: true, PhaseFailed: true, PhaseRescueRequired: true}, PhaseStateExchanged: {PhaseContainerRecreated: true, PhaseRollbackArmed: true, PhaseRescueRequired: true}, PhaseContainerRecreated: {PhaseEgressRebound: true, PhaseRollbackArmed: true, PhaseRescueRequired: true}, PhaseEgressRebound: {PhaseContainerStarted: true, PhaseRollbackArmed: true, PhaseRescueRequired: true}, PhaseContainerStarted: {PhaseLocalHealthPassed: true, PhaseRollbackArmed: true, PhaseRescueRequired: true}, PhaseLocalHealthPassed: {PhaseIndependentProbePassed: true, PhaseRollbackArmed: true, PhaseRescueRequired: true}, PhaseIndependentProbePassed: {PhaseCommitted: true, PhaseRollbackArmed: true, PhaseRescueRequired: true}, PhaseRollbackArmed: {PhaseStateRollbackExchanged: true, PhaseRescueRequired: true}, PhaseStateRollbackExchanged: {PhaseRollbackContainerRecreated: true, PhaseRescueRequired: true}, PhaseRollbackContainerRecreated: {PhaseRollbackEgressRebound: true, PhaseRescueRequired: true}, PhaseRollbackEgressRebound: {PhaseRollbackContainerStarted: true, PhaseRescueRequired: true}, PhaseRollbackContainerStarted: {PhaseRollbackHealthPassed: true, PhaseRescueRequired: true}, PhaseRollbackHealthPassed: {PhaseRolledBack: true, PhaseRescueRequired: true}, PhaseRescueRequired: {PhaseRescueLockdown: true},
}

type Identity struct {
	CandidateID string `json:"candidateId"`
	ProjectID   string `json:"projectId"`
	BackupID    string `json:"backupId"`
}
type Digests struct {
	BackupManifestSHA256 string `json:"backupManifestSha256"`
	BindingSHA256        string `json:"bindingSha256"`
	OldStateSHA256       string `json:"oldStateSha256"`
	NewStateSHA256       string `json:"newStateSha256"`
}
type Event struct {
	Sequence       uint64    `json:"sequence"`
	At             time.Time `json:"at"`
	From           Phase     `json:"from,omitempty"`
	To             Phase     `json:"to"`
	ReasonCode     string    `json:"reasonCode"`
	BindingHash    string    `json:"bindingHash"`
	EvidenceSHA256 string    `json:"evidenceSha256,omitempty"`
	PreviousHash   string    `json:"previousHash"`
	Hash           string    `json:"hash"`
}
type Journal struct {
	Schema      string    `json:"schema"`
	OperationID string    `json:"operationId"`
	Sequence    uint64    `json:"sequence"`
	Phase       Phase     `json:"phase"`
	Identity    Identity  `json:"identity"`
	Digests     Digests   `json:"digests"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Events      []Event   `json:"events"`
}
type TransitionRequest struct {
	To             Phase
	ReasonCode     string
	EvidenceSHA256 string
	At             time.Time
	Topology       *Topology
}

func Phases() []Phase { return append([]Phase(nil), allPhases...) }
func IsTerminal(p Phase) bool {
	return p == PhaseCommitted || p == PhaseRolledBack || p == PhaseFailed || p == PhaseRescueLockdown
}
func CanTransition(from, to Phase) bool { return transitions[from][to] }
func New(operationID string, identity Identity, digests Digests, now time.Time) (Journal, error) {
	now = now.UTC()
	j := Journal{Schema: Schema, OperationID: operationID, Sequence: 1, Phase: PhaseNew, Identity: identity, Digests: digests, CreatedAt: now, UpdatedAt: now}
	binding, err := journalBindingHash(j)
	if err != nil {
		return Journal{}, err
	}
	e := Event{Sequence: 1, At: now, To: PhaseNew, ReasonCode: "CREATED", BindingHash: binding, PreviousHash: GenesisHash}
	e.Hash, err = eventHash(e)
	if err != nil {
		return Journal{}, err
	}
	j.Events = []Event{e}
	if err := j.Validate(); err != nil {
		return Journal{}, err
	}
	return j, nil
}
func (j Journal) Transition(r TransitionRequest) (Journal, error) {
	if err := j.Validate(); err != nil {
		return Journal{}, err
	}
	if IsTerminal(j.Phase) || !CanTransition(j.Phase, r.To) {
		return Journal{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, j.Phase, r.To)
	}
	if !isHash(r.EvidenceSHA256) {
		return Journal{}, fmt.Errorf("%w: exact evidence digest required", ErrInvalidJournal)
	}
	if r.To == PhaseRescueLockdown && r.ReasonCode != "LOCKDOWN_VERIFIED" {
		return Journal{}, fmt.Errorf("%w: lockdown verification evidence required", ErrInvalidTransition)
	}
	if err := validateTransitionTopology(j, r); err != nil {
		return Journal{}, err
	}
	now := r.At.UTC()
	if now.Before(j.UpdatedAt) {
		return Journal{}, ErrClockRollback
	}
	if !safeReason.MatchString(r.ReasonCode) {
		return Journal{}, fmt.Errorf("%w: invalid reason code", ErrInvalidJournal)
	}
	e := Event{Sequence: j.Sequence + 1, At: now, From: j.Phase, To: r.To, ReasonCode: r.ReasonCode, BindingHash: j.Events[0].BindingHash, EvidenceSHA256: r.EvidenceSHA256, PreviousHash: j.Events[len(j.Events)-1].Hash}
	h, err := eventHash(e)
	if err != nil {
		return Journal{}, err
	}
	e.Hash = h
	next := j
	next.Events = append(append([]Event(nil), j.Events...), e)
	next.Sequence, next.Phase, next.UpdatedAt = e.Sequence, r.To, now
	if err := next.Validate(); err != nil {
		return Journal{}, err
	}
	return next, nil
}
func validateTransitionTopology(j Journal, r TransitionRequest) error {
	require := func(live, stage string) error {
		if r.Topology == nil || !r.Topology.LivePresent || !r.Topology.StagePresent || r.Topology.LiveSHA256 != live || r.Topology.StageSHA256 != stage {
			return fmt.Errorf("%w: transition %s -> %s lacks exact topology evidence", ErrInvalidTransition, j.Phase, r.To)
		}
		return nil
	}
	switch r.To {
	case PhaseSwitchArmed:
		return require(j.Digests.OldStateSHA256, j.Digests.NewStateSHA256)
	case PhaseStateExchanged, PhaseRollbackArmed:
		return require(j.Digests.NewStateSHA256, j.Digests.OldStateSHA256)
	case PhaseStateRollbackExchanged:
		return require(j.Digests.OldStateSHA256, j.Digests.NewStateSHA256)
	case PhaseFailed:
		if j.Phase == PhaseSwitchArmed {
			return require(j.Digests.OldStateSHA256, j.Digests.NewStateSHA256)
		}
	}
	return nil
}
func (j Journal) Validate() error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: %s", ErrInvalidJournal, fmt.Sprintf(f, a...)) }
	if j.Schema != Schema {
		return bad("unsupported schema")
	}
	if !safeID.MatchString(j.OperationID) || !safeID.MatchString(j.Identity.CandidateID) || !safeID.MatchString(j.Identity.ProjectID) || !safeID.MatchString(j.Identity.BackupID) {
		return bad("invalid identity")
	}
	for _, h := range []string{j.Digests.BackupManifestSHA256, j.Digests.BindingSHA256, j.Digests.OldStateSHA256, j.Digests.NewStateSHA256} {
		if !isHash(h) {
			return bad("invalid digest")
		}
	}
	if j.Digests.OldStateSHA256 == j.Digests.NewStateSHA256 {
		return bad("old and new state digests must differ")
	}
	if len(j.Events) == 0 || j.Sequence != uint64(len(j.Events)) {
		return bad("event sequence length mismatch")
	}
	if !isUTC(j.CreatedAt) || !isUTC(j.UpdatedAt) || j.CreatedAt.After(j.UpdatedAt) {
		return bad("invalid UTC timestamps")
	}
	binding, err := journalBindingHash(j)
	if err != nil {
		return bad("cannot bind immutable fields")
	}
	previousHash := GenesisHash
	var previousTime time.Time
	var previousPhase Phase
	for i, e := range j.Events {
		want := uint64(i + 1)
		if e.Sequence != want || !isUTC(e.At) || (!previousTime.IsZero() && e.At.Before(previousTime)) {
			return bad("invalid event sequence or clock")
		}
		if !safeReason.MatchString(e.ReasonCode) || e.BindingHash != binding || e.PreviousHash != previousHash || !isHash(e.Hash) || (i > 0 && !isHash(e.EvidenceSHA256)) || (i == 0 && e.EvidenceSHA256 != "") {
			return bad("invalid event fields")
		}
		if i == 0 {
			if e.From != "" || e.To != PhaseNew || e.ReasonCode != "CREATED" || !e.At.Equal(j.CreatedAt) {
				return bad("invalid genesis event")
			}
		} else if e.From != previousPhase || !CanTransition(e.From, e.To) {
			return bad("invalid transition at sequence %d", want)
		}
		h, err := eventHash(e)
		if err != nil || h != e.Hash {
			return bad("event hash mismatch at sequence %d", want)
		}
		previousHash, previousTime, previousPhase = e.Hash, e.At, e.To
	}
	last := j.Events[len(j.Events)-1]
	if j.Phase != last.To || !j.UpdatedAt.Equal(last.At) {
		return bad("journal tail mismatch")
	}
	return nil
}
func eventHash(e Event) (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}
func journalBindingHash(j Journal) (string, error) {
	v := struct {
		Schema      string    `json:"schema"`
		OperationID string    `json:"operationId"`
		Identity    Identity  `json:"identity"`
		Digests     Digests   `json:"digests"`
		CreatedAt   time.Time `json:"createdAt"`
	}{j.Schema, j.OperationID, j.Identity, j.Digests, j.CreatedAt}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}
func isHash(s string) bool   { return hashPattern.MatchString(s) }
func isUTC(t time.Time) bool { return !t.IsZero() && t.Location() == time.UTC }
