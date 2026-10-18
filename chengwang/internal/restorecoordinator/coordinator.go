// Package restorecoordinator connects strict backup parsing, durable evidence
// publication and the restore journal for the pre-live portion of a restore.
//
// It intentionally has no Docker, shell, network or live-state mutation port.
// The package can create a journal and advance it only through INPUT_VERIFIED,
// or record a preflight failure. Reaching INPUT_VERIFIED is a hard boundary,
// not authorization to quiesce or modify a live service.
package restorecoordinator

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"chengwang/internal/proberestore"
	"chengwang/internal/restorecontracts"
	"chengwang/internal/restoreevidence"
)

var (
	ErrInvalidPreparedOperation = errors.New("invalid prepared restore operation")
	ErrOperationMismatch        = errors.New("restore operation does not match durable journal")
	ErrTransitionNotAllowed     = errors.New("restore transition is outside the pre-live coordinator boundary")
	ErrEvidenceNotDurable       = errors.New("restore evidence is not durably committed")
	ErrTrustedInputsUnavailable = errors.New("trusted restore inputs and lifecycle lease are not implemented")
	ErrResumeRequired           = errors.New("non-new durable journal requires explicit evidence reconciliation")
)

type OutcomeCode string

const (
	OutcomeCreatedNew            OutcomeCode = "CREATED_NEW"
	OutcomeAdvancedLocked        OutcomeCode = "ADVANCED_LOCKED"
	OutcomeAdvancedInputVerified OutcomeCode = "ADVANCED_INPUT_VERIFIED"
	OutcomeAlreadyApplied        OutcomeCode = "ALREADY_APPLIED"
	OutcomeBlockedBeforeLive     OutcomeCode = "BLOCKED_BEFORE_LIVE_QUIESCE"
	OutcomeTerminalFailed        OutcomeCode = "TERMINAL_FAILED"
)

type Outcome struct {
	code     OutcomeCode
	journal  proberestore.Journal
	evidence string
}

func (o Outcome) Code() OutcomeCode             { return o.code }
func (o Outcome) Journal() proberestore.Journal { return cloneJournal(o.journal) }
func (o Outcome) EvidenceSHA256() string        { return o.evidence }
func (o Outcome) Phase() proberestore.Phase     { return o.journal.Phase }
func (o Outcome) Sequence() uint64              { return o.journal.Sequence }

type PreparedOperation struct {
	journal   proberestore.Journal
	candidate restorecontracts.CandidateIdentity
	binding   restorecontracts.EvidenceBinding
}

func (p PreparedOperation) Journal() proberestore.Journal                 { return cloneJournal(p.journal) }
func (p PreparedOperation) Candidate() restorecontracts.CandidateIdentity { return p.candidate }
func (p PreparedOperation) Binding() restorecontracts.EvidenceBinding     { return p.binding }

// Prepare validates model inputs but cannot authorize a restore. The current
// implementation deliberately exposes no production Coordinator constructor:
// now, current and oldStateTreeSHA256 remain caller supplied until a concrete
// trusted clock, current-state collector and lifecycle lease are implemented.
func Prepare(operationID string, backupRaw []byte, now time.Time, current restorecontracts.StateOnlyCurrent, oldStateTreeSHA256 string) (PreparedOperation, error) {
	parsed, err := restorecontracts.ParseBackupV3(backupRaw, now)
	if err != nil {
		return PreparedOperation{}, err
	}
	if err := parsed.ValidateStateOnly(now, current); err != nil {
		return PreparedOperation{}, err
	}
	oldHex, err := digestHex(oldStateTreeSHA256)
	if err != nil {
		return PreparedOperation{}, fmt.Errorf("%w: old state digest: %v", ErrInvalidPreparedOperation, err)
	}
	doc := parsed.Snapshot()
	newHex, err := digestHex(doc.State.TreeSHA256)
	if err != nil {
		return PreparedOperation{}, fmt.Errorf("%w: new state digest: %v", ErrInvalidPreparedOperation, err)
	}
	if oldHex == newHex {
		return PreparedOperation{}, fmt.Errorf("%w: old and target state digests are equal", ErrInvalidPreparedOperation)
	}
	bindingHex, err := digestHex(doc.Configuration.ConfigurationBindingSHA256)
	if err != nil {
		return PreparedOperation{}, fmt.Errorf("%w: configuration binding: %v", ErrInvalidPreparedOperation, err)
	}
	journal, err := proberestore.New(operationID, proberestore.Identity{
		CandidateID: doc.Candidate.CandidateID,
		ProjectID:   doc.Candidate.ProjectName,
		BackupID:    doc.BackupID,
	}, proberestore.Digests{
		BackupManifestSHA256: parsed.RawSHA256(),
		BindingSHA256:        bindingHex,
		OldStateSHA256:       oldHex,
		NewStateSHA256:       newHex,
	}, time.Unix(now.UTC().Unix(), 0).UTC())
	if err != nil {
		return PreparedOperation{}, err
	}
	return PreparedOperation{
		journal:   journal,
		candidate: doc.Candidate,
		binding: restorecontracts.EvidenceBinding{
			BackupID: doc.BackupID, BackupManifestSHA256: "sha256:" + parsed.RawSHA256(),
			ConfigurationBindingSHA256: doc.Configuration.ConfigurationBindingSHA256,
			OldStateTreeSHA256:         oldStateTreeSHA256, NewStateTreeSHA256: doc.State.TreeSHA256,
		},
	}, nil
}

type journalStore interface {
	Load() (proberestore.Journal, error)
	Create(proberestore.Journal) error
	Save(proberestore.Journal) error
}

type evidenceRecord interface {
	Evidence() restorecontracts.ParsedEvidence
	RawSHA256() string
	Reliability() restoreevidence.Reliability
	CommitState() restoreevidence.CommitState
	RawBytes() []byte
}

type evidenceStore interface {
	Publish([]byte, restorecontracts.EvidenceContext) (evidenceRecord, error)
	Read(restorecontracts.EvidenceContext) (evidenceRecord, error)
}

type durableEvidenceStore struct{ store *restoreevidence.Store }

func (s durableEvidenceStore) Publish(raw []byte, context restorecontracts.EvidenceContext) (evidenceRecord, error) {
	return s.store.Publish(raw, context)
}

func (s durableEvidenceStore) Read(context restorecontracts.EvidenceContext) (evidenceRecord, error) {
	return s.store.Read(context)
}

type Coordinator struct {
	journal  journalStore
	evidence evidenceStore
}

func newWithStores(journal journalStore, evidence evidenceStore) (*Coordinator, error) {
	if journal == nil || evidence == nil {
		return nil, errors.New("journal and evidence stores are required")
	}
	return &Coordinator{journal: journal, evidence: evidence}, nil
}

func (c *Coordinator) Create(prepared PreparedOperation) (Outcome, error) {
	if err := c.ready(); err != nil {
		return Outcome{}, err
	}
	if err := validatePrepared(prepared); err != nil {
		return Outcome{}, err
	}
	current, err := c.journal.Load()
	if err == nil {
		if sameOperation(current, prepared) {
			if current.Phase != proberestore.PhaseNew || current.Sequence != 1 {
				return Outcome{}, ErrResumeRequired
			}
			return outcome(OutcomeAlreadyApplied, current, ""), nil
		}
		return Outcome{}, ErrOperationMismatch
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Outcome{}, err
	}
	if err := c.journal.Create(prepared.Journal()); err != nil {
		return Outcome{}, err
	}
	created, err := c.journal.Load()
	if err != nil {
		return Outcome{}, err
	}
	if !sameOperation(created, prepared) || created.Phase != proberestore.PhaseNew {
		return Outcome{}, ErrOperationMismatch
	}
	return outcome(OutcomeCreatedNew, created, ""), nil
}

type TransitionInput struct {
	Kind          string
	RawEvidence   []byte
	BootID        string
	SubjectSHA256 string
	Collector     restorecontracts.Collector
	Topology      restorecontracts.Topology
}

func (c *Coordinator) Advance(prepared PreparedOperation, input TransitionInput) (Outcome, error) {
	if err := c.ready(); err != nil {
		return Outcome{}, err
	}
	if err := validatePrepared(prepared); err != nil {
		return Outcome{}, err
	}
	current, err := c.journal.Load()
	if err != nil {
		return Outcome{}, err
	}
	if !sameOperation(current, prepared) {
		return Outcome{}, ErrOperationMismatch
	}
	from, to, kind, reason, code, err := requestedTransition(current.Phase, input.Kind)
	if err != nil {
		return Outcome{}, err
	}
	rawDigest := sha256Hex(input.RawEvidence)

	// A response may have been lost after the journal save. Revalidate the
	// exact durable evidence before acknowledging the already-applied event.
	if current.Phase == to && len(current.Events) > 1 {
		prior := current.Events[len(current.Events)-1]
		expectedFrom := from
		if to == proberestore.PhaseFailed && kind == "FAILURE_RECORDED" {
			if !preLiveFailureSource(prior.From) {
				return Outcome{}, ErrOperationMismatch
			}
			expectedFrom = prior.From
		}
		if prior.From != expectedFrom || prior.To != to || prior.Sequence != current.Sequence || prior.ReasonCode != reason || prior.EvidenceSHA256 != rawDigest {
			return Outcome{}, ErrOperationMismatch
		}
		context := evidenceContext(prepared, input, current, expectedFrom, prior.To, prior.Sequence, kind, reason, prior.PreviousHash, rawDigest)
		verified, readErr := c.evidence.Read(context)
		if readErr != nil || !durableExact(verified, input.RawEvidence, rawDigest) {
			return Outcome{}, errors.Join(ErrEvidenceNotDurable, readErr)
		}
		return outcome(OutcomeAlreadyApplied, current, rawDigest), nil
	}
	if current.Phase == proberestore.PhaseInputVerified && kind != "FAILURE_RECORDED" {
		return outcome(OutcomeBlockedBeforeLive, current, ""), nil
	}
	if current.Phase != from {
		return Outcome{}, ErrTransitionNotAllowed
	}

	sequence := current.Sequence + 1
	previousHead := current.Events[len(current.Events)-1].Hash
	context := evidenceContext(prepared, input, current, current.Phase, to, sequence, kind, reason, previousHead, rawDigest)
	published, publishErr := c.evidence.Publish(input.RawEvidence, context)
	if publishErr != nil {
		return Outcome{}, errors.Join(ErrEvidenceNotDurable, publishErr)
	}
	if !durableExact(published, input.RawEvidence, rawDigest) {
		return Outcome{}, ErrEvidenceNotDurable
	}
	verified, err := c.evidence.Read(context)
	if err != nil || !durableExact(verified, input.RawEvidence, rawDigest) {
		return Outcome{}, errors.Join(ErrEvidenceNotDurable, err)
	}
	snapshot := verified.Evidence().Snapshot()
	next, err := current.Transition(proberestore.TransitionRequest{
		To: to, ReasonCode: reason, EvidenceSHA256: rawDigest,
		At: time.Unix(snapshot.CapturedUnix, 0).UTC(),
	})
	if err != nil {
		return Outcome{}, err
	}
	if err := c.journal.Save(next); err != nil {
		return Outcome{}, err
	}
	stored, err := c.journal.Load()
	if err != nil {
		return Outcome{}, err
	}
	if stored.Sequence != next.Sequence || stored.Phase != next.Phase || stored.Events[len(stored.Events)-1].Hash != next.Events[len(next.Events)-1].Hash {
		return Outcome{}, ErrOperationMismatch
	}
	return outcome(code, stored, rawDigest), nil
}

func preLiveFailureSource(phase proberestore.Phase) bool {
	return phase == proberestore.PhaseNew || phase == proberestore.PhaseLocked || phase == proberestore.PhaseInputVerified
}

func requestedTransition(current proberestore.Phase, requestedKind string) (proberestore.Phase, proberestore.Phase, string, string, OutcomeCode, error) {
	if requestedKind == "FAILURE_RECORDED" {
		switch current {
		case proberestore.PhaseNew, proberestore.PhaseLocked, proberestore.PhaseInputVerified:
			return current, proberestore.PhaseFailed, "FAILURE_RECORDED", "PREFLIGHT_ABORTED", OutcomeTerminalFailed, nil
		case proberestore.PhaseFailed:
			return "", proberestore.PhaseFailed, "FAILURE_RECORDED", "PREFLIGHT_ABORTED", OutcomeTerminalFailed, nil
		default:
			return "", "", "", "", "", ErrTransitionNotAllowed
		}
	}
	switch requestedKind {
	case "LOCK_ACQUIRED":
		if current != proberestore.PhaseNew && current != proberestore.PhaseLocked {
			return "", "", "", "", "", ErrTransitionNotAllowed
		}
		return proberestore.PhaseNew, proberestore.PhaseLocked, "LOCK_ACQUIRED", "LOCK_ACQUIRED", OutcomeAdvancedLocked, nil
	case "INPUT_BOUND":
		if current != proberestore.PhaseLocked && current != proberestore.PhaseInputVerified {
			return "", "", "", "", "", ErrTransitionNotAllowed
		}
		return proberestore.PhaseLocked, proberestore.PhaseInputVerified, "INPUT_BOUND", "INPUT_BOUND", OutcomeAdvancedInputVerified, nil
	case "LIVE_QUIESCED", "":
		if current == proberestore.PhaseInputVerified {
			return proberestore.PhaseInputVerified, proberestore.PhaseLiveQuiesced, "LIVE_QUIESCED", "LIVE_QUIESCED", OutcomeBlockedBeforeLive, nil
		}
		return "", "", "", "", "", ErrTransitionNotAllowed
	default:
		return "", "", "", "", "", ErrTransitionNotAllowed
	}
}

func evidenceContext(prepared PreparedOperation, input TransitionInput, journal proberestore.Journal, from, to proberestore.Phase, sequence uint64, kind, reason, previousHead, rawDigest string) restorecontracts.EvidenceContext {
	return restorecontracts.EvidenceContext{
		OperationID: journal.OperationID, TransitionSequence: sequence, FromPhase: string(from), Kind: kind,
		ReasonCode: reason, TargetPhase: string(to), PreviousJournalHeadSHA256: previousHead,
		BootID: input.BootID, Candidate: prepared.candidate, Binding: prepared.binding,
		SubjectSHA256: input.SubjectSHA256, Collector: input.Collector, Topology: input.Topology,
		RawBytesSHA256: rawDigest,
	}
}

func validatePrepared(prepared PreparedOperation) error {
	if err := prepared.journal.Validate(); err != nil || prepared.journal.Sequence != 1 || prepared.journal.Phase != proberestore.PhaseNew {
		return errors.Join(ErrInvalidPreparedOperation, err)
	}
	if prepared.candidate.CandidateID != prepared.journal.Identity.CandidateID || prepared.candidate.ProjectName != prepared.journal.Identity.ProjectID || prepared.binding.BackupID != prepared.journal.Identity.BackupID {
		return ErrInvalidPreparedOperation
	}
	backup, err := digestHex(prepared.binding.BackupManifestSHA256)
	if err != nil || backup != prepared.journal.Digests.BackupManifestSHA256 {
		return ErrInvalidPreparedOperation
	}
	configuration, err := digestHex(prepared.binding.ConfigurationBindingSHA256)
	if err != nil || configuration != prepared.journal.Digests.BindingSHA256 {
		return ErrInvalidPreparedOperation
	}
	oldState, oldErr := digestHex(prepared.binding.OldStateTreeSHA256)
	newState, newErr := digestHex(prepared.binding.NewStateTreeSHA256)
	if oldErr != nil || newErr != nil || oldState != prepared.journal.Digests.OldStateSHA256 || newState != prepared.journal.Digests.NewStateSHA256 {
		return ErrInvalidPreparedOperation
	}
	return nil
}

func sameOperation(j proberestore.Journal, prepared PreparedOperation) bool {
	return j.OperationID == prepared.journal.OperationID && j.Identity == prepared.journal.Identity && j.Digests == prepared.journal.Digests
}

func (c *Coordinator) ready() error {
	if c == nil || c.journal == nil || c.evidence == nil {
		return ErrTrustedInputsUnavailable
	}
	return nil
}

func durableExact(result evidenceRecord, raw []byte, digest string) bool {
	if result == nil {
		return false
	}
	return result.CommitState() == restoreevidence.Committed && result.Reliability() == restoreevidence.ReliabilityLinuxDurable && result.RawSHA256() == digest && bytes.Equal(result.RawBytes(), raw)
}

func digestHex(value string) (string, error) {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return "", errors.New("digest must use sha256:<64 lowercase hex> format")
	}
	hexValue := strings.TrimPrefix(value, "sha256:")
	decoded, err := hex.DecodeString(hexValue)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != hexValue {
		return "", errors.New("digest must use sha256:<64 lowercase hex> format")
	}
	return hexValue, nil
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func outcome(code OutcomeCode, journal proberestore.Journal, evidence string) Outcome {
	return Outcome{code: code, journal: cloneJournal(journal), evidence: evidence}
}

func cloneJournal(j proberestore.Journal) proberestore.Journal {
	copy := j
	copy.Events = append([]proberestore.Event(nil), j.Events...)
	return copy
}
