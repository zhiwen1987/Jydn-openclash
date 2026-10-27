package subscription

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MinRefreshInterval         = 60 * time.Second
	MaxRefreshInterval         = 7 * 24 * time.Hour
	MaxApprovalTTL             = 30 * 24 * time.Hour
	MaxRefreshClockStep        = 24 * time.Hour
	refreshSchema              = "chengwang.subscription-refresh/v3"
	refreshLegacySchema        = "chengwang.subscription-refresh/v2"
	MaxRefreshReservationBytes = 4*MaxInputBytes + 512*1024
)

// ErrRefreshCommitNotCommitted is returned only when the sidecar writer knows
// its atomic rename did not happen. It authorizes an exact local-stage retry,
// never replay of a network request or domain-store mutation.
var ErrRefreshCommitNotCommitted = errors.New("subscription_refresh_commit_not_committed")

func IsCommitNotCommitted(err error) bool { return errors.Is(err, ErrRefreshCommitNotCommitted) }

type RefreshState string

const (
	RefreshIdle                 RefreshState = "idle"
	RefreshRunning              RefreshState = "running"
	RefreshSucceededNoop        RefreshState = "succeeded_noop"
	RefreshCandidateQuarantined RefreshState = "candidate_quarantined"
	RefreshFailed               RefreshState = "failed"
	RefreshBlocked              RefreshState = "blocked"
	RefreshUnknown              RefreshState = "unknown"
)

type RefreshFailure string

const (
	RefreshFailureNone        RefreshFailure = ""
	RefreshFailureApproval    RefreshFailure = "approval"
	RefreshFailurePolicy      RefreshFailure = "policy"
	RefreshFailureTransport   RefreshFailure = "transport"
	RefreshFailureHTTP        RefreshFailure = "http"
	RefreshFailureRate        RefreshFailure = "rate_limited"
	RefreshFailureInput       RefreshFailure = "input"
	RefreshFailureLimit       RefreshFailure = "store_limit"
	RefreshFailureConflict    RefreshFailure = "conflict"
	RefreshFailureAudit       RefreshFailure = "audit"
	RefreshFailureUnknown     RefreshFailure = "commit_unknown"
	RefreshFailureCanceled    RefreshFailure = "canceled"
	RefreshFailureForbidden   RefreshFailure = "forbidden"
	RefreshFailureUnavailable RefreshFailure = "unavailable"
	RefreshFailureClock       RefreshFailure = "clock_frozen"
	RefreshFailureSequence    RefreshFailure = "sequence_exhausted"
)

type RefreshClockState string

const (
	RefreshClockNormal RefreshClockState = "normal"
	RefreshClockFrozen RefreshClockState = "frozen"
)

type RefreshBinding struct {
	SourceID               string `json:"sourceId"`
	ReferenceID            string `json:"referenceId"`
	PolicyRevision         uint64 `json:"policyRevision"`
	ApprovalID             string `json:"approvalId"`
	ApprovalSourceRevision uint64 `json:"approvalSourceRevision"`
	IntervalSeconds        uint64 `json:"intervalSeconds"`
	ApprovalTTLSeconds     uint64 `json:"approvalTtlSeconds"`
	MaxStaleSeconds        uint64 `json:"maxStaleSeconds"`
	MaxBackoffSeconds      uint64 `json:"maxBackoffSeconds"`
}

type RefreshView struct {
	Scope               Scope                `json:"scope"`
	Binding             RefreshBinding       `json:"binding"`
	BindingSeal         string               `json:"bindingSeal"`
	BindingGeneration   uint64               `json:"bindingGeneration"`
	State               RefreshState         `json:"state"`
	Failure             RefreshFailure       `json:"failure,omitempty"`
	AttemptCount        uint64               `json:"attemptCount"`
	AttemptSequence     uint64               `json:"attemptSequence,omitempty"`
	ConsecutiveFailures uint32               `json:"consecutiveFailures"`
	AttemptKey          string               `json:"attemptKey,omitempty"`
	Fence               string               `json:"fence,omitempty"`
	CommandID           string               `json:"commandId,omitempty"`
	CommandOwnerID      string               `json:"commandOwnerId,omitempty"`
	CommandEpoch        string               `json:"commandEpoch,omitempty"`
	CandidateID         string               `json:"candidateId,omitempty"`
	CandidateDigest     string               `json:"candidateDigest,omitempty"`
	ResultRevision      uint64               `json:"resultRevision,omitempty"`
	StartedAt           time.Time            `json:"startedAt,omitempty"`
	CompletedAt         time.Time            `json:"completedAt,omitempty"`
	LastSuccessAt       time.Time            `json:"lastSuccessAt,omitempty"`
	FreshUntil          time.Time            `json:"freshUntil,omitempty"`
	NextAttemptAt       time.Time            `json:"nextAttemptAt,omitempty"`
	Stale               bool                 `json:"stale"`
	ClockState          RefreshClockState    `json:"clockState"`
	ClockReason         string               `json:"clockReason,omitempty"`
	AuditRecorded       bool                 `json:"auditRecorded"`
	StateMayHaveChanged bool                 `json:"stateMayHaveChanged"`
	Reservation         *RefreshReservation  `json:"reservation,omitempty"`
	StoragePending      bool                 `json:"storagePending,omitempty"`
	StorageRetryCount   uint32               `json:"storageRetryCount,omitempty"`
	StorageNextRetryAt  time.Time            `json:"storageNextRetryAt,omitempty"`
	Lease               *RefreshAttemptLease `json:"-"`
}

// RefreshAttemptLease is an opaque, process-local capability issued only by a
// successful claim. JSON cannot manufacture or restore its private authority.
type RefreshAttemptLease struct {
	mu                               sync.Mutex
	store                            *RefreshStore
	scope                            Scope
	source, attemptKey, fence, epoch string
	sequence                         uint64
	bound, completed                 bool
}

func (*RefreshAttemptLease) String() string   { return "subscription refresh attempt capability" }
func (*RefreshAttemptLease) GoString() string { return "subscription refresh attempt capability" }
func (*RefreshAttemptLease) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"MEMORY_REFRESH_ATTEMPT_CAPABILITY_NOT_AUTHORIZATION"}`), nil
}
func (v *RefreshAttemptLease) UnmarshalJSON([]byte) error {
	if v != nil {
		*v = RefreshAttemptLease{}
	}
	return fail(CodeInputInvalid)
}

type RefreshReservation struct {
	AttemptSequence  uint64 `json:"attemptSequence"`
	AttemptKey       string `json:"attemptKey"`
	Fence            string `json:"fence"`
	CommandSlots     int    `json:"commandSlots"`
	CandidateSlots   int    `json:"candidateSlots"`
	DomainAuditSlots int    `json:"domainAuditSlots"`
	Bytes            int    `json:"bytes"`
}

type RefreshCompletion struct {
	AttemptKey          string
	AttemptSequence     uint64
	BindingSeal         string
	Fence               string
	State               RefreshState
	Failure             RefreshFailure
	CommandID           string
	CandidateID         string
	CandidateDigest     string
	ResultRevision      uint64
	AuditRecorded       bool
	StateMayHaveChanged bool
	Lease               *RefreshAttemptLease
}

type refreshSnapshot struct {
	Schema               string            `json:"schema"`
	IdentityKey          []byte            `json:"identityKey"`
	Epoch                string            `json:"epoch"`
	CheckpointID         string            `json:"checkpointId,omitempty"`
	PreviousCheckpointID string            `json:"previousCheckpointId,omitempty"`
	CheckpointReady      bool              `json:"checkpointReady"`
	LastSequence         uint64            `json:"lastSequence"`
	LastWallClock        time.Time         `json:"lastWallClock,omitempty"`
	ClockState           RefreshClockState `json:"clockState"`
	ClockReason          string            `json:"clockReason,omitempty"`
	Ledgers              []RefreshLedger   `json:"ledgers"`
	Refreshes            []RefreshView     `json:"refreshes"`
}

type RefreshLedger struct {
	Scope              Scope  `json:"scope"`
	SourceID           string `json:"sourceId"`
	Generation         uint64 `json:"generation"`
	LastIssuedSequence uint64 `json:"lastIssuedSequence"`
}

func cloneRefreshView(in RefreshView) RefreshView {
	out := in
	out.Lease = nil
	out.StoragePending = false
	out.StorageRetryCount = 0
	out.StorageNextRetryAt = time.Time{}
	if in.Reservation != nil {
		reservation := *in.Reservation
		out.Reservation = &reservation
	}
	return out
}

func cloneRefreshSnapshot(in refreshSnapshot) refreshSnapshot {
	out := in
	out.IdentityKey = append([]byte(nil), in.IdentityKey...)
	if in.Ledgers != nil {
		out.Ledgers = make([]RefreshLedger, len(in.Ledgers))
		copy(out.Ledgers, in.Ledgers)
	}
	if in.Refreshes != nil {
		out.Refreshes = make([]RefreshView, len(in.Refreshes))
		for i := range in.Refreshes {
			out.Refreshes[i] = cloneRefreshView(in.Refreshes[i])
		}
	}
	return out
}

func detachRefreshView(in RefreshView) RefreshView { return cloneRefreshView(in) }

// RefreshStore is a separately versioned durable scheduler sidecar. The main
// subscription-store/v1 remains byte-compatible with deployments that do not
// enable this feature. A process holds the same secure directory lock for the
// lifetime of this store.
type RefreshStore struct {
	mu               sync.Mutex
	disk             storeDiskIO
	state            refreshSnapshot
	recoverySeed     map[string]bool
	recoveryIssued   bool
	closed, poisoned bool
	now              func() time.Time
}

// RefreshRecovery is an opaque, source-issued, process-local capability. It
// cannot be constructed from JSON and may consume each persisted running
// attempt at most once.
type RefreshRecovery struct {
	mu        sync.Mutex
	store     *RefreshStore
	remaining map[string]bool
	closed    bool
}

func refreshDecode(raw []byte, out *refreshSnapshot) error {
	if len(raw) == 0 || len(raw) > MaxStoreBytes {
		return fail(CodeStoreUnsafe)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return fail(CodeStoreUnsafe)
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return fail(CodeStoreUnsafe)
	}
	canonical, err := json.Marshal(out)
	if err != nil {
		return fail(CodeStoreUnsafe)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(raw, canonical) {
		return fail(CodeStoreUnsafe)
	}
	return nil
}
func refreshEncode(in refreshSnapshot) ([]byte, error) {
	if err := validateRefreshSnapshot(in); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, fail(CodeStoreUnsafe)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxStoreBytes {
		return nil, fail(CodeStoreLimit)
	}
	return raw, nil
}

func OpenRefreshStore(dir string) (*RefreshStore, error) {
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
	s := &RefreshStore{disk: disk, now: func() time.Time { return time.Now().UTC() }}
	if exists {
		if err := refreshDecode(raw, &s.state); err != nil {
			return nil, err
		}
		if s.state.Schema == refreshLegacySchema {
			return nil, fail(CodeStoreUnsafe)
		}
		if err := validateRefreshSnapshot(s.state); err != nil {
			return nil, err
		}
	} else {
		s.state = refreshSnapshot{Schema: refreshSchema, IdentityKey: make([]byte, 32), ClockState: RefreshClockNormal, Ledgers: []RefreshLedger{}, Refreshes: []RefreshView{}}
		if _, err := rand.Read(s.state.IdentityKey); err != nil {
			return nil, fail(CodeStoreUnsafe)
		}
		s.state.Epoch = keyedDigest(s.state.IdentityKey, []byte("refresh-store-epoch-v3"))
		raw, err = refreshEncode(s.state)
		if err != nil {
			return nil, err
		}
		if uncertain, err := disk.write(raw); err != nil {
			if uncertain {
				return nil, fail(CodeCommitUncertain)
			}
			return nil, err
		}
	}
	s.recoverySeed = map[string]bool{}
	for _, v := range s.state.Refreshes {
		if v.State == RefreshRunning {
			s.recoverySeed[v.Binding.SourceID] = true
		}
	}
	keep = true
	return s, nil
}

func (s *RefreshStore) TakeRecovery() (*RefreshRecovery, error) {
	if s == nil {
		return nil, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return nil, err
	}
	if s.recoveryIssued {
		return nil, fail(CodeConflict)
	}
	remaining := map[string]bool{}
	for id, allowed := range s.recoverySeed {
		if allowed {
			remaining[id] = true
		}
	}
	s.recoveryIssued = true
	s.recoverySeed = nil
	return &RefreshRecovery{store: s, remaining: remaining}, nil
}

func (s *RefreshStore) Checkpoint() (string, string, string, bool, error) {
	if s == nil {
		return "", "", "", false, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return "", "", "", false, err
	}
	return s.state.Epoch, s.state.CheckpointID, s.state.PreviousCheckpointID, s.state.CheckpointReady, nil
}

func (s *RefreshStore) FinalizeCheckpoint(epoch, commandID string) error {
	if s == nil {
		return fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	if epoch != s.state.Epoch || !controlIDPattern.MatchString(commandID) {
		return fail(CodeConflict)
	}
	if s.state.CheckpointReady {
		if s.state.CheckpointID == commandID {
			return nil
		}
		return fail(CodeConflict)
	}
	n := cloneRefreshSnapshot(s.state)
	n.CheckpointID = commandID
	n.PreviousCheckpointID = ""
	n.CheckpointReady = true
	return s.persist(n)
}

// RotateCheckpoint is gated by the one-shot capability issued by
// OpenRefreshStore. It is for an explicit paired-store restore workflow, not
// normal startup, and revokes old in-flight attempts before issuing an epoch.
func (s *RefreshStore) RotateCheckpoint(recovery *RefreshRecovery, now time.Time) error {
	if s == nil || recovery == nil || now.IsZero() {
		return fail(CodeInputInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recovery.mu.Lock()
	defer recovery.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	if recovery.closed || recovery.store != s {
		return fail(CodeConflict)
	}
	n := cloneRefreshSnapshot(s.state)
	for i := range n.Refreshes {
		if n.Refreshes[i].State == RefreshRunning {
			n.Refreshes[i].State = RefreshUnknown
			n.Refreshes[i].Failure = RefreshFailureUnknown
			n.Refreshes[i].CompletedAt = now.UTC()
			n.Refreshes[i].NextAttemptAt = time.Time{}
			n.Refreshes[i].StateMayHaveChanged = true
		}
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return fail(CodeStoreUnsafe)
	}
	n.PreviousCheckpointID = n.CheckpointID
	n.Epoch = keyedDigest(n.IdentityKey, []byte("refresh-restore-epoch-v3"), seed)
	n.CheckpointID = ""
	n.CheckpointReady = false
	if err := s.persist(n); err != nil {
		return err
	}
	recovery.closed = true
	recovery.remaining = nil
	recovery.store = nil
	return nil
}

func (r *RefreshRecovery) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.remaining = nil
	r.store = nil
}

func (s *RefreshStore) Close() error {
	if s == nil {
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
func (s *RefreshStore) usable() error {
	if s == nil || s.disk == nil || s.closed {
		return fail(CodeStoreClosed)
	}
	if s.poisoned {
		return fail(CodeCommitUncertain)
	}
	return s.disk.verify()
}
func (s *RefreshStore) persist(next refreshSnapshot) error {
	owned := cloneRefreshSnapshot(next)
	raw, err := refreshEncode(owned)
	if err != nil {
		return err
	}
	uncertain, err := s.disk.write(raw)
	if err != nil {
		if uncertain {
			s.poisoned = true
			return fail(CodeCommitUncertain)
		}
		return ErrRefreshCommitNotCommitted
	}
	s.state = owned
	return nil
}

func validRefreshBinding(v RefreshBinding) bool {
	return validSource(v.SourceID) && controlReferencePattern.MatchString(v.ReferenceID) && v.PolicyRevision > 0 && controlIDPattern.MatchString(v.ApprovalID) && v.ApprovalSourceRevision > 0 && v.IntervalSeconds >= uint64(MinRefreshInterval/time.Second) && v.IntervalSeconds <= uint64(MaxRefreshInterval/time.Second) && v.ApprovalTTLSeconds >= uint64(MinRefreshInterval/time.Second) && v.ApprovalTTLSeconds <= uint64(MaxApprovalTTL/time.Second) && v.MaxStaleSeconds >= v.IntervalSeconds && v.MaxStaleSeconds <= uint64(MaxApprovalTTL/time.Second) && v.MaxBackoffSeconds >= v.IntervalSeconds && v.MaxBackoffSeconds <= uint64(MaxRefreshInterval/time.Second)
}
func refreshStateKnown(v RefreshState) bool {
	switch v {
	case RefreshIdle, RefreshRunning, RefreshSucceededNoop, RefreshCandidateQuarantined, RefreshFailed, RefreshBlocked, RefreshUnknown:
		return true
	}
	return false
}
func refreshFailureKnown(v RefreshFailure) bool {
	switch v {
	case RefreshFailureNone, RefreshFailureApproval, RefreshFailurePolicy, RefreshFailureTransport, RefreshFailureHTTP, RefreshFailureRate, RefreshFailureInput, RefreshFailureLimit, RefreshFailureConflict, RefreshFailureAudit, RefreshFailureUnknown, RefreshFailureCanceled, RefreshFailureForbidden, RefreshFailureUnavailable, RefreshFailureClock, RefreshFailureSequence:
		return true
	}
	return false
}
func bindingSeal(key []byte, scope Scope, v RefreshBinding) string {
	raw, _ := json.Marshal(v)
	return "hmac-sha256:" + keyedDigest(key, []byte("refresh-binding-v2"), []byte(scopeKey(scope)), raw)
}
func refreshIndex(values []RefreshView, scope Scope, source string) (int, error) {
	if !validScope(scope) || !validSource(source) {
		return -1, fail(CodeInputInvalid)
	}
	for i, v := range values {
		if v.Binding.SourceID == source {
			if v.Scope != scope {
				return -1, fail(CodeScopeDenied)
			}
			return i, nil
		}
	}
	return -1, fail(CodeNotFound)
}

func refreshSuccessWindow(v RefreshView) bool {
	if v.LastSuccessAt.IsZero() {
		return v.FreshUntil.IsZero()
	}
	return v.FreshUntil.Equal(v.LastSuccessAt.Add(time.Duration(v.Binding.MaxStaleSeconds) * time.Second))
}
func refreshReservationShape(r *RefreshReservation) bool {
	if r == nil {
		return false
	}
	if r.CommandSlots == 0 && r.CandidateSlots == 0 && r.DomainAuditSlots == 0 && r.Bytes == 0 {
		return true
	}
	if r.Bytes < MaxRefreshReservationBytes {
		return false
	}
	return r.CommandSlots == 1 && r.CandidateSlots == 1 && r.DomainAuditSlots == 1 || r.CommandSlots == 0 && r.CandidateSlots == 1 && r.DomainAuditSlots == 1
}
func refreshBlockedFailure(v RefreshFailure) bool {
	switch v {
	case RefreshFailureApproval, RefreshFailurePolicy, RefreshFailureInput, RefreshFailureLimit, RefreshFailureConflict, RefreshFailureAudit, RefreshFailureForbidden:
		return true
	}
	return false
}
func refreshProducerState(v RefreshView) bool {
	if !refreshSuccessWindow(v) || (v.CandidateID != "") != (v.CandidateDigest != "") {
		return false
	}
	switch v.State {
	case RefreshIdle:
		return v.Failure == RefreshFailureNone && v.AttemptCount == 0 && v.AttemptSequence == 0 && v.ConsecutiveFailures == 0 && v.AttemptKey == "" && v.Fence == "" && v.CommandID == "" && v.CommandOwnerID == "" && v.CommandEpoch == "" && v.CandidateID == "" && v.ResultRevision == 0 && v.StartedAt.IsZero() && v.CompletedAt.IsZero() && v.LastSuccessAt.IsZero() && !v.NextAttemptAt.IsZero() && !v.AuditRecorded && !v.StateMayHaveChanged && v.Reservation == nil
	case RefreshRunning:
		return v.Failure == RefreshFailureNone && v.AttemptCount > 0 && v.AttemptSequence > 0 && v.CompletedAt.IsZero() && v.NextAttemptAt.IsZero() && v.CandidateID == "" && v.ResultRevision == 0 && !v.AuditRecorded && !v.StateMayHaveChanged && refreshReservationShape(v.Reservation)
	case RefreshSucceededNoop:
		return v.Failure == RefreshFailureNone && v.AttemptCount > 0 && v.AttemptSequence > 0 && v.ConsecutiveFailures == 0 && v.CommandID != "" && v.CandidateID != "" && v.ResultRevision > 0 && !v.CompletedAt.IsZero() && v.LastSuccessAt.Equal(v.CompletedAt) && v.NextAttemptAt.Equal(v.CompletedAt.Add(time.Duration(v.Binding.IntervalSeconds)*time.Second)) && v.AuditRecorded && !v.StateMayHaveChanged && v.Reservation == nil
	case RefreshCandidateQuarantined:
		return v.Failure == RefreshFailureNone && v.AttemptCount > 0 && v.AttemptSequence > 0 && v.ConsecutiveFailures == 0 && v.CommandID != "" && v.CandidateID != "" && v.ResultRevision > 0 && !v.CompletedAt.IsZero() && v.LastSuccessAt.Equal(v.CompletedAt) && v.NextAttemptAt.IsZero() && v.AuditRecorded && !v.StateMayHaveChanged && v.Reservation == nil
	case RefreshFailed:
		return refreshRetriable(v.Failure) && v.AttemptCount > 0 && v.AttemptSequence > 0 && v.ConsecutiveFailures > 0 && !v.CompletedAt.IsZero() && v.NextAttemptAt.Equal(v.CompletedAt.Add(refreshBackoff(v.Binding, v.ConsecutiveFailures))) && v.CandidateID == "" && !v.StateMayHaveChanged && v.Reservation == nil
	case RefreshBlocked:
		if v.Failure == RefreshFailureSequence {
			return v.AttemptCount == 0 && v.AttemptSequence == 0 && v.ConsecutiveFailures == 0 && v.AttemptKey == "" && v.Fence == "" && v.CommandID == "" && v.CommandOwnerID == "" && v.CommandEpoch == "" && v.CandidateID == "" && v.ResultRevision == 0 && v.StartedAt.IsZero() && v.CompletedAt.IsZero() && v.LastSuccessAt.IsZero() && v.NextAttemptAt.IsZero() && !v.AuditRecorded && !v.StateMayHaveChanged && v.Reservation == nil
		}
		return refreshBlockedFailure(v.Failure) && v.AttemptCount > 0 && v.AttemptSequence > 0 && !v.CompletedAt.IsZero() && v.NextAttemptAt.IsZero() && v.CandidateID == "" && !v.StateMayHaveChanged && v.Reservation == nil
	case RefreshUnknown:
		return v.Failure == RefreshFailureUnknown && v.AttemptCount > 0 && v.AttemptSequence > 0 && !v.CompletedAt.IsZero() && v.NextAttemptAt.IsZero() && v.StateMayHaveChanged && refreshReservationShape(v.Reservation)
	}
	return false
}

func validateRefreshSnapshot(st refreshSnapshot) error {
	bad := func() error { return fail(CodeStoreUnsafe) }
	if st.Schema != refreshSchema || len(st.IdentityKey) != 32 || !storeHexPattern.MatchString(st.Epoch) || st.Ledgers == nil || len(st.Ledgers) > MaxSources || st.Refreshes == nil || len(st.Refreshes) > MaxSources || (st.ClockState != RefreshClockNormal && st.ClockState != RefreshClockFrozen) {
		return bad()
	}
	if st.CheckpointReady != (st.CheckpointID != "") || st.CheckpointID != "" && !controlIDPattern.MatchString(st.CheckpointID) {
		return bad()
	}
	if st.CheckpointReady && st.PreviousCheckpointID != "" || st.PreviousCheckpointID != "" && !controlIDPattern.MatchString(st.PreviousCheckpointID) {
		return bad()
	}
	if st.ClockState == RefreshClockNormal && st.ClockReason != "" || st.ClockState == RefreshClockFrozen && st.ClockReason == "" {
		return bad()
	}
	seen := map[string]bool{}
	ledgers := map[string]RefreshLedger{}
	running, reservedCommands, reservedCandidates, reservedAudit, reservedBytes := 0, 0, 0, 0, 0
	for _, l := range st.Ledgers {
		if !validScope(l.Scope) || !validSource(l.SourceID) || l.Generation == 0 || l.LastIssuedSequence > st.LastSequence || ledgers[l.SourceID].SourceID != "" {
			return bad()
		}
		ledgers[l.SourceID] = l
	}
	for _, v := range st.Refreshes {
		ledger, ok := ledgers[v.Binding.SourceID]
		if !validScope(v.Scope) || !validRefreshBinding(v.Binding) || seen[v.Binding.SourceID] || v.BindingSeal != bindingSeal(st.IdentityKey, v.Scope, v.Binding) || !ok || ledger.Scope != v.Scope || ledger.Generation != v.BindingGeneration || !refreshStateKnown(v.State) || !refreshFailureKnown(v.Failure) || v.ClockState != st.ClockState || v.ClockReason != st.ClockReason {
			return bad()
		}
		seen[v.Binding.SourceID] = true
		if v.StoragePending || v.StorageRetryCount != 0 || !v.StorageNextRetryAt.IsZero() {
			return bad()
		}
		if v.AttemptSequence > st.LastSequence || v.AttemptSequence > 0 && v.AttemptSequence != ledger.LastIssuedSequence || v.AttemptSequence == 0 && (v.AttemptKey != "" || v.Fence != "" || !v.StartedAt.IsZero()) {
			return bad()
		}
		if v.AttemptSequence > 0 && (!validIdempotency(v.AttemptKey) || !storeHexPattern.MatchString(v.Fence) || v.StartedAt.IsZero()) {
			return bad()
		}
		if v.State == RefreshRunning && (!v.CompletedAt.IsZero() || !v.NextAttemptAt.IsZero() || v.Failure != "") {
			return bad()
		}
		if v.State != RefreshRunning && v.AttemptSequence > 0 && (v.CompletedAt.IsZero() || v.CompletedAt.Before(v.StartedAt)) {
			return bad()
		}
		if v.StateMayHaveChanged != (v.State == RefreshUnknown) {
			return bad()
		}
		if v.CommandID != "" && !controlIDPattern.MatchString(v.CommandID) || v.CandidateID != "" && !storeCandidatePattern.MatchString(v.CandidateID) || v.CandidateDigest != "" && !storeDigestPattern.MatchString(v.CandidateDigest) {
			return bad()
		}
		if (v.CommandID != "") != (v.CommandOwnerID != "" && v.CommandEpoch != "") || v.CommandOwnerID != "" && (!parserText(v.CommandOwnerID, false) || strings.TrimSpace(v.CommandOwnerID) != v.CommandOwnerID) || v.CommandEpoch != "" && !storeHexPattern.MatchString(v.CommandEpoch) {
			return bad()
		}
		if v.State == RefreshUnknown && (v.Failure != RefreshFailureUnknown || !v.NextAttemptAt.IsZero()) {
			return bad()
		}
		if (v.State == RefreshRunning || v.State == RefreshUnknown) != (v.Reservation != nil) {
			return bad()
		}
		if v.Reservation != nil {
			r := v.Reservation
			if r.AttemptSequence != v.AttemptSequence || r.AttemptKey != v.AttemptKey || r.Fence != v.Fence || r.CommandSlots < 0 || r.CommandSlots > 1 || r.CandidateSlots < 0 || r.CandidateSlots > 1 || r.DomainAuditSlots < 0 || r.DomainAuditSlots > 1 || r.Bytes < 0 || r.Bytes > MaxStoreBytes {
				return bad()
			}
		}
		if v.State == RefreshIdle && (v.AttemptSequence != 0 || v.Failure != "" || v.CommandID != "" || v.CommandOwnerID != "" || v.CommandEpoch != "" || v.CandidateID != "" || v.CandidateDigest != "" || v.ResultRevision != 0 || v.AuditRecorded || v.StateMayHaveChanged || v.NextAttemptAt.IsZero()) {
			return bad()
		}
		if v.State == RefreshRunning && (v.AttemptSequence == 0 || v.Reservation == nil || v.AuditRecorded || v.StateMayHaveChanged) {
			return bad()
		}
		if v.State == RefreshUnknown && (v.AttemptSequence == 0 || v.Reservation == nil || !v.StateMayHaveChanged) {
			return bad()
		}
		if (v.State == RefreshSucceededNoop || v.State == RefreshCandidateQuarantined) && (v.AttemptSequence == 0 || v.Failure != "" || v.CommandID == "" || v.CandidateID == "" || v.CandidateDigest == "" || !v.AuditRecorded || v.StateMayHaveChanged) {
			return bad()
		}
		if v.State == RefreshCandidateQuarantined && !v.NextAttemptAt.IsZero() {
			return bad()
		}
		if v.State == RefreshBlocked && (v.Failure == "" || !v.NextAttemptAt.IsZero()) {
			return bad()
		}
		if v.State == RefreshFailed && (v.Failure == "" || v.ConsecutiveFailures == 0 || v.NextAttemptAt.IsZero()) {
			return bad()
		}
		if !v.LastSuccessAt.IsZero() && (v.FreshUntil.IsZero() || !v.FreshUntil.After(v.LastSuccessAt)) {
			return bad()
		}
		if !refreshProducerState(v) {
			return bad()
		}
		if v.State == RefreshRunning {
			running++
		}
		if v.Reservation != nil {
			reservedCommands += v.Reservation.CommandSlots
			reservedCandidates += v.Reservation.CandidateSlots
			reservedAudit += v.Reservation.DomainAuditSlots
			reservedBytes += v.Reservation.Bytes
		}
	}
	if running > 1 || reservedCommands > 1 || reservedCandidates > 1 || reservedAudit > 1 || reservedBytes > MaxStoreBytes {
		return bad()
	}
	return nil
}

func refreshInitialDelay(key []byte, b RefreshBinding) time.Duration {
	w := b.IntervalSeconds / 10
	if w > 30 {
		w = 30
	}
	if w == 0 {
		return 0
	}
	d := keyedDigest(key, []byte("refresh-jitter"), []byte(b.SourceID), []byte(b.ApprovalID))
	n, _ := strconv.ParseUint(d[:8], 16, 32)
	return time.Duration(n%(w+1)) * time.Second
}
func (s *RefreshStore) observe(now time.Time) error {
	now = now.UTC()
	if now.IsZero() {
		return fail(CodeInputInvalid)
	}
	n := cloneRefreshSnapshot(s.state)
	if n.ClockState == RefreshClockNormal && !n.LastWallClock.IsZero() {
		if now.Before(n.LastWallClock) {
			n.ClockState = RefreshClockFrozen
			n.ClockReason = "wall_clock_rollback"
		} else if now.Sub(n.LastWallClock) > MaxRefreshClockStep {
			n.ClockState = RefreshClockFrozen
			n.ClockReason = "wall_clock_forward_jump"
		}
	}
	if now.After(n.LastWallClock) {
		n.LastWallClock = now
	}
	for i := range n.Refreshes {
		n.Refreshes[i].ClockState = n.ClockState
		n.Refreshes[i].ClockReason = n.ClockReason
		n.Refreshes[i].Stale = n.ClockState == RefreshClockFrozen || (!n.Refreshes[i].FreshUntil.IsZero() && !now.Before(n.Refreshes[i].FreshUntil))
	}
	return s.persist(n)
}

func (s *RefreshStore) Reconcile(scope Scope, bindings []RefreshBinding, now time.Time) error {
	if s == nil {
		return fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	if !validScope(scope) || bindings == nil || len(bindings) > MaxSources {
		return fail(CodeInputInvalid)
	}
	if err := s.observe(now); err != nil {
		return err
	}
	next := cloneRefreshSnapshot(s.state)
	old := map[string]RefreshView{}
	for _, v := range next.Refreshes {
		old[v.Binding.SourceID] = v
	}
	next.Refreshes = make([]RefreshView, 0, len(bindings))
	seen := map[string]bool{}
	ledgerIndex := map[string]int{}
	for i, l := range next.Ledgers {
		ledgerIndex[l.SourceID] = i
	}
	for _, b := range bindings {
		if !validRefreshBinding(b) || seen[b.SourceID] {
			return fail(CodeInputInvalid)
		}
		seen[b.SourceID] = true
		seal := bindingSeal(next.IdentityKey, scope, b)
		if v, ok := old[b.SourceID]; ok && v.Scope == scope && v.BindingSeal == seal {
			next.Refreshes = append(next.Refreshes, v)
			continue
		} else if ok && (v.State == RefreshRunning || v.State == RefreshUnknown) {
			return fail(CodeConflict)
		}
		generation := uint64(1)
		if i, ok := ledgerIndex[b.SourceID]; ok {
			if next.Ledgers[i].Scope != scope {
				return fail(CodeScopeDenied)
			}
			if next.Ledgers[i].Generation == math.MaxUint64 {
				return fail(CodeStoreLimit)
			}
			next.Ledgers[i].Generation++
			generation = next.Ledgers[i].Generation
		} else {
			if len(next.Ledgers) >= MaxSources {
				return fail(CodeStoreLimit)
			}
			next.Ledgers = append(next.Ledgers, RefreshLedger{Scope: scope, SourceID: b.SourceID, Generation: generation})
			ledgerIndex[b.SourceID] = len(next.Ledgers) - 1
		}
		next.Refreshes = append(next.Refreshes, RefreshView{Scope: scope, Binding: b, BindingSeal: seal, BindingGeneration: generation, State: RefreshIdle, NextAttemptAt: now.UTC().Add(refreshInitialDelay(next.IdentityKey, b)), ClockState: next.ClockState, ClockReason: next.ClockReason, Stale: next.ClockState == RefreshClockFrozen})
	}
	for id, v := range old {
		if !seen[id] && (v.State == RefreshRunning || v.State == RefreshUnknown) {
			return fail(CodeConflict)
		}
	}
	sort.Slice(next.Refreshes, func(i, j int) bool { return next.Refreshes[i].Binding.SourceID < next.Refreshes[j].Binding.SourceID })
	return s.persist(next)
}

func (s *RefreshStore) Refreshes(scope Scope, now time.Time) ([]RefreshView, error) {
	if s == nil {
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
	if err := s.observe(now); err != nil {
		return nil, err
	}
	out := []RefreshView{}
	for _, v := range s.state.Refreshes {
		if v.Scope == scope {
			out = append(out, detachRefreshView(v))
		}
	}
	return out, nil
}
func (s *RefreshStore) Refresh(scope Scope, source string, now time.Time) (RefreshView, error) {
	values, err := s.Refreshes(scope, now)
	if err != nil {
		return RefreshView{}, err
	}
	i, err := refreshIndex(values, scope, source)
	if err != nil {
		return RefreshView{}, err
	}
	return values[i], nil
}

// SnapshotRefreshes is the non-mutating read model used while a known-not-
// committed persistence stage is backing off. It never advances the durable
// clock and marks its detached projection stale on an observed clock anomaly.
func (s *RefreshStore) SnapshotRefreshes(scope Scope, now time.Time) ([]RefreshView, error) {
	if s == nil {
		return nil, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return nil, err
	}
	if !validScope(scope) || now.IsZero() {
		return nil, fail(CodeInputInvalid)
	}
	now = now.UTC()
	clockAnomaly := !s.state.LastWallClock.IsZero() && (now.Before(s.state.LastWallClock) || now.Sub(s.state.LastWallClock) > MaxRefreshClockStep)
	out := []RefreshView{}
	for _, stored := range s.state.Refreshes {
		if stored.Scope != scope {
			continue
		}
		v := detachRefreshView(stored)
		v.Stale = v.Stale || clockAnomaly || v.ClockState == RefreshClockFrozen || !v.FreshUntil.IsZero() && !now.Before(v.FreshUntil)
		out = append(out, v)
	}
	return out, nil
}
func (s *RefreshStore) SnapshotRefresh(scope Scope, source string, now time.Time) (RefreshView, error) {
	values, err := s.SnapshotRefreshes(scope, now)
	if err != nil {
		return RefreshView{}, err
	}
	i, err := refreshIndex(values, scope, source)
	if err != nil {
		return RefreshView{}, err
	}
	return values[i], nil
}

// Claim starts a new live attempt, or recovers one persisted running attempt
// exactly once after OpenRefreshStore. A live caller cannot reclaim an
// in-process running attempt.
func (s *RefreshStore) claim(scope Scope, source string, recovery *RefreshRecovery, capacity *StoreCapacity, now time.Time) (RefreshView, bool, error) {
	if s == nil {
		return RefreshView{}, false, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return RefreshView{}, false, err
	}
	if err := s.observe(now); err != nil {
		return RefreshView{}, false, err
	}
	i, err := refreshIndex(s.state.Refreshes, scope, source)
	if err != nil {
		return RefreshView{}, false, err
	}
	v := detachRefreshView(s.state.Refreshes[i])
	if s.state.ClockState == RefreshClockFrozen {
		return v, false, nil
	}
	if v.State == RefreshRunning {
		if recovery == nil {
			return v, false, nil
		}
		recovery.mu.Lock()
		defer recovery.mu.Unlock()
		if recovery.closed || recovery.store != s || !recovery.remaining[source] {
			return v, false, fail(CodeConflict)
		}
		delete(recovery.remaining, source)
		v.Lease = &RefreshAttemptLease{store: s, scope: scope, source: source, attemptKey: v.AttemptKey, fence: v.Fence, epoch: v.CommandEpoch, sequence: v.AttemptSequence}
		if v.Lease.epoch == "" {
			v.Lease.epoch = s.state.Epoch
		}
		return v, true, nil
	}
	if recovery != nil {
		return v, false, nil
	}
	if capacity == nil {
		return v, false, fail(CodeInputInvalid)
	}
	if v.NextAttemptAt.IsZero() || now.Before(v.NextAttemptAt) {
		return v, false, nil
	}
	reserved := StoreCapacity{}
	for _, x := range s.state.Refreshes {
		if x.Reservation != nil {
			reserved.CommandsUsed += x.Reservation.CommandSlots
			reserved.CandidatesUsed += x.Reservation.CandidateSlots
			reserved.DomainAuditUsed += x.Reservation.DomainAuditSlots
			reserved.EncodedBytes += x.Reservation.Bytes
		}
	}
	remainingBytes := capacity.EncodedBytesMax - capacity.EncodedBytes - reserved.EncodedBytes
	if capacity.CommandsUsed+reserved.CommandsUsed+1 > capacity.CommandsMax || capacity.CandidatesUsed+reserved.CandidatesUsed+1 > capacity.CandidatesMax || capacity.DomainAuditUsed+reserved.DomainAuditUsed+1 > capacity.DomainAuditMax || remainingBytes < MaxRefreshReservationBytes {
		return detachRefreshView(v), false, fail(CodeStoreLimit)
	}
	if s.state.LastSequence == math.MaxUint64 {
		v.State = RefreshBlocked
		v.Failure = RefreshFailureSequence
		v.AttemptCount = 0
		v.AttemptSequence = 0
		v.ConsecutiveFailures = 0
		v.AttemptKey = ""
		v.Fence = ""
		v.CommandID = ""
		v.CommandOwnerID = ""
		v.CommandEpoch = ""
		v.CandidateID = ""
		v.CandidateDigest = ""
		v.ResultRevision = 0
		v.StartedAt = time.Time{}
		v.CompletedAt = time.Time{}
		v.LastSuccessAt = time.Time{}
		v.FreshUntil = time.Time{}
		v.NextAttemptAt = time.Time{}
		v.AuditRecorded = false
		v.StateMayHaveChanged = false
		v.Reservation = nil
		v.Lease = nil
		n := cloneRefreshSnapshot(s.state)
		n.Refreshes[i] = cloneRefreshView(v)
		if err := s.persist(n); err != nil {
			return RefreshView{}, false, err
		}
		return detachRefreshView(v), false, nil
	}
	n := cloneRefreshSnapshot(s.state)
	n.LastSequence++
	v.State = RefreshRunning
	v.Failure = ""
	v.AttemptCount++
	v.AttemptSequence = n.LastSequence
	seq := strconv.FormatUint(v.AttemptSequence, 10)
	generation := strconv.FormatUint(v.BindingGeneration, 10)
	v.AttemptKey = "refresh_" + keyedDigest(n.IdentityKey, []byte("refresh-attempt-v3"), []byte(n.Epoch), []byte(scopeKey(scope)), []byte(source), []byte(generation), []byte(seq), []byte(v.BindingSeal))[:32]
	v.Fence = keyedDigest(n.IdentityKey, []byte("refresh-fence-v3"), []byte(n.Epoch), []byte(v.AttemptKey), []byte(seq))
	v.StartedAt = now.UTC()
	v.CompletedAt = time.Time{}
	v.NextAttemptAt = time.Time{}
	v.CommandID = ""
	v.CommandOwnerID = ""
	v.CommandEpoch = ""
	v.CandidateID = ""
	v.CandidateDigest = ""
	v.ResultRevision = 0
	v.AuditRecorded = false
	v.StateMayHaveChanged = false
	v.Reservation = &RefreshReservation{AttemptSequence: v.AttemptSequence, AttemptKey: v.AttemptKey, Fence: v.Fence, CommandSlots: 1, CandidateSlots: 1, DomainAuditSlots: 1, Bytes: remainingBytes}
	for j := range n.Ledgers {
		if n.Ledgers[j].SourceID == source {
			n.Ledgers[j].LastIssuedSequence = v.AttemptSequence
		}
	}
	lease := &RefreshAttemptLease{store: s, scope: scope, source: source, attemptKey: v.AttemptKey, fence: v.Fence, epoch: n.Epoch, sequence: v.AttemptSequence}
	n.Refreshes[i] = cloneRefreshView(v)
	if err := s.persist(n); err != nil {
		return RefreshView{}, false, err
	}
	v = detachRefreshView(v)
	v.Lease = lease
	return v, true, nil
}

func (s *RefreshStore) ClaimLive(scope Scope, source string, capacity StoreCapacity, now time.Time) (RefreshView, bool, error) {
	return s.claim(scope, source, nil, &capacity, now)
}
func (s *RefreshStore) ClaimRecovery(scope Scope, source string, recovery *RefreshRecovery, now time.Time) (RefreshView, bool, error) {
	if recovery == nil {
		return RefreshView{}, false, fail(CodeInputInvalid)
	}
	return s.claim(scope, source, recovery, nil, now)
}

func (s *RefreshStore) BindCommand(scope Scope, source string, a RefreshView, owner, commandID string) error {
	if s == nil || a.Lease == nil {
		return fail(CodeConflict)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a.Lease.mu.Lock()
	defer a.Lease.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	lease := a.Lease
	if lease.bound || lease.completed || lease.store != s || lease.scope != scope || lease.source != source || lease.sequence != a.AttemptSequence || lease.attemptKey != a.AttemptKey || lease.fence != a.Fence || lease.epoch != s.state.Epoch || !parserText(owner, false) || strings.TrimSpace(owner) != owner || !controlIDPattern.MatchString(commandID) {
		return fail(CodeConflict)
	}
	i, err := refreshIndex(s.state.Refreshes, scope, source)
	if err != nil {
		return err
	}
	v := cloneRefreshView(s.state.Refreshes[i])
	if v.State != RefreshRunning || v.AttemptSequence != a.AttemptSequence || v.AttemptKey != a.AttemptKey || v.Fence != a.Fence || v.Reservation == nil {
		return fail(CodeConflict)
	}
	if v.CommandID != "" && (v.CommandID != commandID || v.CommandOwnerID != owner || v.CommandEpoch != lease.epoch) {
		return fail(CodeConflict)
	}
	if v.CommandID != commandID {
		n := cloneRefreshSnapshot(s.state)
		v.CommandID = commandID
		v.CommandOwnerID = owner
		v.CommandEpoch = lease.epoch
		n.Refreshes[i] = cloneRefreshView(v)
		if err := s.persist(n); err != nil {
			return err
		}
	}
	lease.bound = true
	return nil
}

func (s *RefreshStore) ReconcileReservation(scope Scope, source string, a RefreshView, command *ControlCommand) error {
	if s == nil || a.Lease == nil {
		return fail(CodeConflict)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a.Lease.mu.Lock()
	defer a.Lease.mu.Unlock()
	if err := s.usable(); err != nil {
		return err
	}
	lease := a.Lease
	if !lease.bound || lease.completed || lease.store != s || lease.scope != scope || lease.source != source || lease.sequence != a.AttemptSequence || lease.attemptKey != a.AttemptKey || lease.fence != a.Fence {
		return fail(CodeConflict)
	}
	i, err := refreshIndex(s.state.Refreshes, scope, source)
	if err != nil {
		return err
	}
	v := cloneRefreshView(s.state.Refreshes[i])
	if v.AttemptSequence != a.AttemptSequence || v.AttemptKey != a.AttemptKey || v.Fence != a.Fence || v.Reservation == nil {
		return fail(CodeConflict)
	}
	n := cloneRefreshSnapshot(s.state)
	r := *v.Reservation
	if command != nil {
		if command.ID != v.CommandID || command.OwnerID != v.CommandOwnerID || command.Scope != scope || command.SourceID != source {
			return fail(CodeConflict)
		}
		r.CommandSlots = 0
		if command.Result != nil {
			r.Bytes = 0
			r.CandidateSlots = 0
			r.DomainAuditSlots = 0
		}
	}
	v.Reservation = &r
	n.Refreshes[i] = cloneRefreshView(v)
	return s.persist(n)
}

func (s *RefreshStore) ReservedCapacity() (StoreCapacity, error) {
	if s == nil {
		return StoreCapacity{}, fail(CodeStoreClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return StoreCapacity{}, err
	}
	out := StoreCapacity{}
	for _, v := range s.state.Refreshes {
		if v.Reservation != nil {
			out.CommandsUsed += v.Reservation.CommandSlots
			out.CandidatesUsed += v.Reservation.CandidateSlots
			out.DomainAuditUsed += v.Reservation.DomainAuditSlots
			out.EncodedBytes += v.Reservation.Bytes
		}
	}
	return out, nil
}

func refreshRetriable(f RefreshFailure) bool {
	switch f {
	case RefreshFailureTransport, RefreshFailureHTTP, RefreshFailureRate, RefreshFailureCanceled, RefreshFailureUnavailable:
		return true
	}
	return false
}
func refreshBackoff(b RefreshBinding, n uint32) time.Duration {
	v := b.IntervalSeconds
	for i := uint32(1); i < n && v < b.MaxBackoffSeconds; i++ {
		if v > b.MaxBackoffSeconds/2 {
			v = b.MaxBackoffSeconds
			break
		}
		v *= 2
	}
	if v > b.MaxBackoffSeconds {
		v = b.MaxBackoffSeconds
	}
	return time.Duration(v) * time.Second
}
func (s *RefreshStore) Complete(scope Scope, source string, c RefreshCompletion, now time.Time) (RefreshView, error) {
	if s == nil || c.Lease == nil {
		return RefreshView{}, fail(CodeConflict)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c.Lease.mu.Lock()
	defer c.Lease.mu.Unlock()
	lease := c.Lease
	if lease.completed || lease.store != s || lease.scope != scope || lease.source != source || lease.sequence != c.AttemptSequence || lease.attemptKey != c.AttemptKey || lease.fence != c.Fence {
		return RefreshView{}, fail(CodeConflict)
	}
	if err := s.usable(); err != nil {
		return RefreshView{}, err
	}
	if err := s.observe(now); err != nil {
		return RefreshView{}, err
	}
	i, err := refreshIndex(s.state.Refreshes, scope, source)
	if err != nil {
		return RefreshView{}, err
	}
	v := cloneRefreshView(s.state.Refreshes[i])
	if v.State != RefreshRunning || c.AttemptKey != v.AttemptKey || c.AttemptSequence != v.AttemptSequence || c.BindingSeal != v.BindingSeal || c.Fence != v.Fence || v.CommandID != "" && (!lease.bound || lease.epoch != v.CommandEpoch) || v.CommandID == "" && lease.bound || c.CommandID != "" && c.CommandID != v.CommandID || !refreshStateKnown(c.State) || c.State == RefreshIdle || c.State == RefreshRunning {
		return RefreshView{}, fail(CodeConflict)
	}
	v.State = c.State
	v.Failure = c.Failure
	if c.CommandID != "" {
		v.CommandID = c.CommandID
	}
	v.CandidateID = c.CandidateID
	v.CandidateDigest = c.CandidateDigest
	v.ResultRevision = c.ResultRevision
	v.AuditRecorded = c.AuditRecorded
	v.StateMayHaveChanged = c.StateMayHaveChanged
	v.CompletedAt = now.UTC()
	if v.CompletedAt.Before(v.StartedAt) {
		return RefreshView{}, fail(CodeStoreUnsafe)
	}
	v.NextAttemptAt = time.Time{}
	switch v.State {
	case RefreshCandidateQuarantined, RefreshSucceededNoop:
		v.Failure = ""
		v.ConsecutiveFailures = 0
		v.LastSuccessAt = v.CompletedAt
		v.FreshUntil = v.CompletedAt.Add(time.Duration(v.Binding.MaxStaleSeconds) * time.Second)
		if v.State == RefreshSucceededNoop {
			v.NextAttemptAt = v.CompletedAt.Add(time.Duration(v.Binding.IntervalSeconds) * time.Second)
		}
	case RefreshUnknown:
		v.Failure = RefreshFailureUnknown
		v.StateMayHaveChanged = true
	case RefreshFailed:
		if !refreshRetriable(v.Failure) || v.StateMayHaveChanged {
			v.State = RefreshBlocked
		} else {
			v.ConsecutiveFailures++
			v.NextAttemptAt = v.CompletedAt.Add(refreshBackoff(v.Binding, v.ConsecutiveFailures))
		}
	case RefreshBlocked:
		if v.Failure == "" {
			return RefreshView{}, fail(CodeInputInvalid)
		}
	}
	if v.State != RefreshUnknown {
		v.Reservation = nil
	}
	v.Lease = nil
	v.Stale = s.state.ClockState == RefreshClockFrozen || (!v.FreshUntil.IsZero() && !now.Before(v.FreshUntil))
	n := cloneRefreshSnapshot(s.state)
	n.Refreshes[i] = cloneRefreshView(v)
	if err := s.persist(n); err != nil {
		return RefreshView{}, err
	}
	lease.completed = true
	return detachRefreshView(v), nil
}
