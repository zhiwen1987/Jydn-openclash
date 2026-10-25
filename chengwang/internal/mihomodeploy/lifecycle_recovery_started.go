package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"time"
)

const lifecycleRecoveryExecutionSchema = "chengwang.mihomo-recovery-execution/v1"
const lifecycleRecoveryCompletedExecutionSchema = "chengwang.mihomo-recovery-execution/v3"
const lifecycleRecoveryAbsentExecutionSchema = "chengwang.mihomo-recovery-execution/v4"
const lifecycleRecoveryAbsentVerifiedExecutionSchema = "chengwang.mihomo-recovery-execution/v5"
const lifecycleRecoveryAbsentCompletedExecutionSchema = "chengwang.mihomo-recovery-execution/v6"

func lifecycleRecoveryExecutionStartedSchema(v string) bool { return v == lifecycleRecoveryExecutionSchema || v == lifecycleRecoveryAbsentExecutionSchema }
func lifecycleRecoveryExecutionVerifiedSchema(v string) bool { return v == lifecycleRecoveryVerifiedExecutionSchema || v == lifecycleRecoveryAbsentVerifiedExecutionSchema }
func lifecycleRecoveryExecutionCompletedSchema(v string) bool { return v == lifecycleRecoveryCompletedExecutionSchema || v == lifecycleRecoveryAbsentCompletedExecutionSchema }

func lifecycleRecoveryStartedToVerifiedSchema(v string) (string, bool) {
	switch v {
	case lifecycleRecoveryExecutionSchema:
		return lifecycleRecoveryVerifiedExecutionSchema, true
	case lifecycleRecoveryAbsentExecutionSchema:
		return lifecycleRecoveryAbsentVerifiedExecutionSchema, true
	default:
		return "", false
	}
}

func lifecycleRecoveryVerifiedToStartedSchema(v string) (string, bool) {
	switch v {
	case lifecycleRecoveryVerifiedExecutionSchema:
		return lifecycleRecoveryExecutionSchema, true
	case lifecycleRecoveryAbsentVerifiedExecutionSchema:
		return lifecycleRecoveryAbsentExecutionSchema, true
	default:
		return "", false
	}
}

func lifecycleRecoveryVerifiedToCompletedSchema(v string) (string, bool) {
	switch v {
	case lifecycleRecoveryVerifiedExecutionSchema:
		return lifecycleRecoveryCompletedExecutionSchema, true
	case lifecycleRecoveryAbsentVerifiedExecutionSchema:
		return lifecycleRecoveryAbsentCompletedExecutionSchema, true
	default:
		return "", false
	}
}

func lifecycleRecoveryCompletedToVerifiedSchema(v string) (string, bool) {
	switch v {
	case lifecycleRecoveryCompletedExecutionSchema:
		return lifecycleRecoveryVerifiedExecutionSchema, true
	case lifecycleRecoveryAbsentCompletedExecutionSchema:
		return lifecycleRecoveryAbsentVerifiedExecutionSchema, true
	default:
		return "", false
	}
}

// V1 records only an actual happened Start. It grants no verification,
// completion or fresh process authority. A later contract needs a new version.
// Keeping the containing transaction's pointer nil preserves old V3 bytes.
type lifecycleRecoveryExecution struct {
	Schema                 string                             `json:"schema"`
	Started                labRecoveryStartedFact             `json:"started"`
	ArmedOwner             lifecycleOwner                     `json:"armedOwner"`
	ArmedLastTrustedAt     time.Time                          `json:"armedLastTrustedAt"`
	ArmedLastRecoveryFence uint64                             `json:"armedLastRecoveryFence"`
	ArmedRecoveryUpdatedAt time.Time                          `json:"armedRecoveryUpdatedAt"`
	ArmedFailedQuiescence  []labQuiescenceObservation         `json:"armedFailedQuiescence"`
	StartedCommitRevision  uint64                             `json:"startedCommitRevision"`
	RecordedAt             time.Time                          `json:"recordedAt"`
	Verification           *lifecycleRecoveryVerification     `json:"verification,omitempty"`
	CompletionSource       *lifecycleRecoveryCompletionSource `json:"completionSource,omitempty"`
}

// Captured only from the same actual START_ARMED WAL, immediately before the
// native call. The closure seals owner, exact canonical bytes and identity;
// copying its fields cannot mint a proof for another store or preimage.
type labRecoveryStartedSource struct {
	store     *lifecycleRecoveryStoreCore
	canonical string
	startMode string
	binding   func(*labRecoveryStartedSource, *lifecycleRecoveryStoreCore) bool
}

func labRecoveryStartedCaptureSource(p *labRecoveryStartPermit, f labRecoveryStartFact, b labRecoveryStartedBinding, now time.Time) (*labRecoveryStartedSource, error) {
	if labRecoveryStartedFinalGate(p, f, b, now) != nil {
		return nil, errLabRecoveryStart
	}
	x := p.core.store
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.verify() != nil || x.trustedNow(now) != nil || x.record.core.Revision != b.Revision || x.record.core.RecordSHA256 != b.RecordSHA256 {
		return nil, errLabRecoveryStart
	}
	expected, err := lifecycleRecoveryStartedBinding(x.record.core)
	if err != nil || !reflect.DeepEqual(expected, b) {
		return nil, errLabRecoveryStart
	}
	s := &labRecoveryStartedSource{store: x, canonical: string(x.raw)}
	canonical := s.canonical
	s.binding = func(candidate *labRecoveryStartedSource, owner *lifecycleRecoveryStoreCore) bool {
		return candidate == s && owner == x && candidate.store == owner && candidate.canonical == canonical
	}
	return s, nil
}

func labRecoveryAbsentStartedCaptureSource(p *labRecoveryAbsentStartPermit, f labRecoveryAbsentStartFact, b labRecoveryStartedBinding, now time.Time) (*labRecoveryStartedSource, error) {
	if labRecoveryStartedFinalAbsentGate(p, f, b, now) != nil { return nil, errLabRecoveryStart }
	x := p.core.store
	x.mu.Lock(); defer x.mu.Unlock()
	if x.verify() != nil || x.trustedNow(now) != nil || x.record.core.Revision != b.Revision || x.record.core.RecordSHA256 != b.RecordSHA256 { return nil, errLabRecoveryStart }
	s := &labRecoveryStartedSource{store: x, canonical: string(x.raw), startMode: labRecoveryStartModeOldEpochAbsent}
	canonical := s.canonical
	s.binding = func(candidate *labRecoveryStartedSource, owner *lifecycleRecoveryStoreCore) bool {
		return candidate == s && owner == x && candidate.store == owner && candidate.canonical == canonical && candidate.startMode == labRecoveryStartModeOldEpochAbsent
	}
	return s, nil
}

func lifecycleRecoveryStartedBinding(w *lifecycleV3Wire) (labRecoveryStartedBinding, error) {
	var zero labRecoveryStartedBinding
	if w == nil || w.Recovery == nil || w.RecoveryOwner == nil {
		return zero, errLifecycleUnsafe
	}
	a := w.Recovery
	absent := a.Plan.Schema == labRecoveryPlanSchemaV3 && a.Plan.StartMode == labRecoveryStartModeOldEpochAbsent
	if a.Phase != "START_ARMED" || a.StartIntent == nil || a.Approval == nil || a.Execution != nil || a.Revocation != nil || a.Failure != nil ||
		absent || a.Quiescence == nil || a.StopBinding == nil ||
		a.StartIntent.OwnerFence != w.LastRecoveryFence || w.RecoveryOwner.Fence != w.LastRecoveryFence || !w.LastTrustedAt.Equal(a.StartIntent.ArmedAt) || !a.UpdatedAt.Equal(a.StartIntent.ArmedAt) {
		return zero, errLifecycleUnsafe
	}
	b := labRecoveryStartedBinding{RecoveryID: a.Plan.RecoveryID, RecoveryPlanSHA256: a.Plan.PlanSHA256, StartIntentSHA256: a.StartIntent.IntentSHA256,
		Revision: w.Revision, RecordSHA256: w.RecordSHA256, TargetArtifact: cloneArtifactDescriptor(a.Plan.TargetArtifact), QuiescenceSHA256: a.Quiescence.QuiescenceSHA256,
		ArmedAt: a.StartIntent.ArmedAt, ExpiresAt: a.Plan.ExpiresAt, ExpectedOldIdentity: a.Quiescence.Binding.ExpectedOldIdentity, StartMillis: a.Plan.Budgets.StartMillis}
	if !labRecoveryStartedBindingValid(b, b.ArmedAt) {
		return zero, errLifecycleUnsafe
	}
	return b, nil
}

func lifecycleRecoveryAbsentStartedBindingMatches(w *lifecycleV3Wire, b labRecoveryStartedBinding) bool {
	if w == nil || w.Recovery == nil || w.RecoveryOwner == nil { return false }
	a := w.Recovery
	h := w.Current.Head
	return a.Phase == "START_ARMED" && a.Plan.Schema == labRecoveryPlanSchemaV3 && a.Plan.StartMode == labRecoveryStartModeOldEpochAbsent &&
		a.StartIntent != nil && a.Approval != nil && a.StopIntent == nil && a.StopBinding == nil && a.Quiescence == nil && a.Execution == nil && a.Revocation == nil && a.Failure == nil &&
		a.StartIntent.OwnerFence == w.LastRecoveryFence && w.RecoveryOwner.Fence == w.LastRecoveryFence && w.LastTrustedAt.Equal(a.StartIntent.ArmedAt) && a.UpdatedAt.Equal(a.StartIntent.ArmedAt) &&
		b.RecoveryID == a.Plan.RecoveryID && b.RecoveryPlanSHA256 == a.Plan.PlanSHA256 && b.StartIntentSHA256 == a.StartIntent.IntentSHA256 &&
		b.Revision == w.Revision && b.RecordSHA256 == w.RecordSHA256 && reflect.DeepEqual(b.TargetArtifact, a.Plan.TargetArtifact) && b.QuiescenceSHA256 == "" &&
		b.ArmedAt.Equal(a.StartIntent.ArmedAt) && b.ExpiresAt.Equal(a.Plan.ExpiresAt) && b.StartMillis == a.Plan.Budgets.StartMillis &&
		b.StartMode == labRecoveryStartModeOldEpochAbsent && lifecycleNonzeroHash(b.AbsenceCleanupSHA256) &&
		b.ExpectedOldIdentity.PID == h.PID && b.ExpectedOldIdentity.StartTicks == h.StartTicks && b.ExpectedOldIdentity.NetNSInode == h.NetNSInode &&
		b.ExpectedOldIdentity.ELFSHA256 == h.KernelSHA256 && b.ExpectedOldIdentity.ArtifactSHA256 == h.Artifact.Config.SHA256 &&
		b.ExpectedOldIdentity.ControllerPort == h.ControllerPort && b.ExpectedOldIdentity.MixedPort == h.MixedPort
}

func lifecycleRecoveryExecutionFieldsValid(a lifecycleRecoveryTxn, at time.Time, revision uint64) bool {
	e := a.Execution
	if e == nil {
		return true
	}
	completed := lifecycleRecoveryExecutionCompletedSchema(e.Schema) && e.Verification != nil && e.CompletionSource != nil && a.Phase == "COMPLETED" && a.Completion != nil
	absent := a.Plan.Schema == labRecoveryPlanSchemaV3 && a.Plan.StartMode == labRecoveryStartModeOldEpochAbsent
	if !lifecycleRecoveryVerificationFieldsValid(a, at, revision) || (!completed && a.Phase != "START_ARMED" && a.Phase != "RECOVERY_UNKNOWN") || (!completed && a.Completion != nil) || a.StartIntent == nil || a.Approval == nil ||
		(absent && (!lifecycleRecoveryExecutionStartedSchema(e.Schema) && !lifecycleRecoveryExecutionVerifiedSchema(e.Schema) && !lifecycleRecoveryExecutionCompletedSchema(e.Schema) || a.Quiescence != nil || a.StopBinding != nil || a.StopIntent != nil || e.Started.Binding.StartMode != labRecoveryStartModeOldEpochAbsent)) ||
		(!absent && (a.Quiescence == nil || a.StopBinding == nil)) ||
		e.ArmedFailedQuiescence == nil || len(e.ArmedFailedQuiescence) > len(a.FailedQuiescence) || !reflect.DeepEqual(e.ArmedFailedQuiescence, a.FailedQuiescence[:len(e.ArmedFailedQuiescence)]) ||
		!lifecycleTime(e.RecordedAt) || e.RecordedAt.Before(e.Started.ObservedAt) || e.RecordedAt.After(a.UpdatedAt) || e.RecordedAt.After(at) ||
		e.StartedCommitRevision <= e.Started.Binding.Revision || e.StartedCommitRevision > revision ||
		e.ArmedLastRecoveryFence != a.StartIntent.OwnerFence || e.ArmedOwner.Fence != e.ArmedLastRecoveryFence ||
		!e.ArmedLastTrustedAt.Equal(a.StartIntent.ArmedAt) || !e.ArmedRecoveryUpdatedAt.Equal(a.StartIntent.ArmedAt) {
		return false
	}
	b := e.Started.Binding
	b.RecoveryID, b.RecoveryPlanSHA256, b.StartIntentSHA256 = a.Plan.RecoveryID, a.Plan.PlanSHA256, a.StartIntent.IntentSHA256
	b.TargetArtifact, b.ArmedAt, b.ExpiresAt, b.StartMillis = cloneArtifactDescriptor(a.Plan.TargetArtifact), a.StartIntent.ArmedAt, a.Plan.ExpiresAt, a.Plan.Budgets.StartMillis
	if !absent {
		b.QuiescenceSHA256, b.ExpectedOldIdentity, b.StartMode, b.AbsenceCleanupSHA256 = a.Quiescence.QuiescenceSHA256, a.Quiescence.Binding.ExpectedOldIdentity, "", ""
	}
	if !labRecoveryStartedFactValid(e.Started, b, at) {
		return false
	}
	for _, stream := range []*labKernelStream{e.Started.Observation.StartObservation.Stdout, e.Started.Observation.StartObservation.Stderr} {
		if stream == nil || stream.Bytes < 0 || stream.Bytes > 64<<10 || stream.TotalBytes < int64(stream.Bytes) || !lifecycleNonzeroHash(stream.SHA256) || stream.Truncated != (stream.TotalBytes > int64(stream.Bytes)) || (stream.Truncated && stream.Bytes != 64<<10) {
			return false
		}
	}
	return true
}

// All armed clock/owner/fence metadata is explicit. Other fields retain their
// exact current immutable bytes; failed observations retain the armed prefix.
// The result is fully decoded and hashed, not a caller-declared source digest.
func lifecycleRecoveryArmedPreimage(w *lifecycleV3Wire, a lifecycleRecoveryTxn) ([]byte, error) {
	return lifecycleRecoveryArmedPreimageScoped(w, a, newLifecycleV3DecodeScope())
}

func lifecycleRecoveryArmedPreimageScoped(w *lifecycleV3Wire, a lifecycleRecoveryTxn, scope *lifecycleV3DecodeScope) ([]byte, error) {
	e := a.Execution
	if scope == nil || w == nil || e == nil || w.Recovery == nil || !reflect.DeepEqual(*w.Recovery, a) ||
		(!lifecycleRecoveryExecutionStartedSchema(e.Schema) && !lifecycleRecoveryExecutionVerifiedSchema(e.Schema)) || e.CompletionSource != nil {
		return nil, errLifecycleUnsafe
	}
	raw, err := json.Marshal(w)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	var armed lifecycleV3Wire
	if json.Unmarshal(raw, &armed) != nil {
		return nil, errLifecycleUnsafe
	}
	armed.Revision = e.Started.Binding.Revision
	armed.RecordSHA256 = e.Started.Binding.RecordSHA256
	armed.LastTrustedAt = e.ArmedLastTrustedAt
	owner := e.ArmedOwner
	armed.RecoveryOwner = &owner
	armed.LastRecoveryFence = e.ArmedLastRecoveryFence
	armed.Recovery.Phase = "START_ARMED"
	armed.Recovery.Revocation = nil // the strict armed phase proves these absent
	armed.Recovery.Failure = nil
	prefix := armed.Recovery.Execution.ArmedFailedQuiescence
	armed.Recovery.Execution = nil
	armed.Recovery.UpdatedAt = e.ArmedRecoveryUpdatedAt
	armed.Recovery.FailedQuiescence = prefix
	raw, err = json.Marshal(&armed)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	r, err := decodeLifecycleV3RecordScoped(raw, scope)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	if e.Started.Binding.StartMode == labRecoveryStartModeOldEpochAbsent {
		if !lifecycleRecoveryAbsentStartedBindingMatches(r.core, e.Started.Binding) { return nil, errLifecycleUnsafe }
	} else {
		binding, err := lifecycleRecoveryStartedBinding(r.core)
		if err != nil || !reflect.DeepEqual(binding, e.Started.Binding) { return nil, errLifecycleUnsafe }
	}
	return raw, nil
}

func validateLifecycleRecoveryExecution(w *lifecycleV3Wire, a lifecycleRecoveryTxn) error {
	return validateLifecycleRecoveryExecutionScoped(w, a, newLifecycleV3DecodeScope())
}

func validateLifecycleRecoveryExecutionScoped(w *lifecycleV3Wire, a lifecycleRecoveryTxn, scope *lifecycleV3DecodeScope) error {
	if scope == nil || w == nil {
		return errLifecycleUnsafe
	}
	if a.Execution == nil {
		return nil
	}
	if !lifecycleRecoveryExecutionFieldsValid(a, w.LastTrustedAt, w.Revision) {
		return errLifecycleUnsafe
	}
	if lifecycleRecoveryExecutionCompletedSchema(a.Execution.Schema) {
		preimage, err := lifecycleRecoveryCompletionPreimageScoped(w, a, scope)
		if err != nil {
			return err
		}
		verified, err := decodeLifecycleV3RecordScoped(preimage, scope)
		if err != nil || verified.core.Recovery == nil || verified.core.Recovery.Execution == nil || !lifecycleRecoveryExecutionVerifiedSchema(verified.core.Recovery.Execution.Schema) {
			return errLifecycleUnsafe
		}
		return nil
	}
	_, err := lifecycleRecoveryArmedPreimageScoped(w, a, scope)
	if err == nil && a.Execution.Verification != nil {
		_, err = lifecycleRecoveryVerificationPreimageScoped(w, a, scope)
	}
	return err
}

// This permit exists only within one locked record method, after consuming
// an issued actual Started capability. Generic candidate preparation cannot
// replace it with an arbitrary wire, callback or "validated" boolean.
type lifecycleStartedPublication struct {
	base      *lifecycleVerifiedBaseCore
	canonical string
	binding   func(*lifecycleStartedPublication, *lifecycleRecoveryStoreCore, *lifecycleVerifiedBaseCore) bool
}

func (x *lifecycleRecoveryStoreCore) startedRecordTransition(base *lifecycleVerifiedBase, next lifecycleV3Record) bool {
	p := x.startedRecord
	if p == nil || p.binding == nil || base == nil || !p.binding(p, x, base.core) || next.core == nil {
		return false
	}
	raw, err := json.Marshal(next.core)
	if err != nil || string(raw) != p.canonical || x.record.core.Recovery == nil || x.record.core.Recovery.Execution != nil || next.core.Recovery == nil || next.core.Recovery.Execution == nil {
		return false
	}
	var projection lifecycleV3Wire
	if json.Unmarshal(raw, &projection) != nil {
		return false
	}
	projection.Recovery.Execution = nil
	return lifecycleV3Transition(x.record.core, &projection)
}

func (s *lifecycleRecoveryStore) recordRecoveryStarted(t *lifecycleRecoveryOwnerToken, q *labRecoveryStartedEpoch, now time.Time) error {
	// Admit/consume the registry item exactly once, before every store/token/
	// phase rejection. The binding comes from the private item, never a DTO;
	// it is independently matched to the actual armed WAL below. Retain the
	// error until the store's clock check so rollback still poisons that store.
	var fact labRecoveryStartedFact
	var consumeErr error
	var consumedCore *labRecoveryStartedEpochCore
	if q == nil || q.core == nil {
		consumeErr = errLabRecoveryStart
	} else {
		consumedCore = q.core
		fact, consumeErr = q.consumeStartedEpochForRecord(q.core.fact.Binding, now)
	}
	if s == nil || s.core == nil {
		return errLifecycleUnsafe
	}
	x := s.core
	x.mu.Lock()
	defer x.mu.Unlock()
	base, err := x.verifiedBase()
	if err != nil {
		return err
	}
	defer base.release()
	if err := x.token(t, false, now); err != nil {
		return err
	}
	if consumeErr != nil {
		return errLifecycleUnsafe
	}
	a := x.record.core.Recovery
	absent := a != nil && a.Plan.Schema == labRecoveryPlanSchemaV3 && a.Plan.StartMode == labRecoveryStartModeOldEpochAbsent
	if a == nil || (a.Phase != "START_ARMED" && a.Phase != "RECOVERY_UNKNOWN") || a.StartIntent == nil || a.Execution != nil ||
		(absent && (a.Quiescence != nil || a.StopBinding != nil || a.StopIntent != nil)) || (!absent && a.Quiescence == nil) {
		return errLifecycleUnsafe
	}
	source := q.core.source
	if source == nil {
		return errLifecycleUnsafe
	}
	armed, sourceErr := decodeLifecycleV3Record([]byte(source.canonical))
	var expected labRecoveryStartedBinding
	if sourceErr == nil {
		if source.startMode == labRecoveryStartModeOldEpochAbsent {
			expected = fact.Binding
			if !lifecycleRecoveryAbsentStartedBindingMatches(armed.core, expected) { sourceErr = errLifecycleUnsafe }
		} else {
			expected, sourceErr = lifecycleRecoveryStartedBinding(armed.core)
		}
	}
	if sourceErr != nil || !reflect.DeepEqual(fact.Binding, expected) || source.binding == nil || !source.binding(source, x) || armed.core.RecoveryOwner == nil || x.live == nil ||
		x.record.core.RecoveryOwner == nil || !reflect.DeepEqual(armed.core.RecoveryOwner, x.record.core.RecoveryOwner) || armed.core.LastRecoveryFence != x.record.core.LastRecoveryFence {
		return errLifecycleUnsafe
	}
	next, err := base.copyRecord()
	if err != nil || next.core.Revision == ^uint64(0) {
		return errLifecycleUnsafe
	}
	b := next.core.Recovery
	executionSchema := lifecycleRecoveryExecutionSchema
	if absent { executionSchema = lifecycleRecoveryAbsentExecutionSchema }
	b.Execution = &lifecycleRecoveryExecution{Schema: executionSchema, Started: fact, ArmedOwner: *armed.core.RecoveryOwner,
		ArmedLastTrustedAt: armed.core.LastTrustedAt, ArmedLastRecoveryFence: armed.core.LastRecoveryFence,
		ArmedRecoveryUpdatedAt: armed.core.Recovery.UpdatedAt, ArmedFailedQuiescence: armed.core.Recovery.FailedQuiescence,
		StartedCommitRevision: next.core.Revision + 1, RecordedAt: now}
	b.UpdatedAt = now
	preimage, err := lifecycleRecoveryArmedPreimage(next.core, *b)
	if err != nil || !bytes.Equal(preimage, []byte(source.canonical)) {
		return errLifecycleUnsafe
	}
	fresh := a.Phase == "START_ARMED" && a.Revocation == nil && a.Failure == nil && a.Approval != nil && now.Before(a.Approval.ExpiresAt) && now.Before(a.Plan.ExpiresAt) && now.Before(x.record.core.RecoveryOwner.ExpiresAt) && labRecoveryStartedBindingValid(fact.Binding, now)
	if !fresh {
		b.Phase = "RECOVERY_UNKNOWN"
		if b.Failure == nil {
			b.Failure = &lifecycleRecoveryFailure{"EXPIRED", now}
		}
	}
	canonical, err := json.Marshal(next.core)
	if err != nil {
		return errLifecycleUnsafe
	}
	proof := &lifecycleStartedPublication{base: base.core, canonical: string(canonical)}
	x.startedRecord = proof
	defer func() { x.startedRecord = nil }()
	sealed := proof.canonical
	proof.binding = func(candidate *lifecycleStartedPublication, owner *lifecycleRecoveryStoreCore, original *lifecycleVerifiedBaseCore) bool {
		return candidate == proof && owner == x && original == base.core && candidate.base == original && candidate.canonical == sealed
	}
	if err := x.commitWithBase(base, next, now); err != nil {
		return err
	}
	// The original registry item was consumed above. Only an actual successful
	// canonical publication/readback may retain its source-owned identity for
	// observation. This never restores that item or grants another Start.
	if fresh && consumedCore.issuer == &processLabRecoveryStartedIssuer {
		// This issuance block is reachable only through the original successful
		// registry consume and actual S1 publication in this locked invocation.
		// There is deliberately no callable factory accepting old fact/core DTOs.
		if x.startedRecord != proof || proof.binding == nil || !proof.binding(proof, x, base.core) || x.verify() != nil ||
			x.record.core.Recovery == nil || x.record.core.Recovery.Execution == nil || x.live != t.core ||
			!reflect.DeepEqual(x.record.core.Recovery.Execution.Started, fact) || !reflect.DeepEqual(consumedCore.fact, fact) {
			return errLifecycleUnsafe
		}
		actualNow := time.Now().UTC()
		current := x.record.core.Recovery
		if x.trustedNow(actualNow) != nil {
			return errLifecycleUnsafe
		}
		if current.Phase == "START_ARMED" && current.Revocation == nil && current.Failure == nil && current.Approval != nil &&
			actualNow.Before(current.Approval.ExpiresAt) && actualNow.Before(current.Plan.ExpiresAt) && actualNow.Before(x.record.core.RecoveryOwner.ExpiresAt) {
			canonical, err := json.Marshal(x.record.core)
			if err != nil || !bytes.Equal(canonical, x.raw) {
				return errLifecycleUnsafe
			}
			started, originalSource, seal, kernel := consumedCore, consumedCore.source, consumedCore.seal, consumedCore.owner
			originalFact := labRecoveryStartedCloneFact(fact)
			owner, image := t.core, string(x.raw)
			custody := &labRecoveryStartedCustody{store: x, owner: owner, started: started, canonical: image}
			custody.binding = func(candidate *labRecoveryStartedCustody, store *lifecycleRecoveryStoreCore) bool {
				return candidate == custody && store == x && candidate.store == x && candidate.owner == owner && candidate.started == started && candidate.canonical == image &&
					started.owner == kernel && started.source == originalSource && started.seal == seal && reflect.DeepEqual(started.fact, originalFact) &&
					originalSource != nil && originalSource.binding != nil && originalSource.binding(originalSource, x)
			}
			x.retainedStarted = custody
		}
	}
	return nil
}

func lifecycleRecoveryStartedReserve(a *lifecycleRecoveryTxn) *lifecycleRecoveryExecution {
	// All values are size-only upper bounds; this function never issues a cap.
	hash := strings.Repeat("f", 64)
	max := uint64(^uint64(0))
	when := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	yes, no, class := true, false, "NONE"
	pid := int(1<<31 - 1)
	id := labKernelIdentity{pid, max, max, hash, 128 << 20, strings.Repeat("f", 40), hash, 65535, 65535}
	stream := labKernelStream{64 << 10, 1<<63 - 1, hash, false, false}
	start := labKernelStartObservation{Attempted: true, Started: &yes, PID: &pid, StartTicks: &max, WaitReturned: &no, WaitErrorClass: "NOT_WAITED", TermSent: &no, KillSent: &no, Stdout: &stream, Stderr: &stream}
	absent := a.Plan.Schema == labRecoveryPlanSchemaV3 && a.Plan.StartMode == labRecoveryStartModeOldEpochAbsent
	binding := labRecoveryStartedBinding{RecoveryID: a.Plan.RecoveryID, RecoveryPlanSHA256: hash, StartIntentSHA256: hash, Revision: max, RecordSHA256: hash,
		TargetArtifact: cloneArtifactDescriptor(a.Plan.TargetArtifact), QuiescenceSHA256: hash, ArmedAt: when, ExpiresAt: when, ExpectedOldIdentity: id, StartMillis: 10000}
	factSchema, observationSchema, executionSchema := labRecoveryStartedFactSchema, labRecoveryStartObservationSchema, lifecycleRecoveryExecutionSchema
	if absent {
		binding.QuiescenceSHA256, binding.StartMode, binding.AbsenceCleanupSHA256 = "", labRecoveryStartModeOldEpochAbsent, hash
		factSchema, observationSchema, executionSchema = labRecoveryAbsentStartedFactSchema, labRecoveryAbsentStartObservationSchema, lifecycleRecoveryAbsentExecutionSchema
	}
	fact := labRecoveryStartedFact{Schema: factSchema, Binding: binding, ObservedAt: when, StartedSHA256: hash,
		Observation: labRecoveryStartObservation{Schema: observationSchema, PermitConsumed: true, StartInvoked: true, StartReturned: true, StartErrorClass: &class, StartObservation: &start, StartupIdentity: &id, VerifiedIdentity: &id, NamespaceInode: &max, ListenersBefore: &yes, ListenersAfter: &yes, StartedAt: &when, ReturnedAt: &when, Outcome: "STARTED", FailureCode: "NONE"}}
	o := lifecycleOwner{hash, max, when, when, when}
	return &lifecycleRecoveryExecution{Schema: executionSchema, Started: fact, ArmedOwner: o, ArmedLastTrustedAt: when, ArmedLastRecoveryFence: max, ArmedRecoveryUpdatedAt: when, ArmedFailedQuiescence: a.FailedQuiescence, StartedCommitRevision: max, RecordedAt: when}
}
