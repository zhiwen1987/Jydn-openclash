package mihomodeploy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"

	"chengwang/internal/adapter/mihomo"
)

const lifecycleRecoveryVerifiedExecutionSchema = "chengwang.mihomo-recovery-execution/v2"
const lifecycleRecoveryVerificationSchema = "chengwang.mihomo-recovery-verification/v1"

// Typed persisted metadata. Arrays in the memory-only observation become
// explicitly bounded nonnil slices; no opaque JSON or private authority is WAL.
type lifecycleRecoveryObservedFact struct {
	Schema             string                         `json:"schema"`
	RecoveryID         string                         `json:"recoveryId"`
	PlanSHA256         string                         `json:"planSHA256"`
	StartIntentSHA256  string                         `json:"startIntentSHA256"`
	StartedSHA256      string                         `json:"startedSHA256"`
	SourceRevision     uint64                         `json:"sourceRevision"`
	SourceRecordSHA256 string                         `json:"sourceRecordSHA256"`
	OwnerFence         uint64                         `json:"ownerFence"`
	Artifact           ArtifactDescriptor             `json:"artifact"`
	StartupIdentity    labKernelIdentity              `json:"startupIdentity"`
	EntryAt            time.Time                      `json:"entryAt"`
	Deadline           time.Time                      `json:"deadline"`
	SampleTimes        []labRecoverySampleWindow      `json:"sampleTimes"`
	ObservedAt         time.Time                      `json:"observedAt"`
	Readback           mihomo.LabTargetReadbackReport `json:"readback"`
	TranscriptSHA256   string                         `json:"transcriptSHA256"`
	BodySHA256s        []string                       `json:"bodySHA256s"`
	VerificationSHA256 string                         `json:"verificationSHA256"`
	LocalPath          *labRecoveryLocalMarkerValue   `json:"localPath"`
	LocalMarkerSHA256  string                         `json:"localMarkerSHA256"`
}

type lifecycleRecoveryVerification struct {
	Schema                     string                        `json:"schema"`
	Observation                lifecycleRecoveryObservedFact `json:"observation"`
	ObservationSHA256          string                        `json:"observationSHA256"`
	SourceOwner                lifecycleOwner                `json:"sourceOwner"`
	SourceLastTrustedAt        time.Time                     `json:"sourceLastTrustedAt"`
	SourceLastRecoveryFence    uint64                        `json:"sourceLastRecoveryFence"`
	SourceRecoveryUpdatedAt    time.Time                     `json:"sourceRecoveryUpdatedAt"`
	SourceFailedQuiescence     []labQuiescenceObservation    `json:"sourceFailedQuiescence"`
	VerificationCommitRevision uint64                        `json:"verificationCommitRevision"`
	RecordedAt                 time.Time                     `json:"recordedAt"`
}

type labRecoveryVerificationRecordCap struct {
	core *labRecoveryVerificationRecordCore
}
type labRecoveryVerificationRecordCore struct {
	collector *labRecoveryCollector
	evidence  *labRecoveryObservedEvidenceCore
	custody   *labRecoveryStartedCustody
	store     *lifecycleRecoveryStoreCore
	disk      lifecycleDisk
	owner     *lifecycleRecoveryOwnerCore
	caller    context.Context
	service   context.Context
	canonical string
	value     lifecycleRecoveryObservedFact
	binding   func(*labRecoveryVerificationRecordCore) bool
}

var processLabRecoveryVerificationIssuer = struct {
	mu     sync.Mutex
	issued map[*labRecoveryVerificationRecordCore]bool
}{issued: map[*labRecoveryVerificationRecordCore]bool{}}

func (labRecoveryVerificationRecordCap) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "private one-use verification record capability")
}
func (labRecoveryVerificationRecordCap) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (c *labRecoveryVerificationRecordCap) UnmarshalJSON([]byte) error {
	if c != nil {
		c.core = nil
	}
	return errLifecycleUnsafe
}

func lifecycleRecoveryObservedFromValue(v labRecoveryObservedValue) lifecycleRecoveryObservedFact {
	marker := v.LocalPath
	if marker != nil {
		copy := labRecoveryCloneMarker(*marker)
		marker = &copy
	}
	readback := v.Readback
	if readback.ObservedProjectionSHA256 != nil {
		hash := *readback.ObservedProjectionSHA256
		readback.ObservedProjectionSHA256 = &hash
	}
	return lifecycleRecoveryObservedFact{v.Schema, v.RecoveryID, v.PlanSHA256, v.StartIntentSHA256, v.StartedSHA256,
		v.SourceRevision, v.SourceRecordSHA256, v.OwnerFence, cloneArtifactDescriptor(v.Artifact), v.StartupIdentity,
		v.EntryAt, v.Deadline, append([]labRecoverySampleWindow{}, v.SampleTimes[:]...), v.ObservedAt, readback,
		v.TranscriptSHA256, append([]string{}, v.BodySHA256s[:]...), v.VerificationSHA256, marker, v.LocalMarkerSHA256}
}

func lifecycleRecoveryObservationHash(v lifecycleRecoveryObservedFact) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", errLifecycleUnsafe
	}
	return labConfigHash(raw), nil
}

// Consumption of the original registered observation is the only issuance
// entrance. No helper accepts a value DTO to mint record authority.
func (c *labRecoveryCollector) consumeForRecord(ctx context.Context, headers []string, evidence *labRecoveryObservedEvidence) (labRecoveryObservedValue, *labRecoveryVerificationRecordCap, error) {
	var zero labRecoveryObservedValue
	value, err := c.consume(ctx, headers, evidence)
	if err != nil {
		return zero, nil, err
	}
	now := time.Now().UTC()
	guard, err := c.authorizeLocal(headers, evidence.core.custody, now)
	if err != nil {
		return zero, nil, err
	}
	defer guard.release()
	source := evidence.core.custody
	fact := lifecycleRecoveryObservedFromValue(value)
	image, err := json.Marshal(fact)
	if err != nil || string(guard.store.raw) != source.canonical || !source.matches(guard.store) {
		return zero, nil, errLabRecoveryCollector
	}
	core := &labRecoveryVerificationRecordCore{collector: c, evidence: evidence.core, custody: source, store: guard.store,
		disk: guard.store.disk, owner: source.owner, caller: ctx, service: guard.service.ctx, canonical: source.canonical, value: fact}
	original, owner, store, sourceImage, sealed := evidence.core, source.owner, guard.store, source.canonical, string(image)
	serviceCtx := guard.service.ctx
	sourceDisk := guard.store.disk
	core.binding = func(candidate *labRecoveryVerificationRecordCore) bool {
		if candidate != core || candidate.collector != c || candidate.evidence != original || candidate.custody != source ||
			candidate.store != store || candidate.owner != owner || candidate.canonical != sourceImage || !labRecoverySameContext(candidate.caller, ctx) || !labRecoverySameContext(candidate.service, serviceCtx) ||
			!lifecycleRecoverySameDisk(candidate.disk, sourceDisk) {
			return false
		}
		actual, err := json.Marshal(candidate.value)
		return err == nil && string(actual) == sealed && source.binding != nil && source.binding(source, store)
	}
	i := &processLabRecoveryVerificationIssuer
	i.mu.Lock()
	defer i.mu.Unlock()
	if !core.binding(core) {
		return zero, nil, errLabRecoveryCollector
	}
	admittedAt := time.Now().UTC()
	if artifactContext(ctx) != nil || artifactContext(guard.service.ctx) != nil || admittedAt.Before(now) ||
		!admittedAt.Before(value.Deadline) || guard.store.trustedNow(admittedAt) != nil || len(i.issued) >= labRecoveryObservationLimit {
		return zero, nil, errLabRecoveryCollector
	}
	i.issued[core] = true
	return value, &labRecoveryVerificationRecordCap{core: core}, nil
}

func lifecycleRecoverySameDisk(a, b lifecycleDisk) bool {
	return a != nil && b != nil && reflect.TypeOf(a) == reflect.TypeOf(b) && reflect.TypeOf(a).Comparable() && a == b
}

func labRecoverySameContext(a, b context.Context) bool {
	return a != nil && b != nil && reflect.TypeOf(a) == reflect.TypeOf(b) && reflect.TypeOf(a).Comparable() && a == b
}

func lifecycleRecoveryObservedValid(v lifecycleRecoveryObservedFact, a lifecycleRecoveryTxn, sourceOwner lifecycleOwner) bool {
	if a.Execution == nil || a.StartIntent == nil || a.Approval == nil || v.Schema != "chengwang.mihomo-recovery-control-observation/v2" ||
		v.RecoveryID != a.Plan.RecoveryID || v.PlanSHA256 != a.Plan.PlanSHA256 || v.StartIntentSHA256 != a.StartIntent.IntentSHA256 ||
		v.StartedSHA256 != a.Execution.Started.StartedSHA256 || v.SourceRevision != a.Execution.StartedCommitRevision || !lifecycleNonzeroHash(v.SourceRecordSHA256) ||
		v.OwnerFence != sourceOwner.Fence || !reflect.DeepEqual(v.Artifact, a.Plan.TargetArtifact) || a.Execution.Started.Observation.StartupIdentity == nil ||
		v.StartupIdentity != *a.Execution.Started.Observation.StartupIdentity || v.SampleTimes == nil || len(v.SampleTimes) != 2 || v.BodySHA256s == nil || len(v.BodySHA256s) != 8 ||
		!lifecycleTime(v.EntryAt) || !lifecycleTime(v.Deadline) || !lifecycleTime(v.ObservedAt) || v.EntryAt.Before(a.Execution.RecordedAt) ||
		v.ObservedAt.Before(v.EntryAt) || !v.ObservedAt.Before(v.Deadline) || v.Deadline.After(v.EntryAt.Add(time.Duration(a.Plan.Budgets.VerificationMillis)*time.Millisecond)) ||
		v.Deadline.After(a.Plan.ExpiresAt) || v.Deadline.After(a.Approval.ExpiresAt) || v.Deadline.After(sourceOwner.ExpiresAt) || v.Deadline.After(a.Execution.Started.ObservedAt.Add(30*time.Second)) {
		return false
	}
	previous := v.EntryAt
	for _, sample := range v.SampleTimes {
		if !lifecycleTime(sample.StartedAt) || !lifecycleTime(sample.CompletedAt) || sample.StartedAt.Before(previous) || sample.CompletedAt.Before(sample.StartedAt) || sample.CompletedAt.After(v.ObservedAt) {
			return false
		}
		previous = sample.CompletedAt
	}
	for _, hash := range v.BodySHA256s {
		if !lifecycleNonzeroHash(hash) {
			return false
		}
	}
	r := v.Readback
	if r.Schema != "chengwang.mihomo-selected-target-readback/v1" || r.Conclusion != mihomo.LabTargetProjectionMatched || r.SampleCount != 2 || r.RequestsObserved != 8 ||
		!lifecycleNonzeroHash(r.TargetProjectionSHA256) || r.ObservedProjectionSHA256 == nil || *r.ObservedProjectionSHA256 != r.TargetProjectionSHA256 ||
		r.DataplaneProven || r.FullPayloadProven || r.AuthorizationProven || r.Production || !lifecycleNonzeroHash(v.TranscriptSHA256) ||
		!lifecycleNonzeroHash(v.VerificationSHA256) || !lifecycleNonzeroHash(v.LocalMarkerSHA256) || v.LocalPath == nil ||
		!labRecoveryMarkerWindow(*v.LocalPath, v.ObservedAt, v.LocalPath.ReturnedAt, v.Deadline) {
		return false
	}
	local, err := json.Marshal(v.LocalPath)
	if err != nil || labConfigHash(local) != v.LocalMarkerSHA256 {
		return false
	}
	verificationSHA := v.VerificationSHA256
	v.VerificationSHA256 = ""
	raw, err := json.Marshal(v)
	return err == nil && labConfigHash(raw) == verificationSHA
}

func lifecycleRecoveryVerificationFieldsValid(a lifecycleRecoveryTxn, at time.Time, revision uint64) bool {
	e := a.Execution
	if e == nil || e.Verification == nil {
		return e == nil || e.Schema == lifecycleRecoveryExecutionSchema
	}
	v := e.Verification
	digest, err := lifecycleRecoveryObservationHash(v.Observation)
	return e.Schema == lifecycleRecoveryVerifiedExecutionSchema && v.Schema == lifecycleRecoveryVerificationSchema && err == nil && digest == v.ObservationSHA256 &&
		lifecycleNonzeroHash(digest) && lifecycleRecoveryObservedValid(v.Observation, a, v.SourceOwner) &&
		v.SourceOwner.Fence == v.SourceLastRecoveryFence && v.SourceLastRecoveryFence == a.StartIntent.OwnerFence &&
		lifecycleTime(v.SourceLastTrustedAt) && lifecycleTime(v.SourceRecoveryUpdatedAt) && v.SourceLastTrustedAt.Equal(e.RecordedAt) && v.SourceRecoveryUpdatedAt.Equal(e.RecordedAt) &&
		v.SourceFailedQuiescence != nil && len(v.SourceFailedQuiescence) <= len(a.FailedQuiescence) && reflect.DeepEqual(v.SourceFailedQuiescence, a.FailedQuiescence[:len(v.SourceFailedQuiescence)]) &&
		v.VerificationCommitRevision > v.Observation.SourceRevision && v.VerificationCommitRevision <= revision && lifecycleTime(v.RecordedAt) &&
		!v.RecordedAt.Before(v.Observation.LocalPath.ReturnedAt) && !v.RecordedAt.After(a.UpdatedAt) && !v.RecordedAt.After(at)
}

// Reconstruct the exact original S1 canonical record. That record then passes
// the old strict v1 decoder and its own original armed-preimage validation.
func lifecycleRecoveryVerificationPreimage(w *lifecycleV3Wire, a lifecycleRecoveryTxn) ([]byte, error) {
	if w == nil || a.Execution == nil || a.Execution.Verification == nil || w.Recovery == nil || !reflect.DeepEqual(*w.Recovery, a) {
		return nil, errLifecycleUnsafe
	}
	v := a.Execution.Verification
	raw, err := json.Marshal(w)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	var source lifecycleV3Wire
	if json.Unmarshal(raw, &source) != nil {
		return nil, errLifecycleUnsafe
	}
	source.Revision, source.RecordSHA256 = v.Observation.SourceRevision, v.Observation.SourceRecordSHA256
	source.LastTrustedAt, source.LastRecoveryFence = v.SourceLastTrustedAt, v.SourceLastRecoveryFence
	owner := v.SourceOwner
	source.RecoveryOwner = &owner
	source.Recovery.Phase = "START_ARMED"
	source.Recovery.Revocation, source.Recovery.Failure = nil, nil
	source.Recovery.UpdatedAt = v.SourceRecoveryUpdatedAt
	source.Recovery.FailedQuiescence = source.Recovery.Execution.Verification.SourceFailedQuiescence
	source.Recovery.Execution.Schema = lifecycleRecoveryExecutionSchema
	source.Recovery.Execution.Verification = nil
	raw, err = json.Marshal(&source)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	decoded, err := decodeLifecycleV3Record(raw)
	if err != nil || decoded.core.Recovery == nil || decoded.core.Recovery.Execution == nil || decoded.core.Recovery.Execution.Schema != lifecycleRecoveryExecutionSchema || decoded.core.Revision != decoded.core.Recovery.Execution.StartedCommitRevision {
		return nil, errLifecycleUnsafe
	}
	return raw, nil
}

type lifecycleVerificationPublication struct {
	base      *lifecycleVerifiedBaseCore
	canonical string
	binding   func(*lifecycleVerificationPublication, *lifecycleRecoveryStoreCore, *lifecycleVerifiedBaseCore) bool
}

func (x *lifecycleRecoveryStoreCore) verificationRecordTransition(base *lifecycleVerifiedBase, next lifecycleV3Record) bool {
	p := x.verificationRecord
	if p == nil || p.binding == nil || base == nil || !p.binding(p, x, base.core) || next.core == nil || x.record.core.Recovery == nil ||
		x.record.core.Recovery.Execution == nil || x.record.core.Recovery.Execution.Schema != lifecycleRecoveryExecutionSchema || x.record.core.Recovery.Execution.Verification != nil ||
		next.core.Recovery == nil || next.core.Recovery.Execution == nil || next.core.Recovery.Execution.Schema != lifecycleRecoveryVerifiedExecutionSchema || next.core.Recovery.Execution.Verification == nil {
		return false
	}
	raw, err := json.Marshal(next.core)
	if err != nil || string(raw) != p.canonical {
		return false
	}
	var projection lifecycleV3Wire
	if json.Unmarshal(raw, &projection) != nil {
		return false
	}
	projection.Recovery.Execution.Schema = lifecycleRecoveryExecutionSchema
	projection.Recovery.Execution.Verification = nil
	return lifecycleV3Transition(x.record.core, &projection)
}

// A record-only operation: no auth/service/runtime lock is taken while the
// actual disk publication/fsync/readback occurs. The cap is a past observed
// fact, never permission to dispatch, complete, replace Current or open API.
func (s *lifecycleRecoveryStore) recordRecoveryVerification(t *lifecycleRecoveryOwnerToken, cap *labRecoveryVerificationRecordCap, now time.Time) error {
	var core *labRecoveryVerificationRecordCore
	if cap != nil {
		core = cap.core
	}
	i := &processLabRecoveryVerificationIssuer
	i.mu.Lock()
	known := core != nil && i.issued[core]
	delete(i.issued, core)
	i.mu.Unlock()
	if !known || core.binding == nil || !core.binding(core) || s == nil || s.core == nil || core.store != s.core ||
		artifactContext(core.caller) != nil || artifactContext(core.service) != nil || !core.collector.fixtureCustody.current(core.collector.service, core.collector.authority) {
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
	if x.token(t, false, now) != nil || x.live != core.owner || x.record.core.RecoveryOwner == nil || !lifecycleRecoverySameDisk(x.disk, core.disk) {
		return errLifecycleUnsafe
	}
	source, err := decodeLifecycleV3Record([]byte(core.canonical))
	if err != nil || source.core.Recovery == nil || source.core.Recovery.Execution == nil || source.core.Recovery.Execution.Schema != lifecycleRecoveryExecutionSchema || source.core.RecoveryOwner == nil {
		return errLifecycleUnsafe
	}
	a := x.record.core.Recovery
	if a == nil || (a.Phase != "START_ARMED" && a.Phase != "RECOVERY_UNKNOWN") || a.Execution == nil || a.Execution.Schema != lifecycleRecoveryExecutionSchema || a.Execution.Verification != nil ||
		!reflect.DeepEqual(a.Execution, source.core.Recovery.Execution) || !reflect.DeepEqual(x.record.core.RecoveryOwner, source.core.RecoveryOwner) ||
		x.record.core.LastRecoveryFence != source.core.LastRecoveryFence || core.value.SourceRevision != source.core.Revision || core.value.SourceRecordSHA256 != source.core.RecordSHA256 {
		return errLifecycleUnsafe
	}
	next, err := base.copyRecord()
	if err != nil || next.core.Revision == ^uint64(0) {
		return errLifecycleUnsafe
	}
	digest, err := lifecycleRecoveryObservationHash(core.value)
	if err != nil {
		return errLifecycleUnsafe
	}
	b := next.core.Recovery
	b.Execution.Schema = lifecycleRecoveryVerifiedExecutionSchema
	b.Execution.Verification = &lifecycleRecoveryVerification{Schema: lifecycleRecoveryVerificationSchema, Observation: core.value, ObservationSHA256: digest,
		SourceOwner: *source.core.RecoveryOwner, SourceLastTrustedAt: source.core.LastTrustedAt, SourceLastRecoveryFence: source.core.LastRecoveryFence,
		SourceRecoveryUpdatedAt: source.core.Recovery.UpdatedAt, SourceFailedQuiescence: source.core.Recovery.FailedQuiescence,
		VerificationCommitRevision: next.core.Revision + 1, RecordedAt: now}
	b.UpdatedAt = now
	preimage, err := lifecycleRecoveryVerificationPreimage(next.core, *b)
	if err != nil || !bytes.Equal(preimage, []byte(core.canonical)) {
		return errLifecycleUnsafe
	}
	actualNow := time.Now().UTC()
	if artifactContext(core.caller) != nil || artifactContext(core.service) != nil || now.After(actualNow) || now.Before(core.value.LocalPath.ReturnedAt) {
		return errLifecycleUnsafe
	}
	fresh := a.Phase == "START_ARMED" && a.Revocation == nil && a.Failure == nil && a.Approval != nil && actualNow.Before(a.Approval.ExpiresAt) && actualNow.Before(a.Plan.ExpiresAt) &&
		actualNow.Before(x.record.core.RecoveryOwner.ExpiresAt) && actualNow.Before(core.value.Deadline)
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
	proof := &lifecycleVerificationPublication{base: base.core, canonical: string(canonical)}
	x.verificationRecord = proof
	defer func() { x.verificationRecord = nil }()
	image := proof.canonical
	proof.binding = func(candidate *lifecycleVerificationPublication, owner *lifecycleRecoveryStoreCore, original *lifecycleVerifiedBaseCore) bool {
		return candidate == proof && owner == x && original == base.core && candidate.base == original && candidate.canonical == image
	}
	if err := x.commitWithBase(base, next, now); err != nil {
		// No later authorization or re-collection retries even a definite
		// NotCommitted attempt through this consumed source record capability.
		x.poisoned = true
		x.live = nil
		x.retainedStarted = nil
		x.validated = nil
		return err
	}
	x.retainedStarted = nil
	return nil
}

// A size-only envelope used before Stop/Start, never an issued observation or
// serialized fact. Both active and archived copies include the full typed S2
// descriptor, sample/body digests, three response hashes and bounded counters.
func lifecycleRecoveryVerificationReserve(a *lifecycleRecoveryTxn) *lifecycleRecoveryVerification {
	hash := strings.Repeat("f", 64)
	max := ^uint64(0)
	maxInt := int(^uint(0) >> 1)
	when := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	role := "B"
	readback := mihomo.LabTargetReadbackReport{Schema: "chengwang.mihomo-selected-target-readback/v1", Conclusion: mihomo.LabTargetProjectionMatched,
		SampleCount: 2, RequestsObserved: 8, TargetProjectionSHA256: hash, ObservedProjectionSHA256: &hash}
	body := labLocalBody{hash, 4096, true}
	counters := []labLocalCounter{}
	for _, name := range []string{"A", "B", "origin"} {
		counters = append(counters, labLocalCounter{name, maxInt, maxInt, maxInt, maxInt, maxInt})
	}
	local := &labRecoveryLocalMarkerValue{Schema: "chengwang.mihomo-recovery-local-marker/v1", Scope: labRecoveryLocalScope,
		ExpectedRole: role, ExpectedMarkerSHA256: hash, ExpectedMarkerBytes: 4096, StartedAt: when, ReturnedAt: when,
		HandlerCompleted: true, ClientNaturalEOF: true, ProxyNaturalEOF: true, OriginWriteComplete: true, LocalProxyMarkerProven: true,
		Route: labLocalRoute{labRecoveryLocalPhase, hash, &body, &body, &body, counters, counters, true}}
	id := a.Execution.Started.Observation.StartupIdentity
	observation := lifecycleRecoveryObservedFact{Schema: "chengwang.mihomo-recovery-control-observation/v2", RecoveryID: a.Plan.RecoveryID,
		PlanSHA256: hash, StartIntentSHA256: hash, StartedSHA256: hash, SourceRevision: max, SourceRecordSHA256: hash, OwnerFence: max,
		Artifact: cloneArtifactDescriptor(a.Plan.TargetArtifact), StartupIdentity: *id, EntryAt: when, Deadline: when,
		SampleTimes: []labRecoverySampleWindow{{when, when}, {when, when}}, ObservedAt: when, Readback: readback, TranscriptSHA256: hash,
		BodySHA256s: []string{hash, hash, hash, hash, hash, hash, hash, hash}, VerificationSHA256: hash, LocalPath: local, LocalMarkerSHA256: hash}
	return &lifecycleRecoveryVerification{Schema: lifecycleRecoveryVerificationSchema, Observation: observation, ObservationSHA256: hash,
		SourceOwner: lifecycleOwner{hash, max, when, when, when}, SourceLastTrustedAt: when, SourceLastRecoveryFence: max,
		SourceRecoveryUpdatedAt: when, SourceFailedQuiescence: a.FailedQuiescence, VerificationCommitRevision: max, RecordedAt: when}
}
