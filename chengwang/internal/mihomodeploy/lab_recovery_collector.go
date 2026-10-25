package mihomodeploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"chengwang/internal/adapter/mihomo"
)

var errLabRecoveryCollector = errors.New("private recovery observation rejected")

const labRecoveryCaptureStage = "recovery-s2"
const labRecoveryObservationLimit = 32

// This is memory-only custody, issued after actual successful S1 readback.
// It neither reissues the spent Started capability nor survives a reopen.
type labRecoveryStartedCustody struct {
	store     *lifecycleRecoveryStoreCore
	owner     *lifecycleRecoveryOwnerCore
	started   *labRecoveryStartedEpochCore
	canonical string
	binding   func(*labRecoveryStartedCustody, *lifecycleRecoveryStoreCore) bool
}

// Called only with the original store mutex after current disk verification.
func (c *labRecoveryStartedCustody) matches(x *lifecycleRecoveryStoreCore) bool {
	if c == nil || c.binding == nil || !c.binding(c, x) || x == nil || x.closed || x.poisoned || x.retainedStarted != c ||
		x.live != c.owner || x.record.core == nil || string(x.raw) != c.canonical || x.record.core.Recovery == nil {
		return false
	}
	a := x.record.core.Recovery
	return a.Execution != nil && reflect.DeepEqual(a.Execution.Started, c.started.fact) && a.Execution.StartedCommitRevision == x.record.core.Revision &&
		x.record.core.RecoveryOwner != nil && x.record.core.RecoveryOwner.Fence == c.owner.fence && x.record.core.LastRecoveryFence == c.owner.fence
}

type labRecoverySampleWindow struct {
	StartedAt   time.Time `json:"startedAt"`
	CompletedAt time.Time `json:"completedAt"`
}

// Metadata only. This DTO cannot construct a proof or mutate Execution/head.
type labRecoveryObservedValue struct {
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
	SampleTimes        [2]labRecoverySampleWindow     `json:"sampleTimes"`
	ObservedAt         time.Time                      `json:"observedAt"`
	Readback           mihomo.LabTargetReadbackReport `json:"readback"`
	TranscriptSHA256   string                         `json:"transcriptSHA256"`
	BodySHA256s        [8]string                      `json:"bodySHA256s"`
	VerificationSHA256 string                         `json:"verificationSHA256"`
	LocalPath          *labRecoveryLocalMarkerValue   `json:"localPath"`
	LocalMarkerSHA256  string                         `json:"localMarkerSHA256"`
}

type labRecoveryCollector struct {
	artifacts      *ArtifactStore
	diagnostics    *labServiceDiagnostics
	authority      *labRecoveryAuthority
	session        *labRecoverySession
	kernel         *ownedLabKernel
	service        *LabService
	fixtureCustody *labServiceFixtureCustody
}

type labRecoveryObservedEvidence struct {
	core *labRecoveryObservedEvidenceCore
}
type labRecoveryObservedEvidenceCore struct {
	collector *labRecoveryCollector
	custody   *labRecoveryStartedCustody
	value     labRecoveryObservedValue
	binding   func(*labRecoveryObservedEvidenceCore) bool
}

// This finite first-slice issuer never evicts or resets spent source claims,
// including across new collector instances. Exhaustion fails closed. It is
// not a maintenance-free long-lived production registry or durable schema.
type labRecoveryObservationIssuer struct {
	mu      sync.Mutex
	claimed map[*labRecoveryStartedCustody]bool
	issued  map[*labRecoveryObservedEvidenceCore]bool
}

var processLabRecoveryObservationIssuer = labRecoveryObservationIssuer{
	claimed: map[*labRecoveryStartedCustody]bool{}, issued: map[*labRecoveryObservedEvidenceCore]bool{},
}

func (labRecoveryStartedCustody) MarshalJSON() ([]byte, error) { return nil, errLabRecoveryCollector }
func (labRecoveryStartedCustody) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "private recorded Started custody")
}
func (*labRecoveryStartedCustody) UnmarshalJSON([]byte) error { return errLabRecoveryCollector }
func (labRecoveryObservedEvidence) String() string            { return "private one-use recovery observation" }
func (labRecoveryObservedEvidence) GoString() string          { return "private one-use recovery observation" }
func (labRecoveryObservedEvidence) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "private one-use recovery observation")
}
func (labRecoveryObservedEvidence) MarshalJSON() ([]byte, error) { return nil, errLabRecoveryCollector }
func (e *labRecoveryObservedEvidence) UnmarshalJSON([]byte) error {
	if e != nil {
		e.core = nil
	}
	return errLabRecoveryCollector
}

func newLabRecoveryCollector(service *LabService, authority *labRecoveryAuthority, session *labRecoverySession, kernel *ownedLabKernel) (*labRecoveryCollector, error) {
	if service == nil || service.core == nil || authority == nil || session == nil || session.core == nil || kernel == nil || kernel.ownedLabKernelCore == nil {
		return nil, errLabRecoveryCollector
	}
	s := service.core
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fixtureCustody == nil || !s.fixtureCustody.currentLocked(s, authority) || s.artifacts == nil || s.diagnostics == nil || s.diagnostics.core == nil {
		return nil, errLabRecoveryCollector
	}
	return &labRecoveryCollector{artifacts: s.artifacts, diagnostics: s.diagnostics, authority: authority, session: session, kernel: kernel,
		service: service, fixtureCustody: s.fixtureCustody}, nil
}

func labRecoveryObservationDeadline(c *labRecoveryStartedCustody, entry time.Time, ctx context.Context) (time.Time, bool) {
	if c == nil || c.started == nil || artifactContext(ctx) != nil || !lifecycleTime(entry) {
		return time.Time{}, false
	}
	// c.canonical is the immutable, actually verified post-S1 image. Derive all
	// bounds from it, never from a caller's policy or timestamp DTO.
	r, err := decodeLifecycleV3Record([]byte(c.canonical))
	if err != nil || r.core.Recovery == nil || r.core.Recovery.Execution == nil || r.core.Recovery.Approval == nil || r.core.RecoveryOwner == nil {
		return time.Time{}, false
	}
	a := r.core.Recovery
	s := a.Execution.Started
	if s.Observation.ReturnedAt == nil || s.ObservedAt.Before(*s.Observation.ReturnedAt) || a.Execution.RecordedAt.Before(s.ObservedAt) || entry.Before(a.Execution.RecordedAt) {
		return time.Time{}, false
	}
	return labRecoveryWindowDeadline(entry, a.Plan.Budgets.VerificationMillis,
		[4]time.Time{a.Plan.ExpiresAt, a.Approval.ExpiresAt, r.core.RecoveryOwner.ExpiresAt, s.ObservedAt.Add(30 * time.Second)}, ctx)
}

func labRecoveryWindowDeadline(entry time.Time, millis uint32, bounds [4]time.Time, ctx context.Context) (time.Time, bool) {
	if !lifecycleTime(entry) || millis != labRecoveryFixedBudgets().VerificationMillis || artifactContext(ctx) != nil {
		return time.Time{}, false
	}
	deadline := entry.Add(time.Duration(millis) * time.Millisecond)
	for _, bound := range bounds {
		if !lifecycleTime(bound) {
			return time.Time{}, false
		}
		if bound.Before(deadline) {
			deadline = bound
		}
	}
	if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
		deadline = bound.UTC()
	}
	return deadline, entry.Before(deadline)
}

func labRecoveryObservationWindow(times [2]mihomo.LabSampleTimes, entry, observed, deadline time.Time) bool {
	if !lifecycleTime(entry) || !lifecycleTime(observed) || observed.Before(entry) || !observed.Before(deadline) {
		return false
	}
	previous := entry
	for _, sample := range times {
		if !lifecycleTime(sample.StartedAt) || !lifecycleTime(sample.CompletedAt) || sample.StartedAt.Before(previous) || sample.CompletedAt.Before(sample.StartedAt) || sample.CompletedAt.After(observed) {
			return false
		}
		previous = sample.CompletedAt
	}
	return true
}

// currentKernelLocked requires the caller to hold service.mu. It performs no
// service/runtime/store locking, but still proves the live fixture custody and
// exact source-owned kernel/startup identity. It is not a cached liveness bit.
func (c *labRecoveryCollector) currentKernelLocked(service *labServiceCore, source *labRecoveryStartedCustody) bool {
	if c == nil || service == nil || c.service == nil || c.service.core != service || c.fixtureCustody == nil ||
		!c.fixtureCustody.currentLocked(service, c.authority) || source == nil || source.started == nil ||
		source.started.fact.Observation.StartupIdentity == nil || c.kernel == nil || source.started.owner == nil ||
		c.kernel.ownedLabKernelCore != source.started.owner.ownedLabKernelCore {
		return false
	}
	id := *source.started.fact.Observation.StartupIdentity
	return labRecoveryStartedOwnerMatches(c.kernel, source.started.seal, id) && labRecoveryStartedOwnerCurrent(c.kernel, id)
}

func (c *labRecoveryCollector) currentKernel(source *labRecoveryStartedCustody) bool {
	if c == nil || c.service == nil || c.service.core == nil {
		return false
	}
	service := c.service.core
	service.mu.Lock()
	defer service.mu.Unlock()
	return c.currentKernelLocked(service, source)
}

// Cancellation joins the actual service lifetime and caller without extending
// either context's deadline or the already established source window. It does
// not make synchronous proc/fsync IO forcibly interruptible.
func labRecoveryPhaseContext(caller, owner context.Context, deadline time.Time) (context.Context, context.CancelFunc, error) {
	if artifactContext(caller) != nil || artifactContext(owner) != nil {
		return nil, nil, errLabRecoveryCollector
	}
	if bound, ok := owner.Deadline(); ok && bound.Before(deadline) {
		deadline = bound
	}
	phase, cancel := context.WithDeadline(caller, deadline)
	stop := context.AfterFunc(owner, cancel)
	if artifactContext(owner) != nil || artifactContext(phase) != nil {
		stop()
		cancel()
		return nil, nil, errLabRecoveryCollector
	}
	return phase, func() {
		stop()
		cancel()
	}, nil
}

func (c *labRecoveryCollector) collect(ctx context.Context, headers []string) (*labRecoveryObservedEvidence, error) {
	if c == nil || artifactContext(ctx) != nil {
		return nil, errLabRecoveryCollector
	}
	entry := time.Now().UTC()
	guard, err := c.authorizeLocal(headers, nil, entry)
	if err != nil {
		return nil, err
	}
	source := guard.custody
	ownerCtx := guard.service.ctx
	i := &processLabRecoveryObservationIssuer
	i.mu.Lock()
	if i.claimed[source] || len(i.claimed) >= labRecoveryObservationLimit {
		i.mu.Unlock()
		guard.release()
		return nil, errLabRecoveryCollector
	}
	i.claimed[source] = true
	i.mu.Unlock()
	guard.release()
	deadline, ok := labRecoveryObservationDeadline(source, entry, ctx)
	if !ok || !c.currentKernel(source) {
		return nil, errLabRecoveryCollector
	}
	phase, cancel, err := labRecoveryPhaseContext(ctx, ownerCtx, deadline)
	if err != nil {
		return nil, err
	}
	defer cancel()
	fact := source.started.fact
	target := fact.Binding.TargetArtifact
	d, artifact, config, err := labCollectorLoad(phase, c.artifacts, target.RecordSHA256)
	if err != nil || !reflect.DeepEqual(d, target) || artifact == nil || artifact.AdmissionError() != nil || !reflect.DeepEqual(artifact.Descriptor(), d.Config) {
		return nil, errLabRecoveryCollector
	}
	expected, err := labExpectationForArtifact(artifact)
	if err != nil {
		return nil, errLabRecoveryCollector
	}
	reader, err := mihomo.NewLabReadbackClient(d.ControllerPort, config.ControllerSecret, 5*time.Second)
	if err != nil {
		return nil, errLabRecoveryCollector
	}
	samples, evidence, readErr := reader.ReadStableCaptured(phase)
	defer evidence.Release()
	descriptor, descErr := evidence.Descriptor()
	transcript, transcriptErr := evidence.PrivateTranscript()
	var bodies [8][]byte
	var hashes [8]string
	for n := range bodies {
		if raw, err := evidence.PrivateBody(uint8(n + 1)); err == nil {
			bodies[n] = raw
			hashes[n] = labConfigHash(raw)
		}
	}
	// Partial originals remain exclusive diagnostics on failure; no replacement
	// GET or second collector can reset the shared source attempt.
	captureErr := c.diagnostics.capture(labRecoveryCaptureStage, transcript, bodies)
	if readErr != nil || descErr != nil || transcriptErr != nil || captureErr != nil || descriptor.Outcome != "COMPLETE" || descriptor.DoInvocations != 8 || descriptor.CompletedBodies != 8 || descriptor.LimitReached {
		return nil, errLabRecoveryCollector
	}
	report, err := mihomo.CompareLabTargetReadback(samples, expected)
	if err != nil || report.Conclusion != mihomo.LabTargetProjectionMatched || report.SampleCount != 2 || report.RequestsObserved != 8 || report.DataplaneProven || report.AuthorizationProven || report.FullPayloadProven || report.Production {
		return nil, errLabRecoveryCollector
	}
	times, err := samples.SampleTimes()
	observed := time.Now().UTC()
	if err != nil || artifactContext(phase) != nil || !labRecoveryObservationWindow(times, entry, observed, deadline) || !c.currentKernel(source) {
		return nil, errLabRecoveryCollector
	}
	role, err := labCollectorRole(config)
	if err != nil {
		return nil, errLabRecoveryCollector
	}
	local, localErr := c.fixtureCustody.fixture.recoveryRoute(phase, role)
	if local.Schema != "chengwang.mihomo-recovery-local-marker/v1" {
		// No source observation exists: keep the eight original GET captures,
		// but do not manufacture an empty local-marker original.
		return nil, errLabRecoveryCollector
	}
	localRaw, encodeErr := json.Marshal(local)
	localSHA, captureLocalErr := c.diagnostics.localMarker(localRaw)
	markerObserved := time.Now().UTC()
	if localErr != nil || encodeErr != nil || captureLocalErr != nil || local.ExpectedRole != role ||
		!labRecoveryMarkerWindow(local, observed, markerObserved, deadline) || artifactContext(phase) != nil || !c.currentKernel(source) {
		return nil, errLabRecoveryCollector
	}
	// Do not hold the source/authority mutex over private fsync or proc/HTTP IO.
	r, err := decodeLifecycleV3Record([]byte(source.canonical))
	if err != nil {
		return nil, errLabRecoveryCollector
	}
	a := r.core.Recovery
	v := labRecoveryObservedValue{Schema: "chengwang.mihomo-recovery-control-observation/v2", RecoveryID: a.Plan.RecoveryID, PlanSHA256: a.Plan.PlanSHA256,
		StartIntentSHA256: a.StartIntent.IntentSHA256, StartedSHA256: fact.StartedSHA256, SourceRevision: r.core.Revision, SourceRecordSHA256: r.core.RecordSHA256,
		OwnerFence: r.core.RecoveryOwner.Fence, Artifact: cloneArtifactDescriptor(target), StartupIdentity: *fact.Observation.StartupIdentity,
		EntryAt: entry, Deadline: deadline, ObservedAt: observed, Readback: report, TranscriptSHA256: labConfigHash(transcript), BodySHA256s: hashes,
		LocalPath: &local, LocalMarkerSHA256: localSHA}
	for n, sample := range times {
		v.SampleTimes[n] = labRecoverySampleWindow{sample.StartedAt, sample.CompletedAt}
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, errLabRecoveryCollector
	}
	v.VerificationSHA256, err = c.diagnostics.verification(labRecoveryCaptureStage, raw)
	if err != nil || artifactContext(phase) != nil {
		return nil, errLabRecoveryCollector
	}
	finalNow := time.Now().UTC()
	if !labRecoveryObservationWindow(times, entry, finalNow, deadline) || !labRecoveryMarkerWindow(local, observed, finalNow, deadline) || !c.currentKernel(source) {
		return nil, errLabRecoveryCollector
	}
	guard, err = c.authorizeLocal(headers, source, finalNow)
	if err != nil {
		return nil, err
	}
	defer guard.release()
	e := &labRecoveryObservedEvidenceCore{collector: c, custody: source, value: v}
	sealed, err := json.Marshal(v)
	if err != nil {
		return nil, errLabRecoveryCollector
	}
	image := string(sealed)
	e.binding = func(candidate *labRecoveryObservedEvidenceCore) bool {
		if candidate != e || candidate.collector != c || candidate.custody != source {
			return false
		}
		actual, err := json.Marshal(candidate.value)
		return err == nil && string(actual) == image
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	admittedAt := time.Now().UTC()
	if artifactContext(phase) != nil || artifactContext(guard.service.ctx) != nil || admittedAt.Before(finalNow) || !labRecoveryObservationWindow(times, entry, admittedAt, deadline) ||
		!labRecoveryMarkerWindow(local, observed, admittedAt, deadline) ||
		guard.store.trustedNow(admittedAt) != nil || len(i.issued) >= labRecoveryObservationLimit || !i.claimed[source] {
		return nil, errLabRecoveryCollector
	}
	i.issued[e] = true
	return &labRecoveryObservedEvidence{core: e}, nil
}

func (c *labRecoveryCollector) consume(ctx context.Context, headers []string, evidence *labRecoveryObservedEvidence) (labRecoveryObservedValue, error) {
	var zero labRecoveryObservedValue
	if evidence == nil || evidence.core == nil {
		return zero, errLabRecoveryCollector
	}
	e := evidence.core
	i := &processLabRecoveryObservationIssuer
	i.mu.Lock()
	known := i.issued[e]
	delete(i.issued, e) // every known entry is spent before later rejections
	i.mu.Unlock()
	if !known || c == nil || e.collector != c || e.binding == nil || !e.binding(e) || artifactContext(ctx) != nil || !c.currentKernel(e.custody) {
		return zero, errLabRecoveryCollector
	}
	now := time.Now().UTC()
	if e.value.LocalPath == nil || !labRecoveryMarkerWindow(*e.value.LocalPath, e.value.ObservedAt, now, e.value.Deadline) {
		return zero, errLabRecoveryCollector
	}
	guard, err := c.authorizeLocal(headers, e.custody, now)
	if err != nil {
		return zero, err
	}
	defer guard.release()
	value := e.value
	marker := labRecoveryCloneMarker(*value.LocalPath)
	value.LocalPath = &marker
	value.Artifact = cloneArtifactDescriptor(value.Artifact)
	if value.Readback.ObservedProjectionSHA256 != nil {
		digest := *value.Readback.ObservedProjectionSHA256
		value.Readback.ObservedProjectionSHA256 = &digest
	}
	returnedAt := time.Now().UTC()
	if artifactContext(ctx) != nil || artifactContext(guard.service.ctx) != nil || returnedAt.Before(now) ||
		!labRecoveryMarkerWindow(marker, value.ObservedAt, returnedAt, value.Deadline) || guard.store.trustedNow(returnedAt) != nil {
		return zero, errLabRecoveryCollector
	}
	return value, nil
}
