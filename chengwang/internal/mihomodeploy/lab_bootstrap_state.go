package mihomodeploy

import (
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"chengwang/internal/adapter/mihomo"
)

const lifecycleCompletedPhase = "ACKNOWLEDGED_SUPPORTED_POSTCONDITION"
const lifecycleCompletedConclusion = "STABLE_NEW_PROJECTION_AND_LOCAL_ROUTE"
const lifecycleObservationConclusion = "CURRENT_SUPPORTED_POSTCONDITION_OBSERVED"
const maxLifecycleHistory = 256

type lifecycleProvisioning struct {
	Schema       string `json:"schema"`
	RuntimeID    string `json:"runtimeID"`
	MarkerSHA256 string `json:"markerSHA256"`
}
type lifecycleCompletion struct {
	PreviousHead   lifecycleHead   `json:"previousHead"`
	Head           lifecycleHead   `json:"head"`
	Active         lifecycleActive `json:"active"`
	Owner          lifecycleOwner  `json:"owner"`
	CommitRevision uint64          `json:"commitRevision"`
	CommittedAt    time.Time       `json:"committedAt"`
}
type lifecycleObservationRecord struct {
	OperationID    string            `json:"operationId"`
	PlanSHA256     string            `json:"planSHA256"`
	IntentSHA256   string            `json:"intentSHA256"`
	Readback       lifecycleReadback `json:"readback"`
	CommitRevision uint64            `json:"commitRevision"`
}
type lifecycleTerminalArchive struct {
	Head           lifecycleHead   `json:"head"`
	Active         lifecycleActive `json:"active"`
	Owner          lifecycleOwner  `json:"owner"`
	CommitRevision uint64          `json:"commitRevision"`
	CommittedAt    time.Time       `json:"committedAt"`
}
type lifecycleV2Wire struct {
	Provisioning lifecycleProvisioning        `json:"provisioning"`
	Completed    []lifecycleCompletion        `json:"completed"`
	Observations []lifecycleObservationRecord `json:"observations"`
	Terminated   []lifecycleTerminalArchive   `json:"terminated"`
}

type lifecycleEvidenceTransition uint8

const (
	lifecycleNoNewEvidence lifecycleEvidenceTransition = iota
	lifecycleAppendCompletion
	lifecycleAppendObservation
	lifecycleAppendTermination
)

func lifecycleReadbackValid(r *lifecycleReadback, conclusion string, now time.Time) bool {
	return r != nil && r.Conclusion == conclusion && lifecycleNonzeroHash(r.EvidenceSHA256) && lifecycleTime(r.ObservedAt) && !r.ObservedAt.After(now)
}
func lifecycleGateReason(s string) bool {
	return s == "FINAL_AUTHORIZATION_REJECTED" || s == "OWNED_IDENTITY_REJECTED" || s == "SERVICE_CONTEXT_CANCELLED"
}
func lifecycleResultSourceValid(schema string, a *lifecycleActive) bool {
	if a == nil || a.Result == nil {
		return false
	}
	r := a.Result
	if schema == lifecycleSchema {
		return r.Origin == "" && r.ServiceGate == nil
	}
	if schema != lifecycleSchemaV2 {
		return false
	}
	if r.Origin == "ADAPTER" {
		return r.ServiceGate == nil
	}
	g := r.ServiceGate
	return r.Origin == "SERVICE_GATE" && g != nil && a.Intent != nil &&
		g.OperationID == a.Plan.OperationID && g.PlanSHA256 == a.Plan.PlanSHA256 && g.IntentSHA256 == a.Intent.IntentSHA256 &&
		lifecycleGateReason(g.Reason) && lifecycleTime(g.ObservedAt) && !g.ObservedAt.Before(a.Intent.ArmedAt) && g.ObservedAt.Equal(r.ObservedAt) &&
		r.Reload.State == mihomo.ReloadRejected && !r.Reload.Dispatched && r.Reload.StatusCode == 0
}

func lifecycleV2Transition(old, next *lifecycleWire, mode lifecycleEvidenceTransition) bool {
	if old == nil || next == nil || next.Schema != old.Schema {
		return false
	}
	if old.Schema == lifecycleSchema {
		return mode == lifecycleNoNewEvidence && old.V2 == nil && next.V2 == nil && reflect.DeepEqual(old.Head, next.Head)
	}
	if old.Schema != lifecycleSchemaV2 || old.V2 == nil || next.V2 == nil || !reflect.DeepEqual(old.V2.Provisioning, next.V2.Provisioning) {
		return false
	}
	a, b := old.V2, next.V2
	if len(b.Completed) < len(a.Completed) || len(b.Observations) < len(a.Observations) || len(b.Terminated) < len(a.Terminated) ||
		!reflect.DeepEqual(b.Completed[:len(a.Completed)], a.Completed) || !reflect.DeepEqual(b.Observations[:len(a.Observations)], a.Observations) || !reflect.DeepEqual(b.Terminated[:len(a.Terminated)], a.Terminated) {
		return false
	}
	if mode != lifecycleAppendTermination && len(b.Terminated) != len(a.Terminated) {
		return false
	}
	switch mode {
	case lifecycleNoNewEvidence:
		return reflect.DeepEqual(old.Head, next.Head) && len(a.Completed) == len(b.Completed) && len(a.Observations) == len(b.Observations)
	case lifecycleAppendObservation:
		return reflect.DeepEqual(old.Head, next.Head) && len(a.Completed) == len(b.Completed) && len(b.Observations) == len(a.Observations)+1 &&
			old.Active != nil && next.Active != nil && old.Active.Phase == "UNKNOWN" && reflect.DeepEqual(old.Active, next.Active) && b.Observations[len(b.Observations)-1].CommitRevision == old.Revision+1
	case lifecycleAppendCompletion:
		if old.Head == nil || next.Head == nil || old.Owner == nil || old.Active == nil || next.Active == nil || old.Active.Phase != "ACKNOWLEDGED" ||
			next.Active.Phase != lifecycleCompletedPhase || len(b.Completed) != len(a.Completed)+1 || len(b.Observations) != len(a.Observations) {
			return false
		}
		v := b.Completed[len(b.Completed)-1]
		return reflect.DeepEqual(v.PreviousHead, *old.Head) && reflect.DeepEqual(v.Head, *next.Head) && reflect.DeepEqual(v.Owner, *old.Owner) &&
			reflect.DeepEqual(v.Active, *next.Active) && v.CommitRevision == old.Revision+1
	case lifecycleAppendTermination:
		if old.Head == nil || old.Owner == nil || old.Active == nil || next.Active == nil || lifecycleTerminal(old.Active.Phase) ||
			(next.Active.Phase != "REVOKED" && next.Active.Phase != "UNSENT_REJECTED") || len(b.Terminated) != len(a.Terminated)+1 || len(b.Completed) != len(a.Completed) || len(b.Observations) != len(a.Observations) || !reflect.DeepEqual(old.Head, next.Head) {
			return false
		}
		v := b.Terminated[len(b.Terminated)-1]
		return reflect.DeepEqual(v.Head, *old.Head) && reflect.DeepEqual(v.Owner, *old.Owner) && reflect.DeepEqual(v.Active, *next.Active) && v.CommitRevision == old.Revision+1
	default:
		return false
	}
}

// Validate archived operations with the unchanged v1 structural rules, after
// projecting only their old-head/ACK state. This does not mint a collector or
// current authority: the real v2 archive also binds exact new-head/readback.
func lifecycleArchiveValid(c lifecycleCompletion) bool {
	a := c.Active
	if a.Phase != lifecycleCompletedPhase || a.Result == nil || a.Result.Origin != "ADAPTER" || a.Result.ServiceGate != nil ||
		!lifecycleReadbackValid(a.Readback, lifecycleCompletedConclusion, c.CommittedAt) || a.Readback.ObservedAt.Before(a.Result.ObservedAt) ||
		!lifecycleTime(c.CommittedAt) || c.CommitRevision < 2 || !c.Head.VerifiedAt.Equal(a.Readback.ObservedAt) ||
		c.Head.VerificationSHA256 != a.Readback.EvidenceSHA256 || c.PreviousHead.Generation >= ^uint64(0)-1 ||
		c.Head.Generation != c.PreviousHead.Generation+1 || c.Head.PreviousHeadSHA256 == nil || *c.Head.PreviousHeadSHA256 != c.PreviousHead.HeadSHA256 ||
		c.Head.DeviceRef != c.PreviousHead.DeviceRef || c.Head.Scope != c.PreviousHead.Scope || c.Head.KernelSHA256 != c.PreviousHead.KernelSHA256 ||
		c.Head.PID != c.PreviousHead.PID || c.Head.StartTicks != c.PreviousHead.StartTicks || c.Head.NetNSInode != c.PreviousHead.NetNSInode ||
		c.Head.ControllerPort != c.PreviousHead.ControllerPort || c.Head.MixedPort != c.PreviousHead.MixedPort || !reflect.DeepEqual(c.Head.Artifact, a.Plan.Artifact) {
		return false
	}
	r := *a.Result
	r.Origin = ""
	r.ServiceGate = nil
	a.Result = &r
	a.Phase = "ACKNOWLEDGED"
	a.Readback = nil
	w := &lifecycleWire{Schema: lifecycleSchema, Boundary: lifecycleBoundary, Revision: c.CommitRevision, LastTrustedAt: c.CommittedAt,
		LastFence: c.Owner.Fence, Head: &c.PreviousHead, Owner: &c.Owner, Active: &a, Tombstones: []lifecycleTombstone{}}
	w.RecordSHA256, _ = lifecycleRecordHash(*w)
	if validateLifecycleRecord(lifecycleRecord{wire: w}) != nil {
		return false
	}
	w.Head = &c.Head
	w.Active = nil
	w.RecordSHA256, _ = lifecycleRecordHash(*w)
	return validateLifecycleRecord(lifecycleRecord{wire: w}) == nil
}

func validateLifecycleV2(w *lifecycleWire) error {
	if w == nil {
		return errLifecycleUnsafe
	}
	if w.Schema == lifecycleSchema {
		if w.V2 != nil {
			return errLifecycleUnsafe
		}
		return nil
	}
	v := w.V2
	if w.Schema != lifecycleSchemaV2 || v == nil || w.Head == nil || v.Provisioning.Schema != "chengwang.mihomo-lab-provision-binding/v1" ||
		!lifecycleNonzeroHash(v.Provisioning.RuntimeID) || !lifecycleNonzeroHash(v.Provisioning.MarkerSHA256) ||
		v.Completed == nil || v.Observations == nil || v.Terminated == nil || len(v.Completed)+len(v.Terminated) > maxLifecycleHistory || len(v.Observations) > maxLifecycleHistory {
		return errLifecycleUnsafe
	}
	if len(v.Completed) == 0 {
		if w.Head.Generation != 1 || w.Head.PreviousHeadSHA256 != nil {
			return errLifecycleUnsafe
		}
	} else {
		var previousRevision uint64
		var previousAt time.Time
		var previousFence uint64
		for i, c := range v.Completed {
			if !lifecycleArchiveValid(c) || c.CommitRevision <= previousRevision || c.CommitRevision > w.Revision || c.CommittedAt.After(w.LastTrustedAt) ||
				(i == 0 && (c.PreviousHead.Generation != 1 || c.PreviousHead.PreviousHeadSHA256 != nil)) ||
				(i > 0 && (!reflect.DeepEqual(c.PreviousHead, v.Completed[i-1].Head) || c.CommittedAt.Before(previousAt) || c.Owner.Fence < previousFence)) {
				return errLifecycleUnsafe
			}
			found := false
			for _, t := range w.Tombstones {
				if t.OperationID == c.Active.Plan.OperationID && t.PlanSHA256 == c.Active.Plan.PlanSHA256 && t.Phase == lifecycleCompletedPhase &&
					t.Attempt == 1 && t.IntentSHA256 != nil && c.Active.Intent != nil && *t.IntentSHA256 == c.Active.Intent.IntentSHA256 && t.TerminalRevision == c.CommitRevision {
					found = true
				}
			}
			if !found {
				return errLifecycleUnsafe
			}
			previousRevision, previousAt, previousFence = c.CommitRevision, c.CommittedAt, c.Owner.Fence
		}
		last := v.Completed[len(v.Completed)-1]
		if !reflect.DeepEqual(*w.Head, last.Head) || w.LastFence < last.Owner.Fence {
			return errLifecycleUnsafe
		}
		if w.Active != nil && w.Active.Phase == lifecycleCompletedPhase && !reflect.DeepEqual(*w.Active, last.Active) {
			return errLifecycleUnsafe
		}
		if w.Active != nil && w.Active.Phase == lifecycleCompletedPhase && len(v.Terminated) > 0 && v.Terminated[len(v.Terminated)-1].CommitRevision > last.CommitRevision {
			return errLifecycleUnsafe
		}
	}
	for _, t := range w.Tombstones {
		if t.Phase == lifecycleCompletedPhase {
			found := false
			for _, c := range v.Completed {
				if c.Active.Plan.PlanSHA256 == t.PlanSHA256 && c.Active.Plan.OperationID == t.OperationID {
					found = true
				}
			}
			if !found {
				return errLifecycleUnsafe
			}
		}
		if t.Phase == "REVOKED" || t.Phase == "UNSENT_REJECTED" {
			found := false
			for _, a := range v.Terminated {
				if a.Active.Plan.OperationID == t.OperationID && a.Active.Plan.PlanSHA256 == t.PlanSHA256 && a.Active.Phase == t.Phase && a.CommitRevision == t.TerminalRevision {
					found = true
				}
			}
			if !found {
				return errLifecycleUnsafe
			}
		}
	}
	if err := validateLifecycleTerminated(w); err != nil {
		return err
	}
	var previousRevision uint64
	var previousAt time.Time
	for _, o := range v.Observations {
		a := w.Active
		if a == nil || a.Phase != "UNKNOWN" || a.Intent == nil || o.OperationID != a.Plan.OperationID || o.PlanSHA256 != a.Plan.PlanSHA256 || o.IntentSHA256 != a.Intent.IntentSHA256 ||
			!lifecycleReadbackValid(&o.Readback, lifecycleObservationConclusion, w.LastTrustedAt) || o.Readback.ObservedAt.Before(a.Intent.ArmedAt) ||
			(a.Result != nil && o.Readback.ObservedAt.Before(a.Result.ObservedAt)) || o.CommitRevision <= previousRevision || o.CommitRevision > w.Revision || o.Readback.ObservedAt.Before(previousAt) {
			return errLifecycleUnsafe
		}
		previousRevision, previousAt = o.CommitRevision, o.Readback.ObservedAt
	}
	return nil
}

func lifecycleObservationMatches(o labObservedLifecycle, h *lifecycleHead, a *lifecycleActive, now time.Time) bool {
	i := o.StartupIdentity
	return h != nil && a != nil && a.Intent != nil && o.Scope == h.Scope && o.DeviceRef == h.DeviceRef && o.OperationID == a.Plan.OperationID && o.PlanSHA256 == a.Plan.PlanSHA256 && o.IntentSHA256 == a.Intent.IntentSHA256 &&
		lifecycleArtifactDescriptorValid(o.Artifact) && reflect.DeepEqual(o.Artifact, a.Plan.Artifact) && i.PID == h.PID && i.StartTicks == h.StartTicks && i.NetNSInode == h.NetNSInode && i.ELFSHA256 == h.KernelSHA256 &&
		i.ControllerPort == h.ControllerPort && i.MixedPort == h.MixedPort && o.Artifact.ControllerPort == h.ControllerPort && o.Artifact.MixedPort == h.MixedPort &&
		lifecycleNonzeroHash(o.VerificationSHA256) && lifecycleTime(o.ObservedAt) && !o.ObservedAt.After(now) && !o.ObservedAt.Before(a.Intent.ArmedAt) &&
		(a.Result == nil || !o.ObservedAt.Before(a.Result.ObservedAt))
}

func (s *lifecycleStore) recordAcknowledgedCompletion(t *lifecycleOwnerToken, e *labObservedEvidence, now time.Time) error {
	if s == nil || s.lifecycleStoreCore == nil || s.mu == nil {
		return errLifecycleUnsafe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.verify(); err != nil {
		return err
	}
	if err := s.token(t, false, now); err != nil {
		return err
	}
	w := s.record.wire
	a := w.Active
	if w.Schema != lifecycleSchemaV2 || a == nil || a.Phase != "ACKNOWLEDGED" || a.Result == nil || a.Result.Reload.State != mihomo.ReloadAcknowledged ||
		len(w.V2.Completed)+len(w.V2.Terminated) >= maxLifecycleHistory || len(w.Tombstones) >= maxLifecycleTombstones || w.Head.Generation >= ^uint64(0)-1 || e == nil {
		return errLifecycleUnsafe
	}
	o, err := e.consumeLifecycle("ACKNOWLEDGED_COMPLETION", now)
	if err != nil || o.Phase != "ACKNOWLEDGED_COMPLETION" || !lifecycleObservationMatches(o, w.Head, a, now) {
		return errLifecycleUnsafe
	}
	next, err := s.copyRecord()
	if err != nil {
		return err
	}
	previous := *next.wire.Head
	head := previous
	head.Generation++
	head.Artifact = cloneArtifactDescriptor(o.Artifact)
	prior := previous.HeadSHA256
	head.PreviousHeadSHA256 = &prior
	head.VerificationSHA256 = o.VerificationSHA256
	head.VerifiedAt = o.ObservedAt
	head.HeadSHA256, err = lifecycleHeadHash(head)
	if err != nil {
		return err
	}
	next.wire.Head = &head
	n := next.wire.Active
	n.Phase = lifecycleCompletedPhase
	n.Readback = &lifecycleReadback{Conclusion: lifecycleCompletedConclusion, EvidenceSHA256: o.VerificationSHA256, ObservedAt: o.ObservedAt}
	next.wire.V2.Completed = append(next.wire.V2.Completed, lifecycleCompletion{PreviousHead: previous, Head: head, Active: *n, Owner: *next.wire.Owner, CommitRevision: w.Revision + 1, CommittedAt: now})
	if err := lifecycleAddTombstone(&next); err != nil {
		return err
	}
	return s.commitTransition(next, now, lifecycleAppendCompletion)
}

func (s *lifecycleStore) recordUnknownObservation(t *lifecycleOwnerToken, e *labObservedEvidence, now time.Time) error {
	if s == nil || s.lifecycleStoreCore == nil || s.mu == nil {
		return errLifecycleUnsafe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.verify(); err != nil {
		return err
	}
	if err := s.token(t, false, now); err != nil {
		return err
	}
	w := s.record.wire
	if w.Schema != lifecycleSchemaV2 || w.Active == nil || w.Active.Phase != "UNKNOWN" || len(w.V2.Observations) >= maxLifecycleHistory || e == nil {
		return errLifecycleUnsafe
	}
	// A recovered current epoch shares the full V3 observation budget with all
	// retired ledgers and recovery failed-quiescence facts. Reject before the
	// one-use evidence is consumed.
	if s.currentEpoch != nil {
		if err := s.currentEpochObservationCapacity(now); err != nil {
			return err
		}
	}
	o, err := e.consumeLifecycle("UNKNOWN_OBSERVATION", now)
	if err != nil || o.Phase != "UNKNOWN_OBSERVATION" || !lifecycleObservationMatches(o, w.Head, w.Active, now) {
		return errLifecycleUnsafe
	}
	next, err := s.copyRecord()
	if err != nil {
		return err
	}
	next.wire.V2.Observations = append(next.wire.V2.Observations, lifecycleObservationRecord{OperationID: o.OperationID, PlanSHA256: o.PlanSHA256, IntentSHA256: o.IntentSHA256,
		Readback: lifecycleReadback{Conclusion: lifecycleObservationConclusion, EvidenceSHA256: o.VerificationSHA256, ObservedAt: o.ObservedAt}, CommitRevision: w.Revision + 1})
	return s.commitTransition(next, now, lifecycleAppendObservation)
}

func (s *lifecycleStore) recordServiceGate(t *lifecycleOwnerToken, intentSHA string, e *labServiceGateEvidence, now time.Time) error {
	if s == nil || s.lifecycleStoreCore == nil || s.mu == nil {
		return errLifecycleUnsafe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.verify(); err != nil {
		return err
	}
	if err := s.token(t, false, now); err != nil {
		return err
	}
	w := s.record.wire
	a := w.Active
	if w.Schema != lifecycleSchemaV2 || a == nil || a.Phase != "DISPATCH_ARMED" || a.Attempt != 1 || a.Intent == nil || a.Intent.IntentSHA256 != intentSHA || a.Result != nil || e == nil {
		return errLifecycleUnsafe
	}
	f, err := e.consumeServiceGate(intentSHA, now)
	if err != nil || f.OperationID != a.Plan.OperationID || f.PlanSHA256 != a.Plan.PlanSHA256 || f.IntentSHA256 != intentSHA || !lifecycleGateReason(f.Reason) ||
		!lifecycleTime(f.ObservedAt) || f.ObservedAt.Before(a.Intent.ArmedAt) || f.ObservedAt.After(now) {
		return errLifecycleUnsafe
	}
	next, err := s.copyRecord()
	if err != nil {
		return err
	}
	n := next.wire.Active
	n.Result = &lifecycleResult{Reload: mihomo.ReloadResult{State: mihomo.ReloadRejected, Dispatched: false, StatusCode: 0}, ObservedAt: f.ObservedAt, Origin: "SERVICE_GATE", ServiceGate: &f}
	n.Phase = "UNSENT_REJECTED"
	lifecycleAppendAudit(n, "RESULT_RECORDED")
	if err := lifecycleAddTombstone(&next); err != nil {
		return err
	}
	if err := lifecycleAppendTerminalArchive(&next, now); err != nil {
		return err
	}
	return s.commitTransition(next, now, lifecycleAppendTermination)
}

// Reserve a conservative encoded upper bound before arming, not a fictional
// persisted result/evidence. The exact current plan/head payload is counted;
// 64KiB additionally bounds all fixed-size future intent/result/gate/revoke/
// audit/readback/digest/time metadata. No other operation can append a history
// entry while this active attempt is armed. Full archives are never deleted.
func (s *lifecycleStore) reserveLifecycleResultCapacity(now time.Time) error {
	if s == nil || s.lifecycleStoreCore == nil || s.record.wire == nil {
		return errLifecycleUnsafe
	}
	if s.currentEpoch != nil {
		return s.reserveCurrentEpochCapacity(now)
	}
	return lifecycleReserveCapacity(s.record.wire, len(s.raw), now)
}
func lifecycleReserveCapacity(w *lifecycleWire, rawBytes int, now time.Time) error {
	if w == nil || rawBytes < 0 || rawBytes > maxLifecycleControlBytes {
		return errLifecycleUnsafe
	}
	if w.Schema == lifecycleSchema {
		return nil
	}
	if w.V2 == nil || w.Active == nil || w.Owner == nil || w.Head == nil || len(w.V2.Completed)+len(w.V2.Terminated) >= maxLifecycleHistory || len(w.Tombstones) >= maxLifecycleTombstones ||
		w.Head.Generation >= ^uint64(0)-1 || w.Revision > ^uint64(0)-4 {
		return errLifecycleUnsafe
	}
	head := *w.Head
	head.Artifact = cloneArtifactDescriptor(w.Active.Plan.Artifact)
	head.VerificationSHA256 = strings.Repeat("f", 64)
	head.VerifiedAt = now
	entry, err := json.Marshal(lifecycleCompletion{PreviousHead: *w.Head, Head: head, Active: *w.Active, Owner: *w.Owner, CommitRevision: w.Revision + 4, CommittedAt: now})
	if err != nil || rawBytes > maxLifecycleControlBytes-len(entry)-(64<<10) {
		return errLifecycleUnsafe
	}
	return nil
}

func lifecycleAppendTerminalArchive(r *lifecycleRecord, now time.Time) error {
	if r == nil || r.wire == nil || r.wire.Schema != lifecycleSchemaV2 || r.wire.V2 == nil || r.wire.Active == nil || r.wire.Head == nil || r.wire.Owner == nil ||
		(r.wire.Active.Phase != "REVOKED" && r.wire.Active.Phase != "UNSENT_REJECTED") || !lifecycleTime(now) || len(r.wire.V2.Completed)+len(r.wire.V2.Terminated) >= maxLifecycleHistory {
		return errLifecycleUnsafe
	}
	r.wire.V2.Terminated = append(r.wire.V2.Terminated, lifecycleTerminalArchive{Head: *r.wire.Head, Active: *r.wire.Active, Owner: *r.wire.Owner, CommitRevision: r.wire.Revision + 1, CommittedAt: now})
	return nil
}

func validateLifecycleTerminated(w *lifecycleWire) error {
	var previousRevision uint64
	var previousAt time.Time
	for _, entry := range w.V2.Terminated {
		a := entry.Active
		if (a.Phase != "REVOKED" && a.Phase != "UNSENT_REJECTED") || entry.CommitRevision <= previousRevision || entry.CommitRevision > w.Revision || !lifecycleTime(entry.CommittedAt) || entry.CommittedAt.After(w.LastTrustedAt) || entry.CommittedAt.Before(previousAt) || entry.Owner.Fence > w.LastFence {
			return errLifecycleUnsafe
		}
		expected := w.Head
		if len(w.V2.Completed) > 0 {
			expected = &w.V2.Completed[0].PreviousHead
			for i := range w.V2.Completed {
				c := &w.V2.Completed[i]
				if c.CommitRevision == entry.CommitRevision || (c.CommitRevision < entry.CommitRevision && c.CommittedAt.After(entry.CommittedAt)) || (c.CommitRevision > entry.CommitRevision && c.CommittedAt.Before(entry.CommittedAt)) {
					return errLifecycleUnsafe
				}
				if c.CommitRevision < entry.CommitRevision {
					expected = &c.Head
				}
			}
		}
		if !reflect.DeepEqual(entry.Head, *expected) {
			return errLifecycleUnsafe
		}
		found := false
		for _, t := range w.Tombstones {
			if t.OperationID == a.Plan.OperationID && t.PlanSHA256 == a.Plan.PlanSHA256 && t.Phase == a.Phase && t.TerminalRevision == entry.CommitRevision && t.Attempt == a.Attempt &&
				((a.Intent == nil && t.IntentSHA256 == nil) || (a.Intent != nil && t.IntentSHA256 != nil && a.Intent.IntentSHA256 == *t.IntentSHA256)) {
				found = true
			}
		}
		if !found {
			return errLifecycleUnsafe
		}
		if a.Result != nil {
			if !lifecycleResultSourceValid(lifecycleSchemaV2, &a) {
				return errLifecycleUnsafe
			}
			copyResult := *a.Result
			copyResult.Origin = ""
			copyResult.ServiceGate = nil
			a.Result = &copyResult
		}
		tombstone := lifecycleTombstone{OperationID: a.Plan.OperationID, PlanSHA256: a.Plan.PlanSHA256, Attempt: a.Attempt, Phase: a.Phase, TerminalRevision: entry.CommitRevision}
		if a.Intent != nil {
			value := a.Intent.IntentSHA256
			tombstone.IntentSHA256 = &value
		}
		test := &lifecycleWire{Schema: lifecycleSchema, Boundary: lifecycleBoundary, Revision: entry.CommitRevision, LastTrustedAt: entry.CommittedAt, LastFence: entry.Owner.Fence, Head: &entry.Head, Owner: &entry.Owner, Active: &a, Tombstones: []lifecycleTombstone{tombstone}}
		test.RecordSHA256, _ = lifecycleRecordHash(*test)
		if validateLifecycleRecord(lifecycleRecord{wire: test}) != nil {
			return errLifecycleUnsafe
		}
		previousRevision, previousAt = entry.CommitRevision, entry.CommittedAt
	}
	if w.Active != nil && (w.Active.Phase == "REVOKED" || w.Active.Phase == "UNSENT_REJECTED") {
		if len(w.V2.Terminated) == 0 || !reflect.DeepEqual(w.V2.Terminated[len(w.V2.Terminated)-1].Active, *w.Active) {
			return errLifecycleUnsafe
		}
	}
	return nil
}
