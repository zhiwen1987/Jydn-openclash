//go:build linux

package mihomodeploy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// MODEL metadata and codec fixture only: the S1 model uses its original test
// issuer. This helper never inserts a verification cap into any issuer map and
// never dispatches a process, HTTP request, or genuine record operation.
func lifecycleVerifiedBoundsModel(t *testing.T) (*lifecycleRecoveryStore, *lifecycleModelDisk, *lifecycleRecoveryOwnerToken, labRecoveryObservedValue, lifecycleV3Record) {
	t.Helper()
	s, disk, owner, started, now := lifecycleStartedRecordModel(t)
	if s.recordRecoveryStarted(owner, started, now) != nil {
		t.Fatal("MODEL S1 source could not be recorded")
	}
	w := s.core.record.core
	a := w.Recovery
	entry := now.Add(time.Nanosecond)
	deadline, ok := labRecoveryWindowDeadline(entry, a.Plan.Budgets.VerificationMillis,
		[4]time.Time{a.Plan.ExpiresAt, a.Approval.ExpiresAt, w.RecoveryOwner.ExpiresAt, a.Execution.Started.ObservedAt.Add(30 * time.Second)}, context.Background())
	if !ok {
		t.Fatal("MODEL source has no observation window")
	}
	observed := entry.Add(5 * time.Nanosecond)
	marker := labRecoveryMarkerBoundsModel(t, "B")
	marker.StartedAt, marker.ReturnedAt = observed.Add(time.Nanosecond), observed.Add(2*time.Nanosecond)
	markerRaw, err := json.Marshal(marker)
	if err != nil {
		t.Fatal("MODEL local metadata encoding")
	}
	target := labConfigHash([]byte("MODEL selected-target projection"))
	value := labRecoveryObservedValue{
		Schema: "chengwang.mihomo-recovery-control-observation/v2", RecoveryID: a.Plan.RecoveryID,
		PlanSHA256: a.Plan.PlanSHA256, StartIntentSHA256: a.StartIntent.IntentSHA256,
		StartedSHA256: a.Execution.Started.StartedSHA256, SourceRevision: w.Revision, SourceRecordSHA256: w.RecordSHA256,
		OwnerFence: w.RecoveryOwner.Fence, Artifact: cloneArtifactDescriptor(a.Plan.TargetArtifact),
		StartupIdentity: *a.Execution.Started.Observation.StartupIdentity,
		EntryAt: entry, Deadline: deadline, ObservedAt: observed,
		SampleTimes: [2]labRecoverySampleWindow{{entry.Add(time.Nanosecond), entry.Add(2 * time.Nanosecond)}, {entry.Add(3 * time.Nanosecond), entry.Add(4 * time.Nanosecond)}},
		TranscriptSHA256: labConfigHash([]byte("MODEL transcript")), LocalPath: &marker, LocalMarkerSHA256: labConfigHash(markerRaw),
	}
	value.Readback.Schema = "chengwang.mihomo-selected-target-readback/v1"
	value.Readback.Conclusion = "TARGET_PROJECTION_MATCHED"
	value.Readback.SampleCount, value.Readback.RequestsObserved = 2, 8
	value.Readback.TargetProjectionSHA256, value.Readback.ObservedProjectionSHA256 = target, &target
	for i := range value.BodySHA256s {
		value.BodySHA256s[i] = labConfigHash([]byte(fmt.Sprintf("MODEL response %d", i)))
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("MODEL observation encoding")
	}
	value.VerificationSHA256 = labConfigHash(raw)
	fact := lifecycleRecoveryObservedFromValue(value)
	if !lifecycleRecoveryObservedValid(fact, *a, *w.RecoveryOwner) {
		t.Fatal("MODEL typed observation positive control rejected")
	}
	next := lifecycleV3Copy(t, s.core.record)
	recordedAt := marker.ReturnedAt.Add(time.Nanosecond)
	next.core.Revision++
	next.core.LastTrustedAt = recordedAt
	next.core.Recovery.UpdatedAt = recordedAt
	next.core.Recovery.Execution.Schema = lifecycleRecoveryVerifiedExecutionSchema
	hash, err := lifecycleRecoveryObservationHash(fact)
	if err != nil {
		t.Fatal("MODEL observation hash")
	}
	next.core.Recovery.Execution.Verification = &lifecycleRecoveryVerification{
		Schema: lifecycleRecoveryVerificationSchema, Observation: fact, ObservationSHA256: hash,
		SourceOwner: *w.RecoveryOwner, SourceLastTrustedAt: w.LastTrustedAt, SourceLastRecoveryFence: w.LastRecoveryFence,
		SourceRecoveryUpdatedAt: a.UpdatedAt, SourceFailedQuiescence: append([]labQuiescenceObservation{}, a.FailedQuiescence...),
		VerificationCommitRevision: next.core.Revision, RecordedAt: recordedAt,
	}
	lifecycleVerifiedBoundsResealRecord(t, &next)
	raw, err = json.Marshal(next.core)
	if err != nil {
		t.Fatal("MODEL v2 encoding")
	}
	if _, err := decodeLifecycleV3Record(raw); err != nil {
		t.Fatal("MODEL strict v2 codec positive control rejected")
	}
	return s, disk, owner, value, next
}

func lifecycleVerifiedBoundsResealRecord(t *testing.T, record *lifecycleV3Record) {
	t.Helper()
	hash, err := lifecycleV3RecordHash(*record.core)
	if err != nil {
		t.Fatal("MODEL outer record hash")
	}
	record.core.RecordSHA256 = hash
}

func lifecycleVerifiedBoundsCopyFact(t *testing.T, fact lifecycleRecoveryObservedFact) lifecycleRecoveryObservedFact {
	t.Helper()
	raw, err := json.Marshal(fact)
	var copied lifecycleRecoveryObservedFact
	if err != nil || json.Unmarshal(raw, &copied) != nil {
		t.Fatal("MODEL independent fact copy")
	}
	return copied
}

func lifecycleVerifiedBoundsResealFact(t *testing.T, fact *lifecycleRecoveryObservedFact) {
	t.Helper()
	if fact.LocalPath != nil {
		raw, err := json.Marshal(fact.LocalPath)
		if err != nil {
			t.Fatal("MODEL marker hash")
		}
		fact.LocalMarkerSHA256 = labConfigHash(raw)
	}
	fact.VerificationSHA256 = ""
	raw, err := json.Marshal(fact)
	if err != nil {
		t.Fatal("MODEL verification hash")
	}
	fact.VerificationSHA256 = labConfigHash(raw)
}

func TestLifecycleRecoveryVerifiedBoundsObservationRequiresExactBoundSlicesAndDigests(t *testing.T) {
	s, _, _, value, _ := lifecycleVerifiedBoundsModel(t)
	baseline := lifecycleRecoveryObservedFromValue(value)
	for name, mutate := range map[string]func(*lifecycleRecoveryObservedFact){
		"nil-samples":      func(v *lifecycleRecoveryObservedFact) { v.SampleTimes = nil },
		"missing-sample":   func(v *lifecycleRecoveryObservedFact) { v.SampleTimes = v.SampleTimes[:1] },
		"extra-sample":     func(v *lifecycleRecoveryObservedFact) { v.SampleTimes = append(v.SampleTimes, v.SampleTimes[1]) },
		"nil-body-hashes":  func(v *lifecycleRecoveryObservedFact) { v.BodySHA256s = nil },
		"missing-body":     func(v *lifecycleRecoveryObservedFact) { v.BodySHA256s = v.BodySHA256s[:7] },
		"extra-body":       func(v *lifecycleRecoveryObservedFact) { v.BodySHA256s = append(v.BodySHA256s, v.BodySHA256s[0]) },
		"empty-body-hash":  func(v *lifecycleRecoveryObservedFact) { v.BodySHA256s[3] = "" },
		"zero-body-hash":   func(v *lifecycleRecoveryObservedFact) { v.BodySHA256s[3] = strings.Repeat("0", 64) },
		"bad-body-hash":    func(v *lifecycleRecoveryObservedFact) { v.BodySHA256s[3] = strings.Repeat("g", 64) },
		"no-local-path":    func(v *lifecycleRecoveryObservedFact) { v.LocalPath = nil },
		"partial-response": func(v *lifecycleRecoveryObservedFact) { v.LocalPath.Route.ProxyResponse.Complete = false },
		"wrong-selected-delta": func(v *lifecycleRecoveryObservedFact) {
			v.LocalPath.Route.CountersAfter[0].ConnectIngress++
		},
		"missing-counter": func(v *lifecycleRecoveryObservedFact) { v.LocalPath.Route.CountersBefore = v.LocalPath.Route.CountersBefore[:2] },
		"counter-reordered": func(v *lifecycleRecoveryObservedFact) {
			v.LocalPath.Route.CountersAfter[0], v.LocalPath.Route.CountersAfter[1] = v.LocalPath.Route.CountersAfter[1], v.LocalPath.Route.CountersAfter[0]
		},
		"payload-claim": func(v *lifecycleRecoveryObservedFact) { v.Readback.FullPayloadProven = true },
		"no-projection": func(v *lifecycleRecoveryObservedFact) { v.Readback.ObservedProjectionSHA256 = nil },
	} {
		t.Run(name, func(t *testing.T) {
			fact := lifecycleVerifiedBoundsCopyFact(t, baseline)
			mutate(&fact)
			lifecycleVerifiedBoundsResealFact(t, &fact)
			if lifecycleRecoveryObservedValid(fact, *s.core.record.core.Recovery, *s.core.record.core.RecoveryOwner) {
				t.Fatal("coordinately resealed malformed MODEL accepted")
			}
		})
	}
}

func TestLifecycleRecoveryVerifiedBoundsWindowIdentityAndSourceStayBound(t *testing.T) {
	s, _, _, value, _ := lifecycleVerifiedBoundsModel(t)
	baseline := lifecycleRecoveryObservedFromValue(value)
	for name, mutate := range map[string]func(*lifecycleRecoveryObservedFact){
		"source-revision": func(v *lifecycleRecoveryObservedFact) { v.SourceRevision++ },
		"owner-fence":     func(v *lifecycleRecoveryObservedFact) { v.OwnerFence++ },
		"recovery-id":     func(v *lifecycleRecoveryObservedFact) { v.RecoveryID += "_other" },
		"plan":            func(v *lifecycleRecoveryObservedFact) { v.PlanSHA256 = strings.Repeat("e", 64) },
		"intent":          func(v *lifecycleRecoveryObservedFact) { v.StartIntentSHA256 = strings.Repeat("e", 64) },
		"started":         func(v *lifecycleRecoveryObservedFact) { v.StartedSHA256 = strings.Repeat("e", 64) },
		"target":          func(v *lifecycleRecoveryObservedFact) { v.Artifact.Config.SHA256 = strings.Repeat("e", 64) },
		"pid":             func(v *lifecycleRecoveryObservedFact) { v.StartupIdentity.PID++ },
		"ticks":           func(v *lifecycleRecoveryObservedFact) { v.StartupIdentity.StartTicks++ },
		"namespace":       func(v *lifecycleRecoveryObservedFact) { v.StartupIdentity.NetNSInode++ },
		"pre-record-entry": func(v *lifecycleRecoveryObservedFact) {
			v.EntryAt = s.core.record.core.Recovery.Execution.RecordedAt.Add(-time.Nanosecond)
		},
		"sample-before-entry": func(v *lifecycleRecoveryObservedFact) { v.SampleTimes[0].StartedAt = v.EntryAt.Add(-time.Nanosecond) },
		"sample-overlap":      func(v *lifecycleRecoveryObservedFact) { v.SampleTimes[1].StartedAt = v.SampleTimes[0].CompletedAt.Add(-time.Nanosecond) },
		"sample-reversed":     func(v *lifecycleRecoveryObservedFact) { v.SampleTimes[0].CompletedAt = v.SampleTimes[0].StartedAt.Add(-time.Nanosecond) },
		"sample-after-observed": func(v *lifecycleRecoveryObservedFact) {
			v.SampleTimes[1].CompletedAt = v.ObservedAt.Add(time.Nanosecond)
		},
		"deadline-equality": func(v *lifecycleRecoveryObservedFact) { v.Deadline = v.ObservedAt },
		"budget-extended": func(v *lifecycleRecoveryObservedFact) {
			v.Deadline = v.EntryAt.Add(time.Duration(s.core.record.core.Recovery.Plan.Budgets.VerificationMillis)*time.Millisecond + time.Nanosecond)
		},
		"marker-before-get": func(v *lifecycleRecoveryObservedFact) { v.LocalPath.StartedAt = v.ObservedAt.Add(-time.Nanosecond) },
		"marker-at-deadline": func(v *lifecycleRecoveryObservedFact) { v.LocalPath.ReturnedAt = v.Deadline },
	} {
		t.Run(name, func(t *testing.T) {
			fact := lifecycleVerifiedBoundsCopyFact(t, baseline)
			mutate(&fact)
			lifecycleVerifiedBoundsResealFact(t, &fact)
			if lifecycleRecoveryObservedValid(fact, *s.core.record.core.Recovery, *s.core.record.core.RecoveryOwner) {
				t.Fatal("MODEL source/time binding changed after outer reseal")
			}
		})
	}
}

func TestLifecycleRecoveryVerifiedBoundsNestedValuesAreDetached(t *testing.T) {
	_, _, _, value, _ := lifecycleVerifiedBoundsModel(t)
	if len(value.Artifact.Config.Capabilities) == 0 {
		t.Fatal("MODEL source lacks the mutable artifact slice positive control")
	}
	fact := lifecycleRecoveryObservedFromValue(value)
	beforeFact, _ := json.Marshal(fact)
	value.LocalPath.Route.ClientResponse.Bytes++
	value.LocalPath.Route.CountersBefore[0].Rejected++
	*value.Readback.ObservedProjectionSHA256 = "MODEL changed source"
	value.Artifact.Config.Capabilities[0] = "MODEL changed source capability"
	value.SampleTimes[0].StartedAt = time.Time{}
	value.BodySHA256s[0] = "MODEL changed source body"
	afterFact, _ := json.Marshal(fact)
	if !bytes.Equal(beforeFact, afterFact) {
		t.Fatal("typed persisted metadata aliases its transient source")
	}
	beforeValue, _ := json.Marshal(value)
	fact.LocalPath.Route.OriginResponse.Bytes++
	fact.LocalPath.Route.CountersAfter[1].TunnelRequests++
	*fact.Readback.ObservedProjectionSHA256 = "MODEL changed destination"
	fact.Artifact.Config.Capabilities[0] = "MODEL changed destination capability"
	fact.SampleTimes[1].CompletedAt = time.Time{}
	fact.BodySHA256s[7] = "MODEL changed destination body"
	afterValue, _ := json.Marshal(value)
	if !bytes.Equal(beforeValue, afterValue) {
		t.Fatal("typed destination changes mutated its original DTO")
	}
}

func TestLifecycleRecoveryVerifiedBoundsUnissuedCopiedAndForeignCapsCannotPublish(t *testing.T) {
	s, disk, owner, value, _ := lifecycleVerifiedBoundsModel(t)
	other, otherDisk, otherOwner, _, _ := lifecycleVerifiedBoundsModel(t)
	fact := lifecycleRecoveryObservedFromValue(value)
	unissued := &labRecoveryVerificationRecordCap{core: &labRecoveryVerificationRecordCore{store: s.core, value: fact}}
	copyCore := *unissued.core
	copyWrapper := *unissued
	before := bytes.Clone(s.core.raw)
	writes := disk.writes
	otherBefore := bytes.Clone(other.core.raw)
	otherWrites := otherDisk.writes
	for _, tc := range []struct {
		name  string
		store *lifecycleRecoveryStore
		owner *lifecycleRecoveryOwnerToken
		cap   *labRecoveryVerificationRecordCap
	}{
		{"nil-cap", s, owner, nil},
		{"empty-cap", s, owner, &labRecoveryVerificationRecordCap{}},
		{"unissued", s, owner, unissued},
		{"unissued-retry", s, owner, unissued},
		{"copied-core", s, owner, &labRecoveryVerificationRecordCap{core: &copyCore}},
		{"copied-wrapper", s, owner, &copyWrapper},
		{"foreign-store", other, otherOwner, unissued},
		{"nil-store", nil, owner, unissued},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.store.recordRecoveryVerification(tc.owner, tc.cap, value.LocalPath.ReturnedAt) == nil {
				t.Fatal("unregistered MODEL metadata became record authority")
			}
		})
	}
	if disk.writes != writes || otherDisk.writes != otherWrites || !bytes.Equal(s.core.raw, before) || !bytes.Equal(other.core.raw, otherBefore) || s.core.record.core.Recovery.Execution.Verification != nil {
		t.Fatal("unissued negative path wrote or adopted a candidate")
	}
	if _, err := json.Marshal(unissued); err == nil {
		t.Fatal("private record cap serialized")
	}
	if json.Unmarshal([]byte(`{"core":{"value":{}}}`), unissued) == nil || !reflect.DeepEqual(*unissued, labRecoveryVerificationRecordCap{}) {
		t.Fatal("JSON retained or minted record authority")
	}
	// These are front-door negatives, not proof that a known issued cap was
	// consumed or that a NotCommitted/Unknown/readback fault was reached.
}

func TestLifecycleRecoveryVerifiedBoundsGenericPublisherCannotMintOrReplaceFact(t *testing.T) {
	s, disk, _, _, next := lifecycleVerifiedBoundsModel(t)
	before := bytes.Clone(s.core.raw)
	writes := disk.writes
	draft := lifecycleV3Copy(t, next)
	draft.core.Revision, draft.core.RecordSHA256 = s.core.record.core.Revision, s.core.record.core.RecordSHA256
	if lifecycleV3Transition(s.core.record.core, draft.core) || s.core.commit(draft, next.core.LastTrustedAt) == nil || disk.writes != writes || !bytes.Equal(s.core.raw, before) {
		t.Fatal("generic publisher minted structurally valid MODEL verification")
	}
	for _, kind := range []string{"drop-execution", "replace-started", "advance-current"} {
		t.Run(kind, func(t *testing.T) {
			candidate := lifecycleV3Copy(t, next)
			candidate.core.Revision, candidate.core.RecordSHA256 = s.core.record.core.Revision, s.core.record.core.RecordSHA256
			switch kind {
			case "drop-execution":
				candidate.core.Recovery.Execution = nil
			case "replace-started":
				candidate.core.Recovery.Execution.Started.StartedSHA256 = strings.Repeat("f", 64)
			case "advance-current":
				candidate.core.Current.Head.Generation++
			}
			if s.core.commit(candidate, candidate.core.LastTrustedAt) == nil || disk.writes != writes || !bytes.Equal(s.core.raw, before) {
				t.Fatal("generic candidate changed record-only source or head")
			}
		})
	}
}

func TestLifecycleRecoveryVerifiedBoundsCoordinatedTamperRejectsAfterReseal(t *testing.T) {
	_, _, _, _, positive := lifecycleVerifiedBoundsModel(t)
	for _, kind := range []string{"source-hash", "source-owner", "source-clock", "source-updated", "source-fence", "source-prefix", "commit-revision", "recorded-before-marker", "head", "version", "nil-verification"} {
		t.Run(kind, func(t *testing.T) {
			next := lifecycleV3Copy(t, positive)
			e := next.core.Recovery.Execution
			v := e.Verification
			switch kind {
			case "source-hash":
				v.Observation.SourceRecordSHA256 = strings.Repeat("e", 64)
			case "source-owner":
				v.SourceOwner.OwnerNonce = strings.Repeat("e", 64)
			case "source-clock":
				v.SourceLastTrustedAt = v.SourceLastTrustedAt.Add(-time.Nanosecond)
			case "source-updated":
				v.SourceRecoveryUpdatedAt = v.SourceRecoveryUpdatedAt.Add(-time.Nanosecond)
			case "source-fence":
				v.SourceLastRecoveryFence++
			case "source-prefix":
				v.SourceFailedQuiescence = nil
			case "commit-revision":
				v.VerificationCommitRevision = v.Observation.SourceRevision
			case "recorded-before-marker":
				v.RecordedAt = v.Observation.LocalPath.ReturnedAt.Add(-time.Nanosecond)
			case "head":
				next.core.Current.Head.PID++
			case "version":
				e.Schema = lifecycleRecoveryExecutionSchema
			case "nil-verification":
				e.Verification = nil
			}
			if e.Verification != nil {
				lifecycleVerifiedBoundsResealFact(t, &v.Observation)
				v.ObservationSHA256, _ = lifecycleRecoveryObservationHash(v.Observation)
			}
			lifecycleVerifiedBoundsResealRecord(t, &next)
			raw, err := json.Marshal(next.core)
			if err != nil {
				t.Fatal("MODEL resealed negative encoding")
			}
			if _, err := decodeLifecycleV3Record(raw); err == nil {
				t.Fatal("coordinated nested and outer reseal bypassed strict source validation")
			}
		})
	}
}
