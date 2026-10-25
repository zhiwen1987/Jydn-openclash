package mihomodeploy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// SYNTHETIC metadata only. This fixture is not an OS/process/port observation,
// not an issued physical capability, and not recovery authorization.
func labQuiescenceModel(t *testing.T) (labQuiescenceBinding, labQuiescenceFact, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	b := labQuiescenceBinding{RecoveryID: "labrec_" + strings.Repeat("1", 32), RecoveryPlanSHA256: strings.Repeat("2", 64),
		StopIntentSHA256: strings.Repeat("3", 64), OldEpochSHA256: strings.Repeat("4", 64),
		ExpectedOldIdentity: labKernelIdentity{PID: 42, StartTicks: 100, NetNSInode: 200, ELFSHA256: strings.Repeat("a", 64),
			ELFBytes: 64, SourceCommit: strings.Repeat("b", 40), ArtifactSHA256: strings.Repeat("c", 64), ControllerPort: 28412, MixedPort: 28411},
		ArmedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}
	exitCode, group := 0, true
	stream := labKernelStream{SHA256: labConfigHash(nil), Complete: true}
	exit := labKernelExit{Started: true, WaitReturned: true, WaitErrorClass: "NONE", ExitCode: &exitCode, GroupAbsent: &group, Stdout: stream, Stderr: stream}
	identity, ns, started, returned := b.ExpectedOldIdentity, b.ExpectedOldIdentity.NetNSInode, now.Add(-time.Millisecond), now
	stopClass := "NONE"
	f := labQuiescenceFact{Schema: labQuiescenceFactSchema, Binding: b, ObservedAt: now,
		Observation: labQuiescenceObservation{Schema: labQuiescenceObservationSchema, StartupIdentity: &identity,
			StopInvoked: true, StopReturned: true, StopErrorClass: &stopClass, Stop: &exit, NamespaceInode: &ns,
			ControllerProbe: &labQuiescenceProbe{Port: 28412, Attempted: true, Result: "CONNECTION_REFUSED"},
			MixedProbe:      &labQuiescenceProbe{Port: 28411, Attempted: true, Result: "CONNECTION_REFUSED"},
			StartedAt:       &started, ReturnedAt: &returned, Outcome: "QUIESCED", FailureCode: "NONE"}}
	labQuiescenceModelReseal(t, &f)
	return b, f, now
}

func labQuiescenceModelReseal(t *testing.T, f *labQuiescenceFact) {
	t.Helper()
	hash, err := labQuiescenceFactHash(*f)
	if err != nil {
		t.Fatal("SYNTHETIC fact encoding")
	}
	f.QuiescenceSHA256 = hash
}

func TestLabQuiescenceBindingIsStructuralBoundedAndNotAnIdentityHash(t *testing.T) {
	b, f, now := labQuiescenceModel(t)
	if !labQuiescenceBindingValid(b, now) || !labQuiescenceFactValid(f, b, now) {
		t.Fatal("SYNTHETIC metadata rejected")
	}
	raw, err := json.Marshal(b.ExpectedOldIdentity)
	if err != nil || labConfigHash(raw) == b.OldEpochSHA256 {
		t.Fatal("SYNTHETIC external epoch hash fixture")
	}
	// The outer scope/provisioning-aware codec owns OldEpochSHA; this layer must
	// not silently replace it with hash(ExpectedOldIdentity).
	if f.Binding.OldEpochSHA256 != b.OldEpochSHA256 {
		t.Fatal("epoch binding rewritten")
	}
}

func TestLabQuiescenceBindingRejectsMalformedTimeHashesAndFixedTarget(t *testing.T) {
	b, _, now := labQuiescenceModel(t)
	variants := []labQuiescenceBinding{}
	for _, id := range []string{"", "labrcv_" + strings.Repeat("1", 32), "labrec_" + strings.Repeat("A", 32)} {
		v := b
		v.RecoveryID = id
		variants = append(variants, v)
	}
	v := b
	v.RecoveryPlanSHA256 = strings.Repeat("0", 64)
	variants = append(variants, v)
	v = b
	v.StopIntentSHA256 = "bad"
	variants = append(variants, v)
	v = b
	v.OldEpochSHA256 = strings.Repeat("0", 64)
	variants = append(variants, v)
	v = b
	v.ArmedAt = now.Add(time.Second)
	variants = append(variants, v)
	v = b
	v.ExpiresAt = now
	variants = append(variants, v)
	v = b
	v.ExpiresAt = b.ArmedAt.Add(5*time.Minute + time.Nanosecond)
	variants = append(variants, v)
	v = b
	v.ArmedAt = now.In(time.FixedZone("not-canonical-UTC", 0))
	variants = append(variants, v)
	for _, field := range []string{"pid", "ticks", "ns", "elf", "bytes", "source", "artifact", "controller", "mixed"} {
		v = b
		switch field {
		case "pid":
			v.ExpectedOldIdentity.PID = 0
		case "ticks":
			v.ExpectedOldIdentity.StartTicks = 0
		case "ns":
			v.ExpectedOldIdentity.NetNSInode = 0
		case "elf":
			v.ExpectedOldIdentity.ELFSHA256 = strings.Repeat("0", 64)
		case "bytes":
			v.ExpectedOldIdentity.ELFBytes = 63
		case "source":
			v.ExpectedOldIdentity.SourceCommit = strings.Repeat("0", 40)
		case "artifact":
			v.ExpectedOldIdentity.ArtifactSHA256 = "bad"
		case "controller":
			v.ExpectedOldIdentity.ControllerPort = 28413
		case "mixed":
			v.ExpectedOldIdentity.MixedPort = 28412
		}
		variants = append(variants, v)
	}
	for i, v := range variants {
		if labQuiescenceBindingValid(v, now) {
			t.Fatalf("SYNTHETIC malformed binding %d accepted", i)
		}
	}
}

func TestLabQuiescenceFactRequiresActualCompleteExitMetadata(t *testing.T) {
	for _, field := range []string{"start", "wait", "wait-error", "group-null", "group-false", "stdout-eof", "stderr-eof", "truncated", "total", "hash", "exit-signal"} {
		t.Run(field, func(t *testing.T) {
			b, f, now := labQuiescenceModel(t)
			switch field {
			case "start":
				f.Observation.Stop.Started = false
			case "wait":
				f.Observation.Stop.WaitReturned = false
			case "wait-error":
				f.Observation.Stop.WaitErrorClass = "WAIT_ERROR"
			case "group-null":
				f.Observation.Stop.GroupAbsent = nil
			case "group-false":
				*f.Observation.Stop.GroupAbsent = false
			case "stdout-eof":
				f.Observation.Stop.Stdout.Complete = false
			case "stderr-eof":
				f.Observation.Stop.Stderr.Complete = false
			case "truncated":
				f.Observation.Stop.Stdout.Truncated = true
			case "total":
				f.Observation.Stop.Stderr.TotalBytes = 1
			case "hash":
				f.Observation.Stop.Stdout.SHA256 = strings.Repeat("0", 64)
			case "exit-signal":
				signal := 15
				f.Observation.Stop.Signal = &signal
			}
			labQuiescenceModelReseal(t, &f)
			if labQuiescenceFactValid(f, b, now) {
				t.Fatal("coherently hashed incomplete exit accepted")
			}
		})
	}
	b, f, now := labQuiescenceModel(t)
	signal := 15
	f.Observation.Stop.ExitCode = nil
	f.Observation.Stop.Signal = &signal
	f.Observation.Stop.WaitErrorClass = "EXIT_STATUS"
	labQuiescenceModelReseal(t, &f)
	if !labQuiescenceFactValid(f, b, now) {
		t.Fatal("SYNTHETIC actual signaled-exit shape rejected")
	}
	copy := labQuiescenceCloneObservation(f.Observation)
	*copy.Stop.Signal = 9
	if *f.Observation.Stop.Signal != 15 {
		t.Fatal("signal metadata aliases source")
	}
}

func TestLabQuiescenceFactRejectsNamespaceProbeAndBindingCrossWires(t *testing.T) {
	for _, field := range []string{"ns", "startup", "port", "not-attempted", "accepted", "timeout", "probe-null", "stop-null", "stop-class-null", "stop-class-failed", "false-capture-limit", "not-invoked", "not-returned", "outcome", "failure", "binding"} {
		t.Run(field, func(t *testing.T) {
			b, f, now := labQuiescenceModel(t)
			switch field {
			case "ns":
				(*f.Observation.NamespaceInode)++
			case "startup":
				f.Observation.StartupIdentity.StartTicks++
			case "port":
				f.Observation.ControllerProbe.Port = 28411
			case "not-attempted":
				f.Observation.MixedProbe.Attempted = false
			case "accepted":
				f.Observation.ControllerProbe.Result = "CONNECTION_ACCEPTED"
			case "timeout":
				f.Observation.MixedProbe.Result = "TIMEOUT"
			case "probe-null":
				f.Observation.ControllerProbe = nil
			case "stop-null":
				f.Observation.Stop = nil
			case "stop-class-null":
				f.Observation.StopErrorClass = nil
			case "stop-class-failed":
				*f.Observation.StopErrorClass = "FAILED"
			case "false-capture-limit":
				*f.Observation.StopErrorClass = "CAPTURE_LIMIT_ONLY"
			case "not-invoked":
				f.Observation.StopInvoked = false
			case "not-returned":
				f.Observation.StopReturned = false
			case "outcome":
				f.Observation.Outcome = "FAILED"
			case "failure":
				f.Observation.FailureCode = "CONTEXT_REJECTED"
			case "binding":
				f.Binding.StopIntentSHA256 = strings.Repeat("f", 64)
			}
			labQuiescenceModelReseal(t, &f)
			if labQuiescenceFactValid(f, b, now) {
				t.Fatal("coherently hashed cross-wire accepted")
			}
		})
	}
}

func TestLabQuiescenceFactBindsActualReturnTimeFreshnessAndDigest(t *testing.T) {
	b, f, now := labQuiescenceModel(t)
	if !labQuiescenceFactValid(f, b, now.Add(30*time.Second)) {
		t.Fatal("SYNTHETIC 30-second boundary rejected")
	}
	if labQuiescenceFactValid(f, b, now.Add(30*time.Second+time.Nanosecond)) || labQuiescenceFactValid(f, b, now.Add(-time.Nanosecond)) {
		t.Fatal("stale or future observation accepted")
	}
	f.ObservedAt = now.Add(-time.Nanosecond)
	labQuiescenceModelReseal(t, &f)
	if labQuiescenceFactValid(f, b, now) {
		t.Fatal("observedAt detached from returnedAt")
	}
	_, f, _ = labQuiescenceModel(t)
	f.QuiescenceSHA256 = strings.Repeat("d", 64)
	if labQuiescenceFactValid(f, b, now) {
		t.Fatal("unbound digest accepted")
	}
}

func TestLabQuiescenceObservationCopiesEveryNullableField(t *testing.T) {
	_, f, _ := labQuiescenceModel(t)
	copy := labQuiescenceCloneObservation(f.Observation)
	copy.StartupIdentity.PID++
	*copy.StopErrorClass = "FAILED"
	*copy.Stop.ExitCode = 1
	*copy.Stop.GroupAbsent = false
	(*copy.NamespaceInode)++
	copy.ControllerProbe.Result = "OTHER"
	copy.MixedProbe.Port++
	*copy.StartedAt = copy.StartedAt.Add(-time.Hour)
	*copy.ReturnedAt = copy.ReturnedAt.Add(time.Hour)
	if f.Observation.StartupIdentity.PID != 42 || *f.Observation.StopErrorClass != "NONE" || *f.Observation.Stop.ExitCode != 0 || !*f.Observation.Stop.GroupAbsent ||
		*f.Observation.NamespaceInode != 200 || f.Observation.ControllerProbe.Result != "CONNECTION_REFUSED" ||
		f.Observation.MixedProbe.Port != 28411 || !f.Observation.ReturnedAt.Equal(f.ObservedAt) {
		t.Fatal("detached observation aliases source")
	}
}

func TestLabQuiescenceNilForgedAndJSONHandlesCannotMintTruth(t *testing.T) {
	b, _, now := labQuiescenceModel(t)
	var nilHandle *labQuiescedEpoch
	for _, q := range []*labQuiescedEpoch{nilHandle, {}, {core: &labQuiescedEpochCore{}}} {
		if _, err := q.consumeQuiescence(b, now); err == nil {
			t.Fatal("unissued handle accepted")
		}
		if _, err := q.consumeQuiescenceForRecord(b, b.ExpiresAt.Add(time.Hour)); err == nil {
			t.Fatal("unissued record-only handle accepted")
		}
	}
	var q labQuiescedEpoch
	if json.Unmarshal([]byte(`{"core":{"nonce":[1],"fact":{}}}`), &q) == nil {
		t.Fatal("JSON capability accepted")
	}
	if _, err := q.consumeQuiescence(b, now); err == nil {
		t.Fatal("JSON minted capability")
	}
	if _, err := q.consumeQuiescenceForRecord(b, b.ExpiresAt.Add(time.Hour)); err == nil {
		t.Fatal("JSON minted record-only capability")
	}
}

func TestLabQuiescenceOpaqueFormattingCannotRevealNonceOrOwner(t *testing.T) {
	q := &labQuiescedEpoch{core: &labQuiescedEpochCore{nonce: [32]byte{77, 88, 99}}}
	for _, value := range []any{q, *q} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x"} {
			if fmt.Sprintf(format, value) != labQuiescenceDebug {
				t.Fatal("opaque formatter traversed core")
			}
		}
		for _, format := range []string{"%p", "%T"} {
			text := fmt.Sprintf(format, value)
			if strings.Contains(text, "nonce:") || strings.Contains(text, "owner:") || strings.Contains(text, "[77 88 99") {
				t.Fatal("special formatter traversed core")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `{"scope":"OWNED_QUIESCENCE_FACT_NOT_AUTHORIZATION"}` {
			t.Fatal("opaque JSON leaked core")
		}
	}
	var nilHandle *labQuiescedEpoch
	if fmt.Sprintf("%v", nilHandle) != "<nil>" {
		t.Fatal("nil formatter")
	}
	raw, err := json.Marshal(nilHandle)
	if err != nil || string(raw) != "null" {
		t.Fatal("nil JSON")
	}
}

func TestLabQuiescenceMissingOwnedHandleCannotPerformPhysicalWork(t *testing.T) {
	b, _, _ := labQuiescenceModel(t)
	now := time.Now().UTC()
	b.ArmedAt, b.ExpiresAt = now.Add(-time.Second), now.Add(time.Minute)
	q, observation, err := quiesceOwnedLabKernel(context.Background(), nil, b)
	if err == nil || q != nil || observation.StopInvoked || observation.StopReturned || observation.Stop != nil ||
		observation.ControllerProbe != nil || observation.MixedProbe != nil || observation.NamespaceInode != nil {
		t.Fatal("missing owned capability became physical observations")
	}
}
