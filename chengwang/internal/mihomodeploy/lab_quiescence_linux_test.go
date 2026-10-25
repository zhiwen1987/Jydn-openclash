//go:build linux

package mihomodeploy

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type labQuiescenceNilContext struct{ context.Context }

// STRUCTURE MODEL ONLY. os.Process{Pid:42} is not an OS-owned process. These
// tests NEVER call valid quiesce/stop/Signal/probe on that fake value. They only
// exercise private metadata guards and one-use consumption. Native proof is a
// separate, still-unrun Linux experiment with an actual Start-owned handle.
func labQuiescenceOwnedModel(t *testing.T) (*ownedLabKernel, labQuiescenceBinding, labQuiescenceFact, time.Time) {
	t.Helper()
	b, f, now := labQuiescenceModel(t)
	pid, ticks := b.ExpectedOldIdentity.PID, b.ExpectedOldIdentity.StartTicks
	done := make(chan struct{})
	close(done)
	c := &ownedLabKernelCore{process: &os.Process{Pid: pid}, bound: b.ExpectedOldIdentity,
		input: &labKernelInput{&labKernelInputCore{commit: b.ExpectedOldIdentity.SourceCommit,
			binaryHash: b.ExpectedOldIdentity.ELFSHA256, binaryBytes: b.ExpectedOldIdentity.ELFBytes}},
		done: done, cancel: func() { panic("STRUCTURE MODEL must not cancel a process") }, closed: true,
		startAttempted: true, startKnown: true, captureStarted: true, observedPID: &pid, observedTicks: &ticks,
		exit: labQuiescenceCloneExit(*f.Observation.Stop), stdout: &labKernelWriter{}, stderr: &labKernelWriter{}}
	c.ops = labKernelOps{
		verifyInput: func() error { panic("STRUCTURE MODEL must not read native input") },
		home: func() (string, error) { panic("STRUCTURE MODEL must not create a home") },
		command: func(context.Context, string, []byte) *exec.Cmd { panic("STRUCTURE MODEL must not create a command") },
		observe: func(int) (labKernelIdentity, error) { panic("STRUCTURE MODEL must not observe any PID") },
	}
	return &ownedLabKernel{c}, b, f, now
}

func labQuiescenceIssuedModel(t *testing.T) (*labQuiescedEpoch, labQuiescenceBinding, time.Time) {
	t.Helper()
	old, b, f, now := labQuiescenceOwnedModel(t)
	return labQuiescenceIssueForModel(t, old, b, f), b, now
}

func labQuiescenceIssueForModel(t *testing.T, old *ownedLabKernel, b labQuiescenceBinding, f labQuiescenceFact) *labQuiescedEpoch {
	t.Helper()
	seal, err := labQuiescenceStartupSeal(old, b.ExpectedOldIdentity)
	if err != nil { t.Fatal("STRUCTURE MODEL startup guard") }
	issuer := &labQuiescenceIssuer{claimed: map[*ownedLabKernelCore]bool{old.ownedLabKernelCore: true}, issued: map[*labQuiescedEpochCore]bool{}}
	core := &labQuiescedEpochCore{issuer: issuer, owner: old, ownerCore: old.ownedLabKernelCore, seal: seal, nonce: [32]byte{1}, fact: f}
	// Direct private registry assembly is explicitly a MODEL, not DTO issuance.
	issuer.issued[core] = true
	return &labQuiescedEpoch{core: core}
}

func labQuiescenceCaptureLimitedModel(t *testing.T) (*ownedLabKernel, labQuiescenceBinding, labQuiescenceFact, time.Time) {
	t.Helper()
	old, b, f, now := labQuiescenceOwnedModel(t)
	writer := &labKernelWriter{}
	full := bytes.Repeat([]byte("SYNTHETIC_STREAM_"), 5000)
	if n, err := writer.Write(full); err != nil || n != len(full) { t.Fatal("MODEL writer short input") }
	tail := []byte("SYNTHETIC_TAIL_AFTER_RETENTION_CAP")
	if n, err := writer.Write(tail); err != nil || n != len(tail) { t.Fatal("MODEL writer stopped draining after cap") }
	full = append(full, tail...)
	// This nil completion is explicitly a MODEL marker, not actual pipe EOF.
	writer.finish(nil)
	prefix, metadata := writer.snapshot()
	if len(prefix) != 64<<10 || metadata.Bytes != len(prefix) || metadata.TotalBytes != int64(len(full)) ||
		!metadata.Complete || !metadata.Truncated || metadata.SHA256 != labConfigHash(full) || metadata.SHA256 == labConfigHash(prefix) {
		t.Fatal("MODEL retention and full-stream accounting are not distinct")
	}
	old.stdout = writer
	old.exit.Stdout = metadata
	exit := labQuiescenceCloneExit(old.exit)
	f.Observation.Stop = &exit
	class := "CAPTURE_LIMIT_ONLY"
	f.Observation.StopErrorClass = &class
	labQuiescenceModelReseal(t, &f)
	return old, b, f, now
}

func TestLabQuiescenceRetainedStartupMetadataSupportsNaturalExitStructure(t *testing.T) {
	old, b, f, _ := labQuiescenceOwnedModel(t)
	seal, err := labQuiescenceStartupSeal(old, b.ExpectedOldIdentity)
	if err != nil || seal.core != old.ownedLabKernelCore || seal.process != old.process || seal.identity != b.ExpectedOldIdentity {
		t.Fatal("STRUCTURE MODEL retained startup rejected")
	}
	if !labQuiescenceOwnerSettled(old, seal, b, *f.Observation.Stop) { t.Fatal("STRUCTURE MODEL naturally exited state rejected") }
	// A live-shaped retained startup also passes this metadata guard; it does
	// not pass the separate settled proof and no native I/O is performed here.
	old.done = make(chan struct{})
	old.closed = false
	old.exit.WaitReturned = false
	if _, err := labQuiescenceStartupSeal(old, b.ExpectedOldIdentity); err != nil { t.Fatal("STRUCTURE MODEL live startup rejected") }
	if labQuiescenceOwnerSettled(old, seal, b, *f.Observation.Stop) { t.Fatal("live structure became settled proof") }
	t.Run("drained_capture_limit_preserves_original_stop_error_class", func(t *testing.T) {
		old, b, f, now := labQuiescenceCaptureLimitedModel(t)
		actual, nativeErr := old.exitSnapshot()
		if nativeErr != errLabKernelStop || !labQuiescenceExitEqual(actual, *f.Observation.Stop) ||
			labQuiescenceExitComplete(actual) || !labQuiescenceCaptureLimited(actual) {
			t.Fatal("MODEL old stop semantics or retention fact changed")
		}
		q := labQuiescenceIssueForModel(t, old, b, f)
		fact, err := q.consumeQuiescence(b, now)
		if err != nil || fact.Observation.StopErrorClass == nil || *fact.Observation.StopErrorClass != "CAPTURE_LIMIT_ONLY" ||
			!fact.Observation.Stop.Stdout.Truncated || fact.Observation.Stop.Stdout.TotalBytes <= int64(fact.Observation.Stop.Stdout.Bytes) {
			t.Fatal("MODEL drained capture limit rejected or hidden")
		}
		if _, err := q.consumeQuiescence(b, now); err == nil { t.Fatal("capture-limited proof replayed") }
	})
	t.Run("capture_limit_never_hides_unsettled_or_inconsistent_metadata", func(t *testing.T) {
		for _, field := range []string{"eof", "wait", "wait-error", "group", "bytes", "total", "digest", "false-flag", "stop-error"} {
			t.Run(field, func(t *testing.T) {
				old, b, f, now := labQuiescenceCaptureLimitedModel(t)
				switch field {
				case "eof": old.exit.Stdout.Complete = false
				case "wait": old.exit.WaitReturned = false
				case "wait-error": old.exit.WaitErrorClass = "WAIT_ERROR"
				case "group": old.exit.GroupAbsent = nil
				case "bytes": old.exit.Stdout.Bytes--
				case "total": old.exit.Stdout.TotalBytes = int64(old.exit.Stdout.Bytes)
				case "digest": old.exit.Stdout.SHA256 = strings.Repeat("0", 64)
				case "false-flag": old.exit.Stdout.Truncated = false
				case "stop-error": *f.Observation.StopErrorClass = "FAILED"
				}
				exit := labQuiescenceCloneExit(old.exit)
				f.Observation.Stop = &exit
				labQuiescenceModelReseal(t, &f)
				if labQuiescenceFactValid(f, b, now) { t.Fatal("coherently hashed unsettled capture accepted") }
				q := labQuiescenceIssueForModel(t, old, b, f)
				if _, err := q.consumeQuiescence(b, now); err == nil { t.Fatal("unsettled capture minted consumption") }
			})
		}
	})
}

func TestLabQuiescenceStartupGuardRejectsMissingOrMismatchedOwnedFields(t *testing.T) {
	for _, field := range []string{"process", "pid", "bound", "attempted", "known", "capture", "started", "observed-pid", "observed-ticks", "input", "source", "hash", "bytes", "done", "cancel", "stdout", "stderr", "verify", "command", "home", "observe"} {
		t.Run(field, func(t *testing.T) {
			old, b, _, _ := labQuiescenceOwnedModel(t)
			switch field {
			case "process": old.process = nil
			case "pid": old.process = &os.Process{Pid: 0}
			case "bound": old.bound.ArtifactSHA256 = strings.Repeat("d", 64)
			case "attempted": old.startAttempted = false
			case "known": old.startKnown = false
			case "capture": old.captureStarted = false
			case "started": old.exit.Started = false
			case "observed-pid": old.observedPID = nil
			case "observed-ticks": old.observedTicks = nil
			case "input": old.input = nil
			case "source": old.input.commit = strings.Repeat("d", 40)
			case "hash": old.input.binaryHash = strings.Repeat("d", 64)
			case "bytes": old.input.binaryBytes++
			case "done": old.done = nil
			case "cancel": old.cancel = nil
			case "stdout": old.stdout = nil
			case "stderr": old.stderr = nil
			case "verify": old.ops.verifyInput = nil
			case "command": old.ops.command = nil
			case "home": old.ops.home = nil
			case "observe": old.ops.observe = nil
			}
			if _, err := labQuiescenceStartupSeal(old, b.ExpectedOldIdentity); err == nil { t.Fatal("STRUCTURE MODEL bad startup accepted") }
		})
	}
}

func TestLabQuiescenceConsumptionIsOnceAcrossCopiedHandlesAndDetachedFacts(t *testing.T) {
	q, b, now := labQuiescenceIssuedModel(t)
	copy := *q
	fact, err := q.consumeQuiescence(b, now)
	if err != nil || !labQuiescenceFactValid(fact, b, now) { t.Fatal("STRUCTURE MODEL consumption rejected") }
	*fact.Observation.Stop.GroupAbsent = false
	*fact.Observation.NamespaceInode = 999
	fact.Observation.StartupIdentity.PID = 999
	if !*q.core.fact.Observation.Stop.GroupAbsent || *q.core.fact.Observation.NamespaceInode != 200 || q.core.fact.Observation.StartupIdentity.PID != 42 {
		t.Fatal("returned fact aliases private record")
	}
	if _, err := copy.consumeQuiescence(b, now); err == nil { t.Fatal("copied handle consumed twice") }
	t.Run("late_record_preserves_issuance_fact_but_never_refreshes_start", func(t *testing.T) {
		q, b, now := labQuiescenceIssuedModel(t)
		copy := *q
		late := b.ExpiresAt.Add(time.Hour)
		fact, err := q.consumeQuiescenceForRecord(b, late)
		if err != nil || !fact.ObservedAt.Equal(now) || !fact.Observation.ReturnedAt.Equal(now) ||
			!labQuiescenceFactValid(fact, b, fact.ObservedAt) || labQuiescenceFactValid(fact, b, late) {
			t.Fatal("late record lost source time or created fresh Start evidence")
		}
		*fact.Observation.Stop.GroupAbsent = false
		if !*q.core.fact.Observation.Stop.GroupAbsent { t.Fatal("record-only result aliases issued fact") }
		if _, err := copy.consumeQuiescenceForRecord(b, late); err == nil { t.Fatal("record-only copy replayed") }
		if _, err := copy.consumeQuiescence(b, now); err == nil { t.Fatal("record-only consumption recreated strict capability") }
	})
	t.Run("strict_late_consume_remains_rejected_and_cannot_fallback", func(t *testing.T) {
		q, b, _ := labQuiescenceIssuedModel(t)
		if _, err := q.consumeQuiescence(b, b.ExpiresAt); err == nil { t.Fatal("strict expiry was relaxed") }
		if _, err := q.consumeQuiescenceForRecord(b, b.ExpiresAt.Add(time.Second)); err == nil { t.Fatal("spent strict attempt revived for recording") }
	})
}

func TestLabQuiescenceFailedConsumptionCannotReviveAfterRestoration(t *testing.T) {
	for _, field := range []string{"binding", "future", "stale", "expiry", "nonce", "owner", "issuer-claim", "wait", "group", "process"} {
		t.Run(field, func(t *testing.T) {
			q, b, now := labQuiescenceIssuedModel(t)
			wanted, at := b, now
			originalExit := labQuiescenceCloneExit(q.core.owner.exit)
			originalProcess := q.core.owner.process
			switch field {
			case "binding": wanted.StopIntentSHA256 = strings.Repeat("e", 64)
			case "future": at = now.Add(-time.Nanosecond)
			case "stale": at = now.Add(30*time.Second+time.Nanosecond)
			case "expiry": at = b.ExpiresAt
			case "nonce": q.core.nonce = [32]byte{}
			case "owner": q.core.ownerCore = &ownedLabKernelCore{}
			case "issuer-claim": delete(q.core.issuer.claimed, q.core.owner.ownedLabKernelCore)
			case "wait": q.core.owner.exit.WaitReturned = false
			case "group": no := false; q.core.owner.exit.GroupAbsent = &no
			case "process": q.core.owner.process = &os.Process{Pid: 42}
			}
			if _, err := q.consumeQuiescence(wanted, at); err == nil { t.Fatal("STRUCTURE MODEL failed consume accepted") }
			q.core.nonce = [32]byte{1}
			q.core.ownerCore = q.core.owner.ownedLabKernelCore
			q.core.issuer.claimed[q.core.ownerCore] = true
			q.core.owner.exit = originalExit
			q.core.owner.process = originalProcess
			if _, err := q.consumeQuiescence(b, now); err == nil { t.Fatal("failed proof revived") }
		})
	}
	t.Run("record_only_rejects_clockback_bad_binding_owner_and_nonce_once", func(t *testing.T) {
		for _, field := range []string{"clockback", "zero-time", "non-utc", "binding", "nonce", "owner", "wait"} {
			t.Run(field, func(t *testing.T) {
				q, b, now := labQuiescenceIssuedModel(t)
				wanted, receive := b, b.ExpiresAt.Add(time.Minute)
				originalExit := labQuiescenceCloneExit(q.core.owner.exit)
				switch field {
				case "clockback": receive = now.Add(-time.Nanosecond)
				case "zero-time": receive = time.Time{}
				case "non-utc": receive = receive.In(time.FixedZone("alias-UTC", 0))
				case "binding": wanted.OldEpochSHA256 = strings.Repeat("e", 64)
				case "nonce": q.core.nonce = [32]byte{}
				case "owner": q.core.ownerCore = &ownedLabKernelCore{}
				case "wait": q.core.owner.exit.WaitReturned = false
				}
				if _, err := q.consumeQuiescenceForRecord(wanted, receive); err == nil { t.Fatal("invalid source/clock accepted for record") }
				q.core.nonce = [32]byte{1}
				q.core.ownerCore = q.core.owner.ownedLabKernelCore
				q.core.owner.exit = originalExit
				if _, err := q.consumeQuiescenceForRecord(b, b.ExpiresAt.Add(time.Minute)); err == nil { t.Fatal("failed record attempt revived") }
			})
		}
	})
}

func TestLabQuiescenceCanceledEntryCannotClaimOrTouchFakeProcess(t *testing.T) {
	old, b, _, _ := labQuiescenceOwnedModel(t)
	now := time.Now().UTC()
	b.ArmedAt, b.ExpiresAt = now.Add(-time.Second), now.Add(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var nilContext *labQuiescenceNilContext
	for _, ctx := range []context.Context{ctx, nil, nilContext} {
		q, observation, err := quiesceOwnedLabKernel(ctx, old, b)
		if err == nil || q != nil || observation.StopInvoked || observation.StopReturned || observation.Stop != nil || observation.StartedAt != nil {
			t.Fatal("canceled/nil entry fabricated work")
		}
	}
	processLabQuiescenceIssuer.mu.Lock()
	claimed := processLabQuiescenceIssuer.claimed[old.ownedLabKernelCore]
	processLabQuiescenceIssuer.mu.Unlock()
	if claimed { t.Fatal("canceled entry spent a physical attempt") }
}

func TestLabQuiescenceInvalidBindingCannotReachFakeNativeStop(t *testing.T) {
	old, b, _, _ := labQuiescenceOwnedModel(t)
	now := time.Now().UTC()
	b.ArmedAt, b.ExpiresAt = now.Add(-time.Second), now.Add(time.Minute)
	b.StopIntentSHA256 = strings.Repeat("0", 64)
	q, observation, err := quiesceOwnedLabKernel(context.Background(), old, b)
	if err == nil || q != nil || observation.StopInvoked || observation.Stop != nil || observation.StartupIdentity != nil {
		t.Fatal("invalid binding entered physical work")
	}
	processLabQuiescenceIssuer.mu.Lock()
	claimed := processLabQuiescenceIssuer.claimed[old.ownedLabKernelCore]
	processLabQuiescenceIssuer.mu.Unlock()
	if claimed { t.Fatal("invalid binding claimed fake process") }
}

func TestLabQuiescenceIssuerAndStopObservationCannotBeReplacedCoherently(t *testing.T) {
	issuer := &labQuiescenceIssuer{claimed: map[*ownedLabKernelCore]bool{}, issued: map[*labQuiescedEpochCore]bool{}}
	first := &ownedLabKernelCore{}
	if issuer.claim(nil) || !issuer.claim(first) || issuer.claim(first) { t.Fatal("physical-attempt claim was replayable") }
	for n := 1; n < maxLabQuiescenceClaims; n++ {
		if !issuer.claim(&ownedLabKernelCore{}) { t.Fatal("STRUCTURE MODEL claim capacity fixture") }
	}
	if issuer.claim(&ownedLabKernelCore{}) { t.Fatal("unbounded physical-attempt registry") }
	q, b, now := labQuiescenceIssuedModel(t)
	foreign := &labQuiescedEpoch{core: &labQuiescedEpochCore{issuer: q.core.issuer, owner: q.core.owner,
		ownerCore: q.core.ownerCore, seal: q.core.seal, nonce: q.core.nonce, fact: q.core.fact}}
	if _, err := foreign.consumeQuiescence(b, now); err == nil { t.Fatal("unissued copied core accepted") }
	if _, err := foreign.consumeQuiescenceForRecord(b, b.ExpiresAt.Add(time.Hour)); err == nil { t.Fatal("unissued DTO became record-only evidence") }
	// Coherent metadata+digest does not replace the source owner's actual exit.
	one := 1
	q.core.fact.Observation.Stop.ExitCode = &one
	q.core.fact.Observation.Stop.WaitErrorClass = "EXIT_STATUS"
	labQuiescenceModelReseal(t, &q.core.fact)
	if !labQuiescenceFactValid(q.core.fact, b, now) { t.Fatal("STRUCTURE MODEL coherent mismatch fixture") }
	if _, err := q.consumeQuiescence(b, now); err == nil { t.Fatal("source exit replaced by detached DTO") }
}
