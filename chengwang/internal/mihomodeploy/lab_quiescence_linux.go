//go:build linux

package mihomodeploy

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

type labQuiescenceOwnerSeal struct {
	core     *ownedLabKernelCore
	process  *os.Process
	identity labKernelIdentity
}

// This reads only the original Start-owned metadata. It does not claim live
// identity, adopt a PID, call observe(0), or require a naturally exited kernel
// to answer /proc or HTTP. Actual Wait/EOF/group proof is checked separately.
func labQuiescenceStartupSeal(old *ownedLabKernel, expected labKernelIdentity) (*labQuiescenceOwnerSeal, error) {
	if old == nil || old.ownedLabKernelCore == nil || !labQuiescenceIdentityValid(expected) {
		return nil, errLabQuiescence
	}
	c := old.ownedLabKernelCore
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.process == nil || c.process.Pid != expected.PID || c.bound != expected ||
		!c.startAttempted || !c.startKnown || !c.captureStarted || !c.exit.Started ||
		c.observedPID == nil || *c.observedPID != expected.PID || c.observedTicks == nil || *c.observedTicks != expected.StartTicks ||
		c.input == nil || c.input.labKernelInputCore == nil || c.input.commit != expected.SourceCommit ||
		c.input.binaryHash != expected.ELFSHA256 || c.input.binaryBytes != expected.ELFBytes ||
		c.done == nil || c.cancel == nil || c.stdout == nil || c.stderr == nil ||
		c.ops.verifyInput == nil || c.ops.home == nil || c.ops.command == nil || c.ops.observe == nil {
		return nil, errLabQuiescence
	}
	return &labQuiescenceOwnerSeal{core: c, process: c.process, identity: c.bound}, nil
}

func labQuiescenceOwnerSettled(old *ownedLabKernel, seal *labQuiescenceOwnerSeal, b labQuiescenceBinding, stop labKernelExit) bool {
	if old == nil || old.ownedLabKernelCore == nil || seal == nil || seal.core != old.ownedLabKernelCore || seal.identity != b.ExpectedOldIdentity {
		return false
	}
	current, err := labQuiescenceStartupSeal(old, b.ExpectedOldIdentity)
	if err != nil || current.core != seal.core || current.process != seal.process {
		return false
	}
	c := old.ownedLabKernelCore
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if !closed {
		return false
	}
	select {
	case <-c.done:
	default:
		return false
	}
	actual, err := c.exitSnapshot()
	if !labQuiescenceExitEqual(actual, stop) {
		return false
	}
	return err == nil && labQuiescenceExitComplete(actual) || err == errLabKernelStop && labQuiescenceCaptureLimited(actual)
}

func labQuiescenceDial(ctx context.Context, port uint16) labQuiescenceProbe {
	value := labQuiescenceProbe{Port: port, Result: "OTHER"}
	if port != 28411 && port != 28412 {
		return value
	}
	dialer := net.Dialer{Timeout: 250 * time.Millisecond}
	value.Attempted = true
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil && conn != nil {
		value.Result = "CONNECTION_ACCEPTED"
	} else if errors.Is(err, syscall.ECONNREFUSED) {
		value.Result = "CONNECTION_REFUSED"
	} else if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		value.Result = "CONTEXT_REJECTED"
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			value.Result = "TIMEOUT"
		}
	}
	return value
}

func quiesceOwnedLabKernel(ctx context.Context, old *ownedLabKernel, b labQuiescenceBinding) (*labQuiescedEpoch, labQuiescenceObservation, error) {
	observation := labQuiescenceObservation{Schema: labQuiescenceObservationSchema, Outcome: "ENTRY_REJECTED", FailureCode: "ENTRY_REJECTED"}
	fail := func(outcome, code string) (*labQuiescedEpoch, labQuiescenceObservation, error) {
		observation.Outcome = outcome
		observation.FailureCode = code
		if observation.StopInvoked {
			returned := time.Now().UTC()
			observation.ReturnedAt = &returned
		}
		return nil, labQuiescenceCloneObservation(observation), errLabQuiescence
	}
	// The outer coordinator must have separately authenticated/approved/armed
	// this action. Structural binding and an owned handle do not grant that.
	if artifactContext(ctx) != nil {
		return fail("ENTRY_REJECTED", "CONTEXT_REJECTED")
	}
	now := time.Now().UTC()
	if !labQuiescenceBindingValid(b, now) {
		return fail("ENTRY_REJECTED", "BINDING_REJECTED")
	}
	seal, err := labQuiescenceStartupSeal(old, b.ExpectedOldIdentity)
	if err != nil {
		return fail("OWNED_REJECTED", "OWNED_REJECTED")
	}
	identity := seal.identity
	observation.StartupIdentity = &identity
	issuer := &processLabQuiescenceIssuer
	if !issuer.claim(seal.core) {
		return fail("OWNED_REJECTED", "ATTEMPT_SPENT")
	}
	// Claim before the one original stop call, never reset after errors. The
	// claim itself is not a claim that Stop or a signal has happened.
	if artifactContext(ctx) != nil {
		return fail("ENTRY_REJECTED", "CONTEXT_REJECTED")
	}
	now = time.Now().UTC()
	if !labQuiescenceBindingValid(b, now) {
		return fail("ENTRY_REJECTED", "CLOCK_REJECTED")
	}
	observation.StartedAt = &now
	observation.StopInvoked = true
	labNativeRecoveryObserve(old.ownedLabKernelCore, "RECOVERY_STOP_DISPATCH")
	stopped, stopErr := old.stop(ctx)
	observation.StopReturned = true
	stopped = labQuiescenceCloneExit(stopped)
	observation.Stop = &stopped
	stopClass := "FAILED"
	if stopErr == nil {
		stopClass = "NONE"
	}
	observation.StopErrorClass = &stopClass
	// Do not change the old stop error or declare retained raw complete. Only
	// that exact sentinel, with every other independent terminal condition
	// proved, can become the capture-limit-only candidate below.
	captureLimitOnly := stopErr == errLabKernelStop && labQuiescenceCaptureLimited(stopped)
	if !(stopErr == nil && labQuiescenceExitComplete(stopped) || captureLimitOnly) || !labQuiescenceOwnerSettled(old, seal, b, stopped) {
		return fail("STOP_UNCERTAIN", "STOP_UNCERTAIN")
	}
	if artifactContext(ctx) != nil {
		return fail("FAILED", "CONTEXT_REJECTED")
	}
	now = time.Now().UTC()
	if !labQuiescenceBindingValid(b, now) || now.Before(*observation.StartedAt) {
		return fail("FAILED", "CLOCK_REJECTED")
	}
	ns, nsErr := labKernelNS("/proc/self/ns/net")
	if nsErr == nil {
		observation.NamespaceInode = &ns
	}
	if nsErr != nil || ns != b.ExpectedOldIdentity.NetNSInode {
		return fail("FAILED", "NAMESPACE_REJECTED")
	}
	if artifactContext(ctx) != nil {
		return fail("FAILED", "CONTEXT_REJECTED")
	}
	now = time.Now().UTC()
	if !labQuiescenceBindingValid(b, now) || now.Before(*observation.StartedAt) {
		return fail("FAILED", "CLOCK_REJECTED")
	}
	controller := labQuiescenceDial(ctx, 28412)
	observation.ControllerProbe = &controller
	if controller.Result != "CONNECTION_REFUSED" {
		return fail("FAILED", "CONTROLLER_NOT_REFUSED")
	}
	if artifactContext(ctx) != nil {
		return fail("FAILED", "CONTEXT_REJECTED")
	}
	now = time.Now().UTC()
	if !labQuiescenceBindingValid(b, now) || now.Before(*observation.StartedAt) {
		return fail("FAILED", "CLOCK_REJECTED")
	}
	mixed := labQuiescenceDial(ctx, 28411)
	observation.MixedProbe = &mixed
	if mixed.Result != "CONNECTION_REFUSED" {
		return fail("FAILED", "MIXED_NOT_REFUSED")
	}
	core := &labQuiescedEpochCore{issuer: issuer, owner: old, ownerCore: seal.core, seal: seal}
	if _, err := rand.Read(core.nonce[:]); err != nil || core.nonce == ([32]byte{}) {
		return fail("FAILED", "ISSUER_REJECTED")
	}
	if artifactContext(ctx) != nil {
		return fail("FAILED", "CONTEXT_REJECTED")
	}
	now = time.Now().UTC()
	if !labQuiescenceBindingValid(b, now) || now.Before(*observation.StartedAt) {
		return fail("FAILED", "CLOCK_REJECTED")
	}
	observation.ReturnedAt = &now
	observation.Outcome = "QUIESCED"
	observation.FailureCode = "NONE"
	if captureLimitOnly {
		stopClass = "CAPTURE_LIMIT_ONLY"
	}
	core.fact = labQuiescenceFact{Schema: labQuiescenceFactSchema, Binding: b,
		Observation: labQuiescenceCloneObservation(observation), ObservedAt: now}
	core.fact.QuiescenceSHA256, err = labQuiescenceFactHash(core.fact)
	if err != nil || !labQuiescenceFactValid(core.fact, b, now) {
		return fail("FAILED", "FACT_REJECTED")
	}
	issuer.mu.Lock()
	issuer.issued[core] = true
	issuer.mu.Unlock()
	return &labQuiescedEpoch{core: core}, labQuiescenceCloneObservation(observation), nil
}
