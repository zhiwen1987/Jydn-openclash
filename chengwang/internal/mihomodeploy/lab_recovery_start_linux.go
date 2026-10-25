//go:build linux

package mihomodeploy

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"reflect"
	"time"
)

type labRecoveryStartedOwnerSeal struct {
	core     *ownedLabKernelCore
	process  *os.Process
	identity labKernelIdentity
}

// Retained startup custody, not a new live-identity claim. This intentionally
// still accepts the original handle after natural exit for recording facts.
func labRecoveryStartedSeal(k *ownedLabKernel, id labKernelIdentity) (*labRecoveryStartedOwnerSeal, error) {
	s, err := labQuiescenceStartupSeal(k, id)
	if err != nil {
		return nil, errLabRecoveryStart
	}
	return &labRecoveryStartedOwnerSeal{core: s.core, process: s.process, identity: s.identity}, nil
}

func labRecoveryStartedOwnerMatches(k *ownedLabKernel, s *labRecoveryStartedOwnerSeal, id labKernelIdentity) bool {
	if s == nil || s.identity != id {
		return false
	}
	actual, err := labRecoveryStartedSeal(k, id)
	return err == nil && actual.core == s.core && actual.process == s.process
}

func labRecoveryStartedOwnerCurrent(k *ownedLabKernel, id labKernelIdentity) bool {
	actual, err := k.identity()
	if err != nil || actual != id || k.verifyListeners() != nil {
		return false
	}
	actual, err = k.identity()
	return err == nil && actual == id
}

func labRecoveryStartedInputMatches(in *labKernelInput, b labRecoveryStartedBinding) bool {
	return in != nil && in.labKernelInputCore != nil && in.commit == b.ExpectedOldIdentity.SourceCommit &&
		in.binaryHash == b.ExpectedOldIdentity.ELFSHA256 && in.binaryBytes == b.ExpectedOldIdentity.ELFBytes
}

// No controller GET, probe connection, retry of Start or cleanup action is
// performed here. Only bounded read-only /proc ownership checks may repeat.
func labRecoveryStartedAwaitListeners(ctx context.Context, k *ownedLabKernel, id labKernelIdentity, b labRecoveryStartedBinding) error {
	for {
		if artifactContext(ctx) != nil || !labRecoveryStartedBindingValid(b, time.Now().UTC()) {
			return errLabRecoveryStart
		}
		actual, err := k.identity()
		if err != nil || actual != id {
			return errLabRecoveryStart
		}
		if k.verifyListeners() == nil {
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return errLabRecoveryStart
		}
	}
}

func startOwnedRecoveryKernel(lifetimeCtx context.Context, in *labKernelInput, store *ArtifactStore, p *labRecoveryStartPermit) (*ownedLabKernel, *labRecoveryStartedEpoch, labRecoveryStartObservation, error) {
	o := labRecoveryStartObservation{Schema: labRecoveryStartObservationSchema, Outcome: "ENTRY_REJECTED", FailureCode: "ENTRY_REJECTED"}
	var kernel *ownedLabKernel
	fail := func(outcome, code string) (*ownedLabKernel, *labRecoveryStartedEpoch, labRecoveryStartObservation, error) {
		o.Outcome, o.FailureCode = outcome, code
		if o.StartInvoked {
			now := time.Now().UTC()
			o.ReturnedAt = &now
		}
		return kernel, nil, labRecoveryStartedCloneObservation(o), errLabRecoveryStart
	}
	// The caller must already have checked current authority and durably armed
	// the step. This primitive consumes structure, not RBAC authorization.
	if artifactContext(lifetimeCtx) != nil || store == nil || in == nil || in.labKernelInputCore == nil {
		return fail("ENTRY_REJECTED", "CONTEXT_OR_INPUT_REJECTED")
	}
	now := time.Now().UTC()
	f, err := p.consumeRecoveryStart(now)
	if err != nil {
		return fail("ENTRY_REJECTED", "PERMIT_REJECTED")
	}
	o.PermitConsumed = true
	b, err := labRecoveryStartedBindingFromPermit(p, f, time.Now().UTC())
	if err != nil {
		return fail("ENTRY_REJECTED", "BINDING_REJECTED")
	}
	issuer := &processLabRecoveryStartedIssuer
	if !issuer.claim(p.core) {
		return fail("ENTRY_REJECTED", "ATTEMPT_SPENT")
	}
	if !labRecoveryStartedInputMatches(in, b) || in.verify() != nil {
		return fail("ENTRY_REJECTED", "INPUT_REJECTED")
	}
	ns, err := labKernelNS("/proc/self/ns/net")
	if err == nil {
		o.NamespaceInode = &ns
	}
	if err != nil || ns != b.ExpectedOldIdentity.NetNSInode {
		return fail("ENTRY_REJECTED", "NAMESPACE_REJECTED")
	}
	deadline := b.ArmedAt.Add(time.Duration(b.StartMillis) * time.Millisecond)
	if b.ExpiresAt.Before(deadline) {
		deadline = b.ExpiresAt
	}
	// This deadline bounds only preparation/readiness; it MUST NOT become the
	// native child's parent context and kill the new kernel on successful return.
	phaseCtx, cancel := context.WithDeadline(lifetimeCtx, deadline)
	defer cancel()
	d, artifact, _, err := labCollectorLoad(phaseCtx, store, b.TargetArtifact.RecordSHA256)
	if err != nil || !reflect.DeepEqual(d, b.TargetArtifact) || artifact == nil || artifact.AdmissionError() != nil ||
		!reflect.DeepEqual(artifact.Descriptor(), d.Config) {
		return fail("ENTRY_REJECTED", "ARTIFACT_REJECTED")
	}
	raw := artifact.Bytes()
	if len(raw) != d.Config.Bytes || labConfigHash(raw) != d.Config.SHA256 {
		return fail("ENTRY_REJECTED", "ARTIFACT_REJECTED")
	}
	if artifactContext(phaseCtx) != nil || !labRecoveryStartedBindingValid(b, time.Now().UTC()) {
		return fail("ENTRY_REJECTED", "BUDGET_REJECTED")
	}
	// Custody/configuration work above may have taken time. A revocation,
	// expired actual lease or different CAS record must prevent this Start,
	// despite the original permit already being irreversibly consumed.
	if labRecoveryStartedFinalGate(p, f, b, time.Now().UTC()) != nil {
		return fail("ENTRY_REJECTED", "STATE_REJECTED")
	}
	if artifactContext(phaseCtx) != nil || !labRecoveryStartedBindingValid(b, time.Now().UTC()) {
		return fail("ENTRY_REJECTED", "BUDGET_REJECTED")
	}
	now = time.Now().UTC()
	o.StartedAt = &now
	o.StartInvoked = true
	// Exactly one original call. In particular no Start retry, Stop, rollback,
	// numeric PID adoption or phase-context cancellation of the child is added.
	kernel, err = startOwnedLabKernel(lifetimeCtx, in, artifact)
	o.StartReturned = true
	class := "NONE"
	if err != nil {
		class = "FAILED"
	}
	o.StartErrorClass = &class
	if kernel == nil {
		var original *labKernelStartError
		if errors.As(err, &original) && original != nil {
			kernel = original.owned()
			v := original.observation()
			o.StartObservation = &v
		}
	}
	if kernel != nil {
		v := kernel.startObservation()
		o.StartObservation = &v
	}
	if err != nil || kernel == nil {
		return fail("START_UNCERTAIN", "START_REJECTED")
	}
	if artifactContext(phaseCtx) != nil || !labRecoveryStartedBindingValid(b, time.Now().UTC()) {
		return fail("START_UNCERTAIN", "BUDGET_REJECTED")
	}
	id, err := kernel.identity()
	if err == nil {
		o.StartupIdentity = &id
	}
	if err != nil || !labRecoveryStartedIdentityValid(id, b) {
		return fail("START_UNCERTAIN", "IDENTITY_REJECTED")
	}
	if err := labRecoveryStartedAwaitListeners(phaseCtx, kernel, id, b); err != nil {
		return fail("START_UNCERTAIN", "LISTENERS_REJECTED")
	}
	before := true
	o.ListenersBefore = &before
	verified, err := kernel.identity()
	if err == nil {
		o.VerifiedIdentity = &verified
	}
	if err != nil || verified != id {
		return fail("START_UNCERTAIN", "IDENTITY_REJECTED")
	}
	after := kernel.verifyListeners() == nil
	o.ListenersAfter = &after
	if !after {
		return fail("START_UNCERTAIN", "LISTENERS_REJECTED")
	}
	seal, err := labRecoveryStartedSeal(kernel, id)
	if err != nil {
		return fail("START_UNCERTAIN", "OWNED_REJECTED")
	}
	core := &labRecoveryStartedEpochCore{issuer: issuer, owner: kernel, seal: seal}
	if _, err := rand.Read(core.nonce[:]); err != nil || core.nonce == ([32]byte{}) {
		return fail("START_UNCERTAIN", "ISSUER_REJECTED")
	}
	if artifactContext(phaseCtx) != nil || !labRecoveryStartedBindingValid(b, time.Now().UTC()) {
		return fail("START_UNCERTAIN", "BUDGET_REJECTED")
	}
	// Refresh measured Start state at the final boundary; never invent Wait=false
	// or complete streams from the earlier return status.
	start := kernel.startObservation()
	o.StartObservation = &start
	now = time.Now().UTC()
	o.ReturnedAt = &now
	o.Outcome, o.FailureCode = "STARTED", "NONE"
	core.fact = labRecoveryStartedFact{Schema: labRecoveryStartedFactSchema, Binding: labRecoveryStartedCloneBinding(b),
		Observation: labRecoveryStartedCloneObservation(o), ObservedAt: now}
	core.fact.StartedSHA256, err = labRecoveryStartedFactHash(core.fact)
	if err != nil || !labRecoveryStartedFactValid(core.fact, b, now) {
		return fail("START_UNCERTAIN", "FACT_REJECTED")
	}
	issuer.mu.Lock()
	issuer.issued[core] = true
	issuer.mu.Unlock()
	return kernel, &labRecoveryStartedEpoch{core: core}, labRecoveryStartedCloneObservation(o), nil
}
