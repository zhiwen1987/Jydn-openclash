//go:build linux

package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// STRUCTURE MODEL ONLY. No native Start, process observation, listener, HTTP,
// authorization or filesystem durability is executed. The WAL transitions,
// exact readback and source capture below are the actual structural methods.
func lifecycleStartedRecordModel(t *testing.T) (*lifecycleRecoveryStore, *lifecycleModelDisk, *lifecycleRecoveryOwnerToken, *labRecoveryStartedEpoch, time.Time) {
	t.Helper()
	s, d, owner, now := lifecycleRecoveryModelQuiesced(t)
	p, err := s.armRecoveryStart(owner, now)
	if err != nil {
		t.Fatal("MODEL arm")
	}
	consumed, err := p.consumeRecoveryStart(now)
	if err != nil {
		t.Fatal("MODEL consume permit")
	}
	b, err := labRecoveryStartedBindingFromPermit(p, consumed, now)
	if err != nil {
		t.Fatal("MODEL source binding")
	}
	source, err := labRecoveryStartedCaptureSource(p, consumed, b, now)
	if err != nil {
		t.Fatal("MODEL exact armed source")
	}
	_, f, _ := labRecoveryStartedModel(t)
	f.Binding = labRecoveryStartedCloneBinding(b)
	id := b.ExpectedOldIdentity
	id.PID++
	id.StartTicks++
	id.ArtifactSHA256 = b.TargetArtifact.Config.SHA256
	startedAt, observedAt := now, now.Add(time.Millisecond)
	f.ObservedAt = observedAt
	f.Observation.StartedAt = &startedAt
	f.Observation.ReturnedAt = &observedAt
	f.Observation.StartupIdentity = &id
	verified := id
	f.Observation.VerifiedIdentity = &verified
	ns := id.NetNSInode
	f.Observation.NamespaceInode = &ns
	pid, ticks := id.PID, id.StartTicks
	f.Observation.StartObservation.PID = &pid
	f.Observation.StartObservation.StartTicks = &ticks
	labRecoveryStartedModelReseal(t, &f)
	if !labRecoveryStartedFactValid(f, b, observedAt) {
		t.Fatal("MODEL happened fact")
	}
	k, _, _, _ := labQuiescenceOwnedModel(t)
	k.process.Pid, k.bound = id.PID, id
	k.observedPID, k.observedTicks = &pid, &ticks
	k.input.commit, k.input.binaryHash, k.input.binaryBytes = id.SourceCommit, id.ELFSHA256, id.ELFBytes
	seal, err := labRecoveryStartedSeal(k, id)
	if err != nil {
		t.Fatal("MODEL retained startup")
	}
	i := &labRecoveryStartedIssuer{claimed: map[*labRecoveryStartCore]bool{}, issued: map[*labRecoveryStartedEpochCore]bool{}}
	x := &labRecoveryStartedEpochCore{issuer: i, owner: k, seal: seal, nonce: [32]byte{1}, fact: f, source: source}
	i.issued[x] = true // MODEL only: production issuance remains native-return-only
	return s, d, owner, &labRecoveryStartedEpoch{core: x}, observedAt
}

func TestLifecycleRecoveryStartedRecordPersistsActualSourceWithoutAdvancingHead(t *testing.T) {
	s, d, owner, q, now := lifecycleStartedRecordModel(t)
	before := lifecycleV3Copy(t, s.core.record)
	writes := d.writes
	if s.recordRecoveryStarted(owner, q, now) != nil || d.writes != writes+1 || s.core.startedRecord != nil {
		t.Fatal("MODEL source-owned append")
	}
	w := s.core.record.core
	e := w.Recovery.Execution
	if e == nil || e.Schema != lifecycleRecoveryExecutionSchema || e.Started.StartedSHA256 != q.core.fact.StartedSHA256 || e.StartedCommitRevision != w.Revision || !e.RecordedAt.Equal(now) ||
		w.Recovery.Phase != "START_ARMED" || w.Recovery.Completion != nil || s.core.permit != nil || !reflect.DeepEqual(w.Current, before.core.Current) || !reflect.DeepEqual(w.SourceV2, before.core.SourceV2) || !reflect.DeepEqual(w.RecoveryHistory, before.core.RecoveryHistory) {
		t.Fatal("MODEL record changed original UNKNOWN or minted completion")
	}
	raw, err := lifecycleRecoveryArmedPreimage(w, *w.Recovery)
	if err != nil || string(raw) != q.core.source.canonical {
		t.Fatal("MODEL armed hash was only a declaration")
	}
	if _, err := decodeLifecycleV3Record(d.raw); err != nil {
		t.Fatal("MODEL durable strict roundtrip")
	}
	copy := lifecycleV3Copy(t, s.core.record)
	copy.core.Recovery.Execution.Started.Binding.TargetArtifact.Config.Capabilities = nil
	if !reflect.DeepEqual(s.core.record.core.Recovery.Execution.Started.Binding.TargetArtifact, q.core.fact.Binding.TargetArtifact) {
		t.Fatal("MODEL detached decode aliased WAL")
	}
}

func TestLifecycleRecoveryStartedRecordLateRevocationKeepsOriginalFailure(t *testing.T) {
	for _, reason := range []string{"EXPLICIT_REVOKED", "AUTHORITY_CHANGED", "EXPIRED"} {
		t.Run(reason, func(t *testing.T) {
			s, d, owner, q, now := lifecycleStartedRecordModel(t)
			if s.revokeRecovery(owner, "MODEL_revoker", reason, now) != nil {
				t.Fatal("MODEL revoke")
			}
			prior := lifecycleV3Copy(t, s.core.record)
			writes := d.writes
			if s.recordRecoveryStarted(owner, q, now.Add(time.Millisecond)) != nil || d.writes != writes+1 {
				t.Fatal("MODEL happened fact lost after revocation")
			}
			a := s.core.record.core.Recovery
			if a.Execution == nil || a.Phase != "RECOVERY_UNKNOWN" || !reflect.DeepEqual(a.Failure, prior.core.Recovery.Failure) || !reflect.DeepEqual(a.Revocation, prior.core.Recovery.Revocation) || a.Completion != nil || s.core.permit != nil {
				t.Fatal("MODEL revocation history or permission restored")
			}
		})
	}
}

func TestLifecycleRecoveryStartedRecordExpiryPreservesFactWithoutNewPermission(t *testing.T) {
	s, d, owner, q, now := lifecycleStartedRecordModel(t)
	expired := s.core.record.core.RecoveryOwner.ExpiresAt.Add(time.Nanosecond)
	if expired.Before(now) {
		t.Fatal("MODEL expiry fixture")
	}
	writes := d.writes
	if s.recordRecoveryStarted(owner, q, expired) != nil || d.writes != writes+1 {
		t.Fatal("MODEL expired happened fact rejected")
	}
	a := s.core.record.core.Recovery
	if a.Phase != "RECOVERY_UNKNOWN" || a.Execution == nil || a.Failure == nil || a.Failure.Code != "EXPIRED" || a.Completion != nil || s.core.permit != nil {
		t.Fatal("MODEL expired fact restored action")
	}
	if _, err := s.armRecoveryStart(owner, expired); err == nil {
		t.Fatal("MODEL repeated Start after happened fact")
	}
}

func TestLifecycleRecoveryStartedRecordRejectsCopiesJSONAndCrossStoreSource(t *testing.T) {
	s, d, owner, q, now := lifecycleStartedRecordModel(t)
	copy := *q
	if s.recordRecoveryStarted(owner, q, now) != nil {
		t.Fatal("MODEL first append")
	}
	writes := d.writes
	if s.recordRecoveryStarted(owner, &copy, now) == nil || d.writes != writes {
		t.Fatal("MODEL copied capability replay")
	}
	var imported labRecoveryStartedEpoch
	raw, _ := json.Marshal(q)
	if json.Unmarshal(raw, &imported) == nil || s.recordRecoveryStarted(owner, &imported, now) == nil {
		t.Fatal("MODEL JSON fact became a source")
	}
	for _, kind := range []string{"foreign", "rewrittenOrigin", "copiedSource", "rewrittenPreimage"} {
		t.Run(kind, func(t *testing.T) {
			original, originalDisk, originalOwner, cap, at := lifecycleStartedRecordModel(t)
			other, otherDisk, otherOwner, _, _ := lifecycleStartedRecordModel(t)
			target, disk, token := other, otherDisk, otherOwner
			switch kind {
			case "rewrittenOrigin":
				cap.core.source.store = other.core
			case "copiedSource":
				v := *cap.core.source
				cap.core.source = &v
				target, disk, token = original, originalDisk, originalOwner
			case "rewrittenPreimage":
				cap.core.source.canonical += " "
				target, disk, token = original, originalDisk, originalOwner
			}
			before := disk.writes
			if target.recordRecoveryStarted(token, cap, at) == nil || disk.writes != before {
				t.Fatal("MODEL mismatched origin/source published")
			}
			if _, err := cap.consumeStartedEpochForRecord(cap.core.fact.Binding, at); err == nil {
				t.Fatal("MODEL failed source attempt was reusable")
			}
		})
	}
}

func TestLifecycleRecoveryStartedRecordFailedPublicationDoesNotAdoptOrRetry(t *testing.T) {
	for _, state := range []lifecycleCommitState{lifecycleNotCommitted, lifecycleUnknown} {
		s, d, owner, q, now := lifecycleStartedRecordModel(t)
		before := bytes.Clone(s.core.raw)
		writes := d.writes
		d.state = state
		if s.recordRecoveryStarted(owner, q, now) == nil || d.writes != writes+1 || s.core.record.core.Recovery.Execution != nil || !bytes.Equal(before, s.core.raw) || s.core.startedRecord != nil {
			t.Fatal("MODEL failed write adopted candidate")
		}
		if state == lifecycleUnknown && (!s.core.poisoned || s.core.validated != nil) {
			t.Fatal("MODEL unknown publication remained writable")
		}
		d.state = lifecycleCommitted
		if s.recordRecoveryStarted(owner, q, now) == nil || d.writes != writes+1 {
			t.Fatal("MODEL failed fact retried write")
		}
	}
}

func TestLifecycleRecoveryStartedRecordReopenClockAndOwnerCannotMintPermission(t *testing.T) {
	for _, kind := range []string{"reopen", "rollback", "owner", "close"} {
		t.Run(kind, func(t *testing.T) {
			s, d, owner, q, now := lifecycleStartedRecordModel(t)
			target, token, at := s, owner, now
			switch kind {
			case "reopen":
				var err error
				target, err = openLifecycleRecoveryStore(d, now)
				if err != nil || target.core.live != nil || target.core.permit != nil {
					t.Fatal("MODEL reopen capability restoration")
				}
			case "rollback":
				at = s.core.record.core.LastTrustedAt.Add(-time.Nanosecond)
			case "owner":
				v := *owner.core
				token = &lifecycleRecoveryOwnerToken{core: &v}
			case "close":
				if s.close() != nil {
					t.Fatal("MODEL close")
				}
			}
			writes := d.writes
			if target.recordRecoveryStarted(token, q, at) == nil || d.writes != writes || target.core.record.core.Recovery.Execution != nil {
				t.Fatal("MODEL stale context recorded or minted execution")
			}
			if kind == "rollback" && !s.core.poisoned {
				t.Fatal("MODEL clock poison removed")
			}
		})
	}
}

func TestLifecycleRecoveryStartedExecutionCodecRejectsAlteredFactsAndPreimage(t *testing.T) {
	s, d, owner, q, now := lifecycleStartedRecordModel(t)
	if s.recordRecoveryStarted(owner, q, now) != nil {
		t.Fatal("MODEL record")
	}
	for _, kind := range []string{"version", "fact", "revision", "time", "owner", "clock", "fence", "prefix", "armedHash", "stream", "head", "completion"} {
		t.Run(kind, func(t *testing.T) {
			r := lifecycleV3Copy(t, s.core.record)
			e := r.core.Recovery.Execution
			switch kind {
			case "version":
				e.Schema = "chengwang.mihomo-recovery-execution/v2"
			case "fact":
				e.Started.Observation.StartInvoked = false
			case "revision":
				e.StartedCommitRevision = e.Started.Binding.Revision
			case "time":
				e.RecordedAt = e.Started.ObservedAt.Add(-time.Nanosecond)
			case "owner":
				e.ArmedOwner.OwnerNonce = strings.Repeat("9", 64)
			case "clock":
				e.ArmedLastTrustedAt = e.ArmedLastTrustedAt.Add(-time.Nanosecond)
			case "fence":
				e.ArmedLastRecoveryFence++
			case "prefix":
				e.ArmedFailedQuiescence = nil
			case "armedHash":
				e.Started.Binding.RecordSHA256 = strings.Repeat("9", 64)
				labRecoveryStartedModelReseal(t, &e.Started)
			case "stream":
				e.Started.Observation.StartObservation.Stdout.TotalBytes++
				labRecoveryStartedModelReseal(t, &e.Started)
			case "head":
				r.core.Current.Head.PID++
			case "completion":
				r.core.Recovery.Phase = "COMPLETED"
			}
			r.core.RecordSHA256, _ = lifecycleV3RecordHash(*r.core)
			raw, _ := json.Marshal(r.core)
			if _, err := decodeLifecycleV3Record(raw); err == nil {
				t.Fatal("MODEL forged execution accepted after outer hash reseal")
			}
		})
	}
	for _, key := range []string{"started", "armedOwner", "recordedAt", "startedCommitRevision"} {
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(d.raw, &fields)
		var recovery map[string]json.RawMessage
		_ = json.Unmarshal(fields["recovery"], &recovery)
		var execution map[string]json.RawMessage
		_ = json.Unmarshal(recovery["execution"], &execution)
		delete(execution, key)
		recovery["execution"], _ = json.Marshal(execution)
		fields["recovery"], _ = json.Marshal(recovery)
		raw, _ := json.Marshal(fields)
		var typed lifecycleV3Wire
		if json.Unmarshal(raw, &typed) != nil || lifecycleRecoveryExecutionFieldsValid(*typed.Recovery, typed.LastTrustedAt, typed.Revision) {
			t.Fatal("MODEL missing execution field retained valid typed semantics")
		}
		if _, err := decodeLifecycleV3Record(raw); err == nil {
			t.Fatal("MODEL missing execution key accepted")
		}
	}
}

func TestLifecycleRecoveryStartedExecutionCannotUseGenericPublisherOrBeRemoved(t *testing.T) {
	s, d, owner, q, now := lifecycleStartedRecordModel(t)
	if s.recordRecoveryStarted(owner, q, now) != nil {
		t.Fatal("MODEL record")
	}
	for _, kind := range []string{"remove", "replace", "advanceHead"} {
		r := lifecycleV3Copy(t, s.core.record)
		switch kind {
		case "remove":
			r.core.Recovery.Execution = nil
		case "replace":
			r.core.Recovery.Execution.RecordedAt = now.Add(time.Second)
		case "advanceHead":
			r.core.Current.Head.Generation++
		}
		writes := d.writes
		if s.core.commit(r, now) == nil || d.writes != writes {
			t.Fatal("MODEL generic publisher changed source-owned execution")
		}
	}
	other, otherDisk, _, _, _ := lifecycleStartedRecordModel(t)
	draft := lifecycleV3Copy(t, other.core.record)
	draft.core.Recovery.Execution = s.core.record.core.Recovery.Execution
	writes := otherDisk.writes
	if other.core.commit(draft, now) == nil || otherDisk.writes != writes {
		t.Fatal("MODEL DTO execution injected through generic transition")
	}
}

type lifecycleStartedReadbackFault struct {
	disk        *lifecycleModelDisk
	afterWrites int
	custody     bool
}

func (d *lifecycleStartedReadbackFault) verify() error {
	if d.custody && d.disk.writes > d.afterWrites {
		return errLifecycleUnsafe
	}
	return d.disk.verify()
}
func (d *lifecycleStartedReadbackFault) readControl() ([]byte, bool, error) {
	if !d.custody && d.disk.writes > d.afterWrites {
		return nil, false, errLifecycleUnsafe
	}
	return d.disk.readControl()
}
func (d *lifecycleStartedReadbackFault) replaceControl(raw []byte) (lifecycleCommitState, error) {
	return d.disk.replaceControl(raw)
}
func (d *lifecycleStartedReadbackFault) close() error { return d.disk.close() }

func TestLifecycleRecoveryStartedRecordFailedActualReadbackNeverAdoptsCandidate(t *testing.T) {
	for _, custody := range []bool{false, true} {
		s, d, owner, q, now := lifecycleStartedRecordModel(t)
		before := bytes.Clone(s.core.raw)
		writes := d.writes
		s.core.disk = &lifecycleStartedReadbackFault{disk: d, afterWrites: writes, custody: custody}
		if s.recordRecoveryStarted(owner, q, now) == nil || d.writes != writes+1 || !s.core.poisoned || s.core.validated != nil || s.core.record.core.Recovery.Execution != nil || !bytes.Equal(s.core.raw, before) {
			t.Fatal("MODEL missing exact readback adopted physical fact")
		}
		if s.recordRecoveryStarted(owner, q, now) == nil || d.writes != writes+1 {
			t.Fatal("MODEL failed readback repeated write")
		}
	}
}

func TestLifecycleRecoveryStartedRecordedReopenKeepsFactButNoLiveCapability(t *testing.T) {
	s, d, owner, q, now := lifecycleStartedRecordModel(t)
	if s.recordRecoveryStarted(owner, q, now) != nil {
		t.Fatal("MODEL record")
	}
	fact := labRecoveryStartedCloneFact(s.core.record.core.Recovery.Execution.Started)
	sourceV2 := bytes.Clone(s.core.record.core.SourceV2.ControlBytes)
	opened, err := openLifecycleRecoveryStore(d, now.Add(time.Millisecond))
	if err != nil || opened.core.live != nil || opened.core.permit != nil || opened.core.startedRecord != nil || opened.core.record.core.Recovery.Phase != "RECOVERY_UNKNOWN" ||
		!reflect.DeepEqual(opened.core.record.core.Recovery.Execution.Started, fact) || !bytes.Equal(opened.core.record.core.SourceV2.ControlBytes, sourceV2) {
		t.Fatal("MODEL reopen changed happened fact or restored authority")
	}
	writes := d.writes
	if opened.recordRecoveryStarted(owner, q, now.Add(time.Millisecond)) == nil || d.writes != writes {
		t.Fatal("MODEL reopened capability imported")
	}
}

func TestLifecycleRecoveryStartedRecordConcurrentCopiesWriteExactlyOnce(t *testing.T) {
	s, d, owner, q, now := lifecycleStartedRecordModel(t)
	copy := *q
	results := make(chan error, 2)
	writes := d.writes
	go func() { results <- s.recordRecoveryStarted(owner, q, now) }()
	go func() { results <- s.recordRecoveryStarted(owner, &copy, now) }()
	accepted := 0
	for i := 0; i < 2; i++ {
		if <-results == nil {
			accepted++
		}
	}
	if accepted != 1 || d.writes != writes+1 || s.core.record.core.Recovery.Execution == nil {
		t.Fatal("MODEL concurrent copies did not share one admitted write")
	}
}

func TestLifecycleRecoveryStartedExecutionNilMatchesOrderedOldTxnBytes(t *testing.T) {
	s, _, owner, _, now := lifecycleStartedRecordModel(t)
	for i := 0; i < 2; i++ {
		a := s.core.record.core.Recovery
		// Frozen old ordered shape, before the optional execution member existed.
		old := struct {
			Plan             labRecoveryPlanDescriptor      `json:"plan"`
			Phase            string                         `json:"phase"`
			Approval         *lifecycleRecoveryApproval     `json:"approval"`
			Revocation       *lifecycleRevocation           `json:"revocation"`
			StopIntent       *lifecycleRecoveryActionIntent `json:"stopIntent"`
			StopBinding      *labQuiescenceBinding          `json:"stopBinding"`
			Quiescence       *labQuiescenceFact             `json:"quiescence"`
			FailedQuiescence []labQuiescenceObservation     `json:"failedQuiescence"`
			StartIntent      *lifecycleRecoveryActionIntent `json:"startIntent"`
			Completion       *lifecycleRecoveryCompletion   `json:"completion"`
			Failure          *lifecycleRecoveryFailure      `json:"failure"`
			UpdatedAt        time.Time                      `json:"updatedAt"`
		}{a.Plan, a.Phase, a.Approval, a.Revocation, a.StopIntent, a.StopBinding, a.Quiescence, a.FailedQuiescence, a.StartIntent, a.Completion, a.Failure, a.UpdatedAt}
		oldBytes, err := json.Marshal(old)
		currentBytes, currentErr := json.Marshal(a)
		if err != nil || currentErr != nil || !bytes.Equal(oldBytes, currentBytes) || bytes.Contains(s.core.raw, []byte(`"execution"`)) {
			t.Fatal("MODEL nil execution changed old canonical transaction bytes")
		}
		withNull := append(bytes.Clone(oldBytes[:len(oldBytes)-1]), []byte(`,"execution":null}`)...)
		raw := bytes.Replace(s.core.raw, oldBytes, withNull, 1)
		if bytes.Equal(raw, s.core.raw) {
			t.Fatal("MODEL null test did not replace actual transaction")
		}
		if _, err := decodeLifecycleV3Record(raw); err == nil {
			t.Fatal("MODEL explicit null extension bypassed canonical omission")
		}
		if i == 0 && s.revokeRecovery(owner, "MODEL_revoker", "EXPLICIT_REVOKED", now) != nil {
			t.Fatal("MODEL old revoked shape")
		}
	}
}

func TestLifecycleRecoveryStartedRecordRejectsNilAndMissingOriginWithoutRetry(t *testing.T) {
	for _, kind := range []string{"nil", "empty", "copiedCore", "missingOrigin"} {
		t.Run(kind, func(t *testing.T) {
			s, d, owner, q, now := lifecycleStartedRecordModel(t)
			cap := q
			switch kind {
			case "nil":
				cap = nil
			case "empty":
				cap = &labRecoveryStartedEpoch{}
			case "copiedCore":
				x := *q.core
				cap = &labRecoveryStartedEpoch{core: &x}
			case "missingOrigin":
				cap.core.source = nil
			}
			writes := d.writes
			if s.recordRecoveryStarted(owner, cap, now) == nil || d.writes != writes {
				t.Fatal("MODEL missing source recorded a DTO")
			}
			if kind == "missingOrigin" {
				if _, err := q.consumeStartedEpochForRecord(q.core.fact.Binding, now); err == nil {
					t.Fatal("MODEL rejected known source was not spent")
				}
			}
		})
	}
}

func TestLifecycleRecoveryStartedRecordEveryAdmittedContextFailureSpendsCapability(t *testing.T) {
	for _, kind := range []string{"nilStore", "wrongToken", "wrongPhase", "custodyFailure"} {
		t.Run(kind, func(t *testing.T) {
			s, d, owner, q, now := lifecycleStartedRecordModel(t)
			target, token := s, owner
			switch kind {
			case "nilStore":
				target = nil
			case "wrongToken":
				copy := *owner.core
				token = &lifecycleRecoveryOwnerToken{core: &copy}
			case "wrongPhase":
				other, _, otherOwner, _ := lifecycleRecoveryModelQuiesced(t)
				target, token = other, otherOwner
				if target.core.record.core.Recovery.Phase != "OLD_EPOCH_QUIESCED" {
					t.Fatal("MODEL wrong-phase test did not reach phase rejection")
				}
			case "custodyFailure":
				d.verifyErr = errLifecycleUnsafe
			}
			writes := d.writes
			if target.recordRecoveryStarted(token, q, now) == nil || d.writes != writes {
				t.Fatal("MODEL context rejection changed original disk")
			}
			d.verifyErr = nil
			if _, err := q.consumeStartedEpochForRecord(q.core.fact.Binding, now); err == nil {
				t.Fatal("MODEL failed context retained issued capability")
			}
			if s.recordRecoveryStarted(owner, q, now) == nil || d.writes != writes {
				t.Fatal("MODEL failed attempt retried against original context")
			}
		})
	}
}

func TestLifecycleRecoveryStartedExecutionGenericEarlyReturnsCannotMintDTO(t *testing.T) {
	seed, _, owner, q, now := lifecycleStartedRecordModel(t)
	if seed.recordRecoveryStarted(owner, q, now) != nil {
		t.Fatal("MODEL actual recorded execution source")
	}
	execution := seed.core.record.core.Recovery.Execution
	for _, kind := range []string{"nilRecovery", "replacementPlan"} {
		t.Run(kind, func(t *testing.T) {
			var before lifecycleV3Record
			if kind == "nilRecovery" {
				s, _, _, _ := lifecycleRecoveryModelStore(t)
				before = lifecycleV3Copy(t, s.core.record)
				if before.core.Recovery != nil {
					t.Fatal("MODEL nil recovery branch not reached")
				}
			} else {
				s, _, token, _, at := lifecycleRecoveryModelPlanned(t)
				if s.revokeRecovery(token, "MODEL_revoker", "EXPLICIT_REVOKED", at) != nil {
					t.Fatal("MODEL replacement precondition")
				}
				before = lifecycleV3Copy(t, s.core.record)
			}
			raw, _ := json.Marshal(before.core)
			var after lifecycleV3Wire
			_ = json.Unmarshal(raw, &after)
			if kind == "nilRecovery" {
				after.Recovery = &lifecycleRecoveryTxn{Phase: "PLANNED"}
			} else {
				after.Recovery.Phase = "PLANNED"
				after.Recovery.Plan.PlanSHA256 = strings.Repeat("9", 64)
			}
			// These are transition-only branch fixtures, not valid records or
			// DTO publication attempts. The positive control proves that the
			// relevant original early branch is actually being exercised.
			if !lifecycleV3Transition(before.core, &after) {
				t.Fatal("MODEL intended generic early branch was not reached")
			}
			after.Recovery.Execution = execution
			if lifecycleV3Transition(before.core, &after) {
				t.Fatal("MODEL early return accepted caller execution DTO")
			}
		})
	}
}

func TestLifecycleRecoveryStartedReserveCoversFullBoundedRecordedFact(t *testing.T) {
	s, _, owner, q, now := lifecycleStartedRecordModel(t)
	// MODEL metadata at the actual writer's bounded size. No raw streams or
	// native process are created. The production writer has the same 64KiB cap.
	for _, stream := range []*labKernelStream{q.core.fact.Observation.StartObservation.Stdout, q.core.fact.Observation.StartObservation.Stderr} {
		stream.Bytes, stream.TotalBytes, stream.Truncated = 64<<10, 1<<63-1, true
	}
	labRecoveryStartedModelReseal(t, &q.core.fact)
	envelope, err := json.Marshal(lifecycleRecoveryStartedReserve(s.core.record.core.Recovery))
	if err != nil {
		t.Fatal("MODEL complete envelope")
	}
	if s.recordRecoveryStarted(owner, q, now) != nil {
		t.Fatal("MODEL valid bounded record")
	}
	actual, err := json.Marshal(s.core.record.core.Recovery.Execution)
	if err != nil || len(actual) > len(envelope) {
		t.Fatal("MODEL started fact exceeded pre-dispatch envelope")
	}
}
