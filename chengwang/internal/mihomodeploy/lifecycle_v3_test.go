package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLifecycleV3ValidationContextRechecksChangedCanonicalSource(t *testing.T) {
	s, _, owner, _, now := lifecycleRecoveryModelPlanned(t)
	if s.revokeRecovery(owner, "MODEL_revoker", "EXPLICIT_REVOKED", now) != nil {
		t.Fatal("MODEL seed history")
	}
	r := lifecycleV3Copy(t, s.core.record)
	if validateLifecycleV3Record(r) != nil {
		t.Fatal("MODEL valid original pass")
	}
	original, err := decodeLifecycleRecord(r.core.SourceV2.ControlBytes)
	if err != nil {
		t.Fatal("MODEL source")
	}
	original.wire.Revision++
	original = lifecycleTestSeal(t, original)
	raw, err := encodeLifecycleRecord(original)
	if err != nil {
		t.Fatal("MODEL independently valid replacement source")
	}
	r.core.SourceV2 = lifecycleLegacySnapshot{lifecycleSchemaV2, labConfigHash(raw), original.wire.RecordSHA256, original.wire.Revision, raw}
	r.core.Current = lifecycleLegacyLedger(original, raw)
	r = lifecycleV3Seal(t, r)
	context, err := lifecycleV3SourceContext(r.core)
	if err != nil {
		t.Fatal("MODEL coherent source envelope did not reach binding check")
	}
	if context.validateDescriptor(r.core.RecoveryHistory[0].Plan) == nil || validateLifecycleV3Record(r) == nil {
		t.Fatal("MODEL stale source context reused across records")
	}
}

func TestLifecycleV3HistoryContextChecksEveryPlanAfterTargetMemoHit(t *testing.T) {
	s, _, owner, p, now := lifecycleRecoveryModelPlanned(t)
	if s.revokeRecovery(owner, "MODEL_revoker", "EXPLICIT_REVOKED", now) != nil {
		t.Fatal("MODEL first archive")
	}
	original, err := lifecycleV3Source(s.core.record.core)
	if err != nil {
		t.Fatal("MODEL source")
	}
	second, err := newLabRecoveryPlan(original, "labrec_"+strings.Repeat("2", 32), p.descriptor().DeclaredInitiatorRef, p.descriptor().TargetArtifact, now, now.Add(time.Minute))
	if err != nil || s.beginRecovery(owner, &second, s.core.record.core.Revision, s.core.record.core.RecordSHA256, now) != nil {
		t.Fatal("MODEL valid second begin")
	}
	if validateLifecycleV3Record(lifecycleV3Copy(t, s.core.record)) != nil {
		t.Fatal("MODEL generic current path rejected")
	}
	if s.revokeRecovery(owner, "MODEL_revoker", "EXPLICIT_REVOKED", now) != nil {
		t.Fatal("MODEL valid second archive")
	}
	if validateLifecycleV3Record(lifecycleV3Copy(t, s.core.record)) != nil {
		t.Fatal("MODEL exact revoked tail rejected")
	}
	for _, kind := range []string{"digest", "time", "budget", "operation", "intent", "head", "epoch", "provisioning", "target"} {
		r := lifecycleV3Copy(t, s.core.record)
		context, err := lifecycleV3SourceContext(r.core)
		if err != nil || context.validateDescriptor(r.core.RecoveryHistory[0].Plan) != nil {
			t.Fatal("MODEL first plan/memo seed")
		}
		d := r.core.RecoveryHistory[1].Plan
		switch kind {
		case "time":
			d.ExpiresAt = d.CreatedAt
		case "budget":
			d.Budgets.StopMillis++
		case "operation":
			d.UnknownOperationID = "MODEL_other_operation"
		case "intent":
			d.OriginalIntentSHA256 = strings.Repeat("d", 64)
		case "head":
			d.PreviousHeadSHA256 = strings.Repeat("d", 64)
		case "epoch":
			d.OldEpochSHA256 = strings.Repeat("d", 64)
		case "provisioning":
			d.Provisioning.MarkerSHA256 = strings.Repeat("d", 64)
		case "target":
			d.TargetArtifact.SourceSpecBytes++
		}
		d = labRecoveryPlanModelReseal(t, d)
		if kind == "digest" {
			d.PlanSHA256 = strings.Repeat("d", 64)
		}
		if context.validateDescriptor(d) == nil {
			t.Fatal("MODEL per-plan check skipped after target cache hit")
		}
		r.core.RecoveryHistory[1].Plan = d
		r.core.Recovery.Plan = d
		r = lifecycleV3Seal(t, r)
		if validateLifecycleV3Record(r) == nil {
			t.Fatal("MODEL invalid history accepted in full record")
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*lifecycleV3Wire)
	}{
		{"current_only_generic_fallback", func(w *lifecycleV3Wire) {
			d := w.Recovery.Plan
			d.TargetArtifact.SourceSpecBytes++
			w.Recovery.Plan = labRecoveryPlanModelReseal(t, d)
		}},
		{"history_only", func(w *lifecycleV3Wire) {
			i := len(w.RecoveryHistory) - 1
			d := w.RecoveryHistory[i].Plan
			d.TargetArtifact.SourceSpecBytes++
			w.RecoveryHistory[i].Plan = labRecoveryPlanModelReseal(t, d)
		}},
		{"source_current_only_fallback", func(w *lifecycleV3Wire) {
			d := w.Recovery.Plan
			d.Source = &labRecoveryPlanSource{}
			w.Recovery.Plan = d
		}},
		{"phase_completed_current_only", func(w *lifecycleV3Wire) {
			w.Recovery.Phase = "COMPLETED"
		}},
		{"phase_failed_reconciled_current_only", func(w *lifecycleV3Wire) {
			w.Recovery.Phase = "FAILED_RECONCILED"
		}},
		{"execution_current_only_fallback", func(w *lifecycleV3Wire) {
			w.Recovery.Execution = &lifecycleRecoveryExecution{}
		}},
		{"reconciliation_current_only_fallback", func(w *lifecycleV3Wire) {
			w.Recovery.Reconciliation = &lifecycleRecoveryReconciliation{}
		}},
		{"id_seen_non_tail", func(w *lifecycleV3Wire) {
			nonTail := w.RecoveryHistory[0]
			w.Recovery = &nonTail
		}},
		{"same_plan_digest_txn_nested_diff", func(w *lifecycleV3Wire) {
			w.Recovery.Revocation.Reason = "AUTHORITY_CHANGED"
		}},
		{"owner_fence", func(w *lifecycleV3Wire) { w.RecoveryOwner.Fence++ }},
		{"trusted_time", func(w *lifecycleV3Wire) {
			w.LastTrustedAt = w.RecoveryHistory[len(w.RecoveryHistory)-1].UpdatedAt.Add(-time.Nanosecond)
		}},
		{"later_schema_missing_checkpoint_history_reject", func(w *lifecycleV3Wire) {
			i := len(w.RecoveryHistory) - 1
			d := w.RecoveryHistory[i].Plan
			d.Schema = labRecoveryPlanSchemaV2
			w.RecoveryHistory[i].Plan = d
			w.Recovery.Plan = d
		}},
	} {
		t.Run("tail_reuse_rejects_"+tc.name, func(t *testing.T) {
			r := lifecycleV3Copy(t, s.core.record)
			tc.mutate(r.core)
			r = lifecycleV3Seal(t, r)
			if validateLifecycleV3Record(r) == nil {
				t.Fatal("MODEL invalid current/history context accepted")
			}
		})
	}
}

// MODEL ONLY: canonical structure and process-local guards. No authentication,
// owned kernel, real quiescence, filesystem durability or recovery is proven.
func lifecycleV3Model(t *testing.T) (lifecycleV3Record, labRecoveryPlan, lifecycleRecord, time.Time) {
	t.Helper()
	p, original, now := labRecoveryPlanModel(t)
	raw, err := encodeLifecycleRecord(original)
	if err != nil {
		t.Fatal("MODEL legacy encode")
	}
	r, err := buildLifecycleV3Evolution(raw, &p, now)
	if err != nil {
		t.Fatal("MODEL evolution")
	}
	return r, p, original, now
}
func lifecycleV3Seal(t *testing.T, r lifecycleV3Record) lifecycleV3Record {
	t.Helper()
	var err error
	r.core.RecordSHA256, err = lifecycleV3RecordHash(*r.core)
	if err != nil {
		t.Fatal("MODEL digest")
	}
	return r
}
func lifecycleV3Copy(t *testing.T, r lifecycleV3Record) lifecycleV3Record {
	t.Helper()
	raw, err := encodeLifecycleV3Record(r)
	if err != nil {
		t.Fatal("MODEL encode")
	}
	r, err = decodeLifecycleV3Record(raw)
	if err != nil {
		t.Fatal("MODEL decode")
	}
	return r
}
func lifecycleV3Reject(t *testing.T, r lifecycleV3Record) {
	t.Helper()
	r = lifecycleV3Seal(t, r)
	if _, err := encodeLifecycleV3Record(r); err == nil {
		t.Fatal("MODEL malformed record accepted")
	}
}

func TestLifecycleV3CanonicalRoundtripPreservesExactLegacySource(t *testing.T) {
	r, _, original, _ := lifecycleV3Model(t)
	raw, err := encodeLifecycleV3Record(r)
	if err != nil {
		t.Fatal("MODEL encode")
	}
	a, err := decodeLifecycleV3Record(raw)
	if err != nil {
		t.Fatal("MODEL decode")
	}
	again, _ := encodeLifecycleV3Record(a)
	old, _ := encodeLifecycleRecord(original)
	if !bytes.Equal(raw, again) || !bytes.Equal(old, a.core.SourceV2.ControlBytes) || a.core.SourceV2.ControlSHA256 != labConfigHash(old) || !reflect.DeepEqual(a.core.Current.Active, original.wire.Active) {
		t.Fatal("MODEL exact source lost")
	}
	// Detached inputs and decoded copies may not mutate the original snapshot.
	a.core.SourceV2.ControlBytes[0] = '!'
	if bytes.Equal(a.core.SourceV2.ControlBytes, r.core.SourceV2.ControlBytes) {
		t.Fatal("MODEL source aliased")
	}
}
func TestLifecycleV3LegacyDecoderAndGoldenBytesRemainUnchanged(t *testing.T) {
	r, _, original, _ := lifecycleV3Model(t)
	old, _ := encodeLifecycleRecord(original)
	v3, _ := encodeLifecycleV3Record(r)
	if _, err := decodeLifecycleRecord(v3); err == nil {
		t.Fatal("MODEL legacy decoder accepted v3")
	}
	if _, err := decodeLifecycleV3Record(old); err == nil {
		t.Fatal("MODEL v3 decoder accepted v2")
	}
	again, _ := encodeLifecycleRecord(original)
	if !bytes.Equal(old, again) {
		t.Fatal("MODEL legacy changed")
	}
	v1, _, _ := lifecycleTestRecord(t)
	raw, _ := encodeLifecycleRecord(v1)
	if _, err := decodeLifecycleRecord(raw); err != nil {
		t.Fatal("MODEL v1 regression")
	}
}
func TestLifecycleV3RejectsDuplicateUnknownMissingNullAndAliases(t *testing.T) {
	r, _, _, _ := lifecycleV3Model(t)
	raw, _ := encodeLifecycleV3Record(r)
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":0,"schema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":null,"schema":`), 1),
		bytes.Replace(raw, []byte(`"retiredEpochs":[]`), []byte(`"retiredEpochs":null`), 1),
		bytes.Replace(raw, []byte(`"recoveryHistory":[]`), []byte(`"recoveryHistory":null`), 1),
		bytes.Replace(raw, []byte(`"recovery":null,`), nil, 1),
		bytes.Replace(raw, []byte(`"lastRecoveryFence"`), []byte(`"LastRecoveryFence"`), 1),
	} {
		if _, err := decodeLifecycleV3Record(bad); err == nil {
			t.Fatal("MODEL shape accepted")
		}
	}
}
func TestLifecycleV3RejectsFloatingNumbersWhitespaceDepthAndOversize(t *testing.T) {
	r, _, _, _ := lifecycleV3Model(t)
	raw, _ := encodeLifecycleV3Record(r)
	badNumber := bytes.Replace(raw, []byte(`"lastRecoveryFence":0`), []byte(`"lastRecoveryFence":0.0`), 1)
	depth := []byte(`{"a":` + strings.Repeat("[", 25) + "0" + strings.Repeat("]", 25) + "}")
	for _, bad := range [][]byte{badNumber, append(bytes.Clone(raw), ' '), depth, bytes.Repeat([]byte(" "), maxLifecycleControlBytes+1)} {
		if _, err := decodeLifecycleV3Record(bad); err == nil {
			t.Fatal("MODEL resource/canonical gate")
		}
	}
}
func TestLifecycleV3SourceSnapshotRejectsHashSchemaMarkerAndRewrittenFacts(t *testing.T) {
	for _, kind := range []string{"hash", "schema", "bytes", "revision", "marker", "active"} {
		r, _, _, _ := lifecycleV3Model(t)
		switch kind {
		case "hash":
			r.core.SourceV2.ControlSHA256 = strings.Repeat("f", 64)
		case "schema":
			r.core.SourceV2.Schema = lifecycleSchema
		case "bytes":
			r.core.SourceV2.ControlBytes = append(r.core.SourceV2.ControlBytes, ' ')
			r.core.SourceV2.ControlSHA256 = labConfigHash(r.core.SourceV2.ControlBytes)
		case "revision":
			r.core.SourceV2.Revision++
		case "marker":
			r.core.Provisioning.MarkerSHA256 = strings.Repeat("f", 64)
		case "active":
			r.core.Current.Active.Result = nil
			r.core.Current.Active.Phase = "DISPATCH_ARMED"
		}
		lifecycleV3Reject(t, r)
	}
}
func TestLifecycleV3UnknownResultAndObservationsCannotBeErased(t *testing.T) {
	p, original, now := labRecoveryPlanModel(t)
	original.wire.V2.Observations = append(original.wire.V2.Observations, lifecycleObservationRecord{original.wire.Active.Plan.OperationID, original.wire.Active.Plan.PlanSHA256, original.wire.Active.Intent.IntentSHA256, lifecycleReadback{lifecycleObservationConclusion, strings.Repeat("e", 64), now}, original.wire.Revision})
	original = lifecycleTestSeal(t, original)
	p, err := newLabRecoveryPlan(original, p.descriptor().RecoveryID, p.descriptor().DeclaredInitiatorRef, p.descriptor().TargetArtifact, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal("MODEL observation plan")
	}
	raw, _ := encodeLifecycleRecord(original)
	r, err := buildLifecycleV3Evolution(raw, &p, now)
	if err != nil {
		t.Fatal("MODEL observation evolution")
	}
	r.core.Current.Observations = []lifecycleObservationRecord{}
	lifecycleV3Reject(t, r)
}
func TestLifecycleV3AnchorCannotChangeGenerationPreviousOrEpoch(t *testing.T) {
	for _, kind := range []string{"generation", "previous", "pid", "source", "kind"} {
		r, _, _, _ := lifecycleV3Model(t)
		switch kind {
		case "generation":
			r.core.Current.Anchor.InitialHead.Generation++
		case "previous":
			v := strings.Repeat("e", 64)
			r.core.Current.Anchor.InitialHead.PreviousHeadSHA256 = &v
		case "pid":
			r.core.Current.Anchor.InitialHead.PID++
		case "source":
			r.core.Current.Anchor.SourceControlSHA256 = strings.Repeat("e", 64)
		case "kind":
			r.core.Current.Anchor.Kind = "RECOVERED_EPOCH"
		}
		lifecycleV3Reject(t, r)
	}
}
func TestLifecycleV3RetiredEpochRequiresMatchingCompleteRecoveryChain(t *testing.T) {
	r, _, _, now := lifecycleV3Model(t)
	id := "labrec_" + strings.Repeat("2", 32)
	ledger := r.core.Current
	sha, _ := lifecycleHash(ledger)
	r.core.RetiredEpochs = append(r.core.RetiredEpochs, lifecycleRetiredEpoch{ledger, now, r.core.Revision, id, sha})
	lifecycleV3Reject(t, r) // A ledger and digest alone are not a completed recovery.
}
func TestLifecycleV3RejectsNullNestedDescriptorAndHistoryLists(t *testing.T) {
	for _, kind := range []string{"requirements", "blockers", "capabilities", "tombstones", "completed", "observations", "terminated"} {
		r, _, _, _ := lifecycleV3Model(t)
		switch kind {
		case "requirements":
			r.core.Current.Head.Artifact.Config.Requirements = nil
		case "blockers":
			r.core.Current.Head.Artifact.Config.Blockers = nil
		case "capabilities":
			r.core.Current.Head.Artifact.Config.Capabilities = nil
		case "tombstones":
			r.core.Current.Tombstones = nil
		case "completed":
			r.core.Current.Completed = nil
		case "observations":
			r.core.Current.Observations = nil
		case "terminated":
			r.core.Current.Terminated = nil
		}
		lifecycleV3Reject(t, r)
	}
}
func TestLifecycleV3DebugJSONAndInvalidVerbCopiesKeepPrivateCoreOpaque(t *testing.T) {
	r, _, _, _ := lifecycleV3Model(t)
	needle := r.core.Current.Owner.OwnerNonce
	for _, v := range []any{r, &r, lifecycleV3Record{}, (*lifecycleV3Record)(nil)} {
		for _, format := range []string{"%v", "%+v", "%#v", "%x", "%d", "%p"} {
			s := fmt.Sprintf(format, v)
			if strings.Contains(s, needle) || strings.Contains(s, "ControlBytes") || strings.Contains(s, "OwnerNonce") || strings.Contains(s, "sourceV2") {
				t.Fatal("MODEL private debug leak")
			}
		}
		raw, err := json.Marshal(v)
		if err != nil || bytes.Contains(raw, []byte(needle)) || bytes.Contains(raw, []byte("controlBytes")) {
			t.Fatal("MODEL JSON privacy")
		}
	}
	if json.Unmarshal([]byte(`{}`), &r) == nil || r.core != nil {
		t.Fatal("MODEL JSON restored private core")
	}
}
func TestLifecycleV3StructuralBuilderRejectsUnboundPlanAndV1(t *testing.T) {
	_, p, original, now := lifecycleV3Model(t)
	raw, _ := encodeLifecycleRecord(original)
	if _, err := buildLifecycleV3Evolution(raw, nil, now); err == nil {
		t.Fatal("MODEL nil plan accepted")
	}
	copy := p
	p.core = &labRecoveryPlanCore{descriptor: p.descriptor()}
	p.core.descriptor.ExpectedRecordSHA256 = strings.Repeat("e", 64)
	if _, err := buildLifecycleV3Evolution(raw, &p, now); err == nil {
		t.Fatal("MODEL wrong original accepted")
	}
	v1, _, _ := lifecycleTestRecord(t)
	raw, _ = encodeLifecycleRecord(v1)
	if _, err := buildLifecycleV3Evolution(raw, &copy, now); err == nil {
		t.Fatal("MODEL v1 auto-migrated")
	}
}
func TestLifecycleV3StructuralEvolutionDoesNotMintOwnersOrActions(t *testing.T) {
	r, _, original, _ := lifecycleV3Model(t)
	if r.core.RecoveryOwner != nil || r.core.LastRecoveryFence != 0 || r.core.Recovery != nil || len(r.core.RecoveryHistory) != 0 || !reflect.DeepEqual(r.core.Current.Active, original.wire.Active) || r.core.Current.Active.Phase != "UNKNOWN" {
		t.Fatal("MODEL evolution granted an action")
	}
}
