package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
)

func TestLabRecoveryPlanValidationContextRequiresCanonicalSourceAndDetaches(t *testing.T) {
	p, original, now := labRecoveryPlanModel(t)
	raw, err := encodeLifecycleRecord(original)
	if err != nil {
		t.Fatal("MODEL canonical source")
	}
	context, err := newLabRecoveryPlanValidationContext(raw)
	if err != nil || context.validateDescriptor(p.descriptor()) != nil {
		t.Fatal("MODEL context rejected valid source")
	}
	for _, bad := range [][]byte{nil, append(bytes.Clone(raw), ' '), bytes.Replace(raw, []byte(`"schema":`), []byte(`"unexpected":0,"schema":`), 1), bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":null,"schema":`), 1)} {
		if _, err := newLabRecoveryPlanValidationContext(bad); err == nil {
			t.Fatal("MODEL invalid source became validated context")
		}
	}
	notUnknown, err := decodeLifecycleRecord(raw)
	if err != nil {
		t.Fatal("MODEL source copy")
	}
	notUnknown.wire.Active.Phase = "DISPATCH_ARMED"
	notUnknown = lifecycleTestSeal(t, notUnknown)
	otherRaw, err := encodeLifecycleRecord(notUnknown)
	if err != nil {
		t.Fatal("MODEL valid non-UNKNOWN legacy record")
	}
	if _, err := newLabRecoveryPlanValidationContext(otherRaw); err == nil {
		t.Fatal("MODEL context accepted other phase")
	}
	// The source bytes/caller object may change after construction; the context
	// must retain its own canonical decoded facts, not either mutable input.
	raw[0] = '!'
	original.wire.Active.Plan.OperationID = "MODEL_mutated_input"
	if context.validateDescriptor(p.descriptor()) != nil {
		t.Fatal("MODEL context aliases source input")
	}
	if _, err := labRecoveryPlanFromDescriptor(p.descriptor(), original); err == nil {
		t.Fatal("MODEL public reconstruction trusted stale context")
	}
	if _, err := newLabRecoveryPlan(original, p.descriptor().RecoveryID, p.descriptor().DeclaredInitiatorRef, p.descriptor().TargetArtifact, now, now.Add(time.Minute)); err == nil {
		t.Fatal("MODEL public constructor skipped complete source validation")
	}
	var nilContext *labRecoveryPlanValidationContext
	for _, invalid := range []*labRecoveryPlanValidationContext{nilContext, {}, {core: &labRecoveryPlanValidationCore{}}} {
		if invalid.validateDescriptor(p.descriptor()) == nil {
			t.Fatal("MODEL unconstructed context accepted")
		}
	}
}

func TestLabRecoveryPlanValidationContextMemoUsesCompleteArtifactBytes(t *testing.T) {
	p, original, _ := labRecoveryPlanModel(t)
	raw, err := encodeLifecycleRecord(original)
	if err != nil {
		t.Fatal("MODEL canonical source")
	}
	context, err := newLabRecoveryPlanValidationContext(raw)
	if err != nil || context.validateDescriptor(p.descriptor()) != nil || len(context.core.targets) != 1 {
		t.Fatal("MODEL seed target validation")
	}
	for _, mutate := range []func(*ArtifactDescriptor){
		func(d *ArtifactDescriptor) { d.Config.Capabilities = nil },
		func(d *ArtifactDescriptor) { d.Config.Requirements = nil },
		func(d *ArtifactDescriptor) { d.Config.Blockers = nil },
		func(d *ArtifactDescriptor) { d.SourceSpecBytes++ },
		func(d *ArtifactDescriptor) { d.SourceSpecSHA256 = strings.Repeat("e", 64) },
		func(d *ArtifactDescriptor) { d.Config.Bytes++ },
		func(d *ArtifactDescriptor) { d.Schema = "MODEL_wrong_schema" },
	} {
		d := p.descriptor()
		mutate(&d.TargetArtifact)
		// Keep the original RecordSHA256/Config.SHA256 as an adversarial weak
		// cache key; recompute the outer plan digest to reach target validation.
		d = labRecoveryPlanModelReseal(t, d)
		if context.validateDescriptor(d) == nil || len(context.core.targets) != 1 {
			t.Fatal("MODEL malformed descriptor hit digest-only memo")
		}
	}
	d := p.descriptor()
	changed, err := newArtifactDescriptor(d.TargetArtifact.Config, strings.Repeat("f", 64), d.TargetArtifact.SourceSpecBytes+1, d.TargetArtifact.ControllerPort, d.TargetArtifact.MixedPort)
	if err != nil {
		t.Fatal("MODEL coherent alternative artifact")
	}
	d.TargetArtifact = changed
	d = labRecoveryPlanModelReseal(t, d)
	if context.validateDescriptor(d) != nil || len(context.core.targets) != 2 {
		t.Fatal("MODEL full distinct descriptor not independently validated")
	}
	otherContext, err := newLabRecoveryPlanValidationContext(raw)
	if err != nil || len(otherContext.core.targets) != 0 {
		t.Fatal("MODEL target memo leaked across validation passes")
	}
}

// MODEL ONLY: declared records, descriptors and budgets. These tests do not
// own a real process, authenticate an actor, approve recovery or touch storage.
func labRecoveryPlanModelOriginal(t *testing.T) (lifecycleRecord, ArtifactDescriptor, time.Time) {
	t.Helper()
	s, _, _, _, now := labV2TestArmed(t)
	r, err := s.copyRecord()
	if err != nil {
		t.Fatal("MODEL original copy")
	}
	r.wire.Active.Phase = "UNKNOWN"
	r = lifecycleTestSeal(t, r)
	if _, err := encodeLifecycleRecord(r); err != nil {
		t.Fatal("MODEL UNKNOWN original invalid")
	}
	return r, cloneArtifactDescriptor(r.wire.Active.Plan.Artifact), now
}

func labRecoveryPlanModel(t *testing.T) (labRecoveryPlan, lifecycleRecord, time.Time) {
	t.Helper()
	r, target, now := labRecoveryPlanModelOriginal(t)
	p, err := newLabRecoveryPlan(r, "labrec_"+strings.Repeat("1", 32), "MODEL_recovery_initiator", target, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal("MODEL recovery plan")
	}
	return p, r, now
}

func labRecoveryPlanModelReseal(t *testing.T, d labRecoveryPlanDescriptor) labRecoveryPlanDescriptor {
	t.Helper()
	var err error
	d.PlanSHA256, err = labRecoveryPlanDigest(d)
	if err != nil {
		t.Fatal("MODEL attack reseal")
	}
	return d
}

func TestLabRecoveryPlanModelCanonicalDescriptorBindsActualOriginalFields(t *testing.T) {
	p, r, now := labRecoveryPlanModel(t)
	d := p.descriptor()
	if d.Schema != labRecoveryPlanSchema || d.Boundary != labRecoveryPlanBoundary || d.UnknownOperationID != r.wire.Active.Plan.OperationID ||
		d.OriginalPlanSHA256 != r.wire.Active.Plan.PlanSHA256 || d.OriginalIntentSHA256 != r.wire.Active.Intent.IntentSHA256 ||
		d.ExpectedRevision != r.wire.Revision || d.ExpectedRecordSHA256 != r.wire.RecordSHA256 ||
		d.PreviousHeadSHA256 != r.wire.Head.HeadSHA256 || d.PreviousHeadGeneration != r.wire.Head.Generation || d.Provisioning != r.wire.V2.Provisioning ||
		!reflect.DeepEqual(d.TargetArtifact, r.wire.Active.Plan.Artifact) || !d.CreatedAt.Equal(now) || !d.ExpiresAt.Equal(now.Add(time.Minute)) || p.validAt(now) != nil {
		t.Fatal("MODEL source binding incomplete")
	}
	parsed, err := labRecoveryPlanFromDescriptor(d, r)
	if err != nil || !reflect.DeepEqual(parsed.descriptor(), d) {
		t.Fatal("MODEL structural roundtrip")
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal("MODEL descriptor JSON")
	}
	// Derive the hash material independently from the actual descriptor bytes:
	// its one final self-digest field is absent, with every other order intact.
	cut := bytes.LastIndex(raw, []byte(`,"planSHA256":`))
	if cut < 0 || labConfigHash(append(bytes.Clone(raw[:cut]), '}')) != d.PlanSHA256 {
		t.Fatal("MODEL ordered digest")
	}
}

func TestLabRecoveryPlanModelDescriptorExactJSONFieldOrder(t *testing.T) {
	p, _, _ := labRecoveryPlanModel(t)
	raw, err := json.Marshal(p.descriptor())
	if err != nil {
		t.Fatal("MODEL descriptor JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		t.Fatal("MODEL descriptor object")
	}
	want := []string{"schema", "boundary", "recoveryId", "unknownOperationId", "originalPlanSHA256", "originalIntentSHA256", "declaredInitiatorRef", "expectedRevision", "expectedRecordSHA256", "previousHeadSHA256", "previousHeadGeneration", "provisioning", "oldEpochSHA256", "targetArtifact", "budgets", "createdAt", "expiresAt", "planSHA256"}
	for _, key := range want {
		actual, err := decoder.Token()
		if err != nil || actual != key {
			t.Fatal("MODEL descriptor key order")
		}
		var discard json.RawMessage
		if decoder.Decode(&discard) != nil {
			t.Fatal("MODEL descriptor value")
		}
	}
	if decoder.More() {
		t.Fatal("MODEL descriptor extra key")
	}
	if _, err := decoder.Token(); err != nil {
		t.Fatal("MODEL descriptor end")
	}
	if _, err := decoder.Token(); err != io.EOF {
		t.Fatal("MODEL descriptor trailing input")
	}
}

func TestLabRecoveryPlanModelRejectsV1AndNonUnknownOriginal(t *testing.T) {
	v1, _, now := lifecycleTestRecord(t)
	if _, err := newLabRecoveryPlan(v1, "labrec_"+strings.Repeat("1", 32), "actor", v1.wire.Head.Artifact, now, now.Add(time.Minute)); err == nil {
		t.Fatal("MODEL v1 recovery accepted")
	}
	s, _, _, _, now := labV2TestArmed(t)
	if _, err := newLabRecoveryPlan(s.record, "labrec_"+strings.Repeat("1", 32), "actor", s.record.wire.Active.Plan.Artifact, now, now.Add(time.Minute)); err == nil {
		t.Fatal("MODEL armed treated unknown")
	}
}

func TestLabRecoveryPlanModelRejectsMissingAttemptIntentAndInvalidOriginalDigest(t *testing.T) {
	for _, kind := range []string{"attempt", "intent", "digest", "head", "v2"} {
		r, target, now := labRecoveryPlanModelOriginal(t)
		switch kind {
		case "attempt":
			r.wire.Active.Attempt = 0
		case "intent":
			r.wire.Active.Intent = nil
		case "digest":
			r.wire.RecordSHA256 = strings.Repeat("f", 64)
		case "head":
			r.wire.Head = nil
		case "v2":
			r.wire.V2 = nil
		}
		if _, err := newLabRecoveryPlan(r, "labrec_"+strings.Repeat("1", 32), "actor", target, now, now.Add(time.Minute)); err == nil {
			t.Fatal("MODEL incomplete original accepted")
		}
	}
}

func TestLabRecoveryPlanModelOriginalNilAndAcknowledgedResultsRemainValidUnknown(t *testing.T) {
	for _, result := range []*lifecycleResult{nil, {Reload: mihomo.ReloadResult{State: mihomo.ReloadAcknowledged, Dispatched: true, StatusCode: 204}, Origin: "ADAPTER"}} {
		r, target, now := labRecoveryPlanModelOriginal(t)
		if result != nil {
			result.ObservedAt = now
		}
		r.wire.Active.Result = result
		r = lifecycleTestSeal(t, r)
		before, err := encodeLifecycleRecord(r)
		if err != nil {
			t.Fatal("MODEL unknown result fixture")
		}
		if _, err := newLabRecoveryPlan(r, "labrec_"+strings.Repeat("1", 32), "actor", target, now, now.Add(time.Minute)); err != nil {
			t.Fatal("MODEL original unknown result rejected")
		}
		after, err := encodeLifecycleRecord(r)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("MODEL original result rewritten")
		}
	}
}

func TestLabRecoveryPlanModelExpiredOldPlanLeaseAndRevocationDoNotAuthorizeOrDenyNewPlan(t *testing.T) {
	r, target, now := labRecoveryPlanModelOriginal(t)
	r.wire.Active.Revocation = &lifecycleRevocation{Revision: r.wire.Revision, At: now, Reason: "EXPLICIT_REVOKED", ActorRef: "MODEL_old_actor"}
	r = lifecycleTestSeal(t, r)
	created := now.Add(24 * time.Hour)
	if !created.After(r.wire.Active.Plan.ExpiresAt) || !created.After(r.wire.Owner.ExpiresAt) {
		t.Fatal("MODEL old expiry prerequisite")
	}
	p, err := newLabRecoveryPlan(r, "labrec_"+strings.Repeat("1", 32), "new-independent-actor", target, created, created.Add(time.Minute))
	if err != nil || p.validAt(created) != nil {
		t.Fatal("MODEL old expiry blocks distinct structural plan")
	}
	if r.wire.Active.Phase != "UNKNOWN" || r.wire.Active.Revocation == nil {
		t.Fatal("MODEL old facts lost")
	}
}

func TestLabRecoveryPlanModelRecoveryIDsAndInitiatorReferencesAreStrict(t *testing.T) {
	r, target, now := labRecoveryPlanModelOriginal(t)
	for _, id := range []string{"", "labop_" + strings.Repeat("1", 32), "labrec_" + strings.Repeat("A", 32), "labrec_" + strings.Repeat("1", 31), "labrec_" + strings.Repeat("1", 32) + "x"} {
		if _, err := newLabRecoveryPlan(r, id, "actor", target, now, now.Add(time.Minute)); err == nil {
			t.Fatal("MODEL invalid recovery id")
		}
	}
	for _, actor := range []string{"", " actor", "actor/other", strings.Repeat("a", 129)} {
		if _, err := newLabRecoveryPlan(r, "labrec_"+strings.Repeat("1", 32), actor, target, now, now.Add(time.Minute)); err == nil {
			t.Fatal("MODEL invalid initiator")
		}
	}
}

func TestLabRecoveryPlanModelTTLAndTrustedUTCDateBounds(t *testing.T) {
	r, target, now := labRecoveryPlanModelOriginal(t)
	for _, duration := range []time.Duration{-time.Nanosecond, 0, 5*time.Minute + time.Nanosecond} {
		if _, err := newLabRecoveryPlan(r, "labrec_"+strings.Repeat("1", 32), "actor", target, now, now.Add(duration)); err == nil {
			t.Fatal("MODEL invalid TTL")
		}
	}
	for _, duration := range []time.Duration{time.Nanosecond, 5 * time.Minute} {
		if _, err := newLabRecoveryPlan(r, "labrec_"+strings.Repeat("1", 32), "actor", target, now, now.Add(duration)); err != nil {
			t.Fatal("MODEL valid TTL boundary")
		}
	}
	for _, kind := range []string{"zero", "before-record", "now-zone", "expiry-zone", "year"} {
		created, expires := now, now.Add(time.Minute)
		switch kind {
		case "zero":
			created = time.Time{}
		case "before-record":
			created = now.Add(-time.Nanosecond)
		case "now-zone":
			created = now.In(time.FixedZone("MODEL_SAME_OFFSET", 0))
		case "expiry-zone":
			expires = expires.In(time.FixedZone("MODEL_SAME_OFFSET", 0))
		case "year":
			created = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			expires = created.Add(time.Minute)
		}
		if _, err := newLabRecoveryPlan(r, "labrec_"+strings.Repeat("1", 32), "actor", target, created, expires); err == nil {
			t.Fatal("MODEL invalid trusted time")
		}
	}
}

func TestLabRecoveryPlanModelValidAtRejectsZeroBackwardAndExpiredTime(t *testing.T) {
	p, _, now := labRecoveryPlanModel(t)
	for _, when := range []time.Time{time.Time{}, now.Add(-time.Nanosecond), now.Add(time.Minute), now.Add(2 * time.Minute), now.In(time.FixedZone("MODEL", 0))} {
		if p.validAt(when) == nil {
			t.Fatal("MODEL invalid validity time")
		}
	}
	if p.validAt(now) != nil || p.validAt(now.Add(time.Minute-time.Nanosecond)) != nil {
		t.Fatal("MODEL active validity interval")
	}
	var zero labRecoveryPlan
	var absent *labRecoveryPlan
	if zero.validAt(now) == nil || absent.validAt(now) == nil || !reflect.DeepEqual(absent.descriptor(), labRecoveryPlanDescriptor{}) {
		t.Fatal("MODEL zero or nil plan valid")
	}
}

func TestLabRecoveryPlanModelSameArtifactIsValidEpochReplacement(t *testing.T) {
	r, _, now := labRecoveryPlanModelOriginal(t)
	p, err := newLabRecoveryPlan(r, "labrec_"+strings.Repeat("1", 32), "actor", r.wire.Head.Artifact, now, now.Add(time.Minute))
	if err != nil || !reflect.DeepEqual(p.descriptor().TargetArtifact, r.wire.Head.Artifact) {
		t.Fatal("MODEL same artifact epoch replacement rejected")
	}
}

func TestLabRecoveryPlanModelTargetMustBeCompleteAdmissibleAndSamePorts(t *testing.T) {
	for _, kind := range []string{"capabilities", "requirements", "blockers", "admission", "record", "ports"} {
		r, target, now := labRecoveryPlanModelOriginal(t)
		switch kind {
		case "capabilities":
			target.Config.Capabilities = nil
		case "requirements":
			target.Config.Requirements = nil
		case "blockers":
			target.Config.Blockers = nil
		case "admission":
			target.Config.Admissible = false
		case "record":
			target.RecordSHA256 = strings.Repeat("f", 64)
		case "ports":
			target.ControllerPort++
		}
		if _, err := newLabRecoveryPlan(r, "labrec_"+strings.Repeat("1", 32), "actor", target, now, now.Add(time.Minute)); err == nil {
			t.Fatal("MODEL unsafe target accepted")
		}
	}
}

func TestLabRecoveryPlanModelEveryDescriptorBindingTamperRejects(t *testing.T) {
	mutations := []func(*labRecoveryPlanDescriptor){
		func(d *labRecoveryPlanDescriptor) { d.Schema = "MODEL" }, func(d *labRecoveryPlanDescriptor) { d.Boundary = "MODEL" },
		func(d *labRecoveryPlanDescriptor) { d.RecoveryID = "labrec_" + strings.Repeat("2", 32) },
		func(d *labRecoveryPlanDescriptor) { d.UnknownOperationID = "different-op" }, func(d *labRecoveryPlanDescriptor) { d.OriginalPlanSHA256 = strings.Repeat("d", 64) },
		func(d *labRecoveryPlanDescriptor) { d.OriginalIntentSHA256 = strings.Repeat("d", 64) }, func(d *labRecoveryPlanDescriptor) { d.DeclaredInitiatorRef = "different-actor" },
		func(d *labRecoveryPlanDescriptor) { d.ExpectedRevision++ }, func(d *labRecoveryPlanDescriptor) { d.ExpectedRecordSHA256 = strings.Repeat("d", 64) },
		func(d *labRecoveryPlanDescriptor) { d.PreviousHeadSHA256 = strings.Repeat("d", 64) }, func(d *labRecoveryPlanDescriptor) { d.PreviousHeadGeneration++ },
		func(d *labRecoveryPlanDescriptor) { d.Provisioning.RuntimeID = strings.Repeat("d", 64) }, func(d *labRecoveryPlanDescriptor) { d.OldEpochSHA256 = strings.Repeat("d", 64) },
		func(d *labRecoveryPlanDescriptor) { d.TargetArtifact.Config.Capabilities[0] = "MODEL" }, func(d *labRecoveryPlanDescriptor) { d.Budgets.StopMillis++ },
		func(d *labRecoveryPlanDescriptor) { d.CreatedAt = d.CreatedAt.Add(time.Nanosecond) }, func(d *labRecoveryPlanDescriptor) { d.ExpiresAt = d.ExpiresAt.Add(time.Nanosecond) },
		func(d *labRecoveryPlanDescriptor) { d.PlanSHA256 = strings.Repeat("d", 64) },
	}
	for _, mutate := range mutations {
		p, r, _ := labRecoveryPlanModel(t)
		d := p.descriptor()
		mutate(&d)
		if _, err := labRecoveryPlanFromDescriptor(d, r); err == nil {
			t.Fatal("MODEL descriptor tamper accepted")
		}
	}
}

func TestLabRecoveryPlanModelResealedForeignOriginalBindingsStillReject(t *testing.T) {
	for _, field := range []string{"op", "plan", "intent", "revision", "record", "head", "generation", "provision", "epoch", "budget"} {
		p, r, _ := labRecoveryPlanModel(t)
		d := p.descriptor()
		switch field {
		case "op":
			d.UnknownOperationID = "different-op"
		case "plan":
			d.OriginalPlanSHA256 = strings.Repeat("d", 64)
		case "intent":
			d.OriginalIntentSHA256 = strings.Repeat("d", 64)
		case "revision":
			d.ExpectedRevision++
		case "record":
			d.ExpectedRecordSHA256 = strings.Repeat("d", 64)
		case "head":
			d.PreviousHeadSHA256 = strings.Repeat("d", 64)
		case "generation":
			d.PreviousHeadGeneration++
		case "provision":
			d.Provisioning.MarkerSHA256 = strings.Repeat("d", 64)
		case "epoch":
			d.OldEpochSHA256 = strings.Repeat("d", 64)
		case "budget":
			d.Budgets.CommitMillis++
		}
		d = labRecoveryPlanModelReseal(t, d)
		if _, err := labRecoveryPlanFromDescriptor(d, r); err == nil {
			t.Fatal("MODEL coherent hash substituted foreign binding")
		}
	}
}

func TestLabRecoveryPlanModelDescriptorCannotCrossChangedOriginalRecord(t *testing.T) {
	p, r, _ := labRecoveryPlanModel(t)
	d := p.descriptor()
	r.wire.Revision++
	r = lifecycleTestSeal(t, r)
	if _, err := encodeLifecycleRecord(r); err != nil {
		t.Fatal("MODEL changed valid original")
	}
	if _, err := labRecoveryPlanFromDescriptor(d, r); err == nil {
		t.Fatal("MODEL original CAS bypass")
	}
}

func TestLabRecoveryPlanModelBudgetsAreFixedDeclarationsNotExpandedByCaller(t *testing.T) {
	p, r, _ := labRecoveryPlanModel(t)
	d := p.descriptor()
	if d.Budgets != (labRecoveryBudgets{StopMillis: 3000, StartMillis: 10000, VerificationMillis: 10000, CommitMillis: 5000}) {
		t.Fatal("MODEL declared budget contract")
	}
	for _, field := range []string{"stop", "start", "verification", "commit"} {
		changed := p.descriptor()
		switch field {
		case "stop":
			changed.Budgets.StopMillis++
		case "start":
			changed.Budgets.StartMillis++
		case "verification":
			changed.Budgets.VerificationMillis++
		case "commit":
			changed.Budgets.CommitMillis++
		}
		changed = labRecoveryPlanModelReseal(t, changed)
		if _, err := labRecoveryPlanFromDescriptor(changed, r); err == nil {
			t.Fatal("MODEL caller expanded source budget")
		}
	}
}

func TestLabRecoveryPlanModelTargetAndReturnedDescriptorDefensiveCopies(t *testing.T) {
	r, target, now := labRecoveryPlanModelOriginal(t)
	target.Config.Requirements = make([]LabPolicyRequirement, 0, 2)
	target.Config.Blockers = make([]LabConfigBlocker, 0, 2)
	p, err := newLabRecoveryPlan(r, "labrec_"+strings.Repeat("1", 32), "actor", target, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal("MODEL copy plan")
	}
	before := p.descriptor()
	target.Config.Capabilities[0] = "MODEL_INPUT_MUTATION"
	target.Config.Requirements = append(target.Config.Requirements, LabPolicyRequirement{Kind: "MODEL"})
	target.Config.Blockers = append(target.Config.Blockers, LabConfigBlocker{})
	returned := p.descriptor()
	returned.TargetArtifact.Config.Capabilities[0] = "MODEL_RETURN_MUTATION"
	returned.TargetArtifact.Config.Requirements = append(returned.TargetArtifact.Config.Requirements, LabPolicyRequirement{Kind: "MODEL"})
	returned.TargetArtifact.Config.Blockers = append(returned.TargetArtifact.Config.Blockers, LabConfigBlocker{})
	if !reflect.DeepEqual(p.descriptor(), before) || cap(p.descriptor().TargetArtifact.Config.Requirements) != 0 || cap(p.descriptor().TargetArtifact.Config.Blockers) != 0 {
		t.Fatal("MODEL descriptor alias")
	}
}

func TestLabRecoveryPlanModelEpochIgnoresReloadArtifactGenerationAndHeadHash(t *testing.T) {
	r, target, _ := labRecoveryPlanModelOriginal(t)
	h := *r.wire.Head
	a, err := labRecoveryEpochSHA256(h, r.wire.V2.Provisioning)
	if err != nil {
		t.Fatal("MODEL epoch")
	}
	h.Artifact = target
	h.Generation++
	h.HeadSHA256 = strings.Repeat("d", 64)
	h.VerificationSHA256 = strings.Repeat("e", 64)
	b, err := labRecoveryEpochSHA256(h, r.wire.V2.Provisioning)
	if err != nil || a != b {
		t.Fatal("MODEL reload changed physical epoch binding")
	}
}

func TestLabRecoveryPlanModelEpochBindsPIDTicksNamespaceKernelPortsAndProvision(t *testing.T) {
	r, _, _ := labRecoveryPlanModelOriginal(t)
	old, err := labRecoveryEpochSHA256(*r.wire.Head, r.wire.V2.Provisioning)
	if err != nil {
		t.Fatal("MODEL epoch")
	}
	for _, field := range []string{"pid", "ticks", "namespace", "kernel", "controller", "mixed", "runtime", "marker", "scope"} {
		h, p := *r.wire.Head, r.wire.V2.Provisioning
		switch field {
		case "pid":
			h.PID++
		case "ticks":
			h.StartTicks++
		case "namespace":
			h.NetNSInode++
		case "kernel":
			h.KernelSHA256 = strings.Repeat("d", 64)
		case "controller":
			h.ControllerPort++
		case "mixed":
			h.MixedPort++
		case "runtime":
			p.RuntimeID = strings.Repeat("d", 64)
		case "marker":
			p.MarkerSHA256 = strings.Repeat("d", 64)
		case "scope":
			h.Scope.SiteID = "different-site"
		}
		got, err := labRecoveryEpochSHA256(h, p)
		if err != nil || got == old {
			t.Fatal("MODEL different epoch not bound")
		}
	}
}

func TestLabRecoveryPlanModelEpochMalformedIdentityRejects(t *testing.T) {
	r, _, _ := labRecoveryPlanModelOriginal(t)
	for _, field := range []string{"pid", "ticks", "namespace", "kernel", "ports", "scope", "provision"} {
		h, p := *r.wire.Head, r.wire.V2.Provisioning
		switch field {
		case "pid":
			h.PID = 0
		case "ticks":
			h.StartTicks = 0
		case "namespace":
			h.NetNSInode = 0
		case "kernel":
			h.KernelSHA256 = strings.Repeat("0", 64)
		case "ports":
			h.MixedPort = h.ControllerPort
		case "scope":
			h.Scope.Environment = "production"
		case "provision":
			p.Schema = "MODEL"
		}
		if _, err := labRecoveryEpochSHA256(h, p); err == nil {
			t.Fatal("MODEL malformed epoch accepted")
		}
	}
}

func TestLabRecoveryPlanModelOpaqueFormattingJSONAndUnmarshalNeverMint(t *testing.T) {
	p, _, now := labRecoveryPlanModel(t)
	d := p.descriptor()
	for _, value := range []any{p, &p, labRecoveryPlan{}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
			if fmt.Sprintf(verb, value) != labRecoveryPlanDebug {
				t.Fatal("MODEL debug exposed binding")
			}
		}
		for _, verb := range []string{"%p", "%T"} {
			text := fmt.Sprintf(verb, value)
			for _, private := range []string{d.DeclaredInitiatorRef, d.ExpectedRecordSHA256, d.OriginalIntentSHA256, d.RecoveryID} {
				if strings.Contains(text, private) {
					t.Fatal("MODEL special fmt traversed opaque core")
				}
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `{"scope":"STRUCTURAL_RECOVERY_PLAN_NOT_AUTHORIZATION"}` {
			t.Fatal("MODEL opaque JSON exposed plan")
		}
	}
	var absent *labRecoveryPlan
	if fmt.Sprintf("%v", absent) != "<nil>" {
		t.Fatal("MODEL typed nil fmt")
	}
	if raw, err := json.Marshal(absent); err != nil || string(raw) != "null" {
		t.Fatal("MODEL typed nil JSON")
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal("MODEL descriptor JSON")
	}
	if json.Unmarshal(raw, &p) == nil || p.validAt(now) == nil {
		t.Fatal("MODEL JSON minted plan")
	}
	if absent.UnmarshalJSON(raw) == nil {
		t.Fatal("MODEL nil unmarshal")
	}
}
