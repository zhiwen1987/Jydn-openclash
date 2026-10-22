//go:build linux

package product

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/authz"
	"chengwang/internal/imagetrust"
)

// These are real store/audit unit tests, not source-worker, Sigstore SDK, or
// Docker image evidence. No clock, production setting, or public hook is added.
func d12RejectionFixture(t *testing.T, maxAge time.Duration) productFixture {
	t.Helper()
	f := newProductFixture(t, true)
	service, err := New(context.Background(), Config{Store: f.store, Audit: f.audit, Scope: f.service.Scope(), WritesEnabled: true, RegistryRoots: x509.NewCertPool(), RefreshMaxAge: maxAge})
	if err != nil {
		t.Fatal("refresh fixture construction failed")
	}
	f.service = service
	return f
}

func d12BadRefresh(t *testing.T, f productFixture, variant int) []byte {
	t.Helper()
	doc := f.doc
	doc.Generation = 2
	doc.NotAfterUnix -= int64(variant + 1)
	var envelope trustcatalog.Envelope
	if json.Unmarshal(f.sign(t, doc), &envelope) != nil || len(envelope.Signatures) != 1 || len(envelope.Signatures[0].Signature) != 64 {
		t.Fatal("invalid rejection fixture")
	}
	envelope.Signatures[0].Signature[0] ^= 1
	return productJSON(t, envelope)
}

type d12RejectionState struct {
	inspection      truststate.Inspection
	journal         []truststate.JournalEntry
	log, checkpoint []byte
}

func d12RejectionSnapshot(t *testing.T, f productFixture) d12RejectionState {
	t.Helper()
	state, err := f.store.Inspect(context.Background())
	if err != nil {
		t.Fatal("rejection inspection failed")
	}
	journal, err := f.store.Journal(context.Background())
	if err != nil {
		t.Fatal("rejection journal failed")
	}
	log, err := os.ReadFile(filepath.Join(f.auditPath, "events.jsonl"))
	if err != nil {
		t.Fatal("rejection audit bytes unavailable")
	}
	checkpoint, err := os.ReadFile(filepath.Join(f.auditPath, "checkpoint.json"))
	if err != nil {
		t.Fatal("rejection checkpoint unavailable")
	}
	return d12RejectionState{state, journal, log, checkpoint}
}

func d12RejectionUnchanged(t *testing.T, before d12RejectionState, f productFixture) {
	t.Helper()
	if !reflect.DeepEqual(before, d12RejectionSnapshot(t, f)) {
		t.Fatal("duplicate rejection changed durable state")
	}
}

func d12RejectionCount(service *Service) int {
	count := 0
	for _, key := range service.refreshRejected {
		if key.rawSHA256 != "" {
			count++
		}
	}
	return count
}

func d12FirstRejection(t *testing.T, f productFixture, raw []byte) {
	t.Helper()
	before := d12RejectionSnapshot(t, f)
	expectCode(t, f.service.ApplyRefresh(context.Background(), raw), imagetrust.CodeInvalid, true)
	after := d12RejectionSnapshot(t, f)
	proof, err := f.audit.Verify()
	if err != nil || !proof.Valid || after.inspection.Sequence != before.inspection.Sequence+4 || len(after.journal) != len(before.journal)+1 || proof.Count != uint64(len(after.journal)*2) || !reflect.DeepEqual(before.inspection.Consumptions, after.inspection.Consumptions) {
		t.Fatal("first rejection omitted real audited outcome")
	}
	entry := after.journal[len(after.journal)-1]
	if entry.State != "PREPARED" || entry.Outcome != truststate.OutcomeRejected || !entry.Acknowledged || entry.Operation.ActorID != "image-trust-refresh" || entry.Operation.Kind != "update" || !reflect.DeepEqual(entry.Operation.Data, map[string]string{"catalogueSHA256": digest(raw)}) {
		t.Fatal("first rejection journal binding failed")
	}
	view, err := f.audit.RecoverySnapshot()
	if err != nil {
		t.Fatal("rejection audit snapshot failed")
	}
	prepared, p := view.Lookup("image-trust/" + entry.Operation.ID + "/prepared")
	result, r := view.Lookup("image-trust/" + entry.Operation.ID + "/result")
	if !p || !r || prepared.Hash != entry.Operation.PreparedAuditHash || result.Hash != entry.ResultAuditHash || prepared.ActorID != "image-trust-refresh" || result.ActorID != "image-trust-refresh" || result.Result != "rejected" {
		t.Fatal("first rejection lacks actual prepared/result audit")
	}
}

func TestProductD12RefreshRejectionDuplicateCandidateNoRepeatedWrites(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	raw := d12BadRefresh(t, f, 0)
	d12FirstRejection(t, f, raw)
	before := d12RejectionSnapshot(t, f)
	for i := 0; i < 32; i++ {
		expectCode(t, f.service.ApplyRefresh(context.Background(), raw), imagetrust.CodeInvalid, false)
	}
	d12RejectionUnchanged(t, before, f)
	if d12RejectionCount(f.service) != 1 {
		t.Fatal("duplicate grew rejection working set")
	}
}

func TestProductD12RefreshRejectionDifferentBytesRemainAudited(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	first, second := d12BadRefresh(t, f, 0), d12BadRefresh(t, f, 1)
	if digest(first) == digest(second) {
		t.Fatal("different-byte fixture conflated")
	}
	d12FirstRejection(t, f, first)
	d12FirstRejection(t, f, second)
	before := d12RejectionSnapshot(t, f)
	for _, raw := range [][]byte{first, second} {
		expectCode(t, f.service.ApplyRefresh(context.Background(), raw), imagetrust.CodeInvalid, false)
	}
	d12RejectionUnchanged(t, before, f)
	if d12RejectionCount(f.service) != 2 {
		t.Fatal("distinct rejection was not independently keyed")
	}
}

func TestProductD12RefreshRejectionFixedRingCapacityAndEviction(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	values := make([][]byte, refreshRejectionCapacity+1)
	for i := range values {
		values[i] = d12BadRefresh(t, f, i)
		d12FirstRejection(t, f, values[i])
		if d12RejectionCount(f.service) > 16 {
			t.Fatal("rejection cache exceeded fixed capacity")
		}
	}
	if len(f.service.refreshRejected) != 16 || d12RejectionCount(f.service) != 16 {
		t.Fatal("rejection cache is not exactly bounded")
	}
	before := d12RejectionSnapshot(t, f)
	expectCode(t, f.service.ApplyRefresh(context.Background(), values[1]), imagetrust.CodeInvalid, false)
	d12RejectionUnchanged(t, before, f)
	d12FirstRejection(t, f, values[0]) // Eviction is explicit, not infinite dedupe.
	if d12RejectionCount(f.service) != 16 {
		t.Fatal("eviction changed fixed capacity")
	}
}

func TestProductD12RefreshRejectionFutureNotBeforeBecomesEligible(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	doc := f.doc
	doc.Generation, doc.NotBeforeUnix = 2, time.Now().Unix()+4
	raw := f.sign(t, doc)
	d12FirstRejection(t, f, raw)
	expectCode(t, f.service.ApplyRefresh(context.Background(), raw), imagetrust.CodeInvalid, false)
	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Unix() < doc.NotBeforeUnix && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if time.Now().Unix() < doc.NotBeforeUnix {
		t.Fatal("real NotBefore wait exceeded bound")
	}
	if err := f.service.ApplyRefresh(context.Background(), raw); err != nil {
		t.Fatal("remembered future candidate did not become eligible")
	}
	after := d12RejectionSnapshot(t, f)
	if after.inspection.Sequence != 9 || after.inspection.Catalogue.Generation != 2 || after.inspection.Catalogue.SHA256 != digest(raw) || len(after.journal) != 2 || d12RejectionCount(f.service) != 0 {
		t.Fatal("eligible candidate bypassed transaction or retained old-base rejections")
	}
}

func TestProductD12RefreshRejectionBaseChangeClearsWorkingSet(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	raw := d12BadRefresh(t, f, 0)
	d12FirstRejection(t, f, raw)
	doc := f.doc
	doc.Generation = 2
	good := f.sign(t, doc)
	if _, err := f.service.Update(context.Background(), f.actor(authz.RoleAdmin), good); err != nil {
		t.Fatal("real base update failed")
	}
	d12FirstRejection(t, f, raw)
	if d12RejectionCount(f.service) != 1 || f.service.refreshRejectBase != 2 || f.service.refreshRejectBaseSHA256 != digest(good) {
		t.Fatal("base change retained old working set")
	}
	before := d12RejectionSnapshot(t, f)
	expectCode(t, f.service.ApplyRefresh(context.Background(), raw), imagetrust.CodeInvalid, false)
	d12RejectionUnchanged(t, before, f)
}

func TestProductD12RefreshRejectionNewServiceDoesNotInheritWorkingSet(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	raw := d12BadRefresh(t, f, 0)
	d12FirstRejection(t, f, raw)
	service, err := New(context.Background(), Config{Store: f.store, Audit: f.audit, Scope: f.service.Scope(), WritesEnabled: true, RegistryRoots: x509.NewCertPool(), RefreshMaxAge: time.Minute})
	if err != nil || d12RejectionCount(service) != 0 {
		t.Fatal("new Service inherited process-local rejection state")
	}
	f.service = service
	d12FirstRejection(t, f, raw)
	if d12RejectionSnapshot(t, f).inspection.Sequence != 9 {
		t.Fatal("new Service claimed persistent rejection dedupe")
	}
}

func TestProductD12RefreshRejectionConcurrentApplyReturnsBusy(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	raw := d12BadRefresh(t, f, 0)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	f.service.fault = func(stage string) {
		if stage == "after-journal-prepare" {
			close(entered)
			<-release
		}
	}
	go func() { done <- f.service.ApplyRefresh(context.Background(), raw) }()
	ownerJoined := false
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		if !ownerJoined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("owner refresh did not join after releasing failure-path barrier")
			}
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("owner did not reach actual prepared intent")
	}
	for i := 0; i < 8; i++ {
		expectCode(t, f.service.ApplyRefresh(context.Background(), raw), imagetrust.CodeBusy, false)
	}
	close(release)
	select {
	case err := <-done:
		ownerJoined = true
		expectCode(t, err, imagetrust.CodeInvalid, true)
	case <-time.After(3 * time.Second):
		t.Fatal("owner refresh did not complete")
	}
	f.service.fault = nil
	after := d12RejectionSnapshot(t, f)
	if after.inspection.Sequence != 5 || len(after.journal) != 1 || d12RejectionCount(f.service) != 1 {
		t.Fatal("concurrent refresh created queued operations")
	}
}

func TestProductD12RefreshRejectionAuditFailureIsNotHiddenByHit(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	raw := d12BadRefresh(t, f, 0)
	d12FirstRejection(t, f, raw)
	before := d12RejectionSnapshot(t, f)
	if f.audit.Close() != nil {
		t.Fatal("audit close failed")
	}
	expectCode(t, f.service.ApplyRefresh(context.Background(), raw), imagetrust.CodeAuditDegraded, false)
	d12RejectionUnchanged(t, before, f)
	if !f.service.unavailable() {
		t.Fatal("audit failure did not retain fail-closed state")
	}
}

func TestProductD12RefreshRejectionStoreFailureIsNotHiddenByHit(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	raw := d12BadRefresh(t, f, 0)
	d12FirstRejection(t, f, raw)
	before := f.audit.Status().Count
	if f.store.Close() != nil {
		t.Fatal("store close failed")
	}
	expectCode(t, f.service.ApplyRefresh(context.Background(), raw), imagetrust.CodeUnavailable, false)
	if !f.service.unavailable() || f.audit.Status().Count != before {
		t.Fatal("store failure was hidden by cached rejection")
	}
}

func TestProductD12RefreshRejectionCanceledContextIsNotHiddenByHit(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	raw := d12BadRefresh(t, f, 0)
	d12FirstRejection(t, f, raw)
	before := d12RejectionSnapshot(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	expectCode(t, f.service.ApplyRefresh(ctx, raw), imagetrust.CodeCanceled, false)
	d12RejectionUnchanged(t, before, f)
	if f.service.unavailable() {
		t.Fatal("caller cancellation poisoned healthy service")
	}
}

func TestProductD12RefreshRejectionNilContextRejected(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	before := d12RejectionSnapshot(t, f)
	expectCode(t, f.service.ApplyRefresh(nil, d12BadRefresh(t, f, 0)), imagetrust.CodeCanceled, false)
	d12RejectionUnchanged(t, before, f)
	if d12RejectionCount(f.service) != 0 {
		t.Fatal("nil-context attempt entered working set")
	}
}

func TestProductD12RefreshRejectionHeldLockReturnsBusyWithoutQueue(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	raw := d12BadRefresh(t, f, 0)
	before := d12RejectionSnapshot(t, f)
	f.service.refreshApplyMu.Lock()
	done := make(chan error, 1)
	go func() { done <- f.service.ApplyRefresh(context.Background(), raw) }()
	select {
	case err := <-done:
		f.service.refreshApplyMu.Unlock()
		expectCode(t, err, imagetrust.CodeBusy, false)
	case <-time.After(time.Second):
		f.service.refreshApplyMu.Unlock()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		t.Fatal("refresh waited for busy lock instead of rejecting")
	}
	d12RejectionUnchanged(t, before, f)
}

func TestProductD12RefreshRejectionAdministratorUpdateStillAudits(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	raw := d12BadRefresh(t, f, 0)
	d12FirstRejection(t, f, raw)
	for i := 0; i < 2; i++ {
		_, err := f.service.Update(context.Background(), f.actor(authz.RoleAdmin), raw)
		expectCode(t, err, imagetrust.CodeInvalid, true)
	}
	before := d12RejectionSnapshot(t, f)
	if before.inspection.Sequence != 13 || len(before.journal) != 3 || before.journal[1].Operation.ActorID != "fixture-actor" || before.journal[2].Operation.ActorID != "fixture-actor" {
		t.Fatal("administrator Update inherited automatic dedupe")
	}
	expectCode(t, f.service.ApplyRefresh(context.Background(), raw), imagetrust.CodeInvalid, false)
	d12RejectionUnchanged(t, before, f)
}

func TestProductD12RefreshRejectionHitDoesNotRenewFreshness(t *testing.T) {
	f := d12RejectionFixture(t, time.Second)
	ctx := context.Background()
	if f.service.ConfirmRefresh(ctx, 1, digest(f.initial)) != nil {
		t.Fatal("unit confirmation failed")
	}
	at, until := f.service.refreshAt, f.service.refreshUntil
	raw := d12BadRefresh(t, f, 0)
	d12FirstRejection(t, f, raw)
	before := d12RejectionSnapshot(t, f)
	for i := 0; i < 3; i++ {
		expectCode(t, f.service.ApplyRefresh(ctx, raw), imagetrust.CodeInvalid, false)
	}
	if !f.service.refreshAt.Equal(at) || !f.service.refreshUntil.Equal(until) {
		t.Fatal("rejection renewed confirmed freshness")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	status, err := f.service.Status(ctx, f.actor(authz.RoleViewer))
	if err != nil || status.RefreshFresh || !status.Fresh || !status.Healthy {
		t.Fatal("cached rejection prevented natural freshness expiry")
	}
	d12RejectionUnchanged(t, before, f)
}

func TestProductD12RefreshRejectionConsumedLedgerRemainsUnchanged(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	ctx := context.Background()
	ticket, err := f.store.Begin(ctx, "fixture-policy", f.approval)
	if err != nil {
		t.Fatal("unit ledger reservation failed")
	}
	// This is a public Store transaction with an explicitly synthetic unit
	// marker, not a claim that the fake unit Sigstore bundle passed an SDK.
	if f.store.Complete(ctx, ticket, digest([]byte("unit-consumption-marker-not-sdk"))) != nil {
		t.Fatal("unit ledger completion failed")
	}
	before := d12RejectionSnapshot(t, f)
	if before.inspection.LedgerUsed != 1 || before.inspection.Consumptions[0].Status != "CONSUMED" {
		t.Fatal("unit consumed ledger missing")
	}
	raw := d12BadRefresh(t, f, 0)
	d12FirstRejection(t, f, raw)
	after := d12RejectionSnapshot(t, f)
	if !reflect.DeepEqual(before.inspection.Consumptions, after.inspection.Consumptions) {
		t.Fatal("first rejection changed consumed ledger")
	}
	expectCode(t, f.service.ApplyRefresh(ctx, raw), imagetrust.CodeInvalid, false)
	d12RejectionUnchanged(t, after, f)
}

func TestProductD12RefreshRejectionUncertainAuditOutcomeNeverCached(t *testing.T) {
	f := d12RejectionFixture(t, time.Minute)
	raw := d12BadRefresh(t, f, 0)
	f.service.fault = func(stage string) {
		if stage == "before-result-audit" {
			_ = f.audit.Close()
		}
	}
	expectCode(t, f.service.ApplyRefresh(context.Background(), raw), imagetrust.CodeAuditDegraded, true)
	f.service.fault = nil
	state, err := f.store.Inspect(context.Background())
	journal, journalErr := f.store.Journal(context.Background())
	if err != nil || journalErr != nil || state.Sequence != 3 || len(journal) != 1 || journal[0].Acknowledged || journal[0].Outcome != "" || d12RejectionCount(f.service) != 0 || !f.service.unavailable() {
		t.Fatal("uncertain result was retained as a definite rejection")
	}
}
