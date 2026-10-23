//go:build linux

package subscriptionctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/subscription"
)

// These fixtures use the real Linux private writer and real chained external
// evidence store. Only the external provider and explicit append failures are
// synthetic; they do not claim a public Internet fetch or cmd/server E2E.
type ctlTestAudit struct {
	store                    *evidence.Store
	mu                       sync.Mutex
	failPrepared, failResult bool
	afterPrepared            func()
}

func (a *ctlTestAudit) AppendOnce(e evidence.EvidenceEvent, key string) (evidence.EvidenceEvent, bool, error) {
	a.mu.Lock()
	fail := a.failPrepared && strings.HasSuffix(key, "/prepared") || a.failResult && strings.HasSuffix(key, "/result")
	callback := a.afterPrepared
	a.mu.Unlock()
	if fail {
		return evidence.EvidenceEvent{}, false, errors.New("synthetic append unavailable")
	}
	r, created, err := a.store.AppendOnce(e, key)
	if err == nil && callback != nil && strings.HasSuffix(key, "/prepared") {
		callback()
	}
	return r, created, err
}

type ctlTestPolicy struct {
	mu                 sync.Mutex
	material           []byte
	revision           uint64
	describes, fetches int
	onFetch            func(context.Context, subscription.Scope, string) (subscription.FetchResult, error)
}

func (p *ctlTestPolicy) Describe(ref string) (PolicyDescriptor, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.describes++
	if ref != "reference" {
		return PolicyDescriptor{}, errors.New("synthetic unavailable")
	}
	return PolicyDescriptor{ReferenceID: ref, Revision: p.revision, Material: append([]byte{}, p.material...)}, nil
}
func (p *ctlTestPolicy) Fetch(ctx context.Context, scope subscription.Scope, source, ref string) (subscription.FetchResult, error) {
	p.mu.Lock()
	p.fetches++
	callback := p.onFetch
	p.mu.Unlock()
	if callback != nil {
		return callback(ctx, scope, source)
	}
	return ctlTestFetched(scope, source), nil
}
func ctlTestFetched(scope subscription.Scope, source string) subscription.FetchResult {
	raw := []byte("http://user:private-password@proxy.example:8080#private-node")
	at := time.Now().UTC()
	return subscription.FetchResult{Scope: scope, SourceID: source, AttemptedAt: at, CompletedAt: at, ResponseBytes: len(raw), Content: raw}
}

type ctlTestEnv struct {
	t      *testing.T
	root   string
	store  *subscription.Store
	audit  *ctlTestAudit
	policy *ctlTestPolicy
	s      *Service
	p      authz.Principal
}

func ctlTestOpen(t *testing.T) *ctlTestEnv {
	t.Helper()
	e := &ctlTestEnv{t: t, root: t.TempDir(), policy: &ctlTestPolicy{material: []byte("private-policy-url-and-secret-version-1"), revision: 1}}
	if os.Chmod(e.root, 0700) != nil {
		t.Fatal("fixture permissions")
	}
	e.p = authz.Principal{ID: "owner@example.test", TenantID: "tenant-a", Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{{TenantID: "tenant-a", SiteID: "site-a", Environment: "lab"}}}
	e.open()
	t.Cleanup(func() {
		if e.store != nil {
			_ = e.store.Close()
		}
		if e.audit != nil && e.audit.store != nil {
			_ = e.audit.store.Close()
		}
	})
	return e
}
func (e *ctlTestEnv) config() Config {
	return Config{Scope: authz.ResourceScope{TenantID: "tenant-a", SiteID: "site-a", Environment: "lab", ObjectType: "subscription-store", ObjectID: "local"}, Store: e.store, Audit: e.audit, Policies: e.policy, WritesEnabled: true}
}
func (e *ctlTestEnv) open() {
	e.t.Helper()
	var err error
	e.store, err = subscription.OpenStore(filepath.Join(e.root, "domain"))
	if err != nil {
		e.t.Fatal(err)
	}
	a, err := evidence.Open(filepath.Join(e.root, "audit"))
	if err != nil {
		e.t.Fatal(err)
	}
	e.audit = &ctlTestAudit{store: a}
	e.s, err = New(context.Background(), e.config())
	if err != nil {
		e.t.Fatal(err)
	}
}
func (e *ctlTestEnv) restart() {
	e.t.Helper()
	if e.store.Close() != nil || e.audit.store.Close() != nil {
		e.t.Fatal("close fixture")
	}
	e.open()
}
func ctlTestError(t *testing.T, err error, code Code, changed bool) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != code || typed.StateMayHaveChanged != changed || err.Error() != string(code) {
		t.Fatalf("expected closed error %s changed=%v", code, changed)
	}
}
func (e *ctlTestEnv) execute(c Command) Receipt {
	e.t.Helper()
	r, err := e.s.Execute(context.Background(), e.p, c)
	if err != nil {
		e.t.Fatal("execute fixture command", err)
	}
	if !r.AuditRecorded || r.PreparedAuditHash == "" || r.ResultAuditHash == "" || r.CompletedAt.IsZero() {
		e.t.Fatal("missing immutable acknowledged receipt")
	}
	return r
}
func (e *ctlTestEnv) create(key string) Receipt {
	return e.execute(Command{Kind: Create, IdempotencyKey: key, Label: "Private source"})
}
func (e *ctlTestEnv) source(id string) subscription.SourceView {
	e.t.Helper()
	v, err := e.store.Source(e.s.scope, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}
func (e *ctlTestEnv) imported(source, key, host string) Receipt {
	return e.execute(Command{Kind: Import, IdempotencyKey: key, SourceID: source, ExpectedRevision: e.source(source).Revision, Content: []byte("http://user:private-password@" + host + ":8080#private-node")})
}
func (e *ctlTestEnv) approved(source, key string) Receipt {
	return e.execute(Command{Kind: Approve, IdempotencyKey: key, SourceID: source, ExpectedRevision: e.source(source).Revision, ReferenceID: "reference", PolicyRevision: 1})
}
func (e *ctlTestEnv) fetch(source string, approval Receipt, key string) Command {
	return Command{Kind: Fetch, IdempotencyKey: key, SourceID: source, ExpectedRevision: e.source(source).Revision, ApprovalID: approval.ApprovalID, PolicyRevision: approval.PolicyRevision}
}
func (e *ctlTestEnv) domain() []byte {
	e.t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.root, "domain", "store.json"))
	if err != nil {
		e.t.Fatal(err)
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		e.t.Fatal("decode fixture")
	}
	delete(value, "commands")
	delete(value, "approvals")
	out, _ := json.Marshal(value)
	return out
}
func (e *ctlTestEnv) commands() []subscription.ControlCommand {
	e.t.Helper()
	c, err := e.store.ControlCommands(e.s.scope)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}
func (e *ctlTestEnv) prepared(c Command) subscription.ControlCommand {
	e.t.Helper()
	id, err := e.store.ControlIdentity(e.s.scope, e.p.ID, c.IdempotencyKey, ctlMaterial(c))
	if err != nil {
		e.t.Fatal(err)
	}
	r := subscription.ControlCommand{ID: id.ID, Scope: e.s.scope, ActorID: id.ActorID, Kind: string(c.Kind), SourceID: c.SourceID, ExpectedRevision: c.ExpectedRevision, Fingerprint: id.Fingerprint, OwnerID: e.p.ID, CoreKey: id.CoreKey, KeyDigest: id.KeyDigest, PreparedAt: time.Now().UTC()}
	a, err := e.s.appendAudit(r, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	r.PreparedAt = a.OccurredAt
	r.PreparedAuditHash = a.Hash
	if created, err := e.store.RecordControlPrepared(r); err != nil || !created {
		e.t.Fatal("prepare fixture")
	}
	return r
}

func TestSubscriptionControlPreparedAuditFailureNoDomainOrFetch(t *testing.T) {
	e := ctlTestOpen(t)
	src := e.create("prepare-source-key-0001")
	a := e.approved(src.SourceID, "prepare-approval-key-01")
	before := e.domain()
	count := len(e.commands())
	e.audit.failPrepared = true
	_, err := e.s.Execute(context.Background(), e.p, e.fetch(src.SourceID, a, "prepare-fetch-key-0001"))
	ctlTestError(t, err, CodeAuditDegraded, false)
	if !bytes.Equal(before, e.domain()) || len(e.commands()) != count || e.policy.fetches != 0 {
		t.Fatal("pre-audit failure performed work")
	}
}
func TestSubscriptionControlPreparedAuditFailureNoParse(t *testing.T) {
	e := ctlTestOpen(t)
	src := e.create("parse-source-key-000001")
	before := e.domain()
	count := len(e.commands())
	e.audit.failPrepared = true
	_, err := e.s.Execute(context.Background(), e.p, Command{Kind: Import, IdempotencyKey: "parse-blocked-key-00001", SourceID: src.SourceID, ExpectedRevision: 1, Content: []byte("malformed://private-canary")})
	ctlTestError(t, err, CodeAuditDegraded, false)
	if !bytes.Equal(before, e.domain()) || len(e.commands()) != count {
		t.Fatal("pre-audit parse/domain mutation")
	}
	e.audit.failPrepared = false
	_, err = e.s.Execute(context.Background(), e.p, Command{Kind: Import, IdempotencyKey: "parse-invalid-key-00001", SourceID: src.SourceID, ExpectedRevision: 1, Content: []byte("malformed://private-canary")})
	ctlTestError(t, err, CodeInvalid, false)
	if !bytes.Equal(before, e.domain()) {
		t.Fatal("invalid import mutated domain")
	}
}
func TestSubscriptionControlCreateReceiptImmutable(t *testing.T) {
	e := ctlTestOpen(t)
	r := e.create("immutable-create-key-01")
	if r.State != "committed" || r.Revision != 1 || r.LocalAuditHash == "" {
		t.Fatal("not an actual domain receipt")
	}
	e.imported(r.SourceID, "immutable-import-key-01", "proxy.example")
	got, err := e.s.ReadReceipt(context.Background(), e.p, r.CommandID)
	if err != nil || !reflect.DeepEqual(r, got) {
		t.Fatal("receipt followed mutable source")
	}
	e.restart()
	got, err = e.s.ReadReceipt(context.Background(), e.p, r.CommandID)
	if err != nil || !reflect.DeepEqual(r, got) {
		t.Fatal("restart rewrote receipt")
	}
}
func TestSubscriptionControlImportDecisionRollbackReceipts(t *testing.T) {
	e := ctlTestOpen(t)
	src := e.create("chain-source-key-000001")
	a := e.imported(src.SourceID, "chain-import-key-000001", "one.example")
	d := e.execute(Command{Kind: Decide, IdempotencyKey: "chain-decide-key-000001", SourceID: src.SourceID, CandidateID: a.CandidateID, ExpectedRevision: a.Revision, ExpectedDigest: a.CandidateDigest, Decision: subscription.CandidateAdmitted})
	b := e.imported(src.SourceID, "chain-import-key-000002", "two.example")
	e.execute(Command{Kind: Decide, IdempotencyKey: "chain-decide-key-000002", SourceID: src.SourceID, CandidateID: b.CandidateID, ExpectedRevision: b.Revision, ExpectedDigest: b.CandidateDigest, Decision: subscription.CandidateAdmitted})
	r := e.execute(Command{Kind: Rollback, IdempotencyKey: "chain-rollback-key-0001", SourceID: src.SourceID, CandidateID: a.CandidateID, ExpectedRevision: e.source(src.SourceID).Revision})
	if a.Revision != 2 || d.Revision != 3 || b.Revision != 4 || r.Revision != 6 || r.LocalAuditHash == "" || e.source(src.SourceID).AcceptedCandidateID != a.CandidateID {
		t.Fatal("domain history/rollback mismatch")
	}
}
func TestSubscriptionControlPostAuditFailureReturnsDegraded(t *testing.T) {
	e := ctlTestOpen(t)
	e.audit.failResult = true
	r, err := e.s.Execute(context.Background(), e.p, Command{Kind: Create, IdempotencyKey: "post-failure-key-000001", Label: "Source"})
	ctlTestError(t, err, CodeAuditDegraded, true)
	if r.State != "committed" || r.AuditRecorded || r.LocalAuditHash == "" || e.source(r.SourceID).Revision != 1 {
		t.Fatal("post failure hid actual mutation")
	}
	e.audit.failResult = false
	e.restart()
	got, err := e.s.ReadReceipt(context.Background(), e.p, r.CommandID)
	if err != nil || !got.AuditRecorded || got.SourceID != r.SourceID {
		t.Fatal("result repair failed")
	}
	// A successful domain write followed by a receipt lookup failure must never
	// be classified as a definitely unchanged failed command.
	e.s.mutationReceipt = func(subscription.Scope, string, string) (subscription.MutationReceipt, bool, error) {
		return subscription.MutationReceipt{}, false, &subscription.Failure{Code: subscription.CodeStoreUnsafe}
	}
	r, err = e.s.Execute(context.Background(), e.p, Command{Kind: Create, IdempotencyKey: "post-lookup-key-000001", Label: "Second"})
	ctlTestError(t, err, CodeCommitUnknown, true)
	if r.State != "unknown" || !r.StateMayHaveChanged || r.CommandID == "" {
		t.Fatal("lookup failure falsely claimed unchanged")
	}
	e.restart()
	got, err = e.s.ReadReceipt(context.Background(), e.p, r.CommandID)
	if err != nil || got.State != "committed" || !got.AuditRecorded {
		t.Fatal("actual mutation not recovered")
	}
}
func TestSubscriptionControlRecoverRepairsCommittedWithoutReplay(t *testing.T) {
	e := ctlTestOpen(t)
	c := Command{Kind: Create, IdempotencyKey: "recover-actual-key-0001", Label: "Source"}
	prepared := e.prepared(c)
	src, err := e.store.CreateSource(e.s.scope, c.Label, prepared.ActorID, prepared.CoreKey)
	if err != nil {
		t.Fatal(err)
	}
	before := e.domain()
	e.restart()
	r, err := e.s.ReadReceipt(context.Background(), e.p, prepared.ID)
	if err != nil || r.State != "committed" || r.SourceID != src.ID || !r.AuditRecorded || !bytes.Equal(before, e.domain()) || e.policy.fetches != 0 {
		t.Fatal("recovery replayed domain or lost fact")
	}
	if err = e.s.Recover(context.Background()); err != nil || !bytes.Equal(before, e.domain()) {
		t.Fatal("second recovery changed domain")
	}
}
func TestSubscriptionControlRecoverPreparedWithoutMutationUnknown(t *testing.T) {
	e := ctlTestOpen(t)
	c := Command{Kind: Create, IdempotencyKey: "recover-unknown-key-001", Label: "Source"}
	p := e.prepared(c)
	before := e.domain()
	e.restart()
	r, err := e.s.ReadReceipt(context.Background(), e.p, p.ID)
	if err != nil || r.State != "unknown" || r.Code != CodeCommitUnknown || !r.StateMayHaveChanged || !r.AuditRecorded || !bytes.Equal(before, e.domain()) {
		t.Fatal("prepared absence automatically replayed")
	}
	_, err = e.s.Execute(context.Background(), e.p, c)
	ctlTestError(t, err, CodeCommitUnknown, true)
	if !bytes.Equal(before, e.domain()) || e.policy.fetches != 0 {
		t.Fatal("unknown retried side effect")
	}
}
func TestSubscriptionControlRecoverNoopReceiptAcrossRestart(t *testing.T) {
	e := ctlTestOpen(t)
	src := e.create("noop-source-key-0000001")
	e.imported(src.SourceID, "noop-import-key-0000001", "proxy.example")
	c := Command{Kind: Import, IdempotencyKey: "noop-import-key-0000002", SourceID: src.SourceID, ExpectedRevision: 2, Content: []byte("http://user:private-password@proxy.example:8080#private-node")}
	r := e.execute(c)
	before := e.domain()
	if r.State != "noop" || r.LocalAuditHash != "" || r.Revision != 2 {
		t.Fatal("noop invented domain receipt")
	}
	e.restart()
	again, err := e.s.Execute(context.Background(), e.p, c)
	if err != nil || !again.Replayed || again.State != "noop" || !again.AuditRecorded || !bytes.Equal(before, e.domain()) {
		t.Fatal("noop replay changed domain")
	}
}
func TestSubscriptionControlApprovalBoundToMaterialAndRevision(t *testing.T) {
	e := ctlTestOpen(t)
	src := e.create("approval-source-key-001")
	a := e.approved(src.SourceID, "approval-command-key-01")
	if a.ApprovalID != a.CommandID || !ctlDigest.MatchString(a.PolicyDigest) || a.LocalAuditHash != "" {
		t.Fatal("approval commitment shape")
	}
	e.policy.material = []byte("changed-private-material")
	_, err := e.s.Execute(context.Background(), e.p, e.fetch(src.SourceID, a, "approval-fetch-key-001"))
	ctlTestError(t, err, CodeApprovalRequired, false)
	if e.policy.fetches != 0 {
		t.Fatal("changed policy fetched")
	}
	e.policy.material = []byte("private-policy-url-and-secret-version-1")
	e.policy.revision = 2
	_, err = e.s.Execute(context.Background(), e.p, e.fetch(src.SourceID, a, "approval-fetch-key-002"))
	ctlTestError(t, err, CodeApprovalRequired, false)
	if e.policy.fetches != 0 {
		t.Fatal("changed revision fetched")
	}
}
func TestSubscriptionControlApprovalSurvivesRestart(t *testing.T) {
	e := ctlTestOpen(t)
	src := e.create("persist-source-key-0001")
	a := e.approved(src.SourceID, "persist-approval-key-01")
	before := e.domain()
	e.restart()
	r, err := e.s.ReadReceipt(context.Background(), e.p, a.CommandID)
	if err != nil || !reflect.DeepEqual(a, r) || !bytes.Equal(before, e.domain()) {
		t.Fatal("approval restart changed commitment")
	}
	fetched := e.execute(e.fetch(src.SourceID, a, "persist-fetch-key-00001"))
	if fetched.State != "committed" || fetched.Revision != 2 || e.policy.fetches != 1 {
		t.Fatal("persisted approval not usable")
	}
}
func TestSubscriptionControlFetchRequiresCurrentApproval(t *testing.T) {
	e := ctlTestOpen(t)
	src := e.create("current-source-key-0001")
	a := e.approved(src.SourceID, "current-approval-key-01")
	b := e.approved(src.SourceID, "current-approval-key-02")
	_, err := e.s.Execute(context.Background(), e.p, e.fetch(src.SourceID, a, "current-fetch-key-00001"))
	ctlTestError(t, err, CodeApprovalRequired, false)
	if e.policy.fetches != 0 || a.ApprovalID == b.ApprovalID {
		t.Fatal("old approval fetched")
	}
	e.execute(e.fetch(src.SourceID, b, "current-fetch-key-00002"))
	if e.policy.fetches != 1 {
		t.Fatal("current approval did not fetch once")
	}
}
func TestSubscriptionControlFetchRechecksApprovalAfterNetwork(t *testing.T) {
	e := ctlTestOpen(t)
	src := e.create("recheck-source-key-0001")
	a := e.approved(src.SourceID, "recheck-approval-key-01")
	before := e.domain()
	e.policy.onFetch = func(ctx context.Context, scope subscription.Scope, source string) (subscription.FetchResult, error) {
		e.policy.mu.Lock()
		e.policy.material = []byte("different-effective-material")
		e.policy.mu.Unlock()
		return ctlTestFetched(scope, source), nil
	}
	_, err := e.s.Execute(context.Background(), e.p, e.fetch(src.SourceID, a, "recheck-fetch-key-00001"))
	ctlTestError(t, err, CodeApprovalRequired, false)
	if e.policy.fetches != 1 || !bytes.Equal(before, e.domain()) {
		t.Fatal("post-network approval change imported")
	}
}
func TestSubscriptionControlFetchRechecksSourceCASAfterNetwork(t *testing.T) {
	e := ctlTestOpen(t)
	src := e.create("cas-source-key-00000001")
	a := e.approved(src.SourceID, "cas-approval-key-000001")
	e.policy.onFetch = func(ctx context.Context, scope subscription.Scope, source string) (subscription.FetchResult, error) {
		_, err := e.store.Import(subscription.ImportRequest{Scope: scope, SourceID: source, ExpectedRevision: 1, ActorID: "trusted-other-controller", IdempotencyKey: "cas-external-key-000001", Content: []byte("http://other.example:8080")})
		if err != nil {
			return subscription.FetchResult{}, err
		}
		return ctlTestFetched(scope, source), nil
	}
	_, err := e.s.Execute(context.Background(), e.p, e.fetch(src.SourceID, a, "cas-fetch-key-000000001"))
	ctlTestError(t, err, CodeConflict, false)
	items, readErr := e.store.Candidates(e.s.scope, src.SourceID)
	if readErr != nil || len(items) != 1 || e.source(src.SourceID).Revision != 2 || e.policy.fetches != 1 {
		t.Fatal("stale network result imported")
	}
}
func TestSubscriptionControlFetchFailureNeverImports(t *testing.T) {
	e := ctlTestOpen(t)
	src := e.create("failed-source-key-00001")
	a := e.approved(src.SourceID, "failed-approval-key-001")
	before := e.domain()
	e.policy.onFetch = func(context.Context, subscription.Scope, string) (subscription.FetchResult, error) {
		return subscription.FetchResult{}, errors.New("private upstream canary")
	}
	_, err := e.s.Execute(context.Background(), e.p, e.fetch(src.SourceID, a, "failed-fetch-key-000001"))
	ctlTestError(t, err, CodeUnavailable, false)
	if e.policy.fetches != 1 || !bytes.Equal(before, e.domain()) || strings.Contains(err.Error(), "canary") {
		t.Fatal("failed fetch changed domain or leaked")
	}
}
func TestSubscriptionControlCancellationBeforeMutation(t *testing.T) {
	e := ctlTestOpen(t)
	before := e.domain()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := e.s.Execute(ctx, e.p, Command{Kind: Create, IdempotencyKey: "cancel-before-key-00001", Label: "Source"})
	ctlTestError(t, err, CodeCanceled, false)
	if len(e.commands()) != 0 || !bytes.Equal(before, e.domain()) {
		t.Fatal("pre-canceled command wrote")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	e.audit.afterPrepared = cancel
	r, err := e.s.Execute(ctx, e.p, Command{Kind: Create, IdempotencyKey: "cancel-after-key-000001", Label: "Source"})
	ctlTestError(t, err, CodeCanceled, false)
	if r.State != "failed" || !r.AuditRecorded || !bytes.Equal(before, e.domain()) {
		t.Fatal("boundary cancellation performed domain work")
	}
}
func TestSubscriptionControlDenialAuditNoPrivateReadsOrNetwork(t *testing.T) {
	e := ctlTestOpen(t)
	if e.store.Close() != nil {
		t.Fatal("close private store")
	}
	if err := e.s.RecordDenied(context.Background(), e.p, authz.ActionFetchSubscription, CodeForbidden); err != nil {
		t.Fatal(err)
	}
	if e.policy.describes != 0 || e.policy.fetches != 0 {
		t.Fatal("denial touched policy")
	}
	report, err := e.audit.store.Verify()
	if err != nil || !report.Valid || report.Count != 1 {
		t.Fatal("denial missing actual audit")
	}
}
func TestSubscriptionControlExternalEvidenceActorAndSafeMetadata(t *testing.T) {
	e := ctlTestOpen(t)
	src := e.create("privacy-source-key-0001")
	e.imported(src.SourceID, "privacy-import-key-0001", "proxy.example")
	e.approved(src.SourceID, "privacy-approval-key-01")
	raw, err := os.ReadFile(filepath.Join(e.root, "audit", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{e.p.ID, "private-password", "private-node", "proxy.example", "private-policy-url", "Private source"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("external evidence leaked private input")
		}
	}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		var event evidence.EvidenceEvent
		if json.Unmarshal(line, &event) != nil || event.ActorID != e.s.actor(e.p.ID) || len(event.ActorID) > 64 {
			t.Fatal("actual audit actor not stable opaque")
		}
	}
	for _, v := range []any{e.s, *e.s, e.config()} {
		if fmt.Sprintf("%+v", v) != fmt.Sprintf("%#v", v) || strings.Contains(fmt.Sprintf("%#v", v), e.p.ID) {
			t.Fatal("formatting exposed service internals")
		}
	}
}
func TestSubscriptionControlRealLinuxRestartAuditChainAndReceipts(t *testing.T) {
	e := ctlTestOpen(t)
	src := e.create("linux-source-key-000001")
	a := e.imported(src.SourceID, "linux-import-key-000001", "proxy.example")
	before := e.domain()
	raw, err := os.ReadFile(filepath.Join(e.root, "audit", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	e.restart()
	got, err := e.s.ReadReceipt(context.Background(), e.p, a.CommandID)
	if err != nil || !reflect.DeepEqual(a, got) || !bytes.Equal(before, e.domain()) {
		t.Fatal("Linux restart receipt mismatch")
	}
	after, err := os.ReadFile(filepath.Join(e.root, "audit", "events.jsonl"))
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("startup duplicated audit")
	}
	report, err := e.audit.store.Verify()
	if err != nil || !report.Valid || report.Count != 4 {
		t.Fatal("real audit chain invalid")
	}
}
func TestSubscriptionControlConcurrentCommandsSingleFlight(t *testing.T) {
	e := ctlTestOpen(t)
	src := e.create("concurrent-source-key01")
	a := e.approved(src.SourceID, "concurrent-approve-key1")
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	var once sync.Once
	e.policy.onFetch = func(ctx context.Context, scope subscription.Scope, source string) (subscription.FetchResult, error) {
		close(entered)
		select {
		case <-release:
			return ctlTestFetched(scope, source), nil
		case <-ctx.Done():
			return subscription.FetchResult{}, ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_, err := e.s.Execute(ctx, e.p, e.fetch(src.SourceID, a, "concurrent-fetch-key01"))
		done <- err
	}()
	joined := false
	defer func() {
		cancel()
		once.Do(func() { close(release) })
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("owner did not join")
			}
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("fetch did not enter")
	}
	_, err := e.s.Execute(context.Background(), e.p, e.fetch(src.SourceID, a, "concurrent-fetch-key02"))
	ctlTestError(t, err, CodeConflict, false)
	ctlTestError(t, e.s.Recover(context.Background()), CodeConflict, false)
	e.policy.mu.Lock()
	count := e.policy.fetches
	e.policy.mu.Unlock()
	if count != 1 {
		t.Fatal("same source admitted duplicate network work")
	}
	once.Do(func() { close(release) })
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("owner did not finish")
	}
	// Deterministic snapshot/lease interleaving: Recover listed a nil result,
	// then a no-op completed before it acquired its per-source lease. Recovery
	// must re-read the actual completed record, not manufacture unknown.
	noop := Command{Kind: Import, IdempotencyKey: "concurrent-noop-key001", SourceID: src.SourceID, ExpectedRevision: 2, Content: ctlTestFetched(e.s.scope, src.SourceID).Content}
	stale := e.prepared(noop)
	result, err := e.s.executeDomain(context.Background(), e.p, noop, stale)
	if err != nil || result.State != "noop" {
		t.Fatal("prepare actual completed no-op")
	}
	if err := e.store.RecordControlResult(e.s.scope, stale.ID, result); err != nil {
		t.Fatal(err)
	}
	completed := stale
	completed.Result = &result
	if err := e.s.completeAudit(completed); err != nil {
		t.Fatal(err)
	}
	before := e.domain()
	if err := e.s.recoverCurrent(context.Background(), stale); err != nil || !bytes.Equal(before, e.domain()) {
		t.Fatal("stale recovery snapshot replaced completed no-op")
	}
	for i := 0; i < 16; i++ {
		if err = e.s.claim(fmt.Sprintf("slot-%d", i), fmt.Sprintf("source-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	ctlTestError(t, e.s.claim("over-budget", "new-source"), CodeLimit, false)
	for i := 0; i < 16; i++ {
		e.s.release(fmt.Sprintf("slot-%d", i), fmt.Sprintf("source-%d", i))
	}
}
func TestSubscriptionControlJournalCapacityAndClosedErrors(t *testing.T) {
	e := ctlTestOpen(t)
	if MaxCommandRecords != 4096 {
		t.Fatal("journal budget drift")
	}
	if MaxCommandRecords != subscription.MaxControlCommands {
		t.Fatal("journal budget drift")
	}
	e.s.denials.Store(MaxCommandRecords)
	ctlTestError(t, e.s.RecordDenied(context.Background(), e.p, authz.ActionReadSubscription, CodeForbidden), CodeLimit, false)
	if e.s.denials.Load() != MaxCommandRecords {
		t.Fatal("denial budget wrapped")
	}
	e.s.denials.Store(^uint32(0))
	ctlTestError(t, e.s.RecordDenied(context.Background(), e.p, authz.ActionReadSubscription, CodeForbidden), CodeLimit, false)
	if e.s.denials.Load() != ^uint32(0) {
		t.Fatal("saturated denial budget reset")
	}
	if e.store.Close() != nil {
		t.Fatal("close fixture")
	}
	_, err := e.s.ListSources(context.Background(), e.p)
	ctlTestError(t, err, CodeUnavailable, false)
	var zero *Service
	ctlTestError(t, zero.Recover(context.Background()), CodeUnavailable, false)
	_, err = zero.ReadReceipt(context.Background(), e.p, "cmd_"+strings.Repeat("a", 32))
	ctlTestError(t, err, CodeUnavailable, false)
}
