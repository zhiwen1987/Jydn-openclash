//go:build linux

package subscriptionctl

// These tests exercise the actual private Linux Store and local evidence log.
// They do not prove HTTP authentication, remote fetching, device publication,
// physical-crash recovery or independent external audit custody.
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
	"testing"

	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/subscription"
)

type readCtlFixture struct {
	root    string
	store   *subscription.Store
	audit   *evidence.Store
	service *Service
	config  Config
	admin   authz.Principal
}

func readCtlPrincipal(role authz.Role, id string) authz.Principal {
	return authz.Principal{ID: id, TenantID: "read-tenant", Roles: []authz.Role{role}, AllowedScopes: []authz.ResourceScope{{TenantID: "read-tenant", SiteID: "read-site", Environment: "isolated"}}}
}

func readCtlNew(t *testing.T) *readCtlFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal("prepare private read-control root")
	}
	for _, name := range []string{"domain", "audit"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal("prepare private read-control leaf")
		}
	}
	store, err := subscription.OpenStore(filepath.Join(root, "domain"))
	if err != nil {
		t.Fatal("open actual read-control domain")
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error("close actual read-control domain")
		}
	})
	audit, err := evidence.Open(filepath.Join(root, "audit"))
	if err != nil {
		t.Fatal("open actual read-control evidence")
	}
	t.Cleanup(func() {
		if err := audit.Close(); err != nil {
			t.Error("close actual read-control evidence")
		}
	})
	config := Config{Scope: authz.ResourceScope{TenantID: "read-tenant", SiteID: "read-site", ObjectType: "subscription-store", ObjectID: "local", Environment: "isolated"}, Store: store, Audit: audit, WritesEnabled: true}
	service, err := New(context.Background(), config)
	if err != nil {
		t.Fatal("construct real read-control application")
	}
	return &readCtlFixture{root: root, store: store, audit: audit, service: service, config: config, admin: readCtlPrincipal(authz.RoleAdmin, "read-admin@example.test")}
}

func readCtlCode(t *testing.T, err error, code Code, changed bool) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure == nil || failure.Code != code || failure.StateMayHaveChanged != changed {
		t.Fatal("unexpected safe read-control classification")
	}
}

func readCtlDisk(t *testing.T, f *readCtlFixture) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	for _, relative := range []string{"domain/store.json", "audit/events.jsonl", "audit/checkpoint.json"} {
		raw, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal("read actual private persistence fence")
		}
		result[relative] = raw
	}
	return result
}

func readCtlUnchanged(t *testing.T, f *readCtlFixture, before map[string][]byte) {
	t.Helper()
	if !reflect.DeepEqual(before, readCtlDisk(t, f)) {
		t.Fatal("read or rejected command changed private persistence")
	}
}

func readCtlExecute(t *testing.T, f *readCtlFixture, p authz.Principal, command Command) Receipt {
	t.Helper()
	r, err := f.service.Execute(context.Background(), p, command)
	if err != nil || r.CommandID == "" || r.State != "committed" || !r.AuditRecorded || r.StateMayHaveChanged || r.PreparedAuditHash == "" || r.ResultAuditHash == "" || r.LocalAuditHash == "" || r.CompletedAt.IsZero() {
		t.Fatal("actual local mutation did not fully commit and audit")
	}
	return r
}

func readCtlCreate(t *testing.T, f *readCtlFixture, key string) Receipt {
	t.Helper()
	return readCtlExecute(t, f, f.admin, Command{Kind: Create, Label: "测试来源", IdempotencyKey: key})
}

func readCtlBody(nodes int, suffix string) []byte {
	var raw strings.Builder
	raw.WriteString("proxies:\n")
	for i := 0; i < nodes; i++ {
		fmt.Fprintf(&raw, "  - {name: private-read-name-%s-%d, type: trojan, server: node%d.example, port: 443, password: private-read-password-%s}\n", suffix, i, i, suffix)
	}
	return []byte(raw.String())
}

func readCtlImport(t *testing.T, f *readCtlFixture, source string, count int, suffix, key string) Receipt {
	t.Helper()
	current, err := f.store.Source(f.service.scope, source)
	if err != nil {
		t.Fatal("read import CAS from real source")
	}
	return readCtlExecute(t, f, f.admin, Command{Kind: Import, SourceID: source, ExpectedRevision: current.Revision, IdempotencyKey: key, Format: subscription.FormatMihomo, Content: readCtlBody(count, suffix)})
}

func TestSubscriptionControlNewRejectsInvalidConfiguration(t *testing.T) {
	f := readCtlNew(t)
	before := readCtlDisk(t, f)
	for i := 0; i < 8; i++ {
		config := f.config
		switch i {
		case 0:
			config.Store = nil
		case 1:
			config.Audit = nil
		case 2:
			var absent *evidence.Store
			config.Audit = absent
		case 3:
			config.Scope.TenantID = ""
		case 4:
			config.Scope.SiteID = "bad/site"
		case 5:
			config.Scope.Environment = ""
		case 6:
			config.Scope.ObjectType = "subscription-source"
		case 7:
			config.Scope.ObjectID = "bad object"
		}
		service, err := New(context.Background(), config)
		readCtlCode(t, err, CodeInvalid, false)
		if service != nil {
			t.Fatal("invalid configuration constructed a service")
		}
	}
	_, err := New(nil, f.config)
	readCtlCode(t, err, CodeInvalid, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = New(ctx, f.config)
	readCtlCode(t, err, CodeCanceled, false)
	readCtlUnchanged(t, f, before)
	if f.service.Scope() != f.config.Scope {
		t.Fatal("trusted metadata scope changed")
	}
}

func TestSubscriptionControlDisabledWritesNeverTouchesDomain(t *testing.T) {
	f := readCtlNew(t)
	config := f.config
	config.WritesEnabled = false
	service, err := New(context.Background(), config)
	if err != nil {
		t.Fatal("construct disabled application")
	}
	before := readCtlDisk(t, f)
	if err := f.store.Close(); err != nil {
		t.Fatal("close domain before testing independent write gate")
	}
	for _, kind := range []Kind{Create, Import, Decide, Rollback, Approve, Fetch} {
		_, err := service.Execute(context.Background(), f.admin, Command{Kind: kind, SourceID: "src_" + strings.Repeat("a", 32)})
		readCtlCode(t, err, CodeLocked, false)
	}
	readCtlUnchanged(t, f, before)
}

func TestSubscriptionControlDirectAuthorizationAndScope(t *testing.T) {
	f := readCtlNew(t)
	created := readCtlCreate(t, f, "read-auth-create-0001")
	before := readCtlDisk(t, f)
	for i := 0; i < 8; i++ {
		p := readCtlPrincipal(authz.RoleViewer, "reader@example.test")
		switch i {
		case 0:
			p.ID = ""
		case 1:
			p.TenantID = "other-tenant"
		case 2:
			p.AllowedScopes[0].SiteID = "other-site"
		case 3:
			p.AllowedScopes[0].Environment = "production"
		case 4:
			p.Roles = nil
		case 5:
			p.Roles = []authz.Role{"unknown"}
		case 6:
			p.ID = "reader\nunsafe"
		case 7:
			p.ID = strings.Repeat("x", 4097)
		}
		_, err := f.service.ListSources(context.Background(), p)
		readCtlCode(t, err, CodeForbidden, false)
		_, err = f.service.Execute(context.Background(), p, Command{Kind: Create, Label: "拒绝", IdempotencyKey: "read-auth-denied-0001"})
		readCtlCode(t, err, CodeForbidden, false)
	}
	for _, role := range []authz.Role{authz.RoleViewer, authz.RoleAuditor, authz.RoleOperator, authz.RoleApprover, authz.RoleAdmin} {
		p := readCtlPrincipal(role, "reader@example.test")
		page, err := f.service.ListSources(context.Background(), p)
		if err != nil || page.Total != 1 {
			t.Fatal("matching read grant was rejected")
		}
	}
	viewer := readCtlPrincipal(authz.RoleViewer, "reader@example.test")
	for _, kind := range []Kind{Create, Import, Decide, Rollback, Approve, Fetch} {
		source := created.SourceID
		if kind == Create {
			source = ""
		}
		_, err := f.service.Execute(context.Background(), viewer, Command{Kind: kind, SourceID: source})
		readCtlCode(t, err, CodeForbidden, false)
	}
	sourceOnly := readCtlPrincipal(authz.RoleAdmin, "source-only@example.test")
	sourceOnly.AllowedScopes = []authz.ResourceScope{Resource(f.config.Scope, created.SourceID)}
	_, err := f.service.ListSources(context.Background(), sourceOnly)
	readCtlCode(t, err, CodeForbidden, false)
	if _, err := f.service.ListCandidates(context.Background(), sourceOnly, created.SourceID, ListQuery{}); err != nil {
		t.Fatal("matching source read was rejected")
	}
	readCtlUnchanged(t, f, before)
}

func TestSubscriptionControlActorIdentityBoundWithoutTruncation(t *testing.T) {
	f := readCtlNew(t)
	common := strings.Repeat("long-identity-", 20)
	first := readCtlPrincipal(authz.RoleOperator, common+"A@example.test")
	second := readCtlPrincipal(authz.RoleOperator, common+"B@example.test")
	command := Command{Kind: Create, Label: "身份绑定", IdempotencyKey: "read-shared-identity-0001"}
	a := readCtlExecute(t, f, first, command)
	b := readCtlExecute(t, f, second, command)
	if a.CommandID == b.CommandID || a.SourceID == b.SourceID {
		t.Fatal("distinct complete identities collided")
	}
	ca, okA, errA := f.store.ControlCommand(f.service.scope, a.CommandID)
	cb, okB, errB := f.store.ControlCommand(f.service.scope, b.CommandID)
	if errA != nil || errB != nil || !okA || !okB || ca.OwnerID != first.ID || cb.OwnerID != second.ID || ca.ActorID == cb.ActorID || len(ca.ActorID) != 64 || len(cb.ActorID) != 64 || !strings.HasPrefix(ca.ActorID, "act_") || !strings.HasPrefix(cb.ActorID, "act_") {
		t.Fatal("persistent actor projection lost full identity binding")
	}
	auditBytes := readCtlDisk(t, f)["audit/events.jsonl"]
	if bytes.Contains(auditBytes, []byte(first.ID)) || bytes.Contains(auditBytes, []byte(second.ID)) || !bytes.Contains(auditBytes, []byte(ca.ActorID)) || !bytes.Contains(auditBytes, []byte(cb.ActorID)) {
		t.Fatal("external audit identity projection is not opaque and bound")
	}
	// Exercise the private canonical command fingerprint at the legal raw-byte
	// boundary, not a claim that this synthetic byte sequence is valid YAML.
	large := Command{Kind: Import, SourceID: a.SourceID, ExpectedRevision: 1, IdempotencyKey: "read-large-fingerprint-1", Format: subscription.FormatMihomo, Content: bytes.Repeat([]byte{'x'}, subscription.MaxInputBytes)}
	material := ctlMaterial(large)
	one, err := f.store.ControlIdentity(f.service.scope, first.ID, large.IdempotencyKey, material)
	if err != nil {
		t.Fatal("legal raw command fingerprint was rejected")
	}
	large.Content[len(large.Content)-1] = 'y'
	two, err := f.store.ControlIdentity(f.service.scope, first.ID, large.IdempotencyKey, ctlMaterial(large))
	if err != nil || one.ID != two.ID || one.Fingerprint == two.Fingerprint || bytes.Contains(material, []byte(strings.Repeat("x", 128))) {
		t.Fatal("last raw byte was omitted from bounded private fingerprint")
	}
}

func TestSubscriptionControlListSourcesSafeBounded(t *testing.T) {
	f := readCtlNew(t)
	for i := 0; i < subscription.MaxSources; i++ {
		readCtlCreate(t, f, fmt.Sprintf("read-list-create-%04d", i))
	}
	before := readCtlDisk(t, f)
	page, err := f.service.ListSources(context.Background(), readCtlPrincipal(authz.RoleViewer, "reader@example.test"))
	if err != nil || page.Total != subscription.MaxSources || len(page.Sources) != subscription.MaxSources {
		t.Fatal("complete bounded source inventory missing")
	}
	seen := map[string]bool{}
	for _, source := range page.Sources {
		if seen[source.ID] || source.Scope != f.service.scope || source.Revision != 1 || source.AcceptedCandidateID != "" || source.LatestCandidateID != "" {
			t.Fatal("invalid independent source inventory")
		}
		seen[source.ID] = true
	}
	page.Sources[0].Label = "detached copy"
	again, err := f.service.ListSources(context.Background(), f.admin)
	if err != nil || again.Sources[0].Label == "detached copy" {
		t.Fatal("returned inventory mutated private state")
	}
	readCtlUnchanged(t, f, before)
	_, err = f.service.Execute(context.Background(), f.admin, Command{Kind: Create, Label: "超额", IdempotencyKey: "read-list-overflow-0001"})
	readCtlCode(t, err, CodeLimit, false)
	after, err := f.service.ListSources(context.Background(), f.admin)
	if err != nil || after.Total != subscription.MaxSources {
		t.Fatal("capacity rejection changed source inventory")
	}
}

func TestSubscriptionControlCandidateSummariesHideNodes(t *testing.T) {
	f := readCtlNew(t)
	created := readCtlCreate(t, f, "read-summary-create-0001")
	readCtlImport(t, f, created.SourceID, 2, "secret-one", "read-summary-import-0001")
	readCtlImport(t, f, created.SourceID, 3, "secret-two", "read-summary-import-0002")
	before := readCtlDisk(t, f)
	page, err := f.service.ListCandidates(context.Background(), f.admin, created.SourceID, ListQuery{Limit: 100})
	if err != nil || page.Total != 2 || len(page.Candidates) != 2 || page.Revision != 3 || page.NextOffset != nil {
		t.Fatal("actual candidate summary inventory missing")
	}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatal("marshal safe candidate summary")
	}
	for _, forbidden := range []string{"nodes", "private-read", "canonicalConfig", "password", "node0.example"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("private candidate material escaped summary")
		}
	}
	for _, summary := range page.Candidates {
		actual, err := f.store.Candidate(f.service.scope, created.SourceID, summary.ID)
		if err != nil || summary.NodeCount != actual.NodeCount || summary.Digest != actual.Digest || summary.State != subscription.CandidateQuarantined || summary.SourceID != created.SourceID || summary.Format != subscription.FormatMihomo {
			t.Fatal("summary diverged from actual parsed candidate")
		}
	}
	page.Candidates[0].Digest = "detached copy"
	again, err := f.service.ListCandidates(context.Background(), f.admin, created.SourceID, ListQuery{})
	if err != nil || again.Candidates[0].Digest == "detached copy" {
		t.Fatal("summary exposed a mutable private alias")
	}
	readCtlUnchanged(t, f, before)
}

func TestSubscriptionControlNodesPaginationBounded(t *testing.T) {
	f := readCtlNew(t)
	created := readCtlCreate(t, f, "read-nodes-create-0001")
	imported := readCtlImport(t, f, created.SourceID, 103, "node-secret", "read-nodes-import-0001")
	before := readCtlDisk(t, f)
	first, err := f.service.ListNodes(context.Background(), f.admin, created.SourceID, imported.CandidateID, ListQuery{Limit: 100})
	if err != nil || first.Total != 103 || len(first.Nodes) != 100 || first.NextOffset == nil || *first.NextOffset != 100 || first.Revision != 2 {
		t.Fatal("first bounded node page incorrect")
	}
	last, err := f.service.ListNodes(context.Background(), f.admin, created.SourceID, imported.CandidateID, ListQuery{Limit: 100, Offset: 100, Revision: first.Revision})
	if err != nil || last.Total != 103 || len(last.Nodes) != 3 || last.NextOffset != nil || last.Revision != first.Revision {
		t.Fatal("continuation node page incorrect")
	}
	seen := map[string]bool{}
	for _, node := range append(first.Nodes, last.Nodes...) {
		if len(node.ID) != 37 || seen[node.ID] || node.Label != "节点-"+node.ID[len(node.ID)-8:] || node.Protocol != "trojan" || !node.CredentialConfigured || node.State != "unknown" {
			t.Fatal("unsafe or duplicate node projection")
		}
		seen[node.ID] = true
	}
	for _, query := range []ListQuery{{Limit: 101}, {Limit: -1}, {Limit: 100, Offset: 104, Revision: 2}} {
		_, err := f.service.ListNodes(context.Background(), f.admin, created.SourceID, imported.CandidateID, query)
		readCtlCode(t, err, CodeInvalid, false)
	}
	first.Nodes[0].Label = "private alias mutation"
	again, err := f.service.ListNodes(context.Background(), f.admin, created.SourceID, imported.CandidateID, ListQuery{Limit: 1})
	if err != nil || again.Nodes[0].Label == "private alias mutation" {
		t.Fatal("node page aliased the private candidate")
	}
	readCtlUnchanged(t, f, before)
}

func TestSubscriptionControlContinuationRevisionRequired(t *testing.T) {
	f := readCtlNew(t)
	created := readCtlCreate(t, f, "read-fence-create-0001")
	imported := readCtlImport(t, f, created.SourceID, 2, "fence", "read-fence-import-0001")
	before := readCtlDisk(t, f)
	for _, query := range []ListQuery{{Limit: 1, Offset: 1}, {Limit: 1, Offset: -1}, {Limit: 1, Offset: subscription.MaxNodes + 1, Revision: 2}} {
		_, err := f.service.ListCandidates(context.Background(), f.admin, created.SourceID, query)
		readCtlCode(t, err, CodeInvalid, false)
		_, err = f.service.ListNodes(context.Background(), f.admin, created.SourceID, imported.CandidateID, query)
		readCtlCode(t, err, CodeInvalid, false)
	}
	page, err := f.service.ListNodes(context.Background(), f.admin, created.SourceID, imported.CandidateID, ListQuery{Limit: 1, Offset: 1, Revision: 2})
	if err != nil || len(page.Nodes) != 1 || page.NextOffset != nil {
		t.Fatal("correctly fenced continuation rejected")
	}
	readCtlUnchanged(t, f, before)
}

func TestSubscriptionControlContinuationRevisionConflict(t *testing.T) {
	f := readCtlNew(t)
	created := readCtlCreate(t, f, "read-change-create-0001")
	imported := readCtlImport(t, f, created.SourceID, 2, "before", "read-change-import-0001")
	page, err := f.service.ListNodes(context.Background(), f.admin, created.SourceID, imported.CandidateID, ListQuery{Limit: 1})
	if err != nil || page.Revision != 2 {
		t.Fatal("capture actual first-page revision")
	}
	readCtlImport(t, f, created.SourceID, 1, "after", "read-change-import-0002")
	before := readCtlDisk(t, f)
	for _, offset := range []int{0, 1} {
		query := ListQuery{Limit: 1, Offset: offset, Revision: page.Revision}
		_, err := f.service.ListNodes(context.Background(), f.admin, created.SourceID, imported.CandidateID, query)
		readCtlCode(t, err, CodeConflict, false)
		_, err = f.service.ListCandidates(context.Background(), f.admin, created.SourceID, query)
		readCtlCode(t, err, CodeConflict, false)
	}
	current, err := f.service.ListCandidates(context.Background(), f.admin, created.SourceID, ListQuery{Limit: 1, Offset: 1, Revision: 3})
	if err != nil || len(current.Candidates) != 1 || current.Revision != 3 || current.Total != 2 {
		t.Fatal("current fenced continuation rejected")
	}
	readCtlUnchanged(t, f, before)
}

func TestSubscriptionControlCommandReplaySameActor(t *testing.T) {
	f := readCtlNew(t)
	command := Command{Kind: Create, Label: "幂等来源", IdempotencyKey: "read-replay-same-0001"}
	first := readCtlExecute(t, f, f.admin, command)
	before := readCtlDisk(t, f)
	second, err := f.service.Execute(context.Background(), f.admin, command)
	if err != nil || !second.Replayed {
		t.Fatal("same actor replay failed")
	}
	second.Replayed = first.Replayed
	if !reflect.DeepEqual(first, second) {
		t.Fatal("replay changed immutable committed receipt")
	}
	service, err := New(context.Background(), f.config)
	if err != nil {
		t.Fatal("reconstruct application over actual verified stores")
	}
	third, err := service.Execute(context.Background(), f.admin, command)
	if err != nil || !third.Replayed {
		t.Fatal("new application lost persistent command identity")
	}
	third.Replayed = first.Replayed
	if !reflect.DeepEqual(first, third) {
		t.Fatal("application reconstruction changed command receipt")
	}
	readBack, err := service.ReadReceipt(context.Background(), f.admin, first.CommandID)
	if err != nil || !reflect.DeepEqual(readBack, first) {
		t.Fatal("read-only receipt differed from committed operation")
	}
	readCtlUnchanged(t, f, before)
}

func TestSubscriptionControlCommandReplayOtherActorDenied(t *testing.T) {
	f := readCtlNew(t)
	owner := readCtlPrincipal(authz.RoleOperator, "owner@example.test")
	command := Command{Kind: Create, Label: "所有者", IdempotencyKey: "read-owner-command-0001"}
	first := readCtlExecute(t, f, owner, command)
	before := readCtlDisk(t, f)
	other := readCtlPrincipal(authz.RoleOperator, "other@example.test")
	_, err := f.service.ReadReceipt(context.Background(), other, first.CommandID)
	readCtlCode(t, err, CodeForbidden, false)
	for _, role := range []authz.Role{authz.RoleAdmin, authz.RoleAuditor} {
		receipt, err := f.service.ReadReceipt(context.Background(), readCtlPrincipal(role, "audit-reader@example.test"), first.CommandID)
		if err != nil || receipt.CommandID != first.CommandID {
			t.Fatal("authorized oversight could not read immutable receipt")
		}
	}
	foreign := readCtlPrincipal(authz.RoleAuditor, "foreign@example.test")
	foreign.AllowedScopes[0].SiteID = "foreign-site"
	_, err = f.service.ReadReceipt(context.Background(), foreign, first.CommandID)
	readCtlCode(t, err, CodeForbidden, false)
	readCtlUnchanged(t, f, before)
	// The same public key is namespaced by full actor identity: it creates a
	// distinct command, never replays or discloses the first actor's command.
	second := readCtlExecute(t, f, other, command)
	if second.CommandID == first.CommandID || second.SourceID == first.SourceID || second.Replayed {
		t.Fatal("different actor reused another command identity")
	}
}

func TestSubscriptionControlCommandKeyConflict(t *testing.T) {
	f := readCtlNew(t)
	command := Command{Kind: Create, Label: "原始语义", IdempotencyKey: "read-conflict-command-1"}
	first := readCtlExecute(t, f, f.admin, command)
	before := readCtlDisk(t, f)
	command.Label = "不同语义"
	_, err := f.service.Execute(context.Background(), f.admin, command)
	readCtlCode(t, err, CodeConflict, false)
	readCtlUnchanged(t, f, before)
	receipt, err := f.service.ReadReceipt(context.Background(), f.admin, first.CommandID)
	if err != nil || !reflect.DeepEqual(first, receipt) {
		t.Fatal("conflicting key overwrote original receipt")
	}
	commands, err := f.store.ControlCommands(f.service.scope)
	if err != nil || len(commands) != 1 || !commands[0].Acknowledged || commands[0].Result == nil || commands[0].Result.SourceID != first.SourceID {
		t.Fatal("conflict altered persistent command journal")
	}
	verified, err := f.audit.Verify()
	if err != nil || !verified.Valid || verified.Count != 2 {
		t.Fatal("key conflict appended another audit pair")
	}
}
