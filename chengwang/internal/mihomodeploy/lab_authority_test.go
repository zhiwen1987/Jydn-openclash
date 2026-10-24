//go:build linux

package mihomodeploy

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
)

// Credentials and SnapshotManager below are REAL temporary files and real
// authn/authz code. ONLY the lifecycle disk/head/preparation are structural
// MODEL fixtures. No HTTP, owned process, collector, PUT or durability proof.
type labAuthorityFixture struct {
	authority *labAuthority
	manager   *authn.SnapshotManager
	path      string
	config    authn.File
	headers   map[string][]string
	scope     authz.ResourceScope
	now       time.Time
}
type labAuthorityModel struct {
	f       *labAuthorityFixture
	store   *lifecycleStore
	disk    *lifecycleModelDisk
	owner   *lifecycleOwnerToken
	session *labSession
	plan    Plan
}

func labAuthorityTestFixture(t *testing.T) *labAuthorityFixture {
	t.Helper()
	spec, now := planTestFixture(t)
	f := &labAuthorityFixture{scope: spec.Target.Scope, now: now, headers: make(map[string][]string), config: authn.File{Version: authn.FileVersion}}
	for _, row := range []struct{ name string; role authz.Role }{
		{"initiator", authz.RoleAdmin}, {"approver", authz.RoleApprover}, {"executor", authz.RoleAdmin},
		{"viewer", authz.RoleViewer}, {"operator", authz.RoleOperator}, {"other-approver", authz.RoleApprover}, {"outsider", authz.RoleAdmin},
	} {
		token, digest, err := authn.GenerateToken(32)
		if err != nil { t.Fatal(err) }
		scope := f.scope
		if row.name == "outsider" { scope.TenantID = "different-tenant" }
		f.headers[row.name] = []string{"Bearer " + token}
		f.config.Identities = append(f.config.Identities, authn.Identity{TokenID: row.name + "-token",
			TokenHash: digest, Principal: authz.Principal{ID: "sensitive-" + row.name, TenantID: scope.TenantID,
				Roles: []authz.Role{row.role}, AllowedScopes: []authz.ResourceScope{scope}}})
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
	f.path = filepath.Join(dir, "private-identities.json")
	f.write(t)
	manager, err := authn.OpenSnapshotManager(f.path, now)
	if err != nil { t.Fatal(err) }
	f.manager = manager
	f.authority, err = newLabAuthority(manager, f.scope)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = f.authority.close(); _ = manager.Close() })
	return f
}
func (f *labAuthorityFixture) write(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(f.config)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(f.path, raw, 0600); err != nil { t.Fatal(err) }
}
func (f *labAuthorityFixture) edit(t *testing.T, name string, edit func(*authn.Identity)) {
	t.Helper()
	for i := range f.config.Identities {
		if f.config.Identities[i].Principal.ID == "sensitive-"+name { edit(&f.config.Identities[i]); f.write(t); return }
	}
	t.Fatal("test identity missing")
}
func labAuthorityTestModel(t *testing.T, f *labAuthorityFixture) *labAuthorityModel {
	t.Helper()
	return labAuthorityTestModelOperation(t, f, "")
}
func labAuthorityTestModelOperation(t *testing.T, f *labAuthorityFixture, operationID string) *labAuthorityModel {
	t.Helper()
	initiator, err := f.authority.authenticateInitiator(f.headers["initiator"], f.now)
	if err != nil { t.Fatal(err) }
	ref, err := f.authority.initiatorReference(initiator)
	if err != nil { t.Fatal(err) }
	record, original, _ := lifecycleTestRecord(t)
	d := original.Descriptor()
	if operationID != "" {
		d.OperationID = operationID
		d.Backup, err = newBackupDescriptor(operationID, d.Backup.Artifact, d.Target)
		if err != nil { t.Fatal(err) }
	}
	plan, err := NewPlan(PlanSpec{OperationID: d.OperationID, DeclaredInitiatorRef: ref, Target: d.Target,
		Artifact: d.Artifact, Backup: d.Backup, ExpiresAt: d.ExpiresAt}, d.CreatedAt)
	if err != nil { t.Fatal(err) }
	store, disk := lifecycleTestOpen(t, record)
	owner := lifecycleTestOwner(t, store, f.now)
	if err := store.recordPlan(owner, plan, f.now); err != nil { t.Fatal(err) }
	session, err := f.authority.bindPlan(initiator, store, owner, f.now)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = store.close() })
	return &labAuthorityModel{f: f, store: store, disk: disk, owner: owner, session: session, plan: plan}
}
func (m *labAuthorityModel) approve(t *testing.T) ApprovalMaterial {
	t.Helper()
	material, err := m.f.authority.approve(m.f.headers["approver"], m.session, m.f.now)
	if err != nil { t.Fatal(err) }
	if err := m.store.recordApproval(m.owner, material, m.f.now); err != nil { t.Fatal(err) }
	return material
}
func (m *labAuthorityModel) prepare(t *testing.T) {
	t.Helper()
	m.approve(t)
	if err := m.store.recordPrepared(m.owner, lifecycleTestPrepared(t, m.plan, m.f.now), m.f.now); err != nil { t.Fatal(err) }
}
func (m *labAuthorityModel) armModel(t *testing.T) {
	t.Helper()
	m.prepare(t)
	if err := m.store.recordIntent(m.owner, m.plan.Descriptor().Target.HeadSHA256, m.f.now); err != nil { t.Fatal(err) }
}

func TestLabAuthorityRequiresCompleteFixedLabScope(t *testing.T) {
	f := labAuthorityTestFixture(t)
	if _, err := newLabAuthority(nil, f.scope); err == nil { t.Fatal("nil identity manager accepted") }
	for _, edit := range []func(*authz.ResourceScope){
		func(s *authz.ResourceScope) { s.TenantID = "" }, func(s *authz.ResourceScope) { s.SiteID = "" },
		func(s *authz.ResourceScope) { s.ObjectID = "" }, func(s *authz.ResourceScope) { s.ObjectType = "control-plane" },
		func(s *authz.ResourceScope) { s.Environment = "production" }, func(s *authz.ResourceScope) { s.SiteID = "*" },
	} {
		scope := f.scope; edit(&scope)
		if _, err := newLabAuthority(f.manager, scope); err == nil { t.Fatal("nonfixed scope accepted") }
	}
	zero, err := newLabAuthority(&authn.SnapshotManager{}, f.scope)
	if err == nil {
		if _, err := zero.authenticateInitiator(f.headers["initiator"], f.now); err == nil { t.Fatal("zero manager authenticated") }
	}
	scope := f.scope
	scope.SiteID = "another-fixed-site"
	other, err := newLabAuthority(f.manager, scope)
	if err != nil { t.Fatal(err) }
	defer other.close()
	if _, err := other.authenticateInitiator(f.headers["initiator"], f.now); err == nil { t.Fatal("same tenant silently granted another site") }
}

func TestLabAuthorityRealHeadersAndCriticalCreateCannotBeDowngraded(t *testing.T) {
	f := labAuthorityTestFixture(t)
	for _, headers := range [][]string{nil, {"Basic invalid"}, {f.headers["initiator"][0], f.headers["initiator"][0]},
		f.headers["viewer"], f.headers["operator"], f.headers["approver"], f.headers["outsider"]} {
		if handle, err := f.authority.authenticateInitiator(headers, f.now); err == nil || handle != nil { t.Fatal("untrusted/low-risk identity created critical binding") }
	}
	h, err := f.authority.authenticateInitiator(f.headers["initiator"], f.now)
	if err != nil { t.Fatal(err) }
	ref, err := f.authority.initiatorReference(h)
	if err != nil || ref != labActorReference(f.scope, "sensitive-initiator") || ref == "sensitive-initiator" { t.Fatal("initiator ref was not derived from authenticated identity") }
	f.authority.discardInitiator(h)
	if _, err := f.authority.initiatorReference(h); err == nil { t.Fatal("discarded handle still valid") }
}

func TestLabAuthorityOpaqueInitiatorCannotBeCopiedOrJSONRestored(t *testing.T) {
	f := labAuthorityTestFixture(t)
	h, err := f.authority.authenticateInitiator(f.headers["initiator"], f.now)
	if err != nil { t.Fatal(err) }
	copyValue := *h
	if _, err := f.authority.initiatorReference(&copyValue); err == nil { t.Fatal("copied initiator wrapper accepted") }
	if err := json.Unmarshal([]byte(`{"core":{}}`), &copyValue); err == nil || copyValue.core != nil { t.Fatal("JSON restored initiator") }
	if _, err := f.authority.initiatorReference(&copyValue); err == nil { t.Fatal("JSON zero binding accepted") }
}

func TestLabAuthorityBindsOnlyActualCurrentWALAndLiveOwner(t *testing.T) {
	f := labAuthorityTestFixture(t)
	m := labAuthorityTestModel(t, f)
	h, err := f.authority.authenticateInitiator(f.headers["initiator"], f.now)
	if err != nil { t.Fatal(err) }
	if _, err := f.authority.bindPlan(h, nil, m.owner, f.now); err == nil { t.Fatal("missing actual store accepted") }
	copyOwner := *m.owner
	if _, err := f.authority.bindPlan(h, m.store, &copyOwner, f.now); err == nil { t.Fatal("copied owner accepted") }
	if _, err := f.authority.bindPlan(h, m.store, nil, f.now); err == nil { t.Fatal("nil owner accepted") }
	if _, err := f.authority.bindPlan(h, m.store, m.owner, f.now); err == nil { t.Fatal("same operation created duplicate session") }
	foreign, err := f.authority.authenticateInitiator(f.headers["executor"], f.now)
	if err != nil { t.Fatal(err) }
	if _, err := f.authority.bindPlan(foreign, m.store, m.owner, f.now); err == nil { t.Fatal("self-reported initiator ref mismatch accepted") }
}

func TestLabAuthorityCannotConstructSessionWithoutHeadOrPlan(t *testing.T) {
	f := labAuthorityTestFixture(t)
	record, _, _ := lifecycleTestRecord(t)
	record.wire.Head = nil
	record = lifecycleTestSeal(t, record)
	store, _ := lifecycleTestOpen(t, record)
	defer store.close()
	h, err := f.authority.authenticateInitiator(f.headers["initiator"], f.now)
	if err != nil { t.Fatal(err) }
	if _, err := f.authority.bindPlan(h, store, nil, f.now); err == nil { t.Fatal("missing head created session") }
}

func TestLabAuthoritySelfApprovalAndInsufficientApproverRolesReject(t *testing.T) {
	f := labAuthorityTestFixture(t)
	f.edit(t, "viewer", func(i *authn.Identity) { i.Principal.BreakGlassEligible = true })
	m := labAuthorityTestModel(t, f)
	for _, name := range []string{"initiator", "viewer", "operator", "outsider"} {
		if _, err := f.authority.approve(f.headers[name], m.session, f.now); err == nil { t.Fatal("self or unauthorized approval accepted") }
	}
	material, err := f.authority.approve(f.headers["approver"], m.session, f.now)
	if err != nil || material.InitiatorRef != labActorReference(f.scope, "sensitive-initiator") || material.ApproverRef != labActorReference(f.scope, "sensitive-approver") {
		t.Fatal("real independent approval failed")
	}
}

func TestLabAuthorityApprovalRetryCannotSwitchAuthenticatedApprover(t *testing.T) {
	f := labAuthorityTestFixture(t)
	m := labAuthorityTestModel(t, f)
	first, err := f.authority.approve(f.headers["approver"], m.session, f.now)
	if err != nil { t.Fatal(err) }
	again, err := f.authority.approve(f.headers["approver"], m.session, f.now.Add(time.Second))
	if err != nil || !reflect.DeepEqual(first, again) { t.Fatal("same pending approval changed material") }
	if _, err := f.authority.approve(f.headers["other-approver"], m.session, f.now.Add(time.Second)); err == nil { t.Fatal("retry switched approval identity") }
}

func TestLabAuthorityMaterialIsNotPermissionUntilExactWALRecord(t *testing.T) {
	f := labAuthorityTestFixture(t)
	m := labAuthorityTestModel(t, f)
	material, err := f.authority.approve(f.headers["approver"], m.session, f.now)
	if err != nil { t.Fatal(err) }
	before := bytes.Clone(m.disk.raw)
	if check, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, f.now); err == nil || check.core != nil { t.Fatal("unrecorded material authorized dispatch check") }
	if !bytes.Equal(before, m.disk.raw) { t.Fatal("authorization check wrote WAL") }
	material.ApproverRef = "caller-forged-approver"
	if err := m.store.recordApproval(m.owner, material, f.now); err != nil { t.Fatal(err) }
	if err := m.store.recordPrepared(m.owner, lifecycleTestPrepared(t, m.plan, f.now), f.now); err != nil { t.Fatal(err) }
	if _, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, f.now); err == nil { t.Fatal("forged but structurally admissible material became authority") }
}

func TestLabAuthorityChecksPreparedAndArmedWithoutExecutingAnything(t *testing.T) {
	f := labAuthorityTestFixture(t)
	m := labAuthorityTestModel(t, f)
	m.approve(t)
	if _, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, f.now); err == nil { t.Fatal("approved but unprepared state accepted") }
	if err := m.store.recordPrepared(m.owner, lifecycleTestPrepared(t, m.plan, f.now), f.now); err != nil { t.Fatal(err) }
	before := bytes.Clone(m.disk.raw)
	check, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, f.now)
	if err != nil || check.core == nil || check.core.operationID != m.plan.Descriptor().OperationID || check.core.intentSHA != "" || !bytes.Equal(before, m.disk.raw) { t.Fatal("prepared check failed or wrote state") }
	if err := m.store.recordIntent(m.owner, m.plan.Descriptor().Target.HeadSHA256, f.now); err != nil { t.Fatal(err) }
	check, err = f.authority.authorizeDispatch(f.headers["executor"], m.session, f.now)
	if err != nil || check.core.intentSHA != m.store.record.wire.Active.Intent.IntentSHA256 || m.store.record.wire.Active.Result != nil { t.Fatal("armed check fabricated a result") }
}

func TestLabAuthorityDispatchRequiresCurrentExecutorRoleAndScope(t *testing.T) {
	f := labAuthorityTestFixture(t)
	m := labAuthorityTestModel(t, f)
	m.prepare(t)
	for _, name := range []string{"viewer", "operator", "approver", "outsider"} {
		if _, err := f.authority.authorizeDispatch(f.headers[name], m.session, f.now); err == nil { t.Fatal("noncritical or wrongscope executor accepted") }
	}
}

func TestLabAuthorityCredentialChangesAndRestoreNeverReviveSession(t *testing.T) {
	for _, change := range []struct{ name string; edit func(*authn.Identity) }{
		{"disabled", func(i *authn.Identity) { i.Disabled = true }},
		{"roles", func(i *authn.Identity) { i.Principal.Roles = []authz.Role{authz.RoleViewer} }},
		{"scope", func(i *authn.Identity) { i.Principal.AllowedScopes[0].SiteID = "other-site" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			f := labAuthorityTestFixture(t); m := labAuthorityTestModel(t, f); m.prepare(t)
			original, err := os.ReadFile(f.path); if err != nil { t.Fatal(err) }
			f.edit(t, "initiator", change.edit)
			if _, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, f.now); err == nil { t.Fatal("changed identity retained session") }
			if err := os.WriteFile(f.path, original, 0600); err != nil { t.Fatal(err) }
			if _, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, f.now); err == nil { t.Fatal("old file bytes revived session") }
		})
	}
}

func TestLabAuthorityExpiredOriginalIdentitiesRejectEvenUnchangedBytes(t *testing.T) {
	for _, name := range []string{"initiator", "approver"} {
		t.Run(name, func(t *testing.T) {
			f := labAuthorityTestFixture(t)
			expires := f.now.Add(time.Minute)
			f.edit(t, name, func(i *authn.Identity) { i.ExpiresAt = &expires })
			m := labAuthorityTestModel(t, f); m.prepare(t)
			if _, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, expires); err == nil { t.Fatal("expired original identity authorized dispatch") }
		})
	}
}

func TestLabAuthorityRoleChangeBeforeApprovalRejectsOriginalInitiator(t *testing.T) {
	f := labAuthorityTestFixture(t)
	m := labAuthorityTestModel(t, f)
	f.edit(t, "initiator", func(i *authn.Identity) { i.Principal.Roles = []authz.Role{authz.RoleViewer} })
	if _, err := f.authority.approve(f.headers["approver"], m.session, f.now); err == nil { t.Fatal("initiator no longer eligible for critical create") }
}

func TestLabAuthoritySessionsCannotCrossInstanceOrManagerRestart(t *testing.T) {
	f := labAuthorityTestFixture(t); m := labAuthorityTestModel(t, f); m.prepare(t)
	other, err := newLabAuthority(f.manager, f.scope); if err != nil { t.Fatal(err) }; defer other.close()
	if _, err := other.authorizeDispatch(f.headers["executor"], m.session, f.now); err == nil { t.Fatal("session transferred to another authority") }
	manager, err := authn.OpenSnapshotManager(f.path, f.now); if err != nil { t.Fatal(err) }; defer manager.Close()
	restarted, err := newLabAuthority(manager, f.scope); if err != nil { t.Fatal(err) }; defer restarted.close()
	if _, err := restarted.authorizeDispatch(f.headers["executor"], m.session, f.now); err == nil { t.Fatal("reopened credential bytes restored approval") }
	if m.store.record.wire.Active.Approval.AuthoritySnapshotRef != nil { t.Fatal("snapshot ref leaked into persisted approval") }
}

func TestLabAuthorityCopiedAndJSONSessionsAreNotIssuedHandles(t *testing.T) {
	f := labAuthorityTestFixture(t); m := labAuthorityTestModel(t, f); m.prepare(t)
	copyValue := *m.session
	if _, err := f.authority.authorizeDispatch(f.headers["executor"], &copyValue, f.now); err == nil { t.Fatal("copied session wrapper accepted") }
	if err := json.Unmarshal([]byte(`{"core":{"approved":true}}`), &copyValue); err == nil || copyValue.core != nil { t.Fatal("JSON supplied session authority") }
	if _, err := f.authority.authorizeDispatch(f.headers["executor"], &copyValue, f.now); err == nil { t.Fatal("zero session accepted") }
}

func TestLabAuthorityExternalWALChangesPoisonBindingInsteadOfTrustingDTO(t *testing.T) {
	f := labAuthorityTestFixture(t); m := labAuthorityTestModel(t, f); m.prepare(t)
	changed, err := m.store.copyRecord(); if err != nil { t.Fatal(err) }
	changed.wire.Revision++
	changed = lifecycleTestSeal(t, changed)
	m.disk.raw, err = encodeLifecycleRecord(changed); if err != nil { t.Fatal(err) }
	if _, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, f.now); err == nil || !m.store.poisoned { t.Fatal("external WAL revision accepted as bound source") }
}

func TestLabAuthoritySessionAndMaterialCannotCrossOperationOrStore(t *testing.T) {
	f := labAuthorityTestFixture(t)
	first := labAuthorityTestModel(t, f)
	material := first.approve(t)
	second := labAuthorityTestModelOperation(t, f, "operation-b")
	before := bytes.Clone(second.disk.raw)
	if err := second.store.recordApproval(second.owner, material, f.now); err == nil || !bytes.Equal(before, second.disk.raw) { t.Fatal("different operation accepted old material") }
	if _, err := f.authority.authorizeRevoke(f.headers["approver"], second.store, second.owner, first.session, f.now); err == nil { t.Fatal("session's stored identity relation transferred to another operation/store") }
	forged := &labSession{core: first.session.core}
	if _, err := f.authority.approve(f.headers["approver"], forged, f.now); err == nil { t.Fatal("copied core reconstructed an issued session") }
}

func TestLabAuthorityRevokeRequiresRelatedIdentityOrScopedAdmin(t *testing.T) {
	f := labAuthorityTestFixture(t); m := labAuthorityTestModel(t, f); m.approve(t)
	before := bytes.Clone(m.disk.raw)
	for _, name := range []string{"viewer", "operator", "other-approver", "outsider"} {
		if _, err := f.authority.authorizeRevoke(f.headers[name], m.store, m.owner, m.session, f.now); err == nil { t.Fatal("unrelated revoker accepted") }
	}
	for _, name := range []string{"initiator", "approver", "executor"} {
		if check, err := f.authority.authorizeRevoke(f.headers[name], m.store, m.owner, m.session, f.now); err != nil || check.core.action != "REVOKE_AUTHORIZATION_CHECK" { t.Fatal("legitimate cancellation check rejected") }
	}
	if !bytes.Equal(before, m.disk.raw) { t.Fatal("authorization layer committed a revocation itself") }
}

func TestLabAuthorityLostSessionDoesNotInventApproverFromOpaqueRefs(t *testing.T) {
	f := labAuthorityTestFixture(t); m := labAuthorityTestModel(t, f); m.approve(t)
	restarted, err := newLabAuthority(f.manager, f.scope); if err != nil { t.Fatal(err) }; defer restarted.close()
	if _, err := restarted.authorizeRevoke(f.headers["approver"], m.store, m.owner, nil, f.now); err == nil { t.Fatal("opaque saved refs turned into a real initiator identity") }
	if _, err := restarted.authorizeRevoke(f.headers["executor"], m.store, m.owner, nil, f.now); err != nil { t.Fatal("current scoped admin cannot cancel lost-session plan") }
}

func TestLabAuthorityRevocationBlocksDispatchButDoesNotEraseObservedResult(t *testing.T) {
	f := labAuthorityTestFixture(t); m := labAuthorityTestModel(t, f); m.armModel(t)
	check, err := f.authority.authorizeRevoke(f.headers["approver"], m.store, m.owner, m.session, f.now)
	if err != nil { t.Fatal(err) }
	if err := m.store.recordRevocation(m.owner, "EXPLICIT_REVOKED", check.core.actorRef, f.now); err != nil { t.Fatal(err) }
	if _, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, f.now); err == nil { t.Fatal("revoked session passed dispatch") }
	// A structural observed-result fixture, NOT a real controller response.
	intent := m.store.record.wire.Active.Intent.IntentSHA256
	if err := m.store.recordResult(m.owner, intent, mihomo.ReloadResult{State: mihomo.ReloadAcknowledged, Dispatched: true, StatusCode: 204}, f.now); err != nil { t.Fatal(err) }
	if m.store.record.wire.Active.Revocation == nil || m.store.record.wire.Active.Result == nil { t.Fatal("revocation discarded result facts") }
}

func TestLabAuthorityExpiredLeasePreventsSendingButAllowsCancellationCheck(t *testing.T) {
	f := labAuthorityTestFixture(t); m := labAuthorityTestModel(t, f); m.armModel(t)
	later := f.now.Add(3*time.Minute)
	if _, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, later); err == nil { t.Fatal("expired live owner authorized new sending") }
	if _, err := f.authority.authorizeRevoke(f.headers["executor"], m.store, m.owner, nil, later); err != nil { t.Fatal("expired lease erased permission to record cancellation") }
}

func TestLabAuthorityClockFailureAndCloseCannotRestoreOldSession(t *testing.T) {
	f := labAuthorityTestFixture(t); m := labAuthorityTestModel(t, f); m.prepare(t)
	if _, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, f.now.Add(-time.Second)); err == nil { t.Fatal("clock rollback accepted") }
	if _, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, f.now); err == nil { t.Fatal("clock recovery revived private binding") }
	if err := f.authority.close(); err != nil { t.Fatal(err) }
	if _, err := f.authority.authenticateInitiator(f.headers["initiator"], f.now); err == nil { t.Fatal("closed authority authenticated") }
	if _, _, err := f.manager.AuthenticateAuthorizationValues(f.headers["initiator"], f.now); err != nil { t.Fatal("authority incorrectly closed borrowed manager") }
}

func TestLabAuthorityClosedManagerFailsEvenWithRetainedSession(t *testing.T) {
	f := labAuthorityTestFixture(t); m := labAuthorityTestModel(t, f); m.prepare(t)
	if err := f.manager.Close(); err != nil { t.Fatal(err) }
	if _, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, f.now); err == nil { t.Fatal("closed manager retained sending eligibility") }
}

func TestLabAuthorityFormattingAndJSONNeverExposeIdentityTokenOrBinding(t *testing.T) {
	f := labAuthorityTestFixture(t); m := labAuthorityTestModel(t, f); m.prepare(t)
	check, err := f.authority.authorizeDispatch(f.headers["executor"], m.session, f.now); if err != nil { t.Fatal(err) }
	initiator, err := f.authority.authenticateInitiator(f.headers["initiator"], f.now); if err != nil { t.Fatal(err) }
	for _, value := range []any{*f.authority, f.authority, *initiator, initiator, *m.session, m.session, check, &check} {
		for _, format := range []string{"%v", "%#v", "%+v", "%s", "%d", "%x", "%q"} {
			if got := fmt.Sprintf(format, value); got != labAuthorityDebug { t.Fatal("ordinary debug output exposed binding") }
		}
		for _, format := range []string{"%p", "%#p", "%T", "%w"} {
			got := fmt.Sprintf(format, value)
			for _, identity := range f.config.Identities {
				for _, forbidden := range []string{identity.Principal.ID, identity.TokenHash, f.path, m.plan.Descriptor().PlanSHA256, m.session.core.initiatorActor} {
					if strings.Contains(got, forbidden) { t.Fatal("special debug output exposed private state") }
				}
			}
			for _, headers := range f.headers {
				token := strings.TrimPrefix(headers[0], "Bearer ")
				for _, forbidden := range []string{token, hex.EncodeToString([]byte(token)), base64.StdEncoding.EncodeToString([]byte(token))} {
					if strings.Contains(got, forbidden) { t.Fatal("token escaped special debug output") }
				}
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `{"scope":"LAB_AUTHORIZATION_CHECK_NOT_EXECUTION"}` { t.Fatal("JSON exported authority internals") }
	}
	for _, value := range []any{(*labAuthority)(nil), (*labInitiator)(nil), (*labSession)(nil), (*labAuthorityCheck)(nil)} {
		if fmt.Sprintf("%#v", value) != "<nil>" { t.Fatal("typed nil formatting unsafe") }
		raw, err := json.Marshal(value); if err != nil || string(raw) != "null" { t.Fatal("typed nil JSON unsafe") }
	}
}

func TestLabAuthorityZeroNilAndForgedCheckCannotGrantAnything(t *testing.T) {
	var authority *labAuthority
	if _, err := authority.authenticateInitiator(nil, time.Now()); err == nil { t.Fatal("nil authority accepted") }
	if _, err := (&labAuthority{}).authorizeDispatch(nil, &labSession{}, time.Now()); err == nil { t.Fatal("zero authority accepted") }
	var check labAuthorityCheck
	if err := json.Unmarshal([]byte(`{"approved":true,"role":"admin"}`), &check); err == nil || check.core != nil { t.Fatal("JSON created authorization check") }
	if labAuthorityErrorCode(nil) != "authority_unavailable" || labAuthorityErrorCode(labAuthorityFailure("self_approval")) != "self_approval" { t.Fatal("safe error code accessor changed") }
}
