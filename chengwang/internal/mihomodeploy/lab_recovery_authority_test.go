//go:build linux

package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/authz"
)

// REAL SnapshotManager, private0700 temporary credential files, actual header
// authentication and policy. Only the WAL/process/quiescence are structural
// MODEL fixtures. No product HTTP, process signal, Stop/Start or OS proof.
type labRecoveryAuthorityModel struct {
	f *labAuthorityFixture
	a *labRecoveryAuthority
	store *lifecycleRecoveryStore
	disk *lifecycleModelDisk
	owner *lifecycleRecoveryOwnerToken
	session *labRecoverySession
	plan labRecoveryPlan
	identity labKernelIdentity
}

func labRecoveryAuthorityTestModel(t *testing.T) *labRecoveryAuthorityModel {
	t.Helper()
	f:=labAuthorityTestFixture(t)
	a,err:=newLabRecoveryAuthority(f.authority,f.now);if err!=nil {t.Fatal("MODEL recovery authority")}
	t.Cleanup(func(){_=a.close()})
	h,err:=a.captureInitiator(f.headers["initiator"],f.now);if err!=nil {t.Fatal("actual recovery initiator authentication")}
	actor,err:=a.initiatorReference(h);if err!=nil {t.Fatal("actual actor reference")}
	prototype,_,_,oldPlan,identity,now:=lifecycleRecoveryStopModel(t)
	original,err:=lifecycleV3Source(prototype.core.record.core);if err!=nil {t.Fatal("MODEL original record")}
	p,err:=newLabRecoveryPlan(original,oldPlan.descriptor().RecoveryID,actor,oldPlan.descriptor().TargetArtifact,now,now.Add(time.Minute));if err!=nil {t.Fatal("MODEL bound recovery plan")}
	raw,err:=encodeLifecycleRecord(original);if err!=nil {t.Fatal("MODEL original encode")}
	v3,err:=buildLifecycleV3Evolution(raw,&p,now);if err!=nil {t.Fatal("MODEL evolution")}
	encoded,err:=encodeLifecycleV3Record(v3);if err!=nil {t.Fatal("MODEL v3 encode")}
	disk:=&lifecycleModelDisk{raw:encoded,exists:true,state:lifecycleCommitted}
	store,err:=openLifecycleRecoveryStore(disk,now);if err!=nil {t.Fatal("MODEL store")}
	owner,err:=store.acquireRecoveryOwner(now,now.Add(time.Minute));if err!=nil {t.Fatal("MODEL recovery owner")}
	if store.beginRecovery(owner,&p,store.core.record.core.Revision,store.core.record.core.RecordSHA256,now)!=nil {t.Fatal("MODEL durable plan")}
	session,err:=a.bindPlan(h,store,owner,now);if err!=nil {t.Fatal("actual identity could not bind MODEL WAL")}
	t.Cleanup(func(){_=store.close();_=prototype.close()})
	return &labRecoveryAuthorityModel{f,a,store,disk,owner,session,p,identity}
}
func (m *labRecoveryAuthorityModel) approve(t *testing.T) lifecycleRecoveryApproval {
	t.Helper();material,err:=m.a.approve(m.f.headers["approver"],m.session,m.f.now)
	if err!=nil {t.Fatal("actual independent recovery approval")}
	if m.store.recordRecoveryApproval(m.owner,material,m.f.now)!=nil {t.Fatal("MODEL approval persistence")}
	return material
}
func (m *labRecoveryAuthorityModel) armStop(t *testing.T) labQuiescenceBinding {
	t.Helper();m.approve(t);b,err:=m.store.armRecoveryStop(m.owner,m.identity,m.f.now)
	if err!=nil {t.Fatal("MODEL STOP intent")};return b
}
func (m *labRecoveryAuthorityModel) armStart(t *testing.T) *labRecoveryStartPermit {
	t.Helper();b:=m.armStop(t);fact:=lifecycleRecoveryModelFact(b,m.f.now)
	q:=lifecycleRecoveryIssuedModel(t,b,fact)
	if m.store.recordRecoveryQuiescence(m.owner,q,m.f.now)!=nil {t.Fatal("MODEL actual registry consumption")}
	p,err:=m.store.armRecoveryStart(m.owner,m.f.now);if err!=nil {t.Fatal("MODEL durable START intent")};return p
}

func TestLabRecoveryAuthorityRealHeadersAndDedicatedPreparePolicy(t *testing.T) {
	f:=labAuthorityTestFixture(t);a,err:=newLabRecoveryAuthority(f.authority,f.now);if err!=nil {t.Fatal("authority setup")};defer a.close()
	for _,headers:=range [][]string{nil,{"Basic invalid"},{f.headers["initiator"][0],f.headers["initiator"][0]},f.headers["viewer"],f.headers["operator"],f.headers["approver"],f.headers["outsider"]} {
		if _,err:=a.captureInitiator(headers,f.now);err==nil {t.Fatal("unauthorized recovery initiator")}
	}
	h,err:=a.captureInitiator(f.headers["initiator"],f.now);if err!=nil {t.Fatal("current critical admin rejected")}
	actor,err:=a.initiatorReference(h)
	if err!=nil||actor!=labActorReference(f.scope,"sensitive-initiator") {t.Fatal("actual initiator reference mismatch")}
}

func TestLabRecoveryAuthorityConstructorNilZeroUTCAndBorrowedBase(t *testing.T) {
	if _,err:=newLabRecoveryAuthority(nil,time.Now().UTC());err==nil {t.Fatal("nil base accepted")}
	if _,err:=newLabRecoveryAuthority(&labAuthority{},time.Now().UTC());err==nil {t.Fatal("zero base accepted")}
	f:=labAuthorityTestFixture(t)
	for _,now:=range []time.Time{{},f.now.In(time.FixedZone("MODEL",0)),f.now.Add(-time.Nanosecond)} {
		// Separate base instances keep the rollback poison intentionally local.
		base,err:=newLabAuthority(f.manager,f.scope);if err!=nil {t.Fatal("base setup")}
		base.core.lastTime=f.now
		if _,err:=newLabRecoveryAuthority(base,now);err==nil {t.Fatal("invalid constructor time accepted")}
		_=base.close()
	}
	a,err:=newLabRecoveryAuthority(f.authority,f.now);if err!=nil {t.Fatal("borrowed authority")}
	if a.core.base!=f.authority||a.core.base.core.manager!=f.manager {t.Fatal("replaced manager or base")}
	_=a.close()
}

func TestLabRecoveryAuthorityBindReadsVerifiedWALAndConsumesIssuedInitiator(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t)
	if m.session.core.plan.DeclaredInitiatorRef!=labActorReference(m.f.scope,"sensitive-initiator")||m.session.core.storeCore!=m.store.core||m.session.core.fence!=m.store.core.record.core.LastRecoveryFence {t.Fatal("real binding missing")}
	if len(m.a.core.initiators)!=0||len(m.a.core.sessions)!=1 {t.Fatal("initiator not consumed")}
	if _,err:=m.a.bindPlan(nil,m.store,m.owner,m.f.now);err==nil {t.Fatal("nil initiator bound")}
	m.disk.raw=append(m.disk.raw,' ')
	if _,err:=m.a.approve(m.f.headers["approver"],m.session,m.f.now);err==nil {t.Fatal("unverified WAL accepted")}
}

func TestLabRecoveryAuthoritySelfApprovalWrongRolesAndScopeCannotApprove(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t)
	for _,name:=range []string{"initiator","viewer","operator","outsider"} {
		if _,err:=m.a.approve(m.f.headers[name],m.session,m.f.now);err==nil {t.Fatal("invalid independent approval")}
	}
	if m.session.core.material!=nil||m.store.core.record.core.Recovery.Approval!=nil {t.Fatal("failed approval left material")}
	material,err:=m.a.approve(m.f.headers["approver"],m.session,m.f.now)
	if err!=nil||material.DeclaredApproverRef!=labActorReference(m.f.scope,"sensitive-approver")||m.store.core.record.core.Recovery.Approval!=nil {t.Fatal("approval became durable permission without write")}
}

func TestLabRecoveryAuthorityApprovalMaterialDetachedAndNotReboundToAnotherApprover(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t)
	material,err:=m.a.approve(m.f.headers["approver"],m.session,m.f.now);if err!=nil {t.Fatal("approval")}
	original:=material;material.DeclaredApproverRef="MODEL_MUTATED"
	again,err:=m.a.approve(m.f.headers["approver"],m.session,m.f.now)
	if err!=nil||!reflect.DeepEqual(again,original) {t.Fatal("approval output aliases registry")}
	if _,err:=m.a.approve(m.f.headers["other-approver"],m.session,m.f.now);err==nil {t.Fatal("different approver rebound material")}
}

func TestLabRecoveryAuthorityBothCurrentIdentitiesAndExecutorAreRefreshed(t *testing.T) {
	for _,identity:=range []string{"initiator","approver","executor"} {
		m:=labRecoveryAuthorityTestModel(t);m.armStop(t);before:=bytes.Clone(m.disk.raw)
		m.f.edit(t,identity,func(i *authn.Identity){i.Disabled=true})
		if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err==nil {t.Fatal("disabled current identity authorized step")}
		if !bytes.Equal(before,m.disk.raw) {t.Fatal("rejected auth changed actual result history")}
	}
}

func TestLabRecoveryAuthorityCredentialRotationAndRestoredBytesNeverReviveRefs(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t);m.armStop(t)
	original,err:=os.ReadFile(m.f.path);if err!=nil {t.Fatal("credential snapshot")}
	m.f.edit(t,"initiator",func(i *authn.Identity){i.Disabled=true})
	if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err==nil {t.Fatal("rotation not observed")}
	if os.WriteFile(m.f.path,original,0600)!=nil {t.Fatal("restore fixture bytes")}
	if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err==nil {t.Fatal("restored bytes revived old approval refs")}
}

func TestLabRecoveryAuthorityMissingAndUnreadableSnapshotCannotFallBack(t *testing.T) {
	for _,mode:=range []string{"missing","permissions"} {
		m:=labRecoveryAuthorityTestModel(t);m.armStop(t)
		if mode=="missing" {if os.Remove(m.f.path)!=nil {t.Fatal("remove snapshot")}} else {if os.Chmod(m.f.path,0644)!=nil {t.Fatal("permission fixture")}}
		if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err==nil {t.Fatal("snapshot fallback")}
		if mode=="missing" {m.f.write(t)} else {if os.Chmod(m.f.path,0600)!=nil {t.Fatal("restore mode")}}
		if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err==nil {t.Fatal("read failure revived retired refs")}
	}
}

func TestLabRecoveryAuthorityCurrentScopeAndRoleChangesInvalidateOldApproval(t *testing.T) {
	for _,kind:=range []string{"scope","role","expiry"} {
		m:=labRecoveryAuthorityTestModel(t);m.armStop(t)
		m.f.edit(t,"approver",func(i *authn.Identity){
			switch kind {case "scope":i.Principal.AllowedScopes[0].SiteID="different-site"
			case "role":i.Principal.Roles=[]authz.Role{authz.RoleViewer}
			case "expiry":at:=m.f.now;i.ExpiresAt=&at}
		})
		if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err==nil {t.Fatal("changed current scope/role/expiry accepted")}
	}
}

func TestLabRecoveryAuthorityStopRequiresDurableApprovalAndArmedIntent(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t)
	if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err==nil {t.Fatal("unapproved STOP")}
	material,err:=m.a.approve(m.f.headers["approver"],m.session,m.f.now);if err!=nil {t.Fatal("actual approval")}
	if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err==nil {t.Fatal("undurable approval granted STOP")}
	if m.store.recordRecoveryApproval(m.owner,material,m.f.now)!=nil {t.Fatal("persist approval")}
	if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err==nil {t.Fatal("STOP without durable intent")}
	if _,err:=m.store.armRecoveryStop(m.owner,m.identity,m.f.now);err!=nil {t.Fatal("arm STOP")}
	before:=m.disk.writes
	check,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now)
	if err!=nil||check.core==nil||check.core.intentSHA256!=m.store.core.record.core.Recovery.StopIntent.IntentSHA256||m.disk.writes!=before {t.Fatal("current check was not a readonly actual-WAL observation")}
}

func TestLabRecoveryAuthorityOldPublishOrStructuralApprovalCannotReplaceRecoveryApproval(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t)
	old:=labAuthorityTestModel(t,m.f);oldApproval:=old.approve(t)
	// Even valid newly hashed structural recovery metadata using the actual
	// old publish approver does not enter the new live approval registry.
	fake,err:=newLifecycleRecoveryApproval(&m.plan,oldApproval.ApproverRef,m.f.now,m.plan.descriptor().ExpiresAt)
	if err!=nil||m.store.recordRecoveryApproval(m.owner,fake,m.f.now)!=nil {t.Fatal("MODEL structural approval fixture")}
	if _,err:=m.store.armRecoveryStop(m.owner,m.identity,m.f.now);err!=nil {t.Fatal("MODEL stop fixture")}
	if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err==nil {t.Fatal("old/serialized material became recovery approval")}
}

func TestLabRecoveryAuthorityStartRequiresActualStorePermitWithoutConsumingIt(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t);permit:=m.armStart(t)
	if m.store.core.quiescenceSHA!="" {t.Fatal("MODEL START arming did not transfer provenance")}
	before:=m.disk.writes
	check,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"START",m.f.now)
	if err!=nil||check.core==nil||m.store.core.permit!=permit.core||m.disk.writes!=before {t.Fatal("START check consumed permit or required spent q cache")}
	if _,err:=permit.consumeRecoveryStart(m.f.now);err!=nil {t.Fatal("readonly auth consumed real permit")}
	if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"START",m.f.now);err==nil {t.Fatal("spent permit remained authorizable")}
}

func TestLabRecoveryAuthorityStartRejectsForgedPermitAndWrongCurrentBinding(t *testing.T) {
	for _,kind:=range []string{"nil","store","fence","intent","revision","record","quiescence","target","time"} {
		m:=labRecoveryAuthorityTestModel(t);m.armStart(t);p:=m.store.core.permit
		switch kind {case "nil":m.store.core.permit=nil
		case "store":p.store=&lifecycleRecoveryStoreCore{}
		case "fence":p.fence++
		case "intent":p.fact.StartIntentSHA256=strings.Repeat("f",64)
		case "revision":p.fact.Revision++
		case "record":p.fact.RecordSHA256=strings.Repeat("f",64)
		case "quiescence":p.fact.QuiescenceSHA256=strings.Repeat("f",64)
		case "target":p.fact.TargetArtifact.Config.Capabilities[0]="MODEL"
		case "time":p.fact.ArmedAt=p.fact.ArmedAt.Add(time.Second)}
		if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"START",m.f.now);err==nil {t.Fatal("forged current START permit accepted")}
	}
}

func TestLabRecoveryAuthorityLateFactsNeverAuthorizeStart(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t);b:=m.armStop(t);fact:=lifecycleRecoveryModelFact(b,m.f.now)
	q:=lifecycleRecoveryIssuedModel(t,b,fact);late:=m.f.now.Add(2*time.Minute)
	if m.store.recordRecoveryQuiescence(m.owner,q,late)!=nil {t.Fatal("MODEL late happened fact lost")}
	if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"START",late);err==nil {t.Fatal("late fact granted recovery START")}
	if m.store.core.record.core.Recovery.Quiescence==nil||m.store.core.record.core.Recovery.Phase!="RECOVERY_UNKNOWN" {t.Fatal("auth rejection erased late fact")}
}

func TestLabRecoveryAuthorityExpiredOrRevokedApprovalCannotAuthorizeStep(t *testing.T) {
	for _,kind:=range []string{"expired","revoked"} {
		m:=labRecoveryAuthorityTestModel(t);m.armStop(t);at:=m.f.now
		if kind=="expired" {at=at.Add(2*time.Minute)} else {if m.store.revokeRecovery(m.owner,"MODEL_revoker","EXPLICIT_REVOKED",at)!=nil {t.Fatal("MODEL revoke")}}
		before:=bytes.Clone(m.disk.raw)
		if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",at);err==nil {t.Fatal("expired/revoked step")}
		if !bytes.Equal(before,m.disk.raw) {t.Fatal("rejected step overwrote happened history")}
	}
}

func TestLabRecoveryAuthorityRevokeAdminWithoutSessionAndMatchedCurrentApprover(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t);m.approve(t)
	if _,err:=m.a.authorizeRevoke(m.f.headers["executor"],m.store,m.owner,nil,m.f.now);err!=nil {t.Fatal("current scoped Admin cancellation requires old session")}
	if _,err:=m.a.authorizeRevoke(m.f.headers["approver"],m.store,m.owner,m.session,m.f.now);err!=nil {t.Fatal("actual bound approver cancellation")}
	for _,name:=range []string{"viewer","operator","other-approver","outsider"} {
		if _,err:=m.a.authorizeRevoke(m.f.headers[name],m.store,m.owner,m.session,m.f.now);err==nil {t.Fatal("unrelated revoker accepted")}
	}
	if _,err:=m.a.authorizeRevoke(m.f.headers["approver"],m.store,m.owner,nil,m.f.now);err==nil {t.Fatal("nil session inferred approver from JSON")}
}

func TestLabRecoveryAuthorityCancellationDoesNotRequireMissingInitiatorOrUnexpiredLease(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t);m.approve(t)
	m.f.edit(t,"initiator",func(i *authn.Identity){i.Disabled=true})
	late:=m.f.now.Add(2*time.Minute)
	if _,err:=m.a.authorizeRevoke(m.f.headers["approver"],m.store,m.owner,m.session,late);err!=nil {t.Fatal("missing old initiator blocked currently authenticated bound approver cancellation")}
	if _,err:=m.a.authorizeRevoke(m.f.headers["executor"],m.store,m.owner,nil,late);err!=nil {t.Fatal("expired lease blocked current Admin cancellation")}
	if m.store.core.record.core.Current.Active.Phase!="UNKNOWN" {t.Fatal("cancellation observation erased old UNKNOWN")}
}

func TestLabRecoveryAuthorityReadIsCurrentAndIndependentOfWriteSession(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t)
	auditor,digest,err:=authn.GenerateToken(32);if err!=nil {t.Fatal("auditor credential")}
	m.f.headers["auditor"]=[]string{"Bearer "+auditor}
	m.f.config.Identities=append(m.f.config.Identities,authn.Identity{TokenID:"auditor-token",TokenHash:digest,
		Principal:authz.Principal{ID:"sensitive-auditor",TenantID:m.f.scope.TenantID,Roles:[]authz.Role{authz.RoleAuditor},AllowedScopes:[]authz.ResourceScope{m.f.scope}}})
	m.f.write(t)
	for _,name:=range []string{"viewer","operator","approver","initiator","executor","auditor"} {
		if m.a.authorizeRead(m.f.headers[name],m.f.now)!=nil {t.Fatal("valid recovery summary read")}
	}
	if m.a.authorizeRead(m.f.headers["outsider"],m.f.now)==nil||m.a.authorizeRead(nil,m.f.now)==nil {t.Fatal("unscoped summary read")}
	m.f.edit(t,"viewer",func(i *authn.Identity){i.Disabled=true})
	if m.a.authorizeRead(m.f.headers["viewer"],m.f.now)==nil {t.Fatal("stale viewer read")}
}

func TestLabRecoveryAuthoritySessionCopiesForeignAuthoritiesAndStoresCannotBind(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t);m.armStop(t)
	copy:=*m.session
	if _,err:=m.a.authorizeStep(m.f.headers["executor"],&copy,"STOP",m.f.now);err==nil {t.Fatal("wrapper copy minted registered session")}
	other,err:=newLabRecoveryAuthority(m.f.authority,m.f.now);if err!=nil {t.Fatal("other wrapper")};defer other.close()
	if _,err:=other.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err==nil {t.Fatal("cross-authority session")}
	saved:=m.session.core.store;m.session.core.store=&lifecycleRecoveryStore{core:&lifecycleRecoveryStoreCore{}}
	if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err==nil {t.Fatal("cross-store binding")}
	m.session.core.store=saved
	if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err!=nil {t.Fatal("foreign attempt damaged original binding")}
}

func TestLabRecoveryAuthorityInitiatorCopiesAndForgedSessionsCannotRevive(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t)
	h,err:=m.a.captureInitiator(m.f.headers["initiator"],m.f.now);if err!=nil {t.Fatal("initiator")};copy:=*h
	if _,err:=m.a.initiatorReference(&copy);err==nil {t.Fatal("copied wrapper accepted")}
	m.a.discardInitiator(h)
	if _,err:=m.a.initiatorReference(h);err==nil {t.Fatal("discarded initiator revived")}
	forged:=&labRecoverySession{core:&labRecoverySessionCore{authority:m.a.core,store:m.store,storeCore:m.store.core,owner:m.owner}}
	if _,err:=m.a.approve(m.f.headers["approver"],forged,m.f.now);err==nil {t.Fatal("caller fields minted session")}
}

func TestLabRecoveryAuthorityReopenCannotRestoreProcessLocalApproval(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t);m.armStop(t)
	fresh,err:=openLifecycleRecoveryStore(m.disk,m.f.now);if err!=nil {t.Fatal("MODEL reopened store")}
	before:=m.session.core.store;m.session.core.store=fresh
	if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);err==nil {t.Fatal("reopened JSON restored session")}
	m.session.core.store=before
	if m.store.core.verify()==nil {t.Fatal("original live store ignored reopened UNKNOWN commit")}
}

func TestLabRecoveryAuthoritySharedClockPoisonAndBaseCloseAreFinal(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t)
	if m.a.authorizeRead(m.f.headers["viewer"],m.f.now.Add(time.Second))!=nil {t.Fatal("forward trusted time")}
	if _,err:=m.a.captureInitiator(m.f.headers["initiator"],m.f.now);err==nil||!m.f.authority.core.poisoned {t.Fatal("recovery clock rollback did not poison common authority")}
	if m.f.authority.authorizeRead(m.f.headers["viewer"],m.f.now.Add(2*time.Second))==nil {t.Fatal("old base bypassed common poison")}
	f:=labAuthorityTestFixture(t);a,err:=newLabRecoveryAuthority(f.authority,f.now);if err!=nil {t.Fatal("authority")}
	if f.authority.close()!=nil||a.authorizeRead(f.headers["viewer"],f.now)==nil {t.Fatal("closed base revived through wrapper")}
}

func TestLabRecoveryAuthorityCloseOnlyOwnRegistryNotBorrowedManager(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t)
	if m.a.close()!=nil||m.a.close()!=nil {t.Fatal("idempotent wrapper close")}
	if _,err:=m.a.approve(m.f.headers["approver"],m.session,m.f.now);err==nil {t.Fatal("closed recovery registry revived")}
	if m.f.authority.authorizeRead(m.f.headers["viewer"],m.f.now)!=nil {t.Fatal("closing recovery closed borrowed base")}
	if _,_,err:=m.f.manager.AuthenticateAuthorizationValues(m.f.headers["initiator"],m.f.now);err!=nil {t.Fatal("closing recovery closed borrowed manager")}
	if m.store.core.verify()!=nil {t.Fatal("closing recovery closed borrowed disk")}
}

func TestLabRecoveryAuthorityCombinedRegistryCapacityAndDiscardAreBounded(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t);f,a:=m.f,m.a
	var first *labRecoveryInitiator
	for i:=0;i<maxLabRecoveryAuthorityBindings-1;i++ {h,err:=a.captureInitiator(f.headers["initiator"],f.now);if err!=nil {t.Fatal("binding capacity early rejection")};if i==0 {first=h}}
	if len(a.core.sessions)!=1||len(a.core.initiators)!=maxLabRecoveryAuthorityBindings-1 {t.Fatal("combined registry fixture")}
	if _,err:=a.captureInitiator(f.headers["initiator"],f.now);err==nil {t.Fatal("unbounded registry")}
	a.discardInitiator(first)
	if _,err:=a.captureInitiator(f.headers["initiator"],f.now);err!=nil {t.Fatal("discarded slot not released")}
}

func TestLabRecoveryAuthorityConcurrentChecksDoNotWriteOrConsumePhysicalPermit(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t);permit:=m.armStart(t);before:=m.disk.writes
	var wg sync.WaitGroup
	for range 4 {wg.Add(1);go func(){defer wg.Done();if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"START",m.f.now);err!=nil {t.Error("current concurrent authorization check")}}()}
	wg.Wait()
	if m.store.core.permit!=permit.core||m.disk.writes!=before {t.Fatal("policy check executed or consumed physical action")}
}

func TestLabRecoveryAuthorityUnknownStepsAndWrongExecutorRolesCannotSend(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t);m.armStop(t)
	for _,step:=range []string{"","stop","STARTUP","RELOAD","STOP/START"} {
		if _,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,step,m.f.now);err==nil {t.Fatal("unbounded step")}
	}
	for _,role:=range []string{"viewer","operator","approver","outsider"} {
		if _,err:=m.a.authorizeStep(m.f.headers[role],m.session,"STOP",m.f.now);err==nil {t.Fatal("wrong executor role")}
	}
}

func TestLabRecoveryAuthorityOpaqueDebugJSONAndNilInputsNeverRestoreBindings(t *testing.T) {
	m:=labRecoveryAuthorityTestModel(t);m.armStop(t);check,err:=m.a.authorizeStep(m.f.headers["executor"],m.session,"STOP",m.f.now);if err!=nil {t.Fatal("check")}
	h,err:=m.a.captureInitiator(m.f.headers["initiator"],m.f.now);if err!=nil {t.Fatal("initiator")}
	values:=[]any{m.a,*m.a,h,*h,m.session,*m.session,check,&check,labRecoveryAuthority{},labRecoveryInitiator{},labRecoverySession{},labRecoveryCheck{}}
	for _,value:=range values {
		for _,verb:=range []string{"%v","%+v","%#v","%x","%s","%q","%d"} {if fmt.Sprintf(verb,value)!=labRecoveryAuthorityDebug {t.Fatal("private recovery debug traversed binding")}}
		for _,verb:=range []string{"%p","%T"} {
			text:=fmt.Sprintf(verb,value)
			for _,needle:=range []string{"sensitive-initiator",m.f.headers["initiator"][0],m.plan.descriptor().PlanSHA256,m.f.path} {if strings.Contains(text,needle) {t.Fatal("special format leaked private state")}}
		}
		raw,err:=json.Marshal(value);if err!=nil||string(raw)!=string(labRecoveryAuthorityJSON()) {t.Fatal("private recovery JSON")}
	}
	var nilAuthority *labRecoveryAuthority;var nilSession *labRecoverySession;var nilInitiator *labRecoveryInitiator;var nilCheck *labRecoveryCheck
	for _,v:=range []any{nilAuthority,nilSession,nilInitiator,nilCheck} {if fmt.Sprintf("%v",v)!="<nil>" {t.Fatal("typed nil debug")};raw,err:=json.Marshal(v);if err!=nil||string(raw)!="null" {t.Fatal("typed nil JSON")}}
	if nilAuthority.authorizeRead(nil,m.f.now)==nil {t.Fatal("nil authority")}
	if _,err:=m.a.approve(m.f.headers["approver"],nilSession,m.f.now);err==nil {t.Fatal("nil session")}
	for _,v:=range []any{&labRecoveryAuthority{},&labRecoveryInitiator{},&labRecoverySession{},&labRecoveryCheck{}} {if json.Unmarshal([]byte(`{"core":{}}`),v)==nil {t.Fatal("JSON minted binding")}}
	if nilCheck.UnmarshalJSON(nil)==nil||nilSession.UnmarshalJSON(nil)==nil||nilInitiator.UnmarshalJSON(nil)==nil||nilAuthority.UnmarshalJSON(nil)==nil {t.Fatal("nil JSON accepted")}
}
