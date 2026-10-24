package mihomodeploy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/domain"
)

const labServiceDebug="private owned isolated laboratory service"
const labServiceCredentialsPath="/tmp/chengwang-mihomo-service-identities/credentials.json"
const labServiceOperationLimit=8
type LabService struct { core *labServiceCore }
type labServiceCore struct {
	mu sync.Mutex
	closeMu sync.Mutex
	gateMu sync.Mutex
	scope authz.ResourceScope
	authority *labAuthority
	runtime *labLifecycleRuntime
	store *lifecycleStore
	artifacts *ArtifactStore
	input *labKernelInput
	kernel *ownedLabKernel
	fixture *labLocalFixture
	collector *labCollector
	diagnostics *labServiceDiagnostics
	owner *lifecycleOwnerToken
	base,candidate ArtifactDescriptor
	ctx context.Context
	cancel context.CancelFunc
	ready,closing,closed,busy bool
	kernelSettled,fixtureSettled,kernelStreamsSaved,closeUncertain bool
	operationCount int
	sessions map[string]*labSession
	stages map[string]string
	observations map[string]*LabObservationView
	once map[string]string
	gates map[*labServiceGateEvidenceCore]bool
	work sync.WaitGroup
	activeDone chan struct{}
	lastObservedResult *mihomo.ReloadResult
	syntaxObservations []*labSyntaxCleanupObservation
	startedOperations map[string]bool
	kernelCloseObservation *labKernelExit
	fixtureCloseObservations []labLocalFixtureCleanup
}
// Actual syntax Start/Wait/pipe observations are retained even on failure.
// No public DTO can reconstruct this source-owned cleanup handle.
type labSyntaxCleanupObservation struct{core *labSyntaxCleanupCore}
type labSyntaxCleanupCore struct{process *os.Process;observation labKernelStartObservation}
func(labSyntaxCleanupObservation)String()string{return labServiceDebug}
func(labSyntaxCleanupObservation)GoString()string{return labServiceDebug}
func(labSyntaxCleanupObservation)Format(s fmt.State,_ rune){_,_=io.WriteString(s,labServiceDebug)}
func(labSyntaxCleanupObservation)MarshalJSON()([]byte,error){return []byte(`{"scope":"PRIVATE_SYNTAX_CLEANUP_OBSERVATION"}`),nil}
func(o *labSyntaxCleanupObservation)settled()bool{
	if o==nil||o.core==nil{return false};v:=o.core.observation
	if v.Started==nil{return false};if !*v.Started{return v.Attempted&&o.core.process==nil}
	return v.Attempted&&o.core.process!=nil&&v.PID!=nil&&*v.PID==o.core.process.Pid&&v.WaitReturned!=nil&&*v.WaitReturned&&(v.WaitErrorClass=="NONE"||v.WaitErrorClass=="EXIT_STATUS")&&v.GroupAbsent!=nil&&*v.GroupAbsent&&labSyntaxStreamSettled(v.Stdout)&&labSyntaxStreamSettled(v.Stderr)
}
func labSyntaxStreamSettled(v *labKernelStream)bool{return v!=nil&&v.Complete&&!v.Truncated&&v.Bytes>=0&&v.Bytes<=64<<10&&v.TotalBytes==int64(v.Bytes)&&lifecycleNonzeroHash(v.SHA256)}
func(c *labServiceCore)syntaxUnsettled()bool{for _,o:=range c.syntaxObservations{if !o.settled(){return true}};return false}
type labServiceGateEvidence struct {core *labServiceGateEvidenceCore}
type labServiceGateFact struct {
	OperationID string `json:"operationId"`
	PlanSHA256 string `json:"planSHA256"`
	IntentSHA256 string `json:"intentSHA256"`
	Reason string `json:"reason"`
	ObservedAt time.Time `json:"observedAt"`
}
type labServiceGateEvidenceCore struct { owner *labServiceCore; fact labServiceGateFact }
func (LabService) String()string{return labServiceDebug}
func (LabService) GoString()string{return labServiceDebug}
func (LabService) Format(s fmt.State,_ rune){_,_=io.WriteString(s,labServiceDebug)}
func (LabService) MarshalJSON()([]byte,error){return []byte(`{"scope":"OWNED_ISOLATED_LAB_SERVICE_NOT_PERMIT"}`),nil}
func (labServiceGateEvidence) String()string{return labServiceDebug}
func (labServiceGateEvidence) GoString()string{return labServiceDebug}
func (labServiceGateEvidence) Format(s fmt.State,_ rune){_,_=io.WriteString(s,labServiceDebug)}
func (labServiceGateEvidence) MarshalJSON()([]byte,error){return []byte(`{"scope":"PRIVATE_NO_DO_FACT_NOT_ADAPTER_RESULT"}`),nil}
func (e *labServiceGateEvidence) UnmarshalJSON([]byte)error{if e!=nil{*e=labServiceGateEvidence{}};return errLabCollector}
func labServiceError(code LabBackendCode,changed bool)error{return &LabBackendError{Code:code,StateMayHaveChanged:changed}}
func labServiceRandom()(string,error){var b [32]byte;if _,err:=io.ReadFull(rand.Reader,b[:]);err!=nil{return "",errLabCollector};return hex.EncodeToString(b[:]),nil}
func labServiceID()(string,error){var b [16]byte;if _,err:=io.ReadFull(rand.Reader,b[:]);err!=nil{return "",errLabCollector};return "labop_"+hex.EncodeToString(b[:]),nil}
func labServiceValidID(id string)bool{if len(id)!=38||!strings.HasPrefix(id,"labop_"){return false};b,e:=hex.DecodeString(id[6:]);return e==nil&&len(b)==16&&strings.ToLower(id)==id}
func labServiceAuthError(err error)error{switch labAuthorityErrorCode(err){case "authentication_rejected":return labServiceError(LabBackendUnauthenticated,false);case "clock_invalid","authority_closed","authority_unavailable","wal_unavailable":return labServiceError(LabBackendUnavailable,false);default:return labServiceError(LabBackendForbidden,false)}}

// The composition supplies its actual manager opened on the fixed credential
// file. No factory parameter accepts an endpoint, PID, path, secret or draft.
// A nonnil service returned with an error remains the cleanup owner.
func OpenIsolatedLabService(ctx context.Context,manager *authn.SnapshotManager,scope authz.ResourceScope)(*LabService,error){
	if artifactContext(ctx)!=nil||manager==nil||labServiceEnvelope()!=nil{return nil,labServiceError(LabBackendUnavailable,false)}
	authority,err:=newLabAuthority(manager,scope);if err!=nil{return nil,labServiceError(LabBackendUnavailable,false)}
	ownedCtx,cancel:=context.WithCancel(ctx)
	c:=&labServiceCore{scope:scope,authority:authority,ctx:ownedCtx,cancel:cancel,sessions:map[string]*labSession{},stages:map[string]string{},observations:map[string]*LabObservationView{},once:map[string]string{},gates:map[*labServiceGateEvidenceCore]bool{}}
	s:=&LabService{core:c}
	r,permit,err:=openLabLifecycleRuntime();c.runtime=r;if err!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	if permit==nil{c.store,err=r.existingStore();return s,labServiceError(LabBackendUnavailable,true)}
	d,err:=openLabServiceDiagnostics();if err!=nil{return s,labServiceError(LabBackendUnavailable,true)};c.diagnostics=d
	if d.event("STARTUP","","")!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	directory,err:=r.artifactDirectory();if err!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	c.artifacts,err=OpenArtifactStore(directory);if err!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	secret,err:=labServiceRandom();if err!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	markerA,err:=labServiceRandom();if err!=nil{return s,labServiceError(LabBackendUnavailable,true)};markerB,err:=labServiceRandom();if err!=nil||markerA==markerB||markerA==secret||markerB==secret{return s,labServiceError(LabBackendUnavailable,true)}
	secrets,_:=json.Marshal(struct{Schema string `json:"schema"`;Controller string `json:"controller"`;RouteA string `json:"routeA"`;RouteB string `json:"routeB"`}{"chengwang.mihomo-lab-service-private-secrets/v1",secret,markerA,markerB})
	if d.write(".secrets.private.json",secrets)!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	build:=func(target string)(ArtifactDescriptor,error){return c.artifacts.Put(ctx,LabConfigSpec{MixedPort:28411,ControllerPort:28412,ControllerSecret:secret,DefaultTarget:target,HTTPNodes:[]LabHTTPNode{{ID:"service-a",Server:"127.0.0.1",Port:28413},{ID:"service-b",Server:"127.0.0.1",Port:28414}},Draft:domain.PolicyDraft{Name:"owned isolated lifecycle "+target}})}
	c.base,err=build("service-a");if err!=nil{return s,labServiceError(LabBackendUnavailable,true)};c.candidate,err=build("service-b");if err!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	_,base,_,err:=labCollectorLoad(ctx,c.artifacts,c.base.RecordSHA256);if err!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	_,candidate,_,err:=labCollectorLoad(ctx,c.artifacts,c.candidate.RecordSHA256);if err!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	if d.write("local-a.config.private.yaml",base.Bytes())!=nil||d.write("local-b.config.private.yaml",candidate.Bytes())!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	c.input,err=openLabKernelInput();if err!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	c.fixture=newLabLocalFixture(markerA,markerB);if c.fixture.start()!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	c.kernel,err=startOwnedLabKernel(ownedCtx,c.input,base);if err!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	// Startup may precede the controller listener. Only source-owned bounded
	// readiness retries run here; no write or bootstrap is retried.
	readyCtx,readyCancel:=context.WithTimeout(ownedCtx,5*time.Second)
	for c.kernel.verifyListeners()!=nil {select{case <-readyCtx.Done():readyCancel();return s,labServiceError(LabBackendUnavailable,true);case <-time.After(25*time.Millisecond):}}
	readyCancel()
	c.collector,err=newLabCollector(c.artifacts,c.kernel,c.fixture,d,scope);if err!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	obs,err:=c.collector.collect(ownedCtx,"BOOTSTRAP",c.base.RecordSHA256,c.candidate.RecordSHA256,"","","","bootstrap");if err!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	c.store,err=r.bootstrap(permit,obs,time.Now().UTC());if err!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	now:=time.Now().UTC();c.owner,err=c.store.acquireOwner(now,now.Add(10*time.Minute));if err!=nil{return s,labServiceError(LabBackendUnavailable,true)}
	c.ready=true;if d.event("HEAD_READY","","")!=nil{c.ready=false;return s,labServiceError(LabBackendUnavailable,true)}
	return s,nil
}
func (s *LabService) Scope()authz.ResourceScope{if s==nil||s.core==nil{return authz.ResourceScope{}};return s.core.scope}
// DiagnosticReady is a protected-read composition capability only: no owned
// process, approval, or permission to write is inferred from durable metadata.
func (s *LabService) DiagnosticReady()bool{
	if s==nil||s.core==nil{return false};c:=s.core;c.mu.Lock();defer c.mu.Unlock()
	if c.closed||c.closing||c.authority==nil||c.authority.core==nil{return false}
	c.authority.core.mu.Lock();stopped:=c.authority.core.closed||c.authority.core.poisoned;c.authority.core.mu.Unlock();if stopped{return false}
	_,err:=c.wire();return err==nil
}
func (c *labServiceCore) read(headers []string)error{if c.closed||c.closing{return labServiceError(LabBackendUnavailable,false)};if err:=c.authority.authorizeRead(headers,time.Now().UTC());err!=nil{return labServiceAuthError(err)};return nil}
func (c *labServiceCore) wire()(lifecycleRecord,error){
	if c.store==nil||c.store.lifecycleStoreCore==nil||c.store.mu==nil{return lifecycleRecord{},labServiceError(LabBackendUnavailable,false)}
	c.store.mu.Lock();defer c.store.mu.Unlock();if c.store.verify()!=nil{return lifecycleRecord{},labServiceError(LabBackendUnavailable,false)}
	r,err:=c.store.copyRecord();if err!=nil{return lifecycleRecord{},labServiceError(LabBackendUnavailable,false)}
	if r.wire==nil||r.wire.Head==nil||r.wire.Head.Scope!=c.scope||r.wire.Head.DeviceRef!=c.scope.ObjectID{return lifecycleRecord{},labServiceError(LabBackendUnavailable,false)};return r,nil
}
func (c *labServiceCore) ensureOwner(now time.Time)error{
	r,err:=c.wire();if err!=nil{return err}
	if r.wire.Active!=nil{
		if !lifecycleTerminal(r.wire.Active.Phase)||r.wire.V2==nil{return errLifecycleUnsafe}
		archived:=false
		for _,v:=range r.wire.V2.Completed{if v.Active.Plan.OperationID==r.wire.Active.Plan.OperationID&&v.Active.Plan.PlanSHA256==r.wire.Active.Plan.PlanSHA256{archived=true}}
		for _,v:=range r.wire.V2.Terminated{if v.Active.Plan.OperationID==r.wire.Active.Plan.OperationID&&v.Active.Plan.PlanSHA256==r.wire.Active.Plan.PlanSHA256{archived=true}}
		if !archived{return errLifecycleUnsafe}
	}
	if r.wire.Owner==nil||!now.Before(r.wire.Owner.ExpiresAt){
		owner,err:=c.store.acquireOwner(now,now.Add(10*time.Minute));if err!=nil{return err};c.owner=owner;return nil
	}
	return c.store.renewOwner(c.owner,now,now.Add(10*time.Minute))
}
func labServicePhase(phase string)string{if phase=="ACKNOWLEDGED_SUPPORTED_POSTCONDITION"{return "COMPLETED"};if phase=="DISPATCH_ARMED"{return "INTENT_ARMED"};return phase}
func (c *labServiceCore) blocked(w *lifecycleWire)bool{if !c.ready||c.busy||c.syntaxUnsettled()||w==nil||w.Head==nil||c.kernel==nil{return true};if _,err:=c.kernel.identity();err!=nil||c.kernel.verifyListeners()!=nil{return true};return w.Active!=nil&&(w.Active.Phase=="UNKNOWN"||w.Active.Phase=="MANUAL_REQUIRED"||w.Active.Phase=="DISPATCH_ARMED"||w.Active.Phase=="ACKNOWLEDGED"||w.Active.Phase=="RESPONSE_REJECTED")}
func (c *labServiceCore) view(id string,replayed bool)(LabDeploymentView,error){
	r,err:=c.wire();if err!=nil{return LabDeploymentView{},err};w:=r.wire;a:=w.Active
	head:=w.Head;revision:=w.Revision
	if a==nil||a.Plan.OperationID!=id{
		a=nil
		if w.V2!=nil{for i:=range w.V2.Completed{entry:=&w.V2.Completed[i];if entry.Active.Plan.OperationID==id{a=&entry.Active;head=&entry.Head;revision=entry.CommitRevision;break}}}
		if a==nil&&w.V2!=nil{for i:=range w.V2.Terminated{entry:=&w.V2.Terminated[i];if entry.Active.Plan.OperationID==id{a=&entry.Active;head=&entry.Head;revision=entry.CommitRevision;break}}}
		if a==nil{return LabDeploymentView{},labServiceError(LabBackendNotFound,false)}
	}
	v:=LabDeploymentView{Schema:LabDeploymentViewSchema,Boundary:LabBackendBoundary,OperationID:id,Phase:labServicePhase(a.Phase),Revision:revision,PlanSHA256:a.Plan.PlanSHA256,CandidateRecordSHA256:a.Plan.Artifact.RecordSHA256,CandidateConfigSHA256:a.Plan.Artifact.Config.SHA256,PreviousHeadSHA256:a.Plan.Target.HeadSHA256,HeadSHA256:head.HeadSHA256,HeadGeneration:head.Generation,ExpiresAt:a.Plan.ExpiresAt,WriteBlocked:c.blocked(w),Replayed:replayed,HeadAdvanced:a.Phase=="ACKNOWLEDGED_SUPPORTED_POSTCONDITION"}
	if a.Result!=nil {origin:=a.Result.Origin;if origin==""{origin="ADAPTER"};v.Transport=&LabTransportView{Result:a.Result.Reload,RecordedAt:a.Result.ObservedAt,Origin:origin};if a.Result.ServiceGate!=nil{reason:=a.Result.ServiceGate.Reason;v.Transport.GateReason=&reason}}
	if o:=c.observations[id];o!=nil{x:=*o;if o.ObservedProjectionSHA256!=nil{h:=*o.ObservedProjectionSHA256;x.ObservedProjectionSHA256=&h};v.Observation=&x}
	if v.Observation==nil&&a.Readback!=nil&&a.Readback.Conclusion==lifecycleCompletedConclusion{v.Observation=&LabObservationView{Conclusion:mihomo.LabStableNewProjection,EvidenceSHA256:a.Readback.EvidenceSHA256,ObservedAt:a.Readback.ObservedAt,LocalRouteVerified:true}}
	return v,nil
}
func (s *LabService) Inspect(ctx context.Context,headers []string,id string)(LabDeploymentView,error){
	if s==nil||s.core==nil||artifactContext(ctx)!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,false)};c:=s.core;c.mu.Lock();defer c.mu.Unlock();if err:=c.read(headers);err!=nil{return LabDeploymentView{},err};if !labServiceValidID(id){return LabDeploymentView{},labServiceError(LabBackendInvalid,false)};return c.view(id,false)
}
func (s *LabService) Head(ctx context.Context,headers []string)(LabHeadView,error){
	if s==nil||s.core==nil||artifactContext(ctx)!=nil{return LabHeadView{},labServiceError(LabBackendUnavailable,false)};c:=s.core;c.mu.Lock();defer c.mu.Unlock();if err:=c.read(headers);err!=nil{return LabHeadView{},err};r,err:=c.wire();if err!=nil||r.wire.Head==nil{return LabHeadView{},labServiceError(LabBackendUnavailable,false)};w:=r.wire;h:=w.Head
	v:=LabHeadView{Schema:LabHeadViewSchema,Boundary:LabBackendBoundary,Revision:w.Revision,Generation:h.Generation,HeadSHA256:h.HeadSHA256,ArtifactRecordSHA256:h.Artifact.RecordSHA256,ConfigSHA256:h.Artifact.Config.SHA256,VerificationSHA256:h.VerificationSHA256,VerifiedAt:h.VerifiedAt,WriteBlocked:c.blocked(w)};if h.PreviousHeadSHA256!=nil{x:=*h.PreviousHeadSHA256;v.PreviousHeadSHA256=&x};if w.Active!=nil{x:=w.Active.Plan.OperationID;v.ActiveOperationID=&x};return v,nil
}
func (s *LabService) Candidates(ctx context.Context,headers []string)(LabCandidateListView,error){
	if s==nil||s.core==nil||artifactContext(ctx)!=nil{return LabCandidateListView{},labServiceError(LabBackendUnavailable,false)};c:=s.core;c.mu.Lock();defer c.mu.Unlock();if err:=c.read(headers);err!=nil{return LabCandidateListView{},err};r,err:=c.wire();if err!=nil{return LabCandidateListView{},err};blocked:=c.blocked(r.wire)
	if c.base.RecordSHA256==""||c.candidate.RecordSHA256==""{return LabCandidateListView{},labServiceError(LabBackendUnavailable,false)}
	v:=LabCandidateListView{Schema:LabCandidateListViewSchema,Boundary:LabBackendBoundary,Candidates:make([]LabCandidateView,0,2),WriteBlocked:blocked}
	for i,d:=range []ArtifactDescriptor{c.base,c.candidate}{name:="local-a";if i==1{name="local-b"};v.Candidates=append(v.Candidates,LabCandidateView{Name:name,RecordSHA256:d.RecordSHA256,ConfigSHA256:d.Config.SHA256,SourceSpecSHA256:d.SourceSpecSHA256,IsCurrent:!blocked&&r.wire.Head.Artifact.RecordSHA256==d.RecordSHA256})};return v,nil
}
func (s *LabService) Create(ctx context.Context,headers []string,request LabCreateRequest)(LabDeploymentView,error){
	if s==nil||s.core==nil||artifactContext(ctx)!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,false)};c:=s.core;c.mu.Lock();defer c.mu.Unlock()
	if err:=c.read(headers);err!=nil{return LabDeploymentView{},err};if !lifecycleNonzeroHash(request.CandidateRecordSHA256)||request.TTLSeconds<1||request.TTLSeconds>300{return LabDeploymentView{},labServiceError(LabBackendInvalid,false)}
	if !c.ready||c.busy||c.operationCount>=labServiceOperationLimit{return LabDeploymentView{},labServiceError(LabBackendUnavailable,false)}
	init,err:=c.authority.authenticateInitiator(headers,time.Now().UTC());if err!=nil{return LabDeploymentView{},labServiceAuthError(err)};defer c.authority.discardInitiator(init)
	r,err:=c.wire();if err!=nil{return LabDeploymentView{},err};w:=r.wire
	if c.blocked(w)||w.Active!=nil&&!lifecycleTerminal(w.Active.Phase){return LabDeploymentView{},labServiceError(LabBackendConflict,false)}
	if w.Head.Generation>=^uint64(0)-1{return LabDeploymentView{},labServiceError(LabBackendUnavailable,false)}
	d:=c.candidate;if request.CandidateRecordSHA256==c.base.RecordSHA256{d=c.base}else if request.CandidateRecordSHA256!=c.candidate.RecordSHA256{return LabDeploymentView{},labServiceError(LabBackendInvalid,false)}
	if d.Config.SHA256==w.Head.Artifact.Config.SHA256{return LabDeploymentView{},labServiceError(LabBackendConflict,false)}
	id,err:=labServiceID();if err!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)};c.operationCount++;stage:=fmt.Sprintf("op-%02d",c.operationCount)
	obs,err:=c.collector.collect(ctx,"BASELINE",w.Head.Artifact.RecordSHA256,d.RecordSHA256,id,"","",stage+"/create");if err!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)};c.collector.discard(obs)
	now:=time.Now().UTC();if c.ensureOwner(now)!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)}
	backup,err:=c.artifacts.CreateBackup(ctx,id,lifecycleHeadTarget(*w.Head),w.Head.Artifact.RecordSHA256);if err!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)}
	actor,err:=c.authority.initiatorReference(init);if err!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)}
	now=time.Now().UTC();plan,err:=NewPlan(PlanSpec{OperationID:id,DeclaredInitiatorRef:actor,Target:lifecycleHeadTarget(*w.Head),Artifact:d,Backup:backup,ExpiresAt:now.Add(time.Duration(request.TTLSeconds)*time.Second)},now);if err!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)}
	if c.store.recordPlan(c.owner,plan,now)!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)}
	session,err:=c.authority.bindPlan(init,c.store,c.owner,time.Now().UTC());if err!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)}
	c.sessions[id]=session;c.stages[id]=stage;if c.diagnostics.event("PLANNED",id,"")!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)};return c.view(id,false)
}
func (s *LabService) Approve(ctx context.Context,headers []string,id string,request LabApprovalRequest)(LabDeploymentView,error){
	if s==nil||s.core==nil||artifactContext(ctx)!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,false)};c:=s.core;c.mu.Lock();defer c.mu.Unlock();if err:=c.read(headers);err!=nil{return LabDeploymentView{},err}
	if !labServiceValidID(id)||!lifecycleNonzeroHash(request.PlanSHA256)||request.Revision==0{return LabDeploymentView{},labServiceError(LabBackendInvalid,false)}
	v,err:=c.view(id,false);if err!=nil{return LabDeploymentView{},err};if c.busy||v.Revision!=request.Revision||v.PlanSHA256!=request.PlanSHA256{return LabDeploymentView{},labServiceError(LabBackendConflict,false)}
	material,err:=c.authority.approve(headers,c.sessions[id],time.Now().UTC());if err!=nil{return LabDeploymentView{},labServiceAuthError(err)}
	if c.store.recordApproval(c.owner,material,time.Now().UTC())!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)};if c.diagnostics.event("APPROVED",id,"")!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)};return c.view(id,false)
}
func (s *LabService) Execute(ctx context.Context,headers []string,id string,request LabExecuteRequest)(LabDeploymentView,error){
	if s==nil||s.core==nil||artifactContext(ctx)!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,false)};c:=s.core;c.mu.Lock()
	if err:=c.read(headers);err!=nil{c.mu.Unlock();return LabDeploymentView{},err}
	if !labServiceValidID(id)||!lifecycleNonzeroHash(request.PlanSHA256)||request.Revision==0{c.mu.Unlock();return LabDeploymentView{},labServiceError(LabBackendInvalid,false)}
	v,err:=c.view(id,false);if err!=nil{changed:=c.lastObservedResult!=nil;c.mu.Unlock();return LabDeploymentView{},labServiceError(LabBackendUnavailable,changed)}
	if v.PlanSHA256!=request.PlanSHA256{c.mu.Unlock();return LabDeploymentView{},labServiceError(LabBackendConflict,false)}
	if v.Phase=="COMPLETED"||v.Phase=="UNKNOWN"||v.Transport!=nil{v.Replayed=true;c.mu.Unlock();return v,nil}
	if !c.ready||c.busy||v.Revision!=request.Revision{c.mu.Unlock();return LabDeploymentView{},labServiceError(LabBackendConflict,false)}
	if c.startedOperations[id]{c.mu.Unlock();return LabDeploymentView{},labServiceError(LabBackendConflict,false)}
	if err:=c.authority.authorizeExecutionStart(headers,c.sessions[id],time.Now().UTC());err!=nil{c.mu.Unlock();return LabDeploymentView{},labServiceAuthError(err)}
	if c.startedOperations==nil{c.startedOperations=map[string]bool{}};c.startedOperations[id]=true
	c.busy=true;c.work.Add(1);done:=make(chan struct{});c.activeDone=done;copied:=append([]string(nil),headers...)
	go func(){defer close(done);defer c.work.Done();session,cancel:=context.WithTimeout(c.ctx,30*time.Second);defer cancel();c.execute(session,copied,id);c.mu.Lock();c.busy=false;c.mu.Unlock()}()
	c.mu.Unlock()
	select{case <-done:c.mu.Lock();defer c.mu.Unlock();return c.completedView(headers,id);case <-ctx.Done():return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)}
}
// Called with service.mu after an accepted background job settled. Any failure
// here is post-start uncertainty, never a read-only 'nothing changed' claim.
func(c *labServiceCore)completedView(headers []string,id string)(LabDeploymentView,error){
	if c.read(headers)!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)}
	v,e:=c.view(id,false);if e!=nil||v.Phase=="APPROVED"||v.Phase=="PREPARED"{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)};return v,nil
}
func (c *labServiceCore) execute(ctx context.Context,headers []string,id string){
	c.mu.Lock();r,err:=c.wire();if err!=nil{c.mu.Unlock();return};a:=r.wire.Active;if a==nil||a.Plan.OperationID!=id{c.mu.Unlock();return};plan,err:=lifecyclePlan(a.Plan);stage:=c.stages[id];c.mu.Unlock();if err!=nil{return}
	prepared,err:=c.artifacts.PrepareReload(ctx,plan,time.Now().UTC());if err!=nil{return}
	_,candidate,source,err:=labCollectorLoad(ctx,c.artifacts,a.Plan.Artifact.RecordSHA256);if err!=nil{return}
	syntaxObservation,syntaxErr:=labServiceSyntax(ctx,c.input,candidate,c.diagnostics,stage)
	c.mu.Lock();if syntaxObservation!=nil{c.syntaxObservations=append(c.syntaxObservations,syntaxObservation);if !syntaxObservation.settled(){c.ready=false}};c.mu.Unlock()
	if syntaxErr!=nil{return}
	before,err:=c.collector.collect(ctx,"BASELINE",a.Plan.Backup.Artifact.RecordSHA256,a.Plan.Artifact.RecordSHA256,id,a.Plan.PlanSHA256,"",stage+"/pre-dispatch");if err!=nil{return};c.collector.discard(before)
	writer,err:=mihomo.NewWriteClient("http://127.0.0.1:28412",source.ControllerSecret,3*time.Second);if err!=nil{return}
	c.mu.Lock()
	if c.closing||c.closed{c.mu.Unlock();return}
	if c.store.recordPrepared(c.owner,prepared,time.Now().UTC())!=nil{c.mu.Unlock();return}
	_ = c.diagnostics.event("PREPARED",id,"")
	if _,err=c.authority.authorizeDispatch(headers,c.sessions[id],time.Now().UTC());err!=nil{c.mu.Unlock();return}
	if c.store.recordIntent(c.owner,a.Plan.Target.HeadSHA256,time.Now().UTC())!=nil{c.mu.Unlock();return}
	armed,err:=c.wire();if err!=nil||armed.wire.Active==nil||armed.wire.Active.Intent==nil{c.mu.Unlock();return};intent:=armed.wire.Active.Intent.IntentSHA256
	c.once[intent]="ARMED";_ = c.diagnostics.event("DISPATCH_ARMED",id,intent)
	reason:=""
	if ctx.Err()!=nil||c.closing{reason="SERVICE_CONTEXT_CANCELLED"}else if _,e:=c.authority.authorizeDispatch(headers,c.sessions[id],time.Now().UTC());e!=nil{reason="FINAL_AUTHORIZATION_REJECTED"}else if actual,e:=c.kernel.identity();e!=nil||actual.PID!=a.Plan.Target.PID||actual.StartTicks!=a.Plan.Target.StartTicks||actual.NetNSInode!=a.Plan.Target.NetNSInode||actual.ELFSHA256!=a.Plan.Target.KernelSHA256||c.kernel.verifyListeners()!=nil{reason="OWNED_IDENTITY_REJECTED"}
	if reason!=""{
		gate:=c.mintServiceGate(armed.wire.Active,reason,time.Now().UTC())
		if gate!=nil&&c.store.recordServiceGate(c.owner,intent,gate,time.Now().UTC())==nil{_ = c.diagnostics.event("SERVICE_GATE_RECORDED",id,intent)}
		c.mu.Unlock();return
	}
	// The only service Reload call is below. Consuming once before invocation
	// is irreversible; no timeout, cancellation, retry or new header resets it.
	if c.once[intent]!="ARMED"{c.mu.Unlock();return};c.once[intent]="RELOAD_CALL_CLAIMED";_ = c.diagnostics.event("RELOAD_CALL_INTENT",id,intent);c.mu.Unlock()
	result,_:=writer.Reload(ctx,prepared.CandidateBytes())
	c.mu.Lock();actualResult:=result;c.lastObservedResult=&actualResult
	// Record the actual adapter outcome without rechecking approval/lease
	// freshness. A concurrently revoked principal cannot erase this fact.
	recordErr:=c.store.recordResult(c.owner,intent,result,time.Now().UTC())
	_ = c.diagnostics.adapterReturned(id,intent,result,recordErr==nil)
	if recordErr==nil{_ = c.diagnostics.event("RESULT_RECORDED",id,intent)}
	c.mu.Unlock();if recordErr!=nil{return}
	phase:="UNKNOWN_OBSERVATION";if result.State==mihomo.ReloadAcknowledged{phase="ACKNOWLEDGED_COMPLETION"}else if result.State!=mihomo.ReloadUnknown{return}
	// A bounded independent completion context preserves facts after an HTTP
	// disconnect; the service lifetime/30s execution budget still applies.
	obs,err:=c.collector.collect(ctx,phase,a.Plan.Backup.Artifact.RecordSHA256,a.Plan.Artifact.RecordSHA256,id,a.Plan.PlanSHA256,intent,stage+"/post-dispatch");if err!=nil{return}
	c.mu.Lock();defer c.mu.Unlock();c.observations[id]=c.collector.observation(obs)
	if phase=="ACKNOWLEDGED_COMPLETION"{if c.store.recordAcknowledgedCompletion(c.owner,obs,time.Now().UTC())==nil{_ = c.diagnostics.event("COMPLETED",id,intent)}}else{if c.store.recordUnknownObservation(c.owner,obs,time.Now().UTC())==nil{_ = c.diagnostics.event("OBSERVATION_RECORDED",id,intent)}}
}
func (c *labServiceCore) mintServiceGate(a *lifecycleActive,reason string,now time.Time)*labServiceGateEvidence{
	if a==nil||a.Intent==nil||a.Phase!="DISPATCH_ARMED"||a.Attempt!=1||a.Result!=nil||c.once[a.Intent.IntentSHA256]!="ARMED"||(reason!="FINAL_AUTHORIZATION_REJECTED"&&reason!="OWNED_IDENTITY_REJECTED"&&reason!="SERVICE_CONTEXT_CANCELLED"){return nil}
	c.once[a.Intent.IntentSHA256]="BLOCKED";e:=&labServiceGateEvidenceCore{owner:c,fact:labServiceGateFact{OperationID:a.Plan.OperationID,PlanSHA256:a.Plan.PlanSHA256,IntentSHA256:a.Intent.IntentSHA256,Reason:reason,ObservedAt:now}};c.gateMu.Lock();c.gates[e]=true;c.gateMu.Unlock();return &labServiceGateEvidence{core:e}
}
func (e *labServiceGateEvidence) consumeServiceGate(intent string,now time.Time)(labServiceGateFact,error){
	if e==nil||e.core==nil||e.core.owner==nil{return labServiceGateFact{},errLabCollector};x:=e.core;c:=x.owner
	// gateMu never acquires authority/store/service locks. The immutable
	// issued fact was minted only after the actual once state became BLOCKED.
	c.gateMu.Lock();defer c.gateMu.Unlock()
	if !c.gates[x]{return labServiceGateFact{},errLabCollector};delete(c.gates,x)
	if x.fact.IntentSHA256!=intent||!lifecycleTime(now)||x.fact.ObservedAt.After(now){return labServiceGateFact{},errLabCollector};return x.fact,nil
}
func (s *LabService) Revoke(ctx context.Context,headers []string,id string,request LabRevokeRequest)(LabDeploymentView,error){
	if s==nil||s.core==nil||artifactContext(ctx)!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,false)};c:=s.core;c.mu.Lock();defer c.mu.Unlock();if err:=c.read(headers);err!=nil{return LabDeploymentView{},err}
	if !labServiceValidID(id)||!lifecycleNonzeroHash(request.PlanSHA256)||request.Revision==0||(request.Reason!="OPERATOR_REQUESTED"&&request.Reason!="SAFETY_STOP"){return LabDeploymentView{},labServiceError(LabBackendInvalid,false)}
	v,err:=c.view(id,false);if err!=nil{return LabDeploymentView{},err};if v.Revision!=request.Revision||v.PlanSHA256!=request.PlanSHA256{return LabDeploymentView{},labServiceError(LabBackendConflict,false)}
	check,err:=c.authority.authorizeRevoke(headers,c.store,c.owner,c.sessions[id],time.Now().UTC());if err!=nil{return LabDeploymentView{},labServiceAuthError(err)}
	if check.core==nil||c.store.recordRevocation(c.owner,"EXPLICIT_REVOKED",check.core.actorRef,time.Now().UTC())!=nil{return LabDeploymentView{},labServiceError(LabBackendUnavailable,true)};_ = c.diagnostics.event("REVOKED",id,"");return c.view(id,false)
}
func (s *LabService) Close(ctx context.Context)error{
	if s==nil||s.core==nil{return nil};if artifactContext(ctx)!=nil{return labServiceError(LabBackendUnavailable,true)};c:=s.core;c.closeMu.Lock();defer c.closeMu.Unlock();c.mu.Lock();if c.closed{c.mu.Unlock();return nil};if c.closeUncertain{c.mu.Unlock();return labServiceError(LabBackendUnavailable,true)};c.closing=true;c.ready=false;if c.cancel!=nil{c.cancel()};done:=c.activeDone;c.mu.Unlock()
	if done!=nil{select{case <-done:case <-ctx.Done():return labServiceError(LabBackendUnavailable,true)}}
	cleanup,cancel:=context.WithTimeout(ctx,10*time.Second);defer cancel()
	if !c.kernelSettled {
		if c.kernel!=nil{observation,err:=c.kernel.stop(cleanup);c.mu.Lock();c.kernelCloseObservation=&observation;c.mu.Unlock();if err!=nil{return labServiceError(LabBackendUnavailable,true)}}
		c.kernelSettled=true
	}
	// A reaped main kernel does not prove an earlier syntax process/group and
	// its streams were settled. Preserve its actual observation/owned handle
	// and all diagnostics/runtime resources; no numeric group kill is used.
	c.mu.Lock();syntaxUnknown:=c.syntaxUnsettled();c.mu.Unlock();if syntaxUnknown{return labServiceError(LabBackendUnavailable,true)}
	// An uncertain stop retains the actual process/diagnostics/runtime above.
	// A later Close may reobserve the original Wait; it cannot return nil merely
	// because an earlier cleanup was attempted.
	if !c.kernelStreamsSaved&&c.kernel!=nil&&c.diagnostics!=nil{
		stdout,stderr,e:=labServiceKernelStreams(c.kernel)
		if e!=nil||c.diagnostics.write("kernel.stdout",stdout)!=nil||c.diagnostics.write("kernel.stderr",stderr)!=nil{return c.markCloseUncertain()};c.kernelStreamsSaved=true
	}
	if !c.fixtureSettled{if c.fixture!=nil{observations:=c.fixture.stop();c.mu.Lock();c.fixtureCloseObservations=observations;c.mu.Unlock();for _,v:=range observations{if !v.ShutdownReturned||!v.ServeReturned||v.ErrorClass!="NONE"{return c.markCloseUncertain()}}};c.fixtureSettled=true}
	if c.collector!=nil{c.collector.close()};if c.authority!=nil{if c.authority.close()!=nil{return c.markCloseUncertain()}}
	if c.artifacts!=nil{if c.artifacts.Close()!=nil{return c.markCloseUncertain()}}
	if c.runtime!=nil{if c.runtime.close()!=nil{return c.markCloseUncertain()}}
	if c.diagnostics!=nil{if c.diagnostics.cleanupObserved(c.kernelCloseObservation,c.fixtureCloseObservations)!=nil||c.diagnostics.event("CLOSED","","")!=nil||c.diagnostics.close()!=nil{return c.markCloseUncertain()}}
	c.mu.Lock();c.closed=true;c.mu.Unlock();return nil
}
func(c *labServiceCore)markCloseUncertain()error{c.mu.Lock();c.closeUncertain=true;c.ready=false;c.mu.Unlock();return labServiceError(LabBackendUnavailable,true)}

var _ LabBackend = (*LabService)(nil)
