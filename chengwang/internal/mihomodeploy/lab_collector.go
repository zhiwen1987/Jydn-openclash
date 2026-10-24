package mihomodeploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authz"
)

const labCollectorDebug = "private owned laboratory observation; not authorization"
var errLabCollector = errors.New("owned laboratory observation rejected")

type labObservedEvidence struct { core *labObservedEvidenceCore }
type labObservedLifecycle struct {
	Phase string
	Scope authz.ResourceScope
	DeviceRef string
	Artifact ArtifactDescriptor
	StartupIdentity labKernelIdentity
	OperationID, PlanSHA256, IntentSHA256 string
	VerificationSHA256 string
	ObservedAt time.Time
}
type labObservedEvidenceCore struct {
	owner *labCollectorCore
	sequence uint64
	value labObservedLifecycle
	readback mihomo.LabReadbackReport
	transcriptSHA256 string
	bodySHA256s [8]string
	route labLocalRoute
}
type labCollector struct { core *labCollectorCore }
type labCollectorCore struct {
	mu sync.Mutex
	collectMu sync.Mutex
	store *ArtifactStore
	kernel *ownedLabKernel
	fixture *labLocalFixture
	diagnostics *labServiceDiagnostics
	scope authz.ResourceScope
	sequence uint64
	issued map[*labObservedEvidenceCore]bool
	closed bool
}
func (labObservedEvidence) String() string { return labCollectorDebug }
func (labObservedEvidence) GoString() string { return labCollectorDebug }
func (labObservedEvidence) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, labCollectorDebug) }
func (labObservedEvidence) MarshalJSON() ([]byte,error) { return []byte(`{"scope":"PRIVATE_OBSERVATION_NOT_AUTHORIZATION"}`),nil }
func (e *labObservedEvidence) UnmarshalJSON([]byte) error { if e!=nil { *e=labObservedEvidence{} };return errLabCollector }

func labCollectorLoad(ctx context.Context, store *ArtifactStore, id string) (ArtifactDescriptor,*LabConfigArtifact,artifactSourceWire,error) {
	var z artifactSourceWire
	if store==nil || !lifecycleNonzeroHash(id) { return ArtifactDescriptor{},nil,z,errLabCollector }
	c,err:=store.lock(ctx);if err!=nil{return ArtifactDescriptor{},nil,z,errLabCollector};defer c.mu.Unlock()
	d,a,s,err:=c.load(id);if err!=nil || artifactContext(ctx)!=nil { return ArtifactDescriptor{},nil,z,errLabCollector }
	return d,a,s,nil
}
func newLabCollector(store *ArtifactStore,kernel *ownedLabKernel,fixture *labLocalFixture,diagnostics *labServiceDiagnostics,scope authz.ResourceScope) (*labCollector,error) {
	if store==nil || kernel==nil || fixture==nil || diagnostics==nil || scope.Environment!=LabEnvironment || scope.ObjectType!=LabObjectType || scope.ObjectID=="" {return nil,errLabCollector}
	if _,err:=kernel.identity();err!=nil{return nil,errLabCollector};if kernel.verifyListeners()!=nil{return nil,errLabCollector}
	return &labCollector{core:&labCollectorCore{store:store,kernel:kernel,fixture:fixture,diagnostics:diagnostics,scope:scope,issued:map[*labObservedEvidenceCore]bool{}}},nil
}
func labCollectorPhase(phase string) bool {return phase=="BOOTSTRAP" || phase=="BASELINE" || phase=="ACKNOWLEDGED_COMPLETION" || phase=="UNKNOWN_OBSERVATION"}
func labCollectorRole(source artifactSourceWire) (string,error) {
	if source.DefaultTarget=="service-a" {return "A",nil};if source.DefaultTarget=="service-b" {return "B",nil};return "",errLabCollector
}
func (c *labCollector) collect(ctx context.Context,phase,oldID,newID,operationID,planSHA,intentSHA,stage string) (*labObservedEvidence,error) {
	if c==nil||c.core==nil||artifactContext(ctx)!=nil||!labCollectorPhase(phase){return nil,errLabCollector};p:=c.core
	p.collectMu.Lock();defer p.collectMu.Unlock()
	p.mu.Lock();closed:=p.closed;p.mu.Unlock();if closed{return nil,errLabCollector}
	if phase=="BOOTSTRAP" {if operationID!=""||planSHA!=""||intentSHA!=""{return nil,errLabCollector}} else if phase!="BASELINE" && (!planReference.MatchString(operationID)||!lifecycleNonzeroHash(planSHA)||!lifecycleNonzeroHash(intentSHA)){return nil,errLabCollector}
	oldD,oldA,oldS,err:=labCollectorLoad(ctx,p.store,oldID);if err!=nil{return nil,err}
	newD,newA,newS,err:=labCollectorLoad(ctx,p.store,newID);if err!=nil{return nil,err}
	if oldS.ControllerSecret!=newS.ControllerSecret||oldD.ControllerPort!=28412||oldD.MixedPort!=28411||newD.ControllerPort!=oldD.ControllerPort||newD.MixedPort!=oldD.MixedPort{return nil,errLabCollector}
	oldE,err:=labExpectationForArtifact(oldA);if err!=nil{return nil,errLabCollector};newE,err:=labExpectationForArtifact(newA);if err!=nil{return nil,errLabCollector}
	before,err:=p.kernel.identity();if err!=nil||p.kernel.verifyListeners()!=nil{return nil,errLabCollector}
	reader,err:=mihomo.NewLabReadbackClient(28412,oldS.ControllerSecret,5*time.Second);if err!=nil{return nil,errLabCollector}
	readCtx,cancel:=context.WithTimeout(ctx,5*time.Second)
	samples,evidence,readErr:=reader.ReadStableCaptured(readCtx)
	// Evidence belongs to this actual read; release on every exit, including a
	// failed diagnostic export. No second GET is used to manufacture captures.
	defer evidence.Release()
	descriptor,descErr:=evidence.Descriptor()
	transcript,transErr:=evidence.PrivateTranscript()
	var bodies [8][]byte
	for i:=0;i<8;i++ { if raw,e:=evidence.PrivateBody(uint8(i+1));e==nil {bodies[i]=raw} }
	cancel()
	stageErr:=p.diagnostics.capture(stage,transcript,bodies)
	if readErr!=nil||descErr!=nil||transErr!=nil||stageErr!=nil||descriptor.Outcome!="COMPLETE"||descriptor.DoInvocations!=8||descriptor.CompletedBodies!=8||descriptor.LimitReached{return nil,errLabCollector}
	report,err:=mihomo.CompareLabReadback(samples,oldE,newE);if err!=nil||report.SampleCount!=2||report.RequestsObserved!=8||report.FullPayloadProven||report.Production||report.AuthorizationProven||report.DataplaneProven{return nil,errLabCollector}
	desired:=oldD;source:=oldS
	if phase=="ACKNOWLEDGED_COMPLETION" {if report.Conclusion!=mihomo.LabStableNewProjection{return nil,errLabCollector};desired=newD;source=newS
	} else if phase=="UNKNOWN_OBSERVATION" {if report.Conclusion==mihomo.LabStableNewProjection{desired=newD;source=newS}else if report.Conclusion!=mihomo.LabStableOldProjection{return nil,errLabCollector}
	} else if report.Conclusion!=mihomo.LabStableOldProjection {return nil,errLabCollector}
	role,err:=labCollectorRole(source);if err!=nil{return nil,err}
	routeCtx,routeCancel:=context.WithTimeout(ctx,3*time.Second);route:=p.fixture.route(routeCtx,phase,role);routeCancel()
	if !route.Matched{return nil,errLabCollector}
	after,err:=p.kernel.identity();if err!=nil||before!=after||p.kernel.verifyListeners()!=nil{return nil,errLabCollector}
	if phase=="BOOTSTRAP"&&after.ArtifactSHA256!=desired.Config.SHA256{return nil,errLabCollector}
	// UNKNOWN binds the intended candidate operation, not an assertion that
	// its entire payload is loaded. The actual report/route preserve old/new.
	if phase=="UNKNOWN_OBSERVATION"{desired=newD}
	observedAt:=time.Now().UTC()
	value:=labObservedLifecycle{Phase:phase,Scope:p.scope,DeviceRef:p.scope.ObjectID,Artifact:cloneArtifactDescriptor(desired),StartupIdentity:after,OperationID:operationID,PlanSHA256:planSHA,IntentSHA256:intentSHA,ObservedAt:observedAt}
	var hashes [8]string;for i,b:=range bodies {if len(b)==0{return nil,errLabCollector};hashes[i]=labConfigHash(b)}
	// The digest binds measured startup identity separately from the intended
	// current artifact. It is a source-bound receipt, not a full-payload readback.
	raw,err:=labCollectorVerificationRaw(value,report,labConfigHash(transcript),hashes,route);if err!=nil{return nil,errLabCollector}
	digest,err:=p.diagnostics.verification(stage,raw);if err!=nil{_ = p.diagnostics.event("CAPTURE_UNAVAILABLE",operationID,intentSHA);return nil,errLabCollector}
	value.VerificationSHA256=digest
	p.mu.Lock();defer p.mu.Unlock();if p.closed||p.sequence==^uint64(0)||len(p.issued)>=32{return nil,errLabCollector};p.sequence++
	e:=&labObservedEvidenceCore{owner:p,sequence:p.sequence,value:value,readback:report,transcriptSHA256:labConfigHash(transcript),bodySHA256s:hashes,route:route};p.issued[e]=true
	return &labObservedEvidence{core:e},nil
}
func labCollectorVerificationRaw(value labObservedLifecycle,report mihomo.LabReadbackReport,transcript string,bodies [8]string,route labLocalRoute)([]byte,error){
	if value.VerificationSHA256!=""{return nil,errLabCollector}
	return json.Marshal(struct{Observation labObservedLifecycle;Readback mihomo.LabReadbackReport;Transcript string;Bodies [8]string;Route labLocalRoute}{value,report,transcript,bodies,route})
}
func (e *labObservedEvidence) consumeLifecycle(phase string,now time.Time) (labObservedLifecycle,error) {
	var zero labObservedLifecycle
	if e==nil||e.core==nil||e.core.owner==nil{return zero,errLabCollector}
	x:=e.core;p:=x.owner;p.mu.Lock();defer p.mu.Unlock()
	if p.closed||!p.issued[x]{return zero,errLabCollector};delete(p.issued,x)
	if !labCollectorPhase(phase)||!lifecycleTime(now)||x.sequence==0||x.value.Phase!=phase||!lifecycleTime(x.value.ObservedAt)||x.value.ObservedAt.After(now)||now.Sub(x.value.ObservedAt)>30*time.Second||x.value.Scope!=p.scope{return zero,errLabCollector}
	// No authority/store/artifact lock and no HTTP request occurs here. A may
	// hold the WAL mutex. The original actual process is checked again.
	identity,err:=p.kernel.identity();if err!=nil||identity!=x.value.StartupIdentity||p.kernel.verifyListeners()!=nil{return zero,errLabCollector}
	v:=x.value;v.Artifact=cloneArtifactDescriptor(v.Artifact);return v,nil
}
func (c *labCollector) observation(e *labObservedEvidence) *LabObservationView {
	if c==nil||c.core==nil||e==nil||e.core==nil||e.core.owner!=c.core{return nil}
	x:=e.core;v:=&LabObservationView{Conclusion:x.readback.Conclusion,EvidenceSHA256:x.value.VerificationSHA256,ObservedAt:x.value.ObservedAt,LocalRouteVerified:x.route.Matched}
	if x.readback.ObservedProjectionSHA256!=nil{s:=*x.readback.ObservedProjectionSHA256;v.ObservedProjectionSHA256=&s};return v
}
func (c *labCollector) discard(e *labObservedEvidence) {if c!=nil&&c.core!=nil&&e!=nil&&e.core!=nil{c.core.mu.Lock();delete(c.core.issued,e.core);c.core.mu.Unlock()}}
func (c *labCollector) close() {if c!=nil&&c.core!=nil{c.core.mu.Lock();c.core.closed=true;c.core.issued=nil;c.core.mu.Unlock()}}

// Keep this equality explicit: descriptors have slice fields and cannot be
// compared with ==. No private payload is included in the metadata comparison.
func labCollectorArtifactEqual(a,b ArtifactDescriptor) bool { return reflect.DeepEqual(a,b) }
