package mihomodeploy

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
)

const labServiceStatePath = "/tmp/chengwang-mihomo-service-state"
const labRuntimePath = labServiceStatePath + "/runtime"
const labProvisionMarkerPath = labRuntimePath + "/provision.marker"
const labArtifactPath = labRuntimePath + "/artifacts"
const labWALPath = labRuntimePath + "/wal"
const labWriterPath = labServiceStatePath + "/writer.lock"
const labProvisionDebug = "private source-owned laboratory initialization; not authorization"

// The platform implementation is source-owned. This interface is not accepted
// by a public constructor and cannot be supplied through HTTP or JSON.
type labRuntimeDisk interface {
	lifecycleDisk
	provisioning() (lifecycleProvisioning,error)
	artifactDirectory() string
}
type labLifecycleRuntime struct { core *labLifecycleRuntimeCore }
type labLifecycleRuntimeCore struct {
	mu sync.Mutex
	disk labRuntimeDisk
	fresh *labFreshPermitCore
	store *lifecycleStore
	closed,poisoned bool
}
type labFreshPermit struct { core *labFreshPermitCore }
type labFreshPermitCore struct {
	runtime *labLifecycleRuntimeCore
	used bool
}

func (labLifecycleRuntime) String() string { return labProvisionDebug }
func (labLifecycleRuntime) GoString() string { return labProvisionDebug }
func (labLifecycleRuntime) Format(s fmt.State,_ rune) { _,_=io.WriteString(s,labProvisionDebug) }
func (labLifecycleRuntime) MarshalJSON() ([]byte,error) { return []byte(`{"scope":"PRIVATE_LAB_RUNTIME_NOT_AUTHORIZATION"}`),nil }
func (*labLifecycleRuntime) UnmarshalJSON([]byte) error { return errLifecycleUnsafe }
func (labFreshPermit) String() string { return labProvisionDebug }
func (labFreshPermit) GoString() string { return labProvisionDebug }
func (labFreshPermit) Format(s fmt.State,_ rune) { _,_=io.WriteString(s,labProvisionDebug) }
func (labFreshPermit) MarshalJSON() ([]byte,error) { return []byte(`{"scope":"PROCESS_LOCAL_FRESH_DIRECTORY_NOT_AUTHORIZATION"}`),nil }
func (*labFreshPermit) UnmarshalJSON([]byte) error { return errLifecycleUnsafe }

func openLabLifecycleRuntime() (*labLifecycleRuntime,*labFreshPermit,error) {
	d,fresh,err:=openLabRuntimeDisk()
	if err!=nil{return nil,nil,err}
	return ownLabLifecycleRuntime(d,fresh)
}

// Only the platform's actual exclusive mkdir result reaches this private
// helper. Test disks are MODEL evidence, never permission to a real runtime.
func ownLabLifecycleRuntime(d labRuntimeDisk,fresh bool) (*labLifecycleRuntime,*labFreshPermit,error) {
	if d==nil{return nil,nil,errLifecycleUnsafe}
	v:=reflect.ValueOf(d)
	switch v.Kind(){case reflect.Pointer,reflect.Map,reflect.Slice,reflect.Func,reflect.Chan,reflect.Interface:if v.IsNil(){return nil,nil,errLifecycleUnsafe}}
	keep:=false
	defer func(){if !keep{_=d.close()}}()
	binding,err:=d.provisioning()
	if err!=nil || d.verify()!=nil{return nil,nil,errLifecycleUnsafe}
	r:=&labLifecycleRuntime{core:&labLifecycleRuntimeCore{disk:d}}
	if fresh {
		_,exists,err:=d.readControl()
		if err!=nil || exists{return nil,nil,errLifecycleUnsafe}
		p:=&labFreshPermit{core:&labFreshPermitCore{runtime:r.core}}
		r.core.fresh=p.core
		keep=true
		return r,p,nil
	}
	// The ordinary opener may persist ARMED/ACK -> UNKNOWN. Reject an old
	// schema or a foreign marker before giving it any opportunity to write.
	raw,exists,err:=d.readControl()
	if err!=nil || !exists || d.verify()!=nil{return nil,nil,errLifecycleUnsafe}
	before,err:=decodeLifecycleRecord(raw)
	if err!=nil || before.wire.Schema!=lifecycleSchemaV2 || before.wire.V2==nil || before.wire.V2.Provisioning!=binding{return nil,nil,errLifecycleUnsafe}
	s,err:=openLifecycleStore(d)
	if err!=nil{return nil,nil,err}
	if s.record.wire.Schema!=lifecycleSchemaV2 || s.record.wire.V2==nil || s.record.wire.V2.Provisioning!=binding{return nil,nil,errLifecycleUnsafe}
	r.core.store=s
	keep=true
	return r,nil,nil
}

func (r *labLifecycleRuntime) artifactDirectory() (string,error) {
	if r==nil || r.core==nil{return "",errLifecycleUnsafe}
	c:=r.core;c.mu.Lock();defer c.mu.Unlock()
	if c.closed || c.poisoned || c.disk==nil{return "",errLifecycleUnsafe}
	if err:=c.disk.verify();err!=nil{c.poisoned=true;return "",err}
	return c.disk.artifactDirectory(),nil
}
func (r *labLifecycleRuntime) existingStore() (*lifecycleStore,error) {
	if r==nil || r.core==nil{return nil,errLifecycleUnsafe}
	c:=r.core;c.mu.Lock();defer c.mu.Unlock()
	if c.closed || c.poisoned || c.store==nil || c.store.lifecycleStoreCore==nil || c.store.mu==nil{return nil,errLifecycleUnsafe}
	c.store.mu.Lock();defer c.store.mu.Unlock()
	if err:=c.store.verify();err!=nil{return nil,err}
	return c.store,nil
}

func (r *labLifecycleRuntime) bootstrap(p *labFreshPermit,e *labObservedEvidence,now time.Time) (*lifecycleStore,error) {
	if r==nil || r.core==nil{return nil,errLifecycleUnsafe}
	c:=r.core;c.mu.Lock();defer c.mu.Unlock()
	if c.closed || c.poisoned || c.disk==nil || c.store!=nil || p==nil || p.core==nil || c.fresh!=p.core || p.core.runtime!=c || p.core.used{return nil,errLifecycleUnsafe}
	// Any admitted bootstrap invocation consumes the actual mkdir capability.
	// No subsequent read error or definite precommit failure recreates freshness.
	p.core.used=true
	if !lifecycleTime(now) || e==nil{return nil,errLifecycleUnsafe}
	o,err:=e.consumeLifecycle("BOOTSTRAP",now)
	if err!=nil{return nil,errLifecycleUnsafe}
	if err:=c.disk.verify();err!=nil{c.poisoned=true;return nil,err}
	_,exists,err:=c.disk.readControl()
	if err!=nil || exists{c.poisoned=true;return nil,errLifecycleUnsafe}
	provision,err:=c.disk.provisioning();if err!=nil{c.poisoned=true;return nil,err}
	i:=o.StartupIdentity
	if o.Phase!="BOOTSTRAP" || o.OperationID!="" || o.PlanSHA256!="" || o.IntentSHA256!="" || !lifecycleArtifactDescriptorValid(o.Artifact) ||
		!o.Artifact.Config.Admissible || i.ArtifactSHA256!=o.Artifact.Config.SHA256 || i.ControllerPort!=o.Artifact.ControllerPort || i.MixedPort!=o.Artifact.MixedPort ||
		!lifecycleNonzeroHash(o.VerificationSHA256) || !lifecycleTime(o.ObservedAt) || !lifecycleTime(now) || o.ObservedAt.After(now){return nil,errLifecycleUnsafe}
	h:=&lifecycleHead{Schema:lifecycleHeadSchema,DeviceRef:o.DeviceRef,Scope:o.Scope,Generation:1,Artifact:cloneArtifactDescriptor(o.Artifact),KernelSHA256:i.ELFSHA256,
		PID:i.PID,StartTicks:i.StartTicks,NetNSInode:i.NetNSInode,ControllerPort:i.ControllerPort,MixedPort:i.MixedPort,VerificationSHA256:o.VerificationSHA256,VerifiedAt:o.ObservedAt}
	h.HeadSHA256,err=lifecycleHeadHash(*h);if err!=nil{return nil,err}
	w:=&lifecycleWire{Schema:lifecycleSchemaV2,Boundary:lifecycleBoundary,Revision:1,LastTrustedAt:now,Head:h,Tombstones:[]lifecycleTombstone{},
		V2:&lifecycleV2Wire{Provisioning:provision,Completed:[]lifecycleCompletion{},Observations:[]lifecycleObservationRecord{},Terminated:[]lifecycleTerminalArchive{}}}
	w.RecordSHA256,err=lifecycleRecordHash(*w);if err!=nil{return nil,err}
	raw,err:=encodeLifecycleRecord(lifecycleRecord{wire:w});if err!=nil{return nil,err}
	state,err:=c.disk.replaceControl(raw)
	if state==lifecycleUnknown || state==lifecycleCommitted && err!=nil || state!=lifecycleNotCommitted && state!=lifecycleCommitted { c.poisoned=true;return nil,errLifecycleCommitUnknown }
	if err!=nil || state!=lifecycleCommitted {if state==lifecycleCommitted{c.poisoned=true};if err!=nil{return nil,err};return nil,errLifecycleUnsafe}
	actual,exists,err:=c.disk.readControl()
	if err!=nil || !exists || !bytes.Equal(raw,actual) || c.disk.verify()!=nil{c.poisoned=true;return nil,errLifecycleCommitUnknown}
	decoded,err:=decodeLifecycleRecord(actual)
	if err!=nil{c.poisoned=true;return nil,errLifecycleCommitUnknown}
	s:=&lifecycleStore{lifecycleStoreCore:&lifecycleStoreCore{mu:&sync.Mutex{},disk:c.disk,record:decoded,raw:bytes.Clone(actual)}}
	c.store=s
	return s,nil
}

func (r *labLifecycleRuntime) close() error {
	if r==nil || r.core==nil{return errLifecycleUnsafe}
	c:=r.core;c.mu.Lock();defer c.mu.Unlock()
	if c.closed{return nil}
	c.closed=true
	if c.fresh!=nil{c.fresh.used=true}
	if c.store!=nil{return c.store.close()}
	if c.disk!=nil{return c.disk.close()}
	return errLifecycleUnsafe
}
