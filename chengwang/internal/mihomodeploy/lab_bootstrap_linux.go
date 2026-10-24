//go:build linux

package mihomodeploy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type labProvisionMarker struct {
	Schema string `json:"schema"`
	RuntimeID string `json:"runtimeID"`
}
type labProvisionLinuxDisk struct { core *labProvisionLinuxCore }
type labProvisionLinuxCore struct {
	probe *lifecycleLinuxDisk
	base []lifecycleDirectory
	runtime,marker *os.File
	runtimeIdentity,markerIdentity syscall.Stat_t
	runtimeMount,markerMount uint64
	runtimeFilesystem syscall.Statfs_t
	markerRaw []byte
	binding lifecycleProvisioning
	inner lifecycleDisk
	artifactPath string
	closed,poisoned bool
}
func (labProvisionLinuxDisk) String() string { return labProvisionDebug }
func (labProvisionLinuxDisk) GoString() string { return labProvisionDebug }
func (labProvisionLinuxDisk) Format(s fmt.State,_ rune){_,_=io.WriteString(s,labProvisionDebug)}
func (labProvisionLinuxDisk) MarshalJSON()([]byte,error){return []byte(`{"scope":"PRIVATE_LAB_PROVISION_DISK_NOT_AUTHORIZATION"}`),nil}

func openLabRuntimeDisk() (labRuntimeDisk,bool,error) {
	if os.Geteuid()!=10001 || os.Getegid()!=10001{return nil,false,errLifecycleUnsafe}
	return openLabRuntimeDiskAt(labServiceStatePath)
}

// Only package tests may choose another safe directory. The product entrypoint
// above has a literal source path and UID/GID; neither comes from HTTP or env.
func openLabRuntimeDiskAt(basePath string) (labRuntimeDisk,bool,error) {
	if !filepath.IsAbs(basePath) || filepath.Clean(basePath)!=basePath || basePath=="/"{return nil,false,errLifecycleUnsafe}
	probe:=&lifecycleLinuxDisk{lifecycleLinuxDiskCore:&lifecycleLinuxDiskCore{uid:uint32(os.Geteuid()),gid:uint32(os.Getegid())}}
	base,err:=probe.openChain(basePath,true,false)
	if err!=nil{return nil,false,err}
	c:=&labProvisionLinuxCore{probe:probe,base:base,artifactPath:filepath.Join(basePath,"runtime","artifacts")}
	d:=&labProvisionLinuxDisk{core:c}
	keep:=false
	defer func(){if !keep{_=d.close()}}()
	parent:=base[len(base)-1].file
	if err:=labProvisionNames(parent,map[string]bool{"writer.lock":true,"runtime":true},2);err!=nil{return nil,false,err}
	existingRuntime,checkErr:=artifactOpen(parent,"runtime",syscall.O_RDONLY|syscall.O_DIRECTORY,0)
	if checkErr==nil { if existingRuntime.Close()!=nil{return nil,false,errLifecycleUnsafe} } else if errors.Is(checkErr,syscall.ENOENT) {
		// The state lock is first created only after runtime+marker. A leftover
		// lock with no runtime is evidence of loss, never a fresh empty base.
		lock,lockErr:=artifactOpen(parent,"writer.lock",syscall.O_RDONLY,0)
		if lockErr==nil{_=lock.Close();return nil,false,errLifecycleUnsafe}
		if !errors.Is(lockErr,syscall.ENOENT){return nil,false,errLifecycleUnsafe}
	} else { return nil,false,errLifecycleUnsafe }
	fresh:=false
	err=syscall.Mkdirat(int(parent.Fd()),"runtime",0700)
	if err==nil {
		fresh=true
		if parent.Sync()!=nil{return nil,false,errLifecycleUnsafe}
	} else if !errors.Is(err,syscall.EEXIST){return nil,false,errLifecycleUnsafe}
	c.runtime,err=artifactOpen(parent,"runtime",syscall.O_RDONLY|syscall.O_DIRECTORY,0)
	if err!=nil{return nil,false,errLifecycleUnsafe}
	c.runtimeIdentity,err=artifactStat(c.runtime)
	if err!=nil || !probe.directorySafe(c.runtimeIdentity,true,filepath.Join(basePath,"runtime")){return nil,false,errLifecycleUnsafe}
	c.runtimeMount,err=lifecycleMountID(c.runtime);if err!=nil{return nil,false,err}
	c.runtimeFilesystem,err=lifecycleFilesystem(c.runtime)
	if err!=nil || !lifecycleSupported(c.runtimeFilesystem) || c.runtimeMount!=base[len(base)-1].mount{return nil,false,errLifecycleUnsafe}
	if fresh {
		if labProvisionNames(c.runtime,map[string]bool{},0)!=nil{return nil,false,errLifecycleUnsafe}
		var nonce [32]byte
		if _,err:=rand.Read(nonce[:]);err!=nil{return nil,false,errLifecycleUnsafe}
		m:=labProvisionMarker{Schema:"chengwang.mihomo-lab-provision/v1",RuntimeID:hex.EncodeToString(nonce[:])}
		raw,err:=json.Marshal(m);if err!=nil{return nil,false,errLifecycleUnsafe}
		f,err:=artifactOpen(c.runtime,"provision.marker",syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL,0600)
		if err!=nil{return nil,false,errLifecycleUnsafe}
		// Deliberately never unlink this marker, even after a short write/sync
		// failure. The already-created runtime can never become fresh again.
		_,writeErr:=io.Copy(f,bytes.NewReader(raw))
		syncErr:=f.Sync()
		closeErr:=f.Close()
		if writeErr!=nil || syncErr!=nil || closeErr!=nil || c.runtime.Sync()!=nil{return nil,false,errLifecycleUnsafe}
	}
	c.marker,err=artifactOpen(c.runtime,"provision.marker",syscall.O_RDONLY,0)
	if err!=nil{return nil,false,errLifecycleUnsafe}
	c.markerIdentity,err=artifactStat(c.marker)
	if err!=nil || !probe.fileSafe(c.markerIdentity,false) || c.markerIdentity.Size>4096{return nil,false,errLifecycleUnsafe}
	c.markerMount,err=lifecycleMountID(c.marker)
	if err!=nil || c.markerMount!=c.runtimeMount{return nil,false,errLifecycleUnsafe}
	c.markerRaw,err=io.ReadAll(io.NewSectionReader(c.marker,0,4097))
	if err!=nil || int64(len(c.markerRaw))!=c.markerIdentity.Size{return nil,false,errLifecycleUnsafe}
	var marker labProvisionMarker
	if artifactDecode(c.markerRaw,&marker)!=nil || marker.Schema!="chengwang.mihomo-lab-provision/v1" || !lifecycleNonzeroHash(marker.RuntimeID){return nil,false,errLifecycleUnsafe}
	canonical,err:=json.Marshal(marker)
	if err!=nil || !bytes.Equal(canonical,c.markerRaw){return nil,false,errLifecycleUnsafe}
	c.binding=lifecycleProvisioning{Schema:"chengwang.mihomo-lab-provision-binding/v1",RuntimeID:marker.RuntimeID,MarkerSHA256:labConfigHash(c.markerRaw)}
	if !fresh {
		// Never let the old mechanical opener create a missing WAL leaf on an
		// interrupted initialization. Existing runtime requires existing state.
		wal,err:=artifactOpen(c.runtime,"wal",syscall.O_RDONLY|syscall.O_DIRECTORY,0)
		if err!=nil{return nil,false,errLifecycleUnsafe}
		control,openErr:=artifactOpen(wal,"control.json",syscall.O_RDONLY,0)
		closeErr:=wal.Close()
		if openErr!=nil || closeErr!=nil{if control!=nil{_=control.Close()};return nil,false,errLifecycleUnsafe}
		if control.Close()!=nil{return nil,false,errLifecycleUnsafe}
	}
	c.inner,err=openLifecycleDiskAt(filepath.Join(basePath,"runtime","wal"),filepath.Join(basePath,"writer.lock"))
	if err!=nil{return nil,false,err}
	if err:=d.verify();err!=nil{return nil,false,err}
	keep=true
	return d,fresh,nil
}

func labProvisionNames(dir *os.File,allowed map[string]bool,maximum int) error {
	f,err:=artifactOpen(dir,".",syscall.O_RDONLY|syscall.O_DIRECTORY,0);if err!=nil{return errLifecycleUnsafe}
	entries,readErr:=f.ReadDir(maximum+1)
	closeErr:=f.Close()
	if (readErr!=nil && !errors.Is(readErr,io.EOF)) || closeErr!=nil || len(entries)>maximum{return errLifecycleUnsafe}
	for _,e:=range entries{if !allowed[e.Name()]{return errLifecycleUnsafe}}
	return nil
}
func (d *labProvisionLinuxDisk) verify() error {
	if d==nil || d.core==nil{return errLifecycleUnsafe}
	c:=d.core
	if c.closed || c.poisoned{return errLifecyclePoisoned}
	fail:=func()error{c.poisoned=true;return errLifecycleUnsafe}
	if c.inner==nil || c.probe==nil || c.runtime==nil || c.marker==nil || len(c.base)==0 || c.probe.checkChain(c.base)!=nil || c.inner.verify()!=nil{return fail()}
	st,e1:=artifactStat(c.runtime);mount,e2:=lifecycleMountID(c.runtime);fs,e3:=lifecycleFilesystem(c.runtime)
	if e1!=nil || e2!=nil || e3!=nil || !artifactSame(c.runtimeIdentity,st,false) || mount!=c.runtimeMount || !lifecycleSameFilesystem(fs,c.runtimeFilesystem) ||
		c.probe.named(c.base[len(c.base)-1].file,"runtime",st,mount,false)!=nil{return fail()}
	st,e1=artifactStat(c.marker);mount,e2=lifecycleMountID(c.marker)
	if e1!=nil || e2!=nil || !artifactSame(c.markerIdentity,st,true) || mount!=c.markerMount || c.probe.named(c.runtime,"provision.marker",st,mount,true)!=nil{return fail()}
	raw,err:=io.ReadAll(io.NewSectionReader(c.marker,0,4097))
	if err!=nil || !bytes.Equal(raw,c.markerRaw){return fail()}
	after,err:=artifactStat(c.marker)
	if err!=nil || !artifactSame(st,after,true) || c.probe.named(c.runtime,"provision.marker",after,mount,true)!=nil{return fail()}
	if labProvisionNames(c.base[len(c.base)-1].file,map[string]bool{"writer.lock":true,"runtime":true},2)!=nil ||
		labProvisionNames(c.runtime,map[string]bool{"provision.marker":true,"wal":true,"artifacts":true},3)!=nil{return fail()}
	for _,name:=range []string{"wal","artifacts"} {
		f,err:=artifactOpen(c.runtime,name,syscall.O_RDONLY|syscall.O_DIRECTORY,0)
		if errors.Is(err,syscall.ENOENT) && name=="artifacts"{continue}
		if err!=nil{return fail()}
		st,e1:=artifactStat(f);mnt,e2:=lifecycleMountID(f);closeErr:=f.Close()
		if e1!=nil || e2!=nil || closeErr!=nil || !c.probe.directorySafe(st,true,name) || mnt!=c.runtimeMount{return fail()}
	}
	return nil
}
func (d *labProvisionLinuxDisk) provisioning()(lifecycleProvisioning,error){
	if err:=d.verify();err!=nil{return lifecycleProvisioning{},err};return d.core.binding,nil
}
func (d *labProvisionLinuxDisk) artifactDirectory()string {if d==nil || d.core==nil{return ""};return d.core.artifactPath}
func (d *labProvisionLinuxDisk) readControl()([]byte,bool,error){
	if err:=d.verify();err!=nil{return nil,false,err}
	raw,exists,err:=d.core.inner.readControl()
	if err!=nil{return nil,false,err}
	if err:=d.verify();err!=nil{return nil,false,err}
	return raw,exists,nil
}
func (d *labProvisionLinuxDisk) replaceControl(raw []byte)(lifecycleCommitState,error){
	if err:=d.verify();err!=nil{return lifecycleNotCommitted,err}
	state,err:=d.core.inner.replaceControl(raw)
	if state==lifecycleUnknown || state==lifecycleCommitted && err!=nil{d.core.poisoned=true;return lifecycleUnknown,errLifecycleCommitUnknown}
	if err!=nil{return state,err}
	if after:=d.verify();after!=nil{
		if state==lifecycleCommitted{return lifecycleUnknown,errLifecycleCommitUnknown}
		return lifecycleNotCommitted,after
	}
	return state,nil
}
func (d *labProvisionLinuxDisk) close()error{
	if d==nil || d.core==nil{return nil}
	c:=d.core;if c.closed{return nil};c.closed=true
	failed:=false
	if c.inner!=nil && c.inner.close()!=nil{failed=true}
	for _,f:=range []*os.File{c.marker,c.runtime}{if f!=nil && f.Close()!=nil{failed=true}}
	for i:=len(c.base)-1;i>=0;i--{if c.base[i].file.Close()!=nil{failed=true}}
	if failed{return errLifecycleUnsafe};return nil
}
