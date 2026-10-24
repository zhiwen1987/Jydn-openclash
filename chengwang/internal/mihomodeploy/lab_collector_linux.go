//go:build linux

package mihomodeploy

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type labDiagnosticsPlatform struct { file *os.File; stat syscall.Stat_t }
func openLabDiagnosticsPlatform() (*labDiagnosticsPlatform,error) {
	if os.Geteuid()!=10001||os.Getuid()!=10001||os.Getgid()!=10001||os.Getegid()!=10001||!labKernelPlain(labDiagnosticsPath){return nil,errLabDiagnostics}
	fd,e:=syscall.Open(labDiagnosticsPath,syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0);if e!=nil{return nil,errLabDiagnostics}
	f:=os.NewFile(uintptr(fd),"private-lab-diagnostics");p:=&labDiagnosticsPlatform{file:f}
	if syscall.Fstat(fd,&p.stat)!=nil||p.stat.Mode&07777!=0700||p.stat.Uid!=10001||p.stat.Gid!=10001 {f.Close();return nil,errLabDiagnostics}
	names,e:=f.Readdirnames(-1);if e!=nil||len(names)!=0{f.Close();return nil,errLabDiagnostics};return p,nil
}
func (p *labDiagnosticsPlatform) verify() error {
	if p==nil||p.file==nil{return errLabDiagnostics};var path,fd syscall.Stat_t
	if syscall.Lstat(labDiagnosticsPath,&path)!=nil||syscall.Fstat(int(p.file.Fd()),&fd)!=nil||path.Dev!=p.stat.Dev||path.Ino!=p.stat.Ino||fd.Dev!=p.stat.Dev||fd.Ino!=p.stat.Ino||fd.Mode&07777!=0700||fd.Uid!=10001||fd.Gid!=10001||path.Mode&syscall.S_IFMT!=syscall.S_IFDIR{return errLabDiagnostics};return nil
}
func (p *labDiagnosticsPlatform) write(name string,raw []byte,appendOnly bool) error {
	if p.verify()!=nil||(!labDiagnosticName(name)&&name!="service-journal.jsonl"){return errLabDiagnostics}
	fd,e:=syscall.Dup(int(p.file.Fd()));if e!=nil{return errLabDiagnostics};defer func(){_ = syscall.Close(fd)}()
	parts:=strings.Split(name,"/")
	for _,part:=range parts[:len(parts)-1] {
		if e=syscall.Mkdirat(fd,part,0700);e!=nil&&e!=syscall.EEXIST{return errLabDiagnostics}
		next,e:=syscall.Openat(fd,part,syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0);if e!=nil{return errLabDiagnostics};var st syscall.Stat_t
		if syscall.Fstat(next,&st)!=nil||st.Mode&07777!=0700||st.Uid!=10001||st.Gid!=10001{syscall.Close(next);return errLabDiagnostics}
		if syscall.Fsync(fd)!=nil{syscall.Close(next);return errLabDiagnostics};syscall.Close(fd);fd=next
	}
	flags:=syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC
	if appendOnly {flags=syscall.O_WRONLY|syscall.O_CREAT|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC}
	n,e:=syscall.Openat(fd,parts[len(parts)-1],flags,0600);if e!=nil{return errLabDiagnostics};f:=os.NewFile(uintptr(n),"private-lab-output");var st syscall.Stat_t
	if syscall.Fstat(n,&st)!=nil||st.Mode&syscall.S_IFMT!=syscall.S_IFREG||st.Mode&07777!=0600||st.Uid!=10001||st.Gid!=10001||st.Nlink!=1{f.Close();return errLabDiagnostics}
	written,e:=f.Write(raw);syncErr:=f.Sync();closeErr:=f.Close();if e!=nil||written!=len(raw)||syncErr!=nil||closeErr!=nil||syscall.Fsync(fd)!=nil||p.verify()!=nil{return errLabDiagnostics};return nil
}
func (p *labDiagnosticsPlatform) close() error {if p==nil||p.file==nil{return nil};e:=p.file.Close();p.file=nil;return e}

func labServiceEnvelope() error {
	if os.Getuid()!=10001||os.Geteuid()!=10001||os.Getgid()!=10001||os.Getegid()!=10001{return errLabKernelInput}
	raw,e:=os.ReadFile("/proc/self/status");if e!=nil||len(raw)>65536{return errLabKernelInput}
	seen:=map[string]bool{};for _,line:=range strings.Split(string(raw),"\n"){for _,key:=range []string{"CapEff:","CapPrm:","CapInh:","CapAmb:"}{if strings.HasPrefix(line,key){s:=strings.TrimSpace(strings.TrimPrefix(line,key));v,e:=strconv.ParseUint(s,16,64);if e!=nil||v!=0{return errLabKernelInput};seen[key]=true}};if strings.HasPrefix(line,"NoNewPrivs:"){if strings.TrimSpace(strings.TrimPrefix(line,"NoNewPrivs:"))!="1"{return errLabKernelInput};seen["NoNewPrivs:"]=true}}
	if len(seen)!=5{return errLabKernelInput}
	interfaces,e:=net.Interfaces();if e!=nil||len(interfaces)!=1||interfaces[0].Name!="lo"{return errLabKernelInput}
	routes,e:=os.ReadFile("/proc/net/route");if e!=nil{return errLabKernelInput};for _,line:=range strings.Split(string(routes),"\n")[1:]{if strings.TrimSpace(line)!=""{return errLabKernelInput}}
	v6,e:=os.ReadFile("/proc/net/ipv6_route");if e!=nil{return errLabKernelInput};for _,line:=range strings.Split(string(v6),"\n"){f:=strings.Fields(line);if len(f)>0&&(len(f)<10||f[len(f)-1]!="lo"){return errLabKernelInput}}
	if !filepath.IsAbs(labKernelPath){return errLabKernelInput};return nil
}
func labServiceKernelStreams(k *ownedLabKernel) ([]byte,[]byte,error) {
	if k==nil||k.ownedLabKernelCore==nil||k.stdout==nil||k.stderr==nil{return nil,nil,errLabKernelInput};a,_:=k.stdout.snapshot();b,_:=k.stderr.snapshot();return a,b,nil
}
