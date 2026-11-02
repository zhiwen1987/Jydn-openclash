"""Bounded CI acquisition for the joint-control-plane lane."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, pathlib, stat, subprocess, sys, unittest
HERE=pathlib.Path(__file__).resolve().parent
_spec=importlib.util.spec_from_file_location("joint_ci_contract",HERE/"contract.py");C=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(C)
WORKFLOW=".github/workflows/chengwang-joint-control-plane.yml"
def need(ok):
    if not ok:raise ValueError("joint-ci-rejected")
def run(*args):return subprocess.check_output(list(args),stderr=subprocess.DEVNULL,timeout=30)
def emit(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    with os.fdopen(fd,"wb") as f:f.write(C.canonical(value));f.flush();os.fsync(f.fileno())
def source(repo,commit):
    repo=pathlib.Path(repo).resolve()
    def git(*args):return run("git","-c","safe.directory="+str(repo),"-c","core.fsmonitor=false","-C",str(repo),*args)
    need(git("rev-parse","HEAD").decode().strip()==commit and not git("status","--porcelain","--untracked-files=all"))
    entries=git("ls-tree","-rz","--full-tree",commit).split(b"\0");rows=[]
    for raw in sorted(x for x in entries if x):
        meta_raw,name_raw=raw.split(b"\t",1);mode,kind,oid=meta_raw.decode().split();name=name_raw.decode("utf-8","strict");need(kind=="blob" and mode in ("100644","100755"))
        p=repo/name;meta=p.lstat();need(stat.S_ISREG(meta.st_mode) and meta.st_nlink==1);data=p.read_bytes();need(data==git("cat-file","blob",oid));rows.append({"path":name,"mode":mode,"blobOID":oid,"bytes":len(data),"sha256":C.sha(data)})
    need(rows and len(rows)==len(entries)-1)
    return rows
def source_contract(repo,base_commit):
    repo=pathlib.Path(repo).resolve()
    need(type(base_commit)is str and len(base_commit)==40 and all(x in "0123456789abcdef" for x in base_commit))
    tracked={line.decode("utf-8","strict") for line in run("git","-c","safe.directory="+str(repo),"-c","core.fsmonitor=false","-C",str(repo),"ls-tree","-r","--name-only","HEAD").splitlines()}
    names={name for name in tracked if name.startswith("chengwang/") and not name.startswith(("chengwang/deploy/","chengwang/docs/"))}|set(C.SOURCE_CONTRACT_SCENE)
    rows=[]
    for name in sorted(names):
        p=repo/name;meta=p.lstat();need(stat.S_ISREG(meta.st_mode) and not p.is_symlink() and meta.st_nlink==1);rows.append({"path":name,"sha256":C.sha(p.read_bytes())})
    need(len(rows)==len(names) and rows)
    return {"schema":"chengwang.joint-control-plane-source-contract/v1","baseCommit":base_commit,"inventory":{"scope":"tracked-chengwang-nondeploy-nondocs-plus-joint-scene","excluded":[WORKFLOW,"chengwang/deploy/joint-control-plane/source_contract.json"],"pathCount":len(rows)},"paths":rows}
def build(path,commit):
    path=pathlib.Path(path);meta=path.lstat();raw=path.read_bytes();need(stat.S_ISREG(meta.st_mode) and meta.st_nlink==1 and raw[:4]==b"\x7fELF" and len(raw)>1024)
    return {"schema":"chengwang.joint-control-plane-build/v2","sourceCommit":commit,"goVersion":run("go","env","GOVERSION").decode().strip(),"moduleMode":"vendor","dependencyDownloads":False,"production":False,"authorization":"BLOCKED","server":{"bytes":len(raw),"sha256":C.sha(raw)}}
def isolation(outer):
    need(sys.platform=="linux" and os.getuid()==C.UID and os.getgid()==C.GID)
    status=dict(x.split(":",1) for x in pathlib.Path("/proc/self/status").read_text().splitlines() if ":" in x)
    links=json.loads(run("/usr/sbin/ip","-json","link","show"));addrs=json.loads(run("/usr/sbin/ip","-json","-4","address","show"))
    value={"schema":"chengwang.joint-control-plane-isolation/v2","outerNetNamespace":outer,"netNamespace":os.readlink("/proc/self/ns/net"),"mountNamespace":os.readlink("/proc/self/ns/mnt"),"pidNamespace":os.readlink("/proc/self/ns/pid"),"uid":os.getuid(),"gid":os.getgid(),"capabilities":status["CapEff"].strip(),"noNewPrivileges":int(status["NoNewPrivs"]),"interfaces":sorted(x["ifname"] for x in links),"ipv4Addresses":sorted(i["local"]+"/"+str(i["prefixlen"]) for a in addrs for i in a["addr_info"]),"ipv4DefaultRoutes":json.loads(run("/usr/sbin/ip","-json","-4","route","show","default")),"ipv6DefaultRoutes":json.loads(run("/usr/sbin/ip","-json","-6","route","show","default")),"unprivilegedPortStart":int(pathlib.Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text())}
    need(value["netNamespace"]!=outer and value["interfaces"]==["lo"] and value["ipv4Addresses"]==["127.0.0.1/8","8.8.4.4/32"] and not value["ipv4DefaultRoutes"] and not value["ipv6DefaultRoutes"] and value["unprivilegedPortStart"]==0 and value["capabilities"]=="0000000000000000" and value["noNewPrivileges"]==1);return value
def units():
    sys.path.insert(0,str(HERE));suite=unittest.TestSuite()
    for name in ("test_joint_fixture","test_run_joint_control_plane","test_check_joint_control_plane","test_sanitize_publication"):suite.addTests(unittest.defaultTestLoader.loadTestsFromName(name))
    result=unittest.TextTestRunner(verbosity=2).run(suite);need(result.wasSuccessful() and not result.skipped);return {"schema":"chengwang.joint-control-plane-units/v2","testsRun":result.testsRun,"failures":0,"syntheticOnly":True,"productAcceptanceProven":False}
def main():
    p=argparse.ArgumentParser();p.add_argument("action",choices=("source","contract","build","isolation","units"));p.add_argument("--output",required=True);p.add_argument("--repo",default=".");p.add_argument("--source-commit");p.add_argument("--base-commit");p.add_argument("--server-binary");p.add_argument("--outer-net-namespace");a=p.parse_args();value={"source":lambda:source(a.repo,a.source_commit),"contract":lambda:source_contract(a.repo,a.base_commit),"build":lambda:build(a.server_binary,a.source_commit),"isolation":lambda:isolation(a.outer_net_namespace),"units":units}[a.action]();emit(a.output,value)
if __name__=="__main__":
    try:main()
    except Exception:print("JOINT_CI=REJECTED",file=sys.stderr);raise SystemExit(1) from None
