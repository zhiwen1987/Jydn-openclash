"""Bounded CI acquisition for the joint-control-plane lane."""
from __future__ import annotations
import argparse, ast, errno, hashlib, importlib.util, json, os, pathlib, re, selectors, stat, subprocess, sys, threading, time, types, unittest
HERE=pathlib.Path(__file__).resolve().parent
_spec=importlib.util.spec_from_file_location("joint_ci_contract",HERE/"contract.py");C=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(C)
WORKFLOW=".github/workflows/chengwang-joint-control-plane.yml"
WORKFLOW_NORMALIZED_SHA256="f7698ec86a19e46d17dd0176ab6ebbe46c33ae81d4de2ed41a20ee9b29ef2830"
MODEL_TEST_SOURCES=("test_joint_fixture.py","test_run_joint_control_plane.py","test_check_joint_control_plane.py","test_sanitize_publication.py","test_uid_probe_diagnostic.py","test_check_uid_probe_diagnostic.py")
MODEL_OUTCOMES=("PASS","FAIL","ERROR","SKIP","UNKNOWN")
MODEL_DIAGNOSTIC_SCHEMA="chengwang.joint-control-plane-model-outcomes/v1"
MODEL_DIAGNOSTIC_MAXIMUM=16384
BOOTSTRAP_STEP_SHA256="390435e14649a0b656b81bf88ba8ba1a349fac7a2e8374a29c5ff870948b9438"
SCENE_STEP=(
    "- name: Real B0 J1 R2 same-binary scene",
    "  if: ${{ steps.bootstrap_progress.outcome == 'success' }}",
    "  env:",
    "    BOOTSTRAP_STEP_OUTCOME: ${{ steps.bootstrap_progress.outcome }}",
    "  run: |",
    "    set -euo pipefail",
    "    root=\"$RUNNER_TEMP/joint-control-plane\"; outer_net=\"$(readlink /proc/self/ns/net)\"; progress=\"$root/evidence/staging/failure-localization.private\"; bootstrap=\"$root/evidence/staging/bootstrap-localization.private/status.json\"",
    "    test \"$BOOTSTRAP_STEP_OUTCOME\" = success",
    "    timeout --signal=TERM --kill-after=15s 600s sudo --non-interactive unshare --mount --net --pid --fork --kill-child=SIGKILL --mount-proc /usr/bin/bash \"$GITHUB_WORKSPACE/chengwang/deploy/joint-control-plane/ci_namespace.sh\" \"$GITHUB_WORKSPACE\" \"$root\" \"$outer_net\" product \"$GITHUB_SHA\" /mnt/joint-control-plane/evidence/staging/bootstrap-localization.private/status.json bootstrap_progress \"$BOOTSTRAP_STEP_OUTCOME\" \"$GITHUB_SHA\"",
)
FAILURE_STEP=(
    "- name: Publish only bounded failure classification",
    "  if: failure()",
    "  env:",
    "    BOOTSTRAP_STEP_OUTCOME: ${{ steps.bootstrap_progress.outcome }}",
    "  run: |",
    "    root=\"$RUNNER_TEMP/joint-control-plane\"",
    "    sudo --non-interactive python3 -I -B chengwang/deploy/joint-control-plane/sanitize_publication.py failure --input \"$root/evidence/staging\" --progress-root \"$root/evidence/staging/failure-localization.private\" --bootstrap-record \"$root/evidence/staging/bootstrap-localization.private/status.json\" --source-commit \"$GITHUB_SHA\" --bootstrap-step-id bootstrap_progress --bootstrap-step-outcome \"$BOOTSTRAP_STEP_OUTCOME\" --bootstrap-step-source \"$GITHUB_SHA\" --code SCENE_FAILED --output \"$root/evidence/public/failure.json\"",
    "    sudo --non-interactive chown -R --no-dereference \"$(id -u):$(id -g)\" \"$root/evidence/public\"",
)
CPU_STEP=(
    "- name: CPU contracts and Go suite",
    "  id: cpu",
    "  env: {GOFLAGS: -mod=vendor, CGO_ENABLED: '0'}",
    "  run: |",
    "    set -uo pipefail",
    "    private=\"$RUNNER_TEMP/joint-control-plane-cpu-private\"; stage=\"$RUNNER_TEMP/joint-control-plane-cpu-stage\"; public=\"$RUNNER_TEMP/joint-control-plane-cpu-public\"; model_public=\"$RUNNER_TEMP/joint-control-plane-model-outcome-public\"",
    "    if test -e \"$private\" || test -L \"$private\" || test -e \"$stage\" || test -L \"$stage\" || test -e \"$public\" || test -L \"$public\" || test -e \"$model_public\" || test -L \"$model_public\"; then",
    "      printf '%s\\n' 'CPU_PUBLICATION=REJECTED_PREEXISTING_PATH' >&2",
    "      exit 1",
    "    fi",
    "    if ! install -d -m 0700 \"$private\" \"$stage\" \"$model_public\"; then",
    "      printf '%s\\n' 'CPU_PUBLICATION=REJECTED_DIRECTORY_CREATION' >&2",
    "      exit 1",
    "    fi",
    "    if python3 -I -B chengwang/deploy/joint-control-plane/ci_joint_control_plane.py units --output \"$private/units.json\" --model-diagnostic \"$private/model-outcome.json\" --source-commit \"$GITHUB_SHA\" >\"$private/units.log\" 2>&1; then",
    "      unit_code=0",
    "    else",
    "      unit_code=$?",
    "    fi",
    "    if (cd chengwang && go test -count=1 -timeout=300s ./...) >\"$private/go.log\" 2>&1; then",
    "      go_code=0",
    "    else",
    "      go_code=$?",
    "    fi",
    "    if ! printf '%s\\n' \"$go_code\" >\"$private/go-exit.txt\"; then",
    "      printf '%s\\n' 'CPU_PUBLICATION=REJECTED_STATUS_WRITE' >&2",
    "      exit 1",
    "    fi",
    "    if python3 -I -B chengwang/deploy/joint-control-plane/ci_joint_control_plane.py model-diagnostic --input \"$private/model-outcome.json\" --source-commit \"$GITHUB_SHA\" --output \"$model_public/model-outcome.json\"; then",
    "      diagnostic_code=0",
    "      if ! printf '%s\\n' 'model_diagnostic_ready=true' >>\"$GITHUB_OUTPUT\"; then",
    "        printf '%s\\n' 'CPU_PUBLICATION=REJECTED_MODEL_OUTPUT_WRITE' >&2",
    "        exit 1",
    "      fi",
    "    else",
    "      diagnostic_code=$?",
    "    fi",
    "    cpu_code=0",
    "    if test \"$unit_code\" = 0 && test \"$go_code\" = 0; then",
    "      if python3 -I -B chengwang/deploy/joint-control-plane/sanitize_publication.py cpu --units \"$private/units.json\" --go-exit \"$private/go-exit.txt\" --output \"$stage/cpu-summary.json\"; then",
    "        projection_code=0",
    "      else",
    "        projection_code=$?",
    "      fi",
    "    else",
    "      cpu_code=1",
    "      if python3 -I -B chengwang/deploy/joint-control-plane/sanitize_publication.py failure --input \"$private\" --code CPU_FAILED --output \"$stage/cpu-failure.json\"; then",
    "        projection_code=0",
    "      else",
    "        projection_code=$?",
    "      fi",
    "    fi",
    "    fallback_code=0",
    "    if test \"$projection_code\" != 0; then",
    "      cpu_code=1",
    "      if python3 -I -B chengwang/deploy/joint-control-plane/sanitize_publication.py cpu-fallback --output \"$stage/cpu-diagnostic-unavailable.json\"; then",
    "        fallback_code=0",
    "      else",
    "        fallback_code=$?",
    "      fi",
    "    fi",
    "    if python3 -I -B chengwang/deploy/joint-control-plane/sanitize_publication.py cpu-publish --input \"$stage\" --output \"$public\"; then",
    "      publish_code=0",
    "    else",
    "      publish_code=$?",
    "    fi",
    "    if test \"$publish_code\" = 0; then",
    "      if ! printf '%s\\n' 'publication_ready=true' >>\"$GITHUB_OUTPUT\"; then",
    "        printf '%s\\n' 'CPU_PUBLICATION=REJECTED_OUTPUT_WRITE' >&2",
    "        exit 1",
    "      fi",
    "    fi",
    "    test \"$diagnostic_code\" = 0 && test \"$fallback_code\" = 0 && test \"$publish_code\" = 0 && test \"$cpu_code\" = 0",
)
CPU_UPLOAD_STEP=(
    "- name: Preserve bounded CPU publication only",
    "  if: ${{ always() && steps.cpu.outputs.publication_ready == 'true' }}",
    "  uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    "  with:",
    "    name: joint-control-plane-cpu-${{ github.run_id }}-${{ github.run_attempt }}",
    "    path: ${{ runner.temp }}/joint-control-plane-cpu-public/",
    "    if-no-files-found: error",
    "    retention-days: 14",
)
MODEL_UPLOAD_STEP=(
    "- name: Preserve source-bound model outcome diagnostic only",
    "  if: ${{ always() && steps.cpu.outputs.model_diagnostic_ready == 'true' }}",
    "  uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    "  with:",
    "    name: joint-control-plane-model-outcomes-${{ github.run_id }}-${{ github.run_attempt }}",
    "    path: ${{ runner.temp }}/joint-control-plane-model-outcome-public/model-outcome.json",
    "    if-no-files-found: error",
    "    retention-days: 14",
)
def need(ok):
    if not ok:raise ValueError("joint-ci-rejected")
def normalized_workflow(raw):
    need(type(raw)is bytes and raw.endswith(b"\n") and b"\r" not in raw and b"\t" not in raw)
    pattern=rb"(?m)^  CONTRACT_SHA256: [a-f0-9]{64}$"
    need(len(re.findall(pattern,raw))==1)
    return re.sub(pattern,b"  CONTRACT_SHA256: <SOURCE_CONTRACT_SHA256>",raw)
def workflow_contract(raw,source_contract_raw=None):
    need(type(raw)is bytes and 0<len(raw)<=65536 and b"\r" not in raw and b"\t" not in raw)
    need(hashlib.sha256(normalized_workflow(raw)).hexdigest()==WORKFLOW_NORMALIZED_SHA256)
    try:lines=raw.decode("utf-8","strict").split("\n")
    except UnicodeDecodeError:raise ValueError("joint-ci-rejected") from None
    need(lines.count("  joint-control-plane:")==1 and lines.count("    steps:")>=1)
    job=lines.index("  joint-control-plane:");steps=lines.index("    steps:",job+1)
    end=next((i for i in range(steps+1,len(lines)) if lines[i].startswith("  ") and not lines[i].startswith("    ")),len(lines))
    starts=[i for i in range(steps+1,end) if lines[i].startswith("      - ")]
    need(starts and all(not lines[i].startswith("       ") for i in starts))
    blocks=[]
    for index,start in enumerate(starts):
        stop=starts[index+1] if index+1<len(starts) else end
        blocks.append(tuple(line[6:] for line in lines[start:stop]))
    named={}
    for block in blocks:
        if block[0].startswith("- name: "):
            name=block[0][8:];need(name and name not in named);named[name]=block
    ids=[line[6:] for block in blocks for line in block if line.startswith("  id: ")]
    need(len(ids)==len(set(ids)) and ids.count("bootstrap_progress")==1)
    bootstrap_block=named.get("Bootstrap bounded namespace progress")
    need(bootstrap_block is not None and hashlib.sha256(("\n".join(bootstrap_block)+"\n").encode()).hexdigest()==BOOTSTRAP_STEP_SHA256)
    need(named.get("Real B0 J1 R2 same-binary scene")==SCENE_STEP)
    need(named.get("Publish only bounded failure classification")==FAILURE_STEP)
    need(named.get("CPU contracts and Go suite")==CPU_STEP)
    need(named.get("Preserve bounded CPU publication only")==CPU_UPLOAD_STEP)
    need(named.get("Preserve source-bound model outcome diagnostic only")==MODEL_UPLOAD_STEP)
    text=raw.decode("utf-8","strict")
    if source_contract_raw is None:source_contract_raw=(HERE/"source_contract.json").read_bytes()
    need(type(source_contract_raw)is bytes and text.count("  CONTRACT_SHA256: "+hashlib.sha256(source_contract_raw).hexdigest())==1)
    required=(
        "UID_PROBE_PRODUCER_SHA256: 98982bd151c9289534fa7421a1520ba51ff67ceb0fd930065e227321e419052d",
        "UID_PROBE_CHECKER_SHA256: 04fdd2ac9acbc2dafa7c2ecab9910b3346649042569dbaeb9cec4efb056e81c8",
        "- name: Probe isolated Linux UID custody",
        "id: uid_probe",
        "test \"$host_preflight\" != PREFLIGHT_EXECUTION_FAILED || diagnostic_failed=true",
        "bridge-payload-digest --repo \"$GITHUB_WORKSPACE\" --source-contract \"$source_contract\"",
        "--bridge-mode setup >/dev/null 2>/dev/null; then bridge_setup_status=0; bridge_active=true",
        "bridge-preflight --classification \"$bridge_preflight\" --exit-status \"$bridge_preflight_status\"",
        "--bridge-mode cleanup >/dev/null 2>/dev/null; then cleanup_status=0",
        "--bridge-mode final-absence >/dev/null 2>/dev/null; then absence_status=0",
        "if run_root root-setup; then :; else original_code=$?; fi",
        "if run_root root-cleanup; then cleanup_status=0; else cleanup_status=$?; fi",
        "if run_root root-final-absence; then absence_status=0; else absence_status=$?; fi",
        "trap 'finish_probe \"$?\"' EXIT",
        "- name: Independently validate UID probe diagnostic",
        "id: uid_probe_diagnostic",
        "if echo 'ready=true' >> \"$GITHUB_OUTPUT\"; then exit 0; else exit 1; fi",
        "if: ${{ always() && steps.uid_probe_diagnostic.outputs.ready == 'true' }}",
        "path: ${{ runner.temp }}/joint-control-plane-uid-probe-public/uid-probe-diagnostic.json",
        "\n  uid-probe-independent-replay:\n",
        "name: joint-control-plane-uid-probe-${{ github.run_id }}-${{ github.run_attempt }}",
    )
    need(all(text.count(value)==1 if value.startswith(("UID_PROBE_","\n  uid-probe-independent")) else text.count(value)>=1 for value in required))
    return True
def run(*args):return subprocess.check_output(list(args),stderr=subprocess.DEVNULL,timeout=30)
def emit(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_BINARY",0),0o600)
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
def _model_inventory():
    names=[];source_rows=[]
    for filename in MODEL_TEST_SOURCES:
        path=HERE/filename;raw=path.read_bytes();tree=ast.parse(raw,filename=filename)
        source_rows.append(filename.encode()+b"\0"+hashlib.sha256(raw).hexdigest().encode()+b"\n")
        module=filename[:-3]
        for cls in tree.body:
            if not isinstance(cls,ast.ClassDef):continue
            for method in cls.body:
                if isinstance(method,(ast.FunctionDef,ast.AsyncFunctionDef)) and method.name.startswith("test_"):
                    names.append(module+"."+cls.name+"."+method.name)
    names=tuple(sorted(names));need(names and len(names)==len(set(names)))
    return names,hashlib.sha256("\n".join(names).encode()).hexdigest(),hashlib.sha256(b"".join(source_rows)).hexdigest()
def _model_counts(rows):
    counts={name:0 for name in MODEL_OUTCOMES}
    for outcome in rows.values():need(outcome in counts);counts[outcome]+=1
    return counts
class ModelOutcomeResult(unittest.TextTestResult):
    _rank={"UNKNOWN":0,"PASS":1,"SKIP":2,"FAIL":3,"ERROR":4}
    def __init__(self,*args,expected,**kwargs):
        super().__init__(*args,**kwargs);self.expected=frozenset(expected);self.started=set();self.outcomes={};self.unknownEvents=0
    def _identity(self,test):
        try:value=test.id()
        except BaseException:
            self.unknownEvents+=1;return None
        if type(value)is not str or value not in self.expected:
            self.unknownEvents+=1;return None
        return value
    def _mark(self,test,outcome):
        identity=self._identity(test)
        if identity is None:return
        previous=self.outcomes.get(identity,"UNKNOWN")
        if self._rank[outcome]>=self._rank[previous]:self.outcomes[identity]=outcome
    def startTest(self,test):
        super().startTest(test);identity=self._identity(test)
        if identity is not None:self.started.add(identity)
    def stopTest(self,test):
        identity=self._identity(test)
        if identity is not None:self.outcomes.setdefault(identity,"UNKNOWN")
        super().stopTest(test)
    def addSuccess(self,test):super().addSuccess(test);self._mark(test,"PASS")
    def addFailure(self,test,err):super().addFailure(test,err);self._mark(test,"FAIL")
    def addError(self,test,err):super().addError(test,err);self._mark(test,"ERROR")
    def addSkip(self,test,reason):super().addSkip(test,reason);self._mark(test,"SKIP")
    def addExpectedFailure(self,test,err):super().addExpectedFailure(test,err);self._mark(test,"UNKNOWN")
    def addUnexpectedSuccess(self,test):super().addUnexpectedSuccess(test);self._mark(test,"UNKNOWN")
    def addSubTest(self,test,subtest,err):
        super().addSubTest(test,subtest,err)
        if err is not None:
            try:failure=issubclass(err[0],test.failureException)
            except BaseException:failure=False
            self._mark(test,"FAIL" if failure else "ERROR")
def _model_value(source_commit,expected,names_sha,source_sha,result):
    need(type(source_commit)is str and re.fullmatch(r"[0-9a-f]{40}",source_commit) is not None)
    outcomes={name:result.outcomes.get(name,"UNKNOWN") for name in expected}
    counts=_model_counts(outcomes)
    return {"schema":MODEL_DIAGNOSTIC_SCHEMA,"sourceCommit":source_commit,"accepted":False,"syntheticOnly":True,
        "projection":"FULL","expectedCount":len(expected),"expectedNamesSHA256":names_sha,"sourceFilesSHA256":source_sha,
        "observedCount":len(result.started),"unknownEventCount":result.unknownEvents,"counts":counts,
        "outcomes":[{"id":name,"outcome":outcomes[name]} for name in expected]}
def _bounded_model_bytes(value,maximum=MODEL_DIAGNOSTIC_MAXIMUM):
    raw=C.canonical(value)
    if len(raw)<=maximum:return raw
    counts=dict(value["counts"]);need(set(counts)==set(MODEL_OUTCOMES) and sum(counts.values())==value["expectedCount"])
    fallback={key:value[key] for key in ("schema","sourceCommit","accepted","syntheticOnly","expectedCount","expectedNamesSHA256","sourceFilesSHA256","observedCount","unknownEventCount","counts")}
    fallback.update({"projection":"FALLBACK","outcomes":[]});raw=C.canonical(fallback);need(len(raw)<=maximum);return raw
def _emit_raw(path,raw,maximum):
    need(type(raw)is bytes and 0<len(raw)<=maximum)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_BINARY",0),0o600)
    with os.fdopen(fd,"wb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
def _decode_model(raw):
    need(type(raw)is bytes and 0<len(raw)<=MODEL_DIAGNOSTIC_MAXIMUM and b"\r" not in raw)
    def pairs(items):
        value={}
        for key,item in items:need(type(key)is str and key not in value);value[key]=item
        return value
    try:value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda unused:(_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError,json.JSONDecodeError,ValueError):raise ValueError("joint-ci-rejected") from None
    need(C.canonical(value)==raw);return value
def validate_model_diagnostic(raw,source_commit):
    value=_decode_model(raw);expected,names_sha,source_sha=_model_inventory()
    keys={"schema","sourceCommit","accepted","syntheticOnly","projection","expectedCount","expectedNamesSHA256","sourceFilesSHA256","observedCount","unknownEventCount","counts","outcomes"}
    need(type(value)is dict and set(value)==keys and value["schema"]==MODEL_DIAGNOSTIC_SCHEMA and value["sourceCommit"]==source_commit and
        value["accepted"] is False and value["syntheticOnly"] is True and value["projection"] in ("FULL","FALLBACK") and
        value["expectedCount"]==len(expected) and value["expectedNamesSHA256"]==names_sha and value["sourceFilesSHA256"]==source_sha and
        type(value["observedCount"])is int and 0<=value["observedCount"]<=len(expected) and type(value["unknownEventCount"])is int and value["unknownEventCount"]>=0)
    counts=value["counts"];need(type(counts)is dict and tuple(sorted(counts))==tuple(sorted(MODEL_OUTCOMES)) and
        all(type(counts[name])is int and counts[name]>=0 for name in MODEL_OUTCOMES) and sum(counts.values())==len(expected))
    rows=value["outcomes"];need(type(rows)is list)
    if value["projection"]=="FULL":
        need(len(rows)==len(expected));observed=[];row_counts={name:0 for name in MODEL_OUTCOMES}
        for row in rows:
            need(type(row)is dict and set(row)=={"id","outcome"} and type(row["id"])is str and row["outcome"] in MODEL_OUTCOMES)
            observed.append(row["id"]);row_counts[row["outcome"]]+=1
        need(tuple(observed)==expected and row_counts==counts)
    else:need(rows==[])
    return value
def _model_all_pass(result,expected):
    expected_set=set(expected)
    return (result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses and
        result.testsRun==len(expected) and result.started==expected_set and set(result.outcomes)==expected_set and
        result.unknownEvents==0 and all(result.outcomes[name]=="PASS" for name in expected))
def units(model_diagnostic=None,source_commit=None):
    need((model_diagnostic is None)==(source_commit is None));expected,names_sha,source_sha=_model_inventory()
    sys.path.insert(0,str(HERE));suite=unittest.TestSuite()
    for name in (source[:-3] for source in MODEL_TEST_SOURCES):suite.addTests(unittest.defaultTestLoader.loadTestsFromName(name))
    holder=[]
    def result_class(*args,**kwargs):
        result=ModelOutcomeResult(*args,expected=expected,**kwargs);holder.append(result);return result
    try:result=unittest.TextTestRunner(verbosity=2,resultclass=result_class).run(suite)
    except BaseException:
        if model_diagnostic is not None:
            incomplete=holder[0] if holder else types.SimpleNamespace(outcomes={},started=set(),unknownEvents=1)
            _emit_raw(model_diagnostic,_bounded_model_bytes(_model_value(source_commit,expected,names_sha,source_sha,incomplete)),MODEL_DIAGNOSTIC_MAXIMUM)
        raise
    if model_diagnostic is not None:_emit_raw(model_diagnostic,_bounded_model_bytes(_model_value(source_commit,expected,names_sha,source_sha,result)),MODEL_DIAGNOSTIC_MAXIMUM)
    need(_model_all_pass(result,expected));return {"schema":"chengwang.joint-control-plane-units/v2","testsRun":result.testsRun,"failures":0,"syntheticOnly":True,"productAcceptanceProven":False}
def bootstrap_argv(progress_root,bootstrap_record,source_commit):
    script=str(pathlib.Path(__file__).resolve())
    need(pathlib.Path(bootstrap_record).name==C.BOOTSTRAP_FILE and pathlib.Path(bootstrap_record).parent.name==C.BOOTSTRAP_DIRECTORY)
    return ["/usr/bin/setpriv","--reuid=10001","--regid=10001","--clear-groups","--bounding-set=-all","--inh-caps=-all","--ambient-caps=-all","--no-new-privs","/usr/bin/env","-i","PATH=/usr/bin:/bin","LANG=C.UTF-8","TZ=UTC","PYTHONDONTWRITEBYTECODE=1","PYTHONHASHSEED=0","/usr/bin/python3","-I","-B",script,"progress","--progress-root",str(progress_root),"--source-commit",source_commit,"--phase","NAMESPACE_SETUP","--state","ENTERED","--receipt"]
def _stop_child(process):
    try:
        if process.poll() is not None:return True
    except Exception:pass
    try:process.terminate()
    except Exception:pass
    try:process.wait(timeout=1)
    except Exception:pass
    try:
        if process.poll() is not None:return True
    except Exception:pass
    try:process.kill()
    except Exception:pass
    try:process.wait(timeout=1)
    except Exception:pass
    try:return process.poll() is not None
    except Exception:return False
def _bounded_child(argv,expected,timeout=10,popen=subprocess.Popen,platform=None,
                   selector_factory=selectors.DefaultSelector,set_blocking=os.set_blocking,
                   read_fd=os.read,failure_decoder=None):
    need(type(expected)is bytes and len(expected)<=1024 and timeout>0)
    try:
        process=popen(argv,cwd="/",env={},shell=False,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True)
    except Exception:
        return "SPAWN_ERROR"
    raw=b"";timed_out=False;oversize=False;supervisor_failed=False;reaped=False;close_failed=False;deadline=time.monotonic()+timeout
    try:
        if process.stdout is None:supervisor_failed=True
        elif (os.name if platform is None else platform)=="posix":
            watch=None
            try:
                fd=process.stdout.fileno();set_blocking(fd,False);watch=selector_factory();watch.register(fd,selectors.EVENT_READ);eof=False
                while not eof:
                    remaining=deadline-time.monotonic()
                    if remaining<=0:timed_out=True;break
                    events=watch.select(min(remaining,0.1))
                    if not events:
                        if process.poll() is not None:
                            if len(raw)>=1025:oversize=True;break
                            capacity=1025-len(raw)
                            try:chunk=read_fd(fd,capacity)
                            except BlockingIOError:chunk=None
                            if chunk:
                                oversize=len(chunk)>capacity;raw+=chunk[:capacity]
                                if oversize or len(raw)>1024:oversize=True;break
                            elif chunk==b"":eof=True
                        continue
                    if len(raw)>=1025:oversize=True;break
                    capacity=1025-len(raw)
                    try:chunk=read_fd(fd,capacity)
                    except BlockingIOError:continue
                    if not chunk:eof=True;continue
                    oversize=len(chunk)>capacity;raw+=chunk[:capacity]
                    if oversize or len(raw)>1024:oversize=True;break
            except Exception:
                supervisor_failed=True
            finally:
                if watch is not None:
                    try:watch.close()
                    except Exception:supervisor_failed=True
        elif not supervisor_failed:
            result=[]
            def read_once():
                try:result.append((process.stdout.read(1025),False))
                except Exception:result.append((b"",True))
            reader=threading.Thread(target=read_once,daemon=True);reader.start();reader.join(timeout)
            if reader.is_alive():timed_out=True
            else:
                raw,supervisor_failed=result[0];raw=raw[:1025];oversize=len(raw)>1024
        if timed_out or oversize or supervisor_failed:
            reaped=_stop_child(process)
        else:
            remaining=max(0.001,deadline-time.monotonic())
            try:process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out=True;reaped=_stop_child(process)
            except Exception:
                supervisor_failed=True;reaped=_stop_child(process)
            else:
                try:reaped=process.poll() is not None
                except Exception:supervisor_failed=True;reaped=_stop_child(process)
        try:code=process.poll()
        except Exception:code=None;supervisor_failed=True
    finally:
        try:process.stdout.close()
        except Exception:close_failed=True
    if supervisor_failed or close_failed or not reaped:
        raise ValueError("joint-ci-child-custody-rejected") from None
    state="TIMEOUT" if timed_out else "STDOUT_OVERSIZE" if oversize else "COMMAND_NONZERO" if code!=0 else "STDOUT_INVALID" if raw!=expected else "PASS"
    if failure_decoder is None:return state
    operation,authority=("NONE","NONE") if state=="PASS" else failure_decoder(raw) if state=="COMMAND_NONZERO" else ("OBSERVED_UNKNOWN","OBSERVED_UNKNOWN")
    return state,operation,authority
def _bootstrap_failure(raw,source_commit):
    try:value=C._strict_object(raw)
    except BaseException:return "OBSERVED_UNKNOWN","OBSERVED_UNKNOWN"
    if raw!=C.canonical(value) or set(value)!={"schema","sourceCommit","operation","authority"} or value.get("schema")!=C.BOOTSTRAP_FAILURE_RECEIPT_SCHEMA or value.get("sourceCommit")!=source_commit or value.get("operation") not in C.BOOTSTRAP_CHILD_OPERATIONS-{"NONE","OBSERVED_UNKNOWN"} or value.get("authority")!="FIXED_SOURCE_CLASSIFICATION":return "OBSERVED_UNKNOWN","OBSERVED_UNKNOWN"
    return value["operation"],value["authority"]
def bootstrap_progress(progress_root,bootstrap_record,source_commit):
    receipt=C.canonical({"schema":C.BOOTSTRAP_RECEIPT_SCHEMA,"sourceCommit":source_commit,"phase":"NAMESPACE_SETUP","state":"ENTERED","status":"PASS"})
    state,operation,authority=_bounded_child(bootstrap_argv(progress_root,bootstrap_record,source_commit),receipt,failure_decoder=lambda raw:_bootstrap_failure(raw,source_commit))
    C.record_bootstrap_status(bootstrap_record,source_commit,state,operation,authority)
    need(state=="PASS")
PROBE_PREFIX="chengwang-joint-bootstrap-custody-probe-"
BRIDGE_PREFIX="chengwang-joint-uid-bridge-"
BRIDGE_FILES=(
    ("chengwang/deploy/joint-control-plane/ci_joint_control_plane.py","ci_joint_control_plane.py"),
    ("chengwang/deploy/joint-control-plane/contract.py","contract.py"),
)
BRIDGE_MAX_FILE_BYTES=1048576
PROBE_SOURCE="0"*40
PROBE_RAW=C.canonical({"schema":C.BOOTSTRAP_SCHEMA,"sourceCommit":PROBE_SOURCE,"bootstrapChildState":"PASS","bootstrapChildOperation":"NONE","bootstrapChildOperationAuthority":"NONE"})
PROBE_MODES=frozenset(("root-setup","uid-prepublish-denials","root-finalize",
    "uid-final-read-and-rename","uid-install-replacement","root-reject-replacement",
    "root-cleanup","root-final-absence"))
def _bridge_stable_read(path):
    path=pathlib.Path(path);before=path.lstat();need(not path.is_symlink() and stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=BRIDGE_MAX_FILE_BYTES)
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0));raw=bytearray()
    try:
        opened=os.fstat(fd);need((opened.st_dev,opened.st_ino,opened.st_size)==(before.st_dev,before.st_ino,before.st_size))
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            raw.extend(chunk);need(len(raw)<=BRIDGE_MAX_FILE_BYTES)
        after_fd=os.fstat(fd)
    finally:os.close(fd)
    after=path.lstat();identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns)
    need(identity(before)==identity(after_fd)==identity(after));return bytes(raw)
def _bridge_rows(repo,source_contract):
    repo=pathlib.Path(repo).resolve(strict=True);contract=pathlib.Path(source_contract).resolve(strict=True)
    need(contract==repo/"chengwang/deploy/joint-control-plane/source_contract.json")
    value=json.loads(_bridge_stable_read(contract));need(type(value)is dict and type(value.get("paths"))is list)
    by_path={row.get("path"):row for row in value["paths"] if type(row)is dict and row.get("path") in {item[0] for item in BRIDGE_FILES}}
    need(set(by_path)=={item[0] for item in BRIDGE_FILES})
    rows=[]
    for relative,basename in BRIDGE_FILES:
        row=by_path[relative];need(set(row)=={"path","sha256"} and re.fullmatch(r"[a-f0-9]{64}",row["sha256"] or ""))
        source=repo/relative;need(source.resolve(strict=True)==source.absolute());raw=_bridge_stable_read(source);need(hashlib.sha256(raw).hexdigest()==row["sha256"])
        rows.append((relative,basename,row["sha256"],raw))
    digest=hashlib.sha256(C.canonical([{"path":relative,"sha256":expected} for relative,_,expected,_ in rows])).hexdigest()
    return rows,digest
def _bridge_parent(path,device,inode,platform=None):
    parent=pathlib.Path(path);meta=parent.lstat();need((os.name if platform is None else platform)=="posix")
    if platform is None:need(parent==pathlib.Path("/tmp"))
    need(parent.is_absolute() and not parent.is_symlink() and stat.S_ISDIR(meta.st_mode) and meta.st_uid==0 and meta.st_gid==0 and str(meta.st_dev)==device and str(meta.st_ino)==inode and parent.resolve(strict=True)==parent.absolute())
    return parent
def _bridge_root(parent,run_id,run_attempt,nonce):
    need(re.fullmatch(r"[1-9][0-9]*",run_id or "") and re.fullmatch(r"[1-9][0-9]*",run_attempt or "") and re.fullmatch(r"[a-f0-9]{32}",nonce or ""))
    root=parent/(BRIDGE_PREFIX+run_id+"-"+run_attempt+"-"+nonce);need(root.parent==parent);return root
def _bridge_owned(path,mode,kind="dir"):
    path=pathlib.Path(path);meta=path.lstat();modes=set(mode) if type(mode)in (set,frozenset,tuple,list) else {mode};need(not path.is_symlink() and meta.st_uid==0 and meta.st_gid==0 and stat.S_IMODE(meta.st_mode) in modes and (stat.S_ISDIR(meta.st_mode) if kind=="dir" else stat.S_ISREG(meta.st_mode) and meta.st_nlink==1));return meta
def _bridge_write(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        seen=0
        while seen<len(raw):
            count=os.write(fd,raw[seen:]);need(count>0);seen+=count
        os.fsync(fd);os.fchmod(fd,0o444);opened=os.fstat(fd);need(stat.S_ISREG(opened.st_mode) and opened.st_nlink==1)
        os.fchown(fd,0,0)
    finally:os.close(fd)
def _bridge_validate(root,rows,partial=False,progress=False):
    root=pathlib.Path(root);_bridge_owned(root,{0o700,0o711} if partial else 0o711)
    entries={item.name for item in root.iterdir()};need(entries<= {"payload","runner"} if partial else entries=={"payload","runner"})
    payload=root/"payload";runner=root/"runner";expected={basename:(expected,raw) for _,basename,expected,raw in rows}
    if not _probe_absent(payload):
        _bridge_owned(payload,{0o700,0o555} if partial else 0o555)
        names={item.name for item in payload.iterdir()};need(names<=set(expected) if partial else names==set(expected))
        for name in names:
            file=payload/name;meta=_bridge_owned(file,{0o600,0o444} if partial else 0o444,"file")
            if not partial or stat.S_IMODE(meta.st_mode)==0o444:
                raw=_bridge_stable_read(file);need(raw==expected[name][1] and hashlib.sha256(raw).hexdigest()==expected[name][0])
    if not _probe_absent(runner):
        _bridge_owned(runner,0o711);names={p.name for p in runner.iterdir()}
        need(names==({"failure-localization.private"} if progress else set()))
        if progress:
            item=runner/"failure-localization.private";meta=item.lstat();need(not item.is_symlink() and stat.S_ISDIR(meta.st_mode) and meta.st_uid==C.UID and meta.st_gid==C.GID and stat.S_IMODE(meta.st_mode)==0o700)
    return payload,runner
def _bridge_cleanup(root,rows,partial=False):
    root=pathlib.Path(root)
    if _probe_absent(root):return
    payload,runner=_bridge_validate(root,rows,partial)
    if not _probe_absent(payload):
        for _,basename,_,_ in rows:
            file=payload/basename
            if not _probe_absent(file):os.unlink(file)
        os.rmdir(payload)
    if not _probe_absent(runner):os.rmdir(runner)
    os.rmdir(root);_probe_dir_fsync(root.parent)
def bridge_payload_digest(repo,source_contract):return _bridge_rows(repo,source_contract)[1]
def bridge_setup(repo,source_contract,parent_path,parent_device,parent_inode,run_id,run_attempt,nonce,platform=None):
    need((os.geteuid(),os.getegid())==(0,0));parent=_bridge_parent(parent_path,parent_device,parent_inode,platform);root=_bridge_root(parent,run_id,run_attempt,nonce);rows,digest=_bridge_rows(repo,source_contract);need(_probe_absent(root));created=False
    try:
        os.mkdir(root,0o700);created=True;os.chown(root,0,0);payload=root/"payload";runner=root/"runner";os.mkdir(payload,0o700);os.chown(payload,0,0);os.mkdir(runner,0o711);os.chown(runner,0,0)
        for _,basename,_,raw in rows:_bridge_write(payload/basename,raw)
        os.chmod(payload,0o555);os.chmod(root,0o711);_probe_dir_fsync(payload);_probe_dir_fsync(runner);_probe_dir_fsync(root);_probe_dir_fsync(parent);_bridge_validate(root,rows)
    except BaseException:
        if created:_bridge_cleanup(root,rows,partial=True);need(_probe_absent(root))
        raise
    return root,digest
def bridge_cleanup(repo,source_contract,parent_path,parent_device,parent_inode,run_id,run_attempt,nonce,platform=None):
    parent=_bridge_parent(parent_path,parent_device,parent_inode,platform);root=_bridge_root(parent,run_id,run_attempt,nonce);rows,_=_bridge_rows(repo,source_contract);need((os.geteuid(),os.getegid())==(0,0));_bridge_cleanup(root,rows);return root
def bridge_final_absence(parent_path,parent_device,parent_inode,run_id,run_attempt,nonce,platform=None):
    parent=_bridge_parent(parent_path,parent_device,parent_inode,platform);root=_bridge_root(parent,run_id,run_attempt,nonce);need(_probe_absent(root));_bridge_parent(parent_path,parent_device,parent_inode,platform);return root
def bridge_progress_setup(repo,source_contract,parent_path,parent_device,parent_inode,run_id,run_attempt,nonce,platform=None):
    parent=_bridge_parent(parent_path,parent_device,parent_inode,platform);root=_bridge_root(parent,run_id,run_attempt,nonce);rows,_=_bridge_rows(repo,source_contract);need((os.geteuid(),os.getegid())==(0,0));_,runner=_bridge_validate(root,rows);progress=runner/"failure-localization.private";os.mkdir(progress,0o700);os.chown(progress,C.UID,C.GID);os.chmod(progress,0o700);_probe_dir_fsync(runner);_bridge_validate(root,rows,progress=True);return progress
def bridge_progress_preflight(repo,source_contract,parent_path,parent_device,parent_inode,run_id,run_attempt,nonce,platform=None):
    parent=_bridge_parent(parent_path,parent_device,parent_inode,platform);root=_bridge_root(parent,run_id,run_attempt,nonce);need((os.geteuid(),os.getegid())==(C.UID,C.GID));_bridge_owned(root,0o711);need({p.name for p in root.iterdir()}=={"payload","runner"});payload=root/"payload";runner=root/"runner";_bridge_owned(payload,0o555);_bridge_owned(runner,0o711);need({p.name for p in payload.iterdir()}=={item[1] for item in BRIDGE_FILES} and {p.name for p in runner.iterdir()}=={"failure-localization.private"})
    for _,basename in BRIDGE_FILES:_bridge_owned(payload/basename,0o444,"file");need(len(_bridge_stable_read(payload/basename))<=BRIDGE_MAX_FILE_BYTES)
    progress=runner/"failure-localization.private";meta=progress.lstat();need(not progress.is_symlink() and stat.S_ISDIR(meta.st_mode) and meta.st_uid==C.UID and meta.st_gid==C.GID and stat.S_IMODE(meta.st_mode)==0o700 and not any(progress.iterdir()));stable=[item.lstat() for item in (root,payload,runner,progress)];probe=progress/"preflight";raw=b"joint-bootstrap-progress-preflight-v1\n";fd=os.open(probe,os.O_RDWR|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_BINARY",0),0o600)
    try:
        need(os.write(fd,raw)==len(raw));os.fsync(fd);os.lseek(fd,0,os.SEEK_SET);need(os.read(fd,len(raw)+1)==raw);meta=os.fstat(fd);need(stat.S_ISREG(meta.st_mode) and meta.st_nlink==1)
    finally:os.close(fd)
    os.unlink(probe);_probe_dir_fsync(progress);need(not any(progress.iterdir()) and all((before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid)==(after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid) for before,after in zip(stable,(item.lstat() for item in (root,payload,runner,progress)))));return progress
def bridge_progress_transfer(repo,source_contract,parent_path,parent_device,parent_inode,run_id,run_attempt,nonce,destination,source_commit,platform=None):
    parent=_bridge_parent(parent_path,parent_device,parent_inode,platform);root=_bridge_root(parent,run_id,run_attempt,nonce);rows,_=_bridge_rows(repo,source_contract);need((os.geteuid(),os.getegid())==(0,0));_,runner=_bridge_validate(root,rows,progress=True);source=runner/"failure-localization.private";_,records=C._progress_rows(source,source_commit);need(len(records)==1);name=C.progress_name(0,"NAMESPACE_SETUP","ENTERED");source_meta=source.lstat();source_file_meta=(source/name).lstat();need(source_meta.st_uid==C.UID and source_meta.st_gid==C.GID and stat.S_IMODE(source_meta.st_mode)==0o700 and source_file_meta.st_uid==C.UID and source_file_meta.st_gid==C.GID and stat.S_IMODE(source_file_meta.st_mode)==0o600 and stat.S_ISREG(source_file_meta.st_mode) and source_file_meta.st_nlink==1);raw=C._private_read(source/name);dest=pathlib.Path(destination);need(dest.is_absolute() and dest.name=="failure-localization.private" and not dest.exists() and not dest.is_symlink());dest_parent=dest.parent;parent_meta=dest_parent.lstat();need(stat.S_ISDIR(parent_meta.st_mode) and not dest_parent.is_symlink());parent_signature=(parent_meta.st_dev,parent_meta.st_ino,parent_meta.st_mode,parent_meta.st_uid,parent_meta.st_gid);dest_identity=None;file_identity=None
    try:
        os.mkdir(dest,0o700);created=dest.lstat();dest_identity=(created.st_dev,created.st_ino);os.chown(dest,C.UID,C.GID);os.chmod(dest,0o700)
        fd=os.open(dest/name,os.O_RDWR|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_BINARY",0),0o600)
        try:
            opened=os.fstat(fd);file_identity=(opened.st_dev,opened.st_ino);seen=0
            while seen<len(raw):count=os.write(fd,raw[seen:]);need(count>0);seen+=count
            os.fchown(fd,C.UID,C.GID);os.fsync(fd);os.lseek(fd,0,os.SEEK_SET);need(os.read(fd,len(raw)+1)==raw)
        finally:os.close(fd)
        dest_meta=dest.lstat();copied_meta=(dest/name).lstat();need((dest_meta.st_dev,dest_meta.st_ino)==dest_identity and (copied_meta.st_dev,copied_meta.st_ino)==file_identity and dest_meta.st_uid==C.UID and dest_meta.st_gid==C.GID and stat.S_IMODE(dest_meta.st_mode)==0o700 and copied_meta.st_uid==C.UID and copied_meta.st_gid==C.GID and stat.S_IMODE(copied_meta.st_mode)==0o600 and stat.S_ISREG(copied_meta.st_mode) and copied_meta.st_nlink==1)
        _probe_dir_fsync(dest);_probe_dir_fsync(dest.parent);after_parent=dest_parent.lstat();need(parent_signature==(after_parent.st_dev,after_parent.st_ino,after_parent.st_mode,after_parent.st_uid,after_parent.st_gid));_,copied=C._progress_rows(dest,source_commit);need(len(copied)==1 and C._private_read(dest/name)==raw)
    except BaseException:
        try:
            if dest_identity is not None:
                current=dest.lstat();need((current.st_dev,current.st_ino)==dest_identity and not dest.is_symlink() and stat.S_ISDIR(current.st_mode) and {p.name for p in dest.iterdir()}<=({name} if file_identity is not None else set()))
                copied=dest/name
                if file_identity is not None and not _probe_absent(copied):
                    copied_meta=copied.lstat();need((copied_meta.st_dev,copied_meta.st_ino)==file_identity and not copied.is_symlink() and stat.S_ISREG(copied_meta.st_mode) and copied_meta.st_nlink==1);os.unlink(copied)
                need(not any(dest.iterdir()));os.rmdir(dest);_probe_dir_fsync(dest_parent);need(_probe_absent(dest));after_parent=dest_parent.lstat();need(parent_signature==(after_parent.st_dev,after_parent.st_ino,after_parent.st_mode,after_parent.st_uid,after_parent.st_gid))
        except BaseException:raise ValueError("joint-progress-transfer-cleanup-rejected") from None
        raise
    os.unlink(source/name);os.rmdir(source);_probe_dir_fsync(runner);_bridge_validate(root,rows);return dest
def bridge_progress_cleanup(repo,source_contract,parent_path,parent_device,parent_inode,run_id,run_attempt,nonce,platform=None):
    parent=_bridge_parent(parent_path,parent_device,parent_inode,platform);root=_bridge_root(parent,run_id,run_attempt,nonce);rows,_=_bridge_rows(repo,source_contract);need((os.geteuid(),os.getegid())==(0,0));runner=root/"runner";runner_names={p.name for p in runner.iterdir()}
    if not runner_names:_bridge_validate(root,rows);_bridge_cleanup(root,rows);return root
    _,runner=_bridge_validate(root,rows,progress=True);progress=runner/"failure-localization.private";names={p.name for p in progress.iterdir()};need(names<= {C.progress_name(0,"NAMESPACE_SETUP","ENTERED")})
    for name in names:
        p=progress/name;m=p.lstat();need(not p.is_symlink() and stat.S_ISREG(m.st_mode) and m.st_nlink==1 and m.st_uid==C.UID and m.st_gid==C.GID and m.st_size<=4096);os.unlink(p)
    os.rmdir(progress);_probe_dir_fsync(runner);_bridge_cleanup(root,rows);return root
def _probe_absent(path):
    try:pathlib.Path(path).lstat()
    except FileNotFoundError:return True
    return False
def _probe_paths(runner_temp,run_id,run_attempt,runner_device,runner_inode,platform=None):
    need((os.name if platform is None else platform)=="posix" and re.fullmatch(r"[1-9][0-9]*",run_id or "") is not None and
         re.fullmatch(r"[1-9][0-9]*",run_attempt or "") is not None)
    runner=pathlib.Path(runner_temp);meta=runner.lstat()
    need(stat.S_ISDIR(meta.st_mode) and not runner.is_symlink() and
         str(meta.st_dev)==runner_device and str(meta.st_ino)==runner_inode and
         runner.resolve(strict=True)==runner.absolute())
    probe=runner/(PROBE_PREFIX+run_id+"-"+run_attempt);product=runner/"joint-control-plane"
    need(probe.parent==runner and probe!=product and probe not in product.parents and product not in probe.parents)
    staging=probe/"staging"
    return runner,probe,staging,{name:staging/name for name in ("protected-original","protected-moved","untrusted-replacement")}
def _probe_owned(path,uid,gid,mode,kind="dir"):
    p=pathlib.Path(path);m=p.lstat()
    need(not p.is_symlink() and m.st_uid==uid and m.st_gid==gid and stat.S_IMODE(m.st_mode)==mode and
         (stat.S_ISDIR(m.st_mode) if kind=="dir" else stat.S_ISREG(m.st_mode) and m.st_nlink==1))
    return m
def _probe_denied(call):
    try:call()
    except OSError as error:
        need(error.errno in (errno.EACCES,errno.EPERM,errno.EROFS));return
    raise ValueError("joint-ci-probe-denial-rejected")
def _probe_open_denied(path,flags):
    try:fd=os.open(path,flags,0o600)
    except OSError as error:
        need(error.errno in (errno.EACCES,errno.EPERM,errno.EROFS));return
    os.close(fd)
    if flags & os.O_CREAT:
        try:os.unlink(path)
        except OSError:pass
    raise ValueError("joint-ci-probe-denial-rejected")
def _probe_rename_denied(source,target):
    try:os.rename(source,target)
    except OSError as error:
        need(error.errno in (errno.EACCES,errno.EPERM,errno.EROFS));return
    os.rename(target,source)
    raise ValueError("joint-ci-probe-denial-rejected")
def _probe_write(path):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_BINARY",0),0o600)
    try:
        seen=0
        while seen<len(PROBE_RAW):
            count=os.write(fd,PROBE_RAW[seen:]);need(count>0);seen+=count
        os.fsync(fd)
    finally:os.close(fd)
def _probe_dir_fsync(path):
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
    try:os.fsync(fd)
    finally:os.close(fd)
def _probe_cleanup_tree(runner,probe,staging,children):
    if _probe_absent(probe):return
    probe_meta=probe.lstat();need(not probe.is_symlink() and stat.S_ISDIR(probe_meta.st_mode) and
        probe_meta.st_uid==0 and probe_meta.st_gid==0 and stat.S_IMODE(probe_meta.st_mode) in (0o700,0o711))
    need({p.name for p in probe.iterdir()}<= {"staging"})
    if not _probe_absent(staging):
        need(not staging.is_symlink() and staging.is_dir() and {p.name for p in staging.iterdir()}<=set(children))
        for child in (children["protected-original"],children["protected-moved"],children["untrusted-replacement"]):
            if _probe_absent(child):continue
            need(not child.is_symlink() and child.is_dir() and {p.name for p in child.iterdir()}<={C.BOOTSTRAP_FILE})
            record=child/C.BOOTSTRAP_FILE
            if not _probe_absent(record):
                record_meta=record.lstat();need(record_meta.st_uid in (0,C.UID) and record_meta.st_gid in (0,C.GID))
                _probe_owned(record,record_meta.st_uid,record_meta.st_gid,stat.S_IMODE(record_meta.st_mode),"file");os.unlink(record)
            os.rmdir(child)
        os.rmdir(staging)
    os.rmdir(probe);_probe_dir_fsync(runner)
def _probe_final_absence(runner_temp,run_id,run_attempt,runner_device,runner_inode,platform=None):
    runner,probe,_,_=_probe_paths(runner_temp,run_id,run_attempt,runner_device,runner_inode,platform)
    need(_probe_absent(probe));_probe_paths(runner,run_id,run_attempt,runner_device,runner_inode,platform)
def bootstrap_permission_probe(runner_temp,run_id,run_attempt,runner_device,runner_inode,mode,platform=None):
    need(mode in PROBE_MODES)
    runner,probe,staging,children=_probe_paths(runner_temp,run_id,run_attempt,runner_device,runner_inode,platform)
    original=children["protected-original"];moved=children["protected-moved"];replacement=children["untrusted-replacement"]
    root_mode=mode.startswith("root-");need((os.geteuid(),os.getegid())==((0,0) if root_mode else (C.UID,C.GID)))
    if mode=="root-setup":
        need(_probe_absent(probe));created=False
        try:
            os.mkdir(probe,0o711);created=True;os.chown(probe,0,0);os.chmod(probe,0o711)
            os.mkdir(staging,0o700);os.chown(staging,C.UID,C.GID);os.chmod(staging,0o700)
            os.mkdir(original,0o700);os.chown(original,0,0);os.chmod(original,0o700)
            _probe_write(original/C.BOOTSTRAP_FILE)
            _probe_owned(probe,0,0,0o711);_probe_owned(staging,C.UID,C.GID,0o700)
            _probe_owned(original,0,0,0o700);_probe_owned(original/C.BOOTSTRAP_FILE,0,0,0o600,"file")
            _probe_dir_fsync(original);_probe_dir_fsync(staging);_probe_dir_fsync(probe);_probe_dir_fsync(runner)
        except BaseException:
            cleanup_error=None;absence_error=None
            if created:
                try:_probe_cleanup_tree(runner,probe,staging,children)
                except BaseException as error:cleanup_error=error
                try:_probe_final_absence(runner_temp,run_id,run_attempt,runner_device,runner_inode,platform)
                except BaseException as error:absence_error=error
            if cleanup_error is not None or absence_error is not None:
                raise ValueError("joint-ci-probe-cleanup-rejected") from None
            raise
    elif mode=="uid-prepublish-denials":
        _probe_owned(staging,C.UID,C.GID,0o700);_probe_owned(original,0,0,0o700)
        _probe_denied(lambda:(original/C.BOOTSTRAP_FILE).read_bytes())
        _probe_open_denied(original/"forbidden",os.O_WRONLY|os.O_CREAT|os.O_EXCL)
        _probe_denied(lambda:os.unlink(original/C.BOOTSTRAP_FILE))
        _probe_rename_denied(original/C.BOOTSTRAP_FILE,original/"forbidden-move")
    elif mode=="root-finalize":
        _probe_owned(original,0,0,0o700);_probe_owned(original/C.BOOTSTRAP_FILE,0,0,0o600,"file")
        os.chmod(original/C.BOOTSTRAP_FILE,0o444);_probe_dir_fsync(original)
        os.chmod(original,0o555);_probe_dir_fsync(staging)
        _probe_owned(original,0,0,0o555);_probe_owned(original/C.BOOTSTRAP_FILE,0,0,0o444,"file")
        need((original/C.BOOTSTRAP_FILE).read_bytes()==PROBE_RAW)
        need(C.bootstrap_record_state(original/C.BOOTSTRAP_FILE,PROBE_SOURCE,directory_name="protected-original")==("ACCEPTED","PASS"))
    elif mode=="uid-final-read-and-rename":
        need((original/C.BOOTSTRAP_FILE).read_bytes()==PROBE_RAW)
        _probe_open_denied(original/C.BOOTSTRAP_FILE,os.O_WRONLY)
        _probe_denied(lambda:os.unlink(original/C.BOOTSTRAP_FILE))
        _probe_open_denied(original/"forbidden",os.O_WRONLY|os.O_CREAT|os.O_EXCL)
        need(_probe_absent(moved));os.rename(original,moved)
    elif mode=="uid-install-replacement":
        need(_probe_absent(original) and not _probe_absent(moved) and _probe_absent(replacement))
        os.mkdir(replacement,0o700);_probe_write(replacement/C.BOOTSTRAP_FILE)
        os.chmod(replacement/C.BOOTSTRAP_FILE,0o444);os.chmod(replacement,0o555);os.rename(replacement,original)
    elif mode=="root-reject-replacement":
        need(C.bootstrap_record_state(original/C.BOOTSTRAP_FILE,PROBE_SOURCE,directory_name="protected-original")==("INVALID","UNKNOWN"))
    elif mode=="root-cleanup":
        _probe_cleanup_tree(runner,probe,staging,children)
    else:
        _probe_final_absence(runner_temp,run_id,run_attempt,runner_device,runner_inode,platform)
def _stdout(raw):
    fd=sys.stdout.fileno();seen=0
    while seen<len(raw):
        count=os.write(fd,raw[seen:]);need(count>0);seen+=count
def main():
    p=argparse.ArgumentParser();p.add_argument("action",choices=("source","contract","build","isolation","units","model-diagnostic","progress","bootstrap-progress","bootstrap-lifecycle","bootstrap-permission-probe","bootstrap-permission-bridge","bridge-payload-digest","workflow-contract"));p.add_argument("--output");p.add_argument("--input");p.add_argument("--model-diagnostic");p.add_argument("--repo",default=".");p.add_argument("--workflow");p.add_argument("--source-contract");p.add_argument("--source-commit");p.add_argument("--base-commit");p.add_argument("--server-binary");p.add_argument("--outer-net-namespace");p.add_argument("--progress-root");p.add_argument("--bootstrap-record");p.add_argument("--phase");p.add_argument("--state");p.add_argument("--receipt",action="store_true");p.add_argument("--runner-temp");p.add_argument("--run-id");p.add_argument("--run-attempt");p.add_argument("--runner-device");p.add_argument("--runner-inode");p.add_argument("--probe-mode");p.add_argument("--bridge-mode",choices=("setup","cleanup","final-absence","progress-setup","progress-preflight","progress-transfer","progress-cleanup"));p.add_argument("--bridge-parent");p.add_argument("--bridge-parent-device");p.add_argument("--bridge-parent-inode");p.add_argument("--bridge-nonce");p.add_argument("--payload-digest");p.add_argument("--stage-statuses");p.add_argument("--primary-exit");p.add_argument("--final-exit");a=p.parse_args()
    if a.action=="workflow-contract":
        need(a.output is None and a.workflow and not a.receipt);workflow_contract(pathlib.Path(a.workflow).read_bytes());return
    if a.action=="bootstrap-permission-probe":
        need(a.output is None and a.runner_temp and a.run_id and a.run_attempt and a.runner_device and a.runner_inode and a.probe_mode and not a.receipt);bootstrap_permission_probe(a.runner_temp,a.run_id,a.run_attempt,a.runner_device,a.runner_inode,a.probe_mode);return
    if a.action=="bridge-payload-digest":
        need(a.source_contract and a.repo and not a.bridge_mode);_stdout((bridge_payload_digest(a.repo,a.source_contract)+"\n").encode());return
    if a.action=="bootstrap-permission-bridge":
        need(a.source_contract and a.repo and a.bridge_mode and a.bridge_parent and a.bridge_parent_device and a.bridge_parent_inode and a.run_id and a.run_attempt and a.bridge_nonce)
        arguments=(a.repo,a.source_contract,a.bridge_parent,a.bridge_parent_device,a.bridge_parent_inode,a.run_id,a.run_attempt,a.bridge_nonce)
        if a.bridge_mode=="setup":root,_=bridge_setup(*arguments);_stdout((str(root)+"\n").encode())
        elif a.bridge_mode=="cleanup":bridge_cleanup(*arguments)
        elif a.bridge_mode=="final-absence":bridge_final_absence(*arguments[2:])
        elif a.bridge_mode=="progress-setup":_stdout((str(bridge_progress_setup(*arguments))+"\n").encode())
        elif a.bridge_mode=="progress-preflight":bridge_progress_preflight(*arguments)
        elif a.bridge_mode=="progress-transfer":need(a.progress_root and a.source_commit);bridge_progress_transfer(*arguments,a.progress_root,a.source_commit)
        else:bridge_progress_cleanup(*arguments)
        return
    if a.action=="bootstrap-lifecycle":
        need(a.output and a.source_commit and a.run_id and a.run_attempt and a.bridge_nonce and a.payload_digest and a.stage_statuses and a.primary_exit is not None and a.final_exit is not None)
        statuses=tuple(int(value) for value in a.stage_statuses.split(","));C.record_bootstrap_lifecycle(a.output,a.source_commit,a.run_id,a.run_attempt,a.bridge_nonce,a.payload_digest,statuses,int(a.primary_exit),int(a.final_exit));return
    if a.action=="progress":
        need(a.output is None and a.progress_root and a.source_commit and a.phase and a.state and not a.bootstrap_record)
        if a.receipt and (a.phase,a.state)==("NAMESPACE_SETUP","ENTERED"):
            try:C.record_bootstrap_progress(a.progress_root,a.source_commit)
            except C.ProgressDiagnosticFailure as error:
                _stdout(C.canonical({"schema":C.BOOTSTRAP_FAILURE_RECEIPT_SCHEMA,"sourceCommit":a.source_commit,"operation":error.operation,"authority":"FIXED_SOURCE_CLASSIFICATION"}));raise SystemExit(70)
        else:C.record_progress(a.progress_root,a.source_commit,a.phase,a.state)
        if a.receipt:
            need((a.phase,a.state)==("NAMESPACE_SETUP","ENTERED"));_stdout(C.canonical({"schema":C.BOOTSTRAP_RECEIPT_SCHEMA,"sourceCommit":a.source_commit,"phase":a.phase,"state":a.state,"status":"PASS"}))
        return
    if a.action=="bootstrap-progress":
        need(a.output is None and a.progress_root and a.bootstrap_record and a.source_commit and not a.phase and not a.state and not a.receipt);bootstrap_progress(a.progress_root,a.bootstrap_record,a.source_commit);return
    if a.action=="model-diagnostic":
        need(a.input and a.output and a.source_commit and a.model_diagnostic is None and not a.receipt)
        emit(a.output,validate_model_diagnostic(pathlib.Path(a.input).read_bytes(),a.source_commit));return
    need(a.output and a.input is None and (a.action=="units" or a.model_diagnostic is None))
    try:value={"source":lambda:source(a.repo,a.source_commit),"contract":lambda:source_contract(a.repo,a.base_commit),"build":lambda:build(a.server_binary,a.source_commit),"isolation":lambda:isolation(a.outer_net_namespace),"units":lambda:units(a.model_diagnostic,a.source_commit)}[a.action]()
    except Exception as error:
        if a.action=="isolation" and a.progress_root and a.source_commit:
            try:C.record_failure_detail(a.progress_root,a.source_commit,error)
            except Exception:pass
        raise
    emit(a.output,value)
if __name__=="__main__":
    try:main()
    except Exception as error:print("JOINT_CI=REJECTED category="+C.exception_type(error),file=sys.stderr);raise SystemExit(1) from None
