#!/usr/bin/env python3
"""Fresh strict reader for one native first-Completion evidence directory."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time
import unicodedata

SCOPE = 'ACTUAL_FIRST_RECOVERY_COMPLETION_NOT_API_REBIND_ORDINARY_PUBLISH_SECOND_RECOVERY_OR_PRODUCTION'
TOP = 'TestLabRecoveryCompletionNativeFirstTransitionAndOwnedCleanup'
OLD_TOP = 'TestLabRecoveryNativeUnknownStartedReplayReopenAndOwnedCleanup'
TAGS = ('chengwang_mihomo_service','chengwang_mihomo_faults','chengwang_mihomo_recovery_native',
        'chengwang_mihomo_completion_native')
MODES = ('positive','not-committed','unknown','readback')
WALS = ('completion-s1.private.json','completion-s2.private.json',
        'completion-attempted.private.json','completion-reopened.private.json')
OLD_V5 = {
 'chengwang/deploy/mihomo-lifecycle-lab/native_recovery_contract.json':'74b29fb4c8c7bbc77439872ba10d56e9d8e1ba3e77d51c5c3b0cd1172510bb61',
 'chengwang/deploy/mihomo-lifecycle-lab/native_recovery_worker.py':'fa3f54df2c9443400a813dcca6d412753457734b715d4f8063b04f1390123146',
 'chengwang/deploy/mihomo-lifecycle-lab/check_native_recovery.py':'8f2ee93e3e6956ec39e37042628fc7e5c8d4b0816d25f150cbe19fdeaeed440d',
 'chengwang/internal/mihomodeploy/lab_native_recovery_linux.go':'d211a41b9f6f22065a1315968d893c7a9ac2ffa0fc192693965d9543c42734e4',
 'chengwang/internal/mihomodeploy/lab_native_recovery_linux_test.go':'04c7eaa88ac7b5172042982e7ad376f1332ed7830123dc43688daf5274650791'}
EXPECTED = {'positive':(1,1,1,0,True,False,True),
            'not-committed':(1,0,0,0,False,True,False),
            'unknown':(1,1,0,0,True,True,False),
            'readback':(1,1,1,1,True,True,False)}
FMT = tuple('internal/mihomodeploy/' + name for name in (
    'lab_bootstrap.go','lab_kernel_linux.go','lab_quiescence_linux.go',
    'lab_recovery_start_linux.go','lab_syntax_linux.go',
    'lab_native_recovery_observer_default.go','lab_native_recovery_observer_linux.go',
    'lab_native_recovery_linux.go','lab_native_recovery_linux_test.go',
    'lifecycle_recovery_checkpoint.go','lifecycle_recovery_completion.go','lifecycle_recovery_completion_test.go',
    'lifecycle_current_epoch.go','lab_current_epoch_runtime.go','lab_native_completion_linux_test.go')) + (
    'internal/adapter/mihomo/lab_reload_response_schedule_linux.go',
    'internal/adapter/mihomo/lab_reload_response_schedule_linux_test.go',
    'internal/mihomodeploy/lab_service.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_default.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_linux.go',
    'internal/mihomodeploy/lab_continuous_recovery_fault_linux_test.go',
    'internal/serverruntime/runtime.go',
    'internal/serverruntime/mihomo_continuous_recovery_e2e_linux_test.go',
    'internal/serverruntime/mihomo_continuous_recovery_hook_default.go',
    'internal/serverruntime/mihomo_continuous_recovery_hook_linux.go')
MANIFEST_REL = 'chengwang/deploy/mihomo-lifecycle-lab/native_completion_source_manifest.json'
DELIVERY_PATHS = (
    '.github/workflows/chengwang-mihomo-native-completion.yml',
    'chengwang/deploy/mihomo-capacity-profile/check_profile.py',
    'chengwang/deploy/mihomo-lifecycle-lab/check_native_completion.py',
    'chengwang/deploy/mihomo-lifecycle-lab/native_completion_contract.json',
    MANIFEST_REL,
    'chengwang/deploy/mihomo-lifecycle-lab/native_completion_worker.py',
    'chengwang/deploy/mihomo-lifecycle-lab/run_native_completion.sh',
    'chengwang/deploy/mihomo-lifecycle-lab/test_native_completion_reader_model.py',
    'chengwang/internal/mihomodeploy/lab_native_completion_linux_test.go')
COMMIT = re.compile(r'[0-9a-f]{40}')
OID = re.compile(r'[0-9a-f]{40}')
MAX_TRACKED_BYTES = 64 << 20
UINT64_MAX = (1 << 64) - 1


def need(value):
    if not value:
        raise ValueError('native first-Completion evidence rejected')


def integer(value, low=0, high=UINT64_MAX):
    need(type(value) is int and low <= value <= high)
    return value


def boolean(value, expected=None):
    need(type(value) is bool and (expected is None or value is expected))
    return value


def exact_same(actual, expected):
    need(type(actual) is type(expected))
    if type(expected) is dict:
        need(set(actual) == set(expected))
        for key in expected:
            exact_same(actual[key],expected[key])
    elif type(expected) in (list,tuple):
        need(len(actual) == len(expected))
        for left,right in zip(actual,expected):
            exact_same(left,right)
    else:
        need(actual == expected)
    return actual


def digest(value, nullable=False):
    if nullable and value is None:
        return value
    need(type(value) is str and re.fullmatch(r'[0-9a-f]{64}',value) is not None and value != '0'*64)
    return value


def timestamp(value):
    need(type(value) is str)
    match = re.fullmatch(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z',value)
    need(match is not None)
    year,month,day,hour,minute,second = map(int,match.groups()[:6])
    import datetime
    date = datetime.date(year,month,day)
    need(hour < 24 and minute < 60 and second < 60)
    return ((date.toordinal()*24+hour)*3600+minute*60+second)*10**9 + int((match.group(7) or '').ljust(9,'0'))


def namespace(value):
    need(type(value) is dict and set(value) == {'networkNamespace','mountNamespace','pidNamespace'})
    for key,prefix in (('networkNamespace','net'),('mountNamespace','mnt'),('pidNamespace','pid')):
        need(type(value[key]) is str and re.fullmatch(prefix+r':\[[1-9][0-9]{0,19}\]',value[key]) is not None)
    return value


def raw_file(path, limit, empty=False):
    info = path.lstat()
    allowed_modes = (0o600,0o644,0o666) if os.name == 'nt' else (0o600,0o644)
    need(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) in allowed_modes and 0 <= info.st_size <= limit and (empty or info.st_size > 0))
    raw = path.read_bytes(); need(len(raw) == info.st_size)
    return raw


def write_new_fsync(path,raw):
    path = Path(path).absolute()
    need(path.parent.exists() and not path.exists())
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd,view); need(count > 0); view = view[count:]
        os.fsync(fd)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and
             (os.name == 'nt' or (info.st_nlink == 1 and info.st_size == len(raw))))
    finally:
        os.close(fd)
    if os.name == 'nt':
        observed = None
        for _ in range(50):
            try:
                observed = source_file(path,max(1,len(raw)))
                break
            except (OSError,ValueError):
                time.sleep(0.01)
        need(observed == raw)
    else:
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
             info.st_nlink == 1 and info.st_size == len(raw))
    if os.name == 'posix':
        directory = os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def source_file(path, limit=2 << 20):
    path = Path(path).absolute()
    for item in (*reversed(path.parents),path):
        info = item.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0) & 1024)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit)
    raw = path.read_bytes(); after = path.lstat()
    sig = lambda value: (value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns)
    need(sig(before) == sig(after) and len(raw) == before.st_size)
    return raw


def decode(raw):
    value = json.loads(raw)
    need(json.dumps(value,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('ascii') == raw)
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('ascii')


def set_digest(schema, rows):
    return sha(canonical({'schema':schema,'entries':rows}))


def source_policy(repo):
    raw = source_file(Path(repo)/MANIFEST_REL,64 << 10)
    value = json.loads(raw)
    need(canonical(value) + b'\n' == raw and value == {
        'allowedGitModes':['100644','100755'],
        'bindingSchema':'chengwang.mihomo-native-completion-source-binding/v2',
        'deliveryPaths':list(DELIVERY_PATHS),
        'generatedManifestIsPrivate':True,
        'generatedManifestSchema':'chengwang.mihomo-native-completion-fulltracked-manifest/v2',
        'maxTrackedFileBytes':MAX_TRACKED_BYTES,
        'oldTwentyOneSourceManifestAccepted':False,
        'rejectCaseFoldCollisions':True,
        'rejectDirtyIndexOrWorktree':True,
        'rejectHardlinks':True,
        'rejectSymlinks':True,
        'schema':'chengwang.mihomo-native-completion-source-policy/v2',
        'trackedSet':'ALL_GIT_HEAD_BLOBS'})
    return raw


def binding_for(manifest_raw,manifest):
    return {'schema':'chengwang.mihomo-native-completion-source-binding/v2',
            'sourceCommit':manifest['sourceCommit'],'sourceTree':manifest['sourceTree'],
            'indexTree':manifest['indexTree'],'sourceManifestSHA256':sha(manifest_raw),
            'sourceSetSHA256':manifest['sourceSetSHA256'],'deliverySetSHA256':manifest['deliverySetSHA256'],
            'policySHA256':manifest['policySHA256'],'sourceCount':manifest['entryCount'],
            'deliveryCount':len(manifest['deliveries'])}


def source_binding(repo, supplied_commit):
    repo = Path(repo).resolve(strict=True)
    need(type(supplied_commit) is str and COMMIT.fullmatch(supplied_commit) is not None)
    def git(*args, limit=4 << 20):
        result = subprocess.run(['git','-C',str(repo),*args],stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        need(result.returncode == 0 and len(result.stdout) <= limit and len(result.stderr) <= 1 << 20)
        return result.stdout
    actual = git('rev-parse','HEAD').strip().decode('ascii')
    tree_oid = git('rev-parse','HEAD^{tree}').strip().decode('ascii')
    index_tree = git('write-tree').strip().decode('ascii')
    need(actual == supplied_commit and OID.fullmatch(tree_oid) is not None and index_tree == tree_oid and
         Path(os.fsdecode(git('rev-parse','--show-toplevel').strip())).resolve() == repo and
         git('status','--porcelain=v1','--untracked-files=all') == b'')
    tree = {}
    folded = set()
    for row in git('ls-tree','-r','-z','--full-tree',actual).split(b'\0'):
        if not row: continue
        meta, encoded = row.split(b'\t',1); mode, kind, oid = meta.split(); path = encoded.decode('utf-8')
        key = unicodedata.normalize('NFC',path).casefold()
        need(path not in tree and key not in folded and not path.startswith('/') and '\\' not in path and
             '..' not in Path(path).parts and mode in (b'100644',b'100755') and kind == b'blob' and
             OID.fullmatch(oid.decode('ascii')) is not None)
        folded.add(key)
        tree[path] = (mode,oid.decode('ascii'))
    need(tree and set(DELIVERY_PATHS).issubset(tree))
    index = {}
    for row in git('ls-files','--stage','-z').split(b'\0'):
        if not row: continue
        meta, encoded = row.split(b'\t',1); mode, oid, stage = meta.split(); path = encoded.decode('utf-8')
        need(path in tree and path not in index and mode in (b'100644',b'100755') and stage == b'0')
        index[path] = (mode,oid.decode('ascii'))
    need(index == tree)
    raws = {}
    for path in tree:
        raw = source_file(repo/path,MAX_TRACKED_BYTES)
        need(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest() == tree[path][1])
        if os.name == 'posix': need(bool((repo/path).lstat().st_mode & 0o111) == (tree[path][0] == b'100755'))
        raws[path] = raw
    proc = subprocess.Popen(['git','-C',str(repo),'cat-file','--batch'],stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    need(proc.stdin is not None and proc.stdout is not None and proc.stderr is not None)
    writer_error = []
    def write_queries():
        try:
            for path in tree:
                proc.stdin.write(tree[path][1].encode('ascii')+b'\n')
            proc.stdin.close()
        except Exception as exc:
            writer_error.append(exc)
    writer = threading.Thread(target=write_queries,name='completion-git-cat-file-writer',daemon=True)
    writer.start()
    for path in tree:
        header = proc.stdout.readline().rstrip(b'\n').split()
        need(len(header) == 3 and header[0].decode('ascii') == tree[path][1] and header[1] == b'blob')
        size = int(header[2]); need(size == len(raws[path]) and 0 < size <= MAX_TRACKED_BYTES)
        need(proc.stdout.read(size) == raws[path] and proc.stdout.read(1) == b'\n')
    writer.join(timeout=30)
    stderr = proc.stderr.read(); tail = proc.stdout.read(1); code = proc.wait(timeout=30)
    proc.stdout.close(); proc.stderr.close()
    need(not writer.is_alive() and not writer_error and code == 0 and stderr == b'' and tail == b'')
    entries = [dict(path=path,mode=tree[path][0].decode('ascii'),gitBlob=tree[path][1],
                    bytes=len(raws[path]),sha256=sha(raws[path])) for path in tree]
    by_path = {row['path']:row for row in entries}
    deliveries = [by_path[path] for path in DELIVERY_PATHS]
    policy_raw = source_policy(repo)
    manifest = {'schema':'chengwang.mihomo-native-completion-fulltracked-manifest/v2',
                'sourceCommit':actual,'sourceTree':tree_oid,'indexTree':index_tree,
                'policySHA256':sha(policy_raw),'entryCount':len(entries),'entries':entries,
                'deliveries':deliveries,
                'sourceSetSHA256':set_digest('chengwang.mihomo-native-completion-fulltracked-set/v2',entries),
                'deliverySetSHA256':set_digest('chengwang.mihomo-native-completion-delivery-set/v2',deliveries)}
    raw = canonical(manifest) + b'\n'
    return binding_for(raw,manifest),raw


def verify_private_manifest(raw,binding):
    manifest = json.loads(raw)
    need(canonical(manifest) + b'\n' == raw and type(manifest) is dict and
         set(manifest) == {'schema','sourceCommit','sourceTree','indexTree','policySHA256','entryCount','entries','deliveries','sourceSetSHA256','deliverySetSHA256'} and
         manifest['schema'] == 'chengwang.mihomo-native-completion-fulltracked-manifest/v2')
    need(type(manifest['sourceCommit']) is str and COMMIT.fullmatch(manifest['sourceCommit']) is not None and
         type(manifest['sourceTree']) is str and OID.fullmatch(manifest['sourceTree']) is not None and
         type(manifest['indexTree']) is str and manifest['indexTree'] == manifest['sourceTree'])
    digest(manifest['policySHA256']); digest(manifest['sourceSetSHA256']); digest(manifest['deliverySetSHA256'])
    exact_same(binding_for(raw,manifest),binding)
    entries = manifest['entries']; deliveries = manifest['deliveries']
    integer(manifest['entryCount'],len(entries),len(entries)); need(len(deliveries) == len(DELIVERY_PATHS))
    folded = set(); paths = set(); by_path = {}
    for row in entries:
        need(type(row) is dict and set(row) == {'path','mode','gitBlob','bytes','sha256'} and
             row['mode'] in ('100644','100755') and OID.fullmatch(row['gitBlob']) is not None and
             type(row['bytes']) is int and 0 < row['bytes'] <= MAX_TRACKED_BYTES and
             re.fullmatch(r'[0-9a-f]{64}',row['sha256']) is not None)
        key = unicodedata.normalize('NFC',row['path']).casefold()
        need(row['path'] not in paths and key not in folded)
        paths.add(row['path']); folded.add(key); by_path[row['path']] = row
    exact_same(deliveries,[by_path.get(path) for path in DELIVERY_PATHS])
    need(set_digest('chengwang.mihomo-native-completion-fulltracked-set/v2',entries) == manifest['sourceSetSHA256'] and
         set_digest('chengwang.mihomo-native-completion-delivery-set/v2',deliveries) == manifest['deliverySetSHA256'])
    return manifest


def source_check(repo):
    contract = json.loads(source_file(repo/'chengwang/deploy/mihomo-lifecycle-lab/native_completion_contract.json',64 << 10))
    need(contract['schema'] == 'chengwang.mihomo-native-completion-contract/v3' and contract['scope'] == SCOPE and
         tuple(contract['tags']) == TAGS and contract['topTests'] == [TOP] and
         tuple(contract['modes']) == MODES)
    integer(contract['goTimeoutSeconds'],105,105); integer(contract['outerGoTimeoutSeconds'],120,120)
    boolean(contract['oldV5ContractChanged'],False); boolean(contract['fullPrivateWALIndependentlyProven'],False)
    boolean(contract['production'],False); boolean(contract['oldS2WorkflowChanged'],False); boolean(contract['oldS2BudgetsChanged'],False)
    exact_same(contract['sourceManifest'],{'policyName':'native_completion_source_manifest.json',
             'policySchema':'chengwang.mihomo-native-completion-source-policy/v2',
             'generatedSchema':'chengwang.mihomo-native-completion-fulltracked-manifest/v2',
             'bindingSchema':'chengwang.mihomo-native-completion-source-binding/v2',
             'trackedSet':'ALL_GIT_HEAD_BLOBS','deliveryCount':len(DELIVERY_PATHS),
             'gitCommitRequired':True,'gitTreeRequired':True,'gitIndexMustMatchCommitTree':True,
             'workingBytesMustMatchGitBlobs':True,'oldTwentyOneSourceManifestAccepted':False})
    exact_same(contract['completePackageTestSources'],{'historicalCount':84,'previousCount':88,'candidateCount':91,
             'continuousRecoveryTaggedSourceCount':3,'ordinaryMandatoryTopLevelCount':688,
             'completionHarnessExcludedFromOrdinaryMandatoryNames':True,
             'continuousRecoveryTaggedSourcesExcludedFromOrdinaryMandatoryNames':True})
    exact_same(contract['coldReopen'],{
        'coldReopenMatchedDiskMeaning':'POST_OPEN_DISK_EQUALS_REOPENED_STORE_RAW',
        'positive':'COMPLETED_UNCHANGED','not-committed':'START_ARMED_TO_RECOVERY_UNKNOWN',
        'unknown':'COMPLETED_UNCHANGED','readback':'COMPLETED_UNCHANGED'})
    integer(contract['maxTrackedFileBytes'],MAX_TRACKED_BYTES,MAX_TRACKED_BYTES)
    need(contract['commandReceiptSchema'] == 'chengwang.mihomo-native-completion-command-receipt/v3')
    go = source_file(repo/'chengwang/internal/mihomodeploy/lab_native_completion_linux_test.go',256 << 10).decode()
    need(go.startswith('//go:build linux && '+ ' && '.join(TAGS) +'\n') and
         len(re.findall(r'^func Test\w+\(t \*testing\.T\)',go,re.M)) == 1 and
         ('func '+TOP+'(t *testing.T)') in go and OLD_TOP not in go and
         'collector.completionCap(completionCtx, headers["initiator"])' in go and
         'runner.store.recordRecoveryCompletion(runner.owner, cap, attemptedAt)' in go and
         'service.core.runtime.adoptCurrentEpoch(handoff, runner.store)' in go and
         'handoff.consumeCurrent(runner.store.core)' in go and
         'runner.holdsClose && service.core.busy && !service.core.closed && !service.core.closing' in go and
         'CloseExclusionHeld: closeExclusionHeld' in go and
         'completionDisk.armed = true' in go and
         'runner.store.recordRecoveryVerification(runner.owner, recordCap' in go and
         'labNativeCompletionReopen(diskRaw, mode)' in go and
         'START_ARMED_TO_RECOVERY_UNKNOWN' in go and 'COMPLETED_UNCHANGED' in go and
         'projected.core.Recovery.Failure = &failure' in go and
         'processLabRecoveryCompletionIssuer.issued[' in go and
         not re.search(r'processLabRecoveryCompletionIssuer\.issued\[[^\]]+\]\s*=',go) and
         not re.search(r'\.ready\s*=\s*true',go) and
         'lifecycleRecoveryCompletionPreimage(' in go and
         'lifecycleRecoveryVerificationPreimage(' in go)
    worker = source_file(repo/'chengwang/deploy/mihomo-lifecycle-lab/native_completion_worker.py',256 << 10).decode()
    need("'-run=^'+TOP+'$'" in worker and "'-timeout=105s'" in worker and
         'reconstruct_s1(s2)' in worker and 'reconstruct_s2(attempted)' in worker)
    profile = source_file(repo/'chengwang/deploy/mihomo-capacity-profile/check_profile.py',512 << 10).decode()
    need("len(suite_test_sources)==91" in profile and "len(previous88)==88" in profile and "len(previous84)==84" in profile and
         "len(names)==688" in profile and "completionHarnessExcludedFromOrdinaryMandatoryNames':True" in profile and
         "continuousRecoveryTaggedTestsExcludedFromOrdinaryMandatoryNames':True" in profile)
    for name, digest in OLD_V5.items():
        need(sha(source_file(repo/name)) == digest)
    return contract


def go_terminal(raw):
    rows = [json.loads(line) for line in raw.splitlines() if line]
    need(rows and all(type(row) is dict for row in rows))
    relevant = [row for row in rows if row.get('Test') == TOP]
    need(sum(row.get('Action') == 'run' for row in relevant) == 1 and
         sum(row.get('Action') == 'pass' for row in relevant) == 1 and
         not any(row.get('Action') in ('fail','skip') for row in rows) and
         not any(row.get('Test') == OLD_TOP for row in rows))
    packages = [row for row in rows if 'Test' not in row and row.get('Action') == 'pass']
    need(len(packages) == 1 and packages[0].get('Package') == 'chengwang/internal/mihomodeploy' and
         all(row.get('Test',TOP).split('/')[0] == TOP for row in rows))


def command_receipts(raw, commit, mode, binding):
    rows = [decode(line) for line in raw.splitlines() if line]
    need(len(rows) == 4)
    classes = ('SANDBOX','GO_VERSION','GOFMT','GO_TEST')
    namespaces = None
    timeouts = (30,15,30,120)
    for number, row in enumerate(rows,1):
        need(set(row) == {'schema','sequence','sourceCommit','commandClass','argv','cwd','timeoutSeconds','exitCode','observed','namespace','sourceBinding'} and
             row['schema'] == 'chengwang.mihomo-native-completion-command-receipt/v3' and row['sourceCommit'] == commit and
             row['commandClass'] == classes[number-1] and type(row['argv']) is list and
             all(type(value) is str for value in row['argv']) and
             row['cwd'] == '/tmp/mihomo-apply-source')
        integer(row['sequence'],number,number); integer(row['exitCode'],0,0)
        integer(row['timeoutSeconds'],timeouts[number-1],timeouts[number-1]); boolean(row['observed'],True)
        exact_same(row['sourceBinding'],binding); current = namespace(row['namespace'])
        if namespaces is None: namespaces = current
        exact_same(current,namespaces)
    test = rows[-1]['argv']
    sandbox = rows[0]['argv']
    need(sandbox[-11:] == ['--sandbox',commit,binding['sourceTree'],binding['indexTree'],
                           binding['sourceManifestSHA256'],binding['sourceSetSHA256'],binding['deliverySetSHA256'],
                           binding['policySHA256'],str(binding['sourceCount']),str(binding['deliveryCount']),mode])
    need('-tags='+','.join(TAGS) in test and '-run=^'+TOP+'$' in test and '-timeout=105s' in test and
         '-chengwang-native-completion-mode='+mode in test)
    return namespaces


def native_calls(report):
    calls = report['nativeCalls']; need(type(calls) is list and 0 < len(calls) <= 256)
    previous = None
    for sequence,row in enumerate(calls,1):
        need(type(row) is dict and set(row) == {'sequence','kind','core','at'} and type(row['kind']) is str and row['kind'])
        integer(row['sequence'],sequence,sequence); integer(row['core'],0,UINT64_MAX)
        observed = timestamp(row['at']); need(previous is None or observed >= previous); previous = observed
    old, new = report['oldCore'], report['newCore']
    integer(old,1,UINT64_MAX); integer(new,1,UINT64_MAX); need(old != new)
    prefix_before_old_wait = [
        ('KERNEL_OS_START_ATTEMPT',old),('KERNEL_OS_START_RETURN',old),('KERNEL_OS_WAIT_ENTER',old),
        ('SYNTAX_OS_START_ATTEMPT',0),('SYNTAX_OS_START_RETURN',0),
        ('RECOVERY_STOP_DISPATCH',old),('OWNED_STOP_HELPER_ENTER',old)]
    old_wait_variants = [
        [('KERNEL_OS_WAIT_RETURN',old),('KERNEL_OS_TERM_ATTEMPT',old),('KERNEL_OS_TERM_RETURN',old)],
        [('KERNEL_OS_TERM_ATTEMPT',old),('KERNEL_OS_WAIT_RETURN',old),('KERNEL_OS_TERM_RETURN',old)],
        [('KERNEL_OS_TERM_ATTEMPT',old),('KERNEL_OS_TERM_RETURN',old),('KERNEL_OS_WAIT_RETURN',old)]]
    prefix_after_old_wait = [('RECOVERY_START_DISPATCH',0),('KERNEL_OS_START_ATTEMPT',new),
                             ('KERNEL_OS_START_RETURN',new),('KERNEL_OS_WAIT_ENTER',new)]
    observed = [(row['kind'],row['core']) for row in calls]
    exact_same(observed[:len(prefix_before_old_wait)],prefix_before_old_wait)
    need(observed[len(prefix_before_old_wait):10] in old_wait_variants)
    exact_same(observed[10:14],prefix_after_old_wait)
    tail = observed[14:]
    need(len(tail) >= 3 and tail[-1] == ('OWNED_STOP_HELPER_ENTER',old) and
         all(core == new for _,core in tail[:-1]))
    kinds = [kind for kind,_ in tail[:-1]]
    allowed = {'OWNED_STOP_HELPER_ENTER','KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_TERM_RETURN',
               'KERNEL_OS_KILL_ATTEMPT','KERNEL_OS_KILL_RETURN','KERNEL_OS_WAIT_RETURN'}
    need(set(kinds) <= allowed and kinds.count('OWNED_STOP_HELPER_ENTER') == 1 and
         kinds.count('KERNEL_OS_WAIT_RETURN') == 1)
    term_attempts,term_returns = kinds.count('KERNEL_OS_TERM_ATTEMPT'),kinds.count('KERNEL_OS_TERM_RETURN')
    kill_attempts,kill_returns = kinds.count('KERNEL_OS_KILL_ATTEMPT'),kinds.count('KERNEL_OS_KILL_RETURN')
    need(term_attempts == term_returns and term_attempts in (0,1) and
         kill_attempts == kill_returns and kill_attempts in (0,1) and
         (kill_attempts == 0 or term_attempts == 1))
    if term_attempts:
        need(kinds.index('OWNED_STOP_HELPER_ENTER') < kinds.index('KERNEL_OS_TERM_ATTEMPT') <
             kinds.index('KERNEL_OS_TERM_RETURN'))
    if kill_attempts:
        need(kinds.index('KERNEL_OS_TERM_RETURN') < kinds.index('KERNEL_OS_KILL_ATTEMPT') <
             kinds.index('KERNEL_OS_KILL_RETURN'))
    return calls


def report_check(value, commit, mode, binding):
    report_binding = value.get('sourceBinding')
    need(type(report_binding) is dict and set(report_binding) == set(binding) | {'privateReportSHA256'} and
         re.fullmatch(r'[0-9a-f]{64}',report_binding['privateReportSHA256']) is not None)
    exact_same({key:report_binding[key] for key in binding},binding); digest(report_binding['privateReportSHA256'])
    need(value['schema'] == 'chengwang.mihomo-native-completion-experiment/v1' and value['scope'] == SCOPE and
         value['sourceCommit'] == commit and value['mode'] == mode and value['outcome'] == 'PASS' and value['failureCode'] == 'NONE')
    for key in ('countersBounded','runtimeClosed','diskOwnerClosed'):
        boolean(value[key],True)
    s1,s2,reopened = value['s1'],value['s2'],value['reopened']
    checkpoint_keys = {'stage','controlSHA256','recordSHA256','revision','phase'}
    need(type(s1) is dict and type(s2) is dict and type(reopened) is dict and
         set(s1) == set(s2) == set(reopened) == checkpoint_keys and
         s1['stage'] == 'completion-s1.private.json' and s2['stage'] == 'completion-s2.private.json' and
         reopened['stage'] == 'completion-reopened' and s1['phase'] == s2['phase'] == 'START_ARMED')
    for checkpoint in (s1,s2,reopened):
        digest(checkpoint['controlSHA256']); digest(checkpoint['recordSHA256'])
    revision = integer(s1['revision'],0,UINT64_MAX-1); integer(s2['revision'],revision+1,revision+1)
    readback = value['controlPlane']['readback']
    integer(readback['requestsObserved'],8,8); integer(readback['sampleCount'],2,2)
    need(readback['conclusion'] == 'TARGET_PROJECTION_MATCHED')
    boolean(readback['dataplaneProven'],False); boolean(readback['production'],False)
    publication = value['completion']; expected = EXPECTED[mode]
    actual = tuple(publication[key] for key in ('replaceAttempts','forwardedWrites','postWriteReads','injectedReads','underlyingCommitted','recordReturnedError','runtimeAdopted'))
    for observed,want in zip(actual,expected):
        if type(want) is bool: boolean(observed,want)
        else: integer(observed,want,want)
    need(publication['schema'] == 'chengwang.mihomo-native-completion-publication/v1' and
         publication['scope'] == SCOPE and publication['mode'] == mode)
    for key in ('capSpent','capReplayRejected','noCompletionNativeCalls','coldReopenMatchedDisk','closeExclusionHeld'):
        boolean(publication[key],True)
    for key in ('serviceRebindProven','apiRouteProven','ordinaryPublishProven','secondRecoveryProven','production'):
        boolean(publication[key],False)
    attempted,returned = timestamp(publication['attemptedAt']),timestamp(publication['returnedAt'])
    need(returned >= attempted)
    for key in ('sourceRevision','memoryRevision','diskRevision'):
        integer(publication[key],0,UINT64_MAX)
    for key in ('sourceRecordSHA256','sourceControlSHA256','memoryRecordSHA256','memoryControlSHA256',
                'diskRecordSHA256','diskControlSHA256','s1PreimageSHA256','previousHeadSHA256','nativePrefixSHA256'):
        digest(publication[key])
    digest(publication['s2PreimageSHA256'],nullable=True); digest(publication['newHeadSHA256'],nullable=True)
    calls = native_calls(value)
    prefix_count = integer(publication['nativePrefixCount'],14,14)
    prefix = calls[:prefix_count]
    need(sha(json.dumps(prefix,ensure_ascii=True,separators=(',',':')).encode('ascii')) == publication['nativePrefixSHA256'] and
         timestamp(prefix[-1]['at']) <= attempted and
         all(timestamp(row['at']) >= returned for row in calls[prefix_count:]))
    exact_same(value['closedPorts'],[28411,28412,28413,28414,28415])
    need(type(value['cleanupProbes']) is list and len(value['cleanupProbes']) == 5)
    for row,port in zip(value['cleanupProbes'],value['closedPorts']):
        need(type(row) is dict and set(row) == {'port','attempted','result'})
        integer(row['port'],port,port); boolean(row['attempted'],True); need(row['result'] == 'CONNECTION_REFUSED')
    need(
         [row['role'] for row in value['fixtureCleanup']] == ['origin','A','B'] and
         all(row['shutdownReturned'] is True and row['serveReturned'] is True and row['errorClass'] == 'NONE' for row in value['fixtureCleanup']))
    for row in value['fixtureCleanup']:
        need(type(row) is dict and set(row) == {'role','shutdownReturned','serveReturned','forcedConnectionsClosed','errorClass'})
        boolean(row['shutdownReturned'],True); boolean(row['serveReturned'],True)
        integer(row['forcedConnectionsClosed'],0,0)
    source_point = (s2['revision'],s2['recordSHA256'],s2['controlSHA256'])
    publication_source = (publication['sourceRevision'],publication['sourceRecordSHA256'],publication['sourceControlSHA256'])
    memory_point = (publication['memoryRevision'],publication['memoryRecordSHA256'],publication['memoryControlSHA256'])
    disk_point = (publication['diskRevision'],publication['diskRecordSHA256'],publication['diskControlSHA256'])
    exact_same(publication_source,source_point)
    need(publication['s1PreimageSHA256'] == s1['controlSHA256'])
    if mode == 'positive':
        boolean(publication['handoffReturned'],True); boolean(publication['handoffReplayRejected'],True)
        boolean(publication['storePoisoned'],False); need(publication['diskPhase'] == 'COMPLETED')
        integer(publication['retiredEpochCount'],1,1); integer(publication['recoveryHistoryCount'],1,1)
        need(publication['newHeadSHA256'] != publication['previousHeadSHA256'] and
             publication['s2PreimageSHA256'] == s2['controlSHA256'] and
             publication['reopenTransition'] == 'COMPLETED_UNCHANGED')
        exact_same(memory_point,disk_point)
        integer(disk_point[0],source_point[0]+1,source_point[0]+1)
        need(disk_point[1] != source_point[1] and disk_point[2] != source_point[2])
    elif mode == 'not-committed':
        boolean(publication['handoffReturned'],False); boolean(publication['handoffReplayRejected'],False)
        boolean(publication['storePoisoned'],True); need(publication['diskPhase'] == 'START_ARMED' and
             publication['s2PreimageSHA256'] is None and publication['newHeadSHA256'] is None)
        integer(publication['retiredEpochCount'],0,0); integer(publication['recoveryHistoryCount'],0,0)
        exact_same(memory_point,source_point); exact_same(disk_point,source_point)
        need(reopened['phase'] == 'RECOVERY_UNKNOWN' and
             integer(reopened['revision'],source_point[0]+1,source_point[0]+1) == source_point[0]+1 and
             reopened['recordSHA256'] != source_point[1] and reopened['controlSHA256'] != source_point[2] and
             publication['reopenTransition'] == 'START_ARMED_TO_RECOVERY_UNKNOWN')
    else:
        boolean(publication['handoffReturned'],False); boolean(publication['handoffReplayRejected'],False)
        boolean(publication['storePoisoned'],True); need(publication['diskPhase'] == 'COMPLETED')
        integer(publication['retiredEpochCount'],1,1); integer(publication['recoveryHistoryCount'],1,1)
        exact_same(memory_point,source_point)
        integer(disk_point[0],source_point[0]+1,source_point[0]+1)
        need(disk_point[1] != source_point[1] and disk_point[2] != source_point[2] and
             publication['newHeadSHA256'] != publication['previousHeadSHA256'] and
             publication['s2PreimageSHA256'] == s2['controlSHA256'] and
             publication['reopenTransition'] == 'COMPLETED_UNCHANGED')
    if mode != 'not-committed':
        exact_same((reopened['revision'],reopened['recordSHA256'],reopened['controlSHA256']),disk_point)
        need(reopened['phase'] == publication['diskPhase'])
    return publication, report_binding


def wal_evidence(out, report, publication, commit, mode, report_binding):
    index = decode(raw_file(out/'completion-wal-index.json',64 << 10))
    receipts = decode(raw_file(out/'completion-fsync-receipts.json',64 << 10))
    need(index['schema'] == 'chengwang.mihomo-native-completion-wal-index/v1' and index['scope'] == SCOPE and
         index['sourceCommit'] == commit and index['mode'] == mode and
         receipts['schema'] == 'chengwang.mihomo-native-completion-fsync-receipts/v1' and receipts['scope'] == SCOPE and
         receipts['sourceCommit'] == commit and receipts['mode'] == mode)
    boolean(index['fullPrivateWALIndependentlyProven'],False); boolean(index['production'],False)
    boolean(receipts['directoryFsyncObserved'],True); boolean(receipts['production'],False)
    exact_same(index['sourceBinding'],report_binding); exact_same(receipts['sourceBinding'],report_binding)
    receipt_names = ('completion-source.private.json','completion-report.private.json',*WALS,
                     'kernel.stdout','kernel.stderr','new-kernel.stdout','new-kernel.stderr')
    need([row['name'] for row in index['entries']] == list(WALS) and
         [row['name'] for row in receipts['entries']] == list(receipt_names))
    checkpoints = (report['s1'],report['s2'],
                   {'revision':publication['diskRevision'],'recordSHA256':publication['diskRecordSHA256'],
                    'controlSHA256':publication['diskControlSHA256'],'phase':publication['diskPhase']},
                   report['reopened'])
    for row,checkpoint in zip(index['entries'],checkpoints):
        need(type(row) is dict and set(row) == {'name','present','bytes','sha256','revision','recordSHA256','phase'})
        boolean(row['present'],True); integer(row['bytes'],1,2 << 20)
        integer(row['revision'],0,UINT64_MAX); digest(row['sha256']); digest(row['recordSHA256'])
        exact_same((row['revision'],row['recordSHA256'],row['sha256'],row['phase']),
                   (checkpoint['revision'],checkpoint['recordSHA256'],checkpoint['controlSHA256'],checkpoint['phase']))
    for row in receipts['entries']:
        need(type(row) is dict and set(row) == {'name','bytes','sha256','mode','uid','gid','fsyncObserved'})
        boolean(row['fsyncObserved'],True); need(row['mode'] == '0600')
        integer(row['uid'],10001,10001); integer(row['gid'],10001,10001)
        integer(row['bytes'],0,8<<20); digest(row['sha256'])
    need(receipts['entries'][0]['sha256'] == report_binding['sourceManifestSHA256'] and
         receipts['entries'][1]['sha256'] == report_binding['privateReportSHA256'])
    by_name = {row['name']:row for row in index['entries']}; receipt = {row['name']:row for row in receipts['entries']}
    for name in WALS:
        need(by_name[name]['sha256'] == receipt[name]['sha256'] and by_name[name]['bytes'] == receipt[name]['bytes'] and
             by_name[name]['recordSHA256'] != '0'*64)
    need(by_name[WALS[0]]['sha256'] == publication['s1PreimageSHA256'] and
         by_name[WALS[1]]['sha256'] == publication['sourceControlSHA256'] and
         by_name[WALS[2]]['sha256'] == publication['diskControlSHA256'])
    if mode == 'not-committed':
        need(by_name[WALS[1]]['sha256'] == by_name[WALS[2]]['sha256'] and
             by_name[WALS[3]]['sha256'] != by_name[WALS[2]]['sha256'] and
             by_name[WALS[3]]['bytes'] > by_name[WALS[2]]['bytes'])
    else:
        need(by_name[WALS[1]]['sha256'] == publication['s2PreimageSHA256'] and
             by_name[WALS[1]]['sha256'] != by_name[WALS[2]]['sha256'] and
             by_name[WALS[2]]['sha256'] == by_name[WALS[3]]['sha256'] and
             by_name[WALS[2]]['bytes'] == by_name[WALS[3]]['bytes'])


def main(args):
    if len(args) == 4 and args[0] == '--source-manifest':
        repo, commit, output = Path(args[1]).absolute(), args[2], Path(args[3]).absolute()
        need(Path(__file__).resolve(strict=True) ==
             (repo/'chengwang/deploy/mihomo-lifecycle-lab/check_native_completion.py').resolve(strict=True))
        binding, manifest_raw = source_binding(repo,commit)
        source_check(repo); verify_private_manifest(manifest_raw,binding)
        write_new_fsync(output,manifest_raw)
        print(canonical(binding).decode('ascii'))
        return 0
    need(len(args) == 4)
    repo, out, commit, mode = Path(args[0]).absolute(), Path(args[1]).absolute(), args[2], args[3]
    need(re.fullmatch(r'[0-9a-f]{40}',commit) is not None and mode in MODES)
    need(Path(__file__).resolve(strict=True) == (repo/'chengwang/deploy/mihomo-lifecycle-lab/check_native_completion.py').resolve(strict=True))
    binding, derived_manifest = source_binding(repo,commit)
    verify_private_manifest(derived_manifest,binding)
    source_check(repo)
    report = decode(raw_file(out/'completion-report.json',1 << 20))
    publication, report_binding = report_check(report,commit,mode,binding)
    wal_evidence(out,report,publication,commit,mode,report_binding)
    go_terminal(raw_file(out/'completion.json',8 << 20))
    command_namespace = command_receipts(raw_file(out/'commands.jsonl',64 << 10),commit,mode,binding)
    sandbox = decode(raw_file(out/'sandbox.json',64 << 10))
    need(sandbox['schema'] == 'chengwang.mihomo-native-completion-sandbox/v3' and sandbox['completionMode'] == mode and
         sandbox['sourceCommit'] == commit)
    exact_same(sandbox['sourceBinding'],binding)
    integer(sandbox['uid'],10001,10001); integer(sandbox['gid'],10001,10001)
    exact_same({key:sandbox[key] for key in command_namespace},command_namespace)
    execution = decode(raw_file(out/'execution.json',64 << 10))
    exact_same(execution,{'schema':'chengwang.mihomo-native-completion-execution/v3','scope':SCOPE,
         'completionMode':mode,'sourceCommit':commit,'formatExit':0,'goExit':0,
         'sourceBinding':binding,
         'captureState':'CAPTURED_NOT_INDEPENDENT_ACCEPTANCE','outcome':'PASS','production':False})
    need(raw_file(out/'gofmt.patch',8 << 20,empty=True) == b'' and raw_file(out/'gofmt.stderr',8 << 20,empty=True) == b'' and
         raw_file(out/'completion.stderr',8 << 20,empty=True) == b'')
    print('NATIVE_FIRST_COMPLETION_ACCEPTED mode='+mode+' private_wal_rechecked_in_producer=true full_private_wal_independent=false production=false')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as exc:
        print(type(exc).__name__+': '+str(exc),file=sys.stderr)
        raise SystemExit(1)
