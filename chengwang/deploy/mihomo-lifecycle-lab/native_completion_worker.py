#!/usr/bin/env python3
"""Capture one real first-Completion native experiment; importing starts nothing."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import unicodedata

SCOPE = 'ACTUAL_FIRST_RECOVERY_COMPLETION_NOT_API_REBIND_ORDINARY_PUBLISH_SECOND_RECOVERY_OR_PRODUCTION'
ROOT = Path('/tmp/chengwang-mihomo-recovery-private')
TAGS = ('chengwang_mihomo_service', 'chengwang_mihomo_faults', 'chengwang_mihomo_recovery_native',
        'chengwang_mihomo_completion_native')
TOP = 'TestLabRecoveryCompletionNativeFirstTransitionAndOwnedCleanup'
MODES = ('positive', 'not-committed', 'unknown', 'readback')
OUTPUT_MODES = {'mihomo-native-completion-'+mode+'-public': mode for mode in MODES}
COMMANDS = ('SANDBOX', 'GO_VERSION', 'GOFMT', 'GO_TEST')
CAPTURE_COMMANDS = {
    'completion-sandbox.private.json': ('completion-sandbox.private.stderr', 'SANDBOX', 30),
    'go-version.txt': ('go-version.private.stderr', 'GO_VERSION', 15),
    'completion-gofmt.patch': ('completion-gofmt.stderr', 'GOFMT', 30),
    'completion.json': ('completion.stderr', 'GO_TEST', 120),
}
WALS = ('completion-s1.private.json', 'completion-s2.private.json',
        'completion-attempted.private.json', 'completion-reopened.private.json')
CAPTURES = ('transcript.json', *(f'body-{n}.json' for n in range(1, 9)),
            'verification.json', 'local-marker.json')
FMT = tuple('internal/mihomodeploy/' + name for name in (
    'lab_bootstrap.go', 'lab_kernel_linux.go', 'lab_quiescence_linux.go',
    'lab_recovery_start_linux.go', 'lab_syntax_linux.go',
    'lab_native_recovery_observer_default.go', 'lab_native_recovery_observer_linux.go',
    'lab_native_recovery_linux.go', 'lab_native_recovery_linux_test.go',
    'lifecycle_recovery_checkpoint.go', 'lifecycle_recovery_completion.go', 'lifecycle_recovery_completion_test.go',
    'lifecycle_current_epoch.go', 'lab_current_epoch_runtime.go',
    'lab_native_completion_linux_test.go'))
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
_SERVICE = None
_STATE = None


def need(value):
    if not value:
        raise ValueError('isolated native Completion capture rejected')


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


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_file(path, limit=2 << 20):
    path = Path(path).absolute()
    for item in (*reversed(path.parents), path):
        info = item.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 1024)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit)
    raw = path.read_bytes(); after = path.lstat()
    signature = lambda value: (value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns)
    need(signature(before) == signature(after) and len(raw) == before.st_size)
    return raw


def source_set_digest(schema, rows):
    return sha(canonical({'schema':schema,'entries':rows}))


def source_policy(root, module_root=False):
    relative = MANIFEST_REL[len('chengwang/'):] if module_root else MANIFEST_REL
    raw = source_file(Path(root)/relative, 64 << 10)
    value = json.loads(raw)
    need(canonical(value) + b'\n' == raw)
    exact_same(value,{
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
    return raw, value


def _binding(manifest_raw, manifest):
    return {'schema':'chengwang.mihomo-native-completion-source-binding/v2',
            'sourceCommit':manifest['sourceCommit'],'sourceTree':manifest['sourceTree'],
            'indexTree':manifest['indexTree'],'sourceManifestSHA256':sha(manifest_raw),
            'sourceSetSHA256':manifest['sourceSetSHA256'],'deliverySetSHA256':manifest['deliverySetSHA256'],
            'policySHA256':manifest['policySHA256'],'sourceCount':manifest['entryCount'],
            'deliveryCount':len(manifest['deliveries'])}


def git_source(repo, supplied_commit):
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
             '..' not in Path(path).parts and mode in (b'100644',b'100755') and kind == b'blob' and OID.fullmatch(oid.decode('ascii')) is not None)
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
        raw = source_file(repo/path, MAX_TRACKED_BYTES)
        need(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest() == tree[path][1])
        if os.name == 'posix':
            need(bool((repo/path).lstat().st_mode & 0o111) == (tree[path][0] == b'100755'))
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
    policy_raw, _ = source_policy(repo)
    manifest = {'schema':'chengwang.mihomo-native-completion-fulltracked-manifest/v2',
                'sourceCommit':actual,'sourceTree':tree_oid,'indexTree':index_tree,
                'policySHA256':sha(policy_raw),'entryCount':len(entries),'entries':entries,
                'deliveries':deliveries,
                'sourceSetSHA256':source_set_digest('chengwang.mihomo-native-completion-fulltracked-set/v2',entries),
                'deliverySetSHA256':source_set_digest('chengwang.mihomo-native-completion-delivery-set/v2',deliveries)}
    manifest_raw = canonical(manifest) + b'\n'
    return actual, _binding(manifest_raw,manifest), manifest_raw


def verify_private_manifest(root, manifest_raw, expected, module_root=False):
    manifest = json.loads(manifest_raw)
    need(canonical(manifest) + b'\n' == manifest_raw and set(manifest) ==
         {'schema','sourceCommit','sourceTree','indexTree','policySHA256','entryCount','entries','deliveries','sourceSetSHA256','deliverySetSHA256'} and
         manifest['schema'] == 'chengwang.mihomo-native-completion-fulltracked-manifest/v2')
    binding = _binding(manifest_raw,manifest)
    by_path = {row.get('path'):row for row in manifest['entries'] if type(row) is dict}
    exact_same(binding,expected)
    need(type(manifest['sourceCommit']) is str and COMMIT.fullmatch(manifest['sourceCommit']) is not None and
         type(manifest['sourceTree']) is str and OID.fullmatch(manifest['sourceTree']) is not None and
         type(manifest['indexTree']) is str and manifest['sourceTree'] == manifest['indexTree'] and
         type(manifest['entryCount']) is int and manifest['entryCount'] == len(manifest['entries']))
    exact_same(manifest['deliveries'],[by_path.get(path) for path in DELIVERY_PATHS])
    policy_raw, _ = source_policy(root,module_root=module_root)
    need(manifest['policySHA256'] == sha(policy_raw) and binding['deliveryCount'] == len(DELIVERY_PATHS))
    folded = set(); paths = set()
    for row in manifest['entries']:
        need(type(row) is dict and set(row) == {'path','mode','gitBlob','bytes','sha256'} and
             row['mode'] in ('100644','100755') and OID.fullmatch(row['gitBlob']) is not None and
             type(row['bytes']) is int and 0 < row['bytes'] <= MAX_TRACKED_BYTES and
             re.fullmatch(r'[0-9a-f]{64}',row['sha256']) is not None)
        key = unicodedata.normalize('NFC',row['path']).casefold()
        need(row['path'] not in paths and key not in folded)
        paths.add(row['path']); folded.add(key)
        if module_root and not row['path'].startswith('chengwang/'):
            continue
        relative = row['path'][len('chengwang/'):] if module_root else row['path']
        raw = source_file(Path(root)/relative,MAX_TRACKED_BYTES)
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'] and
             hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest() == row['gitBlob'])
    need(set(DELIVERY_PATHS).issubset(paths) and
         source_set_digest('chengwang.mihomo-native-completion-fulltracked-set/v2',manifest['entries']) == manifest['sourceSetSHA256'] and
         source_set_digest('chengwang.mihomo-native-completion-delivery-set/v2',manifest['deliveries']) == manifest['deliverySetSHA256'])
    return binding


def service_worker():
    global _SERVICE
    if _SERVICE is None:
        path = Path(__file__).absolute().with_name('service_worker.py')
        for item in (*reversed(path.parents), path):
            info = item.lstat()
            need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 1024)
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 1 << 20)
        spec = importlib.util.spec_from_file_location('_completion_fixed_service_helpers', path)
        need(spec is not None and spec.loader is not None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _SERVICE = module
    return _SERVICE


def contract():
    s = service_worker(); w = s.adapter().shared()
    raw = w.file_bytes(Path(__file__).absolute().with_name('native_completion_contract.json'), 64 << 10)[0]
    value = w.decode(raw)
    need(value['schema'] == 'chengwang.mihomo-native-completion-contract/v3' and
         value['scope'] == SCOPE and tuple(value['tags']) == TAGS and value['topTests'] == [TOP] and
         type(value['goTimeoutSeconds']) is int and value['goTimeoutSeconds'] == 105 and
         type(value['outerGoTimeoutSeconds']) is int and value['outerGoTimeoutSeconds'] == 120 and
         tuple(value['modes']) == MODES and value['oldV5ContractChanged'] is False and
         value['fullPrivateWALIndependentlyProven'] is False and value['production'] is False and
         type(value['maxTrackedFileBytes']) is int and value['maxTrackedFileBytes'] == MAX_TRACKED_BYTES and
         value['commandReceiptSchema'] == 'chengwang.mihomo-native-completion-command-receipt/v3')
    exact_same(value['sourceManifest'],{'policyName':'native_completion_source_manifest.json',
             'policySchema':'chengwang.mihomo-native-completion-source-policy/v2',
             'generatedSchema':'chengwang.mihomo-native-completion-fulltracked-manifest/v2',
             'bindingSchema':'chengwang.mihomo-native-completion-source-binding/v2',
             'trackedSet':'ALL_GIT_HEAD_BLOBS','deliveryCount':len(DELIVERY_PATHS),
             'gitCommitRequired':True,'gitTreeRequired':True,'gitIndexMustMatchCommitTree':True,
             'workingBytesMustMatchGitBlobs':True,'oldTwentyOneSourceManifestAccepted':False})
    exact_same(value['completePackageTestSources'],{'previousCount':84,'candidateCount':88,
             'ordinaryMandatoryTopLevelCount':688,'completionHarnessExcludedFromOrdinaryMandatoryNames':True})
    exact_same(value['coldReopen'],{
        'coldReopenMatchedDiskMeaning':'POST_OPEN_DISK_EQUALS_REOPENED_STORE_RAW',
        'positive':'COMPLETED_UNCHANGED','not-committed':'START_ARMED_TO_RECOVERY_UNKNOWN',
        'unknown':'COMPLETED_UNCHANGED','readback':'COMPLETED_UNCHANGED'})
    need(value['oldS2WorkflowChanged'] is False and value['oldS2BudgetsChanged'] is False)
    return value


def native_base(create):
    if create:
        ROOT.mkdir(mode=0o700)
        os.chown(ROOT, 10001, 10001)
    info = ROOT.lstat()
    need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
         info.st_uid == info.st_gid == 10001)
    names = {path.name for path in ROOT.iterdir()}
    need((create and not names) or (not create and names == {'completion-source.private.json'}))


def write_private_source_manifest(raw):
    path = ROOT/'completion-source.private.json'
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchown(fd,10001,10001)
        view = memoryview(raw)
        while view:
            written = os.write(fd,view); need(written > 0); view = view[written:]
        os.fsync(fd)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 10001 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(raw))
    finally:
        os.close(fd)
    directory = os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def append_command(state, row):
    s = service_worker(); a = s.adapter(); w = a.shared()
    sequence = state.get('completionCommandSequence', 0) + 1
    need(row['sequence'] == sequence and 1 <= sequence <= 4 and row['commandClass'] == COMMANDS[sequence-1])
    raw = w.canonical(row)
    path = a.ROOT_PRIVATE/'completion-commands.private.jsonl'
    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
    if sequence == 1:
        flags |= os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_size + len(raw) + 1 <= 64 << 10)
        identity = (info.st_dev, info.st_ino)
        if sequence == 1:
            state['completionCommandIdentity'] = identity
        need(state['completionCommandIdentity'] == identity)
        view = memoryview(raw + b'\n')
        while view:
            written = os.write(fd, view)
            need(written > 0)
            view = view[written:]
        os.fsync(fd)
        named = path.lstat()
        need((named.st_dev, named.st_ino) == identity and named.st_nlink == 1)
    finally:
        os.close(fd)
    if sequence == 1:
        directory = os.open(a.ROOT_PRIVATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    state['completionCommandSequence'] = sequence


def completion_argv(state, adapter, shared, command_class):
    binding = state.get('sourceBinding')
    mode = state.get('completionMode')
    need(type(binding) is dict and mode in MODES and state.get('commit') == binding.get('sourceCommit'))
    worker = adapter.PATHS['module']+'/deploy/mihomo-lifecycle-lab/native_completion_worker.py'
    commands = {
        'SANDBOX': [shared.tool('python3'),'-B',worker,'--sandbox',state['commit'],
                    binding['sourceTree'],binding['indexTree'],binding['sourceManifestSHA256'],
                    binding['sourceSetSHA256'],binding['deliverySetSHA256'],binding['policySHA256'],
                    str(binding['sourceCount']),str(binding['deliveryCount']),mode],
        'GO_VERSION': [adapter.PATHS['goRoot']+'/bin/go','version'],
        'GOFMT': [adapter.PATHS['goRoot']+'/bin/gofmt','-d',*FMT],
        'GO_TEST': [adapter.PATHS['goRoot']+'/bin/go','test','-json','-count=1','-shuffle=off','-p=1',
                    '-tags='+','.join(TAGS),'-run=^'+TOP+'$','-timeout=105s','./internal/mihomodeploy',
                    '-args','-chengwang-native-completion-mode='+mode],
    }
    need(command_class in commands)
    return tuple(commands[command_class])


def capture(state, argv, name, err_name, timeout, command_class):
    s = service_worker(); a = s.adapter(); w = a.shared()
    actual = tuple(argv)
    need(name in CAPTURE_COMMANDS and
         (err_name, command_class, timeout) == CAPTURE_COMMANDS[name] and
         command_class == COMMANDS[state.get('completionCommandSequence', 0)] and
         type(timeout) is int and actual and
         all(type(arg) is str and 0 < len(arg) <= 4096 for arg in actual) and
         actual == completion_argv(state, a, w, command_class))
    observed, code = False, None
    try:
        a.process_event(state, command_class, 'START_INTENT')
        with (a.ROOT_PRIVATE/name).open('xb') as stdout, (a.ROOT_PRIVATE/err_name).open('xb') as stderr:
            os.fchmod(stdout.fileno(), 0o600)
            os.fchmod(stderr.fileno(), 0o600)
            try:
                process = subprocess.Popen(w.unprivileged(actual, state['environment']),
                                           env=w.ROOT_ENV, cwd=a.PATHS['module'],
                                           stdin=subprocess.DEVNULL, stdout=stdout,
                                           stderr=stderr, start_new_session=True)
            except Exception:
                a.process_event(state, command_class, 'START_UNOBSERVED')
                raise ValueError('owned Completion process start unobserved') from None
            entry = dict(process=process, pidfd=None)
            state['pending'].append(entry)
            a.process_event(state, command_class, 'STARTED', pid=process.pid)
            # The child is deliberately not polled or reaped before the owned
            # reference exists. A fast-exiting child therefore cannot have its
            # PID reused before this Completion worker binds it.
            try:
                fd = os.pidfd_open(process.pid, 0)
            except Exception:
                a.process_event(state, command_class, 'REFERENCE_UNAVAILABLE',
                                pid=process.pid, acquired=False)
                raise ValueError('owned Completion process reference unavailable') from None
            entry['pidfd'] = fd
            a.process_event(state, command_class, 'REFERENCE_ACQUIRED', pid=process.pid, acquired=True)
            try:
                try:
                    code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    a.process_event(state, command_class, 'WAIT_TIMEOUT', pid=process.pid, acquired=True)
                    a.process_event(state, command_class, 'SIGNAL_INTENT', pid=process.pid, acquired=True)
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    except Exception:
                        a.process_event(state, command_class, 'SIGNAL_UNCERTAIN',
                                        pid=process.pid, acquired=True)
                        raise ValueError('owned Completion process termination unobserved') from None
                    a.process_event(state, command_class, 'SIGNAL_SENT', pid=process.pid, acquired=True)
                    try:
                        code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        a.process_event(state, command_class, 'WAIT_UNOBSERVED',
                                        pid=process.pid, acquired=True)
                        raise ValueError('owned Completion process wait unobserved') from None
                except Exception:
                    a.process_event(state, command_class, 'WAIT_UNOBSERVED',
                                    pid=process.pid, acquired=True)
                    raise ValueError('owned Completion process wait unobserved') from None
                a.process_event(state, command_class, 'WAIT_RETURNED',
                                pid=process.pid, acquired=True, exit_code=code)
                stdout.flush(); stderr.flush()
                os.fsync(stdout.fileno()); os.fsync(stderr.fileno())
            finally:
                if process.returncode is not None:
                    os.close(fd)
                    entry['pidfd'] = None
                    state['pending'].remove(entry)
        observed = True
        return code
    finally:
        append_command(state, dict(schema='chengwang.mihomo-native-completion-command-receipt/v3',
            sequence=state.get('completionCommandSequence', 0)+1, sourceCommit=state['commit'],
            commandClass=command_class, argv=list(actual), cwd=a.PATHS['module'], timeoutSeconds=timeout,
            exitCode=code if observed else None, observed=observed, namespace=w.namespace_values(),
            sourceBinding=copy.deepcopy(state['sourceBinding'])))


def private_file(path, limit, empty=False):
    s = service_worker()
    return s.private_file(path, limit, empty=empty)


def record_hash(value):
    need(type(value) is dict and 'recordSHA256' in value)
    preimage = {key: item for key, item in value.items() if key != 'recordSHA256'}
    return sha(canonical(preimage))


def strict_wal(raw):
    value = json.loads(raw)
    need(type(value) is dict and canonical(value) == raw and
         value['schema'] == 'chengwang.mihomo-lifecycle-record/v3' and
         type(value['revision']) is int and value['revision'] > 0 and
         record_hash(value) == value['recordSHA256'])
    return value


def validate_armed_reopen(before, after):
    need(before['recovery']['phase'] == 'START_ARMED' and before['recovery']['failure'] is None and
         after['revision'] == before['revision'] + 1 and
         after['recordSHA256'] != before['recordSHA256'] and
         after['lastTrustedAt'] != before['lastTrustedAt'] and
         after['recovery']['phase'] == 'RECOVERY_UNKNOWN' and
         after['recovery']['failure'] == {'code':'PROCESS_REOPENED','at':after['lastTrustedAt']} and
         after['recovery']['updatedAt'] == after['lastTrustedAt'])
    projected = copy.deepcopy(before)
    projected['revision'] = after['revision']
    projected['recordSHA256'] = after['recordSHA256']
    projected['lastTrustedAt'] = after['lastTrustedAt']
    projected['recovery']['phase'] = after['recovery']['phase']
    projected['recovery']['failure'] = copy.deepcopy(after['recovery']['failure'])
    projected['recovery']['updatedAt'] = after['recovery']['updatedAt']
    need(projected == after)


def reconstruct_s1(s2):
    source = copy.deepcopy(s2)
    recovery = source['recovery']; execution = recovery['execution']; verification = execution['verification']
    observation = verification['observation']
    source['revision'] = observation['sourceRevision']
    source['recordSHA256'] = observation['sourceRecordSHA256']
    source['lastTrustedAt'] = verification['sourceLastTrustedAt']
    source['lastRecoveryFence'] = verification['sourceLastRecoveryFence']
    source['recoveryOwner'] = verification['sourceOwner']
    recovery['phase'] = 'START_ARMED'
    recovery['revocation'] = None
    recovery['failure'] = None
    recovery['updatedAt'] = verification['sourceRecoveryUpdatedAt']
    recovery['failedQuiescence'] = verification['sourceFailedQuiescence']
    execution['schema'] = 'chengwang.mihomo-recovery-execution/v1'
    execution.pop('verification')
    execution.pop('completionSource', None)
    return canonical(source)


def hash_value(value):
    return sha(canonical(value))


def reconstruct_s2(completed):
    source = completed['recovery']['execution']['completionSource']
    need(source['schema'] == 'chengwang.mihomo-recovery-completion-source/v1')
    root = source['root']
    need(root['schema'] == 'chengwang.mihomo-recovery-root-checkpoint/v1' and
         root['recoveryKind'] == 'ACTIVE_VERIFIED')
    retired_count = root['retiredPrefixCount']; history_count = root['recoveryHistoryPrefixCount']
    need(root['currentEpochPosition'] == retired_count and retired_count < len(completed['retiredEpochs']) and
         history_count < len(completed['recoveryHistory']))
    retired = copy.deepcopy(completed['retiredEpochs'][:retired_count])
    history = copy.deepcopy(completed['recoveryHistory'][:history_count])
    need(hash_value({'schema':'chengwang.mihomo-recovery-retired-prefix/v1','entries':retired}) == root['retiredPrefixSHA256'] and
         hash_value({'schema':'chengwang.mihomo-recovery-history-prefix/v1','entries':history}) == root['recoveryHistoryPrefixSHA256'])
    current = copy.deepcopy(completed['retiredEpochs'][root['currentEpochPosition']]['ledger'])
    need(hash_value(current) == root['currentLedgerSHA256'])
    recovery = copy.deepcopy(completed['recovery'])
    recovery['phase'] = 'START_ARMED'
    recovery['completion'] = None
    recovery['updatedAt'] = root['lastTrustedAt']
    recovery['execution']['schema'] = 'chengwang.mihomo-recovery-execution/v2'
    recovery['execution'].pop('completionSource')
    result = dict(schema=completed['schema'], boundary=completed['boundary'], revision=root['revision'],
                  recordSHA256=root['recordSHA256'], lastTrustedAt=root['lastTrustedAt'],
                  provisioning=completed['provisioning'], sourceV2=completed['sourceV2'], current=current,
                  retiredEpochs=retired, recoveryOwner=root['recoveryOwner'],
                  lastRecoveryFence=root['lastRecoveryFence'], recovery=recovery, recoveryHistory=history)
    return canonical(result)


def fsync_receipt(path, raw):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 10001 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(raw))
        os.fsync(fd)
        return dict(name=path.name, bytes=len(raw), sha256=sha(raw), mode='0600', uid=info.st_uid,
                    gid=info.st_gid, fsyncObserved=True)
    finally:
        os.close(fd)


def disclose_inputs():
    s = service_worker(); a = s.adapter(); w = a.shared()
    tokens = w.decode(private_file(ROOT/'tokens.private.json', 16 << 10))
    need(type(tokens) is dict and set(tokens) == {'initiator', 'approver', 'viewer'})
    values = [value.encode() for value in tokens.values()]
    secret_path = s.ROOT/'.secrets.private.json'
    if secret_path.exists():
        private = w.decode(private_file(secret_path, 4096))
        values.extend(private[key].encode() for key in ('controller', 'routeA', 'routeB'))
    configs = [private_file(s.ROOT/name, 1 << 20) for name in
               ('local-a.config.private.yaml', 'local-b.config.private.yaml') if (s.ROOT/name).exists()]
    profile = private_file(s.IDENTITIES/'credentials.json', 1 << 20)
    return a.safe_variants(values, [*configs, profile])


def private_outputs(commit, mode, source_binding):
    s = service_worker(); a = s.adapter(); w = a.shared(); forbidden = disclose_inputs()
    report_raw = private_file(ROOT/'completion-report.private.json', 1 << 20)
    report = w.decode(report_raw)
    need(report['schema'] == 'chengwang.mihomo-native-completion-experiment/v1' and
         report['scope'] == SCOPE and report['sourceCommit'] == commit and report['mode'] == mode and
         report['outcome'] in ('PASS', 'FAIL') and type(report['nativeCalls']) is list and len(report['nativeCalls']) <= 256)
    source_manifest_raw = private_file(ROOT/'completion-source.private.json', 8 << 20)
    need(source_binding['sourceManifestSHA256'] == sha(source_manifest_raw))
    wal_raw = {}; wal = {}; receipts = [fsync_receipt(ROOT/'completion-source.private.json',source_manifest_raw),
                                        fsync_receipt(ROOT/'completion-report.private.json', report_raw)]
    for name in WALS:
        path = ROOT/name
        if not path.exists():
            need(report['outcome'] == 'FAIL')
            continue
        raw = private_file(path, 2 << 20)
        wal_raw[name] = raw; wal[name] = strict_wal(raw); receipts.append(fsync_receipt(path, raw))
    if report['outcome'] == 'PASS':
        need(set(wal) == set(WALS))
        s1, s2, attempted, reopened = (wal[name] for name in WALS)
        need(reconstruct_s1(s2) == wal_raw[WALS[0]])
        publication = report['completion']
        counts = {'positive':(1,1,1,0,True), 'not-committed':(1,0,0,0,False),
                  'unknown':(1,1,0,0,True), 'readback':(1,1,1,1,True)}[mode]
        need(tuple(publication[key] for key in ('replaceAttempts','forwardedWrites','postWriteReads','injectedReads','underlyingCommitted')) == counts and
             publication['sourceControlSHA256'] == sha(wal_raw[WALS[1]]) and
             publication['diskControlSHA256'] == sha(wal_raw[WALS[2]]) and
             publication['s1PreimageSHA256'] == sha(wal_raw[WALS[0]]) and
             publication['coldReopenMatchedDisk'] is True and publication['noCompletionNativeCalls'] is True and
             all(publication[key] is False for key in ('serviceRebindProven','apiRouteProven','ordinaryPublishProven','secondRecoveryProven','production')))
        if mode == 'not-committed':
            validate_armed_reopen(attempted,reopened)
            need(wal_raw[WALS[1]] == wal_raw[WALS[2]] and attempted['recovery']['phase'] == 'START_ARMED' and
                 publication['s2PreimageSHA256'] is None and publication['runtimeAdopted'] is False and
                 publication['reopenTransition'] == 'START_ARMED_TO_RECOVERY_UNKNOWN')
        else:
            need(wal_raw[WALS[2]] == wal_raw[WALS[3]] and reconstruct_s2(attempted) == wal_raw[WALS[1]] and attempted['recovery']['phase'] == 'COMPLETED' and
                 len(attempted['retiredEpochs']) == len(attempted['recoveryHistory']) == 1 and
                 publication['s2PreimageSHA256'] == sha(wal_raw[WALS[1]]) and
                 publication['reopenTransition'] == 'COMPLETED_UNCHANGED')
            need((mode == 'positive') == publication['runtimeAdopted'])
    directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    index = []
    for name in WALS:
        if name not in wal:
            index.append(dict(name=name, present=False))
        else:
            value = wal[name]
            index.append(dict(name=name, present=True, bytes=len(wal_raw[name]), sha256=sha(wal_raw[name]),
                              revision=value['revision'], recordSHA256=value['recordSHA256'], phase=value['recovery']['phase']))
    public_report = copy.deepcopy(report)
    public_report['sourceBinding'] = copy.deepcopy(source_binding)
    public_report['sourceBinding']['privateReportSHA256'] = sha(report_raw)
    bound = copy.deepcopy(public_report['sourceBinding'])
    outputs = {
        'completion-report.json': canonical(public_report),
        'completion-wal-index.json': canonical(dict(schema='chengwang.mihomo-native-completion-wal-index/v1',
            scope=SCOPE, sourceCommit=commit, mode=mode, sourceBinding=bound, entries=index,
            fullPrivateWALIndependentlyProven=False, production=False))}
    for public, path in [('old-kernel.stdout', s.ROOT/'kernel.stdout'), ('old-kernel.stderr', s.ROOT/'kernel.stderr'),
                         ('new-kernel.stdout', ROOT/'new-kernel.stdout'), ('new-kernel.stderr', ROOT/'new-kernel.stderr')]:
        if path.exists():
            raw = private_file(path, 64 << 10, empty=True)
            outputs[public] = raw
            receipts.append(fsync_receipt(path, raw))
        else:
            need(report['outcome'] == 'FAIL')
    total = 0
    for name in CAPTURES:
        path = s.ROOT/'recovery-s2'/name
        if not path.exists():
            need(report['outcome'] == 'FAIL')
            continue
        limit = 64 << 10 if name in ('verification.json','local-marker.json') else 256 << 10 if name.startswith('body-') else 2 << 20
        raw = private_file(path, limit); total += len(raw); need(total <= 2 << 20)
        outputs['recovery-s2-'+name] = raw
    outputs['completion-fsync-receipts.json'] = canonical(dict(
        schema='chengwang.mihomo-native-completion-fsync-receipts/v1', scope=SCOPE,
        sourceCommit=commit, mode=mode, sourceBinding=bound, entries=receipts,
        directoryFsyncObserved=True, production=False))
    for raw in outputs.values():
        s.disclosure(raw, forbidden)
    return outputs, forbidden, report


def command_outputs():
    s = service_worker(); a = s.adapter(); w = a.shared(); outputs = {}
    for public, private in [('commands.jsonl','completion-commands.private.jsonl'),
                            ('process-events.jsonl','process-events.private.jsonl')]:
        outputs[public] = w.file_bytes(a.ROOT_PRIVATE/private, 64 << 10)[0]
    return outputs


def go_terminal(raw):
    rows = [json.loads(line) for line in raw.splitlines() if line]
    relevant = [row for row in rows if row.get('Test') == TOP]
    need(sum(row.get('Action') == 'run' for row in relevant) == 1 and
         sum(row.get('Action') == 'pass' for row in relevant) == 1 and
         not any(row.get('Action') in ('fail','skip') for row in rows))
    packages = [row for row in rows if 'Test' not in row and row.get('Action') == 'pass']
    need(len(packages) == 1 and packages[0].get('Package') == 'chengwang/internal/mihomodeploy' and
         all(row.get('Test', TOP).split('/')[0] == TOP for row in rows))


def main(args):
    global _STATE
    if len(args) == 11 and args[0] == '--sandbox':
        need(args[10] in MODES and args[8].isdigit() and args[9].isdigit())
        module_root = Path('/tmp/mihomo-apply-source')
        need(Path(__file__).resolve(strict=True) ==
             (module_root/'deploy/mihomo-lifecycle-lab/native_completion_worker.py').resolve(strict=True))
        manifest_raw = source_file(ROOT/'completion-source.private.json',8 << 20)
        expected = {'schema':'chengwang.mihomo-native-completion-source-binding/v2','sourceCommit':args[1],
                    'sourceTree':args[2],'indexTree':args[3],'sourceManifestSHA256':args[4],
                    'sourceSetSHA256':args[5],'deliverySetSHA256':args[6],'policySHA256':args[7],
                    'sourceCount':int(args[8]),'deliveryCount':int(args[9])}
        binding = verify_private_manifest(module_root,manifest_raw,expected,module_root=True)
        s = service_worker(); a = s.adapter(); w = a.shared(); contract()
        need(Path(a.PATHS['module']) == module_root)
        module_raw = source_file(module_root/'go.mod',64 << 10)
        facts = a.sandbox(args[1], sha(module_raw)); s.bases(False); native_base(False)
        facts.update(schema='chengwang.mihomo-native-completion-sandbox/v3', completionMode=args[10],
                     sourceBinding=binding,serviceBases=[str(s.ROOT),str(s.IDENTITIES),str(s.STATE)])
        print(canonical(facts).decode('ascii'), end='')
        return 0
    need(len(args) == 5)
    repo = Path(args[0]).absolute()
    need(Path(__file__).resolve(strict=True) ==
         (repo/'chengwang/deploy/mihomo-lifecycle-lab/native_completion_worker.py').resolve(strict=True))
    actual_commit, source_binding, generated_manifest_raw = git_source(repo,args[4])
    s = service_worker(); a = s.adapter(); w = a.shared(); c = contract()
    mode = OUTPUT_MODES.get(Path(args[1]).name)
    need(mode in MODES)
    state = a.prepare_namespace(*args); _STATE = state
    state['sourceBinding'] = source_binding
    state['completionMode'] = mode
    s.bases(True); native_base(True)
    write_private_source_manifest(generated_manifest_raw)
    worker = a.PATHS['module']+'/deploy/mihomo-lifecycle-lab/native_completion_worker.py'
    code = capture(state, [w.tool('python3'),'-B',worker,'--sandbox',state['commit'],
                    source_binding['sourceTree'],source_binding['indexTree'],source_binding['sourceManifestSHA256'],
                    source_binding['sourceSetSHA256'],source_binding['deliverySetSHA256'],source_binding['policySHA256'],
                    str(source_binding['sourceCount']),str(source_binding['deliveryCount']),mode],
                   'completion-sandbox.private.json','completion-sandbox.private.stderr',30,'SANDBOX')
    need(code == 0 and w.file_bytes(a.ROOT_PRIVATE/'completion-sandbox.private.stderr',4096,empty=True)[0] == b'')
    facts = w.decode(w.file_bytes(a.ROOT_PRIVATE/'completion-sandbox.private.json',64 << 10)[0])
    need(facts['schema'] == 'chengwang.mihomo-native-completion-sandbox/v3' and facts['completionMode'] == mode and
         facts['sourceBinding'] == source_binding)
    need(capture(state,[a.PATHS['goRoot']+'/bin/go','version'],'go-version.txt','go-version.private.stderr',15,'GO_VERSION') == 0)
    state['formatExit'] = capture(state,[a.PATHS['goRoot']+'/bin/gofmt','-d',*FMT],
                                  'completion-gofmt.patch','completion-gofmt.stderr',30,'GOFMT')
    argv = [a.PATHS['goRoot']+'/bin/go','test','-json','-count=1','-shuffle=off','-p=1',
            '-tags='+','.join(TAGS),'-run=^'+TOP+'$','-timeout=105s','./internal/mihomodeploy',
            '-args','-chengwang-native-completion-mode='+mode]
    state['goExit'] = capture(state,argv,'completion.json','completion.stderr',c['outerGoTimeoutSeconds'],'GO_TEST')
    after, _, directory = w.custody(state['consumed'])
    need(after == state['inputBefore'] and directory == state['originalDirectory'])
    facts['inputCustody'] = dict(before=state['inputBefore'],after=after)
    outputs = command_outputs()
    for public, private in [('go-version.txt','go-version.txt'),('gofmt.patch','completion-gofmt.patch'),
                            ('gofmt.stderr','completion-gofmt.stderr'),('completion.json','completion.json'),
                            ('completion.stderr','completion.stderr')]:
        outputs[public] = w.file_bytes(a.ROOT_PRIVATE/private,8 << 20,empty=True)[0]
    report_path = ROOT/'completion-report.private.json'
    if report_path.exists():
        private, forbidden, report = private_outputs(state['commit'],mode,source_binding)
        outputs.update(private)
        for raw in outputs.values():
            s.disclosure(raw,forbidden)
        outcome = report['outcome']
    else:
        need(state['goExit'] != 0 and all(not any(path.iterdir()) for path in (ROOT,s.ROOT,s.IDENTITIES,s.STATE)))
        outcome = 'NO_REPORT_EMPTY_RUNTIME_ROOTS'
    outputs['sandbox.json'] = canonical(facts)
    outputs['execution.json'] = canonical(dict(schema='chengwang.mihomo-native-completion-execution/v3',scope=SCOPE,
        completionMode=mode,sourceCommit=state['commit'],formatExit=state['formatExit'],goExit=state['goExit'],
        sourceBinding=source_binding,captureState='CAPTURED_NOT_INDEPENDENT_ACCEPTANCE',outcome=outcome,production=False))
    need(sum(map(len,outputs.values())) <= c['maxPublicBytes'])
    a.unchanged_public(state)
    for name, raw in outputs.items():
        w.write_new(a.EXPORT_ALIAS/name,raw,0o644)
    a.sync_output(state); a.unchanged_public(state); need(not state['pending'])
    if state['formatExit'] != 0 or state['goExit'] != 0 or outputs['gofmt.patch'] or outputs['gofmt.stderr'] or outcome != 'PASS':
        return 1
    go_terminal(outputs['completion.json'])
    print('NATIVE_FIRST_COMPLETION_ORIGINALS=CAPTURED independent_private_wal_acceptance=false production=false')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception:
        if _STATE is not None:
            try:
                service_worker().adapter().sync_output(_STATE)
            except Exception:
                pass
        raise
