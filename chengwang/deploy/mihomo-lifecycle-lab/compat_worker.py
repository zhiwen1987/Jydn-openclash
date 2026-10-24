#!/usr/bin/env python3
"""Source-owned Linux CI compatibility worker; import performs no setup or I/O."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys

TOOL_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
ROOT_ENV = {'PATH': TOOL_PATH, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC'}
CONTRACT_NAME = 'compat_contract.json'
ROOT_PRIVATE = Path('/tmp/mihomo-compat-root')
EXPORT_ALIAS = Path('/tmp/mihomo-compat-export')
MAX_ELF = 128 << 20
MAX_LOG = 8 << 20
SHA = re.compile(r'[a-f0-9]{64}')
FAILURE_STATE = None


def need(value):
    if not value:
        raise ValueError('mihomo compatibility worker rejected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(items):
        value = {}
        for key, child in items:
            need(key not in value)
            value[key] = child
        return value
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                      parse_constant=lambda _: need(False))


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def plain(path):
    path = Path(os.path.abspath(path))
    for entry in [*reversed(path.parents), path]:
        info = entry.lstat()
        need(not stat.S_ISLNK(info.st_mode))
    need(path.resolve(strict=True) == path)
    return path


def file_bytes(path, limit, mode=None, empty=False):
    path = plain(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         (0 if empty else 1) <= before.st_size <= limit)
    if mode is not None:
        need(stat.S_IMODE(before.st_mode) == mode)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        opened = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size,
                              s.st_mtime_ns, s.st_uid, s.st_gid)
        need(identity(before) == identity(opened))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after, named = os.fstat(fd), path.lstat()
        need(identity(before) == identity(opened) == identity(after) == identity(named) and
             before.st_ctime_ns == named.st_ctime_ns and opened.st_ctime_ns == after.st_ctime_ns and
             len(raw) == before.st_size)
        return raw, before
    finally:
        os.close(fd)


def write_new(path, raw, mode=0o600):
    need(not path.exists() and not path.is_symlink())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        need(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink == 1)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            need(count > 0)
            view = view[count:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def contract():
    raw, _ = file_bytes(Path(__file__).parent / CONTRACT_NAME, 64 << 10)
    value = decode(raw)
    need(type(value) is dict and value['schema'] == 'chengwang.mihomo-compat-contract/v1' and
         value['production'] is False and len(value['publicFiles']) == 23 and
         value['privateExtraFiles'] == ['.secrets.private.json', 'base.config.private.yaml', 'candidate.config.private.yaml'])
    need(value['paths'] == dict(module='/tmp/mihomo-compat-source', goRoot='/tmp/mihomo-compat-go',
         home='/tmp/mihomo-compat-home', privateOutput='/tmp/mihomo-compat-private',
         kernelDirectory='/tmp/mihomo-compat-kernel', kernel='/tmp/mihomo-compat-kernel/mihomo',
         receipt='/tmp/mihomo-compat-kernel/consumption.json'))
    return value


def tool(name):
    value = shutil.which(name, path=TOOL_PATH)
    need(value is not None)
    return value


def command(argv, timeout=30):
    result = subprocess.run(argv, env=ROOT_ENV, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    need(result.returncode == 0 and len(result.stdout) <= 1 << 20 and len(result.stderr) <= 1 << 20)
    return result.stdout


def mount_readonly(source, target, executable=False):
    command([tool('mount'), '--bind', str(source), str(target)])
    options = 'remount,bind,ro,nosuid,nodev' + ('' if executable else ',noexec')
    command([tool('mount'), '-o', options, str(target)])
    need(os.statvfs(target).f_flag & os.ST_RDONLY)


def namespace_values():
    return {name: os.readlink('/proc/self/ns/' + kind) for name, kind in
            [('networkNamespace', 'net'), ('mountNamespace', 'mnt'), ('pidNamespace', 'pid')]}


def custody(consumed):
    need(plain(consumed).is_dir() and set(p.name for p in consumed.iterdir()) == {'mihomo', 'consumption.json'})
    info = consumed.lstat()
    need(stat.S_IMODE(info.st_mode) == 0o700)
    values = {}
    data = {}
    for key, name, limit, mode in [('elf', 'mihomo', MAX_ELF, 0o500),
                                    ('receipt', 'consumption.json', 1 << 20, 0o400)]:
        raw, entry = file_bytes(consumed / name, limit, mode)
        values[key] = dict(sha256=sha(raw), bytes=len(raw), mode=format(mode, '04o'),
                           uid=entry.st_uid, gid=entry.st_gid)
        data[key] = raw
    return values, data, (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def environment(c, commit):
    paths = c['paths']
    value = dict(CGO_ENABLED='1', CHENGWANG_MIHOMO_COMPAT_ELF=paths['kernel'],
                 CHENGWANG_MIHOMO_COMPAT_OUT=paths['privateOutput'],
                 CHENGWANG_MIHOMO_COMPAT_RECEIPT=paths['receipt'],
                 CHENGWANG_MIHOMO_COMPAT_SOURCE_COMMIT=commit,
                 GOCACHE=paths['home'] + '/cache', GOENV='off', GOFLAGS='-mod=vendor',
                 GOMODCACHE=paths['home'] + '/mod', GOPROXY='off', GOROOT=paths['goRoot'],
                 GOSUMDB='off', GOTOOLCHAIN='local', HOME=paths['home'],
                 LANG='C.UTF-8', LC_ALL='C.UTF-8', PATH=paths['goRoot'] + '/bin:/usr/bin:/bin',
                 TMPDIR=paths['home'] + '/tmp', TZ='UTC')
    need(sorted(value) == c['environmentKeys'])
    return value


def unprivileged(argv, env):
    return [tool('setpriv'), '--reuid=10001', '--regid=10001', '--clear-groups',
            '--no-new-privs', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
            tool('env'), '-i', *[key + '=' + value for key, value in sorted(env.items())], *argv]


def sandbox(c, commit, module_sha):
    need(os.getuid() == os.geteuid() == 10001 and os.getgid() == os.getegid() == 10001 and not os.getgroups())
    need(dict(os.environ) == environment(c, commit))
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(status[key].strip(), 16) == 0 for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')) and
         status['NoNewPrivs'].strip() == '1')
    names = sorted(name for _, name in socket.if_nameindex())
    v4 = decode(command([tool('ip'), '-j', '-4', 'route', 'show', 'default']))
    v6 = decode(command([tool('ip'), '-j', '-6', 'route', 'show', 'default']))
    need(names == ['lo'] and v4 == v6 == [])
    paths = c['paths']
    need(Path.cwd() == Path(paths['module']))
    module, _ = file_bytes(Path(paths['module']) / 'go.mod', 64 << 10)
    need(sha(module) == module_sha)
    for name in ['home', 'privateOutput']:
        info = Path(paths[name]).lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 10001 and stat.S_IMODE(info.st_mode) == 0o700)
    kernel, info = file_bytes(Path(paths['kernel']), MAX_ELF, 0o500)
    need(info.st_uid == info.st_gid == 10001 and os.access(paths['kernel'], os.X_OK))
    source_ro = bool(os.statvfs(paths['module']).f_flag & os.ST_RDONLY)
    go_ro = bool(os.statvfs(paths['goRoot']).f_flag & os.ST_RDONLY)
    kernel_flags = os.statvfs(paths['kernel']).f_flag
    kernel_ro = bool(kernel_flags & os.ST_RDONLY)
    executable = os.access(paths['kernel'], os.X_OK) and not bool(kernel_flags & os.ST_NOEXEC)
    need(source_ro and go_ro and kernel_ro and executable)
    value = dict(schema=c['sandboxSchema'], sourceCommit=commit, uid=10001, gid=10001,
                 effectiveCaps=status['CapEff'].strip(), noNewPrivileges=True,
                 **namespace_values(), environmentKeys=sorted(os.environ), interfaceNames=names,
                 defaultV4Routes=v4, defaultV6Routes=v6, sourceModuleSHA256=module_sha,
                 sourceReadOnly=source_ro, goReadOnly=go_ro,
                 kernelCopy=dict(sha256=sha(kernel), bytes=len(kernel), mode='0500',
                                 readOnly=kernel_ro, executable=executable))
    need(set(value) == set(c['sandboxKeys']) - {'inputCustody'})
    return value


def forbidden_variants(secrets, bodies):
    values = set()
    for raw in [*secrets, *bodies]:
        text = raw.decode('utf-8')
        values.update([raw, base64.b64encode(raw), base64.urlsafe_b64encode(raw), raw.hex().encode('ascii'),
                       json.dumps(text, ensure_ascii=True).encode('ascii'),
                       json.dumps(text, ensure_ascii=False).encode('utf-8')])
    need(all(values))
    return values


def private_outputs(c):
    root = Path(c['paths']['privateOutput'])
    case_files = [case + suffix for case in c['cases'] for suffix in ('.exec.json', '.stdout', '.stderr')]
    names = set(p.name for p in root.iterdir())
    need(set(c['privateExtraFiles']) <= names <= set(case_files + c['privateExtraFiles']))
    secret_raw, info = file_bytes(root / '.secrets.private.json', 4096, 0o600)
    need(info.st_uid == info.st_gid == 10001)
    secrets = decode(secret_raw)
    need(type(secrets) is dict and set(secrets) == set(c['privateSecretsKeys']) and
         secrets['schema'] == c['privateSecretsSchema'] and
         all(type(secrets[key]) is str and SHA.fullmatch(secrets[key]) for key in ('base', 'candidate')) and
         secrets['base'] != secrets['candidate'])
    bodies = []
    for name in ['base.config.private.yaml', 'candidate.config.private.yaml']:
        body, info = file_bytes(root / name, 1 << 20, 0o600)
        need(info.st_uid == info.st_gid == 10001)
        bodies.append(body)
    need(all(secrets[key].encode('ascii') in bodies[i] for i, key in enumerate(('base', 'candidate'))))
    forbidden = forbidden_variants([secrets['base'].encode('ascii'), secrets['candidate'].encode('ascii')], bodies)
    output = {}
    for name in case_files:
        if name not in names:
            continue  # A failed Start has no stream observation; never invent it.
        limit = 64 << 10 if name.endswith('.exec.json') else c['stdioMaxBytes']
        output[name], info = file_bytes(root / name, limit, 0o600, empty=not name.endswith('.exec.json'))
        need(info.st_uid == info.st_gid == 10001)
        need(not any(value in output[name] for value in forbidden))
    # The confidentiality fence must be the actual stdin, not an unrelated
    # private file with different bytes that happened to pass a canary scan.
    for i, case in enumerate(('base', 'candidate')):
        record = decode(output[case + '.exec.json'])
        need(type(record) is dict and set(record) == set(c['execKeys']) and
             record['inputSHA256'] == sha(bodies[i]) and record['inputBytes'] == len(bodies[i]))
    for case in c['cases']:
        if case + '.exec.json' not in output:
            need(case + '.stdout' not in output and case + '.stderr' not in output)
            continue
        record = decode(output[case + '.exec.json'])
        need(type(record) is dict and set(record) == set(c['execKeys']) and type(record['started']) is bool)
        if record['started']:
            # A hash of a captured prefix does not prove a complete private
            # stream after a copy error, timeout or signal. Keep it private.
            need(record['waitReturned'] is True and record['waitErrorClass'] in ('NONE', 'EXIT_STATUS') and
                 record['timedOut'] is False and record['killSent'] is False and record['signal'] is None)
        for stream in ('stdout', 'stderr'):
            name, metadata = case + '.' + stream, record[stream]
            if not record['started']:
                need(metadata is None and name not in output)
                continue
            need(type(metadata) is dict and set(metadata) == set(c['stdioKeys']) and
                 type(metadata['bytes']) is int and type(metadata['totalBytes']) is int and
                 0 <= metadata['bytes'] == metadata['totalBytes'] <= c['stdioMaxBytes'] and
                 metadata['truncated'] is False and type(metadata['sha256']) is str and SHA.fullmatch(metadata['sha256']) and
                 name in output and len(output[name]) == metadata['bytes'] and sha(output[name]) == metadata['sha256'])
    return output, forbidden


def observed_execution(c, outputs, commit):
    started = []
    for case in c['cases']:
        if case + '.exec.json' not in outputs:
            started.append(None)
            continue
        record = decode(outputs[case + '.exec.json'])
        need(type(record) is dict and set(record) == set(c['execKeys']) and record['schema'] == c['execSchema'] and
             record['sourceCommit'] == commit and record['case'] == case and type(record['started']) is bool)
        if record['started']:
            need(type(record['pid']) is int and record['pid'] >= 2)
        else:
            need(record['pid'] is None)
        started.append(record['started'])
    # A partial observation cannot establish that all four commands started.
    return True if all(started) else None


def main(args):
    global FAILURE_STATE
    c = contract()
    if len(args) == 3 and args[0] == '--sandbox':
        print(canonical(sandbox(c, args[1], args[2])).decode('ascii'), end='')
        return 0
    need(len(args) == 5 and os.name == 'posix' and sys.platform == 'linux' and os.geteuid() == 0)
    repo, out, goroot, consumed = [plain(value) for value in args[:4]]
    commit = args[4]
    need(re.fullmatch('[a-f0-9]{40}', commit) and repo.is_dir() and out.is_dir() and goroot.is_dir())
    need(all(not path.is_relative_to(Path('/tmp')) for path in (repo, out, goroot, consumed)))
    need(not out.is_relative_to(repo) and not consumed.is_relative_to(repo) and not out.is_relative_to(consumed))
    need(set(p.name for p in out.iterdir()) == {'host-before.json', 'consumption.json', 'consumption-independent.json'})
    host_raw, _ = file_bytes(out / 'host-before.json', 4096)
    host = decode(host_raw)
    need(set(host) == {'networkNamespace', 'mountNamespace', 'pidNamespace', 'resolvSHA256'})
    current = namespace_values()
    need(all(current[key] != host[key] for key in current))
    before, original, directory_identity = custody(consumed)
    receipt = decode(original['receipt'])
    need(receipt['schema'] == 'chengwang.mihomo-candidate-consumption/v1' and
         receipt['state'] == 'PINNED_GZIP_EXPANDED_NOT_EXECUTED' and
         receipt['source']['projectSourceCommit'] == commit and
         receipt['elf']['sha256'] == before['elf']['sha256'] and receipt['elf']['bytes'] == before['elf']['bytes'])
    for key in ('runtimeExecuted', 'runtimeCompatibilityProven', 'businessAvailabilityProven',
                'publisherSignatureProven', 'productionApproved', 'production'):
        need(receipt[key] is False)
    for name in ['consumption.json', 'consumption-independent.json']:
        need(file_bytes(out / name, 1 << 20)[0] == original['receipt'])
    original_public = {name: file_bytes(out / name, 1 << 20)[0] for name in
                       ['host-before.json', 'consumption.json', 'consumption-independent.json']}
    FAILURE_STATE = dict(out=out, commit=commit, original=original_public,
                         formatExit=None, goExit=None, observed=None)
    module_raw, _ = file_bytes(repo / 'chengwang/go.mod', 64 << 10)
    need((repo / 'chengwang/vendor').is_dir() and (goroot / 'bin/go').is_file() and (goroot / 'bin/gofmt').is_file())
    command([tool('mount'), '--make-rprivate', '/'])
    command([tool('ip'), 'link', 'set', 'lo', 'up'])
    mount_readonly(repo, repo)
    mount_readonly(goroot, goroot, executable=True)
    command([tool('mount'), '-t', 'tmpfs', '-o', 'nosuid,nodev,mode=755', 'tmpfs', '/tmp'])
    ROOT_PRIVATE.mkdir(mode=0o700)
    paths = c['paths']
    for key in ('module', 'goRoot', 'kernelDirectory'):
        Path(paths[key]).mkdir(mode=0o755)
    for key in ('home', 'privateOutput'):
        Path(paths[key]).mkdir(mode=0o700); os.chown(paths[key], 10001, 10001)
    for name in ('tmp', 'cache', 'mod'):
        p = Path(paths['home']) / name; p.mkdir(mode=0o700); os.chown(p, 10001, 10001)
    mount_readonly(repo / 'chengwang', Path(paths['module']))
    mount_readonly(goroot, Path(paths['goRoot']), executable=True)
    for key, source in [('kernel', original['elf']), ('receipt', original['receipt'])]:
        mode = 0o500 if key == 'kernel' else 0o400
        path = Path(paths[key]); write_new(path, source, mode); os.chown(path, 10001, 10001)
        need(file_bytes(path, len(source), mode)[0] == source)
        mount_readonly(path, path, executable=key == 'kernel')
    EXPORT_ALIAS.mkdir(mode=0o700)
    command([tool('mount'), '--bind', str(out), str(EXPORT_ALIAS)])
    env = environment(c, commit)
    source_worker = str(Path(paths['module']) / 'deploy/mihomo-lifecycle-lab/compat_worker.py')
    sandbox_raw = subprocess.run(unprivileged([tool('python3'), '-B', source_worker, '--sandbox', commit, sha(module_raw)], env),
                                 env=ROOT_ENV, cwd=paths['module'], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    need(sandbox_raw.returncode == 0 and len(sandbox_raw.stdout) <= 64 << 10)
    facts = decode(sandbox_raw.stdout)
    need(facts['kernelCopy']['sha256'] == before['elf']['sha256'] and
         facts['kernelCopy']['bytes'] == before['elf']['bytes'])
    format_exit = go_exit = None
    observed = None
    outputs = {}
    # Commands execute from the exact module alias, not GOROOT or the host path.
    def capture(argv, name, err_name, timeout):
        with (ROOT_PRIVATE / name).open('xb') as stdout, (ROOT_PRIVATE / err_name).open('xb') as stderr:
            process = subprocess.Popen(unprivileged(argv, env), env=ROOT_ENV, cwd=paths['module'],
                                       stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL); code = process.wait()
            stdout.flush(); stderr.flush(); os.fsync(stdout.fileno()); os.fsync(stderr.fileno())
        return code
    version_exit = capture([paths['goRoot'] + '/bin/go', 'version'], 'go-version.txt', 'go-version.private.stderr', 15)
    need(version_exit == 0 and file_bytes(ROOT_PRIVATE / 'go-version.txt', 4096)[0] == b'go version go1.23.12 linux/amd64\n')
    format_exit = capture([paths['goRoot'] + '/bin/gofmt', '-d', 'internal/mihomodeploy/runtime_compat_linux_test.go'],
                          'gofmt.patch', 'gofmt.stderr', 30)
    FAILURE_STATE['formatExit'] = format_exit
    go_exit = capture([paths['goRoot'] + '/bin/go', 'test', '-json', '-count=1', '-shuffle=off',
                       '-tags=chengwang_mihomo_compat', '-run=^TestMihomoCompat',
                       '-timeout=' + str(c['goTimeoutSeconds']) + 's', './internal/mihomodeploy'],
                      'compat.json', 'compat.stderr', c['goTimeoutSeconds'])
    FAILURE_STATE['goExit'] = go_exit
    after, _, after_directory = custody(consumed)
    need(before == after and directory_identity == after_directory)
    facts['inputCustody'] = dict(before=before, after=after)
    need(set(facts) == set(c['sandboxKeys']))
    safe_error = None
    try:
        outputs, forbidden = private_outputs(c)
        for name in ['compat.json', 'compat.stderr', 'gofmt.patch', 'gofmt.stderr', 'go-version.txt']:
            raw, _ = file_bytes(ROOT_PRIVATE / name, MAX_LOG, empty=True)
            need(not any(value in raw for value in forbidden)); outputs[name] = raw
        observed = observed_execution(c, outputs, commit)
        FAILURE_STATE['observed'] = observed
    except Exception:
        outputs = {}
        safe_error = b'MIHOMO_COMPAT_PRIVATE_FENCE_UNAVAILABLE_OR_REJECTED raw_output_suppressed=true\n'
    execution = dict(schema=c['executionSchema'], sourceCommit=commit, formatExit=format_exit,
                     goExit=go_exit, realMihomoExecutionObserved=observed, production=False)
    need(set(execution) == set(c['executionKeys']))
    outputs['sandbox.json'] = canonical(facts)
    outputs['execution.json'] = canonical(execution)
    if safe_error is not None: outputs['compat.stderr'] = safe_error
    need(set(outputs) <= set(c['publicFiles']) - set(original_public) - {'host-after.json'})
    for name, raw in outputs.items():
        write_new(EXPORT_ALIAS / name, raw, 0o644)
    for name, raw in original_public.items(): need(file_bytes(out / name, 1 << 20)[0] == raw)
    need(all(name not in set(p.name for p in out.iterdir()) for name in c['privateExtraFiles']))
    if safe_error is not None or format_exit != 0 or go_exit != 0 or outputs.get('gofmt.patch') or outputs.get('gofmt.stderr'):
        return go_exit if type(go_exit) is int and go_exit > 0 else 1
    need(set(p.name for p in out.iterdir()) == set(c['publicFiles']) - {'host-after.json'})
    print('MIHOMO_COMPAT_WORKER=CAPTURED independent_verification=pending production=false')
    return 0


def report_failure():
    # Only fixed diagnostics are recoverable without a complete private fence.
    # Never copy a raw Go/ELF stream on this path or replace an earlier witness.
    if FAILURE_STATE is None:
        return
    state = FAILURE_STATE
    try:
        out = plain(state['out'])
        for name, raw in state['original'].items():
            need(file_bytes(out / name, 1 << 20)[0] == raw)
        execution = dict(schema='chengwang.mihomo-compat-execution/v1', sourceCommit=state['commit'],
                         formatExit=state['formatExit'], goExit=state['goExit'],
                         realMihomoExecutionObserved=state['observed'], production=False)
        for name, raw in [('execution.json', canonical(execution)),
                          ('compat.stderr', b'MIHOMO_COMPAT_WORKER_REJECTED raw_output_suppressed=true\n')]:
            if not (out / name).exists():
                write_new(out / name, raw, 0o644)
    except Exception:
        pass


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception:
        report_failure()
        raise SystemExit('MIHOMO_COMPAT_WORKER=REJECTED raw_input_suppressed=true') from None
