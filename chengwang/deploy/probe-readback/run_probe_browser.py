"""Isolated browser extension of the real native lab; never a product daemon.

The unchanged native 22-file protocol remains backend-only. Extra source,
process, static-build and browser observations cross a separate public boundary.
All executable inputs are prebuilt by CI; this module never invokes Go/npm.
"""
from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

try:
    import resource
except ImportError:  # Pure contract imports only; runtime still requires Linux.
    resource = None


def load_native():
    parent = pathlib.Path(__file__).resolve().parent
    path = parent / ('runner' if pathlib.Path(__file__).name == 'browser-runner' else 'run_probe_readback.py')
    loader = importlib.machinery.SourceFileLoader('probe_browser_native', str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    value = importlib.util.module_from_spec(spec)
    loader.exec_module(value)
    return value


N = load_native()


def load_status_diagnostics():
    # -I intentionally excludes import-by-cwd. The exact helper is copied into
    # the owned bundle and appears in the existing source-bound copy manifest.
    path = pathlib.Path(__file__).resolve().parent / 'probe_status_diagnostics.py'
    loader = importlib.machinery.SourceFileLoader('probe_status_diagnostic_projection', str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    value = importlib.util.module_from_spec(spec)
    loader.exec_module(value)
    return value


STATUS_DIAGNOSTICS = load_status_diagnostics()


def load_browser_identity():
    path = pathlib.Path(__file__).resolve().parent / 'probe_browser_identity.py'
    loader = importlib.machinery.SourceFileLoader('probe_browser_identity_projection', str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    value = importlib.util.module_from_spec(spec)
    loader.exec_module(value)
    return value


BROWSER_IDENTITY = load_browser_identity()
STAGE = 'ARGUMENTS'
ENGINES = ('chrome-cdp', 'playwright')
ERRORS = frozenset(('ARGUMENTS', 'COPY_INPUT', 'COPY_LIMIT', 'COPY_LINK', 'BROWSER_CONFIG',
    'BROWSER_PREWARM', 'BROWSER_FAILED', 'BROWSER_DEADLINE', 'BROWSER_IDENTITY', 'BROWSER_JOIN',
    'BROWSER_EXPORT', 'BROWSER_ROLE', 'BROWSER_FRESH', 'UNEXPECTED')) | N.FAILURE_CODES


def need(value, code):
    N.require(value, code)


def public_failure_diagnostic(bundle):
    """Expose only closed phase/code enums, never arbitrary browser stderr."""
    for relative, pattern in (
        ('supervisor.private', r'^PROBE_BROWSER_LAB=FAIL stage=([A-Z_]+) code=([A-Z_]+) raw_input_suppressed=true$'),
        ('logs/browser.private', r'^PROBE_BROWSER_CONTROLLER=FAIL stage=([A-Z_]+) raw_input_suppressed=true$'),
        ('logs/browser.private', r'^PROBE_BROWSER_DRIVER_STAGE=([A-Z_]+)$'),
        ('logs/browser.private', r'^PROBE_BROWSER_FLOW_STAGE=([A-Z_]+)$'),
        ('logs/browser.private', r'^PROBE_BROWSER_PAIR_STAGE=([A-Z_]+)$'),
        ('logs/browser.private', r'^PROBE_BROWSER_DRIVER_OPERATION=([A-Z_]+)$'),
        ('logs/browser.private', r'^PROBE_BROWSER_NETWORK_FAILURE=(SNAPSHOT|OBSERVATIONS|PROBE_STATUS|PROBE_DETAILS):(CANCELED|NOT_CANCELED|CANCEL_UNKNOWN):(ABORTED|OTHER):(RUNNING|CLOSING)$'),
        ('logs/browser.private', r'^PROBE_BROWSER_NETWORK_FAILURE_TIMING=(SNAPSHOT|OBSERVATIONS|PROBE_STATUS|PROBE_DETAILS):(NO_HEADERS|HTTP_2XX|HTTP_3XX|HTTP_4XX|HTTP_5XX|HTTP_OTHER):(AGE_LT1S|AGE_1_9S|AGE_9_11S|AGE_GE11S|AGE_UNKNOWN)$'),
        ('logs/browser.private', r'^PROBE_BROWSER_LAUNCH_ERROR=([A-Z_]+)$'),
        ('logs/browser.private', r'^PROBE_BROWSER_LAUNCH_FATAL=((?:base|chrome|content|components|sandbox|third_party)/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.cc):([1-9][0-9]{0,5})$'),
    ):
        path = bundle / relative
        if not path.exists():
            continue
        # Extra diagnostics have their own bounded closed decoder. The legacy
        # projections below still export only their original exact regexes.
        raw = N.stable_read(path, STATUS_DIAGNOSTICS.MAX_LOG_BYTES if relative == 'logs/browser.private' else 65536)[0]
        for line in raw.decode('utf-8', errors='replace').splitlines():
            match = re.fullmatch(pattern, line)
            if not match:
                continue
            if line.startswith(('PROBE_BROWSER_NETWORK_FAILURE=', 'PROBE_BROWSER_NETWORK_FAILURE_TIMING=')):
                sys.stderr.write(line + '\n')
                continue
            if line.startswith('PROBE_BROWSER_LAUNCH_FATAL='):
                if len(match[1]) <= 200:
                    sys.stderr.write(line + '\n')
                continue
            stages = {'ARGUMENTS', 'PREWARM', 'FLOW', 'WAIT_EXPIRED', 'EXPIRED', 'CLOSE', 'DONE', 'FRESH', 'UNEXPECTED',
                      'ENVIRONMENT', 'HOME', 'DIRECTORIES', 'CONFIG', 'CERTIFICATES',
                      'NSS_INIT', 'NSS_IMPORT', 'NSS_READBACK', 'LAUNCH', 'IDENTITY', 'READY',
                      'CLOSE_DRAIN', 'CLOSE_COMMAND', 'CLOSE_WAIT', 'CLOSE_SCAN', 'CLOSE_GUARD', 'CLOSE_RESCAN', 'CLOSE_DONE', 'EVIDENCE',
                      'NAVIGATE', 'NAVIGATION', 'FRESH_TOKEN', 'FRESH_API', 'FRESH_EXPAND',
                      'FRESH_DESKTOP', 'FRESH_MOBILE', 'CLEAR', 'ANONYMOUS', 'HELD_FRESH', 'WITHDRAWN',
                      'CLICK', 'CLICK_TEXT', 'FILL', 'VIEWPORT', 'SNAPSHOT', 'SCREENSHOT', 'NETWORK',
                      'EXPIRED_SUMMARY', 'EXPIRED_FILL', 'EXPIRED_DETAILS', 'EXPIRED_MODEL', 'EXPIRED_GENERATION', 'EXPIRED_PUBLISH',
                      'PERMISSION', 'MODULE_NOT_FOUND', 'PYTHON_STARTUP', 'SHARED_LIBRARY', 'LAUNCHER_REJECTED', 'UNKNOWN'}
            if match[1] in stages and (len(match.groups()) == 1 or match[2] in ERRORS):
                sys.stderr.write(line + '\n')


def public_status_diagnostic(bundle, output, source_commit, engine):
    """Separate diagnostic artifact, never inside the old browser/backend set."""
    path = bundle / 'logs/browser.private'
    if not path.exists():
        return
    raw = N.stable_read(path, STATUS_DIAGNOSTICS.MAX_LOG_BYTES)[0]
    value = STATUS_DIAGNOSTICS.project(raw)
    value.update(sourceCommit=source_commit, engine=engine,
                 clockDomains='JS_MOUNT_MS_CDP_MONOTONIC_US_CDP_EPOCH_US_NOT_INTERCHANGEABLE')
    N.exclusive(output / 'status-diagnostic.json', N.canonical(value) + b'\n')
    print('PROBE_STATUS_DIAGNOSTIC=CAPTURED acceptance_proven=false complete=' + str(value['complete']).lower())


def public_browser_identity(bundle, output, source_commit, engine, fixture, copies):
    path = bundle / 'logs/browser.private'
    if not path.exists():
        return
    raw = N.stable_read(path, BROWSER_IDENTITY.MAX_LOG)[0]
    value = BROWSER_IDENTITY.project(raw, source_commit, engine, fixture, copies)
    N.exclusive(output / 'browser-identity.json', N.canonical(value) + b'\n')
    print('BROWSER_IDENTITY=CAPTURED patch_ancestry_proven=false state=' + value['state'])


def check_public_archive(root):
    """Only the exported Vite build manifest may cross as a hidden entry."""
    need(root.is_dir() and not root.is_symlink(), 'BROWSER_EXPORT')
    count, total = 0, 0
    for path in root.rglob('*'):
        need(not path.is_symlink(), 'BROWSER_EXPORT')
        relative = path.relative_to(root).as_posix()
        hidden = any(part.startswith('.') for part in path.relative_to(root).parts)
        if hidden:
            need(relative in ('lab/browser/web/.vite', 'lab/browser/web/.vite/manifest.json'), 'BROWSER_EXPORT')
            need(path.is_dir() if relative.endswith('/.vite') else path.is_file(), 'BROWSER_EXPORT')
        if path.is_dir():
            continue
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 16 << 20, 'BROWSER_EXPORT')
        count += 1; total += info.st_size
        need(count <= 4096 and total <= 64 << 20, 'BROWSER_EXPORT')
    need(count > 0, 'BROWSER_EXPORT')


def configuration(bundle):
    raw, info = N.stable_read(bundle / 'browser-config.json', 16384, mode=0o440)
    need(info.st_uid == 0 and info.st_gid == 10001, 'BROWSER_CONFIG')
    value = N.decode(raw)
    match = N.TOOLS_RE.fullmatch(str(bundle))
    need(match and type(value) is dict and set(value) == {'schema', 'engine', 'root', 'chrome'}
         and value['schema'] == 'chengwang.probe-browser-config/v1' and value['engine'] in ENGINES
         and value['root'] == '/tmp/chengwang-probe-readback-' + bundle.name.rsplit('-', 1)[1], 'BROWSER_CONFIG')
    return value


def copy_file(source, target, manifest, label, mode=0o440):
    raw, info = N.stable_read(source, 512 << 20)
    need(not info.st_mode & 0o022, 'COPY_INPUT')
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    N.exclusive(target, raw, mode)
    os.chown(target, 0, 10001)
    need(N.stable_read(target, 512 << 20)[0] == raw, 'COPY_INPUT')
    manifest.append({'path': label, 'bytes': len(raw), 'sha256': N.sha(raw)})


def copy_tree(source, destination, manifest, prefix, *, executable_inputs=False):
    need(source.is_dir() and not source.is_symlink(), 'COPY_INPUT')
    for current, dirs, files in os.walk(source, followlinks=False):
        dirs.sort(); files.sort()
        relative = pathlib.Path(current).relative_to(source)
        need(len(relative.parts) <= 24, 'COPY_LIMIT')
        for name in dirs + files:
            need(not (pathlib.Path(current) / name).is_symlink(), 'COPY_LINK')
        for name in files:
            rel = (relative / name).as_posix()
            need(re.fullmatch(r'[A-Za-z0-9_./@+-]+', rel) and '..' not in pathlib.PurePosixPath(rel).parts, 'COPY_INPUT')
            original = pathlib.Path(current) / name
            mode = 0o550 if executable_inputs and original.lstat().st_mode & 0o111 else 0o440
            copy_file(original, destination / rel, manifest, prefix + '/' + rel, mode)
            need(len(manifest) <= 8192 and sum(item['bytes'] for item in manifest) <= 1536 << 20, 'COPY_LIMIT')


def prepare_browser_bundle(options, source):
    bundle, tools = N.prepare_bundle(options, source)
    records = []
    try:
        copy_file(pathlib.Path(__file__), bundle / 'browser-runner', records,
                  'chengwang/deploy/probe-readback/run_probe_browser.py', 0o550)
        copy_file(source / 'chengwang/deploy/probe-readback/probe_status_diagnostics.py',
                  bundle / 'probe_status_diagnostics.py', records,
                  'chengwang/deploy/probe-readback/probe_status_diagnostics.py')
        copy_file(source / 'chengwang/deploy/probe-readback/probe_browser_identity.py',
                  bundle / 'probe_browser_identity.py', records,
                  'chengwang/deploy/probe-readback/probe_browser_identity.py')
        copy_file(source / 'chengwang/deploy/probe-readback/probe_chrome_launcher.py',
                  bundle / 'chrome-launcher', records, 'chengwang/deploy/probe-readback/probe_chrome_launcher.py', 0o550)
        copy_file(pathlib.Path(options.node), bundle / 'browser-node', records, 'toolchain/node', 0o550)
        # /home/runner may be 0750. The low-privilege browser must not traverse
        # it: keep the entire acquired distribution in this traversable bundle.
        copy_tree(pathlib.Path(options.chrome).parent, bundle / 'chrome', records,
                  'toolchain/chrome', executable_inputs=True)
        alias = bundle / 'source'
        directory = source / 'chengwang/tools/probe-browser'
        for name in ('package.json', 'package-lock.json', 'probe-browser-contract.mjs', 'run-browser.mjs',
                     'browser-driver.mjs', 'browser-cli.mjs', 'probe-status-diagnostics.mjs', 'browser-identity.mjs'):
            copy_file(directory / name, alias / 'chengwang/tools/probe-browser' / name,
                      records, 'chengwang/tools/probe-browser/' + name)
        copy_tree(directory / 'node_modules/playwright-core',
                  alias / 'chengwang/tools/probe-browser/node_modules/playwright-core', records, 'npm/playwright-core')
        for rel in ('chengwang/web/scripts/trust-browser-tls.mjs',
                    'chengwang/tools/image-binding/scripts/browser-process-guard.py'):
            copy_file(source / rel, alias / rel, records, rel)
        copy_tree(pathlib.Path(options.web_dir), bundle / 'web', records, 'built-web')
        for name in ('NotoSansCJKsc-Regular.otf', 'NotoSansCJKsc-Bold.otf', 'LICENSE'):
            copy_file(pathlib.Path(options.fonts_dir) / name, bundle / 'fonts' / name, records, 'fonts/' + name)
        font_xml = ('<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd"><fontconfig><dir>'
                    + str(bundle / 'fonts') + '</dir><cachedir>' + options.fixture_root
                    + '/browser/font-cache</cachedir></fontconfig>').encode()
        N.exclusive(bundle / 'fonts/fonts.conf', font_xml, 0o440)
        os.chown(bundle / 'fonts/fonts.conf', 0, 10001)
        config = dict(schema='chengwang.probe-browser-config/v1', engine=options.engine,
                      root=options.fixture_root, chrome=str(bundle / 'chrome/chrome'))
        N.exclusive(bundle / 'browser-config.json', N.canonical(config), 0o440)
        passwd = ('root:x:0:0:root:/root:/usr/sbin/nologin\nprobe-browser:x:10001:10001:probe:'
                  + options.fixture_root + '/browser/home:/usr/sbin/nologin\n').encode()
        for name, raw in (('browser-passwd', passwd), ('browser-group', b'root:x:0:\nprobe-browser:x:10001:\n')):
            N.exclusive(bundle / name, raw, 0o440)
            os.chown(bundle / name, 0, 10001)
        os.chown(bundle / 'browser-config.json', 0, 10001)
        # Only new copies receive these permissions, never the checkout or npm cache.
        for current, dirs, _files in os.walk(bundle):
            if pathlib.Path(current) == bundle / 'logs':
                continue
            for name in dirs:
                path = pathlib.Path(current) / name
                if path != bundle / 'logs':
                    os.chown(path, 0, 10001); path.chmod(0o550)
        return bundle, tools, records
    except BaseException:
        N.cleanup_bundle(bundle)
        raise


def browser_temporary_mount():
    """Short AF_UNIX paths in the browser's already-private mount namespace.

    Overlay only: never chmod, empty or write the host's /var/tmp contents.
    The mount dies with the role namespace and cannot contain executables.
    """
    target = '/var/tmp'
    temporary = pathlib.Path(target)
    original = temporary.lstat()
    need(stat.S_ISDIR(original.st_mode) and not temporary.is_symlink(), 'BROWSER_ROLE')
    N.command(['mount', '-t', 'tmpfs', '-o',
               'size=64m,mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec',
               'chengwang-probe-browser-tmp', target])
    mounted = temporary.lstat()
    need(stat.S_ISDIR(mounted.st_mode) and stat.S_IMODE(mounted.st_mode) == 0o700
         and mounted.st_uid == mounted.st_gid == 10001, 'BROWSER_ROLE')
    flags = N.mount_flags('self', temporary)
    need(all(flag in flags for flag in ('rw', 'nosuid', 'nodev', 'noexec')), 'BROWSER_ROLE')
    records = [line.split(' - ', 1)[1].split()[0]
               for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines()
               if ' - ' in line and line.split(' - ', 1)[0].split()[4] == target]
    need(records and records[-1] == 'tmpfs', 'BROWSER_ROLE')
    return target


def configure_browser_role(options):
    root, bundle = pathlib.Path(options.fixture_root), pathlib.Path(options.bundle)
    need(os.geteuid() == 0 and N.ROOT_RE.fullmatch(str(root)) and N.TOOLS_RE.fullmatch(str(bundle)), 'BROWSER_ROLE')
    parent = pathlib.Path('/proc/1/cmdline').read_bytes().split(b'\0')
    here, init = N.ns(), N.ns(1)
    need(os.getppid() == 1 and str(bundle / 'browser-runner').encode() in parent and b'--inner' in parent
         and here['pid'] == init['pid'] and here['net'] == init['net'] and here['mnt'] != init['mnt'], 'BROWSER_ROLE')
    config = configuration(bundle)
    N.command(['mount', '--make-rprivate', '/'])
    temporary = browser_temporary_mount()
    N.mount_bind(root, True)
    N.mount_bind(root / 'browser', False)
    for name, destination in (('browser-passwd', '/etc/passwd'), ('browser-group', '/etc/group')):
        N.command(['mount', '--bind', str(bundle / name), destination])
        N.command(['mount', '-o', 'remount,bind,ro,nosuid,nodev', destination])
    # Never inherit an inaccessible /home/runner checkout as the low-UID
    # interpreter/browser working directory. All code paths remain absolute.
    os.chdir(root / 'browser')
    environment = dict(N.BASE_ENV)
    environment['TMPDIR'] = temporary
    for key, value in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, 180),
                       (resource.RLIMIT_FSIZE, 32 << 20), (resource.RLIMIT_NOFILE, 1024), (resource.RLIMIT_NPROC, 1024)):
        resource.setrlimit(key, (value, value))
    os.umask(0o077)
    command = ['setpriv', '--reuid=10001', '--regid=10001', '--clear-groups', '--bounding-set=-all',
               '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs', str(bundle / 'browser-node'),
               str(bundle / 'source/chengwang/tools/probe-browser/browser-cli.mjs'),
               '--root', str(root), '--engine', config['engine'], '--chrome', config['chrome'],
               '--launcher', str(bundle / 'chrome-launcher'), '--source-root', str(bundle / 'source'),
               '--source-commit', options.source_commit]
    os.execvpe('setpriv', command, environment)


class BrowserLab(N.Lab):
    def __init__(self, options):
        super().__init__(options)
        self.browser = None
        self.browser_records = []
        self.browser_exit = None
        self.chrome_arguments = None
        self.chrome_executable = None

    def role_entrypoint(self):
        return self.bundle / 'browser-runner'

    def wait_browser(self, predicate, timeout=20):
        until = time.monotonic() + timeout
        while True:
            self.check_budget()
            need(self.browser is not None and self.browser.poll() is None, 'BROWSER_FAILED')
            if predicate():
                return
            need(time.monotonic() < until, 'BROWSER_DEADLINE')
            time.sleep(0.025)

    def private_signal_ready(self, name):
        path = self.root / 'browser' / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 10001
             and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 16384, 'BROWSER_IDENTITY')
        # The Node publisher links a complete private pending file and unlinks
        # that name before signaling. Never read during transient nlink=2.
        need(info.st_nlink in (1, 2), 'BROWSER_IDENTITY')
        if info.st_nlink != 1:
            return False
        value = N.decode(N.stable_read(path, 16384, 10001, 0o600)[0])
        if name == 'prewarmed.private.json':
            need(type(value) is dict and set(value) == {'schema', 'engine', 'sourceCommit'}
                 and value['schema'] == 'chengwang.probe-browser-ready/v1'
                 and value['engine'] == configuration(self.bundle)['engine']
                 and value['sourceCommit'] == self.options.source_commit, 'BROWSER_IDENTITY')
        else:
            need(name == 'fresh-complete.private.json' and type(value) is dict
                 and set(value) == {'phase', 'observedAt'} and value['phase'] == 'fresh-complete', 'BROWSER_IDENTITY')
            N.timestamp_ns(value['observedAt'])
        return True

    def after_prepared(self):
        global STAGE
        STAGE = 'PREWARM'
        for path in (self.root / 'browser', self.root / 'browser/out', self.root / 'browser/tmp'):
            path.mkdir(mode=0o700); os.chown(path, 10001, 10001)
        descriptor = os.open(self.private_logs / 'browser.private', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            self.browser = subprocess.Popen(['unshare', '--mount', sys.executable, '-I', '-B',
                str(self.bundle / 'browser-runner'), '--role', 'browser', '--fixture-root', str(self.root),
                '--bundle', str(self.bundle), '--source-commit', self.options.source_commit],
                stdin=subprocess.DEVNULL, stdout=descriptor, stderr=descriptor, env=N.BASE_ENV)
        finally:
            os.close(descriptor)
        self.wait_browser(lambda: self.private_signal_ready('prewarmed.private.json'))
        handoff = N.decode(N.stable_read(self.root / 'browser/chrome-process.private.json', 4096, 10001, 0o600)[0])
        controller = N.task_profile(self.browser.pid, N.sha(N.stable_read(self.bundle / 'browser-node', 256 << 20)[0]), executable_limit=256 << 20)
        chrome_path = configuration(self.bundle)['chrome']
        chrome_bytes = N.stable_read(chrome_path, 512 << 20)[0]
        chrome = N.task_profile(handoff['pid'], N.sha(chrome_bytes), executable_limit=512 << 20)
        arguments = pathlib.Path('/proc', str(handoff['pid']), 'cmdline').read_bytes()
        need(arguments.endswith(b'\0') and N.sha(arguments) == chrome['argvSHA256'], 'BROWSER_IDENTITY')
        actual_arguments = arguments[:-1].decode('utf-8').split('\0')
        need(0 < len(actual_arguments) <= 128 and all(0 < len(arg) <= 8192 and
             re.fullmatch(r'[\x20-\x7e]+', arg) for arg in actual_arguments), 'BROWSER_IDENTITY')
        private_tokens = [N.stable_read(self.root / (name + '-token.private'), 4096, 10001, 0o600)[0]
                          for name in ('viewer', 'foreign')]
        need(not any(token in arguments for token in private_tokens)
             and b'Bearer ' not in arguments and b'PRIVATE KEY' not in arguments, 'BROWSER_EXPORT')
        self.chrome_arguments = actual_arguments
        self.chrome_executable = dict(path=chrome_path, bytes=len(chrome_bytes), sha256=N.sha(chrome_bytes),
                                     sourceScope='TRUSTED_CI_SYSTEM_TOOL_NOT_INDEPENDENT_SUPPLY_CHAIN')
        need(chrome['startTime'] == str(handoff['startTicks']) and handoff['uid'] == 10001
             and os.getpgid(handoff['pid']) == os.getsid(handoff['pid']) == handoff['pid'], 'BROWSER_IDENTITY')
        self.browser_records = [{'role': 'controller', **controller}, {'role': 'chrome', **chrome}]

    def after_restarted(self, minimum, maximum):
        global STAGE
        STAGE = 'FRESH'
        while time.time_ns() < minimum - 25_000_000_000:
            self.wait_browser(lambda: True)
            time.sleep(0.05)
        need(time.time_ns() < minimum - 20_000_000_000, 'BROWSER_FRESH')
        signal_body = dict(schema='chengwang.probe-browser-phase/v1', phase='fresh',
                           minExpiryUnixNano=str(minimum), maxExpiryUnixNano=str(maximum))
        N.publish_atomic(self.root / 'browser/fresh.go', N.canonical(signal_body), 0o444)
        self.wait_browser(lambda: self.private_signal_ready('fresh-complete.private.json'), 15)
        need(time.time_ns() < minimum - 5_000_000_000, 'BROWSER_FRESH')

    def after_expired(self):
        global STAGE
        STAGE = 'EXPIRED'
        N.publish_atomic(self.root / 'browser/expired.go', b'{"phase":"expired"}', 0o444)
        until = time.monotonic() + 25
        while self.browser.poll() is None:
            self.check_budget()
            need(time.monotonic() < until, 'BROWSER_DEADLINE')
            time.sleep(0.025)
        need(self.browser.returncode == 0, 'BROWSER_JOIN')
        observed = N.decode(N.stable_read(self.root / 'browser/chrome-exit.private.json', 4096, 10001, 0o600)[0])
        chrome = self.browser_records[1]
        need(observed['pid'] == chrome['pid'] and str(observed['startTicks']) == chrome['startTime']
             and type(observed['exitCode']) is int and observed['exitCode'] == 0
             and observed['joined'] is True and observed['forced'] is False, 'BROWSER_JOIN')
        self.browser_exit = observed
        output = pathlib.Path(self.options.output_dir).parent / 'browser'
        secrets = [N.stable_read(self.root / (name + '-token.private'), 4096, 10001, 0o600)[0]
                   for name in ('viewer', 'foreign')]
        files = []
        for path in sorted((self.root / 'browser/out').iterdir()):
            need(re.fullmatch(r'(?:probe-browser-(?:cdp|playwright)-[a-z-]+\.(?:png|json|jsonl)|browser-(?:captures|driver)\.json)', path.name), 'BROWSER_EXPORT')
            raw, _ = N.stable_read(path, 8 << 20, 10001, 0o600)
            need(not any(secret in raw for secret in secrets) and b'PRIVATE KEY' not in raw and b'Bearer ' not in raw, 'BROWSER_EXPORT')
            N.exclusive(output / path.name, raw)
            files.append(dict(path=path.name, bytes=len(raw), sha256=N.sha(raw)))
        N.exclusive(output / 'browser-processes.json', N.canonical(dict(schema='chengwang.probe-browser-processes/v1',
            sourceCommit=self.options.source_commit, records=self.browser_records,
            chromeArgv=self.chrome_arguments, chromeExecutable=self.chrome_executable,
            controllerExitCode=self.browser.returncode, chromeExit=observed,
            webReadOnlyMounts=[dict(role=row['role'], flags=N.mount_flags(row['pid'], self.bundle / 'web'))
                              for row in self.records if row['role'] == 'api-second'],
            files=files, production=False)) + b'\n')

    def publish_launch_failure(self):
        if self.browser is not None and self.browser.poll() != 0:
            diagnostic = dict(schema='chengwang.probe-browser-launch-failure/v1',
                sourceCommit=self.options.source_commit, stage=STAGE,
                controllerRunning=self.browser.poll() is None, launcherHandoffObserved=False,
                chromeWaitObserved=False, chromeExitCode=None, runtimeAcceptanceProven=False, production=False)
            handoff = self.root / 'browser/chrome-process.private.json'
            if handoff.exists():
                value = N.decode(N.stable_read(handoff, 4096, 10001, 0o600)[0])
                need(type(value) is dict and set(value) == {'pid', 'startTicks', 'uid', 'profile'}
                     and type(value['pid']) is int and type(value['startTicks']) is int
                     and value['uid'] == 10001 and value['profile'] == str(self.root / 'browser/chrome-profile'), 'BROWSER_IDENTITY')
                diagnostic['launcherHandoffObserved'] = True
            stopped = self.root / 'browser/chrome-exit.private.json'
            if stopped.exists():
                value = N.decode(N.stable_read(stopped, 4096, 10001, 0o600)[0])
                need(type(value) is dict and set(value) == {'schema', 'engine', 'fixtureId', 'pid', 'startTicks', 'exitCode', 'joined', 'forced'}
                     and value['schema'] == 'chengwang.probe-chrome-exit/v1' and type(value['exitCode']) is int
                     and -128 <= value['exitCode'] <= 255 and value['joined'] is True, 'BROWSER_IDENTITY')
                diagnostic['chromeWaitObserved'] = True
                diagnostic['chromeExitCode'] = value['exitCode']
            N.exclusive(pathlib.Path(self.options.output_dir).parent / 'browser-launch-failure.json', N.canonical(diagnostic) + b'\n')

    def emergency(self):
        try:
            self.publish_launch_failure()
            # Preserve only outputs already admitted by the public capture
            # writer. Failure candidates never satisfy either runtime gate.
            if self.browser is not None and self.browser.poll() not in (None, 0):
                preserve_failed_captures(self.root, pathlib.Path(self.options.output_dir).parent)
        except Exception:
            # Diagnostic rejection is not success and must never stop the
            # mandatory shutdown/PID-namespace cleanup path.
            pass
        finally:
            try:
                if self.browser is not None and self.browser.poll() is None:
                    self.browser.terminate()
                    try:
                        self.browser.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        self.browser.kill(); self.browser.wait(timeout=3)
            finally:
                super().emergency()


def preserve_failed_captures(root, output):
    source = root / 'browser/out'
    if not source.is_dir() or source.is_symlink():
        return
    tokens = [N.stable_read(root / (name + '-token.private'), 4096, 10001, 0o600)[0]
              for name in ('viewer', 'foreign')]
    candidates = sorted(source.iterdir())
    need(len(candidates) <= 20, 'BROWSER_EXPORT')
    records, contents, total = [], [], 0
    for path in candidates:
        need(re.fullmatch(r'(?:probe-browser-(?:cdp|playwright)-(?:fresh|cleared|withdrawn|expired)-(?:status|details|dom|network|desktop|mobile)\.(?:png|json|jsonl)|browser-(?:captures|driver)\.json)', path.name), 'BROWSER_EXPORT')
        raw, _ = N.stable_read(path, 8 << 20, 10001, 0o600)
        total += len(raw)
        need(total <= 64 << 20 and not any(token in raw for token in tokens)
             and b'PRIVATE KEY' not in raw and b'Bearer ' not in raw, 'BROWSER_EXPORT')
        contents.append((path.name, raw))
        records.append(dict(path=path.name, bytes=len(raw), sha256=N.sha(raw)))
    destination = output / 'failed-browser'
    destination.mkdir(mode=0o755)
    for name, raw in contents:
        N.exclusive(destination / name, raw)
    N.exclusive(destination / 'failure-candidates.json', N.canonical(dict(
        schema='chengwang.probe-browser-failure-candidates/v1',
        runtimeAcceptanceProven=False, production=False, files=records)) + b'\n')


def arguments(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self, _message):
            raise N.Failure('ARGUMENTS')
    parser = Parser(add_help=False)
    for name in ('agent', 'server', 'driver', 'source-commit', 'output-dir', 'web-dir', 'fonts-dir',
                 'node', 'chrome', 'engine', 'fixture-root', 'bundle', 'source-root', 'fixture-id', 'role', 'action', 'phase'):
        parser.add_argument('--' + name, default='')
    parser.add_argument('--inner', action='store_true')
    options = parser.parse_args(argv)
    need(N.COMMIT_RE.fullmatch(options.source_commit), 'ARGUMENTS')
    if options.role:
        need(options.role in (*N.ROLES, 'driver', 'browser'), 'ARGUMENTS')
    elif options.inner:
        need(N.ROOT_RE.fullmatch(options.fixture_root) and N.TOOLS_RE.fullmatch(options.bundle)
             and options.fixture_root.endswith(options.fixture_id), 'ARGUMENTS')
    else:
        need(options.engine in ENGINES, 'ARGUMENTS')
        for name in ('agent', 'server', 'driver', 'web_dir', 'fonts_dir', 'node', 'chrome', 'output_dir'):
            value = getattr(options, name)
            need(value, 'ARGUMENTS'); N.checked_path(value, name in ('web_dir', 'fonts_dir', 'output_dir'))
    return options


def outer(options):
    global STAGE
    source = pathlib.Path(__file__).resolve().parents[3]
    output = N.checked_path(options.output_dir, True)
    need(not list(output.iterdir()), 'OUTPUT_NOT_EMPTY')
    for name in ('backend', 'browser'):
        # Public evidence lives under the caller's private 0700 output root.
        # Root-created child directories must remain readable to that caller
        # for the independent verifier and artifact upload (never private logs).
        (output / name).mkdir(mode=0o755)
        (output / name).chmod(0o755)
    options.fixture_id = uuid.uuid4().hex
    options.fixture_root = '/tmp/chengwang-probe-readback-' + options.fixture_id
    root = pathlib.Path(options.fixture_root)
    root.mkdir(mode=0o700); os.chown(root, 10001, 10001)
    options.output_dir = str(output / 'backend')
    bundle = supervisor = None
    try:
        STAGE = 'BUNDLE'
        before, files_before = N.host_observation(source, options.source_commit)
        bundle, tools, copies = prepare_browser_bundle(options, source)
        descriptor = os.open(bundle / 'supervisor.private', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            supervisor = subprocess.Popen(['unshare', '--mount', '--net', '--pid', '--fork', '--kill-child=SIGTERM', '--mount-proc',
                sys.executable, '-I', '-B', str(bundle / 'browser-runner'), '--inner', '--fixture-root', str(root),
                '--bundle', str(bundle), '--source-root', str(source), '--fixture-id', options.fixture_id,
                '--source-commit', options.source_commit, '--output-dir', options.output_dir],
                stdin=subprocess.DEVNULL, stdout=descriptor, stderr=descriptor, env=N.BASE_ENV)
        finally:
            os.close(descriptor)
        STAGE = 'SUPERVISOR'
        if supervisor.wait(timeout=375) != 0:
            public_failure_diagnostic(bundle)
            public_status_diagnostic(bundle, output, options.source_commit, options.engine)
            public_browser_identity(bundle, output, options.source_commit, options.engine, options.fixture_id, copies)
            raise N.Failure('BROWSER_FAILED')
        after, files_after = N.host_observation(source, options.source_commit)
        need(before == after and files_before == files_after and not root.exists(), 'HOST_CHANGED')
        isolation = N.decode(N.stable_read(bundle / 'logs/isolation.private.json')[0])
        N.report(options, 'isolation', 'isolation', hostBefore=before, hostAfter=after,
                 sourceFilesBefore=files_before, sourceFilesAfter=files_after, tools=tools,
                 pythonExecutable=sys.executable, **isolation)
        browser = output / 'browser'
        N.exclusive(browser / 'browser-build.json', N.canonical(dict(schema='chengwang.probe-browser-build/v1',
            sourceCommit=options.source_commit, fixtureId=options.fixture_id, engine=options.engine,
            copiedInputs=copies, sourceFilesBefore=files_before, sourceFilesAfter=files_after,
            hostBefore=before, hostAfter=after, buildScope='TRUSTED_CI_INPUTS_NOT_INDEPENDENT_REBUILD',
            backendSupervisorMode='WRAPPER_IMPORTS_NATIVE_HELPERS', production=False)) + b'\n')
        web = browser / 'web'; web.mkdir(mode=0o755)
        for entry in copies:
            if entry['path'].startswith('built-web/'):
                rel = entry['path'][len('built-web/'):]
                target = web / rel; target.parent.mkdir(parents=True, exist_ok=True)
                N.exclusive(target, N.stable_read(bundle / 'web' / rel, 8 << 20)[0])
        # A complete capture can still fail the independent browser gate.
        # Expose only fixed diagnostic projections before private logs vanish.
        public_failure_diagnostic(bundle)
        public_status_diagnostic(bundle, output, options.source_commit, options.engine)
        public_browser_identity(bundle, output, options.source_commit, options.engine, options.fixture_id, copies)
        N.cleanup_bundle(bundle); bundle = None
        N.report(options, 'cleanup', 'cleanup', ownedProcessesJoined=4, exitCodes=[0] * 4, forcedKills=0,
            privateFixtureRemoved=True, privateToolsRemoved=True, hostNamespaceUnchanged=True,
            hostSysctlUnchanged=True, hostCAUnchanged=True, sourceUnchanged=True, outcome='PASS')
        need(set(path.name for path in (output / 'backend').iterdir()) == N.EXPECTED - {N.PREFIX + 'outcome.json'}, 'OUTPUT_SET')
        N.report(options, 'outcome', 'outcome', outcome='PASS', inputFileCount=21, processCount=4, agentResults=6)
        print('PROBE_BROWSER_LAB=CAPTURED backend_scope=NATIVE_BACKEND_ONLY final_browser_verification=pending production=false')
        return 0
    finally:
        if supervisor is not None and supervisor.poll() is None:
            supervisor.terminate()
            try: supervisor.wait(timeout=20)
            except subprocess.TimeoutExpired:
                supervisor.kill(); supervisor.wait(timeout=5)
        if root.exists():
            need(N.ROOT_RE.fullmatch(str(root)) and not root.is_symlink(), 'CLEANUP_TARGET')
            root.rmdir()
        if bundle is not None:
            N.cleanup_bundle(bundle)


def main(argv=None):
    try:
        options = arguments(argv)
        need(sys.platform.startswith('linux'), 'LINUX_REQUIRED')
        if os.geteuid() != 0:
            need(not options.inner and not options.role, 'ROOT_REQUIRED')
            os.execvpe('sudo', ['sudo', '-n', sys.executable, '-I', '-B', str(pathlib.Path(__file__).resolve()),
                *(sys.argv[1:] if argv is None else argv)], N.BASE_ENV)
        def interrupted(_signum, _frame): raise N.Failure('SIGNAL')
        signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
        if options.role == 'browser':
            configure_browser_role(options)
        elif options.role:
            N.configure_role(options, supervisor_entrypoint='browser-runner',
                web_dir=pathlib.Path(options.bundle) / 'web' if options.role.startswith('api-') else None)
        elif options.inner:
            BrowserLab(options).run()
        else:
            return outer(options)
        return 0
    except Exception as error:
        code = error.args[0] if isinstance(error, N.Failure) and error.args and type(error.args[0]) is str and error.args[0] in ERRORS else 'UNEXPECTED'
        sys.stderr.write('PROBE_BROWSER_LAB=FAIL stage=' + STAGE + ' code=' + code + ' raw_input_suppressed=true\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
