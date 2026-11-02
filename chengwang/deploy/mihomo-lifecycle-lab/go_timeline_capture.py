#!/usr/bin/env python3
"""Bounded diagnostic collector for one instrumented Go JSON stream.

The safe projection has no acceptance authority. Raw Go/stderr bytes remain in
their existing evidence paths; this module publishes only a bounded delta-only
projection. Linux runtime behavior is intentionally left to CI acceptance.
"""
import argparse
import contextlib
import datetime
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

MAX_RAW = 64 << 20
MAX_LINE = 1 << 20
MAX_EVENTS = 65536
MAX_TRANSITIONS = 4096
MAX_PUBLIC = 1 << 20
MAX_I63 = (1 << 63) - 1
PACKAGES = (
    'chengwang/internal/adapter/mihomo',
    'chengwang/internal/mihomodeploy',
    'chengwang/internal/authn',
    'chengwang/internal/api',
    'chengwang/internal/serverruntime',
    'chengwang/internal/authz',
)
FINAL_NAMES = {
    'FOUNDATION_ORDINARY': 'ordinary-go-top-observation-timeline.json',
    'FOUNDATION_RACE': 'race-go-top-observation-timeline.json',
    'CAPACITY_FULL_RACE': 'capacity-go-top-observation-timeline.json',
}
# Custody-only path prefix. The public schema and artifact member basenames
# remain the flat FINAL_NAMES values; this directory name is never serialized.
PUBLICATION_DIR = 'timeline-public'
REGISTRY = Path(__file__).with_name('go_timeline_required_tops.json')
FAILURES = {
    'NONE', 'RAW_CAP', 'RAW_WRITE_FAILED', 'RAW_FSYNC_FAILED',
    'STDERR_FSYNC_FAILED', 'LINE_CAP', 'EVENT_CAP', 'TRANSITION_CAP',
    'JSON_REJECTED', 'FSM_REJECTED', 'PIPE_READ_FAILED', 'COLLECTOR_EXCEPTION',
    'SIGNAL_DEFERRAL_INSTALL_FAILED', 'DEFERRED_CANCELLATION_NO_CHILD',
    'DEFERRED_CANCELLATION_REAPED', 'SIGNAL_HANDLER_RESTORE_FAILED_AFTER_REAP',
    'POPEN_FAILED', 'PGID_REJECTED', 'PUBLICATION_FAILED',
}

def need(value):
    if not value:
        raise ValueError('go timeline rejected')

def canonical(value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    need(len(raw) <= MAX_PUBLIC)
    return raw

def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(type(key) is str and key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False))

def load_registry(path=REGISTRY):
    value = decode(Path(path).read_bytes())
    need(type(value) is dict and set(value) ==
         {'schema', 'count', 'namesSHA256', 'packages', 'names'})
    names = value['names']
    need(value['schema'] == 'chengwang.go-top-required-registry/v1')
    need(type(names) is list and len(names) == value['count'] == 689)
    need(names == sorted(set(names)) and value['packages'] == sorted(PACKAGES))
    raw = '\n'.join(names).encode()
    need(hashlib.sha256(raw).hexdigest() == value['namesSHA256'] ==
         '2ffac806dc10c8019b0342e1e0e0c56a4712a02172bdaee8a29429e5c78fa68f')
    return value

def _close_slot(owner, slot):
    handle = getattr(owner, slot)
    if handle is None:
        return None
    try:
        handle.close()
        return None
    except Exception:
        return 'CLOSE_FAILED'
    finally:
        # Clear in finally: a close exception must not authorize an integer-fd
        # retry after the operating system has reused that number.
        setattr(owner, slot, None)

class OwnerGuard:
    """The one cleanup owner from pre-Popen sinks through direct-child reap."""
    def __init__(self, raw_sink, stderr_sink):
        self.owner = 'NO_CHILD'
        self.process = None
        self.expectedPgid = None
        self.validatedPgid = None
        self.pipe = None
        self.rawSink = raw_sink
        self.stderrSink = stderr_sink
        self.pendingCancellation = False
        self.firstPendingSignal = None
        self.repeatedSignal = False
        self.killIssued = False
        self.waitCompleted = False
        self.returncode = None
        self.active = False
        self.handoffActive = False
        self.previous = {}
        self.installed = []
        self.failure = 'NONE'
        self.secondary = set()

    def _record_signal(self, signum, _frame):
        # Intentionally non-raising and non-I/O. Python runs this on the main
        # interpreter thread; cancellation effects are deferred, not masked.
        if not self.pendingCancellation:
            self.pendingCancellation = True
            self.firstPendingSignal = signum
        else:
            self.repeatedSignal = True

    def install_handlers(self):
        need(sys.platform == 'linux')
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                self.previous[sig] = signal.getsignal(sig)
                signal.signal(sig, self._record_signal)
                self.installed.append(sig)
        except BaseException:
            self.failure = 'SIGNAL_DEFERRAL_INSTALL_FAILED'
            for sig in reversed(self.installed):
                with contextlib.suppress(BaseException):
                    signal.signal(sig, self.previous[sig])
            self.installed.clear()
            raise

    def spawn(self, argv, **kwargs):
        need(self.installed == [signal.SIGINT, signal.SIGTERM])
        if self.pendingCancellation:
            self.failure = 'DEFERRED_CANCELLATION_NO_CHILD'
            raise InterruptedError
        try:
            process = subprocess.Popen(argv, start_new_session=True, **kwargs)
        except BaseException:
            self.failure = 'POPEN_FAILED'
            raise
        # Do not service pending cancellation until this registration sequence
        # is complete. The handlers remain non-raising across every statement.
        self.process = process
        self.pipe = process.stdout
        self.expectedPgid = process.pid
        self.owner = 'CALLER_OWNS'
        self.active = True
        self._validate_pgid()
        return process

    def adopt_spawned(self, process, pipe):
        """Register a Popen created by the guarded capacity caller."""
        need(self.installed == [signal.SIGINT, signal.SIGTERM])
        self.process = process
        self.pipe = pipe
        self.expectedPgid = process.pid
        self.owner = 'CALLER_OWNS'
        self.active = True
        self._validate_pgid()

    def _validate_pgid(self):
        need(self.process is not None and self.expectedPgid == self.process.pid)
        try:
            actual = os.getpgid(self.process.pid)
        except ProcessLookupError:
            code = self._wait_once()
            self.owner = 'REAPED'
            self.returncode = code
            return
        if actual != self.expectedPgid:
            self.failure = 'PGID_REJECTED'
            raise ValueError('process group rejected')
        self.validatedPgid = actual

    def transfer_to_collector(self):
        need(self.owner == 'CALLER_OWNS' and self.active and self.process is not None)
        origin = time.monotonic_ns()
        need(0 <= origin <= MAX_I63)
        self.owner = 'COLLECTOR_OWNS'
        # Callers clear their actual sink and Popen locals before this method.
        # Python cannot prove reference uniqueness; cleanup authority, rather
        # than object reachability, is exclusively retained by this guard.
        self.handoffActive = True
        self.service_pending()
        return origin

    def service_pending(self):
        if not self.pendingCancellation:
            return
        self.failure = ('DEFERRED_CANCELLATION_NO_CHILD' if self.process is None
                        else 'DEFERRED_CANCELLATION_REAPED')
        self.cleanup(kill=True)
        raise InterruptedError

    def _wait_once(self):
        need(self.process is not None)
        if self.waitCompleted:
            return self.returncode
        while True:
            try:
                code = self.process.wait()
                break
            except InterruptedError:
                continue
        self.returncode = code
        self.waitCompleted = True
        return code

    def cleanup(self, kill):
        if self.process is not None and not self.waitCompleted:
            if kill and not self.killIssued:
                # Mark before attempting the syscall; secondary errors cannot
                # authorize another signal to a potentially reused group ID.
                self.killIssued = True
                try:
                    os.killpg(self.expectedPgid, signal.SIGKILL)
                except ProcessLookupError:
                    self.secondary.add('KILLPG_ESRCH')
                except Exception:
                    self.secondary.add('KILLPG_FAILED')
            _close_slot(self, 'pipe')
            self._wait_once()
        if self.process is not None and self.waitCompleted:
            self.owner = 'REAPED'
        for slot in ('pipe', 'rawSink', 'stderrSink'):
            failure = _close_slot(self, slot)
            if failure:
                self.secondary.add(failure)

    def restore_handlers(self):
        need(self.owner in ('NO_CHILD', 'REAPED'))
        need(self.pipe is self.rawSink is self.stderrSink is None)
        failed = False
        for sig in reversed(self.installed):
            try:
                signal.signal(sig, self.previous[sig])
            except BaseException:
                failed = True
        self.installed.clear()
        if failed:
            self.failure = 'SIGNAL_HANDLER_RESTORE_FAILED_AFTER_REAP'
            return False
        return True

class Projector:
    def __init__(self, lane, source_commit, source_tree, registry):
        need(lane in FINAL_NAMES)
        need(re.fullmatch('[a-f0-9]{40}', source_commit) is not None)
        need(re.fullmatch('[a-f0-9]{40}', source_tree) is not None)
        self.lane = lane
        self.source_commit = source_commit
        self.source_tree = source_tree
        self.registry = registry
        self.required = set(registry['names'])
        self.packages = {p: 'ABSENT' for p in PACKAGES}
        self.package_terminal = {p: None for p in PACKAGES}
        self.tests = {}
        self.test_terminal = {}
        self.required_state = {name: {'name': name, 'state': 'ABSENT',
            'terminalAction': None,
            'runDeltaNs': None, 'terminalDeltaNs': None, 'observedSpanNs': None,
            'goActiveElapsedSeconds': None, 'pauseCount': 0, 'continueCount': 0}
            for name in registry['names']}
        self.discard = {'requiredSubtest': 0, 'nonRequiredTop': 0,
                        'nonRequiredSubtest': 0, 'output': 0}
        self.discard_saturated = False
        self.tail = []
        self.transitions = 0
        self.events = 0
        self.failure = 'NONE'
        self.semantic = True
        self.first_line = None
        self.last_line = None

    def reject(self, failure):
        if self.failure == 'NONE':
            self.failure = failure
        self.semantic = False

    def _count(self, key):
        if self.discard[key] >= MAX_EVENTS:
            self.discard_saturated = True
            self.reject('FSM_REJECTED')
            return
        self.discard[key] += 1

    def _transition(self, key, action, delta, elapsed):
        self.transitions += 1
        if self.transitions > MAX_TRANSITIONS:
            self.reject('TRANSITION_CAP')
            return
        state = self.tests.get(key, 'ABSENT')
        next_state = None
        if action == 'run' and state == 'ABSENT': next_state = 'RUNNING'
        elif action == 'pause' and state == 'RUNNING': next_state = 'PAUSED'
        elif action == 'cont' and state == 'PAUSED': next_state = 'RUNNING'
        elif action in ('pass', 'fail', 'skip') and state == 'RUNNING': next_state = 'TERMINAL'
        elif action == 'output' and state != 'ABSENT': next_state = state
        if next_state is None:
            self.reject('FSM_REJECTED'); return
        self.tests[key] = next_state
        if action in ('pass', 'fail', 'skip'):
            self.test_terminal[key] = action
        if key in self.required_state:
            row = self.required_state[key]
            row['state'] = next_state
            if action == 'run': row['runDeltaNs'] = delta
            if action == 'pause': row['pauseCount'] += 1
            if action == 'cont': row['continueCount'] += 1
            if action in ('pass', 'fail', 'skip'):
                row['terminalAction'] = action
                row['terminalDeltaNs'] = delta
                row['observedSpanNs'] = delta - row['runDeltaNs']
                row['goActiveElapsedSeconds'] = elapsed
            if action != 'output':
                self.tail.append({'name': key, 'action': action, 'deltaNs': delta})
                self.tail = self.tail[-20:]

    def event(self, raw, observed_ns, origin):
        if not self.semantic:
            return
        self.events += 1
        if self.events > MAX_EVENTS:
            self.reject('EVENT_CAP'); return
        try:
            value = decode(raw)
            need(type(value) is dict)
            need(set(value) <= {'Time','Action','Package','Test','Elapsed','Output'})
            need({'Time','Action','Package'} <= set(value))
            need(type(value['Time']) is str and re.fullmatch(
                r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z', value['Time']))
            datetime.datetime.fromisoformat(value['Time'].replace('Z', '+00:00'))
            package, action = value['Package'], value['Action']
            need(package in PACKAGES and type(action) is str)
            test = value.get('Test')
            elapsed = value.get('Elapsed')
            if elapsed is not None:
                need(type(elapsed) in (int,float) and not isinstance(elapsed,bool)
                     and math.isfinite(elapsed) and elapsed >= 0)
            if action == 'output': need(set(value) >= {'Output'} and type(value['Output']) is str)
            else: need('Output' not in value)
            delta = observed_ns - origin
            need(0 <= delta <= MAX_I63)
            self.first_line = delta if self.first_line is None else self.first_line
            self.last_line = delta
            pstate = self.packages[package]
            if test is None:
                need(action in ('start','pass','fail','skip','output'))
                if action == 'start': need(pstate == 'ABSENT'); self.packages[package] = 'STARTED'
                elif action == 'output': need(pstate == 'STARTED'); self._count('output')
                else:
                    need(pstate == 'STARTED')
                    observed = [s for key,s in self.tests.items() if key.startswith(package+'::')]
                    if action == 'pass':
                        need(all(s == 'TERMINAL' for s in observed))
                        need(all(self.test_terminal[key] in ('pass','skip') for key in self.tests
                                 if key.startswith(package+'::')))
                    if action == 'skip': need(not observed)
                    self.packages[package] = 'TERMINAL'
                    self.package_terminal[package] = action
                return
            need(type(test) is str and 1 <= len(test.encode()) <= 512)
            need(pstate == 'STARTED')
            key = package + '::' + test
            top = test.split('/', 1)[0]
            required_top = package + '::' + top in self.required
            if '/' in test: category = 'requiredSubtest' if required_top else 'nonRequiredSubtest'
            else: category = None if key in self.required else 'nonRequiredTop'
            if category is not None: self._count(category)
            if action == 'output': self._count('output')
            need(action in ('run','pause','cont','pass','fail','skip','output'))
            self._transition(key, action, delta, elapsed)
        except Exception:
            self.reject('JSON_REJECTED')

    def payload(self, guard, boundaries, stream_closure):
        rows = [self.required_state[name] for name in self.registry['names']]
        for row in rows:
            if row['state'] in ('RUNNING','PAUSED') and row['runDeltaNs'] is not None:
                row['observedSpanNs'] = boundaries['waitReturnedDeltaNs'] - row['runDeltaNs']
        complete = (guard.returncode == 0 and stream_closure == 'COMPLETE_EOF' and self.failure == 'NONE'
                    and self.semantic and all(v == 'TERMINAL' for v in self.packages.values())
                    and all(self.package_terminal[p] == 'pass' for p in PACKAGES)
                    and all(row['state'] == 'TERMINAL' and row['terminalAction'] == 'pass'
                            for row in rows))
        if not self.semantic: coverage = 'REJECTED_SEMANTICS'
        elif complete: coverage = 'COMPLETE_TERMINAL'
        else: coverage = 'PARTIAL_TERMINAL'
        return {
            'schema':'chengwang.go-top-observation-timeline/v1',
            'sourceCommit':self.source_commit,'sourceTree':self.source_tree,
            'lane':self.lane,'manifestCount':689,
            'manifestNamesSHA256':self.registry['namesSHA256'],
            'instrumentationEffect':'PIPE_READER_MAY_PERTURB_SCHEDULING_AND_DURATION',
            'evidenceScope':'THIS_INSTRUMENTED_RUN_ONLY','priorRunTimingEquivalence':False,
            'acceptanceAuthority':False,'causalInference':'NOT_MADE',
            'profileTimerSeconds':120 if self.lane == 'CAPACITY_FULL_RACE' else None,
            'testTimeoutSeconds':180,
            'boundaryDeltas':boundaries,
            'childReturnCodeSigned':guard.returncode,
            'childShellStatus':guard.returncode if guard.returncode >= 0 else 128-guard.returncode,
            'childOutcome':'SIGNALED' if guard.returncode < 0 else 'EXITED',
            'rawOutcome':'COMPLETE' if self.failure not in ('RAW_CAP','RAW_WRITE_FAILED','RAW_FSYNC_FAILED') else self.failure,
            'semanticOutcome':'COMPLETE' if self.semantic else self.failure,
            'streamClosure':stream_closure,'topCoverage':coverage,
            'fixedFailure':self.failure,'secondaryFailureFlags':sorted(guard.secondary),
            'discardCounters':self.discard,'discardCounterSaturated':self.discard_saturated,
            'packages':[{'name':p,'state':self.packages[p],
                         'terminalAction':self.package_terminal[p]} for p in PACKAGES],
            'requiredTops':rows,'requiredTransitionTail':self.tail,
        }

def _full_write(fd, raw):
    offset = 0
    while offset < len(raw):
        count = os.write(fd, raw[offset:])
        need(count > 0)
        offset += count

def _read_fd(fd, limit):
    parts=[];total=0
    while True:
        chunk=os.read(fd,min(65536,limit+1-total))
        if not chunk:return b''.join(parts)
        parts.append(chunk);total+=len(chunk)
        need(total<=limit)

def publish_safe(parent, final_name, raw):
    """Linux same-dirfd linkat no-replace publication with current custody."""
    need(sys.platform == 'linux' and final_name in FINAL_NAMES.values())
    parent = Path(parent)
    need(parent.is_absolute() and parent.name not in ('', '.', '..'))
    for item in reversed((parent,*parent.parents)):
        info=item.lstat();need(not stat.S_ISLNK(info.st_mode))
    stage = final_name + '.stage'
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    dirfd = os.open(parent, flags)
    tempfd = None
    linked = False
    try:
        before = os.fstat(dirfd)
        need(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode)==0o755
             and before.st_uid==os.geteuid() and before.st_gid==os.getegid())
        for name in (stage, final_name):
            try: os.stat(name, dir_fd=dirfd, follow_symlinks=False); need(False)
            except FileNotFoundError: pass
        tempfd = os.open(stage, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                         0o600, dir_fd=dirfd)
        opened = os.fstat(tempfd)
        need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and opened.st_dev == before.st_dev)
        _full_write(tempfd, raw); os.fsync(tempfd); os.lseek(tempfd, 0, os.SEEK_SET)
        need(_read_fd(tempfd,len(raw)) == raw)
        os.fchmod(tempfd, 0o644); os.fsync(tempfd)
        named = os.stat(stage, dir_fd=dirfd, follow_symlinks=False)
        need((named.st_dev,named.st_ino,named.st_size)==(opened.st_dev,opened.st_ino,len(raw)))
        named_parent=os.open(parent,flags)
        try:
            current=os.fstat(named_parent)
            need((before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid,before.st_nlink)==
                 (current.st_dev,current.st_ino,current.st_mode,current.st_uid,current.st_gid,current.st_nlink))
        finally:os.close(named_parent)
        os.link(stage, final_name, src_dir_fd=dirfd, dst_dir_fd=dirfd, follow_symlinks=False)
        linked = True
        linked_stat = os.stat(final_name, dir_fd=dirfd, follow_symlinks=False)
        need(linked_stat.st_ino == opened.st_ino and linked_stat.st_nlink == 2)
        finalfd = os.open(final_name, os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW, dir_fd=dirfd)
        try: need(_read_fd(finalfd,len(raw)) == raw and os.fstat(finalfd).st_ino == opened.st_ino)
        finally: os.close(finalfd)
        os.unlink(stage, dir_fd=dirfd)
        need(os.stat(final_name, dir_fd=dirfd, follow_symlinks=False).st_nlink == 1)
        os.fsync(dirfd)
        named_parent = os.open(parent, flags)
        try:
            after = os.fstat(named_parent)
            need((before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid,before.st_nlink)==
                 (after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid,after.st_nlink))
            finalfd=os.open(final_name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=named_parent)
            try:need(_read_fd(finalfd,len(raw))==raw and os.fstat(finalfd).st_ino==opened.st_ino)
            finally:os.close(finalfd)
        finally: os.close(named_parent)
    except Exception:
        if not linked:
            with contextlib.suppress(Exception):
                named = os.stat(stage, dir_fd=dirfd, follow_symlinks=False)
                if tempfd is not None and named.st_ino == os.fstat(tempfd).st_ino:
                    os.unlink(stage, dir_fd=dirfd); os.fsync(dirfd)
        raise
    finally:
        if tempfd is not None: os.close(tempfd)
        os.close(dirfd)

def write_private(path, raw):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600)
    try: _full_write(fd, raw); os.fsync(fd)
    finally: os.close(fd)

def collect(guard, projector, origin, publication_parent=None, private_output=None):
    need(guard.owner == 'COLLECTOR_OWNS' and guard.pipe is not None)
    buffer = bytearray(); raw_bytes = 0; raw_healthy = True; stream = 'COMPLETE_EOF'
    try:
        while True:
            guard.service_pending()
            try: chunk = os.read(guard.pipe.fileno(), 65536)
            except InterruptedError: continue
            except Exception: projector.reject('PIPE_READ_FAILED'); stream='REJECTED_IO'; raise
            if not chunk: eof_ns=time.monotonic_ns(); break
            if raw_healthy:
                if raw_bytes + len(chunk) > MAX_RAW:
                    raw_healthy=False; projector.reject('RAW_CAP'); stream='TRUNCATED_CAP'
                else:
                    try:
                        count=guard.rawSink.write(chunk);need(count==len(chunk));raw_bytes += count
                    except Exception:
                        raw_healthy=False; projector.reject('RAW_WRITE_FAILED'); stream='REJECTED_IO'
            if projector.semantic:
                buffer.extend(chunk)
                if len(buffer) > MAX_LINE and b'\n' not in buffer:
                    projector.reject('LINE_CAP'); buffer.clear()
                while projector.semantic and b'\n' in buffer:
                    line, _, rest = buffer.partition(b'\n'); buffer = bytearray(rest)
                    if not line or len(line) > MAX_LINE: projector.reject('LINE_CAP'); break
                    projector.event(bytes(line), time.monotonic_ns(), origin)
        if buffer and projector.semantic: projector.reject('JSON_REJECTED')
        _close_slot(guard, 'pipe')
        guard._wait_once(); guard.owner='REAPED'
        wait_ns=time.monotonic_ns()
        try: guard.rawSink.flush(); os.fsync(guard.rawSink.fileno())
        except Exception: projector.reject('RAW_FSYNC_FAILED')
        raw_sync=time.monotonic_ns()
        try: guard.stderrSink.flush(); os.fsync(guard.stderrSink.fileno())
        except Exception: projector.reject('STDERR_FSYNC_FAILED')
        stderr_sync=time.monotonic_ns()
        boundaries={
            'firstLineReadDeltaNs':projector.first_line,
            'eofObservedDeltaNs':eof_ns-origin,
            'waitReturnedDeltaNs':wait_ns-origin,
            'rawFsyncReturnedDeltaNs':raw_sync-origin,
            'stderrFsyncReturnedDeltaNs':stderr_sync-origin,
            'prepublicationFinalizationDeltaNs':time.monotonic_ns()-origin,
        }
        previous=-1
        for value in boundaries.values():
            if value is None: continue
            need(type(value) is int and previous <= value <= MAX_I63); previous=value
        raw=canonical(projector.payload(guard,boundaries,stream))
        guard.service_pending()
        if publication_parent is not None:
            publish_safe(publication_parent, FINAL_NAMES[projector.lane], raw)
        else:
            need(private_output is not None); write_private(private_output, raw)
        return guard.returncode, raw
    except InterruptedError:
        stream='CANCELLED_CLEANED_REAPED'; raise
    except BaseException:
        if projector.failure == 'NONE': projector.reject('COLLECTOR_EXCEPTION')
        guard.cleanup(kill=True)
        raise

def run_spawn(argv, lane, raw_path, stderr_path, publication_parent, source_commit, source_tree):
    raw=None;stderr=None;guard=None;status=125
    try:
        raw=open(raw_path,'xb',buffering=0)
        stderr=open(stderr_path,'xb',buffering=0)
        guard=OwnerGuard(raw,stderr)
        guard.install_handlers()
        # From this point the guard is the only cleanup authority. Clear the
        # caller's actual sink aliases before Popen and its Popen alias before
        # handoff; scalar metadata does not confer close/kill/wait authority.
        raw = None
        stderr = None
        process = guard.spawn(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=guard.stderrSink, close_fds=True)
        process = None
        origin = guard.transfer_to_collector()
        projector = Projector(lane, source_commit, source_tree, load_registry())
        status, _ = collect(guard, projector, origin, publication_parent=publication_parent)
    except BaseException:
        if guard is not None:
            guard.cleanup(kill=True)
            status = guard.returncode if guard.returncode not in (None,0) else 125
        else:
            for handle in (raw,stderr):
                if handle is not None:
                    with contextlib.suppress(BaseException):handle.close()
    finally:
        if guard is not None:
            guard.cleanup(kill=False)
            with contextlib.suppress(BaseException):
                if not guard.restore_handlers(): status = status if status else 125
    return status if status >= 0 else 128-status

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('mode', choices=['spawn'])
    parser.add_argument('--lane', choices=['FOUNDATION_ORDINARY','FOUNDATION_RACE'], required=True)
    parser.add_argument('--raw', type=Path, required=True); parser.add_argument('--stderr', type=Path, required=True)
    parser.add_argument('--publication-parent', type=Path, required=True)
    parser.add_argument('--source-commit', required=True); parser.add_argument('--source-tree', required=True)
    parser.add_argument('argv', nargs=argparse.REMAINDER)
    args=parser.parse_args(); need(args.argv and args.argv[0]=='--')
    raise SystemExit(run_spawn(args.argv[1:],args.lane,args.raw,args.stderr,args.publication_parent,
                               args.source_commit,args.source_tree))

if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit(125) from None
