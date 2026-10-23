"""Independent closed keyring-reader mocks, never Linux permission acceptance.

All OS/file states are constructed here. No real keyring or /tmp path is read
or written, and every subprocess entry point is forbidden during each test.
"""
from contextlib import ExitStack
import hashlib
import io
from pathlib import Path, PurePosixPath
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

import prepare_ci_dependencies as P

CANARY = 'DO_NOT_EXPORT_PRIVATE_KEYRING_ERROR_2a7f93c1'
DATA = b'opaque keyring fixture bytes\x00\xff'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_uid', 'st_gid')


def sample(**changed):
    values = dict(st_dev=7, st_ino=1234, st_mode=stat.S_IFREG | 0o644, st_nlink=1,
                  st_size=len(DATA), st_mtime_ns=700, st_uid=0, st_gid=0)
    values.update(changed)
    return SimpleNamespace(**values)


class FakeStream(io.BytesIO):
    def __init__(self, raw, error=None):
        super().__init__(raw); self.error = error; self.requested = []

    def fileno(self): return 173

    def read(self, count=-1):
        self.requested.append(count)
        if self.error is not None: raise self.error
        return super().read(count)


class ReaderState:
    """Inject four independent metadata samples and a completely fake FD."""
    def __init__(self, *, before=None, opened=None, after=None, final=None, raw=DATA,
                 stat_error=None, open_error=None, fdopen_error=None, fstat_error=None,
                 read_error=None, final_error=None):
        self.before = before or sample(); self.opened = opened or sample()
        self.after = after or sample(); self.final = final or sample()
        self.stream = FakeStream(raw, read_error); self.stack = ExitStack()
        self.stat_error, self.open_error, self.fdopen_error = stat_error, open_error, fdopen_error
        self.fstat_error, self.final_error = fstat_error, final_error

    def __enter__(self):
        self.lstat = self.stack.enter_context(mock.patch.object(Path, 'lstat', side_effect=[
            self.stat_error or self.before, self.final_error or self.final]))
        self.is_link = self.stack.enter_context(mock.patch.object(Path, 'is_symlink', return_value=False))
        self.open = self.stack.enter_context(mock.patch.object(P.os, 'open', return_value=173, side_effect=self.open_error))
        self.fdopen = self.stack.enter_context(mock.patch.object(P.os, 'fdopen', return_value=self.stream, side_effect=self.fdopen_error))
        self.fstat = self.stack.enter_context(mock.patch.object(P.os, 'fstat', side_effect=[
            self.fstat_error or self.opened, self.after]))
        self.close = self.stack.enter_context(mock.patch.object(P.os, 'close'))
        return self

    def __exit__(self, *args): return self.stack.__exit__(*args)


class IndependentKeyringDiagnosticContracts(unittest.TestCase):
    def setUp(self):
        self.guards = ExitStack(); self.addCleanup(self.guards.close)
        for name in ('Popen', 'run', 'check_output', 'call', 'check_call'):
            self.guards.enter_context(mock.patch.object(P.subprocess, name,
                side_effect=AssertionError('subprocess forbidden in independent mock contracts')))
        self.guards.enter_context(mock.patch.object(P.os, 'open', side_effect=AssertionError('real file I/O forbidden')))
        self.guards.enter_context(mock.patch.object(Path, 'lstat', side_effect=AssertionError('real stat forbidden')))

    def read(self, **kwargs): return P.read_file(P.KEYRING, 1024, system_owned=True, diagnostic='KEYRING', **kwargs)

    def rejected(self, reason, state, **kwargs):
        with state:
            with self.assertRaises(P.PrivateSourceRejected) as caught: self.read(**kwargs)
        self.assertEqual(caught.exception.reason, reason)
        self.assertEqual(P.private_failure_stage(caught.exception), 'PRIVATE_' + reason)
        self.assertNotIn(CANARY, str(caught.exception)); self.assertNotIn(CANARY, repr(caught.exception.args))
        return caught.exception

    def test_01_safe_complete_read_returns_exact_original_bytes_and_metadata(self):
        with ReaderState() as state:
            raw, metadata = self.read()
            self.assertEqual(raw, DATA)
            self.assertEqual(metadata, dict(path=str(Path(P.KEYRING)), bytes=len(DATA), sha256=hashlib.sha256(DATA).hexdigest(), uid=0, gid=0, mode=0o644))
            self.assertEqual(state.stream.requested, [1025])
            self.assertTrue(state.stream.closed)
            self.assertEqual(state.open.call_args.args[0], Path(P.KEYRING))
            self.assertEqual(state.open.call_args.args[1], P.os.O_RDONLY | getattr(P.os, 'O_NOFOLLOW', 0) | getattr(P.os, 'O_NONBLOCK', 0))

    def test_02_initial_metadata_rejections_are_independently_classified(self):
        cases = [('KEYRING_SYMLINK', dict(st_mode=stat.S_IFLNK | 0o777)),
                 ('KEYRING_TYPE', dict(st_mode=stat.S_IFDIR | 0o755)),
                 ('KEYRING_LINK_COUNT', dict(st_nlink=2)), ('KEYRING_SIZE', dict(st_size=0)),
                 ('KEYRING_SIZE', dict(st_size=1025)), ('KEYRING_OWNER', dict(st_uid=1001)),
                 ('KEYRING_OWNER', dict(st_gid=1001)), ('KEYRING_MODE', dict(st_mode=stat.S_IFREG | 0o666))]
        for reason, changed in cases:
            with self.subTest(reason=reason, changed=changed):
                state = ReaderState(before=sample(**changed)); self.rejected(reason, state)
                state.open.assert_not_called()

    def test_03_stat_open_fd_stat_read_and_final_stat_failures_are_closed(self):
        for reason, field in [('KEYRING_STAT', 'stat_error'), ('KEYRING_OPEN', 'open_error'),
                              ('KEYRING_OPEN', 'fdopen_error'), ('KEYRING_FD_STAT', 'fstat_error'),
                              ('KEYRING_FD_STAT', 'after'),
                              ('KEYRING_READ', 'read_error'), ('KEYRING_FINAL_STAT', 'final_error')]:
            with self.subTest(reason=reason, field=field):
                state = ReaderState(**{field: OSError(CANARY)}); self.rejected(reason, state)
                if field == 'fdopen_error': state.close.assert_called_once_with(173)
                if field in ('fstat_error', 'after', 'read_error', 'final_error'): self.assertTrue(state.stream.closed)
        with ReaderState(fdopen_error=OSError(CANARY)) as state:
            state.close.side_effect = OSError(CANARY)
            with self.assertRaises(P.PrivateSourceRejected) as caught: self.read()
            self.assertEqual(caught.exception.reason, 'KEYRING_OPEN')

    def test_04_identity_owner_and_group_changes_never_pass_stability(self):
        changed_values = dict(st_dev=8, st_ino=1235, st_mode=stat.S_IFREG | 0o600,
                              st_nlink=2, st_size=len(DATA)+1, st_mtime_ns=701, st_uid=1001, st_gid=1001)
        for field in FIELDS:
            for phase in ('opened', 'after', 'final'):
                with self.subTest(field=field, phase=phase):
                    self.rejected('KEYRING_STABILITY', ReaderState(**{phase:sample(**{field:changed_values[field]})}))

    def test_05_short_and_long_reads_are_length_errors_not_success(self):
        for raw in (DATA[:-1], DATA+b'extra'):
            self.rejected('KEYRING_LENGTH', ReaderState(raw=raw))

    def test_06_diagnostics_only_allow_fixed_path_and_true_system_owner_flag(self):
        cases = [('/tmp/not-the-keyring', True, 'KEYRING'), (P.KEYRING, False, 'KEYRING'),
                 (P.KEYRING, 1, 'KEYRING'), (P.KEYRING, True, 'UNKNOWN'),
                 ('/usr/share/keyrings/../keyrings/ubuntu-archive-keyring.gpg', True, 'KEYRING')]
        for path, owned, diagnostic in cases:
            with self.subTest(path=path, owned=owned, diagnostic=diagnostic), ReaderState() as state:
                with self.assertRaises(ValueError) as caught: P.read_file(path, 1024, system_owned=owned, diagnostic=diagnostic)
                self.assertNotIsInstance(caught.exception, P.PrivateSourceRejected)
                state.lstat.assert_not_called(); state.open.assert_not_called()

    def test_07_default_reader_keeps_generic_behavior_and_permission_boundary(self):
        with ReaderState():
            self.assertEqual(P.read_file(P.KEYRING, 1024, system_owned=True)[0], DATA)
        with ReaderState(before=sample(st_nlink=2)):
            with self.assertRaises(ValueError) as caught: P.read_file(P.KEYRING, 1024, system_owned=True)
            self.assertNotIsInstance(caught.exception, P.PrivateSourceRejected)
        # Other-readability remains the original outer KEYRING_PERMISSION check.
        with ReaderState(before=sample(st_mode=stat.S_IFREG|0o600), opened=sample(st_mode=stat.S_IFREG|0o600),
                         after=sample(st_mode=stat.S_IFREG|0o600), final=sample(st_mode=stat.S_IFREG|0o600)):
            self.assertEqual(self.read()[1]['mode'], 0o600)

    def test_08_creation_chain_propagates_precise_keyring_reason_without_io(self):
        source, mirrors = b'independent host source fixture', b'independent host mirror fixture'
        for reason in ('KEYRING_READ', 'KEYRING_DIGEST'):
            def read_stub(path, *args, **kwargs):
                if str(path) == P.HOST_SOURCE: return source, {}
                if str(path) == P.HOST_MIRROR: return mirrors, {}
                self.assertEqual(str(path), P.KEYRING); self.assertEqual(args, (P.PINNED_KEYRING_BYTES,))
                self.assertEqual(kwargs, {})
                if reason == 'KEYRING_READ': raise OSError(CANARY)
                return DATA[:-1], {}
            with mock.patch.multiple(P, HOST_SOURCE_SIZE=len(source), HOST_SOURCE_SHA=hashlib.sha256(source).hexdigest(),
                                     HOST_MIRROR_SIZE=len(mirrors), HOST_MIRROR_SHA=hashlib.sha256(mirrors).hexdigest()), \
                 mock.patch.object(P, 'read_file', side_effect=read_stub), \
                 mock.patch.object(P, 'parse_ubuntu_sources', return_value=1), \
                 mock.patch.object(P, 'make_private_directory', side_effect=AssertionError('no real directory')) as create:
                with self.assertRaises(P.PrivateSourceRejected) as caught: P.create_private_sources()
                self.assertEqual(caught.exception.reason, reason); create.assert_not_called()
        def unreadable(path, *args, **kwargs):
            if str(path) == P.HOST_SOURCE: return source, {}
            if str(path) == P.HOST_MIRROR: return mirrors, {}
            self.assertEqual(kwargs, {})
            return DATA, dict(mode=0o777)
        with mock.patch.multiple(P, HOST_SOURCE_SIZE=len(source), HOST_SOURCE_SHA=hashlib.sha256(source).hexdigest(),
                                 HOST_MIRROR_SIZE=len(mirrors), HOST_MIRROR_SHA=hashlib.sha256(mirrors).hexdigest()), \
             mock.patch.object(P, 'read_file', side_effect=unreadable), \
             mock.patch.object(P, 'parse_ubuntu_sources', return_value=1), \
             mock.patch.object(P, 'PINNED_KEYRING_BYTES', len(DATA)), \
             mock.patch.object(P, 'PINNED_KEYRING_SHA512', hashlib.sha512(DATA).hexdigest()), \
             mock.patch.object(P, 'make_private_directory', return_value=PurePosixPath('/tmp/chengwang-ci-apt-abcdefgh')), \
             mock.patch.object(P, 'private_files', side_effect=P.PrivateSourceRejected('FILES')):
            with self.assertRaises(P.PrivateSourceRejected) as caught: P.create_private_sources()
            # Writable host bytes alone confer no trust. The exact mocked pin
            # authorizes copying, which then reaches the isolated file stage.
            self.assertEqual(caught.exception.reason, 'FILES')

    def test_09_private_readback_preserves_diagnostic_keyword_and_cause(self):
        # Only pure path strings are simulated here; no Linux directory exists.
        directory = PurePosixPath('/tmp/chengwang-ci-apt-abcdefgh'); replacement = ('mirror+file:'+str(directory/'mirrors.txt')).encode()
        private_signer = str(directory/'ubuntu-archive-keyring.gpg')
        normalized = (P.HOST_MIRROR_URI + '\n' + P.KEYRING).encode(); mirrors = P.mirror_bytes()
        def read_stub(path, *args, **kwargs):
            path = str(path)
            if path == private_signer:
                self.assertEqual(args, (P.PINNED_KEYRING_BYTES,)); self.assertEqual(kwargs, {})
                return DATA[:-1], dict(path=path, uid=1001, gid=1001, mode=0o644)
            data = replacement + b'\n' + private_signer.encode() if path.endswith('/ubuntu.sources') else mirrors
            return data, dict(path=path, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), uid=1001, gid=1001, mode=0o644)
        with mock.patch.multiple(P, HOST_SOURCE_SIZE=len(normalized), HOST_SOURCE_SHA=hashlib.sha256(normalized).hexdigest()), \
             mock.patch.object(P, 'Path', PurePosixPath), \
             mock.patch.object(P, 'read_file', side_effect=read_stub), \
             mock.patch.object(P, 'directory_metadata', side_effect=lambda path,*a,**k:dict(path=str(path),uid=1001,gid=1001,mode=0o755)), \
             mock.patch.object(P, 'parse_ubuntu_sources', return_value=1):
            with self.assertRaises(P.PrivateSourceRejected) as caught: P.private_readback(directory)
            self.assertEqual(caught.exception.reason, 'KEYRING_DIGEST')

    def test_10_unknown_exception_text_and_mutated_reason_never_export_canary(self):
        def broken(): raise RuntimeError(CANARY)
        with self.assertRaises(P.PrivateSourceRejected) as caught: P.private_operation('KEYRING_READ', broken)
        self.assertEqual(caught.exception.reason, 'KEYRING_READ'); self.assertNotIn(CANARY, str(caught.exception))
        caught.exception.reason = CANARY
        self.assertEqual(P.private_failure_stage(caught.exception), 'PRIVATE_SOURCES')
        with self.assertRaises(ValueError) as invalid: P.PrivateSourceRejected(CANARY)
        self.assertNotIn(CANARY, str(invalid.exception))


if __name__ == '__main__': unittest.main()
