"""Independent synthetic pin/copy contracts, not real keyring or Linux acceptance.

Only synthetic text is written inside unittest temporary directories. Candidate
reads and private metadata are mocked; no real keyring, package, HTTP endpoint,
APT command, browser or product runtime is accessed.
"""
from contextlib import ExitStack, contextmanager
import hashlib
import io
from pathlib import Path, PurePosixPath
import socket
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import prepare_ci_dependencies as D


OFFICIAL_BYTES = 3607
OFFICIAL_SHA512 = ('4e344ffbb31f205af8c6db3c260222e4af886af4d5c28462106c579d7ae46f911'
                   '53340eafad843186d7788370634d8097c117748921455e5bbb219bf08a28a40')
SYNTHETIC = b'not-a-real-keyring: independent synthetic unit data\n'
PRIVATE = PurePosixPath('/tmp/chengwang-ci-apt-abcdefgh')


def digest(raw): return hashlib.sha512(raw).hexdigest()


def source_bytes():
    def stanza(suites):
        return ('Types: deb\nURIs: ' + D.HOST_MIRROR_URI + '\nSuites: ' + suites + '\n'
                'Components: main restricted universe multiverse\nSigned-By: ' + D.KEYRING + '\n')
    return (stanza('noble noble-updates noble-backports') + '\n' + stanza('noble-security')).encode('ascii')


def metadata(path, raw, **changed):
    row = dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
               uid=1001, gid=1001, mode=0o644)
    row.update(changed)
    return row


class Stream(io.BytesIO):
    def fileno(self): return 173


class PinnedCiKeyringContracts(unittest.TestCase):
    def setUp(self):
        self.guards = ExitStack(); self.addCleanup(self.guards.close)
        for name in ('Popen', 'run', 'call', 'check_call', 'check_output'):
            self.guards.enter_context(mock.patch.object(D.subprocess, name,
                side_effect=AssertionError('subprocess forbidden in synthetic pin tests')))
        self.guards.enter_context(mock.patch.object(socket, 'socket',
            side_effect=AssertionError('network forbidden in synthetic pin tests')))
        self.guards.enter_context(mock.patch.object(socket, 'create_connection',
            side_effect=AssertionError('network forbidden in synthetic pin tests')))

    @contextmanager
    def pin(self, raw=SYNTHETIC):
        with mock.patch.multiple(D, PINNED_KEYRING_BYTES=len(raw), PINNED_KEYRING_SHA512=digest(raw)):
            yield

    @contextmanager
    def file_states(self, **changed):
        values = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o644, st_nlink=1,
                      st_size=len(SYNTHETIC), st_mtime_ns=123, st_uid=0, st_gid=0)
        values.update(changed); sample = SimpleNamespace(**values)
        stream = Stream(SYNTHETIC)
        with mock.patch.object(Path, 'lstat', return_value=sample), \
             mock.patch.object(Path, 'is_symlink', return_value=stat.S_ISLNK(sample.st_mode)), \
             mock.patch.object(D.os, 'open', return_value=173) as opened, \
             mock.patch.object(D.os, 'fdopen', return_value=stream), \
             mock.patch.object(D.os, 'fstat', return_value=sample):
            yield opened

    @contextmanager
    def readback(self, *, key_raw=SYNTHETIC, key_changes=None, source_change=None):
        """Pure POSIX path strings and invented ownership; no Linux I/O proof."""
        original = source_bytes()
        transformed = original.replace(D.HOST_MIRROR_URI.encode(), ('mirror+file:' + str(PRIVATE/'mirrors.txt')).encode())
        transformed = transformed.replace(D.KEYRING.encode(), str(PRIVATE/'ubuntu-archive-keyring.gpg').encode())
        if source_change is not None: transformed = source_change(transformed)
        payloads = {'ubuntu.sources': transformed, 'mirrors.txt': D.mirror_bytes(),
                    'ubuntu-archive-keyring.gpg': key_raw}

        def read(path, maximum, **kwargs):
            self.assertEqual(PurePosixPath(str(path)).parent, PRIVATE)
            self.assertFalse(kwargs.get('system_owned', False))
            self.assertNotIn('diagnostic', kwargs)
            name = PurePosixPath(str(path)).name
            self.assertIn(name, payloads)
            raw = payloads[name]
            row = metadata(path, raw, **(key_changes or {}) if name == 'ubuntu-archive-keyring.gpg' else {})
            return raw, row

        def directory(path, owner=None, empty=False):
            self.assertIn(str(path), (str(PRIVATE), str(PRIVATE/'sourceparts')))
            return dict(path=str(path), uid=1001, gid=1001, mode=0o755)

        with self.pin(), mock.patch.object(D, 'Path', PurePosixPath), \
             mock.patch.object(D, 'read_file', side_effect=read) as reader, \
             mock.patch.object(D, 'directory_metadata', side_effect=directory), \
             mock.patch.multiple(D, HOST_SOURCE_SIZE=len(original), HOST_SOURCE_SHA=hashlib.sha256(original).hexdigest()):
            yield reader, original

    def test_01_official_pin_is_exact_and_not_discovered_from_host_metadata(self):
        self.assertEqual(D.PINNED_KEYRING_BYTES, OFFICIAL_BYTES)
        self.assertEqual(D.PINNED_KEYRING_SHA512, OFFICIAL_SHA512)
        self.assertRegex(D.PINNED_KEYRING_SHA512, r'^[0-9a-f]{128}$')

    def test_02_candidate_accepts_only_pinned_bytes_with_explicitly_untrusted_read(self):
        with self.pin(), mock.patch.object(D, 'read_file', return_value=(SYNTHETIC,
                metadata(D.KEYRING, SYNTHETIC, uid=0, gid=0, mode=0o777))) as reader:
            self.assertEqual(D.pinned_candidate_keyring(), SYNTHETIC)
            reader.assert_called_once_with(D.KEYRING, len(SYNTHETIC))

    def test_03_same_length_wrong_digest_is_a_closed_keyring_digest_failure(self):
        bad = b'X' + SYNTHETIC[1:]
        with self.pin(), mock.patch.object(D, 'read_file', return_value=(bad, {})):
            with self.assertRaises(D.PrivateSourceRejected) as caught: D.pinned_candidate_keyring()
        self.assertEqual(caught.exception.reason, 'KEYRING_DIGEST')

    def test_04_short_and_long_candidates_fail_even_when_their_hash_is_allowed(self):
        for raw in (SYNTHETIC[:-1], SYNTHETIC+b'X'):
            with self.subTest(size=len(raw)), self.pin(), \
                 mock.patch.object(D, 'PINNED_KEYRING_SHA512', digest(raw)), \
                 mock.patch.object(D, 'read_file', return_value=(raw, {})):
                with self.assertRaises(D.PrivateSourceRejected) as caught: D.pinned_candidate_keyring()
                self.assertEqual(caught.exception.reason, 'KEYRING_DIGEST')

    def test_05_candidate_reader_errors_do_not_create_a_private_directory(self):
        with mock.patch.object(D, 'read_file', side_effect=OSError('PRIVATE-CANARY-DO-NOT-EXPORT')), \
             mock.patch.object(D, 'make_private_directory') as create:
            with self.assertRaises((ValueError, OSError)): D.pinned_candidate_keyring()
            create.assert_not_called()

    def test_06_candidate_keeps_no_symlink_single_link_and_regular_file_checks(self):
        for changed in ({'st_mode': stat.S_IFLNK | 0o777}, {'st_mode': stat.S_IFDIR | 0o755}, {'st_nlink': 2}):
            with self.subTest(changed=changed), self.pin(), self.file_states(**changed) as opened:
                with self.assertRaises(ValueError): D.pinned_candidate_keyring()
                opened.assert_not_called()

    def test_07_original_strict_host_reader_still_rejects_group_or_other_write(self):
        for mode in (0o664, 0o646, 0o666, 0o777):
            with self.subTest(mode=mode), self.file_states(st_mode=stat.S_IFREG | mode) as opened:
                with self.assertRaises(ValueError): D.read_file(D.KEYRING, 3607, system_owned=True)
                opened.assert_not_called()
            with self.subTest(diagnostic_mode=mode), self.file_states(st_mode=stat.S_IFREG | mode) as opened:
                with self.assertRaises(D.PrivateSourceRejected) as caught:
                    D.read_file(D.KEYRING, 3607, system_owned=True, diagnostic='KEYRING')
                self.assertEqual(caught.exception.reason, 'KEYRING_MODE'); opened.assert_not_called()

    def test_08_private_copy_writes_three_synthetic_files_exclusively_and_never_host(self):
        source = source_bytes()
        with tempfile.TemporaryDirectory(prefix='chengwang-pin-unit-') as name:
            directory = Path(name).resolve(); real_open = D.os.open; real_chmod = Path.chmod
            calls, permissions = [], []
            def opened(path, flags, mode=0o777):
                self.assertEqual(Path(path).parent, directory)
                self.assertTrue(flags & D.os.O_EXCL); self.assertTrue(flags & D.os.O_CREAT)
                self.assertEqual(mode, 0o644)
                calls.append(Path(path).name)
                return real_open(path, flags, mode)
            def chmod(path, mode, *args, **kwargs):
                self.assertEqual(path.parent, directory)
                permissions.append((path.name, mode))
                return real_chmod(path, mode, *args, **kwargs)
            with self.pin(), mock.patch.object(D.os, 'open', side_effect=opened), \
                 mock.patch.object(Path, 'chmod', autospec=True, side_effect=chmod):
                D.private_files(directory, source, SYNTHETIC)
            self.assertEqual(set(calls), {'ubuntu.sources', 'mirrors.txt', 'ubuntu-archive-keyring.gpg'})
            self.assertEqual(sorted(permissions), sorted([(item, 0o644) for item in calls]+[('sourceparts', 0o755)]))
            self.assertEqual((directory/'ubuntu-archive-keyring.gpg').read_bytes(), SYNTHETIC)
            expected = source.replace(D.HOST_MIRROR_URI.encode(), ('mirror+file:'+str(directory/'mirrors.txt')).encode())
            expected = expected.replace(D.KEYRING.encode(), str(directory/'ubuntu-archive-keyring.gpg').encode())
            self.assertEqual((directory/'ubuntu.sources').read_bytes(), expected)
            self.assertEqual((directory/'mirrors.txt').read_bytes(), D.mirror_bytes())
            self.assertTrue((directory/'sourceparts').is_dir())
            self.assertEqual(source, source_bytes())

    def test_09_existing_private_keyring_is_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix='chengwang-pin-exclusive-unit-') as name:
            directory = Path(name).resolve(); target = directory/'ubuntu-archive-keyring.gpg'
            target.write_bytes(b'preexisting synthetic marker')
            with self.pin(), self.assertRaises((OSError, ValueError)):
                D.private_files(directory, source_bytes(), SYNTHETIC)
            self.assertEqual(target.read_bytes(), b'preexisting synthetic marker')

    def test_10_private_readback_binds_both_signers_and_complete_keyring_metadata(self):
        with self.readback() as (reader, original): value = D.private_readback(PRIVATE)
        key = value['keyring']
        self.assertEqual(set(key), {'path', 'bytes', 'sha256', 'uid', 'gid', 'mode', 'sha512'})
        self.assertEqual(key, {**metadata(PRIVATE/'ubuntu-archive-keyring.gpg', SYNTHETIC), 'sha512': digest(SYNTHETIC)})
        self.assertEqual(value['source']['replacedSigners'], 2)
        self.assertEqual(value['source']['replacedURIs'], 2)
        self.assertEqual(value['source']['normalizedHostSHA256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(reader.call_count, 3)

    def test_11_private_readback_rejects_changed_keyring_bytes_and_length(self):
        for raw in (b'X'+SYNTHETIC[1:], SYNTHETIC[:-1], SYNTHETIC+b'X'):
            with self.subTest(size=len(raw)), self.readback(key_raw=raw):
                with self.assertRaises(ValueError): D.private_readback(PRIVATE)

    def test_12_private_readback_rejects_unsafe_mode_owner_and_group(self):
        for changed in ({'mode': 0o666}, {'mode': 0o777}, {'mode': 0o640}, {'uid': 0}, {'gid': 0}):
            with self.subTest(changed=changed), self.readback(key_changes=changed):
                with self.assertRaises(ValueError): D.private_readback(PRIVATE)

    def test_13_multiple_or_duplicate_source_signers_fail_before_any_copy(self):
        source = source_bytes()
        for bad in (source.replace(D.KEYRING.encode(), D.KEYRING.encode()+b' /unapproved.gpg', 1),
                    source.replace(b'Signed-By:', b'Signed-By: '+D.KEYRING.encode()+b'\nSigned-By:', 1)):
            with self.subTest(source=bad), mock.patch.object(D.os, 'open') as opened:
                with self.assertRaises(ValueError): D.private_files(PRIVATE, bad, SYNTHETIC)
                opened.assert_not_called()

    def test_14_private_signer_tampering_never_normalizes_into_an_approved_source(self):
        def changed(raw):
            return raw.replace(str(PRIVATE/'ubuntu-archive-keyring.gpg').encode(), b'/unapproved.gpg', 1)
        with self.readback(source_change=changed):
            with self.assertRaises(ValueError): D.private_readback(PRIVATE)

    def test_15_creation_forwards_only_pinned_bytes_and_never_changes_host_permissions(self):
        source, mirrors = source_bytes(), D.mirror_bytes(); result = {'synthetic': True}
        def read(path, maximum, **kwargs):
            self.assertEqual(kwargs, {'system_owned': True})
            self.assertIn(path, (D.HOST_SOURCE, D.HOST_MIRROR))
            return (source if path == D.HOST_SOURCE else mirrors), {}
        with mock.patch.multiple(D, HOST_SOURCE_SIZE=len(source), HOST_SOURCE_SHA=hashlib.sha256(source).hexdigest(),
                HOST_MIRROR_SIZE=len(mirrors), HOST_MIRROR_SHA=hashlib.sha256(mirrors).hexdigest()), \
             mock.patch.object(D, 'read_file', side_effect=read), \
             mock.patch.object(D, 'pinned_candidate_keyring', return_value=SYNTHETIC) as candidate, \
             mock.patch.object(D, 'make_private_directory', return_value=PRIVATE), \
             mock.patch.object(D, 'private_files') as copied, \
             mock.patch.object(D, 'private_readback', return_value=result), \
             mock.patch.object(D.os, 'chmod', side_effect=AssertionError('host chmod forbidden')):
            self.assertEqual(D.create_private_sources(), result)
            candidate.assert_called_once_with(); copied.assert_called_once_with(PRIVATE, source, SYNTHETIC)


if __name__ == '__main__': unittest.main()
