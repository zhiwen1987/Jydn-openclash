"""Pure auxiliary contracts. No Go, helper, sockets or namespaces are run."""
import base64
import copy
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock

_spec = importlib.util.spec_from_file_location('subscription_runner_under_test', pathlib.Path(__file__).with_name('run_subscription_lab.py'))
lab = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lab)


def sample_profile():
    return {'pid': 101, 'startTicks': 99, 'uid': 10001, 'gid': 10001, 'capabilities': 'none', 'noNewPrivileges': True,
            'netNamespace': 'net:[2]', 'mountNamespace': 'mnt:[3]', 'pidNamespace': 'pid:[4]'}


def sample_receipt():
    return {'commandId': 'cmd_' + 'a' * 32, 'state': 'committed', 'auditRecorded': True, 'stateMayHaveChanged': False,
            'preparedAuditHash': 'a' * 64, 'resultAuditHash': 'b' * 64, 'sourceId': 'src_' + 'c' * 32, 'revision': 3}


class RunnerContracts(unittest.TestCase):
    def test_cli_requires_exact_inputs(self):
        values = ['--' + key + '=' + value for key, value in [('server-binary', '/tools/server'), ('wire-script', '/tools/wire.py'), ('private-root', '/tmp/chengwang-subscription-private-' + 'a' * 32), ('evidence-dir', '/evidence'), ('source-commit', 'a' * 40), ('build-record', '/evidence/build.json')]]
        parsed = lab.arguments(values)
        self.assertEqual(parsed.server_binary, '/tools/server')
        with mock.patch('sys.stderr'):
            with self.assertRaises(lab.Failure):
                lab.arguments(values[:-1])
            with self.assertRaises(lab.Failure):
                lab.arguments(values + ['--allow-insecure=true'])
            with self.assertRaises(lab.Failure):
                lab.arguments([item.replace('--server-binary=', '--server-b=') for item in values])
        with mock.patch('sys.stderr') as output, mock.patch.object(lab.os, 'umask'):
            self.assertEqual(lab.main(['--private-token=sentinel-CLI-secret']), 1)
            self.assertNotIn('sentinel-CLI-secret', str(output.mock_calls))

    def test_platform_identity_fails_closed(self):
        with mock.patch.object(lab.sys, 'platform', 'not-linux'):
            with self.assertRaises(lab.Failure):
                lab.platform_profile()
        with mock.patch.object(lab.sys, 'platform', 'linux'), mock.patch.object(lab.os, 'geteuid', return_value=0, create=True), mock.patch.object(lab.os, 'getegid', return_value=10001, create=True):
            with self.assertRaises(lab.Failure):
                lab.platform_profile()

    def test_capability_and_no_new_privileges(self):
        text = 'Uid:\t10001 10001 10001 10001\nGid:\t10001 10001 10001 10001\nGroups:\nNoNewPrivs:\t1\n' + ''.join(key + ':\t0000000000000000\n' for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))
        stat_text = '101 (fixture worker) ' + ' '.join(['S'] + ['0'] * 18 + ['99'])
        def read(path):
            return text if path.name == 'status' else stat_text
        with mock.patch.object(pathlib.Path, 'read_text', autospec=True, side_effect=read), mock.patch.object(lab.os, 'readlink', return_value='namespace:[2]'):
            self.assertEqual(lab.profile(101)['startTicks'], 99)
            text = text.replace('NoNewPrivs:\t1', 'NoNewPrivs:\t0')
            with self.assertRaises(lab.Failure):
                lab.profile(101)

    def test_private_root_is_empty_and_canonical(self):
        self.assertIsNotNone(lab.ROOT_NAME.fullmatch('chengwang-subscription-private-' + 'a' * 32))
        self.assertIsNone(lab.ROOT_NAME.fullmatch('chengwang-subscription-private-' + 'A' * 32))
        self.assertIsNone(lab.ROOT_NAME.fullmatch('chengwang-subscription-private-../other'))
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'value'
            path.write_bytes(b'not-directory')
            with self.assertRaises(lab.Failure):
                lab.safe_path(path, directory=True)

    def test_evidence_root_separate_and_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'output'
            lab.exclusive(path, b'original')
            with self.assertRaises(FileExistsError):
                lab.exclusive(path, b'overwritten')
            self.assertEqual(path.read_bytes(), b'original')
        expected = lab.contract.PUBLIC_FILES - {'build.json', 'source-before.json', 'source-after.json', 'isolation.json'}
        self.assertEqual(len(expected), 16)
        self.assertEqual(len(lab.contract.PUBLIC_FILES), 20)

    def test_nofollow_owner_mode_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'input'
            path.write_bytes(b'fixture')
            # The auxiliary positive branch explicitly uses synthetic POSIX
            # metadata. The historical Windows channel mismatch was not
            # uniquely attributed. Runtime custody checks remain unchanged.
            observed_fd = types.SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600,
                st_uid=10001, st_gid=10001, st_nlink=1, st_size=7, st_mtime_ns=10, st_ctime_ns=11)
            with mock.patch.object(lab.os, 'fstat', return_value=observed_fd), mock.patch.object(lab.os, 'stat', return_value=observed_fd):
                self.assertEqual(lab.stable_read(path, 7, owner=None, mode=None), b'fixture')
            with mock.patch.object(lab.os, 'fstat') as observed:
                actual = path.stat()
                invalid = types.SimpleNamespace(**{name: getattr(actual, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}, st_nlink=2)
                observed.return_value = invalid
                with self.assertRaises(lab.Failure):
                    lab.stable_read(path, 7, owner=None, mode=None)
            for kind in (stat.S_IFLNK, stat.S_IFIFO):
                invalid = copy.copy(observed_fd)
                invalid.st_mode = kind | 0o600
                with mock.patch.object(lab.os, 'fstat', return_value=invalid):
                    with self.assertRaises(lab.Failure):
                        lab.stable_read(path, 7, owner=None, mode=None)

    def test_bounded_private_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'large'
            path.write_bytes(b'x' * 17)
            with self.assertRaises(lab.Failure):
                lab.stable_read(path, 16, owner=None, mode=None)
        with self.assertRaises(lab.Failure):
            lab.decode(b'{"version":1,"version":2}')
        with self.assertRaises(lab.Failure):
            lab.decode(b'{"version":NaN}')

    def test_certificate_commands_are_fixed(self):
        commands = lab.certificate_commands(pathlib.Path('/private'))
        self.assertEqual(len(commands), 17)
        self.assertEqual(sum(args[0] == 'genpkey' for args in commands), 7)
        self.assertEqual(sum(args[0] == 'x509' for args in commands), 3)
        self.assertTrue(all('-out' in args for args in commands))
        self.assertFalse(any('-CApath' in args or '-no_check_time' in args for args in commands))
        self.assertTrue(all(args[args.index('-days') + 1] == '2' for args in commands if '-days' in args))

    def test_private_credentials_are_high_entropy(self):
        first, second = lab.credentials(), lab.credentials()
        self.assertEqual(set(first), set(lab.contract.ROLES))
        self.assertEqual(len(set(first.values())), 7)
        self.assertTrue(set(first.values()).isdisjoint(second.values()))
        self.assertTrue(all(len(base64.urlsafe_b64decode(value + '=')) == 32 for value in first.values()))
        identities = lab.identity_file(first)
        raw = lab.encoded(identities)
        self.assertEqual(identities['version'], 1)
        self.assertFalse(any(token.encode() in raw for token in first.values()))

    def test_policy_material_change_is_single_input(self):
        source_tokens = {ref: 'a' * 64 for ref in lab.contract.REFERENCE_IDS}
        with mock.patch.object(lab, 'stable_read', return_value=b'public fixture CA'):
            first, second = lab.policies(pathlib.Path('/private'), source_tokens)
        self.assertEqual(first['sources'][0]['referenceId'], 'good-a')
        self.assertEqual(second['sources'][0]['secretVersion'], 'v2')
        second['sources'][0]['secretVersion'] = 'v1'
        self.assertEqual(first, second)
        self.assertTrue(all(v['revision'] == 1 for v in first['sources']))
        self.assertEqual(first['resolver']['serverName'], 'resolver.subscription.example')

    def test_environment_is_closed(self):
        with mock.patch.dict(os.environ, {'HTTPS_PROXY': 'private', 'SSL_CERT_FILE': 'foreign', 'CHENGWANG_ALLOW_PUBLISH': 'true'}):
            env = lab.child_environment(pathlib.Path('/private'), 3)
        self.assertEqual(env['CHENGWANG_SUBSCRIPTION_WRITES_ENABLED'], 'false')
        self.assertEqual(env['CHENGWANG_SUBSCRIPTIONS_ENABLED'], 'true')
        self.assertNotIn('HTTPS_PROXY', env)
        self.assertNotIn('SSL_CERT_FILE', env)
        self.assertNotIn('HOME', env)
        self.assertNotIn('CHENGWANG_ALLOW_PUBLISH', env)
        self.assertEqual(pathlib.Path(lab.child_environment(pathlib.Path('/private'), 2)['CHENGWANG_SUBSCRIPTION_POLICY_FILE']).name, 'policy2.json')

    def test_server_argv_has_no_secrets(self):
        source = pathlib.Path(lab.__file__).read_text(encoding='utf-8')
        self.assertIn('self.launch([str(self.binary_path)], epoch)', source)
        self.assertNotIn('shell=True', source)
        self.assertNotIn('InsecureSkipVerify', source)
        self.assertNotIn('CERT_NONE', source)

    def test_process_identity_and_starttime(self):
        raw = '3 (name with ) characters) ' + ' '.join(['S'] + ['1'] * 18 + ['12345'])
        self.assertEqual(lab.parse_stat(raw), 12345)
        with self.assertRaises(lab.Failure):
            lab.parse_stat('malformed process')
        self.assertNotEqual(lab.sha(b'/tools/server\0'), lab.sha(b'/tools/server\0--other\0'))

    def test_process_profile_rejects_privilege(self):
        text = 'Uid: 0 0 0 0\nGid: 10001 10001 10001 10001\nGroups:\nNoNewPrivs: 1\n'
        with mock.patch.object(pathlib.Path, 'read_text', return_value=text):
            with self.assertRaises(lab.Failure):
                lab.profile(3)
        actual = sample_profile()
        value = {'schema': 'chengwang.subscription-isolation/v1', 'outerNetNamespace': actual['netNamespace'],
                 'netNamespace': actual['netNamespace'], 'mountNamespace': actual['mountNamespace'], 'pidNamespace': actual['pidNamespace'],
                 'uid': 10001, 'gid': 10001, 'capabilities': lab.ZERO, 'noNewPrivileges': 1, 'interfaces': ['lo'],
                 'ipv4Addresses': ['127.0.0.1/8', '8.8.4.4/32'], 'ipv4DefaultRoutes': [], 'ipv6DefaultRoutes': [], 'unprivilegedPortStart': 0}
        with self.assertRaises(lab.Failure):
            lab.validate_isolation(value, actual)

    def test_stop_requires_normal_exit_zero(self):
        process = mock.Mock(pid=101)
        process.poll.return_value = None
        process.wait.return_value = 0
        with mock.patch.object(lab, 'profile', return_value=sample_profile()), mock.patch.object(pathlib.Path, 'exists', return_value=False), mock.patch.object(lab, 'owned_session_remains', return_value=False):
            record = lab.stop_process(process, sample_profile())
            self.assertEqual(record['exitCode'], 0)
            self.assertFalse(record['forced'])
            process.send_signal.assert_called_once_with(lab.signal.SIGTERM)
            process.wait.return_value = 137
            with self.assertRaises(lab.Failure):
                lab.stop_process(process, sample_profile())
            process.wait.return_value = 0
            with mock.patch.object(lab, 'owned_session_remains', return_value=True):
                with self.assertRaises(lab.Failure):
                    lab.stop_process(process, sample_profile())

    def test_cleanup_never_claims_success_on_kill(self):
        process = mock.Mock(pid=101)
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('fixture', 15), 0]
        self.assertTrue(lab.emergency_stop(process))
        process.kill.assert_called_once_with()
        process = mock.Mock(pid=102)
        process.poll.return_value = 0
        self.assertFalse(lab.emergency_stop(process))
        process.send_signal.assert_not_called()
        observed = types.SimpleNamespace(stage='private-token-sentinel', captures=[], active=[mock.Mock()])
        observed.active[0].poll.side_effect = RuntimeError('private-token-sentinel')
        report = lab.failure_observation(observed)
        self.assertEqual(report['stage'], 'INPUT')
        self.assertEqual(report['activeChildExitCodes'], [None])
        self.assertNotIn('private-token-sentinel', str(report))

    def test_capture_contract_order_is_exact(self):
        captures = []
        for ordinal, (name, epoch, status_code) in enumerate(lab.contract.CAPTURES, 1):
            value = dict.fromkeys(lab.contract.CAPTURE_KEYS)
            value.update(ordinal=ordinal, name=name, epoch=epoch, status=status_code)
            captures.append(value)
        lab.ensure_capture_order(captures)
        self.assertEqual(len(captures), 46)
        captures[0], captures[1] = captures[1], captures[0]
        with self.assertRaises(lab.Failure):
            lab.ensure_capture_order(captures)
        with self.assertRaises(lab.Failure):
            lab.ensure_capture_order(captures[:-1])

    def test_api_body_is_bounded_and_typed(self):
        value = {'boundary': lab.contract.BOUNDARY, 'authorization': 'BLOCKED', 'deviceActionsExecuted': False, 'stateMayHaveChanged': False}
        lab.validate_response(lab.encoded(value), b'peer', b'peer')
        value['deviceActionsExecuted'] = 0
        with self.assertRaises(lab.Failure):
            lab.validate_response(lab.encoded(value), b'peer', b'peer')
        with self.assertRaises(lab.Failure):
            lab.validate_response(b'x' * (lab.contract.MAX_CAPTURE_BYTES + 1), b'peer', b'peer')

    def test_public_request_projection_is_closed(self):
        self.assertEqual(lab.public_request('viewer', 'GET', None, '')['body'], None)
        self.assertEqual(lab.public_request('operator', 'POST', {'label': '来源A'}, 'subscription-lab-create_a')['body']['label'], '来源A')
        with self.assertRaises(lab.Failure):
            lab.public_request('operator', 'POST', {'url': 'private'}, 'subscription-lab-key')
        with self.assertRaises(lab.Failure):
            lab.public_request('unknown', 'GET', None, '')
        with self.assertRaises(lab.Failure):
            lab.public_request('viewer', 'GET', {}, '')

    def test_tls_peer_certificate_is_bound(self):
        raw = lab.encoded({'boundary': lab.contract.BOUNDARY, 'authorization': 'BLOCKED', 'deviceActionsExecuted': False, 'stateMayHaveChanged': False})
        lab.validate_response(raw, b'actual DER fixture', b'actual DER fixture')
        with self.assertRaises(lab.Failure):
            lab.validate_response(raw, b'foreign DER fixture', b'actual DER fixture')
        with self.assertRaises(lab.Failure):
            lab.validate_response(raw, b'', b'')

    def test_wire_fences_are_complete_prefixes(self):
        self.assertEqual(lab.wire_fence(b''), {'eventCount': 0, 'sha256': lab.sha(b'')})
        event = dict.fromkeys(lab.contract.EVENT_KEYS, '')
        event.update(schema=lab.contract.EVENT_SCHEMA, ordinal=1)
        raw = lab.encoded(event)
        self.assertEqual(lab.wire_fence(raw)['eventCount'], 1)
        with self.assertRaises(lab.Failure):
            lab.wire_fence(raw[:-1])
        event['ordinal'] = 2
        with self.assertRaises(lab.Failure):
            lab.wire_fence(lab.encoded(event))

    def test_state_and_receipt_revision_assertions(self):
        receipt = sample_receipt()
        lab.assert_receipt(receipt, 'committed', receipt['sourceId'], 3)
        with self.assertRaises(lab.Failure):
            lab.assert_receipt(receipt, 'committed', receipt['sourceId'], 2)
        receipt['stateMayHaveChanged'] = True
        with self.assertRaises(lab.Failure):
            lab.assert_receipt(receipt, 'committed')
        sources = {'a': 'src_' + 'a' * 32, 'b': 'src_' + 'b' * 32}
        candidates = {'a': 'cand_' + 'c' * 32, 'b': 'cand_' + 'd' * 32}
        values = [{'id': sources[k], 'revision': 3, 'acceptedCandidateId': candidates[k], 'latestCandidateId': candidates[k], 'scope': lab.contract.SCOPE} for k in ('a', 'b')]
        lab.assert_inventory({'sources': values, 'total': 2}, sources, candidates)
        values[0]['acceptedCandidateId'] = candidates['b']
        with self.assertRaises(lab.Failure):
            lab.assert_inventory({'sources': values, 'total': 2}, sources, candidates)

    def test_publication_scans_secret_variants(self):
        secret = b'private-token-sentinel-0001'
        variants = lab.secret_variants([secret])
        lab.scan_public({'runtime.json': b'public safe fixture'}, variants)
        for raw in (secret, base64.b64encode(secret), lab.sha(secret).encode(), secret.hex().encode()):
            with self.assertRaises(lab.Failure):
                lab.scan_public({'runtime.json': raw}, variants)
        aligned = b'x' + secret + b'yy'
        self.assertNotIn(base64.b64encode(secret), base64.b64encode(aligned))
        with self.assertRaises(lab.Failure):
            lab.scan_public({'captures.jsonl': aligned}, variants)
        with self.assertRaises(lab.Failure):
            lab.scan_public({'runtime.json': b'-----BEGIN PRIVATE KEY-----'}, variants)

    def test_publication_rejects_unknown_and_partial(self):
        with self.assertRaises(lab.Failure):
            lab.scan_public({'identities.json': b'private'}, set())
        with self.assertRaises(lab.Failure):
            lab.scan_public({'runtime.json': b'x' * ((4 << 20) + 1)}, set())
        value = {'schema': 'chengwang.subscription-build/v1', 'sourceCommit': 'a' * 40, 'goVersion': 'go1.23.12', 'moduleMode': 'vendor',
                 'dependencyDownloads': False, 'authorization': 'BLOCKED', 'production': False,
                 'server': {'name': 'server', 'bytes': 7, 'sha256': lab.sha(b'fixture')}}
        lab.validate_build(value, b'fixture', 'a' * 40)
        value['dependencyDownloads'] = 0
        with self.assertRaises(lab.Failure):
            lab.validate_build(value, b'fixture', 'a' * 40)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RunnerContracts))
    accepted = result.wasSuccessful() and result.testsRun == 24 and not result.skipped
    print('SUBSCRIPTION_RUNNER_AUXILIARY_TESTS=' + ('PASS' if accepted else 'FAIL') + ' tests=24 skipped=' + str(len(result.skipped)) + ' synthetic_only=true')
    raise SystemExit(0 if accepted else 1)
