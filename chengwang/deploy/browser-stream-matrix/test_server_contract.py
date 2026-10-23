"""Pure synthetic/AST contracts; never opens a socket, server or Chrome child.

Mocked handler writes are not TLS, browser, process, or on-wire evidence.
"""
import ast
import contextlib
import copy
import importlib.util
import io
import json
import pathlib
import socket
import ssl
import stat
import types
import unittest
from unittest import mock


BASE = pathlib.Path(__file__).resolve().parent


def load(filename, name):
    specification = importlib.util.spec_from_file_location(name, BASE / filename)
    module = importlib.util.module_from_spec(specification); specification.loader.exec_module(module)
    return module


S = load('server.py', 'stream_matrix_server_contract_subject')
L = load('chrome_launcher.py', 'stream_matrix_launcher_contract_subject')


class FakeJournal:
    def __init__(self): self.rows = []; self.seen = set()
    def emit(self, event, case, body=0, framed=0, reason='OK'):
        self.rows.append(S.event_record(len(self.rows) + 1, event, case, body, framed, reason))
    def claim(self, case):
        S.need(case in S.CASES and case not in self.seen); self.seen.add(case)


class TestStreamServerContracts(unittest.TestCase):
    def handler(self, case, receiver=None):
        handler = object.__new__(S.Handler)
        handler.path = '/case/' + case
        handler.headers = {'Host': '127.0.0.1:17881'}
        handler.server = types.SimpleNamespace(journal=FakeJournal())
        handler.wfile = io.BytesIO(); handler.connection = mock.Mock()
        handler.connection.recv.return_value = b''
        if receiver is not None: handler.connection.recv.side_effect = receiver
        handler.close_connection = False; handler.sent_headers = []; handler.statuses = []
        handler.send_response_only = handler.statuses.append
        handler.send_header = lambda key, value: handler.sent_headers.append((key, value))
        handler.end_headers = lambda: None
        return handler

    def invoke(self, handler):
        with mock.patch.object(S.time, 'sleep') as delay:
            handler.do_GET()
        return handler.server.journal.rows, delay

    def config(self):
        fixture = 'a' * 32; bundle = pathlib.PurePosixPath('/tmp/chengwang-stream-tools-' + fixture)
        return bundle, dict(schema='chengwang.stream-matrix-launch/v1', engine='chrome-cdp', fixtureId=fixture,
            root='/tmp/chengwang-stream-matrix-' + fixture, chrome=str(bundle / 'chrome/chrome'), chromeSHA256='b' * 64)

    def test_split_payload_is_exact_eleven_bytes_with_six_five_split(self):
        plan = S.response_plan('split-success')
        self.assertEqual(plan['body'], b'{"ok":true}'); self.assertEqual(len(plan['body']), 11)
        self.assertEqual(tuple(map(len, plan['parts'])), (6, 5)); self.assertEqual(plan['contentLength'], 11)

    def test_boundary_payload_is_exact_one_mebibyte_valid_json_and_ascii_padding(self):
        plan = S.response_plan('boundary-success')
        self.assertEqual(len(plan['body']), 1048576)
        self.assertEqual(json.loads(plan['body']), {'data': 'a' * 1048565})
        self.assertEqual(tuple(map(len, plan['parts'])), (524288, 524288))

    def test_oversize_payload_is_exactly_one_byte_over_and_has_no_content_length(self):
        plan = S.response_plan('oversize')
        self.assertEqual(len(plan['body']), 1048577)
        self.assertEqual(json.loads(plan['body']), {'data': 'a' * 1048566})
        self.assertIsNone(plan['contentLength']); self.assertTrue(plan['chunked'])
        self.assertEqual(tuple(map(len, plan['parts'])), (524288, 524289))

    def test_http_chunk_frames_include_exact_prefix_suffix_not_tls_bytes(self):
        self.assertEqual(S.chunk_frame(b'abcdef'), b'6\r\nabcdef\r\n')
        for body in (b'', b'a' * (S.MAX_BODY + 1), 'SYNTHETIC'):
            with self.assertRaises(S.Rejected): S.chunk_frame(body)

    def test_headers_are_no_store_json_and_only_oversize_uses_chunked(self):
        for case in S.CASES:
            handler = self.handler(case); plan = S.response_plan(case)
            handler.headers_for(plan['contentLength'], plan['chunked'])
            headers = dict(handler.sent_headers)
            self.assertEqual(headers['Cache-Control'], 'no-store')
            self.assertEqual(headers['Content-Type'], 'application/json')
            if case == 'oversize':
                self.assertNotIn('Content-Length', headers); self.assertEqual(headers['Transfer-Encoding'], 'chunked')
            else:
                self.assertEqual(headers['Content-Length'], str(len(plan['body'])))
                self.assertNotIn('Transfer-Encoding', headers)

    def test_split_handler_records_two_actual_write_returns_and_twenty_millisecond_gap(self):
        handler = self.handler('split-success'); rows, delay = self.invoke(handler)
        self.assertEqual(handler.wfile.getvalue(), b'{"ok":true}'); delay.assert_called_once_with(0.020)
        self.assertEqual([r['event'] for r in rows], ['REQUEST', 'WRITE_RETURNED', 'WRITE_RETURNED', 'COMPLETE'])
        self.assertEqual([r['bodyBytes'] for r in rows], [0, 6, 5, 11])

    def test_boundary_handler_never_changes_the_exact_budget_or_declared_length(self):
        handler = self.handler('boundary-success'); rows, _ = self.invoke(handler)
        self.assertEqual(len(handler.wfile.getvalue()), 1048576)
        self.assertEqual(rows[-1]['bodyBytes'], 1048576); self.assertEqual(rows[-1]['framedBytes'], 1048576)
        self.assertIn(('Content-Length', '1048576'), handler.sent_headers)

    def test_oversize_handler_writes_two_real_chunks_and_zero_terminator_without_cl(self):
        handler = self.handler('oversize'); rows, delay = self.invoke(handler)
        plan = S.response_plan('oversize')
        expected = b''.join(S.chunk_frame(part) for part in plan['parts']) + b'0\r\n\r\n'
        self.assertEqual(handler.wfile.getvalue(), expected); self.assertEqual(len(expected), 1048600)
        self.assertEqual([r['bodyBytes'] for r in rows], [0, 524288, 524289, 0, 1048577])
        self.assertEqual(rows[-1]['framedBytes'], 1048600); delay.assert_called_once_with(0.020)
        self.assertNotIn('Content-Length', dict(handler.sent_headers))

    def test_truncated_handler_advertises_eleven_sends_only_six_and_closes(self):
        handler = self.handler('truncated'); rows, delay = self.invoke(handler)
        self.assertEqual(handler.wfile.getvalue(), b'{"ok":'); self.assertTrue(handler.close_connection)
        self.assertEqual(rows[-1]['bodyBytes'], 6); self.assertIn(('Content-Length', '11'), handler.sent_headers)
        delay.assert_called_once_with(0.020); handler.connection.recv.assert_not_called()

    def test_abort_handler_waits_for_observed_peer_close_without_sending_tail(self):
        handler = self.handler('abort'); rows, delay = self.invoke(handler)
        self.assertEqual(handler.wfile.getvalue(), b'{"ok":'); delay.assert_not_called()
        handler.connection.settimeout.assert_called_once_with(3); handler.connection.recv.assert_called_once_with(1)
        self.assertEqual([r['event'] for r in rows], ['REQUEST', 'WRITE_RETURNED', 'PEER_CLOSED', 'COMPLETE'])
        self.assertEqual(rows[2]['reason'], 'PEER_CLOSED'); self.assertEqual(rows[-1]['bodyBytes'], 6)

    def test_abort_deadline_is_failure_not_a_synthetic_peer_close(self):
        handler = self.handler('abort', socket.timeout()); rows, _ = self.invoke(handler)
        self.assertEqual(rows[-1]['event'], 'ERROR'); self.assertEqual(rows[-1]['reason'], 'DEADLINE')
        self.assertNotIn('PEER_CLOSED', [r['event'] for r in rows]); self.assertEqual(handler.wfile.getvalue(), b'{"ok":')

    def test_abort_peer_reset_is_closed_but_positive_write_failure_is_error(self):
        for error in (ssl.SSLEOFError(), ConnectionResetError(), BrokenPipeError()):
            handler = self.handler('abort', error); rows, _ = self.invoke(handler)
            self.assertEqual(rows[-2]['event'], 'PEER_CLOSED')
        handler = self.handler('split-success'); handler.wfile = mock.Mock()
        handler.wfile.write.side_effect = BrokenPipeError(); rows, _ = self.invoke(handler)
        self.assertEqual(rows[-1]['event'], 'ERROR'); self.assertEqual(rows[-1]['reason'], 'PEER_CLOSED')

    def test_case_claim_is_single_use_and_duplicate_requests_fail_without_retry(self):
        handler = self.handler('split-success'); self.invoke(handler); self.invoke(handler)
        self.assertEqual(handler.server.journal.rows[-1]['event'], 'ERROR')
        self.assertEqual(handler.server.journal.rows[-1]['reason'], 'INVALID')
        self.assertEqual(handler.wfile.getvalue(), b'{"ok":true}')

    def test_unknown_path_query_host_and_request_body_cannot_enter_a_fixture(self):
        for change in ('query', 'unknown', 'host', 'body', 'transfer'):
            handler = self.handler('split-success')
            if change == 'query': handler.path += '?SYNTHETIC'
            elif change == 'unknown': handler.path = '/case/unknown'
            elif change == 'host': handler.headers['Host'] = 'foreign.invalid'
            elif change == 'body': handler.headers['Content-Length'] = '1'
            else: handler.headers['Transfer-Encoding'] = 'chunked'
            rows, _ = self.invoke(handler)
            self.assertEqual([r['event'] for r in rows], ['ERROR']); self.assertEqual(handler.wfile.getvalue(), b'')

    def test_document_is_small_static_and_has_no_external_or_http_favicon(self):
        self.assertLess(len(S.HTML), 1024); self.assertIn(b'href="data:,"', S.HTML)
        self.assertNotIn(b'http', S.HTML); self.assertNotIn(b'<script', S.HTML)
        handler = self.handler('split-success'); handler.path = '/'; rows, _ = self.invoke(handler)
        self.assertEqual(handler.wfile.getvalue(), S.HTML); self.assertEqual(rows[-1]['caseId'], 'none')

    def test_event_schema_enums_and_exact_budgets_are_closed_without_wire_claim(self):
        row = S.event_record(1, 'WRITE_RETURNED', 'oversize', 2, 7)
        self.assertEqual(set(row), {'schema', 'ordinal', 'event', 'caseId', 'bodyBytes', 'framedBytes', 'reason'})
        for args in [(True, 'REQUEST', 'none'), (129, 'REQUEST', 'none'), (1, [], 'none'),
                     (1, 'UNKNOWN', 'none'), (1, 'REQUEST', 'none', 1, 1),
                     (1, 'WRITE_RETURNED', 'oversize', 1048578, 1048578),
                     (1, 'WRITE_RETURNED', 'oversize', 8, 7)]:
            with self.assertRaises(S.Rejected): S.event_record(*args)

    def test_write_return_counter_rejects_partial_none_and_boolean_returns(self):
        for returned in (None, True, 2):
            writer = mock.Mock(); writer.write.return_value = returned; journal = FakeJournal()
            with self.assertRaises(S.Rejected): S.write_piece(writer, journal, 'split-success', b'abcdef')
            self.assertEqual(journal.rows, [])

    def test_private_input_links_owners_modes_and_size_fail_before_any_open(self):
        valid = dict(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=10001, st_gid=10001, st_size=16)
        for field, value in [('st_mode', stat.S_IFLNK | 0o600), ('st_mode', stat.S_IFREG | 0o640),
                             ('st_nlink', 2), ('st_uid', 0), ('st_gid', 0), ('st_size', 0), ('st_size', 65537)]:
            metadata = dict(valid); metadata[field] = value
            with mock.patch.object(pathlib.Path, 'lstat', return_value=types.SimpleNamespace(**metadata)), mock.patch.object(S.os, 'open') as opened:
                with self.assertRaises(S.Rejected): S.private_file(pathlib.Path('/SYNTHETIC'))
                opened.assert_not_called()

    def test_launcher_config_binds_only_fixed_bundle_fixture_and_selected_elf(self):
        bundle, config = self.config(); fixture, root, chrome = L.validate_config(config, bundle)
        self.assertEqual(fixture, 'a' * 32); self.assertEqual(chrome.as_posix(), config['chrome'])
        for key, value in [('engine', []), ('fixtureId', 'b' * 32), ('root', '/tmp/other'),
                           ('chrome', '/opt/google/chrome/chrome'), ('chromeSHA256', 'B' * 64), ('extra', 'SYNTHETIC')]:
            changed = copy.deepcopy(config); changed[key] = value
            with self.assertRaises(L.Rejected): L.validate_config(changed, bundle)

    def test_launcher_config_duplicate_nonfinite_extra_and_invalid_root_fail_closed(self):
        with self.assertRaises(L.Rejected): L.decode_config(b'{"a":1,"a":2}')
        with self.assertRaises(L.Rejected): L.decode_config(b'{"a":NaN}')
        for root in ('/tmp/chengwang-stream-matrix-' + 'A' * 32, '/tmp/../tmp/chengwang-stream-matrix-' + 'a' * 32, '/tmp/other', []):
            with self.assertRaises(S.Rejected): S.fixture_root(root)

    def test_launcher_arguments_require_exact_profile_and_forbid_all_tls_bypasses(self):
        profile = pathlib.Path('/tmp/chengwang-stream-matrix-' + 'a' * 32 + '/chrome-profile')
        base = ['--no-sandbox', '--remote-debugging-pipe', '--user-data-dir=' + str(profile)]
        L.validate_arguments(base, profile)
        for extra in ('--ignore-certificate-errors', '--ignore-certificate-errors-spki-list=SYNTHETIC',
                      '--ignore-ssl-errors', '--allow-insecure-localhost', '--disable-web-security',
                      '--unsafely-treat-insecure-origin-as-secure=https://127.0.0.1',
                      '--allow-running-insecure-content', '--user-data-dir=/tmp/other', 'BAD\nARG'):
            with self.assertRaises(L.Rejected): L.validate_arguments(base + [extra], profile)
        with self.assertRaises(L.Rejected): L.validate_arguments(base[1:], profile)

    def test_launcher_environment_does_not_inherit_home_proxy_trust_or_python_options(self):
        root = pathlib.Path('/tmp/chengwang-stream-matrix-' + 'a' * 32)
        with mock.patch.dict(L.os.environ, {'HOME': '/SYNTHETIC', 'HTTPS_PROXY': 'SYNTHETIC', 'SSL_CERT_FILE': 'SYNTHETIC', 'PYTHONPATH': 'SYNTHETIC'}):
            environment = L.environment(root, root / 'chrome-profile')
        self.assertEqual(set(environment), {'PATH', 'LANG', 'LC_ALL', 'TMPDIR', 'XDG_DATA_HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME'})
        self.assertEqual(environment['TMPDIR'], '/var/tmp'); self.assertNotIn('HOME', environment)

    def test_exit_witness_keeps_actual_nonzero_and_forced_state_instead_of_green(self):
        result = L.exit_record('playwright', 'a' * 32, 12, 123, -15, True)
        self.assertEqual(result['exitCode'], -15); self.assertTrue(result['forced']); self.assertTrue(result['joined'])
        self.assertEqual(set(result), {'schema', 'engine', 'fixtureId', 'pid', 'startTicks', 'exitCode', 'joined', 'forced'})
        for values in [('playwright', 'a' * 32, True, 1, 0, False), ('playwright', 'a' * 32, 12, 1, False, False)]:
            with self.assertRaises(L.Rejected): L.exit_record(*values)
        for late_wait in (False, True):
            child = mock.Mock(pid=12, stdin=None)
            child.poll.side_effect = [None, None, 0] if late_wait else [None, 0]
            child.wait.side_effect = ([L.subprocess.TimeoutExpired('SYNTHETIC', 2), 0] if late_wait
                                      else [L.subprocess.TimeoutExpired('SYNTHETIC', 2)])
            intervention = dict(forced=False)
            with mock.patch.object(L.os, 'pidfd_open', create=True, side_effect=ProcessLookupError()), \
                 mock.patch.object(L.signal, 'pidfd_send_signal', create=True) as sent:
                self.assertEqual(L.cleanup_child(child, intervention), 0)
            self.assertFalse(intervention['forced']); sent.assert_not_called()
        for kill in (False, True):
            code = -9 if kill else -15
            child = mock.Mock(pid=12, stdin=None); child.poll.side_effect = [None, code]
            child.wait.side_effect = ([L.subprocess.TimeoutExpired('SYNTHETIC', 2),
                L.subprocess.TimeoutExpired('SYNTHETIC', 8), code] if kill
                else [L.subprocess.TimeoutExpired('SYNTHETIC', 2), code])
            intervention = dict(forced=False)
            with mock.patch.object(L.os, 'pidfd_open', create=True, return_value=7), \
                 mock.patch.object(L.signal, 'pidfd_send_signal', create=True) as sent, \
                 mock.patch.object(L.signal, 'SIGKILL', 9, create=True), \
                 mock.patch.object(L.os, 'close'):
                self.assertEqual(L.cleanup_child(child, intervention), code)
            self.assertTrue(intervention['forced']); self.assertEqual(sent.call_count, 2 if kill else 1)

    def test_launcher_source_preserves_fds_gated_session_and_never_imports_product_helpers(self):
        source = (BASE / 'chrome_launcher.py').read_text(encoding='utf-8'); tree = ast.parse(source)
        commands = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess' and node.func.attr == 'Popen']
        self.assertEqual(len(commands), 1)
        keywords = {keyword.arg: keyword.value for keyword in commands[0].keywords}
        self.assertIs(ast.literal_eval(keywords['close_fds']), False)
        self.assertIs(ast.literal_eval(keywords['start_new_session']), True)
        gate = L.gate_command(pathlib.Path('/SYNTHETIC/chrome'), ['--no-sandbox'])
        self.assertIn('read -r launch_gate', gate[4]); self.assertIn('exec "$@"', gate[4])
        self.assertNotIn('import run_probe_readback', source); self.assertNotIn('import check_probe', source)
        self.assertNotIn('os.link(', source)
        self.assertLess(source.index("publish(root / 'chrome-process.private.json'"), source.index("child.stdin.write(b'start\\n')"))
        class SyntheticPosixPath(pathlib.PurePosixPath):
            def absolute(self): return self
        bundle, config = self.config(); config['chromeSHA256'] = L.hashlib.sha256(b'\x7fELFSYNTHETIC').hexdigest()
        metadata = types.SimpleNamespace(st_gid=10001)
        child = mock.Mock(pid=12); child.poll.side_effect = RuntimeError('SYNTHETIC_PRIVATE_ERROR')
        args = ['--no-sandbox', '--user-data-dir=' + config['root'] + '/chrome-profile']
        captured = io.StringIO()
        with mock.patch.object(L.sys, 'platform', 'linux'), \
             mock.patch.object(L.os, 'geteuid', create=True, return_value=10001), \
             mock.patch.object(L.os, 'getegid', create=True, return_value=10001), \
             mock.patch.dict(L.os.environ, {'TMPDIR': '/var/tmp'}, clear=True), \
             mock.patch.object(L, '__file__', str(bundle / 'matrix-chrome-launcher')), \
             mock.patch.object(L.pathlib, 'Path', SyntheticPosixPath), \
             mock.patch.object(L, 'directory', return_value=metadata), \
             mock.patch.object(L, 'stable_file', side_effect=[(L.canonical(config), metadata), (b'\x7fELFSYNTHETIC', metadata)]), \
             mock.patch.object(L.signal, 'signal'), \
             mock.patch.object(L.subprocess, 'Popen', return_value=child), \
             mock.patch.object(L, 'start_ticks', side_effect=L.Rejected()), contextlib.redirect_stderr(captured):
            self.assertEqual(L.main(args), 1)
        self.assertEqual(captured.getvalue(), 'STREAM_MATRIX_CHROME_LAUNCHER=FAIL raw_input_suppressed=true\n'
                         'STREAM_MATRIX_CHROME_CLEANUP=FAIL raw_input_suppressed=true\n')
        self.assertNotIn('SYNTHETIC_PRIVATE_ERROR', captured.getvalue()); self.assertNotIn('Traceback', captured.getvalue())
        for module in (S, L):
            for rename_code in (0, -1):
                operation = mock.Mock(return_value=rename_code)
                library = types.SimpleNamespace(renameat2=operation)
                output = pathlib.Path('/SYNTHETIC/private/ready.private.json')
                with mock.patch.object(module.os, 'O_NOFOLLOW', 0x20000, create=True), \
                     mock.patch.object(module.os, 'O_CLOEXEC', 0x80000, create=True), \
                     mock.patch.object(module.os, 'open', return_value=7) as opened, \
                     mock.patch.object(module.os, 'fdopen') as fdopen, \
                     mock.patch.object(module.os, 'fsync') as synced, \
                     mock.patch.object(module.os, 'close') as closed, \
                     mock.patch.object(module.ctypes, 'CDLL', return_value=library), \
                     mock.patch.object(pathlib.Path, 'exists', return_value=rename_code != 0), \
                     mock.patch.object(pathlib.Path, 'unlink') as removed:
                    stream = fdopen.return_value.__enter__.return_value
                    if rename_code == 0: module.publish(output, {'synthetic': True})
                    else:
                        with self.assertRaises(module.Rejected): module.publish(output, {'synthetic': True})
                    temporary, flags, mode = opened.call_args.args
                    self.assertEqual(mode, 0o600)
                    self.assertTrue(flags & module.os.O_EXCL); self.assertTrue(flags & module.os.O_NOFOLLOW)
                    stream.write.assert_called_once(); stream.flush.assert_called_once(); synced.assert_called_once_with(7)
                    operation.assert_called_once_with(-100, module.os.fsencode(temporary), -100, module.os.fsencode(output), 1)
                    closed.assert_called_once_with(7)
                    if rename_code == 0: removed.assert_not_called()
                    else: removed.assert_called_once()


if __name__ == '__main__': unittest.main()
