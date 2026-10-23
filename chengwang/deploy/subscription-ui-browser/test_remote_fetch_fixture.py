"""Synthetic CPU contracts only; no TLS, DNS, subprocess or browser starts."""
import ast
import base64
import copy
import importlib.util
import json
import shutil
from pathlib import Path, PurePosixPath
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('remote_fixture_test_' + name, BASE / (name + '.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


F = load('remote_fetch_fixture')
R = load('run_subscription_ui')
FIXTURE = 'a' * 32
COMMIT = 'b' * 40
CA = '-----BEGIN CERTIFICATE-----\nSYNTHETIC-NOT-A-REAL-CERTIFICATE\n-----END CERTIFICATE-----\n'


def private_fixture():
    source = dict(id='src_' + '1' * 32, scope=dict(F.SCOPE), label=F.LABEL, revision=3,
        updatedAt='2026-10-24T00:00:00Z', acceptedCandidateId='cand_' + '2' * 32, latestCandidateId='cand_' + '2' * 32)
    candidate = dict(id=source['acceptedCandidateId'], sourceId=source['id'], scope=dict(F.SCOPE), digest='hmac-sha256:' + '3' * 64,
        format='mihomo-provider-yaml', state='admitted_local', baseRevision=2, nodeCount=2, duplicateCount=0,
        nodes=[dict(id='node_' + str(i) * 32, label='节点 ' + str(i), protocol=protocol, credentialConfigured=True, state='unknown')
               for i, protocol in enumerate(('http', 'socks5'), 1)], createdAt=source['updatedAt'])
    commands = []
    for i, kind, expected, revision in [(1, 'create', 0, 1), (2, 'approve', 1, 1), (3, 'fetch', 1, 2), (4, 'decide', 2, 3)]:
        result = dict(sourceId=source['id'], revision=revision, state='approved' if kind == 'approve' else 'committed',
                      stateMayHaveChanged=False, completedAt=source['updatedAt'])
        if kind == 'approve':
            result.update(referenceId='good-b', policyRevision=1, policyDigest='hmac-sha256:' + '4' * 64, approvalId='cmd_' + '2' * 32)
        else: result['localAuditHash'] = '5' * 64
        if kind in ('fetch', 'decide'): result.update(candidateId=candidate['id'], digest=candidate['digest'])
        commands.append(dict(record=dict(id='cmd_' + str(i) * 32, scope=dict(F.SCOPE), actorId='act_' + str(i) * 60,
            kind=kind, sourceId=source['id'], expectedRevision=expected, preparedAuditHash='6' * 64, resultAuditHash='7' * 64,
            acknowledged=True, result=result, fingerprint='PRIVATE-CANARY-DO-NOT-EXPORT'), seal='PRIVATE-CANARY-DO-NOT-EXPORT'))
    approval = dict(commandId='cmd_' + '2' * 32, scope=dict(F.SCOPE), sourceId=source['id'], referenceId='good-b',
        policyRevision=1, policyDigest='hmac-sha256:' + '4' * 64, sourceRevision=1, approvedAt=source['updatedAt'],
        seal='PRIVATE-CANARY-DO-NOT-EXPORT')
    return dict(schema='chengwang.subscription-store/v1', identityKey='PRIVATE-CANARY-DO-NOT-EXPORT', sources=[source],
        candidates=[dict(view=candidate, raw='PRIVATE-CANARY-DO-NOT-EXPORT', privateNodes=['PRIVATE-CANARY-DO-NOT-EXPORT'])],
        commands=commands, approvals=[approval], audit=[{}, {}, {}])


def wire_fixture():
    contract = F.wire_contract()
    ready = dict(schema=contract.READY_SCHEMA, pid=123, uid=10001, gid=10001, dotAddress='127.0.0.1', dotPort=1853,
        httpsAddress='8.8.4.4', httpsPort=443, tls=True, deadlineSeconds=180)
    events = []
    for number, service, kind in [(1, 'dot', 'A'), (2, 'dot', 'AAAA'), (3, 'https', '')]:
        for action in ('connect', 'tls', 'dns' if service == 'dot' else 'http', 'close'):
            payload = action in ('dns', 'http')
            events.append(dict(schema=contract.EVENT_SCHEMA, ordinal=len(events) + 1, connection=number,
                service=service, event=action, reference='good-b' if payload else '', queryType=kind if payload else '',
                status=200 if action == 'http' else 0, bytes=20 if payload else 0,
                tls=action != 'connect', reason='closed' if action == 'close' else 'ok',
                receivedUnixNano='1792800000000000000' if payload else ''))
    stopped = dict(schema=contract.STOPPED_SCHEMA, pid=123, termination='term', accepted=3, closed=3,
        events=12, workerThreadsAlive=0, listenersClosed=True, normalStop=True)
    return ready, events, stopped


def wire_bytes(events): return b''.join((json.dumps(e) + '\n').encode() for e in events)


class RemoteFetchFixtureContracts(unittest.TestCase):
    def setUp(self):
        for name in ('Popen', 'run', 'call', 'check_call', 'check_output'):
            patch = mock.patch.object(R.subprocess, name, side_effect=AssertionError('real subprocess forbidden'))
            patch.start(); self.addCleanup(patch.stop)

    def test_import_has_no_process_network_or_runtime_side_effect(self):
        with mock.patch.object(F.os, 'open', side_effect=AssertionError('file I/O forbidden')):
            value = load('remote_fetch_fixture')
            self.assertEqual(value.LABEL, F.LABEL)

    def test_input_is_closed_two_roles_and_has_no_url_or_wire_path_field(self):
        browser, _, _, _ = F.generate(CA, CA)
        self.assertEqual(set(browser), {'schema', 'scenario', 'tokens', 'label', 'canaries'})
        self.assertEqual(set(browser['tokens']), {'operator', 'approver'})
        self.assertEqual(len(browser['canaries']), 22)
        for key in ('files', 'wireRoot', 'sourceURL'):
            changed = copy.deepcopy(browser); changed[key] = 'PRIVATE-CANARY-DO-NOT-EXPORT'
            with self.assertRaises(ValueError): F.forbidden(changed)

    def test_generated_policy_uses_same_revision_distinct_good_references(self):
        browser, identities, policy, wire = F.generate(CA, CA)
        self.assertEqual(policy['scope'], F.SCOPE)
        self.assertEqual([(r['referenceId'], r['revision']) for r in policy['sources']], [('good-a', 1), ('good-b', 1)])
        self.assertEqual(policy['resolver'], dict(upstream='127.0.0.1:1853', serverName='resolver.subscription.example', caPEM=CA))
        self.assertEqual(set(wire['sourceTokensByRef']), set(F.wire_contract().REFERENCE_IDS))
        self.assertEqual(len(identities['identities']), 2)
        self.assertTrue(all(t not in repr(identities) for t in browser['tokens'].values()))

    def test_private_upstream_body_has_two_credentials_but_no_business_health_claim(self):
        browser, _, _, wire = F.generate(CA, CA)
        raw = base64.b64decode(wire['goodBodyBase64'], validate=True)
        nodes = [json.loads(line[4:]) for line in raw.decode().splitlines()[1:]]
        self.assertEqual({n['type'] for n in nodes}, {'http', 'socks5'})
        self.assertEqual([n['server'] for n in nodes], ['198.51.100.40', '198.51.100.41'])
        self.assertTrue(all(n[k] in browser['canaries'] for n in nodes for k in ('name', 'username', 'password')))

    def test_canary_fence_checks_raw_encoded_url_and_sha_variants(self):
        browser, _, _, _ = F.generate(CA, CA); forbidden = F.forbidden(browser)
        token = browser['tokens']['operator']
        for raw in (token.encode(), base64.b64encode(token.encode()), F.sha(token.encode()).encode()):
            self.assertIn(raw, forbidden)
            with self.assertRaises(ValueError): R.public_fence(b'prefix' + raw, forbidden)
        n = type('Decode', (), dict(decode=staticmethod(json.loads)))
        capture = json.dumps(dict(kind='FETCH', responseBase64=base64.b64encode(token.encode()).decode())).encode()
        with self.assertRaises(ValueError): R.public_fence(capture, forbidden, captures=True, N=n, scenario='remote_fetch')

    def test_certificate_commands_keep_normal_dns_sans_and_private_fixed_outputs(self):
        root = PurePosixPath('/tmp/chengwang-subscription-private-' + FIXTURE)
        commands = F.certificate_commands(root)
        self.assertEqual(len(commands), 2)
        self.assertIn(b'DNS:resolver.subscription.example', commands[0][1])
        self.assertIn(b'DNS:good-b.subscription.example', commands[1][1])
        for extension, _, group in commands:
            self.assertEqual(extension.parent, root)
            self.assertEqual(len(group), 5)
            for args in group:
                self.assertEqual(PurePosixPath(args[args.index('-out') + 1]).parent, root)
                self.assertNotIn('-noverify', args)
        files = {}; commands_seen = []
        def exclusive(path, raw, mode):
            self.assertEqual(mode, 0o600); self.assertNotIn(str(path), files); files[str(path)] = raw
        def command(args):
            self.assertEqual(args[0], '/usr/bin/openssl'); commands_seen.append(args)
            target = args[args.index('-out') + 1]
            self.assertIn(target, files); files[target] = CA.encode()
        n = type('SyntheticNative', (), dict(exclusive=staticmethod(exclusive), command=staticmethod(command),
            canonical=staticmethod(lambda value: json.dumps(value).encode()),
            stable_read=staticmethod(lambda path, *args: (files[str(path)], None))))
        with mock.patch.object(Path, 'mkdir'), mock.patch.object(Path, 'chmod'), mock.patch.object(F.os, 'chown', create=True) as ownership:
            F.initialize(PurePosixPath('/tmp/chengwang-subscription-ui-' + FIXTURE), FIXTURE, n)
        self.assertEqual(len(commands_seen), 10)
        self.assertTrue(ownership.call_count >= 16)
        browser = json.loads(files['/tmp/chengwang-subscription-ui-' + FIXTURE + '/browser-input.private.json'])
        self.assertEqual(browser['scenario'], 'remote_fetch')

    def test_remote_policy_environment_is_isolated_from_both_old_scenarios(self):
        root, bundle = PurePosixPath('/tmp/root'), PurePosixPath('/tmp/bundle')
        for scenario in ('create_receipt', 'local_admission'):
            self.assertNotIn('CHENGWANG_SUBSCRIPTION_POLICY_FILE', R.child_environment(root, bundle, scenario))
        env = R.child_environment(root, bundle, 'remote_fetch')
        self.assertEqual(env['CHENGWANG_SUBSCRIPTION_POLICY_FILE'], '/tmp/root/policy.remote.private.json')
        self.assertEqual(env['CHENGWANG_ALLOW_PUBLISH'], 'false')
        self.assertEqual(env['CHENGWANG_OPERATION_WRITES_ENABLED'], 'false')

    def test_old_fourteen_file_contract_is_not_broadened(self):
        self.assertEqual(len(R.PUBLIC), 14)
        self.assertEqual(len(R.REMOTE_PUBLIC), 21)
        self.assertEqual(R.REMOTE_PUBLIC - R.PUBLIC, set(F.WIRE_FILES) | {public for _, public in F.CERT_FILES})
        self.assertNotIn('chengwang/deploy/subscription-readback/wire_fixture.py', R.SOURCE_FILES)
        self.assertIn('chengwang/deploy/subscription-readback/wire_fixture.py', R.REMOTE_SOURCE_FILES)

    def test_wire_root_cannot_select_other_devices_paths_or_fixtures(self):
        self.assertEqual(str(F.wire_root(FIXTURE)).replace('\\', '/'), '/tmp/chengwang-subscription-private-' + FIXTURE)
        for value in ('', 'a' * 31, 'A' * 32, '../' + FIXTURE, '/tmp/' + FIXTURE):
            with self.assertRaises(ValueError): F.wire_root(value)
        with mock.patch.object(Path, 'exists', return_value=True), mock.patch.object(Path, 'is_symlink', return_value=True), \
             mock.patch.object(shutil, 'rmtree', side_effect=AssertionError('unsafe cleanup forbidden')) as remove:
            with self.assertRaises(ValueError): F.cleanup(FIXTURE)
            remove.assert_not_called()

    def test_ipv4_projection_comes_from_exact_observed_loopback_addresses(self):
        observed = '1: lo    inet 127.0.0.1/8 scope host lo\n1: lo    inet 8.8.4.4/32 scope global lo\n'
        self.assertEqual(F.ipv4_addresses(observed), ['127.0.0.1/8', '8.8.4.4/32'])
        for raw in (observed.replace('lo    inet 8', 'eth0    inet 8'), observed.replace('8.8.4.4/32', '8.8.8.8/32'), observed.splitlines()[0], ''):
            with self.assertRaises(ValueError): F.ipv4_addresses(raw)

    def test_wire_accepts_only_good_b_three_connections_twelve_normal_events(self):
        ready, events, stopped = wire_fixture()
        F.validate_wire(ready, wire_bytes(events), stopped, 123)
        for change in ('reference', 'service', 'status', 'reason', 'ordinal'):
            altered = copy.deepcopy(events)
            altered[10][change] = {'reference': 'good-a', 'service': 'dot', 'status': 302, 'reason': 'partial', 'ordinal': 0}[change]
            with self.subTest(change=change), self.assertRaises(ValueError): F.validate_wire(ready, wire_bytes(altered), stopped, 123)

    def test_wire_rejects_forced_stop_unclosed_workers_wrong_pid_and_extra_events(self):
        ready, events, stopped = wire_fixture()
        for key, value in [('normalStop', False), ('termination', 'deadline'), ('closed', 2), ('workerThreadsAlive', 1), ('listenersClosed', False)]:
            changed = dict(stopped, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError): F.validate_wire(ready, wire_bytes(events), changed, 123)
        with self.assertRaises(ValueError): F.validate_wire(ready, wire_bytes(events), stopped, 124)
        with self.assertRaises(ValueError): F.validate_wire(ready, wire_bytes(events + events[:1]), stopped, 123)

    def test_private_projection_only_exports_approved_safe_views(self):
        value = F.project(private_fixture(), COMMIT, FIXTURE)
        self.assertEqual(value['sourceCommit'], COMMIT)
        self.assertEqual((value['localAuditCount'], value['commandCount'], value['approvalCount']), (3, 4, 1))
        self.assertNotIn('PRIVATE-CANARY', repr(value))
        self.assertEqual(value['approvals'][0]['referenceId'], 'good-b')
        self.assertTrue(all(n['state'] == 'unknown' for n in value['candidates'][0]['nodes']))

    def test_private_projection_rejects_wrong_approval_revision_or_automatic_admission(self):
        for target in ('reference', 'revision', 'candidate', 'audit'):
            value = private_fixture()
            if target == 'reference': value['approvals'][0]['referenceId'] = 'good-a'
            elif target == 'revision': value['sources'][0]['revision'] = 2
            elif target == 'candidate': value['candidates'][0]['view']['state'] = 'quarantined'
            else: value['audit'].append({})
            with self.subTest(target=target), self.assertRaises(ValueError): F.project(value, COMMIT, FIXTURE)

    def test_stage_projection_has_only_fixed_safe_checkpoint_values(self):
        raw = b'SUBSCRIPTION_UI_STAGE=APPROVE\nSUBSCRIPTION_UI_STAGE=HANDOFF\nSUBSCRIPTION_UI_STAGE=FETCH\n'
        self.assertEqual(F.checkpoints(raw), ['APPROVE', 'HANDOFF', 'FETCH'])
        self.assertEqual(F.checkpoints(b'SUBSCRIPTION_UI_STAGE=PRIVATE-CANARY\n'), [])

    def test_runner_remote_branch_keeps_real_wire_and_normal_exit_guards(self):
        text = Path(R.__file__).read_text(); tree = ast.parse(text)
        self.assertIn("wire.send_signal(signal.SIGTERM); need(wire.wait(timeout=15) == 0)", text)
        self.assertIn("wireExitCode=0", text)
        self.assertIn("remote_fetch().validate_wire(wire_ready, wire_raw, wire_stopped, wire.pid)", text)
        self.assertIn("net.ipv4.ip_unprivileged_port_start=0", text)
        self.assertTrue(any(isinstance(node, ast.FunctionDef) and node.name == 'inner' for node in tree.body))


if __name__ == '__main__': unittest.main()
