"""Synthetic B09 fixture/export contracts, never a real browser or API run."""
import ast
import base64
import copy
import importlib.util
import json
from pathlib import Path, PurePosixPath
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parent
FIXTURE = 'a' * 32
COMMIT = 'b' * 40
CA = '-----BEGIN CERTIFICATE-----\nSYNTHETIC-NOT-A-CERTIFICATE\n-----END CERTIFICATE-----\n'


def load(name):
    spec = importlib.util.spec_from_file_location('handoff_fixture_test_' + name, BASE / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


F = load('handoff_negative_fixture')
R = load('run_subscription_ui')


def opaque(stem, value): return stem + '_' + format(value, '032x')


def private_fixture():
    stamp = '2026-10-24T00:00:00Z'
    a = dict(id=opaque('src', 1), scope=dict(F.SCOPE), label=F.LABELS['a'], revision=2,
             updatedAt=stamp, latestCandidateId=opaque('cand', 3))
    b = dict(id=opaque('src', 2), scope=dict(F.SCOPE), label=F.LABELS['b'], revision=1, updatedAt=stamp)
    view = dict(id=a['latestCandidateId'], sourceId=a['id'], scope=dict(F.SCOPE), digest='hmac-sha256:' + '3' * 64,
        format='mihomo-provider-yaml', state='quarantined', baseRevision=2, nodeCount=2, duplicateCount=0,
        nodes=[dict(id=opaque('node', i), label='节点-' + opaque('node', i)[-8:], protocol=protocol,
                    credentialConfigured=True, state='unknown') for i, protocol in enumerate(('http', 'socks5'), 1)],
        createdAt=stamp)
    commands = []; approvals = []
    pattern = [('create', a, 'committed', ''), ('create', b, 'committed', ''),
        ('approve', a, 'approved', ''), ('approve', a, 'approved', ''), ('approve', b, 'approved', ''),
        *[('fetch', a, 'failed', F.CODE_APPROVAL) for _ in range(4)],
        ('fetch', a, 'committed', ''), ('fetch', a, 'failed', F.CODE_CONFLICT)]
    for i, (kind, source, state, code) in enumerate(pattern, 1):
        result = dict(sourceId=source['id'], revision=2 if kind == 'fetch' and state == 'committed' else 1,
                      state=state, stateMayHaveChanged=False, completedAt=stamp)
        command = dict(id=opaque('cmd', i), scope=dict(F.SCOPE), actorId='act_' + ('2' if kind == 'approve' else '1') * 60,
            kind=kind, expectedRevision=0 if kind == 'create' else 1, preparedAuditHash='4' * 64,
            resultAuditHash='5' * 64, acknowledged=True, result=result,
            fingerprint='PRIVATE-CANARY-NOT-PUBLIC', preparedAt=stamp)
        if kind != 'create': command['sourceId'] = source['id']
        if code: result['code'] = code
        elif kind == 'approve':
            reference = 'good-b' if i == 4 else 'good-a'
            result.update(referenceId=reference, policyRevision=1, policyDigest='hmac-sha256:' + str(i) * 64,
                          approvalId=command['id'])
            approvals.append(dict(commandId=command['id'], scope=dict(F.SCOPE), sourceId=source['id'],
                referenceId=reference, policyRevision=1, policyDigest=result['policyDigest'], sourceRevision=1,
                approvedAt=stamp, seal='PRIVATE-CANARY-NOT-PUBLIC'))
        else:
            result['localAuditHash'] = '6' * 64
            if kind == 'fetch': result.update(candidateId=view['id'], digest=view['digest'])
        commands.append(dict(record=command, ownerId='PRIVATE-CANARY-NOT-PUBLIC', coreKey='PRIVATE-CANARY-NOT-PUBLIC',
                             keyDigest='PRIVATE-CANARY-NOT-PUBLIC', seal='PRIVATE-CANARY-NOT-PUBLIC'))
    return dict(schema='chengwang.subscription-store/v1', identityKey='PRIVATE-CANARY-NOT-PUBLIC',
        sources=[a, b], candidates=[dict(view=view, raw='PRIVATE-CANARY-NOT-PUBLIC', privateNodes=['PRIVATE-CANARY-NOT-PUBLIC'])],
        commands=commands, approvals=approvals, audit=[{}, {}, {}])


def sampler_rows():
    rows = []
    for ordinal in (1, 2):
        approve = ordinal == 1
        response = dict(boundary='LOCAL_SUBSCRIPTION_ADMISSION_ONLY', authorization='BLOCKED',
            deviceActionsExecuted=False, stateMayHaveChanged=False,
            code='subscription_forbidden' if approve else F.CODE_CONFLICT)
        body = json.dumps(response, separators=(',', ':')).encode()
        leaf = b'0-SYNTHETIC-PUBLIC-CERTIFICATE-NOT-TLS-PROOF'
        request = dict(sourceId=opaque('src',1), expectedRevision=1, policyRevision=1,
                       idempotencyKey='synthetic-handoff-sampler-' + str(ordinal))
        request.update(dict(referenceId='good-b') if approve else dict(approvalId=opaque('cmd',4)))
        rows.append(dict(schema='chengwang.handoff-api-sample/v1',ordinal=ordinal,
            caseKey='api_approve_denied' if approve else 'api_stale_fetch', method='POST',
            path='/api/v1/subscriptions/sources/' + opaque('src',1) + ('/approvals' if approve else '/fetches'),
            actorRole='operator', requestPublic=request, status=403 if approve else 409,
            commandIdHeader=None if approve else opaque('cmd',11),denialAuditHeader='recorded' if approve else None,
            responseBase64=base64.b64encode(body).decode(),responseBytes=len(body),responseSHA256=F.remote().sha(body),
            tls=dict(authorized=True,leafDERBase64=base64.b64encode(leaf).decode(),leafSHA256=F.remote().sha(leaf),protocol='TLSv1.3'),
            startedWallTimeUs=1000 * ordinal,headerWallTimeUs=1000 * ordinal + 1,endWallTimeUs=1000 * ordinal + 2,
            terminal=dict(event='END',complete=True,aborted=False)))
    return rows


def sampler_bytes(rows): return b''.join(json.dumps(row,separators=(',', ':')).encode() + b'\n' for row in rows)


class HandoffNegativeFixtureContracts(unittest.TestCase):
    def setUp(self):
        for name in ('Popen', 'run', 'call', 'check_call', 'check_output'):
            patch = mock.patch.object(R.subprocess, name, side_effect=AssertionError('real subprocess forbidden'))
            patch.start(); self.addCleanup(patch.stop)

    def test_input_is_closed_two_labels_two_roles_and_twenty_two_canaries(self):
        value, _, _, _ = F.generate(CA, CA)
        self.assertEqual(set(value), {'schema', 'scenario', 'tokens', 'labels', 'canaries'})
        self.assertEqual(value['labels'], dict(a='browser-handoff-source-a', b='browser-handoff-source-b'))
        self.assertEqual(set(value['tokens']), {'operator', 'approver'})
        self.assertEqual(len(set(value['canaries'])), 22)
        self.assertEqual(value['scenario'], 'remote_handoff_negative')
        contract = json.loads((BASE.parents[1] / 'tools/subscription-ui-browser/handoff-negative-contract.json').read_bytes())
        self.assertEqual(set(contract['privateInputKeys']), F.INPUT_KEYS)
        self.assertEqual((contract['inputSchema'],contract['readbackSchema'],contract['labels']),
                         (F.INPUT_SCHEMA,F.PRIVATE_SCHEMA,F.LABELS))
        self.assertEqual(set(contract['publicFiles']), R.HANDOFF_PUBLIC)

    def test_old_schema_extra_paths_and_bad_canaries_are_rejected(self):
        value, _, _, _ = F.generate(CA, CA)
        variants = []
        for key in ('wireRoot', 'file', 'url'):
            bad = copy.deepcopy(value); bad[key] = 'PRIVATE-CANARY-NOT-PUBLIC'; variants.append(bad)
        for change in (dict(schema='chengwang.remote-fetch-ui-input/v1'), dict(labels={'a':'wrong','b':'wrong'}),
                       dict(canaries=value['canaries'][:-1]), dict(canaries=value['canaries'] + ['extra']),
                       dict(tokens={'operator': '1' * 64, 'approver': '1' * 64})):
            bad = copy.deepcopy(value); bad.update(change); variants.append(bad)
        for bad in variants:
            with self.assertRaises(ValueError): F.forbidden(bad)

    def test_neutral_generation_preserves_private_policy_and_wire_protocol(self):
        value, identities, policy, wire = F.generate(CA, CA)
        self.assertEqual([(v['referenceId'], v['revision']) for v in policy['sources']], [('good-a',1),('good-b',1)])
        self.assertEqual(policy['scope'], F.SCOPE)
        self.assertEqual(policy['resolver']['upstream'], '127.0.0.1:1853')
        self.assertEqual(len(wire['sourceTokensByRef']), 8)
        self.assertEqual(len(identities['identities']), 2)
        self.assertNotIn('expiresAt', policy)
        self.assertTrue(all(token not in json.dumps(identities) for token in value['tokens'].values()))

    def test_private_upstream_credentials_and_all_encodings_are_fenced(self):
        value, _, _, wire = F.generate(CA, CA)
        body = base64.b64decode(wire['goodBodyBase64'], validate=True)
        self.assertEqual(body.count(b'username'), 2)
        secrets = F.forbidden(value)
        for secret in [*value['tokens'].values(), *value['canaries']]:
            raw = secret.encode('ascii')
            for encoded in (raw, base64.b64encode(raw), raw.hex().encode(), F.remote().sha(raw).encode()):
                self.assertIn(encoded, secrets)
                with self.assertRaises(ValueError): R.public_fence(b'prefix' + encoded + b'suffix', secrets)

    def test_initialize_uses_only_neutral_certificates_and_private_fixed_paths(self):
        root = PurePosixPath('/tmp/chengwang-subscription-ui-' + FIXTURE)
        native = types.SimpleNamespace(exclusive=mock.Mock(), command=mock.Mock(),
            stable_read=mock.Mock(return_value=(CA.encode(), object())), canonical=lambda v: json.dumps(v).encode())
        with mock.patch.object(Path, 'mkdir'), mock.patch.object(Path, 'chmod'), mock.patch.object(F.os, 'chown', create=True):
            forbidden = F.initialize(root, FIXTURE, native)
        self.assertTrue(forbidden)
        self.assertEqual(native.command.call_count, 10)
        self.assertTrue(all(call.args[0][0] == '/usr/bin/openssl' for call in native.command.call_args_list))
        json_writes = [call for call in native.exclusive.call_args_list if str(call.args[0]).endswith('.json')]
        self.assertEqual(len(json_writes), 4)
        self.assertTrue(all(call.args[2] == 0o600 for call in json_writes))

    def test_projection_exports_eleven_commands_three_approvals_and_safe_views(self):
        value = F.project(private_fixture(), COMMIT, FIXTURE)
        self.assertEqual(set(value), {'schema','sourceCommit','fixtureId','scope','sources','candidates',
            'localAuditCount','commandCount','approvalCount','commands','approvals'})
        self.assertEqual((value['commandCount'],value['approvalCount'],value['localAuditCount']), (11,3,3))
        self.assertEqual([s['revision'] for s in value['sources']], [2,1])
        self.assertEqual(value['candidates'][0]['state'], 'quarantined')
        self.assertNotIn('PRIVATE-CANARY', json.dumps(value))
        self.assertEqual([c['kind'] for c in value['commands']].count('fetch'), 6)

    def test_failed_receipt_revision_is_not_rewritten_to_latest_inventory(self):
        value = F.project(private_fixture(), COMMIT, FIXTURE)
        failed = [c for c in value['commands'] if c['result']['state'] == 'failed']
        self.assertEqual(len(failed), 5)
        self.assertTrue(all(c['expectedRevision'] == c['result']['revision'] == 1 for c in failed))
        self.assertEqual(value['sources'][0]['revision'], 2)
        self.assertTrue(all('localAuditHash' not in c['result'] and c['acknowledged'] for c in failed))
        bad = private_fixture(); bad['commands'][-1]['record']['result']['revision'] = 2
        with self.assertRaises(ValueError): F.project(bad, COMMIT, FIXTURE)

    def test_projection_rejects_wrong_counts_admission_state_and_unsafe_nodes(self):
        for field in ('commands','approvals','audit','sources','candidates'):
            bad = private_fixture(); bad[field].pop()
            with self.assertRaises(ValueError): F.project(bad, COMMIT, FIXTURE)
        for patch in (dict(state='admitted_local'),dict(baseRevision=1),dict(nodeCount=3)):
            bad = private_fixture(); bad['candidates'][0]['view'].update(patch)
            with self.assertRaises(ValueError): F.project(bad, COMMIT, FIXTURE)
        bad = private_fixture(); bad['candidates'][0]['view']['nodes'][0]['state'] = 'healthy'
        with self.assertRaises(ValueError): F.project(bad, COMMIT, FIXTURE)

    def test_projection_binds_each_approval_to_its_source_command_and_reference(self):
        for field, replacement in [('sourceId', opaque('src',2)),('referenceId','good-b'),
                                   ('sourceRevision',2),('commandId',opaque('cmd',5))]:
            bad = private_fixture(); bad['approvals'][0][field] = replacement
            with self.assertRaises(ValueError): F.project(bad, COMMIT, FIXTURE)
        bad = private_fixture(); bad['approvals'][0]['policyDigest'] = 'hmac-sha256:' + 'f' * 64
        with self.assertRaises(ValueError): F.project(bad, COMMIT, FIXTURE)

    def test_projection_rejects_wrong_command_results_codes_and_extra_public_fields(self):
        for index, field, replacement in [(5,'code',F.CODE_CONFLICT),(10,'code',F.CODE_APPROVAL),
                (5,'state','committed'),(9,'revision',1),(5,'stateMayHaveChanged',True)]:
            bad = private_fixture(); bad['commands'][index]['record']['result'][field] = replacement
            with self.assertRaises(ValueError): F.project(bad, COMMIT, FIXTURE)
        bad = private_fixture(); bad['commands'][5]['record']['result']['rawError'] = 'PRIVATE-CANARY'
        with self.assertRaises(ValueError): F.project(bad, COMMIT, FIXTURE)
        bad = private_fixture(); bad['commands'][0]['record']['kind'] = 'decide'
        with self.assertRaises(ValueError): F.project(bad, COMMIT, FIXTURE)

    def test_old_public_sets_and_old_scenario_acceptance_are_not_broadened(self):
        self.assertEqual((len(R.PUBLIC),len(R.REMOTE_PUBLIC),len(R.HANDOFF_PUBLIC)), (14,21,22))
        self.assertEqual(R.HANDOFF_PUBLIC - R.REMOTE_PUBLIC, {'api-sampler.jsonl'})
        self.assertNotIn('api-sampler.jsonl', R.PUBLIC | R.REMOTE_PUBLIC)
        self.assertNotIn('chengwang/deploy/subscription-ui-browser/handoff_negative_fixture.py', R.SOURCE_FILES)
        self.assertIn('chengwang/deploy/subscription-ui-browser/handoff_negative_fixture.py', R.HANDOFF_SOURCE_FILES)
        raw = json.dumps(dict(kind='APPROVE',responseBase64='e30=')).encode()
        with self.assertRaises(ValueError): R.public_fence(raw, [], captures=True, N=types.SimpleNamespace(decode=json.loads))
        self.assertEqual(R.public_fence(raw,[],captures=True,N=types.SimpleNamespace(decode=json.loads),scenario=F.SCENARIO), raw)

    def test_new_runner_branch_reuses_real_wire_four_process_profiles_and_normal_close(self):
        text = Path(R.__file__).read_text(encoding='utf-8'); tree = ast.parse(text)
        self.assertIn('handoff-negative-cli.mjs', text)
        self.assertIn('remote_fetch().validate_wire(wire_ready, wire_raw, wire_stopped, wire.pid)', text)
        self.assertIn('wire.send_signal(signal.SIGTERM); need(wire.wait(timeout=15) == 0)', text)
        self.assertIn("HANDOFF_PUBLIC if options.scenario == 'remote_handoff_negative'", text)
        self.assertIn("'api-sampler.private.jsonl', 'api-sampler.jsonl'", text)
        self.assertTrue(any(isinstance(node,ast.FunctionDef) and node.name == 'inner' for node in tree.body))

    def test_policy_environment_does_not_escape_the_two_remote_scenarios(self):
        root, bundle = PurePosixPath('/tmp/root'), PurePosixPath('/tmp/bundle')
        for scenario in ('create_receipt','local_admission'):
            self.assertNotIn('CHENGWANG_SUBSCRIPTION_POLICY_FILE', R.child_environment(root,bundle,scenario))
        for scenario in ('remote_fetch',F.SCENARIO):
            self.assertEqual(R.child_environment(root,bundle,scenario)['CHENGWANG_SUBSCRIPTION_POLICY_FILE'], '/tmp/root/policy.remote.private.json')
        self.assertEqual(R.child_environment(root,bundle,F.SCENARIO)['CHENGWANG_ALLOW_PUBLISH'], 'false')

    def test_checkpoints_and_unsupported_navigation_never_fabricate_acceptance(self):
        value = F.checkpoints(b'SUBSCRIPTION_UI_STAGE=CREATE\nSUBSCRIPTION_UI_STAGE=API_SAMPLER\n'
                              b'SUBSCRIPTION_UI_STAGE=PRIVATE\nPRIVATE-CANARY\n')
        self.assertEqual(value, ['CREATE','API_SAMPLER'])
        reader = R.navigation_diagnostics()
        native = types.SimpleNamespace(stable_read=mock.Mock(side_effect=FileNotFoundError()),decode=json.loads)
        self.assertEqual(reader.read(PurePosixPath('/tmp/chengwang-subscription-ui-'+FIXTURE),FIXTURE,
            'chrome-cdp',F.SCENARIO,COMMIT,native), dict(available=False))

    def test_sampler_decoded_body_canary_and_canonical_base64_are_enforced(self):
        native = types.SimpleNamespace(decode=json.loads)
        raw = sampler_bytes(sampler_rows())
        self.assertEqual(F.sampler_fence(raw, [], native), raw)
        self.assertNotIn(b'subscription_forbidden', raw)
        with self.assertRaises(ValueError): F.sampler_fence(raw,[b'subscription_forbidden'],native)
        for field in ('responseBase64',):
            bad = sampler_rows(); bad[0][field] += '\n'
            with self.assertRaises(ValueError): F.sampler_fence(sampler_bytes(bad),[],native)
        secret = b'PRIVATE-CANARY-LEAF-NOT-PUBLIC'
        bad = sampler_rows(); bad[0]['tls'].update(leafDERBase64=base64.b64encode(secret).decode(),leafSHA256=F.remote().sha(secret))
        self.assertNotIn(secret,sampler_bytes(bad))
        with self.assertRaises(ValueError): F.sampler_fence(sampler_bytes(bad),[secret],native)
        for patch in (dict(responseBytes=True),dict(responseBytes=65537),dict(responseSHA256='0'*64)):
            bad = sampler_rows(); bad[0].update(patch)
            with self.assertRaises(ValueError): F.sampler_fence(sampler_bytes(bad),[],native)

    def test_sampler_exact_closed_headers_status_and_rows_are_enforced(self):
        native = types.SimpleNamespace(decode=json.loads)
        for patch in (dict(commandIdHeader=opaque('cmd',1)),dict(denialAuditHeader='unavailable'),dict(status=200),
                      dict(actorRole='approver'),dict(Authorization='PRIVATE'),dict(ordinal=True),dict(headerWallTimeUs=999)):
            bad = sampler_rows(); bad[0].update(patch)
            with self.assertRaises(ValueError): F.sampler_fence(sampler_bytes(bad),[],native)
        for patch in (dict(commandIdHeader=None),dict(denialAuditHeader='recorded'),dict(status=403)):
            bad = sampler_rows(); bad[1].update(patch)
            with self.assertRaises(ValueError): F.sampler_fence(sampler_bytes(bad),[],native)
        bad = sampler_rows(); bad[1]['requestPublic']['sourceId'] = opaque('src',2)
        with self.assertRaises(ValueError): F.sampler_fence(sampler_bytes(bad),[],native)
        bad = sampler_rows(); bad[0]['tls']['authorized'] = False
        with self.assertRaises(ValueError): F.sampler_fence(sampler_bytes(bad),[],native)
        prefix = sampler_bytes(sampler_rows()[:1])
        self.assertEqual(F.sampler_fence(prefix,[],native,partial=True),prefix)
        with self.assertRaises(ValueError): F.sampler_fence(prefix,[],native)
        for raw in (sampler_bytes(sampler_rows()*2),sampler_bytes(list(reversed(sampler_rows()))),b'x'*262145):
            with self.assertRaises(ValueError): F.sampler_fence(raw,[],native)


if __name__ == '__main__': unittest.main(verbosity=2)
