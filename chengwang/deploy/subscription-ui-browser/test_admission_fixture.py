"""Pure fixture/projection/dispatch tests; never executes the product runtime."""
import ast
import base64
import copy
import importlib.util
import json
import pathlib
import types
import unittest

BASE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('admission_test_' + name, BASE / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


A = load('admission_fixture'); R = load('run_subscription_ui')
ROOT = pathlib.PurePosixPath('/tmp/chengwang-subscription-ui-' + 'a' * 32)


def private_fixture():
    scope = dict(A.SCOPE); stamp = '2026-10-24T00:00:00Z'
    a, b = 'src_' + 'a' * 32, 'src_' + 'b' * 32
    sources = [dict(id=a, scope=scope, label=A.LABELS['a'], revision=8, updatedAt=stamp,
                    acceptedCandidateId='cand_' + '1' * 32, latestCandidateId='cand_' + '3' * 32),
               dict(id=b, scope=scope, label=A.LABELS['b'], revision=2, updatedAt=stamp, latestCandidateId='cand_' + '4' * 32)]
    candidates = []
    for index, (source, state, revision) in enumerate(((a, 'admitted_local', 2), (a, 'admitted_local', 4),
            (a, 'rejected', 6), (b, 'quarantined', 2)), 1):
        nodes = [dict(id='node_' + str(index) * 31 + str(offset), label='节点-' + str(index) * 7 + str(offset),
            protocol=protocol, credentialConfigured=True, state='unknown') for offset, protocol in enumerate(('http', 'socks5'))]
        view = dict(id='cand_' + str(index) * 32, sourceId=source, scope=scope, digest='hmac-sha256:' + str(index) * 64,
            format='mihomo-provider-yaml', state=state, baseRevision=revision, nodeCount=2, duplicateCount=0,
            nodes=nodes, createdAt=stamp)
        candidates.append(dict(view=view, raw='PRIVATE YAML', privateNodes=[dict(privateName='PRIVATE NAME', canonicalConfig='PRIVATE CONFIG')]))
    commands = []
    for index, kind in enumerate(('create', 'create', 'import', 'import', 'decide', 'import', 'decide', 'import', 'decide', 'rollback')):
        result = dict(sourceId=a, revision=1, state='committed', stateMayHaveChanged=False,
                      localAuditHash='f' * 64, completedAt=stamp)
        record = dict(id='cmd_' + format(index, '032x'), scope=scope, actorId='act_' + 'c' * 60,
            kind=kind, expectedRevision=0, preparedAuditHash='d' * 64, resultAuditHash='e' * 64,
            acknowledged=True, result=result, fingerprint='PRIVATE FINGERPRINT')
        commands.append(dict(record=record, ownerId='PRIVATE OWNER', coreKey='PRIVATE CORE', keyDigest='PRIVATE KEY', seal='PRIVATE SEAL'))
    return dict(schema='chengwang.subscription-store/v1', sources=sources, candidates=candidates,
                commands=commands, audit=[{}] * 10, identityKey='PRIVATE IDENTITY')


class AdmissionFixtureContracts(unittest.TestCase):
    def test_01_private_input_exact_and_three_files(self):
        value, identities, payloads = A.generate(ROOT)
        self.assertEqual(set(value), {'schema', 'scenario', 'tokens', 'labels', 'files', 'canaries'})
        self.assertEqual([row['key'] for row in value['files']], ['first', 'second', 'third'])
        self.assertEqual(len(payloads), 3)
        self.assertTrue(all(set(row) == {'key', 'path', 'bytes'} for row in value['files']))

    def test_02_four_roles_have_distinct_hash_only_identities(self):
        value, identities, _ = A.generate(ROOT)
        self.assertEqual(len(set(value['tokens'].values())), 4)
        self.assertEqual([row['principal']['roles'] for row in identities['identities']], [[role] for role in A.ROLES])
        for token in value['tokens'].values(): self.assertNotIn(token, repr(identities))

    def test_03_each_yaml_has_two_distinct_credential_nodes(self):
        value, _, payloads = A.generate(ROOT)
        endpoints = set()
        for raw in payloads.values():
            self.assertTrue(raw.startswith(b'proxies:\n'))
            nodes = [json.loads(line.strip()[2:]) for line in raw.decode().splitlines()[1:]]
            self.assertEqual([node['type'] for node in nodes], ['http', 'socks5'])
            self.assertTrue(all(node['username'] and node['password'] for node in nodes))
            endpoints.update(node['server'] for node in nodes)
        self.assertEqual(len(endpoints), 6)
        self.assertTrue(all(endpoint.startswith('198.51.100.') for endpoint in endpoints))

    def test_04_file_sizes_match_private_actual_bytes(self):
        value, _, payloads = A.generate(ROOT)
        for row in value['files']:
            actual = payloads[pathlib.PurePosixPath(row['path'])]
            self.assertEqual(row['bytes'], len(actual)); self.assertNotIn('sha256', row)

    def test_05_canaries_cover_private_scalars_and_basenames(self):
        value, _, payloads = A.generate(ROOT)
        self.assertEqual(len(value['canaries']), 21)
        self.assertTrue(all(len(item) >= 24 and ' ' not in item and '\n' not in item for item in value['canaries']))
        for path in payloads: self.assertIn(path.name, value['canaries'])

    def test_06_canary_encoder_covers_transforms(self):
        secret = 'private-canary-' + 'a' * 32; variants = A.variants(secret)
        self.assertIn(secret.encode(), variants)
        self.assertIn(base64.b64encode(secret.encode()), variants)
        self.assertIn(A.sha(secret.encode()).encode(), variants)

    def test_07_invalid_fixture_root_rejected(self):
        for root in ('/tmp/other', '/tmp/chengwang-subscription-ui-' + 'x' * 32):
            with self.assertRaises(ValueError): A.generate(pathlib.PurePosixPath(root))

    def test_08_duplicate_role_tokens_rejected(self):
        tokens = {role: 'a' * 64 for role in A.ROLES}
        with self.assertRaises(ValueError): A.identity(tokens)

    def test_09_projection_keeps_safe_views_not_private_fields(self):
        value = A.project(private_fixture(), 'a' * 40, 'b' * 32)
        self.assertNotIn('PRIVATE', repr(value)); self.assertEqual(len(value['candidates']), 4)
        self.assertEqual(value['commandCount'], 10); self.assertEqual(value['approvalCount'], 0)
        self.assertEqual(value['schema'], 'chengwang.admission-ui-private-readback/v1')

    def test_10_projection_rejects_remote_result_fields(self):
        value = private_fixture(); value['commands'][0]['record']['result']['approvalId'] = 'unexpected'
        with self.assertRaises(ValueError): A.project(value, 'a' * 40, 'b' * 32)

    def test_11_projection_rejects_wrong_counts(self):
        value = private_fixture(); value['commands'].pop()
        with self.assertRaises(ValueError): A.project(value, 'a' * 40, 'b' * 32)

    def test_12_projection_retains_real_candidate_result_omissions(self):
        value = private_fixture(); result = value['commands'][2]['record']['result']
        result.update(candidateId='cand_' + '1' * 32, digest='hmac-sha256:' + '1' * 64)
        projected = A.project(value, 'a' * 40, 'b' * 32)['commands']
        self.assertNotIn('candidateId', projected[0]['result'])
        self.assertEqual(projected[2]['result']['candidateId'], result['candidateId'])

    def test_13_default_scenario_remains_exact(self):
        self.assertEqual(R.selected_scenario(types.SimpleNamespace()), 'create_receipt')
        self.assertEqual(R.selected_scenario(types.SimpleNamespace(scenario='local_admission')), 'local_admission')
        with self.assertRaises(ValueError): R.selected_scenario(types.SimpleNamespace(scenario='other'))

    def test_14_new_capture_kinds_do_not_widen_old_gate(self):
        raw = json.dumps(dict(kind='IMPORT', responseBase64=base64.b64encode(b'{}').decode())).encode() + b'\n'
        n = types.SimpleNamespace(decode=json.loads)
        with self.assertRaises(ValueError): R.public_fence(raw, [], captures=True, N=n)
        self.assertEqual(R.public_fence(raw, [], captures=True, N=n, scenario='local_admission'), raw)

    def test_15_admission_capture_decoded_canary_rejected(self):
        secret = 'private-canary-' + 'b' * 32
        body = ('prefix' + secret + 'suffix').encode()
        raw = json.dumps(dict(kind='IMPORT', responseBase64=base64.b64encode(body).decode())).encode()
        with self.assertRaises(ValueError): R.public_fence(raw, A.variants(secret), captures=True,
            N=types.SimpleNamespace(decode=json.loads), scenario='local_admission')

    def test_16_checkpoint_and_ast_are_closed(self):
        self.assertEqual(A.checkpoints(b'SUBSCRIPTION_UI_STAGE=IMPORT\nPRIVATE\nSUBSCRIPTION_UI_STAGE=OTHER\n'), ['IMPORT'])
        for name in ('admission_fixture.py', 'test_admission_fixture.py', 'run_subscription_ui.py'):
            self.assertIsInstance(ast.parse((BASE / name).read_text(encoding='utf-8')), ast.Module)


if __name__ == '__main__': unittest.main(verbosity=2)
