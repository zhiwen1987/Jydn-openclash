"""Pure synthetic contracts only; no socket, browser, Go or server execution."""
import ast
import base64
import copy
import importlib.util
import pathlib
import types
import unittest
from unittest import mock

BASE = pathlib.Path(__file__).resolve().parent


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, BASE / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


R = load('run_subscription_ui.py', 'subscription_ui_runner_contract_subject')
L = load('ui_chrome_launcher.py', 'subscription_ui_launcher_contract_subject')
COMMIT = 'a' * 40
FIXTURE = 'b' * 32


def build_fixture():
    server = b'\x7fELFsynthetic-not-an-executable'
    files = [dict(path=path, bytes=3, sha256=R.sha(b'xxx')) for path in
             ('.vite/manifest.json', 'assets/entry.js', 'index.html', 'trust.html')]
    return dict(schema='chengwang.subscription-ui-build/v1', sourceCommit=COMMIT,
        goVersion='go1.23.12', nodeVersion='v22.23.3', moduleMode='vendor', goDependencyDownloads=False,
        server=dict(name='server', bytes=len(server), sha256=R.sha(server)), distFiles=files,
        production=False, authorization='BLOCKED'), server, files


def private_fixture():
    source = dict(id='src_' + 'c' * 32, scope=dict(R.SCOPE), label='browser-ui-source', revision=1,
                  updatedAt='2026-10-24T00:00:00Z')
    command = dict(id='cmd_' + 'd' * 32, scope=dict(R.SCOPE), actorId='act_' + 'e' * 60,
        kind='create', expectedRevision=0, preparedAuditHash='f' * 64, resultAuditHash='1' * 64,
        acknowledged=True, fingerprint='PRIVATE FINGERPRINT', result=dict(sourceId=source['id'], revision=1,
        state='committed', stateMayHaveChanged=False, localAuditHash='2' * 64, completedAt=source['updatedAt']))
    return dict(schema='chengwang.subscription-store/v1', identityKey='PRIVATE IDENTITY', sources=[source],
        candidates=[], audit=[{}], commands=[dict(record=command, ownerId='PRIVATE OWNER',
        coreKey='PRIVATE CORE', keyDigest='PRIVATE DIGEST', seal='PRIVATE SEAL')])


class TestSubscriptionUIRunnerContracts(unittest.TestCase):
    def test_build_exact_valid_contract(self):
        R.validate_build(*((lambda x: (x[0], COMMIT, x[1], x[2]))(build_fixture())))

    def test_build_rejects_wrong_commit(self):
        b, server, files = build_fixture()
        with self.assertRaises(ValueError): R.validate_build(b, '0' * 40, server, files)

    def test_build_rejects_changed_server(self):
        b, server, files = build_fixture()
        with self.assertRaises(ValueError): R.validate_build(b, COMMIT, server + b'x', files)

    def test_build_requires_hidden_manifest(self):
        b, server, files = build_fixture(); files[0]['path'] = 'assets/other.css'; files.sort(key=lambda v: v['path'])
        b['distFiles'] = files
        with self.assertRaises(ValueError): R.validate_build(b, COMMIT, server, files)

    def test_build_rejects_extra_claims(self):
        b, server, files = build_fixture(); b['productionVerified'] = True
        with self.assertRaises(ValueError): R.validate_build(b, COMMIT, server, files)

    def test_relative_path_rejects_traversal(self):
        for value in ('../secret', '/absolute', 'a/../b', 'a\\b', 'a//b'):
            with self.assertRaises(ValueError): R.safe_relative(value)

    def test_environment_has_no_policy_or_publish(self):
        env = R.child_environment(pathlib.PurePosixPath('/tmp/lab'), pathlib.PurePosixPath('/tmp/tools'))
        self.assertNotIn('CHENGWANG_SUBSCRIPTION_POLICY_FILE', env)
        self.assertNotIn('HOME', env); self.assertNotIn('CHENGWANG_MIHOMO_URL', env)
        self.assertEqual(env['CHENGWANG_ALLOW_PUBLISH'], 'false')
        self.assertEqual(env['CHENGWANG_WEB_DIR'], '/tmp/tools/source/chengwang/web/dist')
        self.assertEqual(env['CHENGWANG_ADDR'], '127.0.0.1:17891')

    def test_identity_contains_hash_not_token(self):
        token = 'a' * 64; value = R.identity(token)
        self.assertNotIn(token, repr(value)); self.assertEqual(value['identities'][0]['tokenHash'], R.sha(token.encode()))
        self.assertEqual(value['identities'][0]['principal']['roles'], ['operator'])
        self.assertIn(token.encode(), R.secret_variants(token))
        self.assertIn(R.sha(token.encode()).encode(), R.secret_variants(token))
        n = types.SimpleNamespace(decode=__import__('json').loads)
        secret_body = base64.b64encode(('prefix' + token + 'suffix').encode()).decode()
        with self.assertRaises(ValueError): R.public_fence(
            __import__('json').dumps(dict(kind='CREATE', responseBase64=secret_body)).encode(), R.secret_variants(token), captures=True, N=n)

    def test_private_projection_removes_secrets(self):
        value = R.private_projection(private_fixture(), COMMIT, FIXTURE)
        self.assertNotIn('PRIVATE', repr(value)); self.assertEqual(value['commandCount'], 1)
        self.assertEqual(value['approvalCount'], 0); self.assertEqual(value['candidates'], [])

    def test_private_projection_rejects_fetch(self):
        value = private_fixture(); value['commands'][0]['record']['kind'] = 'fetch'
        with self.assertRaises(ValueError): R.private_projection(value, COMMIT, FIXTURE)

    def test_private_projection_rejects_candidate(self):
        value = private_fixture(); value['candidates'] = [{'raw': 'PRIVATE'}]
        with self.assertRaises(ValueError): R.private_projection(value, COMMIT, FIXTURE)

    def test_private_projection_rejects_extra_source_field(self):
        value = private_fixture(); value['sources'][0]['privateURL'] = 'PRIVATE'
        with self.assertRaises(ValueError): R.private_projection(value, COMMIT, FIXTURE)

    def test_launcher_accepts_only_exact_fixture(self):
        bundle = pathlib.PurePosixPath('/tmp/chengwang-subscription-ui-tools-' + FIXTURE)
        config = dict(schema='chengwang.subscription-ui-launch/v1', engine='playwright', fixtureId=FIXTURE,
            root='/tmp/chengwang-subscription-ui-' + FIXTURE, chrome=str(bundle / 'chrome/chrome'), chromeSHA256='a' * 64)
        self.assertEqual(L.validate_config(config, bundle)[0], FIXTURE)
        config['root'] += '0'
        with self.assertRaises(ValueError): L.validate_config(config, bundle)

    def test_launcher_rejects_tls_bypass(self):
        profile = pathlib.Path('/tmp/profile')
        with self.assertRaises(ValueError): L.validate_arguments([
            '--user-data-dir=' + str(profile), '--no-sandbox', '--ignore-certificate-errors'], profile)

    def test_launcher_exit_keeps_observed_failure(self):
        value = L.exit_record('chrome-cdp', FIXTURE, 42, 99, -15, True)
        self.assertEqual(value['schema'], 'chengwang.subscription-ui-chrome-exit/v1')
        self.assertEqual(value['exitCode'], -15); self.assertTrue(value['forced'])
        self.assertEqual(R.driver_checkpoints(b'raw-private-data\nSUBSCRIPTION_UI_STAGE=CONNECT\n'
            b'SUBSCRIPTION_UI_STAGE=PRIVATE\n'), ['CONNECT'])

    def test_ast_all_modules_import_without_runtime(self):
        for filename in ('run_subscription_ui.py', 'ui_chrome_launcher.py', 'test_run_subscription_ui.py'):
            self.assertIsInstance(ast.parse((BASE / filename).read_text(encoding='utf-8')), ast.Module)


if __name__ == '__main__': unittest.main(verbosity=2)
