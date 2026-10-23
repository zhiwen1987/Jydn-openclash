"""Pure/temporary-file verifier contracts; no apt, font tools or browser run."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import check_ci_dependencies as C

COMMIT = 'a' * 40
PRIVATE_DIRECTORY = '/tmp/chengwang-ci-apt-abcdefgh'


def fixture():
    blobs = {C.HELPER: b'# synthetic source bytes only, never executed\n',
             C.CONTRACT: (json.dumps(C.FROZEN_CONTRACT, separators=(',', ':')) + '\n').encode()}
    fonts = [dict(path=item['path'], family='Noto Sans CJK SC', style=item['style'],
                  bytes=100, sha256=digest * 64, uid=0, gid=0, mode=0o644, ownerPackage='fonts-noto-cjk')
             for item, digest in zip(C.FONTS, ('b', 'c'))]
    packages = [dict(name=name, status='install ok installed', version=version)
                for name, version in zip(C.PACKAGES, ('2:3.98-1build1', '1:20230817-1'))]
    readback = ''.join(row['name'] + '\t' + row['status'] + '\t' + row['version'] + '\n' for row in reversed(packages))
    for font in fonts:
        readback += font['family'] + '\t' + font['style'] + '\t' + font['path'] + '\n'
        readback += 'fonts-noto-cjk: ' + font['path'] + '\n'
    logs = dict(zip(C.LOG_NAMES, (b'', b'Fetched synthetic dependency fixture\n', readback.encode(),
                                 b'apt 2.8.3 (amd64)\nSupported modules:\n')))
    policy = C.FROZEN_CONTRACT['privateSourcePolicy']
    source = sorted([dict(path=policy['hostSourcePath'], bytes=policy['hostSourceBytes'], sha256=policy['hostSourceSHA256']),
                     dict(path='/etc/apt/apt-mirrors.txt', bytes=policy['hostMirrorBytes'], sha256=policy['hostMirrorSHA256'])], key=lambda r:r['path'])
    source_size = policy['hostSourceBytes'] + 2 * (len('mirror+file:' + PRIVATE_DIRECTORY + '/mirrors.txt') - len(policy['hostMirrorURI']))
    source_size += 2 * (len(PRIVATE_DIRECTORY + '/' + policy['privateSignedBy']) - len(policy['signedBy']))
    value = dict(schema='chengwang.ci-ui-dependencies/v3', scope=C.SCOPE, sourceCommit=COMMIT,
        outcome='PASS', failureStage='NONE', platform=dict(githubActions=True, runnerOS='Linux', system='Linux',
        ubuntu='24.04', architecture='amd64'), commands=[dict(stage=s, argv=C.argv(s, PRIVATE_DIRECTORY), executed=True,
        exitCode=0, timedOut=False, elapsedMilliseconds=20) for s in ('UPDATE', 'INSTALL')],
        logs=[dict(path=name, bytes=len(logs[name]), sha256=C.sha(logs[name]), truncated=False) for name in C.LOG_NAMES],
        sourcesBefore=source, sourcesAfter=copy.deepcopy(source), sourceConfigurationModified=False,
        packages=packages, certutil=dict(path='/usr/bin/certutil', bytes=100, sha256='e' * 64, uid=0, gid=0, mode=0o755),
        fonts=fonts, readbackComplete=True, production=False, authorization='BLOCKED',
        aptVersion=dict(version='2.8.3', architecture='amd64'), privateSources=dict(
            directory=dict(path=PRIVATE_DIRECTORY, uid=1001, gid=1001, mode=0o755),
            source=dict(path=PRIVATE_DIRECTORY+'/ubuntu.sources', bytes=source_size, sha256='f'*64,
                        uid=1001, gid=1001, mode=0o644, normalizedHostSHA256=policy['hostSourceSHA256'], replacedURIs=2, replacedSigners=2),
            mirrors=dict(path=PRIVATE_DIRECTORY+'/mirrors.txt', bytes=len(C.mirrors_bytes()), sha256=C.sha(C.mirrors_bytes()),
                         uid=1001, gid=1001, mode=0o644),
            parts=dict(path=PRIVATE_DIRECTORY+'/sourceparts', uid=1001, gid=1001, mode=0o755, empty=True),
            keyring=dict(path=PRIVATE_DIRECTORY+'/'+policy['privateSignedBy'], bytes=policy['keyringBytes'],
                         sha256='1'*64, sha512=policy['keyringSHA512'], uid=1001, gid=1001, mode=0o644),
            extraSourcesProbe=dict(argv=C.probe_argv(PRIVATE_DIRECTORY), exitCode=0, timedOut=False,
                                   elapsedMilliseconds=3, emptyOutput=True),
            effectiveConfigurationChanged=True),
        sourceInputs=[dict(path=name, bytes=len(blobs[name]), sha256=C.sha(blobs[name])) for name in sorted(blobs)])
    return value, logs, blobs


class DependencyReadbackVerifierContracts(unittest.TestCase):
    def check(self, args): return C.verify(*args, COMMIT)

    def test_01_closed_success_has_narrow_trusted_projection_scope(self):
        result = self.check(fixture())
        self.assertEqual(result['outcome'], 'PASS')
        self.assertEqual(result['fontStyles'], ['Regular', 'Bold'])
        for key in ('executionAttestationProven', 'independentLocalFontBytesVerified',
                    'reproduciblePackageProvenanceProven', 'browserAcceptanceProven', 'production',
                    'privateSourceReadbackIndependentlyProven', 'hostSourceConfigurationModified'):
            self.assertIs(result[key], False)
        self.assertIs(result['effectiveSourceConfigurationChanged'], True)

    def test_02_report_identity_schema_and_extra_fields_rejected(self):
        for key, val in [('sourceCommit', 'b' * 40), ('schema', 'other'), ('production', True),
                         ('authorization', 'APPROVED'), ('secret', 'unexportable')]:
            value, logs, blobs = fixture(); value[key] = val
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        for key, val in [('githubActions', 1), ('runnerOS', 'Windows'), ('architecture', 'arm64')]:
            value, logs, blobs = fixture(); value['platform'][key] = val
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        with self.assertRaises(C.Rejected): C.decoded(b'{"a":1,"a":1}')

    def test_03_missing_changed_or_truncated_original_log_rejected(self):
        for mode in ('missing', 'changed', 'truncated', 'bytes_bool'):
            value, logs, blobs = fixture()
            if mode == 'missing': logs.pop(C.LOG_NAMES[0])
            elif mode == 'changed': logs[C.LOG_NAMES[0]] = b'PASS\n'
            elif mode == 'truncated': value['logs'][0]['truncated'] = True
            else: value['logs'][0]['bytes'] = False
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_04_missing_source_blob_or_changed_contract_rejected(self):
        for name in C.SOURCE_PATHS:
            value, logs, blobs = fixture(); blobs.pop(name)
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); blobs[C.HELPER] += b'# changed\n'
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); changed = copy.deepcopy(C.FROZEN_CONTRACT); changed['updateTimeoutSeconds'] = 121
        blobs[C.CONTRACT] = json.dumps(changed).encode()
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_05_fail_timeout_nonzero_or_unexecuted_phase_cannot_pass(self):
        for field, val in [('outcome', 'FAIL'), ('failureStage', 'INSTALL'), ('readbackComplete', False)]:
            value, logs, blobs = fixture(); value[field] = val
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        for field, val in [('exitCode', 100), ('exitCode', False), ('timedOut', True), ('executed', False),
                           ('elapsedMilliseconds', None), ('elapsedMilliseconds', 999999)]:
            value, logs, blobs = fixture(); value['commands'][0][field] = val
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_06_unsafe_argv_host_options_path_and_duplicate_phase_rejected(self):
        for replacement in ('https://unreviewed.example/repo', '/tmp/fake-apt-get', '--allow-unauthenticated'):
            value, logs, blobs = fixture(); value['commands'][0]['argv'][-1] = replacement
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); value['commands'][1] = copy.deepcopy(value['commands'][0])
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); value['commands'][0]['argv'].remove('APT::Update::Error-Mode=any')
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_07_partial_fonts_wrong_tool_owner_mode_or_package_rejected(self):
        value, logs, blobs = fixture(); value['fonts'].pop()
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        for target, field, val in [('certutil', 'path', '/tmp/certutil'), ('certutil', 'mode', 0o777),
                                   ('certutil', 'uid', False), ('font', 'family', 'fallback'),
                                   ('font', 'ownerPackage', 'unknown'), ('font', 'bytes', 0), ('font', 'mode', 0o600)]:
            value, logs, blobs = fixture(); row = value['fonts'][0] if target == 'font' else value[target]; row[field] = val
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); value['packages'][0]['status'] = 'install ok unpacked'
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_08_source_configuration_change_or_unsafe_path_rejected(self):
        for mode in ('changed', 'flag', 'unknown', 'duplicate', 'traversal'):
            value, logs, blobs = fixture()
            if mode == 'changed': value['sourcesAfter'][0]['sha256'] = 'a' * 64
            elif mode == 'flag': value['sourceConfigurationModified'] = True
            elif mode == 'unknown': value['sourcesAfter'] = None
            elif mode == 'duplicate': value['sourcesBefore'].append(copy.deepcopy(value['sourcesBefore'][0]))
            else: value['sourcesBefore'][0]['path'] = '/etc/apt/../../tmp/config'
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_09_readback_lines_bind_projections_not_merely_log_hash(self):
        for content in (b'PASS\n', fixture()[1][C.LOG_NAMES[2]].replace(b'Regular', b'Bold', 1),
                        fixture()[1][C.LOG_NAMES[2]].replace(b'2:3.98-1build1', b'2:3.99', 1)):
            value, logs, blobs = fixture(); logs[C.LOG_NAMES[2]] = content
            value['logs'][2].update(bytes=len(content), sha256=C.sha(content))
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_10_empty_logs_stable_read_and_exclusive_external_report(self):
        with tempfile.TemporaryDirectory(prefix='dependency-checker-contract-') as directory:
            root = Path(directory); evidence = root / 'evidence'; repo = root / 'repo'; evidence.mkdir(); repo.mkdir()
            empty = evidence / 'empty.log'
            with empty.open('xb'): pass
            self.assertEqual(C.read(empty, 1), b'')
            normal = evidence / 'normal.log'
            with normal.open('xb') as output: output.write(b'original bytes\n')
            self.assertEqual(C.read(normal, 64), b'original bytes\n')
            actual = normal.stat()
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            def sample(ctime):
                values = {key: getattr(actual, key) for key in fields}; values['st_ctime_ns'] = ctime
                return SimpleNamespace(**values)
            # Path/FD ctime can differ, but neither API may change during read.
            for path_change, fd_change in ((False, False), (True, False), (False, True)):
                with mock.patch.object(Path, 'lstat', side_effect=[sample(11), sample(12 if path_change else 11)]), \
                     mock.patch.object(C.os, 'fstat', side_effect=[sample(22), sample(23 if fd_change else 22)]):
                    if path_change or fd_change:
                        with self.assertRaises(C.Rejected): C.read(normal, 64)
                    else: self.assertEqual(C.read(normal, 64), b'original bytes\n')
            result = self.check(fixture()); report = root / 'check.json'
            C.write_report(report, evidence, repo, result); saved = report.read_bytes()
            with self.assertRaises(FileExistsError): C.write_report(report, evidence, repo, result)
            self.assertEqual(saved, report.read_bytes())
            for bad in (evidence / 'bad.json', repo / 'bad.json'):
                with self.assertRaises(C.Rejected): C.write_report(bad, evidence, repo, result)

    def test_11_v2_contract_is_exact_and_old_schema_cannot_pass(self):
        # Historical frozen test name retained; the accepted contract is v3.
        actual = C.decoded(Path(__file__).with_name('ci-dependencies-contract.json').read_bytes())
        self.assertTrue(C.same(actual, C.FROZEN_CONTRACT))
        for schema in ('chengwang.ci-ui-dependencies/v1', 'chengwang.ci-ui-dependencies/v2'):
            value, logs, blobs = fixture(); value['schema'] = schema
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); value.pop('privateSources')
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_12_toolchain_first_line_version_architecture_and_budget(self):
        for raw in (b'apt x (amd64)\n', b'apt 2.8.3 (arm64)\n', b'apt 2.8.3 (amd64)\r\n',
                    b'apt 2.8.3 (amd64)', b'apt 2.8.4 (amd64)\n', b'apt 2.8.3 (amd64)\n\xff', b'x'*16385):
            value, logs, blobs = fixture(); logs[C.LOG_NAMES[3]] = raw
            value['logs'][3].update(bytes=len(raw), sha256=C.sha(raw))
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); value['aptVersion']['architecture'] = 'arm64'
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_13_missing_or_reordered_fourth_original_log_is_rejected(self):
        value, logs, blobs = fixture(); logs.pop(C.LOG_NAMES[3])
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); value['logs'][2], value['logs'][3] = value['logs'][3], value['logs'][2]
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_14_private_directory_owner_permissions_and_parts_are_closed(self):
        for field, key, val in [('directory','path','/tmp/chengwang-ci-apt-../escape'), ('directory','uid',True),
                                ('directory','mode',0o777), ('source','gid',1002), ('parts','empty',False),
                                ('parts','mode',0o777), ('mirrors','path',PRIVATE_DIRECTORY+'/other.txt')]:
            value, logs, blobs = fixture(); value['privateSources'][field][key] = val
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_15_normalized_host_hash_replacement_count_and_size_are_bound(self):
        for key, val in [('normalizedHostSHA256','0'*64), ('replacedURIs',True), ('replacedURIs',0),
                         ('replacedURIs',17), ('bytes',2995), ('sha256','invalid')]:
            value, logs, blobs = fixture(); value['privateSources']['source'][key] = val
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_16_private_mirror_priority_bytes_hash_and_unknown_payload_rejected(self):
        expected = b'https://archive.ubuntu.com/ubuntu/\tpriority:1\nhttps://security.ubuntu.com/ubuntu/\tpriority:2\nhttp://azure.archive.ubuntu.com/ubuntu/\tpriority:3\n'
        self.assertEqual(C.mirrors_bytes(), expected)
        for key, val in [('sha256','0'*64), ('bytes',1), ('mode',0o666), ('contents','secret source')]:
            value, logs, blobs = fixture(); value['privateSources']['mirrors'][key] = val
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_17_closed_security_options_private_paths_and_host_change_flags(self):
        for item in C.FROZEN_CONTRACT['securityOptions']:
            value, logs, blobs = fixture(); args = value['commands'][0]['argv']
            args[args.index(item)] = item.rsplit('=',1)[0] + '=' + ('true' if item.endswith('false') else 'false')
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); value['commands'][0]['argv'].append('APT_CONFIG=/tmp/other')
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); value['privateSources']['effectiveConfigurationChanged'] = False
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); value['sourceConfigurationModified'] = True
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_18_required_host_records_and_root_keyring_cannot_be_substituted(self):
        # Historical name retained: the isolated keyring now matches its private
        # directory's owner, never a root-owned host path trusted by metadata.
        for i in (0,1):
            value, logs, blobs = fixture(); value['sourcesBefore'][i]['sha256'] = '0'*64
            value['sourcesAfter'] = copy.deepcopy(value['sourcesBefore'])
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        for field, val in [('path','/tmp/other.gpg'), ('uid',0), ('gid',True), ('mode',0o666), ('bytes',2097153)]:
            value, logs, blobs = fixture(); value['privateSources']['keyring'][field] = val
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_19_extra_sources_probe_must_be_bound_empty_and_successful(self):
        value, logs, blobs = fixture(); value['privateSources'].pop('extraSourcesProbe')
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        for key, val in [('exitCode',1), ('exitCode',False), ('timedOut',True), ('emptyOutput',False),
                         ('elapsedMilliseconds',True), ('elapsedMilliseconds',5001), ('rawOutput','secret')]:
            value, logs, blobs = fixture(); value['privateSources']['extraSourcesProbe'][key] = val
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        for target in ('phase', 'probe'):
            value, logs, blobs = fixture()
            args = value['commands'][0]['argv'] if target == 'phase' else value['privateSources']['extraSourcesProbe']['argv']
            args.remove('APT_CONFIG')
            with self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); value['privateSources']['extraSourcesProbe']['argv'][-1] = 'Binary::apt-get'
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_20_v3_approved_manifest_pin_and_candidate_policy_are_frozen(self):
        policy = C.FROZEN_CONTRACT['privateSourcePolicy']
        self.assertEqual(policy['keyringBytes'], 3607)
        self.assertEqual(policy['keyringSHA512'],
            '4e344ffbb31f205af8c6db3c260222e4af886af4d5c28462106c579d7ae46f91153340eafad843186d7788370634d8097c117748921455e5bbb219bf08a28a40')
        self.assertEqual(policy['keyringManifestURL'],
            'https://git.launchpad.net/ubuntu/+source/ubuntu-keyring/plain/SHA512SUMS.txt.asc?id=edc0a0be9a90f364bc39a87d3837ad4c15395950')
        for field, val in [('keyringBytes',3608), ('keyringSHA512','0'*128),
                           ('privateSignedBy','../ubuntu-archive-keyring.gpg'),
                           ('keyringManifestURL',policy['keyringManifestURL'].split('?')[0]),
                           ('hostKeyringTreatedAsUntrusted',False), ('hostKeyringModified',True),
                           ('pinSignatureIndependentlyVerified',True)]:
            value, logs, blobs = fixture(); altered = copy.deepcopy(C.FROZEN_CONTRACT)
            altered['privateSourcePolicy'][field] = val
            blobs[C.CONTRACT] = json.dumps(altered).encode()
            # Re-seal source metadata so the independent frozen contract check,
            # not only a stale byte digest, rejects the altered trust policy.
            for row in value['sourceInputs']:
                if row['path'] == C.CONTRACT:
                    row.update(bytes=len(blobs[C.CONTRACT]), sha256=C.sha(blobs[C.CONTRACT]))
            with self.subTest(field=field), self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_21_signer_count_is_required_integer_equal_to_uri_count(self):
        for val in (None, False, 0, 1, 3, 17, '2'):
            value, logs, blobs = fixture(); source = value['privateSources']['source']
            source['replacedSigners'] = val
            with self.subTest(value=val), self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); value['privateSources']['source'].pop('replacedSigners')
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_22_private_source_size_requires_both_uri_and_signer_deltas(self):
        policy = C.FROZEN_CONTRACT['privateSourcePolicy']
        uri_delta = len('mirror+file:' + PRIVATE_DIRECTORY + '/mirrors.txt') - len(policy['hostMirrorURI'])
        signer_delta = len(PRIVATE_DIRECTORY + '/' + policy['privateSignedBy']) - len(policy['signedBy'])
        self.assertNotEqual(signer_delta, 0)
        for count in (1, 2, 16):
            value, logs, blobs = fixture(); row = value['privateSources']['source']
            row.update(replacedURIs=count, replacedSigners=count,
                       bytes=policy['hostSourceBytes'] + count * (uri_delta + signer_delta))
            self.assertEqual(self.check((value, logs, blobs))['outcome'], 'PASS')
            for omitted_delta in (signer_delta, uri_delta):
                bad = copy.deepcopy(value); bad['privateSources']['source']['bytes'] -= count * omitted_delta
                with self.subTest(count=count, omitted=omitted_delta), self.assertRaises(C.Rejected):
                    self.check((bad, logs, blobs))

    def test_23_keyring_pin_size_and_closed_projection_are_required(self):
        for field, val in [('sha512','0'*128), ('sha512','4'*127), ('sha512',True),
                           ('sha512',C.FROZEN_CONTRACT['privateSourcePolicy']['keyringSHA512'].upper()),
                           ('bytes',3606), ('bytes',3608), ('bytes',True), ('sha256','wrong'),
                           ('rawBytes','not public'), ('signatureVerified',True)]:
            value, logs, blobs = fixture(); value['privateSources']['keyring'][field] = val
            with self.subTest(field=field, value=val), self.assertRaises(C.Rejected): self.check((value, logs, blobs))
        value, logs, blobs = fixture(); value['privateSources']['keyring'].pop('sha512')
        with self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_24_private_keyring_cannot_refer_back_to_host_or_other_directory(self):
        for path in (C.FROZEN_CONTRACT['privateSourcePolicy']['signedBy'],
                     '/tmp/chengwang-ci-apt-ijklmnop/ubuntu-archive-keyring.gpg',
                     PRIVATE_DIRECTORY+'/../ubuntu-archive-keyring.gpg',
                     PRIVATE_DIRECTORY+'/ubuntu-archive-keyring.gpg.link'):
            value, logs, blobs = fixture(); value['privateSources']['keyring']['path'] = path
            with self.subTest(path=path), self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_25_private_keyring_owner_and_exact_mode_follow_isolated_directory(self):
        for uid, gid in ((0,0), (1001,1001), (123,456)):
            value, logs, blobs = fixture()
            for name in ('directory', 'source', 'mirrors', 'parts', 'keyring'):
                value['privateSources'][name].update(uid=uid, gid=gid)
            self.assertEqual(self.check((value, logs, blobs))['outcome'], 'PASS')
        for field, val in [('uid',True), ('gid',1002), ('mode',0o600), ('mode',0o664),
                           ('mode',0o666), ('mode',0o644 | 0o4000)]:
            value, logs, blobs = fixture(); value['privateSources']['keyring'][field] = val
            with self.subTest(field=field, value=val), self.assertRaises(C.Rejected): self.check((value, logs, blobs))

    def test_26_pin_projection_does_not_claim_independent_key_bytes_or_signature(self):
        # No keyring bytes exist in this fixture or are fetched.  SHA256 remains
        # a safe producer projection: it cannot be derived from the SHA512 pin.
        for projected_sha256 in ('1'*64, '2'*64):
            value, logs, blobs = fixture(); value['privateSources']['keyring']['sha256'] = projected_sha256
            with mock.patch.object(C.subprocess, 'check_output', side_effect=AssertionError('no process allowed')):
                result = self.check((value, logs, blobs))
            self.assertEqual(result['schema'], 'chengwang.ci-ui-dependencies-verification/v3')
            for key in ('privateSourceReadbackIndependentlyProven', 'executionAttestationProven',
                        'reproduciblePackageProvenanceProven', 'browserAcceptanceProven', 'production'):
                self.assertIs(result[key], False)
            self.assertNotIn('signatureVerified', result)


if __name__ == '__main__': unittest.main()
