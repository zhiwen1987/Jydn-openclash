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
    logs = dict(zip(C.LOG_NAMES, (b'', b'Fetched synthetic dependency fixture\n', readback.encode())))
    source = [dict(path='/etc/apt/sources.list.d/ubuntu.sources', bytes=100, sha256='d' * 64)]
    value = dict(schema='chengwang.ci-ui-dependencies/v1', scope=C.SCOPE, sourceCommit=COMMIT,
        outcome='PASS', failureStage='NONE', platform=dict(githubActions=True, runnerOS='Linux', system='Linux',
        ubuntu='24.04', architecture='amd64'), commands=[dict(stage=s, argv=C.argv(s), executed=True,
        exitCode=0, timedOut=False, elapsedMilliseconds=20) for s in ('UPDATE', 'INSTALL')],
        logs=[dict(path=name, bytes=len(logs[name]), sha256=C.sha(logs[name]), truncated=False) for name in C.LOG_NAMES],
        sourcesBefore=source, sourcesAfter=copy.deepcopy(source), sourceConfigurationModified=False,
        packages=packages, certutil=dict(path='/usr/bin/certutil', bytes=100, sha256='e' * 64, uid=0, gid=0, mode=0o755),
        fonts=fonts, readbackComplete=True, production=False, authorization='BLOCKED',
        sourceInputs=[dict(path=name, bytes=len(blobs[name]), sha256=C.sha(blobs[name])) for name in sorted(blobs)])
    return value, logs, blobs


class DependencyReadbackVerifierContracts(unittest.TestCase):
    def check(self, args): return C.verify(*args, COMMIT)

    def test_01_closed_success_has_narrow_trusted_projection_scope(self):
        result = self.check(fixture())
        self.assertEqual(result['outcome'], 'PASS')
        self.assertEqual(result['fontStyles'], ['Regular', 'Bold'])
        for key in ('executionAttestationProven', 'independentLocalFontBytesVerified',
                    'reproduciblePackageProvenanceProven', 'browserAcceptanceProven', 'production'):
            self.assertIs(result[key], False)

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


if __name__ == '__main__': unittest.main()
