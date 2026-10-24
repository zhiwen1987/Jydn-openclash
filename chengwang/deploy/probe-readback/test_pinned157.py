"""Pure CPU contracts; synthetic custody fixtures are never real-browser PASS evidence."""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import check_pinned157 as V
import prepare_pinned157 as P

COMMIT = 'a' * 40
FIXTURE = 'b' * 32


def fixture():
    installed = b'{"name":"playwright-core","version":"1.64.1"}'
    files = [dict(path='chrome', bytes=V.ELF_BYTES, sha256=V.ELF_SHA)]
    receipt = dict(schema='chengwang.pinned-browser-consumption-verification/v1', sourceCommit=COMMIT,
                   pinEnforced=True, browserExecuted=False, elf=dict(bytes=V.ELF_BYTES, sha256=V.ELF_SHA))
    copied = dict(schema='chengwang.probe-pinned157-copy/v1', sourceCommit=COMMIT, browserVersion='157.0.8103.6',
                  actualAcquisition='FIXED_CFT_ARCHIVE_NOT_HOST_CHROME', receiptSHA256=V.sha(V.canonical(receipt)),
                  files=files, sourceUnchanged=True, rootOwnedReadOnlyDistribution=True, browserExecuted=False, production=False)
    chrome = dict(role='chrome', pid=123, startTime='456', argvSHA256='c' * 64, exeSHA256=V.ELF_SHA)
    chrome_id = dict(pid=123, startTicks=456, argvSHA256='c' * 64)
    browser = dict(product='Chrome/157.0.8103.6', revision='@' + V.TAG, protocolVersion='1.3')
    copyrows = [dict(path='toolchain/chrome/chrome', bytes=V.ELF_BYTES, sha256=V.ELF_SHA),
                dict(path='toolchain/node', bytes=1, sha256='d' * 64),
                dict(path='npm/playwright-core/package.json', bytes=len(installed), sha256=V.sha(installed))]
    data = {'pinned157-consumption.json': receipt, 'pinned157-copy.json': copied,
        'lab/browser/browser-build.json': dict(sourceCommit=COMMIT, engine='chrome-cdp', production=False,
            fixtureId=FIXTURE, sourceFilesBefore=[], sourceFilesAfter=[], copiedInputs=copyrows),
        'lab/browser/browser-processes.json': dict(sourceCommit=COMMIT, controllerExitCode=0, production=False,
            records=[chrome, dict(role='controller', exeSHA256='d' * 64)],
            chromeExecutable=dict(bytes=V.ELF_BYTES, sha256=V.ELF_SHA, sourceScope='TRUSTED_CI_SYSTEM_TOOL_NOT_INDEPENDENT_SUPPLY_CHAIN')),
        'lab/browser/browser-driver.json': dict(fixtureId=FIXTURE, engine='chrome-cdp', runtime=True,
            realBrowser=browser['product'], chrome=chrome_id, mockedResponses=False, injectedFetch=False, tlsBypass=False,
            **{k: 0 for k in V.COUNTERS}),
        'lab/browser-identity.json': dict(sourceCommit=COMMIT, fixtureId=FIXTURE, engine='chrome-cdp', state='observed',
            rawIdentityLines=1, executable=dict(bytes=V.ELF_BYTES, sha256=V.ELF_SHA),
            observation=dict(fixtureId=FIXTURE, engine='chrome-cdp', browser=browser, chrome=chrome_id)),
        'toolchain.json': dict(schema='chengwang.probe-browser-toolchain/v1', outcome='PASS', acceptanceScope='TOOLCHAIN_ONLY',
            runtime=False, browserStarted=False, nodeVersion='v22.23.3', playwrightVersion='1.64.1', chromiumLaunchAvailable=True)}
    return data, copy.deepcopy(receipt), copy.deepcopy(files), installed


class Pinned157Contracts(unittest.TestCase):
    def check(self, values=None):
        return V.verify_binding(*(values or fixture()), COMMIT, 'chrome-cdp')

    def test_synthetic_closed_identity_intersection_never_claims_browser_acceptance(self):
        result = self.check()
        self.assertEqual(result['actualAcquisition'], 'FIXED_CFT_ARCHIVE_NOT_HOST_CHROME')
        self.assertFalse(result['browserAcceptanceProven'])
        self.assertFalse(result['uniqueCancellationRootCauseProven'])

    def test_host155_with_pinned_receipt_is_rejected(self):
        f = fixture(); f[0]['lab/browser/browser-driver.json']['realBrowser'] = 'Chrome/155.0.8059.39'
        f[0]['lab/browser-identity.json']['observation']['browser']['product'] = 'Chrome/155.0.8059.39'
        with self.assertRaises(ValueError): self.check(f)

    def test_correct_version_with_wrong_revision_is_rejected(self):
        f = fixture(); f[0]['lab/browser-identity.json']['observation']['browser']['revision'] = '@' + '0' * 40
        with self.assertRaises(ValueError): self.check(f)

    def test_correct_version_receipt_with_wrong_process_elf_is_rejected(self):
        f = fixture(); f[0]['lab/browser/browser-processes.json']['records'][0]['exeSHA256'] = '0' * 64
        with self.assertRaises(ValueError): self.check(f)

    def test_correct_process_with_wrong_copied_elf_is_rejected(self):
        f = fixture(); f[0]['lab/browser/browser-build.json']['copiedInputs'][0]['sha256'] = '0' * 64
        with self.assertRaises(ValueError): self.check(f)

    def test_missing_or_extra_distribution_member_is_rejected(self):
        for remove in (True, False):
            f = fixture(); rows = f[0]['lab/browser/browser-build.json']['copiedInputs']
            if remove: rows.pop(0)
            else: rows.append(dict(path='toolchain/chrome/extra', bytes=1, sha256='e' * 64))
            with self.assertRaises(ValueError): self.check(f)

    def test_changed_fresh_receipt_is_not_replaced_by_producer_pass(self):
        f = fixture(); f[1]['independentlyChanged'] = True
        with self.assertRaises(ValueError): self.check(f)

    def test_copy_receipt_hash_and_source_commit_are_bound(self):
        for key, value in [('receiptSHA256', '0' * 64), ('sourceCommit', 'd' * 40), ('actualAcquisition', 'HOST_INSTALLATION')]:
            f = fixture(); f[0]['pinned157-copy.json'][key] = value
            with self.assertRaises(ValueError): self.check(f)

    def test_identity_pid_start_and_argv_cannot_be_swapped(self):
        for key, value in [('pid', 124), ('startTicks', 457), ('argvSHA256', '0' * 64)]:
            f = fixture(); f[0]['lab/browser-identity.json']['observation']['chrome'][key] = value
            with self.assertRaises(ValueError): self.check(f)

    def test_cross_engine_fixture_and_commit_reject(self):
        for field, value in [('engine', 'playwright'), ('fixtureId', 'd' * 32), ('sourceCommit', 'd' * 40)]:
            f = fixture(); f[0]['lab/browser-identity.json'][field] = value
            with self.assertRaises(ValueError): self.check(f)

    def test_all_original_eight_error_counters_stay_strict(self):
        for key in V.COUNTERS:
            for value in (1, False):
                f = fixture(); f[0]['lab/browser/browser-driver.json'][key] = value
                with self.assertRaises(ValueError): self.check(f)

    def test_mock_fetch_and_tls_bypass_never_qualify(self):
        for key in ('mockedResponses', 'injectedFetch', 'tlsBypass'):
            f = fixture(); f[0]['lab/browser/browser-driver.json'][key] = True
            with self.assertRaises(ValueError): self.check(f)

    def test_controller_executable_must_match_actual_copied_node(self):
        f = fixture(); f[0]['lab/browser/browser-processes.json']['records'][1]['exeSHA256'] = '0' * 64
        with self.assertRaises(ValueError): self.check(f)

    def test_playwright_alpha_or_changed_package_bytes_are_rejected(self):
        f = fixture(); f[0]['toolchain.json']['playwrightVersion'] = '1.65.0-alpha-2026-10-23'
        with self.assertRaises(ValueError): self.check(f)
        f = fixture(); f = (*f[:3], f[3] + b' ')
        with self.assertRaises(ValueError): self.check(f)

    def test_changed_node_version_and_toolchain_boolean_spoof_reject(self):
        for key, value in [('nodeVersion', 'v24.0.0'), ('browserStarted', 0), ('chromiumLaunchAvailable', 1)]:
            f = fixture(); f[0]['toolchain.json'][key] = value
            # Python dict equality must not confuse bool with an integer.
            with self.assertRaises(ValueError): self.check(f)

    def test_legacy_trust_class_cannot_be_used_as_acquisition_proof(self):
        f = fixture(); del f[0]['pinned157-copy.json']['actualAcquisition']
        with self.assertRaises(ValueError): self.check(f)

    def test_source_metadata_drift_rejects(self):
        f = fixture(); f[0]['lab/browser/browser-build.json']['sourceFilesAfter'] = [{'changed': True}]
        with self.assertRaises(ValueError): self.check(f)

    def test_duplicate_json_nonfinite_and_duplicate_copy_records_reject(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'[]'):
            with self.assertRaises(ValueError): V.decode(raw)
        row = dict(path='toolchain/chrome/chrome', bytes=1, sha256='a' * 64)
        with self.assertRaises(ValueError): V.records([row, row])

    def test_unsafe_copy_member_paths_are_rejected(self):
        for path in ('../secret', '/secret', 'a/../secret'):
            with self.assertRaises(ValueError): V.records([dict(path=path, bytes=1, sha256='a' * 64)])

    def test_expanded_directories_are_not_fabricated_file_copies(self):
        manifest = dict(expanded=dict(members=[dict(path='chrome-linux64/', type='directory', bytes=0),
            dict(path='chrome-linux64/chrome', type='file', bytes=1, sha256='a' * 64)]))
        self.assertEqual(V.copy_files(manifest), [dict(path='chrome', bytes=1, sha256='a' * 64)])

    def test_copy_destination_cannot_overwrite_existing_or_host_chrome(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); src = root / 'source'; src.mkdir()
            dst = root / 'chrome'; dst.mkdir()
            with self.assertRaises(ValueError): P.copy_distribution(src, dst, [])
            with self.assertRaises(ValueError): P.copy_distribution(src, Path('/opt/google/chrome'), [])

    def test_exclusive_report_and_symlink_read_reject(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); target = root / 'report.json'; V.write_new(target, b'{}')
            with self.assertRaises(ValueError): V.write_new(target, b'overwrite')
            with mock.patch.object(Path, 'lstat', return_value=type('Info', (), {'st_mode': stat_mode_link(), 'st_file_attributes': 0})()):
                with self.assertRaises(ValueError): V.unaliased(target)

    def test_regular_reader_rejects_limit_and_open_descriptor_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'source'; path.write_bytes(b'abc')
            self.assertEqual(V.read_file(path, 3), b'abc')
            with self.assertRaises(ValueError): V.read_file(path, 2)
            actual = os.fstat
            calls = 0
            def changed(fd):
                nonlocal calls
                value = actual(fd); calls += 1
                if calls == 2:
                    fake = type('Info', (), {k: getattr(value, k) for k in ('st_dev','st_ino','st_size','st_mode','st_nlink','st_mtime_ns','st_ctime_ns')})()
                    fake.st_mtime_ns += 1; return fake
                return value
            with mock.patch.object(os, 'fstat', side_effect=changed):
                with self.assertRaises(ValueError): V.read_file(path, 3)

    def test_binding_source_git_mismatch_and_alias_reject(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(V, 'SOURCES', ('source.txt',)), mock.patch.object(V, 'HOST', Path(temp)), \
                 mock.patch.object(V.subprocess, 'run', return_value=type('R', (), {'returncode':0,'stdout':b'git-bytes'})()), \
                 mock.patch.object(V, 'read_file', return_value=b'different'):
                with self.assertRaises(ValueError): V.bind_sources(Path(temp), COMMIT)

    def test_fixed_cli_rejections_do_not_echo_private_arguments(self):
        for script in ('check_pinned157.py', 'prepare_pinned157.py'):
            run = subprocess.run([sys.executable, '-B', str(Path(__file__).parent / script), '--SECRET-ARGUMENT'], capture_output=True)
            self.assertNotEqual(run.returncode, 0); self.assertNotIn(b'SECRET-ARGUMENT', run.stderr)
            self.assertIn(b'raw_input_suppressed=true', run.stderr)

    def test_actual_workflow_selector_defaults_only_for_absent_key(self):
        source = (V.HOST / '.github/workflows/chengwang-probe-browser.yml').read_text(encoding='utf-8')
        block = source.split("python3 -B - <<'PY'\n", 1)[1].split('\n          PY', 1)[0]
        block = '\n'.join(line[10:] for line in block.splitlines())
        positive = [(inputs, event, 'hosted') for event in ('push','pull_request','workflow_dispatch') for inputs in (None,{})]
        positive += [({'browser-runtime':value}, 'workflow_call', value) for value in ('hosted','pinned157')]
        for inputs, event, expected in positive:
            with tempfile.TemporaryDirectory() as temp:
                out = Path(temp) / 'output'
                env = dict(os.environ, BROWSER_RUNTIME_INPUTS=json.dumps(inputs), BROWSER_RUNTIME_EVENT=event, GITHUB_OUTPUT=str(out))
                run = subprocess.run([sys.executable, '-c', block], capture_output=True, env=env)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(out.read_text(), 'runtime=' + expected + '\n')
        negative = [(inputs,'push') for inputs in [{'browser-runtime':''}, {'browser-runtime':None}, {'browser-runtime':False},
                       {'browser-runtime':'pinned158'}, {'other':'PRIVATE_SENTINEL'}, {'browser-runtime':'hosted','other':True}, []]]
        negative += [(inputs,event) for event in ('workflow_call','schedule','repository_dispatch','') for inputs in (None,{})]
        for inputs, event in negative:
            with tempfile.TemporaryDirectory() as temp:
                out = Path(temp) / 'output'
                run = subprocess.run([sys.executable, '-c', block], capture_output=True,
                    env=dict(os.environ, BROWSER_RUNTIME_INPUTS=json.dumps(inputs), BROWSER_RUNTIME_EVENT=event, GITHUB_OUTPUT=str(out)))
                self.assertNotEqual(run.returncode, 0); self.assertFalse(out.exists())
                self.assertNotIn(b'PRIVATE_SENTINEL', run.stderr)

    def test_actual_prepare_copies_only_verified_bytes_and_refuses_reentry(self):
        # Only POSIX ownership validation is mocked; real source reads, exclusive
        # writes, content hashes and bounded path logic execute on this host.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); src = root / 'source'; src.mkdir(); (src/'locales').mkdir()
            (src/'chrome').write_bytes(b'SYNTHETIC_NOT_AN_ELF'); (src/'locales/a.pak').write_bytes(b'locale')
            rows = [dict(path=name,bytes=len((src/name).read_bytes()),sha256=V.sha((src/name).read_bytes()))
                    for name in ('chrome','locales/a.pak')]
            runtime = root/'chengwang-probe-browser-runtime'; runtime.mkdir(); dst=runtime/'chrome'
            with mock.patch.object(P.sys,'platform','linux'), mock.patch.object(P.os,'geteuid',return_value=0,create=True), \
                 mock.patch.object(P,'validate_copy_info') as ownership:
                P.copy_distribution(src,dst,rows)
                self.assertEqual(ownership.call_count,2)
                self.assertEqual((dst/'chrome').read_bytes(),b'SYNTHETIC_NOT_AN_ELF')
                self.assertEqual((dst/'locales/a.pak').read_bytes(),b'locale')
                with self.assertRaises(ValueError): P.copy_distribution(src,dst,rows)

    def test_prepare_hash_mismatch_and_source_link_never_publish_distribution(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);src=root/'source';src.mkdir();(src/'chrome').write_bytes(b'actual')
            runtime=root/'chengwang-probe-browser-runtime';runtime.mkdir();dst=runtime/'chrome'
            with mock.patch.object(P.sys,'platform','linux'), mock.patch.object(P.os,'geteuid',return_value=0,create=True):
                with self.assertRaises(ValueError): P.copy_distribution(src,dst,[dict(path='chrome',bytes=6,sha256='0'*64)])
                self.assertFalse((dst/'chrome').exists())
            with mock.patch.object(V,'unaliased',side_effect=ValueError('link')):
                with self.assertRaises(ValueError): P.copy_distribution(src,runtime/'other',[])

    def test_prepared_file_must_be_root_owned_nonwritable_and_regular(self):
        import stat
        def info(**kw):
            values=dict(st_mode=stat.S_IFREG|0o755,st_nlink=1,st_uid=0,st_gid=0);values.update(kw)
            return type('Info',(),values)()
        P.validate_copy_info(info(),0o755)
        for value in [info(st_uid=10001),info(st_gid=10001),info(st_nlink=2),
                      info(st_mode=stat.S_IFLNK|0o755),info(st_mode=stat.S_IFREG|0o777)]:
            with self.assertRaises(ValueError):P.validate_copy_info(value,0o755)

    def test_prepare_locations_cannot_escape_fixed_runner_temp_family(self):
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); runtime=root/'chengwang-probe-browser-runtime'
            values=dict(destination=runtime/'chrome',consumption_root=root/'chengwang-probe-pinned157-consumption',
                        receipt=runtime/'evidence/pinned157-consumption.json',report=runtime/'evidence/pinned157-copy.json')
            P.validate_locations(Namespace(**values),root)
            for key in values:
                changed=dict(values);changed[key]=root/'unrelated'
                with self.assertRaises(ValueError):P.validate_locations(Namespace(**changed),root)

    def test_fixed_workflow_reuses_original_gates_without_host_success_dependency(self):
        source=(V.HOST/'.github/workflows/chengwang-probe-pinned157.yml').read_text(encoding='utf-8')
        self.assertIn('uses: ./.github/workflows/chengwang-probe-browser.yml',source)
        self.assertIn('browser-runtime: pinned157',source)
        self.assertNotIn('continue-on-error',source)
        self.assertIn('needs: pinned-producer',source)
        # The experimental wrapper must not activate on main or PR, including
        # manual dispatch from another ref; both jobs carry the exact guard.
        on = source.split('permissions:',1)[0]
        self.assertIn('  workflow_dispatch:',on)
        self.assertIn('    branches: [codex/chengwang-probe-pinned157-20261024]',on)
        self.assertNotIn('pull_request:',on);self.assertNotIn('branches: [main',on)
        producer = source.split('  pinned-producer:',1)[1].split('  fresh-pinned-verifier:',1)[0]
        fresh = source.split('  fresh-pinned-verifier:',1)[1]
        guard = "github.ref == 'refs/heads/codex/chengwang-probe-pinned157-20261024' && (github.event_name == 'push' || github.event_name == 'workflow_dispatch')"
        self.assertIn('if: ${{ '+guard+' }}',producer)
        self.assertIn("if: ${{ !cancelled() && "+guard+" && needs.pinned-producer.result != 'skipped' }}",fresh)
        original=(V.HOST/'.github/workflows/chengwang-probe-browser.yml').read_text(encoding='utf-8')
        self.assertIn('  pull_request:\n    branches: [main]',original)
        self.assertIn('branches: [main, codex/chengwang-security-hardening, codex/chengwang-live-overview-20261024, codex/chengwang-probe-pinned157-20261024]',original)
        for script in ['check_probe_readback','check_probe_browser','check_status_diagnostic','check_request_binding',
                       'check_status_network_lifecycle','probe_browser_identity','check_eof_cleanup','check_pinned157']:
            self.assertIn('/'+script+'.py',source)


def stat_mode_link():
    import stat
    return stat.S_IFLNK | 0o777


if __name__ == '__main__':
    unittest.main()
