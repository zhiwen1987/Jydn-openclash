"""Supplemental source-bound normal-EOF observations, never cancellation causality.

The two original unmodified CLIs are actually replayed, not replaced by stored
PASS values. Only their stable original inputs and reports are accepted. The
normal read's absence of cancellation is not relabelled as RESOLVED.
"""
import argparse
import hashlib
import json
import pathlib
import re
import stat
import subprocess
import sys
import tempfile

import check_probe_readback as B
import check_request_binding as R

HERE = pathlib.Path(__file__).resolve().parent
HOST_ROOT = HERE.parents[2]
CONTRACT_PATH = 'chengwang/deploy/probe-readback/eof-cleanup-contract.json'
CONTRACT_RAW = B.read_file(HERE / 'eof-cleanup-contract.json', 65536)
CONTRACT = B.decoded(CONTRACT_RAW)
BROWSER_SUCCESS = b'PROBE_BROWSER_CHECK=PASS authorization=BLOCKED production=false'
BINDING_SUCCESS = b'PROBE_REQUEST_BINDING=VERIFIED browser_acceptance_proven=false cancellation_root_cause_proven=false'
COUNTERS = ('runtimeErrors', 'consoleErrors', 'consoleWarnings', 'cspErrors',
            'assetErrors', 'forbiddenRequests', 'failedRequests', 'captureErrors')


def need(value):
    if not value:
        raise ValueError('EOF cleanup evidence rejected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_contract():
    need(CONTRACT['schema'] == 'chengwang.probe-eof-cleanup-contract/v1'
         and CONTRACT['verificationSchema'] == 'chengwang.probe-eof-cleanup-verification/v1'
         and type(CONTRACT['anonymousStatusRequests']) is int and CONTRACT['anonymousStatusRequests'] == 7
         and CONTRACT['clockDomains'] == R.CLOCKS)
    paths = CONTRACT['requiredSourceFiles']
    need(type(paths) is list and len(paths) == len(set(paths)) == 16
         and CONTRACT_PATH in paths and 'chengwang/deploy/probe-readback/check_eof_cleanup.py' in paths
         and '.github/workflows/chengwang-probe-browser.yml' in paths)
    need(all(type(path) is str and re.fullmatch(r'[A-Za-z0-9_./-]+', path)
             and '..' not in pathlib.PurePosixPath(path).parts for path in paths))
    for field in ('oldBrowserAndBindingVerifiersModified', 'oldDiagnosticSchemasModified',
                  'oldEightZeroErrorCountersRelaxed', 'perRequestDTOSchemaProven',
                  'cancellationRootCauseProven', 'packetCausalityProven',
                  'longTermStabilityProven', 'production'):
        need(CONTRACT[field] is False)
    need(CONTRACT['hostOnlySourcesDoNotRequireRuntimeCopies'] is True
         and CONTRACT['authorization'] == 'BLOCKED')
    synthetic = CONTRACT['syntheticContract']
    need(synthetic['module'] == 'test_check_eof_cleanup'
         and synthetic['class'] == 'EOFCleanupVerifierContracts'
         and type(synthetic['tests']) is int and synthetic['tests'] == 26
         and synthetic['nameEncoding'] == 'UTF8_SORTED_LF_NO_TRAILING_LF'
         and synthetic['scope'] == 'MOCKED_ORIGINAL_CLI_HELPER_UNIT_ONLY')
    need(all(type(synthetic[field]) is str and re.fullmatch('[a-f0-9]{64}', synthetic[field])
             for field in ('methodNamesSHA256', 'fullNamesSHA256')))


def input_snapshot(evidence):
    """All original lab inputs and the two consumed reports, never our own log."""
    need(evidence.is_dir() and not evidence.is_symlink())
    lab = evidence / 'lab'
    need(lab.is_dir() and not lab.is_symlink())
    paths = []
    for path in sorted(lab.rglob('*')):
        need(not path.is_symlink())
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        paths.append(path)
    paths.extend(evidence / name for name in ('browser-verification.json', 'request-binding-verification.json'))
    need(0 < len(paths) <= CONTRACT['maxInputFiles'])
    result, total = {}, 0
    for path in paths:
        raw = B.read_file(path, CONTRACT['maxInputFileBytes'])
        total += len(raw)
        need(total <= CONTRACT['maxInputBytes'])
        key = path.relative_to(evidence).as_posix()
        need(key not in result)
        result[key] = raw
    return result


def git_blob(repo, commit, name):
    result = subprocess.run(['git', '-C', str(repo), 'show', commit + ':' + name],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    need(result.returncode == 0 and 0 < len(result.stdout) <= CONTRACT['maxInputFileBytes'])
    return result.stdout


def bind_sources(repo, commit, build):
    before, after = build['sourceFilesBefore'], build['sourceFilesAfter']
    need(type(before) is list and type(after) is list and before == after)
    sources = {}
    for entry in before:
        need(type(entry) is dict and set(entry) == {'path', 'bytes', 'sha256'}
             and type(entry['path']) is str and entry['path'] not in sources
             and type(entry['bytes']) is int and 0 < entry['bytes'] <= CONTRACT['maxInputFileBytes']
             and type(entry['sha256']) is str and re.fullmatch('[a-f0-9]{64}', entry['sha256']))
        sources[entry['path']] = entry
    bindings, host = [], {}
    for name in CONTRACT['requiredSourceFiles']:
        need(name in sources)
        raw = git_blob(repo, commit, name)
        expected = dict(path=name, bytes=len(raw), sha256=sha(raw))
        need(sources[name] == expected)
        # New checker/contract/workflow are host-only; copiedInputs is not a
        # runtime-copy requirement for them. The original CLIs check their own
        # real runtime copies independently, unchanged.
        actual = B.read_file(HOST_ROOT / name, CONTRACT['maxInputFileBytes'])
        need(actual == raw)
        bindings.append(expected)
        host[name] = actual
    need(host[CONTRACT_PATH] == CONTRACT_RAW)
    return bindings, host


def replay_originals(evidence, repo, commit, engine, scratch_parent, originals):
    commands = (
        ('browser', HERE / 'check_probe_browser.py', ['verify', '--backend-dir', str(evidence / 'lab/backend'),
         '--browser-dir', str(evidence / 'lab/browser'), '--source-commit', commit, '--engine', engine],
         'browser-verification.json', BROWSER_SUCCESS),
        ('binding', HERE / 'check_request_binding.py', ['--evidence-root', str(evidence / 'lab'),
         '--source-commit', commit, '--engine', engine, '--repo', str(repo)],
         'request-binding-verification.json', BINDING_SUCCESS),
    )
    reports = {}
    with tempfile.TemporaryDirectory(prefix='probe-eof-originals-', dir=scratch_parent) as directory:
        scratch = pathlib.Path(directory)
        need(not scratch.resolve().is_relative_to(evidence.resolve())
             and not scratch.resolve().is_relative_to(repo.resolve()))
        for kind, script, arguments, original_name, marker in commands:
            report = scratch / (kind + '.json')
            result = subprocess.run([sys.executable, '-B', str(script), *arguments, '--report', str(report)],
                                    cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=600, check=False)
            need(result.returncode == 0 and result.stdout.strip() == marker and result.stderr == b'')
            raw = B.read_file(report, CONTRACT['maxReportBytes'])
            need(raw == originals[original_name])
            reports[kind] = B.decoded(raw)
    return reports


def normal_eof_facts(binding, old_raw, driver, commit, engine):
    rows, complete = R.check_envelope(binding, old_raw, commit, engine)
    _old_rows, old_complete = R.old_observations(old_raw, commit, engine)
    need(complete and old_complete)
    for key in COUNTERS:
        need(type(driver.get(key)) is int and driver[key] == 0)
    need(not any(row['e'] in ('CANCEL_RESULT', 'NET_FAIL')
                 or row['e'] == 'JS' and row['j'] in ('CANCEL', 'ABORT') for row in rows))
    begins = {}
    for row in rows:
        if row['e'] == 'JS' and row['j'] == 'BEGIN':
            key = (row['m'], row['r'])
            need(key not in begins)
            begins[key] = row
    expected = CONTRACT['anonymousStatusRequests']
    need(len(begins) == expected)
    sends, starts, nmap = {}, {}, {}
    for row in rows:
        if row['e'] in ('SEND', 'NET_START'):
            key = (row['m'], row['r'])
            need(key in begins)
            table = sends if row['e'] == 'SEND' else starts
            need(key not in table)
            table[key] = row
            if row['e'] == 'NET_START':
                need(row['n'] not in nmap)
                nmap[row['n']] = key
    need(set(sends) == set(starts) == set(begins) and len(nmap) == expected)
    for key in begins:
        events = [row for row in rows if row['e'] == 'JS' and (row['m'], row['r']) == key]
        need(all(row['a'] is False for row in events) and sends[key]['a'] is False)
        selected = {}
        for kind in ('BEGIN', 'ARM', 'HEADERS', 'EOF', 'READ_END', 'FINALLY'):
            matches = [row for row in events if row['j'] == kind]
            need(len(matches) == 1)
            selected[kind] = matches[0]
        eof, end, final = selected['EOF'], selected['READ_END'], selected['FINALLY']
        need(end['k'] == 'EOF_OK' and end['f'] is True and type(eof['n']) is int
             and 0 < eof['n'] <= 1 << 20 and eof['n'] == end['n'])
        # Only original same-JS-stream order is used. JS/CDP clocks and their
        # interleaved arrival q values never establish cross-layer causality.
        need(eof['q'] < end['q'] < final['q'])
        network = [row for row in rows if row['e'] in ('NET_HEADERS', 'NET_FINISH')
                   and row['n'] == starts[key]['n']]
        headers = [row for row in network if row['e'] == 'NET_HEADERS']
        finishes = [row for row in network if row['e'] == 'NET_FINISH']
        # The original verifier already checks its per-network chain. This
        # supplementary gate adds no new inter-event arrival-order assumption.
        need(len(network) == 2 and len(headers) == len(finishes) == 1 and headers[0]['st'] == 200)
    return dict(anonymousStatusRequests=expected, uniqueRequestIdentities=len(begins), sends=len(sends),
                networkStarts=len(starts), normalNetworkFinishes=expected, normalJSONEOFs=expected,
                finallyRecords=expected, cancelRecords=0, cancellationResults=0, abortRecords=0,
                networkFailures=0, driverErrorCounters={key: driver[key] for key in COUNTERS})


def verify(evidence, repo, commit, engine, scratch_parent):
    validate_contract()
    need(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit)
         and engine in ('chrome-cdp', 'playwright'))
    before = input_snapshot(evidence)
    build = B.decoded(before['lab/browser/browser-build.json'], source_manifest=True)
    bindings, host = bind_sources(repo, commit, build)
    reports = replay_originals(evidence, repo, commit, engine, scratch_parent, before)
    browser, binding_report = reports['browser'], reports['binding']
    for report in (browser, binding_report):
        need(report['sourceCommit'] == commit and report['engine'] == engine
             and report['production'] is False and report['authorization'] == 'BLOCKED'
             and report['fixtureId'] == build['fixtureId'])
    need(browser['outcome'] == 'PASS' and browser['browserE2EProven'] is True
         and binding_report['requestIdentityBindingProven'] is True)
    binding = B.decoded(before['lab/request-binding.json'])
    driver = B.decoded(before['lab/browser/browser-driver.json'])
    facts = normal_eof_facts(binding, before['lab/status-diagnostic.json'], driver, commit, engine)
    for field in ('requests', 'sends', 'boundRequests'):
        need(type(binding_report[field]) is int and binding_report[field] == CONTRACT['anonymousStatusRequests'])
    for field in ('unboundAttempts', 'missingSends', 'openNetworks', 'missingFinally',
                  'missingCancellationResults', 'cancellationResults', 'networkFailures'):
        need(type(binding_report[field]) is int and binding_report[field] == 0)
    need(input_snapshot(evidence) == before)
    need(all(B.read_file(HOST_ROOT / name, CONTRACT['maxInputFileBytes']) == raw for name, raw in host.items()))
    return dict(schema=CONTRACT['verificationSchema'], sourceCommit=commit, engine=engine,
        fixtureId=build['fixtureId'], outcome='PASS', scope=CONTRACT['scope'], **facts,
        originalBrowserGateReplayed=True, originalRequestBindingGateReplayed=True,
        originalReportsByteEqual=True, oldDiagnosticSchemasModified=False,
        oldEightZeroErrorCountersRelaxed=False, requiredGitBlobsVerified=len(bindings), sourceBindings=bindings,
        originalBrowserReportSHA256=sha(before['browser-verification.json']),
        originalRequestBindingReportSHA256=sha(before['request-binding-verification.json']),
        evidenceSHA256={name: sha(raw) for name, raw in sorted(before.items())},
        contractSHA256=sha(CONTRACT_RAW), observationTrust=CONTRACT['observationTrust'],
        perRequestDTOSchemaProven=False, cancellationRootCauseProven=False, packetCausalityProven=False,
        independentBrowserInternalAttestationProven=False, longTermStabilityProven=False,
        production=False, authorization='BLOCKED')


def main():
    parser = argparse.ArgumentParser()
    for name in ('evidence-root', 'repo', 'report'):
        parser.add_argument('--' + name, required=True, type=pathlib.Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--engine', required=True, choices=('chrome-cdp', 'playwright'))
    args = parser.parse_args()
    need(not args.evidence_root.is_symlink() and not args.repo.is_symlink())
    evidence, repo = args.evidence_root.resolve(strict=True), args.repo.resolve(strict=True)
    report = args.report.absolute()
    need(not report.exists() and not report.is_symlink()
         and not report.resolve().is_relative_to(evidence) and not report.resolve().is_relative_to(repo))
    result = verify(evidence, repo, args.source_commit, args.engine, report.parent)
    with report.open('xb') as target:
        target.write(B.encoded(result) + b'\n')
    print('PROBE_EOF_CLEANUP=VERIFIED normal_json_eof_only=true cancellation_root_cause_proven=false production=false')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('PROBE_EOF_CLEANUP=REJECTED raw_input_suppressed=true') from None
