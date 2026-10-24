"""Independent passive sidecar identity/source verifier, never browser acceptance."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess

import check_probe_readback as B
import check_request_binding as RB
import status_network_lifecycle as D

SCOPE = 'PASSIVE_ANONYMOUS_STATUS_NETWORK_METADATA_NOT_BROWSER_ACCEPTANCE'
CONTRACT = 'chengwang/deploy/probe-readback/status-network-lifecycle-contract.json'
REQUIRED_COPIES = {CONTRACT, 'chengwang/deploy/probe-readback/status_network_lifecycle.py',
                   'chengwang/tools/probe-browser/status-network-lifecycle.mjs'}
REQUIRED_SOURCES = REQUIRED_COPIES | RB.REQUIRED_SOURCES | {
    'chengwang/deploy/probe-readback/run_probe_browser.py',
    'chengwang/deploy/probe-readback/check_probe_readback.py',
    'chengwang/deploy/probe-readback/check_status_network_lifecycle.py'}


def sha(raw): return hashlib.sha256(raw).hexdigest()


def checked_path(path):
    """Reject symlink components before resolve erases their identity."""
    path = pathlib.Path(path).absolute()
    D.need(not any(p.is_symlink() for p in (path, *path.parents)))
    return path


def host_helpers():
    base = 'chengwang/deploy/probe-readback/'
    return {base + 'check_status_network_lifecycle.py': pathlib.Path(__file__),
            base + 'status_network_lifecycle.py': pathlib.Path(D.__file__),
            base + 'check_request_binding.py': pathlib.Path(RB.__file__),
            base + 'probe_request_binding.py': pathlib.Path(RB.D.__file__),
            base + 'probe_status_diagnostics.py': pathlib.Path(RB.OLD.__file__),
            base + 'check_probe_readback.py': pathlib.Path(B.__file__),
            CONTRACT: pathlib.Path(D.__file__).resolve().parent / D.CONTRACT_NAME}


def verify(value, binding_raw, old_raw, build, commit, engine):
    D.exact(value, {'schema', 'observationalOnly', 'browserAcceptanceProven', 'cancellationRootCauseProven',
        'production', 'authorization', 'eventCount', 'rejectedLines', 'sinkClosed', 'complete', 'incompleteReasons',
        'records', 'sourceCommit', 'engine', 'fixtureId', 'bindingSHA256', 'clockDomains'})
    D.need(value['sourceCommit'] == commit and value['engine'] == engine and engine in {'chrome-cdp', 'playwright'}
           and type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit)
           and type(value['fixtureId']) is str and re.fullmatch('[a-f0-9]{32}', value['fixtureId'])
           and value['bindingSHA256'] == sha(binding_raw) and value['clockDomains'] == RB.CLOCKS)
    D.need(type(value['records']) is list and len(value['records']) <= D.MAX_ROWS)
    raw = b''.join(D.PREFIX.encode() + D.encoded(row) + b'\n' for row in value['records'])
    projected = D.project(raw)
    D.need(all(value[k] == v and type(value[k]) is type(v) for k, v in projected.items()))
    binding = B.decoded(binding_raw)
    identity = RB.verify(binding, old_raw, build, commit, engine)
    D.need(identity['requestIdentityBindingProven'] is True and value['fixtureId'] == binding['fixtureId'])
    sources = RB.build_sources(build, commit, engine, value['fixtureId'])
    copied = {r['path']: r for r in build['copiedInputs']}
    D.need(REQUIRED_SOURCES <= sources.keys() and REQUIRED_COPIES <= copied.keys())
    requests = [r for r in value['records'] if r['e'] == 'REQUEST']
    starts = [r for r in binding['records'] if r['e'] == 'NET_START']
    D.need(len(requests) == len(starts) == 7)
    for r, start in zip(requests, starts):
        D.need((r['n'], r['m'], r['r'], r['startUs']) == (start['n'], start['m'], start['r'], start['x']))
        events = [e for e in binding['records'] if e.get('n') == r['n'] and e['e'] in {'NET_HEADERS', 'NET_FINISH', 'NET_FAIL'}]
        headers = [e for e in events if e['e'] == 'NET_HEADERS']; ends = [e for e in events if e['e'] in {'NET_FINISH', 'NET_FAIL'}]
        D.need(len(headers) == len(ends) == 1 and r['response'] is not None)
        D.need((r['responseUs'], r['response']['status']) == (headers[0]['x'], headers[0]['st']))
        end = ends[0]; D.need(r['endUs'] == end['x'] and r['terminal'] == ('FINISHED' if end['e'] == 'NET_FINISH' else 'FAILED'))
        if end['e'] == 'NET_FAIL':
            canceled = 'NOT_OBSERVED' if end['canceled'] == 'UNKNOWN' else end['canceled']
            error = 'NOT_OBSERVED' if end['error'] == 'UNKNOWN' else end['error']
            D.need((r['canceled'], r['error']) == (canceled, error))
    return dict(schema='chengwang.status-network-lifecycle-verification/v1', sourceCommit=commit, engine=engine,
                fixtureId=value['fixtureId'], outcome='DIAGNOSTIC_COMPLETE' if value['complete'] else 'DIAGNOSTIC_INCOMPLETE',
                diagnosticComplete=value['complete'], scope=SCOPE, requests=len(requests),
                networkFailures=sum(r['terminal'] == 'FAILED' for r in requests), incompleteReasons=value['incompleteReasons'],
                oldSchemasModified=False, oldEightZeroErrorCountersRelaxed=False, browserAcceptanceProven=False,
                cancellationRootCauseProven=False, independentBrowserInternalAttestationProven=False,
                production=False, authorization='BLOCKED')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--evidence-root', required=True, type=pathlib.Path)
    p.add_argument('--source-commit', required=True)
    p.add_argument('--engine', required=True, choices=('chrome-cdp', 'playwright'))
    p.add_argument('--repo', required=True, type=pathlib.Path)
    p.add_argument('--report', required=True, type=pathlib.Path)
    a = p.parse_args(); root = checked_path(a.evidence_root).resolve(strict=True); repo = checked_path(a.repo).resolve(strict=True)
    report = checked_path(a.report).resolve()
    D.need(not report.is_relative_to(root) and not report.is_relative_to(repo))
    host_paths = {name: checked_path(path).resolve(strict=True) for name, path in host_helpers().items()}
    D.need(report not in host_paths.values())
    host_before = {name: B.read_file(path, 2 << 20) for name, path in host_paths.items()}
    paths = dict(sidecar=root/'status-network-lifecycle.json', binding=root/'lab/request-binding.json',
                 old=root/'lab/status-diagnostic.json', build=root/'lab/browser/browser-build.json')
    limits = dict(sidecar=D.MAX_BYTES + 16384, binding=540672, old=329728, build=2 << 20)
    raw = {k: B.read_file(checked_path(v), limits[k]) for k, v in paths.items()}
    value, build = D.decoded(raw['sidecar']), B.decoded(raw['build'], source_manifest=True)
    result = verify(value, raw['binding'], raw['old'], build, a.source_commit, a.engine)
    sources = {r['path']: r for r in build['sourceFilesBefore']}
    for name in sorted(REQUIRED_SOURCES):
        blob = subprocess.check_output(['git', '-C', str(repo), 'show', a.source_commit + ':' + name], stderr=subprocess.DEVNULL)
        D.need(len(blob) == sources[name]['bytes'] and sha(blob) == sources[name]['sha256'])
        if name in host_before: D.need(host_before[name] == blob)
        if name == CONTRACT:
            D.need(B.decoded(blob) == D.load_contract())
    D.need(all(B.read_file(paths[k], limits[k]) == v for k, v in raw.items()))
    D.need(all(B.read_file(host_paths[name], 2 << 20) == raw for name, raw in host_before.items()))
    result.update(requiredGitBlobsVerified=len(REQUIRED_SOURCES), hostHelpersMatchedGitAndStable=True,
                  actualHostHelperSHA256={k: sha(v) for k, v in host_before.items()},
                  originalSHA256={k: sha(v) for k, v in raw.items()})
    data = D.encoded(result) + b'\n'
    with report.open('xb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
    D.need(report.read_bytes() == data and result['diagnosticComplete'] is True)
    print('STATUS_NETWORK_LIFECYCLE=DIAGNOSTIC_COMPLETE browser_acceptance_proven=false root_cause_proven=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('STATUS_NETWORK_LIFECYCLE=REJECTED raw_input_suppressed=true') from None
