"""Verify a separate status diagnostic artifact, not browser acceptance/causality."""
import argparse
import json
import pathlib
import re
import subprocess

import check_probe_readback as backend
import probe_status_diagnostics as D

CLOCKS = 'JS_MOUNT_MS_CDP_MONOTONIC_US_CDP_EPOCH_US_NOT_INTERCHANGEABLE'
REQUIRED_COPIES = {
    'chengwang/deploy/probe-readback/probe_status_diagnostics.py',
    'chengwang/tools/probe-browser/probe-status-diagnostics.mjs',
}


def verify(value, build, commit, engine):
    D.need(type(commit) is str and re.fullmatch(r'[a-f0-9]{40}', commit))
    D.need(engine in {'chrome-cdp', 'playwright'})
    D.need(type(value) is dict and set(value) == {
        'schema', 'observationalOnly', 'browserAcceptanceProven', 'causalRequestBindingProven',
        'eventCount', 'rejectedLines', 'sinkClosed', 'complete', 'records', 'sourceCommit', 'engine', 'clockDomains'})
    D.need(value['schema'] == 'chengwang.probe-status-diagnostic/v1'
           and value['sourceCommit'] == commit and value['engine'] == engine and value['clockDomains'] == CLOCKS)
    D.need(value['observationalOnly'] is True and value['browserAcceptanceProven'] is False
           and value['causalRequestBindingProven'] is False)
    D.integer(value['eventCount'], 1, D.MAX_ROWS); D.integer(value['rejectedLines'], 0, D.MAX_LOG_BYTES)
    D.need(type(value['sinkClosed']) is bool and type(value['complete']) is bool)
    D.need(type(value['records']) is list and len(value['records']) == value['eventCount'])
    raw = b'\n'.join((D.PREFIX + json.dumps(row, separators=(',', ':'), ensure_ascii=True)).encode('ascii') for row in value['records'])
    reparsed = D.project(raw)
    D.need(reparsed['records'] == value['records'] and reparsed['eventCount'] == value['eventCount']
           and reparsed['sinkClosed'] == value['sinkClosed'])
    D.need(value['complete'] is bool(reparsed['complete'] and value['rejectedLines'] == 0))
    D.need(type(build) is dict and build.get('sourceCommit') == commit and build.get('engine') == engine
           and build.get('production') is False)
    before, after, copies = build.get('sourceFilesBefore'), build.get('sourceFilesAfter'), build.get('copiedInputs')
    D.need(type(before) is list and type(after) is list and before == after and type(copies) is list)
    D.need(all(type(row) is dict and type(row.get('path')) is str for row in before + copies))
    source = {row['path']: row for row in before}; inputs = {row['path']: row for row in copies}
    D.need(len(source) == len(before) and len(inputs) == len(copies) and REQUIRED_COPIES <= inputs.keys())
    for name in REQUIRED_COPIES:
        D.need(name in source and set(inputs[name]) == {'path', 'bytes', 'sha256'})
        D.integer(inputs[name]['bytes'], 1, 1 << 20)
        D.need(type(inputs[name]['sha256']) is str and re.fullmatch(r'[a-f0-9]{64}', inputs[name]['sha256']))
        D.need(source[name]['bytes'] == inputs[name]['bytes'] and source[name]['sha256'] == inputs[name]['sha256'])
    records = value['records']
    js = [row for row in records if row['e'] == 'JS']
    D.need(js and any(row['j'] == 'MOUNT' for row in js) and any(row['j'] == 'BEGIN' for row in js))
    D.need(any(row['e'] == 'NET_START' for row in records))
    return dict(schema='chengwang.probe-status-diagnostic-verification/v1', sourceCommit=commit, engine=engine,
        observationScope='CLOSED_LIFECYCLE_AND_NETWORK_RECORDS_NOT_CAUSAL_PROOF',
        outcome='OBSERVATIONS_COMPLETE' if value['complete'] else 'OBSERVATIONS_INCOMPLETE',
        records=len(records), jsRecords=len(js), networkStarts=sum(row['e'] == 'NET_START' for row in records),
        networkFailures=sum(row['e'] == 'NET_FAIL' for row in records),
        abortRecords=sum(row['j'] == 'ABORT' for row in js),
        requiredCopiedHelpers=sorted(REQUIRED_COPIES),
        browserAcceptanceProven=False, causalRequestBindingProven=False, production=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence-root', required=True, type=pathlib.Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--engine', required=True, choices=('chrome-cdp', 'playwright'))
    parser.add_argument('--report', required=True, type=pathlib.Path)
    args = parser.parse_args()
    root = args.evidence_root.resolve(strict=True); report = args.report.resolve()
    D.need(not report.is_relative_to(root))
    value_raw = backend.read_file(root / 'status-diagnostic.json', D.MAX_LOG_BYTES)
    build_raw = backend.read_file(root / 'browser/browser-build.json', 2 << 20)
    value, build = backend.decoded(value_raw), backend.decoded(build_raw, source_manifest=True)
    result = verify(value, build, args.source_commit, args.engine)
    copies = {row['path']: row for row in build['copiedInputs']}
    for name in REQUIRED_COPIES:
        original = subprocess.check_output(['git', 'show', args.source_commit + ':' + name], stderr=subprocess.DEVNULL)
        D.need(len(original) == copies[name]['bytes'] and backend.sha(original) == copies[name]['sha256'])
    result['requiredGitBlobsVerified'] = len(REQUIRED_COPIES)
    result.update(originalDiagnosticSHA256=backend.sha(value_raw), originalBuildSHA256=backend.sha(build_raw))
    with report.open('xb') as output:
        output.write((json.dumps(result, separators=(',', ':')) + '\n').encode())
    D.need(result['outcome'] == 'OBSERVATIONS_COMPLETE')
    print('PROBE_STATUS_DIAGNOSTIC=VERIFIED browser_acceptance_proven=false causal_binding_proven=false')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('PROBE_STATUS_DIAGNOSTIC=REJECTED raw_input_suppressed=true') from None
