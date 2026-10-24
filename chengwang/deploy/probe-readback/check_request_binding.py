"""Independent anonymous request-identity observation verifier.

This does not infer cancellation causes, attest on-wire headers, relax any
browser error counter, or prove browser acceptance. Clock domains stay separate.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

import check_probe_readback as B
import probe_request_binding as D
import probe_status_diagnostics as OLD

CLOCKS = 'JS_MOUNT_MS_CDP_MONOTONIC_US_CDP_EPOCH_US_NOT_INTERCHANGEABLE'
SCOPE = 'CI_ANONYMOUS_REQUEST_IDENTITY_OBSERVATIONS_NOT_CANCELLATION_ROOT_CAUSE'
REQUIRED_COPIES = {
    'chengwang/tools/probe-browser/probe-request-binding.mjs',
    'chengwang/deploy/probe-readback/probe_request_binding.py',
    'chengwang/deploy/probe-readback/request-binding-contract.json',
}
REQUIRED_SOURCES = REQUIRED_COPIES | {
    'chengwang/deploy/probe-readback/check_request_binding.py',
    'chengwang/tools/probe-browser/browser-driver.mjs',
    'chengwang/web/src/probe-api.ts',
    'chengwang/web/src/probe-status-observation.ts',
    'chengwang/web/src/probe-request-binding.ts',
    'chengwang/deploy/probe-readback/probe_status_diagnostics.py',
    'chengwang/tools/probe-browser/probe-status-diagnostics.mjs',
}
OUTER = {'schema', 'observationalOnly', 'browserAcceptanceProven', 'cancellationRootCauseProven',
         'eventCount', 'rejectedLines', 'sinkClosed', 'complete', 'records', 'sourceCommit', 'engine',
         'fixtureId', 'oldDiagnosticSHA256', 'clockDomains'}


def exact(value, fields): D.need(type(value) is dict and set(value) == fields)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def same(a, b): return json.dumps(a, sort_keys=True, separators=(',', ':')) == json.dumps(b, sort_keys=True, separators=(',', ':'))


def check_envelope(value, old_raw, commit, engine):
    D.need(type(commit) is str and re.fullmatch(r'[a-f0-9]{40}', commit))
    D.choice(engine, {'chrome-cdp', 'playwright'}); exact(value, OUTER)
    D.need(value['schema'] == 'chengwang.probe-request-binding/v1' and value['sourceCommit'] == commit
           and value['engine'] == engine and value['clockDomains'] == CLOCKS)
    D.need(type(value['fixtureId']) is str and re.fullmatch(r'[a-f0-9]{32}', value['fixtureId']))
    D.need(value['observationalOnly'] is True and value['browserAcceptanceProven'] is False
           and value['cancellationRootCauseProven'] is False)
    D.need(type(old_raw) is bytes and 0 < len(old_raw) <= OLD.MAX_LOG_BYTES
           and value['oldDiagnosticSHA256'] == sha(old_raw))
    D.integer(value['eventCount'], 0, D.MAX_ROWS); D.integer(value['rejectedLines'], 0, D.MAX_BYTES)
    D.need(type(value['sinkClosed']) is bool and type(value['complete']) is bool)
    D.need(type(value['records']) is list and len(value['records']) == value['eventCount'])
    raw = b'\n'.join((D.PREFIX + json.dumps(row, separators=(',', ':'), ensure_ascii=True)).encode('ascii')
                     for row in value['records'])
    # Decode every closed row, but independently recalculate all summaries here.
    rows = [D.decode_line(line) for line in raw.splitlines()]
    D.need(all(row['q'] == i + 1 for i, row in enumerate(rows)))
    metas = [row for row in rows if row['e'] == 'META']
    D.need(len(metas) <= 1 and (not metas or rows[-1] is metas[0]))
    closed = bool(metas); D.need(value['sinkClosed'] is closed)
    meta = metas[0] if metas else None
    counts = {name: sum(row['e'] == event for row in rows) for name, event in D.COUNT_EVENTS.items()}
    counts['docs'] = len({row['d'] for row in rows if 'd' in row})
    complete = bool(meta and not value['rejectedLines'] and not meta['rejected'] and not meta['overflow']
                    and counts['js'] + counts['sends'] + counts['results'] <= 256
                    and all(meta[name] == count for name, count in counts.items()))
    D.need(value['complete'] is complete)
    return rows, complete


def old_observations(raw, commit, engine):
    old = B.decoded(raw)
    exact(old, {'schema', 'observationalOnly', 'browserAcceptanceProven', 'causalRequestBindingProven',
                'eventCount', 'rejectedLines', 'sinkClosed', 'complete', 'records', 'sourceCommit', 'engine', 'clockDomains'})
    D.need(old['schema'] == 'chengwang.probe-status-diagnostic/v1' and old['sourceCommit'] == commit
           and old['engine'] == engine and old['clockDomains'] == CLOCKS)
    D.need(old['observationalOnly'] is True and old['browserAcceptanceProven'] is False
           and old['causalRequestBindingProven'] is False)
    D.integer(old['eventCount'], 0, OLD.MAX_ROWS); D.integer(old['rejectedLines'], 0, OLD.MAX_LOG_BYTES)
    D.need(type(old['sinkClosed']) is bool and type(old['complete']) is bool
           and type(old['records']) is list and len(old['records']) == old['eventCount'])
    records = []
    for row in old['records']:
        # OLD decoder is frozen and provides the exact original closed DTO.
        data = (OLD.PREFIX + json.dumps(row, separators=(',', ':'), ensure_ascii=True)).encode('ascii')
        records.append(OLD.decode_line(data))
    D.need(all(row['q'] == i + 1 for i, row in enumerate(records)))
    metas = [row for row in records if row['e'] == 'META']
    D.need(len(metas) <= 1 and (not metas or records[-1] is metas[0]))
    D.need(old['sinkClosed'] is bool(metas))
    meta = metas[0] if metas else None
    complete = bool(meta and not old['rejectedLines'] and not meta['rej'] and not meta['over']
                    and meta['js'] == sum(r['e'] == 'JS' for r in records)
                    and meta['net'] == sum(r['e'] == 'NET_START' for r in records))
    D.need(old['complete'] is complete)
    return records, complete


def build_sources(build, commit, engine, fixture):
    exact(build, {'schema', 'sourceCommit', 'fixtureId', 'engine', 'copiedInputs', 'sourceFilesBefore',
                  'sourceFilesAfter', 'hostBefore', 'hostAfter', 'buildScope', 'backendSupervisorMode', 'production'})
    D.need(build['schema'] == 'chengwang.probe-browser-build/v1' and build['sourceCommit'] == commit
           and build['engine'] == engine and build['fixtureId'] == fixture and build['production'] is False
           and build['buildScope'] == 'TRUSTED_CI_INPUTS_NOT_INDEPENDENT_REBUILD'
           and build['backendSupervisorMode'] == 'WRAPPER_IMPORTS_NATIVE_HELPERS')
    D.need(same(build['sourceFilesBefore'], build['sourceFilesAfter']) and same(build['hostBefore'], build['hostAfter']))
    maps = []
    for field in ('sourceFilesBefore', 'copiedInputs'):
        rows = build[field]; D.need(type(rows) is list and 1 <= len(rows) <= 8192)
        mapped = {}
        for row in rows:
            exact(row, {'path', 'bytes', 'sha256'}); name = row['path']
            D.need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./@+-]+', name)
                   and all(p not in {'', '.', '..'} for p in name.split('/')) and name not in mapped)
            D.integer(row['bytes'], 1, 512 << 20)
            D.need(type(row['sha256']) is str and re.fullmatch(r'[a-f0-9]{64}', row['sha256']))
            mapped[name] = row
        maps.append(mapped)
    sources, copies = maps
    D.need(REQUIRED_SOURCES <= sources.keys() and REQUIRED_COPIES <= copies.keys())
    for name, row in copies.items():
        if name.startswith('chengwang/'):
            D.need(name in sources and same(row, sources[name]))
    return sources


def reconstruct(rows, old_rows):
    """Rebuild per-layer state and join by anonymous identities, not proximity."""
    sessions = [r for r in rows if r['e'] == 'SESSION']
    docs = [r for r in rows if r['e'] == 'DOCUMENT']
    contexts = [r for r in rows if r['e'] == 'CONTEXT']
    D.need(len(sessions) == len(docs) == len(contexts) == 1 and rows[0]['e'] == 'SESSION')
    doc, context = docs[0], contexts[0]
    D.need(sessions[0]['q'] < doc['q'] < context['q'] and context['default'] is True and context['h'] == doc['h'])
    mounts, begins, sends, results, networks = {}, {}, {}, {}, {}
    js, old_js = [], []
    last_t = {}
    for row in rows:
        event = row['e']
        if event in {'JS', 'SEND', 'CANCEL_RESULT'}:
            D.need(row['c'] == context['c'] and row['q'] > context['q'])
            m, r = row['m'], row['r']; key = (m, r)
            D.need(row['t'] >= last_t.get(m, 0)); last_t[m] = row['t']
            if event == 'JS':
                js.append(row)
                if row['j'] == 'MOUNT':
                    D.need(m not in mounts); mounts[m] = row
                else: D.need(m in mounts)
                if row['j'] == 'BEGIN':
                    D.need(key not in begins); begins[key] = row
                elif row['j'] not in {'MOUNT', 'CLEANUP'}: D.need(key in begins)
            else:
                D.need(key in begins and row['q'] > begins[key]['q'])
                D.need(row['d'] == 1)
                target = sends if event == 'SEND' else results
                D.need(key not in target); target[key] = row
                if event == 'CANCEL_RESULT': D.need(key in sends)
        elif event == 'NET_START':
            D.need(row['n'] not in networks and row['h'] == doc['h'] and row['d'] == 1 and row['q'] > doc['q'])
            networks[row['n']] = [row]
        elif event in {'NET_HEADERS', 'NET_FINISH', 'NET_FAIL'}:
            D.need(row['n'] in networks); chain = networks[row['n']]
            D.need(chain[-1]['e'] not in {'NET_FINISH', 'NET_FAIL'} and row['x'] >= chain[0]['x'])
            if event == 'NET_HEADERS': D.need(len(chain) == 1)
            chain.append(row)
    D.need(mounts and begins)
    # The old and new collectors independently saw the same original JS stream.
    for row in old_rows:
        if row['e'] == 'JS': old_js.append({k: v for k, v in row.items() if k not in {'v', 'e', 'q', 'u'}})
    new_js = []
    for row in js:
        public = {k: v for k, v in row.items() if k not in {'v', 'e', 'q', 's', 'c'}}
        if 'cause' in public: public['c'] = public.pop('cause')
        new_js.append(public)
    D.need(same(new_js, old_js))
    old_docs = [r for r in old_rows if r['e'] == 'DOCUMENT']
    D.need(len(old_docs) == 1)
    old_networks = {}
    for row in old_rows:
        if row['e'] == 'NET_START':
            D.need(row['s'] not in old_networks and row['h'] == old_docs[0]['h'])
            old_networks[row['s']] = [row]
        elif row['e'] in {'NET_HEADERS', 'NET_FINISH', 'NET_FAIL'}:
            D.need(row['s'] in old_networks); chain = old_networks[row['s']]
            D.need(chain[-1]['e'] not in {'NET_FINISH', 'NET_FAIL'} and row['x'] >= chain[0]['x'])
            if row['e'] == 'NET_HEADERS': D.need(len(chain) == 1)
            chain.append(row)
    # x/w identify identical original CDP starts, not a causal timing heuristic.
    old_by_start = {(c[0]['x'], c[0]['w']): c for c in old_networks.values()}
    D.need(len(old_by_start) == len(old_networks) == len(networks))
    bound, open_networks, failures, used_start = {}, 0, 0, set()
    for chain in networks.values():
        first = chain[0]; pair = (first['x'], first['w']); key = (first['m'], first['r'])
        D.need(pair in old_by_start and pair not in used_start and key not in bound)
        used_start.add(pair); bound[key] = first
        def normalized(c, old=False):
            out = []
            for item in c[1:]:
                v = {k: v for k, v in item.items() if k not in {'v', 'q', 's', 'n'}}
                if old and v['e'] == 'NET_FAIL': v['canceled'] = v.pop('c'); v['error'] = v.pop('ec')
                out.append(v)
            return out
        D.need(same(normalized(chain), normalized(old_by_start[pair], True)))
        open_networks += chain[-1]['e'] not in {'NET_FINISH', 'NET_FAIL'}
        failures += chain[-1]['e'] == 'NET_FAIL'
    # Missing networks are explicit unbound attempts; never invent starts.
    D.need(set(bound) <= begins.keys() and set(bound) <= sends.keys())
    D.need(set(sends) <= begins.keys())
    missing_sends = len(set(begins) - sends.keys())
    unbound = len(set(begins) - bound.keys())
    missing_finally, missing_results = 0, 0
    for key, begin in begins.items():
        events = [r for r in js if (r['m'], r['r']) == key]
        finals = [r for r in events if r['j'] == 'FINALLY']
        D.need(len(finals) <= 1)
        missing_finally += not finals
        if key in sends: D.need(not finals or sends[key]['q'] < finals[0]['q'])
        cancellations = [r for r in events if r['j'] == 'CANCEL']
        D.need(len(cancellations) in {0, 2})
        if cancellations:
            before, after = cancellations
            D.need(before['p'] == 'BEFORE' and after['p'] == 'AFTER' and before['q'] < after['q'])
            if key in results: D.need(results[key]['q'] > before['q'])
            else: missing_results += 1
        else: D.need(key not in results)
        aborts = [r for r in events if r['j'] == 'ABORT']
        D.need(len(aborts) in {0, 2})
        if aborts: D.need(aborts[0]['p'] == 'BEFORE' and aborts[1]['p'] == 'AFTER'
                         and aborts[0]['cause'] == aborts[1]['cause'])
    complete = not (missing_sends or unbound or open_networks or missing_finally or missing_results)
    return dict(requests=len(begins), sends=len(sends), boundRequests=len(bound), unboundAttempts=unbound,
                missingSends=missing_sends, openNetworks=open_networks, missingFinally=missing_finally,
                missingCancellationResults=missing_results, cancellationResults=len(results),
                networkFailures=failures, identityComplete=bool(complete))


def verify(value, old_raw, build, commit, engine):
    rows, complete = check_envelope(value, old_raw, commit, engine)
    old_rows, old_complete = old_observations(old_raw, commit, engine)
    sources = build_sources(build, commit, engine, value['fixtureId'])
    facts = reconstruct(rows, old_rows)
    proven = bool(complete and old_complete and facts['identityComplete'])
    return dict(schema='chengwang.probe-request-binding-verification/v1', sourceCommit=commit, engine=engine,
                fixtureId=value['fixtureId'], observationScope=SCOPE,
                outcome='IDENTITY_OBSERVATIONS_COMPLETE' if proven else 'IDENTITY_OBSERVATIONS_INCOMPLETE',
                requestIdentityBindingProven=proven, clockDomains=CLOCKS,
                rawOnWireHeaderAttestationProven=False, browserAcceptanceProven=False,
                cancellationRootCauseProven=False, production=False, authorization='BLOCKED',
                originalDiagnosticSHA256=sha(old_raw), records=len(rows), **facts,
                requiredCopiedHelpers=sorted(REQUIRED_COPIES), requiredSourceFiles=sorted(REQUIRED_SOURCES))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence-root', required=True, type=pathlib.Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--engine', required=True, choices=('chrome-cdp', 'playwright'))
    parser.add_argument('--repo', required=True, type=pathlib.Path)
    parser.add_argument('--report', required=True, type=pathlib.Path)
    args = parser.parse_args()
    root = args.evidence_root.resolve(strict=True); repo = args.repo.resolve(strict=True); report = args.report.resolve()
    D.need(not report.is_relative_to(root) and not report.is_relative_to(repo))
    paths = {'binding': root / 'request-binding.json', 'old': root / 'status-diagnostic.json',
             'build': root / 'browser/browser-build.json'}
    raw = {k: B.read_file(p, D.MAX_BYTES + 16384 if k == 'binding' else OLD.MAX_LOG_BYTES if k == 'old' else 2 << 20)
           for k, p in paths.items()}
    value, build = B.decoded(raw['binding']), B.decoded(raw['build'], source_manifest=True)
    result = verify(value, raw['old'], build, args.source_commit, args.engine)
    sources = {row['path']: row for row in build['sourceFilesBefore']}
    for name in sorted(REQUIRED_SOURCES):
        blob = subprocess.check_output(['git', '-C', str(repo), 'show', args.source_commit + ':' + name], stderr=subprocess.DEVNULL)
        D.need(len(blob) == sources[name]['bytes'] and sha(blob) == sources[name]['sha256'])
        if name.endswith('/request-binding-contract.json'):
            contract = B.decoded(blob)
            D.need(contract.get('schema') == 'chengwang.probe-request-binding-contract/v1'
                   and contract.get('jsAbortCauseField') == 'cause' and contract.get('clocks') == CLOCKS
                   and contract.get('publicSchema') == value['schema'] and contract.get('scope') == SCOPE)
    result.update(requiredGitBlobsVerified=len(REQUIRED_SOURCES), originalBindingSHA256=sha(raw['binding']),
                  originalBuildSHA256=sha(raw['build']))
    D.need(all(B.read_file(paths[k], max(len(v), 1)) == v for k, v in raw.items()))
    with report.open('xb') as out: out.write((json.dumps(result, separators=(',', ':')) + '\n').encode())
    D.need(result['requestIdentityBindingProven'])
    print('PROBE_REQUEST_BINDING=VERIFIED browser_acceptance_proven=false cancellation_root_cause_proven=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('PROBE_REQUEST_BINDING=REJECTED raw_input_suppressed=true') from None
