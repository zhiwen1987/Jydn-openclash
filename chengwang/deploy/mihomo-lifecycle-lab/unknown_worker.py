#!/usr/bin/env python3
"""Source-fixed UNKNOWN experiment exporter; importing starts no processes.

Only the existing namespace/custody and disclosure primitives are reused. No
normal-service report, dropped-response fixture or acceptance is fabricated.
CAPTURED means original bytes were exported, never independent acceptance.
"""
import importlib.util
import os
from pathlib import Path
import stat
import sys

ROOT = Path('/tmp/chengwang-mihomo-service-private')
IDENTITIES = Path('/tmp/chengwang-mihomo-service-identities')
STATE = Path('/tmp/chengwang-mihomo-service-state')
STAGES = ('bootstrap', 'op-01/create', 'op-01/pre-dispatch', 'op-01/post-dispatch')
CAPTURE = ('transcript.json', *(f'body-{i}.json' for i in range(1, 9)), 'verification.json')
SCOPE = 'ACTUAL_FIXED_KERNEL_UNKNOWN_OUTCOME_NO_RESEND_NOT_RECOVERY_OR_PRODUCTION'
TAGS = ('chengwang_mihomo_service', 'chengwang_mihomo_faults')
PACKAGES = ('./internal/adapter/mihomo', './internal/serverruntime')
TOPS = ('TestLabReloadFaultCapsuleModelBoundaries', 'TestMihomoServiceHTTPUnknownOutcomeBlocksReplayAndNewPlan')
FMT = ('internal/adapter/mihomo/lab_reload_fault_default.go',
       'internal/adapter/mihomo/lab_reload_fault_linux.go',
       'internal/adapter/mihomo/lab_reload_fault_unsupported.go',
       'internal/adapter/mihomo/lab_reload_fault_linux_test.go',
       'internal/mihomodeploy/lab_unknown_acceptance_linux.go',
       'internal/serverruntime/mihomo_unknown_e2e_linux_test.go',
       'internal/adapter/mihomo/write_client.go')
MAPPING = {stage.replace('/', '-')+'-'+name: stage+'/'+name for stage in STAGES for name in CAPTURE}
MAPPING.update({name: name for name in ('service-journal.jsonl', 'kernel.stdout', 'kernel.stderr')})
MAPPING.update({'op-01-'+name: 'op-01/'+name for name in ('syntax.json', 'syntax.stdout', 'syntax.stderr')})
MAPPING['unknown-report.json'] = 'unknown-report.private.json'
WORKER = ('sandbox.json', 'execution.json', 'go-version.txt', 'gofmt.patch',
          'gofmt.stderr', 'unknown.json', 'unknown.stderr')
PREEXISTING = ('host-before.json', 'host-after.json', 'consumption.json', 'consumption-independent.json')
PUBLIC = tuple(MAPPING) + WORKER + PREEXISTING
REPORT_KEYS = ('schema', 'scope', 'sourceCommit', 'outcome', 'failureCode', 'http', 'before',
               'after', 'replay', 'final', 'fault', 'callsBefore', 'callsAfter', 'callsReplay',
               'callsFinal', 'controllerReceivedCount', 'closedPorts', 'runtimeReturned',
               'runtimeErrorClass', 'production', 'fullPayloadProven', 'internetBusinessProven')
_SHARED = None
_STATE = None


def need(value):
    if not value:
        raise ValueError('isolated unknown experiment rejected')


def shared_service():
    global _SHARED
    if _SHARED is None:
        path = Path(__file__).absolute().with_name('service_worker.py')
        for item in (*reversed(path.parents), path):
            info = item.lstat()
            need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 1024)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 1 << 20)
        spec = importlib.util.spec_from_file_location('_unknown_fixed_service_primitives', path)
        need(spec is not None and spec.loader is not None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        need(module.ROOT == ROOT and module.IDENTITIES == IDENTITIES and module.STATE == STATE)
        _SHARED = module
    return _SHARED


def adapter():
    return shared_service().adapter()


def validate_contract(value):
    expected = dict(schema='chengwang.mihomo-unknown-experiment-contract/v1', scope=SCOPE,
                    tags=list(TAGS), goPackages=list(PACKAGES), topTests=list(TOPS),
                    goTimeoutSeconds=75, outerGoTimeoutSeconds=90,
                    privateRoot=ROOT.as_posix(), identityRoot=IDENTITIES.as_posix(), stateRoot=STATE.as_posix(),
                    captureStages=list(STAGES), captureFiles=list(CAPTURE), maxPublicBytes=16 << 20,
                    maxCaptureBodyBytes=256 << 10, maxVerificationBytes=64 << 10, production=False)
    # Canonical JSON distinguishes booleans from integer aliases.
    need(adapter().shared().canonical(value) == adapter().shared().canonical(expected))
    need(len(MAPPING) == 47 and len(PUBLIC) == len(set(PUBLIC)) == 58)
    return value


def contract():
    w = adapter().shared()
    raw, _ = w.file_bytes(Path(__file__).absolute().with_name('unknown_contract.json'), 64 << 10)
    return validate_contract(w.decode(raw))


def encoded_body(value, limit):
    return shared_service().encoded_body(value, limit)


def disclosure(raw, forbidden):
    return shared_service().disclosure(raw, forbidden)


def private_variants(values, configs, tls_key):
    return shared_service().private_variants(values, configs, tls_key)


def report_decoded_bodies(report):
    # UNKNOWN has no invented unobserved response; only actual HTTP originals.
    need(type(report) is dict and 'dropped' not in report and
         type(report.get('http')) is list and len(report['http']) <= 32)
    values = []
    for row in report['http']:
        need(type(row) is dict and 'requestBody' in row and 'responseBody' in row)
        values.extend(encoded_body(row[key], 16 << 10) for key in ('requestBody', 'responseBody'))
    return values


def decoded_header_values(transcript):
    need(type(transcript) is dict and type(transcript.get('records')) is list and len(transcript['records']) <= 8)
    values = []
    for record in transcript['records']:
        need(type(record) is dict and type(record.get('headers')) is dict)
        headers = record['headers']
        for key in ('contentTypeValuesB64', 'contentEncodingValuesB64', 'transferEncodingValuesB64'):
            need(type(headers.get(key)) is list and len(headers[key]) <= 16)
            for value in headers[key]:
                need(type(value) is str)
                values.append(encoded_body(value, 16 << 10))
    return values


def validate_report(report, commit):
    need(type(report) is dict and set(report) == set(REPORT_KEYS))
    need(report['schema'] == 'chengwang.mihomo-unknown-http-experiment/v1' and
         report['scope'] == SCOPE and report['sourceCommit'] == commit and
         type(report['outcome']) is str and report['outcome'] in ('PASS', 'FAIL') and
         type(report['failureCode']) is str and len(report['failureCode']) <= 128 and
         report['production'] is False and report['fullPayloadProven'] is False and
         report['internetBusinessProven'] is False and report['controllerReceivedCount'] is None)
    return report


def actual_observed(report):
    before = report.get('before')
    if type(before) is dict and type(before.get('observedProcessMatchesHead')) is bool:
        return before['observedProcessMatchesHead']
    return None


def private_outputs(commit):
    s = shared_service(); a = adapter(); w = a.shared()
    secret = w.decode(s.private_file(ROOT/'.secrets.private.json', 4096))
    need(type(secret) is dict and set(secret) == {'schema', 'controller', 'routeA', 'routeB'} and
         secret['schema'] == 'chengwang.mihomo-lab-service-private-secrets/v1')
    values = [secret[k] for k in ('controller', 'routeA', 'routeB')]
    need(all(type(v) is str and a.SECRET.fullmatch(v) for v in values) and len(set(values)) == 3)
    configs = [s.private_file(ROOT/name, 1 << 20) for name in ('local-a.config.private.yaml', 'local-b.config.private.yaml')]
    for raw in configs:
        raw.decode('utf-8', errors='strict')
        need(secret['controller'].encode('ascii') in raw)
    tokens = w.decode(s.private_file(IDENTITIES/'http-secrets.private.json', 16 << 10))
    need(type(tokens) is dict and set(tokens) == {'viewer', 'operator', 'approver', 'auditor', 'admin', 'foreign', 'wrong-scope'} and
         all(type(v) is str and 24 <= len(v) <= 4096 for v in tokens.values()))
    values += list(tokens.values())
    tls_key = s.private_file(IDENTITIES/'tls-key.private.pem', 16 << 10)
    forbidden = private_variants(values, configs, tls_key)
    outputs = {}
    for public, relative in MAPPING.items():
        limit = 64 << 10 if relative.endswith('/verification.json') else (
            256 << 10 if relative.endswith(('.json', '.jsonl')) else 1 << 20)
        if public == 'unknown-report.json':
            limit = 512 << 10
        raw = s.private_file(ROOT/relative, limit, empty=relative.endswith(('.stdout', '.stderr')))
        disclosure(raw, forbidden)
        outputs[public] = raw
    report = validate_report(w.decode(outputs['unknown-report.json']), commit)
    for raw in report_decoded_bodies(report):
        disclosure(raw, forbidden)
    for stage in STAGES:
        transcript = w.decode(outputs[stage.replace('/', '-')+'-transcript.json'])
        for raw in decoded_header_values(transcript):
            disclosure(raw, forbidden)
    need(sum(map(len, outputs.values())) <= 16 << 20)
    return outputs, forbidden, report


def go_arguments(c, go_root):
    return [go_root+'/bin/go', 'test', '-json', '-count=1', '-shuffle=off', '-p=1',
            '-tags='+','.join(TAGS), '-run=^('+'|'.join(TOPS)+')$',
            '-timeout='+str(c['goTimeoutSeconds'])+'s', *PACKAGES]


def execution(state):
    return dict(schema='chengwang.mihomo-unknown-execution/v1', sourceCommit=state['commit'],
                formatExit=state['formatExit'], goExit=state['goExit'],
                realMihomoExecutionObserved=state['observed'], production=False)


def failure():
    if _STATE is None:
        return
    try:
        a = adapter(); w = a.shared(); state = _STATE
        a.unchanged_public(state)
        for name, value in (('execution.json', execution(state)), ('worker-failure.json',
                dict(schema='chengwang.mihomo-unknown-worker-failure/v1', sourceCommit=state['commit'],
                     failureCode='WORKER_REJECTED_RAW_OUTPUT_SUPPRESSED', rawOutputSuppressed=True))):
            path = a.EXPORT_ALIAS/name
            if not path.exists() and not path.is_symlink():
                w.write_new(path, w.canonical(value), 0o644)
        a.sync_output(state)
    except Exception:
        return


def main(args):
    global _STATE
    c = contract(); a = adapter(); w = a.shared(); s = shared_service()
    if len(args) == 3 and args[0] == '--sandbox':
        facts = a.sandbox(args[1], args[2])
        s.bases(False)
        facts['schema'] = 'chengwang.mihomo-unknown-sandbox/v1'
        facts['serviceBases'] = [str(ROOT), str(IDENTITIES), str(STATE)]
        print(w.canonical(facts).decode('ascii'), end='')
        return 0
    need(len(args) == 5)
    state = a.prepare_namespace(*args); _STATE = state
    s.bases(True)
    worker = a.PATHS['module']+'/deploy/mihomo-lifecycle-lab/unknown_worker.py'
    code = a.capture(state, [w.tool('python3'), '-B', worker, '--sandbox', state['commit'], state['moduleSHA256']],
                     'sandbox.private.json', 'sandbox.private.stderr', 30)
    need(code == 0 and w.file_bytes(a.ROOT_PRIVATE/'sandbox.private.stderr', 4096, empty=True)[0] == b'')
    facts = w.decode(w.file_bytes(a.ROOT_PRIVATE/'sandbox.private.json', 64 << 10)[0])
    need(facts['schema'] == 'chengwang.mihomo-unknown-sandbox/v1' and facts['sourceCommit'] == state['commit'])
    code = a.capture(state, [a.PATHS['goRoot']+'/bin/go', 'version'], 'go-version.txt', 'go-version.private.stderr', 15)
    need(code == 0 and w.file_bytes(a.ROOT_PRIVATE/'go-version.private.stderr', 4096, empty=True)[0] == b'')
    state['formatExit'] = a.capture(state, [a.PATHS['goRoot']+'/bin/gofmt', '-d', *FMT],
                                    'gofmt.patch', 'gofmt.stderr', 30)
    # These names are the existing capture primitive's private GO_TEST slots,
    # not legacy results: this exact call runs the new two-package experiment.
    state['goExit'] = a.capture(state, go_arguments(c, a.PATHS['goRoot']),
                               'apply.json', 'apply.stderr', c['outerGoTimeoutSeconds'])
    after, _, directory = w.custody(state['consumed'])
    need(after == state['inputBefore'] and directory == state['originalDirectory'])
    facts['inputCustody'] = dict(before=state['inputBefore'], after=after)
    outputs, forbidden, report = private_outputs(state['commit'])
    state['observed'] = actual_observed(report)
    for public, original in (('go-version.txt', 'go-version.txt'), ('gofmt.patch', 'gofmt.patch'),
                            ('gofmt.stderr', 'gofmt.stderr'), ('unknown.json', 'apply.json'), ('unknown.stderr', 'apply.stderr')):
        raw = w.file_bytes(a.ROOT_PRIVATE/original, 8 << 20, empty=True)[0]
        disclosure(raw, forbidden)
        outputs[public] = raw
    outputs['sandbox.json'] = w.canonical(facts)
    outputs['execution.json'] = w.canonical(execution(state))
    need(set(outputs) == set(PUBLIC)-set(PREEXISTING) and sum(map(len, outputs.values())) <= 16 << 20)
    a.unchanged_public(state)
    for name, raw in outputs.items():
        w.write_new(a.EXPORT_ALIAS/name, raw, 0o644)
    a.sync_output(state); a.unchanged_public(state)
    need(not state['pending'])
    if state['formatExit'] != 0 or state['goExit'] != 0 or outputs['gofmt.patch'] or outputs['gofmt.stderr'] or report['outcome'] != 'PASS':
        return state['goExit'] if type(state['goExit']) is int and state['goExit'] > 0 else 1
    need({p.name for p in state['out'].iterdir()} == set(PUBLIC)-{'host-after.json'})
    print('MIHOMO_UNKNOWN_WORKER=CAPTURED independent_verification=pending production=false')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception:
        failure()
        raise SystemExit('MIHOMO_UNKNOWN_WORKER=REJECTED raw_output_suppressed=true') from None
