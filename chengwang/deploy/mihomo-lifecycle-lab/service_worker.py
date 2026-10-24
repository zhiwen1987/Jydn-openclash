#!/usr/bin/env python3
"""Actual isolated product HTTP experiment producer; import starts nothing.

The existing apply worker provides source-fixed namespace/custody/pidfd capture
primitives only. Its apply acceptance/report is never reused or relabelled.
Public originals are copies of actual private bytes, after a disclosure fence;
independent check_service.py alone may accept their semantics.
"""
import base64
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
SCOPE = 'ACTUAL_ISOLATED_PRODUCT_HTTP_AND_LOCAL_POSTCONDITION_NOT_FULL_SYSTEM_OR_PRODUCTION'
TOP = 'TestMihomoServiceHTTPApprovalReloadReadbackAndReplay'
TAG = 'chengwang_mihomo_service'
FMT = ('internal/adapter/mihomo/write_client.go',
       'internal/mihomodeploy/lab_service_acceptance_linux.go',
       'internal/serverruntime/mihomo_lab_runtime.go',
       'internal/serverruntime/mihomo_lab_config_test.go',
       'internal/serverruntime/mihomo_service_e2e_linux_test.go')
MAPPING = {stage.replace('/', '-')+'-'+name: (stage+'/'+name)
           for stage in STAGES for name in CAPTURE}
MAPPING.update({name: name for name in ('service-journal.jsonl', 'kernel.stdout', 'kernel.stderr')})
MAPPING.update({'op-01-'+name: 'op-01/'+name
                for name in ('syntax.json', 'syntax.stdout', 'syntax.stderr')})
MAPPING['e2e-report.json'] = 'e2e-report.private.json'
WORKER = ('sandbox.json', 'execution.json', 'go-version.txt', 'gofmt.patch',
          'gofmt.stderr', 'service.json', 'service.stderr')
PREEXISTING = ('host-before.json', 'host-after.json', 'consumption.json', 'consumption-independent.json')
PUBLIC = tuple(MAPPING) + WORKER + PREEXISTING
_ADAPTER = None
_STATE = None


def need(value):
    if not value:
        raise ValueError('isolated service experiment rejected')


def adapter():
    global _ADAPTER
    if _ADAPTER is None:
        path = Path(__file__).absolute().with_name('apply_worker.py')
        for item in (*reversed(path.parents), path):
            info = item.lstat()
            need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 1024)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 1 << 20)
        spec = importlib.util.spec_from_file_location('_service_fixed_envelope', path)
        need(spec is not None and spec.loader is not None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _ADAPTER = module
    return _ADAPTER


def contract():
    a = adapter(); w = a.shared()
    raw, _ = w.file_bytes(Path(__file__).absolute().with_name('service_contract.json'), 64 << 10)
    value = w.decode(raw)
    expected = dict(schema='chengwang.mihomo-service-experiment-contract/v1', scope=SCOPE,
                    tag=TAG, goPackage='./internal/serverruntime', topTest=TOP,
                    goTimeoutSeconds=75, outerGoTimeoutSeconds=90,
                    privateRoot=str(ROOT), identityRoot=str(IDENTITIES), stateRoot=str(STATE),
                    captureStages=list(STAGES), captureFiles=list(CAPTURE), maxPublicBytes=16 << 20,
                    maxCaptureBodyBytes=256 << 10, maxVerificationBytes=64 << 10, production=False)
    need(w.canonical(value) == w.canonical(expected) and len(PUBLIC) == len(set(PUBLIC)) == 58)
    return value


def bases(create):
    for path in (ROOT, IDENTITIES, STATE):
        if create:
            path.mkdir(mode=0o700)
            os.chown(path, 10001, 10001)
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
             info.st_uid == info.st_gid == 10001 and not any(path.iterdir()))
    if create:
        fd = os.open('/tmp', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def private_file(path, limit, empty=False):
    a = adapter()
    raw, info = a.shared().file_bytes(path, limit, 0o600, empty=empty)
    need(info.st_uid == info.st_gid == 10001)
    return raw


def encoded_body(value, limit):
    # []byte is base64 in Go JSON. Searching the outer JSON is insufficient:
    # the secret's base64 need not align with base64(JSON containing secret).
    if value is None:
        return b''
    need(type(value) is str and len(value) <= ((limit+2)//3)*4)
    raw = base64.b64decode(value, validate=True)
    need(len(raw) <= limit and base64.b64encode(raw).decode('ascii') == value)
    return raw


def disclosure(raw, forbidden):
    need(type(raw) is bytes and not any(value in raw for value in forbidden))


def private_variants(values, configs, tls_key):
    need(type(tls_key) is bytes and b'-----BEGIN PRIVATE KEY-----' in tls_key and
         b'-----END PRIVATE KEY-----' in tls_key)
    forbidden = adapter().safe_variants([v.encode('utf-8') for v in values], [*configs, tls_key])
    forbidden.update((b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN EC PRIVATE KEY-----',
                      b'-----BEGIN RSA PRIVATE KEY-----', b'-----BEGIN OPENSSH PRIVATE KEY-----'))
    return forbidden


def report_decoded_bodies(report):
    need(type(report) is dict and type(report.get('http')) is list and len(report['http']) <= 32)
    values = []
    for row in report['http']:
        need(type(row) is dict)
        values.extend(encoded_body(row[key], 16 << 10) for key in ('requestBody', 'responseBody'))
    need(type(report.get('dropped')) is dict)
    values.append(encoded_body(report['dropped']['generatedBody'], 16 << 10))
    return values


def private_outputs(commit):
    a = adapter(); w = a.shared()
    secret = w.decode(private_file(ROOT/'.secrets.private.json', 4096))
    need(type(secret) is dict and set(secret) == {'schema', 'controller', 'routeA', 'routeB'} and
         secret['schema'] == 'chengwang.mihomo-lab-service-private-secrets/v1')
    values = [secret[k] for k in ('controller', 'routeA', 'routeB')]
    need(all(type(v) is str and a.SECRET.fullmatch(v) for v in values) and len(set(values)) == 3)
    configs = [private_file(ROOT/name, 1 << 20)
               for name in ('local-a.config.private.yaml', 'local-b.config.private.yaml')]
    for raw in configs:
        raw.decode('utf-8', errors='strict')
        need(secret['controller'].encode('ascii') in raw)
    tokens = w.decode(private_file(IDENTITIES/'http-secrets.private.json', 16 << 10))
    need(type(tokens) is dict and set(tokens) == {'viewer','operator','approver','auditor','admin','foreign','wrong-scope'} and
         all(type(v) is str and 24 <= len(v) <= 4096 for v in tokens.values()))
    values += list(tokens.values())
    tls_key = private_file(IDENTITIES/'tls-key.private.pem', 16 << 10)
    forbidden = private_variants(values, configs, tls_key)
    outputs = {}
    for public, relative in MAPPING.items():
        limit = 64 << 10 if relative.endswith('/verification.json') else (
            256 << 10 if relative.endswith(('.json', '.jsonl')) else 1 << 20)
        if public == 'e2e-report.json':
            limit = 512 << 10
        raw = private_file(ROOT/relative, limit, empty=relative.endswith(('.stdout','.stderr')))
        disclosure(raw, forbidden)
        outputs[public] = raw
    report = w.decode(outputs['e2e-report.json'])
    need(report['schema'] == 'chengwang.mihomo-service-http-experiment/v1' and
         report['scope'] == SCOPE and report['sourceCommit'] == commit and
         report['production'] is False and report['fullPayloadProven'] is False and
         report['internetBusinessProven'] is False)
    for raw in report_decoded_bodies(report):
        disclosure(raw, forbidden)
    # Transcripts have base64-selected header values too. Inspect their decoded
    # bytes without replacing the original transcript or accepting its facts.
    for stage in STAGES:
        transcript = w.decode(outputs[stage.replace('/', '-')+'-transcript.json'])
        need(type(transcript) is dict and type(transcript.get('records')) is list)
        for entry in transcript['records']:
            headers = entry.get('headers')
            need(type(headers) is dict)
            for key in ('contentTypeValuesB64', 'contentEncodingValuesB64', 'transferEncodingValuesB64'):
                need(type(headers.get(key)) is list and len(headers[key]) <= 16)
                for encoded in headers[key]:
                    disclosure(encoded_body(encoded, 16 << 10), forbidden)
    need(sum(map(len, outputs.values())) <= 16 << 20)
    return outputs, forbidden, report


def execution(state):
    return dict(schema='chengwang.mihomo-service-execution/v1', sourceCommit=state['commit'],
                formatExit=state['formatExit'], goExit=state['goExit'],
                realMihomoExecutionObserved=state['observed'], production=False)


def failure():
    if _STATE is None:
        return
    try:
        a = adapter(); w = a.shared(); state = _STATE
        a.unchanged_public(state)
        for name, value in (('execution.json', execution(state)), ('worker-failure.json',
                dict(schema='chengwang.mihomo-service-worker-failure/v1', sourceCommit=state['commit'],
                     failureCode='WORKER_REJECTED_RAW_OUTPUT_SUPPRESSED', rawOutputSuppressed=True))):
            path = a.EXPORT_ALIAS/name
            if not path.exists() and not path.is_symlink():
                w.write_new(path, w.canonical(value), 0o644)
        a.sync_output(state)
    except Exception:
        return


def main(args):
    global _STATE
    c = contract(); a = adapter(); w = a.shared()
    if len(args) == 3 and args[0] == '--sandbox':
        facts = a.sandbox(args[1], args[2])
        bases(False)
        facts['schema'] = 'chengwang.mihomo-service-sandbox/v1'
        facts['serviceBases'] = [str(ROOT),str(IDENTITIES),str(STATE)]
        print(w.canonical(facts).decode('ascii'), end='')
        return 0
    need(len(args) == 5)
    state = a.prepare_namespace(*args); _STATE = state
    bases(True)
    worker = a.PATHS['module']+'/deploy/mihomo-lifecycle-lab/service_worker.py'
    code = a.capture(state, [w.tool('python3'), '-B', worker, '--sandbox', state['commit'], state['moduleSHA256']],
                     'sandbox.private.json', 'sandbox.private.stderr', 30)
    need(code == 0 and w.file_bytes(a.ROOT_PRIVATE/'sandbox.private.stderr',4096,empty=True)[0] == b'')
    facts = w.decode(w.file_bytes(a.ROOT_PRIVATE/'sandbox.private.json',64 << 10)[0])
    need(facts['schema'] == 'chengwang.mihomo-service-sandbox/v1' and facts['sourceCommit'] == state['commit'])
    code = a.capture(state,[a.PATHS['goRoot']+'/bin/go','version'], 'go-version.txt','go-version.private.stderr',15)
    need(code == 0 and w.file_bytes(a.ROOT_PRIVATE/'go-version.private.stderr',4096,empty=True)[0] == b'')
    state['formatExit'] = a.capture(state, [a.PATHS['goRoot']+'/bin/gofmt','-d',*FMT],
                                    'gofmt.patch','gofmt.stderr',30)
    state['goExit'] = a.capture(state, [a.PATHS['goRoot']+'/bin/go','test','-json','-count=1','-shuffle=off',
        '-tags='+TAG,'-run=^'+TOP+'$','-timeout='+str(c['goTimeoutSeconds'])+'s',c['goPackage']],
        'apply.json','apply.stderr',c['outerGoTimeoutSeconds'])
    after, _, directory = w.custody(state['consumed'])
    need(after == state['inputBefore'] and directory == state['originalDirectory'])
    facts['inputCustody'] = dict(before=state['inputBefore'],after=after)
    outputs, forbidden, report = private_outputs(state['commit'])
    for public, original in (('go-version.txt','go-version.txt'),('gofmt.patch','gofmt.patch'),
            ('gofmt.stderr','gofmt.stderr'),('service.json','apply.json'),('service.stderr','apply.stderr')):
        raw = w.file_bytes(a.ROOT_PRIVATE/original,8 << 20,empty=True)[0]
        disclosure(raw, forbidden); outputs[public] = raw
    state['observed'] = bool(report.get('before') and report['before'].get('observedProcessMatchesHead') is True)
    outputs['sandbox.json'] = w.canonical(facts)
    outputs['execution.json'] = w.canonical(execution(state))
    need(set(outputs) == set(PUBLIC)-set(PREEXISTING) and sum(map(len,outputs.values())) <= 16 << 20)
    a.unchanged_public(state)
    for name, raw in outputs.items():
        w.write_new(a.EXPORT_ALIAS/name,raw,0o644)
    a.sync_output(state); a.unchanged_public(state)
    need(not state['pending'])
    if state['formatExit'] != 0 or state['goExit'] != 0 or outputs['gofmt.patch'] or outputs['gofmt.stderr'] or report['outcome'] != 'PASS':
        return state['goExit'] if type(state['goExit']) is int and state['goExit'] > 0 else 1
    need({p.name for p in state['out'].iterdir()} == set(PUBLIC)-{'host-after.json'})
    print('MIHOMO_SERVICE_WORKER=CAPTURED independent_verification=pending production=false')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception:
        failure()
        raise SystemExit('MIHOMO_SERVICE_WORKER=REJECTED raw_output_suppressed=true') from None
