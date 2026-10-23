"""Offline failure-observation verifier, never a product acceptance gate.

No driver reader or producer validator is imported. Missing legacy diagnostics
stay unavailable. The current tool may review older commits without pretending
that this implementation existed in those historical runs.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess

_spec = importlib.util.spec_from_file_location('navigation_neutral_bytes',Path(__file__).with_name('check_subscription_ui.py'))
H = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(H)
need,exact,integer,same,decode,read,sha,canonical = H.need,H.exact,H.integer,H.same,H.decode,H.read,H.sha,H.canonical
CONTRACT_PATH = 'chengwang/tools/subscription-ui-browser/navigation-diagnostics-contract.json'
CONTRACT = decode(read(Path(__file__).resolve().parents[2]/'tools/subscription-ui-browser/navigation-diagnostics-contract.json'))
OWN = 'chengwang/deploy/subscription-ui-browser/check_navigation_diagnostics.py'
NEUTRAL = 'chengwang/deploy/subscription-ui-browser/check_subscription_ui.py'
READER = 'chengwang/deploy/subscription-ui-browser/navigation_diagnostics.py'
MODULE = 'chengwang/tools/subscription-ui-browser/navigation-diagnostics.mjs'
RUNNER = 'chengwang/deploy/subscription-ui-browser/run_subscription_ui.py'
PREFIX = 'chengwang.subscription-ui-supervisor/v1'
PUBLIC = {'driver.json','captures.jsonl','dom.jsonl','created-desktop.png','created-mobile.png','processes.json','isolation.json','inputs.json','certificates.json','pin-consumption.json','private-readback.json','audit-events.jsonl','audit-checkpoint.json','build.json'}
REMOTE_PUBLIC = {'wire-ready.json','wire-events.jsonl','wire-stopped.json','source-ca.pem','source-leaf.pem','resolver-ca.pem','resolver-leaf.pem'}
FAILURE_FILES = {'failure.json','failed-host-readback.json'}
STAGES = ('WIRE_START','SERVER_START','DRIVER_START','DRIVER_BARRIER','UI_RUN','SERVER_STOP','WIRE_STOP','PROCESS_REAP','READBACK','EXPORT')
CHECKPOINTS = {'create_receipt':('ENVIRONMENT','LAUNCH','NAVIGATE','CONNECT','CONFIRM','RECEIPT','CLOSE','COMPLETE'),
               'local_admission':('ENVIRONMENT','LAUNCH','NAVIGATE','CREATE','IMPORT','ROLES','DECIDE','ROLLBACK','RECEIPT','CLOSE','COMPLETE'),
               'remote_fetch':('ENVIRONMENT','LAUNCH','NAVIGATE','CREATE','APPROVE','HANDOFF','FETCH','DECIDE','RECEIPT','CLOSE','COMPLETE')}


def validate_observation(value, commit, fixture, engine, scenario):
    """Recompute the closed contract; do not trust a producer available flag."""
    need(type(commit) is str and re.fullmatch(r'[a-f0-9]{40}',commit) and type(fixture) is str and re.fullmatch(r'[a-f0-9]{32}',fixture))
    need(scenario in CONTRACT['scenarios'] and engine in CONTRACT['phasesByEngine'])
    exact(value,CONTRACT['observationKeys'])
    same(value['schema'],CONTRACT['observationSchema']); same(value['scope'],CONTRACT['scope'])
    for field,expected in (('sourceCommit',commit),('fixtureId',fixture),('engine',engine),('scenario',scenario)): same(value[field],expected)
    phases = value['phases']; order = CONTRACT['phasesByEngine'][engine]
    need(type(phases) is list and len(phases) <= len(order))
    for number,row in enumerate(phases):
        exact(row,CONTRACT['phaseKeys']); same(row['phase'],order[number]); need(row['entered'] is True and type(row['completed']) is bool)
        need(number == len(phases)-1 or row['completed'] is True)
    incomplete = phases[-1]['phase'] if phases and not phases[-1]['completed'] else None
    need(type(value['cause']) is str)
    need(value['cause'] in CONTRACT['causesByPhase'][incomplete] if incomplete else value['cause'] == CONTRACT['completedCause'])
    input_position = order.index('INPUT_DISPATCHED')
    if len(phases) <= input_position: need(value['input'] is None)
    elif engine == 'chrome-cdp':
        exact(value['input'],('kind','mask')); same(value['input']['kind'],'CDP_ACK_MASK'); mask = value['input']['mask']
        need(type(mask) is int and mask in CONTRACT['cdpAcknowledgementMasks'])
        if incomplete == 'INPUT_DISPATCHED':
            masks = {'INPUT_MOVE_REJECTED':0,'INPUT_PRESS_REJECTED':1,'INPUT_RELEASE_REJECTED':3}
            need(value['cause'] in masks); same(mask,masks[value['cause']])
        else: same(mask,7)
    else:
        exact(value['input'],('kind','returned')); same(value['input']['kind'],'PW_CLICK_RETURN'); need(type(value['input']['returned']) is bool)
        if incomplete == 'INPUT_DISPATCHED': need(value['cause'] == 'PW_CLICK_REJECTED' and value['input']['returned'] is False)
        else: need(value['input']['returned'] is True)
    journal = value['journal']; need(type(journal) is dict and type(journal.get('available')) is bool)
    if journal['available'] is False: exact(journal,CONTRACT['journalUnavailableKeys'])
    else:
        exact(journal,CONTRACT['journalAvailableKeys']); need(type(journal['failure']) is bool); exact(journal['counters'],CONTRACT['counterNames'])
        for counter in journal['counters'].values(): integer(counter,0,CONTRACT['maxCounter'])
        for key in ('requests','terminal','pending','captures','tasks'): integer(journal[key],0,CONTRACT['maxRequestsByScenario'][scenario])
        integer(journal['mutations'],0,CONTRACT['maxMutationsByScenario'][scenario])
        need(journal['terminal']+journal['pending'] == journal['requests'] and journal['captures'] <= journal['terminal'] and journal['mutations'] <= journal['requests'])
    return dict(enteredPhases=[v['phase'] for v in phases],completedPhases=[v['phase'] for v in phases if v['completed']],incompletePhase=incomplete,cause=value['cause'],input=value['input'],journal=journal)


def projection(value, commit, fixture, engine, scenario):
    need(type(value) is dict and type(value.get('available')) is bool)
    if value['available'] is False: exact(value,('available',)); return None
    exact(value,('available','observation'))
    return validate_observation(value['observation'],commit,fixture,engine,scenario)


def context(value, commit, fixture, engine):
    need(value['schema'] == PREFIX and value['sourceCommit'] == commit and value['fixtureId'] == fixture and value['engine'] == engine and value['production'] is False)


def failure_metadata(value, commit, fixture, engine, scenario):
    fields = {'schema','sourceCommit','fixtureId','engine','stage','driverCheckpoints','serverExitCode','controllerExitCode','records','forcedSignals','noLiveOwnedProcesses','capturedOriginals','acceptance','production'}
    if scenario == 'remote_fetch': fields.add('wireExitCode')
    need(type(value) is dict and fields <= set(value) <= fields|{'driverDiagnostics'}); context(value,commit,fixture,engine)
    need(value['stage'] in STAGES and value['acceptance'] == 'REJECTED_DIAGNOSTIC_ONLY')
    for key in ('serverExitCode','controllerExitCode','wireExitCode'):
        if key in value and value[key] is not None: integer(value[key],-255,255)
    integer(value['forcedSignals'],0,16); need(type(value['noLiveOwnedProcesses']) is bool)
    checkpoints = value['driverCheckpoints']; need(type(checkpoints) is list and len(checkpoints) <= 64 and all(type(c) is str and c in CHECKPOINTS[scenario] for c in checkpoints))
    published = value['capturedOriginals']; need(type(published) is list and len(published) == len(set(published)) and set(published) <= {'driver.json','captures.jsonl','dom.jsonl','created-desktop.png','created-mobile.png'})
    records = value['records']; need(type(records) is list and len(records) <= (4 if scenario == 'remote_fetch' else 3)); roles = set(); pids = set()
    root = '/tmp/chengwang-subscription-ui-'+fixture; bundle = '/tmp/chengwang-subscription-ui-tools-'+fixture
    for record in records:
        exact(record,('pid','startTime','exeSHA256','argvSHA256','uid','gid','groups','capabilities','noNewPrivs','namespaces','limits','role','argv'))
        need(record['role'] in ('server','controller','chrome','wire') and (scenario == 'remote_fetch' or record['role'] != 'wire') and record['role'] not in roles); roles.add(record['role'])
        integer(record['pid'],2); need(record['pid'] not in pids); pids.add(record['pid']); need(type(record['startTime']) is str and re.fullmatch(r'[1-9][0-9]{0,19}',record['startTime']))
        H.digest(record['exeSHA256']); H.digest(record['argvSHA256'])
        for key in ('uid','gid'):
            need(type(record[key]) is list and len(record[key]) == 4)
            for item in record[key]: integer(item,0,(1<<32)-1)
        need(type(record['groups']) is list and len(record['groups']) <= 256)
        for item in record['groups']: integer(item,0,(1<<32)-1)
        integer(record['noNewPrivs'],0,1); exact(record['capabilities'],('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
        need(all(type(v) is str and re.fullmatch(r'[a-f0-9]{16}',v) for v in record['capabilities'].values()))
        exact(record['namespaces'],('net','mnt','pid','user'))
        for key,v in record['namespaces'].items(): need(type(v) is str and re.fullmatch(key+r':\[[0-9]+\]',v))
        exact(record['limits'],('cpuSeconds','fileBytes','openFiles','processes','coreBytes'))
        for item in record['limits'].values():
            need(type(item) is list and len(item) == 2)
            for number in item: integer(number,-1,(1<<63)-1)
        argv = record['argv']; need(type(argv) is list and 1 <= len(argv) <= 128 and all(type(a) is str and 0 < len(a) <= 4096 for a in argv))
        same(sha(b''.join(a.encode()+b'\0' for a in argv)),record['argvSHA256'])
        if record['role'] == 'server': same(argv,[bundle+'/server'])
        elif record['role'] == 'controller':
            script = {'create_receipt':'ui-cli.mjs','local_admission':'admission-cli.mjs','remote_fetch':'remote-fetch-cli.mjs'}[scenario]
            same(argv,[bundle+'/node',bundle+'/source/chengwang/tools/subscription-ui-browser/'+script,'--root',root,'--bundle',bundle,'--engine',engine,'--source-commit',commit])
        elif record['role'] == 'chrome':
            same(argv[0],bundle+'/chrome/chrome'); same([a for a in argv if a.startswith('--user-data-dir')],['--user-data-dir='+root+'/chrome-profile'])
        else:
            need(re.fullmatch(r'/usr/bin/python3(?:\.[0-9]{1,2})?',argv[0]))
            same(argv[1:],['-I','-B',bundle+'/source/chengwang/deploy/subscription-readback/wire_fixture.py','serve','--root','/tmp/chengwang-subscription-private-'+fixture,'--deadline-seconds','180'])


def source_manifest(host, source_blobs):
    exact(host,('schema','sourceCommit','fixtureId','engine','hostBefore','hostAfter','sourceFilesBefore','sourceFilesAfter','innerExitCode','innerTimedOut','acceptance','production'))
    same(host['hostBefore'],host['hostAfter']); same(host['sourceFilesBefore'],host['sourceFilesAfter'])
    need(type(host['innerTimedOut']) is bool); integer(host['innerExitCode'],-255,255); same(host['acceptance'],'REJECTED_DIAGNOSTIC_ONLY')
    before = host['hostBefore']; exact(before,('netNamespace','mountNamespace','pidNamespace','userNamespace','portStart','systemCASHA256','sourceSHA256'))
    for field,kind in (('netNamespace','net'),('mountNamespace','mnt'),('pidNamespace','pid'),('userNamespace','user')): need(type(before[field]) is str and re.fullmatch(kind+r':\[[0-9]+\]',before[field]))
    integer(before['portStart'],0,65535); H.digest(before['systemCASHA256']); H.digest(before['sourceSHA256'])
    rows = host['sourceFilesBefore']; need(type(rows) is list and 1 <= len(rows) <= 8192); names = []
    for row in rows:
        exact(row,('path','bytes','sha256')); path = row['path']; need(type(path) is str and path.startswith(('chengwang/','.github/workflows/')) and re.fullmatch(r'[A-Za-z0-9_./@+-]+',path) and '..' not in path.split('/'))
        need(path in source_blobs); raw = source_blobs[path]; same(row['bytes'],len(raw)); same(row['sha256'],sha(raw)); names.append(path)
    need(names == sorted(set(names)) and set(names) == set(source_blobs)); same(before['sourceSHA256'],sha(canonical(rows)))


def copied_inputs(value, commit, fixture, engine, source_blobs):
    exact(value,('schema','sourceCommit','fixtureId','engine','copiedInputs','inputTrustScope','production')); context(value,commit,fixture,engine)
    same(value['inputTrustScope'],'SOURCE_GIT_AND_NPM_LOCK_TRUSTED_CI_NOT_INDEPENDENT_REBUILD')
    need(type(value['copiedInputs']) is list and 1 <= len(value['copiedInputs']) <= 8192); copied = {}
    for row in value['copiedInputs']:
        exact(row,('path','bytes','sha256')); path = row['path']; need(type(path) is str and path not in copied and re.fullmatch(r'[A-Za-z0-9_./@+:-]+',path) and '..' not in path.split('/'))
        integer(row['bytes'],0,512<<20); H.digest(row['sha256']); copied[path] = row
        if path.startswith('chengwang/'):
            raw = source_blobs.get(path.removesuffix(':launcher')); need(raw is not None); same(row['bytes'],len(raw)); same(row['sha256'],sha(raw))
        else: need(path.startswith(('chrome/','npm/playwright-core/','dist/')) or path in ('toolchain/node','toolchain/server','build/report.json'))
    return copied


def captures(raw, scenario, build):
    need(type(raw) is bytes and 0 < len(raw) <= 24<<20 and raw.endswith(b'\n')); rows = [decode(line) for line in raw.splitlines()]
    need(1 <= len(rows) <= (64 if scenario == 'create_receipt' else 256)); ordinals = set(); requests = set(); ids = set(); kinds = {}; statuses = {}; mutations = 0
    required = set(H.CAPTURE_KEYS) | (set() if scenario == 'create_receipt' else {'actorRole'})
    dist = {v['path']:v for v in build['distFiles']}; total = 0
    allowed = {'DOCUMENT','ASSET','SNAPSHOT','COLLECTION_ACCESS','SOURCES','CREATE','SOURCE_ACCESS','CANDIDATES','RECEIPT'}
    allowed |= {'NODES','APPROVE','FETCH','DECIDE'} if scenario == 'remote_fetch' else {'NODES','IMPORT','DECIDE','ROLLBACK'} if scenario == 'local_admission' else set()
    previous = 0
    for row in rows:
        exact(row,required); same(row['schema'],{'create_receipt':'chengwang.subscription-ui-capture/v1','remote_fetch':'chengwang.remote-fetch-ui-capture/v1','local_admission':'chengwang.admission-ui-capture/v1'}[scenario])
        integer(row['ordinal'],1,256); need(previous < row['ordinal'] and row['ordinal'] not in ordinals); previous = row['ordinal']; ordinals.add(row['ordinal'])
        integer(row['requestOrdinal'],1,256); need(row['requestOrdinal'] not in requests); requests.add(row['requestOrdinal'])
        need(type(row['requestId']) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',row['requestId']) and row['requestId'] not in ids); ids.add(row['requestId'])
        need(row['kind'] in allowed and row['method'] in ('GET','POST')); integer(row['status'],100,599); need(type(row['authorizationPresent']) is bool)
        if scenario != 'create_receipt': need(row['actorRole'] in ('anonymous','operator','approver','viewer','auditor'))
        for k in ('startedWallTimeUs','startTimeUs','headerTimeUs','endTimeUs'): integer(row[k],1)
        need(row['headerTimeUs'] >= row['startTimeUs'] and row['endTimeUs'] >= row['startTimeUs']); exact(row['terminal'],('event','encodedDataLength')); same(row['terminal']['event'],'FINISH'); integer(row['terminal']['encodedDataLength'],0,16<<20)
        body = H.unbase64(row['responseBase64'],8<<20 if row['kind'] in ('DOCUMENT','ASSET') else 65536); same(row['responseBytes'],len(body)); same(row['responseSHA256'],sha(body)); total += len(body); need(total <= 16<<20)
        static = row['kind'] in ('DOCUMENT','ASSET','SNAPSHOT'); same(row['authorizationPresent'],not static)
        if scenario != 'create_receipt': need(row['actorRole'] == 'anonymous' if static else row['actorRole'] != 'anonymous')
        need(type(row['path']) is str and len(row['path']) <= 512)
        if row['kind'] in ('DOCUMENT','ASSET'):
            need(row['method'] == 'GET'); path = 'index.html' if row['path'] == '/' and row['kind'] == 'DOCUMENT' else row['path'][1:] if re.fullmatch(r'/assets/[A-Za-z0-9_.-]+',row['path']) else None
            need(path in dist); same({k:dist[path][k] for k in ('bytes','sha256')},dict(bytes=len(body),sha256=sha(body)))
        else:
            need(row['path'] == '/api/v1/snapshot' if row['kind'] == 'SNAPSHOT' else re.fullmatch(r'/api/v1/subscriptions/[A-Za-z0-9_/?=&-]+',row['path']))
            decode(body,allow_float=row['kind'] == 'SNAPSHOT')
        if row['method'] == 'GET': need(row['requestPublic'] is None)
        else: need(not static and type(row['requestPublic']) is dict); mutations += 1
        kinds[row['kind']] = kinds.get(row['kind'],0)+1; statuses[str(row['status'])] = statuses.get(str(row['status']),0)+1
    return dict(captures=len(rows),mutations=mutations,kinds=kinds,statuses=statuses)


def verify_raw(raws, source_blobs, commit, engine, scenario):
    need(type(commit) is str and re.fullmatch(r'[a-f0-9]{40}',commit) and engine in ('chrome-cdp','playwright') and scenario in CHECKPOINTS)
    allowed = PUBLIC|FAILURE_FILES|(REMOTE_PUBLIC if scenario == 'remote_fetch' else set())
    need(type(raws) is dict and {'failure.json','failed-host-readback.json','inputs.json','build.json'} <= set(raws) <= allowed)
    failure = decode(raws['failure.json']); fixture = failure.get('fixtureId'); need(type(fixture) is str and re.fullmatch(r'[a-f0-9]{32}',fixture))
    failure_metadata(failure,commit,fixture,engine,scenario); host = decode(raws['failed-host-readback.json']); context(host,commit,fixture,engine); source_manifest(host,source_blobs)
    copied = copied_inputs(decode(raws['inputs.json']),commit,fixture,engine,source_blobs)
    build = decode(raws['build.json']); H.validate_build(build,commit)
    same(copied.get('build/report.json'),dict(path='build/report.json',bytes=len(raws['build.json']),sha256=sha(raws['build.json'])))
    for name in failure['capturedOriginals']: need(name in raws)
    observed = captures(raws['captures.jsonl'],scenario,build) if 'captures.jsonl' in raws else None
    detail = projection(failure.get('driverDiagnostics',dict(available=False)),commit,fixture,engine,scenario)
    diagnostic_bound = False
    if detail is not None:
        driver = 'chengwang/tools/subscription-ui-browser/'+('ui-driver.mjs' if scenario == 'create_receipt' else 'remote-fetch-driver.mjs')
        for path in (OWN,NEUTRAL,READER,MODULE,RUNNER,CONTRACT_PATH,driver): need(path in source_blobs)
        same(source_blobs[OWN],read(Path(__file__))); same(source_blobs[NEUTRAL],read(Path(H.__file__))); same(decode(source_blobs[CONTRACT_PATH]),CONTRACT)
        for path in (READER,MODULE,CONTRACT_PATH,driver): need(path in copied)
        diagnostic_bound = True
    return dict(schema='chengwang.subscription-ui-navigation-diagnostics-verification/v1',status='DIAGNOSTIC_OBSERVATIONS_VERIFIED_NOT_ACCEPTANCE' if detail is not None else 'UNAVAILABLE_NOT_ACCEPTANCE',sourceCommit=commit,fixtureId=fixture,engine=engine,scenario=scenario,
        scope='OFFLINE_FAILURE_EVIDENCE_AND_TRUSTED_CI_PRE_CLEANUP_OBSERVATIONS_ONLY',failureStageObserved=failure['stage'],driverCheckpointsObserved=failure['driverCheckpoints'],controllerExitCodeObserved=failure['controllerExitCode'],forcedSignalsObserved=failure['forcedSignals'],noLiveOwnedProcessesObserved=failure['noLiveOwnedProcesses'],diagnosticSourceBindingsVerified=diagnostic_bound,
        historicalVerifierSourceClaimed=False,sourceGitBlobs=len(source_blobs),sourceAndHostUnchangedObserved=True,captureObservations=observed,diagnosticObservations=detail,
        productAcceptanceProven=False,browserAcceptanceProven=False,uniqueRootCauseProven=False,independentExecutionAttestationProven=False,production=False,authorization='BLOCKED',evidenceSHA256={n:sha(raws[n]) for n in sorted(raws)})


def git_source_blobs(repo, commit, names):
    prefix = ['git','-c','safe.directory='+str(repo),'-c','core.fsmonitor=false','-C',str(repo)]
    tracked = subprocess.check_output(prefix+['ls-tree','-r','-z','--name-only',commit,'--','chengwang','.github/workflows'],stderr=subprocess.DEVNULL,timeout=30)
    need(set(names) == {v.decode() for v in tracked.split(b'\0') if v})
    raw = subprocess.check_output(prefix+['cat-file','--batch'],input=b''.join((commit+':'+n+'\n').encode() for n in names),stderr=subprocess.DEVNULL,timeout=60)
    need(len(raw) <= 160<<20); at = 0; blobs = {}
    for name in names:
        end = raw.find(b'\n',at); need(end >= at); header = raw[at:end].split(); need(len(header) == 3 and header[1] == b'blob' and header[2].isdigit())
        size = int(header[2]); integer(size,0,16<<20); data = raw[end+1:end+1+size]; need(len(data) == size and raw[end+1+size:end+2+size] == b'\n'); blobs[name] = data; at = end+2+size
    same(at,len(raw)); return blobs


def verify(directory, repo, commit, engine, scenario):
    need(not directory.is_symlink() and directory.is_dir() and repo.is_dir())
    allowed = PUBLIC|FAILURE_FILES|(REMOTE_PUBLIC if scenario == 'remote_fetch' else set()); names = {p.name for p in directory.iterdir()}; need(names <= allowed)
    raw = {n:read(directory/n,24<<20 if n == 'captures.jsonl' else 16<<20) for n in names}; need(sum(map(len,raw.values())) <= 64<<20)
    host = decode(raw['failed-host-readback.json']); rows = host['sourceFilesBefore']; need(type(rows) is list and 1 <= len(rows) <= 8192)
    paths = []
    for row in rows:
        exact(row,('path','bytes','sha256')); path = row['path']; need(type(path) is str and re.fullmatch(r'[A-Za-z0-9_./@+-]+',path) and '..' not in path.split('/')); paths.append(path)
    need(paths == sorted(set(paths)))
    blobs = git_source_blobs(repo,commit,paths); result = verify_raw(raw,blobs,commit,engine,scenario)
    need({p.name for p in directory.iterdir()} == names and all(read(directory/n,24<<20 if n == 'captures.jsonl' else 16<<20) == value for n,value in raw.items()))
    return result


def write_report(path, evidence, repo, value):
    need(not path.is_symlink() and not path.exists() and not path.resolve().is_relative_to(evidence.resolve()) and not path.resolve().is_relative_to(repo.resolve()))
    with path.open('xb') as output: output.write(canonical(value)+b'\n')


def main():
    p = argparse.ArgumentParser()
    for name in ('evidence','repo','report'): p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--source-commit',required=True); p.add_argument('--engine',required=True,choices=('chrome-cdp','playwright')); p.add_argument('--scenario',required=True,choices=tuple(CHECKPOINTS)); args = p.parse_args()
    need(not args.evidence.is_symlink() and not args.repo.is_symlink()); evidence = args.evidence.resolve(strict=True); repo = args.repo.resolve(strict=True); report = args.report.absolute()
    need(not report.exists() and not report.is_symlink() and not report.resolve().is_relative_to(evidence) and not report.resolve().is_relative_to(repo))
    result = verify(evidence,repo,args.source_commit,args.engine,args.scenario); write_report(report,evidence,repo,result)
    print('NAVIGATION_DIAGNOSTICS='+result['status']+' product_acceptance_proven=false unique_root_cause_proven=false')


if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('NAVIGATION_DIAGNOSTICS=REJECTED raw_input_suppressed=true') from None
