"""Pure CPU and ordinary temporary files only, never a product/browser test."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import check_navigation_diagnostics as C

COMMIT = 'a'*40
FIXTURE = 'b'*32


def packed(value): return C.canonical(value)+b'\n'


def observation(engine='chrome-cdp',scenario='remote_fetch',phase='NAV_TARGET_ACTIONABLE',cause='NAV_TARGET_HIT_MISMATCH'):
    order=C.CONTRACT['phasesByEngine'][engine]; at=order.index(phase)
    phases=[dict(phase=p,entered=True,completed=i<at) for i,p in enumerate(order[:at+1])]
    inp=None
    if at>=order.index('INPUT_DISPATCHED'):
        inp=dict(kind='CDP_ACK_MASK',mask={'INPUT_MOVE_REJECTED':0,'INPUT_PRESS_REJECTED':1,'INPUT_RELEASE_REJECTED':3}.get(cause,7)) if engine=='chrome-cdp' else dict(kind='PW_CLICK_RETURN',returned=phase!='INPUT_DISPATCHED')
    return dict(schema=C.CONTRACT['observationSchema'],sourceCommit=COMMIT,fixtureId=FIXTURE,engine=engine,scenario=scenario,scope=C.CONTRACT['scope'],phases=phases,cause=cause,input=inp,journal=dict(available=True,failure=False,counters={n:0 for n in C.CONTRACT['counterNames']},requests=6,terminal=6,pending=0,captures=6,tasks=0,mutations=0))


def fixture(available=True,engine='chrome-cdp',scenario='remote_fetch'):
    driver='chengwang/tools/subscription-ui-browser/'+('ui-driver.mjs' if scenario=='create_receipt' else 'remote-fetch-driver.mjs')
    if available:
        blobs={name:b'pure synthetic source, never executed\n' for name in (C.READER,C.MODULE,C.RUNNER,driver)}
        blobs.update({C.OWN:Path(C.__file__).read_bytes(),C.NEUTRAL:Path(C.H.__file__).read_bytes(),C.CONTRACT_PATH:packed(C.CONTRACT)})
    else: blobs={'chengwang/legacy.py':b'legacy synthetic source, never executed\n'}
    sources=[dict(path=p,bytes=len(v),sha256=C.sha(v)) for p,v in sorted(blobs.items())]
    host=dict(netNamespace='net:[100]',mountNamespace='mnt:[101]',pidNamespace='pid:[102]',userNamespace='user:[103]',portStart=1024,systemCASHA256='c'*64,sourceSHA256=C.sha(C.canonical(sources)))
    common=dict(schema=C.PREFIX,sourceCommit=COMMIT,fixtureId=FIXTURE,engine=engine,production=False)
    failure=dict(**common,stage='UI_RUN',driverCheckpoints=['ENVIRONMENT','LAUNCH','NAVIGATE'],serverExitCode=0,controllerExitCode=1,records=[],forcedSignals=2,noLiveOwnedProcesses=True,capturedOriginals=['captures.jsonl'],acceptance='REJECTED_DIAGNOSTIC_ONLY')
    if scenario=='remote_fetch': failure['wireExitCode']=0
    if available:
        obs=observation(engine,scenario) if engine=='chrome-cdp' else observation(engine,scenario,'INPUT_DISPATCHED','PW_CLICK_REJECTED')
        failure['driverDiagnostics']=dict(available=True,observation=obs)
    old_host=dict(**common,hostBefore=host,hostAfter=copy.deepcopy(host),sourceFilesBefore=sources,sourceFilesAfter=copy.deepcopy(sources),innerExitCode=1,innerTimedOut=False,acceptance='REJECTED_DIAGNOSTIC_ONLY')
    html=b'<html>synthetic</html>'; js=b'const authorizationPrefix="Bearer ";'
    build=dict(schema='chengwang.subscription-ui-build/v1',sourceCommit=COMMIT,goVersion='go1.23.12',nodeVersion='v22.23.3',moduleMode='vendor',goDependencyDownloads=False,server=dict(name='server',bytes=1,sha256='d'*64),distFiles=sorted([dict(path=p,bytes=len(v),sha256=C.sha(v)) for p,v in [('index.html',html),('trust.html',b'x'),('.vite/manifest.json',b'{}'),('assets/app.js',js)]],key=lambda r:r['path']),production=False,authorization='BLOCKED')
    copied=copy.deepcopy(sources)+[dict(path='build/report.json',bytes=len(packed(build)),sha256=C.sha(packed(build)))]
    inputs=dict(**common,copiedInputs=copied,inputTrustScope='SOURCE_GIT_AND_NPM_LOCK_TRUSTED_CI_NOT_INDEPENDENT_REBUILD')
    captures=[]
    for i,(kind,path,raw) in enumerate((('DOCUMENT','/',html),('ASSET','/assets/app.js',js),('SNAPSHOT','/api/v1/snapshot',b'{"load":0.1}\n')),1):
        row=dict(schema={'create_receipt':'chengwang.subscription-ui-capture/v1','remote_fetch':'chengwang.remote-fetch-ui-capture/v1','local_admission':'chengwang.admission-ui-capture/v1'}[scenario],ordinal=i,requestOrdinal=i,requestId=str(i),method='GET',path=path,kind=kind,status=200,authorizationPresent=False,requestPublic=None,responseBase64=base64.b64encode(raw).decode(),responseSHA256=C.sha(raw),responseBytes=len(raw),startedWallTimeUs=1792800000000000+i,startTimeUs=i,headerTimeUs=i+1,endTimeUs=i+2,terminal=dict(event='FINISH',encodedDataLength=len(raw)))
        if scenario!='create_receipt': row['actorRole']='anonymous'
        captures.append(row)
    raws={'failure.json':packed(failure),'failed-host-readback.json':packed(old_host),'inputs.json':packed(inputs),'build.json':packed(build),'captures.jsonl':b''.join(packed(r) for r in captures)}
    return raws,blobs


class NavigationDiagnosticVerifierContracts(unittest.TestCase):
    def setUp(self):
        self.proc=mock.patch.object(C.subprocess,'check_output',side_effect=AssertionError('no process in pure tests')); self.proc.start(); self.addCleanup(self.proc.stop)
        self.run=mock.patch.object(C.subprocess,'run',side_effect=AssertionError('no runtime in pure tests')); self.run.start(); self.addCleanup(self.run.stop)

    def check(self,raws,blobs,engine='chrome-cdp',scenario='remote_fetch'): return C.verify_raw(raws,blobs,COMMIT,engine,scenario)

    def test_01_closed_diagnostic_verification_is_never_product_acceptance(self):
        result=self.check(*fixture()); self.assertEqual(result['status'],'DIAGNOSTIC_OBSERVATIONS_VERIFIED_NOT_ACCEPTANCE')
        self.assertEqual(result['diagnosticObservations']['incompletePhase'],'NAV_TARGET_ACTIONABLE'); self.assertTrue(result['diagnosticSourceBindingsVerified'])
        for field in ('productAcceptanceProven','browserAcceptanceProven','uniqueRootCauseProven','independentExecutionAttestationProven','historicalVerifierSourceClaimed','production'): self.assertIs(result[field],False)

    def test_02_legacy_missing_projection_is_explicitly_unavailable(self):
        result=self.check(*fixture(False)); self.assertEqual(result['status'],'UNAVAILABLE_NOT_ACCEPTANCE'); self.assertFalse(result['diagnosticSourceBindingsVerified']); self.assertIsNone(result['diagnosticObservations'])
        self.assertEqual(result['captureObservations']['mutations'],0); self.assertNotIn('counters',result)
        raws,blobs=fixture(False); f=C.decode(raws['failure.json']); f['driverDiagnostics']=dict(available=False); raws['failure.json']=packed(f)
        self.assertEqual(self.check(raws,blobs)['status'],'UNAVAILABLE_NOT_ACCEPTANCE')

    def test_03_unavailable_never_supplies_fabricated_observation_or_counters(self):
        for extra in ('observation','counters','cause'):
            with self.subTest(field=extra),self.assertRaises(ValueError): C.projection(dict(available=False,**{extra:{}}),COMMIT,FIXTURE,'chrome-cdp','remote_fetch')
        value=observation(); value['journal']=dict(available=False); result=C.validate_observation(value,COMMIT,FIXTURE,'chrome-cdp','remote_fetch'); self.assertEqual(result['journal'],dict(available=False))
        value['journal']['counters']={n:0 for n in C.CONTRACT['counterNames']}
        with self.assertRaises(ValueError): C.validate_observation(value,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')

    def test_04_phase_prefix_completion_and_cause_are_recomputed(self):
        for mode in ('skip','reorder','entered','two_incomplete','unknown_cause','wrong_cause','unclassified'):
            v=observation()
            if mode=='skip': v['phases'].pop(0)
            elif mode=='reorder': v['phases'][0],v['phases'][1]=v['phases'][1],v['phases'][0]
            elif mode=='entered': v['phases'][0]['entered']=1
            elif mode=='two_incomplete': v['phases'][0]['completed']=False
            elif mode=='unknown_cause': v['cause']='arbitrary private exception'
            elif mode=='wrong_cause': v['cause']='API_CERT_REJECTED'
            else: v['cause']='UNCLASSIFIED'
            with self.subTest(mode=mode),self.assertRaises(ValueError): C.validate_observation(v,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')
        v=observation(); v['phases']=[]; v['cause']='UNCLASSIFIED'; C.validate_observation(v,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')
        v=observation(); v['phases'][-1]['completed']=True; v['cause']='UNCLASSIFIED'; C.validate_observation(v,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')

    def test_05_cdp_each_unacknowledged_input_rejection_has_exact_mask(self):
        for cause,mask in (('INPUT_MOVE_REJECTED',0),('INPUT_PRESS_REJECTED',1),('INPUT_RELEASE_REJECTED',3)):
            v=observation(phase='INPUT_DISPATCHED',cause=cause); self.assertEqual(v['input']['mask'],mask); C.validate_observation(v,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')
            for wrong in (True,7,mask+2):
                bad=copy.deepcopy(v); bad['input']['mask']=wrong
                with self.subTest(cause=cause,wrong=wrong),self.assertRaises(ValueError): C.validate_observation(bad,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')

    def test_06_cdp_completed_input_requires_all_three_real_acknowledgements(self):
        v=observation(phase='ANON_DOM',cause='ANON_SHAPE_REJECTED'); C.validate_observation(v,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')
        for mask in (0,1,3,True):
            bad=copy.deepcopy(v); bad['input']['mask']=mask
            with self.assertRaises(ValueError): C.validate_observation(bad,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')
        v=observation(); v['input']=dict(kind='CDP_ACK_MASK',mask=0)
        with self.assertRaises(ValueError): C.validate_observation(v,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')

    def test_07_playwright_does_not_forge_cdp_actionability_or_mouse_ack(self):
        v=observation('playwright',phase='INPUT_DISPATCHED',cause='PW_CLICK_REJECTED'); C.validate_observation(v,COMMIT,FIXTURE,'playwright','remote_fetch')
        for inp in (dict(kind='CDP_ACK_MASK',mask=7),dict(kind='PW_CLICK_RETURN',returned=True)):
            bad=copy.deepcopy(v); bad['input']=inp
            with self.assertRaises(ValueError): C.validate_observation(bad,COMMIT,FIXTURE,'playwright','remote_fetch')
        v=observation('playwright',phase='ANON_DOM',cause='ANON_SHAPE_REJECTED'); C.validate_observation(v,COMMIT,FIXTURE,'playwright','remote_fetch')
        v['phases'].insert(3,dict(phase='NAV_TARGET_ACTIONABLE',entered=True,completed=True))
        with self.assertRaises(ValueError): C.validate_observation(v,COMMIT,FIXTURE,'playwright','remote_fetch')

    def test_08_original_eight_counter_types_bounds_and_availability_are_strict(self):
        for counter in C.CONTRACT['counterNames']:
            for val in (-1,True,2147483648):
                v=observation(); v['journal']['counters'][counter]=val
                with self.subTest(counter=counter,value=val),self.assertRaises(ValueError): C.validate_observation(v,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')
        v=observation(); v['journal']['counters']['runtimeErrors']=2147483647; C.validate_observation(v,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')
        v['journal']['counters']['unknown']=0
        with self.assertRaises(ValueError): C.validate_observation(v,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')

    def test_09_instantaneous_journal_arithmetic_and_scenario_budgets(self):
        for field,val in [('requests',257),('terminal',7),('pending',1),('captures',7),('mutations',5),('tasks',True)]:
            v=observation(); v['journal'][field]=val
            with self.subTest(field=field),self.assertRaises(ValueError): C.validate_observation(v,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')
        v=observation(scenario='create_receipt'); v['journal']['requests']=65; v['journal']['pending']=59
        with self.assertRaises(ValueError): C.validate_observation(v,COMMIT,FIXTURE,'chrome-cdp','create_receipt')

    def test_10_raw_context_ids_and_unsupported_admission_cannot_be_forged(self):
        for field,val in [('fixtureId','c'*32),('sourceCommit','c'*40),('engine','playwright'),('scenario','create_receipt'),('scope','acceptance')]:
            v=observation(); v[field]=val
            with self.subTest(field=field),self.assertRaises(ValueError): C.validate_observation(v,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')
        raws,blobs=fixture(False,scenario='local_admission'); self.assertEqual(self.check(raws,blobs,scenario='local_admission')['status'],'UNAVAILABLE_NOT_ACCEPTANCE')
        with self.assertRaises(ValueError): C.validate_observation(observation(),COMMIT,FIXTURE,'chrome-cdp','local_admission')

    def test_11_new_source_contract_module_reader_driver_and_self_must_be_bound(self):
        for target in (C.READER,C.MODULE,C.RUNNER,C.CONTRACT_PATH,C.OWN,C.NEUTRAL,'chengwang/tools/subscription-ui-browser/remote-fetch-driver.mjs'):
            raws,blobs=fixture(); blobs[target]+=b'changed'
            with self.subTest(path=target),self.assertRaises(ValueError): self.check(raws,blobs)
        raws,blobs=fixture(); inputs=C.decode(raws['inputs.json']); inputs['copiedInputs']=[r for r in inputs['copiedInputs'] if r['path']!=C.MODULE]; raws['inputs.json']=packed(inputs)
        with self.assertRaises(ValueError): self.check(raws,blobs)

    def test_12_host_and_all_original_source_records_must_remain_identical(self):
        for mode in ('host','source','duplicate','wronghash'):
            raws,blobs=fixture(); host=C.decode(raws['failed-host-readback.json'])
            if mode=='host': host['hostAfter']['portStart']=0
            elif mode=='source': host['sourceFilesAfter'].pop()
            elif mode=='duplicate': host['sourceFilesBefore'].append(copy.deepcopy(host['sourceFilesBefore'][0])); host['sourceFilesAfter']=copy.deepcopy(host['sourceFilesBefore'])
            else: host['sourceFilesBefore'][0]['sha256']='0'*64; host['sourceFilesAfter']=copy.deepcopy(host['sourceFilesBefore'])
            raws['failed-host-readback.json']=packed(host)
            with self.subTest(mode=mode),self.assertRaises(ValueError): self.check(raws,blobs)

    def test_13_failure_root_identity_exit_and_process_argv_fields_are_closed(self):
        for field,val in [('fixtureId','c'*32),('engine','playwright'),('sourceCommit','c'*40),('forcedSignals',True),('acceptance','PASS'),('exception','private text')]:
            raws,blobs=fixture(); failure=C.decode(raws['failure.json']); failure[field]=val; raws['failure.json']=packed(failure)
            with self.subTest(field=field),self.assertRaises(ValueError): self.check(raws,blobs)

    def test_14_capture_body_base64_hash_status_and_request_identity_are_actual(self):
        raws,blobs=fixture(); result=self.check(raws,blobs); self.assertEqual(result['captureObservations']['captures'],3); self.assertEqual(result['captureObservations']['statuses'],{'200':3})
        for field,val in [('responseSHA256','0'*64),('responseBase64','YQ=='),('responseBytes',True),('requestId','private path /'),('status',False)]:
            raws,blobs=fixture(); rows=[C.decode(x) for x in raws['captures.jsonl'].splitlines()]; rows[0][field]=val; raws['captures.jsonl']=b''.join(packed(r) for r in rows)
            with self.subTest(field=field),self.assertRaises(ValueError): self.check(raws,blobs)
        # The body clock is CDP-local: FINISH can precede HEADERS dispatch.
        raws,blobs=fixture(); rows=[C.decode(x) for x in raws['captures.jsonl'].splitlines()]; rows[0]['headerTimeUs']=rows[0]['endTimeUs']+1; raws['captures.jsonl']=b''.join(packed(r) for r in rows); self.check(raws,blobs)

    def test_15_missing_capture_evidence_is_null_not_invented_zero(self):
        raws,blobs=fixture(False); raws.pop('captures.jsonl'); f=C.decode(raws['failure.json']); f['capturedOriginals']=[]; raws['failure.json']=packed(f)
        self.assertIsNone(self.check(raws,blobs)['captureObservations'])

    def test_16_unknown_public_files_secrets_extra_fields_and_duplicate_json_rejected(self):
        raws,blobs=fixture(); raws['private-input.json']=b'secret'
        with self.assertRaises(ValueError): self.check(raws,blobs)
        with self.assertRaises(ValueError): C.decode(b'{"available":false,"available":true}')
        v=observation(); v['exception']='secret'
        with self.assertRaises(ValueError): C.validate_observation(v,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')

    def test_17_raw_observation_unavailable_is_not_silently_used_after_malformation(self):
        for projection in (dict(available=1),dict(available=True),dict(available=False,observation=None)):
            with self.assertRaises(ValueError): C.projection(projection,COMMIT,FIXTURE,'chrome-cdp','remote_fetch')
        raws,blobs=fixture(); f=C.decode(raws['failure.json']); f['driverDiagnostics']['observation']['cause']='private exception'; raws['failure.json']=packed(f)
        with self.assertRaises(ValueError): self.check(raws,blobs)

    def test_18_exclusive_output_never_overwrites_evidence_or_source(self):
        with tempfile.TemporaryDirectory(prefix='navigation-diagnostic-contract-') as directory:
            root=Path(directory); evidence=root/'evidence'; repo=root/'repo'; evidence.mkdir(); repo.mkdir(); result=self.check(*fixture(False)); report=root/'diagnostic.json'
            C.write_report(report,evidence,repo,result); raw=report.read_bytes()
            with self.assertRaises(ValueError): C.write_report(report,evidence,repo,result)
            self.assertEqual(report.read_bytes(),raw)
            for bad in (evidence/'bad.json',repo/'bad.json'):
                with self.assertRaises(ValueError): C.write_report(bad,evidence,repo,result)


if __name__=='__main__': unittest.main()
