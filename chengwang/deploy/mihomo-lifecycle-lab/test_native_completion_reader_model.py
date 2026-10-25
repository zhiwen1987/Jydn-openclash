"""MODEL_ONLY unit checks; these are not native runtime acceptance evidence."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


def load_worker():
    path = Path(__file__).with_name('native_completion_worker.py')
    spec = importlib.util.spec_from_file_location('_completion_reader_model', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_checker():
    path = Path(__file__).with_name('check_native_completion.py')
    spec = importlib.util.spec_from_file_location('_completion_fresh_checker_model', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CompletionReaderModelTests(unittest.TestCase):
    def setUp(self):
        self.w = load_worker()
        self.c = load_checker()

    def binding_fixture(self):
        return {'schema':'chengwang.mihomo-native-completion-source-binding/v2','sourceCommit':'a'*40,
                'sourceTree':'b'*40,'indexTree':'b'*40,'sourceManifestSHA256':'c'*64,
                'sourceSetSHA256':'d'*64,'deliverySetSHA256':'e'*64,'policySHA256':'f'*64,
                'sourceCount':1356,'deliveryCount':9}

    def native_calls_fixture(self):
        kinds = [('KERNEL_OS_START_ATTEMPT',1),('KERNEL_OS_START_RETURN',1),('KERNEL_OS_WAIT_ENTER',1),
                 ('SYNTAX_OS_START_ATTEMPT',0),('SYNTAX_OS_START_RETURN',0),
                 ('RECOVERY_STOP_DISPATCH',1),('OWNED_STOP_HELPER_ENTER',1),
                 ('KERNEL_OS_TERM_ATTEMPT',1),('KERNEL_OS_TERM_RETURN',1),('KERNEL_OS_WAIT_RETURN',1),
                 ('RECOVERY_START_DISPATCH',0),('KERNEL_OS_START_ATTEMPT',2),
                 ('KERNEL_OS_START_RETURN',2),('KERNEL_OS_WAIT_ENTER',2),
                 ('OWNED_STOP_HELPER_ENTER',2),('KERNEL_OS_TERM_ATTEMPT',2),
                 ('KERNEL_OS_TERM_RETURN',2),('KERNEL_OS_WAIT_RETURN',2),('OWNED_STOP_HELPER_ENTER',1)]
        return [{'sequence':index,'kind':kind,'core':core,
                 'at':'2026-10-25T00:%02d:%02dZ'%((0,index) if index <= 14 else (2,index-14))}
                for index,(kind,core) in enumerate(kinds,1)]

    def report_fixture(self,mode):
        binding = self.binding_fixture(); calls = self.native_calls_fixture(); expected = self.c.EXPECTED[mode]
        s1_control,s2_control,disk_control = '1'*64,'2'*64,'3'*64
        s1_record,s2_record,disk_record,reopened_record = '4'*64,'5'*64,'6'*64,'7'*64
        source = (8,s2_record,s2_control)
        disk = source if mode == 'not-committed' else (9,disk_record,disk_control)
        memory = disk if mode == 'positive' else source
        reopened = {'stage':'completion-reopened','controlSHA256':disk[2],'recordSHA256':disk[1],
                    'revision':disk[0],'phase':'START_ARMED' if mode=='not-committed' else 'COMPLETED'}
        if mode == 'not-committed':
            reopened = {'stage':'completion-reopened','controlSHA256':'8'*64,'recordSHA256':reopened_record,
                        'revision':9,'phase':'RECOVERY_UNKNOWN'}
        publication = {'schema':'chengwang.mihomo-native-completion-publication/v1','scope':self.c.SCOPE,'mode':mode,
            'attemptedAt':'2026-10-25T00:01:00Z','returnedAt':'2026-10-25T00:01:01Z',
            'replaceAttempts':expected[0],'forwardedWrites':expected[1],'postWriteReads':expected[2],
            'injectedReads':expected[3],'underlyingCommitted':expected[4],'recordReturnedError':expected[5],
            'runtimeAdopted':expected[6],'capSpent':True,'capReplayRejected':True,'noCompletionNativeCalls':True,
            'coldReopenMatchedDisk':True,'closeExclusionHeld':True,'nativePrefixCount':14,
            'nativePrefixSHA256':hashlib.sha256(json.dumps(calls[:14],ensure_ascii=True,separators=(',',':')).encode('ascii')).hexdigest(),
            'serviceRebindProven':False,'apiRouteProven':False,'ordinaryPublishProven':False,
            'secondRecoveryProven':False,'production':False,'sourceRevision':source[0],'sourceRecordSHA256':source[1],
            'sourceControlSHA256':source[2],'memoryRevision':memory[0],'memoryRecordSHA256':memory[1],'memoryControlSHA256':memory[2],
            'diskRevision':disk[0],'diskRecordSHA256':disk[1],'diskControlSHA256':disk[2],'s1PreimageSHA256':s1_control,
            's2PreimageSHA256':None if mode=='not-committed' else s2_control,'previousHeadSHA256':'9'*64,
            'newHeadSHA256':None if mode=='not-committed' else 'a'*64,
            'handoffReturned':mode=='positive','handoffReplayRejected':mode=='positive',
            'storePoisoned':mode!='positive','diskPhase':'START_ARMED' if mode=='not-committed' else 'COMPLETED',
            'reopenTransition':'START_ARMED_TO_RECOVERY_UNKNOWN' if mode=='not-committed' else 'COMPLETED_UNCHANGED',
            'retiredEpochCount':0 if mode=='not-committed' else 1,
            'recoveryHistoryCount':0 if mode=='not-committed' else 1}
        report = {'schema':'chengwang.mihomo-native-completion-experiment/v1','scope':self.c.SCOPE,
            'sourceCommit':binding['sourceCommit'],'mode':mode,'outcome':'PASS','failureCode':'NONE',
            'countersBounded':True,'runtimeClosed':True,'diskOwnerClosed':True,'oldCore':1,'newCore':2,
            'nativeCalls':calls,
            's1':{'stage':'completion-s1.private.json','controlSHA256':s1_control,'recordSHA256':s1_record,'phase':'START_ARMED','revision':7},
            's2':{'stage':'completion-s2.private.json','controlSHA256':s2_control,'recordSHA256':s2_record,'phase':'START_ARMED','revision':8},
            'reopened':reopened,
            'controlPlane':{'readback':{'requestsObserved':8,'sampleCount':2,
                'conclusion':'TARGET_PROJECTION_MATCHED','dataplaneProven':False,'production':False}},
            'completion':publication,'closedPorts':[28411,28412,28413,28414,28415],
            'cleanupProbes':[{'port':port,'attempted':True,'result':'CONNECTION_REFUSED'} for port in (28411,28412,28413,28414,28415)],
            'fixtureCleanup':[{'role':role,'shutdownReturned':True,'serveReturned':True,
                'forcedConnectionsClosed':0,'errorClass':'NONE'} for role in ('origin','A','B')],
            'sourceBinding':dict(binding,privateReportSHA256='8'*64)}
        return report,binding

    def command_fixture(self,mode='positive'):
        binding = self.binding_fixture(); commit = binding['sourceCommit']
        namespace = {'networkNamespace':'net:[1]','mountNamespace':'mnt:[2]','pidNamespace':'pid:[3]'}
        rows = []
        for sequence,(name,timeout) in enumerate(zip(('SANDBOX','GO_VERSION','GOFMT','GO_TEST'),(30,15,30,120)),1):
            argv = ['placeholder']
            if name == 'SANDBOX':
                argv = ['python3','-B','worker.py','--sandbox',commit,binding['sourceTree'],binding['indexTree'],
                        binding['sourceManifestSHA256'],binding['sourceSetSHA256'],binding['deliverySetSHA256'],
                        binding['policySHA256'],str(binding['sourceCount']),str(binding['deliveryCount']),mode]
            elif name == 'GO_TEST':
                argv = ['go','test','-tags='+','.join(self.c.TAGS),'-run=^'+self.c.TOP+'$','-timeout=105s',
                        '-chengwang-native-completion-mode='+mode]
            rows.append({'schema':'chengwang.mihomo-native-completion-command-receipt/v3','sequence':sequence,
                'sourceCommit':commit,'commandClass':name,'argv':argv,'cwd':'/tmp/source/chengwang',
                'timeoutSeconds':timeout,'exitCode':0,'observed':True,'namespace':namespace,'sourceBinding':binding})
        return rows,binding

    def test_s1_reconstruction_uses_embedded_verified_source(self):
        s1 = {'schema':'v3','revision':9,'recordSHA256':'a'*64,'lastTrustedAt':'t1','lastRecoveryFence':2,
              'recoveryOwner':{'ownerNonce':'b'*64},'recovery':{'phase':'START_ARMED','revocation':None,
              'failure':None,'updatedAt':'t1','failedQuiescence':[],
              'execution':{'schema':'chengwang.mihomo-recovery-execution/v1','started':{'x':1}}}}
        s2 = copy.deepcopy(s1)
        s2['revision']=10; s2['recordSHA256']='c'*64; s2['lastTrustedAt']='t2'
        s2['recovery']['updatedAt']='t2'; s2['recovery']['execution']['schema']='chengwang.mihomo-recovery-execution/v2'
        s2['recovery']['execution']['verification']={'observation':{'sourceRevision':9,'sourceRecordSHA256':'a'*64},
            'sourceLastTrustedAt':'t1','sourceLastRecoveryFence':2,'sourceOwner':{'ownerNonce':'b'*64},
            'sourceRecoveryUpdatedAt':'t1','sourceFailedQuiescence':[]}
        self.assertEqual(self.w.reconstruct_s1(s2),self.w.canonical(s1))

    def completed_fixture(self):
        ledger={'anchor':{'kind':'LEGACY'},'head':{'headSHA256':'d'*64}}
        recovery={'phase':'COMPLETED','completion':{'head':{}},'updatedAt':'t3',
                  'execution':{'schema':'chengwang.mihomo-recovery-execution/v3','verification':{'x':1}}}
        retired=[]; history=[]
        root={'schema':'chengwang.mihomo-recovery-root-checkpoint/v1','revision':10,
              'recordSHA256':'c'*64,'lastTrustedAt':'t2','recoveryOwner':{'ownerNonce':'b'*64},
              'lastRecoveryFence':2,'currentEpochPosition':0,'currentLedgerSHA256':self.w.hash_value(ledger),
              'retiredPrefixCount':0,'retiredPrefixSHA256':self.w.hash_value({'schema':'chengwang.mihomo-recovery-retired-prefix/v1','entries':retired}),
              'recoveryHistoryPrefixCount':0,'recoveryHistoryPrefixSHA256':self.w.hash_value({'schema':'chengwang.mihomo-recovery-history-prefix/v1','entries':history}),
              'recoveryKind':'ACTIVE_VERIFIED'}
        recovery['execution']['completionSource']={'schema':'chengwang.mihomo-recovery-completion-source/v1','root':root,'commitDeadline':'t4'}
        completed={'schema':'v3','boundary':'b','revision':11,'recordSHA256':'e'*64,'lastTrustedAt':'t3',
                   'provisioning':{},'sourceV2':{},'current':{'anchor':{'kind':'RECOVERED'}},
                   'retiredEpochs':[{'ledger':ledger}],'recoveryOwner':{'ownerNonce':'b'*64},
                   'lastRecoveryFence':2,'recovery':recovery,'recoveryHistory':[copy.deepcopy(recovery)]}
        expected={'schema':'v3','boundary':'b','revision':10,'recordSHA256':'c'*64,'lastTrustedAt':'t2',
                  'provisioning':{},'sourceV2':{},'current':ledger,'retiredEpochs':[],
                  'recoveryOwner':{'ownerNonce':'b'*64},'lastRecoveryFence':2,
                  'recovery':copy.deepcopy(recovery),'recoveryHistory':[]}
        expected['recovery']['phase']='START_ARMED'; expected['recovery']['completion']=None
        expected['recovery']['updatedAt']='t2'; expected['recovery']['execution']['schema']='chengwang.mihomo-recovery-execution/v2'
        expected['recovery']['execution'].pop('completionSource')
        return completed, expected

    def test_s2_reconstruction_checks_prefix_and_ledger_hashes(self):
        completed, expected = self.completed_fixture()
        self.assertEqual(self.w.reconstruct_s2(completed),self.w.canonical(expected))
        armed = {'revision':8,'recordSHA256':'1'*64,'lastTrustedAt':'2026-10-25T00:00:00Z',
                 'provisioning':{'kept':True},'recovery':{'phase':'START_ARMED','failure':None,
                 'updatedAt':'2026-10-25T00:00:00Z','execution':{'kept':True}}}
        reopened = copy.deepcopy(armed)
        reopened['revision']=9; reopened['recordSHA256']='2'*64
        reopened['lastTrustedAt']='2026-10-25T00:00:01Z'
        reopened['recovery']['phase']='RECOVERY_UNKNOWN'
        reopened['recovery']['failure']={'code':'PROCESS_REOPENED','at':reopened['lastTrustedAt']}
        reopened['recovery']['updatedAt']=reopened['lastTrustedAt']
        self.w.validate_armed_reopen(armed,reopened)
        reopened['provisioning']['kept']=False
        with self.assertRaises(ValueError): self.w.validate_armed_reopen(armed,reopened)

    def test_s2_reconstruction_rejects_changed_prefix_digest(self):
        completed, _ = self.completed_fixture()
        completed['recovery']['execution']['completionSource']['root']['retiredPrefixSHA256']='0'*64
        with self.assertRaises(ValueError):
            self.w.reconstruct_s2(completed)

    def source_fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        source_root = Path(__file__).resolve().parents[3]
        for name in self.w.DELIVERY_PATHS:
            source = source_root/name
            destination = root/name; destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,destination)
            if os.name == 'posix' and name.endswith('.sh'):
                destination.chmod(0o755)
        for name in ('chengwang/internal/mihomodeploy/lifecycle_recovery_completion.go',
                     'chengwang/internal/mihomodeploy/lifecycle_recovery_store.go'):
            path = root/name; path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(('dependency:'+name+'\n').encode('ascii'))
        def git(*args):
            return subprocess.run(['git','-C',str(root),*args],check=True,stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
        git('init','-q'); git('add','--all')
        git('-c','user.email=model@example.invalid','-c','user.name=Model','commit','-q','-m','fixture')
        return temporary, root, git('rev-parse','HEAD').strip().decode('ascii')

    def test_fulltracked_authorities_match_and_reject_all_material_tamper(self):
        temporary, root, head = self.source_fixture()
        try:
            actual, worker_binding, manifest = self.w.git_source(root,head)
            checker_binding, checker_manifest = self.c.source_binding(root,head)
            self.assertEqual(actual,head)
            self.assertEqual((worker_binding,manifest),(checker_binding,checker_manifest))
            self.assertEqual(worker_binding['deliveryCount'],9)
            self.assertGreater(worker_binding['sourceCount'],9)
            self.assertEqual(self.w.verify_private_manifest(root,manifest,worker_binding),worker_binding)
            self.assertEqual(self.c.verify_private_manifest(manifest,checker_binding)['sourceCommit'],head)
            with self.assertRaises(ValueError):
                self.w.git_source(root,'0'*40)
            with self.assertRaises(ValueError):
                self.c.source_binding(root,'0'*40)
            names = [
                'chengwang/internal/mihomodeploy/lab_native_completion_linux_test.go',
                'chengwang/internal/mihomodeploy/lifecycle_recovery_completion.go',
                'chengwang/internal/mihomodeploy/lifecycle_recovery_store.go',
                'chengwang/deploy/mihomo-lifecycle-lab/native_completion_contract.json',
                'chengwang/deploy/mihomo-lifecycle-lab/native_completion_worker.py',
                'chengwang/deploy/mihomo-lifecycle-lab/check_native_completion.py',
                'chengwang/deploy/mihomo-lifecycle-lab/run_native_completion.sh',
                'chengwang/deploy/mihomo-capacity-profile/check_profile.py',
                '.github/workflows/chengwang-mihomo-native-completion.yml']
            for name in names:
                with self.subTest(name=name):
                    path = root/name; original = path.read_bytes(); path.write_bytes(b'tampered\n')
                    with self.assertRaises(ValueError): self.w.git_source(root,head)
                    with self.assertRaises(ValueError): self.c.source_binding(root,head)
                    path.write_bytes(original)
            changed = copy.deepcopy(self.w.json.loads(manifest)) if hasattr(self.w,'json') else None
            changed['entries'][0]['sha256'] = '0'*64
            forged = self.w.canonical(changed) + b'\n'
            with self.assertRaises(ValueError):
                self.w.verify_private_manifest(root,forged,worker_binding)
            with self.assertRaises(ValueError):
                self.c.verify_private_manifest(forged,checker_binding)
            for field,value in (('entryCount',float(changed['entryCount'])),):
                with self.subTest(manifest_field=field):
                    aliased = copy.deepcopy(self.w.json.loads(manifest))
                    aliased[field] = value
                    forged = self.w.canonical(aliased) + b'\n'
                    forged_binding = self.w._binding(forged,aliased)
                    with self.assertRaises(ValueError):
                        self.w.verify_private_manifest(root,forged,forged_binding)
                    with self.assertRaises(ValueError):
                        self.c.verify_private_manifest(forged,self.c.binding_for(forged,aliased))
            aliased = copy.deepcopy(self.w.json.loads(manifest))
            aliased['entries'][0]['bytes'] = float(aliased['entries'][0]['bytes'])
            aliased['deliveries'] = [next(row for row in aliased['entries'] if row['path'] == name)
                                     for name in self.w.DELIVERY_PATHS]
            aliased['sourceSetSHA256'] = self.w.source_set_digest(
                'chengwang.mihomo-native-completion-fulltracked-set/v2',aliased['entries'])
            aliased['deliverySetSHA256'] = self.w.source_set_digest(
                'chengwang.mihomo-native-completion-delivery-set/v2',aliased['deliveries'])
            forged = self.w.canonical(aliased) + b'\n'
            with self.assertRaises(ValueError):
                self.w.verify_private_manifest(root,forged,self.w._binding(forged,aliased))
            with self.assertRaises(ValueError):
                self.c.verify_private_manifest(forged,self.c.binding_for(forged,aliased))
        finally:
            temporary.cleanup()

    def test_report_contract_accepts_all_four_exact_modes(self):
        for mode in self.c.MODES:
            with self.subTest(mode=mode):
                report,binding = self.report_fixture(mode)
                publication,observed = self.c.report_check(report,binding['sourceCommit'],mode,binding)
                self.assertIs(publication,report['completion'])
                self.assertEqual(observed['privateReportSHA256'],'8'*64)

    def test_report_contract_rejects_aliases_in_all_four_modes(self):
        fields = ('replaceAttempts','forwardedWrites','postWriteReads','injectedReads',
                  'underlyingCommitted','recordReturnedError','runtimeAdopted')
        for mode in self.c.MODES:
            for field,want in zip(fields,self.c.EXPECTED[mode]):
                with self.subTest(mode=mode,field=field):
                    report,binding = self.report_fixture(mode)
                    report['completion'][field] = int(want) if type(want) is bool else bool(want)
                    with self.assertRaises(ValueError):
                        self.c.report_check(report,binding['sourceCommit'],mode,binding)
            report,binding = self.report_fixture(mode)
            report['s1']['revision'] = True
            with self.assertRaises(ValueError): self.c.report_check(report,binding['sourceCommit'],mode,binding)
            report,binding = self.report_fixture(mode)
            report['controlPlane']['readback']['requestsObserved'] = 8.0
            with self.assertRaises(ValueError): self.c.report_check(report,binding['sourceCommit'],mode,binding)
            report,binding = self.report_fixture(mode)
            report['closedPorts'][0] = 28411.0
            with self.assertRaises(ValueError): self.c.report_check(report,binding['sourceCommit'],mode,binding)
            report,binding = self.report_fixture(mode)
            report['nativeCalls'].append({'sequence':len(report['nativeCalls'])+1,
                'kind':'POST_COMPLETION_MUTATION','core':0,'at':'2026-10-25T00:03:00Z'})
            with self.assertRaises(ValueError): self.c.report_check(report,binding['sourceCommit'],mode,binding)
            if mode != 'not-committed':
                report,binding = self.report_fixture(mode)
                report['completion']['newHeadSHA256'] = report['completion']['previousHeadSHA256']
                with self.assertRaises(ValueError): self.c.report_check(report,binding['sourceCommit'],mode,binding)
            mutations = (
                lambda r: r['completion'].__setitem__('sourceRevision',r['completion']['sourceRevision']+1),
                lambda r: r['completion'].__setitem__('sourceRecordSHA256','b'*64),
                lambda r: r['completion'].__setitem__('sourceControlSHA256','c'*64),
                lambda r: r['completion'].__setitem__('memoryRevision',r['completion']['memoryRevision']+1),
                lambda r: r['completion'].__setitem__('diskRecordSHA256','d'*64),
                lambda r: r['completion'].__setitem__('s1PreimageSHA256','e'*64),
                lambda r: r['fixtureCleanup'][0].__setitem__('forcedConnectionsClosed',1))
            for number,mutate in enumerate(mutations,1):
                with self.subTest(mode=mode,cross_field_mutant=number):
                    report,binding = self.report_fixture(mode); mutate(report)
                    with self.assertRaises(ValueError):
                        self.c.report_check(report,binding['sourceCommit'],mode,binding)

    def test_command_receipts_accept_exact_and_reject_aliases(self):
        rows,binding = self.command_fixture()
        raw = b'\n'.join(self.c.canonical(row) for row in rows) + b'\n'
        self.assertEqual(self.c.command_receipts(raw,binding['sourceCommit'],'positive',binding),rows[0]['namespace'])
        for field,value in (('sequence',1.0),('exitCode',False),('timeoutSeconds',30.0)):
            with self.subTest(field=field):
                changed = copy.deepcopy(rows); changed[0][field] = value
                raw = b'\n'.join(self.c.canonical(row) for row in changed) + b'\n'
                with self.assertRaises(ValueError):
                    self.c.command_receipts(raw,binding['sourceCommit'],'positive',binding)

    def test_native_events_reject_sequence_and_core_aliases(self):
        report,binding = self.report_fixture('positive')
        for field,value in (('sequence',1.0),('core',1.0)):
            with self.subTest(field=field):
                changed = copy.deepcopy(report); changed['nativeCalls'][0][field] = value
                with self.assertRaises(ValueError):
                    self.c.report_check(changed,binding['sourceCommit'],'positive',binding)
        for order in (('KERNEL_OS_WAIT_RETURN','KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_TERM_RETURN'),
                      ('KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_WAIT_RETURN','KERNEL_OS_TERM_RETURN'),
                      ('KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_TERM_RETURN','KERNEL_OS_WAIT_RETURN')):
            scheduled = copy.deepcopy(report)
            rows = {row['kind']:row for row in scheduled['nativeCalls'][7:10]}
            scheduled['nativeCalls'][7:10] = [rows[kind] for kind in order]
            for sequence,row in enumerate(scheduled['nativeCalls'],1): row['sequence'] = sequence
            for second,row in enumerate(scheduled['nativeCalls'][7:10],8): row['at'] = '2026-10-25T00:00:%02dZ'%second
            scheduled['completion']['nativePrefixSHA256'] = hashlib.sha256(json.dumps(
                scheduled['nativeCalls'][:14],ensure_ascii=True,separators=(',',':')).encode('ascii')).hexdigest()
            self.c.report_check(scheduled,binding['sourceCommit'],'positive',binding)
        return_before_attempt = copy.deepcopy(report)
        return_before_attempt['nativeCalls'][7],return_before_attempt['nativeCalls'][8] = (
            return_before_attempt['nativeCalls'][8],return_before_attempt['nativeCalls'][7])
        for sequence,row in enumerate(return_before_attempt['nativeCalls'],1): row['sequence'] = sequence
        for second,row in enumerate(return_before_attempt['nativeCalls'][7:10],8): row['at'] = '2026-10-25T00:00:%02dZ'%second
        return_before_attempt['completion']['nativePrefixSHA256'] = hashlib.sha256(json.dumps(
            return_before_attempt['nativeCalls'][:14],ensure_ascii=True,separators=(',',':')).encode('ascii')).hexdigest()
        with self.assertRaises(ValueError):
            self.c.report_check(return_before_attempt,binding['sourceCommit'],'positive',binding)
        bad_hash = copy.deepcopy(report); bad_hash['completion']['nativePrefixSHA256'] = '0'*64
        with self.assertRaises(ValueError): self.c.report_check(bad_hash,binding['sourceCommit'],'positive',binding)
        late_prefix = copy.deepcopy(report); late_prefix['nativeCalls'][13]['at'] = '2026-10-25T00:01:30Z'
        late_prefix['completion']['nativePrefixSHA256'] = hashlib.sha256(json.dumps(
            late_prefix['nativeCalls'][:14],ensure_ascii=True,separators=(',',':')).encode('ascii')).hexdigest()
        with self.assertRaises(ValueError): self.c.report_check(late_prefix,binding['sourceCommit'],'positive',binding)
        no_term = copy.deepcopy(report)
        no_term['nativeCalls'] = [row for row in no_term['nativeCalls']
                                  if not (row['core'] == 2 and row['kind'] in
                                      ('KERNEL_OS_TERM_ATTEMPT','KERNEL_OS_TERM_RETURN'))]
        for sequence,row in enumerate(no_term['nativeCalls'],1): row['sequence'] = sequence
        self.c.report_check(no_term,binding['sourceCommit'],'positive',binding)
        killed = copy.deepcopy(report)
        wait = next(index for index,row in enumerate(killed['nativeCalls'])
                    if row['core'] == 2 and row['kind'] == 'KERNEL_OS_WAIT_RETURN')
        killed['nativeCalls'][wait:wait] = [
            {'sequence':0,'kind':'KERNEL_OS_KILL_ATTEMPT','core':2,'at':'2026-10-25T00:02:03Z'},
            {'sequence':0,'kind':'KERNEL_OS_KILL_RETURN','core':2,'at':'2026-10-25T00:02:03Z'}]
        for sequence,row in enumerate(killed['nativeCalls'],1): row['sequence'] = sequence
        self.c.report_check(killed,binding['sourceCommit'],'positive',binding)
        killed['nativeCalls'][wait-1],killed['nativeCalls'][wait] = killed['nativeCalls'][wait],killed['nativeCalls'][wait-1]
        for sequence,row in enumerate(killed['nativeCalls'],1): row['sequence'] = sequence
        with self.assertRaises(ValueError):
            self.c.report_check(killed,binding['sourceCommit'],'positive',binding)

    def test_wal_receipts_reject_uid_gid_and_count_aliases(self):
        for mode in self.c.MODES:
            report,binding = self.report_fixture(mode)
            publication,report_binding = self.c.report_check(report,binding['sourceCommit'],mode,binding)
            temporary = tempfile.TemporaryDirectory()
            try:
                out = Path(temporary.name)
                points = (report['s1'],report['s2'],
                    {'revision':publication['diskRevision'],'recordSHA256':publication['diskRecordSHA256'],
                     'controlSHA256':publication['diskControlSHA256'],'phase':publication['diskPhase']},
                    report['reopened'])
                wal_bytes = (1,1,1,2 if mode == 'not-committed' else 1)
                index = {'schema':'chengwang.mihomo-native-completion-wal-index/v1','scope':self.c.SCOPE,
                    'sourceCommit':binding['sourceCommit'],'mode':mode,'sourceBinding':report_binding,
                    'entries':[{'name':name,'present':True,'bytes':wal_bytes[number],'sha256':point['controlSHA256'],
                                'revision':point['revision'],'recordSHA256':point['recordSHA256'],'phase':point['phase']}
                                for number,(name,point) in enumerate(zip(self.c.WALS,points))],
                    'fullPrivateWALIndependentlyProven':False,'production':False}
                names = ('completion-source.private.json','completion-report.private.json',*self.c.WALS,
                         'kernel.stdout','kernel.stderr','new-kernel.stdout','new-kernel.stderr')
                wal_hashes = [point['controlSHA256'] for point in points]
                receipts = {'schema':'chengwang.mihomo-native-completion-fsync-receipts/v1','scope':self.c.SCOPE,
                    'sourceCommit':binding['sourceCommit'],'mode':mode,'sourceBinding':report_binding,
                    'entries':[{'name':name,'bytes':wal_bytes[number-2] if 2 <= number < 6 else 1,'sha256':
                        report_binding['sourceManifestSHA256'] if number==0 else report_binding['privateReportSHA256'] if number==1 else
                        wal_hashes[number-2] if 2 <= number < 6 else '9'*64,
                        'fsyncObserved':True,'mode':'0600','uid':10001,'gid':10001} for number,name in enumerate(names)],
                    'directoryFsyncObserved':True,'production':False}
                def write():
                    (out/'completion-wal-index.json').write_bytes(self.c.canonical(index))
                    (out/'completion-fsync-receipts.json').write_bytes(self.c.canonical(receipts))
                write(); self.c.wal_evidence(out,report,publication,binding['sourceCommit'],mode,report_binding)
                if mode == 'not-committed':
                    self.assertGreater(index['entries'][3]['bytes'],index['entries'][2]['bytes'])
                    # Frozen v2 used the inverse gate here and rejected this legal
                    # opener-authored RECOVERY_UNKNOWN growth before any runtime claim.
                    self.assertFalse(index['entries'][2]['bytes'] == index['entries'][3]['bytes'])
                    original_index = index['entries'][3]['bytes']; original_receipt = receipts['entries'][5]['bytes']
                    index['entries'][3]['bytes'] = index['entries'][2]['bytes']
                    receipts['entries'][5]['bytes'] = index['entries'][2]['bytes']
                    write()
                    with self.assertRaises(ValueError):
                        self.c.wal_evidence(out,report,publication,binding['sourceCommit'],mode,report_binding)
                    index['entries'][3]['bytes'],receipts['entries'][5]['bytes'] = original_index,original_receipt
                    original_hash = report['reopened']['controlSHA256']
                    report['reopened']['controlSHA256'] = publication['diskControlSHA256']
                    with self.assertRaises(ValueError):
                        self.c.report_check(report,binding['sourceCommit'],mode,binding)
                    report['reopened']['controlSHA256'] = original_hash
                    original_phase = report['reopened']['phase']
                    report['reopened']['phase'] = 'START_ARMED'
                    with self.assertRaises(ValueError):
                        self.c.report_check(report,binding['sourceCommit'],mode,binding)
                    report['reopened']['phase'] = original_phase
                for target,field,value in ((receipts['entries'][0],'uid',10001.0),
                                           (receipts['entries'][0],'gid',True),
                                           (index['entries'][0],'revision',float(index['entries'][0]['revision'])),
                                           (index['entries'][3],'recordSHA256','f'*64)):
                    with self.subTest(mode=mode,field=field,value=repr(value)):
                        original = target[field]; target[field] = value; write()
                        with self.assertRaises(ValueError):
                            self.c.wal_evidence(out,report,publication,binding['sourceCommit'],mode,report_binding)
                        target[field] = original
            finally:
                temporary.cleanup()

    def test_exact_same_rejects_bool_int_and_float_aliases(self):
        for value in (False,True,1.0):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError): self.c.exact_same({'count':value},{'count':1})


if __name__ == '__main__':
    unittest.main()
