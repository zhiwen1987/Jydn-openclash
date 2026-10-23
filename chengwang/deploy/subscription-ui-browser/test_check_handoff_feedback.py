"""Pure CPU auxiliary contracts, not browser or UI acceptance.

Business replay is mocked only for orchestration/custody unit tests. These
fixtures never prove the original business acceptance or real notice text.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import check_handoff_feedback as C

COMMIT='a'*40
FIXTURE='b'*32


def packed(value): return C.canonical(value)+b'\n'


def fixture():
    rows=[]; observations=[]
    for ordinal,step in enumerate(C.CONTRACT['steps'],1):
        expected=C.CONTRACT['expected'][step]
        row=dict(schema=C.B.CONTRACT['domSchema'],ordinal=ordinal,step=step,captureCount=ordinal,mutationCount=0,actorRole='operator',wireFence=dict(eventCount=0,bytes=0,sha256=C.sha(b'')),samplerFence=dict(recordCount=0,bytes=0,sha256=C.sha(b'')),dom=dict(pageVisible=step!='hidden',alertVisible=expected['alertVisible']))
        raw=packed(row); rows.append(raw)
        observations.append(dict(schema=C.CONTRACT['observationSchema'],ordinal=ordinal,step=step,domRowSHA256=C.sha(raw),**copy.deepcopy(expected)))
    return observations,b''.join(rows)


def transcript(observations):
    return b''.join(C.PREFIX+json.dumps(row,ensure_ascii=True,separators=(',',':')).encode('ascii')+b'\n' for row in observations)+C.SUCCESS


def source_fixture():
    blobs={p:b'synthetic source metadata, never executed\n' for p in C.SOURCE_PATHS}
    blobs[C.SOURCE_PATHS[0]]=Path(C.__file__).read_bytes(); blobs[C.CONTRACT_PATH]=C.CONTRACT_RAW
    sources=[dict(path=p,bytes=len(b),sha256=C.sha(b)) for p,b in sorted(blobs.items())]
    return blobs,dict(sourceFilesBefore=sources),dict(copiedInputs=[v for v in sources if v['path'] in C.COPIED_PATHS])


def prepare_files(directory):
    observations,dom=fixture(); originals=directory/'originals'; originals.mkdir()
    _,iso,inputs=source_fixture(); isolation_raw=packed(iso); inputs_raw=packed(inputs)
    (originals/'isolation.json').write_bytes(isolation_raw); (originals/'inputs.json').write_bytes(inputs_raw)
    business=dict(outcome='PASS',sourceCommit=COMMIT,engine='chrome-cdp',fixtureId=FIXTURE,sourceGitBlobs=900,production=False,authorization='BLOCKED',fullSubscriptionE2EProven=False,evidenceSHA256={'dom.jsonl':C.sha(dom),'isolation.json':C.sha(isolation_raw),'inputs.json':C.sha(inputs_raw)})
    (directory/'independent.json').write_bytes(packed(business)); (directory/'supervisor-original.log').write_bytes(transcript(observations)); (originals/'dom.jsonl').write_bytes(dom)
    return business


class HandoffFeedbackVerifierContracts(unittest.TestCase):
    def setUp(self):
        guard=mock.patch.object(C.B.subprocess,'run',side_effect=AssertionError('runtime forbidden in pure tests')); guard.start(); self.addCleanup(guard.stop)

    def test_01_frozen_49_scope_does_not_change_old_schemas(self):
        C.validate_contract(); self.assertEqual(len(C.CONTRACT['steps']),49); self.assertEqual(len(C.B.PUBLIC),22)
        self.assertEqual(C.B.CONTRACT['domStepKeys'],['schema','ordinal','step','captureCount','mutationCount','actorRole','wireFence','samplerFence','dom'])
        self.assertFalse(C.CONTRACT['fullSubscriptionE2EProven'])

    def test_02_complete_transcript_bound_to_all_original_rows(self):
        rows,dom=fixture(); self.assertEqual(C.validate_transcript(transcript(rows),dom),rows)

    def test_03_known_rejection_cannot_keep_waiting_status(self):
        for step in ('unknown_failed','wrong_source_failed','wrong_policy_failed','superseded_failed'):
            rows,dom=fixture(); row=next(v for v in rows if v['step']==step); row.update(status='WAITING',statusVisible=True)
            with self.subTest(step=step),self.assertRaises(ValueError): C.validate_transcript(transcript(rows),dom)

    def test_04_cross_owner_error_clears_stale_history_without_claiming_pending(self):
        for step in ('cross_owner_denied','cross_owner_recovered','api_approve_denied','valid_handoff_bound','valid_handoff_prepared'):
            rows,dom=fixture(); row=next(v for v in rows if v['step']==step); self.assertEqual(row['status'],'ABSENT'); row.update(status='HISTORY',statusVisible=True)
            with self.subTest(step=step),self.assertRaises(ValueError): C.validate_transcript(transcript(rows),dom)

    def test_05_owner_failed_receipt_history_is_separate_from_pending(self):
        rows,dom=fixture()
        for step in ('unknown_receipt','wrong_source_receipt','wrong_policy_receipt','superseded_receipt','stale_receipt_failed'):
            self.assertEqual(next(v for v in rows if v['step']==step)['status'],'HISTORY')
        next(v for v in rows if v['step']=='stale_receipt_failed')['alert']='CONFLICT'
        with self.assertRaises(ValueError): C.validate_transcript(transcript(rows),dom)

    def test_06_row_hash_uses_exact_original_bytes_including_lf(self):
        rows,dom=fixture(); rows[0]['domRowSHA256']=C.sha(dom.splitlines()[0])
        with self.assertRaises(ValueError): C.validate_transcript(transcript(rows),dom)
        rows,dom=fixture(); changed=dom.replace(b'"captureCount":1,',b'"captureCount":1, ',1)
        with self.assertRaises(ValueError): C.validate_transcript(transcript(rows),changed)

    def test_07_missing_duplicate_and_reordered_stage_rejected(self):
        for mode in ('missing','duplicate','order'):
            rows,dom=fixture()
            if mode=='missing': rows.pop()
            elif mode=='duplicate': rows[-1]=copy.deepcopy(rows[-2])
            else: rows[1],rows[2]=rows[2],rows[1]
            with self.subTest(mode=mode),self.assertRaises(ValueError): C.validate_transcript(transcript(rows),dom)

    def test_08_unknown_or_raw_secret_text_never_exported(self):
        for key in ('status','alert'):
            rows,dom=fixture(); rows[0][key]='CANARY_PRIVATE_UNEXPECTED_TEXT'
            with self.subTest(key=key),self.assertRaises(ValueError) as caught: C.validate_transcript(transcript(rows),dom)
            self.assertNotIn('CANARY',str(caught.exception))

    def test_09_closed_keys_and_boolean_integer_types(self):
        for key,value in (('rawText','secret'),('ordinal',True),('statusVisible',0),('alertVisible',1),('schema','other')):
            rows,dom=fixture(); rows[0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): C.validate_transcript(transcript(rows),dom)
        rows,dom=fixture(); rows[0]=dict(reversed(list(rows[0].items())))
        with self.assertRaises(ValueError): C.validate_transcript(transcript(rows),dom)

    def test_10_ascii_lf_line_and_total_budgets_are_independent(self):
        rows,dom=fixture(); raw=transcript(rows)
        for bad in (raw.replace(b'\n',b'\r\n'),raw[:-1],b'x'*65537+C.SUCCESS,raw.replace(b'ABSENT',b'\xc2\xa0ABSENT',1),b' '+raw):
            with self.assertRaises(ValueError): C.validate_transcript(bad,dom)
        with self.assertRaises(ValueError): C.validate_transcript(raw,dom[:-1])
        overlong=C.PREFIX+b' '*1024+packed(rows[0])+b''.join(C.PREFIX+packed(row) for row in rows[1:])+C.SUCCESS
        self.assertLess(len(overlong),65536)
        with self.assertRaises(ValueError): C.validate_transcript(overlong,dom)
        for altered in (raw.replace(b'"ordinal":',b'"ord\\u0069nal":',1),raw.replace(C.PREFIX,C.PREFIX+b' ',1)):
            with self.assertRaises(ValueError): C.validate_transcript(altered,dom)

    def test_11_success_suffix_unique_no_noise_or_failure_marker(self):
        rows,dom=fixture(); raw=transcript(rows)
        for bad in (raw+C.SUCCESS,C.SUCCESS+raw,raw.replace(C.SUCCESS,b'SUBSCRIPTION_UI=REJECTED\n'),raw.replace(C.SUCCESS,b'PRIVATE ERROR TEXT\n'+C.SUCCESS)):
            with self.assertRaises(ValueError): C.validate_transcript(bad,dom)

    def test_12_rendered_alert_matches_original_dom_observation(self):
        rows,dom=fixture(); lines=dom.splitlines(keepends=True); value=C.decode(lines[0]); value['dom']['alertVisible']=True; lines[0]=packed(value); rows[0]['domRowSHA256']=C.sha(lines[0])
        with self.assertRaises(ValueError): C.validate_transcript(transcript(rows),b''.join(lines))

    def test_13_hidden_retains_enum_but_not_visibility(self):
        rows,dom=fixture(); hidden=next(v for v in rows if v['step']=='hidden'); self.assertEqual(hidden['status'],'HISTORY'); self.assertFalse(hidden['statusVisible'])
        hidden['statusVisible']=True
        with self.assertRaises(ValueError): C.validate_transcript(transcript(rows),dom)

    def test_14_new_sources_self_and_contract_are_exact_git_bound(self):
        blobs,iso,inputs=source_fixture()
        with mock.patch.object(C,'read',side_effect=lambda p,*_: Path(C.__file__).read_bytes() if Path(p)==Path(C.__file__) else packed(iso) if Path(p).name=='isolation.json' else packed(inputs)),mock.patch.object(C,'git_bytes',side_effect=lambda repo,commit,path:blobs[path]):
            bindings=C.validate_sources(Path('.'),COMMIT,Path('originals')); self.assertEqual(len(bindings),len(C.SOURCE_PATHS))
            blobs[C.CONTRACT_PATH]=b'changed frozen policy'
            with self.assertRaises(ValueError): C.validate_sources(Path('.'),COMMIT,Path('originals'))

    def test_15_missing_runtime_copy_or_git_source_rejected(self):
        for mode in ('copy','source','hash'):
            blobs,iso,inputs=source_fixture()
            if mode=='copy': inputs['copiedInputs'].pop()
            elif mode=='source': iso['sourceFilesBefore'].pop()
            else: iso['sourceFilesBefore'][0]['sha256']='0'*64
            with mock.patch.object(C,'read',side_effect=lambda p,*_: Path(C.__file__).read_bytes() if Path(p)==Path(C.__file__) else packed(iso) if Path(p).name=='isolation.json' else packed(inputs)),mock.patch.object(C,'git_bytes',side_effect=lambda repo,commit,path:blobs[path]),self.subTest(mode=mode),self.assertRaises(ValueError): C.validate_sources(Path('.'),COMMIT,Path('originals'))

    def test_16_safe_marker_never_substitutes_original_business_replay(self):
        with tempfile.TemporaryDirectory(prefix='feedback-pure-') as tmp:
            root=Path(tmp); prepare_files(root)
            with mock.patch.object(C.B,'verify',side_effect=ValueError('business rejected')) as replay,mock.patch.object(C,'validate_sources') as sources,self.assertRaises(ValueError): C.verify(root,root,COMMIT,'chrome-cdp')
            replay.assert_called_once_with(root/'originals',root,COMMIT,'chrome-cdp'); sources.assert_not_called()

    def test_17_replayed_business_report_must_equal_original_bytes(self):
        with tempfile.TemporaryDirectory(prefix='feedback-pure-') as tmp:
            root=Path(tmp); business=prepare_files(root); (root/'independent.json').write_bytes(b' '+packed(business))
            with mock.patch.object(C.B,'verify',return_value=business),mock.patch.object(C,'validate_sources'),self.assertRaises(ValueError): C.verify(root,root,COMMIT,'chrome-cdp')
        for name in ('dom.jsonl','isolation.json','inputs.json'):
            with tempfile.TemporaryDirectory(prefix='feedback-pure-') as tmp:
                root=Path(tmp); business=prepare_files(root); business['evidenceSHA256'][name]='0'*64; (root/'independent.json').write_bytes(packed(business))
                with mock.patch.object(C.B,'verify',return_value=business),mock.patch.object(C,'validate_sources'),self.subTest(name=name),self.assertRaises(ValueError): C.verify(root,root,COMMIT,'chrome-cdp')

    def test_18_engine_commit_and_production_are_not_accepted_on_trust(self):
        for key,value in (('engine','playwright'),('sourceCommit','c'*40),('production',True),('authorization','OPEN'),('fullSubscriptionE2EProven',True)):
            with tempfile.TemporaryDirectory(prefix='feedback-pure-') as tmp:
                root=Path(tmp); business=prepare_files(root); business[key]=value; (root/'independent.json').write_bytes(packed(business))
                with mock.patch.object(C.B,'verify',return_value=business),mock.patch.object(C,'validate_sources'),self.subTest(key=key),self.assertRaises(ValueError): C.verify(root,root,COMMIT,'chrome-cdp')

    def test_19_no_unknown_timeout_or_raw_notice_proof_claims(self):
        with tempfile.TemporaryDirectory(prefix='feedback-pure-') as tmp:
            root=Path(tmp); business=prepare_files(root)
            with mock.patch.object(C.B,'verify',return_value=business),mock.patch.object(C,'validate_sources',return_value=[]): value=C.verify(root,root,COMMIT,'chrome-cdp')
            for key in ('unknownResultRealBrowserProven','timeoutRealBrowserProven','rawNoticeTextIndependentlyVerified','completeUXClosureProven','packetEvidenceProven','perHTTPFeedbackCausalityProven','production','fullSubscriptionE2EProven'): self.assertIs(value[key],False)
            self.assertEqual(value['observations'],49); self.assertTrue(value['normalBusinessEvidenceIndependentlyReplayed'])
        with tempfile.TemporaryDirectory(prefix='feedback-pure-') as tmp:
            root=Path(tmp); business=prepare_files(root); calls={}; ordinary=C.read
            def changed(path,*limits):
                count=calls.get(str(path),0)+1; calls[str(path)]=count; raw=ordinary(path,*limits)
                return raw+b' ' if Path(path).name=='supervisor-original.log' and count>1 else raw
            with mock.patch.object(C.B,'verify',return_value=business),mock.patch.object(C,'validate_sources',return_value=[]),mock.patch.object(C,'read',side_effect=changed),self.assertRaises(ValueError): C.verify(root,root,COMMIT,'chrome-cdp')

    def test_20_cli_report_exclusive_and_outside_repo_and_evidence(self):
        with tempfile.TemporaryDirectory(prefix='feedback-pure-') as tmp:
            root=Path(tmp); evidence=root/'evidence'; repo=root/'repo'; evidence.mkdir(); repo.mkdir(); occupied=root/'occupied'; occupied.write_bytes(b'preserved')
            for output in (evidence/'bad',repo/'bad',occupied):
                args=['checker','--evidence',str(evidence),'--repo',str(repo),'--source-commit',COMMIT,'--engine','chrome-cdp','--report',str(output)]
                with mock.patch('sys.argv',args),mock.patch.object(C,'verify',side_effect=AssertionError('must reject first')),self.assertRaises(ValueError): C.main()
            self.assertEqual(occupied.read_bytes(),b'preserved')


if __name__=='__main__': unittest.main()
