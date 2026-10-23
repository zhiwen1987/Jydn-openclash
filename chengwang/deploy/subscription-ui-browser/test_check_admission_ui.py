"""Pure synthetic admission verifier counterexamples, not browser evidence."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import unittest

_s=importlib.util.spec_from_file_location('admission_checker_under_test',Path(__file__).with_name('check_admission_ui.py'))
C=importlib.util.module_from_spec(_s); _s.loader.exec_module(C)
DATE='2026-10-24T00:00:00Z'


def encoded(value):
    return json.dumps(dict(boundary='LOCAL_SUBSCRIPTION_ADMISSION_ONLY',authorization='BLOCKED',deviceActionsExecuted=False,stateMayHaveChanged=False,result=value),separators=(',',':')).encode()+b'\n'


def fixture():
    sources={a:'src_'+str(i)*32 for i,a in enumerate(('a','b'),1)}
    candidates={a:'cand_'+str(i)*32 for i,a in enumerate(('a1','b1','a2','a3'),3)}
    candidate_digests={a:'hmac-sha256:'+str(i)*64 for i,a in enumerate(('a1','b1','a2','a3'),3)}
    rows=[]; values={}
    for index,action in enumerate(C.ACTIONS,1):
        kind=action['kind']; sid=sources[action['source']]
        rc=dict(commandId='cmd_'+format(index,'032x'),kind=kind,sourceId=sid,revision=action['toRevision'],state='committed',replayed=False,stateMayHaveChanged=False,auditRecorded=True,
            preparedAuditHash=format(index,'064x'),resultAuditHash=format(index+100,'064x'),localAuditHash=format(index+200,'064x'),completedAt=DATE)
        public=dict(idempotencyKey='sub_'+format(index,'032x'))
        if kind=='create': public['label']=C.CONTRACT['labels'][action['source']]; path=C.BASE+'/sources'
        else:
            public.update(sourceId=sid,expectedRevision=action['fromRevision']); path=C.BASE+'/sources/'+sid+{'import':'/candidates','decide':'/decisions','rollback':'/rollbacks'}[kind]
            alias=action['candidate']; rc.update(candidateId=candidates[alias],candidateDigest=candidate_digests[alias])
            if kind=='import': public.update(format='mihomo-provider-yaml',contentBytes=700)
            else:
                public['candidateId']=candidates[alias]
                if kind=='decide': public.update(expectedDigest=candidate_digests[alias],decision=action['decision'])
        raw=encoded(rc); values[index]=rc
        rows.append(dict(schema=C.CONTRACT['captureSchema'],ordinal=index,requestOrdinal=index,requestId=str(index),method='POST',path=path,kind=kind.upper(),status=200,authorizationPresent=True,actorRole=action['role'],requestPublic=public,
            responseBase64=base64.b64encode(raw).decode(),responseSHA256=C.sha(raw),responseBytes=len(raw),startedWallTimeUs=1000000000+index*100,startTimeUs=index*100,headerTimeUs=index*100+20,endTimeUs=index*100+10,terminal=dict(event='FINISH',encodedDataLength=len(raw)+100)))
    return rows,values


def nodes(number):
    out=[]
    for offset,protocol in enumerate(('http','socks5')):
        ident='node_'+format(number*2+offset,'032x'); out.append(dict(id=ident,label='节点-'+ident[-8:],protocol=protocol,credentialConfigured=True,state='unknown'))
    return out


def full_facts():
    rows,values=fixture(); facts=C.reconstruct(rows,values)
    for index,cid in enumerate(facts['aliases']['candidates'].values(),1): facts['nodeViews'][cid]=nodes(index); facts['candidateCreatedAt'][cid]=DATE
    return rows,values,facts


def audit_fixture(facts):
    out=[]; previous='0'*64
    for index,(action,row) in enumerate(zip(C.ACTIONS,facts['posts']),1):
        rc=C.envelope(C.unbase64(row['responseBase64'],65536)); actor='act_'+('a' if action['role']=='operator' else 'b')*60
        stable=dict(**C.SCOPE,managementObject='local',kind=action['kind'],commandDigest='hmac-sha256:'+format(index,'064x'))
        for stage in ('prepared','result'):
            data=dict(stable)
            if stage=='result': data.update(state='committed',code='',sourceId=rc['sourceId'],candidateId=rc.get('candidateId',''),revision=str(rc['revision']),candidateDigest=rc.get('candidateDigest',''),localAuditHash=rc['localAuditHash'],approvalId='',policyDigest='',policyRevision='0',stateMayHaveChanged='false')
            e=dict(id='event-'+str(index)+'-'+stage,idempotencyKey='subscription/'+rc['commandId']+'/'+stage,traceId=rc['commandId'],actorId=actor,action='subscription.command.'+stage,target='subscription/'+('local' if action['kind']=='create' else rc['sourceId']),result=stage,occurredAt=DATE,data=data,previousHash=previous,hash='')
            e['hash']=C.sha(C.H.go_event_bytes(e)); previous=e['hash']; out.append(e)
            facts['receipts'][rc['commandId']]['preparedAuditHash' if stage=='prepared' else 'resultAuditHash']=e['hash']
        # Keep raw immutable receipt and reconstructed lookup byte-consistent.
        changed=facts['receipts'][rc['commandId']]; raw=encoded(changed); row.update(responseBase64=base64.b64encode(raw).decode(),responseSHA256=C.sha(raw),responseBytes=len(raw))
    return out,dict(count=20,lastHash=previous)


class AdmissionVerifierContracts(unittest.TestCase):
    def reject(self,fn,*args):
        with self.assertRaises((ValueError,KeyError,TypeError)): fn(*args)
    def test_01_ten_mutation_state_machine(self):
        r,v=fixture(); f=C.reconstruct(r,v); self.assertEqual(len(f['states']),11); self.assertEqual(f['states'][-1]['sources'][f['aliases']['sources']['a']]['revision'],8)
    def test_02_rejection_keeps_last_known_pointer(self):
        r,v=fixture(); f=C.reconstruct(r,v); s=f['states'][9]['sources'][f['aliases']['sources']['a']]; self.assertEqual(s['acceptedCandidateId'],f['aliases']['candidates']['a2']); self.assertEqual(s['latestCandidateId'],f['aliases']['candidates']['a3'])
    def test_03_rollback_historical_base_cas_rejected(self):
        r,v=fixture(); r[-1]['requestPublic']['expectedRevision']=2; self.reject(C.reconstruct,r,v)
    def test_04_rollback_rejected_candidate_rejected(self):
        r,v=fixture(); r[-1]['requestPublic']['candidateId']=r[-2]['requestPublic']['candidateId']; self.reject(C.reconstruct,r,v)
    def test_05_cross_source_import_rejected(self):
        r,v=fixture(); r[3]['requestPublic']['sourceId']=r[2]['requestPublic']['sourceId']; self.reject(C.reconstruct,r,v)
    def test_06_decision_digest_mismatch_rejected(self):
        r,v=fixture(); r[4]['requestPublic']['expectedDigest']='hmac-sha256:'+'f'*64; self.reject(C.reconstruct,r,v)
    def test_07_operator_cannot_masquerade_as_approver(self):
        r,v=fixture(); r[4]['actorRole']='operator'; self.reject(C.reconstruct,r,v)
    def test_08_idempotency_key_reuse_rejected(self):
        r,v=fixture(); r[-1]['requestPublic']['idempotencyKey']=r[0]['requestPublic']['idempotencyKey']; self.reject(C.reconstruct,r,v)
    def test_09_receipt_missing_audit_rejected(self):
        r,v=fixture(); v[5]['auditRecorded']=False; self.reject(C.reconstruct,r,v)
    def test_10_receipt_bool_revision_rejected(self):
        r,v=fixture(); v[1]['revision']=True; self.reject(C.reconstruct,r,v)
    def test_11_import_private_content_projection_rejected(self):
        r,v=fixture(); r[2]['requestPublic']['contentBase64']='private'; self.reject(C.reconstruct,r,v)
    def test_12_non_product_mutation_endpoint_rejected(self):
        r,v=fixture(); r[2]['path']=r[2]['path'].replace('/candidates','/imports'); self.reject(C.reconstruct,r,v)
        r,v=fixture(); r[-1]['path']=r[-1]['path'].replace('/rollbacks','/rollback'); self.reject(C.reconstruct,r,v)
    def test_13_viewer_writes_gate_is_not_permission(self):
        e=C.expected_access('viewer','src_'+'1'*32); self.assertTrue(e['writesEnabled']); self.assertEqual(e['actions'],['subscription.read'])
    def test_14_approver_source_actions_ordered(self):
        self.assertEqual(C.expected_access('approver','src_'+'1'*32)['actions'],['subscription.read','subscription.admission.decide','subscription.source.approve','subscription.rollback'])
        enabled={k:dict(enabled=True) for k in ('prepare_admit','prepare_reject')}
        disabled={k:dict(enabled=False) for k in ('prepare_admit','prepare_reject')}
        current=dict(state='quarantined',baseRevision=2)
        C.validate_decision_controls(enabled,'approver',current,2)
        self.reject(C.validate_decision_controls,disabled,'approver',current,2)
        for state,base,revision in (('admitted_local',2,8),('rejected',6,8),('quarantined',2,8)):
            candidate=dict(state=state,baseRevision=base)
            C.validate_decision_controls(disabled,'approver',candidate,revision)
            self.reject(C.validate_decision_controls,enabled,'approver',candidate,revision)
        C.validate_decision_controls(disabled,'approver',None,None)
        for role in ('operator','viewer','auditor','anonymous'):
            C.validate_decision_controls(disabled,role,current,2)
            self.reject(C.validate_decision_controls,enabled,role,current,2)
    def test_15_nodes_private_address_rejected(self):
        n=nodes(1); n[0]['server']='private'; self.reject(C.safe_nodes,n)
    def test_16_node_label_must_match_actual_id(self):
        n=nodes(1); n[0]['label']='private-name'; self.reject(C.safe_nodes,n)
    def test_17_node_credential_status_must_be_true(self):
        n=nodes(1); n[0]['credentialConfigured']=False; self.reject(C.safe_nodes,n)
    def test_18_admission_never_claims_node_healthy(self):
        n=nodes(1); n[0]['state']='healthy'; self.reject(C.safe_nodes,n)
    def test_19_nodes_are_id_sorted_not_protocol_order(self):
        C.safe_nodes(nodes(1)); self.reject(C.safe_nodes,list(reversed(nodes(1))))
        # The actual rendered collector omits API's label after checking it.
        dom_nodes=[{k:v for k,v in node.items() if k!='label'} for node in nodes(1)]
        self.assertEqual(set(dom_nodes[0]),{'id','protocol','credentialConfigured','state'})
    def test_20_same_clock_finish_before_headers_is_valid(self):
        r,v=fixture(); f=C.reconstruct(r,v); states=C.possible_states(dict(startTimeUs=1001,endTimeUs=1011,headerTimeUs=1020),f); self.assertEqual(len(states),2)
    def test_21_wall_clock_not_used_for_state_window(self):
        r,v=fixture(); f=C.reconstruct(r,v); a=C.possible_states(dict(startTimeUs=900,endTimeUs=950,startedWallTimeUs=0),f); b=C.possible_states(dict(startTimeUs=900,endTimeUs=950,startedWallTimeUs=9999999999999),f); self.assertEqual(a,b)
    def test_22_role_steps_exactly_cover_fixed_plan(self):
        self.assertEqual(len(C.STEPS),37); self.assertEqual(C.role_for_step('admitted_a2'),'approver'); self.assertEqual(C.role_for_step('cleared'),'anonymous'); self.assertEqual(C.role_for_step('viewer_a'),'viewer')
    def test_23_source_private_field_rejected(self):
        r,v=fixture(); f=C.reconstruct(r,v); s=copy.deepcopy(next(iter(f['states'][-1]['sources'].values()))); s['url']='private'; self.reject(C.safe_source,s)
    def test_24_source_bool_revision_rejected(self):
        r,v=fixture(); f=C.reconstruct(r,v); s=copy.deepcopy(next(iter(f['states'][-1]['sources'].values()))); s['revision']=True; self.reject(C.safe_source,s)
    def test_25_twenty_original_audit_events_recomputed(self):
        _,_,f=full_facts(); rows,cp=audit_fixture(f); self.assertEqual(set(C.validate_audit(rows,cp,f)),{'operator','approver'})
    def test_26_audit_modified_domain_state_rejected(self):
        _,_,f=full_facts(); rows,cp=audit_fixture(f); rows[-1]['data']['revision']='7'; self.reject(C.validate_audit,rows,cp,f)
    def test_27_audit_missing_stage_rejected(self):
        _,_,f=full_facts(); rows,cp=audit_fixture(f); self.reject(C.validate_audit,rows[:-1],cp,f)
    def test_28_audit_checkpoint_bool_is_not_count(self):
        _,_,f=full_facts(); rows,cp=audit_fixture(f); cp['count']=True; self.reject(C.validate_audit,rows,cp,f)


if __name__=='__main__': unittest.main(verbosity=2)
