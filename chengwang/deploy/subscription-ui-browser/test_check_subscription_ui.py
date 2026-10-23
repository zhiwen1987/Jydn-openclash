"""Pure synthetic counterexamples, never real browser or product evidence."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import zlib

_spec=importlib.util.spec_from_file_location('subscription_ui_checker_under_test',Path(__file__).with_name('check_subscription_ui.py'))
C=importlib.util.module_from_spec(_spec); _spec.loader.exec_module(C)
COMMIT='1'*40
FIXTURE='2'*32
SID='src_'+'3'*32
CMD='cmd_'+'4'*32
ACTOR='act_'+'5'*60
DATE='2026-10-24T00:00:00Z'


def sample_source(): return dict(id=SID,scope=dict(C.SCOPE),label='browser-ui-source',revision=1,updatedAt=DATE)
def sample_receipt():
    return dict(commandId=CMD,kind='create',sourceId=SID,revision=1,state='committed',replayed=False,
        stateMayHaveChanged=False,auditRecorded=True,preparedAuditHash='a'*64,resultAuditHash='b'*64,
        localAuditHash='c'*64,completedAt=DATE)
def sample_build():
    files=[dict(path=p,bytes=1,sha256=C.sha(b'x')) for p in ('.vite/manifest.json','assets/main.js','index.html','trust.html')]
    return dict(schema='chengwang.subscription-ui-build/v1',sourceCommit=COMMIT,goVersion='go1.23.12',nodeVersion='v22.23.3',moduleMode='vendor',goDependencyDownloads=False,
        server=dict(name='server',bytes=99,sha256='9'*64),distFiles=files,production=False,authorization='BLOCKED')


def png_sample(width=2,height=2):
    def chunk(kind,body): return struct.pack('>I',len(body))+kind+body+struct.pack('>I',zlib.crc32(kind+body)&0xffffffff)
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,6,0,0,0))+chunk(b'IDAT',zlib.compress((b'\0'+b'\1'*(width*4))*height))+chunk(b'IEND',b'')


def capture_sample():
    build=sample_build(); build['distFiles'][1].update(bytes=1,sha256=C.sha(b'x')); build['distFiles'][2].update(bytes=1,sha256=C.sha(b'x'))
    rc=sample_receipt(); source=sample_source(); access=dict(scope=C.SCOPE,resource=dict(type='subscription-store',id='local'),writesEnabled=True,
        actions=['subscription.read','subscription.source.manage'],policyState='not_configured',references=[])
    access_source=copy.deepcopy(access); access_source.update(resource=dict(type='subscription-source',id=SID),actions=['subscription.read','subscription.import','subscription.fetch'])
    payloads=[('DOCUMENT','/',b'x'),('ASSET','/assets/main.js',b'x'),('SNAPSHOT','/api/v1/snapshot',b'{}'),
        ('COLLECTION_ACCESS',C.BASE+'/access',access),('SOURCES',C.BASE+'/sources',dict(sources=[],total=0)),
        ('CREATE',C.BASE+'/sources',rc),('COLLECTION_ACCESS',C.BASE+'/access',access),('SOURCES',C.BASE+'/sources',dict(sources=[source],total=1)),
        ('SOURCE_ACCESS',C.BASE+'/sources/'+SID+'/access',access_source),('CANDIDATES',C.BASE+'/sources/'+SID+'/candidates?limit=20&offset=0&revision=1',dict(candidates=[],total=0,revision=1)),
        ('RECEIPT',C.BASE+'/commands/'+CMD,rc)]
    rows=[]
    for n,(kind,path,body) in enumerate(payloads,1):
        if type(body) is dict: body=json.dumps(dict(boundary='LOCAL_SUBSCRIPTION_ADMISSION_ONLY',authorization='BLOCKED',deviceActionsExecuted=False,stateMayHaveChanged=False,result=body),separators=(',',':')).encode()+b'\n'
        rows.append(dict(schema='chengwang.subscription-ui-capture/v1',ordinal=n,requestOrdinal=n,requestId=str(n),method='POST' if kind=='CREATE' else 'GET',path=path,kind=kind,status=200,
            authorizationPresent=n>=4,requestPublic=dict(label='browser-ui-source',idempotencyKey='sub_'+'7'*32) if kind=='CREATE' else None,responseBase64=base64.b64encode(body).decode(),responseSHA256=C.sha(body),responseBytes=len(body),
            startedWallTimeUs=1792800000000000,startTimeUs=100,headerTimeUs=120,endTimeUs=110,terminal=dict(event='FINISH',encodedDataLength=len(body)+100)))
    return rows,build


def audit_sample():
    rc=sample_receipt(); stable=dict(**C.SCOPE,managementObject='local',kind='create',commandDigest='hmac-sha256:'+'6'*64)
    rows=[]; previous='0'*64
    for stage in ('prepared','result'):
        data=dict(stable)
        if stage=='result': data.update(state='committed',code='',sourceId=SID,candidateId='',revision='1',candidateDigest='',localAuditHash='c'*64,approvalId='',policyDigest='',policyRevision='0',stateMayHaveChanged='false')
        event=dict(id='event-'+stage,idempotencyKey='subscription/'+CMD+'/'+stage,traceId=CMD,actorId=ACTOR,action='subscription.command.'+stage,target='subscription/local',result=stage,occurredAt=DATE,data=data,previousHash=previous,hash='')
        event['hash']=C.sha(C.go_event_bytes(event)); previous=event['hash']; rows.append(event)
    rc.update(preparedAuditHash=rows[0]['hash'],resultAuditHash=rows[1]['hash'])
    facts=dict(receipt=rc,source=sample_source(),create=dict(startedWallTimeUs=1792800000000000,startTimeUs=100,endTimeUs=110))
    return rows,dict(count=2,lastHash=previous),facts


def private_sample(facts):
    rc=facts['receipt']; return dict(schema='chengwang.subscription-ui-private-readback/v1',sourceCommit=COMMIT,fixtureId=FIXTURE,scope=dict(C.SCOPE),sources=[sample_source()],candidates=[],localAuditCount=1,commandCount=1,approvalCount=0,
        commands=[dict(id=CMD,scope=dict(C.SCOPE),actorId=ACTOR,kind='create',expectedRevision=0,preparedAuditHash=rc['preparedAuditHash'],resultAuditHash=rc['resultAuditHash'],acknowledged=True,
            result={k:rc[k] for k in ('sourceId','revision','state','stateMayHaveChanged','localAuditHash','completedAt')})])


class CheckerContracts(unittest.TestCase):
    def reject(self,fn,*args):
        with self.assertRaises((ValueError,TypeError,KeyError)): fn(*args)

    def test_01_json_duplicate_key_rejected(self): self.reject(C.decode,b'{"a":1,"a":2}')
    def test_02_json_nan_rejected(self): self.reject(C.decode,b'{"a":NaN}')
    def test_03_boolean_is_not_integer(self): self.reject(C.integer,True)
    def test_04_same_rejects_false_as_zero(self): self.reject(C.same,False,0)
    def test_05_noncanonical_base64_rejected(self): self.reject(C.unbase64,'eB==',8)
    def test_06_valid_png_all_crcs(self): C.png(png_sample(),2,2)
    def test_07_png_bad_crc_rejected(self):
        raw=bytearray(png_sample()); raw[-1]^=1; self.reject(C.png,bytes(raw),2,2)
    def test_08_png_trailing_bytes_rejected(self): self.reject(C.png,png_sample()+b'x',2,2)
    def test_09_png_wrong_viewport_rejected(self): self.reject(C.png,png_sample(),375,2)
    def test_10_source_cross_scope_rejected(self):
        s=sample_source(); s['scope']['siteId']='foreign'; self.reject(C.source,s)
    def test_11_source_private_field_rejected(self):
        s=sample_source(); s['url']='private'; self.reject(C.source,s)
    def test_12_receipt_false_as_revision_rejected(self):
        rc=sample_receipt(); rc['revision']=True; self.reject(C.receipt,rc)
    def test_13_receipt_success_without_audit_rejected(self):
        rc=sample_receipt(); rc['auditRecorded']=False; self.reject(C.receipt,rc)
    def test_14_real_shape_captures_accept_finish_before_header(self):
        rows,b= capture_sample(); self.assertEqual(C.validate_captures(rows,b)['receipt']['commandId'],CMD)
        # Product JS contains a legal Bearer template; it is not a fixture
        # secret. Preserve API-leak rejection while accepting source assets.
        asset=b'const headers={Authorization:`Bearer ${token}`}'; row=rows[1]
        row.update(responseBase64=base64.b64encode(asset).decode(),responseSHA256=C.sha(asset),responseBytes=len(asset))
        b['distFiles'][1].update(bytes=len(asset),sha256=C.sha(asset))
        self.assertEqual(C.validate_captures(rows,b)['receipt']['commandId'],CMD)
    def test_15_capture_raw_sha_tamper_rejected(self):
        rows,b=capture_sample(); rows[5]['responseSHA256']='0'*64; self.reject(C.validate_captures,rows,b)
    def test_16_capture_raw_size_tamper_rejected(self):
        rows,b=capture_sample(); rows[5]['responseBytes']+=1; self.reject(C.validate_captures,rows,b)
    def test_17_capture_duplicate_request_rejected(self):
        rows,b=capture_sample(); rows[5]['requestId']=rows[4]['requestId']; self.reject(C.validate_captures,rows,b)
    def test_18_capture_missing_post_authorization_rejected(self):
        rows,b=capture_sample(); rows[5]['authorizationPresent']=False; self.reject(C.validate_captures,rows,b)
    def test_19_capture_wrong_label_rejected(self):
        rows,b=capture_sample(); rows[5]['requestPublic']['label']='other'; self.reject(C.validate_captures,rows,b)
    def test_20_capture_missing_idempotency_key_rejected(self):
        rows,b=capture_sample(); del rows[5]['requestPublic']['idempotencyKey']; self.reject(C.validate_captures,rows,b)
    def test_21_capture_receipt_is_readonly_rejected_post(self):
        rows,b=capture_sample(); rows[-1]['method']='POST'; self.reject(C.validate_captures,rows,b)
    def test_22_capture_finish_before_start_rejected(self):
        rows,b=capture_sample(); rows[0]['endTimeUs']=99; self.reject(C.validate_captures,rows,b)
    def test_23_build_exact_source_bound_shape(self): C.validate_build(sample_build(),COMMIT)
    def test_24_build_downloads_claim_rejected(self):
        b=sample_build(); b['goDependencyDownloads']=True; self.reject(C.validate_build,b,COMMIT)
    def test_25_build_traversal_rejected(self):
        b=sample_build(); b['distFiles'][0]['path']='../secret'; self.reject(C.validate_build,b,COMMIT)
    def test_26_audit_original_chain_recomputed(self):
        rows,cp,facts=audit_sample(); self.assertEqual(C.validate_audit(rows,cp,facts),ACTOR)
    def test_27_audit_modified_result_hash_rejected(self):
        rows,cp,facts=audit_sample(); rows[1]['data']['sourceId']='src_'+'f'*32; self.reject(C.validate_audit,rows,cp,facts)
    def test_28_audit_missing_prepared_rejected(self):
        rows,cp,facts=audit_sample(); self.reject(C.validate_audit,rows[1:],cp,facts)
    def test_29_audit_checkpoint_count_bool_rejected(self):
        rows,cp,facts=audit_sample(); cp['count']=True; self.reject(C.validate_audit,rows,cp,facts)
    def test_30_private_safe_projection_exact(self):
        _,_,f=audit_sample(); C.validate_private(private_sample(f),f,ACTOR,COMMIT,FIXTURE)
    def test_31_private_extra_command_rejected(self):
        _,_,f=audit_sample(); p=private_sample(f); p['commands'].append(copy.deepcopy(p['commands'][0])); self.reject(C.validate_private,p,f,ACTOR,COMMIT,FIXTURE)
    def test_32_private_secret_field_rejected(self):
        _,_,f=audit_sample(); p=private_sample(f); p['commands'][0]['fingerprint']='private'; self.reject(C.validate_private,p,f,ACTOR,COMMIT,FIXTURE)
    def test_33_private_candidate_without_import_rejected(self):
        _,_,f=audit_sample(); p=private_sample(f); p['candidates']=[{}]; self.reject(C.validate_private,p,f,ACTOR,COMMIT,FIXTURE)
    def test_34_stable_reader_rejects_symlink(self):
        # Synthetic lstat mode avoids requiring Windows symlink privilege.
        # The pure test proves the pre-open gate, not a live filesystem race.
        with mock.patch.object(Path,'lstat',return_value=mock.Mock(st_mode=0o120777,st_nlink=1,st_size=1)), mock.patch.object(C.os,'open') as opened:
            self.reject(C.read,Path('synthetic-link')); opened.assert_not_called()
    def test_35_stable_reader_empty_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'empty'; p.touch(); self.reject(C.read,p)
    def test_36_timestamp_exact_nanoseconds(self): self.assertEqual(C.timestamp('2026-10-24T00:00:00.123456789Z')%1000000000,123456789)


if __name__=='__main__': unittest.main(verbosity=2)
