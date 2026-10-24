"""SYNTHETIC raw-HTTP models, not actual GET/Go/kernel/worker evidence.

fixture() is a pure model helper shared by the root's full-checker models.
It imports no producer or old apply test and creates no files/process/network.
"""
import base64
import copy
import hashlib
import json
import unittest
from unittest import mock

import get_projection as G


def wire(value):
    return (json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')


def hashed(raw):
    return hashlib.sha256(raw).hexdigest()


def bind(raw):
    return dict(sha256=hashed(raw), bytes=len(raw))


def b64(raw):
    return base64.b64encode(raw).decode('ascii')


def model_proxy(name, kind, number, now=None):
    value = dict(type=kind, history=[], extra={}, alive=True, name=name, udp=kind == 'Direct',
                 uot=False, xudp=False, tfo=False, mptcp=False, smux=False,
                 interface='', **{'routing-mark': 0, 'provider-name': '', 'dialer-proxy': ''})
    if kind == 'Selector':
        value.update(now=now, all=['apply-a', 'apply-b'], testUrl='', hidden=False,
                     icon='', emptyFallback='COMPATIBLE')
    else:
        value['id'] = '00000000-0000-0000-0000-' + str(number).zfill(12)
    return value


def model_round(target):
    general = json.loads(G.GENERAL_TEMPLATE)
    general['mixed-port'] = 28411
    proxies = {'DIRECT': model_proxy('DIRECT', 'Direct', 1),
               'apply-a': model_proxy('apply-a', 'Http', 2),
               'apply-b': model_proxy('apply-b', 'Http', 3),
               '默认策略': model_proxy('默认策略', 'Selector', 0, target)}
    rule = dict(index=0, type='Match', payload='', proxy='默认策略', size=-1,
                extra=dict(disabled=False, hitCount=0, hitAt='0001-01-01T00:00:00Z',
                           missCount=0, missAt='0001-01-01T00:00:00Z'))
    return [wire(dict(meta=True, version='v1.19.32')), wire(general),
            wire(dict(proxies=proxies)), wire(dict(rules=[rule]))]


def fixture():
    """Return (18 invented capture originals, partial v2 report); no execution."""
    raw, phases = {}, {}
    for phase, target in [('baseline', 'apply-a'), ('candidate', 'apply-b')]:
        bodies = model_round(target)
        for ordinal in range(1, 9):
            raw[phase + '-get-' + str(ordinal).zfill(2) + '.body'] = bodies[(ordinal - 1) % 4]
        phases[phase] = G.projection_from_bodies(*bodies)[0]
    report = dict(schema='chengwang.mihomo-runtime-apply-report/v2', getEvidence={}, readbacks={},
                  flags=dict(apiExercised=False, authorizationExercised=False, authorizationProven=False,
                    fullPayloadProven=False, headAdvanced=False, production=False, perGetRawEvidenceAvailable=True,
                    independentProjectionRecomputeProven=False, internetBusinessProven=False))
    for phase in ('baseline', 'candidate'):
        records, schedule, total = [], [], 0
        for i in range(1, 9):
            kind = ('VERSION', 'CONFIGS', 'PROXIES', 'RULES')[(i - 1) % 4]
            round_ = 1 + (i - 1) // 4
            schedule.append(dict(ordinal=i, round=round_, endpointKind=kind))
            body = raw[phase + '-get-' + str(i).zfill(2) + '.body']
            total += len(body)
            records.append(dict(ordinal=i, round=round_, endpointKind=kind, requestBuilt=True,
                doInvoked=True, responseObserved=True, statusCode=200,
                headers=dict(contentTypeValuesB64=[b64(b'application/json')], contentEncodingValuesB64=[],
                             transferEncodingValuesB64=[], setCookieCount=0),
                contentLength=len(body), uncompressed=False, readAttempted=True, retainedBytes=len(body),
                retainedSHA256=hashed(body), naturalEOF=True, readErrorClass='NONE', limitReached=False,
                closeAttempted=True, closeErrorClass='NONE', contextState='ACTIVE',
                parseState='SHAPE_ACCEPTED', terminalClass='NONE'))
        transcript = dict(schema='chengwang.mihomo-lab-get-evidence/v1',
            scope='PRIVATE_HTTP_ENTITY_RESPONSE_EVIDENCE_NOT_AUTHORIZATION_OR_PAYLOAD_PROOF',
            expectedSchedule=schedule, records=records, slotsEntered=8, doInvocations=8,
            responsesObserved=8, readAttempts=8, completedBodies=8, retainedBytes=total,
            outcome='COMPLETE', failureClass=None, limitReached=False, contextState='ACTIVE')
        name = phase + '-get-evidence.json'
        raw[name] = wire(transcript)
        report['getEvidence'][phase] = bind(raw[name])
        report['readbacks'][phase] = dict(conclusion='STABLE_OLD_PROJECTION' if phase == 'baseline' else 'STABLE_NEW_PROJECTION',
            sampleCount=2, requestsObserved=8, previousProjectionSHA256=phases['baseline'],
            candidateProjectionSHA256=phases['candidate'], observedProjectionSHA256=phases[phase],
            dataplaneProven=False, fullPayloadProven=False, authorizationProven=False, production=False)
    return raw, report


def full_fixture():
    captures, report = fixture()
    # These18 opaque old inputs are outside this module's semantic scope;
    # the root checker models supply their real model structures separately.
    raw = {name: b'SYNTHETIC_OLD_ORIGINAL_NOT_VERIFIED_BY_THIS_MODULE' for name in G.PUBLIC}
    raw.update(captures)
    return raw, report


def reseal(raw, report, phase):
    """Coherently rehash transcript/body metadata after a deliberate mutation."""
    name = phase + '-get-evidence.json'
    transcript = json.loads(raw[name])
    total = 0
    for i, row in enumerate(transcript['records'], 1):
        body = raw[phase + '-get-' + str(i).zfill(2) + '.body']
        row['retainedBytes'], row['retainedSHA256'] = len(body), hashed(body)
        if row['contentLength'] != -1:
            row['contentLength'] = len(body)
        total += len(body)
    transcript['retainedBytes'] = total
    raw[name] = wire(transcript)
    report['getEvidence'][phase] = bind(raw[name])


def set_json(raw, name, change):
    value = json.loads(raw[name]); change(value); raw[name] = wire(value)


def recapture_metadata(raw, report, phase, change):
    name = phase + '-get-evidence.json'
    set_json(raw, name, change)
    report['getEvidence'][phase] = bind(raw[name])


class SyntheticGetProjectionModels(unittest.TestCase):
    def reject(self, raw, report):
        with self.assertRaisesRegex(ValueError, '^captured laboratory GET evidence rejected$'):
            G.verify_captured(raw, report)

    def reject_meta(self, change):
        raw, report = full_fixture(); recapture_metadata(raw, report, 'baseline', change); self.reject(raw, report)

    def reject_body(self, ordinal, change):
        raw, report = full_fixture(); name='baseline-get-'+str(ordinal).zfill(2)+'.body'
        set_json(raw,name,change)
        # Isolate the raw semantic gate before unchanged round2/summary can
        # mask it. All callers of this helper deliberately make invalid data.
        bodies=[raw['baseline-get-'+str(i).zfill(2)+'.body'] for i in range(1,5)]
        with self.assertRaises(ValueError):G.projection_from_bodies(*bodies)
        reseal(raw,report,'baseline'); self.reject(raw,report)

    def test_synthetic_success_proves_observed_projection_not_private_source_or_fence(self):
        raw, report = full_fixture(); summary = G.verify_captured(raw, report)
        self.assertTrue(summary['perGetRawEvidenceAvailable']); self.assertTrue(summary['independentProjectionRecomputeProven'])
        self.assertFalse(summary['expectedSourceIndependentlyProven']); self.assertFalse(summary['privateDisclosureFenceIndependentlyProven'])
        self.assertFalse(summary['production']); self.assertEqual(set(summary['phases']),{'baseline','candidate'})
        self.assertNotIn('proxies',json.dumps(summary)); self.assertNotIn('contentTypeValuesB64',json.dumps(summary))

    def test_fixed18_capture_and_full36_closed_sets(self):
        expected=tuple(n for p in ('baseline','candidate') for n in (p+'-get-evidence.json',*(p+'-get-'+str(i).zfill(2)+'.body' for i in range(1,9))))
        self.assertEqual(G.CAPTURE_FILES,expected); self.assertEqual(len(G.PUBLIC),36)
        for mode in ('missing','extra','private'):
            raw,report=full_fixture()
            if mode=='missing':del raw['baseline-get-01.body']
            elif mode=='extra':raw['unexpected.body']=b'{}'
            else:raw['.secrets.private.json']=b'SYNTHETIC_PRIVATE'
            self.reject(raw,report)

    def test_v1_report_or_unavailable_and_self_claimed_proof_rejects(self):
        for key,value in [('schema','chengwang.mihomo-runtime-apply-report/v1'),('getEvidence',None)]:
            raw,report=full_fixture();report[key]=value;self.reject(raw,report)
        for key,value in [('perGetRawEvidenceAvailable',False),('independentProjectionRecomputeProven',True),
                          ('production',True),('apiExercised',0)]:
            raw,report=full_fixture();report['flags'][key]=value;self.reject(raw,report)

    def test_transcript_raw_hash_and_length_are_bound(self):
        for key,value in [('sha256','c'*64),('bytes',1),('bytes',True),('bytes',1.0)]:
            raw,report=full_fixture();report['getEvidence']['baseline'][key]=value;self.reject(raw,report)

    def test_metadata_exact_keys_order_alias_and_unknown_fields(self):
        self.reject_meta(lambda t:t.__setitem__('sourceURL','http://127.0.0.1/private'))
        self.reject_meta(lambda t:t.__setitem__('Schema',t.pop('schema')))
        self.reject_meta(lambda t:t['records'][0].__setitem__('body','not-a-permitted-field'))
        raw,report=full_fixture();t=json.loads(raw['baseline-get-evidence.json']);t=dict(reversed(list(t.items())))
        raw['baseline-get-evidence.json']=wire(t);report['getEvidence']['baseline']=bind(raw['baseline-get-evidence.json']);self.reject(raw,report)

    def test_schedule_and_entered_slots_must_be_exact_eight(self):
        for key,value in [('ordinal',0),('ordinal',True),('round',2),('endpointKind','PROXIES')]:
            self.reject_meta(lambda t,k=key,v=value:t['expectedSchedule'][0].__setitem__(k,v))
        self.reject_meta(lambda t:t['records'].pop());self.reject_meta(lambda t:t['records'].append(copy.deepcopy(t['records'][0])))

    def test_each_slot_success_types_status_close_eof_and_context(self):
        for key,value in [('requestBuilt',1),('doInvoked',False),('responseObserved',False),('statusCode',True),('statusCode',204),
            ('uncompressed',True),('readAttempted',False),('naturalEOF',False),('readErrorClass','IO'),('limitReached',True),
            ('closeAttempted',False),('closeErrorClass','IO'),('contextState','DEADLINE'),('parseState','JSON_ACCEPTED'),('terminalClass','SHAPE')]:
            self.reject_meta(lambda t,k=key,v=value:t['records'][0].__setitem__(k,v))

    def test_counts_and_retained_totals_are_recomputed_not_summary_trusted(self):
        for key,value in [('slotsEntered',0),('doInvocations',9),('responsesObserved',True),('readAttempts',8.0),('completedBodies',7),('retainedBytes',0)]:
            self.reject_meta(lambda t,k=key,v=value:t.__setitem__(k,v))
        self.reject_meta(lambda t:t.__setitem__('outcome','FAILED'));self.reject_meta(lambda t:t.__setitem__('failureClass','CLOSE'))

    def test_raw_body_hash_size_and_known_content_length_reject(self):
        for key,value in [('retainedSHA256','c'*64),('retainedBytes',0),('retainedBytes',True),('contentLength',0),('contentLength',-2)]:
            self.reject_meta(lambda t,k=key,v=value:t['records'][0].__setitem__(k,v))
        raw,report=full_fixture();raw['baseline-get-01.body']+=b' ';self.reject(raw,report)

    def test_unknown_length_and_parsed_chunked_are_supported_without_synthetic_eof(self):
        raw,report=full_fixture()
        def edit(t):
            for row in t['records']:
                row['contentLength']=-1;row['headers']['transferEncodingValuesB64']=[b64(b'chunked')]
        recapture_metadata(raw,report,'baseline',edit);G.verify_captured(raw,report)
        recapture_metadata(raw,report,'baseline',lambda t:t['records'][0].__setitem__('contentLength',t['records'][0]['retainedBytes']))
        self.reject(raw,report)

    def test_canonical_base64_missing_vs_null_and_encoded_header_bounds(self):
        for value in ([b64(b'application/json')+'='],['not base64!'],None,[],[b64(b'application/json')]*2):
            self.reject_meta(lambda t,v=value:t['records'][0]['headers'].__setitem__('contentTypeValuesB64',v))
        self.reject_meta(lambda t:t['records'][0]['headers'].__setitem__('contentEncodingValuesB64',None))
        self.reject_meta(lambda t:t['records'][0]['headers'].__setitem__('contentTypeValuesB64',[b64(b'a'*(16385))]))

    def test_go_mime_valid_parameters_quotes_equal_duplicates_and_continuations(self):
        for value in (b'Application/JSON; charset="UTF-8"',b'application/json;',
                      b'application/json;charset=utf-8;CHARSET=utf-8',
                      b"application/json; charset*=utf-8''utf-8",b'application/json; charset*0=utf-; charset*1=8',
                      'appl\u0130cation/json'.encode('utf-8')):
            raw,report=full_fixture();recapture_metadata(raw,report,'baseline',lambda t,v=value:t['records'][0]['headers'].__setitem__('contentTypeValuesB64',[b64(v)]));G.verify_captured(raw,report)

    def test_go_mime_bad_parameters_duplicates_and_content_encodings_reject(self):
        for value in (b'text/json',b'application/json;foo=bar',b'application/json;charset=ascii',
                      b'application/json;charset=utf-8;charset=UTF-8',b'application/json;;',b'application/json; charset="utf-8\r\n"'):
            self.reject_meta(lambda t,v=value:t['records'][0]['headers'].__setitem__('contentTypeValuesB64',[b64(v)]))
        for key,value in [('contentEncodingValuesB64',[b64(b'gzip')]),('transferEncodingValuesB64',[b64(b'identity')]),('setCookieCount',1)]:
            self.reject_meta(lambda t,k=key,v=value:t['records'][0]['headers'].__setitem__(k,v))

    def test_duplicate_escaped_keys_surrogates_invalid_utf8_numbers_and_depth(self):
        for body in (b'{"meta":true,"\\u006deta":true,"version":"v1.19.32"}',b'{"meta":true,"version":"\\ud800"}',b'\xff',
                     b'{"meta":true,"version":NaN}',b'{"meta":true,"version":-0}',b'['*26+b'0'+b']'*26):
            raw,report=full_fixture();raw['baseline-get-01.body']=body;reseal(raw,report,'baseline');self.reject(raw,report)
        self.reject_body(2,lambda g:g.__setitem__('mixed-port',28411.0))
        raw,report=full_fixture();raw['baseline-get-03.body']=raw['baseline-get-03.body'].replace(b'"routing-mark":0',b'"routing-mark":-0',1)
        bodies=[raw['baseline-get-'+str(i).zfill(2)+'.body'] for i in range(1,5)]
        with self.assertRaises(ValueError):G.projection_from_bodies(*bodies)
        reseal(raw,report,'baseline');self.reject(raw,report)

    def test_version_is_validated_before_projection_hashing(self):
        for key,value in [('meta',1),('version','v1.19.33'),('unexpected',False)]:
            self.reject_body(1,lambda v,k=key,x=value:v.__setitem__(k,x))

    def test_general_shape_types_unknown_fields_and_fixed_enum_bounds(self):
        for key,value in [('unknown',False),('mixed-port',True),('mixed-port',65536),('mode','auto'),('geodata-loader','unknown')]:
            self.reject_body(2,lambda g,k=key,v=value:g.__setitem__(k,v))
        self.reject_body(2,lambda g:g.pop('tun'));self.reject_body(2,lambda g:g['tun'].__setitem__('stack','other'))

    def test_credential_bearing_general_fields_reject_even_coherent_raw_hashes(self):
        for key in ('certificate','private-key','ech-key'):
            self.reject_body(2,lambda g,k=key:g['tuic-server'].__setitem__(k,'SYNTHETIC_PRIVATE'))
        for key in ('ss-config','vmess-config'):
            self.reject_body(2,lambda g,k=key:g.__setitem__(k,'SYNTHETIC_PRIVATE'))

    def test_map_order_ignored_but_null_and_empty_array_remain_distinct(self):
        self.assertEqual(G.go_codec({'z':1,'a':2}),b'{"a":2,"z":1}')
        self.assertNotEqual(G.go_codec(None),G.go_codec([]))
        raw,report=full_fixture()
        for ordinal in (2,6):
            name='baseline-get-'+str(ordinal).zfill(2)+'.body';value=json.loads(raw[name]);raw[name]=wire(dict(reversed(list(value.items()))))
        reseal(raw,report,'baseline');G.verify_captured(raw,report)

    def test_proxy_fields_unknown_alias_boolean_and_routing_integer_reject(self):
        for key,value in [('udp',1),('routing-mark',True),('routing-mark',1<<31),('extraField',None),('Name','apply-a')]:
            self.reject_body(3,lambda v,k=key,x=value:v['proxies']['apply-a'].__setitem__(k,x))

    def test_uuid_witness_rejects_invalid_or_cross_round_changed_ids(self):
        bodies=model_round('apply-a')
        witness=G.projection_from_bodies(*bodies)[1]
        expected=b'{"DIRECT":"00000000-0000-0000-0000-000000000001","apply-a":"00000000-0000-0000-0000-000000000002","apply-b":"00000000-0000-0000-0000-000000000003"}'
        self.assertEqual(witness,hashed(expected))
        self.reject_body(3,lambda v:v['proxies']['apply-a'].__setitem__('id','FFFFFFFF-0000-0000-0000-000000000001'))
        raw,report=full_fixture();set_json(raw,'baseline-get-07.body',lambda v:v['proxies']['apply-a'].__setitem__('id','00000000-0000-0000-0000-000000000099'))
        reseal(raw,report,'baseline');self.reject(raw,report)

    def test_valid_telemetry_is_validated_then_excluded_not_silently_trusted(self):
        raw,report=full_fixture()
        def edit(v):
            row=v['proxies']['apply-a'];row['alive']=False;row['history']=[dict(time='2026-10-25T1:02:03,123Z',delay=65535)]
            row['extra']={'HTTPS://example.com:99999/check?':dict(alive=False,history=None)}
        set_json(raw,'baseline-get-07.body',edit);reseal(raw,report,'baseline');G.verify_captured(raw,report)
        self.reject_body(3,lambda v:v['proxies']['apply-a'].__setitem__('history',None))
        self.reject_body(3,lambda v:v['proxies']['apply-a'].__setitem__('history',[dict(time='2026-01-01T00:00:00Z',delay=True)]))

    def test_invalid_telemetry_url_or_history_cannot_hide_in_excluded_data(self):
        for url in ('https://user@example.com/', 'https://example.com/?token=x','https://example.com/#x','https://example.com:abc/','https://example.com/%zz'):
            self.reject_body(3,lambda v,u=url:v['proxies']['apply-a'].__setitem__('extra',{u:dict(alive=True,history=[])}))
        self.reject_body(3,lambda v:v['proxies']['apply-a'].__setitem__('history',[dict(time='2026-02-30T00:00:00Z',delay=1)]))

    def test_selector_member_reference_duplicate_now_and_type_reject(self):
        bodies=model_round('apply-a');original=G.projection_from_bodies(*bodies)[0]
        proxies=json.loads(bodies[2]);proxies['proxies']['默认策略']['all'].reverse();bodies[2]=wire(proxies)
        self.assertNotEqual(G.projection_from_bodies(*bodies)[0],original)
        for key,value in [('now','missing'),('all',['apply-a','apply-a']),('all',['missing']),('hidden',0)]:
            self.reject_body(3,lambda v,k=key,x=value:v['proxies']['默认策略'].__setitem__(k,x))
        self.reject_body(3,lambda v:v['proxies']['DIRECT'].__setitem__('type','Reject'))

    def test_rule_order_index_size_domain_payload_and_reference_reject(self):
        bodies=model_round('apply-a');rule=json.loads(bodies[3])['rules'][0]
        first=copy.deepcopy(rule);first.update(index=0,type='DomainSuffix',payload='one.example')
        second=copy.deepcopy(rule);second.update(index=1,type='DomainSuffix',payload='two.example')
        bodies[3]=wire(dict(rules=[first,second]));original=G.projection_from_bodies(*bodies)[0]
        first['index'],second['index']=1,0;bodies[3]=wire(dict(rules=[second,first]))
        self.assertNotEqual(G.projection_from_bodies(*bodies)[0],original)
        for key,value in [('index',1),('index',False),('size',0),('type','IPCIDR'),('payload','nonempty'),('proxy','missing')]:
            self.reject_body(4,lambda v,k=key,x=value:v['rules'][0].__setitem__(k,x))
        def domain(v):v['rules'][0].update(type='DomainSuffix',payload='EXAMPLE.COM')
        self.reject_body(4,domain)

    def test_rule_telemetry_uint64_time_and_disabled_are_strict(self):
        for key,value in [('hitCount',-1),('hitCount',1<<64),('hitCount',True),('hitAt','0000-01-01T00:00:00Z'),('missAt','2026-01-01T00:00:60Z'),('disabled',0)]:
            self.reject_body(4,lambda v,k=key,x=value:v['rules'][0]['extra'].__setitem__(k,x))

    def test_different_full_observed_samples_reject_after_coherent_rehash(self):
        raw,report=full_fixture();set_json(raw,'baseline-get-06.body',lambda g:g.__setitem__('log-level','info'))
        reseal(raw,report,'baseline');self.reject(raw,report)

    def test_summary_observed_and_expected_hash_relationships_are_cross_checked(self):
        raw,report=full_fixture();report['readbacks']['baseline']['observedProjectionSHA256']='c'*64;self.reject(raw,report)
        raw,report=full_fixture();report['readbacks']['candidate']['previousProjectionSHA256']='c'*64;self.reject(raw,report)
        raw,report=full_fixture();report['readbacks']['baseline']['dataplaneProven']=True;self.reject(raw,report)

    def test_valid_coherent_drift_does_not_gain_private_expected_source_proof(self):
        raw,report=full_fixture();digests={}
        for phase in ('baseline','candidate'):
            for ordinal in (2,6):set_json(raw,phase+'-get-'+str(ordinal).zfill(2)+'.body',lambda g:g.__setitem__('log-level','info'))
            reseal(raw,report,phase)
            bodies=[raw[phase+'-get-'+str(i).zfill(2)+'.body'] for i in range(1,5)]
            digests[phase]=G.projection_from_bodies(*bodies)[0]
        for phase in ('baseline','candidate'):
            report['readbacks'][phase].update(previousProjectionSHA256=digests['baseline'],candidateProjectionSHA256=digests['candidate'],observedProjectionSHA256=digests[phase])
        summary=G.verify_captured(raw,report);self.assertFalse(summary['expectedSourceIndependentlyProven'])

    def test_body_limit_and_transcript_limit_reject_without_new_requests(self):
        raw,report=full_fixture();raw['baseline-get-01.body']=b' '*(8*1024*1024+1);reseal(raw,report,'baseline');self.reject(raw,report)
        raw,report=full_fixture();raw['baseline-get-evidence.json']=b' '*(1024*1024+1);report['getEvidence']['baseline']=bind(raw['baseline-get-evidence.json']);self.reject(raw,report)
        def too_many_proxies(v):
            v['proxies'].update({'node-'+str(i):model_proxy('node-'+str(i),'Http',i+10) for i in range(393)})
        proxies=json.loads(model_round('apply-a')[2]);too_many_proxies(proxies)
        with self.assertRaises(ValueError):G._proxies(proxies)
        self.reject_body(3,too_many_proxies)
        def too_many_rules(v):
            original=v['rules'][0];v['rules']=[dict(copy.deepcopy(original),index=i) for i in range(2050)]
        rules=json.loads(model_round('apply-a')[3]);too_many_rules(rules)
        with self.assertRaises(ValueError):G._rules(rules,{'默认策略'})
        self.reject_body(4,too_many_rules)
        def too_many_members(v):
            names=['默认策略']+['node-'+str(i).zfill(3) for i in range(1,392)];proxies={}
            for i,name in enumerate(names):
                row=model_proxy(name,'Selector' if i<169 else 'Http',i+10,names[0])
                if i<169:row['all']=list(names)
                proxies[name]=row
            v['proxies']=proxies
        proxies=json.loads(model_round('apply-a')[2]);too_many_members(proxies)
        with self.assertRaises(ValueError):G._proxies(proxies)
        self.reject_body(3,too_many_members)

    def test_unicode_version_drift_is_explicit_failclosed(self):
        raw,report=full_fixture()
        with mock.patch.object(G.unicodedata,'unidata_version','16.0.0'):
            with self.assertRaisesRegex(ValueError,'^captured projection requires Unicode 15.0.0$'):G.verify_captured(raw,report)

    def test_source_grounded_go_codec_html_utf8_map_struct_and_null_vectors(self):
        # Literal vectors derived from fixed Go json.Marshal source semantics;
        # they are NOT claimed to have been generated by a Go run in this test.
        self.assertEqual(G.go_codec({'z':'<>&\u2028\u2029','a':'中文'}),'{"a":"中文","z":"\\u003c\\u003e\\u0026\\u2028\\u2029"}'.encode())
        self.assertEqual(G.go_codec(G._Struct((('z',None),('a',[])))),b'{"z":null,"a":[]}')
        self.assertEqual(G.go_codec({'x':-(1<<31),'y':(1<<64)-1}),b'{"x":-2147483648,"y":18446744073709551615}')

    def test_source_grounded_go_time_fallback_vectors_preserve_accepted_edges(self):
        for value in ('0001-01-01T00:00:00+24:60','9999-12-31T23:59:59-24:60','2026-10-25T1:02:03,123Z','2026-10-25T01:02:03.123456789012Z'):
            G.go_timestamp(value)
        for value in ('0000-01-01T00:00:00Z','2026-02-30T00:00:00Z','2026-01-01T24:00:00Z','2026-01-01T00:00:00+25:00','2026-01-01T00:00:00+00:61','2026-01-01t00:00:00z'):
            with self.assertRaises(ValueError):G.go_timestamp(value)

    def test_error_surface_never_reflects_body_header_or_private_text(self):
        raw,report=full_fixture();raw['baseline-get-01.body']=b'SYNTHETIC_PRIVATE_ERROR_MARKER';reseal(raw,report,'baseline')
        with self.assertRaises(ValueError) as raised:G.verify_captured(raw,report)
        self.assertEqual(str(raised.exception),'captured laboratory GET evidence rejected')


if __name__ == '__main__':
    unittest.main()
