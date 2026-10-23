"""Independent offline reconstruction of a partial, real subscription UI flow.

No browser or product process is launched here. Process/Store observations are
trusted CI projections, not independent host or private-database attestations.
"""
import argparse
import base64
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile
import zlib

BASE = '/api/v1/subscriptions'
ORIGIN = 'https://127.0.0.1:17891'
SCOPE = dict(tenantId='subscription-ui-lab', siteId='isolated', environment='candidate')
STEPS = ('anonymous', 'connected', 'prepared', 'cancelled', 'prepared_again',
         'created_desktop', 'created_mobile', 'receipt', 'hidden', 'returned', 'cleared')
PUBLIC = {'driver.json', 'captures.jsonl', 'dom.jsonl', 'created-desktop.png', 'created-mobile.png',
          'processes.json', 'isolation.json', 'inputs.json', 'certificates.json', 'pin-consumption.json',
          'private-readback.json', 'audit-events.jsonl', 'audit-checkpoint.json', 'build.json'}
CONTROLS = ('connect','clear','refresh_sources','prepare_create','refresh_source','prepare_import',
            'prepare_approve','prepare_fetch','prepare_admit','prepare_reject','prepare_rollback',
            'confirm','cancel','candidate_previous','candidate_next','node_previous','node_next','read_receipt')
TAG = '41520584daa68d0040db7746ae562a0ff82187f6'
ELF_SHA = 'ec4e78d65a5382c2b50aaf28c6a655a624973b3d3c711a2a4ae34369fd9a3444'
PIN_SHA = '404667848e68330c45b463702578967becb7c2857a174d5e5921364f898e8bea'
CAPTURE_KEYS = ('schema','ordinal','requestOrdinal','requestId','method','path','kind','status',
                'authorizationPresent','requestPublic','responseBase64','responseSHA256','responseBytes',
                'startedWallTimeUs','startTimeUs','headerTimeUs','endTimeUs','terminal')


def need(value):
    if not value: raise ValueError('subscription UI evidence rejected')


def exact(value, keys): need(type(value) is dict and set(value) == set(keys))
def integer(value, low=0, high=9007199254740991):
    need(type(value) is int and low <= value <= high)
    return value
def boolean(value): need(type(value) is bool)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def digest(value): need(type(value) is str and re.fullmatch('[a-f0-9]{64}', value)); return value
def identifier(value, prefix): need(type(value) is str and re.fullmatch(prefix + '_[a-f0-9]{32}', value)); return value
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def same(actual, expected):
    need(type(actual) is type(expected))
    if type(expected) is dict:
        exact(actual, expected)
        for key in expected: same(actual[key], expected[key])
    elif type(expected) is list:
        need(len(actual) == len(expected))
        for a, b in zip(actual, expected): same(a, b)
    else: need(actual == expected)


def decode(raw, allow_float=False):
    need(type(raw) is bytes and 0 < len(raw) <= 16 << 20)
    def unique(pairs):
        out = {}
        for key, value in pairs: need(key not in out); out[key] = value
        return out
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False))
    def bounded(item, depth=0):
        need(depth <= 20)
        if type(item) is dict:
            need(len(item) <= 8192)
            for key, child in item.items(): need(type(key) is str); bounded(child, depth+1)
        elif type(item) is list:
            need(len(item) <= 8192)
            for child in item: bounded(child, depth+1)
        elif type(item) is str: need(len(item) <= 12 << 20 and not any(0xD800 <= ord(c) <= 0xDFFF for c in item))
        else: need(item is None or type(item) in (bool,int) or allow_float and type(item) is float and math.isfinite(item))
    bounded(value)
    return value


def lines(raw, maximum=64):
    need(raw.endswith(b'\n') and 0 < len(raw.splitlines()) <= maximum)
    return [decode(line) for line in raw.splitlines()]


def read(path, maximum=16 << 20):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum)
    fd = os.open(path, os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_BINARY',0))
    try:
        opened = os.fstat(fd)
        with os.fdopen(fd,'rb',closefd=False) as handle: raw = handle.read(maximum+1)
        after, named = os.fstat(fd), path.lstat()
        identity = lambda v: (v.st_dev,v.st_ino,v.st_mode,v.st_size,v.st_mtime_ns,v.st_nlink)
        need(identity(before) == identity(opened) == identity(after) == identity(named)
             and before.st_ctime_ns == named.st_ctime_ns and opened.st_ctime_ns == after.st_ctime_ns
             and len(raw) == before.st_size)
        return raw
    finally: os.close(fd)


def unbase64(value, maximum):
    need(type(value) is str and 0 < len(value) <= (maximum+2)//3*4)
    raw = base64.b64decode(value,validate=True)
    need(len(raw) <= maximum and base64.b64encode(raw).decode('ascii') == value)
    return raw


def timestamp(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.[0-9]{1,9})?Z',value))
    whole, fraction = value[:-1], ''
    if '.' in whole: whole, fraction = whole.split('.')
    result = datetime.datetime.strptime(whole,'%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc)
    need(result.year > 1)
    return int(result.timestamp())*1000000000 + int((fraction+'0'*9)[:9])


def png(raw, width, height):
    """Check complete PNG framing, every CRC and bounded decompressed scanlines."""
    need(type(raw) is bytes and raw.startswith(b'\x89PNG\r\n\x1a\n') and len(raw) <= 8 << 20)
    at, chunks, compressed, header = 8, [], bytearray(), None
    while at < len(raw):
        need(at + 12 <= len(raw)); size = struct.unpack('>I',raw[at:at+4])[0]
        need(size <= 8 << 20 and at+12+size <= len(raw))
        kind, body = raw[at+4:at+8], raw[at+8:at+8+size]
        need(zlib.crc32(kind+body)&0xffffffff == struct.unpack('>I',raw[at+8+size:at+12+size])[0])
        need(re.fullmatch(b'[A-Za-z]{4}',kind) is not None)
        chunks.append(kind); at += size+12
        if kind == b'IHDR':
            need(header is None and len(chunks) == 1 and size == 13)
            header = struct.unpack('>IIBBBBB',body)
        elif kind == b'IDAT': compressed.extend(body)
        elif kind == b'IEND': need(size == 0 and at == len(raw))
        else: need(kind in (b'sRGB',b'gAMA',b'cHRM',b'pHYs',b'tEXt',b'iTXt'))
    need(header is not None and chunks[-1:] == [b'IEND'] and chunks.count(b'IEND') == 1
         and b'IDAT' in chunks and all(k == b'IDAT' for k in chunks[chunks.index(b'IDAT'):len(chunks)-1]))
    w,h,depth,color,compression,filtering,interlace = header
    need((w,h) == (width,height) and depth == 8 and color in (2,6) and compression == filtering == interlace == 0)
    stride = width*(3 if color == 2 else 4)+1; budget = stride*height
    z = zlib.decompressobj(); pixels = z.decompress(bytes(compressed),budget+1)
    need(z.eof and not z.unused_data and not z.unconsumed_tail and len(pixels) == budget)
    need(all(pixels[i*stride] <= 4 for i in range(height)))


def source(value):
    exact(value,('id','scope','label','revision','updatedAt')); identifier(value['id'],'src')
    same(value['scope'],SCOPE); same(value['revision'],1)
    need(value['label'] == 'browser-ui-source'); timestamp(value['updatedAt'])
    return value


def receipt(value):
    exact(value,('commandId','kind','sourceId','revision','state','replayed','stateMayHaveChanged',
                 'auditRecorded','preparedAuditHash','resultAuditHash','localAuditHash','completedAt'))
    identifier(value['commandId'],'cmd'); identifier(value['sourceId'],'src'); same(value['revision'],1)
    need(value['kind'] == 'create' and value['state'] == 'committed' and value['replayed'] is False
         and value['stateMayHaveChanged'] is False and value['auditRecorded'] is True)
    for key in ('preparedAuditHash','resultAuditHash','localAuditHash'): digest(value[key])
    timestamp(value['completedAt']); return value


def envelope(raw):
    value = decode(raw); exact(value,('boundary','authorization','deviceActionsExecuted','stateMayHaveChanged','result'))
    need(value['boundary'] == 'LOCAL_SUBSCRIPTION_ADMISSION_ONLY' and value['authorization'] == 'BLOCKED'
         and value['deviceActionsExecuted'] is False and value['stateMayHaveChanged'] is False)
    return value['result']


def access(value, object_type, object_id):
    exact(value,('scope','resource','writesEnabled','actions','policyState','references'))
    same(value['scope'],SCOPE); same(value['resource'],dict(type=object_type,id=object_id))
    need(value['writesEnabled'] is True and value['policyState'] == 'not_configured'); same(value['references'],[])
    # The fixture Operator has collection manage and source import/fetch, not approval/admission.
    same(value['actions'],['subscription.read','subscription.source.manage'] if object_type == 'subscription-store'
         else ['subscription.read','subscription.import','subscription.fetch'])


def validate_captures(rows, build):
    need(type(rows) is list and 1 <= len(rows) <= 64)
    ids, requests, values, decoded, total_bytes = set(), set(), {}, {}, 0
    for index,row in enumerate(rows,1):
        exact(row,CAPTURE_KEYS); same(row['ordinal'],index)
        need(row['schema'] == 'chengwang.subscription-ui-capture/v1'); integer(row['requestOrdinal'],1,64)
        need(row['requestOrdinal'] not in requests); requests.add(row['requestOrdinal'])
        need(type(row['requestId']) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',row['requestId']) and row['requestId'] not in ids)
        ids.add(row['requestId']); need(row['method'] in ('GET','POST')); same(row['status'],200); boolean(row['authorizationPresent'])
        for key in ('startedWallTimeUs','startTimeUs','headerTimeUs','endTimeUs'): integer(row[key],1)
        need(row['headerTimeUs'] >= row['startTimeUs'] and row['endTimeUs'] >= row['startTimeUs'])
        exact(row['terminal'],('event','encodedDataLength')); need(row['terminal']['event'] == 'FINISH')
        integer(row['terminal']['encodedDataLength'],1,16 << 20)
        kind = row['kind']; path = row['path']
        need(kind in ('DOCUMENT','ASSET','SNAPSHOT','COLLECTION_ACCESS','SOURCES','CREATE','SOURCE_ACCESS','CANDIDATES','RECEIPT'))
        body = unbase64(row['responseBase64'],8 << 20 if kind in ('DOCUMENT','ASSET') else 65536)
        total_bytes += len(body); need(total_bytes <= 16 << 20)
        same(row['responseBytes'],len(body)); need(sha(body) == digest(row['responseSHA256']))
        # A compiled product ASSET legitimately contains the Authorization
        # template's literal "Bearer ". Actual fixture-token variants are
        # scanned independently by both driver and supervisor before export.
        # API responses still reject this token-bearing header prefix.
        need(b'PRIVATE KEY' not in body and (kind=='ASSET' or b'Bearer ' not in body))
        values[index] = body
        if kind in ('DOCUMENT','ASSET'):
            need(row['method'] == 'GET' and row['authorizationPresent'] is False)
            relative = 'index.html' if kind == 'DOCUMENT' else path.lstrip('/')
            need(path == '/' if kind == 'DOCUMENT' else type(path) is str and re.fullmatch(r'/assets/[A-Za-z0-9_.-]+',path))
            matches = [f for f in build['distFiles'] if f['path'] == relative]; need(len(matches) == 1)
            same(dict(bytes=len(body),sha256=sha(body)),{k:matches[0][k] for k in ('bytes','sha256')})
        elif kind == 'SNAPSHOT':
            # Real product Snapshot.Pools[].LossRate is a float64. Subscription
            # DTOs, ordinals and security quantities keep their strict int gates.
            need(row['method'] == 'GET' and path == '/api/v1/snapshot' and row['authorizationPresent'] is False); decode(body,allow_float=True)
        else:
            need(row['authorizationPresent'] is True)
            result = envelope(body); decoded[index] = result
            if kind in ('COLLECTION_ACCESS','SOURCES','CREATE'): need(path == BASE + ('/access' if kind == 'COLLECTION_ACCESS' else '/sources'))
            elif kind == 'SOURCE_ACCESS': need(re.fullmatch(re.escape(BASE)+r'/sources/src_[a-f0-9]{32}/access',path))
            elif kind == 'CANDIDATES': need(re.fullmatch(re.escape(BASE)+r'/sources/src_[a-f0-9]{32}/candidates\?limit=20&offset=0&revision=1',path))
            else: need(re.fullmatch(re.escape(BASE)+r'/commands/cmd_[a-f0-9]{32}',path))
            if kind == 'CREATE':
                need(row['method'] == 'POST'); receipt(result)
                exact(row['requestPublic'],('label','idempotencyKey')); need(row['requestPublic']['label']=='browser-ui-source')
                need(type(row['requestPublic']['idempotencyKey']) is str and re.fullmatch(r'sub_[a-f0-9]{32}',row['requestPublic']['idempotencyKey']))
            else: need(row['method'] == 'GET')
        if kind != 'CREATE': need(row['requestPublic'] is None)
    need(requests == set(range(1,len(rows)+1)))
    kinds = {kind:[r for r in rows if r['kind'] == kind] for kind in ('DOCUMENT','ASSET','SNAPSHOT','COLLECTION_ACCESS','SOURCES','CREATE','SOURCE_ACCESS','CANDIDATES','RECEIPT')}
    need(len(kinds['DOCUMENT']) == len(kinds['SNAPSHOT']) == len(kinds['CREATE']) == len(kinds['SOURCE_ACCESS']) == len(kinds['CANDIDATES']) == len(kinds['RECEIPT']) == 1)
    need(len(kinds['ASSET']) >= 1 and len(kinds['SOURCES']) == len(kinds['COLLECTION_ACCESS']) == 2)
    need(len({r['path'] for r in kinds['ASSET']}) == len(kinds['ASSET']))
    created = decoded[kinds['CREATE'][0]['ordinal']]; receipt_read = decoded[kinds['RECEIPT'][0]['ordinal']]
    same(receipt_read,created); sid = created['sourceId']
    need(kinds['RECEIPT'][0]['path'] == BASE+'/commands/'+created['commandId'])
    pages = [decoded[r['ordinal']] for r in kinds['SOURCES']]
    for page in pages: exact(page,('sources','total')); integer(page['total'],0,1); need(type(page['sources']) is list and len(page['sources']) == page['total'])
    same(pages[0],dict(sources=[],total=0)); need(pages[1]['total'] == 1); actual_source = source(pages[1]['sources'][0]); need(actual_source['id'] == sid)
    for row in kinds['COLLECTION_ACCESS']: access(decoded[row['ordinal']],'subscription-store','local')
    access(decoded[kinds['SOURCE_ACCESS'][0]['ordinal']],'subscription-source',sid)
    need(kinds['SOURCE_ACCESS'][0]['path'] == BASE+'/sources/'+sid+'/access')
    candidates = decoded[kinds['CANDIDATES'][0]['ordinal']]; same(candidates,dict(candidates=[],total=0,revision=1))
    need(kinds['CANDIDATES'][0]['path'].startswith(BASE+'/sources/'+sid+'/candidates?'))
    create_request = kinds['CREATE'][0]['requestOrdinal']
    need(all(r['requestOrdinal'] < create_request for r in kinds['SOURCES'][:1]+kinds['COLLECTION_ACCESS'][:1]))
    need(all(r['requestOrdinal'] > create_request for r in kinds['SOURCES'][1:]+kinds['COLLECTION_ACCESS'][1:]+kinds['SOURCE_ACCESS']+kinds['CANDIDATES']+kinds['RECEIPT']))
    return dict(source=actual_source,receipt=created,create=kinds['CREATE'][0],receiptRead=kinds['RECEIPT'][0],bodies=values)


def validate_dom(rows, captures, facts):
    need(type(rows) is list and len(rows) == 11)
    previous_count = 0
    for index,(row,step) in enumerate(zip(rows,STEPS),1):
        exact(row,('schema','ordinal','step','captureCount','mutationCount','dom'))
        need(row['schema'] == 'chengwang.subscription-ui-dom-capture/v1' and row['step'] == step); same(row['ordinal'],index)
        integer(row['captureCount'],previous_count,len(captures)); previous_count = row['captureCount']
        same(row['mutationCount'],0 if index <= 5 else 1)
        seen = captures[:row['captureCount']]
        need(sum(r['method'] == 'POST' for r in seen) == row['mutationCount'])
        dom = row['dom']; exact(dom,('schema','pageMounted','pageVisible','https','viewport','session','controls','sources','candidates','nodes','paging','mode','directory','sessionApproval','handoff','confirmation','receipt','stale','alertVisible','boundaryVisible'))
        need(dom['schema'] == 'chengwang.subscription-browser-dom/v1')
        for k in ('pageMounted','https'): need(dom[k] is True)
        same(dom['pageVisible'],step!='hidden'); same(dom['boundaryVisible'],step!='hidden')
        need(dom['alertVisible'] is False)
        viewport=dom['viewport']; exact(viewport,('width','height','scrollX','scrollY','clientWidth','scrollWidth'))
        for k in ('width','height','clientWidth','scrollWidth'): integer(viewport[k],1,100000)
        for k in ('scrollX','scrollY'): integer(viewport[k],-100000,100000)
        need(viewport['scrollWidth'] == viewport['clientWidth'] and viewport['clientWidth'] <= viewport['width'])
        need(viewport['width'] == (375 if step in ('created_mobile','receipt','hidden','returned','cleared') else 1440))
        session=dom['session']; exact(session,('tokenMounted','tokenType','tokenEmpty','fileMounted','fileEmpty','storageEmpty','cookiesEmpty'))
        need(session['tokenMounted'] is True and session['tokenType'] == 'password' and session['tokenEmpty'] is True
             and session['storageEmpty'] is True and session['cookiesEmpty'] is True)
        boolean(session['fileMounted']); need(session['fileEmpty'] is True if session['fileMounted'] else session['fileEmpty'] is None)
        controls=dom['controls']; need(type(controls) is list and len(controls) == len(CONTROLS))
        for ctl,key in zip(controls,CONTROLS):
            exact(ctl,('key','present','visible','enabled','inViewport','unobstructed','rect')); need(ctl['key'] == key)
            for k in ('present','visible','enabled','inViewport','unobstructed'): boolean(ctl[k])
            need(ctl['present'] or not any(ctl[k] for k in ('visible','enabled','inViewport','unobstructed')))
            need(ctl['visible'] == (ctl['rect'] is not None) and (not ctl['inViewport'] or ctl['visible']) and (not ctl['unobstructed'] or ctl['inViewport']))
            if ctl['rect'] is not None:
                exact(ctl['rect'],('x','y','width','height'))
                for k in ('x','y'): integer(ctl['rect'][k],-100000,100000)
                for k in ('width','height'): integer(ctl['rect'][k],0,100000)
        cm={c['key']:c for c in controls}
        same(dom['candidates'],[]); same(dom['nodes'],[]); same(dom['stale'],dict(sources=False,candidates=False,nodes=False))
        need(dom['sessionApproval'] is None and dom['handoff'] is None and dom['mode'] in ('absent','session'))
        exact(dom['directory'],('present','disabled','references')); boolean(dom['directory']['present']); boolean(dom['directory']['disabled']); same(dom['directory']['references'],[])
        exact(dom['paging'],('candidates','nodes')); need(dom['paging']['nodes'] is None)
        prepared=step in ('prepared','prepared_again')
        same(dom['confirmation'],dict(kind='create',binding=None,unverifiedReference=False,rollbackRequired=False,rollbackChecked=False) if prepared else None)
        if prepared: need(all(cm[k]['present'] and cm[k]['enabled'] for k in ('confirm','cancel')))
        if index <= 5 or step == 'cleared':
            same(dom['sources'],[]); need(dom['receipt'] is None and dom['paging']['candidates'] is None)
        else:
            same(dom['sources'],[dict(id=facts['source']['id'],revision=1,selected=True,accepted=False,disabled=False)])
            same(dom['paging']['candidates'],dict(page=1,revision=1))
            same(dom['receipt'],{k:facts['receipt'][k] for k in ('commandId','revision','state','replayed','auditRecorded')})
            need(any(r['kind']=='CREATE' for r in seen) and any(r['kind']=='CANDIDATES' for r in seen))
        if step in ('anonymous','cleared'):
            need(not cm['prepare_create']['enabled'] and not any(r['authorizationPresent'] for r in seen if step == 'anonymous'))
        else: need(cm['prepare_create']['enabled'])
        if step == 'receipt': need(any(r['kind']=='RECEIPT' for r in seen))
    need(rows[-1]['captureCount'] == len(captures))


def go_event_bytes(event):
    order=('id','idempotencyKey','traceId','actorId','action','target','result','occurredAt','data','previousHash','hash')
    value={k:(dict(sorted(event[k].items())) if k=='data' else event[k]) for k in order if k in event}; value['hash']=''
    return json.dumps(value,ensure_ascii=False,separators=(',',':')).replace('&','\\u0026').replace('<','\\u003c').replace('>','\\u003e').replace('\u2028','\\u2028').replace('\u2029','\\u2029').encode()


def validate_audit(rows, checkpoint, facts):
    need(type(rows) is list and len(rows) == 2); previous='0'*64; stages={}; command=facts['receipt']['commandId']
    stable=dict(**SCOPE,managementObject='local',kind='create')
    for event in rows:
        exact(event,('id','idempotencyKey','traceId','actorId','action','target','result','occurredAt','data','previousHash','hash'))
        need(type(event['id']) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}',event['id']))
        need(type(event['actorId']) is str and re.fullmatch(r'act_[a-f0-9]{60}',event['actorId']))
        need(event['traceId']==command and event['target']=='subscription/local' and event['previousHash']==previous
             and sha(go_event_bytes(event))==digest(event['hash']))
        previous=event['hash']; stage=event['result']; need(stage in ('prepared','result') and stage not in stages)
        need(event['action']=='subscription.command.'+stage and event['idempotencyKey']=='subscription/'+command+'/'+stage)
        data=event['data']; required=set(stable)|{'commandDigest'}
        if stage=='result': required|={'state','code','sourceId','candidateId','revision','candidateDigest','localAuditHash','approvalId','policyDigest','policyRevision','stateMayHaveChanged'}
        exact(data,required); need(all(type(v) is str for v in data.values()))
        need(all(data[k]==v for k,v in stable.items()) and re.fullmatch(r'hmac-sha256:[a-f0-9]{64}',data['commandDigest']))
        timestamp(event['occurredAt']); stages[stage]=event
    same(checkpoint,dict(count=2,lastHash=previous)); need(set(stages)=={'prepared','result'})
    a,b=stages['prepared'],stages['result']; need(a['actorId']==b['actorId'] and timestamp(a['occurredAt']) <= timestamp(b['occurredAt']))
    need(a['data']=={k:b['data'][k] for k in a['data']})
    rc=facts['receipt']; need(a['hash']==rc['preparedAuditHash'] and b['hash']==rc['resultAuditHash'] and b['occurredAt']==rc['completedAt'])
    expected=dict(**stable,commandDigest=a['data']['commandDigest'],state='committed',code='',sourceId=rc['sourceId'],candidateId='',revision='1',candidateDigest='',localAuditHash=rc['localAuditHash'],approvalId='',policyDigest='',policyRevision='0',stateMayHaveChanged='false')
    same(b['data'],expected)
    # Do not combine browser wallTime and monotonic event times into a new
    # precision claim. The immutable receipt/operation IDs bind the HTTP and
    # audit results; original audit timestamps retain their own clock domain.
    return a['actorId']


def validate_private(value, facts, actor, commit, fixture):
    exact(value,('schema','sourceCommit','fixtureId','scope','sources','candidates','localAuditCount','commandCount','approvalCount','commands'))
    need(value['schema']=='chengwang.subscription-ui-private-readback/v1' and value['sourceCommit']==commit and value['fixtureId']==fixture)
    same(value['scope'],SCOPE); same(value['sources'],[facts['source']]); same(value['candidates'],[])
    same(value['localAuditCount'],1); same(value['commandCount'],1); same(value['approvalCount'],0)
    need(type(value['commands']) is list and len(value['commands'])==1); c=value['commands'][0]; rc=facts['receipt']
    same(c,dict(id=rc['commandId'],scope=SCOPE,actorId=actor,kind='create',expectedRevision=0,
        preparedAuditHash=rc['preparedAuditHash'],resultAuditHash=rc['resultAuditHash'],acknowledged=True,
        result={k:rc[k] for k in ('sourceId','revision','state','stateMayHaveChanged','localAuditHash','completedAt')}))


def validate_build(value, commit):
    exact(value,('schema','sourceCommit','goVersion','nodeVersion','moduleMode','goDependencyDownloads','server','distFiles','production','authorization'))
    need(value['schema']=='chengwang.subscription-ui-build/v1' and value['sourceCommit']==commit and value['goVersion']=='go1.23.12'
         and value['nodeVersion']=='v22.23.3' and value['moduleMode']=='vendor' and value['goDependencyDownloads'] is False
         and value['production'] is False and value['authorization']=='BLOCKED')
    exact(value['server'],('name','bytes','sha256')); need(value['server']['name']=='server'); integer(value['server']['bytes'],1,128<<20); digest(value['server']['sha256'])
    files=value['distFiles']; need(type(files) is list and 4<=len(files)<=512); paths=[]
    for item in files:
        exact(item,('path','bytes','sha256')); p=item['path']; need(type(p) is str and re.fullmatch(r'[A-Za-z0-9_./@+-]+',p)
            and '..' not in p.split('/') and not p.startswith('/') and (p in ('index.html','trust.html','.vite/manifest.json') or p.startswith('assets/')))
        integer(item['bytes'],1,16<<20); digest(item['sha256']); paths.append(p)
    need(paths==sorted(set(paths)) and {'index.html','trust.html','.vite/manifest.json'}<=set(paths))


def verify_tls(certs, driver, captures):
    exact(certs,('caPEM','leafPEM'))
    def der(pem):
        need(type(pem) is str and len(pem)<=65536 and re.fullmatch(r'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\n?',pem))
        return base64.b64decode(''.join(pem.splitlines()[1:-1]),validate=True)
    ca,leaf=der(certs['caPEM']),der(certs['leafPEM'])
    same(driver['normalTrust'],dict(method='PRIVATE_NSS_SQL_XDG_LOCAL_CA',trustFlags='C,,',caSHA256=sha(ca),leafSHA256=sha(leaf),homeEnvironmentAbsent=True,legacyDatabaseAbsent=True))
    tls=driver['tls']; exact(tls,('securityState','protocol','cipher','leafSHA256','caSHA256','serverChainLength','leafSignatureVerified','ipSANVerified'))
    need(tls['securityState']=='secure' and tls['protocol'] in ('TLS 1.2','TLS 1.3') and type(tls['cipher']) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',tls['cipher'])
         and tls['leafSHA256']==sha(leaf) and tls['caSHA256']==sha(ca) and tls['leafSignatureVerified'] is True and tls['ipSANVerified'] is True)
    chain=driver['certificateChain']; need(type(chain) is list and 1<=len(chain)<=2); same(tls['serverChainLength'],len(chain))
    need([unbase64(v,65536) for v in chain]==([leaf] if len(chain)==1 else [leaf,ca]))
    stamp=min(r['startedWallTimeUs'] for r in captures)
    with tempfile.TemporaryDirectory(prefix='subscription-ui-offline-cert-') as tmp:
        paths=[Path(tmp)/n for n in ('ca.pem','leaf.pem')]
        for path,pem in zip(paths,(certs['caPEM'],certs['leafPEM'])):
            with path.open('xb') as handle: handle.write(pem.encode('ascii'))
        result=subprocess.run(['openssl','verify','-trusted',str(paths[0]),'-check_ss_sig','-attime',str(stamp//1000000),'-purpose','sslserver','-verify_ip','127.0.0.1',str(paths[1])],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,env={'PATH':os.environ.get('PATH',os.defpath),'OPENSSL_CONF':os.devnull})
        need(result.returncode==0)


def git_bytes(repo,commit,path):
    return subprocess.check_output(['git','-c','safe.directory='+str(repo),'-C',str(repo),'show',commit+':'+path],stderr=subprocess.DEVNULL)


def validate_supervisor(p,iso,inputs,build,d,receipt_value,repo,commit,engine,fixture):
    prefix='chengwang.subscription-ui-supervisor/v1'
    for value in (p,iso,inputs): need(value['schema']==prefix and value['sourceCommit']==commit and value['fixtureId']==fixture and value['engine']==engine and value['production'] is False)
    exact(p,('schema','sourceCommit','fixtureId','engine','records','serverExitCode','controllerExitCode','noLiveOwnedProcesses','forcedSignals','processScope','production'))
    exact(inputs,('schema','sourceCommit','fixtureId','engine','copiedInputs','inputTrustScope','production'))
    exact(iso,('schema','sourceCommit','fixtureId','engine','hostBefore','hostAfter','sourceFilesBefore','sourceFilesAfter','lab','production','authorization','deviceActionsExecuted','pythonBinaryProvenanceProven'))
    need(p['processScope']=='TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION' and inputs['inputTrustScope']=='SOURCE_GIT_AND_NPM_LOCK_TRUSTED_CI_NOT_INDEPENDENT_REBUILD')
    need(iso['authorization']=='BLOCKED' and iso['deviceActionsExecuted'] is False and iso['pythonBinaryProvenanceProven'] is False)
    same(iso['hostBefore'],iso['hostAfter']); same(iso['sourceFilesBefore'],iso['sourceFilesAfter']); host=iso['hostBefore']
    exact(host,('netNamespace','mountNamespace','pidNamespace','userNamespace','portStart','systemCASHA256','sourceSHA256')); integer(host['portStart'],0,65535)
    for name,kind in (('netNamespace','net'),('mountNamespace','mnt'),('pidNamespace','pid'),('userNamespace','user')): need(type(host[name]) is str and re.fullmatch(kind+r':\[[0-9]+\]',host[name]))
    digest(host['systemCASHA256']); digest(host['sourceSHA256'])
    sources=iso['sourceFilesBefore']; need(type(sources) is list and 1<=len(sources)<=8192); source_map={}
    for item in sources:
        exact(item,('path','bytes','sha256')); path=item['path']; need(type(path) is str and re.fullmatch(r'[A-Za-z0-9_./@+-]+',path) and '..' not in path.split('/') and path not in source_map and path.startswith(('chengwang/','.github/workflows/')))
        original=git_bytes(repo,commit,path); same(item['bytes'],len(original)); need(item['sha256']==sha(original)); source_map[path]=item
    tracked=subprocess.check_output(['git','-c','safe.directory='+str(repo),'-C',str(repo),'ls-tree','-r','-z','--name-only',commit,'--','chengwang','.github/workflows'],stderr=subprocess.DEVNULL)
    need(set(source_map)=={x.decode() for x in tracked.split(b'\0') if x} and sha(canonical(sources))==host['sourceSHA256'])
    own='chengwang/deploy/subscription-ui-browser/check_subscription_ui.py'; need(own in source_map and git_bytes(repo,commit,own)==read(Path(__file__)))
    lab=iso['lab']; exact(lab,('namespaces','defaultIPv4Routes','defaultIPv6Routes','interfaces','sourceMount','bundleMount','tmpMount'))
    same(lab['defaultIPv4Routes'],0); same(lab['defaultIPv6Routes'],0); same(lab['interfaces'],['lo']); exact(lab['namespaces'],('net','mnt','pid','user'))
    for key in lab['namespaces']: need(type(lab['namespaces'][key]) is str and re.fullmatch(key+r':\[[0-9]+\]',lab['namespaces'][key]))
    need(lab['namespaces']['user']==host['userNamespace'])
    for key,name in (('net','netNamespace'),('mnt','mountNamespace'),('pid','pidNamespace')): need(lab['namespaces'][key]!=host[name])
    for key in ('sourceMount','bundleMount','tmpMount'):
        need(type(lab[key]) is list and all(type(v) is str for v in lab[key]) and len(set(lab[key]))==len(lab[key]))
    for key in ('sourceMount','bundleMount'): need({'ro','nosuid','nodev'}<=set(lab[key]))
    need({'rw','nosuid','nodev','noexec'}<=set(lab['tmpMount']))
    copied={}
    for item in inputs['copiedInputs']:
        exact(item,('path','bytes','sha256')); path=item['path']; need(type(path) is str and path not in copied and '..' not in path.split('/')); integer(item['bytes'],0,512<<20); digest(item['sha256']); copied[path]=item
        if path.startswith('chengwang/'):
            original=source_map.get(path.removesuffix(':launcher')); need(original is not None)
            same({k:item[k] for k in ('bytes','sha256')},{k:original[k] for k in ('bytes','sha256')})
        else: need(path.startswith(('chrome/','npm/playwright-core/','dist/')) or path in ('toolchain/node','toolchain/server','build/report.json'))
    for path in ('chrome/chrome','toolchain/node','toolchain/server','npm/playwright-core/package.json'): need(path in copied)
    same({k:copied['toolchain/server'][k] for k in ('bytes','sha256')},{k:build['server'][k] for k in ('bytes','sha256')})
    same({k:copied['chrome/chrome'][k] for k in ('bytes','sha256')},dict(bytes=305061192,sha256=ELF_SHA))
    same([{**item,'path':item['path'][5:]} for path,item in sorted(copied.items()) if path.startswith('dist/')],build['distFiles'])
    records=p['records']; need(type(records) is list and len(records)==3); roles={r['role']:r for r in records}; need(set(roles)=={'server','controller','chrome'} and len({r['pid'] for r in records})==3)
    same(p['serverExitCode'],0); same(p['controllerExitCode'],0); same(p['forcedSignals'],0); need(p['noLiveOwnedProcesses'] is True)
    root='/tmp/chengwang-subscription-ui-'+fixture; bundle='/tmp/chengwang-subscription-ui-tools-'+fixture
    for role,r in roles.items():
        exact(r,('pid','startTime','exeSHA256','argvSHA256','uid','gid','groups','capabilities','noNewPrivs','namespaces','limits','role','argv'))
        integer(r['pid'],2); need(type(r['startTime']) is str and re.fullmatch('[1-9][0-9]{0,19}',r['startTime'])); digest(r['exeSHA256']); digest(r['argvSHA256'])
        same(r['uid'],[10001]*4); same(r['gid'],[10001]*4); same(r['groups'],[]); same(r['noNewPrivs'],1)
        same(r['capabilities'],{k:'0000000000000000' for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')}); same(r['namespaces'],lab['namespaces'])
        same(r['limits'],dict(cpuSeconds=[180,180],fileBytes=[32<<20]*2,openFiles=[1024]*2,processes=[1024]*2,coreBytes=[0,0]))
        need(type(r['argv']) is list and 1<=len(r['argv'])<=128 and all(type(v) is str and len(v)<=4096 for v in r['argv']))
        need(sha(b''.join(v.encode()+b'\0' for v in r['argv']))==r['argvSHA256'])
    c=d['chrome']; exact(c,('pid','startTicks','uid','profile','argvSHA256','exeSHA256','exeBytes'))
    same(c['pid'],roles['chrome']['pid']); same(c['startTicks'],int(roles['chrome']['startTime'])); same(c['uid'],10001); same(c['exeBytes'],305061192)
    need(c['profile']==root+'/chrome-profile' and c['exeSHA256']==roles['chrome']['exeSHA256']==ELF_SHA and c['argvSHA256']==roles['chrome']['argvSHA256'])
    need(roles['controller']['exeSHA256']==copied['toolchain/node']['sha256'] and roles['server']['exeSHA256']==build['server']['sha256'])
    argv=roles['chrome']['argv']; need(argv[0]==bundle+'/chrome/chrome' and '--no-sandbox' in argv and [v for v in argv if v.startswith('--user-data-dir')]==['--user-data-dir='+root+'/chrome-profile'])
    forbidden=('--ignore-certificate-errors','--ignore-certificate-errors-spki-list','--ignore-ssl-errors','--allow-insecure-localhost','--disable-web-security','--unsafely-treat-insecure-origin-as-secure')
    need(not any(v.split('=',1)[0] in forbidden for v in argv))
    need(roles['server']['argv']==[bundle+'/server'])
    same(roles['controller']['argv'],[bundle+'/node',bundle+'/source/chengwang/tools/subscription-ui-browser/ui-cli.mjs','--root',root,'--bundle',bundle,'--engine',engine,'--source-commit',commit])
    close=d['close']; exact(close,('normalCloseCommandCompleted','chromeExit','launcherExit','noLiveOwnedProcesses','processScope'))
    need(close['normalCloseCommandCompleted'] is True and close['noLiveOwnedProcesses'] is True and close['processScope']=='CHROME_SESSION_AND_LAUNCHER_ONLY')
    same(close['chromeExit'],dict(schema='chengwang.subscription-ui-chrome-exit/v1',engine=engine,fixtureId=fixture,pid=c['pid'],startTicks=c['startTicks'],exitCode=0,joined=True,forced=False))
    same(close['launcherExit'],dict(code=0,signal=None) if engine=='chrome-cdp' else None)
    need(receipt_value['schema']=='chengwang.pinned-browser-consumption-verification/v1' and receipt_value['sourceCommit']==commit and receipt_value['state']=='PIN_ENFORCED_EXPANDED_NOT_EXECUTED'
         and receipt_value['pinSHA256']==PIN_SHA and receipt_value['pinEnforced'] is True and receipt_value['allMemberCRCsVerified'] is True and receipt_value['actualExpandedFileHashesVerified'] is True)
    same(receipt_value['zip'],dict(bytes=202676171,sha256='7802b25411aa5b8aa387cc733a45df6eed1aea8cc046fd4e2dec64d5918b1853',md5Base64='5qChIL/Gh+8hZv73vzEakQ=='))
    need(receipt_value['elf']['sha256']==ELF_SHA); same(receipt_value['elf']['bytes'],305061192)
    for k in ('browserExecuted','runtimeVersionProven','projectFixProven','publisherSignatureProven','production'): need(receipt_value[k] is False)
    return len(sources)


def verify(directory,repo,commit,engine):
    need(type(commit) is str and re.fullmatch('[a-f0-9]{40}',commit) and engine in ('chrome-cdp','playwright'))
    need(not directory.is_symlink() and {p.name for p in directory.iterdir()}==PUBLIC)
    raw={name:read(directory/name,24 << 20 if name=='captures.jsonl' else 16 << 20) for name in PUBLIC}
    need(all(b'PRIVATE KEY' not in v and b'Bearer ' not in v for v in raw.values()))
    d=decode(raw['driver.json']); contract=decode(git_bytes(repo,commit,'chengwang/deploy/subscription-ui-browser/contract.json'))
    same(contract['publicFiles'],['driver.json','captures.jsonl','dom.jsonl','created-desktop.png','created-mobile.png','processes.json','isolation.json','inputs.json','certificates.json','pin-consumption.json','private-readback.json','audit-events.jsonl','audit-checkpoint.json','build.json'])
    exact(d,contract['driverKeys']); fixture=d['fixtureId']; need(type(fixture) is str and re.fullmatch('[a-f0-9]{32}',fixture))
    need(d['schema']=='chengwang.subscription-ui-driver/v1' and d['sourceCommit']==commit and d['engine']==engine and d['origin']==ORIGIN and d['runtime'] is True)
    need(d['scope']=='REAL_PRODUCT_CREATE_RECEIPT_FLOW_PARTIAL_FULL_SUBSCRIPTION_PLAN_PENDING'); same(d['steps'],list(STEPS))
    for key in ('mockedResponses','injectedFetch','tlsBypass','production','fullSubscriptionE2EProven'): need(d[key] is False)
    exact(d['browser'],('product','revision','protocolVersion')); need(d['browser']['product'] in ('Chrome/157.0.8103.6','HeadlessChrome/157.0.8103.6') and d['browser']['revision']=='@'+TAG and d['browser']['protocolVersion']=='1.3')
    exact(d['counters'],('runtimeErrors','consoleErrors','consoleWarnings','cspErrors','assetErrors','forbiddenRequests','failedRequests','captureErrors'))
    need(all(type(v) is int and v==0 for v in d['counters'].values()))
    build=decode(raw['build.json']); validate_build(build,commit)
    captures=lines(raw['captures.jsonl']); facts=validate_captures(captures,build); dom=lines(raw['dom.jsonl'],11); validate_dom(dom,captures,facts)
    same(d['captures'],dict(path='captures.jsonl',bytes=len(raw['captures.jsonl']),sha256=sha(raw['captures.jsonl']),records=len(captures)))
    screenshots=d['screenshots']; need(type(screenshots) is list and len(screenshots)==2)
    for item,name,step,width in zip(screenshots,('created-desktop.png','created-mobile.png'),('created_desktop','created_mobile'),(1440,375)):
        exact(item,('path','step','bytes','sha256','viewport','scrollX','scrollY','capturedWallTimeUs'))
        need(item['path']==name and item['step']==step and item['sha256']==sha(raw[name])); same(item['bytes'],len(raw[name])); integer(item['capturedWallTimeUs'],1)
        exact(item['viewport'],('width','height')); same(item['viewport']['width'],width); integer(item['viewport']['height'],1,10000)
        row=next(x for x in dom if x['step']==step); vp=row['dom']['viewport']; same(item['viewport']['height'],vp['height']); same(item['scrollX'],vp['scrollX']); same(item['scrollY'],vp['scrollY'])
        png(raw[name],width,item['viewport']['height'])
        need(item['capturedWallTimeUs']>=facts['create']['startedWallTimeUs'])
    actor=validate_audit(lines(raw['audit-events.jsonl'],8),decode(raw['audit-checkpoint.json']),facts)
    validate_private(decode(raw['private-readback.json']),facts,actor,commit,fixture)
    inputs=decode(raw['inputs.json']); build_input=[r for r in inputs['copiedInputs'] if r['path']=='build/report.json']
    need(len(build_input)==1); same(build_input[0],dict(path='build/report.json',bytes=len(raw['build.json']),sha256=sha(raw['build.json'])))
    source_count=validate_supervisor(decode(raw['processes.json']),decode(raw['isolation.json']),inputs,build,d,decode(raw['pin-consumption.json']),repo,commit,engine,fixture)
    verify_tls(decode(raw['certificates.json']),d,captures)
    need({name:read(directory/name,24 << 20 if name=='captures.jsonl' else 16 << 20) for name in PUBLIC}==raw)
    return dict(schema='chengwang.subscription-ui-verification/v1',sourceCommit=commit,engine=engine,fixtureId=fixture,outcome='PASS',
        scope='REAL_PRODUCT_CREATE_RECEIPT_FLOW_PARTIAL_FULL_SUBSCRIPTION_PLAN_PENDING',actualBrowser=d['browser'],actualChromeELFSHA256=ELF_SHA,
        steps=11,screenshots=2,requests=len(captures),mutations=1,commands=1,externalAuditEvents=2,sourceGitBlobs=source_count,
        normalTLSOfflineVerifiedAtCapture=True,pinConsumed=True,realCreateReceiptFlowProven=True,fullSubscriptionE2EProven=False,
        fetchDNSWireEvaluated=False,privateDatabaseRawIndependentlyVerified=False,independentReproducibleBuildProven=False,
        screenshotVisualReviewProven=False,privateReadbackTrustBoundary='TRUSTED_RUNNER_SAFE_PROJECTION_NOT_INDEPENDENT_PRIVATE_DATABASE_VERIFICATION',
        processTrustBoundary='TRUSTED_CI_PROC_AND_PARENT_WAIT_NOT_INDEPENDENT_SIGNAL_ATTESTATION',production=False,authorization='BLOCKED',
        remaining=contract['remaining'],evidenceSHA256={n:sha(raw[n]) for n in sorted(raw)})


def main():
    p=argparse.ArgumentParser()
    for name in ('evidence','repo','report'): p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--source-commit',required=True); p.add_argument('--engine',required=True,choices=('chrome-cdp','playwright')); a=p.parse_args()
    evidence=a.evidence.resolve(strict=True); report=a.report.absolute()
    need(not a.evidence.is_symlink() and not report.resolve().is_relative_to(evidence) and not report.exists() and not report.is_symlink())
    result=verify(evidence,a.repo.resolve(strict=True),a.source_commit,a.engine)
    with report.open('xb') as handle: handle.write(canonical(result)+b'\n')
    print('SUBSCRIPTION_UI_INDEPENDENT=PASS full_subscription_e2e_proven=false production=false')


if __name__=='__main__':
    try: main()
    except Exception: raise SystemExit('SUBSCRIPTION_UI_INDEPENDENT=REJECTED raw_input_suppressed=true') from None
