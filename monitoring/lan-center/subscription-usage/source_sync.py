"""One-way SSH import into the information-only registry. No publisher API."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.parse

OWNER = 'openclash:转换'
MAX_SOURCES = 128


class SyncError(ValueError):
    pass


def atomic(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent, delete=False) as f:
        temporary = Path(f.name); os.chmod(temporary, 0o600)
        json.dump(value, f, ensure_ascii=False, separators=(',', ':'))
        f.flush(); os.fsync(f.fileno())
    os.replace(temporary, path)


def target_directory(value):
    p = Path(value).resolve()
    if p.name != 'subscription-usage':
        raise SyncError('information_directory_required')
    return p


def url_identity(value):
    if not isinstance(value, str) or len(value)>8192 or re.search(r'[\x00-\x20\x7f]', value):
        raise SyncError('invalid_source_url')
    p=urllib.parse.urlsplit(value)
    if p.scheme not in ('http','https') or not p.hostname:
        raise SyncError('invalid_source_url')
    try:p.port
    except ValueError:raise SyncError('invalid_source_port') from None
    # HTTP fragments are display annotations, not account identity.
    return urllib.parse.urlunsplit(p._replace(fragment=''))


def parse_export(document):
    if (not isinstance(document,dict) or document.get('schema')!=1
            or document.get('source_name')!='转换' or document.get('state')!='ok'
            or type(document.get('enabled')) is not bool):
        raise SyncError('export_not_valid')
    addresses=document.get('addresses')
    count=document.get('address_count')
    if type(count) is not int:raise SyncError('invalid_export_inventory')
    if addresses=={} and count==0:addresses=[]  # luci.jsonc empty table
    if not isinstance(addresses,list) or len(addresses)>MAX_SOURCES:
        raise SyncError('invalid_export_inventory')
    if len(addresses)!=count:raise SyncError('invalid_export_inventory')
    result=[];seen=set()
    for raw in addresses:
        url=url_identity(raw)
        if url not in seen:result.append(url);seen.add(url)
    return result if document['enabled'] else []


def validate_registry(doc):
    if not isinstance(doc,dict) or doc.get('schema')!=1 or doc.get('purpose')!='subscription_information_only':
        raise SyncError('invalid_information_registry')
    rows=doc.get('sources')
    if not isinstance(rows,list) or len(rows)>MAX_SOURCES:raise SyncError('invalid_information_registry')
    ids=set()
    for row in rows:
        if (not isinstance(row,dict) or not isinstance(row.get('id'),str)
                or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',row['id']) or row['id'] in ids):
            raise SyncError('invalid_information_registry')
        ids.add(row['id']);url_identity(row.get('url'))
    return doc


def merge(document, urls):
    """Replace only this owner's rows. Manual entries keep data and identity."""
    validate_registry(document)
    rows=document['sources'];manual=[dict(r) for r in rows if r.get('owner')!=OWNER]
    manual_urls={url_identity(r['url']) for r in manual}
    old={url_identity(r['url']):r for r in rows if r.get('owner')==OWNER}
    ids={r['id'] for r in manual};managed=[]
    for url in urls:
        if url in manual_urls:continue
        if url in old:
            row=dict(old[url]);row.update(url=url,owner=OWNER,enabled=True)
        else:
            digest=hashlib.sha256(url.encode()).hexdigest()
            sid='Info_'+digest[:20]
            if sid in ids:sid='Info_'+digest
            if sid in ids:raise SyncError('source_identity_collision')
            row={'id':sid,'name':sid,'url':url,'owner':OWNER,'enabled':True}
        if row['id'] in ids:raise SyncError('source_identity_collision')
        ids.add(row['id']);managed.append(row)
    result={'schema':1,'purpose':'subscription_information_only','owner':OWNER,'sources':manual+managed}
    validate_registry(result);return result


def import_once(directory, document, now=None):
    directory=target_directory(directory);now=time.time() if now is None else now
    path=directory/'information-sources.json';status_path=directory/'sync-state.json'
    # Invalid local manual edits must not be silently replaced from a backup.
    current=validate_registry(json.loads(path.read_text(encoding='utf-8')))
    urls=parse_export(document);result=merge(current,urls)
    changed=result!=current
    if changed:atomic(path,result)
    # Last good includes manual entries and is kept private with the registry.
    good=None
    try:good=json.loads((directory/'information-sources.good.json').read_text(encoding='utf-8'))
    except (OSError,ValueError):pass
    if good!=result:
        atomic(directory/'information-sources.good.json',result)
    old={}
    try:old=json.loads(status_path.read_text())
    except (OSError,ValueError):pass
    revision=hashlib.sha256(json.dumps(result,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    state={'schema':1,'state':'ok','source_name':'转换','last_attempt':now,'last_success':now,
           'last_change':now if changed else old.get('last_change',now),'revision':revision,
           'managed_count':sum(r.get('owner')==OWNER for r in result['sources']),
           'manual_count':sum(r.get('owner')!=OWNER for r in result['sources'])}
    atomic(status_path,state)
    return {'changed':changed,'managed_count':state['managed_count'],'manual_count':state['manual_count']}


def fail(directory, code):
    old={};path=directory/'sync-state.json'
    try:old=json.loads(path.read_text())
    except (OSError,ValueError):pass
    if code not in ('ssh_unavailable','export_not_valid','invalid_source_url','invalid_source_port',
                    'invalid_export_inventory','invalid_information_registry','source_identity_collision'):
        code='sync_unavailable'
    state={k:v for k,v in old.items() if k in ('last_success','last_change','managed_count','manual_count','revision')}
    state.update(schema=1,state='error',error=code,source_name='转换',last_attempt=time.time())
    atomic(path,state)


def run(config):
    directory=target_directory(config['directory'])
    with (directory/'source-sync.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return {'state':'busy'}
        try:
            # argv contains only fixed command/paths, never subscription URLs.
            args=['ssh','-T','-i',config['key'],'-o','BatchMode=yes','-o','IdentitiesOnly=yes',
                  '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+config['known_hosts'],
                  '-o','ConnectTimeout=3','-o','ClearAllForwardings=yes',config['target'],
                  'subscription-info-export-v1']
            with tempfile.TemporaryFile() as output:
                p=subprocess.run(args,stdout=output,stderr=subprocess.DEVNULL,timeout=8)
                if p.returncode or output.tell()>2*1024**2:raise SyncError('ssh_unavailable')
                output.seek(0);doc=json.load(output)
            return {'state':'ok',**import_once(directory,doc)}
        except Exception as e:
            code=str(e) if isinstance(e,SyncError) else 'sync_unavailable'
            fail(directory,code);return {'state':'error','error':code if isinstance(e,SyncError) else 'sync_unavailable'}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('config');args=p.parse_args()
    result=run(json.loads(Path(args.config).read_text()));print(json.dumps(result))
    raise SystemExit(0 if result['state'] in ('ok','busy') else 1)
