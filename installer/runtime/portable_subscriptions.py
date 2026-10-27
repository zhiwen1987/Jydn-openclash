"""Portable startup for empty/new sites; existing accepted releases stay sticky."""
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
import urllib.parse

sys.path.insert(0,'/local-subscription')
# The incremental metadata extension is code-only and persists through the
# existing /data mount. Its private directory is owned by the deployment receipt.
USAGE_CODE=Path('/data/subscription-usage/code')
if USAGE_CODE.is_dir():sys.path.insert(0,str(USAGE_CODE))


def install_usage_bridge():
    import local_web
    if getattr(local_web,'SUBSCRIPTION_USAGE_INTEGRATED',False):return
    try:
        from subscription_usage import install as install_usage
    except ImportError:return
    previous=local_web.install
    def install(namespace,*args,**kwargs):
        result=previous(namespace,*args,**kwargs)
        try:install_usage(namespace)
        except Exception as error:
            if callable(namespace.get('log')):namespace['log']('subscription_usage_unavailable',type(error).__name__,'warning')
        return result
    local_web.install=install


def resume_metadata_reload(module):
    """Keep the old publisher deadline on a UI-only process reload."""
    path=module.DATA/'usage-reload-defer.json'
    try:
        value=json.loads(path.read_text());path.unlink()
        now=module.now();deadline=value.get('until');release=module.current_manifest()
        if (type(deadline) not in (int,float) or not now<=deadline<=now+3600
                or not release or release.get('release_id')!=value.get('release_id')):return
        health=dict(value.get('health',{}));health.update(epoch=now,current_release=release['release_id'],
            reason='schedule_preserved_after_metadata_reload',metadata_reload_deferred=True,
            previous_cycle_epoch=value.get('health',{}).get('epoch'),next_cycle_epoch=deadline)
        module.atomic_json(module.HEALTH_PATH,health)
        stop_at=time.monotonic()+deadline-now
        while time.monotonic()<stop_at:
            time.sleep(min(30,max(1,stop_at-time.monotonic())))
            try:
                module.maintain_probation()
                if module.repair_pointer():
                    with module.exclusive(module.DATA.parent/'routing-owner.lock') as acquired:
                        if acquired:
                            module.refresh_providers(module.load_sources())
                            (module.DATA/'recovery-refresh.json').unlink(missing_ok=True)
            except Exception as error:
                module.log('metadata_reload_maintenance_error',type(error).__name__,'warning')
            health['epoch']=module.now();module.atomic_json(module.HEALTH_PATH,health)
    except (OSError,ValueError,TypeError):return


def load():
    spec=importlib.util.spec_from_file_location('subscription_impl','/subscription_impl.py')
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return module


def install_public_header(module):
    previous=module.Handler.do_GET
    def get(h):
        path=urllib.parse.urlsplit(h.path).path
        match=re.fullmatch(r'/providers/([A-Za-z0-9_.-]{1,80})\.yaml',path)
        header=h.headers.get('Authorization','')
        if match and match.group(1)!='local-custom' and header:
            import hmac
            if not hmac.compare_digest(header,'Bearer '+module.PUBLISH_TOKEN) or h.client_address[0] not in module.ALLOWED_PROVIDER_CLIENTS:
                module.log('provider_forbidden','source='+match.group(1)+' client='+h.client_address[0],'warning')
                h.send(403,'application/json',b'{"error":"forbidden"}');return
            manifest=module.current_manifest()
            item=next((s for s in (manifest or {}).get('sources',[]) if s['id']==match.group(1)),None)
            if not item:
                h.send(503,'application/json',b'{"error":"provider_not_ready"}');return
            raw=(module.RELEASES/manifest['release_id']/item['file']).read_bytes()
            h.send(200,'text/yaml; charset=utf-8',raw);return
        return previous(h)
    module.Handler.do_GET=get


def scheduler(module):
    def run():
        resume_metadata_reload(module)
        while True:
            started=time.monotonic();delay=30
            try:
                with module.LOCK:
                    sources=module.load_sources()
                    if not sources:
                        module.atomic_json(module.HEALTH_PATH,{'status':'awaiting_sources','mode':module.MODE,'epoch':module.now(),'node_count':0})
                    else:
                        if not module.current_manifest():
                            # First publication uses the existing explicit shadow
                            # bootstrap, after syntax/native validation. It doesn't
                            # switch business selections or relax future admission.
                            module.api_request('GET','/version')
                            batches={source.source_id:module.load_or_fetch(source)[0] for source in sources}
                            from local_source import native_validator
                            unique=[]
                            for source in sources:
                                unique += [dict(n,name=source.source_id+'-'+str(i)) for i,n in enumerate(batches[source.source_id])]
                            native_validator('/local-subscription/core',unique)
                            release,manifest,risk,reasons,hold=module.create_release(batches,sources,{},0,{})
                            if hold:raise RuntimeError('bootstrap_below_configured_minimum')
                            previous_mode=module.MODE
                            try:
                                module.MODE='shadow';ok,_=module.publish(release,manifest,sources)
                                if not ok:raise RuntimeError('bootstrap_publish_deferred')
                            finally:module.MODE=previous_mode
                        bootstrap_verified=module.DATA/'bootstrap-runtime-verified.json'
                        if not bootstrap_verified.exists():
                            module.refresh_providers(sources)
                            runtime=module.api_request('GET','/providers/proxies').get('providers',{})
                            for source in sources:
                                nodes=runtime.get(source.provider_name,{}).get('proxies',[])
                                if not any(n.get('type') not in ('Reject','RejectDrop','Direct','Pass','PassRule') and not n.get('name','').startswith('__STACK_EMPTY_') for n in nodes):
                                    raise module.ControllerError('bootstrap_provider_not_loaded:'+source.source_id)
                            module.atomic_json(bootstrap_verified,{'at':time.time()})
                            module.atomic_json(module.DATA.parent/'local-discovery.json',{'at':time.time(),'source':'public_release'})
                            current=module.current_manifest()
                            module.atomic_json(module.HEALTH_PATH,{'status':'ok','mode':module.MODE,'epoch':module.now(),'node_count':current['node_count'],'current_release':current['release_id']})
                        else:
                            before=module.current_manifest().get('release_id')
                            module.cycle()
                            after=(module.current_manifest() or {}).get('release_id')
                            if before!=after:module.atomic_json(module.DATA.parent/'local-discovery.json',{'at':time.time(),'source':'public_release'})
                        delay=module.INTERVAL
            except Exception as error:
                # Retain controlled reason codes without leaking URLs or node data.
                detail=str(error)
                reason=detail if isinstance(error,module.ControllerError) and re.fullmatch(r'[A-Za-z0-9_:.+-]{1,140}',detail) else type(error).__name__
                module.log('cycle_failed',reason,'error')
                module.atomic_json(module.HEALTH_PATH,{'status':'degraded','mode':module.MODE,'epoch':module.now(),'reason':reason,'current_release':(module.current_manifest() or {}).get('release_id','')})
            # Keep the existing bounded probation/recovery work during the fetch
            # cooldown; bootstrapping must not remove these safety checks.
            deadline=max(started+delay,time.monotonic()+10)
            while time.monotonic()<deadline:
                time.sleep(min(30,max(1,deadline-time.monotonic())))
                try:
                    module.maintain_probation()
                    if module.repair_pointer():
                        with module.exclusive(module.DATA.parent/'routing-owner.lock') as acquired:
                            if acquired:
                                module.refresh_providers(module.load_sources())
                                (module.DATA/'recovery-refresh.json').unlink(missing_ok=True)
                except Exception as error:
                    module.log('release_probation_tick_error',type(error).__name__,'warning')
    return run


def main():
    module=load();install_public_header(module);install_usage_bridge()
    load_sources=module.load_sources
    def load_optional_sources():
        try:return load_sources()
        except module.ControllerError as error:
            if str(error)=='no_enabled_sources':return []
            raise
    module.load_sources=load_optional_sources
    previous_health=module.health_http_code
    module.health_http_code=lambda health:200 if health.get('status')=='awaiting_sources' and 0<=module.now()-health.get('epoch',0)<90 else previous_health(health)
    parse=module.parse_nodes
    def parse_nodes(raw):
        decoded=module.maybe_decode_base64(raw)
        text=decoded.decode('utf-8-sig').strip()
        if re.match(r'(?i)^(ss|vmess|vless|trojan|hy2|hysteria2|socks5|https?)://',text):
            from node_links import parse_line
            lines=[line.strip() for line in text.splitlines() if line.strip()]
            if len(lines)>10000:raise ValueError('subscription_node_limit')
            return [dict(node,name=name) for name,node in map(parse_line,lines)]
        return parse(raw)
    module.parse_nodes=parse_nodes;module.scheduler=scheduler(module)
    module.main()


if __name__=='__main__':main()
