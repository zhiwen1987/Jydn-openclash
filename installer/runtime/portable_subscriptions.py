"""Portable startup for empty/new sites; existing accepted releases stay sticky."""
import importlib.util
import json
import os
import re
import sys
import threading
import time
import urllib.parse

sys.path.insert(0,'/local-subscription')


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
        while True:
            started=time.time();delay=30
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
                            module.refresh_providers(sources)
                            module.atomic_json(module.DATA.parent/'local-discovery.json',{'at':time.time(),'source':'public_release'})
                            module.atomic_json(module.HEALTH_PATH,{'status':'ok','mode':module.MODE,'epoch':module.now(),'node_count':manifest['node_count'],'current_release':release})
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
            time.sleep(max(10,delay-(time.time()-started)))
    return run


def main():
    module=load();install_public_header(module)
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
