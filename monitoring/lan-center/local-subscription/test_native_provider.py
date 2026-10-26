"""Exact production kernel + real HTTP/provider/auth/health DB, network=none.

Everything uses synthetic credentials and loopback origins, in disposable data.
"""
import contextlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml
from local_source import Manager, SELECTOR, PROBE, PROVIDER, EMPTY, native_validator
from local_web import install

ROOT = Path(__file__).parent
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec);sys.modules[name] = mod;spec.loader.exec_module(mod)
    return mod


def main():
    os.environ['NO_PROXY'] = ''
    os.environ['no_proxy'] = ''
    checks, processes, servers = [], [], []
    def check(name, condition):
        if not condition: raise AssertionError(name)
        checks.append(name)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        def core(name, config, port):
            folder=tmp/name;folder.mkdir(exist_ok=True);path=folder/'config.yaml';path.write_text(yaml.safe_dump(config,allow_unicode=True))
            log=(folder/'core.log').open('ab')
            p=subprocess.Popen([str(ROOT/'core'),'-d',str(folder),'-f',str(path)],stdout=log,stderr=log,env={**os.environ,'GOMAXPROCS':'1','GOMEMLIMIT':'48MiB'})
            processes.append((p,log))
            for _ in range(120):
                if p.poll() is not None: raise RuntimeError('fixture core exited: '+(folder/'core.log').read_text()[-700:])
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):return p
                except OSError:time.sleep(.1)
            raise RuntimeError('fixture core not ready')
        def request(path, method='GET', data=None, headers=None, port=19003):
            headers=dict(headers or {})
            if data is not None:headers['Content-Type']='application/json'
            req=urllib.request.Request('http://127.0.0.1:'+str(port)+path,method=method,data=json.dumps(data).encode() if data is not None else None,headers=headers)
            try:
                with OPENER.open(req,timeout=40) as r:return r.status,r.read(),r.headers
            except urllib.error.HTTPError as e:return e.code,e.read(),e.headers
        def api(path, method='GET', body=None):
            code,raw,_=request(path,method,body,{'Authorization':'Bearer lab-kernel'},19090)
            if code>=300:raise RuntimeError('fixture API failure '+str(code))
            return json.loads(raw) if raw else {}
        def select(group, target):api('/proxies/'+urllib.parse.quote(group,safe=''),'PUT',{'name':target})
        def proxy_http(port):
            try:
                with socket.create_connection(('127.0.0.1',19080),timeout=3) as s:
                    s.sendall(('GET http://127.0.0.1:'+str(port)+'/ HTTP/1.1\r\nHost: 127.0.0.1:'+str(port)+'\r\nConnection: close\r\n\r\n').encode())
                    return b'200' in s.recv(128).split(b'\r\n',1)[0]
            except OSError:return False
        class Origin(BaseHTTPRequestHandler):
            def log_message(self,*a):pass
            def do_GET(self):
                self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
        try:
            for port in (19082,19083):
                server=ThreadingHTTPServer(('127.0.0.1',port),Origin);servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start()
            upstream_config={'socks-port':19081,'allow-lan':False,'mode':'direct','dns':{'enable':False}}
            private_core=core('upstream',upstream_config,19081)
            core('public',dict(upstream_config,**{'socks-port':19084}),19084)
            os.environ.update(SUBSCRIPTION_DATA_DIR=str(tmp/'data/subscription-controller'),SUBSCRIPTION_DB=str(tmp/'data/subscription-controller/controller.db'),OPENCLASH_API='http://127.0.0.1:19090',OPENCLASH_SECRET='lab-kernel',LOCAL_SOURCE_HOSTS='127.0.0.1:19003',CAPABILITY_DB=str(tmp/'data/node-capability.db'))
            controller=module('lab_subscription_controller',ROOT/'subscription-controller.py')
            controller.DATA.mkdir(parents=True)
            with controller.db():pass
            controller.dashboard=lambda:'<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>订阅管理隔离验收</title><main><h1>订阅管理隔离验收</h1></main></html>'.encode()
            controller.ALLOWED_PROVIDER_CLIENTS={'127.0.0.1'}
            manager=Manager(controller.DATA/'local-source',api,lambda nodes:native_validator(ROOT/'core',nodes),tmp/'data/node-capability.db')
            if '--serve-ui' in sys.argv:
                (manager.root/'admin-token').write_text('isolated-ui-only\n')
                os.environ['LOCAL_SOURCE_HOSTS'] += ',127.0.0.1:13113'
            install(vars(controller),manager)
            server=ThreadingHTTPServer(('0.0.0.0' if '--serve-ui' in sys.argv else '127.0.0.1',19003),controller.Handler);servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start()
            sentinel_filter='^'+__import__('re').escape(EMPTY)+'$'
            config={'mixed-port':19080,'external-controller':'127.0.0.1:19090','secret':'lab-kernel','allow-lan':False,'mode':'rule','dns':{'enable':False},'profile':{'store-selected':True},
                'proxy-providers':{PROVIDER:{'type':'http','url':'http://127.0.0.1:19003/providers/local-custom.yaml','path':'./local.yaml','proxy':'DIRECT','interval':3600,'header':{'Authorization':['Bearer '+manager.credential('provider-token')]},'health-check':{'enable':False}}},
                'proxies':[{'name':'Public','type':'socks5','server':'127.0.0.1','port':19084}],
                'proxy-groups':[{'name':'Google','type':'select','proxies':['Public',SELECTOR]},{'name':'Gemini','type':'select','proxies':['Public']},{'name':SELECTOR,'type':'select','proxies':['REJECT','Public'],'use':[PROVIDER],'exclude-filter':sentinel_filter,'empty-fallback':'REJECT'},{'name':PROBE,'type':'select','proxies':['Public'],'use':[PROVIDER],'exclude-filter':sentinel_filter}],
                'listeners':[{'name':'probe-only','type':'http','listen':'127.0.0.1','port':19085,'proxy':PROBE}],
                'rules':['DST-PORT,19082,Google','MATCH,Gemini']}
            primary=core('router',config,19090)
            for _ in range(80):
                try:manager.verify([]);break
                except Exception:time.sleep(.1)
            manager.verify([]);check('native_empty_provider_is_closed_and_sentinel_hidden',True)
            check('unauthenticated_status_denied',request('/api/local/status')[0]==401)
            check('provider_credentials_not_in_url_required',request('/providers/local-custom.yaml')[0]==403)
            check('cross_origin_write_denied',request('/api/local/login','POST',{'token':'x'},{'Origin':'http://evil.invalid'})[0]==403)
            headers={'Origin':'http://127.0.0.1:19003'}
            code,raw,h=request('/api/local/login','POST',{'token':manager.credential('admin-token')},headers)
            check('authenticated_login',code==200 and 'HttpOnly' in h['Set-Cookie'] and 'SameSite=Strict' in h['Set-Cookie'])
            headers['Cookie']=h['Set-Cookie'].split(';')[0];headers['X-CSRF-Token']=json.loads(raw)['csrf']
            check('csrf_missing_denied',request('/api/local/publish','POST',{'version':0},{'Origin':headers['Origin'],'Cookie':headers['Cookie']})[0]==403)
            link='socks5://127.0.0.1:19081#本地验收'
            code,raw,_=request('/api/local/preview','POST',{'text':link},headers);check('uri_preview_native_validation',code==200 and json.loads(raw)['count']==1)
            code,raw,_=request('/api/local/publish','POST',{'version':0,'mode':'merge','text':link},headers)
            check('real_provider_refresh_and_custom_and_probe_membership',code==200 and json.loads(raw)['status']=='loaded')
            node=manager.read('state.json')['nodes'][0]
            select('Google',SELECTOR);select(SELECTOR,node['name'])
            check('real_http_via_imported_node',proxy_http(19082))
            check('other_business_http_unchanged',proxy_http(19083))
            # Exercise the original public publisher against actual native HTTP
            # providers. Each source-count case gets a fresh public bootstrap;
            # private canonical data/pointer stay constant across every case.
            private_before=manager.provider_payload()
            controller.PUBLISH_TOKEN='synthetic-public-publish-token-12345678'
            sources=[controller.Source('publica','fixture A','http://127.0.0.1:19082/source/a','Public_A'),controller.Source('publicb','fixture B','http://127.0.0.1:19082/source/b','Public_B')]
            source_nodes={s.source_id:[{'name':s.source_id+'-'+str(i),'type':'socks5','server':'127.0.0.1','port':19084,'username':s.source_id+str(i),'password':'synthetic-only'} for i in range(3)] for s in sources}
            for case,count,forced_failure in [('one-source',1,False),('two-sources',2,False),('public-rollback',2,True)]:
                controller.DATA=tmp/'data'/case;controller.DATA.mkdir()
                for key,filename in [('DB_PATH','controller.db'),('RELEASES','releases'),('CACHE','cache'),('CURRENT_PATH','current.json'),('PENDING_PATH','publish-pending.json'),('LOG_PATH','controller.log'),('HEALTH_PATH','health.json')]:setattr(controller,key,controller.DATA/filename)
                with controller.db():pass
                batch=sources[:count];definitions={s.source_id:source_nodes[s.source_id] for s in batch}
                controller.MODE='shadow'
                rid,manifest,*_=controller.create_release(definitions,batch,{},0,{})
                check(case+'_original_shadow_bootstrap',controller.publish(rid,manifest,batch)[0])
                for source in batch:
                    config['proxy-providers'][source.provider_name]={'type':'http','url':'http://127.0.0.1:19003/providers/'+source.source_id+'.yaml?token='+controller.PUBLISH_TOKEN,'path':'./'+source.source_id+'.yaml','proxy':'DIRECT','interval':3600,'health-check':{'enable':False}}
                config['proxy-groups'][2]['use']=[PROVIDER]+[s.provider_name for s in batch]
                config_path=tmp/'router/config.yaml';config_path.write_text(yaml.safe_dump(config,allow_unicode=True))
                api('/configs?force=true','PUT',{'path':str(config_path)})
                select('Google',SELECTOR);select(SELECTOR,node['name'])
                controller.MODE='automatic';controller.POST_PUBLISH_WAIT=1
                controller.production_smoke=(lambda:(False,'isolated_forced_failure')) if forced_failure else (lambda:(proxy_http(19083),'loopback_public_business'))
                changed={key:[dict(n,name=n['name']+'-updated') for n in values] for key,values in definitions.items()}
                rid2,manifest2,*_=controller.create_release(changed,batch,{},0,{s.source_id:3 for s in batch})
                published,_=controller.publish(rid2,manifest2,batch)
                check(case+'_actual_native_public_publish',published is not forced_failure)
                check(case+'_private_source_not_overwritten',manager.provider_payload()==private_before and proxy_http(19082))
                if forced_failure:check('failed_public_release_pointer_restored',controller.current_manifest()['release_id']==rid)
            # Exercise existing discovery and actual curl->node->origin probes,
            # substituting only test targets inside this isolated network.
            cap=module('lab_capability',ROOT/'node-capability.py');cap.init_db()
            cap.API='http://127.0.0.1:19090';cap.API_SECRET='lab-kernel';cap.PROXY='http://127.0.0.1:19085';cap.PROXY_AUTH='fixture:fixture';cap.GROUP=PROBE;cap.SETTLE_SECONDS=0;cap.GENERAL_ATTEMPTS=1
            cap.GENERAL_PROBES=[(name,'http://127.0.0.1:19083/','GET',{200},None) for name in ('one','two','three')]
            cap.BUSINESS_PROBES=[('fixture_business','http://127.0.0.1:19083/','GET',{200},None)]
            cap.probe_egress=lambda:{}
            nodes=cap.sync_nodes(cap.discover_nodes());entry=next(n for n in nodes if n['name']==node['name'])
            # Mark Public evaluated first so the existing scheduler allows deep checks.
            cap.probe_node(next(n for n in nodes if n['name']=='Public'));cap.probe_node(entry)
            state=manager.status();check('capability_db_discovery_real_probe_recorded',state['nodes'][0]['evaluated_at']>0 and state['nodes'][0]['health']!='queued')
            check('health_detection_did_not_change_business_choice',api('/proxies/Google')['now']==SELECTOR and api('/proxies/Gemini')['now']=='Public')
            private_core.terminate();private_core.wait(timeout=8)
            check('private_node_fault_does_not_fallback_to_public',not proxy_http(19082) and api('/proxies/'+urllib.parse.quote(SELECTOR,safe=''))['now']==node['name'])
            check('private_node_fault_does_not_affect_other_business',proxy_http(19083))
            cap.probe_node(entry);cap.probe_node(entry)
            check('failed_private_node_recorded_in_health_database',manager.status()['nodes'][0]['health'] in ('cooling','unavailable'))
            private_core=core('upstream',upstream_config,19081)
            # Kernel/provider survives restart with the same mounted source data.
            primary.terminate();primary.wait(timeout=8)
            path=tmp/'router/config.yaml';log=(tmp/'router/core.log').open('ab');primary=subprocess.Popen([str(ROOT/'core'),'-d',str(tmp/'router'),'-f',str(path)],stdout=log,stderr=log,env={**os.environ,'GOMAXPROCS':'1'});processes.append((primary,log))
            for _ in range(80):
                try:manager.verify([node]);break
                except Exception:time.sleep(.1)
            manager.verify([node]);check('kernel_restart_preserves_private_provider',True)
            select('Google',SELECTOR);select(SELECTOR,node['name'])
            code,raw,_=request('/api/local/publish','POST',{'version':manager.read('state.json')['version'],'mode':'remove','ids':[node['id']]},headers)
            selected_after=api('/proxies/'+urllib.parse.quote(SELECTOR,safe=''))['now'];http_after=proxy_http(19082)
            if code!=200 or selected_after!='REJECT' or http_after:
                print(json.dumps({'delete_status':code,'delete_receipt':raw.decode(),'selected_after':selected_after,'http_after':http_after,'google_now':api('/proxies/Google')['now']},ensure_ascii=False),flush=True)
            check('selected_node_deletion_fails_closed',code==200 and selected_after=='REJECT' and not http_after)
            check('public_business_remains_available_after_private_delete',proxy_http(19083))
            check('no_private_members_in_other_business_pool',api('/proxies/Gemini')['all']==['Public'])
            print(json.dumps({'passed':len(checks),'checks':checks},ensure_ascii=False))
            if '--serve-ui' in sys.argv:
                print('isolated_ui_ready',flush=True)
                while True:time.sleep(1)
        except Exception:
            print(json.dumps({'checks_before_failure':checks,'fixture_logs':{p.parent.name:p.read_text()[-1500:] for p in tmp.glob('*/core.log')}},ensure_ascii=False),flush=True)
            raise
        finally:
            for server in servers:server.shutdown();server.server_close()
            for p,log in processes:
                if p.poll() is None:
                    p.terminate()
                    try:p.wait(timeout=8)
                    except subprocess.TimeoutExpired:p.kill();p.wait()
                log.close()


if __name__=='__main__':main()
