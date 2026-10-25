"""Exact router kernel, network=none. All origins, proxies and DNS are loopback."""
import contextlib,json,os,shutil,socket,struct,subprocess,tempfile,threading,time,urllib.request,urllib.parse,uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from strict_select import activate
ROOT=Path('/strict');TOKEN='isolated-lab-only';op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
HTTP_ERRORS={}
class Origin(BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def do_GET(self):
  body=b'strict-origin-ok';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
def api(port,path,method='GET',body=None):
 req=urllib.request.Request('http://127.0.0.1:'+str(port)+path,method=method,data=json.dumps(body,ensure_ascii=False).encode() if body is not None else None,headers={'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'})
 with op.open(req,timeout=5) as r:raw=r.read()
 return json.loads(raw) if raw else {}
def select(group,node):return api(19447,'/proxies/'+urllib.parse.quote(group,safe=''),'PUT',{'name':node})
def http(business):
 client=urllib.request.build_opener(urllib.request.ProxyHandler({'http':'http://127.0.0.1:19445'}))
 try:
  with client.open('http://'+business.lower()+'.strict.invalid:19440/',timeout=3) as r:return r.status==200 and r.read()==b'strict-origin-ok'
 except Exception as error:
  HTTP_ERRORS[business]={'type':type(error).__name__,'detail':str(error)[:180]};return False
def recv_exact(s,n):
 out=b''
 while len(out)<n:
  part=s.recv(n-len(out))
  if not part:raise EOFError()
  out+=part
 return out
def dns(business):
 name=uuid.uuid4().hex[:8]+'.'+business.lower()+'.strict.invalid';ident=os.urandom(2)
 q=ident+struct.pack('!5H',0x100,1,0,0,0)+b''.join(bytes([len(p)])+p.encode() for p in name.split('.'))+b'\x00'+struct.pack('!2H',1,1)
 try:
  with socket.create_connection(('127.0.0.1',19456),timeout=5) as s:
   s.sendall(struct.pack('!H',len(q))+q);n=struct.unpack('!H',recv_exact(s,2))[0];r=recv_exact(s,n)
  h=struct.unpack('!6H',r[:12]);return r[:2]==ident and (h[1]&15)==0 and h[3]>0
 except Exception:return False
def main():
 results=[];processes=[];server=ThreadingHTTPServer(('127.0.0.1',19440),Origin);threading.Thread(target=server.serve_forever,daemon=True).start()
 with tempfile.TemporaryDirectory() as temp:
  root=Path(temp);a=root/'fixture';b=root/'candidate';a.mkdir();b.mkdir()
  def start(folder,config):
   if config=='all-nodes.yaml':
    for filename in ['provider-one.yaml','provider-two.yaml']:
     if not (folder/filename).exists():(folder/filename).write_bytes((ROOT/filename).read_bytes())
   path=folder/'config.yaml';path.write_bytes((ROOT/config).read_bytes())
   log=(folder/'core.log').open('ab');p=subprocess.Popen([str(ROOT/'core'),'-d',str(folder),'-f',str(path)],stdout=log,stderr=log,env={**os.environ,'GOMAXPROCS':'1','GOMEMLIMIT':'48MiB'});processes.append((p,log))
   port=19446 if folder==a else 19447;deadline=time.time()+30
   while time.time()<deadline:
    if p.poll() is not None:raise RuntimeError('isolated core exited: '+(folder/'core.log').read_text()[-500:])
    try:
     api(port,'/version')
     if folder==b and api(port,'/proxies/Google').get('type')!='Selector':raise RuntimeError('groups not ready')
     with socket.create_connection(('127.0.0.1',19441 if folder==a else 19445),timeout=.4):pass
     return p
    except Exception:time.sleep(.25)
   raise RuntimeError('isolated core not ready')
  def stop(p):
   p.terminate()
   try:p.wait(timeout=8)
   except subprocess.TimeoutExpired:p.kill();p.wait()
  def check(name,condition):
   if not condition:raise AssertionError(name)
   results.append(name)
  try:
   pa=start(a,'fixture.yaml');pb=start(b,'empty.yaml')
   deadline=time.time()+8
   while time.time()<deadline and not http('Google'):time.sleep(.25)
   check('baseline_google_http',http('Google'));check('baseline_gemini_http',http('Gemini'))
   check('baseline_google_dns',dns('Google'));check('baseline_gemini_dns',dns('Gemini'))
   # Hold an old public Google connection, then exercise the actual activation helper.
   held=socket.create_connection(('127.0.0.1',19445),timeout=4)
   held.sendall(b'CONNECT google.strict.invalid:19440 HTTP/1.1\r\nHost: google.strict.invalid:19440\r\n\r\n')
   check('old_connection_established',b'200' in held.recv(4096));time.sleep(.25)
   held.sendall(b'GET / HTTP/1.1\r\nHost: google.strict.invalid\r\n\r\n');held.recv(4096);time.sleep(.25)
   activated=activate(lambda path,method='GET',body=None:api(19447,path,method,body),'Google','node')
   check('old_google_connections_drained',activated['matching_connections_closed']>=1);held.close()
   check('empty_node_http_rejected',not http('Google'));check('empty_node_dns_rejected',not dns('Google'))
   check('other_business_http_unchanged',http('Gemini'));check('other_business_dns_unchanged',dns('Gemini'))
   stop(pb);pb=start(b,'configured.yaml')
   select('Google','🔐 自定义节点');select('🔐 自定义节点','🔐 自建节点 · own-good')
   check('approved_node_http',http('Google'));check('approved_node_dns',dns('Google'))
   select('Gemini','🔐 自定义节点')
   check('shared_node_serves_two_businesses',http('Google') and http('Gemini') and dns('Gemini'))
   api(19446,'/configs','PATCH',{'mixed-port':0});time.sleep(.3)
   check('failed_node_http_rejected',not http('Google'));check('failed_node_dns_rejected',not dns('Google'))
   check('shared_node_failure_rejects_all_subscribers',not http('Gemini') and not dns('Gemini'))
   select('Gemini','PublicPool')
   check('business_can_independently_leave_shared_entry',http('Gemini') and dns('Gemini'))
   check('failed_node_no_other_http_impact',http('Gemini'));check('failed_node_no_other_dns_impact',dns('Gemini'))
   time.sleep(2);stop(pb);pb=start(b,'configured.yaml')
   check('restart_keeps_strict_outer',api(19447,'/proxies/'+urllib.parse.quote('Google',safe=''))['now']=='🔐 自定义节点')
   check('restart_does_not_fall_back',not http('Google'))
   api(19446,'/configs','PATCH',{'mixed-port':19441})
   select('Google','🔐 自定义节点');select('🔐 自定义节点','🔐 自建节点池 · mine')
   deadline=time.time()+12
   while time.time()<deadline and not http('Google'):time.sleep(.5)
   check('pool_uses_approved_healthy_member',http('Google'))
   api(19446,'/configs','PATCH',{'mixed-port':0});time.sleep(2)
   check('all_pool_nodes_failed_http_rejected',not http('Google'));check('all_pool_nodes_failed_dns_rejected',not dns('Google'))
   check('pool_failure_other_business_ok',http('Gemini') and dns('Gemini'))
   stop(pb);shutil.rmtree(b);b.mkdir();pb=start(b,'locked.yaml')
   check('cache_loss_retains_durable_allowlist',api(19447,'/proxies/Google')['all']==['🔐 自定义节点','REJECT'])
   check('cache_loss_does_not_restore_public_traffic',not http('Google') and not dns('Google'))
   check('durable_lock_other_business_unchanged',http('Gemini') and dns('Gemini'))
   try:select('Google','PublicPool');escaped=True
   except Exception:escaped=False
   check('durable_lock_refuses_public_api_selection',not escaped)
   stop(pb);pb=start(b,'locked-empty.yaml')
   check('removed_nodes_stay_rejected',not http('Google') and not dns('Google'))
   check('removed_nodes_other_business_ok',http('Gemini') and dns('Gemini'))
   stop(pb);shutil.rmtree(b);b.mkdir();api(19446,'/configs','PATCH',{'mixed-port':19441});pb=start(b,'all-nodes.yaml')
   shared='🔐 自定义节点';path='/proxies/'+urllib.parse.quote(shared,safe='');deadline=time.time()+10
   while time.time()<deadline and 'subscription-good' not in api(19447,path)['all']:time.sleep(.2)
   entry=api(19447,path)
   check('all_sources_visible',set(entry['all'])=={'REJECT','raw-good','subscription-good','subscription-bad'})
   check('all_nodes_defaults_reject',entry['now']=='REJECT' and entry.get('emptyFallback')=='REJECT')
   check('group_and_bypass_nodes_not_selectable',not set(entry['all']) & {'DIRECT','PublicPool','raw-direct','alias-direct','剩余流量 99GB'})
   select('Google',shared);select(shared,'subscription-good')
   check('subscription_node_http_and_dns',http('Google') and dns('Google'))
   api(19446,'/configs','PATCH',{'mixed-port':0});time.sleep(.3)
   check('subscription_failure_does_not_switch',not http('Google') and not dns('Google') and api(19447,path)['now']=='subscription-good')
   check('subscription_failure_other_business_ok',http('Gemini') and dns('Gemini'))
   api(19446,'/configs','PATCH',{'mixed-port':19441})
   replacement={'proxies':[{'name':'subscription-replacement','type':'socks5','server':'127.0.0.1','port':19441}]}
   (b/'provider-one.yaml').write_text(json.dumps(replacement));api(19447,'/providers/proxies/provider-one','PUT')
   entry=api(19447,path)
   check('provider_refresh_adds_new_node', 'subscription-replacement' in entry['all'] and 'subscription-good' not in entry['all'])
   check('removed_selected_subscription_rejects',entry['now']=='REJECT' and not http('Google') and not dns('Google'))
   select(shared,'raw-good');check('inline_node_selectable',http('Google') and dns('Google'))
   select(shared,'subscription-replacement');check('new_subscription_selectable',http('Google') and dns('Google'))
   print(json.dumps({'passed':True,'tests':results,'test_count':len(results),'network':'none','production_data_mounted':False,'production_selectors_changed':False,'native_kernel_sha256':__import__('hashlib').sha256((ROOT/'core').read_bytes()).hexdigest()}))
  except BaseException as error:
   import sys
   print(json.dumps({'failed_step':str(error),'http_errors':HTTP_ERRORS,'candidate_log':(b/'core.log').read_text(errors='replace')[-1400:],'fixture_log':(a/'core.log').read_text(errors='replace')[-800:]},ensure_ascii=False),file=sys.stderr)
   raise
  finally:
   for process,log in reversed(processes):
    if process.poll() is None:stop(process)
    log.close()
   server.shutdown();server.server_close()
if __name__=='__main__':main()
