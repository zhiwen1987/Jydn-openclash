"""Real local HTTP/curl regression; never reads real subscriptions or publishes nodes."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import json,os,shutil,tempfile,threading,time,unittest,urllib.parse,urllib.request
import subscription_usage as usage


def run_lifecycle():
    temporary=tempfile.TemporaryDirectory(prefix='usage-isolated-');work=Path(temporary.name)
    modes={};downloads={'a':100,'b':200,'c':300,'d':400,'e':500,'f':600};calls={};snapshots=[]
    class Origin(BaseHTTPRequestHandler):
     def log_message(self,*args):pass
     def do_GET(self):
      key=urllib.parse.urlsplit(self.path).path[1:];calls[key]=calls.get(key,0)+1;mode=modes.get(key,'ok')
      if mode=='slow':time.sleep(5)
      self.send_response(503 if mode=='fail' else 429 if mode=='limit' else 200)
      if mode=='limit':self.send_header('Retry-After','60')
      if mode in ('ok','slow'):self.send_header('subscription-userinfo',f'upload=1; download={downloads[key]}; total=100000; expire=2000000000')
      self.send_header('Content-Length','0');self.end_headers()
    origin=ThreadingHTTPServer(('127.0.0.1',0),Origin)
    threading.Thread(target=origin.serve_forever,daemon=True).start()
    source_path=work/'sources.yaml'
    def write(keys):
     data={'sources':[{'id':k,'name':'隔离来源 '+k.upper(),'url':f'http://127.0.0.1:{origin.server_port}/{k}'} for k in keys]}
     temp=work/'next.yaml';temp.write_text(json.dumps(data),encoding='utf-8');os.replace(temp,source_path)
    write(['a','b'])
    # Only normal refresh is accelerated. Registry watching, real curl, timeout,
    # backoff and the metadata HTTP handlers are the deployed implementations.
    collector=usage.Collector(source_path,work/'cache',usage.Fetcher(timeout=3),interval=3,stale_after=20)
    class Web(BaseHTTPRequestHandler):
     def log_message(self,*args):pass
     def send(self,status,kind,raw):
      self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
     def do_GET(self):self.send(404,'text/plain',b'fixture')
    namespace={'Handler':Web,'SOURCES_FILE':source_path,'DATA':work/'controller','ALLOWED_PROVIDER_CLIENTS':{'127.0.0.1'},'dashboard':lambda:b'<main></main>'}
    usage.install(namespace,collector)
    server=ThreadingHTTPServer(('127.0.0.1',0),Web);threading.Thread(target=server.serve_forever,daemon=True).start()
    base=f'http://127.0.0.1:{server.server_port}'
    op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def get(private=False):
     request=urllib.request.Request(base+('/subscription-info' if private else '/api/subscription-usage'),headers={'Authorization':'Bearer '+collector.token} if private else {})
     with op.open(request,timeout=2) as r:return json.load(r)
    def rows(d):return {p['id']:p for p in d['providers']}
    def wait(predicate,limit=14):
     started=time.monotonic()
     while time.monotonic()-started<limit:
      d=get()
      if predicate(d):return d,round(time.monotonic()-started,3)
      time.sleep(.1)
     raise AssertionError('fixture_timeout')
    def stage(name,d,seconds=None):
     assert d['registry_state']=='ok'
     # Also cross-check the private OpenClash aggregate HTTP endpoint every stage.
     other=get(True);assert [p['id'] for p in d['providers']]==[p['id'] for p in other['providers']]
     snapshots.append({'stage':name,'elapsed_seconds':seconds,'data':d})
    def okids(d,ids):
     r=rows(d);return set(r)==set(ids) and all(r[k]['usage_status']=='ok' for k in ids)
    try:
     d,t=wait(lambda d:okids(d,['a','b']));stage('initial_two',d,t)
     write(['a','b','c']);d,t=wait(lambda d:okids(d,['a','b','c']))
     assert [rows(d)[k]['metrics']['download'] for k in ['a','b','c']]==[100,200,300]
     stage('third_added',d,t)
     write(['a','c']);d,t=wait(lambda d:set(rows(d))=={'a','c'});stage('second_deleted',d,t)
     modes['a']='fail';downloads['c']=4321
     d,t=wait(lambda d:rows(d)['a']['usage_status']=='cached' and rows(d)['a']['error']=='http_503' and rows(d)['c']['metrics']['download']==4321)
     assert rows(d)['a']['metrics']['download']==100 and rows(d)['c']['usage_status']=='ok'
     stage('one_503_other_updated',d,t)
     modes['d']='limit';write(['a','c','d'])
     d,t=wait(lambda d:'d' in rows(d) and rows(d)['d']['usage_status']=='unavailable' and rows(d)['d']['error']=='http_429')
     assert rows(d)['d']['metrics'] is None;assert rows(d)['d']['next_due']>time.time()+40
     stage('429_new_source_no_fake_zero',d,t)
     attempts=calls['d'];downloads['c']=5432
     d,t=wait(lambda d:rows(d)['c']['metrics']['download']==5432)
     assert calls['d']==attempts and rows(d)['c']['usage_status']=='ok'
     stage('429_backoff_other_keeps_refreshing',d,t)
     modes['e']='slow';write(['a','c','d','e'])
     d,t=wait(lambda d:'e' in rows(d) and calls.get('e',0)>0)
     started=time.monotonic();get();latency=round(time.monotonic()-started,4);assert latency<1
     assert rows(d)['e']['usage_status']=='checking'
     stage('slow_source_api_nonblocking',d,t)
     write(['a','c','d']);d,t=wait(lambda d:'e' not in rows(d));time.sleep(5)
     d=get();assert 'e' not in rows(d);stage('inflight_deleted_does_not_reappear',d,t)
     modes['f']='slow';write(['a','c','d','f']);downloads['c']=6543
     d,t=wait(lambda d:'f' in rows(d) and rows(d)['f']['usage_status']=='unavailable' and rows(d)['f']['error']=='transport_unavailable' and rows(d)['c']['metrics']['download']==6543)
     assert rows(d)['c']['usage_status']=='ok' and rows(d)['f']['metrics'] is None
     stage('timeout_other_still_updates',d,t)
     write([]);d,t=wait(lambda d:not d['providers']);stage('all_deleted_empty_inventory',d,t)
     modes.clear();write(['a','b','c']);d,t=wait(lambda d:okids(d,['a','b','c']));stage('readded_three_after_empty',d,t)
     return {'passed':True,'real_curl_and_http':True,'isolated_loopback_only':True,'normal_interval_seconds':3,'production_normal_interval_seconds':600,'api_latency_during_slow_source':latency,'stages':snapshots}
    finally:
     collector.close();server.shutdown();server.server_close();origin.shutdown();origin.server_close();temporary.cleanup()


@unittest.skipUnless(shutil.which('curl'), 'curl is required for real HTTP acceptance')
class HttpLifecycle(unittest.TestCase):
    def test_dynamic_sources_failure_isolation_and_late_deletion(self):
        result=run_lifecycle()
        self.assertTrue(result['passed'])
        self.assertEqual(len(result['stages']),11)
        self.assertLess(result['api_latency_during_slow_source'],1)


if __name__=='__main__':unittest.main()
