import concurrent.futures
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

import subscription_usage as usage


GOOD = {'upload': 10, 'download': 20, 'total': 100, 'expire': 2000000000}


def source(sid, **extra):
    return dict(id=sid, name='来源 '+sid, url='https://subscription.example/'+sid+'?token=synthetic', **extra)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.sources = self.root/'sources.json'
        self.write([source('one'), source('two')])
        self.now = [1000]
        self.collectors = []

    def tearDown(self):
        for collector in self.collectors:
            collector.close()
        self.temp.cleanup()

    def write(self, entries):
        self.sources.write_text(json.dumps({'sources': entries}))

    def collector(self, fetcher=None):
        c = usage.Collector(self.sources, self.root/'data', fetcher or (lambda _: {'metrics': GOOD}),
                            clock=lambda: self.now[0], interval=60, stale_after=120)
        self.collectors.append(c)
        return c

    def settle(self, c, predicate=lambda data: all(p['usage_status']=='ok' for p in data['providers'])):
        for _ in range(100):
            c.tick(); data = c.snapshot()
            if predicate(data): return data
            time.sleep(.005)
        self.fail('fixture did not settle')

    def test_zero_one_two_three_and_removed_sources(self):
        c = self.collector();self.assertEqual(len(self.settle(c)['providers']),2)
        self.write([source('one'),source('two'),source('three')]);self.assertEqual(len(self.settle(c)['providers']),3)
        self.write([source('three')]);self.assertEqual([x['id'] for x in self.settle(c)['providers']],['three'])
        self.write([]);self.assertEqual(self.settle(c)['providers'],[])

    def test_disabled_sources_are_removed(self):
        self.write([source('one'),source('two',enabled=False)])
        self.assertEqual([x['id'] for x in self.settle(self.collector())['providers']],['one'])

    def test_one_invalid_source_does_not_block_other_sources(self):
        self.write([source('one'),{'id':'bad','url':'file:///etc/passwd'}])
        data=self.settle(self.collector(),lambda d:d['providers'][0]['usage_status']=='ok')
        self.assertEqual(data['providers'][1]['usage_status'],'unavailable')
        self.assertIsNone(data['providers'][1]['metrics'])

    def test_single_failure_leaves_other_source_available(self):
        c=self.collector(lambda url: {'error':'http_403'} if '/two?' in url else {'metrics':GOOD})
        data=self.settle(c,lambda d:d['providers'][1]['usage_status']=='unavailable')
        self.assertEqual(data['providers'][0]['usage_status'],'ok')
        self.assertEqual(data['providers'][1]['error'],'http_403')

    def test_failed_refresh_shows_cached_value_and_timestamp(self):
        results=[{'metrics':GOOD}]
        c=self.collector(lambda _:results[0]);self.settle(c)
        results[0]={'error':'transport_unavailable'};self.now[0]+=61
        data=self.settle(c,lambda d:d['providers'][0]['usage_status']=='cached')
        self.assertEqual(data['providers'][0]['metrics'],GOOD)
        self.assertEqual(data['providers'][0]['last_success'],1000)

    def test_expired_cache_is_explicit(self):
        c=self.collector();self.settle(c);self.now[0]+=121
        self.assertTrue(c.snapshot()['providers'][0]['stale'])
        self.assertEqual(c.snapshot()['providers'][0]['usage_status'],'cached')

    def test_new_account_same_id_does_not_inherit_old_usage(self):
        c=self.collector();self.settle(c)
        event=threading.Event()
        c.fetcher=lambda _: event.wait(.3) or {'metrics':GOOD}
        self.write([dict(source('one'),url='https://subscription.example/new?token=new-synthetic')])
        c.tick();self.assertIsNone(c.snapshot()['providers'][0]['metrics']);event.set()

    def test_invalid_registry_retains_known_source_inventory(self):
        c=self.collector();self.settle(c);self.sources.write_text('{')
        c.tick();data=c.snapshot();self.assertEqual(data['registry_state'],'error')
        self.assertEqual(len(data['providers']),2)

    def test_duplicate_source_id_is_not_silently_dropped(self):
        with self.assertRaises(usage.UsageError):usage.inventory({'sources':[source('one'),source('one')]})

    def test_converter_and_explicit_information_origin(self):
        entries=[dict(source('one'),url='http://converter.example/sub?url=https%3A%2F%2Forigin.example%2Fsub')]
        self.assertEqual(usage.inventory({'sources':entries})['one']['url'],'https://origin.example/sub')
        entries[0]['info_url']='https://other.example/info'
        self.assertEqual(usage.inventory({'sources':entries})['one']['url'],'https://other.example/info')
        opaque=dict(source('opaque'),url='https://origin.example/sub?sub=opaque-account-token')
        self.assertEqual(usage.inventory({'sources':[opaque]})['opaque']['url'],opaque['url'])

    def test_source_names_do_not_echo_private_urls(self):
        item=dict(source('one'),name='https://private.example/?token=private-value')
        self.assertEqual(usage.inventory({'sources':[item]})['one']['name'],'one')

    def test_header_validation_and_expiry_not_fabricated(self):
        self.assertEqual(usage.parse_userinfo('Subscription-Userinfo: upload=0; download=0; total=0'),{'upload':0,'download':0,'total':0})
        for text in ['upload=1;total=5','upload=-1;download=1;total=5','upload=1;upload=2;download=1;total=5',
                     'upload=1;download=2;total=9999999999999999']:
            with self.assertRaises(usage.UsageError):usage.parse_userinfo('subscription-userinfo: '+text)

    def test_cache_reused_after_worker_restart(self):
        c=self.collector();self.settle(c);c.close();self.collectors.remove(c)
        newer=self.collector(lambda _:self.fail('unchanged fresh cache should not fetch'))
        self.assertEqual(self.settle(newer)['providers'][0]['metrics'],GOOD)

    def test_persisted_cache_cannot_inject_extra_public_fields(self):
        c=self.collector();self.settle(c);c.close();self.collectors.remove(c)
        p=self.root/'data/cache.json';d=json.loads(p.read_text());d['records']['one']['metrics']['password']='synthetic-secret';p.write_text(json.dumps(d))
        newer=self.collector();self.assertNotIn('synthetic-secret',json.dumps(self.settle(newer)))

    def test_corrupt_cache_does_not_turn_into_zero_usage(self):
        (self.root/'data').mkdir();(self.root/'data/cache.json').write_text('{')
        c=self.collector(lambda _:{'error':'information_header_missing'})
        data=self.settle(c,lambda d:d['providers'][0]['usage_status']=='unavailable')
        self.assertIsNone(data['providers'][0]['metrics'])

    def test_inflight_deleted_source_cannot_reappear(self):
        event=threading.Event();c=self.collector(lambda _: event.wait(.2) and {'metrics':GOOD})
        c.tick();self.write([]);c.tick();event.set();time.sleep(.01);c.tick()
        self.assertEqual(c.snapshot()['providers'],[])

    def test_worker_queue_is_bounded(self):
        self.write([source('source'+str(n)) for n in range(20)]);event=threading.Event()
        c=self.collector(lambda _:event.wait(.2) and {'metrics':GOOD});c.tick()
        self.assertLessEqual(len(c.pending),2);event.set()

    def test_slow_source_does_not_block_snapshot_or_fast_source(self):
        event=threading.Event()
        def fetch(url):
            if '/one?' in url:event.wait(.3)
            return {'metrics':GOOD}
        c=self.collector(fetch);c.tick();started=time.monotonic();c.snapshot()
        self.assertLess(time.monotonic()-started,.05)
        data=self.settle(c,lambda d:d['providers'][1]['usage_status']=='ok')
        self.assertEqual(data['providers'][0]['usage_status'],'checking');event.set()

    def test_rate_limit_honored_without_hammering(self):
        calls=[];c=self.collector(lambda url:calls.append(url) or {'error':'http_429','retry_after':900})
        self.settle(c,lambda d:d['providers'][0]['usage_status']=='unavailable');count=len(calls)
        self.now[0]+=100
        for _ in range(10):c.tick()
        self.assertEqual(len(calls),count)

    def test_real_http_aggregates_without_credentials_and_requires_private_auth(self):
        c=self.collector();self.settle(c)
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def send(self,status,kind,raw):
                self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def do_GET(self):self.send(200,'text/plain',b'original')
        namespace={'Handler':Handler,'SOURCES_FILE':self.sources,'DATA':self.root/'controller',
                   'ALLOWED_PROVIDER_CLIENTS':{'127.0.0.1'},'dashboard':lambda:b'<main></main>'}
        usage.install(namespace,c)
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
        url='http://127.0.0.1:'+str(server.server_port)
        try:
            with urllib.request.urlopen(url+'/api/subscription-usage') as response:data=json.load(response)
            self.assertEqual(len(data['providers']),2)
            raw=json.dumps(data);self.assertNotIn('synthetic',raw);self.assertNotIn('identity',raw);self.assertNotIn(c.token,raw)
            with self.assertRaises(urllib.error.HTTPError) as error:urllib.request.urlopen(url+'/subscription-info')
            self.assertEqual(error.exception.code,403)
            with urllib.request.urlopen(urllib.request.Request(url+'/subscription-info',headers={'Authorization':'Bearer '+c.token})) as response:
                self.assertEqual(len(json.load(response)['providers']),2)
            self.write([source('one'),source('two'),source('three')]);self.settle(c)
            with urllib.request.urlopen(url+'/api/subscription-usage') as response:self.assertEqual(len(json.load(response)['providers']),3)
        finally:server.shutdown();server.server_close()

    def test_fetcher_keeps_tokens_out_of_argv_and_classifies_429(self):
        calls=[]
        def run(args,**kwargs):
            calls.append((args,kwargs));return type('Result',(),{'returncode':0,'stdout':'HTTP/2 429\r\nRetry-After: 1200\r\n\n__JYDN_HTTP__=429'})()
        with patch.object(usage.subprocess,'run',side_effect=run):
            result=usage.Fetcher('http://proxy.example','synthetic:password')('https://origin.example/?token=synthetic')
        self.assertEqual(result,{'error':'http_429','retry_after':1200});self.assertEqual(len(calls),1)
        self.assertNotIn('synthetic',repr(calls[0][0]));self.assertIn('synthetic',calls[0][1]['input'])


if __name__=='__main__':unittest.main()
