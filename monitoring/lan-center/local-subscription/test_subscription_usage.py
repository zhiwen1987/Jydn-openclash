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
        self.assertEqual(usage.parse_userinfo('Subscription-Userinfo: upload=1;download=2;total=100;expire='),{'upload':1,'download':2,'total':100})
        for text in ['upload=1;download=2;total=100;expire=;expire=0',
                     'upload=;download=2;total=100;expire=',
                     'upload=1;download=2;total=100;expire=unknown']:
            with self.assertRaises(usage.UsageError):usage.parse_userinfo('subscription-userinfo: '+text)
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

    def test_names_plain_base64_mime_rfc5987_and_filename(self):
        import base64
        title='测试机场 · A'
        encoded=base64.b64encode(title.encode()).decode().rstrip('=')
        for headers in ['profile-title: '+title,'profile-title: base64:'+encoded,
                        'profile-title: =?UTF-8?B?'+base64.b64encode(title.encode()).decode()+'?=',
                        "content-disposition: attachment; filename*=UTF-8''%E6%B5%8B%E8%AF%95%E6%9C%BA%E5%9C%BA%20%C2%B7%20A.yaml"]:
            self.assertEqual(usage.subscription_name(headers),title)
        self.assertEqual(usage.subscription_name('Content-Disposition: attachment; filename="Airport B.yml"'),'Airport B')

    def test_name_final_response_only_and_title_precedence(self):
        self.assertEqual(usage.subscription_name('HTTP/1.1 302 Found\r\nprofile-title: Old\r\n\r\nHTTP/2 200\r\nContent-Disposition: attachment;filename="New.yml"\r\n'),'New')
        self.assertEqual(usage.subscription_name('profile-title: Explicit Title\r\nContent-Disposition: attachment;filename="Fallback.yml"'),'Explicit Title')

    def test_bad_name_never_breaks_usage_or_echoes_credentials(self):
        for value in ['profile-title: base64:!!!','profile-title: https://private.example/?token=synthetic',
                      'content-disposition: attachment;filename="clash.yaml"',
                      "content-disposition: attachment;filename*=unknown-charset''%FF"]:
            self.assertIsNone(usage.subscription_name(value))
        raw='HTTP/2 200\r\nprofile-title: base64:!!!\r\nsubscription-userinfo: upload=1;download=2;total=100\r\n\n__JYDN_HTTP__=200'
        with patch.object(usage.subprocess,'run',return_value=type('Response',(),{'returncode':0,'stdout':raw})()):
            result=usage.Fetcher()('https://origin.example/')
        self.assertEqual(result['metrics']['total'],100);self.assertIsNone(result['reported_name'])

    def test_generic_labels_use_discovered_names_but_manual_names_win(self):
        self.write([dict(source('one'),name='source-1'),dict(source('two'),display_name='我的专用机场')])
        c=self.collector(lambda _: {'metrics':GOOD,'reported_name':'自动机场'})
        data=self.settle(c)
        self.assertEqual([p['name'] for p in data['providers']],['自动机场','我的专用机场'])
        self.assertEqual([p['name_origin'] for p in data['providers']],['subscription_header','configured'])

    def test_unknown_name_is_explicit_and_not_guessed_from_domain(self):
        self.write([dict(source('one'),name='source-1')]);data=self.settle(self.collector())
        self.assertEqual(data['providers'][0]['name'],'未识别机场 · source-1')
        self.assertEqual(data['providers'][0]['name_origin'],'unidentified')

    def test_name_cached_on_failure_and_restarted_without_extra_fetch(self):
        self.write([dict(source('one'),name='source-1')]);result=[{'metrics':GOOD,'reported_name':'已识别机场'}]
        c=self.collector(lambda _:result[0]);self.settle(c);result[0]={'error':'http_429','retry_after':900};self.now[0]+=61
        d=self.settle(c,lambda d:d['providers'][0]['usage_status']=='cached');self.assertEqual(d['providers'][0]['name'],'已识别机场')
        c.close();self.collectors.remove(c);newer=self.collector(lambda _:self.fail('rate limit must survive restart'))
        newer.tick();self.assertEqual(newer.snapshot()['providers'][0]['name'],'已识别机场')

    def test_new_account_cannot_keep_old_airport_name(self):
        self.write([dict(source('one'),name='source-1')]);c=self.collector(lambda _: {'metrics':GOOD,'reported_name':'旧机场'})
        self.settle(c);self.write([dict(source('one'),name='source-1',url='https://new.example/sub')]);c.tick()
        self.assertNotEqual(c.snapshot()['providers'][0]['name'],'旧机场')

    def test_account_name_works_even_without_usage_header(self):
        self.write([dict(source('one'),name='source-1')]);c=self.collector(lambda _: {'error':'information_header_missing','reported_name':'只有名称的机场'})
        d=self.settle(c,lambda d:d['providers'][0]['usage_status']=='unavailable')
        self.assertEqual(d['providers'][0]['name'],'只有名称的机场');self.assertIsNone(d['providers'][0]['metrics'])

    def test_old_cache_migration_preserves_rate_limit_and_metrics(self):
        c=self.collector();self.settle(c);c.close();self.collectors.remove(c)
        path=self.root/'data/cache.json';cache=json.loads(path.read_text())
        for item in cache['records'].values():item.pop('name_checked',None);item.pop('reported_name',None)
        cache['records']['two'].update(error='http_429',next_due=self.now[0]+900)
        path.write_text(json.dumps(cache));calls=[]
        newer=self.collector(lambda url:calls.append(url) or {'metrics':GOOD,'reported_name':'新识别机场'})
        self.settle(newer,lambda d:len(calls)==1 and newer.records['one'].get('name_checked') is True)
        self.assertEqual(len(calls),1);self.assertTrue('/one?' in calls[0]);self.assertEqual(newer.records['two']['metrics'],GOOD)

    def test_n_sources_and_node_counts_are_independent_of_fixed_positions(self):
        import hashlib
        for n in [0,1,2,3,7,16,64,128,17,0]:
            entries=[dict(source('s'+str(i)),node_count=[0,1,100000][i%3]) for i in range(n)]
            self.write(entries)
            c=self.collector(lambda url:{'metrics':dict(GOOD,download=int(hashlib.sha256(url.encode()).hexdigest()[:4],16))})
            d=self.settle(c);self.assertEqual([p['id'] for p in d['providers']],[e['id'] for e in entries])
            self.assertLessEqual(len(c.pending),2)
            self.write(list(reversed(entries)));c.tick();self.assertEqual([p['id'] for p in c.snapshot()['providers']],[e['id'] for e in reversed(entries)])
            self.write(entries[::2]);d=self.settle(c);self.assertEqual({p['id'] for p in d['providers']},{e['id'] for e in entries[::2]})
            c.close();self.collectors.remove(c)

    def test_new_untried_source_precedes_retries_in_large_inventory(self):
        self.write([source('old'+str(i)) for i in range(10)]+[source('new')])
        event=threading.Event();c=self.collector(lambda _:event.wait(.1) or {'metrics':GOOD});c._registry()
        for sid,r in c.records.items():r['next_due']=900 if sid!='new' else 0
        c.tick();self.assertIn('new',c.pending);self.assertLessEqual(len(c.pending),2);event.set()

    def test_over_limit_registry_preserves_last_valid_inventory(self):
        c=self.collector();self.settle(c);self.write([source('n'+str(i)) for i in range(129)]);c.tick()
        d=c.snapshot();self.assertEqual(d['registry_state'],'error');self.assertEqual({p['id'] for p in d['providers']},{'one','two'})

    def test_information_registry_activation_does_not_modify_publisher_sources(self):
        before=self.sources.read_bytes();c=self.collector();self.settle(c)
        info=c.root/'information-sources.json';info.write_text(json.dumps({'sources':[source('one'),source('two'),source('three')]}))
        d=self.settle(c);self.assertEqual(len(d['providers']),3);self.assertEqual(before,self.sources.read_bytes())
        self.assertEqual(c.sources,info)

    def test_independent_registry_empty_does_not_fall_back_to_node_sources(self):
        c=self.collector();(c.root/'source-mode.json').write_text('{"mode":"luci_info_sync"}')
        info=c.root/'information-sources.json';info.write_text('{"sources":[]}')
        d=self.settle(c);self.assertEqual(d['providers'],[]);self.assertEqual(d['registry_state'],'ok')

    def test_information_registry_corrupt_restart_recovers_last_good(self):
        c=self.collector();good={'sources':[source('three')]};(c.root/'information-sources.json').write_text(json.dumps(good));self.settle(c)
        (c.root/'information-sources.good.json').write_text(json.dumps(good));c.close();self.collectors.remove(c)
        (c.root/'information-sources.json').write_text('{bad')
        newer=self.collector(lambda _:self.fail('fresh cache must survive registry recovery'))
        newer.tick();d=newer.snapshot();self.assertEqual(d['registry_state'],'error');self.assertEqual([r['id'] for r in d['providers']],['three']);self.assertEqual(d['providers'][0]['metrics'],GOOD)

    def test_information_registry_missing_does_not_adopt_node_publishers(self):
        c=self.collector();(c.root/'source-mode.json').write_text('{"mode":"luci_info_sync"}');c.tick();d=c.snapshot()
        self.assertEqual(d['registry_state'],'error');self.assertEqual(d['providers'],[])

    def test_sync_status_is_sanitized_and_stale_timer_visible(self):
        c=self.collector();(c.root/'information-sources.json').write_text('{"sources":[]}')
        (c.root/'sync-state.json').write_text(json.dumps({'schema':1,'state':'ok','source_name':'https://secret.example/?token=private','last_attempt':1000,'last_success':1000,'url':'private'}))
        d=self.settle(c);self.assertEqual(d['source_sync']['state'],'ok');self.assertNotIn('private',json.dumps(d));self.now[0]+=121
        self.assertEqual(c.snapshot()['source_sync']['state'],'stale')


if __name__=='__main__':unittest.main()
