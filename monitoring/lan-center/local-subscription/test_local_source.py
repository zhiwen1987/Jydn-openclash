"""Synthetic-only tests; no production URLs, credentials, mounts or selections."""
import base64
import contextlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from node_links import Invalid, parse
from local_source import Manager, EMPTY, PROVIDER, SELECTOR, PROBE, atomic, native_validator
from patch_runtime import patch_capability, patch_subscription

SS = 'ss://' + base64.urlsafe_b64encode(b'aes-128-gcm:synthetic-password').decode().rstrip('=') + '@127.0.0.1:19831#fixture'
UUID = '4e100fd8-83d0-4a6f-9c6e-6874fd932f01'


class Links(unittest.TestCase):
    def test_supported_protocols_and_native(self):
        vmess = {'v':'2','ps':'vmess fixture','add':'127.0.0.1','port':'19831','id':UUID,'aid':'0','scy':'auto','net':'ws','type':'none','host':'example.invalid','path':'/fixture','tls':'tls','sni':'example.invalid'}
        links = [SS, 'ss://' + base64.b64encode(b'aes-128-gcm:synthetic-password@127.0.0.1:19831').decode() + '#legacy', 'vmess://' + base64.b64encode(json.dumps(vmess).encode()).decode(),
                 'vless://' + UUID + '@127.0.0.1:19831?security=tls&type=ws&sni=example.invalid&path=%2Ffixture#vless',
                 'vless://' + UUID + '@127.0.0.1:19831?security=reality&fp=chrome&pbk=YHw3jNkb0JjO-C4_lkFUs2hL4wYkJ2F9iUkJk9HRn1U&sid=0123456789abcdef&type=tcp#reality',
                 'trojan://synthetic-password@127.0.0.1:19831?sni=example.invalid#trojan',
                 'hy2://synthetic-password@127.0.0.1:19831?sni=example.invalid&obfs=salamander&obfs-password=synthetic-obfs#hy2',
                 'socks5://test:synthetic-password@127.0.0.1:19831#socks', 'http://127.0.0.1:19831#http', 'https://test:synthetic-password@127.0.0.1:19831#https']
        nodes = parse('\n'.join(links))
        self.assertEqual(len(nodes), 10)
        core = os.getenv('TEST_CORE')
        if core:
            native_validator(core, [dict(n, name='fixture-' + str(i)) for i, (_, n) in enumerate(nodes)])
    def test_unsupported_never_silently_dropped(self):
        for link in [SS.replace('#fixture', '?plugin=v2ray-plugin#fixture'), 'vless://' + UUID + '@test.invalid:443?security=reality&fp=chrome&pbk=key&spx=%2F', 'trojan://secret@localhost:443?security=none', 'socks5://localhost:1080?unknown=true', 'tuic://unimplemented@localhost:443', 'http://localhost:80/path', SS.replace(':19831', ':99999')]:
            with self.subTest(link=link.split('://')[0]), self.assertRaises(Invalid):
                parse(link)
    def test_empty_and_size_limits(self):
        self.assertEqual(parse(' \n'), [])
        for data in ['x'*196609, '\n'.join([SS]*101)]:
            with self.assertRaises(Invalid): parse(data)
    def test_no_secret_in_error(self):
        with self.assertRaises(Invalid) as caught: parse('vless://my-secret@test.invalid:443')
        self.assertNotIn('my-secret', str(caught.exception))


class Transactions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'data/subscription-controller/local-source'
        self.loaded = {EMPTY}
        self.selected = 'REJECT'
        self.public_selection = 'public-original'
        self.calls = []
        self.refresh_failure = False
        self.m = Manager(self.root, self.api, lambda _: None)
        self.public_pointer = self.root.parent / 'current.json'
        atomic(self.public_pointer, {'release_id':'airport-unchanged'})
    def tearDown(self): self.tmp.cleanup()
    def api(self, path, method='GET', body=None):
        self.calls.append((path,method))
        if path == '/providers/proxies/' + PROVIDER and method == 'PUT':
            import yaml
            nodes = yaml.safe_load(self.m.provider_payload())['proxies']
            if self.refresh_failure and nodes[0]['name'] != EMPTY: raise RuntimeError('synthetic refresh fail')
            self.loaded = {n['name'] for n in nodes}
            if self.selected not in self.loaded: self.selected = 'REJECT'
            return {}
        if path == '/providers/proxies': return {'providers': {PROVIDER:{'proxies':[{'name':n} for n in self.loaded]}}}
        if path.endswith(__import__('urllib.parse',fromlist=['quote']).quote(SELECTOR,safe='')):
            if method == 'PUT': self.selected=body['name']
            return {'all':['REJECT','public-original'] + sorted(self.loaded-{EMPTY}), 'now':self.selected}
        if path.endswith(__import__('urllib.parse',fromlist=['quote']).quote(PROBE,safe='')): return {'all':['public-original']+sorted(self.loaded-{EMPTY})}
        if path == '/connections': return {'connections':[{'id':'private-flow','chains':[SELECTOR]},{'id':'public-flow','chains':['public-original']}]}
        if method == 'DELETE': return {}
        raise AssertionError(path)
    def update(self, text=SS, mode='merge', **kwargs):
        return self.m.update({'version':self.m.read('state.json')['version'],'text':text,'mode':mode,**kwargs})
    def test_add_dedup_zero_one_independent_public_sources(self):
        r=self.update(SS+'\n'+SS); self.assertEqual(r['count'],1)
        self.assertEqual(self.update()['status'],'unchanged')
        self.assertEqual(json.loads(self.public_pointer.read_text()),{'release_id':'airport-unchanged'})
        self.assertTrue(self.m.status()['router_loaded'])
        self.assertEqual(self.m.status()['nodes'][0]['health'],'queued')
        self.update('', 'replace'); self.assertEqual(self.loaded,{EMPTY})
        self.assertEqual(self.public_selection,'public-original')
    def test_selected_removal_fences_only_own_connections(self):
        self.update(); node=self.m.read('state.json')['nodes'][0]; self.selected=node['name']
        self.update(mode='remove',ids=[node['id']])
        self.assertEqual(self.selected,'REJECT')
        self.assertIn(('/connections/private-flow','DELETE'),self.calls)
        self.assertNotIn(('/connections/public-flow','DELETE'),self.calls)
    def test_optimistic_concurrency_and_native_rejection(self):
        self.update()
        with self.assertRaisesRegex(Invalid,'version_conflict'): self.m.update({'version':0,'text':SS})
        before=self.m.read('state.json')
        self.m.validator=lambda _: (_ for _ in ()).throw(Invalid('native_rejected'))
        with self.assertRaisesRegex(Invalid,'native_rejected'): self.update(SS.replace('fixture','second'),'replace')
        self.assertEqual(self.m.read('state.json'),before)
    def test_publish_failure_preserves_previous(self):
        self.refresh_failure=True
        with self.assertRaisesRegex(Invalid,'publish_failed'): self.update()
        self.assertEqual(self.m.read('state.json')['version'],0)
        self.assertEqual(self.loaded,{EMPTY})
        self.assertFalse((self.root/'pending.json').exists())
    def test_restart_crash_before_and_after_commit(self):
        self.update(); good=self.m.read('state.json')
        bad={'version':good['version']+1,'nodes':[]};self.m.write_release(bad)
        atomic(self.root/'pending.json',{'previous':good['version'],'candidate':bad['version']})
        atomic(self.root/'current.json',{'version':bad['version']})
        restarted=Manager(self.root,self.api,lambda _:None);restarted.recover()
        self.assertEqual(restarted.read('current.json')['version'],good['version'])
        atomic(self.root/'pending.json',{'previous':0,'candidate':good['version']})
        restarted.recover();self.assertEqual(restarted.read('state.json'),good)
    def test_credentials_permissions_and_readonly_response(self):
        self.update(); state=self.m.status()
        self.assertNotIn('synthetic-password',json.dumps(state))
        for p in self.root.rglob('*'):
            self.assertEqual(p.stat().st_mode & 0o077,0,str(p))
    def test_edit_and_freshness(self):
        self.update(); node=self.m.read('state.json')['nodes'][0];self.selected=node['name']
        link='ss://' + base64.urlsafe_b64encode(b'aes-128-gcm:new-synthetic-password').decode().rstrip('=') + '@127.0.0.1:19831#fixture'
        self.update(link,'edit',id=node['id'])
        self.assertEqual(self.selected,'REJECT');self.assertEqual(len(self.m.status()['nodes']),1)


if __name__ == '__main__': unittest.main(verbosity=2)
