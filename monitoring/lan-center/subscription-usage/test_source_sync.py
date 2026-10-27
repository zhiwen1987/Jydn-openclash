import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import source_sync as sync


def row(sid,url,owner=sync.OWNER,**extra):return dict(id=sid,name=sid,url=url,owner=owner,**extra)
def registry(rows):return {'schema':1,'purpose':'subscription_information_only','sources':rows}
def exported(urls,**extra):return dict(schema=1,state='ok',source_name='转换',enabled=True,addresses=urls,address_count=len(urls),**extra)


class SyncTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)/'subscription-usage';self.root.mkdir()
  self.file=self.root/'information-sources.json';self.write(registry([row('existing','https://example.com/a')]))
 def write(self,d):self.file.write_text(json.dumps(d),encoding='utf-8')
 def read(self):return json.loads(self.file.read_text())
 def test_add_delete_reorder_preserves_existing_id_and_display_name(self):
  self.write(registry([row('existing','https://example.com/a',display_name='人工别名')]))
  sync.import_once(self.root,exported(['https://example.com/a','https://example.com/b']),now=100)
  first=self.read();self.assertEqual(first['sources'][0]['id'],'existing');self.assertEqual(first['sources'][0]['display_name'],'人工别名')
  b=first['sources'][1]['id'];sync.import_once(self.root,exported(['https://example.com/b','https://example.com/a']),now=101)
  self.assertEqual([x['id'] for x in self.read()['sources']],[b,'existing'])
  sync.import_once(self.root,exported(['https://example.com/b']),now=102);self.assertEqual([x['id'] for x in self.read()['sources']],[b])
 def test_manual_entries_survive_clear_and_matching_url_not_duplicated(self):
  self.write(registry([row('manual','https://example.com/m',owner='manual'),row('existing','https://example.com/a')]))
  sync.import_once(self.root,exported(['https://example.com/m','https://example.com/a']))
  self.assertEqual(len(self.read()['sources']),2)
  sync.import_once(self.root,exported([]));self.assertEqual([x['id'] for x in self.read()['sources']],['manual'])
 def test_disabled_source_clears_only_managed(self):
  d=exported(['https://example.com/a']);d['enabled']=False;sync.import_once(self.root,d);self.assertEqual(self.read()['sources'],[])
 def test_exporter_empty_lua_object_requires_explicit_zero_count(self):
  d=exported([]);d['addresses']={};sync.import_once(self.root,d);self.assertEqual(self.read()['sources'],[])
  d.pop('address_count')
  with self.assertRaises(sync.SyncError):sync.parse_export(d)
 def test_invalid_missing_or_ambiguous_export_never_deletes_registry(self):
  before=self.file.read_bytes()
  for d in [{'schema':1,'source_name':'转换','state':'error'},exported(['file:///secret']),{}]:
   with self.assertRaises((sync.SyncError,ValueError)):sync.import_once(self.root,d)
   self.assertEqual(self.file.read_bytes(),before)
 def test_duplicate_and_fragment_labels_share_identity(self):
  sync.import_once(self.root,exported(['https://example.com/a#name=one','https://example.com/a#name=two']))
  self.assertEqual([r['id'] for r in self.read()['sources']],['existing'])
 def test_address_change_gets_new_identity(self):
  sync.import_once(self.root,exported(['https://example.com/a?account=new']))
  self.assertNotEqual(self.read()['sources'][0]['id'],'existing')
 def test_128_and_over_limit_are_bounded_without_truncation(self):
  urls=['https://example.com/'+str(i) for i in range(128)];sync.import_once(self.root,exported(urls));self.assertEqual(len(self.read()['sources']),128)
  before=self.file.read_bytes()
  with self.assertRaises(sync.SyncError):sync.import_once(self.root,exported(urls+['https://example.com/extra']))
  self.assertEqual(before,self.file.read_bytes())
 def test_unchanged_snapshot_does_not_rewrite_inventory(self):
  sync.import_once(self.root,exported(['https://example.com/a']),now=100);stamp=self.file.stat().st_mtime_ns
  result=sync.import_once(self.root,exported(['https://example.com/a']),now=101)
  self.assertFalse(result['changed']);self.assertEqual(self.file.stat().st_mtime_ns,stamp)
 def test_bad_local_manual_edits_are_not_overwritten(self):
  self.file.write_text('{bad')
  with self.assertRaises(ValueError):sync.import_once(self.root,exported([]))
  self.assertEqual(self.file.read_text(),'{bad')
 def test_valid_manual_edit_updates_last_good_even_without_managed_change(self):
  sync.import_once(self.root,exported(['https://example.com/a']))
  d=self.read();d['sources'].append(row('manual','https://example.com/manual',owner='manual'));self.write(d)
  sync.import_once(self.root,exported(['https://example.com/a']))
  self.assertEqual(json.loads((self.root/'information-sources.good.json').read_text()),self.read())
 def test_node_publisher_output_path_is_rejected(self):
  for path in [self.root.parent/'subscription-sources.json',self.root.parent/'publish']:
   with self.assertRaises(sync.SyncError):sync.target_directory(path)
 def test_ssh_failure_preserves_registry_and_private_values_not_logged(self):
  before=self.file.read_bytes();config={'directory':str(self.root),'key':'/private/key','known_hosts':'/private/hosts','target':'root@127.0.0.1'}
  with patch.object(sync.subprocess,'run',return_value=type('Result',(),{'returncode':1})()):r=sync.run(config)
  self.assertEqual(r['state'],'error');self.assertEqual(self.file.read_bytes(),before)
  self.assertNotIn('https://',json.dumps(json.loads((self.root/'sync-state.json').read_text())))


if __name__=='__main__':unittest.main()
