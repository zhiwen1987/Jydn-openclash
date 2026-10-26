import unittest,json,tempfile,copy,hashlib,tarfile,io,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from stack.model import profile,Failure,verify_bundle,digest,canonical
class SafetyTests(unittest.TestCase):
 def valid(self):
  return {'schema':1,'site':'lab','mode':'fresh','server':{'host':'192.0.2.10','user':'root','fingerprint':'SHA256:'+'A'*43},'router':{'host':'192.0.2.11','user':'root','fingerprint':'SHA256:'+'B'*43,'mac':'02:00:00:00:00:01'},'ports':{'kuma':3101,'capability':3102,'subscription':3103,'dns':53,'api':9090,'proxy':7893,'probe':17895,'router_dns':7874},'dns':{'publish':False,'upstreams':['192.0.2.11:7874'],'allowed_cidrs':['192.0.2.0/24']}}
 def test_explicit_target_and_trust_required(self):
  for role in ('server','router'):
   for key in ('host','fingerprint'):
    p=self.valid();p[role].pop(key)
    with self.assertRaises((Failure,ValueError)):profile(p)
  p=self.valid();p['router'].pop('mac')
  with self.assertRaises(Failure):profile(p)
 def test_unknown_fields_and_injected_names_rejected(self):
  for key,val in [('site','lab;reboot'),('mode','overwrite'),('hidden_password','test')]:
   p=self.valid();p[key]=val
   with self.assertRaises(Failure):profile(p)
 def test_port_collisions_blocked(self):
  for left,right in [('capability','kuma'),('probe','api'),('router_dns','proxy')]:
   p=self.valid();p['ports'][left]=p['ports'][right]
   with self.assertRaises(Failure):profile(p)
  p=self.valid();p['dns']['publish']=True;p['ports']['dns']=3101
  with self.assertRaises(Failure):profile(p)
 def test_tampered_or_traversal_payload_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);p=root/'agent.py';p.write_bytes(b'first')
   for name in ('payload.tar.gz','clash-center.tar.gz','payload/router/core'):
    path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture')
   files={str(f.relative_to(root)).replace('\\','/'):digest(f) for f in root.rglob('*') if f.is_file()}
   m={'schema':1,'version':'0.1.0','platform':'linux/amd64','image_id':'sha256:'+'a'*64,'core_sha256':files['payload/router/core'],'payload_sha256':files['payload.tar.gz'],'image_archive_sha256':files['clash-center.tar.gz'],'payload_files':{'payload/router/core':files['payload/router/core']},'router_files':['core'],'files':files}
   (root/'manifest.json').write_text(json.dumps(m));verify_bundle(root)
   p.write_bytes(b'changed')
   with self.assertRaises(Failure):verify_bundle(root)
   p.write_bytes(b'first')
   m['files']['../agent.py']='a'*64;(root/'manifest.json').write_text(json.dumps(m))
   with self.assertRaises(Failure):verify_bundle(root)
   m['files'].pop('../agent.py');m['payload_sha256']='../../outside'
   (root/'manifest.json').write_text(json.dumps(m))
   with self.assertRaises(Failure):verify_bundle(root)
 def test_manifest_has_no_credential_fields_in_profile(self):
  p=self.valid();self.assertEqual(profile(p),p)
  self.assertNotIn('password',canonical(p).decode())
 def test_dns_acceptance_name_is_bounded(self):
  for name in ('www.baidu.com','example.com.','a'*63+'.test'):
   p=self.valid();p['dns']['test_name']=name;profile(p)
  for name in ('','a'*64+'.test','a..test','-bad.test','https://example.com',123):
   p=self.valid();p['dns']['test_name']=name
   with self.assertRaises(Failure):profile(p)
if __name__=='__main__':unittest.main()
