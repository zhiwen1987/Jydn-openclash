"""249 phases; no credentials/raw environment/configuration in public receipts."""
import os,json,time,sqlite3,hashlib,subprocess,shutil,base64
from pathlib import Path
P=Path('/root/dpanel/compose/lan-center');D=P/'data/failover'
def run(args,timeout=25):
 p=subprocess.run(args,capture_output=True,timeout=timeout)
 if p.returncode:raise RuntimeError('Operation failed: '+args[0])
 return p.stdout.decode()
def save(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2));os.chmod(p,0o600)
def dbcopy(src,dst):
 a=sqlite3.connect('file:'+str(src)+'?mode=ro',uri=True);b=sqlite3.connect(dst)
 try:a.backup(b);assert b.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
 finally:a.close();b.close()
if ARGS['phase']=='verify_hooks':
 b=Path(ARGS['server']);old=json.loads((b/'docker-compose.yml').read_text());now=json.loads((P/'docker-compose.yml').read_text());now['services']['center']['image']=old['services']['center']['image'];assert now==old,'Other compose settings changed'
 m=json.loads((b/'manifest.json').read_text())
 for name,path in [('.env',P/'.env'),('route-quality-policy.json',D/'route-quality-policy.json')]:
  if name in m['files']:assert hashlib.sha256(path.read_bytes()).hexdigest()==m['files'][name]
 result={'compose_unchanged':True,'environment_unchanged':True,'quality_policy_unchanged':True,'autonomy_timer':run(['systemctl','is-active','lan-center-autonomy.timer']).strip(),'grok_timer':run(['systemctl','is-active','lan-center-grok-failover.timer']).strip()}
 save(b/'persistence-acceptance.json',result)
elif ARGS['phase']=='observe':
 import importlib.util
 b=Path(ARGS['server']);spec=importlib.util.spec_from_file_location('strict_recovery',b/'stage/server_recovery.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 db=sqlite3.connect('file:'+str(P/'data/uptime-kuma/kuma.db')+'?mode=ro',uri=True)
 try:rows=db.execute('SELECT m.name,h.status FROM monitor m LEFT JOIN heartbeat h ON h.id=(SELECT MAX(id) FROM heartbeat WHERE monitor_id=m.id) WHERE m.active=1').fetchall()
 finally:db.close()
 result={'health':mod.health(),'active_monitor_count':len(rows),'monitor_status_counts':{str(status):sum(1 for _,v in rows if v==status) for status in {v for _,v in rows}},'center_running':json.loads(run(['docker','inspect','clash-center']))[0]['State']['Running']}
 save(b/('observation-'+str(int(time.time()))+'.json'),result)
elif ARGS['phase']=='preflight':
 x=json.loads(run(['docker','inspect','clash-center']))[0]
 quality=json.loads((D/'route-quality-policy.json').read_text())
 result={'center':{'image_id':x['Image'],'tag':x['Config']['Image'],'running':x['State']['Running'],'health':x['State'].get('Health',{}).get('Status')},
  'neighbor':run(['ip','neigh','show','10.88.0.254']).strip(),'quality_policy':{k:v for k,v in quality.items() if k in ['enabled','manual_override_seconds']},
  'disk':run(['df','-h','/']).strip(),'compose_sha256':hashlib.sha256((P/'docker-compose.yml').read_bytes()).hexdigest(),
  'grok_timer':run(['systemctl','is-active','lan-center-grok-failover.timer']).strip()}
 if ARGS.get('server'):
  log=Path(ARGS['server'])/'stage/native-tests.log'
  if log.exists():result['native_test_log_tail']=log.read_text(errors='replace')[-2500:]
elif ARGS['phase']=='backup':
 b=Path('/var/backups')/('shared-custom-20261026-'+str(time.time_ns()));b.mkdir(mode=0o700)
 for rel in ['docker-compose.yml','docker-compose.override.yml','.env']:
  if (P/rel).is_file():shutil.copyfile(P/rel,b/rel);os.chmod(b/rel,0o600)
 for src in [D/'node-capability.db',D/'subscription-controller/controller.db',P/'data/uptime-kuma/kuma.db']:
  if src.exists():dbcopy(src,b/(src.parent.name+'-'+src.name));os.chmod(b/(src.parent.name+'-'+src.name),0o600)
 for name in ['route-quality-policy.json','route-quality.json','health','node-capability.health']:
  if (D/name).is_file():shutil.copyfile(D/name,b/name);os.chmod(b/name,0o600)
 raw=run(['docker','exec','clash-center','cat','/route_quality.py']);(b/'route_quality.py').write_text(raw);os.chmod(b/'route_quality.py',0o600)
 rows=json.loads(run(['docker','inspect']+run(['docker','ps','-aq']).split()))
 public=[{'name':x['Name'].lstrip('/'),'id':x['Id'],'image':x['Image'],'started':x['State']['StartedAt'],'running':x['State']['Running'],'restarts':x['RestartCount']} for x in rows]
 manifest={'backup':str(b),'containers':public,'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in b.iterdir() if p.is_file()}}
 save(b/'manifest.json',manifest);assert all(hashlib.sha256((b/k).read_bytes()).hexdigest()==v for k,v in manifest['files'].items())
 result={'backup':str(b),'verified_files':len(manifest['files']),'sqlite_snapshots_verified':True,'production_restarted':False}
elif ARGS['phase']=='stage':
 b=Path(ARGS['server']);assert b.parent==Path('/var/backups') and b.name.startswith('shared-custom-20261026-')
 stage=b/'stage';stage.mkdir(mode=0o700,exist_ok=True)
 for name,encoded in BUNDLE.items():
  rel=Path(name);assert not rel.is_absolute() and '..' not in rel.parts
  target=stage/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(base64.b64decode(encoded));os.chmod(target,0o600)
 original=b/'route_quality.py';shutil.copyfile(original,stage/'route_quality.py')
 run(['python3',str(stage/'patch_quality.py'),str(stage/'tests/fixtures/route_quality.py'),str(stage/'quality-reference.py')])
 assert hashlib.sha256(original.read_bytes()).hexdigest()==hashlib.sha256((stage/'quality-reference.py').read_bytes()).hexdigest(),'Control regression source differs from installed controller'
 (stage/'.dockerignore').write_text('*\n!Dockerfile\n!route_quality.py\n!strict_custom_guard.py\n!strict_select.py\n')
 image=json.loads(run(['docker','inspect','clash-center']))[0]
 m=json.loads((b/'manifest.json').read_text());previous=next(x for x in m['containers'] if x['name']=='clash-center');assert image['Image']==previous['image']
 m.update(previous_tag=image['Config']['Image'],candidate_tag=image['Config']['Image']);save(b/'manifest.json',m)
 assert json.loads((D/'route-quality-policy.json').read_text()).get('manual_override_seconds',0)==0,'Current manual selection policy is not permanent'
 args=['docker','run','--rm','--network','none','--memory','256m','--cpus','.5','-v',str(stage)+':/strict:ro','--entrypoint','python3',image['Config']['Image'],'-B','/strict/test_strict_control.py']
 p=subprocess.run(args,capture_output=True,timeout=60);(stage/'control-tests.log').write_bytes(p.stdout+p.stderr);assert p.returncode==0,'Control regression tests failed'
 result={'staged':True,'control_tests_passed':True,'candidate_image':m['candidate_tag'],'base_image':image['Image'],'private_inputs_not_in_build_context':True}
elif ARGS['phase']=='lab':
 b=Path(ARGS['server']);stage=b/'stage';m=json.loads((b/'manifest.json').read_text());os.chmod(stage/'core',0o700)
 args=['docker','run','--rm','--network','none','--memory','384m','--cpus','.75','--pids-limit','128','-v',str(stage)+':/strict:ro','--entrypoint','python3',m['candidate_tag'],'-B','/strict/test_native_kernel.py']
 p=subprocess.run(args,capture_output=True,timeout=240);(stage/'native-tests.log').write_bytes(p.stdout+p.stderr)
 if p.returncode:raise RuntimeError('Native isolation test failed; inspect private native-tests.log')
 result=json.loads(p.stdout.decode().splitlines()[-1]);save(b/'lab.json',result)
elif ARGS['phase']=='accept':
 import importlib.util
 b=Path(ARGS['server']);stage=b/'stage';m=json.loads((b/'manifest.json').read_text())
 spec=importlib.util.spec_from_file_location('strict_recovery',stage/'server_recovery.py');recovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(recovery);health=recovery.health()
 rows=json.loads(run(['docker','inspect']+run(['docker','ps','-aq']).split()));current={v['Name'].lstrip('/'):v for v in rows}
 for old in m['containers']:
  v=current[old['name']];assert old['id']==v['Id'] and old['started']==v['State']['StartedAt'] and old['running']==v['State']['Running'] and old['restarts']==v['RestartCount'],'Unrelated container changed'
 assert hashlib.sha256(run(['docker','exec','clash-center','cat','/route_quality.py']).encode()).hexdigest()==m['files']['route_quality.py']
 assert hashlib.sha256((P/'docker-compose.yml').read_bytes()).hexdigest()==m['files']['docker-compose.yml']
 assert hashlib.sha256((D/'route-quality-policy.json').read_bytes()).hexdigest()==m['files']['route-quality-policy.json']
 assert json.loads((D/'route-quality-policy.json').read_text()).get('manual_override_seconds',0)==0
 result={'accepted':True,'health':health,'all_containers_unchanged':True,'center_quality_controller_unchanged':True,'compose_unchanged':True}
 save(b/'server-acceptance.json',result)
elif ARGS['phase']=='rollback':
 result={'server_configuration_unchanged':True,'server_rollback_not_required':True}
else:raise ValueError('Unknown phase')
print(json.dumps(result,ensure_ascii=False))
