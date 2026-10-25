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
 result={'compose_only_image_changed':True,'environment_unchanged':True,'quality_policy_unchanged':True,'autonomy_timer':run(['systemctl','is-active','lan-center-autonomy.timer']).strip(),'grok_timer':run(['systemctl','is-active','lan-center-grok-failover.timer']).strip()}
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
 b=Path('/var/backups')/('strict-custom-20261026-'+str(time.time_ns()));b.mkdir(mode=0o700)
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
 b=Path(ARGS['server']);assert b.parent==Path('/var/backups') and b.name.startswith('strict-custom-20261026-')
 stage=b/'stage';stage.mkdir(mode=0o700,exist_ok=True)
 for name,encoded in BUNDLE.items():
  rel=Path(name);assert not rel.is_absolute() and '..' not in rel.parts
  target=stage/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(base64.b64decode(encoded));os.chmod(target,0o600)
 original=b/'route_quality.py';run(['python3',str(stage/'patch_quality.py'),str(original),str(stage/'route_quality.py')])
 (stage/'.dockerignore').write_text('*\n!Dockerfile\n!route_quality.py\n!strict_custom_guard.py\n!strict_select.py\n')
 image=json.loads(run(['docker','inspect','clash-center']))[0]
 m=json.loads((b/'manifest.json').read_text());previous=next(x for x in m['containers'] if x['name']=='clash-center');assert image['Image']==previous['image']
 m.update(previous_tag=image['Config']['Image'],candidate_tag='lan-center-unified:20261026-strict-r1');save(b/'manifest.json',m)
 args=['docker','run','--rm','--network','none','--memory','256m','--cpus','.5','-v',str(stage)+':/strict:ro','--entrypoint','python3',image['Config']['Image'],'-B','/strict/test_strict_control.py']
 p=subprocess.run(args,capture_output=True,timeout=60);(stage/'control-tests.log').write_bytes(p.stdout+p.stderr);assert p.returncode==0,'Control regression tests failed'
 result={'staged':True,'control_tests_passed':True,'candidate_image':m['candidate_tag'],'base_image':image['Image'],'private_inputs_not_in_build_context':True}
elif ARGS['phase']=='build':
 b=Path(ARGS['server']);stage=b/'stage';m=json.loads((b/'manifest.json').read_text())
 previous=next(x for x in m['containers'] if x['name']=='clash-center')
 assert json.loads(run(['docker','image','inspect',m['previous_tag']]))[0]['Id']==previous['image']
 log=stage/'build.log'
 with log.open('wb') as stream:
  p=subprocess.Popen(['nice','-n','15','docker','build','--pull=false','--build-arg','BASE_IMAGE='+m['previous_tag'],'-t',m['candidate_tag'],str(stage)],stdout=stream,stderr=subprocess.STDOUT)
  start=time.time()
  while p.poll() is None:
   if time.time()-start>180:p.terminate();raise RuntimeError('Build budget exceeded')
   print(json.dumps({'_progress':'strict_image_build','seconds':int(time.time()-start)}),flush=True);time.sleep(5)
  assert p.returncode==0,'Candidate image build failed'
 image=json.loads(run(['docker','image','inspect',m['candidate_tag']]))[0]
 result={'built':True,'image':m['candidate_tag'],'image_id':image['Id'],'base_image_id':previous['image'],
  'route_quality_sha256':hashlib.sha256((stage/'route_quality.py').read_bytes()).hexdigest()}
 save(b/'build.json',result)
elif ARGS['phase']=='lab':
 b=Path(ARGS['server']);stage=b/'stage';m=json.loads((b/'manifest.json').read_text());os.chmod(stage/'core',0o700)
 args=['docker','run','--rm','--network','none','--memory','384m','--cpus','.75','--pids-limit','128','-v',str(stage)+':/strict:ro','--entrypoint','python3',m['candidate_tag'],'-B','/strict/test_native_kernel.py']
 p=subprocess.run(args,capture_output=True,timeout=240);(stage/'native-tests.log').write_bytes(p.stdout+p.stderr)
 if p.returncode:raise RuntimeError('Native isolation test failed; inspect private native-tests.log')
 result=json.loads(p.stdout.decode().splitlines()[-1]);save(b/'lab.json',result)
elif ARGS['phase']=='activate_server':
 import fcntl,importlib.util
 b=Path(ARGS['server']);stage=b/'stage';m=json.loads((b/'manifest.json').read_text());assert json.loads((b/'lab.json').read_text())['passed']
 build=json.loads((b/'build.json').read_text());assert json.loads(run(['docker','image','inspect',m['candidate_tag']]))[0]['Id']==build['image_id']
 assert hashlib.sha256((b/'route_quality.py').read_bytes()).hexdigest()==hashlib.sha256((stage/'tests/fixtures/route_quality.py').read_bytes()).hexdigest(),'Compatibility fixture differs from deployed baseline; no activation performed'
 assert hashlib.sha256((P/'docker-compose.yml').read_bytes()).hexdigest()==m['files']['docker-compose.yml'],'Compose changed during preparation'
 spec=importlib.util.spec_from_file_location('strict_recovery',stage/'server_recovery.py');recovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(recovery)
 fd=os.open('/var/lock/jydn-strict-rollout.lock',os.O_CREAT|os.O_RDWR,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 rows=json.loads(run(['docker','inspect']+run(['docker','ps','-aq']).split()))
 a={'started_at':time.time(),'freeze_preexisted':(D/'automation-freeze').exists(),'timer_active':run(['systemctl','is-active','lan-center-autonomy.timer']).strip()=='active',
  'before':[{'name':v['Name'].lstrip('/'),'id':v['Id'],'started':v['State']['StartedAt'],'running':v['State']['Running'],'restarts':v['RestartCount']} for v in rows]}
 compose=json.loads((P/'docker-compose.yml').read_text());compose['services']['center']['image']=m['candidate_tag'];raw=json.dumps(compose,ensure_ascii=False,indent=2).encode();a['compose_sha256']=hashlib.sha256(raw).hexdigest()
 unit='jydn-strict-guard-'+str(time.time_ns());a['unit']=unit;save(b/'activated_server.json',a)
 service=Path('/etc/systemd/system')/(unit+'.service');timer=service.with_suffix('.timer')
 service.write_text('[Unit]\nDescription=Strict rollout independent recovery\nAfter=docker.service\n\n[Service]\nType=oneshot\nUMask=0077\nTimeoutStartSec=180\nExecStart=/usr/bin/python3 '+str(stage/'server_recovery.py')+' guard '+str(b)+'\n')
 timer.write_text('[Unit]\nDescription=Strict rollout health guard\n\n[Timer]\nOnActiveSec=10s\nOnBootSec=30s\nOnUnitActiveSec=10s\nUnit='+unit+'.service\n\n[Install]\nWantedBy=timers.target\n')
 run(['systemctl','daemon-reload']);run(['systemctl','enable','--now',unit+'.timer'])
 owner=None
 try:
  if not a['freeze_preexisted']:(D/'automation-freeze').touch(mode=0o600)
  owner=os.open(D/'routing-owner.lock',os.O_CREAT|os.O_RDWR,0o600);deadline=time.time()+100
  while True:
   try:fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB);break
   except BlockingIOError:
    if time.time()>deadline:raise RuntimeError('Routing writer did not drain')
    time.sleep(2)
  run(['systemctl','stop','lan-center-autonomy.timer']);deadline=time.time()+60
  while run(['systemctl','show','lan-center-autonomy.service','-p','ActiveState','--value']).strip()=='activating':
   if time.time()>deadline:raise RuntimeError('Sensor did not drain')
   time.sleep(2)
  tmp=P/'docker-compose.yml.strict-tmp';tmp.write_bytes(raw);os.chmod(tmp,0o600);os.replace(tmp,P/'docker-compose.yml')
  run(['docker','compose','--project-directory',str(P),'config','--quiet'])
  print(json.dumps({'_progress':'strict_center_recreate_starting'}),flush=True)
  run(['docker','compose','--project-directory',str(P),'up','-d','--no-deps','--no-build','--pull','never','center'],120)
  deadline=time.time()+80
  while True:
   try:health=recovery.health();break
   except Exception:
    if time.time()>deadline:raise
    time.sleep(2)
  result={'server_activated':True,'image':m['candidate_tag'],'health':health,'rollback_guard_armed':True,'routing_automation_frozen_until_acceptance':True}
  save(b/'server-activated-receipt.json',result)
 except BaseException:
  recovery.restore(b);raise
 finally:
  if owner is not None:os.close(owner)
  os.close(fd)
elif ARGS['phase']=='accept':
 import importlib.util
 b=Path(ARGS['server']);stage=b/'stage';m=json.loads((b/'manifest.json').read_text());a=json.loads((b/'activated_server.json').read_text())
 spec=importlib.util.spec_from_file_location('strict_recovery',stage/'server_recovery.py');recovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(recovery);health=recovery.health()
 rows=json.loads(run(['docker','inspect']+run(['docker','ps','-aq']).split()));current={v['Name'].lstrip('/'):v for v in rows}
 for old in a['before']:
  if old['name']=='clash-center':continue
  v=current[old['name']];assert old['id']==v['Id'] and old['started']==v['State']['StartedAt'] and old['running']==v['State']['Running'] and old['restarts']==v['RestartCount'],'Unrelated container changed'
 assert current['clash-center']['Image']==json.loads((b/'build.json').read_text())['image_id']
 assert hashlib.sha256((b/'route_quality.py').read_bytes()).hexdigest()==hashlib.sha256((stage/'tests/fixtures/route_quality.py').read_bytes()).hexdigest(),'Compatibility fixture differs from deployed baseline'
 for name in ['strict_custom_guard.py','strict_select.py','route_quality.py']:
  assert hashlib.sha256(run(['docker','exec','clash-center','cat','/'+name]).encode()).hexdigest()==hashlib.sha256((stage/name).read_bytes()).hexdigest(),'Image source drift'
 if not a['freeze_preexisted']:(D/'automation-freeze').unlink(missing_ok=True)
 if a['timer_active']:run(['systemctl','start','lan-center-autonomy.timer'])
 (b/'SERVER_ACCEPTED').touch(mode=0o600);run(['systemctl','disable','--now',a['unit']+'.timer'])
 result={'accepted':True,'health':health,'other_containers_unchanged':True,'image_matches_build':True,'compatibility_fixture_matches_previous_deployed_source':True,'rollback_guard_disarmed':True}
 save(b/'server-acceptance.json',result)
elif ARGS['phase']=='rollback':
 import importlib.util
 b=Path(ARGS['server']);spec=importlib.util.spec_from_file_location('strict_recovery',b/'stage/server_recovery.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);result=mod.restore(b)
else:raise ValueError('Unknown phase')
print(json.dumps(result,ensure_ascii=False))
