"""Host-only bounded recovery; never inside the container being replaced."""
import fcntl,hashlib,json,os,socket,struct,subprocess,sys,time,urllib.request
from pathlib import Path
P=Path('/root/dpanel/compose/lan-center');D=P/'data/failover'
def run(args,timeout=35):
 p=subprocess.run(args,capture_output=True,timeout=timeout)
 if p.returncode:raise RuntimeError('Recovery operation failed: '+args[0])
 return p.stdout.decode()
def save(p,v):p.write_text(json.dumps(v,ensure_ascii=False,indent=2));os.chmod(p,0o600)
def health():
 op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 for port in [3101,3102,3103]:
  with op.open('http://10.88.0.249:'+str(port)+'/',timeout=3) as r:assert r.status==200
 q=b'\x7a\x11'+struct.pack('!5H',0x100,1,0,0,0)+b'\x03www\x05baidu\x03com\x00'+struct.pack('!2H',1,1)
 for tcp in [False,True]:
  with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
   s.settimeout(3)
   if tcp:
    s.connect(('10.88.0.249',53));s.sendall(struct.pack('!H',len(q))+q);head=s.recv(2);size=struct.unpack('!H',head)[0];data=b''
    while len(data)<size:
     chunk=s.recv(size-len(data))
     if not chunk:break
     data+=chunk
   else:s.sendto(q,('10.88.0.249',53));data=s.recv(4096)
  assert len(data)>=12 and data[:2]==q[:2] and struct.unpack('!6H',data[:12])[3]>0
 return {'http_ports':[3101,3102,3103],'dns_udp':True,'dns_tcp':True}
def restore(b):
 m=json.loads((b/'manifest.json').read_text());a=json.loads((b/'activated_server.json').read_text())
 current=hashlib.sha256((P/'docker-compose.yml').read_bytes()).hexdigest()
 assert current in [m['files']['docker-compose.yml'],a['compose_sha256']],'Concurrent Compose edit; refusing overwrite'
 previous=next(v for v in m['containers'] if v['name']=='clash-center')
 assert json.loads(run(['docker','image','inspect',m['previous_tag']]))[0]['Id']==previous['image']
 raw=(b/'docker-compose.yml').read_bytes();assert hashlib.sha256(raw).hexdigest()==m['files']['docker-compose.yml']
 tmp=P/'docker-compose.yml.strict-restore';tmp.write_bytes(raw);os.chmod(tmp,0o600);os.replace(tmp,P/'docker-compose.yml')
 run(['docker','compose','--project-directory',str(P),'up','-d','--no-deps','--no-build','--pull','never','center'],120)
 deadline=time.time()+80
 while True:
  try:result=health();break
  except Exception:
   if time.time()>deadline:raise
   time.sleep(2)
 if not a['freeze_preexisted']:(D/'automation-freeze').unlink(missing_ok=True)
 if a['timer_active']:run(['systemctl','start','lan-center-autonomy.timer'])
 if a.get('unit'):run(['systemctl','disable','--now',a['unit']+'.timer'])
 result.update(rollback_completed=True,restored_image=m['previous_tag'],live_databases_preserved=True)
 save(b/'server-rollback.json',result);return result
def main():
 action=sys.argv[1];b=Path(sys.argv[2]);assert b.parent==Path('/var/backups') and b.name.startswith('strict-custom-20261026-') and b.stat().st_uid==0
 with open('/var/lock/jydn-strict-rollout.lock','a') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return
  if action=='rollback':print(json.dumps(restore(b)));return
  if (b/'SERVER_ACCEPTED').exists():return
  a=json.loads((b/'activated_server.json').read_text());age=time.time()-a['started_at']
  try:health();failed=False
  except Exception:failed=True
  state=json.loads((b/'server-guard.json').read_text()) if (b/'server-guard.json').exists() else {'failures':0}
  state.update(failures=state['failures']+1 if failed else 0,epoch=time.time());save(b/'server-guard.json',state)
  if age>600 or age>30 and state['failures']>=3:restore(b)
if __name__=='__main__':main()
