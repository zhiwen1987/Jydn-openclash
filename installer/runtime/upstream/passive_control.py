"""Network-isolated rehearsal entry. Production deployment must not enable this."""
import os,signal,subprocess,time
from autonomy_store import atomic_json
from pathlib import Path

def main():
 assert os.getenv('LAN_CENTER_PASSIVE')=='1','Rehearsal mode must be explicit'
 procs=[];stop=False
 def halt(_sig,_frame):
  nonlocal stop
  stop=True
 signal.signal(signal.SIGTERM,halt);signal.signal(signal.SIGINT,halt)
 try:
  for args in [['python3','-B','/fixture_dns.py'],['python3','-B','/node-capability.py','--serve-only'],['python3','-B','/subscription-controller.py','--serve-only'],['python3','-B','/probe_http.py']]:
   procs.append(subprocess.Popen(args))
  while not stop:
   if any(p.poll() is not None for p in procs):raise RuntimeError('passive_child_exited')
   atomic_json(Path('/data/health'),{'epoch':int(time.time()),'status':'ok','detail':'isolated_rehearsal_no_automation'})
   time.sleep(2)
 finally:
  for p in procs:
   if p.poll() is None:p.terminate()
  for p in procs:
   try:p.wait(timeout=10)
   except subprocess.TimeoutExpired:p.kill();p.wait()

if __name__=='__main__':main()
