"""Private interactive rollout; credentials and router YAML never leave their host."""
import getpass,json,shlex,sys,datetime,base64,importlib.util
from pathlib import Path
import paramiko
ROOT=Path(__file__).resolve().parents[1]
CASE=ROOT/'reports/shared-custom-all-nodes-20261026'
def connection(host,user,password,sock=None):
 c=paramiko.SSHClient();c.load_system_host_keys();c.set_missing_host_key_policy(paramiko.RejectPolicy())
 c.connect(host,username=user,password=password,sock=sock,timeout=12,allow_agent=False,look_for_keys=False);return c
def main():
 sys.stdout.reconfigure(encoding='utf-8');CASE.mkdir(parents=True,exist_ok=True)
 sp=getpass.getpass('249 SSH password (not saved): ');rp=getpass.getpass('254 SSH password (not saved): ')
 s=connection('10.88.0.249','zhiwen',sp);sp=None
 channel=s.get_transport().open_channel('direct-tcpip',('10.88.0.254',22),('127.0.0.1',0),timeout=12)
 r=connection('10.88.0.254','root',rp,sock=channel);rp=None
 try:
  while True:
   phase=input('Shared phase (preflight/backup/stage/lab/observe/activate_router/accept/verify_hooks/rollback/exit): ').strip()
   if phase=='exit':break
   if not phase.replace('_','').isalpha():continue
   owner=None
   try:
    results={}
    hosts=[('router',r),('server',s)]
    if phase in ['lab','stage_server']:hosts=[('server',s)]
    if phase=='activate_router':hosts=[('router',r)]
    for name,c in hosts:
     source=(ROOT/'scripts/strict_custom_guest.py').read_text(encoding='utf-8')
     args={'phase':'stage' if phase=='stage_server' else phase,'host':name}
     loc=CASE/'location.json'
     if loc.exists():args.update(json.loads(loc.read_text(encoding='utf-8')))
     bundle={}
     if phase in ['stage','stage_server']:
      paths=['scripts/strict_custom.rb','scripts/test_strict_custom.rb','scripts/strict_bind.rb','scripts/jydn_strict_custom_hook.sh','modules/strict-custom-policy.json','modules/strict-custom-private.example.yaml','scripts/strict_fixture_configs.rb','scripts/strict_custom_router_recovery.rb'] if name=='router' else [str(p.relative_to(ROOT)).replace('\\','/') for p in (ROOT/'monitoring/lan-center/strict-custom').rglob('*') if p.is_file() and '__pycache__' not in p.parts]
      for relative in paths:
       path=ROOT/relative;key=path.name if name=='router' else path.relative_to(ROOT/'monitoring/lan-center/strict-custom').as_posix()
       bundle[key]=base64.b64encode(path.read_bytes()).decode()
     payload='ARGS='+repr(args)+'\nBUNDLE='+repr(bundle)+'\nTRUSTED_SOURCE='+repr(source.encode())+'\nexec(compile(TRUSTED_SOURCE,"strict_custom_guest.py","exec"))\n'
     cmd='ruby -e '+shlex.quote('exec "python3", "-"') if False else 'python3 -'
     if name=='router':
      # OpenWrt has Ruby; all router phases use the Ruby guest, not Python.
      ruby=(ROOT/'scripts/strict_custom_router_guest.rb').read_text(encoding='utf-8')
      payload='require "yaml"\nARGS=YAML.load('+json.dumps(json.dumps(args),ensure_ascii=False)+')\nBUNDLE=YAML.load('+json.dumps(json.dumps(bundle),ensure_ascii=False)+')\n'+ruby
      cmd='ruby -'
     else:cmd='sudo -n python3 -'
     owner=None
     if name=='router' and phase in ['activate_router','rollback']:
      lock_code='import fcntl,sys; f=open("/root/dpanel/compose/lan-center/data/failover/routing-owner.lock","a"); fcntl.flock(f,fcntl.LOCK_EX); print("ready",flush=True); sys.stdin.read()'
      owner=s.exec_command('sudo -n python3 -u -c '+shlex.quote(lock_code),timeout=120)
      if owner[1].readline().strip()!='ready':raise RuntimeError('Routing writer lock unavailable')
     inp,out,err=c.exec_command(cmd,timeout=1200);inp.write(payload);inp.channel.shutdown_write()
     value=None
     if name=='router':
      raw=out.read()
      parser="import sys,yaml,json;print(json.dumps(yaml.safe_load(sys.stdin.buffer.read()),ensure_ascii=False))"
      pin,pout,perr=s.exec_command('sudo -n docker exec -i clash-center python3 -B -c '+shlex.quote(parser),timeout=30)
      pin.write(raw);pin.channel.shutdown_write();parsed=pout.read();perr.read()
      if pout.channel.recv_exit_status():raise RuntimeError('Router receipt conversion failed')
      value=json.loads(parsed)
     else:
      while line:=out.readline():
       item=json.loads(line)
       if item.get('_progress'):print(json.dumps(item,ensure_ascii=False),flush=True)
       else:value=item
     error=err.read();status=out.channel.recv_exit_status()
     if owner is not None:owner[0].channel.shutdown_write();owner[1].read();owner[2].read();owner=None
     if status:raise RuntimeError(name+' phase failed '+str(status)+' '+error.decode('utf-8','replace')[-600:])
     results[name]=value
    if phase=='stage':
     meta=json.loads((CASE/'location.json').read_text(encoding='utf-8'))
     with r.open_sftp() as rsf:
      for filename in ['empty.yaml','configured.yaml','locked.yaml','locked-empty.yaml','fixture.yaml','all-nodes.yaml','provider-one.yaml','provider-two.yaml']:
       raw=rsf.open(meta['router']+'/stage/fixtures/'+filename,'rb').read()
       command='sudo -n sh -c '+shlex.quote('umask 077; cat > '+shlex.quote(meta['server']+'/stage/'+filename))
       pin,pout,perr=s.exec_command(command,timeout=30);pin.write(raw);pin.channel.shutdown_write();pout.read();perr.read()
       if pout.channel.recv_exit_status():raise RuntimeError('Fixture transfer failed')
      pin,pout,perr=s.exec_command('sudo -n sh -c '+shlex.quote('umask 077; cat > '+shlex.quote(meta['server']+'/stage/core')),timeout=60)
      with rsf.open('/etc/openclash/core/clash_meta','rb') as source_core:
       while chunk:=source_core.read(65536):pin.write(chunk)
      pin.channel.shutdown_write();pout.read();perr.read()
      if pout.channel.recv_exit_status():raise RuntimeError('Kernel transfer failed')
    (CASE/(phase+'.json')).write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
    if phase=='backup':(CASE/'location.json').write_text(json.dumps({k:results[k]['backup'] for k in results}),encoding='utf-8')
    print(json.dumps(results,ensure_ascii=False),flush=True)
   except Exception as e:
    if owner is not None:owner[0].channel.close()
    print(json.dumps({'phase_failed':phase,'detail':str(e)[:700]},ensure_ascii=False),flush=True)
 finally:r.close();s.close();sp=None;rp=None
if __name__=='__main__':main()
