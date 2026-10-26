import base64
import hashlib
import json
import socket
import time
from pathlib import Path

from .model import Failure, require


def fingerprint(key):
    return 'SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def inspect_key(host, port=22, via=None):
    import paramiko
    sock=via.client.get_transport().open_channel('direct-tcpip',(host,port),('127.0.0.1',0),timeout=10) if via else socket.create_connection((host,port),timeout=10)
    transport=paramiko.Transport(sock)
    try:
        transport.start_client(timeout=10)
        return fingerprint(transport.get_remote_server_key())
    finally:
        transport.close()


class SSH:
    def __init__(self, settings, password=None, via=None):
        import paramiko
        pinned=settings['fingerprint']
        class Pinned(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                if fingerprint(key)!=pinned:raise Failure('SSH 主机指纹不一致，已停止')
        self.client=paramiko.SSHClient();self.client.set_missing_host_key_policy(Pinned())
        sock=None
        try:
            if via:sock=via.client.get_transport().open_channel('direct-tcpip',(settings['host'],settings.get('port',22)),('127.0.0.1',0),timeout=15)
            self.client.connect(settings['host'],port=settings.get('port',22),username=settings['user'],password=password,sock=sock,allow_agent=password is None,look_for_keys=password is None,timeout=15,banner_timeout=15,auth_timeout=20)
        except Failure:
            self.client.close();raise
        except paramiko.AuthenticationException:
            self.client.close();raise Failure('SSH 认证失败，请核对该设备的登录方式') from None
        except (paramiko.SSHException,OSError):
            self.client.close();raise Failure('SSH 连接未建立，请检查设备、管理端口及跳板通道') from None
        self.client.get_transport().set_keepalive(20)
        self.root=settings['user']=='root'

    def close(self):
        self.client.close()

    def run(self, command, payload=b'', timeout=180, allow_failure=False):
        i,o,e=self.client.exec_command(command,timeout=timeout)
        if payload:i.write(payload)
        i.channel.shutdown_write()
        channel=o.channel;raw=bytearray();err=bytearray();deadline=time.monotonic()+timeout
        while True:
            while channel.recv_ready():raw.extend(channel.recv(65536))
            while channel.recv_stderr_ready():err.extend(channel.recv_stderr(65536))
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():break
            if time.monotonic()>deadline:channel.close();raise Failure('远程操作超时；目标设备保留独立回退保护')
            time.sleep(.03)
        status=channel.recv_exit_status();raw=bytes(raw)
        if status and not allow_failure:raise Failure('远程操作失败（exit '+str(status)+'）；详细信息保留在目标设备的事务记录中')
        return raw

    def python(self, source, args):
        payload=('ARGS='+repr(args)+'\nAGENT_SOURCE='+repr(source)+'\nexec(compile(AGENT_SOURCE,"<stack-agent>","exec"))\n').encode()
        raw=self.run(('' if self.root else 'sudo -n ')+'python3 -B -',payload,timeout=1200,allow_failure=True)
        try:value=json.loads(raw)
        except Exception:raise Failure('目标主机返回了无效收据') from None
        require(value.get('ok') is True,'目标主机拒绝操作：'+str(value.get('error','unknown')))
        return value['result']

    def ruby(self, source, args):
        encoded_args=base64.b64encode(json.dumps(args,ensure_ascii=False).encode()).decode()
        encoded_source=base64.b64encode(source.encode()).decode()
        payload=('require "yaml"\nARGS=YAML.load("'+encoded_args+'".unpack1("m0"))\nROUTER_AGENT_SOURCE="'+encoded_source+'".unpack1("m0")\n'+source).encode()
        raw=self.run('ruby -',payload,timeout=900,allow_failure=True)
        try:value=json.loads(raw)
        except Exception:raise Failure('旁路由返回了无效收据') from None
        require(value.get('ok') is True,'旁路由拒绝操作：'+str(value.get('error','unknown')))
        return value['result']

    def upload_router(self, source, destination, expected, mode='600'):
        import shlex
        require(destination.startswith('/etc/openclash/custom/clash-stack-') and '/releases/' in destination and '..' not in destination.split('/'),'旁路由上传路径不安全')
        script='''set -eu
dest=$1
expected=$2
mode=$3
tmp="$dest.$$.upload"
umask 077
mkdir -p -m 700 "$(dirname "$dest")"
trap 'rm -f "$tmp"' EXIT INT TERM
cat > "$tmp"
actual=$(sha256sum "$tmp")
test "${actual%% *}" = "$expected"
chmod "$mode" "$tmp"
mv "$tmp" "$dest"
'''
        command='sh -c '+shlex.quote(script)+' sh '+shlex.quote(destination)+' '+shlex.quote(expected)+' '+shlex.quote(mode)
        i,o,e=self.client.exec_command(command,timeout=600)
        with open(source,'rb') as f:
            while block:=f.read(1024*1024):i.write(block)
        i.channel.shutdown_write();o.read();e.read()
        require(o.channel.recv_exit_status()==0,'旁路由文件上传或校验失败')

    def router_settings(self, destination, value):
        import shlex
        require(destination.startswith('/etc/openclash/custom/clash-stack-') and destination.endswith('/settings.json'),'旁路由配置路径不安全')
        script='set -eu; umask 077; mkdir -p -m 700 '+shlex.quote(str(Path(destination).parent).replace('\\','/'))+'; cat > '+shlex.quote(destination+'.upload')+'; chmod 600 '+shlex.quote(destination+'.upload')+'; mv '+shlex.quote(destination+'.upload')+' '+shlex.quote(destination)
        self.run('sh -c '+shlex.quote(script),json.dumps(value,ensure_ascii=False).encode())

    def upload(self, source, destination, expected=None):
        """Stream to a root-only temporary file, hash it, then atomically rename."""
        import shlex
        p=Path(source);require(p.is_file(),'本地上传文件不存在')
        if not expected:
            from .model import digest
            expected=digest(p)
        require(destination.startswith('/opt/clash-stack/') and '..' not in destination.split('/') and '\\' not in destination,'上传目标必须位于安装器目录')
        code='''import os,sys,hashlib,tempfile
from pathlib import Path
p=Path(sys.argv[1]);p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
fd,tmp=tempfile.mkstemp(prefix='.upload-',dir=p.parent);h=hashlib.sha256()
try:
 with os.fdopen(fd,'wb') as f:
  os.fchmod(f.fileno(),0o600)
  while True:
   b=sys.stdin.buffer.read(1048576)
   if not b:break
   h.update(b);f.write(b)
  f.flush();os.fsync(f.fileno())
 if h.hexdigest()!=sys.argv[2]:raise ValueError('checksum')
 os.replace(tmp,p)
finally:
 if os.path.exists(tmp):os.unlink(tmp)
'''
        command=('' if self.root else 'sudo -n ')+'python3 -c '+shlex.quote(code)+' '+shlex.quote(destination)+' '+shlex.quote(expected)
        i,o,e=self.client.exec_command(command,timeout=1800)
        with p.open('rb') as f:
            while block:=f.read(1024*1024):i.write(block)
        i.channel.shutdown_write();o.read();e.read()
        require(o.channel.recv_exit_status()==0,'上传文件或校验失败')
