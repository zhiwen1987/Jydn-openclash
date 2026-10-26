import hashlib
import json
import time
from pathlib import Path

from .model import Failure, canonical, digest, require, site_paths, verify_bundle
from .transport import SSH


class Coordinator:
    def __init__(self, root, profile, passwords=None, emit=print):
        self.root=Path(root).resolve();self.p=profile;self.paths=site_paths(profile)
        self.manifest=verify_bundle(self.root);self.emit=emit;passwords=passwords or {}
        self.server=SSH(profile['server'],passwords.get('server'))
        try:self.router=SSH(profile['router'],passwords.get('router'),self.server if profile['router'].get('via_server') else None)
        except Exception:self.server.close();raise
        self.server_code=(self.root/'agents/server.py').read_text(encoding='utf-8')
        self.router_code=(self.root/'agents/router.rb').read_text(encoding='utf-8')
        self.package='/opt/clash-stack/_packages/'+self.manifest['version']+'-'+self.manifest['payload_sha256'][:16]

    def close(self):self.router.close();self.server.close()

    def server_action(self, action, **kwargs):
        return self.server.python(self.server_code,{'action':action,'profile':self.p,'base':self.paths['base'],**kwargs})

    def router_action(self, action, **kwargs):
        return self.router.ruby(self.router_code,{'action':action,'profile':self.p,'base':self.paths['router_base'],**kwargs})

    def doctor(self):
        self.emit('只读检查 Docker 主机与旁路由…')
        self.router.run('command -v ruby >/dev/null && command -v curl >/dev/null && test -f /etc/init.d/openclash',timeout=15)
        server=self.server_action('doctor');router=self.router_action('doctor')
        require(router['architecture'] in ('x86_64','amd64'),'安装包架构与旁路由不一致')
        require(router['kernel_sha256']==self.manifest['core_sha256'],'旁路由内核版本不在本包兼容范围；已停止，未替换运行内核')
        require(server['free_bytes']>=self.manifest.get('required_free_bytes',6*1024**3),'Docker 主机磁盘余量不足')
        return {'server':server,'router':router}

    def plan(self):
        inventory=self.doctor();server=inventory['server'];router=inventory['router']
        if self.p['mode']=='fresh':
            # A same-site managed container is handled by the idempotent path.
            if server['container'] is None:require(all(server['ports_free'].values()),'目标端口已被占用，请修改环境档案；不会停止占用端口的业务')
        else:require(server['container'] is not None,'要接管的容器不存在')
        changes=['保存目标配置、选择状态与在线 SQLite 备份','部署一个中心容器，持久数据单独保存','核验服务、DNS、实际规则和入口，再解除双端恢复守护']
        if self.p['mode']=='fresh':changes.insert(1,'安装管理钩子并切换旁路由到本站点配置')
        else:changes.insert(1,'保留旁路由配置；仅升级已识别的中心服务镜像，Kuma/DNS 将短暂停顿')
        value={'schema':1,'profile_sha256':hashlib.sha256(canonical(self.p)).hexdigest(),'manifest_sha256':hashlib.sha256(canonical(self.manifest)).hexdigest(),'created_at':time.time(),'inventory':inventory,'changes':changes,'requires_router_switch':self.p['mode']=='fresh' and router['running'] and router['source']!=self.paths['router_config'],'pending_user_actions':['主路由 DHCP/DNS/下一跳按环境接入；安装器不修改爱快','真实节点与账号业务验收']}
        value['plan_id']=hashlib.sha256(canonical(value)).hexdigest()
        return value

    def _validate_plan(self, plan, allow_router_switch):
        body={k:v for k,v in plan.items() if k!='plan_id'}
        require(hashlib.sha256(canonical(body)).hexdigest()==plan.get('plan_id'),'安装计划校验失败')
        require(0<=time.time()-plan['created_at']<=1800,'安装计划已过期，请重新预览')
        require(plan['profile_sha256']==hashlib.sha256(canonical(self.p)).hexdigest(),'环境档案已变化')
        require(plan['manifest_sha256']==hashlib.sha256(canonical(self.manifest)).hexdigest(),'安装包已变化')
        now=self.doctor()
        for key in ('mac','source_sha256','runtime_sha256','uci_sha256','overwrite_sha256','kernel_sha256'):
            require(now['router'].get(key)==plan['inventory']['router'].get(key),'旁路由在预览后发生变化：'+key)
        require(now['server']['container']==plan['inventory']['server']['container'],'目标容器在预览后变化')
        require(not plan['requires_router_switch'] or allow_router_switch,'此计划会切换正在运行的旁路由配置，需要明确允许 --allow-router-switch')

    def stage_package(self):
        self.emit('上传并校验离线资源；不会拉取 latest 镜像…')
        for name in ('payload.tar.gz','clash-center.tar.gz'):
            path=self.package+'/'+name
            import shlex
            prefix='' if self.server.root else 'sudo -n '
            result=self.server.run(prefix+'sha256sum '+shlex.quote(path),timeout=120,allow_failure=True).decode().split()
            if result and result[0]==self.manifest['files'][name]:continue
            self.server.upload(self.root/name,path,self.manifest['files'][name])

    def stage_router(self, material, source_count):
        base=self.paths['router_base'];release=base+'/releases/'+self.manifest['version']
        p=self.p;settings={'profile':p,'ports':p['ports'],'material':material,'base':base,'server':p['server']['host'],'source_count':source_count,'release':release}
        for name in self.manifest['router_files']:
            require(not Path(name).is_absolute() and '..' not in Path(name).parts,'旁路由资源路径无效')
            source=self.root/'payload/router'/name;target=release+'/'+name
            self.router.upload_router(source,target,self.manifest['files']['payload/router/'+name],'700' if name=='core' else '600')
        self.router.router_settings(release+'/settings.json',settings)

    def install(self, plan, inputs=None, allow_router_switch=False):
        self._validate_plan(plan,allow_router_switch)
        server=plan['inventory']['server']
        if server.get('managed_version')==self.manifest['version']:
            require(server.get('managed_profile_sha256')==server['profile_sha256'],'同一版本的环境档案已变化，请先评审迁移；不会直接覆盖')
            self.emit('本站点已安装同一版本，仅核验，不重建容器或覆盖数据…')
            return {'installed':True,'idempotent':True,'version':self.manifest['version'],**self.verify()}
        self.stage_package()
        server_prepared=router_prepared=False
        try:
            self.emit('创建配置与数据库备份…')
            receipt=self.server_action('prepare',package=self.package,manifest=self.manifest,inputs=inputs or {})
            server_prepared=True;material=receipt.pop('private')
            self.router_action('prepare',material=material,allow_router_switch=allow_router_switch,expected=plan['inventory']['router']);router_prepared=True
            if self.p['mode']=='fresh':self.stage_router(material,receipt['source_count'])
            self.emit('部署中心服务并启用独立回退保护…')
            self.server_action('install',package=self.package)
            self.emit('应用旁路由配置…')
            self.router_action('install',version=self.manifest['version'],core_sha256=self.manifest['core_sha256'])
            self.emit('等待实际运行状态；不以保存成功代替服务验收…')
            last=None;deadline=time.monotonic()+240
            for _ in range(40):
                if time.monotonic()>deadline:break
                try:
                    router=self.router_action('verify');server=self.server_action('verify');break
                except Failure as error:last=error;time.sleep(5)
            else:raise last or Failure('服务启动超时')
            if time.monotonic()>deadline:raise last or Failure('服务启动超时')
            self.router_action('verify',accept=True)
            self.server_action('verify',accept=True)
            return {'installed':True,'site':self.p['site'],'version':self.manifest['version'],'backup':receipt['backup'],'router':router,'server':server,'pending_user_actions':plan['pending_user_actions']}
        except BaseException:
            self.emit('安装未通过，正在恢复本次变更…')
            failures=[]
            if router_prepared:
                try:self.router_action('restore',manual=True)
                except Exception as error:failures.append('旁路由恢复需要检查目标事务记录：'+(str(error) if isinstance(error,Failure) else type(error).__name__))
            # Never remove the center if restoring the router was refused.
            if server_prepared and not failures:
                try:self.server_action('restore',manual=True)
                except Exception as error:failures.append('中心服务恢复需要检查目标事务记录：'+(str(error) if isinstance(error,Failure) else type(error).__name__))
            if failures:raise Failure('；'.join(failures)) from None
            raise

    def verify(self):
        return {'router':self.router_action('verify'),'server':self.server_action('verify')}

    def restore(self):
        self.emit('恢复上一已记录版本；保留业务数据…')
        router=self.router_action('restore',manual=True)
        server=self.server_action('restore',manual=True)
        return {'router':router,'server':server}

    def backup(self):
        return {'server':self.server_action('backup'),'router':self.router_action('backup')}
