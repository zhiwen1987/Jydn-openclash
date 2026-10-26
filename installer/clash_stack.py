#!/usr/bin/env python3
"""Chinese interactive/CLI installer; uses only its bundled Python dependencies."""
import argparse
import getpass
import json
import os
from pathlib import Path
import platform
import sys

sys.dont_write_bytecode=True
if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(line_buffering=True)
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
tag=('win' if os.name=='nt' else 'linux')+'-cp'+str(sys.version_info.major)+str(sys.version_info.minor)
vendor=ROOT/'vendor'/tag
common=ROOT/'vendor/linux-common'
if os.name!='nt' and common.is_dir():sys.path.insert(0,str(common))
if vendor.is_dir():sys.path.insert(0,str(vendor))
from stack.model import Failure, read_profile, profile, verify_bundle


def save(path,value):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')


def ask(title, default=''):
    value=input(title+(' ['+str(default)+']' if default!='' else '')+'：').strip()
    return value or str(default)


def confirm_fingerprint(host, port, via=None):
    from stack.transport import inspect_key
    actual=inspect_key(host,port,via)
    print('目标 SSH 主机指纹：'+actual)
    if ask('请核对设备控制台或已知记录，确认后输入 yes')!='yes':raise Failure('未确认设备身份，未进行修改')
    return actual


def wizard():
    from stack.transport import SSH
    print('Clash Stack 一键安装向导\n支持单容器中心服务及已有 OpenClash 的 x86_64 旁路由。\n不会修改 Windows 应用、系统代理或本机 DNS。')
    verify_bundle(ROOT)
    site=ask('站点名（小写英文/数字/短横线）','home')
    mode='adopt' if ask('1 全新部署，2 接管已有单容器中心','1')=='2' else 'fresh'
    server={'host':ask('Docker 主机 IPv4 地址'),'user':ask('SSH 用户名','root'),'port':int(ask('SSH 端口','22'))}
    server['fingerprint']=confirm_fingerprint(server['host'],server['port'])
    passwords={'server':getpass.getpass('Docker 主机 SSH 密码（留空使用现有密钥）：') or None}
    connection=SSH(server,passwords['server'])
    try:
        router={'host':ask('旁路由 SSH IPv4 地址'),'user':ask('旁路由 SSH 用户名','root'),'port':int(ask('旁路由 SSH 端口','22')),'via_server':ask('通过 Docker 主机连接旁路由？yes/no','yes')=='yes'}
        router['fingerprint']=confirm_fingerprint(router['host'],router['port'],connection if router['via_server'] else None)
        passwords['router']=getpass.getpass('旁路由 SSH 密码（留空使用现有密钥）：') or None
        r=SSH(router,passwords['router'],connection if router['via_server'] else None)
        try:
            observed=r.run('cat /sys/class/net/br-lan/address',timeout=10).decode().strip()
            router['mac']=ask('旁路由 br-lan MAC，请核对实际设备',observed).lower()
        finally:r.close()
    finally:connection.close()
    ports={'kuma':3101,'capability':3102,'subscription':3103,'dns':53,'api':9090,'proxy':7893,'probe':17895,'router_dns':7874}
    if ask('需要调整默认服务端口？yes/no','no')=='yes':
        ports={k:int(ask(k+' 端口',v)) for k,v in ports.items()}
    prefix='.'.join(server['host'].split('.')[:3])+'.0/24'
    publish=ask('发布中心 DNS 端口？不会修改 DHCP 或终端 DNS。yes/no','no')=='yes'
    value={'schema':1,'site':site,'mode':mode,'server':server,'router':router,'ports':ports,'dns':{'publish':publish,'upstreams':[router['host']+':'+str(ports['router_dns'])],'allowed_cidrs':[ask('允许访问 DNS 的实际局域网网段',prefix)]},'public_minimum':int(ask('公共订阅最低合格节点数','1'))}
    if mode=='adopt':value.update(existing_compose=ask('现有 Compose JSON 文件的绝对路径','/root/dpanel/compose/lan-center/docker-compose.yml'),existing_container=ask('现有单容器名称','clash-center'))
    profile(value);path=ROOT/'sites'/(site+'.json');save(path,value)
    print('环境档案已保存：'+str(path)+'（不含密码或订阅链接）')
    return path,passwords


def main():
    parser=argparse.ArgumentParser(description='Clash Stack 可回退的一键部署安装器')
    parser.add_argument('action',nargs='?',default='wizard',choices=['wizard','doctor','plan','install','verify','restore','upgrade','backup','self-check'])
    parser.add_argument('--profile',type=Path);parser.add_argument('--plan',type=Path);parser.add_argument('--output',type=Path);parser.add_argument('--yes',action='store_true');parser.add_argument('--allow-router-switch',action='store_true');parser.add_argument('--secrets-stdin',action='store_true')
    args=parser.parse_args()
    if args.action=='self-check':
        manifest=verify_bundle(ROOT);import paramiko
        print(json.dumps({'package_verified':True,'version':manifest['version'],'platform':platform.system(),'python':platform.python_version(),'ssh_library':paramiko.__version__},ensure_ascii=False));return
    passwords={};secrets={}
    if args.action=='wizard':
        args.profile,passwords=wizard();args.action='install'
    if args.profile is None:raise Failure('请指定 --profile 环境档案，或直接运行向导')
    p=read_profile(args.profile)
    if args.secrets_stdin:
        secrets=json.load(sys.stdin);passwords={k:secrets.get(k+'_password') for k in ('server','router')}
    elif not passwords:
        passwords={role:getpass.getpass(('Docker 主机' if role=='server' else '旁路由')+' SSH 密码（留空用现有密钥）：') or None for role in ('server','router')}
    from stack.coordinator import Coordinator
    c=Coordinator(ROOT,p,passwords);passwords.clear()
    try:
        if args.action=='doctor':result=c.doctor()
        elif args.action=='plan':
            result=c.plan();path=args.output or args.profile.with_suffix('.plan.json');save(path,result);print('只读计划已保存：'+str(path))
        elif args.action in ('install','upgrade'):
            plan=json.loads(args.plan.read_text(encoding='utf-8')) if args.plan else c.plan()
            print('\n将执行：\n'+'\n'.join(' - '+x for x in plan['changes']))
            if not args.yes and ask('确认上述具体变更？输入 install 执行')!='install':raise Failure('安装已取消，未修改生产配置')
            inputs={'subscriptions':secrets.get('subscriptions',[]),'kuma':secrets.get('kuma')}
            if p['mode']=='fresh' and not args.secrets_stdin:
                urls=[]
                print('订阅地址可输入 0 条、1 条或多条；输入留空结束。输入不会回显。')
                for index in range(16):
                    url=getpass.getpass('订阅 '+str(index+1)+'：').strip()
                    if not url:break
                    urls.append(url)
                inputs['subscriptions']=urls
                username=ask('Kuma 初始管理员用户名（留空稍后在面板设置）','')
                if username:
                    password=getpass.getpass('Kuma 管理员密码：');again=getpass.getpass('再次输入：')
                    if password!=again:raise Failure('两次密码不同')
                    inputs['kuma']={'username':username,'password':password}
            result=c.install(plan,inputs,args.allow_router_switch)
        elif args.action=='verify':result=c.verify()
        elif args.action=='restore':
            if not args.yes and ask('确认恢复上一记录版本并保留数据？输入 restore')!='restore':raise Failure('未执行恢复')
            result=c.restore()
        elif args.action=='backup':result=c.backup()
        else:raise Failure('此操作尚不支持')
        if args.output:save(args.output,result)
        print(json.dumps(result,ensure_ascii=False,indent=2))
    finally:c.close();secrets.clear()


if __name__=='__main__':
    try:main()
    except (Failure,ValueError,KeyboardInterrupt) as error:
        print('操作已停止：'+str(error),file=sys.stderr);raise SystemExit(1)
