import hashlib
import ipaddress
import json
import re
from pathlib import Path


class Failure(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise Failure(reason)


def digest(path):
    value = hashlib.sha256()
    with open(path, 'rb') as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def profile(value):
    require(isinstance(value, dict) and value.get('schema') == 1, '环境档案版本不支持')
    require(set(value) <= {'schema','site','mode','server','router','ports','dns','public_minimum','existing_compose','existing_container'}, '环境档案存在未知字段')
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,31}', value.get('site','')), '站点名只允许小写字母、数字和短横线')
    require(value.get('mode') in ('fresh','adopt'), '安装方式必须是 fresh 或 adopt')
    for role in ('server','router'):
        item=value.get(role,{})
        require(set(item) <= {'host','user','port','fingerprint','mac','via_server','api_host','provider_client'}, 'SSH 字段不支持')
        require(ipaddress.ip_address(item.get('host','')).version==4,'此版本仅支持 IPv4 管理地址')
        if item.get('api_host'):require(ipaddress.ip_address(item['api_host']).version==4,'API 管理地址无效')
        if item.get('provider_client'):require(ipaddress.ip_address(item['provider_client']).version==4,'提供者客户端地址无效')
        require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,31}',item.get('user','')), 'SSH 用户名无效')
        require(type(item.get('port',22)) is int and 0<item.get('port',22)<65536,'SSH 端口无效')
        require(bool(re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',item.get('fingerprint',''))), '必须固定 SSH 主机指纹')
    require(bool(re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',value['router'].get('mac',''))),'必须固定旁路由 MAC')
    ports=value.get('ports',{})
    require(set(ports)=={'kuma','capability','subscription','dns','api','proxy','probe','router_dns'}, '端口字段不完整')
    require(all(type(p) is int and 1024<=p<65536 for k,p in ports.items() if k!='dns'),'服务端口应在 1024–65535')
    require(type(ports['dns']) is int and 0<ports['dns']<65536,'DNS 端口无效')
    require(len(set(ports[k] for k in ('kuma','capability','subscription')))==3,'中心服务端口重复')
    require(len(set(ports[k] for k in ('api','proxy','probe')))==3,'旁路由端口重复')
    require(ports['router_dns'] not in [ports[k] for k in ('api','proxy','probe')],'旁路由 DNS 与服务端口重复')
    dns=value.get('dns',{})
    require(set(dns) <= {'publish','upstreams','test_name','allowed_cidrs'}, 'DNS 字段不支持')
    require(type(dns.get('publish')) is bool,'必须明确是否发布 DNS 端口')
    if 'test_name' in dns:
        name=dns['test_name']
        require(isinstance(name,str) and 1<=len(name.rstrip('.'))<=253 and all(
            bool(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label))
            for label in name.rstrip('.').split('.')),'DNS 验收域名格式无效')
    require(not dns['publish'] or ports['dns'] not in [ports[k] for k in ('kuma','capability','subscription')],'中心 DNS 与面板端口重复')
    require(isinstance(dns.get('upstreams'),list) and 1<=len(dns['upstreams'])<=4,'需要 1–4 个 DNS 上游')
    for address in dns['upstreams']:
        require(isinstance(address,str) and bool(re.fullmatch(r'[0-9.]+(?::[0-9]{1,5})?',address)), '此版本 DNS 上游需 IPv4，可带端口')
        ipaddress.IPv4Address(address.split(':')[0])
        if ':' in address:require(0<int(address.split(':')[1])<65536,'DNS 上游端口无效')
    require(isinstance(dns.get('allowed_cidrs'),list) and 1<=len(dns['allowed_cidrs'])<=16,'需要明确 DNS 允许访问的网段')
    for net in dns['allowed_cidrs']:ipaddress.ip_network(net,strict=False)
    require(type(value.get('public_minimum',1)) is int and 1<=value.get('public_minimum',1)<=100,'公共订阅最低节点数无效')
    if value['mode']=='adopt':
        require(value.get('existing_compose','').startswith('/'),'接管需要原 Compose 绝对路径')
        require(bool(re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',value.get('existing_container',''))),'接管容器名无效')
    return value


def read_profile(path):
    return profile(json.loads(Path(path).read_text(encoding='utf-8')))


def verify_bundle(root):
    root=Path(root).resolve()
    manifest=json.loads((root/'manifest.json').read_text(encoding='utf-8'))
    require(manifest.get('schema')==1,'安装包清单不支持')
    require(bool(re.fullmatch(r'[0-9][A-Za-z0-9_.-]{0,63}',manifest.get('version',''))),'安装包版本无效')
    require(manifest.get('platform')=='linux/amd64','此安装包仅支持 Linux x86_64')
    require(isinstance(manifest.get('files'),dict) and manifest['files'],'安装包文件清单为空')
    for key in ('core_sha256','payload_sha256','image_archive_sha256'):
        require(bool(re.fullmatch(r'[0-9a-f]{64}',manifest.get(key,''))),'安装包散列字段无效：'+key)
    require(manifest['files'].get('payload.tar.gz')==manifest['payload_sha256'] and manifest['files'].get('clash-center.tar.gz')==manifest['image_archive_sha256'],'资源清单与归档散列不一致')
    require(isinstance(manifest.get('payload_files'),dict) and manifest['payload_files'],'部署资源清单为空')
    for name,expected in manifest['payload_files'].items():
        require(manifest['files'].get(name)==expected,'部署资源缺少完整性记录')
    require(isinstance(manifest.get('router_files'),list) and manifest['router_files'],'旁路由资源清单为空')
    for name in manifest['router_files']:
        require(isinstance(name,str) and 'payload/router/'+name in manifest['payload_files'],'旁路由资源路径无效')
    for name,expected in manifest['files'].items():
        require(isinstance(name,str) and '\\' not in name and ':' not in name and bool(re.fullmatch(r'[0-9a-f]{64}',expected)),'安装包路径或散列无效')
        path=root/name
        require(not Path(name).is_absolute() and '..' not in Path(name).parts and path.resolve().is_relative_to(root) and path.is_file() and not path.is_symlink(),'安装包路径不安全')
        require(digest(path)==expected,'安装包文件校验失败：'+name)
    require(re.fullmatch(r'sha256:[0-9a-f]{64}',manifest.get('image_id','')),'镜像 ID 无效')
    return manifest


def site_paths(p):
    base='/opt/clash-stack/'+p['site']
    return {'base':base,'container':'clash-center-'+p['site'],'router_base':'/etc/openclash/custom/clash-stack-'+p['site'],'router_config':'/etc/openclash/config/clash-stack-'+p['site']+'.yaml'}
