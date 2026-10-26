"""Bounded, local-only URI conversion. Unknown transport options fail closed.

Formats follow SIP002, XTLS share links and Hysteria 2 URI specifications.
This parser does not fetch URLs, execute plugins or guess TLS/transport options.
The actual installed Mihomo kernel is the final compatibility validator.
"""
import base64
import ipaddress
import json
import re
import urllib.parse as url
import uuid


class Invalid(ValueError):
    pass


def b64(value):
    try:
        return base64.b64decode(value.replace('-', '+').replace('_', '/') + '=' * (-len(value) % 4), validate=True).decode('utf-8')
    except Exception:
        raise Invalid('base64_invalid') from None


def host(value):
    if not isinstance(value, str) or len(value) > 253 or not value:
        raise Invalid('server_invalid')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value) or '..' in value:
            raise Invalid('server_invalid')
    return value


def flag(value):
    if value not in ('0', '1', 'true', 'false'):
        raise Invalid('boolean_invalid')
    return value in ('1', 'true')


def clean_label(value):
    value = value.strip()[:72]
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Invalid('label_invalid')
    return value or '未命名节点'


def parse_line(line):
    if re.search(r'%(?![0-9A-Fa-f]{2})', line):
        raise Invalid('percent_encoding_invalid')
    scheme = line.split('://', 1)[0].lower()
    if scheme == 'vmess':
        v = json.loads(b64(line[8:]))
        allowed = {'v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'net', 'type', 'host', 'path', 'tls', 'sni', 'alpn', 'fp', 'allowInsecure'}
        if not isinstance(v, dict) or set(v) - allowed:
            raise Invalid('vmess_unknown_option')
        if str(v.get('v', '2')) != '2' or v.get('type', 'none') not in ('none', ''):
            raise Invalid('vmess_version_or_header_unsupported')
        uuid.UUID(v['id'])
        n = {'type': 'vmess', 'server': host(v['add']), 'port': int(v['port']), 'uuid': v['id'], 'alterId': int(v.get('aid', 0)), 'cipher': v.get('scy') or 'auto', 'udp': True}
        q = {'type': v.get('net') or 'tcp', 'security': v.get('tls') or 'none'}
        for key in ('sni', 'alpn', 'fp', 'allowInsecure', 'host', 'path'):
            if str(v.get(key, '')):
                q[key] = str(v[key])
        transport(n, q)
        label = clean_label(str(v.get('ps', '')))
    else:
        if scheme == 'ss':
            # SIP002 userinfo, plus legacy whole-authority base64.
            rest = line[5:]
            if '@' not in rest.split('#', 1)[0].split('?', 1)[0]:
                authority, sep, fragment = rest.partition('#')
                line = 'ss://' + b64(authority) + (sep + fragment if sep else '')
        p = url.urlsplit(line)
        if p.path not in ('', '/') or not p.hostname:
            raise Invalid('uri_authority_invalid')
        q = url.parse_qs(p.query, keep_blank_values=True, strict_parsing=True, errors='strict')
        if any(len(v) != 1 for v in q.values()):
            raise Invalid('duplicate_option')
        q = {k: v[0] for k, v in q.items()}
        n = {'type': scheme, 'server': host(p.hostname), 'port': p.port or (443 if scheme in ('trojan', 'hysteria2', 'hy2') else 0), 'udp': True}
        label = clean_label(url.unquote(p.fragment, errors='strict'))
        user = url.unquote(p.username or '', errors='strict')
        if scheme == 'ss':
            credential = user + ':' + url.unquote(p.password, errors='strict') if p.password is not None else b64(user)
            cipher, sep, password = credential.partition(':')
            if not sep or not password:
                raise Invalid('ss_credentials_invalid')
            n.update(type='ss', cipher=cipher, password=password)
            # Plugins are executable adapters; do not silently discard them.
            if q:
                raise Invalid('ss_option_unsupported')
        elif scheme == 'vless':
            uuid.UUID(user)
            if p.password is not None or q.pop('encryption', 'none') != 'none':
                raise Invalid('vless_encryption_unsupported')
            n['uuid'] = user
            flow = q.pop('flow', '')
            if flow:
                if flow != 'xtls-rprx-vision':
                    raise Invalid('flow_unsupported')
                n['flow'] = flow
            transport(n, q)
        elif scheme == 'trojan':
            if not user or p.password is not None:
                raise Invalid('trojan_credentials_invalid')
            n['password'] = user
            q.setdefault('security', 'tls')
            transport(n, q)
        elif scheme in ('hysteria2', 'hy2'):
            n.update(type='hysteria2', password=user + (':' + url.unquote(p.password, errors='strict') if p.password is not None else ''))
            if not n['password']:
                raise Invalid('password_missing')
            allowed = {'sni', 'insecure', 'obfs', 'obfs-password'}
            if set(q) - allowed:
                raise Invalid('hysteria_option_unsupported')
            if q.get('sni'):
                n['sni'] = host(q['sni'])
            if 'insecure' in q:
                n['skip-cert-verify'] = flag(q['insecure'])
            if 'obfs' in q:
                if q['obfs'] != 'salamander' or not q.get('obfs-password'):
                    raise Invalid('obfs_invalid')
                n.update(obfs='salamander', **{'obfs-password': q['obfs-password']})
            elif 'obfs-password' in q:
                raise Invalid('obfs_invalid')
        elif scheme in ('socks5', 'http', 'https'):
            if q:
                raise Invalid('proxy_option_unsupported')
            n['type'] = 'http' if scheme in ('http', 'https') else 'socks5'
            n['udp'] = scheme == 'socks5'
            if user:
                if p.password is None:
                    raise Invalid('proxy_password_missing')
                n.update(username=user, password=url.unquote(p.password, errors='strict'))
            elif p.password is not None:
                raise Invalid('proxy_username_missing')
            if scheme == 'https':
                n['tls'] = True
        else:
            raise Invalid('protocol_unsupported')
    if not 1 <= n['port'] <= 65535:
        raise Invalid('port_invalid')
    return label, n


def transport(n, q):
    q = dict(q)
    security = q.pop('security', 'none')
    if security not in ('none', 'tls', 'reality'):
        raise Invalid('security_unsupported')
    if n['type'] == 'trojan' and security != 'tls':
        raise Invalid('trojan_requires_tls')
    sni = q.pop('sni', q.pop('peer', ''))
    alpn = q.pop('alpn', '')
    fp = q.pop('fp', '')
    insecure = q.pop('allowInsecure', q.pop('insecure', None))
    if security != 'none':
        n['tls'] = True
        if sni:
            n['servername' if n['type'] != 'trojan' else 'sni'] = host(sni)
        if alpn:
            n['alpn'] = alpn.split(',')
        if fp:
            n['client-fingerprint'] = fp
        if insecure is not None:
            n['skip-cert-verify'] = flag(insecure)
    elif sni or alpn or fp or insecure is not None:
        raise Invalid('tls_options_without_tls')
    if security == 'reality':
        if n['type'] != 'vless' or not q.get('pbk') or not fp:
            raise Invalid('reality_key_or_fingerprint_missing')
        n['reality-opts'] = {'public-key': q.pop('pbk'), 'short-id': q.pop('sid', '')}
        # spx is not representable in this Mihomo outbound schema.
    net = q.pop('type', 'tcp')
    if net == 'ws':
        n['network'] = 'ws'
        n['ws-opts'] = {'path': q.pop('path', '/')}
        if 'host' in q:
            n['ws-opts']['headers'] = {'Host': q.pop('host')}
    elif net == 'grpc':
        n['network'] = 'grpc'
        n['grpc-opts'] = {'grpc-service-name': q.pop('serviceName', '')}
        if q.pop('mode', 'gun') != 'gun':
            raise Invalid('grpc_mode_unsupported')
    elif net != 'tcp':
        raise Invalid('transport_unsupported')
    elif q.pop('headerType', 'none') != 'none':
        raise Invalid('tcp_header_unsupported')
    if q:
        raise Invalid('unknown_or_inapplicable_option')


def parse(text):
    if not isinstance(text, str) or len(text.encode()) > 196608:
        raise Invalid('input_too_large')
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) > 100:
        raise Invalid('node_limit_100')
    result = []
    for index, line in enumerate(lines, 1):
        try:
            result.append(parse_line(line))
        except Exception as exc:
            reason = str(exc) if isinstance(exc, Invalid) else 'malformed_node'
            # Never return the URI, exception URL, credentials or malformed body.
            raise Invalid(f'line_{index}:{reason}') from None
    return result
