"""Independent reconstruction from captured HTTP entity originals, not a producer.

No Go, worker, apply producer, network or filesystem code is imported/called.
Codec/parser references are pinned to Go go1.23.12 (BSD-3-Clause upstream):
https://github.com/golang/go/blob/go1.23.12/src/encoding/json/encode.go
https://github.com/golang/go/blob/go1.23.12/src/time/format.go
https://github.com/golang/go/blob/go1.23.12/src/time/format_rfc3339.go
https://github.com/golang/go/blob/go1.23.12/src/mime/mediatype.go
Semantic field order/subset follows formatted adapter/mihomo/lab_readback.go.
Raw reconstruction does not prove private YAML ancestry or the private fence.
"""
import base64
import datetime
import hashlib
import ipaddress
import json
import re
import unicodedata
import urllib.parse


PHASES = ('baseline', 'candidate')
TRANSCRIPT_NAMES = {p: p + '-get-evidence.json' for p in PHASES}
BODY_NAMES = {p: tuple(p + '-get-' + str(i).zfill(2) + '.body' for i in range(1, 9)) for p in PHASES}
CAPTURE_FILES = tuple(name for p in PHASES for name in (TRANSCRIPT_NAMES[p], *BODY_NAMES[p]))
NEW_PUBLIC = CAPTURE_FILES
PUBLIC = ('apply-observations.jsonl', 'apply-report.json', 'kernel.stdout', 'kernel.stderr',
          'syntax.exec.json', 'syntax.stdout', 'syntax.stderr') + CAPTURE_FILES + (
          'sandbox.json', 'execution.json', 'go-version.txt', 'gofmt.patch', 'gofmt.stderr',
          'apply.json', 'apply.stderr', 'host-before.json', 'host-after.json',
          'consumption.json', 'consumption-independent.json')
UNICODE_VERSION = '15.0.0'
BODY_LIMIT = 8 << 20
METADATA_LIMIT = 1 << 20
HEADER_LIMIT = 16 << 10
PROXY_LIMIT = 392
RULE_LIMIT = 2049
MEMBER_LIMIT = 66052
TOP_KEYS = ('schema', 'scope', 'expectedSchedule', 'records', 'slotsEntered', 'doInvocations',
            'responsesObserved', 'readAttempts', 'completedBodies', 'retainedBytes',
            'outcome', 'failureClass', 'limitReached', 'contextState')
RECORD_KEYS = ('ordinal', 'round', 'endpointKind', 'requestBuilt', 'doInvoked', 'responseObserved',
               'statusCode', 'headers', 'contentLength', 'uncompressed', 'readAttempted',
               'retainedBytes', 'retainedSHA256', 'naturalEOF', 'readErrorClass', 'limitReached',
               'closeAttempted', 'closeErrorClass', 'contextState', 'parseState', 'terminalClass')
HEADER_KEYS = ('contentTypeValuesB64', 'contentEncodingValuesB64', 'transferEncodingValuesB64', 'setCookieCount')
SCHEDULE_KEYS = ('ordinal', 'round', 'endpointKind')
KINDS = ('VERSION', 'CONFIGS', 'PROXIES', 'RULES')
SCHEDULE = tuple(dict(ordinal=i, round=1 + (i - 1) // 4, endpointKind=KINDS[(i - 1) % 4]) for i in range(1, 9))
READBACK_KEYS = ('conclusion', 'sampleCount', 'requestsObserved', 'previousProjectionSHA256',
                 'candidateProjectionSHA256', 'observedProjectionSHA256', 'dataplaneProven',
                 'fullPayloadProven', 'authorizationProven', 'production')
PRODUCER_FLAGS = ('apiExercised', 'authorizationExercised', 'authorizationProven', 'fullPayloadProven',
                  'headAdvanced', 'production', 'perGetRawEvidenceAvailable',
                  'independentProjectionRecomputeProven', 'internetBusinessProven')
PROXY_FIELDS = ('name', 'type', 'udp', 'now', 'all', 'testUrl', 'hidden', 'icon', 'emptyFallback',
                'uot', 'xudp', 'tfo', 'mptcp', 'smux', 'interface', 'routing-mark', 'provider-name', 'dialer-proxy')
RULE_FIELDS = ('index', 'type', 'payload', 'proxy', 'size', 'disabled')
BUILTINS = {'DIRECT': 'Direct', 'REJECT': 'Reject', 'REJECT-DROP': 'RejectDrop',
            'COMPATIBLE': 'Compatible', 'PASS': 'Pass', 'PASS-RULE': 'PassRule'}
GO_SPACE = '\t\n\v\f\r \u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000'
HEX = re.compile(r'[a-f0-9]{64}')
UUID = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}')
# Source-derived shape, not a claim that a captured General must equal these
# values. Valid drift is retained and hashed; private expected-source proof is false.
GENERAL_TEMPLATE = r'''{"port":0,"socks-port":0,"redir-port":0,"tproxy-port":0,"mixed-port":0,"tun":{"enable":false,"device":"","stack":"Mips","dns-hijack":["0.0.0.0:53"],"auto-route":true,"auto-detect-interface":true,"inet4-address":["198.18.0.1/30"],"file-descriptor":0,"recvmsgx":true,"processors-per-channel":1},"tuic-server":{"enable":false,"listen":"","certificate":"","private-key":"","ech-key":"","mux-option":{"brutal":{"enabled":false}}},"ss-config":"","vmess-config":"","authentication":null,"skip-auth-prefixes":null,"lan-allowed-ips":["0.0.0.0/0","::/0"],"lan-disallowed-ips":null,"allow-lan":false,"bind-address":"127.0.0.1","inbound-tfo":false,"inbound-mptcp":false,"mode":"rule","unified-delay":false,"log-level":"silent","ipv6":false,"interface-name":"","routing-mark":0,"geox-url":{"geo-ip":"","mmdb":"","asn":"","geo-site":""},"geo-auto-update":false,"geo-update-interval":24,"geodata-mode":false,"geodata-loader":"memconservative","geosite-matcher":"succinct","tcp-concurrent":false,"find-process-mode":"off","sniffing":false,"global-ua":"clash.meta/v1.19.32","etag-support":true,"keep-alive-idle":0,"keep-alive-interval":0,"disable-keep-alive":false}'''


def _need(value):
    if not value:
        raise ValueError('captured laboratory GET evidence rejected')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _object(value, keys, ordered=False):
    _need(type(value) is dict and set(value) == set(keys))
    if ordered:
        _need(tuple(value) == tuple(keys))
    return value


def _integer(value, low, high):
    _need(type(value) is int and low <= value <= high)
    return value


def _string(value, maximum):
    _need(type(value) is str and len(value.encode('utf-8')) <= maximum and
          value.strip(GO_SPACE) == value and
          not any(ord(c) < 32 or 127 <= ord(c) <= 159 or unicodedata.category(c) == 'Cf' for c in value))
    return value


def _name(value):
    _string(value, 268)
    _need(bool(value))
    for i, c in enumerate(value):
        _need(unicodedata.category(c)[0] in ('L', 'N') or i > 0 and c in '._ -')
    return value


def _domain(value):
    _string(value, 253)
    _need(bool(value) and value.lower() == value)
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        _need(False)
    _need(all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
              for label in value.split('.')))


def _json(raw, maximum=BODY_LIMIT):
    _need(type(raw) is bytes and 0 < len(raw) <= maximum)
    text = raw.decode('utf-8', 'strict')
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result)
            result[key] = value
        return result
    def number(value):
        _need(value != '-0' and len(value) <= 21)
        return int(value)
    def invalid(_):
        _need(False)
    value = json.loads(text, object_pairs_hook=pairs, parse_int=number,
                       parse_float=invalid, parse_constant=invalid)
    def visit(v, depth):
        _need(depth <= 24)
        if type(v) is dict:
            for k, child in v.items():
                _need(not any(0xd800 <= ord(c) <= 0xdfff for c in k))
                visit(child, depth + 1)
        elif type(v) is list:
            for child in v:
                visit(child, depth + 1)
        elif type(v) is str:
            _need(not any(0xd800 <= ord(c) <= 0xdfff for c in v))
    visit(value, 0)
    return value


class _Struct(tuple):
    """Explicit Go struct order, distinct from a recursively sorted Go map."""


def _quoted(value):
    _need(type(value) is str and not any(0xd800 <= ord(c) <= 0xdfff for c in value))
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')


def go_codec(value):
    """Go1.23 json.Marshal supported projection values, no trailing LF."""
    def encode(v):
        if v is None:
            return 'null'
        if type(v) is bool:
            return 'true' if v else 'false'
        if type(v) is int:
            return str(v)
        if type(v) is str:
            return _quoted(v)
        if type(v) is _Struct:
            return '{' + ','.join(_quoted(k) + ':' + encode(x) for k, x in v) + '}'
        if type(v) is dict:
            _need(all(type(k) is str for k in v))
            return '{' + ','.join(_quoted(k) + ':' + encode(v[k]) for k in sorted(v, key=lambda k: k.encode('utf-8'))) + '}'
        if type(v) is list:
            return '[' + ','.join(encode(x) for x in v) + ']'
        _need(False)
    return encode(value).encode('utf-8')


def go_timestamp(value):
    """Go Parse(RFC3339Nano) legality, not UTC conversion or a freshness test.

    format.go fallback accepts a one-digit hour, comma fractions, fractions
    longer than9 (truncated by Go), timezone hour24/minute60. labTimestamp
    independently limits UTF8 length35 and local calendar year1..9999.
    """
    _need(type(value) is str and len(value.encode('utf-8')) <= 35)
    m = re.fullmatch(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{1,2}):([0-9]{2}):([0-9]{2})(?:[.,]([0-9]+))?(Z|[+-][0-9]{2}:[0-9]{2})', value)
    _need(m is not None)
    y, mo, d, h, minute, second = map(int, m.groups()[:6])
    _need(1 <= y <= 9999 and h < 24 and minute < 60 and second < 60)
    datetime.date(y, mo, d)
    zone = m.group(8)
    if zone != 'Z':
        _need(int(zone[1:3]) <= 24 and int(zone[4:6]) <= 60)


def _history(value, nullable):
    if value is None:
        _need(nullable)
        return
    _need(type(value) is list and len(value) <= 10)
    for row in value:
        _object(row, ('time', 'delay'))
        go_timestamp(row['time'])
        _integer(row['delay'], 0, 65535)


def _telemetry_url(key):
    # Fixed Go1.23 net/url: scheme is lowercased, host ports have digit syntax
    # but no numeric range limit, and a bare ? or # leaves query/fragment empty.
    # Do not use Python urlsplit's stripping/IP-literal/port-range policies.
    _string(key, 2048)
    without_fragment, separator, fragment = key.partition('#')
    _need(not separator or fragment == '')
    before_query, separator, query = without_fragment.partition('?')
    _need(not separator or query == '')
    match = re.match(r'([A-Za-z][A-Za-z0-9+.-]*):', before_query)
    _need(match is not None and match.group(1).lower() in ('http', 'https'))
    rest = before_query[match.end():]
    _need(rest.startswith('//'))
    authority, slash, path = rest[2:].partition('/')
    _need(bool(authority) and '@' not in authority)
    _need(re.search(r'%(?![A-Fa-f0-9]{2})', path) is None)
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~!$&'()*+,;=:[]<>\""
    def host_bytes(text, zone=False):
        index = 0
        while index < len(text):
            char = text[index]
            if char == '%':
                code = text[index:index + 3]
                _need(re.fullmatch(r'%[A-Fa-f0-9]{2}', code) is not None)
                byte = int(code[1:], 16)
                if zone:
                    _need(code == '%25' or byte == 32 or chr(byte) in allowed)
                else:
                    _need(byte >= 128 or code == '%25')
                index += 3
            else:
                _need(ord(char) >= 128 or char in allowed)
                index += 1
    if authority.startswith('['):
        close = authority.rfind(']')
        _need(close >= 0 and re.fullmatch(r'(?::[0-9]*)?', authority[close + 1:]) is not None)
        zone = authority[:close].find('%25')
        if zone >= 0:
            host_bytes(authority[:zone]); host_bytes(authority[zone:close], True); host_bytes(authority[close:])
        else:
            host_bytes(authority)
    else:
        if ':' in authority:
            _need(re.fullmatch(r':[0-9]*', authority[authority.rfind(':'):]) is not None)
        host_bytes(authority)


def _telemetry(value):
    _need(type(value['alive']) is bool)
    _history(value['history'], False)
    extra = value['extra']
    _need(type(extra) is dict)
    for key, row in extra.items():
        _telemetry_url(key)
        _object(row, ('alive', 'history'))
        _need(type(row['alive']) is bool)
        _history(row['history'], True)


def _general(value):
    template = _json(GENERAL_TEMPLATE.encode())
    def shape(v, t):
        if type(t) is dict:
            _object(v, t)
            for key in t:
                shape(v[key], t[key])
        elif type(t) is list:
            _need(type(v) is list and len(v) <= 1024)
            for x in v:
                _string(x, 4096)
        elif t is None:
            if v is not None:
                _need(type(v) is list and len(v) <= 1024)
                for x in v:
                    _string(x, 4096)
        elif type(t) is bool:
            _need(type(v) is bool)
        elif type(t) is str:
            _string(v, 4096)
        else:
            _integer(v, -1, (1 << 31) - 1)
    shape(value, template)
    for key, allowed in {'mode': ('rule', 'global', 'direct'), 'log-level': ('debug', 'info', 'warning', 'error', 'silent'),
                         'find-process-mode': ('off', 'strict', 'always'), 'geodata-loader': ('memconservative', 'standard'),
                         'geosite-matcher': ('succinct', 'mph')}.items():
        _need(value[key] in allowed)
    _need(value['tun']['stack'] in ('Mips', 'Mixed', 'System', 'gVisor'))
    for key in ('port', 'socks-port', 'redir-port', 'tproxy-port', 'mixed-port'):
        _integer(value[key], 0, 65535)
    _need(all(value['tuic-server'][k] == '' for k in ('certificate', 'private-key', 'ech-key')) and
          value['ss-config'] == value['vmess-config'] == '')
    return value


def _proxies(value):
    _object(value, ('proxies',))
    proxies = value['proxies']
    _need(type(proxies) is dict and len(proxies) <= PROXY_LIMIT)
    common = ('type', 'history', 'extra', 'alive', 'name', 'udp', 'uot', 'xudp', 'tfo', 'mptcp',
              'smux', 'interface', 'routing-mark', 'provider-name', 'dialer-proxy')
    out, ids, members = [], {}, 0
    for name, row in proxies.items():
        _name(name)
        _need(type(row) is dict)
        kind = _string(row.get('type'), 32)
        selected = kind == 'Selector'
        _object(row, common + (('now', 'all', 'testUrl', 'hidden', 'icon', 'emptyFallback') if selected else ('id',)))
        _need(row['name'] == name)
        _telemetry(row)
        data = dict.fromkeys(PROXY_FIELDS)
        data.update(name=name, type=kind)
        for key in ('udp', 'uot', 'xudp', 'tfo', 'mptcp', 'smux'):
            _need(type(row[key]) is bool)
            data[key] = row[key]
        for key, limit in (('interface', 256), ('provider-name', 268), ('dialer-proxy', 268)):
            data[key] = _string(row[key], limit)
        data['routing-mark'] = _integer(row['routing-mark'], -(1 << 31), (1 << 31) - 1)
        if selected:
            data['now'] = _name(row['now'])
            all_ = row['all']
            _need(type(all_) is list and 1 <= len(all_) <= PROXY_LIMIT)
            for member in all_:
                _name(member)
            _need(len(set(all_)) == len(all_) and row['now'] in all_)
            members += len(all_)
            _need(members <= MEMBER_LIMIT)
            data['all'] = list(all_)
            for key in ('testUrl', 'icon'):
                data[key] = _string(row[key], 2048)
            data['emptyFallback'] = _name(row['emptyFallback'])
            _need(type(row['hidden']) is bool)
            data['hidden'] = row['hidden']
        else:
            _need(kind == 'Http' or BUILTINS.get(name) == kind)
            _need(type(row['id']) is str and UUID.fullmatch(row['id']) is not None)
            ids[name] = row['id']
        out.append(_Struct((key, data[key]) for key in PROXY_FIELDS))
    for row in out:
        for member in dict(row)['all'] or []:
            _need(member in proxies)
    out.sort(key=lambda row: dict(row)['name'].encode('utf-8'))
    return out, _sha(go_codec(ids)), set(proxies)


def _rules(value, names):
    _object(value, ('rules',))
    rows = value['rules']
    _need(type(rows) is list and 1 <= len(rows) <= RULE_LIMIT)
    out = []
    for i, row in enumerate(rows):
        _object(row, ('index', 'type', 'payload', 'proxy', 'size', 'extra'))
        _integer(row['index'], i, i)
        _integer(row['size'], -1, -1)
        kind = _string(row['type'], 32)
        _need(kind in ('DomainSuffix', 'Match'))
        payload = _string(row['payload'], 253)
        if kind == 'DomainSuffix':
            _domain(payload)
        else:
            _need(payload == '')
        proxy = _name(row['proxy'])
        _need(proxy in names)
        extra = _object(row['extra'], ('disabled', 'hitCount', 'hitAt', 'missCount', 'missAt'))
        _integer(extra['hitCount'], 0, (1 << 64) - 1)
        _integer(extra['missCount'], 0, (1 << 64) - 1)
        go_timestamp(extra['hitAt']); go_timestamp(extra['missAt'])
        _need(type(extra['disabled']) is bool)
        values = (i, kind, payload, proxy, -1, extra['disabled'])
        out.append(_Struct(zip(RULE_FIELDS, values)))
    return out


def projection_from_bodies(version_raw, general_raw, proxies_raw, rules_raw):
    """Pure reconstruction; all telemetry validated before exclusion."""
    version = _object(_json(version_raw), ('meta', 'version'))
    _need(version['meta'] is True and version['version'] == 'v1.19.32')
    general = _general(_json(general_raw))
    proxies, witness, names = _proxies(_json(proxies_raw))
    rules = _rules(_json(rules_raw), names)
    raw = go_codec(_Struct((('general', general), ('proxies', proxies), ('rules', rules))))
    return _sha(raw), witness


def _percent(value):
    _need(re.search(r'%(?![a-fA-F0-9]{2})', value) is None)
    return urllib.parse.unquote_to_bytes(value).decode('latin1')


def _go_lower(value):
    # Unicode15 simple lowercase, unlike Python's context/full-string lower:
    # U+0130 is the default lowercase expansion requiring this simple mapping.
    return ''.join('i' if c == '\u0130' else c.lower() for c in value)


def _mime_json(raw):
    # Independent implementation of the fixed Go MIME parser's relevant
    # media-type/parameter grammar, including equal duplicates/RFC2231.
    value = raw.decode('utf-8', 'surrogateescape')
    base, sep, rest = value.partition(';')
    _need(_go_lower(base.strip(GO_SPACE)) == 'application/json')
    rest = sep + rest if sep else ''
    params, pieces = {}, {}
    token = re.compile(r'[!#$%&\'*+.^_`|~{}0-9A-Za-z-]+')
    special = '()<>@,;:\\"/[]?='
    while rest:
        rest = rest.lstrip(GO_SPACE)
        if not rest:
            break
        _need(rest.startswith(';'))
        remaining = rest[1:].lstrip(GO_SPACE)
        if not remaining:
            break
        match = token.match(remaining)
        _need(match is not None)
        key = match.group().lower()
        remaining = remaining[match.end():].lstrip(GO_SPACE)
        _need(remaining.startswith('='))
        remaining = remaining[1:].lstrip(GO_SPACE)
        if remaining.startswith('"'):
            buf, index, closed = [], 1, False
            while index < len(remaining):
                char = remaining[index]
                if char == '"':
                    index += 1; closed = True; break
                _need(char not in '\r\n')
                if char == '\\' and index + 1 < len(remaining) and remaining[index + 1] in special:
                    index += 1; char = remaining[index]
                buf.append(char); index += 1
            _need(closed)
            item, rest = ''.join(buf), remaining[index:]
        else:
            match = token.match(remaining)
            _need(match is not None)
            item, rest = match.group(), remaining[match.end():]
        target = params if '*' not in key else pieces.setdefault(key.split('*', 1)[0], {})
        _need(key not in target or target[key] == item)
        target[key] = item
    def encoded(item):
        parts = item.split("'", 2)
        if len(parts) != 3 or parts[0].lower() not in ('us-ascii', 'utf-8'):
            return None
        try:
            return _percent(parts[2])
        except ValueError:
            return None
    for key, mapping in pieces.items():
        if key + '*' in mapping:
            decoded = encoded(mapping[key + '*'])
            if decoded is not None:
                params[key] = decoded
            continue
        result, used, index = [], False, 0
        while True:
            simple = key + '*' + str(index)
            if simple in mapping:
                result.append(mapping[simple]); used = True
            elif simple + '*' in mapping:
                item = mapping[simple + '*']; used = True
                if index == 0:
                    result.append(encoded(item) or '')
                else:
                    try:
                        result.append(_percent(item))
                    except ValueError:
                        result.append('')
            else:
                break
            index += 1
        if used:
            params[key] = ''.join(result)
    _need(len(params) <= 1 and all(k == 'charset' and v.lower() == 'utf-8' for k, v in params.items()))


def _headers(value):
    _object(value, HEADER_KEYS, True)
    _integer(value['setCookieCount'], 0, 0)
    decoded, total, count = {}, 0, 0
    for key in HEADER_KEYS[:3]:
        values = value[key]
        _need(type(values) is list and len(values) <= HEADER_LIMIT)
        decoded[key] = []
        for encoded in values:
            _need(type(encoded) is str and len(encoded) <= ((HEADER_LIMIT + 2) // 3) * 4)
            raw = base64.b64decode(encoded, validate=True)
            _need(base64.b64encode(raw).decode('ascii') == encoded)
            total += len(raw); count += 1
            _need(total <= HEADER_LIMIT and count <= HEADER_LIMIT)
            decoded[key].append(raw)
    types = decoded['contentTypeValuesB64']
    _need(len(types) == 1)
    _mime_json(types[0])
    _need(decoded['contentEncodingValuesB64'] in ([], [b'identity']) and
          decoded['transferEncodingValuesB64'] in ([], [b'chunked']))
    return decoded


def _capture(raw, phase, report):
    transcript_raw = raw[TRANSCRIPT_NAMES[phase]]
    binding = _object(report['getEvidence'][phase], ('sha256', 'bytes'))
    _integer(binding['bytes'], 1, METADATA_LIMIT)
    _need(binding['sha256'] == _sha(transcript_raw) and binding['bytes'] == len(transcript_raw))
    transcript = _object(_json(transcript_raw, METADATA_LIMIT), TOP_KEYS, True)
    _need(transcript['schema'] == 'chengwang.mihomo-lab-get-evidence/v1' and
          transcript['scope'] == 'PRIVATE_HTTP_ENTITY_RESPONSE_EVIDENCE_NOT_AUTHORIZATION_OR_PAYLOAD_PROOF' and
          transcript['outcome'] == 'COMPLETE' and transcript['failureClass'] is None and
          transcript['limitReached'] is False and transcript['contextState'] == 'ACTIVE')
    schedule, records = transcript['expectedSchedule'], transcript['records']
    _need(type(schedule) is list and type(records) is list and len(schedule) == len(records) == 8)
    body_inputs, bodies, total = [], [], 0
    for i, expected in enumerate(SCHEDULE):
        _object(schedule[i], SCHEDULE_KEYS, True)
        _integer(schedule[i]['ordinal'], i + 1, i + 1)
        _integer(schedule[i]['round'], expected['round'], expected['round'])
        _need(schedule[i]['endpointKind'] == expected['endpointKind'])
        row = _object(records[i], RECORD_KEYS, True)
        _integer(row['ordinal'], i + 1, i + 1)
        _integer(row['round'], expected['round'], expected['round'])
        _need(row['endpointKind'] == expected['endpointKind'])
        _need(all(row[k] is True for k in ('requestBuilt', 'doInvoked', 'responseObserved', 'readAttempted', 'naturalEOF', 'closeAttempted')))
        _integer(row['statusCode'], 200, 200)
        headers = _headers(row['headers'])
        _need(row['uncompressed'] is False and row['limitReached'] is False and
              row['readErrorClass'] == row['closeErrorClass'] == 'NONE' and row['contextState'] == 'ACTIVE' and
              row['parseState'] == 'SHAPE_ACCEPTED' and row['terminalClass'] == 'NONE')
        body_raw = raw[BODY_NAMES[phase][i]]
        _need(type(body_raw) is bytes and 0 < len(body_raw) <= BODY_LIMIT)
        _integer(row['retainedBytes'], len(body_raw), len(body_raw))
        _need(type(row['retainedSHA256']) is str and row['retainedSHA256'] == _sha(body_raw))
        length = _integer(row['contentLength'], -1, BODY_LIMIT)
        _need(length == -1 or length == len(body_raw))
        if headers['transferEncodingValuesB64']:
            _need(length == -1)
        total += len(body_raw)
        bodies.append(body_raw)
        body_inputs.append(dict(**expected, bytes=len(body_raw), sha256=_sha(body_raw)))
    for key in ('slotsEntered', 'doInvocations', 'responsesObserved', 'readAttempts', 'completedBodies'):
        _integer(transcript[key], 8, 8)
    _integer(transcript['retainedBytes'], total, total)
    digests, witnesses = [], []
    for start in (0, 4):
        digest, witness = projection_from_bodies(*bodies[start:start + 4])
        digests.append(digest); witnesses.append(witness)
    _need(digests[0] == digests[1] and witnesses[0] == witnesses[1])
    readback = _object(report['readbacks'][phase], READBACK_KEYS)
    _integer(readback['sampleCount'], 2, 2); _integer(readback['requestsObserved'], 8, 8)
    _need(all(readback[k] is False for k in ('dataplaneProven', 'fullPayloadProven', 'authorizationProven', 'production')))
    for key in ('previousProjectionSHA256', 'candidateProjectionSHA256', 'observedProjectionSHA256'):
        _need(type(readback[key]) is str and HEX.fullmatch(readback[key]) is not None)
    old, new = readback['previousProjectionSHA256'], readback['candidateProjectionSHA256']
    _need(old != new and readback['observedProjectionSHA256'] == digests[0] and
          readback['conclusion'] == ('STABLE_OLD_PROJECTION' if phase == 'baseline' else 'STABLE_NEW_PROJECTION') and
          digests[0] == (old if phase == 'baseline' else new))
    return dict(transcript=dict(bytes=len(transcript_raw), sha256=_sha(transcript_raw)),
                bodyInputs=body_inputs, roundProjectionSHA256=digests, roundUUIDWitnessSHA256=witnesses,
                observedProjectionSHA256=digests[0], uuidWitnessSHA256=witnesses[0])


def verify_captured(raw, report):
    """Full36 inputs, strict18 new originals, independent observed proof only."""
    if unicodedata.unidata_version != UNICODE_VERSION:
        raise ValueError('captured projection requires Unicode 15.0.0')
    try:
        _need(type(raw) is dict and set(raw) == set(PUBLIC) and len(PUBLIC) == 36 and
              all(type(raw[name]) is bytes for name in CAPTURE_FILES))
        _need(type(report) is dict and report.get('schema') == 'chengwang.mihomo-runtime-apply-report/v2')
        _object(report['getEvidence'], PHASES)
        _object(report['readbacks'], PHASES)
        flags = _object(report['flags'], PRODUCER_FLAGS)
        _need(flags['perGetRawEvidenceAvailable'] is True and
              all(flags[k] is False for k in PRODUCER_FLAGS if k != 'perGetRawEvidenceAvailable'))
        phases = {phase: _capture(raw, phase, report) for phase in PHASES}
        before, after = report['readbacks']['baseline'], report['readbacks']['candidate']
        _need(before['previousProjectionSHA256'] == after['previousProjectionSHA256'] and
              before['candidateProjectionSHA256'] == after['candidateProjectionSHA256'])
        return dict(schema='chengwang.mihomo-captured-projection-verification/v1', phases=phases,
                    perGetRawEvidenceAvailable=True, independentProjectionRecomputeProven=True,
                    expectedSourceIndependentlyProven=False, privateDisclosureFenceIndependentlyProven=False,
                    production=False)
    except Exception:
        raise ValueError('captured laboratory GET evidence rejected') from None
