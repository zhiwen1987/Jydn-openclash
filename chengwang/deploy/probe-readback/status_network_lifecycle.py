"""Closed passive metadata projection. Completeness is never browser acceptance."""
import json
import pathlib

PREFIX = 'CW_STATUS_NET:'
MAX_BYTES = 131072
MAX_ROWS = 128
MAX_INTEGER = 9007199254740991
CONTRACT_NAME = 'status-network-lifecycle-contract.json'
REQUEST_FIELDS = {'n', 'm', 'r', 'startUs', 'responseUs', 'endUs', 'response', 'extra', 'chunks',
                  'dataBytes', 'encodedBytes', 'terminal', 'canceled', 'error', 'blocked', 'cors', 'hasExtra'}
TRI = {'YES', 'NO', 'NOT_OBSERVED'}
CONTEXT = {'DOCUMENT', 'DOCUMENT_CHANGED', 'DEFAULT_CREATED', 'DEFAULT_DESTROYED', 'CONTEXTS_CLEARED', 'FRAME_DETACHED'}


class Rejected(ValueError):
    def __init__(self): super().__init__('status network metadata rejected')


def need(value):
    if not value: raise Rejected()


def integer(value, minimum=0, maximum=MAX_INTEGER):
    need(type(value) is int and minimum <= value <= maximum)


def choice(value, values): need(type(value) is str and value in values)
def exact(value, fields): need(type(value) is dict and set(value) == set(fields))


def unique(pairs):
    out = {}
    for k, v in pairs:
        need(k not in out); out[k] = v
    return out


def encoded(value): return json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def decoded(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES + 16384)
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected()))
    except (ValueError, UnicodeError, RecursionError): raise Rejected() from None


def load_contract():
    parent = pathlib.Path(__file__).resolve().parent
    path = parent / CONTRACT_NAME
    if not path.is_file():
        path = parent / 'source/chengwang/deploy/probe-readback' / CONTRACT_NAME
    raw = path.read_bytes(); need(len(raw) <= 16384)
    c = decoded(raw)
    need(c.get('schema') == 'chengwang.status-network-lifecycle-contract/v1')
    for key, expected in dict(maxRequests=7, maxContexts=16, maxRows=128, maxLineBytes=4096,
                              maxBytes=131072, maxBodyBytes=1048576).items():
        integer(c.get(key), expected, expected)
    for field in ('protocols', 'blockedReasons', 'corsReasons'):
        a = c.get(field); need(type(a) is list and 1 <= len(a) <= 64)
        need(all(type(v) is str and 1 <= len(v) <= 100 and v.isascii() for v in a) and len(set(a)) == len(a))
    return c


def framing(value):
    exact(value, {'length', 'transfer', 'encoding', 'connection'})
    n = value['length']
    if n is not None:
        if type(n) is int: integer(n, 0, 1048576)
        else: choice(n, {'CONFLICT', 'INVALID'})
    for k, values in dict(transfer={'chunked', 'identity'}, encoding={'gzip', 'br', 'deflate', 'identity'},
                           connection={'close', 'keep-alive'}).items():
        if value[k] is not None: choice(value[k], values | {'UNKNOWN', 'CONFLICT'})


def validate_row(row, contract):
    need(type(row) is dict)
    integer(row.get('v'), 1, 1); integer(row.get('s'), 1, 1); integer(row.get('q'), 1, MAX_ROWS)
    event = row.get('e'); choice(event, {'SESSION', 'CONTEXT', 'REQUEST', 'META'})
    base = {'v', 's', 'q', 'e'}
    if event == 'SESSION': exact(row, base)
    elif event == 'CONTEXT':
        exact(row, base | {'k', 'c', 'phase'}); choice(row['k'], CONTEXT); choice(row['phase'], {'RUNNING', 'CLOSING'})
        if row['k'] in {'DEFAULT_CREATED', 'DEFAULT_DESTROYED'}: integer(row['c'], 1, 16)
        else: need(row['c'] is None)
    elif event == 'META':
        exact(row, base | {'requests', 'contexts', 'rejected', 'overflow', 'sinkFailed'})
        integer(row['requests'], 0, 7); integer(row['contexts'], 0, 64); integer(row['rejected'], 0, 128)
        need(type(row['overflow']) is bool and type(row['sinkFailed']) is bool)
    else:
        exact(row, base | REQUEST_FIELDS)
        integer(row['n'], 1, 7); integer(row['m'], 1, 128); integer(row['r'], 1, 128); integer(row['startUs'])
        for k in ('responseUs', 'endUs'):
            if row[k] is not None: integer(row[k], row['startUs'])
        choice(row['terminal'], {'MISSING', 'FINISHED', 'FAILED'}); choice(row['hasExtra'], TRI)
        need((row['terminal'] == 'MISSING') == (row['endUs'] is None))
        if row['response'] is None: need(row['responseUs'] is None)
        else:
            need(row['responseUs'] is not None)
            v = row['response']; exact(v, {'status', 'protocol', 'connection', 'reused', 'diskCache', 'serviceWorker', 'prefetchCache', 'framing'})
            integer(v['status'], 100, 599); choice(v['protocol'], contract['protocols'])
            if v['connection'] is not None: integer(v['connection'], 1, 7)
            for k in ('reused', 'diskCache', 'serviceWorker', 'prefetchCache'): choice(v[k], TRI)
            framing(v['framing'])
        if row['extra'] is not None:
            exact(row['extra'], {'status', 'framing'}); integer(row['extra']['status'], 100, 599); framing(row['extra']['framing'])
        if row['chunks'] is None: need(row['dataBytes'] is None and row['encodedBytes'] is None)
        else:
            integer(row['chunks'], 1, 1024); integer(row['dataBytes'], 0, 1048576); integer(row['encodedBytes'], 0, 1048576)
        if row['terminal'] == 'FAILED':
            choice(row['canceled'], TRI); choice(row['error'], {'ABORTED', 'OTHER', 'NOT_OBSERVED'})
            if row['blocked'] is not None: choice(row['blocked'], contract['blockedReasons'])
            if row['cors'] is not None: choice(row['cors'], contract['corsReasons'])
        else: need(all(row[k] is None for k in ('canceled', 'error', 'blocked', 'cors')))


def project(raw, contract=None):
    """Missing required events remain null/MISSING and explicitly incomplete."""
    c = load_contract() if contract is None else contract
    need(type(raw) is bytes and len(raw) <= MAX_BYTES)
    rows, rejected, closed = [], 0, False
    for line in raw.splitlines():
        try:
            need(len(rows) < MAX_ROWS and 0 < len(line) + 1 <= c['maxLineBytes']
                 and line.startswith(PREFIX.encode()) and all(32 <= b <= 126 for b in line))
            body = line[len(PREFIX):]; row = decoded(body)
            need(encoded(row) == body and not closed and row.get('q') == len(rows) + 1)
            validate_row(row, c); rows.append(row); closed = row['e'] == 'META'
        except Rejected: rejected += 1
    requests = [r for r in rows if r['e'] == 'REQUEST']; contexts = [r for r in rows if r['e'] == 'CONTEXT']
    missing = set()
    if not rows or rows[0]['e'] != 'SESSION' or sum(r['e'] == 'SESSION' for r in rows) != 1: missing.add('SESSION')
    if not closed: missing.add('META')
    if len(requests) != 7: missing.add('SEVEN_REQUESTS')
    if [r['n'] for r in requests] != list(range(1, len(requests) + 1)): missing.add('REQUEST_ORDER')
    if len({(r['m'], r['r']) for r in requests}) != len(requests): missing.add('IDENTITY_UNIQUE')
    if not any(r['k'] == 'DOCUMENT' for r in contexts) or not any(r['k'] == 'DEFAULT_CREATED' for r in contexts): missing.add('CONTEXT')
    if closed:
        meta = rows[-1]
        if meta['requests'] != len(requests) or meta['contexts'] != len(contexts): missing.add('COUNTS')
        if meta['rejected'] or meta['overflow'] or meta['sinkFailed']: missing.add('COLLECTOR')
    for r in requests:
        if r['response'] is None: missing.add('RESPONSE')
        if r['chunks'] is None: missing.add('DATA')
        if r['terminal'] == 'MISSING': missing.add('TERMINAL')
        if r['hasExtra'] == 'NOT_OBSERVED': missing.add('EXTRA_EXPECTATION')
        if r['hasExtra'] == 'YES' and r['extra'] is None: missing.add('EXPECTED_EXTRA')
        if r['terminal'] == 'FAILED' and (r['canceled'] == 'NOT_OBSERVED' or r['error'] == 'NOT_OBSERVED'): missing.add('FAILURE_FIELDS')
    if rejected: missing.add('REJECTED_LINES')
    return dict(schema=c['publicSchema'], observationalOnly=True, browserAcceptanceProven=False,
                cancellationRootCauseProven=False, production=False, authorization='BLOCKED',
                eventCount=len(rows), rejectedLines=rejected, sinkClosed=closed, complete=not missing,
                incompleteReasons=sorted(missing), records=rows)
