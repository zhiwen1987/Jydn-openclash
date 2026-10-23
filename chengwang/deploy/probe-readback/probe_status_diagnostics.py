"""Closed, secret-free diagnostic projection; never a browser acceptance gate.

Clock domains remain separate. This decoder does not infer which JS request
caused a CDP event. The original backend/browser verifiers remain unchanged.
"""
import json

PREFIX = 'CW_PROBE_DIAG:'
MAX_LOG_BYTES = 327680
MAX_ROWS = 512
MAX_INTEGER = 9007199254740991
JS_FIELDS = {
    'MOUNT': set(), 'BEGIN': {'tr'}, 'ARM': set(), 'HEADERS': set(),
    'EOF': {'n'}, 'ABORT': {'c', 'p'}, 'CLEANUP': set(),
    'READ_END': {'k', 'n', 'f'}, 'CANCEL': {'p', 'n', 'f'}, 'FINALLY': set(),
}
FIELDS = {
    'NET_START': {'s', 'x', 'w', 'h', 'l'}, 'NET_HEADERS': {'s', 'x', 'st'},
    'NET_FAIL': {'s', 'x', 'c', 'ec'}, 'NET_FINISH': {'s', 'x'},
    'DOCUMENT': {'x', 'w', 'h', 'l'}, 'FRAME_NAV': {'h', 'l', 'p'},
    'META': {'js', 'net', 'rej', 'over'},
}


class Rejected(ValueError):
    def __init__(self):
        super().__init__('status diagnostic rejected')


def need(value):
    if not value:
        raise Rejected()


def integer(value, minimum=0, maximum=MAX_INTEGER):
    need(type(value) is int and minimum <= value <= maximum)


def choice(value, options):
    need(type(value) is str and value in options)


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value)
        value[key] = item
    return value


def decode_line(line):
    """Return only closed primitives, never a slice of arbitrary stderr."""
    need(type(line) is bytes and 0 < len(line) <= 512)
    need(all(32 <= item <= 126 for item in line) and line.startswith(PREFIX.encode('ascii')))
    raw = line[len(PREFIX):].decode('ascii')
    try:
        row = json.loads(raw, object_pairs_hook=unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(Rejected()))
    except (ValueError, TypeError, RecursionError):
        raise Rejected() from None
    need(type(row) is dict and json.dumps(row, separators=(',', ':'), ensure_ascii=True) == raw)
    need(row.get('v') == 1 and type(row.get('v')) is int)
    integer(row.get('q'), 1, MAX_ROWS)
    event = row.get('e')
    choice(event, {'JS', *FIELDS})
    if event == 'JS':
        kind = row.get('j')
        choice(kind, JS_FIELDS)
        need(set(row) == {'v', 'e', 'q', 'u', 'j', 'm', 'r', 't', 'a'} | JS_FIELDS[kind])
        integer(row['u']); integer(row['m'], 1, 128); integer(row['r'], 0, 128)
        integer(row['t'], 0, 2147483647); need(type(row['a']) is bool)
        if kind == 'MOUNT':
            need(row['r'] == row['t'] == 0 and row['a'] is False)
        elif kind != 'CLEANUP':
            integer(row['r'], 1, 128)
        if kind == 'BEGIN': choice(row['tr'], {'INITIAL', 'MANUAL', 'POLL'})
        if kind == 'ABORT':
            choice(row['c'], {'DEADLINE', 'CLEANUP'}); choice(row['p'], {'BEFORE', 'AFTER'})
        if kind == 'READ_END':
            choice(row['k'], {'FETCH_ERROR', 'HEADERS_REJECT', 'READ_ERROR', 'UTF8_REJECT',
                              'SIZE_REJECT', 'JSON_REJECT', 'EOF_OK'})
        if kind == 'CANCEL': choice(row['p'], {'BEFORE', 'AFTER'})
        if kind in {'READ_END', 'CANCEL', 'EOF'}: integer(row['n'], 0, 1048577)
        if kind in {'READ_END', 'CANCEL'}: need(type(row['f']) is bool)
    else:
        need(set(row) == {'v', 'e', 'q'} | FIELDS[event])
        for key in {'x', 'w'} & set(row): integer(row[key])
        for key in {'h', 'l'} & set(row): integer(row[key], 1, 256)
        if 's' in row: integer(row['s'], 1, 128)
        if event == 'NET_HEADERS': integer(row['st'], 100, 599)
        if event == 'NET_FAIL':
            choice(row['c'], {'YES', 'NO', 'UNKNOWN'})
            choice(row['ec'], {'ABORTED', 'OTHER', 'UNKNOWN'})
        if event == 'FRAME_NAV': integer(row['p'], 0, 256)
        if event == 'META':
            integer(row['js'], 0, 128); integer(row['net'], 0, 128)
            integer(row['rej'], 0, MAX_ROWS); need(type(row['over']) is bool)
    return row


def project(raw):
    """Invalid lines are counted, never exported, and make completeness false.

    A valid META means the observation sink closed, not that requests or browser
    acceptance passed. Counts can exceed emitted rows only when overflow=true.
    """
    need(type(raw) is bytes and len(raw) <= MAX_LOG_BYTES)
    records, rejected, candidates = [], 0, 0
    terminal_seen = False
    for line in raw.splitlines():
        if not line.startswith(PREFIX.encode('ascii')):
            continue
        candidates += 1
        if candidates > MAX_ROWS:
            rejected += 1
            continue
        try:
            row = decode_line(line)
            need(not terminal_seen and row['q'] == len(records) + 1)
            terminal_seen = row['e'] == 'META'
            records.append(row)
        except Rejected:
            rejected += 1
    meta = records[-1] if terminal_seen else None
    js = sum(row['e'] == 'JS' for row in records)
    net = sum(row['e'] == 'NET_START' for row in records)
    counts_match = bool(meta and meta['js'] == js and meta['net'] == net)
    return dict(schema='chengwang.probe-status-diagnostic/v1', observationalOnly=True,
                browserAcceptanceProven=False, causalRequestBindingProven=False,
                eventCount=len(records), rejectedLines=rejected,
                sinkClosed=terminal_seen,
                complete=bool(meta and counts_match and not rejected and not meta['rej'] and not meta['over']),
                records=records)
