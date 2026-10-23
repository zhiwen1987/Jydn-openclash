"""Closed projection of the dedicated request-binding descriptor, not acceptance.

No private protocol ID, header nonce, filename, raw error or arbitrary string is
exported. Structural completeness is not an independent identity proof.
"""
import json

PREFIX = 'CW_PROBE_BIND_DIAG:'
MAX_BYTES = 524288
MAX_ROWS = 1024
MAX_INTEGER = 9007199254740991
JS_FIELDS = {
    'MOUNT': set(), 'BEGIN': {'tr'}, 'ARM': set(), 'HEADERS': set(),
    'EOF': {'n'}, 'ABORT': {'cause', 'p'}, 'CLEANUP': set(),
    'READ_END': {'k', 'n', 'f'}, 'CANCEL': {'p', 'n', 'f'}, 'FINALLY': set(),
}
FIELDS = {
    'SESSION': set(), 'DOCUMENT': {'h'}, 'CONTEXT': {'c', 'h', 'default'},
    'SEND': {'c', 'd', 'm', 'r', 't', 'a'},
    'CANCEL_RESULT': {'c', 'd', 'm', 'r', 't', 'a', 'o'},
    'NET_START': {'n', 'd', 'm', 'r', 'h', 'x', 'w'},
    'NET_HEADERS': {'n', 'x', 'st'}, 'NET_FINISH': {'n', 'x'},
    'NET_FAIL': {'n', 'x', 'canceled', 'error'},
    'META': {'js', 'sends', 'results', 'net', 'contexts', 'docs', 'rejected', 'overflow'},
}
COUNT_EVENTS = dict(js='JS', sends='SEND', results='CANCEL_RESULT', net='NET_START',
                    contexts='CONTEXT', docs='DOCUMENT')


class Rejected(ValueError):
    def __init__(self): super().__init__('request binding rejected')


def need(value):
    if not value: raise Rejected()


def integer(value, minimum=0, maximum=MAX_INTEGER):
    need(type(value) is int and minimum <= value <= maximum)


def choice(value, choices):
    need(type(value) is str and value in choices)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result); result[key] = value
    return result


def decode_line(line):
    need(type(line) is bytes and 0 < len(line) <= 512 and line.startswith(PREFIX.encode('ascii')))
    need(all(32 <= byte <= 126 for byte in line))
    raw = line[len(PREFIX):].decode('ascii')
    try:
        row = json.loads(raw, object_pairs_hook=unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(Rejected()))
    except (ValueError, TypeError, RecursionError): raise Rejected() from None
    need(type(row) is dict and json.dumps(row, separators=(',', ':'), ensure_ascii=True) == raw)
    integer(row.get('v'), 1, 1); integer(row.get('q'), 1, MAX_ROWS); integer(row.get('s'), 1, 1)
    event = row.get('e'); choice(event, {'JS', *FIELDS})
    if event == 'JS':
        kind = row.get('j'); choice(kind, JS_FIELDS)
        need(set(row) == {'v', 'e', 'q', 's', 'c', 'j', 'm', 'r', 't', 'a'} | JS_FIELDS[kind])
        integer(row['c'], 1, 16); integer(row['m'], 1, 128); integer(row['r'], 0, 128)
        integer(row['t'], 0, 2147483647); need(type(row['a']) is bool)
        if kind == 'MOUNT': need(row['r'] == row['t'] == 0 and row['a'] is False)
        elif kind != 'CLEANUP': integer(row['r'], 1, 128)
        if kind == 'BEGIN': choice(row['tr'], {'INITIAL', 'MANUAL', 'POLL'})
        if kind == 'ABORT':
            choice(row['cause'], {'DEADLINE', 'CLEANUP'}); choice(row['p'], {'BEFORE', 'AFTER'})
        if kind == 'READ_END':
            choice(row['k'], {'FETCH_ERROR', 'HEADERS_REJECT', 'READ_ERROR', 'UTF8_REJECT',
                              'SIZE_REJECT', 'JSON_REJECT', 'EOF_OK'})
        if kind == 'CANCEL': choice(row['p'], {'BEFORE', 'AFTER'})
        if kind in {'READ_END', 'CANCEL', 'EOF'}: integer(row['n'], 0, 1048577)
        if kind in {'READ_END', 'CANCEL'}: need(type(row['f']) is bool)
    else:
        need(set(row) == {'v', 'e', 'q', 's'} | FIELDS[event])
        for key in {'x', 'w'} & row.keys(): integer(row[key])
        for key in {'c', 'h', 'd'} & row.keys(): integer(row[key], 1, 16)
        for key in {'m', 'r', 'n'} & row.keys(): integer(row[key], 1, 128)
        if event in {'SEND', 'CANCEL_RESULT'}:
            integer(row['t'], 0, 2147483647); need(type(row['a']) is bool)
        if event == 'CONTEXT': need(type(row['default']) is bool)
        if event == 'CANCEL_RESULT': choice(row['o'], {'RESOLVED', 'REJECTED', 'THREW', 'NO_BODY'})
        if event == 'NET_HEADERS': integer(row['st'], 100, 599)
        if event == 'NET_FAIL':
            choice(row['canceled'], {'YES', 'NO', 'UNKNOWN'}); choice(row['error'], {'ABORTED', 'OTHER', 'UNKNOWN'})
        if event == 'META':
            for key in COUNT_EVENTS:
                integer(row[key], 0, 256 if key == 'js' else 16 if key in {'contexts', 'docs'} else 128)
            integer(row['rejected'], 0, MAX_ROWS); need(type(row['overflow']) is bool)
    return row


def project(raw):
    """A malformed/foreign line is counted and suppressed, never exported."""
    need(type(raw) is bytes and len(raw) <= MAX_BYTES)
    records, rejected, closed = [], 0, False
    for ordinal, line in enumerate(raw.splitlines(), 1):
        try:
            need(ordinal <= MAX_ROWS)
            row = decode_line(line)
            need(not closed and row['q'] == len(records) + 1)
            closed = row['e'] == 'META'; records.append(row)
        except Rejected: rejected += 1
    meta = records[-1] if closed else None
    counts = {name: sum(row['e'] == event for row in records) for name, event in COUNT_EVENTS.items()}
    counts['docs'] = len({row['d'] for row in records if 'd' in row})
    complete = bool(meta and not rejected and not meta['rejected'] and not meta['overflow']
                    and counts['js'] + counts['sends'] + counts['results'] <= 256
                    and all(meta[name] == count for name, count in counts.items()))
    return dict(schema='chengwang.probe-request-binding/v1', observationalOnly=True,
                browserAcceptanceProven=False, cancellationRootCauseProven=False,
                eventCount=len(records), rejectedLines=rejected, sinkClosed=closed,
                complete=complete, records=records)
