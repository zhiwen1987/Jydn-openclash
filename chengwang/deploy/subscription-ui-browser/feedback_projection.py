"""Closed successful feedback projection; never publishes private log text."""
import hashlib
import json
from pathlib import Path
import re


def need(value):
    if not value: raise ValueError('feedback projection rejected')


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result); result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: need(False))


CONTRACT = decode((Path(__file__).parents[2] /
    'tools/subscription-ui-browser/handoff-feedback-contract.json').read_bytes())
PREFIX = CONTRACT['prefix'].encode('ascii')


def project(raw, dom_raw, *, allow_noise=False):
    """Return only strict enums and hashes after complete 49-stage validation.

    The caller supplies stable file reads. The inner driver log can contain
    unrelated PRIVATE text, which is never returned; the outer supervisor
    projection must contain only these successful observations. Neither form
    independently discloses or verifies raw rendered notice text.
    """
    need(type(allow_noise) is bool and type(raw) is bytes and type(dom_raw) is bytes)
    need(0 < len(raw) <= (32 << 20 if allow_noise else CONTRACT['maxProjectionBytes'])
         and raw.endswith(b'\n') and 0 < len(dom_raw) <= 1 << 20 and dom_raw.endswith(b'\n'))
    lines = []
    for line in raw.splitlines(keepends=True):
        if PREFIX not in line:
            need(allow_noise); continue
        need(line.startswith(PREFIX) and line.endswith(b'\n') and not line.endswith(b'\r\n')
             and len(line) <= CONTRACT['maxLineBytes']
             and all(32 <= byte <= 126 for byte in line[:-1]))
        lines.append(line)
    need(len(lines) == len(CONTRACT['steps']) == CONTRACT['maxRows'] == 49
         and sum(map(len, lines)) <= CONTRACT['maxProjectionBytes'])
    dom_lines = dom_raw.splitlines(keepends=True)
    need(len(dom_lines) == 49)
    for ordinal, (line, dom_line, step) in enumerate(zip(lines, dom_lines, CONTRACT['steps']), 1):
        payload = line[len(PREFIX):-1]; observation = decode(payload)
        need(type(observation) is dict and list(observation) == CONTRACT['observationKeys'])
        need(json.dumps(observation, ensure_ascii=True, separators=(',', ':')).encode('ascii') == payload)
        need(observation['schema'] == CONTRACT['observationSchema']
             and type(observation['ordinal']) is int and observation['ordinal'] == ordinal
             and observation['step'] == step
             and type(observation['domRowSHA256']) is str
             and re.fullmatch('[a-f0-9]{64}', observation['domRowSHA256'])
             and observation['domRowSHA256'] == hashlib.sha256(dom_line).hexdigest())
        expected = CONTRACT['expected'][step]
        for key in CONTRACT['snapshotKeys']:
            need(type(observation[key]) is type(expected[key]) and observation[key] == expected[key])
        need(dom_line.endswith(b'\n') and not dom_line.endswith(b'\r\n'))
        dom = decode(dom_line)
        need(type(dom) is dict and dom.get('schema') == 'chengwang.handoff-negative-ui-dom-capture/v1'
             and type(dom.get('ordinal')) is int and dom['ordinal'] == ordinal and dom.get('step') == step)
        snapshot = dom.get('dom')
        need(type(snapshot) is dict and type(snapshot.get('alertVisible')) is bool
             and type(snapshot.get('pageVisible')) is bool
             and observation['alertVisible'] == snapshot['alertVisible']
             and observation['statusVisible'] == (observation['status'] != 'ABSENT' and snapshot['pageVisible']))
    return b''.join(lines)
