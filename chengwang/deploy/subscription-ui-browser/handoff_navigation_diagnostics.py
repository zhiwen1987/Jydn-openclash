"""Failure-only safe navigation projection; importing starts no runtime.

The observation is an instantaneous trusted-driver projection before cleanup.
Missing, unsafe, stale or unknown input is unavailable, never acceptance or
invented zero counters. The caller supplies the existing native safe reader.
"""
from __future__ import annotations

import re

SCHEMA = 'chengwang.handoff-negative-navigation-diagnostics/v1'
SCOPE = 'FAILURE_ONLY_PRE_CLEANUP_INSTANT_NOT_ACCEPTANCE'
PRIVATE_FILE = 'driver-handoff-navigation.private.json'
MAX_BYTES = 8192
UID = 10001
MODE = 0o600
SCENARIOS = ('remote_handoff_negative',)
OBSERVATION_KEYS = {'schema', 'sourceCommit', 'fixtureId', 'engine', 'scenario',
                    'scope', 'phases', 'cause', 'input', 'journal'}
PHASE_KEYS = {'phase', 'entered', 'completed'}
PHASES = {
    'chrome-cdp': ('VIEWPORT', 'NAVIGATE_RETURN', 'READY', 'NAV_TARGET_FOUND', 'NAV_TARGET_ACTIONABLE',
                   'INPUT_DISPATCHED', 'ANON_DOM', 'API_CERT', 'TLS_VERIFIED'),
    'playwright': ('VIEWPORT', 'NAVIGATE_RETURN', 'READY', 'NAV_TARGET_FOUND', 'INPUT_DISPATCHED',
                   'ANON_DOM', 'API_CERT', 'TLS_VERIFIED'),
}
CAUSES = {
    'VIEWPORT': ('VIEWPORT_REJECTED',),
    'NAVIGATE_RETURN': ('NAVIGATE_CALL_REJECTED', 'NAVIGATE_ERROR_PRESENT'),
    'READY': ('READY_WAIT_REJECTED',),
    'NAV_TARGET_FOUND': ('NAV_TARGET_QUERY_REJECTED', 'NAV_TARGET_ZERO', 'NAV_TARGET_MULTIPLE'),
    'NAV_TARGET_ACTIONABLE': ('NAV_TARGET_DISABLED', 'NAV_TARGET_RECT_EMPTY',
                              'NAV_TARGET_OUTSIDE_VIEWPORT', 'NAV_TARGET_HIT_MISMATCH'),
    'INPUT_DISPATCHED': ('INPUT_MOVE_REJECTED', 'INPUT_PRESS_REJECTED',
                         'INPUT_RELEASE_REJECTED', 'PW_CLICK_REJECTED'),
    'ANON_DOM': ('ANON_DOM_WAIT_REJECTED', 'ANON_IDENTITY_REJECTED', 'ANON_SHAPE_REJECTED',
                'ANON_STEP_REJECTED', 'ANON_CONTENT_FENCE_REJECTED', 'ANON_JOURNAL_WAIT_REJECTED',
                'ANON_WIRE_FENCE_REJECTED', 'ANON_SAMPLER_FENCE_REJECTED', 'ANON_FEEDBACK_REJECTED'),
    'API_CERT': ('API_CERT_REJECTED',),
    'TLS_VERIFIED': ('TLS_PROOF_REJECTED',),
}
COUNTERS = ('runtimeErrors', 'consoleErrors', 'consoleWarnings', 'cspErrors', 'assetErrors',
            'forbiddenRequests', 'failedRequests', 'captureErrors')
JOURNAL_KEYS = {'available', 'failure', 'counters', 'requests', 'terminal', 'pending',
                'captures', 'tasks', 'mutations'}
MAX_REQUESTS = {'remote_handoff_negative': 256}
MAX_MUTATIONS = {'remote_handoff_negative': 10}
MAX_COUNTER = 2147483647


def need(value):
    if not value:
        raise ValueError('navigation diagnostics unavailable')


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys))


def integer(value, maximum):
    need(type(value) is int and 0 <= value <= maximum)


def validate(value, fixture, engine, scenario, source_commit):
    """Validate the whole closed observation, without probing or filling facts."""
    need(type(fixture) is str and re.fullmatch('[a-f0-9]{32}', fixture))
    need(type(source_commit) is str and re.fullmatch('[a-f0-9]{40}', source_commit))
    need(type(engine) is str and engine in PHASES and type(scenario) is str and scenario in SCENARIOS)
    exact(value, OBSERVATION_KEYS)
    need(value['schema'] == SCHEMA and value['scope'] == SCOPE
         and value['fixtureId'] == fixture and value['sourceCommit'] == source_commit
         and value['engine'] == engine and value['scenario'] == scenario)
    phases = value['phases']
    need(type(phases) is list and len(phases) <= len(PHASES[engine]))
    for index, row in enumerate(phases):
        exact(row, PHASE_KEYS)
        need(row['phase'] == PHASES[engine][index] and row['entered'] is True
             and type(row['completed']) is bool)
        need(index == len(phases) - 1 or row['completed'] is True)
    incomplete = phases[-1]['phase'] if phases and phases[-1]['completed'] is False else None
    need(type(value['cause']) is str)
    need(value['cause'] in CAUSES[incomplete] if incomplete else value['cause'] == 'UNCLASSIFIED')
    input_index = PHASES[engine].index('INPUT_DISPATCHED')
    if len(phases) <= input_index:
        need(value['input'] is None)
    elif engine == 'chrome-cdp':
        exact(value['input'], ('kind', 'mask'))
        mask = value['input']['mask']
        need(value['input']['kind'] == 'CDP_ACK_MASK' and type(mask) is int and mask in (0, 1, 3, 7))
        if incomplete == 'INPUT_DISPATCHED':
            need(value['cause'] in ('INPUT_MOVE_REJECTED', 'INPUT_PRESS_REJECTED', 'INPUT_RELEASE_REJECTED'))
            need(mask == {'INPUT_MOVE_REJECTED': 0, 'INPUT_PRESS_REJECTED': 1,
                          'INPUT_RELEASE_REJECTED': 3}[value['cause']])
        else:
            need(mask == 7)
    else:
        exact(value['input'], ('kind', 'returned'))
        need(value['input']['kind'] == 'PW_CLICK_RETURN' and type(value['input']['returned']) is bool)
        if incomplete == 'INPUT_DISPATCHED':
            need(value['cause'] == 'PW_CLICK_REJECTED' and value['input']['returned'] is False)
        else:
            need(value['input']['returned'] is True)
    journal = value['journal']
    need(type(journal) is dict and type(journal.get('available')) is bool)
    if journal['available'] is False:
        exact(journal, ('available',))
    else:
        exact(journal, JOURNAL_KEYS)
        need(type(journal['failure']) is bool)
        exact(journal['counters'], COUNTERS)
        for counter in journal['counters'].values():
            integer(counter, MAX_COUNTER)
        for key in ('requests', 'terminal', 'pending', 'captures', 'tasks'):
            integer(journal[key], MAX_REQUESTS[scenario])
        integer(journal['mutations'], MAX_MUTATIONS[scenario])
        need(journal['terminal'] + journal['pending'] == journal['requests']
             and journal['captures'] <= journal['terminal'] and journal['mutations'] <= journal['requests'])
    return value


def read(root, fixture, engine, scenario, source_commit, N):
    """Read only the fixture's derived private file; failure stays unavailable."""
    try:
        need(type(fixture) is str and re.fullmatch('[a-f0-9]{32}', fixture)
             and str(root) == '/tmp/chengwang-subscription-ui-' + fixture)
        raw = N.stable_read(root / PRIVATE_FILE, MAX_BYTES, UID, MODE)[0]
        need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
        value = validate(N.decode(raw), fixture, engine, scenario, source_commit)
        return dict(available=True, observation=value)
    except Exception:
        # No original exception, malformed field, path, or fabricated count is public.
        return dict(available=False)
