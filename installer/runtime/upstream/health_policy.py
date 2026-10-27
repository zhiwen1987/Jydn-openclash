"""Shared, deterministic node recovery policy; no routing or network writes."""
import math
import json
from pathlib import Path
import time

COOLDOWN = 3600
CONFIRM_FAILURES = 3
RECOVER_SUCCESSES = 2
MIN_SAMPLE_GAP = 10
INFRASTRUCTURE = ('busy', 'native_ssh', 'native_admission_', 'admission_',
                  'restricted_ssh_', 'core_pin_', 'core_version_', 'isolated_core_',
                  'bootstrap_resolver_', 'detector_', 'probe_group_changed', 'input_rejected')


def acceptance_hold(path=Path('/data/node-health/acceptance-hold.json')):
    try:
        value=json.loads(path.read_text());until=value['until'];now=time.time()
        return type(until) not in (int,float) or not math.isfinite(until) or until>now
    except FileNotFoundError:return False
    except (OSError,ValueError,TypeError,KeyError):return True


def error_scope(reason):
    reason = str(reason or '')
    if reason.startswith(INFRASTRUCTURE):
        return 'detector'
    if reason in ('rate_limited', 'access_denied', 'region_restricted', 'unexpected_content'):
        return 'business'
    return 'node'


def transition(previous, success, epoch, reason='ok', observed_at=None):
    r = dict(previous or {})
    stamp = epoch if observed_at is None else observed_at
    for key in ('last_observation', 'last_success', 'last_attempt', 'cooldown_until', 'next_due'):
        v = r.get(key, 0)
        if type(v) not in (int, float) or not math.isfinite(v) or v < 0 or v > epoch+COOLDOWN:
            r[key] = 0
    scope = error_scope(reason)
    r.update(last_attempt=epoch, error_scope=scope, reason=reason)
    if not success and scope == 'detector':
        r.update(next_due=max(epoch+30,r.get('cooldown_until',0)), detector_error=True)
        return r
    r['detector_error'] = False
    if stamp <= r.get('last_observation', 0) or stamp-r.get('last_observation', 0) < MIN_SAMPLE_GAP:
        r['next_due'] = max(r.get('next_due', 0), epoch+30)
        return r
    r.update(last_observation=stamp, at=stamp, ok=False)
    if success:
        r.update(failure_streak=0, success_streak=min(1000, int(r.get('success_streak', 0))+1), last_success=stamp)
        if epoch < r.get('cooldown_until', 0):
            r.update(status='cooling', next_due=r['cooldown_until'])
        elif r.get('status') == 'available' or r['success_streak'] >= RECOVER_SUCCESSES:
            r.update(status='available', ok=True, cooldown_until=0, next_due=epoch+300)
        else:
            r.update(status='checking', next_due=epoch+30)
    else:
        r.update(success_streak=0, failure_streak=min(1000, int(r.get('failure_streak', 0))+1))
        if r['failure_streak'] >= CONFIRM_FAILURES:
            r.update(status='unavailable', cooldown_until=epoch+COOLDOWN, next_due=epoch+COOLDOWN)
        else:
            r.update(status='checking', next_due=epoch+30*r['failure_streak'])
    return r


def eligible(record, epoch):
    return bool(record.get('ok') is True and record.get('status') == 'available'
                and 0 <= epoch-record.get('at', 0) < 3600
                and epoch >= record.get('cooldown_until', 0))


def due(record, epoch):
    if not record:return 0
    # Old busy/exception caches are observations of the detector, not the node.
    if 'next_due' not in record:
        return record.get('at', 0)+(30 if error_scope(record.get('reason')) == 'detector' else COOLDOWN)
    value = record.get('next_due', 0)
    return value if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= epoch+COOLDOWN else epoch


def latency_summary(values):
    numbers = sorted(float(v) for v in values if type(v) in (int, float) and math.isfinite(v) and v > 0)
    if not numbers:
        return {'samples': 0, 'median_ms': None, 'p95_ms': None}
    n=len(numbers);median=numbers[n//2] if n%2 else (numbers[n//2-1]+numbers[n//2])/2
    return {'samples': n, 'median_ms': round(median, 2), 'p95_ms': round(numbers[max(0, math.ceil(n*.95)-1)], 2) if n>=20 else None}
