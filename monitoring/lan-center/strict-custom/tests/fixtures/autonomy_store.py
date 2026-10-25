"""Small crash-safe documents. Checkpoints contain no activation-policy defaults."""
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
import time


def valid_sample(row):
    return (isinstance(row,dict) and type(row.get("ok")) is bool
            and type(row.get("at")) in (int,float) and math.isfinite(row["at"]) and row["at"]>=0
            and type(row.get("ms")) in (int,float) and math.isfinite(row["ms"]) and 0<=row["ms"]<=60000)


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name, dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(value, stream, ensure_ascii=False, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def checkpoint(path, value):
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
    atomic_json(Path(str(path) + ".good"), {
        "sha256": hashlib.sha256(payload.encode()).hexdigest(), "payload": payload,
    })


def recover_document(path, validator):
    path = Path(path)
    def reject_constant(_):raise ValueError("nonfinite_json")
    try:
        value = json.loads(path.read_text(encoding="utf-8"),parse_constant=reject_constant)
        if not validator(value):
            raise ValueError("invalid_document")
        return value, "primary"
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        pass
    try:
        backup = json.loads(Path(str(path) + ".good").read_text(encoding="utf-8"))
        if hashlib.sha256(backup["payload"].encode()).hexdigest() != backup["sha256"]:
            raise ValueError("checkpoint_checksum")
        value = json.loads(backup["payload"],parse_constant=reject_constant)
        if not validator(value):
            raise ValueError("invalid_checkpoint")
        # Retain the most recent damaged document; bounded, no indefinite copies.
        if path.is_file():
            os.replace(path, Path(str(path) + ".damaged"))
        atomic_json(path, value)
        return value, "checkpoint"
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        return None, "unavailable"


@contextmanager
def exclusive(path):
    """Process-wide advisory lock; production uses Linux flock, not PID files."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+b") as stream:
        os.chmod(path, 0o600)
        if os.name == "nt":
            import msvcrt
            if path.stat().st_size == 0:
                stream.write(b"0"); stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                yield False
                return
        else:
            import fcntl
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
        try:
            yield True
        finally:
            if os.name == "nt":
                stream.seek(0); msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def assess_window(records, started, now, seconds=86400, interval=120):
    """Time passing is not acceptance. Require coverage and first-attempt quality."""
    if now - started < seconds:
        return {"status": "running", "elapsed_seconds": max(0, now-started)}
    failures = []
    summaries = {}
    for business in ("gemini", "chatgpt", "default"):
        rows = sorted((r for r in records.get(business, []) if started <= r["at"] <= started+seconds), key=lambda r:r["at"])
        boundaries = [started] + [r["at"] for r in rows] + [started+seconds]
        max_gap = max(b-a for a,b in zip(boundaries,boundaries[1:]))
        count = len(rows)
        ratio = sum(bool(r["ok"]) for r in rows)/count if count else 0
        slow = sum(not r["ok"] or r["ms"]>3000 for r in rows)/count if count else 1
        latency = sorted(r["ms"] for r in rows if r["ok"])
        p95 = latency[min(len(latency)-1, int(len(latency)*.95))] if latency else None
        summaries[business] = {"checks":count,"success_ratio":ratio,"slow_ratio":slow,"p95_ms":p95,"max_gap_seconds":max_gap}
        if count < seconds/interval*.8 or max_gap > interval*4:
            failures.append(business+":insufficient_coverage")
        elif ratio < .99 or slow > .05 or p95 is None or p95 > 3000:
            failures.append(business+":quality_below_target")
    return {"status":"failed" if failures else "passed", "reasons":failures, "businesses":summaries,
            "elapsed_seconds":now-started,"scope":"unauthenticated_transport_not_account_availability"}


def reserve_restart(path, child, now, limit=3, window=600):
    value,reason=recover_document(path,lambda d:isinstance(d,dict) and d.get("schema")==1 and isinstance(d.get("events"),list))
    if value is None:
        if Path(path).exists():return False
        value={"schema":1,"events":[],"highwater":now}
    if now<value.get("highwater",0):return False
    events=[e for e in value["events"] if 0<=now-e["at"]<window]
    if sum(e["child"]==child for e in events)>=limit:return False
    events.append({"child":child,"at":now})
    value.update(events=events,highwater=now)
    atomic_json(path,value);checkpoint(path,value)
    return True


def publication_verdict(baseline, records, started, now):
    """Bounded release probation; a bad pre-existing WAN is not software blame."""
    if now-started<600:return "running"
    enough=all(len(records.get(b,[]))>=5 for b in ("gemini","chatgpt","default"))
    if not enough:return "unverified" if now-started>=1800 else "running"
    after={b:{"success_ratio":sum(r["ok"] for r in rows)/len(rows),
              "slow_ratio":sum(not r["ok"] or r["ms"]>3000 for r in rows)/len(rows)} for b,rows in records.items() if rows}
    for business,m in after.items():
        before=baseline.get(business,{})
        if (before.get("samples",0)>=3 and before.get("success_ratio",0)>=.9
            and (m["success_ratio"]<.8 or (before.get("slow_ratio",1)<=.1 and m["slow_ratio"]>=.4))):
            return "rollback_regression"
    if all(after[b]["success_ratio"]>=.95 and after[b]["slow_ratio"]<=.2 for b in ("gemini","chatgpt","default")):
        return "passed"
    return "unverified" if now-started>=1800 else "running"
