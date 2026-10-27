"""Single persistent, fair admission queue. No fetch, publish or selector API."""
import fcntl
import json
import os
from pathlib import Path
import tempfile
import time
from health_policy import transition, eligible, due, error_scope


def atomic(path, value):
    with tempfile.NamedTemporaryFile('w',dir=path.parent,delete=False,encoding='utf-8') as f:
        p=Path(f.name);os.chmod(p,0o600);json.dump(value,f,ensure_ascii=False);f.flush();os.fsync(f.fileno())
    os.replace(p,path)


def read_cache(path):
    try:
        if path.stat().st_size>2*1024**2:raise ValueError('cache_too_large')
        value=json.loads(path.read_text())
        if not isinstance(value,dict):raise ValueError('invalid_cache')
        return {k:v for k,v in value.items() if isinstance(v,dict) and len(k)==64}
    except FileNotFoundError:return {}


def tick(module, validator=None, epoch=None):
    explicit_epoch=epoch is not None
    epoch=int(time.time()) if epoch is None else int(epoch)
    from clash_measurement import batch_paused
    if batch_paused(epoch):return False
    parent=module.DATA.parent;state_dir=parent/'node-health';state_dir.mkdir(mode=0o700,exist_ok=True)
    # A deployment can hold tests without perturbing the normal publisher.
    if (state_dir/'pause-admission').exists():return False
    with (state_dir/'admission-queue.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return False
        clock=state_dir/'admission-clock.json'
        try:last=json.loads(clock.read_text()).get('last_attempt',0)
        except (OSError,ValueError):last=0
        if 0<=epoch-last<30:return False
        cache_path=module.DATA/'admission-cache.json';cache=read_cache(cache_path)
        manifest=module.current_manifest();published=module.previous_fingerprints(manifest);candidates={}
        for source in module.load_sources():
            p=module.CACHE/(source.source_id+'.yaml')
            if not p.is_file() or p.stat().st_size>module.MAX_BYTES:continue
            for node in module.normalized_nodes(module.parse_nodes(p.read_bytes())):
                fingerprint=module.fingerprint(node)
                if fingerprint not in published:candidates.setdefault(fingerprint,node)
        pending=[(due(cache.get(fp,{}),epoch),fp,node) for fp,node in candidates.items() if due(cache.get(fp,{}),epoch)<=epoch]
        if not pending:return False
        _,fp,node=min(pending,key=lambda r:r[:2])
        if validator is None:
            from node_admission import validate
            validator=validate
        # No SQLite write transaction or routing lock spans an external test.
        ok,reason=validator(node);finished=epoch if explicit_epoch else int(time.time())
        previous=cache.get(fp,{})
        # Legacy success caches had no recovery streak; do not silently promote.
        cache[fp]=transition(previous,ok,finished,reason)
        # Cache never stores node credentials/addresses, only fingerprints/state.
        keep=set(candidates)|published
        cache={k:v for k,v in cache.items() if k in keep}
        atomic(cache_path,cache);atomic(clock,{'last_attempt':finished,'last_scope':error_scope(reason),'candidate_count':len(candidates)})
        return True
